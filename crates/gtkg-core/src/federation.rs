//! Local-only federation contracts and deterministic coordinator reduction.
//!
//! Workers return immutable [`ShardResult`] values. They never write canonical
//! knowledge; the coordinator validates and reduces results before any finalize
//! step is allowed to run.

use std::collections::{BTreeMap, BTreeSet};

use gtkg_protocol::{
    ContractValidationError, ErrorCode, NodeDescriptor, NodeSetLock, ShardResult, WorkUnit,
};
use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[error("{message}")]
pub struct FederationFailure {
    pub code: ErrorCode,
    pub stage: &'static str,
    pub message: String,
    pub recovery_hint: &'static str,
}

impl FederationFailure {
    fn invalid(message: impl Into<String>) -> Self {
        Self {
            code: ErrorCode::InvalidRequest,
            stage: "federation.validate",
            message: message.into(),
            recovery_hint: "repair the exact node, work-unit, or shard-result contract and retry",
        }
    }

    fn nondeterministic(work_id: &str, digests: &BTreeSet<String>) -> Self {
        Self {
            code: ErrorCode::NonDeterministicResult,
            stage: "federation.reduce",
            message: format!(
                "work unit {work_id} produced conflicting output digests: {}",
                digests.iter().cloned().collect::<Vec<_>>().join(", ")
            ),
            recovery_hint: "block finalize and investigate worker binary, parser, sandbox, and source lock drift",
        }
    }
}

/// Freeze an exact local node set after validating every descriptor.
pub fn freeze_node_set(nodes: Vec<NodeDescriptor>) -> Result<NodeSetLock, FederationFailure> {
    NodeSetLock::new(nodes).map_err(contract_failure)
}

/// Validate and deterministically reduce at-least-once worker results.
///
/// Results are independent of arrival order. Identical retries are coalesced;
/// conflicting digests for one WorkId fail closed. The selected representative
/// is the lexicographically smallest `(node_id, attempt)` result so even receipt
/// ordering is stable.
pub fn reduce_shard_results(
    work_units: &[WorkUnit],
    shard_results: &[ShardResult],
) -> Result<Vec<ShardResult>, FederationFailure> {
    let mut expected = BTreeMap::new();
    for work in work_units {
        work.validate().map_err(contract_failure)?;
        if expected.insert(work.work_id.clone(), work).is_some() {
            return Err(FederationFailure::invalid(format!(
                "duplicate work_id in plan: {}",
                work.work_id
            )));
        }
    }

    let mut grouped: BTreeMap<&str, Vec<&ShardResult>> = BTreeMap::new();
    for result in shard_results {
        result.validate().map_err(contract_failure)?;
        if !expected.contains_key(&result.work_id) {
            return Err(FederationFailure::invalid(format!(
                "shard result references unknown work_id {}",
                result.work_id
            )));
        }
        grouped.entry(&result.work_id).or_default().push(result);
    }

    let mut reduced = Vec::with_capacity(expected.len());
    for work_id in expected.keys() {
        let Some(results) = grouped.get(work_id.as_str()) else {
            return Err(FederationFailure::invalid(format!(
                "work unit {work_id} has no shard result"
            )));
        };
        let digests: BTreeSet<String> = results
            .iter()
            .map(|result| result.output_sha256.clone())
            .collect();
        if digests.len() != 1 {
            return Err(FederationFailure::nondeterministic(work_id, &digests));
        }

        let Some(representative) = results.iter().min_by(|left, right| {
            left.node_id
                .cmp(&right.node_id)
                .then_with(|| left.attempt.cmp(&right.attempt))
                .then_with(|| left.output_sha256.cmp(&right.output_sha256))
        }) else {
            return Err(FederationFailure::invalid(format!(
                "work unit {work_id} has an empty result group"
            )));
        };
        // ShardResult::validate enforces this invariant. Keep the assignment
        // explicit so a future receipt extension cannot accidentally inherit a
        // worker-side canonical write count.
        let mut accepted = (*representative).clone();
        accepted.canonical_write_count = 0;
        reduced.push(accepted);
    }
    Ok(reduced)
}

fn contract_failure(error: ContractValidationError) -> FederationFailure {
    FederationFailure::invalid(error.to_string())
}
