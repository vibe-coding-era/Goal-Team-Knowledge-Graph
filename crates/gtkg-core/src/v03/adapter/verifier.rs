//! A06 cross-adapter verification gate.
//!
//! The complete verifier is built in this module without changing accepted
//! adapter implementations or protocol contracts.

use std::collections::{BTreeMap, BTreeSet};

use gtkg_protocol::v03::AdapterKindV1;
use gtkg_protocol::v03::adapter::{
    AdapterContractErrorV1, AdapterDescriptorV1, CandidateFactStateV1, ExternalEdgeFactV1,
    ExternalFactBundleV1, FactTrustStateV1, VerifiedResolutionV1,
};
use gtkg_protocol::{canonical_json_sha256, validate_sha256};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;

use super::codegraph::CodeGraphImportReceiptV1;
use super::graphify::{GraphifyImportReceiptV2, GraphifySourceLocatorV1};
use super::lsp_snapshot::LspSnapshotImportReceiptV1;
use super::native::NativeAdapterEffectsV1;
use super::scip::ScipImportReceiptV1;
use super::verify_external_fact_bundle_v1;

pub const MAX_ADAPTER_INPUT_BYTES_V1: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AdapterVerifierErrorV1 {
    #[error("adapter verifier requires exactly one of each frozen adapter kind")]
    ExactSet,
    #[error("adapter semantic oracle is invalid or tampered")]
    OracleInvalid,
    #[error("adapter semantic oracle does not match the independently trusted pin")]
    TrustedOracleMismatch,
    #[error("adapter semantic oracle does not cover the exact edge denominator")]
    OracleIncomplete,
    #[error("adapter fact differs from the frozen semantic oracle")]
    SemanticMismatch,
    #[error("adapter source bytes or spans do not replay exactly")]
    SourceReplayIncomplete,
    #[error("adapter trust laundering was detected")]
    TrustLaundering,
    #[error("adapter import receipt does not match its bundle or locators")]
    ReceiptMismatch,
    #[error("adapter input exceeds the independent A06 hard cap")]
    InputBudget,
    #[error("adapter actual input bytes differ from the authoritative sealed observation")]
    SealedInputMismatch,
    #[error("adapter descriptor or bundle contract is invalid")]
    ContractInvalid,
    #[error("adapter gate receipt is invalid")]
    GateReceiptInvalid,
    #[error("adapter gate receipt differs from exact recomputation")]
    GateReceiptMismatch,
}

impl AdapterVerifierErrorV1 {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::ExactSet => "E_ADAPTER_EXACT_SET",
            Self::OracleInvalid => "E_ADAPTER_ORACLE_INVALID",
            Self::TrustedOracleMismatch => "E_ADAPTER_TRUSTED_ORACLE_MISMATCH",
            Self::OracleIncomplete => "E_ADAPTER_ORACLE_INCOMPLETE",
            Self::SemanticMismatch => "E_ADAPTER_SEMANTIC_MISMATCH",
            Self::SourceReplayIncomplete => "E_ADAPTER_SOURCE_REPLAY_INCOMPLETE",
            Self::TrustLaundering => "E_ADAPTER_TRUST_LAUNDERING",
            Self::ReceiptMismatch => "E_ADAPTER_RECEIPT_MISMATCH",
            Self::InputBudget => "E_ADAPTER_INPUT_BUDGET",
            Self::SealedInputMismatch => "E_ADAPTER_SEALED_INPUT_MISMATCH",
            Self::ContractInvalid => "E_ADAPTER_CONTRACT_INVALID",
            Self::GateReceiptInvalid => "E_ADAPTER_GATE_RECEIPT_INVALID",
            Self::GateReceiptMismatch => "E_ADAPTER_GATE_RECEIPT_MISMATCH",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterTrustedOraclePinV1 {
    pub schema_version: String,
    pub pin_id: String,
    pub expected_oracle_sha256: String,
    pub review_material_sha256: String,
    pub pin_sha256: String,
}

impl AdapterTrustedOraclePinV1 {
    pub fn with_computed_digest(mut self) -> Result<Self, AdapterVerifierErrorV1> {
        self.validate_shape()?;
        self.pin_sha256 = digest_without_field(&self, "pin_sha256")?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), AdapterVerifierErrorV1> {
        self.validate_shape()?;
        if self.pin_sha256 != digest_without_field(self, "pin_sha256")? {
            return Err(AdapterVerifierErrorV1::TrustedOracleMismatch);
        }
        Ok(())
    }

    fn validate_shape(&self) -> Result<(), AdapterVerifierErrorV1> {
        if self.schema_version != "gtkg.adapter-trusted-oracle-pin/v1"
            || self.pin_id.trim().is_empty()
            || self.pin_id.contains("..")
            || validate_sha256(&self.expected_oracle_sha256).is_err()
            || validate_sha256(&self.review_material_sha256).is_err()
        {
            return Err(AdapterVerifierErrorV1::TrustedOracleMismatch);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterTrustedOracleFixtureV1 {
    pub schema_version: String,
    pub pin: AdapterTrustedOraclePinV1,
    pub review_material: Value,
    pub oracle: AdapterSemanticOracleV1,
}

impl AdapterTrustedOracleFixtureV1 {
    pub fn validate(&self) -> Result<(), AdapterVerifierErrorV1> {
        self.pin.validate()?;
        self.oracle.validate()?;
        let review_material_sha256 = canonical_json_sha256(&self.review_material)
            .map_err(|_| AdapterVerifierErrorV1::TrustedOracleMismatch)?;
        if self.schema_version != "gtkg.a06-trusted-oracle-material/v1"
            || review_material_sha256 != self.pin.review_material_sha256
            || self.oracle.oracle_sha256 != self.pin.expected_oracle_sha256
        {
            return Err(AdapterVerifierErrorV1::TrustedOracleMismatch);
        }
        Ok(())
    }

    pub fn canonical_sha256(&self) -> Result<String, AdapterVerifierErrorV1> {
        self.validate()?;
        canonical_json_sha256(self).map_err(|_| AdapterVerifierErrorV1::TrustedOracleMismatch)
    }
}

#[derive(Debug, Clone, Copy)]
pub enum AdapterReceiptRefV1<'a> {
    Native(&'a NativeAdapterEffectsV1),
    Scip(&'a ScipImportReceiptV1),
    Lsp(&'a LspSnapshotImportReceiptV1),
    CodeGraph(&'a CodeGraphImportReceiptV1),
    GraphifyV2(&'a GraphifyImportReceiptV2),
}

impl<'a> AdapterReceiptRefV1<'a> {
    pub const fn kind(self) -> AdapterKindV1 {
        match self {
            Self::Native(_) => AdapterKindV1::Native,
            Self::Scip(_) => AdapterKindV1::Scip,
            Self::Lsp(_) => AdapterKindV1::LspSnapshot,
            Self::CodeGraph(_) => AdapterKindV1::CodeGraphExport,
            Self::GraphifyV2(_) => AdapterKindV1::GraphifyExport,
        }
    }

    pub fn identity_sha256(self) -> Result<String, AdapterVerifierErrorV1> {
        match self {
            Self::Native(effects) => canonical_json_sha256(&json!({
                "source_file_read_count": effects.source_file_read_count,
                "target_process_count": effects.target_process_count,
                "network_call_count": effects.network_call_count,
                "write_count": effects.write_count,
                "executed_target_content": effects.executed_target_content,
            })),
            Self::Scip(receipt) => Ok(receipt.receipt_sha256.clone()),
            Self::Lsp(receipt) => Ok(receipt.receipt_sha256.clone()),
            Self::CodeGraph(receipt) => Ok(receipt.receipt_sha256.clone()),
            Self::GraphifyV2(receipt) => Ok(receipt.receipt_sha256.clone()),
        }
        .map_err(|_| AdapterVerifierErrorV1::ReceiptMismatch)
    }

    fn imported_file_sha256(self) -> Option<&'a str> {
        match self {
            Self::Native(_) => None,
            Self::Scip(receipt) => Some(&receipt.scip_file_sha256),
            Self::Lsp(receipt) => Some(&receipt.snapshot_file_sha256),
            Self::CodeGraph(receipt) => Some(&receipt.codegraph_file_sha256),
            Self::GraphifyV2(receipt) => Some(&receipt.graphify_file_sha256),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AdapterSubmissionV1<'a> {
    pub descriptor: &'a AdapterDescriptorV1,
    pub bundle: &'a ExternalFactBundleV1,
    pub source_files: &'a BTreeMap<String, Vec<u8>>,
    pub source_locators: &'a [GraphifySourceLocatorV1],
    pub receipt: AdapterReceiptRefV1<'a>,
    pub input_file_bytes: u64,
    pub configured_max_file_bytes: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct SealedInputObservationV1<'a> {
    pub actual_input_bytes: &'a [u8],
}

#[derive(Debug, Clone)]
pub struct StrictAdapterSubmissionV1<'a> {
    pub submission: AdapterSubmissionV1<'a>,
    pub observation: SealedInputObservationV1<'a>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterFactExpectationV1 {
    pub adapter_descriptor_sha256: String,
    pub fact_id: String,
    pub accepted_target_references: Vec<String>,
    pub candidate_node_ids: Vec<String>,
    pub candidate_state: CandidateFactStateV1,
    pub trust_state: FactTrustStateV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterSemanticOracleV1 {
    pub schema_version: String,
    pub expectations: Vec<AdapterFactExpectationV1>,
    pub oracle_sha256: String,
}

impl AdapterSemanticOracleV1 {
    pub fn with_computed_digest(mut self) -> Result<Self, AdapterVerifierErrorV1> {
        for expectation in &mut self.expectations {
            expectation.accepted_target_references.sort();
            expectation.accepted_target_references.dedup();
            expectation.candidate_node_ids.sort();
            expectation.candidate_node_ids.dedup();
        }
        self.expectations.sort_by(|left, right| {
            (&left.adapter_descriptor_sha256, &left.fact_id)
                .cmp(&(&right.adapter_descriptor_sha256, &right.fact_id))
        });
        self.validate_shape()?;
        self.oracle_sha256 = digest_without_field(&self, "oracle_sha256")?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), AdapterVerifierErrorV1> {
        self.validate_shape()?;
        if self.oracle_sha256 != digest_without_field(self, "oracle_sha256")? {
            return Err(AdapterVerifierErrorV1::OracleInvalid);
        }
        Ok(())
    }

    fn validate_shape(&self) -> Result<(), AdapterVerifierErrorV1> {
        let mut keys = BTreeSet::new();
        if self.schema_version != "gtkg.adapter-semantic-oracle/v1"
            || self.expectations.is_empty()
            || self.expectations.iter().any(|expectation| {
                validate_sha256(&expectation.adapter_descriptor_sha256).is_err()
                    || expectation.fact_id.trim().is_empty()
                    || expectation.accepted_target_references.is_empty()
                    || expectation
                        .accepted_target_references
                        .iter()
                        .any(|value| value.trim().is_empty())
                    || !strictly_sorted_unique(&expectation.accepted_target_references)
                    || !strictly_sorted_unique(&expectation.candidate_node_ids)
                    || !keys.insert((
                        expectation.adapter_descriptor_sha256.as_str(),
                        expectation.fact_id.as_str(),
                    ))
            })
        {
            return Err(AdapterVerifierErrorV1::OracleInvalid);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterFactIdentityV1 {
    pub adapter_kind: AdapterKindV1,
    pub adapter_descriptor_sha256: String,
    pub fact_id: String,
    pub stable_id: String,
    pub name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdapterCollisionKindV1 {
    StableId,
    FactId,
    SameName,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterCollisionGroupV1 {
    pub kind: AdapterCollisionKindV1,
    pub key: String,
    pub members: Vec<AdapterFactIdentityV1>,
    pub selected_fact_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterCollisionReportV1 {
    pub stable_id_collisions: Vec<AdapterCollisionGroupV1>,
    pub fact_id_collisions: Vec<AdapterCollisionGroupV1>,
    pub same_name_conflicts: Vec<AdapterCollisionGroupV1>,
    pub selected_fact_ids: Vec<String>,
    pub canonical_write_count: u64,
}

pub fn detect_adapter_collisions_v1(facts: &[AdapterFactIdentityV1]) -> AdapterCollisionReportV1 {
    AdapterCollisionReportV1 {
        stable_id_collisions: collision_groups(facts, AdapterCollisionKindV1::StableId, |fact| {
            fact.stable_id.clone()
        }),
        fact_id_collisions: collision_groups(facts, AdapterCollisionKindV1::FactId, |fact| {
            fact.fact_id.clone()
        }),
        same_name_conflicts: collision_groups(facts, AdapterCollisionKindV1::SameName, |fact| {
            fact.name.trim().to_lowercase()
        }),
        selected_fact_ids: Vec::new(),
        canonical_write_count: 0,
    }
}

fn collision_groups<F>(
    facts: &[AdapterFactIdentityV1],
    kind: AdapterCollisionKindV1,
    key: F,
) -> Vec<AdapterCollisionGroupV1>
where
    F: Fn(&AdapterFactIdentityV1) -> String,
{
    let mut grouped = BTreeMap::<String, Vec<AdapterFactIdentityV1>>::new();
    for fact in facts {
        let group_key = key(fact);
        if !group_key.is_empty() {
            grouped.entry(group_key).or_default().push(fact.clone());
        }
    }
    grouped
        .into_iter()
        .filter_map(|(key, mut members)| {
            let adapter_kinds = members
                .iter()
                .map(|member| member.adapter_kind.as_str())
                .collect::<BTreeSet<_>>();
            if adapter_kinds.len() < 2 {
                return None;
            }
            members.sort_by(|left, right| {
                (
                    left.adapter_kind.as_str(),
                    &left.adapter_descriptor_sha256,
                    &left.fact_id,
                    &left.stable_id,
                )
                    .cmp(&(
                        right.adapter_kind.as_str(),
                        &right.adapter_descriptor_sha256,
                        &right.fact_id,
                        &right.stable_id,
                    ))
            });
            Some(AdapterCollisionGroupV1 {
                kind,
                key,
                members,
                selected_fact_id: None,
            })
        })
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdapterGateAuthorityStateV1 {
    UntrustedLegacy,
    TrustedPinBound,
    TrustedFixtureBound,
    TrustedFixtureInputBound,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterGateReceiptV1 {
    pub schema_version: String,
    pub verifier_identity: String,
    pub adapter_count: u64,
    pub adapter_kinds: Vec<AdapterKindV1>,
    pub authority_state: AdapterGateAuthorityStateV1,
    pub input_set_sha256: String,
    pub oracle_sha256: String,
    pub trusted_oracle_pin_sha256: Option<String>,
    pub trusted_oracle_fixture_sha256: Option<String>,
    pub sealed_input_set_sha256: Option<String>,
    pub discovered_count: u64,
    pub admitted_count: u64,
    pub omitted_count: u64,
    pub omission_closure_numerator: u64,
    pub omission_closure_denominator: u64,
    pub omission_closure_basis_points: u64,
    pub evidence_count: u64,
    pub source_locator_count: u64,
    pub source_replay_receipt_count: u64,
    pub resolved_verified_count: u64,
    pub false_confirmed: u64,
    pub trust_laundering_count: u64,
    pub receipt_mismatch_count: u64,
    pub collisions: AdapterCollisionReportV1,
    pub canonical_eligible: bool,
    pub canonical_selected_fact_ids: Vec<String>,
    pub target_execution_count: u64,
    pub provider_call_count: u64,
    pub network_call_count: u64,
    pub write_count: u64,
    pub canonical_write_count: u64,
    pub receipt_sha256: String,
}

impl AdapterGateReceiptV1 {
    pub fn validate(&self) -> Result<(), AdapterVerifierErrorV1> {
        if self.schema_version != "gtkg.adapter-gate-receipt/v1"
            || self.verifier_identity.trim().is_empty()
            || self.verifier_identity.contains("..")
            || self.adapter_count != 5
            || self.adapter_kinds.as_slice() != AdapterKindV1::ALL.as_slice()
            || validate_sha256(&self.input_set_sha256).is_err()
            || validate_sha256(&self.oracle_sha256).is_err()
            || self
                .trusted_oracle_pin_sha256
                .as_ref()
                .is_some_and(|sha256| validate_sha256(sha256).is_err())
            || self
                .trusted_oracle_fixture_sha256
                .as_ref()
                .is_some_and(|sha256| validate_sha256(sha256).is_err())
            || self
                .sealed_input_set_sha256
                .as_ref()
                .is_some_and(|sha256| validate_sha256(sha256).is_err())
            || !authority_bindings_are_consistent(self)
            || self.discovered_count == 0
            || self.discovered_count
                != self
                    .admitted_count
                    .checked_add(self.omitted_count)
                    .ok_or(AdapterVerifierErrorV1::GateReceiptInvalid)?
            || self.omission_closure_numerator != self.discovered_count
            || self.omission_closure_denominator != self.discovered_count
            || self.omission_closure_basis_points != 10_000
            || self.source_replay_receipt_count != self.admitted_count
            || self.resolved_verified_count > self.source_replay_receipt_count
            || self.false_confirmed != 0
            || self.trust_laundering_count != 0
            || self.receipt_mismatch_count != 0
            || self.canonical_eligible
            || !self.canonical_selected_fact_ids.is_empty()
            || self.target_execution_count != 0
            || self.provider_call_count != 0
            || self.network_call_count != 0
            || self.write_count != 0
            || self.canonical_write_count != 0
            || !collision_report_is_nonselecting(&self.collisions)
            || self.receipt_sha256 != digest_without_field(self, "receipt_sha256")?
        {
            return Err(AdapterVerifierErrorV1::GateReceiptInvalid);
        }
        Ok(())
    }

    pub fn validate_against(
        &self,
        submissions: &[AdapterSubmissionV1<'_>],
        oracle: &AdapterSemanticOracleV1,
        trusted_pin: &AdapterTrustedOraclePinV1,
        verifier_identity: &str,
    ) -> Result<(), AdapterVerifierErrorV1> {
        self.validate()?;
        let expected = verify_adapter_gate_with_trusted_oracle_v1(
            submissions,
            oracle,
            trusted_pin,
            verifier_identity,
        )?;
        if self != &expected {
            return Err(AdapterVerifierErrorV1::GateReceiptMismatch);
        }
        Ok(())
    }

    pub fn validate_strict_against(
        &self,
        submissions: &[AdapterSubmissionV1<'_>],
        trusted_fixture: &AdapterTrustedOracleFixtureV1,
        verifier_identity: &str,
    ) -> Result<(), AdapterVerifierErrorV1> {
        self.validate()?;
        if self.authority_state != AdapterGateAuthorityStateV1::TrustedFixtureBound {
            return Err(AdapterVerifierErrorV1::GateReceiptMismatch);
        }
        let expected =
            verify_adapter_gate_strict_v1(submissions, trusted_fixture, verifier_identity)?;
        if self != &expected {
            return Err(AdapterVerifierErrorV1::GateReceiptMismatch);
        }
        Ok(())
    }

    pub fn validate_sealed_strict_against(
        &self,
        submissions: &[StrictAdapterSubmissionV1<'_>],
        trusted_fixture: &AdapterTrustedOracleFixtureV1,
        verifier_identity: &str,
    ) -> Result<(), AdapterVerifierErrorV1> {
        self.validate()?;
        if self.authority_state != AdapterGateAuthorityStateV1::TrustedFixtureInputBound {
            return Err(AdapterVerifierErrorV1::GateReceiptMismatch);
        }
        let expected =
            verify_adapter_gate_sealed_strict_v1(submissions, trusted_fixture, verifier_identity)?;
        if self != &expected {
            return Err(AdapterVerifierErrorV1::GateReceiptMismatch);
        }
        Ok(())
    }
}

fn collision_report_is_nonselecting(report: &AdapterCollisionReportV1) -> bool {
    report.selected_fact_ids.is_empty()
        && report.canonical_write_count == 0
        && report
            .stable_id_collisions
            .iter()
            .chain(&report.fact_id_collisions)
            .chain(&report.same_name_conflicts)
            .all(|group| group.members.len() >= 2 && group.selected_fact_id.is_none())
}

fn authority_bindings_are_consistent(receipt: &AdapterGateReceiptV1) -> bool {
    match receipt.authority_state {
        AdapterGateAuthorityStateV1::UntrustedLegacy => {
            receipt.trusted_oracle_pin_sha256.is_none()
                && receipt.trusted_oracle_fixture_sha256.is_none()
                && receipt.sealed_input_set_sha256.is_none()
        }
        AdapterGateAuthorityStateV1::TrustedPinBound => {
            receipt.trusted_oracle_pin_sha256.is_some()
                && receipt.trusted_oracle_fixture_sha256.is_none()
                && receipt.sealed_input_set_sha256.is_none()
        }
        AdapterGateAuthorityStateV1::TrustedFixtureBound => {
            receipt.trusted_oracle_pin_sha256.is_some()
                && receipt.trusted_oracle_fixture_sha256.is_some()
                && receipt.sealed_input_set_sha256.is_none()
        }
        AdapterGateAuthorityStateV1::TrustedFixtureInputBound => {
            receipt.trusted_oracle_pin_sha256.is_some()
                && receipt.trusted_oracle_fixture_sha256.is_some()
                && receipt.sealed_input_set_sha256.is_some()
        }
    }
}

pub fn verify_adapter_gate_v1(
    submissions: &[AdapterSubmissionV1<'_>],
    oracle: &AdapterSemanticOracleV1,
    verifier_identity: &str,
) -> Result<AdapterGateReceiptV1, AdapterVerifierErrorV1> {
    verify_adapter_gate_internal_v1(
        submissions,
        oracle,
        None,
        AdapterGateAuthorityStateV1::UntrustedLegacy,
        None,
        None,
        verifier_identity,
    )
}

pub fn verify_adapter_gate_with_trusted_oracle_v1(
    submissions: &[AdapterSubmissionV1<'_>],
    oracle: &AdapterSemanticOracleV1,
    trusted_pin: &AdapterTrustedOraclePinV1,
    verifier_identity: &str,
) -> Result<AdapterGateReceiptV1, AdapterVerifierErrorV1> {
    trusted_pin.validate()?;
    oracle.validate()?;
    if oracle.oracle_sha256 != trusted_pin.expected_oracle_sha256 {
        return Err(AdapterVerifierErrorV1::TrustedOracleMismatch);
    }
    verify_adapter_gate_internal_v1(
        submissions,
        oracle,
        Some(trusted_pin),
        AdapterGateAuthorityStateV1::TrustedPinBound,
        None,
        None,
        verifier_identity,
    )
}

pub fn verify_adapter_gate_strict_v1(
    submissions: &[AdapterSubmissionV1<'_>],
    trusted_fixture: &AdapterTrustedOracleFixtureV1,
    verifier_identity: &str,
) -> Result<AdapterGateReceiptV1, AdapterVerifierErrorV1> {
    trusted_fixture.validate()?;
    let fixture_sha256 = trusted_fixture.canonical_sha256()?;
    verify_adapter_gate_internal_v1(
        submissions,
        &trusted_fixture.oracle,
        Some(&trusted_fixture.pin),
        AdapterGateAuthorityStateV1::TrustedFixtureBound,
        Some(fixture_sha256),
        None,
        verifier_identity,
    )
}

pub fn verify_adapter_gate_sealed_strict_v1(
    submissions: &[StrictAdapterSubmissionV1<'_>],
    trusted_fixture: &AdapterTrustedOracleFixtureV1,
    verifier_identity: &str,
) -> Result<AdapterGateReceiptV1, AdapterVerifierErrorV1> {
    trusted_fixture.validate()?;
    let fixture_sha256 = trusted_fixture.canonical_sha256()?;
    let mut legacy_submissions = Vec::with_capacity(submissions.len());
    let mut sealed_identities = Vec::with_capacity(submissions.len());
    for strict in submissions {
        validate_input_budget(&strict.submission)?;
        let actual_len = count(strict.observation.actual_input_bytes.len())?;
        if actual_len == 0
            || actual_len > MAX_ADAPTER_INPUT_BYTES_V1
            || actual_len > strict.submission.configured_max_file_bytes
            || actual_len != strict.submission.input_file_bytes
        {
            return Err(AdapterVerifierErrorV1::SealedInputMismatch);
        }
        let actual_sha256 = sha256(strict.observation.actual_input_bytes);
        if let Some(expected_sha256) = strict.submission.receipt.imported_file_sha256() {
            if actual_sha256 != expected_sha256 {
                return Err(AdapterVerifierErrorV1::SealedInputMismatch);
            }
        } else {
            let mut native_sources = strict.submission.source_files.values();
            if native_sources.next().map(Vec::as_slice)
                != Some(strict.observation.actual_input_bytes)
                || native_sources.next().is_some()
            {
                return Err(AdapterVerifierErrorV1::SealedInputMismatch);
            }
        }
        sealed_identities.push(SealedInputIdentityV1 {
            adapter_kind: strict.submission.descriptor.kind,
            actual_len,
            actual_sha256,
            configured_max_file_bytes: strict.submission.configured_max_file_bytes,
            import_receipt_sha256: strict.submission.receipt.identity_sha256()?,
        });
        legacy_submissions.push(strict.submission.clone());
    }
    sealed_identities.sort_by_key(|identity| adapter_rank(identity.adapter_kind));
    let sealed_input_set_sha256 = canonical_json_sha256(&sealed_identities)
        .map_err(|_| AdapterVerifierErrorV1::SealedInputMismatch)?;
    verify_adapter_gate_internal_v1(
        &legacy_submissions,
        &trusted_fixture.oracle,
        Some(&trusted_fixture.pin),
        AdapterGateAuthorityStateV1::TrustedFixtureInputBound,
        Some(fixture_sha256),
        Some(sealed_input_set_sha256),
        verifier_identity,
    )
}

#[derive(Debug, Serialize)]
struct SealedInputIdentityV1 {
    adapter_kind: AdapterKindV1,
    actual_len: u64,
    actual_sha256: String,
    configured_max_file_bytes: u64,
    import_receipt_sha256: String,
}

fn verify_adapter_gate_internal_v1(
    submissions: &[AdapterSubmissionV1<'_>],
    oracle: &AdapterSemanticOracleV1,
    trusted_pin: Option<&AdapterTrustedOraclePinV1>,
    authority_state: AdapterGateAuthorityStateV1,
    trusted_oracle_fixture_sha256: Option<String>,
    sealed_input_set_sha256: Option<String>,
    verifier_identity: &str,
) -> Result<AdapterGateReceiptV1, AdapterVerifierErrorV1> {
    oracle.validate()?;
    if verifier_identity.trim().is_empty() || verifier_identity.contains("..") {
        return Err(AdapterVerifierErrorV1::GateReceiptInvalid);
    }
    let mut kinds = submissions
        .iter()
        .map(|submission| submission.descriptor.kind.as_str())
        .collect::<Vec<_>>();
    kinds.sort_unstable();
    kinds.dedup();
    let mut expected_kinds = AdapterKindV1::ALL
        .iter()
        .map(|kind| kind.as_str())
        .collect::<Vec<_>>();
    expected_kinds.sort_unstable();
    if submissions.len() != 5 || kinds != expected_kinds {
        return Err(AdapterVerifierErrorV1::ExactSet);
    }

    let expectations = oracle
        .expectations
        .iter()
        .map(|expectation| {
            (
                (
                    expectation.adapter_descriptor_sha256.as_str(),
                    expectation.fact_id.as_str(),
                ),
                expectation,
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut consumed_expectations = BTreeSet::new();
    let mut ordered = submissions.iter().collect::<Vec<_>>();
    ordered.sort_by_key(|submission| adapter_rank(submission.descriptor.kind));

    let mut discovered_count = 0_u64;
    let mut admitted_count = 0_u64;
    let mut omitted_count = 0_u64;
    let mut evidence_count = 0_u64;
    let mut source_locator_count = 0_u64;
    let mut source_replay_receipt_count = 0_u64;
    let mut resolved_verified_count = 0_u64;
    let mut identities = Vec::new();
    let mut input_identities = Vec::new();

    for submission in ordered {
        validate_input_budget(submission)?;
        submission
            .descriptor
            .validate()
            .map_err(|_| AdapterVerifierErrorV1::ContractInvalid)?;
        submission
            .bundle
            .validate()
            .map_err(|_| AdapterVerifierErrorV1::ContractInvalid)?;
        if submission.bundle.adapter_descriptor_sha256 != submission.descriptor.descriptor_sha256
            || submission.receipt.kind() != submission.descriptor.kind
        {
            return Err(AdapterVerifierErrorV1::ContractInvalid);
        }
        validate_node_and_candidate_ids(submission.bundle)?;
        validate_evidence_denominator(submission.bundle)?;

        for edge in &submission.bundle.edges {
            let key = (
                submission.descriptor.descriptor_sha256.as_str(),
                edge.fact_id.as_str(),
            );
            let expectation = expectations
                .get(&key)
                .ok_or(AdapterVerifierErrorV1::OracleIncomplete)?;
            validate_edge_semantics(submission, edge, expectation)?;
            consumed_expectations.insert((key.0.to_owned(), key.1.to_owned()));
        }

        let (replay_count, resolved_count) = validate_source_replay(submission, verifier_identity)?;
        validate_receipt_against(submission)?;

        discovered_count = checked_add(discovered_count, submission.bundle.discovered_count)?;
        admitted_count = checked_add(admitted_count, submission.bundle.admitted_count)?;
        omitted_count = checked_add(omitted_count, submission.bundle.omitted_count)?;
        evidence_count = checked_add(evidence_count, count(submission.bundle.evidence.len())?)?;
        source_locator_count = checked_add(
            source_locator_count,
            count(submission.source_locators.len())?,
        )?;
        source_replay_receipt_count = checked_add(source_replay_receipt_count, replay_count)?;
        resolved_verified_count = checked_add(resolved_verified_count, resolved_count)?;

        identities.extend(
            submission
                .bundle
                .nodes
                .iter()
                .map(|node| AdapterFactIdentityV1 {
                    adapter_kind: submission.descriptor.kind,
                    adapter_descriptor_sha256: submission.descriptor.descriptor_sha256.clone(),
                    fact_id: node.fact_id.clone(),
                    stable_id: node.node_id.clone(),
                    name: node.name.clone(),
                }),
        );
        identities.extend(
            submission
                .bundle
                .edges
                .iter()
                .map(|edge| AdapterFactIdentityV1 {
                    adapter_kind: submission.descriptor.kind,
                    adapter_descriptor_sha256: submission.descriptor.descriptor_sha256.clone(),
                    fact_id: edge.fact_id.clone(),
                    stable_id: edge.edge_id.clone(),
                    name: edge.target_reference.clone(),
                }),
        );
        input_identities.push(input_identity(submission)?);
    }

    if consumed_expectations.len() != expectations.len()
        || !oracle.expectations.iter().all(|expectation| {
            consumed_expectations.contains(&(
                expectation.adapter_descriptor_sha256.clone(),
                expectation.fact_id.clone(),
            ))
        })
    {
        return Err(AdapterVerifierErrorV1::OracleIncomplete);
    }
    if discovered_count != checked_add(admitted_count, omitted_count)? || discovered_count == 0 {
        return Err(AdapterVerifierErrorV1::ContractInvalid);
    }

    let input_set_sha256 = canonical_json_sha256(&input_identities)
        .map_err(|_| AdapterVerifierErrorV1::GateReceiptInvalid)?;
    let collisions = detect_adapter_collisions_v1(&identities);
    let mut receipt = AdapterGateReceiptV1 {
        schema_version: "gtkg.adapter-gate-receipt/v1".to_owned(),
        verifier_identity: verifier_identity.to_owned(),
        adapter_count: 5,
        adapter_kinds: AdapterKindV1::ALL.to_vec(),
        authority_state,
        input_set_sha256,
        oracle_sha256: oracle.oracle_sha256.clone(),
        trusted_oracle_pin_sha256: trusted_pin.map(|pin| pin.pin_sha256.clone()),
        trusted_oracle_fixture_sha256,
        sealed_input_set_sha256,
        discovered_count,
        admitted_count,
        omitted_count,
        omission_closure_numerator: discovered_count,
        omission_closure_denominator: discovered_count,
        omission_closure_basis_points: 10_000,
        evidence_count,
        source_locator_count,
        source_replay_receipt_count,
        resolved_verified_count,
        false_confirmed: 0,
        trust_laundering_count: 0,
        receipt_mismatch_count: 0,
        collisions,
        canonical_eligible: false,
        canonical_selected_fact_ids: Vec::new(),
        target_execution_count: 0,
        provider_call_count: 0,
        network_call_count: 0,
        write_count: 0,
        canonical_write_count: 0,
        receipt_sha256: String::new(),
    };
    receipt.receipt_sha256 = digest_without_field(&receipt, "receipt_sha256")?;
    receipt.validate()?;
    Ok(receipt)
}

fn validate_input_budget(
    submission: &AdapterSubmissionV1<'_>,
) -> Result<(), AdapterVerifierErrorV1> {
    if submission.input_file_bytes == 0
        || submission.configured_max_file_bytes == 0
        || submission.configured_max_file_bytes > MAX_ADAPTER_INPUT_BYTES_V1
        || submission.input_file_bytes > submission.configured_max_file_bytes
    {
        return Err(AdapterVerifierErrorV1::InputBudget);
    }
    Ok(())
}

fn validate_evidence_denominator(
    bundle: &ExternalFactBundleV1,
) -> Result<(), AdapterVerifierErrorV1> {
    let evidence_ids = bundle
        .evidence
        .iter()
        .map(|evidence| evidence.evidence_id.as_str())
        .collect::<BTreeSet<_>>();
    let mut referenced = BTreeSet::new();
    for evidence_id in bundle
        .nodes
        .iter()
        .flat_map(|node| node.evidence_ids.iter())
        .chain(
            bundle
                .edges
                .iter()
                .flat_map(|edge| edge.evidence_ids.iter()),
        )
    {
        if !evidence_ids.contains(evidence_id.as_str()) {
            return Err(AdapterVerifierErrorV1::SourceReplayIncomplete);
        }
        referenced.insert(evidence_id.as_str());
    }
    if referenced != evidence_ids {
        return Err(AdapterVerifierErrorV1::SourceReplayIncomplete);
    }
    Ok(())
}

fn validate_node_and_candidate_ids(
    bundle: &ExternalFactBundleV1,
) -> Result<(), AdapterVerifierErrorV1> {
    let mut node_ids = BTreeSet::new();
    for node in &bundle.nodes {
        if node.node_id.trim().is_empty()
            || node.name.trim().is_empty()
            || !node_ids.insert(node.node_id.as_str())
        {
            return Err(AdapterVerifierErrorV1::ContractInvalid);
        }
    }
    for edge in &bundle.edges {
        let mut candidates = BTreeSet::new();
        if edge
            .candidate_node_ids
            .iter()
            .any(|node_id| !node_ids.contains(node_id.as_str()) || !candidates.insert(node_id))
        {
            return Err(AdapterVerifierErrorV1::SemanticMismatch);
        }
    }
    Ok(())
}

fn validate_edge_semantics(
    submission: &AdapterSubmissionV1<'_>,
    edge: &ExternalEdgeFactV1,
    expectation: &AdapterFactExpectationV1,
) -> Result<(), AdapterVerifierErrorV1> {
    let mut candidates = edge.candidate_node_ids.clone();
    let original_candidate_count = candidates.len();
    candidates.sort();
    candidates.dedup();
    if candidates.len() != original_candidate_count
        || edge.candidate_state != expectation.candidate_state
        || edge.trust_state != expectation.trust_state
        || candidates != expectation.candidate_node_ids
        || !expectation
            .accepted_target_references
            .contains(&edge.target_reference)
    {
        return Err(AdapterVerifierErrorV1::SemanticMismatch);
    }
    if edge.evidence_ids.is_empty() || edge.candidate_node_ids.is_empty() {
        return Ok(());
    }
    let evidence = submission
        .bundle
        .evidence
        .iter()
        .map(|item| (item.evidence_id.as_str(), item))
        .collect::<BTreeMap<_, _>>();
    let aliases = expectation
        .accepted_target_references
        .iter()
        .map(String::as_bytes)
        .collect::<Vec<_>>();
    let alias_replayed = edge.evidence_ids.iter().any(|evidence_id| {
        let Some(item) = evidence.get(evidence_id.as_str()) else {
            return false;
        };
        let Some(bytes) = submission.source_files.get(&item.source_logical_path) else {
            return false;
        };
        let Ok(start) = usize::try_from(item.byte_start) else {
            return false;
        };
        let Ok(end) = usize::try_from(item.byte_end) else {
            return false;
        };
        bytes
            .get(start..end)
            .is_some_and(|snippet| aliases.contains(&snippet))
    });
    if !alias_replayed {
        return Err(AdapterVerifierErrorV1::SourceReplayIncomplete);
    }
    Ok(())
}

fn validate_source_replay(
    submission: &AdapterSubmissionV1<'_>,
    verifier_identity: &str,
) -> Result<(u64, u64), AdapterVerifierErrorV1> {
    let verification = verify_external_fact_bundle_v1(
        submission.descriptor,
        submission.descriptor,
        submission.bundle,
        submission.source_files,
        verifier_identity,
    )
    .map_err(|error| match error {
        AdapterContractErrorV1::TrustLaundering => AdapterVerifierErrorV1::TrustLaundering,
        _ => AdapterVerifierErrorV1::ContractInvalid,
    })?;
    let resolutions = verification
        .receipts
        .iter()
        .map(|receipt| (receipt.fact_id.as_str(), receipt.resolution))
        .collect::<BTreeMap<_, _>>();
    let every_exact_fact_replayed = submission
        .bundle
        .nodes
        .iter()
        .map(|node| {
            (
                node.fact_id.as_str(),
                node.candidate_state,
                node.trust_state,
                node.evidence_ids.is_empty(),
            )
        })
        .chain(submission.bundle.edges.iter().map(|edge| {
            (
                edge.fact_id.as_str(),
                edge.candidate_state,
                edge.trust_state,
                edge.evidence_ids.is_empty(),
            )
        }))
        .all(|(fact_id, state, trust, evidence_empty)| {
            evidence_empty
                || state != CandidateFactStateV1::CandidateExternal
                || trust != FactTrustStateV1::Extracted
                || resolutions.get(fact_id) == Some(&VerifiedResolutionV1::ResolvedVerified)
        });
    if !every_exact_fact_replayed || verification.false_confirmed != 0 {
        return Err(AdapterVerifierErrorV1::SourceReplayIncomplete);
    }
    Ok((
        count(verification.receipts.len())?,
        count(verification.resolved_verified_fact_ids.len())?,
    ))
}

fn validate_receipt_against(
    submission: &AdapterSubmissionV1<'_>,
) -> Result<(), AdapterVerifierErrorV1> {
    if !submission.source_locators.is_empty()
        && submission.descriptor.kind != AdapterKindV1::GraphifyExport
    {
        return Err(AdapterVerifierErrorV1::ReceiptMismatch);
    }
    match submission.receipt {
        AdapterReceiptRefV1::Native(effects) => {
            if effects.source_file_read_count != 1
                || effects.target_process_count != 0
                || effects.network_call_count != 0
                || effects.write_count != 0
                || effects.executed_target_content
                || !submission.source_locators.is_empty()
            {
                return Err(AdapterVerifierErrorV1::ReceiptMismatch);
            }
        }
        AdapterReceiptRefV1::Scip(receipt) => {
            receipt
                .validate()
                .map_err(|_| AdapterVerifierErrorV1::ReceiptMismatch)?;
            if receipt.source_snapshot_sha256 != submission.bundle.source_snapshot_sha256
                || receipt.adapter_descriptor_sha256 != submission.descriptor.descriptor_sha256
                || receipt.bundle_sha256 != submission.bundle.bundle_sha256
                || receipt.document_count != count(submission.source_files.len())?
                || receipt.symbol_count != count(submission.bundle.nodes.len())?
                || receipt.relationship_count != count(submission.bundle.edges.len())?
                || receipt.discovered_count != submission.bundle.discovered_count
                || receipt.admitted_count != submission.bundle.admitted_count
                || receipt.omitted_count != submission.bundle.omitted_count
                || receipt.target_execution_count != 0
                || receipt.network_call_count != 0
                || receipt.write_count != 0
                || receipt.canonical_write_count != 0
            {
                return Err(AdapterVerifierErrorV1::ReceiptMismatch);
            }
        }
        AdapterReceiptRefV1::Lsp(receipt) => {
            receipt
                .validate()
                .map_err(|_| AdapterVerifierErrorV1::ReceiptMismatch)?;
            let symbol_count = count(
                submission
                    .bundle
                    .nodes
                    .iter()
                    .filter(|node| node.node_kind.starts_with("lsp.symbol."))
                    .count(),
            )?;
            let diagnostic_count = count(
                submission
                    .bundle
                    .nodes
                    .iter()
                    .filter(|node| node.node_kind.starts_with("lsp.diagnostic."))
                    .count(),
            )?;
            if receipt.source_snapshot_sha256 != submission.bundle.source_snapshot_sha256
                || receipt.adapter_descriptor_sha256 != submission.descriptor.descriptor_sha256
                || receipt.bundle_sha256 != submission.bundle.bundle_sha256
                || receipt.document_count != count(submission.source_files.len())?
                || receipt.symbol_count != symbol_count
                || receipt.diagnostic_count != diagnostic_count
                || receipt.relationship_count != count(submission.bundle.edges.len())?
                || receipt.source_range_count != count(submission.bundle.evidence.len())?
                || receipt.discovered_count != submission.bundle.discovered_count
                || receipt.admitted_count != submission.bundle.admitted_count
                || receipt.omitted_count != submission.bundle.omitted_count
                || receipt.lsp_server_invocation_count != 0
                || receipt.json_rpc_request_count != 0
                || receipt.json_rpc_response_count != 0
                || receipt.target_execution_count != 0
                || receipt.network_call_count != 0
                || receipt.write_count != 0
                || receipt.canonical_write_count != 0
            {
                return Err(AdapterVerifierErrorV1::ReceiptMismatch);
            }
        }
        AdapterReceiptRefV1::CodeGraph(receipt) => {
            receipt
                .validate()
                .map_err(|_| AdapterVerifierErrorV1::ReceiptMismatch)?;
            let fact_count = checked_add(
                count(submission.bundle.nodes.len())?,
                count(submission.bundle.edges.len())?,
            )?;
            if receipt.source_snapshot_sha256 != submission.bundle.source_snapshot_sha256
                || receipt.adapter_descriptor_sha256 != submission.descriptor.descriptor_sha256
                || receipt.bundle_sha256 != submission.bundle.bundle_sha256
                || receipt.node_count != count(submission.bundle.nodes.len())?
                || receipt.link_count != count(submission.bundle.edges.len())?
                || receipt.discovered_count != submission.bundle.discovered_count
                || receipt.admitted_count != submission.bundle.admitted_count
                || receipt.omitted_count != submission.bundle.omitted_count
                || receipt.source_evidence_count != count(submission.bundle.evidence.len())?
                || receipt.locator_only_count != fact_count
                || receipt.export_file_read_count != 1
                || receipt.target_execution_count != 0
                || receipt.network_call_count != 0
                || receipt.write_count != 0
                || receipt.canonical_write_count != 0
                || !submission.source_files.is_empty()
            {
                return Err(AdapterVerifierErrorV1::ReceiptMismatch);
            }
        }
        AdapterReceiptRefV1::GraphifyV2(receipt) => {
            receipt
                .validate()
                .map_err(|_| AdapterVerifierErrorV1::ReceiptMismatch)?;
            validate_graphify_receipt_against(submission, receipt)?;
        }
    }
    Ok(())
}

fn validate_graphify_receipt_against(
    submission: &AdapterSubmissionV1<'_>,
    receipt: &GraphifyImportReceiptV2,
) -> Result<(), AdapterVerifierErrorV1> {
    let mut extracted = 0_u64;
    let mut inferred = 0_u64;
    let mut ambiguous = 0_u64;
    for edge in &submission.bundle.edges {
        match edge.trust_state {
            FactTrustStateV1::Extracted => extracted = checked_add(extracted, 1)?,
            FactTrustStateV1::Inferred => inferred = checked_add(inferred, 1)?,
            FactTrustStateV1::Ambiguous => ambiguous = checked_add(ambiguous, 1)?,
            FactTrustStateV1::Unverified => {
                return Err(AdapterVerifierErrorV1::ReceiptMismatch);
            }
        }
    }
    for omission in &submission.bundle.omissions {
        if omission.reason.contains("_extracted_") {
            extracted = checked_add(extracted, 1)?;
        } else if omission.reason.contains("_inferred_") {
            inferred = checked_add(inferred, 1)?;
        } else if omission.reason.contains("_ambiguous_") {
            ambiguous = checked_add(ambiguous, 1)?;
        } else {
            return Err(AdapterVerifierErrorV1::ReceiptMismatch);
        }
    }
    let fact_ids = submission
        .bundle
        .nodes
        .iter()
        .map(|node| (node.fact_id.as_str(), node.candidate_state))
        .chain(
            submission
                .bundle
                .edges
                .iter()
                .map(|edge| (edge.fact_id.as_str(), edge.candidate_state)),
        )
        .collect::<BTreeMap<_, _>>();
    let mut locator_fact_ids = BTreeSet::new();
    for locator in submission.source_locators {
        if locator.source_logical_path.trim().is_empty()
            || locator.source_location.trim().is_empty()
            || !locator_fact_ids.insert(locator.fact_id.as_str())
            || !fact_ids.contains_key(locator.fact_id.as_str())
            || fact_ids.get(locator.fact_id.as_str()) == Some(&CandidateFactStateV1::LocatorOnly)
        {
            return Err(AdapterVerifierErrorV1::ReceiptMismatch);
        }
    }
    if fact_ids.iter().any(|(fact_id, state)| {
        *state == CandidateFactStateV1::CandidateExternal && !locator_fact_ids.contains(*fact_id)
    }) {
        return Err(AdapterVerifierErrorV1::ReceiptMismatch);
    }
    let locator_only_count = count(
        submission
            .bundle
            .nodes
            .iter()
            .filter(|node| node.candidate_state == CandidateFactStateV1::LocatorOnly)
            .count()
            + submission
                .bundle
                .edges
                .iter()
                .filter(|edge| edge.candidate_state == CandidateFactStateV1::LocatorOnly)
                .count(),
    )?;
    let source_locator_count = count(submission.source_locators.len())?;
    if receipt.source_snapshot_sha256 != submission.bundle.source_snapshot_sha256
        || receipt.adapter_descriptor_sha256 != submission.descriptor.descriptor_sha256
        || receipt.bundle_sha256 != submission.bundle.bundle_sha256
        || receipt.node_count != count(submission.bundle.nodes.len())?
        || receipt.link_count != count(submission.bundle.edges.len())?
        || receipt.hyperedge_count != submission.bundle.omitted_count
        || receipt.dual_slot_hyperedge_count != submission.bundle.omitted_count
        || receipt.discovered_count != submission.bundle.discovered_count
        || receipt.admitted_count != submission.bundle.admitted_count
        || receipt.omitted_count != submission.bundle.omitted_count
        || receipt.extracted_relationship_count != extracted
        || receipt.inferred_relationship_count != inferred
        || receipt.ambiguous_relationship_count != ambiguous
        || receipt.source_locator_count != source_locator_count
        || receipt.missing_source_location_count
            != submission
                .bundle
                .admitted_count
                .checked_sub(source_locator_count)
                .ok_or(AdapterVerifierErrorV1::ReceiptMismatch)?
        || receipt.locator_only_count != locator_only_count
        || receipt.export_file_read_count != 1
        || receipt.target_execution_count != 0
        || receipt.provider_call_count != 0
        || receipt.network_call_count != 0
        || receipt.write_count != 0
        || receipt.canonical_write_count != 0
        || !submission.source_files.is_empty()
        || !submission.bundle.evidence.is_empty()
    {
        return Err(AdapterVerifierErrorV1::ReceiptMismatch);
    }
    Ok(())
}

#[derive(Serialize)]
struct AdapterInputIdentityV1 {
    adapter_kind: AdapterKindV1,
    adapter_descriptor_sha256: String,
    bundle_sha256: String,
    receipt_sha256: String,
    input_file_bytes: u64,
    configured_max_file_bytes: u64,
    source_files: Vec<(String, String)>,
    source_locators_sha256: String,
}

fn input_identity(
    submission: &AdapterSubmissionV1<'_>,
) -> Result<AdapterInputIdentityV1, AdapterVerifierErrorV1> {
    let source_files = submission
        .source_files
        .iter()
        .map(|(path, bytes)| (path.clone(), sha256(bytes)))
        .collect::<Vec<_>>();
    let source_locators_sha256 = canonical_json_sha256(&submission.source_locators)
        .map_err(|_| AdapterVerifierErrorV1::GateReceiptInvalid)?;
    Ok(AdapterInputIdentityV1 {
        adapter_kind: submission.descriptor.kind,
        adapter_descriptor_sha256: submission.descriptor.descriptor_sha256.clone(),
        bundle_sha256: submission.bundle.bundle_sha256.clone(),
        receipt_sha256: submission.receipt.identity_sha256()?,
        input_file_bytes: submission.input_file_bytes,
        configured_max_file_bytes: submission.configured_max_file_bytes,
        source_files,
        source_locators_sha256,
    })
}

fn adapter_rank(kind: AdapterKindV1) -> u8 {
    match kind {
        AdapterKindV1::Native => 0,
        AdapterKindV1::Scip => 1,
        AdapterKindV1::LspSnapshot => 2,
        AdapterKindV1::CodeGraphExport => 3,
        AdapterKindV1::GraphifyExport => 4,
    }
}

fn checked_add(left: u64, right: u64) -> Result<u64, AdapterVerifierErrorV1> {
    left.checked_add(right)
        .ok_or(AdapterVerifierErrorV1::ContractInvalid)
}

fn count(value: usize) -> Result<u64, AdapterVerifierErrorV1> {
    u64::try_from(value).map_err(|_| AdapterVerifierErrorV1::ContractInvalid)
}

fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn digest_without_field<T: Serialize>(
    value: &T,
    field: &str,
) -> Result<String, AdapterVerifierErrorV1> {
    let mut encoded =
        serde_json::to_value(value).map_err(|_| AdapterVerifierErrorV1::GateReceiptInvalid)?;
    encoded
        .as_object_mut()
        .ok_or(AdapterVerifierErrorV1::GateReceiptInvalid)?
        .remove(field);
    canonical_json_sha256(&encoded).map_err(|_| AdapterVerifierErrorV1::GateReceiptInvalid)
}

fn strictly_sorted_unique(values: &[String]) -> bool {
    values
        .windows(2)
        .all(|pair| pair[0].as_str() < pair[1].as_str())
}
