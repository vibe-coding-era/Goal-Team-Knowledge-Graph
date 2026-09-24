//! P02 deterministic, file-only analysis orchestration.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

use gtkg_protocol::v2::{
    AnalysisAdapterInputV2, AnalysisBuildPayloadV2, AnalysisPlanPayloadV2, AnalysisVerifyPayloadV2,
    CodeGraphAnalysisPinV2, GraphifyAnalysisPinV2, LspSnapshotAnalysisPinV2, ScipAnalysisPinV2,
    SourceSnapshotV2, V2ErrorCode,
};
use gtkg_protocol::v03::AdapterKindV1;
use gtkg_protocol::v03::adapter::{
    AdapterDescriptorV1, ExternalFactBundleV1, VerifiedFactReceiptV1, VerifiedResolutionV1,
};
use gtkg_protocol::{FileReceiptRef, canonical_json_sha256};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::durable::{DurableErrorKind, publish_immutable_json};
use crate::exact_read::{ExactReadFailure, read_bound_regular_file};
use crate::v03::adapter::codegraph::{CodeGraphExportPinV1, import_pinned_codegraph_json_file_v1};
use crate::v03::adapter::graphify::{GraphifyGraphPinV2, import_pinned_graphify_json_file_v2};
use crate::v03::adapter::lsp_snapshot::{
    LspSnapshotFilePinV1, import_pinned_lsp_snapshot_json_file_v1,
};
use crate::v03::adapter::native::adapt_native_path_v1;
use crate::v03::adapter::scip::{ScipFilePinV1, import_pinned_scip_json_file_v1};
use crate::v03::adapter::verify_external_fact_bundle_v1;
use crate::{CallContext, ContextError};

const PLAN_SCHEMA: &str = "gtkg.analysis-plan/v1";
const CANDIDATE_SCHEMA: &str = "gtkg.typed-candidate-ir/v1";
const VERIFICATION_SCHEMA: &str = "gtkg.analysis-verification/v1";
const MAX_ANALYSIS_INPUT_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug)]
pub(crate) struct AnalysisFailureV1 {
    pub code: V2ErrorCode,
    pub stage: &'static str,
    pub message: String,
    pub recovery_hint: &'static str,
}

#[derive(Debug)]
pub(crate) struct AnalysisResultV1 {
    pub reference: FileReceiptRef,
    pub summary: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PlannedAdapterV1 {
    selection_id: String,
    input: AnalysisAdapterInputV2,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AnalysisPlanV1 {
    schema_version: String,
    workspace_root: PathBuf,
    source_root: PathBuf,
    source_snapshot_ref: FileReceiptRef,
    source_snapshot_artifact_sha256: String,
    source_snapshot_exact_set_sha256: String,
    adapters: Vec<PlannedAdapterV1>,
    selection_exact_set_sha256: String,
    target_execution_count: u64,
    network_call_count: u64,
    provider_call_count: u64,
    canonical_write_count: u64,
    plan_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceDigestV1 {
    logical_path: String,
    sha256: String,
    bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdapterEffectsV1 {
    source_file_read_count: u64,
    target_execution_count: u64,
    process_count: u64,
    network_call_count: u64,
    provider_call_count: u64,
    adapter_write_count: u64,
    canonical_write_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdapterRunV1 {
    selection_id: String,
    adapter_kind: AdapterKindV1,
    input_sha256: String,
    descriptor: AdapterDescriptorV1,
    bundle: ExternalFactBundleV1,
    import_receipt: Value,
    source_file_digests: Vec<SourceDigestV1>,
    source_locators: Value,
    effects: AdapterEffectsV1,
}

struct ExecutedAdapterV1 {
    artifact: AdapterRunV1,
    source_files: BTreeMap<String, Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CandidateArtifactV1 {
    schema_version: String,
    plan_ref: FileReceiptRef,
    plan_sha256: String,
    source_snapshot_exact_set_sha256: String,
    adapter_runs: Vec<AdapterRunV1>,
    discovered_count: u64,
    admitted_count: u64,
    omitted_count: u64,
    target_execution_count: u64,
    network_call_count: u64,
    provider_call_count: u64,
    adapter_write_count: u64,
    canonical_write_count: u64,
    a06_cross_adapter_status: String,
    collision_check: String,
    canonical_eligible: bool,
    candidate_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct VerificationRunV1 {
    selection_id: String,
    adapter_descriptor_sha256: String,
    bundle_sha256: String,
    fact_receipts: Vec<VerifiedFactReceiptV1>,
    resolved_verified_count: u64,
    ambiguous_count: u64,
    locator_only_count: u64,
    false_confirmed: u64,
    canonical_write_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct VerificationArtifactV1 {
    schema_version: String,
    candidate_ref: FileReceiptRef,
    candidate_sha256: String,
    plan_sha256: String,
    source_snapshot_exact_set_sha256: String,
    adapter_verifications: Vec<VerificationRunV1>,
    resolved_verified_count: u64,
    ambiguous_count: u64,
    locator_only_count: u64,
    false_confirmed: u64,
    target_execution_count: u64,
    network_call_count: u64,
    provider_call_count: u64,
    canonical_write_count: u64,
    current_write_count: u64,
    a06_cross_adapter_status: String,
    collision_check: String,
    canonical_eligible: bool,
    verification_sha256: String,
}

pub(crate) fn plan(
    context: &CallContext,
    payload: AnalysisPlanPayloadV2,
) -> Result<AnalysisResultV1, AnalysisFailureV1> {
    let workspace = context
        .authorize_write(&payload.workspace_root)
        .map_err(context_failure)?;
    let source_root = context
        .authorize_read(&payload.source_root)
        .map_err(context_failure)?;
    let (_, snapshot) = load_snapshot(context, &workspace, &payload.source_snapshot_ref)?;
    let mut adapters = payload
        .adapter_inputs
        .into_iter()
        .map(|input| normalize_input(context, input, &snapshot))
        .collect::<Result<Vec<_>, _>>()?;
    adapters.sort_by(|left, right| left.selection_id.cmp(&right.selection_id));
    if adapters
        .windows(2)
        .any(|pair| pair[0].selection_id == pair[1].selection_id)
    {
        return Err(invalid("analysis.plan", "duplicate adapter selection"));
    }
    validate_native_coverage(&adapters, &snapshot)?;
    let selection_ids = adapters
        .iter()
        .map(|adapter| adapter.selection_id.as_str())
        .collect::<Vec<_>>();
    let selection_exact_set_sha256 = canonical_json_sha256(&selection_ids)
        .map_err(|error| invalid("analysis.plan", error.to_string()))?;
    let mut plan = AnalysisPlanV1 {
        schema_version: PLAN_SCHEMA.to_owned(),
        workspace_root: workspace.clone(),
        source_root,
        source_snapshot_ref: payload.source_snapshot_ref.clone(),
        source_snapshot_artifact_sha256: payload.source_snapshot_ref.sha256,
        source_snapshot_exact_set_sha256: snapshot.exact_set_sha256,
        adapters,
        selection_exact_set_sha256,
        target_execution_count: 0,
        network_call_count: 0,
        provider_call_count: 0,
        canonical_write_count: 0,
        plan_sha256: String::new(),
    };
    plan.plan_sha256 = digest_without(&plan, "plan_sha256", "analysis.plan")?;
    let path = workspace.join(format!(
        ".gtkg/analysis/plans/{}.json",
        digest_hex(&plan.plan_sha256)?
    ));
    let reference = publish(context, &workspace, &path, &plan, "analysis.plan")?;
    Ok(AnalysisResultV1 {
        reference: reference.clone(),
        summary: json!({
            "plan_ref": reference,
            "plan_sha256": plan.plan_sha256,
            "source_snapshot_exact_set_sha256": plan.source_snapshot_exact_set_sha256,
            "adapter_selection_count": plan.adapters.len(),
            "selection_exact_set_sha256": plan.selection_exact_set_sha256,
            "target_execution_count": 0,
            "network_call_count": 0,
            "provider_call_count": 0,
            "canonical_write_count": 0,
        }),
    })
}

pub(crate) fn build(
    context: &CallContext,
    payload: AnalysisBuildPayloadV2,
) -> Result<AnalysisResultV1, AnalysisFailureV1> {
    let workspace = context
        .authorize_write(&payload.workspace_root)
        .map_err(context_failure)?;
    let plan: AnalysisPlanV1 =
        load_artifact(context, &workspace, &payload.plan_ref, "analysis.build")?;
    validate_plan(&plan)?;
    if plan.workspace_root != workspace {
        return Err(invalid_state(
            "analysis.build",
            "analysis plan is bound to a different workspace root",
        ));
    }
    validate_semantic_reference(
        &payload.plan_ref,
        "plans",
        &plan.plan_sha256,
        "analysis.build",
    )?;
    let (_, snapshot) = load_snapshot(context, &workspace, &plan.source_snapshot_ref)?;
    if snapshot.exact_set_sha256 != plan.source_snapshot_exact_set_sha256 {
        return Err(source_changed(
            "analysis.build",
            "source snapshot identity drifted",
        ));
    }
    let executions = execute_adapters(context, &plan, &snapshot)?;
    let candidate = candidate_from(&plan, payload.plan_ref.clone(), &executions)?;
    let path = workspace.join(format!(
        ".gtkg/analysis/candidates/{}.json",
        digest_hex(&candidate.candidate_sha256)?
    ));
    let reference = publish(context, &workspace, &path, &candidate, "analysis.build")?;
    Ok(AnalysisResultV1 {
        reference: reference.clone(),
        summary: json!({
            "candidate_ref": reference,
            "candidate_sha256": candidate.candidate_sha256,
            "adapter_run_count": candidate.adapter_runs.len(),
            "discovered_count": candidate.discovered_count,
            "admitted_count": candidate.admitted_count,
            "omitted_count": candidate.omitted_count,
            "target_execution_count": 0,
            "network_call_count": 0,
            "provider_call_count": 0,
            "adapter_write_count": 0,
            "canonical_write_count": 0,
            "a06_cross_adapter_status": "not_run",
            "collision_check": "not_run",
            "canonical_eligible": false,
        }),
    })
}

pub(crate) fn verify(
    context: &CallContext,
    payload: AnalysisVerifyPayloadV2,
) -> Result<AnalysisResultV1, AnalysisFailureV1> {
    let workspace = context
        .authorize_write(&payload.workspace_root)
        .map_err(context_failure)?;
    let receipt = replay_verification(context, &workspace, payload.candidate_ref)?;
    let path = workspace.join(format!(
        ".gtkg/analysis/verifications/{}.json",
        digest_hex(&receipt.verification_sha256)?
    ));
    let reference = publish(context, &workspace, &path, &receipt, "analysis.verify")?;
    Ok(AnalysisResultV1 {
        reference: reference.clone(),
        summary: json!({
            "verification_ref": reference,
            "verification_sha256": receipt.verification_sha256,
            "resolved_verified_count": receipt.resolved_verified_count,
            "ambiguous_count": receipt.ambiguous_count,
            "locator_only_count": receipt.locator_only_count,
            "false_confirmed": receipt.false_confirmed,
            "target_execution_count": 0,
            "network_call_count": 0,
            "provider_call_count": 0,
            "canonical_write_count": 0,
            "current_write_count": 0,
            "a06_cross_adapter_status": "not_run",
            "collision_check": "not_run",
            "canonical_eligible": false,
        }),
    })
}

/// Read-only replay validation for P03 and later consumers. A persisted P02
/// verification cannot self-prove: the candidate, plan, snapshot, adapter
/// imports, source join, and every per-fact receipt are rebuilt before the
/// exact verification artifact is returned.
pub(crate) fn validate_verification_chain_v1(
    context: &CallContext,
    workspace_root: &Path,
    reference: &FileReceiptRef,
) -> Result<Value, AnalysisFailureV1> {
    let workspace = context
        .authorize_read(workspace_root)
        .map_err(context_failure)?;
    let observed: VerificationArtifactV1 =
        load_artifact(context, &workspace, reference, "analysis.validate-chain")?;
    validate_semantic_reference(
        reference,
        "verifications",
        &observed.verification_sha256,
        "analysis.validate-chain",
    )?;
    let expected = replay_verification(context, &workspace, observed.candidate_ref.clone())?;
    if observed != expected {
        return Err(invalid_state(
            "analysis.validate-chain",
            "persisted verification differs from adapter/source replay",
        ));
    }
    serde_json::to_value(observed)
        .map_err(|error| invalid_state("analysis.validate-chain", error.to_string()))
}

fn replay_verification(
    context: &CallContext,
    workspace: &Path,
    candidate_ref: FileReceiptRef,
) -> Result<VerificationArtifactV1, AnalysisFailureV1> {
    let candidate: CandidateArtifactV1 =
        load_artifact(context, workspace, &candidate_ref, "analysis.verify")?;
    validate_candidate(&candidate)?;
    validate_semantic_reference(
        &candidate_ref,
        "candidates",
        &candidate.candidate_sha256,
        "analysis.verify",
    )?;
    let plan: AnalysisPlanV1 =
        load_artifact(context, workspace, &candidate.plan_ref, "analysis.verify")?;
    validate_plan(&plan)?;
    if plan.workspace_root != workspace {
        return Err(invalid_state(
            "analysis.verify",
            "analysis plan is bound to a different workspace root",
        ));
    }
    if plan.plan_sha256 != candidate.plan_sha256 {
        return Err(invalid_state(
            "analysis.verify",
            "candidate plan identity drifted",
        ));
    }
    let (_, snapshot) = load_snapshot(context, workspace, &plan.source_snapshot_ref)?;
    let executions = execute_adapters(context, &plan, &snapshot)?;
    let replayed = candidate_from(&plan, candidate.plan_ref.clone(), &executions)?;
    if replayed != candidate {
        return Err(source_changed(
            "analysis.verify",
            "adapter replay differs from the immutable candidate",
        ));
    }
    let mut runs = Vec::new();
    for execution in executions {
        let verification = verify_external_fact_bundle_v1(
            &execution.artifact.descriptor,
            &execution.artifact.descriptor,
            &execution.artifact.bundle,
            &execution.source_files,
            "gtkg.verifier/p02",
        )
        .map_err(|error| bundle("analysis.verify", error.to_string()))?;
        if verification.false_confirmed != 0 || verification.canonical_write_count != 0 {
            return Err(bundle(
                "analysis.verify",
                "per-bundle verifier reported a forbidden confirmation or canonical write",
            ));
        }
        for receipt in &verification.receipts {
            receipt
                .validate()
                .map_err(|error| bundle("analysis.verify", error.to_string()))?;
        }
        let resolved_verified_count = verification.resolved_verified_fact_ids.len() as u64;
        let ambiguous_count = verification
            .receipts
            .iter()
            .filter(|receipt| receipt.resolution == VerifiedResolutionV1::Ambiguous)
            .count() as u64;
        let locator_only_count = verification
            .receipts
            .iter()
            .filter(|receipt| receipt.resolution == VerifiedResolutionV1::LocatorOnly)
            .count() as u64;
        runs.push(VerificationRunV1 {
            selection_id: execution.artifact.selection_id,
            adapter_descriptor_sha256: execution.artifact.descriptor.descriptor_sha256,
            bundle_sha256: execution.artifact.bundle.bundle_sha256,
            fact_receipts: verification.receipts,
            resolved_verified_count,
            ambiguous_count,
            locator_only_count,
            false_confirmed: verification.false_confirmed,
            canonical_write_count: verification.canonical_write_count,
        });
    }
    let mut receipt = VerificationArtifactV1 {
        schema_version: VERIFICATION_SCHEMA.to_owned(),
        candidate_ref,
        candidate_sha256: candidate.candidate_sha256,
        plan_sha256: plan.plan_sha256,
        source_snapshot_exact_set_sha256: snapshot.exact_set_sha256,
        resolved_verified_count: sum(&runs, |run| run.resolved_verified_count)?,
        ambiguous_count: sum(&runs, |run| run.ambiguous_count)?,
        locator_only_count: sum(&runs, |run| run.locator_only_count)?,
        false_confirmed: sum(&runs, |run| run.false_confirmed)?,
        canonical_write_count: sum(&runs, |run| run.canonical_write_count)?,
        adapter_verifications: runs,
        target_execution_count: 0,
        network_call_count: 0,
        provider_call_count: 0,
        current_write_count: 0,
        a06_cross_adapter_status: "not_run".to_owned(),
        collision_check: "not_run".to_owned(),
        canonical_eligible: false,
        verification_sha256: String::new(),
    };
    receipt.verification_sha256 =
        digest_without(&receipt, "verification_sha256", "analysis.verify")?;
    Ok(receipt)
}

fn normalize_input(
    context: &CallContext,
    input: AnalysisAdapterInputV2,
    snapshot: &SourceSnapshotV2,
) -> Result<PlannedAdapterV1, AnalysisFailureV1> {
    let input = match input {
        AnalysisAdapterInputV2::Native { logical_path } => {
            if !snapshot
                .inventory
                .iter()
                .any(|entry| entry.logical_path == logical_path)
            {
                return Err(source_changed(
                    "analysis.plan",
                    "native path is absent from snapshot",
                ));
            }
            AnalysisAdapterInputV2::Native { logical_path }
        }
        AnalysisAdapterInputV2::Codegraph { input_path, pin } => {
            require_source_pin(&pin.source_snapshot_sha256, snapshot)?;
            let converted = codegraph_pin(&pin);
            converted
                .validate()
                .map_err(|error| invalid("analysis.plan", error.to_string()))?;
            let input_path = normalize_input_path(context, &input_path, pin.max_file_bytes)?;
            AnalysisAdapterInputV2::Codegraph { input_path, pin }
        }
        AnalysisAdapterInputV2::Scip {
            input_path,
            mut pin,
        } => {
            bind_selected_snapshot(&mut pin.selected_source_snapshot_sha256, snapshot, "SCIP")?;
            scip_pin(&pin)
                .validate()
                .map_err(|error| invalid("analysis.plan", error.to_string()))?;
            let input_path = normalize_input_path(context, &input_path, pin.max_file_bytes)?;
            AnalysisAdapterInputV2::Scip { input_path, pin }
        }
        AnalysisAdapterInputV2::LspSnapshot {
            input_path,
            mut pin,
        } => {
            bind_selected_snapshot(&mut pin.selected_source_snapshot_sha256, snapshot, "LSP")?;
            lsp_pin(&pin)
                .validate()
                .map_err(|error| invalid("analysis.plan", error.to_string()))?;
            let input_path = normalize_input_path(context, &input_path, pin.max_file_bytes)?;
            AnalysisAdapterInputV2::LspSnapshot { input_path, pin }
        }
        AnalysisAdapterInputV2::Graphify { input_path, pin } => {
            require_source_pin(&pin.source_snapshot_sha256, snapshot)?;
            graphify_pin(&pin)
                .validate()
                .map_err(|error| invalid("analysis.plan", error.to_string()))?;
            let input_path = normalize_input_path(context, &input_path, pin.max_file_bytes)?;
            AnalysisAdapterInputV2::Graphify { input_path, pin }
        }
    };
    let selection_id = canonical_json_sha256(&input)
        .map_err(|error| invalid("analysis.plan", error.to_string()))?;
    Ok(PlannedAdapterV1 {
        selection_id,
        input,
    })
}

fn execute_adapters(
    context: &CallContext,
    plan: &AnalysisPlanV1,
    snapshot: &SourceSnapshotV2,
) -> Result<Vec<ExecutedAdapterV1>, AnalysisFailureV1> {
    let mut runs = Vec::new();
    for adapter in &plan.adapters {
        let execution = match &adapter.input {
            AnalysisAdapterInputV2::Native { logical_path } => {
                execute_native(context, plan, snapshot, adapter, logical_path)?
            }
            AnalysisAdapterInputV2::Codegraph { input_path, pin } => {
                execute_codegraph(context, adapter, input_path, pin)?
            }
            AnalysisAdapterInputV2::Scip { input_path, pin } => {
                execute_scip(context, plan, snapshot, adapter, input_path, pin)?
            }
            AnalysisAdapterInputV2::LspSnapshot { input_path, pin } => {
                execute_lsp(context, plan, snapshot, adapter, input_path, pin)?
            }
            AnalysisAdapterInputV2::Graphify { input_path, pin } => {
                execute_graphify(context, adapter, input_path, pin)?
            }
        };
        runs.push(execution);
    }
    Ok(runs)
}

fn execute_scip(
    context: &CallContext,
    plan: &AnalysisPlanV1,
    snapshot: &SourceSnapshotV2,
    adapter: &PlannedAdapterV1,
    input_path: &Path,
    pin: &ScipAnalysisPinV2,
) -> Result<ExecutedAdapterV1, AnalysisFailureV1> {
    let before = read_bound_regular_file(context, input_path).map_err(exact_failure)?;
    let output = import_pinned_scip_json_file_v1(input_path, &scip_pin(pin))
        .map_err(|error| bundle("analysis.build", error.to_string()))?;
    output
        .receipt
        .validate()
        .map_err(|error| bundle("analysis.build", error.to_string()))?;
    validate_external_sources(context, plan, snapshot, &output.source_files)?;
    ensure_input_unchanged(
        context,
        input_path,
        &before.sha256,
        &pin.file_sha256,
        "SCIP",
    )?;
    let source_file_digests = source_digests(&output.source_files);
    Ok(ExecutedAdapterV1 {
        artifact: AdapterRunV1 {
            selection_id: adapter.selection_id.clone(),
            adapter_kind: AdapterKindV1::Scip,
            input_sha256: before.sha256,
            descriptor: output.descriptor,
            bundle: output.bundle,
            import_receipt: serde_json::to_value(output.receipt)
                .map_err(|error| invalid("analysis.build", error.to_string()))?,
            source_file_digests,
            source_locators: json!([]),
            effects: zero_adapter_effects(1),
        },
        source_files: output.source_files,
    })
}

fn execute_lsp(
    context: &CallContext,
    plan: &AnalysisPlanV1,
    snapshot: &SourceSnapshotV2,
    adapter: &PlannedAdapterV1,
    input_path: &Path,
    pin: &LspSnapshotAnalysisPinV2,
) -> Result<ExecutedAdapterV1, AnalysisFailureV1> {
    let before = read_bound_regular_file(context, input_path).map_err(exact_failure)?;
    let output = import_pinned_lsp_snapshot_json_file_v1(input_path, &lsp_pin(pin))
        .map_err(|error| bundle("analysis.build", error.to_string()))?;
    output
        .receipt
        .validate()
        .map_err(|error| bundle("analysis.build", error.to_string()))?;
    validate_external_sources(context, plan, snapshot, &output.source_files)?;
    ensure_input_unchanged(context, input_path, &before.sha256, &pin.file_sha256, "LSP")?;
    let source_file_digests = source_digests(&output.source_files);
    Ok(ExecutedAdapterV1 {
        artifact: AdapterRunV1 {
            selection_id: adapter.selection_id.clone(),
            adapter_kind: AdapterKindV1::LspSnapshot,
            input_sha256: before.sha256,
            descriptor: output.descriptor,
            bundle: output.bundle,
            import_receipt: serde_json::to_value(output.receipt)
                .map_err(|error| invalid("analysis.build", error.to_string()))?,
            source_file_digests,
            source_locators: json!([]),
            effects: zero_adapter_effects(1),
        },
        source_files: output.source_files,
    })
}

fn execute_graphify(
    context: &CallContext,
    adapter: &PlannedAdapterV1,
    input_path: &Path,
    pin: &GraphifyAnalysisPinV2,
) -> Result<ExecutedAdapterV1, AnalysisFailureV1> {
    let before = read_bound_regular_file(context, input_path).map_err(exact_failure)?;
    let output = import_pinned_graphify_json_file_v2(input_path, &graphify_pin(pin))
        .map_err(|error| bundle("analysis.build", error.to_string()))?;
    output
        .receipt
        .validate()
        .map_err(|error| bundle("analysis.build", error.to_string()))?;
    ensure_input_unchanged(
        context,
        input_path,
        &before.sha256,
        &pin.file_sha256,
        "Graphify",
    )?;
    Ok(ExecutedAdapterV1 {
        artifact: AdapterRunV1 {
            selection_id: adapter.selection_id.clone(),
            adapter_kind: AdapterKindV1::GraphifyExport,
            input_sha256: before.sha256,
            descriptor: output.descriptor,
            bundle: output.bundle,
            import_receipt: serde_json::to_value(output.receipt)
                .map_err(|error| invalid("analysis.build", error.to_string()))?,
            source_file_digests: Vec::new(),
            source_locators: serde_json::to_value(output.source_locators)
                .map_err(|error| invalid("analysis.build", error.to_string()))?,
            effects: zero_adapter_effects(1),
        },
        source_files: BTreeMap::new(),
    })
}

fn execute_native(
    context: &CallContext,
    plan: &AnalysisPlanV1,
    snapshot: &SourceSnapshotV2,
    adapter: &PlannedAdapterV1,
    logical_path: &str,
) -> Result<ExecutedAdapterV1, AnalysisFailureV1> {
    let path = safe_join(&plan.source_root, logical_path)?;
    let before = read_bound_regular_file(context, &path).map_err(exact_failure)?;
    let entry = snapshot
        .inventory
        .iter()
        .find(|entry| entry.logical_path == logical_path)
        .ok_or_else(|| source_changed("analysis.build", "native path left the snapshot"))?;
    if before.sha256 != entry.content_sha256 || before.bytes.len() as u64 != entry.bytes {
        return Err(source_changed(
            "analysis.build",
            "native source bytes drifted",
        ));
    }
    let output = adapt_native_path_v1(snapshot, logical_path, &path)
        .map_err(|error| bundle("analysis.build", error.to_string()))?;
    let after = read_bound_regular_file(context, &path).map_err(exact_failure)?;
    if before.sha256 != after.sha256 || before.bytes != after.bytes {
        return Err(source_changed(
            "analysis.build",
            "native source changed during adapter run",
        ));
    }
    let source_files = BTreeMap::from([(logical_path.to_owned(), before.bytes)]);
    let artifact = AdapterRunV1 {
        selection_id: adapter.selection_id.clone(),
        adapter_kind: AdapterKindV1::Native,
        input_sha256: before.sha256,
        descriptor: output.descriptor,
        bundle: output.bundle,
        import_receipt: json!({
            "schema_version": "gtkg.native-adapter-receipt/v1",
            "source_file_read_count": output.effects.source_file_read_count,
            "target_process_count": output.effects.target_process_count,
            "network_call_count": output.effects.network_call_count,
            "write_count": output.effects.write_count,
            "executed_target_content": output.effects.executed_target_content,
        }),
        source_file_digests: source_digests(&source_files),
        source_locators: json!([]),
        effects: AdapterEffectsV1 {
            source_file_read_count: 1,
            target_execution_count: 0,
            process_count: 0,
            network_call_count: 0,
            provider_call_count: 0,
            adapter_write_count: 0,
            canonical_write_count: 0,
        },
    };
    Ok(ExecutedAdapterV1 {
        artifact,
        source_files,
    })
}

fn execute_codegraph(
    context: &CallContext,
    adapter: &PlannedAdapterV1,
    input_path: &Path,
    pin: &CodeGraphAnalysisPinV2,
) -> Result<ExecutedAdapterV1, AnalysisFailureV1> {
    let before = read_bound_regular_file(context, input_path).map_err(exact_failure)?;
    let converted = codegraph_pin(pin);
    let output = import_pinned_codegraph_json_file_v1(input_path, &converted)
        .map_err(|error| bundle("analysis.build", error.to_string()))?;
    output
        .receipt
        .validate()
        .map_err(|error| bundle("analysis.build", error.to_string()))?;
    let after = read_bound_regular_file(context, input_path).map_err(exact_failure)?;
    if before.sha256 != after.sha256 || before.sha256 != pin.file_sha256 {
        return Err(source_changed(
            "analysis.build",
            "CodeGraph export changed during import",
        ));
    }
    Ok(ExecutedAdapterV1 {
        artifact: AdapterRunV1 {
            selection_id: adapter.selection_id.clone(),
            adapter_kind: AdapterKindV1::CodeGraphExport,
            input_sha256: before.sha256,
            descriptor: output.descriptor,
            bundle: output.bundle,
            import_receipt: serde_json::to_value(output.receipt)
                .map_err(|error| invalid("analysis.build", error.to_string()))?,
            source_file_digests: Vec::new(),
            source_locators: json!([]),
            effects: AdapterEffectsV1 {
                source_file_read_count: 1,
                target_execution_count: 0,
                process_count: 0,
                network_call_count: 0,
                provider_call_count: 0,
                adapter_write_count: 0,
                canonical_write_count: 0,
            },
        },
        source_files: BTreeMap::new(),
    })
}

fn candidate_from(
    plan: &AnalysisPlanV1,
    plan_ref: FileReceiptRef,
    executions: &[ExecutedAdapterV1],
) -> Result<CandidateArtifactV1, AnalysisFailureV1> {
    let mut candidate = CandidateArtifactV1 {
        schema_version: CANDIDATE_SCHEMA.to_owned(),
        plan_ref,
        plan_sha256: plan.plan_sha256.clone(),
        source_snapshot_exact_set_sha256: plan.source_snapshot_exact_set_sha256.clone(),
        adapter_runs: executions.iter().map(|run| run.artifact.clone()).collect(),
        discovered_count: sum_runs(executions, |run| run.bundle.discovered_count)?,
        admitted_count: sum_runs(executions, |run| run.bundle.admitted_count)?,
        omitted_count: sum_runs(executions, |run| run.bundle.omitted_count)?,
        target_execution_count: 0,
        network_call_count: 0,
        provider_call_count: 0,
        adapter_write_count: 0,
        canonical_write_count: 0,
        a06_cross_adapter_status: "not_run".to_owned(),
        collision_check: "not_run".to_owned(),
        canonical_eligible: false,
        candidate_sha256: String::new(),
    };
    candidate.candidate_sha256 = digest_without(&candidate, "candidate_sha256", "analysis.build")?;
    Ok(candidate)
}

fn validate_plan(plan: &AnalysisPlanV1) -> Result<(), AnalysisFailureV1> {
    plan.source_snapshot_ref
        .validate()
        .map_err(|error| invalid_state("analysis.plan", error.to_string()))?;
    let mut previous = None;
    let mut observed_ids = Vec::with_capacity(plan.adapters.len());
    for adapter in &plan.adapters {
        let selected_snapshot_valid = match &adapter.input {
            AnalysisAdapterInputV2::Scip { pin, .. } => {
                pin.selected_source_snapshot_sha256.as_deref()
                    == Some(plan.source_snapshot_exact_set_sha256.as_str())
            }
            AnalysisAdapterInputV2::LspSnapshot { pin, .. } => {
                pin.selected_source_snapshot_sha256.as_deref()
                    == Some(plan.source_snapshot_exact_set_sha256.as_str())
            }
            AnalysisAdapterInputV2::Codegraph { pin, .. } => {
                pin.source_snapshot_sha256 == plan.source_snapshot_exact_set_sha256
            }
            AnalysisAdapterInputV2::Graphify { pin, .. } => {
                pin.source_snapshot_sha256 == plan.source_snapshot_exact_set_sha256
            }
            AnalysisAdapterInputV2::Native { .. } => true,
        };
        if adapter.selection_id
            != canonical_json_sha256(&adapter.input)
                .map_err(|error| invalid_state("analysis.plan", error.to_string()))?
            || previous.is_some_and(|value: &str| value >= adapter.selection_id.as_str())
            || !selected_snapshot_valid
        {
            return Err(invalid_state(
                "analysis.plan",
                "adapter selection identity/order is invalid",
            ));
        }
        previous = Some(adapter.selection_id.as_str());
        observed_ids.push(adapter.selection_id.as_str());
    }
    let selection_exact_set_sha256 = canonical_json_sha256(&observed_ids)
        .map_err(|error| invalid_state("analysis.plan", error.to_string()))?;
    if plan.schema_version != PLAN_SCHEMA
        || plan.adapters.is_empty()
        || !plan.workspace_root.is_absolute()
        || !plan.source_root.is_absolute()
        || plan.source_snapshot_ref.sha256 != plan.source_snapshot_artifact_sha256
        || plan.selection_exact_set_sha256 != selection_exact_set_sha256
        || plan.target_execution_count != 0
        || plan.network_call_count != 0
        || plan.provider_call_count != 0
        || plan.canonical_write_count != 0
        || plan.plan_sha256 != digest_without(plan, "plan_sha256", "analysis.plan")?
    {
        return Err(invalid_state(
            "analysis.plan",
            "analysis plan is invalid or tampered",
        ));
    }
    Ok(())
}

fn validate_semantic_reference(
    reference: &FileReceiptRef,
    partition: &str,
    semantic_sha256: &str,
    stage: &'static str,
) -> Result<(), AnalysisFailureV1> {
    let expected = format!(
        ".gtkg/analysis/{partition}/{}.json",
        digest_hex(semantic_sha256)?
    );
    if reference.path != expected {
        return Err(invalid_state(
            stage,
            "artifact path is not bound to its semantic digest",
        ));
    }
    Ok(())
}

fn validate_candidate(candidate: &CandidateArtifactV1) -> Result<(), AnalysisFailureV1> {
    let denominator_closed = candidate
        .admitted_count
        .checked_add(candidate.omitted_count)
        .is_some_and(|total| total == candidate.discovered_count);
    if candidate.schema_version != CANDIDATE_SCHEMA
        || candidate.adapter_runs.is_empty()
        || !denominator_closed
        || candidate.target_execution_count != 0
        || candidate.network_call_count != 0
        || candidate.provider_call_count != 0
        || candidate.adapter_write_count != 0
        || candidate.canonical_write_count != 0
        || candidate.a06_cross_adapter_status != "not_run"
        || candidate.collision_check != "not_run"
        || candidate.canonical_eligible
        || candidate.candidate_sha256
            != digest_without(candidate, "candidate_sha256", "analysis.verify")?
    {
        return Err(invalid_state(
            "analysis.verify",
            "typed candidate artifact is invalid or tampered",
        ));
    }
    for run in &candidate.adapter_runs {
        run.descriptor
            .validate()
            .map_err(|error| bundle("analysis.verify", error.to_string()))?;
        run.bundle
            .validate()
            .map_err(|error| bundle("analysis.verify", error.to_string()))?;
        if run.bundle.adapter_descriptor_sha256 != run.descriptor.descriptor_sha256
            || run.effects.target_execution_count != 0
            || run.effects.process_count != 0
            || run.effects.network_call_count != 0
            || run.effects.provider_call_count != 0
            || run.effects.adapter_write_count != 0
            || run.effects.canonical_write_count != 0
        {
            return Err(bundle(
                "analysis.verify",
                "adapter run identity or effects are invalid",
            ));
        }
    }
    Ok(())
}

fn load_snapshot(
    context: &CallContext,
    workspace: &Path,
    reference: &FileReceiptRef,
) -> Result<(String, SourceSnapshotV2), AnalysisFailureV1> {
    let path = context
        .resolve_workspace_receipt(workspace, reference)
        .map_err(context_failure)?;
    let read = read_bound_regular_file(context, &path).map_err(exact_failure)?;
    if read.sha256 != reference.sha256 {
        return Err(lock(
            "analysis.snapshot",
            "source snapshot artifact digest mismatch",
        ));
    }
    let snapshot: SourceSnapshotV2 = serde_json::from_slice(&read.bytes)
        .map_err(|error| invalid("analysis.snapshot", error.to_string()))?;
    snapshot
        .validate()
        .map_err(|error| source_changed("analysis.snapshot", error.to_string()))?;
    Ok((read.sha256, snapshot))
}

fn load_artifact<T>(
    context: &CallContext,
    workspace: &Path,
    reference: &FileReceiptRef,
    stage: &'static str,
) -> Result<T, AnalysisFailureV1>
where
    T: for<'de> Deserialize<'de>,
{
    let path = context
        .resolve_workspace_receipt(workspace, reference)
        .map_err(context_failure)?;
    let read = read_bound_regular_file(context, &path).map_err(exact_failure)?;
    if read.sha256 != reference.sha256 {
        return Err(lock(
            stage,
            "artifact digest differs from its receipt reference",
        ));
    }
    serde_json::from_slice(&read.bytes).map_err(|error| invalid_state(stage, error.to_string()))
}

fn publish<T: Serialize>(
    context: &CallContext,
    workspace: &Path,
    path: &Path,
    value: &T,
    stage: &'static str,
) -> Result<FileReceiptRef, AnalysisFailureV1> {
    let path = publish_immutable_json(
        context,
        path,
        value,
        "analysis.after_temp_sync_before_rename",
    )
    .map_err(|error| durable_failure(stage, error.kind, error.to_string()))?;
    let read = read_bound_regular_file(context, &path).map_err(exact_failure)?;
    let relative = path
        .strip_prefix(workspace)
        .map_err(|_| invalid_state(stage, "analysis artifact escaped workspace"))?;
    let reference = FileReceiptRef {
        path: relative.to_string_lossy().into_owned(),
        sha256: read.sha256,
    };
    reference
        .validate()
        .map_err(|error| invalid_state(stage, error.to_string()))?;
    Ok(reference)
}

fn validate_native_coverage(
    adapters: &[PlannedAdapterV1],
    snapshot: &SourceSnapshotV2,
) -> Result<(), AnalysisFailureV1> {
    let native = adapters
        .iter()
        .filter_map(|adapter| match &adapter.input {
            AnalysisAdapterInputV2::Native { logical_path } => Some(logical_path.as_str()),
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    if !native.is_empty()
        && native
            != snapshot
                .inventory
                .iter()
                .map(|entry| entry.logical_path.as_str())
                .collect::<BTreeSet<_>>()
    {
        return Err(invalid(
            "analysis.plan",
            "native selections must cover the admitted snapshot exact set",
        ));
    }
    Ok(())
}

fn require_source_pin(
    observed: &str,
    snapshot: &SourceSnapshotV2,
) -> Result<(), AnalysisFailureV1> {
    if observed != snapshot.exact_set_sha256 {
        return Err(source_changed(
            "analysis.plan",
            "adapter source snapshot pin differs from the selected snapshot",
        ));
    }
    Ok(())
}

fn bind_selected_snapshot(
    selected: &mut Option<String>,
    snapshot: &SourceSnapshotV2,
    adapter: &str,
) -> Result<(), AnalysisFailureV1> {
    match selected {
        Some(observed) if observed != &snapshot.exact_set_sha256 => Err(source_changed(
            "analysis.plan",
            format!("{adapter} selected SourceSnapshot identity differs from analysis input"),
        )),
        Some(_) => Ok(()),
        None => {
            *selected = Some(snapshot.exact_set_sha256.clone());
            Ok(())
        }
    }
}

fn codegraph_pin(pin: &CodeGraphAnalysisPinV2) -> CodeGraphExportPinV1 {
    CodeGraphExportPinV1 {
        file_sha256: pin.file_sha256.clone(),
        schema_sha256: pin.schema_sha256.clone(),
        tool_version: pin.tool_version.clone(),
        tool_commit: pin.tool_commit.clone(),
        tool_license: pin.tool_license.clone(),
        source_snapshot_sha256: pin.source_snapshot_sha256.clone(),
        max_file_bytes: pin.max_file_bytes,
    }
}

fn scip_pin(pin: &ScipAnalysisPinV2) -> ScipFilePinV1 {
    ScipFilePinV1 {
        file_sha256: pin.file_sha256.clone(),
        schema_version: pin.schema_version.clone(),
        schema_sha256: pin.schema_sha256.clone(),
        tool_name: pin.tool_name.clone(),
        tool_version: pin.tool_version.clone(),
        tool_commit: pin.tool_commit.clone(),
        tool_license: pin.tool_license.clone(),
        source_snapshot_sha256: pin.source_snapshot_sha256.clone(),
        max_file_bytes: pin.max_file_bytes,
    }
}

fn lsp_pin(pin: &LspSnapshotAnalysisPinV2) -> LspSnapshotFilePinV1 {
    LspSnapshotFilePinV1 {
        file_sha256: pin.file_sha256.clone(),
        schema_version: pin.schema_version.clone(),
        schema_sha256: pin.schema_sha256.clone(),
        protocol_version: pin.protocol_version.clone(),
        position_encoding: pin.position_encoding.clone(),
        producer_name: pin.producer_name.clone(),
        producer_version: pin.producer_version.clone(),
        producer_commit: pin.producer_commit.clone(),
        producer_license: pin.producer_license.clone(),
        producer_config_sha256: pin.producer_config_sha256.clone(),
        source_snapshot_sha256: pin.source_snapshot_sha256.clone(),
        max_file_bytes: pin.max_file_bytes,
    }
}

fn graphify_pin(pin: &GraphifyAnalysisPinV2) -> GraphifyGraphPinV2 {
    GraphifyGraphPinV2 {
        file_sha256: pin.file_sha256.clone(),
        canonical_schema_sha256: pin.canonical_schema_sha256.clone(),
        tool_version: pin.tool_version.clone(),
        tool_commit: pin.tool_commit.clone(),
        tool_license: pin.tool_license.clone(),
        export_py_sha256: pin.export_py_sha256.clone(),
        validate_py_sha256: pin.validate_py_sha256.clone(),
        pyproject_sha256: pin.pyproject_sha256.clone(),
        license_sha256: pin.license_sha256.clone(),
        extraction_spec_sha256: pin.extraction_spec_sha256.clone(),
        source_snapshot_sha256: pin.source_snapshot_sha256.clone(),
        source_repository_commit: pin.source_repository_commit.clone(),
        max_file_bytes: pin.max_file_bytes,
        max_node_count: pin.max_node_count,
        max_link_count: pin.max_link_count,
        max_hyperedge_count: pin.max_hyperedge_count,
    }
}

fn normalize_input_path(
    context: &CallContext,
    path: &Path,
    max_file_bytes: u64,
) -> Result<PathBuf, AnalysisFailureV1> {
    if max_file_bytes == 0 || max_file_bytes > MAX_ANALYSIS_INPUT_BYTES {
        return Err(invalid(
            "analysis.plan",
            "adapter input size budget is outside the P02 64 MiB cap",
        ));
    }
    let before = std::fs::symlink_metadata(path)
        .map_err(|error| invalid("analysis.plan", error.to_string()))?;
    if before.file_type().is_symlink()
        || !before.file_type().is_file()
        || before.len() > max_file_bytes
        || !private_inode(&before)
    {
        return Err(AnalysisFailureV1 {
            code: V2ErrorCode::SymlinkRejected,
            stage: "analysis.plan",
            message: "adapter input must be a bounded private regular file".to_owned(),
            recovery_hint: "use one caller-authorized frozen adapter file",
        });
    }
    let authorized = context.authorize_read(path).map_err(context_failure)?;
    let after = std::fs::symlink_metadata(&authorized)
        .map_err(|error| invalid("analysis.plan", error.to_string()))?;
    if !same_inode(&before, &after) || !private_inode(&after) {
        return Err(source_changed(
            "analysis.plan",
            "adapter input identity changed during planning",
        ));
    }
    Ok(authorized)
}

#[cfg(unix)]
fn same_inode(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    left.dev() == right.dev() && left.ino() == right.ino() && left.len() == right.len()
}

#[cfg(not(unix))]
fn same_inode(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    left.len() == right.len()
}

#[cfg(unix)]
fn private_inode(metadata: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    metadata.nlink() == 1
}

#[cfg(not(unix))]
fn private_inode(_metadata: &std::fs::Metadata) -> bool {
    true
}

fn validate_external_sources(
    context: &CallContext,
    plan: &AnalysisPlanV1,
    snapshot: &SourceSnapshotV2,
    source_files: &BTreeMap<String, Vec<u8>>,
) -> Result<(), AnalysisFailureV1> {
    if source_files.is_empty() {
        return Err(source_changed(
            "analysis.build",
            "source-bearing adapter returned no source files",
        ));
    }
    for (logical_path, embedded) in source_files {
        let entry = snapshot
            .inventory
            .iter()
            .find(|entry| entry.logical_path == *logical_path)
            .ok_or_else(|| {
                source_changed(
                    "analysis.build",
                    "adapter embedded source is absent from SourceSnapshot inventory",
                )
            })?;
        let path = safe_join(&plan.source_root, logical_path)?;
        let observed = read_bound_regular_file(context, &path).map_err(exact_failure)?;
        if observed.bytes != *embedded
            || observed.sha256 != entry.content_sha256
            || observed.bytes.len() as u64 != entry.bytes
        {
            return Err(source_changed(
                "analysis.build",
                "adapter embedded source differs from exact current snapshot bytes",
            ));
        }
    }
    Ok(())
}

fn ensure_input_unchanged(
    context: &CallContext,
    path: &Path,
    before_sha256: &str,
    pinned_sha256: &str,
    label: &str,
) -> Result<(), AnalysisFailureV1> {
    let after = read_bound_regular_file(context, path).map_err(exact_failure)?;
    if before_sha256 != pinned_sha256 || after.sha256 != pinned_sha256 {
        return Err(source_changed(
            "analysis.build",
            format!("{label} frozen input changed during import"),
        ));
    }
    Ok(())
}

fn zero_adapter_effects(source_file_read_count: u64) -> AdapterEffectsV1 {
    AdapterEffectsV1 {
        source_file_read_count,
        target_execution_count: 0,
        process_count: 0,
        network_call_count: 0,
        provider_call_count: 0,
        adapter_write_count: 0,
        canonical_write_count: 0,
    }
}

fn source_digests(files: &BTreeMap<String, Vec<u8>>) -> Vec<SourceDigestV1> {
    files
        .iter()
        .map(|(path, bytes)| SourceDigestV1 {
            logical_path: path.clone(),
            sha256: format!("sha256:{}", hex::encode(Sha256::digest(bytes))),
            bytes: bytes.len() as u64,
        })
        .collect()
}

fn safe_join(root: &Path, logical_path: &str) -> Result<PathBuf, AnalysisFailureV1> {
    let relative = Path::new(logical_path);
    if relative.is_absolute()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(AnalysisFailureV1 {
            code: V2ErrorCode::PathEscape,
            stage: "analysis.path",
            message: "logical source path is unsafe".to_owned(),
            recovery_hint: "use an admitted relative source snapshot path",
        });
    }
    Ok(root.join(relative))
}

fn digest_without<T: Serialize>(
    value: &T,
    field: &str,
    stage: &'static str,
) -> Result<String, AnalysisFailureV1> {
    let mut encoded =
        serde_json::to_value(value).map_err(|error| invalid_state(stage, error.to_string()))?;
    let object = encoded
        .as_object_mut()
        .ok_or_else(|| invalid_state(stage, "analysis artifact must be an object"))?;
    object.remove(field);
    canonical_json_sha256(&encoded).map_err(|error| invalid_state(stage, error.to_string()))
}

fn digest_hex(value: &str) -> Result<&str, AnalysisFailureV1> {
    value
        .strip_prefix("sha256:")
        .ok_or_else(|| invalid_state("analysis.identity", "semantic digest is malformed"))
}

fn sum_runs<F>(runs: &[ExecutedAdapterV1], select: F) -> Result<u64, AnalysisFailureV1>
where
    F: Fn(&AdapterRunV1) -> u64,
{
    runs.iter().try_fold(0_u64, |total, run| {
        total
            .checked_add(select(&run.artifact))
            .ok_or_else(|| bundle("analysis.build", "adapter denominator overflow"))
    })
}

fn sum<F>(runs: &[VerificationRunV1], select: F) -> Result<u64, AnalysisFailureV1>
where
    F: Fn(&VerificationRunV1) -> u64,
{
    runs.iter().try_fold(0_u64, |total, run| {
        total
            .checked_add(select(run))
            .ok_or_else(|| bundle("analysis.verify", "verification denominator overflow"))
    })
}

fn context_failure(error: ContextError) -> AnalysisFailureV1 {
    AnalysisFailureV1 {
        code: V2ErrorCode::PathEscape,
        stage: "analysis.path",
        message: error.to_string(),
        recovery_hint: "use only caller-authorized private workspace and input paths",
    }
}

fn exact_failure(error: ExactReadFailure) -> AnalysisFailureV1 {
    let code = match error.code {
        gtkg_protocol::ErrorCode::PathEscape => V2ErrorCode::PathEscape,
        gtkg_protocol::ErrorCode::SymlinkRejected => V2ErrorCode::SymlinkRejected,
        gtkg_protocol::ErrorCode::NotFound => V2ErrorCode::NotFound,
        _ => V2ErrorCode::Io,
    };
    AnalysisFailureV1 {
        code,
        stage: "analysis.readback",
        message: format!("{}: {}", error.path.display(), error.message),
        recovery_hint: "repair the exact private regular input and retry",
    }
}

fn durable_failure(
    stage: &'static str,
    kind: DurableErrorKind,
    message: String,
) -> AnalysisFailureV1 {
    let code = match kind {
        DurableErrorKind::Unauthorized | DurableErrorKind::Unsafe => V2ErrorCode::PathEscape,
        DurableErrorKind::Conflict => V2ErrorCode::InvalidState,
        DurableErrorKind::Invalid => V2ErrorCode::InvalidRequest,
        DurableErrorKind::Io => V2ErrorCode::Io,
    };
    AnalysisFailureV1 {
        code,
        stage,
        message,
        recovery_hint: "use a new private immutable analysis artifact path",
    }
}

fn invalid(stage: &'static str, message: impl Into<String>) -> AnalysisFailureV1 {
    AnalysisFailureV1 {
        code: V2ErrorCode::InvalidRequest,
        stage,
        message: message.into(),
        recovery_hint: "use the exact closed P02 analysis contract",
    }
}

fn invalid_state(stage: &'static str, message: impl Into<String>) -> AnalysisFailureV1 {
    AnalysisFailureV1 {
        code: V2ErrorCode::InvalidState,
        stage,
        message: message.into(),
        recovery_hint: "discard the tampered artifact and replay from its immutable predecessor",
    }
}

fn lock(stage: &'static str, message: impl Into<String>) -> AnalysisFailureV1 {
    AnalysisFailureV1 {
        code: V2ErrorCode::LockMismatch,
        stage,
        message: message.into(),
        recovery_hint: "use the exact current artifact digest",
    }
}

fn source_changed(stage: &'static str, message: impl Into<String>) -> AnalysisFailureV1 {
    AnalysisFailureV1 {
        code: V2ErrorCode::SourceChanged,
        stage,
        message: message.into(),
        recovery_hint: "recapture source and replay the analysis chain",
    }
}

fn bundle(stage: &'static str, message: impl Into<String>) -> AnalysisFailureV1 {
    AnalysisFailureV1 {
        code: V2ErrorCode::BundleInvalid,
        stage,
        message: message.into(),
        recovery_hint: "repair the pinned adapter input and rebuild the candidate",
    }
}
