//! Deterministic, file-only build, summary, bundle, and snapshot pipeline.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::Write;
use std::path::{Component, Path, PathBuf};

use gtkg_extract::{ObservedStaticFact, extract_path};
use gtkg_protocol::{
    ErrorCode, FileReceiptRef, OperationId, OperationRequest, OperationResponse, OperationStatus,
    SourceKey, SourceLock, SourceManifestEntry, TemplateLock, canonical_json_sha256,
    validate_path_identifier, validate_sha256,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use serde_yaml::Value as YamlValue;
use sha2::{Digest, Sha256};
use walkdir::WalkDir;

use crate::CallContext;
use crate::durable::{DurableErrorKind, DurableWriteError, publish_immutable_json};
use crate::file_model::{
    FileModelError, publish_immutable_version, sha256_file, tree_sha256, validate_index_tree,
    write_index_tree,
};
use crate::okf::{GeneratedBy, OkfFrontmatter, OkfStatus, SourceEntry};

const RUN_SCHEMA: &str = "gtkg.run/v1";
const MANIFEST_SCHEMA: &str = "gtkg.artifact-manifest/v1";

#[derive(Debug)]
pub struct PipelineFailure {
    pub code: ErrorCode,
    pub stage: &'static str,
    pub message: String,
    pub recovery_hint: &'static str,
}

impl PipelineFailure {
    fn invalid(stage: &'static str, message: impl Into<String>) -> Self {
        Self {
            code: ErrorCode::InvalidRequest,
            stage,
            message: message.into(),
            recovery_hint: "correct the request and retry with a new request_id",
        }
    }

    fn state(message: impl Into<String>) -> Self {
        Self {
            code: ErrorCode::InvalidState,
            stage: "run-state",
            message: message.into(),
            recovery_hint: "inspect run.get and resume only from the reported state",
        }
    }

    fn lock(message: impl Into<String>) -> Self {
        Self {
            code: ErrorCode::LockMismatch,
            stage: "lock-validation",
            message: message.into(),
            recovery_hint: "re-inspect sources and start a new exact-lock run",
        }
    }

    fn bundle(message: impl Into<String>) -> Self {
        Self {
            code: ErrorCode::BundleInvalid,
            stage: "bundle-validation",
            message: message.into(),
            recovery_hint: "rebuild an unpublished candidate from exact locks",
        }
    }

    fn io(stage: &'static str, path: &Path, error: impl std::fmt::Display) -> Self {
        Self {
            code: ErrorCode::Io,
            stage,
            message: format!("{}: {error}", path.display()),
            recovery_hint: "verify the explicit workspace path and filesystem permissions",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BuildPlanPayload {
    workspace_root: PathBuf,
    mode: BuildMode,
    source_inspection_ref: FileReceiptRef,
    template_validation_ref: FileReceiptRef,
    #[serde(default)]
    baseline_bundle: Option<PathBuf>,
    #[serde(default)]
    baseline_tree_sha256: Option<String>,
    bundle_version: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum BuildMode {
    Full,
    Incremental,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkspacePayload {
    workspace_root: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SummaryAcceptPayload {
    workspace_root: PathBuf,
    packet_id: String,
    source_sha256: String,
    template_manifest_sha256: String,
    summary_markdown: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BundlePathPayload {
    bundle_path: PathBuf,
    #[serde(default)]
    expected_tree_sha256: Option<String>,
    #[serde(default)]
    expected_manifest_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BundleQueryPayload {
    bundle_path: PathBuf,
    #[serde(default)]
    expected_tree_sha256: Option<String>,
    query: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SearchIndexRow {
    knowledge_id: String,
    source_key: SourceKey,
    resource: String,
    text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BundleComparePayload {
    left_bundle: PathBuf,
    #[serde(default)]
    left_expected_tree_sha256: Option<String>,
    right_bundle: PathBuf,
    #[serde(default)]
    right_expected_tree_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SnapshotCreatePayload {
    workspace_root: PathBuf,
    bundle_path: PathBuf,
    #[serde(default)]
    expected_bundle_tree_sha256: Option<String>,
    snapshot_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SnapshotPathPayload {
    snapshot_path: PathBuf,
    #[serde(default)]
    expected_snapshot_tree_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SnapshotRestorePayload {
    workspace_root: PathBuf,
    snapshot_path: PathBuf,
    #[serde(default)]
    expected_snapshot_tree_sha256: Option<String>,
    restore_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RunPlan {
    schema_version: String,
    run_id: String,
    mode: BuildMode,
    source_inspection_ref: FileReceiptRef,
    template_validation_ref: FileReceiptRef,
    source_lock: SourceLock,
    template_lock: TemplateLock,
    omissions: Vec<crate::source::SourceOmission>,
    baseline_bundle: Option<PathBuf>,
    baseline_tree_sha256: Option<String>,
    bundle_version: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RunState {
    Planned,
    AwaitingSummary,
    ReadyToFinalize,
    Finalized,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RunStateFile {
    schema_version: String,
    run_id: String,
    state: RunState,
    accepted_summaries: usize,
    expected_summaries: usize,
    reused_summaries: usize,
    total_sources: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RunEvent {
    schema_version: String,
    sequence: u64,
    request_id: String,
    run_id: String,
    operation_id: OperationId,
    from: Option<RunState>,
    to: RunState,
    state: RunStateFile,
    locks: BTreeMap<String, String>,
    actor: String,
    observed_unix_millis: u128,
    evidence_refs: Vec<String>,
    previous_event_sha256: Option<String>,
    event_sha256: String,
}

#[derive(Debug)]
struct RunProjection {
    state: RunStateFile,
    stored_state: Option<RunStateFile>,
    state_stale: bool,
    acceptance_head: Option<AcceptanceHead>,
    acceptance_head_stale: bool,
}

/// Host-facing generation constraints shipped inside every SummaryJob packet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SummaryConstraints {
    schema: String,
    evidence_scope: String,
    generation_rule: String,
    model_identity_rule: String,
}

fn summary_constraints() -> SummaryConstraints {
    SummaryConstraints {
        schema: "gtkg.summary-constraints/v1".to_owned(),
        evidence_scope: "packet_only".to_owned(),
        generation_rule: "derive the summary candidate exclusively from analysis_text, \
                          observed_facts and observations supplied in this packet; do not \
                          invent evidence beyond the packet"
            .to_owned(),
        model_identity_rule: "declare the generating model as a leading `model: <id>` line \
                              in summary_markdown; summaries without a declaration are \
                              recorded with model_identity \"unspecified\""
            .to_owned(),
    }
}

const MODEL_IDENTITY_UNSPECIFIED: &str = "unspecified";

fn unspecified_model_identity() -> String {
    MODEL_IDENTITY_UNSPECIFIED.to_owned()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AnalysisPacket {
    schema_version: String,
    packet_id: String,
    repo_id: String,
    source_path: String,
    source_sha256: String,
    source_bytes: u64,
    template_manifest_sha256: String,
    media_type: String,
    extractor_id: String,
    analysis_text: String,
    observed_facts: Vec<ObservedStaticFact>,
    observations: BTreeMap<String, String>,
    template_markdown: String,
    template_slot_ids: Vec<String>,
    constraints: SummaryConstraints,
    target_process_count: u64,
    executed_target_content: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SummaryCandidate {
    schema_version: String,
    packet_id: String,
    repo_id: String,
    source_path: String,
    source_sha256: String,
    template_manifest_sha256: String,
    summary_markdown: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AcceptedSummaryReceipt {
    schema_version: String,
    packet_id: String,
    candidate_sha256: String,
    /// Exact `model:` declaration from the summary metadata header, or the
    /// explicit string "unspecified" when the summary declared no identity.
    #[serde(default = "unspecified_model_identity")]
    model_identity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AcceptanceEvent {
    schema_version: String,
    sequence: u64,
    run_plan_sha256: String,
    packet_id: String,
    candidate_sha256: String,
    acceptance_receipt_sha256: String,
    previous_event_sha256: Option<String>,
    event_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AcceptanceHead {
    schema_version: String,
    event_count: u64,
    run_plan_sha256: String,
    head_sha256: String,
}

#[derive(Debug, Clone)]
struct VerifiedAcceptance {
    receipts: BTreeMap<String, AcceptedSummaryReceipt>,
    events: Vec<AcceptanceEvent>,
    head: AcceptanceHead,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FinalizedRecord {
    schema_version: String,
    bundle_path: PathBuf,
    semantic_digest: String,
    tree_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ArtifactManifest {
    pub(crate) schema_version: String,
    pub(crate) bundle_version: String,
    pub(crate) semantic_digest: String,
    pub(crate) source_lock: SourceLock,
    pub(crate) template_lock: TemplateLock,
    pub(crate) sources: Vec<ArtifactSource>,
    pub(crate) knowledge: Vec<ArtifactKnowledge>,
    pub(crate) analysis: Vec<ArtifactAnalysis>,
    pub(crate) canonical_documents: Vec<ArtifactDocument>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ArtifactSource {
    pub(crate) source_key: SourceKey,
    pub(crate) source_sha256: String,
    pub(crate) role: String,
    pub(crate) bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ArtifactKnowledge {
    pub(crate) source_key: SourceKey,
    pub(crate) packet_id: String,
    pub(crate) path: String,
    pub(crate) sha256: String,
    pub(crate) summary_receipt_path: String,
    pub(crate) summary_receipt_sha256: String,
    pub(crate) acceptance_receipt_path: String,
    pub(crate) acceptance_receipt_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ArtifactAnalysis {
    pub(crate) source_key: SourceKey,
    pub(crate) packet_id: String,
    pub(crate) source_sha256: String,
    pub(crate) extractor_id: String,
    pub(crate) path: String,
    pub(crate) sha256: String,
    pub(crate) fact_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ArtifactDocument {
    pub(crate) path: String,
    pub(crate) sha256: String,
}

#[derive(Debug, Clone)]
pub(crate) struct VerifiedProjectionFile {
    pub(crate) path: String,
    pub(crate) sha256: String,
}

#[derive(Debug, Clone)]
pub(crate) struct VerifiedProjectionKnowledge {
    pub(crate) source_key: SourceKey,
    pub(crate) source_sha256: String,
    pub(crate) knowledge_id: String,
    pub(crate) knowledge_path: String,
    pub(crate) knowledge_sha256: String,
    pub(crate) title: String,
    pub(crate) description: String,
    pub(crate) body: String,
    /// H04: OKF v0.2 trust provenance (sources/status/revision) projected into
    /// the A2UI data model.
    pub(crate) provenance: Value,
    pub(crate) analysis_path: String,
    pub(crate) analysis_sha256: String,
    pub(crate) packet_id: String,
    pub(crate) media_type: String,
    pub(crate) extractor_id: String,
    pub(crate) observed_facts: Vec<ObservedStaticFact>,
    pub(crate) target_process_count: u64,
    pub(crate) executed_target_content: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct VerifiedProjectionView {
    pub(crate) bundle_path: PathBuf,
    pub(crate) bundle_tree_sha256: String,
    pub(crate) artifact_manifest_sha256: String,
    pub(crate) source_lock_sha256: String,
    pub(crate) manifest: ArtifactManifest,
    pub(crate) canonical_documents: Vec<VerifiedProjectionFile>,
    pub(crate) indexes: Vec<VerifiedProjectionFile>,
    pub(crate) knowledge: Vec<VerifiedProjectionKnowledge>,
}

#[derive(Debug, Clone, Serialize)]
struct ImpactSet {
    added: Vec<SourceKey>,
    changed: Vec<SourceKey>,
    deleted: Vec<SourceKey>,
    unchanged: Vec<SourceKey>,
}

#[derive(Debug, Serialize)]
struct SemanticInput<'a> {
    source_lock: &'a SourceLock,
    template_lock: &'a TemplateLock,
    summaries: &'a [SummaryCandidate],
    analysis: &'a [AnalysisPacket],
}

pub fn execute(
    context: &CallContext,
    request: &OperationRequest,
) -> Result<OperationResponse, PipelineFailure> {
    match request.operation_id {
        OperationId::BuildPlan => build_plan(context, request),
        OperationId::BuildPrepare => build_prepare(context, request),
        OperationId::SummaryNext => summary_next(context, request),
        OperationId::SummaryAccept => summary_accept(context, request),
        OperationId::BuildFinalize => build_finalize(context, request),
        OperationId::RunGet => run_get(context, request),
        OperationId::RunCancel => run_cancel(context, request),
        OperationId::BundleVerify => bundle_verify(context, request),
        OperationId::BundleQuery => bundle_query(context, request),
        OperationId::BundleCompare => bundle_compare(context, request),
        OperationId::SnapshotCreate => snapshot_create(context, request),
        OperationId::SnapshotVerify => snapshot_verify(context, request),
        OperationId::SnapshotRestore => snapshot_restore(context, request),
        _ => Err(PipelineFailure::invalid(
            "dispatch",
            format!(
                "{} is not a pipeline operation",
                request.operation_id.as_str()
            ),
        )),
    }
}

fn build_plan(
    context: &CallContext,
    request: &OperationRequest,
) -> Result<OperationResponse, PipelineFailure> {
    let mut payload: BuildPlanPayload = parse_payload(request, "build.plan")?;
    let workspace_root = context
        .authorize_write(&payload.workspace_root)
        .map_err(context_pipeline_failure("build.plan"))?;
    validate_workspace_path(&workspace_root)?;
    validate_version(&payload.bundle_version)?;
    if let Some(baseline) = payload.baseline_bundle.as_mut() {
        *baseline = context
            .authorize_read(baseline)
            .map_err(context_pipeline_failure("build.plan"))?;
    }

    validate_exact_receipt_locks(
        request,
        &payload.source_inspection_ref,
        &payload.template_validation_ref,
    )?;
    let verified_source = crate::source::load_and_revalidate(
        context,
        &workspace_root,
        &payload.source_inspection_ref,
    )
    .map_err(map_source_failure)?;
    let verified_template = crate::template::load_and_revalidate(
        context,
        &workspace_root,
        &payload.template_validation_ref,
    )
    .map_err(map_template_failure)?;
    let mut source_lock = verified_source.source_lock;
    let mut template_lock = verified_template.template_lock;
    let omissions = verified_source.omissions;
    normalize_source_lock(&mut source_lock);
    normalize_template_lock(&mut template_lock);

    match (
        payload.mode,
        &payload.baseline_bundle,
        &payload.baseline_tree_sha256,
    ) {
        (BuildMode::Full, Some(_), _) | (BuildMode::Full, None, Some(_)) => {
            return Err(PipelineFailure::invalid(
                "build.plan",
                "full builds must not declare baseline bundle identity",
            ));
        }
        (BuildMode::Incremental, Some(path), Some(expected)) => {
            let baseline = verify_bundle_expected(path, expected, "build.plan", false)?;
            if baseline.template_lock != template_lock {
                return Err(PipelineFailure::lock(
                    "incremental build template lock differs from baseline",
                ));
            }
        }
        (BuildMode::Incremental, _, _) => {
            return Err(PipelineFailure::lock(
                "incremental builds require baseline_bundle and full baseline_tree_sha256",
            ));
        }
        (BuildMode::Full, None, None) => {}
    }

    let _guard = WriteGuard::acquire(context, &workspace_root)?;
    let runs_root = workspace_root.join(".gtkg/runs");
    authorize_write_path(context, &runs_root, "build.plan")?;
    fs::create_dir_all(&runs_root)
        .map_err(|error| PipelineFailure::io("build.plan", &runs_root, error))?;
    let plan_identity = json!({
        "source_inspection_ref": payload.source_inspection_ref,
        "template_validation_ref": payload.template_validation_ref,
        "source_lock": source_lock,
        "template_lock": template_lock,
        "omissions": omissions,
        "mode": payload.mode,
        "baseline_bundle": payload.baseline_bundle,
        "baseline_tree_sha256": payload.baseline_tree_sha256,
        "bundle_version": payload.bundle_version,
        "workspace_root": workspace_root,
    });
    let plan_digest = canonical_json_sha256(&plan_identity)
        .map_err(|error| PipelineFailure::invalid("build.plan", error.to_string()))?;
    let run_id = format!("run-{}", &plan_digest[7..31]);
    let run_dir = run_dir(&workspace_root, &run_id);
    authorize_write_path(context, &run_dir, "build.plan")?;
    let plan = RunPlan {
        schema_version: "gtkg.build-plan/v1".to_owned(),
        run_id: run_id.clone(),
        mode: payload.mode,
        source_inspection_ref: payload.source_inspection_ref,
        template_validation_ref: payload.template_validation_ref,
        source_lock,
        template_lock,
        omissions,
        baseline_bundle: payload.baseline_bundle,
        baseline_tree_sha256: payload.baseline_tree_sha256,
        bundle_version: payload.bundle_version,
    };
    let current_state = if run_dir.exists() {
        reject_symlinks_below(&run_dir, "build.plan")?;
        validate_existing_run_identity(context, &run_dir, &plan)?;
        if run_dir.join("events.ndjson").exists() {
            reconcile_run_for_mutation(context, &run_dir, request, "build.plan")?
        } else {
            bootstrap_exact_partial_run(context, &run_dir, request, &plan)?
        }
    } else {
        initialize_run_atomically(
            context,
            &workspace_root,
            &runs_root,
            &run_dir,
            request,
            &plan,
        )?
    };
    let impact = compute_impact(&plan)?;
    let mut response = OperationResponse::completed(
        request,
        json!({
            "run_id": run_id,
            "state": current_state.state,
            "mode": plan.mode,
            "source_count": plan.source_lock.entries.len(),
            "impact": impact,
        }),
    );
    response.run_id = Some(run_id);
    Ok(response)
}

fn build_prepare(
    context: &CallContext,
    request: &OperationRequest,
) -> Result<OperationResponse, PipelineFailure> {
    let payload: WorkspacePayload = parse_payload(request, "build.prepare")?;
    let workspace_root = context
        .authorize_write(&payload.workspace_root)
        .map_err(context_pipeline_failure("build.prepare"))?;
    let run_id = required_run_id(request)?;
    let _guard = WriteGuard::acquire(context, &workspace_root)?;
    let directory = run_dir(&workspace_root, run_id);
    authorize_write_path(context, &directory, "build.prepare")?;
    reject_symlinks_below(&directory, "build.prepare")?;
    let mut plan: RunPlan = read_json(&directory.join("plan.json"), "build.prepare")?;
    if let Some(baseline) = plan.baseline_bundle.as_mut() {
        *baseline = context
            .authorize_read(baseline)
            .map_err(context_pipeline_failure("build.prepare"))?;
    }
    let verified_source =
        crate::source::load_and_revalidate(context, &workspace_root, &plan.source_inspection_ref)
            .map_err(map_source_failure)?;
    if verified_source.source_lock != plan.source_lock {
        return Err(PipelineFailure::lock(
            "source inspection no longer matches the run SourceLock",
        ));
    }
    let verified_template = crate::template::load_and_revalidate(
        context,
        &workspace_root,
        &plan.template_validation_ref,
    )
    .map_err(map_template_failure)?;
    if verified_template.template_lock != plan.template_lock {
        return Err(PipelineFailure::lock(
            "template validation no longer matches the run TemplateLock",
        ));
    }
    let template_markdown = load_locked_template_markdown(&verified_template, "build.prepare")?;
    let mut impact = compute_impact(&plan)?;
    if plan.mode == BuildMode::Incremental {
        propagate_dependency_invalidation(&plan, &mut impact)?;
    }
    let extracted_count = impact.added.len() + impact.changed.len();
    let reused_count = impact.unchanged.len();
    let mut state = reconcile_run_for_mutation(context, &directory, request, "build.prepare")?;
    if state.state != RunState::Planned {
        if matches!(
            state.state,
            RunState::AwaitingSummary | RunState::ReadyToFinalize
        ) {
            return Ok(status_response(
                request,
                OperationStatus::NeedsLlm,
                json!({
                    "state": state.state,
                    "packet_count": state.expected_summaries,
                    "extracted_count": extracted_count,
                    "reused_count": reused_count,
                    "summary_required_count": state.expected_summaries,
                }),
            ));
        }
        return Err(PipelineFailure::state(format!(
            "build.prepare requires planned, observed {:?}",
            state.state
        )));
    }
    let packets_dir = directory.join("packets");
    let analysis_dir = directory.join("analysis");
    if let Some(baseline) = plan.baseline_bundle.as_ref() {
        let expected = plan.baseline_tree_sha256.as_deref().ok_or_else(|| {
            PipelineFailure::lock("incremental run is missing its baseline tree digest")
        })?;
        let baseline_manifest = verify_bundle_expected(baseline, expected, "build.prepare", false)?;
        let by_key: BTreeMap<_, _> = baseline_manifest
            .knowledge
            .iter()
            .map(|entry| (entry.source_key.clone(), entry))
            .collect();
        let analysis_by_key: BTreeMap<_, _> = baseline_manifest
            .analysis
            .iter()
            .map(|entry| (entry.source_key.clone(), entry))
            .collect();
        for key in &impact.unchanged {
            let knowledge = by_key.get(key).ok_or_else(|| {
                PipelineFailure::bundle(format!(
                    "baseline has no reusable summary for {}:{}",
                    key.repo_id, key.logical_path
                ))
            })?;
            let receipt_path = safe_join(baseline, &knowledge.summary_receipt_path)?;
            let candidate: SummaryCandidate = read_json(&receipt_path, "build.prepare")?;
            if candidate.repo_id != key.repo_id || candidate.source_path != key.logical_path {
                return Err(PipelineFailure::bundle(
                    "baseline summary receipt SourceKey mismatch",
                ));
            }
            let reused_identity =
                parse_model_identity(&candidate.summary_markdown, "build.prepare")?;
            persist_accepted_candidate(
                context,
                &directory,
                &candidate,
                &reused_identity,
                "build.prepare",
            )?;
            let analysis = analysis_by_key.get(key).ok_or_else(|| {
                PipelineFailure::bundle(format!(
                    "baseline has no reusable analysis evidence for {}:{}",
                    key.repo_id, key.logical_path
                ))
            })?;
            let analysis_path = safe_join(baseline, &analysis.path)?;
            if sha256_file(&analysis_path).map_err(map_file_model("build.prepare"))?
                != analysis.sha256
            {
                return Err(PipelineFailure::bundle(
                    "baseline analysis evidence digest mismatch",
                ));
            }
            let packet: AnalysisPacket = read_json(&analysis_path, "build.prepare")?;
            validate_analysis_packet(
                &packet,
                key,
                analysis.source_sha256.as_str(),
                analysis.fact_count,
                "build.prepare",
            )?;
            if packet.packet_id != candidate.packet_id
                || packet.extractor_id != analysis.extractor_id
            {
                return Err(PipelineFailure::bundle(
                    "baseline analysis evidence does not bind the reused summary",
                ));
            }
            write_json_atomic(
                &analysis_dir.join(format!("{}.json", packet.packet_id)),
                &packet,
                "build.prepare",
            )?;
        }
    }
    let affected: BTreeSet<_> = impact
        .added
        .iter()
        .chain(impact.changed.iter())
        .cloned()
        .collect();
    let material_root = directory.join("source-material");
    for entry in plan
        .source_lock
        .entries
        .iter()
        .filter(|entry| affected.contains(&source_key(entry)))
    {
        let key = source_key(entry);
        let bytes =
            crate::source::read_locked_blob(&verified_source, &key).map_err(map_source_failure)?;
        let repo_root = safe_join(&material_root, &entry.repo_id)?;
        let source_path = safe_join(&repo_root, &entry.logical_path)?;
        authorize_write_path(context, &source_path, "build.prepare")?;
        if let Some(parent) = source_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| PipelineFailure::io("build.prepare", parent, error))?;
        }
        fs::write(&source_path, &bytes)
            .map_err(|error| PipelineFailure::io("build.prepare", &source_path, error))?;
        let extracted = extract_path(&source_path).map_err(|error| PipelineFailure {
            code: ErrorCode::ExtractInvalid,
            stage: "build.prepare",
            message: format!("{}: {error}", entry.logical_path),
            recovery_hint: "use a supported static source or provide a separately governed OCR result",
        })?;
        if extracted.source_sha256 != entry.content_sha256 {
            return Err(PipelineFailure::lock(format!(
                "source changed during prepare: {}",
                entry.logical_path
            )));
        }
        if extracted.executed_target_content || extracted.target_process_count != 0 {
            return Err(PipelineFailure::state(format!(
                "extractor reported target execution for {}",
                entry.logical_path
            )));
        }
        validate_observed_facts(
            &extracted.observed_facts,
            &bytes,
            &entry.logical_path,
            "build.prepare",
        )?;
        let packet_seed = json!({
            "repo_id": entry.repo_id,
            "source_path": entry.logical_path,
            "source_sha256": entry.content_sha256,
            "template_manifest_sha256": plan.template_lock.template.manifest_sha256,
            "extractor_id": extracted.extractor_id,
            "observed_facts": extracted.observed_facts,
            "observations": extracted.observations,
        });
        let packet_digest = canonical_json_sha256(&packet_seed)
            .map_err(|error| PipelineFailure::invalid("build.prepare", error.to_string()))?;
        let packet = AnalysisPacket {
            schema_version: "gtkg.analysis-packet/v1".to_owned(),
            packet_id: format!("packet-{}", &packet_digest[7..39]),
            repo_id: entry.repo_id.clone(),
            source_path: entry.logical_path.clone(),
            source_sha256: entry.content_sha256.clone(),
            source_bytes: entry.bytes,
            template_manifest_sha256: plan.template_lock.template.manifest_sha256.clone(),
            media_type: extracted.media_type,
            extractor_id: extracted.extractor_id,
            analysis_text: normalize_text(&extracted.text),
            observed_facts: extracted.observed_facts,
            observations: extracted.observations,
            template_markdown: template_markdown.clone(),
            template_slot_ids: plan.template_lock.slot_ids.clone(),
            constraints: summary_constraints(),
            target_process_count: 0,
            executed_target_content: false,
        };
        write_json_atomic(
            &packets_dir.join(format!("{}.json", packet.packet_id)),
            &packet,
            "build.prepare",
        )?;
        write_json_atomic(
            &analysis_dir.join(format!("{}.json", packet.packet_id)),
            &packet,
            "build.prepare",
        )?;
    }
    state.expected_summaries = extracted_count;
    state.reused_summaries = reused_count;
    state.total_sources = plan.source_lock.entries.len();
    state.state = if state.expected_summaries == 0 {
        RunState::ReadyToFinalize
    } else {
        RunState::AwaitingSummary
    };
    append_event(context, &directory, request, &state)?;
    write_json_atomic(&directory.join("state.json"), &state, "build.prepare")?;
    Ok(status_response(
        request,
        if state.state == RunState::AwaitingSummary {
            OperationStatus::NeedsLlm
        } else {
            OperationStatus::Completed
        },
        json!({
            "state": state.state,
            "packet_count": state.expected_summaries,
            "extracted_count": extracted_count,
            "reused_count": reused_count,
            "summary_required_count": state.expected_summaries,
            "executed_target_content": false,
        }),
    ))
}

fn summary_next(
    context: &CallContext,
    request: &OperationRequest,
) -> Result<OperationResponse, PipelineFailure> {
    let payload: WorkspacePayload = parse_payload(request, "summary.next")?;
    let workspace_root = context
        .authorize_read(&payload.workspace_root)
        .map_err(context_pipeline_failure("summary.next"))?;
    let run_id = required_run_id(request)?;
    let directory = run_dir(&workspace_root, run_id);
    authorize_read_path(context, &directory, "summary.next")?;
    reject_symlinks_below(&directory, "summary.next")?;
    let mut packets = read_packets(&directory)?;
    packets.sort_by(|left, right| {
        (&left.repo_id, &left.source_path).cmp(&(&right.repo_id, &right.source_path))
    });
    for packet in packets {
        let candidate = directory
            .join("candidates")
            .join(format!("{}.json", packet.packet_id));
        if !candidate.exists() {
            validate_packet_binding(context, &directory, &packet, "summary.next")?;
            return Ok(OperationResponse::completed(
                request,
                json!({"job": {
                    "packet_id": packet.packet_id,
                    "repo_id": packet.repo_id,
                    "source_path": packet.source_path,
                    "source_sha256": packet.source_sha256,
                    "template_manifest_sha256": packet.template_manifest_sha256,
                    "analysis_text": packet.analysis_text,
                    "observed_facts": packet.observed_facts,
                    "observations": packet.observations,
                    "template_markdown": packet.template_markdown,
                    "template_slot_ids": packet.template_slot_ids,
                    "constraints": packet.constraints,
                }}),
            ));
        }
    }
    Ok(OperationResponse::completed(request, json!({"job": null})))
}

fn summary_accept(
    context: &CallContext,
    request: &OperationRequest,
) -> Result<OperationResponse, PipelineFailure> {
    let payload: SummaryAcceptPayload = parse_payload(request, "summary.accept")?;
    if payload.summary_markdown.trim().is_empty() {
        return Err(PipelineFailure::invalid(
            "summary.accept",
            "summary_markdown must not be empty",
        ));
    }
    validate_generated_id("packet_id", &payload.packet_id)?;
    let workspace_root = context
        .authorize_write(&payload.workspace_root)
        .map_err(context_pipeline_failure("summary.accept"))?;
    let run_id = required_run_id(request)?;
    let _guard = WriteGuard::acquire(context, &workspace_root)?;
    let directory = run_dir(&workspace_root, run_id);
    authorize_write_path(context, &directory, "summary.accept")?;
    reject_symlinks_below(&directory, "summary.accept")?;
    let mut state = reconcile_run_for_mutation(context, &directory, request, "summary.accept")?;
    if !matches!(
        state.state,
        RunState::AwaitingSummary | RunState::ReadyToFinalize
    ) {
        return Err(PipelineFailure::state(format!(
            "summary.accept requires awaiting_summary, observed {:?}",
            state.state
        )));
    }
    let packet: AnalysisPacket = read_json(
        &directory
            .join("packets")
            .join(format!("{}.json", payload.packet_id)),
        "summary.accept",
    )?;
    if packet.source_sha256 != payload.source_sha256
        || packet.template_manifest_sha256 != payload.template_manifest_sha256
    {
        return Err(PipelineFailure::lock(format!(
            "summary locks do not match packet {}",
            payload.packet_id
        )));
    }
    validate_packet_binding(context, &directory, &packet, "summary.accept")?;
    let model_identity = parse_model_identity(&payload.summary_markdown, "summary.accept")?;
    let (claim_count, cited_claim_count) =
        validate_summary_claims(&payload.summary_markdown, &packet, "summary.accept")?;
    let candidate = SummaryCandidate {
        schema_version: "gtkg.summary-candidate/v1".to_owned(),
        packet_id: packet.packet_id.clone(),
        repo_id: packet.repo_id,
        source_path: packet.source_path,
        source_sha256: packet.source_sha256,
        template_manifest_sha256: packet.template_manifest_sha256,
        summary_markdown: normalize_text(&payload.summary_markdown),
    };
    if persist_accepted_candidate(
        context,
        &directory,
        &candidate,
        &model_identity,
        "summary.accept",
    )? {
        state = inspect_run_projection(context, &directory, "summary.accept")?.state;
        append_event(context, &directory, request, &state)?;
        write_json_atomic(&directory.join("state.json"), &state, "summary.accept")?;
    }
    Ok(OperationResponse::completed(
        request,
        json!({
            "packet_id": candidate.packet_id,
            "accepted": true,
            "model_identity": model_identity,
            "claim_count": claim_count,
            "cited_claim_count": cited_claim_count,
            "state": state.state,
            "accepted_summaries": state.accepted_summaries,
            "expected_summaries": state.expected_summaries,
        }),
    ))
}

fn build_finalize(
    context: &CallContext,
    request: &OperationRequest,
) -> Result<OperationResponse, PipelineFailure> {
    let payload: WorkspacePayload = parse_payload(request, "build.finalize")?;
    let workspace_root = context
        .authorize_write(&payload.workspace_root)
        .map_err(context_pipeline_failure("build.finalize"))?;
    let run_id = required_run_id(request)?;
    let _guard = WriteGuard::acquire(context, &workspace_root)?;
    let directory = run_dir(&workspace_root, run_id);
    authorize_write_path(context, &directory, "build.finalize")?;
    reject_symlinks_below(&directory, "build.finalize")?;
    let state = reconcile_run_for_mutation(context, &directory, request, "build.finalize")?;
    if state.state == RunState::Finalized {
        let record: FinalizedRecord =
            read_json(&directory.join("finalized.json"), "build.finalize")?;
        return Ok(finalize_response(request, &record));
    }
    if state.state != RunState::ReadyToFinalize
        || state.accepted_summaries != state.expected_summaries
    {
        return Err(PipelineFailure::state(format!(
            "build.finalize requires ready_to_finalize with all summaries; state={:?} accepted={}/{}",
            state.state, state.accepted_summaries, state.expected_summaries
        )));
    }
    let plan: RunPlan = read_json(&directory.join("plan.json"), "build.finalize")?;
    let source =
        crate::source::load_and_revalidate(context, &workspace_root, &plan.source_inspection_ref)
            .map_err(map_source_failure)?;
    if source.source_lock != plan.source_lock {
        return Err(PipelineFailure::lock(
            "source inspection drifted before finalization",
        ));
    }
    let template = crate::template::load_and_revalidate(
        context,
        &workspace_root,
        &plan.template_validation_ref,
    )
    .map_err(map_template_failure)?;
    if template.template_lock != plan.template_lock {
        return Err(PipelineFailure::lock(
            "template validation drifted before finalization",
        ));
    }
    let mut summaries = read_candidates(&directory)?;
    summaries.sort_by(|left, right| {
        (&left.repo_id, &left.source_path).cmp(&(&right.repo_id, &right.source_path))
    });
    if summaries.len() != state.total_sources || summaries.len() != plan.source_lock.entries.len() {
        return Err(PipelineFailure::state(
            "candidate count does not match the exact source lock",
        ));
    }
    let mut analysis = read_analysis_packets(&directory)?;
    analysis.sort_by(|left, right| {
        (&left.repo_id, &left.source_path).cmp(&(&right.repo_id, &right.source_path))
    });
    if analysis.len() != state.total_sources || analysis.len() != plan.source_lock.entries.len() {
        return Err(PipelineFailure::state(
            "analysis evidence count does not match the exact source lock",
        ));
    }
    let summary_by_key: BTreeMap<SourceKey, &SummaryCandidate> = summaries
        .iter()
        .map(|summary| {
            (
                SourceKey {
                    repo_id: summary.repo_id.clone(),
                    logical_path: summary.source_path.clone(),
                },
                summary,
            )
        })
        .collect();
    for (packet, source) in analysis.iter().zip(&plan.source_lock.entries) {
        let key = source_key(source);
        validate_analysis_packet(
            packet,
            &key,
            &source.content_sha256,
            packet.observed_facts.len() as u64,
            "build.finalize",
        )?;
        if packet.source_bytes != source.bytes
            || packet.template_manifest_sha256 != plan.template_lock.template.manifest_sha256
            || summary_by_key
                .get(&key)
                .is_none_or(|summary| summary.packet_id != packet.packet_id)
        {
            return Err(PipelineFailure::lock(format!(
                "analysis evidence does not close over source/template/summary locks for {}:{}",
                key.repo_id, key.logical_path
            )));
        }
    }
    let acceptances = verify_accepted_candidates(context, &directory, &summaries)?;
    let semantic_digest = canonical_json_sha256(&SemanticInput {
        source_lock: &plan.source_lock,
        template_lock: &plan.template_lock,
        summaries: &summaries,
        analysis: &analysis,
    })
    .map_err(|error| PipelineFailure::invalid("build.finalize", error.to_string()))?;
    quarantine_staging(
        context,
        &directory,
        &directory.join("bundle-staging"),
        "legacy-bundle-staging",
        "build.finalize",
    )?;
    let request_digest = digest_string(&request.request_id);
    let staging = directory
        .join("staging")
        .join(format!("finalize-{}", &request_digest[..24]));
    authorize_write_path(context, &staging, "build.finalize")?;
    if staging.exists() {
        quarantine_staging(
            context,
            &directory,
            &staging,
            "finalize-staging",
            "build.finalize",
        )?;
    }
    fs::create_dir_all(&staging)
        .map_err(|error| PipelineFailure::io("build.finalize", &staging, error))?;
    render_bundle(
        &staging,
        &plan,
        &summaries,
        &analysis,
        &acceptances,
        &semantic_digest,
    )?;
    write_index_tree(&staging).map_err(map_file_model("build.finalize"))?;
    validate_index_tree(&staging).map_err(map_file_model("build.finalize"))?;
    verify_bundle(&staging)?;
    let versions_root = workspace_root.join("artifacts/bundles/versions");
    authorize_write_path(context, &versions_root, "build.finalize")?;
    let bundle_path = publish_immutable_version(&staging, &versions_root, &plan.bundle_version)
        .map_err(map_file_model("build.finalize"))?;
    let published_tree_digest =
        tree_sha256(&bundle_path).map_err(map_file_model("build.finalize"))?;
    verify_bundle_expected(&bundle_path, &published_tree_digest, "build.finalize", true)?;
    if staging.exists() {
        quarantine_staging(
            context,
            &directory,
            &staging,
            "idempotent-finalize-staging",
            "build.finalize",
        )?;
    }
    let record = FinalizedRecord {
        schema_version: "gtkg.finalized/v1".to_owned(),
        tree_digest: published_tree_digest,
        bundle_path,
        semantic_digest,
    };
    write_json_atomic(&directory.join("finalized.json"), &record, "build.finalize")?;
    let mut finalized_state = state;
    finalized_state.state = RunState::Finalized;
    append_event(context, &directory, request, &finalized_state)?;
    write_json_atomic(
        &directory.join("state.json"),
        &finalized_state,
        "build.finalize",
    )?;
    Ok(finalize_response(request, &record))
}

fn run_get(
    context: &CallContext,
    request: &OperationRequest,
) -> Result<OperationResponse, PipelineFailure> {
    let payload: WorkspacePayload = parse_payload(request, "run.get")?;
    let workspace_root = context
        .authorize_read(&payload.workspace_root)
        .map_err(context_pipeline_failure("run.get"))?;
    let run_id = required_run_id(request)?;
    let directory = run_dir(&workspace_root, run_id);
    authorize_read_path(context, &directory, "run.get")?;
    reject_symlinks_below(&directory, "run.get")?;
    let projection = inspect_run_projection(context, &directory, "run.get")?;
    let plan: RunPlan = read_json(&directory.join("plan.json"), "run.get")?;
    Ok(OperationResponse::completed(
        request,
        json!({
            "state": projection.state,
            "stored_state": projection.stored_state,
            "projected_stale": projection.state_stale || projection.acceptance_head_stale,
            "plan": plan
        }),
    ))
}

fn run_cancel(
    context: &CallContext,
    request: &OperationRequest,
) -> Result<OperationResponse, PipelineFailure> {
    let payload: WorkspacePayload = parse_payload(request, "run.cancel")?;
    let workspace_root = context
        .authorize_write(&payload.workspace_root)
        .map_err(context_pipeline_failure("run.cancel"))?;
    let run_id = required_run_id(request)?;
    let _guard = WriteGuard::acquire(context, &workspace_root)?;
    let directory = run_dir(&workspace_root, run_id);
    authorize_write_path(context, &directory, "run.cancel")?;
    reject_symlinks_below(&directory, "run.cancel")?;
    if !directory.is_dir() {
        return Err(PipelineFailure {
            code: ErrorCode::NotFound,
            stage: "run.cancel",
            message: format!("run does not exist: {run_id}"),
            recovery_hint: "use the exact run_id returned by build.plan",
        });
    }
    let state = reconcile_run_for_mutation(context, &directory, request, "run.cancel")?;
    let cancelled = match state.state {
        RunState::Cancelled => state,
        RunState::Finalized => {
            return Err(PipelineFailure::state(
                "finalized runs are immutable and cannot be cancelled",
            ));
        }
        RunState::Planned | RunState::AwaitingSummary | RunState::ReadyToFinalize => {
            let mut cancelled = state;
            cancelled.state = RunState::Cancelled;
            append_event(context, &directory, request, &cancelled)?;
            write_json_atomic(&directory.join("state.json"), &cancelled, "run.cancel")?;
            cancelled
        }
    };
    Ok(status_response(
        request,
        OperationStatus::Cancelled,
        json!({
            "state": cancelled.state,
            "cancelled": true,
        }),
    ))
}

fn bundle_verify(
    context: &CallContext,
    request: &OperationRequest,
) -> Result<OperationResponse, PipelineFailure> {
    let mut payload: BundlePathPayload = parse_payload(request, "bundle.verify")?;
    payload.bundle_path = context
        .authorize_read(&payload.bundle_path)
        .map_err(context_pipeline_failure("bundle.verify"))?;
    let expected = payload
        .expected_tree_sha256
        .as_deref()
        .ok_or_else(|| PipelineFailure::lock("bundle.verify requires full expected_tree_sha256"))?;
    require_current_bundle_marker_after_digest_match(&payload.bundle_path, expected)?;
    let manifest = verify_bundle_expected(&payload.bundle_path, expected, "bundle.verify", true)?;
    if let Some(expected) = payload.expected_manifest_sha256.as_deref() {
        validate_sha256(expected).map_err(|error| {
            PipelineFailure::bundle(format!("invalid expected manifest digest: {error}"))
        })?;
        let observed = sha256_file(&payload.bundle_path.join("artifact-manifest.json"))
            .map_err(map_file_model("bundle.verify"))?;
        if observed != expected {
            return Err(PipelineFailure::bundle("expected manifest digest mismatch"));
        }
    }
    Ok(OperationResponse::completed(
        request,
        json!({
            "valid": true,
            "bundle_path": payload.bundle_path,
            "semantic_digest": manifest.semantic_digest,
            "source_count": manifest.sources.len(),
            "tree_digest": expected,
        }),
    ))
}

fn require_current_bundle_marker_after_digest_match(
    root: &Path,
    expected_tree_sha256: &str,
) -> Result<(), PipelineFailure> {
    validate_sha256(expected_tree_sha256).map_err(|error| {
        expected_digest_failure(
            "bundle.verify",
            true,
            format!("invalid expected tree digest: {error}"),
        )
    })?;
    let observed = tree_sha256(root).map_err(map_file_model("bundle.verify"))?;
    if observed != expected_tree_sha256 {
        return Err(expected_digest_failure(
            "bundle.verify",
            true,
            "expected tree digest mismatch before compatibility classification",
        ));
    }
    let marker = root.join("index.gtkg.json");
    if !marker
        .try_exists()
        .map_err(|error| PipelineFailure::io("bundle.verify", &marker, error))?
    {
        return Err(PipelineFailure {
            code: ErrorCode::BundleInvalid,
            stage: "bundle.compatibility",
            message: "bundle root is missing the current index.gtkg.json marker; legacy bundles require a stable rebuild"
                .to_owned(),
            recovery_hint: "rebuild the legacy bundle with the current GTKG pipeline and retry bundle.verify",
        });
    }
    Ok(())
}

fn bundle_query(
    context: &CallContext,
    request: &OperationRequest,
) -> Result<OperationResponse, PipelineFailure> {
    let mut payload: BundleQueryPayload = parse_payload(request, "bundle.query")?;
    payload.bundle_path = context
        .authorize_read(&payload.bundle_path)
        .map_err(context_pipeline_failure("bundle.query"))?;
    let expected = required_expected_digest(
        payload.expected_tree_sha256.as_deref(),
        "bundle.query",
        "expected_tree_sha256",
    )?;
    let manifest = verify_bundle_expected(&payload.bundle_path, expected, "bundle.query", false)?;
    let source_digests: BTreeMap<SourceKey, String> = manifest
        .sources
        .iter()
        .map(|entry| (entry.source_key.clone(), entry.source_sha256.clone()))
        .collect();
    let search_path = safe_join(&payload.bundle_path, "indexes/search.ndjson")?;
    let search_source = fs::read_to_string(&search_path)
        .map_err(|error| PipelineFailure::io("bundle.query", &search_path, error))?;
    let mut indexed = BTreeMap::new();
    for (line_number, line) in search_source.lines().enumerate() {
        if line.trim().is_empty() {
            return Err(PipelineFailure::bundle(format!(
                "search index contains an empty row at line {}",
                line_number + 1
            )));
        }
        let row: SearchIndexRow = serde_json::from_str(line).map_err(|error| {
            PipelineFailure::bundle(format!(
                "invalid search index row {}: {error}",
                line_number + 1
            ))
        })?;
        if indexed.insert(row.resource.clone(), row).is_some() {
            return Err(PipelineFailure::bundle(
                "search index contains a duplicate knowledge resource",
            ));
        }
    }
    if indexed.len() != manifest.knowledge.len() {
        return Err(PipelineFailure::bundle(
            "search index row count does not close over bundle knowledge",
        ));
    }
    let mut documents = Vec::with_capacity(manifest.knowledge.len());
    for knowledge in &manifest.knowledge {
        let row = indexed.remove(&knowledge.path).ok_or_else(|| {
            PipelineFailure::bundle(format!(
                "search index is missing knowledge resource {}",
                knowledge.path
            ))
        })?;
        let expected_id = Path::new(&knowledge.path)
            .file_stem()
            .and_then(|value| value.to_str())
            .map(|stable_id| format!("knowledge:{stable_id}"))
            .ok_or_else(|| PipelineFailure::bundle("knowledge path has no stable id"))?;
        if row.knowledge_id != expected_id || row.source_key != knowledge.source_key {
            return Err(PipelineFailure::bundle(format!(
                "search index identity drifted for {}",
                knowledge.path
            )));
        }
        let source_sha256 = source_digests
            .get(&knowledge.source_key)
            .cloned()
            .ok_or_else(|| {
                PipelineFailure::bundle(format!(
                    "knowledge {} has no manifest source digest",
                    knowledge.path
                ))
            })?;
        documents.push(crate::query::QueryDocument {
            source_key: knowledge.source_key.clone(),
            knowledge_path: knowledge.path.clone(),
            knowledge_sha256: knowledge.sha256.clone(),
            source_sha256,
            content: row.text,
        });
    }
    if !indexed.is_empty() {
        return Err(PipelineFailure::bundle(
            "search index contains resources outside bundle knowledge",
        ));
    }
    let mut result = crate::query::ranked_query(&payload.query, &documents);
    if let Some(object) = result.as_object_mut() {
        object.insert(
            "retrieval_source".to_owned(),
            Value::String("indexes/search.ndjson".to_owned()),
        );
        object.insert(
            "progressive_load".to_owned(),
            json!({
                "index_rows_loaded": documents.len(),
                "knowledge_documents_loaded_for_ranking": 0,
                "bundle_verification": "full_digest_closure_before_ranking"
            }),
        );
    }
    Ok(OperationResponse::completed(request, result))
}

fn bundle_compare(
    context: &CallContext,
    request: &OperationRequest,
) -> Result<OperationResponse, PipelineFailure> {
    let mut payload: BundleComparePayload = parse_payload(request, "bundle.compare")?;
    payload.left_bundle = context
        .authorize_read(&payload.left_bundle)
        .map_err(context_pipeline_failure("bundle.compare"))?;
    payload.right_bundle = context
        .authorize_read(&payload.right_bundle)
        .map_err(context_pipeline_failure("bundle.compare"))?;
    let left_expected = required_expected_digest(
        payload.left_expected_tree_sha256.as_deref(),
        "bundle.compare",
        "left_expected_tree_sha256",
    )?;
    let right_expected = required_expected_digest(
        payload.right_expected_tree_sha256.as_deref(),
        "bundle.compare",
        "right_expected_tree_sha256",
    )?;
    let left =
        verify_bundle_expected(&payload.left_bundle, left_expected, "bundle.compare", false)?;
    let right = verify_bundle_expected(
        &payload.right_bundle,
        right_expected,
        "bundle.compare",
        false,
    )?;
    let left_map: BTreeMap<SourceKey, String> = left
        .sources
        .iter()
        .map(|entry| (entry.source_key.clone(), entry.source_sha256.clone()))
        .collect();
    let right_map: BTreeMap<SourceKey, String> = right
        .sources
        .iter()
        .map(|entry| (entry.source_key.clone(), entry.source_sha256.clone()))
        .collect();
    let added: Vec<_> = right_map
        .keys()
        .filter(|key| !left_map.contains_key(*key))
        .cloned()
        .collect();
    let deleted: Vec<_> = left_map
        .keys()
        .filter(|key| !right_map.contains_key(*key))
        .cloned()
        .collect();
    let changed: Vec<_> = left_map
        .iter()
        .filter_map(|(key, digest)| {
            right_map
                .get(key)
                .filter(|right_digest| *right_digest != digest)
                .map(|_| key.clone())
        })
        .collect();
    Ok(OperationResponse::completed(
        request,
        json!({
            "added_sources": added,
            "deleted_sources": deleted,
            "changed_sources": changed,
            "semantic_equal": left.semantic_digest == right.semantic_digest,
        }),
    ))
}

fn snapshot_create(
    context: &CallContext,
    request: &OperationRequest,
) -> Result<OperationResponse, PipelineFailure> {
    let mut payload: SnapshotCreatePayload = parse_payload(request, "snapshot.create")?;
    payload.workspace_root = context
        .authorize_write(&payload.workspace_root)
        .map_err(context_pipeline_failure("snapshot.create"))?;
    payload.bundle_path = context
        .authorize_read(&payload.bundle_path)
        .map_err(context_pipeline_failure("snapshot.create"))?;
    validate_version(&payload.snapshot_version)?;
    let expected = required_expected_digest(
        payload.expected_bundle_tree_sha256.as_deref(),
        "snapshot.create",
        "expected_bundle_tree_sha256",
    )?;
    verify_bundle_expected(&payload.bundle_path, expected, "snapshot.create", false)?;
    let _guard = WriteGuard::acquire(context, &payload.workspace_root)?;
    let digest = tree_sha256(&payload.bundle_path).map_err(map_file_model("snapshot.create"))?;
    let versions = payload.workspace_root.join("artifacts/snapshots/versions");
    authorize_write_path(context, &versions, "snapshot.create")?;
    if let Some(snapshot_path) = exact_version_path(&versions, &payload.snapshot_version, &digest) {
        verify_bundle_expected(&snapshot_path, &digest, "snapshot.create", false)?;
        return Ok(OperationResponse::completed(
            request,
            json!({
                "snapshot_path": snapshot_path,
                "source_bundle": payload.bundle_path,
                "tree_digest": digest,
                "idempotent_replay": true,
            }),
        ));
    }
    let gtkg_root = payload.workspace_root.join(".gtkg");
    let legacy_staging = gtkg_root.join("snapshot-staging").join(&digest[7..31]);
    quarantine_staging(
        context,
        &gtkg_root,
        &legacy_staging,
        "legacy-snapshot-staging",
        "snapshot.create",
    )?;
    let request_digest = digest_string(&request.request_id);
    let staging = gtkg_root
        .join("staging")
        .join(format!("snapshot-create-{}", &request_digest[..24]));
    authorize_write_path(context, &staging, "snapshot.create")?;
    if staging.exists() {
        quarantine_staging(
            context,
            &gtkg_root,
            &staging,
            "snapshot-create-staging",
            "snapshot.create",
        )?;
    }
    copy_tree(&payload.bundle_path, &staging, "snapshot.create")?;
    verify_bundle_expected(&staging, expected, "snapshot.create", false)?;
    let snapshot_path = publish_immutable_version(&staging, &versions, &payload.snapshot_version)
        .map_err(map_file_model("snapshot.create"))?;
    verify_bundle_expected(&snapshot_path, &digest, "snapshot.create", false)?;
    if staging.exists() {
        quarantine_staging(
            context,
            &gtkg_root,
            &staging,
            "idempotent-snapshot-staging",
            "snapshot.create",
        )?;
    }
    Ok(OperationResponse::completed(
        request,
        json!({
            "snapshot_path": snapshot_path,
            "source_bundle": payload.bundle_path,
            "tree_digest": tree_sha256(&snapshot_path).map_err(map_file_model("snapshot.create"))?,
        }),
    ))
}

fn snapshot_verify(
    context: &CallContext,
    request: &OperationRequest,
) -> Result<OperationResponse, PipelineFailure> {
    let mut payload: SnapshotPathPayload = parse_payload(request, "snapshot.verify")?;
    payload.snapshot_path = context
        .authorize_read(&payload.snapshot_path)
        .map_err(context_pipeline_failure("snapshot.verify"))?;
    let expected = required_expected_digest(
        payload.expected_snapshot_tree_sha256.as_deref(),
        "snapshot.verify",
        "expected_snapshot_tree_sha256",
    )?;
    let manifest =
        verify_bundle_expected(&payload.snapshot_path, expected, "snapshot.verify", false)?;
    Ok(OperationResponse::completed(
        request,
        json!({
            "valid": true,
            "snapshot_path": payload.snapshot_path,
            "semantic_digest": manifest.semantic_digest,
        }),
    ))
}

fn snapshot_restore(
    context: &CallContext,
    request: &OperationRequest,
) -> Result<OperationResponse, PipelineFailure> {
    let mut payload: SnapshotRestorePayload = parse_payload(request, "snapshot.restore")?;
    payload.workspace_root = context
        .authorize_write(&payload.workspace_root)
        .map_err(context_pipeline_failure("snapshot.restore"))?;
    payload.snapshot_path = context
        .authorize_read(&payload.snapshot_path)
        .map_err(context_pipeline_failure("snapshot.restore"))?;
    validate_version(&payload.restore_version)?;
    let expected = required_expected_digest(
        payload.expected_snapshot_tree_sha256.as_deref(),
        "snapshot.restore",
        "expected_snapshot_tree_sha256",
    )?;
    verify_bundle_expected(&payload.snapshot_path, expected, "snapshot.restore", false)?;
    let _guard = WriteGuard::acquire(context, &payload.workspace_root)?;
    let digest = tree_sha256(&payload.snapshot_path).map_err(map_file_model("snapshot.restore"))?;
    let versions = payload.workspace_root.join("artifacts/restored/versions");
    authorize_write_path(context, &versions, "snapshot.restore")?;
    if let Some(restored_path) = exact_version_path(&versions, &payload.restore_version, &digest) {
        verify_bundle_expected(&restored_path, &digest, "snapshot.restore", false)?;
        return Ok(OperationResponse::completed(
            request,
            json!({
                "restored_path": restored_path,
                "tree_digest": digest,
                "idempotent_replay": true,
            }),
        ));
    }
    let gtkg_root = payload.workspace_root.join(".gtkg");
    let legacy_staging = gtkg_root.join("restore-staging").join(&digest[7..31]);
    quarantine_staging(
        context,
        &gtkg_root,
        &legacy_staging,
        "legacy-restore-staging",
        "snapshot.restore",
    )?;
    let request_digest = digest_string(&request.request_id);
    let staging = gtkg_root
        .join("staging")
        .join(format!("snapshot-restore-{}", &request_digest[..24]));
    authorize_write_path(context, &staging, "snapshot.restore")?;
    if staging.exists() {
        quarantine_staging(
            context,
            &gtkg_root,
            &staging,
            "snapshot-restore-staging",
            "snapshot.restore",
        )?;
    }
    copy_tree(&payload.snapshot_path, &staging, "snapshot.restore")?;
    verify_bundle_expected(&staging, expected, "snapshot.restore", false)?;
    let restored_path = publish_immutable_version(&staging, &versions, &payload.restore_version)
        .map_err(map_file_model("snapshot.restore"))?;
    verify_bundle_expected(&restored_path, &digest, "snapshot.restore", false)?;
    if staging.exists() {
        quarantine_staging(
            context,
            &gtkg_root,
            &staging,
            "idempotent-restore-staging",
            "snapshot.restore",
        )?;
    }
    Ok(OperationResponse::completed(
        request,
        json!({"restored_path": restored_path, "tree_digest": digest}),
    ))
}

fn render_bundle(
    root: &Path,
    plan: &RunPlan,
    summaries: &[SummaryCandidate],
    analysis_packets: &[AnalysisPacket],
    acceptances: &VerifiedAcceptance,
    semantic_digest: &str,
) -> Result<(), PipelineFailure> {
    for directory in [
        "locks",
        "knowledge/documents",
        "knowledge/architecture",
        "indexes",
        "reports",
        "evidence/analysis",
        "evidence/summaries",
        "evidence/acceptance",
        "projections",
    ] {
        fs::create_dir_all(root.join(directory))
            .map_err(|error| PipelineFailure::io("build.finalize", root, error))?;
    }
    write_json_atomic(
        &root.join("locks/source-lock.json"),
        &plan.source_lock,
        "build.finalize",
    )?;
    write_json_atomic(
        &root.join("locks/template-lock.json"),
        &plan.template_lock,
        "build.finalize",
    )?;
    write_json_atomic(
        &root.join("reports/omission-report.json"),
        &json!({
            "schema_version": "gtkg.omission-report/v1",
            "admitted_count": plan.source_lock.entries.len(),
            "omission_count": plan.omissions.len(),
            "omissions": plan.omissions,
        }),
        "build.finalize",
    )?;
    let acceptance_events = acceptances
        .events
        .iter()
        .map(|event| serde_json::to_value(event).unwrap_or(Value::Null))
        .collect::<Vec<_>>();
    write_ndjson(
        &root.join("evidence/acceptance/events.ndjson"),
        &acceptance_events,
        "build.finalize",
    )?;
    write_json_atomic(
        &root.join("evidence/acceptance/head.json"),
        &acceptances.head,
        "build.finalize",
    )?;

    let source_by_key: BTreeMap<SourceKey, &SourceManifestEntry> = plan
        .source_lock
        .entries
        .iter()
        .map(|entry| (source_key(entry), entry))
        .collect();
    let analysis_by_key: BTreeMap<SourceKey, &AnalysisPacket> = analysis_packets
        .iter()
        .map(|packet| {
            (
                SourceKey {
                    repo_id: packet.repo_id.clone(),
                    logical_path: packet.source_path.clone(),
                },
                packet,
            )
        })
        .collect();
    let module_index = ModuleIndex::from_packets(analysis_packets);
    let mut knowledge = Vec::new();
    let mut analysis = Vec::new();
    let mut canonical_documents = Vec::new();
    let mut graph_lines = Vec::new();
    let mut search_lines = Vec::new();
    for summary in summaries {
        let key = SourceKey {
            repo_id: summary.repo_id.clone(),
            logical_path: summary.source_path.clone(),
        };
        let entry = source_by_key.get(&key).ok_or_else(|| {
            PipelineFailure::lock(format!(
                "summary references unlocked source {}:{}",
                summary.repo_id, summary.source_path
            ))
        })?;
        let stable_id = digest_string(&format!("{}:{}", entry.repo_id, entry.logical_path));
        let packet = analysis_by_key.get(&key).ok_or_else(|| {
            PipelineFailure::lock(format!(
                "missing analysis evidence for {}:{}",
                key.repo_id, key.logical_path
            ))
        })?;
        if packet.packet_id != summary.packet_id {
            return Err(PipelineFailure::lock(format!(
                "analysis packet does not bind summary for {}:{}",
                key.repo_id, key.logical_path
            )));
        }
        let analysis_path = format!("evidence/analysis/{stable_id}.json");
        write_json_atomic(&root.join(&analysis_path), packet, "build.finalize")?;
        let analysis_sha256 =
            sha256_file(&root.join(&analysis_path)).map_err(map_file_model("build.finalize"))?;
        analysis.push(ArtifactAnalysis {
            source_key: key.clone(),
            packet_id: packet.packet_id.clone(),
            source_sha256: packet.source_sha256.clone(),
            extractor_id: packet.extractor_id.clone(),
            path: analysis_path.clone(),
            sha256: analysis_sha256.clone(),
            fact_count: packet.observed_facts.len() as u64,
        });
        let relative = format!("knowledge/documents/{stable_id}.md");
        let document = render_knowledge_document(
            &format!("{stable_id}.md"),
            entry,
            summary,
            &stable_id,
            &analysis_path,
            &analysis_sha256,
        )?;
        let path = root.join(&relative);
        fs::write(&path, document.as_bytes())
            .map_err(|error| PipelineFailure::io("build.finalize", &path, error))?;
        let digest = sha256_file(&path).map_err(map_file_model("build.finalize"))?;
        canonical_documents.push(ArtifactDocument {
            path: relative.clone(),
            sha256: digest.clone(),
        });
        let summary_receipt_path = format!("evidence/summaries/{stable_id}.json");
        write_json_atomic(&root.join(&summary_receipt_path), summary, "build.finalize")?;
        let summary_receipt_sha256 = sha256_file(&root.join(&summary_receipt_path))
            .map_err(map_file_model("build.finalize"))?;
        let acceptance = acceptances
            .receipts
            .get(&summary.packet_id)
            .ok_or_else(|| {
                PipelineFailure::lock(format!(
                    "missing acceptance evidence for {}",
                    summary.packet_id
                ))
            })?;
        let acceptance_receipt_path = format!("evidence/acceptance/{stable_id}.json");
        write_json_atomic(
            &root.join(&acceptance_receipt_path),
            acceptance,
            "build.finalize",
        )?;
        let acceptance_receipt_sha256 = sha256_file(&root.join(&acceptance_receipt_path))
            .map_err(map_file_model("build.finalize"))?;
        knowledge.push(ArtifactKnowledge {
            source_key: key.clone(),
            packet_id: summary.packet_id.clone(),
            path: relative.clone(),
            sha256: digest,
            summary_receipt_path: summary_receipt_path.clone(),
            summary_receipt_sha256,
            acceptance_receipt_path,
            acceptance_receipt_sha256,
        });
        graph_lines.extend(graph_rows_for_source(&GraphSource {
            key: &key,
            source_sha256: &entry.content_sha256,
            packet,
            stable_id: &stable_id,
            knowledge_path: &relative,
            summary_receipt_path: &summary_receipt_path,
            analysis_path: &analysis_path,
            index: &module_index,
        }));
        search_lines.push(json!({
            "knowledge_id": format!("knowledge:{stable_id}"),
            "source_key": source_key(entry),
            "resource": relative,
            "text": document,
        }));
    }
    knowledge.sort_by(|left, right| left.source_key.cmp(&right.source_key));
    analysis.sort_by(|left, right| left.source_key.cmp(&right.source_key));
    write_ndjson(
        &root.join("indexes/graph.ndjson"),
        &graph_lines,
        "build.finalize",
    )?;
    write_ndjson(
        &root.join("indexes/search.ndjson"),
        &search_lines,
        "build.finalize",
    )?;
    let source_lines = plan
        .source_lock
        .entries
        .iter()
        .map(|entry| serde_json::to_value(entry).unwrap_or(Value::Null))
        .collect::<Vec<_>>();
    write_ndjson(
        &root.join("indexes/source-manifest.ndjson"),
        &source_lines,
        "build.finalize",
    )?;

    for name in ["agent", "claude", "rules", "architecture", "design"] {
        let relative = format!("knowledge/architecture/{name}.md");
        let body = architecture_body(
            name,
            &plan.source_lock.entries,
            analysis_packets,
            summaries,
            &plan.bundle_version,
            knowledge.len(),
        );
        let document = render_okf(
            "architecture",
            &format!("GTKG {name}"),
            architecture_description(name),
            &format!("{name}.md"),
            "gtkg.architecture/v2",
            &body,
            vec!["gtkg".to_owned(), "architecture".to_owned()],
            Vec::new(),
            BTreeMap::from([
                (
                    "semantic_digest".to_owned(),
                    YamlValue::String(semantic_digest.to_owned()),
                ),
                (
                    "bundle_version".to_owned(),
                    YamlValue::String(plan.bundle_version.clone()),
                ),
                (
                    "generator_version".to_owned(),
                    YamlValue::String(format!("gtkg/{}", env!("CARGO_PKG_VERSION"))),
                ),
                (
                    "document_version".to_owned(),
                    YamlValue::String(format!(
                        "{}+gtkg.{}",
                        plan.bundle_version,
                        env!("CARGO_PKG_VERSION")
                    )),
                ),
                ("revision".to_owned(), YamlValue::Number(1_u64.into())),
            ]),
        )?;
        let path = root.join(relative);
        fs::write(&path, document)
            .map_err(|error| PipelineFailure::io("build.finalize", &path, error))?;
        canonical_documents.push(ArtifactDocument {
            path: format!("knowledge/architecture/{name}.md"),
            sha256: sha256_file(&path).map_err(map_file_model("build.finalize"))?,
        });
    }

    canonical_documents.sort_by(|left, right| left.path.cmp(&right.path));

    let sources = plan
        .source_lock
        .entries
        .iter()
        .map(|entry| ArtifactSource {
            source_key: source_key(entry),
            source_sha256: entry.content_sha256.clone(),
            role: entry.role.clone(),
            bytes: entry.bytes,
        })
        .collect();
    let manifest = ArtifactManifest {
        schema_version: MANIFEST_SCHEMA.to_owned(),
        bundle_version: plan.bundle_version.clone(),
        semantic_digest: semantic_digest.to_owned(),
        source_lock: plan.source_lock.clone(),
        template_lock: plan.template_lock.clone(),
        sources,
        knowledge,
        analysis,
        canonical_documents,
    };
    write_json_atomic(
        &root.join("artifact-manifest.json"),
        &manifest,
        "build.finalize",
    )?;
    write_checksums(root)?;
    Ok(())
}

fn render_knowledge_document(
    relative: &str,
    source: &SourceManifestEntry,
    summary: &SummaryCandidate,
    stable_id: &str,
    analysis_path: &str,
    analysis_sha256: &str,
) -> Result<String, PipelineFailure> {
    let sources = vec![SourceEntry {
        // SPEC §5.1: `resource` is required within an entry; the repo-relative
        // logical path names the artifact, with repo_id/sha256 kept as
        // tolerated extra credibility keys (SPEC §11).
        resource: source.logical_path.clone(),
        extra: BTreeMap::from([
            (
                "repo_id".to_owned(),
                YamlValue::String(source.repo_id.clone()),
            ),
            (
                "sha256".to_owned(),
                YamlValue::String(source.content_sha256.clone()),
            ),
        ]),
    }];
    render_okf(
        "knowledge",
        &format!("Summary: {}", source.logical_path),
        "Accepted source-bound summary",
        relative,
        "gtkg.knowledge/v1",
        &format!(
            "# {}\n\n{}\n",
            source.logical_path, summary.summary_markdown
        ),
        vec!["gtkg".to_owned(), "summary".to_owned()],
        sources,
        BTreeMap::from([
            (
                "knowledge_id".to_owned(),
                YamlValue::String(format!("knowledge:{stable_id}")),
            ),
            ("revision".to_owned(), YamlValue::Number(1_u64.into())),
            (
                "template_manifest_sha256".to_owned(),
                YamlValue::String(summary.template_manifest_sha256.clone()),
            ),
            (
                "source_sha256".to_owned(),
                YamlValue::String(summary.source_sha256.clone()),
            ),
            (
                "analysis_ref".to_owned(),
                YamlValue::String(analysis_path.to_owned()),
            ),
            (
                "analysis_sha256".to_owned(),
                YamlValue::String(analysis_sha256.to_owned()),
            ),
        ]),
    )
}

#[allow(clippy::too_many_arguments)]
fn render_okf(
    kind: &str,
    title: &str,
    description: &str,
    resource: &str,
    schema: &str,
    body: &str,
    tags: Vec<String>,
    sources: Vec<SourceEntry>,
    extensions: BTreeMap<String, YamlValue>,
) -> Result<String, PipelineFailure> {
    let mut gtkg = BTreeMap::from([
        ("schema".to_owned(), YamlValue::String(schema.to_owned())),
        (
            "progressive_loading".to_owned(),
            serde_yaml::to_value(BTreeMap::from([("level", "L2")]))
                .map_err(|error| PipelineFailure::invalid("build.finalize", error.to_string()))?,
        ),
        (
            "evidence_state".to_owned(),
            YamlValue::String("accepted_not_verified".to_owned()),
        ),
    ]);
    gtkg.extend(extensions);
    let normalized_body = normalize_text(body);
    let frontmatter = OkfFrontmatter {
        kind: kind.to_owned(),
        title: Some(title.to_owned()),
        description: Some(description.to_owned()),
        resource: Some(format!("./{resource}")),
        tags,
        generated: Some(GeneratedBy {
            by: format!("gtkg/{}", env!("CARGO_PKG_VERSION")),
            // The Core has no trustworthy wall-clock or source-authored change
            // timestamp in its locked inputs. SPEC §5.2 requires `generated.by`
            // but does not require `generated.at`; omitting it is more truthful
            // than deriving a fictional date from content bytes.
            at: String::new(),
            extra: BTreeMap::new(),
        }),
        verified: None,
        // "accepted_not_verified" evidence state maps to SPEC §5.4 `draft`.
        status: OkfStatus::Draft,
        stale_after: None,
        sources,
        okf_version: Some(crate::okf::OKF_VERSION.to_owned()),
        gtkg: Some(gtkg),
        extra: BTreeMap::new(),
    };
    let yaml = serde_yaml::to_string(&frontmatter)
        .map_err(|error| PipelineFailure::invalid("build.finalize", error.to_string()))?;
    Ok(format!("---\n{yaml}---\n\n{normalized_body}"))
}

fn verify_bundle_expected(
    root: &Path,
    expected_tree_sha256: &str,
    stage: &'static str,
    mismatch_is_bundle_invalid: bool,
) -> Result<ArtifactManifest, PipelineFailure> {
    validate_sha256(expected_tree_sha256).map_err(|error| {
        expected_digest_failure(
            stage,
            mismatch_is_bundle_invalid,
            format!("invalid expected tree digest: {error}"),
        )
    })?;
    let before = tree_sha256(root).map_err(map_file_model(stage))?;
    if before != expected_tree_sha256 {
        return Err(expected_digest_failure(
            stage,
            mismatch_is_bundle_invalid,
            "expected tree digest mismatch before verification",
        ));
    }
    let manifest = verify_bundle(root)?;
    let after = tree_sha256(root).map_err(map_file_model(stage))?;
    if after != expected_tree_sha256 {
        return Err(expected_digest_failure(
            stage,
            mismatch_is_bundle_invalid,
            "expected tree digest drifted during verification",
        ));
    }
    Ok(manifest)
}

/// Returns an owned projection input only after the exact D03 verifier has closed over the
/// caller-held full-tree digest. No mutable repository path or caller-reported source identity is
/// admitted into this view.
pub(crate) fn verified_projection_view(
    context: &CallContext,
    bundle_path: &Path,
    expected_full_tree_sha256: &str,
) -> Result<VerifiedProjectionView, PipelineFailure> {
    let bundle_path = context
        .authorize_read(bundle_path)
        .map_err(context_pipeline_failure("a2ui.generate"))?;
    let manifest = verify_bundle_expected(
        &bundle_path,
        expected_full_tree_sha256,
        "a2ui.generate",
        true,
    )?;
    let artifact_manifest_sha256 = sha256_file(&bundle_path.join("artifact-manifest.json"))
        .map_err(map_file_model("a2ui.generate"))?;
    let source_lock_sha256 = sha256_file(&bundle_path.join("locks/source-lock.json"))
        .map_err(map_file_model("a2ui.generate"))?;

    let canonical_documents = manifest
        .canonical_documents
        .iter()
        .map(|document| VerifiedProjectionFile {
            path: document.path.clone(),
            sha256: document.sha256.clone(),
        })
        .collect::<Vec<_>>();

    let mut indexes = Vec::new();
    for entry in WalkDir::new(&bundle_path)
        .follow_links(false)
        .sort_by_file_name()
    {
        let entry = entry.map_err(|error| {
            PipelineFailure::bundle(format!("projection index evidence walk failed: {error}"))
        })?;
        if !entry.file_type().is_file()
            || entry.path().file_name().and_then(|name| name.to_str()) != Some("index.md")
        {
            continue;
        }
        let path = entry
            .path()
            .strip_prefix(&bundle_path)
            .map_err(|error| PipelineFailure::bundle(format!("index path escape: {error}")))?
            .to_string_lossy()
            .into_owned();
        indexes.push(VerifiedProjectionFile {
            path,
            sha256: sha256_file(entry.path()).map_err(map_file_model("a2ui.generate"))?,
        });
    }
    indexes.sort_by(|left, right| left.path.cmp(&right.path));

    let source_by_key: BTreeMap<_, _> = manifest
        .sources
        .iter()
        .map(|source| (source.source_key.clone(), source))
        .collect();
    let analysis_by_key: BTreeMap<_, _> = manifest
        .analysis
        .iter()
        .map(|analysis| (analysis.source_key.clone(), analysis))
        .collect();
    let mut knowledge_resources = Vec::with_capacity(manifest.knowledge.len());
    for knowledge in &manifest.knowledge {
        let source = source_by_key.get(&knowledge.source_key).ok_or_else(|| {
            PipelineFailure::bundle("verified knowledge has no SourceLock closure")
        })?;
        let analysis = analysis_by_key.get(&knowledge.source_key).ok_or_else(|| {
            PipelineFailure::bundle("verified knowledge has no analysis evidence closure")
        })?;
        let knowledge_path = safe_join(&bundle_path, &knowledge.path)?;
        let okf_source = fs::read_to_string(&knowledge_path)
            .map_err(|error| PipelineFailure::io("a2ui.generate", &knowledge_path, error))?;
        let okf = crate::okf::parse_okf_concept(&okf_source).map_err(|error| {
            PipelineFailure::bundle(format!("verified OKF parse failed: {error}"))
        })?;
        crate::okf::validate_current_version(&okf.frontmatter).map_err(|error| {
            PipelineFailure::bundle(format!("verified OKF version failed: {error}"))
        })?;
        let knowledge_id = okf
            .frontmatter
            .gtkg
            .as_ref()
            .and_then(|gtkg| gtkg.get("knowledge_id"))
            .and_then(YamlValue::as_str)
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| PipelineFailure::bundle("verified OKF has no knowledge_id"))?
            .to_owned();
        let title = okf
            .frontmatter
            .title
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| PipelineFailure::bundle("verified OKF has no title"))?;
        let description = okf
            .frontmatter
            .description
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| PipelineFailure::bundle("verified OKF has no description"))?;
        // H04: carry the OKF v0.2 trust vocabulary (sources/status/revision)
        // into the A2UI data model as the selected document's provenance.
        let provenance = json!({
            "sources": okf.frontmatter.sources.iter().map(|entry| {
                let mut source = json!({ "resource": entry.resource });
                if let Some(map) = source.as_object_mut() {
                    for (key, value) in &entry.extra {
                        map.insert(
                            key.clone(),
                            serde_json::to_value(value).unwrap_or(Value::Null),
                        );
                    }
                }
                source
            }).collect::<Vec<_>>(),
            "status": serde_json::to_value(okf.frontmatter.status).unwrap_or(Value::Null),
            "revision": okf
                .frontmatter
                .gtkg
                .as_ref()
                .and_then(|gtkg| gtkg.get("revision"))
                .and_then(YamlValue::as_u64)
                .unwrap_or(1),
        });
        let analysis_path = safe_join(&bundle_path, &analysis.path)?;
        let packet: AnalysisPacket = read_json(&analysis_path, "a2ui.generate")?;
        validate_analysis_packet(
            &packet,
            &knowledge.source_key,
            &source.source_sha256,
            analysis.fact_count,
            "bundle.verify",
        )?;
        knowledge_resources.push(VerifiedProjectionKnowledge {
            source_key: knowledge.source_key.clone(),
            source_sha256: source.source_sha256.clone(),
            knowledge_id,
            knowledge_path: knowledge.path.clone(),
            knowledge_sha256: knowledge.sha256.clone(),
            title,
            description,
            body: okf.body,
            provenance,
            analysis_path: analysis.path.clone(),
            analysis_sha256: analysis.sha256.clone(),
            packet_id: packet.packet_id,
            media_type: packet.media_type,
            extractor_id: packet.extractor_id,
            observed_facts: packet.observed_facts,
            target_process_count: packet.target_process_count,
            executed_target_content: packet.executed_target_content,
        });
    }
    knowledge_resources.sort_by(|left, right| left.source_key.cmp(&right.source_key));

    let after = tree_sha256(&bundle_path).map_err(map_file_model("a2ui.generate"))?;
    if after != expected_full_tree_sha256 {
        return Err(PipelineFailure::bundle(
            "bundle tree digest drifted while constructing the verified projection view",
        ));
    }
    Ok(VerifiedProjectionView {
        bundle_path,
        bundle_tree_sha256: expected_full_tree_sha256.to_owned(),
        artifact_manifest_sha256,
        source_lock_sha256,
        manifest,
        canonical_documents,
        indexes,
        knowledge: knowledge_resources,
    })
}

fn required_expected_digest<'a>(
    value: Option<&'a str>,
    stage: &'static str,
    field: &'static str,
) -> Result<&'a str, PipelineFailure> {
    value.ok_or_else(|| {
        let mut failure =
            PipelineFailure::lock(format!("{stage} requires caller-supplied full {field}"));
        failure.stage = stage;
        failure
    })
}

fn expected_digest_failure(
    stage: &'static str,
    mismatch_is_bundle_invalid: bool,
    message: impl Into<String>,
) -> PipelineFailure {
    if mismatch_is_bundle_invalid {
        PipelineFailure::bundle(message)
    } else {
        let mut failure = PipelineFailure::lock(message);
        failure.stage = stage;
        failure
    }
}

fn verify_bundle(root: &Path) -> Result<ArtifactManifest, PipelineFailure> {
    if !root.is_dir() {
        return Err(PipelineFailure::bundle(format!(
            "bundle is not a directory: {}",
            root.display()
        )));
    }
    validate_index_tree(root)
        .map_err(|error| PipelineFailure::bundle(format!("index closure invalid: {error}")))?;
    let manifest_path = root.join("artifact-manifest.json");
    let manifest: ArtifactManifest = read_json(&manifest_path, "bundle.verify")?;
    if manifest.schema_version != MANIFEST_SCHEMA {
        return Err(PipelineFailure::bundle(format!(
            "unsupported artifact manifest schema {}",
            manifest.schema_version
        )));
    }
    manifest
        .source_lock
        .validate()
        .map_err(|error| PipelineFailure::bundle(error.to_string()))?;
    manifest
        .template_lock
        .validate()
        .map_err(|error| PipelineFailure::bundle(error.to_string()))?;

    let locked_source: SourceLock =
        read_json(&root.join("locks/source-lock.json"), "bundle.verify")?;
    let locked_template: TemplateLock =
        read_json(&root.join("locks/template-lock.json"), "bundle.verify")?;
    if locked_source != manifest.source_lock || locked_template != manifest.template_lock {
        return Err(PipelineFailure::bundle(
            "manifest locks do not match the canonical lock files",
        ));
    }

    let expected_sources: BTreeSet<_> = manifest
        .source_lock
        .entries
        .iter()
        .map(|entry| {
            (
                source_key(entry),
                entry.content_sha256.clone(),
                entry.role.clone(),
                entry.bytes,
            )
        })
        .collect();
    let observed_sources: BTreeSet<_> = manifest
        .sources
        .iter()
        .map(|entry| {
            (
                entry.source_key.clone(),
                entry.source_sha256.clone(),
                entry.role.clone(),
                entry.bytes,
            )
        })
        .collect();
    if expected_sources != observed_sources || manifest.sources.len() != expected_sources.len() {
        return Err(PipelineFailure::bundle(
            "artifact sources do not exactly close over SourceLock entries",
        ));
    }
    if !manifest
        .sources
        .windows(2)
        .all(|pair| pair[0].source_key < pair[1].source_key)
        || !manifest
            .knowledge
            .windows(2)
            .all(|pair| pair[0].source_key < pair[1].source_key)
        || !manifest
            .analysis
            .windows(2)
            .all(|pair| pair[0].source_key < pair[1].source_key)
        || !manifest
            .canonical_documents
            .windows(2)
            .all(|pair| pair[0].path < pair[1].path)
    {
        return Err(PipelineFailure::bundle(
            "artifact manifest arrays must be strictly sorted exact sets",
        ));
    }

    let expected_document_paths: BTreeSet<String> = WalkDir::new(root)
        .follow_links(false)
        .sort_by_file_name()
        .into_iter()
        .map(|entry| {
            entry.map_err(|error| PipelineFailure::bundle(format!("bundle walk failed: {error}")))
        })
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter(|entry| {
            entry.file_type().is_file()
                && entry.path().extension().and_then(|value| value.to_str()) == Some("md")
                && entry.path().file_name().and_then(|value| value.to_str()) != Some("index.md")
        })
        .map(|entry| {
            entry
                .path()
                .strip_prefix(root)
                .map(|path| path.to_string_lossy().into_owned())
                .map_err(|error| PipelineFailure::bundle(format!("document path escape: {error}")))
        })
        .collect::<Result<_, _>>()?;
    let manifest_document_paths: BTreeSet<_> = manifest
        .canonical_documents
        .iter()
        .map(|entry| entry.path.clone())
        .collect();
    if manifest_document_paths != expected_document_paths
        || manifest.canonical_documents.len() != manifest_document_paths.len()
    {
        return Err(PipelineFailure::bundle(
            "canonical document manifest is not an exact set",
        ));
    }
    for required in ["agent", "claude", "rules", "architecture", "design"] {
        let path = format!("knowledge/architecture/{required}.md");
        if !manifest_document_paths.contains(&path) {
            return Err(PipelineFailure::bundle(format!(
                "required architecture document is missing: {path}"
            )));
        }
    }
    for document in &manifest.canonical_documents {
        let path = safe_join(root, &document.path)?;
        if sha256_file(&path).map_err(map_file_model("bundle.verify"))? != document.sha256 {
            return Err(PipelineFailure::bundle(format!(
                "canonical document digest mismatch: {}",
                document.path
            )));
        }
        validate_okf_resource_self(root, &path)?;
    }

    let acceptance_events = read_bundle_acceptance_events(root)?;
    let acceptance_by_packet: BTreeMap<_, _> = acceptance_events
        .iter()
        .map(|event| (event.packet_id.as_str(), event))
        .collect();
    if acceptance_by_packet.len() != acceptance_events.len() {
        return Err(PipelineFailure::bundle(
            "bundle acceptance evidence contains duplicate packet_id",
        ));
    }

    let mut paths = BTreeSet::new();
    let mut knowledge_keys = BTreeSet::new();
    let mut packet_ids = BTreeSet::new();
    let mut accepted_packet_ids = BTreeSet::new();
    let mut candidates = Vec::new();
    for knowledge in &manifest.knowledge {
        if !paths.insert(knowledge.path.as_str()) {
            return Err(PipelineFailure::bundle(format!(
                "duplicate knowledge path {}",
                knowledge.path
            )));
        }
        let path = safe_join(root, &knowledge.path)?;
        if sha256_file(&path).map_err(map_file_model("bundle.verify"))? != knowledge.sha256 {
            return Err(PipelineFailure::bundle(format!(
                "knowledge digest mismatch: {}",
                knowledge.path
            )));
        }
        if !knowledge_keys.insert(knowledge.source_key.clone()) {
            return Err(PipelineFailure::bundle(format!(
                "duplicate knowledge SourceKey {}:{}",
                knowledge.source_key.repo_id, knowledge.source_key.logical_path
            )));
        }
        let source = manifest
            .sources
            .iter()
            .find(|source| source.source_key == knowledge.source_key)
            .ok_or_else(|| PipelineFailure::bundle("knowledge references an unlocked source"))?;
        let receipt_path = safe_join(root, &knowledge.summary_receipt_path)?;
        if sha256_file(&receipt_path).map_err(map_file_model("bundle.verify"))?
            != knowledge.summary_receipt_sha256
        {
            return Err(PipelineFailure::bundle(format!(
                "summary receipt digest mismatch: {}",
                knowledge.summary_receipt_path
            )));
        }
        let candidate: SummaryCandidate = read_json(&receipt_path, "bundle.verify")?;
        if candidate.schema_version != "gtkg.summary-candidate/v1"
            || validate_path_identifier("packet_id", &candidate.packet_id).is_err()
            || candidate.packet_id != knowledge.packet_id
            || !packet_ids.insert(candidate.packet_id.clone())
            || candidate.repo_id != knowledge.source_key.repo_id
            || candidate.source_path != knowledge.source_key.logical_path
            || candidate.source_sha256 != source.source_sha256
            || candidate.template_manifest_sha256 != manifest.template_lock.template.manifest_sha256
        {
            return Err(PipelineFailure::bundle(format!(
                "summary receipt does not close over source/template locks: {}",
                knowledge.summary_receipt_path
            )));
        }
        let acceptance_path = safe_join(root, &knowledge.acceptance_receipt_path)?;
        if sha256_file(&acceptance_path).map_err(map_file_model("bundle.verify"))?
            != knowledge.acceptance_receipt_sha256
        {
            return Err(PipelineFailure::bundle(format!(
                "acceptance receipt digest mismatch: {}",
                knowledge.acceptance_receipt_path
            )));
        }
        let acceptance: AcceptedSummaryReceipt = read_json(&acceptance_path, "bundle.verify")?;
        let acceptance_event = acceptance_by_packet
            .get(candidate.packet_id.as_str())
            .ok_or_else(|| {
                PipelineFailure::bundle(format!(
                    "acceptance event is missing for {}",
                    candidate.packet_id
                ))
            })?;
        if acceptance.schema_version != "gtkg.accepted-summary/v1"
            || acceptance.packet_id != candidate.packet_id
            || acceptance.candidate_sha256 != knowledge.summary_receipt_sha256
            || acceptance_event.candidate_sha256 != knowledge.summary_receipt_sha256
            || acceptance_event.acceptance_receipt_sha256 != knowledge.acceptance_receipt_sha256
            || !accepted_packet_ids.insert(candidate.packet_id.clone())
        {
            return Err(PipelineFailure::bundle(format!(
                "acceptance evidence does not bind the summary receipt: {}",
                knowledge.acceptance_receipt_path
            )));
        }
        candidates.push(candidate);
    }
    let source_keys: BTreeSet<_> = manifest
        .sources
        .iter()
        .map(|entry| entry.source_key.clone())
        .collect();
    if knowledge_keys != source_keys || manifest.knowledge.len() != manifest.sources.len() {
        return Err(PipelineFailure::bundle(
            "knowledge does not exactly close over artifact sources",
        ));
    }
    if accepted_packet_ids.len() != acceptance_events.len() {
        return Err(PipelineFailure::bundle(
            "acceptance event chain is not an exact set for bundle knowledge",
        ));
    }
    let expected_analysis_paths: BTreeSet<String> = WalkDir::new(root.join("evidence/analysis"))
        .follow_links(false)
        .sort_by_file_name()
        .into_iter()
        .map(|entry| {
            entry.map_err(|error| {
                PipelineFailure::bundle(format!("analysis evidence walk failed: {error}"))
            })
        })
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter(|entry| {
            entry.file_type().is_file()
                && !matches!(
                    entry.path().file_name().and_then(|name| name.to_str()),
                    Some("index.md" | "index.gtkg.json")
                )
        })
        .map(|entry| {
            entry
                .path()
                .strip_prefix(root)
                .map(|path| path.to_string_lossy().into_owned())
                .map_err(|error| {
                    PipelineFailure::bundle(format!("analysis evidence path escape: {error}"))
                })
        })
        .collect::<Result<_, _>>()?;
    let manifest_analysis_paths: BTreeSet<_> = manifest
        .analysis
        .iter()
        .map(|entry| entry.path.clone())
        .collect();
    if manifest_analysis_paths != expected_analysis_paths
        || manifest.analysis.len() != manifest_analysis_paths.len()
    {
        return Err(PipelineFailure::bundle(
            "analysis evidence manifest is not an exact file set",
        ));
    }
    let knowledge_by_key: BTreeMap<_, _> = manifest
        .knowledge
        .iter()
        .map(|entry| (entry.source_key.clone(), entry))
        .collect();
    let source_by_key: BTreeMap<_, _> = manifest
        .sources
        .iter()
        .map(|entry| (entry.source_key.clone(), entry))
        .collect();
    let mut analysis_keys = BTreeSet::new();
    let mut analysis_packet_ids = BTreeSet::new();
    let mut analysis_packets = Vec::new();
    for entry in &manifest.analysis {
        let source = source_by_key.get(&entry.source_key).ok_or_else(|| {
            PipelineFailure::bundle("analysis evidence references an unlocked source")
        })?;
        let knowledge = knowledge_by_key.get(&entry.source_key).ok_or_else(|| {
            PipelineFailure::bundle("analysis evidence has no matching knowledge resource")
        })?;
        let path = safe_join(root, &entry.path)?;
        if sha256_file(&path).map_err(map_file_model("bundle.verify"))? != entry.sha256 {
            return Err(PipelineFailure::bundle(format!(
                "analysis evidence digest mismatch: {}",
                entry.path
            )));
        }
        let packet: AnalysisPacket = read_json(&path, "bundle.verify")?;
        validate_analysis_packet(
            &packet,
            &entry.source_key,
            &entry.source_sha256,
            entry.fact_count,
            "bundle.verify",
        )?;
        if entry.source_sha256 != source.source_sha256
            || packet.source_bytes != source.bytes
            || entry.extractor_id != packet.extractor_id
            || entry.packet_id != packet.packet_id
            || knowledge.packet_id != packet.packet_id
            || packet.template_manifest_sha256 != manifest.template_lock.template.manifest_sha256
            || !analysis_keys.insert(entry.source_key.clone())
            || !analysis_packet_ids.insert(packet.packet_id.clone())
        {
            return Err(PipelineFailure::bundle(format!(
                "analysis evidence does not close over canonical locks: {}",
                entry.path
            )));
        }
        analysis_packets.push(packet);
    }
    if analysis_keys != source_keys || manifest.analysis.len() != manifest.sources.len() {
        return Err(PipelineFailure::bundle(
            "analysis evidence does not exactly close over artifact sources",
        ));
    }
    candidates.sort_by(|left, right| {
        (&left.repo_id, &left.source_path).cmp(&(&right.repo_id, &right.source_path))
    });
    analysis_packets.sort_by(|left, right| {
        (&left.repo_id, &left.source_path).cmp(&(&right.repo_id, &right.source_path))
    });
    let semantic_digest = canonical_json_sha256(&SemanticInput {
        source_lock: &manifest.source_lock,
        template_lock: &manifest.template_lock,
        summaries: &candidates,
        analysis: &analysis_packets,
    })
    .map_err(|error| PipelineFailure::bundle(format!("semantic digest failed: {error}")))?;
    if semantic_digest != manifest.semantic_digest {
        return Err(PipelineFailure::bundle(
            "semantic digest does not match the source/template/summary closure",
        ));
    }
    verify_derived_bundle(
        root,
        &manifest,
        &candidates,
        &analysis_packets,
        &semantic_digest,
    )?;
    verify_checksums(root)?;
    Ok(manifest)
}

fn read_bundle_acceptance_events(root: &Path) -> Result<Vec<AcceptanceEvent>, PipelineFailure> {
    let events_path = root.join("evidence/acceptance/events.ndjson");
    let head_path = root.join("evidence/acceptance/head.json");
    let head: AcceptanceHead = read_json(&head_path, "bundle.verify")?;
    if head.schema_version != "gtkg.acceptance-head/v1"
        || validate_sha256(&head.run_plan_sha256).is_err()
        || validate_sha256(&head.head_sha256).is_err()
    {
        return Err(PipelineFailure::bundle("bundle acceptance head is invalid"));
    }
    let source = fs::read_to_string(&events_path)
        .map_err(|error| PipelineFailure::io("bundle.verify", &events_path, error))?;
    let mut events = Vec::new();
    let mut previous = None;
    let mut packet_ids = BTreeSet::new();
    for (index, line) in source.lines().enumerate() {
        let event: AcceptanceEvent = serde_json::from_str(line).map_err(|error| {
            PipelineFailure::bundle(format!("invalid bundled acceptance event: {error}"))
        })?;
        let event_digest = acceptance_event_sha256(&event).map_err(|error| {
            PipelineFailure::bundle(format!(
                "bundled acceptance event digest failed: {}",
                error.message
            ))
        })?;
        if line.trim().is_empty()
            || event.schema_version != "gtkg.acceptance-event/v1"
            || event.sequence != index as u64
            || event.run_plan_sha256 != head.run_plan_sha256
            || event.previous_event_sha256 != previous
            || validate_path_identifier("packet_id", &event.packet_id).is_err()
            || validate_sha256(&event.candidate_sha256).is_err()
            || validate_sha256(&event.acceptance_receipt_sha256).is_err()
            || event_digest != event.event_sha256
            || !packet_ids.insert(event.packet_id.clone())
        {
            return Err(PipelineFailure::bundle(format!(
                "bundled acceptance event chain is invalid at sequence {index}"
            )));
        }
        previous = Some(event.event_sha256.clone());
        events.push(event);
    }
    if events.is_empty()
        || head.event_count != events.len() as u64
        || Some(head.head_sha256.as_str()) != previous.as_deref()
    {
        return Err(PipelineFailure::bundle(
            "bundled acceptance head does not close over its event chain",
        ));
    }
    Ok(events)
}

fn verify_derived_bundle(
    root: &Path,
    manifest: &ArtifactManifest,
    candidates: &[SummaryCandidate],
    analysis_packets: &[AnalysisPacket],
    semantic_digest: &str,
) -> Result<(), PipelineFailure> {
    let source_by_key: BTreeMap<SourceKey, &SourceManifestEntry> = manifest
        .source_lock
        .entries
        .iter()
        .map(|entry| (source_key(entry), entry))
        .collect();
    let knowledge_by_key: BTreeMap<&SourceKey, &ArtifactKnowledge> = manifest
        .knowledge
        .iter()
        .map(|entry| (&entry.source_key, entry))
        .collect();
    let analysis_by_key: BTreeMap<&SourceKey, &ArtifactAnalysis> = manifest
        .analysis
        .iter()
        .map(|entry| (&entry.source_key, entry))
        .collect();
    let packet_by_key: BTreeMap<SourceKey, &AnalysisPacket> = analysis_packets
        .iter()
        .map(|packet| {
            (
                SourceKey {
                    repo_id: packet.repo_id.clone(),
                    logical_path: packet.source_path.clone(),
                },
                packet,
            )
        })
        .collect();
    let module_index = ModuleIndex::from_packets(analysis_packets);
    let mut graph_lines = Vec::new();
    let mut search_lines = Vec::new();

    for candidate in candidates {
        let key = SourceKey {
            repo_id: candidate.repo_id.clone(),
            logical_path: candidate.source_path.clone(),
        };
        let source = source_by_key.get(&key).ok_or_else(|| {
            PipelineFailure::bundle(format!(
                "summary has no locked source during derivation: {}:{}",
                key.repo_id, key.logical_path
            ))
        })?;
        let knowledge = knowledge_by_key.get(&key).ok_or_else(|| {
            PipelineFailure::bundle(format!(
                "summary has no knowledge entry during derivation: {}:{}",
                key.repo_id, key.logical_path
            ))
        })?;
        let analysis = analysis_by_key.get(&key).ok_or_else(|| {
            PipelineFailure::bundle(format!(
                "summary has no analysis entry during derivation: {}:{}",
                key.repo_id, key.logical_path
            ))
        })?;
        let packet = packet_by_key.get(&key).ok_or_else(|| {
            PipelineFailure::bundle(format!(
                "summary has no analysis packet during derivation: {}:{}",
                key.repo_id, key.logical_path
            ))
        })?;
        let stable_id = digest_string(&format!("{}:{}", source.repo_id, source.logical_path));
        let expected_knowledge_path = format!("knowledge/documents/{stable_id}.md");
        let expected_analysis_path = format!("evidence/analysis/{stable_id}.json");
        let expected_receipt_path = format!("evidence/summaries/{stable_id}.json");
        let expected_acceptance_path = format!("evidence/acceptance/{stable_id}.json");
        if knowledge.path != expected_knowledge_path
            || knowledge.summary_receipt_path != expected_receipt_path
            || knowledge.acceptance_receipt_path != expected_acceptance_path
            || analysis.path != expected_analysis_path
            || analysis.packet_id != packet.packet_id
        {
            return Err(PipelineFailure::bundle(format!(
                "derived paths do not match SourceKey {}:{}",
                key.repo_id, key.logical_path
            )));
        }
        let document = render_knowledge_document(
            &format!("{stable_id}.md"),
            source,
            candidate,
            &stable_id,
            &analysis.path,
            &analysis.sha256,
        )
        .map_err(|error| {
            PipelineFailure::bundle(format!("knowledge derivation failed: {}", error.message))
        })?;
        verify_exact_bytes(root, &expected_knowledge_path, document.as_bytes())?;
        let packet_bytes = serde_json::to_vec_pretty(packet).map_err(|error| {
            PipelineFailure::bundle(format!("analysis derivation failed: {error}"))
        })?;
        verify_exact_bytes(root, &expected_analysis_path, &packet_bytes)?;

        graph_lines.extend(graph_rows_for_source(&GraphSource {
            key: &key,
            source_sha256: &source.content_sha256,
            packet,
            stable_id: &stable_id,
            knowledge_path: &expected_knowledge_path,
            summary_receipt_path: &expected_receipt_path,
            analysis_path: &analysis.path,
            index: &module_index,
        }));
        search_lines.push(json!({
            "knowledge_id": format!("knowledge:{stable_id}"),
            "source_key": source_key(source),
            "resource": format!("knowledge/documents/{stable_id}.md"),
            "text": document,
        }));
    }

    verify_exact_bytes(
        root,
        "indexes/graph.ndjson",
        ndjson_string(&graph_lines, "bundle.verify")?.as_bytes(),
    )?;
    verify_exact_bytes(
        root,
        "indexes/search.ndjson",
        ndjson_string(&search_lines, "bundle.verify")?.as_bytes(),
    )?;
    let source_lines = manifest
        .source_lock
        .entries
        .iter()
        .map(|entry| serde_json::to_value(entry).unwrap_or(Value::Null))
        .collect::<Vec<_>>();
    verify_exact_bytes(
        root,
        "indexes/source-manifest.ndjson",
        ndjson_string(&source_lines, "bundle.verify")?.as_bytes(),
    )?;

    for name in ["agent", "claude", "rules", "architecture", "design"] {
        let document = render_okf(
            "architecture",
            &format!("GTKG {name}"),
            architecture_description(name),
            &format!("{name}.md"),
            "gtkg.architecture/v2",
            &architecture_body(
                name,
                &manifest.source_lock.entries,
                analysis_packets,
                candidates,
                &manifest.bundle_version,
                manifest.knowledge.len(),
            ),
            vec!["gtkg".to_owned(), "architecture".to_owned()],
            Vec::new(),
            BTreeMap::from([
                (
                    "semantic_digest".to_owned(),
                    YamlValue::String(semantic_digest.to_owned()),
                ),
                (
                    "bundle_version".to_owned(),
                    YamlValue::String(manifest.bundle_version.clone()),
                ),
                (
                    "generator_version".to_owned(),
                    YamlValue::String(format!("gtkg/{}", env!("CARGO_PKG_VERSION"))),
                ),
                (
                    "document_version".to_owned(),
                    YamlValue::String(format!(
                        "{}+gtkg.{}",
                        manifest.bundle_version,
                        env!("CARGO_PKG_VERSION")
                    )),
                ),
                ("revision".to_owned(), YamlValue::Number(1_u64.into())),
            ]),
        )
        .map_err(|error| {
            PipelineFailure::bundle(format!("architecture derivation failed: {}", error.message))
        })?;
        verify_exact_bytes(
            root,
            &format!("knowledge/architecture/{name}.md"),
            document.as_bytes(),
        )?;
    }
    Ok(())
}

fn verify_exact_bytes(root: &Path, relative: &str, expected: &[u8]) -> Result<(), PipelineFailure> {
    let path = safe_join(root, relative)?;
    let observed =
        fs::read(&path).map_err(|error| PipelineFailure::io("bundle.verify", &path, error))?;
    if observed != expected {
        return Err(PipelineFailure::bundle(format!(
            "derived artifact does not match its locked inputs: {relative}"
        )));
    }
    Ok(())
}

fn validate_okf_resource_self(root: &Path, path: &Path) -> Result<(), PipelineFailure> {
    let source = fs::read_to_string(path)
        .map_err(|error| PipelineFailure::io("bundle.verify", path, error))?;
    let document = crate::okf::parse_okf_concept(&source)
        .map_err(|error| PipelineFailure::bundle(format!("{}: {error}", path.display())))?;
    crate::okf::validate_current_version(&document.frontmatter)
        .map_err(|error| PipelineFailure::bundle(format!("{}: {error}", path.display())))?;
    let parent = path
        .parent()
        .ok_or_else(|| PipelineFailure::bundle("canonical document has no parent"))?;
    let resource = document.frontmatter.resource.as_deref().ok_or_else(|| {
        PipelineFailure::bundle("canonical document has no resource self-reference")
    })?;
    let resource = safe_join(parent, resource)?;
    let canonical_resource = fs::canonicalize(&resource)
        .map_err(|error| PipelineFailure::io("bundle.verify", &resource, error))?;
    let canonical_path = fs::canonicalize(path)
        .map_err(|error| PipelineFailure::io("bundle.verify", path, error))?;
    let canonical_root = fs::canonicalize(root)
        .map_err(|error| PipelineFailure::io("bundle.verify", root, error))?;
    if canonical_resource != canonical_path || !canonical_resource.starts_with(canonical_root) {
        return Err(PipelineFailure::bundle(format!(
            "OKF resource does not resolve to its own canonical document: {}",
            path.display()
        )));
    }
    Ok(())
}

fn write_checksums(root: &Path) -> Result<(), PipelineFailure> {
    let mut lines = Vec::new();
    for entry in WalkDir::new(root).follow_links(false).sort_by_file_name() {
        let entry = entry.map_err(|error| PipelineFailure::io("build.finalize", root, error))?;
        if entry.file_type().is_symlink() {
            return Err(PipelineFailure::bundle(format!(
                "symlink rejected: {}",
                entry.path().display()
            )));
        }
        if !entry.file_type().is_file()
            || matches!(
                entry.path().file_name().and_then(|name| name.to_str()),
                Some("checksums.sha256" | "index.md" | "index.gtkg.json")
            )
        {
            continue;
        }
        let relative = entry
            .path()
            .strip_prefix(root)
            .map_err(|error| PipelineFailure::bundle(format!("checksum path escape: {error}")))?;
        let digest = sha256_file(entry.path()).map_err(map_file_model("build.finalize"))?;
        lines.push(format!("{}  {}", &digest[7..], relative.to_string_lossy()));
    }
    lines.sort();
    let path = root.join("checksums.sha256");
    fs::write(&path, format!("{}\n", lines.join("\n")))
        .map_err(|error| PipelineFailure::io("build.finalize", &path, error))
}

fn verify_checksums(root: &Path) -> Result<(), PipelineFailure> {
    let path = root.join("checksums.sha256");
    let content = fs::read_to_string(&path)
        .map_err(|error| PipelineFailure::io("bundle.verify", &path, error))?;
    let mut listed = BTreeSet::new();
    for line in content.lines().filter(|line| !line.trim().is_empty()) {
        let Some((expected, relative)) = line.split_once("  ") else {
            return Err(PipelineFailure::bundle("malformed checksums.sha256 line"));
        };
        if expected.len() != 64 || !expected.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(PipelineFailure::bundle("invalid checksum digest"));
        }
        let target = safe_join(root, relative)?;
        if !listed.insert(relative.to_owned()) {
            return Err(PipelineFailure::bundle(format!(
                "duplicate checksum entry: {relative}"
            )));
        }
        let observed = sha256_file(&target).map_err(map_file_model("bundle.verify"))?;
        if observed[7..] != *expected {
            return Err(PipelineFailure::bundle(format!(
                "checksum mismatch: {relative}"
            )));
        }
    }
    let expected: BTreeSet<String> = WalkDir::new(root)
        .follow_links(false)
        .sort_by_file_name()
        .into_iter()
        .map(|entry| {
            entry.map_err(|error| PipelineFailure::bundle(format!("checksum walk failed: {error}")))
        })
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter(|entry| {
            entry.file_type().is_file()
                && !matches!(
                    entry.path().file_name().and_then(|name| name.to_str()),
                    Some("checksums.sha256" | "index.md" | "index.gtkg.json")
                )
        })
        .map(|entry| {
            entry
                .path()
                .strip_prefix(root)
                .map(|path| path.to_string_lossy().into_owned())
                .map_err(|error| PipelineFailure::bundle(format!("checksum path escape: {error}")))
        })
        .collect::<Result<_, _>>()?;
    if listed != expected {
        return Err(PipelineFailure::bundle(format!(
            "checksum exact-set mismatch; expected {expected:?}, observed {listed:?}"
        )));
    }
    Ok(())
}

fn compute_impact(plan: &RunPlan) -> Result<ImpactSet, PipelineFailure> {
    if plan.mode == BuildMode::Full {
        let mut keys = plan
            .source_lock
            .entries
            .iter()
            .map(source_key)
            .collect::<Vec<_>>();
        keys.sort();
        return Ok(ImpactSet {
            added: keys,
            changed: Vec::new(),
            deleted: Vec::new(),
            unchanged: Vec::new(),
        });
    }
    let baseline = plan
        .baseline_bundle
        .as_ref()
        .ok_or_else(|| PipelineFailure::invalid("build.plan", "missing incremental baseline"))?;
    let expected = plan.baseline_tree_sha256.as_deref().ok_or_else(|| {
        PipelineFailure::lock("incremental plan is missing its baseline tree digest")
    })?;
    let manifest = verify_bundle_expected(baseline, expected, "incremental-impact", false)?;
    let previous: BTreeMap<SourceKey, String> = manifest
        .sources
        .iter()
        .map(|entry| (entry.source_key.clone(), entry.source_sha256.clone()))
        .collect();
    let current: BTreeMap<SourceKey, String> = plan
        .source_lock
        .entries
        .iter()
        .map(|entry| (source_key(entry), entry.content_sha256.clone()))
        .collect();
    let added: Vec<_> = current
        .keys()
        .filter(|key| !previous.contains_key(*key))
        .cloned()
        .collect();
    let deleted: Vec<_> = previous
        .keys()
        .filter(|key| !current.contains_key(*key))
        .cloned()
        .collect();
    let changed: Vec<_> = current
        .iter()
        .filter_map(|(key, digest)| {
            previous
                .get(key)
                .filter(|previous_digest| *previous_digest != digest)
                .map(|_| key.clone())
        })
        .collect();
    let unchanged: Vec<_> = current
        .iter()
        .filter_map(|(key, digest)| {
            previous
                .get(key)
                .filter(|previous_digest| *previous_digest == digest)
                .map(|_| key.clone())
        })
        .collect();
    Ok(ImpactSet {
        added,
        changed,
        deleted,
        unchanged,
    })
}

fn source_key(entry: &SourceManifestEntry) -> SourceKey {
    SourceKey {
        repo_id: entry.repo_id.clone(),
        logical_path: entry.logical_path.clone(),
    }
}

fn normalize_source_lock(source_lock: &mut SourceLock) {
    source_lock
        .repositories
        .sort_by(|left, right| left.repo_id.cmp(&right.repo_id));
    for repository in &mut source_lock.repositories {
        repository
            .submodules
            .sort_by(|left, right| left.logical_path.cmp(&right.logical_path));
    }
    source_lock.entries.sort_by(|left, right| {
        (&left.repo_id, &left.logical_path).cmp(&(&right.repo_id, &right.logical_path))
    });
}

fn normalize_template_lock(template_lock: &mut TemplateLock) {
    template_lock.slot_ids.sort();
}

fn read_packets(directory: &Path) -> Result<Vec<AnalysisPacket>, PipelineFailure> {
    read_json_directory(&directory.join("packets"), "summary.next")
}

fn read_analysis_packets(directory: &Path) -> Result<Vec<AnalysisPacket>, PipelineFailure> {
    read_json_directory(&directory.join("analysis"), "build.finalize")
}

fn validate_observed_facts(
    facts: &[ObservedStaticFact],
    source: &[u8],
    logical_path: &str,
    stage: &'static str,
) -> Result<(), PipelineFailure> {
    if !facts.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err(analysis_failure(
            stage,
            format!("observed facts are not a strictly sorted set for {logical_path}"),
        ));
    }
    for fact in facts {
        validate_fact_shape(fact, source.len() as u64, stage)?;
        let start = fact.span.start as usize;
        let end = fact.span.end as usize;
        if source.get(start..end) != Some(fact.marker_id.as_bytes()) {
            return Err(analysis_failure(
                stage,
                format!("observed fact span does not select marker_id for {logical_path}"),
            ));
        }
    }
    Ok(())
}

fn validate_analysis_packet(
    packet: &AnalysisPacket,
    expected_key: &SourceKey,
    expected_source_sha256: &str,
    expected_fact_count: u64,
    stage: &'static str,
) -> Result<(), PipelineFailure> {
    if packet.schema_version != "gtkg.analysis-packet/v1"
        || validate_path_identifier("packet_id", &packet.packet_id).is_err()
        || packet.repo_id != expected_key.repo_id
        || packet.source_path != expected_key.logical_path
        || packet.source_sha256 != expected_source_sha256
        || validate_sha256(&packet.source_sha256).is_err()
        || packet.executed_target_content
        || packet.target_process_count != 0
        || packet.observed_facts.len() as u64 != expected_fact_count
        || !packet
            .observed_facts
            .windows(2)
            .all(|pair| pair[0] < pair[1])
    {
        return Err(analysis_failure(
            stage,
            format!(
                "analysis packet is not an exact static-evidence receipt for {}:{}",
                expected_key.repo_id, expected_key.logical_path
            ),
        ));
    }
    for fact in &packet.observed_facts {
        validate_fact_shape(fact, packet.source_bytes, stage)?;
    }
    Ok(())
}

fn validate_fact_shape(
    fact: &ObservedStaticFact,
    source_bytes: u64,
    stage: &'static str,
) -> Result<(), PipelineFailure> {
    let kind_valid = !fact.kind.is_empty()
        && fact.kind.len() <= 64
        && fact
            .kind
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_');
    let marker_valid = !fact.marker_id.is_empty()
        && fact.marker_id.len() <= 256
        && !fact
            .marker_id
            .chars()
            .any(|character| character.is_control());
    if !kind_valid
        || !marker_valid
        || fact.evidence_level != "observed_static"
        || fact.span.start >= fact.span.end
        || fact.span.end > source_bytes
        || fact.span.end - fact.span.start != fact.marker_id.len() as u64
    {
        return Err(analysis_failure(stage, "invalid observed static fact"));
    }
    Ok(())
}

fn analysis_failure(stage: &'static str, message: impl Into<String>) -> PipelineFailure {
    if stage == "bundle.verify" {
        PipelineFailure::bundle(message)
    } else {
        let mut failure = PipelineFailure::lock(message);
        failure.stage = stage;
        failure
    }
}

fn load_locked_template_markdown(
    verified: &crate::template::VerifiedTemplateValidation,
    stage: &'static str,
) -> Result<String, PipelineFailure> {
    let path = safe_join(&verified.package_root, &verified.manifest.template_file)?;
    let text =
        fs::read_to_string(&path).map_err(|error| PipelineFailure::io(stage, &path, error))?;
    let digest = format!("sha256:{}", digest_string(&text));
    if digest != verified.manifest.template_sha256 {
        return Err(PipelineFailure::lock(
            "template markdown drifted from the locked template manifest",
        ));
    }
    Ok(normalize_text(&text))
}

fn packet_id_for(packet: &AnalysisPacket) -> Result<String, PipelineFailure> {
    let seed = json!({
        "repo_id": packet.repo_id,
        "source_path": packet.source_path,
        "source_sha256": packet.source_sha256,
        "template_manifest_sha256": packet.template_manifest_sha256,
        "extractor_id": packet.extractor_id,
        "observed_facts": packet.observed_facts,
        "observations": packet.observations,
    });
    let digest = canonical_json_sha256(&seed)
        .map_err(|error| PipelineFailure::invalid("packet-identity", error.to_string()))?;
    Ok(format!("packet-{}", &digest[7..39]))
}

/// Fail-closed binding check: the served packet must re-derive its own id and
/// its facts must select their markers in the locked source material.
fn validate_packet_binding(
    context: &CallContext,
    directory: &Path,
    packet: &AnalysisPacket,
    stage: &'static str,
) -> Result<(), PipelineFailure> {
    let material_root = safe_join(&directory.join("source-material"), &packet.repo_id)?;
    let source_path = safe_join(&material_root, &packet.source_path)?;
    authorize_read_path(context, &source_path, stage)?;
    let bytes =
        fs::read(&source_path).map_err(|error| PipelineFailure::io(stage, &source_path, error))?;
    let source_digest = format!("sha256:{}", hex::encode(Sha256::digest(&bytes)));
    if source_digest != packet.source_sha256 {
        return Err(analysis_failure(
            stage,
            format!(
                "packet source digest drifted for {}:{}",
                packet.repo_id, packet.source_path
            ),
        ));
    }
    validate_observed_facts(&packet.observed_facts, &bytes, &packet.source_path, stage)?;
    if packet_id_for(packet)? != packet.packet_id {
        return Err(analysis_failure(
            stage,
            format!(
                "packet {} no longer matches its own evidence digest",
                packet.packet_id
            ),
        ));
    }
    Ok(())
}

/// Evidence index resolved from a packet's observed facts and E02 semantic
/// records; claim citations are validated against it exactly.
#[derive(Debug, Default)]
struct PacketEvidence {
    facts: BTreeSet<(String, String)>,
    definitions: BTreeSet<String>,
    imports: BTreeSet<String>,
    calls: BTreeSet<(String, String)>,
}

impl PacketEvidence {
    fn from_packet(packet: &AnalysisPacket) -> Self {
        let section = |key: &str| packet.observations.get(key).cloned().unwrap_or_default();
        Self {
            facts: packet
                .observed_facts
                .iter()
                .map(|fact| (fact.kind.clone(), fact.marker_id.clone()))
                .collect(),
            definitions: section("semantic_definitions")
                .lines()
                .filter_map(|line| line.split('\t').nth(1).map(str::to_owned))
                .collect(),
            imports: section("semantic_imports")
                .lines()
                .filter_map(|line| line.split('\t').next().map(str::to_owned))
                .collect(),
            calls: section("semantic_calls")
                .lines()
                .filter_map(|line| {
                    let mut columns = line.split('\t');
                    Some((columns.next()?.to_owned(), columns.next()?.to_owned()))
                })
                .collect(),
        }
    }

    /// `fact:<kind>:<marker_id>`, `def:<name>`, `import:<module>` or
    /// `call:<caller>-><callee>`; unknown reference kinds never resolve.
    fn contains(&self, reference: &str) -> bool {
        if let Some(rest) = reference.strip_prefix("fact:") {
            return rest.split_once(':').is_some_and(|(kind, marker)| {
                self.facts.contains(&(kind.to_owned(), marker.to_owned()))
            });
        }
        if let Some(name) = reference.strip_prefix("def:") {
            return self.definitions.contains(name);
        }
        if let Some(module) = reference.strip_prefix("import:") {
            return self.imports.contains(module);
        }
        if let Some(edge) = reference.strip_prefix("call:") {
            return edge.split_once("->").is_some_and(|(caller, callee)| {
                self.calls.contains(&(caller.to_owned(), callee.to_owned()))
            });
        }
        false
    }
}

/// Claim-span gate: claim lines have the exact form
/// `- claim: <text> | evidence: <ref>[, <ref>...]`. Every citation must
/// resolve against the packet evidence (unsupported claims are rejected); a
/// `!`-prefixed ref asserts absence and is rejected when the evidence exists
/// (contradiction). Summaries without claim lines pass through unchanged.
/// Returns `(claim_count, cited_claim_count)`.
fn validate_summary_claims(
    summary_markdown: &str,
    packet: &AnalysisPacket,
    stage: &'static str,
) -> Result<(u64, u64), PipelineFailure> {
    let malformed = |reason: &str| {
        PipelineFailure::invalid(
            stage,
            format!(
                "malformed claim line; expected `- claim: <text> | evidence: <ref>[, ...]`: {reason}"
            ),
        )
    };
    let evidence = PacketEvidence::from_packet(packet);
    let mut claim_count = 0_u64;
    let mut cited_count = 0_u64;
    for line in summary_markdown.lines() {
        if !line.starts_with("- claim") {
            continue;
        }
        let Some(rest) = line.strip_prefix("- claim: ") else {
            return Err(malformed("claim prefix must be `- claim: `"));
        };
        let Some((text, citations)) = rest.split_once(" | evidence: ") else {
            return Err(malformed("claim is missing its ` | evidence: ` segment"));
        };
        if text.is_empty()
            || text.len() > 512
            || text != text.trim()
            || text.chars().any(|character| character.is_control())
        {
            return Err(malformed("claim text must be 1..=512 visible characters"));
        }
        let references: Vec<&str> = citations.split(',').map(str::trim).collect();
        if references.is_empty() || references.iter().any(|reference| reference.is_empty()) {
            return Err(malformed("claim evidence list must not be empty"));
        }
        claim_count += 1;
        for reference in references {
            if let Some(negated) = reference.strip_prefix('!') {
                if evidence.contains(negated) {
                    return Err(PipelineFailure::invalid(
                        stage,
                        format!(
                            "claim contradicts packet evidence: {negated} is present in {}",
                            packet.source_path
                        ),
                    ));
                }
            } else if !evidence.contains(reference) {
                return Err(PipelineFailure::invalid(
                    stage,
                    format!(
                        "unsupported claim citation: {reference} is not packet evidence for {}",
                        packet.source_path
                    ),
                ));
            }
        }
        cited_count += 1;
    }
    Ok((claim_count, cited_count))
}

fn module_id_of(repo_id: &str, logical_path: &str) -> String {
    format!("module:{repo_id}:{logical_path}")
}

fn source_key_from_module_id(module_id: &str) -> Option<SourceKey> {
    let rest = module_id.strip_prefix("module:")?;
    let (repo_id, logical_path) = rest.split_once(':')?;
    Some(SourceKey {
        repo_id: repo_id.to_owned(),
        logical_path: logical_path.to_owned(),
    })
}

/// Resolve an import string to candidate module ids: any module whose file
/// stem appears as a segment of the import (excluding the importing module).
fn resolve_import_modules(index: &ModuleIndex, self_module: &str, import: &str) -> Vec<String> {
    let segments: BTreeSet<&str> = import
        .split([':', '.', '/'])
        .filter(|segment| !segment.is_empty() && *segment != "*")
        .collect();
    let mut candidates: Vec<String> = index
        .stems
        .iter()
        .filter(|(stem, _)| segments.contains(stem.as_str()))
        .flat_map(|(_, modules)| modules.iter().cloned())
        .collect();
    candidates.sort();
    candidates.dedup();
    candidates.retain(|candidate| candidate != self_module);
    candidates
}

/// Every module a packet depends on, resolved from its E02 import and call
/// records against the module index (unknown and conflict resolutions count
/// as dependencies: invalidation is conservative).
fn dependency_targets(index: &ModuleIndex, packet: &AnalysisPacket) -> BTreeSet<SourceKey> {
    let self_module = module_id_of(&packet.repo_id, &packet.source_path);
    let mut targets = BTreeSet::new();
    let imports: BTreeSet<&str> = packet
        .observations
        .get("semantic_imports")
        .map(|section| {
            section
                .lines()
                .filter_map(|line| line.split('\t').next())
                .collect()
        })
        .unwrap_or_default();
    for import in imports {
        for module in resolve_import_modules(index, &self_module, import) {
            if let Some(key) = source_key_from_module_id(&module) {
                targets.insert(key);
            }
        }
    }
    let callees: BTreeSet<&str> = packet
        .observations
        .get("semantic_calls")
        .map(|section| {
            section
                .lines()
                .filter_map(|line| line.split('\t').nth(1))
                .collect()
        })
        .unwrap_or_default();
    for callee in callees {
        if let Some(modules) = index.definition_modules_by_name.get(callee) {
            for module in modules {
                if *module != self_module
                    && let Some(key) = source_key_from_module_id(module)
                {
                    targets.insert(key);
                }
            }
        }
    }
    targets
}

/// Dependency-aware invalidation: an unchanged source whose (transitive)
/// import/call dependencies were added, changed or deleted must be
/// re-summarized instead of reusing its baseline summary.
fn propagate_dependency_invalidation(
    plan: &RunPlan,
    impact: &mut ImpactSet,
) -> Result<(), PipelineFailure> {
    let baseline = plan
        .baseline_bundle
        .as_ref()
        .ok_or_else(|| PipelineFailure::lock("incremental run is missing its baseline bundle"))?;
    let expected = plan.baseline_tree_sha256.as_deref().ok_or_else(|| {
        PipelineFailure::lock("incremental run is missing its baseline tree digest")
    })?;
    let manifest = verify_bundle_expected(baseline, expected, "build.prepare", false)?;
    let mut baseline_packets = Vec::new();
    for analysis in &manifest.analysis {
        let packet_path = safe_join(baseline, &analysis.path)?;
        baseline_packets.push(read_json::<AnalysisPacket>(&packet_path, "build.prepare")?);
    }
    let index = ModuleIndex::from_packets(&baseline_packets);
    let packet_by_key: BTreeMap<SourceKey, &AnalysisPacket> = baseline_packets
        .iter()
        .map(|packet| {
            (
                SourceKey {
                    repo_id: packet.repo_id.clone(),
                    logical_path: packet.source_path.clone(),
                },
                packet,
            )
        })
        .collect();
    let mut closure: BTreeSet<SourceKey> = impact
        .added
        .iter()
        .chain(impact.changed.iter())
        .chain(impact.deleted.iter())
        .cloned()
        .collect();
    let unchanged: BTreeSet<SourceKey> = impact.unchanged.iter().cloned().collect();
    loop {
        let mut progressed = false;
        for key in &unchanged {
            if closure.contains(key) {
                continue;
            }
            let packet = packet_by_key.get(key).ok_or_else(|| {
                PipelineFailure::bundle(format!(
                    "baseline has no analysis evidence for {}:{}",
                    key.repo_id, key.logical_path
                ))
            })?;
            let dependencies = dependency_targets(&index, packet);
            if dependencies
                .iter()
                .any(|dependency| closure.contains(dependency))
            {
                closure.insert(key.clone());
                progressed = true;
            }
        }
        if !progressed {
            break;
        }
    }
    let invalidated: Vec<SourceKey> = unchanged.intersection(&closure).cloned().collect();
    if !invalidated.is_empty() {
        impact.unchanged.retain(|key| !closure.contains(key));
        impact.changed.extend(invalidated);
        impact.changed.sort();
        impact.changed.dedup();
    }
    Ok(())
}

fn symbol_id_of(repo_id: &str, logical_path: &str, kind: &str, name: &str) -> String {
    format!("symbol:{repo_id}:{logical_path}:{kind}:{name}")
}

/// Parsed `semantic_definitions` rows as sorted deduplicated
/// `(kind, name, line_start)` triples.
fn semantic_definition_rows(packet: &AnalysisPacket) -> Vec<(String, String, u64)> {
    let mut rows: Vec<(String, String, u64)> = packet
        .observations
        .get("semantic_definitions")
        .map(|section| {
            section
                .lines()
                .filter_map(|line| {
                    let mut columns = line.split('\t');
                    let kind = columns.next()?.to_owned();
                    let name = columns.next()?.to_owned();
                    let line_start = columns.nth(2)?.parse().ok()?;
                    Some((kind, name, line_start))
                })
                .collect()
        })
        .unwrap_or_default();
    rows.sort();
    rows.dedup();
    rows
}

/// Cross-module resolution index over every analysis packet in a build.
#[derive(Debug, Default)]
struct ModuleIndex {
    /// File stem → sorted module ids with that stem.
    stems: BTreeMap<String, Vec<String>>,
    /// Definition name → sorted symbol ids defining it.
    definitions_by_name: BTreeMap<String, Vec<String>>,
    /// Definition name → sorted module ids defining it.
    definition_modules_by_name: BTreeMap<String, Vec<String>>,
    /// Module id → sorted deduplicated definition rows.
    local_definitions: BTreeMap<String, Vec<(String, String, u64)>>,
}

impl ModuleIndex {
    fn from_packets(packets: &[AnalysisPacket]) -> Self {
        let mut index = Self::default();
        for packet in packets {
            let module_id = module_id_of(&packet.repo_id, &packet.source_path);
            let stem = Path::new(&packet.source_path)
                .file_stem()
                .and_then(|stem| stem.to_str())
                .unwrap_or_default()
                .to_owned();
            if !stem.is_empty() {
                index.stems.entry(stem).or_default().push(module_id.clone());
            }
            let definitions = semantic_definition_rows(packet);
            for (kind, name, _) in &definitions {
                index
                    .definitions_by_name
                    .entry(name.clone())
                    .or_default()
                    .push(symbol_id_of(
                        &packet.repo_id,
                        &packet.source_path,
                        kind,
                        name,
                    ));
                index
                    .definition_modules_by_name
                    .entry(name.clone())
                    .or_default()
                    .push(module_id.clone());
            }
            index.local_definitions.insert(module_id, definitions);
        }
        for modules in index.stems.values_mut() {
            modules.sort();
            modules.dedup();
        }
        for symbols in index.definitions_by_name.values_mut() {
            symbols.sort();
            symbols.dedup();
        }
        for modules in index.definition_modules_by_name.values_mut() {
            modules.sort();
            modules.dedup();
        }
        index
    }
}

/// Inputs for graph row derivation of a single source.
struct GraphSource<'a> {
    key: &'a SourceKey,
    source_sha256: &'a str,
    packet: &'a AnalysisPacket,
    stable_id: &'a str,
    knowledge_path: &'a str,
    summary_receipt_path: &'a str,
    analysis_path: &'a str,
    index: &'a ModuleIndex,
}

/// Graph v2 rows for one source: the legacy `knowledge_entity` summarizes row
/// followed by module/symbol entities and typed edges. Unresolvable
/// references are explicit `unknown` edges carrying the raw target; ambiguous
/// references are explicit `conflict` edges carrying the sorted candidates.
fn graph_rows_for_source(source: &GraphSource<'_>) -> Vec<Value> {
    let key = source.key;
    let packet = source.packet;
    let index = source.index;
    let stable_id = source.stable_id;
    let knowledge_path = source.knowledge_path;
    let summary_receipt_path = source.summary_receipt_path;
    let analysis_path = source.analysis_path;
    let source_sha256 = source.source_sha256;
    let module_id = module_id_of(&key.repo_id, &key.logical_path);
    let mut rows = vec![json!({
        "type": "knowledge_entity",
        "knowledge_id": format!("knowledge:{stable_id}"),
        "source_key": key,
        "source_sha256": source_sha256,
        "relation": "summarizes",
        "evidence_ref": knowledge_path,
        "summary_receipt_ref": summary_receipt_path,
        "state": "resolved",
    })];
    rows.push(json!({
        "type": "module_entity",
        "schema": "gtkg.graph/v2",
        "module_id": module_id,
        "source_key": key,
        "source_sha256": source_sha256,
        "state": "resolved",
    }));
    let empty_definitions = Vec::new();
    let definitions = index
        .local_definitions
        .get(&module_id)
        .unwrap_or(&empty_definitions);
    for (kind, name, line_start) in definitions {
        rows.push(json!({
            "type": "symbol_entity",
            "schema": "gtkg.graph/v2",
            "symbol_id": symbol_id_of(&key.repo_id, &key.logical_path, kind, name),
            "module_id": module_id,
            "kind": kind,
            "name": name,
            "line_start": line_start,
            "state": "resolved",
        }));
    }
    for (kind, name, _) in definitions {
        rows.push(json!({
            "type": "graph_edge",
            "schema": "gtkg.graph/v2",
            "relation": "defines",
            "from": module_id,
            "to": symbol_id_of(&key.repo_id, &key.logical_path, kind, name),
            "state": "resolved",
            "evidence_ref": analysis_path,
        }));
    }
    let imports: BTreeSet<String> = packet
        .observations
        .get("semantic_imports")
        .map(|section| {
            section
                .lines()
                .filter_map(|line| line.split('\t').next().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    for import in imports {
        let candidates = resolve_import_modules(index, &module_id, &import);
        let mut edge = json!({
            "type": "graph_edge",
            "schema": "gtkg.graph/v2",
            "relation": "imports",
            "from": module_id,
            "target": import,
            "evidence_ref": analysis_path,
        });
        match candidates.as_slice() {
            [] => edge["state"] = json!("unknown"),
            [resolved] => {
                edge["state"] = json!("resolved");
                edge["to"] = json!(resolved);
            }
            _ => {
                edge["state"] = json!("conflict");
                edge["candidates"] = json!(candidates);
            }
        }
        rows.push(edge);
    }
    let calls: BTreeSet<(String, String)> = packet
        .observations
        .get("semantic_calls")
        .map(|section| {
            section
                .lines()
                .filter_map(|line| {
                    let mut columns = line.split('\t');
                    Some((columns.next()?.to_owned(), columns.next()?.to_owned()))
                })
                .collect()
        })
        .unwrap_or_default();
    for (caller, callee) in calls {
        let caller_symbol = definitions
            .iter()
            .find(|(_, name, _)| *name == caller)
            .map(|(kind, name, _)| symbol_id_of(&key.repo_id, &key.logical_path, kind, name));
        let mut edge = json!({
            "type": "graph_edge",
            "schema": "gtkg.graph/v2",
            "relation": "calls",
            "target": callee,
            "evidence_ref": analysis_path,
        });
        match caller_symbol {
            Some(symbol) => edge["from"] = json!(symbol),
            None => {
                edge["from_target"] = json!(caller);
                edge["state"] = json!("unknown");
                rows.push(edge);
                continue;
            }
        }
        let targets: Vec<String> = index
            .definitions_by_name
            .get(&callee)
            .cloned()
            .unwrap_or_default();
        match targets.as_slice() {
            [] => edge["state"] = json!("unknown"),
            [resolved] => {
                edge["state"] = json!("resolved");
                edge["to"] = json!(resolved);
            }
            _ => {
                edge["state"] = json!("conflict");
                edge["candidates"] = json!(targets);
            }
        }
        rows.push(edge);
    }
    rows.push(json!({
        "type": "graph_edge",
        "schema": "gtkg.graph/v2",
        "relation": "documents",
        "from": format!("knowledge:{stable_id}"),
        "to": module_id,
        "state": "resolved",
        "evidence_ref": knowledge_path,
    }));
    rows
}
/// declaration lines of the exact form `model: <value>`, `generator: <value>`
/// or `parameters: <value>` (single space, non-empty value of at most 256
/// characters without control characters, no surrounding whitespace). The
/// first line that is not a declaration ends the header. The bound identity
/// is the exact `model:` value; without a `model:` declaration the identity
/// is the explicit string "unspecified".
fn parse_model_identity(
    summary_markdown: &str,
    stage: &'static str,
) -> Result<String, PipelineFailure> {
    let malformed = |line: &str| {
        PipelineFailure::invalid(
            stage,
            format!(
                "malformed summary metadata declaration line; expected `<key>: <value>`: {line:?}"
            ),
        )
    };
    let mut identity: Option<String> = None;
    for line in summary_markdown.lines() {
        let mut declaration = false;
        for key in ["model", "generator", "parameters"] {
            let Some(rest) = line
                .strip_prefix(key)
                .and_then(|rest| rest.strip_prefix(':'))
            else {
                continue;
            };
            declaration = true;
            let Some(value) = rest.strip_prefix(' ') else {
                return Err(malformed(line));
            };
            if value.is_empty()
                || value.len() > 256
                || value != value.trim()
                || value.chars().any(|character| character.is_control())
            {
                return Err(malformed(line));
            }
            if key == "model" {
                if identity.is_some() {
                    return Err(PipelineFailure::invalid(
                        stage,
                        "duplicate model identity declaration in summary metadata",
                    ));
                }
                identity = Some(value.to_owned());
            }
        }
        if !declaration {
            break;
        }
    }
    Ok(identity.unwrap_or_else(unspecified_model_identity))
}

fn read_candidates(directory: &Path) -> Result<Vec<SummaryCandidate>, PipelineFailure> {
    read_json_directory(&directory.join("candidates"), "build.finalize")
}

fn persist_accepted_candidate(
    context: &CallContext,
    directory: &Path,
    candidate: &SummaryCandidate,
    model_identity: &str,
    stage: &'static str,
) -> Result<bool, PipelineFailure> {
    let candidate_path = directory
        .join("candidates")
        .join(format!("{}.json", candidate.packet_id));
    authorize_write_path(context, &candidate_path, stage)?;
    if candidate_path.exists() {
        let existing: SummaryCandidate = read_json(&candidate_path, stage)?;
        if existing != *candidate {
            return Err(PipelineFailure::lock(format!(
                "accepted summary is immutable for packet {}",
                candidate.packet_id
            )));
        }
    } else {
        write_json_atomic(&candidate_path, candidate, stage)?;
    }
    let candidate_sha256 = sha256_file(&candidate_path).map_err(map_file_model(stage))?;
    let receipt = AcceptedSummaryReceipt {
        schema_version: "gtkg.accepted-summary/v1".to_owned(),
        packet_id: candidate.packet_id.clone(),
        candidate_sha256,
        model_identity: model_identity.to_owned(),
    };
    let receipt_path = directory
        .join("accepted")
        .join(format!("{}.json", candidate.packet_id));
    authorize_write_path(context, &receipt_path, stage)?;
    write_json_immutable(context, &receipt_path, &receipt, stage)?;
    let receipt_sha256 = sha256_file(&receipt_path).map_err(map_file_model(stage))?;
    append_acceptance_event(context, directory, &receipt, &receipt_sha256, stage)
}

fn verify_accepted_candidates(
    context: &CallContext,
    directory: &Path,
    summaries: &[SummaryCandidate],
) -> Result<VerifiedAcceptance, PipelineFailure> {
    authorize_read_path(context, &directory.join("accepted"), "build.finalize")?;
    let receipts: Vec<AcceptedSummaryReceipt> =
        read_json_directory(&directory.join("accepted"), "build.finalize")?;
    if receipts.len() != summaries.len() {
        return Err(PipelineFailure::lock(
            "accepted-summary receipt exact-set does not match candidates",
        ));
    }
    let by_packet: BTreeMap<_, _> = receipts
        .iter()
        .map(|receipt| (receipt.packet_id.as_str(), receipt))
        .collect();
    if by_packet.len() != receipts.len() {
        return Err(PipelineFailure::lock(
            "duplicate accepted-summary receipt packet_id",
        ));
    }
    let (events, head, head_stale) = load_acceptance_events(context, directory, "build.finalize")?;
    if head_stale {
        write_acceptance_head_projection(context, directory, head.as_ref(), "build.finalize")?;
    }
    if events.len() != receipts.len() {
        return Err(PipelineFailure::lock(
            "acceptance event exact-set does not match receipts",
        ));
    }
    let events_by_packet: BTreeMap<_, _> = events
        .iter()
        .map(|event| (event.packet_id.as_str(), event))
        .collect();
    if events_by_packet.len() != events.len() {
        return Err(PipelineFailure::lock(
            "duplicate acceptance event packet_id",
        ));
    }
    for summary in summaries {
        let receipt = by_packet.get(summary.packet_id.as_str()).ok_or_else(|| {
            PipelineFailure::lock(format!(
                "missing accepted-summary receipt for {}",
                summary.packet_id
            ))
        })?;
        if receipt.schema_version != "gtkg.accepted-summary/v1" || receipt.model_identity.is_empty()
        {
            return Err(PipelineFailure::lock(
                "unsupported accepted-summary receipt schema",
            ));
        }
        let receipt_path = directory
            .join("accepted")
            .join(format!("{}.json", summary.packet_id));
        authorize_read_path(context, &receipt_path, "build.finalize")?;
        let receipt_sha256 =
            sha256_file(&receipt_path).map_err(map_file_model("build.finalize"))?;
        let event = events_by_packet
            .get(summary.packet_id.as_str())
            .ok_or_else(|| {
                PipelineFailure::lock(format!(
                    "missing acceptance event for {}",
                    summary.packet_id
                ))
            })?;
        let candidate_path = directory
            .join("candidates")
            .join(format!("{}.json", summary.packet_id));
        authorize_read_path(context, &candidate_path, "build.finalize")?;
        let digest = sha256_file(&candidate_path).map_err(map_file_model("build.finalize"))?;
        if receipt.candidate_sha256 != digest
            || event.candidate_sha256 != digest
            || event.acceptance_receipt_sha256 != receipt_sha256
        {
            return Err(PipelineFailure::lock(format!(
                "accepted summary digest drifted for {}",
                summary.packet_id
            )));
        }
    }
    Ok(VerifiedAcceptance {
        receipts: receipts
            .into_iter()
            .map(|receipt| (receipt.packet_id.clone(), receipt))
            .collect(),
        events,
        head: head.ok_or_else(|| PipelineFailure::lock("acceptance head is missing"))?,
    })
}

fn append_acceptance_event(
    context: &CallContext,
    directory: &Path,
    receipt: &AcceptedSummaryReceipt,
    receipt_sha256: &str,
    stage: &'static str,
) -> Result<bool, PipelineFailure> {
    let (mut events, projected_head, head_stale) =
        load_acceptance_events(context, directory, stage)?;
    if head_stale {
        write_acceptance_head_projection(context, directory, projected_head.as_ref(), stage)?;
    }
    if let Some(existing) = events
        .iter()
        .find(|event| event.packet_id == receipt.packet_id)
    {
        if existing.candidate_sha256 == receipt.candidate_sha256
            && existing.acceptance_receipt_sha256 == receipt_sha256
        {
            return Ok(false);
        }
        return Err(PipelineFailure::lock(format!(
            "acceptance event is immutable for packet {}",
            receipt.packet_id
        )));
    }

    let plan_path = directory.join("plan.json");
    authorize_read_path(context, &plan_path, stage)?;
    let run_plan_sha256 = sha256_file(&plan_path).map_err(map_file_model(stage))?;
    let mut event = AcceptanceEvent {
        schema_version: "gtkg.acceptance-event/v1".to_owned(),
        sequence: events.len() as u64,
        run_plan_sha256: run_plan_sha256.clone(),
        packet_id: receipt.packet_id.clone(),
        candidate_sha256: receipt.candidate_sha256.clone(),
        acceptance_receipt_sha256: receipt_sha256.to_owned(),
        previous_event_sha256: events.last().map(|event| event.event_sha256.clone()),
        event_sha256: String::new(),
    };
    event.event_sha256 = acceptance_event_sha256(&event)?;
    let ledger_path = directory.join("acceptance-events.ndjson");
    authorize_write_path(context, &ledger_path, stage)?;
    events.push(event);
    let values = events
        .iter()
        .map(|event| serde_json::to_value(event).unwrap_or(Value::Null))
        .collect::<Vec<_>>();
    write_atomic(
        &ledger_path,
        ndjson_string(&values, stage)?.as_bytes(),
        stage,
    )?;

    let head = AcceptanceHead {
        schema_version: "gtkg.acceptance-head/v1".to_owned(),
        event_count: events.len() as u64,
        run_plan_sha256,
        head_sha256: events
            .last()
            .map(|event| event.event_sha256.clone())
            .ok_or_else(|| PipelineFailure::lock("acceptance head has no event"))?,
    };
    write_acceptance_head_projection(context, directory, Some(&head), stage)?;
    Ok(true)
}

fn load_acceptance_events(
    context: &CallContext,
    directory: &Path,
    stage: &'static str,
) -> Result<(Vec<AcceptanceEvent>, Option<AcceptanceHead>, bool), PipelineFailure> {
    let ledger_path = directory.join("acceptance-events.ndjson");
    let head_path = directory.join("acceptance-head.json");
    if !ledger_path.exists() {
        return Ok((Vec::new(), None, head_path.exists()));
    }
    authorize_read_path(context, &ledger_path, stage)?;
    let plan_path = directory.join("plan.json");
    authorize_read_path(context, &plan_path, stage)?;
    let run_plan_sha256 = sha256_file(&plan_path).map_err(map_file_model(stage))?;
    let source = fs::read_to_string(&ledger_path)
        .map_err(|error| PipelineFailure::io(stage, &ledger_path, error))?;
    let mut events = Vec::new();
    let mut previous = None;
    let mut packet_ids = BTreeSet::new();
    for (index, line) in source.lines().enumerate() {
        if line.trim().is_empty() {
            return Err(PipelineFailure::lock(
                "acceptance ledger contains an empty record",
            ));
        }
        let event: AcceptanceEvent = serde_json::from_str(line)
            .map_err(|error| PipelineFailure::lock(format!("invalid acceptance event: {error}")))?;
        if event.schema_version != "gtkg.acceptance-event/v1"
            || event.sequence != index as u64
            || event.run_plan_sha256 != run_plan_sha256
            || event.previous_event_sha256 != previous
            || validate_path_identifier("packet_id", &event.packet_id).is_err()
            || validate_sha256(&event.candidate_sha256).is_err()
            || validate_sha256(&event.acceptance_receipt_sha256).is_err()
            || acceptance_event_sha256(&event)? != event.event_sha256
            || !packet_ids.insert(event.packet_id.clone())
        {
            return Err(PipelineFailure::lock(format!(
                "acceptance event chain is invalid at sequence {index}"
            )));
        }
        previous = Some(event.event_sha256.clone());
        events.push(event);
    }
    if events.is_empty() {
        return Err(PipelineFailure::lock("acceptance ledger is empty"));
    }
    let projected = AcceptanceHead {
        schema_version: "gtkg.acceptance-head/v1".to_owned(),
        event_count: events.len() as u64,
        run_plan_sha256,
        head_sha256: previous
            .ok_or_else(|| PipelineFailure::lock("acceptance ledger has no head digest"))?,
    };
    let observed = if head_path.exists() {
        authorize_read_path(context, &head_path, stage)?;
        fs::read(&head_path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<AcceptanceHead>(&bytes).ok())
    } else {
        None
    };
    let stale = observed.as_ref().is_none_or(|head| {
        head.schema_version != projected.schema_version
            || head.event_count != projected.event_count
            || head.run_plan_sha256 != projected.run_plan_sha256
            || head.head_sha256 != projected.head_sha256
    });
    Ok((events, Some(projected), stale))
}

fn write_acceptance_head_projection(
    context: &CallContext,
    directory: &Path,
    head: Option<&AcceptanceHead>,
    stage: &'static str,
) -> Result<(), PipelineFailure> {
    let path = directory.join("acceptance-head.json");
    authorize_write_path(context, &path, stage)?;
    if let Some(head) = head {
        write_json_atomic(&path, head, stage)
    } else if path.exists() {
        quarantine_staging(context, directory, &path, "orphan-acceptance-head", stage).map(|_| ())
    } else {
        Ok(())
    }
}

fn acceptance_event_sha256(event: &AcceptanceEvent) -> Result<String, PipelineFailure> {
    canonical_json_sha256(&json!({
        "schema_version": event.schema_version,
        "sequence": event.sequence,
        "run_plan_sha256": event.run_plan_sha256,
        "packet_id": event.packet_id,
        "candidate_sha256": event.candidate_sha256,
        "acceptance_receipt_sha256": event.acceptance_receipt_sha256,
        "previous_event_sha256": event.previous_event_sha256,
    }))
    .map_err(|error| PipelineFailure::lock(format!("acceptance event digest failed: {error}")))
}

fn read_json_directory<T>(directory: &Path, stage: &'static str) -> Result<Vec<T>, PipelineFailure>
where
    T: for<'de> Deserialize<'de>,
{
    let mut paths = fs::read_dir(directory)
        .map_err(|error| PipelineFailure::io(stage, directory, error))?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| PipelineFailure::io(stage, directory, error))?;
    paths.retain(|path| path.extension().and_then(|value| value.to_str()) == Some("json"));
    paths.sort();
    paths.iter().map(|path| read_json(path, stage)).collect()
}

fn inspect_run_projection(
    context: &CallContext,
    directory: &Path,
    stage: &'static str,
) -> Result<RunProjection, PipelineFailure> {
    let events = load_run_events(context, directory, stage)?;
    let ledger_state = events
        .last()
        .map(|event| event.state.clone())
        .ok_or_else(|| PipelineFailure::lock("run event ledger has no initial state"))?;
    let (acceptance_events, acceptance_head, acceptance_head_stale) =
        load_acceptance_events(context, directory, stage)?;
    let mut state = ledger_state.clone();
    if matches!(
        state.state,
        RunState::AwaitingSummary | RunState::ReadyToFinalize
    ) {
        let packets_directory = directory.join("packets");
        authorize_read_path(context, &packets_directory, stage)?;
        reject_symlinks_below(&packets_directory, stage)?;
        let packet_ids: BTreeSet<String> = if packets_directory.is_dir() {
            read_json_directory::<AnalysisPacket>(&packets_directory, stage)?
                .into_iter()
                .map(|packet| packet.packet_id)
                .collect()
        } else {
            BTreeSet::new()
        };
        let accepted_summaries = acceptance_events
            .iter()
            .filter(|event| packet_ids.contains(&event.packet_id))
            .count();
        if accepted_summaries > state.expected_summaries {
            return Err(PipelineFailure::lock(
                "acceptance ledger exceeds the exact packet set",
            ));
        }
        state.accepted_summaries = accepted_summaries;
        state.state = if accepted_summaries == state.expected_summaries {
            RunState::ReadyToFinalize
        } else {
            RunState::AwaitingSummary
        };
    }
    let state_path = directory.join("state.json");
    let stored_state = if state_path.is_file() {
        authorize_read_path(context, &state_path, stage)?;
        fs::read(&state_path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<RunStateFile>(&bytes).ok())
    } else {
        None
    };
    let state_stale = stored_state.as_ref() != Some(&state);
    Ok(RunProjection {
        state,
        stored_state,
        state_stale,
        acceptance_head,
        acceptance_head_stale,
    })
}

fn reconcile_run_for_mutation(
    context: &CallContext,
    directory: &Path,
    request: &OperationRequest,
    stage: &'static str,
) -> Result<RunStateFile, PipelineFailure> {
    let projection = inspect_run_projection(context, directory, stage)?;
    if projection.acceptance_head_stale {
        write_acceptance_head_projection(
            context,
            directory,
            projection.acceptance_head.as_ref(),
            stage,
        )?;
    }
    let events = load_run_events(context, directory, stage)?;
    let ledger_state = &events
        .last()
        .ok_or_else(|| PipelineFailure::lock("run event ledger has no initial state"))?
        .state;
    if ledger_state != &projection.state {
        append_event(context, directory, request, &projection.state)?;
    }
    if projection.state_stale {
        authorize_write_path(context, &directory.join("state.json"), stage)?;
        write_json_atomic(&directory.join("state.json"), &projection.state, stage)?;
    }
    Ok(projection.state)
}

fn run_dir(workspace_root: &Path, run_id: &str) -> PathBuf {
    workspace_root.join(".gtkg/runs").join(run_id)
}

fn planned_state(plan: &RunPlan) -> RunStateFile {
    RunStateFile {
        schema_version: RUN_SCHEMA.to_owned(),
        run_id: plan.run_id.clone(),
        state: RunState::Planned,
        accepted_summaries: 0,
        expected_summaries: 0,
        reused_summaries: 0,
        total_sources: plan.source_lock.entries.len(),
    }
}

fn initialize_run_atomically(
    context: &CallContext,
    workspace_root: &Path,
    runs_root: &Path,
    run_directory: &Path,
    request: &OperationRequest,
    plan: &RunPlan,
) -> Result<RunStateFile, PipelineFailure> {
    let request_digest = digest_string(&request.request_id);
    let gtkg_root = workspace_root.join(".gtkg");
    let staging_parent = gtkg_root.join("run-staging").join(&request_digest[..24]);
    let staging = staging_parent.join(&plan.run_id);
    authorize_write_path(context, &staging_parent, "build.plan")?;
    authorize_write_path(context, &staging, "build.plan")?;
    if staging.exists() {
        quarantine_staging(
            context,
            &gtkg_root,
            &staging,
            "run-bootstrap-staging",
            "build.plan",
        )?;
    }
    fs::create_dir_all(&staging_parent)
        .map_err(|error| PipelineFailure::io("build.plan", &staging_parent, error))?;
    let state = write_initial_run_layout(context, &staging, request, plan)?;
    sync_directory(&staging, "build.plan")?;
    if run_directory.exists() {
        return Err(PipelineFailure::state(format!(
            "run identity appeared during atomic bootstrap: {}",
            run_directory.display()
        )));
    }
    fs::rename(&staging, run_directory)
        .map_err(|error| PipelineFailure::io("build.plan", run_directory, error))?;
    sync_directory(runs_root, "build.plan")?;
    Ok(state)
}

fn write_initial_run_layout(
    context: &CallContext,
    directory: &Path,
    request: &OperationRequest,
    plan: &RunPlan,
) -> Result<RunStateFile, PipelineFailure> {
    for path in [
        directory.join("locks"),
        directory.join("packets"),
        directory.join("analysis"),
        directory.join("candidates"),
        directory.join("accepted"),
    ] {
        authorize_write_path(context, &path, "build.plan")?;
        fs::create_dir_all(&path)
            .map_err(|error| PipelineFailure::io("build.plan", &path, error))?;
    }
    write_json_atomic(&directory.join("plan.json"), plan, "build.plan")?;
    write_json_atomic(
        &directory.join("locks/source-lock.json"),
        &plan.source_lock,
        "build.plan",
    )?;
    write_json_atomic(
        &directory.join("locks/template-lock.json"),
        &plan.template_lock,
        "build.plan",
    )?;
    let state = planned_state(plan);
    append_event(context, directory, request, &state)?;
    write_json_atomic(&directory.join("state.json"), &state, "build.plan")?;
    for path in [
        directory.join("locks"),
        directory.join("packets"),
        directory.join("analysis"),
        directory.join("candidates"),
        directory.join("accepted"),
        directory.to_path_buf(),
    ] {
        sync_directory(&path, "build.plan")?;
    }
    Ok(state)
}

fn validate_existing_run_identity(
    context: &CallContext,
    directory: &Path,
    plan: &RunPlan,
) -> Result<(), PipelineFailure> {
    let plan_path = directory.join("plan.json");
    authorize_read_path(context, &plan_path, "build.plan")?;
    let existing: RunPlan = read_json(&plan_path, "build.plan")?;
    let existing_digest = canonical_json_sha256(&existing)
        .map_err(|error| PipelineFailure::lock(format!("existing plan is invalid: {error}")))?;
    let expected_digest = canonical_json_sha256(plan)
        .map_err(|error| PipelineFailure::lock(format!("expected plan is invalid: {error}")))?;
    if existing_digest != expected_digest {
        return Err(PipelineFailure::state(format!(
            "run identity collision at {}",
            directory.display()
        )));
    }
    let source_path = directory.join("locks/source-lock.json");
    let template_path = directory.join("locks/template-lock.json");
    authorize_read_path(context, &source_path, "build.plan")?;
    authorize_read_path(context, &template_path, "build.plan")?;
    let source_lock: SourceLock = read_json(&source_path, "build.plan")?;
    let template_lock: TemplateLock = read_json(&template_path, "build.plan")?;
    if source_lock != plan.source_lock || template_lock != plan.template_lock {
        return Err(PipelineFailure::lock(
            "persisted run locks do not match the revalidated exact plan",
        ));
    }
    Ok(())
}

fn bootstrap_exact_partial_run(
    context: &CallContext,
    directory: &Path,
    request: &OperationRequest,
    plan: &RunPlan,
) -> Result<RunStateFile, PipelineFailure> {
    let mut observed = fs::read_dir(directory)
        .map_err(|error| PipelineFailure::io("build.plan", directory, error))?
        .map(|entry| {
            entry
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .map_err(|error| PipelineFailure::io("build.plan", directory, error))
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    let state_present = observed.remove("state.json");
    let expected = BTreeSet::from([
        "accepted".to_owned(),
        "analysis".to_owned(),
        "candidates".to_owned(),
        "locks".to_owned(),
        "packets".to_owned(),
        "plan.json".to_owned(),
    ]);
    if observed != expected {
        return Err(PipelineFailure::lock(
            "partial run contains progress or unknown residue and cannot be bootstrapped",
        ));
    }
    if state_present {
        return Err(PipelineFailure::lock(
            "partial run has a state projection without an initial event",
        ));
    }
    for empty in ["accepted", "analysis", "candidates", "packets"] {
        let path = directory.join(empty);
        authorize_read_path(context, &path, "build.plan")?;
        if fs::read_dir(&path)
            .map_err(|error| PipelineFailure::io("build.plan", &path, error))?
            .next()
            .is_some()
        {
            return Err(PipelineFailure::lock(format!(
                "partial run {empty} directory is not empty"
            )));
        }
    }
    let lock_names = fs::read_dir(directory.join("locks"))
        .map_err(|error| PipelineFailure::io("build.plan", &directory.join("locks"), error))?
        .map(|entry| {
            entry
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .map_err(|error| PipelineFailure::io("build.plan", directory, error))
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    if lock_names
        != BTreeSet::from([
            "source-lock.json".to_owned(),
            "template-lock.json".to_owned(),
        ])
    {
        return Err(PipelineFailure::lock(
            "partial run lock exact-set is invalid",
        ));
    }
    let state = planned_state(plan);
    append_event(context, directory, request, &state)?;
    write_json_atomic(&directory.join("state.json"), &state, "build.plan")?;
    sync_directory(directory, "build.plan")?;
    Ok(state)
}

fn required_run_id(request: &OperationRequest) -> Result<&str, PipelineFailure> {
    let value = request
        .run_id
        .as_deref()
        .ok_or_else(|| PipelineFailure::invalid("request", "a safe run_id is required"))?;
    validate_generated_id("run_id", value)?;
    Ok(value)
}

fn validate_generated_id(kind: &'static str, value: &str) -> Result<(), PipelineFailure> {
    validate_path_identifier(kind, value)
        .map_err(|error| PipelineFailure::invalid("request-identity", error.to_string()))
}

fn validate_exact_receipt_locks(
    request: &OperationRequest,
    source: &FileReceiptRef,
    template: &FileReceiptRef,
) -> Result<(), PipelineFailure> {
    let expected = BTreeMap::from([
        ("source_inspection", source.sha256.as_str()),
        ("template_validation", template.sha256.as_str()),
    ]);
    if request.locks.len() != expected.len()
        || expected
            .iter()
            .any(|(name, digest)| request.locks.get(*name).map(String::as_str) != Some(*digest))
    {
        return Err(PipelineFailure::lock(
            "build.plan request locks must exactly bind both receipt digests",
        ));
    }
    Ok(())
}

fn context_pipeline_failure(
    stage: &'static str,
) -> impl FnOnce(crate::ContextError) -> PipelineFailure + Copy {
    move |error| PipelineFailure {
        code: match error {
            crate::ContextError::PathEscape(_) | crate::ContextError::UnsafeRoot(_) => {
                ErrorCode::PathEscape
            }
            _ => ErrorCode::InvalidRequest,
        },
        stage,
        message: error.to_string(),
        recovery_hint: "use a canonical path contained by a CallContext authorized root",
    }
}

fn map_source_failure(error: crate::source::SourceFailure) -> PipelineFailure {
    PipelineFailure {
        code: error.code,
        stage: error.stage,
        message: error.message,
        recovery_hint: error.recovery_hint,
    }
}

fn map_template_failure(error: crate::template::TemplateFailure) -> PipelineFailure {
    PipelineFailure {
        code: error.code,
        stage: error.stage,
        message: error.message,
        recovery_hint: error.recovery_hint,
    }
}

fn parse_payload<T>(request: &OperationRequest, stage: &'static str) -> Result<T, PipelineFailure>
where
    T: for<'de> Deserialize<'de>,
{
    serde_json::from_value(request.payload.clone())
        .map_err(|error| PipelineFailure::invalid(stage, error.to_string()))
}

fn read_json<T>(path: &Path, stage: &'static str) -> Result<T, PipelineFailure>
where
    T: for<'de> Deserialize<'de>,
{
    let bytes = fs::read(path).map_err(|error| PipelineFailure::io(stage, path, error))?;
    serde_json::from_slice(&bytes)
        .map_err(|error| PipelineFailure::invalid(stage, format!("{}: {error}", path.display())))
}

fn write_json_atomic<T>(path: &Path, value: &T, stage: &'static str) -> Result<(), PipelineFailure>
where
    T: Serialize,
{
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| PipelineFailure::invalid(stage, error.to_string()))?;
    write_atomic(path, &bytes, stage)
}

fn write_atomic(path: &Path, bytes: &[u8], stage: &'static str) -> Result<(), PipelineFailure> {
    let parent = path.parent().ok_or_else(|| {
        PipelineFailure::invalid(stage, format!("path has no parent: {}", path.display()))
    })?;
    fs::create_dir_all(parent).map_err(|error| PipelineFailure::io(stage, parent, error))?;
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| {
            PipelineFailure::invalid(stage, format!("non-UTF-8 filename: {}", path.display()))
        })?;
    let content_digest = hex::encode(Sha256::digest(bytes));
    let temporary = parent.join(format!(
        ".{file_name}.{}.{}.tmp",
        &content_digest[..16],
        std::process::id()
    ));
    let opened = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary);
    let mut file = match opened {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let metadata = fs::symlink_metadata(&temporary)
                .map_err(|error| PipelineFailure::io(stage, &temporary, error))?;
            if !metadata.file_type().is_file() {
                return Err(PipelineFailure::state(format!(
                    "atomic write temporary is not a regular file: {}",
                    temporary.display()
                )));
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if metadata.nlink() > 1 {
                    return Err(PipelineFailure::state(format!(
                        "atomic write temporary is hardlinked: {}",
                        temporary.display()
                    )));
                }
            }
            let existing = fs::read(&temporary)
                .map_err(|error| PipelineFailure::io(stage, &temporary, error))?;
            if existing != bytes {
                return Err(PipelineFailure::lock(format!(
                    "atomic write temporary content conflicts at {}",
                    temporary.display()
                )));
            }
            fs::rename(&temporary, path)
                .map_err(|error| PipelineFailure::io(stage, path, error))?;
            sync_directory(parent, stage)?;
            return Ok(());
        }
        Err(error) => return Err(PipelineFailure::io(stage, &temporary, error)),
    };
    if let Err(error) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        let _ = fs::remove_file(&temporary);
        return Err(PipelineFailure::io(stage, &temporary, error));
    }
    drop(file);
    fs::rename(&temporary, path).map_err(|error| PipelineFailure::io(stage, path, error))?;
    sync_directory(parent, stage)?;
    Ok(())
}

fn sync_directory(path: &Path, stage: &'static str) -> Result<(), PipelineFailure> {
    #[cfg(unix)]
    {
        fs::File::open(path)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| PipelineFailure::io(stage, path, error))?;
    }
    Ok(())
}

fn write_json_immutable<T>(
    context: &CallContext,
    path: &Path,
    value: &T,
    stage: &'static str,
) -> Result<(), PipelineFailure>
where
    T: Serialize,
{
    publish_immutable_json(
        context,
        path,
        value,
        "summary.accept.accepted_receipt.after_partial_temp_write",
    )
    .map(|_| ())
    .map_err(|error| durable_failure(stage, error))
}

fn durable_failure(stage: &'static str, error: DurableWriteError) -> PipelineFailure {
    let (code, recovery_hint) = match error.kind {
        DurableErrorKind::Invalid => (
            ErrorCode::InvalidRequest,
            "correct the immutable receipt request and retry",
        ),
        DurableErrorKind::Unauthorized => (
            ErrorCode::PathEscape,
            "use only paths authorized by the current CallContext",
        ),
        DurableErrorKind::Unsafe => (
            ErrorCode::SymlinkRejected,
            "replace symlinked or hardlinked receipt paths with private regular files",
        ),
        DurableErrorKind::Conflict => (
            ErrorCode::LockMismatch,
            "preserve the immutable receipt and investigate content drift",
        ),
        DurableErrorKind::Io => (
            ErrorCode::Io,
            "verify the workspace filesystem and retry exact work",
        ),
    };
    PipelineFailure {
        code,
        stage,
        message: error.to_string(),
        recovery_hint,
    }
}

fn write_ndjson(path: &Path, values: &[Value], stage: &'static str) -> Result<(), PipelineFailure> {
    let output = ndjson_string(values, stage)?;
    fs::write(path, output).map_err(|error| PipelineFailure::io(stage, path, error))
}

fn ndjson_string(values: &[Value], stage: &'static str) -> Result<String, PipelineFailure> {
    let mut output = String::new();
    for value in values {
        let canonical = serde_json::to_string(value)
            .map_err(|error| PipelineFailure::invalid(stage, error.to_string()))?;
        output.push_str(&canonical);
        output.push('\n');
    }
    Ok(output)
}

fn append_event(
    context: &CallContext,
    run_directory: &Path,
    request: &OperationRequest,
    state: &RunStateFile,
) -> Result<bool, PipelineFailure> {
    let path = run_directory.join("events.ndjson");
    authorize_write_path(context, &path, "run-event")?;
    let mut events = load_run_events(context, run_directory, "run-event")?;
    if let Some(existing) = events.last()
        && existing.state == *state
    {
        return Ok(false);
    }
    let previous = events.last();
    let from = previous.map(|event| event.to);
    if !valid_run_transition(from, state.state) {
        return Err(PipelineFailure::state(format!(
            "illegal run transition from {from:?} to {:?}",
            state.state
        )));
    }
    let observed_unix_millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_millis());
    let run_id = run_directory
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| PipelineFailure::invalid("run-event", "run directory has no UTF-8 id"))?
        .to_owned();
    if state.schema_version != RUN_SCHEMA || state.run_id != run_id {
        return Err(PipelineFailure::lock(
            "run state does not bind the current run identity",
        ));
    }
    let mut event = RunEvent {
        schema_version: "gtkg.run-event/v2".to_owned(),
        sequence: events.len() as u64,
        request_id: request.request_id.clone(),
        run_id,
        operation_id: request.operation_id,
        from,
        to: state.state,
        state: state.clone(),
        locks: request.locks.clone(),
        actor: "gtkg-core".to_owned(),
        observed_unix_millis,
        evidence_refs: Vec::new(),
        previous_event_sha256: previous.map(|event| event.event_sha256.clone()),
        event_sha256: String::new(),
    };
    event.event_sha256 = run_event_sha256(&event)?;
    events.push(event);
    let values = events
        .iter()
        .map(|event| serde_json::to_value(event).unwrap_or(Value::Null))
        .collect::<Vec<_>>();
    write_atomic(
        &path,
        ndjson_string(&values, "run-event")?.as_bytes(),
        "run-event",
    )?;
    Ok(true)
}

fn load_run_events(
    context: &CallContext,
    run_directory: &Path,
    stage: &'static str,
) -> Result<Vec<RunEvent>, PipelineFailure> {
    let path = run_directory.join("events.ndjson");
    if !path.exists() {
        return Ok(Vec::new());
    }
    authorize_read_path(context, &path, stage)?;
    let source =
        fs::read_to_string(&path).map_err(|error| PipelineFailure::io(stage, &path, error))?;
    let expected_run_id = run_directory
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| PipelineFailure::invalid(stage, "run directory has no UTF-8 id"))?;
    let mut events = Vec::new();
    let mut previous_digest = None;
    let mut previous_state = None;
    for (index, line) in source.lines().enumerate() {
        if line.trim().is_empty() {
            return Err(PipelineFailure::lock(
                "run event ledger contains an empty record",
            ));
        }
        let event: RunEvent = serde_json::from_str(line)
            .map_err(|error| PipelineFailure::lock(format!("invalid run event: {error}")))?;
        if event.schema_version != "gtkg.run-event/v2"
            || event.sequence != index as u64
            || event.run_id != expected_run_id
            || event.state.schema_version != RUN_SCHEMA
            || event.state.run_id != expected_run_id
            || event.state.state != event.to
            || event.from != previous_state
            || event.previous_event_sha256 != previous_digest
            || !valid_run_transition(event.from, event.to)
            || run_event_sha256(&event)? != event.event_sha256
        {
            return Err(PipelineFailure::lock(format!(
                "run event chain is invalid at sequence {index}"
            )));
        }
        previous_state = Some(event.to);
        previous_digest = Some(event.event_sha256.clone());
        events.push(event);
    }
    if source.is_empty() || events.is_empty() {
        return Err(PipelineFailure::lock("run event ledger is empty"));
    }
    Ok(events)
}

fn run_event_sha256(event: &RunEvent) -> Result<String, PipelineFailure> {
    canonical_json_sha256(&json!({
        "schema_version": event.schema_version,
        "sequence": event.sequence,
        "request_id": event.request_id,
        "run_id": event.run_id,
        "operation_id": event.operation_id,
        "from": event.from,
        "to": event.to,
        "state": event.state,
        "locks": event.locks,
        "actor": event.actor,
        "observed_unix_millis": event.observed_unix_millis,
        "evidence_refs": event.evidence_refs,
        "previous_event_sha256": event.previous_event_sha256,
    }))
    .map_err(|error| PipelineFailure::lock(format!("run event digest failed: {error}")))
}

fn valid_run_transition(from: Option<RunState>, to: RunState) -> bool {
    matches!(
        (from, to),
        (None, RunState::Planned)
            | (Some(RunState::Planned), RunState::AwaitingSummary)
            | (Some(RunState::Planned), RunState::ReadyToFinalize)
            | (Some(RunState::AwaitingSummary), RunState::AwaitingSummary)
            | (Some(RunState::AwaitingSummary), RunState::ReadyToFinalize)
            | (Some(RunState::ReadyToFinalize), RunState::ReadyToFinalize)
            | (Some(RunState::ReadyToFinalize), RunState::Finalized)
            | (Some(RunState::Planned), RunState::Cancelled)
            | (Some(RunState::AwaitingSummary), RunState::Cancelled)
            | (Some(RunState::ReadyToFinalize), RunState::Cancelled)
    )
}

fn status_response(
    request: &OperationRequest,
    status: OperationStatus,
    result: Value,
) -> OperationResponse {
    OperationResponse {
        protocol_version: gtkg_protocol::PROTOCOL_VERSION.to_owned(),
        operation_id: request.operation_id,
        request_id: request.request_id.clone(),
        run_id: request.run_id.clone(),
        status,
        result,
        evidence_refs: Vec::new(),
        warnings: Vec::new(),
    }
}

fn finalize_response(request: &OperationRequest, record: &FinalizedRecord) -> OperationResponse {
    OperationResponse::completed(
        request,
        json!({
            "bundle_path": record.bundle_path,
            "semantic_digest": record.semantic_digest,
            "tree_digest": record.tree_digest,
        }),
    )
}

fn safe_join(root: &Path, relative: &str) -> Result<PathBuf, PipelineFailure> {
    let path = Path::new(relative);
    if relative.is_empty()
        || path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(PipelineFailure {
            code: ErrorCode::PathEscape,
            stage: "path-validation",
            message: format!("unsafe relative path: {relative}"),
            recovery_hint: "use a normalized relative path without parent traversal",
        });
    }
    Ok(root.join(path))
}

fn authorize_read_path(
    context: &CallContext,
    path: &Path,
    stage: &'static str,
) -> Result<PathBuf, PipelineFailure> {
    context
        .authorize_read(path)
        .map_err(context_pipeline_failure(stage))
}

fn authorize_write_path(
    context: &CallContext,
    path: &Path,
    stage: &'static str,
) -> Result<PathBuf, PipelineFailure> {
    context
        .authorize_write(path)
        .map_err(context_pipeline_failure(stage))
}

fn reject_symlinks_below(root: &Path, stage: &'static str) -> Result<(), PipelineFailure> {
    for entry in WalkDir::new(root).follow_links(false).sort_by_file_name() {
        let entry = entry.map_err(|error| PipelineFailure::io(stage, root, error))?;
        if entry.file_type().is_symlink() {
            return Err(PipelineFailure {
                code: ErrorCode::SymlinkRejected,
                stage,
                message: format!("symlink rejected: {}", entry.path().display()),
                recovery_hint: "replace the symlink with an explicitly locked regular file",
            });
        }
        #[cfg(unix)]
        if entry.file_type().is_file() {
            use std::os::unix::fs::MetadataExt;
            if entry
                .metadata()
                .map_err(|error| PipelineFailure::io(stage, entry.path(), error))?
                .nlink()
                > 1
            {
                return Err(PipelineFailure {
                    code: ErrorCode::SymlinkRejected,
                    stage,
                    message: format!("hardlink rejected: {}", entry.path().display()),
                    recovery_hint: "replace the hardlink with a private regular file copy",
                });
            }
        }
    }
    Ok(())
}

fn validate_workspace_path(path: &Path) -> Result<(), PipelineFailure> {
    if !path.is_absolute() {
        return Err(PipelineFailure::invalid(
            "build.plan",
            "workspace_root must be absolute",
        ));
    }
    Ok(())
}

fn validate_version(version: &str) -> Result<(), PipelineFailure> {
    let lower = version.to_ascii_lowercase();
    if version.is_empty()
        || matches!(lower.as_str(), "current" | "latest" | "head" | "main")
        || version.contains('/')
        || version.contains("..")
        || !version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        return Err(PipelineFailure::invalid(
            "version-validation",
            format!("unsafe or floating version: {version}"),
        ));
    }
    Ok(())
}

fn normalize_text(value: &str) -> String {
    value.replace("\r\n", "\n").replace('\0', "�")
}

fn digest_string(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

fn architecture_body(
    name: &str,
    sources: &[SourceManifestEntry],
    packets: &[AnalysisPacket],
    summaries: &[SummaryCandidate],
    bundle_version: &str,
    count: usize,
) -> String {
    let source_list = sources
        .iter()
        .map(|entry| {
            format!(
                "- `{}`:`{}` ({})",
                entry.repo_id, entry.logical_path, entry.role
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let index = ModuleIndex::from_packets(packets);
    let mut sorted_packets: Vec<&AnalysisPacket> = packets.iter().collect();
    sorted_packets.sort_by(|left, right| {
        (&left.repo_id, &left.source_path).cmp(&(&right.repo_id, &right.source_path))
    });

    let mut structure = Vec::new();
    for packet in &sorted_packets {
        let definitions = semantic_definition_rows(packet);
        if definitions.is_empty() {
            continue;
        }
        let defined = definitions
            .iter()
            .map(|(kind, name, _)| format!("{kind} `{name}`"))
            .collect::<Vec<_>>()
            .join(", ");
        structure.push(format!("- `{}` defines {defined}", packet.source_path));
    }
    let structure_section = if structure.is_empty() {
        "(no static module structure observed)".to_owned()
    } else {
        structure.join("\n")
    };

    let mut edges = Vec::new();
    for packet in &sorted_packets {
        let module_id = module_id_of(&packet.repo_id, &packet.source_path);
        let imports: BTreeSet<&str> = packet
            .observations
            .get("semantic_imports")
            .map(|section| {
                section
                    .lines()
                    .filter_map(|line| line.split('\t').next())
                    .collect()
            })
            .unwrap_or_default();
        for import in imports {
            match resolve_import_modules(&index, &module_id, import).as_slice() {
                [resolved] => {
                    let target = source_key_from_module_id(resolved)
                        .map(|key| key.logical_path)
                        .unwrap_or_else(|| resolved.clone());
                    edges.push(format!("- `{}` imports `{target}`", packet.source_path));
                }
                [] => edges.push(format!(
                    "- `{}` imports external `{import}`",
                    packet.source_path
                )),
                candidates => edges.push(format!(
                    "- `{}` imports `{import}` (conflict: {} candidates)",
                    packet.source_path,
                    candidates.len()
                )),
            }
        }
        let calls: BTreeSet<(String, String)> = packet
            .observations
            .get("semantic_calls")
            .map(|section| {
                section
                    .lines()
                    .filter_map(|line| {
                        let mut columns = line.split('\t');
                        Some((columns.next()?.to_owned(), columns.next()?.to_owned()))
                    })
                    .collect()
            })
            .unwrap_or_default();
        for (_, callee) in calls {
            if let Some(modules) = index.definition_modules_by_name.get(&callee)
                && let [resolved] = modules.as_slice()
            {
                let target = source_key_from_module_id(resolved)
                    .map(|key| key.logical_path)
                    .unwrap_or_else(|| resolved.clone());
                edges.push(format!(
                    "- `{}` calls `{callee}` defined in `{target}`",
                    packet.source_path
                ));
            }
        }
    }
    let edges_section = if edges.is_empty() {
        "(no dependency edges observed)".to_owned()
    } else {
        edges.join("\n")
    };

    let mut accepted = summaries.iter().collect::<Vec<_>>();
    accepted.sort_by(|left, right| {
        (&left.repo_id, &left.source_path).cmp(&(&right.repo_id, &right.source_path))
    });
    let summary_insights = accepted
        .iter()
        .map(|summary| {
            let excerpt = summary
                .summary_markdown
                .lines()
                .map(str::trim)
                .find(|line| !line.is_empty())
                .unwrap_or("(empty accepted summary)");
            let excerpt = excerpt.chars().take(160).collect::<String>();
            format!(
                "- `{}`:`{}` — {}",
                summary.repo_id, summary.source_path, excerpt
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let role_section = match name {
        "agent" => {
            "## Agent operating contract\n\nUse the source lock, accepted-summary evidence, graph edges, and progressive indexes as the only repository context. Revalidate digests before mutation and keep target content non-executing."
        }
        "claude" => {
            "## Claude context contract\n\nLoad L0 directory links first, then L1/L2 sidecars and only the L3 knowledge documents required by the task. Cite source and acceptance evidence; preserve unknown/conflict states."
        }
        "rules" => {
            "## Repository rules\n\n1. Git object identity and caller-held tree digests are mandatory.\n2. OKF concepts remain source-bound and immutable within a bundle version.\n3. Generated content never grants renderer or external-publish evidence by itself.\n4. No database or target-content execution is permitted."
        }
        "architecture" => {
            "## Architecture view\n\nThe bundle is a file-backed pipeline from locked Git blobs through static extraction, accepted summaries, typed graph/search indexes, versioned OKF documents, and deterministic Wiki/A2UI projections."
        }
        "design" => {
            "## Design decisions\n\nThe design favors portable files, explicit provenance, independent indexes, immutable version directories, fail-closed replay, and progressive disclosure over hidden database state or unbound generated prose."
        }
        other => panic!("unknown architecture document profile {other}"),
    };

    format!(
        "# {name}\n\nBundle version: `{bundle_version}`.  \nGenerator version: `gtkg/{}`.  \nKnowledge documents: {count}.\n\n{role_section}\n\n## Accepted summary insights\n\n{summary_insights}\n\n## Locked sources\n\n{source_list}\n\n## Module structure\n\n{structure_section}\n\n## Dependency edges\n\n{edges_section}\n",
        env!("CARGO_PKG_VERSION")
    )
}

fn architecture_description(name: &str) -> &'static str {
    match name {
        "agent" => "Versioned operating context for repository agents",
        "claude" => "Versioned progressive-loading context for Claude-compatible agents",
        "rules" => "Versioned repository and evidence rules derived from the locked bundle",
        "architecture" => {
            "Versioned module and dependency architecture derived from static evidence"
        }
        "design" => "Versioned design decisions and accepted-summary traceability",
        other => panic!("unknown architecture document profile {other}"),
    }
}

fn copy_tree(source: &Path, target: &Path, stage: &'static str) -> Result<(), PipelineFailure> {
    if target.exists() {
        return Err(PipelineFailure::state(format!(
            "copy target already exists: {}",
            target.display()
        )));
    }
    for entry in WalkDir::new(source).follow_links(false).sort_by_file_name() {
        let entry = entry.map_err(|error| PipelineFailure::io(stage, source, error))?;
        if entry.file_type().is_symlink() {
            return Err(PipelineFailure {
                code: ErrorCode::SymlinkRejected,
                stage,
                message: format!("symlink rejected: {}", entry.path().display()),
                recovery_hint: "replace the symlink with an explicitly locked regular file",
            });
        }
        let relative = entry.path().strip_prefix(source).map_err(|error| {
            PipelineFailure::invalid(stage, format!("copy path escape: {error}"))
        })?;
        let destination = target.join(relative);
        if entry.file_type().is_dir() {
            fs::create_dir_all(&destination)
                .map_err(|error| PipelineFailure::io(stage, &destination, error))?;
        } else if entry.file_type().is_file() {
            fs::copy(entry.path(), &destination)
                .map_err(|error| PipelineFailure::io(stage, &destination, error))?;
        }
    }
    Ok(())
}

fn quarantine_staging(
    context: &CallContext,
    scope_root: &Path,
    staging: &Path,
    label: &'static str,
    stage: &'static str,
) -> Result<Option<PathBuf>, PipelineFailure> {
    if !staging.exists() {
        return Ok(None);
    }
    authorize_write_path(context, staging, stage)?;
    reject_symlinks_below(staging, stage)?;
    let quarantine_root = scope_root.join("quarantine");
    authorize_write_path(context, &quarantine_root, stage)?;
    fs::create_dir_all(&quarantine_root)
        .map_err(|error| PipelineFailure::io(stage, &quarantine_root, error))?;
    let identity = if staging.is_dir() {
        tree_sha256(staging).map_err(map_file_model(stage))?
    } else if staging.is_file() {
        sha256_file(staging).map_err(map_file_model(stage))?
    } else {
        return Err(PipelineFailure::state(format!(
            "unsupported staging entry: {}",
            staging.display()
        )));
    };
    let identity = digest_string(&format!("{label}:{identity}"));
    let mut sequence = 0_u64;
    let target = loop {
        let candidate = quarantine_root.join(format!("{label}-{}-{sequence:04}", &identity[..16]));
        authorize_write_path(context, &candidate, stage)?;
        if !candidate.exists() {
            break candidate;
        }
        sequence = sequence.checked_add(1).ok_or_else(|| {
            PipelineFailure::state("quarantine sequence exhausted for stale staging")
        })?;
    };
    fs::rename(staging, &target).map_err(|error| PipelineFailure::io(stage, &target, error))?;
    Ok(Some(target))
}

fn exact_version_path(versions: &Path, version: &str, tree_digest: &str) -> Option<PathBuf> {
    let suffix = tree_digest.strip_prefix("sha256:")?;
    let prefix = suffix.get(..12)?;
    let path = versions.join(format!("v{version}--{prefix}"));
    path.is_dir().then_some(path)
}

fn map_file_model(stage: &'static str) -> impl FnOnce(FileModelError) -> PipelineFailure + Copy {
    move |error| PipelineFailure {
        code: match error {
            FileModelError::Symlink(_) | FileModelError::Hardlink(_) => ErrorCode::SymlinkRejected,
            FileModelError::VersionImmutable(_) => ErrorCode::VersionImmutable,
            FileModelError::MissingIndex(_)
            | FileModelError::ClosureMismatch { .. }
            | FileModelError::DuplicateEntry { .. }
            | FileModelError::DigestMismatch(_)
            | FileModelError::Okf(_)
            | FileModelError::IndexJson(_) => ErrorCode::IndexInvalid,
            _ => ErrorCode::Io,
        },
        stage,
        message: error.to_string(),
        recovery_hint: "inspect the file-only artifact and rebuild an unpublished candidate",
    }
}

struct WriteGuard {
    file: File,
}

impl WriteGuard {
    fn acquire(context: &CallContext, workspace_root: &Path) -> Result<Self, PipelineFailure> {
        let directory =
            authorize_write_path(context, &workspace_root.join(".gtkg"), "single-writer")?;
        let path = directory.join("writer.lock");
        authorize_write_path(context, &path, "single-writer")?;
        fs::create_dir_all(&directory)
            .map_err(|error| PipelineFailure::io("single-writer", &directory, error))?;
        if path.exists() {
            let metadata = fs::symlink_metadata(&path)
                .map_err(|error| PipelineFailure::io("single-writer", &path, error))?;
            if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
                return Err(PipelineFailure {
                    code: ErrorCode::SymlinkRejected,
                    stage: "single-writer",
                    message: format!("writer lock is not a regular file: {}", path.display()),
                    recovery_hint: "replace the lock path with a private regular file",
                });
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if metadata.nlink() > 1 {
                    return Err(PipelineFailure {
                        code: ErrorCode::SymlinkRejected,
                        stage: "single-writer",
                        message: format!("writer lock is hardlinked: {}", path.display()),
                        recovery_hint: "replace the lock path with a private regular file",
                    });
                }
            }
        }
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(|error| PipelineFailure::io("single-writer", &path, error))?;
        let path_metadata = fs::symlink_metadata(&path)
            .map_err(|error| PipelineFailure::io("single-writer", &path, error))?;
        let file_metadata = file
            .metadata()
            .map_err(|error| PipelineFailure::io("single-writer", &path, error))?;
        if path_metadata.file_type().is_symlink() || !file_metadata.is_file() {
            return Err(PipelineFailure {
                code: ErrorCode::SymlinkRejected,
                stage: "single-writer",
                message: format!("writer lock changed during open: {}", path.display()),
                recovery_hint: "replace the lock path with a private regular file",
            });
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if file_metadata.nlink() > 1
                || path_metadata.dev() != file_metadata.dev()
                || path_metadata.ino() != file_metadata.ino()
            {
                return Err(PipelineFailure {
                    code: ErrorCode::SymlinkRejected,
                    stage: "single-writer",
                    message: format!("writer lock identity changed: {}", path.display()),
                    recovery_hint: "replace the lock path with a private regular file",
                });
            }
        }
        match file.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => {
                return Err(PipelineFailure::state(format!(
                    "single-writer lock is held at {}",
                    path.display()
                )));
            }
            Err(TryLockError::Error(error)) => {
                return Err(PipelineFailure::io("single-writer", &path, error));
            }
        }
        file.set_len(0)
            .and_then(|()| writeln!(file, "pid={}", std::process::id()))
            .and_then(|()| file.sync_data())
            .map_err(|error| PipelineFailure::io("single-writer", &path, error))?;
        Ok(Self { file })
    }
}

impl Drop for WriteGuard {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}
