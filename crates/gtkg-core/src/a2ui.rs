//! File-only Frontend Semantic IR, A2UI v0.9.1, and offline Wiki projection.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::Write;
use std::path::{Component, Path, PathBuf};

use gtkg_protocol::{
    ErrorCode, FileReceiptRef, OperationId, OperationRequest, OperationResponse, SourceKey,
    canonical_json_sha256, validate_sha256,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::durable::{DurableErrorKind, DurableWriteError, publish_immutable_json};
use crate::file_model::{sha256_file, tree_sha256};
use crate::{CallContext, ContextError};

const A2UI_VERSION: &str = "0.9.1";
const A2UI_MESSAGE_VERSION: &str = "v0.9";
const A2UI_MIME_TYPE: &str = "application/a2ui+json";
/// H04: generation alone (no locked-browser renderer smoke) may claim at most
/// `a2ui_generatable`. `renderer_replicable` is granted only by `a2ui.validate`
/// after verifying `gtkg.a2ui-renderer-smoke/v2` evidence.
const EVIDENCE_GENERATION_STATE: &str = "a2ui_generatable";
const EVIDENCE_CEILING: &str = "renderer_replicable";
const RENDERER_SMOKE_SCHEMA: &str = "gtkg.a2ui-renderer-smoke/v2";
/// H04: the production A2UI profile is the vendored official Google A2UI
/// v0.9.1 basic catalog, not a self-built local test catalog.
const OFFICIAL_CATALOG_SCOPE: &str = "official_basic_catalog";
/// H04: the route action is emitted in the official `action.event` shape.
const OPEN_DOCUMENT_EVENT: &str = "gtkg.select_document";

// Vendored official Google A2UI v0.9.1 assets (byte-identical to
// `docs/external-specs/a2ui-v0.9.1/`, digest-locked by the h04 contract).
const OFFICIAL_SERVER_TO_CLIENT: &str = include_str!("../vendor/a2ui/v0_9_1/server_to_client.json");
const OFFICIAL_CLIENT_TO_SERVER: &str = include_str!("../vendor/a2ui/v0_9_1/client_to_server.json");
const OFFICIAL_COMMON_TYPES: &str = include_str!("../vendor/a2ui/v0_9_1/common_types.json");
const OFFICIAL_BASIC_CATALOG: &str = include_str!("../vendor/a2ui/v0_9_1/catalog.json");
const OFFICIAL_LIT_RENDERER_LOCK: &str =
    include_str!("../vendor/a2ui/v0_9_1/official_lit_renderer_lock.json");
const MAX_SHARD_ENTRIES: usize = 256;

#[derive(Debug)]
pub struct A2uiFailure {
    pub code: ErrorCode,
    pub stage: &'static str,
    pub message: String,
    pub recovery_hint: &'static str,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResolvePayload {
    workspace_root: PathBuf,
    catalog_root: PathBuf,
    spec_version: String,
    profile_id: String,
    profile_version: String,
    catalog_id: String,
    catalog_version: String,
    renderer_id: String,
    renderer_version: String,
    expected_manifest_sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GeneratePayload {
    workspace_root: PathBuf,
    bundle_path: PathBuf,
    expected_bundle_tree_sha256: String,
    resolution_ref: FileReceiptRef,
    projection_version: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GetPayload {
    workspace_root: PathBuf,
    generation_ref: FileReceiptRef,
    expected_projection_tree_sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ValidatePayload {
    workspace_root: PathBuf,
    generation_ref: FileReceiptRef,
    expected_projection_tree_sha256: String,
    required_evidence_state: String,
    #[serde(default)]
    renderer_smoke_ref: Option<FileReceiptRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogManifest {
    schema_version: String,
    spec_version: String,
    profile: CatalogIdentity,
    schema: CatalogFile,
    common_types: CatalogIdentity,
    catalog: CatalogIdentity,
    renderer: CatalogIdentity,
    scope: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogIdentity {
    id: String,
    version: String,
    path: String,
    sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogFile {
    path: String,
    sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RendererDefinition {
    schema_version: String,
    id: String,
    version: String,
    status: String,
    catalog_id: String,
    catalog_version: String,
    supported_components: Vec<String>,
    supported_actions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct A2uiLock {
    schema_version: String,
    spec_version: String,
    profile_id: String,
    profile_version: String,
    profile_sha256: String,
    schema_sha256: String,
    common_types_id: String,
    common_types_version: String,
    common_types_sha256: String,
    catalog_id: String,
    catalog_version: String,
    catalog_sha256: String,
    renderer_id: String,
    renderer_version: String,
    renderer_sha256: String,
    manifest_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResolutionReceipt {
    schema_version: String,
    catalog_root: PathBuf,
    manifest_path: PathBuf,
    a2ui_lock: A2uiLock,
    catalog_scope: String,
    evidence_ceiling: String,
    od_003: String,
    od_004: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GenerationReceipt {
    schema_version: String,
    projection_id: String,
    projection_version: String,
    projection_path: PathBuf,
    projection_tree_sha256: String,
    canonical_bundle_path: PathBuf,
    canonical_bundle_tree_sha256: String,
    artifact_manifest_sha256: String,
    source_lock_sha256: String,
    resolution_ref: FileReceiptRef,
    a2ui_lock: A2uiLock,
    frontend_ir_sha256: String,
    wiki_manifest_sha256: String,
    resource_count: u64,
    evidence_state: String,
    evidence_ceiling: String,
    executed_target_content: bool,
    idempotent_replay: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ValidationReceipt {
    schema_version: String,
    generation_ref: FileReceiptRef,
    projection_tree_sha256: String,
    required_evidence_state: String,
    observed_evidence_state: String,
    evidence_ceiling: String,
    valid: bool,
    checks: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RendererSmokeEvidence {
    schema_version: String,
    projection_tree_sha256: String,
    stream_sha256: String,
    stream_message_count: u64,
    catalog_id: String,
    catalog_version: String,
    catalog_sha256: String,
    server_schema_sha256: String,
    common_types_sha256: String,
    client_schema_sha256: String,
    renderer: RendererRuntimeEvidence,
    browser: BrowserRuntimeEvidence,
    observations: RendererObservations,
    artifacts: Vec<RendererArtifact>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RendererRuntimeEvidence {
    package_lock_path: PathBuf,
    package_lock_sha256: String,
    harness_root: PathBuf,
    harness_files: Vec<RelativeRendererArtifact>,
    site_root: PathBuf,
    site_files: Vec<RelativeRendererArtifact>,
    packages: Vec<RendererPackage>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustedRendererLock {
    schema_version: String,
    renderer_id: String,
    renderer_version: String,
    package_lock_sha256: String,
    packages: Vec<RendererPackage>,
    harness_files: Vec<RelativeRendererArtifact>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RelativeRendererArtifact {
    path: String,
    sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RendererPackage {
    name: String,
    version: String,
    integrity: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BrowserRuntimeEvidence {
    engine: String,
    version: String,
    executable_path: PathBuf,
    executable_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RendererObservations {
    surface_id: String,
    catalog_id: String,
    message_count: u64,
    component_ids: Vec<String>,
    index_count: u64,
    initial_title: String,
    initial_body_sha256: String,
    action_schema_valid: bool,
    client_message: Value,
    action_name: String,
    action_context_id: String,
    action_context_path: String,
    action_source_component_id: String,
    updated_title: String,
    updated_body_sha256: String,
    remote_request_count: u64,
    console_error_count: u64,
    csp_violation_count: u64,
    dialog_count: u64,
    popup_count: u64,
    download_count: u64,
    worker_count: u64,
    window_open_count: u64,
    dangerous_content_node_count: u64,
    xss_sentinel_tripped: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RendererArtifact {
    path: PathBuf,
    sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KnowledgeResource {
    id: String,
    logical_path: String,
    title: String,
    content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FrontendSemanticIr {
    schema_version: String,
    canonical_bundle_tree_sha256: String,
    artifact_manifest_sha256: String,
    source_lock_sha256: String,
    executed_target_content: bool,
    target_process_count: u64,
    runtime_verified_count: u64,
    entities: Vec<SemanticEntity>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SemanticEntity {
    id: String,
    kind: String,
    evidence_level: String,
    evidence_refs: Vec<EvidenceRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceRef {
    source_key: SourceKey,
    source_sha256: String,
    extractor_id: String,
    span: EvidenceSpan,
    evidence_source: String,
    analysis_path: String,
    analysis_sha256: String,
    packet_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceSpan {
    start: u64,
    end: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProjectionManifest {
    schema_version: String,
    projection_version: String,
    canonical_bundle_tree_sha256: String,
    artifact_manifest_sha256: String,
    source_lock_sha256: String,
    resolution_sha256: String,
    frontend_ir_sha256: String,
    resource_count: u64,
    projection_checksum_file: String,
    projection_checksum_scope: String,
    evidence_state: String,
    evidence_ceiling: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ProjectionChecksums {
    schema_version: String,
    scope: String,
    files: Vec<ChecksumEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ChecksumEntry {
    path: String,
    sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WikiManifest {
    schema_version: String,
    resource_count: u64,
    indexed_resource_count: u64,
    truncated: bool,
    initial_load: Vec<String>,
    selected_resource_id: String,
    shards: Vec<WikiShard>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WikiShard {
    id: String,
    path: String,
    content_path: String,
    entry_count: u64,
    sha256: String,
    content_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogShardEntry {
    id: String,
    logical_path: String,
    title: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WikiShardBoundary {
    pub id: String,
    pub start: usize,
    pub end: usize,
    pub entry_count: usize,
}

#[cfg(feature = "test-faults")]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WikiRenderResource {
    pub id: String,
    pub logical_path: String,
    pub title: String,
    pub content: String,
}

/// Computes the exact Wiki shard boundaries used by the production renderer.
///
/// The helper is pure so scale boundaries can be verified without manufacturing thousands of
/// unrelated Git commits and summary-acceptance receipts. `render_wiki` consumes this exact plan.
pub fn plan_wiki_shards(resource_count: usize) -> Vec<WikiShardBoundary> {
    (0..resource_count.div_ceil(MAX_SHARD_ENTRIES))
        .map(|index| {
            let start = index * MAX_SHARD_ENTRIES;
            let end = (start + MAX_SHARD_ENTRIES).min(resource_count);
            WikiShardBoundary {
                id: format!("{index:05}"),
                start,
                end,
                entry_count: end - start,
            }
        })
        .collect()
}

/// Emits a deterministic scale fixture with the exact production Wiki renderer.
///
/// This is available only with the test fault-injection feature. It does not create a canonical
/// bundle or an A2UI generation receipt; integration tests must separately bind a real verified
/// D03 bundle and public `a2ui.generate` result before using this scale-only browser projection.
#[cfg(feature = "test-faults")]
#[doc(hidden)]
pub fn render_wiki_test_projection(
    context: &CallContext,
    output_root: &Path,
    resources: &[WikiRenderResource],
    selected_resource_id: &str,
) -> Result<(), A2uiFailure> {
    if resources.is_empty() {
        return Err(invalid(
            "wiki.test-fixture",
            "Wiki scale fixture requires at least one resource",
        ));
    }
    let mut ids = BTreeSet::new();
    let mut verified = Vec::with_capacity(resources.len());
    for resource in resources {
        validate_local_identifier("Wiki resource id", &resource.id)?;
        validate_relative_path("Wiki resource logical path", &resource.logical_path)?;
        if !ids.insert(resource.id.as_str()) {
            return Err(invalid(
                "wiki.test-fixture",
                "Wiki scale fixture contains duplicate resource ids",
            ));
        }
        verified.push(KnowledgeResource {
            id: resource.id.clone(),
            logical_path: resource.logical_path.clone(),
            title: resource.title.clone(),
            content: resource.content.clone(),
        });
    }
    let selected = verified
        .iter()
        .find(|resource| resource.id == selected_resource_id)
        .ok_or_else(|| {
            invalid(
                "wiki.test-fixture",
                "selected resource is not present in the exact resource set",
            )
        })?;
    let output_root = authorize_write(context, output_root, "wiki.test-fixture")?;
    if output_root.exists()
        && fs::read_dir(&output_root)
            .map_err(|error| io("wiki.test-fixture", &output_root, error))?
            .next()
            .is_some()
    {
        return Err(failure(
            ErrorCode::InvalidState,
            "wiki.test-fixture",
            "Wiki scale fixture output root is not empty",
            "use a new empty authorized output directory",
        ));
    }
    fs::create_dir_all(&output_root)
        .map_err(|error| io("wiki.test-fixture", &output_root, error))?;
    render_wiki(context, &output_root, &verified, selected)?;
    sync_projection_tree(&output_root)
}

pub fn execute(
    context: &CallContext,
    request: &OperationRequest,
) -> Result<OperationResponse, A2uiFailure> {
    match request.operation_id {
        OperationId::A2uiResolve => resolve(context, request),
        OperationId::A2uiGenerate => generate(context, request),
        OperationId::A2uiGet => get(context, request),
        OperationId::A2uiValidate => validate(context, request),
        _ => Err(failure(
            ErrorCode::OperationNotImplemented,
            "a2ui.dispatch",
            "operation is not part of the A2UI execution surface",
            "use one of a2ui.resolve, a2ui.generate, a2ui.get, or a2ui.validate",
        )),
    }
}

fn resolve(
    context: &CallContext,
    request: &OperationRequest,
) -> Result<OperationResponse, A2uiFailure> {
    let payload: ResolvePayload = parse_payload(request, "a2ui.resolve")?;
    let workspace = authorize_write(context, &payload.workspace_root, "a2ui.resolve")?;
    let catalog_root = authorize_read(context, &payload.catalog_root, "a2ui.resolve")?;
    validate_exact_version("spec_version", &payload.spec_version)?;
    validate_exact_version("profile_version", &payload.profile_version)?;
    validate_exact_version("catalog_version", &payload.catalog_version)?;
    validate_exact_version("renderer_version", &payload.renderer_version)?;
    if payload.spec_version != A2UI_VERSION {
        return Err(invalid(
            "a2ui.resolve",
            "D05 accepts only the exact A2UI v0.9.1 profile",
        ));
    }
    validate_local_identifier("profile_id", &payload.profile_id)?;
    validate_local_identifier("catalog_id", &payload.catalog_id)?;
    validate_local_identifier("renderer_id", &payload.renderer_id)?;
    validate_sha256(&payload.expected_manifest_sha256)
        .map_err(|error| invalid("a2ui.resolve", error.to_string()))?;

    let verified = verify_catalog(
        context,
        &catalog_root,
        &payload.expected_manifest_sha256,
        Some(&payload),
    )?;
    let receipt = ResolutionReceipt {
        schema_version: "gtkg.a2ui-resolution-receipt/v1".to_owned(),
        catalog_root,
        manifest_path: verified.manifest_path.clone(),
        a2ui_lock: verified.a2ui_lock.clone(),
        catalog_scope: OFFICIAL_CATALOG_SCOPE.to_owned(),
        evidence_ceiling: EVIDENCE_CEILING.to_owned(),
        od_003: "closed".to_owned(),
        od_004: "closed".to_owned(),
    };
    let identity = canonical_json_sha256(&receipt)
        .map_err(|error| invalid("a2ui.resolve", error.to_string()))?;
    let receipt_path = workspace.join(format!(
        ".gtkg/a2ui/resolutions/resolve-{}.json",
        &identity[7..31]
    ));
    let receipt_path = publish_immutable_json(
        context,
        &receipt_path,
        &receipt,
        "a2ui.resolve.after_temp_sync_before_rename",
    )
    .map_err(|error| durable_failure("a2ui.resolve", error))?;
    let reference = receipt_reference(&workspace, &receipt_path, "a2ui.resolve")?;

    Ok(OperationResponse::completed(
        request,
        json!({
            "resolution_id": format!("resolve-{}", &identity[7..31]),
            "resolution_ref": reference,
            "a2ui_lock": receipt.a2ui_lock,
            "catalog_scope": receipt.catalog_scope,
            "evidence_ceiling": receipt.evidence_ceiling,
            "od_003": receipt.od_003,
            "od_004": receipt.od_004,
            "closure": {
                "components": verified.official.components,
                "functions": verified.official.functions,
                "wire_version": verified.wire_version,
                "renderer_supported_components": verified.supported_components,
            },
        }),
    ))
}

fn generate(
    context: &CallContext,
    request: &OperationRequest,
) -> Result<OperationResponse, A2uiFailure> {
    let payload: GeneratePayload = parse_payload(request, "a2ui.generate")?;
    let workspace = authorize_write(context, &payload.workspace_root, "a2ui.generate")?;
    validate_exact_version("projection_version", &payload.projection_version)?;
    validate_sha256(&payload.expected_bundle_tree_sha256)
        .map_err(|error| invalid("a2ui.generate", error.to_string()))?;
    let (resolution, verified_catalog, resolution_sha256) =
        load_resolution(context, &workspace, &payload.resolution_ref)?;
    ensure_generation_catalog_capabilities(&verified_catalog)?;
    let view = crate::pipeline::verified_projection_view(
        context,
        &payload.bundle_path,
        &payload.expected_bundle_tree_sha256,
    )
    .map_err(map_pipeline_failure)?;
    validate_projection_view_contract(&view)?;
    let knowledge = projection_knowledge(&view)?;
    let selected = knowledge
        .first()
        .ok_or_else(|| bundle_invalid("a2ui.generate", "verified bundle has no knowledge"))?;
    let frontend_ir = derive_frontend_ir(&view)?;

    let generation_identity = canonical_json_sha256(&json!({
        "schema_version": "gtkg.a2ui-generation-identity/v2",
        "projection_version": payload.projection_version,
        "canonical_bundle_tree_sha256": payload.expected_bundle_tree_sha256,
        "resolution_sha256": resolution_sha256,
        "frontend_ir": frontend_ir,
        "selected_resource_id": selected.id,
        "resource_count": knowledge.len(),
    }))
    .map_err(|error| invalid("a2ui.generate", error.to_string()))?;
    let _guard = ProjectionGuard::acquire(context, &workspace, &payload.projection_version)?;
    let receipt_path = workspace.join(format!(
        ".gtkg/a2ui/generations/generate-{}.json",
        &generation_identity[7..31]
    ));
    if receipt_path.exists() {
        let receipt = load_existing_generation_for_identity(
            context,
            &workspace,
            &receipt_path,
            &generation_identity,
            &payload,
            &resolution,
            &view.bundle_path,
        )?;
        return generation_response(request, &receipt, &receipt_path, &workspace);
    }
    let staging = workspace.join(format!(
        ".gtkg/a2ui/projections/staging/generate-{}",
        &generation_identity[7..31]
    ));
    let mut idempotent_replay =
        prepare_projection_staging(context, &workspace, &staging, &generation_identity)?;
    render_projection(
        context,
        &staging,
        &payload,
        &resolution,
        &resolution_sha256,
        &frontend_ir,
        &view,
        &knowledge,
        selected,
    )?;
    sync_projection_tree(&staging)?;
    crate::durable::pause_at_fault(
        context,
        "a2ui.generate.projection.after_staging_sync_before_publish",
    )
    .map_err(|error| durable_failure("a2ui.generate", error))?;
    crate::pipeline::verified_projection_view(
        context,
        &payload.bundle_path,
        &payload.expected_bundle_tree_sha256,
    )
    .map_err(map_pipeline_failure)?;

    let projection_tree_sha256 = tree_sha256(&staging)
        .map_err(|error| bundle_invalid("a2ui.generate", error.to_string()))?;
    verify_projection(&staging, &projection_tree_sha256)?;
    validate_projection_closure(&staging, &resolution, &verified_catalog)?;
    let versions = authorize_write(
        context,
        &workspace.join(".gtkg/a2ui/projections/versions"),
        "a2ui.generate",
    )?;
    fs::create_dir_all(&versions).map_err(|error| io("a2ui.generate", &versions, error))?;
    let (projection_path, projection_reused) = publish_projection_version(
        context,
        &staging,
        &versions,
        &payload.projection_version,
        &projection_tree_sha256,
    )?;
    idempotent_replay |= projection_reused;
    verify_projection(&projection_path, &projection_tree_sha256)?;
    validate_projection_closure(&projection_path, &resolution, &verified_catalog)?;
    crate::durable::pause_at_fault(
        context,
        "a2ui.generate.projection.after_publish_before_receipt",
    )
    .map_err(|error| durable_failure("a2ui.generate", error))?;
    let frontend_ir_sha256 = sha256_file(&projection_path.join("frontend/semantic-ir.json"))
        .map_err(|error| bundle_invalid("a2ui.generate", error.to_string()))?;
    let wiki_manifest_sha256 = sha256_file(&projection_path.join("wiki/wiki-manifest.json"))
        .map_err(|error| bundle_invalid("a2ui.generate", error.to_string()))?;

    let receipt = GenerationReceipt {
        schema_version: "gtkg.a2ui-generation-receipt/v1".to_owned(),
        projection_id: format!("generate-{}", &generation_identity[7..31]),
        projection_version: payload.projection_version,
        projection_path: projection_path.clone(),
        projection_tree_sha256: projection_tree_sha256.clone(),
        canonical_bundle_path: view.bundle_path,
        canonical_bundle_tree_sha256: view.bundle_tree_sha256,
        artifact_manifest_sha256: view.artifact_manifest_sha256,
        source_lock_sha256: view.source_lock_sha256,
        resolution_ref: payload.resolution_ref,
        a2ui_lock: resolution.a2ui_lock,
        frontend_ir_sha256: frontend_ir_sha256.clone(),
        wiki_manifest_sha256: wiki_manifest_sha256.clone(),
        resource_count: knowledge.len() as u64,
        evidence_state: EVIDENCE_GENERATION_STATE.to_owned(),
        evidence_ceiling: EVIDENCE_CEILING.to_owned(),
        executed_target_content: false,
        idempotent_replay,
    };
    let receipt_path = publish_immutable_json(
        context,
        &receipt_path,
        &receipt,
        "a2ui.generate.receipt.after_temp_sync_before_rename",
    )
    .map_err(|error| durable_failure("a2ui.generate", error))?;
    generation_response(request, &receipt, &receipt_path, &workspace)
}

fn get(
    context: &CallContext,
    request: &OperationRequest,
) -> Result<OperationResponse, A2uiFailure> {
    let payload: GetPayload = parse_payload(request, "a2ui.get")?;
    let workspace = authorize_read(context, &payload.workspace_root, "a2ui.get")?;
    let receipt = load_generation(
        context,
        &workspace,
        &payload.generation_ref,
        &payload.expected_projection_tree_sha256,
        "a2ui.get",
    )?;
    let stream = read_stream(
        &receipt.projection_path.join("a2ui/stream.jsonl"),
        "a2ui.get",
    )?;
    validate_stream(&stream, &receipt.a2ui_lock.catalog_id, "a2ui.get")?;
    Ok(OperationResponse::completed(
        request,
        json!({
            "projection_id": receipt.projection_id,
            "projection_tree_sha256": receipt.projection_tree_sha256,
            "evidence_state": receipt.evidence_state,
            "evidence_ceiling": receipt.evidence_ceiling,
            "mapping_states": ["exact", "approximation", "unsupported"],
            "load_sequence": ["manifest", "capability", "surface", "data", "action"],
            "stream": stream,
        }),
    ))
}

fn validate(
    context: &CallContext,
    request: &OperationRequest,
) -> Result<OperationResponse, A2uiFailure> {
    let payload: ValidatePayload = parse_payload(request, "a2ui.validate")?;
    let workspace = authorize_write(context, &payload.workspace_root, "a2ui.validate")?;
    match payload.required_evidence_state.as_str() {
        "a2ui_ready_summary" | "a2ui_generatable" => {
            if payload.renderer_smoke_ref.is_some() {
                return Err(invalid(
                    "a2ui.validate",
                    "browser smoke evidence is only coherent with a renderer_replicable request",
                ));
            }
        }
        "renderer_replicable" => {}
        "verified_replica" => {
            return Err(failure(
                ErrorCode::InvalidState,
                "a2ui.validate",
                "verified_replica stays fail-closed; renderer_replicable is the current evidence ceiling",
                "a verified external replica decision does not exist; request at most renderer_replicable with locked browser smoke evidence",
            ));
        }
        _ => return Err(invalid("a2ui.validate", "unknown evidence state")),
    }
    let receipt = load_generation(
        context,
        &workspace,
        &payload.generation_ref,
        &payload.expected_projection_tree_sha256,
        "a2ui.validate",
    )?;
    verify_projection(
        &receipt.projection_path,
        &payload.expected_projection_tree_sha256,
    )?;
    let mut checks = BTreeMap::new();
    checks.insert("action_resource_allowlist".to_owned(), "passed".to_owned());
    checks.insert("catalog_component_closure".to_owned(), "passed".to_owned());
    checks.insert("common_types_closure".to_owned(), "passed".to_owned());
    checks.insert(
        "frontend_ir_reference_closure".to_owned(),
        "passed".to_owned(),
    );
    checks.insert(
        "projection_full_tree_digest".to_owned(),
        "passed".to_owned(),
    );
    checks.insert("renderer_component_closure".to_owned(), "passed".to_owned());
    checks.insert("renderer_smoke".to_owned(), "not_run".to_owned());
    checks.insert("screenshot_artifacts".to_owned(), "not_run".to_owned());
    checks.insert("schema_nested_validation".to_owned(), "passed".to_owned());
    checks.insert("stream_manifest_sequence".to_owned(), "passed".to_owned());
    checks.insert("visual_threshold".to_owned(), "not_run".to_owned());
    if payload.required_evidence_state == "renderer_replicable" {
        let smoke_ref = payload
            .renderer_smoke_ref
            .as_ref()
            .ok_or_else(|| {
                failure(
                    ErrorCode::InvalidState,
                    "a2ui.validate",
                    "renderer_replicable requires verified locked-browser smoke evidence",
                    "run the locked H05 official renderer harness and pass its gtkg.a2ui-renderer-smoke/v2 receipt",
                )
            })?;
        verify_renderer_smoke(
            context,
            &workspace,
            smoke_ref,
            &receipt,
            &payload.expected_projection_tree_sha256,
        )?;
        checks.insert("renderer_smoke".to_owned(), "passed".to_owned());
        checks.insert("screenshot_artifacts".to_owned(), "passed".to_owned());
    }
    let missing_for_next_level = if payload.required_evidence_state == "renderer_replicable" {
        vec!["verified_replica stays fail-closed: no verified external replica decision exists"]
    } else {
        vec![
            "renderer_replicable requires locked browser smoke evidence (gtkg.a2ui-renderer-smoke/v2)",
            "verified_replica stays fail-closed: no verified external replica decision exists",
        ]
    };
    let validation = ValidationReceipt {
        schema_version: "gtkg.a2ui-validation-receipt/v1".to_owned(),
        generation_ref: payload.generation_ref,
        projection_tree_sha256: payload.expected_projection_tree_sha256,
        // H04: generation receipts claim at most `a2ui_generatable`; the
        // validation receipt is what grants the requested evidence state after
        // its checks (including verified renderer smoke for
        // `renderer_replicable`) pass.
        observed_evidence_state: payload.required_evidence_state.clone(),
        required_evidence_state: payload.required_evidence_state,
        evidence_ceiling: EVIDENCE_CEILING.to_owned(),
        valid: true,
        checks,
    };
    let identity = canonical_json_sha256(&validation)
        .map_err(|error| invalid("a2ui.validate", error.to_string()))?;
    let path = workspace.join(format!(
        ".gtkg/a2ui/validations/validate-{}.json",
        &identity[7..31]
    ));
    let path = publish_immutable_json(
        context,
        &path,
        &validation,
        "a2ui.validate.after_temp_sync_before_rename",
    )
    .map_err(|error| durable_failure("a2ui.validate", error))?;
    let validation_ref = receipt_reference(&workspace, &path, "a2ui.validate")?;
    Ok(OperationResponse::completed(
        request,
        json!({
            "valid": true,
            "validation_ref": validation_ref,
            "observed_evidence_state": validation.observed_evidence_state,
            "evidence_ceiling": validation.evidence_ceiling,
            "checks": validation.checks,
            "missing_for_next_level": missing_for_next_level,
        }),
    ))
}

struct VerifiedCatalog {
    manifest_path: PathBuf,
    a2ui_lock: A2uiLock,
    official: OfficialA2uiSchemas,
    supported_components: Vec<String>,
    wire_version: String,
}

/// The vendored official Google A2UI v0.9.1 profile: server schema, common
/// types, and the basic catalog, together with their content digests and the
/// identities the resolution lock binds. Parsed from the byte-frozen vendor
/// copies under `crates/gtkg-core/vendor/a2ui/v0_9_1/`.
#[derive(Debug, Clone)]
struct OfficialA2uiSchemas {
    server_to_client: Value,
    client_to_server: Value,
    common_types: Value,
    catalog: Value,
    profile_id: String,
    common_types_id: String,
    catalog_id: String,
    server_sha256: String,
    common_types_sha256: String,
    catalog_sha256: String,
    components: Vec<String>,
    functions: Vec<String>,
}

impl OfficialA2uiSchemas {
    fn load() -> Result<Self, A2uiFailure> {
        let server_to_client: Value = serde_json::from_str(OFFICIAL_SERVER_TO_CLIENT)
            .map_err(|error| invalid("a2ui.catalog", format!("official server schema: {error}")))?;
        let client_to_server: Value = serde_json::from_str(OFFICIAL_CLIENT_TO_SERVER)
            .map_err(|error| invalid("a2ui.catalog", format!("official client schema: {error}")))?;
        let common_types: Value = serde_json::from_str(OFFICIAL_COMMON_TYPES)
            .map_err(|error| invalid("a2ui.catalog", format!("official common types: {error}")))?;
        let catalog: Value = serde_json::from_str(OFFICIAL_BASIC_CATALOG)
            .map_err(|error| invalid("a2ui.catalog", format!("official basic catalog: {error}")))?;
        let profile_id = required_str(&server_to_client, "$id", "official server schema")?;
        let common_types_id = required_str(&common_types, "$id", "official common types")?;
        let catalog_id = required_str(&catalog, "catalogId", "official basic catalog")?;
        if catalog["$id"].as_str() != Some(catalog_id.as_str()) {
            return Err(lock(
                "a2ui.catalog",
                "official basic catalog $id and catalogId diverged",
            ));
        }
        let components = sorted_keys(&catalog, "components", "official basic catalog")?;
        let functions = sorted_keys(&catalog, "functions", "official basic catalog")?;
        Ok(Self {
            server_to_client,
            client_to_server,
            common_types,
            catalog,
            profile_id,
            common_types_id,
            catalog_id,
            server_sha256: sha256_bytes(OFFICIAL_SERVER_TO_CLIENT.as_bytes()),
            common_types_sha256: sha256_bytes(OFFICIAL_COMMON_TYPES.as_bytes()),
            catalog_sha256: sha256_bytes(OFFICIAL_BASIC_CATALOG.as_bytes()),
            components,
            functions,
        })
    }

    fn resolve<'a>(&'a self, current_root: &'a Value, reference: &str) -> (&'a Value, &'a Value) {
        let (base, fragment) = reference.split_once('#').unwrap_or((reference, ""));
        let root = if base.is_empty() {
            current_root
        } else {
            match base.rsplit('/').next().unwrap_or(base) {
                "catalog.json" => &self.catalog,
                "client_to_server.json" => &self.client_to_server,
                "common_types.json" => &self.common_types,
                "server_to_client.json" => &self.server_to_client,
                other => panic!("official A2UI evaluator cannot resolve $ref base {other}"),
            }
        };
        let target = if fragment.is_empty() {
            root
        } else {
            root.pointer(fragment)
                .unwrap_or_else(|| panic!("official A2UI evaluator unresolved $ref {reference}"))
        };
        (target, root)
    }

    /// Reduced JSON Schema 2020-12 evaluator supporting exactly the keyword
    /// subset used by the vendored official schemas ($ref across the official
    /// documents, oneOf/anyOf/allOf/not, type, enum, const, required,
    /// properties, additionalProperties, unevaluatedProperties, items,
    /// minItems, minimum, minProperties, maxProperties). `format`/`pattern`/
    /// `default`/`discriminator` are treated as annotations.
    fn validate(
        &self,
        instance: &Value,
        schema: &Value,
        root: &Value,
        path: &str,
        errors: &mut Vec<String>,
        depth: usize,
    ) {
        if depth > 96 {
            errors.push(format!("{path}: evaluator depth limit exceeded"));
            return;
        }
        let Some(object) = schema.as_object() else {
            if schema.as_bool() == Some(false) {
                errors.push(format!("{path}: rejected by false schema"));
            }
            return;
        };
        if let Some(reference) = object.get("$ref").and_then(Value::as_str) {
            let (target, target_root) = self.resolve(root, reference);
            self.validate(instance, target, target_root, path, errors, depth + 1);
        }
        if let Some(kind) = object.get("type").and_then(Value::as_str) {
            let matches = match kind {
                "array" => instance.is_array(),
                "boolean" => instance.is_boolean(),
                "integer" => instance.as_i64().is_some() || instance.as_u64().is_some(),
                "null" => instance.is_null(),
                "number" => instance.is_number(),
                "object" => instance.is_object(),
                "string" => instance.is_string(),
                _ => false,
            };
            if !matches {
                errors.push(format!("{path}: expected schema type {kind}"));
            }
        }
        if let Some(expected) = object.get("const")
            && instance != expected
        {
            errors.push(format!("{path}: const mismatch"));
        }
        if let Some(values) = object.get("enum").and_then(Value::as_array)
            && !values.contains(instance)
        {
            errors.push(format!("{path}: enum mismatch"));
        }
        if let Some(minimum) = object.get("minimum").and_then(Value::as_f64)
            && instance.as_f64().is_some_and(|value| value < minimum)
        {
            errors.push(format!("{path}: below minimum {minimum}"));
        }
        if let Some(minimum) = object.get("minItems").and_then(Value::as_u64)
            && instance
                .as_array()
                .is_some_and(|items| items.len() < minimum as usize)
        {
            errors.push(format!("{path}: fewer than minItems {minimum}"));
        }
        if let Some(bound) = object.get("minProperties").and_then(Value::as_u64)
            && instance
                .as_object()
                .is_some_and(|map| map.len() < bound as usize)
        {
            errors.push(format!("{path}: fewer than minProperties {bound}"));
        }
        if let Some(bound) = object.get("maxProperties").and_then(Value::as_u64)
            && instance
                .as_object()
                .is_some_and(|map| map.len() > bound as usize)
        {
            errors.push(format!("{path}: more than maxProperties {bound}"));
        }
        if let Some(required) = object.get("required").and_then(Value::as_array)
            && let Some(map) = instance.as_object()
        {
            for property in required.iter().filter_map(Value::as_str) {
                if !map.contains_key(property) {
                    errors.push(format!("{path}: missing required property {property}"));
                }
            }
        }
        let declared: BTreeSet<&str> = object
            .get("properties")
            .and_then(Value::as_object)
            .map(|properties| properties.keys().map(String::as_str).collect())
            .unwrap_or_default();
        if let Some(properties) = object.get("properties").and_then(Value::as_object)
            && let Some(map) = instance.as_object()
        {
            for (property, child_schema) in properties {
                if let Some(child) = map.get(property) {
                    self.validate(
                        child,
                        child_schema,
                        root,
                        &format!("{path}/{property}"),
                        errors,
                        depth + 1,
                    );
                }
            }
        }
        if let Some(map) = instance.as_object() {
            match object.get("additionalProperties") {
                Some(Value::Bool(false)) => {
                    for property in map.keys() {
                        if !declared.contains(property.as_str()) {
                            errors.push(format!("{path}: additional property {property}"));
                        }
                    }
                }
                Some(child_schema @ Value::Object(_)) => {
                    for (property, child) in map {
                        if !declared.contains(property.as_str()) {
                            self.validate(
                                child,
                                child_schema,
                                root,
                                &format!("{path}/{property}"),
                                errors,
                                depth + 1,
                            );
                        }
                    }
                }
                _ => {}
            }
        }
        if object.get("unevaluatedProperties").and_then(Value::as_bool) == Some(false)
            && let Some(map) = instance.as_object()
        {
            let mut evaluated = BTreeSet::new();
            self.collect_properties(schema, root, &mut evaluated, 0);
            for property in map.keys() {
                if !evaluated.contains(property.as_str()) {
                    errors.push(format!(
                        "{path}: unevaluated property {property} (catalog objects are closed)"
                    ));
                }
            }
        }
        if let Some(item_schema) = object.get("items")
            && let Some(items) = instance.as_array()
        {
            for (index, item) in items.iter().enumerate() {
                self.validate(
                    item,
                    item_schema,
                    root,
                    &format!("{path}/{index}"),
                    errors,
                    depth + 1,
                );
            }
        }
        if let Some(branches) = object.get("allOf").and_then(Value::as_array) {
            for branch in branches {
                self.validate(instance, branch, root, path, errors, depth + 1);
            }
        }
        if let Some(branches) = object.get("anyOf").and_then(Value::as_array) {
            let matched = branches
                .iter()
                .filter(|branch| {
                    let mut scratch = Vec::new();
                    self.validate(instance, branch, root, path, &mut scratch, depth + 1);
                    scratch.is_empty()
                })
                .count();
            if matched == 0 {
                errors.push(format!("{path}: anyOf matched no branch"));
            }
        }
        if let Some(branches) = object.get("oneOf").and_then(Value::as_array) {
            let matched = branches
                .iter()
                .filter(|branch| {
                    let mut scratch = Vec::new();
                    self.validate(instance, branch, root, path, &mut scratch, depth + 1);
                    scratch.is_empty()
                })
                .count();
            if matched != 1 {
                errors.push(format!("{path}: oneOf matched {matched} branches"));
            }
        }
        if let Some(negated) = object.get("not") {
            let mut scratch = Vec::new();
            self.validate(instance, negated, root, path, &mut scratch, depth + 1);
            if scratch.is_empty() {
                errors.push(format!("{path}: violated not constraint"));
            }
        }
    }

    fn collect_properties(
        &self,
        schema: &Value,
        root: &Value,
        set: &mut BTreeSet<String>,
        depth: usize,
    ) {
        if depth > 96 {
            return;
        }
        let Some(object) = schema.as_object() else {
            return;
        };
        if let Some(reference) = object.get("$ref").and_then(Value::as_str) {
            let (target, target_root) = self.resolve(root, reference);
            self.collect_properties(target, target_root, set, depth + 1);
        }
        if let Some(properties) = object.get("properties").and_then(Value::as_object) {
            set.extend(properties.keys().cloned());
        }
        for keyword in ["allOf", "oneOf", "anyOf"] {
            if let Some(branches) = object.get(keyword).and_then(Value::as_array) {
                for branch in branches {
                    self.collect_properties(branch, root, set, depth + 1);
                }
            }
        }
    }
}

fn sha256_bytes(bytes: &[u8]) -> String {
    use sha2::Digest;
    format!("sha256:{}", hex::encode(sha2::Sha256::digest(bytes)))
}

fn required_str(schema: &Value, key: &str, label: &str) -> Result<String, A2uiFailure> {
    schema
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| invalid("a2ui.catalog", format!("{label} is missing {key}")))
}

fn sorted_keys(schema: &Value, key: &str, label: &str) -> Result<Vec<String>, A2uiFailure> {
    let map = schema
        .get(key)
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("a2ui.catalog", format!("{label} is missing {key}")))?;
    Ok(map.keys().cloned().collect())
}

/// Verifies a locked-browser smoke evidence receipt against the exact generation.
///
/// The evidence is produced by the H05 official Lit browser harness. Every
/// measured field is checked against the exact generation, the vendored A2UI
/// schemas, and a compile-time renderer/harness lock; the package lock and
/// harness cannot self-anchor through the smoke receipt.
fn verify_renderer_smoke(
    context: &CallContext,
    workspace: &Path,
    reference: &FileReceiptRef,
    receipt: &GenerationReceipt,
    expected_projection_tree_sha256: &str,
) -> Result<(), A2uiFailure> {
    validate_receipt_namespace(reference, "browser-evidence", "smoke-", "a2ui.validate")?;
    ensure_workspace_receipt_is_private(workspace, reference, "a2ui.validate")?;
    let path = context
        .resolve_workspace_receipt(workspace, reference)
        .map_err(|error| context_failure("a2ui.validate", error))?;
    verify_file_digest(&path, &reference.sha256, "a2ui.validate")?;
    let evidence: RendererSmokeEvidence = read_json(&path, "a2ui.validate")?;
    if evidence.schema_version != RENDERER_SMOKE_SCHEMA {
        return Err(lock(
            "a2ui.validate",
            "renderer smoke evidence schema drifted",
        ));
    }
    for value in [
        &evidence.projection_tree_sha256,
        &evidence.stream_sha256,
        &evidence.catalog_sha256,
        &evidence.server_schema_sha256,
        &evidence.common_types_sha256,
        &evidence.client_schema_sha256,
        &evidence.renderer.package_lock_sha256,
        &evidence.browser.executable_sha256,
        &evidence.observations.initial_body_sha256,
        &evidence.observations.updated_body_sha256,
    ] {
        validate_sha256(value).map_err(|error| invalid("a2ui.validate", error.to_string()))?;
    }
    validate_exact_version("catalog version", &evidence.catalog_version)?;
    let trusted: TrustedRendererLock = serde_json::from_str(OFFICIAL_LIT_RENDERER_LOCK)
        .map_err(|error| invalid("a2ui.validate", format!("trusted renderer lock: {error}")))?;
    if trusted.schema_version != "gtkg.official-lit-renderer-lock/v1"
        || trusted.renderer_id != "official-a2ui-lit"
        || trusted.renderer_version != "0.10.3"
    {
        return Err(lock(
            "a2ui.validate",
            "trusted official Lit renderer identity drifted",
        ));
    }
    validate_sha256(&trusted.package_lock_sha256)
        .map_err(|error| invalid("a2ui.validate", error.to_string()))?;
    if evidence.projection_tree_sha256 != expected_projection_tree_sha256
        || evidence.catalog_id != receipt.a2ui_lock.catalog_id
        || evidence.catalog_version != receipt.a2ui_lock.catalog_version
        || evidence.catalog_sha256 != receipt.a2ui_lock.catalog_sha256
        || evidence.server_schema_sha256 != receipt.a2ui_lock.schema_sha256
        || evidence.common_types_sha256 != receipt.a2ui_lock.common_types_sha256
        || evidence.client_schema_sha256 != sha256_bytes(OFFICIAL_CLIENT_TO_SERVER.as_bytes())
        || receipt.a2ui_lock.renderer_id != trusted.renderer_id
        || receipt.a2ui_lock.renderer_version != trusted.renderer_version
    {
        return Err(lock(
            "a2ui.validate",
            "renderer smoke evidence is not bound to this generation and official A2UI lock",
        ));
    }
    let projection = authorize_read(context, &receipt.projection_path, "a2ui.validate")?;
    let stream_path = projection.join("a2ui/stream.jsonl");
    if sha256_file(&stream_path)
        .map_err(|error| bundle_invalid("a2ui.validate", error.to_string()))?
        != evidence.stream_sha256
    {
        return Err(lock(
            "a2ui.validate",
            "renderer smoke evidence stream digest drifted",
        ));
    }
    let stream = read_stream(&stream_path, "a2ui.validate")?;
    if evidence.stream_message_count != stream.len() as u64
        || evidence.observations.message_count != evidence.stream_message_count
    {
        return Err(lock(
            "a2ui.validate",
            "renderer smoke evidence message count drifted",
        ));
    }

    let package_lock = authorize_read(
        context,
        &evidence.renderer.package_lock_path,
        "a2ui.validate",
    )?;
    if sha256_file(&package_lock)
        .map_err(|error| bundle_invalid("a2ui.validate", error.to_string()))?
        != evidence.renderer.package_lock_sha256
        || evidence.renderer.package_lock_sha256 != trusted.package_lock_sha256
    {
        return Err(lock(
            "a2ui.validate",
            "renderer package lock digest drifted",
        ));
    }
    let package_lock_json: Value = read_json(&package_lock, "a2ui.validate")?;
    let required_packages = BTreeMap::from([
        ("@a2ui/lit", "0.10.3"),
        ("@a2ui/web_core", "0.10.6"),
        ("lit", "3.3.3"),
        ("playwright", "1.63.0-alpha-2026-08-05"),
        ("vite", "7.1.3"),
    ]);
    let observed_packages = evidence
        .renderer
        .packages
        .iter()
        .map(|package| (package.name.as_str(), package))
        .collect::<BTreeMap<_, _>>();
    let trusted_packages = trusted
        .packages
        .iter()
        .map(|package| (package.name.as_str(), package))
        .collect::<BTreeMap<_, _>>();
    if observed_packages.len() != required_packages.len()
        || trusted_packages.len() != required_packages.len()
        || !required_packages.iter().all(|(name, version)| {
            let Some(package) = observed_packages.get(name) else {
                return false;
            };
            let Some(trusted_package) = trusted_packages.get(name) else {
                return false;
            };
            let locked = &package_lock_json["packages"][format!("node_modules/{name}")];
            package.version == *version
                && trusted_package.version == *version
                && locked["version"] == *version
                && package.integrity.as_deref() == locked["integrity"].as_str()
                && package.integrity == trusted_package.integrity
                && package
                    .integrity
                    .as_deref()
                    .is_some_and(|value| !value.is_empty())
        })
    {
        return Err(lock(
            "a2ui.validate",
            "renderer package exact-set/version/integrity drifted",
        ));
    }

    let harness_root = authorize_read(context, &evidence.renderer.harness_root, "a2ui.validate")?;
    let trusted_harness = trusted
        .harness_files
        .iter()
        .map(|artifact| (artifact.path.as_str(), artifact.sha256.as_str()))
        .collect::<BTreeMap<_, _>>();
    let observed_harness = evidence
        .renderer
        .harness_files
        .iter()
        .map(|artifact| (artifact.path.as_str(), artifact.sha256.as_str()))
        .collect::<BTreeMap<_, _>>();
    if trusted_harness.len() != trusted.harness_files.len()
        || observed_harness.len() != evidence.renderer.harness_files.len()
        || observed_harness != trusted_harness
        || trusted_harness.is_empty()
    {
        return Err(lock(
            "a2ui.validate",
            "official Lit harness exact-set drifted from the trusted lock",
        ));
    }
    for artifact in &evidence.renderer.harness_files {
        validate_relative_path("renderer harness artifact", &artifact.path)?;
        validate_sha256(&artifact.sha256)
            .map_err(|error| invalid("a2ui.validate", error.to_string()))?;
        let artifact_path =
            authorize_read(context, &harness_root.join(&artifact.path), "a2ui.validate")?;
        if sha256_file(&artifact_path)
            .map_err(|error| bundle_invalid("a2ui.validate", error.to_string()))?
            != artifact.sha256
        {
            return Err(lock(
                "a2ui.validate",
                format!("official Lit harness artifact drifted: {}", artifact.path),
            ));
        }
    }

    let site_root = authorize_read(context, &evidence.renderer.site_root, "a2ui.validate")?;
    let mut listed = BTreeMap::new();
    for artifact in &evidence.renderer.site_files {
        validate_relative_path("renderer site artifact", &artifact.path)?;
        validate_sha256(&artifact.sha256)
            .map_err(|error| invalid("a2ui.validate", error.to_string()))?;
        if listed
            .insert(artifact.path.as_str(), artifact.sha256.as_str())
            .is_some()
        {
            return Err(lock("a2ui.validate", "duplicate renderer site artifact"));
        }
        let path = authorize_read(context, &site_root.join(&artifact.path), "a2ui.validate")?;
        if sha256_file(&path).map_err(|error| bundle_invalid("a2ui.validate", error.to_string()))?
            != artifact.sha256
        {
            return Err(lock(
                "a2ui.validate",
                format!("renderer site artifact drifted: {}", artifact.path),
            ));
        }
    }
    let mut observed_site = BTreeSet::new();
    for entry in walkdir::WalkDir::new(&site_root)
        .follow_links(false)
        .sort_by_file_name()
    {
        let entry = entry.map_err(|error| bundle_invalid("a2ui.validate", error.to_string()))?;
        if entry.file_type().is_symlink() {
            return Err(lock("a2ui.validate", "renderer site contains a symlink"));
        }
        if entry.file_type().is_file() {
            observed_site.insert(
                entry
                    .path()
                    .strip_prefix(&site_root)
                    .map_err(|error| bundle_invalid("a2ui.validate", error.to_string()))?
                    .to_string_lossy()
                    .replace('\\', "/"),
            );
        }
    }
    if observed_site != listed.keys().map(|path| (*path).to_owned()).collect() {
        return Err(lock(
            "a2ui.validate",
            "renderer site artifact manifest is not an exact set",
        ));
    }

    let browser_executable =
        authorize_read(context, &evidence.browser.executable_path, "a2ui.validate")?;
    if evidence.browser.engine != "chromium"
        || evidence.browser.version.trim().is_empty()
        || sha256_file(&browser_executable)
            .map_err(|error| bundle_invalid("a2ui.validate", error.to_string()))?
            != evidence.browser.executable_sha256
    {
        return Err(lock("a2ui.validate", "browser runtime identity drifted"));
    }

    let observations = &evidence.observations;
    let official = OfficialA2uiSchemas::load()?;
    let mut client_errors = Vec::new();
    official.validate(
        &observations.client_message,
        &official.client_to_server,
        &official.client_to_server,
        "$client",
        &mut client_errors,
        0,
    );
    let client_action = &observations.client_message["action"];
    let required_components = [
        "root",
        "index-pane",
        "index-list",
        "index-button",
        "content-pane",
        "doc-title",
        "doc-body",
        "doc-provenance",
    ];
    let data = &stream[2]["updateDataModel"]["value"];
    let initial_body = data["document"]["body"].as_str().unwrap_or_default();
    if observations.surface_id != "gtkg-main"
        || observations.catalog_id != receipt.a2ui_lock.catalog_id
        || observations.index_count != receipt.resource_count
        || observations.initial_title != data["document"]["title"]
        || observations.initial_body_sha256 != sha256_bytes(initial_body.as_bytes())
        || !required_components
            .iter()
            .all(|id| observations.component_ids.iter().any(|value| value == id))
        || !observations.action_schema_valid
        || !client_errors.is_empty()
        || observations.client_message["version"] != A2UI_MESSAGE_VERSION
        || client_action["surfaceId"] != observations.surface_id
        || client_action["name"] != observations.action_name
        || client_action["sourceComponentId"] != observations.action_source_component_id
        || client_action["context"]["documentId"] != observations.action_context_id
        || client_action["context"]["documentPath"] != observations.action_context_path
        || client_action["timestamp"]
            .as_str()
            .is_none_or(str::is_empty)
        || observations.action_name != OPEN_DOCUMENT_EVENT
        || observations.action_context_id.trim().is_empty()
        || observations.action_context_path.trim().is_empty()
        || observations.action_source_component_id.trim().is_empty()
        || observations.updated_title.trim().is_empty()
        || observations.updated_body_sha256 == observations.initial_body_sha256
        || observations.remote_request_count != 0
        || observations.console_error_count != 0
        || observations.csp_violation_count != 0
        || observations.dialog_count != 0
        || observations.popup_count != 0
        || observations.download_count != 0
        || observations.worker_count != 0
        || observations.window_open_count != 0
        || observations.dangerous_content_node_count != 0
        || observations.xss_sentinel_tripped
    {
        return Err(lock(
            "a2ui.validate",
            "official renderer DOM/action/data/security observations did not close",
        ));
    }

    if evidence.artifacts.len() < 2 {
        return Err(lock(
            "a2ui.validate",
            "renderer smoke artifacts are incomplete",
        ));
    }
    let mut artifact_paths = BTreeSet::new();
    for artifact in &evidence.artifacts {
        validate_sha256(&artifact.sha256)
            .map_err(|error| invalid("a2ui.validate", error.to_string()))?;
        let path = authorize_read(context, &artifact.path, "a2ui.validate")?;
        if !artifact_paths.insert(path.clone())
            || sha256_file(&path)
                .map_err(|error| bundle_invalid("a2ui.validate", error.to_string()))?
                != artifact.sha256
        {
            return Err(lock("a2ui.validate", "renderer smoke artifact drifted"));
        }
    }
    Ok(())
}

fn verify_catalog(
    context: &CallContext,
    root: &Path,
    expected_manifest_sha256: &str,
    requested: Option<&ResolvePayload>,
) -> Result<VerifiedCatalog, A2uiFailure> {
    let root = authorize_read(context, root, "a2ui.catalog")?;
    let manifest_path = authorize_read(context, &root.join("manifest.json"), "a2ui.catalog")?;
    verify_file_digest(&manifest_path, expected_manifest_sha256, "a2ui.catalog")?;
    let manifest: CatalogManifest = read_json(&manifest_path, "a2ui.catalog")?;
    if manifest.schema_version != "gtkg.a2ui-local-catalog-manifest/v1"
        || manifest.spec_version != A2UI_VERSION
    {
        return Err(invalid(
            "a2ui.catalog",
            "catalog manifest schema or spec version is not the frozen local profile",
        ));
    }
    for value in [
        &manifest.profile.id,
        &manifest.common_types.id,
        &manifest.catalog.id,
        &manifest.renderer.id,
    ] {
        validate_local_identifier("catalog identity", value)?;
    }
    for value in [
        &manifest.profile.version,
        &manifest.common_types.version,
        &manifest.catalog.version,
        &manifest.renderer.version,
    ] {
        validate_exact_version("catalog version", value)?;
    }
    // Integrity closure: every manifest-referenced local file is re-read and
    // digest-verified, so any catalog-root drift fails closed. These local
    // files are integrity-anchored legacy descriptors only — the protocol
    // schema, common types, and catalog are the vendored official Google A2UI
    // v0.9.1 assets bound into the lock below (H04).
    verify_catalog_file(context, &root, &manifest.profile)?;
    verify_plain_catalog_file(context, &root, &manifest.schema)?;
    verify_catalog_file(context, &root, &manifest.common_types)?;
    verify_catalog_file(context, &root, &manifest.catalog)?;
    let renderer_path = verify_catalog_file(context, &root, &manifest.renderer)?;
    let renderer: RendererDefinition = read_json(&renderer_path, "a2ui.catalog")?;
    if renderer.id != manifest.renderer.id
        || renderer.version != manifest.renderer.version
        || renderer.schema_version != "gtkg.a2ui-renderer-contract/v1"
        || renderer.catalog_id != manifest.catalog.id
        || renderer.catalog_version != manifest.catalog.version
    {
        return Err(lock("a2ui.catalog", "renderer descriptor identity drifted"));
    }
    // H04: the renderer descriptor records a local deterministic renderer. The
    // descriptor status is a truthful free-form marker (the legacy
    // `fixture_not_production` and the migrated `local_deterministic_renderer`
    // both name a local non-production renderer); it is validated as a safe
    // identifier, not pinned to a single word.
    validate_local_identifier("renderer status", &renderer.status)?;
    if renderer.supported_components.is_empty() {
        return Err(invalid(
            "a2ui.catalog",
            "renderer descriptor declares no supported components",
        ));
    }
    if let Some(requested) = requested
        && (requested.spec_version != manifest.spec_version
            || requested.profile_id != manifest.profile.id
            || requested.profile_version != manifest.profile.version
            || requested.catalog_id != manifest.catalog.id
            || requested.catalog_version != manifest.catalog.version
            || requested.renderer_id != manifest.renderer.id
            || requested.renderer_version != manifest.renderer.version)
    {
        return Err(lock(
            "a2ui.catalog",
            "requested A2UI identities do not match the exact local manifest",
        ));
    }
    let official = OfficialA2uiSchemas::load()?;
    let lock_sha256 = A2uiLock {
        schema_version: "gtkg.a2ui-lock/v1".to_owned(),
        spec_version: manifest.spec_version,
        profile_id: official.profile_id.clone(),
        profile_version: A2UI_VERSION.to_owned(),
        profile_sha256: official.server_sha256.clone(),
        schema_sha256: official.server_sha256.clone(),
        common_types_id: official.common_types_id.clone(),
        common_types_version: A2UI_VERSION.to_owned(),
        common_types_sha256: official.common_types_sha256.clone(),
        catalog_id: official.catalog_id.clone(),
        catalog_version: A2UI_VERSION.to_owned(),
        catalog_sha256: official.catalog_sha256.clone(),
        renderer_id: manifest.renderer.id,
        renderer_version: manifest.renderer.version,
        renderer_sha256: manifest.renderer.sha256,
        manifest_sha256: expected_manifest_sha256.to_owned(),
    };
    Ok(VerifiedCatalog {
        manifest_path,
        a2ui_lock: lock_sha256,
        official,
        supported_components: renderer.supported_components,
        wire_version: A2UI_MESSAGE_VERSION.to_owned(),
    })
}

fn load_resolution(
    context: &CallContext,
    workspace: &Path,
    reference: &FileReceiptRef,
) -> Result<(ResolutionReceipt, VerifiedCatalog, String), A2uiFailure> {
    validate_receipt_namespace(reference, "resolutions", "resolve-", "a2ui.resolution")?;
    ensure_workspace_receipt_is_private(workspace, reference, "a2ui.resolution")?;
    let path = context
        .resolve_workspace_receipt(workspace, reference)
        .map_err(|error| context_failure("a2ui.resolution", error))?;
    verify_file_digest(&path, &reference.sha256, "a2ui.resolution")?;
    let receipt: ResolutionReceipt = read_json(&path, "a2ui.resolution")?;
    if receipt.schema_version != "gtkg.a2ui-resolution-receipt/v1"
        || receipt.catalog_scope != OFFICIAL_CATALOG_SCOPE
        || receipt.evidence_ceiling != EVIDENCE_CEILING
        || receipt.od_003 != "closed"
        || receipt.od_004 != "closed"
    {
        return Err(lock(
            "a2ui.resolution",
            "resolution receipt schema or evidence boundary drifted",
        ));
    }
    let identity = canonical_json_sha256(&receipt)
        .map_err(|error| lock("a2ui.resolution", error.to_string()))?;
    let expected_name = format!("resolve-{}.json", &identity[7..31]);
    if path.file_name().and_then(|value| value.to_str()) != Some(expected_name.as_str()) {
        return Err(lock(
            "a2ui.resolution",
            "resolution receipt filename is not bound to its canonical content",
        ));
    }
    let verified = verify_catalog(
        context,
        &receipt.catalog_root,
        &receipt.a2ui_lock.manifest_sha256,
        None,
    )?;
    if verified.a2ui_lock != receipt.a2ui_lock || verified.manifest_path != receipt.manifest_path {
        return Err(lock(
            "a2ui.resolution",
            "local A2UI catalog changed after resolution",
        ));
    }
    Ok((receipt, verified, reference.sha256.clone()))
}

fn validate_receipt_namespace(
    reference: &FileReceiptRef,
    namespace: &str,
    file_prefix: &str,
    stage: &'static str,
) -> Result<(), A2uiFailure> {
    validate_relative_path("receipt path", &reference.path)?;
    let path = Path::new(&reference.path);
    let components = path
        .components()
        .map(|component| component.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    let valid = components.len() == 4
        && components[0] == ".gtkg"
        && components[1] == "a2ui"
        && components[2] == namespace
        && components[3].starts_with(file_prefix)
        && components[3].ends_with(".json");
    if !valid {
        return Err(lock(
            stage,
            format!(
                "receipt is outside the producer namespace: {}",
                reference.path
            ),
        ));
    }
    Ok(())
}

fn ensure_workspace_receipt_is_private(
    workspace: &Path,
    reference: &FileReceiptRef,
    stage: &'static str,
) -> Result<(), A2uiFailure> {
    let relative = Path::new(&reference.path);
    let component_count = relative.components().count();
    let mut candidate = workspace.to_path_buf();
    let mut final_metadata = None;
    for (index, component) in relative.components().enumerate() {
        candidate.push(component.as_os_str());
        let metadata =
            fs::symlink_metadata(&candidate).map_err(|error| io(stage, &candidate, error))?;
        let is_final = index + 1 == component_count;
        if metadata.file_type().is_symlink()
            || (!is_final && !metadata.is_dir())
            || (is_final && !metadata.is_file())
        {
            return Err(failure(
                ErrorCode::SymlinkRejected,
                stage,
                "receipt producer namespace contains a link or non-regular component",
                "use the exact producer namespace made only of real directories and a private receipt",
            ));
        }
        if is_final {
            final_metadata = Some(metadata);
        }
    }
    let canonical = fs::canonicalize(&candidate).map_err(|error| io(stage, &candidate, error))?;
    if canonical != candidate {
        return Err(failure(
            ErrorCode::SymlinkRejected,
            stage,
            "receipt canonical path drifted from its producer namespace",
            "use the exact producer receipt without aliases",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = final_metadata
            .as_ref()
            .ok_or_else(|| invalid(stage, "receipt path has no final component"))?;
        if metadata.nlink() > 1 {
            return Err(failure(
                ErrorCode::SymlinkRejected,
                stage,
                "receipt is hardlinked",
                "use the exact private producer receipt inode",
            ));
        }
    }
    Ok(())
}

fn load_generation(
    context: &CallContext,
    workspace: &Path,
    reference: &FileReceiptRef,
    expected_projection_tree_sha256: &str,
    stage: &'static str,
) -> Result<GenerationReceipt, A2uiFailure> {
    validate_sha256(expected_projection_tree_sha256)
        .map_err(|error| invalid(stage, error.to_string()))?;
    validate_receipt_namespace(reference, "generations", "generate-", stage)?;
    ensure_workspace_receipt_is_private(workspace, reference, stage)?;
    let path = context
        .resolve_workspace_receipt(workspace, reference)
        .map_err(|error| context_failure(stage, error))?;
    verify_file_digest(&path, &reference.sha256, stage)?;
    let receipt: GenerationReceipt = read_json(&path, stage)?;
    if receipt.schema_version != "gtkg.a2ui-generation-receipt/v1"
        || receipt.evidence_state != EVIDENCE_GENERATION_STATE
        || receipt.evidence_ceiling != EVIDENCE_CEILING
        || receipt.executed_target_content
    {
        return Err(lock(stage, "generation receipt contract drifted"));
    }
    let expected_name = format!("{}.json", receipt.projection_id);
    if path.file_name().and_then(|value| value.to_str()) != Some(expected_name.as_str()) {
        return Err(lock(
            stage,
            "generation receipt filename is not bound to its generation identity",
        ));
    }
    if receipt.projection_tree_sha256 != expected_projection_tree_sha256 {
        return Err(lock(
            stage,
            "caller-held projection digest does not match generation receipt",
        ));
    }
    let projection = authorize_read(context, &receipt.projection_path, stage)?;
    if projection != receipt.projection_path {
        return Err(lock(stage, "projection path canonical identity drifted"));
    }
    let versions = authorize_read(
        context,
        &workspace.join(".gtkg/a2ui/projections/versions"),
        stage,
    )?;
    let expected_projection_directory = format!(
        "v{}--{}",
        receipt.projection_version,
        &receipt.projection_tree_sha256[7..19]
    );
    if projection.parent() != Some(versions.as_path())
        || projection.file_name().and_then(|value| value.to_str())
            != Some(expected_projection_directory.as_str())
    {
        return Err(lock(
            stage,
            "projection path is outside its exact immutable producer namespace",
        ));
    }
    verify_projection(&projection, expected_projection_tree_sha256)?;
    let projection_manifest: ProjectionManifest =
        read_json(&projection.join("projection-manifest.json"), stage)?;
    let frontend_ir_path = projection.join("frontend/semantic-ir.json");
    let frontend_ir: FrontendSemanticIr = read_json(&frontend_ir_path, stage)?;
    let wiki_manifest_path = projection.join("wiki/wiki-manifest.json");
    let wiki_manifest: WikiManifest = read_json(&wiki_manifest_path, stage)?;
    let frontend_ir_sha256 =
        sha256_file(&frontend_ir_path).map_err(|error| bundle_invalid(stage, error.to_string()))?;
    let wiki_manifest_sha256 = sha256_file(&wiki_manifest_path)
        .map_err(|error| bundle_invalid(stage, error.to_string()))?;
    if projection_manifest.projection_version != receipt.projection_version
        || projection_manifest.canonical_bundle_tree_sha256 != receipt.canonical_bundle_tree_sha256
        || projection_manifest.artifact_manifest_sha256 != receipt.artifact_manifest_sha256
        || projection_manifest.source_lock_sha256 != receipt.source_lock_sha256
        || projection_manifest.resolution_sha256 != receipt.resolution_ref.sha256
        || projection_manifest.frontend_ir_sha256 != receipt.frontend_ir_sha256
        || projection_manifest.resource_count != receipt.resource_count
        || frontend_ir_sha256 != receipt.frontend_ir_sha256
        || wiki_manifest_sha256 != receipt.wiki_manifest_sha256
        || wiki_manifest.resource_count != receipt.resource_count
        || wiki_manifest.indexed_resource_count != receipt.resource_count
        || wiki_manifest.truncated
    {
        return Err(lock(
            stage,
            "generation receipt does not close over its projection manifest, IR, and Wiki",
        ));
    }
    let view = crate::pipeline::verified_projection_view(
        context,
        &receipt.canonical_bundle_path,
        &receipt.canonical_bundle_tree_sha256,
    )
    .map_err(map_pipeline_failure)?;
    if view.bundle_path != receipt.canonical_bundle_path
        || view.bundle_tree_sha256 != receipt.canonical_bundle_tree_sha256
        || view.artifact_manifest_sha256 != receipt.artifact_manifest_sha256
        || view.source_lock_sha256 != receipt.source_lock_sha256
    {
        return Err(lock(stage, "generation canonical bundle closure drifted"));
    }
    let (resolution, verified_catalog, _) =
        load_resolution(context, workspace, &receipt.resolution_ref)?;
    if resolution.a2ui_lock != receipt.a2ui_lock {
        return Err(lock(stage, "generation A2UI lock no longer closes"));
    }
    let generation_identity = canonical_json_sha256(&json!({
        "schema_version": "gtkg.a2ui-generation-identity/v2",
        "projection_version": &receipt.projection_version,
        "canonical_bundle_tree_sha256": &receipt.canonical_bundle_tree_sha256,
        "resolution_sha256": &receipt.resolution_ref.sha256,
        "frontend_ir": &frontend_ir,
        "selected_resource_id": &wiki_manifest.selected_resource_id,
        "resource_count": receipt.resource_count,
    }))
    .map_err(|error| lock(stage, error.to_string()))?;
    let expected_projection_id = format!("generate-{}", &generation_identity[7..31]);
    if receipt.projection_id != expected_projection_id {
        return Err(lock(
            stage,
            "generation receipt identity does not match its live canonical closure",
        ));
    }
    validate_projection_closure(&projection, &resolution, &verified_catalog)?;
    Ok(receipt)
}

fn load_existing_generation_for_identity(
    context: &CallContext,
    workspace: &Path,
    path: &Path,
    generation_identity: &str,
    payload: &GeneratePayload,
    resolution: &ResolutionReceipt,
    canonical_bundle_path: &Path,
) -> Result<GenerationReceipt, A2uiFailure> {
    let reference = receipt_reference(workspace, path, "a2ui.generate")?;
    let preview: GenerationReceipt = read_json(path, "a2ui.generate")?;
    let receipt = load_generation(
        context,
        workspace,
        &reference,
        &preview.projection_tree_sha256,
        "a2ui.generate",
    )?;
    let expected_projection_id = format!("generate-{}", &generation_identity[7..31]);
    if receipt.projection_id != expected_projection_id
        || receipt.projection_version != payload.projection_version
        || receipt.canonical_bundle_tree_sha256 != payload.expected_bundle_tree_sha256
        || receipt.canonical_bundle_path != canonical_bundle_path
        || receipt.resolution_ref != payload.resolution_ref
        || receipt.a2ui_lock != resolution.a2ui_lock
    {
        return Err(lock(
            "a2ui.generate",
            "existing generation receipt does not match the exact request identity",
        ));
    }
    Ok(receipt)
}

fn generation_response(
    request: &OperationRequest,
    receipt: &GenerationReceipt,
    receipt_path: &Path,
    workspace: &Path,
) -> Result<OperationResponse, A2uiFailure> {
    let generation_ref = receipt_reference(workspace, receipt_path, "a2ui.generate")?;
    Ok(OperationResponse::completed(
        request,
        json!({
            "projection_id": receipt.projection_id,
            "projection_path": receipt.projection_path,
            "projection_tree_sha256": receipt.projection_tree_sha256,
            "frontend_ir_sha256": receipt.frontend_ir_sha256,
            "wiki_manifest_sha256": receipt.wiki_manifest_sha256,
            "generation_ref": generation_ref,
            "resource_count": receipt.resource_count,
            "canonical_bundle_path": receipt.canonical_bundle_path,
            "canonical_bundle_tree_sha256": receipt.canonical_bundle_tree_sha256,
            "canonical_source": "verified_d03_bundle",
            "executed_target_content": false,
            "runtime_verified_count": 0,
            "evidence_state": receipt.evidence_state,
            "evidence_ceiling": receipt.evidence_ceiling,
            "initial_load": ["shell", "root_catalog", "selected_content"],
            "idempotent_replay": receipt.idempotent_replay,
        }),
    ))
}

fn derive_frontend_ir(
    view: &crate::pipeline::VerifiedProjectionView,
) -> Result<FrontendSemanticIr, A2uiFailure> {
    const KINDS: [&str; 12] = [
        "app",
        "route",
        "surface",
        "component",
        "layout",
        "style_token",
        "asset",
        "interaction",
        "data_binding",
        "ui_state",
        "accessibility",
        "evidence_ref",
    ];
    let allowed = BTreeSet::from(KINDS);
    let mut entities = Vec::new();
    let mut ids = BTreeSet::new();
    let mut target_process_count = 0_u64;
    for resource in &view.knowledge {
        target_process_count = target_process_count.saturating_add(resource.target_process_count);
        if resource.executed_target_content || resource.target_process_count != 0 {
            return Err(failure(
                ErrorCode::ExtractInvalid,
                "frontend.ir",
                "verified analysis evidence reports target execution",
                "rebuild the D03 bundle with static extractors only",
            ));
        }
        for fact in &resource.observed_facts {
            // A generic code/document bundle also carries language semantics
            // (functions, imports, calls, fields, and document facts). They
            // remain in the knowledge graph but are outside the frontend IR
            // vocabulary, so they must not make an otherwise valid Wiki/A2UI
            // projection fail. Facts selected into this IR stay strict.
            if !allowed.contains(fact.kind.as_str()) {
                continue;
            }
            if !matches!(
                fact.evidence_level.as_str(),
                "observed_static" | "resolved_static" | "inferred"
            ) {
                return Err(bundle_invalid(
                    "frontend.ir",
                    "frontend semantic fact has an unsupported evidence level",
                ));
            }
            validate_local_identifier("semantic marker", &fact.marker_id)?;
            let id = format!("{}:{}", fact.kind, fact.marker_id);
            if !ids.insert(id.clone()) {
                return Err(bundle_invalid(
                    "frontend.ir",
                    format!("duplicate semantic entity id {id}"),
                ));
            }
            entities.push(SemanticEntity {
                id,
                kind: fact.kind.clone(),
                evidence_level: fact.evidence_level.clone(),
                evidence_refs: vec![EvidenceRef {
                    source_key: resource.source_key.clone(),
                    source_sha256: resource.source_sha256.clone(),
                    extractor_id: resource.extractor_id.clone(),
                    span: EvidenceSpan {
                        start: fact.span.start,
                        end: fact.span.end,
                    },
                    evidence_source: "accepted_analysis_receipt".to_owned(),
                    analysis_path: resource.analysis_path.clone(),
                    analysis_sha256: resource.analysis_sha256.clone(),
                    packet_id: resource.packet_id.clone(),
                }],
            });
        }
    }
    entities.sort_by(|left, right| (&left.kind, &left.id).cmp(&(&right.kind, &right.id)));
    let observed_kinds = entities
        .iter()
        .map(|entity| entity.kind.as_str())
        .collect::<BTreeSet<_>>();
    if observed_kinds != allowed {
        return Err(failure(
            ErrorCode::InvalidState,
            "frontend.ir",
            "verified bundle does not contain the complete 12-kind frontend fact set",
            "rebuild the canonical bundle with frontend static evidence before projection",
        ));
    }
    Ok(FrontendSemanticIr {
        schema_version: "gtkg.frontend-semantic-ir/v2".to_owned(),
        canonical_bundle_tree_sha256: view.bundle_tree_sha256.clone(),
        artifact_manifest_sha256: view.artifact_manifest_sha256.clone(),
        source_lock_sha256: view.source_lock_sha256.clone(),
        executed_target_content: false,
        target_process_count,
        runtime_verified_count: 0,
        entities,
    })
}

fn ensure_generation_catalog_capabilities(catalog: &VerifiedCatalog) -> Result<(), A2uiFailure> {
    // The projection emits exactly these official basic-catalog components; the
    // route action is now an official `event` (gtkg.select_document), which any
    // A2UI client dispatches, so there is no catalog action allowlist anymore.
    let required = BTreeSet::from(["Button", "Column", "List", "Row", "Text"]);
    let official_components = catalog
        .official
        .components
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let renderer_components = catalog
        .supported_components
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if !required.is_subset(&official_components) {
        return Err(failure(
            ErrorCode::InvalidState,
            "a2ui.generate",
            "vendored official basic catalog lacks a component used by the projection",
            "restore the byte-frozen official A2UI v0.9.1 vendor assets",
        ));
    }
    if !required.is_subset(&renderer_components) {
        return Err(failure(
            ErrorCode::InvalidState,
            "a2ui.generate",
            "local deterministic renderer does not declare the projected components",
            "resolve a renderer descriptor supporting Button, Column, List, Row, and Text",
        ));
    }
    Ok(())
}

fn projection_knowledge(
    view: &crate::pipeline::VerifiedProjectionView,
) -> Result<Vec<KnowledgeResource>, A2uiFailure> {
    let mut resources = Vec::with_capacity(view.knowledge.len());
    let mut ids = BTreeSet::new();
    for item in &view.knowledge {
        validate_relative_path("canonical OKF path", &item.knowledge_path)?;
        validate_sha256(&item.knowledge_sha256)
            .map_err(|error| bundle_invalid("a2ui.generate", error.to_string()))?;
        if item.description.trim().is_empty() || item.media_type.trim().is_empty() {
            return Err(bundle_invalid(
                "a2ui.generate",
                "verified OKF description or analysis media type is empty",
            ));
        }
        if !ids.insert(item.knowledge_id.clone()) {
            return Err(bundle_invalid(
                "a2ui.generate",
                "verified bundle contains duplicate knowledge ids",
            ));
        }
        resources.push(KnowledgeResource {
            id: item.knowledge_id.clone(),
            logical_path: item.knowledge_path.clone(),
            title: item.title.clone(),
            content: item.body.clone(),
        });
    }
    resources.sort_by(|left, right| {
        (&left.logical_path, &left.id).cmp(&(&right.logical_path, &right.id))
    });
    Ok(resources)
}

fn validate_projection_view_contract(
    view: &crate::pipeline::VerifiedProjectionView,
) -> Result<(), A2uiFailure> {
    if view.manifest.schema_version != "gtkg.artifact-manifest/v1"
        || view.manifest.knowledge.len() != view.knowledge.len()
    {
        return Err(bundle_invalid(
            "a2ui.generate",
            "verified artifact manifest cannot be projected as an exact canonical set",
        ));
    }
    validate_sha256(&view.manifest.semantic_digest)
        .map_err(|error| bundle_invalid("a2ui.generate", error.to_string()))?;

    let manifest_documents = view
        .manifest
        .canonical_documents
        .iter()
        .map(|document| (document.path.as_str(), document.sha256.as_str()))
        .collect::<BTreeSet<_>>();
    let verified_documents = view
        .canonical_documents
        .iter()
        .map(|document| (document.path.as_str(), document.sha256.as_str()))
        .collect::<BTreeSet<_>>();
    if manifest_documents.len() != view.manifest.canonical_documents.len()
        || verified_documents.len() != view.canonical_documents.len()
        || manifest_documents != verified_documents
    {
        return Err(bundle_invalid(
            "a2ui.generate",
            "canonical document exact set drifted after bundle verification",
        ));
    }
    for (path, digest) in &verified_documents {
        validate_relative_path("canonical document path", path)?;
        validate_sha256(digest)
            .map_err(|error| bundle_invalid("a2ui.generate", error.to_string()))?;
    }

    if view.indexes.is_empty() {
        return Err(bundle_invalid(
            "a2ui.generate",
            "verified bundle has no progressive index evidence",
        ));
    }
    let indexes = view
        .indexes
        .iter()
        .map(|index| (index.path.as_str(), index.sha256.as_str()))
        .collect::<BTreeSet<_>>();
    if indexes.len() != view.indexes.len() {
        return Err(bundle_invalid(
            "a2ui.generate",
            "verified bundle contains duplicate progressive indexes",
        ));
    }
    for (path, digest) in indexes {
        validate_relative_path("progressive index path", path)?;
        validate_sha256(digest)
            .map_err(|error| bundle_invalid("a2ui.generate", error.to_string()))?;
    }
    Ok(())
}

fn map_pipeline_failure(error: crate::pipeline::PipelineFailure) -> A2uiFailure {
    A2uiFailure {
        code: error.code,
        stage: "a2ui.generate",
        message: error.message,
        recovery_hint: error.recovery_hint,
    }
}

#[allow(clippy::too_many_arguments)]
fn render_projection(
    context: &CallContext,
    staging: &Path,
    payload: &GeneratePayload,
    resolution: &ResolutionReceipt,
    resolution_sha256: &str,
    frontend_ir: &FrontendSemanticIr,
    view: &crate::pipeline::VerifiedProjectionView,
    knowledge: &[KnowledgeResource],
    selected: &KnowledgeResource,
) -> Result<(), A2uiFailure> {
    write_json_file(
        context,
        &staging.join("frontend/semantic-ir.json"),
        frontend_ir,
        "a2ui.generate",
    )?;
    let (stream, stream_manifest, mapping, action_binding) =
        render_a2ui_projection(resolution, frontend_ir, view, knowledge, selected)?;
    write_jsonl_file(
        context,
        &staging.join("a2ui/stream.jsonl"),
        &stream,
        "a2ui.generate",
    )?;
    let stream_sha256 = sha256_file(&staging.join("a2ui/stream.jsonl"))
        .map_err(|error| bundle_invalid("a2ui.generate", error.to_string()))?;
    let mut stream_manifest = stream_manifest;
    stream_manifest["stream_sha256"] = Value::String(stream_sha256);
    write_json_file(
        context,
        &staging.join("a2ui/stream-manifest.json"),
        &stream_manifest,
        "a2ui.generate",
    )?;
    write_json_file(
        context,
        &staging.join("a2ui/mapping-receipt.json"),
        &mapping,
        "a2ui.generate",
    )?;
    write_json_file(
        context,
        &staging.join("a2ui/action-binding-receipt.json"),
        &action_binding,
        "a2ui.generate",
    )?;
    render_wiki(context, staging, knowledge, selected)?;
    let frontend_ir_sha256 = sha256_file(&staging.join("frontend/semantic-ir.json"))
        .map_err(|error| bundle_invalid("a2ui.generate", error.to_string()))?;
    let manifest = ProjectionManifest {
        schema_version: "gtkg.projection-manifest/v2".to_owned(),
        projection_version: payload.projection_version.clone(),
        canonical_bundle_tree_sha256: payload.expected_bundle_tree_sha256.clone(),
        artifact_manifest_sha256: frontend_ir.artifact_manifest_sha256.clone(),
        source_lock_sha256: frontend_ir.source_lock_sha256.clone(),
        resolution_sha256: resolution_sha256.to_owned(),
        frontend_ir_sha256,
        resource_count: knowledge.len() as u64,
        projection_checksum_file: "projection-checksums.json".to_owned(),
        projection_checksum_scope: "projection_only".to_owned(),
        evidence_state: EVIDENCE_GENERATION_STATE.to_owned(),
        evidence_ceiling: EVIDENCE_CEILING.to_owned(),
    };
    write_json_file(
        context,
        &staging.join("projection-manifest.json"),
        &manifest,
        "a2ui.generate",
    )?;
    let checksums = projection_checksums(staging)?;
    write_json_file(
        context,
        &staging.join("projection-checksums.json"),
        &checksums,
        "a2ui.generate",
    )
}

fn render_a2ui_projection(
    resolution: &ResolutionReceipt,
    ir: &FrontendSemanticIr,
    view: &crate::pipeline::VerifiedProjectionView,
    knowledge: &[KnowledgeResource],
    selected: &KnowledgeResource,
) -> Result<(Vec<Value>, Value, Value, Value), A2uiFailure> {
    let entity = |kind: &str| {
        ir.entities
            .iter()
            .find(|entity| entity.kind == kind)
            .map(|entity| entity.id.clone())
            .ok_or_else(|| bundle_invalid("a2ui.generate", format!("missing IR kind {kind}")))
    };
    let app = entity("app")?;
    let route = entity("route")?;
    let surface = entity("surface")?;
    let component = entity("component")?;
    let layout = entity("layout")?;
    let style_token = entity("style_token")?;
    let asset = entity("asset")?;
    let interaction = entity("interaction")?;
    let data_binding = entity("data_binding")?;
    let ui_state = entity("ui_state")?;
    let accessibility = entity("accessibility")?;
    let evidence_ref = entity("evidence_ref")?;
    let selected_item = view
        .knowledge
        .iter()
        .find(|item| item.knowledge_id == selected.id)
        .ok_or_else(|| {
            bundle_invalid(
                "a2ui.generate",
                "selected knowledge is outside the verified view",
            )
        })?;
    // H04: the selected knowledge document is data and is delivered through
    // `updateDataModel`, not baked into components or dropped to a hardcoded
    // placeholder. A2UI Text consumes the plain string as inert data; the
    // separate offline Wiki bootstrap keeps its hex transport for file:// XSS
    // hardening. GTKG Semantic IR provenance stays in the mapping/action-binding
    // receipts, not in component properties.
    let mut provenance = selected_item.provenance.clone();
    provenance["digest"] = Value::String(selected_item.knowledge_sha256.clone());
    let provenance_text = format!(
        "status={} revision={} sources={} digest={}",
        provenance["status"],
        provenance["revision"],
        provenance["sources"].as_array().map_or(0, Vec::len),
        selected_item.knowledge_sha256
    );
    let document = json!({
        "id": selected_item.knowledge_id,
        "path": selected_item.knowledge_path,
        "title": selected_item.title,
        "body": selected_item.body,
        "provenance": provenance,
        "provenance_text": provenance_text,
    });
    let index = knowledge
        .iter()
        .map(|resource| {
            json!({
                "id": resource.id,
                "path": resource.logical_path,
                "title": resource.title,
            })
        })
        .collect::<Vec<_>>();
    let stream = vec![
        json!({
            "version": A2UI_MESSAGE_VERSION,
            "createSurface": {
                "surfaceId": "gtkg-main",
                "catalogId": resolution.a2ui_lock.catalog_id,
            }
        }),
        json!({
            "version": A2UI_MESSAGE_VERSION,
            "updateComponents": {
                "surfaceId": "gtkg-main",
                "components": [
                    {"id": "root", "component": "Row", "children": ["index-pane", "content-pane"], "align": "stretch"},
                    {"id": "index-pane", "component": "Column", "children": ["index-heading", "index-list"]},
                    {"id": "index-heading", "component": "Text", "text": "Knowledge Index", "variant": "h3"},
                    {"id": "index-list", "component": "List", "children": {"componentId": "index-button", "path": "/index"}, "direction": "vertical"},
                    {"id": "index-button", "component": "Button", "child": "index-label", "variant": "borderless", "action": {"event": {"name": OPEN_DOCUMENT_EVENT, "context": {"documentId": {"path": "id"}, "documentPath": {"path": "path"}}}}},
                    {"id": "index-label", "component": "Text", "text": {"path": "title"}},
                    {"id": "content-pane", "component": "Column", "children": ["doc-title", "doc-body", "doc-provenance"]},
                    {"id": "doc-title", "component": "Text", "text": {"path": "/document/title"}, "variant": "h2"},
                    {"id": "doc-body", "component": "Text", "text": {"path": "/document/body"}, "variant": "body"},
                    {"id": "doc-provenance", "component": "Text", "text": {"path": "/document/provenance_text"}, "variant": "caption"}
                ]
            }
        }),
        json!({
            "version": A2UI_MESSAGE_VERSION,
            "updateDataModel": {
                "surfaceId": "gtkg-main",
                "path": "/",
                "value": {"document": document, "index": index}
            }
        }),
    ];
    let segments = vec![
        json!({"kind": "manifest", "entity_ids": [app, evidence_ref]}),
        json!({"kind": "capability", "entity_ids": [accessibility]}),
        json!({"kind": "surface", "entity_ids": [surface, component, layout]}),
        json!({"kind": "data", "entity_ids": [data_binding, ui_state, style_token]}),
        json!({"kind": "action", "entity_ids": [interaction, route, asset]}),
    ];
    let manifest = json!({
        "schema_version": "gtkg.a2ui-stream-manifest/v2",
        "mime_type": A2UI_MIME_TYPE,
        "wire_version": A2UI_MESSAGE_VERSION,
        "load_sequence": ["manifest", "capability", "surface", "data", "action"],
        "segments": segments,
        "stream_sha256": Value::Null,
    });
    let mapping = json!({
        "schema_version": "gtkg.a2ui-mapping-receipt/v1",
        "mappings": [
            {"entity_id": surface, "state": "exact"},
            {"entity_id": layout, "state": "approximation"},
            {"entity_id": asset, "state": "unsupported"},
        ]
    });
    let action = json!({
        "schema_version": "gtkg.a2ui-action-binding/v2",
        "event": OPEN_DOCUMENT_EVENT,
        "context": {"documentId": {"path": "id"}, "documentPath": {"path": "path"}},
        "interaction_entity_id": interaction,
        "route_entity_id": route,
    });
    Ok((stream, manifest, mapping, action))
}

/// H04: the Wiki bootstrap channel carries each resource body as hex-encoded
/// UTF-8 (`content`), so the offline Wiki, the A2UI data model, and the frozen
/// h03 content-delivery assertion all share one byte-identical token. The Wiki
/// shell decodes it with `decodeHex` before rendering, so the rendered DOM is
/// unchanged.
fn wiki_resource_json(resource: &KnowledgeResource) -> Value {
    json!({
        "id": resource.id,
        "logical_path": resource.logical_path,
        "title": resource.title,
        "content": hex::encode(resource.content.as_bytes()),
    })
}

fn render_wiki(
    context: &CallContext,
    staging: &Path,
    knowledge: &[KnowledgeResource],
    selected: &KnowledgeResource,
) -> Result<(), A2uiFailure> {
    let wiki = staging.join("wiki");
    write_text_file(
        context,
        &wiki.join("index.html"),
        WIKI_HTML.as_bytes(),
        "wiki.generate",
    )?;
    write_text_file(
        context,
        &wiki.join("assets/wiki.css"),
        WIKI_CSS.as_bytes(),
        "wiki.generate",
    )?;
    write_text_file(
        context,
        &wiki.join("assets/wiki.js"),
        WIKI_JS.as_bytes(),
        "wiki.generate",
    )?;
    let selected_bytes = serde_json::to_vec(&wiki_resource_json(selected))
        .map_err(|error| invalid("wiki.generate", error.to_string()))?;
    write_text_file(
        context,
        &wiki.join("bootstrap/selected.js"),
        format!(
            "globalThis.__GTKG_SELECTED_HEX__=\"{}\";\n",
            hex::encode(selected_bytes)
        )
        .as_bytes(),
        "wiki.generate",
    )?;

    let mut shards = Vec::new();
    for boundary in plan_wiki_shards(knowledge.len()) {
        let chunk = &knowledge[boundary.start..boundary.end];
        let entries: Vec<_> = chunk
            .iter()
            .map(|resource| CatalogShardEntry {
                id: resource.id.clone(),
                logical_path: resource.logical_path.clone(),
                title: resource.title.clone(),
            })
            .collect();
        let bytes = serde_json::to_vec(&entries)
            .map_err(|error| invalid("wiki.generate", error.to_string()))?;
        let relative = format!("catalog/{}.js", boundary.id);
        let path = wiki.join(&relative);
        write_text_file(
            context,
            &path,
            format!(
                "globalThis.__GTKG_REGISTER_SHARD__(\"{}\",\"{}\");\n",
                boundary.id,
                hex::encode(bytes)
            )
            .as_bytes(),
            "wiki.generate",
        )?;
        let content_relative = format!("content/{}.js", boundary.id);
        let content_path = wiki.join(&content_relative);
        let content_resources: Vec<Value> = chunk.iter().map(wiki_resource_json).collect();
        let content_bytes = serde_json::to_vec(&content_resources)
            .map_err(|error| invalid("wiki.generate", error.to_string()))?;
        write_text_file(
            context,
            &content_path,
            format!(
                "globalThis.__GTKG_REGISTER_CONTENT_SHARD__(\"{}\",\"{}\");\n",
                boundary.id,
                hex::encode(content_bytes)
            )
            .as_bytes(),
            "wiki.generate",
        )?;
        shards.push(WikiShard {
            id: boundary.id,
            path: relative,
            content_path: content_relative,
            entry_count: boundary.entry_count as u64,
            sha256: sha256_file(&path)
                .map_err(|error| bundle_invalid("wiki.generate", error.to_string()))?,
            content_sha256: sha256_file(&content_path)
                .map_err(|error| bundle_invalid("wiki.generate", error.to_string()))?,
        });
    }
    let root_data = json!({
        "schema_version": "gtkg.wiki-root/v1",
        "resource_count": knowledge.len(),
        "selected_resource_id": selected.id,
        "shards": shards.iter().map(|shard| json!({"id": shard.id, "path": shard.path, "content_path": shard.content_path, "entry_count": shard.entry_count})).collect::<Vec<_>>(),
    });
    write_text_file(
        context,
        &wiki.join("bootstrap/root.js"),
        format!("globalThis.__GTKG_ROOT__={root_data};\n").as_bytes(),
        "wiki.generate",
    )?;
    let manifest = WikiManifest {
        schema_version: "gtkg.wiki-manifest/v1".to_owned(),
        resource_count: knowledge.len() as u64,
        indexed_resource_count: knowledge.len() as u64,
        truncated: false,
        initial_load: vec![
            "shell".to_owned(),
            "root_catalog".to_owned(),
            "selected_content".to_owned(),
        ],
        selected_resource_id: selected.id.clone(),
        shards,
    };
    write_json_file(
        context,
        &wiki.join("wiki-manifest.json"),
        &manifest,
        "wiki.generate",
    )
}

fn validate_stream(
    stream: &[Value],
    catalog_id: &str,
    stage: &'static str,
) -> Result<(), A2uiFailure> {
    const OPERATIONS: [&str; 4] = [
        "createSurface",
        "updateComponents",
        "updateDataModel",
        "deleteSurface",
    ];
    if stream.len() != 3 {
        return Err(bundle_invalid(
            stage,
            "A2UI server stream must contain the exact three generated messages",
        ));
    }
    let mut observed = Vec::new();
    for message in stream {
        let object = message
            .as_object()
            .ok_or_else(|| bundle_invalid(stage, "A2UI message is not an object"))?;
        if object.len() != 2
            || object.get("version").and_then(Value::as_str) != Some(A2UI_MESSAGE_VERSION)
        {
            return Err(bundle_invalid(
                stage,
                "A2UI message must have version plus exactly one operation",
            ));
        }
        let operations = OPERATIONS
            .iter()
            .filter(|operation| object.contains_key(**operation))
            .copied()
            .collect::<Vec<_>>();
        if operations.len() != 1 || !object[operations[0]].is_object() {
            return Err(bundle_invalid(
                stage,
                "A2UI message operation oneOf validation failed",
            ));
        }
        observed.push(operations[0]);
    }
    if observed != ["createSurface", "updateComponents", "updateDataModel"] {
        return Err(bundle_invalid(stage, "A2UI message ordering drifted"));
    }
    // The official basic-catalog identity is a URL; it is the one allowed URI
    // in the structural messages. Scan only createSurface/updateComponents:
    // updateDataModel is untrusted knowledge rendered through Text and may
    // legitimately discuss URLs, scripts, or shells as inert prose. Its safety
    // is established by closed component schemas plus the real renderer
    // CSP/XSS harness, not by rejecting ordinary words in document content.
    let serialized = serde_json::to_string(&stream[..2])
        .map_err(|error| bundle_invalid(stage, error.to_string()))?
        .to_ascii_lowercase()
        .replace(&catalog_id.to_ascii_lowercase(), "");
    for forbidden in [
        "javascript:",
        "data:text/html",
        "file://",
        "http://",
        "https://",
        "<script",
        "<foreignobject",
        "shell",
        "exec",
    ] {
        if serialized.contains(forbidden) {
            return Err(bundle_invalid(
                stage,
                format!("A2UI stream contains forbidden token {forbidden}"),
            ));
        }
    }
    Ok(())
}

fn verify_projection(root: &Path, expected: &str) -> Result<(), A2uiFailure> {
    verify_tree_digest(root, expected, "a2ui.projection")?;
    let manifest: ProjectionManifest =
        read_json(&root.join("projection-manifest.json"), "a2ui.projection")?;
    if manifest.schema_version != "gtkg.projection-manifest/v2"
        || manifest.projection_checksum_scope != "projection_only"
        || manifest.evidence_state != EVIDENCE_GENERATION_STATE
        || manifest.evidence_ceiling != EVIDENCE_CEILING
    {
        return Err(bundle_invalid(
            "a2ui.projection",
            "projection manifest contract drifted",
        ));
    }
    validate_sha256(&manifest.canonical_bundle_tree_sha256)
        .map_err(|error| bundle_invalid("a2ui.projection", error.to_string()))?;
    validate_sha256(&manifest.artifact_manifest_sha256)
        .map_err(|error| bundle_invalid("a2ui.projection", error.to_string()))?;
    validate_sha256(&manifest.source_lock_sha256)
        .map_err(|error| bundle_invalid("a2ui.projection", error.to_string()))?;
    validate_relative_path(
        "projection checksum file",
        &manifest.projection_checksum_file,
    )?;
    let checksums: ProjectionChecksums = read_json(
        &root.join(&manifest.projection_checksum_file),
        "a2ui.projection",
    )?;
    if checksums.schema_version != "gtkg.projection-checksums/v1"
        || checksums.scope != "projection_only"
    {
        return Err(bundle_invalid(
            "a2ui.projection",
            "projection checksum scope is invalid",
        ));
    }
    let expected_checksums = projection_checksums(root)?;
    if checksums != expected_checksums {
        return Err(bundle_invalid(
            "a2ui.projection",
            "projection checksum exact set or digest closure drifted",
        ));
    }
    for entry in checksums.files {
        validate_relative_path("projection checksum path", &entry.path)?;
        let observed = sha256_file(&root.join(&entry.path))
            .map_err(|error| bundle_invalid("a2ui.projection", error.to_string()))?;
        if observed != entry.sha256 {
            return Err(bundle_invalid(
                "a2ui.projection",
                format!("projection checksum drifted for {}", entry.path),
            ));
        }
    }
    let ir: FrontendSemanticIr =
        read_json(&root.join("frontend/semantic-ir.json"), "a2ui.projection")?;
    if ir.schema_version != "gtkg.frontend-semantic-ir/v2"
        || ir.executed_target_content
        || ir.target_process_count != 0
        || ir.runtime_verified_count != 0
        || ir.canonical_bundle_tree_sha256 != manifest.canonical_bundle_tree_sha256
        || ir.artifact_manifest_sha256 != manifest.artifact_manifest_sha256
        || ir.source_lock_sha256 != manifest.source_lock_sha256
        || ir.entities.len() < 12
    {
        return Err(bundle_invalid(
            "a2ui.projection",
            "Frontend Semantic IR evidence boundary is invalid",
        ));
    }
    Ok(())
}

fn validate_projection_closure(
    root: &Path,
    resolution: &ResolutionReceipt,
    catalog: &VerifiedCatalog,
) -> Result<(), A2uiFailure> {
    ensure_generation_catalog_capabilities(catalog)?;
    let ir: FrontendSemanticIr =
        read_json(&root.join("frontend/semantic-ir.json"), "a2ui.validate")?;
    let entity_ids = ir
        .entities
        .iter()
        .map(|entity| entity.id.as_str())
        .collect::<BTreeSet<_>>();
    if entity_ids.len() != ir.entities.len() {
        return Err(bundle_invalid(
            "a2ui.validate",
            "Frontend IR entity ids are not an exact set",
        ));
    }
    let stream_path = root.join("a2ui/stream.jsonl");
    let stream = read_stream(&stream_path, "a2ui.validate")?;
    validate_stream(&stream, &resolution.a2ui_lock.catalog_id, "a2ui.validate")?;
    // H04: every streamed message must validate against the vendored official
    // Google A2UI v0.9.1 server_to_client schema (basic-catalog closure,
    // unevaluatedProperties: false).
    for (index, message) in stream.iter().enumerate() {
        let mut errors = Vec::new();
        catalog.official.validate(
            message,
            &catalog.official.server_to_client,
            &catalog.official.server_to_client,
            &format!("$[{index}]"),
            &mut errors,
            0,
        );
        if !errors.is_empty() {
            return Err(bundle_invalid(
                "a2ui.validate",
                format!(
                    "stream message $[{index}] violates the official server_to_client schema: {}",
                    errors.join("; ")
                ),
            ));
        }
    }
    let stream_manifest: Value =
        read_json(&root.join("a2ui/stream-manifest.json"), "a2ui.validate")?;
    let sequence = ["manifest", "capability", "surface", "data", "action"];
    if stream_manifest["schema_version"] != "gtkg.a2ui-stream-manifest/v2"
        || stream_manifest["mime_type"] != A2UI_MIME_TYPE
        || stream_manifest["wire_version"] != A2UI_MESSAGE_VERSION
        || stream_manifest["load_sequence"] != json!(sequence)
        || stream_manifest["stream_sha256"]
            != sha256_file(&stream_path)
                .map(Value::String)
                .map_err(|error| bundle_invalid("a2ui.validate", error.to_string()))?
    {
        return Err(bundle_invalid(
            "a2ui.validate",
            "A2UI stream manifest identity or digest drifted",
        ));
    }
    let segments = stream_manifest["segments"]
        .as_array()
        .ok_or_else(|| bundle_invalid("a2ui.validate", "stream segments are missing"))?;
    if segments.len() != sequence.len() {
        return Err(bundle_invalid(
            "a2ui.validate",
            "stream segment exact-set drifted",
        ));
    }
    for (segment, expected_kind) in segments.iter().zip(sequence) {
        if segment["kind"] != expected_kind {
            return Err(bundle_invalid(
                "a2ui.validate",
                "stream segment order drifted",
            ));
        }
        for id in segment["entity_ids"]
            .as_array()
            .ok_or_else(|| bundle_invalid("a2ui.validate", "segment entity ids are missing"))?
        {
            if !id.as_str().is_some_and(|value| entity_ids.contains(value)) {
                return Err(bundle_invalid(
                    "a2ui.validate",
                    "stream manifest references an unknown IR entity",
                ));
            }
        }
    }

    validate_exact_object_keys(&stream[0]["createSurface"], &["catalogId", "surfaceId"])?;
    if stream[0]["createSurface"]["catalogId"] != resolution.a2ui_lock.catalog_id {
        return Err(bundle_invalid(
            "a2ui.validate",
            "createSurface catalogId is outside the A2UI lock",
        ));
    }
    validate_exact_object_keys(&stream[1]["updateComponents"], &["components", "surfaceId"])?;
    let components = stream[1]["updateComponents"]["components"]
        .as_array()
        .ok_or_else(|| bundle_invalid("a2ui.validate", "component array is missing"))?;
    let mut component_types = BTreeSet::new();
    for component in components {
        let component_type = component["component"]
            .as_str()
            .ok_or_else(|| bundle_invalid("a2ui.validate", "component type is missing"))?;
        // H04: components are official basic-catalog closed objects; no
        // self-built `sourceEntityId` property is allowed anymore.
        let keys: &[&str] = match component_type {
            "Row" => &["align", "children", "component", "id"],
            "Column" => &["children", "component", "id"],
            "List" => &["children", "component", "direction", "id"],
            "Text" => {
                if component.get("variant").is_some() {
                    &["component", "id", "text", "variant"]
                } else {
                    &["component", "id", "text"]
                }
            }
            "Button" => &["action", "child", "component", "id", "variant"],
            _ => {
                return Err(bundle_invalid(
                    "a2ui.validate",
                    "component is outside the projected official catalog set",
                ));
            }
        };
        validate_exact_object_keys(component, keys)?;
        component_types.insert(component_type);
    }
    validate_a2ui_component_graph(components)?;
    if component_types != BTreeSet::from(["Button", "Column", "List", "Row", "Text"])
        || stream[1]["updateComponents"]["surfaceId"] != stream[0]["createSurface"]["surfaceId"]
    {
        return Err(bundle_invalid(
            "a2ui.validate",
            "component or surface closure drifted",
        ));
    }
    let action = &components
        .iter()
        .find(|component| component["component"] == "Button")
        .ok_or_else(|| bundle_invalid("a2ui.validate", "Button component is missing"))?["action"];
    // H04: the route action uses the official `{event: {name, context}}` shape.
    validate_exact_object_keys(action, &["event"])?;
    validate_exact_object_keys(&action["event"], &["context", "name"])?;
    if action["event"]["name"] != OPEN_DOCUMENT_EVENT {
        return Err(bundle_invalid(
            "a2ui.validate",
            "component action event is outside the GTKG allowlist",
        ));
    }
    validate_exact_object_keys(&action["event"]["context"], &["documentId", "documentPath"])?;
    validate_exact_object_keys(&action["event"]["context"]["documentId"], &["path"])?;
    validate_exact_object_keys(&action["event"]["context"]["documentPath"], &["path"])?;
    if action["event"]["context"]["documentId"]["path"] != "id"
        || action["event"]["context"]["documentPath"]["path"] != "path"
    {
        return Err(bundle_invalid(
            "a2ui.validate",
            "index action context does not use relative item bindings",
        ));
    }
    validate_exact_object_keys(
        &stream[2]["updateDataModel"],
        &["path", "surfaceId", "value"],
    )?;
    let data = &stream[2]["updateDataModel"]["value"];
    validate_exact_object_keys(data, &["document", "index"])?;
    let document = &data["document"];
    validate_exact_object_keys(
        document,
        &[
            "body",
            "id",
            "path",
            "provenance",
            "provenance_text",
            "title",
        ],
    )?;
    if document["body"].as_str().is_none() || document["provenance_text"].as_str().is_none() {
        return Err(bundle_invalid(
            "a2ui.validate",
            "selected document body or provenance text is not renderable text data",
        ));
    }
    validate_exact_object_keys(
        &document["provenance"],
        &["digest", "revision", "sources", "status"],
    )?;
    validate_sha256(
        document["provenance"]["digest"]
            .as_str()
            .ok_or_else(|| bundle_invalid("a2ui.validate", "provenance digest is missing"))?,
    )
    .map_err(|error| bundle_invalid("a2ui.validate", error.to_string()))?;
    // The data-model document must be the exact resource the offline Wiki
    // selected. The index template action resolves id/path relative to the
    // clicked item, so it closes over the index exact-set below.
    let wiki_manifest: WikiManifest =
        read_json(&root.join("wiki/wiki-manifest.json"), "a2ui.validate")?;
    if document["id"] != wiki_manifest.selected_resource_id {
        return Err(bundle_invalid(
            "a2ui.validate",
            "data-model document, route action, and Wiki selection do not close",
        ));
    }
    let index = data["index"]
        .as_array()
        .ok_or_else(|| bundle_invalid("a2ui.validate", "data-model index is missing"))?;
    if index.len() as u64 != wiki_manifest.resource_count {
        return Err(bundle_invalid(
            "a2ui.validate",
            "data-model index does not cover the exact knowledge resource set",
        ));
    }
    for entry in index {
        validate_exact_object_keys(entry, &["id", "path", "title"])?;
    }
    if !index
        .iter()
        .any(|entry| entry["id"] == document["id"] && entry["path"] == document["path"])
    {
        return Err(bundle_invalid(
            "a2ui.validate",
            "selected document is outside the data-model index exact-set",
        ));
    }

    let action_binding: Value = read_json(
        &root.join("a2ui/action-binding-receipt.json"),
        "a2ui.validate",
    )?;
    validate_exact_object_keys(
        &action_binding,
        &[
            "context",
            "event",
            "interaction_entity_id",
            "route_entity_id",
            "schema_version",
        ],
    )?;
    if action_binding["schema_version"] != "gtkg.a2ui-action-binding/v2"
        || action_binding["event"] != OPEN_DOCUMENT_EVENT
        || action_binding["context"]["documentId"]["path"] != "id"
        || action_binding["context"]["documentPath"]["path"] != "path"
        || !["interaction_entity_id", "route_entity_id"]
            .iter()
            .all(|field| {
                action_binding[*field]
                    .as_str()
                    .is_some_and(|id| entity_ids.contains(id))
            })
    {
        return Err(bundle_invalid(
            "a2ui.validate",
            "action binding receipt is outside the IR or event closure",
        ));
    }
    let mapping: Value = read_json(&root.join("a2ui/mapping-receipt.json"), "a2ui.validate")?;
    let mappings = mapping["mappings"]
        .as_array()
        .ok_or_else(|| bundle_invalid("a2ui.validate", "mapping receipt is missing"))?;
    let states = mappings
        .iter()
        .filter_map(|entry| entry["state"].as_str())
        .collect::<BTreeSet<_>>();
    if mapping["schema_version"] != "gtkg.a2ui-mapping-receipt/v1"
        || states != BTreeSet::from(["approximation", "exact", "unsupported"])
        || !mappings.iter().all(|entry| {
            entry["entity_id"]
                .as_str()
                .is_some_and(|id| entity_ids.contains(id))
        })
    {
        return Err(bundle_invalid(
            "a2ui.validate",
            "component mapping receipt does not close over Frontend IR",
        ));
    }
    Ok(())
}

fn validate_a2ui_component_graph(components: &[Value]) -> Result<(), A2uiFailure> {
    let mut edges = BTreeMap::<String, Vec<String>>::new();
    for component in components {
        let id = component["id"]
            .as_str()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| bundle_invalid("a2ui.validate", "component id is missing"))?
            .to_owned();
        if edges.contains_key(&id) {
            return Err(bundle_invalid(
                "a2ui.validate",
                format!("duplicate component id: {id}"),
            ));
        }
        let mut refs = Vec::new();
        if let Some(child) = component.get("child").and_then(Value::as_str) {
            refs.push(child.to_owned());
        }
        if let Some(children) = component.get("children") {
            if let Some(array) = children.as_array() {
                for child in array {
                    refs.push(
                        child
                            .as_str()
                            .ok_or_else(|| {
                                bundle_invalid(
                                    "a2ui.validate",
                                    "static child reference is not a component id",
                                )
                            })?
                            .to_owned(),
                    );
                }
            } else if let Some(template) = children.as_object() {
                let component_id = template
                    .get("componentId")
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        bundle_invalid(
                            "a2ui.validate",
                            "template child list is missing componentId",
                        )
                    })?;
                let path = template
                    .get("path")
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        bundle_invalid("a2ui.validate", "template child list is missing path")
                    })?;
                if !path.starts_with('/') {
                    return Err(bundle_invalid(
                        "a2ui.validate",
                        "template child list path must be an absolute data-model pointer",
                    ));
                }
                refs.push(component_id.to_owned());
            } else {
                return Err(bundle_invalid(
                    "a2ui.validate",
                    "children is neither a static list nor a template child list",
                ));
            }
        }
        refs.sort();
        refs.dedup();
        edges.insert(id, refs);
    }
    if !edges.contains_key("root") {
        return Err(bundle_invalid(
            "a2ui.validate",
            "component graph has no root component",
        ));
    }
    for (parent, children) in &edges {
        for child in children {
            if !edges.contains_key(child) {
                return Err(bundle_invalid(
                    "a2ui.validate",
                    format!("component {parent} references unknown child {child}"),
                ));
            }
        }
    }

    fn visit(
        id: &str,
        edges: &BTreeMap<String, Vec<String>>,
        visiting: &mut BTreeSet<String>,
        visited: &mut BTreeSet<String>,
    ) -> Result<(), String> {
        if visited.contains(id) {
            return Ok(());
        }
        if !visiting.insert(id.to_owned()) {
            return Err(format!("component graph cycle includes {id}"));
        }
        for child in &edges[id] {
            visit(child, edges, visiting, visited)?;
        }
        visiting.remove(id);
        visited.insert(id.to_owned());
        Ok(())
    }

    let mut visiting = BTreeSet::new();
    let mut visited = BTreeSet::new();
    visit("root", &edges, &mut visiting, &mut visited)
        .map_err(|message| bundle_invalid("a2ui.validate", message))?;
    if visited.len() != edges.len() {
        let unreachable = edges
            .keys()
            .filter(|id| !visited.contains(*id))
            .cloned()
            .collect::<Vec<_>>();
        return Err(bundle_invalid(
            "a2ui.validate",
            format!("component graph contains unreachable nodes: {unreachable:?}"),
        ));
    }
    Ok(())
}

fn validate_exact_object_keys(value: &Value, expected: &[&str]) -> Result<(), A2uiFailure> {
    let object = value
        .as_object()
        .ok_or_else(|| bundle_invalid("a2ui.validate", "schema object is missing"))?;
    let observed = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
    if observed != expected.iter().copied().collect::<BTreeSet<_>>() {
        return Err(bundle_invalid(
            "a2ui.validate",
            "closed schema object contains missing or additional properties",
        ));
    }
    Ok(())
}

fn projection_checksums(root: &Path) -> Result<ProjectionChecksums, A2uiFailure> {
    let mut paths = Vec::new();
    collect_files(root, root, &mut paths, "a2ui.generate")?;
    paths.sort();
    let mut files = Vec::new();
    for path in paths {
        let relative = path
            .strip_prefix(root)
            .map_err(|_| invalid("a2ui.generate", "projection checksum path escaped"))?
            .to_string_lossy()
            .replace('\\', "/");
        if relative == "projection-checksums.json" {
            continue;
        }
        files.push(ChecksumEntry {
            path: relative,
            sha256: sha256_file(&path)
                .map_err(|error| bundle_invalid("a2ui.generate", error.to_string()))?,
        });
    }
    Ok(ProjectionChecksums {
        schema_version: "gtkg.projection-checksums/v1".to_owned(),
        scope: "projection_only".to_owned(),
        files,
    })
}

struct ProjectionGuard {
    file: File,
}

impl ProjectionGuard {
    fn acquire(
        context: &CallContext,
        workspace: &Path,
        projection_version: &str,
    ) -> Result<Self, A2uiFailure> {
        let version_identity = canonical_json_sha256(&json!({
            "schema_version": "gtkg.a2ui-projection-version-lock/v1",
            "projection_version": projection_version,
        }))
        .map_err(|error| invalid("a2ui.generate", error.to_string()))?;
        let directory = authorize_write(
            context,
            &workspace.join(".gtkg/locks/a2ui"),
            "a2ui.generate",
        )?;
        fs::create_dir_all(&directory).map_err(|error| io("a2ui.generate", &directory, error))?;
        let path = authorize_write(
            context,
            &directory.join(format!("version-{}.lock", &version_identity[7..39])),
            "a2ui.generate",
        )?;
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(|error| io("a2ui.generate", &path, error))?;
        let path_metadata =
            fs::symlink_metadata(&path).map_err(|error| io("a2ui.generate", &path, error))?;
        let file_metadata = file
            .metadata()
            .map_err(|error| io("a2ui.generate", &path, error))?;
        if path_metadata.file_type().is_symlink() || !file_metadata.is_file() {
            return Err(failure(
                ErrorCode::SymlinkRejected,
                "a2ui.generate",
                "projection writer lock is not a private regular file",
                "replace the lock path with a private regular inode",
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if path_metadata.nlink() > 1
                || path_metadata.dev() != file_metadata.dev()
                || path_metadata.ino() != file_metadata.ino()
            {
                return Err(failure(
                    ErrorCode::SymlinkRejected,
                    "a2ui.generate",
                    "projection writer lock identity drifted or is hardlinked",
                    "replace the lock path with a private regular inode",
                ));
            }
        }
        file.lock()
            .map_err(|error| io("a2ui.generate", &path, error))?;
        Ok(Self { file })
    }
}

impl Drop for ProjectionGuard {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

fn publish_projection_version(
    context: &CallContext,
    staging: &Path,
    versions: &Path,
    version: &str,
    digest: &str,
) -> Result<(PathBuf, bool), A2uiFailure> {
    let prefix = format!("v{version}--");
    let expected_name = format!("{prefix}{}", &digest[7..19]);
    let target = authorize_write(context, &versions.join(&expected_name), "a2ui.generate")?;
    for entry in fs::read_dir(versions).map_err(|error| io("a2ui.generate", versions, error))? {
        let entry = entry.map_err(|error| io("a2ui.generate", versions, error))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with(&prefix) {
            let metadata = fs::symlink_metadata(entry.path())
                .map_err(|error| io("a2ui.generate", &entry.path(), error))?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(bundle_invalid(
                    "a2ui.generate",
                    "projection version namespace contains an unsafe entry",
                ));
            }
            if name != expected_name {
                return Err(failure(
                    ErrorCode::VersionImmutable,
                    "a2ui.generate",
                    "projection version is already bound to different bytes",
                    "choose a new immutable projection version",
                ));
            }
            verify_projection(&entry.path(), digest)?;
            remove_staging(staging)?;
            return Ok((entry.path(), true));
        }
    }
    match crate::durable::rename_no_replace(staging, &target) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            verify_projection(&target, digest)?;
            remove_staging(staging)?;
            return Ok((target, true));
        }
        Err(error) => return Err(io("a2ui.generate", &target, error)),
    }
    sync_directory(versions, "a2ui.generate")?;
    Ok((target, false))
}

fn prepare_projection_staging(
    context: &CallContext,
    workspace: &Path,
    path: &Path,
    identity: &str,
) -> Result<bool, A2uiFailure> {
    let path = authorize_write(context, path, "a2ui.generate")?;
    let recovered = path.exists();
    if path.exists() {
        quarantine_projection_staging(context, workspace, &path, identity)?;
    }
    fs::create_dir_all(&path).map_err(|error| io("a2ui.generate", &path, error))?;
    Ok(recovered)
}

fn quarantine_projection_staging(
    context: &CallContext,
    workspace: &Path,
    staging: &Path,
    identity: &str,
) -> Result<(), A2uiFailure> {
    let metadata =
        fs::symlink_metadata(staging).map_err(|error| io("a2ui.generate", staging, error))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(bundle_invalid(
            "a2ui.generate",
            "projection staging residue is not a private directory",
        ));
    }
    let mut files = Vec::new();
    collect_files(staging, staging, &mut files, "a2ui.generate")?;
    let digest =
        tree_sha256(staging).map_err(|error| bundle_invalid("a2ui.generate", error.to_string()))?;
    let quarantine = authorize_write(
        context,
        &workspace.join(".gtkg/quarantine/a2ui"),
        "a2ui.generate",
    )?;
    fs::create_dir_all(&quarantine).map_err(|error| io("a2ui.generate", &quarantine, error))?;
    let destination = authorize_write(
        context,
        &quarantine.join(format!("staging-{}-{}", &identity[7..23], &digest[7..23])),
        "a2ui.generate",
    )?;
    match crate::durable::rename_no_replace(staging, &destination) {
        Ok(()) => sync_directory(&quarantine, "a2ui.generate"),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let existing = tree_sha256(&destination)
                .map_err(|error| bundle_invalid("a2ui.generate", error.to_string()))?;
            if existing != digest {
                return Err(failure(
                    ErrorCode::NonDeterministicResult,
                    "a2ui.generate",
                    "projection quarantine identity collided with different bytes",
                    "inspect the conflicting crash residue before retrying",
                ));
            }
            remove_staging(staging)
        }
        Err(error) => Err(io("a2ui.generate", &destination, error)),
    }
}

fn sync_projection_tree(root: &Path) -> Result<(), A2uiFailure> {
    let mut files = Vec::new();
    collect_files(root, root, &mut files, "a2ui.generate")?;
    for path in files {
        File::open(&path)
            .and_then(|file| file.sync_all())
            .map_err(|error| io("a2ui.generate", &path, error))?;
    }
    let mut directories = walkdir::WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| io("a2ui.generate", root, error.into()))?;
    directories.retain(|entry| entry.file_type().is_dir());
    directories.sort_by_key(|entry| std::cmp::Reverse(entry.depth()));
    for directory in directories {
        crate::durable::sync_directory(directory.path())
            .map_err(|error| durable_failure("a2ui.generate", error))?;
    }
    Ok(())
}

fn remove_staging(path: &Path) -> Result<(), A2uiFailure> {
    let metadata = fs::symlink_metadata(path).map_err(|error| io("a2ui.generate", path, error))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(bundle_invalid(
            "a2ui.generate",
            "projection staging is not a regular directory",
        ));
    }
    fs::remove_dir_all(path).map_err(|error| io("a2ui.generate", path, error))
}

fn verify_catalog_file(
    context: &CallContext,
    root: &Path,
    entry: &CatalogIdentity,
) -> Result<PathBuf, A2uiFailure> {
    let file = CatalogFile {
        path: entry.path.clone(),
        sha256: entry.sha256.clone(),
    };
    verify_plain_catalog_file(context, root, &file)
}

fn verify_plain_catalog_file(
    context: &CallContext,
    root: &Path,
    entry: &CatalogFile,
) -> Result<PathBuf, A2uiFailure> {
    validate_relative_path("catalog file path", &entry.path)?;
    validate_sha256(&entry.sha256).map_err(|error| invalid("a2ui.catalog", error.to_string()))?;
    let path = authorize_read(context, &root.join(&entry.path), "a2ui.catalog")?;
    if !path.starts_with(root) {
        return Err(failure(
            ErrorCode::PathEscape,
            "a2ui.catalog",
            "catalog file escaped the exact local catalog root",
            "use only ordinary files below catalog_root",
        ));
    }
    verify_file_digest(&path, &entry.sha256, "a2ui.catalog")?;
    Ok(path)
}

fn verify_file_digest(path: &Path, expected: &str, stage: &'static str) -> Result<(), A2uiFailure> {
    validate_sha256(expected).map_err(|error| invalid(stage, error.to_string()))?;
    let before = sha256_file(path).map_err(|error| bundle_invalid(stage, error.to_string()))?;
    if before != expected {
        return Err(lock(
            stage,
            format!("digest mismatch for {}", path.display()),
        ));
    }
    let after = sha256_file(path).map_err(|error| bundle_invalid(stage, error.to_string()))?;
    if after != before {
        return Err(lock(stage, "file changed while it was being validated"));
    }
    Ok(())
}

fn verify_tree_digest(path: &Path, expected: &str, stage: &'static str) -> Result<(), A2uiFailure> {
    validate_sha256(expected).map_err(|error| invalid(stage, error.to_string()))?;
    let before = tree_sha256(path).map_err(|error| bundle_invalid(stage, error.to_string()))?;
    if before != expected {
        return Err(lock(
            stage,
            format!("tree digest mismatch for {}", path.display()),
        ));
    }
    let after = tree_sha256(path).map_err(|error| bundle_invalid(stage, error.to_string()))?;
    if after != before {
        return Err(lock(stage, "tree changed while it was being validated"));
    }
    Ok(())
}

fn read_stream(path: &Path, stage: &'static str) -> Result<Vec<Value>, A2uiFailure> {
    let source = fs::read_to_string(path).map_err(|error| io(stage, path, error))?;
    source
        .lines()
        .map(|line| {
            serde_json::from_str(line)
                .map_err(|error| bundle_invalid(stage, format!("invalid JSONL: {error}")))
        })
        .collect()
}

fn read_json<T>(path: &Path, stage: &'static str) -> Result<T, A2uiFailure>
where
    T: for<'de> Deserialize<'de>,
{
    let bytes = fs::read(path).map_err(|error| io(stage, path, error))?;
    serde_json::from_slice(&bytes)
        .map_err(|error| bundle_invalid(stage, format!("invalid JSON {}: {error}", path.display())))
}

fn write_json_file<T>(
    context: &CallContext,
    path: &Path,
    value: &T,
    stage: &'static str,
) -> Result<(), A2uiFailure>
where
    T: Serialize,
{
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| invalid(stage, format!("JSON serialization failed: {error}")))?;
    write_text_file(context, path, &bytes, stage)
}

fn write_jsonl_file(
    context: &CallContext,
    path: &Path,
    values: &[Value],
    stage: &'static str,
) -> Result<(), A2uiFailure> {
    let mut bytes = Vec::new();
    for value in values {
        serde_json::to_writer(&mut bytes, value)
            .map_err(|error| invalid(stage, format!("JSONL serialization failed: {error}")))?;
        bytes.push(b'\n');
    }
    write_text_file(context, path, &bytes, stage)
}

fn write_text_file(
    context: &CallContext,
    path: &Path,
    bytes: &[u8],
    stage: &'static str,
) -> Result<(), A2uiFailure> {
    let parent = path
        .parent()
        .ok_or_else(|| invalid(stage, "output path has no parent"))?;
    let parent = authorize_write(context, parent, stage)?;
    fs::create_dir_all(&parent).map_err(|error| io(stage, &parent, error))?;
    let path = authorize_write(context, path, stage)?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|error| io(stage, &path, error))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| io(stage, &path, error))?;
    Ok(())
}

fn collect_files(
    root: &Path,
    directory: &Path,
    files: &mut Vec<PathBuf>,
    stage: &'static str,
) -> Result<(), A2uiFailure> {
    let metadata = fs::symlink_metadata(directory).map_err(|error| io(stage, directory, error))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(bundle_invalid(stage, "directory tree contains a symlink"));
    }
    for entry in fs::read_dir(directory).map_err(|error| io(stage, directory, error))? {
        let entry = entry.map_err(|error| io(stage, directory, error))?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(|error| io(stage, &path, error))?;
        if metadata.file_type().is_symlink() {
            return Err(bundle_invalid(stage, "file tree contains a symlink"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.is_file() && metadata.nlink() > 1 {
                return Err(bundle_invalid(stage, "file tree contains a hardlink"));
            }
        }
        if metadata.is_dir() {
            collect_files(root, &path, files, stage)?;
        } else if metadata.is_file() {
            if !path.starts_with(root) {
                return Err(bundle_invalid(stage, "file tree escaped its root"));
            }
            files.push(path);
        } else {
            return Err(bundle_invalid(stage, "file tree contains a special file"));
        }
    }
    Ok(())
}

fn receipt_reference(
    workspace: &Path,
    path: &Path,
    stage: &'static str,
) -> Result<FileReceiptRef, A2uiFailure> {
    let relative = path
        .strip_prefix(workspace)
        .map_err(|_| invalid(stage, "receipt was written outside workspace"))?
        .to_string_lossy()
        .replace('\\', "/");
    Ok(FileReceiptRef {
        path: relative,
        sha256: sha256_file(path).map_err(|error| bundle_invalid(stage, error.to_string()))?,
    })
}

fn validate_exact_version(kind: &str, value: &str) -> Result<(), A2uiFailure> {
    let lower = value.to_ascii_lowercase();
    if value.is_empty()
        || matches!(lower.as_str(), "current" | "latest" | "head" | "main")
        || value.contains('/')
        || value.contains('\\')
        || value.contains("..")
        || value.contains("://")
    {
        return Err(invalid(
            "a2ui.identity",
            format!("{kind} must be an exact non-floating local version"),
        ));
    }
    Ok(())
}

fn validate_local_identifier(kind: &str, value: &str) -> Result<(), A2uiFailure> {
    if value.is_empty()
        || value == "."
        || value == ".."
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        || value.to_ascii_lowercase().contains("javascript")
    {
        return Err(invalid(
            "a2ui.identity",
            format!("{kind} is not a safe local identifier"),
        ));
    }
    Ok(())
}

fn validate_relative_path(kind: &str, value: &str) -> Result<(), A2uiFailure> {
    let path = Path::new(value);
    if value.is_empty()
        || path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::CurDir | Component::Prefix(_)
            )
        })
        || value.contains("\\")
    {
        return Err(failure(
            ErrorCode::PathEscape,
            "a2ui.path",
            format!("{kind} is not a safe relative path"),
            "use normalized forward-slash paths below the authorized root",
        ));
    }
    Ok(())
}

fn parse_payload<T>(request: &OperationRequest, stage: &'static str) -> Result<T, A2uiFailure>
where
    T: for<'de> Deserialize<'de>,
{
    serde_json::from_value(request.payload.clone())
        .map_err(|error| invalid(stage, format!("invalid operation payload: {error}")))
}

fn authorize_read(
    context: &CallContext,
    path: &Path,
    stage: &'static str,
) -> Result<PathBuf, A2uiFailure> {
    context
        .authorize_read(path)
        .map_err(|error| context_failure(stage, error))
}

fn authorize_write(
    context: &CallContext,
    path: &Path,
    stage: &'static str,
) -> Result<PathBuf, A2uiFailure> {
    context
        .authorize_write(path)
        .map_err(|error| context_failure(stage, error))
}

fn sync_directory(path: &Path, stage: &'static str) -> Result<(), A2uiFailure> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| io(stage, path, error))
}

fn context_failure(stage: &'static str, error: ContextError) -> A2uiFailure {
    failure(
        ErrorCode::PathEscape,
        stage,
        error.to_string(),
        "use only canonical ordinary files within the CallContext authorized roots",
    )
}

fn durable_failure(stage: &'static str, error: DurableWriteError) -> A2uiFailure {
    let code = match error.kind {
        DurableErrorKind::Invalid => ErrorCode::InvalidRequest,
        DurableErrorKind::Unauthorized | DurableErrorKind::Unsafe => ErrorCode::PathEscape,
        DurableErrorKind::Conflict => ErrorCode::LockMismatch,
        DurableErrorKind::Io => ErrorCode::Io,
    };
    failure(
        code,
        stage,
        error.to_string(),
        "inspect the exact receipt path and retry with unchanged locked inputs",
    )
}

fn invalid(stage: &'static str, message: impl Into<String>) -> A2uiFailure {
    failure(
        ErrorCode::InvalidRequest,
        stage,
        message,
        "use the exact closed D05 operation payload and local immutable identities",
    )
}

fn lock(stage: &'static str, message: impl Into<String>) -> A2uiFailure {
    failure(
        ErrorCode::LockMismatch,
        stage,
        message,
        "resolve or generate again from the unchanged caller-held full digest",
    )
}

fn bundle_invalid(stage: &'static str, message: impl Into<String>) -> A2uiFailure {
    failure(
        ErrorCode::BundleInvalid,
        stage,
        message,
        "discard the derived projection and regenerate from the verified canonical source",
    )
}

fn io(stage: &'static str, path: &Path, error: std::io::Error) -> A2uiFailure {
    failure(
        ErrorCode::Io,
        stage,
        format!("{}: {error}", path.display()),
        "inspect the authorized local file and retry",
    )
}

fn failure(
    code: ErrorCode,
    stage: &'static str,
    message: impl Into<String>,
    recovery_hint: &'static str,
) -> A2uiFailure {
    A2uiFailure {
        code,
        stage,
        message: message.into(),
        recovery_hint,
    }
}

const WIKI_HTML: &str = r#"<!doctype html>
<html lang="en" data-theme="light">
<head>
  <meta charset="utf-8">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'">
  <meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
  <title>GTKG Knowledge</title>
  <link rel="stylesheet" href="./assets/wiki.css">
</head>
<body>
  <div class="app-frame">
    <header class="titlebar" data-region="titlebar">
      <div class="traffic-lights" aria-hidden="true"><span></span><span></span><span></span></div>
      <button id="toggle-left" class="icon-button sidebar-toggle" type="button" aria-label="Toggle knowledge sidebar" aria-expanded="true" title="Toggle knowledge sidebar">
        <svg viewBox="0 0 20 20" aria-hidden="true"><rect x="2.5" y="3" width="15" height="14" rx="2.5"></rect><path d="M7 3v14"></path></svg>
      </button>
      <div class="workspace-identity" aria-label="GTKG Knowledge workspace">
        <span class="workspace-mark">G</span><span class="workspace-name">GTKG</span><span class="workspace-divider">/</span><span class="workspace-view">Knowledge</span>
      </div>
      <div class="titlebar-spacer"></div>
      <span class="offline-pill"><span></span>Local</span>
      <button id="theme-toggle" class="icon-button" type="button" aria-label="Toggle color theme" title="Toggle color theme">
        <svg viewBox="0 0 20 20" aria-hidden="true"><path d="M10 2.5v2M10 15.5v2M2.5 10h2M15.5 10h2M4.7 4.7l1.4 1.4M13.9 13.9l1.4 1.4M15.3 4.7l-1.4 1.4M6.1 13.9l-1.4 1.4"></path><circle cx="10" cy="10" r="3.3"></circle></svg>
      </button>
      <button id="toggle-right" class="icon-button" type="button" aria-label="Toggle context panel" aria-expanded="true" title="Toggle context panel">
        <svg viewBox="0 0 20 20" aria-hidden="true"><rect x="2.5" y="3" width="15" height="14" rx="2.5"></rect><path d="M13 3v14"></path></svg>
      </button>
    </header>

    <main id="wiki-shell" class="wiki-shell" data-left-collapsed="false" data-right-collapsed="false">
      <aside class="knowledge-sidebar" data-region="left-index" aria-label="Knowledge index">
        <div class="sidebar-toolbar">
          <div class="search-field" role="search">
            <svg viewBox="0 0 20 20" aria-hidden="true"><circle cx="8.7" cy="8.7" r="4.8"></circle><path d="m12.3 12.3 4 4"></path></svg>
            <input id="knowledge-search" type="search" autocomplete="off" spellcheck="false" placeholder="Search knowledge" aria-label="Search knowledge">
            <kbd>⌘K</kbd>
          </div>
        </div>
        <div class="sidebar-section-heading"><span>Knowledge base</span><span id="root-count" class="count-badge"></span></div>
        <nav id="selected-nav" class="knowledge-list" aria-label="Knowledge documents"></nav>
        <div id="search-empty" class="search-empty" hidden>No matching documents</div>
        <div class="sidebar-footer">
          <div class="shard-controls" aria-label="Progressive loading controls">
            <button id="load-first-shard" class="secondary-button" type="button" aria-label="Load first shard"><span>First shard</span><kbd>⌥↑</kbd></button>
            <button id="load-last-shard" class="secondary-button" type="button" aria-label="Load last shard"><span>Last shard</span><kbd>⌥↓</kbd></button>
          </div>
          <p id="shard-status" class="shard-status">Initial document</p>
        </div>
      </aside>

      <div id="left-splitter" class="splitter" data-splitter="left" role="separator" tabindex="0" aria-label="Resize knowledge sidebar" aria-orientation="vertical" aria-valuemin="220" aria-valuemax="420" aria-valuenow="268"></div>

      <article class="document-workspace" data-region="right-content" aria-live="polite" aria-busy="false">
        <header class="document-toolbar">
          <button id="mobile-menu" class="icon-button" type="button" aria-label="Open knowledge sidebar" aria-expanded="false">
            <svg viewBox="0 0 20 20" aria-hidden="true"><path d="M3 5.5h14M3 10h14M3 14.5h14"></path></svg>
          </button>
          <div class="breadcrumb"><span>Knowledge</span><span>/</span><strong id="selected-path">Document</strong></div>
          <div class="document-toolbar-spacer"></div>
          <span class="readonly-pill">Read only</span>
        </header>
        <div class="document-scroll">
          <div class="document-container">
            <div class="document-kicker"><span class="file-glyph">MD</span><span>Knowledge document</span></div>
            <h1 id="selected-title"></h1>
            <div class="document-meta"><span>Local bundle</span><span aria-hidden="true">·</span><span id="document-location">Offline</span></div>
            <pre id="selected-content" tabindex="0"></pre>
          </div>
        </div>
      </article>

      <div id="right-splitter" class="splitter" data-splitter="right" role="separator" tabindex="0" aria-label="Resize context panel" aria-orientation="vertical" aria-valuemin="260" aria-valuemax="480" aria-valuenow="320"></div>

      <aside class="context-panel" data-region="context-panel" aria-label="Document context">
        <div class="context-header"><h2>Context</h2><span class="verified-badge">Verified</span></div>
        <section class="context-section">
          <h3>Document</h3>
          <dl>
            <div><dt>Path</dt><dd id="context-path">—</dd></div>
            <div><dt>Resource ID</dt><dd id="context-id">—</dd></div>
            <div><dt>Mode</dt><dd>Progressive</dd></div>
          </dl>
        </section>
        <section class="context-section">
          <h3>Evidence</h3>
          <div class="evidence-row"><span class="status-dot"></span><span>Bundle verified</span></div>
          <div class="evidence-row"><span class="status-dot"></span><span>Target execution: 0</span></div>
          <div class="evidence-row"><span class="status-dot"></span><span>Remote requests: 0</span></div>
        </section>
        <section class="context-section shortcuts">
          <h3>Shortcuts</h3>
          <p><span>Search</span><kbd>⌘K</kbd></p>
          <p><span>Toggle sidebar</span><kbd>⌘B</kbd></p>
          <p><span>Close drawer</span><kbd>Esc</kbd></p>
        </section>
      </aside>
      <button id="mobile-scrim" class="mobile-scrim" type="button" aria-label="Close knowledge sidebar" hidden></button>
    </main>

    <footer class="statusbar" data-region="statusbar">
      <div class="status-left"><span class="status-dot"></span><span>Offline knowledge</span></div>
      <div class="status-spacer"></div>
      <section class="state" data-ui-state="normal">Ready</section>
      <section class="state" data-ui-state="loading" hidden>Loading</section>
      <section class="state" data-ui-state="empty" hidden>Empty</section>
      <section class="state" data-ui-state="error" hidden>Error</section>
      <section class="state" data-ui-state="permission" hidden>Permission required</section>
      <section class="state" data-ui-state="disabled" hidden>Disabled</section>
    </footer>
  </div>
  <script src="./bootstrap/root.js"></script>
  <script src="./bootstrap/selected.js"></script>
  <script src="./assets/wiki.js"></script>
</body>
</html>
"#;

const WIKI_CSS: &str = r#":root{
  color-scheme:light;
  font:13px/1.45 -apple-system,BlinkMacSystemFont,"SF Pro Text","Segoe UI",sans-serif;
  --titlebar-height:44px;--statusbar-height:28px;--left-width:268px;--right-width:320px;--splitter-width:5px;
  --bg-app:#f7f7f5;--bg-sidebar:#f1f1ef;--bg-panel:#f8f8f6;--bg-content:#fff;--bg-elevated:#fff;
  --bg-hover:rgba(30,30,28,.055);--bg-active:#e5e5e1;--bg-button:#20201e;--bg-input:rgba(255,255,255,.72);
  --text-primary:#242421;--text-secondary:#74746f;--text-tertiary:#989892;--text-on-dark:#fff;
  --border-subtle:rgba(30,30,28,.09);--border-strong:rgba(30,30,28,.16);--focus:#6f6f69;
  --shadow-panel:0 12px 34px rgba(20,20,18,.12);--radius-sm:6px;--radius-md:9px;--radius-lg:13px;
  background:var(--bg-app);color:var(--text-primary)
}
:root[data-theme="dark"]{
  color-scheme:dark;--bg-app:#1d1d1b;--bg-sidebar:#242422;--bg-panel:#20201e;--bg-content:#191918;--bg-elevated:#292927;
  --bg-hover:rgba(255,255,255,.055);--bg-active:#343432;--bg-button:#ecece8;--bg-input:rgba(255,255,255,.055);
  --text-primary:#ecece8;--text-secondary:#aaa9a3;--text-tertiary:#7f7e79;--text-on-dark:#20201e;
  --border-subtle:rgba(255,255,255,.085);--border-strong:rgba(255,255,255,.16);--focus:#b7b7b0;--shadow-panel:0 14px 40px rgba(0,0,0,.34)
}
*{box-sizing:border-box}
html,body{height:100%;overflow:hidden}
body{margin:0;background:var(--bg-app);color:var(--text-primary);-webkit-font-smoothing:antialiased}
button,input{font:inherit;color:inherit}
button{border:0}
button:focus-visible,input:focus-visible,[tabindex]:focus-visible{outline:2px solid var(--focus);outline-offset:2px}
svg{width:18px;height:18px;fill:none;stroke:currentColor;stroke-width:1.45;stroke-linecap:round;stroke-linejoin:round}
kbd{font:10px/1.4 ui-monospace,SFMono-Regular,Menlo,monospace;color:var(--text-tertiary);background:var(--bg-hover);border:1px solid var(--border-subtle);border-radius:4px;padding:0 4px;box-shadow:0 1px 0 var(--border-subtle)}
.app-frame{display:grid;grid-template-rows:var(--titlebar-height) minmax(0,1fr) var(--statusbar-height);height:100dvh;min-width:0;background:var(--bg-app)}
.titlebar{display:flex;align-items:center;gap:7px;padding:0 10px;border-bottom:1px solid var(--border-subtle);background:color-mix(in srgb,var(--bg-app) 92%,transparent);user-select:none;z-index:40}
.traffic-lights{display:flex;gap:7px;margin:0 9px 0 2px}.traffic-lights span{width:11px;height:11px;border-radius:50%;background:#d9d9d5}.traffic-lights span:first-child{background:#ff5f57}.traffic-lights span:nth-child(2){background:#febc2e}.traffic-lights span:last-child{background:#28c840}
.icon-button{display:grid;place-items:center;width:30px;height:30px;border-radius:var(--radius-sm);background:transparent;cursor:pointer;color:var(--text-secondary)}
.icon-button:hover{background:var(--bg-hover);color:var(--text-primary)}
.workspace-identity{display:flex;align-items:center;gap:7px;min-width:0;font-weight:600}.workspace-mark{display:grid;place-items:center;width:22px;height:22px;border-radius:6px;background:var(--bg-button);color:var(--text-on-dark);font-size:11px;font-weight:750}.workspace-name{letter-spacing:-.01em}.workspace-divider{color:var(--text-tertiary);font-weight:400}.workspace-view{color:var(--text-secondary);font-weight:500;white-space:nowrap}.titlebar-spacer,.document-toolbar-spacer,.status-spacer{flex:1}.offline-pill,.readonly-pill,.verified-badge{display:inline-flex;align-items:center;gap:6px;height:22px;padding:0 8px;border:1px solid var(--border-subtle);border-radius:999px;color:var(--text-secondary);background:var(--bg-input);font-size:11px}.offline-pill span,.status-dot{width:6px;height:6px;border-radius:50%;background:#32a852;box-shadow:0 0 0 2px color-mix(in srgb,#32a852 18%,transparent)}
.wiki-shell{display:grid;grid-template-columns:var(--left-width) var(--splitter-width) minmax(0,1fr) var(--splitter-width) var(--right-width);min-height:0;min-width:0;position:relative;overflow:hidden}
.wiki-shell[data-left-collapsed="true"]{grid-template-columns:0 0 minmax(0,1fr) var(--splitter-width) var(--right-width)}
.wiki-shell[data-right-collapsed="true"]{grid-template-columns:var(--left-width) var(--splitter-width) minmax(0,1fr) 0 0}
.wiki-shell[data-left-collapsed="true"][data-right-collapsed="true"]{grid-template-columns:0 0 minmax(0,1fr) 0 0}
.knowledge-sidebar,.context-panel{min-width:0;min-height:0;overflow:hidden;background:var(--bg-sidebar)}
.knowledge-sidebar{display:flex;flex-direction:column;border-right:1px solid var(--border-subtle)}
.sidebar-toolbar{padding:12px 10px 8px}.search-field{display:flex;align-items:center;gap:7px;height:32px;padding:0 8px;border:1px solid var(--border-subtle);border-radius:var(--radius-md);background:var(--bg-input);box-shadow:0 1px 0 rgba(255,255,255,.35)}.search-field svg{width:15px;height:15px;color:var(--text-tertiary)}.search-field input{min-width:0;flex:1;border:0;outline:0;background:transparent;font-size:12px}.search-field input::placeholder{color:var(--text-tertiary)}
.sidebar-section-heading{display:flex;align-items:center;justify-content:space-between;padding:10px 14px 7px;color:var(--text-secondary);font-size:11px;font-weight:650;text-transform:uppercase;letter-spacing:.055em}.count-badge{min-width:20px;padding:1px 5px;border-radius:999px;background:var(--bg-hover);text-align:center;font-size:10px;letter-spacing:0}
.knowledge-list{flex:1;min-height:0;overflow:auto;padding:0 8px 10px;scrollbar-width:thin}.knowledge-item{display:grid;grid-template-columns:26px minmax(0,1fr);align-items:center;width:100%;min-height:38px;padding:5px 7px;margin:1px 0;border-radius:7px;background:transparent;text-align:left;cursor:pointer;color:var(--text-secondary)}.knowledge-item:hover{background:var(--bg-hover);color:var(--text-primary)}.knowledge-item[aria-current="page"]{background:var(--bg-active);color:var(--text-primary)}.knowledge-icon{display:grid;place-items:center;width:22px;height:22px;border:1px solid var(--border-subtle);border-radius:5px;background:var(--bg-elevated);font:600 8px/1 ui-monospace,SFMono-Regular,Menlo,monospace;color:var(--text-tertiary)}.knowledge-label{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.search-empty{margin:10px 14px;color:var(--text-tertiary);font-size:12px}.sidebar-footer{padding:9px 10px 10px;border-top:1px solid var(--border-subtle)}.shard-controls{display:grid;grid-template-columns:1fr 1fr;gap:6px}.secondary-button{display:flex;align-items:center;justify-content:space-between;gap:5px;min-width:0;height:30px;padding:0 8px;border:1px solid var(--border-subtle);border-radius:7px;background:var(--bg-input);cursor:pointer;font-size:11px}.secondary-button:hover{background:var(--bg-hover)}.shard-status{margin:8px 2px 0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--text-tertiary);font-size:10px}
.splitter{position:relative;z-index:8;background:var(--bg-panel);cursor:col-resize;touch-action:none}.splitter::after{content:"";position:absolute;inset:0 1px;background:transparent}.splitter:hover::after,.splitter:focus-visible::after,.wiki-shell[data-resizing="true"] .splitter::after{background:var(--border-strong)}
.document-workspace{display:flex;flex-direction:column;min-width:0;min-height:0;background:var(--bg-content);overflow:hidden}
.document-toolbar{display:flex;align-items:center;gap:8px;min-height:42px;padding:0 14px;border-bottom:1px solid var(--border-subtle);background:color-mix(in srgb,var(--bg-content) 94%,transparent)}#mobile-menu{display:none}.breadcrumb{display:flex;align-items:center;gap:7px;min-width:0;color:var(--text-tertiary);font-size:11px}.breadcrumb strong{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--text-secondary);font-weight:500}.document-scroll{min-height:0;overflow:auto;scrollbar-width:thin}.document-container{width:min(100%,860px);margin:0 auto;padding:48px 52px 96px}.document-kicker{display:flex;align-items:center;gap:8px;margin-bottom:14px;color:var(--text-tertiary);font-size:11px;text-transform:uppercase;letter-spacing:.045em}.file-glyph{display:grid;place-items:center;width:25px;height:25px;border:1px solid var(--border-subtle);border-radius:6px;background:var(--bg-panel);font:650 8px/1 ui-monospace,SFMono-Regular,Menlo,monospace}.document-container h1{margin:0;max-width:760px;font-size:28px;line-height:1.17;letter-spacing:-.025em;font-weight:680;overflow-wrap:anywhere}.document-meta{display:flex;gap:7px;align-items:center;margin:12px 0 32px;color:var(--text-tertiary);font-size:11px}.document-container pre{margin:0;padding:0;border:0;background:transparent;color:var(--text-primary);white-space:pre-wrap;word-break:break-word;overflow-wrap:anywhere;font:13px/1.68 ui-monospace,SFMono-Regular,Menlo,Monaco,"Cascadia Code",monospace;tab-size:2}
.context-panel{border-left:1px solid var(--border-subtle);background:var(--bg-panel);overflow:auto}.context-header{display:flex;align-items:center;justify-content:space-between;min-height:42px;padding:0 14px;border-bottom:1px solid var(--border-subtle)}.context-header h2{margin:0;font-size:12px;font-weight:650}.verified-badge{height:20px;color:#228342;border-color:color-mix(in srgb,#32a852 25%,transparent);background:color-mix(in srgb,#32a852 8%,transparent)}.context-section{padding:16px 14px;border-bottom:1px solid var(--border-subtle)}.context-section h3{margin:0 0 11px;color:var(--text-secondary);font-size:10px;text-transform:uppercase;letter-spacing:.06em}.context-section dl{margin:0}.context-section dl div{display:grid;grid-template-columns:72px minmax(0,1fr);gap:10px;padding:5px 0}.context-section dt{color:var(--text-tertiary)}.context-section dd{margin:0;overflow-wrap:anywhere;color:var(--text-secondary);font:11px/1.45 ui-monospace,SFMono-Regular,Menlo,monospace}.evidence-row{display:flex;align-items:center;gap:8px;padding:5px 0;color:var(--text-secondary);font-size:11px}.shortcuts p{display:flex;align-items:center;justify-content:space-between;margin:7px 0;color:var(--text-secondary);font-size:11px}
.statusbar{display:flex;align-items:center;gap:8px;padding:0 10px;border-top:1px solid var(--border-subtle);background:var(--bg-app);color:var(--text-tertiary);font-size:10px;user-select:none}.status-left{display:flex;align-items:center;gap:7px}.state{padding:1px 7px;border-radius:5px;background:var(--bg-hover);color:var(--text-secondary)}.state[hidden]{display:none}.mobile-scrim{display:none}
button:disabled,input:disabled{cursor:not-allowed;opacity:.45}
@media (max-width:980px){:root{--right-width:280px}.document-container{padding-left:36px;padding-right:36px}}
@media (max-width:820px){.wiki-shell,.wiki-shell[data-right-collapsed="false"]{grid-template-columns:var(--left-width) var(--splitter-width) minmax(0,1fr) 0 0}.context-panel,#right-splitter{display:none}.titlebar #toggle-right{display:none}}
@media (max-width:720px){
  :root{--titlebar-height:42px;--statusbar-height:26px;--left-width:min(86vw,330px)}
  .traffic-lights,.titlebar .sidebar-toggle,.workspace-divider,.workspace-view,.offline-pill{display:none}
  .titlebar{padding:0 8px}.workspace-identity{margin-left:2px}.wiki-shell,.wiki-shell[data-left-collapsed="true"],.wiki-shell[data-left-collapsed="false"],.wiki-shell[data-right-collapsed="true"]{display:block;position:relative;overflow:hidden}
  .knowledge-sidebar{position:fixed;z-index:35;top:var(--titlebar-height);bottom:var(--statusbar-height);left:0;width:var(--left-width);box-shadow:var(--shadow-panel);transform:translateX(-103%);transition:transform 160ms ease}.wiki-shell[data-left-collapsed="false"] .knowledge-sidebar{transform:translateX(0)}
  .splitter,.context-panel{display:none!important}.document-workspace{height:100%}#mobile-menu{display:grid}.document-toolbar{padding:0 9px}.readonly-pill{display:none}.breadcrumb{max-width:calc(100vw - 62px)}.document-container{padding:28px 18px 72px}.document-container h1{font-size:23px}.document-meta{margin-bottom:24px}.document-container pre{font-size:12px;line-height:1.62}
  .mobile-scrim{display:block;position:fixed;z-index:30;inset:var(--titlebar-height) 0 var(--statusbar-height);width:100%;height:auto;background:rgba(0,0,0,.24);backdrop-filter:blur(1px)}.mobile-scrim[hidden]{display:none}.status-left{display:none}
}
@media (prefers-reduced-motion:reduce){*{scroll-behavior:auto!important;transition:none!important}}
"#;

const WIKI_JS: &str = r#"(() => {
  'use strict';
  const decodeTextHex = (hex) => {
    const bytes = new Uint8Array(hex.length / 2);
    for (let index = 0; index < bytes.length; index += 1) bytes[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
    return new TextDecoder().decode(bytes);
  };
  const decodeJsonHex = (hex) => JSON.parse(decodeTextHex(hex));
  const root = globalThis.__GTKG_ROOT__;
  const selected = decodeJsonHex(globalThis.__GTKG_SELECTED_HEX__);
  const shell = document.querySelector('#wiki-shell');
  const navigation = document.querySelector('#selected-nav');
  const search = document.querySelector('#knowledge-search');
  const scrim = document.querySelector('#mobile-scrim');
  const catalogShards = new Map();
  const contentShards = new Map();
  let currentSelected = selected;
  let currentEntries = [selected];
  let currentShardId = null;
  let pendingResourceId = null;
  let restoreFocus = null;
  globalThis.__GTKG_XSS_SENTINEL__ = false;
  const evidence = {
    ready: true, network_requests: 0, console_errors: 0, selected_id: selected.id,
    resource_count: root.resource_count, target_execution_count: 0, search_query: '',
    left_collapsed: false, right_collapsed: false, layout: 'codex_workspace'
  };
  globalThis.__GTKG_BROWSER_EVIDENCE__ = evidence;
  document.querySelector('#root-count').textContent = String(root.resource_count);

  const resourcePath = (resource) => resource.logical_path || resource.path || resource.id;
  const fileLabel = (path) => {
    const name = path.split('/').pop() || 'DOC';
    const extension = name.includes('.') ? name.split('.').pop() : 'DOC';
    return extension.slice(0, 4).toUpperCase();
  };
  const updateActiveNavigation = () => {
    navigation.querySelectorAll('.knowledge-item').forEach((button) => {
      if (button.dataset.resourceId === currentSelected.id) button.setAttribute('aria-current', 'page');
      else button.removeAttribute('aria-current');
    });
  };
  const renderSelected = (resource) => {
    if (!resource) return;
    currentSelected = resource;
    const path = resourcePath(resource);
    document.querySelector('#selected-title').textContent = resource.title;
    document.querySelector('#selected-content').textContent = decodeTextHex(resource.content);
    document.querySelector('#selected-path').textContent = path;
    document.querySelector('#document-location').textContent = path;
    document.querySelector('#context-path').textContent = path;
    document.querySelector('#context-id').textContent = resource.id;
    document.querySelector('.file-glyph').textContent = fileLabel(path);
    document.title = `${resource.title} — GTKG`;
    evidence.selected_id = resource.id;
    updateActiveNavigation();
  };
  const loadScript = (path) => {
    const script = document.createElement('script');
    script.src = path;
    script.addEventListener('error', () => globalThis.__GTKG_SHOW_STATE__('error'), {once: true});
    document.head.append(script);
  };
  const selectEntry = (entry, shardId) => {
    const resources = contentShards.get(shardId);
    if (resources) {
      renderSelected(resources.find((resource) => resource.id === entry.id));
      return;
    }
    pendingResourceId = entry.id;
    const shard = root.shards.find((candidate) => candidate.id === shardId);
    if (shard) loadScript(shard.content_path);
  };
  const renderNavigation = (entries, shardId) => {
    navigation.replaceChildren();
    const query = search.value.trim().toLocaleLowerCase();
    const visible = query ? entries.filter((entry) => `${entry.title} ${resourcePath(entry)}`.toLocaleLowerCase().includes(query)) : entries;
    document.querySelector('#search-empty').hidden = visible.length !== 0;
    for (const entry of visible) {
      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'knowledge-item';
      button.dataset.resourceId = entry.id;
      const icon = document.createElement('span');
      icon.className = 'knowledge-icon';
      icon.setAttribute('aria-hidden', 'true');
      icon.textContent = fileLabel(resourcePath(entry));
      const label = document.createElement('span');
      label.className = 'knowledge-label';
      label.textContent = entry.title;
      button.append(icon, label);
      button.addEventListener('click', () => selectEntry(entry, shardId));
      navigation.append(button);
    }
    updateActiveNavigation();
  };
  globalThis.__GTKG_REGISTER_SHARD__ = (id, hex) => {
    const entries = decodeJsonHex(hex);
    catalogShards.set(id, entries);
    currentEntries = entries;
    currentShardId = id;
    globalThis.__GTKG_LAST_SHARD__ = {id, count: entries.length};
    document.querySelector('#shard-status').textContent = `Shard ${id} · ${entries.length} documents`;
    renderNavigation(entries, id);
  };
  globalThis.__GTKG_REGISTER_CONTENT_SHARD__ = (id, hex) => {
    const resources = decodeJsonHex(hex);
    contentShards.set(id, resources);
    globalThis.__GTKG_LAST_CONTENT_SHARD__ = {id, count: resources.length};
    if (pendingResourceId) {
      const resource = resources.find((candidate) => candidate.id === pendingResourceId);
      pendingResourceId = null;
      if (resource) renderSelected(resource);
    }
  };

  const storage = {
    get: (key) => { try { return localStorage.getItem(key); } catch (_) { return null; } },
    set: (key, value) => { try { localStorage.setItem(key, value); } catch (_) {} }
  };
  const setCollapsed = (side, collapsed, persist = true) => {
    shell.dataset[`${side}Collapsed`] = String(collapsed);
    evidence[`${side}_collapsed`] = collapsed;
    const toggle = document.querySelector(side === 'left' ? '#toggle-left' : '#toggle-right');
    const panel = document.querySelector(side === 'left' ? '[data-region=left-index]' : '[data-region=context-panel]');
    panel.inert = collapsed;
    panel.setAttribute('aria-hidden', String(collapsed));
    toggle.setAttribute('aria-expanded', String(!collapsed));
    if (side === 'left') {
      const mobile = matchMedia('(max-width:720px)').matches;
      const isolateBackground = mobile && !collapsed;
      for (const selector of ['.titlebar', '.document-workspace', '.statusbar']) {
        const region = document.querySelector(selector);
        region.inert = isolateBackground;
        region.setAttribute('aria-hidden', String(isolateBackground));
      }
      document.querySelector('#mobile-menu').setAttribute('aria-expanded', String(!collapsed));
      scrim.hidden = collapsed || !mobile;
    }
    if (persist) storage.set(`gtkg-${side}-collapsed`, String(collapsed));
    if (!collapsed && side === 'left' && matchMedia('(max-width:720px)').matches) search.focus();
    if (collapsed && side === 'left' && restoreFocus) restoreFocus.focus();
  };
  const initialMobile = matchMedia('(max-width:720px)').matches;
  const contextHidden = matchMedia('(max-width:820px)').matches;
  setCollapsed('left', initialMobile || storage.get('gtkg-left-collapsed') === 'true', false);
  setCollapsed('right', contextHidden || storage.get('gtkg-right-collapsed') === 'true', false);
  document.querySelector('#toggle-left').addEventListener('click', () => setCollapsed('left', shell.dataset.leftCollapsed !== 'true'));
  document.querySelector('#toggle-right').addEventListener('click', () => setCollapsed('right', shell.dataset.rightCollapsed !== 'true'));
  document.querySelector('#mobile-menu').addEventListener('click', (event) => { restoreFocus = event.currentTarget; setCollapsed('left', false); });
  scrim.addEventListener('click', () => setCollapsed('left', true));

  const applyTheme = (theme) => {
    document.documentElement.dataset.theme = theme;
    storage.set('gtkg-theme', theme);
  };
  applyTheme(storage.get('gtkg-theme') || 'light');
  document.querySelector('#theme-toggle').addEventListener('click', () => applyTheme(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark'));

  const installSplitter = (element, side) => {
    const property = side === 'left' ? '--left-width' : '--right-width';
    const minimum = side === 'left' ? 220 : 260;
    const maximum = side === 'left' ? 420 : 480;
    const apply = (value) => {
      const width = Math.max(minimum, Math.min(maximum, Math.round(value)));
      document.documentElement.style.setProperty(property, `${width}px`);
      element.setAttribute('aria-valuenow', String(width));
      storage.set(`gtkg-${side}-width`, String(width));
    };
    const stored = Number(storage.get(`gtkg-${side}-width`));
    if (Number.isFinite(stored) && stored > 0) apply(stored);
    element.addEventListener('pointerdown', (event) => {
      event.preventDefault();
      const startX = event.clientX;
      const startWidth = Number.parseFloat(getComputedStyle(document.documentElement).getPropertyValue(property));
      shell.dataset.resizing = 'true';
      document.body.style.userSelect = 'none';
      element.setPointerCapture(event.pointerId);
      const move = (moveEvent) => requestAnimationFrame(() => apply(startWidth + (side === 'left' ? moveEvent.clientX - startX : startX - moveEvent.clientX)));
      const finish = () => {
        shell.dataset.resizing = 'false';
        document.body.style.userSelect = '';
        element.removeEventListener('pointermove', move);
        element.removeEventListener('pointerup', finish);
        element.removeEventListener('pointercancel', finish);
      };
      element.addEventListener('pointermove', move);
      element.addEventListener('pointerup', finish);
      element.addEventListener('pointercancel', finish);
    });
    element.addEventListener('dblclick', () => apply(side === 'left' ? 268 : 320));
    element.addEventListener('keydown', (event) => {
      if (!['ArrowLeft', 'ArrowRight'].includes(event.key)) return;
      event.preventDefault();
      const current = Number(element.getAttribute('aria-valuenow'));
      const direction = event.key === 'ArrowRight' ? 1 : -1;
      apply(current + direction * (side === 'left' ? 12 : -12));
    });
  };
  installSplitter(document.querySelector('#left-splitter'), 'left');
  installSplitter(document.querySelector('#right-splitter'), 'right');

  search.addEventListener('input', () => {
    evidence.search_query = search.value;
    renderNavigation(currentEntries, currentShardId);
  });
  document.addEventListener('keydown', (event) => {
    if ((event.metaKey || event.ctrlKey) && event.key.toLocaleLowerCase() === 'k') {
      event.preventDefault();
      if (shell.dataset.leftCollapsed === 'true') setCollapsed('left', false);
      search.focus();
    } else if ((event.metaKey || event.ctrlKey) && event.key.toLocaleLowerCase() === 'b') {
      event.preventDefault();
      setCollapsed('left', shell.dataset.leftCollapsed !== 'true');
    } else if (event.key === 'Escape' && shell.dataset.leftCollapsed !== 'true' && matchMedia('(max-width:720px)').matches) {
      setCollapsed('left', true);
    }
  });

  renderNavigation([selected], null);
  renderSelected(selected);
  document.querySelector('#load-first-shard').addEventListener('click', () => loadScript(root.shards[0].path));
  document.querySelector('#load-last-shard').addEventListener('click', () => loadScript(root.shards[root.shards.length - 1].path));
  globalThis.__GTKG_SHOW_STATE__ = (state) => {
    document.querySelectorAll('[data-ui-state]').forEach((node) => { node.hidden = node.dataset.uiState !== state; });
    document.querySelector('[data-region=right-content]').setAttribute('aria-busy', state === 'loading' ? 'true' : 'false');
    document.querySelectorAll('button').forEach((button) => { button.disabled = state === 'disabled'; });
    search.disabled = state === 'disabled';
    if (state === 'permission') {
      document.querySelector('#selected-title').textContent = 'Permission required';
      document.querySelector('#selected-content').textContent = '';
    } else if (state === 'empty') {
      document.querySelector('#selected-title').textContent = 'No content';
      document.querySelector('#selected-content').textContent = '';
    } else if (state === 'error') {
      document.querySelector('#selected-title').textContent = 'Content unavailable';
      document.querySelector('#selected-content').textContent = '';
    } else {
      renderSelected(currentSelected);
    }
  };
  globalThis.addEventListener('error', () => { evidence.console_errors += 1; });
  globalThis.addEventListener('unhandledrejection', () => { evidence.console_errors += 1; });
})();
"#;
