//! U04 local Wiki/A2UI evidence drawer.
//!
//! This is deliberately a projection boundary, not another query engine. It
//! re-executes the narrow Q04 queries against exact file-index artifacts,
//! verifies the accepted U03 Explorer output it is paired with, and reads the
//! P05 `current.get` document through its real handler.  Current and Replay
//! are consequently distinct presentation facts: Current is discovery-only;
//! Replay is an immutable Q04 evidence-manifest reference and never writes or
//! refreshes anything.

use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::io::Write;
use std::path::{Component, Path, PathBuf};

use gtkg_protocol::v03::query::FileQueryExpectedIdentitiesV1;
use gtkg_protocol::{FileReceiptRef, OperationId, OperationRequest, canonical_json_sha256};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;

use super::explorer::StaticGraphExplorerReceiptV2;
use super::graph_query::{FileGraphQueryOperationV1, execute_file_graph_operation_v1};
use crate::exact_read::read_bound_regular_file;
use crate::{CallContext, Dispatcher, EffectPolicy};

pub const EVIDENCE_DRAWER_SCHEMA_V1: &str = "gtkg.u04-evidence-drawer/v1";
const EVIDENCE_DRAWER_MANIFEST_SCHEMA_V1: &str = "gtkg.u04-evidence-drawer-manifest/v1";
const OFFICIAL_A2UI_CATALOG_ID_V091: &str =
    "https://a2ui.org/specification/v0_9/catalogs/basic/catalog.json";
const OFFICIAL_A2UI_BASIC_CATALOG: &str = include_str!("../../vendor/a2ui/v0_9_1/catalog.json");
const OFFICIAL_A2UI_BASIC_CATALOG_SHA256: &str =
    "sha256:8cc94d0a482e67048f9fc989964ca5da56fe42f531d919315a508989fb22e13e";
const MAX_DRAWER_FILE_BYTES: u64 = 8 * 1024 * 1024;

/// Only artifact identities and query parameters enter the U04 surface.  It
/// does not accept a caller-created response envelope or HTML payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceDrawerArtifactInputV1 {
    pub query_root: PathBuf,
    pub query_manifest_ref: FileReceiptRef,
    pub evidence_root: PathBuf,
    pub evidence_manifest_ref: FileReceiptRef,
    pub expected_identities: FileQueryExpectedIdentitiesV1,
    pub explorer_receipt: StaticGraphExplorerReceiptV2,
    pub current_path: PathBuf,
    pub current_sha256: String,
    pub search_query: String,
    pub unknown_query: String,
    pub explain_node_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceDrawerCurrentV1 {
    pub state: String,
    pub current_sha256: String,
    pub deliverable_id: String,
    pub version: String,
    pub version_path: String,
    pub tree_sha256: String,
    pub manifest_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceDrawerReplayV1 {
    pub state: String,
    pub evidence_manifest_path: String,
    pub evidence_manifest_file_sha256: String,
    pub source_snapshot_exact_set_sha256: String,
    pub read_only: bool,
}

/// Serializable, inert UI data.  All untrusted labels/evidence remain data
/// and the static renderer uses `textContent` exclusively.
/// Opaque projection data. Only the artifact-bound builder in this module can
/// create it; callers can serialize a verified projection but cannot seed one
/// from arbitrary JSON and send it to the writer.
///
/// ```compile_fail
/// use gtkg_core::v03::evidence_drawer::EvidenceDrawerProjectionV1;
/// let _ = serde_json::from_str::<EvidenceDrawerProjectionV1>("{}");
/// ```
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceDrawerProjectionV1 {
    schema_version: String,
    source_kind: String,
    source_snapshot_exact_set_sha256: String,
    graph_sha256: String,
    overlay_sha256: String,
    explorer_projection_sha256: String,
    current: EvidenceDrawerCurrentV1,
    replay: EvidenceDrawerReplayV1,
    evidence_level: String,
    a2ui_catalog_sha256: String,
    records: Vec<Value>,
    source_evidence: Vec<Value>,
    relations: Vec<Value>,
    claim_states: Vec<Value>,
    unknown: Value,
    conflicts: Vec<Value>,
    q04_execution_count: u64,
    network_calls: u64,
    database_reads: u64,
    target_execution_count: u64,
    projection_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredEvidenceDrawerProjectionV1 {
    schema_version: String,
    source_kind: String,
    source_snapshot_exact_set_sha256: String,
    graph_sha256: String,
    overlay_sha256: String,
    explorer_projection_sha256: String,
    current: EvidenceDrawerCurrentV1,
    replay: EvidenceDrawerReplayV1,
    evidence_level: String,
    a2ui_catalog_sha256: String,
    records: Vec<Value>,
    source_evidence: Vec<Value>,
    relations: Vec<Value>,
    claim_states: Vec<Value>,
    unknown: Value,
    conflicts: Vec<Value>,
    q04_execution_count: u64,
    network_calls: u64,
    database_reads: u64,
    target_execution_count: u64,
    projection_sha256: String,
}

impl From<StoredEvidenceDrawerProjectionV1> for EvidenceDrawerProjectionV1 {
    fn from(stored: StoredEvidenceDrawerProjectionV1) -> Self {
        Self {
            schema_version: stored.schema_version,
            source_kind: stored.source_kind,
            source_snapshot_exact_set_sha256: stored.source_snapshot_exact_set_sha256,
            graph_sha256: stored.graph_sha256,
            overlay_sha256: stored.overlay_sha256,
            explorer_projection_sha256: stored.explorer_projection_sha256,
            current: stored.current,
            replay: stored.replay,
            evidence_level: stored.evidence_level,
            a2ui_catalog_sha256: stored.a2ui_catalog_sha256,
            records: stored.records,
            source_evidence: stored.source_evidence,
            relations: stored.relations,
            claim_states: stored.claim_states,
            unknown: stored.unknown,
            conflicts: stored.conflicts,
            q04_execution_count: stored.q04_execution_count,
            network_calls: stored.network_calls,
            database_reads: stored.database_reads,
            target_execution_count: stored.target_execution_count,
            projection_sha256: stored.projection_sha256,
        }
    }
}

/// Public readback is deliberately non-writable metadata.  It proves that a
/// receipt's fixed files are self-consistent, but it cannot be converted back
/// into a builder projection and therefore cannot become a write bypass.
///
/// ```compile_fail
/// use gtkg_core::v03::evidence_drawer::{EvidenceDrawerProjectionV1, EvidenceDrawerReadbackV1};
/// fn write_input(_: &EvidenceDrawerProjectionV1) {}
/// let readback: EvidenceDrawerReadbackV1 = panic!();
/// write_input(&readback);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceDrawerReadbackV1 {
    schema_version: String,
    source_kind: String,
    projection_sha256: String,
    explorer_projection_sha256: String,
    current_state: String,
    replay_state: String,
    a2ui_catalog_sha256: String,
}

impl PartialEq<EvidenceDrawerProjectionV1> for EvidenceDrawerReadbackV1 {
    fn eq(&self, projection: &EvidenceDrawerProjectionV1) -> bool {
        self.schema_version == projection.schema_version
            && self.source_kind == projection.source_kind
            && self.projection_sha256 == projection.projection_sha256
            && self.explorer_projection_sha256 == projection.explorer_projection_sha256
            && self.current_state == projection.current.state
            && self.replay_state == projection.replay.state
            && self.a2ui_catalog_sha256 == projection.a2ui_catalog_sha256
    }
}

/// Non-serializable descriptor-bound root for exactly one fresh U04 output.
/// It is minted below a canonical workspace root and exact authorized parent.
/// A later equivalent `WorkspaceWrite` Context with those same bindings may
/// use it; a different root, missing parent authorization, or `ReadOnly`
/// Context cannot.
pub struct EvidenceDrawerOutputRootCapabilityV1 {
    context_root: PathBuf,
    parent: PathBuf,
    parent_identity: EvidenceDrawerDirectoryIdentityV1,
    root: PathBuf,
    root_identity: EvidenceDrawerDirectoryIdentityV1,
    capability_id: String,
    capability_digest: String,
    nonce: [u8; 16],
}

impl std::fmt::Debug for EvidenceDrawerOutputRootCapabilityV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EvidenceDrawerOutputRootCapabilityV1")
            .field("root", &self.root)
            .field("capability_id", &self.capability_id)
            .field("capability_digest", &self.capability_digest)
            .finish_non_exhaustive()
    }
}

impl EvidenceDrawerOutputRootCapabilityV1 {
    pub fn path(&self) -> &Path {
        &self.root
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EvidenceDrawerDirectoryIdentityV1 {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(unix)]
    mode: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceDrawerReceiptV1 {
    pub schema_version: String,
    pub source_kind: String,
    pub site_root: String,
    pub index_relative_path: String,
    pub index_sha256: String,
    pub projection_relative_path: String,
    pub projection_sha256: String,
    pub a2ui_stream_relative_path: String,
    pub a2ui_stream_sha256: String,
    pub site_manifest_sha256: String,
    pub a2ui_catalog_sha256: String,
    pub explorer_projection_sha256: String,
    pub q04_execution_count: u64,
    pub network_calls: u64,
    pub database_reads: u64,
    pub target_execution_count: u64,
}

#[derive(Debug, Error)]
pub enum EvidenceDrawerErrorV1 {
    #[error("invalid U04 evidence drawer input: {0}")]
    InvalidInput(String),
    #[error("U04 rejected the U03 Explorer binding: {0}")]
    U03Binding(String),
    #[error("U04 rejected the Current binding: {0}")]
    CurrentBinding(String),
    #[error("U04 rejected the Q04 evidence binding: {0}")]
    Q04Binding(String),
    #[error("U04 writer requires workspace-write context")]
    WriteDenied,
    #[error("U04 output parent is not an explicitly authorized root")]
    CapabilityParentRejected,
    #[error("U04 output parent is a symlink: {0}")]
    OutputParentSymlink(PathBuf),
    #[error("U04 output-root capability no longer matches a fresh 0700 root")]
    CapabilityMismatch,
    #[error(
        "U04 output-root capability is not bound to an equivalent workspace-write authorization"
    )]
    CapabilityContextRejected,
    #[error("U04 output-root capabilities require Unix dirfd semantics")]
    UnsupportedPlatform,
    #[error("U04 output already exists: {0}")]
    OutputExists(PathBuf),
    #[error("U04 output is invalid: {0}")]
    InvalidArtifact(String),
    #[error("U04 I/O failed at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("U04 JSON failed: {0}")]
    Json(#[from] serde_json::Error),
}

impl EvidenceDrawerErrorV1 {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidInput(_) => "E_U04_INPUT_INVALID",
            Self::U03Binding(_) => "E_U04_U03_BINDING",
            Self::CurrentBinding(_) => "E_U04_CURRENT_BINDING",
            Self::Q04Binding(_) => "E_U04_Q04_BINDING",
            Self::WriteDenied => "E_U04_WRITE_DENIED",
            Self::CapabilityParentRejected => "E_U04_CAPABILITY_PARENT_REJECTED",
            Self::OutputParentSymlink(_) => "E_U04_OUTPUT_PARENT_SYMLINK",
            Self::CapabilityMismatch => "E_U04_CAPABILITY_MISMATCH",
            Self::CapabilityContextRejected => "E_U04_CAPABILITY_CONTEXT_REJECTED",
            Self::UnsupportedPlatform => "E_U04_UNSUPPORTED_PLATFORM",
            Self::OutputExists(_) => "E_U04_OUTPUT_EXISTS",
            Self::InvalidArtifact(_) => "E_U04_ARTIFACT_INVALID",
            Self::Io { .. } => "E_U04_IO",
            Self::Json(_) => "E_U04_JSON",
        }
    }
}

/// Construct a drawer from real predecessor boundaries.  Search, unknown
/// answer and relation explanation are separate Q04 calls, so the projection
/// cannot fabricate any of those states from a browser fixture.
pub fn build_evidence_drawer_from_artifacts_v1(
    context: &CallContext,
    input: &EvidenceDrawerArtifactInputV1,
) -> Result<EvidenceDrawerProjectionV1, EvidenceDrawerErrorV1> {
    validate_input(input)?;
    validate_u03_receipt(context, &input.explorer_receipt, &input.expected_identities)?;
    let current = read_current(context, input)?;

    let search = execute_q04(
        context,
        input,
        FileGraphQueryOperationV1::Search,
        json!({"query": input.search_query, "max_results": 64}),
    )?;
    let unknown = execute_q04(
        context,
        input,
        FileGraphQueryOperationV1::Search,
        json!({"query": input.unknown_query, "max_results": 64}),
    )?;
    let explain = execute_q04(
        context,
        input,
        FileGraphQueryOperationV1::Explain,
        json!({"node_id": input.explain_node_id, "max_results": 64}),
    )?;

    let (source, graph, overlay, records, source_evidence, conflicts, evidence_level) =
        bind_claim_search(&search, input, "search")?;
    let (_, unknown_graph, unknown_overlay, _, _, _, _) =
        bind_claim_search(&unknown, input, "unknown")?;
    if unknown_graph != graph || unknown_overlay != overlay {
        return Err(EvidenceDrawerErrorV1::Q04Binding(
            "unknown-query response differs from the search identity".to_owned(),
        ));
    }
    let unknown_raw = unknown["result"].clone();
    if unknown_raw["answer_state"] != "no_answer"
        || !unknown_raw["matches"].is_array()
        || unknown_raw["matches"]
            .as_array()
            .is_none_or(|matches| !matches.is_empty())
    {
        return Err(EvidenceDrawerErrorV1::Q04Binding(
            "unknown query did not produce Q04's observed no_answer state".to_owned(),
        ));
    }
    // Q04's transport vocabulary is `no_answer`; the Wiki vocabulary is the
    // product-facing `unknown`. Preserve the raw state beside the explicit,
    // one-way display mapping so the drawer cannot upgrade it to supported.
    let unknown_result = json!({
        "answer_state": "unknown",
        "q04_answer_state": "no_answer",
        "query": unknown_raw["query"],
        "matches": unknown_raw["matches"],
        "truncated": unknown_raw["truncated"],
        "continuation": unknown_raw["continuation"],
    });
    let relations = bind_structural_explain(&explain, input, &source, &graph)?;
    let claim_states = claim_states(&records)?;

    let mut projection = EvidenceDrawerProjectionV1 {
        schema_version: EVIDENCE_DRAWER_SCHEMA_V1.to_owned(),
        source_kind: "q04_file_index_artifacts".to_owned(),
        source_snapshot_exact_set_sha256: source,
        graph_sha256: graph,
        overlay_sha256: overlay,
        explorer_projection_sha256: input.explorer_receipt.projection_sha256.clone(),
        current,
        replay: EvidenceDrawerReplayV1 {
            state: "replay_read_only".to_owned(),
            evidence_manifest_path: input.evidence_manifest_ref.path.clone(),
            evidence_manifest_file_sha256: input.evidence_manifest_ref.sha256.clone(),
            source_snapshot_exact_set_sha256: input.expected_identities.source_identity.clone(),
            read_only: true,
        },
        evidence_level,
        a2ui_catalog_sha256: OFFICIAL_A2UI_BASIC_CATALOG_SHA256.to_owned(),
        records,
        source_evidence,
        relations,
        claim_states,
        unknown: unknown_result,
        conflicts,
        q04_execution_count: 3,
        network_calls: 0,
        database_reads: 0,
        target_execution_count: 0,
        projection_sha256: String::new(),
    };
    projection.projection_sha256 = projection_digest(&projection)?;
    validate_projection(&projection)?;
    Ok(projection)
}

/// Mint a fresh, owner-only U04 output capability below an exact authorized
/// parent. The random path prevents an arbitrary pre-existing directory from
/// becoming a writer target.
pub fn create_evidence_drawer_output_root_v1(
    context: &CallContext,
    authorized_parent: &Path,
) -> Result<EvidenceDrawerOutputRootCapabilityV1, EvidenceDrawerErrorV1> {
    if context.effect_policy != EffectPolicy::WorkspaceWrite {
        return Err(EvidenceDrawerErrorV1::WriteDenied);
    }
    #[cfg(not(unix))]
    {
        let _ = (context, authorized_parent);
        return Err(EvidenceDrawerErrorV1::UnsupportedPlatform);
    }
    #[cfg(unix)]
    {
        let mut nonce = [0_u8; 16];
        getrandom::fill(&mut nonce).map_err(|_| EvidenceDrawerErrorV1::CapabilityMismatch)?;
        for attempt in 0..32 {
            let name = OsString::from(format!(
                ".gtkg-u04-drawer-{}-{}-{attempt}",
                std::process::id(),
                hex::encode(&nonce[..8])
            ));
            if let Ok(capability) = mint_named_output_root(context, authorized_parent, &name, nonce)
            {
                return Ok(capability);
            }
        }
        Err(EvidenceDrawerErrorV1::CapabilityMismatch)
    }
}

/// Legacy-shaped convenience API. It mints an internal descriptor capability
/// for exactly the requested fresh direct child before writing; it never opens
/// output files through the caller's pathname after authorization.
pub fn write_evidence_drawer_v1(
    context: &CallContext,
    output_root: &Path,
    projection: &EvidenceDrawerProjectionV1,
) -> Result<EvidenceDrawerReceiptV1, EvidenceDrawerErrorV1> {
    if context.effect_policy != EffectPolicy::WorkspaceWrite {
        return Err(EvidenceDrawerErrorV1::WriteDenied);
    }
    #[cfg(not(unix))]
    {
        let _ = (context, output_root, projection);
        return Err(EvidenceDrawerErrorV1::UnsupportedPlatform);
    }
    #[cfg(unix)]
    {
        let parent = output_root
            .parent()
            .ok_or(EvidenceDrawerErrorV1::CapabilityParentRejected)?;
        let name = output_root
            .file_name()
            .filter(|name| !name.is_empty())
            .ok_or(EvidenceDrawerErrorV1::CapabilityParentRejected)?;
        if output_root.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::CurDir | Component::Prefix(_)
            )
        }) {
            return Err(EvidenceDrawerErrorV1::CapabilityParentRejected);
        }
        let mut nonce = [0_u8; 16];
        getrandom::fill(&mut nonce).map_err(|_| EvidenceDrawerErrorV1::CapabilityMismatch)?;
        let capability = mint_named_output_root(context, parent, name, nonce)?;
        write_evidence_drawer_with_capability_v1(context, &capability, projection)
    }
}

/// Write the fixed U04 artifact set using a nonserializable capability. All
/// file creation is `openat`/`mkdirat` from a validated directory descriptor.
pub fn write_evidence_drawer_with_capability_v1(
    context: &CallContext,
    capability: &EvidenceDrawerOutputRootCapabilityV1,
    projection: &EvidenceDrawerProjectionV1,
) -> Result<EvidenceDrawerReceiptV1, EvidenceDrawerErrorV1> {
    validate_output_capability_context(context, capability)?;
    validate_projection(projection)?;
    let root_file = validate_fresh_output_capability(capability)?;
    let root = capability.root.clone();

    let projection_bytes = serde_json::to_vec_pretty(projection)?;
    let index_bytes = render_html(projection)?.into_bytes();
    let stream_bytes = render_a2ui_stream(projection)?;
    let index_sha256 = sha256(&index_bytes);
    let projection_sha256 = sha256(&projection_bytes);
    let stream_sha256 = sha256(&stream_bytes);
    write_private_new_file(
        &root_file,
        OsStr::new("projection.json"),
        &root.join("projection.json"),
        &projection_bytes,
    )?;
    write_private_new_file(
        &root_file,
        OsStr::new("index.html"),
        &root.join("index.html"),
        &index_bytes,
    )?;
    let a2ui_file =
        create_private_child_directory(&root_file, OsStr::new("a2ui"), &root.join("a2ui"))?;
    write_private_new_file(
        &a2ui_file,
        OsStr::new("stream.jsonl"),
        &root.join("a2ui/stream.jsonl"),
        &stream_bytes,
    )?;

    let manifest = json!({
        "schema_version": EVIDENCE_DRAWER_MANIFEST_SCHEMA_V1,
        "source_kind": projection.source_kind,
        "index_relative_path": "index.html",
        "index_sha256": index_sha256,
        "projection_relative_path": "projection.json",
        "projection_file_sha256": projection_sha256,
        "projection_sha256": projection.projection_sha256,
        "a2ui_stream_relative_path": "a2ui/stream.jsonl",
        "a2ui_stream_sha256": stream_sha256,
        "a2ui_catalog_id": OFFICIAL_A2UI_CATALOG_ID_V091,
        "a2ui_catalog_sha256": projection.a2ui_catalog_sha256,
        "explorer_projection_sha256": projection.explorer_projection_sha256,
    });
    let site_manifest_sha256 = canonical_json_sha256(&manifest)?;
    write_private_new_file(
        &root_file,
        OsStr::new("manifest.json"),
        &root.join("manifest.json"),
        &serde_json::to_vec_pretty(&manifest)?,
    )?;
    validate_written_output_capability(capability)?;
    let receipt = EvidenceDrawerReceiptV1 {
        schema_version: "gtkg.u04-evidence-drawer-receipt/v1".to_owned(),
        source_kind: projection.source_kind.clone(),
        site_root: root.display().to_string(),
        index_relative_path: "index.html".to_owned(),
        index_sha256,
        projection_relative_path: "projection.json".to_owned(),
        projection_sha256: projection.projection_sha256.clone(),
        a2ui_stream_relative_path: "a2ui/stream.jsonl".to_owned(),
        a2ui_stream_sha256: stream_sha256,
        site_manifest_sha256,
        a2ui_catalog_sha256: projection.a2ui_catalog_sha256.clone(),
        explorer_projection_sha256: projection.explorer_projection_sha256.clone(),
        q04_execution_count: projection.q04_execution_count,
        network_calls: projection.network_calls,
        database_reads: projection.database_reads,
        target_execution_count: projection.target_execution_count,
    };
    let readback = read_evidence_drawer_v1(context, &receipt)?;
    if readback != *projection {
        return Err(EvidenceDrawerErrorV1::InvalidArtifact(
            "post-write projection readback drifted".to_owned(),
        ));
    }
    Ok(receipt)
}

/// Exact-read the durable projection and all fixed companion files.  This
/// does not load any target source, browser runtime, network resource, or
/// arbitrary files from a projected record.
pub fn read_evidence_drawer_v1(
    context: &CallContext,
    receipt: &EvidenceDrawerReceiptV1,
) -> Result<EvidenceDrawerReadbackV1, EvidenceDrawerErrorV1> {
    if receipt.schema_version != "gtkg.u04-evidence-drawer-receipt/v1"
        || receipt.source_kind != "q04_file_index_artifacts"
        || receipt.index_relative_path != "index.html"
        || receipt.projection_relative_path != "projection.json"
        || receipt.a2ui_stream_relative_path != "a2ui/stream.jsonl"
        || receipt.a2ui_catalog_sha256 != OFFICIAL_A2UI_BASIC_CATALOG_SHA256
        || receipt.q04_execution_count != 3
        || receipt.network_calls != 0
        || receipt.database_reads != 0
        || receipt.target_execution_count != 0
    {
        return Err(EvidenceDrawerErrorV1::InvalidArtifact(
            "receipt has an invalid fixed U04 boundary".to_owned(),
        ));
    }
    let root = authorize_plain_directory(context, Path::new(&receipt.site_root))?;
    let manifest = read_exact_json(context, &root.join("manifest.json"))?;
    if canonical_json_sha256(&manifest)? != receipt.site_manifest_sha256
        || manifest["schema_version"] != EVIDENCE_DRAWER_MANIFEST_SCHEMA_V1
        || manifest["source_kind"] != receipt.source_kind
        || manifest["index_relative_path"] != receipt.index_relative_path
        || manifest["index_sha256"] != receipt.index_sha256
        || manifest["projection_relative_path"] != receipt.projection_relative_path
        || manifest["a2ui_stream_relative_path"] != receipt.a2ui_stream_relative_path
        || manifest["a2ui_stream_sha256"] != receipt.a2ui_stream_sha256
        || manifest["projection_sha256"] != receipt.projection_sha256
        || manifest["explorer_projection_sha256"] != receipt.explorer_projection_sha256
        || manifest["a2ui_catalog_id"] != OFFICIAL_A2UI_CATALOG_ID_V091
        || manifest["a2ui_catalog_sha256"] != receipt.a2ui_catalog_sha256
    {
        return Err(EvidenceDrawerErrorV1::InvalidArtifact(
            "drawer manifest does not bind the receipt".to_owned(),
        ));
    }
    let index = read_exact_bytes(context, &root.join("index.html"))?;
    if sha256(&index) != receipt.index_sha256 {
        return Err(EvidenceDrawerErrorV1::InvalidArtifact(
            "drawer index digest drifted".to_owned(),
        ));
    }
    let stream = read_exact_bytes(context, &root.join("a2ui/stream.jsonl"))?;
    if sha256(&stream) != receipt.a2ui_stream_sha256 {
        return Err(EvidenceDrawerErrorV1::InvalidArtifact(
            "drawer A2UI stream digest drifted".to_owned(),
        ));
    }
    validate_a2ui_stream(&stream)?;
    let projection_bytes = read_exact_bytes(context, &root.join("projection.json"))?;
    if manifest["projection_file_sha256"] != sha256(&projection_bytes) {
        return Err(EvidenceDrawerErrorV1::InvalidArtifact(
            "drawer projection file digest drifted".to_owned(),
        ));
    }
    let projection: EvidenceDrawerProjectionV1 = StoredEvidenceDrawerProjectionV1::deserialize(
        &mut serde_json::Deserializer::from_slice(&projection_bytes),
    )?
    .into();
    if projection.projection_sha256 != receipt.projection_sha256
        || projection.explorer_projection_sha256 != receipt.explorer_projection_sha256
        || projection.a2ui_catalog_sha256 != receipt.a2ui_catalog_sha256
    {
        return Err(EvidenceDrawerErrorV1::InvalidArtifact(
            "drawer projection receipt binding drifted".to_owned(),
        ));
    }
    validate_projection(&projection)?;
    Ok(EvidenceDrawerReadbackV1 {
        schema_version: projection.schema_version,
        source_kind: projection.source_kind,
        projection_sha256: projection.projection_sha256,
        explorer_projection_sha256: projection.explorer_projection_sha256,
        current_state: projection.current.state,
        replay_state: projection.replay.state,
        a2ui_catalog_sha256: projection.a2ui_catalog_sha256,
    })
}

fn validate_input(input: &EvidenceDrawerArtifactInputV1) -> Result<(), EvidenceDrawerErrorV1> {
    for (name, value) in [
        ("search_query", input.search_query.as_str()),
        ("unknown_query", input.unknown_query.as_str()),
        ("explain_node_id", input.explain_node_id.as_str()),
    ] {
        if value.trim().is_empty() {
            return Err(EvidenceDrawerErrorV1::InvalidInput(format!(
                "{name} must not be empty"
            )));
        }
    }
    if input.search_query == input.unknown_query {
        return Err(EvidenceDrawerErrorV1::InvalidInput(
            "unknown_query must be different from search_query".to_owned(),
        ));
    }
    input
        .query_manifest_ref
        .validate()
        .map_err(|error| EvidenceDrawerErrorV1::InvalidInput(error.to_string()))?;
    input
        .evidence_manifest_ref
        .validate()
        .map_err(|error| EvidenceDrawerErrorV1::InvalidInput(error.to_string()))?;
    Ok(())
}

fn validate_u03_receipt(
    context: &CallContext,
    receipt: &StaticGraphExplorerReceiptV2,
    expected: &FileQueryExpectedIdentitiesV1,
) -> Result<(), EvidenceDrawerErrorV1> {
    if receipt.schema_version != "gtkg.static-graph-explorer-receipt/v2"
        || receipt.source_kind != "q04_file_index_artifacts"
        || receipt.index_relative_path != "index.html"
        || receipt.network_calls != 0
        || receipt.database_reads != 0
        || receipt.target_execution_count != 0
        || receipt.projection_sha256.is_empty()
        || !receipt.output_root_capability_id.starts_with("u03o2-")
        || !is_sha256_identity(&receipt.output_root_capability_digest)
    {
        return Err(EvidenceDrawerErrorV1::U03Binding(
            "receipt does not describe an accepted local Q04 Explorer".to_owned(),
        ));
    }
    let root = authorize_plain_directory(context, Path::new(&receipt.site_root))
        .map_err(|error| EvidenceDrawerErrorV1::U03Binding(error.to_string()))?;
    let index = read_exact_bytes(context, &root.join("index.html"))
        .map_err(|error| EvidenceDrawerErrorV1::U03Binding(error.to_string()))?;
    if sha256(&index) != receipt.index_sha256 {
        return Err(EvidenceDrawerErrorV1::U03Binding(
            "Explorer index digest does not match its receipt".to_owned(),
        ));
    }
    let manifest = read_exact_json(context, &root.join("manifest.json"))
        .map_err(|error| EvidenceDrawerErrorV1::U03Binding(error.to_string()))?;
    if canonical_json_sha256(&manifest)? != receipt.site_manifest_sha256
        || manifest["schema_version"] != "gtkg.static-graph-explorer-manifest/v2"
        || manifest["source_kind"] != receipt.source_kind
        || manifest["index_relative_path"] != receipt.index_relative_path
        || manifest["index_sha256"] != receipt.index_sha256
        || manifest["projection_sha256"] != receipt.projection_sha256
    {
        return Err(EvidenceDrawerErrorV1::U03Binding(
            "Explorer manifest does not bind its receipt".to_owned(),
        ));
    }
    let index_text = std::str::from_utf8(&index).map_err(|error| {
        EvidenceDrawerErrorV1::U03Binding(format!("Explorer index is not UTF-8: {error}"))
    })?;
    let explorer = embedded_json(index_text, "explorer-data")?;
    if explorer["schema_version"] != "gtkg.static-graph-explorer/v2"
        || explorer["source_kind"] != "q04_file_index_artifacts"
        || explorer["source_snapshot_exact_set_sha256"] != expected.source_identity
        || explorer["graph_sha256"] != expected.graph_identity
        || explorer["overlay_sha256"] != expected.overlay_identity
        || explorer["projection_sha256"] != receipt.projection_sha256
    {
        return Err(EvidenceDrawerErrorV1::U03Binding(
            "Explorer serialized projection is not bound to this exact Q04 identity".to_owned(),
        ));
    }
    Ok(())
}

fn read_current(
    context: &CallContext,
    input: &EvidenceDrawerArtifactInputV1,
) -> Result<EvidenceDrawerCurrentV1, EvidenceDrawerErrorV1> {
    let request = OperationRequest::new(
        OperationId::CurrentGet,
        "u04-current-readback",
        json!({
            "current_path": input.current_path,
            "expected_current_sha256": input.current_sha256,
        }),
    );
    let response = Dispatcher
        .execute(context, request)
        .map_err(|error| EvidenceDrawerErrorV1::CurrentBinding(error.error.message))?;
    let current = &response.result["current"];
    if response.result["discovery_only"] != true
        || response.result["current_sha256"] != input.current_sha256
        || current["manifest_sha256"] != input.evidence_manifest_ref.sha256
    {
        return Err(EvidenceDrawerErrorV1::CurrentBinding(
            "current.get result is not the exact Q04 evidence manifest anchor".to_owned(),
        ));
    }
    Ok(EvidenceDrawerCurrentV1 {
        state: "current_discovery_only".to_owned(),
        current_sha256: input.current_sha256.clone(),
        deliverable_id: current_field(current, "deliverable_id")?,
        version: current_field(current, "version")?,
        version_path: current_field(current, "version_path")?,
        tree_sha256: current_field(current, "tree_sha256")?,
        manifest_sha256: current_field(current, "manifest_sha256")?,
    })
}

fn execute_q04(
    context: &CallContext,
    input: &EvidenceDrawerArtifactInputV1,
    operation: FileGraphQueryOperationV1,
    payload: Value,
) -> Result<Value, EvidenceDrawerErrorV1> {
    execute_file_graph_operation_v1(
        context,
        &input.query_root,
        &input.query_manifest_ref,
        &input.evidence_root,
        &input.evidence_manifest_ref,
        &input.expected_identities,
        operation,
        &payload,
    )
    .map_err(|error| EvidenceDrawerErrorV1::Q04Binding(error.to_string()))
}

type ClaimSearchBinding = (
    String,
    String,
    String,
    Vec<Value>,
    Vec<Value>,
    Vec<Value>,
    String,
);

fn bind_claim_search(
    response: &Value,
    input: &EvidenceDrawerArtifactInputV1,
    label: &str,
) -> Result<ClaimSearchBinding, EvidenceDrawerErrorV1> {
    if response["schema_version"] != "gtkg.claim-aware-query-result/v2"
        || response["operation_id"] != "graph.search"
        || response["mode"] != "file_index_claim_aware"
    {
        return Err(EvidenceDrawerErrorV1::Q04Binding(format!(
            "{label} response is not a Q04 claim-aware search"
        )));
    }
    let pack = &response["evidence_pack"];
    let source = required_string(
        &pack["graph_readback"]["source_snapshot_exact_set_sha256"],
        "Q04 source identity",
    )?;
    let graph = required_string(
        &pack["graph_readback"]["graph_sha256"],
        "Q04 graph identity",
    )?;
    let overlay = required_string(
        &pack["overlay_readback"]["overlay_sha256"],
        "Q04 overlay identity",
    )?;
    if source != input.expected_identities.source_identity
        || graph != input.expected_identities.graph_identity
        || overlay != input.expected_identities.overlay_identity
        || pack["query_index"]["evidence_manifest_file_sha256"]
            != input.evidence_manifest_ref.sha256
        || pack["query_index"]["network_call_count"] != 0
        || pack["query_index"]["database_read_count"] != 0
        || pack["query_index"]["daemon_call_count"] != 0
    {
        return Err(EvidenceDrawerErrorV1::Q04Binding(format!(
            "{label} response evidence pack drifted from exact Q04 artifacts"
        )));
    }
    let records = response["result"]["matches"]
        .as_array()
        .ok_or_else(|| {
            EvidenceDrawerErrorV1::Q04Binding(format!("{label} response has no matches array"))
        })?
        .clone();
    let evidence = pack["evidence"]
        .as_array()
        .ok_or_else(|| {
            EvidenceDrawerErrorV1::Q04Binding(format!("{label} response has no evidence array"))
        })?
        .clone();
    let conflicts = response["result"]["knowledge_conflicts"]
        .as_array()
        .ok_or_else(|| {
            EvidenceDrawerErrorV1::Q04Binding(format!("{label} response has no conflicts array"))
        })?
        .clone();
    let evidence_level = required_string(
        &pack["query_index"]["knowledge_assurance"],
        "Q04 knowledge assurance",
    )?;
    Ok((
        source,
        graph,
        overlay,
        records,
        evidence,
        conflicts,
        evidence_level,
    ))
}

fn bind_structural_explain(
    response: &Value,
    input: &EvidenceDrawerArtifactInputV1,
    source: &str,
    graph: &str,
) -> Result<Vec<Value>, EvidenceDrawerErrorV1> {
    if response["schema_version"] != "gtkg.structural-query-result/v3"
        || response["operation_id"] != "graph.explain"
        || response["mode"] != "file_index_structural"
    {
        return Err(EvidenceDrawerErrorV1::Q04Binding(
            "explain response is not an actual Q04 structural response".to_owned(),
        ));
    }
    let pack = &response["evidence_pack"];
    if pack["graph_readback"]["source_snapshot_exact_set_sha256"] != source
        || pack["graph_readback"]["graph_sha256"] != graph
        || pack["query_index"]["evidence_manifest_file_sha256"]
            != input.evidence_manifest_ref.sha256
        || pack["query_index"]["network_call_count"] != 0
        || pack["query_index"]["database_read_count"] != 0
        || pack["query_index"]["daemon_call_count"] != 0
    {
        return Err(EvidenceDrawerErrorV1::Q04Binding(
            "explain evidence pack drifted from exact Q04 artifacts".to_owned(),
        ));
    }
    let relations = response["result"]["relations"]
        .as_array()
        .ok_or_else(|| {
            EvidenceDrawerErrorV1::Q04Binding("explain has no relations array".to_owned())
        })?
        .clone();
    if relations.is_empty()
        || relations.iter().any(|relation| {
            !matches!(
                relation["resolution"].as_str(),
                Some("resolved" | "ambiguous" | "unresolved" | "unsupported")
            )
        })
    {
        return Err(EvidenceDrawerErrorV1::Q04Binding(
            "explain relations have invalid resolution state".to_owned(),
        ));
    }
    Ok(relations)
}

fn claim_states(records: &[Value]) -> Result<Vec<Value>, EvidenceDrawerErrorV1> {
    let mut states = records
        .iter()
        .filter_map(|record| {
            record["claim_id"].as_str().map(|claim_id| {
                json!({
                    "entity_id": record["entity_id"],
                    "claim_id": claim_id,
                    "kind": record["kind"],
                    "state": record["knowledge_state"],
                })
            })
        })
        .collect::<Vec<_>>();
    if states.iter().any(|state| {
        !matches!(
            state["state"].as_str(),
            Some("accepted_grounded" | "abstention")
        ) || state["claim_id"].as_str().is_none_or(str::is_empty)
    }) {
        return Err(EvidenceDrawerErrorV1::Q04Binding(
            "claim-aware Q04 match has an invalid claim state".to_owned(),
        ));
    }
    states.sort_by(|left, right| left["entity_id"].as_str().cmp(&right["entity_id"].as_str()));
    states.dedup_by(|left, right| left["entity_id"] == right["entity_id"]);
    Ok(states)
}

fn validate_projection(
    projection: &EvidenceDrawerProjectionV1,
) -> Result<(), EvidenceDrawerErrorV1> {
    if projection.schema_version != EVIDENCE_DRAWER_SCHEMA_V1
        || projection.source_kind != "q04_file_index_artifacts"
        || projection.current.state != "current_discovery_only"
        || projection.replay.state != "replay_read_only"
        || !projection.replay.read_only
        || projection.records.is_empty()
        || projection.source_evidence.is_empty()
        || projection.relations.is_empty()
        || projection.q04_execution_count != 3
        || projection.network_calls != 0
        || projection.database_reads != 0
        || projection.target_execution_count != 0
        || projection.unknown["answer_state"] != "unknown"
        || projection.unknown["q04_answer_state"] != "no_answer"
        || projection.a2ui_catalog_sha256 != OFFICIAL_A2UI_BASIC_CATALOG_SHA256
        || projection.projection_sha256 != projection_digest(projection)?
    {
        return Err(EvidenceDrawerErrorV1::InvalidArtifact(
            "projection has an invalid U04 identity or evidence boundary".to_owned(),
        ));
    }
    Ok(())
}

fn projection_digest(
    projection: &EvidenceDrawerProjectionV1,
) -> Result<String, EvidenceDrawerErrorV1> {
    let mut canonical = projection.clone();
    canonical.projection_sha256.clear();
    canonical_json_sha256(&canonical).map_err(EvidenceDrawerErrorV1::Json)
}

fn render_a2ui_stream(
    projection: &EvidenceDrawerProjectionV1,
) -> Result<Vec<u8>, EvidenceDrawerErrorV1> {
    validate_official_catalog()?;
    let source_evidence_json = serde_json::to_string(&projection.source_evidence)?;
    let relations_json = serde_json::to_string(&projection.relations)?;
    let claim_states_json = serde_json::to_string(&projection.claim_states)?;
    let unknown_json = serde_json::to_string(&projection.unknown)?;
    let conflicts_json = serde_json::to_string(&projection.conflicts)?;
    let stream = [
        json!({
            "version": "v0.9",
            "createSurface": {"surfaceId": "gtkg-u04-drawer", "catalogId": OFFICIAL_A2UI_CATALOG_ID_V091}
        }),
        json!({
            "version": "v0.9",
            "updateComponents": {"surfaceId": "gtkg-u04-drawer", "components": [
                {"id":"root","component":"Row","children":["index","detail"],"align":"stretch"},
                {"id":"index","component":"Column","children":["title","records"]},
                {"id":"title","component":"Text","text":"Evidence drawer","variant":"h2"},
                {"id":"records","component":"List","children":{"componentId":"record","path":"/records"},"direction":"vertical"},
                {"id":"record","component":"Text","text":{"path":"label"},"variant":"body"},
                {"id":"detail","component":"Column","children":["current","replay","state","source-evidence","relations","claims","unknown","conflicts"]},
                {"id":"current","component":"Text","text":{"path":"/current/state"},"variant":"caption"},
                {"id":"replay","component":"Text","text":{"path":"/replay/state"},"variant":"caption"},
                {"id":"state","component":"Text","text":{"path":"/evidence_level"},"variant":"caption"},
                {"id":"source-evidence","component":"Text","text":{"path":"/source_evidence_json"},"variant":"body"},
                {"id":"relations","component":"Text","text":{"path":"/relations_json"},"variant":"body"},
                {"id":"claims","component":"Text","text":{"path":"/claim_states_json"},"variant":"body"},
                {"id":"unknown","component":"Text","text":{"path":"/unknown_json"},"variant":"body"},
                {"id":"conflicts","component":"Text","text":{"path":"/conflicts_json"},"variant":"body"}
            ]}
        }),
        json!({
            "version": "v0.9",
            "updateDataModel": {"surfaceId": "gtkg-u04-drawer", "path":"/", "value": {
                "records": projection.records,
                "current": projection.current,
                "replay": projection.replay,
                "evidence_level": projection.evidence_level,
                "source_evidence": projection.source_evidence,
                "relations": projection.relations,
                "claim_states": projection.claim_states,
                "unknown": projection.unknown,
                "conflicts": projection.conflicts,
                "source_evidence_json": source_evidence_json,
                "relations_json": relations_json,
                "claim_states_json": claim_states_json,
                "unknown_json": unknown_json,
                "conflicts_json": conflicts_json,
                "provenance": {
                    "projection_sha256": projection.projection_sha256,
                    "source_snapshot_exact_set_sha256": projection.source_snapshot_exact_set_sha256,
                    "graph_sha256": projection.graph_sha256,
                    "overlay_sha256": projection.overlay_sha256,
                    "explorer_projection_sha256": projection.explorer_projection_sha256,
                    "a2ui_catalog_sha256": projection.a2ui_catalog_sha256
                }
            }}
        }),
    ];
    let bytes = stream
        .iter()
        .map(serde_json::to_string)
        .collect::<Result<Vec<_>, _>>()?
        .join("\n")
        .into_bytes();
    validate_a2ui_stream(&bytes)?;
    Ok(bytes)
}

fn validate_official_catalog() -> Result<(), EvidenceDrawerErrorV1> {
    let catalog: Value = serde_json::from_str(OFFICIAL_A2UI_BASIC_CATALOG)?;
    if sha256(OFFICIAL_A2UI_BASIC_CATALOG.as_bytes()) != OFFICIAL_A2UI_BASIC_CATALOG_SHA256
        || catalog["$id"] != OFFICIAL_A2UI_CATALOG_ID_V091
        || ["Row", "Column", "List", "Text"].iter().any(|component| {
            !catalog["components"]
                .as_object()
                .is_some_and(|components| components.contains_key(*component))
        })
    {
        return Err(EvidenceDrawerErrorV1::InvalidArtifact(
            "vendored official A2UI basic catalog is incomplete".to_owned(),
        ));
    }
    Ok(())
}

fn validate_a2ui_stream(bytes: &[u8]) -> Result<(), EvidenceDrawerErrorV1> {
    validate_official_catalog()?;
    let lines = std::str::from_utf8(bytes).map_err(|error| {
        EvidenceDrawerErrorV1::InvalidArtifact(format!("A2UI stream UTF-8: {error}"))
    })?;
    let messages = lines
        .lines()
        .map(serde_json::from_str::<Value>)
        .collect::<Result<Vec<_>, _>>()?;
    let components = messages
        .get(1)
        .and_then(|message| message["updateComponents"]["components"].as_array())
        .ok_or_else(|| {
            EvidenceDrawerErrorV1::InvalidArtifact("A2UI stream has no component array".to_owned())
        })?;
    let component_kinds = components
        .iter()
        .map(|component| component["component"].as_str())
        .collect::<Option<std::collections::BTreeSet<_>>>()
        .ok_or_else(|| {
            EvidenceDrawerErrorV1::InvalidArtifact(
                "A2UI stream component has no official component kind".to_owned(),
            )
        })?;
    if messages.len() != 3
        || messages[0]["version"] != "v0.9"
        || messages[0]["createSurface"]["surfaceId"] != "gtkg-u04-drawer"
        || messages[0]["createSurface"]["catalogId"] != OFFICIAL_A2UI_CATALOG_ID_V091
        || messages[1]["updateComponents"]["surfaceId"] != "gtkg-u04-drawer"
        || component_kinds != std::collections::BTreeSet::from(["Column", "List", "Row", "Text"])
        || messages[2]["updateDataModel"]["surfaceId"] != "gtkg-u04-drawer"
        || messages[2]["updateDataModel"]["path"] != "/"
        || !messages[2]["updateDataModel"]["value"].is_object()
    {
        return Err(EvidenceDrawerErrorV1::InvalidArtifact(
            "A2UI stream is not a fixed official-catalog projection".to_owned(),
        ));
    }
    let data = &messages[2]["updateDataModel"]["value"];
    for field in [
        "records",
        "source_evidence",
        "relations",
        "claim_states",
        "unknown",
        "conflicts",
        "current",
        "replay",
        "provenance",
    ] {
        if data[field].is_null() {
            return Err(EvidenceDrawerErrorV1::InvalidArtifact(format!(
                "A2UI data model omitted U04 field {field}"
            )));
        }
    }
    for field in [
        "source_evidence_json",
        "relations_json",
        "claim_states_json",
        "unknown_json",
        "conflicts_json",
    ] {
        if data[field].as_str().is_none_or(str::is_empty) {
            return Err(EvidenceDrawerErrorV1::InvalidArtifact(format!(
                "A2UI data model omitted display binding {field}"
            )));
        }
    }
    Ok(())
}

fn render_html(projection: &EvidenceDrawerProjectionV1) -> Result<String, EvidenceDrawerErrorV1> {
    let encoded = serde_json::to_string(projection)?
        .replace('&', "\\u0026")
        .replace('<', "\\u003c")
        .replace('>', "\\u003e");
    Ok(format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src 'none'; connect-src 'none'; base-uri 'none'; form-action 'none'">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>GTKG Evidence Drawer</title>
<style>
:root {{ color-scheme: light dark; font-family: ui-sans-serif, system-ui, sans-serif; }}
body {{ margin: 0; background: #10151f; color: #edf2f7; }} main {{ display:grid; grid-template-columns:minmax(18rem,34%) 1fr; min-height:100vh; }} aside {{ padding:1rem; border-right:1px solid #374151; }} section {{ padding:1.25rem; }} button {{ display:block; width:100%; margin:.4rem 0; padding:.55rem; text-align:left; border:1px solid #4b5563; border-radius:.35rem; background:#172033; color:inherit; font:inherit; }} button[aria-pressed="true"] {{ border-color:#60a5fa; }} button:focus-visible {{ outline:3px solid #60a5fa; outline-offset:2px; }} #mode-buttons {{ display:flex; gap:.5rem; }} #mode-buttons button {{ width:auto; }} pre {{ white-space:pre-wrap; overflow-wrap:anywhere; background:#172033; padding:1rem; border-radius:.4rem; }} ul {{ list-style:none; padding:0; }}
</style>
</head>
<body>
<main data-evidence-drawer="q04-u04">
  <aside><h1>Evidence drawer</h1><p id="evidence-level"></p><ul id="records" aria-label="Verified evidence records"></ul></aside>
  <section aria-live="polite"><div id="mode-buttons"><button id="show-current" type="button" aria-pressed="true">Current</button><button id="show-replay" type="button" aria-pressed="false">Replay</button></div><h2 id="drawer-title"></h2><pre id="drawer-state"></pre><h2>Q04 source evidence</h2><pre id="drawer-evidence"></pre><h2>Relations / claims / unknown / conflicts</h2><pre id="drawer-facts"></pre></section>
</main>
<script id="drawer-data" type="application/json">{encoded}</script>
<script>
(() => {{
  const data = JSON.parse(document.getElementById('drawer-data').textContent);
  const records = document.getElementById('records'); const title = document.getElementById('drawer-title');
  const state = document.getElementById('drawer-state'); const evidence = document.getElementById('drawer-evidence');
  const facts = document.getElementById('drawer-facts'); const level = document.getElementById('evidence-level');
  let selected = data.records[0]; let mode = 'current';
  function showMode(next) {{ mode = next; document.getElementById('show-current').setAttribute('aria-pressed', String(mode === 'current')); document.getElementById('show-replay').setAttribute('aria-pressed', String(mode === 'replay')); state.textContent = JSON.stringify(mode === 'current' ? data.current : data.replay, null, 2); globalThis.__GTKG_U04__ = {{mode, selected_id:selected.entity_id, projection_sha256:data.projection_sha256}}; }}
  function showRecord(record) {{ selected = record; title.textContent = record.label + ' · ' + record.entity_id; evidence.textContent = JSON.stringify(data.source_evidence, null, 2); facts.textContent = JSON.stringify({{relations:data.relations, claim_states:data.claim_states, unknown:data.unknown, conflicts:data.conflicts}}, null, 2); records.querySelectorAll('button[data-record-id]').forEach((button) => button.setAttribute('aria-pressed', String(button.dataset.recordId === record.entity_id))); showMode(mode); }}
  for (const record of data.records) {{ const item = document.createElement('li'); const button = document.createElement('button'); button.type='button'; button.dataset.recordId=record.entity_id; button.setAttribute('aria-controls','drawer-evidence'); button.setAttribute('aria-pressed',String(record === selected)); button.textContent=record.label; button.addEventListener('click', () => showRecord(record)); item.append(button); records.append(item); }}
  document.getElementById('show-current').addEventListener('click', () => showMode('current')); document.getElementById('show-replay').addEventListener('click', () => showMode('replay'));
  level.textContent = 'Evidence level: ' + data.evidence_level; showRecord(selected); globalThis.__GTKG_U04_XSS__ = false;
}})();
</script>
</body>
</html>"#
    ))
}

fn authorize_plain_directory(
    context: &CallContext,
    requested: &Path,
) -> Result<PathBuf, EvidenceDrawerErrorV1> {
    let lexical = fs::symlink_metadata(requested).map_err(|source| EvidenceDrawerErrorV1::Io {
        path: requested.to_path_buf(),
        source,
    })?;
    if lexical.file_type().is_symlink() || !lexical.is_dir() {
        return Err(EvidenceDrawerErrorV1::InvalidArtifact(
            "drawer directory must be a non-symlink directory".to_owned(),
        ));
    }
    context
        .authorize_read(requested)
        .map_err(|error| EvidenceDrawerErrorV1::InvalidInput(error.to_string()))
}

fn read_exact_bytes(context: &CallContext, path: &Path) -> Result<Vec<u8>, EvidenceDrawerErrorV1> {
    let read = read_bound_regular_file(context, path)
        .map_err(|failure| EvidenceDrawerErrorV1::InvalidArtifact(failure.message))?;
    if read.bytes.is_empty() || read.bytes.len() as u64 > MAX_DRAWER_FILE_BYTES {
        return Err(EvidenceDrawerErrorV1::InvalidArtifact(
            "drawer artifact size is outside its bounded range".to_owned(),
        ));
    }
    Ok(read.bytes)
}

fn read_exact_json(context: &CallContext, path: &Path) -> Result<Value, EvidenceDrawerErrorV1> {
    serde_json::from_slice(&read_exact_bytes(context, path)?).map_err(EvidenceDrawerErrorV1::Json)
}

#[cfg(unix)]
fn mint_named_output_root(
    context: &CallContext,
    requested_parent: &Path,
    name: &OsStr,
    nonce: [u8; 16],
) -> Result<EvidenceDrawerOutputRootCapabilityV1, EvidenceDrawerErrorV1> {
    if context.effect_policy != EffectPolicy::WorkspaceWrite {
        return Err(EvidenceDrawerErrorV1::WriteDenied);
    }
    let context_root = context
        .workspace_root()
        .map(Path::to_path_buf)
        .ok_or(EvidenceDrawerErrorV1::CapabilityContextRejected)?;
    let (parent, parent_file, parent_identity) =
        open_exact_authorized_parent(context, requested_parent)?;
    if name.is_empty() {
        return Err(EvidenceDrawerErrorV1::CapabilityParentRejected);
    }
    match rustix::fs::mkdirat(&parent_file, name, rustix::fs::Mode::from_raw_mode(0o700)) {
        Ok(()) => {}
        Err(error) if error == rustix::io::Errno::EXIST => {
            return Err(EvidenceDrawerErrorV1::OutputExists(parent.join(name)));
        }
        Err(_) => return Err(EvidenceDrawerErrorV1::CapabilityMismatch),
    }
    parent_file
        .sync_all()
        .map_err(|source| EvidenceDrawerErrorV1::Io {
            path: parent.clone(),
            source,
        })?;
    let (_, _, observed_parent_identity) = open_directory_nofollow(&parent)?;
    if observed_parent_identity != parent_identity {
        return Err(EvidenceDrawerErrorV1::CapabilityMismatch);
    }
    let root = parent.join(name);
    let (_, root_file, root_identity) = open_directory_nofollow(&root)?;
    if root_identity.mode != 0o700 || !directory_is_empty(&root)? {
        return Err(EvidenceDrawerErrorV1::CapabilityMismatch);
    }
    root_file
        .sync_all()
        .map_err(|source| EvidenceDrawerErrorV1::Io {
            path: root.clone(),
            source,
        })?;
    let capability_id = format!("u04o1-{}", hex::encode(&nonce[..8]));
    let capability_digest = output_capability_digest(&context_root, &root, &root_identity, &nonce)?;
    Ok(EvidenceDrawerOutputRootCapabilityV1 {
        context_root,
        parent,
        parent_identity,
        root,
        root_identity,
        capability_id,
        capability_digest,
        nonce,
    })
}

#[cfg(unix)]
fn open_exact_authorized_parent(
    context: &CallContext,
    requested_parent: &Path,
) -> Result<(PathBuf, File, EvidenceDrawerDirectoryIdentityV1), EvidenceDrawerErrorV1> {
    if !requested_parent.is_absolute() {
        return Err(EvidenceDrawerErrorV1::CapabilityParentRejected);
    }
    let lexical = fs::symlink_metadata(requested_parent)
        .map_err(|_| EvidenceDrawerErrorV1::CapabilityParentRejected)?;
    if lexical.file_type().is_symlink() {
        return Err(EvidenceDrawerErrorV1::OutputParentSymlink(
            requested_parent.to_path_buf(),
        ));
    }
    if !lexical.is_dir()
        || !context
            .authorized_lexical_roots()
            .iter()
            .any(|root| root == requested_parent)
    {
        return Err(EvidenceDrawerErrorV1::CapabilityParentRejected);
    }
    let authorized = context
        .authorize_write(requested_parent)
        .map_err(|_| EvidenceDrawerErrorV1::CapabilityParentRejected)?;
    if !context
        .authorized_roots()
        .iter()
        .any(|root| root == &authorized)
    {
        return Err(EvidenceDrawerErrorV1::CapabilityParentRejected);
    }
    let (canonical, file, identity) = open_directory_nofollow(&authorized)?;
    if canonical
        != fs::canonicalize(requested_parent)
            .map_err(|_| EvidenceDrawerErrorV1::CapabilityParentRejected)?
    {
        return Err(EvidenceDrawerErrorV1::CapabilityParentRejected);
    }
    Ok((requested_parent.to_path_buf(), file, identity))
}

#[cfg(unix)]
fn open_directory_nofollow(
    path: &Path,
) -> Result<(PathBuf, File, EvidenceDrawerDirectoryIdentityV1), EvidenceDrawerErrorV1> {
    use std::os::unix::fs::MetadataExt;

    let descriptor = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|_| EvidenceDrawerErrorV1::CapabilityMismatch)?;
    let file = File::from(descriptor);
    let metadata = file
        .metadata()
        .map_err(|_| EvidenceDrawerErrorV1::CapabilityMismatch)?;
    if !metadata.is_dir() {
        return Err(EvidenceDrawerErrorV1::CapabilityMismatch);
    }
    let canonical =
        fs::canonicalize(path).map_err(|_| EvidenceDrawerErrorV1::CapabilityMismatch)?;
    Ok((
        canonical,
        file,
        EvidenceDrawerDirectoryIdentityV1 {
            device: metadata.dev(),
            inode: metadata.ino(),
            mode: metadata.mode() & 0o777,
        },
    ))
}

#[cfg(unix)]
fn directory_is_empty(path: &Path) -> Result<bool, EvidenceDrawerErrorV1> {
    let mut entries = fs::read_dir(path).map_err(|source| EvidenceDrawerErrorV1::Io {
        path: path.to_path_buf(),
        source,
    })?;
    entries
        .next()
        .transpose()
        .map(|entry| entry.is_none())
        .map_err(|source| EvidenceDrawerErrorV1::Io {
            path: path.to_path_buf(),
            source,
        })
}

#[cfg(unix)]
fn output_capability_digest(
    context_root: &Path,
    root: &Path,
    identity: &EvidenceDrawerDirectoryIdentityV1,
    nonce: &[u8; 16],
) -> Result<String, EvidenceDrawerErrorV1> {
    canonical_json_sha256(&json!({
        "schema_version": "gtkg.u04-evidence-drawer-output-capability/v1",
        "context_root": context_root,
        "root": root,
        "device": identity.device,
        "inode": identity.inode,
        "mode": identity.mode,
        "nonce": hex::encode(nonce),
    }))
    .map_err(EvidenceDrawerErrorV1::Json)
}

fn validate_output_capability_context(
    context: &CallContext,
    capability: &EvidenceDrawerOutputRootCapabilityV1,
) -> Result<(), EvidenceDrawerErrorV1> {
    if context.effect_policy != EffectPolicy::WorkspaceWrite {
        return Err(EvidenceDrawerErrorV1::WriteDenied);
    }
    let current_root = context
        .workspace_root()
        .ok_or(EvidenceDrawerErrorV1::CapabilityContextRejected)?;
    if current_root != capability.context_root
        || !context
            .authorized_lexical_roots()
            .iter()
            .any(|root| root == &capability.parent)
        || !context
            .authorized_roots()
            .iter()
            .any(|root| root == current_root)
    {
        return Err(EvidenceDrawerErrorV1::CapabilityContextRejected);
    }
    context
        .authorize_write(&capability.parent)
        .map_err(|_| EvidenceDrawerErrorV1::CapabilityContextRejected)?;
    Ok(())
}

#[cfg(unix)]
fn validate_output_capability(
    capability: &EvidenceDrawerOutputRootCapabilityV1,
) -> Result<File, EvidenceDrawerErrorV1> {
    let (parent, parent_file, parent_identity) = open_directory_nofollow(&capability.parent)?;
    if parent_identity != capability.parent_identity
        || parent
            != fs::canonicalize(&capability.parent)
                .map_err(|_| EvidenceDrawerErrorV1::CapabilityMismatch)?
    {
        return Err(EvidenceDrawerErrorV1::CapabilityMismatch);
    }
    let name = capability
        .root
        .file_name()
        .ok_or(EvidenceDrawerErrorV1::CapabilityMismatch)?;
    let descriptor = rustix::fs::openat(
        &parent_file,
        name,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|_| EvidenceDrawerErrorV1::CapabilityMismatch)?;
    let root_file = File::from(descriptor);
    let (_, root_check, root_identity) = open_directory_nofollow(&capability.root)?;
    drop(root_check);
    if root_identity != capability.root_identity
        || root_identity.mode != 0o700
        || capability.root.parent() != Some(capability.parent.as_path())
        || capability.capability_digest
            != output_capability_digest(
                &capability.context_root,
                &capability.root,
                &capability.root_identity,
                &capability.nonce,
            )?
    {
        return Err(EvidenceDrawerErrorV1::CapabilityMismatch);
    }
    Ok(root_file)
}

#[cfg(unix)]
fn validate_fresh_output_capability(
    capability: &EvidenceDrawerOutputRootCapabilityV1,
) -> Result<File, EvidenceDrawerErrorV1> {
    let root_file = validate_output_capability(capability)?;
    if !directory_is_empty(&capability.root)? {
        return Err(EvidenceDrawerErrorV1::CapabilityMismatch);
    }
    Ok(root_file)
}

#[cfg(not(unix))]
fn validate_fresh_output_capability(
    _capability: &EvidenceDrawerOutputRootCapabilityV1,
) -> Result<File, EvidenceDrawerErrorV1> {
    Err(EvidenceDrawerErrorV1::UnsupportedPlatform)
}

#[cfg(unix)]
fn create_private_child_directory(
    root: &File,
    name: &OsStr,
    path: &Path,
) -> Result<File, EvidenceDrawerErrorV1> {
    rustix::fs::mkdirat(root, name, rustix::fs::Mode::from_raw_mode(0o700))
        .map_err(|_| EvidenceDrawerErrorV1::CapabilityMismatch)?;
    let descriptor = rustix::fs::openat(
        root,
        name,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|_| EvidenceDrawerErrorV1::CapabilityMismatch)?;
    let file = File::from(descriptor);
    file.sync_all()
        .map_err(|source| EvidenceDrawerErrorV1::Io {
            path: path.to_path_buf(),
            source,
        })?;
    Ok(file)
}

#[cfg(unix)]
fn write_private_new_file(
    root: &File,
    name: &OsStr,
    path: &Path,
    bytes: &[u8],
) -> Result<(), EvidenceDrawerErrorV1> {
    use std::os::unix::fs::MetadataExt;

    if bytes.is_empty() || bytes.len() as u64 > MAX_DRAWER_FILE_BYTES {
        return Err(EvidenceDrawerErrorV1::InvalidArtifact(
            "drawer output file size is outside its bounded range".to_owned(),
        ));
    }
    let descriptor = rustix::fs::openat(
        root,
        name,
        rustix::fs::OFlags::WRONLY
            | rustix::fs::OFlags::CREATE
            | rustix::fs::OFlags::EXCL
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::from_raw_mode(0o600),
    )
    .map_err(|_| EvidenceDrawerErrorV1::CapabilityMismatch)?;
    let mut file = File::from(descriptor);
    rustix::fs::fchmod(&file, rustix::fs::Mode::from_raw_mode(0o600))
        .map_err(|_| EvidenceDrawerErrorV1::CapabilityMismatch)?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|source| EvidenceDrawerErrorV1::Io {
            path: path.to_path_buf(),
            source,
        })?;
    let metadata = file
        .metadata()
        .map_err(|_| EvidenceDrawerErrorV1::CapabilityMismatch)?;
    if !metadata.is_file() || metadata.nlink() != 1 || metadata.mode() & 0o777 != 0o600 {
        return Err(EvidenceDrawerErrorV1::CapabilityMismatch);
    }
    Ok(())
}

#[cfg(not(unix))]
fn create_private_child_directory(
    _root: &File,
    _name: &OsStr,
    _path: &Path,
) -> Result<File, EvidenceDrawerErrorV1> {
    Err(EvidenceDrawerErrorV1::UnsupportedPlatform)
}

#[cfg(not(unix))]
fn write_private_new_file(
    _root: &File,
    _name: &OsStr,
    _path: &Path,
    _bytes: &[u8],
) -> Result<(), EvidenceDrawerErrorV1> {
    Err(EvidenceDrawerErrorV1::UnsupportedPlatform)
}

#[cfg(unix)]
fn validate_written_output_capability(
    capability: &EvidenceDrawerOutputRootCapabilityV1,
) -> Result<(), EvidenceDrawerErrorV1> {
    let _root = validate_output_capability(capability)?;
    Ok(())
}

#[cfg(not(unix))]
fn validate_written_output_capability(
    _capability: &EvidenceDrawerOutputRootCapabilityV1,
) -> Result<(), EvidenceDrawerErrorV1> {
    Err(EvidenceDrawerErrorV1::UnsupportedPlatform)
}

fn required_string(value: &Value, label: &str) -> Result<String, EvidenceDrawerErrorV1> {
    value
        .as_str()
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| EvidenceDrawerErrorV1::Q04Binding(format!("{label} is absent")))
}

fn is_sha256_identity(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hexadecimal| {
        hexadecimal.len() == 64 && hexadecimal.bytes().all(|byte| byte.is_ascii_hexdigit())
    })
}

fn embedded_json(html: &str, id: &str) -> Result<Value, EvidenceDrawerErrorV1> {
    let prefix = format!("<script id=\"{id}\" type=\"application/json\">");
    let (_, remainder) = html.split_once(&prefix).ok_or_else(|| {
        EvidenceDrawerErrorV1::U03Binding(format!("Explorer index has no {id} projection"))
    })?;
    let (payload, _) = remainder.split_once("</script>").ok_or_else(|| {
        EvidenceDrawerErrorV1::U03Binding(format!("Explorer {id} projection has no closing tag"))
    })?;
    serde_json::from_str(payload).map_err(|error| {
        EvidenceDrawerErrorV1::U03Binding(format!(
            "Explorer {id} projection is invalid JSON: {error}"
        ))
    })
}

fn current_field(current: &Value, field: &str) -> Result<String, EvidenceDrawerErrorV1> {
    current[field]
        .as_str()
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| {
            EvidenceDrawerErrorV1::CurrentBinding(format!(
                "current.get result has no non-empty {field}"
            ))
        })
}

fn sha256(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}
