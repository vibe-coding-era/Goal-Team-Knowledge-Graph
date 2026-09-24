//! U03 local static Graph Explorer.
//!
//! This writer executes Q04 only against exact, context-authorized file-index
//! artifacts, then presents those locally bound results as a `file:` document.
//! It never accepts caller-supplied response JSON, reaches a network service,
//! executes target code, or accepts raw HTML from the caller.

use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use gtkg_protocol::v03::query::FileQueryExpectedIdentitiesV1;
use gtkg_protocol::{FileReceiptRef, canonical_json_sha256};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;

use super::graph_query::{FileGraphQueryOperationV1, execute_file_graph_operation_v1};
use crate::{CallContext, EffectPolicy};

pub const STATIC_GRAPH_EXPLORER_SCHEMA_V1: &str = "gtkg.static-graph-explorer/v1";
pub const STATIC_GRAPH_EXPLORER_SCHEMA_V2: &str = "gtkg.static-graph-explorer/v2";
const MANIFEST_SCHEMA_V2: &str = "gtkg.static-graph-explorer-manifest/v2";
const OUTPUT_ROOT_ATTEMPTS_V2: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticGraphExplorerInputV1 {
    pub search: Value,
    pub neighbors: Value,
    pub path: Value,
    pub impact: Value,
    pub trace: Value,
}

/// The only current Explorer input.  Unlike V1 it contains no caller-supplied
/// response JSON: every view is freshly obtained from the exact Q04 artifact
/// roots and receipt references below.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticGraphExplorerArtifactInputV2 {
    pub query_root: PathBuf,
    pub query_manifest_ref: FileReceiptRef,
    pub evidence_root: PathBuf,
    pub evidence_manifest_ref: FileReceiptRef,
    pub expected_identities: FileQueryExpectedIdentitiesV1,
    pub search_query: String,
    pub primary_entity_id: String,
    pub path_target_entity_id: String,
}

/// A non-serializable write capability for exactly one fresh, owner-only
/// Explorer root.  A pathname, receipt, or serialized data cannot recreate
/// this capability.
pub struct StaticGraphExplorerOutputRootCapabilityV2 {
    parent: PathBuf,
    parent_identity: ExplorerDirectoryIdentityV2,
    root: PathBuf,
    root_identity: ExplorerDirectoryIdentityV2,
    capability_id: String,
    capability_digest: String,
    nonce: [u8; 16],
}

impl std::fmt::Debug for StaticGraphExplorerOutputRootCapabilityV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StaticGraphExplorerOutputRootCapabilityV2")
            .field("root", &self.root)
            .field("capability_id", &self.capability_id)
            .field("capability_digest", &self.capability_digest)
            .finish_non_exhaustive()
    }
}

impl StaticGraphExplorerOutputRootCapabilityV2 {
    pub fn path(&self) -> &Path {
        &self.root
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExplorerDirectoryIdentityV2 {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(unix)]
    mode: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct StaticGraphExplorerRecordV1 {
    entity_id: String,
    label: String,
    kind: String,
    knowledge_state: String,
    evidence: Vec<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct StaticGraphExplorerViewsV1 {
    neighbors: Value,
    path: Value,
    impact: Value,
    trace: Value,
}

/// An opaque, serializable browser projection.  Its fields are intentionally
/// private and it does not implement `Deserialize`, so only this module's
/// artifact-bound builder can create one for the capability writer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StaticGraphExplorerProjectionV1 {
    schema_version: String,
    source_kind: String,
    source_snapshot_exact_set_sha256: String,
    graph_sha256: String,
    overlay_sha256: String,
    records: Vec<StaticGraphExplorerRecordV1>,
    views: StaticGraphExplorerViewsV1,
    projection_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StaticGraphExplorerReceiptV1 {
    pub schema_version: String,
    pub source_kind: String,
    pub site_root: String,
    pub index_relative_path: String,
    pub index_sha256: String,
    pub site_manifest_sha256: String,
    pub projection_sha256: String,
    pub network_calls: u64,
    pub database_reads: u64,
    pub target_execution_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StaticGraphExplorerReceiptV2 {
    pub schema_version: String,
    pub source_kind: String,
    pub site_root: String,
    pub index_relative_path: String,
    pub index_sha256: String,
    pub site_manifest_sha256: String,
    pub projection_sha256: String,
    pub output_root_capability_id: String,
    pub output_root_capability_digest: String,
    pub network_calls: u64,
    pub database_reads: u64,
    pub target_execution_count: u64,
}

#[derive(Debug, Error)]
pub enum StaticGraphExplorerErrorV1 {
    #[error("invalid static Explorer input: {0}")]
    InvalidInput(String),
    #[error("static Explorer requires workspace-write context")]
    WriteDenied,
    #[error("naked caller-supplied Q04 response input is no longer accepted")]
    LegacyInputRejected,
    #[error("actual Q04 artifact binding was rejected: {0}")]
    Q04ArtifactRejected(String),
    #[error("Explorer output parent is not an exact CallContext-authorized root")]
    CapabilityParentRejected,
    #[error("Explorer output parent is a symlink: {0}")]
    OutputParentSymlink(PathBuf),
    #[error("an explicit Explorer output-root capability is required")]
    CapabilityRequired,
    #[error("Explorer output-root capability no longer matches a fresh 0700 root")]
    CapabilityMismatch,
    #[error("Explorer output-root capabilities require Unix dirfd semantics")]
    UnsupportedPlatform,
    #[error("static Explorer output already exists: {0}")]
    OutputExists(PathBuf),
    #[error("static Explorer I/O failed at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("static Explorer JSON encoding failed: {0}")]
    Json(#[from] serde_json::Error),
}

impl StaticGraphExplorerErrorV1 {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidInput(_) => "E_EXPLORER_INPUT_INVALID",
            Self::WriteDenied => "E_EXPLORER_WRITE_DENIED",
            Self::LegacyInputRejected => "E_EXPLORER_LEGACY_INPUT_REJECTED",
            Self::Q04ArtifactRejected(_) => "E_EXPLORER_Q04_ARTIFACT_REJECTED",
            Self::CapabilityParentRejected => "E_EXPLORER_CAPABILITY_PARENT_REJECTED",
            Self::OutputParentSymlink(_) => "E_EXPLORER_OUTPUT_PARENT_SYMLINK",
            Self::CapabilityRequired => "E_EXPLORER_CAPABILITY_REQUIRED",
            Self::CapabilityMismatch => "E_EXPLORER_CAPABILITY_MISMATCH",
            Self::UnsupportedPlatform => "E_EXPLORER_UNSUPPORTED_PLATFORM",
            Self::OutputExists(_) => "E_EXPLORER_OUTPUT_EXISTS",
            Self::Io { .. } => "E_EXPLORER_IO",
            Self::Json(_) => "E_EXPLORER_JSON",
        }
    }
}

/// Retained only so callers that still hold naked response JSON fail closed.
///
/// V2 intentionally removes the path from arbitrary JSON to a browser page;
/// use [`build_static_graph_explorer_from_artifacts_v2`] instead.
pub fn build_static_graph_explorer_v1(
    _input: &StaticGraphExplorerInputV1,
) -> Result<StaticGraphExplorerProjectionV1, StaticGraphExplorerErrorV1> {
    Err(StaticGraphExplorerErrorV1::LegacyInputRejected)
}

/// Execute the fixed Explorer journeys against the supplied, context-authorized
/// Q03/Q04 artifacts.  The resulting responses are local variables only: the
/// public API never accepts a self-claimed response envelope.
pub fn build_static_graph_explorer_from_artifacts_v2(
    context: &CallContext,
    input: &StaticGraphExplorerArtifactInputV2,
) -> Result<StaticGraphExplorerProjectionV1, StaticGraphExplorerErrorV1> {
    validate_artifact_input_v2(context, input)?;
    let search = execute_q04_v2(
        context,
        input,
        FileGraphQueryOperationV1::Search,
        json!({"query": input.search_query, "max_results": 64}),
    )?;
    let matches = search["result"]["matches"].as_array().ok_or_else(|| {
        StaticGraphExplorerErrorV1::Q04ArtifactRejected(
            "graph.search returned no matches array".to_owned(),
        )
    })?;
    if !matches.iter().any(|entry| {
        entry["entity_id"]
            .as_str()
            .is_some_and(|entity_id| entity_id == input.primary_entity_id)
    }) {
        return Err(StaticGraphExplorerErrorV1::Q04ArtifactRejected(
            "primary_entity_id is not present in the actual graph.search response".to_owned(),
        ));
    }
    let neighbors = execute_q04_v2(
        context,
        input,
        FileGraphQueryOperationV1::Neighbors,
        json!({"node_id": input.primary_entity_id, "direction": "outgoing", "max_results": 64}),
    )?;
    let path = execute_q04_v2(
        context,
        input,
        FileGraphQueryOperationV1::Path,
        json!({
            "source_node_id": input.primary_entity_id,
            "target_node_id": input.path_target_entity_id,
            "max_depth": 8,
        }),
    )?;
    let impact = execute_q04_v2(
        context,
        input,
        FileGraphQueryOperationV1::Impact,
        json!({"node_id": input.primary_entity_id, "max_depth": 8, "max_results": 64}),
    )?;
    let trace = execute_q04_v2(
        context,
        input,
        FileGraphQueryOperationV1::Trace,
        json!({"entity_id": input.primary_entity_id}),
    )?;
    projection_from_verified_q04_responses_v2(input, &search, &neighbors, &path, &impact, &trace)
}

fn projection_from_verified_q04_responses_v2(
    input: &StaticGraphExplorerArtifactInputV2,
    search_response: &Value,
    neighbors_response: &Value,
    path_response: &Value,
    impact_response: &Value,
    trace_response: &Value,
) -> Result<StaticGraphExplorerProjectionV1, StaticGraphExplorerErrorV1> {
    let search = response_identity_v2(
        search_response,
        "graph.search",
        &input.expected_identities,
        true,
    )?;
    for (response, operation) in [
        (neighbors_response, "graph.neighbors"),
        (path_response, "graph.path"),
        (impact_response, "graph.impact"),
        (trace_response, "graph.trace"),
    ] {
        let observed =
            response_identity_v2(response, operation, &input.expected_identities, false)?;
        if observed.source != search.source || observed.graph != search.graph {
            return Err(StaticGraphExplorerErrorV1::Q04ArtifactRejected(format!(
                "{operation} response does not bind the actual graph.search identity"
            )));
        }
    }
    let matches = search_response["result"]["matches"]
        .as_array()
        .ok_or_else(|| {
            StaticGraphExplorerErrorV1::Q04ArtifactRejected(
                "actual graph.search matches must be an array".to_owned(),
            )
        })?;
    if matches.is_empty() {
        return Err(StaticGraphExplorerErrorV1::Q04ArtifactRejected(
            "Explorer requires at least one actual graph.search match".to_owned(),
        ));
    }
    let evidence = search_response["evidence_pack"]["evidence"]
        .as_array()
        .ok_or_else(|| {
            StaticGraphExplorerErrorV1::Q04ArtifactRejected(
                "actual graph.search evidence pack must be an array".to_owned(),
            )
        })?
        .clone();
    if evidence.is_empty() {
        return Err(StaticGraphExplorerErrorV1::Q04ArtifactRejected(
            "Explorer requires evidence-bearing Q04 search results".to_owned(),
        ));
    }
    let mut records = matches
        .iter()
        .map(|entry| record_from_match(entry, &evidence))
        .collect::<Result<Vec<_>, _>>()?;
    records.sort_by(|left, right| left.entity_id.cmp(&right.entity_id));
    records.dedup_by(|left, right| left.entity_id == right.entity_id);
    let mut projection = StaticGraphExplorerProjectionV1 {
        schema_version: STATIC_GRAPH_EXPLORER_SCHEMA_V2.to_owned(),
        source_kind: "q04_file_index_artifacts".to_owned(),
        source_snapshot_exact_set_sha256: search.source,
        graph_sha256: search.graph,
        overlay_sha256: search.overlay,
        records,
        views: StaticGraphExplorerViewsV1 {
            neighbors: neighbors_response["result"].clone(),
            path: path_response["result"].clone(),
            impact: impact_response["result"].clone(),
            trace: trace_response["result"].clone(),
        },
        projection_sha256: String::new(),
    };
    projection.projection_sha256 = projection_digest(&projection)?;
    Ok(projection)
}

/// Mint a capability for one fresh `0700` output root directly below an exact
/// CallContext-authorized parent.  The caller supplies no output-root path.
pub fn create_static_graph_explorer_output_root_v2(
    context: &CallContext,
    authorized_parent: &Path,
) -> Result<StaticGraphExplorerOutputRootCapabilityV2, StaticGraphExplorerErrorV1> {
    if context.effect_policy != EffectPolicy::WorkspaceWrite {
        return Err(StaticGraphExplorerErrorV1::WriteDenied);
    }
    #[cfg(not(unix))]
    {
        let _ = (context, authorized_parent);
        return Err(StaticGraphExplorerErrorV1::UnsupportedPlatform);
    }
    #[cfg(unix)]
    {
        let (parent, parent_file, parent_identity) =
            open_exact_authorized_parent_v2(context, authorized_parent)?;
        let mut nonce = [0_u8; 16];
        getrandom::fill(&mut nonce).map_err(|_| StaticGraphExplorerErrorV1::CapabilityMismatch)?;
        for attempt in 0..OUTPUT_ROOT_ATTEMPTS_V2 {
            let name = OsString::from(format!(
                ".gtkg-u03-explorer-{}-{}-{attempt}",
                std::process::id(),
                hex::encode(&nonce[..8])
            ));
            match rustix::fs::mkdirat(&parent_file, &name, rustix::fs::Mode::from_raw_mode(0o700)) {
                Ok(()) => {}
                Err(error) if error == rustix::io::Errno::EXIST => continue,
                Err(_) => return Err(StaticGraphExplorerErrorV1::CapabilityMismatch),
            }
            parent_file
                .sync_all()
                .map_err(|source| StaticGraphExplorerErrorV1::Io {
                    path: parent.clone(),
                    source,
                })?;
            let (_, _, observed_parent_identity) = open_directory_nofollow_v2(&parent)?;
            if observed_parent_identity != parent_identity {
                return Err(StaticGraphExplorerErrorV1::CapabilityMismatch);
            }
            let root = parent.join(&name);
            let (_, root_file, root_identity) = open_directory_nofollow_v2(&root)?;
            if root_identity.mode != 0o700 || !directory_is_empty_v2(&root)? {
                return Err(StaticGraphExplorerErrorV1::CapabilityMismatch);
            }
            root_file
                .sync_all()
                .map_err(|source| StaticGraphExplorerErrorV1::Io {
                    path: root.clone(),
                    source,
                })?;
            let capability_id = format!("u03o2-{}", hex::encode(&nonce[..8]));
            let capability_digest = capability_digest_v2(&root, &root_identity, &nonce)?;
            return Ok(StaticGraphExplorerOutputRootCapabilityV2 {
                parent,
                parent_identity,
                root,
                root_identity,
                capability_id,
                capability_digest,
                nonce,
            });
        }
        Err(StaticGraphExplorerErrorV1::CapabilityMismatch)
    }
}

/// Legacy raw-path writer retained only to reject accidental or adversarial
/// use.  Current callers must hold an output-root capability.
pub fn write_static_graph_explorer_v1(
    _context: &CallContext,
    _output_root: &Path,
    _projection: &StaticGraphExplorerProjectionV1,
) -> Result<StaticGraphExplorerReceiptV1, StaticGraphExplorerErrorV1> {
    Err(StaticGraphExplorerErrorV1::CapabilityRequired)
}

/// Write exactly one self-contained local HTML document into a freshly minted
/// capability root.  The root is re-opened and identity-checked before and
/// after writing; no arbitrary caller path is accepted here.
pub fn write_static_graph_explorer_with_capability_v2(
    capability: &StaticGraphExplorerOutputRootCapabilityV2,
    projection: &StaticGraphExplorerProjectionV1,
) -> Result<StaticGraphExplorerReceiptV2, StaticGraphExplorerErrorV1> {
    validate_projection(projection)?;
    let root_file = validate_fresh_output_capability_v2(capability)?;
    let index_path = capability.root.join("index.html");
    let html = render_html(projection)?;
    write_private_new_file_v2(
        &root_file,
        OsStr::new("index.html"),
        &index_path,
        html.as_bytes(),
    )?;
    let index_sha256 = sha256(html.as_bytes());
    let manifest = json!({
        "schema_version": MANIFEST_SCHEMA_V2,
        "index_relative_path": "index.html",
        "index_sha256": index_sha256,
        "projection_sha256": projection.projection_sha256,
        "source_kind": projection.source_kind,
    });
    let manifest_sha256 = canonical_json_sha256(&manifest)?;
    let manifest_path = capability.root.join("manifest.json");
    write_private_new_file_v2(
        &root_file,
        OsStr::new("manifest.json"),
        &manifest_path,
        &serde_json::to_vec_pretty(&manifest)?,
    )?;
    validate_written_output_capability_v2(capability, &index_path, &manifest_path)?;
    Ok(StaticGraphExplorerReceiptV2 {
        schema_version: "gtkg.static-graph-explorer-receipt/v2".to_owned(),
        source_kind: projection.source_kind.clone(),
        site_root: capability.root.display().to_string(),
        index_relative_path: "index.html".to_owned(),
        index_sha256,
        site_manifest_sha256: manifest_sha256,
        projection_sha256: projection.projection_sha256.clone(),
        output_root_capability_id: capability.capability_id.clone(),
        output_root_capability_digest: capability.capability_digest.clone(),
        network_calls: 0,
        database_reads: 0,
        target_execution_count: 0,
    })
}

fn validate_artifact_input_v2(
    context: &CallContext,
    input: &StaticGraphExplorerArtifactInputV2,
) -> Result<(), StaticGraphExplorerErrorV1> {
    for (name, root) in [
        ("query_root", &input.query_root),
        ("evidence_root", &input.evidence_root),
    ] {
        let metadata = fs::symlink_metadata(root).map_err(|error| {
            StaticGraphExplorerErrorV1::Q04ArtifactRejected(format!(
                "{name} cannot be inspected: {error}"
            ))
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(StaticGraphExplorerErrorV1::Q04ArtifactRejected(format!(
                "{name} must be an existing non-symlink directory"
            )));
        }
        context.authorize_read(root).map_err(|error| {
            StaticGraphExplorerErrorV1::Q04ArtifactRejected(format!(
                "{name} is outside the current CallContext: {error}"
            ))
        })?;
    }
    for (name, receipt) in [
        ("query_manifest_ref", &input.query_manifest_ref),
        ("evidence_manifest_ref", &input.evidence_manifest_ref),
    ] {
        receipt.validate().map_err(|error| {
            StaticGraphExplorerErrorV1::Q04ArtifactRejected(format!(
                "{name} is not an exact FileReceiptRef: {error}"
            ))
        })?;
        if !receipt.path.starts_with("manifests/") {
            return Err(StaticGraphExplorerErrorV1::Q04ArtifactRejected(format!(
                "{name} must bind a manifest receipt below manifests/"
            )));
        }
    }
    for (name, identity) in [
        (
            "source_identity",
            &input.expected_identities.source_identity,
        ),
        ("graph_identity", &input.expected_identities.graph_identity),
        (
            "overlay_identity",
            &input.expected_identities.overlay_identity,
        ),
    ] {
        if !is_sha256_identity_v2(identity) {
            return Err(StaticGraphExplorerErrorV1::Q04ArtifactRejected(format!(
                "{name} is not a canonical sha256 identity"
            )));
        }
    }
    for (name, value) in [
        ("search_query", &input.search_query),
        ("primary_entity_id", &input.primary_entity_id),
        ("path_target_entity_id", &input.path_target_entity_id),
    ] {
        if value.trim().is_empty() || value.len() > 4_096 || value.chars().any(char::is_control) {
            return Err(StaticGraphExplorerErrorV1::Q04ArtifactRejected(format!(
                "{name} is not a bounded non-control Q04 request value"
            )));
        }
    }
    Ok(())
}

fn execute_q04_v2(
    context: &CallContext,
    input: &StaticGraphExplorerArtifactInputV2,
    operation: FileGraphQueryOperationV1,
    payload: Value,
) -> Result<Value, StaticGraphExplorerErrorV1> {
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
    .map_err(|error| {
        StaticGraphExplorerErrorV1::Q04ArtifactRejected(format!("{}: {error}", error.code()))
    })
}

fn is_sha256_identity_v2(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hexadecimal| {
        hexadecimal.len() == 64 && hexadecimal.bytes().all(|byte| byte.is_ascii_hexdigit())
    })
}

#[cfg(unix)]
fn open_exact_authorized_parent_v2(
    context: &CallContext,
    requested_parent: &Path,
) -> Result<(PathBuf, File, ExplorerDirectoryIdentityV2), StaticGraphExplorerErrorV1> {
    if !requested_parent.is_absolute() {
        return Err(StaticGraphExplorerErrorV1::CapabilityParentRejected);
    }
    let lexical = fs::symlink_metadata(requested_parent)
        .map_err(|_| StaticGraphExplorerErrorV1::CapabilityParentRejected)?;
    if lexical.file_type().is_symlink() {
        return Err(StaticGraphExplorerErrorV1::OutputParentSymlink(
            requested_parent.to_path_buf(),
        ));
    }
    if !lexical.is_dir()
        || !context
            .authorized_lexical_roots()
            .iter()
            .any(|root| root == requested_parent)
    {
        return Err(StaticGraphExplorerErrorV1::CapabilityParentRejected);
    }
    let authorized = context
        .authorize_write(requested_parent)
        .map_err(|_| StaticGraphExplorerErrorV1::CapabilityParentRejected)?;
    if !context
        .authorized_roots()
        .iter()
        .any(|root| root == &authorized)
    {
        return Err(StaticGraphExplorerErrorV1::CapabilityParentRejected);
    }
    let (canonical, file, identity) = open_directory_nofollow_v2(&authorized)?;
    if canonical
        != fs::canonicalize(requested_parent)
            .map_err(|_| StaticGraphExplorerErrorV1::CapabilityParentRejected)?
    {
        return Err(StaticGraphExplorerErrorV1::CapabilityParentRejected);
    }
    Ok((requested_parent.to_path_buf(), file, identity))
}

#[cfg(unix)]
fn open_directory_nofollow_v2(
    path: &Path,
) -> Result<(PathBuf, File, ExplorerDirectoryIdentityV2), StaticGraphExplorerErrorV1> {
    use std::os::unix::fs::MetadataExt;

    let descriptor = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|_| StaticGraphExplorerErrorV1::CapabilityMismatch)?;
    let file = File::from(descriptor);
    let metadata = file
        .metadata()
        .map_err(|_| StaticGraphExplorerErrorV1::CapabilityMismatch)?;
    if !metadata.is_dir() {
        return Err(StaticGraphExplorerErrorV1::CapabilityMismatch);
    }
    let canonical =
        fs::canonicalize(path).map_err(|_| StaticGraphExplorerErrorV1::CapabilityMismatch)?;
    Ok((
        canonical,
        file,
        ExplorerDirectoryIdentityV2 {
            device: metadata.dev(),
            inode: metadata.ino(),
            mode: metadata.mode() & 0o777,
        },
    ))
}

#[cfg(unix)]
fn directory_is_empty_v2(path: &Path) -> Result<bool, StaticGraphExplorerErrorV1> {
    let mut entries = fs::read_dir(path).map_err(|source| StaticGraphExplorerErrorV1::Io {
        path: path.to_path_buf(),
        source,
    })?;
    entries
        .next()
        .transpose()
        .map(|entry| entry.is_none())
        .map_err(|source| StaticGraphExplorerErrorV1::Io {
            path: path.to_path_buf(),
            source,
        })
}

#[cfg(unix)]
fn capability_digest_v2(
    root: &Path,
    identity: &ExplorerDirectoryIdentityV2,
    nonce: &[u8; 16],
) -> Result<String, StaticGraphExplorerErrorV1> {
    canonical_json_sha256(&json!({
        "schema_version": "gtkg.static-graph-explorer-output-capability/v2",
        "root": root,
        "device": identity.device,
        "inode": identity.inode,
        "mode": identity.mode,
        "nonce": hex::encode(nonce),
    }))
    .map_err(StaticGraphExplorerErrorV1::Json)
}

#[cfg(unix)]
fn validate_output_capability_identity_v2(
    capability: &StaticGraphExplorerOutputRootCapabilityV2,
) -> Result<File, StaticGraphExplorerErrorV1> {
    let (parent, _, parent_identity) = open_directory_nofollow_v2(&capability.parent)?;
    let (root, root_file, root_identity) = open_directory_nofollow_v2(&capability.root)?;
    if parent
        != fs::canonicalize(&capability.parent)
            .map_err(|_| StaticGraphExplorerErrorV1::CapabilityMismatch)?
        || parent_identity != capability.parent_identity
        || root
            != fs::canonicalize(&capability.root)
                .map_err(|_| StaticGraphExplorerErrorV1::CapabilityMismatch)?
        || root_identity != capability.root_identity
        || root_identity.mode != 0o700
        || capability.root.parent() != Some(capability.parent.as_path())
        || capability.capability_digest
            != capability_digest_v2(
                &capability.root,
                &capability.root_identity,
                &capability.nonce,
            )?
    {
        return Err(StaticGraphExplorerErrorV1::CapabilityMismatch);
    }
    Ok(root_file)
}

#[cfg(unix)]
fn validate_fresh_output_capability_v2(
    capability: &StaticGraphExplorerOutputRootCapabilityV2,
) -> Result<File, StaticGraphExplorerErrorV1> {
    let root_file = validate_output_capability_identity_v2(capability)?;
    if !directory_is_empty_v2(&capability.root)? {
        return Err(StaticGraphExplorerErrorV1::CapabilityMismatch);
    }
    Ok(root_file)
}

#[cfg(not(unix))]
fn validate_fresh_output_capability_v2(
    _capability: &StaticGraphExplorerOutputRootCapabilityV2,
) -> Result<File, StaticGraphExplorerErrorV1> {
    Err(StaticGraphExplorerErrorV1::UnsupportedPlatform)
}

#[cfg(unix)]
fn write_private_new_file_v2(
    root: &File,
    name: &OsStr,
    path: &Path,
    bytes: &[u8],
) -> Result<(), StaticGraphExplorerErrorV1> {
    use std::os::unix::fs::MetadataExt;

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
    .map_err(|_| StaticGraphExplorerErrorV1::CapabilityMismatch)?;
    let mut file = File::from(descriptor);
    rustix::fs::fchmod(&file, rustix::fs::Mode::from_raw_mode(0o600))
        .map_err(|_| StaticGraphExplorerErrorV1::CapabilityMismatch)?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|source| StaticGraphExplorerErrorV1::Io {
            path: path.to_path_buf(),
            source,
        })?;
    let metadata = file
        .metadata()
        .map_err(|_| StaticGraphExplorerErrorV1::CapabilityMismatch)?;
    if !metadata.is_file() || metadata.nlink() != 1 || metadata.mode() & 0o777 != 0o600 {
        return Err(StaticGraphExplorerErrorV1::CapabilityMismatch);
    }
    Ok(())
}

#[cfg(not(unix))]
fn write_private_new_file_v2(
    _root: &File,
    _name: &OsStr,
    _path: &Path,
    _bytes: &[u8],
) -> Result<(), StaticGraphExplorerErrorV1> {
    Err(StaticGraphExplorerErrorV1::UnsupportedPlatform)
}

#[cfg(unix)]
fn validate_written_output_capability_v2(
    capability: &StaticGraphExplorerOutputRootCapabilityV2,
    index_path: &Path,
    manifest_path: &Path,
) -> Result<(), StaticGraphExplorerErrorV1> {
    let _root_file = validate_output_capability_identity_v2(capability)?;
    let mut names = fs::read_dir(&capability.root)
        .map_err(|source| StaticGraphExplorerErrorV1::Io {
            path: capability.root.clone(),
            source,
        })?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| StaticGraphExplorerErrorV1::Io {
            path: capability.root.clone(),
            source,
        })?;
    names.sort();
    if names
        != [
            OsString::from("index.html"),
            OsString::from("manifest.json"),
        ]
        || !index_path.is_file()
        || !manifest_path.is_file()
    {
        return Err(StaticGraphExplorerErrorV1::CapabilityMismatch);
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_written_output_capability_v2(
    _capability: &StaticGraphExplorerOutputRootCapabilityV2,
    _index_path: &Path,
    _manifest_path: &Path,
) -> Result<(), StaticGraphExplorerErrorV1> {
    Err(StaticGraphExplorerErrorV1::UnsupportedPlatform)
}

struct ResponseIdentityV1 {
    source: String,
    graph: String,
    overlay: String,
}

fn response_identity_v2(
    response: &Value,
    operation: &str,
    expected: &FileQueryExpectedIdentitiesV1,
    requires_overlay: bool,
) -> Result<ResponseIdentityV1, StaticGraphExplorerErrorV1> {
    if response["operation_id"] != operation {
        return Err(StaticGraphExplorerErrorV1::Q04ArtifactRejected(format!(
            "actual Q04 execution did not return {operation}"
        )));
    }
    let pack = &response["evidence_pack"];
    let source = pack["graph_readback"]["source_snapshot_exact_set_sha256"]
        .as_str()
        .filter(|value| value.starts_with("sha256:"))
        .ok_or_else(|| {
            StaticGraphExplorerErrorV1::Q04ArtifactRejected(format!(
                "{operation} has no source identity-bound graph readback"
            ))
        })?
        .to_owned();
    let graph = pack["graph_readback"]["graph_sha256"]
        .as_str()
        .filter(|value| value.starts_with("sha256:"))
        .ok_or_else(|| {
            StaticGraphExplorerErrorV1::Q04ArtifactRejected(format!(
                "{operation} has no graph identity-bound readback"
            ))
        })?
        .to_owned();
    let overlay = if requires_overlay {
        pack["overlay_readback"]["overlay_sha256"]
            .as_str()
            .filter(|value| value.starts_with("sha256:"))
            .ok_or_else(|| {
                StaticGraphExplorerErrorV1::Q04ArtifactRejected(
                    "graph.search lacks an overlay-bound evidence pack".to_owned(),
                )
            })?
            .to_owned()
    } else {
        String::new()
    };
    let index = &pack["query_index"];
    for key in [
        "full_graph_read_count",
        "database_read_count",
        "network_call_count",
        "daemon_call_count",
    ] {
        if index[key] != 0 {
            return Err(StaticGraphExplorerErrorV1::Q04ArtifactRejected(format!(
                "{operation} evidence pack has non-zero {key}"
            )));
        }
    }
    if !pack["evidence"].is_array() {
        return Err(StaticGraphExplorerErrorV1::Q04ArtifactRejected(format!(
            "{operation} evidence pack is absent"
        )));
    }
    if source != expected.source_identity || graph != expected.graph_identity {
        return Err(StaticGraphExplorerErrorV1::Q04ArtifactRejected(format!(
            "{operation} graph readback does not match the exact expected identities"
        )));
    }
    if requires_overlay && overlay != expected.overlay_identity {
        return Err(StaticGraphExplorerErrorV1::Q04ArtifactRejected(
            "graph.search overlay readback does not match the exact expected identity".to_owned(),
        ));
    }
    Ok(ResponseIdentityV1 {
        source,
        graph,
        overlay,
    })
}

fn record_from_match(
    entry: &Value,
    evidence: &[Value],
) -> Result<StaticGraphExplorerRecordV1, StaticGraphExplorerErrorV1> {
    let required = |key: &str| {
        entry[key]
            .as_str()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                StaticGraphExplorerErrorV1::InvalidInput(format!(
                    "graph.search match has no non-empty {key}"
                ))
            })
    };
    Ok(StaticGraphExplorerRecordV1 {
        entity_id: required("entity_id")?.to_owned(),
        label: required("label")?.to_owned(),
        kind: required("kind")?.to_owned(),
        knowledge_state: required("knowledge_state")?.to_owned(),
        evidence: evidence.to_vec(),
    })
}

fn projection_digest(
    projection: &StaticGraphExplorerProjectionV1,
) -> Result<String, StaticGraphExplorerErrorV1> {
    canonical_json_sha256(&json!({
        "schema_version": projection.schema_version,
        "source_kind": projection.source_kind,
        "source_snapshot_exact_set_sha256": projection.source_snapshot_exact_set_sha256,
        "graph_sha256": projection.graph_sha256,
        "overlay_sha256": projection.overlay_sha256,
        "records": projection.records,
        "views": projection.views,
    }))
    .map_err(StaticGraphExplorerErrorV1::Json)
}

fn validate_projection(
    projection: &StaticGraphExplorerProjectionV1,
) -> Result<(), StaticGraphExplorerErrorV1> {
    if projection.schema_version != STATIC_GRAPH_EXPLORER_SCHEMA_V2
        || projection.source_kind != "q04_file_index_artifacts"
        || projection.records.is_empty()
        || projection.projection_sha256 != projection_digest(projection)?
    {
        return Err(StaticGraphExplorerErrorV1::InvalidInput(
            "Explorer projection is incomplete or digest-invalid".to_owned(),
        ));
    }
    Ok(())
}

fn render_html(
    projection: &StaticGraphExplorerProjectionV1,
) -> Result<String, StaticGraphExplorerErrorV1> {
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
<title>GTKG Graph Explorer</title>
<style>
:root {{ color-scheme: light dark; font-family: ui-sans-serif, system-ui, sans-serif; }}
body {{ margin: 0; background: #10151f; color: #edf2f7; }}
main {{ display: grid; grid-template-columns: minmax(17rem, 32%) 1fr; min-height: 100vh; }}
aside {{ border-right: 1px solid #374151; padding: 1rem; }}
section {{ padding: 1.25rem; }}
input, button {{ font: inherit; }} input {{ width: 100%; box-sizing: border-box; padding: .55rem; }}
button {{ display: block; width: 100%; text-align: left; padding: .55rem; margin-top: .4rem; border: 1px solid #4b5563; background: #172033; color: inherit; border-radius: .35rem; }}
button:focus-visible, input:focus-visible {{ outline: 3px solid #60a5fa; outline-offset: 2px; }}
#records {{ list-style: none; padding: 0; margin: .75rem 0 0; }} #records li {{ margin: 0; padding: 0; }}
#views button {{ display: inline-block; width: auto; margin-right: .5rem; }} pre {{ white-space: pre-wrap; word-break: break-word; background: #172033; padding: 1rem; border-radius: .4rem; }}
</style>
</head>
<body>
<main data-explorer="q04-file-index">
  <aside data-region="search-index"><label for="search">Search verified graph</label><input id="search" type="search" autocomplete="off"><ul id="records" aria-label="Verified graph results"></ul></aside>
  <section id="evidence-detail" data-region="evidence-detail" aria-live="polite"><p id="source-kind"></p><h1 id="selected-title"></h1><p id="selected-meta"></p><h2>Evidence</h2><pre id="selected-evidence"></pre><div id="views"><button id="show-neighbors" type="button">Show neighbors</button><button id="show-path" type="button">Show path</button><button id="show-impact" type="button">Show impact</button><button id="show-trace" type="button">Show trace</button></div><h2 id="view-title">Graph response</h2><pre id="view-output"></pre></section>
</main>
<script id="explorer-data" type="application/json">{encoded}</script>
<script>
(() => {{
  const data = JSON.parse(document.getElementById('explorer-data').textContent);
  const input = document.getElementById('search');
  const records = document.getElementById('records');
  const title = document.getElementById('selected-title');
  const meta = document.getElementById('selected-meta');
  const evidence = document.getElementById('selected-evidence');
  const viewTitle = document.getElementById('view-title');
  const viewOutput = document.getElementById('view-output');
  let selectedEntityId = data.records[0].entity_id;
  document.getElementById('source-kind').textContent = data.source_kind + ' · ' + data.graph_sha256;
  function select(record) {{
    selectedEntityId = record.entity_id;
    title.textContent = record.label;
    meta.textContent = record.entity_id + ' · ' + record.kind + ' · ' + record.knowledge_state;
    evidence.textContent = JSON.stringify(record.evidence, null, 2);
    records.querySelectorAll('button[data-entity-id]').forEach((button) => button.setAttribute('aria-pressed', String(button.dataset.entityId === record.entity_id)));
    globalThis.__GTKG_U03_EVIDENCE__ = {{ selected_id: record.entity_id, network_calls: 0, database_reads: 0, target_execution_count: 0, projection_sha256: data.projection_sha256 }};
  }}
  function render() {{
    const needle = input.value.trim().toLocaleLowerCase();
    records.replaceChildren();
    data.records.filter((record) => !needle || (record.label + ' ' + record.entity_id + ' ' + record.kind).toLocaleLowerCase().includes(needle)).forEach((record) => {{
      const item = document.createElement('li'); const button = document.createElement('button'); button.type = 'button'; button.setAttribute('aria-controls', 'evidence-detail'); button.setAttribute('aria-pressed', String(record.entity_id === selectedEntityId)); button.textContent = record.label; button.dataset.entityId = record.entity_id; button.addEventListener('click', () => select(record)); item.append(button); records.append(item);
    }});
  }}
  input.addEventListener('input', render);
  [['show-neighbors','Neighbors','neighbors'],['show-path','Path','path'],['show-impact','Impact','impact'],['show-trace','Trace','trace']].forEach(([id,label,key]) => document.getElementById(id).addEventListener('click', () => {{ viewTitle.textContent = label; viewOutput.textContent = JSON.stringify(data.views[key], null, 2); }}));
  render(); select(data.records[0]);
  globalThis.__GTKG_U03_XSS__ = false;
}})();
</script>
</body>
</html>"#
    ))
}

fn sha256(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}
