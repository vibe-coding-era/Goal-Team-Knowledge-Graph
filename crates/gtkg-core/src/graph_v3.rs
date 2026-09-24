//! V0.2 T11A provider-free structural Graph v3.
//!
//! This module is deliberately limited to the already-local T02/T05 Typed IR
//! and T06 passed document-relation receipts. It does not accept claims,
//! summaries, providers, embeddings, or any knowledge-overlay input.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::Read;
use std::path::{Component, Path, PathBuf};

use gtkg_protocol::canonical_json_sha256;
use gtkg_protocol::v2::{EvidenceSpanV2, IrResolutionStateV2, TypedIrV2};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::document_relations::{
    DocumentRelationFormatV2, DocumentRelationReceiptV2, DocumentRelationStatusV2,
};

pub const STRUCTURAL_GRAPH_V3_SCHEMA: &str = "gtkg.structural-graph/v3";
const SHARD_SCHEMA: &str = "gtkg.structural-graph-shard/v3";
const MANIFEST_SCHEMA: &str = "gtkg.structural-graph-manifest/v3";
const SHARD_DIRECTORY: &str = "shards";
/// Maximum serialized byte length of one Graph v3 shard. The limit applies to
/// the exact bytes written to disk, not to an in-memory record estimate.
pub const MAX_STRUCTURAL_GRAPH_SHARD_BYTES_V3: usize = 8 * 1024 * 1024;
/// A graph artifact cannot make a query process an unbounded manifest.
pub const MAX_STRUCTURAL_GRAPH_MANIFEST_BYTES_V3: usize = 1024 * 1024;
/// The readback limit is intentionally below filesystem-level exhaustion and
/// applies before JSON deserialization.
pub const MAX_STRUCTURAL_GRAPH_SHARDS_V3: usize = 4_096;
pub const MAX_STRUCTURAL_GRAPH_TOTAL_SHARD_BYTES_V3: usize = 64 * 1024 * 1024;

/// A caller supplies a repository-logical identity because T06 receipts retain
/// their execution path for audit but must not leak host-specific paths into a
/// deterministic graph identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocumentRelationGraphInputV3 {
    pub logical_path: String,
    pub receipt: DocumentRelationReceiptV2,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructuralGraphBuildInputV3 {
    pub source_snapshot_exact_set_sha256: String,
    /// T02/T05 Typed IR plus the exact source bytes required to replay its
    /// digest and every EvidenceSpan before graph construction.
    pub typed_inputs: Vec<TypedIrGraphInputV3>,
    pub document_relations: Vec<DocumentRelationGraphInputV3>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypedIrGraphInputV3 {
    pub ir: TypedIrV2,
    pub source_bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphEvidenceV3 {
    pub kind: String,
    pub evidence_id: String,
    pub source_snapshot_exact_set_sha256: Option<String>,
    pub source_logical_path: String,
    pub source_sha256: String,
    pub byte_start: Option<u64>,
    pub byte_end: Option<u64>,
    pub snippet_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphProvenanceV3 {
    pub input_kind: String,
    pub input_id: String,
    pub input_sha256: String,
    pub source_snapshot_exact_set_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StructuralGraphNodeV3 {
    pub id: String,
    pub kind: String,
    pub label: String,
    pub source_logical_path: String,
    pub source_sha256: String,
    pub provenance: GraphProvenanceV3,
    pub evidence: Vec<GraphEvidenceV3>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StructuralGraphEdgeV3 {
    pub id: String,
    pub kind: String,
    pub source_node_id: String,
    pub target_node_id: Option<String>,
    pub target_reference: String,
    pub resolution: IrResolutionStateV2,
    pub candidate_node_ids: Vec<String>,
    pub provenance: GraphProvenanceV3,
    pub evidence: Vec<GraphEvidenceV3>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StructuralGraphShardIndexV3 {
    pub shard_id: String,
    pub relative_path: String,
    pub shard_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StructuralGraphShardV3 {
    schema_version: String,
    shard_id: String,
    nodes: Vec<StructuralGraphNodeV3>,
    edges: Vec<StructuralGraphEdgeV3>,
}

#[derive(Clone)]
enum GraphRecord {
    Node(StructuralGraphNodeV3),
    Edge(StructuralGraphEdgeV3),
}

impl GraphRecord {
    fn id(&self) -> &str {
        match self {
            Self::Node(node) => &node.id,
            Self::Edge(edge) => &edge.id,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StructuralGraphV3 {
    pub schema_version: String,
    /// Always `structural_only` for T11A. T11B owns the separate overlay.
    pub layer: String,
    pub source_snapshot_exact_set_sha256: String,
    pub nodes: Vec<StructuralGraphNodeV3>,
    pub edges: Vec<StructuralGraphEdgeV3>,
    pub shards: Vec<StructuralGraphShardIndexV3>,
    /// This stays absent rather than empty so a caller cannot mistake T11A for
    /// a graph with an accepted-claim overlay.
    pub knowledge_overlay: Option<String>,
    pub graph_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StructuralGraphManifestV3 {
    schema_version: String,
    layer: String,
    source_snapshot_exact_set_sha256: String,
    shards: Vec<StructuralGraphShardIndexV3>,
    knowledge_overlay: Option<String>,
    graph_sha256: String,
}

#[derive(Debug, Error)]
pub enum StructuralGraphErrorV3 {
    #[error("invalid structural graph input: {0}")]
    InvalidInput(String),
    #[error("invalid structural graph artifact: {0}")]
    InvalidArtifact(String),
    #[error("structural graph output already exists: {0}")]
    OutputExists(PathBuf),
    #[error("cannot access structural graph artifact {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("cannot encode or decode structural graph JSON: {0}")]
    Json(#[from] serde_json::Error),
}

impl StructuralGraphErrorV3 {
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidInput(message) if message.contains("oversize structural graph record") => {
                "E_V2_GRAPH_SHARD_OVERSIZE"
            }
            Self::InvalidInput(message) if message.contains("snapshot") => {
                "E_V2_GRAPH_INPUT_SNAPSHOT_MISMATCH"
            }
            Self::InvalidInput(_) => "E_V2_GRAPH_INPUT_INVALID",
            Self::InvalidArtifact(_) => "E_V2_GRAPH_READBACK_INVALID",
            Self::OutputExists(_) => "E_V2_GRAPH_OUTPUT_EXISTS",
            Self::Io { .. } => "E_V2_GRAPH_IO",
            Self::Json(_) => "E_V2_GRAPH_JSON",
        }
    }
}

/// Build the deterministic structural graph in memory. No provider, claim,
/// summary, corpus output, or knowledge overlay is accepted by this API.
pub fn build_structural_graph_v3(
    input: &StructuralGraphBuildInputV3,
) -> Result<StructuralGraphV3, StructuralGraphErrorV3> {
    require_sha256("source snapshot", &input.source_snapshot_exact_set_sha256)?;
    let mut nodes = Vec::new();
    let mut edges = Vec::new();

    let mut typed_inputs = input.typed_inputs.clone();
    typed_inputs.sort_by(|left, right| {
        left.ir
            .source_logical_path
            .cmp(&right.ir.source_logical_path)
    });
    let mut typed_paths = BTreeSet::new();
    for typed_input in &typed_inputs {
        let ir = &typed_input.ir;
        if ir.source_snapshot_exact_set_sha256 != input.source_snapshot_exact_set_sha256 {
            return Err(StructuralGraphErrorV3::InvalidInput(format!(
                "typed IR {} belongs to another source snapshot",
                ir.source_logical_path
            )));
        }
        require_sha256("typed IR digest", &ir.typed_ir_sha256)?;
        require_sha256("typed source digest", &ir.source_sha256)?;
        ir.validate_for_source(&typed_input.source_bytes)
            .map_err(|error| {
                StructuralGraphErrorV3::InvalidInput(format!(
                    "typed IR {} failed exact source/evidence readback: {error}",
                    ir.source_logical_path
                ))
            })?;
        if !typed_paths.insert(ir.source_logical_path.clone()) {
            return Err(StructuralGraphErrorV3::InvalidInput(format!(
                "duplicate typed IR logical path {}",
                ir.source_logical_path
            )));
        }

        let evidence_by_id = ir
            .evidence
            .iter()
            .map(|evidence| (evidence.id.as_str(), evidence))
            .collect::<BTreeMap<_, _>>();
        let code_provenance = GraphProvenanceV3 {
            input_kind: "typed_ir".to_owned(),
            input_id: ir.source_logical_path.clone(),
            input_sha256: ir.typed_ir_sha256.clone(),
            source_snapshot_exact_set_sha256: Some(ir.source_snapshot_exact_set_sha256.clone()),
        };
        for node in &ir.nodes {
            let evidence = typed_evidence(&evidence_by_id, &node.evidence_ids)?;
            nodes.push(StructuralGraphNodeV3 {
                id: code_node_id(&ir.source_logical_path, &node.id),
                kind: "code_symbol".to_owned(),
                label: node.name.clone(),
                source_logical_path: ir.source_logical_path.clone(),
                source_sha256: ir.source_sha256.clone(),
                provenance: code_provenance.clone(),
                evidence,
            });
        }
        for edge in &ir.edges {
            let Some(source_node) = edge.source_node_id.as_deref() else {
                return Err(StructuralGraphErrorV3::InvalidInput(format!(
                    "typed edge {} has no structural source node",
                    edge.id
                )));
            };
            let evidence = typed_evidence(&evidence_by_id, &edge.evidence_ids)?;
            let source_node_id = code_node_id(&ir.source_logical_path, source_node);
            let target_node_id = edge
                .resolved_node_id
                .as_deref()
                .map(|id| code_node_id(&ir.source_logical_path, id));
            let candidate_node_ids = edge
                .candidate_node_ids
                .iter()
                .map(|id| code_node_id(&ir.source_logical_path, id))
                .collect();
            edges.push(StructuralGraphEdgeV3 {
                id: code_edge_id(&ir.source_logical_path, &edge.id),
                kind: edge.kind.clone(),
                source_node_id,
                target_node_id,
                target_reference: edge.target_reference.clone(),
                resolution: edge.resolution,
                candidate_node_ids,
                provenance: code_provenance.clone(),
                evidence,
            });
        }
    }

    let mut document_relations = input.document_relations.clone();
    document_relations.sort_by(|left, right| left.logical_path.cmp(&right.logical_path));
    let mut document_paths = BTreeSet::new();
    for document in &document_relations {
        validate_document_input(document, &mut document_paths)?;
        let receipt_sha256 =
            canonical_json_sha256(&document.receipt).map_err(StructuralGraphErrorV3::Json)?;
        let provenance = GraphProvenanceV3 {
            input_kind: "document_relation_receipt".to_owned(),
            input_id: document.logical_path.clone(),
            input_sha256: receipt_sha256,
            source_snapshot_exact_set_sha256: None,
        };
        let evidence = vec![GraphEvidenceV3 {
            kind: "document_relation_receipt".to_owned(),
            evidence_id: format!("document-sha256:{}", document.receipt.document_sha256),
            source_snapshot_exact_set_sha256: None,
            source_logical_path: document.logical_path.clone(),
            source_sha256: document.receipt.document_sha256.clone(),
            byte_start: None,
            byte_end: None,
            snippet_sha256: None,
        }];
        let document_id = document_node_id(&document.logical_path);
        nodes.push(StructuralGraphNodeV3 {
            id: document_id.clone(),
            kind: "document".to_owned(),
            label: document.logical_path.clone(),
            source_logical_path: document.logical_path.clone(),
            source_sha256: document.receipt.document_sha256.clone(),
            provenance: provenance.clone(),
            evidence: evidence.clone(),
        });
        for source_id in &document.receipt.relation.source_ids {
            let source_node_id = document_source_node_id(&document.logical_path, source_id);
            nodes.push(StructuralGraphNodeV3 {
                id: source_node_id.clone(),
                kind: "document_source".to_owned(),
                label: source_id.clone(),
                source_logical_path: document.logical_path.clone(),
                source_sha256: document.receipt.document_sha256.clone(),
                provenance: provenance.clone(),
                evidence: evidence.clone(),
            });
            edges.push(StructuralGraphEdgeV3 {
                id: document_edge_id(&document.logical_path, source_id),
                kind: "cites_source".to_owned(),
                source_node_id: document_id.clone(),
                target_node_id: Some(source_node_id),
                target_reference: source_id.clone(),
                resolution: IrResolutionStateV2::Resolved,
                candidate_node_ids: Vec::new(),
                provenance: provenance.clone(),
                evidence: evidence.clone(),
            });
        }
    }

    nodes.sort_by(|left, right| left.id.cmp(&right.id));
    edges.sort_by(|left, right| left.id.cmp(&right.id));
    validate_records(&nodes, &edges)?;
    let shards = make_shards(&nodes, &edges)?;
    let mut graph = StructuralGraphV3 {
        schema_version: STRUCTURAL_GRAPH_V3_SCHEMA.to_owned(),
        layer: "structural_only".to_owned(),
        source_snapshot_exact_set_sha256: input.source_snapshot_exact_set_sha256.clone(),
        nodes,
        edges,
        shards,
        knowledge_overlay: None,
        graph_sha256: String::new(),
    };
    graph.graph_sha256 = graph_digest(&graph)?;
    validate_graph(&graph)?;
    Ok(graph)
}

/// Verify an in-memory structural graph before another layer binds to it.
/// T11B uses this entrypoint so a caller cannot swap in a structurally
/// plausible but digest-tampered graph as overlay provenance.
pub fn validate_structural_graph_v3(
    graph: &StructuralGraphV3,
) -> Result<(), StructuralGraphErrorV3> {
    validate_graph(graph)
}

/// Write a new immutable file-shard graph. Existing outputs are rejected to
/// avoid replacing a separately verified graph identity.
pub fn write_structural_graph_v3(
    output_root: &Path,
    graph: &StructuralGraphV3,
) -> Result<(), StructuralGraphErrorV3> {
    validate_graph(graph)?;
    if output_root.exists() {
        return Err(StructuralGraphErrorV3::OutputExists(
            output_root.to_path_buf(),
        ));
    }
    let shard_root = output_root.join(SHARD_DIRECTORY);
    fs::create_dir_all(&shard_root).map_err(|source| StructuralGraphErrorV3::Io {
        path: shard_root.clone(),
        source,
    })?;
    let shard_map = materialize_shards(&graph.nodes, &graph.edges)?;
    for index in &graph.shards {
        let shard = shard_map.get(&index.shard_id).ok_or_else(|| {
            StructuralGraphErrorV3::InvalidArtifact(format!(
                "missing generated shard {}",
                index.shard_id
            ))
        })?;
        let bytes = shard_bytes(shard)?;
        if digest_bytes(&bytes) != index.shard_sha256 {
            return Err(StructuralGraphErrorV3::InvalidArtifact(format!(
                "shard index digest mismatch for {}",
                index.shard_id
            )));
        }
        let path = output_root.join(&index.relative_path);
        fs::write(&path, bytes).map_err(|source| StructuralGraphErrorV3::Io { path, source })?;
    }
    let manifest = StructuralGraphManifestV3 {
        schema_version: MANIFEST_SCHEMA.to_owned(),
        layer: graph.layer.clone(),
        source_snapshot_exact_set_sha256: graph.source_snapshot_exact_set_sha256.clone(),
        shards: graph.shards.clone(),
        knowledge_overlay: None,
        graph_sha256: graph.graph_sha256.clone(),
    };
    let manifest_path = output_root.join("manifest.json");
    fs::write(&manifest_path, serde_json::to_vec_pretty(&manifest)?).map_err(|source| {
        StructuralGraphErrorV3::Io {
            path: manifest_path,
            source,
        }
    })?;
    Ok(())
}

/// Reconstruct the graph exclusively from the manifest and shards, checking
/// every shard digest and the final graph digest before returning it.
pub fn read_structural_graph_v3(
    output_root: &Path,
) -> Result<StructuralGraphV3, StructuralGraphErrorV3> {
    let root = verified_graph_root(output_root)?;
    let bytes = read_graph_artifact_file(
        &root,
        Path::new("manifest.json"),
        MAX_STRUCTURAL_GRAPH_MANIFEST_BYTES_V3,
    )?;
    let manifest: StructuralGraphManifestV3 = serde_json::from_slice(&bytes)?;
    if manifest.schema_version != MANIFEST_SCHEMA
        || manifest.layer != "structural_only"
        || manifest.knowledge_overlay.is_some()
    {
        return Err(StructuralGraphErrorV3::InvalidArtifact(
            "manifest is not a structural-only Graph v3".to_owned(),
        ));
    }
    if manifest.shards.len() > MAX_STRUCTURAL_GRAPH_SHARDS_V3 {
        return Err(StructuralGraphErrorV3::InvalidArtifact(format!(
            "graph manifest declares more than {MAX_STRUCTURAL_GRAPH_SHARDS_V3} shards"
        )));
    }
    let mut nodes = Vec::new();
    let mut edges = Vec::new();
    let mut total_shard_bytes = 0_usize;
    for index in &manifest.shards {
        validate_relative_shard_path(&index.relative_path)?;
        let bytes = read_graph_artifact_file(
            &root,
            Path::new(&index.relative_path),
            MAX_STRUCTURAL_GRAPH_SHARD_BYTES_V3,
        )?;
        total_shard_bytes = total_shard_bytes.checked_add(bytes.len()).ok_or_else(|| {
            StructuralGraphErrorV3::InvalidArtifact("graph shard byte total overflow".to_owned())
        })?;
        if total_shard_bytes > MAX_STRUCTURAL_GRAPH_TOTAL_SHARD_BYTES_V3 {
            return Err(StructuralGraphErrorV3::InvalidArtifact(format!(
                "graph shards exceed {MAX_STRUCTURAL_GRAPH_TOTAL_SHARD_BYTES_V3} bytes"
            )));
        }
        if digest_bytes(&bytes) != index.shard_sha256 {
            return Err(StructuralGraphErrorV3::InvalidArtifact(format!(
                "raw shard bytes do not match {}",
                index.shard_id
            )));
        }
        let shard: StructuralGraphShardV3 = serde_json::from_slice(&bytes)?;
        if shard.schema_version != SHARD_SCHEMA || shard.shard_id != index.shard_id {
            return Err(StructuralGraphErrorV3::InvalidArtifact(format!(
                "invalid shard {}",
                index.shard_id
            )));
        }
        nodes.extend(shard.nodes);
        edges.extend(shard.edges);
    }
    nodes.sort_by(|left, right| left.id.cmp(&right.id));
    edges.sort_by(|left, right| left.id.cmp(&right.id));
    let graph = StructuralGraphV3 {
        schema_version: STRUCTURAL_GRAPH_V3_SCHEMA.to_owned(),
        layer: manifest.layer,
        source_snapshot_exact_set_sha256: manifest.source_snapshot_exact_set_sha256,
        nodes,
        edges,
        shards: manifest.shards,
        knowledge_overlay: manifest.knowledge_overlay,
        graph_sha256: manifest.graph_sha256,
    };
    validate_graph(&graph)?;
    Ok(graph)
}

/// The query boundary must never follow an artifact-root symlink or accept an
/// artifact directory that resolves outside the caller-selected root.
fn verified_graph_root(output_root: &Path) -> Result<PathBuf, StructuralGraphErrorV3> {
    let metadata =
        fs::symlink_metadata(output_root).map_err(|source| StructuralGraphErrorV3::Io {
            path: output_root.to_path_buf(),
            source,
        })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(StructuralGraphErrorV3::InvalidArtifact(
            "graph artifact root must be a non-symlink directory".to_owned(),
        ));
    }
    let canonical = fs::canonicalize(output_root).map_err(|source| StructuralGraphErrorV3::Io {
        path: output_root.to_path_buf(),
        source,
    })?;
    let canonical_metadata =
        fs::symlink_metadata(&canonical).map_err(|source| StructuralGraphErrorV3::Io {
            path: canonical.clone(),
            source,
        })?;
    if canonical_metadata.file_type().is_symlink() || !canonical_metadata.is_dir() {
        return Err(StructuralGraphErrorV3::InvalidArtifact(
            "canonical graph artifact root is unsafe".to_owned(),
        ));
    }
    Ok(canonical)
}

fn read_graph_artifact_file(
    root: &Path,
    relative: &Path,
    max_bytes: usize,
) -> Result<Vec<u8>, StructuralGraphErrorV3> {
    let candidate = root.join(relative);
    let parts = relative.components().collect::<Vec<_>>();
    if parts.is_empty()
        || parts
            .iter()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err(StructuralGraphErrorV3::InvalidArtifact(
            "graph artifact path must be a non-empty relative normal path".to_owned(),
        ));
    }
    let mut cursor = root.to_path_buf();
    for (index, part) in parts.iter().enumerate() {
        let Component::Normal(name) = part else {
            unreachable!("normal components checked")
        };
        cursor.push(name);
        let metadata =
            fs::symlink_metadata(&cursor).map_err(|source| StructuralGraphErrorV3::Io {
                path: cursor.clone(),
                source,
            })?;
        if metadata.file_type().is_symlink() {
            return Err(StructuralGraphErrorV3::InvalidArtifact(format!(
                "graph artifact path contains a symlink: {}",
                cursor.display()
            )));
        }
        if index + 1 == parts.len() {
            if !metadata.file_type().is_file() {
                return Err(StructuralGraphErrorV3::InvalidArtifact(format!(
                    "graph artifact endpoint is not a regular file: {}",
                    cursor.display()
                )));
            }
        } else if !metadata.is_dir() {
            return Err(StructuralGraphErrorV3::InvalidArtifact(format!(
                "graph artifact path contains a non-directory component: {}",
                cursor.display()
            )));
        }
    }
    let mut file = open_graph_file_no_follow(root, relative)?;
    let opened = file
        .metadata()
        .map_err(|source| StructuralGraphErrorV3::Io {
            path: candidate.clone(),
            source,
        })?;
    if !opened.file_type().is_file() || opened.len() > max_bytes as u64 {
        return Err(StructuralGraphErrorV3::InvalidArtifact(format!(
            "graph artifact file exceeds {max_bytes} bytes or is not regular: {}",
            candidate.display()
        )));
    }
    ensure_private_graph_inode(&candidate, &opened)?;
    let mut bytes = Vec::with_capacity(usize::try_from(opened.len()).unwrap_or(max_bytes));
    file.read_to_end(&mut bytes)
        .map_err(|source| StructuralGraphErrorV3::Io {
            path: candidate.clone(),
            source,
        })?;
    if bytes.len() > max_bytes {
        return Err(StructuralGraphErrorV3::InvalidArtifact(format!(
            "graph artifact file exceeds {max_bytes} bytes after read: {}",
            candidate.display()
        )));
    }
    let after = fs::symlink_metadata(&candidate).map_err(|source| StructuralGraphErrorV3::Io {
        path: candidate.clone(),
        source,
    })?;
    ensure_same_graph_inode(&candidate, &after, &opened)?;
    Ok(bytes)
}

#[cfg(unix)]
fn open_graph_file_no_follow(root: &Path, relative: &Path) -> Result<File, StructuralGraphErrorV3> {
    use rustix::fs::{Mode, OFlags, open, openat};
    let directory_flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut directory =
        open(root, directory_flags, Mode::empty()).map_err(|error| StructuralGraphErrorV3::Io {
            path: root.to_path_buf(),
            source: std::io::Error::from_raw_os_error(error.raw_os_error()),
        })?;
    let parts = relative.components().collect::<Vec<_>>();
    for (index, part) in parts.iter().enumerate() {
        let Component::Normal(name) = part else {
            return Err(StructuralGraphErrorV3::InvalidArtifact(
                "unsafe graph artifact path".to_owned(),
            ));
        };
        let is_file = index + 1 == parts.len();
        let flags = if is_file {
            OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC
        } else {
            directory_flags
        };
        let opened = openat(&directory, *name, flags, Mode::empty()).map_err(|error| {
            StructuralGraphErrorV3::Io {
                path: root.join(relative),
                source: std::io::Error::from_raw_os_error(error.raw_os_error()),
            }
        })?;
        if is_file {
            return Ok(File::from(opened));
        }
        directory = opened;
    }
    Err(StructuralGraphErrorV3::InvalidArtifact(
        "empty graph artifact path".to_owned(),
    ))
}

#[cfg(not(unix))]
fn open_graph_file_no_follow(root: &Path, relative: &Path) -> Result<File, StructuralGraphErrorV3> {
    File::open(root.join(relative)).map_err(|source| StructuralGraphErrorV3::Io {
        path: root.join(relative),
        source,
    })
}

fn ensure_private_graph_inode(
    path: &Path,
    metadata: &fs::Metadata,
) -> Result<(), StructuralGraphErrorV3> {
    if !metadata.file_type().is_file() {
        return Err(StructuralGraphErrorV3::InvalidArtifact(
            "graph artifact handle is not regular".to_owned(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() > 1 {
            return Err(StructuralGraphErrorV3::InvalidArtifact(format!(
                "graph artifact hardlink is rejected: {}",
                path.display()
            )));
        }
    }
    Ok(())
}

fn ensure_same_graph_inode(
    path: &Path,
    path_metadata: &fs::Metadata,
    file_metadata: &fs::Metadata,
) -> Result<(), StructuralGraphErrorV3> {
    ensure_private_graph_inode(path, path_metadata)?;
    ensure_private_graph_inode(path, file_metadata)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if path_metadata.dev() != file_metadata.dev() || path_metadata.ino() != file_metadata.ino()
        {
            return Err(StructuralGraphErrorV3::InvalidArtifact(format!(
                "graph artifact inode changed while reading: {}",
                path.display()
            )));
        }
    }
    Ok(())
}

fn validate_document_input(
    document: &DocumentRelationGraphInputV3,
    seen_paths: &mut BTreeSet<String>,
) -> Result<(), StructuralGraphErrorV3> {
    validate_logical_path(&document.logical_path)?;
    if !seen_paths.insert(document.logical_path.clone()) {
        return Err(StructuralGraphErrorV3::InvalidInput(format!(
            "duplicate document relation logical path {}",
            document.logical_path
        )));
    }
    if document.receipt.schema_version != "gtkg.document-relation-receipt/v2"
        || document.receipt.relation.format != DocumentRelationFormatV2::Markdown
        || document.receipt.relation.status != DocumentRelationStatusV2::Passed
        || document.receipt.relation.source_ids.is_empty()
        || document.receipt.relation.source_ids != document.receipt.relation.footnote_ids
        || !document.receipt.relation.issues.is_empty()
    {
        return Err(StructuralGraphErrorV3::InvalidInput(format!(
            "document relation {} is not a passed Markdown closure",
            document.logical_path
        )));
    }
    document
        .receipt
        .relation
        .binding
        .raw_spec_pin
        .validate()
        .map_err(|error| {
            StructuralGraphErrorV3::InvalidInput(format!("invalid T03 relation binding: {error}"))
        })?;
    require_sha256(
        "document relation document",
        &document.receipt.document_sha256,
    )?;
    require_sha256(
        "document relation corpus manifest",
        &document.receipt.relation.binding.corpus_manifest_sha256,
    )?;
    require_sha256(
        "document relation T03 receipt",
        &document.receipt.relation.binding.receipt_sha256,
    )
}

fn typed_evidence(
    all: &BTreeMap<&str, &EvidenceSpanV2>,
    ids: &[String],
) -> Result<Vec<GraphEvidenceV3>, StructuralGraphErrorV3> {
    if ids.is_empty() {
        return Err(StructuralGraphErrorV3::InvalidInput(
            "typed structural record has no evidence".to_owned(),
        ));
    }
    let mut evidence = Vec::new();
    for id in ids {
        let item = all.get(id.as_str()).ok_or_else(|| {
            StructuralGraphErrorV3::InvalidInput(format!("typed evidence {id} is absent"))
        })?;
        evidence.push(GraphEvidenceV3 {
            kind: "evidence_span".to_owned(),
            evidence_id: item.id.clone(),
            source_snapshot_exact_set_sha256: Some(item.source_snapshot_exact_set_sha256.clone()),
            source_logical_path: item.source_logical_path.clone(),
            source_sha256: item.source_sha256.clone(),
            byte_start: Some(item.byte_start),
            byte_end: Some(item.byte_end),
            snippet_sha256: Some(item.snippet_sha256.clone()),
        });
    }
    evidence.sort_by(|left, right| left.evidence_id.cmp(&right.evidence_id));
    evidence.dedup_by(|left, right| left.evidence_id == right.evidence_id);
    Ok(evidence)
}

fn validate_records(
    nodes: &[StructuralGraphNodeV3],
    edges: &[StructuralGraphEdgeV3],
) -> Result<(), StructuralGraphErrorV3> {
    let node_ids = nodes
        .iter()
        .map(|node| node.id.as_str())
        .collect::<BTreeSet<_>>();
    if node_ids.len() != nodes.len() {
        return Err(StructuralGraphErrorV3::InvalidInput(
            "duplicate structural node ID".to_owned(),
        ));
    }
    let edge_ids = edges
        .iter()
        .map(|edge| edge.id.as_str())
        .collect::<BTreeSet<_>>();
    if edge_ids.len() != edges.len() {
        return Err(StructuralGraphErrorV3::InvalidInput(
            "duplicate structural edge ID".to_owned(),
        ));
    }
    for node in nodes {
        validate_node(node)?;
    }
    for edge in edges {
        if !node_ids.contains(edge.source_node_id.as_str())
            || edge
                .target_node_id
                .as_deref()
                .is_some_and(|id| !node_ids.contains(id))
            || edge.evidence.is_empty()
        {
            return Err(StructuralGraphErrorV3::InvalidInput(format!(
                "edge {} has invalid structural endpoints or evidence",
                edge.id
            )));
        }
        validate_evidence(&edge.evidence)?;
        validate_provenance(&edge.provenance)?;
    }
    Ok(())
}

fn validate_node(node: &StructuralGraphNodeV3) -> Result<(), StructuralGraphErrorV3> {
    if node.id.trim().is_empty() || node.label.trim().is_empty() || node.evidence.is_empty() {
        return Err(StructuralGraphErrorV3::InvalidInput(
            "node is missing identity or evidence".to_owned(),
        ));
    }
    require_sha256("node source", &node.source_sha256)?;
    validate_evidence(&node.evidence)?;
    validate_provenance(&node.provenance)
}

fn validate_provenance(provenance: &GraphProvenanceV3) -> Result<(), StructuralGraphErrorV3> {
    if !matches!(
        provenance.input_kind.as_str(),
        "typed_ir" | "document_relation_receipt"
    ) || provenance.input_id.trim().is_empty()
    {
        return Err(StructuralGraphErrorV3::InvalidInput(
            "unsupported graph provenance input".to_owned(),
        ));
    }
    require_sha256("provenance input", &provenance.input_sha256)
}

fn validate_evidence(evidence: &[GraphEvidenceV3]) -> Result<(), StructuralGraphErrorV3> {
    for item in evidence {
        if item.evidence_id.trim().is_empty() || item.source_logical_path.trim().is_empty() {
            return Err(StructuralGraphErrorV3::InvalidInput(
                "graph evidence lacks an identity or logical path".to_owned(),
            ));
        }
        require_sha256("graph evidence source", &item.source_sha256)?;
        if let Some(snapshot) = &item.source_snapshot_exact_set_sha256 {
            require_sha256("graph evidence snapshot", snapshot)?;
        }
        if let Some(snippet) = &item.snippet_sha256 {
            require_sha256("graph evidence snippet", snippet)?;
        }
        if item.byte_start.is_some() != item.byte_end.is_some()
            || item
                .byte_start
                .zip(item.byte_end)
                .is_some_and(|(start, end)| start >= end)
        {
            return Err(StructuralGraphErrorV3::InvalidInput(
                "graph evidence has an invalid byte span".to_owned(),
            ));
        }
    }
    Ok(())
}

fn make_shards(
    nodes: &[StructuralGraphNodeV3],
    edges: &[StructuralGraphEdgeV3],
) -> Result<Vec<StructuralGraphShardIndexV3>, StructuralGraphErrorV3> {
    let shards = materialize_shards(nodes, edges)?;
    shards
        .values()
        .map(|shard| {
            Ok(StructuralGraphShardIndexV3 {
                shard_id: shard.shard_id.clone(),
                relative_path: format!("{SHARD_DIRECTORY}/{}.json", shard.shard_id),
                shard_sha256: digest_bytes(&shard_bytes(shard)?),
            })
        })
        .collect()
}

fn materialize_shards(
    nodes: &[StructuralGraphNodeV3],
    edges: &[StructuralGraphEdgeV3],
) -> Result<BTreeMap<String, StructuralGraphShardV3>, StructuralGraphErrorV3> {
    let mut buckets: BTreeMap<String, Vec<GraphRecord>> = BTreeMap::new();
    for node in nodes {
        buckets
            .entry(shard_prefix(&node.id))
            .or_default()
            .push(GraphRecord::Node(node.clone()));
    }
    for edge in edges {
        buckets
            .entry(shard_prefix(&edge.id))
            .or_default()
            .push(GraphRecord::Edge(edge.clone()));
    }
    let mut result = BTreeMap::new();
    for (prefix, mut records) in buckets {
        records.sort_by(|left, right| left.id().cmp(right.id()));
        let mut ordinal = 0_usize;
        let mut current = Vec::<GraphRecord>::new();
        for record in records {
            let mut candidate = current.clone();
            candidate.push(record.clone());
            let candidate_shard = shard_from_records(&prefix, ordinal, candidate.clone())?;
            if shard_bytes(&candidate_shard)?.len() > MAX_STRUCTURAL_GRAPH_SHARD_BYTES_V3 {
                if current.is_empty() {
                    return Err(StructuralGraphErrorV3::InvalidInput(format!(
                        "oversize structural graph record {} exceeds the {} byte shard limit",
                        record.id(),
                        MAX_STRUCTURAL_GRAPH_SHARD_BYTES_V3
                    )));
                }
                let shard = shard_from_records(&prefix, ordinal, current)?;
                result.insert(shard.shard_id.clone(), shard);
                ordinal = ordinal.checked_add(1).ok_or_else(|| {
                    StructuralGraphErrorV3::InvalidInput(
                        "structural graph shard ordinal overflow".to_owned(),
                    )
                })?;
                current = vec![record];
                let single = shard_from_records(&prefix, ordinal, current.clone())?;
                if shard_bytes(&single)?.len() > MAX_STRUCTURAL_GRAPH_SHARD_BYTES_V3 {
                    return Err(StructuralGraphErrorV3::InvalidInput(format!(
                        "oversize structural graph record {} exceeds the {} byte shard limit",
                        current[0].id(),
                        MAX_STRUCTURAL_GRAPH_SHARD_BYTES_V3
                    )));
                }
            } else {
                current = candidate;
            }
        }
        if !current.is_empty() {
            let shard = shard_from_records(&prefix, ordinal, current)?;
            result.insert(shard.shard_id.clone(), shard);
        }
    }
    Ok(result)
}

fn shard_from_records(
    prefix: &str,
    ordinal: usize,
    records: Vec<GraphRecord>,
) -> Result<StructuralGraphShardV3, StructuralGraphErrorV3> {
    let mut nodes = Vec::new();
    let mut edges = Vec::new();
    for record in records {
        match record {
            GraphRecord::Node(node) => nodes.push(node),
            GraphRecord::Edge(edge) => edges.push(edge),
        }
    }
    nodes.sort_by(|left, right| left.id.cmp(&right.id));
    edges.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(StructuralGraphShardV3 {
        schema_version: SHARD_SCHEMA.to_owned(),
        shard_id: format!("{prefix}-{ordinal:04}"),
        nodes,
        edges,
    })
}

fn validate_graph(graph: &StructuralGraphV3) -> Result<(), StructuralGraphErrorV3> {
    if graph.schema_version != STRUCTURAL_GRAPH_V3_SCHEMA
        || graph.layer != "structural_only"
        || graph.knowledge_overlay.is_some()
    {
        return Err(StructuralGraphErrorV3::InvalidArtifact(
            "graph must remain structural_only without overlay".to_owned(),
        ));
    }
    require_sha256("graph snapshot", &graph.source_snapshot_exact_set_sha256)?;
    validate_records(&graph.nodes, &graph.edges)?;
    let expected_shards = make_shards(&graph.nodes, &graph.edges)?;
    if graph.shards != expected_shards || graph.graph_sha256 != graph_digest(graph)? {
        return Err(StructuralGraphErrorV3::InvalidArtifact(
            "graph digest or shard index mismatch".to_owned(),
        ));
    }
    Ok(())
}

fn graph_digest(graph: &StructuralGraphV3) -> Result<String, StructuralGraphErrorV3> {
    let mut unsigned = graph.clone();
    unsigned.graph_sha256.clear();
    canonical_json_sha256(&unsigned).map_err(StructuralGraphErrorV3::Json)
}

fn shard_bytes(shard: &StructuralGraphShardV3) -> Result<Vec<u8>, StructuralGraphErrorV3> {
    serde_json::to_vec_pretty(shard).map_err(StructuralGraphErrorV3::Json)
}

fn digest_bytes(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn shard_prefix(id: &str) -> String {
    let digest = hex::encode(Sha256::digest(id.as_bytes()));
    digest[..2].to_owned()
}

fn code_node_id(path: &str, id: &str) -> String {
    format!("code:{}", stable_id_hash(&format!("{path}\n{id}")))
}

fn code_edge_id(path: &str, id: &str) -> String {
    format!("edge:{}", stable_id_hash(&format!("{path}\n{id}")))
}

fn document_node_id(path: &str) -> String {
    format!("document:{}", stable_id_hash(path))
}

fn document_source_node_id(path: &str, source_id: &str) -> String {
    format!(
        "document-source:{}",
        stable_id_hash(&format!("{path}\n{source_id}"))
    )
}

fn document_edge_id(path: &str, source_id: &str) -> String {
    format!(
        "edge:{}",
        stable_id_hash(&format!("cites_source\n{path}\n{source_id}"))
    )
}

fn stable_id_hash(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

fn validate_logical_path(value: &str) -> Result<(), StructuralGraphErrorV3> {
    let path = Path::new(value);
    if value.trim().is_empty()
        || path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(StructuralGraphErrorV3::InvalidInput(format!(
            "unsafe logical path {value}"
        )));
    }
    Ok(())
}

fn validate_relative_shard_path(value: &str) -> Result<(), StructuralGraphErrorV3> {
    let path = Path::new(value);
    if !value.starts_with("shards/")
        || path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(StructuralGraphErrorV3::InvalidArtifact(format!(
            "unsafe shard path {value}"
        )));
    }
    Ok(())
}

fn require_sha256(label: &str, value: &str) -> Result<(), StructuralGraphErrorV3> {
    let valid = value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'));
    if !valid {
        return Err(StructuralGraphErrorV3::InvalidInput(format!(
            "invalid {label} sha256"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(id: String, label: String) -> StructuralGraphNodeV3 {
        StructuralGraphNodeV3 {
            id,
            kind: "test".to_owned(),
            label,
            source_logical_path: "fixture.rs".to_owned(),
            source_sha256: format!("sha256:{}", "a".repeat(64)),
            provenance: GraphProvenanceV3 {
                input_kind: "typed_ir".to_owned(),
                input_id: "fixture.rs".to_owned(),
                input_sha256: format!("sha256:{}", "b".repeat(64)),
                source_snapshot_exact_set_sha256: Some(format!("sha256:{}", "c".repeat(64))),
            },
            evidence: vec![GraphEvidenceV3 {
                kind: "test".to_owned(),
                evidence_id: "evidence".to_owned(),
                source_snapshot_exact_set_sha256: None,
                source_logical_path: "fixture.rs".to_owned(),
                source_sha256: format!("sha256:{}", "a".repeat(64)),
                byte_start: None,
                byte_end: None,
                snippet_sha256: None,
            }],
        }
    }

    fn same_prefix_id(first: &str) -> String {
        let prefix = shard_prefix(first);
        for ordinal in 0_u64..=10_000 {
            let candidate = format!("collision-{ordinal}");
            if candidate != first && shard_prefix(&candidate) == prefix {
                return candidate;
            }
        }
        panic!("SHA-256 prefix collision was unexpectedly absent")
    }

    #[test]
    fn shard_boundary_uses_final_serialized_bytes_not_record_estimates() {
        let first = "boundary-first";
        let second = same_prefix_id(first);
        let half = "x".repeat(MAX_STRUCTURAL_GRAPH_SHARD_BYTES_V3 / 2);
        let shards = materialize_shards(
            &[node(first.to_owned(), half.clone()), node(second, half)],
            &[],
        )
        .expect("two separately valid shards");
        assert_eq!(shards.len(), 2, "final JSON overhead requires a split");
        assert!(
            shards
                .values()
                .all(|shard| shard_bytes(shard).expect("shard bytes").len()
                    <= MAX_STRUCTURAL_GRAPH_SHARD_BYTES_V3)
        );
    }

    #[test]
    fn oversize_single_record_fails_closed() {
        let error = materialize_shards(
            &[node(
                "oversize".to_owned(),
                "x".repeat(MAX_STRUCTURAL_GRAPH_SHARD_BYTES_V3),
            )],
            &[],
        )
        .expect_err("a record cannot silently exceed one raw shard");
        assert_eq!(error.code(), "E_V2_GRAPH_SHARD_OVERSIZE");
    }
}
