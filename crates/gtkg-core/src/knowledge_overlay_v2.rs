//! V0.2 T11B deterministic accepted-claim knowledge overlay.
//!
//! The overlay is deliberately a separate artifact from Graph v3.  It accepts
//! only the complete T10 proposal set whose digest is sealed in the T10
//! receipt, the matching AcceptedClaimSet, a verified T11A structural graph,
//! and passed T06 document-relation receipts.  It has no Provider input and
//! does not derive or paraphrase any free text.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::Read;
use std::path::{Component, Path, PathBuf};

use gtkg_protocol::{canonical_json_sha256, validate_sha256};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::claim_v2::{
    AcceptedClaimSetV2, AtomicClaimV2, ClaimModalityV2, ClaimSetStateV2,
    ClaimVerificationReceiptV2, ClaimVerificationStateV2, claim_proposal_set_digest,
};
use crate::document_relations::{DocumentRelationFormatV2, DocumentRelationStatusV2};
use crate::graph_v3::{
    DocumentRelationGraphInputV3, GraphEvidenceV3, StructuralGraphNodeV3, StructuralGraphV3,
    validate_structural_graph_v3,
};

pub const KNOWLEDGE_OVERLAY_V2_SCHEMA: &str = "gtkg.knowledge-overlay/v2";
const MANIFEST_SCHEMA: &str = "gtkg.knowledge-overlay-manifest/v2";
const OVERLAY_FILE: &str = "overlay.json";
const MAX_OVERLAY_MANIFEST_BYTES: usize = 1024 * 1024;
const MAX_OVERLAY_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnowledgeOverlayBuildInputV2 {
    pub structural_graph: StructuralGraphV3,
    /// The complete proposal set that was passed to T10, not a regenerated
    /// semantic approximation. It is re-digested before use.
    pub claims: Vec<AtomicClaimV2>,
    pub verification_receipt: ClaimVerificationReceiptV2,
    pub accepted_claim_set: AcceptedClaimSetV2,
    /// T06 passed Markdown closures are the sole source/footnote input.
    pub document_relations: Vec<DocumentRelationGraphInputV3>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KnowledgeOverlayProvenanceV2 {
    pub structural_graph_sha256: String,
    pub verification_receipt_sha256: String,
    pub accepted_claim_set_sha256: String,
    pub t03_receipt_sha256: String,
    pub t04_manifest_sha256: String,
    pub document_relation_receipt_sha256s: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KnowledgeOverlayNodeV2 {
    pub id: String,
    /// One of `accepted_claim`, `abstention`, `source`, `footnote`, or
    /// `provenance`.
    pub kind: String,
    pub label: String,
    pub claim_id: Option<String>,
    /// A claim can only cite evidence already present in the structural graph.
    pub structural_evidence_ids: Vec<String>,
    pub provenance: KnowledgeOverlayProvenanceV2,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KnowledgeOverlayEdgeV2 {
    pub id: String,
    pub kind: String,
    pub source_node_id: String,
    pub target_node_id: String,
    pub provenance: KnowledgeOverlayProvenanceV2,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KnowledgeOverlayV2 {
    pub schema_version: String,
    pub layer: String,
    pub source_snapshot_exact_set_sha256: String,
    pub structural_graph_sha256: String,
    pub nodes: Vec<KnowledgeOverlayNodeV2>,
    pub edges: Vec<KnowledgeOverlayEdgeV2>,
    pub overlay_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KnowledgeOverlayManifestV2 {
    schema_version: String,
    overlay_relative_path: String,
    overlay_bytes_sha256: String,
    overlay_sha256: String,
}

#[derive(Debug, Error)]
pub enum KnowledgeOverlayErrorV2 {
    #[error("invalid knowledge overlay input: {0}")]
    InvalidInput(String),
    #[error("invalid knowledge overlay artifact: {0}")]
    InvalidArtifact(String),
    #[error("knowledge overlay output already exists: {0}")]
    OutputExists(PathBuf),
    #[error("cannot access knowledge overlay artifact {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("cannot encode or decode knowledge overlay JSON: {0}")]
    Json(#[from] serde_json::Error),
}

impl KnowledgeOverlayErrorV2 {
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidInput(message) if message.contains("snapshot") => {
                "E_V2_OVERLAY_SNAPSHOT_MISMATCH"
            }
            Self::InvalidInput(message) if message.contains("proposal") => {
                "E_V2_OVERLAY_T10_PROPOSAL_MISMATCH"
            }
            Self::InvalidInput(_) => "E_V2_OVERLAY_INPUT_INVALID",
            Self::InvalidArtifact(_) => "E_V2_OVERLAY_READBACK_INVALID",
            Self::OutputExists(_) => "E_V2_OVERLAY_OUTPUT_EXISTS",
            Self::Io { .. } => "E_V2_OVERLAY_IO",
            Self::Json(_) => "E_V2_OVERLAY_JSON",
        }
    }
}

/// Construct the claim/source/footnote/provenance layer. It does not mutate
/// the structural graph and deliberately provides no API for Provider output.
pub fn build_knowledge_overlay_v2(
    input: &KnowledgeOverlayBuildInputV2,
) -> Result<KnowledgeOverlayV2, KnowledgeOverlayErrorV2> {
    validate_structural_graph_v3(&input.structural_graph).map_err(|error| {
        KnowledgeOverlayErrorV2::InvalidInput(format!("invalid structural graph: {error}"))
    })?;
    input.verification_receipt.validate().map_err(|_| {
        KnowledgeOverlayErrorV2::InvalidInput("invalid T10 verification receipt".to_owned())
    })?;
    input
        .accepted_claim_set
        .validate(&input.verification_receipt)
        .map_err(|_| {
            KnowledgeOverlayErrorV2::InvalidInput("invalid T10 accepted claim set".to_owned())
        })?;
    validate_claim_set(input)?;

    let graph = &input.structural_graph;
    let provenance = KnowledgeOverlayProvenanceV2 {
        structural_graph_sha256: graph.graph_sha256.clone(),
        verification_receipt_sha256: input.verification_receipt.receipt_sha256.clone(),
        accepted_claim_set_sha256: input.accepted_claim_set.accepted_claim_set_sha256.clone(),
        t03_receipt_sha256: input.verification_receipt.t03_receipt_sha256.clone(),
        t04_manifest_sha256: input.verification_receipt.t04_manifest_sha256.clone(),
        document_relation_receipt_sha256s: document_receipt_digests(input)?,
    };
    validate_provenance(&provenance)?;

    let structural_evidence = graph
        .nodes
        .iter()
        .flat_map(|node| node.evidence.iter())
        .chain(graph.edges.iter().flat_map(|edge| edge.evidence.iter()))
        .map(|evidence| (evidence.evidence_id.as_str(), evidence))
        .collect::<BTreeMap<_, _>>();
    let structural_nodes = graph
        .nodes
        .iter()
        .map(|node| (node.id.as_str(), node))
        .collect::<BTreeMap<_, _>>();

    let mut nodes = Vec::new();
    let mut edges = Vec::new();
    let verification_node_id = provenance_node_id(&provenance);
    nodes.push(KnowledgeOverlayNodeV2 {
        id: verification_node_id.clone(),
        kind: "provenance".to_owned(),
        label: "t10_verification".to_owned(),
        claim_id: None,
        structural_evidence_ids: Vec::new(),
        provenance: provenance.clone(),
    });

    let mut claims = input.claims.clone();
    claims.sort_by(|left, right| left.claim_id.cmp(&right.claim_id));
    let accepted_ids = input
        .accepted_claim_set
        .accepted_claim_ids
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let receipt_states = input
        .verification_receipt
        .claims
        .iter()
        .map(|record| (record.claim_id.as_str(), record.state))
        .collect::<BTreeMap<_, _>>();
    for claim in &claims {
        let mut evidence_ids = Vec::new();
        for citation in &claim.evidence {
            let evidence = structural_evidence
                .get(citation.evidence_id.as_str())
                .ok_or_else(|| {
                    KnowledgeOverlayErrorV2::InvalidInput(format!(
                        "claim {} cites evidence absent from structural graph",
                        claim.claim_id
                    ))
                })?;
            if !citation_matches_structural(citation, evidence) {
                return Err(KnowledgeOverlayErrorV2::InvalidInput(format!(
                    "claim {} evidence does not exactly match structural graph",
                    claim.claim_id
                )));
            }
            evidence_ids.push(citation.evidence_id.clone());
        }
        evidence_ids.sort();
        evidence_ids.dedup();
        let claim_node_id = claim_node_id(&claim.claim_id);
        let is_accepted = accepted_ids.contains(claim.claim_id.as_str());
        let (kind, label, edge_kind) = if is_accepted {
            (
                "accepted_claim",
                format!("{} {} {}", claim.subject, claim.predicate, claim.object),
                "verified_by",
            )
        } else if receipt_states.get(claim.claim_id.as_str())
            == Some(&ClaimVerificationStateV2::Unknown)
        {
            // Unknown is retained only as an explicit abstention. It cannot
            // appear as grounded knowledge for any later query consumer.
            ("abstention", "unknown".to_owned(), "abstains_from")
        } else {
            return Err(KnowledgeOverlayErrorV2::InvalidInput(format!(
                "claim {} is neither accepted nor an explicit T10 abstention",
                claim.claim_id
            )));
        };
        nodes.push(KnowledgeOverlayNodeV2 {
            id: claim_node_id.clone(),
            kind: kind.to_owned(),
            // Accepted fields are sealed by proposal_set_sha256; abstentions
            // use a fixed label and introduce no free text.
            label,
            claim_id: Some(claim.claim_id.clone()),
            structural_evidence_ids: evidence_ids,
            provenance: provenance.clone(),
        });
        edges.push(KnowledgeOverlayEdgeV2 {
            id: edge_id(edge_kind, &claim_node_id, &verification_node_id),
            kind: edge_kind.to_owned(),
            source_node_id: claim_node_id,
            target_node_id: verification_node_id.clone(),
            provenance: provenance.clone(),
        });
    }

    let mut relations = input.document_relations.clone();
    relations.sort_by(|left, right| left.logical_path.cmp(&right.logical_path));
    let mut paths = BTreeSet::new();
    for relation in &relations {
        validate_document_relation(relation, &mut paths, &structural_nodes)?;
        let relation_digest = canonical_json_sha256(&relation.receipt)?;
        let relation_provenance_id =
            document_provenance_node_id(&relation.logical_path, &relation_digest);
        nodes.push(KnowledgeOverlayNodeV2 {
            id: relation_provenance_id.clone(),
            kind: "provenance".to_owned(),
            label: relation.logical_path.clone(),
            claim_id: None,
            structural_evidence_ids: Vec::new(),
            provenance: provenance.clone(),
        });
        edges.push(KnowledgeOverlayEdgeV2 {
            id: edge_id("documents", &relation_provenance_id, &verification_node_id),
            kind: "documents".to_owned(),
            source_node_id: relation_provenance_id.clone(),
            target_node_id: verification_node_id.clone(),
            provenance: provenance.clone(),
        });
        for source_id in &relation.receipt.relation.source_ids {
            let source_node_id = source_node_id(&relation.logical_path, source_id);
            let footnote_node_id = footnote_node_id(&relation.logical_path, source_id);
            nodes.push(KnowledgeOverlayNodeV2 {
                id: source_node_id.clone(),
                kind: "source".to_owned(),
                label: source_id.clone(),
                claim_id: None,
                structural_evidence_ids: Vec::new(),
                provenance: provenance.clone(),
            });
            nodes.push(KnowledgeOverlayNodeV2 {
                id: footnote_node_id.clone(),
                kind: "footnote".to_owned(),
                label: source_id.clone(),
                claim_id: None,
                structural_evidence_ids: Vec::new(),
                provenance: provenance.clone(),
            });
            edges.push(KnowledgeOverlayEdgeV2 {
                id: edge_id("has_source", &relation_provenance_id, &source_node_id),
                kind: "has_source".to_owned(),
                source_node_id: relation_provenance_id.clone(),
                target_node_id: source_node_id.clone(),
                provenance: provenance.clone(),
            });
            edges.push(KnowledgeOverlayEdgeV2 {
                id: edge_id("has_footnote", &source_node_id, &footnote_node_id),
                kind: "has_footnote".to_owned(),
                source_node_id,
                target_node_id: footnote_node_id,
                provenance: provenance.clone(),
            });
        }
    }

    nodes.sort_by(|left, right| left.id.cmp(&right.id));
    edges.sort_by(|left, right| left.id.cmp(&right.id));
    let mut overlay = KnowledgeOverlayV2 {
        schema_version: KNOWLEDGE_OVERLAY_V2_SCHEMA.to_owned(),
        layer: "knowledge_overlay".to_owned(),
        source_snapshot_exact_set_sha256: graph.source_snapshot_exact_set_sha256.clone(),
        structural_graph_sha256: graph.graph_sha256.clone(),
        nodes,
        edges,
        overlay_sha256: String::new(),
    };
    overlay.overlay_sha256 = overlay_digest(&overlay)?;
    validate_overlay(&overlay)?;
    Ok(overlay)
}

/// Persist a new overlay without replacing an independently verified output.
pub fn write_knowledge_overlay_v2(
    output_root: &Path,
    overlay: &KnowledgeOverlayV2,
) -> Result<(), KnowledgeOverlayErrorV2> {
    validate_overlay(overlay)?;
    if output_root.exists() {
        return Err(KnowledgeOverlayErrorV2::OutputExists(
            output_root.to_path_buf(),
        ));
    }
    fs::create_dir_all(output_root).map_err(|source| KnowledgeOverlayErrorV2::Io {
        path: output_root.to_path_buf(),
        source,
    })?;
    let overlay_bytes = serde_json::to_vec_pretty(overlay)?;
    let overlay_path = output_root.join(OVERLAY_FILE);
    fs::write(&overlay_path, &overlay_bytes).map_err(|source| KnowledgeOverlayErrorV2::Io {
        path: overlay_path,
        source,
    })?;
    let manifest = KnowledgeOverlayManifestV2 {
        schema_version: MANIFEST_SCHEMA.to_owned(),
        overlay_relative_path: OVERLAY_FILE.to_owned(),
        overlay_bytes_sha256: digest_bytes(&overlay_bytes),
        overlay_sha256: overlay.overlay_sha256.clone(),
    };
    let manifest_path = output_root.join("manifest.json");
    fs::write(&manifest_path, serde_json::to_vec_pretty(&manifest)?).map_err(|source| {
        KnowledgeOverlayErrorV2::Io {
            path: manifest_path,
            source,
        }
    })?;
    Ok(())
}

/// Read an overlay only after raw-byte, manifest, semantic, and provenance
/// identities all agree.
pub fn read_knowledge_overlay_v2(
    output_root: &Path,
) -> Result<KnowledgeOverlayV2, KnowledgeOverlayErrorV2> {
    let root = verified_overlay_root(output_root)?;
    let manifest_bytes = read_overlay_artifact_file(
        &root,
        Path::new("manifest.json"),
        MAX_OVERLAY_MANIFEST_BYTES,
    )?;
    let manifest: KnowledgeOverlayManifestV2 = serde_json::from_slice(&manifest_bytes)?;
    if manifest.schema_version != MANIFEST_SCHEMA || manifest.overlay_relative_path != OVERLAY_FILE
    {
        return Err(KnowledgeOverlayErrorV2::InvalidArtifact(
            "invalid overlay manifest identity".to_owned(),
        ));
    }
    validate_relative_path(&manifest.overlay_relative_path)?;
    validate_sha(&manifest.overlay_bytes_sha256, "manifest overlay bytes")?;
    validate_sha(&manifest.overlay_sha256, "manifest overlay")?;
    let bytes = read_overlay_artifact_file(
        &root,
        Path::new(&manifest.overlay_relative_path),
        MAX_OVERLAY_BYTES,
    )?;
    if digest_bytes(&bytes) != manifest.overlay_bytes_sha256 {
        return Err(KnowledgeOverlayErrorV2::InvalidArtifact(
            "raw overlay bytes do not match manifest".to_owned(),
        ));
    }
    let overlay: KnowledgeOverlayV2 = serde_json::from_slice(&bytes)?;
    if overlay.overlay_sha256 != manifest.overlay_sha256 {
        return Err(KnowledgeOverlayErrorV2::InvalidArtifact(
            "overlay identity does not match manifest".to_owned(),
        ));
    }
    validate_overlay(&overlay).map_err(|error| {
        KnowledgeOverlayErrorV2::InvalidArtifact(format!(
            "overlay readback validation failed: {error}"
        ))
    })?;
    Ok(overlay)
}

fn verified_overlay_root(output_root: &Path) -> Result<PathBuf, KnowledgeOverlayErrorV2> {
    let metadata =
        fs::symlink_metadata(output_root).map_err(|source| KnowledgeOverlayErrorV2::Io {
            path: output_root.to_path_buf(),
            source,
        })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(KnowledgeOverlayErrorV2::InvalidArtifact(
            "overlay artifact root must be a non-symlink directory".to_owned(),
        ));
    }
    let canonical =
        fs::canonicalize(output_root).map_err(|source| KnowledgeOverlayErrorV2::Io {
            path: output_root.to_path_buf(),
            source,
        })?;
    let canonical_metadata =
        fs::symlink_metadata(&canonical).map_err(|source| KnowledgeOverlayErrorV2::Io {
            path: canonical.clone(),
            source,
        })?;
    if canonical_metadata.file_type().is_symlink() || !canonical_metadata.is_dir() {
        return Err(KnowledgeOverlayErrorV2::InvalidArtifact(
            "canonical overlay artifact root is unsafe".to_owned(),
        ));
    }
    Ok(canonical)
}

fn read_overlay_artifact_file(
    root: &Path,
    relative: &Path,
    max_bytes: usize,
) -> Result<Vec<u8>, KnowledgeOverlayErrorV2> {
    let candidate = root.join(relative);
    let parts = relative.components().collect::<Vec<_>>();
    if parts.is_empty()
        || parts
            .iter()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err(KnowledgeOverlayErrorV2::InvalidArtifact(
            "overlay artifact path must be a non-empty relative normal path".to_owned(),
        ));
    }
    let mut cursor = root.to_path_buf();
    for (index, part) in parts.iter().enumerate() {
        let Component::Normal(name) = part else {
            unreachable!("normal components checked")
        };
        cursor.push(name);
        let metadata =
            fs::symlink_metadata(&cursor).map_err(|source| KnowledgeOverlayErrorV2::Io {
                path: cursor.clone(),
                source,
            })?;
        if metadata.file_type().is_symlink() {
            return Err(KnowledgeOverlayErrorV2::InvalidArtifact(format!(
                "overlay artifact path contains a symlink: {}",
                cursor.display()
            )));
        }
        if index + 1 == parts.len() {
            if !metadata.file_type().is_file() {
                return Err(KnowledgeOverlayErrorV2::InvalidArtifact(format!(
                    "overlay artifact endpoint is not a regular file: {}",
                    cursor.display()
                )));
            }
        } else if !metadata.is_dir() {
            return Err(KnowledgeOverlayErrorV2::InvalidArtifact(format!(
                "overlay artifact path contains a non-directory component: {}",
                cursor.display()
            )));
        }
    }
    let mut file = open_overlay_file_no_follow(root, relative)?;
    let opened = file
        .metadata()
        .map_err(|source| KnowledgeOverlayErrorV2::Io {
            path: candidate.clone(),
            source,
        })?;
    if !opened.file_type().is_file() || opened.len() > max_bytes as u64 {
        return Err(KnowledgeOverlayErrorV2::InvalidArtifact(format!(
            "overlay artifact file exceeds {max_bytes} bytes or is not regular: {}",
            candidate.display()
        )));
    }
    ensure_private_overlay_inode(&candidate, &opened)?;
    let mut bytes = Vec::with_capacity(usize::try_from(opened.len()).unwrap_or(max_bytes));
    file.read_to_end(&mut bytes)
        .map_err(|source| KnowledgeOverlayErrorV2::Io {
            path: candidate.clone(),
            source,
        })?;
    if bytes.len() > max_bytes {
        return Err(KnowledgeOverlayErrorV2::InvalidArtifact(format!(
            "overlay artifact file exceeds {max_bytes} bytes after read: {}",
            candidate.display()
        )));
    }
    let after = fs::symlink_metadata(&candidate).map_err(|source| KnowledgeOverlayErrorV2::Io {
        path: candidate.clone(),
        source,
    })?;
    ensure_same_overlay_inode(&candidate, &after, &opened)?;
    Ok(bytes)
}

#[cfg(unix)]
fn open_overlay_file_no_follow(
    root: &Path,
    relative: &Path,
) -> Result<File, KnowledgeOverlayErrorV2> {
    use rustix::fs::{Mode, OFlags, open, openat};
    let directory_flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut directory = open(root, directory_flags, Mode::empty()).map_err(|error| {
        KnowledgeOverlayErrorV2::Io {
            path: root.to_path_buf(),
            source: std::io::Error::from_raw_os_error(error.raw_os_error()),
        }
    })?;
    let parts = relative.components().collect::<Vec<_>>();
    for (index, part) in parts.iter().enumerate() {
        let Component::Normal(name) = part else {
            return Err(KnowledgeOverlayErrorV2::InvalidArtifact(
                "unsafe overlay artifact path".to_owned(),
            ));
        };
        let is_file = index + 1 == parts.len();
        let flags = if is_file {
            OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC
        } else {
            directory_flags
        };
        let opened = openat(&directory, *name, flags, Mode::empty()).map_err(|error| {
            KnowledgeOverlayErrorV2::Io {
                path: root.join(relative),
                source: std::io::Error::from_raw_os_error(error.raw_os_error()),
            }
        })?;
        if is_file {
            return Ok(File::from(opened));
        }
        directory = opened;
    }
    Err(KnowledgeOverlayErrorV2::InvalidArtifact(
        "empty overlay artifact path".to_owned(),
    ))
}

#[cfg(not(unix))]
fn open_overlay_file_no_follow(
    root: &Path,
    relative: &Path,
) -> Result<File, KnowledgeOverlayErrorV2> {
    File::open(root.join(relative)).map_err(|source| KnowledgeOverlayErrorV2::Io {
        path: root.join(relative),
        source,
    })
}

fn ensure_private_overlay_inode(
    path: &Path,
    metadata: &fs::Metadata,
) -> Result<(), KnowledgeOverlayErrorV2> {
    if !metadata.file_type().is_file() {
        return Err(KnowledgeOverlayErrorV2::InvalidArtifact(
            "overlay artifact handle is not regular".to_owned(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() > 1 {
            return Err(KnowledgeOverlayErrorV2::InvalidArtifact(format!(
                "overlay artifact hardlink is rejected: {}",
                path.display()
            )));
        }
    }
    Ok(())
}

fn ensure_same_overlay_inode(
    path: &Path,
    path_metadata: &fs::Metadata,
    file_metadata: &fs::Metadata,
) -> Result<(), KnowledgeOverlayErrorV2> {
    ensure_private_overlay_inode(path, path_metadata)?;
    ensure_private_overlay_inode(path, file_metadata)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if path_metadata.dev() != file_metadata.dev() || path_metadata.ino() != file_metadata.ino()
        {
            return Err(KnowledgeOverlayErrorV2::InvalidArtifact(format!(
                "overlay artifact inode changed while reading: {}",
                path.display()
            )));
        }
    }
    Ok(())
}

fn validate_claim_set(input: &KnowledgeOverlayBuildInputV2) -> Result<(), KnowledgeOverlayErrorV2> {
    let accepted = &input.accepted_claim_set;
    if !matches!(
        accepted.state,
        ClaimSetStateV2::AcceptedGrounded | ClaimSetStateV2::AcceptedPartialWithAbstention
    ) || accepted.accepted_claim_ids.is_empty()
    {
        return Err(KnowledgeOverlayErrorV2::InvalidInput(
            "T10 accepted claim set has no accepted semantic claims".to_owned(),
        ));
    }
    if input.structural_graph.source_snapshot_exact_set_sha256
        != accepted.source_snapshot_exact_set_sha256
        || input.verification_receipt.source_snapshot_exact_set_sha256
            != accepted.source_snapshot_exact_set_sha256
    {
        return Err(KnowledgeOverlayErrorV2::InvalidInput(
            "snapshot mismatch between T10 and T11A".to_owned(),
        ));
    }
    let proposal_digest = claim_proposal_set_digest(&input.claims).map_err(|_| {
        KnowledgeOverlayErrorV2::InvalidInput("invalid T10 proposal set".to_owned())
    })?;
    if proposal_digest != input.verification_receipt.proposal_set_sha256 {
        return Err(KnowledgeOverlayErrorV2::InvalidInput(
            "T10 proposal set digest mismatch".to_owned(),
        ));
    }
    let mut claim_ids = input
        .claims
        .iter()
        .map(|claim| claim.claim_id.clone())
        .collect::<Vec<_>>();
    claim_ids.sort();
    let receipt_ids = input
        .verification_receipt
        .claims
        .iter()
        .map(|record| record.claim_id.clone())
        .collect::<Vec<_>>();
    if claim_ids != receipt_ids
        || !accepted
            .accepted_claim_ids
            .iter()
            .all(|id| claim_ids.binary_search(id).is_ok())
    {
        return Err(KnowledgeOverlayErrorV2::InvalidInput(
            "T10 proposal claims do not match receipt or accepted subset".to_owned(),
        ));
    }
    let receipt_states = input
        .verification_receipt
        .claims
        .iter()
        .map(|record| (record.claim_id.as_str(), record.state))
        .collect::<BTreeMap<_, _>>();
    for claim in &input.claims {
        let state = receipt_states.get(claim.claim_id.as_str());
        let accepted_claim = accepted
            .accepted_claim_ids
            .binary_search(&claim.claim_id)
            .is_ok();
        let expected = if accepted_claim {
            claim.modality == ClaimModalityV2::Asserted
                && state == Some(&ClaimVerificationStateV2::Entailed)
        } else {
            claim.modality == ClaimModalityV2::Unknown
                && state == Some(&ClaimVerificationStateV2::Unknown)
        };
        if !expected
            || claim.subject.trim().is_empty()
            || claim.predicate.trim().is_empty()
            || claim.object.trim().is_empty()
            || claim.natural_language.trim().is_empty()
            || claim.evidence.is_empty()
        {
            return Err(KnowledgeOverlayErrorV2::InvalidInput(format!(
                "claim {} is not a deterministic T10 accepted claim or abstention",
                claim.claim_id
            )));
        }
    }
    Ok(())
}

fn document_receipt_digests(
    input: &KnowledgeOverlayBuildInputV2,
) -> Result<Vec<String>, KnowledgeOverlayErrorV2> {
    let mut digests = input
        .document_relations
        .iter()
        .map(|relation| {
            canonical_json_sha256(&relation.receipt).map_err(KnowledgeOverlayErrorV2::Json)
        })
        .collect::<Result<Vec<_>, _>>()?;
    digests.sort();
    digests.dedup();
    if digests.is_empty() {
        return Err(KnowledgeOverlayErrorV2::InvalidInput(
            "T06 source/footnote provenance is required".to_owned(),
        ));
    }
    Ok(digests)
}

fn validate_document_relation(
    relation: &DocumentRelationGraphInputV3,
    seen_paths: &mut BTreeSet<String>,
    structural_nodes: &BTreeMap<&str, &StructuralGraphNodeV3>,
) -> Result<(), KnowledgeOverlayErrorV2> {
    validate_logical_path(&relation.logical_path)?;
    if !seen_paths.insert(relation.logical_path.clone())
        || relation.receipt.schema_version != "gtkg.document-relation-receipt/v2"
        || relation.receipt.relation.format != DocumentRelationFormatV2::Markdown
        || relation.receipt.relation.status != DocumentRelationStatusV2::Passed
        || relation.receipt.relation.source_ids.is_empty()
        || relation.receipt.relation.source_ids != relation.receipt.relation.footnote_ids
        || !relation.receipt.relation.issues.is_empty()
    {
        return Err(KnowledgeOverlayErrorV2::InvalidInput(
            "T06 document relation is not a passed source/footnote closure".to_owned(),
        ));
    }
    relation
        .receipt
        .relation
        .binding
        .raw_spec_pin
        .validate()
        .map_err(|_| {
            KnowledgeOverlayErrorV2::InvalidInput(
                "invalid T03 document relation binding".to_owned(),
            )
        })?;
    validate_sha(&relation.receipt.document_sha256, "document digest")?;
    validate_sha(
        &relation.receipt.relation.binding.corpus_manifest_sha256,
        "T03 corpus manifest digest",
    )?;
    validate_sha(
        &relation.receipt.relation.binding.receipt_sha256,
        "T03 relation receipt digest",
    )?;
    let relation_digest = canonical_json_sha256(&relation.receipt)?;
    let document_id = document_node_id(&relation.logical_path);
    let Some(document_node) = structural_nodes.get(document_id.as_str()) else {
        return Err(KnowledgeOverlayErrorV2::InvalidInput(
            "T06 document is absent from the structural graph".to_owned(),
        ));
    };
    if document_node.provenance.input_kind != "document_relation_receipt"
        || document_node.provenance.input_sha256 != relation_digest
    {
        return Err(KnowledgeOverlayErrorV2::InvalidInput(
            "T06 document provenance does not match the structural graph".to_owned(),
        ));
    }
    for source_id in &relation.receipt.relation.source_ids {
        let structural_source =
            structural_document_source_node_id(&relation.logical_path, source_id);
        let Some(source_node) = structural_nodes.get(structural_source.as_str()) else {
            return Err(KnowledgeOverlayErrorV2::InvalidInput(format!(
                "T06 source {source_id} is absent from the structural graph"
            )));
        };
        if source_node.provenance.input_kind != "document_relation_receipt"
            || source_node.provenance.input_sha256 != relation_digest
        {
            return Err(KnowledgeOverlayErrorV2::InvalidInput(
                "T06 source provenance does not match the structural graph".to_owned(),
            ));
        }
    }
    Ok(())
}

fn citation_matches_structural(
    citation: &crate::claim_v2::ClaimEvidenceRefV2,
    evidence: &GraphEvidenceV3,
) -> bool {
    evidence.kind == "evidence_span"
        && evidence.source_snapshot_exact_set_sha256.as_deref()
            == Some(citation.source_snapshot_exact_set_sha256.as_str())
        && evidence.source_logical_path == citation.source_logical_path
        && evidence.source_sha256 == citation.source_sha256
        && evidence.byte_start == Some(citation.byte_start)
        && evidence.byte_end == Some(citation.byte_end)
        && evidence.snippet_sha256.as_deref() == Some(citation.snippet_sha256.as_str())
}

fn validate_overlay(overlay: &KnowledgeOverlayV2) -> Result<(), KnowledgeOverlayErrorV2> {
    if overlay.schema_version != KNOWLEDGE_OVERLAY_V2_SCHEMA || overlay.layer != "knowledge_overlay"
    {
        return Err(KnowledgeOverlayErrorV2::InvalidArtifact(
            "overlay must remain in the knowledge_overlay layer".to_owned(),
        ));
    }
    validate_sha(
        &overlay.source_snapshot_exact_set_sha256,
        "overlay snapshot",
    )?;
    validate_sha(&overlay.structural_graph_sha256, "structural graph digest")?;
    validate_sha(&overlay.overlay_sha256, "overlay digest")?;
    let node_ids = overlay
        .nodes
        .iter()
        .map(|node| node.id.as_str())
        .collect::<BTreeSet<_>>();
    if node_ids.len() != overlay.nodes.len() || overlay.nodes.is_empty() {
        return Err(KnowledgeOverlayErrorV2::InvalidArtifact(
            "overlay has duplicate or no nodes".to_owned(),
        ));
    }
    for node in &overlay.nodes {
        if !matches!(
            node.kind.as_str(),
            "accepted_claim" | "abstention" | "source" | "footnote" | "provenance"
        ) || node.id.trim().is_empty()
            || node.label.trim().is_empty()
            || matches!(node.kind.as_str(), "accepted_claim" | "abstention")
                != node.claim_id.is_some()
            || !strictly_sorted_unique(&node.structural_evidence_ids)
        {
            return Err(KnowledgeOverlayErrorV2::InvalidArtifact(
                "overlay node contract is invalid".to_owned(),
            ));
        }
        if matches!(node.kind.as_str(), "accepted_claim" | "abstention")
            && node.structural_evidence_ids.is_empty()
        {
            return Err(KnowledgeOverlayErrorV2::InvalidArtifact(
                "accepted claim lacks structural evidence".to_owned(),
            ));
        }
        validate_provenance(&node.provenance)?;
    }
    let edge_ids = overlay
        .edges
        .iter()
        .map(|edge| edge.id.as_str())
        .collect::<BTreeSet<_>>();
    if edge_ids.len() != overlay.edges.len() {
        return Err(KnowledgeOverlayErrorV2::InvalidArtifact(
            "overlay has duplicate edges".to_owned(),
        ));
    }
    for edge in &overlay.edges {
        if !matches!(
            edge.kind.as_str(),
            "verified_by" | "abstains_from" | "documents" | "has_source" | "has_footnote"
        ) || !node_ids.contains(edge.source_node_id.as_str())
            || !node_ids.contains(edge.target_node_id.as_str())
        {
            return Err(KnowledgeOverlayErrorV2::InvalidArtifact(
                "overlay edge contract is invalid".to_owned(),
            ));
        }
        validate_provenance(&edge.provenance)?;
    }
    if overlay.overlay_sha256 != overlay_digest(overlay)? {
        return Err(KnowledgeOverlayErrorV2::InvalidArtifact(
            "overlay digest mismatch".to_owned(),
        ));
    }
    Ok(())
}

fn validate_provenance(
    provenance: &KnowledgeOverlayProvenanceV2,
) -> Result<(), KnowledgeOverlayErrorV2> {
    validate_sha(&provenance.structural_graph_sha256, "provenance graph")?;
    validate_sha(
        &provenance.verification_receipt_sha256,
        "provenance T10 receipt",
    )?;
    validate_sha(
        &provenance.accepted_claim_set_sha256,
        "provenance accepted set",
    )?;
    validate_sha(&provenance.t03_receipt_sha256, "provenance T03 receipt")?;
    validate_sha(&provenance.t04_manifest_sha256, "provenance T04 manifest")?;
    if !strictly_sorted_unique(&provenance.document_relation_receipt_sha256s) {
        return Err(KnowledgeOverlayErrorV2::InvalidInput(
            "provenance relation receipts are not sorted and unique".to_owned(),
        ));
    }
    for value in &provenance.document_relation_receipt_sha256s {
        validate_sha(value, "provenance document relation receipt")?;
    }
    Ok(())
}

fn overlay_digest(overlay: &KnowledgeOverlayV2) -> Result<String, KnowledgeOverlayErrorV2> {
    let mut unsigned = overlay.clone();
    unsigned.overlay_sha256.clear();
    canonical_json_sha256(&unsigned).map_err(KnowledgeOverlayErrorV2::Json)
}

fn validate_sha(value: &str, label: &str) -> Result<(), KnowledgeOverlayErrorV2> {
    validate_sha256(value)
        .map_err(|_| KnowledgeOverlayErrorV2::InvalidInput(format!("invalid {label} sha256")))
}

fn validate_logical_path(value: &str) -> Result<(), KnowledgeOverlayErrorV2> {
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
        return Err(KnowledgeOverlayErrorV2::InvalidInput(format!(
            "unsafe logical path {value}"
        )));
    }
    Ok(())
}

fn validate_relative_path(value: &str) -> Result<(), KnowledgeOverlayErrorV2> {
    let path = Path::new(value);
    if value != OVERLAY_FILE
        || path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(KnowledgeOverlayErrorV2::InvalidArtifact(
            "unsafe overlay relative path".to_owned(),
        ));
    }
    Ok(())
}

fn strictly_sorted_unique(values: &[String]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn digest_bytes(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn stable_id_hash(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

fn claim_node_id(claim_id: &str) -> String {
    format!("claim:{}", stable_id_hash(claim_id))
}

fn provenance_node_id(provenance: &KnowledgeOverlayProvenanceV2) -> String {
    format!(
        "provenance:{}",
        stable_id_hash(&format!(
            "{}\n{}\n{}",
            provenance.verification_receipt_sha256,
            provenance.accepted_claim_set_sha256,
            provenance.structural_graph_sha256
        ))
    )
}

fn document_provenance_node_id(path: &str, digest: &str) -> String {
    format!(
        "provenance:{}",
        stable_id_hash(&format!("document\n{path}\n{digest}"))
    )
}

fn source_node_id(path: &str, source_id: &str) -> String {
    format!("source:{}", stable_id_hash(&format!("{path}\n{source_id}")))
}

fn footnote_node_id(path: &str, footnote_id: &str) -> String {
    format!(
        "footnote:{}",
        stable_id_hash(&format!("{path}\n{footnote_id}"))
    )
}

fn document_node_id(path: &str) -> String {
    format!("document:{}", stable_id_hash(path))
}

fn structural_document_source_node_id(path: &str, source_id: &str) -> String {
    format!(
        "document-source:{}",
        stable_id_hash(&format!("{path}\n{source_id}"))
    )
}

fn edge_id(kind: &str, source: &str, target: &str) -> String {
    format!(
        "overlay-edge:{}",
        stable_id_hash(&format!("{kind}\n{source}\n{target}"))
    )
}
