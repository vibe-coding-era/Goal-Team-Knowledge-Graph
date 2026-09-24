//! T14B local-only Wiki and A2UI projection.
//!
//! This projection has a deliberately narrow boundary: it reads the verified
//! T11A structural graph and T11B knowledge overlay, binds both to the T13
//! local lifecycle identity, then writes a static Wiki whose index and page
//! shards can be read independently.  It neither invokes a Provider nor
//! promotes an old renderer/browser receipt.  The generated A2UI stream is
//! therefore capped at `a2ui_generatable` until the existing renderer evidence
//! chain is separately re-run against this exact projection.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Component, Path, PathBuf};

use gtkg_protocol::{canonical_json_sha256, validate_sha256};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::graph_v3::{StructuralGraphErrorV3, read_structural_graph_v3};
use crate::knowledge_overlay_v2::{KnowledgeOverlayErrorV2, read_knowledge_overlay_v2};
use crate::lifecycle_v2::LifecycleIdentityV2;

pub const LOCAL_WIKI_A2UI_SCHEMA_V2: &str = "gtkg.local-wiki-a2ui/v2";
pub const LOCAL_WIKI_A2UI_EVIDENCE_STATE_V2: &str = "a2ui_generatable";
const MANIFEST_SCHEMA: &str = "gtkg.local-wiki-a2ui-manifest/v2";
const INDEX_SCHEMA: &str = "gtkg.local-wiki-index/v2";
const PAGE_SCHEMA: &str = "gtkg.local-wiki-page/v2";
const MAX_INDEX_ENTRIES: usize = 100_000;
const MAX_PAGE_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalWikiA2uiInputV2 {
    pub graph_artifact_root: PathBuf,
    pub overlay_artifact_root: PathBuf,
    pub lifecycle_identity: LifecycleIdentityV2,
    /// The exact T12B `graph.search` result consumed by this projection.
    /// T14B never synthesizes an equivalent evidence pack from graph files.
    pub query_receipt: ClaimAwareQueryReceiptV2,
}

/// A sealed, in-memory T12B query receipt. The result itself is an immutable
/// protocol value; its canonical digest is carried into the projection and
/// browser fixture so a structurally similar replacement cannot be accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimAwareQueryReceiptV2 {
    pub result: Value,
    pub query_receipt_sha256: String,
}

impl ClaimAwareQueryReceiptV2 {
    pub fn from_result(result: Value) -> Result<Self, LocalWikiA2uiErrorV2> {
        let query_receipt_sha256 = canonical_json_sha256(&result).map_err(|error| {
            LocalWikiA2uiErrorV2::InvalidInput(format!("T12B query receipt digest: {error}"))
        })?;
        Ok(Self {
            result,
            query_receipt_sha256,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalWikiA2uiEntryV2 {
    pub id: String,
    pub kind: String,
    pub title: String,
    pub evidence_ids: Vec<String>,
    pub page_relative_path: String,
    pub page_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalWikiA2uiProjectionV2 {
    pub schema_version: String,
    pub source_snapshot_exact_set_sha256: String,
    pub structural_graph_sha256: String,
    pub knowledge_overlay_sha256: String,
    pub lifecycle_identity_sha256: String,
    pub query_receipt_sha256: String,
    pub evidence_state: String,
    pub entries: Vec<LocalWikiA2uiEntryV2>,
    pub projection_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProjectionManifestV2 {
    schema_version: String,
    projection_sha256: String,
    index_relative_path: String,
    index_sha256: String,
    a2ui_stream_relative_path: String,
    a2ui_stream_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WikiIndexV2 {
    schema_version: String,
    projection: LocalWikiA2uiProjectionV2,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WikiPageV2 {
    schema_version: String,
    id: String,
    kind: String,
    title: String,
    body: String,
    evidence_ids: Vec<String>,
    structural_graph_sha256: String,
    knowledge_overlay_sha256: String,
    lifecycle_identity_sha256: String,
    query_receipt_sha256: String,
    evidence_state: String,
}

#[derive(Debug, Error)]
pub enum LocalWikiA2uiErrorV2 {
    #[error("invalid local Wiki/A2UI input: {0}")]
    InvalidInput(String),
    #[error("verified structural graph readback failed: {0}")]
    GraphReadback(#[from] StructuralGraphErrorV3),
    #[error("verified knowledge overlay readback failed: {0}")]
    OverlayReadback(#[from] KnowledgeOverlayErrorV2),
    #[error("local Wiki/A2UI output already exists: {0}")]
    OutputExists(PathBuf),
    #[error("local Wiki/A2UI artifact is invalid: {0}")]
    InvalidArtifact(String),
    #[error("cannot access local Wiki/A2UI artifact {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("cannot encode or decode local Wiki/A2UI JSON: {0}")]
    Json(#[from] serde_json::Error),
}

impl LocalWikiA2uiErrorV2 {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidInput(_) => "E_V2_WIKI_A2UI_INPUT_INVALID",
            Self::GraphReadback(_) | Self::OverlayReadback(_) => "E_V2_WIKI_A2UI_READBACK",
            Self::OutputExists(_) => "E_V2_WIKI_A2UI_OUTPUT_EXISTS",
            Self::InvalidArtifact(_) => "E_V2_WIKI_A2UI_ARTIFACT_INVALID",
            Self::Io { .. } => "E_V2_WIKI_A2UI_IO",
            Self::Json(_) => "E_V2_WIKI_A2UI_JSON",
        }
    }
}

/// Build the immutable projection plan from verified upstream artifacts.
/// Page content is a direct, inert presentation of graph/overlay labels; this
/// function never accepts arbitrary summaries, HTML, a Provider response, or
/// a target project process.
pub fn build_local_wiki_a2ui_projection_v2(
    input: &LocalWikiA2uiInputV2,
) -> Result<LocalWikiA2uiProjectionV2, LocalWikiA2uiErrorV2> {
    input
        .lifecycle_identity
        .validate()
        .map_err(|error| LocalWikiA2uiErrorV2::InvalidInput(error.to_string()))?;
    let graph = read_structural_graph_v3(&input.graph_artifact_root)?;
    let overlay = read_knowledge_overlay_v2(&input.overlay_artifact_root)?;
    if graph.layer != "structural_only" || graph.knowledge_overlay.is_some() {
        return Err(LocalWikiA2uiErrorV2::InvalidInput(
            "T14B requires a structural_only T11A graph".to_owned(),
        ));
    }
    if overlay.layer != "knowledge_overlay"
        || overlay.structural_graph_sha256 != graph.graph_sha256
        || overlay.source_snapshot_exact_set_sha256 != graph.source_snapshot_exact_set_sha256
    {
        return Err(LocalWikiA2uiErrorV2::InvalidInput(
            "T11B overlay does not bind to the verified T11A graph".to_owned(),
        ));
    }
    if input.lifecycle_identity.source_snapshot_exact_set_sha256
        != graph.source_snapshot_exact_set_sha256
        || input.lifecycle_identity.structural_graph_sha256 != graph.graph_sha256
        || input.lifecycle_identity.knowledge_overlay_sha256 != overlay.overlay_sha256
    {
        return Err(LocalWikiA2uiErrorV2::InvalidInput(
            "T13 lifecycle identity does not bind to verified T11A/T11B artifacts".to_owned(),
        ));
    }
    validate_t12b_query_receipt(
        &input.query_receipt,
        &graph.source_snapshot_exact_set_sha256,
        &graph.graph_sha256,
        &overlay.overlay_sha256,
    )?;
    let lifecycle_identity_sha256 = input
        .lifecycle_identity
        .identity_sha256()
        .map_err(|error| LocalWikiA2uiErrorV2::InvalidInput(error.to_string()))?;
    let mut entries = Vec::new();
    let mut ids = BTreeSet::new();
    for node in &graph.nodes {
        push_entry(
            &mut entries,
            &mut ids,
            &node.id,
            &format!("structural_{}", node.kind),
            &node.label,
            node.evidence
                .iter()
                .map(|item| item.evidence_id.clone())
                .collect(),
        )?;
    }
    for node in &overlay.nodes {
        // T11B has already separated accepted claims from abstentions.  Both
        // are displayable, while no structural record is promoted to a claim.
        push_entry(
            &mut entries,
            &mut ids,
            &node.id,
            &node.kind,
            &node.label,
            node.structural_evidence_ids.clone(),
        )?;
    }
    entries.sort_by(|left, right| left.id.cmp(&right.id));
    if entries.is_empty() || entries.len() > MAX_INDEX_ENTRIES {
        return Err(LocalWikiA2uiErrorV2::InvalidInput(format!(
            "projection requires between 1 and {MAX_INDEX_ENTRIES} entries"
        )));
    }
    let mut projection = LocalWikiA2uiProjectionV2 {
        schema_version: LOCAL_WIKI_A2UI_SCHEMA_V2.to_owned(),
        source_snapshot_exact_set_sha256: graph.source_snapshot_exact_set_sha256,
        structural_graph_sha256: graph.graph_sha256,
        knowledge_overlay_sha256: overlay.overlay_sha256,
        lifecycle_identity_sha256,
        query_receipt_sha256: input.query_receipt.query_receipt_sha256.clone(),
        evidence_state: LOCAL_WIKI_A2UI_EVIDENCE_STATE_V2.to_owned(),
        entries,
        projection_sha256: String::new(),
    };
    bind_page_digests(&mut projection)?;
    projection.projection_sha256 = projection_digest(&projection)?;
    Ok(projection)
}

fn validate_t12b_query_receipt(
    receipt: &ClaimAwareQueryReceiptV2,
    source_snapshot_exact_set_sha256: &str,
    structural_graph_sha256: &str,
    knowledge_overlay_sha256: &str,
) -> Result<(), LocalWikiA2uiErrorV2> {
    let observed_digest = canonical_json_sha256(&receipt.result).map_err(|error| {
        LocalWikiA2uiErrorV2::InvalidInput(format!("T12B query receipt digest: {error}"))
    })?;
    if observed_digest != receipt.query_receipt_sha256 {
        return Err(LocalWikiA2uiErrorV2::InvalidInput(
            "T12B query receipt digest drifted".to_owned(),
        ));
    }
    let result = &receipt.result;
    let graph = &result["evidence_pack"]["graph_readback"];
    let overlay = &result["evidence_pack"]["overlay_readback"];
    if result["schema_version"] != "gtkg.claim-aware-query-result/v2"
        || result["operation_id"] != "graph.search"
        || result["mode"] != "claim_aware_hybrid"
        || graph["source_snapshot_exact_set_sha256"] != source_snapshot_exact_set_sha256
        || graph["graph_sha256"] != structural_graph_sha256
        || graph["layer"] != "structural_only"
        || overlay["source_snapshot_exact_set_sha256"] != source_snapshot_exact_set_sha256
        || overlay["structural_graph_sha256"] != structural_graph_sha256
        || overlay["overlay_sha256"] != knowledge_overlay_sha256
        || overlay["layer"] != "knowledge_overlay"
        || !result["evidence_pack"]["evidence"].is_array()
        || !result["result"]["matches"].is_array()
    {
        return Err(LocalWikiA2uiErrorV2::InvalidInput(
            "T12B graph.search QueryReceipt is not bound to the verified graph/overlay evidence pack"
                .to_owned(),
        ));
    }
    Ok(())
}

/// Write a static local projection. This is a same-principal local-development
/// writer, not a Current/Release writer or a multi-user security boundary;
/// T15D owns any stronger host/process assurance. Its root is nevertheless
/// created atomically and a partial write lacks the final manifest, so readers
/// fail closed rather than consuming an incomplete replacement.
pub fn write_local_wiki_a2ui_projection_v2(
    output_root: &Path,
    projection: &LocalWikiA2uiProjectionV2,
) -> Result<(), LocalWikiA2uiErrorV2> {
    validate_projection(projection)?;
    fs::create_dir(output_root).map_err(|source| {
        if source.kind() == std::io::ErrorKind::AlreadyExists {
            LocalWikiA2uiErrorV2::OutputExists(output_root.to_path_buf())
        } else {
            LocalWikiA2uiErrorV2::Io {
                path: output_root.to_path_buf(),
                source,
            }
        }
    })?;
    let root_metadata =
        fs::symlink_metadata(output_root).map_err(|source| LocalWikiA2uiErrorV2::Io {
            path: output_root.to_path_buf(),
            source,
        })?;
    if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
        return Err(LocalWikiA2uiErrorV2::InvalidArtifact(
            "local projection writer root did not create a plain directory".to_owned(),
        ));
    }
    let pages = output_root.join("pages");
    fs::create_dir(&pages).map_err(|source| LocalWikiA2uiErrorV2::Io {
        path: pages.clone(),
        source,
    })?;
    for entry in &projection.entries {
        let page = WikiPageV2 {
            schema_version: PAGE_SCHEMA.to_owned(),
            id: entry.id.clone(),
            kind: entry.kind.clone(),
            title: entry.title.clone(),
            body: entry.title.clone(),
            evidence_ids: entry.evidence_ids.clone(),
            structural_graph_sha256: projection.structural_graph_sha256.clone(),
            knowledge_overlay_sha256: projection.knowledge_overlay_sha256.clone(),
            lifecycle_identity_sha256: projection.lifecycle_identity_sha256.clone(),
            query_receipt_sha256: projection.query_receipt_sha256.clone(),
            evidence_state: projection.evidence_state.clone(),
        };
        let bytes = serde_json::to_vec(&page)?;
        if bytes.len() > MAX_PAGE_BYTES || sha(&bytes) != entry.page_sha256 {
            return Err(LocalWikiA2uiErrorV2::InvalidArtifact(format!(
                "page plan does not bind {}",
                entry.id
            )));
        }
        let path = output_root.join(&entry.page_relative_path);
        fs::write(&path, bytes).map_err(|source| LocalWikiA2uiErrorV2::Io { path, source })?;
    }
    let index = WikiIndexV2 {
        schema_version: INDEX_SCHEMA.to_owned(),
        projection: projection.clone(),
    };
    let index_bytes = serde_json::to_vec(&index)?;
    let stream_bytes = render_a2ui_stream(projection)?;
    let manifest = ProjectionManifestV2 {
        schema_version: MANIFEST_SCHEMA.to_owned(),
        projection_sha256: projection.projection_sha256.clone(),
        index_relative_path: "index.json".to_owned(),
        index_sha256: sha(&index_bytes),
        a2ui_stream_relative_path: "a2ui/stream.jsonl".to_owned(),
        a2ui_stream_sha256: sha(&stream_bytes),
    };
    let a2ui = output_root.join("a2ui");
    fs::create_dir(&a2ui).map_err(|source| LocalWikiA2uiErrorV2::Io { path: a2ui, source })?;
    write_file(output_root.join("index.json"), index_bytes)?;
    write_file(output_root.join("a2ui/stream.jsonl"), stream_bytes)?;
    write_file(
        output_root.join("index.html"),
        WIKI_HTML.as_bytes().to_vec(),
    )?;
    write_file(output_root.join("app.js"), WIKI_JS.as_bytes().to_vec())?;
    write_file(
        output_root.join("manifest.json"),
        serde_json::to_vec(&manifest)?,
    )
}

/// Read the index and all immutable identity bindings without eagerly reading
/// a single content page. A caller invokes `read_local_wiki_a2ui_page_v2` for
/// its selected entry only.
pub fn read_local_wiki_a2ui_projection_v2(
    output_root: &Path,
) -> Result<LocalWikiA2uiProjectionV2, LocalWikiA2uiErrorV2> {
    let root = verified_root(output_root)?;
    let manifest_bytes = read_plain_file(&root, Path::new("manifest.json"), 1024 * 1024)?;
    let manifest: ProjectionManifestV2 = serde_json::from_slice(&manifest_bytes)?;
    if manifest.schema_version != MANIFEST_SCHEMA
        || manifest.index_relative_path != "index.json"
        || manifest.a2ui_stream_relative_path != "a2ui/stream.jsonl"
    {
        return Err(LocalWikiA2uiErrorV2::InvalidArtifact(
            "invalid projection manifest".to_owned(),
        ));
    }
    let index_bytes = read_plain_file(
        &root,
        Path::new(&manifest.index_relative_path),
        16 * 1024 * 1024,
    )?;
    if sha(&index_bytes) != manifest.index_sha256 {
        return Err(LocalWikiA2uiErrorV2::InvalidArtifact(
            "index digest does not match manifest".to_owned(),
        ));
    }
    let stream = read_plain_file(
        &root,
        Path::new(&manifest.a2ui_stream_relative_path),
        4 * 1024 * 1024,
    )?;
    if sha(&stream) != manifest.a2ui_stream_sha256 {
        return Err(LocalWikiA2uiErrorV2::InvalidArtifact(
            "A2UI stream digest does not match manifest".to_owned(),
        ));
    }
    let index: WikiIndexV2 = serde_json::from_slice(&index_bytes)?;
    if index.schema_version != INDEX_SCHEMA
        || index.projection.projection_sha256 != manifest.projection_sha256
    {
        return Err(LocalWikiA2uiErrorV2::InvalidArtifact(
            "index projection identity does not match manifest".to_owned(),
        ));
    }
    validate_projection(&index.projection)?;
    Ok(index.projection)
}

/// Read exactly one selected page after index readback. This is the only page
/// reader in the T14B surface, making all-document eager loading impossible by
/// construction.
pub fn read_local_wiki_a2ui_page_v2(
    output_root: &Path,
    projection: &LocalWikiA2uiProjectionV2,
    entry_id: &str,
) -> Result<Value, LocalWikiA2uiErrorV2> {
    let root = verified_root(output_root)?;
    let entry = projection
        .entries
        .iter()
        .find(|entry| entry.id == entry_id)
        .ok_or_else(|| {
            LocalWikiA2uiErrorV2::InvalidInput("selected entry is absent from index".to_owned())
        })?;
    let bytes = read_plain_file(&root, Path::new(&entry.page_relative_path), MAX_PAGE_BYTES)?;
    if sha(&bytes) != entry.page_sha256 {
        return Err(LocalWikiA2uiErrorV2::InvalidArtifact(
            "selected page digest does not match index".to_owned(),
        ));
    }
    let page: WikiPageV2 = serde_json::from_slice(&bytes)?;
    if page.schema_version != PAGE_SCHEMA
        || page.id != entry.id
        || page.kind != entry.kind
        || page.title != entry.title
        || page.evidence_ids != entry.evidence_ids
        || page.structural_graph_sha256 != projection.structural_graph_sha256
        || page.knowledge_overlay_sha256 != projection.knowledge_overlay_sha256
        || page.lifecycle_identity_sha256 != projection.lifecycle_identity_sha256
        || page.query_receipt_sha256 != projection.query_receipt_sha256
        || page.evidence_state != LOCAL_WIKI_A2UI_EVIDENCE_STATE_V2
    {
        return Err(LocalWikiA2uiErrorV2::InvalidArtifact(
            "selected page is not bound to the verified index identity".to_owned(),
        ));
    }
    serde_json::to_value(page).map_err(LocalWikiA2uiErrorV2::Json)
}

fn push_entry(
    entries: &mut Vec<LocalWikiA2uiEntryV2>,
    ids: &mut BTreeSet<String>,
    id: &str,
    kind: &str,
    title: &str,
    mut evidence_ids: Vec<String>,
) -> Result<(), LocalWikiA2uiErrorV2> {
    if id.is_empty() || kind.is_empty() || title.is_empty() || !ids.insert(id.to_owned()) {
        return Err(LocalWikiA2uiErrorV2::InvalidInput(
            "projection contains empty or duplicate upstream entry identity".to_owned(),
        ));
    }
    evidence_ids.sort();
    evidence_ids.dedup();
    let filename = hex::encode(Sha256::digest(id.as_bytes()));
    let page = WikiPageV2 {
        schema_version: PAGE_SCHEMA.to_owned(),
        id: id.to_owned(),
        kind: kind.to_owned(),
        title: title.to_owned(),
        body: title.to_owned(),
        evidence_ids: evidence_ids.clone(),
        structural_graph_sha256: String::new(),
        knowledge_overlay_sha256: String::new(),
        lifecycle_identity_sha256: String::new(),
        query_receipt_sha256: String::new(),
        evidence_state: LOCAL_WIKI_A2UI_EVIDENCE_STATE_V2.to_owned(),
    };
    // The per-page digest is populated by `bind_page_digests`, after all
    // projection identities are fixed. This placeholder only reserves a safe
    // filename and avoids treating an upstream id as a filesystem path.
    let _ = page;
    entries.push(LocalWikiA2uiEntryV2 {
        id: id.to_owned(),
        kind: kind.to_owned(),
        title: title.to_owned(),
        evidence_ids,
        page_relative_path: format!("pages/{filename}.json"),
        page_sha256: String::new(),
    });
    Ok(())
}

fn projection_digest(
    projection: &LocalWikiA2uiProjectionV2,
) -> Result<String, LocalWikiA2uiErrorV2> {
    let mut canonical = projection.clone();
    canonical.projection_sha256.clear();
    canonical_json_sha256(&canonical)
        .map_err(|error| LocalWikiA2uiErrorV2::InvalidInput(format!("projection digest: {error}")))
}

fn bind_page_digests(
    projection: &mut LocalWikiA2uiProjectionV2,
) -> Result<(), LocalWikiA2uiErrorV2> {
    for entry in &mut projection.entries {
        let page = WikiPageV2 {
            schema_version: PAGE_SCHEMA.to_owned(),
            id: entry.id.clone(),
            kind: entry.kind.clone(),
            title: entry.title.clone(),
            body: entry.title.clone(),
            evidence_ids: entry.evidence_ids.clone(),
            structural_graph_sha256: projection.structural_graph_sha256.clone(),
            knowledge_overlay_sha256: projection.knowledge_overlay_sha256.clone(),
            lifecycle_identity_sha256: projection.lifecycle_identity_sha256.clone(),
            query_receipt_sha256: projection.query_receipt_sha256.clone(),
            evidence_state: projection.evidence_state.clone(),
        };
        entry.page_sha256 = sha(&serde_json::to_vec(&page)?);
    }
    Ok(())
}

fn validate_projection(projection: &LocalWikiA2uiProjectionV2) -> Result<(), LocalWikiA2uiErrorV2> {
    if projection.schema_version != LOCAL_WIKI_A2UI_SCHEMA_V2
        || projection.evidence_state != LOCAL_WIKI_A2UI_EVIDENCE_STATE_V2
        || projection.entries.is_empty()
        || projection.entries.len() > MAX_INDEX_ENTRIES
    {
        return Err(LocalWikiA2uiErrorV2::InvalidArtifact(
            "projection schema, evidence ceiling, or entry denominator is invalid".to_owned(),
        ));
    }
    for digest in [
        &projection.source_snapshot_exact_set_sha256,
        &projection.structural_graph_sha256,
        &projection.knowledge_overlay_sha256,
        &projection.lifecycle_identity_sha256,
        &projection.query_receipt_sha256,
        &projection.projection_sha256,
    ] {
        validate_sha256(digest)
            .map_err(|error| LocalWikiA2uiErrorV2::InvalidArtifact(error.to_string()))?;
    }
    let mut ids = BTreeSet::new();
    for entry in &projection.entries {
        if entry.id.is_empty()
            || entry.kind.is_empty()
            || entry.title.is_empty()
            || entry.page_sha256.is_empty()
            || !ids.insert(entry.id.clone())
        {
            return Err(LocalWikiA2uiErrorV2::InvalidArtifact(
                "projection entry is malformed or duplicate".to_owned(),
            ));
        }
        validate_sha256(&entry.page_sha256)
            .map_err(|error| LocalWikiA2uiErrorV2::InvalidArtifact(error.to_string()))?;
        valid_relative_path(&entry.page_relative_path)?;
    }
    let expected = projection_digest(projection)?;
    if expected != projection.projection_sha256 {
        return Err(LocalWikiA2uiErrorV2::InvalidArtifact(
            "projection digest does not self-bind".to_owned(),
        ));
    }
    Ok(())
}

fn render_a2ui_stream(
    projection: &LocalWikiA2uiProjectionV2,
) -> Result<Vec<u8>, LocalWikiA2uiErrorV2> {
    let selected = projection.entries.first().ok_or_else(|| {
        LocalWikiA2uiErrorV2::InvalidArtifact("projection has no selected entry".to_owned())
    })?;
    let lines = [
        json!({
            "version": "v0.9",
            "createSurface": {"surfaceId": "gtkg-v2-local", "catalogId": "https://a2ui.org/specification/v0_9/catalogs/basic/catalog.json"}
        }),
        json!({
            "version": "v0.9",
            "updateComponents": {"surfaceId": "gtkg-v2-local", "components": [
                {"id":"root","component":"Row","children":["index","content"],"align":"stretch"},
                {"id":"index","component":"Column","children":["index-title","index-list"]},
                {"id":"index-title","component":"Text","text":"Knowledge Index","variant":"h3"},
                {"id":"index-list","component":"List","children":{"componentId":"index-entry","path":"/index"},"direction":"vertical"},
                {"id":"index-entry","component":"Text","text":{"path":"title"}},
                {"id":"content","component":"Column","children":["content-title","content-state"]},
                {"id":"content-title","component":"Text","text":{"path":"/selected/title"},"variant":"h2"},
                {"id":"content-state","component":"Text","text":{"path":"/selected/evidence_state"},"variant":"caption"}
            ]}
        }),
        json!({
            "version": "v0.9",
            "updateDataModel": {"surfaceId": "gtkg-v2-local", "path":"/", "value": {
                "index": projection.entries.iter().map(|entry| json!({"id":entry.id,"title":entry.title,"kind":entry.kind,"page":entry.page_relative_path})).collect::<Vec<_>>(),
                "selected": {"id":selected.id,"title":selected.title,"evidence_state":projection.evidence_state},
                "provenance": {"projection_sha256":projection.projection_sha256,"structural_graph_sha256":projection.structural_graph_sha256,"knowledge_overlay_sha256":projection.knowledge_overlay_sha256,"lifecycle_identity_sha256":projection.lifecycle_identity_sha256,"query_receipt_sha256":projection.query_receipt_sha256}
            }}
        }),
    ];
    let mut bytes = Vec::new();
    for line in lines {
        bytes.extend(serde_json::to_vec(&line)?);
        bytes.push(b'\n');
    }
    Ok(bytes)
}

fn verified_root(output_root: &Path) -> Result<PathBuf, LocalWikiA2uiErrorV2> {
    let metadata =
        fs::symlink_metadata(output_root).map_err(|source| LocalWikiA2uiErrorV2::Io {
            path: output_root.to_path_buf(),
            source,
        })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(LocalWikiA2uiErrorV2::InvalidArtifact(
            "projection root must be a non-symlink directory".to_owned(),
        ));
    }
    fs::canonicalize(output_root).map_err(|source| LocalWikiA2uiErrorV2::Io {
        path: output_root.to_path_buf(),
        source,
    })
}

fn read_plain_file(
    root: &Path,
    relative: &Path,
    max_bytes: usize,
) -> Result<Vec<u8>, LocalWikiA2uiErrorV2> {
    valid_relative_path(&relative.to_string_lossy())?;
    let mut path = root.to_path_buf();
    for component in relative.components() {
        let Component::Normal(name) = component else {
            return Err(LocalWikiA2uiErrorV2::InvalidArtifact(
                "projection file path has a non-normal component".to_owned(),
            ));
        };
        path.push(name);
        let metadata = fs::symlink_metadata(&path).map_err(|source| LocalWikiA2uiErrorV2::Io {
            path: path.clone(),
            source,
        })?;
        if metadata.file_type().is_symlink() {
            return Err(LocalWikiA2uiErrorV2::InvalidArtifact(
                "projection file path contains a symlink".to_owned(),
            ));
        }
    }
    let metadata = fs::metadata(&path).map_err(|source| LocalWikiA2uiErrorV2::Io {
        path: path.clone(),
        source,
    })?;
    if !metadata.is_file() || metadata.len() > max_bytes as u64 {
        return Err(LocalWikiA2uiErrorV2::InvalidArtifact(
            "projection file is unsafe or exceeds its bounded reader budget".to_owned(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() > 1 {
            return Err(LocalWikiA2uiErrorV2::InvalidArtifact(
                "projection file is hardlinked".to_owned(),
            ));
        }
    }
    fs::read(&path).map_err(|source| LocalWikiA2uiErrorV2::Io { path, source })
}

fn valid_relative_path(value: &str) -> Result<(), LocalWikiA2uiErrorV2> {
    let path = Path::new(value);
    if value.is_empty()
        || path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(LocalWikiA2uiErrorV2::InvalidArtifact(
            "projection path escapes its root".to_owned(),
        ));
    }
    Ok(())
}

fn write_file(path: PathBuf, bytes: Vec<u8>) -> Result<(), LocalWikiA2uiErrorV2> {
    fs::write(&path, bytes).map_err(|source| LocalWikiA2uiErrorV2::Io { path, source })
}

fn sha(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

const WIKI_HTML: &str = r#"<!doctype html><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'self'; connect-src 'self'; style-src 'self'"><title>GTKG local Wiki</title><main><nav aria-label="Knowledge index"><ul id="index"></ul></nav><article><h1 id="title"></h1><pre id="body"></pre><p id="evidence"></p></article></main><script src="app.js"></script>"#;

const WIKI_JS: &str = r#"const index=document.querySelector('#index');const title=document.querySelector('#title');const body=document.querySelector('#body');const evidence=document.querySelector('#evidence');async function select(entry){const page=await fetch(entry.page).then(response=>response.json());title.textContent=page.title;body.textContent=page.body;evidence.textContent=page.evidence_state+' '+page.evidence_ids.join(',');}fetch('index.json').then(response=>response.json()).then(({projection})=>{for(const entry of projection.entries){const item=document.createElement('li');const button=document.createElement('button');button.type='button';button.textContent=entry.title;button.addEventListener('click',()=>select({page:entry.page_relative_path}));item.append(button);index.append(item);}select({page:projection.entries[0].page_relative_path});});"#;
