//! Rebuildable reviewed-claim projection. Source chunks remain immutable originals.
use super::query_meter::{PostingRowsMode, QueryMeter};
use super::{
    analysis, artifact, authoring,
    index::{self, ArtifactRef, IndexManifest},
    knowledge::{self, AuthorMode, ClaimBody, EpistemicStatus, Judgment, KnowledgeGoal},
    source_context::{ReviewedSummaryContext, SourceCitationAnchor},
};
use crate::CallContext;
use gtkg_protocol::FileReceiptRef;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

pub const PROJECTION_POLICY: &str = "gtkg.qk.reviewed-context/v1";
pub const QUERY_POLICY: &str = "gtkg.qk.query-reviewed-context/v1";
const OVERLAY_SCHEMA: &str = "gtkg.qk.query-index-overlay/v1";
const CATALOG_SCHEMA: &str = "gtkg.qk.semantic-catalog/v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticPrepareRequest {
    pub schema: String,
    pub verified_ref: FileReceiptRef,
    pub base_index_ref: FileReceiptRef,
    pub accepted_refs: Vec<FileReceiptRef>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueryIndexOverlay {
    pub schema: String,
    pub profile: String,
    pub query_policy: String,
    pub projection_policy: String,
    pub verified_ref: ArtifactRef,
    pub base_index_ref: ArtifactRef,
    pub catalog_ref: ArtifactRef,
    pub source_ref: FileReceiptRef,
    pub snapshot_id: String,
    pub source_commit: String,
    pub source_tree: String,
    pub analysis_context_digest: String,
    pub total_index_bytes: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimDisposition {
    pub accepted_ref: FileReceiptRef,
    pub claim_id: String,
    pub claim_digest: String,
    pub reason: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticCatalogManifest {
    pub schema: String,
    pub identity: String,
    pub catalog_root: String,
    pub projection_policy: String,
    pub tokenizer: String,
    pub verified_ref: ArtifactRef,
    pub base_index_ref: ArtifactRef,
    pub source_ref: FileReceiptRef,
    pub snapshot_id: String,
    pub source_commit: String,
    pub source_tree: String,
    pub analysis_context_digest: String,
    pub accepted_refs: Vec<ArtifactRef>,
    pub accepted_set_digest: String,
    pub total_contexts: u64,
    pub total_context_tokens: u64,
    pub total_mappings: u64,
    pub total_index_bytes: u64,
    pub unmapped_claims: Vec<ClaimDisposition>,
    pub excluded_claims: Vec<ClaimDisposition>,
    pub router: BTreeMap<String, Option<ArtifactRef>>,
    pub context_router: BTreeMap<String, Option<ArtifactRef>>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimLineage {
    pub accepted_ref: ArtifactRef,
    pub job_ref: ArtifactRef,
    pub proposal_ref: ArtifactRef,
    pub review_ref: ArtifactRef,
    pub okf_ref: ArtifactRef,
    pub verified_ref: ArtifactRef,
    pub claim_id: String,
    pub claim_digest: String,
    pub job_digest: String,
    pub proposal_digest: String,
    pub verification_digest: String,
    pub reviewer_ids: Vec<String>,
    pub author_mode: AuthorMode,
    pub execution_assurance: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextChunkMapping {
    pub citation_index: u32,
    pub chunk_id: String,
    pub chunk_ref: ArtifactRef,
    pub overlap_byte_start: usize,
    pub overlap_byte_end: usize,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewedContextRecord {
    pub schema: String,
    pub id: String,
    pub catalog_identity: String,
    pub body: ClaimBody,
    pub text: String,
    pub text_tokens: u32,
    pub citations: Vec<SourceCitationAnchor>,
    pub mappings: Vec<ContextChunkMapping>,
    pub lineage: ClaimLineage,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticPosting {
    pub chunk_id: String,
    pub chunk_ref: ArtifactRef,
    pub context_id: String,
    pub context_ref: ArtifactRef,
    pub term_frequency: u32,
    pub context_tokens: u32,
}

#[derive(Clone)]
pub struct ReplayedProjection {
    overlay: QueryIndexOverlay,
    overlay_ref: FileReceiptRef,
    files: BTreeMap<String, Vec<u8>>,
}
#[derive(Debug, Clone)]
pub struct LoadedOverlay {
    pub overlay_ref: FileReceiptRef,
    pub overlay: QueryIndexOverlay,
    pub base: IndexManifest,
    pub catalog: SemanticCatalogManifest,
}

fn checked_ref(r: &ArtifactRef) -> Result<(), String> {
    file_ref(r).validate().map_err(|e| e.to_string())?;
    if r.bytes == 0 {
        return Err("empty semantic artifact reference".into());
    }
    Ok(())
}
fn validate_overlay(
    overlay_ref: &FileReceiptRef,
    o: &QueryIndexOverlay,
    b: &IndexManifest,
    c: &SemanticCatalogManifest,
) -> Result<(), String> {
    index::validate_manifest(b)?;
    if o.schema != OVERLAY_SCHEMA
        || o.profile != gtkg_protocol::v04::PROFILE_ID
        || o.query_policy != QUERY_POLICY
        || o.projection_policy != PROJECTION_POLICY
        || c.schema != CATALOG_SCHEMA
        || c.projection_policy != PROJECTION_POLICY
        || c.tokenizer != index::TOKENIZER
    {
        return Err("unsupported semantic overlay/catalog policy".into());
    }
    for r in [&o.verified_ref, &o.base_index_ref, &o.catalog_ref] {
        checked_ref(r)?;
    }
    for r in &c.accepted_refs {
        checked_ref(r)?;
    }
    let expected_identity = hash_json(&(
        PROJECTION_POLICY,
        index::TOKENIZER,
        &c.verified_ref,
        &c.base_index_ref,
        &c.accepted_refs,
    ))?;
    if c.identity != expected_identity
        || c.catalog_root != format!(".gtkg/qk/semantic/{}", &expected_identity[7..])
        || overlay_ref.path != format!("{}/overlay.json", c.catalog_root)
        || o.catalog_ref.path != format!("{}/manifest.json", c.catalog_root)
        || o.base_index_ref.path != format!("{}/manifest.json", b.index_root)
        || c.accepted_set_digest != hash_json(&c.accepted_refs)?
    {
        return Err("semantic identity/path/accepted set mismatch".into());
    }
    if c.accepted_refs.windows(2).any(|w| w[0].path >= w[1].path) {
        return Err("semantic accepted set is not canonical".into());
    }
    if o.verified_ref != c.verified_ref
        || o.base_index_ref != c.base_index_ref
        || o.source_ref != c.source_ref
        || c.source_ref != b.source_ref
        || o.snapshot_id != c.snapshot_id
        || c.snapshot_id != b.snapshot_id
        || o.source_commit != c.source_commit
        || c.source_commit != b.source_commit
        || o.source_tree != c.source_tree
        || c.source_tree != b.source_tree
        || o.analysis_context_digest != c.analysis_context_digest
        || c.analysis_context_digest != b.analysis_context_digest
    {
        return Err("semantic overlay crosses source/index/verified/context identities".into());
    }
    let expected_bytes = b
        .total_index_bytes
        .checked_add(c.total_index_bytes)
        .and_then(|n| n.checked_add(raw_json(o).ok()?.len() as u64))
        .ok_or("semantic index size overflow")?;
    if expected_bytes != o.total_index_bytes {
        return Err("semantic overlay byte denominator mismatch".into());
    }
    for (router, kind) in [
        (&c.router, "postings"),
        (&c.context_router, "context-router"),
    ] {
        if router.len() != 256 {
            return Err("complete semantic 256-bucket router required".into());
        }
        for bucket in routes().keys() {
            if let Some(r) = router.get(bucket).ok_or("semantic route missing")? {
                checked_ref(r)?;
                if r.path != format!("{}/{kind}/{bucket}.json", c.catalog_root) {
                    return Err("semantic router path mismatch".into());
                }
            }
        }
    }
    Ok(())
}

/// Bounded actual reads, including authority/admission failures, remain in meter.
/// The caller applies the authenticated overlay's frozen denominator after its
/// bounded bootstrap read, before optional postings or context reads.
pub fn load_overlay_with_io(
    context: &CallContext,
    workspace: &Path,
    overlay_ref: &FileReceiptRef,
    meter: &mut QueryMeter,
) -> Result<LoadedOverlay, String> {
    let root = artifact::workspace(context, workspace)?;
    let overlay: QueryIndexOverlay =
        meter.read_reference(context, &root, overlay_ref, 64 * 1024 * 1024)?;
    let base: IndexManifest = meter.read_artifact(context, &root, &overlay.base_index_ref)?;
    let catalog: SemanticCatalogManifest =
        meter.read_artifact(context, &root, &overlay.catalog_ref)?;
    validate_overlay(overlay_ref, &overlay, &base, &catalog)?;
    verify_admission(context, &root, overlay_ref, &overlay, meter)?;
    Ok(LoadedOverlay {
        overlay_ref: overlay_ref.clone(),
        overlay,
        base,
        catalog,
    })
}

pub fn load_selected_postings(
    context: &CallContext,
    workspace: &Path,
    loaded: &LoadedOverlay,
    term: &str,
    meter: &mut QueryMeter,
) -> Result<Vec<SemanticPosting>, String> {
    let c = &loaded.catalog;
    let bucket = index::token_bucket(term);
    let Some(reference) = c
        .router
        .get(&bucket)
        .ok_or("semantic posting route absent")?
    else {
        return Ok(vec![]);
    };
    let router: PostingRouter = meter.read_artifact(context, workspace, reference)?;
    if router.schema != "gtkg.qk.semantic-posting-router/v1"
        || router.catalog_identity != c.identity
        || router.bucket != bucket
    {
        return Err("semantic posting router identity mismatch".into());
    }
    for (token, r) in &router.terms {
        checked_ref(r)?;
        if index::token_bucket(token) != bucket
            || r.path
                != format!(
                    "{}/postings/{bucket}/{}.json",
                    c.catalog_root,
                    &artifact::digest(token.as_bytes())[7..]
                )
        {
            return Err("semantic term route mismatch".into());
        }
    }
    let Some(reference) = router.terms.get(term) else {
        return Ok(vec![]);
    };
    checked_ref(reference)?;
    let root = artifact::workspace(context, workspace)?;
    let bytes = meter.read(context, &root.join(&reference.path), reference.bytes)?;
    if bytes.len() as u64 != reference.bytes || artifact::digest(&bytes) != reference.sha256 {
        return Err("semantic posting leaf bytes/digest mismatch".into());
    }
    let decoded = meter.decode_posting_rows::<SemanticPosting>(
        &bytes,
        PostingRowsMode::Rows,
        &["schema", "catalog_identity", "term"],
    )?;
    let header: PostingLeafHeader =
        serde_json::from_value(serde_json::Value::Object(decoded.header))
            .map_err(|e| e.to_string())?;
    let leaf = PostingLeaf {
        schema: header.schema,
        catalog_identity: header.catalog_identity,
        term: header.term,
        rows: decoded.rows.ok_or("semantic posting rows absent")?,
    };
    if leaf.schema != "gtkg.qk.semantic-posting-leaf/v1"
        || leaf.catalog_identity != c.identity
        || leaf.term != term
    {
        return Err("semantic posting leaf identity mismatch".into());
    }
    let mut keys = BTreeSet::new();
    for row in &leaf.rows {
        checked_ref(&row.context_ref)?;
        checked_ref(&row.chunk_ref)?;
        if !hex_id(&row.context_id)
            || !hex_id(&row.chunk_id)
            || row.context_ref.path
                != format!("{}/contexts/{}.json", c.catalog_root, row.context_id)
            || row.chunk_ref.path
                != format!("{}/chunks/{}.json", loaded.base.index_root, row.chunk_id)
            || row.term_frequency == 0
            || row.context_tokens == 0
            || !keys.insert((&row.chunk_id, &row.context_id))
        {
            return Err("invalid or duplicate semantic posting row".into());
        }
    }
    if leaf
        .rows
        .windows(2)
        .any(|w| (&w[0].chunk_id, &w[0].context_id) >= (&w[1].chunk_id, &w[1].context_id))
    {
        return Err("semantic postings not canonically ordered".into());
    }
    Ok(leaf.rows)
}

pub fn load_selected_context(
    context: &CallContext,
    workspace: &Path,
    loaded: &LoadedOverlay,
    reference: &ArtifactRef,
    meter: &mut QueryMeter,
) -> Result<ReviewedContextRecord, String> {
    checked_ref(reference)?;
    let c = &loaded.catalog;
    let id = reference
        .path
        .strip_prefix(&format!("{}/contexts/", c.catalog_root))
        .and_then(|p| p.strip_suffix(".json"))
        .filter(|id| hex_id(id))
        .ok_or("context reference outside selected catalog")?;
    let r = c
        .context_router
        .get(&id[..2])
        .ok_or("context router bucket missing")?
        .as_ref()
        .ok_or("context router shard absent")?;
    let router: ContextRouter = meter.read_artifact(context, workspace, r)?;
    if router.schema != "gtkg.qk.semantic-context-router/v1"
        || router.catalog_identity != c.identity
        || router.bucket != id[..2]
        || router.contexts.get(id) != Some(reference)
    {
        return Err("context not bound by catalog router".into());
    }
    for (key, r) in &router.contexts {
        checked_ref(r)?;
        if !hex_id(key)
            || !key.starts_with(&router.bucket)
            || r.path != format!("{}/contexts/{key}.json", c.catalog_root)
        {
            return Err("context router entry invalid".into());
        }
    }
    let record: ReviewedContextRecord = meter.read_artifact(context, workspace, reference)?;
    if record.schema != "gtkg.qk.reviewed-context/v1"
        || record.id != id
        || record.catalog_identity != c.identity
        || record.text != rendered(&record.body).0
        || record.text_tokens as usize != context_units(&record.body)
        || record.citations.is_empty()
        || !c.accepted_refs.contains(&record.lineage.accepted_ref)
        || record.lineage.verified_ref != loaded.overlay.verified_ref
        || record.id
            != hash_json(&(
                &c.identity,
                &record.lineage.accepted_ref,
                &record.lineage.claim_digest,
            ))?[7..]
    {
        return Err("context body/source/lineage identity mismatch".into());
    }
    if matches!(
        record.body,
        ClaimBody::Interpretive {
            epistemic: EpistemicStatus::Unknown,
            ..
        }
    ) {
        return Err("unknown context cannot be promoted".into());
    }
    for m in &record.mappings {
        let citation = record
            .citations
            .get(m.citation_index as usize)
            .ok_or("context mapping citation absent")?;
        checked_ref(&m.chunk_ref)?;
        if !hex_id(&m.chunk_id)
            || m.chunk_ref.path != format!("{}/chunks/{}.json", loaded.base.index_root, m.chunk_id)
            || m.overlap_byte_start >= m.overlap_byte_end
            || m.overlap_byte_start < citation.span.byte_start
            || m.overlap_byte_end > citation.span.byte_end
        {
            return Err("context mapping does not overlap its citation".into());
        }
    }
    Ok(record)
}

pub fn verify_selected_lineage(
    context: &CallContext,
    workspace: &Path,
    loaded: &LoadedOverlay,
    record: &ReviewedContextRecord,
    reference: &ArtifactRef,
    meter: &mut QueryMeter,
) -> Result<ReviewedSummaryContext, String> {
    // Rebind even a caller-supplied in-memory record to its selected ordinary file.
    if load_selected_context(context, workspace, loaded, reference, meter)? != *record {
        return Err("selected context argument changed".into());
    }
    let l = &record.lineage;
    let a: authoring::AcceptedArtifact =
        meter.read_artifact(context, workspace, &l.accepted_ref)?;
    let j: authoring::JobArtifact = meter.read_artifact(context, workspace, &l.job_ref)?;
    let p: authoring::ProposalArtifact =
        meter.read_artifact(context, workspace, &l.proposal_ref)?;
    let r: authoring::ReviewArtifact = meter.read_artifact(context, workspace, &l.review_ref)?;
    if a.job_ref != file_ref(&l.job_ref)
        || a.review_ref != file_ref(&l.review_ref)
        || a.okf_ref != file_ref(&l.okf_ref)
        || p.job_ref != file_ref(&l.job_ref)
        || r.proposal_ref != file_ref(&l.proposal_ref)
        || j.verified_ref != file_ref(&loaded.overlay.verified_ref)
        || l.verified_ref != loaded.overlay.verified_ref
        || l.job_digest != j.job.job_digest
        || p.proposal.job_digest != l.job_digest
        || r.verification.job_digest != l.job_digest
        || a.accepted.job_digest != l.job_digest
        || l.proposal_digest != p.proposal.proposal_digest
        || r.verification.proposal_digest != l.proposal_digest
        || a.accepted.proposal_digest != l.proposal_digest
        || l.verification_digest != r.verification.verification_digest
        || a.accepted.verification_digest != l.verification_digest
        || a.accepted.author_mode != l.author_mode
        || p.proposal.candidate.author_mode != l.author_mode
        || a.accepted.execution_assurance != l.execution_assurance
        || l.author_mode == AuthorMode::StaticTranscription
        || j.job.input.goal != KnowledgeGoal::SemanticUnderstanding
    {
        return Err("selected accepted/job/proposal/review/source chain mismatch".into());
    }
    let claim = a
        .accepted
        .supported_claims
        .iter()
        .find(|claim| claim.claim_id == l.claim_id)
        .ok_or("selected claim was not accepted")?;
    if !p.proposal.candidate.claims.contains(claim)
        || !r.verification.supported_claim_ids.contains(&l.claim_id)
        || knowledge::claim_digest(claim).map_err(|e| e.to_string())? != l.claim_digest
        || claim.body != record.body
        || claim
            .citations
            .iter()
            .map(|c| SourceCitationAnchor {
                path: c.path.clone(),
                file_sha256: c.file_sha256.clone(),
                span: c.span.clone(),
            })
            .collect::<Vec<_>>()
            != record.citations
    {
        return Err("selected claim text or citations differ from accepted reviewed body".into());
    }
    if matches!(claim.body, ClaimBody::Interpretive { .. }) {
        let mut ids = vec![];
        for review in &r.verification.reviews {
            if review.proposal_digest != l.proposal_digest
                || review.reviewer_id == p.proposal.candidate.author_id
                || !review.decisions.iter().any(|d| {
                    d.claim_id == l.claim_id
                        && d.claim_digest == l.claim_digest
                        && d.judgment == Judgment::Supported
                })
            {
                return Err("interpretive selected review decision invalid".into());
            }
            ids.push(review.reviewer_id.clone());
        }
        ids.sort();
        if ids.len() != 2 || ids[0] == ids[1] || ids != l.reviewer_ids {
            return Err("interpretive selected reviewer identities mismatch".into());
        }
    } else if !l.reviewer_ids.is_empty() {
        return Err("structural replay must not present invented semantic reviews".into());
    }
    checked_ref(&l.okf_ref)?;
    let root = artifact::workspace(context, workspace)?;
    let okf = meter.read(context, &root.join(&l.okf_ref.path), l.okf_ref.bytes)?;
    if okf.len() as u64 != l.okf_ref.bytes
        || artifact::digest(&okf) != l.okf_ref.sha256
        || okf != authoring::render_okf(&j.job, &a.accepted).as_bytes()
    {
        return Err("selected canonical OKF differs from accepted chain".into());
    }
    let (text, version_condition, epistemic, review_kind) = rendered(&record.body);
    Ok(ReviewedSummaryContext {
        context_id: record.id.clone(),
        context_ref: reference.clone(),
        text,
        claim_id: l.claim_id.clone(),
        claim_digest: l.claim_digest.clone(),
        author_mode: l.author_mode.clone(),
        epistemic,
        version_condition,
        review_kind,
        accepted_ref: file_ref(&l.accepted_ref),
        review_ref: file_ref(&l.review_ref),
        job_ref: file_ref(&l.job_ref),
        verification_digest: l.verification_digest.clone(),
        reviewer_ids: l.reviewer_ids.clone(),
        citations: record.citations.clone(),
        selected_lineage: vec![
            l.accepted_ref.clone(),
            l.job_ref.clone(),
            l.proposal_ref.clone(),
            l.review_ref.clone(),
            l.okf_ref.clone(),
        ],
        evidence_ids: vec![],
        citation_coverage_in_pack: "partial".into(),
        execution_assurance: l.execution_assurance.clone(),
    })
}

fn verify_admission(
    context: &CallContext,
    workspace: &Path,
    overlay_ref: &FileReceiptRef,
    overlay: &QueryIndexOverlay,
    meter: &mut QueryMeter,
) -> Result<(), String> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Authority {
        schema: String,
        workspace: String,
        key: String,
    }
    let authority_path = workspace.join(".gtkg/qk/runtime/query-authority.json");
    let bytes = meter.read(context, &authority_path, 16 * 1024)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let meta = std::fs::symlink_metadata(&authority_path).map_err(|e| e.to_string())?;
        if meta.nlink() != 1 || meta.permissions().mode() & 0o077 != 0 {
            return Err("semantic query authority must be private single-link file".into());
        }
    }
    let a: Authority = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    if a.schema != "gtkg.qk.query-authority/v1" || a.workspace != workspace.to_string_lossy() {
        return Err("semantic authority belongs to different workspace".into());
    }
    let key: [u8; 32] = hex::decode(&a.key)
        .map_err(|_| "invalid authority key")?
        .try_into()
        .map_err(|_| "invalid authority key length")?;
    let bytes = meter.read(
        context,
        &workspace.join(admission_path(overlay_ref)?),
        16 * 1024,
    )?;
    let admitted: Admission = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    if admitted.schema != "gtkg.qk.semantic-admission/v1" || admitted.overlay_ref != *overlay_ref {
        return Err("overlay has not been admitted by full replay".into());
    }
    use hmac::{Hmac, Mac};
    let mut mac =
        Hmac::<sha2::Sha256>::new_from_slice(&key).map_err(|_| "invalid semantic MAC key")?;
    mac.update(ADMISSION_DOMAIN);
    mac.update(&admission_body(overlay_ref, overlay)?);
    mac.verify_slice(&hex::decode(admitted.signature).map_err(|_| "invalid admission MAC")?)
        .map_err(|_| "semantic overlay admission authentication failed".to_string())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PostingRouter {
    schema: String,
    catalog_identity: String,
    bucket: String,
    terms: BTreeMap<String, ArtifactRef>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PostingLeaf {
    schema: String,
    catalog_identity: String,
    term: String,
    rows: Vec<SemanticPosting>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PostingLeafHeader {
    schema: String,
    catalog_identity: String,
    term: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ContextRouter {
    schema: String,
    catalog_identity: String,
    bucket: String,
    contexts: BTreeMap<String, ArtifactRef>,
}
fn file_ref(r: &ArtifactRef) -> FileReceiptRef {
    FileReceiptRef {
        path: r.path.clone(),
        sha256: r.sha256.clone(),
    }
}
fn raw_json<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    serde_json::to_vec_pretty(value).map_err(|e| e.to_string())
}
fn hash_json<T: Serialize>(value: &T) -> Result<String, String> {
    Ok(artifact::digest(
        &serde_json::to_vec(value).map_err(|e| e.to_string())?,
    ))
}
fn hex_id(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn bound_ref(
    context: &CallContext,
    root: &Path,
    r: &FileReceiptRef,
) -> Result<ArtifactRef, String> {
    r.validate().map_err(|e| e.to_string())?;
    let raw = crate::exact_read::read_bound_regular_file(context, &root.join(&r.path))
        .map_err(|e| e.message)?;
    if raw.sha256 != r.sha256 {
        return Err("semantic lineage reference digest mismatch".into());
    }
    Ok(ArtifactRef {
        path: r.path.clone(),
        bytes: raw.bytes.len() as u64,
        sha256: raw.sha256,
    })
}
fn insert<T: Serialize>(
    files: &mut BTreeMap<String, Vec<u8>>,
    path: String,
    value: &T,
) -> Result<ArtifactRef, String> {
    let raw = raw_json(value)?;
    let r = ArtifactRef {
        path: path.clone(),
        bytes: raw.len() as u64,
        sha256: artifact::digest(&raw),
    };
    file_ref(&r).validate().map_err(|e| e.to_string())?;
    if files.len() >= 100_000
        || files.values().map(|b| b.len() as u64).sum::<u64>() + r.bytes > 512 * 1024 * 1024
    {
        return Err("semantic projection build bound exceeded".into());
    }
    if files.insert(path, raw).is_some() {
        return Err("duplicate semantic projection path".into());
    }
    Ok(r)
}
fn routes() -> BTreeMap<String, Option<ArtifactRef>> {
    (0..256).map(|b| (format!("{b:02x}"), None)).collect()
}
fn sorted_refs(refs: &[FileReceiptRef]) -> Result<Vec<FileReceiptRef>, String> {
    let mut output = refs.to_vec();
    for r in &output {
        r.validate().map_err(|e| e.to_string())?;
    }
    output.sort_by(|a, b| (&a.path, &a.sha256).cmp(&(&b.path, &b.sha256)));
    output.dedup();
    if output.windows(2).any(|w| w[0].path == w[1].path) {
        return Err("conflicting accepted references".into());
    }
    Ok(output)
}
fn rendered(body: &ClaimBody) -> (String, Option<String>, EpistemicStatus, String) {
    match body {
        ClaimBody::Interpretive {
            proposition,
            version_condition,
            epistemic,
        } => (
            proposition.clone(),
            Some(version_condition.clone()),
            epistemic.clone(),
            "independently_reviewed_interpretation".into(),
        ),
        ClaimBody::Structural { .. } => (
            authoring::render_claim_body(body),
            None,
            EpistemicStatus::Direct,
            "structural_replayed".into(),
        ),
    }
}
fn context_units(body: &ClaimBody) -> usize {
    let (text, condition, _, _) = rendered(body);
    text.chars().count() + condition.as_deref().map_or(0, |s| s.chars().count())
}
fn context_terms(body: &ClaimBody) -> Vec<String> {
    let (text, condition, _, _) = rendered(body);
    index::tokenize(&text)
        .into_iter()
        .chain(condition.as_deref().into_iter().flat_map(index::tokenize))
        .collect()
}

pub fn replay_projection(
    context: &CallContext,
    workspace: &Path,
    request: &SemanticPrepareRequest,
) -> Result<ReplayedProjection, String> {
    if request.schema != "gtkg.qk.semantic-prepare/v1" {
        return Err("unsupported semantic prepare schema".into());
    }
    let root = artifact::workspace(context, workspace)?;
    let (v, candidate, _, _, _) = analysis::load_verified(context, &root, &request.verified_ref)?;
    if v.index_ref.as_ref() != Some(&request.base_index_ref) {
        return Err("semantic base index is not verified analysis index".into());
    }
    let base = index::load_manifest(context, &root, &request.base_index_ref)?;
    if base.source_ref != v.source_ref
        || base.snapshot_id != v.snapshot_id
        || base.source_tree != v.source_tree
        || base.source_commit != v.source_commit
        || base.analysis_context_digest != gtkg_extract::v04::context_digest(&v.context)
    {
        return Err("semantic projection has mixed source or analysis context".into());
    }
    let chunks = super::lifecycle::replay_index_chunks(context, &root, &base, &candidate, &v)?;
    let refs = sorted_refs(&request.accepted_refs)?;
    let verified_ref = bound_ref(context, &root, &request.verified_ref)?;
    let base_index_ref = bound_ref(context, &root, &request.base_index_ref)?;
    let accepted_refs: Vec<_> = refs
        .iter()
        .map(|r| bound_ref(context, &root, r))
        .collect::<Result<_, _>>()?;
    let accepted_set_digest = hash_json(&accepted_refs)?;
    let identity = hash_json(&(
        PROJECTION_POLICY,
        index::TOKENIZER,
        &verified_ref,
        &base_index_ref,
        &accepted_refs,
    ))?;
    let catalog_root = format!(".gtkg/qk/semantic/{}", &identity[7..]);
    let mut files = BTreeMap::new();
    let mut records: BTreeMap<String, ArtifactRef> = BTreeMap::new();
    let mut postings: BTreeMap<String, Vec<SemanticPosting>> = BTreeMap::new();
    let mut unmapped_claims = vec![];
    let mut excluded_claims = vec![];
    let mut total_context_tokens = 0u64;
    let mut supported_fact_keys = BTreeSet::new();
    let mut total_mappings = 0u64;
    for accepted_ref in &accepted_refs {
        let (a, j, p, r, _) = authoring::accepted_chain(context, &root, &file_ref(accepted_ref))?;
        if j.verified_ref != request.verified_ref {
            return Err("accepted claim crosses verified source revisions".into());
        }
        let mut lineage = ClaimLineage {
            accepted_ref: accepted_ref.clone(),
            job_ref: bound_ref(context, &root, &a.job_ref)?,
            proposal_ref: bound_ref(context, &root, &r.proposal_ref)?,
            review_ref: bound_ref(context, &root, &a.review_ref)?,
            okf_ref: bound_ref(context, &root, &a.okf_ref)?,
            verified_ref: verified_ref.clone(),
            claim_id: String::new(),
            claim_digest: String::new(),
            job_digest: j.job.job_digest.clone(),
            proposal_digest: p.proposal.proposal_digest.clone(),
            verification_digest: r.verification.verification_digest.clone(),
            reviewer_ids: vec![],
            author_mode: a.accepted.author_mode.clone(),
            execution_assurance: a.accepted.execution_assurance.clone(),
        };
        for claim in &a.accepted.supported_claims {
            let claim_digest = knowledge::claim_digest(claim).map_err(|e| e.to_string())?;
            let exclusion = if a.accepted.author_mode == AuthorMode::StaticTranscription {
                Some("static_transcription_not_semantic_authoring")
            } else if j.job.input.goal != KnowledgeGoal::SemanticUnderstanding {
                Some("archive_goal_not_semantic_understanding")
            } else if matches!(
                claim.body,
                ClaimBody::Interpretive {
                    epistemic: EpistemicStatus::Unknown,
                    ..
                }
            ) {
                Some("unknown_claim_not_factual_context")
            } else {
                None
            };
            if let Some(reason) = exclusion {
                excluded_claims.push(ClaimDisposition {
                    accepted_ref: file_ref(accepted_ref),
                    claim_id: claim.claim_id.clone(),
                    claim_digest,
                    reason: reason.into(),
                });
                continue;
            }
            lineage.claim_id = claim.claim_id.clone();
            lineage.claim_digest = claim_digest.clone();
            lineage.reviewer_ids = if matches!(claim.body, ClaimBody::Interpretive { .. }) {
                let mut ids: Vec<_> = r
                    .verification
                    .reviews
                    .iter()
                    .filter(|review| {
                        review.decisions.iter().any(|d| {
                            d.claim_id == claim.claim_id
                                && d.claim_digest == claim_digest
                                && d.judgment == Judgment::Supported
                        })
                    })
                    .map(|review| review.reviewer_id.clone())
                    .collect();
                ids.sort();
                if ids.len() != 2
                    || ids[0] == ids[1]
                    || ids.contains(&p.proposal.candidate.author_id)
                {
                    return Err(
                        "interpretive context needs actual two independent supported reviews"
                            .into(),
                    );
                }
                ids
            } else {
                vec![]
            };
            let citations: Vec<_> = claim
                .citations
                .iter()
                .map(|c| SourceCitationAnchor {
                    path: c.path.clone(),
                    file_sha256: c.file_sha256.clone(),
                    span: c.span.clone(),
                })
                .collect();
            // Claim IDs, reviewer chains, wording outside the typed body and
            // epistemic presentation cannot inflate the retrieval denominator.
            let mut canonical_body =
                serde_json::to_value(&claim.body).map_err(|e| e.to_string())?;
            if let Some(body) = canonical_body.as_object_mut() {
                body.remove("epistemic");
            }
            let mut canonical_citations: Vec<_> = citations
                .iter()
                .map(|c| {
                    (
                        &c.path,
                        &c.file_sha256,
                        c.span.byte_start,
                        c.span.byte_end,
                        c.span.line_start,
                        c.span.line_end,
                    )
                })
                .collect();
            canonical_citations.sort();
            canonical_citations.dedup();
            if !supported_fact_keys.insert(hash_json(&(&canonical_body, canonical_citations))?) {
                excluded_claims.push(ClaimDisposition {
                    accepted_ref: file_ref(accepted_ref),
                    claim_id: claim.claim_id.clone(),
                    claim_digest: claim_digest.clone(),
                    reason: "duplicate_supported_fact".into(),
                });
                continue;
            }
            let mut mappings = vec![];
            for (n, citation) in citations.iter().enumerate() {
                for (chunk, reference) in &chunks {
                    let begin = citation.span.byte_start.max(chunk.byte_start);
                    let end = citation.span.byte_end.min(chunk.byte_end);
                    if citation.path == chunk.path
                        && citation
                            .file_sha256
                            .strip_prefix("sha256:")
                            .unwrap_or(&citation.file_sha256)
                            == chunk.file_sha
                        && begin < end
                    {
                        mappings.push(ContextChunkMapping {
                            citation_index: n as u32,
                            chunk_id: chunk.id.clone(),
                            chunk_ref: reference.clone(),
                            overlap_byte_start: begin,
                            overlap_byte_end: end,
                        });
                    }
                }
            }
            mappings.sort_by(|a, b| {
                (
                    &a.chunk_id,
                    a.citation_index,
                    a.overlap_byte_start,
                    a.overlap_byte_end,
                )
                    .cmp(&(
                        &b.chunk_id,
                        b.citation_index,
                        b.overlap_byte_start,
                        b.overlap_byte_end,
                    ))
            });
            if mappings.is_empty() {
                unmapped_claims.push(ClaimDisposition {
                    accepted_ref: file_ref(accepted_ref),
                    claim_id: claim.claim_id.clone(),
                    claim_digest: claim_digest.clone(),
                    reason: "no_indexed_citation_overlap".into(),
                });
            }
            let id = hash_json(&(&identity, accepted_ref, &claim_digest))?[7..].to_owned();
            let units = context_units(&claim.body);
            let record = ReviewedContextRecord {
                schema: "gtkg.qk.reviewed-context/v1".into(),
                id: id.clone(),
                catalog_identity: identity.clone(),
                body: claim.body.clone(),
                text: rendered(&claim.body).0,
                text_tokens: u32::try_from(units)
                    .map_err(|_| "context text exceeds count representation")?,
                citations,
                mappings,
                lineage: lineage.clone(),
            };
            let reference = insert(
                &mut files,
                format!("{catalog_root}/contexts/{id}.json"),
                &record,
            )?;
            total_context_tokens += u64::from(record.text_tokens);
            total_mappings += record.mappings.len() as u64;
            let mut frequencies: BTreeMap<String, u32> = BTreeMap::new();
            for term in context_terms(&record.body) {
                *frequencies.entry(term).or_default() += 1;
            }
            // Keep every citation interval for coverage accounting, including
            // delimiters. A delimiter-only overlap cannot be a semantic hit.
            let targets: BTreeMap<_, _> = record
                .mappings
                .iter()
                .filter(|mapping| {
                    chunks
                        .iter()
                        .find(|(chunk, _)| chunk.id == mapping.chunk_id)
                        .is_some_and(|(chunk, _)| {
                            chunk
                                .text
                                .get(
                                    mapping.overlap_byte_start - chunk.byte_start
                                        ..mapping.overlap_byte_end - chunk.byte_start,
                                )
                                .is_some_and(|text| text.chars().any(|ch| !ch.is_whitespace()))
                        })
                })
                .map(|m| (m.chunk_id.clone(), m.chunk_ref.clone()))
                .collect();
            if targets.is_empty() && !record.mappings.is_empty() {
                unmapped_claims.push(ClaimDisposition {
                    accepted_ref: file_ref(accepted_ref),
                    claim_id: claim.claim_id.clone(),
                    claim_digest: claim_digest.clone(),
                    reason: "no_nonwhitespace_citation_overlap".into(),
                });
            }
            for (term, term_frequency) in frequencies {
                for (chunk_id, chunk_ref) in &targets {
                    postings
                        .entry(term.clone())
                        .or_default()
                        .push(SemanticPosting {
                            chunk_id: chunk_id.clone(),
                            chunk_ref: chunk_ref.clone(),
                            context_id: id.clone(),
                            context_ref: reference.clone(),
                            term_frequency,
                            context_tokens: record.text_tokens,
                        });
                }
            }
            records.insert(id, reference);
        }
    }
    let mut router = routes();
    let mut context_router = routes();
    for b in 0..256 {
        let bucket = format!("{b:02x}");
        let mut terms = BTreeMap::new();
        for (term, rows) in postings
            .iter_mut()
            .filter(|(term, _)| index::token_bucket(term) == bucket)
        {
            rows.sort_by(|a, b| (&a.chunk_id, &a.context_id).cmp(&(&b.chunk_id, &b.context_id)));
            let leaf = PostingLeaf {
                schema: "gtkg.qk.semantic-posting-leaf/v1".into(),
                catalog_identity: identity.clone(),
                term: term.clone(),
                rows: rows.clone(),
            };
            let r = insert(
                &mut files,
                format!(
                    "{catalog_root}/postings/{bucket}/{}.json",
                    &artifact::digest(term.as_bytes())[7..]
                ),
                &leaf,
            )?;
            terms.insert(term.clone(), r);
        }
        if !terms.is_empty() {
            let r = insert(
                &mut files,
                format!("{catalog_root}/postings/{bucket}.json"),
                &PostingRouter {
                    schema: "gtkg.qk.semantic-posting-router/v1".into(),
                    catalog_identity: identity.clone(),
                    bucket: bucket.clone(),
                    terms,
                },
            )?;
            router.insert(bucket.clone(), Some(r));
        }
        let contexts: BTreeMap<_, _> = records
            .iter()
            .filter(|(id, _)| id.starts_with(&bucket))
            .map(|(id, r)| (id.clone(), r.clone()))
            .collect();
        if !contexts.is_empty() {
            let r = insert(
                &mut files,
                format!("{catalog_root}/context-router/{bucket}.json"),
                &ContextRouter {
                    schema: "gtkg.qk.semantic-context-router/v1".into(),
                    catalog_identity: identity.clone(),
                    bucket: bucket.clone(),
                    contexts,
                },
            )?;
            context_router.insert(bucket, Some(r));
        }
    }
    let derived_bytes: u64 = files.values().map(|b| b.len() as u64).sum();
    let mut catalog = SemanticCatalogManifest {
        schema: CATALOG_SCHEMA.into(),
        identity,
        catalog_root: catalog_root.clone(),
        projection_policy: PROJECTION_POLICY.into(),
        tokenizer: index::TOKENIZER.into(),
        verified_ref: verified_ref.clone(),
        base_index_ref: base_index_ref.clone(),
        source_ref: base.source_ref.clone(),
        snapshot_id: base.snapshot_id.clone(),
        source_commit: base.source_commit.clone(),
        source_tree: base.source_tree.clone(),
        analysis_context_digest: base.analysis_context_digest.clone(),
        accepted_refs,
        accepted_set_digest,
        total_contexts: records.len() as u64,
        total_context_tokens,
        total_mappings,
        total_index_bytes: derived_bytes,
        unmapped_claims,
        excluded_claims,
        router,
        context_router,
    };
    for _ in 0..16 {
        let next = derived_bytes + raw_json(&catalog)?.len() as u64;
        if next == catalog.total_index_bytes {
            break;
        }
        catalog.total_index_bytes = next;
    }
    let catalog_ref = insert(
        &mut files,
        format!("{catalog_root}/manifest.json"),
        &catalog,
    )?;
    let mut overlay = QueryIndexOverlay {
        schema: OVERLAY_SCHEMA.into(),
        profile: gtkg_protocol::v04::PROFILE_ID.into(),
        query_policy: QUERY_POLICY.into(),
        projection_policy: PROJECTION_POLICY.into(),
        verified_ref,
        base_index_ref,
        catalog_ref,
        source_ref: base.source_ref.clone(),
        snapshot_id: base.snapshot_id.clone(),
        source_commit: base.source_commit.clone(),
        source_tree: base.source_tree.clone(),
        analysis_context_digest: base.analysis_context_digest.clone(),
        total_index_bytes: 0,
    };
    for _ in 0..16 {
        let next = base
            .total_index_bytes
            .checked_add(catalog.total_index_bytes)
            .and_then(|n| n.checked_add(raw_json(&overlay).ok()?.len() as u64))
            .ok_or("overlay size overflow")?;
        if next == overlay.total_index_bytes {
            break;
        }
        overlay.total_index_bytes = next;
    }
    let overlay_ref = file_ref(&insert(
        &mut files,
        format!("{catalog_root}/overlay.json"),
        &overlay,
    )?);
    Ok(ReplayedProjection {
        overlay,
        overlay_ref,
        files,
    })
}

pub fn publish_projection(
    context: &CallContext,
    workspace: &Path,
    replayed: ReplayedProjection,
) -> Result<FileReceiptRef, String> {
    if context.effect_policy != crate::EffectPolicy::WorkspaceWrite {
        return Err("semantic publication requires WorkspaceWrite".into());
    }
    let root = artifact::workspace(context, workspace)?;
    for (path, raw) in &replayed.files {
        super::source::write_workspace_object(&root, path, raw).map_err(|e| e.to_string())?;
    }
    write_admission(context, &root, &replayed)?;
    Ok(replayed.overlay_ref)
}

/// Recompute all records, routes, mappings and text terms. No runtime admission
/// is required or created while independently verifying a portable projection.
pub fn verify_projection(
    context: &CallContext,
    workspace: &Path,
    overlay_ref: &FileReceiptRef,
) -> Result<ReplayedProjection, String> {
    let root = artifact::workspace(context, workspace)?;
    let (overlay, _): (QueryIndexOverlay, _) = artifact::read(context, &root, overlay_ref)?;
    let (catalog, _): (SemanticCatalogManifest, _) =
        artifact::read(context, &root, &file_ref(&overlay.catalog_ref))?;
    let replayed = replay_projection(
        context,
        &root,
        &SemanticPrepareRequest {
            schema: "gtkg.qk.semantic-prepare/v1".into(),
            verified_ref: file_ref(&overlay.verified_ref),
            base_index_ref: file_ref(&overlay.base_index_ref),
            accepted_refs: catalog.accepted_refs.iter().map(file_ref).collect(),
        },
    )?;
    if replayed.overlay_ref != *overlay_ref || replayed.overlay != overlay {
        return Err("semantic overlay differs from complete replay".into());
    }
    for (path, expected) in &replayed.files {
        let raw = crate::exact_read::read_bound_regular_file(context, &root.join(path))
            .map_err(|e| e.message)?;
        if raw.bytes != *expected {
            return Err("semantic projection differs from replayed records/routes/terms".into());
        }
    }
    Ok(replayed)
}

const ADMISSION_DOMAIN: &[u8] = b"gtkg.qk.semantic-admission/v1\0";
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Admission {
    schema: String,
    overlay_ref: FileReceiptRef,
    signature: String,
}
fn admission_path(overlay_ref: &FileReceiptRef) -> Result<String, String> {
    overlay_ref.validate().map_err(|e| e.to_string())?;
    Ok(format!(
        ".gtkg/qk/runtime/semantic-admission/{}.json",
        &overlay_ref.sha256[7..]
    ))
}
fn admission_body(
    overlay_ref: &FileReceiptRef,
    overlay: &QueryIndexOverlay,
) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&(overlay_ref, overlay)).map_err(|e| e.to_string())
}
fn mac(key: &[u8; 32], bytes: &[u8]) -> Result<String, String> {
    use hmac::{Hmac, Mac};
    let mut mac =
        Hmac::<sha2::Sha256>::new_from_slice(key).map_err(|_| "invalid semantic MAC key")?;
    mac.update(ADMISSION_DOMAIN);
    mac.update(bytes);
    Ok(hex::encode(mac.finalize().into_bytes()))
}
fn write_admission(
    context: &CallContext,
    workspace: &Path,
    replayed: &ReplayedProjection,
) -> Result<(), String> {
    if context.effect_policy != crate::EffectPolicy::WorkspaceWrite {
        return Err("semantic admission requires WorkspaceWrite".into());
    }
    let workspace = artifact::workspace(context, workspace)?;
    super::query::initialize_authority(context, &workspace)?;
    let (key, _) = super::query::authority(context, &workspace)?;
    let record = Admission {
        schema: "gtkg.qk.semantic-admission/v1".into(),
        overlay_ref: replayed.overlay_ref.clone(),
        signature: mac(
            &key,
            &admission_body(&replayed.overlay_ref, &replayed.overlay)?,
        )?,
    };
    crate::durable::publish_private_immutable_json(
        context,
        &workspace.join(admission_path(&replayed.overlay_ref)?),
        &record,
        "qk-semantic-admission",
    )
    .map(|_| ())
    .map_err(|e| e.to_string())
}

impl ReplayedProjection {
    pub fn overlay(&self) -> &QueryIndexOverlay {
        &self.overlay
    }
    pub fn overlay_ref(&self) -> &FileReceiptRef {
        &self.overlay_ref
    }
    pub(crate) fn files(&self) -> &BTreeMap<String, Vec<u8>> {
        &self.files
    }
    pub(crate) fn admit(self, context: &CallContext, workspace: &Path) -> Result<(), String> {
        write_admission(context, workspace, &self)
    }
}
