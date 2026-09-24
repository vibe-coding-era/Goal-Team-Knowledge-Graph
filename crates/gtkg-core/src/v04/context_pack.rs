//! Terminal, authenticated reference packing. Staging and persistence belong to the host.
use super::{
    artifact,
    graph_projection::GraphLink,
    index::{self, ArtifactRef, EvidenceChunk, IndexManifest, Posting},
    query_meter::{QueryBudgetLimits, QueryBudgetUsage, QueryMeter},
    semantic_projection as semantic, source,
    source_context::ReviewedSummaryContext,
};
use crate::CallContext;
use gtkg_protocol::{FileReceiptRef, v04::ArtifactPayload};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::Sha256;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

pub const REQUEST_SCHEMA: &str = "gtkg.qk.context-pack-request/v1";
pub const PLAN_SCHEMA: &str = "gtkg.qk.query-plan-artifact/v1";
pub const HITS_SCHEMA: &str = "gtkg.qk.query-hits-artifact/v1";
const TICKET_SCHEMA: &str = "gtkg.qk.context-pack-ticket/v1";
const DOMAIN: &[u8] = b"gtkg.qk.context-pack-ticket/v1\0";
const TICKET_LIMIT: usize = 16 * 1024;
const REQUEST_LIMIT: u64 = 32 * 1024;
const PLAN_LIMIT: u64 = 128 * 1024;
const HITS_LIMIT: u64 = 8 * 1024 * 1024;
fn default_units() -> u32 {
    8000
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackRequest {
    pub schema: String,
    pub plan_ref: FileReceiptRef,
    pub hits_ref: FileReceiptRef,
    pub pack_ticket: String,
    #[serde(default = "default_units")]
    pub max_context_units: u32,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuerySourceIdentity {
    pub snapshot_id: String,
    pub source_commit: String,
    pub source_tree: String,
    pub source_ref: FileReceiptRef,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueryPlanArtifact {
    pub schema: String,
    pub original_query: String,
    pub query_policy: String,
    pub query_identity: String,
    pub public_index_ref: FileReceiptRef,
    pub base_index_ref: FileReceiptRef,
    pub selected_index_lineage: Vec<ArtifactRef>,
    pub total_index_bytes: u64,
    pub source_identity: QuerySourceIdentity,
    pub query_plan: Value,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueryHitsArtifact {
    pub schema: String,
    pub query_identity: String,
    pub plan_sha256: String,
    pub ranking_complete: bool,
    pub ranking_scope: String,
    pub candidate_ambiguities: Vec<Vec<String>>,
    pub hits: Vec<PackHitRef>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackHitRef {
    pub rank: u32,
    pub posting: Posting,
    pub evidence_byte_start: usize,
    pub evidence_byte_end: usize,
    pub score: f64,
    pub score_reasons: Value,
    pub neighbor_of: Option<String>,
    pub graph_relation: Option<GraphLink>,
    pub summary_context: Vec<ReviewedSummaryContext>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackPreparation {
    pub plan_json: String,
    pub hits_json: String,
    pub pack_ticket: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SealedBytes {
    sha256: String,
    bytes: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PackTicketBody {
    schema: String,
    workspace: String,
    query_identity: String,
    public_index_ref: FileReceiptRef,
    base_index_ref: FileReceiptRef,
    source_identity: QuerySourceIdentity,
    plan: SealedBytes,
    hits: SealedBytes,
    usage: QueryBudgetUsage,
    limits: QueryBudgetLimits,
}
/// Exact strings are staged verbatim. Input digests and usage come from Core.
pub fn prepare_pack(
    workspace: &Path,
    plan: &QueryPlanArtifact,
    hits: &QueryHitsArtifact,
    usage: QueryBudgetUsage,
    limits: QueryBudgetLimits,
    key: &[u8; 32],
) -> Result<PackPreparation, String> {
    limits.validate()?;
    if plan.schema != PLAN_SCHEMA
        || hits.schema != HITS_SCHEMA
        || plan.query_identity != hits.query_identity
        || limits != QueryBudgetLimits::for_index(plan.total_index_bytes)
    {
        return Err("pack preparation identity/schema/budget mismatch".into());
    }
    let plan_json = serde_json::to_string(plan).map_err(|e| e.to_string())?;
    let mut bound_hits = hits.clone();
    let plan_sha = artifact::digest(plan_json.as_bytes());
    if !bound_hits.plan_sha256.is_empty() && bound_hits.plan_sha256 != plan_sha {
        return Err("pack hits plan digest mismatch".into());
    }
    bound_hits.plan_sha256 = plan_sha.clone();
    let hits_json = serde_json::to_string(&bound_hits).map_err(|e| e.to_string())?;
    validate_batch(plan, &bound_hits)?;
    if plan_json.len() as u64 > PLAN_LIMIT || hits_json.len() as u64 > HITS_LIMIT {
        return Err("pack staging exceeds bounded transport size".into());
    }
    let body = PackTicketBody {
        schema: TICKET_SCHEMA.into(),
        workspace: workspace.to_string_lossy().into(),
        query_identity: plan.query_identity.clone(),
        public_index_ref: plan.public_index_ref.clone(),
        base_index_ref: plan.base_index_ref.clone(),
        source_identity: plan.source_identity.clone(),
        plan: SealedBytes {
            sha256: plan_sha,
            bytes: plan_json.len() as u64,
        },
        hits: SealedBytes {
            sha256: artifact::digest(hits_json.as_bytes()),
            bytes: hits_json.len() as u64,
        },
        usage,
        limits,
    };
    let bytes = serde_json::to_vec(&body).map_err(|e| e.to_string())?;
    let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|_| "invalid HMAC key")?;
    mac.update(DOMAIN);
    mac.update(&bytes);
    let pack_ticket = format!(
        "{}.{}",
        hex::encode(bytes),
        hex::encode(mac.finalize().into_bytes())
    );
    if pack_ticket.len() > TICKET_LIMIT {
        return Err("pack ticket exceeds bounded transport size".into());
    }
    Ok(PackPreparation {
        plan_json,
        hits_json,
        pack_ticket,
    })
}

fn validate_batch(plan: &QueryPlanArtifact, hits: &QueryHitsArtifact) -> Result<(), String> {
    if plan.schema != PLAN_SCHEMA
        || hits.schema != HITS_SCHEMA
        || plan.query_identity != hits.query_identity
        || plan.original_query.trim().is_empty()
        || plan.original_query.len() > 16384
        || !plan.query_plan.is_object()
        || hits.hits.len() > 1000
        || hits.ranking_scope
            != if hits.ranking_complete {
                "all_required_candidates"
            } else {
                "observed_candidates_provisional_scores"
            }
    {
        return Err("pack plan/hit batch identity or bounds invalid".into());
    }
    plan.public_index_ref
        .validate()
        .map_err(|e| e.to_string())?;
    plan.base_index_ref.validate().map_err(|e| e.to_string())?;
    plan.source_identity
        .source_ref
        .validate()
        .map_err(|e| e.to_string())?;
    let mut ids = BTreeSet::new();
    let mut rank = None;
    for h in &hits.hits {
        if !h.score.is_finite()
            || h.evidence_byte_start >= h.evidence_byte_end
            || !h.score_reasons.is_array()
            || !ids.insert(&h.posting.chunk_id)
            || rank.is_some_and(|r| r >= h.rank)
        {
            return Err("pack hit ordering/span/score invalid".into());
        }
        rank = Some(h.rank);
    }
    Ok(())
}
fn authenticate(token: &str, key: &[u8; 32], root: &Path) -> Result<PackTicketBody, String> {
    if token.len() > TICKET_LIMIT {
        return Err("pack ticket exceeds bounded transport size".into());
    }
    let (body, signature) = token.split_once('.').ok_or("invalid pack ticket")?;
    let bytes = hex::decode(body).map_err(|_| "invalid pack ticket encoding")?;
    let signature = hex::decode(signature).map_err(|_| "invalid pack ticket signature")?;
    let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|_| "invalid HMAC key")?;
    mac.update(DOMAIN);
    mac.update(&bytes);
    mac.verify_slice(&signature)
        .map_err(|_| "pack ticket authentication failed")?;
    let body: PackTicketBody =
        serde_json::from_slice(&bytes).map_err(|_| "invalid pack ticket body")?;
    if body.schema != TICKET_SCHEMA
        || body.workspace != root.to_string_lossy()
        || body.plan.bytes > PLAN_LIMIT
        || body.hits.bytes > HITS_LIMIT
    {
        return Err("pack ticket workspace/schema/bounds mismatch".into());
    }
    body.limits.validate()?;
    Ok(body)
}
pub(crate) fn read_authority(
    context: &CallContext,
    root: &Path,
    meter: &mut QueryMeter,
) -> Result<[u8; 32], String> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Authority {
        schema: String,
        workspace: String,
        key: String,
    }
    let path = root.join(".gtkg/qk/runtime/query-authority.json");
    let bytes = meter.read(context, &path, 16 * 1024)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let m = fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
        if m.nlink() != 1 || m.permissions().mode() & 0o077 != 0 {
            return Err("pack authority must be private single-link regular file".into());
        }
    }
    let a: Authority = serde_json::from_slice(&bytes).map_err(|_| "invalid query authority")?;
    if a.schema != "gtkg.qk.query-authority/v1" || a.workspace != root.to_string_lossy() {
        return Err("pack authority belongs to another workspace".into());
    }
    hex::decode(a.key)
        .map_err(|_| "invalid query authority key")?
        .try_into()
        .map_err(|_| "invalid query authority key length".into())
}
fn sealed<T: serde::de::DeserializeOwned>(
    context: &CallContext,
    root: &Path,
    reference: &FileReceiptRef,
    seal: &SealedBytes,
    meter: &mut QueryMeter,
) -> Result<T, String> {
    reference.validate().map_err(|e| e.to_string())?;
    if reference.sha256 != seal.sha256 {
        return Err("staged reference differs from authenticated bytes".into());
    }
    let bytes = meter.read(context, &root.join(&reference.path), seal.bytes)?;
    if bytes.len() as u64 != seal.bytes || artifact::digest(&bytes) != seal.sha256 {
        return Err("staged artifact differs from authenticated bytes".into());
    }
    serde_json::from_slice(&bytes).map_err(|e| e.to_string())
}
fn budget_error(error: &str) -> bool {
    error.starts_with("E_QUERY_IO_BUDGET") || error.starts_with("E_QUERY_WALL_TIME_BUDGET")
}

#[derive(Default)]
struct Progress {
    plan: Option<QueryPlanArtifact>,
    hits: Option<QueryHitsArtifact>,
    evidence: Vec<Value>,
    summaries: Vec<ReviewedSummaryContext>,
    omissions: Vec<Value>,
    source_objects: u64,
    source_ledgers: u64,
    chunk_shards: u64,
    chunks: u64,
    index_lineage: u64,
    reviewed_lineage: u64,
    context_units: usize,
    truncated: bool,
}
fn receipt(
    request: &PackRequest,
    ticket: &PackTicketBody,
    meter: &QueryMeter,
    p: &Progress,
    exhaustion: Option<&str>,
) -> Value {
    let usage = meter.usage();
    let partial =
        exhaustion.is_some() || p.truncated || p.hits.as_ref().is_none_or(|h| !h.ranking_complete);
    json!({"schema":"gtkg.qk.context-pack-receipt/v1","status":if partial {"partial"}else{"complete"},
        "plan_ref":request.plan_ref,"hits_ref":request.hits_ref,"query_identity":ticket.query_identity,
        "original_query":p.plan.as_ref().map(|v|&v.original_query),"query_policy":p.plan.as_ref().map(|v|&v.query_policy),
        "public_index_ref":ticket.public_index_ref,"base_index_ref":ticket.base_index_ref,"source_identity":ticket.source_identity,
        "ranking_complete":p.hits.as_ref().is_some_and(|h|h.ranking_complete),
        "ranking_scope":p.hits.as_ref().map(|h|h.ranking_scope.as_str()).unwrap_or("authenticated_batch_not_read"),
        "candidate_ambiguities":p.hits.as_ref().map(|h|&h.candidate_ambiguities),"raw_evidence":p.evidence,"summary_context":p.summaries,
        "answerability":if exhaustion.is_some(){"budget_exhausted"}else if p.hits.as_ref().is_some_and(|h|h.ranking_complete&&h.hits.is_empty()){"no_match_within_declared_scope"}else{"unresolved"},
        "omitted":p.omissions,"budget":{"usage":usage,"limits":ticket.limits,"query_usage":ticket.usage,
            "io_bytes_this_pack":usage.io_bytes.saturating_sub(ticket.usage.io_bytes),"wall_time_us_this_pack":usage.wall_time_us.saturating_sub(ticket.usage.wall_time_us),
            "context_units":p.context_units,"context_unit_limit":request.max_context_units,"tokenizer":index::TOKENIZER,
            "mandatory_header_overrun":usage.io_bytes>ticket.limits.io_bytes},
        "verification_scope":{"source_object_reads":p.source_objects,"source_ledger_reads":p.source_ledgers,"chunk_shard_reads":p.chunk_shards,"chunk_reads":p.chunks,
            "selected_index_lineage_reads":p.index_lineage,"selected_reviewed_lineages":p.reviewed_lineage,
            "selected_raw_spans":if p.evidence.is_empty(){"not_read"}else{"reverified_this_call"},
            "selected_lineage":if p.reviewed_lineage==0{"not_read"}else{"digest_and_selected_claim_rechecked_this_call"},
            "review_admission":"authenticated_prior_query_admission","semantic_review_replayed_this_call":false,
            "ranking":"authenticated_query_result","unread_objects":"not_checked","full_graph_reads":0},
        "truncation":{"budget":exhaustion.is_some(),"reason":exhaustion,"context_units":p.truncated},"terminal":true,"continuation":null,
        "budget_guarantee":"authenticated_linear_chain_ending_in_pack","retry_fork_accounting":"host_owned; old query cursors and pack tickets remain replayable",
        "deadline_scope":"cooperative Core checks; blocking OS calls are not preempted","source_fallback":false,"target_execution":false,
        "scope_limitations":["one authenticated returned hit batch; no new discovery, ranking, or structural expansion","unread artifacts and full source absence are not verified","context units count Unicode codepoints, not measured model tokens"]})
}
/// Host stages input; this operation only reads and returns a terminal receipt.
pub fn execute(context: &CallContext, payload: &ArtifactPayload) -> Result<Value, String> {
    let mut bootstrap_limits = QueryBudgetLimits::for_index(0);
    bootstrap_limits.io_bytes = 64 * 1024;
    let mut meter = QueryMeter::new(QueryBudgetUsage::default(), bootstrap_limits);
    let root = artifact::workspace(context, &payload.workspace_root)?;
    let request: PackRequest =
        meter.read_reference(context, &root, &payload.artifact_ref, REQUEST_LIMIT)?;
    if request.schema != REQUEST_SCHEMA || !(1..=8000).contains(&request.max_context_units) {
        return Err("pack request schema/context bounds invalid".into());
    }
    let key = read_authority(context, &root, &mut meter)?;
    let ticket = authenticate(&request.pack_ticket, &key, &root)?;
    meter.inherit(ticket.usage.clone(), ticket.limits.clone())?;
    let mut progress = Progress::default();
    let result = pack(context, &root, &request, &ticket, &mut meter, &mut progress);
    match result {
        Ok(()) => Ok(receipt(&request, &ticket, &meter, &progress, None)),
        Err(error) if budget_error(&error) => {
            Ok(receipt(&request, &ticket, &meter, &progress, Some(&error)))
        }
        Err(error) => Err(format!(
            "{error}; authenticated_budget_usage={}",
            serde_json::to_string(&meter.usage()).map_err(|e| e.to_string())?
        )),
    }
}

fn pack(
    context: &CallContext,
    root: &Path,
    request: &PackRequest,
    ticket: &PackTicketBody,
    meter: &mut QueryMeter,
    p: &mut Progress,
) -> Result<(), String> {
    meter.check_time()?;
    if meter.remaining_io() == 0 {
        return Err("E_QUERY_IO_BUDGET".into());
    }
    let plan: QueryPlanArtifact = sealed(context, root, &request.plan_ref, &ticket.plan, meter)?;
    if plan.query_identity != ticket.query_identity
        || plan.public_index_ref != ticket.public_index_ref
        || plan.base_index_ref != ticket.base_index_ref
        || plan.source_identity != ticket.source_identity
        || QueryBudgetLimits::for_index(plan.total_index_bytes) != ticket.limits
    {
        return Err("pack plan differs from authenticated query/index/source/budget".into());
    }
    p.plan = Some(plan.clone());
    let hits: QueryHitsArtifact = sealed(context, root, &request.hits_ref, &ticket.hits, meter)?;
    validate_batch(&plan, &hits)?;
    if hits.plan_sha256 != ticket.plan.sha256 {
        return Err("pack hits belong to a different plan".into());
    }
    p.hits = Some(hits.clone());
    let (manifest, overlay, base_bytes) = if plan.public_index_ref == plan.base_index_ref {
        if !matches!(
            plan.query_policy.as_str(),
            index::QUERY_POLICY | gtkg_protocol::v04::SELECTIVE_QUERY_POLICY
        ) {
            return Err("pack raw index/query policy mismatch".into());
        }
        let before = meter.usage().io_bytes;
        let m: IndexManifest =
            meter.read_reference(context, root, &plan.base_index_ref, meter.remaining_io())?;
        let actual = meter.usage().io_bytes.saturating_sub(before);
        index::validate_manifest(&m)?;
        if m.total_index_bytes != plan.total_index_bytes {
            return Err("pack source index byte denominator mismatch".into());
        }
        (m, None, actual)
    } else {
        if plan.query_policy != semantic::QUERY_POLICY {
            return Err("pack overlay/query policy mismatch".into());
        }
        let loaded = semantic::load_overlay_with_io(context, root, &plan.public_index_ref, meter)?;
        if loaded.overlay.base_index_ref.path != plan.base_index_ref.path
            || loaded.overlay.base_index_ref.sha256 != plan.base_index_ref.sha256
            || loaded.overlay.total_index_bytes != plan.total_index_bytes
        {
            return Err("pack overlay/base/denominator mismatch".into());
        }
        let actual = loaded.overlay.base_index_ref.bytes;
        (loaded.base.clone(), Some(loaded), actual)
    };
    if plan.base_index_ref.path != format!("{}/manifest.json", manifest.index_root)
        || manifest.source_ref != plan.source_identity.source_ref
        || manifest.snapshot_id != plan.source_identity.snapshot_id
        || manifest.source_commit != plan.source_identity.source_commit
        || manifest.source_tree != plan.source_identity.source_tree
    {
        return Err("pack manifest/source identity mismatch".into());
    }
    let mut seen_lineage = BTreeMap::from([(
        plan.base_index_ref.path.clone(),
        ArtifactRef {
            path: plan.base_index_ref.path.clone(),
            sha256: plan.base_index_ref.sha256.clone(),
            bytes: base_bytes,
        },
    )]);
    p.index_lineage = 1;
    for r in &plan.selected_index_lineage {
        if let Some(previous) = seen_lineage.insert(r.path.clone(), r.clone()) {
            if previous != *r {
                return Err("conflicting selected index lineage".into());
            }
            continue;
        }
        // Parsing is not required for these query-authenticated provenance bytes.
        verify_bytes(context, root, r, meter)?;
        p.index_lineage += 1;
    }
    let mut ledger = None;
    let mut routers = BTreeMap::new();
    let mut objects = BTreeMap::new();
    let mut contexts: BTreeMap<String, ReviewedSummaryContext> = BTreeMap::new();
    for hit in &hits.hits {
        meter.check_time()?;
        if p.context_units >= request.max_context_units as usize {
            p.truncated = true;
            p.omissions
                .push(json!({"evidence_id":hit.posting.chunk_id,"reason":"context_units"}));
            continue;
        }
        let chunk = load_chunk(
            context,
            root,
            &manifest,
            &hit.posting,
            meter,
            &mut routers,
            p,
        )?;
        if ledger.is_none() {
            let loaded: source::SourceCoverageLedger =
                meter.read_reference(context, root, &manifest.source_ref, meter.remaining_io())?;
            if loaded.schema_version != "gtkg.qk.source-coverage-ledger/v1"
                || loaded.snapshot_id != manifest.snapshot_id
                || loaded.source_commit != manifest.source_commit
                || loaded.source_tree != manifest.source_tree
            {
                return Err("pack source ledger/index mismatch".into());
            }
            let mut paths = BTreeSet::new();
            for leaf in &loaded.leaves {
                if !paths.insert(&leaf.path) {
                    return Err("duplicate source ledger path".into());
                }
            }
            ledger = Some(loaded);
            p.source_ledgers += 1;
        }
        let l = ledger.as_ref().ok_or("source ledger absent")?;
        let leaf = l
            .leaves
            .iter()
            .find(|l| l.path == chunk.path)
            .ok_or("chunk source path absent from pinned ledger")?;
        if leaf.scope != source::Scope::Included
            || leaf.text != source::TextStatus::Extracted
            || leaf.content_sha256.as_deref() != Some(&chunk.file_sha)
            || leaf.object_sha256.as_deref() != Some(&chunk.object_sha)
            || leaf.byte_len != chunk.object_bytes
        {
            return Err("chunk source path/object membership mismatch".into());
        }
        if !objects.contains_key(&chunk.object_sha) {
            let raw = meter.read(
                context,
                &root
                    .join(&manifest.archive_root)
                    .join("objects")
                    .join(&chunk.object_sha),
                chunk.object_bytes,
            )?;
            if raw.len() as u64 != chunk.object_bytes
                || artifact::digest(&raw) != format!("sha256:{}", chunk.object_sha)
            {
                return Err("pack archived source object identity mismatch".into());
            }
            objects.insert(chunk.object_sha.clone(), raw);
            p.source_objects += 1;
        }
        let raw = objects
            .get(&chunk.object_sha)
            .ok_or("source bytes absent")?;
        let text = std::str::from_utf8(raw).map_err(|_| "source object is not UTF8")?;
        if text.as_bytes().get(chunk.byte_start..chunk.byte_end) != Some(chunk.text.as_bytes())
            || !text.is_char_boundary(chunk.byte_start)
            || !text.is_char_boundary(chunk.byte_end)
            || line_at(text, chunk.byte_start) != chunk.line_start
            || line_at(text, chunk.byte_end - 1) != chunk.line_end
        {
            return Err("pack source span/line differs from indexed chunk".into());
        }
        if hit.evidence_byte_start < chunk.byte_start
            || hit.evidence_byte_end > chunk.byte_end
            || !text.is_char_boundary(hit.evidence_byte_start)
            || !text.is_char_boundary(hit.evidence_byte_end)
        {
            return Err("authenticated source window exceeds chunk or splits Unicode".into());
        }
        let window = &text[hit.evidence_byte_start..hit.evidence_byte_end];
        let remaining = request.max_context_units as usize - p.context_units;
        let anchor = window_anchor(window, hit, &chunk);
        let (relative_begin, relative_end) = clipped_window(window, anchor, remaining);
        let begin = hit.evidence_byte_start + relative_begin;
        let end = hit.evidence_byte_start + relative_end;
        let source_text = &text[begin..end];
        p.context_units += source_text.chars().count();
        let clipped = relative_begin != 0 || relative_end != window.len();
        p.truncated |= clipped;
        p.evidence.push(json!({"id":chunk.id,"path":chunk.path,"text":source_text,"byte_start":begin,"byte_end":end,"line_start":line_at(text,begin),"line_end":line_at(text,end-1),
            "file_sha":chunk.file_sha,"object_sha":chunk.object_sha,"source_commit":chunk.source_commit,"source_tree":chunk.source_tree,"snapshot_id":chunk.snapshot_id,
            "role":chunk.role,"language":chunk.language,"parent":chunk.parent,"score":hit.score,"score_reasons":hit.score_reasons,"neighbor_of":hit.neighbor_of,"graph_relation":hit.graph_relation,
            "source_span_verified":true,"inference_status":"original_source_only","truncated":clipped}));
        for summary in &hit.summary_context {
            let mut identity = summary.clone();
            identity.evidence_ids.clear();
            identity.citation_coverage_in_pack = "partial".into();
            if let Some(previous) = contexts.insert(summary.context_id.clone(), identity.clone())
                && previous != identity
            {
                return Err("conflicting reviewed context identity within batch".into());
            }
        }
    }
    for summary in contexts.values() {
        if summary.text_units() > request.max_context_units as usize - p.context_units {
            p.truncated = true;
            p.omissions.push(json!({"context_id":summary.context_id,"reason":"context_units; proposition and condition omitted together"}));
            continue;
        }
        let loaded = overlay
            .as_ref()
            .ok_or("reviewed context requires admitted semantic overlay")?;
        let record =
            semantic::load_selected_context(context, root, loaded, &summary.context_ref, meter)?;
        let mut checked = semantic::verify_selected_lineage(
            context,
            root,
            loaded,
            &record,
            &summary.context_ref,
            meter,
        )?;
        if &checked != summary {
            return Err("staged reviewed context differs from selected accepted lineage".into());
        }
        fill_coverage(&mut checked, &p.evidence);
        p.context_units += checked.text_units();
        p.summaries.push(checked);
        p.reviewed_lineage += 1;
    }
    meter.check_time()
}
fn verify_bytes(
    context: &CallContext,
    root: &Path,
    r: &ArtifactRef,
    meter: &mut QueryMeter,
) -> Result<(), String> {
    FileReceiptRef {
        path: r.path.clone(),
        sha256: r.sha256.clone(),
    }
    .validate()
    .map_err(|e| e.to_string())?;
    let raw = meter.read(context, &root.join(&r.path), r.bytes)?;
    if raw.len() as u64 != r.bytes || artifact::digest(&raw) != r.sha256 {
        return Err("selected index lineage bytes/digest mismatch".into());
    }
    Ok(())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChunkShard {
    schema: String,
    snapshot_id: String,
    index_root: String,
    bucket: String,
    chunks: BTreeMap<String, ArtifactRef>,
}
fn load_chunk(
    context: &CallContext,
    root: &Path,
    m: &IndexManifest,
    posting: &Posting,
    meter: &mut QueryMeter,
    routers: &mut BTreeMap<String, ChunkShard>,
    p: &mut Progress,
) -> Result<EvidenceChunk, String> {
    index::validate_posting(m, posting)?;
    let bucket = &posting.chunk_id[..2];
    if !routers.contains_key(bucket) {
        let r = m
            .chunk_router
            .get(bucket)
            .and_then(|v| v.as_ref())
            .ok_or("selected chunk router missing")?;
        let shard: ChunkShard = meter.read_artifact(context, root, r)?;
        if shard.schema != "gtkg.qk.chunk-router-shard/v1"
            || shard.snapshot_id != m.snapshot_id
            || shard.index_root != m.index_root
            || shard.bucket != bucket
        {
            return Err("selected chunk router identity mismatch".into());
        }
        for (id, r) in &shard.chunks {
            if id.len() != 64
                || !id
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                || !id.starts_with(bucket)
                || r.path != format!("{}/chunks/{id}.json", m.index_root)
            {
                return Err("chunk router entry identity mismatch".into());
            }
            FileReceiptRef {
                path: r.path.clone(),
                sha256: r.sha256.clone(),
            }
            .validate()
            .map_err(|e| e.to_string())?;
        }
        routers.insert(bucket.into(), shard);
        p.chunk_shards += 1;
    }
    if routers
        .get(bucket)
        .and_then(|s| s.chunks.get(&posting.chunk_id))
        != Some(&posting.chunk_ref)
    {
        return Err("hit chunk ref is not a member of pinned index router".into());
    }
    let chunk: EvidenceChunk = meter.read_artifact(context, root, &posting.chunk_ref)?;
    index::validate_chunk(m, &chunk)?;
    if chunk.id != posting.chunk_id || chunk.tokens != posting.tokens {
        return Err("pack posting/chunk identity mismatch".into());
    }
    p.chunks += 1;
    Ok(chunk)
}
fn line_at(text: &str, at: usize) -> usize {
    text.as_bytes()[..at]
        .iter()
        .filter(|b| **b == b'\n')
        .count()
        + 1
}
fn window_anchor(window: &str, hit: &PackHitRef, chunk: &EvidenceChunk) -> usize {
    // A reviewed match anchors at its source citation, never at summary text.
    for citation in hit.summary_context.iter().flat_map(|s| &s.citations) {
        if citation.path == chunk.path
            && citation
                .file_sha256
                .strip_prefix("sha256:")
                .unwrap_or(&citation.file_sha256)
                == chunk.file_sha
            && citation.span.byte_end > hit.evidence_byte_start
            && citation.span.byte_start < hit.evidence_byte_end
        {
            let anchor =
                citation.span.byte_start.max(hit.evidence_byte_start) - hit.evidence_byte_start;
            if window.is_char_boundary(anchor) {
                return anchor;
            }
        }
    }
    let mut reasons: Vec<_> = hit.score_reasons.as_array().into_iter().flatten().collect();
    reasons.sort_by_key(|r| std::cmp::Reverse(r["tier"].as_u64().unwrap_or(0)));
    for r in reasons {
        if let Some((channel, term)) = r["term"].as_str().and_then(|t| t.split_once(':'))
            && let Some(at) = window.find(term).or_else(|| {
                (channel == "fold")
                    .then(|| folded_window_anchor(window, term))
                    .flatten()
            })
        {
            return at;
        }
    }
    0
}
fn clipped_window(window: &str, anchor: usize, units: usize) -> (usize, usize) {
    let count = window.chars().count();
    let take = count.min(units);
    let start = if take == count {
        0
    } else {
        window[..anchor]
            .chars()
            .count()
            .saturating_sub(take / 4)
            .min(count - take)
    };
    let begin = window
        .char_indices()
        .nth(start)
        .map_or(window.len(), |(n, _)| n);
    let end = window
        .char_indices()
        .nth(start + take)
        .map_or(window.len(), |(n, _)| n);
    (begin, end)
}
/// Locate a normalized match while retaining an offset in the original bytes.
fn folded_window_anchor(text: &str, term: &str) -> Option<usize> {
    use unicode_normalization::{
        UnicodeNormalization,
        char::{canonical_combining_class, decompose_canonical},
    };
    let mut units: Vec<(char, usize, u8)> = vec![];
    for (origin, ch) in text.char_indices() {
        decompose_canonical(ch, |part| {
            for lower in part.to_lowercase() {
                decompose_canonical(lower, |unit| {
                    let class = canonical_combining_class(unit);
                    let mut at = units.len();
                    if class != 0 {
                        while at > 0 && units[at - 1].2 > class {
                            at -= 1;
                        }
                    }
                    units.insert(at, (unit, origin, class));
                });
            }
        });
    }
    let mut folded = String::new();
    let mut origins = vec![];
    for (ch, origin, _) in units {
        folded.push(ch);
        origins.extend((0..ch.len_utf8()).map(|_| origin));
    }
    let needle: String = term.nfd().flat_map(char::to_lowercase).nfd().collect();
    folded.find(&needle).and_then(|n| origins.get(n).copied())
}
pub(crate) fn fill_coverage(summary: &mut ReviewedSummaryContext, evidence: &[Value]) {
    let mut ids = BTreeSet::new();
    let mut complete = !summary.citations.is_empty();
    for citation in &summary.citations {
        let mut spans = vec![];
        for e in evidence {
            if e["path"].as_str() == Some(&citation.path)
                && e["file_sha"].as_str()
                    == Some(
                        citation
                            .file_sha256
                            .strip_prefix("sha256:")
                            .unwrap_or(&citation.file_sha256),
                    )
                && let (Some(begin), Some(end), Some(id)) = (
                    e["byte_start"].as_u64(),
                    e["byte_end"].as_u64(),
                    e["id"].as_str(),
                )
            {
                let begin = begin as usize;
                let end = end as usize;
                if begin < citation.span.byte_end && end > citation.span.byte_start {
                    spans.push((begin, end));
                    ids.insert(id.to_string());
                }
            }
        }
        spans.sort_unstable();
        let mut covered = citation.span.byte_start;
        for (begin, end) in spans {
            if begin > covered {
                break;
            }
            covered = covered.max(end);
        }
        complete &= covered >= citation.span.byte_end;
    }
    summary.evidence_ids = ids.into_iter().collect();
    summary.citation_coverage_in_pack = if complete { "complete" } else { "partial" }.into();
}

#[cfg(test)]
mod tests {
    #[test]
    fn clipped_pack_window_retains_folded_match_and_original_unicode() {
        let text =
            "an unrelated source heading repeated before 中文 Café source evidence continues";
        let anchor =
            super::folded_window_anchor(text, "CAFE\u{301}").expect("folded original anchor");
        let (begin, end) = super::clipped_window(text, anchor, 12);
        assert!(text[begin..end].contains("Café"));
        assert_eq!(text[begin..end].chars().count(), 12);
        assert!(text.is_char_boundary(begin) && text.is_char_boundary(end));
    }
}
