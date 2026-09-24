//! Lazy confirmed-call projection. Build replays relations from archived source;
//! reads authenticate only the pinned root and selected source-path bucket.
use super::{
    analysis::{AnalysisCandidate, AnalysisPlan},
    artifact,
    index::ArtifactRef,
    source,
};
use crate::{CallContext, durable::publish_immutable_json, exact_read::read_bound_regular_file};
use gtkg_extract::v04::{
    AnalysisContext, Span,
    binding::{CallBindingProof, RESOLVER_PROFILE, VERIFIER_PROFILE, confirmed_edges},
    context_digest,
};
use gtkg_protocol::FileReceiptRef;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};
const SCHEMA: &str = "gtkg.qk.confirmed-call-graph/v1";
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphLink {
    pub call_id: String,
    pub source_path: String,
    pub call_span: Span,
    pub expression: String,
    pub target_path: String,
    pub target_id: String,
    pub target_name: String,
    pub target_span: Span,
    pub target_name_span: Span,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphManifest {
    pub schema: String,
    pub graph_root: String,
    pub source_ref: FileReceiptRef,
    pub candidate_ref: FileReceiptRef,
    pub snapshot_id: String,
    pub source_commit: String,
    pub source_tree: String,
    pub context_digest: String,
    pub resolver: String,
    pub verifier: String,
    pub total_calls: usize,
    pub total_links: usize,
    pub total_graph_bytes: u64,
    pub router: BTreeMap<String, Option<ArtifactRef>>,
    pub bucket_counts: BTreeMap<String, usize>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GraphShard {
    schema: String,
    graph_root: String,
    source_ref: FileReceiptRef,
    candidate_ref: FileReceiptRef,
    context_digest: String,
    bucket: String,
    links: Vec<GraphLink>,
}
fn relative(p: &str) -> Result<(), String> {
    if p.is_empty()
        || p.contains(['\\', '\0'])
        || Path::new(p).is_absolute()
        || p.split('/').any(|x| x.is_empty() || x == "." || x == "..")
    {
        Err("invalid graph relative path".into())
    } else {
        Ok(())
    }
}
fn graph_root(
    source_ref: &FileReceiptRef,
    candidate_ref: &FileReceiptRef,
    ctx: &str,
) -> Result<String, String> {
    let d = artifact::digest(
        &serde_json::to_vec(&(
            source_ref,
            candidate_ref,
            ctx,
            RESOLVER_PROFILE,
            VERIFIER_PROFILE,
            SCHEMA,
        ))
        .map_err(|e| e.to_string())?,
    );
    Ok(format!(".gtkg/qk/graphs/{}", &d[7..]))
}
fn publish<T: Serialize>(
    context: &CallContext,
    workspace: &Path,
    path: &str,
    value: &T,
) -> Result<ArtifactRef, String> {
    relative(path)?;
    let bytes = serde_json::to_vec_pretty(value).map_err(|e| e.to_string())?;
    publish_immutable_json(context, &workspace.join(path), value, "qk-confirmed-graph")
        .map_err(|e| e.to_string())?;
    Ok(ArtifactRef {
        path: path.into(),
        bytes: bytes.len() as u64,
        sha256: artifact::digest(&bytes),
    })
}
fn replay_bound_inputs(
    context: &CallContext,
    workspace: &Path,
    source_ref: &FileReceiptRef,
    candidate_ref: &FileReceiptRef,
    proofs: &[CallBindingProof],
    raw_sources: &BTreeMap<String, Vec<u8>>,
    analysis_context: &AnalysisContext,
) -> Result<source::SourceCoverageLedger, String> {
    let root = artifact::workspace(context, workspace)?;
    let (candidate, _): (AnalysisCandidate, _) = artifact::read(context, &root, candidate_ref)?;
    let (plan, _): (AnalysisPlan, _) = artifact::read(context, &root, &candidate.plan_ref)?;
    let (ledger, source_path): (source::SourceCoverageLedger, _) =
        artifact::read(context, &root, source_ref)?;
    if candidate.schema != "gtkg.qk.analysis-candidate/v1"
        || candidate.proofs != proofs
        || plan.schema != "gtkg.qk.analysis-plan/v1"
        || plan.source_ref != *source_ref
        || plan.context != *analysis_context
        || plan.snapshot_id != ledger.snapshot_id
        || analysis_context.snapshot_id != ledger.snapshot_id
        || plan.selection_manifest_sha256 != ledger.selection_manifest.sha256
    {
        return Err("graph candidate/source/context lineage mismatch".into());
    }
    let archive = source_path.parent().ok_or("graph source archive missing")?;
    if source::load_archive(archive).map_err(|e| e.to_string())? != ledger {
        return Err("graph source changed during admission".into());
    }
    let expected: BTreeSet<_> = ledger
        .leaves
        .iter()
        .filter(|l| l.scope == source::Scope::Included && l.main_route == source::MainRoute::Code)
        .map(|l| l.path.as_str())
        .collect();
    if expected != raw_sources.keys().map(String::as_str).collect() {
        return Err("graph raw-source exact set differs from code ledger".into());
    }
    for leaf in ledger
        .leaves
        .iter()
        .filter(|l| expected.contains(l.path.as_str()))
    {
        let sha = leaf
            .object_sha256
            .as_deref()
            .ok_or("graph source object unavailable")?;
        let bytes = source::read_object(archive, sha).map_err(|e| e.to_string())?;
        if raw_sources.get(&leaf.path) != Some(&bytes) {
            return Err("graph replay bytes differ from pinned archive".into());
        }
    }
    let replayed = raw_sources
        .iter()
        .map(|(path, bytes)| {
            gtkg_extract::v04::extract(path, bytes, analysis_context)
                .map(|fact| (path.clone(), fact))
                .map_err(|e| e.to_string())
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    let candidate_facts: BTreeMap<_, _> = candidate
        .facts
        .iter()
        .map(|f| (f.path.clone(), f.clone()))
        .collect();
    if candidate_facts.len() != candidate.facts.len() || candidate_facts != replayed {
        return Err("graph candidate facts differ from source replay".into());
    }
    // This is the independent batch verifier, not a name/span-only admission check.
    confirmed_edges(proofs, raw_sources, analysis_context).map_err(|e| e.to_string())?;
    Ok(ledger)
}

fn projected_links(proofs: &[CallBindingProof]) -> Result<Vec<GraphLink>, String> {
    let mut links = Vec::new();
    for p in proofs.iter().filter(|p| p.proof_status == "confirmed") {
        let t = p.target.as_ref().ok_or("confirmed graph target absent")?;
        let link = GraphLink {
            call_id: p.call.id.clone(),
            source_path: p.source_path.clone(),
            call_span: p.call.span.clone(),
            expression: p.call.expression.clone(),
            target_path: t.path.clone(),
            target_id: t.declaration.id.clone(),
            target_name: t.declaration.name.clone(),
            target_span: t.declaration.span.clone(),
            target_name_span: t.declaration.name_span.clone(),
        };
        validate_link(&link)?;
        links.push(link);
    }
    Ok(links)
}

/// Bind the exact candidate and source lineage before publishing any graph shard.
pub fn build(
    context: &CallContext,
    workspace: &Path,
    source_ref: &FileReceiptRef,
    candidate_ref: &FileReceiptRef,
    proofs: &[CallBindingProof],
    raw_sources: &BTreeMap<String, Vec<u8>>,
    analysis_context: &AnalysisContext,
) -> Result<FileReceiptRef, String> {
    let root = artifact::workspace(context, workspace)?;
    let ledger = replay_bound_inputs(
        context,
        &root,
        source_ref,
        candidate_ref,
        proofs,
        raw_sources,
        analysis_context,
    )?;
    let ctx = context_digest(analysis_context);
    let generation = graph_root(source_ref, candidate_ref, &ctx)?;
    let mut grouped: Vec<Vec<GraphLink>> = vec![vec![]; 256];
    for link in projected_links(proofs)? {
        let bucket = usize::from_str_radix(&super::index::token_bucket(&link.source_path), 16)
            .map_err(|e| e.to_string())?;
        grouped[bucket].push(link);
    }
    let mut router = BTreeMap::new();
    let mut bucket_counts = BTreeMap::new();
    let mut total_bytes = 0u64;
    for (i, mut links) in grouped.into_iter().enumerate() {
        let bucket = format!("{i:02x}");
        links.sort_by(|a, b| {
            (&a.source_path, a.call_span.byte_start, &a.call_id).cmp(&(
                &b.source_path,
                b.call_span.byte_start,
                &b.call_id,
            ))
        });
        bucket_counts.insert(bucket.clone(), links.len());
        if links.is_empty() {
            router.insert(bucket, None);
        } else {
            let shard = GraphShard {
                schema: "gtkg.qk.confirmed-call-shard/v1".into(),
                graph_root: generation.clone(),
                source_ref: source_ref.clone(),
                candidate_ref: candidate_ref.clone(),
                context_digest: ctx.clone(),
                bucket: bucket.clone(),
                links,
            };
            let r = publish(
                context,
                &root,
                &format!("{generation}/calls/{bucket}.json"),
                &shard,
            )?;
            total_bytes += r.bytes;
            router.insert(bucket, Some(r));
        }
    }
    let mut manifest = GraphManifest {
        schema: SCHEMA.into(),
        graph_root: generation.clone(),
        source_ref: source_ref.clone(),
        candidate_ref: candidate_ref.clone(),
        snapshot_id: ledger.snapshot_id,
        source_commit: ledger.source_commit,
        source_tree: ledger.source_tree,
        context_digest: ctx,
        resolver: RESOLVER_PROFILE.into(),
        verifier: VERIFIER_PROFILE.into(),
        total_calls: proofs.len(),
        total_links: proofs
            .iter()
            .filter(|p| p.proof_status == "confirmed")
            .count(),
        total_graph_bytes: total_bytes,
        router,
        bucket_counts,
    };
    for _ in 0..8 {
        let n = total_bytes
            + serde_json::to_vec_pretty(&manifest)
                .map_err(|e| e.to_string())?
                .len() as u64;
        if n == manifest.total_graph_bytes {
            break;
        }
        manifest.total_graph_bytes = n;
    }
    let r = publish(
        context,
        &root,
        &format!("{generation}/manifest.json"),
        &manifest,
    )?;
    Ok(FileReceiptRef {
        path: r.path,
        sha256: r.sha256,
    })
}
fn valid_span(s: &Span) -> bool {
    s.byte_start < s.byte_end && s.line_start > 0 && s.line_start <= s.line_end
}
fn validate_link(l: &GraphLink) -> Result<(), String> {
    relative(&l.source_path)?;
    relative(&l.target_path)?;
    if l.call_id.is_empty()
        || l.target_id.is_empty()
        || l.expression.is_empty()
        || l.target_name.is_empty()
        || !valid_span(&l.call_span)
        || !valid_span(&l.target_span)
        || !valid_span(&l.target_name_span)
        || l.target_span.byte_start > l.target_name_span.byte_start
        || l.target_span.byte_end < l.target_name_span.byte_end
        || l.target_span.line_start > l.target_name_span.line_start
        || l.target_span.line_end < l.target_name_span.line_end
    {
        return Err("invalid graph link identity/span".into());
    }
    Ok(())
}
fn validate_manifest(m: &GraphManifest) -> Result<(), String> {
    m.source_ref.validate().map_err(|e| e.to_string())?;
    m.candidate_ref.validate().map_err(|e| e.to_string())?;
    if m.schema != SCHEMA
        || m.resolver != RESOLVER_PROFILE
        || m.verifier != VERIFIER_PROFILE
        || m.graph_root != graph_root(&m.source_ref, &m.candidate_ref, &m.context_digest)?
        || m.router.len() != 256
        || m.bucket_counts.len() != 256
        || m.total_links > m.total_calls
    {
        return Err("graph manifest identity/denominator invalid".into());
    }
    let mut total = 0usize;
    for i in 0..256 {
        let b = format!("{i:02x}");
        let n = *m.bucket_counts.get(&b).ok_or("graph bucket count absent")?;
        total = total.checked_add(n).ok_or("graph count overflow")?;
        match m.router.get(&b).ok_or("graph routing bucket absent")? {
            Some(r) => {
                FileReceiptRef {
                    path: r.path.clone(),
                    sha256: r.sha256.clone(),
                }
                .validate()
                .map_err(|e| e.to_string())?;
                if n == 0 || r.path != format!("{}/calls/{b}.json", m.graph_root) {
                    return Err("graph routing entry invalid".into());
                }
            }
            None if n == 0 => (),
            None => return Err("graph nonempty routing bucket missing artifact".into()),
        }
    }
    if total != m.total_links {
        return Err("graph link denominator mismatch".into());
    }
    Ok(())
}
/// Reads exactly one manifest and returns actual byte count for budget accounting.
pub fn load_manifest(
    context: &CallContext,
    workspace: &Path,
    graph_ref: &FileReceiptRef,
) -> Result<(GraphManifest, u64), String> {
    graph_ref.validate().map_err(|e| e.to_string())?;
    let root = artifact::workspace(context, workspace)?;
    let raw =
        read_bound_regular_file(context, &root.join(&graph_ref.path)).map_err(|e| e.message)?;
    if raw.sha256 != graph_ref.sha256 {
        return Err("graph manifest digest mismatch".into());
    }
    let m: GraphManifest = serde_json::from_slice(&raw.bytes).map_err(|e| e.to_string())?;
    validate_manifest(&m)?;
    if graph_ref.path != format!("{}/manifest.json", m.graph_root) {
        return Err("graph manifest path differs from identity".into());
    }
    let declared = m
        .router
        .values()
        .flatten()
        .try_fold(raw.bytes.len() as u64, |sum, r| sum.checked_add(r.bytes))
        .ok_or("graph byte denominator overflow")?;
    if declared != m.total_graph_bytes {
        return Err("graph byte denominator differs from root and routed shards".into());
    }
    Ok((m, raw.bytes.len() as u64))
}
/// After a pinned manifest read, only the selected source-path bucket is opened.
pub fn load_related_from_manifest(
    context: &CallContext,
    workspace: &Path,
    m: &GraphManifest,
    source_path: &str,
) -> Result<(Vec<GraphLink>, u64), String> {
    relative(source_path)?;
    let bucket = super::index::token_bucket(source_path);
    let (links, bytes) = load_bucket(context, workspace, m, &bucket)?;
    Ok((
        links
            .into_iter()
            .filter(|l| l.source_path == source_path)
            .collect(),
        bytes,
    ))
}
fn load_bucket(
    context: &CallContext,
    workspace: &Path,
    m: &GraphManifest,
    bucket: &str,
) -> Result<(Vec<GraphLink>, u64), String> {
    validate_manifest(m)?;
    let Some(r) = m.router.get(bucket).ok_or("graph bucket absent")? else {
        return Ok((vec![], 0));
    };
    let root = artifact::workspace(context, workspace)?;
    let raw = read_bound_regular_file(context, &root.join(&r.path)).map_err(|e| e.message)?;
    if raw.sha256 != r.sha256 || raw.bytes.len() as u64 != r.bytes {
        return Err("graph shard digest/length mismatch".into());
    }
    let shard: GraphShard = serde_json::from_slice(&raw.bytes).map_err(|e| e.to_string())?;
    if shard.schema != "gtkg.qk.confirmed-call-shard/v1"
        || shard.graph_root != m.graph_root
        || shard.source_ref != m.source_ref
        || shard.candidate_ref != m.candidate_ref
        || shard.context_digest != m.context_digest
        || shard.bucket != bucket
        || shard.links.len() != m.bucket_counts[bucket]
    {
        return Err("graph shard identity/denominator mismatch".into());
    }
    let mut seen = BTreeSet::new();
    for link in &shard.links {
        validate_link(link)?;
        if super::index::token_bucket(&link.source_path) != bucket || !seen.insert(&link.call_id) {
            return Err("graph link duplicate or wrong routing bucket".into());
        }
    }
    Ok((shard.links, raw.bytes.len() as u64))
}
/// Full artifact verification for build/import/audit, never used by ordinary query.
/// Validates all graph bytes and routing; source semantic replay remains build's contract.
pub fn verify_all(
    context: &CallContext,
    workspace: &Path,
    graph_ref: &FileReceiptRef,
) -> Result<(GraphManifest, Vec<GraphLink>, u64), String> {
    let (manifest, mut bytes) = load_manifest(context, workspace, graph_ref)?;
    let mut links = Vec::new();
    for bucket in manifest.router.keys() {
        let (mut selected, n) = load_bucket(context, workspace, &manifest, bucket)?;
        bytes += n;
        links.append(&mut selected);
    }
    if links.len() != manifest.total_links || bytes != manifest.total_graph_bytes {
        return Err("graph complete artifact denominator mismatch".into());
    }
    Ok((manifest, links, bytes))
}
pub fn load_related(
    context: &CallContext,
    workspace: &Path,
    graph_ref: &FileReceiptRef,
    source_path: &str,
) -> Result<(Vec<GraphLink>, u64), String> {
    let (m, n) = load_manifest(context, workspace, graph_ref)?;
    let (links, k) = load_related_from_manifest(context, workspace, &m, source_path)?;
    Ok((links, n + k))
}

/// Source-semantic admission for index build/import. Unlike ordinary lazy reads,
/// this replays the complete candidate/source proof set and compares every link.
pub fn verify_source_projection(
    context: &CallContext,
    workspace: &Path,
    graph_ref: &FileReceiptRef,
) -> Result<GraphManifest, String> {
    let (manifest, mut actual, _) = verify_all(context, workspace, graph_ref)?;
    let (candidate, _): (AnalysisCandidate, _) =
        artifact::read(context, workspace, &manifest.candidate_ref)?;
    let (plan, _): (AnalysisPlan, _) = artifact::read(context, workspace, &candidate.plan_ref)?;
    let (ledger, path): (source::SourceCoverageLedger, _) =
        artifact::read(context, workspace, &manifest.source_ref)?;
    let archive = path.parent().ok_or("graph admission archive absent")?;
    let raw = super::analysis::raw_code(&ledger, archive)?;
    let checked = replay_bound_inputs(
        context,
        workspace,
        &manifest.source_ref,
        &manifest.candidate_ref,
        &candidate.proofs,
        &raw,
        &plan.context,
    )?;
    let mut expected = projected_links(&candidate.proofs)?;
    expected.sort_by(|a, b| a.call_id.cmp(&b.call_id));
    actual.sort_by(|a, b| a.call_id.cmp(&b.call_id));
    if actual != expected
        || manifest.total_calls != candidate.proofs.len()
        || manifest.total_links != expected.len()
        || manifest.context_digest != context_digest(&plan.context)
        || manifest.snapshot_id != checked.snapshot_id
        || manifest.source_tree != checked.source_tree
        || manifest.source_commit != checked.source_commit
    {
        return Err(
            "graph projection differs from independently replayed candidate/source proofs".into(),
        );
    }
    Ok(manifest)
}
