//! Source-bound selection plans. Code and text routes remain independent.
use super::{
    artifact::{self, QkResult},
    source,
};
use crate::CallContext;
use gtkg_extract::v04::AnalysisContext;
use gtkg_protocol::{
    FileReceiptRef,
    v04::{ArtifactPayload, PROFILE_ID},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnalysisPlan {
    pub schema: String,
    pub profile: String,
    pub source_ref: FileReceiptRef,
    pub snapshot_id: String,
    pub selection_manifest_sha256: String,
    pub context: AnalysisContext,
}
pub fn plan(context: &CallContext, payload: &ArtifactPayload) -> QkResult<Value> {
    let root = artifact::workspace(context, &payload.workspace_root)?;
    let (ledger, path): (source::SourceCoverageLedger, _) =
        artifact::read(context, &root, &payload.artifact_ref)?;
    let archive = path.parent().ok_or("archive parent absent")?;
    let verified = source::load_archive(archive).map_err(|e| e.to_string())?;
    if serde_json::to_value(&ledger).map_err(|e| e.to_string())?
        != serde_json::to_value(&verified).map_err(|e| e.to_string())?
    {
        return Err("source ledger changed during plan".into());
    }
    let selected = ledger
        .leaves
        .iter()
        .filter(|l| l.scope == source::Scope::Included)
        .count();
    let p = AnalysisPlan {
        schema: "gtkg.qk.analysis-plan/v1".into(),
        profile: PROFILE_ID.into(),
        source_ref: payload.artifact_ref.clone(),
        snapshot_id: ledger.snapshot_id.clone(),
        selection_manifest_sha256: ledger.selection_manifest.sha256.clone(),
        context: derive_context(&ledger, archive)?,
    };
    let r = artifact::publish(context, &root, "plans", &p)?;
    Ok(
        json!({"status":"planned","artifact_ref":r,"selected_files":selected,"profile":PROFILE_ID,"source_tree":ledger.source_tree,"empty":selected==0}),
    )
}

use gtkg_extract::v04::{
    ExtractedFile,
    binding::{CallBindingProof, GraphEdge, bind, confirmed_edges},
    extract,
};
use std::collections::BTreeMap;
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteReceipt {
    pub path: String,
    pub route: String,
    pub semantic: String,
    pub reason: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnalysisCandidate {
    pub schema: String,
    pub plan_ref: FileReceiptRef,
    pub facts: Vec<ExtractedFile>,
    pub proofs: Vec<CallBindingProof>,
    pub routes: Vec<RouteReceipt>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedAnalysis {
    pub schema: String,
    pub candidate_ref: FileReceiptRef,
    pub plan_ref: FileReceiptRef,
    pub source_ref: FileReceiptRef,
    pub context: AnalysisContext,
    pub snapshot_id: String,
    pub source_tree: String,
    pub source_commit: String,
    pub edges: Vec<GraphEdge>,
    pub routes: Vec<RouteReceipt>,
    pub total_calls: usize,
    pub confirmed_calls: usize,
    pub index_ref: Option<FileReceiptRef>,
}
fn inputs(
    context: &CallContext,
    root: &std::path::Path,
    reference: &FileReceiptRef,
) -> QkResult<(
    AnalysisPlan,
    source::SourceCoverageLedger,
    std::path::PathBuf,
)> {
    let (p, _): (AnalysisPlan, _) = artifact::read(context, root, reference)?;
    if p.schema != "gtkg.qk.analysis-plan/v1" || p.profile != PROFILE_ID {
        return Err("unsupported plan profile".into());
    }
    let (l, path): (source::SourceCoverageLedger, _) =
        artifact::read(context, root, &p.source_ref)?;
    let archive = path
        .parent()
        .ok_or("source archive parent absent")?
        .to_owned();
    let verified = source::load_archive(&archive).map_err(|e| e.to_string())?;
    if l != verified
        || p.snapshot_id != l.snapshot_id
        || p.context.snapshot_id != p.snapshot_id
        || p.selection_manifest_sha256 != l.selection_manifest.sha256
        || p.context.profile != gtkg_extract::v04::EXTRACTOR_PROFILE
    {
        return Err("plan source/context binding mismatch".into());
    }
    Ok((p, l, archive))
}
pub fn raw_code(
    ledger: &source::SourceCoverageLedger,
    archive: &std::path::Path,
) -> QkResult<BTreeMap<String, Vec<u8>>> {
    let mut raw = BTreeMap::new();
    for l in &ledger.leaves {
        if l.scope == source::Scope::Included && l.main_route == source::MainRoute::Code {
            let sha = l
                .object_sha256
                .as_ref()
                .ok_or_else(|| format!("source_unavailable: {}", l.path))?;
            raw.insert(
                l.path.clone(),
                source::read_object(archive, sha).map_err(|e| e.to_string())?,
            );
        }
    }
    Ok(raw)
}
fn analyze(
    ledger: &source::SourceCoverageLedger,
    raw: &BTreeMap<String, Vec<u8>>,
    ctx: &AnalysisContext,
) -> QkResult<(Vec<ExtractedFile>, Vec<RouteReceipt>)> {
    let mut facts = vec![];
    let mut routes = vec![];
    for l in &ledger.leaves {
        if l.scope != source::Scope::Included {
            continue;
        }
        if l.main_route == source::MainRoute::Code {
            let bytes = raw.get(&l.path).ok_or("missing selected code bytes")?;
            let f = extract(&l.path, bytes, ctx)
                .map_err(|e| format!("analysis failed for {}: {e}", l.path))?;
            routes.push(RouteReceipt {
                path: l.path.clone(),
                route: "code".into(),
                semantic: f.semantic_status.clone(),
                reason: format!(
                    "parse={},variant={}; {}",
                    f.parse_status,
                    f.variant_status,
                    f.limitations.join("; ")
                ),
            });
            facts.push(f);
        } else {
            routes.push(RouteReceipt {
                path: l.path.clone(),
                route: format!("{:?}", l.main_route).to_lowercase(),
                semantic: "not_applicable".into(),
                reason: l.semantic_reason.clone(),
            });
        }
    }
    Ok((facts, routes))
}
pub fn build(context: &CallContext, payload: &ArtifactPayload) -> QkResult<Value> {
    let root = artifact::workspace(context, &payload.workspace_root)?;
    let (p, l, archive) = inputs(context, &root, &payload.artifact_ref)?;
    let raw = raw_code(&l, &archive)?;
    let (facts, routes) = analyze(&l, &raw, &p.context)?;
    let proofs = bind(&facts, &p.context);
    let text_files = routes.iter().filter(|r| r.route == "text").count();
    let code_files = facts.len();
    let total_calls = proofs.len();
    let c = AnalysisCandidate {
        schema: "gtkg.qk.analysis-candidate/v1".into(),
        plan_ref: payload.artifact_ref.clone(),
        facts,
        proofs,
        routes,
    };
    let r = artifact::publish(context, &root, "candidates", &c)?;
    Ok(
        json!({"status":"candidate","artifact_ref":r,"code_files":code_files,"text_files":text_files,"total_calls":total_calls,"semantic_quality":"not_yet_verified"}),
    )
}
pub fn verify(context: &CallContext, payload: &ArtifactPayload) -> QkResult<Value> {
    let root = artifact::workspace(context, &payload.workspace_root)?;
    let (c, _): (AnalysisCandidate, _) = artifact::read(context, &root, &payload.artifact_ref)?;
    if c.schema != "gtkg.qk.analysis-candidate/v1" {
        return Err("unsupported candidate schema".into());
    }
    let (p, l, archive) = inputs(context, &root, &c.plan_ref)?;
    let raw = raw_code(&l, &archive)?;
    let (facts, routes) = analyze(&l, &raw, &p.context)?;
    if c.facts != facts || c.routes != routes {
        return Err("candidate facts/routes differ from exact source replay".into());
    }
    let edges = confirmed_edges(&c.proofs, &raw, &p.context).map_err(|e| e.to_string())?;
    let total = c.proofs.len();
    let confirmed = edges.len();
    let graph_ref = super::graph_projection::build(
        context,
        &root,
        &p.source_ref,
        &payload.artifact_ref,
        &c.proofs,
        &raw,
        &p.context,
    )?;
    let index_ref = super::index::build_with_graph(
        context,
        &root,
        &p.source_ref,
        &facts,
        &p.context,
        Some(&graph_ref),
    )?;
    let v = VerifiedAnalysis {
        schema: "gtkg.qk.analysis-verification/v1".into(),
        candidate_ref: payload.artifact_ref.clone(),
        plan_ref: c.plan_ref,
        source_ref: p.source_ref,
        context: p.context,
        snapshot_id: l.snapshot_id,
        source_tree: l.source_tree,
        source_commit: l.source_commit,
        edges,
        routes,
        total_calls: total,
        confirmed_calls: confirmed,
        index_ref: Some(index_ref.clone()),
    };
    let r = artifact::publish(context, &root, "verified", &v)?;
    Ok(
        json!({"status":"verified_scope","artifact_ref":r,"index_ref":index_ref,"graph_ref":graph_ref,"total_calls":total,"confirmed_calls":confirmed,"unresolved_calls":total-confirmed,"profile":PROFILE_ID,"knowledge_ready":false,"full_corpus_precision_recall":"not_evaluated"}),
    )
}

fn derive_context(
    ledger: &source::SourceCoverageLedger,
    archive: &std::path::Path,
) -> QkResult<AnalysisContext> {
    let mut ctx = AnalysisContext {
        snapshot_id: ledger.snapshot_id.clone(),
        ..Default::default()
    };
    let mut modules = vec![];
    for l in &ledger.leaves {
        if l.scope == source::Scope::Included
            && (l.path == "go.mod" || l.path.ends_with("/go.mod"))
            && let Some(sha) = &l.object_sha256
        {
            let b = source::read_object(archive, sha).map_err(|e| e.to_string())?;
            if let Ok(text) = std::str::from_utf8(&b) {
                for line in text.lines() {
                    let parts: Vec<_> = line.split_whitespace().collect();
                    if parts.len() >= 2 && parts[0] == "module" {
                        let module = parts[1].trim_matches('"');
                        let parent = std::path::Path::new(&l.path)
                            .parent()
                            .and_then(|p| p.to_str())
                            .unwrap_or("");
                        modules.push((parent.to_string(), module.to_string()));
                        break;
                    }
                }
            }
        }
    }
    modules.sort_by(|a, b| b.0.len().cmp(&a.0.len()).then_with(|| a.cmp(b)));
    let mut mappings: BTreeMap<String, std::collections::BTreeSet<String>> = BTreeMap::new();
    for l in &ledger.leaves {
        if l.scope != source::Scope::Included || l.language.as_deref() != Some("go") {
            continue;
        }
        let dir = std::path::Path::new(&l.path)
            .parent()
            .and_then(|p| p.to_str())
            .unwrap_or("");
        if let Some((root, module)) = modules.iter().find(|(root, _)| {
            root.is_empty() || dir == root || dir.starts_with(&format!("{root}/"))
        }) {
            let relative = dir
                .strip_prefix(root)
                .unwrap_or(dir)
                .trim_start_matches('/');
            let import = if relative.is_empty() {
                module.clone()
            } else {
                format!("{module}/{relative}")
            };
            mappings.entry(import).or_default().insert(dir.to_string());
        }
    }
    for (key, dirs) in mappings {
        if dirs.len() == 1
            && let Some(dir) = dirs.into_iter().next()
        {
            ctx.import_modules.insert(key, dir);
        }
    }
    Ok(ctx)
}

/// Revalidate a persisted verification without trusting its status or writing artifacts.
pub type LoadedVerified = (
    VerifiedAnalysis,
    AnalysisCandidate,
    source::SourceCoverageLedger,
    std::path::PathBuf,
    BTreeMap<String, Vec<u8>>,
);
pub fn load_verified(
    context: &CallContext,
    root: &std::path::Path,
    reference: &FileReceiptRef,
) -> QkResult<LoadedVerified> {
    let (v, _): (VerifiedAnalysis, _) = artifact::read(context, root, reference)?;
    let (c, _): (AnalysisCandidate, _) = artifact::read(context, root, &v.candidate_ref)?;
    let (p, l, archive) = inputs(context, root, &c.plan_ref)?;
    let raw = raw_code(&l, &archive)?;
    let (facts, routes) = analyze(&l, &raw, &p.context)?;
    let edges = confirmed_edges(&c.proofs, &raw, &p.context).map_err(|e| e.to_string())?;
    if v.schema != "gtkg.qk.analysis-verification/v1"
        || c.schema != "gtkg.qk.analysis-candidate/v1"
        || c.facts != facts
        || c.routes != routes
        || v.plan_ref != c.plan_ref
        || v.source_ref != p.source_ref
        || v.context != p.context
        || v.snapshot_id != l.snapshot_id
        || v.source_tree != l.source_tree
        || v.source_commit != l.source_commit
        || v.edges != edges
        || v.routes != routes
        || v.total_calls != c.proofs.len()
        || v.confirmed_calls != edges.len()
    {
        return Err("verification/source/facts/edge identity mismatch".into());
    }
    Ok((v, c, l, archive, raw))
}
