//! Deterministic source-bound search. Authority is created only by build/import.
use super::{
    artifact,
    graph_projection::{self, GraphLink},
    index::{self, EvidenceChunk, IndexManifest, Posting, SourceBinding},
};
use crate::{
    CallContext, durable::publish_private_immutable_json, exact_read::read_bound_regular_file,
};
use gtkg_protocol::v04::QueryPayload;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::Sha256;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
    time::Instant,
};
use unicode_normalization::UnicodeNormalization;
#[path = "query_reviewed.rs"]
mod reviewed;
#[path = "query_selective.rs"]
mod selective;
#[path = "query_postings.rs"]
mod source_postings;
const SELECTIVE_POLICY: &str = gtkg_protocol::v04::SELECTIVE_QUERY_POLICY;
const AUTHORITY: &str = ".gtkg/qk/runtime/query-authority.json";
const MAX_CANDIDATES: usize = 2000;
const MAX_POSTINGS: u64 = 100_000;
const MAX_MICROS: u64 = 5_000_000;
const CURSOR_LIMIT: usize = 4 * 1024 * 1024;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Authority {
    schema: String,
    workspace: String,
    key: String,
}
pub(crate) fn authority(
    context: &CallContext,
    workspace: &Path,
) -> Result<([u8; 32], u64), String> {
    let path = workspace.join(AUTHORITY);
    let read = read_bound_regular_file(context, &path).map_err(|e| {
        format!(
            "query authority unavailable; build/import this workspace first: {}",
            e.message
        )
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let meta = fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
        if meta.nlink() != 1 || meta.permissions().mode() & 0o077 != 0 {
            return Err("query authority must be a private single-link regular file".into());
        }
    }
    let a: Authority =
        serde_json::from_slice(&read.bytes).map_err(|_| "invalid query authority")?;
    if a.schema != "gtkg.qk.query-authority/v1" || a.workspace != workspace.to_string_lossy() {
        return Err("query authority belongs to a different workspace".into());
    }
    let bytes = hex::decode(a.key).map_err(|_| "invalid query authority key")?;
    let key = bytes
        .try_into()
        .map_err(|_| "invalid query authority key length")?;
    Ok((key, read.bytes.len() as u64))
}
/// Called exclusively from the authorized index build/import write path.
pub(crate) fn initialize_authority(context: &CallContext, workspace: &Path) -> Result<(), String> {
    if context.effect_policy != crate::EffectPolicy::WorkspaceWrite {
        return Err("query authority initialization requires WorkspaceWrite".into());
    }
    let workspace = artifact::workspace(context, workspace)?;
    let path = workspace.join(AUTHORITY);
    if path.exists() {
        authority(context, &workspace)?;
        return Ok(());
    }
    let mut key = [0u8; 32];
    getrandom::fill(&mut key).map_err(|_| "query authority randomness unavailable")?;
    let a = Authority {
        schema: "gtkg.qk.query-authority/v1".into(),
        workspace: workspace.to_string_lossy().into(),
        key: hex::encode(key),
    };
    match publish_private_immutable_json(context, &path, &a, "qk-query-authority") {
        Ok(_) => Ok(()),
        Err(_) if path.exists() => authority(context, &workspace).map(|_| ()),
        Err(e) => Err(e.to_string()),
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Term {
    term: String,
    tier: u8,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Group {
    signal: String,
    terms: Vec<Term>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    candidate_selection: Option<String>,
    revision: String,
    kind: String,
    initial_subqueries: Vec<Group>,
    expanded_terms: Vec<String>,
    structural_neighbors: bool,
    limitations: Vec<String>,
}
fn han(c: char) -> bool {
    matches!(c as u32,0x3400..=0x4dbf|0x4e00..=0x9fff|0xf900..=0xfaff|0x20000..=0x323af)
}
fn push_group(
    groups: &mut Vec<Group>,
    signals: &mut BTreeSet<String>,
    signal: String,
    terms: Vec<Term>,
) {
    if groups.len() < 4 && !terms.is_empty() && signals.insert(signal.clone()) {
        groups.push(Group { signal, terms })
    }
}
fn plan(query: &str) -> Plan {
    let lower = query.to_lowercase();
    let stop = [
        "a",
        "an",
        "the",
        "is",
        "are",
        "was",
        "where",
        "how",
        "what",
        "which",
        "why",
        "does",
        "do",
        "can",
        "to",
        "of",
        "in",
        "for",
        "with",
        "and",
        "or",
        "it",
        "this",
        "that",
        "implemented",
        "implement",
        "implementation",
        "please",
    ];
    let runs: Vec<&str> = query
        .split(|c: char| {
            !(c.is_alphanumeric()
                || unicode_normalization::char::canonical_combining_class(c) != 0
                || matches!(c, '_' | '.' | ':' | '-'))
        })
        .filter(|s| !s.is_empty())
        .collect();
    let special: Vec<_> = runs
        .iter()
        .copied()
        .filter(|s| s.contains(['_', '.', ':']))
        .collect();
    let structural = [
        "调用",
        "流程",
        "上下游",
        "依赖",
        "调用链",
        "call",
        "flow",
        "dependency",
        "neighbor",
    ]
    .iter()
    .any(|s| lower.contains(s));
    let mut groups = vec![];
    let mut signals = BTreeSet::new();
    let mut expanded = vec![];
    for s in &special {
        let tokens = index::tokenize(s);
        let mut terms = vec![Term {
            term: format!("exact:{s}"),
            tier: 3,
        }];
        if let Some(t) = tokens
            .iter()
            .find(|t| t.starts_with("fold:") && t[5..].contains(['_', '.', ':']))
        {
            terms.push(Term {
                term: t.clone(),
                tier: 2,
            })
        }
        push_group(&mut groups, &mut signals, (*s).into(), terms);
    }
    // Versioned finite vocabulary, no provider rewrite or general-translation claim.
    for (zh, en) in [
        ("会话", "session"),
        ("恢复", "resume"),
        ("重试", "retry"),
        ("消息", "message"),
        ("归档", "archive"),
        ("配置", "config"),
        ("存储", "storage"),
        ("错误", "error"),
        ("认证", "auth"),
        ("权限", "permission"),
    ] {
        if query.contains(zh) {
            expanded.push(en.to_string());
            push_group(
                &mut groups,
                &mut signals,
                zh.into(),
                vec![
                    Term {
                        term: format!("cjk:{zh}"),
                        tier: 2,
                    },
                    Term {
                        term: format!("fold:{en}"),
                        tier: 1,
                    },
                ],
            );
        }
    }
    for s in &runs {
        if special.contains(s)
            || s.chars().any(han)
            || stop.contains(&s.to_lowercase().as_str())
            || s.chars().count() < 2
        {
            continue;
        }
        let ts = index::tokenize(s);
        let mut terms = vec![Term {
            term: format!("exact:{s}"),
            tier: 2,
        }];
        let normalized = format!(
            "fold:{}",
            s.nfc().flat_map(char::to_lowercase).collect::<String>()
        );
        if let Some(t) = ts.iter().find(|t| **t == normalized) {
            terms.push(Term {
                term: t.clone(),
                tier: 1,
            })
        }
        push_group(&mut groups, &mut signals, (*s).into(), terms);
    }
    for s in &special {
        for t in index::tokenize(s).into_iter().filter(|t| {
            t.starts_with("fold:") && !t[5..].contains(['_', '.', ':']) && t[5..].len() > 1
        }) {
            push_group(
                &mut groups,
                &mut signals,
                t[5..].into(),
                vec![Term { term: t, tier: 1 }],
            );
        }
    }
    if groups.is_empty() {
        for t in index::tokenize(query)
            .into_iter()
            .filter(|s| s.starts_with("cjk:") && s[4..].chars().count() == 2)
        {
            push_group(
                &mut groups,
                &mut signals,
                t.clone(),
                vec![Term { term: t, tier: 1 }],
            );
        }
    }
    Plan {
        candidate_selection: None,
        revision: "gtkg.qk.query-plan/v1".into(),
        kind: if !special.is_empty() {
            "qualified_or_error"
        } else if structural {
            "structural"
        } else {
            "natural_or_phrase"
        }
        .into(),
        initial_subqueries: groups,
        expanded_terms: expanded,
        structural_neighbors: structural,
        limitations: vec![
            "finite bilingual vocabulary; lexical evidence does not prove an answer".into(),
            "structural expansion is previous/next chunk only; cross-file calls are not projected"
                .into(),
        ],
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MatchReason {
    term: String,
    tier: u8,
    tf: u32,
    df: usize,
    bm25: f64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Candidate {
    posting: Posting,
    reasons: Vec<MatchReason>,
    score: f64,
    role: Option<String>,
    neighbor_of: Option<String>,
    graph_link: Option<GraphLink>,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
struct Counts {
    posting_ids_observed: u64,
    eligible_ids: u64,
    filtered_ids: u64,
    io: u64,
    postings: u64,
    scored_postings: u64,
    posting_shard_reads: u64,
    graph_shard_reads: u64,
    elapsed_us: u64,
    source_ledger_reads: u64,
    expansions: u32,
    source_object_reads: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    schema: String,
    identity: String,
    plan: Plan,
    terms: Vec<Term>,
    term_index: usize,
    posting_offset: usize,
    candidates: BTreeMap<String, Candidate>,
    considered_ids: BTreeSet<String>,
    evaluated: usize,
    expansion_done: bool,
    ranked: Vec<String>,
    ranking_complete: bool,
    page_offset: usize,
    counts: Counts,
    exhausted: Option<String>,
}
fn identity(workspace: &Path, p: &QueryPayload) -> Result<String, String> {
    Ok(artifact::digest(
        &serde_json::to_vec(&(workspace, &p.index_ref, &p.query, &p.query_policy))
            .map_err(|e| e.to_string())?,
    ))
}
fn encode(s: &State, key: &[u8; 32]) -> Result<String, String> {
    let bytes = serde_json::to_vec(s).map_err(|e| e.to_string())?;
    let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|_| "invalid HMAC key")?;
    mac.update(&bytes);
    let token = format!(
        "{}.{}",
        hex::encode(bytes),
        hex::encode(mac.finalize().into_bytes())
    );
    if token.len() > CURSOR_LIMIT {
        return Err("query continuation exceeds bounded transport size".into());
    }
    Ok(token)
}
fn decode(token: &str, key: &[u8; 32], expected: &str) -> Result<State, String> {
    if token.len() > CURSOR_LIMIT {
        return Err("continuation size invalid".into());
    }
    let (body, sig) = token.split_once('.').ok_or("invalid continuation")?;
    let bytes = hex::decode(body).map_err(|_| "invalid continuation encoding")?;
    let signature = hex::decode(sig).map_err(|_| "invalid continuation signature")?;
    let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|_| "invalid HMAC key")?;
    mac.update(&bytes);
    mac.verify_slice(&signature)
        .map_err(|_| "continuation authentication failed")?;
    let s: State = serde_json::from_slice(&bytes).map_err(|_| "invalid continuation state")?;
    if s.schema != "gtkg.qk.query-cursor/v1" || s.identity != expected {
        return Err("continuation query/policy/index/workspace identity mismatch".into());
    }
    Ok(s)
}
fn time_left(s: &State, start: Instant) -> bool {
    s.counts
        .elapsed_us
        .saturating_add(start.elapsed().as_micros() as u64)
        < MAX_MICROS
}
fn reserve(s: &mut State, bytes: u64, limit: u64, start: Instant) -> bool {
    if !time_left(s, start) {
        s.exhausted = Some("wall_time".into());
        return false;
    }
    if s.counts.io.saturating_add(bytes) > limit {
        s.exhausted = Some("io".into());
        return false;
    }
    s.counts.io += bytes;
    true
}
fn role_weight(role: &str) -> f64 {
    match role {
        "source_code" => 1.05,
        "configuration_or_text" => 1.01,
        _ => 1.0,
    }
}
fn candidate_score(c: &Candidate) -> f64 {
    f64::from(c.reasons.iter().map(|r| r.tier).max().unwrap_or(0)) * 1_000_000.0
        + c.reasons.iter().map(|r| r.bm25).sum::<f64>()
            * role_weight(c.role.as_deref().unwrap_or(""))
}
fn rank(s: &mut State) {
    let mut ids: Vec<_> = s.candidates.keys().cloned().collect();
    ids.sort_by(|a, b| {
        s.candidates[b]
            .score
            .total_cmp(&s.candidates[a].score)
            .then_with(|| a.cmp(b))
    });
    s.ranked = ids;
}
/// Preserve legacy state/score semantics while charging actual selected reads and
/// each admitted typed row, including a failed/exhausted leaf.
fn bounded_postings(
    context: &CallContext,
    workspace: &Path,
    m: &IndexManifest,
    term: &str,
    s: &mut State,
    limit: u64,
    start: Instant,
) -> Result<Option<Vec<Posting>>, String> {
    use super::query_meter::{QueryBudgetLimits, QueryBudgetUsage, QueryMeter};
    let limits = QueryBudgetLimits::for_index(m.total_index_bytes);
    if limits.io_bytes != limit {
        return Err("query posting budget identity mismatch".into());
    }
    let usage = QueryBudgetUsage {
        io_bytes: s.counts.io,
        wall_time_us: s
            .counts
            .elapsed_us
            .saturating_add(start.elapsed().as_micros() as u64),
        posting_rows: s.counts.postings,
        ..Default::default()
    };
    let mut meter = QueryMeter::new(usage, limits);
    let result = source_postings::load(
        context,
        workspace,
        m,
        term,
        &mut meter,
        &mut s.counts.posting_shard_reads,
    );
    let usage = meter.usage();
    s.counts.io = usage.io_bytes;
    s.counts.postings = usage.posting_rows;
    match result {
        Ok(rows) => Ok(Some(rows)),
        Err(e)
            if e.starts_with("E_QUERY_POSTING_BUDGET")
                || e.starts_with("E_QUERY_IO_BUDGET")
                || e.starts_with("E_QUERY_WALL_TIME_BUDGET") =>
        {
            s.exhausted = Some(
                if e.starts_with("E_QUERY_POSTING_BUDGET") {
                    "postings"
                } else if e.starts_with("E_QUERY_IO_BUDGET") {
                    "io"
                } else {
                    "wall_time"
                }
                .into(),
            );
            Ok(None)
        }
        Err(e) => Err(format!(
            "{e}; authenticated_posting_usage={}",
            serde_json::to_string(&usage).map_err(|e| e.to_string())?
        )),
    }
}
fn scan(
    context: &CallContext,
    workspace: &Path,
    reader: &index::QueryIndexReader<'_>,
    s: &mut State,
    limit: u64,
    start: Instant,
) -> Result<(), String> {
    let m = reader.manifest();
    while s.term_index < s.terms.len() {
        let term = s.terms[s.term_index].clone();
        let Some(postings) = bounded_postings(context, workspace, m, &term.term, s, limit, start)?
        else {
            return Ok(());
        };
        let df = postings.len();
        if df > m.total_chunks {
            return Err("posting document frequency exceeds index denominator".into());
        }
        for p in postings.into_iter().skip(s.posting_offset) {
            if !time_left(s, start) {
                s.exhausted = Some("wall_time".into());
                return Ok(());
            }
            if !s.considered_ids.contains(&p.chunk_id) && s.considered_ids.len() >= MAX_CANDIDATES {
                s.exhausted = Some("candidates".into());
                return Ok(());
            }
            s.counts.scored_postings += 1;
            s.considered_ids.insert(p.chunk_id.clone());
            s.posting_offset += 1;
            let avg = (m.total_tokens as f64 / m.total_chunks.max(1) as f64).max(1.0);
            let tf = f64::from(p.term_frequency);
            let idf = (1.0 + (m.total_chunks as f64 - df as f64 + 0.5) / (df as f64 + 0.5)).ln();
            let bm25 = idf * tf * 2.2 / (tf + 1.2 * (0.25 + 0.75 * f64::from(p.tokens) / avg));
            let c = s
                .candidates
                .entry(p.chunk_id.clone())
                .or_insert_with(|| Candidate {
                    posting: p.clone(),
                    reasons: vec![],
                    score: 0.0,
                    role: None,
                    neighbor_of: None,
                    graph_link: None,
                });
            if c.posting.chunk_ref != p.chunk_ref || c.posting.tokens != p.tokens {
                return Err("conflicting candidate identity across postings".into());
            }
            c.reasons.push(MatchReason {
                term: term.term.clone(),
                tier: term.tier,
                tf: p.term_frequency,
                df,
                bm25,
            });
            c.score = candidate_score(c);
        }
        s.term_index += 1;
        s.posting_offset = 0;
    }
    finish_scan(context, workspace, reader, s, limit, start)
}
fn finish_scan(
    context: &CallContext,
    workspace: &Path,
    reader: &index::QueryIndexReader<'_>,
    s: &mut State,
    limit: u64,
    start: Instant,
) -> Result<(), String> {
    let m = reader.manifest();
    let ids: Vec<_> = s.candidates.keys().cloned().collect();
    while s.evaluated < ids.len() {
        let id = &ids[s.evaluated];
        let p = s.candidates[id].posting.clone();
        if !reserve(s, p.chunk_ref.bytes, limit, start) {
            return Ok(());
        }
        let c = reader.load_chunk(&p)?;
        let candidate = s.candidates.get_mut(id).ok_or("candidate lost")?;
        candidate.role = Some(c.role);
        candidate.score = candidate_score(candidate);
        s.evaluated += 1;
    }
    if !s.expansion_done {
        if s.plan.structural_neighbors && !s.candidates.is_empty() {
            rank(s);
            let id = s.ranked[0].clone();
            let p = s.candidates[&id].posting.clone();
            if !reserve(s, p.chunk_ref.bytes, limit, start) {
                return Ok(());
            }
            let seed = reader.load_chunk(&p)?;
            if !expand_graph(context, workspace, reader, s, &seed, limit, start)? {
                return Ok(());
            }
            for neighbor in [seed.previous, seed.next].into_iter().flatten().take(2) {
                if s.counts.expansions >= 2 {
                    break;
                }
                if s.candidates.contains_key(&neighbor) {
                    continue;
                }
                if !s.considered_ids.contains(&neighbor) && s.considered_ids.len() >= MAX_CANDIDATES
                {
                    s.exhausted = Some("candidates".into());
                    return Ok(());
                }
                let r = m
                    .chunk_router
                    .get(&neighbor[..2])
                    .ok_or("neighbor routing bucket missing")?
                    .as_ref()
                    .ok_or("neighbor routing shard missing")?;
                if !reserve(s, r.bytes, limit, start) {
                    return Ok(());
                }
                let (reference, n) = reader.lookup_chunk_ref(&neighbor)?;
                if n != r.bytes {
                    return Err("neighbor router IO identity mismatch".into());
                }
                // The second lookup really re-reads the router. Charge both reads.
                if !reserve(s, reference.bytes + r.bytes, limit, start) {
                    return Ok(());
                }
                let c = reader.load_chunk_by_id(&neighbor)?;
                if c.path != seed.path || c.object_sha != seed.object_sha {
                    return Err("chunk neighbor crosses a source object".into());
                }
                s.counts.expansions += 1;
                s.considered_ids.insert(c.id.clone());
                s.evaluated += 1;
                s.candidates.insert(
                    c.id.clone(),
                    Candidate {
                        posting: Posting {
                            chunk_id: c.id,
                            chunk_ref: reference,
                            term_frequency: 1,
                            tokens: c.tokens,
                        },
                        reasons: vec![],
                        score: 0.5,
                        role: Some(c.role),
                        neighbor_of: Some(id.clone()),
                        graph_link: None,
                    },
                );
            }
        }
        s.expansion_done = true;
    }
    rank(s);
    s.ranking_complete = true;
    Ok(())
}

/// Expand only independently confirmed calls in the leading original chunk.
/// The graph root, selected graph shard, target postings and all inspected chunks
/// share the original query's IO, posting, candidate, time and expansion limits.
fn expand_graph(
    context: &CallContext,
    workspace: &Path,
    reader: &index::QueryIndexReader<'_>,
    s: &mut State,
    seed: &EvidenceChunk,
    limit: u64,
    start: Instant,
) -> Result<bool, String> {
    let m = reader.manifest();
    let Some(reference) = &m.graph_ref else {
        return Ok(true);
    };
    let path = context
        .authorize_read(&workspace.join(&reference.path))
        .map_err(|e| e.to_string())?;
    let expected = fs::metadata(path).map_err(|e| e.to_string())?.len();
    if !reserve(s, expected, limit, start) {
        return Ok(false);
    }
    let (g, n) = graph_projection::load_manifest(context, workspace, reference)?;
    if n != expected {
        return Err("graph root changed length during budgeted read".into());
    }
    if g.source_ref != m.source_ref
        || g.context_digest != m.analysis_context_digest
        || g.snapshot_id != m.snapshot_id
        || g.source_commit != m.source_commit
        || g.source_tree != m.source_tree
    {
        return Err("query graph/index source or context identity mismatch".into());
    }
    let selected = g
        .router
        .get(&index::token_bucket(&seed.path))
        .ok_or("graph source routing bucket absent")?
        .as_ref()
        .map_or(0, |r| r.bytes);
    if !reserve(s, selected, limit, start) {
        return Ok(false);
    }
    let (links, n) =
        graph_projection::load_related_from_manifest(context, workspace, &g, &seed.path)?;
    if n != selected {
        return Err("graph selected shard IO identity mismatch".into());
    }
    if selected > 0 {
        s.counts.graph_shard_reads += 1;
    }
    let mut targets = BTreeSet::new();
    for link in links.into_iter().filter(|l| {
        l.call_span.byte_start >= seed.byte_start
            && l.call_span.byte_start < seed.byte_end
            && l.target_path != seed.path
    }) {
        if s.counts.expansions >= 2 {
            break;
        }
        if !targets.insert((link.target_path.clone(), link.target_id.clone())) {
            continue;
        }
        let term = format!("exact:{}", link.target_name);
        let Some(postings) = bounded_postings(context, workspace, m, &term, s, limit, start)?
        else {
            return Ok(false);
        };
        let mut matched = None;
        for posting in postings {
            if !s.considered_ids.contains(&posting.chunk_id)
                && s.considered_ids.len() >= MAX_CANDIDATES
            {
                s.exhausted = Some("candidates".into());
                return Ok(false);
            }
            s.considered_ids.insert(posting.chunk_id.clone());
            if !reserve(s, posting.chunk_ref.bytes, limit, start) {
                return Ok(false);
            }
            let chunk = reader.load_chunk(&posting)?;
            if chunk.path == link.target_path
                && chunk.byte_start <= link.target_name_span.byte_start
                && chunk.byte_end >= link.target_name_span.byte_end
            {
                // Both the exact target name span and the path are required; a
                // same-name reference/string/method elsewhere cannot substitute.
                let begin = link.target_name_span.byte_start - chunk.byte_start;
                let end = link.target_name_span.byte_end - chunk.byte_start;
                if chunk.text.get(begin..end) != Some(link.target_name.as_str()) {
                    return Err("graph target name span differs from chunk text".into());
                }
                if matched.is_some() {
                    return Err("multiple chunks claim the same graph target name span".into());
                }
                matched = Some((posting, chunk));
            }
        }
        let (posting, chunk) =
            matched.ok_or("confirmed graph target name span is missing from the index")?;
        s.counts.expansions += 1;
        let score = s.candidates[&seed.id].score - (s.counts.expansions as f64) * 0.25;
        if let Some(candidate) = s.candidates.get_mut(&chunk.id) {
            candidate.graph_link = Some(link);
            candidate.neighbor_of = Some(seed.id.clone());
        } else {
            s.evaluated += 1;
            s.candidates.insert(
                chunk.id.clone(),
                Candidate {
                    posting,
                    reasons: vec![],
                    score,
                    role: Some(chunk.role),
                    neighbor_of: Some(seed.id.clone()),
                    graph_link: Some(link),
                },
            );
        }
    }
    Ok(true)
}

/// Canonical decomposition lets a folded/NFC match map back to original UTF-8
/// bytes even when case expansion or composition changes the encoded length.
/// Normalized text is used only for locating a window, never as returned source.
fn folded_anchor(text: &str, term: &str) -> Option<usize> {
    use unicode_normalization::char::{canonical_combining_class, decompose_canonical};
    let mut units: Vec<(char, usize, u8)> = Vec::new();
    for (origin, ch) in text.char_indices() {
        decompose_canonical(ch, |part| {
            for lower in part.to_lowercase() {
                decompose_canonical(lower, |unit| {
                    let class = canonical_combining_class(unit);
                    let mut at = units.len();
                    // Stable canonical ordering stops at the previous starter.
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
    let mut origins = Vec::new();
    for (ch, origin, _) in units {
        folded.push(ch);
        origins.extend((0..ch.len_utf8()).map(|_| origin));
    }
    let needle: String = term.nfd().flat_map(char::to_lowercase).nfd().collect();
    folded
        .find(&needle)
        .and_then(|index| origins.get(index).copied())
}
fn evidence(c: &EvidenceChunk, candidate: &Candidate, tokens: usize) -> (Value, usize, bool) {
    let count = c.text.chars().count();
    let take = count.min(tokens);
    let mut reasons: Vec<_> = candidate.reasons.iter().collect();
    reasons.sort_by_key(|r| std::cmp::Reverse(r.tier));
    let anchor = reasons
        .into_iter()
        .find_map(|r| {
            let (channel, term) = r.term.split_once(':')?;
            c.text.find(term).or_else(|| {
                (channel == "fold")
                    .then(|| folded_anchor(&c.text, term))
                    .flatten()
            })
        })
        .unwrap_or(0);
    let start_char = if take == count {
        0
    } else {
        c.text[..anchor]
            .chars()
            .count()
            .saturating_sub(take / 4)
            .min(count - take)
    };
    let begin = c
        .text
        .char_indices()
        .nth(start_char)
        .map_or(c.text.len(), |(n, _)| n);
    let end = c
        .text
        .char_indices()
        .nth(start_char + take)
        .map_or(c.text.len(), |(n, _)| n);
    let text = &c.text[begin..end];
    let line_start = c.line_start + c.text[..begin].bytes().filter(|b| *b == b'\n').count();
    let line_end = line_start
        + text
            .as_bytes()
            .iter()
            .take(text.len().saturating_sub(1))
            .filter(|b| **b == b'\n')
            .count();
    (
        json!({"id":c.id,"path":c.path,"text":text,"byte_start":c.byte_start+begin,"byte_end":c.byte_start+end,"line_start":line_start,"line_end":line_end,"original_chunk_byte_start":c.byte_start,"original_chunk_byte_end":c.byte_end,"original_chunk_line_end":c.line_end,"file_sha":c.file_sha,"object_sha":c.object_sha,"source_commit":c.source_commit,"source_tree":c.source_tree,"snapshot_id":c.snapshot_id,"role":c.role,"language":c.language,"parent":c.parent,"score":candidate.score,"score_reasons":candidate.reasons,"neighbor_of":candidate.neighbor_of,"graph_relation":candidate.graph_link,"source_span_verified":true,"inference_status":"original_source_only","truncated":take<count}),
        take,
        take < count,
    )
}

// Query-owned source references and consumed counters are sealed in memory.
// The host stages the exact strings; neither query nor pack writes those files.
fn prepare_source_pack(
    workspace: &Path,
    payload: &QueryPayload,
    manifest: &IndexManifest,
    manifest_bytes: u64,
    state: &State,
    evidence: &[Value],
    key: &[u8; 32],
) -> Result<super::context_pack::PackPreparation, String> {
    use super::context_pack::{
        self, PackHitRef, QueryHitsArtifact, QueryPlanArtifact, QuerySourceIdentity,
    };
    use super::query_meter::{QueryBudgetLimits, QueryBudgetUsage};
    let plan = QueryPlanArtifact {
        schema: context_pack::PLAN_SCHEMA.into(),
        original_query: payload.query.clone(),
        query_policy: payload.query_policy.clone(),
        query_identity: state.identity.clone(),
        public_index_ref: payload.index_ref.clone(),
        base_index_ref: payload.index_ref.clone(),
        selected_index_lineage: vec![index::ArtifactRef {
            path: payload.index_ref.path.clone(),
            bytes: manifest_bytes,
            sha256: payload.index_ref.sha256.clone(),
        }],
        total_index_bytes: manifest.total_index_bytes,
        source_identity: QuerySourceIdentity {
            snapshot_id: manifest.snapshot_id.clone(),
            source_commit: manifest.source_commit.clone(),
            source_tree: manifest.source_tree.clone(),
            source_ref: manifest.source_ref.clone(),
        },
        query_plan: serde_json::to_value(&state.plan).map_err(|e| e.to_string())?,
    };
    let selected = evidence
        .iter()
        .map(|hit| {
            let id = hit["id"].as_str().ok_or("query pack evidence ID missing")?;
            let candidate = state
                .candidates
                .get(id)
                .ok_or("query pack candidate missing")?;
            let rank = state
                .ranked
                .iter()
                .position(|candidate| candidate == id)
                .ok_or("query pack rank missing")?;
            Ok(PackHitRef {
                rank: rank as u32,
                posting: candidate.posting.clone(),
                evidence_byte_start: usize::try_from(
                    hit["byte_start"]
                        .as_u64()
                        .ok_or("query pack byte start missing")?,
                )
                .map_err(|_| "query pack span overflow")?,
                evidence_byte_end: usize::try_from(
                    hit["byte_end"]
                        .as_u64()
                        .ok_or("query pack byte end missing")?,
                )
                .map_err(|_| "query pack span overflow")?,
                score: candidate.score,
                score_reasons: serde_json::to_value(&candidate.reasons)
                    .map_err(|e| e.to_string())?,
                neighbor_of: candidate.neighbor_of.clone(),
                graph_relation: candidate.graph_link.clone(),
                summary_context: vec![],
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let hits = QueryHitsArtifact {
        schema: context_pack::HITS_SCHEMA.into(),
        query_identity: state.identity.clone(),
        plan_sha256: String::new(),
        ranking_complete: state.ranking_complete,
        ranking_scope: if state.ranking_complete {
            "all_required_candidates"
        } else {
            "observed_candidates_provisional_scores"
        }
        .into(),
        candidate_ambiguities: state
            .ranked
            .windows(2)
            .filter(|pair| state.candidates[&pair[0]].score == state.candidates[&pair[1]].score)
            .map(|pair| pair.to_vec())
            .collect(),
        hits: selected,
    };
    let usage = QueryBudgetUsage {
        io_bytes: state.counts.io,
        wall_time_us: state.counts.elapsed_us,
        posting_rows: state.counts.postings,
        candidate_count: state.considered_ids.len() as u64,
        initial_subqueries: state.plan.initial_subqueries.len() as u32,
        structural_expansions: state.counts.expansions,
    };
    context_pack::prepare_pack(
        workspace,
        &plan,
        &hits,
        usage,
        QueryBudgetLimits::for_index(manifest.total_index_bytes),
        key,
    )
}
pub fn search(context: &CallContext, payload: &QueryPayload) -> Result<Value, String> {
    if payload.query_policy == super::semantic_projection::QUERY_POLICY {
        return reviewed::search(context, payload);
    }
    let start = Instant::now();
    if payload.query.trim().is_empty()
        || payload.query.len() > 16384
        || !matches!(
            payload.query_policy.as_str(),
            index::QUERY_POLICY | SELECTIVE_POLICY
        )
        || !(1..=1000).contains(&payload.max_results)
        || payload.max_tokens > 8000
    {
        return Err("query policy or bounds invalid".into());
    }
    let workspace = artifact::workspace(context, &payload.workspace_root)?;
    let (reader, manifest_bytes) =
        index::QueryIndexReader::load(context, &workspace, &payload.index_ref)?;
    let m = reader.manifest();
    let selective_policy = payload.query_policy == SELECTIVE_POLICY;
    // v2 changes candidate eligibility, never the immutable token/chunk/posting
    // projection. This is an explicit compatibility pair, not a wildcard join.
    if m.query_policy != payload.query_policy
        && !(m.query_policy == index::QUERY_POLICY && selective_policy)
    {
        return Err("query policy/index mismatch".into());
    }
    let limit = (m.total_index_bytes / 20).min(64 * 1024 * 1024);
    let (key, authority_bytes) = authority(context, &workspace)?;
    let identity = identity(&workspace, payload)?;
    let mut s = if let Some(token) = &payload.continuation {
        decode(token, &key, &identity)?
    } else {
        let mut plan = if selective_policy {
            selective::plan(&payload.query)
        } else {
            plan(&payload.query)
        };
        if m.graph_ref.is_some() {
            plan.limitations
                .retain(|text| !text.contains("cross-file calls are not projected"));
            plan.limitations.push("at most two confirmed-call target/previous/next expansions from the leading evidence chunk".into());
        }
        let mut seen = BTreeSet::new();
        let terms = plan
            .initial_subqueries
            .iter()
            .flat_map(|g| g.terms.iter().cloned())
            .filter(|t| seen.insert(t.term.clone()))
            .collect();
        State {
            schema: "gtkg.qk.query-cursor/v1".into(),
            identity,
            plan,
            terms,
            term_index: 0,
            posting_offset: 0,
            candidates: BTreeMap::new(),
            considered_ids: BTreeSet::new(),
            evaluated: 0,
            expansion_done: false,
            ranked: vec![],
            ranking_complete: false,
            page_offset: 0,
            counts: Counts::default(),
            exhausted: None,
        }
    };
    // The manifest must be read to learn the limit. Mandatory header IO remains
    // visible even when a tiny index cannot pay for its own header; no floor is added.
    s.counts.io = s.counts.io.saturating_add(manifest_bytes + authority_bytes);
    if s.counts.io > limit {
        s.exhausted = Some("io".into())
    }
    if !time_left(&s, start) {
        s.exhausted = Some("wall_time".into())
    }
    if s.exhausted.is_none() && !s.ranking_complete {
        if selective_policy {
            selective::scan(context, &workspace, &reader, &mut s, limit, start)?;
        } else {
            scan(context, &workspace, &reader, &mut s, limit, start)?;
        }
    }
    let mut results = vec![];
    let mut used_tokens = 0usize;
    let mut token_truncated = false;
    let max_tokens = if payload.max_tokens == 0 {
        8000
    } else {
        payload.max_tokens as usize
    };
    let mut binding: Option<SourceBinding> = None;
    // Posting/candidate exhaustion closes discovery, not the remaining IO/time
    // allowance for already observed source evidence. Its ordering is explicitly
    // provisional; continuation never restarts discovery or refreshes a budget.
    let partial_evidence = matches!(s.exhausted.as_deref(), Some("postings" | "candidates"));
    if partial_evidence && s.ranked.is_empty() {
        rank(&mut s);
    }
    if (s.ranking_complete && s.exhausted.is_none()) || partial_evidence {
        while s.page_offset < s.ranked.len()
            && results.len() < payload.max_results as usize
            && used_tokens < max_tokens
        {
            let id = s.ranked[s.page_offset].clone();
            let candidate = s.candidates[&id].clone();
            if !reserve(&mut s, candidate.posting.chunk_ref.bytes, limit, start) {
                break;
            }
            let chunk = reader.load_chunk(&candidate.posting)?;
            if binding.is_none() {
                let source_path = context
                    .authorize_read(&workspace.join(&m.source_ref.path))
                    .map_err(|e| e.to_string())?;
                let expected = fs::metadata(source_path).map_err(|e| e.to_string())?.len();
                if !reserve(&mut s, expected, limit, start) {
                    break;
                }
                let (b, actual) = reader.load_source_binding()?;
                if actual != expected {
                    return Err("source ledger changed length during budgeted read".into());
                }
                s.counts.source_ledger_reads += 1;
                binding = Some(b);
            }
            if !reserve(&mut s, chunk.object_bytes, limit, start) {
                break;
            }
            let actual = reader.validate_chunk_source_with_binding(
                &chunk,
                binding.as_ref().ok_or("source binding absent")?,
            )?;
            if actual != chunk.object_bytes {
                return Err("source object IO identity mismatch".into());
            }
            s.counts.source_object_reads += 1;
            let (hit, n, truncated) = evidence(&chunk, &candidate, max_tokens - used_tokens);
            results.push(hit);
            used_tokens += n;
            token_truncated |= truncated;
            s.page_offset += 1;
        }
    }
    if !time_left(&s, start) {
        s.exhausted = Some("wall_time".into())
    }
    s.counts.elapsed_us = s
        .counts
        .elapsed_us
        .saturating_add(start.elapsed().as_micros() as u64);
    let remaining = !s.ranking_complete || s.page_offset < s.ranked.len();
    token_truncated |= used_tokens == max_tokens && s.page_offset < s.ranked.len();
    let continuation = if remaining {
        Some(encode(&s, &key)?)
    } else {
        None
    };
    let ambiguity: Vec<_> = s
        .ranked
        .windows(2)
        .filter(|pair| s.candidates[&pair[0]].score == s.candidates[&pair[1]].score)
        .map(|pair| json!({"kind":"candidate_ambiguity","ids":pair}))
        .collect();
    let budget_exhausted = s.exhausted.is_some();
    let answerability = if budget_exhausted {
        "budget_exhausted"
    } else if results.is_empty() && !s.terms.is_empty() {
        "no_match_within_declared_scope"
    } else {
        "unresolved"
    };
    let pack_preparation =
        prepare_source_pack(&workspace, payload, m, manifest_bytes, &s, &results, &key)?;
    let mut response = json!({"schema":"gtkg.qk.query-context-receipt/v1","status":if budget_exhausted{"partial"}else{"complete"},"original_query":payload.query,"query_policy":payload.query_policy,"index_projection_policy":m.query_policy,"query_plan":s.plan,"index_ref":payload.index_ref,"source_identity":{"snapshot_id":m.snapshot_id,"source_commit":m.source_commit,"source_tree":m.source_tree,"source_ref":m.source_ref},"evidence":results,"answerability":answerability,"ranking_complete":s.ranking_complete,"ranking_scope":if s.ranking_complete {"all_required_candidates"} else {"observed_candidates_provisional_scores"},"candidate_ambiguities":ambiguity,"source_fallback":false,"scope_limitations":["only index-declared archived source and selected lexical routes were queried","zero hits do not establish absence from full source or correctness of an answer","unread artifacts are not verified in this query"],"scanned":{"posting_ids_observed":s.counts.posting_ids_observed,"eligible_ids":s.counts.eligible_ids,"filtered_ids":s.counts.filtered_ids,"term_count":s.term_index,"required_terms":s.terms.len(),"current_posting_offset":s.posting_offset,"postings":s.counts.postings,"postings_scored":s.counts.scored_postings,"candidates":s.considered_ids.len(),"ranked_candidates":s.candidates.len(),"evaluated_candidates":s.evaluated},"budget":{"io_bytes":s.counts.io,"io_limit":limit,"manifest_bytes_this_call":manifest_bytes,"authority_bytes_this_call":authority_bytes,"mandatory_header_overrun":s.counts.io>limit,"posting_limit":MAX_POSTINGS,"candidate_limit":MAX_CANDIDATES,"wall_time_us":s.counts.elapsed_us,"wall_time_limit_us":MAX_MICROS,"evidence_tokens":used_tokens,"evidence_token_limit":max_tokens,"structural_expansions":s.counts.expansions,"structural_expansion_limit":2},"verification_scope":{"manifest":"digest_verified","selected_shards":if s.counts.posting_shard_reads>0 {"read_shards_digest_verified"}else{"not_read"},"posting_shard_reads":s.counts.posting_shard_reads,"graph_shard_reads":s.counts.graph_shard_reads,"source_ledger_reads":s.counts.source_ledger_reads,"source_object_reads":s.counts.source_object_reads,"unread_objects":"not_checked","full_graph_reads":0},"truncation":{"budget":budget_exhausted,"reason":s.exhausted,"tokens":token_truncated,"pagination":remaining},"continuation":continuation,"continuation_scope":"same_workspace_durable_authority","continuation_budget":"cumulative; exhausted budgets are not reset by continuation","ranking_formula":{"identity":payload.query_policy,"formula":"match_tier*1000000 + sum(BM25)*source_role_weight","k1":1.2,"b":0.75,"tie_break":"chunk_id","path_weight":0,"structural_rule":"confirmed target score is seed score minus 0.25 per structural expansion"},"target_execution":false});
    response["pack_preparation"] =
        serde_json::to_value(pack_preparation).map_err(|e| e.to_string())?;
    Ok(response)
}
