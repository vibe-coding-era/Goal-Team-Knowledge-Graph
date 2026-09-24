//! Explicit reviewed-context query policy; shared budgets and source-bound evidence.
use super::super::{
    context_pack as pack,
    query_meter::{QueryBudgetLimits, QueryBudgetUsage, QueryMeter},
    semantic_projection as semantic, source,
    source_context::ReviewedSummaryContext,
};
use super::*;
use gtkg_protocol::FileReceiptRef;
use index::ArtifactRef;

const CURSOR_DOMAIN: &[u8] = b"gtkg.qk.reviewed-query-cursor/v1\0";
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReviewedReason {
    term: String,
    tier: u8,
    tf: u32,
    df: usize,
    bm25: f64,
    context_id: String,
    context_ref: ArtifactRef,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReviewedCandidate {
    posting: Posting,
    source_reasons: Vec<MatchReason>,
    reviewed_reasons: Vec<ReviewedReason>,
    score: f64,
    role: Option<String>,
    neighbor_of: Option<String>,
    graph_link: Option<GraphLink>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReviewedState {
    schema: String,
    identity: String,
    plan: Plan,
    candidates: BTreeMap<String, ReviewedCandidate>,
    admitted_ids: BTreeSet<String>,
    ranked: Vec<String>,
    page_offset: usize,
    discovered: bool,
    ranking_complete: bool,
    usage: QueryBudgetUsage,
    exhausted: Option<String>,
    source_postings: u64,
    reviewed_postings: u64,
    observed_ids: usize,
    eligible_ids: usize,
    structural_expansions: u32,
}
fn is_budget(error: &str) -> bool {
    error.starts_with("E_QUERY_") || error == "E_POSTING_BUDGET"
}
fn cursor(s: &ReviewedState, key: &[u8; 32]) -> Result<String, String> {
    let bytes = serde_json::to_vec(s).map_err(|e| e.to_string())?;
    let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|_| "invalid cursor key")?;
    mac.update(CURSOR_DOMAIN);
    mac.update(&bytes);
    let value = format!(
        "{}.{}",
        hex::encode(bytes),
        hex::encode(mac.finalize().into_bytes())
    );
    if value.len() > CURSOR_LIMIT {
        return Err("reviewed query cursor exceeds bounded transport size".into());
    }
    Ok(value)
}
fn resume(token: &str, key: &[u8; 32], identity: &str) -> Result<ReviewedState, String> {
    if token.len() > CURSOR_LIMIT {
        return Err("reviewed cursor exceeds size bound".into());
    }
    let (body, signature) = token.split_once('.').ok_or("invalid reviewed cursor")?;
    let bytes = hex::decode(body).map_err(|_| "invalid reviewed cursor encoding")?;
    let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|_| "invalid cursor key")?;
    mac.update(CURSOR_DOMAIN);
    mac.update(&bytes);
    mac.verify_slice(&hex::decode(signature).map_err(|_| "invalid cursor signature")?)
        .map_err(|_| "reviewed cursor authentication failed")?;
    let s: ReviewedState = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    if s.schema != "gtkg.qk.reviewed-query-cursor/v1"
        || s.identity != identity
        || s.admitted_ids.len() > MAX_CANDIDATES
        || s.candidates.len() > MAX_CANDIDATES
        || s.page_offset > s.ranked.len()
    {
        return Err("reviewed cursor identity/bounds mismatch".into());
    }
    Ok(s)
}
fn source_postings(
    context: &CallContext,
    root: &Path,
    m: &IndexManifest,
    term: &str,
    meter: &mut QueryMeter,
) -> Result<Vec<Posting>, String> {
    super::source_postings::load(context, root, m, term, meter, &mut 0)
}
fn bm25(n: usize, df: usize, tf: u32, units: u32, average: f64) -> f64 {
    let idf = (1.0 + (n as f64 - df as f64 + 0.5) / (df as f64 + 0.5)).ln();
    idf * f64::from(tf) * 2.2
        / (f64::from(tf) + 1.2 * (0.25 + 0.75 * f64::from(units) / average.max(1.0)))
}
fn score(c: &ReviewedCandidate) -> f64 {
    let source = c
        .source_reasons
        .iter()
        .map(|r| r.tier)
        .max()
        .map_or(0.0, |tier| {
            f64::from(tier) * 1_000_000.0
                + c.source_reasons.iter().map(|r| r.bm25).sum::<f64>()
                    * role_weight(c.role.as_deref().unwrap_or(""))
        });
    let reviewed = c
        .reviewed_reasons
        .iter()
        .map(|r| r.tier)
        .max()
        .map_or(0.0, |tier| {
            f64::from(tier) * 1_000_000.0 + c.reviewed_reasons.iter().map(|r| r.bm25).sum::<f64>()
        });
    source + reviewed
}
fn ordered(s: &mut ReviewedState) {
    s.ranked = s.candidates.keys().cloned().collect();
    s.ranked.sort_by(|a, b| {
        s.candidates[b]
            .score
            .total_cmp(&s.candidates[a].score)
            .then_with(|| a.cmp(b))
    });
}
fn terms(p: &Plan) -> Vec<Term> {
    let mut seen = BTreeSet::new();
    p.initial_subqueries
        .iter()
        .flat_map(|g| g.terms.clone())
        .filter(|t| seen.insert(t.term.clone()))
        .collect()
}
fn collect(
    context: &CallContext,
    root: &Path,
    loaded: &semantic::LoadedOverlay,
    s: &mut ReviewedState,
    meter: &mut QueryMeter,
) -> Result<(), String> {
    let mut by_source = BTreeMap::new();
    let mut by_context = BTreeMap::new();
    let mut observed = BTreeSet::new();
    let selected_terms = terms(&s.plan);
    for term in &selected_terms {
        let before = meter.usage().posting_rows;
        let rows = source_postings(context, root, &loaded.base, &term.term, meter);
        s.source_postings += meter.usage().posting_rows.saturating_sub(before);
        let rows = rows?;
        observed.extend(rows.iter().map(|r| r.chunk_id.clone()));
        s.observed_ids = observed.len();
        by_source.insert(term.term.clone(), rows);
        let before = meter.usage().posting_rows;
        let rows = semantic::load_selected_postings(context, root, loaded, &term.term, meter);
        s.reviewed_postings += meter.usage().posting_rows.saturating_sub(before);
        let rows = rows?;
        observed.extend(rows.iter().map(|r| r.chunk_id.clone()));
        s.observed_ids = observed.len();
        by_context.insert(term.term.clone(), rows);
    }
    s.observed_ids = observed.len();
    let mut eligible: Option<BTreeSet<String>> = None;
    for group in &s.plan.initial_subqueries {
        let ids: BTreeSet<_> = group
            .terms
            .iter()
            .flat_map(|t| {
                by_source
                    .get(&t.term)
                    .into_iter()
                    .flatten()
                    .map(|p| p.chunk_id.clone())
                    .chain(
                        by_context
                            .get(&t.term)
                            .into_iter()
                            .flatten()
                            .map(|p| p.chunk_id.clone()),
                    )
            })
            .collect();
        eligible = Some(match eligible {
            None => ids,
            Some(previous) => previous.intersection(&ids).cloned().collect(),
        });
    }
    let intersection = eligible.unwrap_or_default();
    let eligible = if intersection.is_empty() {
        s.plan.candidate_selection = Some("source_and_reviewed_union_fallback".into());
        observed
    } else {
        s.plan.candidate_selection = Some("source_and_reviewed_all_signal_groups".into());
        intersection
    };
    s.eligible_ids = eligible.len();
    s.admitted_ids = eligible.iter().take(MAX_CANDIDATES).cloned().collect();
    for term in &selected_terms {
        let source = &by_source[&term.term];
        let df = source.len();
        let avg = loaded.base.total_tokens as f64 / loaded.base.total_chunks.max(1) as f64;
        for p in source
            .iter()
            .filter(|p| s.admitted_ids.contains(&p.chunk_id))
        {
            let c = s
                .candidates
                .entry(p.chunk_id.clone())
                .or_insert_with(|| ReviewedCandidate {
                    posting: p.clone(),
                    source_reasons: vec![],
                    reviewed_reasons: vec![],
                    score: 0.0,
                    role: None,
                    neighbor_of: None,
                    graph_link: None,
                });
            if c.posting.chunk_ref != p.chunk_ref
                || (c.posting.tokens != 0 && c.posting.tokens != p.tokens)
            {
                return Err("source and semantic candidate identities disagree".into());
            }
            c.posting.tokens = p.tokens;
            c.source_reasons.push(MatchReason {
                term: term.term.clone(),
                tier: term.tier,
                tf: p.term_frequency,
                df,
                bm25: bm25(
                    loaded.base.total_chunks,
                    df,
                    p.term_frequency,
                    p.tokens,
                    avg,
                ),
            });
        }
        let semantic = &by_context[&term.term];
        let df = semantic
            .iter()
            .map(|r| &r.context_id)
            .collect::<BTreeSet<_>>()
            .len();
        if df as u64 > loaded.catalog.total_contexts {
            return Err("reviewed df exceeds context denominator".into());
        }
        let avg = loaded.catalog.total_context_tokens as f64
            / loaded.catalog.total_contexts.max(1) as f64;
        let mut best: BTreeMap<String, ReviewedReason> = BTreeMap::new();
        for p in semantic
            .iter()
            .filter(|p| s.admitted_ids.contains(&p.chunk_id))
        {
            let reason = ReviewedReason {
                term: term.term.clone(),
                tier: term.tier,
                tf: p.term_frequency,
                df,
                bm25: bm25(
                    loaded.catalog.total_contexts as usize,
                    df,
                    p.term_frequency,
                    p.context_tokens,
                    avg,
                ),
                context_id: p.context_id.clone(),
                context_ref: p.context_ref.clone(),
            };
            let replace = best.get(&p.chunk_id).is_none_or(|prior| {
                reason.bm25 > prior.bm25
                    || (reason.bm25 == prior.bm25 && reason.context_id < prior.context_id)
            });
            if replace {
                best.insert(p.chunk_id.clone(), reason);
            }
            let c = s
                .candidates
                .entry(p.chunk_id.clone())
                .or_insert_with(|| ReviewedCandidate {
                    posting: Posting {
                        chunk_id: p.chunk_id.clone(),
                        chunk_ref: p.chunk_ref.clone(),
                        term_frequency: 1,
                        tokens: 0,
                    },
                    source_reasons: vec![],
                    reviewed_reasons: vec![],
                    score: 0.0,
                    role: None,
                    neighbor_of: None,
                    graph_link: None,
                });
            if c.posting.chunk_ref != p.chunk_ref {
                return Err("reviewed/source posting chunk identity collision".into());
            }
        }
        for (id, reason) in best {
            s.candidates
                .get_mut(&id)
                .ok_or("candidate lost")?
                .reviewed_reasons
                .push(reason);
        }
    }
    for c in s.candidates.values_mut() {
        c.score = score(c);
    }
    s.discovered = true;
    if eligible.len() > MAX_CANDIDATES {
        s.exhausted = Some("E_QUERY_CANDIDATE_BUDGET".into());
    }
    Ok(())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChunkRouter {
    schema: String,
    snapshot_id: String,
    index_root: String,
    bucket: String,
    chunks: BTreeMap<String, ArtifactRef>,
}
fn chunk_by_ref(
    context: &CallContext,
    root: &Path,
    m: &IndexManifest,
    p: &Posting,
    meter: &mut QueryMeter,
) -> Result<EvidenceChunk, String> {
    let c: EvidenceChunk = meter.read_artifact(context, root, &p.chunk_ref)?;
    index::validate_chunk(m, &c)?;
    if c.id != p.chunk_id
        || (p.tokens != 0 && p.tokens != c.tokens)
        || p.chunk_ref.path != format!("{}/chunks/{}.json", m.index_root, c.id)
    {
        return Err("selected chunk identity mismatch".into());
    }
    Ok(c)
}
fn chunk_by_id(
    context: &CallContext,
    root: &Path,
    m: &IndexManifest,
    id: &str,
    meter: &mut QueryMeter,
) -> Result<(Posting, EvidenceChunk), String> {
    if id.len() != 64 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("invalid neighbor chunk id".into());
    }
    let bucket = &id[..2];
    let reference = m
        .chunk_router
        .get(bucket)
        .ok_or("neighbor router missing")?
        .as_ref()
        .ok_or("neighbor shard absent")?;
    let shard: ChunkRouter = meter.read_artifact(context, root, reference)?;
    if shard.schema != "gtkg.qk.chunk-router-shard/v1"
        || shard.snapshot_id != m.snapshot_id
        || shard.index_root != m.index_root
        || shard.bucket != bucket
    {
        return Err("neighbor chunk router identity mismatch".into());
    }
    let r = shard.chunks.get(id).ok_or("neighbor chunk absent")?;
    let mut p = Posting {
        chunk_id: id.into(),
        chunk_ref: r.clone(),
        term_frequency: 1,
        tokens: 0,
    };
    let c = chunk_by_ref(context, root, m, &p, meter)?;
    p.tokens = c.tokens;
    Ok((p, c))
}
fn evaluate(
    context: &CallContext,
    root: &Path,
    loaded: &semantic::LoadedOverlay,
    s: &mut ReviewedState,
    meter: &mut QueryMeter,
    cache: &mut BTreeMap<String, EvidenceChunk>,
) -> Result<(), String> {
    for (id, candidate) in &mut s.candidates {
        meter.check_time()?;
        let chunk = chunk_by_ref(context, root, &loaded.base, &candidate.posting, meter)?;
        candidate.posting.tokens = chunk.tokens;
        candidate.role = Some(chunk.role.clone());
        if !candidate.source_reasons.is_empty() || !candidate.reviewed_reasons.is_empty() {
            candidate.score = score(candidate);
        }
        cache.insert(id.clone(), chunk);
    }
    ordered(s);
    if s.exhausted.is_none() {
        expand(context, root, loaded, s, meter, cache)?;
    }
    ordered(s);
    s.ranking_complete = s.exhausted.is_none();
    Ok(())
}
fn expand(
    context: &CallContext,
    root: &Path,
    loaded: &semantic::LoadedOverlay,
    s: &mut ReviewedState,
    meter: &mut QueryMeter,
    cache: &mut BTreeMap<String, EvidenceChunk>,
) -> Result<(), String> {
    if !s.plan.structural_neighbors || s.ranked.is_empty() {
        return Ok(());
    }
    let seed_id = s.ranked[0].clone();
    let seed = cache.get(&seed_id).ok_or("expansion seed missing")?.clone();
    expand_calls(context, root, loaded, s, meter, cache, &seed)?;
    for id in [seed.previous, seed.next].into_iter().flatten() {
        if s.structural_expansions >= 2 {
            break;
        }
        if s.candidates.contains_key(&id) {
            continue;
        }
        if s.admitted_ids.len() >= MAX_CANDIDATES {
            return Err("E_QUERY_CANDIDATE_BUDGET".into());
        }
        s.admitted_ids.insert(id.clone());
        let (posting, c) = chunk_by_id(context, root, &loaded.base, &id, meter)?;
        if c.path != seed.path || c.object_sha != seed.object_sha {
            return Err("neighbor crosses source object".into());
        }
        s.structural_expansions += 1;
        let candidate = ReviewedCandidate {
            posting,
            source_reasons: vec![],
            reviewed_reasons: vec![],
            score: s.candidates[&seed_id].score - 0.25 * f64::from(s.structural_expansions),
            role: Some(c.role.clone()),
            neighbor_of: Some(seed_id.clone()),
            graph_link: None,
        };
        cache.insert(id.clone(), c);
        s.candidates.insert(id, candidate);
    }
    Ok(())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CallShard {
    schema: String,
    graph_root: String,
    source_ref: FileReceiptRef,
    candidate_ref: FileReceiptRef,
    context_digest: String,
    bucket: String,
    links: Vec<GraphLink>,
}
fn expand_calls(
    context: &CallContext,
    root: &Path,
    loaded: &semantic::LoadedOverlay,
    s: &mut ReviewedState,
    meter: &mut QueryMeter,
    cache: &mut BTreeMap<String, EvidenceChunk>,
    seed: &EvidenceChunk,
) -> Result<(), String> {
    let Some(reference) = &loaded.base.graph_ref else {
        return Ok(());
    };
    let graph: graph_projection::GraphManifest =
        meter.read_reference(context, root, reference, 64 * 1024 * 1024)?;
    if graph.schema != "gtkg.qk.confirmed-call-graph/v1"
        || graph.source_ref != loaded.base.source_ref
        || graph.context_digest != loaded.base.analysis_context_digest
        || graph.snapshot_id != loaded.base.snapshot_id
        || graph.source_commit != loaded.base.source_commit
        || graph.source_tree != loaded.base.source_tree
        || graph.router.len() != 256
        || graph.bucket_counts.len() != 256
        || graph.resolver != gtkg_extract::v04::binding::RESOLVER_PROFILE
        || graph.verifier != gtkg_extract::v04::binding::VERIFIER_PROFILE
    {
        return Err("reviewed query graph/source identity mismatch".into());
    }
    let bucket = index::token_bucket(&seed.path);
    let Some(reference) = graph.router.get(&bucket).ok_or("graph route absent")? else {
        return Ok(());
    };
    if reference.path != format!("{}/calls/{bucket}.json", graph.graph_root) {
        return Err("selected graph shard path mismatch".into());
    }
    let shard: CallShard = meter.read_artifact(context, root, reference)?;
    if shard.schema != "gtkg.qk.confirmed-call-shard/v1"
        || shard.graph_root != graph.graph_root
        || shard.source_ref != graph.source_ref
        || shard.candidate_ref != graph.candidate_ref
        || shard.context_digest != graph.context_digest
        || shard.bucket != bucket
        || Some(&shard.links.len()) != graph.bucket_counts.get(&bucket)
    {
        return Err("selected graph shard identity/count mismatch".into());
    }
    let mut call_ids = BTreeSet::new();
    for link in &shard.links {
        if !call_ids.insert(&link.call_id) || index::token_bucket(&link.source_path) != bucket {
            return Err("selected graph link duplicate/wrong bucket".into());
        }
    }
    let mut targets = BTreeSet::new();
    for link in shard.links.into_iter().filter(|link| {
        link.source_path == seed.path
            && link.call_span.byte_start >= seed.byte_start
            && link.call_span.byte_start < seed.byte_end
            && link.target_path != seed.path
    }) {
        meter.check_time()?;
        if s.structural_expansions >= 2 {
            break;
        }
        if !targets.insert((link.target_path.clone(), link.target_id.clone())) {
            continue;
        }
        let before = meter.usage().posting_rows;
        let candidates = source_postings(
            context,
            root,
            &loaded.base,
            &format!("exact:{}", link.target_name),
            meter,
        );
        s.source_postings += meter.usage().posting_rows.saturating_sub(before);
        let mut matched = None;
        for posting in candidates? {
            if !s.admitted_ids.contains(&posting.chunk_id) && s.admitted_ids.len() >= MAX_CANDIDATES
            {
                return Err("E_QUERY_CANDIDATE_BUDGET".into());
            }
            s.admitted_ids.insert(posting.chunk_id.clone());
            let chunk = match cache.get(&posting.chunk_id) {
                Some(c) => c.clone(),
                None => chunk_by_ref(context, root, &loaded.base, &posting, meter)?,
            };
            if chunk.path == link.target_path
                && chunk.byte_start <= link.target_name_span.byte_start
                && chunk.byte_end >= link.target_name_span.byte_end
            {
                let begin = link.target_name_span.byte_start - chunk.byte_start;
                let end = link.target_name_span.byte_end - chunk.byte_start;
                if chunk.text.get(begin..end) != Some(link.target_name.as_str()) {
                    return Err("graph target name differs from original chunk span".into());
                }
                if matched.is_some() {
                    return Err("multiple chunks claim one graph target name span".into());
                }
                matched = Some((posting, chunk));
            }
        }
        let (posting, chunk) = matched.ok_or("confirmed graph target absent from source index")?;
        s.structural_expansions += 1;
        let new_score = s.candidates[&seed.id].score - 0.25 * f64::from(s.structural_expansions);
        if let Some(candidate) = s.candidates.get_mut(&chunk.id) {
            candidate.graph_link = Some(link);
            candidate.neighbor_of = Some(seed.id.clone());
        } else {
            s.candidates.insert(
                chunk.id.clone(),
                ReviewedCandidate {
                    posting,
                    source_reasons: vec![],
                    reviewed_reasons: vec![],
                    score: new_score,
                    role: Some(chunk.role.clone()),
                    neighbor_of: Some(seed.id.clone()),
                    graph_link: Some(link),
                },
            );
        }
        cache.insert(chunk.id.clone(), chunk);
    }
    Ok(())
}
fn source_binding(
    context: &CallContext,
    root: &Path,
    m: &IndexManifest,
    meter: &mut QueryMeter,
) -> Result<source::SourceCoverageLedger, String> {
    let ledger: source::SourceCoverageLedger =
        meter.read_reference(context, root, &m.source_ref, 64 * 1024 * 1024)?;
    if ledger.schema_version != "gtkg.qk.source-coverage-ledger/v1"
        || ledger.snapshot_id != m.snapshot_id
        || ledger.source_commit != m.source_commit
        || ledger.source_tree != m.source_tree
    {
        return Err("source ledger differs from semantic/base identity".into());
    }
    let mut paths = BTreeSet::new();
    for leaf in &ledger.leaves {
        if !paths.insert(&leaf.path) {
            return Err("duplicate source ledger path".into());
        }
    }
    Ok(ledger)
}
fn verify_source(
    context: &CallContext,
    root: &Path,
    m: &IndexManifest,
    c: &EvidenceChunk,
    ledger: &source::SourceCoverageLedger,
    meter: &mut QueryMeter,
) -> Result<(), String> {
    let leaf = ledger
        .leaves
        .iter()
        .find(|l| l.path == c.path)
        .ok_or("selected source path absent")?;
    if leaf.scope != source::Scope::Included
        || leaf.text != source::TextStatus::Extracted
        || leaf.content_sha256.as_deref() != Some(c.file_sha.as_str())
        || leaf.object_sha256.as_deref() != Some(c.object_sha.as_str())
        || leaf.byte_len != c.object_bytes
    {
        return Err("selected chunk not bound to archived source leaf".into());
    }
    let bytes = meter.read(
        context,
        &root
            .join(&m.archive_root)
            .join("objects")
            .join(&c.object_sha),
        c.object_bytes,
    )?;
    if bytes.len() as u64 != c.object_bytes
        || artifact::digest(&bytes) != format!("sha256:{}", c.object_sha)
        || bytes.get(c.byte_start..c.byte_end) != Some(c.text.as_bytes())
    {
        return Err("selected original source span differs from chunk".into());
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| "source object is not UTF8")?;
    if !text.is_char_boundary(c.byte_start)
        || !text.is_char_boundary(c.byte_end)
        || line(text, c.byte_start) != c.line_start
        || line(text, c.byte_end - 1) != c.line_end
    {
        return Err("selected source line mapping mismatch".into());
    }
    Ok(())
}
fn line(text: &str, at: usize) -> usize {
    text.as_bytes()[..at]
        .iter()
        .filter(|b| **b == b'\n')
        .count()
        + 1
}
fn reasons(c: &ReviewedCandidate) -> Value {
    let source=c.source_reasons.iter().map(|r|json!({"channel":"source_text","term":r.term,"tier":r.tier,"tf":r.tf,"df":r.df,"bm25":r.bm25}));
    let semantic=c.reviewed_reasons.iter().map(|r|json!({"channel":"reviewed_context","term":r.term,"tier":r.tier,"tf":r.tf,"df":r.df,"bm25":r.bm25,"context_id":r.context_id,"context_ref":r.context_ref}));
    Value::Array(source.chain(semantic).collect())
}
fn window(
    c: &EvidenceChunk,
    candidate: &ReviewedCandidate,
    units: usize,
    semantic_anchor: Option<usize>,
) -> Value {
    let count = c.text.chars().count();
    let take = count.min(units);
    let anchor = semantic_anchor
        .or_else(|| {
            candidate.source_reasons.iter().rev().find_map(|r| {
                let (channel, term) = r.term.split_once(':')?;
                c.text.find(term).or_else(|| {
                    (channel == "fold")
                        .then(|| folded_anchor(&c.text, term))
                        .flatten()
                })
            })
        })
        .unwrap_or(0)
        .min(c.text.len());
    let anchor_char = c.text[..anchor].chars().count();
    let start = if take == count {
        0
    } else if semantic_anchor.is_some() {
        anchor_char.min(count - take)
    } else {
        anchor_char.saturating_sub(take / 4).min(count - take)
    };
    let begin = c
        .text
        .char_indices()
        .nth(start)
        .map_or(c.text.len(), |(i, _)| i);
    let end = c
        .text
        .char_indices()
        .nth(start + take)
        .map_or(c.text.len(), |(i, _)| i);
    let text = &c.text[begin..end];
    json!({"id":c.id,"path":c.path,"text":text,"byte_start":c.byte_start+begin,"byte_end":c.byte_start+end,"line_start":c.line_start+line(&c.text,begin)-1,"line_end":c.line_start+line(&c.text,end.saturating_sub(1))-1,"original_chunk_byte_start":c.byte_start,"original_chunk_byte_end":c.byte_end,"original_chunk_line_end":c.line_end,"file_sha":c.file_sha,"object_sha":c.object_sha,"source_commit":c.source_commit,"source_tree":c.source_tree,"snapshot_id":c.snapshot_id,"role":c.role,"language":c.language,"parent":c.parent,"score":candidate.score,"score_reasons":reasons(candidate),"neighbor_of":candidate.neighbor_of,"graph_relation":candidate.graph_link,"source_span_verified":true,"inference_status":"original_source_only","truncated":take<count})
}
pub(super) fn search(context: &CallContext, payload: &QueryPayload) -> Result<Value, String> {
    if payload.query.trim().is_empty()
        || payload.query.len() > 16384
        || payload.query_policy != semantic::QUERY_POLICY
        || !(1..=1000).contains(&payload.max_results)
        || payload.max_tokens > 8000
    {
        return Err("reviewed query policy or bounds invalid".into());
    }
    let mut bootstrap = QueryBudgetLimits::for_index(0);
    bootstrap.io_bytes = 64 * 1024 * 1024;
    let mut meter = QueryMeter::new(QueryBudgetUsage::default(), bootstrap);
    let result = execute(context, payload, &mut meter);
    result.map_err(|e| {
        format!(
            "{e}; authenticated_budget_usage={}",
            serde_json::to_string(&meter.usage()).unwrap_or_default()
        )
    })
}
fn execute(
    context: &CallContext,
    payload: &QueryPayload,
    meter: &mut QueryMeter,
) -> Result<Value, String> {
    let root = artifact::workspace(context, &payload.workspace_root)?;
    let loaded = semantic::load_overlay_with_io(context, &root, &payload.index_ref, meter)?;
    let key = pack::read_authority(context, &root, meter)?;
    let query_identity = identity(&root, payload)?;
    let mut s = if let Some(token) = &payload.continuation {
        resume(token, &key, &query_identity)?
    } else {
        let mut plan = selective::plan(&payload.query);
        plan.revision = "gtkg.qk.query-plan-reviewed/v1".into();
        if loaded.base.graph_ref.is_some() {
            plan.limitations
                .retain(|v| !v.contains("cross-file calls are not projected"));
            plan.limitations.push("at most two confirmed-call target/previous/next expansions from the leading evidence chunk".into());
        }
        plan.limitations.push("reviewed context and original source are separate channels; original source spans remain authoritative evidence".into());
        ReviewedState {
            schema: "gtkg.qk.reviewed-query-cursor/v1".into(),
            identity: query_identity.clone(),
            plan,
            candidates: BTreeMap::new(),
            admitted_ids: BTreeSet::new(),
            ranked: vec![],
            page_offset: 0,
            discovered: false,
            ranking_complete: false,
            usage: QueryBudgetUsage::default(),
            exhausted: None,
            source_postings: 0,
            reviewed_postings: 0,
            observed_ids: 0,
            eligible_ids: 0,
            structural_expansions: 0,
        }
    };
    let limits = QueryBudgetLimits::for_index(loaded.overlay.total_index_bytes);
    meter.inherit(s.usage.clone(), limits.clone())?;
    if meter.remaining_io() == 0 {
        s.exhausted = Some("E_QUERY_IO_BUDGET".into());
    }
    if let Err(e) = meter.check_time() {
        s.exhausted = Some(e);
    }
    let mut cache = BTreeMap::new();
    if !s.discovered
        && s.exhausted.is_none()
        && let Err(e) = collect(context, &root, &loaded, &mut s, meter)
    {
        if is_budget(&e) {
            s.exhausted = Some(e);
        } else {
            return Err(e);
        }
    }
    if s.discovered
        && !s.ranking_complete
        && (s.exhausted.is_none() || s.exhausted.as_deref() == Some("E_QUERY_CANDIDATE_BUDGET"))
        && let Err(e) = evaluate(context, &root, &loaded, &mut s, meter, &mut cache)
    {
        if is_budget(&e) {
            s.exhausted = Some(e);
            ordered(&mut s);
        } else {
            return Err(e);
        }
    }
    let max_units = if payload.max_tokens == 0 {
        8000
    } else {
        payload.max_tokens as usize
    };
    let mut evidence = vec![];
    let mut summaries: BTreeMap<String, ReviewedSummaryContext> = BTreeMap::new();
    let mut context_first_hit = BTreeMap::new();
    let mut pack_hits = vec![];
    let mut omissions = vec![];
    let mut source_units = 0usize;
    let mut context_units = 0usize;
    let mut token_truncated = false;
    let mut ledger = None;
    let mut source_object_reads = 0u64;
    let can_emit = s.exhausted.is_none()
        || matches!(
            s.exhausted.as_deref(),
            Some("E_QUERY_CANDIDATE_BUDGET" | "E_QUERY_POSTING_BUDGET")
        );
    if can_emit {
        while s.page_offset < s.ranked.len()
            && evidence.len() < payload.max_results as usize
            && source_units + context_units < max_units
        {
            let id = s.ranked[s.page_offset].clone();
            let candidate = s.candidates[&id].clone();
            let attempt = (|| -> Result<(Value, Vec<ReviewedSummaryContext>), String> {
                let c = match cache.get(&id) {
                    Some(c) => c.clone(),
                    None => chunk_by_ref(context, &root, &loaded.base, &candidate.posting, meter)?,
                };
                if ledger.is_none() {
                    ledger = Some(source_binding(context, &root, &loaded.base, meter)?);
                }
                verify_source(
                    context,
                    &root,
                    &loaded.base,
                    &c,
                    ledger.as_ref().ok_or("source binding absent")?,
                    meter,
                )?;
                source_object_reads += 1;
                let refs: BTreeMap<_, _> = candidate
                    .reviewed_reasons
                    .iter()
                    .map(|r| (r.context_id.clone(), r.context_ref.clone()))
                    .collect();
                let mut contexts = vec![];
                let mut new_units = 0usize;
                let mut anchor = None;
                for (context_id, reference) in refs {
                    let record = semantic::load_selected_context(
                        context, &root, &loaded, &reference, meter,
                    )?;
                    for mapping in record.mappings.iter().filter(|m| m.chunk_id == id) {
                        let citation = &record.citations[mapping.citation_index as usize];
                        if mapping.chunk_ref != candidate.posting.chunk_ref
                            || citation.path != c.path
                            || citation
                                .file_sha256
                                .strip_prefix("sha256:")
                                .unwrap_or(&citation.file_sha256)
                                != c.file_sha
                            || mapping.overlap_byte_start < c.byte_start
                            || mapping.overlap_byte_end > c.byte_end
                        {
                            return Err(
                                "semantic match does not overlap this original chunk".into()
                            );
                        }
                        let start = mapping.overlap_byte_start - c.byte_start;
                        if !c.text.is_char_boundary(start) {
                            return Err("semantic citation anchor is not Unicode boundary".into());
                        }
                        anchor = Some(anchor.map_or(start, |prior: usize| prior.min(start)));
                    }
                    let summary = semantic::verify_selected_lineage(
                        context, &root, &loaded, &record, &reference, meter,
                    )?;
                    if !summaries.contains_key(&context_id) {
                        if source_units + context_units + new_units + summary.text_units() + 1
                            > max_units
                        {
                            omissions.push(json!({"context_id":context_id,"reason":"complete_reviewed_text_and_condition_do_not_fit"}));
                            token_truncated = true;
                            continue;
                        }
                        new_units += summary.text_units();
                        contexts.push(summary);
                    }
                }
                Ok((
                    window(
                        &c,
                        &candidate,
                        max_units - source_units - context_units - new_units,
                        anchor,
                    ),
                    contexts,
                ))
            })();
            match attempt {
                Ok((hit, contexts)) => {
                    let units = hit["text"]
                        .as_str()
                        .ok_or("evidence text missing")?
                        .chars()
                        .count();
                    source_units += units;
                    token_truncated |= hit["truncated"] == true;
                    for summary in contexts {
                        context_units += summary.text_units();
                        context_first_hit.insert(summary.context_id.clone(), pack_hits.len());
                        summaries.insert(summary.context_id.clone(), summary);
                    }
                    pack_hits.push(pack::PackHitRef {
                        rank: s.page_offset as u32,
                        posting: candidate.posting.clone(),
                        evidence_byte_start: hit["byte_start"]
                            .as_u64()
                            .ok_or("byte start absent")?
                            as usize,
                        evidence_byte_end: hit["byte_end"].as_u64().ok_or("byte end absent")?
                            as usize,
                        score: candidate.score,
                        score_reasons: reasons(&candidate),
                        neighbor_of: candidate.neighbor_of,
                        graph_relation: candidate.graph_link,
                        summary_context: vec![],
                    });
                    evidence.push(hit);
                    s.page_offset += 1;
                }
                Err(e) if is_budget(&e) => {
                    s.exhausted = Some(e);
                    break;
                }
                Err(e) => return Err(e),
            }
        }
    }
    for summary in summaries.values_mut() {
        pack::fill_coverage(summary, &evidence);
    }
    for (id, summary) in &summaries {
        pack_hits[*context_first_hit
            .get(id)
            .ok_or("context attachment absent")?]
        .summary_context
        .push(summary.clone());
    }
    if let Err(e) = meter.check_time() {
        s.exhausted = Some(e);
    }
    s.usage = meter.usage();
    s.usage.candidate_count = s.admitted_ids.len() as u64;
    s.usage.initial_subqueries = s.plan.initial_subqueries.len() as u32;
    s.usage.structural_expansions = s.structural_expansions;
    let remaining = !s.ranking_complete || s.page_offset < s.ranked.len();
    token_truncated |= source_units + context_units == max_units && s.page_offset < s.ranked.len();
    let continuation = if remaining {
        Some(cursor(&s, &key)?)
    } else {
        None
    };
    let ambiguities: Vec<Vec<String>> = s
        .ranked
        .windows(2)
        .filter(|p| s.candidates[&p[0]].score == s.candidates[&p[1]].score)
        .map(|p| p.to_vec())
        .collect();
    let ranking_scope = if s.ranking_complete {
        "all_required_candidates"
    } else {
        "observed_candidates_provisional_scores"
    };
    let source_identity = pack::QuerySourceIdentity {
        snapshot_id: loaded.base.snapshot_id.clone(),
        source_commit: loaded.base.source_commit.clone(),
        source_tree: loaded.base.source_tree.clone(),
        source_ref: loaded.base.source_ref.clone(),
    };
    let public_ref = ArtifactRef {
        path: payload.index_ref.path.clone(),
        sha256: payload.index_ref.sha256.clone(),
        bytes: serde_json::to_vec_pretty(&loaded.overlay)
            .map_err(|e| e.to_string())?
            .len() as u64,
    };
    let plan = pack::QueryPlanArtifact {
        schema: pack::PLAN_SCHEMA.into(),
        original_query: payload.query.clone(),
        query_policy: payload.query_policy.clone(),
        query_identity: query_identity.clone(),
        public_index_ref: payload.index_ref.clone(),
        base_index_ref: FileReceiptRef {
            path: loaded.overlay.base_index_ref.path.clone(),
            sha256: loaded.overlay.base_index_ref.sha256.clone(),
        },
        selected_index_lineage: vec![
            public_ref,
            loaded.overlay.base_index_ref.clone(),
            loaded.overlay.catalog_ref.clone(),
        ],
        total_index_bytes: loaded.overlay.total_index_bytes,
        source_identity: source_identity.clone(),
        query_plan: serde_json::to_value(&s.plan).map_err(|e| e.to_string())?,
    };
    let hits = pack::QueryHitsArtifact {
        schema: pack::HITS_SCHEMA.into(),
        query_identity,
        plan_sha256: String::new(),
        ranking_complete: s.ranking_complete,
        ranking_scope: ranking_scope.into(),
        candidate_ambiguities: ambiguities.clone(),
        hits: pack_hits,
    };
    let preparation =
        pack::prepare_pack(&root, &plan, &hits, s.usage.clone(), limits.clone(), &key)?;
    let exhausted = s.exhausted.is_some();
    Ok(
        json!({"schema":"gtkg.qk.query-context-receipt/v2","status":if exhausted||token_truncated{"partial"}else{"complete"},"original_query":payload.query,"query_policy":payload.query_policy,"index_ref":payload.index_ref,"base_index_ref":plan.base_index_ref,"catalog_ref":loaded.overlay.catalog_ref,"source_identity":source_identity,"query_plan":s.plan,"evidence":evidence,"reviewed_contexts":summaries.into_values().collect::<Vec<_>>(),"semantic_context_available":loaded.catalog.total_contexts>0,"answerability":if exhausted{"budget_exhausted"}else if evidence.is_empty()&&!terms(&s.plan).is_empty(){"no_match_within_declared_scope"}else{"unresolved"},"ranking_complete":s.ranking_complete,"ranking_scope":ranking_scope,"candidate_ambiguities":ambiguities,"scanned":{"source_posting_rows":s.source_postings,"reviewed_posting_rows":s.reviewed_postings,"observed_ids":s.observed_ids,"eligible_ids":s.eligible_ids,"admitted_candidates":s.admitted_ids.len()},"budget":{"usage":s.usage,"limits":limits,"io_bytes":s.usage.io_bytes,"io_limit":limits.io_bytes,"mandatory_header_overrun":s.usage.io_bytes>limits.io_bytes,"source_units":source_units,"reviewed_context_units":context_units,"evidence_tokens":source_units+context_units,"evidence_token_limit":max_units,"tokenizer":index::TOKENIZER},"verification_scope":{"manifest":"digest_and_full_replay_admission_verified","selected_lineage":"selected_accepted_job_proposal_review_okf_digests","semantic_review_replayed_this_call":false,"source_ledger_reads":usize::from(ledger.is_some()),"source_object_reads":source_object_reads,"full_graph_reads":0,"unread_objects":"not_checked"},"omitted":omissions,"truncation":{"budget":exhausted,"reason":s.exhausted,"tokens":token_truncated,"pagination":remaining},"continuation":continuation,"continuation_budget":"cumulative authenticated linear chain; exhausted budgets are not reset","retry_fork_accounting":"host_owned; old cursors and pack tickets remain replayable","deadline_scope":"cooperative Core checks; blocking OS calls are not preempted","ranking_formula":{"identity":payload.query_policy,"formula":"source_max_tier*1000000 + sum(source_BM25)*source_role_weight + reviewed_max_tier*1000000 + sum(best_reviewed_BM25_per_term_chunk); empty channel=0","reviewed_denominator":"distinct canonical body and source citation contexts","duplicate_rule":"one best context per term/chunk; context_id tie-break","k1":1.2,"b":0.75,"tie_break":"chunk_id"},"pack_preparation":preparation,"source_fallback":false,"target_execution":false}),
    )
}
