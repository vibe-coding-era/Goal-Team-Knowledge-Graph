//! Explicit v2 eligibility: posting-set preselection precedes candidate admission.
//! Every decoded leaf is charged; no source chunk is read or scored by preselection.
use super::*;

pub(super) fn plan(query: &str) -> Plan {
    let mut p = super::plan(query);
    p.revision = "gtkg.qk.query-plan/v2".into();
    // In an English "how ... work?" question this word is scaffolding, not an
    // additional repository signal. Literal/qualified identifier queries retain it.
    let lower = query.trim().to_lowercase();
    if p.kind == "natural_or_phrase"
        && lower.starts_with("how ")
        && (lower.ends_with(" work?") || lower.ends_with(" work"))
    {
        p.initial_subqueries
            .retain(|g| g.signal.to_lowercase() != "work");
    }
    p.candidate_selection = Some("pending_posting_preselection".into());
    p.limitations.push("posting IDs are prefiltered by all signal groups (OR within a group); empty intersection explicitly falls back to union; at most 2000 eligible chunks are admitted and scored".into());
    p
}

pub(super) fn scan(
    context: &CallContext,
    workspace: &Path,
    reader: &index::QueryIndexReader<'_>,
    s: &mut State,
    limit: u64,
    start: Instant,
) -> Result<(), String> {
    let m = reader.manifest();
    let mut by_term: BTreeMap<String, Vec<Posting>> = BTreeMap::new();
    let mut observed = BTreeSet::new();
    // These bounded posting rows are temporary. If collection exhausts a budget,
    // discovery remains exhausted in the authenticated cursor; it cannot restart
    // with a fresh allowance or persist an unbounded posting array in the token.
    for term in s.terms.clone() {
        let Some(postings) = bounded_postings(context, workspace, m, &term.term, s, limit, start)?
        else {
            return Ok(());
        };
        if postings.len() > m.total_chunks {
            return Err("posting document frequency exceeds index denominator".into());
        }
        for p in &postings {
            observed.insert(p.chunk_id.clone());
        }
        s.counts.posting_ids_observed = observed.len() as u64;
        by_term.insert(term.term, postings);
        s.term_index += 1;
    }
    let mut eligible: Option<BTreeSet<String>> = None;
    for group in &s.plan.initial_subqueries {
        let members: BTreeSet<_> = group
            .terms
            .iter()
            .filter_map(|t| by_term.get(&t.term))
            .flatten()
            .map(|p| p.chunk_id.clone())
            .collect();
        eligible = Some(match eligible {
            None => members,
            Some(previous) => previous.intersection(&members).cloned().collect(),
        });
    }
    let intersection = eligible.unwrap_or_default();
    let eligible = if intersection.is_empty() {
        s.plan.candidate_selection = Some("union_fallback".into());
        observed.clone()
    } else {
        s.plan.candidate_selection = Some("all_signal_groups".into());
        intersection
    };
    s.counts.eligible_ids = eligible.len() as u64;
    s.counts.filtered_ids = observed.len().saturating_sub(eligible.len()) as u64;
    s.considered_ids = eligible.iter().take(MAX_CANDIDATES).cloned().collect();
    for term in &s.terms {
        let postings = by_term
            .get(&term.term)
            .ok_or("selected posting set absent")?;
        let df = postings.len();
        for p in postings
            .iter()
            .filter(|p| s.considered_ids.contains(&p.chunk_id))
        {
            if !time_left(s, start) {
                s.exhausted = Some("wall_time".into());
                return Ok(());
            }
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
            s.counts.scored_postings += 1;
        }
    }
    if eligible.len() > MAX_CANDIDATES {
        s.exhausted = Some("candidates".into());
        return Ok(());
    }
    finish_scan(context, workspace, reader, s, limit, start)
}
