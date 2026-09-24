//! F02: explainable ranked retrieval for `bundle.query`.
//!
//! Matching is conjunctive: a document is a hit only when every query term
//! appears in it, so a query whose distinctive terms are absent from the
//! bundle can never surface a merely term-sharing document (the B16 oracle).
//! Hits are ranked by a transparent scorer: every query term contributes the
//! weight of the strongest document field it hits (source path > claim line >
//! heading > body) plus a bounded body-frequency bonus. Documents below the
//! absolute score threshold are dropped instead of being returned as padding
//! hits, ties within the conflict margin across differing content are reported
//! as an explicit conflict, and every match carries a re-verifiable evidence
//! pack. All ordering keys are total and content-derived, so identical inputs
//! produce byte-identical results.

use gtkg_protocol::SourceKey;
use serde_json::{Value, json};

/// Absolute minimum score for a document to count as a hit. A single
/// body-only term occurrence scores 1 and is treated as noise.
pub(crate) const SCORE_THRESHOLD: u64 = 2;
/// Maximum score distance from the top hit that still counts as a tie.
pub(crate) const CONFLICT_MARGIN: u64 = 1;
const MAX_RESULTS: usize = 10;
const MAX_CANDIDATES: usize = 5;
const SNIPPET_RADIUS_CHARS: usize = 120;
const SNIPPET_WINDOW_CHARS: usize = 240;
const BODY_FREQUENCY_BONUS_CAP: u64 = 2;

const WEIGHT_PATH: u64 = 6;
const WEIGHT_CLAIM: u64 = 4;
const WEIGHT_HEADING: u64 = 3;
const WEIGHT_BODY: u64 = 1;

const STOPWORDS: &[&str] = &[
    "a", "an", "and", "are", "as", "at", "be", "by", "for", "from", "how", "in", "is", "of", "on",
    "or", "the", "to", "what", "with",
];

/// One verified bundle knowledge document offered to the ranker.
pub(crate) struct QueryDocument {
    pub(crate) source_key: SourceKey,
    pub(crate) knowledge_path: String,
    pub(crate) knowledge_sha256: String,
    pub(crate) source_sha256: String,
    pub(crate) content: String,
}

struct ScoredDocument<'a> {
    document: &'a QueryDocument,
    score: u64,
    matched_terms: Vec<String>,
    matched_fields: Vec<&'static str>,
    claim_refs: Vec<String>,
    snippet: String,
    snippet_char_start: usize,
    snippet_char_end: usize,
}

/// Run a ranked query over the verified knowledge documents and build the
/// `bundle.query` result object.
pub(crate) fn ranked_query(query: &str, documents: &[QueryDocument]) -> Value {
    let terms = tokenize(query);
    if terms.is_empty() {
        return json!({
            "query": query,
            "status": "no_answer",
            "reason": "query contains no searchable terms after tokenization",
            "score_threshold": SCORE_THRESHOLD,
            "matches": [],
            "candidates": [],
        });
    }

    let mut scored: Vec<ScoredDocument> = documents
        .iter()
        .filter_map(|document| score_document(&terms, document))
        .collect();
    scored.sort_by(|left, right| {
        right.score.cmp(&left.score).then_with(|| {
            left.document
                .knowledge_path
                .cmp(&right.document.knowledge_path)
        })
    });

    let best_below_threshold = scored.iter().map(|entry| entry.score).max().unwrap_or(0);
    let mut hits: Vec<ScoredDocument> = scored
        .into_iter()
        .filter(|entry| entry.score >= SCORE_THRESHOLD)
        .collect();
    if hits.is_empty() {
        let reason = if best_below_threshold > 0 {
            format!(
                "best score {best_below_threshold} is below the relevance threshold {SCORE_THRESHOLD}"
            )
        } else {
            "no document contains any query term".to_owned()
        };
        return json!({
            "query": query,
            "status": "no_answer",
            "reason": reason,
            "score_threshold": SCORE_THRESHOLD,
            "matches": [],
            "candidates": [],
        });
    }
    hits.truncate(MAX_RESULTS);

    let top_score = hits[0].score;
    let tied: Vec<&ScoredDocument> = hits
        .iter()
        .take_while(|entry| entry.score + CONFLICT_MARGIN > top_score)
        .collect();
    let mut distinct_digests: Vec<&str> = tied
        .iter()
        .map(|entry| entry.document.knowledge_sha256.as_str())
        .collect();
    distinct_digests.sort_unstable();
    distinct_digests.dedup();
    let conflict = tied.len() >= 2 && distinct_digests.len() >= 2;

    let matches: Vec<Value> = hits.iter().map(match_json).collect();
    if conflict {
        let candidates: Vec<Value> = tied
            .iter()
            .take(MAX_CANDIDATES)
            .map(|entry| {
                json!({
                    "source_key": entry.document.source_key,
                    "knowledge_path": entry.document.knowledge_path,
                    "knowledge_sha256": entry.document.knowledge_sha256,
                    "score": entry.score,
                })
            })
            .collect();
        json!({
            "query": query,
            "status": "conflict",
            "reason": format!(
                "top-ranked documents tie within margin {CONFLICT_MARGIN} with differing content"
            ),
            "score_threshold": SCORE_THRESHOLD,
            "matches": matches,
            "candidates": candidates,
        })
    } else {
        json!({
            "query": query,
            "status": "answered",
            "reason": Value::Null,
            "score_threshold": SCORE_THRESHOLD,
            "matches": matches,
            "candidates": [],
        })
    }
}

fn match_json(entry: &ScoredDocument) -> Value {
    json!({
        "source_key": entry.document.source_key,
        "knowledge_path": entry.document.knowledge_path,
        "snippet": entry.snippet,
        "score": entry.score,
        "matched_terms": entry.matched_terms,
        "evidence": {
            "knowledge_path": entry.document.knowledge_path,
            "knowledge_sha256": entry.document.knowledge_sha256,
            "source_sha256": entry.document.source_sha256,
            "matched_fields": entry.matched_fields,
            "claim_refs": entry.claim_refs,
            "snippet_char_start": entry.snippet_char_start,
            "snippet_char_end": entry.snippet_char_end,
        },
    })
}

/// Split a query into lowercase search terms. ASCII runs stay whole (with a
/// small stopword list applied); non-ASCII alphanumeric runs (e.g. Chinese)
/// are split into overlapping character bigrams so phrase matching degrades
/// gracefully instead of requiring an exact substring.
fn tokenize(query: &str) -> Vec<String> {
    let mut terms = Vec::new();
    let mut run = String::new();
    for character in query.to_lowercase().chars() {
        if character.is_alphanumeric() {
            run.push(character);
        } else if !run.is_empty() {
            emit_run(&run, &mut terms);
            run.clear();
        }
    }
    if !run.is_empty() {
        emit_run(&run, &mut terms);
    }
    let mut unique: Vec<String> = Vec::new();
    for term in terms {
        if !unique.contains(&term) {
            unique.push(term);
        }
    }
    if unique.iter().all(|term| is_stopword(term)) {
        return unique;
    }
    unique
        .into_iter()
        .filter(|term| !is_stopword(term))
        .collect()
}

fn emit_run(run: &str, terms: &mut Vec<String>) {
    if run.is_ascii() {
        terms.push(run.to_owned());
        return;
    }
    let characters: Vec<char> = run.chars().collect();
    if characters.len() == 1 {
        terms.push(run.to_owned());
        return;
    }
    for window in characters.windows(2) {
        terms.push(window.iter().collect());
    }
}

fn is_stopword(term: &str) -> bool {
    term.is_ascii() && STOPWORDS.contains(&term)
}

fn score_document<'a>(terms: &[String], document: &'a QueryDocument) -> Option<ScoredDocument<'a>> {
    let content_lower = document.content.to_lowercase();
    let path_lower = document.source_key.logical_path.to_lowercase();
    let claim_lines: Vec<&str> = document
        .content
        .lines()
        .filter(|line| line.starts_with("- claim:"))
        .collect();
    let claim_lower: Vec<String> = claim_lines.iter().map(|line| line.to_lowercase()).collect();
    let heading_lower: Vec<String> = document
        .content
        .lines()
        .filter(|line| line.starts_with('#'))
        .map(|line| line.to_lowercase())
        .collect();

    let mut score = 0_u64;
    let mut matched_terms = Vec::new();
    let mut fields = Vec::new();
    let mut focus: Option<(u64, usize, String)> = None;
    for term in terms {
        let body_count = content_lower.matches(term.as_str()).count() as u64;
        let mut weight = 0_u64;
        if path_lower.contains(term.as_str()) {
            weight = weight.max(WEIGHT_PATH);
            push_field(&mut fields, "path");
        }
        if claim_lower.iter().any(|line| line.contains(term.as_str())) {
            weight = weight.max(WEIGHT_CLAIM);
            push_field(&mut fields, "claim");
        }
        if heading_lower
            .iter()
            .any(|line| line.contains(term.as_str()))
        {
            weight = weight.max(WEIGHT_HEADING);
            push_field(&mut fields, "heading");
        }
        if body_count > 0 {
            weight = weight.max(WEIGHT_BODY);
            push_field(&mut fields, "body");
        }
        if weight == 0 {
            continue;
        }
        score += weight + (body_count.saturating_sub(1)).min(BODY_FREQUENCY_BONUS_CAP);
        if !matched_terms.contains(term) {
            matched_terms.push(term.clone());
        }
        let contribution = weight + (body_count.saturating_sub(1)).min(BODY_FREQUENCY_BONUS_CAP);
        let replace = focus
            .as_ref()
            .is_none_or(|(best, _, _)| contribution > *best);
        if replace {
            focus = Some((contribution, body_count as usize, term.clone()));
        }
    }
    if score == 0 || matched_terms.len() != terms.len() {
        // Conjunctive matching: a hit must contain every query term; partial
        // term overlap alone never surfaces a document.
        return None;
    }

    let mut claim_refs = Vec::new();
    for line in &claim_lines {
        let line_lower = line.to_lowercase();
        if !matched_terms
            .iter()
            .any(|term| line_lower.contains(term.as_str()))
        {
            continue;
        }
        if let Some((_, citations)) = line.split_once(" | evidence: ") {
            for reference in citations.split(',').map(str::trim) {
                if !reference.is_empty() && !claim_refs.iter().any(|seen| seen == reference) {
                    claim_refs.push(reference.to_owned());
                }
            }
        }
    }

    let focus_term = focus.map(|(_, _, term)| term).unwrap_or_default();
    let (snippet, snippet_char_start, snippet_char_end) =
        centered_snippet(&document.content, &content_lower, &focus_term);
    Some(ScoredDocument {
        document,
        score,
        matched_terms,
        matched_fields: fields,
        claim_refs,
        snippet,
        snippet_char_start,
        snippet_char_end,
    })
}

fn push_field(fields: &mut Vec<&'static str>, field: &'static str) {
    if !fields.contains(&field) {
        fields.push(field);
    }
}

/// Extract a window of at most [`SNIPPET_WINDOW_CHARS`] characters centered on
/// the first occurrence of the focus term, with `…` markers where the window
/// is truncated. Returns the snippet plus its char-offset window in the
/// original content.
fn centered_snippet(
    content: &str,
    content_lower: &str,
    focus_term: &str,
) -> (String, usize, usize) {
    let total_chars = content.chars().count();
    let focus_char = content_lower
        .find(focus_term)
        .map(|byte| content_lower[..byte].chars().count());
    let start = match focus_char {
        Some(index) => index.saturating_sub(SNIPPET_RADIUS_CHARS),
        None => 0,
    };
    let end = (start + SNIPPET_WINDOW_CHARS).min(total_chars);
    let window: String = content.chars().skip(start).take(end - start).collect();
    let mut snippet = String::new();
    if start > 0 {
        snippet.push('…');
    }
    snippet.push_str(&window);
    if end < total_chars {
        snippet.push('…');
    }
    (snippet, start, end)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokenize_keeps_ascii_runs_and_splits_cjk_into_bigrams() {
        assert_eq!(tokenize("schema migration"), vec!["schema", "migration"]);
        assert_eq!(
            tokenize("用户认证"),
            vec!["用户", "户认", "认证"],
            "CJK runs become overlapping bigrams"
        );
        assert_eq!(tokenize("the cache of the TTL"), vec!["cache", "ttl"]);
        assert_eq!(tokenize("  "), Vec::<String>::new());
    }

    #[test]
    fn centered_snippet_covers_late_hits() {
        let mut content = "填充。".repeat(100);
        content.push_str("布隆过滤器 protects the cache.");
        let lower = content.to_lowercase();
        let (snippet, start, end) = centered_snippet(&content, &lower, "布隆过滤器");
        assert!(snippet.contains("布隆过滤器"));
        assert!(start > 0);
        let window: String = content.chars().skip(start).take(end - start).collect();
        assert!(window.contains("布隆过滤器"));
    }
}
