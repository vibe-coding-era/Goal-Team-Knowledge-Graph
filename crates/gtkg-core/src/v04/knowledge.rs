//! Source-bound knowledge candidates and explicit host-observed authoring records.
use gtkg_extract::v04::{AnalysisContext, Span, binding::CallBindingProof};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone)]
pub struct KnowledgeSources {
    pub raw_sources: BTreeMap<String, Vec<u8>>,
    pub context: AnalysisContext,
    pub call_proofs: Vec<CallBindingProof>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KnowledgeGoal {
    Archive,
    SemanticUnderstanding,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorMode {
    StaticTranscription,
    HumanAuthored,
    ModelGenerated,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionEvidence {
    Unavailable,
    HostObserved,
    HumanRecorded,
    StaticRecorded,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EpistemicStatus {
    Direct,
    Inferred,
    Unknown,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Judgment {
    Supported,
    Rejected,
    Unknown,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KnowledgeInput {
    pub job_id: String,
    pub goal: KnowledgeGoal,
    pub source_paths: Vec<String>,
    pub understanding_items: Vec<String>,
    pub prompt: String,
    pub policy: String,
    pub max_context_units: usize,
    /// Missing paths mean full-file context; present entries select exact raw spans.
    #[serde(default)]
    pub source_spans: BTreeMap<String, Vec<Span>>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextSource {
    pub path: String,
    pub file_sha256: String,
    pub text: String,
    pub span: Span,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KnowledgeJob {
    pub schema: String,
    pub input: KnowledgeInput,
    pub source_set_digest: String,
    pub analysis_context_digest: String,
    pub context: Vec<ContextSource>,
    pub context_digest: String,
    pub prompt_digest: String,
    pub policy_digest: String,
    pub job_digest: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Usage {
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationExecutionRecord {
    pub schema: String,
    pub job_digest: String,
    pub context_digest: String,
    pub prompt_digest: String,
    pub policy_digest: String,
    pub author_id: String,
    pub author_mode: AuthorMode,
    pub execution_evidence: ExecutionEvidence,
    pub host_id: Option<String>,
    pub model_id: Option<String>,
    pub transcript: Option<String>,
    pub transcript_digest: Option<String>,
    pub output: String,
    pub output_digest: String,
    pub usage: Usage,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Citation {
    pub path: String,
    pub file_sha256: String,
    pub span: Span,
    pub excerpt: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "predicate", rename_all = "snake_case", deny_unknown_fields)]
pub enum Predicate {
    Declares {
        path: String,
        name: String,
        kind: String,
    },
    Calls {
        call_id: String,
        source_path: String,
        target_path: String,
        target_id: String,
    },
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "claim_kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ClaimBody {
    Structural {
        predicate: Predicate,
        polarity: bool,
    },
    Interpretive {
        proposition: String,
        epistemic: EpistemicStatus,
        version_condition: String,
    },
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KnowledgeClaim {
    pub claim_id: String,
    pub understanding_item: String,
    pub natural_language: String,
    pub body: ClaimBody,
    pub citations: Vec<Citation>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KnowledgeCandidate {
    pub author_id: String,
    pub author_mode: AuthorMode,
    pub summary: String,
    pub claims: Vec<KnowledgeClaim>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KnowledgeProposal {
    pub schema: String,
    pub job_digest: String,
    pub candidate: KnowledgeCandidate,
    pub execution_record: Option<GenerationExecutionRecord>,
    pub state: String,
    pub proposal_digest: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimReview {
    pub claim_id: String,
    pub claim_digest: String,
    pub judgment: Judgment,
    pub reason: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IndependentReview {
    pub reviewer_id: String,
    pub proposal_digest: String,
    pub decisions: Vec<ClaimReview>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KnowledgeVerification {
    pub schema: String,
    pub job_digest: String,
    pub proposal_digest: String,
    pub reviews: Vec<IndependentReview>,
    pub supported_claim_ids: Vec<String>,
    pub covered_understanding_items: Vec<String>,
    pub verification_digest: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptedKnowledge {
    pub schema: String,
    pub job_digest: String,
    pub proposal_digest: String,
    pub verification_digest: String,
    pub author_mode: AuthorMode,
    pub execution_assurance: String,
    pub supported_claims: Vec<KnowledgeClaim>,
    pub covered_understanding_items: Vec<String>,
    pub required_understanding_count: usize,
    pub knowledge_ready: bool,
    pub llm_qa_validated: bool,
}
#[derive(Debug, thiserror::Error)]
pub enum KnowledgeError {
    #[error("invalid knowledge chain: {0}")]
    Invalid(String),
    #[error("semantic authoring pending")]
    SemanticAuthoringPending,
}
pub fn digest(bytes: &[u8]) -> String {
    gtkg_extract::v04::digest(bytes)
}
pub fn claim_digest(claim: &KnowledgeClaim) -> Result<String, KnowledgeError> {
    serde_json::to_vec(claim)
        .map(|b| digest(&b))
        .map_err(|e| KnowledgeError::Invalid(e.to_string()))
}
fn proposition_identity(claim: &KnowledgeClaim) -> Result<String, KnowledgeError> {
    let mut body = serde_json::to_value(&claim.body).map_err(|e| invalid(e.to_string()))?;
    // Evidence confidence, prose, IDs and assignment to a requested item do not
    // create another proposition or another unit of understanding coverage.
    if let Some(object) = body.as_object_mut() {
        object.remove("epistemic");
    }
    Ok(digest(&encoded(&body)?))
}
fn invalid(message: impl Into<String>) -> KnowledgeError {
    KnowledgeError::Invalid(message.into())
}
fn encoded<T: Serialize>(value: &T) -> Result<Vec<u8>, KnowledgeError> {
    serde_json::to_vec(value).map_err(|e| invalid(e.to_string()))
}
fn seal<T: Serialize>(value: &T, field: &str) -> Result<String, KnowledgeError> {
    let mut v = serde_json::to_value(value).map_err(|e| invalid(e.to_string()))?;
    v.as_object_mut()
        .ok_or_else(|| invalid("seal requires object"))?
        .remove(field);
    Ok(digest(&encoded(&v)?))
}
fn nonempty(value: &str) -> Result<(), KnowledgeError> {
    if value.trim().is_empty() {
        Err(invalid("empty identity or text"))
    } else {
        Ok(())
    }
}
fn source_path(value: &str) -> Result<(), KnowledgeError> {
    if value.is_empty()
        || value.starts_with('/')
        || value.contains(['\\', '\0'])
        || value
            .split('/')
            .any(|p| p.is_empty() || p == "." || p == "..")
    {
        Err(invalid("noncanonical source path"))
    } else {
        Ok(())
    }
}
fn unique_ordered(values: &[String]) -> Result<(), KnowledgeError> {
    for value in values {
        nonempty(value)?;
    }
    if values.windows(2).any(|p| p[0] >= p[1]) {
        Err(invalid("set must be unique and sorted"))
    } else {
        Ok(())
    }
}
fn source_window<'a>(
    raw: &'a [u8],
    span: &Span,
    allow_empty: bool,
) -> Result<&'a str, KnowledgeError> {
    if span.byte_start > span.byte_end
        || span.byte_end > raw.len()
        || (!allow_empty && span.byte_start == span.byte_end)
    {
        return Err(invalid("invalid context byte window"));
    }
    if raw[..span.byte_start]
        .iter()
        .filter(|b| **b == b'\n')
        .count()
        + 1
        != span.line_start
        || raw[..span.byte_end.saturating_sub(1)]
            .iter()
            .filter(|b| **b == b'\n')
            .count()
            + 1
            != span.line_end
    {
        return Err(invalid(
            "context window has incorrect original line coordinates",
        ));
    }
    let text = std::str::from_utf8(raw).map_err(|_| invalid("context source is not UTF8"))?;
    text.get(span.byte_start..span.byte_end)
        .ok_or_else(|| invalid("context window splits a UTF8 character"))
}
/// Prepare only the explicitly requested context subset. The unit budget is
/// UTF8-codepoint-v1, a conservative bound, not a measured model tokenizer.
pub fn prepare_job(
    input: &KnowledgeInput,
    sources: &KnowledgeSources,
) -> Result<KnowledgeJob, KnowledgeError> {
    nonempty(&input.job_id)?;
    nonempty(&input.prompt)?;
    nonempty(&input.policy)?;
    nonempty(&sources.context.snapshot_id)?;
    unique_ordered(&input.source_paths)?;
    unique_ordered(&input.understanding_items)?;
    if input.source_paths.is_empty()
        || !(1..=8000).contains(&input.max_context_units)
        || (input.goal == KnowledgeGoal::SemanticUnderstanding
            && input.understanding_items.is_empty())
    {
        return Err(invalid(
            "missing context/understanding denominator or invalid budget",
        ));
    }
    let mut identities = BTreeMap::new();
    for (path, bytes) in &sources.raw_sources {
        source_path(path)?;
        identities.insert(path.clone(), digest(bytes));
    }
    let mut context = Vec::new();
    let mut units = 0usize;
    if input
        .source_spans
        .keys()
        .any(|path| !input.source_paths.contains(path))
    {
        return Err(invalid("context span path was not requested"));
    }
    for path in &input.source_paths {
        source_path(path)?;
        let raw = sources
            .raw_sources
            .get(path)
            .ok_or_else(|| invalid("requested source unavailable"))?;
        let default_span = vec![Span {
            byte_start: 0,
            byte_end: raw.len(),
            line_start: 1,
            line_end: raw[..raw.len().saturating_sub(1)]
                .iter()
                .filter(|b| **b == b'\n')
                .count()
                + 1,
        }];
        let spans = input.source_spans.get(path).unwrap_or(&default_span);
        if spans.is_empty() {
            return Err(invalid("explicit source span set is empty"));
        }
        let mut previous_end = 0;
        for span in spans {
            if span.byte_start < previous_end {
                return Err(invalid("context windows overlap or are not ordered"));
            }
            let text = source_window(
                raw,
                span,
                raw.is_empty() && !input.source_spans.contains_key(path),
            )?
            .to_owned();
            previous_end = span.byte_end;
            units = units
                .checked_add(text.chars().count())
                .ok_or_else(|| invalid("context budget overflow"))?;
            if units > input.max_context_units {
                return Err(invalid(
                    "context budget exhausted; select an explicit smaller source window set",
                ));
            }
            context.push(ContextSource {
                path: path.clone(),
                file_sha256: digest(raw),
                text,
                span: span.clone(),
            });
        }
    }
    let mut job = KnowledgeJob {
        schema: "gtkg.qk.knowledge-job/v2".into(),
        input: input.clone(),
        source_set_digest: digest(&encoded(&identities)?),
        analysis_context_digest: gtkg_extract::v04::context_digest(&sources.context),
        context_digest: digest(&encoded(&context)?),
        context,
        prompt_digest: digest(input.prompt.as_bytes()),
        policy_digest: digest(input.policy.as_bytes()),
        job_digest: String::new(),
    };
    job.job_digest = seal(&job, "job_digest")?;
    Ok(job)
}
fn validate_job(job: &KnowledgeJob, sources: &KnowledgeSources) -> Result<(), KnowledgeError> {
    if prepare_job(&job.input, sources)? != *job {
        return Err(invalid("job/context/source/policy identity drift"));
    }
    Ok(())
}
fn validate_citation(
    c: &Citation,
    job: &KnowledgeJob,
    sources: &KnowledgeSources,
) -> Result<(), KnowledgeError> {
    if !job.input.source_paths.contains(&c.path) {
        return Err(invalid("citation was not present in this job context"));
    }
    let bytes = sources
        .raw_sources
        .get(&c.path)
        .ok_or_else(|| invalid("citation source missing"))?;
    let s = &c.span;
    if s.byte_start >= s.byte_end
        || s.byte_end > bytes.len()
        || digest(bytes) != c.file_sha256
        || bytes.get(s.byte_start..s.byte_end) != Some(c.excerpt.as_bytes())
        || bytes[..s.byte_start]
            .iter()
            .filter(|b| **b == b'\n')
            .count()
            + 1
            != s.line_start
        || bytes[..s.byte_end - 1]
            .iter()
            .filter(|b| **b == b'\n')
            .count()
            + 1
            != s.line_end
    {
        return Err(invalid("citation bytes/span/line/source digest mismatch"));
    }
    let mut covered_until = s.byte_start;
    for part in job
        .context
        .iter()
        .filter(|part| part.path == c.path && part.file_sha256 == c.file_sha256)
    {
        if part.span.byte_end <= covered_until {
            continue;
        }
        if part.span.byte_start > covered_until {
            break;
        }
        covered_until = covered_until.max(part.span.byte_end);
        if covered_until >= s.byte_end {
            return Ok(());
        }
    }
    Err(invalid("citation references an unobserved source window"))
}
fn is_code(path: &str) -> bool {
    matches!(
        path.rsplit('.').next().unwrap_or(""),
        "go" | "rs" | "py" | "pyi" | "ts" | "tsx" | "mts" | "cts" | "js" | "jsx" | "mjs" | "cjs"
    )
}
fn validate_claims(
    job: &KnowledgeJob,
    candidate: &KnowledgeCandidate,
    sources: &KnowledgeSources,
) -> Result<(), KnowledgeError> {
    nonempty(&candidate.author_id)?;
    nonempty(&candidate.summary)?;
    if candidate.summary.len() > 65536 || candidate.claims.len() > 1024 {
        return Err(invalid("candidate bounds exceeded"));
    }
    let needs_calls = candidate.claims.iter().any(|c| {
        matches!(
            c.body,
            ClaimBody::Structural {
                predicate: Predicate::Calls { .. },
                ..
            }
        )
    });
    // The binding verifier receives the complete code source set, not the
    // authoring context subset. Markdown/config never become code Typed IR.
    let edges = if needs_calls {
        let code_sources = sources
            .raw_sources
            .iter()
            .filter(|(p, _)| is_code(p))
            .map(|(p, b)| (p.clone(), b.clone()))
            .collect();
        gtkg_extract::v04::binding::confirmed_edges(
            &sources.call_proofs,
            &code_sources,
            &sources.context,
        )
        .map_err(|e| invalid(format!("Calls proof replay failed: {e}")))?
    } else {
        vec![]
    };
    let mut ids = BTreeSet::new();
    let mut parsed = BTreeMap::new();
    for claim in &candidate.claims {
        nonempty(&claim.claim_id)?;
        nonempty(&claim.natural_language)?;
        if !ids.insert(&claim.claim_id)
            || !job
                .input
                .understanding_items
                .contains(&claim.understanding_item)
            || claim.citations.is_empty()
        {
            return Err(invalid(
                "duplicate claim, unknown understanding item or missing evidence",
            ));
        }
        for citation in &claim.citations {
            validate_citation(citation, job, sources)?;
        }
        match &claim.body {
            ClaimBody::Structural {
                predicate: Predicate::Declares { path, name, kind },
                polarity,
            } => {
                nonempty(name)?;
                nonempty(kind)?;
                if !job.input.source_paths.contains(path) {
                    return Err(invalid("structural subject outside observed context"));
                }
                if !parsed.contains_key(path) {
                    let raw = sources
                        .raw_sources
                        .get(path)
                        .ok_or_else(|| invalid("predicate source missing"))?;
                    let f = gtkg_extract::v04::extract(path, raw, &sources.context)
                        .map_err(|e| invalid(e.to_string()))?;
                    if f.parse_status != "parsed" || f.variant_status != "active" {
                        return Err(invalid("predicate source is partial/inactive"));
                    }
                    parsed.insert(path.clone(), f);
                }
                let f = parsed
                    .get(path)
                    .ok_or_else(|| invalid("predicate replay missing"))?;
                let declarations: Vec<_> = f
                    .declarations
                    .iter()
                    .filter(|d| d.name == *name && d.kind == *kind)
                    .collect();
                if declarations.is_empty() == *polarity {
                    return Err(invalid(
                        "structural declaration/polarity contradicted by replay",
                    ));
                }
                let supported = if *polarity {
                    declarations.iter().any(|d| {
                        claim.citations.iter().any(|c| {
                            c.path == *path
                                && c.span.byte_start <= d.name_span.byte_start
                                && c.span.byte_end >= d.name_span.byte_end
                        })
                    })
                } else {
                    claim.citations.iter().any(|c| {
                        c.path == *path
                            && c.span.byte_start == 0
                            && c.span.byte_end == sources.raw_sources[path].len()
                    })
                };
                if !supported {
                    return Err(invalid(
                        "citation does not support the structural subject or absence denominator",
                    ));
                }
            }
            ClaimBody::Structural {
                predicate:
                    Predicate::Calls {
                        call_id,
                        source_path,
                        target_path,
                        target_id,
                    },
                polarity,
            } => {
                if !*polarity {
                    return Err(invalid(
                        "negative Calls needs an absence proof; unresolved is not false",
                    ));
                }
                if !job.input.source_paths.contains(source_path)
                    || !job.input.source_paths.contains(target_path)
                    || !edges.iter().any(|e| {
                        e.call_id == *call_id
                            && e.source_path == *source_path
                            && e.target_path == *target_path
                            && e.target_id == *target_id
                    })
                {
                    return Err(invalid(
                        "Calls proposition is not present in replayed confirmed edges",
                    ));
                }
                let proof = sources
                    .call_proofs
                    .iter()
                    .find(|p| p.call.id == *call_id)
                    .ok_or_else(|| invalid("Calls proof missing"))?;
                if !claim.citations.iter().any(|c| {
                    c.path == *source_path
                        && c.span.byte_start <= proof.call.span.byte_start
                        && c.span.byte_end >= proof.call.span.byte_end
                }) {
                    return Err(invalid(
                        "Calls citation does not include the actual call-site",
                    ));
                }
                let target = proof
                    .target
                    .as_ref()
                    .ok_or_else(|| invalid("Calls target declaration missing"))?;
                if !claim.citations.iter().any(|c| {
                    c.path == *target_path
                        && c.span.byte_start <= target.declaration.name_span.byte_start
                        && c.span.byte_end >= target.declaration.name_span.byte_end
                }) {
                    return Err(invalid(
                        "Calls target declaration is not supported by observed evidence",
                    ));
                }
            }
            ClaimBody::Interpretive {
                proposition,
                version_condition,
                ..
            } => {
                nonempty(proposition)?;
                nonempty(version_condition)?;
            }
        }
    }
    Ok(())
}
fn execution_state(
    job: &KnowledgeJob,
    candidate: &KnowledgeCandidate,
    record: Option<&GenerationExecutionRecord>,
) -> Result<String, KnowledgeError> {
    let pending = if job.input.goal == KnowledgeGoal::SemanticUnderstanding {
        "semantic_authoring_pending"
    } else {
        "archive_only"
    };
    let Some(r) = record else {
        return Ok(pending.into());
    };
    if r.schema != "gtkg.qk.generation-execution-record/v1"
        || r.job_digest != job.job_digest
        || r.context_digest != job.context_digest
        || r.prompt_digest != job.prompt_digest
        || r.policy_digest != job.policy_digest
        || r.author_id != candidate.author_id
        || r.author_mode != candidate.author_mode
        || digest(r.output.as_bytes()) != r.output_digest
    {
        return Err(invalid("generation execution record identity mismatch"));
    }
    if r.output.len() > 2 * 1024 * 1024 {
        return Err(invalid("generation output bound exceeded"));
    }
    let parsed: KnowledgeCandidate =
        serde_json::from_str(&r.output).map_err(|e| invalid(e.to_string()))?;
    if parsed != *candidate {
        return Err(invalid(
            "actual recorded output does not encode submitted candidate",
        ));
    }
    match (&r.transcript, &r.transcript_digest) {
        (Some(text), Some(sha)) if !text.is_empty() && digest(text.as_bytes()) == *sha => {}
        (None, None) => {}
        _ => return Err(invalid("transcript digest mismatch")),
    }
    let available = match (&r.author_mode, &r.execution_evidence) {
        (_, ExecutionEvidence::Unavailable) => false,
        (AuthorMode::ModelGenerated, ExecutionEvidence::HostObserved) => {
            r.host_id.as_ref().is_some_and(|x| !x.trim().is_empty())
                && r.model_id.as_ref().is_some_and(|x| !x.trim().is_empty())
                && r.transcript.is_some()
        }
        (AuthorMode::HumanAuthored, ExecutionEvidence::HumanRecorded) => true,
        (AuthorMode::StaticTranscription, ExecutionEvidence::StaticRecorded) => true,
        _ => return Err(invalid("author mode/execution evidence mismatch")),
    };
    if !available
        || (job.input.goal == KnowledgeGoal::SemanticUnderstanding
            && candidate.author_mode == AuthorMode::StaticTranscription)
    {
        Ok(pending.into())
    } else {
        Ok("ready_for_review".into())
    }
}
pub fn submit_proposal(
    job: &KnowledgeJob,
    candidate: &KnowledgeCandidate,
    record: Option<&GenerationExecutionRecord>,
    sources: &KnowledgeSources,
) -> Result<KnowledgeProposal, KnowledgeError> {
    validate_job(job, sources)?;
    validate_claims(job, candidate, sources)?;
    let state = execution_state(job, candidate, record)?;
    let mut proposal = KnowledgeProposal {
        schema: "gtkg.qk.knowledge-proposal/v1".into(),
        job_digest: job.job_digest.clone(),
        candidate: candidate.clone(),
        execution_record: record.cloned(),
        state,
        proposal_digest: String::new(),
    };
    proposal.proposal_digest = seal(&proposal, "proposal_digest")?;
    Ok(proposal)
}
pub fn review_proposal(
    job: &KnowledgeJob,
    proposal: &KnowledgeProposal,
    reviews: &[IndependentReview],
    sources: &KnowledgeSources,
) -> Result<KnowledgeVerification, KnowledgeError> {
    if submit_proposal(
        job,
        &proposal.candidate,
        proposal.execution_record.as_ref(),
        sources,
    )? != *proposal
    {
        return Err(invalid("proposal identity drift"));
    }
    if proposal.state == "semantic_authoring_pending" {
        return Err(KnowledgeError::SemanticAuthoringPending);
    }
    if reviews.len() != 2 {
        return Err(invalid("two independent reviews required"));
    }
    let expected: BTreeMap<_, _> = proposal
        .candidate
        .claims
        .iter()
        .map(|c| Ok((c.claim_id.as_str(), claim_digest(c)?)))
        .collect::<Result<_, KnowledgeError>>()?;
    let mut reviewers = BTreeSet::new();
    let mut judgments: BTreeMap<String, usize> = BTreeMap::new();
    for review in reviews {
        nonempty(&review.reviewer_id)?;
        if !reviewers.insert(&review.reviewer_id)
            || review.reviewer_id == proposal.candidate.author_id
            || review.proposal_digest != proposal.proposal_digest
        {
            return Err(invalid("reviewer identity or reviewed proposal mismatch"));
        }
        let mut seen = BTreeSet::new();
        for decision in &review.decisions {
            nonempty(&decision.reason)?;
            if !seen.insert(decision.claim_id.as_str())
                || expected.get(decision.claim_id.as_str()) != Some(&decision.claim_digest)
            {
                return Err(invalid("review decision does not bind the exact claim"));
            }
            if decision.judgment == Judgment::Supported {
                *judgments.entry(decision.claim_id.clone()).or_default() += 1;
            }
        }
        if seen != expected.keys().copied().collect() {
            return Err(invalid("review claim denominator incomplete"));
        }
    }
    let mut supported = Vec::new();
    let mut covered = BTreeSet::new();
    let mut seen_propositions = BTreeSet::new();
    for claim in &proposal.candidate.claims {
        let known = !matches!(
            claim.body,
            ClaimBody::Interpretive {
                epistemic: EpistemicStatus::Unknown,
                ..
            }
        );
        if known && judgments.get(&claim.claim_id) == Some(&2) {
            supported.push(claim.claim_id.clone());
            if seen_propositions.insert(proposition_identity(claim)?) {
                covered.insert(claim.understanding_item.clone());
            }
        }
    }
    supported.sort();
    let mut verification = KnowledgeVerification {
        schema: "gtkg.qk.knowledge-verification/v1".into(),
        job_digest: job.job_digest.clone(),
        proposal_digest: proposal.proposal_digest.clone(),
        reviews: reviews.to_vec(),
        supported_claim_ids: supported,
        covered_understanding_items: covered.into_iter().collect(),
        verification_digest: String::new(),
    };
    verification.verification_digest = seal(&verification, "verification_digest")?;
    Ok(verification)
}
pub fn accept(
    job: &KnowledgeJob,
    proposal: &KnowledgeProposal,
    verification: &KnowledgeVerification,
    sources: &KnowledgeSources,
) -> Result<AcceptedKnowledge, KnowledgeError> {
    if review_proposal(job, proposal, &verification.reviews, sources)? != *verification {
        return Err(invalid("verification identity/decision drift"));
    }
    let mut seen = BTreeSet::new();
    let mut claims = Vec::new();
    for c in &proposal.candidate.claims {
        // Claim IDs, paraphrases and repeated citations are not coverage units.
        let key = proposition_identity(c)?;
        if verification.supported_claim_ids.contains(&c.claim_id) && seen.insert(key) {
            claims.push(c.clone());
        }
    }
    let assurance = match proposal
        .execution_record
        .as_ref()
        .map(|r| &r.execution_evidence)
    {
        Some(ExecutionEvidence::HostObserved) => "host_observed/not_independently_attested",
        Some(ExecutionEvidence::HumanRecorded) => "human_recorded_not_independently_attested",
        Some(ExecutionEvidence::StaticRecorded) => "static_recorded_not_semantic_authoring",
        _ => "unavailable",
    };
    Ok(AcceptedKnowledge {
        schema: "gtkg.qk.accepted-knowledge/v1".into(),
        job_digest: job.job_digest.clone(),
        proposal_digest: proposal.proposal_digest.clone(),
        verification_digest: verification.verification_digest.clone(),
        author_mode: proposal.candidate.author_mode.clone(),
        execution_assurance: assurance.into(),
        supported_claims: claims,
        covered_understanding_items: verification.covered_understanding_items.clone(),
        required_understanding_count: job.input.understanding_items.len(),
        knowledge_ready: job.input.goal == KnowledgeGoal::SemanticUnderstanding
            && proposal.state == "ready_for_review"
            && !job.input.understanding_items.is_empty()
            && verification.covered_understanding_items == job.input.understanding_items,
        llm_qa_validated: false,
    })
}

/// A complete reviewed chain is replayed before any knowledge enters a view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KnowledgeChain {
    pub job: KnowledgeJob,
    pub proposal: KnowledgeProposal,
    pub verification: KnowledgeVerification,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectViewKind {
    Overview,
    KeyFlows,
    DesignDecisions,
    AgentTaskGuide,
    ProjectRules,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleAspect {
    Purpose,
    InputsOutputs,
    MajorSymbols,
    StateData,
    Dependencies,
    FailureBranches,
    Evidence,
    Limitations,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectUnderstandingItem {
    pub item_id: String,
    pub question: String,
    pub view: ProjectViewKind,
    pub module_id: Option<String>,
    pub aspect: Option<ModuleAspect>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectModuleInput {
    pub module_id: String,
    pub name: String,
    pub subsystem: String,
    pub language: String,
    pub source_paths: Vec<String>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectKnowledgeInput {
    pub project_name: String,
    pub inventory_id: String,
    pub understanding_items: Vec<ProjectUnderstandingItem>,
    pub modules: Vec<ProjectModuleInput>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectSourceEntry {
    pub path: String,
    pub file_sha256: String,
    pub language: String,
    pub parse_status: String,
    pub variant_status: String,
    pub limitations: Vec<String>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectSymbolEntry {
    pub path: String,
    pub file_sha256: String,
    pub symbol_id: String,
    pub name: String,
    pub kind: String,
    pub span: Span,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SharedProjectInventory {
    pub inventory_id: String,
    pub sources: Vec<ProjectSourceEntry>,
    pub symbols: Vec<ProjectSymbolEntry>,
    pub verification_scope: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectClaimRef {
    pub job_digest: String,
    pub proposal_digest: String,
    pub verification_digest: String,
    pub claim_id: String,
    pub claim_digest: String,
    pub author_mode: AuthorMode,
    pub execution_assurance: String,
    pub epistemic: EpistemicStatus,
    pub version_condition: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectKnowledgeEntry {
    pub item_id: String,
    pub question: String,
    pub module_id: Option<String>,
    pub aspect: Option<ModuleAspect>,
    pub status: String,
    pub summary: String,
    pub claim_refs: Vec<ProjectClaimRef>,
    pub citations: Vec<Citation>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectView {
    pub kind: ProjectViewKind,
    pub title: String,
    pub responsibility: String,
    pub status: String,
    pub inventory_ref: String,
    pub items: Vec<ProjectKnowledgeEntry>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleAspectView {
    pub status: String,
    pub item_refs: Vec<String>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectModuleView {
    pub module_id: String,
    pub name: String,
    pub subsystem: String,
    pub language: String,
    pub source_paths: Vec<String>,
    pub inventory_ref: String,
    pub aspects: BTreeMap<ModuleAspect, ModuleAspectView>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnderstandingCoverage {
    pub required_items: Vec<String>,
    pub covered_items: Vec<String>,
    pub unknown_items: Vec<String>,
    pub unique_propositions: usize,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectKnowledgeViews {
    pub schema: String,
    pub project_name: String,
    pub navigation_metadata_origin: String,
    pub source_set_digest: String,
    pub analysis_context_digest: String,
    pub inventory: SharedProjectInventory,
    pub views: Vec<ProjectView>,
    pub modules: Vec<ProjectModuleView>,
    pub coverage: UnderstandingCoverage,
    pub readiness_scope: String,
    pub knowledge_ready: bool,
    pub llm_qa_validated: bool,
    pub view_digest: String,
}

pub fn project_views(
    input: &ProjectKnowledgeInput,
    chains: &[KnowledgeChain],
    sources: &KnowledgeSources,
) -> Result<ProjectKnowledgeViews, KnowledgeError> {
    nonempty(&input.project_name)?;
    nonempty(&input.inventory_id)?;
    nonempty(&sources.context.snapshot_id)?;
    if sources.raw_sources.is_empty()
        || input.understanding_items.is_empty()
        || input.understanding_items.len() > 4096
        || input.modules.len() > 1024
        || chains.len() > 4096
    {
        return Err(invalid(
            "missing project denominator/source or project bounds exceeded",
        ));
    }
    let mut module_ids = BTreeSet::new();
    for module in &input.modules {
        nonempty(&module.module_id)?;
        nonempty(&module.name)?;
        nonempty(&module.subsystem)?;
        nonempty(&module.language)?;
        unique_ordered(&module.source_paths)?;
        if !module_ids.insert(module.module_id.as_str()) || module.source_paths.is_empty() {
            return Err(invalid("duplicate module or missing module source"));
        }
        for path in &module.source_paths {
            source_path(path)?;
            if !sources.raw_sources.contains_key(path) {
                return Err(invalid(
                    "module source is outside the exact source inventory",
                ));
            }
        }
    }
    let mut entries = BTreeMap::new();
    for item in &input.understanding_items {
        nonempty(&item.item_id)?;
        nonempty(&item.question)?;
        if item.module_id.is_some() != item.aspect.is_some()
            || item
                .module_id
                .as_ref()
                .is_some_and(|id| !module_ids.contains(id.as_str()))
            || entries.contains_key(&item.item_id)
        {
            return Err(invalid(
                "duplicate item or invalid module/aspect assignment",
            ));
        }
        entries.insert(
            item.item_id.clone(),
            ProjectKnowledgeEntry {
                item_id: item.item_id.clone(),
                question: item.question.clone(),
                module_id: item.module_id.clone(),
                aspect: item.aspect,
                status: "unknown".into(),
                summary: "unknown".into(),
                claim_refs: vec![],
                citations: vec![],
            },
        );
    }
    // Every supplied chain is replayed, including duplicates and archive chains.
    // Archive material can be navigated in the inventory but never fills this
    // semantic understanding denominator.
    let mut selected = Vec::new();
    for chain in chains {
        let accepted = accept(&chain.job, &chain.proposal, &chain.verification, sources)?;
        if chain.job.input.goal != KnowledgeGoal::SemanticUnderstanding
            || accepted.author_mode == AuthorMode::StaticTranscription
            || chain.proposal.state != "ready_for_review"
        {
            continue;
        }
        for claim in accepted.supported_claims {
            if entries.contains_key(&claim.understanding_item) {
                selected.push((claim, chain, accepted.execution_assurance.clone()));
            }
        }
    }
    selected.sort_by(|a, b| {
        (
            &a.0.understanding_item,
            &a.1.proposal.proposal_digest,
            &a.0.claim_id,
        )
            .cmp(&(
                &b.0.understanding_item,
                &b.1.proposal.proposal_digest,
                &b.0.claim_id,
            ))
    });
    let mut propositions = BTreeSet::new();
    for (claim, chain, assurance) in selected {
        let summary = project_claim_summary(&claim);
        if summary.is_empty() {
            continue;
        }
        let mut normalized = claim.clone();
        if let ClaimBody::Interpretive { proposition, .. } = &mut normalized.body {
            *proposition = display_proposition_identity(&summary);
        }
        if !propositions.insert(proposition_identity(&normalized)?) {
            continue;
        }
        let (epistemic, version_condition) = match &claim.body {
            ClaimBody::Structural { .. } => (EpistemicStatus::Direct, None),
            ClaimBody::Interpretive {
                epistemic,
                version_condition,
                ..
            } => (epistemic.clone(), Some(version_condition.clone())),
        };
        let entry = entries
            .get_mut(&claim.understanding_item)
            .ok_or_else(|| invalid("understanding item disappeared"))?;
        if entry.claim_refs.is_empty() {
            entry.summary = summary;
        } else {
            entry.summary.push_str("\n\n");
            entry.summary.push_str(&summary);
        }
        entry.status = "supported".into();
        entry.claim_refs.push(ProjectClaimRef {
            job_digest: chain.job.job_digest.clone(),
            proposal_digest: chain.proposal.proposal_digest.clone(),
            verification_digest: chain.verification.verification_digest.clone(),
            claim_id: claim.claim_id.clone(),
            claim_digest: claim_digest(&claim)?,
            author_mode: chain.proposal.candidate.author_mode.clone(),
            execution_assurance: assurance,
            epistemic,
            version_condition,
        });
        for citation in claim.citations {
            if !entry.citations.contains(&citation) {
                entry.citations.push(citation);
            }
        }
    }
    let mut identities = BTreeMap::new();
    let mut inventory = SharedProjectInventory {
        inventory_id: input.inventory_id.clone(),
        sources: vec![],
        symbols: vec![],
        verification_scope:
            "exact_source_hashes_and_bounded_static_extraction; not_runtime_or_semantic_coverage"
                .into(),
    };
    for (path, raw) in &sources.raw_sources {
        source_path(path)?;
        let file_sha = digest(raw);
        identities.insert(path.clone(), file_sha.clone());
        let mut entry = ProjectSourceEntry {
            path: path.clone(),
            file_sha256: file_sha.clone(),
            language: material_language(path).into(),
            parse_status: "not_code".into(),
            variant_status: "not_applicable".into(),
            limitations: vec![],
        };
        if is_code(path) {
            match gtkg_extract::v04::extract(path, raw, &sources.context) {
                Ok(file) => {
                    entry.language = file.language;
                    entry.parse_status = file.parse_status;
                    entry.variant_status = file.variant_status;
                    entry.limitations = file.limitations;
                    if entry.parse_status == "parsed" && entry.variant_status == "active" {
                        for declaration in file.declarations {
                            inventory.symbols.push(ProjectSymbolEntry {
                                path: path.clone(),
                                file_sha256: file_sha.clone(),
                                symbol_id: declaration.id,
                                name: declaration.name,
                                kind: declaration.kind,
                                span: declaration.name_span,
                            });
                        }
                    }
                }
                Err(error) => {
                    entry.parse_status = "unavailable".into();
                    entry.variant_status = "unknown".into();
                    entry.limitations.push(error.to_string());
                }
            }
        }
        inventory.sources.push(entry);
    }
    let mut modules = Vec::new();
    for module in &input.modules {
        let languages: BTreeSet<_> = inventory
            .sources
            .iter()
            .filter(|source| module.source_paths.contains(&source.path))
            .map(|source| source.language.as_str())
            .collect();
        let language = languages.into_iter().collect::<Vec<_>>().join(", ");
        if module.language != language {
            return Err(invalid(
                "module language disagrees with its source inventory",
            ));
        }
        let aspects = MODULE_ASPECTS
            .into_iter()
            .map(|aspect| {
                let items: Vec<_> = entries
                    .values()
                    .filter(|entry| {
                        entry.module_id.as_deref() == Some(module.module_id.as_str())
                            && entry.aspect == Some(aspect)
                    })
                    .collect();
                let status =
                    if !items.is_empty() && items.iter().all(|entry| entry.status == "supported") {
                        "supported"
                    } else if items.iter().any(|entry| entry.status == "supported") {
                        "partial"
                    } else {
                        "unknown"
                    };
                (
                    aspect,
                    ModuleAspectView {
                        status: status.into(),
                        item_refs: items.iter().map(|entry| entry.item_id.clone()).collect(),
                    },
                )
            })
            .collect();
        modules.push(ProjectModuleView {
            module_id: module.module_id.clone(),
            name: module.name.clone(),
            subsystem: module.subsystem.clone(),
            language,
            source_paths: module.source_paths.clone(),
            inventory_ref: input.inventory_id.clone(),
            aspects,
        });
    }
    modules.sort_by(|a, b| a.module_id.cmp(&b.module_id));
    let views = PROJECT_VIEWS
        .into_iter()
        .map(|(kind, title, responsibility)| {
            let item_ids: BTreeSet<_> = input
                .understanding_items
                .iter()
                .filter(|item| item.view == kind)
                .map(|item| item.item_id.as_str())
                .collect();
            let items: Vec<_> = entries
                .values()
                .filter(|entry| item_ids.contains(entry.item_id.as_str()))
                .cloned()
                .collect();
            let status = if !items.is_empty() && items.iter().all(|item| item.status == "supported")
            {
                "supported"
            } else if items.iter().any(|item| item.status == "supported") {
                "partial"
            } else {
                "unknown"
            };
            ProjectView {
                kind,
                title: title.into(),
                responsibility: responsibility.into(),
                status: status.into(),
                inventory_ref: input.inventory_id.clone(),
                items,
            }
        })
        .collect();
    let coverage = UnderstandingCoverage {
        required_items: entries.keys().cloned().collect(),
        covered_items: entries
            .values()
            .filter(|entry| entry.status == "supported")
            .map(|entry| entry.item_id.clone())
            .collect(),
        unknown_items: entries
            .values()
            .filter(|entry| entry.status == "unknown")
            .map(|entry| entry.item_id.clone())
            .collect(),
        unique_propositions: propositions.len(),
    };
    let mut output = ProjectKnowledgeViews {
        schema: "gtkg.qk.project-knowledge-views/v1".into(),
        project_name: input.project_name.clone(),
        navigation_metadata_origin:
            "caller_supplied_navigation; semantic_body_requires_replayed_reviews".into(),
        source_set_digest: digest(&encoded(&identities)?),
        analysis_context_digest: gtkg_extract::v04::context_digest(&sources.context),
        inventory,
        views,
        modules,
        knowledge_ready: coverage.unknown_items.is_empty(),
        readiness_scope:
            "declared_understanding_items_only; other_view_and_module_unknowns_remain_visible"
                .into(),
        coverage,
        llm_qa_validated: false,
        view_digest: String::new(),
    };
    output.view_digest = seal(&output, "view_digest")?;
    Ok(output)
}

const MODULE_ASPECTS: [ModuleAspect; 8] = [
    ModuleAspect::Purpose,
    ModuleAspect::InputsOutputs,
    ModuleAspect::MajorSymbols,
    ModuleAspect::StateData,
    ModuleAspect::Dependencies,
    ModuleAspect::FailureBranches,
    ModuleAspect::Evidence,
    ModuleAspect::Limitations,
];
const PROJECT_VIEWS: [(ProjectViewKind, &str, &str); 5] = [
    (
        ProjectViewKind::Overview,
        "项目总览",
        "项目目标、边界、子系统和入口；区分文档意图与已审查实现",
    ),
    (
        ProjectViewKind::KeyFlows,
        "关键流程",
        "用户动作、前端、桥、Controller、Agent、持久化之间的转换和异常",
    ),
    (
        ProjectViewKind::DesignDecisions,
        "设计与决策",
        "有来源的设计理由、约束与备选；缺少依据的决策保留 unknown",
    ),
    (
        ProjectViewKind::AgentTaskGuide,
        "Agent 任务导览",
        "问题和改动入口、阅读路径、影响范围及需要进一步核查的位置",
    ),
    (
        ProjectViewKind::ProjectRules,
        "项目规则",
        "构建、配置与开发边界及其适用范围；规则作为资料而非执行指令",
    ),
];

fn material_language(path: &str) -> &str {
    match path.rsplit('.').next().unwrap_or("") {
        "md" | "mdx" => "markdown",
        "json" => "json",
        "yaml" | "yml" => "yaml",
        "toml" => "toml",
        "go" => "go",
        "rs" => "rust",
        "py" | "pyi" => "python",
        "ts" | "tsx" | "mts" | "cts" => "typescript",
        "js" | "jsx" | "mjs" | "cjs" => "javascript",
        _ => "unknown",
    }
}

fn project_claim_summary(claim: &KnowledgeClaim) -> String {
    match &claim.body {
        ClaimBody::Structural {
            predicate: Predicate::Declares { path, name, kind },
            polarity,
        } => format!(
            "{path} {} {kind} {name}。",
            if *polarity { "定义" } else { "未定义" }
        ),
        ClaimBody::Structural {
            predicate:
                Predicate::Calls {
                    call_id,
                    source_path,
                    target_path,
                    target_id,
                },
            ..
        } => format!("{source_path} 的调用 {call_id} 解析到 {target_path} 的符号 {target_id}。"),
        ClaimBody::Interpretive { proposition, .. } => structured_body(proposition),
    }
}

/// Display the reviewed body, not candidate summaries, headings or generation
/// metadata. The original exact claim remains available through its digest.
fn structured_body(text: &str) -> String {
    let visible = strip_noncode_html_comments(text);
    let lines: Vec<_> = visible
        .trim_start_matches('\u{feff}')
        .trim()
        .lines()
        .collect();
    let mut start = 0;
    if let Some(first) = lines.first().map(|line| line.trim())
        && (first == "---" || first == "+++")
    {
        let Some(end) = lines
            .iter()
            .enumerate()
            .skip(1)
            .find(|(_, line)| {
                let line = line.trim();
                line == first || (first == "---" && line == "...")
            })
            .map(|(i, _)| i)
        else {
            return String::new();
        };
        start = end + 1;
    }
    let mut body = Vec::new();
    let mut cursor = start;
    while cursor < lines.len() {
        let line = lines[cursor].trim();
        if let Some((marker, count)) = fence_marker(line) {
            let close = (cursor + 1..lines.len()).find(|index| {
                let candidate = lines[*index].trim();
                candidate.chars().all(|c| c == marker) && candidate.len() >= count
            });
            let end = close.unwrap_or(lines.len());
            let content = &lines[cursor + 1..end];
            // Discard metadata-only fences. Real code is retained verbatim,
            // including indentation, operators and metadata-like field names.
            if content
                .iter()
                .any(|part| !part.trim().is_empty() && !generation_metadata(part.trim()))
            {
                body.extend_from_slice(&lines[cursor..close.map_or(end, |n| n + 1)]);
            }
            cursor = close.map_or(end, |n| n + 1);
            continue;
        }
        if !line.starts_with('#')
            && !setext_marker(line)
            && !lines
                .get(cursor + 1)
                .is_some_and(|next| setext_marker(next.trim()))
            && !generation_metadata(line)
        {
            body.push(line);
        }
        cursor += 1;
    }
    body.join("\n").trim().to_owned()
}

fn strip_noncode_html_comments(text: &str) -> String {
    let mut output = String::new();
    let mut fence = None;
    let mut comment = false;
    for line in text.split_inclusive('\n') {
        if let Some((marker, count)) = fence {
            output.push_str(line);
            let trimmed = line.trim();
            if trimmed.len() >= count && trimmed.chars().all(|c| c == marker) {
                fence = None;
            }
            continue;
        }
        if !comment && let Some(open) = fence_marker(line.trim()) {
            fence = Some(open);
            output.push_str(line);
            continue;
        }
        let mut remaining = line;
        loop {
            if comment {
                let Some(end) = remaining.find("-->") else {
                    break;
                };
                remaining = &remaining[end + 3..];
                comment = false;
            } else if let Some(start) = remaining.find("<!--") {
                output.push_str(&remaining[..start]);
                remaining = &remaining[start + 4..];
                comment = true;
            } else {
                output.push_str(remaining);
                break;
            }
        }
    }
    output
}

fn setext_marker(text: &str) -> bool {
    text.len() >= 3 && (text.bytes().all(|b| b == b'=') || text.bytes().all(|b| b == b'-'))
}

fn fence_marker(line: &str) -> Option<(char, usize)> {
    let marker = line.chars().next()?;
    if !matches!(marker, '`' | '~') {
        return None;
    }
    let count = line.chars().take_while(|c| *c == marker).count();
    (count >= 3).then_some((marker, count))
}

fn generation_metadata(line: &str) -> bool {
    let line = ["- ", "* ", "+ "]
        .iter()
        .find_map(|prefix| line.strip_prefix(prefix))
        .unwrap_or(line);
    let key = line
        .split_once([':', '：'])
        .map(|(key, _)| key.trim_matches('*').trim().to_lowercase());
    key.as_deref().is_some_and(|key| {
        matches!(
            key,
            "model"
                | "model_id"
                | "generator"
                | "generated_by"
                | "generated_at"
                | "author"
                | "模型"
                | "生成模型"
                | "生成器"
        )
    })
}

fn display_proposition_identity(summary: &str) -> String {
    let mut text = summary.trim();
    // Remove a paired whole-proposition bold wrapper, never arbitrary stars
    // inside code, identifiers or arithmetic expressions.
    if let Some(inner) = text.strip_prefix("**").and_then(|s| s.strip_suffix("**"))
        && !inner.is_empty()
        && !inner.starts_with(char::is_whitespace)
        && !inner.ends_with(char::is_whitespace)
        && !inner.contains("**")
    {
        text = inner;
    }
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}
