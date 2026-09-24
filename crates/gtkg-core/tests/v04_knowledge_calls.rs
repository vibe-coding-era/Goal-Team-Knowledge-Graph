//! Integration readback against the real T03 verifier, not a verified boolean.
use gtkg_core::v04::knowledge::*;
use gtkg_extract::v04::{AnalysisContext, Span, binding, extract};
use std::collections::BTreeMap;

fn case() -> (KnowledgeSources, KnowledgeJob, KnowledgeCandidate) {
    let raw = b"package p\nfunc Entry() {}\nfunc Run() { Entry() }\n".to_vec();
    let context = AnalysisContext { snapshot_id: "fixture-calls-snapshot".into(), ..AnalysisContext::default() };
    let file = extract("main.go", &raw, &context).unwrap();
    let proofs = binding::bind(std::slice::from_ref(&file), &context);
    let target = file.declarations.iter().find(|d| d.name == "Entry").unwrap();
    let sources = KnowledgeSources { raw_sources: BTreeMap::from([
        ("main.go".into(), raw.clone()), ("README.md".into(), b"fixture documentation".to_vec())]), context, call_proofs: proofs };
    let job = prepare_job(&KnowledgeInput { job_id: "calls-job".into(), goal: KnowledgeGoal::SemanticUnderstanding,
        source_paths: vec!["README.md".into(), "main.go".into()], understanding_items: vec!["flow".into()],
        prompt: "Fixture explain flow".into(), policy: "fixture-policy".into(), max_context_units: 8000, source_spans:BTreeMap::new() }, &sources).unwrap();
    let candidate = KnowledgeCandidate { author_id: "fixture-author".into(), author_mode: AuthorMode::HumanAuthored,
        summary: "Run calls Entry in the frozen fixture".into(), claims: vec![KnowledgeClaim {
            claim_id: "flow-1".into(), understanding_item: "flow".into(), natural_language: "Run calls Entry".into(),
            body: ClaimBody::Structural { predicate: Predicate::Calls { call_id: file.calls[0].id.clone(),
                source_path: "main.go".into(), target_path: "main.go".into(), target_id: target.id.clone() }, polarity: true },
            citations: vec![Citation { path: "main.go".into(), file_sha256: digest(&raw),
                span: Span { byte_start: 0, byte_end: raw.len(), line_start: 1, line_end: 3 }, excerpt: String::from_utf8(raw).unwrap() }] }] };
    (sources, job, candidate)
}
fn record(job: &KnowledgeJob, candidate: &KnowledgeCandidate) -> GenerationExecutionRecord {
    let output = serde_json::to_string(candidate).unwrap();
    GenerationExecutionRecord { schema: "gtkg.qk.generation-execution-record/v1".into(), job_digest: job.job_digest.clone(),
        context_digest: job.context_digest.clone(), prompt_digest: job.prompt_digest.clone(), policy_digest: job.policy_digest.clone(),
        author_id: candidate.author_id.clone(), author_mode: candidate.author_mode.clone(), execution_evidence: ExecutionEvidence::HumanRecorded,
        host_id: None, model_id: None, transcript: None, transcript_digest: None,
        output_digest: digest(output.as_bytes()), output, usage: Usage { input_tokens: None, output_tokens: None } }
}
fn reviews(p: &KnowledgeProposal) -> Vec<IndependentReview> {
    ["fixture-qa-a", "fixture-qa-b"].into_iter().map(|id| IndependentReview { reviewer_id: id.into(),
        proposal_digest: p.proposal_digest.clone(), decisions: p.candidate.claims.iter().map(|c| ClaimReview {
            claim_id: c.claim_id.clone(), claim_digest: claim_digest(c).unwrap(), judgment: Judgment::Supported, reason: "fixture inspected".into() }).collect() }).collect()
}
#[test]
fn calls_accepts_actual_replayed_graph_with_documents_outside_code_exact_set() {
    let (s, j, c) = case();
    assert_eq!(binding::confirmed_edges(&s.call_proofs, &BTreeMap::from([("main.go".into(), s.raw_sources["main.go"].clone())]), &s.context).unwrap().len(), 1);
    let p = submit_proposal(&j, &c, Some(&record(&j, &c)), &s).unwrap();
    let v = review_proposal(&j, &p, &reviews(&p), &s).unwrap();
    assert!(accept(&j, &p, &v, &s).unwrap().knowledge_ready);
    let mut incomplete = s.clone(); incomplete.call_proofs.clear();
    assert!(submit_proposal(&j, &c, Some(&record(&j, &c)), &incomplete).is_err());
}
#[test]
fn unknown_explanation_is_not_promoted_by_positive_reviewer_labels() {
    let (s, j, mut c) = case();
    c.claims[0].body = ClaimBody::Interpretive { proposition: "Design motivation is unknown".into(),
        epistemic: EpistemicStatus::Unknown, version_condition: "fixture-calls-snapshot".into() };
    let p = submit_proposal(&j, &c, Some(&record(&j, &c)), &s).unwrap();
    let v = review_proposal(&j, &p, &reviews(&p), &s).unwrap();
    let a = accept(&j, &p, &v, &s).unwrap();
    assert!(!a.knowledge_ready); assert!(a.covered_understanding_items.is_empty());
}
#[test]
fn forged_verification_projection_cannot_bypass_replay_of_review_decisions() {
    let (s, j, c) = case();
    let p = submit_proposal(&j, &c, Some(&record(&j, &c)), &s).unwrap();
    let mut rr = reviews(&p); rr[1].decisions[0].judgment = Judgment::Rejected;
    let mut v = review_proposal(&j, &p, &rr, &s).unwrap();
    v.supported_claim_ids.push(c.claims[0].claim_id.clone()); v.covered_understanding_items.push("flow".into());
    assert!(accept(&j, &p, &v, &s).is_err());
}
