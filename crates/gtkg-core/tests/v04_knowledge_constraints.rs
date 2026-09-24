//! Adversarial source visibility and coverage tests; synthetic human records only.
use gtkg_core::v04::knowledge::*;
use gtkg_extract::v04::{AnalysisContext, Span, binding, extract};
use std::collections::BTreeMap;

fn span(raw: &str, needle: &str) -> Span {
    let start = raw.find(needle).unwrap();
    let end = start + needle.len();
    Span { byte_start: start, byte_end: end,
        line_start: raw[..start].bytes().filter(|b| *b == b'\n').count() + 1,
        line_end: raw[..end - 1].bytes().filter(|b| *b == b'\n').count() + 1 }
}
fn fixture() -> (KnowledgeSources, KnowledgeInput) {
    let raw = "package p\nfunc Target() {}\nfunc Run() { Target() }\n";
    let context = AnalysisContext { snapshot_id: "fixture-constraints".into(), ..AnalysisContext::default() };
    let file = extract("main.go", raw.as_bytes(), &context).unwrap();
    let sources = KnowledgeSources { raw_sources: BTreeMap::from([("main.go".into(), raw.as_bytes().to_vec())]),
        call_proofs: binding::bind(&[file], &context), context };
    let input = KnowledgeInput { job_id: "constraints-job".into(), goal: KnowledgeGoal::SemanticUnderstanding,
        source_paths: vec!["main.go".into()], understanding_items: vec!["entry".into(), "flow".into()],
        prompt: "Explain observed source".into(), policy: "fixture-policy".into(), max_context_units: 8000,
        source_spans: BTreeMap::new() };
    (sources, input)
}
fn citation(s: &KnowledgeSources, needle: &str) -> Citation {
    let raw = std::str::from_utf8(&s.raw_sources["main.go"]).unwrap();
    Citation { path: "main.go".into(), file_sha256: digest(raw.as_bytes()), span: span(raw, needle), excerpt: needle.into() }
}
fn claim(s: &KnowledgeSources) -> KnowledgeCandidate {
    KnowledgeCandidate { author_id: "fixture-author".into(), author_mode: AuthorMode::HumanAuthored,
        summary: "Target is declared".into(), claims: vec![KnowledgeClaim { claim_id: "a".into(),
            understanding_item: "entry".into(), natural_language: "Target is declared".into(),
            body: ClaimBody::Structural { predicate: Predicate::Declares { path: "main.go".into(),
                name: "Target".into(), kind: "function".into() }, polarity: true },
            citations: vec![citation(s, "func Target() {}\n")] }] }
}
fn accepted(j: &KnowledgeJob, c: &KnowledgeCandidate, s: &KnowledgeSources) -> AcceptedKnowledge {
    let output = serde_json::to_string(c).unwrap();
    let record = GenerationExecutionRecord { schema: "gtkg.qk.generation-execution-record/v1".into(),
        job_digest: j.job_digest.clone(), context_digest: j.context_digest.clone(), prompt_digest: j.prompt_digest.clone(),
        policy_digest: j.policy_digest.clone(), author_id: c.author_id.clone(), author_mode: c.author_mode.clone(),
        execution_evidence: ExecutionEvidence::HumanRecorded, host_id: None, model_id: None, transcript: None,
        transcript_digest: None, output_digest: digest(output.as_bytes()), output,
        usage: Usage { input_tokens: None, output_tokens: None } };
    let proposal = submit_proposal(j, c, Some(&record), s).unwrap();
    let reviews = ["fixture-review-a", "fixture-review-b"].into_iter().map(|id| IndependentReview {
        reviewer_id: id.into(), proposal_digest: proposal.proposal_digest.clone(),
        decisions: c.claims.iter().map(|claim| ClaimReview { claim_id: claim.claim_id.clone(),
            claim_digest: claim_digest(claim).unwrap(), judgment: Judgment::Supported,
            reason: "Synthetic fixture: inspected".into() }).collect() }).collect::<Vec<_>>();
    let verification = review_proposal(j, &proposal, &reviews, s).unwrap();
    accept(j, &proposal, &verification, s).unwrap()
}
#[test]
fn windows_share_one_total_budget_and_cannot_exceed_the_global_cap() {
    let (s, mut i) = fixture();
    let raw = std::str::from_utf8(&s.raw_sources["main.go"]).unwrap();
    let a = "func Target() {}\n";
    let b = "func Run() { Target() }\n";
    i.source_spans.insert("main.go".into(), vec![span(raw, a), span(raw, b)]);
    i.max_context_units = a.chars().count() + b.chars().count() - 1;
    assert!(prepare_job(&i, &s).is_err());
    i.max_context_units += 1;
    assert_eq!(prepare_job(&i, &s).unwrap().context.len(), 2);
    i.max_context_units = 8001;
    assert!(prepare_job(&i, &s).is_err());
}
#[test]
fn repeated_body_relabelled_with_new_ids_and_items_cannot_fill_the_denominator() {
    let (s, i) = fixture();
    let j = prepare_job(&i, &s).unwrap();
    let mut c = claim(&s);
    let mut duplicate = c.claims[0].clone();
    duplicate.claim_id = "b".into();
    duplicate.understanding_item = "flow".into();
    duplicate.natural_language = "The Target function exists".into();
    c.claims.push(duplicate);
    let a = accepted(&j, &c, &s);
    assert_eq!(a.covered_understanding_items, vec!["entry"]);
    assert_eq!(a.supported_claims.len(), 1);
    assert!(!a.knowledge_ready);
}
#[test]
fn same_file_call_claim_cannot_assert_an_unobserved_target_declaration() {
    let (s, mut i) = fixture();
    let raw = std::str::from_utf8(&s.raw_sources["main.go"]).unwrap();
    let run = "func Run() { Target() }\n";
    i.source_spans.insert("main.go".into(), vec![span(raw, run)]);
    let j = prepare_job(&i, &s).unwrap();
    let proof = &s.call_proofs[0];
    let mut c = claim(&s);
    c.claims[0].body = ClaimBody::Structural { predicate: Predicate::Calls { call_id: proof.call.id.clone(),
        source_path: "main.go".into(), target_path: "main.go".into(), target_id: proof.target.as_ref().unwrap().declaration.id.clone() }, polarity: true };
    c.claims[0].citations = vec![citation(&s, run)];
    assert!(submit_proposal(&j, &c, None, &s).is_err(), "source name alone cannot establish which unseen declaration resolves");
    i.source_spans.clear();
    let full = prepare_job(&i, &s).unwrap();
    c.claims[0].citations.push(citation(&s, "func Target() {}\n"));
    assert!(submit_proposal(&full, &c, None, &s).is_ok());
}
