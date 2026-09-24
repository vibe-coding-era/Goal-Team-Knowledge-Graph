//! Additional semantic-view gates: archive, unknown and metadata-only material.
use gtkg_core::v04::knowledge::*;
use gtkg_extract::v04::{AnalysisContext, Span};
use std::collections::BTreeMap;

fn fixture(mode: AuthorMode, goal: KnowledgeGoal, texts: &[&str]) -> (KnowledgeSources, ProjectKnowledgeInput, KnowledgeChain) {
    let raw = "A documentation excerpt supports the fixture review.\n";
    let sources = KnowledgeSources { raw_sources: BTreeMap::from([("README.md".into(), raw.as_bytes().to_vec())]),
        context: AnalysisContext { snapshot_id: "fixture-view-constraints".into(), ..AnalysisContext::default() }, call_proofs: vec![] };
    let kinds = [ProjectViewKind::Overview, ProjectViewKind::KeyFlows, ProjectViewKind::DesignDecisions, ProjectViewKind::AgentTaskGuide, ProjectViewKind::ProjectRules];
    let input = ProjectKnowledgeInput { project_name: "Agent Nine".into(), inventory_id: "shared".into(), modules: vec![],
        understanding_items: texts.iter().enumerate().map(|(n,_)| ProjectUnderstandingItem { item_id: format!("item-{n}"),
            question: format!("Fixture question {n}"), view: kinds[n % 5], module_id: None, aspect: None }).collect() };
    let job = prepare_job(&KnowledgeInput { job_id: "view-constraints".into(), goal,
        source_paths: vec!["README.md".into()], understanding_items: input.understanding_items.iter().map(|i| i.item_id.clone()).collect(),
        prompt: "Explain the selected questions".into(), policy: "fixture".into(), max_context_units: 8000, source_spans: BTreeMap::new() }, &sources).unwrap();
    let candidate = KnowledgeCandidate { author_id: "fixture-author".into(), author_mode: mode.clone(), summary: "metadata is not knowledge".into(),
        claims: texts.iter().enumerate().map(|(n,text)| KnowledgeClaim { claim_id: format!("claim-{n}"), understanding_item: format!("item-{n}"),
            natural_language: text.to_string(), body: ClaimBody::Interpretive { proposition: text.to_string(), epistemic: EpistemicStatus::Direct,
                version_condition: "fixture-view-constraints".into() }, citations: vec![Citation { path: "README.md".into(), file_sha256: digest(raw.as_bytes()),
                    span: Span { byte_start: 0, byte_end: raw.len(), line_start: 1, line_end: 1 }, excerpt: raw.into() }] }).collect() };
    let output = serde_json::to_string(&candidate).unwrap();
    let record = GenerationExecutionRecord { schema: "gtkg.qk.generation-execution-record/v1".into(), job_digest: job.job_digest.clone(),
        context_digest: job.context_digest.clone(), prompt_digest: job.prompt_digest.clone(), policy_digest: job.policy_digest.clone(),
        author_id: candidate.author_id.clone(), author_mode: mode.clone(),
        execution_evidence: if mode == AuthorMode::StaticTranscription { ExecutionEvidence::StaticRecorded } else { ExecutionEvidence::HumanRecorded },
        host_id: None, model_id: None, transcript: None, transcript_digest: None, output_digest: digest(output.as_bytes()), output,
        usage: Usage { input_tokens: None, output_tokens: None } };
    let proposal = submit_proposal(&job, &candidate, Some(&record), &sources).unwrap();
    let reviews = ["fixture-review-a", "fixture-review-b"].into_iter().map(|id| IndependentReview { reviewer_id: id.into(), proposal_digest: proposal.proposal_digest.clone(),
        decisions: candidate.claims.iter().map(|c| ClaimReview { claim_id: c.claim_id.clone(), claim_digest: claim_digest(c).unwrap(), judgment: Judgment::Supported,
            reason: "Synthetic fixture review".into() }).collect() }).collect::<Vec<_>>();
    let verification = review_proposal(&job, &proposal, &reviews, &sources).unwrap();
    (sources, input, KnowledgeChain { job, proposal, verification })
}
#[test]
fn static_archive_claims_remain_inventory_material_and_never_semantic_coverage() {
    let (s, i, c) = fixture(AuthorMode::StaticTranscription, KnowledgeGoal::Archive, &["The fixture copies documentation."]);
    let views = project_views(&i, &[c], &s).unwrap();
    assert!(!views.knowledge_ready);
    assert!(views.coverage.covered_items.is_empty());
    assert_eq!(views.coverage.unknown_items, vec!["item-0"]);
    assert!(views.views.iter().all(|v| v.status == "unknown"));
    assert_eq!(views.inventory.sources.len(), 1);
}
#[test]
fn metadata_changes_and_new_ids_cannot_make_one_body_fill_two_view_questions() {
    let (s, i, c) = fixture(AuthorMode::HumanAuthored, KnowledgeGoal::SemanticUnderstanding, &[
        "---\nmodel: first\n---\n# First heading\nThe same reviewed proposition.",
        "---\nmodel: second\n---\n# Second heading\nThe same reviewed proposition."]);
    let views = project_views(&i, &[c], &s).unwrap();
    assert_eq!(views.coverage.covered_items, vec!["item-0"]);
    assert_eq!(views.coverage.unique_propositions, 1);
    assert_eq!(views.views[1].items[0].status, "unknown");
}
#[test]
fn markdown_setext_and_localized_model_headers_cannot_become_knowledge_body() {
    let (s, i, c) = fixture(AuthorMode::HumanAuthored, KnowledgeGoal::SemanticUnderstanding, &[
        "Fixture generated title\n=======================\n模型：pretend-model\n生成器：fixture\n<!-- generator metadata -->",
        "### Title\nmodel: pretend-model\ngenerator: fixture"]);
    let views = project_views(&i, &[c], &s).unwrap();
    assert!(views.coverage.covered_items.is_empty(), "headings and generation labels are not reviewed semantic content");
    assert!(views.views.iter().flat_map(|v| &v.items).all(|item| item.summary == "unknown"));
}
#[test]
fn structured_metadata_cleanup_preserves_actual_negation_and_version_in_body() {
    let (s, i, c) = fixture(AuthorMode::HumanAuthored, KnowledgeGoal::SemanticUnderstanding,
        &["# Local behavior\nThe controller does not execute remote commands in version 0.4."]);
    let views = project_views(&i, &[c], &s).unwrap();
    assert_eq!(views.views[0].items[0].summary, "The controller does not execute remote commands in version 0.4.");
    assert_eq!(views.views[0].items[0].claim_refs[0].version_condition.as_deref(), Some("fixture-view-constraints"));
    assert!(!views.llm_qa_validated);
}
