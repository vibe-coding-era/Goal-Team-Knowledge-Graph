//! Project understanding views from exact reviewed chains; no real model QA.
use gtkg_core::v04::knowledge::*;
use gtkg_extract::v04::{AnalysisContext, Span};
use std::collections::{BTreeMap, BTreeSet};

fn fixture() -> (KnowledgeSources, ProjectKnowledgeInput, KnowledgeChain) {
    let text = "Agent Nine coordinates local agent tasks.\nThe user request reaches the controller.\nLocal persistence keeps task history.\nRead the controller before changing task execution.\nBuild rules apply to the desktop workspace.\n";
    let sources = KnowledgeSources { raw_sources: BTreeMap::from([("README.md".into(), text.as_bytes().to_vec()),
        ("main.go".into(), b"package p\nfunc Entry() {}\n".to_vec())]),
        context: AnalysisContext { snapshot_id: "fixture-views".into(), ..AnalysisContext::default() }, call_proofs: vec![] };
    let kinds = [ProjectViewKind::Overview, ProjectViewKind::KeyFlows, ProjectViewKind::DesignDecisions,
        ProjectViewKind::AgentTaskGuide, ProjectViewKind::ProjectRules];
    let items = kinds.into_iter().enumerate().map(|(n, view)| ProjectUnderstandingItem {
        item_id: format!("item-{n}"), question: format!("Independent fixture question {n}"), view,
        module_id: Some("controller".into()), aspect: Some(ModuleAspect::Purpose) }).collect::<Vec<_>>();
    let input = ProjectKnowledgeInput { project_name: "Agent Nine".into(), inventory_id: "shared-source-symbols".into(),
        understanding_items: items, modules: vec![ProjectModuleInput { module_id: "controller".into(),
            name: "Task Controller".into(), subsystem: "Desktop Runtime".into(), language: "go".into(),
            source_paths: vec!["main.go".into()] }] };
    let job = prepare_job(&KnowledgeInput { job_id: "views-job".into(), goal: KnowledgeGoal::SemanticUnderstanding,
        source_paths: vec!["README.md".into(), "main.go".into()],
        understanding_items: input.understanding_items.iter().map(|i| i.item_id.clone()).collect(),
        prompt: "Explain five distinct project questions".into(), policy: "fixture-policy".into(),
        max_context_units: 8000, source_spans: BTreeMap::new() }, &sources).unwrap();
    let candidate = KnowledgeCandidate { author_id: "fixture-human".into(), author_mode: AuthorMode::HumanAuthored,
        summary: "model: fake-summary-header-must-not-be-used".into(),
        claims: text.lines().enumerate().map(|(n, line)| KnowledgeClaim { claim_id: format!("claim-{n}"),
            understanding_item: format!("item-{n}"), natural_language: "model: header-must-not-be-used".into(),
            body: ClaimBody::Interpretive { proposition: format!("---\nmodel: fake-frontmatter\ngenerator: fixture\n---\n# Metadata heading\nmodel: fake-header\ngenerator: fixture\n\n{line}"),
                epistemic: EpistemicStatus::Direct, version_condition: "fixture-views".into() },
            citations: vec![Citation { path: "README.md".into(), file_sha256: digest(text.as_bytes()),
                span: Span { byte_start: 0, byte_end: text.len(), line_start: 1, line_end: 5 }, excerpt: text.into() }] }).collect() };
    let output = serde_json::to_string(&candidate).unwrap();
    let record = GenerationExecutionRecord { schema: "gtkg.qk.generation-execution-record/v1".into(),
        job_digest: job.job_digest.clone(), context_digest: job.context_digest.clone(), prompt_digest: job.prompt_digest.clone(),
        policy_digest: job.policy_digest.clone(), author_id: candidate.author_id.clone(), author_mode: candidate.author_mode.clone(),
        execution_evidence: ExecutionEvidence::HumanRecorded, host_id: None, model_id: None, transcript: None,
        transcript_digest: None, output_digest: digest(output.as_bytes()), output,
        usage: Usage { input_tokens: None, output_tokens: None } };
    let proposal = submit_proposal(&job, &candidate, Some(&record), &sources).unwrap();
    let reviews = ["fixture-review-a", "fixture-review-b"].into_iter().map(|id| IndependentReview { reviewer_id: id.into(),
        proposal_digest: proposal.proposal_digest.clone(), decisions: candidate.claims.iter().map(|c| ClaimReview {
            claim_id: c.claim_id.clone(), claim_digest: claim_digest(c).unwrap(), judgment: Judgment::Supported,
            reason: "Synthetic fixture: independent question and source inspected".into() }).collect() }).collect::<Vec<_>>();
    let verification = review_proposal(&job, &proposal, &reviews, &sources).unwrap();
    (sources, input, KnowledgeChain { job, proposal, verification })
}
#[test]
fn five_distinct_views_share_one_inventory_and_use_reviewed_body_summaries() {
    let (s, i, c) = fixture();
    let p = project_views(&i, &[c], &s).unwrap();
    assert_eq!(p.project_name, "Agent Nine");
    assert_eq!(p.views.iter().map(|v| v.title.as_str()).collect::<Vec<_>>(),
        vec!["项目总览", "关键流程", "设计与决策", "Agent 任务导览", "项目规则"]);
    assert_eq!(p.views.iter().map(|v| &v.responsibility).collect::<BTreeSet<_>>().len(), 5);
    assert_eq!(p.inventory.sources.len(), 2);
    assert_eq!(p.inventory.symbols.len(), 1);
    assert_eq!(p.inventory.symbols[0].name, "Entry");
    assert!(p.views.iter().all(|v| v.inventory_ref == p.inventory.inventory_id));
    let bodies = p.views.iter().map(|v| &v.items[0].summary).collect::<BTreeSet<_>>();
    assert_eq!(bodies.len(), 5);
    assert!(bodies.iter().all(|s| !s.contains("model:") && !s.contains("generator:") && !s.contains("Metadata heading")));
    assert_eq!(p.views[0].items[0].summary, "Agent Nine coordinates local agent tasks.");
    assert_eq!(p.coverage.covered_items.len(), 5);
    assert_eq!(p.coverage.unique_propositions, 5);
    assert!(p.knowledge_ready);
    assert!(!p.llm_qa_validated);
    let json = serde_json::to_value(&p).unwrap();
    for v in json["views"].as_array().unwrap() {
        assert!(v.get("sources").is_none() && v.get("symbols").is_none());
    }
}
#[test]
fn missing_understanding_and_module_facets_remain_explicit_unknown() {
    let (s, mut i, c) = fixture();
    i.understanding_items.push(ProjectUnderstandingItem { item_id: "item-unknown".into(), question: "What happens when disk persistence fails?".into(),
        view: ProjectViewKind::KeyFlows, module_id: Some("controller".into()), aspect: Some(ModuleAspect::FailureBranches) });
    let p = project_views(&i, &[c], &s).unwrap();
    assert_eq!(p.coverage.required_items.len(), 6);
    assert_eq!(p.coverage.covered_items.len(), 5);
    assert_eq!(p.coverage.unknown_items, vec!["item-unknown"]);
    assert!(!p.knowledge_ready);
    let entry = p.views[1].items.iter().find(|x| x.item_id == "item-unknown").unwrap();
    assert_eq!(entry.status, "unknown");
    assert_eq!(entry.summary, "unknown");
    assert_eq!(p.modules[0].name, "Task Controller");
    assert_eq!(p.modules[0].aspects.len(), 8);
    assert_eq!(p.modules[0].aspects[&ModuleAspect::FailureBranches].status, "unknown");
    assert_eq!(p.modules[0].aspects[&ModuleAspect::InputsOutputs].status, "unknown");
}
#[test]
fn replayed_chains_reject_tampered_reviews_source_identity_and_inventory_paths() {
    let (s, i, c) = fixture();
    let mut forged = c.clone();
    forged.verification.supported_claim_ids.clear();
    assert!(project_views(&i, &[forged], &s).is_err());
    let mut drift = s.clone();
    drift.raw_sources.get_mut("README.md").unwrap().push(b'!');
    assert!(project_views(&i, std::slice::from_ref(&c), &drift).is_err());
    let mut invalid = i;
    invalid.modules[0].source_paths.push("missing.go".into());
    assert!(project_views(&invalid, &[c], &s).is_err());
}
#[test]
fn repeated_reviewed_chains_do_not_duplicate_coverage_or_view_content() {
    let (s, i, c) = fixture();
    let p = project_views(&i, &[c.clone(), c], &s).unwrap();
    assert_eq!(p.coverage.covered_items.len(), 5);
    assert_eq!(p.coverage.unique_propositions, 5);
    assert!(p.views.iter().all(|v| v.items.len() == 1 && v.items[0].claim_refs.len() == 1));
}
#[test]
fn no_generation_record_yields_unknown_views_without_model_or_runtime_claims() {
    let (s, i, _) = fixture();
    let p = project_views(&i, &[], &s).unwrap();
    assert!(!p.knowledge_ready);
    assert!(!p.llm_qa_validated);
    assert!(p.coverage.covered_items.is_empty());
    assert_eq!(p.coverage.unknown_items.len(), 5);
    assert!(p.views.iter().flat_map(|v| &v.items).all(|x| x.status == "unknown"));
}
