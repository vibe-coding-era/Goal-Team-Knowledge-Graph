//! Independent synthetic review cases for T05 view projection only.
use gtkg_core::v04::knowledge::*;
use gtkg_extract::v04::{AnalysisContext, Span};
use std::collections::BTreeMap;

fn reviewed(texts: &[(&str, EpistemicStatus)]) -> (KnowledgeSources, ProjectKnowledgeInput, KnowledgeChain) {
    let raw = b"The controller coordinates tasks.\n";
    let sources = KnowledgeSources {
        raw_sources: BTreeMap::from([("README.md".into(), raw.to_vec())]),
        context: AnalysisContext { snapshot_id: "independent-t05-fixture".into(), ..AnalysisContext::default() },
        call_proofs: vec![],
    };
    let input = ProjectKnowledgeInput {
        project_name: "Independent synthetic project".into(), inventory_id: "fixture-inventory".into(),
        understanding_items: texts.iter().enumerate().map(|(n, _)| ProjectUnderstandingItem {
            item_id: format!("q-{n}"), question: format!("Fixture question {n}"),
            view: if n == 0 { ProjectViewKind::Overview } else { ProjectViewKind::KeyFlows },
            module_id: Some("docs".into()), aspect: Some(ModuleAspect::Purpose),
        }).collect(),
        modules: vec![ProjectModuleInput { module_id: "docs".into(), name: "Documentation".into(),
            subsystem: "Fixture".into(), language: "markdown".into(), source_paths: vec!["README.md".into()] }],
    };
    let job = prepare_job(&KnowledgeInput {
        job_id: "independent-t05-job".into(), goal: KnowledgeGoal::SemanticUnderstanding,
        source_paths: vec!["README.md".into()], understanding_items: input.understanding_items.iter().map(|i| i.item_id.clone()).collect(),
        prompt: "Synthetic view-projection review; not project gold".into(), policy: "fixture-only".into(),
        max_context_units: 8000, source_spans: BTreeMap::new(),
    }, &sources).unwrap();
    let candidate = KnowledgeCandidate {
        author_id: "independent-fixture-author".into(), author_mode: AuthorMode::HumanAuthored,
        summary: "Unused metadata summary".into(),
        claims: texts.iter().enumerate().map(|(n, (text, epistemic))| KnowledgeClaim {
            claim_id: format!("c-{n}"), understanding_item: format!("q-{n}"), natural_language: text.to_string(),
            body: ClaimBody::Interpretive { proposition: text.to_string(), epistemic: epistemic.clone(), version_condition: "fixture-v1".into() },
            citations: vec![Citation { path: "README.md".into(), file_sha256: digest(raw),
                span: Span { byte_start: 0, byte_end: raw.len(), line_start: 1, line_end: 1 },
                excerpt: String::from_utf8(raw.to_vec()).unwrap() }],
        }).collect(),
    };
    let output = serde_json::to_string(&candidate).unwrap();
    let record = GenerationExecutionRecord {
        schema: "gtkg.qk.generation-execution-record/v1".into(), job_digest: job.job_digest.clone(),
        context_digest: job.context_digest.clone(), prompt_digest: job.prompt_digest.clone(), policy_digest: job.policy_digest.clone(),
        author_id: candidate.author_id.clone(), author_mode: candidate.author_mode.clone(), execution_evidence: ExecutionEvidence::HumanRecorded,
        host_id: None, model_id: None, transcript: None, transcript_digest: None,
        output_digest: digest(output.as_bytes()), output, usage: Usage { input_tokens: None, output_tokens: None },
    };
    let proposal = submit_proposal(&job, &candidate, Some(&record), &sources).unwrap();
    let reviews = ["independent-fixture-review-a", "independent-fixture-review-b"].into_iter().map(|id| IndependentReview {
        reviewer_id: id.into(), proposal_digest: proposal.proposal_digest.clone(),
        decisions: candidate.claims.iter().map(|claim| ClaimReview { claim_id: claim.claim_id.clone(),
            claim_digest: claim_digest(claim).unwrap(), judgment: Judgment::Supported, reason: "Synthetic tool-boundary oracle only".into() }).collect(),
    }).collect::<Vec<_>>();
    let verification = review_proposal(&job, &proposal, &reviews, &sources).unwrap();
    (sources, input, KnowledgeChain { job, proposal, verification })
}

#[test]
fn fenced_metadata_only_material_cannot_cover_understanding() {
    for text in ["```yaml\nmodel: fixture-model\ngenerator: fixture\n```", "- model: fixture-model\n- generator: fixture"] {
        let (sources, input, chain) = reviewed(&[(text, EpistemicStatus::Direct)]);
        let output = project_views(&input, &[chain], &sources).unwrap();
        assert!(output.coverage.covered_items.is_empty(), "Only metadata/formatting remained, but coverage was {:?}", output.coverage);
        assert!(!output.knowledge_ready);
    }
}

#[test]
fn bold_wrappers_cannot_make_same_proposition_cover_a_second_item() {
    let (sources, input, chain) = reviewed(&[
        ("The controller coordinates tasks.", EpistemicStatus::Direct),
        ("**The controller coordinates tasks.**", EpistemicStatus::Direct),
    ]);
    let output = project_views(&input, &[chain], &sources).unwrap();
    assert_eq!(output.coverage.unique_propositions, 1, "Markdown emphasis alone added an understanding proposition");
    assert_eq!(output.coverage.covered_items.len(), 1);
    assert!(!output.knowledge_ready);
}

#[test]
fn unknown_reviewed_claims_and_seven_undeclared_module_aspects_stay_unknown() {
    let (sources, input, chain) = reviewed(&[("Controller behavior is unknown.", EpistemicStatus::Unknown)]);
    let output = project_views(&input, &[chain], &sources).unwrap();
    assert!(!output.knowledge_ready);
    assert!(output.coverage.covered_items.is_empty());
    assert_eq!(output.modules[0].aspects.len(), 8);
    assert!(output.modules[0].aspects.values().all(|aspect| aspect.status == "unknown"));
    assert!(output.views.iter().all(|view| view.inventory_ref == output.inventory.inventory_id));
}

#[test]
fn source_inventory_and_view_digest_bind_additional_unclaimed_material() {
    let (sources, input, chain) = reviewed(&[("The controller coordinates tasks.", EpistemicStatus::Direct)]);
    let first = project_views(&input, &[], &sources).unwrap();
    let mut extended = sources.clone();
    extended.raw_sources.insert("NOTES.md".into(), b"Unclaimed source material.\n".to_vec());
    assert!(project_views(&input, &[chain], &extended).is_err(), "A source-set drift must invalidate the old reviewed chain");
    let second = project_views(&input, &[], &extended).unwrap();
    assert_ne!(first.source_set_digest, second.source_set_digest);
    assert_ne!(first.view_digest, second.view_digest);
    assert_eq!(first.coverage, second.coverage);
    assert_eq!(second.inventory.sources.len(), 2);
    assert!(!second.llm_qa_validated);
}
