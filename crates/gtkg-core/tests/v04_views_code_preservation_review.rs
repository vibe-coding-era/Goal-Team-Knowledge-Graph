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
fn meaningful_fenced_code_keeps_indentation_operators_and_metadata_named_fields() {
    let text = "The fixture does not execute this code in version v1.\n```python\nclass Config:\n    model: str\n    value = 2 ** 3\n```";
    let (sources, input, chain) = reviewed(&[(text, EpistemicStatus::Direct)]);
    let output = project_views(&input, &[chain], &sources).unwrap();
    assert_eq!(output.views[0].items[0].summary, text);
}

#[test]
fn html_comment_delimiters_inside_code_literals_are_not_generation_metadata() {
    let text = "The literal is retained in version v1.\n```javascript\nconst value = \"<!-- do not execute -->\";\n```";
    let (sources, input, chain) = reviewed(&[(text, EpistemicStatus::Direct)]);
    let output = project_views(&input, &[chain], &sources).unwrap();
    assert_eq!(output.views[0].items[0].summary, text, "HTML delimiters inside a code literal must retain their reviewed meaning");
}
