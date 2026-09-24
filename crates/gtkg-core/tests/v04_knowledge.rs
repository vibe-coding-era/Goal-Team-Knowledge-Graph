//! Synthetic source/author/reviewer fixtures; no real model execution is claimed.
use gtkg_core::v04::knowledge::*;
use gtkg_extract::v04::{AnalysisContext, Span, binding::{BindingTarget, CallBindingProof}, extract};
use std::collections::BTreeMap;

fn sources() -> KnowledgeSources {
    KnowledgeSources {
        raw_sources: BTreeMap::from([
            ("main.go".into(), b"package p\nfunc Entry() {}\nfunc Other() { Entry() }\n".to_vec()),
            ("alt.go".into(), b"package p\nfunc Alt() {}\n".to_vec()),
        ]),
        context: AnalysisContext { snapshot_id: "fixture-snapshot".into(), ..AnalysisContext::default() },
        call_proofs: vec![],
    }
}
fn input() -> KnowledgeInput {
    KnowledgeInput { job_id: "fixture-job".into(), goal: KnowledgeGoal::SemanticUnderstanding,
        source_paths: vec!["alt.go".into(), "main.go".into()], understanding_items: vec!["entry".into()],
        prompt: "Explain the source with scoped evidence".into(), policy: "fixture-policy-v1".into(), max_context_units:8000, source_spans:BTreeMap::new() }
}
fn citation(s: &KnowledgeSources) -> Citation {
    let bytes = &s.raw_sources["main.go"];
    Citation { path: "main.go".into(), file_sha256: digest(bytes),
        span: Span { byte_start: 10, byte_end: 26, line_start: 2, line_end: 2 },
        excerpt: "func Entry() {}\n".into() }
}
fn candidate(s: &KnowledgeSources) -> KnowledgeCandidate {
    KnowledgeCandidate { author_id: "fixture-author".into(), author_mode: AuthorMode::HumanAuthored,
        summary: "The fixture declares Entry.".into(), claims: vec![KnowledgeClaim {
            claim_id: "claim-1".into(), understanding_item: "entry".into(),
            natural_language: "Entry is a declared function in main.go".into(),
            body: ClaimBody::Structural { predicate: Predicate::Declares { path:"main.go".into(), name:"Entry".into(), kind:"function".into() }, polarity:true },
            citations: vec![citation(s)] }] }
}
fn record(job: &KnowledgeJob, candidate: &KnowledgeCandidate) -> GenerationExecutionRecord {
    let output = serde_json::to_string(candidate).unwrap();
    GenerationExecutionRecord { schema:"gtkg.qk.generation-execution-record/v1".into(),
        job_digest:job.job_digest.clone(), context_digest:job.context_digest.clone(), prompt_digest:job.prompt_digest.clone(), policy_digest:job.policy_digest.clone(),
        author_id:candidate.author_id.clone(), author_mode:candidate.author_mode.clone(), execution_evidence:ExecutionEvidence::HumanRecorded,
        host_id:None,model_id:None,transcript:None,transcript_digest:None,output_digest:digest(output.as_bytes()),output,
        usage:Usage { input_tokens:None,output_tokens:None } }
}
fn reviews(proposal: &KnowledgeProposal) -> Vec<IndependentReview> {
    ["fixture-reviewer-a","fixture-reviewer-b"].into_iter().map(|id| IndependentReview {
        reviewer_id:id.into(),proposal_digest:proposal.proposal_digest.clone(),decisions:proposal.candidate.claims.iter().map(|c|ClaimReview {
            claim_id:c.claim_id.clone(),claim_digest:claim_digest(c).unwrap(),judgment:Judgment::Supported,reason:"Fixture oracle: source and proposition inspected".into()}).collect()}).collect()
}
fn setup() -> (KnowledgeSources,KnowledgeJob,KnowledgeCandidate) {
    let s=sources();let j=prepare_job(&input(),&s).expect("valid source-bound job");let c=candidate(&s);(s,j,c)
}
#[test]
fn source_bound_human_claim_requires_dual_review_and_preserves_quality_axes() {
    let(s,j,c)=setup();let p=submit_proposal(&j,&c,Some(&record(&j,&c)),&s).unwrap();
    let v=review_proposal(&j,&p,&reviews(&p),&s).unwrap();let a=accept(&j,&p,&v,&s).unwrap();
    assert!(a.knowledge_ready);assert!(!a.llm_qa_validated);assert_eq!(a.covered_understanding_items,vec!["entry"]);
    assert_eq!(a.execution_assurance,"human_recorded_not_independently_attested");
}
#[test]
fn unchanged_quote_cannot_cover_changed_structural_subject_object_kind_or_polarity() {
    let(s,j,c)=setup();
    let mutations=vec![
        ClaimBody::Structural{predicate:Predicate::Declares{path:"alt.go".into(),name:"Entry".into(),kind:"function".into()},polarity:true},
        ClaimBody::Structural{predicate:Predicate::Declares{path:"main.go".into(),name:"Missing".into(),kind:"function".into()},polarity:true},
        ClaimBody::Structural{predicate:Predicate::Declares{path:"main.go".into(),name:"Entry".into(),kind:"variable".into()},polarity:true},
        ClaimBody::Structural{predicate:Predicate::Declares{path:"main.go".into(),name:"Entry".into(),kind:"function".into()},polarity:false},
        ClaimBody::Structural{predicate:Predicate::Calls{call_id:"invented".into(),source_path:"main.go".into(),target_path:"main.go".into(),target_id:"invented".into()},polarity:true},
    ];
    for body in mutations{let mut bad=c.clone();bad.claims[0].body=body;assert_eq!(bad.claims[0].citations,c.claims[0].citations);assert_eq!(bad.claims[0].natural_language,c.claims[0].natural_language);assert!(submit_proposal(&j,&bad,Some(&record(&j,&bad)),&s).is_err());}
}
#[test]
fn record_identity_output_and_transcript_tampering_fail_closed() {
    let(s,j,c)=setup();let r=record(&j,&c);
    for field in ["job","context","prompt","policy","output"]{let mut bad=r.clone();match field{"job"=>bad.job_digest="wrong".into(),"context"=>bad.context_digest="wrong".into(),"prompt"=>bad.prompt_digest="wrong".into(),"policy"=>bad.policy_digest="wrong".into(),_=>bad.output_digest="wrong".into()};assert!(submit_proposal(&j,&c,Some(&bad),&s).is_err());}
    let mut drift=s.clone();drift.raw_sources.insert("alt.go".into(),b"package changed".to_vec());assert!(submit_proposal(&j,&c,Some(&r),&drift).is_err());
    let mut altered=r;altered.output="{}".into();altered.output_digest=digest(altered.output.as_bytes());assert!(submit_proposal(&j,&c,Some(&altered),&s).is_err());
}
#[test]
fn model_header_without_execution_stays_pending_and_usage_is_null() {
    let(s,j,mut c)=setup();c.author_mode=AuthorMode::ModelGenerated;
    let p=submit_proposal(&j,&c,None,&s).unwrap();assert_eq!(p.state,"semantic_authoring_pending");assert!(review_proposal(&j,&p,&reviews(&p),&s).is_err());
    let mut r=record(&j,&c);r.execution_evidence=ExecutionEvidence::Unavailable;r.model_id=Some("fixture-model-label".into());
    let p=submit_proposal(&j,&c,Some(&r),&s).unwrap();assert_eq!(p.state,"semantic_authoring_pending");
    let serialized=serde_json::to_value(&r).unwrap();assert!(serialized["usage"]["input_tokens"].is_null());
}
#[test]
fn host_observation_never_becomes_independent_model_attestation() {
    let(s,j,mut c)=setup();c.author_mode=AuthorMode::ModelGenerated;let mut r=record(&j,&c);
    r.execution_evidence=ExecutionEvidence::HostObserved;r.host_id=Some("fixture-host".into());r.model_id=Some("fixture-model".into());
    r.transcript=Some("SYNTHETIC FIXTURE transcript; no real model ran".into());r.transcript_digest=Some(digest(r.transcript.as_ref().unwrap().as_bytes()));
    let p=submit_proposal(&j,&c,Some(&r),&s).unwrap();let v=review_proposal(&j,&p,&reviews(&p),&s).unwrap();let a=accept(&j,&p,&v,&s).unwrap();
    assert_eq!(a.execution_assurance,"host_observed/not_independently_attested");assert!(!a.llm_qa_validated);
    r.transcript_digest=Some("wrong".into());assert!(submit_proposal(&j,&c,Some(&r),&s).is_err());
    let mut value=serde_json::to_value(r).unwrap();value["execution_evidence"]=serde_json::json!("independently_attested");assert!(serde_json::from_value::<GenerationExecutionRecord>(value).is_err());
}
#[test]
fn static_transcription_cannot_satisfy_semantic_goal() {
    let(s,j,mut c)=setup();c.author_mode=AuthorMode::StaticTranscription;let mut r=record(&j,&c);r.execution_evidence=ExecutionEvidence::StaticRecorded;
    let p=submit_proposal(&j,&c,Some(&r),&s).unwrap();assert_eq!(p.state,"semantic_authoring_pending");assert!(review_proposal(&j,&p,&reviews(&p),&s).is_err());
}
#[test]
fn interpreted_negation_and_version_mutations_invalidate_old_independent_reviews() {
    let(s,j,mut c)=setup();c.claims[0].body=ClaimBody::Interpretive{proposition:"Entry exists in this fixture".into(),epistemic:EpistemicStatus::Direct,version_condition:"fixture-snapshot".into()};
    let p=submit_proposal(&j,&c,Some(&record(&j,&c)),&s).unwrap();let prior=reviews(&p);review_proposal(&j,&p,&prior,&s).unwrap();
    for change in ["negation","version"]{let mut changed=c.clone();if let ClaimBody::Interpretive{proposition,version_condition,..}=&mut changed.claims[0].body{if change=="negation"{*proposition="Entry does not exist in this fixture".into()}else{*version_condition="different-release".into()}}let new=submit_proposal(&j,&changed,Some(&record(&j,&changed)),&s).unwrap();assert!(review_proposal(&j,&new,&prior,&s).is_err());}
}
#[test]
fn repeated_proposition_ids_do_not_inflate_understanding_coverage() {
    let(s,j,mut c)=setup();let template=c.claims[0].clone();c.claims=(0..100).map(|i|{let mut claim=template.clone();claim.claim_id=format!("id-{i}");claim}).collect();
    let p=submit_proposal(&j,&c,Some(&record(&j,&c)),&s).unwrap();let v=review_proposal(&j,&p,&reviews(&p),&s).unwrap();let a=accept(&j,&p,&v,&s).unwrap();assert_eq!(a.covered_understanding_items.len(),1);assert_eq!(a.required_understanding_count,1);assert_eq!(a.supported_claims.len(),1);
    c.claims[1].claim_id=c.claims[0].claim_id.clone();assert!(submit_proposal(&j,&c,Some(&record(&j,&c)),&s).is_err());
}
#[test]
fn reviewers_are_distinct_complete_and_rejection_is_not_accepted() {
    let(s,j,c)=setup();let p=submit_proposal(&j,&c,Some(&record(&j,&c)),&s).unwrap();let rr=reviews(&p);
    assert!(review_proposal(&j,&p,&rr[..1],&s).is_err());let mut same=rr.clone();same[1].reviewer_id=same[0].reviewer_id.clone();assert!(review_proposal(&j,&p,&same,&s).is_err());
    let mut author=rr.clone();author[0].reviewer_id=c.author_id.clone();assert!(review_proposal(&j,&p,&author,&s).is_err());
    let mut incomplete=rr.clone();incomplete[0].decisions.clear();assert!(review_proposal(&j,&p,&incomplete,&s).is_err());
    let mut rejected=rr;rejected[1].decisions[0].judgment=Judgment::Rejected;let v=review_proposal(&j,&p,&rejected,&s).unwrap();let a=accept(&j,&p,&v,&s).unwrap();assert!(!a.knowledge_ready);assert!(a.supported_claims.is_empty());
}
#[test]
fn forged_calls_verified_label_and_citation_coordinates_are_not_trusted() {
    let(mut s,j,mut c)=setup();let parsed=extract("main.go",&s.raw_sources["main.go"],&s.context).unwrap();
    let call=parsed.calls[0].clone();let target=parsed.declarations.iter().find(|d|d.name=="Entry").unwrap().clone();
    c.claims[0].body=ClaimBody::Structural{predicate:Predicate::Calls{call_id:call.id.clone(),source_path:"main.go".into(),target_path:"main.go".into(),target_id:target.id.clone()},polarity:true};
    s.call_proofs.push(CallBindingProof{schema:"gtkg.qk.call-binding-proof/v1".into(),source_path:"main.go".into(),language:"go".into(),source_set_digest:"invented".into(),context_digest:"invented".into(),extractor_profile:"invented".into(),resolver_profile:"invented".into(),verifier_profile:"invented".into(),call,resolution:"resolved".into(),proof_status:"verified".into(),rule:"same-name".into(),reason:"self asserted".into(),target:Some(BindingTarget{path:"main.go".into(),declaration:target}),candidates:vec![]});
    assert!(submit_proposal(&j,&c,Some(&record(&j,&c)),&s).is_err());
    c=candidate(&s);c.claims[0].citations[0].span.line_start=1;assert!(submit_proposal(&j,&c,Some(&record(&j,&c)),&s).is_err());
}
#[test]
fn context_subset_is_explicit_bounded_and_allows_documents_without_code_parsing() {
    let mut s=sources();s.raw_sources.insert("README.md".into(),b"documentation only".to_vec());
    let mut i=input();i.source_paths=vec!["README.md".into()];i.max_context_units=3;
    assert!(prepare_job(&i,&s).is_err());i.max_context_units=8000;
    let j=prepare_job(&i,&s).unwrap();assert_eq!(j.context.len(),1);assert_eq!(j.context[0].path,"README.md");
    let c=candidate(&s);assert!(submit_proposal(&j,&c,Some(&record(&j,&c)),&s).is_err());
}
