//! Synthetic claims and archives only; no external evaluation inputs.
#[path = "v04_lifecycle_fixture.rs"]
mod fixture;
use fixture::Fixture;
use gtkg_core::{CallContext,EffectPolicy,TransportKind};
use gtkg_core::v04::{analysis,artifact,authoring,knowledge::*,semantic_projection::{self as semantic,SemanticPrepareRequest},query_meter::{QueryMeter,QueryBudgetUsage,QueryBudgetLimits}};
use gtkg_extract::v04::Span;
use gtkg_protocol::FileReceiptRef;
use std::collections::BTreeMap;

fn meter()->QueryMeter { QueryMeter::new(QueryBudgetUsage::default(),QueryBudgetLimits::for_index(1280*1024*1024)) }
fn source_request(f:&Fixture)->(SemanticPrepareRequest,FileReceiptRef) {
    let guide="The raven queue does not persist payloads.\n";
    let (verified_ref,_,_)=f.build("reviewed",&[("guide.md",guide)],false);
    let (v,_):(analysis::VerifiedAnalysis,_)=artifact::read(&f.context,&f.workspace,&verified_ref).unwrap();
    let (_,sources)=authoring::load_verified_sources(&f.context,&f.workspace,&verified_ref).unwrap();
    let job=prepare_job(&KnowledgeInput {job_id:"reviewed-guide".into(),goal:KnowledgeGoal::SemanticUnderstanding,source_paths:vec!["guide.md".into()],understanding_items:vec!["persistence".into()],prompt:"Explain the synthetic guide".into(),policy:"synthetic-only".into(),max_context_units:8000,source_spans:BTreeMap::new()},&sources).unwrap();
    let job_ref=artifact::publish(&f.context,&f.workspace,"authoring-jobs",&authoring::JobArtifact {verified_ref:verified_ref.clone(),job:job.clone()}).unwrap();
    let candidate=KnowledgeCandidate {author_id:"synthetic-author".into(),author_mode:AuthorMode::HumanAuthored,summary:"FORBIDDEN_SUMMARY_ONLY".into(),claims:vec![KnowledgeClaim {claim_id:"guide-persistence".into(),understanding_item:"persistence".into(),natural_language:"FORBIDDEN_FREE_TEXT_ONLY".into(),body:ClaimBody::Interpretive {proposition:"The raven queue does not persist payloads.".into(),epistemic:EpistemicStatus::Direct,version_condition:"fixture-v1 only; not fixture-v2".into()},citations:vec![Citation {path:"guide.md".into(),file_sha256:digest(guide.as_bytes()),span:Span {byte_start:0,byte_end:guide.len(),line_start:1,line_end:1},excerpt:guide.into()}]}]};
    let output=serde_json::to_string(&candidate).unwrap();
    let record=GenerationExecutionRecord {schema:"gtkg.qk.generation-execution-record/v1".into(),job_digest:job.job_digest.clone(),context_digest:job.context_digest.clone(),prompt_digest:job.prompt_digest.clone(),policy_digest:job.policy_digest.clone(),author_id:candidate.author_id.clone(),author_mode:candidate.author_mode.clone(),execution_evidence:ExecutionEvidence::HumanRecorded,host_id:None,model_id:None,transcript:None,transcript_digest:None,output_digest:digest(output.as_bytes()),output,usage:Usage {input_tokens:None,output_tokens:None}};
    let proposal=submit_proposal(&job,&candidate,Some(&record),&sources).unwrap();
    let proposal_ref=artifact::publish(&f.context,&f.workspace,"proposals",&authoring::ProposalArtifact {job_ref:job_ref.clone(),proposal:proposal.clone()}).unwrap();
    let reviews=["synthetic-review-a","synthetic-review-b"].into_iter().map(|id|IndependentReview {reviewer_id:id.into(),proposal_digest:proposal.proposal_digest.clone(),decisions:candidate.claims.iter().map(|c|ClaimReview {claim_id:c.claim_id.clone(),claim_digest:claim_digest(c).unwrap(),judgment:Judgment::Supported,reason:"Public synthetic source independently represented for boundary testing".into()}).collect()}).collect::<Vec<_>>();
    let verification=review_proposal(&job,&proposal,&reviews,&sources).unwrap();
    let review_ref=artifact::publish(&f.context,&f.workspace,"knowledge-reviews",&authoring::ReviewArtifact {proposal_ref,verification:verification.clone()}).unwrap();
    let accepted=accept(&job,&proposal,&verification,&sources).unwrap();
    let okf_ref=artifact::publish_text(&f.context,&f.workspace,"knowledge",&authoring::render_okf(&job,&accepted)).unwrap();
    let accepted_ref=artifact::publish(&f.context,&f.workspace,"accepted",&authoring::AcceptedArtifact {review_ref,job_ref,accepted,okf_ref}).unwrap();
    (SemanticPrepareRequest {schema:"gtkg.qk.semantic-prepare/v1".into(),verified_ref:verified_ref.clone(),base_index_ref:v.index_ref.unwrap(),accepted_refs:vec![accepted_ref]},verified_ref)
}
fn prepare(f:&Fixture,r:&SemanticPrepareRequest)->FileReceiptRef {
    semantic::publish_projection(&f.context,&f.workspace,semantic::replay_projection(&f.context,&f.workspace,r).unwrap()).unwrap()
}

#[test]
fn only_reviewed_body_is_indexed_and_source_context_stays_distinct() {
    let f=Fixture::new(); let (request,_)=source_request(&f); let overlay_ref=prepare(&f,&request); let mut m=meter();
    let loaded=semantic::load_overlay_with_io(&f.context,&f.workspace,&overlay_ref,&mut m).unwrap();
    assert_eq!(loaded.catalog.total_contexts,1);
    for term in ["exact:FORBIDDEN_SUMMARY_ONLY","exact:FORBIDDEN_FREE_TEXT_ONLY"] { assert!(semantic::load_selected_postings(&f.context,&f.workspace,&loaded,term,&mut m).unwrap().is_empty()); }
    let hits=semantic::load_selected_postings(&f.context,&f.workspace,&loaded,"fold:fixture-v2",&mut m).unwrap();
    assert!(!hits.is_empty());
    let record=semantic::load_selected_context(&f.context,&f.workspace,&loaded,&hits[0].context_ref,&mut m).unwrap();
    let summary=semantic::verify_selected_lineage(&f.context,&f.workspace,&loaded,&record,&hits[0].context_ref,&mut m).unwrap();
    assert_eq!(summary.text,"The raven queue does not persist payloads.");
    assert_eq!(summary.version_condition.as_deref(),Some("fixture-v1 only; not fixture-v2"));
    assert_eq!(summary.reviewer_ids.len(),2);
    assert_eq!(summary.text_units(),summary.text.chars().count()+summary.version_condition.as_ref().unwrap().chars().count());
    let serialized=serde_json::to_value(&summary).unwrap(); assert!(serialized.get("body").is_none());
    let raw=std::fs::read_to_string(f.workspace.join(&hits[0].chunk_ref.path)).unwrap(); assert!(!raw.contains("fixture-v2"));
    assert!(m.usage().posting_rows>0); assert!(m.usage().io_bytes>0);
}

#[test]
fn every_selected_lineage_file_tamper_is_rejected_and_actual_io_is_retained() {
    let f=Fixture::new(); let (request,_)=source_request(&f); let overlay_ref=prepare(&f,&request); let mut m=meter();
    let loaded=semantic::load_overlay_with_io(&f.context,&f.workspace,&overlay_ref,&mut m).unwrap();
    let hits=semantic::load_selected_postings(&f.context,&f.workspace,&loaded,"fold:raven",&mut m).unwrap();
    let record=semantic::load_selected_context(&f.context,&f.workspace,&loaded,&hits[0].context_ref,&mut m).unwrap();
    for reference in [&record.lineage.accepted_ref,&record.lineage.job_ref,&record.lineage.proposal_ref,&record.lineage.review_ref,&record.lineage.okf_ref] {
        let path=f.workspace.join(&reference.path); let before=std::fs::read(&path).unwrap(); let mut changed=before.clone(); changed[0]=if changed[0]==b'{' {b'['}else{b'x'}; std::fs::write(&path,&changed).unwrap();
        let mut failure_meter=meter();
        assert!(semantic::verify_selected_lineage(&f.context,&f.workspace,&loaded,&record,&hits[0].context_ref,&mut failure_meter).is_err());
        assert!(failure_meter.usage().io_bytes>0,"rejected reads must remain charged"); std::fs::write(path,before).unwrap();
    }
    let mut changed=record.clone(); if let ClaimBody::Interpretive {proposition,..}=&mut changed.body { *proposition="The raven queue persists payloads.".into(); }
    assert!(semantic::verify_selected_lineage(&f.context,&f.workspace,&loaded,&changed,&hits[0].context_ref,&mut meter()).is_err());
}

#[test]
fn duplicate_refs_are_normalized_empty_input_is_honest_and_read_only_verify_does_not_admit() {
    let f=Fixture::new(); let (mut request,_)=source_request(&f); let first=prepare(&f,&request);
    request.accepted_refs.push(request.accepted_refs[0].clone()); assert_eq!(first,prepare(&f,&request));
    let (accepted,_):(authoring::AcceptedArtifact,_)=artifact::read(&f.context,&f.workspace,&request.accepted_refs[0]).unwrap();
    let duplicate=artifact::publish(&f.context,&f.workspace,"accepted-copy",&accepted).unwrap();
    request.accepted_refs.push(duplicate);
    let duplicate_overlay=prepare(&f,&request); let deduplicated=semantic::load_overlay_with_io(&f.context,&f.workspace,&duplicate_overlay,&mut meter()).unwrap();
    assert_eq!(deduplicated.catalog.total_contexts,1);
    assert_eq!(deduplicated.catalog.excluded_claims.iter().filter(|c|c.reason=="duplicate_supported_fact").count(),1);
    request.accepted_refs.clear(); let empty=prepare(&f,&request); let loaded=semantic::load_overlay_with_io(&f.context,&f.workspace,&empty,&mut meter()).unwrap();
    assert_eq!(loaded.catalog.total_contexts,0); assert_eq!(loaded.catalog.total_mappings,0); assert!(loaded.catalog.router.values().all(Option::is_none));
    let admission=f.workspace.join(format!(".gtkg/qk/runtime/semantic-admission/{}.json",&first.sha256[7..])); std::fs::remove_file(&admission).unwrap();
    let ro=CallContext::restricted(TransportKind::Test,vec![f.workspace.clone()],EffectPolicy::ReadOnly).unwrap();
    let verified=semantic::verify_projection(&ro,&f.workspace,&first).unwrap();
    assert_eq!(verified.overlay_ref(),&first); assert!(!admission.exists());
    assert!(semantic::load_overlay_with_io(&ro,&f.workspace,&first,&mut meter()).is_err());
    assert!(semantic::publish_projection(&ro,&f.workspace,verified).is_err()); assert!(!admission.exists());
}

#[test]
fn cross_source_and_self_resigned_policy_changes_cannot_be_admitted() {
    let f=Fixture::new(); let (mut request,_)=source_request(&f); let original=prepare(&f,&request);
    let (other,_,_)=f.build("different",&[("other.md","different source\n")],false);
    let (v,_):(analysis::VerifiedAnalysis,_)=artifact::read(&f.context,&f.workspace,&other).unwrap();
    request.verified_ref=other; request.base_index_ref=v.index_ref.unwrap(); assert!(semantic::replay_projection(&f.context,&f.workspace,&request).is_err());
    let (mut overlay,_):(semantic::QueryIndexOverlay,_)=artifact::read(&f.context,&f.workspace,&original).unwrap(); overlay.query_policy="gtkg.qk.query/v2".into();
    let raw=serde_json::to_vec_pretty(&overlay).unwrap(); std::fs::write(f.workspace.join(&original.path),&raw).unwrap();
    let resigned=FileReceiptRef {path:original.path,sha256:digest(&raw)};
    assert!(semantic::load_overlay_with_io(&f.context,&f.workspace,&resigned,&mut meter()).is_err());
}

#[test]
fn rejected_bounded_read_keeps_bytes_and_never_reports_a_semantic_result() {
    let f=Fixture::new(); let (request,_)=source_request(&f); let reference=prepare(&f,&request);
    let mut m=QueryMeter::new(QueryBudgetUsage::default(),QueryBudgetLimits::for_index(400));
    assert!(semantic::load_overlay_with_io(&f.context,&f.workspace,&reference,&mut m).is_err());
    // Opened-handle length rejection reads zero content bytes; never invent IO.
    assert_eq!(m.usage().io_bytes,0);
}

#[test]
fn semantic_posting_decode_enforces_the_remaining_row_budget_before_decoding() {
    let f=Fixture::new();let (request,_)=source_request(&f);let reference=prepare(&f,&request);
    let mut m=meter();let loaded=semantic::load_overlay_with_io(&f.context,&f.workspace,&reference,&mut m).unwrap();
    let usage=QueryBudgetUsage {posting_rows:99_999,..Default::default()};
    let mut limited=QueryMeter::new(usage,QueryBudgetLimits::for_index(1280*1024*1024));
    let rows=semantic::load_selected_postings(&f.context,&f.workspace,&loaded,"fold:raven",&mut limited).unwrap();
    assert_eq!(rows.len(),1);assert_eq!(limited.usage().posting_rows,100_000);
    let prior=limited.usage().io_bytes;
    let error=semantic::load_selected_postings(&f.context,&f.workspace,&loaded,"fold:raven",&mut limited).unwrap_err();
    assert!(error.starts_with("E_QUERY_POSTING_BUDGET"));
    assert_eq!(limited.usage().posting_rows,100_000);assert!(limited.usage().io_bytes>prior);
}
