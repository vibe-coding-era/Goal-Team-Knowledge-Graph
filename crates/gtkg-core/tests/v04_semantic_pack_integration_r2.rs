//! Public synthetic regression: only reviewed body terms may retrieve original chunks.
#[path = "v04_lifecycle_fixture.rs"]
mod fixture;
use fixture::Fixture;
use gtkg_core::v04::{artifact,authoring,knowledge::*,semantic_projection as semantic,query};
use gtkg_protocol::{FileReceiptRef,v04::{QueryPayload,Revision}};

fn exercise_semantic_pack(include_trailing_newline: bool) {
    let f=Fixture::new();
    let filler="Public synthetic padding material. ".repeat(500);
    let files:Vec<_>=(0..64).map(|i|(format!("padding-{i:02}.md"),filler.clone())).collect();
    let extras:Vec<_>=files.iter().map(|(p,t)|(p.as_str(),t.as_str())).collect();
    let (verified_ref,accepted_refs,_)=f.build("reviewed_query",&extras,false);
    let (_,j,p,_,sources)=authoring::accepted_chain(&f.context,&f.workspace,&accepted_refs[0]).unwrap();
    let mut candidate=p.proposal.candidate.clone(); candidate.summary="SUMMARYPOISON_SENTINEL".into(); candidate.claims[0].natural_language="NATURALPOISON_SENTINEL".into();
    let mut interpretation=candidate.claims[0].clone(); interpretation.claim_id="reviewed-entry".into(); interpretation.natural_language="UNINDEXED_PROSE_SENTINEL".into(); interpretation.body=ClaimBody::Interpretive {proposition:"The copper kestrel identifies the synthetic entry declaration.".into(),epistemic:EpistemicStatus::Inferred,version_condition:"Synthetic fixture only; not a production claim".into()}; if !include_trailing_newline { interpretation.citations[0].span.byte_end=25; interpretation.citations[0].excerpt="func Entry() {}".into(); } candidate.claims.push(interpretation);
    let mut execution=p.proposal.execution_record.unwrap(); execution.output=serde_json::to_string(&candidate).unwrap(); execution.output_digest=digest(execution.output.as_bytes());
    let proposal=submit_proposal(&j.job,&candidate,Some(&execution),&sources).unwrap();
    let proposal_ref=artifact::publish(&f.context,&f.workspace,"proposals",&authoring::ProposalArtifact {job_ref:p.job_ref.clone(),proposal:proposal.clone()}).unwrap();
    let reviews=["query-review-a","query-review-b"].into_iter().map(|id|IndependentReview {reviewer_id:id.into(),proposal_digest:proposal.proposal_digest.clone(),decisions:candidate.claims.iter().map(|c|ClaimReview {claim_id:c.claim_id.clone(),claim_digest:claim_digest(c).unwrap(),judgment:Judgment::Supported,reason:"Synthetic declaration evidence inspected for this deterministic fixture".into()}).collect()}).collect::<Vec<_>>();
    let verification=review_proposal(&j.job,&proposal,&reviews,&sources).unwrap();
    let review_ref=artifact::publish(&f.context,&f.workspace,"knowledge-reviews",&authoring::ReviewArtifact {proposal_ref,verification:verification.clone()}).unwrap();
    let accepted=accept(&j.job,&proposal,&verification,&sources).unwrap();
    let okf=artifact::publish_text(&f.context,&f.workspace,"knowledge",&authoring::render_okf(&j.job,&accepted)).unwrap();
    let accepted_ref=artifact::publish(&f.context,&f.workspace,"accepted",&authoring::AcceptedArtifact {review_ref,job_ref:p.job_ref,accepted,okf_ref:okf}).unwrap();
    let (verified,_):(gtkg_core::v04::analysis::VerifiedAnalysis,_)=artifact::read(&f.context,&f.workspace,&verified_ref).unwrap();
    let overlay=semantic::publish_projection(&f.context,&f.workspace,semantic::replay_projection(&f.context,&f.workspace,&semantic::SemanticPrepareRequest {schema:"gtkg.qk.semantic-prepare/v1".into(),verified_ref,base_index_ref:verified.index_ref.unwrap(),accepted_refs:vec![accepted_ref]}).unwrap()).unwrap();
    let payload=|text:&str|QueryPayload {payload_revision:Revision::R1,workspace_root:f.workspace.clone(),index_ref:FileReceiptRef {path:overlay.path.clone(),sha256:overlay.sha256.clone()},query:text.into(),query_policy:semantic::QUERY_POLICY.into(),max_results:5,max_tokens:8000,continuation:None};
    let positive=query::search(&f.context,&payload("copper kestrel")).unwrap();
    let preparation=&positive["pack_preparation"];
    let plan_path=f.workspace.join("review-plan.json"); let hits_path=f.workspace.join("review-hits.json");
    std::fs::write(&plan_path,preparation["plan_json"].as_str().unwrap()).unwrap();
    std::fs::write(&hits_path,preparation["hits_json"].as_str().unwrap()).unwrap();
    let request_path=f.workspace.join("review-pack-request.json");
    let mut request=serde_json::json!({"schema":"gtkg.qk.context-pack-request/v1","plan_ref":artifact::reference(&f.context,&f.workspace,&plan_path).unwrap(),"hits_ref":artifact::reference(&f.context,&f.workspace,&hits_path).unwrap(),"pack_ticket":preparation["pack_ticket"],"max_context_units":8000});
    let reader=gtkg_core::CallContext::restricted(gtkg_core::TransportKind::Test,vec![f.workspace.clone(),f.repository.clone()],gtkg_core::EffectPolicy::ReadOnly).unwrap();
    let run=|request:&serde_json::Value| {
        std::fs::write(&request_path,serde_json::to_vec(request).unwrap()).unwrap();
        let p=gtkg_protocol::v04::ArtifactPayload {payload_revision:Revision::R1,workspace_root:f.workspace.clone(),artifact_ref:artifact::reference(&reader,&f.workspace,&request_path).unwrap()};
        gtkg_core::v04::context_pack::execute(&reader,&p).unwrap()
    };
    let packed=run(&request);
    let raw=packed["raw_evidence"].as_array().unwrap();let contexts=packed["summary_context"].as_array().unwrap();
    assert!(!raw.is_empty());assert_eq!(contexts.len(),1,"reviewed context should be separate and deduplicated");
    assert!(raw.iter().any(|h|h["text"].as_str().unwrap().contains("Entry")));
    assert!(raw.iter().all(|h|!h["text"].as_str().unwrap().contains("copper")));
    let source_units=raw.iter().map(|h|h["text"].as_str().unwrap().chars().count()).sum::<usize>();
    let context_units=contexts.iter().map(|h|h["text"].as_str().unwrap().chars().count()+h["version_condition"].as_str().unwrap_or("").chars().count()).sum::<usize>();
    assert_eq!(packed["budget"]["context_units"].as_u64().unwrap() as usize,source_units+context_units);
    assert_eq!(contexts[0]["epistemic"],"inferred");assert!(contexts[0]["version_condition"].as_str().unwrap().contains("not a production"));
    assert_eq!(raw.len(),1);
    assert_eq!(raw[0]["byte_start"],10); assert_eq!(raw[0]["byte_end"],25);
    assert_eq!(raw[0]["text"],"func Entry() {}");
    assert_eq!(contexts[0]["citations"][0]["span"]["byte_end"], if include_trailing_newline {26} else {25});
    assert_eq!(contexts[0]["citation_coverage_in_pack"],if include_trailing_newline {"partial"} else {"complete"});
    request["max_context_units"]=serde_json::json!(source_units+1);
    let narrow=run(&request);
    assert!(narrow["summary_context"].as_array().unwrap().is_empty(),"a whole condition/proposition must be omitted together when it does not fit");
    assert!(narrow["omitted"].as_array().unwrap().iter().any(|v|v.get("context_id").is_some()));
    // The new independently staged call is a replay branch, not a monotonic single chain.
    assert_eq!(narrow["retry_fork_accounting"],"host_owned; old query cursors and pack tickets remain replayable");
}

#[test]
fn source_bound_pack_retains_partial_for_unselected_citation_newline() { exercise_semantic_pack(true); }
#[test]
fn semantic_pack_includes_complete_source_citation_and_untruncated_condition() { exercise_semantic_pack(false); }
