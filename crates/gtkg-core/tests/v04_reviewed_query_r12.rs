//! Public synthetic regression: only reviewed body terms may retrieve original chunks.
#[path = "v04_lifecycle_fixture.rs"]
mod fixture;
use fixture::Fixture;
use gtkg_core::v04::{artifact,authoring,knowledge::*,semantic_projection as semantic,query};
use gtkg_protocol::{FileReceiptRef,v04::{QueryPayload,Revision}};

#[test]
fn reviewed_proposition_retrieves_original_source_but_summary_and_structural_prose_do_not() {
    let f=Fixture::new();
    let filler="Public synthetic padding material. ".repeat(500);
    let files:Vec<_>=(0..64).map(|i|(format!("padding-{i:02}.md"),filler.clone())).collect();
    let extras:Vec<_>=files.iter().map(|(p,t)|(p.as_str(),t.as_str())).collect();
    let (verified_ref,accepted_refs,_)=f.build("reviewed_query",&extras,false);
    let (_,j,p,_,sources)=authoring::accepted_chain(&f.context,&f.workspace,&accepted_refs[0]).unwrap();
    let mut candidate=p.proposal.candidate.clone(); candidate.summary="SUMMARYPOISON_SENTINEL".into(); candidate.claims[0].natural_language="NATURALPOISON_SENTINEL".into();
    let mut interpretation=candidate.claims[0].clone(); interpretation.claim_id="reviewed-entry".into(); interpretation.natural_language="UNINDEXED_PROSE_SENTINEL".into(); interpretation.body=ClaimBody::Interpretive {proposition:"The copper kestrel identifies the synthetic entry declaration.".into(),epistemic:EpistemicStatus::Inferred,version_condition:"Synthetic fixture only; not a production claim".into()}; candidate.claims.push(interpretation);
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
    assert_eq!(positive["ranking_complete"],true,"{positive}");
    assert_eq!(positive["evidence"][0]["path"],"main.go","{positive}");
    assert!(positive["evidence"][0]["text"].as_str().unwrap().contains("Entry"));
    assert!(!positive["evidence"][0]["text"].as_str().unwrap().contains("copper"));
    assert_eq!(positive["reviewed_contexts"][0]["text"],"The copper kestrel identifies the synthetic entry declaration.");
    assert_eq!(positive["reviewed_contexts"][0]["epistemic"],"inferred");
    assert!(positive["reviewed_contexts"][0]["version_condition"].as_str().unwrap().contains("not a production"));
    assert!(positive["pack_preparation"]["plan_json"].is_string()); assert!(positive["pack_preparation"]["hits_json"].is_string()); assert!(positive["pack_preparation"]["pack_ticket"].is_string());
    for poison in ["SUMMARYPOISON_SENTINEL","NATURALPOISON_SENTINEL","UNINDEXED_PROSE_SENTINEL"] {
        let value=query::search(&f.context,&payload(poison)).unwrap();
        assert!(value["evidence"].as_array().unwrap().is_empty(),"unsafe prose indexed: {poison}: {value}");
    }
}
