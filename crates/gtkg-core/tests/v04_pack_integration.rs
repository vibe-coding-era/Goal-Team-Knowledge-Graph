#![allow(clippy::unwrap_used, dead_code)]
#[path = "v04_lifecycle_fixture.rs"] mod fixture;
use gtkg_core::{CallContext, EffectPolicy, TransportKind, Dispatcher};
use gtkg_core::v04::{analysis, artifact};
use gtkg_protocol::{v2::{OperationRequestV2},v04::PAYLOAD_REVISION};
use serde_json::json;
use std::fs;

#[test]
fn query_produces_authenticated_staging_and_dispatcher_packs_refs_readonly() {
    let f=fixture::Fixture::new();
    let noise=(0..8192).map(|i|format!("pad_{i:05}_{:040x}\n",(i as u128+19)*0xabcdef0123456789u128)).collect::<String>();
    let (verified,_,_)=f.build("pack-integration",&[("noise.md",noise.as_str())],false);
    let(v,_):(analysis::VerifiedAnalysis,_)=artifact::read(&f.context,&f.workspace,&verified).unwrap();
    let ctx=CallContext::restricted(TransportKind::Test,vec![f.workspace.clone(),f.repository.clone()],EffectPolicy::ReadOnly).unwrap();
    let result=Dispatcher.execute_v2(&ctx,OperationRequestV2::new("graph.search","pack-source",json!({"payload_revision":PAYLOAD_REVISION,"workspace_root":f.workspace,"index_ref":v.index_ref.unwrap(),"query":"Entry","query_policy":"gtkg.qk.query/v2","max_results":2,"max_tokens":8000,"continuation":null}))).unwrap().result;
    assert!(!result["evidence"].as_array().unwrap().is_empty());
    let prepared=&result["pack_preparation"];
    assert!(prepared.is_object(),"query must provide Core-authenticated exact plan/hit staging bytes");
    let plan=f.workspace.join("staged-plan.json");let hits=f.workspace.join("staged-hits.json");
    fs::write(&plan,prepared["plan_json"].as_str().unwrap()).unwrap();fs::write(&hits,prepared["hits_json"].as_str().unwrap()).unwrap();
    let request=f.workspace.join("staged-pack.json");
    fs::write(&request,serde_json::to_vec(&json!({"schema":"gtkg.qk.context-pack-request/v1","plan_ref":artifact::reference(&ctx,&f.workspace,&plan).unwrap(),"hits_ref":artifact::reference(&ctx,&f.workspace,&hits).unwrap(),"pack_ticket":prepared["pack_ticket"],"max_context_units":8000})).unwrap()).unwrap();
    let pack=Dispatcher.execute_v2(&ctx,OperationRequestV2::new("context.pack","pack-refs",json!({"payload_revision":PAYLOAD_REVISION,"workspace_root":f.workspace,"artifact_ref":artifact::reference(&ctx,&f.workspace,&request).unwrap()}))).expect("reference-based pack must be routed through the shared dispatcher").result;
    assert_eq!(pack["target_execution"],false);assert_eq!(pack["source_fallback"],false);
    assert!(!pack["raw_evidence"].as_array().unwrap().is_empty());
    assert!(pack["raw_evidence"].as_array().unwrap().iter().any(|v|v["text"].as_str().unwrap().contains("Entry")));
}
