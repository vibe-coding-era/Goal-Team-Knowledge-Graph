#[path = "v04_reviewed_query_fixture.rs"]
mod fixture;
use gtkg_core::{CallContext,EffectPolicy,TransportKind};
use gtkg_core::v04::{artifact,query,semantic_projection as semantic,context_pack as pack};
use gtkg_protocol::{FileReceiptRef,v04::{ArtifactPayload,QueryPayload,Revision}};
use std::{collections::BTreeMap,path::Path};
fn snapshot(root:&Path)->BTreeMap<String,Vec<u8>> {
    fn walk(root:&Path,dir:&Path,out:&mut BTreeMap<String,Vec<u8>>){for entry in std::fs::read_dir(dir).unwrap(){let entry=entry.unwrap();if entry.file_type().unwrap().is_dir(){walk(root,&entry.path(),out);}else{out.insert(entry.path().strip_prefix(root).unwrap().to_string_lossy().into_owned(),std::fs::read(entry.path()).unwrap());}}}
    let mut files=BTreeMap::new();walk(root,root,&mut files);files
}
#[test]
fn reviewed_query_conditions_budget_cursor_graph_and_terminal_pack_boundaries() {
    let (f,overlay)=fixture::input();
    let ro=CallContext::restricted(TransportKind::Test,vec![f.workspace.clone()],EffectPolicy::ReadOnly).unwrap();
    let payload=|query:&str,units,max_results,continuation|QueryPayload {payload_revision:Revision::R1,workspace_root:f.workspace.clone(),index_ref:overlay.clone(),query:query.into(),query_policy:semantic::QUERY_POLICY.into(),max_results,max_tokens:units,continuation};
    let before=snapshot(&f.workspace);
    let tiny=query::search(&ro,&payload("copper kestrel",1,5,None)).unwrap();
    assert!(tiny["reviewed_contexts"].as_array().unwrap().is_empty());
    assert!(!tiny["omitted"].as_array().unwrap().is_empty());
    assert!(tiny["budget"]["evidence_tokens"].as_u64().unwrap()<=1);
    let first=query::search(&ro,&payload("Entry",8000,1,None)).unwrap();
    let continuation=first["continuation"].as_str().expect("more source evidence requires continuation").to_string();
    let second=query::search(&ro,&payload("Entry",8000,1,Some(continuation.clone()))).unwrap();
    assert!(second["budget"]["io_bytes"].as_u64().unwrap()>first["budget"]["io_bytes"].as_u64().unwrap());
    assert!(query::search(&ro,&payload("different query",8000,1,Some(continuation.clone()))).is_err());
    let mut changed=continuation;changed.pop();changed.push('z');assert!(query::search(&ro,&payload("Entry",8000,1,Some(changed))).is_err());
    let graph=query::search(&ro,&payload("Bridge flow",8000,5,None)).unwrap();
    assert!(graph["evidence"].as_array().unwrap().iter().any(|e|e["path"]=="main.go"&&!e["graph_relation"].is_null()),"{graph}");
    assert!(graph["budget"]["usage"]["structural_expansions"].as_u64().unwrap()<=2);
    let (o,_):(semantic::QueryIndexOverlay,_)=artifact::read(&ro,&f.workspace,&overlay).unwrap();
    let mut raw_request=payload("Entry",8000,5,None);raw_request.index_ref=FileReceiptRef {path:o.base_index_ref.path,sha256:o.base_index_ref.sha256};assert!(query::search(&ro,&raw_request).is_err());
    assert!(before==snapshot(&f.workspace),"queries cannot mutate runtime or canonical artifacts");
    let original=query::search(&ro,&payload("copper kestrel",8000,5,None)).unwrap();
    let prep:&serde_json::Value=&original["pack_preparation"];
    let plan_path=f.workspace.join("staged-plan.json");let hits_path=f.workspace.join("staged-hits.json");
    std::fs::write(&plan_path,prep["plan_json"].as_str().unwrap()).unwrap();std::fs::write(&hits_path,prep["hits_json"].as_str().unwrap()).unwrap();
    let request=pack::PackRequest {schema:pack::REQUEST_SCHEMA.into(),plan_ref:artifact::reference(&f.context,&f.workspace,&plan_path).unwrap(),hits_ref:artifact::reference(&f.context,&f.workspace,&hits_path).unwrap(),pack_ticket:prep["pack_ticket"].as_str().unwrap().into(),max_context_units:8000};
    let request_ref=artifact::publish(&f.context,&f.workspace,"inputs",&request).unwrap();let staged_before=snapshot(&f.workspace);
    let packed=pack::execute(&ro,&ArtifactPayload {payload_revision:Revision::R1,workspace_root:f.workspace.clone(),artifact_ref:request_ref}).unwrap();
    assert_eq!(packed["terminal"],true);assert!(packed["budget"]["usage"]["io_bytes"].as_u64().unwrap()>=original["budget"]["io_bytes"].as_u64().unwrap());
    assert!(packed["budget"]["context_units"].as_u64().unwrap()<=8000);assert!(staged_before==snapshot(&f.workspace));
    assert!(query::search(&ro,&payload("copper kestrel",8000,5,Some(request.pack_ticket))).is_err());
}
