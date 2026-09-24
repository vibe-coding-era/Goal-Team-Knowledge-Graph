#![allow(clippy::unwrap_used)]
use gtkg_core::{CallContext,EffectPolicy,TransportKind};
use gtkg_core::v04::{artifact,analysis::{AnalysisPlan,AnalysisCandidate},source::{self,SourceCaptureRequest,ScopePolicy},graph_projection,index,query};
use gtkg_extract::v04::{AnalysisContext,extract,binding::bind};
use gtkg_protocol::{FileReceiptRef,v04::{QueryPayload,PAYLOAD_REVISION,PROFILE_ID}};
use serde_json::{json,Value};
use std::{collections::BTreeMap,fs,path::Path,process::Command};
use tempfile::TempDir;
fn git(root:&Path,args:&[&str])->String{let out=Command::new("git").arg("-C").arg(root).args(args).output().unwrap();assert!(out.status.success(),"{}",String::from_utf8_lossy(&out.stderr));String::from_utf8(out.stdout).unwrap().trim().into()}
fn fixture(large:bool)->(TempDir,CallContext,FileReceiptRef,FileReceiptRef){
 let t=TempDir::new().unwrap();let root=fs::canonicalize(t.path()).unwrap();let repo=root.join("repo");let work=root.join("work");fs::create_dir(&repo).unwrap();fs::create_dir(&work).unwrap();git(&repo,&["init","-q"]);
 let raw:BTreeMap<String,Vec<u8>>=[("app/caller.go","package app\nfunc Entry() { Helper() }\n"),("app/helper.go","package app\nfunc Helper() string { return \"real target evidence\" }\n"),("unrelated/helper.go","package app\nfunc Helper() string { return \"wrong same name\" }\n")].into_iter().map(|(p,s)|(p.into(),s.as_bytes().to_vec())).collect();
 for(p,s)in &raw{fs::create_dir_all(repo.join(p).parent().unwrap()).unwrap();fs::write(repo.join(p),s).unwrap();}
 if large{let body=(0..16000).map(|i|format!("{:064x}\n",(i as u128+7)*0x123456789abcdef123u128)).collect::<String>();fs::write(repo.join("unrelated.md"),body).unwrap();}
 git(&repo,&["add","."]);git(&repo,&["-c","user.name=QK Fixture","-c","user.email=qk@example.invalid","-c","core.hooksPath=/dev/null","commit","-qm","fixture"]);
 let c=CallContext::restricted(TransportKind::Test,vec![work.clone(),repo.clone()],EffectPolicy::WorkspaceWrite).unwrap();
 let ledger=source::capture(&SourceCaptureRequest{repository_id:"graph-fixture".into(),source_root:repo.clone(),source_commit:git(&repo,&["rev-parse","HEAD"]),expected_tree:git(&repo,&["rev-parse","HEAD^{tree}"]),output_path:work.join("archive"),policy:ScopePolicy::default()}).unwrap();
 let source_ref=artifact::reference(&c,&work,&work.join("archive").join(source::LEDGER_FILE)).unwrap();
 let ctx=AnalysisContext{snapshot_id:ledger.snapshot_id.clone(),..Default::default()};let facts=raw.iter().map(|(p,b)|extract(p,b,&ctx).unwrap()).collect::<Vec<_>>();let proofs=bind(&facts,&ctx);
 assert_eq!(proofs.len(),1);assert_eq!(proofs[0].proof_status,"confirmed");assert_eq!(proofs[0].target.as_ref().unwrap().path,"app/helper.go");
 let plan=AnalysisPlan{schema:"gtkg.qk.analysis-plan/v1".into(),profile:PROFILE_ID.into(),source_ref:source_ref.clone(),snapshot_id:ledger.snapshot_id,selection_manifest_sha256:ledger.selection_manifest.sha256,context:ctx.clone()};
 let plan_ref=artifact::publish(&c,&work,"plans",&plan).unwrap();
 let candidate=AnalysisCandidate{schema:"gtkg.qk.analysis-candidate/v1".into(),plan_ref:plan_ref.clone(),facts:facts.clone(),proofs:proofs.clone(),routes:vec![]};
 let candidate_ref=artifact::publish(&c,&work,"candidates",&candidate).unwrap();
 let graph=graph_projection::build(&c,&work,&source_ref,&candidate_ref,&proofs,&raw,&ctx).expect("confirmed projection must independently replay and publish source-bound links");
 let mut fake=proofs.clone();fake[0].target.as_mut().unwrap().path="unrelated/helper.go".into();fake[0].target.as_mut().unwrap().declaration=facts.iter().find(|f|f.path=="unrelated/helper.go").unwrap().declarations.iter().find(|d|d.name=="Helper").unwrap().clone();
 let forged=AnalysisCandidate{schema:"gtkg.qk.analysis-candidate/v1".into(),plan_ref,facts:facts.clone(),proofs:fake.clone(),routes:vec![]};let forged_ref=artifact::publish(&c,&work,"candidates",&forged).unwrap();
 assert!(graph_projection::build(&c,&work,&source_ref,&forged_ref,&fake,&raw,&ctx).is_err(),"real same-name target spans must not turn a wrong relation into confirmed");
 let idx=index::build_with_graph(&c,&work,&source_ref,&facts,&ctx,Some(&graph)).expect("index must pin the confirmed graph projection");
 (t,c,idx,graph)
}
fn payload(c:&CallContext,r:&FileReceiptRef)->QueryPayload{serde_json::from_value(json!({"payload_revision":PAYLOAD_REVISION,"workspace_root":c.workspace_root().unwrap(),"index_ref":r,"query":"Entry 调用流程","query_policy":index::QUERY_POLICY,"max_results":8,"max_tokens":8000,"continuation":null})).unwrap()}
#[test]
fn confirmed_cross_file_target_is_packed_without_same_name_guessing(){
 let(_t,c,idx,graph)=fixture(true);let root=c.workspace_root().unwrap();let m=index::load_manifest(&c,root,&idx).unwrap();assert_eq!(m.graph_ref,Some(graph.clone()));
 let (links,io)=graph_projection::load_related(&c,root,&graph,"app/caller.go").unwrap();assert_eq!(links.len(),1);assert_eq!(links[0].target_path,"app/helper.go");assert_eq!(links[0].target_name,"Helper");assert!(io>fs::metadata(root.join(&graph.path)).unwrap().len());
 let result=query::search(&c,&payload(&c,&idx)).unwrap();assert_eq!(result["ranking_complete"],true,"{result}");
 let hits=result["evidence"].as_array().unwrap();assert!(hits.iter().any(|h|h["path"]=="app/caller.go"));
 let target=hits.iter().find(|h|h["path"]=="app/helper.go").expect("structural context must carry independently confirmed cross-file target source");
 assert!(target["text"].as_str().unwrap().contains("real target evidence"));assert_eq!(target["graph_relation"]["call_id"],links[0].call_id);assert_eq!(target["source_span_verified"],true);
 assert!(!hits.iter().any(|h|h["path"]=="unrelated/helper.go"));assert!(result["budget"]["structural_expansions"].as_u64().unwrap()<=2);assert!(result["budget"]["io_bytes"].as_u64().unwrap()<=result["budget"]["io_limit"].as_u64().unwrap());
 let g:Value=serde_json::from_slice(&fs::read(root.join(&graph.path)).unwrap()).unwrap();assert_eq!(g["router"].as_object().unwrap().len(),256);assert_eq!(g["total_links"],1);
 let selected=g["router"][index::token_bucket("app/caller.go")]["path"].as_str().unwrap();let shard=root.join(selected);let bytes=fs::read(&shard).unwrap();fs::write(&shard,b"{}").unwrap();
 assert!(graph_projection::load_related(&c,root,&graph,"app/caller.go").is_err());assert!(query::search(&c,&payload(&c,&idx)).is_err(),"graph tampering cannot silently remove structural evidence");
 fs::write(&shard,bytes).unwrap();fs::remove_file(&shard).unwrap();assert!(graph_projection::load_related(&c,root,&graph,"app/caller.go").is_err(),"missing declared graph shard must fail closed");
}
#[test]
fn graph_expansion_does_not_gain_a_fresh_small_index_budget(){
 let(_t,c,idx,_graph)=fixture(false);let out=query::search(&c,&payload(&c,&idx)).unwrap();let m=index::load_manifest(&c,c.workspace_root().unwrap(),&idx).unwrap();
 assert_eq!(out["budget"]["io_limit"],m.total_index_bytes/20);assert_eq!(out["status"],"partial");assert_eq!(out["answerability"],"budget_exhausted");assert_eq!(out["ranking_complete"],false);assert_eq!(out["budget"]["structural_expansions"],0);
}
