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
 fake[0].candidates=vec![fake[0].target.as_ref().unwrap().declaration.id.clone()];
 let forged=AnalysisCandidate{schema:"gtkg.qk.analysis-candidate/v1".into(),plan_ref,facts:facts.clone(),proofs:fake.clone(),routes:vec![]};let forged_ref=artifact::publish(&c,&work,"candidates",&forged).unwrap();
 let error=graph_projection::build(&c,&work,&source_ref,&forged_ref,&fake,&raw,&ctx).unwrap_err();
 assert!(error.contains("binding_rule_replay_rejected"),"self-consistent metadata must reach independent relation replay: {error}");
 let idx=index::build_with_graph(&c,&work,&source_ref,&facts,&ctx,Some(&graph)).expect("index must pin the confirmed graph projection");
 (t,c,idx,graph)
}

#[test]
fn self_consistent_wrong_same_name_graph_relation_is_rejected(){ let _ = fixture(false); }
