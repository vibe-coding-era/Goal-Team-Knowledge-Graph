#![allow(clippy::unwrap_used)]
use gtkg_core::{CallContext, EffectPolicy, TransportKind};
use gtkg_core::v04::{artifact, index, source::{self, ScopePolicy, SourceCaptureRequest}};
use gtkg_protocol::v04::{QueryPayload, PAYLOAD_REVISION};
use serde_json::json;
use gtkg_core::v04::query;
use sha2::{Digest, Sha256};
use std::{fs, path::Path, process::Command};

fn git(root: &Path, args: &[&str]) -> String {
    let o = Command::new("git").arg("-C").arg(root).args(args).output().unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    String::from_utf8(o.stdout).unwrap().trim().into()
}

fn run_query(ctx:&CallContext,p:&QueryPayload)->Result<serde_json::Value,String> {
    let Ok(binary)=std::env::var("QK_POLICY_TEST_BINARY") else { return query::search(ctx,p); };
    let request=p.workspace_root.join("test-query-request.json");
    fs::write(&request,serde_json::to_vec(&json!({"protocol_version":"gtkg.protocol/v2","operation_id":"graph.search","request_id":"selective-test","payload":p})).unwrap()).unwrap();
    let output=Command::new(&binary).args(["v2-op","graph.search","--profile","graph","--request"]).arg(request).args(["--output","json"]).current_dir(&p.workspace_root).output().unwrap();
    if !output.status.success() { return Err(String::from_utf8_lossy(&output.stdout).chars().take(700).collect()); }
    let out:serde_json::Value=serde_json::from_slice(&output.stdout).map_err(|e|e.to_string())?;
    out.get("result").cloned().ok_or_else(|| "missing Core result".into())
}
#[test]
fn selective_policy_uses_discriminative_groups_before_bounded_candidate_admission() {
    if let Ok(binary)=std::env::var("QK_POLICY_TEST_BINARY") { println!("Query executable SHA256 {}",hex::encode(Sha256::digest(fs::read(binary).unwrap()))); }
    let tmp=tempfile::tempdir().unwrap(); let repo=tmp.path().join("repo"); let work=tmp.path().join("work");
    fs::create_dir(&repo).unwrap();fs::create_dir(&work).unwrap();git(&repo,&["init","-q"]);
    let body=(0..2105).map(|i| {
        let words=(0..32).map(|j| format!("u{i:06}v{j:03}")).collect::<Vec<_>>().join(" ");
        format!("# Noise {i}\nsession {words}\n\n")
    }).collect::<String>();
    fs::write(repo.join("target.md"), "# Distinct first\nsession recovery resume Exact_Signal UniqueTailOne\n\n# Distinct second\nsession recovery resume Exact_Signal UniqueTailTwo\n").unwrap();
    fs::write(repo.join("manual.md"),body).unwrap();git(&repo,&["add","."]);
    git(&repo,&["-c","user.name=Fixture","-c","user.email=fixture@example.invalid","-c","core.hooksPath=/dev/null","commit","-qm","selective fixture"]);
    source::capture(&SourceCaptureRequest{repository_id:"selective".into(),source_root:repo.clone(),source_commit:git(&repo,&["rev-parse","HEAD"]),expected_tree:git(&repo,&["rev-parse","HEAD^{tree}"]),output_path:work.join("archive"),policy:ScopePolicy::default()}).unwrap();
    let ctx=CallContext::restricted(TransportKind::Test,vec![work.clone(),repo],EffectPolicy::WorkspaceWrite).unwrap();
    let source_ref=artifact::reference(&ctx,&work,&work.join("archive").join(source::LEDGER_FILE)).unwrap();
    let reference=index::build(&ctx,&work,&source_ref,&[]).unwrap();
    let before=fs::read(work.join(&reference.path)).unwrap();
    let mut p:QueryPayload=serde_json::from_value(json!({"payload_revision":PAYLOAD_REVISION,"workspace_root":work,"index_ref":reference,"query":"session recovery","query_policy":"gtkg.qk.query/v2","max_results":1,"max_tokens":8000,"continuation":null})).unwrap();
    let out=run_query(&ctx,&p).expect("explicit selective policy must use late discriminative groups before admitting candidate blocks");
    assert_eq!(out["status"],"complete");assert_eq!(out["ranking_complete"],true);
    assert_eq!(out["scanned"]["candidates"],2);
    assert!(out["scanned"]["posting_ids_observed"].as_u64().unwrap()>2000);
    assert_eq!(out["index_projection_policy"],index::QUERY_POLICY);
    assert_eq!(out["query_policy"],"gtkg.qk.query/v2");
    let first=&out["evidence"].as_array().unwrap()[0];assert!(first["text"].as_str().unwrap().contains("recovery"));
    assert_eq!(first["source_span_verified"],true);
    p.continuation=out["continuation"].as_str().map(str::to_owned);
    let next=run_query(&ctx,&p).unwrap();let second=&next["evidence"].as_array().unwrap()[0];
    assert_ne!(first["id"],second["id"]);assert_eq!(next["ranking_complete"],true);
    let mut incompatible=p.clone();incompatible.query_policy=index::QUERY_POLICY.into();assert!(run_query(&ctx,&incompatible).is_err());
    p.continuation=None;p.query="会话恢复".into();p.max_results=10;
    let zh=run_query(&ctx,&p).unwrap();assert_eq!(zh["ranking_complete"],true);assert_eq!(zh["scanned"]["candidates"],2);
    p.query="How does session recovery work?".into();let english=run_query(&ctx,&p).unwrap();assert_eq!(english["scanned"]["candidates"],2);assert_eq!(english["ranking_complete"],true);
    p.query="Exact_Signal".into();let exact=run_query(&ctx,&p).unwrap();assert_eq!(exact["ranking_complete"],true);assert_eq!(exact["scanned"]["candidates"],2);
    p.query="session".into();let broad=run_query(&ctx,&p).unwrap();assert_eq!(broad["status"],"partial");assert_eq!(broad["ranking_complete"],false);assert_eq!(broad["scanned"]["candidates"],2000);
    assert!(broad["budget"]["io_bytes"].as_u64().unwrap()<=broad["budget"]["io_limit"].as_u64().unwrap());
    assert!(broad["scanned"]["postings"].as_u64().unwrap()<=100000);
    p.query_policy=index::QUERY_POLICY.into();let legacy=run_query(&ctx,&p).unwrap();assert_eq!(legacy["status"],"partial");
    assert_eq!(before,fs::read(work.join(&reference.path)).unwrap());
}
