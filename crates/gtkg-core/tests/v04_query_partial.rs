#![allow(clippy::unwrap_used)]
use gtkg_core::{CallContext, EffectPolicy, TransportKind};
use gtkg_core::v04::{artifact, index, source::{self, ScopePolicy, SourceCaptureRequest}};
use gtkg_protocol::v04::{QueryPayload, PAYLOAD_REVISION};
use serde_json::json;
use gtkg_core::v04::query;
use std::{fs, path::Path, process::Command};

fn git(root: &Path, args: &[&str]) -> String {
    let o = Command::new("git").arg("-C").arg(root).args(args).output().unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    String::from_utf8(o.stdout).unwrap().trim().into()
}

#[test]
fn candidate_limit_keeps_observed_verified_evidence_without_claiming_global_rank() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("repo"); let work = tmp.path().join("work");
    fs::create_dir(&repo).unwrap(); fs::create_dir(&work).unwrap();
    git(&repo, &["init", "-q"]);
    let body = (0..2105).map(|i| {
        let words = (0..16).map(|j| format!("item{i:06}word{j:02}")).collect::<Vec<_>>().join(" ");
        format!("# Section {i}\nQK_COMMON_BUDGET {words}\n\n")
    }).collect::<String>();
    fs::write(repo.join("manual.md"), body).unwrap();
    git(&repo, &["add", "."]);
    git(&repo, &["-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "-c", "core.hooksPath=/dev/null", "commit", "-qm", "candidate fixture"]);
    source::capture(&SourceCaptureRequest {repository_id:"partial".into(),source_root:repo.clone(),source_commit:git(&repo,&["rev-parse","HEAD"]),expected_tree:git(&repo,&["rev-parse","HEAD^{tree}"]),output_path:work.join("archive"),policy:ScopePolicy::default()}).unwrap();
    let ctx=CallContext::restricted(TransportKind::Test,vec![work.clone(),repo],EffectPolicy::WorkspaceWrite).unwrap();
    let source_ref=artifact::reference(&ctx,&work,&work.join("archive").join(source::LEDGER_FILE)).unwrap();
    let reference=index::build(&ctx,&work,&source_ref,&[]).unwrap();
    let p:QueryPayload=serde_json::from_value(json!({"payload_revision":PAYLOAD_REVISION,"workspace_root":work,"index_ref":reference,"query":"QK_COMMON_BUDGET","query_policy":index::QUERY_POLICY,"max_results":2,"max_tokens":8000,"continuation":null})).unwrap();
    let out=query::search(&ctx,&p).unwrap();
    assert_eq!(out["status"],"partial");
    assert_eq!(out["ranking_complete"],false);
    assert_eq!(out["scanned"]["candidates"],2000);
    let hits=out["evidence"].as_array().unwrap();
    assert!(!hits.is_empty(), "already observed candidates can be source-verified within the remaining IO/time allowance: {out}");
    assert!(hits.iter().all(|h| h["source_span_verified"]==true && h["text"].as_str().unwrap().contains("QK_COMMON_BUDGET")));
    assert!(out["budget"]["io_bytes"].as_u64().unwrap()<=out["budget"]["io_limit"].as_u64().unwrap());
    let mut next=p; next.continuation=out["continuation"].as_str().map(str::to_owned);
    let resumed=query::search(&ctx,&next).unwrap();
    assert_eq!(resumed["ranking_complete"],false);
    assert_eq!(resumed["scanned"]["candidates"],2000);
    for h in resumed["evidence"].as_array().unwrap() { assert!(!hits.iter().any(|old| old["id"]==h["id"])); }
}
