#![allow(clippy::unwrap_used)]
use gtkg_core::v04::{artifact, index, query, source::{self, ScopePolicy, SourceCaptureRequest}};
use gtkg_core::{CallContext, EffectPolicy, TransportKind};
use gtkg_protocol::{FileReceiptRef, v04::{QueryPayload, PAYLOAD_REVISION}};
use serde_json::{Value, json};
use std::{collections::BTreeSet, fs, path::Path, process::Command};
use tempfile::TempDir;

fn git(root: &Path, args: &[&str]) -> String {
    let out = Command::new("git").arg("-C").arg(root).args(args).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8(out.stdout).unwrap().trim().into()
}
fn fixture(large: bool) -> (TempDir, CallContext, FileReceiptRef) {
    let t = TempDir::new().unwrap();
    let root = fs::canonicalize(t.path()).unwrap();
    let repo = root.join("repo");
    let work = root.join("work");
    fs::create_dir(&repo).unwrap(); fs::create_dir(&work).unwrap();
    git(&repo, &["init", "-q"]);
    let low = format!("# Reference\nE_SESSION_LOST {}\n", "irrelevant ".repeat(65));
    for (path, body) in [
        ("high.md", "# Recovery\nE_SESSION_LOST E_SESSION_LOST E_SESSION_LOST\nSession resume restores archived messages.\n"),
        ("low.md", low.as_str()),
        ("medium.md", "# Failure\nE_SESSION_LOST indicates lost session. Retry later when storage recovers.\n"),
        ("session.md", "# Implementation\nAgent.Session.resume loads the session archive and resumes message history.\n"),
        ("unicode.md", "# Unicode\nCafé session resume support.\n"),
        ("other.md", "# Different failure\nE_SESSION_LOST_OTHER is distinct from the full error code.\n"),
    ] { fs::write(repo.join(path), body).unwrap(); }
    if large {
        // Real indexed unrelated source content, never an inflated manifest denominator.
        let body = (0..16_000).map(|i| format!("{:064x}\n", (i as u128 + 7) * 0x123456789abcdef123u128)).collect::<String>();
        fs::write(repo.join("unrelated.md"), body).unwrap();
    }
    git(&repo, &["add", "."]);
    git(&repo, &["-c", "user.name=QK Fixture", "-c", "user.email=qk@example.invalid", "-c", "core.hooksPath=/dev/null", "commit", "-qm", "fixture"]);
    let c = CallContext::restricted(TransportKind::Test, vec![work.clone(), repo.clone()], EffectPolicy::WorkspaceWrite).unwrap();
    source::capture(&SourceCaptureRequest {
        repository_id: "query-fixture".into(), source_root: repo.clone(),
        source_commit: git(&repo, &["rev-parse", "HEAD"]), expected_tree: git(&repo, &["rev-parse", "HEAD^{tree}"]),
        output_path: work.join("archive"), policy: ScopePolicy::default(),
    }).unwrap();
    let source_ref = artifact::reference(&c, &work, &work.join("archive").join(source::LEDGER_FILE)).unwrap();
    let r = index::build(&c, &work, &source_ref, &[]).unwrap();
    (t, c, r)
}
fn payload(c: &CallContext, r: &FileReceiptRef, q: &str) -> QueryPayload {
    serde_json::from_value(json!({"payload_revision":PAYLOAD_REVISION,"workspace_root":c.workspace_root().unwrap(),"index_ref":r,"query":q,"query_policy":index::QUERY_POLICY,"max_results":1,"max_tokens":8000,"continuation":null})).unwrap()
}
fn hits(v: &Value) -> &Vec<Value> { v["evidence"].as_array().unwrap() }


#[test]
#[ignore = "executed only as a separate cold process by the parent test"]
fn cold_resume_worker() {
    let input = std::env::var("GTKG_QK_COLD_INPUT").unwrap();
    let output = std::env::var("GTKG_QK_COLD_OUTPUT").unwrap();
    let p: QueryPayload = serde_json::from_slice(&fs::read(input).unwrap()).unwrap();
    let c = CallContext::restricted(TransportKind::Test, vec![p.workspace_root.clone()], EffectPolicy::ReadOnly).unwrap();
    let value = query::search(&c, &p).expect("cold process must authenticate and resume a workspace cursor");
    fs::write(output, serde_json::to_vec(&value).unwrap()).unwrap();
}
#[test]
fn cold_resume_nfc_no_answer_and_selected_shard_integrity() {
    let (_t, c, r) = fixture(true);
    let root = c.workspace_root().unwrap();
    let read_only = CallContext::restricted(TransportKind::Test, vec![root.to_path_buf()], EffectPolicy::ReadOnly).unwrap();
    // A decomposed user identifier must match NFC-folded source spelling.
    let nfc = query::search(&read_only, &payload(&c, &r, "Cafe\u{301}")).unwrap();
    assert!(hits(&nfc).iter().any(|h| h["path"] == "unicode.md"), "NFC equivalent query lost its folded channel");
    let mut p = payload(&c, &r, "E_SESSION_LOST");
    let first = query::search(&read_only, &p).unwrap();
    assert_eq!(first["ranking_complete"], true);
    p.continuation = first["continuation"].as_str().map(str::to_owned);
    assert!(p.continuation.is_some());
    let input = root.join("cold-input.json"); let output = root.join("cold-output.json");
    fs::write(&input, serde_json::to_vec(&p).unwrap()).unwrap();
    let child = Command::new(std::env::current_exe().unwrap())
        .args(["--ignored", "--exact", "cold_resume_worker", "--nocapture"])
        .env("GTKG_QK_COLD_INPUT", &input).env("GTKG_QK_COLD_OUTPUT", &output).output().unwrap();
    assert!(child.status.success(), "{} {}", String::from_utf8_lossy(&child.stdout), String::from_utf8_lossy(&child.stderr));
    let next: Value = serde_json::from_slice(&fs::read(output).unwrap()).unwrap();
    assert_ne!(hits(&first)[0]["id"], hits(&next)[0]["id"]);
    assert!(next["budget"]["io_bytes"].as_u64().unwrap() > first["budget"]["io_bytes"].as_u64().unwrap());
    assert_eq!(next["continuation_scope"], "same_workspace_durable_authority");
    let absent = query::search(&read_only, &payload(&c, &r, "nonexistentqkxylophone")).unwrap();
    assert!(hits(&absent).is_empty()); assert_eq!(absent["ranking_complete"], true);
    assert_eq!(absent["answerability"], "no_match_within_declared_scope");
    assert!(absent["scope_limitations"].as_array().unwrap().iter().any(|x| x.as_str().unwrap().contains("do not establish absence")));
    let mut small = payload(&c, &r, "Agent.Session.resume"); small.max_tokens = 12;
    let window = query::search(&read_only, &small).unwrap();
    let h = &hits(&window)[0];
    assert!(h["text"].as_str().unwrap().contains("Agent"), "tight evidence must contain the matched symbol rather than only a heading");
    let manifest = index::load_manifest(&c, root, &r).unwrap();
    let source_bytes = fs::read(root.join(&manifest.archive_root).join("objects").join(h["object_sha"].as_str().unwrap())).unwrap();
    assert_eq!(&source_bytes[h["byte_start"].as_u64().unwrap() as usize..h["byte_end"].as_u64().unwrap() as usize], h["text"].as_str().unwrap().as_bytes());
    let shard = manifest.router[&index::token_bucket("exact:E_SESSION_LOST")].as_ref().unwrap();
    let path = root.join(&shard.path); let before = fs::read(&path).unwrap(); fs::write(&path, b"{}").unwrap();
    assert!(query::search(&read_only, &payload(&c, &r, "E_SESSION_LOST")).is_err(), "tampered selected shard must not become a no-match result");
    fs::write(&path, &before).unwrap();
    let authority = root.join(".gtkg/qk/runtime/query-authority.json"); let before = fs::read(&authority).unwrap();
    fs::remove_file(&authority).unwrap();
    assert!(query::search(&read_only, &payload(&c, &r, "E_SESSION_LOST")).is_err());
    assert!(!authority.exists(), "read-only search must not initialize missing runtime authority");
    fs::write(&authority, before).unwrap();
}
