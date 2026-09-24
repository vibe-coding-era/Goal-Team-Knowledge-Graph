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
fn global_rank_cursor_source_and_chinese_plan_contract() {
    let (_t, c, r) = fixture(true);
    let root = c.workspace_root().unwrap();
    let mut p = payload(&c, &r, "E_SESSION_LOST");
    let first = query::search(&c, &p).expect("implemented bounded query must return a source-bound first page");
    assert_eq!(first["ranking_complete"], true, "{first}");
    assert_eq!(hits(&first)[0]["path"], "high.md", "tf/idf + length normalization must rank the strongest evidence before node-ID paging");
    assert_eq!(first["original_query"], p.query);
    assert_eq!(first["source_fallback"], false);
    assert!(first["budget"]["io_bytes"].as_u64().unwrap() <= first["budget"]["io_limit"].as_u64().unwrap());
    assert_eq!(first["verification_scope"]["full_graph_reads"], 0);
    assert_eq!(first["verification_scope"]["source_ledger_reads"], 1);
    assert!(first["continuation"].is_string());
    let mut bad = p.clone(); bad.query = "different".into(); bad.continuation = first["continuation"].as_str().map(str::to_owned);
    assert!(query::search(&c, &bad).is_err(), "cross-query cursor must fail closed");
    bad = p.clone();
    let mut token = first["continuation"].as_str().unwrap().as_bytes().to_vec();
    let last = token.len()-1; token[last] = if token[last] == b'0' { b'1' } else { b'0' };
    bad.continuation = Some(String::from_utf8(token).unwrap());
    assert!(query::search(&c, &bad).is_err(), "tampered cursor must fail closed");
    let mut seen = BTreeSet::new(); let mut page = first;
    let mut previous_score = f64::INFINITY; let mut previous_io = 0;
    loop {
        for h in hits(&page) {
            assert!(seen.insert(h["id"].as_str().unwrap().to_owned()), "pagination repeated a chunk");
            let score = h["score"].as_f64().unwrap(); assert!(score <= previous_score); previous_score = score;
            assert!(!h["text"].as_str().unwrap().is_empty());
            assert!(h["line_start"].as_u64().unwrap() > 0);
            assert!(h["score_reasons"].is_array());
        }
        let io = page["budget"]["io_bytes"].as_u64().unwrap(); assert!(io >= previous_io); previous_io = io;
        if page["continuation"].is_null() { break; }
        assert!(seen.len() < 20, "cursor must progress");
        p.continuation = page["continuation"].as_str().map(str::to_owned);
        page = query::search(&c, &p).unwrap();
        assert_eq!(page["ranking_complete"], true);
    }
    assert!(seen.len() >= 3);
    let zh = query::search(&c, &payload(&c, &r, "会话恢复在哪里实现？")).unwrap();
    assert!(zh["query_plan"]["initial_subqueries"].as_array().unwrap().len() <= 4);
    assert!(zh["query_plan"]["expanded_terms"].as_array().unwrap().iter().any(|x| x == "resume"));
    assert!(hits(&zh).iter().any(|x| x["text"].as_str().unwrap().to_lowercase().contains("session")), "bounded bilingual aliases must retrieve source evidence: {zh}");
    let mut tiny = payload(&c, &r, "Agent.Session.resume"); tiny.max_tokens = 12;
    let packed = query::search(&c, &tiny).unwrap();
    assert!(packed["budget"]["evidence_tokens"].as_u64().unwrap() <= 12);
    assert_eq!(packed["truncation"]["tokens"], true);
    // The original repo may disappear: all returned source bytes must come from the archive.
    fs::rename(root.parent().unwrap().join("repo"), root.parent().unwrap().join("moved-repo")).unwrap();
    let moved = query::search(&c, &payload(&c, &r, "Agent.Session.resume")).unwrap();
    assert!(!hits(&moved).is_empty()); assert_eq!(moved["source_fallback"], false);
    let h = &hits(&moved)[0];
    let manifest = index::load_manifest(&c, root, &r).unwrap();
    let object = root.join(&manifest.archive_root).join("objects").join(h["object_sha"].as_str().unwrap());
    assert!(object.exists(), "source object path must be real");
    fs::write(object, b"tampered archived bytes").unwrap();
    assert!(query::search(&c, &payload(&c, &r, "Agent.Session.resume")).is_err(), "source mutation must fail instead of falling back to repository");
}

#[test]
fn small_index_budget_is_not_silently_enlarged() {
    let (_t, c, r) = fixture(false);
    let p = payload(&c, &r, "E_SESSION_LOST");
    let out = query::search(&c, &p).expect("small source still returns an honest budget receipt");
    let m = index::load_manifest(&c, c.workspace_root().unwrap(), &r).unwrap();
    assert_eq!(out["budget"]["io_limit"], m.total_index_bytes / 20);
    assert_eq!(out["status"], "partial"); assert_eq!(out["answerability"], "budget_exhausted");
    assert_eq!(out["ranking_complete"], false);
    assert_eq!(out["truncation"]["budget"], true);
    assert!(out["continuation"].is_string());
    assert!(hits(&out).is_empty());
}
