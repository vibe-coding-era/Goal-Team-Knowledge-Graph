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
        ("unicode.md", "# A deliberately long unrelated reference heading before the meaningful evidence\nCafé session resume support.\n"),
        ("tie-a.md", "# Equal score\nE_TIE_EXACT is reported.\n"),
        ("tie-b.md", "# Equal score\nE_TIE_EXACT is reported.\n"),
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


// One real local index fixture amortizes setup; every check precedes the final
// Unicode-window assertion so a failure does not conceal the passed controls.
#[test]
fn independent_intrafile_readonly_paging_spans_integrity_and_unicode_window() {
    let (_temp, writer, reference) = fixture(true);
    let root = writer.workspace_root().unwrap();
    let reader = CallContext::restricted(TransportKind::Test, vec![root.to_path_buf()], EffectPolicy::ReadOnly).unwrap();
    let authority = root.join(".gtkg/qk/runtime/query-authority.json");
    let authority_before = fs::read(&authority).unwrap();
    let mut query_payload = payload(&writer, &reference, "E_SESSION_LOST");
    let mut all = query_payload.clone(); all.max_results = 100;
    let whole = query::search(&reader, &all).unwrap();
    assert_eq!(whole["ranking_complete"], true);
    let whole_ids = hits(&whole).iter().map(|hit| hit["id"].as_str().unwrap().to_owned()).collect::<Vec<_>>();
    let mut pages = Vec::new(); let mut last_io = 0; let mut last_wall = 0;
    let manifest = index::load_manifest(&reader, root, &reference).unwrap();
    loop {
        let result = query::search(&reader, &query_payload).unwrap();
        assert_eq!(result["ranking_complete"], true);
        assert_eq!(result["source_fallback"], false);
        assert!(result["budget"]["io_bytes"].as_u64().unwrap() >= last_io);
        assert!(result["budget"]["wall_time_us"].as_u64().unwrap() >= last_wall);
        last_io = result["budget"]["io_bytes"].as_u64().unwrap();
        last_wall = result["budget"]["wall_time_us"].as_u64().unwrap();
        for hit in hits(&result) {
            pages.push(hit["id"].as_str().unwrap().to_owned());
            let original = fs::read(root.join(&manifest.archive_root).join("objects").join(hit["object_sha"].as_str().unwrap())).unwrap();
            let begin = hit["byte_start"].as_u64().unwrap() as usize;
            let end = hit["byte_end"].as_u64().unwrap() as usize;
            assert_eq!(&original[begin..end], hit["text"].as_str().unwrap().as_bytes());
            assert_eq!(hit["line_start"].as_u64().unwrap() as usize, original[..begin].iter().filter(|byte| **byte == b'\n').count() + 1);
            let last_byte = end.saturating_sub(1);
            assert_eq!(hit["line_end"].as_u64().unwrap() as usize, original[..last_byte].iter().filter(|byte| **byte == b'\n').count() + 1);
        }
        let Some(next) = result["continuation"].as_str() else { break; };
        query_payload.continuation = Some(next.into());
        assert!(pages.len() < 15, "pagination did not advance");
    }
    assert_eq!(pages, whole_ids, "paging must preserve the globally ranked candidate order");
    assert_eq!(pages.len(), pages.iter().collect::<BTreeSet<_>>().len());
    assert_eq!(fs::read(&authority).unwrap(), authority_before, "ReadOnly search rewrote authority");
    let tied = query::search(&reader, &payload(&writer, &reference, "E_TIE_EXACT")).unwrap();
    assert!(tied["candidate_ambiguities"].as_array().unwrap().iter().any(|value| value["kind"] == "candidate_ambiguity"));
    assert!(tied.get("knowledge_conflicts").is_none(), "a score tie is not contradictory knowledge");
    let shard = manifest.router[&index::token_bucket("exact:E_SESSION_LOST")].as_ref().unwrap();
    let shard_path = root.join(&shard.path); let shard_bytes = fs::read(&shard_path).unwrap();
    fs::remove_file(&shard_path).unwrap();
    assert!(query::search(&reader, &payload(&writer, &reference, "E_SESSION_LOST")).is_err(), "missing selected shard cannot return normal zero hits");
    fs::write(&shard_path, shard_bytes).unwrap();
    for spelling in ["CAFÉ", "Cafe\u{301}"] {
        let mut narrow = payload(&writer, &reference, spelling); narrow.max_tokens = 24;
        let result = query::search(&reader, &narrow).unwrap();
        assert_eq!(hits(&result)[0]["path"], "unicode.md");
        assert!(hits(&result)[0]["text"].as_str().unwrap().contains("Café"),
            "NFC/Unicode-fold matched the chunk but the evidence window lost its matched source token: query={spelling:?}, result={result}");
    }
}
