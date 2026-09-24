#![allow(clippy::unwrap_used)]
use super::*;
use crate::{EffectPolicy, TransportKind, v04::query};
use gtkg_protocol::v04::{PAYLOAD_REVISION, QueryPayload};
use std::{fs, process::Command};
use tempfile::TempDir;

fn git(root: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().into()
}

fn fixture(large: bool) -> (TempDir, CallContext, FileReceiptRef) {
    let temp = TempDir::new().unwrap();
    let root = fs::canonicalize(temp.path()).unwrap();
    let repo = root.join("repo");
    let work = root.join("work");
    fs::create_dir(&repo).unwrap();
    fs::create_dir(&work).unwrap();
    git(&repo, &["init", "-q"]);
    for (path, text) in [
        (
            "a.md",
            "# Recovery\nE_SESSION_LOST E_SESSION_LOST E_SESSION_LOST\n",
        ),
        (
            "b.md",
            "# Failure\nE_SESSION_LOST is recoverable after retry.\n",
        ),
        (
            "c.md",
            "# State\nE_SESSION_LOST retains the session archive.\n",
        ),
    ] {
        fs::write(repo.join(path), text).unwrap();
    }
    if large {
        // Real unrelated indexed content pays the unchanged 5% budget.
        let text = (0..16_000)
            .map(|i| format!("{:064x}\n", (i as u128 + 7) * 0x123456789abcdef123u128))
            .collect::<String>();
        fs::write(repo.join("unrelated.md"), text).unwrap();
    }
    git(&repo, &["add", "."]);
    git(
        &repo,
        &[
            "-c",
            "user.name=QK Fixture",
            "-c",
            "user.email=qk@example.invalid",
            "-c",
            "core.hooksPath=/dev/null",
            "commit",
            "-qm",
            "fixture",
        ],
    );
    let context = CallContext::restricted(
        TransportKind::Test,
        vec![work.clone(), repo.clone()],
        EffectPolicy::WorkspaceWrite,
    )
    .unwrap();
    source::capture(&source::SourceCaptureRequest {
        repository_id: "performance-fixture".into(),
        source_root: repo.clone(),
        source_commit: git(&repo, &["rev-parse", "HEAD"]),
        expected_tree: git(&repo, &["rev-parse", "HEAD^{tree}"]),
        output_path: work.join("archive"),
        policy: source::ScopePolicy::default(),
    })
    .unwrap();
    let source_ref = artifact::reference(
        &context,
        &work,
        &work.join("archive").join(source::LEDGER_FILE),
    )
    .unwrap();
    let index_ref = build(&context, &work, &source_ref, &[]).unwrap();
    (temp, context, index_ref)
}

fn payload(context: &CallContext, reference: &FileReceiptRef, policy: &str) -> QueryPayload {
    serde_json::from_value(serde_json::json!({
        "payload_revision": PAYLOAD_REVISION,
        "workspace_root": context.workspace_root().unwrap(),
        "index_ref": reference, "query": "E_SESSION_LOST", "query_policy": policy,
        "max_results": 3, "max_tokens": 8000, "continuation": null
    }))
    .unwrap()
}

fn query_validates_manifest_once(policy: &str) {
    let (_temp, context, reference) = fixture(true);
    let request = payload(&context, &reference, policy);
    for _ in 0..2 {
        MANIFEST_VALIDATIONS.with(|count| count.set(0));
        let result = query::search(&context, &request).unwrap();
        assert_eq!(result["ranking_complete"], true, "{result}");
        assert_eq!(result["evidence"].as_array().unwrap().len(), 3);
        assert!(result["scanned"]["evaluated_candidates"].as_u64().unwrap() >= 3);
        let validations = MANIFEST_VALIDATIONS.with(|count| count.get());
        assert_eq!(
            validations, 1,
            "one complete manifest validation per new query, including selected source reads; policy={policy}"
        );
    }
}

#[test]
fn performance_source_v1_validates_manifest_once_per_query() {
    query_validates_manifest_once(QUERY_POLICY);
}

#[test]
fn performance_source_v2_validates_manifest_once_per_query() {
    query_validates_manifest_once(gtkg_protocol::v04::SELECTIVE_QUERY_POLICY);
}

#[test]
fn performance_bare_manifest_reader_still_rejects_an_unselected_bad_route() {
    let (_temp, context, reference) = fixture(false);
    let workspace = context.workspace_root().unwrap();
    let mut manifest = load_manifest(&context, workspace, &reference).unwrap();
    let term = tokenize("E_SESSION_LOST").remove(0);
    let posting = load_postings(&context, workspace, &manifest, &term)
        .unwrap()
        .remove(0);
    manifest.chunk_router.remove("00");
    assert!(load_chunk(&context, workspace, &manifest, &posting).is_err());
    assert!(load_source_binding(&context, workspace, &manifest).is_err());
    assert!(lookup_chunk_ref(&context, workspace, &manifest, &posting.chunk_id).is_err());
}

#[test]
fn performance_new_query_rereads_its_pinned_manifest() {
    let (_temp, context, reference) = fixture(false);
    let request = payload(&context, &reference, QUERY_POLICY);
    query::search(&context, &request).unwrap();
    fs::write(
        context.workspace_root().unwrap().join(&reference.path),
        b"{}",
    )
    .unwrap();
    assert!(query::search(&context, &request).is_err());
}
