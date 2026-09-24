#![allow(clippy::unwrap_used)]
use super::*;
use crate::{EffectPolicy, TransportKind};
use std::{fs, process::Command};
use tempfile::TempDir;

fn git(path: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(path)
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
fn fixture(text: &str) -> (TempDir, CallContext, FileReceiptRef) {
    let temp = TempDir::new().unwrap();
    let root = fs::canonicalize(temp.path()).unwrap();
    let repo = root.join("repo");
    let work = root.join("work");
    fs::create_dir(&repo).unwrap();
    fs::create_dir(&work).unwrap();
    git(&repo, &["init", "-q"]);
    fs::write(repo.join("source.md"), text).unwrap();
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
        repository_id: "checked-reader".into(),
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
fn posting(context: &CallContext, reader: &QueryIndexReader<'_>) -> Posting {
    let term = tokenize("alpha").remove(0);
    load_postings(
        context,
        context.workspace_root().unwrap(),
        reader.manifest(),
        &term,
    )
    .unwrap()
    .remove(0)
}

#[test]
fn checked_reader_rejects_repinned_unselected_router_corruption() {
    let (_temp, context, reference) = fixture("# Example\nalpha beta\n");
    let work = context.workspace_root().unwrap();
    let mut manifest = load_manifest(&context, work, &reference).unwrap();
    manifest.chunk_router.remove("00");
    let path = work.join(&reference.path);
    fs::write(&path, serde_json::to_vec(&manifest).unwrap()).unwrap();
    let repinned = artifact::reference(&context, work, &path).unwrap();
    let error = QueryIndexReader::load(&context, work, &repinned)
        .err()
        .unwrap();
    assert!(error.contains("complete 256-bucket router"), "{error}");
}

#[test]
fn checked_reader_rejects_correct_bytes_in_the_wrong_manifest_location() {
    let (_temp, context, reference) = fixture("# Example\nalpha beta\n");
    let work = context.workspace_root().unwrap();
    let wrong = work.join("wrong-manifest.json");
    fs::copy(work.join(&reference.path), &wrong).unwrap();
    let repinned = artifact::reference(&context, work, &wrong).unwrap();
    let error = QueryIndexReader::load(&context, work, &repinned)
        .err()
        .unwrap();
    assert!(error.contains("index root location mismatch"), "{error}");
}

#[test]
fn checked_reader_keeps_its_manifest_immutable_and_rechecks_selected_bytes() {
    let (_temp, context, reference) = fixture("# Example\nalpha beta\n");
    let work = context.workspace_root().unwrap();
    let (reader, _) = QueryIndexReader::load(&context, work, &reference).unwrap();
    let p = posting(&context, &reader);
    let mut independent_copy = reader.manifest().clone();
    independent_copy.chunk_router.remove("00");
    assert_eq!(reader.manifest().chunk_router.len(), 256);
    assert!(load_chunk(&context, work, &independent_copy, &p).is_err());
    reader.load_chunk(&p).unwrap();
    fs::write(work.join(&p.chunk_ref.path), b"{}").unwrap();
    assert!(
        reader.load_chunk(&p).is_err(),
        "a checked root does not authenticate subsequently changed selected bytes"
    );
}

#[test]
fn checked_reader_rechecks_selected_chunk_router() {
    let (_temp, context, reference) = fixture("# Example\nalpha beta\n");
    let work = context.workspace_root().unwrap();
    let (reader, _) = QueryIndexReader::load(&context, work, &reference).unwrap();
    let p = posting(&context, &reader);
    reader.load_chunk_by_id(&p.chunk_id).unwrap();
    let route = reader.manifest().chunk_router[&p.chunk_id[..2]]
        .as_ref()
        .unwrap();
    fs::write(work.join(&route.path), b"{}").unwrap();
    assert!(reader.lookup_chunk_ref(&p.chunk_id).is_err());
    assert!(reader.load_chunk_by_id(&p.chunk_id).is_err());
}

#[test]
fn checked_reader_does_not_accept_a_different_source_binding() {
    let (_a, context_a, reference_a) = fixture("# Example\nalpha first\n");
    let (_b, context_b, reference_b) = fixture("# Example\nalpha different source\n");
    let (reader_a, _) = QueryIndexReader::load(
        &context_a,
        context_a.workspace_root().unwrap(),
        &reference_a,
    )
    .unwrap();
    let (reader_b, _) = QueryIndexReader::load(
        &context_b,
        context_b.workspace_root().unwrap(),
        &reference_b,
    )
    .unwrap();
    let p = posting(&context_a, &reader_a);
    let chunk = reader_a.load_chunk(&p).unwrap();
    let (binding_a, _) = reader_a.load_source_binding().unwrap();
    let (binding_b, _) = reader_b.load_source_binding().unwrap();
    reader_a
        .validate_chunk_source_with_binding(&chunk, &binding_a)
        .unwrap();
    assert!(
        reader_a
            .validate_chunk_source_with_binding(&chunk, &binding_b)
            .is_err()
    );
}
