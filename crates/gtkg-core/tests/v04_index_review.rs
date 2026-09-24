//! Independent evidence/source-authority adversaries. No target source execution.
#![allow(clippy::unwrap_used)]
use gtkg_core::v04::{
    artifact,
    index::*,
    source::{self, ScopePolicy, SourceCaptureRequest},
};
use gtkg_core::{CallContext, EffectPolicy, TransportKind};
use gtkg_extract::v04::{AnalysisContext, extract};
use gtkg_protocol::FileReceiptRef;
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, fs, path::Path, process::Command};
use tempfile::TempDir;
fn git(root: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap().trim().into()
}
fn fixture(
    files: &[(&str, &str)],
) -> (
    TempDir,
    CallContext,
    FileReceiptRef,
    source::SourceCoverageLedger,
) {
    let temp = TempDir::new().unwrap();
    let root = fs::canonicalize(temp.path()).unwrap();
    let repo = root.join("repo");
    let work = root.join("work");
    fs::create_dir(&repo).unwrap();
    fs::create_dir(&work).unwrap();
    git(&repo, &["init", "-q"]);
    for (p, s) in files {
        fs::write(repo.join(p), s).unwrap();
    }
    git(&repo, &["add", "."]);
    git(
        &repo,
        &[
            "-c",
            "user.name=Independent QK QA",
            "-c",
            "user.email=qa@example.invalid",
            "-c",
            "core.hooksPath=/dev/null",
            "commit",
            "-qm",
            "fixture",
        ],
    );
    let ctx = CallContext::restricted(
        TransportKind::Test,
        vec![work.clone(), repo.clone()],
        EffectPolicy::WorkspaceWrite,
    )
    .unwrap();
    let ledger = source::capture(&SourceCaptureRequest {
        repository_id: "independent-qa".into(),
        source_root: repo.clone(),
        source_commit: git(&repo, &["rev-parse", "HEAD"]),
        expected_tree: git(&repo, &["rev-parse", "HEAD^{tree}"]),
        output_path: work.join("archive"),
        policy: ScopePolicy::default(),
    })
    .unwrap();
    let reference =
        artifact::reference(&ctx, &work, &work.join("archive").join(source::LEDGER_FILE)).unwrap();
    (temp, ctx, reference, ledger)
}

#[test]
fn source_parent_name_cannot_be_attached_to_another_real_declaration_span() {
    let src =
        "package p\nfunc First() { println(\"alpha\") }\nfunc Second() { println(\"beta\") }\n";
    let (_temp, ctx, reference, ledger) = fixture(&[("main.go", src)]);
    let mut analysis = AnalysisContext::default();
    analysis.snapshot_id = ledger.snapshot_id;
    let mut facts = extract("main.go", src.as_bytes(), &analysis).unwrap();
    let second = facts
        .declarations
        .iter()
        .find(|d| d.name == "Second")
        .unwrap()
        .span
        .clone();
    let first = facts
        .declarations
        .iter_mut()
        .find(|d| d.name == "First")
        .unwrap();
    first.span = second;
    assert!(
        build(&ctx, ctx.workspace_root().unwrap(), &reference, &[facts]).is_err(),
        "a real name span plus a different real function span cannot authenticate the parent relation"
    );
}

#[test]
fn nfc_channel_normalizes_combining_sequences_before_token_boundaries() {
    let folded = |text: &str| {
        tokenize(text)
            .into_iter()
            .filter(|t| t.starts_with("fold:"))
            .collect::<BTreeSet<_>>()
    };
    let composed = folded("Résumé");
    let decomposed = folded("Re\u{301}sume\u{301}");
    assert!(composed.contains("fold:résumé"));
    assert_eq!(
        decomposed, composed,
        "canonically equivalent source bytes need the same NFC recall channel"
    );
}

#[test]
fn source_replay_rejects_real_object_bytes_cited_under_another_source_path() {
    let (_temp, ctx, reference, _) =
        fixture(&[("a.md", "alpha_content"), ("b.md", "beta_content")]);
    let root = ctx.workspace_root().unwrap();
    let index = build(&ctx, root, &reference, &[]).unwrap();
    let manifest = load_manifest(&ctx, root, &index).unwrap();
    let posts = load_postings(&ctx, root, &manifest, "exact:beta_content").unwrap();
    let mut chunk = load_chunk(&ctx, root, &manifest, &posts[0]).unwrap();
    validate_chunk_source(&ctx, root, &manifest, &chunk).unwrap();
    assert_eq!(chunk.path, "b.md");
    chunk.path = "a.md".into();
    let raw = serde_json::to_vec(&(
        &chunk.snapshot_id,
        &chunk.path,
        chunk.byte_start,
        chunk.byte_end,
        CHUNKER,
        TOKENIZER,
    ))
    .unwrap();
    chunk.id = hex::encode(Sha256::digest(&raw));
    assert!(
        validate_chunk_source(&ctx, root, &manifest, &chunk).is_err(),
        "the bytes/hash belong to b.md; source replay must not certify them as a.md"
    );
}
