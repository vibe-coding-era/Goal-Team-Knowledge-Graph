#![allow(clippy::unwrap_used)]
use gtkg_core::{CallContext, EffectPolicy, TransportKind};
use gtkg_core::v04::{artifact, index, source::{self, ScopePolicy, SourceCaptureRequest}};
use sha2::{Digest, Sha256};
use std::{fs, path::Path, process::Command};

fn git(root: &Path, args: &[&str]) -> String {
    let o = Command::new("git").arg("-C").arg(root).args(args).output().unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    String::from_utf8(o.stdout).unwrap().trim().into()
}

#[test]
fn selective_posting_partition_does_not_scan_unrelated_terms() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("repo");
    let work = tmp.path().join("work");
    fs::create_dir(&repo).unwrap(); fs::create_dir(&work).unwrap();
    git(&repo, &["init", "-q"]);
    let term = "exact:QK_SPARSE_TARGET";
    let hash = hex::encode(Sha256::digest(term.as_bytes()));
    let distractors: Vec<String> = (0..100_000).map(|i| format!("qknoise{i:06}"))
        .filter(|t| {
            let h = hex::encode(Sha256::digest(format!("exact:{t}").as_bytes()));
            h[..2] == hash[..2] && h[2..3] != hash[2..3]
        }).take(16).collect();
    assert_eq!(distractors.len(), 16);
    fs::write(repo.join("target.md"), "# QK_SPARSE_TARGET\nExact source witness.\n").unwrap();
    fs::write(repo.join("unrelated.md"), (distractors.join(" ")+"\n\n").repeat(400)).unwrap();
    git(&repo, &["add", "."]);
    git(&repo, &["-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "-c", "core.hooksPath=/dev/null", "commit", "-qm", "sparse fixture"]);
    source::capture(&SourceCaptureRequest {repository_id:"sparse".into(),source_root:repo.clone(),source_commit:git(&repo,&["rev-parse","HEAD"]),expected_tree:git(&repo,&["rev-parse","HEAD^{tree}"]),output_path:work.join("archive"),policy:ScopePolicy::default()}).unwrap();
    let ctx = CallContext::restricted(TransportKind::Test,vec![work.clone(),repo],EffectPolicy::WorkspaceWrite).unwrap();
    let source_ref = artifact::reference(&ctx,&work,&work.join("archive").join(source::LEDGER_FILE)).unwrap();
    let reference = index::build(&ctx,&work,&source_ref,&[]).unwrap();
    let manifest = index::load_manifest(&ctx,&work,&reference).unwrap();
    let (posts, scanned) = index::load_postings_bounded(&ctx,&work,&manifest,term,16)
        .expect("an exact term must not spend its posting allowance on a different partition");
    assert_eq!(posts.len(),1);
    assert!(scanned<=16);
    let chunk = index::load_chunk(&ctx,&work,&manifest,&posts[0]).unwrap();
    assert_eq!(chunk.path,"target.md");
    assert!(chunk.text.contains("QK_SPARSE_TARGET"));
}
