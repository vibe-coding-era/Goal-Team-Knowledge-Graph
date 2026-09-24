#![allow(clippy::unwrap_used)]
use gtkg_core::v04::source::{ScopePolicy, SourceCaptureRequest, capture};
use std::{fs, path::Path, process::Command};
use tempfile::TempDir;
fn git(root: &Path, args: &[&str]) -> String {
    let o = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    String::from_utf8(o.stdout).unwrap().trim().into()
}
#[test]
#[ignore = "subprocess probe invoked with a private fixture only"]
fn capture_missing_object_child() {
    let path = std::env::var("QK_SOURCE_REQUEST").expect("private request file");
    let request: SourceCaptureRequest = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    assert!(
        capture(&request).is_err(),
        "missing object must be source unavailable"
    );
}
#[test]
fn capture_never_spawns_fetch_for_missing_promisor_blob_or_commit() {
    for missing in ["blob", "commit"] {
        let t = TempDir::new().unwrap();
        let repo = t.path().join("repo");
        fs::create_dir(&repo).unwrap();
        git(&repo, &["init", "-q"]);
        fs::write(repo.join("main.go"), b"package main\nfunc main() {}\n").unwrap();
        git(&repo, &["add", "main.go"]);
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
        let commit = git(&repo, &["rev-parse", "HEAD"]);
        let tree = git(&repo, &["rev-parse", "HEAD^{tree}"]);
        let blob = git(&repo, &["rev-parse", "HEAD:main.go"]);
        git(&repo, &["config", "extensions.partialclone", "origin"]);
        git(&repo, &["config", "remote.origin.promisor", "true"]);
        git(
            &repo,
            &["config", "remote.origin.partialclonefilter", "blob:none"],
        );
        git(
            &repo,
            &[
                "config",
                "remote.origin.url",
                t.path().join("absent-local-remote").to_str().unwrap(),
            ],
        );
        let removed = if missing == "blob" { &blob } else { &commit };
        fs::remove_file(
            repo.join(".git/objects")
                .join(&removed[..2])
                .join(&removed[2..]),
        )
        .unwrap();
        let request = SourceCaptureRequest {
            repository_id: "private-promisor-fixture".into(),
            source_root: repo,
            source_commit: commit,
            expected_tree: tree,
            output_path: t.path().join("archive"),
            policy: ScopePolicy::default(),
        };
        let file = t.path().join("request.json");
        fs::write(&file, serde_json::to_vec(&request).unwrap()).unwrap();
        let trace = t.path().join("git-trace.log");
        let out = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "capture_missing_object_child",
                "--ignored",
                "--nocapture",
            ])
            .env("QK_SOURCE_REQUEST", file)
            .env("GIT_TRACE", &trace)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let observed = fs::read_to_string(trace).unwrap();
        assert!(
            !observed.contains(" fetch ")
                && !observed.contains("git-upload-pack")
                && !observed.contains("upload-pack")
                && !observed.contains("remote-https"),
            "capture performed implicit target transport for missing {missing}:\n{observed}"
        );
    }
}
