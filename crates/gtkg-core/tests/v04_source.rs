#![allow(clippy::unwrap_used)]
use gtkg_core::v04::source::*;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs,
    io::Write,
    path::Path,
    process::{Command, Stdio},
};
use tempfile::TempDir;

fn git(root: &Path, args: &[&str]) -> String {
    let o = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    String::from_utf8(o.stdout).unwrap().trim().to_owned()
}
fn fixture(files: &[(&str, &[u8])]) -> (TempDir, SourceCaptureRequest) {
    let t = TempDir::new().unwrap();
    let root = t.path().join("repo");
    fs::create_dir(&root).unwrap();
    git(&root, &["init", "-q"]);
    // Fast-import creates exact test objects without executing target files or hooks.
    let mut input = Vec::new();
    for (i, (_, bytes)) in files.iter().enumerate() {
        write!(input, "blob\nmark :{}\ndata {}\n", i + 1, bytes.len()).unwrap();
        input.extend_from_slice(bytes);
        input.push(b'\n');
    }
    write!(input,"commit refs/heads/main\ncommitter QK Fixture <qk@example.invalid> 0 +0000\ndata 7\nfixture\n").unwrap();
    for (i, (path, _)) in files.iter().enumerate() {
        writeln!(input, "M 100644 :{} {}", i + 1, path).unwrap();
    }
    input.push(b'\n');
    let mut child = Command::new("git")
        .arg("-C")
        .arg(&root)
        .args(["fast-import", "--quiet"])
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(&input).unwrap();
    assert!(child.wait_with_output().unwrap().status.success());
    let commit = git(&root, &["rev-parse", "main"]);
    let tree = git(&root, &["rev-parse", "main^{tree}"]);
    let req = SourceCaptureRequest {
        repository_id: "fixture".into(),
        source_root: root,
        source_commit: commit,
        expected_tree: tree,
        output_path: t.path().join("archive"),
        policy: ScopePolicy::default(),
    };
    (t, req)
}
fn independent_paths(req: &SourceCaptureRequest) -> BTreeSet<String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(&req.source_root)
        .args(["ls-tree", "-r", "-z", "--name-only", &req.source_commit])
        .output()
        .unwrap();
    assert!(out.status.success());
    out.stdout
        .split(|b| *b == 0)
        .filter(|x| !x.is_empty())
        .map(|x| String::from_utf8(x.to_vec()).unwrap())
        .collect()
}
fn json(root: &Path, name: &str) -> Value {
    serde_json::from_slice(&fs::read(root.join(name)).unwrap()).unwrap()
}
fn save_json(root: &Path, name: &str, value: &Value) {
    fs::write(root.join(name), serde_json::to_vec(value).unwrap()).unwrap();
}
fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[test]
fn exact_set_boundaries_and_pages_preserve_every_leaf() {
    for count in [0, 1, 255, 256, 257, 5104, 10001] {
        let owned: Vec<String> = (0..count).map(|i| format!("src/f{i:05}.go")).collect();
        let files: Vec<(&str, &[u8])> = owned
            .iter()
            .map(|s| (s.as_str(), b"package p\nfunc F() {}\n".as_slice()))
            .collect();
        let (_t, req) = fixture(&files);
        let ledger =
            capture(&req).expect("exact Git capture must support the frozen cardinality boundary");
        let expected = independent_paths(&req);
        assert_eq!(
            ledger
                .leaves
                .iter()
                .map(|r| r.path.clone())
                .collect::<BTreeSet<_>>(),
            expected
        );
        assert_eq!(ledger.leaves.len(), count);
        let selection: AnalysisSelectionManifest = serde_json::from_slice(
            &fs::read(req.output_path.join(&ledger.selection_manifest.path)).unwrap(),
        )
        .unwrap();
        let mut selected = Vec::new();
        for (index, r) in selection.pages.iter().enumerate() {
            let page: SelectionPage =
                serde_json::from_slice(&fs::read(req.output_path.join(&r.path)).unwrap()).unwrap();
            assert_eq!(page.page_index, index);
            assert_eq!(page.total_pages, selection.pages.len());
            assert_eq!(page.total_files, count);
            assert!(page.paths.len() <= 128);
            assert!(page.source_bytes <= PAGE_BYTES || page.oversized_streamed);
            selected.extend(page.paths);
        }
        assert_eq!(selected.len(), count);
        assert_eq!(selected.into_iter().collect::<BTreeSet<_>>(), expected);
        assert_eq!(load_archive(&req.output_path).unwrap(), ledger);
        assert_eq!(capture(&req).unwrap(), ledger);
    }
}
#[test]
fn exact_commit_beats_dirty_worktree_and_archive_survives_source_move() {
    let (_t, req) = fixture(&[
        ("main.go", b"package main\n// frozen\n"),
        ("README.md", b"# Frozen\n"),
    ]);
    fs::write(
        req.source_root.join("main.go"),
        b"malicious dirty replacement",
    )
    .unwrap();
    let ledger = capture(&req).unwrap();
    let leaf = ledger.leaves.iter().find(|l| l.path == "main.go").unwrap();
    assert_eq!(leaf.text, TextStatus::Extracted);
    assert_eq!(leaf.semantic, SemanticStatus::NotRequested);
    fs::rename(
        &req.source_root,
        req.source_root.with_file_name("repo-moved"),
    )
    .unwrap();
    assert_eq!(
        read_object(&req.output_path, leaf.object_sha256.as_ref().unwrap()).unwrap(),
        b"package main\n// frozen\n"
    );
    assert_eq!(load_archive(&req.output_path).unwrap(), ledger);
}
#[test]
fn mixed_routes_scope_components_and_stage_axes_are_explicit() {
    let (_t, mut req) = fixture(&[
        ("foo/skip.go", b"package foo"),
        ("foobar/keep.go", b"package foobar"),
        ("README.md", b"# text"),
        ("settings.json", b"{}"),
        ("dev", b"#!/bin/sh\necho hello"),
        ("image.png", b"\x89PNG\0\xff"),
        ("manual.pdf", b"%PDF-1.7\0"),
    ]);
    req.policy.rules.push(ScopeRule {
        path_prefix: "foo".into(),
        included: false,
        rule_id: "exclude-foo".into(),
        origin: "user-policy".into(),
        reason: "explicit fixture exclusion".into(),
    });
    let l = capture(&req).unwrap();
    assert_eq!(l.leaves.len(), 7);
    let find = |p: &str| l.leaves.iter().find(|x| x.path == p).unwrap();
    assert_eq!(find("foo/skip.go").scope, Scope::Excluded);
    assert_eq!(find("foo/skip.go").capture, CaptureStatus::NotRequested);
    assert_eq!(find("foobar/keep.go").scope, Scope::Included);
    assert_eq!(find("foobar/keep.go").main_route, MainRoute::Code);
    for p in ["README.md", "settings.json", "dev"] {
        assert_eq!(find(p).main_route, MainRoute::Text);
        assert_eq!(find(p).text, TextStatus::Extracted);
        assert!(find(p).object_sha256.is_some());
    }
    assert_eq!(find("image.png").text, TextStatus::NotApplicable);
    assert!(find("image.png").object_sha256.is_none());
    assert_eq!(find("manual.pdf").text, TextStatus::Unsupported);
    for leaf in &l.leaves {
        assert!(!leaf.matched_rule.is_empty());
        assert!(!leaf.rule_origin.is_empty());
        assert!(!leaf.semantic_reason.is_empty());
    }
}
#[cfg(unix)]
#[test]
fn symlink_gitlink_classification_never_follows_target() {
    let (_t, mut req) = fixture(&[("normal.go", b"package normal")]);
    git(&req.source_root, &["read-tree", &req.source_commit]);
    let mut p = Command::new("git")
        .arg("-C")
        .arg(&req.source_root)
        .args(["hash-object", "-w", "--stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    p.stdin
        .take()
        .unwrap()
        .write_all(b"../../outside-secret")
        .unwrap();
    let oid = String::from_utf8(p.wait_with_output().unwrap().stdout)
        .unwrap()
        .trim()
        .to_owned();
    git(
        &req.source_root,
        &[
            "update-index",
            "--add",
            "--cacheinfo",
            &format!("120000,{oid},link"),
        ],
    );
    git(
        &req.source_root,
        &[
            "update-index",
            "--add",
            "--cacheinfo",
            &format!("160000,{},submodule", req.source_commit),
        ],
    );
    let tree = git(&req.source_root, &["write-tree"]);
    let out = Command::new("git")
        .arg("-C")
        .arg(&req.source_root)
        .args([
            "-c",
            "user.name=QK",
            "-c",
            "user.email=qk@example.invalid",
            "commit-tree",
            &tree,
            "-m",
            "modes",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    req.source_commit = String::from_utf8(out.stdout).unwrap().trim().into();
    req.expected_tree = tree;
    let ledger = capture(&req).unwrap();
    assert_eq!(ledger.leaves.len(), 3);
    for (p, route) in [
        ("link", MainRoute::Symlink),
        ("submodule", MainRoute::Gitlink),
    ] {
        let l = ledger.leaves.iter().find(|x| x.path == p).unwrap();
        assert_eq!(l.main_route, route);
        assert_eq!(l.capture, CaptureStatus::Unsupported);
        assert!(l.object_sha256.is_none());
    }
}
#[test]
fn missing_duplicate_cross_snapshot_and_tampered_pages_fail_closed() {
    for attack in ["missing", "duplicate", "cross-snapshot", "object", "ledger"] {
        let names: Vec<String> = (0..257).map(|i| format!("f{i}.md")).collect();
        let files: Vec<_> = names
            .iter()
            .map(|n| (n.as_str(), b"source".as_slice()))
            .collect();
        let (_t, req) = fixture(&files);
        let l = capture(&req).unwrap();
        let mut manifest = json(&req.output_path, &l.selection_manifest.path);
        let page_path = manifest["pages"][0]["path"].as_str().unwrap().to_owned();
        match attack {
            "missing" => fs::remove_file(req.output_path.join(page_path)).unwrap(),
            "duplicate" => {
                let duplicate = manifest["pages"][0].clone();
                manifest["pages"].as_array_mut().unwrap().push(duplicate);
                save_json(&req.output_path, &l.selection_manifest.path, &manifest);
            }
            "cross-snapshot" => {
                let mut page = json(&req.output_path, &page_path);
                page["snapshot_id"] = Value::String("f".repeat(64));
                save_json(&req.output_path, &page_path, &page);
            }
            "object" => {
                let digest = l.leaves[0].object_sha256.as_ref().unwrap();
                fs::write(req.output_path.join("objects").join(digest), b"tampered").unwrap();
                assert!(read_object(&req.output_path, digest).is_err());
            }
            _ => {
                let mut root = json(&req.output_path, LEDGER_FILE);
                root["leaves"].as_array_mut().unwrap().pop();
                save_json(&req.output_path, LEDGER_FILE, &root);
            }
        }
        assert!(load_archive(&req.output_path).is_err(), "accepted {attack}");
    }
}
#[test]
fn resume_identity_mismatch_and_path_escape_are_rejected() {
    let (_t, mut req) = fixture(&[("README.md", b"source")]);
    let l = capture(&req).unwrap();
    let before = fs::read(req.output_path.join(LEDGER_FILE)).unwrap();
    // A completed archive is idempotent; a partial archive with matching checkpoint can finish.
    fs::remove_file(req.output_path.join(LEDGER_FILE)).unwrap();
    assert_eq!(capture(&req).unwrap(), l);
    assert_eq!(fs::read(req.output_path.join(LEDGER_FILE)).unwrap(), before);
    req.policy.revision = "new-policy".into();
    assert!(capture(&req).is_err());
    req.policy = ScopePolicy::default();
    req.expected_tree = "0".repeat(40);
    assert!(capture(&req).is_err());
    assert!(read_object(&req.output_path, "../../outside").is_err());
    assert!(read_object(&req.output_path, &"g".repeat(64)).is_err());
    req.expected_tree = l.source_tree;
    req.output_path = req.source_root.join("archive");
    assert!(capture(&req).is_err());
}
#[test]
fn byte_budget_and_single_oversized_text_are_not_silently_skipped() {
    let a = vec![b'a'; 9 * 1024 * 1024];
    let b = vec![b'b'; 9 * 1024 * 1024];
    let big = vec![b'c'; 17 * 1024 * 1024 + 3];
    let (_t, req) = fixture(&[("a.txt", &a), ("b.txt", &b), ("c.txt", &big)]);
    let l = capture(&req).unwrap();
    let m: AnalysisSelectionManifest =
        serde_json::from_slice(&fs::read(req.output_path.join(l.selection_manifest.path)).unwrap())
            .unwrap();
    assert_eq!(m.pages.len(), 3);
    let leaf = l.leaves.iter().find(|x| x.path == "c.txt").unwrap();
    assert!(leaf.oversized_streamed);
    assert_eq!(leaf.text, TextStatus::Extracted);
    assert_eq!(leaf.content_sha256, Some(hash(&big)));
    assert_eq!(
        read_object(&req.output_path, leaf.object_sha256.as_ref().unwrap()).unwrap(),
        big
    );
}
#[cfg(unix)]
#[test]
fn output_object_symlink_and_untrusted_git_replace_are_rejected_or_ignored() {
    use std::os::unix::fs::symlink;
    let (t, req) = fixture(&[("README.md", b"source")]);
    let l = capture(&req).unwrap();
    let digest = l.leaves[0].object_sha256.as_ref().unwrap();
    let object = req.output_path.join("objects").join(digest);
    let outside = t.path().join("outside");
    fs::write(&outside, b"source").unwrap();
    fs::remove_file(&object).unwrap();
    symlink(&outside, &object).unwrap();
    assert!(read_object(&req.output_path, digest).is_err());
    assert!(load_archive(&req.output_path).is_err());
    assert!(capture(&req).is_err());
    assert_eq!(fs::read(&outside).unwrap(), b"source");
}
