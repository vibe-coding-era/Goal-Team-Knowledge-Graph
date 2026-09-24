//! Rev24 L02 security and portability contract for published I06 evidence.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use gtkg_core::file_model::sha256_file;
use serde_json::Value;

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root")
}

fn json(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

fn collect_files(root: &Path, relative: &Path, output: &mut BTreeSet<String>) {
    let directory = root.join(relative);
    for entry in fs::read_dir(&directory).unwrap() {
        let entry = entry.unwrap();
        let kind = entry.file_type().unwrap();
        assert!(
            !kind.is_symlink(),
            "evidence symlink: {}",
            entry.path().display()
        );
        let child = relative.join(entry.file_name());
        if kind.is_dir() {
            collect_files(root, &child, output);
        } else if kind.is_file() {
            output.insert(child.to_string_lossy().replace('\\', "/"));
        } else {
            panic!("non-regular evidence entry: {}", entry.path().display());
        }
    }
}

#[test]
fn evidence_checksum_is_an_exact_duplicate_free_symlink_free_set() {
    let evidence = root().join("deliverables/codex-wiki-reverse/evidence");
    let expected = BTreeSet::from([
        "diff/before-vs-codex-style.metrics.json".to_owned(),
        "diff/before-vs-codex-style.png".to_owned(),
        "diff/desktop-self-replay.metrics.json".to_owned(),
        "diff/desktop-self-replay.png".to_owned(),
        "e2e/browser-fixture-receipt.json".to_owned(),
        "e2e/codex-wiki-e2e.json".to_owned(),
        "generated/desktop-collapsed.png".to_owned(),
        "generated/desktop-initial-replay.png".to_owned(),
        "generated/desktop-initial.png".to_owned(),
        "generated/desktop-resized.png".to_owned(),
        "generated/desktop-search.png".to_owned(),
        "generated/desktop-selected.png".to_owned(),
        "generated/mobile-closed-focus.png".to_owned(),
        "generated/mobile-drawer-open.png".to_owned(),
        "generated/mobile-initial.png".to_owned(),
        "source/wiki-before-desktop.png".to_owned(),
        "source/wiki-before-mobile.png".to_owned(),
    ]);
    let mut actual = BTreeSet::new();
    for directory in ["diff", "e2e", "generated", "source"] {
        collect_files(&evidence, Path::new(directory), &mut actual);
    }
    assert_eq!(actual, expected, "published evidence exact-set drift");

    let sums = fs::read_to_string(evidence.join("SHA256SUMS.txt")).unwrap();
    let mut pinned = BTreeSet::new();
    for line in sums.lines() {
        let (digest, relative) = line.split_once("  ").expect("canonical checksum line");
        assert!(
            pinned.insert(relative.to_owned()),
            "duplicate checksum path: {relative}"
        );
        assert_eq!(
            sha256_file(&evidence.join(relative)).unwrap(),
            format!("sha256:{digest}")
        );
    }
    assert_eq!(pinned, expected, "SHA256SUMS exact-set drift");
}

#[test]
fn receipt_uses_portable_paths_and_binds_runtime_and_observed_security() {
    let workspace = root();
    let evidence = workspace.join("deliverables/codex-wiki-reverse/evidence");
    let receipt = json(&evidence.join("e2e/codex-wiki-e2e.json"));
    for key in ["fixture_receipt", "source", "harness", "pixel_diff"] {
        let path = if key == "fixture_receipt" {
            receipt[key].as_str().unwrap()
        } else {
            receipt[key]["path"].as_str().unwrap()
        };
        assert!(
            !Path::new(path).is_absolute(),
            "non-portable receipt path: {path}"
        );
        assert!(!path.split('/').any(|part| part == ".."));
    }
    assert_eq!(
        receipt["fixture_receipt"],
        "e2e/browser-fixture-receipt.json"
    );
    assert_eq!(
        receipt["fixture_receipt_sha256"],
        sha256_file(&evidence.join("e2e/browser-fixture-receipt.json")).unwrap()
    );

    for (key, relative) in [
        ("source", "crates/gtkg-core/src/a2ui.rs"),
        (
            "harness",
            "crates/gtkg-testkit/browser/i06_codex_wiki_e2e_contract.sh",
        ),
        (
            "pixel_diff",
            "crates/gtkg-testkit/browser/support/pixel_diff.py",
        ),
    ] {
        assert_eq!(receipt[key]["path"], relative);
        assert_eq!(
            receipt[key]["sha256"],
            sha256_file(&workspace.join(relative)).unwrap()
        );
    }

    assert_eq!(receipt["playwright"]["offline"], true);
    for (key, relative) in [
        (
            "wrapper",
            "crates/gtkg-testkit/browser/playwright_cli_locked.sh",
        ),
        (
            "lock",
            "crates/gtkg-testkit/browser/playwright_cli.lock.json",
        ),
        (
            "config",
            "crates/gtkg-testkit/browser/d05_playwright_cli.config.json",
        ),
    ] {
        assert_eq!(receipt["playwright"][key]["path"], relative);
        assert_eq!(
            receipt["playwright"][key]["sha256"],
            sha256_file(&workspace.join(relative)).unwrap()
        );
    }

    assert_eq!(
        receipt["self_replay_metrics"]["path"],
        "diff/desktop-self-replay.metrics.json"
    );
    assert_eq!(
        receipt["self_replay_metrics"]["sha256"],
        sha256_file(&evidence.join("diff/desktop-self-replay.metrics.json")).unwrap()
    );
    assert_eq!(receipt["self_replay_metrics"]["passed"], true);

    let sessions = receipt["security_observations"].as_array().unwrap();
    assert_eq!(sessions.len(), 2);
    assert_eq!(sessions[0]["session"], "A");
    assert_eq!(sessions[1]["session"], "B");
    for session in sessions {
        assert_eq!(session["offline"], true);
        assert_eq!(session["remote_requests"].as_array().unwrap().len(), 0);
        assert_eq!(session["console_errors"].as_array().unwrap().len(), 0);
        assert_eq!(session["csp_violations"].as_array().unwrap().len(), 0);
        assert_eq!(session["target_execution_count"], 0);
        assert_eq!(session["xss_sentinel"], false);
    }
    assert_eq!(receipt["security"]["observed_sessions"], 2);
    assert_eq!(receipt["security"]["remote_requests"], 0);
    assert_eq!(receipt["security"]["console_errors"], 0);
    assert_eq!(receipt["security"]["csp_violations"], 0);
    assert_eq!(receipt["security"]["target_execution_count"], 0);
    assert_eq!(receipt["security"]["xss_sentinel"], false);
}

#[test]
fn harness_has_no_external_skill_path_and_derives_security_from_both_sessions() {
    let harness = fs::read_to_string(
        root().join("crates/gtkg-testkit/browser/i06_codex_wiki_e2e_contract.sh"),
    )
    .unwrap();
    for forbidden in [
        "/Users/Rou/.codex/skills/",
        "/Users/Rou/.agents/skills/",
        "~/.codex/skills/",
        "$HOME/.codex/skills/",
        "a2ui-reverse-engineer/scripts/pixel_diff.py",
    ] {
        assert!(
            !harness.contains(forbidden),
            "external Skill path remains: {forbidden}"
        );
    }
    assert!(harness.contains("SECURITY_A="));
    assert!(harness.contains("SECURITY_B="));
    assert!(harness.contains("security_observations"));
    assert!(!harness.contains("security: {remote_requests: 0"));
}
