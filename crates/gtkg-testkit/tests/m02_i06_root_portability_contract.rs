//! Rev25 M02 root preflight, portable JSON, and offline-probe contract.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root")
}

fn has_absolute_string(value: &Value) -> bool {
    match value {
        Value::String(text) => Path::new(text).is_absolute() || text.starts_with("file://"),
        Value::Array(items) => items.iter().any(has_absolute_string),
        Value::Object(fields) => fields.values().any(has_absolute_string),
        _ => false,
    }
}

#[test]
fn unsafe_overlap_and_symlink_roots_reject_before_cargo_or_browser() {
    let workspace = root();
    let helper = workspace.join("crates/gtkg-testkit/browser/support/pixel_diff.py");
    let temp = tempfile::tempdir().unwrap();
    let outside = temp.path().join("outside");
    fs::create_dir(&outside).unwrap();

    #[cfg(unix)]
    std::os::unix::fs::symlink(&outside, workspace.join("output/m02-symlink-root")).unwrap();

    for (name, output, publish) in [
        (
            "outside",
            outside.join("run"),
            workspace.join("deliverables/codex-wiki-reverse/evidence"),
        ),
        (
            "overlap",
            workspace.join("output/m02-overlap"),
            workspace.join("output/m02-overlap/publish"),
        ),
        (
            "symlink",
            workspace.join("output/m02-symlink-root/run"),
            workspace.join("deliverables/codex-wiki-reverse/evidence"),
        ),
    ] {
        let result = Command::new("python3")
            .args(["-B"])
            .arg(&helper)
            .arg("--prepare-roots")
            .arg("--repo-root")
            .arg(&workspace)
            .arg("--output-root")
            .arg(output)
            .arg("--publish-root")
            .arg(publish)
            .output()
            .unwrap();
        assert_eq!(result.status.code(), Some(2), "unsafe {name} root accepted");
    }

    #[cfg(unix)]
    fs::remove_file(workspace.join("output/m02-symlink-root")).unwrap();

    let harness = fs::read_to_string(
        workspace.join("crates/gtkg-testkit/browser/i06_codex_wiki_e2e_contract.sh"),
    )
    .unwrap();
    let preflight = harness.find("--prepare-roots").unwrap();
    assert!(preflight < harness.find("cargo test").unwrap());
    assert!(preflight < harness.find(" open about:blank").unwrap());
    assert!(!harness.contains("mkdir -p \"$OUT_ROOT"));
    assert!(!harness.contains("cp \"$OUT_ROOT"));
    assert!(harness.contains("--publish-evidence"));
}

#[test]
fn persisted_fixture_metrics_and_receipt_have_no_absolute_paths() {
    let evidence = root().join("deliverables/codex-wiki-reverse/evidence");
    for relative in [
        "e2e/browser-fixture-receipt.json",
        "e2e/codex-wiki-e2e.json",
        "diff/desktop-self-replay.metrics.json",
        "diff/before-vs-codex-style.metrics.json",
    ] {
        let value: Value =
            serde_json::from_slice(&fs::read(evidence.join(relative)).unwrap()).unwrap();
        assert!(
            !has_absolute_string(&value),
            "non-portable JSON: {relative}"
        );
    }
    let receipt: Value =
        serde_json::from_slice(&fs::read(evidence.join("e2e/codex-wiki-e2e.json")).unwrap())
            .unwrap();
    for key in ["fixture_receipt", "source", "harness", "pixel_diff"] {
        let path = if key == "fixture_receipt" {
            receipt[key].as_str().unwrap()
        } else {
            receipt[key]["path"].as_str().unwrap()
        };
        assert!(
            evidence.join(path).starts_with(&evidence) || root().join(path).starts_with(root())
        );
    }
}

#[test]
fn both_sessions_observe_exact_offline_probe_and_zero_unexpected_remote() {
    let receipt: Value = serde_json::from_slice(
        &fs::read(root().join("deliverables/codex-wiki-reverse/evidence/e2e/codex-wiki-e2e.json"))
            .unwrap(),
    )
    .unwrap();
    let observations = receipt["security_observations"].as_array().unwrap();
    assert_eq!(observations.len(), 2);
    for (index, expected_session) in ["A", "B"].iter().enumerate() {
        let observed = &observations[index];
        assert_eq!(observed["session"], *expected_session);
        assert_eq!(
            observed["remote_probe"]["url"],
            "https://gtkg.invalid/__offline_probe__"
        );
        assert_eq!(observed["remote_probe"]["failed"], true);
        assert!(observed["remote_probe"]["error"].as_str().unwrap().len() > 0);
        assert_eq!(
            observed["expected_remote_requests"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            observed["unexpected_remote_requests"]
                .as_array()
                .unwrap()
                .len(),
            0
        );
    }
    assert_eq!(receipt["security"]["observed_sessions"], 2);
    assert_eq!(receipt["security"]["offline_probe_failures"], 2);
    assert_eq!(receipt["security"]["unexpected_remote_requests"], 0);
}
