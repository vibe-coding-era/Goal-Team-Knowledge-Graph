//! I06 contracts for the Codex-inspired static Wiki renderer and its A2UI
//! reverse-engineering artifact set.

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
    serde_json::from_slice(&fs::read(path).unwrap_or_else(|error| {
        panic!("read {}: {error}", path.display());
    }))
    .unwrap_or_else(|error| panic!("parse {}: {error}", path.display()))
}

#[test]
fn pixel_diff_and_published_evidence_are_repo_local_and_digest_current() {
    let workspace = root();
    let harness_path = workspace.join("crates/gtkg-testkit/browser/i06_codex_wiki_e2e_contract.sh");
    let runner_path = workspace.join("crates/gtkg-testkit/browser/support/pixel_diff.py");
    let harness = fs::read_to_string(&harness_path).expect("I06 browser harness");

    assert!(
        runner_path.is_file(),
        "repo-local pixel diff runner is missing"
    );
    assert!(
        harness.contains("$REPO_ROOT/crates/gtkg-testkit/browser/support/pixel_diff.py"),
        "I06 must invoke the repo-local pixel diff runner"
    );
    assert_eq!(
        harness.matches("/Users/Rou/.codex/skills/").count(),
        0,
        "I06 must not depend on a user-local Skill checkout"
    );

    let runner = fs::read_to_string(&runner_path).expect("pixel diff runner source");
    for forbidden in ["PIL", "numpy", "cv2", "imageio", "matplotlib"] {
        assert!(
            !runner.contains(forbidden),
            "pixel diff runner must remain Python-stdlib-only: {forbidden}"
        );
    }

    let evidence = workspace.join("deliverables/codex-wiki-reverse/evidence");
    let sums = fs::read_to_string(evidence.join("SHA256SUMS.txt"))
        .expect("published evidence SHA256SUMS.txt");
    let mut pinned = 0usize;
    for (line_number, line) in sums.lines().enumerate() {
        let (expected, relative) = line
            .split_once("  ")
            .unwrap_or_else(|| panic!("invalid SHA256SUMS line {}", line_number + 1));
        assert_eq!(
            expected.len(),
            64,
            "invalid digest width at line {}",
            line_number + 1
        );
        assert!(
            !relative.starts_with('/') && !relative.split('/').any(|part| part == ".."),
            "unsafe evidence path at line {}",
            line_number + 1
        );
        assert_eq!(
            sha256_file(&evidence.join(relative)).expect("evidence digest"),
            format!("sha256:{expected}"),
            "published evidence drift: {relative}"
        );
        pinned += 1;
    }
    assert!(pinned > 0, "SHA256SUMS.txt pins no evidence files");

    let receipt = json(&evidence.join("e2e/codex-wiki-e2e.json"));
    assert_eq!(
        receipt["source"]["sha256"],
        sha256_file(&workspace.join("crates/gtkg-core/src/a2ui.rs")).expect("A2UI source digest")
    );
    assert_eq!(
        receipt["harness"]["sha256"],
        sha256_file(&harness_path).expect("I06 harness digest")
    );
}

#[test]
fn wiki_shell_carries_codex_workspace_responsive_and_accessible_contracts() {
    let source = fs::read_to_string(root().join("crates/gtkg-core/src/a2ui.rs")).unwrap();
    for required in [
        "class=\"app-frame\"",
        "data-region=\"titlebar\"",
        "data-region=\"left-index\"",
        "data-region=\"right-content\"",
        "data-region=\"context-panel\"",
        "id=\"knowledge-search\"",
        "role=\"separator\"",
        "aria-valuemin=\"220\"",
        "@media (max-width:720px)",
        "requestAnimationFrame",
        "pointerdown",
        "panel.inert = collapsed",
        "isolateBackground",
        "focus-visible",
        "decodeTextHex",
        "decodeJsonHex",
        "layout: 'codex_workspace'",
    ] {
        assert!(
            source.contains(required),
            "missing Wiki contract: {required}"
        );
    }
    assert!(
        !source[source.find("const WIKI_JS").unwrap()..].contains("innerHTML"),
        "untrusted Wiki content must never use innerHTML"
    );
    assert!(source.contains("connect-src 'none'"));
    assert!(source.contains("document.querySelector('#selected-content').textContent"));
}

#[test]
fn reverse_engineering_artifacts_are_complete_and_a2ui_stays_three_messages() {
    let output = root().join("deliverables/codex-wiki-reverse");
    let expected = BTreeSet::from([
        "a2ui/a2ui.config.json",
        "a2ui/action-contract.json",
        "a2ui/catalog-map.json",
        "a2ui/data-fixtures.json",
        "a2ui/messages.json",
        "a2ui/routes.json",
        "a2ui/theme-tokens.json",
        "analysis/api-map.json",
        "analysis/component-map.json",
        "analysis/frontend-architecture.json",
        "analysis/generation-report.json",
        "analysis/interaction-map.json",
        "analysis/route-map.json",
        "analysis/semantic-ir.json",
        "analysis/visual-ir.json",
        "docs/frontend-architecture.md",
        "docs/reverse-engineering-report.md",
    ]);
    for relative in &expected {
        assert!(
            output.join(relative).is_file(),
            "missing artifact: {relative}"
        );
    }
    let messages = json(&output.join("a2ui/messages.json"));
    let messages = messages.as_array().expect("messages array");
    assert_eq!(messages.len(), 3);
    assert!(messages[0].get("createSurface").is_some());
    assert!(messages[1].get("updateComponents").is_some());
    assert!(messages[2].get("updateDataModel").is_some());
    assert_eq!(messages[0]["version"], "v0.9");
    assert_eq!(
        messages[0]["createSurface"]["catalogId"],
        "https://a2ui.org/specification/v0_9/catalogs/basic/catalog.json"
    );
    let components = messages[1]["updateComponents"]["components"]
        .as_array()
        .unwrap();
    assert_eq!(components.len(), 10);
    assert_eq!(
        messages[2]["updateDataModel"]["value"]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["document".to_owned(), "index".to_owned()])
    );
}

#[test]
fn reports_disclose_reference_and_pixel_boundaries() {
    let output = root().join("deliverables/codex-wiki-reverse");
    let config = json(&output.join("a2ui/a2ui.config.json"));
    let generation = json(&output.join("analysis/generation-report.json"));
    assert_eq!(
        config["pixel_acceptance"]["codex_reference_comparison"],
        "not_applicable_reference_blocked"
    );
    assert_eq!(
        config["pixel_acceptance"]["full_pixel_equivalence"],
        "not_claimed"
    );
    assert_eq!(
        generation["reference_capture"],
        "blocked_by_computer_use_policy"
    );
    assert_eq!(generation["full_pixel_equivalence"], "not_claimed");
    let report = fs::read_to_string(output.join("docs/reverse-engineering-report.md")).unwrap();
    assert!(report.contains("not_applicable_reference_blocked"));
    assert!(report.contains("不使用“官方 token”或“100% 像素复刻”表述"));
}
