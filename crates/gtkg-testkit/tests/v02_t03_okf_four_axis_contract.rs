//! V0.2 T03 contract: an OKF pin is an identity input, while the four
//! conformance axes are independent, fail-closed verdicts.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use gtkg_core::okf::parse_okf;
use gtkg_core::okf_v2::{
    validate_current_normative_corpus, validate_current_okf_raw_asset,
    validate_current_okf_raw_asset_manifest, validate_reference_runner,
    validate_reference_runner_manifest,
};
use gtkg_protocol::v2::{
    OkfAxisStatusV2, OkfFourAxisVerdictV2, OkfInternalVerdictV2, OkfSpecPinV2,
};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

const CURRENT_PIN_SHA256: &str =
    "sha256:26aa5da029278939f914e578107242d9607d4f2dc5fe153272b82f9ed1030101";

fn current_pin() -> OkfSpecPinV2 {
    OkfSpecPinV2::new(
        "0.2",
        "62432a095456147ee71e70ac6e4dc0d2dea3ac30",
        CURRENT_PIN_SHA256,
    )
    .expect("current PRD observation is a syntactically valid pin")
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

fn copied_reference_runner_workspace() -> (TempDir, PathBuf) {
    let temporary = tempfile::tempdir().expect("temporary reference-runner workspace");
    let checkout = temporary
        .path()
        .join("docs/reference/okf-v0.2-reference-W4G1");
    fs::create_dir_all(checkout.parent().expect("checkout parent"))
        .expect("create copied checkout parent");
    let source = workspace_root().join("docs/reference/okf-v0.2-reference-W4G1");
    let output = Command::new("git")
        .args(["clone", "--no-hardlinks", "--quiet"])
        .arg(source)
        .arg(&checkout)
        .output()
        .expect("clone pinned reference runner");
    assert!(
        output.status.success(),
        "cannot clone pinned reference runner: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    fs::copy(
        workspace_root().join("docs/reference/okf-v0.2-reference-W4G1/MANIFEST.json"),
        checkout.join("MANIFEST.json"),
    )
    .expect("copy GTKG runner manifest");
    fs::create_dir_all(
        temporary
            .path()
            .join("crates/gtkg-testkit/fixtures/h01_okf/bundle"),
    )
    .expect("create historical smoke boundary directory");
    (temporary, checkout)
}

#[test]
fn internal_consumer_and_producer_are_subverdicts_that_cannot_compensate() {
    let internal = OkfInternalVerdictV2::new(OkfAxisStatusV2::Passed, OkfAxisStatusV2::Failed);
    assert_eq!(internal.consumer, OkfAxisStatusV2::Passed);
    assert_eq!(internal.producer, OkfAxisStatusV2::Failed);
    assert_eq!(internal.status(), OkfAxisStatusV2::Failed);

    let verdict = OkfFourAxisVerdictV2::new(
        current_pin(),
        internal,
        OkfAxisStatusV2::Passed,
        OkfAxisStatusV2::Passed,
        OkfAxisStatusV2::Passed,
    );
    assert!(!verdict.all_axes_passed());
    assert_eq!(verdict.blocking_axis_ids(), vec!["internal"]);
}

#[test]
fn absent_current_raw_asset_is_cannot_confirm_not_current_conformance() {
    let result = validate_current_okf_raw_asset(&current_pin(), None);
    assert_eq!(result.status, OkfAxisStatusV2::CannotConfirm);
    assert_eq!(result.code, "E_V2_OKF_CURRENT_RAW_ASSET_MISSING");
    assert!(result.detail.contains("not current OKF conformance"));
}

#[test]
fn frozen_h01_asset_cannot_be_promoted_to_the_current_prd_pin() {
    let result = validate_current_okf_raw_asset(
        &current_pin(),
        Some(&workspace_root().join("docs/external-specs/okf-SPEC-v0.2.md")),
    );
    assert_eq!(result.status, OkfAxisStatusV2::CannotConfirm);
    assert_eq!(result.code, "E_V2_OKF_CURRENT_RAW_ASSET_DIGEST_MISMATCH");
    assert!(result.detail.contains("not current OKF conformance"));
}

#[test]
fn controlled_current_raw_asset_manifest_binds_the_exact_current_pin() {
    let asset_directory = workspace_root().join("docs/external-specs/okf-v0.2-62432a");
    let result = validate_current_okf_raw_asset_manifest(
        &current_pin(),
        &asset_directory.join("SPEC.md"),
        &asset_directory.join("MANIFEST.json"),
    );

    assert_eq!(result.status, OkfAxisStatusV2::NotRun);
    assert_eq!(result.code, "E_V2_OKF_CURRENT_NORMATIVE_CORPUS_NOT_RUN");
    assert!(result.detail.contains("exact pinned raw asset"));
}

#[test]
fn absent_reference_runner_is_blocked_and_cannot_be_offset_by_other_axes() {
    let result = validate_reference_runner(None);
    assert_eq!(result.status, OkfAxisStatusV2::Blocked);
    assert_eq!(result.code, "E_V2_OKF_REFERENCE_RUNNER_MISSING");

    let verdict = OkfFourAxisVerdictV2::new(
        current_pin(),
        OkfInternalVerdictV2::new(OkfAxisStatusV2::Passed, OkfAxisStatusV2::Passed),
        OkfAxisStatusV2::Passed,
        result.status,
        OkfAxisStatusV2::Passed,
    );
    assert!(!verdict.all_axes_passed());
    assert_eq!(verdict.blocking_axis_ids(), vec!["reference_compatibility"]);
}

#[test]
fn pinned_runner_availability_is_not_current_corpus_reference_compatibility() {
    let workspace = workspace_root();
    let result = validate_reference_runner_manifest(
        &workspace,
        &workspace.join("docs/reference/okf-v0.2-reference-W4G1/MANIFEST.json"),
    );

    assert!(result.runner_available);
    assert_eq!(result.availability.status, OkfAxisStatusV2::Passed);
    assert_eq!(
        result.availability.code,
        "I_V2_OKF_REFERENCE_RUNNER_AVAILABLE"
    );
    assert_eq!(
        result.current_corpus_reference_compatibility.status,
        OkfAxisStatusV2::NotRun
    );
    assert_eq!(
        result.current_corpus_reference_compatibility.code,
        "E_V2_OKF_CURRENT_CORPUS_REFERENCE_COMPATIBILITY_NOT_RUN"
    );

    let verdict = OkfFourAxisVerdictV2::new(
        current_pin(),
        OkfInternalVerdictV2::new(OkfAxisStatusV2::Passed, OkfAxisStatusV2::Passed),
        OkfAxisStatusV2::NotRun,
        result.current_corpus_reference_compatibility.status,
        OkfAxisStatusV2::Passed,
    );
    assert!(!verdict.all_axes_passed());
    assert_eq!(
        verdict.blocking_axis_ids(),
        vec!["current_official_format", "reference_compatibility"]
    );
}

#[test]
fn runner_manifest_rejects_a_clean_checkout_at_a_different_head() {
    let (temporary, checkout) = copied_reference_runner_workspace();
    let manifest = checkout.join("MANIFEST.json");
    let output = Command::new("git")
        .arg("-C")
        .arg(&checkout)
        .args(["checkout", "--detach", "--quiet", "HEAD~1"])
        .output()
        .expect("checkout copied runner at a non-manifest head");
    assert!(
        output.status.success(),
        "cannot checkout copied runner at a non-manifest head: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let result = validate_reference_runner_manifest(temporary.path(), &manifest);
    assert!(!result.runner_available);
    assert_eq!(result.availability.status, OkfAxisStatusV2::Invalid);
    assert_eq!(
        result.availability.code,
        "E_V2_OKF_REFERENCE_RUNNER_COMMIT_MISMATCH"
    );
    assert_eq!(
        result.current_corpus_reference_compatibility.status,
        OkfAxisStatusV2::Blocked
    );
}

#[test]
fn runner_manifest_rejects_a_different_command_without_executing_it() {
    let workspace = workspace_root();
    let source = workspace.join("docs/reference/okf-v0.2-reference-W4G1/MANIFEST.json");
    let temporary = tempfile::tempdir().expect("temporary manifest directory");
    let copied = temporary.path().join("MANIFEST.json");
    let content = fs::read_to_string(source).expect("reference-runner manifest");
    fs::write(
        &copied,
        content.replace(
            "cargo run --locked -q -p okf --no-default-features --features validator -- validate <bundle> --json",
            "arbitrary command must never execute",
        ),
    )
    .expect("write malformed command manifest");

    let result = validate_reference_runner_manifest(&workspace, &copied);
    assert!(!result.runner_available);
    assert_eq!(result.availability.status, OkfAxisStatusV2::Invalid);
    assert_eq!(
        result.availability.code,
        "E_V2_OKF_REFERENCE_RUNNER_MANIFEST_MISMATCH"
    );
    assert_eq!(
        result.current_corpus_reference_compatibility.status,
        OkfAxisStatusV2::Blocked
    );
}

#[test]
fn runner_manifest_rejects_tracked_worktree_tamper_after_a_clean_green_check() {
    let (temporary, checkout) = copied_reference_runner_workspace();
    let manifest = checkout.join("MANIFEST.json");
    let green = validate_reference_runner_manifest(temporary.path(), &manifest);
    assert!(green.runner_available);

    let readme = checkout.join("README.md");
    let mut content = fs::read_to_string(&readme).expect("runner readme");
    content.push_str("\nT03 tamper fixture\n");
    fs::write(&readme, content).expect("tamper copied worktree");

    let red = validate_reference_runner_manifest(temporary.path(), &manifest);
    assert!(!red.runner_available);
    assert_eq!(red.availability.status, OkfAxisStatusV2::Invalid);
    assert_eq!(
        red.availability.code,
        "E_V2_OKF_REFERENCE_RUNNER_WORKTREE_DIRTY"
    );
}

#[test]
fn runner_manifest_rejects_staged_index_tamper() {
    let (temporary, checkout) = copied_reference_runner_workspace();
    let manifest = checkout.join("MANIFEST.json");
    fs::write(checkout.join("README.md"), "T03 staged tamper\n").expect("tamper copied worktree");
    let output = Command::new("git")
        .arg("-C")
        .arg(&checkout)
        .args(["add", "README.md"])
        .output()
        .expect("stage copied tamper");
    assert!(
        output.status.success(),
        "cannot stage copied tamper: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let result = validate_reference_runner_manifest(temporary.path(), &manifest);
    assert!(!result.runner_available);
    assert_eq!(result.availability.status, OkfAxisStatusV2::Invalid);
    assert_eq!(
        result.availability.code,
        "E_V2_OKF_REFERENCE_RUNNER_INDEX_DIRTY"
    );
}

#[test]
fn runner_manifest_rejects_untracked_paths_outside_the_manifest_allowlist() {
    let (temporary, checkout) = copied_reference_runner_workspace();
    let manifest = checkout.join("MANIFEST.json");
    fs::write(
        checkout.join("unexpected-tamper.txt"),
        "T03 untracked tamper\n",
    )
    .expect("write unexpected untracked path");

    let result = validate_reference_runner_manifest(temporary.path(), &manifest);
    assert!(!result.runner_available);
    assert_eq!(result.availability.status, OkfAxisStatusV2::Invalid);
    assert_eq!(
        result.availability.code,
        "E_V2_OKF_REFERENCE_RUNNER_UNTRACKED_POLICY_VIOLATION"
    );
}

#[test]
fn v2_pin_rejects_non_sha256_and_current_pin_identity_is_exact() {
    let error = OkfSpecPinV2::new("0.2", "commit", "5a3311").expect_err("not a sha256 pin");
    assert_eq!(error.code(), "E_V2_OKF_PIN_INVALID");
    assert_ne!(
        current_pin().raw_sha256,
        "sha256:5a3311d270bebb16d558010e75064f5b75323f284992641732b1c8097511f948"
    );
}

#[test]
fn v1_frozen_fixture_bytes_and_consumer_parser_remain_unchanged_by_v2_validation() {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures/h01_okf/resource-forms/minimal-type-only.md");
    let bytes = fs::read(fixture).expect("frozen H01 fixture bytes");
    assert_eq!(
        format!("{:x}", Sha256::digest(&bytes)),
        "629a85e87ec6a09ec46df7d75b3b63a0e3641c610b00ee427b178bd87406ec69"
    );
    let source = String::from_utf8(bytes).expect("H01 fixture utf-8");
    let parsed = parse_okf(&source).expect("frozen v1 consumer parser behavior");
    assert_eq!(parsed.frontmatter.kind, "Reference");
    assert_eq!(parsed.body, "");
}

#[test]
fn current_normative_corpus_preserves_runner_warnings_as_advisories_without_hiding_them() {
    let workspace = workspace_root();
    let result = validate_current_normative_corpus(
        &workspace,
        &current_pin(),
        &workspace.join("deliverables/v02-t03/current-okf-normative-corpus.json"),
    );

    assert_eq!(result.official_format.status, OkfAxisStatusV2::Passed);
    assert_eq!(
        result.official_format.code,
        "I_V2_OKF_CURRENT_CORPUS_ADVISORIES_PRESENT"
    );
    assert_eq!(
        result.reference_compatibility.status,
        OkfAxisStatusV2::Passed
    );
    let receipt_path = result.receipt_path.expect("local execution receipt");
    let receipt: serde_json::Value =
        serde_json::from_slice(&fs::read(receipt_path).expect("read local current-corpus receipt"))
            .expect("receipt JSON");
    assert_eq!(receipt["status"], "passed");
    assert_eq!(receipt["case_count"], 13);
    assert_eq!(
        receipt["runner_warning_case_ids"].as_array().map(Vec::len),
        Some(10)
    );
    assert_eq!(
        receipt["runner_unexpected_error_case_ids"]
            .as_array()
            .map(Vec::len),
        Some(0)
    );
    let cases = receipt["cases"].as_array().expect("case receipts");
    for case_id in ["C01", "C13"] {
        let case = cases
            .iter()
            .find(|case| case["id"] == case_id)
            .expect("warning-only frozen case");
        assert!(case["runner_warning_count"].as_u64().unwrap_or_default() > 0);
        assert_eq!(case["runner_error_count"], 0);
        assert_eq!(case["runner_errors_match_expected_disposition"], true);
    }
    for case_id in ["C02", "C03", "C11"] {
        let case = cases
            .iter()
            .find(|case| case["id"] == case_id)
            .expect("frozen nonconformant runner case");
        assert_eq!(case["expected_runner"], "nonconformant");
        assert!(case["runner_error_count"].as_u64().unwrap_or_default() > 0);
        assert_eq!(case["runner_errors_match_expected_disposition"], true);
    }
    assert_eq!(result.case_count, 13);
}

#[test]
fn current_normative_corpus_manifest_digest_drift_is_invalid_without_running_the_runner() {
    let workspace = workspace_root();
    let source = workspace.join("deliverables/v02-t03/current-okf-normative-corpus.json");
    let temporary = tempfile::tempdir().expect("temporary corpus manifest directory");
    let copied = temporary.path().join("current-okf-normative-corpus.json");
    let content = fs::read_to_string(source).expect("current corpus manifest");
    fs::write(
        &copied,
        content.replace(
            "sha256:629a85e87ec6a09ec46df7d75b3b63a0e3641c610b00ee427b178bd87406ec69",
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        ),
    )
    .expect("write drifting corpus manifest");

    let result = validate_current_normative_corpus(&workspace, &current_pin(), &copied);
    assert_eq!(result.official_format.status, OkfAxisStatusV2::Invalid);
    assert_eq!(
        result.official_format.code,
        "E_V2_OKF_CURRENT_CORPUS_CASE_INVALID"
    );
    assert!(result.receipt_path.is_none());
}
