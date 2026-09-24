//! H05 official renderer contract.
//!
//! The non-ignored test freezes the exact browser package lock. The ignored
//! finalizer is driven by `h05_official_lit_renderer_contract.sh` after the real
//! @a2ui/lit browser run has produced a v2 smoke receipt.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use gtkg_core::file_model::{sha256_file, tree_sha256};
use gtkg_core::{CallContext, Dispatcher, EffectPolicy, TransportKind};
use gtkg_protocol::{ErrorCode, FileReceiptRef, OperationId, OperationRequest};
use serde_json::{Value, json};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root")
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(
        &fs::read(path).unwrap_or_else(|error| panic!("read {}: {error}", path.display())),
    )
    .unwrap_or_else(|error| panic!("parse {}: {error}", path.display()))
}

#[test]
fn h05_renderer_package_lock_is_exact_and_non_floating() {
    let root = repo_root().join("crates/gtkg-testkit/browser/h05-a2ui-lit");
    let trusted: Value = read_json(
        &repo_root().join("crates/gtkg-core/vendor/a2ui/v0_9_1/official_lit_renderer_lock.json"),
    );
    let package: Value = read_json(&root.join("package.json"));
    let lock: Value = read_json(&root.join("package-lock.json"));
    assert_eq!(
        trusted["schema_version"],
        "gtkg.official-lit-renderer-lock/v1"
    );
    assert_eq!(trusted["renderer_id"], "official-a2ui-lit");
    assert_eq!(trusted["renderer_version"], "0.10.3");
    assert_eq!(
        trusted["package_lock_sha256"],
        sha256_file(&root.join("package-lock.json")).unwrap()
    );
    for (name, version) in [
        ("@a2ui/lit", "0.10.3"),
        ("@a2ui/web_core", "0.10.6"),
        ("lit", "3.3.3"),
        ("playwright", "1.63.0-alpha-2026-08-05"),
        ("vite", "7.1.3"),
    ] {
        let declared = package["dependencies"]
            .get(name)
            .or_else(|| package["devDependencies"].get(name))
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("package.json missing {name}"));
        assert_eq!(declared, version, "{name} must be an exact pin");
        let locked = &lock["packages"][format!("node_modules/{name}")];
        assert_eq!(locked["version"], version, "{name} lock version");
        assert!(
            locked["integrity"]
                .as_str()
                .is_some_and(|value| !value.is_empty()),
            "{name} lock integrity"
        );
        let trusted_package = trusted["packages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|package| package["name"] == name)
            .unwrap_or_else(|| panic!("trusted renderer lock missing {name}"));
        assert_eq!(trusted_package["version"], version);
        assert_eq!(trusted_package["integrity"], locked["integrity"]);
    }
    assert_eq!(trusted["packages"].as_array().unwrap().len(), 5);
    let harness = trusted["harness_files"].as_array().unwrap();
    let mut paths = BTreeSet::new();
    for artifact in harness {
        let relative = artifact["path"].as_str().expect("harness path");
        assert!(paths.insert(relative));
        assert_eq!(
            artifact["sha256"],
            sha256_file(&root.join(relative)).expect("trusted harness digest")
        );
    }
    assert_eq!(harness.len(), 7);
}

#[test]
#[ignore = "driven by the H05 shell harness after the official Lit renderer smoke"]
fn validate_h05_renderer_replicable_with_browser_evidence() {
    let output = PathBuf::from(
        std::env::var_os("GTKG_H05_BROWSER_OUTPUT")
            .expect("GTKG_H05_BROWSER_OUTPUT must name the H05 output root"),
    );
    let emitter = output.join("emitter/h05-current-source-receipt.json");
    let fixture = read_json(&emitter);
    assert_eq!(
        fixture["schema_version"],
        "gtkg.h05-current-source-receipt/v1"
    );
    assert_eq!(fixture["source_snapshot"]["state"], "dirty_snapshot");
    assert_eq!(
        fixture["source_snapshot"]["excluded_paths"],
        serde_json::json!([
            "TaskList.md",
            "loop-review.md",
            "deliverables/h05-official-renderer"
        ])
    );
    assert_eq!(
        fixture["source_file_count"].as_u64().unwrap(),
        fixture["admitted_source_count"].as_u64().unwrap()
            + fixture["omission_count"].as_u64().unwrap()
    );
    assert!(fixture["admitted_source_count"].as_u64().unwrap() > 12);
    let bundle = PathBuf::from(fixture["bundle_path"].as_str().expect("bundle path"));
    assert_eq!(
        tree_sha256(&bundle).expect("bundle tree"),
        fixture["bundle_tree_sha256"]
    );
    assert_eq!(fixture["a2ui_lock"]["renderer_id"], "official-a2ui-lit");
    assert_eq!(fixture["a2ui_lock"]["renderer_version"], "0.10.3");
    let workspace = PathBuf::from(fixture["workspace"].as_str().expect("workspace"));
    let evidence_path = workspace.join(".gtkg/a2ui/browser-evidence/smoke-h05-v2.json");
    let evidence = read_json(&evidence_path);
    assert_eq!(evidence["schema_version"], "gtkg.a2ui-renderer-smoke/v2");

    let browser_executable = PathBuf::from(
        evidence["browser"]["executable_path"]
            .as_str()
            .expect("browser executable"),
    );
    let browser_root = browser_executable
        .parent()
        .expect("browser executable parent")
        .to_owned();
    let context = CallContext::restricted(
        TransportKind::Test,
        vec![output.clone(), repo_root(), browser_root],
        EffectPolicy::WorkspaceWrite,
    )
    .expect("H05 call context");
    let evidence_ref = FileReceiptRef {
        path: evidence_path
            .strip_prefix(&workspace)
            .expect("evidence in workspace")
            .to_string_lossy()
            .replace('\\', "/"),
        sha256: sha256_file(&evidence_path).expect("evidence digest"),
    };
    let validated = Dispatcher
        .execute(
            &context,
            OperationRequest::new(
                OperationId::A2uiValidate,
                "h05-official-renderer-validate",
                json!({
                    "workspace_root": workspace,
                    "generation_ref": fixture["generation_ref"],
                    "expected_projection_tree_sha256": fixture["projection_tree_sha256"],
                    "required_evidence_state": "renderer_replicable",
                    "renderer_smoke_ref": evidence_ref,
                }),
            ),
        )
        .expect("H05 v2 evidence must grant renderer_replicable");
    assert_eq!(validated.result["valid"], true);
    assert_eq!(
        validated.result["observed_evidence_state"],
        "renderer_replicable"
    );
    assert_eq!(validated.result["checks"]["renderer_smoke"], "passed");
    assert_eq!(validated.result["checks"]["screenshot_artifacts"], "passed");
    assert_eq!(validated.result["checks"]["visual_threshold"], "not_run");

    let replica = Dispatcher
        .execute(
            &context,
            OperationRequest::new(
                OperationId::A2uiValidate,
                "h05-verified-replica-stays-closed",
                json!({
                    "workspace_root": workspace,
                    "generation_ref": fixture["generation_ref"],
                    "expected_projection_tree_sha256": fixture["projection_tree_sha256"],
                    "required_evidence_state": "verified_replica",
                    "renderer_smoke_ref": evidence_ref,
                }),
            ),
        )
        .expect_err("verified_replica is not granted by local renderer evidence");
    assert_eq!(replica.error.code, ErrorCode::InvalidState);

    fs::write(
        output.join("h05-validation.json"),
        serde_json::to_vec_pretty(&json!({
            "schema_version": "gtkg.h05-validation/v1",
            "evidence_sha256": sha256_file(&evidence_path).unwrap(),
            "source_snapshot": fixture["source_snapshot"],
            "source_file_count": fixture["source_file_count"],
            "admitted_source_count": fixture["admitted_source_count"],
            "omission_count": fixture["omission_count"],
            "bundle_tree_sha256": fixture["bundle_tree_sha256"],
            "projection_tree_sha256": fixture["projection_tree_sha256"],
            "validation": validated.result,
            "verified_replica": "not_run_fail_closed"
        }))
        .unwrap(),
    )
    .unwrap();
}
