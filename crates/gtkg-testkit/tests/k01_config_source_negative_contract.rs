//! K01 validator coverage for config-driven source inspection.

use std::fs;
use std::path::Path;
use std::process::Command;

use gtkg_core::{CallContext, Dispatcher, EffectPolicy, TransportKind};
use gtkg_protocol::{ErrorCode, OperationId, OperationRequest};
use serde_json::json;
use tempfile::tempdir;

#[test]
fn v1_source_inspect_rejects_the_unversioned_config_mode_without_expanding_its_schema() {
    let temp = tempdir().expect("tempdir");
    let root = temp.path();
    let repository = root.join("repository");
    let templates = root.join("templates");
    let workspace = root.join("workspace");
    fs::create_dir_all(repository.join("src")).unwrap();
    fs::create_dir_all(&templates).unwrap();
    fs::create_dir_all(&workspace).unwrap();
    fs::write(repository.join("src/lib.rs"), "pub fn product() {}\n").unwrap();
    init_git(&repository);

    let config_path = root.join("gtkg.json");
    fs::write(
        &config_path,
        serde_json::to_vec_pretty(&json!({
            "schema_version": "gtkg.config/v2",
            "workspace_root": workspace,
            "storage_model": "okf-and-ordinary-files",
            "database_backend": null,
            "repositories": [{
                "repo_id": "product",
                "path": repository,
                "role": "code",
                "include": ["src"],
                "exclude": []
            }],
            "template_catalog_roots": [templates],
            "node_endpoints": []
        }))
        .unwrap(),
    )
    .unwrap();
    let expected_config_sha256 = format!("sha256:{}", "0".repeat(64));
    let context = CallContext::restricted(
        TransportKind::Test,
        vec![root.to_path_buf()],
        EffectPolicy::WorkspaceWrite,
    )
    .unwrap();

    for (request_id, payload) in [
        (
            "k01-complete-config-mode",
            json!({
                "config_path": config_path,
                "expected_config_sha256": expected_config_sha256,
            }),
        ),
        ("k01-config-path-only", json!({"config_path": config_path})),
        (
            "k01-config-digest-only",
            json!({"expected_config_sha256": expected_config_sha256}),
        ),
    ] {
        let error = Dispatcher
            .execute(
                &context,
                OperationRequest::new(OperationId::SourceInspect, request_id, payload),
            )
            .expect_err("v1 config mode must fail closed at its frozen schema");
        assert_eq!(error.error.code, ErrorCode::InvalidRequest);
        assert_eq!(error.error.stage, "payload-schema");
        assert!(
            error.error.message.contains("unknown field")
                || error.error.message.contains("missing required field"),
            "unexpected {request_id} error: {}",
            error.error.message
        );
    }
}

fn init_git(root: &Path) {
    for arguments in [
        &["init"][..],
        &["config", "user.name", "GTKG Fixture"],
        &["config", "user.email", "fixture@invalid.example"],
        &["add", "-A"],
        &["commit", "-m", "fixture"],
    ] {
        let output = Command::new("/usr/bin/git")
            .arg("-C")
            .arg(root)
            .args(arguments)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LC_ALL", "C")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git {} failed: {}",
            arguments.join(" "),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
