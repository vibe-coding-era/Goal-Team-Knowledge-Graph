//! P04 successor: legacy migration and replay must remain inside the authorized workspace.

use std::fs;
use std::path::{Path, PathBuf};

use gtkg_core::file_model::tree_sha256;
use gtkg_core::{CallContext, Dispatcher, EffectPolicy, TransportKind};
use gtkg_protocol::v2::{OperationRequestV2, V2ErrorCode, V2ErrorEnvelope};
use gtkg_protocol::{FileReceiptRef, canonical_json_sha256};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

#[test]
fn p04_rehashed_bundle_cannot_replay_an_absolute_legacy_tree_outside_workspace() {
    let workspace = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    write_v1_manifest(outside.path());
    let outside_tree = tree_sha256(outside.path()).unwrap();
    let bundle_ref = forge_migrated_bundle(workspace.path(), outside.path(), &outside_tree);
    let context = context(workspace.path());

    for (operation, payload) in [
        (
            "bundle.verify",
            json!({"workspace_root": workspace.path(), "bundle_ref": bundle_ref}),
        ),
        (
            "bundle.compare",
            json!({
                "workspace_root": workspace.path(),
                "left_bundle_ref": bundle_ref,
                "right_bundle_ref": bundle_ref
            }),
        ),
        (
            "snapshot.create",
            json!({
                "workspace_root": workspace.path(),
                "bundle_ref": bundle_ref,
                "snapshot_version": "legacy-boundary"
            }),
        ),
    ] {
        assert_security_failure(Dispatcher.execute_v2(
            &context,
            OperationRequestV2::new(operation, format!("p04-outside-{operation}"), payload),
        ));
    }
}

#[test]
fn p04_migration_requires_a_well_formed_v1_manifest_and_stores_a_relative_path() {
    let workspace = tempfile::tempdir().unwrap();
    let empty = workspace.path().join("empty");
    let unknown = workspace.path().join("unknown");
    let malformed = workspace.path().join("malformed");
    let valid = workspace.path().join("valid");
    for directory in [&empty, &unknown, &malformed, &valid] {
        fs::create_dir(directory).unwrap();
    }
    fs::write(
        unknown.join("manifest.json"),
        br#"{"schema_version":"gtkg.bundle/unknown"}"#,
    )
    .unwrap();
    fs::write(malformed.join("manifest.json"), b"{not-json").unwrap();
    write_v1_manifest(&valid);

    for (name, directory) in [
        ("empty", &empty),
        ("unknown", &unknown),
        ("malformed", &malformed),
    ] {
        assert_security_failure(migrate(workspace.path(), directory, name));
    }

    let migrated = migrate(workspace.path(), &valid, "valid").unwrap();
    let bundle_ref: FileReceiptRef =
        serde_json::from_value(migrated.result["bundle_ref"].clone()).unwrap();
    let bundle: Value =
        serde_json::from_slice(&fs::read(workspace.path().join(bundle_ref.path)).unwrap()).unwrap();
    assert_eq!(bundle["legacy_bundle_path"], "valid");
}

#[cfg(unix)]
#[test]
fn p04_migration_rejects_symlink_and_hardlink_entries() {
    use std::os::unix::fs::symlink;

    let workspace = tempfile::tempdir().unwrap();
    let target = workspace.path().join("target.json");
    fs::write(&target, b"target").unwrap();

    let symlinked = workspace.path().join("symlinked");
    fs::create_dir(&symlinked).unwrap();
    write_v1_manifest(&symlinked);
    symlink(&target, symlinked.join("alias.json")).unwrap();
    assert_security_failure(migrate_with_declared_digest(
        workspace.path(),
        &symlinked,
        digest("symlink-tree"),
        "symlink",
    ));

    let hardlinked = workspace.path().join("hardlinked");
    fs::create_dir(&hardlinked).unwrap();
    write_v1_manifest(&hardlinked);
    fs::hard_link(
        hardlinked.join("manifest.json"),
        hardlinked.join("manifest-copy.json"),
    )
    .unwrap();
    assert_security_failure(migrate_with_declared_digest(
        workspace.path(),
        &hardlinked,
        digest("hardlink-tree"),
        "hardlink",
    ));
}

fn migrate(
    workspace: &Path,
    legacy: &Path,
    request_id: &str,
) -> Result<gtkg_protocol::v2::OperationResponseV2, V2ErrorEnvelope> {
    migrate_with_declared_digest(workspace, legacy, tree_sha256(legacy).unwrap(), request_id)
}

fn migrate_with_declared_digest(
    workspace: &Path,
    legacy: &Path,
    expected_tree: String,
    request_id: &str,
) -> Result<gtkg_protocol::v2::OperationResponseV2, V2ErrorEnvelope> {
    Dispatcher.execute_v2(
        &context(workspace),
        OperationRequestV2::new(
            "bundle.migrate.v1_to_v2",
            format!("p04-legacy-{request_id}"),
            json!({
                "workspace_root": workspace,
                "legacy_bundle_path": legacy,
                "expected_legacy_tree_sha256": expected_tree,
                "migration_version": "legacy-boundary"
            }),
        ),
    )
}

fn forge_migrated_bundle(workspace: &Path, legacy: &Path, tree: &str) -> FileReceiptRef {
    let mut bundle = json!({
        "schema_version": "gtkg.candidate-bundle/v2",
        "bundle_kind": "migrated_legacy_candidate",
        "bundle_version": "legacy-boundary",
        "source_snapshot_exact_set_sha256": null,
        "analysis_verification_ref": null,
        "analysis_verification_sha256": null,
        "accepted_summary_ref": null,
        "accepted_summary_sha256": null,
        "legacy_bundle_path": legacy,
        "legacy_tree_sha256": tree,
        "fact_receipt_sha256s": [],
        "asserted_claim_receipt_sha256s": [],
        "provenance_state": "not_proven",
        "migration_gap": true,
        "partial": true,
        "a06_cross_adapter_status": "not_run",
        "collision_check": "not_run",
        "canonical_eligible": false,
        "git_external_write_count": 0,
        "current_write_count": 0,
        "canonical_write_count": 0,
        "bundle_sha256": ""
    });
    let mut semantic = bundle.clone();
    semantic.as_object_mut().unwrap().remove("bundle_sha256");
    let bundle_sha = canonical_json_sha256(&semantic).unwrap();
    bundle["bundle_sha256"] = json!(bundle_sha);
    let bytes = serde_json::to_vec_pretty(&bundle).unwrap();
    let relative = PathBuf::from(format!(
        ".gtkg/lifecycle/bundles/{}.json",
        bundle_sha.strip_prefix("sha256:").unwrap()
    ));
    let path = workspace.join(&relative);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, &bytes).unwrap();
    FileReceiptRef {
        path: relative.to_string_lossy().into_owned(),
        sha256: sha256(&bytes),
    }
}

fn write_v1_manifest(root: &Path) {
    fs::write(
        root.join("manifest.json"),
        serde_json::to_vec_pretty(&json!({
            "schema_version": "gtkg.bundle/v1",
            "legacy_fact": "not_proven"
        }))
        .unwrap(),
    )
    .unwrap();
}

fn context(root: &Path) -> CallContext {
    CallContext::restricted(
        TransportKind::Test,
        vec![root.to_path_buf()],
        EffectPolicy::WorkspaceWrite,
    )
    .unwrap()
}

fn assert_security_failure(
    result: Result<gtkg_protocol::v2::OperationResponseV2, V2ErrorEnvelope>,
) {
    let code = result.unwrap_err().error.code;
    assert!(matches!(
        code,
        V2ErrorCode::InvalidRequest
            | V2ErrorCode::InvalidState
            | V2ErrorCode::PathEscape
            | V2ErrorCode::SymlinkRejected
    ));
}

fn digest(label: &str) -> String {
    sha256(label.as_bytes())
}

fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}
