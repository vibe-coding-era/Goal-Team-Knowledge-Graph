//! P04 migration/snapshot durability and replay security successor.

use std::fs;
use std::path::{Path, PathBuf};

use gtkg_core::file_model::tree_sha256;
use gtkg_core::{CallContext, Dispatcher, EffectPolicy, TransportKind};
use gtkg_protocol::v2::{OperationRequestV2, V2ErrorCode};
use gtkg_protocol::{FileReceiptRef, canonical_json_sha256};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

#[test]
fn p04_migration_and_restore_are_request_id_independent_and_legacy_bytes_unchanged() {
    let fixture = Fixture::new();
    let before = fs::read(fixture.legacy.join("manifest.json")).unwrap();
    let first = fixture.migrate("p04-migrate-first").unwrap();
    let replay = fixture.migrate("p04-migrate-replay").unwrap();
    assert_eq!(first.result, replay.result);
    assert_eq!(
        fs::read(fixture.legacy.join("manifest.json")).unwrap(),
        before
    );
    let bundle_ref: FileReceiptRef =
        serde_json::from_value(first.result["bundle_ref"].clone()).unwrap();
    let snapshot = fixture.snapshot(&bundle_ref, "p04-snapshot-first");
    let snapshot_replay = fixture.snapshot(&bundle_ref, "p04-snapshot-replay");
    assert_eq!(snapshot.result, snapshot_replay.result);
    let snapshot_ref: FileReceiptRef =
        serde_json::from_value(snapshot.result["snapshot_ref"].clone()).unwrap();
    let restore = fixture.restore(&snapshot_ref, "p04-restore-first").unwrap();
    let restore_replay = fixture
        .restore(&snapshot_ref, "p04-restore-replay")
        .unwrap();
    assert_eq!(restore.result, restore_replay.result);
    assert_eq!(restore.result["replay"], true);
    assert_eq!(restore.result["current_write_count"], 0);
    assert_eq!(restore.result["canonical_write_count"], 0);
}

#[test]
fn p04_rehashed_non_replay_snapshot_is_rejected() {
    let fixture = Fixture::new();
    let migrated = fixture.migrate("p04-tamper-migrate").unwrap();
    let bundle_ref: FileReceiptRef =
        serde_json::from_value(migrated.result["bundle_ref"].clone()).unwrap();
    let snapshot = fixture.snapshot(&bundle_ref, "p04-tamper-snapshot");
    let snapshot_ref: FileReceiptRef =
        serde_json::from_value(snapshot.result["snapshot_ref"].clone()).unwrap();
    let mut value: Value =
        serde_json::from_slice(&fs::read(fixture.root().join(snapshot_ref.path)).unwrap()).unwrap();
    value["replay_only"] = json!(false);
    let forged_ref = fixture.forge(value, "snapshot_sha256", ".gtkg/lifecycle/snapshots");
    let verify = Dispatcher.execute_v2(
        &fixture.context(),
        OperationRequestV2::new(
            "snapshot.verify",
            "p04-forged-snapshot-verify",
            json!({"workspace_root": fixture.root(), "snapshot_ref": forged_ref}),
        ),
    );
    assert_invalid(verify);
    let restore = fixture.restore(&forged_ref, "p04-forged-snapshot-restore");
    assert_invalid(restore);
}

#[test]
fn p04_partial_temp_recovers_and_conflicting_final_is_never_clobbered() {
    let fixture = Fixture::new();
    let first = fixture.migrate("p04-durable-first").unwrap();
    let bundle_ref: FileReceiptRef =
        serde_json::from_value(first.result["bundle_ref"].clone()).unwrap();
    let final_path = fixture.root().join(&bundle_ref.path);
    let file_name = final_path.file_name().unwrap().to_string_lossy();
    let temporary = final_path
        .parent()
        .unwrap()
        .join(format!(".{file_name}.receipt.tmp"));
    fs::write(&temporary, b"partial").unwrap();
    let recovered = fixture.migrate("p04-durable-recover").unwrap();
    assert_eq!(recovered.result, first.result);
    assert!(!temporary.exists());

    fs::remove_file(&final_path).unwrap();
    let conflict = b"{}";
    fs::write(&final_path, conflict).unwrap();
    let error = fixture.migrate("p04-durable-conflict").unwrap_err();
    assert_eq!(error.error.code, V2ErrorCode::InvalidState);
    assert_eq!(fs::read(final_path).unwrap(), conflict);
}

fn assert_invalid(
    result: Result<gtkg_protocol::v2::OperationResponseV2, gtkg_protocol::v2::V2ErrorEnvelope>,
) {
    assert_eq!(result.unwrap_err().error.code, V2ErrorCode::InvalidState);
}

struct Fixture {
    workspace: tempfile::TempDir,
    legacy: PathBuf,
    legacy_tree: String,
}

impl Fixture {
    fn new() -> Self {
        let workspace = tempfile::tempdir().unwrap();
        let legacy = workspace.path().join("legacy");
        fs::create_dir(&legacy).unwrap();
        fs::write(
            legacy.join("manifest.json"),
            serde_json::to_vec_pretty(&json!({
                "schema_version": "gtkg.bundle/v1",
                "legacy_fact": "not_proven"
            }))
            .unwrap(),
        )
        .unwrap();
        let legacy_tree = tree_sha256(&legacy).unwrap();
        Self {
            workspace,
            legacy,
            legacy_tree,
        }
    }

    fn root(&self) -> &Path {
        self.workspace.path()
    }

    fn context(&self) -> CallContext {
        CallContext::restricted(
            TransportKind::Test,
            vec![self.root().to_path_buf()],
            EffectPolicy::WorkspaceWrite,
        )
        .unwrap()
    }

    fn migrate(
        &self,
        request_id: &str,
    ) -> Result<gtkg_protocol::v2::OperationResponseV2, gtkg_protocol::v2::V2ErrorEnvelope> {
        Dispatcher.execute_v2(
            &self.context(),
            OperationRequestV2::new(
                "bundle.migrate.v1_to_v2",
                request_id,
                json!({
                    "workspace_root": self.root(),
                    "legacy_bundle_path": self.legacy,
                    "expected_legacy_tree_sha256": self.legacy_tree,
                    "migration_version": "migration-security"
                }),
            ),
        )
    }

    fn snapshot(
        &self,
        bundle_ref: &FileReceiptRef,
        request_id: &str,
    ) -> gtkg_protocol::v2::OperationResponseV2 {
        Dispatcher
            .execute_v2(
                &self.context(),
                OperationRequestV2::new(
                    "snapshot.create",
                    request_id,
                    json!({
                        "workspace_root": self.root(),
                        "bundle_ref": bundle_ref,
                        "snapshot_version": "snapshot-security"
                    }),
                ),
            )
            .unwrap()
    }

    fn restore(
        &self,
        snapshot_ref: &FileReceiptRef,
        request_id: &str,
    ) -> Result<gtkg_protocol::v2::OperationResponseV2, gtkg_protocol::v2::V2ErrorEnvelope> {
        Dispatcher.execute_v2(
            &self.context(),
            OperationRequestV2::new(
                "snapshot.restore",
                request_id,
                json!({
                    "workspace_root": self.root(),
                    "snapshot_ref": snapshot_ref,
                    "expected_snapshot_sha256": snapshot_ref.sha256,
                    "restore_version": "restore-security"
                }),
            ),
        )
    }

    fn forge(&self, mut value: Value, field: &str, partition: &str) -> FileReceiptRef {
        let mut semantic = value.clone();
        semantic.as_object_mut().unwrap().remove(field);
        let digest = canonical_json_sha256(&semantic).unwrap();
        value[field] = json!(digest);
        let bytes = serde_json::to_vec_pretty(&value).unwrap();
        let path = self.root().join(format!(
            "{partition}/{}.json",
            digest.strip_prefix("sha256:").unwrap()
        ));
        fs::write(&path, &bytes).unwrap();
        FileReceiptRef {
            path: path
                .strip_prefix(self.root())
                .unwrap()
                .to_string_lossy()
                .into_owned(),
            sha256: sha256(&bytes),
        }
    }
}

fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}
