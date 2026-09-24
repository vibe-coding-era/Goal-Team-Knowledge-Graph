//! I00 immutable contract: a legacy migration remains explicitly unproven,
//! while an independently rebuilt v2 candidate can be joined to a sealed A06
//! gate without granting Current or canonical write authority.

#[path = "support/v03_i00_migration_fixture.rs"]
mod fixture;

use std::fs;
use std::path::Path;

use gtkg_core::file_model::tree_sha256;
use gtkg_core::v03::adapter::verifier::{AdapterGateAuthorityStateV1, AdapterGateReceiptV1};
use gtkg_core::v03::lifecycle::{
    A06TrustedGateExpectationV1, MigrationRebuildProvenanceV1,
    bind_migration_rebuild_provenance_v1, validate_migration_rebuild_provenance_v1,
};
use gtkg_core::{CallContext, Dispatcher, EffectPolicy, TransportKind};
use gtkg_protocol::FileReceiptRef;
use gtkg_protocol::canonical_json_sha256;
use gtkg_protocol::v2::{OperationRequestV2, V2ErrorCode};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

#[test]
fn i00_binds_legacy_to_exact_rebuild_and_sealed_a06_gate_without_laundering() {
    let (workspace, rebuilt_bundle_ref) = fixture::finalized_candidate();
    let root = workspace.path();
    let context = context(root);
    let migrated_bundle_ref = migrate_legacy(root, &context);
    let gate = fixture::sealed_a06_gate();
    assert_eq!(
        gate.authority_state,
        AdapterGateAuthorityStateV1::TrustedFixtureInputBound
    );
    let gate_ref = persist_gate(root, &gate);
    let expected = expected_gate(root, &rebuilt_bundle_ref, &gate);

    let joined = bind_migration_rebuild_provenance_v1(
        &context,
        root,
        migrated_bundle_ref.clone(),
        rebuilt_bundle_ref.clone(),
        gate_ref,
        expected.clone(),
    )
    .expect("legacy plus exact rebuild plus sealed gate must form an immutable I00 join");

    assert_eq!(joined.migration_bundle_ref, migrated_bundle_ref);
    assert_eq!(joined.rebuilt_bundle_ref, rebuilt_bundle_ref);
    assert_eq!(joined.provenance_state, "rebuild_bound_not_promoted");
    assert_eq!(joined.legacy_provenance_state, "not_proven");
    assert!(joined.migration_gap);
    assert!(!joined.canonical_eligible);
    assert_eq!(joined.current_write_count, 0);
    assert_eq!(joined.canonical_write_count, 0);
    assert_eq!(joined.replay_canonical_write_count, 0);

    let joined_ref = joined
        .file_receipt_ref()
        .expect("newly published provenance must carry its immutable file receipt");
    let readback = validate_migration_rebuild_provenance_v1(&context, root, &joined_ref, &expected)
        .expect("I01 must be able to replay-validate the immutable join");
    assert_eq!(readback, joined);

    let detached: MigrationRebuildProvenanceV1 =
        serde_json::from_slice(&serde_json::to_vec(&joined).unwrap()).unwrap();
    let detached_error = detached
        .file_receipt_ref()
        .expect_err("a deserialized record without its runtime file reference must fail closed");
    assert_eq!(detached_error.code, V2ErrorCode::InvalidState);
    assert_eq!(detached_error.stage, "migration.provenance.read");

    let migrated: Value = serde_json::from_slice(
        &fs::read(root.join(&migrated_bundle_ref.path)).expect("migrated candidate"),
    )
    .unwrap();
    assert_eq!(migrated["provenance_state"], "not_proven");
    assert_eq!(migrated["migration_gap"], true);
}

#[test]
fn i00_rejects_stale_or_resealed_a06_gate_and_replay_remains_noncanonical() {
    let (workspace, rebuilt_bundle_ref) = fixture::finalized_candidate();
    let root = workspace.path();
    let context = context(root);
    let migrated_bundle_ref = migrate_legacy(root, &context);
    let gate = fixture::sealed_a06_gate();
    let gate_ref = persist_gate(root, &gate);
    let expected = expected_gate(root, &rebuilt_bundle_ref, &gate);

    let stale = expected.with_source_snapshot_exact_set_sha256(sha256_prefixed(b"stale-source"));
    let stale_error = bind_migration_rebuild_provenance_v1(
        &context,
        root,
        migrated_bundle_ref.clone(),
        rebuilt_bundle_ref.clone(),
        gate_ref.clone(),
        stale,
    )
    .expect_err("a gate bound to another source snapshot is stale");
    assert_eq!(stale_error.stage, "migration.provenance.bind");

    let forged = resealed_downgrade(&gate);
    forged
        .validate()
        .expect("the attack is structurally self-consistent");
    assert_eq!(
        forged.authority_state,
        AdapterGateAuthorityStateV1::TrustedFixtureBound
    );
    let forged_ref = persist_gate(root, &forged);
    let forged_error = bind_migration_rebuild_provenance_v1(
        &context,
        root,
        migrated_bundle_ref,
        rebuilt_bundle_ref.clone(),
        forged_ref,
        expected,
    )
    .expect_err("a rehashed authority downgrade must not satisfy the sealed A06 pin");
    assert_eq!(forged_error.stage, "migration.provenance.bind");

    let snapshot = Dispatcher
        .execute_v2(
            &context,
            OperationRequestV2::new(
                "snapshot.create",
                "i00-replay-snapshot",
                json!({
                    "workspace_root": root,
                    "bundle_ref": rebuilt_bundle_ref,
                    "snapshot_version": "i00-replay"
                }),
            ),
        )
        .unwrap();
    let snapshot_ref: FileReceiptRef =
        serde_json::from_value(snapshot.result["snapshot_ref"].clone()).unwrap();
    let restore = Dispatcher
        .execute_v2(
            &context,
            OperationRequestV2::new(
                "snapshot.restore",
                "i00-replay-restore",
                json!({
                    "workspace_root": root,
                    "snapshot_ref": snapshot_ref,
                    "expected_snapshot_sha256": snapshot_ref.sha256,
                    "restore_version": "i00-replay"
                }),
            ),
        )
        .unwrap();
    for field in [
        "adapter_refresh_count",
        "index_write_count",
        "assistant_config_write_count",
        "network_call_count",
        "git_external_write_count",
        "current_write_count",
        "canonical_write_count",
    ] {
        assert_eq!(restore.result[field], 0, "{field}");
    }
}

fn context(root: &Path) -> CallContext {
    CallContext::restricted(
        TransportKind::Test,
        vec![root.to_path_buf()],
        EffectPolicy::WorkspaceWrite,
    )
    .unwrap()
}

fn migrate_legacy(root: &Path, context: &CallContext) -> FileReceiptRef {
    let legacy = root.join("i00-legacy");
    fs::create_dir(&legacy).unwrap();
    fs::write(
        legacy.join("manifest.json"),
        serde_json::to_vec_pretty(&json!({
            "schema_version": "gtkg.bundle/v1",
            "legacy_status": "not_proven"
        }))
        .unwrap(),
    )
    .unwrap();
    let migrated = Dispatcher
        .execute_v2(
            context,
            OperationRequestV2::new(
                "bundle.migrate.v1_to_v2",
                "i00-migrate",
                json!({
                    "workspace_root": root,
                    "legacy_bundle_path": legacy,
                    "expected_legacy_tree_sha256": tree_sha256(&root.join("i00-legacy")).unwrap(),
                    "migration_version": "i00-migration"
                }),
            ),
        )
        .unwrap();
    serde_json::from_value(migrated.result["bundle_ref"].clone()).unwrap()
}

fn persist_gate(root: &Path, gate: &AdapterGateReceiptV1) -> FileReceiptRef {
    let semantic = gate.receipt_sha256.strip_prefix("sha256:").unwrap();
    let relative = format!(".gtkg/a06/gates/{semantic}.json");
    let path = root.join(&relative);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let bytes = serde_json::to_vec_pretty(gate).unwrap();
    fs::write(&path, &bytes).unwrap();
    FileReceiptRef {
        path: relative,
        sha256: sha256_prefixed(&bytes),
    }
}

fn expected_gate(
    root: &Path,
    rebuilt_bundle_ref: &FileReceiptRef,
    gate: &AdapterGateReceiptV1,
) -> A06TrustedGateExpectationV1 {
    let rebuilt: Value = serde_json::from_slice(
        &fs::read(root.join(&rebuilt_bundle_ref.path)).expect("rebuilt bundle"),
    )
    .unwrap();
    A06TrustedGateExpectationV1::new(
        rebuilt["source_snapshot_exact_set_sha256"]
            .as_str()
            .unwrap()
            .to_owned(),
        gate.receipt_sha256.clone(),
        gate.trusted_oracle_pin_sha256.clone().unwrap(),
        gate.trusted_oracle_fixture_sha256.clone().unwrap(),
        gate.sealed_input_set_sha256.clone().unwrap(),
    )
    .unwrap()
}

fn resealed_downgrade(gate: &AdapterGateReceiptV1) -> AdapterGateReceiptV1 {
    let mut forged = gate.clone();
    forged.authority_state = AdapterGateAuthorityStateV1::TrustedFixtureBound;
    forged.sealed_input_set_sha256 = None;
    let mut semantic = serde_json::to_value(&forged).unwrap();
    semantic.as_object_mut().unwrap().remove("receipt_sha256");
    forged.receipt_sha256 = canonical_json_sha256(&semantic).unwrap();
    forged
}

fn sha256_prefixed(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}
