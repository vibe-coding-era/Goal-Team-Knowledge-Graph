//! I00 source-bound successor: a sealed A06 gate is accepted only when its
//! complete strict replay input comes from the exact P02/P03 rebuilt source.

#[path = "support/v03_i00_source_bound_fixture.rs"]
mod fixture;
#[path = "support/v03_i00_migration_fixture.rs"]
mod v1_fixture;

use std::fs;
use std::path::Path;

use gtkg_core::file_model::tree_sha256;
use gtkg_core::v03::adapter::verifier::AdapterGateReceiptV1;
use gtkg_core::v03::lifecycle::{
    A06TrustedGateExpectationV1, MigrationRebuildProvenanceV2,
    bind_migration_rebuild_provenance_source_bound_v2, bind_migration_rebuild_provenance_v1,
    publish_a06_source_bound_gate_attestation_v1,
    validate_migration_rebuild_provenance_source_bound_v2,
};
use gtkg_core::{CallContext, Dispatcher, EffectPolicy, TransportKind};
use gtkg_protocol::FileReceiptRef;
use gtkg_protocol::v2::{OperationRequestV2, V2ErrorCode};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

#[test]
fn i00_v2_binds_legacy_to_a_full_strict_a06_replay_from_the_rebuilt_source() {
    let candidate = fixture::same_source_candidate();
    let root = candidate.workspace.path();
    let context = context(root);
    let migrated_bundle_ref = migrate_legacy(root, &context);
    let gate_ref = candidate.persist_gate();
    let trusted_fixture_ref = candidate.persist_trusted_fixture();
    let attestation = publish_a06_source_bound_gate_attestation_v1(
        &context,
        root,
        candidate.attestation_input(gate_ref, trusted_fixture_ref),
    )
    .expect("the real five-adapter gate must strict-replay from the exact rebuilt source");
    let attestation_ref = attestation
        .file_receipt_ref()
        .expect("new immutable attestation has a receipt");

    let joined = bind_migration_rebuild_provenance_source_bound_v2(
        &context,
        root,
        migrated_bundle_ref.clone(),
        candidate.bundle_ref.clone(),
        attestation_ref,
    )
    .expect("only a source-bound strict gate may join the rebuilt candidate");
    assert_eq!(joined.migration_bundle_ref, migrated_bundle_ref);
    assert_eq!(joined.rebuilt_bundle_ref, candidate.bundle_ref);
    assert_eq!(joined.provenance_state, "source_bound_rebuild_not_promoted");
    assert_eq!(joined.legacy_provenance_state, "not_proven");
    assert!(joined.migration_gap);
    assert!(!joined.canonical_eligible);
    assert_eq!(joined.current_write_count, 0);
    assert_eq!(joined.canonical_write_count, 0);
    assert_eq!(joined.replay_canonical_write_count, 0);

    let joined_ref = joined.file_receipt_ref().unwrap();
    let readback =
        validate_migration_rebuild_provenance_source_bound_v2(&context, root, &joined_ref)
            .expect("I01 can revalidate the same source-bound strict gate");
    assert_eq!(readback, joined);

    let detached: MigrationRebuildProvenanceV2 =
        serde_json::from_slice(&serde_json::to_vec(&joined).unwrap()).unwrap();
    let detached_error = detached.file_receipt_ref().unwrap_err();
    assert_eq!(detached_error.code, V2ErrorCode::InvalidState);
    assert_eq!(detached_error.stage, "migration.provenance.v2.read");

    assert_replay_has_no_current_or_canonical_writes(&context, root, &candidate.bundle_ref);
}

#[test]
fn i00_v2_rejects_a_structurally_valid_sealed_gate_replayed_from_different_source() {
    let candidate = fixture::foreign_source_candidate();
    let root = candidate.workspace.path();
    let context = context(root);
    candidate
        .gate
        .validate()
        .expect("precondition: source-B gate is valid");
    let gate_ref = candidate.persist_gate();
    let trusted_fixture_ref = candidate.persist_trusted_fixture();

    let error = publish_a06_source_bound_gate_attestation_v1(
        &context,
        root,
        candidate.attestation_input(gate_ref, trusted_fixture_ref),
    )
    .expect_err("a valid source-A gate cannot strict-replay from source-B");
    assert_eq!(error.code, V2ErrorCode::LockMismatch);
    assert_eq!(error.stage, "migration.a06-attestation");
}

#[test]
fn i00_v2_allows_one_exact_source_image_file_to_be_replayed_by_multiple_adapters() {
    let candidate = fixture::shared_source_candidate();
    let root = candidate.workspace.path();
    let context = context(root);
    let gate_ref = candidate.persist_gate();
    let trusted_fixture_ref = candidate.persist_trusted_fixture();
    let attestation = publish_a06_source_bound_gate_attestation_v1(
        &context,
        root,
        candidate.attestation_input(gate_ref, trusted_fixture_ref),
    )
    .expect("Native and LSP may replay the same exact ledger.rs source image entry");
    assert!(attestation.file_receipt_ref().is_ok());
}

#[test]
fn i00_v2_reader_rejects_a_real_historical_v1_provenance_reference() {
    let (workspace, rebuilt_bundle_ref) = v1_fixture::finalized_candidate();
    let root = workspace.path();
    let context = context(root);
    let migrated_bundle_ref = migrate_legacy(root, &context);
    let gate = v1_fixture::sealed_a06_gate();
    let gate_ref = persist_v1_gate(root, &gate);
    let rebuilt: Value = serde_json::from_slice(
        &fs::read(root.join(&rebuilt_bundle_ref.path)).expect("historical rebuilt bundle"),
    )
    .unwrap();
    let expectation = A06TrustedGateExpectationV1::new(
        rebuilt["source_snapshot_exact_set_sha256"]
            .as_str()
            .unwrap()
            .to_owned(),
        gate.receipt_sha256.clone(),
        gate.trusted_oracle_pin_sha256.clone().unwrap(),
        gate.trusted_oracle_fixture_sha256.clone().unwrap(),
        gate.sealed_input_set_sha256.clone().unwrap(),
    )
    .unwrap();
    let historical = bind_migration_rebuild_provenance_v1(
        &context,
        root,
        migrated_bundle_ref,
        rebuilt_bundle_ref,
        gate_ref,
        expectation,
    )
    .expect("precondition: preserved V1 route remains readable historical evidence");
    let historical_ref = historical.file_receipt_ref().unwrap();

    let error =
        validate_migration_rebuild_provenance_source_bound_v2(&context, root, &historical_ref)
            .expect_err("a V1 reference must never satisfy the V2/I01 source-bound reader");
    assert_eq!(error.code, V2ErrorCode::InvalidState);
    assert_eq!(error.stage, "migration.provenance.v2.read");
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
    let legacy = root.join("i00-v2-legacy");
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
                "i00-v2-migrate",
                json!({
                    "workspace_root": root,
                    "legacy_bundle_path": legacy,
                    "expected_legacy_tree_sha256": tree_sha256(&root.join("i00-v2-legacy")).unwrap(),
                    "migration_version": "i00-v2-migration"
                }),
            ),
        )
        .unwrap();
    serde_json::from_value(migrated.result["bundle_ref"].clone()).unwrap()
}

fn assert_replay_has_no_current_or_canonical_writes(
    context: &CallContext,
    root: &Path,
    bundle_ref: &FileReceiptRef,
) {
    let snapshot = Dispatcher
        .execute_v2(
            context,
            OperationRequestV2::new(
                "snapshot.create",
                "i00-v2-replay-snapshot",
                json!({
                    "workspace_root": root,
                    "bundle_ref": bundle_ref,
                    "snapshot_version": "i00-v2-replay"
                }),
            ),
        )
        .unwrap();
    let snapshot_ref: FileReceiptRef =
        serde_json::from_value(snapshot.result["snapshot_ref"].clone()).unwrap();
    let restore = Dispatcher
        .execute_v2(
            context,
            OperationRequestV2::new(
                "snapshot.restore",
                "i00-v2-replay-restore",
                json!({
                    "workspace_root": root,
                    "snapshot_ref": snapshot_ref,
                    "expected_snapshot_sha256": snapshot_ref.sha256,
                    "restore_version": "i00-v2-replay"
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

fn persist_v1_gate(root: &Path, gate: &AdapterGateReceiptV1) -> FileReceiptRef {
    let semantic = gate.receipt_sha256.strip_prefix("sha256:").unwrap();
    let relative = format!(".gtkg/a06/gates/{semantic}.json");
    let path = root.join(&relative);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let bytes = serde_json::to_vec_pretty(gate).unwrap();
    fs::write(&path, &bytes).unwrap();
    FileReceiptRef {
        path: relative,
        sha256: format!("sha256:{}", hex::encode(Sha256::digest(bytes))),
    }
}
