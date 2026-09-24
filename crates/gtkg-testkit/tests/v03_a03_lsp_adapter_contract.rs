use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use gtkg_core::v03::adapter::lsp_snapshot::{
    LspSnapshotFilePinV1, import_pinned_lsp_snapshot_json_file_v1,
};
use gtkg_core::v03::adapter::verify_external_fact_bundle_v1;
use gtkg_protocol::v03::AdapterKindV1;
use gtkg_protocol::v03::adapter::{CandidateFactStateV1, FactTrustStateV1};
use sha2::{Digest, Sha256};

const LSP_SNAPSHOT_SCHEMA_VERSION: &str = "gtkg.lsp-snapshot/v1";
const LSP_SNAPSHOT_SCHEMA_SHA256: &str =
    "sha256:97a36add17cb89ec94b92222e8c4b1673dbb5bd5443644f1f346140ad4dd19c1";
const LSP_PROTOCOL_VERSION: &str = "3.17";
const POSITION_ENCODING: &str = "utf-8";
const PRODUCER_COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
const PRODUCER_CONFIG_SHA256: &str =
    "sha256:9569022226845a35bce92d52c125556785d8a1d67f6e78b900bb3dc02bac9228";
const SOURCE_SNAPSHOT_SHA256: &str =
    "sha256:c45839fdd713b1acb620523e6c9d80ac07fc271113cfad5eb76ef328045e6ddc";
const VALID_FILE_SHA256: &str =
    "sha256:34f19599535a24ad43b2c8da9fc74a0df76d36885a7fdb7f8e79cc25839f3841";
const SHUFFLED_FILE_SHA256: &str =
    "sha256:ef5fe74bc96d2dfcc4115727195fb7568fc32cd7c55cc8d14610b6c3f744426b";
const INVALID_RANGE_FILE_SHA256: &str =
    "sha256:e29e40d5482f21674fcba60414b34541b72be576bd970fbeaf426a987cfadca3";
const SCHEMA_DRIFT_FILE_SHA256: &str =
    "sha256:600040ad75d967ad0f67a89869932e419681d21d936ed38797933316ac8dfad1";
const LIVE_RESPONSE_FILE_SHA256: &str =
    "sha256:fb6501d96661ef55adbd3ca0724973ec74842a893b99837b2298d3278df22253";
const NONDETERMINISTIC_FILE_SHA256: &str =
    "sha256:3fedcd23faffeb51f705ad42e634ded372729022b478c69cf034edd5708be846";
const SOURCE_TAMPERED_FILE_SHA256: &str =
    "sha256:403dbff468f47e96e91d7571ed761cc7888618ceb7cd54bfa3228346bd587dbb";

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures/v03_a03")
        .join(name)
}

fn pin(file_sha256: &str) -> LspSnapshotFilePinV1 {
    LspSnapshotFilePinV1 {
        file_sha256: file_sha256.to_owned(),
        schema_version: LSP_SNAPSHOT_SCHEMA_VERSION.to_owned(),
        schema_sha256: LSP_SNAPSHOT_SCHEMA_SHA256.to_owned(),
        protocol_version: LSP_PROTOCOL_VERSION.to_owned(),
        position_encoding: POSITION_ENCODING.to_owned(),
        producer_name: "rust-analyzer".to_owned(),
        producer_version: "2026-08-24".to_owned(),
        producer_commit: PRODUCER_COMMIT.to_owned(),
        producer_license: "MIT OR Apache-2.0".to_owned(),
        producer_config_sha256: PRODUCER_CONFIG_SHA256.to_owned(),
        source_snapshot_sha256: SOURCE_SNAPSHOT_SHA256.to_owned(),
        max_file_bytes: 64 * 1024,
    }
}

fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

#[test]
fn a03_frozen_lsp_snapshot_is_deterministic_across_input_order() {
    let first = import_pinned_lsp_snapshot_json_file_v1(
        &fixture("valid-lsp-snapshot.json"),
        &pin(VALID_FILE_SHA256),
    )
    .expect("the exact frozen LSP snapshot must import");
    let replay = import_pinned_lsp_snapshot_json_file_v1(
        &fixture("valid-lsp-snapshot.json"),
        &pin(VALID_FILE_SHA256),
    )
    .expect("replaying identical bytes must import");
    let shuffled = import_pinned_lsp_snapshot_json_file_v1(
        &fixture("valid-lsp-snapshot-shuffled.json"),
        &pin(SHUFFLED_FILE_SHA256),
    )
    .expect("semantic input order must not affect candidate facts");

    assert_eq!(first, replay);
    assert_eq!(first.descriptor, shuffled.descriptor);
    assert_eq!(first.bundle, shuffled.bundle);
    assert_eq!(first.source_files, shuffled.source_files);
    assert_ne!(
        first.receipt.snapshot_file_sha256,
        shuffled.receipt.snapshot_file_sha256
    );
    assert_eq!(first.descriptor.kind, AdapterKindV1::LspSnapshot);
    assert_eq!(first.descriptor.adapter_version, "2026-08-24");
    assert_eq!(first.descriptor.schema_sha256, LSP_SNAPSHOT_SCHEMA_SHA256);
    assert_eq!(first.descriptor.source_commit, PRODUCER_COMMIT);
    assert_eq!(first.descriptor.license, "MIT OR Apache-2.0");
    assert_eq!(first.receipt.producer_config_sha256, PRODUCER_CONFIG_SHA256);
    assert_eq!(first.receipt.protocol_version, LSP_PROTOCOL_VERSION);
    assert_eq!(first.receipt.position_encoding, POSITION_ENCODING);
    assert_eq!(first.bundle.source_snapshot_sha256, SOURCE_SNAPSHOT_SHA256);
    assert_eq!(first.bundle.nodes.len(), 3);
    assert_eq!(first.bundle.edges.len(), 1);
    assert_eq!(first.bundle.evidence.len(), 6);
    assert_eq!(first.bundle.discovered_count, 4);
    assert_eq!(first.bundle.admitted_count, 4);
    assert_eq!(first.bundle.omitted_count, 0);
    assert!(first.bundle.omissions.is_empty());
    assert_eq!(
        first.bundle.discovered_count,
        first.bundle.admitted_count + first.bundle.omitted_count
    );
    assert!(
        first
            .bundle
            .nodes
            .windows(2)
            .all(|pair| pair[0].node_id < pair[1].node_id)
    );
    assert!(
        first
            .bundle
            .evidence
            .windows(2)
            .all(|pair| pair[0].evidence_id < pair[1].evidence_id)
    );
    assert!(first.receipt.validate().is_ok());
}

#[test]
fn a03_preserves_symbols_utf8_ranges_diagnostics_and_a00_boundary() {
    let imported = import_pinned_lsp_snapshot_json_file_v1(
        &fixture("valid-lsp-snapshot.json"),
        &pin(VALID_FILE_SHA256),
    )
    .expect("valid frozen LSP snapshot must import");

    let names = imported
        .bundle
        .nodes
        .iter()
        .map(|node| node.name.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        names,
        BTreeSet::from([
            "helper",
            "main",
            "non_ascii_literal: non-ASCII literal retained in frozen evidence",
        ])
    );
    assert!(imported.bundle.nodes.iter().all(|node| {
        node.candidate_state == CandidateFactStateV1::CandidateExternal
            && node.trust_state == FactTrustStateV1::Extracted
            && !node.evidence_ids.is_empty()
    }));

    let relationship = &imported.bundle.edges[0];
    assert_eq!(relationship.edge_kind, "lsp.call");
    assert_eq!(relationship.target_reference, "helper");
    assert_eq!(relationship.candidate_node_ids.len(), 1);
    assert_eq!(
        relationship.candidate_state,
        CandidateFactStateV1::CandidateExternal
    );
    assert_eq!(relationship.trust_state, FactTrustStateV1::Extracted);

    let mut readback = Vec::new();
    for evidence in &imported.bundle.evidence {
        let source = &imported.source_files[&evidence.source_logical_path];
        let start = usize::try_from(evidence.byte_start).unwrap();
        let end = usize::try_from(evidence.byte_end).unwrap();
        let snippet = &source[start..end];
        assert_eq!(sha256(source), evidence.source_bytes_sha256);
        assert_eq!(sha256(snippet), evidence.snippet_sha256);
        readback.push(std::str::from_utf8(snippet).unwrap().to_owned());
    }
    assert_eq!(readback.len(), 6);
    assert!(readback.contains(&"fn main() {\n    helper(\"中文🙂\");\n}".to_owned()));
    assert!(readback.contains(&"fn helper(message: &str) {}".to_owned()));
    assert!(readback.contains(&"中文🙂".to_owned()));
    assert_eq!(
        readback
            .iter()
            .filter(|item| item.as_str() == "helper")
            .count(),
        2
    );

    let verified = verify_external_fact_bundle_v1(
        &imported.descriptor,
        &imported.descriptor,
        &imported.bundle,
        &imported.source_files,
        "gtkg.verifier/a03",
    )
    .expect("A00 exact source replay must consume A03 candidates");
    assert_eq!(verified.false_confirmed, 0);
    assert_eq!(verified.canonical_write_count, 0);
    assert_eq!(verified.resolved_verified_fact_ids.len(), 4);
}

#[test]
fn a03_rejects_live_and_nondeterministic_lsp_responses() {
    let live = import_pinned_lsp_snapshot_json_file_v1(
        &fixture("live-response-lsp-snapshot.json"),
        &pin(LIVE_RESPONSE_FILE_SHA256),
    )
    .unwrap_err();
    assert_eq!(live.code(), "E_LSP_LIVE_RESPONSE_REJECTED");

    let nondeterministic = import_pinned_lsp_snapshot_json_file_v1(
        &fixture("nondeterministic-lsp-snapshot.json"),
        &pin(NONDETERMINISTIC_FILE_SHA256),
    )
    .unwrap_err();
    assert_eq!(nondeterministic.code(), "E_LSP_NONDETERMINISTIC_SNAPSHOT");
}

#[test]
fn a03_rejects_range_schema_source_and_file_tamper_fail_closed() {
    let invalid_range = import_pinned_lsp_snapshot_json_file_v1(
        &fixture("invalid-range-lsp-snapshot.json"),
        &pin(INVALID_RANGE_FILE_SHA256),
    )
    .unwrap_err();
    assert_eq!(invalid_range.code(), "E_LSP_RANGE_INVALID");

    let schema_drift = import_pinned_lsp_snapshot_json_file_v1(
        &fixture("schema-drift-lsp-snapshot.json"),
        &pin(SCHEMA_DRIFT_FILE_SHA256),
    )
    .unwrap_err();
    assert_eq!(schema_drift.code(), "E_LSP_SCHEMA_UNSUPPORTED");

    let source_tampered = import_pinned_lsp_snapshot_json_file_v1(
        &fixture("source-tampered-lsp-snapshot.json"),
        &pin(SOURCE_TAMPERED_FILE_SHA256),
    )
    .unwrap_err();
    assert_eq!(source_tampered.code(), "E_LSP_SOURCE_TAMPERED");

    let file_tampered = import_pinned_lsp_snapshot_json_file_v1(
        &fixture("valid-lsp-snapshot-shuffled.json"),
        &pin(VALID_FILE_SHA256),
    )
    .unwrap_err();
    assert_eq!(file_tampered.code(), "E_LSP_PIN_MISMATCH");
}

#[test]
fn a03_binds_protocol_producer_config_schema_source_and_position_encoding() {
    let path = fixture("valid-lsp-snapshot.json");
    let mut mismatches = Vec::new();

    let mut changed = pin(VALID_FILE_SHA256);
    changed.producer_name = "other-lsp".to_owned();
    mismatches.push(changed);

    let mut changed = pin(VALID_FILE_SHA256);
    changed.producer_version = "latest".to_owned();
    mismatches.push(changed);

    let mut changed = pin(VALID_FILE_SHA256);
    changed.producer_commit = "1123456789abcdef0123456789abcdef01234567".to_owned();
    mismatches.push(changed);

    let mut changed = pin(VALID_FILE_SHA256);
    changed.producer_license = "Apache-2.0".to_owned();
    mismatches.push(changed);

    let mut changed = pin(VALID_FILE_SHA256);
    changed.producer_config_sha256 =
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned();
    mismatches.push(changed);

    let mut changed = pin(VALID_FILE_SHA256);
    changed.schema_sha256 =
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned();
    mismatches.push(changed);

    let mut changed = pin(VALID_FILE_SHA256);
    changed.source_snapshot_sha256 =
        "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_owned();
    mismatches.push(changed);

    for mismatch in mismatches {
        let error = import_pinned_lsp_snapshot_json_file_v1(&path, &mismatch).unwrap_err();
        assert_eq!(error.code(), "E_LSP_PIN_MISMATCH");
    }

    let mut protocol_drift = pin(VALID_FILE_SHA256);
    protocol_drift.protocol_version = "3.18".to_owned();
    let error = import_pinned_lsp_snapshot_json_file_v1(&path, &protocol_drift).unwrap_err();
    assert_eq!(error.code(), "E_LSP_PROTOCOL_UNSUPPORTED");

    let mut unsupported_encoding = pin(VALID_FILE_SHA256);
    unsupported_encoding.position_encoding = "utf-16".to_owned();
    let error = import_pinned_lsp_snapshot_json_file_v1(&path, &unsupported_encoding).unwrap_err();
    assert_eq!(error.code(), "E_LSP_POSITION_ENCODING_UNSUPPORTED");
}

#[test]
fn a03_file_adapter_reports_zero_daemon_process_network_and_write_effects() {
    let path = fixture("valid-lsp-snapshot.json");
    let before = std::fs::read(&path).unwrap();
    let imported = import_pinned_lsp_snapshot_json_file_v1(&path, &pin(VALID_FILE_SHA256)).unwrap();
    let after = std::fs::read(&path).unwrap();

    assert_eq!(before, after);
    assert_eq!(imported.receipt.lsp_server_invocation_count, 0);
    assert_eq!(imported.receipt.json_rpc_request_count, 0);
    assert_eq!(imported.receipt.json_rpc_response_count, 0);
    assert_eq!(imported.receipt.target_execution_count, 0);
    assert_eq!(imported.receipt.network_call_count, 0);
    assert_eq!(imported.receipt.write_count, 0);
    assert_eq!(imported.receipt.canonical_write_count, 0);
    assert_eq!(imported.receipt.document_count, 1);
    assert_eq!(imported.receipt.symbol_count, 2);
    assert_eq!(imported.receipt.diagnostic_count, 1);
    assert_eq!(imported.receipt.relationship_count, 1);
    assert_eq!(imported.receipt.source_range_count, 6);

    let mut tampered_receipt = imported.receipt;
    tampered_receipt.write_count = 1;
    assert_eq!(
        tampered_receipt.validate().unwrap_err().code(),
        "E_LSP_RECEIPT_INVALID"
    );
}

#[cfg(unix)]
#[test]
fn a03_rejects_symlinked_snapshot_input_before_readback() {
    use std::os::unix::fs::symlink;

    let temporary = tempfile::tempdir().unwrap();
    let link = temporary.path().join("snapshot.lsp.json");
    symlink(fixture("valid-lsp-snapshot.json"), &link).unwrap();
    let error =
        import_pinned_lsp_snapshot_json_file_v1(&link, &pin(VALID_FILE_SHA256)).unwrap_err();
    assert_eq!(error.code(), "E_LSP_FILE_INVALID");
}
