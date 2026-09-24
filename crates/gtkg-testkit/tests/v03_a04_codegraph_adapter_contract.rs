use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use gtkg_core::v03::adapter::codegraph::{
    CODEGRAPH_EXPORT_SCHEMA_SHA256_V1, CODEGRAPH_PINNED_COMMIT_V1, CODEGRAPH_PINNED_LICENSE_V1,
    CODEGRAPH_PINNED_VERSION_V1, CodeGraphExportPinV1, import_pinned_codegraph_json_file_v1,
};
use gtkg_core::v03::adapter::verify_external_fact_bundle_v1;
use gtkg_protocol::v03::AdapterKindV1;
use gtkg_protocol::v03::adapter::{CandidateFactStateV1, FactTrustStateV1, VerifiedResolutionV1};
use sha2::{Digest, Sha256};

const SOURCE_SNAPSHOT_SHA256: &str =
    "sha256:7777777777777777777777777777777777777777777777777777777777777777";
const VALID_FILE_SHA256: &str =
    "sha256:66b2bc48661dc6348c2930afc8e368c71a5dd5bdfb580c911c726d4fed70842b";
const SHUFFLED_FILE_SHA256: &str =
    "sha256:048748d6f051b8ee9ddc9839989cf21bd61d2fb660b60c1c6869a0e6d3295518";
const DANGLING_FILE_SHA256: &str =
    "sha256:80ce040fbf9f4c49b023078c4d496e83155404b40eb703b9589978ef4886840d";
const DUPLICATE_FILE_SHA256: &str =
    "sha256:5a964b678279fff6536dc907aec40b3a2f97c6a7cb68a8e8408d86e90e77d246";
const SCHEMA_DRIFT_FILE_SHA256: &str =
    "sha256:0ab7ff2fe660af3326f3f9ec06d4b780c67098ec70d12f62564ad8e3d5bc1a4b";

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures/v03_a04")
        .join(name)
}

fn pin(file_sha256: &str) -> CodeGraphExportPinV1 {
    CodeGraphExportPinV1 {
        file_sha256: file_sha256.to_owned(),
        schema_sha256: CODEGRAPH_EXPORT_SCHEMA_SHA256_V1.to_owned(),
        tool_version: CODEGRAPH_PINNED_VERSION_V1.to_owned(),
        tool_commit: CODEGRAPH_PINNED_COMMIT_V1.to_owned(),
        tool_license: CODEGRAPH_PINNED_LICENSE_V1.to_owned(),
        source_snapshot_sha256: SOURCE_SNAPSHOT_SHA256.to_owned(),
        max_file_bytes: 64 * 1024,
    }
}

fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

#[test]
fn a04_binds_the_pinned_codegraph_community_export_identity() {
    let imported = import_pinned_codegraph_json_file_v1(
        &fixture("valid-codegraph.json"),
        &pin(VALID_FILE_SHA256),
    )
    .expect("the exact CodeGraph v0.20.1 community JSON export must import");

    assert_eq!(imported.descriptor.kind, AdapterKindV1::CodeGraphExport);
    assert_eq!(
        imported.descriptor.adapter_version,
        CODEGRAPH_PINNED_VERSION_V1
    );
    assert_eq!(
        imported.descriptor.source_commit,
        CODEGRAPH_PINNED_COMMIT_V1
    );
    assert_eq!(imported.descriptor.license, CODEGRAPH_PINNED_LICENSE_V1);
    assert_eq!(
        imported.descriptor.schema_sha256,
        CODEGRAPH_EXPORT_SCHEMA_SHA256_V1
    );
    assert_eq!(
        imported.bundle.source_snapshot_sha256,
        SOURCE_SNAPSHOT_SHA256
    );
    assert_eq!(imported.bundle.nodes.len(), 4);
    assert_eq!(imported.bundle.edges.len(), 4);
    assert_eq!(imported.bundle.discovered_count, 8);
    assert_eq!(imported.bundle.admitted_count, 8);
    assert_eq!(imported.bundle.omitted_count, 0);
    assert!(imported.bundle.omissions.is_empty());
    assert!(imported.receipt.validate().is_ok());
}

#[test]
fn a04_missing_source_bytes_never_upgrade_export_locators_to_verified_facts() {
    let imported = import_pinned_codegraph_json_file_v1(
        &fixture("valid-codegraph.json"),
        &pin(VALID_FILE_SHA256),
    )
    .unwrap();

    assert!(imported.bundle.evidence.is_empty());
    assert!(imported.source_files.is_empty());
    assert!(imported.bundle.nodes.iter().all(|node| {
        node.candidate_state == CandidateFactStateV1::LocatorOnly
            && node.trust_state == FactTrustStateV1::Unverified
            && node.evidence_ids.is_empty()
    }));
    assert!(imported.bundle.edges.iter().all(|edge| {
        edge.candidate_state == CandidateFactStateV1::LocatorOnly
            && edge.trust_state == FactTrustStateV1::Unverified
            && edge.evidence_ids.is_empty()
            && edge.candidate_node_ids.len() == 1
    }));
    assert_eq!(
        imported.bundle.candidate_states,
        vec![CandidateFactStateV1::LocatorOnly]
    );

    let verification = verify_external_fact_bundle_v1(
        &imported.descriptor,
        &imported.descriptor,
        &imported.bundle,
        &imported.source_files,
        "gtkg.verifier/a04",
    )
    .expect("A00 must consume CodeGraph locators without promoting them");
    assert_eq!(verification.false_confirmed, 0);
    assert_eq!(verification.canonical_write_count, 0);
    assert!(verification.resolved_verified_fact_ids.is_empty());
    assert!(verification.receipts.iter().all(|receipt| {
        receipt.resolution == VerifiedResolutionV1::LocatorOnly
            && receipt.reason == "missing_evidence"
    }));
}

#[test]
fn a04_normalization_is_deterministic_across_export_array_and_property_order() {
    let first = import_pinned_codegraph_json_file_v1(
        &fixture("valid-codegraph.json"),
        &pin(VALID_FILE_SHA256),
    )
    .unwrap();
    let replay = import_pinned_codegraph_json_file_v1(
        &fixture("valid-codegraph.json"),
        &pin(VALID_FILE_SHA256),
    )
    .unwrap();
    let shuffled = import_pinned_codegraph_json_file_v1(
        &fixture("valid-codegraph-shuffled.json"),
        &pin(SHUFFLED_FILE_SHA256),
    )
    .unwrap();

    assert_eq!(first, replay);
    assert_eq!(first.descriptor, shuffled.descriptor);
    assert_eq!(first.bundle, shuffled.bundle);
    assert_ne!(
        first.receipt.codegraph_file_sha256,
        shuffled.receipt.codegraph_file_sha256
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
            .edges
            .windows(2)
            .all(|pair| pair[0].edge_id < pair[1].edge_id)
    );

    let names = first
        .bundle
        .nodes
        .iter()
        .map(|node| node.name.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        names,
        BTreeSet::from(["helper", "main", "src/lib.rs", "src/main.rs"])
    );
}

#[test]
fn a04_rejects_identity_drift_tamper_and_non_official_schema_shape() {
    let path = fixture("valid-codegraph.json");
    let mut mismatches = Vec::new();

    let mut changed = pin(VALID_FILE_SHA256);
    changed.tool_version = "0.20.2".to_owned();
    mismatches.push(changed);

    let mut changed = pin(VALID_FILE_SHA256);
    changed.tool_commit = "589ccf1612555510f8367e3e673181f6a1275fe4".to_owned();
    mismatches.push(changed);

    let mut changed = pin(VALID_FILE_SHA256);
    changed.tool_license = "MIT".to_owned();
    mismatches.push(changed);

    let mut changed = pin(VALID_FILE_SHA256);
    changed.schema_sha256 =
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned();
    mismatches.push(changed);

    let mut changed = pin(VALID_FILE_SHA256);
    changed.source_snapshot_sha256 = "sha256:not-a-digest".to_owned();
    mismatches.push(changed);

    for mismatch in mismatches {
        let error = import_pinned_codegraph_json_file_v1(&path, &mismatch).unwrap_err();
        assert_eq!(error.code(), "E_CODEGRAPH_PIN_MISMATCH");
    }

    let tampered = import_pinned_codegraph_json_file_v1(
        &fixture("valid-codegraph-shuffled.json"),
        &pin(VALID_FILE_SHA256),
    )
    .unwrap_err();
    assert_eq!(tampered.code(), "E_CODEGRAPH_PIN_MISMATCH");

    let schema_drift = import_pinned_codegraph_json_file_v1(
        &fixture("schema-drift-codegraph.json"),
        &pin(SCHEMA_DRIFT_FILE_SHA256),
    )
    .unwrap_err();
    assert_eq!(schema_drift.code(), "E_CODEGRAPH_SCHEMA_UNSUPPORTED");
}

#[test]
fn a04_rejects_duplicate_and_dangling_export_graphs_fail_closed() {
    let duplicate = import_pinned_codegraph_json_file_v1(
        &fixture("duplicate-codegraph.json"),
        &pin(DUPLICATE_FILE_SHA256),
    )
    .unwrap_err();
    assert_eq!(duplicate.code(), "E_CODEGRAPH_GRAPH_INVALID");

    let dangling = import_pinned_codegraph_json_file_v1(
        &fixture("dangling-codegraph.json"),
        &pin(DANGLING_FILE_SHA256),
    )
    .unwrap_err();
    assert_eq!(dangling.code(), "E_CODEGRAPH_GRAPH_INVALID");
}

#[test]
fn a04_adapter_is_one_read_file_only_and_has_no_canonical_authority() {
    let path = fixture("valid-codegraph.json");
    let before = std::fs::read(&path).unwrap();
    assert_eq!(sha256(&before), VALID_FILE_SHA256);
    let imported = import_pinned_codegraph_json_file_v1(&path, &pin(VALID_FILE_SHA256)).unwrap();
    let after = std::fs::read(&path).unwrap();

    assert_eq!(before, after);
    assert_eq!(imported.receipt.export_file_read_count, 1);
    assert_eq!(imported.receipt.target_execution_count, 0);
    assert_eq!(imported.receipt.network_call_count, 0);
    assert_eq!(imported.receipt.write_count, 0);
    assert_eq!(imported.receipt.canonical_write_count, 0);
    assert_eq!(imported.receipt.source_evidence_count, 0);
    assert_eq!(imported.receipt.locator_only_count, 8);
}

#[cfg(unix)]
#[test]
fn a04_rejects_symlinked_export_before_readback() {
    use std::os::unix::fs::symlink;

    let temporary = tempfile::tempdir().unwrap();
    let link = temporary.path().join("codegraph.json");
    symlink(fixture("valid-codegraph.json"), &link).unwrap();
    let error = import_pinned_codegraph_json_file_v1(&link, &pin(VALID_FILE_SHA256)).unwrap_err();
    assert_eq!(error.code(), "E_CODEGRAPH_FILE_INVALID");
}
