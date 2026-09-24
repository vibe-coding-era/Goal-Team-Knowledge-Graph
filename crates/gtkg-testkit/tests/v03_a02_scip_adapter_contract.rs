use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use gtkg_core::v03::adapter::scip::{ScipFilePinV1, import_pinned_scip_json_file_v1};
use gtkg_core::v03::adapter::verify_external_fact_bundle_v1;
use gtkg_protocol::v03::AdapterKindV1;
use gtkg_protocol::v03::adapter::{CandidateFactStateV1, FactTrustStateV1};
use sha2::{Digest, Sha256};

const SCIP_SCHEMA_VERSION: &str = "scip/0.4-json";
const SCIP_SCHEMA_SHA256: &str =
    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SCIP_TOOL_COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
const SOURCE_SNAPSHOT_SHA256: &str =
    "sha256:7a516a066420d92c5b10da8f76f5e8eccf1dd1250d425879dab88f3af4654a20";
const VALID_FILE_SHA256: &str =
    "sha256:6c1aa34317015297620f517829cbbe1105765f28897a2f3f87c5a622d5672fce";
const SHUFFLED_FILE_SHA256: &str =
    "sha256:9e4cd63ab2c9ad5c21e7f0e65399ab2bb03c735c207a43cb8635bf95f3dea40a";
const INVALID_RANGE_FILE_SHA256: &str =
    "sha256:767b875675553a22701db41b122f86d22c81d053fbf19c3fcf99c95e0a84a0b0";
const UNKNOWN_RELATION_FILE_SHA256: &str =
    "sha256:8515df0974645901ee2ba82433b6260fc3e89d13ade1d08742db8e867784fa5b";
const SCHEMA_DRIFT_FILE_SHA256: &str =
    "sha256:c9c316ecb52627b7d13418554ec5e3cc43732100503850bf600450737d3bfaab";

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures/v03_a02")
        .join(name)
}

fn pin(file_sha256: &str) -> ScipFilePinV1 {
    ScipFilePinV1 {
        file_sha256: file_sha256.to_owned(),
        schema_version: SCIP_SCHEMA_VERSION.to_owned(),
        schema_sha256: SCIP_SCHEMA_SHA256.to_owned(),
        tool_name: "scip-rust".to_owned(),
        tool_version: "0.3.3".to_owned(),
        tool_commit: SCIP_TOOL_COMMIT.to_owned(),
        tool_license: "Apache-2.0".to_owned(),
        source_snapshot_sha256: SOURCE_SNAPSHOT_SHA256.to_owned(),
        max_file_bytes: 64 * 1024,
    }
}

fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

#[test]
fn a02_pinned_scip_json_import_is_deterministic_across_input_order() {
    let first =
        import_pinned_scip_json_file_v1(&fixture("valid-scip.json"), &pin(VALID_FILE_SHA256))
            .expect("the exact pinned SCIP JSON fixture must import");
    let replay =
        import_pinned_scip_json_file_v1(&fixture("valid-scip.json"), &pin(VALID_FILE_SHA256))
            .expect("replaying identical bytes must import");
    let shuffled = import_pinned_scip_json_file_v1(
        &fixture("valid-scip-shuffled.json"),
        &pin(SHUFFLED_FILE_SHA256),
    )
    .expect("semantic input order must not affect candidate facts");

    assert_eq!(first, replay);
    assert_eq!(first.descriptor, shuffled.descriptor);
    assert_eq!(first.bundle, shuffled.bundle);
    assert_eq!(first.source_files, shuffled.source_files);
    assert_ne!(
        first.receipt.scip_file_sha256,
        shuffled.receipt.scip_file_sha256
    );
    assert_eq!(first.descriptor.kind, AdapterKindV1::Scip);
    assert_eq!(first.descriptor.adapter_version, "0.3.3");
    assert_eq!(first.descriptor.schema_sha256, SCIP_SCHEMA_SHA256);
    assert_eq!(first.descriptor.source_commit, SCIP_TOOL_COMMIT);
    assert_eq!(first.descriptor.license, "Apache-2.0");
    assert_eq!(first.bundle.source_snapshot_sha256, SOURCE_SNAPSHOT_SHA256);
    assert_eq!(first.bundle.nodes.len(), 2);
    assert_eq!(first.bundle.edges.len(), 1);
    assert_eq!(first.bundle.discovered_count, 3);
    assert_eq!(first.bundle.admitted_count, 3);
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
    assert!(
        first
            .bundle
            .nodes
            .iter()
            .all(|node| node.node_id.starts_with("scip-node-"))
    );
    assert!(
        first
            .bundle
            .edges
            .iter()
            .all(|edge| edge.edge_id.starts_with("scip-edge-"))
    );
    assert!(first.receipt.validate().is_ok());
}

#[test]
fn a02_preserves_symbols_source_ranges_and_relationship_candidates() {
    let imported =
        import_pinned_scip_json_file_v1(&fixture("valid-scip.json"), &pin(VALID_FILE_SHA256))
            .expect("valid pinned SCIP JSON must import");

    let names = imported
        .bundle
        .nodes
        .iter()
        .map(|node| node.name.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(names, BTreeSet::from(["helper", "run"]));
    assert!(imported.bundle.nodes.iter().all(|node| {
        node.candidate_state == CandidateFactStateV1::CandidateExternal
            && node.trust_state == FactTrustStateV1::Extracted
            && !node.evidence_ids.is_empty()
    }));

    let relationship = &imported.bundle.edges[0];
    assert_eq!(relationship.edge_kind, "scip.reference");
    assert_eq!(
        relationship.target_reference,
        "rust cargo demo 0.1.0 lib/helper()."
    );
    assert_eq!(relationship.candidate_node_ids.len(), 1);
    assert_eq!(
        relationship.candidate_state,
        CandidateFactStateV1::CandidateExternal
    );
    assert_eq!(relationship.trust_state, FactTrustStateV1::Extracted);

    let mut readback = BTreeSet::new();
    for evidence in &imported.bundle.evidence {
        let source = &imported.source_files[&evidence.source_logical_path];
        let start = usize::try_from(evidence.byte_start).unwrap();
        let end = usize::try_from(evidence.byte_end).unwrap();
        let snippet = &source[start..end];
        assert_eq!(sha256(source), evidence.source_bytes_sha256);
        assert_eq!(sha256(snippet), evidence.snippet_sha256);
        readback.insert(std::str::from_utf8(snippet).unwrap().to_owned());
    }
    assert_eq!(
        readback,
        BTreeSet::from(["helper".to_owned(), "pub fn run".to_owned()])
    );

    let verified = verify_external_fact_bundle_v1(
        &imported.descriptor,
        &imported.descriptor,
        &imported.bundle,
        &imported.source_files,
        "gtkg.verifier/a02",
    )
    .expect("A00 exact source replay must consume the A02 candidate bundle");
    assert_eq!(verified.false_confirmed, 0);
    assert_eq!(verified.canonical_write_count, 0);
    assert_eq!(verified.resolved_verified_fact_ids.len(), 3);
}

#[test]
fn a02_rejects_range_schema_tamper_and_unknown_relationship_fail_closed() {
    let invalid_range = import_pinned_scip_json_file_v1(
        &fixture("invalid-range-scip.json"),
        &pin(INVALID_RANGE_FILE_SHA256),
    )
    .unwrap_err();
    assert_eq!(invalid_range.code(), "E_SCIP_RANGE_INVALID");

    let schema_drift = import_pinned_scip_json_file_v1(
        &fixture("schema-drift-scip.json"),
        &pin(SCHEMA_DRIFT_FILE_SHA256),
    )
    .unwrap_err();
    assert_eq!(schema_drift.code(), "E_SCIP_SCHEMA_UNSUPPORTED");

    let unknown_relationship = import_pinned_scip_json_file_v1(
        &fixture("unknown-relation-scip.json"),
        &pin(UNKNOWN_RELATION_FILE_SHA256),
    )
    .unwrap_err();
    assert_eq!(unknown_relationship.code(), "E_SCIP_RELATION_UNSUPPORTED");

    let tampered = import_pinned_scip_json_file_v1(
        &fixture("valid-scip-shuffled.json"),
        &pin(VALID_FILE_SHA256),
    )
    .unwrap_err();
    assert_eq!(tampered.code(), "E_SCIP_PIN_MISMATCH");
}

#[test]
fn a02_binds_tool_commit_license_schema_and_source_identity() {
    let path = fixture("valid-scip.json");
    let mut mismatches = Vec::new();

    let mut changed = pin(VALID_FILE_SHA256);
    changed.tool_name = "other-scip".to_owned();
    mismatches.push(changed);

    let mut changed = pin(VALID_FILE_SHA256);
    changed.tool_version = "0.3.4".to_owned();
    mismatches.push(changed);

    let mut changed = pin(VALID_FILE_SHA256);
    changed.tool_commit = "1123456789abcdef0123456789abcdef01234567".to_owned();
    mismatches.push(changed);

    let mut changed = pin(VALID_FILE_SHA256);
    changed.tool_license = "MIT".to_owned();
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
        let error = import_pinned_scip_json_file_v1(&path, &mismatch).unwrap_err();
        assert_eq!(error.code(), "E_SCIP_PIN_MISMATCH");
    }
}

#[test]
fn a02_file_adapter_reports_zero_execution_network_and_write_effects() {
    let path = fixture("valid-scip.json");
    let before = std::fs::read(&path).unwrap();
    let imported = import_pinned_scip_json_file_v1(&path, &pin(VALID_FILE_SHA256)).unwrap();
    let after = std::fs::read(&path).unwrap();

    assert_eq!(before, after);
    assert_eq!(imported.receipt.target_execution_count, 0);
    assert_eq!(imported.receipt.network_call_count, 0);
    assert_eq!(imported.receipt.write_count, 0);
    assert_eq!(imported.receipt.canonical_write_count, 0);
    assert_eq!(imported.receipt.document_count, 1);
    assert_eq!(imported.receipt.symbol_count, 2);
    assert_eq!(imported.receipt.relationship_count, 1);
}

#[cfg(unix)]
#[test]
fn a02_rejects_symlinked_scip_input_before_readback() {
    use std::os::unix::fs::symlink;

    let temporary = tempfile::tempdir().unwrap();
    let link = temporary.path().join("index.scip.json");
    symlink(fixture("valid-scip.json"), &link).unwrap();
    let error = import_pinned_scip_json_file_v1(&link, &pin(VALID_FILE_SHA256)).unwrap_err();
    assert_eq!(error.code(), "E_SCIP_FILE_INVALID");
}
