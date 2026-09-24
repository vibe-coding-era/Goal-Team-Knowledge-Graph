use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use gtkg_core::v03::adapter::graphify::{
    GRAPHIFY_GRAPH_SCHEMA_SHA256_V1, GRAPHIFY_PINNED_COMMIT_V1, GRAPHIFY_PINNED_LICENSE_V1,
    GRAPHIFY_PINNED_VERSION_V1, GraphifyGraphPinV1, import_pinned_graphify_json_file_v1,
};
use gtkg_core::v03::adapter::verify_external_fact_bundle_v1;
use gtkg_protocol::v03::AdapterKindV1;
use gtkg_protocol::v03::adapter::{CandidateFactStateV1, FactTrustStateV1, VerifiedResolutionV1};
use sha2::{Digest, Sha256};

const SOURCE_SNAPSHOT_SHA256: &str =
    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const SOURCE_REPOSITORY_COMMIT: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const VALID_FILE_SHA256: &str =
    "sha256:7cd7b7301c37d0cc37e19201a9be3db9d4f9606ff4a8016ff085fe6494222e05";
const SHUFFLED_FILE_SHA256: &str =
    "sha256:a28d370119e01a9dde8f49ac9a9cc1a06e1258f95e005894f340a986adf1778c";
const SCHEMA_DRIFT_FILE_SHA256: &str =
    "sha256:3a6a6ff7ded4fe5264b656001980ab7190046a623b6e4a1c141b699640bff9a4";
const CONFIDENCE_DRIFT_FILE_SHA256: &str =
    "sha256:f139faa8c44fe684fa83cba1b354a3f08ebd5428eed8a6ad3bc860857d145adb";
const DANGLING_FILE_SHA256: &str =
    "sha256:d93f8cd962156e66bcafdf17eff3c385ab6def932b01f9ea7d6051f50e67c1d4";
const DUPLICATE_FILE_SHA256: &str =
    "sha256:c5ae3489237f0f8e7868b398c00df2db62afe0204d3cc0d4b9574d7d4e08aad1";

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures/v03_a05")
        .join(name)
}

fn pin(file_sha256: &str) -> GraphifyGraphPinV1 {
    GraphifyGraphPinV1 {
        file_sha256: file_sha256.to_owned(),
        schema_sha256: GRAPHIFY_GRAPH_SCHEMA_SHA256_V1.to_owned(),
        tool_version: GRAPHIFY_PINNED_VERSION_V1.to_owned(),
        tool_commit: GRAPHIFY_PINNED_COMMIT_V1.to_owned(),
        tool_license: GRAPHIFY_PINNED_LICENSE_V1.to_owned(),
        source_snapshot_sha256: SOURCE_SNAPSHOT_SHA256.to_owned(),
        source_repository_commit: SOURCE_REPOSITORY_COMMIT.to_owned(),
        max_file_bytes: 64 * 1024,
        max_node_count: 64,
        max_link_count: 64,
        max_hyperedge_count: 16,
    }
}

fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

#[test]
fn a05_binds_graphify_0952_graph_json_and_closes_the_denominator() {
    assert_eq!(
        GRAPHIFY_GRAPH_SCHEMA_SHA256_V1,
        "sha256:eeaf28766aaac19841e6a98c686fde9227598d60d3db1e9262b627feed6dd715"
    );
    let imported = import_pinned_graphify_json_file_v1(
        &fixture("valid-graphify.json"),
        &pin(VALID_FILE_SHA256),
    )
    .expect("the exact Graphify v0.9.52 graph.json must import offline");

    assert_eq!(imported.descriptor.kind, AdapterKindV1::GraphifyExport);
    assert_eq!(
        imported.descriptor.adapter_version,
        GRAPHIFY_PINNED_VERSION_V1
    );
    assert_eq!(imported.descriptor.source_commit, GRAPHIFY_PINNED_COMMIT_V1);
    assert_eq!(imported.descriptor.license, GRAPHIFY_PINNED_LICENSE_V1);
    assert_eq!(
        imported.descriptor.schema_sha256,
        GRAPHIFY_GRAPH_SCHEMA_SHA256_V1
    );
    assert_eq!(imported.bundle.nodes.len(), 4);
    assert_eq!(imported.bundle.edges.len(), 4);
    assert_eq!(imported.bundle.discovered_count, 9);
    assert_eq!(imported.bundle.admitted_count, 8);
    assert_eq!(imported.bundle.omitted_count, 1);
    assert_eq!(imported.bundle.omissions.len(), 1);
    assert_eq!(
        imported.bundle.omissions[0].reason,
        "graphify_hyperedge_inferred_not_representable_v1"
    );
    assert_eq!(
        imported.bundle.discovered_count,
        imported.bundle.admitted_count + imported.bundle.omitted_count
    );
    assert!(imported.receipt.validate().is_ok());
}

#[test]
fn a05_preserves_extracted_inferred_and_ambiguous_without_trust_laundering() {
    let imported = import_pinned_graphify_json_file_v1(
        &fixture("valid-graphify.json"),
        &pin(VALID_FILE_SHA256),
    )
    .unwrap();
    let edges = imported
        .bundle
        .edges
        .iter()
        .map(|edge| (edge.edge_kind.as_str(), edge))
        .collect::<BTreeMap<_, _>>();

    assert_eq!(
        edges["graphify.calls"].candidate_state,
        CandidateFactStateV1::CandidateExternal
    );
    assert_eq!(
        edges["graphify.calls"].trust_state,
        FactTrustStateV1::Extracted
    );
    assert_eq!(
        edges["graphify.implements"].candidate_state,
        CandidateFactStateV1::CandidateExternal
    );
    assert_eq!(
        edges["graphify.implements"].trust_state,
        FactTrustStateV1::Inferred
    );
    assert_eq!(
        edges["graphify.references"].candidate_state,
        CandidateFactStateV1::Ambiguous
    );
    assert_eq!(
        edges["graphify.references"].trust_state,
        FactTrustStateV1::Ambiguous
    );
    assert_eq!(
        edges["graphify.imports"].candidate_state,
        CandidateFactStateV1::LocatorOnly
    );
    assert_eq!(
        edges["graphify.imports"].trust_state,
        FactTrustStateV1::Extracted
    );
    assert!(imported.bundle.evidence.is_empty());
    assert!(imported.source_files.is_empty());
    assert!(
        imported
            .bundle
            .edges
            .iter()
            .all(|edge| edge.evidence_ids.is_empty())
    );
    assert_eq!(imported.source_locators.len(), 4);

    let verification = verify_external_fact_bundle_v1(
        &imported.descriptor,
        &imported.descriptor,
        &imported.bundle,
        &imported.source_files,
        "gtkg.verifier/a05",
    )
    .expect("Graphify confidence remains candidate-only without exact source bytes");
    assert_eq!(verification.false_confirmed, 0);
    assert_eq!(verification.canonical_write_count, 0);
    assert!(verification.resolved_verified_fact_ids.is_empty());
    assert!(verification.receipts.iter().all(|receipt| {
        receipt.resolution == VerifiedResolutionV1::LocatorOnly
            && receipt.reason == "missing_evidence"
    }));
}

#[test]
fn a05_source_location_controls_candidate_vs_locator_only_mapping() {
    let imported = import_pinned_graphify_json_file_v1(
        &fixture("valid-graphify.json"),
        &pin(VALID_FILE_SHA256),
    )
    .unwrap();
    let nodes = imported
        .bundle
        .nodes
        .iter()
        .map(|node| (node.name.as_str(), node))
        .collect::<BTreeMap<_, _>>();

    assert_eq!(
        nodes["main"].candidate_state,
        CandidateFactStateV1::CandidateExternal
    );
    assert_eq!(nodes["main"].trust_state, FactTrustStateV1::Unverified);
    assert_eq!(
        nodes["module.rs"].candidate_state,
        CandidateFactStateV1::LocatorOnly
    );
    assert_eq!(
        nodes["authentication"].candidate_state,
        CandidateFactStateV1::LocatorOnly
    );
    assert_eq!(imported.receipt.source_locator_count, 4);
    assert_eq!(imported.receipt.missing_source_location_count, 4);
    assert_eq!(imported.receipt.locator_only_count, 3);
}

#[test]
fn a05_normalization_is_deterministic_across_json_and_array_order() {
    let first = import_pinned_graphify_json_file_v1(
        &fixture("valid-graphify.json"),
        &pin(VALID_FILE_SHA256),
    )
    .unwrap();
    let replay = import_pinned_graphify_json_file_v1(
        &fixture("valid-graphify.json"),
        &pin(VALID_FILE_SHA256),
    )
    .unwrap();
    let shuffled = import_pinned_graphify_json_file_v1(
        &fixture("valid-graphify-shuffled.json"),
        &pin(SHUFFLED_FILE_SHA256),
    )
    .unwrap();

    assert_eq!(first, replay);
    assert_eq!(first.descriptor, shuffled.descriptor);
    assert_eq!(first.bundle, shuffled.bundle);
    assert_eq!(first.source_locators, shuffled.source_locators);
    assert_ne!(
        first.receipt.graphify_file_sha256,
        shuffled.receipt.graphify_file_sha256
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
}

#[test]
fn a05_rejects_tool_schema_license_source_and_file_identity_drift() {
    let path = fixture("valid-graphify.json");
    let mut mismatches = Vec::new();

    let mut changed = pin(VALID_FILE_SHA256);
    changed.tool_version = "0.9.53".to_owned();
    mismatches.push(changed);

    let mut changed = pin(VALID_FILE_SHA256);
    changed.tool_commit = "780e3ed8edd3dc1fa1961050912941880b778207".to_owned();
    mismatches.push(changed);

    let mut changed = pin(VALID_FILE_SHA256);
    changed.tool_license = "MIT".to_owned();
    mismatches.push(changed);

    let mut changed = pin(VALID_FILE_SHA256);
    changed.schema_sha256 =
        "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_owned();
    mismatches.push(changed);

    let mut changed = pin(VALID_FILE_SHA256);
    changed.source_snapshot_sha256 = "sha256:not-a-digest".to_owned();
    mismatches.push(changed);

    for mismatch in mismatches {
        let error = import_pinned_graphify_json_file_v1(&path, &mismatch).unwrap_err();
        assert_eq!(error.code(), "E_GRAPHIFY_PIN_MISMATCH");
    }

    let mut source_drift = pin(VALID_FILE_SHA256);
    source_drift.source_repository_commit = "cccccccccccccccccccccccccccccccccccccccc".to_owned();
    let error = import_pinned_graphify_json_file_v1(&path, &source_drift).unwrap_err();
    assert_eq!(error.code(), "E_GRAPHIFY_SOURCE_IDENTITY_MISMATCH");

    let tampered = import_pinned_graphify_json_file_v1(
        &fixture("valid-graphify-shuffled.json"),
        &pin(VALID_FILE_SHA256),
    )
    .unwrap_err();
    assert_eq!(tampered.code(), "E_GRAPHIFY_PIN_MISMATCH");
}

#[test]
fn a05_rejects_schema_confidence_dangling_and_duplicate_drift_fail_closed() {
    let schema = import_pinned_graphify_json_file_v1(
        &fixture("schema-drift-graphify.json"),
        &pin(SCHEMA_DRIFT_FILE_SHA256),
    )
    .unwrap_err();
    assert_eq!(schema.code(), "E_GRAPHIFY_SCHEMA_UNSUPPORTED");

    let confidence = import_pinned_graphify_json_file_v1(
        &fixture("confidence-drift-graphify.json"),
        &pin(CONFIDENCE_DRIFT_FILE_SHA256),
    )
    .unwrap_err();
    assert_eq!(confidence.code(), "E_GRAPHIFY_CONFIDENCE_INVALID");

    let dangling = import_pinned_graphify_json_file_v1(
        &fixture("dangling-graphify.json"),
        &pin(DANGLING_FILE_SHA256),
    )
    .unwrap_err();
    assert_eq!(dangling.code(), "E_GRAPHIFY_GRAPH_INVALID");

    let duplicate = import_pinned_graphify_json_file_v1(
        &fixture("duplicate-graphify.json"),
        &pin(DUPLICATE_FILE_SHA256),
    )
    .unwrap_err();
    assert_eq!(duplicate.code(), "E_GRAPHIFY_GRAPH_INVALID");
}

#[test]
fn a05_is_one_read_file_only_and_has_no_canonical_authority() {
    let path = fixture("valid-graphify.json");
    let before = std::fs::read(&path).unwrap();
    assert_eq!(sha256(&before), VALID_FILE_SHA256);
    let imported = import_pinned_graphify_json_file_v1(&path, &pin(VALID_FILE_SHA256)).unwrap();
    let after = std::fs::read(&path).unwrap();

    assert_eq!(before, after);
    assert_eq!(imported.receipt.export_file_read_count, 1);
    assert_eq!(imported.receipt.node_count, 4);
    assert_eq!(imported.receipt.link_count, 4);
    assert_eq!(imported.receipt.hyperedge_count, 1);
    assert_eq!(imported.receipt.extracted_relationship_count, 2);
    assert_eq!(imported.receipt.inferred_relationship_count, 2);
    assert_eq!(imported.receipt.ambiguous_relationship_count, 1);
    assert_eq!(imported.receipt.target_execution_count, 0);
    assert_eq!(imported.receipt.network_call_count, 0);
    assert_eq!(imported.receipt.provider_call_count, 0);
    assert_eq!(imported.receipt.write_count, 0);
    assert_eq!(imported.receipt.canonical_write_count, 0);
}

#[cfg(unix)]
#[test]
fn a05_rejects_symlinked_graph_json_before_readback() {
    use std::os::unix::fs::symlink;

    let temporary = tempfile::tempdir().unwrap();
    let link = temporary.path().join("graph.json");
    symlink(fixture("valid-graphify.json"), &link).unwrap();
    let error = import_pinned_graphify_json_file_v1(&link, &pin(VALID_FILE_SHA256)).unwrap_err();
    assert_eq!(error.code(), "E_GRAPHIFY_FILE_INVALID");
}
