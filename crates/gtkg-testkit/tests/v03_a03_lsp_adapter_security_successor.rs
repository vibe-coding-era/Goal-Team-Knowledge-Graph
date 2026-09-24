use std::fs;
use std::path::{Path, PathBuf};

use gtkg_core::v03::adapter::lsp_snapshot::{
    LspSnapshotAdapterErrorV1, LspSnapshotFilePinV1, LspSnapshotImportV1,
    import_pinned_lsp_snapshot_json_file_v1,
};
use gtkg_core::v03::adapter::verify_external_fact_bundle_v1;
use gtkg_protocol::v03::adapter::{CandidateFactStateV1, FactTrustStateV1};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

const LSP_SNAPSHOT_SCHEMA_VERSION: &str = "gtkg.lsp-snapshot/v1";
const LSP_SNAPSHOT_SCHEMA_SHA256: &str =
    "sha256:97a36add17cb89ec94b92222e8c4b1673dbb5bd5443644f1f346140ad4dd19c1";
const PRODUCER_COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
const PRODUCER_CONFIG_SHA256: &str =
    "sha256:9569022226845a35bce92d52c125556785d8a1d67f6e78b900bb3dc02bac9228";
const SOURCE_SNAPSHOT_SHA256: &str =
    "sha256:c45839fdd713b1acb620523e6c9d80ac07fc271113cfad5eb76ef328045e6ddc";

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures/v03_a03")
        .join(name)
}

fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn pin(file_bytes: &[u8]) -> LspSnapshotFilePinV1 {
    LspSnapshotFilePinV1 {
        file_sha256: sha256(file_bytes),
        schema_version: LSP_SNAPSHOT_SCHEMA_VERSION.to_owned(),
        schema_sha256: LSP_SNAPSHOT_SCHEMA_SHA256.to_owned(),
        protocol_version: "3.17".to_owned(),
        position_encoding: "utf-8".to_owned(),
        producer_name: "rust-analyzer".to_owned(),
        producer_version: "2026-08-24".to_owned(),
        producer_commit: PRODUCER_COMMIT.to_owned(),
        producer_license: "MIT OR Apache-2.0".to_owned(),
        producer_config_sha256: PRODUCER_CONFIG_SHA256.to_owned(),
        source_snapshot_sha256: SOURCE_SNAPSHOT_SHA256.to_owned(),
        max_file_bytes: 64 * 1024,
    }
}

fn valid_json() -> Value {
    serde_json::from_slice(&fs::read(fixture("valid-lsp-snapshot.json")).unwrap()).unwrap()
}

fn write_snapshot(value: &Value) -> (TempDir, PathBuf, Vec<u8>) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("snapshot.json");
    let mut bytes = serde_json::to_vec_pretty(value).unwrap();
    bytes.push(b'\n');
    fs::write(&path, &bytes).unwrap();
    (directory, path, bytes)
}

fn import_value(value: &Value) -> Result<LspSnapshotImportV1, LspSnapshotAdapterErrorV1> {
    let (_directory, path, bytes) = write_snapshot(value);
    import_pinned_lsp_snapshot_json_file_v1(&path, &pin(&bytes))
}

fn reference_mut(value: &mut Value) -> &mut Value {
    &mut value["documents"][0]["symbols"][0]["references"][0]
}

#[test]
fn a03_successor_binds_relationship_text_to_target_and_source_symbol_range() {
    let imported = import_value(&valid_json()).expect("valid relationship must import");
    let edge = &imported.bundle.edges[0];
    let edge_evidence = imported
        .bundle
        .evidence
        .iter()
        .find(|item| item.evidence_id == edge.evidence_ids[0])
        .unwrap();
    let source = &imported.source_files[&edge_evidence.source_logical_path];
    let edge_start = usize::try_from(edge_evidence.byte_start).unwrap();
    let edge_end = usize::try_from(edge_evidence.byte_end).unwrap();
    assert_eq!(
        &source[edge_start..edge_end],
        edge.target_reference.as_bytes()
    );

    let source_node = imported
        .bundle
        .nodes
        .iter()
        .find(|node| node.node_id == edge.source_node_id)
        .unwrap();
    assert!(source_node.evidence_ids.iter().any(|evidence_id| {
        imported.bundle.evidence.iter().any(|item| {
            item.evidence_id == *evidence_id
                && item.byte_start <= edge_evidence.byte_start
                && item.byte_end >= edge_evidence.byte_end
        })
    }));

    let verified = verify_external_fact_bundle_v1(
        &imported.descriptor,
        &imported.descriptor,
        &imported.bundle,
        &imported.source_files,
        "gtkg.verifier/a03-successor",
    )
    .unwrap();
    assert_eq!(verified.false_confirmed, 0);

    let mut target_mismatch = valid_json();
    reference_mut(&mut target_mismatch)["range"] = json!([0, 3, 0, 7]);
    assert_eq!(
        import_value(&target_mismatch).unwrap_err().code(),
        "E_LSP_RANGE_INVALID"
    );

    let mut outside_source = valid_json();
    reference_mut(&mut outside_source)["range"] = json!([4, 3, 4, 9]);
    assert_eq!(
        import_value(&outside_source).unwrap_err().code(),
        "E_LSP_RANGE_INVALID"
    );
}

#[test]
fn a03_successor_rejects_oversize_symlink_and_hardlink_inputs() {
    let original = fs::read(fixture("valid-lsp-snapshot.json")).unwrap();
    let mut undersized_pin = pin(&original);
    undersized_pin.max_file_bytes = u64::try_from(original.len() - 1).unwrap();
    assert_eq!(
        import_pinned_lsp_snapshot_json_file_v1(
            &fixture("valid-lsp-snapshot.json"),
            &undersized_pin,
        )
        .unwrap_err()
        .code(),
        "E_LSP_FILE_INVALID"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let private = directory.path().join("private.json");
        let hardlink = directory.path().join("hardlink.json");
        let symlink_path = directory.path().join("symlink.json");
        fs::write(&private, &original).unwrap();
        fs::hard_link(&private, &hardlink).unwrap();
        symlink(&private, &symlink_path).unwrap();
        for path in [&private, &hardlink, &symlink_path] {
            assert_eq!(
                import_pinned_lsp_snapshot_json_file_v1(path, &pin(&original))
                    .unwrap_err()
                    .code(),
                "E_LSP_FILE_INVALID"
            );
        }
    }
}

#[test]
fn a03_successor_rejects_trimmed_floating_version_and_unknown_license() {
    for floating in [" latest ", " CURRENT\t", "\nhead "] {
        let mut changed = pin(b"{}");
        changed.producer_version = floating.to_owned();
        assert_eq!(changed.validate().unwrap_err().code(), "E_LSP_PIN_MISMATCH");
    }
    for unknown in [" unknown ", "\tUNKNOWN\n"] {
        let mut changed = pin(b"{}");
        changed.producer_license = unknown.to_owned();
        assert_eq!(changed.validate().unwrap_err().code(), "E_LSP_PIN_MISMATCH");
    }
}

#[test]
fn a03_successor_rejects_duplicate_documents_symbols_and_relationships() {
    let mut duplicate_document = valid_json();
    let document = duplicate_document["documents"][0].clone();
    duplicate_document["documents"]
        .as_array_mut()
        .unwrap()
        .push(document);
    assert_eq!(
        import_value(&duplicate_document).unwrap_err().code(),
        "E_LSP_BUNDLE_INVALID"
    );

    let mut duplicate_symbol = valid_json();
    let symbol = duplicate_symbol["documents"][0]["symbols"][0].clone();
    duplicate_symbol["documents"][0]["symbols"]
        .as_array_mut()
        .unwrap()
        .push(symbol);
    assert_eq!(
        import_value(&duplicate_symbol).unwrap_err().code(),
        "E_LSP_BUNDLE_INVALID"
    );

    let mut duplicate_relationship = valid_json();
    let relationship = reference_mut(&mut duplicate_relationship).clone();
    duplicate_relationship["documents"][0]["symbols"][0]["references"]
        .as_array_mut()
        .unwrap()
        .push(relationship);
    assert_eq!(
        import_value(&duplicate_relationship).unwrap_err().code(),
        "E_LSP_BUNDLE_INVALID"
    );
}

#[test]
fn a03_successor_preserves_dangling_partial_and_multi_target_uncertainty() {
    let cases = [
        (
            json!(["sym-missing"]),
            CandidateFactStateV1::LocatorOnly,
            FactTrustStateV1::Unverified,
        ),
        (
            json!(["sym-helper", "sym-missing"]),
            CandidateFactStateV1::Ambiguous,
            FactTrustStateV1::Ambiguous,
        ),
        (
            json!(["sym-helper", "sym-main"]),
            CandidateFactStateV1::Ambiguous,
            FactTrustStateV1::Ambiguous,
        ),
    ];

    for (target_ids, expected_state, expected_trust) in cases {
        let mut value = valid_json();
        reference_mut(&mut value)["target_symbol_ids"] = target_ids;
        let imported =
            import_value(&value).expect("uncertain relationship must remain a candidate");
        let edge = &imported.bundle.edges[0];
        assert_eq!(edge.candidate_state, expected_state);
        assert_eq!(edge.trust_state, expected_trust);
        assert_ne!(edge.trust_state, FactTrustStateV1::Extracted);

        let verified = verify_external_fact_bundle_v1(
            &imported.descriptor,
            &imported.descriptor,
            &imported.bundle,
            &imported.source_files,
            "gtkg.verifier/a03-successor-uncertain",
        )
        .unwrap();
        assert_eq!(verified.false_confirmed, 0);
        assert!(!verified.resolved_verified_fact_ids.contains(&edge.fact_id));
    }
}

#[test]
fn a03_successor_receipt_denominators_fail_closed_on_tamper() {
    let imported = import_value(&valid_json()).unwrap();
    let mut mutations = Vec::new();

    let mut changed = imported.receipt.clone();
    changed.document_count += 1;
    mutations.push(changed);

    let mut changed = imported.receipt.clone();
    changed.symbol_count += 1;
    mutations.push(changed);

    let mut changed = imported.receipt.clone();
    changed.relationship_count += 1;
    mutations.push(changed);

    let mut changed = imported.receipt.clone();
    changed.source_range_count += 1;
    mutations.push(changed);

    let mut changed = imported.receipt.clone();
    changed.discovered_count += 1;
    mutations.push(changed);

    let mut changed = imported.receipt;
    changed.admitted_count += 1;
    mutations.push(changed);

    for changed in mutations {
        assert_eq!(
            changed.validate().unwrap_err().code(),
            "E_LSP_RECEIPT_INVALID"
        );
    }
}
