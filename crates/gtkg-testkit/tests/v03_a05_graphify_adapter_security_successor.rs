use std::fs;
use std::path::{Path, PathBuf};

use gtkg_core::v03::adapter::graphify::{
    GRAPHIFY_CANONICAL_SCHEMA_SHA256_V2, GRAPHIFY_EXPORT_PY_SHA256_V2,
    GRAPHIFY_EXTRACTION_SPEC_SHA256_V2, GRAPHIFY_LICENSE_SHA256_V2, GRAPHIFY_PINNED_COMMIT_V1,
    GRAPHIFY_PINNED_LICENSE_V1, GRAPHIFY_PINNED_VERSION_V1, GRAPHIFY_PYPROJECT_SHA256_V2,
    GRAPHIFY_VALIDATE_PY_SHA256_V2, GraphifyAdapterErrorV1, GraphifyGraphPinV2, GraphifyImportV2,
    MAX_GRAPHIFY_BYTES_V1, import_pinned_graphify_json_file_v2,
};
use gtkg_core::v03::adapter::verify_external_fact_bundle_v1;
use gtkg_protocol::canonical_json_sha256;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

const SOURCE_SNAPSHOT_SHA256: &str =
    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const SOURCE_REPOSITORY_COMMIT: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const STRICT_FILE_SHA256: &str =
    "sha256:0e2e258daef9182ca2573c561bad47958a56f08a5e5b853ce71bcf9508e4edf0";
const LEGACY_MISMATCH_FILE_SHA256: &str =
    "sha256:7cd7b7301c37d0cc37e19201a9be3db9d4f9606ff4a8016ff085fe6494222e05";

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures/v03_a05")
        .join(name)
}

fn workspace(path: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(path)
}

fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn pin(file_sha256: &str) -> GraphifyGraphPinV2 {
    GraphifyGraphPinV2 {
        file_sha256: file_sha256.to_owned(),
        canonical_schema_sha256: GRAPHIFY_CANONICAL_SCHEMA_SHA256_V2.to_owned(),
        tool_version: GRAPHIFY_PINNED_VERSION_V1.to_owned(),
        tool_commit: GRAPHIFY_PINNED_COMMIT_V1.to_owned(),
        tool_license: GRAPHIFY_PINNED_LICENSE_V1.to_owned(),
        export_py_sha256: GRAPHIFY_EXPORT_PY_SHA256_V2.to_owned(),
        validate_py_sha256: GRAPHIFY_VALIDATE_PY_SHA256_V2.to_owned(),
        pyproject_sha256: GRAPHIFY_PYPROJECT_SHA256_V2.to_owned(),
        license_sha256: GRAPHIFY_LICENSE_SHA256_V2.to_owned(),
        extraction_spec_sha256: GRAPHIFY_EXTRACTION_SPEC_SHA256_V2.to_owned(),
        source_snapshot_sha256: SOURCE_SNAPSHOT_SHA256.to_owned(),
        source_repository_commit: SOURCE_REPOSITORY_COMMIT.to_owned(),
        max_file_bytes: 64 * 1024,
        max_node_count: 64,
        max_link_count: 64,
        max_hyperedge_count: 16,
    }
}

fn strict_json() -> Value {
    serde_json::from_slice(&fs::read(fixture("strict-graphify-v2.json")).unwrap()).unwrap()
}

fn write_json(value: &Value) -> (TempDir, PathBuf, Vec<u8>) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("graph.json");
    let mut bytes = serde_json::to_vec_pretty(value).unwrap();
    bytes.push(b'\n');
    fs::write(&path, &bytes).unwrap();
    (directory, path, bytes)
}

fn import_value(value: &Value) -> Result<GraphifyImportV2, GraphifyAdapterErrorV1> {
    let (_directory, path, bytes) = write_json(value);
    import_pinned_graphify_json_file_v2(&path, &pin(&sha256(&bytes)))
}

#[test]
fn a05_v2_binds_canonical_schema_to_five_exact_upstream_blobs() {
    assert!(MAX_GRAPHIFY_BYTES_V1 <= 64 * 1024 * 1024);
    let manifest: Value = serde_json::from_slice(
        &fs::read(workspace(
            "deliverables/v03-development/test-receipts/a05-upstream-pin.json",
        ))
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        canonical_json_sha256(&manifest["canonical_schema_material"]).unwrap(),
        GRAPHIFY_CANONICAL_SCHEMA_SHA256_V2
    );
    assert_eq!(
        manifest["canonical_schema_sha256"],
        json!(GRAPHIFY_CANONICAL_SCHEMA_SHA256_V2)
    );

    let blobs = &manifest["canonical_schema_material"]["upstream_blob_sha256"];
    assert_eq!(
        blobs["graphify/export.py"],
        json!(GRAPHIFY_EXPORT_PY_SHA256_V2)
    );
    assert_eq!(
        blobs["graphify/validate.py"],
        json!(GRAPHIFY_VALIDATE_PY_SHA256_V2)
    );
    assert_eq!(blobs["pyproject.toml"], json!(GRAPHIFY_PYPROJECT_SHA256_V2));
    assert_eq!(blobs["LICENSE"], json!(GRAPHIFY_LICENSE_SHA256_V2));
    assert_eq!(
        blobs["graphify/skills/codex/references/extraction-spec.md"],
        json!(GRAPHIFY_EXTRACTION_SPEC_SHA256_V2)
    );
}

#[test]
fn a05_v2_accepts_exact_dual_slots_and_one_or_two_member_hyperedges() {
    let imported = import_pinned_graphify_json_file_v2(
        &fixture("strict-graphify-v2.json"),
        &pin(STRICT_FILE_SHA256),
    )
    .expect("strict Graphify v2 fixture must import");

    assert_eq!(imported.receipt.node_count, 4);
    assert_eq!(imported.receipt.link_count, 4);
    assert_eq!(imported.receipt.hyperedge_count, 2);
    assert_eq!(imported.receipt.dual_slot_hyperedge_count, 2);
    assert_eq!(imported.receipt.discovered_count, 10);
    assert_eq!(imported.receipt.admitted_count, 8);
    assert_eq!(imported.receipt.omitted_count, 2);
    assert_eq!(imported.receipt.extracted_relationship_count, 3);
    assert_eq!(imported.receipt.inferred_relationship_count, 1);
    assert_eq!(imported.receipt.ambiguous_relationship_count, 2);
    assert_eq!(imported.receipt.source_locator_count, 4);
    assert_eq!(imported.receipt.missing_source_location_count, 4);
    assert_eq!(imported.receipt.locator_only_count, 3);
    assert!(imported.receipt.validate().is_ok());
}

#[test]
fn a05_v2_rejects_legacy_dual_slot_mismatch_and_unknown_root_fields() {
    let mismatch = import_pinned_graphify_json_file_v2(
        &fixture("valid-graphify.json"),
        &pin(LEGACY_MISMATCH_FILE_SHA256),
    )
    .unwrap_err();
    assert_eq!(mismatch.code(), "E_GRAPHIFY_HYPEREDGE_SLOT_MISMATCH");

    let mut unknown = strict_json();
    unknown["unexpected_root"] = json!(true);
    let error = import_value(&unknown).unwrap_err();
    assert_eq!(error.code(), "E_GRAPHIFY_SCHEMA_UNSUPPORTED");
}

#[test]
fn a05_v2_rejects_pin_over_cap_oversize_and_hardlinked_inputs() {
    let mut over_cap = pin(STRICT_FILE_SHA256);
    over_cap.max_file_bytes = MAX_GRAPHIFY_BYTES_V1 + 1;
    assert_eq!(
        over_cap.validate().unwrap_err().code(),
        "E_GRAPHIFY_PIN_MISMATCH"
    );

    let oversized_dir = tempfile::tempdir().unwrap();
    let oversized = oversized_dir.path().join("oversized.json");
    let file = fs::File::create(&oversized).unwrap();
    file.set_len(MAX_GRAPHIFY_BYTES_V1 + 1).unwrap();
    let mut capped = pin(&sha256(b"not-the-file"));
    capped.max_file_bytes = MAX_GRAPHIFY_BYTES_V1;
    assert_eq!(
        import_pinned_graphify_json_file_v2(&oversized, &capped)
            .unwrap_err()
            .code(),
        "E_GRAPHIFY_FILE_INVALID"
    );

    #[cfg(unix)]
    {
        let bytes = fs::read(fixture("strict-graphify-v2.json")).unwrap();
        let directory = tempfile::tempdir().unwrap();
        let private = directory.path().join("private.json");
        let hardlink = directory.path().join("hardlink.json");
        fs::write(&private, &bytes).unwrap();
        fs::hard_link(&private, &hardlink).unwrap();
        for path in [&private, &hardlink] {
            assert_eq!(
                import_pinned_graphify_json_file_v2(path, &pin(&sha256(&bytes)))
                    .unwrap_err()
                    .code(),
                "E_GRAPHIFY_FILE_INVALID"
            );
        }
    }
}

#[test]
fn a05_v2_rejects_every_upstream_pin_drift() {
    let mut changes = Vec::new();
    let replacement = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    let mut changed = pin(STRICT_FILE_SHA256);
    changed.canonical_schema_sha256 = replacement.to_owned();
    changes.push(changed);
    let mut changed = pin(STRICT_FILE_SHA256);
    changed.export_py_sha256 = replacement.to_owned();
    changes.push(changed);
    let mut changed = pin(STRICT_FILE_SHA256);
    changed.validate_py_sha256 = replacement.to_owned();
    changes.push(changed);
    let mut changed = pin(STRICT_FILE_SHA256);
    changed.pyproject_sha256 = replacement.to_owned();
    changes.push(changed);
    let mut changed = pin(STRICT_FILE_SHA256);
    changed.license_sha256 = replacement.to_owned();
    changes.push(changed);
    let mut changed = pin(STRICT_FILE_SHA256);
    changed.extraction_spec_sha256 = replacement.to_owned();
    changes.push(changed);

    for changed in changes {
        assert_eq!(
            changed.validate().unwrap_err().code(),
            "E_GRAPHIFY_PIN_MISMATCH"
        );
    }
}

#[test]
fn a05_v2_receipt_counts_and_digest_fail_closed_on_tamper() {
    let imported = import_pinned_graphify_json_file_v2(
        &fixture("strict-graphify-v2.json"),
        &pin(STRICT_FILE_SHA256),
    )
    .unwrap();
    let mut mutations = Vec::new();

    let mut changed = imported.receipt.clone();
    changed.extracted_relationship_count += 1;
    mutations.push(changed);
    let mut changed = imported.receipt.clone();
    changed.inferred_relationship_count += 1;
    mutations.push(changed);
    let mut changed = imported.receipt.clone();
    changed.ambiguous_relationship_count += 1;
    mutations.push(changed);
    let mut changed = imported.receipt.clone();
    changed.source_locator_count += 1;
    mutations.push(changed);
    let mut changed = imported.receipt.clone();
    changed.missing_source_location_count += 1;
    mutations.push(changed);
    let mut changed = imported.receipt.clone();
    changed.locator_only_count += 1;
    mutations.push(changed);
    let mut changed = imported.receipt;
    changed.dual_slot_hyperedge_count += 1;
    mutations.push(changed);

    for changed in mutations {
        assert_eq!(
            changed.validate().unwrap_err().code(),
            "E_GRAPHIFY_V2_RECEIPT_INVALID"
        );
    }
}

#[test]
fn a05_v2_remains_file_only_candidate_data_without_canonical_authority() {
    let imported = import_pinned_graphify_json_file_v2(
        &fixture("strict-graphify-v2.json"),
        &pin(STRICT_FILE_SHA256),
    )
    .unwrap();
    let verification = verify_external_fact_bundle_v1(
        &imported.descriptor,
        &imported.descriptor,
        &imported.bundle,
        &imported.source_files,
        "gtkg.verifier/a05-v2",
    )
    .unwrap();

    assert_eq!(verification.false_confirmed, 0);
    assert_eq!(verification.canonical_write_count, 0);
    assert!(verification.resolved_verified_fact_ids.is_empty());
    assert_eq!(imported.receipt.export_file_read_count, 1);
    assert_eq!(imported.receipt.target_execution_count, 0);
    assert_eq!(imported.receipt.provider_call_count, 0);
    assert_eq!(imported.receipt.network_call_count, 0);
    assert_eq!(imported.receipt.write_count, 0);
    assert_eq!(imported.receipt.canonical_write_count, 0);
}
