use gtkg_core::v03::adapter::scip::{ScipFilePinV1, import_pinned_scip_json_file_v1};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

const FILE_SHA256: &str = "sha256:6c1aa34317015297620f517829cbbe1105765f28897a2f3f87c5a622d5672fce";
const SOURCE_SNAPSHOT_SHA256: &str =
    "sha256:7a516a066420d92c5b10da8f76f5e8eccf1dd1250d425879dab88f3af4654a20";

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/v03_a02/valid-scip.json")
}

fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

#[test]
fn relationship_edge_binds_the_target_reference_span_not_a_definition_span() {
    let imported =
        import_pinned_scip_json_file_v1(
            &fixture(),
            &ScipFilePinV1 {
                file_sha256: FILE_SHA256.to_owned(),
                schema_version: "scip/0.4-json".to_owned(),
                schema_sha256:
                    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        .to_owned(),
                tool_name: "scip-rust".to_owned(),
                tool_version: "0.3.3".to_owned(),
                tool_commit: "0123456789abcdef0123456789abcdef01234567".to_owned(),
                tool_license: "Apache-2.0".to_owned(),
                source_snapshot_sha256: SOURCE_SNAPSHOT_SHA256.to_owned(),
                max_file_bytes: 64 * 1024,
            },
        )
        .unwrap();
    let edge = &imported.bundle.edges[0];
    assert_eq!(edge.evidence_ids.len(), 1);
    let evidence = imported
        .bundle
        .evidence
        .iter()
        .find(|item| item.evidence_id == edge.evidence_ids[0])
        .unwrap();
    let source = &imported.source_files[&evidence.source_logical_path];
    let snippet = &source[evidence.byte_start as usize..evidence.byte_end as usize];
    assert_eq!(snippet, b"helper");
    assert_eq!(sha256(snippet), evidence.snippet_sha256);
}
