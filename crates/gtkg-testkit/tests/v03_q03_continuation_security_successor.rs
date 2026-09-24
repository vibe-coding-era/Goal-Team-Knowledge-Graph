use std::fs;
use std::path::{Path, PathBuf};

use gtkg_core::v03::query::{
    AdjacencyEdgeInputV1, FileQueryErrorV1, LexicalDocumentV1, build_adjacency_routing_index_v1,
    build_lexical_shard_v1, execute_file_query_page_v1,
    file_query_index_manifest_content_sha256_v1, lexical_routing_catalog_content_sha256_v1,
    validate_file_query_page_v1, write_file_query_index_v1,
};
use gtkg_core::{CallContext, EffectPolicy, TransportKind};
use gtkg_protocol::FileReceiptRef;
use gtkg_protocol::v03::query::{
    FileQueryExpectedIdentitiesV1, FileQueryIndexManifestV1, FileQueryLookupV1, FileQueryRequestV1,
    LexicalRoutingEntryV1, QueryResolutionStateV1,
};

fn digest(label: &str) -> String {
    use sha2::{Digest, Sha256};
    format!("sha256:{}", hex::encode(Sha256::digest(label.as_bytes())))
}

fn file_digest(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn document(node_id: &str, text: &str) -> LexicalDocumentV1 {
    LexicalDocumentV1 {
        node_id: node_id.to_owned(),
        evidence_ref: format!("evidence:{node_id}"),
        text: text.to_owned(),
    }
}

fn edge() -> AdjacencyEdgeInputV1 {
    AdjacencyEdgeInputV1 {
        edge_id: "edge-a-b".to_owned(),
        source_node_id: "node-a".to_owned(),
        target_node_id: "node-b".to_owned(),
        resolution_state: QueryResolutionStateV1::Resolved,
        evidence_ref: "evidence:edge-a-b".to_owned(),
    }
}

struct Fixture {
    workspace: tempfile::TempDir,
    index_root: PathBuf,
    reference: FileReceiptRef,
    expected: FileQueryExpectedIdentitiesV1,
}

impl Fixture {
    fn new(shards: Vec<(&str, Vec<LexicalDocumentV1>)>) -> Self {
        let workspace = tempfile::tempdir().unwrap();
        let index_root = workspace.path().join(".gtkg/query-index");
        let context = context(workspace.path());
        let lexical = shards
            .into_iter()
            .map(|(shard_id, documents)| build_lexical_shard_v1(shard_id, &documents).unwrap())
            .collect::<Vec<_>>();
        let adjacency = build_adjacency_routing_index_v1(
            &["node-a".to_owned(), "node-b".to_owned()],
            &[edge()],
        )
        .unwrap();
        let expected = FileQueryExpectedIdentitiesV1 {
            source_identity: digest("source"),
            graph_identity: digest("graph"),
            overlay_identity: digest("overlay"),
        };
        let reference =
            write_file_query_index_v1(&context, &index_root, &expected, &lexical, &adjacency)
                .unwrap();
        Self {
            workspace,
            index_root,
            reference,
            expected,
        }
    }

    fn run(
        &self,
        reference: &FileReceiptRef,
        request: &FileQueryRequestV1,
    ) -> Result<gtkg_core::v03::query::FileQueryPageV1, FileQueryErrorV1> {
        execute_file_query_page_v1(
            &context(self.workspace.path()),
            &self.index_root,
            reference,
            &self.expected,
            request,
        )
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

fn search(query: &str, max_results: u64, continuation: Option<String>) -> FileQueryRequestV1 {
    FileQueryRequestV1 {
        lookup: FileQueryLookupV1::Search {
            query: query.to_owned(),
        },
        max_results,
        continuation,
    }
}

#[test]
fn q03_continuation_cannot_cross_a_resealed_routing_manifest() {
    let fixture = Fixture::new(vec![(
        "lex-shared",
        vec![
            document("node-1", "shared_query"),
            document("node-2", "shared_query"),
            document("node-3", "shared_query"),
        ],
    )]);
    let first = fixture
        .run(&fixture.reference, &search("shared_query", 1, None))
        .unwrap();
    let token = first.receipt.continuation.unwrap();

    let manifest_path = fixture.index_root.join(&fixture.reference.path);
    let mut manifest: FileQueryIndexManifestV1 =
        serde_json::from_slice(&fs::read(manifest_path).unwrap()).unwrap();
    manifest
        .lexical_routing_catalog
        .entries
        .push(LexicalRoutingEntryV1 {
            routing_key: format!("term:{}", hex::encode("zzz")),
            shard_ids: vec!["lex-shared".to_owned()],
        });
    manifest
        .lexical_routing_catalog
        .entries
        .sort_by(|left, right| left.routing_key.cmp(&right.routing_key));
    manifest.lexical_routing_catalog.raw_bytes_sha256 =
        lexical_routing_catalog_content_sha256_v1(&manifest.lexical_routing_catalog);
    manifest.manifest_sha256 = file_query_index_manifest_content_sha256_v1(&manifest);
    let bytes = serde_json::to_vec_pretty(&manifest).unwrap();
    let reference = FileReceiptRef {
        path: format!(
            "manifests/{}.json",
            manifest.manifest_sha256.strip_prefix("sha256:").unwrap()
        ),
        sha256: file_digest(&bytes),
    };
    fs::write(fixture.index_root.join(&reference.path), bytes).unwrap();

    assert_eq!(
        fixture.run(&reference, &search("shared_query", 1, Some(token)),),
        Err(FileQueryErrorV1::ContinuationInvalid)
    );
}

#[test]
fn q03_page_validator_rejects_receipt_and_continuation_tamper() {
    let fixture = Fixture::new(vec![(
        "lex-shared",
        vec![
            document("node-1", "shared_query"),
            document("node-2", "shared_query"),
        ],
    )]);
    let page = fixture
        .run(&fixture.reference, &search("shared_query", 1, None))
        .unwrap();

    let mut receipt_tamper = page.clone();
    receipt_tamper.receipt.query_sha256 = digest("other-query");
    assert_eq!(
        validate_file_query_page_v1(&receipt_tamper),
        Err(FileQueryErrorV1::ManifestTampered)
    );

    let mut continuation_tamper = page;
    continuation_tamper.receipt.continuation = Some("gtkgc1.00".to_owned());
    assert_eq!(
        validate_file_query_page_v1(&continuation_tamper),
        Err(FileQueryErrorV1::ContinuationInvalid)
    );
}

#[test]
fn q03_disjoint_phrase_routes_are_a_valid_no_answer() {
    let fixture = Fixture::new(vec![
        ("lex-alpha", vec![document("node-alpha", "alpha")]),
        ("lex-beta", vec![document("node-beta", "beta")]),
    ]);
    let page = fixture
        .run(&fixture.reference, &search("alpha beta", 10, None))
        .unwrap();
    assert!(page.lexical_hits.is_empty());
    assert!(page.receipt.selected_shards.is_empty());
    assert_eq!(page.shard_files_opened, 0);
}
