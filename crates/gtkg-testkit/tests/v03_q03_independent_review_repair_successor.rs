use std::fs;
use std::path::{Path, PathBuf};

use gtkg_core::v03::query::{
    AdjacencyEdgeInputV1, FileQueryErrorV1, FileQueryPageV1, LexicalDocumentV1,
    adjacency_routing_catalog_content_sha256_v1, build_adjacency_routing_index_v1,
    build_lexical_shard_v1, execute_file_query_page_v1, execute_next_file_query_page_v1,
    file_query_continuation_content_sha256_v1, file_query_index_manifest_content_sha256_v1,
    lexical_routing_catalog_content_sha256_v1, query_index_manifest_sha256_v1,
    query_shard_catalog_digests_v1, validate_next_page_against_v1, write_file_query_index_v1,
    write_file_query_index_with_pre_mkdir_hook_v1,
};
use gtkg_core::{CallContext, EffectPolicy, TransportKind};
use gtkg_protocol::FileReceiptRef;
use gtkg_protocol::v03::query::{
    AdjacencyDirectionV1, FileQueryContinuationV1, FileQueryExpectedIdentitiesV1,
    FileQueryIndexManifestV1, FileQueryLookupV1, FileQueryRequestV1, QueryResolutionStateV1,
    QueryShardKindV1,
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

fn edge(edge_id: &str, source: &str, target: &str) -> AdjacencyEdgeInputV1 {
    AdjacencyEdgeInputV1 {
        edge_id: edge_id.to_owned(),
        source_node_id: source.to_owned(),
        target_node_id: target.to_owned(),
        resolution_state: QueryResolutionStateV1::Resolved,
        evidence_ref: format!("evidence:{edge_id}"),
    }
}

fn expected() -> FileQueryExpectedIdentitiesV1 {
    FileQueryExpectedIdentitiesV1 {
        source_identity: digest("source"),
        graph_identity: digest("graph"),
        overlay_identity: digest("overlay"),
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

struct Fixture {
    workspace: tempfile::TempDir,
    index_root: PathBuf,
    reference: FileReceiptRef,
    expected: FileQueryExpectedIdentitiesV1,
}

impl Fixture {
    fn new() -> Self {
        let workspace = tempfile::tempdir().unwrap();
        let index_root = workspace.path().join(".gtkg/query-index");
        let expected = expected();
        let lexical = vec![
            build_lexical_shard_v1(
                "lex-auth",
                &[
                    document("node-auth-1", "authentication shared_query"),
                    document("node-auth-2", "authentication shared_query"),
                    document("node-auth-3", "authentication shared_query"),
                    document("node-auth-4", "authentication shared_query"),
                ],
            )
            .unwrap(),
            build_lexical_shard_v1(
                "lex-billing",
                &[document("node-billing", "billing invoice")],
            )
            .unwrap(),
        ];
        let adjacency = build_adjacency_routing_index_v1(
            &[
                "node-a".to_owned(),
                "node-b".to_owned(),
                "node-isolated".to_owned(),
            ],
            &[edge("edge-a-b", "node-a", "node-b")],
        )
        .unwrap();
        let reference = write_file_query_index_v1(
            &context(workspace.path()),
            &index_root,
            &expected,
            &lexical,
            &adjacency,
        )
        .unwrap();
        Self {
            workspace,
            index_root,
            reference,
            expected,
        }
    }

    fn manifest(&self) -> FileQueryIndexManifestV1 {
        serde_json::from_slice(&fs::read(self.index_root.join(&self.reference.path)).unwrap())
            .unwrap()
    }

    fn forge_manifest(&self, mut manifest: FileQueryIndexManifestV1) -> FileReceiptRef {
        manifest.manifest_sha256 = file_query_index_manifest_content_sha256_v1(&manifest);
        let bytes = serde_json::to_vec_pretty(&manifest).unwrap();
        let reference = FileReceiptRef {
            path: format!(
                "manifests/{}.json",
                manifest.manifest_sha256.strip_prefix("sha256:").unwrap()
            ),
            sha256: file_digest(&bytes),
        };
        fs::write(self.index_root.join(&reference.path), bytes).unwrap();
        reference
    }

    fn query_with(
        &self,
        reference: &FileReceiptRef,
        request: &FileQueryRequestV1,
    ) -> Result<FileQueryPageV1, FileQueryErrorV1> {
        execute_file_query_page_v1(
            &context(self.workspace.path()),
            &self.index_root,
            reference,
            &self.expected,
            request,
        )
    }

    fn query(&self, request: &FileQueryRequestV1) -> FileQueryPageV1 {
        self.query_with(&self.reference, request).unwrap()
    }
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

fn encode_continuation(continuation: &FileQueryContinuationV1) -> String {
    format!(
        "gtkgc1.{}",
        hex::encode(serde_json::to_vec(continuation).unwrap())
    )
}

fn decode_continuation(token: &str) -> FileQueryContinuationV1 {
    let bytes = hex::decode(token.strip_prefix("gtkgc1.").unwrap()).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[test]
fn q03_resealed_lexical_and_adjacency_route_deletion_is_not_a_no_answer() {
    let lexical = Fixture::new();
    let mut manifest = lexical.manifest();
    manifest
        .lexical_routing_catalog
        .entries
        .retain(|entry| !entry.routing_key.ends_with(&hex::encode("authentication")));
    manifest.lexical_routing_catalog.raw_bytes_sha256 =
        lexical_routing_catalog_content_sha256_v1(&manifest.lexical_routing_catalog);
    let forged = lexical.forge_manifest(manifest);
    assert_eq!(
        lexical.query_with(&forged, &search("authentication", 10, None)),
        Err(FileQueryErrorV1::InvalidManifest)
    );

    let adjacency = Fixture::new();
    let mut manifest = adjacency.manifest();
    manifest.adjacency_catalog.routes.retain(|route| {
        !(route.node_id == "node-a" && route.direction == AdjacencyDirectionV1::Outgoing)
    });
    manifest.adjacency_catalog.denominator.route_count =
        u64::try_from(manifest.adjacency_catalog.routes.len()).unwrap();
    manifest.adjacency_catalog.raw_bytes_sha256 =
        adjacency_routing_catalog_content_sha256_v1(&manifest.adjacency_catalog);
    let forged = adjacency.forge_manifest(manifest);
    assert_eq!(
        adjacency.query_with(
            &forged,
            &FileQueryRequestV1 {
                lookup: FileQueryLookupV1::Adjacency {
                    node_id: "node-a".to_owned(),
                    direction: AdjacencyDirectionV1::Outgoing,
                },
                max_results: 10,
                continuation: None,
            },
        ),
        Err(FileQueryErrorV1::InvalidManifest)
    );
}

#[test]
fn q03_forged_self_digest_cursor_cannot_skip_or_duplicate_an_actual_page() {
    let fixture = Fixture::new();
    let first = fixture.query(&search("shared_query", 2, None));
    let original = first.receipt.continuation.clone().unwrap();

    for forged_offset in [1_u64, 3_u64] {
        let mut continuation = decode_continuation(&original);
        continuation.next_offset = forged_offset;
        continuation.continuation_sha256 = file_query_continuation_content_sha256_v1(&continuation);
        let forged = encode_continuation(&continuation);
        assert_eq!(
            execute_next_file_query_page_v1(
                &context(fixture.workspace.path()),
                &fixture.index_root,
                &fixture.reference,
                &fixture.expected,
                &first,
                &search("shared_query", 2, Some(forged)),
            ),
            Err(FileQueryErrorV1::ContinuationInvalid)
        );
    }

    let second = execute_next_file_query_page_v1(
        &context(fixture.workspace.path()),
        &fixture.index_root,
        &fixture.reference,
        &fixture.expected,
        &first,
        &search("shared_query", 2, Some(original)),
    )
    .unwrap();
    validate_next_page_against_v1(&first, &second).unwrap();
    assert_eq!(second.start_offset, first.end_offset);
}

#[test]
#[cfg(unix)]
fn q03_writer_parent_swap_before_mkdir_creates_nothing_outside_the_bound_root() {
    use std::os::unix::fs::symlink;

    let workspace = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let index_root = workspace.path().join(".gtkg/query-index");
    let lexical = vec![
        build_lexical_shard_v1("lex-auth", &[document("node-auth", "authentication")]).unwrap(),
    ];
    let adjacency = build_adjacency_routing_index_v1(
        &["node-a".to_owned(), "node-b".to_owned()],
        &[edge("edge-a-b", "node-a", "node-b")],
    )
    .unwrap();

    let result = write_file_query_index_with_pre_mkdir_hook_v1(
        &context(workspace.path()),
        &index_root,
        &expected(),
        &lexical,
        &adjacency,
        |_| symlink(outside.path(), workspace.path().join(".gtkg")).unwrap(),
    );
    assert_eq!(result, Err(FileQueryErrorV1::UnsafePath));
    assert!(!outside.path().join("query-index").exists());
    assert!(!outside.path().join("shards").exists());
    assert!(!outside.path().join("manifests").exists());
}

#[test]
fn q03_resealed_lexical_record_denominator_mismatch_fails_after_selected_read() {
    let fixture = Fixture::new();
    let mut manifest = fixture.manifest();
    let file = manifest
        .shard_files
        .iter_mut()
        .find(|file| file.shard_id == "lex-auth")
        .unwrap();
    file.record_count += 1;
    let descriptor = manifest
        .index
        .shards
        .entries
        .iter_mut()
        .find(|entry| entry.shard_id == "lex-auth" && entry.shard_kind == QueryShardKindV1::Lexical)
        .unwrap();
    descriptor.record_count += 1;
    manifest.index.digests = query_shard_catalog_digests_v1(&manifest.index.shards.entries);
    manifest.index_manifest_sha256 = query_index_manifest_sha256_v1(&manifest.index);
    let forged = fixture.forge_manifest(manifest);
    assert_eq!(
        fixture.query_with(&forged, &search("authentication", 10, None)),
        Err(FileQueryErrorV1::ShardTampered)
    );
}
