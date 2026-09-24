use std::fs;
use std::path::{Path, PathBuf};

use gtkg_core::v03::query::{
    AdjacencyEdgeInputV1, FileQueryErrorV1, LexicalDocumentV1,
    adjacency_routing_catalog_content_sha256_v1, build_adjacency_routing_index_v1,
    build_lexical_shard_v1, execute_first_file_query_page_v1, execute_next_file_query_page_v1,
    file_query_continuation_content_sha256_v1, file_query_index_manifest_content_sha256_v1,
    lexical_routing_catalog_content_sha256_v1, write_file_query_index_v1,
    write_file_query_index_with_pre_publish_hook_v1,
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

fn edge() -> AdjacencyEdgeInputV1 {
    AdjacencyEdgeInputV1 {
        edge_id: "edge-a-b".to_owned(),
        source_node_id: "node-a".to_owned(),
        target_node_id: "node-b".to_owned(),
        resolution_state: QueryResolutionStateV1::Resolved,
        evidence_ref: "evidence:edge-a-b".to_owned(),
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
            &[edge()],
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

    fn forge(&self, mut manifest: FileQueryIndexManifestV1) -> FileReceiptRef {
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

    fn execute(
        &self,
        reference: &FileReceiptRef,
        lookup: FileQueryLookupV1,
    ) -> Result<gtkg_core::v03::query::FileQueryPageV1, FileQueryErrorV1> {
        execute_first_file_query_page_v1(
            &context(self.workspace.path()),
            &self.index_root,
            reference,
            &self.expected,
            &FileQueryRequestV1 {
                lookup,
                max_results: 10,
                continuation: None,
            },
        )
    }
}

#[test]
fn q03_routing_proof_rejects_simultaneous_catalog_and_per_shard_key_deletion() {
    let lexical = Fixture::new();
    let mut manifest = lexical.manifest();
    let key_suffix = hex::encode("authentication");
    manifest
        .lexical_routing_catalog
        .entries
        .retain(|entry| !entry.routing_key.ends_with(&key_suffix));
    manifest.lexical_routing_catalog.raw_bytes_sha256 =
        lexical_routing_catalog_content_sha256_v1(&manifest.lexical_routing_catalog);
    manifest
        .shard_files
        .iter_mut()
        .find(|file| file.shard_id == "lex-auth")
        .unwrap()
        .routing_keys
        .retain(|key| !key.ends_with(&key_suffix));
    let forged = lexical.forge(manifest);
    assert_eq!(
        lexical.execute(
            &forged,
            FileQueryLookupV1::Search {
                query: "authentication".to_owned(),
            },
        ),
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
    manifest
        .adjacency_routes
        .iter_mut()
        .find(|route| {
            route.node_id == "node-a" && route.direction == AdjacencyDirectionV1::Outgoing
        })
        .unwrap()
        .shard_id = None;
    manifest
        .shard_files
        .iter_mut()
        .filter(|file| file.shard_kind == QueryShardKindV1::Adjacency)
        .for_each(|file| {
            file.routing_keys
                .retain(|key| !key.ends_with(&hex::encode("node-a")));
        });
    let forged = adjacency.forge(manifest);
    assert_eq!(
        adjacency.execute(
            &forged,
            FileQueryLookupV1::Adjacency {
                node_id: "node-a".to_owned(),
                direction: AdjacencyDirectionV1::Outgoing,
            },
        ),
        Err(FileQueryErrorV1::InvalidManifest)
    );
}

#[test]
#[cfg(unix)]
fn q03_post_mkdir_intermediate_symlink_swap_cannot_publish_outside_root() {
    use std::os::unix::fs::symlink;

    let workspace = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    fs::create_dir_all(outside.path().join("query-index/shards")).unwrap();
    fs::create_dir_all(outside.path().join("query-index/manifests")).unwrap();
    let index_root = workspace.path().join(".gtkg/query-index");
    let lexical = vec![
        build_lexical_shard_v1("lex-auth", &[document("node-auth", "authentication")]).unwrap(),
    ];
    let adjacency =
        build_adjacency_routing_index_v1(&["node-a".to_owned(), "node-b".to_owned()], &[edge()])
            .unwrap();
    let result = write_file_query_index_with_pre_publish_hook_v1(
        &context(workspace.path()),
        &index_root,
        &expected(),
        &lexical,
        &adjacency,
        |_| {
            fs::rename(
                workspace.path().join(".gtkg"),
                workspace.path().join(".gtkg.saved"),
            )
            .unwrap();
            symlink(outside.path(), workspace.path().join(".gtkg")).unwrap();
        },
    );
    assert_eq!(result, Err(FileQueryErrorV1::UnsafePath));
    assert_eq!(
        fs::read_dir(outside.path().join("query-index/shards"))
            .unwrap()
            .count(),
        0
    );
    assert_eq!(
        fs::read_dir(outside.path().join("query-index/manifests"))
            .unwrap()
            .count(),
        0
    );
}

#[test]
fn q03_production_first_page_api_rejects_even_self_rehashed_continuation() {
    let fixture = Fixture::new();
    let request = FileQueryRequestV1 {
        lookup: FileQueryLookupV1::Search {
            query: "shared_query".to_owned(),
        },
        max_results: 1,
        continuation: None,
    };
    let first = execute_first_file_query_page_v1(
        &context(fixture.workspace.path()),
        &fixture.index_root,
        &fixture.reference,
        &fixture.expected,
        &request,
    )
    .unwrap();
    let original = first.receipt.continuation.clone().unwrap();
    let mut continuation: FileQueryContinuationV1 =
        serde_json::from_slice(&hex::decode(original.strip_prefix("gtkgc1.").unwrap()).unwrap())
            .unwrap();
    continuation.next_offset += 1;
    continuation.continuation_sha256 = file_query_continuation_content_sha256_v1(&continuation);
    let forged = format!(
        "gtkgc1.{}",
        hex::encode(serde_json::to_vec(&continuation).unwrap())
    );
    let forged_request = FileQueryRequestV1 {
        continuation: Some(forged),
        ..request.clone()
    };
    assert_eq!(
        execute_first_file_query_page_v1(
            &context(fixture.workspace.path()),
            &fixture.index_root,
            &fixture.reference,
            &fixture.expected,
            &forged_request,
        ),
        Err(FileQueryErrorV1::ContinuationInvalid)
    );
    let valid_next = execute_next_file_query_page_v1(
        &context(fixture.workspace.path()),
        &fixture.index_root,
        &fixture.reference,
        &fixture.expected,
        &first,
        &FileQueryRequestV1 {
            continuation: Some(original),
            ..request
        },
    )
    .unwrap();
    assert_eq!(valid_next.start_offset, first.end_offset);
}
