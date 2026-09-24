use std::path::PathBuf;

use gtkg_core::v03::query::{
    AdjacencyEdgeInputV1, LexicalDocumentV1, build_adjacency_routing_index_v1,
    build_lexical_shard_v1, execute_file_query_page_v1, write_file_query_index_v1,
};
use gtkg_core::{CallContext, EffectPolicy, TransportKind};
use gtkg_protocol::FileReceiptRef;
use gtkg_protocol::v03::query::{
    AdjacencyDirectionV1, FileQueryExpectedIdentitiesV1, FileQueryLookupV1, FileQueryRequestV1,
    QueryResolutionStateV1,
};

fn digest(label: &str) -> String {
    use sha2::{Digest, Sha256};
    format!("sha256:{}", hex::encode(Sha256::digest(label.as_bytes())))
}

struct Fixture {
    _workspace: tempfile::TempDir,
    context: CallContext,
    root: PathBuf,
    reference: FileReceiptRef,
    expected: FileQueryExpectedIdentitiesV1,
}

impl Fixture {
    fn new() -> Self {
        let workspace = tempfile::tempdir().unwrap();
        let context = CallContext::restricted(
            TransportKind::Test,
            vec![workspace.path().to_path_buf()],
            EffectPolicy::WorkspaceWrite,
        )
        .unwrap();
        let root = workspace.path().join(".gtkg/query-index");
        let lexical = vec![
            build_lexical_shard_v1(
                "lex-auth",
                &[LexicalDocumentV1 {
                    node_id: "服务:身份".to_owned(),
                    evidence_ref: "evidence:auth".to_owned(),
                    text: "身份认证服务".to_owned(),
                }],
            )
            .unwrap(),
            build_lexical_shard_v1(
                "lex-billing",
                &[LexicalDocumentV1 {
                    node_id: "服务:账单".to_owned(),
                    evidence_ref: "evidence:billing".to_owned(),
                    text: "账单渲染服务".to_owned(),
                }],
            )
            .unwrap(),
        ];
        let adjacency = build_adjacency_routing_index_v1(
            &["node-a".to_owned(), "node-b".to_owned()],
            &[AdjacencyEdgeInputV1 {
                edge_id: "edge-a-b".to_owned(),
                source_node_id: "node-a".to_owned(),
                target_node_id: "node-b".to_owned(),
                resolution_state: QueryResolutionStateV1::Resolved,
                evidence_ref: "evidence:edge-a-b".to_owned(),
            }],
        )
        .unwrap();
        let expected = FileQueryExpectedIdentitiesV1 {
            source_identity: digest("source"),
            graph_identity: digest("graph"),
            overlay_identity: digest("overlay"),
        };
        let reference =
            write_file_query_index_v1(&context, &root, &expected, &lexical, &adjacency).unwrap();
        Self {
            _workspace: workspace,
            context,
            root,
            reference,
            expected,
        }
    }

    fn run(&self, lookup: FileQueryLookupV1) -> gtkg_core::v03::query::FileQueryPageV1 {
        execute_file_query_page_v1(
            &self.context,
            &self.root,
            &self.reference,
            &self.expected,
            &FileQueryRequestV1 {
                lookup,
                max_results: 10,
                continuation: None,
            },
        )
        .unwrap()
    }
}

#[test]
fn q03_short_cjk_substring_routes_only_the_matching_lexical_shard() {
    let fixture = Fixture::new();
    let page = fixture.run(FileQueryLookupV1::Search {
        query: "认证".to_owned(),
    });
    assert_eq!(page.opened_shards, ["lex-auth"]);
    assert_eq!(page.lexical_hits.len(), 1);
    assert_eq!(page.lexical_hits[0].node_id, "服务:身份");
}

#[test]
fn q03_unknown_adjacency_node_is_a_valid_zero_open_no_answer() {
    let fixture = Fixture::new();
    let page = fixture.run(FileQueryLookupV1::Adjacency {
        node_id: "node-missing".to_owned(),
        direction: AdjacencyDirectionV1::Outgoing,
    });
    assert!(page.adjacency_edges.is_empty());
    assert!(page.receipt.selected_shards.is_empty());
    assert_eq!(page.shard_files_opened, 0);
}
