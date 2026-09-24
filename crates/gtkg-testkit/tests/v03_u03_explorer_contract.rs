//! U03 immutable Red: the static Explorer must consume actual Q04 file-index
//! responses, not a hand-seeded browser data object.

use std::fs;
use std::path::{Path, PathBuf};

use gtkg_core::v03::explorer::{
    StaticGraphExplorerInputV1, build_static_graph_explorer_v1, write_static_graph_explorer_v1,
};
use gtkg_core::v03::graph_query::{
    FileGraphQueryOperationV1, GraphQueryEntityV1, execute_file_graph_operation_v1,
    write_graph_query_evidence_index_v1,
};
use gtkg_core::v03::query::{
    AdjacencyEdgeInputV1, LexicalDocumentV1, build_adjacency_routing_index_v1,
    build_lexical_shard_v1, write_file_query_index_v1,
};
use gtkg_core::{CallContext, EffectPolicy, TransportKind};
use gtkg_protocol::FileReceiptRef;
use gtkg_protocol::v03::query::{
    FileQueryExpectedIdentitiesV1, FileQueryIndexManifestV1, QueryResolutionStateV1,
};
use serde_json::{Value, json};

fn digest(label: &str) -> String {
    use sha2::{Digest, Sha256};
    format!("sha256:{}", hex::encode(Sha256::digest(label.as_bytes())))
}

fn context(root: &Path, policy: EffectPolicy) -> CallContext {
    CallContext::restricted(TransportKind::Test, vec![root.to_path_buf()], policy).unwrap()
}

fn evidence(id: &str, index: usize) -> Value {
    json!({
        "kind": "source_span",
        "evidence_id": id,
        "source_snapshot_exact_set_sha256": digest("source"),
        "source_logical_path": format!("src/module_{index}.rs"),
        "source_sha256": digest(&format!("source-{index}")),
        "byte_start": index * 10,
        "byte_end": index * 10 + 8,
        "snippet_sha256": digest(&format!("snippet-{index}")),
    })
}

struct Fixture {
    workspace: tempfile::TempDir,
    query_root: PathBuf,
    query_manifest_ref: FileReceiptRef,
    evidence_root: PathBuf,
    evidence_manifest_ref: FileReceiptRef,
    expected: FileQueryExpectedIdentitiesV1,
}

impl Fixture {
    fn new() -> Self {
        let workspace = tempfile::tempdir().unwrap();
        let query_root = workspace.path().join(".gtkg/query-index");
        let evidence_root = workspace.path().join(".gtkg/query-evidence");
        let expected = FileQueryExpectedIdentitiesV1 {
            source_identity: digest("source"),
            graph_identity: digest("graph"),
            overlay_identity: digest("overlay"),
        };
        let documents = vec![
            LexicalDocumentV1 {
                node_id: "node-a".to_owned(),
                evidence_ref: "evidence:node-a".to_owned(),
                text: "node-a authenticated symbol".to_owned(),
            },
            LexicalDocumentV1 {
                node_id: "node-b".to_owned(),
                evidence_ref: "evidence:node-b".to_owned(),
                text: "node-b target symbol".to_owned(),
            },
            LexicalDocumentV1 {
                node_id: "edge-a-b".to_owned(),
                evidence_ref: "evidence:edge-a-b".to_owned(),
                text: "edge-a-b calls node-a node-b".to_owned(),
            },
        ];
        let lexical = vec![build_lexical_shard_v1("explorer-lex", &documents).unwrap()];
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
        let entities = vec![
            GraphQueryEntityV1::StructuralNode {
                entity_id: "node-a".to_owned(),
                node_kind: "code_symbol".to_owned(),
                label: "Auth <img src=x onerror=window.__u03_xss=true>".to_owned(),
                source_logical_path: "src/auth.rs".to_owned(),
                structural_provenance: json!({
                    "input_kind":"typed_ir",
                    "input_id":"src/auth.rs",
                    "input_sha256":digest("typed-a"),
                    "source_snapshot_exact_set_sha256":expected.source_identity,
                }),
                evidence: vec![evidence("evidence:node-a", 0)],
            },
            GraphQueryEntityV1::StructuralNode {
                entity_id: "node-b".to_owned(),
                node_kind: "code_symbol".to_owned(),
                label: "Target B".to_owned(),
                source_logical_path: "src/target.rs".to_owned(),
                structural_provenance: json!({
                    "input_kind":"typed_ir",
                    "input_id":"src/target.rs",
                    "input_sha256":digest("typed-b"),
                    "source_snapshot_exact_set_sha256":expected.source_identity,
                }),
                evidence: vec![evidence("evidence:node-b", 1)],
            },
            GraphQueryEntityV1::StructuralEdge {
                entity_id: "edge-a-b".to_owned(),
                edge_kind: "calls".to_owned(),
                source_node_id: "node-a".to_owned(),
                target_node_id: Some("node-b".to_owned()),
                target_reference: "node-b".to_owned(),
                resolution_state: QueryResolutionStateV1::Resolved,
                candidate_node_ids: Vec::new(),
                structural_provenance: json!({
                    "input_kind":"typed_ir",
                    "input_id":"src/auth.rs",
                    "input_sha256":digest("typed-edge"),
                    "source_snapshot_exact_set_sha256":expected.source_identity,
                }),
                evidence: vec![evidence("evidence:edge-a-b", 2)],
            },
        ];
        let write = context(workspace.path(), EffectPolicy::WorkspaceWrite);
        let query_manifest_ref =
            write_file_query_index_v1(&write, &query_root, &expected, &lexical, &adjacency)
                .unwrap();
        let manifest: FileQueryIndexManifestV1 =
            serde_json::from_slice(&fs::read(query_root.join(&query_manifest_ref.path)).unwrap())
                .unwrap();
        let evidence_manifest_ref = write_graph_query_evidence_index_v1(
            &write,
            &evidence_root,
            &expected,
            &query_manifest_ref,
            &manifest.index_manifest_sha256,
            &entities,
        )
        .unwrap();
        Self {
            workspace,
            query_root,
            query_manifest_ref,
            evidence_root,
            evidence_manifest_ref,
            expected,
        }
    }

    fn query(&self, operation: FileGraphQueryOperationV1, payload: Value) -> Value {
        execute_file_graph_operation_v1(
            &context(self.workspace.path(), EffectPolicy::ReadOnly),
            &self.query_root,
            &self.query_manifest_ref,
            &self.evidence_root,
            &self.evidence_manifest_ref,
            &self.expected,
            operation,
            &payload,
        )
        .unwrap()
    }

    fn input(&self) -> StaticGraphExplorerInputV1 {
        StaticGraphExplorerInputV1 {
            search: self.query(
                FileGraphQueryOperationV1::Search,
                json!({"query":"authenticated","max_results":10}),
            ),
            neighbors: self.query(
                FileGraphQueryOperationV1::Neighbors,
                json!({"node_id":"node-a","direction":"outgoing","max_results":10}),
            ),
            path: self.query(
                FileGraphQueryOperationV1::Path,
                json!({"source_node_id":"node-a","target_node_id":"node-b","max_depth":2}),
            ),
            impact: self.query(
                FileGraphQueryOperationV1::Impact,
                json!({"node_id":"node-a","max_depth":2,"max_results":10}),
            ),
            trace: self.query(
                FileGraphQueryOperationV1::Trace,
                json!({"entity_id":"node-a"}),
            ),
        }
    }
}

fn build_real_site(output_root: &Path) -> Value {
    let fixture = Fixture::new();
    let projection = build_static_graph_explorer_v1(&fixture.input()).unwrap();
    let receipt = write_static_graph_explorer_v1(
        &context(fixture.workspace.path(), EffectPolicy::WorkspaceWrite),
        output_root,
        &projection,
    )
    .unwrap();
    serde_json::to_value(receipt).unwrap()
}

#[test]
fn u03_static_explorer_consumes_q04_responses_and_preserves_evidence_boundaries() {
    let temporary = tempfile::tempdir().unwrap();
    let receipt = build_real_site(&temporary.path().join("site"));
    assert_eq!(
        receipt["schema_version"],
        "gtkg.static-graph-explorer-receipt/v1"
    );
    assert_eq!(receipt["source_kind"], "q04_file_index_responses");
    assert_eq!(receipt["network_calls"], 0);
    assert_eq!(receipt["database_reads"], 0);
    assert_eq!(receipt["target_execution_count"], 0);
    assert!(
        receipt["site_manifest_sha256"]
            .as_str()
            .unwrap()
            .starts_with("sha256:")
    );
    assert!(temporary.path().join("site/index.html").is_file());
}

#[test]
#[ignore = "emits a real Q04-backed local fixture for the separately frozen browser harness"]
fn emit_u03_real_explorer_browser_fixture() {
    let output = PathBuf::from(std::env::var("GTKG_U03_BROWSER_OUTPUT").unwrap());
    assert!(!output.exists(), "browser output must not exist");
    fs::create_dir_all(&output).unwrap();
    let receipt = build_real_site(&output.join("site"));
    fs::write(
        output.join("browser-fixture-receipt.json"),
        serde_json::to_vec_pretty(&receipt).unwrap(),
    )
    .unwrap();
}
