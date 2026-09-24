use std::fs;
#[cfg(unix)]
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

use gtkg_core::v03::graph_query::{
    FileGraphEvidenceManifestV1, FileGraphQueryOperationV1, GraphQueryEntityV1,
    execute_file_graph_operation_v1, write_graph_query_evidence_index_v1,
};
use gtkg_core::v03::query::{
    AdjacencyEdgeInputV1, LexicalDocumentV1, build_adjacency_routing_index_v1,
    build_lexical_shard_v1, write_file_query_index_v1,
};
use gtkg_core::{CallContext, Dispatcher, EffectPolicy, TransportKind};
use gtkg_protocol::FileReceiptRef;
use gtkg_protocol::v2::{OperationRequestV2, V2ErrorCode};
use gtkg_protocol::v03::query::{
    FileQueryExpectedIdentitiesV1, FileQueryIndexManifestV1, QueryResolutionStateV1,
};
use serde_json::{Value, json};

fn digest(label: &str) -> String {
    use sha2::{Digest, Sha256};
    format!("sha256:{}", hex::encode(Sha256::digest(label.as_bytes())))
}

fn context(root: &Path, effect: EffectPolicy) -> CallContext {
    CallContext::restricted(TransportKind::Test, vec![root.to_path_buf()], effect).unwrap()
}

struct Fixture {
    workspace: tempfile::TempDir,
    query_root: PathBuf,
    evidence_root: PathBuf,
    query_ref: FileReceiptRef,
    evidence_ref: FileReceiptRef,
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
        let documents = [
            LexicalDocumentV1 {
                node_id: "opaque-node-a".to_owned(),
                evidence_ref: "evidence:node-a".to_owned(),
                text: "human readable authentication label".to_owned(),
            },
            LexicalDocumentV1 {
                node_id: "opaque-node-b".to_owned(),
                evidence_ref: "evidence:node-b".to_owned(),
                text: "human readable storage label".to_owned(),
            },
            LexicalDocumentV1 {
                node_id: "opaque-edge-a-b".to_owned(),
                evidence_ref: "evidence:edge-a-b".to_owned(),
                text: "calls relation".to_owned(),
            },
        ];
        let lexical = vec![build_lexical_shard_v1("lex", &documents).unwrap()];
        let edge = AdjacencyEdgeInputV1 {
            edge_id: "opaque-edge-a-b".to_owned(),
            source_node_id: "opaque-node-a".to_owned(),
            target_node_id: "opaque-node-b".to_owned(),
            resolution_state: QueryResolutionStateV1::Resolved,
            evidence_ref: "evidence:edge-a-b".to_owned(),
        };
        let adjacency = build_adjacency_routing_index_v1(
            &["opaque-node-a".to_owned(), "opaque-node-b".to_owned()],
            &[edge],
        )
        .unwrap();
        let writer = context(workspace.path(), EffectPolicy::WorkspaceWrite);
        let query_ref =
            write_file_query_index_v1(&writer, &query_root, &expected, &lexical, &adjacency)
                .unwrap();
        let manifest: FileQueryIndexManifestV1 =
            serde_json::from_slice(&fs::read(query_root.join(&query_ref.path)).unwrap()).unwrap();
        let entities = vec![
            GraphQueryEntityV1::StructuralNode {
                entity_id: "opaque-node-a".to_owned(),
                node_kind: "code_symbol".to_owned(),
                label: "authentication".to_owned(),
                source_logical_path: "src/a.rs".to_owned(),
                structural_provenance: json!({"input_kind":"typed_ir","input_id":"a","input_sha256":digest("a"),"source_snapshot_exact_set_sha256":expected.source_identity}),
                evidence: vec![json!({"evidence_id":"evidence:node-a"})],
            },
            GraphQueryEntityV1::StructuralNode {
                entity_id: "opaque-node-b".to_owned(),
                node_kind: "code_symbol".to_owned(),
                label: "storage".to_owned(),
                source_logical_path: "src/b.rs".to_owned(),
                structural_provenance: json!({"input_kind":"typed_ir","input_id":"b","input_sha256":digest("b"),"source_snapshot_exact_set_sha256":expected.source_identity}),
                evidence: vec![json!({"evidence_id":"evidence:node-b"})],
            },
            GraphQueryEntityV1::StructuralEdge {
                entity_id: "opaque-edge-a-b".to_owned(),
                edge_kind: "calls".to_owned(),
                source_node_id: "opaque-node-a".to_owned(),
                target_node_id: Some("opaque-node-b".to_owned()),
                target_reference: "opaque-node-b".to_owned(),
                resolution_state: QueryResolutionStateV1::Resolved,
                candidate_node_ids: Vec::new(),
                structural_provenance: json!({"input_kind":"typed_ir","input_id":"edge","input_sha256":digest("edge"),"source_snapshot_exact_set_sha256":expected.source_identity}),
                evidence: vec![json!({"evidence_id":"evidence:edge-a-b"})],
            },
        ];
        let evidence_ref = write_graph_query_evidence_index_v1(
            &writer,
            &evidence_root,
            &expected,
            &query_ref,
            &manifest.index_manifest_sha256,
            &entities,
        )
        .unwrap();
        Self {
            workspace,
            query_root,
            evidence_root,
            query_ref,
            evidence_ref,
            expected,
        }
    }

    fn trace(&self) -> Value {
        execute_file_graph_operation_v1(
            &context(self.workspace.path(), EffectPolicy::ReadOnly),
            &self.query_root,
            &self.query_ref,
            &self.evidence_root,
            &self.evidence_ref,
            &self.expected,
            FileGraphQueryOperationV1::Trace,
            &json!({"entity_id":"opaque-node-a"}),
        )
        .unwrap()
    }
}

#[test]
fn q04_trace_routes_exact_entity_id_even_when_human_text_does_not_contain_it() {
    let fixture = Fixture::new();
    let trace = fixture.trace();
    assert_eq!(trace["result"]["entity_id"], "opaque-node-a");
    assert_eq!(trace["result"]["entity_kind"], "node");
    assert_eq!(
        trace["evidence_pack"]["query_index"]["full_graph_read_count"],
        0
    );
}

#[test]
fn q04_evidence_bytes_account_for_preflight_manifest_replay() {
    let fixture = Fixture::new();
    let manifest_bytes = fs::read(fixture.evidence_root.join(&fixture.evidence_ref.path)).unwrap();
    let manifest: FileGraphEvidenceManifestV1 = serde_json::from_slice(&manifest_bytes).unwrap();
    let record = manifest
        .records
        .iter()
        .find(|entry| entry.entity_id == "opaque-node-a")
        .unwrap();
    let trace = fixture.trace();
    assert_eq!(
        trace["evidence_pack"]["query_index"]["evidence_bytes_read"],
        (manifest_bytes.len() as u64) * 2 + record.byte_len
    );
}

#[test]
#[cfg(unix)]
fn q04_dispatcher_rejects_a_lexical_evidence_root_symlink_before_canonicalization() {
    let fixture = Fixture::new();
    let link = fixture.workspace.path().join(".gtkg/query-evidence-link");
    symlink(&fixture.evidence_root, &link).unwrap();
    let request = OperationRequestV2::new(
        "graph.trace",
        "q04-symlink-root",
        json!({
            "query_index_path": ".gtkg/query-index",
            "query_manifest_ref": fixture.query_ref,
            "evidence_index_path": ".gtkg/query-evidence-link",
            "evidence_manifest_ref": fixture.evidence_ref,
            "expected_identities": fixture.expected,
            "entity_id": "opaque-node-a"
        }),
    );
    let error = Dispatcher
        .execute_v2(
            &context(fixture.workspace.path(), EffectPolicy::ReadOnly),
            request,
        )
        .unwrap_err();
    assert_eq!(error.error.code, V2ErrorCode::PathEscape);
}
