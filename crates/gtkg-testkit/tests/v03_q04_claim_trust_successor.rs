use std::fs;
use std::path::{Path, PathBuf};

use gtkg_core::knowledge_overlay_v2::KnowledgeOverlayBuildInputV2;
use gtkg_core::v03::graph_query::{
    FileGraphQueryErrorV1, GraphQueryEntityV1,
    write_graph_query_evidence_index_from_verified_overlay_v1, write_graph_query_evidence_index_v1,
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
use serde_json::json;

fn digest(label: &str) -> String {
    use sha2::{Digest, Sha256};
    format!("sha256:{}", hex::encode(Sha256::digest(label.as_bytes())))
}

fn context(root: &Path, transport: TransportKind, effect: EffectPolicy) -> CallContext {
    CallContext::restricted(transport, vec![root.to_path_buf()], effect).unwrap()
}

struct Fixture {
    workspace: tempfile::TempDir,
    evidence_root: PathBuf,
    expected: FileQueryExpectedIdentitiesV1,
    query_ref: FileReceiptRef,
    index_manifest_sha256: String,
    structural: Vec<GraphQueryEntityV1>,
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
                node_id: "node-a".to_owned(),
                evidence_ref: "evidence:node-a".to_owned(),
                text: "node-a structural symbol".to_owned(),
            },
            LexicalDocumentV1 {
                node_id: "node-b".to_owned(),
                evidence_ref: "evidence:node-b".to_owned(),
                text: "node-b structural symbol".to_owned(),
            },
            LexicalDocumentV1 {
                node_id: "edge-a-b".to_owned(),
                evidence_ref: "evidence:edge-a-b".to_owned(),
                text: "edge-a-b calls relation".to_owned(),
            },
            LexicalDocumentV1 {
                node_id: "claim-a".to_owned(),
                evidence_ref: "evidence:node-a".to_owned(),
                text: "claim-a accepted claim".to_owned(),
            },
        ];
        let lexical = vec![build_lexical_shard_v1("lex", &documents).unwrap()];
        let edge = AdjacencyEdgeInputV1 {
            edge_id: "edge-a-b".to_owned(),
            source_node_id: "node-a".to_owned(),
            target_node_id: "node-b".to_owned(),
            resolution_state: QueryResolutionStateV1::Resolved,
            evidence_ref: "evidence:edge-a-b".to_owned(),
        };
        let adjacency =
            build_adjacency_routing_index_v1(&["node-a".to_owned(), "node-b".to_owned()], &[edge])
                .unwrap();
        let writer = context(
            workspace.path(),
            TransportKind::Test,
            EffectPolicy::WorkspaceWrite,
        );
        let query_ref =
            write_file_query_index_v1(&writer, &query_root, &expected, &lexical, &adjacency)
                .unwrap();
        let manifest: FileQueryIndexManifestV1 =
            serde_json::from_slice(&fs::read(query_root.join(&query_ref.path)).unwrap()).unwrap();
        let structural = vec![
            GraphQueryEntityV1::StructuralNode {
                entity_id: "node-a".to_owned(),
                node_kind: "code_symbol".to_owned(),
                label: "node a".to_owned(),
                source_logical_path: "src/a.rs".to_owned(),
                structural_provenance: json!({"input_kind":"typed_ir","input_id":"a","input_sha256":digest("a"),"source_snapshot_exact_set_sha256":expected.source_identity}),
                evidence: vec![json!({"evidence_id":"evidence:node-a"})],
            },
            GraphQueryEntityV1::StructuralNode {
                entity_id: "node-b".to_owned(),
                node_kind: "code_symbol".to_owned(),
                label: "node b".to_owned(),
                source_logical_path: "src/b.rs".to_owned(),
                structural_provenance: json!({"input_kind":"typed_ir","input_id":"b","input_sha256":digest("b"),"source_snapshot_exact_set_sha256":expected.source_identity}),
                evidence: vec![json!({"evidence_id":"evidence:node-b"})],
            },
            GraphQueryEntityV1::StructuralEdge {
                entity_id: "edge-a-b".to_owned(),
                edge_kind: "calls".to_owned(),
                source_node_id: "node-a".to_owned(),
                target_node_id: Some("node-b".to_owned()),
                target_reference: "node-b".to_owned(),
                resolution_state: QueryResolutionStateV1::Resolved,
                candidate_node_ids: Vec::new(),
                structural_provenance: json!({"input_kind":"typed_ir","input_id":"edge","input_sha256":digest("edge"),"source_snapshot_exact_set_sha256":expected.source_identity}),
                evidence: vec![json!({"evidence_id":"evidence:edge-a-b"})],
            },
        ];
        Self {
            workspace,
            evidence_root,
            expected,
            query_ref,
            index_manifest_sha256: manifest.index_manifest_sha256,
            structural,
        }
    }

    fn claim(&self, kind: &str, state: &str, structural_evidence: &str) -> GraphQueryEntityV1 {
        GraphQueryEntityV1::KnowledgeNode {
            entity_id: "claim-a".to_owned(),
            knowledge_kind: kind.to_owned(),
            label: "claim".to_owned(),
            claim_id: "claim-a".to_owned(),
            knowledge_state: state.to_owned(),
            structural_evidence_ids: vec![structural_evidence.to_owned()],
            overlay_provenance: json!({"structural_graph_sha256":self.expected.graph_identity,"accepted_claim_set_sha256":digest("accepted")}),
            evidence: vec![json!({"evidence_id":"evidence:node-a"})],
        }
    }
}

#[test]
fn q04_unsealed_or_cross_state_knowledge_cannot_enter_a_production_evidence_index() {
    let fixture = Fixture::new();
    let mut entities = fixture.structural.clone();
    entities.push(fixture.claim("accepted_claim", "accepted_grounded", "evidence:node-a"));
    let production = context(
        fixture.workspace.path(),
        TransportKind::Cli,
        EffectPolicy::WorkspaceWrite,
    );
    let error = write_graph_query_evidence_index_v1(
        &production,
        &fixture.evidence_root,
        &fixture.expected,
        &fixture.query_ref,
        &fixture.index_manifest_sha256,
        &entities,
    )
    .unwrap_err();
    assert_eq!(error.code(), "E_QUERY_KNOWLEDGE_UNATTESTED");

    let test_writer = context(
        fixture.workspace.path(),
        TransportKind::Test,
        EffectPolicy::WorkspaceWrite,
    );
    let mut cross_state = fixture.structural.clone();
    cross_state.push(fixture.claim("accepted_claim", "abstention", "evidence:node-a"));
    assert_eq!(
        write_graph_query_evidence_index_v1(
            &test_writer,
            &fixture.evidence_root,
            &fixture.expected,
            &fixture.query_ref,
            &fixture.index_manifest_sha256,
            &cross_state,
        ),
        Err(FileGraphQueryErrorV1::InvalidRequest)
    );
}

#[test]
fn q04_exposes_a_strict_writer_that_rebuilds_the_verified_overlay_input() {
    let _strict_writer: fn(
        &CallContext,
        &Path,
        &FileQueryExpectedIdentitiesV1,
        &FileReceiptRef,
        &str,
        &[GraphQueryEntityV1],
        &KnowledgeOverlayBuildInputV2,
    ) -> Result<FileReceiptRef, FileGraphQueryErrorV1> =
        write_graph_query_evidence_index_from_verified_overlay_v1;
}
