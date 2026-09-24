use std::fs;
use std::path::Path;

use gtkg_core::v03::graph_query::{
    FileGraphQueryOperationV1, GraphQueryEntityV1, execute_file_graph_operation_v1,
    write_graph_query_evidence_index_v1,
};
use gtkg_core::v03::query::{
    AdjacencyEdgeInputV1, LexicalDocumentV1, build_adjacency_routing_index_v1,
    build_lexical_shard_v1, write_file_query_index_v1,
};
use gtkg_core::{CallContext, EffectPolicy, TransportKind};
use gtkg_protocol::canonical_json_sha256;
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

#[test]
fn q04_self_rehashed_slice_cursor_cannot_repeat_or_skip_the_actual_predecessor_page() {
    let workspace = tempfile::tempdir().unwrap();
    let query_root = workspace.path().join(".gtkg/query-index");
    let evidence_root = workspace.path().join(".gtkg/query-evidence");
    let expected = FileQueryExpectedIdentitiesV1 {
        source_identity: digest("source"),
        graph_identity: digest("graph"),
        overlay_identity: digest("overlay"),
    };
    let nodes = ["node-a", "node-b", "node-c", "node-d"]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let edges = ["node-b", "node-c", "node-d"]
        .into_iter()
        .enumerate()
        .map(|(index, target)| AdjacencyEdgeInputV1 {
            edge_id: format!("edge-{index}"),
            source_node_id: "node-a".to_owned(),
            target_node_id: target.to_owned(),
            resolution_state: QueryResolutionStateV1::Resolved,
            evidence_ref: format!("evidence:edge-{index}"),
        })
        .collect::<Vec<_>>();
    let documents = nodes
        .iter()
        .map(|node| LexicalDocumentV1 {
            node_id: node.clone(),
            evidence_ref: format!("evidence:{node}"),
            text: format!("{node} symbol"),
        })
        .chain(edges.iter().map(|edge| LexicalDocumentV1 {
            node_id: edge.edge_id.clone(),
            evidence_ref: edge.evidence_ref.clone(),
            text: format!("{} relation", edge.edge_id),
        }))
        .collect::<Vec<_>>();
    let lexical = vec![build_lexical_shard_v1("lex", &documents).unwrap()];
    let adjacency = build_adjacency_routing_index_v1(&nodes, &edges).unwrap();
    let writer = context(workspace.path(), EffectPolicy::WorkspaceWrite);
    let query_ref =
        write_file_query_index_v1(&writer, &query_root, &expected, &lexical, &adjacency).unwrap();
    let query_manifest: FileQueryIndexManifestV1 =
        serde_json::from_slice(&fs::read(query_root.join(&query_ref.path)).unwrap()).unwrap();
    let node_entities = nodes.iter().map(|node| GraphQueryEntityV1::StructuralNode {
        entity_id: node.clone(),
        node_kind: "code_symbol".to_owned(),
        label: node.clone(),
        source_logical_path: format!("src/{node}.rs"),
        structural_provenance: json!({"input_kind": "typed_ir", "input_id": node, "input_sha256": digest(node), "source_snapshot_exact_set_sha256": expected.source_identity}),
        evidence: vec![json!({"evidence_id": format!("evidence:{node}")})],
    });
    let edge_entities = edges.iter().map(|edge| GraphQueryEntityV1::StructuralEdge {
        entity_id: edge.edge_id.clone(),
        edge_kind: "calls".to_owned(),
        source_node_id: edge.source_node_id.clone(),
        target_node_id: Some(edge.target_node_id.clone()),
        target_reference: edge.target_node_id.clone(),
        resolution_state: edge.resolution_state,
        candidate_node_ids: Vec::new(),
        structural_provenance: json!({"input_kind": "typed_ir", "input_id": edge.edge_id, "input_sha256": digest(&edge.edge_id), "source_snapshot_exact_set_sha256": expected.source_identity}),
        evidence: vec![json!({"evidence_id": edge.evidence_ref})],
    });
    let entities = node_entities.chain(edge_entities).collect::<Vec<_>>();
    let evidence_ref = write_graph_query_evidence_index_v1(
        &writer,
        &evidence_root,
        &expected,
        &query_ref,
        &query_manifest.index_manifest_sha256,
        &entities,
    )
    .unwrap();
    let reader = context(workspace.path(), EffectPolicy::ReadOnly);
    let first = execute_file_graph_operation_v1(
        &reader,
        &query_root,
        &query_ref,
        &evidence_root,
        &evidence_ref,
        &expected,
        FileGraphQueryOperationV1::Neighbors,
        &json!({"node_id": "node-a", "direction": "outgoing", "max_results": 1}),
    )
    .unwrap();
    let token = first["continuation"].as_str().unwrap();
    let encoded = token.strip_prefix("gtkgq4c1.").unwrap();
    let mut forged: Value = serde_json::from_slice(&hex::decode(encoded).unwrap()).unwrap();
    forged["state"]["next_offset"] = json!(0);
    forged["continuation_sha256"] = json!("");
    forged["continuation_sha256"] = json!(canonical_json_sha256(&forged).unwrap());
    let forged = format!(
        "gtkgq4c1.{}",
        hex::encode(serde_json::to_vec(&forged).unwrap())
    );
    let error = execute_file_graph_operation_v1(
        &reader,
        &query_root,
        &query_ref,
        &evidence_root,
        &evidence_ref,
        &expected,
        FileGraphQueryOperationV1::Neighbors,
        &json!({"node_id": "node-a", "direction": "outgoing", "max_results": 1, "continuation": forged}),
    )
    .unwrap_err();
    assert_eq!(error.code(), "E_QUERY_CONTINUATION_INVALID");
}
