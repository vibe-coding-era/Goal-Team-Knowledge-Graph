use std::fs;
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

const NODE_COUNT: usize = 50;

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
        "source_logical_path": format!("src/module_{index:03}.rs"),
        "source_sha256": digest(&format!("source-{index}")),
        "byte_start": index * 10,
        "byte_end": index * 10 + 8,
        "snippet_sha256": digest(&format!("snippet-{index}")),
    })
}

fn expected() -> FileQueryExpectedIdentitiesV1 {
    FileQueryExpectedIdentitiesV1 {
        source_identity: digest("source"),
        graph_identity: digest("graph"),
        overlay_identity: digest("overlay"),
    }
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
        let expected = expected();

        let mut documents = Vec::new();
        let mut nodes = Vec::new();
        let mut edges = Vec::new();
        let mut entities = Vec::new();
        for index in 0..NODE_COUNT {
            let next = (index + 1) % NODE_COUNT;
            let node_id = format!("node-{index:03}");
            let edge_id = format!("edge-{index:03}");
            let target_id = format!("node-{next:03}");
            let node_evidence = format!("evidence:{node_id}");
            let edge_evidence = format!("evidence:{edge_id}");
            documents.push(LexicalDocumentV1 {
                node_id: node_id.clone(),
                evidence_ref: node_evidence.clone(),
                text: format!("{node_id} symbol_{index:03} shared node label"),
            });
            documents.push(LexicalDocumentV1 {
                node_id: edge_id.clone(),
                evidence_ref: edge_evidence.clone(),
                text: format!("{edge_id} calls {node_id} {target_id} shared edge"),
            });
            nodes.push(node_id.clone());
            edges.push(AdjacencyEdgeInputV1 {
                edge_id: edge_id.clone(),
                source_node_id: node_id.clone(),
                target_node_id: target_id.clone(),
                resolution_state: QueryResolutionStateV1::Resolved,
                evidence_ref: edge_evidence.clone(),
            });
            entities.push(GraphQueryEntityV1::StructuralNode {
                entity_id: node_id.clone(),
                node_kind: "code_symbol".to_owned(),
                label: format!("Symbol {index:03}"),
                source_logical_path: format!("src/module_{index:03}.rs"),
                structural_provenance: json!({
                    "input_kind": "typed_ir",
                    "input_id": format!("src/module_{index:03}.rs"),
                    "input_sha256": digest(&format!("typed-ir-{index}")),
                    "source_snapshot_exact_set_sha256": expected.source_identity,
                }),
                evidence: vec![evidence(&node_evidence, index)],
            });
            entities.push(GraphQueryEntityV1::StructuralEdge {
                entity_id: edge_id,
                edge_kind: "calls".to_owned(),
                source_node_id: node_id,
                target_node_id: Some(target_id.clone()),
                target_reference: target_id,
                resolution_state: QueryResolutionStateV1::Resolved,
                candidate_node_ids: Vec::new(),
                structural_provenance: json!({
                    "input_kind": "typed_ir",
                    "input_id": format!("src/module_{index:03}.rs"),
                    "input_sha256": digest(&format!("typed-ir-{index}")),
                    "source_snapshot_exact_set_sha256": expected.source_identity,
                }),
                evidence: vec![evidence(&edge_evidence, index)],
            });
        }
        documents.push(LexicalDocumentV1 {
            node_id: "claim-auth".to_owned(),
            evidence_ref: "evidence:claim-auth".to_owned(),
            text: "claim-auth verified_claim_auth shared accepted claim".to_owned(),
        });
        entities.push(GraphQueryEntityV1::KnowledgeNode {
            entity_id: "claim-auth".to_owned(),
            knowledge_kind: "accepted_claim".to_owned(),
            label: "Authentication is verified".to_owned(),
            claim_id: "claim-auth".to_owned(),
            knowledge_state: "accepted_grounded".to_owned(),
            structural_evidence_ids: vec!["evidence:node-000".to_owned()],
            overlay_provenance: json!({
                "structural_graph_sha256": expected.graph_identity,
                "accepted_claim_sha256": digest("accepted-claim-auth"),
            }),
            evidence: vec![evidence("evidence:claim-auth", NODE_COUNT)],
        });

        let lexical = vec![build_lexical_shard_v1("lex-gold", &documents).unwrap()];
        let adjacency = build_adjacency_routing_index_v1(&nodes, &edges).unwrap();
        let write_context = context(workspace.path(), EffectPolicy::WorkspaceWrite);
        let query_manifest_ref =
            write_file_query_index_v1(&write_context, &query_root, &expected, &lexical, &adjacency)
                .unwrap();
        let query_manifest: FileQueryIndexManifestV1 =
            serde_json::from_slice(&fs::read(query_root.join(&query_manifest_ref.path)).unwrap())
                .unwrap();
        let evidence_manifest_ref = write_graph_query_evidence_index_v1(
            &write_context,
            &evidence_root,
            &expected,
            &query_manifest_ref,
            &query_manifest.index_manifest_sha256,
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

    fn execute(&self, operation: FileGraphQueryOperationV1, payload: Value) -> Value {
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

    fn dispatcher_payload(&self, operation_fields: Value) -> Value {
        let mut value = operation_fields.as_object().unwrap().clone();
        value.insert("query_index_path".to_owned(), json!(".gtkg/query-index"));
        value.insert(
            "query_manifest_ref".to_owned(),
            serde_json::to_value(&self.query_manifest_ref).unwrap(),
        );
        value.insert(
            "evidence_index_path".to_owned(),
            json!(".gtkg/query-evidence"),
        );
        value.insert(
            "evidence_manifest_ref".to_owned(),
            serde_json::to_value(&self.evidence_manifest_ref).unwrap(),
        );
        value.insert(
            "expected_identities".to_owned(),
            serde_json::to_value(&self.expected).unwrap(),
        );
        Value::Object(value)
    }
}

fn assert_index_evidence(response: &Value) {
    assert_eq!(
        response["evidence_pack"]["graph_readback"]["graph_sha256"],
        digest("graph")
    );
    assert_eq!(
        response["evidence_pack"]["query_index"]["full_graph_read_count"],
        0
    );
    assert_eq!(
        response["evidence_pack"]["query_index"]["database_read_count"],
        0
    );
    assert_eq!(
        response["evidence_pack"]["query_index"]["network_call_count"],
        0
    );
    assert_eq!(
        response["evidence_pack"]["query_index"]["daemon_call_count"],
        0
    );
    assert!(
        response["evidence_pack"]["query_index"]["query_plans"]
            .as_array()
            .is_some_and(|plans| !plans.is_empty())
    );
    assert!(
        response["evidence_pack"]["evidence"]
            .as_array()
            .is_some_and(|items| !items.is_empty())
    );
}

#[test]
fn q04_runs_300_gold_queries_through_file_indices_with_evidence_pack_parity() {
    let fixture = Fixture::new();
    let mut observed = 0;
    for index in 0..NODE_COUNT {
        let next = (index + 1) % NODE_COUNT;
        let node_id = format!("node-{index:03}");
        let next_id = format!("node-{next:03}");
        let edge_id = format!("edge-{index:03}");

        let neighbors = fixture.execute(
            FileGraphQueryOperationV1::Neighbors,
            json!({"node_id": node_id, "direction": "outgoing", "max_results": 10}),
        );
        assert_eq!(
            neighbors["result"]["neighbors"][0]["neighbor_node_id"],
            next_id
        );
        assert_eq!(neighbors["result"]["neighbors"][0]["edge_id"], edge_id);
        assert_index_evidence(&neighbors);
        observed += 1;

        let path = fixture.execute(
            FileGraphQueryOperationV1::Path,
            json!({"source_node_id": node_id, "target_node_id": next_id, "max_depth": 1}),
        );
        assert_eq!(path["result"]["found"], true);
        assert_eq!(path["result"]["edge_ids"][0], edge_id);
        assert_index_evidence(&path);
        observed += 1;

        let impact = fixture.execute(
            FileGraphQueryOperationV1::Impact,
            json!({"node_id": node_id, "max_depth": 1, "max_results": 10}),
        );
        assert_eq!(impact["result"]["impacts"][0]["node_id"], next_id);
        assert_eq!(impact["result"]["impacts"][0]["label"], "confirmed");
        assert_index_evidence(&impact);
        observed += 1;

        let explain = fixture.execute(
            FileGraphQueryOperationV1::Explain,
            json!({"node_id": node_id, "max_results": 10}),
        );
        assert_eq!(explain["result"]["node"]["id"], node_id);
        assert_eq!(explain["result"]["relations"].as_array().unwrap().len(), 2);
        assert_index_evidence(&explain);
        observed += 1;

        let trace = fixture.execute(
            FileGraphQueryOperationV1::Trace,
            json!({"entity_id": node_id}),
        );
        assert_eq!(trace["result"]["entity_kind"], "node");
        assert_eq!(trace["result"]["entity_id"], node_id);
        assert_index_evidence(&trace);
        observed += 1;

        let search = fixture.execute(
            FileGraphQueryOperationV1::Search,
            json!({"query": format!("symbol_{index:03}"), "max_results": 10}),
        );
        assert_eq!(search["result"]["matches"][0]["entity_id"], node_id);
        assert_eq!(
            search["result"]["matches"][0]["knowledge_state"],
            "structural_only"
        );
        assert_index_evidence(&search);
        observed += 1;
    }
    assert_eq!(observed, 300);
}

#[test]
fn q04_search_preserves_claim_state_and_returns_explicit_no_answer() {
    let fixture = Fixture::new();
    let claim = fixture.execute(
        FileGraphQueryOperationV1::Search,
        json!({"query": "verified_claim_auth", "max_results": 10}),
    );
    assert_eq!(claim["result"]["answer_state"], "answered");
    assert_eq!(claim["result"]["matches"][0]["kind"], "accepted_claim");
    assert_eq!(
        claim["result"]["matches"][0]["knowledge_state"],
        "accepted_grounded"
    );
    assert_eq!(claim["result"]["matches"][0]["claim_id"], "claim-auth");
    assert_index_evidence(&claim);

    let absent = fixture.execute(
        FileGraphQueryOperationV1::Search,
        json!({"query": "definitely_absent_term", "max_results": 10}),
    );
    assert_eq!(absent["result"]["answer_state"], "no_answer");
    assert_eq!(absent["result"]["matches"], json!([]));
    assert_eq!(
        absent["evidence_pack"]["query_index"]["full_graph_read_count"],
        0
    );
}

#[test]
fn q04_continuation_is_bound_and_tamper_fails_closed() {
    let fixture = Fixture::new();
    let first = fixture.execute(
        FileGraphQueryOperationV1::Search,
        json!({"query": "shared", "max_results": 2}),
    );
    assert_eq!(first["result"]["matches"].as_array().unwrap().len(), 2);
    assert_eq!(first["result"]["truncated"], true);
    let token = first["result"]["continuation"].as_str().unwrap();
    assert!(token.starts_with("gtkgq4c1."));

    let second = fixture.execute(
        FileGraphQueryOperationV1::Search,
        json!({"query": "shared", "max_results": 2, "continuation": token}),
    );
    assert_eq!(second["result"]["matches"].as_array().unwrap().len(), 2);
    assert_ne!(
        first["result"]["matches"][0]["entity_id"],
        second["result"]["matches"][0]["entity_id"]
    );

    let mut tampered = token.as_bytes().to_vec();
    let last = tampered.len() - 1;
    tampered[last] = if tampered[last] == b'0' { b'1' } else { b'0' };
    let error = execute_file_graph_operation_v1(
        &context(fixture.workspace.path(), EffectPolicy::ReadOnly),
        &fixture.query_root,
        &fixture.query_manifest_ref,
        &fixture.evidence_root,
        &fixture.evidence_manifest_ref,
        &fixture.expected,
        FileGraphQueryOperationV1::Search,
        &json!({
            "query": "shared",
            "max_results": 2,
            "continuation": String::from_utf8(tampered).unwrap(),
        }),
    )
    .unwrap_err();
    assert_eq!(error.code(), "E_QUERY_CONTINUATION_INVALID");
}

#[test]
fn q04_stale_identity_budget_and_evidence_tamper_fail_closed() {
    let fixture = Fixture::new();
    let mut stale = fixture.expected.clone();
    stale.graph_identity = digest("other-graph");
    let stale_error = execute_file_graph_operation_v1(
        &context(fixture.workspace.path(), EffectPolicy::ReadOnly),
        &fixture.query_root,
        &fixture.query_manifest_ref,
        &fixture.evidence_root,
        &fixture.evidence_manifest_ref,
        &stale,
        FileGraphQueryOperationV1::Neighbors,
        &json!({"node_id": "node-000", "direction": "outgoing", "max_results": 10}),
    )
    .unwrap_err();
    assert_eq!(stale_error.code(), "E_QUERY_INDEX_STALE");

    let budget_error = execute_file_graph_operation_v1(
        &context(fixture.workspace.path(), EffectPolicy::ReadOnly),
        &fixture.query_root,
        &fixture.query_manifest_ref,
        &fixture.evidence_root,
        &fixture.evidence_manifest_ref,
        &fixture.expected,
        FileGraphQueryOperationV1::Impact,
        &json!({"node_id": "node-000", "max_depth": 9, "max_results": 10}),
    )
    .unwrap_err();
    assert_eq!(budget_error.code(), "E_QUERY_BUDGET_EXCEEDED");

    let manifest: FileGraphEvidenceManifestV1 = serde_json::from_slice(
        &fs::read(
            fixture
                .evidence_root
                .join(&fixture.evidence_manifest_ref.path),
        )
        .unwrap(),
    )
    .unwrap();
    let record = manifest
        .records
        .iter()
        .find(|record| record.entity_id == "node-000")
        .unwrap();
    fs::write(fixture.evidence_root.join(&record.relative_path), b"{}\n").unwrap();
    let tamper_error = execute_file_graph_operation_v1(
        &context(fixture.workspace.path(), EffectPolicy::ReadOnly),
        &fixture.query_root,
        &fixture.query_manifest_ref,
        &fixture.evidence_root,
        &fixture.evidence_manifest_ref,
        &fixture.expected,
        FileGraphQueryOperationV1::Trace,
        &json!({"entity_id": "node-000"}),
    )
    .unwrap_err();
    assert_eq!(tamper_error.code(), "E_QUERY_EVIDENCE_TAMPERED");
}

#[test]
fn q04_dispatcher_uses_only_new_index_payload_and_preserves_read_policy() {
    let fixture = Fixture::new();
    let request = OperationRequestV2::new(
        "graph.neighbors",
        "q04-dispatch",
        fixture.dispatcher_payload(
            json!({"node_id": "node-000", "direction": "outgoing", "max_results": 10}),
        ),
    );
    let dispatcher = Dispatcher;
    let response = dispatcher
        .execute_v2(
            &context(fixture.workspace.path(), EffectPolicy::ReadOnly),
            request,
        )
        .unwrap();
    assert_eq!(response.operation_id.as_str(), "graph.neighbors");
    assert_eq!(
        response.result["evidence_pack"]["query_index"]["full_graph_read_count"],
        0
    );

    let legacy = OperationRequestV2::new(
        "graph.neighbors",
        "q04-legacy-rejected",
        json!({
            "graph_artifact_path": "graph",
            "node_id": "node-000",
            "direction": "outgoing",
        }),
    );
    let error = dispatcher
        .execute_v2(
            &context(fixture.workspace.path(), EffectPolicy::ReadOnly),
            legacy,
        )
        .unwrap_err();
    assert_eq!(error.error.code, V2ErrorCode::InvalidRequest);
    assert!(error.error.message.contains("query_index_path"));
}
