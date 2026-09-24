//! U04 immutable Red: a local Wiki/A2UI evidence drawer must be rebuilt from
//! actual Q04 file-index evidence and an accepted U03 Explorer receipt.  It
//! must expose Current and Replay separately, retain Q04 resolution/claim
//! states, and never turn labels into browser markup.

use std::fs;
use std::path::{Path, PathBuf};

use gtkg_core::v03::evidence_drawer::{
    EvidenceDrawerArtifactInputV1, build_evidence_drawer_from_artifacts_v1,
    read_evidence_drawer_v1, write_evidence_drawer_v1,
};
use gtkg_core::v03::explorer::{
    StaticGraphExplorerArtifactInputV2, StaticGraphExplorerReceiptV2,
    build_static_graph_explorer_from_artifacts_v2,
    create_static_graph_explorer_output_root_v2, write_static_graph_explorer_with_capability_v2,
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

fn sha256(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn context(roots: Vec<PathBuf>, policy: EffectPolicy) -> CallContext {
    CallContext::restricted(TransportKind::Test, roots, policy).unwrap()
}

fn evidence(id: &str, index: usize) -> Value {
    json!({
        "kind": "source_span",
        "evidence_id": id,
        "source_snapshot_exact_set_sha256": digest("u04-source"),
        "source_logical_path": format!("src/u04_{index}.rs"),
        "source_sha256": digest(&format!("u04-source-{index}")),
        "byte_start": index * 10,
        "byte_end": index * 10 + 8,
        "snippet_sha256": digest(&format!("u04-snippet-{index}")),
    })
}

struct Fixture {
    workspace: tempfile::TempDir,
    query_root: PathBuf,
    query_manifest_ref: FileReceiptRef,
    evidence_root: PathBuf,
    evidence_manifest_ref: FileReceiptRef,
    expected: FileQueryExpectedIdentitiesV1,
    explorer_receipt: StaticGraphExplorerReceiptV2,
    current_path: PathBuf,
    current_sha256: String,
    drawer_parent: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let workspace = tempfile::tempdir().unwrap();
        let query_root = workspace.path().join(".gtkg/query-index");
        let evidence_root = workspace.path().join(".gtkg/query-evidence");
        let expected = FileQueryExpectedIdentitiesV1 {
            source_identity: digest("u04-source"),
            graph_identity: digest("u04-graph"),
            overlay_identity: digest("u04-overlay"),
        };
        let documents = vec![
            LexicalDocumentV1 {
                node_id: "node-origin".to_owned(),
                evidence_ref: "evidence:node-origin".to_owned(),
                text: "drawer current origin trusted symbol".to_owned(),
            },
            LexicalDocumentV1 {
                node_id: "node-target".to_owned(),
                evidence_ref: "evidence:node-target".to_owned(),
                text: "drawer target symbol".to_owned(),
            },
            LexicalDocumentV1 {
                node_id: "edge-resolved".to_owned(),
                evidence_ref: "evidence:edge-resolved".to_owned(),
                text: "drawer resolved relation".to_owned(),
            },
            LexicalDocumentV1 {
                node_id: "edge-ambiguous".to_owned(),
                evidence_ref: "evidence:edge-ambiguous".to_owned(),
                text: "drawer ambiguous relation".to_owned(),
            },
            LexicalDocumentV1 {
                node_id: "edge-unsupported".to_owned(),
                evidence_ref: "evidence:edge-unsupported".to_owned(),
                text: "drawer unsupported relation".to_owned(),
            },
            LexicalDocumentV1 {
                node_id: "claim-accepted".to_owned(),
                evidence_ref: "evidence:claim-accepted".to_owned(),
                text: "drawer accepted claim".to_owned(),
            },
            LexicalDocumentV1 {
                node_id: "claim-abstained".to_owned(),
                evidence_ref: "evidence:claim-abstained".to_owned(),
                text: "drawer abstained claim".to_owned(),
            },
        ];
        let lexical = vec![build_lexical_shard_v1("u04-lex", &documents).unwrap()];
        let adjacency = build_adjacency_routing_index_v1(
            &["node-origin".to_owned(), "node-target".to_owned()],
            &[
                AdjacencyEdgeInputV1 {
                    edge_id: "edge-resolved".to_owned(),
                    source_node_id: "node-origin".to_owned(),
                    target_node_id: "node-target".to_owned(),
                    resolution_state: QueryResolutionStateV1::Resolved,
                    evidence_ref: "evidence:edge-resolved".to_owned(),
                },
                AdjacencyEdgeInputV1 {
                    edge_id: "edge-ambiguous".to_owned(),
                    source_node_id: "node-origin".to_owned(),
                    target_node_id: "node-target".to_owned(),
                    resolution_state: QueryResolutionStateV1::Ambiguous,
                    evidence_ref: "evidence:edge-ambiguous".to_owned(),
                },
                AdjacencyEdgeInputV1 {
                    edge_id: "edge-unsupported".to_owned(),
                    source_node_id: "node-origin".to_owned(),
                    target_node_id: "node-target".to_owned(),
                    resolution_state: QueryResolutionStateV1::Unsupported,
                    evidence_ref: "evidence:edge-unsupported".to_owned(),
                },
            ],
        )
        .unwrap();
        let entities = vec![
            GraphQueryEntityV1::StructuralNode {
                entity_id: "node-origin".to_owned(),
                node_kind: "code_symbol".to_owned(),
                label: "Current <img src=x onerror=globalThis.__u04_xss=true> origin".to_owned(),
                source_logical_path: "src/origin.rs".to_owned(),
                structural_provenance: json!({
                    "input_kind":"typed_ir", "input_id":"src/origin.rs",
                    "input_sha256":digest("u04-origin"),
                    "source_snapshot_exact_set_sha256":expected.source_identity,
                }),
                evidence: vec![evidence("evidence:node-origin", 0)],
            },
            GraphQueryEntityV1::StructuralNode {
                entity_id: "node-target".to_owned(),
                node_kind: "code_symbol".to_owned(),
                label: "Replay target".to_owned(),
                source_logical_path: "src/target.rs".to_owned(),
                structural_provenance: json!({
                    "input_kind":"typed_ir", "input_id":"src/target.rs",
                    "input_sha256":digest("u04-target"),
                    "source_snapshot_exact_set_sha256":expected.source_identity,
                }),
                evidence: vec![evidence("evidence:node-target", 1)],
            },
            edge("edge-resolved", QueryResolutionStateV1::Resolved, Vec::new(), 2, &expected),
            edge(
                "edge-ambiguous",
                QueryResolutionStateV1::Ambiguous,
                vec!["node-target".to_owned()],
                3,
                &expected,
            ),
            edge("edge-unsupported", QueryResolutionStateV1::Unsupported, Vec::new(), 4, &expected),
            GraphQueryEntityV1::KnowledgeNode {
                entity_id: "claim-accepted".to_owned(),
                knowledge_kind: "accepted_claim".to_owned(),
                label: "drawer accepted claim".to_owned(),
                claim_id: "claim-accepted".to_owned(),
                knowledge_state: "accepted_grounded".to_owned(),
                structural_evidence_ids: vec!["evidence:node-origin".to_owned()],
                overlay_provenance: json!({"structural_graph_sha256":expected.graph_identity}),
                evidence: vec![evidence("evidence:claim-accepted", 5)],
            },
            GraphQueryEntityV1::KnowledgeNode {
                entity_id: "claim-abstained".to_owned(),
                knowledge_kind: "abstention".to_owned(),
                label: "drawer abstained claim".to_owned(),
                claim_id: "claim-abstained".to_owned(),
                knowledge_state: "abstention".to_owned(),
                structural_evidence_ids: vec!["evidence:node-origin".to_owned()],
                overlay_provenance: json!({"structural_graph_sha256":expected.graph_identity}),
                evidence: vec![evidence("evidence:claim-abstained", 6)],
            },
        ];
        let u03_parent = workspace.path().join("u03-parent");
        let drawer_parent = workspace.path().join("u04-parent");
        fs::create_dir(&u03_parent).unwrap();
        fs::create_dir(&drawer_parent).unwrap();
        let write = context(
            vec![workspace.path().to_path_buf(), u03_parent.clone(), drawer_parent.clone()],
            EffectPolicy::WorkspaceWrite,
        );
        let query_manifest_ref =
            write_file_query_index_v1(&write, &query_root, &expected, &lexical, &adjacency).unwrap();
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
        let explorer_source = StaticGraphExplorerArtifactInputV2 {
            query_root: query_root.clone(),
            query_manifest_ref: query_manifest_ref.clone(),
            evidence_root: evidence_root.clone(),
            evidence_manifest_ref: evidence_manifest_ref.clone(),
            expected_identities: expected.clone(),
            search_query: "drawer".to_owned(),
            primary_entity_id: "node-origin".to_owned(),
            path_target_entity_id: "node-target".to_owned(),
        };
        let explorer_projection = build_static_graph_explorer_from_artifacts_v2(&write, &explorer_source)
            .unwrap();
        let explorer_capability = create_static_graph_explorer_output_root_v2(&write, &u03_parent)
            .unwrap();
        let explorer_receipt =
            write_static_graph_explorer_with_capability_v2(&explorer_capability, &explorer_projection)
                .unwrap();
        let current_path = workspace.path().join("CURRENT.json");
        let current_bytes = serde_json::to_vec_pretty(&json!({
            "schema_version":"gtkg.current/v1",
            "deliverable_id":"u04-local-drawer",
            "version":"0.3.0",
            "version_path":"versions/0.3.0",
            "tree_sha256":digest("u04-current-tree"),
            "manifest_sha256":evidence_manifest_ref.sha256,
        }))
        .unwrap();
        fs::write(&current_path, &current_bytes).unwrap();
        Self {
            workspace,
            query_root,
            query_manifest_ref,
            evidence_root,
            evidence_manifest_ref,
            expected,
            explorer_receipt,
            current_path,
            current_sha256: sha256(&current_bytes),
            drawer_parent,
        }
    }

    fn source(&self) -> EvidenceDrawerArtifactInputV1 {
        EvidenceDrawerArtifactInputV1 {
            query_root: self.query_root.clone(),
            query_manifest_ref: self.query_manifest_ref.clone(),
            evidence_root: self.evidence_root.clone(),
            evidence_manifest_ref: self.evidence_manifest_ref.clone(),
            expected_identities: self.expected.clone(),
            explorer_receipt: self.explorer_receipt.clone(),
            current_path: self.current_path.clone(),
            current_sha256: self.current_sha256.clone(),
            search_query: "drawer".to_owned(),
            unknown_query: "not-present-u04".to_owned(),
            explain_node_id: "node-origin".to_owned(),
        }
    }

    fn write_context(&self) -> CallContext {
        context(
            vec![
                self.workspace.path().to_path_buf(),
                self.drawer_parent.clone(),
                PathBuf::from(&self.explorer_receipt.site_root),
            ],
            EffectPolicy::WorkspaceWrite,
        )
    }
}

fn edge(
    id: &str,
    resolution_state: QueryResolutionStateV1,
    candidate_node_ids: Vec<String>,
    index: usize,
    expected: &FileQueryExpectedIdentitiesV1,
) -> GraphQueryEntityV1 {
    GraphQueryEntityV1::StructuralEdge {
        entity_id: id.to_owned(),
        edge_kind: "references".to_owned(),
        source_node_id: "node-origin".to_owned(),
        target_node_id: Some("node-target".to_owned()),
        target_reference: "node-target".to_owned(),
        resolution_state,
        candidate_node_ids,
        structural_provenance: json!({
            "input_kind":"typed_ir", "input_id":id,
            "input_sha256":digest(id),
            "source_snapshot_exact_set_sha256":expected.source_identity,
        }),
        evidence: vec![evidence(&format!("evidence:{id}"), index)],
    }
}

#[test]
fn u04_builds_a_receipt_bound_current_replay_drawer_from_actual_q04_evidence() {
    let fixture = Fixture::new();
    let projection = build_evidence_drawer_from_artifacts_v1(&fixture.write_context(), &fixture.source())
        .expect("actual Q04 + U03 + current.get evidence drawer");
    let value = serde_json::to_value(&projection).unwrap();
    assert_eq!(value["schema_version"], "gtkg.u04-evidence-drawer/v1");
    assert_eq!(value["source_kind"], "q04_file_index_artifacts");
    assert_eq!(value["current"]["state"], "current_discovery_only");
    assert_eq!(value["replay"]["state"], "replay_read_only");
    assert_eq!(value["unknown"]["answer_state"], "unknown");
    assert_eq!(value["conflicts"], json!([]));
    assert!(value["relations"].as_array().unwrap().iter().any(|relation| relation["resolution"] == "resolved"));
    assert!(value["relations"].as_array().unwrap().iter().any(|relation| relation["resolution"] == "ambiguous"));
    assert!(value["relations"].as_array().unwrap().iter().any(|relation| relation["resolution"] == "unsupported"));
    assert!(value["claim_states"].as_array().unwrap().iter().any(|state| state["state"] == "accepted_grounded"));
    assert!(value["claim_states"].as_array().unwrap().iter().any(|state| state["state"] == "abstention"));
    assert_eq!(value["q04_execution_count"], 3);
    assert_eq!(value["network_calls"], 0);
    assert_eq!(value["database_reads"], 0);
    assert_eq!(value["target_execution_count"], 0);

    let output_root = fixture.drawer_parent.join("drawer");
    let receipt = write_evidence_drawer_v1(&fixture.write_context(), &output_root, &projection)
        .expect("drawer write");
    let readback = read_evidence_drawer_v1(&fixture.write_context(), &receipt).expect("drawer readback");
    assert_eq!(readback, projection);
    let stream = fs::read_to_string(output_root.join("a2ui/stream.jsonl")).unwrap();
    assert_eq!(stream.lines().count(), 3);
    assert!(stream.contains("https://a2ui.org/specification/v0_9/catalogs/basic/catalog.json"));
    assert!(stream.contains("Current"));
    assert!(stream.contains("Replay"));
    let html = fs::read_to_string(output_root.join("index.html")).unwrap();
    assert!(html.contains("data-evidence-drawer=\"q04-u04\""));
    assert!(html.contains("textContent"));
    assert!(!html.contains("innerHTML"));
    assert!(!html.contains("https://"));
    assert!(!html.contains("src=\"http"));
}

#[test]
fn u04_rejects_forged_u03_or_current_bindings_without_substituting_data() {
    let fixture = Fixture::new();
    let mut forged_explorer = fixture.source();
    forged_explorer.explorer_receipt.index_sha256 = digest("forged-u03-index");
    let error = build_evidence_drawer_from_artifacts_v1(&fixture.write_context(), &forged_explorer)
        .expect_err("forged U03 receipt must fail closed");
    assert_eq!(error.code(), "E_U04_U03_BINDING");

    let mismatch_path = fixture.workspace.path().join("CURRENT-mismatch.json");
    let mismatch = serde_json::to_vec_pretty(&json!({
        "schema_version":"gtkg.current/v1",
        "deliverable_id":"u04-local-drawer",
        "version":"0.3.0",
        "version_path":"versions/0.3.0",
        "tree_sha256":digest("u04-current-tree"),
        "manifest_sha256":digest("wrong-q04-manifest"),
    }))
    .unwrap();
    fs::write(&mismatch_path, &mismatch).unwrap();
    let mut forged_current = fixture.source();
    forged_current.current_path = mismatch_path;
    forged_current.current_sha256 = sha256(&mismatch);
    let error = build_evidence_drawer_from_artifacts_v1(&fixture.write_context(), &forged_current)
        .expect_err("current unrelated to Q04 evidence must fail closed");
    assert_eq!(error.code(), "E_U04_CURRENT_BINDING");
}

#[test]
#[ignore = "emits a U04 capability-bound actual-Q04 browser fixture"]
fn emit_u04_actual_q04_browser_fixture() {
    let parent = PathBuf::from(std::env::var("GTKG_U04_BROWSER_OUTPUT_PARENT").unwrap());
    assert!(parent.is_dir());
    assert!(fs::read_dir(&parent).unwrap().next().is_none());
    let fixture = Fixture::new();
    let context = context(
        vec![
            fixture.workspace.path().to_path_buf(),
            fixture.drawer_parent.clone(),
            parent.clone(),
            PathBuf::from(&fixture.explorer_receipt.site_root),
        ],
        EffectPolicy::WorkspaceWrite,
    );
    let projection = build_evidence_drawer_from_artifacts_v1(&context, &fixture.source()).unwrap();
    let receipt = write_evidence_drawer_v1(&context, &parent.join("site"), &projection).unwrap();
    fs::write(
        parent.join("browser-fixture-receipt.json"),
        serde_json::to_vec_pretty(&receipt).unwrap(),
    )
    .unwrap();

    let check = execute_file_graph_operation_v1(
        &context,
        &fixture.query_root,
        &fixture.query_manifest_ref,
        &fixture.evidence_root,
        &fixture.evidence_manifest_ref,
        &fixture.expected,
        FileGraphQueryOperationV1::Search,
        &json!({"query":"drawer","max_results":64}),
    )
    .unwrap();
    assert_eq!(check["operation_id"], "graph.search");
}
