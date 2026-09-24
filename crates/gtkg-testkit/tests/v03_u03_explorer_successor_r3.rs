//! U03 r3 immutable successor: capability-bound Explorer output and actual
//! Q04 artifact reads.  This test intentionally does not accept caller-made
//! JSON graph responses.

use std::fs;
use std::path::{Path, PathBuf};

use gtkg_core::v03::explorer::{
    StaticGraphExplorerArtifactInputV2, StaticGraphExplorerInputV1,
    build_static_graph_explorer_from_artifacts_v2, build_static_graph_explorer_v1,
    create_static_graph_explorer_output_root_v2, write_static_graph_explorer_v1,
    write_static_graph_explorer_with_capability_v2,
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

fn context(roots: Vec<PathBuf>, policy: EffectPolicy) -> CallContext {
    CallContext::restricted(TransportKind::Test, roots, policy).unwrap()
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
        let write = context(vec![workspace.path().to_path_buf()], EffectPolicy::WorkspaceWrite);
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

    fn source(&self) -> StaticGraphExplorerArtifactInputV2 {
        StaticGraphExplorerArtifactInputV2 {
            query_root: self.query_root.clone(),
            query_manifest_ref: self.query_manifest_ref.clone(),
            evidence_root: self.evidence_root.clone(),
            evidence_manifest_ref: self.evidence_manifest_ref.clone(),
            expected_identities: self.expected.clone(),
            search_query: "authenticated".to_owned(),
            primary_entity_id: "node-a".to_owned(),
            path_target_entity_id: "node-b".to_owned(),
        }
    }

    fn original_response_input(&self) -> StaticGraphExplorerInputV1 {
        let read = context(vec![self.workspace.path().to_path_buf()], EffectPolicy::ReadOnly);
        let query = |operation, payload| {
            execute_file_graph_operation_v1(
                &read,
                &self.query_root,
                &self.query_manifest_ref,
                &self.evidence_root,
                &self.evidence_manifest_ref,
                &self.expected,
                operation,
                &payload,
            )
            .unwrap()
        };
        StaticGraphExplorerInputV1 {
            search: query(
                FileGraphQueryOperationV1::Search,
                json!({"query":"authenticated","max_results":10}),
            ),
            neighbors: query(
                FileGraphQueryOperationV1::Neighbors,
                json!({"node_id":"node-a","direction":"outgoing","max_results":10}),
            ),
            path: query(
                FileGraphQueryOperationV1::Path,
                json!({"source_node_id":"node-a","target_node_id":"node-b","max_depth":2}),
            ),
            impact: query(
                FileGraphQueryOperationV1::Impact,
                json!({"node_id":"node-a","max_depth":2,"max_results":10}),
            ),
            trace: query(FileGraphQueryOperationV1::Trace, json!({"entity_id":"node-a"})),
        }
    }
}

fn build_real_site(parent: &Path) -> (Value, PathBuf) {
    let fixture = Fixture::new();
    let write = context(
        vec![fixture.workspace.path().to_path_buf(), parent.to_path_buf()],
        EffectPolicy::WorkspaceWrite,
    );
    let projection = build_static_graph_explorer_from_artifacts_v2(&write, &fixture.source()).unwrap();
    let capability = create_static_graph_explorer_output_root_v2(&write, parent).unwrap();
    let root = capability.path().to_path_buf();
    let receipt = write_static_graph_explorer_with_capability_v2(&capability, &projection).unwrap();
    (serde_json::to_value(receipt).unwrap(), root)
}

#[test]
fn u03_successor_uses_actual_q04_artifacts_and_a_nonserializable_output_capability() {
    let parent = tempfile::tempdir().unwrap();
    let (receipt, root) = build_real_site(parent.path());
    assert_eq!(receipt["schema_version"], "gtkg.static-graph-explorer-receipt/v2");
    assert_eq!(receipt["source_kind"], "q04_file_index_artifacts");
    assert_eq!(receipt["network_calls"], 0);
    assert_eq!(receipt["database_reads"], 0);
    assert_eq!(receipt["target_execution_count"], 0);
    assert!(root.starts_with(parent.path()));
    assert!(root.join("index.html").is_file());
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        assert_eq!(fs::metadata(&root).unwrap().mode() & 0o777, 0o700);
    }
}

#[test]
fn u03_successor_rejects_forged_legacy_responses_and_identity_drift() {
    let fixture = Fixture::new();
    let read = context(vec![fixture.workspace.path().to_path_buf()], EffectPolicy::ReadOnly);
    let forged = fixture.original_response_input();
    assert_eq!(
        build_static_graph_explorer_v1(&forged).unwrap_err().code(),
        "E_EXPLORER_LEGACY_INPUT_REJECTED"
    );
    let mut source = fixture.source();
    source.expected_identities.graph_identity = digest("forged-graph");
    assert_eq!(
        build_static_graph_explorer_from_artifacts_v2(&read, &source)
            .unwrap_err()
            .code(),
        "E_EXPLORER_Q04_ARTIFACT_REJECTED"
    );
}

#[test]
fn u03_successor_rejects_cross_root_symlink_and_existing_arbitrary_output_roots() {
    let fixture = Fixture::new();
    let parent = tempfile::tempdir().unwrap();
    let isolated = context(vec![fixture.workspace.path().to_path_buf()], EffectPolicy::WorkspaceWrite);
    assert_eq!(
        create_static_graph_explorer_output_root_v2(&isolated, parent.path())
            .unwrap_err()
            .code(),
        "E_EXPLORER_CAPABILITY_PARENT_REJECTED"
    );

    let write = context(
        vec![fixture.workspace.path().to_path_buf(), parent.path().to_path_buf()],
        EffectPolicy::WorkspaceWrite,
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let link = fixture.workspace.path().join("u03-output-parent-link");
        symlink(parent.path(), &link).unwrap();
        assert_eq!(
            create_static_graph_explorer_output_root_v2(&write, &link)
                .unwrap_err()
                .code(),
            "E_EXPLORER_OUTPUT_PARENT_SYMLINK"
        );
    }

    let arbitrary = parent.path().join("caller-selected-existing-root");
    fs::create_dir(&arbitrary).unwrap();
    let projection = build_static_graph_explorer_from_artifacts_v2(&write, &fixture.source()).unwrap();
    assert_eq!(
        write_static_graph_explorer_v1(&write, &arbitrary, &projection)
            .unwrap_err()
            .code(),
        "E_EXPLORER_CAPABILITY_REQUIRED"
    );
    let capability = create_static_graph_explorer_output_root_v2(&write, parent.path()).unwrap();
    let root = capability.path().to_path_buf();
    assert_ne!(root, arbitrary);
    write_static_graph_explorer_with_capability_v2(&capability, &projection).unwrap();
    assert_eq!(
        write_static_graph_explorer_with_capability_v2(&capability, &projection)
            .unwrap_err()
            .code(),
        "E_EXPLORER_CAPABILITY_MISMATCH"
    );
}

#[test]
#[ignore = "emits a capability-bound, actual-Q04 browser fixture for the r3 harness"]
fn emit_u03_capability_bound_browser_fixture_r3() {
    let parent = PathBuf::from(std::env::var("GTKG_U03_BROWSER_OUTPUT_PARENT").unwrap());
    assert!(parent.is_dir(), "browser harness must create the authorized parent");
    assert!(fs::read_dir(&parent).unwrap().next().is_none(), "parent must start empty");
    let (receipt, _root) = build_real_site(&parent);
    fs::write(
        parent.join("browser-fixture-receipt.json"),
        serde_json::to_vec_pretty(&receipt).unwrap(),
    )
    .unwrap();
}
