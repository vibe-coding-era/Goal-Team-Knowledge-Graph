//! T12A: all structural queries read verified T11A shards, stay bounded, and
//! never manufacture a claim/overlay answer.

use gtkg_core::graph_v3::{
    StructuralGraphBuildInputV3, TypedIrGraphInputV3, build_structural_graph_v3,
    write_structural_graph_v3,
};
use gtkg_core::structural_query_v3::{StructuralQueryOperationV3, execute_structural_query_v3};
use gtkg_core::{CallContext, Dispatcher, EffectPolicy, TransportKind};
use gtkg_extract::{build_typed_ir_v2, extract_path, resolve_local_typed_ir_v2};
use gtkg_protocol::v2::{
    OperationRequestV2, SourceBaselineIdentityV2, SourceCaptureModeV2, SourceEligibilityV2,
    SourceSnapshotDenominatorV2, SourceSnapshotEntryV2, SourceSnapshotV2, V2OperationId,
};
use serde_json::json;
use sha2::{Digest, Sha256};

const DIGEST: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn sha(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn graph_artifact() -> (tempfile::TempDir, gtkg_core::graph_v3::StructuralGraphV3) {
    graph_artifact_for_source("fn leaf() {}\nfn caller() { leaf(); }\n")
}

fn graph_artifact_for_source(
    source: &str,
) -> (tempfile::TempDir, gtkg_core::graph_v3::StructuralGraphV3) {
    let files = [("src/lib.rs", source)];
    let snapshot = SourceSnapshotV2 {
        schema_version: "gtkg.source-snapshot/v2".to_owned(),
        capture_mode: SourceCaptureModeV2::DirectoryExact,
        repository_id: "t12a".to_owned(),
        baseline: SourceBaselineIdentityV2 {
            kind: "directory".to_owned(),
            head: None,
            tree: None,
            status_sha256: DIGEST.to_owned(),
        },
        inventory: files
            .iter()
            .map(|(path, source)| SourceSnapshotEntryV2 {
                logical_path: (*path).to_owned(),
                content_sha256: sha(source.as_bytes()),
                bytes: source.len() as u64,
            })
            .collect(),
        omissions: Vec::new(),
        denominator: SourceSnapshotDenominatorV2 {
            discovered_entries: files.len() as u64,
            admitted_entries: files.len() as u64,
            omitted_entries: 0,
        },
        exact_set_sha256: String::new(),
        eligibility: SourceEligibilityV2 {
            development_eligible: true,
            source_release_candidate: false,
            environment_ready: false,
            release_ready: false,
        },
    }
    .with_exact_set_digest()
    .expect("snapshot");
    let temporary = tempfile::tempdir().expect("temporary");
    let mut typed_inputs = Vec::new();
    for (path, source) in files {
        let source_path = temporary.path().join(path);
        std::fs::create_dir_all(source_path.parent().expect("parent")).expect("parent");
        std::fs::write(&source_path, source).expect("source");
        let extracted = extract_path(&source_path).expect("extract");
        let ir = build_typed_ir_v2(&snapshot, path, &extracted).expect("IR");
        typed_inputs.push(TypedIrGraphInputV3 {
            ir: resolve_local_typed_ir_v2(&ir, source.as_bytes()).expect("resolve"),
            source_bytes: source.as_bytes().to_vec(),
        });
    }
    let graph = build_structural_graph_v3(&StructuralGraphBuildInputV3 {
        source_snapshot_exact_set_sha256: snapshot.exact_set_sha256,
        typed_inputs,
        document_relations: Vec::new(),
    })
    .expect("graph");
    let output = temporary.path().join("graph");
    write_structural_graph_v3(&output, &graph).expect("shards");
    (temporary, graph)
}

#[test]
fn structural_queries_read_shards_and_return_only_structural_evidence() {
    let (temporary, graph) = graph_artifact();
    let source = graph
        .edges
        .iter()
        .find(|edge| edge.kind == "calls")
        .expect("call edge")
        .source_node_id
        .clone();
    let target = graph
        .edges
        .iter()
        .find(|edge| edge.kind == "calls")
        .and_then(|edge| edge.target_node_id.clone())
        .expect("resolved target");
    let root = temporary.path().join("graph");
    let neighbors = execute_structural_query_v3(
        &root,
        StructuralQueryOperationV3::Neighbors,
        &json!({ "node_id": source, "direction": "outgoing" }),
    )
    .expect("neighbors");
    assert_eq!(neighbors["mode"], "structural_only");
    assert_eq!(
        neighbors["evidence_pack"]["graph_readback"]["graph_sha256"],
        graph.graph_sha256
    );
    assert_eq!(
        neighbors["result"]["neighbors"][0]["neighbor_node_id"],
        target
    );
    assert!(
        neighbors["evidence_pack"]["evidence"]
            .as_array()
            .is_some_and(|items| !items.is_empty())
    );

    let path = execute_structural_query_v3(
        &root,
        StructuralQueryOperationV3::Path,
        &json!({ "source_node_id": source, "target_node_id": target, "max_depth": 1 }),
    )
    .expect("path");
    assert_eq!(path["result"]["found"], true);
    let impact = execute_structural_query_v3(
        &root,
        StructuralQueryOperationV3::Impact,
        &json!({ "node_id": source, "max_depth": 1 }),
    )
    .expect("impact");
    assert_eq!(impact["result"]["impacts"][0]["label"], "confirmed");
    let explain = execute_structural_query_v3(
        &root,
        StructuralQueryOperationV3::Explain,
        &json!({ "node_id": source }),
    )
    .expect("explain");
    assert_eq!(explain["result"]["node"]["id"], source);
    let trace = execute_structural_query_v3(
        &root,
        StructuralQueryOperationV3::Trace,
        &json!({ "entity_id": target }),
    )
    .expect("trace");
    assert_eq!(
        trace["result"]["unavailable_lineage"],
        json!(["accepted_claim", "okf_verification"])
    );
}

#[test]
fn structural_query_is_bounded_and_fails_closed_on_tampered_readback_or_overlay_fields() {
    let (temporary, graph) = graph_artifact();
    let source = graph
        .edges
        .iter()
        .find(|edge| edge.kind == "calls")
        .expect("call edge")
        .source_node_id
        .clone();
    let root = temporary.path().join("graph");
    let error = execute_structural_query_v3(
        &root,
        StructuralQueryOperationV3::Impact,
        &json!({ "node_id": source, "max_depth": 9 }),
    )
    .expect_err("depth must be bounded");
    assert_eq!(error.code(), "E_V2_STRUCTURAL_QUERY_INVALID");
    let error = execute_structural_query_v3(
        &root,
        StructuralQueryOperationV3::Explain,
        &json!({ "node_id": source, "knowledge_overlay": "forbidden" }),
    )
    .expect_err("claims are forbidden");
    assert_eq!(error.code(), "E_V2_STRUCTURAL_QUERY_INVALID");
    let shard = root.join(&graph.shards[0].relative_path);
    let mut bytes = std::fs::read(&shard).expect("shard");
    bytes.push(b' ');
    std::fs::write(shard, bytes).expect("tamper");
    let error = execute_structural_query_v3(
        &root,
        StructuralQueryOperationV3::Neighbors,
        &json!({ "node_id": source }),
    )
    .expect_err("must reread and reject tampered shards");
    assert_eq!(error.code(), "E_V2_STRUCTURAL_QUERY_READBACK");
}

#[test]
fn structural_query_explicitly_truncates_adversarial_fanout() {
    let mut source = String::new();
    for index in 0..128 {
        source.push_str(&format!("fn leaf_{index}() {{}}\n"));
    }
    source.push_str("fn caller() {");
    for index in 0..128 {
        source.push_str(&format!(" leaf_{index}();"));
    }
    source.push_str(" }\n");
    let (temporary, graph) = graph_artifact_for_source(&source);
    let source_node = graph
        .nodes
        .iter()
        .find(|node| node.label == "caller")
        .expect("caller node")
        .id
        .clone();
    let result = execute_structural_query_v3(
        &temporary.path().join("graph"),
        StructuralQueryOperationV3::Neighbors,
        &json!({ "node_id": source_node, "direction": "outgoing", "max_results": 1 }),
    )
    .expect("bounded fanout query");
    assert_eq!(
        result["result"]["neighbors"].as_array().map(Vec::len),
        Some(1)
    );
    assert_eq!(result["truncated"], true);
}

#[cfg(unix)]
#[test]
fn structural_graph_readback_rejects_symlink_and_hardlink_artifacts() {
    let (temporary, graph) = graph_artifact();
    let root = temporary.path().join("graph");
    let shard = root.join(&graph.shards[0].relative_path);
    let external = temporary.path().join("external.json");
    std::fs::copy(&shard, &external).expect("copy shard");
    std::fs::remove_file(&shard).expect("remove shard");
    std::os::unix::fs::symlink(&external, &shard).expect("symlink shard");
    let error = execute_structural_query_v3(
        &root,
        StructuralQueryOperationV3::Neighbors,
        &json!({ "node_id": graph.nodes[0].id }),
    )
    .expect_err("symlink shard must fail");
    assert_eq!(error.code(), "E_V2_STRUCTURAL_QUERY_READBACK");

    let (temporary, graph) = graph_artifact();
    let root = temporary.path().join("graph");
    let manifest = root.join("manifest.json");
    let external = temporary.path().join("external-manifest.json");
    std::fs::copy(&manifest, &external).expect("copy manifest");
    std::fs::remove_file(&manifest).expect("remove manifest");
    std::os::unix::fs::symlink(&external, &manifest).expect("symlink manifest");
    let error = execute_structural_query_v3(
        &root,
        StructuralQueryOperationV3::Neighbors,
        &json!({ "node_id": graph.nodes[0].id }),
    )
    .expect_err("symlink manifest must fail");
    assert_eq!(error.code(), "E_V2_STRUCTURAL_QUERY_READBACK");

    let (temporary, graph) = graph_artifact();
    let root = temporary.path().join("graph");
    let shard = root.join(&graph.shards[0].relative_path);
    let external = temporary.path().join("external.json");
    std::fs::rename(&shard, &external).expect("move shard");
    std::fs::hard_link(&external, &shard).expect("hardlink shard");
    let error = execute_structural_query_v3(
        &root,
        StructuralQueryOperationV3::Neighbors,
        &json!({ "node_id": graph.nodes[0].id }),
    )
    .expect_err("hardlink shard must fail");
    assert_eq!(error.code(), "E_V2_STRUCTURAL_QUERY_READBACK");
}

#[test]
fn v2_dispatcher_reads_only_a_workspace_relative_verified_graph_artifact() {
    let (temporary, graph) = graph_artifact();
    let source = graph
        .edges
        .iter()
        .find(|edge| edge.kind == "calls")
        .expect("call edge")
        .source_node_id
        .clone();
    let context = CallContext::restricted(
        TransportKind::Test,
        vec![temporary.path().to_path_buf()],
        EffectPolicy::ReadOnly,
    )
    .expect("bounded context");
    let response = Dispatcher
        .execute_v2(
            &context,
            OperationRequestV2::new(
                "graph.neighbors",
                "t12a-v2",
                json!({
                    "graph_artifact_path": "graph",
                    "node_id": source,
                    "direction": "outgoing",
                }),
            ),
        )
        .expect("callable v2 structural query");
    assert_eq!(response.operation_id, V2OperationId::GraphNeighbors);
    assert_eq!(response.result["mode"], "structural_only");
    let error = Dispatcher
        .execute_v2(
            &context,
            OperationRequestV2::new(
                "graph.neighbors",
                "t12a-escape",
                json!({
                    "graph_artifact_path": "../graph",
                    "node_id": source,
                }),
            ),
        )
        .expect_err("workspace escape must fail");
    assert_eq!(
        error.error.code,
        gtkg_protocol::v2::V2ErrorCode::InvalidRequest
    );
    let shard = temporary
        .path()
        .join("graph")
        .join(&graph.shards[0].relative_path);
    let mut bytes = std::fs::read(&shard).expect("shard");
    bytes.push(b' ');
    std::fs::write(shard, bytes).expect("tamper shard");
    let error = Dispatcher
        .execute_v2(
            &context,
            OperationRequestV2::new(
                "graph.neighbors",
                "t12a-readback",
                json!({ "graph_artifact_path": "graph", "node_id": source }),
            ),
        )
        .expect_err("readback failure is distinct from payload invalidity");
    assert_eq!(
        error.error.code,
        gtkg_protocol::v2::V2ErrorCode::StructuralQueryReadbackFailed
    );
}
