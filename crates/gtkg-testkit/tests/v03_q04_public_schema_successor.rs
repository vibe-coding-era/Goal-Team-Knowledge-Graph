use std::collections::BTreeSet;

use gtkg_app::v2_profile_discovery;
use gtkg_protocol::v2::{
    V2OperationId, v2_operation_request_schema, validate_v2_operation_payload,
};
use gtkg_protocol::v03::discovery_profiles_v03;
use serde_json::{Value, json};

const GRAPH_OPERATIONS: [V2OperationId; 6] = [
    V2OperationId::GraphNeighbors,
    V2OperationId::GraphPath,
    V2OperationId::GraphImpact,
    V2OperationId::GraphExplain,
    V2OperationId::GraphTrace,
    V2OperationId::GraphSearch,
];

const COMMON: [&str; 5] = [
    "evidence_index_path",
    "evidence_manifest_ref",
    "expected_identities",
    "query_index_path",
    "query_manifest_ref",
];

fn digest(label: &str) -> String {
    use sha2::{Digest, Sha256};
    format!("sha256:{}", hex::encode(Sha256::digest(label.as_bytes())))
}

fn common() -> Value {
    json!({
        "query_index_path": ".gtkg/query-index",
        "query_manifest_ref": {
            "path": "manifests/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.json",
            "sha256": digest("query-manifest-file"),
        },
        "evidence_index_path": ".gtkg/query-evidence",
        "evidence_manifest_ref": {
            "path": "manifests/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.json",
            "sha256": digest("evidence-manifest-file"),
        },
        "expected_identities": {
            "source_identity": digest("source"),
            "graph_identity": digest("graph"),
            "overlay_identity": digest("overlay"),
        }
    })
}

fn payload(operation: V2OperationId) -> Value {
    let mut object = common().as_object().unwrap().clone();
    let fields = match operation {
        V2OperationId::GraphNeighbors => {
            json!({"node_id": "node-a", "direction": "outgoing", "max_results": 10})
        }
        V2OperationId::GraphPath => {
            json!({"source_node_id": "node-a", "target_node_id": "node-b", "max_depth": 3})
        }
        V2OperationId::GraphImpact => {
            json!({"node_id": "node-a", "max_depth": 3, "max_results": 10})
        }
        V2OperationId::GraphExplain => json!({"node_id": "node-a", "max_results": 10}),
        V2OperationId::GraphTrace => json!({"entity_id": "node-a"}),
        V2OperationId::GraphSearch => json!({"query": "authentication", "max_results": 10}),
        _ => unreachable!(),
    };
    object.extend(fields.as_object().unwrap().clone());
    Value::Object(object)
}

fn operation_fields(
    operation: V2OperationId,
) -> (&'static [&'static str], &'static [&'static str]) {
    match operation {
        V2OperationId::GraphNeighbors => (
            &["node_id"],
            &["node_id", "direction", "max_results", "continuation"],
        ),
        V2OperationId::GraphPath => (
            &["source_node_id", "target_node_id"],
            &["source_node_id", "target_node_id", "max_depth"],
        ),
        V2OperationId::GraphImpact => (
            &["node_id"],
            &["node_id", "max_depth", "max_results", "continuation"],
        ),
        V2OperationId::GraphExplain => (&["node_id"], &["node_id", "max_results", "continuation"]),
        V2OperationId::GraphTrace => (&["entity_id"], &["entity_id"]),
        V2OperationId::GraphSearch => (&["query"], &["query", "max_results", "continuation"]),
        _ => unreachable!(),
    }
}

#[test]
fn q04_six_graph_operations_disclose_closed_constructible_payload_schemas() {
    for operation in GRAPH_OPERATIONS {
        let envelope = v2_operation_request_schema(operation);
        let schema = &envelope["properties"]["payload"];
        assert_eq!(schema["type"], "object", "{}", operation.as_str());
        assert_eq!(
            schema["additionalProperties"],
            false,
            "{}",
            operation.as_str()
        );
        let (required_operation, all_operation) = operation_fields(operation);
        let mut expected_required = COMMON.into_iter().collect::<BTreeSet<_>>();
        expected_required.extend(required_operation.iter().copied());
        let observed_required = schema["required"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            observed_required,
            expected_required,
            "{}",
            operation.as_str()
        );
        let mut expected_properties = COMMON.into_iter().collect::<BTreeSet<_>>();
        expected_properties.extend(all_operation.iter().copied());
        let observed_properties = schema["properties"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            observed_properties,
            expected_properties,
            "{}",
            operation.as_str()
        );
        assert!(!observed_properties.contains("graph_artifact_path"));
        assert!(!observed_properties.contains("overlay_artifact_path"));
        assert!(validate_v2_operation_payload(operation, &payload(operation)).is_ok());

        let mut unknown = payload(operation).as_object().unwrap().clone();
        unknown.insert("graph_artifact_path".to_owned(), json!("graph"));
        assert!(
            validate_v2_operation_payload(operation, &Value::Object(unknown)).is_err(),
            "{} accepted a legacy/unknown field",
            operation.as_str()
        );
    }
}

#[test]
fn q04_graph_profile_discovery_projects_the_same_six_input_schemas() {
    let graph = discovery_profiles_v03()
        .into_iter()
        .find(|profile| profile.profile_id.as_str() == "graph")
        .unwrap();
    let discovery = v2_profile_discovery(Some("graph"), Some(&graph.digest)).unwrap();
    let tools = discovery["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 6);
    for operation in GRAPH_OPERATIONS {
        let tool = tools
            .iter()
            .find(|tool| tool["x-gtkg-operation-id"] == operation.as_str())
            .unwrap();
        assert_eq!(
            tool["inputSchema"],
            v2_operation_request_schema(operation),
            "{} discovery schema drift",
            operation.as_str()
        );
    }
}
