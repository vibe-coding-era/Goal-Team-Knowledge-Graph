use gtkg_protocol::v2::{V2OperationId, validate_v2_operation_payload};
use serde_json::{Value, json};

fn digest(character: char) -> String {
    format!("sha256:{}", character.to_string().repeat(64))
}

fn common() -> serde_json::Map<String, Value> {
    json!({
        "query_index_path": ".gtkg/query-index",
        "query_manifest_ref": {"path":format!("manifests/{}.json", "a".repeat(64)),"sha256":digest('a')},
        "evidence_index_path": ".gtkg/query-evidence",
        "evidence_manifest_ref": {"path":format!("manifests/{}.json", "b".repeat(64)),"sha256":digest('b')},
        "expected_identities": {
            "source_identity": digest('c'),
            "graph_identity": digest('d'),
            "overlay_identity": digest('e')
        }
    })
    .as_object()
    .unwrap()
    .clone()
}

fn payload(fields: Value) -> Value {
    let mut object = common();
    object.extend(fields.as_object().unwrap().clone());
    Value::Object(object)
}

#[test]
fn q04_optional_fields_reject_explicit_null_exactly_as_the_public_schema_does() {
    let cases = [
        (
            V2OperationId::GraphNeighbors,
            json!({"node_id":"node","direction":null}),
        ),
        (
            V2OperationId::GraphNeighbors,
            json!({"node_id":"node","max_results":null}),
        ),
        (
            V2OperationId::GraphNeighbors,
            json!({"node_id":"node","continuation":null}),
        ),
        (
            V2OperationId::GraphPath,
            json!({"source_node_id":"a","target_node_id":"b","max_depth":null}),
        ),
        (
            V2OperationId::GraphImpact,
            json!({"node_id":"node","max_depth":null}),
        ),
        (
            V2OperationId::GraphImpact,
            json!({"node_id":"node","max_results":null}),
        ),
        (
            V2OperationId::GraphImpact,
            json!({"node_id":"node","continuation":null}),
        ),
        (
            V2OperationId::GraphExplain,
            json!({"node_id":"node","max_results":null}),
        ),
        (
            V2OperationId::GraphExplain,
            json!({"node_id":"node","continuation":null}),
        ),
        (
            V2OperationId::GraphSearch,
            json!({"query":"term","max_results":null}),
        ),
        (
            V2OperationId::GraphSearch,
            json!({"query":"term","continuation":null}),
        ),
    ];
    for (operation, value) in cases {
        assert!(
            validate_v2_operation_payload(operation, &payload(value)).is_err(),
            "{} accepted an explicit null excluded by its schema",
            operation.as_str()
        );
    }
}

#[test]
fn q04_query_budget_uses_unicode_scalar_count_at_schema_and_runtime() {
    let within = payload(json!({"query":"界".repeat(300)}));
    assert!(validate_v2_operation_payload(V2OperationId::GraphSearch, &within).is_ok());

    let boundary = payload(json!({"query":"界".repeat(512)}));
    assert!(validate_v2_operation_payload(V2OperationId::GraphSearch, &boundary).is_ok());

    let over = payload(json!({"query":"界".repeat(513)}));
    assert!(validate_v2_operation_payload(V2OperationId::GraphSearch, &over).is_err());
}
