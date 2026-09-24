include!("v03_q04_schema_runtime_parity_successor.rs");

use gtkg_protocol::v2::v2_operation_request_schema;

#[test]
fn q04_previous_page_schema_requires_continuation_exactly_where_runtime_does() {
    for operation in [
        V2OperationId::GraphNeighbors,
        V2OperationId::GraphImpact,
        V2OperationId::GraphExplain,
    ] {
        let schema = v2_operation_request_schema(operation);
        let payload_schema = &schema["properties"]["payload"];
        let all_of = payload_schema["allOf"].as_array().unwrap();
        assert!(all_of.iter().any(|rule| {
            rule["if"]["required"] == serde_json::json!(["previous_page"])
                && rule["then"]["required"] == serde_json::json!(["continuation"])
        }));
    }
    let without_continuation = payload(json!({
        "node_id":"node",
        "previous_page": {}
    }));
    assert!(
        validate_v2_operation_payload(V2OperationId::GraphNeighbors, &without_continuation)
            .is_err()
    );
}
