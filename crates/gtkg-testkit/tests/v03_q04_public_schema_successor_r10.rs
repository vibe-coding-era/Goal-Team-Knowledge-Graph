include!("v03_q04_public_schema_successor.rs");

#[test]
fn q04_r10_closed_schemas_include_previous_page_only_for_structural_slices() {
    for operation in GRAPH_OPERATIONS {
        let envelope = v2_operation_request_schema(operation);
        let schema = &envelope["properties"]["payload"];
        let mut expected = COMMON.into_iter().collect::<BTreeSet<_>>();
        let operation_fields = match operation {
            V2OperationId::GraphNeighbors => &[
                "node_id",
                "direction",
                "max_results",
                "continuation",
                "previous_page",
            ][..],
            V2OperationId::GraphPath => &["source_node_id", "target_node_id", "max_depth"],
            V2OperationId::GraphImpact => &[
                "node_id",
                "max_depth",
                "max_results",
                "continuation",
                "previous_page",
            ],
            V2OperationId::GraphExplain => {
                &["node_id", "max_results", "continuation", "previous_page"]
            }
            V2OperationId::GraphTrace => &["entity_id"],
            V2OperationId::GraphSearch => &["query", "max_results", "continuation"],
            _ => unreachable!(),
        };
        expected.extend(operation_fields.iter().copied());
        let observed = schema["properties"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        assert_eq!(observed, expected, "{}", operation.as_str());
        assert_eq!(schema["additionalProperties"], false);
        assert!(validate_v2_operation_payload(operation, &payload(operation)).is_ok());
    }
}
