include!("v03_q04_file_graph_operations.rs");

#[test]
fn q04_structural_continuation_survives_process_state_loss_and_parallel_consumers() {
    let fixture = Fixture::new();
    let first = fixture.execute(
        FileGraphQueryOperationV1::Impact,
        json!({"node_id":"node-000","max_depth":3,"max_results":1}),
    );
    let payload = json!({
        "node_id":"node-000",
        "max_depth":3,
        "max_results":1,
        "continuation":first["continuation"],
        "previous_page":first
    });
    let execute = || {
        execute_file_graph_operation_v1(
            &context(fixture.workspace.path(), EffectPolicy::ReadOnly),
            &fixture.query_root,
            &fixture.query_manifest_ref,
            &fixture.evidence_root,
            &fixture.evidence_manifest_ref,
            &fixture.expected,
            FileGraphQueryOperationV1::Impact,
            &payload,
        )
    };
    let first_consumer = execute().unwrap();
    let second_consumer = execute().unwrap();
    assert_eq!(first_consumer, second_consumer);
    assert_eq!(
        first_consumer["result"]["impacts"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}
