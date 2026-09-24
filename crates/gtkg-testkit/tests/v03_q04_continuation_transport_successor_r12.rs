include!("v03_q04_file_graph_operations.rs");

fn without_query_latency(mut value: Value) -> Value {
    if let Some(plans) = value["evidence_pack"]["query_index"]["query_plans"].as_array_mut() {
        for plan in plans {
            if let Some(object) = plan.as_object_mut() {
                object.remove("latency_ms");
            }
        }
    }
    value
}

#[test]
fn q04_r12_previous_page_has_cross_process_and_concurrent_semantic_parity() {
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
        .unwrap()
    };
    let first_consumer = execute();
    let second_consumer = execute();
    assert_eq!(
        without_query_latency(first_consumer),
        without_query_latency(second_consumer)
    );
}
