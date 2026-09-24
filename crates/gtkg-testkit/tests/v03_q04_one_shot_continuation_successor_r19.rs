include!("v03_q04_file_graph_operations.rs");

use gtkg_core::v03::graph_query::FileGraphQueryErrorV1;

#[test]
fn q04_r19_no_previous_page_cursor_is_accepted_once_then_replay_fails_closed() {
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
    assert!(execute().is_ok());
    assert_eq!(execute(), Err(FileGraphQueryErrorV1::ContinuationInvalid));
}
