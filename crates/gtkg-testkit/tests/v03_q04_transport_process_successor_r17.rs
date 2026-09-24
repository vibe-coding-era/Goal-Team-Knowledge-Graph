include!("v03_q04_file_graph_operations.rs");

fn normalized_transport_result(mut value: Value) -> Value {
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
fn q04_transport_process_child() {
    let Some(input) = std::env::var_os("Q04_TRANSPORT_PROCESS_INPUT") else {
        return;
    };
    let output = std::env::var_os("Q04_TRANSPORT_PROCESS_OUTPUT").unwrap();
    let value: Value = serde_json::from_slice(&fs::read(input).unwrap()).unwrap();
    let root = PathBuf::from(value["root"].as_str().unwrap());
    let query_root = PathBuf::from(value["query_root"].as_str().unwrap());
    let evidence_root = PathBuf::from(value["evidence_root"].as_str().unwrap());
    let query_ref: FileReceiptRef = serde_json::from_value(value["query_ref"].clone()).unwrap();
    let evidence_ref: FileReceiptRef =
        serde_json::from_value(value["evidence_ref"].clone()).unwrap();
    let expected: FileQueryExpectedIdentitiesV1 =
        serde_json::from_value(value["expected"].clone()).unwrap();
    let result = execute_file_graph_operation_v1(
        &context(&root, EffectPolicy::ReadOnly),
        &query_root,
        &query_ref,
        &evidence_root,
        &evidence_ref,
        &expected,
        FileGraphQueryOperationV1::Impact,
        &value["payload"],
    )
    .unwrap();
    fs::write(output, serde_json::to_vec(&result).unwrap()).unwrap();
}

fn spawn_transport_child(input: &Path, output: &Path) -> std::process::Child {
    std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "q04_transport_process_child", "--nocapture"])
        .env("Q04_TRANSPORT_PROCESS_INPUT", input)
        .env("Q04_TRANSPORT_PROCESS_OUTPUT", output)
        .spawn()
        .unwrap()
}

#[test]
fn q04_r17_one_shot_process_and_parallel_consumers_preserve_semantic_continuation() {
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
    let input = fixture.workspace.path().join("transport-input.json");
    fs::write(
        &input,
        serde_json::to_vec(&json!({
            "root": fixture.workspace.path(),
            "query_root": fixture.query_root,
            "evidence_root": fixture.evidence_root,
            "query_ref": fixture.query_manifest_ref,
            "evidence_ref": fixture.evidence_manifest_ref,
            "expected": fixture.expected,
            "payload": payload,
        }))
        .unwrap(),
    )
    .unwrap();
    let first_output = fixture.workspace.path().join("transport-first.json");
    let second_output = fixture.workspace.path().join("transport-second.json");
    let mut first_child = spawn_transport_child(&input, &first_output);
    let mut second_child = spawn_transport_child(&input, &second_output);
    assert!(first_child.wait().unwrap().success());
    assert!(second_child.wait().unwrap().success());
    let first: Value = serde_json::from_slice(&fs::read(first_output).unwrap()).unwrap();
    let second: Value = serde_json::from_slice(&fs::read(second_output).unwrap()).unwrap();
    assert_eq!(
        normalized_transport_result(first),
        normalized_transport_result(second)
    );
}
