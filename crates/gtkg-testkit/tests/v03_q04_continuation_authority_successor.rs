use gtkg_core::v03::graph_query::FileGraphQueryErrorV1;

include!("v03_q04_file_graph_operations.rs");

#[test]
#[cfg(unix)]
fn q04_continuation_requires_private_persistent_authority_not_fabricated_page_content() {
    use std::os::unix::fs::PermissionsExt;

    let reference = Fixture::new();
    let reference_first = reference.execute(
        FileGraphQueryOperationV1::Impact,
        json!({"node_id":"node-000","max_depth":3,"max_results":1}),
    );
    let reference_second = reference.execute(
        FileGraphQueryOperationV1::Impact,
        json!({
            "node_id":"node-000",
            "max_depth":3,
            "max_results":1,
            "continuation":reference_first["continuation"]
        }),
    );
    let second_value = reference_second["result"]["impacts"][0].clone();

    let target = Fixture::new();
    let target_first = target.execute(
        FileGraphQueryOperationV1::Impact,
        json!({"node_id":"node-000","max_depth":3,"max_results":1}),
    );
    let token = target_first["continuation"].as_str().unwrap();
    let mut forged: Value =
        serde_json::from_slice(&hex::decode(token.strip_prefix("gtkgq4c1.").unwrap()).unwrap())
            .unwrap();
    let request_sha256 = forged["request_sha256"].as_str().unwrap().to_owned();
    let full_result_sha256 = forged["state"]["full_result_sha256"]
        .as_str()
        .unwrap()
        .to_owned();
    let previous_result_sha256 =
        gtkg_protocol::canonical_json_sha256(&vec![&second_value]).unwrap();
    let previous_page_sha256 = gtkg_protocol::canonical_json_sha256(&(
        FileGraphQueryOperationV1::Impact,
        request_sha256.as_str(),
        full_result_sha256.as_str(),
        1_usize,
        2_usize,
        previous_result_sha256.as_str(),
    ))
    .unwrap();
    forged["state"]["previous_start_offset"] = json!(1);
    forged["state"]["previous_end_offset"] = json!(2);
    forged["state"]["next_offset"] = json!(2);
    forged["state"]["previous_result_sha256"] = json!(previous_result_sha256);
    forged["state"]["previous_page_sha256"] = json!(previous_page_sha256);
    forged["continuation_sha256"] = json!("");
    forged["continuation_sha256"] = json!(gtkg_protocol::canonical_json_sha256(&forged).unwrap());
    let forged = format!(
        "gtkgq4c1.{}",
        hex::encode(serde_json::to_vec(&forged).unwrap())
    );
    let fabricated_previous_page = json!({
        "schema_version":"gtkg.structural-query-result/v3",
        "operation_id":"graph.impact",
        "mode":"file_index_structural",
        "result":{"impacts":[second_value]},
        "truncated":true,
        "continuation":forged,
        "evidence_pack":{"query_index":{"evidence_manifest_file_sha256":target.evidence_manifest_ref.sha256}}
    });
    let observed = execute_file_graph_operation_v1(
        &context(target.workspace.path(), EffectPolicy::ReadOnly),
        &target.query_root,
        &target.query_manifest_ref,
        &target.evidence_root,
        &target.evidence_manifest_ref,
        &target.expected,
        FileGraphQueryOperationV1::Impact,
        &json!({
            "node_id":"node-000",
            "max_depth":3,
            "max_results":1,
            "continuation":fabricated_previous_page["continuation"],
            "previous_page":fabricated_previous_page
        }),
    );
    assert_eq!(observed, Err(FileGraphQueryErrorV1::ContinuationInvalid));

    let control = target.evidence_root.join("control");
    let authorities = fs::read_dir(control)
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(authorities.len(), 1);
    let metadata = authorities[0].metadata().unwrap();
    assert!(metadata.is_file());
    assert_eq!(metadata.permissions().mode() & 0o077, 0);
    let authority: Value =
        serde_json::from_slice(&fs::read(authorities[0].path()).unwrap()).unwrap();
    assert_eq!(
        authority["schema_version"],
        "gtkg.file-graph-continuation-authority/v1"
    );
    assert_eq!(authority["key_hex"].as_str().unwrap().len(), 64);
    assert!(
        authority["authority_sha256"]
            .as_str()
            .unwrap()
            .starts_with("sha256:")
    );
}
