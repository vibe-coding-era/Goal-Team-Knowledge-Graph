include!("v03_p06_transport_e2e_contract.rs");

fn current_binary_r4() -> PathBuf {
    let path = PathBuf::from(std::env::var_os("GTKG_BIN").expect("P06 r4 requires GTKG_BIN"));
    let expected = std::env::var("P06_BINARY_SHA256").expect("P06 r4 requires P06_BINARY_SHA256");
    assert!(path.is_file());
    assert_eq!(sha256(&fs::read(&path).unwrap()), expected);
    path
}

fn graph_common_r4() -> serde_json::Map<String, Value> {
    json!({
        "query_index_path": "query-index",
        "query_manifest_ref": {
            "path": "manifests/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.json",
            "sha256": digest('a')
        },
        "evidence_index_path": "evidence-index",
        "evidence_manifest_ref": {
            "path": "manifests/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.json",
            "sha256": digest('b')
        },
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

fn current_payload_r4(fixture: &Fixture, operation: V2OperationId) -> Value {
    let graph_fields = match operation {
        V2OperationId::GraphNeighbors => Some(json!({
            "node_id": "p06-node", "direction": "outgoing", "max_results": 1
        })),
        V2OperationId::GraphPath => Some(json!({
            "source_node_id": "p06-source", "target_node_id": "p06-target", "max_depth": 2
        })),
        V2OperationId::GraphImpact => Some(json!({
            "node_id": "p06-node", "max_depth": 2, "max_results": 1
        })),
        V2OperationId::GraphExplain => Some(json!({"node_id": "p06-node", "max_results": 1})),
        V2OperationId::GraphTrace => Some(json!({"entity_id": "p06-node"})),
        V2OperationId::GraphSearch => Some(json!({"query": "p06", "max_results": 1})),
        _ => None,
    };
    let Some(fields) = graph_fields else {
        return fixture.payload(operation);
    };
    let mut value = graph_common_r4();
    value.extend(fields.as_object().unwrap().clone());
    Value::Object(value)
}

fn cli_call_explicit_r4(
    binary: &Path,
    root: &Path,
    profile_digest: &str,
    operation: &str,
    request: &Value,
) -> Value {
    let mut child = Command::new(binary)
        .args([
            "v2-op",
            operation,
            "--profile",
            "all",
            "--profile-digest",
            profile_digest,
            "--request",
            "-",
            "--output",
            "json",
        ])
        .current_dir(root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    serde_json::to_writer(child.stdin.as_mut().unwrap(), request).unwrap();
    drop(child.stdin.take());
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "current explicit-profile CLI failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn p06_r4_rebuilt_binary_has_current_46_cli_mcp_profile_parity() {
    let fixture = Fixture::new();
    let binary = current_binary_r4();
    let all = discovery_profiles_v03()
        .into_iter()
        .find(|profile| profile.profile_id.as_str() == "all")
        .unwrap();
    let mut mcp = LineChild::spawn_v2(&binary, fixture.root(), "all", Some(&all.digest));
    let listed = mcp.send(json!({
        "jsonrpc": "2.0", "id": "p06-r4-list", "method": "tools/list", "params": {}
    }));
    assert_eq!(listed["result"]["tools"].as_array().unwrap().len(), 46);

    let mut callable = BTreeSet::new();
    let mut denied = BTreeSet::new();
    let mut negative = BTreeSet::new();
    for definition in V2_PUBLIC_OPERATIONS {
        let operation = definition.id;
        let request = OperationRequestV2::new(
            operation.as_str(),
            format!("p06-r4-{}", operation.as_str()),
            current_payload_r4(&fixture, operation),
        );
        let request_value = serde_json::to_value(&request).unwrap();
        let cli = cli_call_explicit_r4(
            &binary,
            fixture.root(),
            &all.digest,
            operation.as_str(),
            &request_value,
        );
        let rpc = mcp.send(json!({
            "jsonrpc": "2.0",
            "id": format!("p06-r4-mcp-{}", operation.as_str()),
            "method": "tools/call",
            "params": {"name": operation.mcp_tool_name(), "arguments": request}
        }));
        assert_eq!(
            rpc["result"]["structuredContent"],
            cli,
            "{}",
            operation.as_str()
        );
        if definition.callability == CallabilityV2::DeniedByPolicy {
            assert_eq!(cli["error"]["code"], "E_SIDE_EFFECT_DENIED");
            denied.insert(operation);
        } else if let Some(error) = cli.get("error") {
            assert_ne!(error["stage"], "request-schema");
            assert_ne!(error["stage"], "payload-schema");
            assert_ne!(error["stage"], "dispatch");
            callable.insert(operation);
        } else {
            callable.insert(operation);
        }

        let invalid = json!({
            "protocol_version": PROTOCOL_VERSION_V2,
            "operation_id": operation.as_str(),
            "request_id": format!("p06-r4-invalid-{}", operation.as_str()),
            "payload": current_payload_r4(&fixture, operation),
            "unexpected_transport_field": true
        });
        let cli_invalid = cli_call_explicit_r4(
            &binary,
            fixture.root(),
            &all.digest,
            operation.as_str(),
            &invalid,
        );
        let rpc_invalid = mcp.send(json!({
            "jsonrpc": "2.0",
            "id": format!("p06-r4-invalid-mcp-{}", operation.as_str()),
            "method": "tools/call",
            "params": {"name": operation.mcp_tool_name(), "arguments": invalid}
        }));
        assert_eq!(rpc_invalid["result"]["structuredContent"], cli_invalid);
        assert_eq!(cli_invalid["error"]["stage"], "request-schema");
        negative.insert(operation);
    }
    assert_eq!(callable.len(), 42);
    assert_eq!(denied, POLICY_DENIED.into_iter().collect());
    assert_eq!(negative.len(), 46);
}
