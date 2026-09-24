use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use gtkg_core::file_model::sha256_file;
use gtkg_core::{CallContext, Dispatcher, EffectPolicy, TransportKind};
use gtkg_protocol::{
    ErrorCode, NodeDescriptor, NodeTransport, OperationId, OperationRequest, OperationStatus,
    PROTOCOL_VERSION, ShardResult, WorkUnit, canonical_json_sha256,
};
use serde_json::{Value, json};
use tempfile::tempdir;

#[test]
fn mcp_json_rpc_ids_are_exactly_string_number_or_null() {
    let binary = gtkg_binary();
    let mut mcp = LineChild::spawn(&binary, &["mcp", "serve", "--stdio"], &workspace_root());

    for (label, id) in [
        ("string", json!("request-id")),
        ("number", json!(17)),
        ("null", Value::Null),
    ] {
        let response = mcp.send(json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/list",
            "params": {}
        }));
        assert_eq!(response["jsonrpc"], "2.0", "valid {label} id");
        assert_eq!(response["id"], id, "valid {label} id must be echoed");
        assert!(response.get("error").is_none(), "valid {label} id");
        assert_eq!(
            response["result"]["tools"]
                .as_array()
                .expect("tools/list result")
                .len(),
            34,
            "valid {label} id"
        );
    }

    let mut accepted_invalid_ids = Vec::new();
    for (label, id) in [
        ("boolean", json!(true)),
        ("object", json!({"nested": "id"})),
        ("array", json!([1, 2, 3])),
    ] {
        let response = mcp.send(json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/list",
            "params": {}
        }));
        if response.get("result").is_some() {
            accepted_invalid_ids.push(label);
        } else {
            assert_eq!(response["error"]["code"], -32600, "invalid {label} id");
        }
    }
    assert!(
        accepted_invalid_ids.is_empty(),
        "JSON-RPC accepted forbidden request id kinds: {accepted_invalid_ids:?}"
    );
}

#[test]
fn federation_work_unit_payload_schema_and_runtime_are_exactly_source_path() {
    let tools = gtkg_app::mcp_tools();
    let federation = tools
        .iter()
        .find(|tool| tool["x-gtkg-operation-id"] == "federation.validate")
        .expect("federation.validate tool");
    let payload_schema = &federation["inputSchema"]["properties"]["payload"]["properties"]["work_units"]
        ["items"]["properties"]["payload"];
    assert_eq!(payload_schema["type"], "object");
    assert_eq!(payload_schema["additionalProperties"], false);
    assert_string_set(
        &payload_schema["required"],
        &["source_path"],
        "WorkUnit payload required fields",
    );
    assert_property_set(
        payload_schema,
        &["source_path"],
        "WorkUnit payload properties",
    );

    let valid = execute_federation("valid", json!({"source_path": "docs/input.md"}))
        .expect("exact source_path payload must complete");
    assert_eq!(valid.status, OperationStatus::Completed);
    assert_eq!(
        valid.result["accepted_results"].as_array().unwrap().len(),
        1
    );

    let mut accepted_invalid_payloads = Vec::new();
    for (label, payload) in [
        ("unknown-only", json!({"unknown": "docs/input.md"})),
        (
            "extra-field",
            json!({"source_path": "docs/input.md", "unexpected": true}),
        ),
    ] {
        match execute_federation(label, payload) {
            Ok(_) => accepted_invalid_payloads.push(label),
            Err(error) => assert_eq!(error.error.code, ErrorCode::InvalidRequest, "{label}"),
        }
    }
    assert!(
        accepted_invalid_payloads.is_empty(),
        "federation runtime accepted non-exact WorkUnit payloads: {accepted_invalid_payloads:?}"
    );
}

#[cfg(unix)]
#[test]
fn exact_reads_reject_leaf_and_intermediate_symlinks_before_canonicalization() {
    use std::os::unix::fs::symlink;

    let temp = tempdir().expect("exact-read fixture");
    let real = temp.path().join("real");
    let workspace = temp.path().join("workspace");
    let repository = temp.path().join("repository");
    let catalog = temp.path().join("catalog");
    for directory in [&real, &workspace, &repository, &catalog] {
        fs::create_dir_all(directory).expect("fixture directory");
    }

    let config_target = real.join("gtkg-config.json");
    write_json(
        &config_target,
        &json!({
            "schema_version": "gtkg.config/v1",
            "workspace_root": workspace,
            "storage_model": "okf-and-ordinary-files",
            "database_backend": null,
            "repository_roots": [repository],
            "template_catalog_roots": [catalog],
            "node_endpoints": []
        }),
    );
    let current_target = real.join("CURRENT.json");
    write_json(
        &current_target,
        &json!({
            "schema_version": "gtkg.current/v1",
            "deliverable_id": "knowledge",
            "version": "0.1.0",
            "version_path": "versions/v0.1.0--111111111111",
            "tree_sha256": digest('1'),
            "manifest_sha256": digest('2')
        }),
    );

    let canonical_config = fs::canonicalize(&config_target).expect("canonical config target");
    let canonical_current = fs::canonicalize(&current_target).expect("canonical CURRENT target");
    let config_sha256 = sha256_file(&canonical_config).expect("config digest");
    let current_sha256 = sha256_file(&canonical_current).expect("CURRENT digest");
    let context = CallContext::restricted(
        TransportKind::Test,
        vec![temp.path().to_path_buf()],
        EffectPolicy::ReadOnly,
    )
    .expect("read context");

    let config = execute_exact_read(
        &context,
        OperationId::ConfigValidate,
        "direct-config",
        &canonical_config,
        &current_sha256,
    )
    .expect("direct canonical config target must succeed");
    assert_eq!(config.result["config_sha256"], config_sha256);
    let current = execute_exact_read(
        &context,
        OperationId::CurrentGet,
        "direct-current",
        &canonical_current,
        &current_sha256,
    )
    .expect("direct canonical CURRENT target must succeed");
    assert_eq!(current.result["current_sha256"], current_sha256);

    let config_leaf = temp.path().join("config-leaf-link.json");
    let current_leaf = temp.path().join("current-leaf-link.json");
    let intermediate = temp.path().join("intermediate-link");
    symlink(&canonical_config, &config_leaf).expect("config leaf symlink");
    symlink(&canonical_current, &current_leaf).expect("CURRENT leaf symlink");
    symlink(&real, &intermediate).expect("intermediate directory symlink");

    let mut accepted_symlinks = Vec::new();
    for (label, operation, path) in [
        ("config-leaf", OperationId::ConfigValidate, config_leaf),
        ("current-leaf", OperationId::CurrentGet, current_leaf),
        (
            "config-intermediate",
            OperationId::ConfigValidate,
            intermediate.join("gtkg-config.json"),
        ),
        (
            "current-intermediate",
            OperationId::CurrentGet,
            intermediate.join("CURRENT.json"),
        ),
    ] {
        match execute_exact_read(&context, operation, label, &path, &current_sha256) {
            Ok(_) => accepted_symlinks.push(label),
            Err(error) => assert!(
                matches!(
                    error.error.code,
                    ErrorCode::PathEscape | ErrorCode::SymlinkRejected
                ),
                "{label}: {:?}",
                error.error.code
            ),
        }
    }
    assert!(
        accepted_symlinks.is_empty(),
        "exact reads accepted symlinked request paths: {accepted_symlinks:?}"
    );
}

fn execute_federation(
    label: &str,
    payload: Value,
) -> Result<gtkg_protocol::OperationResponse, gtkg_protocol::ErrorEnvelope> {
    let work = canonical_work_unit(payload);
    let output = json!({
        "executed_target_content": false,
        "target_process_count": 0,
        "text": "static fixture"
    });
    let shard = ShardResult {
        schema_version: "gtkg.shard-result/v1".to_owned(),
        work_id: work.work_id.clone(),
        node_id: "worker-a".to_owned(),
        attempt: 1,
        output_sha256: canonical_json_sha256(&output).expect("output identity"),
        output,
        canonical_write_count: 0,
    };
    Dispatcher.execute(
        &CallContext::test(),
        OperationRequest::new(
            OperationId::FederationValidate,
            format!("r8-federation-{label}"),
            json!({
                "nodes": [local_node()],
                "work_units": [work],
                "shard_results": [shard]
            }),
        ),
    )
}

fn canonical_work_unit(payload: Value) -> WorkUnit {
    let input_sha256 = digest('3');
    let policy_sha256 = digest('4');
    let identity = json!({
        "schema_version": "gtkg.work-unit/v1",
        "kind": "static_extract",
        "input_sha256": input_sha256,
        "policy_sha256": policy_sha256,
        "payload": payload
    });
    WorkUnit {
        schema_version: "gtkg.work-unit/v1".to_owned(),
        work_id: canonical_json_sha256(&identity).expect("canonical WorkUnit identity"),
        kind: "static_extract".to_owned(),
        input_sha256: identity["input_sha256"].as_str().unwrap().to_owned(),
        policy_sha256: identity["policy_sha256"].as_str().unwrap().to_owned(),
        payload: identity["payload"].clone(),
    }
}

fn local_node() -> NodeDescriptor {
    NodeDescriptor {
        schema_version: "gtkg.node/v1".to_owned(),
        node_id: "worker-a".to_owned(),
        logical_address: "local://worker-a".to_owned(),
        transport: NodeTransport::Exec,
        endpoint: std::env::current_exe()
            .expect("test executable")
            .to_string_lossy()
            .into_owned(),
        binary_sha256: digest('a'),
        source_sha256: digest('b'),
        protocol_version: PROTOCOL_VERSION.to_owned(),
        parser_sha256: digest('c'),
        sandbox_policy_sha256: digest('d'),
        platform: std::env::consts::OS.to_owned(),
        capabilities: vec!["static_extract".to_owned()],
        max_parallel: 1,
        work_unit_kinds: vec!["static_extract".to_owned()],
    }
}

fn execute_exact_read(
    context: &CallContext,
    operation: OperationId,
    request_id: &str,
    path: &Path,
    current_sha256: &str,
) -> Result<gtkg_protocol::OperationResponse, gtkg_protocol::ErrorEnvelope> {
    let payload = match operation {
        OperationId::ConfigValidate => json!({"config_path": path}),
        OperationId::CurrentGet => json!({
            "current_path": path,
            "expected_current_sha256": current_sha256
        }),
        _ => panic!("unsupported exact-read operation"),
    };
    Dispatcher.execute(
        context,
        OperationRequest::new(operation, request_id, payload),
    )
}

fn assert_property_set(schema: &Value, expected: &[&str], label: &str) {
    let mut observed = schema["properties"]
        .as_object()
        .expect("properties")
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>();
    observed.sort_unstable();
    let mut expected = expected.to_vec();
    expected.sort_unstable();
    assert_eq!(observed, expected, "{label}");
}

fn assert_string_set(value: &Value, expected: &[&str], label: &str) {
    let mut observed = value
        .as_array()
        .expect("string array")
        .iter()
        .map(|value| value.as_str().expect("string"))
        .collect::<Vec<_>>();
    observed.sort_unstable();
    let mut expected = expected.to_vec();
    expected.sort_unstable();
    assert_eq!(observed, expected, "{label}");
}

struct LineChild {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl LineChild {
    fn spawn(binary: &Path, args: &[&str], root: &Path) -> Self {
        let mut child = Command::new(binary)
            .args(args)
            .current_dir(root)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn gtkg");
        let stdin = child.stdin.take().expect("stdin");
        let stdout = BufReader::new(child.stdout.take().expect("stdout"));
        Self {
            child,
            stdin,
            stdout,
        }
    }

    fn send(&mut self, value: Value) -> Value {
        serde_json::to_writer(&mut self.stdin, &value).expect("write frame");
        self.stdin.write_all(b"\n").expect("newline");
        self.stdin.flush().expect("flush");
        let mut line = String::new();
        assert_ne!(self.stdout.read_line(&mut line).expect("read frame"), 0);
        serde_json::from_str(&line).expect("JSON response")
    }
}

impl Drop for LineChild {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn gtkg_binary() -> PathBuf {
    if let Some(path) = std::env::var_os("GTKG_BIN") {
        let path = PathBuf::from(path);
        assert!(path.is_file(), "GTKG_BIN is not a file: {}", path.display());
        return path;
    }
    let path = workspace_root().join("target/debug/gtkg");
    assert!(path.is_file(), "build {} before this test", path.display());
    path
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

fn write_json(path: &Path, value: &Value) {
    fs::write(path, serde_json::to_vec_pretty(value).expect("JSON bytes")).expect("write JSON");
}

fn digest(fill: char) -> String {
    format!("sha256:{}", fill.to_string().repeat(64))
}
