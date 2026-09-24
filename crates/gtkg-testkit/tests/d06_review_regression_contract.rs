use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use gtkg_core::file_model::sha256_file;
use gtkg_core::{CallContext, Dispatcher, EffectPolicy, TransportKind};
use gtkg_protocol::{ErrorCode, OperationId, OperationRequest};
use serde_json::{Value, json};
use tempfile::tempdir;

#[test]
fn mcp_json_rpc_rejects_wrong_version_missing_version_and_unknown_top_level_fields() {
    let binary = gtkg_binary();
    let mut mcp = LineChild::spawn(&binary, &["mcp", "serve", "--stdio"], &workspace_root());
    for (index, request) in [
        json!({"id": 1, "method": "initialize", "params": {}}),
        json!({"jsonrpc": "1.0", "id": 2, "method": "initialize", "params": {}}),
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/list",
            "params": {},
            "unexpected": true
        }),
    ]
    .into_iter()
    .enumerate()
    {
        let response = mcp.send(request);
        assert_eq!(response["jsonrpc"], "2.0", "case {index}");
        assert_eq!(response["error"]["code"], -32600, "case {index}");
        assert!(response.get("result").is_none(), "case {index}");
    }
}

#[test]
fn every_nested_mcp_request_object_is_closed_and_selected_shapes_match_handlers() {
    let tools = gtkg_app::mcp_tools();
    assert_eq!(tools.len(), 34);
    for tool in &tools {
        assert_closed_schema(
            &tool["inputSchema"],
            tool["name"].as_str().expect("tool name"),
        );
    }

    let source = payload_schema(&tools, "source.inspect");
    let repository = &source["properties"]["repositories"]["items"];
    assert_eq!(repository["additionalProperties"], false);
    assert_string_set(
        &repository["required"],
        &["repo_id", "path"],
        "source repository required fields",
    );
    assert_property_set(
        repository,
        &["repo_id", "path", "role", "include", "exclude"],
        "source repository fields",
    );

    let node = payload_schema(&tools, "node.describe");
    let descriptor = &node["properties"]["descriptor"];
    assert_eq!(descriptor["additionalProperties"], false);
    for field in [
        "schema_version",
        "node_id",
        "logical_address",
        "transport",
        "endpoint",
        "binary_sha256",
        "source_sha256",
        "protocol_version",
        "parser_sha256",
        "sandbox_policy_sha256",
        "platform",
        "capabilities",
        "max_parallel",
        "work_unit_kinds",
    ] {
        assert!(
            descriptor["properties"].get(field).is_some(),
            "descriptor.{field}"
        );
    }

    let federation = payload_schema(&tools, "federation.validate");
    let work = &federation["properties"]["work_units"]["items"];
    assert_eq!(work["additionalProperties"], false);
    assert_property_set(
        work,
        &[
            "schema_version",
            "work_id",
            "kind",
            "input_sha256",
            "policy_sha256",
            "payload",
        ],
        "WorkUnit fields",
    );
    assert_eq!(work["properties"]["payload"]["additionalProperties"], false);
    assert!(
        work["properties"]["payload"]["properties"]
            .get("source_path")
            .is_some()
    );

    let shard = &federation["properties"]["shard_results"]["items"];
    assert_eq!(shard["additionalProperties"], false);
    assert_property_set(
        shard,
        &[
            "schema_version",
            "work_id",
            "node_id",
            "attempt",
            "output",
            "output_sha256",
            "canonical_write_count",
        ],
        "ShardResult fields",
    );
}

#[test]
fn config_and_current_exact_reads_bind_returned_bytes_and_reject_linked_inodes() {
    let temp = tempdir().expect("exact read root");
    let workspace = temp.path().join("workspace");
    let repository = temp.path().join("repository");
    let catalog = temp.path().join("catalog");
    fs::create_dir_all(&workspace).expect("workspace");
    fs::create_dir_all(&repository).expect("repository");
    fs::create_dir_all(&catalog).expect("catalog");
    let config_path = temp.path().join("gtkg-config.json");
    write_json(
        &config_path,
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
    let current_path = temp.path().join("CURRENT.json");
    write_json(
        &current_path,
        &json!({
            "schema_version": "gtkg.current/v1",
            "deliverable_id": "knowledge",
            "version": "0.1.0",
            "version_path": "versions/v0.1.0--111111111111",
            "tree_sha256": digest('1'),
            "manifest_sha256": digest('2')
        }),
    );
    fs::hard_link(&config_path, temp.path().join("config-alias.json"))
        .expect("controlled config hardlink");
    fs::hard_link(&current_path, temp.path().join("current-alias.json"))
        .expect("controlled CURRENT hardlink");
    let context = CallContext::restricted(
        TransportKind::Test,
        vec![temp.path().to_path_buf()],
        EffectPolicy::ReadOnly,
    )
    .expect("read context");

    let config_error = Dispatcher
        .execute(
            &context,
            OperationRequest::new(
                OperationId::ConfigValidate,
                "linked-config",
                json!({"config_path": config_path}),
            ),
        )
        .expect_err("linked config inode must be rejected before parsing");
    assert!(matches!(
        config_error.error.code,
        ErrorCode::PathEscape | ErrorCode::SymlinkRejected
    ));

    let current_error = Dispatcher
        .execute(
            &context,
            OperationRequest::new(
                OperationId::CurrentGet,
                "linked-current",
                json!({
                    "current_path": current_path,
                    "expected_current_sha256": sha256_file(&current_path).expect("CURRENT digest")
                }),
            ),
        )
        .expect_err("linked CURRENT inode must be rejected before parsing");
    assert!(matches!(
        current_error.error.code,
        ErrorCode::PathEscape | ErrorCode::SymlinkRejected
    ));

    let core = Path::new(env!("CARGO_MANIFEST_DIR")).join("../gtkg-core/src");
    let helper = fs::read_to_string(core.join("exact_read.rs"))
        .expect("exact reads must share one audited helper");
    let config_source = fs::read_to_string(core.join("config.rs")).expect("config source");
    let current_source = fs::read_to_string(core.join("current.rs")).expect("current source");
    assert!(helper.contains("read_to_end"));
    assert!(helper.contains("sha256_bytes"));
    assert!(helper.contains("path_metadata"));
    assert!(helper.contains("file_metadata"));
    assert!(helper.contains("nlink()"));
    assert!(helper.contains("dev()") && helper.contains("ino()"));
    assert!(config_source.contains("read_bound_regular_file"));
    assert!(current_source.contains("read_bound_regular_file"));
    assert!(!config_source.contains("let before = sha256_file(&path)"));
    assert!(!current_source.contains("let before = sha256_file(&path)"));
}

fn payload_schema<'a>(tools: &'a [Value], operation: &str) -> &'a Value {
    &tools
        .iter()
        .find(|tool| tool["x-gtkg-operation-id"] == operation)
        .expect("operation tool")["inputSchema"]["properties"]["payload"]
}

fn assert_closed_schema(schema: &Value, path: &str) {
    if schema["type"] == "object" {
        assert!(
            schema.get("additionalProperties").is_some(),
            "object schema is not explicit at {path}: {schema}"
        );
        if let Some(properties) = schema.get("properties").and_then(Value::as_object) {
            for (name, child) in properties {
                assert_closed_schema(child, &format!("{path}.properties.{name}"));
            }
        }
        if let Some(additional) = schema.get("additionalProperties")
            && additional.is_object()
        {
            assert_closed_schema(additional, &format!("{path}.additionalProperties"));
        }
    }
    if let Some(items) = schema.get("items") {
        assert_closed_schema(items, &format!("{path}.items"));
    }
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
