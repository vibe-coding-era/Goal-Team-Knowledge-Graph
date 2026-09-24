//! T08 real-process contracts for the explicit V0.2 CLI/MCP transport.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use gtkg_protocol::v2::{OperationRequestV2, PROTOCOL_VERSION_V2, V2_PUBLIC_OPERATIONS};
use serde_json::{Value, json};

#[test]
fn v2_cli_and_mcp_expose_only_the_v2_registry_and_preserve_field_exact_error_parity() {
    let binary = gtkg_binary();
    let root = workspace_root();
    let mut mcp = LineChild::spawn(
        &binary,
        &["mcp", "serve", "--protocol", "v2", "--stdio"],
        &root,
    );

    let listed = mcp.send(json!({
        "jsonrpc": "2.0", "id": "v2-list", "method": "tools/list", "params": {}
    }));
    let tools = listed["result"]["tools"]
        .as_array()
        .expect("v2 tools/list array");
    assert_eq!(tools.len(), 46);
    assert!(
        tools
            .iter()
            .all(|tool| tool["x-gtkg-protocol-version"] == PROTOCOL_VERSION_V2)
    );
    assert!(tools.iter().all(|tool| {
        if matches!(
            tool["x-gtkg-operation-id"].as_str(),
            Some(
                "graph.neighbors"
                    | "graph.path"
                    | "graph.impact"
                    | "graph.explain"
                    | "graph.trace"
                    | "graph.search"
            )
        ) {
            tool["x-gtkg-availability"] == "implemented"
        } else {
            tool["x-gtkg-availability"] == "not_implemented"
        }
    }));
    assert!(tools.iter().all(|tool| {
        if matches!(
            tool["x-gtkg-operation-id"].as_str(),
            Some(
                "graph.neighbors"
                    | "graph.path"
                    | "graph.impact"
                    | "graph.explain"
                    | "graph.trace"
                    | "graph.search"
            )
        ) {
            tool["x-gtkg-callability"] == "callable"
        } else {
            tool["x-gtkg-callability"] == "not_implemented"
        }
    }));
    assert!(tools.iter().all(|tool| {
        tool["name"]
            .as_str()
            .is_some_and(|name| name.starts_with("gtkg_v2_"))
    }));
    assert!(
        tools
            .iter()
            .all(|tool| tool["x-gtkg-operation-id"] != "source.inspect")
    );

    for definition in V2_PUBLIC_OPERATIONS {
        let request = OperationRequestV2::new(
            definition.id.as_str(),
            format!("v2-e2e-{}", definition.id.as_str()),
            json!({}),
        );
        let cli = cli_call(&binary, &root, &request);
        let tool = tools
            .iter()
            .find(|tool| tool["x-gtkg-operation-id"] == definition.id.as_str())
            .expect("published v2 tool");
        let mcp_response = mcp.send(json!({
            "jsonrpc": "2.0",
            "id": format!("mcp-{}", definition.id.as_str()),
            "method": "tools/call",
            "params": {"name": tool["name"], "arguments": request}
        }));
        let structured = &mcp_response["result"]["structuredContent"];
        assert_eq!(
            structured,
            &cli,
            "v2 CLI/MCP drift for {}",
            definition.id.as_str()
        );
        assert_eq!(structured["protocol_version"], PROTOCOL_VERSION_V2);
        assert_eq!(
            structured["request_id"],
            format!("v2-e2e-{}", definition.id.as_str())
        );
        if definition.callability == gtkg_protocol::v2::CallabilityV2::Callable {
            assert_eq!(structured["error"]["code"], "E_INVALID_REQUEST");
        } else {
            assert_eq!(structured["error"]["code"], "E_OPERATION_NOT_IMPLEMENTED");
        }
        assert_eq!(mcp_response["result"]["isError"], true);
        assert_eq!(
            mcp_response["result"]["content"][0]["text"],
            serde_json::to_string(structured).expect("structured content JSON mirror")
        );
    }
}

#[test]
fn v1_remains_default_and_v2_rejects_v1_only_ids_at_the_transport_boundary() {
    let binary = gtkg_binary();
    let root = workspace_root();
    let mut v1 = LineChild::spawn(&binary, &["mcp", "serve", "--stdio"], &root);
    let listed = v1.send(json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}));
    assert_eq!(
        listed["result"]["tools"]
            .as_array()
            .expect("v1 tools")
            .len(),
        34
    );

    let request = OperationRequestV2::new("source.inspect", "v2-legacy", json!({}));
    let cli = cli_call(&binary, &root, &request);
    assert_eq!(cli["protocol_version"], PROTOCOL_VERSION_V2);
    assert_eq!(cli["request_id"], "v2-legacy");
    assert_eq!(cli["error"]["code"], "E_OPERATION_VERSION_UNSUPPORTED");
}

#[test]
fn v2_cli_and_mcp_return_the_same_closed_invalid_request_envelope_for_missing_payload_and_empty_request_id()
 {
    let binary = gtkg_binary();
    let root = workspace_root();
    let mut mcp = LineChild::spawn(
        &binary,
        &["mcp", "serve", "--protocol", "v2", "--stdio"],
        &root,
    );

    for (label, arguments, expected_request_id) in [
        (
            "missing-payload",
            json!({
                "protocol_version": PROTOCOL_VERSION_V2,
                "operation_id": "source.capture",
                "request_id": "v2-missing-payload"
            }),
            "v2-missing-payload",
        ),
        (
            "empty-request-id",
            json!({
                "protocol_version": PROTOCOL_VERSION_V2,
                "operation_id": "source.capture",
                "request_id": "",
                "payload": {}
            }),
            "",
        ),
    ] {
        let cli = cli_call_value(&binary, &root, "source.capture", &arguments);
        let response = mcp.send(json!({
            "jsonrpc": "2.0",
            "id": format!("v2-invalid-{label}"),
            "method": "tools/call",
            "params": {"name": "gtkg_v2_source_capture", "arguments": arguments}
        }));
        let structured = &response["result"]["structuredContent"];
        assert_eq!(structured, &cli, "v2 CLI/MCP invalid-schema drift: {label}");
        assert_eq!(
            structured["protocol_version"], PROTOCOL_VERSION_V2,
            "{label}"
        );
        assert_eq!(structured["request_id"], expected_request_id, "{label}");
        assert_eq!(structured["error"]["code"], "E_INVALID_REQUEST", "{label}");
        assert_eq!(structured["error"]["stage"], "request-schema", "{label}");
        assert_eq!(response["result"]["isError"], true, "{label}");
    }
}

fn cli_call(binary: &Path, root: &Path, request: &OperationRequestV2) -> Value {
    let request_value = serde_json::to_value(request).expect("encode v2 request");
    cli_call_value(binary, root, &request.operation_id, &request_value)
}

fn cli_call_value(binary: &Path, root: &Path, operation_id: &str, request: &Value) -> Value {
    let mut child = Command::new(binary)
        .args(["v2-op", operation_id, "--request", "-", "--output", "json"])
        .current_dir(root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn v2 gtkg CLI");
    serde_json::to_writer(child.stdin.as_mut().expect("CLI stdin"), request)
        .expect("write v2 CLI request");
    drop(child.stdin.take());
    let output = child.wait_with_output().expect("wait for v2 CLI");
    assert!(
        output.status.success(),
        "gtkg v2-op failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("v2 CLI JSON envelope")
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
            .unwrap_or_else(|error| panic!("spawn {}: {error}", args.join(" ")));
        Self {
            stdin: child.stdin.take().expect("MCP stdin"),
            stdout: BufReader::new(child.stdout.take().expect("MCP stdout")),
            child,
        }
    }

    fn send(&mut self, value: Value) -> Value {
        serde_json::to_writer(&mut self.stdin, &value).expect("write MCP frame");
        self.stdin.write_all(b"\n").expect("MCP newline");
        self.stdin.flush().expect("flush MCP frame");
        let mut line = String::new();
        assert_ne!(self.stdout.read_line(&mut line).expect("read MCP frame"), 0);
        serde_json::from_str(&line)
            .unwrap_or_else(|error| panic!("invalid MCP JSON: {error}: {line}"))
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
