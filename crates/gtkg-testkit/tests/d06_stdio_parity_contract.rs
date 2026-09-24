use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use gtkg_core::file_model::sha256_file;
use gtkg_protocol::{OperationId, OperationRequest, PROTOCOL_VERSION, PUBLIC_OPERATIONS, WorkUnit};
use serde_json::{Value, json};
use tempfile::tempdir;

#[test]
fn real_cli_and_mcp_stdio_have_field_exact_parity_for_all_34_operations() {
    let binary = gtkg_binary();
    let root = workspace_root();
    let mut mcp = LineChild::spawn(&binary, &["mcp", "serve", "--stdio"], &root);
    let initialized = mcp.send(json!({
        "jsonrpc": "2.0",
        "id": "initialize",
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "d06-contract", "version": "1"}
        }
    }));
    assert_eq!(initialized["result"]["protocolVersion"], "2025-06-18");

    assert_eq!(PUBLIC_OPERATIONS.len(), 34);
    for definition in PUBLIC_OPERATIONS {
        for (variant, payload) in [
            ("valid", json!({})),
            ("unknown", json!({"unexpected": true})),
        ] {
            let request = OperationRequest::new(
                definition.id,
                format!("d06-{variant}-{}", definition.id.as_str()),
                payload,
            );
            let cli = cli_call(&binary, &root, &request);
            let mcp_response = mcp.send(json!({
                "jsonrpc": "2.0",
                "id": format!("mcp-{variant}-{}", definition.id.as_str()),
                "method": "tools/call",
                "params": {
                    "name": definition.id.mcp_tool_name(),
                    "arguments": request
                }
            }));
            let structured = &mcp_response["result"]["structuredContent"];
            assert_eq!(
                structured,
                &cli,
                "CLI/MCP drift for {} {variant}",
                definition.id.as_str()
            );
            assert_eq!(
                mcp_response["result"]["content"][0]["text"],
                serde_json::to_string(structured).expect("structured content text"),
                "MCP text mirror for {} {variant}",
                definition.id.as_str()
            );
            if variant == "unknown" {
                assert_eq!(
                    structured["error"]["code"],
                    "E_INVALID_REQUEST",
                    "unknown payload field for {}",
                    definition.id.as_str()
                );
                assert_eq!(mcp_response["result"]["isError"], true);
            }
        }
    }
}

#[test]
fn mcp_stdio_exposes_only_tools_and_rejects_all_other_capability_methods() {
    let binary = gtkg_binary();
    let root = workspace_root();
    let mut mcp = LineChild::spawn(&binary, &["mcp", "serve", "--stdio"], &root);
    let initialized = mcp.send(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {}
    }));
    assert_eq!(
        initialized["result"]["capabilities"],
        json!({"tools": {"listChanged": false}})
    );
    let tools = mcp.send(json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
        "params": {}
    }));
    assert_eq!(
        tools["result"]["tools"].as_array().expect("tools").len(),
        34
    );
    assert!(
        tools["result"]["tools"]
            .as_array()
            .expect("tools")
            .iter()
            .all(|tool| tool["name"] != "gtkg_node_work_execute")
    );

    for (index, method) in [
        "resources/list",
        "resources/read",
        "prompts/list",
        "prompts/get",
        "sampling/createMessage",
        "tasks/list",
        "tasks/get",
    ]
    .iter()
    .enumerate()
    {
        let response = mcp.send(json!({
            "jsonrpc": "2.0",
            "id": 10 + index,
            "method": method,
            "params": {}
        }));
        assert_eq!(response["error"]["code"], -32601, "{method}");
    }
}

#[test]
fn node_stdio_is_private_deterministic_and_never_writes_canonical_knowledge() {
    let binary = gtkg_binary();
    let temp = tempdir().expect("node workspace");
    let source = temp.path().join("source.md");
    fs::write(&source, "# Worker source\n\nStatic only.\n").expect("source fixture");
    let input_sha256 = sha256_file(&source).expect("source digest");
    let work = WorkUnit::new(
        "static_extract",
        input_sha256,
        digest('a'),
        json!({"source_path": source}),
    )
    .expect("work unit");
    let frame = json!({
        "schema_version": "gtkg.node-stdio-request/v1",
        "request_id": "worker-request-1",
        "operation": "node.work.execute",
        "node_id": "local-worker",
        "attempt": 1,
        "work_unit": work
    });
    let mut node = LineChild::spawn(&binary, &["node", "serve", "--stdio"], temp.path());
    let first = node.send(frame.clone());
    let second = node.send(frame);
    assert_eq!(first, second, "at-least-once replay must be deterministic");
    assert_eq!(first["schema_version"], "gtkg.node-stdio-response/v1");
    assert_eq!(first["request_id"], "worker-request-1");
    assert_eq!(first["result"]["schema_version"], "gtkg.shard-result/v1");
    assert_eq!(first["result"]["work_id"], work.work_id);
    assert_eq!(first["result"]["canonical_write_count"], 0);
    assert_eq!(first["result"]["output"]["target_process_count"], 0);
    assert_eq!(first["result"]["output"]["executed_target_content"], false);
    assert_eq!(first["result"]["output"]["media_type"], "text/markdown");
    assert!(!temp.path().join(".gtkg").exists());

    let injection = node.send(json!({
        "jsonrpc": "2.0",
        "id": 99,
        "method": "tools/list",
        "params": {}
    }));
    assert_eq!(injection["schema_version"], "gtkg.node-stdio-response/v1");
    assert_eq!(injection["error"]["code"], "E_INVALID_REQUEST");
    assert!(injection.get("result").is_none());
}

fn cli_call(binary: &Path, root: &Path, request: &OperationRequest) -> Value {
    let mut child = Command::new(binary)
        .args([
            "op",
            request.operation_id.as_str(),
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
        .expect("spawn gtkg CLI");
    serde_json::to_writer(child.stdin.as_mut().expect("CLI stdin"), request)
        .expect("write CLI request");
    drop(child.stdin.take());
    let output = child.wait_with_output().expect("wait for CLI");
    assert!(
        output.status.success(),
        "gtkg CLI failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("CLI JSON envelope")
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
        let stdin = child.stdin.take().expect("child stdin");
        let stdout = BufReader::new(child.stdout.take().expect("child stdout"));
        Self {
            child,
            stdin,
            stdout,
        }
    }

    fn send(&mut self, value: Value) -> Value {
        serde_json::to_writer(&mut self.stdin, &value).expect("write child frame");
        self.stdin.write_all(b"\n").expect("frame newline");
        self.stdin.flush().expect("flush frame");
        let mut line = String::new();
        let bytes = self.stdout.read_line(&mut line).expect("read child frame");
        assert_ne!(bytes, 0, "child closed stdout without a response");
        serde_json::from_str(&line)
            .unwrap_or_else(|error| panic!("invalid child JSON: {error}: {line}"))
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
    assert!(
        path.is_file(),
        "missing {}; build it first with `cargo build -p gtkg-app --bin gtkg`",
        path.display()
    );
    path
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

fn digest(fill: char) -> String {
    format!("sha256:{}", fill.to_string().repeat(64))
}

#[test]
fn protocol_version_constant_remains_the_transport_identity() {
    assert_eq!(PROTOCOL_VERSION, "gtkg.protocol/v1");
    assert_eq!(OperationId::parse("node.work.execute"), None);
}
