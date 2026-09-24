use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use gtkg_protocol::{
    CORE_VERSION, OperationId, OperationRequest, PROTOCOL_VERSION, PUBLIC_OPERATIONS,
};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use tempfile::tempdir;

#[test]
fn cli_and_mcp_discovery_bind_the_same_binary_core_protocol_and_schema_identity() {
    let binary = gtkg_binary();
    let temp = tempdir().expect("identity workspace");
    let binary_sha256 = sha256_prefixed(&fs::read(&binary).expect("read gtkg binary"));
    let tools = gtkg_app::mcp_tools();
    let schema_sha256 = sha256_prefixed(&serde_json::to_vec(&tools).expect("encode tool schemas"));
    let core_sha256 = sha256_prefixed(
        format!("gtkg-core|{CORE_VERSION}|{PROTOCOL_VERSION}|{schema_sha256}").as_bytes(),
    );
    let expected = json!({
        "binary_sha256": binary_sha256,
        "core_sha256": core_sha256,
        "protocol_version": PROTOCOL_VERSION,
        "operation_schema_sha256": schema_sha256,
    });

    let request = OperationRequest::new(OperationId::SystemDescribe, "d07-identity", json!({}));
    let cli = cli_call(&binary, temp.path(), &request);
    assert_eq!(cli["result"]["identity"], expected);

    let mut mcp = LineChild::spawn(&binary, temp.path());
    let initialized = mcp.send(json!({
        "jsonrpc": "2.0",
        "id": "initialize",
        "method": "initialize",
        "params": {"protocolVersion": "2025-06-18", "capabilities": {}}
    }));
    assert_eq!(initialized["result"]["x-gtkg-identity"], expected);
    let via_mcp = mcp_call(&mut mcp, &request);
    assert_eq!(via_mcp, cli);
}

#[test]
fn all_34_operations_use_schema_valid_classified_fixtures_across_cli_and_mcp() {
    let binary = gtkg_binary();
    let temp = tempdir().expect("classified transport fixture");
    let fixture = temp.path().join("fixture.json");
    fs::write(&fixture, b"{}\n").expect("fixture file");
    let tools = gtkg_app::mcp_tools();
    assert_eq!(tools.len(), 34);
    assert_eq!(PUBLIC_OPERATIONS.len(), 34);

    let mut mcp = LineChild::spawn(&binary, temp.path());
    let initialized = mcp.send(json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}
    }));
    assert_eq!(initialized["result"]["protocolVersion"], "2025-06-18");

    for definition in PUBLIC_OPERATIONS {
        let tool = tools
            .iter()
            .find(|tool| tool["x-gtkg-operation-id"] == definition.id.as_str())
            .expect("operation tool schema");
        let payload_schema = &tool["inputSchema"]["properties"]["payload"];
        let payload = synthesize(payload_schema, "payload", temp.path(), &fixture);
        let request = OperationRequest::new(
            definition.id,
            format!("d07-valid-{}", definition.id.as_str()),
            payload.clone(),
        );
        let cli = cli_call(&binary, temp.path(), &request);
        let mcp_result = mcp_call(&mut mcp, &request);
        assert_eq!(
            mcp_result,
            cli,
            "valid fixture parity: {}",
            definition.id.as_str()
        );

        match classify(definition.id) {
            FixtureClass::Completed => assert_eq!(cli["status"], "completed"),
            FixtureClass::AuthorizationDenied => {
                assert_eq!(cli["error"]["code"], "E_SIDE_EFFECT_DENIED")
            }
            FixtureClass::StateChain => {
                assert_ne!(cli["error"]["stage"], "payload-schema");
                assert_ne!(cli["error"]["code"], "E_OPERATION_NOT_IMPLEMENTED");
            }
        }

        let mut invalid = payload.as_object().expect("payload object").clone();
        invalid.insert("unexpected".to_owned(), Value::Bool(true));
        let invalid_request = OperationRequest::new(
            definition.id,
            format!("d07-invalid-{}", definition.id.as_str()),
            Value::Object(invalid),
        );
        let cli_invalid = cli_call(&binary, temp.path(), &invalid_request);
        let mcp_invalid = mcp_call(&mut mcp, &invalid_request);
        assert_eq!(
            mcp_invalid,
            cli_invalid,
            "negative fixture parity: {}",
            definition.id.as_str()
        );
        assert_eq!(cli_invalid["error"]["code"], "E_INVALID_REQUEST");
        assert_eq!(cli_invalid["error"]["stage"], "payload-schema");
    }
}

#[test]
fn codegraph_and_qoder_are_informative_only_and_absent_from_runtime_dependency_surfaces() {
    let root = workspace_root();
    let mut files = vec![root.join("Cargo.toml"), root.join("Cargo.lock")];
    for directory in [
        "crates/gtkg-protocol",
        "crates/gtkg-extract",
        "crates/gtkg-core",
        "crates/gtkg-app",
        "crates/gtkg-testkit/src",
        "crates/gtkg-testkit/tests",
    ] {
        collect_regular_files(&root.join(directory), &mut files);
    }
    let this_contract = root.join("crates/gtkg-testkit/tests/d07_transport_identity_contract.rs");
    let informative_contract =
        root.join("crates/gtkg-testkit/tests/h07_product_completion_contract.rs");
    for path in files {
        if path == this_contract {
            continue;
        }
        let bytes =
            fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
        let text = String::from_utf8_lossy(&bytes).to_ascii_lowercase();
        if path == informative_contract {
            assert!(text.contains("evidence_scope"));
            assert!(text.contains("informative-only"));
            continue;
        }
        assert!(
            !text.contains("codegraph"),
            "CodeGraph enforcement reference: {}",
            path.display()
        );
        assert!(
            !text.contains("qoder"),
            "Qoder enforcement reference: {}",
            path.display()
        );
    }
}

#[derive(Debug, Clone, Copy)]
enum FixtureClass {
    Completed,
    AuthorizationDenied,
    StateChain,
}

fn classify(operation: OperationId) -> FixtureClass {
    match operation {
        OperationId::SystemDescribe => FixtureClass::Completed,
        OperationId::GitPublish
        | OperationId::CurrentActivate
        | OperationId::TemplatePublish
        | OperationId::DeliverablePublish => FixtureClass::AuthorizationDenied,
        _ => FixtureClass::StateChain,
    }
}

fn synthesize(schema: &Value, field: &str, root: &Path, fixture: &Path) -> Value {
    if let Some(value) = schema.get("const") {
        return value.clone();
    }
    if let Some(value) = schema
        .get("enum")
        .and_then(Value::as_array)
        .and_then(|values| values.first())
    {
        return value.clone();
    }
    match schema.get("type").and_then(Value::as_str) {
        Some("object") => {
            let properties = schema
                .get("properties")
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_default();
            let required = schema
                .get("oneOf")
                .and_then(Value::as_array)
                .and_then(|branches| branches.first())
                .and_then(|branch| branch.get("required"))
                .or_else(|| schema.get("required"))
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            let mut object = Map::new();
            for required_field in required {
                let name = required_field.as_str().expect("required field name");
                let value_schema = properties.get(name).expect("required property schema");
                object.insert(
                    name.to_owned(),
                    synthesize(value_schema, name, root, fixture),
                );
            }
            Value::Object(object)
        }
        Some("array") => Value::Array(vec![synthesize(
            schema.get("items").unwrap_or(&json!({})),
            field,
            root,
            fixture,
        )]),
        Some("boolean") => Value::Bool(false),
        Some("integer") | Some("number") => json!(1),
        Some("string") => Value::String(synthetic_string(schema, field, root, fixture)),
        _ => json!({}),
    }
}

fn synthetic_string(schema: &Value, field: &str, root: &Path, fixture: &Path) -> String {
    let pattern = schema.get("pattern").and_then(Value::as_str).unwrap_or("");
    if pattern.contains("sha256") || field.ends_with("sha256") {
        return digest('a');
    }
    if pattern.contains("local://") || field == "logical_address" {
        return "local://d07-node".to_owned();
    }
    if field.contains("path") || field.contains("root") || field == "endpoint" {
        return if matches!(
            field,
            "config_path" | "current_path" | "source_path" | "endpoint"
        ) {
            fixture.display().to_string()
        } else {
            root.display().to_string()
        };
    }
    if field.contains("version") {
        return "0.1.0".to_owned();
    }
    if field == "query" {
        return "d07".to_owned();
    }
    "d07".to_owned()
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

fn mcp_call(mcp: &mut LineChild, request: &OperationRequest) -> Value {
    let response = mcp.send(json!({
        "jsonrpc": "2.0",
        "id": format!("mcp-{}", request.request_id),
        "method": "tools/call",
        "params": {"name": request.operation_id.mcp_tool_name(), "arguments": request}
    }));
    response["result"]["structuredContent"].clone()
}

struct LineChild {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl LineChild {
    fn spawn(binary: &Path, root: &Path) -> Self {
        let mut child = Command::new(binary)
            .args(["mcp", "serve", "--stdio"])
            .current_dir(root)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn MCP stdio");
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

fn collect_regular_files(directory: &Path, files: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(directory)
        .unwrap_or_else(|error| panic!("read {}: {error}", directory.display()))
    {
        let path = entry.expect("directory entry").path();
        let metadata = fs::symlink_metadata(&path).expect("entry metadata");
        assert!(
            !metadata.file_type().is_symlink(),
            "source symlink: {}",
            path.display()
        );
        if metadata.is_dir() {
            collect_regular_files(&path, files);
        } else if metadata.is_file() {
            files.push(path);
        }
    }
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

fn gtkg_binary() -> PathBuf {
    if let Some(path) = std::env::var_os("GTKG_BIN") {
        let path = PathBuf::from(path);
        assert!(path.is_file(), "GTKG_BIN is not a file: {}", path.display());
        return path;
    }
    let path = workspace_root().join("target/debug/gtkg");
    assert!(path.is_file(), "build gtkg first: {}", path.display());
    path
}

fn sha256_prefixed(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn digest(fill: char) -> String {
    format!("sha256:{}", fill.to_string().repeat(64))
}
