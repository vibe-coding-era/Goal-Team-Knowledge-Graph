//! L01 transport-neutral presence semantics for `source.inspect`.

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use gtkg_core::{CallContext, Dispatcher, EffectPolicy, TransportKind};
use gtkg_protocol::{OperationId, OperationRequest};
use serde_json::{Value, json};
use tempfile::tempdir;

#[test]
fn v1_source_inspect_accepts_only_its_frozen_workspace_and_repositories_schema_across_transports() {
    let temp = tempdir().expect("tempdir");
    let root_path = temp.path().canonicalize().expect("canonical tempdir");
    let root = root_path.as_path();
    let repository = root.join("repository");
    let legacy_workspace = root.join("legacy-workspace");
    fs::create_dir_all(repository.join("src")).unwrap();
    fs::create_dir_all(&legacy_workspace).unwrap();
    fs::write(repository.join("src/lib.rs"), "pub fn product() {}\n").unwrap();
    init_git(&repository);

    let repositories = json!([{
        "repo_id": "product",
        "path": repository,
        "role": "code",
        "include": ["src"],
        "exclude": []
    }]);
    let context = CallContext::restricted(
        TransportKind::Test,
        vec![root.to_path_buf()],
        EffectPolicy::WorkspaceWrite,
    )
    .unwrap();
    let binary = gtkg_binary();
    let mut mcp = LineChild::spawn(&binary, root);

    let legacy = OperationRequest::new(
        OperationId::SourceInspect,
        "l01-positive-legacy",
        json!({
            "workspace_root": legacy_workspace,
            "repositories": repositories,
        }),
    );
    let direct = Dispatcher
        .execute(&context, legacy.clone())
        .expect("frozen v1 source.inspect mode must reach its handler");
    assert_eq!(serde_json::to_value(direct).unwrap()["status"], "completed");
    let cli = cli_call(&binary, root, &legacy);
    let via_mcp = mcp_call(&mut mcp, &legacy);
    assert_eq!(cli["status"], "completed", "CLI v1 mode: {cli:#}");
    assert_eq!(via_mcp["status"], "completed", "MCP v1 mode: {via_mcp:#}");

    let rejected_config_fields = [
        OperationRequest::new(
            OperationId::SourceInspect,
            "l01-config-pair",
            json!({
                "workspace_root": legacy_workspace,
                "repositories": repositories,
                "config_path": root.join("gtkg.json"),
                "expected_config_sha256": format!("sha256:{}", "0".repeat(64)),
            }),
        ),
        OperationRequest::new(
            OperationId::SourceInspect,
            "l01-config-path-only",
            json!({
                "workspace_root": legacy_workspace,
                "repositories": repositories,
                "config_path": root.join("gtkg.json"),
            }),
        ),
        OperationRequest::new(
            OperationId::SourceInspect,
            "l01-config-digest-only",
            json!({
                "workspace_root": legacy_workspace,
                "repositories": repositories,
                "expected_config_sha256": format!("sha256:{}", "0".repeat(64)),
            }),
        ),
        OperationRequest::new(
            OperationId::SourceInspect,
            "l01-null-config-fields",
            json!({
                "workspace_root": legacy_workspace,
                "repositories": repositories,
                "config_path": null,
                "expected_config_sha256": null,
            }),
        ),
    ];
    for request in &rejected_config_fields {
        let direct = Dispatcher
            .execute(&context, request.clone())
            .expect_err("v1 config input must fail at the frozen shared schema boundary");
        assert_schema_error(&serde_json::to_value(direct).unwrap());
        assert_schema_error(&cli_call(&binary, root, request));
        assert_schema_error(&mcp_call(&mut mcp, request));
    }
}

fn assert_schema_error(value: &Value) {
    assert_eq!(value["error"]["code"], "E_INVALID_REQUEST");
    assert_eq!(value["error"]["stage"], "payload-schema");
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

fn init_git(root: &Path) {
    for arguments in [
        &["init"][..],
        &["config", "user.name", "GTKG Fixture"],
        &["config", "user.email", "fixture@invalid.example"],
        &["add", "-A"],
        &["commit", "-m", "fixture"],
    ] {
        let output = Command::new("/usr/bin/git")
            .arg("-C")
            .arg(root)
            .args(arguments)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LC_ALL", "C")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git {} failed: {}",
            arguments.join(" "),
            String::from_utf8_lossy(&output.stderr)
        );
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
    assert!(
        path.is_file(),
        "build the current gtkg binary first: {}",
        path.display()
    );
    path
}
