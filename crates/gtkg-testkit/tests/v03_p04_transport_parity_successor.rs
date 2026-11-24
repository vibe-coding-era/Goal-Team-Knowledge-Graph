//! P04 CLI/MCP field parity for all nine lifecycle handlers.

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use gtkg_protocol::v2::{OperationRequestV2, V2OperationId};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

#[test]
fn p04_all_nine_handlers_have_cli_mcp_error_field_parity() {
    let workspace = tempfile::tempdir().unwrap();
    fs::write(workspace.path().join("invalid.json"), b"{}\n").unwrap();
    let reference = json!({"path": "invalid.json", "sha256": sha256(b"{}\n")});
    let root = workspace.path();
    let requests = [
        OperationRequestV2::new(
            "build.finalize.v2",
            "p04-parity-finalize",
            json!({
                "workspace_root": root, "analysis_verification_ref": reference,
                "accepted_summary_ref": reference, "bundle_version": "v"
            }),
        ),
        OperationRequestV2::new(
            "run.get",
            "p04-parity-run-get",
            json!({
                "workspace_root": root, "run_ref": reference
            }),
        ),
        OperationRequestV2::new(
            "run.cancel",
            "p04-parity-run-cancel",
            json!({
                "workspace_root": root, "run_ref": reference, "expected_run_sha256": reference["sha256"]
            }),
        ),
        OperationRequestV2::new(
            "bundle.verify",
            "p04-parity-bundle-verify",
            json!({
                "workspace_root": root, "bundle_ref": reference
            }),
        ),
        OperationRequestV2::new(
            "bundle.compare",
            "p04-parity-bundle-compare",
            json!({
                "workspace_root": root, "left_bundle_ref": reference, "right_bundle_ref": reference
            }),
        ),
        OperationRequestV2::new(
            "bundle.migrate.v1_to_v2",
            "p04-parity-migrate",
            json!({
                "workspace_root": root, "legacy_bundle_path": root.join("invalid.json"),
                "expected_legacy_tree_sha256": digest('1'), "migration_version": "v"
            }),
        ),
        OperationRequestV2::new(
            "snapshot.create",
            "p04-parity-snapshot-create",
            json!({
                "workspace_root": root, "bundle_ref": reference, "snapshot_version": "v"
            }),
        ),
        OperationRequestV2::new(
            "snapshot.verify",
            "p04-parity-snapshot-verify",
            json!({
                "workspace_root": root, "snapshot_ref": reference
            }),
        ),
        OperationRequestV2::new(
            "snapshot.restore",
            "p04-parity-snapshot-restore",
            json!({
                "workspace_root": root, "snapshot_ref": reference,
                "expected_snapshot_sha256": reference["sha256"], "restore_version": "v"
            }),
        ),
    ];
    let binary = gtkg_binary();
    let mut mcp = LineChild::spawn(&binary, root);
    for request in requests {
        let cli = cli_call(&binary, root, &request);
        let mcp_result = mcp.send(json!({
            "jsonrpc": "2.0", "id": request.request_id, "method": "tools/call",
            "params": {
                "name": V2OperationId::parse(&request.operation_id).unwrap().mcp_tool_name(),
                "arguments": request
            }
        }));
        assert_eq!(mcp_result["result"]["isError"], true);
        assert_eq!(mcp_result["result"]["structuredContent"], cli);
        assert_ne!(cli["error"]["code"], "E_OPERATION_NOT_IMPLEMENTED");
        assert_ne!(cli["error"]["stage"], "dispatch");
    }
}

fn cli_call(binary: &Path, root: &Path, request: &OperationRequestV2) -> Value {
    let mut child = Command::new(binary)
        .args([
            "v2-op",
            request.operation_id.as_str(),
            "--profile",
            "all",
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
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

struct LineChild {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}
impl LineChild {
    fn spawn(binary: &Path, root: &Path) -> Self {
        let mut child = Command::new(binary)
            .args([
                "mcp",
                "serve",
                "--protocol",
                "v2",
                "--profile",
                "all",
                "--stdio",
            ])
            .current_dir(root)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        Self {
            stdin: child.stdin.take().unwrap(),
            stdout: BufReader::new(child.stdout.take().unwrap()),
            child,
        }
    }
    fn send(&mut self, value: Value) -> Value {
        serde_json::to_writer(&mut self.stdin, &value).unwrap();
        self.stdin.write_all(b"\n").unwrap();
        self.stdin.flush().unwrap();
        let mut line = String::new();
        assert_ne!(self.stdout.read_line(&mut line).unwrap(), 0);
        serde_json::from_str(&line).unwrap()
    }
}
impl Drop for LineChild {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
fn gtkg_binary() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/gtkg")
}
fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}
fn digest(character: char) -> String {
    format!("sha256:{}", character.to_string().repeat(64))
}
