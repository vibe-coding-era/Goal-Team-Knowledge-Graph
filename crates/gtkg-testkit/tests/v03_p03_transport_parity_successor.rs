//! P03 CLI/MCP field parity for every context-summary handler error boundary.

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use gtkg_protocol::v2::{OperationRequestV2, V2OperationId};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

#[test]
fn p03_all_six_handlers_have_cli_mcp_error_field_parity() {
    let workspace = tempfile::tempdir().unwrap();
    let invalid = workspace.path().join("invalid.json");
    fs::write(&invalid, b"{}\n").unwrap();
    let reference = json!({"path": "invalid.json", "sha256": sha256(b"{}\n")});
    let requests = [
        OperationRequestV2::new(
            "context.pack",
            "p03-parity-context",
            json!({
                "workspace_root": workspace.path(),
                "analysis_verification_ref": reference,
                "max_fact_count": 1
            }),
        ),
        OperationRequestV2::new(
            "summary.job.next",
            "p03-parity-job",
            json!({
                "workspace_root": workspace.path(),
                "analysis_verification_ref": reference,
                "max_fact_count": 1,
                "expected_context_pack_sha256": digest('1')
            }),
        ),
        OperationRequestV2::new(
            "summary.proposal.submit",
            "p03-parity-proposal",
            json!({
                "workspace_root": workspace.path(),
                "analysis_verification_ref": reference,
                "context_pack_sha256": digest('1'),
                "summary_job_sha256": digest('2'),
                "proposer_id": "p",
                "summary_text": "candidate",
                "decisions": []
            }),
        ),
        OperationRequestV2::new(
            "summary.verification.next",
            "p03-parity-verification-next",
            json!({"workspace_root": workspace.path(), "proposal_ref": reference}),
        ),
        OperationRequestV2::new(
            "summary.verification.submit",
            "p03-parity-verification-submit",
            json!({
                "workspace_root": workspace.path(),
                "proposal_ref": reference,
                "verification_job_sha256": digest('3'),
                "verifier_id": "v",
                "decisions": []
            }),
        ),
        OperationRequestV2::new(
            "summary.accept.v2",
            "p03-parity-accept",
            json!({
                "workspace_root": workspace.path(),
                "proposal_ref": reference,
                "summary_verification_ref": reference
            }),
        ),
    ];
    let binary = gtkg_binary();
    let mut mcp = LineChild::spawn(&binary, workspace.path());
    for request in requests {
        let cli = cli_call(&binary, workspace.path(), &request);
        let mcp_result = mcp.send(json!({
            "jsonrpc": "2.0",
            "id": format!("mcp-{}", request.request_id),
            "method": "tools/call",
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
