//! P06 r3 successor: an explicit CLI profile binds the same full runtime
//! identity as MCP and preserves exact structured-content parity for all 46.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use gtkg_protocol::v2::{OperationRequestV2, V2_PUBLIC_OPERATIONS};
use gtkg_protocol::v03::discovery_profiles_v03;
use serde_json::{Value, json};

#[test]
fn p06_explicit_all_profile_has_exact_cli_mcp_parity_for_all_46() {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("invalid.json"), b"{}\n").unwrap();
    fs::create_dir(root.path().join("invalid-dir")).unwrap();
    let binary = gtkg_binary();
    let all = discovery_profiles_v03()
        .into_iter()
        .find(|profile| profile.profile_id.as_str() == "all")
        .unwrap();
    let payloads = payloads(root.path());
    assert_eq!(payloads.len(), 46);
    assert_eq!(
        payloads.keys().map(String::as_str).collect::<BTreeSet<_>>(),
        V2_PUBLIC_OPERATIONS
            .iter()
            .map(|definition| definition.id.as_str())
            .collect::<BTreeSet<_>>()
    );
    let mut mcp = LineChild::spawn(&binary, root.path(), &all.digest);

    for definition in V2_PUBLIC_OPERATIONS {
        let operation = definition.id;
        let request = OperationRequestV2::new(
            operation.as_str(),
            format!("p06-r3-{}", operation.as_str()),
            payloads.get(operation.as_str()).unwrap().clone(),
        );
        let cli = cli_call(
            &binary,
            root.path(),
            &all.digest,
            operation.as_str(),
            &serde_json::to_value(&request).unwrap(),
        );
        let rpc = mcp.send(json!({
            "jsonrpc": "2.0",
            "id": format!("p06-r3-mcp-{}", operation.as_str()),
            "method": "tools/call",
            "params": {"name": operation.mcp_tool_name(), "arguments": request}
        }));
        assert_eq!(
            rpc["result"]["structuredContent"],
            cli,
            "explicit-profile CLI/MCP drift for {}",
            operation.as_str()
        );
        if let Some(runtime) = cli.get("result").and_then(|result| result.get("runtime")) {
            assert_eq!(runtime["profile_id"], "all");
            assert_eq!(runtime["profile_digest"], all.digest);
        }
    }
}

fn payloads(root: &Path) -> BTreeMap<String, Value> {
    let mut value: Value =
        serde_json::from_str(include_str!("../fixtures/v03_p06/transport-payloads.json")).unwrap();
    replace_root(&mut value, &root.to_string_lossy());
    serde_json::from_value(value).unwrap()
}

fn replace_root(value: &mut Value, root: &str) {
    match value {
        Value::String(text) => {
            if text.contains("$ROOT") {
                *text = text.replace("$ROOT", root);
            }
        }
        Value::Array(values) => values
            .iter_mut()
            .for_each(|value| replace_root(value, root)),
        Value::Object(values) => values
            .values_mut()
            .for_each(|value| replace_root(value, root)),
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

fn cli_call(
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
        "explicit-profile CLI failed: {}",
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
    fn spawn(binary: &Path, root: &Path, digest: &str) -> Self {
        let mut child = Command::new(binary)
            .args([
                "mcp",
                "serve",
                "--protocol",
                "v2",
                "--profile",
                "all",
                "--profile-digest",
                digest,
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
    if let Some(path) = std::env::var_os("GTKG_BIN") {
        return PathBuf::from(path);
    }
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/gtkg")
}
