use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use serde_json::{Value, json};

#[test]
fn invalid_request_ids_are_normalized_to_null_in_json_rpc_errors() {
    let binary = gtkg_binary();
    let mut mcp = LineChild::spawn(&binary, &workspace_root());

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
        assert_eq!(response["jsonrpc"], "2.0", "invalid {label} id");
        assert_eq!(response["error"]["code"], -32600, "invalid {label} id");
        assert_eq!(response["id"], Value::Null, "invalid {label} id");
        assert!(response.get("result").is_none(), "invalid {label} id");
    }
}

#[test]
fn valid_request_ids_remain_exact_in_json_rpc_responses() {
    let binary = gtkg_binary();
    let mut mcp = LineChild::spawn(&binary, &workspace_root());

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
        assert_eq!(response["id"], id, "valid {label} id");
        assert!(response.get("error").is_none(), "valid {label} id");
        assert_eq!(
            response["result"]["tools"]
                .as_array()
                .expect("tools/list array")
                .len(),
            34,
            "valid {label} id"
        );
    }
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
            .expect("spawn gtkg MCP stdio");
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
