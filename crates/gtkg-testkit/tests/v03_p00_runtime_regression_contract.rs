use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

#[test]
fn core_contract_identity_succeeds_while_live_discovery_still_rejects_dead_tools() {
    let identity = gtkg_app::runtime_identity_v2_for_profile(Some("core"), None)
        .expect("core contract identity must not require every selected handler to be live");
    assert_eq!(identity["profile_id"], "core");
    assert_eq!(identity["profile_operation_count"], 10);

    let discovery = gtkg_app::v2_profile_discovery(Some("core"), None)
        .expect_err("core live discovery must reject nine unavailable handlers");
    assert_eq!(discovery["code"], "E_DEAD_TOOL_EXPOSED");
    assert_eq!(discovery["selected_operation_count"], 10);
    assert_eq!(
        discovery["unavailable_operation_ids"]
            .as_array()
            .expect("unavailable IDs")
            .len(),
        9
    );
}

#[test]
fn default_core_mcp_initialize_succeeds_but_tools_list_remains_fail_closed() {
    let binary = gtkg_binary();
    let root = workspace_root();
    let mut mcp = LineChild::spawn(
        &binary,
        &root,
        &["mcp", "serve", "--protocol", "v2", "--stdio"],
    );
    let initialized = mcp.send(json!({
        "jsonrpc":"2.0","id":"p00-init","method":"initialize","params":{}
    }));
    assert!(initialized.get("error").is_none(), "{initialized}");
    assert_eq!(
        initialized["result"]["x-gtkg-identity"]["profile_id"],
        "core"
    );
    assert_eq!(
        initialized["result"]["x-gtkg-identity"]["profile_operation_count"],
        10
    );

    let listed = mcp.send(json!({
        "jsonrpc":"2.0","id":"p00-list","method":"tools/list","params":{}
    }));
    assert_eq!(listed["error"]["data"]["code"], "E_DEAD_TOOL_EXPOSED");
}

struct LineChild {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl LineChild {
    fn spawn(binary: &Path, root: &Path, args: &[&str]) -> Self {
        let mut child = Command::new(binary)
            .args(args)
            .current_dir(root)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn GTKG MCP");
        Self {
            stdin: child.stdin.take().expect("MCP stdin"),
            stdout: BufReader::new(child.stdout.take().expect("MCP stdout")),
            child,
        }
    }

    fn send(&mut self, value: Value) -> Value {
        serde_json::to_writer(&mut self.stdin, &value).expect("write frame");
        self.stdin.write_all(b"\n").expect("newline");
        self.stdin.flush().expect("flush");
        let mut line = String::new();
        assert_ne!(self.stdout.read_line(&mut line).expect("read frame"), 0);
        serde_json::from_str(&line).unwrap_or_else(|error| panic!("{error}: {line}"))
    }
}

impl Drop for LineChild {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn gtkg_binary() -> PathBuf {
    workspace_root().join("target/debug/gtkg")
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root")
}
