use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use gtkg_protocol::v2::{
    CallabilityV2, OperationRequestV2, PROTOCOL_VERSION_V2, V2_PUBLIC_OPERATIONS, V2OperationId,
};
use gtkg_protocol::v03::discovery_profiles_v03;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const POLICY_DENIED: [V2OperationId; 4] = [
    V2OperationId::GitPublish,
    V2OperationId::CurrentActivate,
    V2OperationId::TemplatePublish,
    V2OperationId::DeliverablePublish,
];

fn digest(character: char) -> String {
    format!("sha256:{}", character.to_string().repeat(64))
}

fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn current_binary() -> PathBuf {
    let path = PathBuf::from(std::env::var_os("GTKG_BIN").expect("P06 r5 requires GTKG_BIN"));
    let expected = std::env::var("P06_BINARY_SHA256").expect("P06 r5 requires P06_BINARY_SHA256");
    assert!(path.is_file());
    assert_eq!(sha256(&fs::read(&path).unwrap()), expected);
    path
}

fn replace_root(value: &mut Value, root: &str) {
    match value {
        Value::String(text) if text.contains("$ROOT") => *text = text.replace("$ROOT", root),
        Value::Array(values) => values
            .iter_mut()
            .for_each(|value| replace_root(value, root)),
        Value::Object(values) => values
            .values_mut()
            .for_each(|value| replace_root(value, root)),
        Value::String(_) | Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

fn graph_common() -> serde_json::Map<String, Value> {
    json!({
        "query_index_path": "query-index",
        "query_manifest_ref": {"path":"manifests/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.json","sha256":digest('a')},
        "evidence_index_path": "evidence-index",
        "evidence_manifest_ref": {"path":"manifests/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.json","sha256":digest('b')},
        "expected_identities": {"source_identity":digest('c'),"graph_identity":digest('d'),"overlay_identity":digest('e')}
    })
    .as_object()
    .unwrap()
    .clone()
}

fn graph_payload(operation: V2OperationId) -> Option<Value> {
    let fields = match operation {
        V2OperationId::GraphNeighbors => {
            json!({"node_id":"p06-node","direction":"outgoing","max_results":1})
        }
        V2OperationId::GraphPath => {
            json!({"source_node_id":"p06-source","target_node_id":"p06-target","max_depth":2})
        }
        V2OperationId::GraphImpact => json!({"node_id":"p06-node","max_depth":2,"max_results":1}),
        V2OperationId::GraphExplain => json!({"node_id":"p06-node","max_results":1}),
        V2OperationId::GraphTrace => json!({"entity_id":"p06-node"}),
        V2OperationId::GraphSearch => json!({"query":"p06","max_results":1}),
        _ => return None,
    };
    let mut payload = graph_common();
    payload.extend(fields.as_object().unwrap().clone());
    Some(Value::Object(payload))
}

fn current_payloads(root: &Path) -> BTreeMap<String, Value> {
    let mut value: Value =
        serde_json::from_str(include_str!("../fixtures/v03_p06/transport-payloads.json")).unwrap();
    replace_root(&mut value, &root.to_string_lossy());
    let mut payloads: BTreeMap<String, Value> = serde_json::from_value(value).unwrap();
    for definition in V2_PUBLIC_OPERATIONS {
        if let Some(payload) = graph_payload(definition.id) {
            payloads.insert(definition.id.as_str().to_owned(), payload);
        }
    }
    payloads
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
        "current explicit-profile CLI failed: {}",
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

#[test]
fn p06_r5_rebuilt_binary_has_current_46_cli_mcp_profile_parity() {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("invalid.json"), b"{}\n").unwrap();
    fs::create_dir(root.path().join("invalid-dir")).unwrap();
    let binary = current_binary();
    let all = discovery_profiles_v03()
        .into_iter()
        .find(|profile| profile.profile_id.as_str() == "all")
        .unwrap();
    let payloads = current_payloads(root.path());
    assert_eq!(payloads.len(), 46);
    let mut mcp = LineChild::spawn(&binary, root.path(), &all.digest);
    let listed =
        mcp.send(json!({"jsonrpc":"2.0","id":"p06-r5-list","method":"tools/list","params":{}}));
    assert_eq!(listed["result"]["tools"].as_array().unwrap().len(), 46);

    let mut callable = BTreeSet::new();
    let mut denied = BTreeSet::new();
    let mut negative = BTreeSet::new();
    for definition in V2_PUBLIC_OPERATIONS {
        let operation = definition.id;
        let request = OperationRequestV2::new(
            operation.as_str(),
            format!("p06-r5-{}", operation.as_str()),
            payloads.get(operation.as_str()).unwrap().clone(),
        );
        let request_value = serde_json::to_value(&request).unwrap();
        let cli = cli_call(
            &binary,
            root.path(),
            &all.digest,
            operation.as_str(),
            &request_value,
        );
        let rpc = mcp.send(json!({
            "jsonrpc":"2.0",
            "id":format!("p06-r5-mcp-{}", operation.as_str()),
            "method":"tools/call",
            "params":{"name":operation.mcp_tool_name(),"arguments":request}
        }));
        assert_eq!(
            rpc["result"]["structuredContent"],
            cli,
            "{}",
            operation.as_str()
        );
        if definition.callability == CallabilityV2::DeniedByPolicy {
            assert_eq!(cli["error"]["code"], "E_SIDE_EFFECT_DENIED");
            denied.insert(operation);
        } else if let Some(error) = cli.get("error") {
            assert_ne!(error["stage"], "request-schema");
            assert_ne!(error["stage"], "payload-schema");
            assert_ne!(error["stage"], "dispatch");
            callable.insert(operation);
        } else {
            callable.insert(operation);
        }
        let invalid = json!({
            "protocol_version":PROTOCOL_VERSION_V2,
            "operation_id":operation.as_str(),
            "request_id":format!("p06-r5-invalid-{}", operation.as_str()),
            "payload":payloads.get(operation.as_str()).unwrap(),
            "unexpected_transport_field":true
        });
        let cli_invalid = cli_call(
            &binary,
            root.path(),
            &all.digest,
            operation.as_str(),
            &invalid,
        );
        let rpc_invalid = mcp.send(json!({
            "jsonrpc":"2.0",
            "id":format!("p06-r5-invalid-mcp-{}", operation.as_str()),
            "method":"tools/call",
            "params":{"name":operation.mcp_tool_name(),"arguments":invalid}
        }));
        assert_eq!(rpc_invalid["result"]["structuredContent"], cli_invalid);
        assert_eq!(cli_invalid["error"]["stage"], "request-schema");
        negative.insert(operation);
    }
    assert_eq!(callable.len(), 42);
    assert_eq!(denied, POLICY_DENIED.into_iter().collect());
    assert_eq!(negative.len(), 46);
}
