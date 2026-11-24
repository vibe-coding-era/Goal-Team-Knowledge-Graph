//! P06 r2 successor: correct the two r1 field-path oracles without changing
//! the 46-operation positive/negative/effect denominator.

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

const POLICY_DENIED: [V2OperationId; 4] = [
    V2OperationId::GitPublish,
    V2OperationId::CurrentActivate,
    V2OperationId::TemplatePublish,
    V2OperationId::DeliverablePublish,
];

#[test]
fn p06_r2_product_disclosure_reads_each_operation_surface_at_its_owned_path() {
    let root = tempfile::tempdir().unwrap();
    let binary = gtkg_binary();
    let system = cli_call(
        &binary,
        root.path(),
        &OperationRequestV2::new("system.describe", "p06-r2-system", json!({})),
    );
    assert_eq!(system["result"]["public_operation_count"], 46);
    assert_eq!(system["result"]["implemented_operation_count"], 46);
    assert_eq!(system["result"]["callable_operation_count"], 42);

    let capability = cli_call(
        &binary,
        root.path(),
        &OperationRequestV2::new("capability.describe", "p06-r2-capability", json!({})),
    );
    assert_eq!(
        capability["result"]["operation_surface"]["public_operation_count"],
        46
    );
    assert_eq!(
        capability["result"]["operation_surface"]["implemented_operation_count"],
        46
    );
    assert_eq!(
        capability["result"]["operation_surface"]["complete_46_operation_product"],
        true
    );
}

#[test]
fn p06_r2_all_46_reach_real_handlers_with_cli_mcp_and_effect_parity() {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("invalid.json"), b"{}\n").unwrap();
    fs::create_dir(root.path().join("invalid-dir")).unwrap();
    let binary = gtkg_binary();
    let all = discovery_profiles_v03()
        .into_iter()
        .find(|profile| profile.profile_id.as_str() == "all")
        .unwrap();
    let mut mcp = LineChild::spawn(&binary, root.path(), &all.digest);
    let listed = mcp.send(json!({
        "jsonrpc": "2.0", "id": "p06-r2-list", "method": "tools/list", "params": {}
    }));
    let tools = listed["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 46);

    let payloads = payloads(root.path());
    assert_eq!(
        payloads.keys().map(String::as_str).collect::<BTreeSet<_>>(),
        V2_PUBLIC_OPERATIONS
            .iter()
            .map(|definition| definition.id.as_str())
            .collect::<BTreeSet<_>>()
    );
    let mut callable_reached = BTreeSet::new();
    let mut denied = BTreeSet::new();
    let mut negative = BTreeSet::new();
    let mut effects = BTreeSet::new();

    for definition in V2_PUBLIC_OPERATIONS {
        let operation = definition.id;
        let payload = payloads.get(operation.as_str()).unwrap().clone();
        let tool = tools
            .iter()
            .find(|tool| tool["x-gtkg-operation-id"] == operation.as_str())
            .unwrap();
        assert_eq!(tool["x-gtkg-availability"], "implemented");
        assert_eq!(
            tool["x-gtkg-callability"],
            serde_json::to_value(definition.callability).unwrap()
        );
        assert_eq!(
            tool["x-gtkg-side-effect"],
            serde_json::to_value(definition.side_effect).unwrap()
        );
        effects.insert(operation);

        let request = OperationRequestV2::new(
            operation.as_str(),
            format!("p06-r2-positive-{}", operation.as_str()),
            payload.clone(),
        );
        let cli = cli_call(&binary, root.path(), &request);
        let rpc = mcp.send(json!({
            "jsonrpc": "2.0",
            "id": format!("p06-r2-mcp-positive-{}", operation.as_str()),
            "method": "tools/call",
            "params": {"name": operation.mcp_tool_name(), "arguments": request}
        }));
        let mut cli_business = cli.clone();
        let mut mcp_business = rpc["result"]["structuredContent"].clone();
        strip_runtime(&mut cli_business);
        strip_runtime(&mut mcp_business);
        assert_eq!(
            mcp_business,
            cli_business,
            "positive transport drift for {}",
            operation.as_str()
        );
        assert_eq!(cli_business["protocol_version"], PROTOCOL_VERSION_V2);
        assert_eq!(
            cli_business["request_id"],
            format!("p06-r2-positive-{}", operation.as_str())
        );
        assert_eq!(
            rpc["result"]["isError"],
            cli_business.get("error").is_some()
        );

        if definition.callability == CallabilityV2::DeniedByPolicy {
            assert_eq!(cli_business["error"]["code"], "E_SIDE_EFFECT_DENIED");
            assert_eq!(cli_business["error"]["stage"], "effect-policy");
            denied.insert(operation);
        } else if let Some(error) = cli_business.get("error") {
            assert_ne!(error["code"], "E_OPERATION_NOT_IMPLEMENTED");
            assert_ne!(error["stage"], "dispatch");
            assert_ne!(error["stage"], "request-schema");
            assert_ne!(
                error["stage"],
                "payload-schema",
                "schema-valid positive fixture rejected for {}: {error}",
                operation.as_str()
            );
            callable_reached.insert(operation);
        } else {
            assert_eq!(cli_business["operation_id"], operation.as_str());
            assert!(cli_business["result"].is_object());
            callable_reached.insert(operation);
        }

        let invalid = json!({
            "protocol_version": PROTOCOL_VERSION_V2,
            "operation_id": operation.as_str(),
            "request_id": format!("p06-r2-negative-{}", operation.as_str()),
            "payload": payload,
            "unexpected_transport_field": true
        });
        let cli_invalid = cli_call_value(&binary, root.path(), operation.as_str(), &invalid);
        let rpc_invalid = mcp.send(json!({
            "jsonrpc": "2.0",
            "id": format!("p06-r2-mcp-negative-{}", operation.as_str()),
            "method": "tools/call",
            "params": {"name": operation.mcp_tool_name(), "arguments": invalid}
        }));
        assert_eq!(rpc_invalid["result"]["structuredContent"], cli_invalid);
        assert_eq!(cli_invalid["error"]["code"], "E_INVALID_REQUEST");
        assert_eq!(cli_invalid["error"]["stage"], "request-schema");
        negative.insert(operation);
    }

    assert_eq!(callable_reached.len(), 42);
    assert_eq!(denied, POLICY_DENIED.into_iter().collect());
    assert_eq!(negative.len(), 46);
    assert_eq!(effects.len(), 46);
}

fn payloads(root: &Path) -> BTreeMap<String, Value> {
    let mut value: Value =
        serde_json::from_str(include_str!("../fixtures/v03_p06/transport-payloads.json")).unwrap();
    // Keep the original fixture artifact intact; the public graph handlers now
    // consume the pinned file-index contract disclosed by the r6 fixture.
    let graph: BTreeMap<String, Value> = serde_json::from_str(include_str!(
        "../fixtures/v03_p06/transport-graph-payloads-current-r6.json"
    ))
    .unwrap();
    value.as_object_mut().unwrap().extend(graph);
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
        Value::Array(values) => {
            for value in values {
                replace_root(value, root);
            }
        }
        Value::Object(values) => {
            for value in values.values_mut() {
                replace_root(value, root);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

fn strip_runtime(value: &mut Value) {
    if let Some(result) = value.get_mut("result").and_then(Value::as_object_mut) {
        result.remove("runtime");
    }
}

fn cli_call(binary: &Path, root: &Path, request: &OperationRequestV2) -> Value {
    cli_call_value(
        binary,
        root,
        request.operation_id.as_str(),
        &serde_json::to_value(request).unwrap(),
    )
}

fn cli_call_value(binary: &Path, root: &Path, operation: &str, request: &Value) -> Value {
    let mut child = Command::new(binary)
        .args([
            "v2-op",
            operation,
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
        "GTKG v2-op failed: {}",
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
