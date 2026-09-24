//! P06 r6: one SHA-bound current-binary denominator for the complete local
//! V0.3 transport surface.  It deliberately keeps the r1-r5 tests and their
//! historical graph-schema Reds immutable rather than including them.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Output, Stdio};

use gtkg_protocol::v2::{
    CallabilityV2, OperationRequestV2, PROTOCOL_VERSION_V2, V2_PUBLIC_OPERATIONS, V2OperationId,
};
use gtkg_protocol::v03::discovery_profiles_v03;
use gtkg_protocol::{OperationId, PUBLIC_OPERATIONS};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const POLICY_DENIED: [V2OperationId; 4] = [
    V2OperationId::GitPublish,
    V2OperationId::CurrentActivate,
    V2OperationId::TemplatePublish,
    V2OperationId::DeliverablePublish,
];

const V1_SCHEMA_PROJECTION_SHA256: &str =
    "sha256:d5589096e6e3a1fd6c10420749e570c60b7f28bccae0f6bbaf13256d9b445c82";
const BASE_FIXTURE: &[u8] = include_bytes!("../fixtures/v03_p06/transport-payloads.json");
const GRAPH_FIXTURE: &[u8] =
    include_bytes!("../fixtures/v03_p06/transport-graph-payloads-current-r6.json");
const TEST_SOURCE: &[u8] = include_bytes!("v03_p06_current_transport_successor_r6.rs");
const RUNNER_SOURCE: &[u8] = include_bytes!("../../../scripts/v03/run-p06-current-transport-r6.sh");

fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn env_required(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("P06 r6 requires {name}"))
}

fn current_binary() -> (PathBuf, String) {
    let binary = PathBuf::from(env_required("GTKG_BIN"));
    let binary_sha256 = env_required("P06_BINARY_SHA256");
    assert!(binary.is_file(), "GTKG_BIN must be a current binary");
    assert_eq!(sha256(&fs::read(&binary).unwrap()), binary_sha256);
    assert_eq!(
        sha256(BASE_FIXTURE),
        env_required("P06_BASE_FIXTURE_SHA256")
    );
    assert_eq!(
        sha256(GRAPH_FIXTURE),
        env_required("P06_GRAPH_FIXTURE_SHA256")
    );
    assert_eq!(sha256(TEST_SOURCE), env_required("P06_TEST_SOURCE_SHA256"));
    assert_eq!(sha256(RUNNER_SOURCE), env_required("P06_HARNESS_SHA256"));

    let executable = PathBuf::from(env_required("P06_TEST_EXECUTABLE"));
    assert_eq!(
        sha256(&fs::read(&executable).unwrap()),
        env_required("P06_TEST_EXECUTABLE_SHA256")
    );
    assert_eq!(
        fs::canonicalize(executable).unwrap(),
        fs::canonicalize(std::env::current_exe().unwrap()).unwrap()
    );
    let manifest = PathBuf::from(env_required("P06_SOURCE_MANIFEST_PATH"));
    let manifest_bytes = fs::read(&manifest).unwrap();
    assert_eq!(
        sha256(&manifest_bytes),
        env_required("P06_SOURCE_MANIFEST_SHA256")
    );
    let manifest_text = String::from_utf8(manifest_bytes).unwrap();
    assert!(manifest_text.contains("v03_p06_current_transport_successor_r6.rs"));
    assert!(manifest_text.contains("transport-graph-payloads-current-r6.json"));
    (binary, binary_sha256)
}

fn replace_root(value: &mut Value, root: &str) {
    match value {
        Value::String(text) if text.contains("$ROOT") => *text = text.replace("$ROOT", root),
        Value::Array(values) => values
            .iter_mut()
            .for_each(|entry| replace_root(entry, root)),
        Value::Object(values) => values
            .values_mut()
            .for_each(|entry| replace_root(entry, root)),
        Value::String(_) | Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

fn current_payloads(root: &Path) -> BTreeMap<String, Value> {
    let mut base: Value = serde_json::from_slice(BASE_FIXTURE).unwrap();
    replace_root(&mut base, &root.to_string_lossy());
    let mut payloads: BTreeMap<String, Value> = serde_json::from_value(base).unwrap();
    let graph: BTreeMap<String, Value> = serde_json::from_slice(GRAPH_FIXTURE).unwrap();
    assert_eq!(graph.len(), 6);
    for (operation, payload) in graph {
        assert!(operation.starts_with("graph."));
        payloads.insert(operation, payload);
    }
    assert_eq!(payloads.len(), 46);
    assert_eq!(
        payloads.keys().map(String::as_str).collect::<BTreeSet<_>>(),
        V2_PUBLIC_OPERATIONS
            .iter()
            .map(|definition| definition.id.as_str())
            .collect::<BTreeSet<_>>()
    );
    payloads
}

fn cli_output(
    binary: &Path,
    root: &Path,
    operation: &str,
    request: &Value,
    profile: Option<(&str, &str)>,
) -> Output {
    let mut command = Command::new(binary);
    command
        .args(["v2-op", operation, "--request", "-", "--output", "json"])
        .current_dir(root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some((profile_id, digest)) = profile {
        command.args(["--profile", profile_id, "--profile-digest", digest]);
    }
    let mut child = command.spawn().unwrap();
    serde_json::to_writer(child.stdin.as_mut().unwrap(), request).unwrap();
    drop(child.stdin.take());
    child.wait_with_output().unwrap()
}

fn cli_call(
    binary: &Path,
    root: &Path,
    profile: &str,
    digest: &str,
    operation: &str,
    request: &Value,
) -> Value {
    let output = cli_output(binary, root, operation, request, Some((profile, digest)));
    assert!(
        output.status.success(),
        "explicit-profile CLI failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn cli_profile_error(output: Output) -> Value {
    assert!(
        !output.status.success(),
        "profile rejection unexpectedly succeeded"
    );
    serde_json::from_slice(&output.stderr).unwrap_or_else(|error| {
        panic!(
            "profile error was not JSON: {error}: {}",
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

fn cli_discovery(binary: &Path, root: &Path, profile: &str, digest: &str) -> Value {
    let output = Command::new(binary)
        .args([
            "v2-discover",
            "--profile",
            profile,
            "--profile-digest",
            digest,
            "--output",
            "json",
        ])
        .current_dir(root)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "v2 discovery failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn cli_stale_discovery(binary: &Path, root: &Path, profile: &str) -> Value {
    let output = Command::new(binary)
        .args([
            "v2-discover",
            "--profile",
            profile,
            "--profile-digest",
            "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "--output",
            "json",
        ])
        .current_dir(root)
        .output()
        .unwrap();
    cli_profile_error(output)
}

struct LineChild {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl LineChild {
    fn spawn_v2(binary: &Path, root: &Path, profile: &str, digest: &str) -> Self {
        Self::spawn(
            binary,
            root,
            &[
                "mcp",
                "serve",
                "--protocol",
                "v2",
                "--profile",
                profile,
                "--profile-digest",
                digest,
                "--stdio",
            ],
        )
    }

    fn spawn_v1(binary: &Path, root: &Path) -> Self {
        Self::spawn(binary, root, &["mcp", "serve", "--stdio"])
    }

    fn spawn(binary: &Path, root: &Path, args: &[&str]) -> Self {
        let mut child = Command::new(binary)
            .args(args)
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

fn assert_default_cli_is_core(
    binary: &Path,
    root: &Path,
    binary_sha256: &str,
    payloads: &BTreeMap<String, Value>,
) {
    let core = discovery_profiles_v03()
        .into_iter()
        .find(|profile| profile.profile_id.as_str() == "core")
        .unwrap();
    let system = OperationRequestV2::new("system.describe", "p06-r6-default-core", json!({}));
    let output = cli_output(
        binary,
        root,
        "system.describe",
        &serde_json::to_value(system).unwrap(),
        None,
    );
    assert!(output.status.success());
    let response: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response["result"]["runtime"]["profile_id"], "core");
    assert_eq!(response["result"]["runtime"]["profile_digest"], core.digest);
    assert_eq!(
        response["result"]["runtime"]["binary_sha256"],
        binary_sha256
    );

    let graph_request = OperationRequestV2::new(
        "graph.neighbors",
        "p06-r6-default-hidden",
        payloads["graph.neighbors"].clone(),
    );
    let rejection = cli_profile_error(cli_output(
        binary,
        root,
        "graph.neighbors",
        &serde_json::to_value(graph_request).unwrap(),
        None,
    ));
    assert_eq!(rejection["code"], "E_OPERATION_NOT_IN_PROFILE");
    assert_eq!(rejection["profile_id"], "core");
    assert_eq!(rejection["operation_id"], "graph.neighbors");
}

fn assert_profiles(binary: &Path, root: &Path, payloads: &BTreeMap<String, Value>) {
    let profiles = discovery_profiles_v03();
    assert_eq!(profiles.len(), 7);
    let all_ids = V2_PUBLIC_OPERATIONS
        .iter()
        .map(|definition| definition.id)
        .collect::<BTreeSet<_>>();
    for profile in profiles {
        let profile_id = profile.profile_id.as_str();
        let cli = cli_discovery(binary, root, profile_id, &profile.digest);
        let mut mcp = LineChild::spawn_v2(binary, root, profile_id, &profile.digest);
        let listed = mcp.send(json!({
            "jsonrpc":"2.0",
            "id":format!("p06-r6-list-{profile_id}"),
            "method":"tools/list",
            "params":{}
        }));
        assert_eq!(
            listed["result"], cli,
            "{profile_id} CLI/MCP discovery drift"
        );
        let tools = cli["tools"].as_array().unwrap();
        assert_eq!(
            tools
                .iter()
                .map(|tool| tool["x-gtkg-operation-id"].as_str().unwrap())
                .collect::<Vec<_>>(),
            profile
                .operation_ids
                .iter()
                .map(|operation| operation.as_str())
                .collect::<Vec<_>>()
        );
        if profile_id == "core" {
            assert_eq!(tools.len(), 10);
        }

        let stale_cli = cli_stale_discovery(binary, root, profile_id);
        assert_eq!(stale_cli["code"], "E_PROFILE_STALE");
        let stale_digest =
            "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        let mut stale_mcp = LineChild::spawn_v2(binary, root, profile_id, stale_digest);
        let stale_rpc = stale_mcp.send(json!({
            "jsonrpc":"2.0",
            "id":format!("p06-r6-stale-{profile_id}"),
            "method":"tools/list",
            "params":{}
        }));
        assert_eq!(stale_rpc["error"]["code"], -32003);
        assert_eq!(stale_rpc["error"]["data"]["code"], "E_PROFILE_STALE");

        let selected = profile
            .operation_ids
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        let hidden = all_ids.difference(&selected).copied().next();
        if let Some(hidden) = hidden {
            let request = OperationRequestV2::new(
                hidden.as_str(),
                format!("p06-r6-hidden-{profile_id}"),
                payloads[hidden.as_str()].clone(),
            );
            let cli_hidden = cli_profile_error(cli_output(
                binary,
                root,
                hidden.as_str(),
                &serde_json::to_value(&request).unwrap(),
                Some((profile_id, &profile.digest)),
            ));
            assert_eq!(cli_hidden["code"], "E_OPERATION_NOT_IN_PROFILE");
            assert_eq!(cli_hidden["profile_id"], profile_id);
            let rpc_hidden = mcp.send(json!({
                "jsonrpc":"2.0",
                "id":format!("p06-r6-hidden-mcp-{profile_id}"),
                "method":"tools/call",
                "params":{"name":hidden.mcp_tool_name(),"arguments":request}
            }));
            assert_eq!(rpc_hidden["error"]["code"], -32602);
            assert_eq!(
                rpc_hidden["error"]["data"]["code"],
                "E_OPERATION_NOT_IN_PROFILE"
            );
            assert_eq!(rpc_hidden["error"]["data"]["profile_id"], profile_id);
            assert_eq!(rpc_hidden["error"]["data"]["operation_id"], hidden.as_str());
        } else {
            assert_eq!(profile_id, "all");
            assert_eq!(selected, all_ids);
        }
    }
}

fn assert_all_transport(
    binary: &Path,
    root: &Path,
    binary_sha256: &str,
    payloads: &BTreeMap<String, Value>,
) {
    let all = discovery_profiles_v03()
        .into_iter()
        .find(|profile| profile.profile_id.as_str() == "all")
        .unwrap();
    let mut mcp = LineChild::spawn_v2(binary, root, "all", &all.digest);
    let listed = mcp.send(json!({
        "jsonrpc":"2.0", "id":"p06-r6-all-list", "method":"tools/list", "params":{}
    }));
    let tools = listed["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 46);

    let mut callable = BTreeSet::new();
    let mut denied = BTreeSet::new();
    let mut negative = BTreeSet::new();
    let mut effect_metadata = BTreeSet::new();
    for definition in V2_PUBLIC_OPERATIONS {
        let operation = definition.id;
        let payload = payloads[operation.as_str()].clone();
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
        effect_metadata.insert(operation);

        let request = OperationRequestV2::new(
            operation.as_str(),
            format!("p06-r6-positive-{}", operation.as_str()),
            payload.clone(),
        );
        let request_value = serde_json::to_value(&request).unwrap();
        let cli = cli_call(
            binary,
            root,
            "all",
            &all.digest,
            operation.as_str(),
            &request_value,
        );
        let rpc = mcp.send(json!({
            "jsonrpc":"2.0",
            "id":format!("p06-r6-mcp-positive-{}", operation.as_str()),
            "method":"tools/call",
            "params":{"name":operation.mcp_tool_name(),"arguments":request}
        }));
        assert_eq!(
            rpc["result"]["structuredContent"],
            cli,
            "{}",
            operation.as_str()
        );
        let is_error = cli.get("error").is_some();
        assert_eq!(rpc["result"]["isError"], is_error, "{}", operation.as_str());
        if !is_error {
            assert_eq!(cli["result"]["runtime"]["binary_sha256"], binary_sha256);
            assert_eq!(cli["result"]["runtime"]["profile_id"], "all");
            assert_eq!(cli["result"]["runtime"]["profile_digest"], all.digest);
        }
        if operation == V2OperationId::SystemDescribe {
            assert_eq!(cli["result"]["public_operation_count"], 46);
            assert_eq!(cli["result"]["implemented_operation_count"], 46);
            assert_eq!(cli["result"]["callable_operation_count"], 42);
        }
        if operation == V2OperationId::CapabilityDescribe {
            assert_eq!(
                cli["result"]["operation_surface"]["public_operation_count"],
                46
            );
            assert_eq!(
                cli["result"]["operation_surface"]["implemented_operation_count"],
                46
            );
            assert_eq!(
                cli["result"]["operation_surface"]["complete_46_operation_product"],
                true
            );
        }
        if definition.callability == CallabilityV2::DeniedByPolicy {
            assert_eq!(cli["error"]["code"], "E_SIDE_EFFECT_DENIED");
            assert_eq!(cli["error"]["stage"], "effect-policy");
            denied.insert(operation);
        } else {
            if let Some(error) = cli.get("error") {
                assert_ne!(error["code"], "E_OPERATION_NOT_IMPLEMENTED");
                assert_ne!(error["stage"], "dispatch");
                assert_ne!(error["stage"], "request-schema");
                assert_ne!(error["stage"], "payload-schema");
            }
            callable.insert(operation);
        }

        let invalid = json!({
            "protocol_version": PROTOCOL_VERSION_V2,
            "operation_id": operation.as_str(),
            "request_id": format!("p06-r6-negative-{}", operation.as_str()),
            "payload": payload,
            "unexpected_transport_field": true
        });
        let cli_invalid = cli_call(
            binary,
            root,
            "all",
            &all.digest,
            operation.as_str(),
            &invalid,
        );
        let rpc_invalid = mcp.send(json!({
            "jsonrpc":"2.0",
            "id":format!("p06-r6-negative-mcp-{}", operation.as_str()),
            "method":"tools/call",
            "params":{"name":operation.mcp_tool_name(),"arguments":invalid}
        }));
        assert_eq!(rpc_invalid["result"]["structuredContent"], cli_invalid);
        assert_eq!(rpc_invalid["result"]["isError"], true);
        assert_eq!(cli_invalid["error"]["code"], "E_INVALID_REQUEST");
        assert_eq!(cli_invalid["error"]["stage"], "request-schema");
        negative.insert(operation);
    }
    assert_eq!(callable.len(), 42);
    assert_eq!(denied, POLICY_DENIED.into_iter().collect());
    assert_eq!(negative.len(), 46);
    assert_eq!(effect_metadata.len(), 46);
    println!("P06_R6_OBSERVED all=46 callable=42 denied=4 negative=46 effect_metadata=46");
}

fn assert_v1_freeze(binary: &Path, root: &Path) {
    const V1_IDS: [&str; 34] = [
        "system.describe",
        "config.validate",
        "source.inspect",
        "build.plan",
        "build.prepare",
        "summary.next",
        "summary.accept",
        "build.finalize",
        "run.get",
        "run.cancel",
        "bundle.verify",
        "bundle.query",
        "bundle.compare",
        "snapshot.create",
        "snapshot.verify",
        "snapshot.restore",
        "git.publish",
        "current.get",
        "current.activate",
        "node.describe",
        "federation.validate",
        "template.list",
        "template.resolve",
        "template.prefetch",
        "template.get",
        "template.validate",
        "template.derive",
        "template.publish",
        "deliverable.derive",
        "deliverable.publish",
        "a2ui.resolve",
        "a2ui.generate",
        "a2ui.get",
        "a2ui.validate",
    ];
    assert_eq!(PUBLIC_OPERATIONS.len(), 34);
    assert_eq!(
        PUBLIC_OPERATIONS
            .iter()
            .map(|definition| definition.id.as_str())
            .collect::<Vec<_>>(),
        V1_IDS
    );
    assert!(V1_IDS.iter().all(|id| OperationId::parse(id).is_some()));
    let mut mcp = LineChild::spawn_v1(binary, root);
    let listed = mcp.send(json!({
        "jsonrpc":"2.0", "id":"p06-r6-v1-list", "method":"tools/list", "params":{}
    }));
    let tools = listed["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 34);
    assert_eq!(
        tools
            .iter()
            .map(|tool| tool["x-gtkg-operation-id"].as_str().unwrap())
            .collect::<Vec<_>>(),
        V1_IDS
    );
    assert_eq!(
        sha256(&serde_json::to_vec(tools).unwrap()),
        V1_SCHEMA_PROJECTION_SHA256
    );
}

#[test]
fn p06_r6_sha_bound_current_binary_full_transport_profile_and_v1_contract() {
    let (binary, binary_sha256) = current_binary();
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("invalid.json"), b"{}\n").unwrap();
    fs::create_dir(root.path().join("invalid-dir")).unwrap();
    let payloads = current_payloads(root.path());
    assert_default_cli_is_core(&binary, root.path(), &binary_sha256, &payloads);
    assert_all_transport(&binary, root.path(), &binary_sha256, &payloads);
    assert_profiles(&binary, root.path(), &payloads);
    assert_v1_freeze(&binary, root.path());
}
