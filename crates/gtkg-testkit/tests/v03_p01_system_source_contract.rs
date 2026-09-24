//! P01 immutable contract: four real system/config/source handlers with a
//! closed v2 payload surface, bounded effects, exact-source capture, and
//! transport parity.

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use gtkg_core::source_v2::{
    CaptureErrorCode, SourceCaptureRequestV2, capture_source_snapshot_v2_with_observer,
};
use gtkg_core::{CallContext, Dispatcher, EffectPolicy, TransportKind};
use gtkg_protocol::v2::{
    CallabilityV2, OperationAvailabilityV2, OperationRequestV2, SourceCaptureModeV2,
    SourceSnapshotV2, V2_PUBLIC_OPERATIONS, V2ErrorCode, V2OperationId, v2_operation_definition,
    v2_operation_request_schema,
};
use serde_json::{Value, json};

const P01_OPERATIONS: [V2OperationId; 4] = [
    V2OperationId::SystemDescribe,
    V2OperationId::ConfigValidate,
    V2OperationId::CapabilityDescribe,
    V2OperationId::SourceCapture,
];

#[test]
fn p01_promotes_only_four_real_handlers_and_publishes_closed_payload_schemas() {
    for operation_id in P01_OPERATIONS {
        let definition = v2_operation_definition(operation_id).expect("P01 registry entry");
        assert_eq!(
            definition.availability,
            OperationAvailabilityV2::Implemented
        );
        assert_eq!(definition.callability, CallabilityV2::Callable);
        let schema = v2_operation_request_schema(operation_id);
        assert_eq!(schema["additionalProperties"], false);
        assert_eq!(schema["properties"]["payload"]["type"], "object");
        assert_eq!(
            schema["properties"]["payload"]["additionalProperties"],
            false
        );
    }

    for operation_id in [
        V2OperationId::SystemDescribe,
        V2OperationId::CapabilityDescribe,
    ] {
        let schema = v2_operation_request_schema(operation_id);
        assert_eq!(schema["properties"]["payload"]["properties"], json!({}));
        assert_eq!(schema["properties"]["payload"]["required"], json!([]));
    }

    let config = v2_operation_request_schema(V2OperationId::ConfigValidate);
    assert_eq!(
        config["properties"]["payload"]["required"],
        json!(["config_path"])
    );
    assert_eq!(
        object_keys(&config["properties"]["payload"]["properties"]),
        vec!["config_path"]
    );

    let source = v2_operation_request_schema(V2OperationId::SourceCapture);
    assert_eq!(
        source["properties"]["payload"]["required"],
        json!([
            "capture_mode",
            "repository_id",
            "source_root",
            "output_path"
        ])
    );
    assert_eq!(
        object_keys(&source["properties"]["payload"]["properties"]),
        vec![
            "capture_mode",
            "output_path",
            "repository_id",
            "source_root"
        ]
    );
    assert_eq!(
        source["properties"]["payload"]["properties"]["capture_mode"]["enum"],
        json!(["worktree_exact", "directory_exact", "git_commit"])
    );

    let implemented = V2_PUBLIC_OPERATIONS
        .iter()
        .filter(|definition| definition.availability == OperationAvailabilityV2::Implemented)
        .map(|definition| definition.id)
        .collect::<Vec<_>>();
    assert_eq!(implemented.len(), 10, "P01 adds four to six graph handlers");
    assert!(P01_OPERATIONS.iter().all(|id| implemented.contains(id)));
    assert_eq!(
        v2_operation_definition(V2OperationId::AnalysisPlan)
            .expect("successor registry entry")
            .availability,
        OperationAvailabilityV2::NotImplemented,
        "P01 must not promote successor handlers"
    );
}

#[test]
fn p01_direct_handlers_return_real_results_and_persist_a_valid_snapshot() {
    let fixture = Fixture::new();
    let context = fixture.context(EffectPolicy::WorkspaceWrite);

    let system = execute(
        &context,
        OperationRequestV2::new("system.describe", "p01-system", json!({})),
    );
    assert_eq!(system["result"]["product"], "gtkg");
    assert_eq!(system["result"]["protocol_version"], "gtkg.protocol/v2");
    assert_eq!(system["result"]["public_operation_count"], 46);
    assert_eq!(system["result"]["implemented_operation_count"], 10);
    assert_eq!(system["result"]["storage_model"], "okf-and-ordinary-files");
    assert_eq!(system["result"]["database_backend"], Value::Null);

    let config = execute(
        &context,
        OperationRequestV2::new(
            "config.validate",
            "p01-config",
            json!({"config_path": fixture.config_path}),
        ),
    );
    assert_eq!(config["result"]["valid"], true);
    assert_eq!(config["result"]["schema_version"], "gtkg.config/v2");
    assert_eq!(config["result"]["repository_root_count"], 1);
    assert_eq!(config["result"]["database_backend"], Value::Null);

    let capability = execute(
        &context,
        OperationRequestV2::new("capability.describe", "p01-capability", json!({})),
    );
    assert_eq!(
        capability["result"]["schema_version"],
        "gtkg.capability-description/v1"
    );
    assert_eq!(capability["result"]["profile_id"], "GTKG-V0.3-CORE");
    assert_eq!(
        capability["result"]["source_snapshot"]["schema_version"],
        "gtkg.source-snapshot/v2"
    );
    assert_eq!(
        capability["result"]["source_snapshot"]["toctou_policy"],
        "fail_closed"
    );
    assert_eq!(
        capability["result"]["authority"]["external_git_write"],
        false
    );
    assert_eq!(capability["result"]["authority"]["current_write"], false);

    let captured = execute(&context, fixture.source_request("p01-source"));
    assert_eq!(
        captured["result"]["snapshot"]["schema_version"],
        "gtkg.source-snapshot/v2"
    );
    assert_eq!(
        captured["result"]["snapshot"]["repository_id"],
        "p01-fixture"
    );
    assert_eq!(
        captured["result"]["snapshot"]["denominator"]["admitted_entries"],
        1
    );
    assert_eq!(captured["result"]["snapshot_ref"]["readback"], "passed");
    assert_eq!(captured["result"]["canonical_write_count"], 0);
    assert_eq!(captured["result"]["external_write_count"], 0);

    let bytes = fs::read(&fixture.output_path).expect("caller-authorized snapshot output");
    let snapshot: SourceSnapshotV2 =
        serde_json::from_slice(&bytes).expect("persisted SourceSnapshotV2");
    snapshot.validate().expect("complete persisted snapshot");
    assert_eq!(
        captured["result"]["snapshot"]["exact_set_sha256"],
        snapshot.exact_set_sha256
    );
    assert_eq!(
        captured["result"]["snapshot_ref"]["path"],
        fixture.output_path.to_string_lossy().as_ref()
    );
    assert!(
        captured["result"]["snapshot_ref"]["artifact_sha256"]
            .as_str()
            .is_some_and(|digest| digest.starts_with("sha256:") && digest.len() == 71)
    );
}

#[test]
fn p01_closed_payload_effect_path_and_source_failures_are_explicit() {
    let fixture = Fixture::new();
    let writable = fixture.context(EffectPolicy::WorkspaceWrite);
    let read_only = fixture.context(EffectPolicy::ReadOnly);

    let unexpected = Dispatcher
        .execute_v2(
            &writable,
            OperationRequestV2::new(
                "system.describe",
                "p01-unknown-field",
                json!({"unexpected": true}),
            ),
        )
        .expect_err("closed empty payload rejects unknown fields");
    assert_eq!(unexpected.error.code, V2ErrorCode::InvalidRequest);
    assert_eq!(unexpected.error.stage, "payload-schema");

    let denied = Dispatcher
        .execute_v2(&read_only, fixture.source_request("p01-effect-denied"))
        .expect_err("source.capture requires bounded workspace write authority");
    assert_eq!(denied.error.code, V2ErrorCode::SideEffectDenied);
    assert!(!fixture.output_path.exists());

    let outside = tempfile::tempdir().expect("unauthorized source root");
    fs::write(outside.path().join("escape.rs"), "fn escape() {}\n").expect("outside source");
    let escaped = Dispatcher
        .execute_v2(
            &writable,
            OperationRequestV2::new(
                "source.capture",
                "p01-source-escape",
                json!({
                    "capture_mode": "directory_exact",
                    "repository_id": "outside",
                    "source_root": outside.path(),
                    "output_path": fixture.output_path,
                }),
            ),
        )
        .expect_err("caller authority must bound the source root");
    assert_eq!(escaped.error.code, V2ErrorCode::PathEscape);

    let overlap = Dispatcher
        .execute_v2(
            &writable,
            OperationRequestV2::new(
                "source.capture",
                "p01-output-overlap",
                json!({
                    "capture_mode": "directory_exact",
                    "repository_id": "overlap",
                    "source_root": fixture.source_root,
                    "output_path": fixture.source_root.join(".gtkg/source-snapshot.json"),
                }),
            ),
        )
        .expect_err("output below source must fail closed");
    assert_eq!(overlap.error.code, V2ErrorCode::SourceOutputOverlap);

    #[cfg(unix)]
    {
        std::os::unix::fs::symlink("lib.rs", fixture.source_root.join("linked.rs"))
            .expect("source symlink fixture");
        let symlink = Dispatcher
            .execute_v2(&writable, fixture.source_request("p01-symlink"))
            .expect_err("source symlink must fail closed");
        assert_eq!(symlink.error.code, V2ErrorCode::SymlinkRejected);
    }

    let config_outside = Dispatcher
        .execute_v2(
            &writable,
            OperationRequestV2::new(
                "config.validate",
                "p01-config-escape",
                json!({"config_path": outside.path().join("config.json")}),
            ),
        )
        .expect_err("config path must be caller-authorized");
    assert_eq!(config_outside.error.code, V2ErrorCode::PathEscape);
}

#[test]
fn p01_source_capture_retains_the_existing_deterministic_toctou_guard() {
    let fixture = Fixture::new();
    let request = SourceCaptureRequestV2::new(
        SourceCaptureModeV2::DirectoryExact,
        "p01-toctou",
        fixture.source_root.clone(),
        fixture
            .output_path
            .parent()
            .expect("output parent")
            .to_path_buf(),
    );
    let source_file = fixture.source_root.join("lib.rs");
    let error = capture_source_snapshot_v2_with_observer(&request, |path| {
        if path == source_file {
            fs::write(path, "fn changed_during_capture() {}\n").expect("TOCTOU mutation");
        }
    })
    .expect_err("changed bytes must not produce a partial SourceSnapshotV2");
    assert_eq!(error.code(), CaptureErrorCode::SnapshotDrift);
    assert!(!fixture.output_path.exists());
}

#[test]
fn p01_real_cli_and_mcp_have_positive_and_closed_error_parity() {
    let fixture = Fixture::new();
    let binary = gtkg_binary();
    let mut mcp = LineChild::spawn(
        &binary,
        fixture.workspace.path(),
        &["mcp", "serve", "--protocol", "v2", "--stdio"],
    );

    let blocked_list = mcp.send(json!({
        "jsonrpc": "2.0", "id": "p01-list", "method": "tools/list", "params": {}
    }));
    assert_eq!(blocked_list["error"]["data"]["code"], "E_DEAD_TOOL_EXPOSED");
    assert_eq!(
        blocked_list["error"]["data"]["unavailable_operation_ids"]
            .as_array()
            .expect("remaining core operations")
            .len(),
        5,
        "P01 removes exactly four dead tools from the core profile"
    );

    let requests = [
        OperationRequestV2::new("system.describe", "p01-cli-system", json!({})),
        OperationRequestV2::new(
            "config.validate",
            "p01-cli-config",
            json!({"config_path": fixture.config_path}),
        ),
        OperationRequestV2::new("capability.describe", "p01-cli-capability", json!({})),
        fixture.source_request("p01-cli-source"),
    ];
    for request in requests {
        let cli = cli_call(&binary, fixture.workspace.path(), &request);
        let mcp_result = mcp.send(json!({
            "jsonrpc": "2.0",
            "id": format!("mcp-{}", request.request_id),
            "method": "tools/call",
            "params": {
                "name": V2OperationId::parse(&request.operation_id)
                    .expect("known P01 operation")
                    .mcp_tool_name(),
                "arguments": request,
            }
        }));
        assert_eq!(mcp_result["result"]["isError"], false);
        assert_eq!(mcp_result["result"]["structuredContent"], cli);
        assert_eq!(
            mcp_result["result"]["content"][0]["text"],
            serde_json::to_string(&cli).expect("MCP text mirror")
        );
    }

    let invalid = OperationRequestV2::new(
        "capability.describe",
        "p01-cli-invalid",
        json!({"unexpected": true}),
    );
    let cli = cli_call(&binary, fixture.workspace.path(), &invalid);
    let mcp_result = mcp.send(json!({
        "jsonrpc": "2.0",
        "id": "mcp-p01-invalid",
        "method": "tools/call",
        "params": {
            "name": "gtkg_v2_capability_describe",
            "arguments": invalid,
        }
    }));
    assert_eq!(mcp_result["result"]["isError"], true);
    assert_eq!(mcp_result["result"]["structuredContent"], cli);
    assert_eq!(cli["error"]["code"], "E_INVALID_REQUEST");
    assert_eq!(cli["error"]["stage"], "payload-schema");
}

struct Fixture {
    workspace: tempfile::TempDir,
    source_root: PathBuf,
    config_path: PathBuf,
    output_path: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let workspace = tempfile::tempdir().expect("P01 workspace");
        let source_root = workspace.path().join("repository");
        let templates = workspace.path().join("templates");
        fs::create_dir_all(&source_root).expect("source root");
        fs::create_dir_all(&templates).expect("template root");
        fs::write(source_root.join("lib.rs"), "fn stable() {}\n").expect("source fixture");
        let config_path = workspace.path().join("gtkg.config.json");
        fs::write(
            &config_path,
            serde_json::to_vec_pretty(&json!({
                "schema_version": "gtkg.config/v2",
                "workspace_root": workspace.path(),
                "storage_model": "okf-and-ordinary-files",
                "database_backend": null,
                "repositories": [{
                    "repo_id": "p01-fixture",
                    "path": source_root,
                    "role": "source",
                    "include": [],
                    "exclude": [],
                }],
                "template_catalog_roots": [templates],
                "node_endpoints": [],
            }))
            .expect("config JSON"),
        )
        .expect("config fixture");
        let output_path = workspace
            .path()
            .join(".gtkg/source-snapshots/p01-source-snapshot.json");
        Self {
            workspace,
            source_root,
            config_path,
            output_path,
        }
    }

    fn context(&self, effect_policy: EffectPolicy) -> CallContext {
        CallContext::restricted(
            TransportKind::Test,
            vec![self.workspace.path().to_path_buf()],
            effect_policy,
        )
        .expect("bounded P01 context")
    }

    fn source_request(&self, request_id: &str) -> OperationRequestV2 {
        OperationRequestV2::new(
            "source.capture",
            request_id,
            json!({
                "capture_mode": "directory_exact",
                "repository_id": "p01-fixture",
                "source_root": self.source_root,
                "output_path": self.output_path,
            }),
        )
    }
}

fn object_keys(value: &Value) -> Vec<&str> {
    value
        .as_object()
        .expect("schema object")
        .keys()
        .map(String::as_str)
        .collect()
}

fn execute(context: &CallContext, request: OperationRequestV2) -> Value {
    serde_json::to_value(
        Dispatcher
            .execute_v2(context, request)
            .expect("P01 handler success"),
    )
    .expect("P01 response JSON")
}

fn cli_call(binary: &Path, root: &Path, request: &OperationRequestV2) -> Value {
    let mut child = Command::new(binary)
        .args([
            "v2-op",
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
        .expect("spawn GTKG v2 CLI");
    serde_json::to_writer(child.stdin.as_mut().expect("CLI stdin"), request)
        .expect("write CLI request");
    drop(child.stdin.take());
    let output = child.wait_with_output().expect("wait for GTKG CLI");
    assert!(
        output.status.success(),
        "GTKG CLI failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("CLI JSON")
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

    fn send(&mut self, request: Value) -> Value {
        serde_json::to_writer(&mut self.stdin, &request).expect("write MCP frame");
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
