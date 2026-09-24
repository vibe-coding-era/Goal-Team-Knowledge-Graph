// P06 immutable Development contract for the complete v2 product transport.
//
// This is intentionally a real-process harness. It keeps registry presence,
// implementation availability, current callability, profile visibility, and
// operation outcomes on separate axes. A policy denial is an implemented
// outcome, not a dead-tool failure.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use gtkg_core::file_model::tree_sha256;
use gtkg_protocol::v2::{
    CallabilityV2, OperationAvailabilityV2, OperationRequestV2, PROTOCOL_VERSION_V2,
    V2_PUBLIC_OPERATIONS, V2OperationId,
};
use gtkg_protocol::v03::discovery_profiles_v03;
use gtkg_protocol::{
    NodeDescriptor, NodeTransport, OperationId, PUBLIC_OPERATIONS, ShardResult, WorkUnit,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const V1_SCHEMA_PROJECTION_SHA256: &str =
    "sha256:d5589096e6e3a1fd6c10420749e570c60b7f28bccae0f6bbaf13256d9b445c82";

const POLICY_DENIED: [V2OperationId; 4] = [
    V2OperationId::GitPublish,
    V2OperationId::CurrentActivate,
    V2OperationId::TemplatePublish,
    V2OperationId::DeliverablePublish,
];

#[test]
fn p06_all_46_bindings_are_implemented_and_product_disclosure_is_current() {
    assert_eq!(V2_PUBLIC_OPERATIONS.len(), 46);
    assert!(
        V2_PUBLIC_OPERATIONS
            .iter()
            .all(|definition| definition.availability == OperationAvailabilityV2::Implemented)
    );
    assert_eq!(
        V2_PUBLIC_OPERATIONS
            .iter()
            .filter(|definition| definition.callability == CallabilityV2::Callable)
            .count(),
        42
    );
    assert_eq!(
        V2_PUBLIC_OPERATIONS
            .iter()
            .filter(|definition| definition.callability == CallabilityV2::DeniedByPolicy)
            .map(|definition| definition.id)
            .collect::<BTreeSet<_>>(),
        POLICY_DENIED.into_iter().collect()
    );

    let fixture = Fixture::new();
    for (operation, request_id) in [
        (V2OperationId::SystemDescribe, "p06-system-disclosure"),
        (
            V2OperationId::CapabilityDescribe,
            "p06-capability-disclosure",
        ),
    ] {
        let response = cli_call(
            &gtkg_binary(),
            fixture.root(),
            &OperationRequestV2::new(operation.as_str(), request_id, json!({})),
        );
        assert_eq!(response["result"]["public_operation_count"], 46);
        assert_eq!(response["result"]["implemented_operation_count"], 46);
        if operation == V2OperationId::SystemDescribe {
            assert_eq!(response["result"]["callable_operation_count"], 42);
        } else {
            assert_eq!(
                response["result"]["operation_surface"]["complete_46_operation_product"],
                true
            );
        }
    }
}

#[test]
fn p06_seven_profiles_have_exact_cli_mcp_discovery_and_hidden_tools_stay_hidden() {
    let binary = gtkg_binary();
    let fixture = Fixture::new();
    let profiles = discovery_profiles_v03();
    assert_eq!(profiles.len(), 7);

    for profile in profiles {
        let profile_id = profile.profile_id.as_str();
        let cli = cli_discovery(&binary, fixture.root(), profile_id, Some(&profile.digest));
        let mut mcp =
            LineChild::spawn_v2(&binary, fixture.root(), profile_id, Some(&profile.digest));
        let listed = mcp.send(json!({
            "jsonrpc": "2.0",
            "id": format!("p06-list-{profile_id}"),
            "method": "tools/list",
            "params": {}
        }));
        assert_eq!(
            listed["result"], cli,
            "profile discovery drift: {profile_id}"
        );
        assert_eq!(cli["profile_id"], profile_id);
        assert_eq!(cli["profile_digest"], profile.digest);
        assert_eq!(
            cli["tools"]
                .as_array()
                .expect("profile tools")
                .iter()
                .map(|tool| tool["x-gtkg-operation-id"].as_str().unwrap())
                .collect::<Vec<_>>(),
            profile
                .operation_ids
                .iter()
                .map(|operation| operation.as_str())
                .collect::<Vec<_>>()
        );

        if let Some(hidden) = V2_PUBLIC_OPERATIONS
            .iter()
            .map(|definition| definition.id)
            .find(|operation| !profile.operation_ids.contains(operation))
        {
            let hidden_response = mcp.send(json!({
                "jsonrpc": "2.0",
                "id": format!("p06-hidden-{profile_id}"),
                "method": "tools/call",
                "params": {
                    "name": hidden.mcp_tool_name(),
                    "arguments": OperationRequestV2::new(
                        hidden.as_str(),
                        format!("p06-hidden-{profile_id}"),
                        json!({}),
                    )
                }
            }));
            assert_eq!(hidden_response["error"]["code"], -32602, "{profile_id}");
            assert_eq!(
                hidden_response["error"]["data"]["code"],
                "E_OPERATION_NOT_IN_PROFILE",
                "{profile_id} exposed {} through tools/call",
                hidden.as_str()
            );
            assert_eq!(hidden_response["error"]["data"]["profile_id"], profile_id);
            assert_eq!(
                hidden_response["error"]["data"]["operation_id"],
                hidden.as_str()
            );
        }
    }
}

#[test]
fn p06_all_46_have_cli_mcp_positive_negative_and_effect_denominator_coverage() {
    let binary = gtkg_binary();
    let fixture = Fixture::new();
    let all_profile = discovery_profiles_v03()
        .into_iter()
        .find(|profile| profile.profile_id.as_str() == "all")
        .expect("all profile");
    let mut mcp = LineChild::spawn_v2(&binary, fixture.root(), "all", Some(&all_profile.digest));
    let listed = mcp.send(json!({
        "jsonrpc": "2.0", "id": "p06-all-list", "method": "tools/list", "params": {}
    }));
    let tools = listed["result"]["tools"].as_array().expect("all tools");
    assert_eq!(tools.len(), 46);

    let mut reached_handler = BTreeSet::new();
    let mut policy_denied = BTreeSet::new();
    let mut negative_closed = BTreeSet::new();
    let mut effect_bound = BTreeSet::new();

    for definition in V2_PUBLIC_OPERATIONS {
        let operation = definition.id;
        let tool = tools
            .iter()
            .find(|tool| tool["x-gtkg-operation-id"] == operation.as_str())
            .expect("operation in all discovery");
        assert_eq!(tool["x-gtkg-availability"], "implemented");
        assert_eq!(
            tool["x-gtkg-callability"],
            serde_json::to_value(definition.callability).unwrap()
        );
        assert_eq!(
            tool["x-gtkg-side-effect"],
            serde_json::to_value(definition.side_effect).unwrap()
        );
        effect_bound.insert(operation);

        let request = OperationRequestV2::new(
            operation.as_str(),
            format!("p06-positive-{}", operation.as_str()),
            fixture.payload(operation),
        );
        let cli = cli_call(&binary, fixture.root(), &request);
        let mcp_response = mcp.send(json!({
            "jsonrpc": "2.0",
            "id": format!("p06-mcp-positive-{}", operation.as_str()),
            "method": "tools/call",
            "params": {"name": operation.mcp_tool_name(), "arguments": request}
        }));
        let mut cli_business = cli.clone();
        let mut mcp_business = mcp_response["result"]["structuredContent"].clone();
        strip_runtime_profile(&mut cli_business);
        strip_runtime_profile(&mut mcp_business);
        assert_eq!(
            mcp_business,
            cli_business,
            "positive CLI/MCP drift for {}",
            operation.as_str()
        );
        assert_eq!(cli_business["protocol_version"], PROTOCOL_VERSION_V2);
        assert_eq!(cli_business["operation_id"], operation.as_str());
        if definition.callability == CallabilityV2::DeniedByPolicy {
            assert_eq!(cli_business["error"]["code"], "E_SIDE_EFFECT_DENIED");
            assert_eq!(cli_business["error"]["stage"], "effect-policy");
            assert_eq!(mcp_response["result"]["isError"], true);
            policy_denied.insert(operation);
        } else {
            assert_ne!(
                cli_business["error"]["code"],
                "E_OPERATION_NOT_IMPLEMENTED",
                "{} fell back to an unimplemented slot",
                operation.as_str()
            );
            assert_ne!(
                cli_business["error"]["stage"],
                "dispatch",
                "{} failed before its bound handler",
                operation.as_str()
            );
            reached_handler.insert(operation);
        }

        let invalid = json!({
            "protocol_version": PROTOCOL_VERSION_V2,
            "operation_id": operation.as_str(),
            "request_id": format!("p06-negative-{}", operation.as_str()),
            "payload": fixture.payload(operation),
            "unexpected_transport_field": true
        });
        let cli_invalid = cli_call_value(&binary, fixture.root(), operation.as_str(), &invalid);
        let mcp_invalid = mcp.send(json!({
            "jsonrpc": "2.0",
            "id": format!("p06-mcp-negative-{}", operation.as_str()),
            "method": "tools/call",
            "params": {"name": operation.mcp_tool_name(), "arguments": invalid}
        }));
        assert_eq!(
            mcp_invalid["result"]["structuredContent"],
            cli_invalid,
            "negative CLI/MCP drift for {}",
            operation.as_str()
        );
        assert_eq!(cli_invalid["error"]["code"], "E_INVALID_REQUEST");
        assert_eq!(cli_invalid["error"]["stage"], "request-schema");
        negative_closed.insert(operation);
    }

    assert_eq!(reached_handler.len(), 42);
    assert_eq!(policy_denied, POLICY_DENIED.into_iter().collect());
    assert_eq!(negative_closed.len(), 46);
    assert_eq!(effect_bound.len(), 46);
}

#[test]
fn p06_v1_34_registry_schema_and_default_mcp_surface_remain_frozen() {
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

    let binary = gtkg_binary();
    let fixture = Fixture::new();
    let mut v1 = LineChild::spawn_v1(&binary, fixture.root());
    let listed = v1.send(json!({
        "jsonrpc": "2.0", "id": "p06-v1-list", "method": "tools/list", "params": {}
    }));
    let tools = listed["result"]["tools"].as_array().expect("v1 tools");
    assert_eq!(tools.len(), 34);
    assert_eq!(
        tools
            .iter()
            .map(|tool| tool["x-gtkg-operation-id"].as_str().unwrap())
            .collect::<Vec<_>>(),
        V1_IDS
    );
    assert_eq!(
        sha256(&serde_json::to_vec(tools).expect("v1 schema projection")),
        V1_SCHEMA_PROJECTION_SHA256
    );
}

struct Fixture {
    root: tempfile::TempDir,
    current_path: PathBuf,
    current_sha256: String,
    catalog_root: PathBuf,
    parent_root: PathBuf,
    parent_tree_sha256: String,
    node: NodeDescriptor,
    work: WorkUnit,
    result: ShardResult,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().expect("P06 workspace");
        fs::create_dir(root.path().join("invalid-dir")).unwrap();
        fs::write(root.path().join("invalid.json"), b"{}\n").unwrap();
        let current_path = root.path().join("CURRENT.json");
        let current_bytes = serde_json::to_vec_pretty(&json!({
            "schema_version": "gtkg.current/v1",
            "deliverable_id": "p06-deliverable",
            "version": "0.3.0",
            "version_path": "versions/0.3.0",
            "tree_sha256": digest('1'),
            "manifest_sha256": digest('2'),
        }))
        .unwrap();
        fs::write(&current_path, &current_bytes).unwrap();
        let current_sha256 = sha256(&current_bytes);

        let catalog_root = root.path().join("template-catalog");
        fs::create_dir(&catalog_root).unwrap();
        let parent_root = root.path().join("published-parent");
        fs::create_dir(&parent_root).unwrap();
        fs::write(parent_root.join("artifact.md"), "# P06 parent\n").unwrap();
        let parent_tree_sha256 = tree_sha256(&parent_root).unwrap();

        let node = local_node();
        let work = WorkUnit::new(
            "static_extract",
            digest('3'),
            digest('4'),
            json!({"source_path": "README.md"}),
        )
        .unwrap();
        let result = ShardResult::new(&work, &node.node_id, 1, json!({"text": "stable"})).unwrap();
        Self {
            root,
            current_path,
            current_sha256,
            catalog_root,
            parent_root,
            parent_tree_sha256,
            node,
            work,
            result,
        }
    }

    fn root(&self) -> &Path {
        self.root.path()
    }

    fn payload(&self, operation: V2OperationId) -> Value {
        let invalid_ref = || json!({"path": "invalid.json", "sha256": sha256(b"{}\n")});
        let missing_ref = || json!({"path": "missing.json", "sha256": digest('f')});
        match operation {
            V2OperationId::SystemDescribe | V2OperationId::CapabilityDescribe => json!({}),
            V2OperationId::ConfigValidate => {
                json!({"config_path": self.root().join("missing-config.json")})
            }
            V2OperationId::SourceCapture => json!({
                "capture_mode": "directory_exact",
                "repository_id": "p06-missing",
                "source_root": self.root().join("missing-source"),
                "output_path": self.root().join(".gtkg/source-snapshots/p06.json"),
            }),
            V2OperationId::AnalysisPlan => json!({
                "workspace_root": self.root(),
                "source_root": self.root().join("missing-source"),
                "source_snapshot_ref": missing_ref(),
                "adapter_inputs": [{"adapter_kind": "native", "logical_path": "missing.rs"}],
            }),
            V2OperationId::AnalysisBuild => {
                json!({"workspace_root": self.root(), "plan_ref": missing_ref()})
            }
            V2OperationId::AnalysisVerify => {
                json!({"workspace_root": self.root(), "candidate_ref": missing_ref()})
            }
            V2OperationId::ContextPack => json!({
                "workspace_root": self.root(),
                "analysis_verification_ref": invalid_ref(),
                "max_fact_count": 1,
            }),
            V2OperationId::SummaryJobNext => json!({
                "workspace_root": self.root(),
                "analysis_verification_ref": invalid_ref(),
                "max_fact_count": 1,
                "expected_context_pack_sha256": digest('1'),
            }),
            V2OperationId::SummaryProposalSubmit => json!({
                "workspace_root": self.root(),
                "analysis_verification_ref": invalid_ref(),
                "context_pack_sha256": digest('1'),
                "summary_job_sha256": digest('2'),
                "proposer_id": "p06-proposer",
                "summary_text": "candidate",
                "decisions": [],
            }),
            V2OperationId::SummaryVerificationNext => {
                json!({"workspace_root": self.root(), "proposal_ref": invalid_ref()})
            }
            V2OperationId::SummaryVerificationSubmit => json!({
                "workspace_root": self.root(),
                "proposal_ref": invalid_ref(),
                "verification_job_sha256": digest('3'),
                "verifier_id": "p06-verifier",
                "decisions": [],
            }),
            V2OperationId::SummaryAcceptV2 => json!({
                "workspace_root": self.root(),
                "proposal_ref": invalid_ref(),
                "summary_verification_ref": invalid_ref(),
            }),
            V2OperationId::BuildFinalizeV2 => json!({
                "workspace_root": self.root(),
                "analysis_verification_ref": invalid_ref(),
                "accepted_summary_ref": invalid_ref(),
                "bundle_version": "0.3.0",
            }),
            V2OperationId::RunGet => {
                json!({"workspace_root": self.root(), "run_ref": invalid_ref()})
            }
            V2OperationId::RunCancel => json!({
                "workspace_root": self.root(),
                "run_ref": invalid_ref(),
                "expected_run_sha256": invalid_ref()["sha256"],
            }),
            V2OperationId::BundleVerify => {
                json!({"workspace_root": self.root(), "bundle_ref": invalid_ref()})
            }
            V2OperationId::BundleCompare => json!({
                "workspace_root": self.root(),
                "left_bundle_ref": invalid_ref(),
                "right_bundle_ref": invalid_ref(),
            }),
            V2OperationId::BundleMigrateV1ToV2 => json!({
                "workspace_root": self.root(),
                "legacy_bundle_path": self.root().join("invalid.json"),
                "expected_legacy_tree_sha256": digest('1'),
                "migration_version": "0.3.0",
            }),
            V2OperationId::SnapshotCreate => json!({
                "workspace_root": self.root(),
                "bundle_ref": invalid_ref(),
                "snapshot_version": "0.3.0",
            }),
            V2OperationId::SnapshotVerify => {
                json!({"workspace_root": self.root(), "snapshot_ref": invalid_ref()})
            }
            V2OperationId::SnapshotRestore => json!({
                "workspace_root": self.root(),
                "snapshot_ref": invalid_ref(),
                "expected_snapshot_sha256": invalid_ref()["sha256"],
                "restore_version": "0.3.0",
            }),
            V2OperationId::GitPublish => json!({
                "workspace_root": self.root(),
                "artifact_path": self.parent_root,
                "expected_tree_sha256": self.parent_tree_sha256,
                "repository_root": self.root(),
                "ref_name": "refs/heads/p06",
            }),
            V2OperationId::CurrentGet => json!({
                "current_path": self.current_path,
                "expected_current_sha256": self.current_sha256,
            }),
            V2OperationId::CurrentActivate => json!({
                "workspace_root": self.root(),
                "current_root": self.root().join("current"),
                "version_path": "versions/0.3.0",
                "expected_tree_sha256": digest('1'),
            }),
            V2OperationId::NodeDescribe => json!({
                "descriptor": self.node,
                "probe_sandbox": false,
            }),
            V2OperationId::FederationValidate => json!({
                "nodes": [self.node],
                "work_units": [self.work],
                "shard_results": [self.result],
            }),
            V2OperationId::TemplateList => json!({"catalog_root": self.catalog_root}),
            V2OperationId::TemplateResolve => json!({
                "workspace_root": self.root(),
                "catalog_root": self.catalog_root,
                "template_id": "p06-template",
                "version": "0.3.0",
            }),
            V2OperationId::TemplatePrefetch => {
                json!({"workspace_root": self.root(), "resolution_ref": missing_ref()})
            }
            V2OperationId::TemplateGet => {
                json!({"workspace_root": self.root(), "template_ref": missing_ref()})
            }
            V2OperationId::TemplateValidate => {
                json!({"workspace_root": self.root(), "resolution_ref": missing_ref()})
            }
            V2OperationId::TemplateDerive => json!({
                "workspace_root": self.root(),
                "parent_ref": missing_ref(),
                "new_version": "0.3.1",
                "slot_overrides": {},
            }),
            V2OperationId::TemplatePublish => json!({
                "workspace_root": self.root(),
                "draft_ref": missing_ref(),
                "repository_root": self.root(),
                "version": "0.3.1",
            }),
            V2OperationId::DeliverableDerive => json!({
                "workspace_root": self.root(),
                "parent_path": self.root().join("missing-parent"),
                "expected_parent_tree_sha256": digest('1'),
                "deliverable_id": "p06-deliverable",
                "new_version": "0.3.1",
                "slot_overrides": BTreeMap::<String, String>::new(),
            }),
            V2OperationId::DeliverablePublish => json!({
                "workspace_root": self.root(),
                "draft_ref": missing_ref(),
                "repository_root": self.root(),
                "version": "0.3.1",
            }),
            V2OperationId::GraphNeighbors => json!({
                "graph_artifact_path": "missing-graph", "node_id": "p06-node",
                "direction": "outgoing",
            }),
            V2OperationId::GraphPath => json!({
                "graph_artifact_path": "missing-graph", "source_node_id": "p06-source",
                "target_node_id": "p06-target", "max_depth": 2,
            }),
            V2OperationId::GraphImpact => json!({
                "graph_artifact_path": "missing-graph", "node_id": "p06-node",
                "max_depth": 2,
            }),
            V2OperationId::GraphExplain => json!({
                "graph_artifact_path": "missing-graph", "edge_id": "p06-edge",
            }),
            V2OperationId::GraphTrace => json!({
                "graph_artifact_path": "missing-graph", "node_id": "p06-node",
            }),
            V2OperationId::GraphSearch => json!({
                "graph_artifact_path": "missing-graph",
                "overlay_artifact_path": "missing-overlay",
                "query": "p06",
            }),
            V2OperationId::A2uiResolve => json!({
                "workspace_root": self.root(),
                "catalog_root": self.root().join("missing-a2ui-catalog"),
                "spec_version": "0.9.1",
                "profile_id": "basic",
                "profile_version": "0.9.1",
                "catalog_id": "basic",
                "catalog_version": "0.9.1",
                "renderer_id": "lit",
                "renderer_version": "0.9.1",
                "expected_manifest_sha256": digest('5'),
            }),
            V2OperationId::A2uiGenerate => json!({
                "workspace_root": self.root(),
                "bundle_path": self.root().join("missing-bundle"),
                "expected_bundle_tree_sha256": digest('1'),
                "resolution_ref": missing_ref(),
                "projection_version": "0.3.0",
            }),
            V2OperationId::A2uiGet => json!({
                "workspace_root": self.root(),
                "generation_ref": missing_ref(),
                "expected_projection_tree_sha256": digest('6'),
            }),
            V2OperationId::A2uiValidate => json!({
                "workspace_root": self.root(),
                "generation_ref": missing_ref(),
                "expected_projection_tree_sha256": digest('6'),
                "required_evidence_state": "a2ui_generatable",
            }),
        }
    }
}

fn local_node() -> NodeDescriptor {
    NodeDescriptor {
        schema_version: "gtkg.node/v1".to_owned(),
        node_id: "p06-worker".to_owned(),
        logical_address: "local://p06-worker".to_owned(),
        transport: NodeTransport::Exec,
        endpoint: std::env::current_exe()
            .expect("current test executable")
            .to_string_lossy()
            .into_owned(),
        binary_sha256: digest('a'),
        source_sha256: digest('b'),
        protocol_version: gtkg_protocol::PROTOCOL_VERSION.to_owned(),
        parser_sha256: digest('c'),
        sandbox_policy_sha256: digest('d'),
        platform: std::env::consts::OS.to_owned(),
        capabilities: vec!["static_extract".to_owned()],
        max_parallel: 1,
        work_unit_kinds: vec!["static_extract".to_owned()],
    }
}

fn cli_discovery(binary: &Path, root: &Path, profile: &str, profile_digest: Option<&str>) -> Value {
    let mut command = Command::new(binary);
    command
        .args(["v2-discover", "--profile", profile, "--output", "json"])
        .current_dir(root)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(digest) = profile_digest {
        command.args(["--profile-digest", digest]);
    }
    let output = command.output().expect("run v2 discovery");
    assert!(
        output.status.success(),
        "v2 discovery failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("v2 discovery JSON")
}

fn cli_call(binary: &Path, root: &Path, request: &OperationRequestV2) -> Value {
    cli_call_value(
        binary,
        root,
        request.operation_id.as_str(),
        &serde_json::to_value(request).expect("v2 request JSON"),
    )
}

fn cli_call_value(binary: &Path, root: &Path, operation_id: &str, request: &Value) -> Value {
    let mut child = Command::new(binary)
        .args(["v2-op", operation_id, "--request", "-", "--output", "json"])
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
        "GTKG v2-op failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("CLI response JSON")
}

fn strip_runtime_profile(value: &mut Value) {
    if let Some(result) = value.get_mut("result").and_then(Value::as_object_mut) {
        result.remove("runtime");
    }
}

struct LineChild {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl LineChild {
    fn spawn_v1(binary: &Path, root: &Path) -> Self {
        Self::spawn(binary, root, &["mcp", "serve", "--stdio"])
    }

    fn spawn_v2(binary: &Path, root: &Path, profile: &str, profile_digest: Option<&str>) -> Self {
        let mut args = vec![
            "mcp",
            "serve",
            "--protocol",
            "v2",
            "--profile",
            profile,
            "--stdio",
        ];
        if let Some(digest) = profile_digest {
            args.push("--profile-digest");
            args.push(digest);
        }
        Self::spawn(binary, root, &args)
    }

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
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/gtkg");
    assert!(path.is_file(), "build {} before P06", path.display());
    path
}

fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn digest(character: char) -> String {
    format!("sha256:{}", character.to_string().repeat(64))
}
