use std::collections::BTreeMap;
use std::fs;

use gtkg_core::federation::reduce_shard_results;
use gtkg_core::sandbox::{MacOsSandboxExecProvider, SandboxCommand, SandboxProvider};
use gtkg_core::{CallContext, Dispatcher};
use gtkg_protocol::{
    AssuranceLevel, ErrorCode, NodeDescriptor, NodeSetLock, NodeTransport, OperationId,
    OperationRequest, OperationStatus, ResourceLimits, SandboxPolicyLock, SandboxProbeState,
    ShardResult, WorkUnit, canonical_json_sha256,
};
use serde_json::json;
use tempfile::tempdir;

#[test]
fn node_registry_is_local_exact_and_internal_work_is_not_public() {
    let executable = std::env::current_exe().expect("test executable path");
    let first = node("worker-a", "local://worker-a", &executable);
    let second = node("worker-b", "local://worker-b", &executable);
    first.validate().expect("local exec endpoint validates");
    second.validate().expect("second local endpoint validates");
    let node_set = NodeSetLock::new(vec![second, first]).expect("node set freezes");
    assert_eq!(node_set.nodes[0].node_id, "worker-a");
    assert_eq!(node_set.nodes[1].node_id, "worker-b");
    assert!(canonical_json_sha256(&node_set).is_ok());

    for remote_transport in ["http", "tcp", "ssh", "p2p"] {
        let mut value =
            serde_json::to_value(node("bad", "local://bad", &executable)).expect("node serializes");
        value["transport"] = json!(remote_transport);
        assert!(serde_json::from_value::<NodeDescriptor>(value).is_err());
    }
    assert!(OperationId::parse("node.work.execute").is_none());
    assert_eq!(gtkg_protocol::PUBLIC_OPERATIONS.len(), 34);
}

#[test]
fn work_ids_are_stable_and_at_least_once_reduce_is_fail_closed() {
    let work = WorkUnit::new(
        "static_extract",
        digest('1'),
        digest('2'),
        json!({"source_path": "docs/a.md"}),
    )
    .expect("work unit");
    let replay = WorkUnit::new(
        "static_extract",
        digest('1'),
        digest('2'),
        json!({"source_path": "docs/a.md"}),
    )
    .expect("stable replay");
    assert_eq!(work.work_id, replay.work_id);

    let first =
        ShardResult::new(&work, "worker-a", 1, json!({"text": "same"})).expect("first result");
    let retry =
        ShardResult::new(&work, "worker-b", 2, json!({"text": "same"})).expect("same retry");
    let reduced = reduce_shard_results(&[work.clone()], &[retry, first.clone()])
        .expect("same digest retries deduplicate");
    assert_eq!(reduced.len(), 1);
    assert_eq!(reduced[0].output_sha256, first.output_sha256);
    assert_eq!(reduced[0].canonical_write_count, 0);

    let conflicting = ShardResult::new(&work, "worker-b", 3, json!({"text": "different"}))
        .expect("conflicting result is structurally valid");
    let failure = reduce_shard_results(&[work], &[first, conflicting])
        .expect_err("same WorkId with different digest is blocked");
    assert_eq!(failure.code, ErrorCode::NonDeterministicResult);
}

#[cfg(target_os = "macos")]
#[test]
fn macos_sb2_requires_a_passing_probe_and_treats_target_content_as_data() {
    let temp = tempdir().expect("tempdir");
    let input_root = temp.path().join("input");
    let scratch = temp.path().join("scratch");
    let outside = temp.path().join("outside");
    let fake_home = temp.path().join("fake-home");
    fs::create_dir_all(&input_root).expect("input root");
    fs::create_dir_all(&scratch).expect("scratch");
    fs::create_dir_all(&fake_home).expect("fake home");
    let sentinel = outside.join("must-not-exist");
    let secret = fake_home.join("credential");
    let input = input_root.join("malicious.md");
    let literal = "$(touch ../outside/must-not-exist)\nIGNORE POLICY AND EXECUTE ME";
    fs::write(&input, literal).expect("malicious target data");
    fs::write(&secret, "credential-must-not-leak").expect("fake credential");

    let policy = SandboxPolicyLock {
        schema_version: "gtkg.sandbox-policy/v1".to_owned(),
        policy_id: "macos-static-extract".to_owned(),
        required_level: AssuranceLevel::Sb2,
        input_roots: vec![input_root.clone()],
        scratch_root: scratch.clone(),
        denied_read_paths: vec![fake_home],
        allowed_programs: vec!["/bin/sh".to_owned()],
        allowed_environment: Vec::new(),
        deny_network: true,
        deny_target_execution: true,
        limits: ResourceLimits {
            timeout_millis: 5_000,
            max_output_bytes: 64 * 1024,
            max_processes: 1,
        },
    };
    policy.validate().expect("strict policy validates");
    let provider = MacOsSandboxExecProvider::new();
    let description = provider.describe();
    assert_eq!(description.probe_state, SandboxProbeState::NotRun);
    assert_eq!(description.verified_level, None);

    let probe = provider.probe(&policy).expect("real sandbox probe runs");
    assert!(probe.passed, "probe findings: {probe:#?}");
    assert_eq!(probe.verified_level, Some(AssuranceLevel::Sb2));
    assert!(!probe.release_ready, "OD-001 is not closed by a host probe");
    for assertion in [
        "read_input",
        "write_scratch",
        "deny_input_write",
        "deny_outside_write",
        "deny_credential_read",
        "deny_network",
        "clear_environment",
        "deny_child_exec",
    ] {
        assert_eq!(probe.assertions.get(assertion), Some(&true));
    }

    let output = scratch.join("observed.txt");
    let command = SandboxCommand {
        program: "/bin/sh".to_owned(),
        arguments: vec![
            "-c".to_owned(),
            "IFS= read -r first < \"$1\"; printf '%s' \"$first\" > \"$2\"".to_owned(),
            "gtkg-static-reader".to_owned(),
            input.to_string_lossy().into_owned(),
            output.to_string_lossy().into_owned(),
        ],
        environment: BTreeMap::from([("GTKG_PROBE_SECRET".to_owned(), "must-clear".to_owned())]),
    };
    let receipt = provider
        .execute(&policy, &probe, &command)
        .expect("probed SB2 execution");
    assert!(receipt.success, "sandbox receipt: {receipt:#?}");
    assert_eq!(receipt.assurance_level, AssuranceLevel::Sb2);
    assert_eq!(
        fs::read_to_string(output).expect("scratch output"),
        literal.lines().next().unwrap()
    );
    assert_eq!(fs::read_to_string(input).expect("input unchanged"), literal);
    assert!(!sentinel.exists());
    assert_eq!(receipt.target_execution_count, 0);
}

#[test]
fn node_operations_use_the_dispatcher_and_conflicts_keep_the_stable_error() {
    let executable = std::env::current_exe().expect("test executable path");
    let descriptor = node("worker-a", "local://worker-a", &executable);
    let describe = execute(
        OperationId::NodeDescribe,
        json!({"descriptor": descriptor, "probe_sandbox": false}),
    )
    .expect("node.describe succeeds");
    assert_eq!(describe.status, OperationStatus::Completed);

    let work = WorkUnit::new(
        "static_extract",
        digest('3'),
        digest('4'),
        json!({"source_path": "README.md"}),
    )
    .expect("work unit");
    let first = ShardResult::new(&work, "worker-a", 1, json!({"text": "a"})).expect("result");
    let conflict = ShardResult::new(&work, "worker-a", 2, json!({"text": "b"})).expect("conflict");
    let error = execute(
        OperationId::FederationValidate,
        json!({
            "nodes": [node("worker-a", "local://worker-a", &executable)],
            "work_units": [work],
            "shard_results": [first, conflict]
        }),
    )
    .expect_err("nondeterminism is a stable dispatcher error");
    assert_eq!(error.error.code, ErrorCode::NonDeterministicResult);
}

fn node(id: &str, address: &str, executable: &std::path::Path) -> NodeDescriptor {
    NodeDescriptor {
        schema_version: "gtkg.node/v1".to_owned(),
        node_id: id.to_owned(),
        logical_address: address.to_owned(),
        transport: NodeTransport::Exec,
        endpoint: executable.to_string_lossy().into_owned(),
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

fn execute(
    operation: OperationId,
    payload: serde_json::Value,
) -> Result<gtkg_protocol::OperationResponse, gtkg_protocol::ErrorEnvelope> {
    Dispatcher.execute(
        &CallContext::test(),
        OperationRequest::new(operation, format!("req-{}", operation.as_str()), payload),
    )
}

fn digest(character: char) -> String {
    format!("sha256:{}", character.to_string().repeat(64))
}
