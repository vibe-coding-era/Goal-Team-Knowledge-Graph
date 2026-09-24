//! T14A: a real local CLI/MCP process consumes a graph built from exact source
//! and records a separately verifiable, durable local lifecycle boundary.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use gtkg_core::graph_v3::{
    StructuralGraphBuildInputV3, TypedIrGraphInputV3, build_structural_graph_v3,
    write_structural_graph_v3,
};
use gtkg_core::lifecycle_v2::{
    ArtifactSelectorV2, BundleDispositionV2, BundleFormatV2, LifecycleIdentityV2,
    LocalLifecycleStoreV2, LocalVersionV2, PostActivationReadbackReceiptV2,
};
use gtkg_core::runtime_receipt_v2::{
    LOCAL_RUNTIME_EVENT_SCHEMA_V2, LOCAL_RUNTIME_RECEIPT_SCHEMA_V2, LocalRuntimeAuthorityV2,
    LocalRuntimeLifecycleReceiptV2, RuntimeVerifierIdentityV2,
    persist_local_runtime_lifecycle_receipt_v2,
};
use gtkg_core::{CallContext, EffectPolicy, TransportKind};
use gtkg_extract::{build_typed_ir_v2, extract_path, resolve_local_typed_ir_v2};
use gtkg_protocol::v2::{
    OperationRequestV2, SourceBaselineIdentityV2, SourceCaptureModeV2, SourceEligibilityV2,
    SourceSnapshotDenominatorV2, SourceSnapshotEntryV2, SourceSnapshotV2,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const FIXTURE_STATUS: &str =
    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

#[test]
fn local_source_to_typed_graph_query_has_cli_mcp_success_parity_and_runtime_identity() {
    let temporary = tempfile::tempdir().expect("temporary workspace");
    let (graph, source) = build_graph_from_exact_source(temporary.path());
    let caller = graph
        .edges
        .iter()
        .find(|edge| edge.kind == "calls")
        .expect("call relation")
        .source_node_id
        .clone();
    let request = OperationRequestV2::new(
        "graph.neighbors",
        "t14a-cli-mcp-success",
        json!({
            "graph_artifact_path": "graph",
            "node_id": caller,
            "direction": "outgoing",
        }),
    );
    let binary = gtkg_binary();
    let cli = cli_call(&binary, temporary.path(), &request);
    assert_eq!(cli["operation_id"], "graph.neighbors");
    assert_eq!(cli["result"]["mode"], "structural_only");
    assert_eq!(
        cli["result"]["evidence_pack"]["graph_readback"]["graph_sha256"],
        graph.graph_sha256
    );
    assert_eq!(
        cli["result"]["runtime"]["authority"]["scope"],
        "local_development_only"
    );
    assert_eq!(
        cli["result"]["runtime"]["authority"]["external_current_activation"],
        false
    );
    assert_eq!(
        cli["result"]["runtime"]["authority"]["release_execution"],
        false
    );
    assert!(
        cli["result"]["runtime"]["binary_sha256"]
            .as_str()
            .is_some_and(|value| value.starts_with("sha256:"))
    );

    let mut mcp = LineChild::spawn(
        &binary,
        &["mcp", "serve", "--protocol", "v2", "--stdio"],
        temporary.path(),
    );
    let initialized = mcp.send(json!({
        "jsonrpc": "2.0", "id": "t14a-initialize", "method": "initialize", "params": {}
    }));
    assert_eq!(
        initialized["result"]["x-gtkg-identity"], cli["result"]["runtime"],
        "MCP discovery identity and callable result identity must bind the same binary/schema"
    );
    let response = mcp.send(json!({
        "jsonrpc": "2.0",
        "id": "t14a-mcp-success",
        "method": "tools/call",
        "params": {"name": "gtkg_v2_graph_neighbors", "arguments": request}
    }));
    assert_eq!(response["result"]["isError"], false);
    assert_eq!(response["result"]["structuredContent"], cli);
    assert_eq!(
        response["result"]["content"][0]["text"],
        serde_json::to_string(&cli).expect("mirrored MCP content")
    );

    let source_path = temporary.path().join("src/lib.rs");
    assert_eq!(
        std::fs::read_to_string(source_path).expect("source readback"),
        source
    );
}

#[test]
fn local_lifecycle_receipt_binds_authority_verifier_and_immutable_event_without_release() {
    let temporary = tempfile::tempdir().expect("temporary workspace");
    let context = CallContext::restricted(
        TransportKind::Test,
        vec![temporary.path().to_path_buf()],
        EffectPolicy::WorkspaceWrite,
    )
    .expect("bounded workspace");
    let candidate_identity = identity('1');
    let previous = LocalVersionV2 {
        version_id: "v2-previous".to_owned(),
        format: BundleFormatV2::V2,
        immutable_bundle_sha256: digest('1'),
        identity: identity('1'),
        disposition: BundleDispositionV2::CurrentEligible,
    };
    let version = LocalVersionV2 {
        version_id: "v2-local".to_owned(),
        format: BundleFormatV2::V2,
        immutable_bundle_sha256: digest('2'),
        identity: candidate_identity,
        disposition: BundleDispositionV2::CurrentEligible,
    };
    let mut store =
        LocalLifecycleStoreV2::new(vec![previous, version], Some("v2-previous")).expect("store");
    let previous_current = store.current_digest().expect("digest").expect("current");
    let current = store
        .activate_local_cas(&previous_current, "v2-local")
        .expect("local-only CAS activation");
    let selection = store
        .select(ArtifactSelectorV2::Current {
            expected_current_sha256: current.clone(),
        })
        .expect("read-only selection");
    let readback = PostActivationReadbackReceiptV2::passed(
        current,
        selection.lifecycle_identity_sha256.clone(),
    )
    .expect("passed local readback");
    let receipt = LocalRuntimeLifecycleReceiptV2 {
        schema_version: LOCAL_RUNTIME_RECEIPT_SCHEMA_V2.to_owned(),
        receipt_id: "t14a-local-lifecycle".to_owned(),
        authority: LocalRuntimeAuthorityV2::local_development("gtkg-local-runtime"),
        verifier: RuntimeVerifierIdentityV2 {
            verifier_id: "t13-lifecycle-verifier-v1".to_owned(),
            verifier_sha256: digest('3'),
        },
        selection,
        readback,
    };
    let writes_before_persist = store.canonical_write_count();
    let paths = persist_local_runtime_lifecycle_receipt_v2(
        &context,
        &temporary.path().join(".gtkg/t14a"),
        &receipt,
    )
    .expect("durable local receipt and event");
    let receipt_json: Value =
        serde_json::from_slice(&std::fs::read(&paths.receipt_path).expect("receipt bytes"))
            .expect("receipt JSON");
    let event_json: Value =
        serde_json::from_slice(&std::fs::read(&paths.event_path).expect("event bytes"))
            .expect("event JSON");
    assert_eq!(
        receipt_json["schema_version"],
        LOCAL_RUNTIME_RECEIPT_SCHEMA_V2
    );
    assert_eq!(receipt_json["authority"]["scope"], "local_development_only");
    assert_eq!(
        receipt_json["authority"]["external_current_activation"],
        false
    );
    assert_eq!(receipt_json["authority"]["release_execution"], false);
    assert_eq!(receipt_json["authority"]["real_provider_execution"], false);
    assert_eq!(event_json["schema_version"], LOCAL_RUNTIME_EVENT_SCHEMA_V2);
    assert_eq!(
        event_json["receipt_sha256"],
        receipt.receipt_sha256().expect("receipt digest")
    );
    assert_eq!(event_json["event_sha256"], paths.event_sha256);
    assert_eq!(
        store.canonical_write_count(),
        writes_before_persist,
        "writing the runtime receipt did not activate Current"
    );

    let mut forbidden = receipt.clone();
    forbidden.authority.release_execution = true;
    assert!(
        persist_local_runtime_lifecycle_receipt_v2(
            &context,
            &temporary.path().join(".gtkg/t14a-forbidden"),
            &forbidden,
        )
        .is_err()
    );
    assert!(
        persist_local_runtime_lifecycle_receipt_v2(
            &context,
            &temporary.path().join("release/current"),
            &receipt,
        )
        .is_err(),
        "local evidence cannot target release/current"
    );
}

fn build_graph_from_exact_source(root: &Path) -> (gtkg_core::graph_v3::StructuralGraphV3, String) {
    let source = "fn leaf() {}\nfn caller() { leaf(); }\n".to_owned();
    let source_path = root.join("src/lib.rs");
    std::fs::create_dir_all(source_path.parent().expect("source parent")).expect("source parent");
    std::fs::write(&source_path, &source).expect("source fixture");
    let snapshot = SourceSnapshotV2 {
        schema_version: "gtkg.source-snapshot/v2".to_owned(),
        capture_mode: SourceCaptureModeV2::DirectoryExact,
        repository_id: "t14a-local".to_owned(),
        baseline: SourceBaselineIdentityV2 {
            kind: "directory".to_owned(),
            head: None,
            tree: None,
            status_sha256: FIXTURE_STATUS.to_owned(),
        },
        inventory: vec![SourceSnapshotEntryV2 {
            logical_path: "src/lib.rs".to_owned(),
            content_sha256: sha(source.as_bytes()),
            bytes: source.len() as u64,
        }],
        omissions: Vec::new(),
        denominator: SourceSnapshotDenominatorV2 {
            discovered_entries: 1,
            admitted_entries: 1,
            omitted_entries: 0,
        },
        exact_set_sha256: String::new(),
        eligibility: SourceEligibilityV2 {
            development_eligible: true,
            source_release_candidate: false,
            environment_ready: false,
            release_ready: false,
        },
    }
    .with_exact_set_digest()
    .expect("source snapshot");
    let extracted = extract_path(&source_path).expect("static source extraction");
    let typed = build_typed_ir_v2(&snapshot, "src/lib.rs", &extracted).expect("typed IR");
    let resolved = resolve_local_typed_ir_v2(&typed, source.as_bytes()).expect("local resolver");
    let graph = build_structural_graph_v3(&StructuralGraphBuildInputV3 {
        source_snapshot_exact_set_sha256: snapshot.exact_set_sha256,
        typed_inputs: vec![TypedIrGraphInputV3 {
            ir: resolved,
            source_bytes: source.as_bytes().to_vec(),
        }],
        document_relations: Vec::new(),
    })
    .expect("structural graph");
    write_structural_graph_v3(&root.join("graph"), &graph).expect("verified graph shards");
    (graph, source)
}

fn digest(byte: char) -> String {
    format!("sha256:{}", byte.to_string().repeat(64))
}

fn identity(seed: char) -> LifecycleIdentityV2 {
    LifecycleIdentityV2 {
        source_snapshot_exact_set_sha256: digest(seed),
        local_resolver_profile_sha256: digest('b'),
        document_relation_receipts_sha256: digest('c'),
        context_pack_sha256: digest('d'),
        claim_verification_receipt_sha256: digest('e'),
        structural_graph_sha256: digest('f'),
        knowledge_overlay_sha256: digest('0'),
    }
}

fn sha(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn cli_call(binary: &Path, root: &Path, request: &OperationRequestV2) -> Value {
    let mut child = Command::new(binary)
        .args([
            "v2-op",
            &request.operation_id,
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
        .expect("spawn CLI");
    serde_json::to_writer(child.stdin.as_mut().expect("CLI stdin"), request)
        .expect("write CLI request");
    drop(child.stdin.take());
    let output = child.wait_with_output().expect("wait CLI");
    assert!(
        output.status.success(),
        "CLI error: {}",
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
    fn spawn(binary: &Path, args: &[&str], root: &Path) -> Self {
        let mut child = Command::new(binary)
            .args(args)
            .current_dir(root)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn MCP");
        Self {
            stdin: child.stdin.take().expect("MCP stdin"),
            stdout: BufReader::new(child.stdout.take().expect("MCP stdout")),
            child,
        }
    }

    fn send(&mut self, value: Value) -> Value {
        serde_json::to_writer(&mut self.stdin, &value).expect("write MCP frame");
        self.stdin.write_all(b"\n").expect("MCP newline");
        self.stdin.flush().expect("flush MCP frame");
        let mut line = String::new();
        assert_ne!(self.stdout.read_line(&mut line).expect("read MCP frame"), 0);
        serde_json::from_str(&line).expect("MCP JSON")
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
        assert!(path.is_file(), "GTKG_BIN missing: {}", path.display());
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
