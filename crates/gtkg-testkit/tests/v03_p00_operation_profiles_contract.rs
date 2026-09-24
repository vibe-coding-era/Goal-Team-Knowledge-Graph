//! P00 immutable contract: v2 operation bindings and profile-scoped discovery.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Output, Stdio};

use gtkg_protocol::v2::{CallabilityV2, OperationAvailabilityV2};
use gtkg_protocol::v03::profiles::{
    DEFAULT_DISCOVERY_PROFILE_V1, discoverable_operation_profile_v03,
    operation_profile_projection_v03,
};
use gtkg_protocol::v03::{
    DISCOVERY_PROFILE_DIGESTS_V1, DiscoveryProfileIdV1, operation_bindings_v03,
};
use serde_json::{Value, json};

const CORE: &[&str] = &[
    "system.describe",
    "config.validate",
    "capability.describe",
    "source.capture",
    "analysis.plan",
    "analysis.build",
    "analysis.verify",
    "build.finalize.v2",
    "context.pack",
    "graph.search",
];
const GRAPH: &[&str] = &[
    "graph.neighbors",
    "graph.path",
    "graph.impact",
    "graph.explain",
    "graph.trace",
    "graph.search",
];
const AUTHORING: &[&str] = &[
    "context.pack",
    "summary.job.next",
    "summary.proposal.submit",
    "summary.verification.next",
    "summary.verification.submit",
    "summary.accept.v2",
    "analysis.verify",
    "build.finalize.v2",
];
const LIFECYCLE: &[&str] = &[
    "run.get",
    "run.cancel",
    "bundle.verify",
    "bundle.compare",
    "bundle.migrate.v1_to_v2",
    "snapshot.create",
    "snapshot.verify",
    "snapshot.restore",
    "git.publish",
    "current.get",
    "current.activate",
    "node.describe",
    "federation.validate",
];
const TEMPLATES: &[&str] = &[
    "template.list",
    "template.resolve",
    "template.prefetch",
    "template.get",
    "template.validate",
    "template.derive",
    "template.publish",
    "deliverable.derive",
    "deliverable.publish",
];
const A2UI: &[&str] = &["a2ui.resolve", "a2ui.generate", "a2ui.get", "a2ui.validate"];

fn ids(value: &[gtkg_protocol::v2::V2OperationId]) -> Vec<&'static str> {
    value.iter().map(|operation| operation.as_str()).collect()
}

#[test]
fn p00_projects_all_46_bindings_without_promoting_unimplemented_handlers() {
    let bindings = operation_bindings_v03();
    assert_eq!(bindings.len(), 46);
    assert_eq!(
        bindings
            .iter()
            .map(|binding| binding.operation_id)
            .collect::<BTreeSet<_>>()
            .len(),
        46,
    );
    assert!(bindings.iter().all(|binding| {
        binding.handler_id.starts_with("gtkg.v03.")
            && binding.schema_sha256.starts_with("sha256:")
            && binding.schema_sha256.len() == 71
    }));

    let implemented = bindings
        .iter()
        .filter(|binding| binding.availability == OperationAvailabilityV2::Implemented)
        .map(|binding| binding.operation_id.as_str())
        .collect::<Vec<_>>();
    let callable = bindings
        .iter()
        .filter(|binding| binding.callability == CallabilityV2::Callable)
        .map(|binding| binding.operation_id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        implemented, GRAPH,
        "P00 must not implement later P handlers"
    );
    assert_eq!(callable, GRAPH, "P00 must not promote later P handlers");
}

#[test]
fn p00_profile_projection_is_exact_ordered_defaulted_and_digest_bound() {
    assert_eq!(DEFAULT_DISCOVERY_PROFILE_V1, "core");
    let all = ids(&operation_profile_projection_v03(Some("all"), None)
        .expect("all profile projection")
        .profile
        .operation_ids);
    assert_eq!(all.len(), 46);

    let expected = BTreeMap::from([
        ("core", CORE),
        ("graph", GRAPH),
        ("authoring", AUTHORING),
        ("lifecycle", LIFECYCLE),
        ("templates", TEMPLATES),
        ("a2ui", A2UI),
        ("all", all.as_slice()),
    ]);
    let expected_digests = DISCOVERY_PROFILE_DIGESTS_V1
        .iter()
        .map(|(profile, digest)| (profile.as_str(), *digest))
        .collect::<BTreeMap<_, _>>();

    for (profile_id, expected_ids) in expected {
        let projection = operation_profile_projection_v03(Some(profile_id), None)
            .unwrap_or_else(|error| panic!("{profile_id} projection failed: {error:?}"));
        assert_eq!(projection.profile.profile_id.as_str(), profile_id);
        assert_eq!(ids(&projection.profile.operation_ids), expected_ids);
        assert_eq!(projection.bindings.len(), expected_ids.len());
        assert_eq!(
            projection
                .bindings
                .iter()
                .map(|binding| binding.operation_id.as_str())
                .collect::<Vec<_>>(),
            expected_ids,
        );
        assert_eq!(projection.profile.digest, expected_digests[profile_id]);
        assert_eq!(projection.profile.is_default, profile_id == "core");
    }

    let default = operation_profile_projection_v03(None, None).expect("default profile");
    assert_eq!(default.profile.profile_id, DiscoveryProfileIdV1::Core);
    assert_eq!(ids(&default.profile.operation_ids), CORE);
}

#[test]
fn p00_discovery_fails_closed_for_unknown_stale_and_dead_profiles() {
    let unknown = operation_profile_projection_v03(Some("CORE"), None)
        .expect_err("profile IDs are exact and case-sensitive");
    assert_eq!(unknown.code(), "E_PROFILE_UNKNOWN");

    let stale = operation_profile_projection_v03(
        Some("graph"),
        Some("sha256:0000000000000000000000000000000000000000000000000000000000000000"),
    )
    .expect_err("stale profile digest must not auto-upgrade");
    assert_eq!(stale.code(), "E_PROFILE_STALE");

    let graph = discoverable_operation_profile_v03(Some("graph"), None)
        .expect("all six graph handlers exist");
    assert_eq!(graph.bindings.len(), 6);
    assert!(graph.bindings.iter().all(|binding| {
        binding.availability == OperationAvailabilityV2::Implemented
            && binding.callability == CallabilityV2::Callable
    }));

    for profile_id in ["core", "authoring", "lifecycle", "templates", "a2ui", "all"] {
        let error = discoverable_operation_profile_v03(Some(profile_id), None)
            .expect_err("profile with unimplemented operations must not expose dead tools");
        assert_eq!(error.code(), "E_DEAD_TOOL_EXPOSED");
        assert!(error.selected_operation_count() >= error.unavailable_operation_ids().len());
        assert!(!error.unavailable_operation_ids().is_empty());
    }
}

#[test]
fn p00_cli_and_mcp_profile_selectors_have_exact_discovery_parity() {
    let binary = gtkg_binary();
    let root = workspace_root();

    let cli = run(&binary, &root, &["v2-discover", "--profile", "graph"]);
    assert!(
        cli.status.success(),
        "profile discovery CLI failed: {}",
        String::from_utf8_lossy(&cli.stderr)
    );
    let cli_value: Value = serde_json::from_slice(&cli.stdout).expect("CLI discovery JSON");
    assert_eq!(cli_value["schema_version"], "gtkg.discovery-response/v1");
    assert_eq!(cli_value["profile_id"], "graph");
    assert_eq!(cli_value["tools"].as_array().expect("CLI tools").len(), 6);

    let mut mcp = LineChild::spawn(
        &binary,
        &root,
        &[
            "mcp",
            "serve",
            "--protocol",
            "v2",
            "--profile",
            "graph",
            "--stdio",
        ],
    );
    let listed = mcp.send(json!({
        "jsonrpc": "2.0", "id": "p00-list", "method": "tools/list", "params": {}
    }));
    assert_eq!(listed["result"], cli_value);
    let listed_ids = listed["result"]["tools"]
        .as_array()
        .expect("MCP tools")
        .iter()
        .map(|tool| tool["x-gtkg-operation-id"].as_str().expect("operation ID"))
        .collect::<Vec<_>>();
    assert_eq!(listed_ids, GRAPH);
    assert!(
        listed_ids
            .iter()
            .all(|operation| operation.starts_with("graph."))
    );

    let default = run(&binary, &root, &["v2-discover"]);
    assert!(
        !default.status.success(),
        "default core must not expose dead tools"
    );
    assert!(String::from_utf8_lossy(&default.stderr).contains("E_DEAD_TOOL_EXPOSED"));

    let mut default_mcp = LineChild::spawn(
        &binary,
        &root,
        &["mcp", "serve", "--protocol", "v2", "--stdio"],
    );
    let blocked = default_mcp.send(json!({
        "jsonrpc": "2.0", "id": "p00-core", "method": "tools/list", "params": {}
    }));
    assert_eq!(blocked["error"]["data"]["code"], "E_DEAD_TOOL_EXPOSED");
    assert_eq!(blocked["error"]["data"]["profile_id"], "core");
    assert_eq!(blocked["error"]["data"]["selected_operation_count"], 10);
    assert_eq!(
        blocked["error"]["data"]["unavailable_operation_ids"]
            .as_array()
            .expect("unavailable IDs")
            .len(),
        9,
    );

    let unknown = run(&binary, &root, &["v2-discover", "--profile", "unknown"]);
    assert!(!unknown.status.success());
    assert!(String::from_utf8_lossy(&unknown.stderr).contains("E_PROFILE_UNKNOWN"));

    let stale = run(
        &binary,
        &root,
        &[
            "v2-discover",
            "--profile",
            "graph",
            "--profile-digest",
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        ],
    );
    assert!(!stale.status.success());
    assert!(String::from_utf8_lossy(&stale.stderr).contains("E_PROFILE_STALE"));
}

fn run(binary: &Path, root: &Path, args: &[&str]) -> Output {
    Command::new(binary)
        .args(args)
        .current_dir(root)
        .output()
        .unwrap_or_else(|error| panic!("spawn {}: {error}", args.join(" ")))
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
            .unwrap_or_else(|error| panic!("spawn {}: {error}", args.join(" ")));
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
