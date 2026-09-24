//! U06 immutable Red: a fresh isolated local installation must install the
//! current built GTKG binary, execute a real Q04 CLI query, create a
//! receipt-bound U03 Explorer, and uninstall the exact managed set.  This is
//! local Development only: no system install, Current activation, Release,
//! target-project execution, database, or mock browser data.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use gtkg_core::v03::explorer::{
    StaticGraphExplorerArtifactInputV2, StaticGraphExplorerReceiptV2,
    build_static_graph_explorer_from_artifacts_v2,
    create_static_graph_explorer_output_root_v2, write_static_graph_explorer_with_capability_v2,
};
use gtkg_core::v03::graph_query::{
    GraphQueryEntityV1, write_graph_query_evidence_index_v1,
};
use gtkg_core::v03::installer::{
    INSTALL_MANIFEST_SCHEMA_V1, InstallActionV1, InstallManifestV1, InstallReceiptV1,
    apply_install_with_capability_v1, create_isolated_root_v1,
    preview_install_with_capability_v1, uninstall_with_capability_v1,
};
use gtkg_core::v03::query::{
    AdjacencyEdgeInputV1, LexicalDocumentV1, build_adjacency_routing_index_v1,
    build_lexical_shard_v1, write_file_query_index_v1,
};
use gtkg_core::{CallContext, EffectPolicy, TransportKind};
use gtkg_protocol::FileReceiptRef;
use gtkg_protocol::v2::OperationRequestV2;
use gtkg_protocol::v03::query::{
    FileQueryExpectedIdentitiesV1, FileQueryIndexManifestV1, QueryResolutionStateV1,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const TEST_SOURCE: &[u8] = include_bytes!("v03_u06_local_e2e.rs");

fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn digest(label: &str) -> String {
    sha256(label.as_bytes())
}

fn required_env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("U06 requires {name}"))
}

fn current_binary() -> (PathBuf, String) {
    let binary = PathBuf::from(required_env("U06_SOURCE_BINARY"));
    let expected = required_env("U06_SOURCE_BINARY_SHA256");
    assert!(binary.is_file(), "U06 source binary must exist");
    assert_eq!(sha256(&fs::read(&binary).unwrap()), expected);
    assert_eq!(sha256(TEST_SOURCE), required_env("U06_TEST_SOURCE_SHA256"));
    (binary, expected)
}

fn context(roots: Vec<PathBuf>) -> CallContext {
    CallContext::restricted(TransportKind::Test, roots, EffectPolicy::WorkspaceWrite).unwrap()
}

fn manifest(binary_sha256: &str) -> InstallManifestV1 {
    InstallManifestV1 {
        schema_version: INSTALL_MANIFEST_SCHEMA_V1.to_owned(),
        version: "0.3.0-u06-local".to_owned(),
        platform: format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
        files: vec!["bin/gtkg".to_owned()],
        modes: BTreeMap::from([("bin/gtkg".to_owned(), 0o755)]),
        digests: BTreeMap::from([("bin/gtkg".to_owned(), binary_sha256.to_owned())]),
        destinations: BTreeMap::from([("bin/gtkg".to_owned(), "bin/gtkg".to_owned())]),
    }
}

fn evidence(id: &str, index: usize) -> Value {
    json!({
        "kind": "source_span",
        "evidence_id": id,
        "source_snapshot_exact_set_sha256": digest("u06-source"),
        "source_logical_path": format!("src/u06_{index}.rs"),
        "source_sha256": digest(&format!("u06-source-{index}")),
        "byte_start": index * 10,
        "byte_end": index * 10 + 8,
        "snippet_sha256": digest(&format!("u06-snippet-{index}")),
    })
}

#[derive(Debug)]
struct Journey {
    source_binary_sha256: String,
    installed_binary_sha256: String,
    install: InstallReceiptV1,
    query_response: Value,
    query_response_sha256: String,
    explorer: StaticGraphExplorerReceiptV2,
    uninstall: InstallReceiptV1,
    target_project_execution_count: u64,
}

fn run_journey(explorer_parent: &Path) -> Journey {
    let (source_binary, source_binary_sha256) = current_binary();
    let workspace = tempfile::tempdir().unwrap();
    let package_root = workspace.path().join("package");
    fs::create_dir(&package_root).unwrap();
    fs::create_dir(package_root.join("bin")).unwrap();
    fs::copy(&source_binary, package_root.join("bin/gtkg")).unwrap();
    let package_binary = package_root.join("bin/gtkg");
    assert_eq!(sha256(&fs::read(&package_binary).unwrap()), source_binary_sha256);

    let install_parent = tempfile::tempdir().unwrap();
    let isolated = create_isolated_root_v1(install_parent.path()).unwrap();
    let preview = preview_install_with_capability_v1(
        &package_root,
        &isolated,
        &manifest(&source_binary_sha256),
    )
    .unwrap();
    assert_eq!(preview.write_count(), 0, "preview does not install");
    let install = apply_install_with_capability_v1(&isolated, &preview).unwrap();
    assert_eq!(install.action, InstallActionV1::Install);
    assert!(install.readback_verified);
    let installed_binary = isolated.path().join("bin/gtkg");
    let installed_binary_sha256 = sha256(&fs::read(&installed_binary).unwrap());
    assert_eq!(installed_binary_sha256, source_binary_sha256);

    let query_root = workspace.path().join("query-index");
    let evidence_root = workspace.path().join("evidence-index");
    let expected = FileQueryExpectedIdentitiesV1 {
        source_identity: digest("u06-source"),
        graph_identity: digest("u06-graph"),
        overlay_identity: digest("u06-overlay"),
    };
    let documents = vec![
        LexicalDocumentV1 {
            node_id: "node-u06".to_owned(),
            evidence_ref: "evidence:node-u06".to_owned(),
            text: "u06 installed binary evidence query".to_owned(),
        },
        LexicalDocumentV1 {
            node_id: "node-target".to_owned(),
            evidence_ref: "evidence:node-target".to_owned(),
            text: "u06 explorer target".to_owned(),
        },
        LexicalDocumentV1 {
            node_id: "edge-u06-target".to_owned(),
            evidence_ref: "evidence:edge-u06-target".to_owned(),
            text: "u06 installed relation".to_owned(),
        },
    ];
    let lexical = vec![build_lexical_shard_v1("u06-lex", &documents).unwrap()];
    let adjacency = build_adjacency_routing_index_v1(
        &["node-u06".to_owned(), "node-target".to_owned()],
        &[AdjacencyEdgeInputV1 {
            edge_id: "edge-u06-target".to_owned(),
            source_node_id: "node-u06".to_owned(),
            target_node_id: "node-target".to_owned(),
            resolution_state: QueryResolutionStateV1::Resolved,
            evidence_ref: "evidence:edge-u06-target".to_owned(),
        }],
    )
    .unwrap();
    let entities = vec![
        GraphQueryEntityV1::StructuralNode {
            entity_id: "node-u06".to_owned(),
            node_kind: "code_symbol".to_owned(),
            label: "U06 <img src=x onerror=globalThis.__u06_xss=true> installed evidence".to_owned(),
            source_logical_path: "src/u06.rs".to_owned(),
            structural_provenance: json!({"input_kind":"typed_ir","input_id":"src/u06.rs","input_sha256":digest("u06-ir"),"source_snapshot_exact_set_sha256":expected.source_identity}),
            evidence: vec![evidence("evidence:node-u06", 0)],
        },
        GraphQueryEntityV1::StructuralNode {
            entity_id: "node-target".to_owned(),
            node_kind: "code_symbol".to_owned(),
            label: "U06 target".to_owned(),
            source_logical_path: "src/target.rs".to_owned(),
            structural_provenance: json!({"input_kind":"typed_ir","input_id":"src/target.rs","input_sha256":digest("target-ir"),"source_snapshot_exact_set_sha256":expected.source_identity}),
            evidence: vec![evidence("evidence:node-target", 1)],
        },
        GraphQueryEntityV1::StructuralEdge {
            entity_id: "edge-u06-target".to_owned(),
            edge_kind: "calls".to_owned(),
            source_node_id: "node-u06".to_owned(),
            target_node_id: Some("node-target".to_owned()),
            target_reference: "node-target".to_owned(),
            resolution_state: QueryResolutionStateV1::Resolved,
            candidate_node_ids: Vec::new(),
            structural_provenance: json!({"input_kind":"typed_ir","input_id":"src/u06.rs","input_sha256":digest("u06-edge"),"source_snapshot_exact_set_sha256":expected.source_identity}),
            evidence: vec![evidence("evidence:edge-u06-target", 2)],
        },
    ];
    assert!(explorer_parent.is_dir());
    let write = context(vec![workspace.path().to_path_buf(), explorer_parent.to_path_buf()]);
    let query_manifest_ref =
        write_file_query_index_v1(&write, &query_root, &expected, &lexical, &adjacency).unwrap();
    let query_manifest: FileQueryIndexManifestV1 =
        serde_json::from_slice(&fs::read(query_root.join(&query_manifest_ref.path)).unwrap())
            .unwrap();
    let evidence_manifest_ref = write_graph_query_evidence_index_v1(
        &write,
        &evidence_root,
        &expected,
        &query_manifest_ref,
        &query_manifest.index_manifest_sha256,
        &entities,
    )
    .unwrap();

    let request = OperationRequestV2::new(
        "graph.search",
        "u06-installed-search",
        json!({
            "query_index_path": "query-index",
            "query_manifest_ref": query_manifest_ref,
            "evidence_index_path": "evidence-index",
            "evidence_manifest_ref": evidence_manifest_ref,
            "expected_identities": expected,
            "query": "u06",
            "max_results": 10
        }),
    );
    let mut query_child = Command::new(&installed_binary)
        .args([
            "v2-op",
            "graph.search",
            "--profile",
            "graph",
            "--request",
            "-",
            "--output",
            "json",
        ])
        .current_dir(workspace.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    serde_json::to_writer(query_child.stdin.as_mut().unwrap(), &request).unwrap();
    query_child.stdin.take().unwrap().flush().unwrap();
    let query_output = query_child.wait_with_output().unwrap();
    assert!(
        query_output.status.success(),
        "installed binary query failed: {}",
        String::from_utf8_lossy(&query_output.stderr)
    );
    let query_response: Value = serde_json::from_slice(&query_output.stdout).unwrap();
    assert_eq!(query_response["operation_id"], "graph.search");
    assert_eq!(query_response["result"]["operation_id"], "graph.search");
    assert!(query_response["result"]["result"]["matches"]
        .as_array()
        .is_some_and(|matches| !matches.is_empty()));
    let query_index = &query_response["result"]["evidence_pack"]["query_index"];
    assert_eq!(query_index["network_call_count"], 0);
    assert_eq!(query_index["database_read_count"], 0);
    assert_eq!(query_index["daemon_call_count"], 0);
    let query_response_sha256 = sha256(&query_output.stdout);

    let explorer_input = StaticGraphExplorerArtifactInputV2 {
        query_root,
        query_manifest_ref,
        evidence_root,
        evidence_manifest_ref,
        expected_identities: expected,
        search_query: "u06".to_owned(),
        primary_entity_id: "node-u06".to_owned(),
        path_target_entity_id: "node-target".to_owned(),
    };
    let explorer_projection =
        build_static_graph_explorer_from_artifacts_v2(&write, &explorer_input).unwrap();
    let explorer_capability =
        create_static_graph_explorer_output_root_v2(&write, explorer_parent).unwrap();
    let explorer =
        write_static_graph_explorer_with_capability_v2(&explorer_capability, &explorer_projection)
            .unwrap();
    assert_eq!(explorer.network_calls, 0);
    assert_eq!(explorer.database_reads, 0);
    assert_eq!(explorer.target_execution_count, 0);

    let uninstall = uninstall_with_capability_v1(&isolated, &install).unwrap();
    assert_eq!(uninstall.action, InstallActionV1::Uninstall);
    assert!(uninstall.readback_verified);
    assert!(!installed_binary.exists());
    assert!(!isolated.path().join(".gtkg-install").exists());

    Journey {
        source_binary_sha256,
        installed_binary_sha256,
        install,
        query_response,
        query_response_sha256,
        explorer,
        uninstall,
        target_project_execution_count: 0,
    }
}

#[test]
fn u06_isolated_local_install_query_explorer_uninstall_journey() {
    let explorer_parent = tempfile::tempdir().unwrap();
    let journey = run_journey(explorer_parent.path());
    assert_eq!(journey.source_binary_sha256, journey.installed_binary_sha256);
    assert_eq!(journey.install.managed_file_write_count, 1);
    assert_eq!(journey.uninstall.managed_file_remove_count, 1);
    assert_eq!(journey.target_project_execution_count, 0);
    assert!(journey.explorer.site_root.starts_with(explorer_parent.path().to_str().unwrap()));
}

#[test]
#[ignore = "emits the actual installed-binary U06 Explorer fixture for browser E2E"]
fn emit_u06_browser_fixture() {
    let output_parent = PathBuf::from(required_env("GTKG_U06_BROWSER_OUTPUT_PARENT"));
    assert!(output_parent.is_dir());
    assert!(fs::read_dir(&output_parent).unwrap().next().is_none());
    let journey = run_journey(&output_parent);
    fs::write(
        output_parent.join("u06-browser-fixture-receipt.json"),
        serde_json::to_vec_pretty(&json!({
            "schema_version": "gtkg.u06-browser-fixture/v1",
            "site_root": journey.explorer.site_root,
            "explorer_receipt": journey.explorer,
            "install": journey.install,
            "query_response_sha256": journey.query_response_sha256,
            "query_operation": journey.query_response["operation_id"],
            "uninstall": journey.uninstall,
            "source_binary_sha256": journey.source_binary_sha256,
            "installed_binary_sha256": journey.installed_binary_sha256,
            "target_project_execution_count": journey.target_project_execution_count,
            "network_calls": 0,
            "database_reads": 0
        }))
        .unwrap(),
    )
    .unwrap();
}
