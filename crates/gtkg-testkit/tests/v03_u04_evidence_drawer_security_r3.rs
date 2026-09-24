//! U04 r3 security successor: descriptor-bound output capability, opaque
//! projection construction, exact U03/Q04/Current inputs, and complete A2UI
//! evidence state delivery.

use std::fs;
use std::path::{Path, PathBuf};

use gtkg_core::v03::evidence_drawer::{
    EvidenceDrawerArtifactInputV1, build_evidence_drawer_from_artifacts_v1,
    create_evidence_drawer_output_root_v1, read_evidence_drawer_v1, write_evidence_drawer_v1,
    write_evidence_drawer_with_capability_v1,
};
use gtkg_core::v03::explorer::{
    StaticGraphExplorerArtifactInputV2, build_static_graph_explorer_from_artifacts_v2,
    create_static_graph_explorer_output_root_v2, write_static_graph_explorer_with_capability_v2,
};
use gtkg_core::v03::graph_query::{GraphQueryEntityV1, write_graph_query_evidence_index_v1};
use gtkg_core::v03::query::{
    AdjacencyEdgeInputV1, LexicalDocumentV1, build_adjacency_routing_index_v1,
    build_lexical_shard_v1, write_file_query_index_v1,
};
use gtkg_core::{CallContext, EffectPolicy, TransportKind};
use gtkg_protocol::FileReceiptRef;
use gtkg_protocol::v03::query::{
    FileQueryExpectedIdentitiesV1, FileQueryIndexManifestV1, QueryResolutionStateV1,
};
use serde_json::json;

fn digest(label: &str) -> String {
    use sha2::{Digest, Sha256};
    format!("sha256:{}", hex::encode(Sha256::digest(label.as_bytes())))
}

fn sha256(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn context(roots: Vec<PathBuf>, policy: EffectPolicy) -> CallContext {
    CallContext::restricted(TransportKind::Test, roots, policy).unwrap()
}

pub(crate) struct Fixture {
    pub(crate) workspace: tempfile::TempDir,
    pub(crate) query_root: PathBuf,
    pub(crate) query_manifest_ref: FileReceiptRef,
    pub(crate) evidence_root: PathBuf,
    pub(crate) evidence_manifest_ref: FileReceiptRef,
    pub(crate) expected: FileQueryExpectedIdentitiesV1,
    pub(crate) explorer_receipt: gtkg_core::v03::explorer::StaticGraphExplorerReceiptV2,
    pub(crate) current_path: PathBuf,
    pub(crate) current_sha256: String,
    pub(crate) u03_parent: PathBuf,
    pub(crate) u04_parent: PathBuf,
}

impl Fixture {
    pub(crate) fn new() -> Self {
        let workspace = tempfile::tempdir().unwrap();
        let query_root = workspace.path().join(".gtkg/query-index");
        let evidence_root = workspace.path().join(".gtkg/query-evidence");
        let u03_parent = workspace.path().join("u03-parent");
        let u04_parent = workspace.path().join("u04-parent");
        fs::create_dir(&u03_parent).unwrap();
        fs::create_dir(&u04_parent).unwrap();
        let expected = FileQueryExpectedIdentitiesV1 {
            source_identity: digest("u04-r3-source"),
            graph_identity: digest("u04-r3-graph"),
            overlay_identity: digest("u04-r3-overlay"),
        };
        let docs = vec![
            LexicalDocumentV1 {
                node_id: "node-a".to_owned(),
                evidence_ref: "evidence:node-a".to_owned(),
                text: "drawer security origin".to_owned(),
            },
            LexicalDocumentV1 {
                node_id: "node-b".to_owned(),
                evidence_ref: "evidence:node-b".to_owned(),
                text: "drawer security target".to_owned(),
            },
            LexicalDocumentV1 {
                node_id: "edge-a-b".to_owned(),
                evidence_ref: "evidence:edge-a-b".to_owned(),
                text: "drawer security relation".to_owned(),
            },
        ];
        let lexical = vec![build_lexical_shard_v1("u04-r3", &docs).unwrap()];
        let adjacency = build_adjacency_routing_index_v1(
            &["node-a".to_owned(), "node-b".to_owned()],
            &[AdjacencyEdgeInputV1 {
                edge_id: "edge-a-b".to_owned(),
                source_node_id: "node-a".to_owned(),
                target_node_id: "node-b".to_owned(),
                resolution_state: QueryResolutionStateV1::Resolved,
                evidence_ref: "evidence:edge-a-b".to_owned(),
            }],
        )
        .unwrap();
        let entities = vec![
            GraphQueryEntityV1::StructuralNode {
                entity_id: "node-a".to_owned(),
                node_kind: "code_symbol".to_owned(),
                label: "safe <img src=x onerror=globalThis.__u04_r3_xss=true> label".to_owned(),
                source_logical_path: "src/a.rs".to_owned(),
                structural_provenance: json!({"input_kind":"typed_ir","input_id":"src/a.rs","input_sha256":digest("a"),"source_snapshot_exact_set_sha256":expected.source_identity}),
                evidence: vec![json!({"evidence_id":"evidence:node-a"})],
            },
            GraphQueryEntityV1::StructuralNode {
                entity_id: "node-b".to_owned(),
                node_kind: "code_symbol".to_owned(),
                label: "target".to_owned(),
                source_logical_path: "src/b.rs".to_owned(),
                structural_provenance: json!({"input_kind":"typed_ir","input_id":"src/b.rs","input_sha256":digest("b"),"source_snapshot_exact_set_sha256":expected.source_identity}),
                evidence: vec![json!({"evidence_id":"evidence:node-b"})],
            },
            GraphQueryEntityV1::StructuralEdge {
                entity_id: "edge-a-b".to_owned(),
                edge_kind: "calls".to_owned(),
                source_node_id: "node-a".to_owned(),
                target_node_id: Some("node-b".to_owned()),
                target_reference: "node-b".to_owned(),
                resolution_state: QueryResolutionStateV1::Resolved,
                candidate_node_ids: Vec::new(),
                structural_provenance: json!({"input_kind":"typed_ir","input_id":"edge","input_sha256":digest("edge"),"source_snapshot_exact_set_sha256":expected.source_identity}),
                evidence: vec![json!({"evidence_id":"evidence:edge-a-b"})],
            },
        ];
        let write = context(
            vec![
                workspace.path().to_path_buf(),
                u03_parent.clone(),
                u04_parent.clone(),
            ],
            EffectPolicy::WorkspaceWrite,
        );
        let query_manifest_ref =
            write_file_query_index_v1(&write, &query_root, &expected, &lexical, &adjacency)
                .unwrap();
        let manifest: FileQueryIndexManifestV1 =
            serde_json::from_slice(&fs::read(query_root.join(&query_manifest_ref.path)).unwrap())
                .unwrap();
        let evidence_manifest_ref = write_graph_query_evidence_index_v1(
            &write,
            &evidence_root,
            &expected,
            &query_manifest_ref,
            &manifest.index_manifest_sha256,
            &entities,
        )
        .unwrap();
        let explorer = build_static_graph_explorer_from_artifacts_v2(
            &write,
            &StaticGraphExplorerArtifactInputV2 {
                query_root: query_root.clone(),
                query_manifest_ref: query_manifest_ref.clone(),
                evidence_root: evidence_root.clone(),
                evidence_manifest_ref: evidence_manifest_ref.clone(),
                expected_identities: expected.clone(),
                search_query: "drawer".to_owned(),
                primary_entity_id: "node-a".to_owned(),
                path_target_entity_id: "node-b".to_owned(),
            },
        )
        .unwrap();
        let u03_capability =
            create_static_graph_explorer_output_root_v2(&write, &u03_parent).unwrap();
        let explorer_receipt =
            write_static_graph_explorer_with_capability_v2(&u03_capability, &explorer).unwrap();
        let current_path = workspace.path().join("CURRENT.json");
        let current_bytes = serde_json::to_vec_pretty(&json!({
            "schema_version":"gtkg.current/v1",
            "deliverable_id":"u04-r3",
            "version":"0.3.0",
            "version_path":"versions/0.3.0",
            "tree_sha256":digest("r3-tree"),
            "manifest_sha256":evidence_manifest_ref.sha256,
        }))
        .unwrap();
        fs::write(&current_path, &current_bytes).unwrap();
        Self {
            workspace,
            query_root,
            query_manifest_ref,
            evidence_root,
            evidence_manifest_ref,
            expected,
            explorer_receipt,
            current_path,
            current_sha256: sha256(&current_bytes),
            u03_parent,
            u04_parent,
        }
    }

    pub(crate) fn input(&self) -> EvidenceDrawerArtifactInputV1 {
        EvidenceDrawerArtifactInputV1 {
            query_root: self.query_root.clone(),
            query_manifest_ref: self.query_manifest_ref.clone(),
            evidence_root: self.evidence_root.clone(),
            evidence_manifest_ref: self.evidence_manifest_ref.clone(),
            expected_identities: self.expected.clone(),
            explorer_receipt: self.explorer_receipt.clone(),
            current_path: self.current_path.clone(),
            current_sha256: self.current_sha256.clone(),
            search_query: "drawer".to_owned(),
            unknown_query: "never-r3".to_owned(),
            explain_node_id: "node-a".to_owned(),
        }
    }

    pub(crate) fn write_context(&self) -> CallContext {
        context(
            vec![
                self.workspace.path().to_path_buf(),
                self.u03_parent.clone(),
                self.u04_parent.clone(),
            ],
            EffectPolicy::WorkspaceWrite,
        )
    }
}

#[cfg(unix)]
#[test]
fn u04_r3_capability_writes_only_from_actual_builder_and_delivers_all_a2ui_facts() {
    let fixture = Fixture::new();
    let context = fixture.write_context();
    let projection = build_evidence_drawer_from_artifacts_v1(&context, &fixture.input()).unwrap();
    let capability = create_evidence_drawer_output_root_v1(&context, &fixture.u04_parent).unwrap();
    let receipt =
        write_evidence_drawer_with_capability_v1(&context, &capability, &projection).unwrap();
    assert!(
        receipt
            .site_root
            .starts_with(fixture.u04_parent.to_str().unwrap())
    );
    assert_eq!(
        read_evidence_drawer_v1(&context, &receipt).unwrap(),
        projection
    );

    let stream =
        fs::read_to_string(Path::new(&receipt.site_root).join("a2ui/stream.jsonl")).unwrap();
    let messages = stream
        .lines()
        .map(serde_json::from_str::<serde_json::Value>)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let data = &messages[2]["updateDataModel"]["value"];
    for key in [
        "source_evidence",
        "relations",
        "claim_states",
        "unknown",
        "conflicts",
        "source_evidence_json",
        "relations_json",
        "claim_states_json",
        "unknown_json",
        "conflicts_json",
    ] {
        assert!(!data[key].is_null(), "A2UI data omitted {key}");
    }

    let external = fixture.workspace.path().join("external-index.json");
    let index = Path::new(&receipt.site_root).join("index.html");
    fs::rename(&index, &external).unwrap();
    fs::hard_link(&external, &index).unwrap();
    assert_eq!(
        read_evidence_drawer_v1(&context, &receipt)
            .unwrap_err()
            .code(),
        "E_U04_ARTIFACT_INVALID"
    );
}

#[cfg(unix)]
#[test]
fn u04_r3_rejects_parent_root_swap_and_symlink_before_any_external_write() {
    use std::os::unix::fs::symlink;

    let fixture = Fixture::new();
    let context = fixture.write_context();
    let projection = build_evidence_drawer_from_artifacts_v1(&context, &fixture.input()).unwrap();

    let parent_link = fixture.workspace.path().join("u04-parent-link");
    symlink(&fixture.u04_parent, &parent_link).unwrap();
    assert_eq!(
        write_evidence_drawer_v1(&context, &parent_link.join("drawer"), &projection)
            .unwrap_err()
            .code(),
        "E_U04_OUTPUT_PARENT_SYMLINK"
    );

    let capability = create_evidence_drawer_output_root_v1(&context, &fixture.u04_parent).unwrap();
    let parked = fixture.workspace.path().join("parked-u04-parent");
    let external = fixture.workspace.path().join("external-target");
    fs::create_dir(&external).unwrap();
    fs::rename(&fixture.u04_parent, &parked).unwrap();
    symlink(&external, &fixture.u04_parent).unwrap();
    assert_eq!(
        write_evidence_drawer_with_capability_v1(&context, &capability, &projection)
            .unwrap_err()
            .code(),
        "E_U04_CAPABILITY_MISMATCH"
    );
    assert!(fs::read_dir(&external).unwrap().next().is_none());
}
