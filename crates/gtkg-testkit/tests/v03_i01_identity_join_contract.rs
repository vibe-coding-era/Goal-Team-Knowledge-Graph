//! I01 joins only already-verified local identities. It deliberately never
//! activates Current, changes a canonical pointer, or performs a system install.

#[path = "support/v03_i00_source_bound_fixture.rs"]
#[allow(dead_code)]
mod i00_fixture;

use std::fs;
use std::path::{Path, PathBuf};

use gtkg_core::file_model::tree_sha256;
use gtkg_core::v03::identity_lifecycle::{
    IDENTITY_LIFECYCLE_CANDIDATE_SCHEMA_V1, IdentityLifecycleCandidateV1, IdentityLifecycleErrorV1,
    IdentityLifecycleStaleComponentV1, verify_identity_lifecycle_join_v1,
};
use gtkg_core::v03::installer::{
    InstallManifestV1, InstallReceiptV1, apply_install_with_capability_v1, create_isolated_root_v1,
    preview_install_with_capability_v1,
};
use gtkg_core::v03::lifecycle::{
    bind_migration_rebuild_provenance_source_bound_v2, publish_a06_source_bound_gate_attestation_v1,
};
use gtkg_core::v03::query::{
    AdjacencyEdgeInputV1, LexicalDocumentV1, build_adjacency_routing_index_v1,
    build_lexical_shard_v1, write_file_query_index_v1,
};
use gtkg_core::{CallContext, Dispatcher, EffectPolicy, TransportKind};
use gtkg_protocol::FileReceiptRef;
use gtkg_protocol::canonical_json_sha256;
use gtkg_protocol::v2::OperationRequestV2;
use gtkg_protocol::v03::discovery_profiles_v03;
use gtkg_protocol::v03::query::{
    FileQueryExpectedIdentitiesV1, FileQueryIndexManifestV1, QueryIndexEquivalenceIdentityV1,
    QueryResolutionStateV1,
};
use serde_json::json;
use sha2::{Digest, Sha256};

#[cfg(unix)]
#[test]
fn i01_source_bound_candidate_joins_actual_index_binary_and_isolated_install_without_writes() {
    let baseline = baseline();
    let before = tree_sha256(&baseline.workspace).unwrap();
    let receipt = verify_identity_lifecycle_join_v1(
        &baseline.context,
        &baseline.workspace,
        &baseline.candidate,
        &baseline.candidate,
    )
    .expect("all source-bound local identities must join");
    assert!(!receipt.current_activation);
    assert_eq!(receipt.current_write_count, 0);
    assert_eq!(receipt.canonical_write_count, 0);
    assert_eq!(receipt.replay_write_count, 0);
    assert_eq!(tree_sha256(&baseline.workspace).unwrap(), before);
}

#[cfg(unix)]
#[test]
fn i01_rejects_each_identity_mutation_precisely_without_auto_upgrade() {
    let baseline = baseline();
    let cases: Vec<IdentityMutationCase> = vec![
        (
            IdentityLifecycleStaleComponentV1::MigrationProvenance,
            Box::new(|candidate| {
                candidate.migration_provenance_ref.sha256 = sha256("i01-stale-provenance")
            }),
        ),
        (
            IdentityLifecycleStaleComponentV1::MigrationProvenance,
            Box::new(|candidate| {
                candidate.migration_provenance_ref.path =
                    "lifecycle/migration-provenance-v2/stale.json".to_owned()
            }),
        ),
        (
            IdentityLifecycleStaleComponentV1::Source,
            Box::new(|candidate| candidate.source_identity = sha256("i01-stale-source")),
        ),
        (
            IdentityLifecycleStaleComponentV1::Bundle,
            Box::new(|candidate| candidate.bundle_identity = sha256("i01-stale-bundle")),
        ),
        (
            IdentityLifecycleStaleComponentV1::Adapter,
            Box::new(|candidate| candidate.adapter_identity = sha256("i01-stale-adapter")),
        ),
        (
            IdentityLifecycleStaleComponentV1::Graph,
            Box::new(|candidate| candidate.graph_identity = sha256("i01-stale-graph")),
        ),
        (
            IdentityLifecycleStaleComponentV1::Overlay,
            Box::new(|candidate| candidate.overlay_identity = sha256("i01-stale-overlay")),
        ),
        (
            IdentityLifecycleStaleComponentV1::Index,
            Box::new(|candidate| candidate.index_manifest_identity = sha256("i01-stale-index")),
        ),
        (
            IdentityLifecycleStaleComponentV1::Index,
            Box::new(|candidate| {
                candidate.index_manifest_ref.path = "manifests/stale-index.json".to_owned()
            }),
        ),
        (
            IdentityLifecycleStaleComponentV1::Binary,
            Box::new(|candidate| candidate.binary_identity = sha256("i01-stale-binary")),
        ),
        (
            IdentityLifecycleStaleComponentV1::Profile,
            Box::new(|candidate| candidate.profile_digest = sha256("i01-stale-profile")),
        ),
        (
            IdentityLifecycleStaleComponentV1::InstallManifest,
            Box::new(|candidate| {
                candidate.install_manifest_identity = sha256("i01-stale-install-manifest")
            }),
        ),
        (
            IdentityLifecycleStaleComponentV1::InstallReceipt,
            Box::new(|candidate| {
                candidate.install_receipt_identity = sha256("i01-stale-install-receipt")
            }),
        ),
    ];
    let before = tree_sha256(&baseline.workspace).unwrap();
    for (component, mutate) in cases {
        let mut observed = baseline.candidate.clone();
        mutate(&mut observed);
        let observed = observed.seal().unwrap();
        let error = verify_identity_lifecycle_join_v1(
            &baseline.context,
            &baseline.workspace,
            &baseline.candidate,
            &observed,
        )
        .expect_err("one identity mutation must be stale, never auto-upgraded");
        assert_stale(error, component);
    }
    assert_eq!(tree_sha256(&baseline.workspace).unwrap(), before);
}

#[cfg(unix)]
#[test]
fn i01_rejects_selector_side_effect_flags_before_reading_any_candidate() {
    let baseline = baseline();
    let mut candidate = baseline.candidate.clone();
    candidate.current_activation = true;
    assert!(matches!(
        candidate.seal(),
        Err(IdentityLifecycleErrorV1::SideEffectAttempt)
    ));
}

#[cfg(not(unix))]
#[test]
fn i01_identity_join_requires_unix_descriptor_installer_support() {
    assert!(true);
}

struct Baseline {
    _fixture: i00_fixture::Candidate,
    workspace: PathBuf,
    context: CallContext,
    candidate: IdentityLifecycleCandidateV1,
}

type IdentityMutationCase = (
    IdentityLifecycleStaleComponentV1,
    Box<dyn Fn(&mut IdentityLifecycleCandidateV1)>,
);

#[cfg(unix)]
fn baseline() -> Baseline {
    let fixture = i00_fixture::same_source_candidate();
    let workspace = fixture.workspace.path().to_path_buf();
    let context = context(&workspace);
    let migrated_bundle_ref = migrate_legacy(&workspace, &context);
    let attestation = publish_a06_source_bound_gate_attestation_v1(
        &context,
        &workspace,
        fixture.attestation_input(fixture.persist_gate(), fixture.persist_trusted_fixture()),
    )
    .unwrap();
    let provenance = bind_migration_rebuild_provenance_source_bound_v2(
        &context,
        &workspace,
        migrated_bundle_ref,
        fixture.bundle_ref.clone(),
        attestation.file_receipt_ref().unwrap(),
    )
    .unwrap();
    let provenance_ref = provenance.file_receipt_ref().unwrap();

    let profile = discovery_profiles_v03()
        .into_iter()
        .find(|profile| profile.profile_id.as_str() == "core")
        .unwrap();
    let adapter_identity = sha256("i01-actual-five-adapter-replay-set");
    let query_identity = QueryIndexEquivalenceIdentityV1::new(
        provenance
            .rebuilt_source_snapshot_exact_set_sha256()
            .to_owned(),
        adapter_identity.clone(),
        profile.digest.clone(),
    )
    .unwrap();
    let query_expected = query_identity.file_query_expected_identities().unwrap();
    let index_manifest_ref = write_actual_query_index(&context, &workspace, &query_expected);
    let manifest: FileQueryIndexManifestV1 = serde_json::from_slice(
        &fs::read(
            workspace
                .join(".gtkg/i01-query-index")
                .join(&index_manifest_ref.path),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        manifest.index.source_identity,
        query_expected.source_identity
    );
    assert_eq!(manifest.index.graph_identity, query_expected.graph_identity);
    assert_eq!(
        manifest.index.overlay_identity,
        query_expected.overlay_identity
    );

    let (binary_identity, install_manifest, install_receipt) = isolated_install_identities();
    let install_manifest_identity = install_receipt.manifest_sha256.clone();
    let install_receipt_identity = canonical_json_sha256(&install_receipt).unwrap();
    let candidate = IdentityLifecycleCandidateV1 {
        schema_version: IDENTITY_LIFECYCLE_CANDIDATE_SCHEMA_V1.to_owned(),
        migration_provenance_ref: provenance_ref,
        source_identity: query_expected.source_identity,
        bundle_identity: provenance.rebuilt_bundle_sha256().to_owned(),
        adapter_identity,
        graph_identity: query_expected.graph_identity,
        overlay_identity: query_expected.overlay_identity,
        index_manifest_ref: index_manifest_ref.clone(),
        index_manifest_identity: index_manifest_ref.sha256,
        binary_identity,
        profile_id: profile.profile_id.as_str().to_owned(),
        profile_digest: profile.digest,
        install_manifest,
        install_manifest_identity,
        install_receipt,
        install_receipt_identity,
        current_activation: false,
        current_write_count: 0,
        canonical_write_count: 0,
        replay_write_count: 0,
        candidate_sha256: String::new(),
    }
    .seal()
    .unwrap();
    Baseline {
        _fixture: fixture,
        workspace,
        context,
        candidate,
    }
}

#[cfg(unix)]
fn write_actual_query_index(
    context: &CallContext,
    workspace: &Path,
    expected: &FileQueryExpectedIdentitiesV1,
) -> FileReceiptRef {
    let lexical = vec![
        build_lexical_shard_v1(
            "i01-lexical",
            &[LexicalDocumentV1 {
                node_id: "node-i01".to_owned(),
                evidence_ref: "evidence:node-i01".to_owned(),
                text: "I01 source-bound graph identity".to_owned(),
            }],
        )
        .unwrap(),
    ];
    let adjacency = build_adjacency_routing_index_v1(
        &["node-i01".to_owned(), "node-i01-target".to_owned()],
        &[AdjacencyEdgeInputV1 {
            edge_id: "edge-i01".to_owned(),
            source_node_id: "node-i01".to_owned(),
            target_node_id: "node-i01-target".to_owned(),
            resolution_state: QueryResolutionStateV1::Resolved,
            evidence_ref: "evidence:edge-i01".to_owned(),
        }],
    )
    .unwrap();
    write_file_query_index_v1(
        context,
        &workspace.join(".gtkg/i01-query-index"),
        expected,
        &lexical,
        &adjacency,
    )
    .unwrap()
}

#[cfg(unix)]
fn isolated_install_identities() -> (String, InstallManifestV1, InstallReceiptV1) {
    let package_root = fixture("v1");
    let manifest: InstallManifestV1 =
        serde_json::from_slice(&fs::read(package_root.join("install-manifest.json")).unwrap())
            .unwrap();
    let source_binary = fs::read(package_root.join("bin/gtkg")).unwrap();
    let binary_identity = sha256_bytes(&source_binary);
    assert_eq!(manifest.digests["bin/gtkg"], binary_identity);

    let parent = tempfile::Builder::new()
        .prefix("gtkg-i01-install-")
        .tempdir_in(fixed_system_temp_root())
        .unwrap();
    let root = create_isolated_root_v1(parent.path()).unwrap();
    let preview = preview_install_with_capability_v1(&package_root, &root, &manifest).unwrap();
    let receipt = apply_install_with_capability_v1(&root, &preview).unwrap();
    assert!(receipt.readback_verified);
    assert_eq!(
        sha256_bytes(&fs::read(root.path().join("bin/gtkg")).unwrap()),
        binary_identity
    );
    (binary_identity, manifest, receipt)
}

#[cfg(unix)]
fn fixed_system_temp_root() -> &'static Path {
    if cfg!(target_os = "macos") {
        Path::new("/private/tmp")
    } else {
        Path::new("/tmp")
    }
}

#[cfg(unix)]
fn fixture(version: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures/v03_u01")
        .join(version)
}

#[cfg(unix)]
fn context(root: &Path) -> CallContext {
    CallContext::restricted(
        TransportKind::Test,
        vec![root.to_path_buf()],
        EffectPolicy::WorkspaceWrite,
    )
    .unwrap()
}

#[cfg(unix)]
fn migrate_legacy(root: &Path, context: &CallContext) -> FileReceiptRef {
    let legacy = root.join("i01-legacy");
    fs::create_dir(&legacy).unwrap();
    fs::write(
        legacy.join("manifest.json"),
        serde_json::to_vec_pretty(&json!({
            "schema_version": "gtkg.bundle/v1",
            "legacy_status": "not_proven"
        }))
        .unwrap(),
    )
    .unwrap();
    let migrated = Dispatcher
        .execute_v2(
            context,
            OperationRequestV2::new(
                "bundle.migrate.v1_to_v2",
                "i01-migrate",
                json!({
                    "workspace_root": root,
                    "legacy_bundle_path": legacy,
                    "expected_legacy_tree_sha256": tree_sha256(&root.join("i01-legacy")).unwrap(),
                    "migration_version": "i01-migration"
                }),
            ),
        )
        .unwrap();
    serde_json::from_value(migrated.result["bundle_ref"].clone()).unwrap()
}

fn assert_stale(error: IdentityLifecycleErrorV1, component: IdentityLifecycleStaleComponentV1) {
    match error {
        IdentityLifecycleErrorV1::Stale {
            component: observed,
            ..
        } => assert_eq!(observed, component),
        other => panic!("expected precise stale {component:?}, got {other:?}"),
    }
}

fn sha256(value: &str) -> String {
    sha256_bytes(value.as_bytes())
}

fn sha256_bytes(value: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(value)))
}
