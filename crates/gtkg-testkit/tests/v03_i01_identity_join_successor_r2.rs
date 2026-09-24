//! I01 r2 replaces the review-rejected self-described selector with actual
//! I00 provenance, Q06 index, and U01 installed-binary readback.

#[path = "support/v03_i00_source_bound_fixture.rs"]
#[allow(dead_code)]
mod i00_fixture;

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use gtkg_core::file_model::tree_sha256;
use gtkg_core::v03::identity_lifecycle::{
    IdentityLifecycleErrorV1, IdentityLifecycleReadbackInputV2, IdentityLifecycleStaleComponentV1,
    verify_identity_lifecycle_readback_v2,
};
use gtkg_core::v03::installer::{
    INSTALL_MANIFEST_SCHEMA_V1, InstallManifestV1, InstallReceiptV1, IsolatedInstallRootV1,
    apply_install_with_capability_v1, create_isolated_root_v1, preview_install_with_capability_v1,
};
use gtkg_core::v03::lifecycle::{
    bind_migration_rebuild_provenance_source_bound_v2,
    publish_a06_source_bound_gate_attestation_v1, read_source_bound_identity_v2,
};
use gtkg_core::v03::query::{
    AdjacencyEdgeInputV1, LexicalDocumentV1, build_adjacency_routing_index_v1,
    build_lexical_shard_v1, write_file_query_index_v1,
};
use gtkg_core::{CallContext, Dispatcher, EffectPolicy, TransportKind};
use gtkg_protocol::FileReceiptRef;
use gtkg_protocol::v2::OperationRequestV2;
use gtkg_protocol::v03::discovery_profiles_v03;
use gtkg_protocol::v03::query::{
    FileQueryExpectedIdentitiesV1, FileQueryLookupV1, FileQueryRequestV1,
    QueryIndexEquivalenceIdentityV1, QueryResolutionStateV1,
};
use serde_json::json;
use sha2::{Digest, Sha256};

#[cfg(unix)]
#[test]
fn i01_r2_reads_actual_provenance_index_and_installed_current_binary_without_writes() {
    let baseline = baseline();
    let before_workspace = tree_sha256(&baseline.workspace).unwrap();
    let receipt = verify_identity_lifecycle_readback_v2(
        &baseline.context,
        &baseline.workspace,
        &input(&baseline),
    )
    .expect("only actual local readbacks may form the I01 r2 receipt");
    assert_eq!(receipt.source_identity, baseline.source_identity);
    assert_eq!(receipt.bundle_identity, baseline.bundle_identity);
    assert_eq!(receipt.binary_sha256, baseline.install.binary_sha256);
    assert_eq!(
        receipt.index_receipt_sha256,
        baseline.index_manifest_ref.sha256
    );
    assert!(!receipt.current_activation);
    assert_eq!(receipt.current_write_count, 0);
    assert_eq!(receipt.canonical_write_count, 0);
    assert_eq!(receipt.replay_write_count, 0);
    assert_eq!(tree_sha256(&baseline.workspace).unwrap(), before_workspace);
}

#[cfg(unix)]
#[test]
fn i01_r2_rejects_actual_index_binary_receipt_manifest_profile_and_provenance_drift() {
    let baseline = baseline();
    let mut receipt_input = input(&baseline);
    receipt_input.install_receipt.capability_digest = sha256("tampered-capability");
    assert_stale(
        verify_identity_lifecycle_readback_v2(
            &baseline.context,
            &baseline.workspace,
            &receipt_input,
        )
        .unwrap_err(),
        IdentityLifecycleStaleComponentV1::InstallReceipt,
    );

    let mut manifest_input = input(&baseline);
    manifest_input
        .install_manifest
        .digests
        .insert("bin/gtkg".to_owned(), sha256("tampered-manifest-binary"));
    assert_stale(
        verify_identity_lifecycle_readback_v2(
            &baseline.context,
            &baseline.workspace,
            &manifest_input,
        )
        .unwrap_err(),
        IdentityLifecycleStaleComponentV1::InstallManifest,
    );

    let mut profile_input = input(&baseline);
    profile_input.profile_digest = sha256("tampered-profile");
    assert_stale(
        verify_identity_lifecycle_readback_v2(
            &baseline.context,
            &baseline.workspace,
            &profile_input,
        )
        .unwrap_err(),
        IdentityLifecycleStaleComponentV1::Profile,
    );

    let mut provenance_input = input(&baseline);
    provenance_input.migration_provenance_ref.sha256 = sha256("tampered-provenance-ref");
    assert_stale(
        verify_identity_lifecycle_readback_v2(
            &baseline.context,
            &baseline.workspace,
            &provenance_input,
        )
        .unwrap_err(),
        IdentityLifecycleStaleComponentV1::MigrationProvenance,
    );

    fs::write(
        baseline.install.root.path().join("bin/gtkg"),
        b"tampered installed binary\n",
    )
    .unwrap();
    assert_stale(
        verify_identity_lifecycle_readback_v2(
            &baseline.context,
            &baseline.workspace,
            &input(&baseline),
        )
        .unwrap_err(),
        IdentityLifecycleStaleComponentV1::Binary,
    );

    fs::write(baseline.index_path(), b"tampered index manifest\n").unwrap();
    assert_stale(
        verify_identity_lifecycle_readback_v2(
            &baseline.context,
            &baseline.workspace,
            &input(&baseline),
        )
        .unwrap_err(),
        IdentityLifecycleStaleComponentV1::Index,
    );
}

#[cfg(not(unix))]
#[test]
fn i01_r2_requires_unix_descriptor_bound_install_readback() {
    assert!(true);
}

struct CurrentInstall {
    _parent: tempfile::TempDir,
    root: IsolatedInstallRootV1,
    manifest: InstallManifestV1,
    receipt: InstallReceiptV1,
    binary_sha256: String,
}

struct Baseline {
    _fixture: i00_fixture::Candidate,
    workspace: PathBuf,
    context: CallContext,
    migration_provenance_ref: FileReceiptRef,
    source_identity: String,
    bundle_identity: String,
    profile_id: String,
    profile_digest: String,
    index_manifest_ref: FileReceiptRef,
    install: CurrentInstall,
}

#[cfg(unix)]
fn baseline() -> Baseline {
    let fixture = i00_fixture::same_source_candidate();
    let workspace = fixture.workspace.path().to_path_buf();
    let write_context = workspace_context(&workspace);
    let migrated_bundle_ref = migrate_legacy(&workspace, &write_context);
    let attestation = publish_a06_source_bound_gate_attestation_v1(
        &write_context,
        &workspace,
        fixture.attestation_input(fixture.persist_gate(), fixture.persist_trusted_fixture()),
    )
    .unwrap();
    let provenance = bind_migration_rebuild_provenance_source_bound_v2(
        &write_context,
        &workspace,
        migrated_bundle_ref,
        fixture.bundle_ref.clone(),
        attestation.file_receipt_ref().unwrap(),
    )
    .unwrap();
    let migration_provenance_ref = provenance.file_receipt_ref().unwrap();
    let source_bound =
        read_source_bound_identity_v2(&write_context, &workspace, &migration_provenance_ref)
            .unwrap();
    let profile = discovery_profiles_v03()
        .into_iter()
        .find(|profile| profile.profile_id.as_str() == "core")
        .unwrap();
    let query_identity = QueryIndexEquivalenceIdentityV1::new(
        source_bound.source_identity.clone(),
        source_bound.adapter_replay_identity,
        profile.digest.clone(),
    )
    .unwrap();
    let query_expected = query_identity.file_query_expected_identities().unwrap();
    let index_manifest_ref = write_actual_query_index(&write_context, &workspace, &query_expected);
    let install = current_binary_install(&workspace);
    let context = CallContext::restricted(
        TransportKind::Test,
        vec![workspace.clone(), install.root.path().to_path_buf()],
        EffectPolicy::WorkspaceWrite,
    )
    .unwrap();
    Baseline {
        _fixture: fixture,
        workspace,
        context,
        migration_provenance_ref,
        source_identity: source_bound.source_identity,
        bundle_identity: source_bound.bundle_identity,
        profile_id: profile.profile_id.as_str().to_owned(),
        profile_digest: profile.digest,
        index_manifest_ref,
        install,
    }
}

#[cfg(unix)]
fn input(baseline: &Baseline) -> IdentityLifecycleReadbackInputV2<'_> {
    IdentityLifecycleReadbackInputV2 {
        migration_provenance_ref: baseline.migration_provenance_ref.clone(),
        profile_id: baseline.profile_id.clone(),
        profile_digest: baseline.profile_digest.clone(),
        index_root: baseline.workspace.join(".gtkg/i01-r2-query-index"),
        index_manifest_ref: baseline.index_manifest_ref.clone(),
        index_request: FileQueryRequestV1 {
            lookup: FileQueryLookupV1::Search {
                query: "i01".to_owned(),
            },
            max_results: 10,
            continuation: None,
        },
        isolated_install_root: &baseline.install.root,
        install_manifest: baseline.install.manifest.clone(),
        install_receipt: baseline.install.receipt.clone(),
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
            "i01-r2-lexical",
            &[LexicalDocumentV1 {
                node_id: "node-i01-r2".to_owned(),
                evidence_ref: "evidence:node-i01-r2".to_owned(),
                text: "I01 r2 actual secure query index".to_owned(),
            }],
        )
        .unwrap(),
    ];
    let adjacency = build_adjacency_routing_index_v1(
        &["node-i01-r2".to_owned(), "node-i01-r2-target".to_owned()],
        &[AdjacencyEdgeInputV1 {
            edge_id: "edge-i01-r2".to_owned(),
            source_node_id: "node-i01-r2".to_owned(),
            target_node_id: "node-i01-r2-target".to_owned(),
            resolution_state: QueryResolutionStateV1::Resolved,
            evidence_ref: "evidence:edge-i01-r2".to_owned(),
        }],
    )
    .unwrap();
    write_file_query_index_v1(
        context,
        &workspace.join(".gtkg/i01-r2-query-index"),
        expected,
        &lexical,
        &adjacency,
    )
    .unwrap()
}

#[cfg(unix)]
fn current_binary_install(workspace: &Path) -> CurrentInstall {
    let binary = PathBuf::from(required_env("I01_SOURCE_BINARY"));
    let expected_binary_sha256 = required_env("I01_SOURCE_BINARY_SHA256");
    let bytes = fs::read(&binary).unwrap();
    assert_eq!(sha256_bytes(&bytes), expected_binary_sha256);
    let package_root = workspace.join("i01-r2-package");
    fs::create_dir(&package_root).unwrap();
    fs::create_dir(package_root.join("bin")).unwrap();
    fs::copy(&binary, package_root.join("bin/gtkg")).unwrap();
    let manifest = InstallManifestV1 {
        schema_version: INSTALL_MANIFEST_SCHEMA_V1.to_owned(),
        version: "0.3.0-i01-r2-local".to_owned(),
        platform: format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
        files: vec!["bin/gtkg".to_owned()],
        modes: BTreeMap::from([("bin/gtkg".to_owned(), 0o755)]),
        digests: BTreeMap::from([("bin/gtkg".to_owned(), expected_binary_sha256.clone())]),
        destinations: BTreeMap::from([("bin/gtkg".to_owned(), "bin/gtkg".to_owned())]),
    };
    let parent = tempfile::Builder::new()
        .prefix("gtkg-i01-r2-install-")
        .tempdir_in(fixed_system_temp_root())
        .unwrap();
    let root = create_isolated_root_v1(parent.path()).unwrap();
    let preview = preview_install_with_capability_v1(&package_root, &root, &manifest).unwrap();
    let receipt = apply_install_with_capability_v1(&root, &preview).unwrap();
    assert!(receipt.readback_verified);
    assert_eq!(
        sha256_bytes(&fs::read(root.path().join("bin/gtkg")).unwrap()),
        expected_binary_sha256
    );
    CurrentInstall {
        _parent: parent,
        root,
        manifest,
        receipt,
        binary_sha256: expected_binary_sha256,
    }
}

#[cfg(unix)]
fn workspace_context(root: &Path) -> CallContext {
    CallContext::restricted(
        TransportKind::Test,
        vec![root.to_path_buf()],
        EffectPolicy::WorkspaceWrite,
    )
    .unwrap()
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
fn migrate_legacy(root: &Path, context: &CallContext) -> FileReceiptRef {
    let legacy = root.join("i01-r2-legacy");
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
                "i01-r2-migrate",
                json!({
                    "workspace_root": root,
                    "legacy_bundle_path": legacy,
                    "expected_legacy_tree_sha256": tree_sha256(&root.join("i01-r2-legacy")).unwrap(),
                    "migration_version": "i01-r2-migration"
                }),
            ),
        )
        .unwrap();
    serde_json::from_value(migrated.result["bundle_ref"].clone()).unwrap()
}

#[cfg(unix)]
impl Baseline {
    fn index_path(&self) -> PathBuf {
        self.workspace
            .join(".gtkg/i01-r2-query-index")
            .join(&self.index_manifest_ref.path)
    }
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

fn required_env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("I01 r2 requires {name}"))
}

fn sha256(value: &str) -> String {
    sha256_bytes(value.as_bytes())
}

fn sha256_bytes(value: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(value)))
}
