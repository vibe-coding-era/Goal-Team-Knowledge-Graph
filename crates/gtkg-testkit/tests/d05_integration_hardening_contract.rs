use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

use gtkg_core::file_model::{sha256_file, tree_sha256, write_index_tree};
use gtkg_core::{CallContext, Dispatcher, EffectPolicy, TransportKind};
use gtkg_protocol::{
    ErrorCode, FileReceiptRef, OperationId, OperationRequest, OperationResponse, OperationStatus,
    canonical_json_sha256,
};
use serde_json::{Value, json};
use tempfile::{TempDir, tempdir};

const CHILD_REQUEST_ENV: &str = "GTKG_D05_R5_CHILD_REQUEST";
const CHILD_ROOT_ENV: &str = "GTKG_D05_R5_CHILD_ROOT";
const FAULT_POINT_ENV: &str = "GTKG_TEST_FAULT_POINT";
const FAULT_READY_ENV: &str = "GTKG_TEST_FAULT_READY";
const PROJECTION_STAGING_FAULT: &str = "a2ui.generate.projection.after_staging_sync_before_publish";
const PUBLISHED_BEFORE_RECEIPT_FAULT: &str =
    "a2ui.generate.projection.after_publish_before_receipt";
const GENERATION_RECEIPT_FAULT: &str = "a2ui.generate.receipt.after_temp_sync_before_rename";

const MESSAGE_OPERATIONS: [&str; 4] = [
    "createSurface",
    "updateComponents",
    "updateDataModel",
    "deleteSurface",
];
const STREAM_SEGMENTS: [&str; 5] = ["manifest", "capability", "surface", "data", "action"];
const ENTITY_FIXTURES: [(&str, &str, &str, &str); 12] = [
    (
        "app",
        "src/App.tsx",
        "app-shell-alpha",
        "gtkg-code-static-ts/v1",
    ),
    (
        "route",
        "src/routes.ts",
        "route-docs-bravo",
        "gtkg-code-static-ts/v1",
    ),
    (
        "surface",
        "src/KnowledgeSurface.tsx",
        "surface-wiki-charlie",
        "gtkg-code-static-ts/v1",
    ),
    (
        "component",
        "src/KnowledgeCard.tsx",
        "component-card-delta",
        "gtkg-code-static-ts/v1",
    ),
    (
        "layout",
        "src/layout.css",
        "layout-split-echo",
        "gtkg-css-static/v1",
    ),
    (
        "style_token",
        "src/tokens.css",
        "style-accent-foxtrot",
        "gtkg-css-static/v1",
    ),
    (
        "asset",
        "src/logo.svg",
        "asset-logo-golf",
        "gtkg-svg-static/v1",
    ),
    (
        "interaction",
        "src/OpenButton.tsx",
        "interaction-open-hotel",
        "gtkg-code-static-ts/v1",
    ),
    (
        "data_binding",
        "src/TitleBinding.tsx",
        "binding-title-india",
        "gtkg-code-static-ts/v1",
    ),
    (
        "ui_state",
        "src/state.ts",
        "state-loading-juliet",
        "gtkg-code-static-ts/v1",
    ),
    (
        "accessibility",
        "src/AccessibleNavigation.tsx",
        "a11y-main-kilo",
        "gtkg-code-static-ts/v1",
    ),
    (
        "evidence_ref",
        "src/evidence.md",
        "evidence-source-lima",
        "gtkg-markdown/v1",
    ),
];

#[test]
fn a0_real_d03_bundle_is_the_only_public_generation_input_and_closes_canonical_artifacts() {
    let fixture = Fixture::new();
    let context = fixture.context();
    let resolution = fixture.resolve(&context, &fixture.a2ui_catalog);

    let generated = fixture.generate(
        &context,
        &resolution.result["resolution_ref"],
        "51.0.0",
        "r5-real-bundle",
    );
    assert_eq!(generated.status, OperationStatus::Completed);
    assert_eq!(
        generated.result["canonical_bundle_tree_sha256"],
        fixture.bundle_tree_sha256
    );
    assert_eq!(
        generated.result["canonical_bundle_path"],
        fixture.bundle.to_string_lossy().as_ref()
    );
    assert_eq!(generated.result["canonical_source"], "verified_d03_bundle");
    assert_eq!(generated.result["executed_target_content"], false);
    assert_receipt_ref(&fixture.workspace, &generated.result["generation_ref"]);

    let missing_external_tree_digest = execute_error(
        &context,
        OperationId::A2uiGenerate,
        "r5-missing-external-tree-digest",
        json!({
            "workspace_root": fixture.workspace,
            "bundle_path": fixture.bundle,
            "resolution_ref": resolution.result["resolution_ref"],
            "projection_version": "51.0.4"
        }),
    );
    assert!(matches!(
        missing_external_tree_digest,
        ErrorCode::InvalidRequest | ErrorCode::LockMismatch
    ));
    let manifest_digest_is_not_a_tree_lock = execute_error(
        &context,
        OperationId::A2uiGenerate,
        "r5-manifest-digest-is-not-tree-lock",
        json!({
            "workspace_root": fixture.workspace,
            "bundle_path": fixture.bundle,
            "expected_bundle_manifest_sha256": sha256_file(&fixture.bundle.join("artifact-manifest.json")).unwrap(),
            "resolution_ref": resolution.result["resolution_ref"],
            "projection_version": "51.0.5"
        }),
    );
    assert_eq!(
        manifest_digest_is_not_a_tree_lock,
        ErrorCode::InvalidRequest
    );

    let manifest = read_json(&fixture.bundle.join("artifact-manifest.json"));
    assert_eq!(manifest["schema_version"], "gtkg.artifact-manifest/v1");
    assert_eq!(
        manifest["source_lock"]["schema_version"],
        "gtkg.source-lock/v1"
    );
    assert_eq!(
        manifest["source_lock"]["repositories"][0]["repo_id"],
        "frontend"
    );
    let source_entries = manifest["source_lock"]["entries"].as_array().unwrap();
    assert_eq!(source_entries.len(), ENTITY_FIXTURES.len());
    let source_paths = source_entries
        .iter()
        .map(|entry| entry["logical_path"].as_str().unwrap())
        .collect::<BTreeSet<_>>();
    assert!(source_paths.contains("src/layout.css"));
    assert!(source_paths.contains("src/tokens.css"));
    assert!(source_paths.contains("src/logo.svg"));
    assert_eq!(manifest["knowledge"].as_array().unwrap().len(), 12);
    assert!(fixture.bundle.join("locks/source-lock.json").is_file());
    assert!(fixture.bundle.join("index.md").is_file());
    for entry in manifest["knowledge"].as_array().unwrap() {
        let knowledge = fixture.bundle.join(entry["path"].as_str().unwrap());
        let text = fs::read_to_string(knowledge).expect("OKF knowledge document");
        assert!(text.starts_with("---\n"));
        assert!(text.contains("okf_version: '0.2'") || text.contains("okf_version: 0.2"));
        let logical_path = entry["source_key"]["logical_path"].as_str().unwrap();
        let marker = ENTITY_FIXTURES
            .iter()
            .find(|(_, path, _, _)| *path == logical_path)
            .and_then(|(kind, _, _, _)| fixture.entity_markers.get(*kind))
            .expect("knowledge SourceKey maps to a dynamic frontend marker");
        let analysis_receipt = fs::read_to_string(
            fixture
                .bundle
                .join(entry["summary_receipt_path"].as_str().unwrap()),
        )
        .unwrap();
        assert!(analysis_receipt.contains(marker));
    }

    let legacy = execute_error(
        &context,
        OperationId::A2uiGenerate,
        "r5-legacy-canonical-root",
        json!({
            "workspace_root": fixture.workspace,
            "frontend_root": fixture.repository,
            "canonical_root": fixture.bundle,
            "expected_canonical_tree_sha256": fixture.bundle_tree_sha256,
            "resolution_ref": resolution.result["resolution_ref"],
            "projection_version": "51.0.1",
            "selected_resource_id": "caller-invented",
            "expected_resource_count": 12
        }),
    );
    assert_eq!(legacy, ErrorCode::InvalidRequest);

    let caller_selected_identity = execute_error(
        &context,
        OperationId::A2uiGenerate,
        "r5-caller-source-identity",
        json!({
            "workspace_root": fixture.workspace,
            "bundle_path": fixture.bundle,
            "expected_bundle_tree_sha256": fixture.bundle_tree_sha256,
            "source_inspection_ref": fixture.source_inspection_ref,
            "frontend_repo_id": "frontend",
            "resolution_ref": resolution.result["resolution_ref"],
            "projection_version": "51.0.2"
        }),
    );
    assert_eq!(caller_selected_identity, ErrorCode::InvalidRequest);

    for mutation in [
        BundleMutation::MissingArtifactManifest,
        BundleMutation::MissingSourceLock,
        BundleMutation::MissingOkfKnowledge,
        BundleMutation::MissingRootIndex,
        BundleMutation::ForgedSourceLock,
        BundleMutation::ForgedArtifactManifest,
        BundleMutation::ForgedOkfKnowledge,
        BundleMutation::ForgedRootIndex,
    ] {
        let (copy, observed_tree) = fixture.mutated_bundle(mutation);
        let error = execute_error(
            &context,
            OperationId::A2uiGenerate,
            &format!("r5-invalid-bundle-{mutation:?}"),
            json!({
                "workspace_root": fixture.workspace,
                "bundle_path": copy,
                "expected_bundle_tree_sha256": observed_tree,
                "resolution_ref": resolution.result["resolution_ref"],
                "projection_version": format!("51.1.{}", mutation as u8)
            }),
        );
        assert!(
            matches!(
                error,
                ErrorCode::BundleInvalid | ErrorCode::LockMismatch | ErrorCode::InvalidRequest
            ),
            "{mutation:?} must fail closed, observed {error:?}"
        );
    }
}

#[test]
fn a1_frontend_ir_is_marker_derived_from_bundle_evidence_and_a2ui_lines_close_to_ir() {
    let fixture = Fixture::new();
    let context = fixture.context();
    let resolution = fixture.resolve(&context, &fixture.a2ui_catalog);
    let generated = fixture.generate(
        &context,
        &resolution.result["resolution_ref"],
        "52.0.0",
        "r5-semantic-ir",
    );
    let projection = result_path(&generated, "projection_path");
    let ir = read_json(&projection.join("frontend/semantic-ir.json"));
    assert_eq!(ir["schema_version"], "gtkg.frontend-semantic-ir/v2");
    assert_eq!(
        ir["canonical_bundle_tree_sha256"],
        fixture.bundle_tree_sha256
    );
    assert_eq!(ir["executed_target_content"], false);
    assert_eq!(ir["runtime_verified_count"], 0);
    assert_eq!(ir["target_process_count"], 0);
    assert!(ir["source_lock_sha256"].as_str().is_some());

    let entities = ir["entities"].as_array().expect("semantic entities");
    assert_eq!(entities.len(), ENTITY_FIXTURES.len());
    let observed_kinds = entities
        .iter()
        .map(|entity| entity["kind"].as_str().unwrap())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        observed_kinds,
        ENTITY_FIXTURES
            .iter()
            .map(|(kind, _, _, _)| *kind)
            .collect::<BTreeSet<_>>()
    );

    let mut entity_ids = BTreeSet::new();
    for (kind, logical_path, _, extractor_id) in ENTITY_FIXTURES {
        let marker = fixture.entity_markers.get(kind).expect("dynamic marker");
        let entity = entities
            .iter()
            .find(|entity| entity["kind"] == kind)
            .unwrap_or_else(|| panic!("missing semantic entity {kind}"));
        let expected_id = format!("{kind}:{marker}");
        assert_eq!(entity["id"], expected_id);
        assert_ne!(entity["id"], format!("{kind}:root"));
        assert!(entity_ids.insert(entity["id"].as_str().unwrap()));
        assert!(
            ["observed_static", "resolved_static", "inferred"]
                .contains(&entity["evidence_level"].as_str().unwrap())
        );
        let refs = entity["evidence_refs"].as_array().expect("evidence refs");
        assert_eq!(refs.len(), 1);
        let evidence = &refs[0];
        assert_eq!(evidence["source_key"]["repo_id"], "frontend");
        assert_eq!(evidence["source_key"]["logical_path"], logical_path);
        assert_eq!(
            evidence["source_sha256"],
            sha256_file(&fixture.repository.join(logical_path)).unwrap()
        );
        assert_eq!(evidence["extractor_id"], extractor_id);
        let source = fs::read(fixture.repository.join(logical_path)).unwrap();
        let start = evidence["span"]["start"].as_u64().unwrap() as usize;
        let end = evidence["span"]["end"].as_u64().unwrap() as usize;
        assert!(start < end && end <= source.len());
        assert_eq!(&source[start..end], marker.as_bytes());
        assert_eq!(evidence["evidence_source"], "accepted_analysis_receipt");
    }

    let stream_path = projection.join("a2ui/stream.jsonl");
    let stream_manifest = read_json(&projection.join("a2ui/stream-manifest.json"));
    assert_eq!(
        stream_manifest["schema_version"],
        "gtkg.a2ui-stream-manifest/v2"
    );
    assert_eq!(stream_manifest["mime_type"], "application/a2ui+json");
    assert_eq!(stream_manifest["wire_version"], "v0.9");
    assert_eq!(stream_manifest["load_sequence"], json!(STREAM_SEGMENTS));
    assert_eq!(
        stream_manifest["stream_sha256"],
        sha256_file(&stream_path).unwrap()
    );
    let segments = stream_manifest["segments"].as_array().unwrap();
    assert_eq!(segments.len(), STREAM_SEGMENTS.len());
    assert_eq!(
        segments
            .iter()
            .map(|segment| segment["kind"].as_str().unwrap())
            .collect::<Vec<_>>(),
        STREAM_SEGMENTS
    );
    let mut referenced_entities = BTreeSet::new();
    for segment in segments {
        for entity in segment["entity_ids"].as_array().unwrap() {
            let id = entity.as_str().unwrap();
            assert!(
                entity_ids.contains(id),
                "stream manifest referenced unknown IR id {id}"
            );
            referenced_entities.insert(id.to_owned());
        }
    }

    let stream_bytes = fs::read_to_string(&stream_path).unwrap();
    assert!(!stream_bytes.contains("gtkgSegment"));
    assert!(!stream_bytes.contains("gtkgEntityRefs"));
    let lines = stream_bytes
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("A2UI JSON line"))
        .collect::<Vec<_>>();
    assert_eq!(lines.len(), 3);
    let mut observed_operations = Vec::new();
    for line in &lines {
        assert_eq!(line["version"], "v0.9");
        assert_eq!(line.as_object().unwrap().len(), 2);
        let present = MESSAGE_OPERATIONS
            .iter()
            .filter(|operation| line.get(**operation).is_some())
            .copied()
            .collect::<Vec<_>>();
        assert_eq!(present.len(), 1, "each v0.9 line has one message kind");
        observed_operations.push(present[0]);
    }
    assert_eq!(
        observed_operations,
        vec!["createSurface", "updateComponents", "updateDataModel"]
    );

    let components = lines[1]["updateComponents"]["components"]
        .as_array()
        .unwrap();
    assert_eq!(
        components
            .iter()
            .map(|component| component["component"].as_str().unwrap())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["Button", "Column", "List", "Row", "Text"])
    );
    // H04: components are official basic-catalog closed objects; Semantic IR
    // provenance is carried by the stream manifest segments and the
    // mapping/action-binding receipts, not by component properties.
    for component in components {
        assert!(
            component.get("sourceEntityId").is_none(),
            "official basic-catalog components must not carry sourceEntityId"
        );
    }
    // H04/H05: the selected knowledge document is directly renderable data,
    // delivered through updateDataModel with the exact index.
    let data_model = &lines[2]["updateDataModel"]["value"];
    let document = &data_model["document"];
    assert!(!document["id"].as_str().unwrap().is_empty());
    assert!(!document["path"].as_str().unwrap().is_empty());
    assert!(!document["title"].as_str().unwrap().is_empty());
    assert!(!document["body"].as_str().unwrap().is_empty());
    assert!(!document["provenance_text"].as_str().unwrap().is_empty());
    assert!(document["provenance"]["sources"].is_array());
    assert_eq!(
        data_model["index"].as_array().unwrap().len(),
        ENTITY_FIXTURES.len()
    );

    let action_binding = read_json(&projection.join("a2ui/action-binding-receipt.json"));
    assert_eq!(
        action_binding["schema_version"],
        "gtkg.a2ui-action-binding/v2"
    );
    assert_eq!(action_binding["event"], "gtkg.select_document");
    assert_eq!(action_binding["context"]["documentId"]["path"], "id");
    assert_eq!(action_binding["context"]["documentPath"]["path"], "path");
    for field in ["interaction_entity_id", "route_entity_id"] {
        let id = action_binding[field].as_str().unwrap();
        assert!(entity_ids.contains(id));
        referenced_entities.insert(id.to_owned());
    }
    for required_kind in [
        "surface",
        "component",
        "data_binding",
        "interaction",
        "route",
    ] {
        let id = entities
            .iter()
            .find(|entity| entity["kind"] == required_kind)
            .unwrap()["id"]
            .as_str()
            .unwrap();
        assert!(referenced_entities.contains(id));
    }
    let mapping = read_json(&projection.join("a2ui/mapping-receipt.json"));
    let states = mapping["mappings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["state"].as_str().unwrap())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        states,
        BTreeSet::from(["exact", "approximation", "unsupported"])
    );
    for entry in mapping["mappings"].as_array().unwrap() {
        assert!(entity_ids.contains(entry["entity_id"].as_str().unwrap()));
    }
}

#[test]
fn a2_catalog_schema_renderer_and_action_allowlist_are_validated_as_an_exact_local_closure() {
    let fixture = Fixture::new();
    let context = fixture.context();
    let resolution = fixture.resolve(&context, &fixture.a2ui_catalog);
    let lock = &resolution.result["a2ui_lock"];
    assert_eq!(lock["spec_version"], "0.9.1");
    assert_eq!(lock["profile_version"], "0.9.1");
    assert_eq!(lock["catalog_version"], "0.9.1");
    assert_eq!(lock["common_types_version"], "0.9.1");
    assert_eq!(lock["renderer_version"], "test-only");
    // H04: the lock binds the vendored official Google A2UI v0.9.1 profile,
    // common types, and basic catalog; only the renderer descriptor and the
    // manifest anchor stay local.
    let vendor = vendor_dir();
    assert_eq!(lock["profile_id"], OFFICIAL_SERVER_SCHEMA_ID);
    assert_eq!(lock["common_types_id"], OFFICIAL_COMMON_TYPES_ID);
    assert_eq!(lock["catalog_id"], OFFICIAL_BASIC_CATALOG_ID);
    assert_eq!(
        lock["profile_sha256"],
        sha256_file(&vendor.join("server_to_client.json")).unwrap()
    );
    assert_eq!(
        lock["schema_sha256"],
        sha256_file(&vendor.join("server_to_client.json")).unwrap()
    );
    assert_eq!(
        lock["common_types_sha256"],
        sha256_file(&vendor.join("common_types.json")).unwrap()
    );
    assert_eq!(
        lock["catalog_sha256"],
        sha256_file(&vendor.join("catalog.json")).unwrap()
    );
    assert_eq!(
        lock["renderer_sha256"],
        sha256_file(&fixture.a2ui_catalog.join("renderer.json")).unwrap()
    );
    assert_eq!(
        resolution.result["closure"]["components"],
        official_components()
    );
    assert_eq!(
        resolution.result["closure"]["renderer_supported_components"],
        json!(["Button", "Column", "List", "Row", "Text"])
    );
    assert_eq!(resolution.result["closure"]["wire_version"], "v0.9");
    assert_eq!(resolution.result["catalog_scope"], "official_basic_catalog");
    let renderer = read_json(&fixture.a2ui_catalog.join("renderer.json"));
    assert_eq!(renderer["status"], "local_deterministic_renderer");
    assert_eq!(
        renderer["supported_components"],
        json!(["Button", "Column", "List", "Row", "Text"])
    );
    assert_eq!(
        renderer["supported_actions"],
        json!(["gtkg.select_document"])
    );

    let generated = fixture.generate(
        &context,
        &resolution.result["resolution_ref"],
        "53.0.0",
        "r5-catalog-positive",
    );
    let validation = execute_ok(
        &context,
        OperationId::A2uiValidate,
        "r5-catalog-validate",
        json!({
            "workspace_root": fixture.workspace,
            "generation_ref": generated.result["generation_ref"],
            "expected_projection_tree_sha256": generated.result["projection_tree_sha256"],
            "required_evidence_state": "a2ui_generatable"
        }),
    );
    assert_eq!(validation.result["valid"], true);
    assert_eq!(
        validation.result["checks"],
        json!({
            "action_resource_allowlist": "passed",
            "catalog_component_closure": "passed",
            "common_types_closure": "passed",
            "frontend_ir_reference_closure": "passed",
            "projection_full_tree_digest": "passed",
            "renderer_component_closure": "passed",
            "renderer_smoke": "not_run",
            "screenshot_artifacts": "not_run",
            "schema_nested_validation": "passed",
            "stream_manifest_sequence": "passed",
            "visual_threshold": "not_run"
        })
    );
    assert_receipt_ref(&fixture.workspace, &validation.result["validation_ref"]);

    // H04: the protocol schema/common-types/catalog are vendored official
    // assets (digest-locked by the h04 contract), so the local catalog root is
    // an integrity-anchored descriptor of the local deterministic renderer.
    // Fail-closed coverage migrates accordingly: any unpinned file drift or
    // identity/manifest drift fails resolve, and a renderer capability gap
    // fails generation.
    for mutation in [
        CatalogMutation::SchemaDigestDrift,
        CatalogMutation::MissingButton,
        CatalogMutation::ManifestProfileIdentityDrift,
        CatalogMutation::RendererIdentityDrift,
        CatalogMutation::MissingCommonTypes,
        CatalogMutation::CommonTypesDigestDrift,
        CatalogMutation::ProfileDigestDrift,
        CatalogMutation::RendererMissingButton,
    ] {
        let catalog = fixture.mutated_catalog(mutation);
        let resolved = fixture.resolve_result(&context, &catalog);
        match mutation {
            CatalogMutation::SchemaDigestDrift
            | CatalogMutation::ManifestProfileIdentityDrift
            | CatalogMutation::RendererIdentityDrift
            | CatalogMutation::MissingCommonTypes
            | CatalogMutation::CommonTypesDigestDrift
            | CatalogMutation::ProfileDigestDrift => {
                assert!(resolved.is_err(), "{mutation:?} must fail during resolve");
            }
            CatalogMutation::MissingButton | CatalogMutation::RendererMissingButton => {
                let resolved = resolved.expect("renderer capability gap still resolves");
                let error = fixture.generate_error(
                    &context,
                    &resolved.result["resolution_ref"],
                    &format!("53.1.{}", mutation as u8),
                    &format!("r5-catalog-negative-{mutation:?}"),
                );
                assert!(matches!(
                    error,
                    ErrorCode::InvalidRequest
                        | ErrorCode::LockMismatch
                        | ErrorCode::BundleInvalid
                        | ErrorCode::InvalidState
                ));
            }
        }
    }
}

#[cfg(unix)]
#[test]
fn a3_receipt_namespace_path_symlink_and_hardlink_inputs_fail_closed() {
    let fixture = Fixture::new();
    let context = fixture.context();
    let resolution = fixture.resolve(&context, &fixture.a2ui_catalog);

    let wrong_namespace = execute_error(
        &context,
        OperationId::A2uiGenerate,
        "r5-wrong-resolution-namespace",
        json!({
            "workspace_root": fixture.workspace,
            "bundle_path": fixture.bundle,
            "expected_bundle_tree_sha256": fixture.bundle_tree_sha256,
            "resolution_ref": fixture.source_inspection_ref,
            "projection_version": "54.0.0"
        }),
    );
    assert!(matches!(
        wrong_namespace,
        ErrorCode::InvalidRequest | ErrorCode::LockMismatch | ErrorCode::PathEscape
    ));

    let resolution_ref = parse_receipt_ref(&resolution.result["resolution_ref"]);
    let resolution_path = fixture.workspace.join(&resolution_ref.path);
    let symlink_dir = fixture
        .workspace
        .join(".gtkg/a2ui/resolutions/evil-symlink");
    fs::create_dir_all(&symlink_dir).unwrap();
    let symlink_path = symlink_dir.join("resolution-receipt.json");
    std::os::unix::fs::symlink(&resolution_path, &symlink_path).unwrap();
    let symlink_error = fixture.generate_error_with_ref(
        &context,
        json!({"path": receipt_relative(&fixture.workspace, &symlink_path), "sha256": resolution_ref.sha256}),
        "54.0.1",
        "r5-resolution-symlink",
    );
    assert!(matches!(
        symlink_error,
        ErrorCode::SymlinkRejected | ErrorCode::PathEscape | ErrorCode::LockMismatch
    ));

    let hardlink_path = resolution_path.with_file_name("resolution-hardlink.json");
    fs::hard_link(&resolution_path, &hardlink_path).unwrap();
    let hardlink_error = fixture.generate_error_with_ref(
        &context,
        json!({"path": receipt_relative(&fixture.workspace, &resolution_path), "sha256": resolution_ref.sha256}),
        "54.0.2",
        "r5-resolution-hardlink",
    );
    assert!(matches!(
        hardlink_error,
        ErrorCode::SymlinkRejected | ErrorCode::LockMismatch | ErrorCode::BundleInvalid
    ));
    fs::remove_file(hardlink_path).unwrap();

    let generated = fixture.generate(
        &context,
        &resolution.result["resolution_ref"],
        "54.0.3",
        "r5-receipt-positive",
    );
    let get_wrong_namespace = execute_error(
        &context,
        OperationId::A2uiGet,
        "r5-generation-wrong-namespace",
        json!({
            "workspace_root": fixture.workspace,
            "generation_ref": resolution.result["resolution_ref"],
            "expected_projection_tree_sha256": generated.result["projection_tree_sha256"]
        }),
    );
    assert!(matches!(
        get_wrong_namespace,
        ErrorCode::InvalidRequest | ErrorCode::LockMismatch | ErrorCode::PathEscape
    ));
}

#[test]
fn child_executes_d05_generation_fault_request() {
    let Some(request_path) = std::env::var_os(CHILD_REQUEST_ENV) else {
        return;
    };
    let root = PathBuf::from(std::env::var_os(CHILD_ROOT_ENV).expect("child root"));
    let request: OperationRequest =
        serde_json::from_slice(&fs::read(PathBuf::from(request_path)).expect("child request"))
            .expect("request JSON");
    let context = CallContext::restricted(
        TransportKind::Test,
        vec![root],
        EffectPolicy::WorkspaceWrite,
    )
    .expect("child context");
    Dispatcher
        .execute(&context, request)
        .expect("child must reach the requested D05 fault point");
}

#[cfg(unix)]
#[test]
fn z9_projection_staging_publish_and_receipt_sigkill_replay_are_full_digest_safe() {
    let fixture = Fixture::new();
    let context = fixture.context();
    let resolution = fixture.resolve(&context, &fixture.a2ui_catalog);

    for (index, fault_point) in [
        PROJECTION_STAGING_FAULT,
        PUBLISHED_BEFORE_RECEIPT_FAULT,
        GENERATION_RECEIPT_FAULT,
    ]
    .into_iter()
    .enumerate()
    {
        let version = format!("55.0.{index}");
        let request_id = format!("r5-crash-{index}");
        let request =
            fixture.generate_request(&resolution.result["resolution_ref"], &version, &request_id);
        let request_path = fixture.root.join(format!("request-{index}.json"));
        fs::write(&request_path, serde_json::to_vec_pretty(&request).unwrap()).unwrap();
        let ready = fixture.root.join(format!("fault-ready-{index}"));
        let quarantine_before = count_files(&fixture.workspace.join(".gtkg/quarantine"));
        let generation_receipts_before =
            count_files(&fixture.workspace.join(".gtkg/a2ui/generations"));
        let mut child = spawn_fault_child(&fixture.root, &request_path, &ready, fault_point);
        wait_for_fault(&mut child, &ready, fault_point);
        child.kill().expect("SIGKILL fault child");
        assert!(!child.wait().expect("reap fault child").success());

        if fault_point == PUBLISHED_BEFORE_RECEIPT_FAULT {
            assert_eq!(count_version_directories(&fixture.workspace, &version), 1);
            assert_eq!(
                count_files(&fixture.workspace.join(".gtkg/a2ui/generations")),
                generation_receipts_before
            );
        }

        let replayed = Dispatcher
            .execute(&context, request.clone())
            .unwrap_or_else(|error| panic!("exact replay failed at {fault_point}: {error:#?}"));
        assert_eq!(replayed.result["idempotent_replay"], true);
        let projection = result_path(&replayed, "projection_path");
        let expected = replayed.result["projection_tree_sha256"].as_str().unwrap();
        assert_eq!(tree_sha256(&projection).unwrap(), expected);
        assert_receipt_ref(&fixture.workspace, &replayed.result["generation_ref"]);
        assert_eq!(count_version_directories(&fixture.workspace, &version), 1);
        assert_eq!(
            count_files(&fixture.workspace.join(".gtkg/a2ui/generations")),
            generation_receipts_before + 1
        );
        assert_eq!(
            count_files(&fixture.workspace.join(".gtkg/a2ui/projections/staging")),
            0
        );
        if fault_point == PROJECTION_STAGING_FAULT {
            assert!(
                count_files(&fixture.workspace.join(".gtkg/quarantine")) > quarantine_before,
                "synced staging residue must be quarantined before replay"
            );
        }

        let second = Dispatcher
            .execute(&context, request)
            .expect("stable exact replay");
        assert_eq!(second.result, replayed.result);
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
enum BundleMutation {
    MissingArtifactManifest = 0,
    MissingSourceLock = 1,
    MissingOkfKnowledge = 2,
    MissingRootIndex = 3,
    ForgedSourceLock = 4,
    ForgedArtifactManifest = 5,
    ForgedOkfKnowledge = 6,
    ForgedRootIndex = 7,
}

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
enum CatalogMutation {
    SchemaDigestDrift = 0,
    MissingButton = 1,
    ManifestProfileIdentityDrift = 2,
    RendererIdentityDrift = 3,
    MissingCommonTypes = 4,
    CommonTypesDigestDrift = 5,
    ProfileDigestDrift = 6,
    RendererMissingButton = 7,
}

struct Fixture {
    _temp: TempDir,
    root: PathBuf,
    workspace: PathBuf,
    repository: PathBuf,
    a2ui_catalog: PathBuf,
    bundle: PathBuf,
    bundle_tree_sha256: String,
    source_inspection_ref: Value,
    entity_markers: BTreeMap<String, String>,
}

impl Fixture {
    fn new() -> Self {
        let temp = tempdir().expect("tempdir");
        let root = temp.path().to_path_buf();
        let workspace = root.join("workspace");
        let repository = root.join("frontend-repository");
        let template_catalog = root.join("template-catalog");
        let a2ui_catalog = root.join("a2ui-catalog");
        fs::create_dir_all(&workspace).unwrap();
        fs::create_dir_all(repository.join("src")).unwrap();
        let fixture_identity = canonical_json_sha256(&root.to_string_lossy().to_string()).unwrap();
        let fixture_nonce = &fixture_identity[7..15];
        let mut entity_markers = BTreeMap::new();
        for (kind, logical_path, marker_base, _) in ENTITY_FIXTURES {
            let marker = format!("{marker_base}-{fixture_nonce}");
            let source = frontend_fixture_source(kind, &marker);
            fs::write(repository.join(logical_path), source).unwrap();
            entity_markers.insert(kind.to_owned(), marker);
        }
        init_and_commit(&repository);
        create_template_catalog(&template_catalog);
        create_a2ui_catalog(&a2ui_catalog);
        let context = CallContext::restricted(
            TransportKind::Test,
            vec![root.clone()],
            EffectPolicy::WorkspaceWrite,
        )
        .unwrap();

        let inspected = execute_ok(
            &context,
            OperationId::SourceInspect,
            "r5-source-inspect",
            json!({
                "workspace_root": workspace,
                "repositories": [{
                    "repo_id": "frontend",
                    "path": repository,
                    "role": "frontend",
                    "include": []
                }]
            }),
        );
        let source_inspection_ref = inspected.result["inspection_ref"].clone();
        let resolved = execute_ok(
            &context,
            OperationId::TemplateResolve,
            "r5-template-resolve",
            json!({
                "workspace_root": workspace,
                "catalog_root": template_catalog,
                "template_id": "summary-template",
                "version": "0.1.0"
            }),
        );
        let validated = execute_ok(
            &context,
            OperationId::TemplateValidate,
            "r5-template-validate",
            json!({
                "workspace_root": workspace,
                "resolution_ref": resolved.result["resolution_ref"]
            }),
        );
        let template_ref = validated.result["validation_ref"].clone();
        let mut plan_request = OperationRequest::new(
            OperationId::BuildPlan,
            "r5-build-plan",
            json!({
                "workspace_root": workspace,
                "mode": "full",
                "source_inspection_ref": source_inspection_ref,
                "template_validation_ref": template_ref,
                "baseline_bundle": null,
                "bundle_version": "50.0.0"
            }),
        );
        plan_request.locks = BTreeMap::from([
            (
                "source_inspection".to_owned(),
                source_inspection_ref["sha256"].as_str().unwrap().to_owned(),
            ),
            (
                "template_validation".to_owned(),
                template_ref["sha256"].as_str().unwrap().to_owned(),
            ),
        ]);
        let planned = Dispatcher
            .execute(&context, plan_request)
            .expect("build.plan");
        let run_id = planned.run_id.expect("run id");
        execute_ok_run(
            &context,
            OperationId::BuildPrepare,
            &run_id,
            "r5-build-prepare",
            json!({"workspace_root": workspace}),
        );
        loop {
            let next = execute_ok_run(
                &context,
                OperationId::SummaryNext,
                &run_id,
                "r5-summary-next",
                json!({"workspace_root": workspace}),
            );
            let Some(job) = next.result.get("job").filter(|value| !value.is_null()) else {
                break;
            };
            execute_ok_run(
                &context,
                OperationId::SummaryAccept,
                &run_id,
                &format!("r5-summary-{}", job["packet_id"].as_str().unwrap()),
                json!({
                    "workspace_root": workspace,
                    "packet_id": job["packet_id"],
                    "source_sha256": job["source_sha256"],
                    "template_manifest_sha256": job["template_manifest_sha256"],
                    "summary_markdown": format!(
                        "# Static frontend analysis\n\nrepo_id: {}\nlogical_path: {}\nextractor: gtkg-code-static-ts/v1\n\n```typescript\n{}\n```",
                        job["repo_id"].as_str().unwrap(),
                        job["source_path"].as_str().unwrap(),
                        job["analysis_text"].as_str().unwrap()
                    )
                }),
            );
        }
        let finalized = execute_ok_run(
            &context,
            OperationId::BuildFinalize,
            &run_id,
            "r5-build-finalize",
            json!({"workspace_root": workspace}),
        );
        let bundle = result_path(&finalized, "bundle_path");
        let bundle_tree_sha256 = finalized.result["tree_digest"].as_str().unwrap().to_owned();
        assert_eq!(tree_sha256(&bundle).unwrap(), bundle_tree_sha256);
        Self {
            _temp: temp,
            root,
            workspace,
            repository,
            a2ui_catalog,
            bundle,
            bundle_tree_sha256,
            source_inspection_ref,
            entity_markers,
        }
    }

    fn context(&self) -> CallContext {
        CallContext::restricted(
            TransportKind::Test,
            vec![self.root.clone()],
            EffectPolicy::WorkspaceWrite,
        )
        .unwrap()
    }

    fn resolve(&self, context: &CallContext, catalog: &Path) -> OperationResponse {
        self.resolve_result(context, catalog)
            .unwrap_or_else(|error| panic!("a2ui.resolve failed: {error:#?}"))
    }

    fn resolve_result(
        &self,
        context: &CallContext,
        catalog: &Path,
    ) -> Result<OperationResponse, gtkg_protocol::ErrorEnvelope> {
        let manifest_sha256 = sha256_file(&catalog.join("manifest.json")).unwrap();
        Dispatcher.execute(
            context,
            OperationRequest::new(
                OperationId::A2uiResolve,
                format!("r5-resolve-{}", &manifest_sha256[7..19]),
                json!({
                    "workspace_root": self.workspace,
                    "catalog_root": catalog,
                    "spec_version": "0.9.1",
                    "profile_id": "gtkg-test-profile",
                    "profile_version": "0.9.1",
                    "catalog_id": "gtkg-test-catalog",
                    "catalog_version": "0.1.0",
                    "renderer_id": "gtkg-test-renderer",
                    "renderer_version": "test-only",
                    "expected_manifest_sha256": manifest_sha256
                }),
            ),
        )
    }

    fn generate(
        &self,
        context: &CallContext,
        resolution_ref: &Value,
        version: &str,
        request_id: &str,
    ) -> OperationResponse {
        Dispatcher
            .execute(
                context,
                self.generate_request(resolution_ref, version, request_id),
            )
            .unwrap_or_else(|error| panic!("a2ui.generate failed: {error:#?}"))
    }

    fn generate_error(
        &self,
        context: &CallContext,
        resolution_ref: &Value,
        version: &str,
        request_id: &str,
    ) -> ErrorCode {
        Dispatcher
            .execute(
                context,
                self.generate_request(resolution_ref, version, request_id),
            )
            .expect_err("generation must fail closed")
            .error
            .code
    }

    fn generate_error_with_ref(
        &self,
        context: &CallContext,
        resolution_ref: Value,
        version: &str,
        request_id: &str,
    ) -> ErrorCode {
        self.generate_error(context, &resolution_ref, version, request_id)
    }

    fn generate_request(
        &self,
        resolution_ref: &Value,
        version: &str,
        request_id: &str,
    ) -> OperationRequest {
        OperationRequest::new(
            OperationId::A2uiGenerate,
            request_id,
            json!({
                "workspace_root": self.workspace,
                "bundle_path": self.bundle,
                "expected_bundle_tree_sha256": self.bundle_tree_sha256,
                "resolution_ref": resolution_ref,
                "projection_version": version
            }),
        )
    }

    fn mutated_bundle(&self, mutation: BundleMutation) -> (PathBuf, String) {
        let copy = self
            .root
            .join(format!("bundle-mutation-{}", mutation as u8));
        copy_tree(&self.bundle, &copy);
        match mutation {
            BundleMutation::MissingArtifactManifest => {
                fs::remove_file(copy.join("artifact-manifest.json")).unwrap();
            }
            BundleMutation::MissingSourceLock => {
                fs::remove_file(copy.join("locks/source-lock.json")).unwrap();
            }
            BundleMutation::MissingOkfKnowledge => {
                let manifest = read_json(&copy.join("artifact-manifest.json"));
                fs::remove_file(copy.join(manifest["knowledge"][0]["path"].as_str().unwrap()))
                    .unwrap();
            }
            BundleMutation::MissingRootIndex => {
                fs::remove_file(copy.join("index.md")).unwrap();
            }
            BundleMutation::ForgedSourceLock => {
                let path = copy.join("locks/source-lock.json");
                let mut lock = read_json(&path);
                lock["entries"][0]["content_sha256"] = Value::String(digest('f'));
                fs::write(&path, serde_json::to_vec_pretty(&lock).unwrap()).unwrap();
                let mut manifest = read_json(&copy.join("artifact-manifest.json"));
                manifest["source_lock"] = lock;
                manifest["sources"][0]["source_sha256"] = Value::String(digest('f'));
                fs::write(
                    copy.join("artifact-manifest.json"),
                    serde_json::to_vec_pretty(&manifest).unwrap(),
                )
                .unwrap();
                rewrite_bundle_closure(&copy);
            }
            BundleMutation::ForgedArtifactManifest => {
                let path = copy.join("artifact-manifest.json");
                let mut manifest = read_json(&path);
                manifest["semantic_digest"] = Value::String(digest('e'));
                fs::write(path, serde_json::to_vec_pretty(&manifest).unwrap()).unwrap();
                rewrite_bundle_closure(&copy);
            }
            BundleMutation::ForgedOkfKnowledge => {
                let manifest_path = copy.join("artifact-manifest.json");
                let mut manifest = read_json(&manifest_path);
                let relative = manifest["knowledge"][0]["path"]
                    .as_str()
                    .unwrap()
                    .to_owned();
                let knowledge_path = copy.join(&relative);
                let mut knowledge = fs::read_to_string(&knowledge_path).unwrap();
                knowledge.push_str("\nforged semantic content\n");
                fs::write(&knowledge_path, knowledge).unwrap();
                let forged_sha256 = sha256_file(&knowledge_path).unwrap();
                manifest["knowledge"][0]["sha256"] = Value::String(forged_sha256.clone());
                let canonical = manifest["canonical_documents"]
                    .as_array_mut()
                    .unwrap()
                    .iter_mut()
                    .find(|entry| entry["path"] == relative)
                    .unwrap();
                canonical["sha256"] = Value::String(forged_sha256);
                fs::write(
                    &manifest_path,
                    serde_json::to_vec_pretty(&manifest).unwrap(),
                )
                .unwrap();
                rewrite_bundle_closure(&copy);
            }
            BundleMutation::ForgedRootIndex => {
                fs::write(copy.join("index.md"), "forged non-OKF index\n").unwrap();
            }
        }
        let observed = tree_sha256(&copy).unwrap();
        (copy, observed)
    }

    fn mutated_catalog(&self, mutation: CatalogMutation) -> PathBuf {
        let copy = self
            .root
            .join(format!("catalog-mutation-{}", mutation as u8));
        copy_tree(&self.a2ui_catalog, &copy);
        match mutation {
            CatalogMutation::SchemaDigestDrift => {
                fs::write(copy.join("schema.json"), r#"{"version":"v0.9.1"}"#).unwrap();
            }
            CatalogMutation::MissingButton => {
                let mut catalog = read_json(&copy.join("catalog.json"));
                catalog["components"] = json!(["Column", "Text"]);
                fs::write(
                    copy.join("catalog.json"),
                    serde_json::to_vec_pretty(&catalog).unwrap(),
                )
                .unwrap();
                let mut renderer = read_json(&copy.join("renderer.json"));
                renderer["supported_components"] = json!(["Column", "Text"]);
                fs::write(
                    copy.join("renderer.json"),
                    serde_json::to_vec_pretty(&renderer).unwrap(),
                )
                .unwrap();
            }
            CatalogMutation::ManifestProfileIdentityDrift => {
                let manifest_path = copy.join("manifest.json");
                let mut manifest = read_json(&manifest_path);
                manifest["profile"]["id"] = Value::String("drifted-profile".to_owned());
                fs::write(manifest_path, serde_json::to_vec_pretty(&manifest).unwrap()).unwrap();
            }
            CatalogMutation::RendererIdentityDrift => {
                let mut renderer = read_json(&copy.join("renderer.json"));
                renderer["id"] = Value::String("drifted-renderer".to_owned());
                fs::write(
                    copy.join("renderer.json"),
                    serde_json::to_vec_pretty(&renderer).unwrap(),
                )
                .unwrap();
            }
            CatalogMutation::MissingCommonTypes => {
                fs::remove_file(copy.join("common_types.json")).unwrap();
            }
            CatalogMutation::CommonTypesDigestDrift => {
                let path = copy.join("common_types.json");
                let mut bytes = fs::read(&path).unwrap();
                bytes.extend_from_slice(b"\n");
                fs::write(path, bytes).unwrap();
            }
            CatalogMutation::ProfileDigestDrift => {
                let path = copy.join("profile.json");
                let mut bytes = fs::read(&path).unwrap();
                bytes.extend_from_slice(b"\n");
                fs::write(path, bytes).unwrap();
            }
            CatalogMutation::RendererMissingButton => {
                let mut renderer = read_json(&copy.join("renderer.json"));
                renderer["supported_components"] = json!(["Column", "Text"]);
                fs::write(
                    copy.join("renderer.json"),
                    serde_json::to_vec_pretty(&renderer).unwrap(),
                )
                .unwrap();
            }
        }
        if matches!(
            mutation,
            CatalogMutation::MissingButton
                | CatalogMutation::RendererIdentityDrift
                | CatalogMutation::RendererMissingButton
        ) {
            rewrite_a2ui_manifest_digests(&copy);
        }
        copy
    }
}

fn execute_ok(
    context: &CallContext,
    operation: OperationId,
    request_id: &str,
    payload: Value,
) -> OperationResponse {
    Dispatcher
        .execute(
            context,
            OperationRequest::new(operation, request_id, payload),
        )
        .unwrap_or_else(|error| panic!("{} failed: {error:#?}", operation.as_str()))
}

fn execute_ok_run(
    context: &CallContext,
    operation: OperationId,
    run_id: &str,
    request_id: &str,
    payload: Value,
) -> OperationResponse {
    let mut request = OperationRequest::new(operation, request_id, payload);
    request.run_id = Some(run_id.to_owned());
    Dispatcher
        .execute(context, request)
        .unwrap_or_else(|error| panic!("{} failed: {error:#?}", operation.as_str()))
}

fn execute_error(
    context: &CallContext,
    operation: OperationId,
    request_id: &str,
    payload: Value,
) -> ErrorCode {
    Dispatcher
        .execute(
            context,
            OperationRequest::new(operation, request_id, payload),
        )
        .expect_err("operation must fail closed")
        .error
        .code
}

fn create_a2ui_catalog(root: &Path) {
    fs::create_dir_all(root).unwrap();
    fs::write(
        root.join("schema.json"),
        serde_json::to_vec_pretty(&json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": "urn:gtkg:a2ui-message:v0.9",
            "version": "v0.9.1",
            "type": "object",
            "required": ["version"],
            "properties": {
                "version": {"const": "v0.9"},
                "createSurface": {"$ref": "#/$defs/createSurface"},
                "updateComponents": {"$ref": "#/$defs/updateComponents"},
                "updateDataModel": {"$ref": "#/$defs/updateDataModel"},
                "deleteSurface": {"$ref": "#/$defs/deleteSurface"}
            },
            "oneOf": MESSAGE_OPERATIONS.map(|operation| json!({"required": [operation]})),
            "additionalProperties": false,
            "$defs": {
                "sourceEntityId": {"type": "string", "minLength": 1},
                "action": {
                    "type": "object",
                    "required": ["name", "resource"],
                    "properties": {
                        "name": {"const": "route"},
                        "resource": {"const": "selected_okf_document"}
                    },
                    "additionalProperties": false
                },
                "component": {
                    "type": "object",
                    "required": ["id", "component", "sourceEntityId"],
                    "properties": {
                        "id": {"type": "string", "minLength": 1},
                        "component": {"enum": ["Button", "Column", "List", "Row", "Text"]},
                        "sourceEntityId": {"$ref": "#/$defs/sourceEntityId"},
                        "children": {"type": "array", "items": {"type": "string"}},
                        "child": {"type": "string"},
                        "text": {"type": "object"},
                        "action": {"$ref": "#/$defs/action"}
                    },
                    "additionalProperties": false
                },
                "createSurface": {
                    "type": "object",
                    "required": ["surfaceId", "catalogId"],
                    "properties": {
                        "surfaceId": {"type": "string", "minLength": 1},
                        "catalogId": {"const": "gtkg-test-catalog"}
                    },
                    "additionalProperties": false
                },
                "updateComponents": {
                    "type": "object",
                    "required": ["surfaceId", "components"],
                    "properties": {
                        "surfaceId": {"type": "string", "minLength": 1},
                        "components": {"type": "array", "minItems": 1, "items": {"$ref": "#/$defs/component"}}
                    },
                    "additionalProperties": false
                },
                "updateDataModel": {
                    "type": "object",
                    "required": ["surfaceId", "path", "value"],
                    "properties": {
                        "surfaceId": {"type": "string", "minLength": 1},
                        "path": {"const": "/"},
                        "value": {
                            "type": "object",
                            "required": ["sourceEntityIds"],
                            "properties": {
                                "sourceEntityIds": {"type": "array", "minItems": 1, "items": {"$ref": "#/$defs/sourceEntityId"}},
                                "title": {"type": "string"}
                            },
                            "additionalProperties": false
                        }
                    },
                    "additionalProperties": false
                },
                "deleteSurface": {
                    "type": "object",
                    "required": ["surfaceId"],
                    "properties": {"surfaceId": {"type": "string", "minLength": 1}},
                    "additionalProperties": false
                }
            }
        }))
        .unwrap(),
    )
    .unwrap();
    fs::write(
        root.join("profile.json"),
        serde_json::to_vec_pretty(&json!({
            "schema_version": "gtkg.a2ui-profile/v1",
            "id": "gtkg-test-profile",
            "version": "0.9.1",
            "mime_type": "application/a2ui+json",
            "wire_version": "v0.9",
            "schema_id": "urn:gtkg:a2ui-message:v0.9",
            "common_types_id": "gtkg-test-common-types",
            "catalog_id": "gtkg-test-catalog",
            "catalog_version": "0.1.0"
        }))
        .unwrap(),
    )
    .unwrap();
    fs::write(
        root.join("common_types.json"),
        serde_json::to_vec_pretty(&json!({
            "schema_version": "gtkg.a2ui-common-types/v1",
            "id": "gtkg-test-common-types",
            "version": "0.1.0",
            "wire_version": "v0.9",
            "types": {
                "entity_id": {"type": "string", "min_length": 1},
                "action_name": {"enum": ["route"]},
                "resource": {"enum": ["selected_okf_document"]}
            }
        }))
        .unwrap(),
    )
    .unwrap();
    fs::write(
        root.join("catalog.json"),
        r#"{"id":"gtkg-test-catalog","version":"0.1.0","components":["Button","Column","List","Row","Text"],"actions":["gtkg.select_document"]}"#,
    )
    .unwrap();
    fs::write(
        root.join("renderer.json"),
        serde_json::to_vec_pretty(&json!({
            "schema_version": "gtkg.a2ui-renderer-contract/v1",
            "id": "gtkg-test-renderer",
            "version": "test-only",
            "status": "local_deterministic_renderer",
            "catalog_id": "gtkg-test-catalog",
            "catalog_version": "0.1.0",
            "supported_components": ["Button", "Column", "List", "Row", "Text"],
            "supported_actions": ["gtkg.select_document"]
        }))
        .unwrap(),
    )
    .unwrap();
    rewrite_a2ui_manifest_digests(root);
}

fn rewrite_a2ui_manifest_digests(root: &Path) {
    let manifest = json!({
        "schema_version": "gtkg.a2ui-local-catalog-manifest/v1",
        "spec_version": "0.9.1",
        "profile": {
            "id": "gtkg-test-profile",
            "version": "0.9.1",
            "path": "profile.json",
            "sha256": sha256_file(&root.join("profile.json")).unwrap()
        },
        "schema": {
            "path": "schema.json",
            "sha256": sha256_file(&root.join("schema.json")).unwrap()
        },
        "common_types": {
            "id": "gtkg-test-common-types",
            "version": "0.1.0",
            "path": "common_types.json",
            "sha256": sha256_file(&root.join("common_types.json")).unwrap()
        },
        "catalog": {
            "id": "gtkg-test-catalog",
            "version": "0.1.0",
            "path": "catalog.json",
            "sha256": sha256_file(&root.join("catalog.json")).unwrap()
        },
        "renderer": {
            "id": "gtkg-test-renderer",
            "version": "test-only",
            "path": "renderer.json",
            "sha256": sha256_file(&root.join("renderer.json")).unwrap()
        },
        "scope": "official_basic_catalog"
    });
    fs::write(
        root.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();
}

fn create_template_catalog(catalog: &Path) {
    let staging = catalog.join("summary-template/versions/staging");
    fs::create_dir_all(&staging).unwrap();
    let template = staging.join("template.md");
    fs::write(
        &template,
        "---\ntype: template\ntitle: Summary\ndescription: D05 R5 static analysis fixture\nresource: ./template.md\ntags: [fixture]\ngenerated: false\nverified: false\nstatus: validated\nsources: []\nokf_version: '0.2'\ngtkg:\n  schema: gtkg.template/v1\n---\n\n# Summary\n",
    )
    .unwrap();
    let manifest = json!({
        "schema_version": "gtkg.template-manifest/v1",
        "template_id": "summary-template",
        "version": "0.1.0",
        "template_file": "template.md",
        "template_sha256": sha256_file(&template).unwrap(),
        "slot_ids": ["summary"]
    });
    fs::write(
        staging.join("template-manifest.json"),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();
    let digest = canonical_json_sha256(&manifest).unwrap();
    fs::rename(
        &staging,
        staging
            .parent()
            .unwrap()
            .join(format!("v0.1.0--{}", &digest[7..19])),
    )
    .unwrap();
}

fn frontend_fixture_source(kind: &str, marker: &str) -> String {
    match kind {
        "app" => format!(
            "export function App() {{ return <div data-app-id=\"{marker}\"><KnowledgeSurface /></div>; }}\n"
        ),
        "route" => {
            format!("export const docsRoute = {{ id: \"{marker}\", path: \"/docs\" }} as const;\n")
        }
        "surface" => format!(
            "export function KnowledgeSurface() {{ return <main data-surface-id=\"{marker}\" />; }}\n"
        ),
        "component" => format!(
            "export function KnowledgeCard() {{ return <article data-component-id=\"{marker}\" />; }}\n"
        ),
        "layout" => {
            format!(".{marker} {{ display: grid; grid-template-columns: 20rem minmax(0, 1fr); }}\n")
        }
        "style_token" => format!(":root {{ --{marker}: #3366ff; }}\n"),
        "asset" => format!(
            "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 16 16\"><symbol id=\"{marker}\"><path d=\"M0 0h1v1z\"/></symbol></svg>\n"
        ),
        "interaction" => format!(
            "export function OpenButton() {{ return <button onClick={{() => openKnowledge(\"{marker}\")}}>Open</button>; }}\n"
        ),
        "data_binding" => format!(
            "export function TitleBinding({{ model }}) {{ return <h1>{{model[\"{marker}\"]}}</h1>; }}\n"
        ),
        "ui_state" => format!(
            "export const initialUiState = {{ stateId: \"{marker}\", loading: true, error: null }} as const;\n"
        ),
        "accessibility" => format!(
            "export function AccessibleNavigation() {{ return <nav aria-label=\"{marker}\" />; }}\n"
        ),
        "evidence_ref" => format!(
            "---\ntype: evidence\ntitle: Frontend evidence metadata\ndescription: Static evidence reference\nresource: ./evidence.md\ntags: [frontend, evidence]\ngenerated: false\nverified: false\nstatus: candidate\nsources: []\nokf_version: '0.2'\ngtkg:\n  schema: gtkg.frontend-evidence/v1\n  evidence_ref: {marker}\n---\n\n# Evidence\n"
        ),
        other => panic!("unsupported frontend entity fixture {other}"),
    }
}

fn init_and_commit(root: &Path) {
    git(root, &["init"]);
    git(root, &["config", "user.name", "GTKG Fixture"]);
    git(root, &["config", "user.email", "fixture@invalid.example"]);
    git(root, &["add", "-A"]);
    git(root, &["commit", "-m", "fixture"]);
}

fn git(root: &Path, arguments: &[&str]) {
    let output = Command::new("/usr/bin/git")
        .arg("-C")
        .arg(root)
        .args(arguments)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {} failed: {}",
        arguments.join(" "),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn copy_tree(source: &Path, target: &Path) {
    fs::create_dir_all(target).unwrap();
    let mut entries = fs::read_dir(source)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect::<Vec<_>>();
    entries.sort();
    for path in entries {
        let destination = target.join(path.file_name().unwrap());
        if path.is_dir() {
            copy_tree(&path, &destination);
        } else {
            fs::copy(path, destination).unwrap();
        }
    }
}

fn rewrite_bundle_closure(root: &Path) {
    let mut files = Vec::new();
    collect_regular_files(root, root, &mut files);
    files.sort();
    let lines = files
        .into_iter()
        .filter(|relative| {
            !matches!(
                relative.file_name().and_then(|value| value.to_str()),
                Some("index.md" | "index.gtkg.json" | "checksums.sha256")
            )
        })
        .map(|relative| {
            let digest = sha256_file(&root.join(&relative)).unwrap();
            format!("{}  {}", &digest[7..], relative.to_string_lossy())
        })
        .collect::<Vec<_>>();
    fs::write(
        root.join("checksums.sha256"),
        format!("{}\n", lines.join("\n")),
    )
    .unwrap();
    write_index_tree(root).unwrap();
}

fn collect_regular_files(root: &Path, directory: &Path, output: &mut Vec<PathBuf>) {
    let mut entries = fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect::<Vec<_>>();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            collect_regular_files(root, &path, output);
        } else if path.is_file() {
            output.push(path.strip_prefix(root).unwrap().to_path_buf());
        }
    }
}

fn spawn_fault_child(root: &Path, request: &Path, ready: &Path, fault: &str) -> Child {
    Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("child_executes_d05_generation_fault_request")
        .arg("--nocapture")
        .env(CHILD_ROOT_ENV, root)
        .env(CHILD_REQUEST_ENV, request)
        .env(FAULT_POINT_ENV, fault)
        .env(FAULT_READY_ENV, ready)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap()
}

fn wait_for_fault(child: &mut Child, ready: &Path, fault: &str) {
    for _ in 0..500 {
        if let Some(status) = child.try_wait().unwrap() {
            panic!("fault child exited before {fault}: {status}");
        }
        if ready.is_file() {
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
    let _ = child.kill();
    let _ = child.wait();
    panic!("fault child did not reach {fault}");
}

fn count_version_directories(workspace: &Path, version: &str) -> usize {
    let versions = workspace.join(".gtkg/a2ui/projections/versions");
    fs::read_dir(versions)
        .ok()
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .filter(|entry| {
            entry.file_type().is_ok_and(|kind| kind.is_dir())
                && entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(&format!("v{version}--"))
        })
        .count()
}

fn count_files(root: &Path) -> usize {
    let Ok(entries) = fs::read_dir(root) else {
        return 0;
    };
    entries
        .filter_map(Result::ok)
        .map(|entry| {
            if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                count_files(&entry.path())
            } else {
                1
            }
        })
        .sum()
}

fn result_path(response: &OperationResponse, field: &str) -> PathBuf {
    PathBuf::from(response.result[field].as_str().unwrap())
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

/// H04: the production A2UI profile is the vendored official Google A2UI
/// v0.9.1 basic catalog. These are its frozen identities.
const OFFICIAL_SERVER_SCHEMA_ID: &str = "https://a2ui.org/specification/v0_9/server_to_client.json";
const OFFICIAL_COMMON_TYPES_ID: &str = "https://a2ui.org/specification/v0_9/common_types.json";
const OFFICIAL_BASIC_CATALOG_ID: &str =
    "https://a2ui.org/specification/v0_9/catalogs/basic/catalog.json";

fn vendor_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../crates/gtkg-core/vendor/a2ui/v0_9_1")
}

fn official_components() -> Value {
    let catalog = read_json(&vendor_dir().join("catalog.json"));
    let components = catalog["components"]
        .as_object()
        .expect("official components")
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    json!(components)
}

fn parse_receipt_ref(value: &Value) -> FileReceiptRef {
    serde_json::from_value(value.clone()).unwrap()
}

fn receipt_relative(workspace: &Path, path: &Path) -> String {
    path.strip_prefix(workspace)
        .unwrap()
        .to_string_lossy()
        .replace('\\', "/")
}

fn assert_receipt_ref(workspace: &Path, value: &Value) {
    let reference = parse_receipt_ref(value);
    reference.validate().unwrap();
    let path = workspace.join(&reference.path);
    assert!(path.is_file());
    assert_eq!(sha256_file(&path).unwrap(), reference.sha256);
}

fn digest(character: char) -> String {
    format!("sha256:{}", character.to_string().repeat(64))
}
