use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use gtkg_core::file_model::{sha256_file, tree_sha256};
use gtkg_core::{CallContext, Dispatcher, EffectPolicy, TransportKind};
use gtkg_protocol::{
    ErrorCode, OperationAvailability, OperationId, OperationRequest, OperationResponse,
    OperationStatus, PUBLIC_OPERATIONS, canonical_json_sha256,
};
use serde_json::{Value, json};
use tempfile::{TempDir, tempdir};

const MESSAGE_OPERATIONS: [&str; 4] = [
    "createSurface",
    "updateComponents",
    "updateDataModel",
    "deleteSurface",
];
const STREAM_KINDS: [&str; 5] = ["manifest", "capability", "surface", "data", "action"];
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
fn local_v091_catalog_is_exact_and_all_four_handlers_are_truthfully_available() {
    let fixture = Fixture::new(3);
    let context = fixture.context();

    let availability: BTreeMap<_, _> = PUBLIC_OPERATIONS
        .iter()
        .map(|definition| (definition.id, definition.availability))
        .collect();
    for operation in [
        OperationId::A2uiResolve,
        OperationId::A2uiGenerate,
        OperationId::A2uiGet,
        OperationId::A2uiValidate,
    ] {
        assert_eq!(
            availability.get(&operation),
            Some(&OperationAvailability::Implemented),
            "{operation:?} must disclose a real Dispatcher handler"
        );
    }

    let resolved = fixture.resolve(&context);
    assert_eq!(resolved.status, OperationStatus::Completed);
    let lock = &resolved.result["a2ui_lock"];
    assert_eq!(lock["spec_version"], "0.9.1");
    assert_eq!(lock["profile_version"], "0.9.1");
    assert_eq!(lock["common_types_version"], "0.9.1");
    assert_eq!(lock["catalog_version"], "0.9.1");
    assert_eq!(lock["renderer_version"], "test-only");
    // H04: the lock binds the vendored official Google A2UI v0.9.1 profile,
    // common types, and basic catalog, plus the local deterministic renderer.
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
        sha256_file(&fixture.catalog.join("renderer.json")).unwrap()
    );
    assert_eq!(resolved.result["closure"]["wire_version"], "v0.9");
    assert_eq!(
        resolved.result["closure"]["components"],
        official_components()
    );
    assert_eq!(
        resolved.result["closure"]["renderer_supported_components"],
        json!(["Button", "Column", "List", "Row", "Text"])
    );
    assert_eq!(resolved.result["catalog_scope"], "official_basic_catalog");
    // H04: the resolution ceiling is still renderer_replicable, but generation
    // alone may only claim a2ui_generatable; OD-003/OD-004 stay closed.
    assert_eq!(resolved.result["evidence_ceiling"], "renderer_replicable");
    assert_eq!(resolved.result["od_003"], "closed");
    assert_eq!(resolved.result["od_004"], "closed");
    assert_receipt_ref(&fixture.workspace, &resolved.result["resolution_ref"]);

    let floating = execute_err(
        &context,
        OperationId::A2uiResolve,
        json!({
            "workspace_root": fixture.workspace,
            "catalog_root": fixture.catalog,
            "spec_version": "latest",
            "profile_id": "gtkg-test-profile",
            "profile_version": "0.9.1",
            "catalog_id": "gtkg-test-catalog",
            "catalog_version": "0.1.0",
            "renderer_id": "gtkg-test-renderer",
            "renderer_version": "test-only",
            "expected_manifest_sha256": fixture.catalog_manifest_sha256,
        }),
    );
    assert_eq!(floating, ErrorCode::InvalidRequest);

    let remote = execute_err(
        &context,
        OperationId::A2uiResolve,
        json!({
            "workspace_root": fixture.workspace,
            "catalog_root": "https://a2ui.org/specification/v0_9_1/",
            "spec_version": "0.9.1",
            "profile_id": "gtkg-test-profile",
            "profile_version": "0.9.1",
            "catalog_id": "gtkg-test-catalog",
            "catalog_version": "0.1.0",
            "renderer_id": "gtkg-test-renderer",
            "renderer_version": "test-only",
            "expected_manifest_sha256": fixture.catalog_manifest_sha256,
        }),
    );
    assert!(matches!(
        remote,
        ErrorCode::InvalidRequest | ErrorCode::PathEscape
    ));
}

#[test]
fn frontend_semantic_ir_and_a2ui_stream_are_deterministic_provenanced_and_non_executing() {
    let fixture = Fixture::new(17);
    let context = fixture.context();
    let first = fixture.generate(&context, "0.1.0");
    let second = fixture.generate(&context, "0.1.0");

    assert_eq!(first.status, OperationStatus::Completed);
    assert_eq!(
        first.result, second.result,
        "identical locks must be deterministic"
    );
    assert_eq!(first.result["canonical_source"], "verified_d03_bundle");
    assert_eq!(
        first.result["canonical_bundle_tree_sha256"],
        fixture.bundle_tree_sha256
    );
    assert_eq!(first.result["executed_target_content"], false);
    // H04: a generation receipt without locked-browser renderer smoke may claim
    // at most a2ui_generatable; renderer_replicable is granted only by
    // a2ui.validate after verifying gtkg.a2ui-renderer-smoke/v1 evidence.
    assert_eq!(first.result["evidence_state"], "a2ui_generatable");
    assert_eq!(first.result["evidence_ceiling"], "renderer_replicable");
    assert_eq!(first.result["runtime_verified_count"], 0);

    let projection = PathBuf::from(first.result["projection_path"].as_str().unwrap());
    let ir: Value = read_json(&projection.join("frontend/semantic-ir.json"));
    assert_eq!(ir["schema_version"], "gtkg.frontend-semantic-ir/v2");
    assert_eq!(
        ir["canonical_bundle_tree_sha256"],
        fixture.bundle_tree_sha256
    );
    assert_eq!(ir["executed_target_content"], false);
    assert_eq!(ir["target_process_count"], 0);
    assert_eq!(ir["runtime_verified_count"], 0);
    let entities = ir["entities"].as_array().expect("semantic entities");
    assert_eq!(entities.len(), ENTITY_FIXTURES.len());
    let kinds: BTreeSet<_> = entities
        .iter()
        .map(|entity| entity["kind"].as_str().unwrap())
        .collect();
    assert_eq!(
        kinds,
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
        assert_eq!(entity["id"], format!("{kind}:{marker}"));
        assert!(entity_ids.insert(entity["id"].as_str().unwrap()));
        assert!(
            ["observed_static", "resolved_static", "inferred"]
                .contains(&entity["evidence_level"].as_str().unwrap())
        );
        assert_eq!(entity["evidence_refs"].as_array().unwrap().len(), 1);
        let evidence = &entity["evidence_refs"][0];
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

    let stream_manifest = read_json(&projection.join("a2ui/stream-manifest.json"));
    assert_eq!(
        stream_manifest["schema_version"],
        "gtkg.a2ui-stream-manifest/v2"
    );
    assert_eq!(stream_manifest["mime_type"], "application/a2ui+json");
    assert_eq!(stream_manifest["wire_version"], "v0.9");
    assert_eq!(stream_manifest["load_sequence"], json!(STREAM_KINDS));
    assert_eq!(
        stream_manifest["stream_sha256"],
        sha256_file(&projection.join("a2ui/stream.jsonl")).unwrap()
    );
    let segments = stream_manifest["segments"].as_array().unwrap();
    assert_eq!(segments.len(), STREAM_KINDS.len());
    for segment in segments {
        for entity in segment["entity_ids"].as_array().unwrap() {
            assert!(entity_ids.contains(entity.as_str().unwrap()));
        }
    }

    let generation_ref = first.result["generation_ref"].clone();
    assert_receipt_ref(&fixture.workspace, &generation_ref);
    let got = execute_ok(
        &context,
        OperationId::A2uiGet,
        json!({
            "workspace_root": fixture.workspace,
            "generation_ref": generation_ref,
            "expected_projection_tree_sha256": first.result["projection_tree_sha256"],
        }),
    );
    let stream = got.result["stream"].as_array().unwrap();
    assert_eq!(stream.len(), 3);
    let mut observed_operations = Vec::new();
    for line in stream {
        assert_eq!(line["version"], "v0.9");
        assert_eq!(line.as_object().unwrap().len(), 2);
        let present = MESSAGE_OPERATIONS
            .iter()
            .filter(|operation| line.get(**operation).is_some())
            .copied()
            .collect::<Vec<_>>();
        assert_eq!(present.len(), 1);
        observed_operations.push(present[0]);
    }
    assert_eq!(
        observed_operations,
        vec!["createSurface", "updateComponents", "updateDataModel"]
    );
    assert_eq!(
        got.result["mapping_states"],
        json!(["exact", "approximation", "unsupported"])
    );
    assert_eq!(got.result["load_sequence"], json!(STREAM_KINDS));
}

#[test]
fn offline_wiki_uses_progressive_shards_without_truncation_and_separates_checksums() {
    let fixture = Fixture::new(17);
    let context = fixture.context();
    let real_d03_bundle = (
        fixture.bundle.clone(),
        fixture.bundle_tree_sha256.clone(),
        17_u64,
    );

    for (bundle, bundle_tree_sha256, resource_count) in [real_d03_bundle] {
        let generated = fixture.generate_bundle(
            &context,
            &bundle,
            &bundle_tree_sha256,
            &format!("0.2.{resource_count}"),
        );
        assert_eq!(generated.result["resource_count"], resource_count);
        let projection = PathBuf::from(generated.result["projection_path"].as_str().unwrap());
        let wiki = projection.join("wiki");
        let manifest: Value = read_json(&wiki.join("wiki-manifest.json"));
        assert_eq!(manifest["resource_count"], resource_count);
        assert_eq!(manifest["indexed_resource_count"], resource_count);
        assert!(manifest["truncated"].as_bool().is_some_and(|value| !value));
        assert_eq!(
            manifest["initial_load"],
            json!(["shell", "root_catalog", "selected_content"])
        );
        assert_eq!(manifest["shards"].as_array().unwrap().len(), 1);
        assert_eq!(
            manifest["shards"]
                .as_array()
                .unwrap()
                .iter()
                .map(|shard| shard["entry_count"].as_u64().unwrap())
                .collect::<Vec<_>>(),
            vec![17]
        );
        for shard in manifest["shards"].as_array().unwrap() {
            assert_eq!(
                shard["sha256"],
                sha256_file(&wiki.join(shard["path"].as_str().unwrap())).unwrap()
            );
            assert_eq!(
                shard["content_sha256"],
                sha256_file(&wiki.join(shard["content_path"].as_str().unwrap())).unwrap()
            );
        }
        let sharded: u64 = manifest["shards"]
            .as_array()
            .unwrap()
            .iter()
            .map(|shard| shard["entry_count"].as_u64().unwrap())
            .sum();
        assert_eq!(sharded, resource_count);

        let html = fs::read_to_string(wiki.join("index.html")).expect("wiki shell");
        assert!(html.contains("data-region=\"left-index\""));
        assert!(html.contains("data-region=\"right-content\""));
        assert!(html.contains("default-src 'none'"));
        assert!(html.contains("connect-src 'none'"));
        assert!(!html.contains("unsafe-inline"));
        for state in [
            "normal",
            "loading",
            "empty",
            "error",
            "permission",
            "disabled",
        ] {
            assert!(html.contains(&format!("data-ui-state=\"{state}\"")));
        }
        let script = fs::read_to_string(wiki.join("assets/wiki.js")).expect("wiki script");
        for forbidden in [
            "fetch(",
            "XMLHttpRequest",
            "WebSocket",
            "eval(",
            "innerHTML",
        ] {
            assert!(
                !script.contains(forbidden),
                "forbidden browser primitive: {forbidden}"
            );
        }

        let projection_manifest: Value = read_json(&projection.join("projection-manifest.json"));
        assert_eq!(
            projection_manifest["canonical_bundle_tree_sha256"],
            bundle_tree_sha256
        );
        assert_ne!(
            generated.result["projection_tree_sha256"],
            bundle_tree_sha256
        );
        assert!(projection.join("projection-checksums.json").is_file());

        fs::remove_dir_all(&projection).expect("projection is rebuildable and removable");
        assert_eq!(
            tree_sha256(&bundle).expect("canonical bundle still verifies"),
            bundle_tree_sha256
        );
    }

    for (resource_count, expected_last_count) in [(10_000_usize, 16_usize), (10_001, 17)] {
        let plan = gtkg_core::a2ui::plan_wiki_shards(resource_count);
        assert_eq!(plan.len(), 40);
        assert_eq!(plan.first().unwrap().id, "00000");
        assert_eq!(plan.first().unwrap().start, 0);
        assert_eq!(plan.first().unwrap().end, 256);
        assert_eq!(plan.first().unwrap().entry_count, 256);
        let last = plan.last().unwrap();
        assert_eq!(last.id, "00039");
        assert_eq!(last.start, 9_984);
        assert_eq!(last.end, resource_count);
        assert_eq!(last.entry_count, expected_last_count);
        assert_eq!(
            plan.iter()
                .map(|boundary| boundary.entry_count)
                .sum::<usize>(),
            resource_count
        );
        for pair in plan.windows(2) {
            assert_eq!(pair[0].end, pair[1].start);
            assert!(pair[0].entry_count <= 256);
        }
    }
}

#[test]
fn xss_svg_path_url_tamper_and_replica_overclaim_fail_closed() {
    let fixture = Fixture::new(7);
    let context = fixture.context();
    let generated = fixture.generate(&context, "0.3.0");
    let projection = PathBuf::from(generated.result["projection_path"].as_str().unwrap());
    let wiki = projection.join("wiki");

    let all_projection_text = read_all_text(&projection);
    for forbidden in [
        "<script>alert",
        "javascript:",
        "<foreignObject",
        "onerror=",
        "../../outside",
    ] {
        assert!(
            !all_projection_text.contains(forbidden),
            "projection leaked unsafe token {forbidden}"
        );
    }
    let selected = fs::read_to_string(wiki.join("bootstrap/selected.js")).unwrap();
    assert!(selected.contains("__GTKG_SELECTED_HEX__"));

    let valid = execute_ok(
        &context,
        OperationId::A2uiValidate,
        json!({
            "workspace_root": fixture.workspace,
            "generation_ref": generated.result["generation_ref"],
            "expected_projection_tree_sha256": generated.result["projection_tree_sha256"],
            "required_evidence_state": "a2ui_generatable",
        }),
    );
    assert_eq!(valid.result["valid"], true);
    assert_eq!(valid.result["checks"]["common_types_closure"], "passed");
    assert_eq!(valid.result["checks"]["schema_nested_validation"], "passed");
    assert_eq!(valid.result["checks"]["renderer_smoke"], "not_run");
    assert_eq!(valid.result["checks"]["visual_threshold"], "not_run");
    assert_receipt_ref(&fixture.workspace, &valid.result["validation_ref"]);

    // G04 trusted plumbing delta (OD-003/OD-004): renderer_replicable is now
    // grantable, but only with verified locked-browser smoke evidence; without it
    // the request still fails closed. verified_replica stays fail-closed.
    let missing_smoke = execute_err(
        &context,
        OperationId::A2uiValidate,
        json!({
            "workspace_root": fixture.workspace,
            "generation_ref": generated.result["generation_ref"],
            "expected_projection_tree_sha256": generated.result["projection_tree_sha256"],
            "required_evidence_state": "renderer_replicable",
        }),
    );
    assert_eq!(missing_smoke, ErrorCode::InvalidState);
    let overclaim = execute_err(
        &context,
        OperationId::A2uiValidate,
        json!({
            "workspace_root": fixture.workspace,
            "generation_ref": generated.result["generation_ref"],
            "expected_projection_tree_sha256": generated.result["projection_tree_sha256"],
            "required_evidence_state": "verified_replica",
        }),
    );
    assert_eq!(overclaim, ErrorCode::InvalidState);

    fs::write(
        projection.join("a2ui/stream.jsonl"),
        "{\"version\":\"v0.9\",\"updateDataModel\":{\"surfaceId\":\"wiki\",\"path\":\"/\",\"value\":{\"url\":\"javascript:alert(1)\"}}}\n",
    )
    .expect("tamper projection");
    let tampered = execute_err(
        &context,
        OperationId::A2uiValidate,
        json!({
            "workspace_root": fixture.workspace,
            "generation_ref": generated.result["generation_ref"],
            "expected_projection_tree_sha256": generated.result["projection_tree_sha256"],
            "required_evidence_state": "a2ui_generatable",
        }),
    );
    assert!(matches!(
        tampered,
        ErrorCode::LockMismatch | ErrorCode::BundleInvalid
    ));

    let escaped = execute_err(
        &context,
        OperationId::A2uiGet,
        json!({
            "workspace_root": fixture.workspace,
            "generation_ref": {"path": "../outside.json", "sha256": digest('0')},
            "expected_projection_tree_sha256": digest('0'),
        }),
    );
    assert!(matches!(
        escaped,
        ErrorCode::PathEscape | ErrorCode::InvalidRequest
    ));
}

struct Fixture {
    _temp: TempDir,
    root: PathBuf,
    workspace: PathBuf,
    catalog: PathBuf,
    repository: PathBuf,
    bundle: PathBuf,
    catalog_manifest_sha256: String,
    bundle_tree_sha256: String,
    entity_markers: BTreeMap<String, String>,
}

impl Fixture {
    fn new(requested_resource_count: u64) -> Self {
        let temp = tempdir().expect("tempdir");
        let root = temp.path().to_path_buf();
        let workspace = root.join("workspace");
        let repository = root.join("frontend-repository");
        let template_catalog = root.join("template-catalog");
        let catalog = root.join("a2ui-catalog");
        fs::create_dir_all(&workspace).unwrap();
        fs::create_dir_all(repository.join("src")).unwrap();
        fs::create_dir_all(repository.join("docs")).unwrap();

        let fixture_identity = canonical_json_sha256(&root.to_string_lossy().to_string()).unwrap();
        let fixture_nonce = &fixture_identity[7..15];
        let mut entity_markers = BTreeMap::new();
        for (kind, logical_path, marker_base, _) in ENTITY_FIXTURES {
            let marker = format!("{marker_base}-{fixture_nonce}");
            fs::write(
                repository.join(logical_path),
                frontend_fixture_source(kind, &marker),
            )
            .unwrap();
            entity_markers.insert(kind.to_owned(), marker);
        }
        let resource_count = requested_resource_count.max(ENTITY_FIXTURES.len() as u64);
        for index in 0..resource_count - ENTITY_FIXTURES.len() as u64 {
            fs::write(
                repository.join(format!("docs/knowledge-{index:05}.md")),
                format!("# Knowledge item {index}\n\nCanonical content {index}.\n"),
            )
            .unwrap();
        }
        init_and_commit(&repository);
        create_template_catalog(&template_catalog);
        create_a2ui_catalog(&catalog);
        let catalog_manifest_sha256 = sha256_file(&catalog.join("manifest.json")).unwrap();

        let context = CallContext::restricted(
            TransportKind::Test,
            vec![root.clone()],
            EffectPolicy::WorkspaceWrite,
        )
        .unwrap();
        let inspected = execute_ok_with_id(
            &context,
            OperationId::SourceInspect,
            "d05-source-inspect",
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
        let resolved = execute_ok_with_id(
            &context,
            OperationId::TemplateResolve,
            "d05-template-resolve",
            json!({
                "workspace_root": workspace,
                "catalog_root": template_catalog,
                "template_id": "summary-template",
                "version": "0.1.0"
            }),
        );
        let validated = execute_ok_with_id(
            &context,
            OperationId::TemplateValidate,
            "d05-template-validate",
            json!({
                "workspace_root": workspace,
                "resolution_ref": resolved.result["resolution_ref"]
            }),
        );
        let template_ref = validated.result["validation_ref"].clone();
        let mut plan_request = OperationRequest::new(
            OperationId::BuildPlan,
            "d05-build-plan",
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
            "d05-build-prepare",
            json!({"workspace_root": workspace}),
        );
        loop {
            let next = execute_ok_run(
                &context,
                OperationId::SummaryNext,
                &run_id,
                "d05-summary-next",
                json!({"workspace_root": workspace}),
            );
            let Some(job) = next.result.get("job").filter(|value| !value.is_null()) else {
                break;
            };
            execute_ok_run(
                &context,
                OperationId::SummaryAccept,
                &run_id,
                &format!("d05-summary-{}", job["packet_id"].as_str().unwrap()),
                json!({
                    "workspace_root": workspace,
                    "packet_id": job["packet_id"],
                    "source_sha256": job["source_sha256"],
                    "template_manifest_sha256": job["template_manifest_sha256"],
                    "summary_markdown": format!(
                        "# Static frontend analysis\n\nrepo_id: {}\nlogical_path: {}\nextractor: gtkg-static-fixture/v1\n\n```text\n{}\n```",
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
            "d05-build-finalize",
            json!({"workspace_root": workspace}),
        );
        let bundle = PathBuf::from(finalized.result["bundle_path"].as_str().unwrap());
        let bundle_tree_sha256 = finalized.result["tree_digest"].as_str().unwrap().to_owned();
        assert_eq!(tree_sha256(&bundle).unwrap(), bundle_tree_sha256);
        assert_eq!(
            read_json(&bundle.join("artifact-manifest.json"))["knowledge"]
                .as_array()
                .unwrap()
                .len() as u64,
            resource_count
        );

        Self {
            _temp: temp,
            root,
            workspace,
            catalog,
            repository,
            bundle,
            catalog_manifest_sha256,
            bundle_tree_sha256,
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

    fn resolve(&self, context: &CallContext) -> OperationResponse {
        execute_ok(
            context,
            OperationId::A2uiResolve,
            json!({
                "workspace_root": self.workspace,
                "catalog_root": self.catalog,
                "spec_version": "0.9.1",
                "profile_id": "gtkg-test-profile",
                "profile_version": "0.9.1",
                "catalog_id": "gtkg-test-catalog",
                "catalog_version": "0.1.0",
                "renderer_id": "gtkg-test-renderer",
                "renderer_version": "test-only",
                "expected_manifest_sha256": self.catalog_manifest_sha256,
            }),
        )
    }

    fn generate(&self, context: &CallContext, projection_version: &str) -> OperationResponse {
        self.generate_bundle(
            context,
            &self.bundle,
            &self.bundle_tree_sha256,
            projection_version,
        )
    }

    fn generate_bundle(
        &self,
        context: &CallContext,
        bundle: &Path,
        bundle_tree_sha256: &str,
        projection_version: &str,
    ) -> OperationResponse {
        let resolution = self.resolve(context);
        execute_ok(
            context,
            OperationId::A2uiGenerate,
            json!({
                "workspace_root": self.workspace,
                "bundle_path": bundle,
                "expected_bundle_tree_sha256": bundle_tree_sha256,
                "resolution_ref": resolution.result["resolution_ref"],
                "projection_version": projection_version,
            }),
        )
    }
}

fn execute_ok(context: &CallContext, operation: OperationId, payload: Value) -> OperationResponse {
    execute_ok_with_id(
        context,
        operation,
        &format!("d05-{}", operation.as_str()),
        payload,
    )
}

fn execute_ok_with_id(
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
        .unwrap_or_else(|error| {
            panic!(
                "{} failed at {}: {}",
                operation.as_str(),
                error.error.stage,
                error.error.message
            )
        })
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

fn execute_err(context: &CallContext, operation: OperationId, payload: Value) -> ErrorCode {
    let request = OperationRequest::new(
        operation,
        format!("d05-negative-{}", operation.as_str()),
        payload,
    );
    Dispatcher
        .execute(context, request)
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
    let manifest = json!({
        "schema_version": "gtkg.a2ui-local-catalog-manifest/v1",
        "spec_version": "0.9.1",
        "profile": {"id": "gtkg-test-profile", "version": "0.9.1", "path": "profile.json", "sha256": sha256_file(&root.join("profile.json")).unwrap()},
        "schema": {"path": "schema.json", "sha256": sha256_file(&root.join("schema.json")).unwrap()},
        "common_types": {"id": "gtkg-test-common-types", "version": "0.1.0", "path": "common_types.json", "sha256": sha256_file(&root.join("common_types.json")).unwrap()},
        "catalog": {"id": "gtkg-test-catalog", "version": "0.1.0", "path": "catalog.json", "sha256": sha256_file(&root.join("catalog.json")).unwrap()},
        "renderer": {"id": "gtkg-test-renderer", "version": "test-only", "path": "renderer.json", "sha256": sha256_file(&root.join("renderer.json")).unwrap()},
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
            "---\ntype: evidence\ntitle: Unsafe <script>alert(1)</script>\ndescription: Static evidence reference\nresource: ./evidence.md\ntags: [frontend, evidence]\ngenerated: false\nverified: false\nstatus: candidate\nsources: []\nokf_version: '0.2'\ngtkg:\n  schema: gtkg.frontend-evidence/v1\n  evidence_ref: {marker}\n---\n\n# Evidence\n\n<img src=x onerror=alert(1)> [bad](javascript:alert(1)) <svg><foreignObject>bad</foreignObject></svg> ../../outside\n"
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

fn assert_receipt_ref(workspace: &Path, reference: &Value) {
    let path = reference["path"].as_str().expect("receipt relative path");
    assert!(!Path::new(path).is_absolute());
    let digest = reference["sha256"].as_str().expect("receipt digest");
    assert_eq!(sha256_file(&workspace.join(path)).unwrap(), digest);
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

fn read_all_text(root: &Path) -> String {
    let mut paths = Vec::new();
    collect_files(root, &mut paths);
    paths.sort();
    paths
        .into_iter()
        .filter_map(|path| fs::read_to_string(path).ok())
        .collect::<Vec<_>>()
        .join("\n")
}

fn collect_files(root: &Path, paths: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(root).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if entry.file_type().unwrap().is_dir() {
            collect_files(&path, paths);
        } else if entry.file_type().unwrap().is_file() {
            paths.push(path);
        }
    }
}

fn digest(character: char) -> String {
    format!("sha256:{}", character.to_string().repeat(64))
}

#[test]
fn contract_fixture_digests_are_canonical_and_non_floating() {
    let fixture = Fixture::new(1);
    let manifest: Value = read_json(&fixture.catalog.join("manifest.json"));
    assert_eq!(canonical_json_sha256(&manifest).unwrap().len(), 71);
    assert_eq!(fixture.catalog_manifest_sha256.len(), 71);
}
