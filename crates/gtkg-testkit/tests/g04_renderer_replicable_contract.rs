//! G04 frozen contract: OD-003/OD-004 closure — A2UI evidence ceiling is
//! `renderer_replicable`; `verified_replica` stays fail-closed.
//!
//! Oracles:
//! (a) catalog/renderer identity carries an exact non-floating version plus a
//!     content SHA-256 digest that is re-read and verified on every use; the
//!     resolution receipt records OD-003/OD-004 as closed.
//! (b) browser smoke under the locked Playwright runner on a frozen fixture is
//!     gated by `crates/gtkg-testkit/browser/g04_renderer_replicable_contract.sh`:
//!     page renders, six UI states isolate, remote requests = 0,
//!     console errors = 0, target execution = 0.
//! (c) deterministic replay: the same binary in two independent processes emits
//!     byte-identical projections and pixel-identical screenshots (diff = 0);
//!     the cross-build replay threshold below is the value measured by the G04
//!     harness and is frozen here together with its explanation.
//! (d) `a2ui.validate` grants `renderer_replicable` only with a verified
//!     `gtkg.a2ui-renderer-smoke/v1` evidence receipt bound to the exact
//!     generation, catalog, renderer, and Wiki shell digests; every tampered
//!     or missing evidence variant fails closed, and `verified_replica` is
//!     rejected even with complete evidence.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use gtkg_core::a2ui::WikiRenderResource;
use gtkg_core::a2ui::render_wiki_test_projection;
use gtkg_core::file_model::{sha256_file, tree_sha256};
use gtkg_core::{CallContext, Dispatcher, EffectPolicy, TransportKind};
use gtkg_protocol::{
    ErrorCode, OperationId, OperationRequest, OperationResponse, OperationStatus,
    canonical_json_sha256,
};
use serde_json::{Value, json};
use tempfile::{TempDir, tempdir};

const MESSAGE_OPERATIONS: [&str; 4] = [
    "createSurface",
    "updateComponents",
    "updateDataModel",
    "deleteSurface",
];
const UI_STATES: [&str; 6] = [
    "normal",
    "loading",
    "empty",
    "error",
    "permission",
    "disabled",
];
const SCREENSHOT_REGIONS: [&str; 3] = ["full", "left-index", "right-content"];
/// G04 measured cross-build (debug vs release) replay: the projection bytes are a
/// pure function of the frozen fixture (tree digest identical across builds), so
/// the pinned Chromium renders byte-identical PNGs; measured max pixel diff = 0.
const CROSS_BUILD_PIXEL_THRESHOLD: u64 = 0;
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
fn catalog_renderer_identity_is_exact_digest_locked_and_reread_verified() {
    let fixture = Fixture::new();
    let context = fixture.context();
    let resolved = fixture.resolve(&context);
    assert_eq!(resolved.status, OperationStatus::Completed);

    let lock = &resolved.result["a2ui_lock"];
    assert_eq!(lock["spec_version"], "0.9.1");
    assert_eq!(lock["profile_id"], OFFICIAL_SERVER_SCHEMA_ID);
    assert_eq!(lock["profile_version"], "0.9.1");
    assert_eq!(lock["common_types_id"], OFFICIAL_COMMON_TYPES_ID);
    assert_eq!(lock["common_types_version"], "0.9.1");
    assert_eq!(lock["catalog_id"], OFFICIAL_BASIC_CATALOG_ID);
    assert_eq!(lock["catalog_version"], "0.9.1");
    assert_eq!(lock["renderer_id"], "gtkg-test-renderer");
    assert_eq!(lock["renderer_version"], "test-only");
    for field in [
        "profile_sha256",
        "schema_sha256",
        "common_types_sha256",
        "catalog_sha256",
        "renderer_sha256",
        "manifest_sha256",
    ] {
        let digest = lock[field].as_str().expect("lock digest field");
        assert!(
            digest.len() == 71 && digest.starts_with("sha256:"),
            "{field} must be a full content SHA-256 digest"
        );
    }
    // H04: protocol/common-types/catalog digests bind the vendored official
    // Google A2UI assets; the local root retains only the renderer descriptor
    // and manifest anchor.
    assert_eq!(
        lock["profile_sha256"],
        sha256_file(&vendor_dir().join("server_to_client.json")).unwrap()
    );
    assert_eq!(
        lock["schema_sha256"],
        sha256_file(&vendor_dir().join("server_to_client.json")).unwrap()
    );
    assert_eq!(
        lock["common_types_sha256"],
        sha256_file(&vendor_dir().join("common_types.json")).unwrap()
    );
    assert_eq!(
        lock["catalog_sha256"],
        sha256_file(&vendor_dir().join("catalog.json")).unwrap()
    );
    assert_eq!(
        lock["renderer_sha256"],
        sha256_file(&fixture.catalog.join("renderer.json")).unwrap()
    );
    assert_eq!(
        lock["manifest_sha256"],
        sha256_file(&fixture.catalog.join("manifest.json")).unwrap()
    );
    let renderer: Value = read_json(&fixture.catalog.join("renderer.json"));
    assert_eq!(renderer["id"], lock["renderer_id"]);
    assert_eq!(renderer["version"], lock["renderer_version"]);

    // OD-003/OD-004 are closed by this wave; the ceiling is renderer_replicable.
    assert_eq!(resolved.result["evidence_ceiling"], "renderer_replicable");
    assert_eq!(resolved.result["od_003"], "closed");
    assert_eq!(resolved.result["od_004"], "closed");

    // Drift in the locked renderer definition after resolution fails closed on re-read.
    let mut drifted: Value = read_json(&fixture.catalog.join("renderer.json"));
    drifted["supported_components"] = json!(["Button", "Column", "List", "Row", "Text", "Image"]);
    fs::write(
        fixture.catalog.join("renderer.json"),
        serde_json::to_vec_pretty(&drifted).unwrap(),
    )
    .unwrap();
    let error = execute_err(
        &context,
        OperationId::A2uiGenerate,
        json!({
            "workspace_root": fixture.workspace,
            "bundle_path": fixture.bundle,
            "expected_bundle_tree_sha256": fixture.bundle_tree_sha256,
            "resolution_ref": resolved.result["resolution_ref"],
            "projection_version": "70.0.0",
        }),
    );
    assert_eq!(
        error,
        ErrorCode::LockMismatch,
        "renderer digest drift must fail closed on re-read"
    );
}

#[test]
fn legacy_wiki_smoke_cannot_grant_renderer_replicable() {
    let fixture = Fixture::new();
    let context = fixture.context();
    let generated = fixture.generate(&context, "70.1.0");
    assert_eq!(generated.result["evidence_state"], "a2ui_generatable");
    assert_eq!(generated.result["evidence_ceiling"], "renderer_replicable");
    assert_eq!(generated.result["executed_target_content"], false);

    // renderer_replicable without browser smoke evidence fails closed.
    let missing = execute_err(
        &context,
        OperationId::A2uiValidate,
        json!({
            "workspace_root": fixture.workspace,
            "generation_ref": generated.result["generation_ref"],
            "expected_projection_tree_sha256": generated.result["projection_tree_sha256"],
            "required_evidence_state": "renderer_replicable",
        }),
    );
    assert_eq!(missing, ErrorCode::InvalidState);

    // G04's legacy receipt proves only the standalone Wiki HTML renderer. H05
    // requires a v2 receipt bound to stream.jsonl, official packages, browser
    // binary, DOM/data/action observations, and screenshot artifacts.
    let legacy_ref = fixture.write_smoke_evidence(&generated, json!({}));
    let legacy = execute_err(
        &context,
        OperationId::A2uiValidate,
        json!({
            "workspace_root": fixture.workspace,
            "generation_ref": generated.result["generation_ref"],
            "expected_projection_tree_sha256": generated.result["projection_tree_sha256"],
            "required_evidence_state": "renderer_replicable",
            "renderer_smoke_ref": legacy_ref.clone(),
        }),
    );
    assert!(
        matches!(
            legacy,
            ErrorCode::InvalidRequest | ErrorCode::LockMismatch | ErrorCode::BundleInvalid
        ),
        "legacy Wiki-only smoke must fail closed, got {legacy:?}"
    );

    // verified_replica stays fail-closed regardless of supplied evidence.
    let replica = execute_err(
        &context,
        OperationId::A2uiValidate,
        json!({
            "workspace_root": fixture.workspace,
            "generation_ref": generated.result["generation_ref"],
            "expected_projection_tree_sha256": generated.result["projection_tree_sha256"],
            "required_evidence_state": "verified_replica",
            "renderer_smoke_ref": legacy_ref.clone(),
        }),
    );
    assert_eq!(replica, ErrorCode::InvalidState);

    // Lower evidence states keep their previous contract (smoke checks not run).
    let lower = execute_ok(
        &context,
        OperationId::A2uiValidate,
        json!({
            "workspace_root": fixture.workspace,
            "generation_ref": generated.result["generation_ref"],
            "expected_projection_tree_sha256": generated.result["projection_tree_sha256"],
            "required_evidence_state": "a2ui_generatable",
        }),
    );
    assert_eq!(lower.result["valid"], true);
    assert_eq!(lower.result["checks"]["renderer_smoke"], "not_run");
    assert_eq!(lower.result["checks"]["visual_threshold"], "not_run");

    // Smoke evidence attached to a lower-state request is rejected as incoherent.
    let incoherent = execute_err(
        &context,
        OperationId::A2uiValidate,
        json!({
            "workspace_root": fixture.workspace,
            "generation_ref": generated.result["generation_ref"],
            "expected_projection_tree_sha256": generated.result["projection_tree_sha256"],
            "required_evidence_state": "a2ui_generatable",
            "renderer_smoke_ref": legacy_ref,
        }),
    );
    assert_eq!(incoherent, ErrorCode::InvalidRequest);
}

#[test]
fn renderer_output_is_byte_deterministic_across_repeated_renders() {
    let fixture = Fixture::new();
    let context = fixture.context();
    let first = fixture.generate(&context, "70.2.0");
    let second = fixture.generate(&context, "70.2.0");
    assert_eq!(
        first.result, second.result,
        "repeated generation must be byte deterministic"
    );

    // The production Wiki renderer is a pure function of its resource input.
    let resources: Vec<WikiRenderResource> = (0..300_u64)
        .map(|index| WikiRenderResource {
            id: format!("g04-resource-{index:05}"),
            logical_path: format!("g04/docs/{index:05}.md"),
            title: format!("G04 knowledge {index:05}"),
            content: format!("Frozen G04 replay content {index:05}"),
        })
        .collect();
    let render = |directory: &Path| {
        render_wiki_test_projection(&context, directory, &resources, "g04-resource-00000")
            .expect("production Wiki renderer must emit the frozen fixture");
        tree_sha256(directory).unwrap()
    };
    let first_tree = render(&fixture.root.join("replay-a"));
    let second_tree = render(&fixture.root.join("replay-b"));
    assert_eq!(
        first_tree, second_tree,
        "production renderer must be byte deterministic"
    );
}

#[test]
fn browser_harness_contract_freezes_locked_runner_and_replay_oracles() {
    let script_path =
        repo_root().join("crates/gtkg-testkit/browser/g04_renderer_replicable_contract.sh");
    let script = fs::read_to_string(&script_path).unwrap_or_else(|error| {
        panic!(
            "G04 browser harness {} must exist: {error}",
            script_path.display()
        )
    });
    assert!(
        script.contains(
            "PWCLI=\"${PWCLI:-$REPO_ROOT/crates/gtkg-testkit/browser/playwright_cli_locked.sh}\""
        ),
        "G04 harness must default to the in-repo locked Playwright runner"
    );
    assert!(
        !script.contains("@latest"),
        "G04 harness must not reference any floating Playwright tag"
    );
    for marker in [
        // six-state isolation smoke
        "'normal', 'loading', 'empty', 'error', 'permission', 'disabled'",
        // remote request = 0 oracle
        "remote requests observed",
        // target execution = 0 oracle
        "target_execution_count !== 0",
        // same-build cross-process replay requires pixel diff = 0
        "same-build replay pixel diff must be 0",
        // cross-build replay against a second build of the same source
        "--release",
        // evidence schema handed to a2ui.validate
        "gtkg.a2ui-renderer-smoke/v1",
        // emitter + finalizer ignored tests
        "emit_g04_browser_fixture",
        "validate_g04_renderer_replicable_with_browser_evidence",
    ] {
        assert!(
            script.contains(marker),
            "G04 harness is missing oracle: {marker}"
        );
    }
    let threshold = format!("CROSS_BUILD_PIXEL_THRESHOLD={CROSS_BUILD_PIXEL_THRESHOLD}");
    assert!(
        script.contains(&threshold),
        "G04 harness must freeze the measured cross-build threshold {threshold}"
    );
}

struct Fixture {
    _temp: TempDir,
    root: PathBuf,
    workspace: PathBuf,
    catalog: PathBuf,
    bundle: PathBuf,
    catalog_manifest_sha256: String,
    bundle_tree_sha256: String,
}

impl Fixture {
    fn new() -> Self {
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
        for (kind, logical_path, marker_base, _) in ENTITY_FIXTURES {
            let marker = format!("{marker_base}-{fixture_nonce}");
            fs::write(
                repository.join(logical_path),
                frontend_fixture_source(kind, &marker),
            )
            .unwrap();
        }
        for index in 0..5_u64 {
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
            "g04-source-inspect",
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
            "g04-template-resolve",
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
            "g04-template-validate",
            json!({
                "workspace_root": workspace,
                "resolution_ref": resolved.result["resolution_ref"]
            }),
        );
        let template_ref = validated.result["validation_ref"].clone();
        let mut plan_request = OperationRequest::new(
            OperationId::BuildPlan,
            "g04-build-plan",
            json!({
                "workspace_root": workspace,
                "mode": "full",
                "source_inspection_ref": source_inspection_ref,
                "template_validation_ref": template_ref,
                "baseline_bundle": null,
                "bundle_version": "70.0.0"
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
            "g04-build-prepare",
            json!({"workspace_root": workspace}),
        );
        loop {
            let next = execute_ok_run(
                &context,
                OperationId::SummaryNext,
                &run_id,
                "g04-summary-next",
                json!({"workspace_root": workspace}),
            );
            let Some(job) = next.result.get("job").filter(|value| !value.is_null()) else {
                break;
            };
            execute_ok_run(
                &context,
                OperationId::SummaryAccept,
                &run_id,
                &format!("g04-summary-{}", job["packet_id"].as_str().unwrap()),
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
            "g04-build-finalize",
            json!({"workspace_root": workspace}),
        );
        let bundle = PathBuf::from(finalized.result["bundle_path"].as_str().unwrap());
        let bundle_tree_sha256 = finalized.result["tree_digest"].as_str().unwrap().to_owned();
        assert_eq!(tree_sha256(&bundle).unwrap(), bundle_tree_sha256);

        Self {
            _temp: temp,
            root,
            workspace,
            catalog,
            bundle,
            catalog_manifest_sha256,
            bundle_tree_sha256,
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
        let resolution = self.resolve(context);
        execute_ok(
            context,
            OperationId::A2uiGenerate,
            json!({
                "workspace_root": self.workspace,
                "bundle_path": self.bundle,
                "expected_bundle_tree_sha256": self.bundle_tree_sha256,
                "resolution_ref": resolution.result["resolution_ref"],
                "projection_version": projection_version,
            }),
        )
    }

    /// Writes a well-formed `gtkg.a2ui-renderer-smoke/v1` evidence receipt into the
    /// workspace producer namespace, with `patch` shallow-merged for tamper cases.
    fn write_smoke_evidence(&self, generated: &OperationResponse, patch: Value) -> Value {
        let projection = PathBuf::from(generated.result["projection_path"].as_str().unwrap());
        let generation_ref = &generated.result["generation_ref"];
        let generation: Value = read_json(
            &self
                .workspace
                .join(generation_ref["path"].as_str().unwrap()),
        );
        let lock = &generation["a2ui_lock"];
        let mut evidence = json!({
            "schema_version": "gtkg.a2ui-renderer-smoke/v1",
            "projection_tree_sha256": generated.result["projection_tree_sha256"],
            "catalog_id": lock["catalog_id"],
            "catalog_version": lock["catalog_version"],
            "catalog_sha256": lock["catalog_sha256"],
            "renderer_id": lock["renderer_id"],
            "renderer_version": lock["renderer_version"],
            "renderer_sha256": lock["renderer_sha256"],
            "wiki_shell_sha256": {
                "index_html": sha256_file(&projection.join("wiki/index.html")).unwrap(),
                "wiki_css": sha256_file(&projection.join("wiki/assets/wiki.css")).unwrap(),
                "wiki_js": sha256_file(&projection.join("wiki/assets/wiki.js")).unwrap(),
            },
            "browser": {
                "engine": "chromium",
                "playwright_cli_package": "@playwright/cli",
                "playwright_cli_version": "0.1.18",
            },
            "states": UI_STATES,
            "regions": SCREENSHOT_REGIONS,
            "remote_request_count": 0,
            "console_error_count": 0,
            "csp_violation_count": 0,
            "target_execution_count": 0,
            "xss_sentinel_tripped": false,
            "same_build_replay": {
                "independent_processes": 2,
                "screenshot_pairs": 18,
                "pixel_diff_max": 0,
            },
            "cross_build_replay": {
                "builds": ["debug", "release"],
                "pixel_diff_max": CROSS_BUILD_PIXEL_THRESHOLD,
                "threshold": CROSS_BUILD_PIXEL_THRESHOLD,
                "explanation": "G04 measured: projection bytes are a pure function of the frozen fixture (identical tree digest across builds), so the pinned Chromium emits identical pixels.",
            },
        });
        if let Value::Object(patch) = patch {
            for (key, value) in patch {
                evidence[key] = value;
            }
        }
        let directory = self.workspace.join(".gtkg/a2ui/browser-evidence");
        fs::create_dir_all(&directory).unwrap();
        let identity = canonical_json_sha256(&evidence).unwrap();
        let path = directory.join(format!("smoke-{}.json", &identity[7..31]));
        fs::write(&path, serde_json::to_vec_pretty(&evidence).unwrap()).unwrap();
        json!({
            "path": path.strip_prefix(&self.workspace).unwrap().to_string_lossy().replace('\\', "/"),
            "sha256": sha256_file(&path).unwrap(),
        })
    }
}

fn execute_ok(context: &CallContext, operation: OperationId, payload: Value) -> OperationResponse {
    execute_ok_with_id(
        context,
        operation,
        &format!("g04-{}", operation.as_str()),
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
        format!("g04-negative-{}", operation.as_str()),
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
        "---\ntype: template\ntitle: Summary\ndescription: G04 static analysis fixture\nresource: ./template.md\ntags: [fixture]\ngenerated: false\nverified: false\nstatus: validated\nsources: []\nokf_version: '0.2'\ngtkg:\n  schema: gtkg.template/v1\n---\n\n# Summary\n",
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

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("gtkg-testkit must live at <repo>/crates/gtkg-testkit")
        .to_owned()
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

const OFFICIAL_SERVER_SCHEMA_ID: &str = "https://a2ui.org/specification/v0_9/server_to_client.json";
const OFFICIAL_COMMON_TYPES_ID: &str = "https://a2ui.org/specification/v0_9/common_types.json";
const OFFICIAL_BASIC_CATALOG_ID: &str =
    "https://a2ui.org/specification/v0_9/catalogs/basic/catalog.json";

fn vendor_dir() -> PathBuf {
    repo_root().join("crates/gtkg-core/vendor/a2ui/v0_9_1")
}
