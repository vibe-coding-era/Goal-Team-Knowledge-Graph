//! G04 browser fixture emitter and evidence-bound finalizer.
//!
//! Both tests are `#[ignore]`d: they are driven by the frozen shell harness
//! `crates/gtkg-testkit/browser/g04_renderer_replicable_contract.sh`, never by the
//! default `cargo test` gate.
//!
//! - `emit_g04_browser_fixture` runs the real D03 -> A2UI pipeline in a fresh
//!   output directory, renders the deterministic frozen Wiki fixture with the
//!   production renderer, and writes `g04-browser-fixture-receipt/v1`.
//! - `validate_g04_renderer_replicable_with_browser_evidence` consumes the smoke
//!   evidence receipt the harness measured with the locked Playwright runner and
//!   proves `a2ui.validate` grants `renderer_replicable` while `verified_replica`
//!   stays fail-closed.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use gtkg_core::a2ui::{WikiRenderResource, plan_wiki_shards, render_wiki_test_projection};
use gtkg_core::file_model::{sha256_file, tree_sha256};
use gtkg_core::{CallContext, Dispatcher, EffectPolicy, TransportKind};
use gtkg_protocol::{ErrorCode, OperationId, OperationRequest, OperationResponse};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const FROZEN_RESOURCE_COUNT: u64 = 300;
const MESSAGE_OPERATIONS: [&str; 4] = [
    "createSurface",
    "updateComponents",
    "updateDataModel",
    "deleteSurface",
];
const ENTITY_FIXTURES: [(&str, &str, &str); 12] = [
    ("app", "src/App.tsx", "app-shell-browser"),
    ("route", "src/routes.ts", "route-docs-browser"),
    (
        "surface",
        "src/KnowledgeSurface.tsx",
        "surface-wiki-browser",
    ),
    (
        "component",
        "src/KnowledgeCard.tsx",
        "component-card-browser",
    ),
    ("layout", "src/layout.css", "layout-split-browser"),
    ("style_token", "src/tokens.css", "style-accent-browser"),
    ("asset", "src/logo.svg", "asset-logo-browser"),
    (
        "interaction",
        "src/OpenButton.tsx",
        "interaction-open-browser",
    ),
    (
        "data_binding",
        "src/TitleBinding.tsx",
        "binding-title-browser",
    ),
    ("ui_state", "src/state.ts", "state-loading-browser"),
    (
        "accessibility",
        "src/AccessibleNavigation.tsx",
        "a11y-main-browser",
    ),
    ("evidence_ref", "src/evidence.md", "evidence-source-browser"),
];

#[test]
#[ignore = "driven by the G04 shell harness with GTKG_G04_BROWSER_OUTPUT set"]
fn emit_g04_browser_fixture() {
    let root = PathBuf::from(
        std::env::var_os("GTKG_G04_BROWSER_OUTPUT")
            .expect("GTKG_G04_BROWSER_OUTPUT must name a new empty directory"),
    );
    assert!(root.is_absolute(), "browser output must be absolute");
    let entries = fs::read_dir(&root)
        .expect("browser output directory must already exist")
        .count();
    assert_eq!(entries, 0, "browser output directory must be empty");

    let workspace = root.join("workspace");
    let repository = root.join("frontend-repository");
    let template_catalog = root.join("template-catalog");
    let a2ui_catalog = root.join("a2ui-catalog");
    fs::create_dir_all(&workspace).unwrap();
    fs::create_dir_all(&repository).unwrap();
    for (kind, logical_path, marker) in ENTITY_FIXTURES {
        let path = repository.join(logical_path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, frontend_fixture_source(kind, marker)).unwrap();
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
    let inspected = execute(
        &context,
        OperationId::SourceInspect,
        "g04-browser-source-inspect",
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
    let template_resolution = execute(
        &context,
        OperationId::TemplateResolve,
        "g04-browser-template-resolve",
        json!({
            "workspace_root": workspace,
            "catalog_root": template_catalog,
            "template_id": "summary-template",
            "version": "0.1.0"
        }),
    );
    let template_validation = execute(
        &context,
        OperationId::TemplateValidate,
        "g04-browser-template-validate",
        json!({
            "workspace_root": workspace,
            "resolution_ref": template_resolution.result["resolution_ref"]
        }),
    );
    let template_validation_ref = template_validation.result["validation_ref"].clone();
    let mut plan_request = OperationRequest::new(
        OperationId::BuildPlan,
        "g04-browser-build-plan",
        json!({
            "workspace_root": workspace,
            "mode": "full",
            "source_inspection_ref": source_inspection_ref,
            "template_validation_ref": template_validation_ref,
            "baseline_bundle": null,
            "bundle_version": "70.0.0-browser"
        }),
    );
    plan_request.locks = BTreeMap::from([
        (
            "source_inspection".to_owned(),
            source_inspection_ref["sha256"].as_str().unwrap().to_owned(),
        ),
        (
            "template_validation".to_owned(),
            template_validation_ref["sha256"]
                .as_str()
                .unwrap()
                .to_owned(),
        ),
    ]);
    let planned = Dispatcher
        .execute(&context, plan_request)
        .expect("build.plan must succeed");
    let run_id = planned.run_id.expect("build.plan must return a run id");
    execute_run(
        &context,
        OperationId::BuildPrepare,
        &run_id,
        "g04-browser-build-prepare",
        json!({"workspace_root": workspace}),
    );
    loop {
        let next = execute_run(
            &context,
            OperationId::SummaryNext,
            &run_id,
            "g04-browser-summary-next",
            json!({"workspace_root": workspace}),
        );
        let Some(job) = next.result.get("job").filter(|value| !value.is_null()) else {
            break;
        };
        execute_run(
            &context,
            OperationId::SummaryAccept,
            &run_id,
            &format!("g04-browser-summary-{}", job["packet_id"].as_str().unwrap()),
            json!({
                "workspace_root": workspace,
                "packet_id": job["packet_id"],
                "source_sha256": job["source_sha256"],
                "template_manifest_sha256": job["template_manifest_sha256"],
                "summary_markdown": format!(
                    "# Static frontend analysis\n\nrepo_id: {}\nlogical_path: {}\nextractor: gtkg-browser-static-fixture/v1\n\n```text\n{}\n```",
                    job["repo_id"].as_str().unwrap(),
                    job["source_path"].as_str().unwrap(),
                    job["analysis_text"].as_str().unwrap()
                )
            }),
        );
    }
    let finalized = execute_run(
        &context,
        OperationId::BuildFinalize,
        &run_id,
        "g04-browser-build-finalize",
        json!({"workspace_root": workspace}),
    );
    let bundle_path = PathBuf::from(finalized.result["bundle_path"].as_str().unwrap());
    let bundle_tree_sha256 = finalized.result["tree_digest"].as_str().unwrap();
    assert_eq!(tree_sha256(&bundle_path).unwrap(), bundle_tree_sha256);

    let a2ui_manifest_sha256 = sha256_file(&a2ui_catalog.join("manifest.json")).unwrap();
    let a2ui_resolution = execute(
        &context,
        OperationId::A2uiResolve,
        "g04-browser-a2ui-resolve",
        json!({
            "workspace_root": workspace,
            "catalog_root": a2ui_catalog,
            "spec_version": "0.9.1",
            "profile_id": "gtkg-test-profile",
            "profile_version": "0.9.1",
            "catalog_id": "gtkg-test-catalog",
            "catalog_version": "0.1.0",
            "renderer_id": "gtkg-test-renderer",
            "renderer_version": "test-only",
            "expected_manifest_sha256": a2ui_manifest_sha256
        }),
    );
    assert_eq!(
        a2ui_resolution.result["evidence_ceiling"],
        "renderer_replicable"
    );
    assert_eq!(a2ui_resolution.result["od_003"], "closed");
    assert_eq!(a2ui_resolution.result["od_004"], "closed");
    let generated = execute(
        &context,
        OperationId::A2uiGenerate,
        "g04-browser-a2ui-generate",
        json!({
            "workspace_root": workspace,
            "bundle_path": bundle_path,
            "expected_bundle_tree_sha256": bundle_tree_sha256,
            "resolution_ref": a2ui_resolution.result["resolution_ref"],
            "projection_version": "70.0.0-browser"
        }),
    );
    let projection = PathBuf::from(generated.result["projection_path"].as_str().unwrap());
    let stream_path = projection.join("a2ui/stream.jsonl");
    let stream_message_count = fs::read_to_string(&stream_path)
        .unwrap()
        .lines()
        .filter(|line| !line.is_empty())
        .count();
    let generation_receipt_path =
        workspace.join(generated.result["generation_ref"]["path"].as_str().unwrap());
    let generation_shell = json!({
        "index_html": sha256_file(&projection.join("wiki/index.html")).unwrap(),
        "wiki_css": sha256_file(&projection.join("wiki/assets/wiki.css")).unwrap(),
        "wiki_js": sha256_file(&projection.join("wiki/assets/wiki.js")).unwrap(),
    });

    // Deterministic frozen fixture rendered by the exact production Wiki renderer.
    let frozen = root.join("frozen-wiki");
    let mut resources = Vec::with_capacity(FROZEN_RESOURCE_COUNT as usize);
    for index in 0..FROZEN_RESOURCE_COUNT {
        resources.push(WikiRenderResource {
            id: format!("g04-frozen-{index:05}"),
            logical_path: format!("frozen/docs/{index:05}.md"),
            title: format!("Frozen knowledge {index:05}"),
            content: if index == 0 {
                "# Frozen selected\n<img src=x onerror=globalThis.__GTKG_XSS_SENTINEL__=true> <script>globalThis.__GTKG_XSS_SENTINEL__=true</script> [bad](javascript:alert(1)) <svg><foreignObject>bad</foreignObject></svg>".to_owned()
            } else if index == FROZEN_RESOURCE_COUNT - 1 {
                "Production renderer boundary content".to_owned()
            } else {
                format!("Frozen G04 replay content {index:05}")
            },
        });
    }
    let selected = resources.first().unwrap();
    let expected_last = resources.last().unwrap();
    render_wiki_test_projection(&context, &frozen, &resources, &selected.id)
        .expect("production Wiki renderer must emit the frozen fixture");
    let shard_plan = plan_wiki_shards(resources.len());
    let expected_last_shard = shard_plan.last().unwrap();
    let frozen_index = frozen.join("wiki/index.html");
    let frozen_tree_sha256 = tree_sha256(&frozen).unwrap();
    // The frozen fixture must ship the exact same renderer shell bytes as the
    // real generation projection; this is what binds the browser smoke to the
    // renderer under validation.
    let frozen_shell = json!({
        "index_html": sha256_file(&frozen.join("wiki/index.html")).unwrap(),
        "wiki_css": sha256_file(&frozen.join("wiki/assets/wiki.css")).unwrap(),
        "wiki_js": sha256_file(&frozen.join("wiki/assets/wiki.js")).unwrap(),
    });
    assert_eq!(
        frozen_shell, generation_shell,
        "frozen fixture and generation projection must share the exact renderer shell"
    );

    let receipt = json!({
        "schema_version": "gtkg.g04-browser-fixture-receipt/v1",
        "workspace": workspace,
        "generation_ref": generated.result["generation_ref"],
        "generation_receipt_path": generation_receipt_path,
        "projection_path": projection,
        "projection_tree_sha256": generated.result["projection_tree_sha256"],
        "stream_path": stream_path.clone(),
        "stream_sha256": sha256_file(&stream_path).unwrap(),
        "stream_message_count": stream_message_count,
        "a2ui_lock": a2ui_resolution.result["a2ui_lock"],
        "wiki_shell_sha256": generation_shell,
        "frozen": {
            "provenance": "test-only frozen data rendered by the production Wiki renderer; resources are not claimed as canonical bundle content",
            "wiki_index": frozen_index,
            "file_url": format!("file://{}", frozen_index.display()),
            "tree_sha256": frozen_tree_sha256,
            "resource_count": resources.len(),
            "expected_initial_requests": [
                "assets/wiki.css",
                "assets/wiki.js",
                "bootstrap/root.js",
                "bootstrap/selected.js",
                "index.html"
            ],
            "expected_initial": {
                "id": selected.id,
                "title": selected.title,
                "content": selected.content,
            },
            "expected_last": {
                "id": expected_last.id,
                "title": expected_last.title,
                "content": expected_last.content,
            },
            "expected_last_shard": {
                "id": expected_last_shard.id,
                "entry_count": expected_last_shard.entry_count,
            },
            "offline": true,
        }
    });
    fs::write(
        root.join("g04-browser-fixture-receipt.json"),
        serde_json::to_vec_pretty(&receipt).unwrap(),
    )
    .unwrap();
}

#[test]
#[ignore = "driven by the H05 shell harness with GTKG_H05_CURRENT_OUTPUT set"]
fn emit_h05_current_source_fixture() {
    let root = PathBuf::from(
        std::env::var_os("GTKG_H05_CURRENT_OUTPUT")
            .expect("GTKG_H05_CURRENT_OUTPUT must name a new empty directory"),
    );
    assert!(root.is_absolute(), "H05 output must be absolute");
    assert_eq!(
        fs::read_dir(&root)
            .expect("H05 output directory must exist")
            .count(),
        0,
        "H05 output directory must be empty"
    );

    let current_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("current GTKG root");
    let repository = root.join("current-source-snapshot");
    let source_snapshot = snapshot_current_repository(&current_root, &repository, &root);
    let workspace = root.join("workspace");
    let template_catalog = root.join("template-catalog");
    let a2ui_catalog = root.join("a2ui-catalog");
    fs::create_dir_all(&workspace).unwrap();
    create_template_catalog(&template_catalog);
    create_h05_a2ui_catalog(&a2ui_catalog);

    let context = CallContext::restricted(
        TransportKind::Test,
        vec![root.clone()],
        EffectPolicy::WorkspaceWrite,
    )
    .unwrap();
    let inspected = execute(
        &context,
        OperationId::SourceInspect,
        "h05-current-source-inspect",
        json!({
            "workspace_root": workspace,
            "repositories": [{
                "repo_id": "gtkg-current",
                "path": repository,
                "role": "product-source",
                "include": []
            }]
        }),
    );
    let source_file_count = source_snapshot["source_file_count"].as_u64().unwrap();
    let admitted_count = inspected.result["source_lock"]["entries"]
        .as_array()
        .expect("source lock entries")
        .len() as u64;
    let omission_count = inspected.result["omission_count"].as_u64().unwrap();
    assert_eq!(
        admitted_count + omission_count,
        source_file_count,
        "every current-source file must be admitted or explicitly omitted"
    );
    let source_inspection_ref = inspected.result["inspection_ref"].clone();
    let template_resolution = execute(
        &context,
        OperationId::TemplateResolve,
        "h05-current-template-resolve",
        json!({
            "workspace_root": workspace,
            "catalog_root": template_catalog,
            "template_id": "summary-template",
            "version": "0.1.0"
        }),
    );
    let template_validation = execute(
        &context,
        OperationId::TemplateValidate,
        "h05-current-template-validate",
        json!({
            "workspace_root": workspace,
            "resolution_ref": template_resolution.result["resolution_ref"]
        }),
    );
    let template_validation_ref = template_validation.result["validation_ref"].clone();
    let mut plan_request = OperationRequest::new(
        OperationId::BuildPlan,
        "h05-current-build-plan",
        json!({
            "workspace_root": workspace,
            "mode": "full",
            "source_inspection_ref": source_inspection_ref,
            "template_validation_ref": template_validation_ref,
            "baseline_bundle": null,
            "bundle_version": "0.5.0-h05-current"
        }),
    );
    plan_request.locks = BTreeMap::from([
        (
            "source_inspection".to_owned(),
            source_inspection_ref["sha256"].as_str().unwrap().to_owned(),
        ),
        (
            "template_validation".to_owned(),
            template_validation_ref["sha256"]
                .as_str()
                .unwrap()
                .to_owned(),
        ),
    ]);
    let planned = Dispatcher
        .execute(&context, plan_request)
        .expect("current-source build.plan");
    let run_id = planned.run_id.expect("current-source run id");
    execute_run(
        &context,
        OperationId::BuildPrepare,
        &run_id,
        "h05-current-build-prepare",
        json!({"workspace_root": workspace}),
    );
    loop {
        let next = execute_run(
            &context,
            OperationId::SummaryNext,
            &run_id,
            "h05-current-summary-next",
            json!({"workspace_root": workspace}),
        );
        let Some(job) = next.result.get("job").filter(|value| !value.is_null()) else {
            break;
        };
        let analysis = job["analysis_text"].as_str().unwrap_or_default();
        let excerpt = analysis
            .lines()
            .take(80)
            .map(|line| format!("> {line}"))
            .collect::<Vec<_>>()
            .join("\n");
        execute_run(
            &context,
            OperationId::SummaryAccept,
            &run_id,
            &format!("h05-current-summary-{}", job["packet_id"].as_str().unwrap()),
            json!({
                "workspace_root": workspace,
                "packet_id": job["packet_id"],
                "source_sha256": job["source_sha256"],
                "template_manifest_sha256": job["template_manifest_sha256"],
                "summary_markdown": format!(
                    "# Current GTKG source\n\nRepository: `{}`  \nPath: `{}`\n\n## Static analysis excerpt\n\n{}",
                    job["repo_id"].as_str().unwrap(),
                    job["source_path"].as_str().unwrap(),
                    excerpt
                )
            }),
        );
    }
    let finalized = execute_run(
        &context,
        OperationId::BuildFinalize,
        &run_id,
        "h05-current-build-finalize",
        json!({"workspace_root": workspace}),
    );
    let bundle_path = PathBuf::from(finalized.result["bundle_path"].as_str().unwrap());
    let bundle_tree_sha256 = finalized.result["tree_digest"].as_str().unwrap();
    assert_eq!(tree_sha256(&bundle_path).unwrap(), bundle_tree_sha256);

    let a2ui_manifest_sha256 = sha256_file(&a2ui_catalog.join("manifest.json")).unwrap();
    let a2ui_resolution = execute(
        &context,
        OperationId::A2uiResolve,
        "h05-current-a2ui-resolve",
        json!({
            "workspace_root": workspace,
            "catalog_root": a2ui_catalog,
            "spec_version": "0.9.1",
            "profile_id": "gtkg-test-profile",
            "profile_version": "0.9.1",
            "catalog_id": "gtkg-test-catalog",
            "catalog_version": "0.1.0",
            "renderer_id": "official-a2ui-lit",
            "renderer_version": "0.10.3",
            "expected_manifest_sha256": a2ui_manifest_sha256
        }),
    );
    let generated = execute(
        &context,
        OperationId::A2uiGenerate,
        "h05-current-a2ui-generate",
        json!({
            "workspace_root": workspace,
            "bundle_path": bundle_path,
            "expected_bundle_tree_sha256": bundle_tree_sha256,
            "resolution_ref": a2ui_resolution.result["resolution_ref"],
            "projection_version": "0.5.0-h05-current"
        }),
    );
    assert_eq!(generated.result["resource_count"], admitted_count);
    assert_eq!(generated.result["evidence_state"], "a2ui_generatable");
    let projection = PathBuf::from(generated.result["projection_path"].as_str().unwrap());
    let stream_path = projection.join("a2ui/stream.jsonl");
    let generation_receipt_path =
        workspace.join(generated.result["generation_ref"]["path"].as_str().unwrap());
    let receipt = json!({
        "schema_version": "gtkg.h05-current-source-receipt/v1",
        "workspace": workspace,
        "source_snapshot": source_snapshot,
        "source_inspection_ref": source_inspection_ref,
        "source_lock_sha256": inspected.result["source_lock_digest"],
        "source_file_count": source_file_count,
        "admitted_source_count": admitted_count,
        "omission_count": omission_count,
        "omissions": inspected.result["omissions"],
        "bundle_path": bundle_path,
        "bundle_tree_sha256": bundle_tree_sha256,
        "generation_ref": generated.result["generation_ref"],
        "generation_receipt_path": generation_receipt_path,
        "projection_path": projection.clone(),
        "projection_tree_sha256": generated.result["projection_tree_sha256"],
        "wiki_path": projection.join("wiki"),
        "stream_path": stream_path,
        "stream_sha256": sha256_file(&stream_path).unwrap(),
        "stream_message_count": fs::read_to_string(&stream_path).unwrap().lines().filter(|line| !line.is_empty()).count(),
        "a2ui_lock": a2ui_resolution.result["a2ui_lock"],
    });
    fs::write(
        root.join("h05-current-source-receipt.json"),
        serde_json::to_vec_pretty(&receipt).unwrap(),
    )
    .unwrap();
}

#[test]
#[ignore = "driven by the G04 shell harness after the locked browser smoke completes"]
fn validate_g04_renderer_replicable_with_browser_evidence() {
    let root = PathBuf::from(
        std::env::var_os("GTKG_G04_BROWSER_OUTPUT")
            .expect("GTKG_G04_BROWSER_OUTPUT must name a completed emitter output"),
    );
    let receipt: Value =
        serde_json::from_slice(&fs::read(root.join("g04-browser-fixture-receipt.json")).unwrap())
            .unwrap();
    let workspace = PathBuf::from(receipt["workspace"].as_str().unwrap());

    // The frozen fixture on disk must still match the emitted tree digest exactly.
    let frozen = root.join("frozen-wiki");
    assert_eq!(
        tree_sha256(&frozen).unwrap(),
        receipt["frozen"]["tree_sha256"]
    );

    let evidence_dir = workspace.join(".gtkg/a2ui/browser-evidence");
    let smoke_files: Vec<_> = fs::read_dir(&evidence_dir)
        .expect("harness must publish the smoke evidence receipt")
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("smoke-") && name.ends_with(".json"))
        })
        .collect();
    assert_eq!(
        smoke_files.len(),
        1,
        "exactly one smoke evidence receipt must exist"
    );
    let smoke_path = smoke_files.first().unwrap();
    let smoke_ref = json!({
        "path": smoke_path.strip_prefix(&workspace).unwrap().to_string_lossy().replace('\\', "/"),
        "sha256": sha256_file(smoke_path).unwrap(),
    });
    let smoke: Value = serde_json::from_slice(&fs::read(smoke_path).unwrap()).unwrap();
    assert_eq!(smoke["schema_version"], "gtkg.a2ui-renderer-smoke/v1");

    let context = CallContext::restricted(
        TransportKind::Test,
        vec![root.clone()],
        EffectPolicy::WorkspaceWrite,
    )
    .unwrap();
    let granted = execute(
        &context,
        OperationId::A2uiValidate,
        "g04-browser-a2ui-validate-renderer-replicable",
        json!({
            "workspace_root": workspace,
            "generation_ref": receipt["generation_ref"],
            "expected_projection_tree_sha256": receipt["projection_tree_sha256"],
            "required_evidence_state": "renderer_replicable",
            "renderer_smoke_ref": smoke_ref,
        }),
    );
    assert_eq!(granted.result["valid"], true);
    assert_eq!(granted.result["checks"]["renderer_smoke"], "passed");
    assert_eq!(granted.result["checks"]["visual_threshold"], "passed");
    assert_eq!(
        granted.result["observed_evidence_state"],
        "renderer_replicable"
    );

    let replica = Dispatcher
        .execute(
            &context,
            OperationRequest::new(
                OperationId::A2uiValidate,
                "g04-browser-a2ui-validate-verified-replica",
                json!({
                    "workspace_root": workspace,
                    "generation_ref": receipt["generation_ref"],
                    "expected_projection_tree_sha256": receipt["projection_tree_sha256"],
                    "required_evidence_state": "verified_replica",
                    "renderer_smoke_ref": smoke_ref,
                }),
            ),
        )
        .expect_err("verified_replica must stay fail-closed");
    assert_eq!(replica.error.code, ErrorCode::InvalidState);
}

fn execute(
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

fn execute_run(
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
        .unwrap_or_else(|error| {
            panic!(
                "{} failed at {}: {}",
                operation.as_str(),
                error.error.stage,
                error.error.message
            )
        })
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
            "status": "fixture_not_production",
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
        "scope": "local_test_catalog"
    });
    fs::write(
        root.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();
}

fn create_h05_a2ui_catalog(root: &Path) {
    create_a2ui_catalog(root);
    fs::write(
        root.join("renderer.json"),
        serde_json::to_vec_pretty(&json!({
            "schema_version": "gtkg.a2ui-renderer-contract/v1",
            "id": "official-a2ui-lit",
            "version": "0.10.3",
            "status": "official_package_runtime",
            "catalog_id": "gtkg-test-catalog",
            "catalog_version": "0.1.0",
            "supported_components": ["Button", "Column", "List", "Row", "Text"],
            "supported_actions": ["gtkg.select_document"]
        }))
        .unwrap(),
    )
    .unwrap();
    let mut manifest: Value =
        serde_json::from_slice(&fs::read(root.join("manifest.json")).unwrap()).unwrap();
    manifest["renderer"] = json!({
        "id": "official-a2ui-lit",
        "version": "0.10.3",
        "path": "renderer.json",
        "sha256": sha256_file(&root.join("renderer.json")).unwrap()
    });
    manifest["scope"] =
        Value::String("official_basic_catalog_with_official_lit_runtime".to_owned());
    fs::write(
        root.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();
}

fn snapshot_current_repository(source: &Path, destination: &Path, output_root: &Path) -> Value {
    let baseline_commit = String::from_utf8(git_capture(source, &["rev-parse", "HEAD"]))
        .unwrap()
        .trim()
        .to_owned();
    let tracked_patch = git_capture(source, &["diff", "--binary", "HEAD", "--"]);
    let status = git_capture(
        source,
        &[
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
            "--ignore-submodules=none",
        ],
    );
    let listed = git_capture(
        source,
        &[
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
        ],
    );
    let untracked = git_capture(
        source,
        &["ls-files", "-z", "--others", "--exclude-standard"],
    );
    let untracked = nul_paths(&untracked).into_iter().collect::<BTreeSet<_>>();
    let mut paths = nul_paths(&listed);
    paths.sort();
    paths.dedup();
    paths.retain(|path| {
        path != "TaskList.md"
            && path != "loop-review.md"
            && path != "deliverables/h05-official-renderer"
            && !path.starts_with("deliverables/h05-official-renderer/")
    });
    fs::create_dir_all(destination).unwrap();
    let mut files = Vec::with_capacity(paths.len());
    let mut untracked_files = Vec::new();
    for relative in paths {
        let relative_path = Path::new(&relative);
        assert!(
            relative_path
                .components()
                .all(|component| matches!(component, std::path::Component::Normal(_))),
            "unsafe source snapshot path: {relative}"
        );
        let from = source.join(relative_path);
        let metadata = fs::symlink_metadata(&from).unwrap();
        assert!(metadata.is_file() && !metadata.file_type().is_symlink());
        let to = destination.join(relative_path);
        fs::create_dir_all(to.parent().unwrap()).unwrap();
        fs::copy(&from, &to).unwrap();
        let record = json!({
            "path": relative,
            "bytes": metadata.len(),
            "sha256": sha256_file(&from).unwrap(),
        });
        if untracked.contains(record["path"].as_str().unwrap()) {
            untracked_files.push(record.clone());
        }
        files.push(record);
    }
    let manifest = json!({
        "schema_version": "gtkg.current-source-manifest/v1",
        "source_state": if status.is_empty() { "clean_snapshot" } else { "dirty_snapshot" },
        "baseline_commit": baseline_commit,
        "tracked_patch_sha256": sha256_bytes(&tracked_patch),
        "git_status_sha256": sha256_bytes(&status),
        "untracked_manifest_sha256": gtkg_protocol::canonical_json_sha256(&untracked_files).unwrap(),
        "excluded_paths": ["TaskList.md", "loop-review.md", "deliverables/h05-official-renderer"],
        "files": files,
    });
    let manifest_path = output_root.join("current-source-manifest.json");
    fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();
    let manifest_sha256 = sha256_file(&manifest_path).unwrap();
    init_and_commit(destination);
    let snapshot_commit = String::from_utf8(git_capture(destination, &["rev-parse", "HEAD"]))
        .unwrap()
        .trim()
        .to_owned();
    let snapshot_tree = String::from_utf8(git_capture(destination, &["rev-parse", "HEAD^{tree}"]))
        .unwrap()
        .trim()
        .to_owned();
    json!({
        "state": manifest["source_state"],
        "baseline_commit": baseline_commit,
        "tracked_patch_sha256": manifest["tracked_patch_sha256"],
        "git_status_sha256": manifest["git_status_sha256"],
        "untracked_manifest_sha256": manifest["untracked_manifest_sha256"],
        "current_source_manifest_path": manifest_path,
        "current_source_manifest_sha256": manifest_sha256,
        "source_file_count": manifest["files"].as_array().unwrap().len(),
        "excluded_paths": manifest["excluded_paths"],
        "snapshot_commit": snapshot_commit,
        "snapshot_tree": snapshot_tree,
    })
}

fn nul_paths(bytes: &[u8]) -> Vec<String> {
    bytes
        .split(|byte| *byte == 0)
        .filter(|value| !value.is_empty())
        .map(|value| std::str::from_utf8(value).unwrap().to_owned())
        .collect()
}

fn git_capture(root: &Path, arguments: &[&str]) -> Vec<u8> {
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
    output.stdout
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn create_template_catalog(catalog: &Path) {
    let staging = catalog.join("summary-template/versions/staging");
    fs::create_dir_all(&staging).unwrap();
    let template = staging.join("template.md");
    fs::write(
        &template,
        "---\ntype: template\ntitle: Summary\ndescription: Deterministic static analysis summary template\nresource: ./template.md\ntags: [fixture]\nstatus: stable\nokf_version: '0.2'\ngtkg:\n  schema: gtkg.template/v1\n---\n\n# Summary\n",
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
    let digest = gtkg_protocol::canonical_json_sha256(&manifest).unwrap();
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
