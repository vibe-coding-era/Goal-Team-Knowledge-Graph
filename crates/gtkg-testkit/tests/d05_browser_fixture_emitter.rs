use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use gtkg_core::a2ui::{WikiRenderResource, plan_wiki_shards, render_wiki_test_projection};
use gtkg_core::file_model::{sha256_file, tree_sha256};
use gtkg_core::{CallContext, Dispatcher, EffectPolicy, TransportKind};
use gtkg_protocol::{OperationId, OperationRequest, OperationResponse, canonical_json_sha256};
use serde_json::{Value, json};

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
#[ignore = "emits the persistent file:// browser fixture selected by GTKG_D05_BROWSER_OUTPUT"]
fn emit_d05_file_wiki_browser_fixture() {
    let root = PathBuf::from(
        std::env::var_os("GTKG_D05_BROWSER_OUTPUT")
            .expect("GTKG_D05_BROWSER_OUTPUT must name a new empty directory"),
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
        "d05-browser-source-inspect",
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
        "d05-browser-template-resolve",
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
        "d05-browser-template-validate",
        json!({
            "workspace_root": workspace,
            "resolution_ref": template_resolution.result["resolution_ref"]
        }),
    );
    let template_validation_ref = template_validation.result["validation_ref"].clone();
    let mut plan_request = OperationRequest::new(
        OperationId::BuildPlan,
        "d05-browser-build-plan",
        json!({
            "workspace_root": workspace,
            "mode": "full",
            "source_inspection_ref": source_inspection_ref,
            "template_validation_ref": template_validation_ref,
            "baseline_bundle": null,
            "bundle_version": "51.0.0-browser"
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
        "d05-browser-build-prepare",
        json!({"workspace_root": workspace}),
    );
    loop {
        let next = execute_run(
            &context,
            OperationId::SummaryNext,
            &run_id,
            "d05-browser-summary-next",
            json!({"workspace_root": workspace}),
        );
        let Some(job) = next.result.get("job").filter(|value| !value.is_null()) else {
            break;
        };
        execute_run(
            &context,
            OperationId::SummaryAccept,
            &run_id,
            &format!("d05-browser-summary-{}", job["packet_id"].as_str().unwrap()),
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
        "d05-browser-build-finalize",
        json!({"workspace_root": workspace}),
    );
    let bundle_path = PathBuf::from(finalized.result["bundle_path"].as_str().unwrap());
    let bundle_tree_sha256 = finalized.result["tree_digest"].as_str().unwrap();
    assert_eq!(tree_sha256(&bundle_path).unwrap(), bundle_tree_sha256);

    let a2ui_manifest_sha256 = sha256_file(&a2ui_catalog.join("manifest.json")).unwrap();
    let a2ui_resolution = execute(
        &context,
        OperationId::A2uiResolve,
        "d05-browser-a2ui-resolve",
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
    let generated = execute(
        &context,
        OperationId::A2uiGenerate,
        "d05-browser-a2ui-generate",
        json!({
            "workspace_root": workspace,
            "bundle_path": bundle_path,
            "expected_bundle_tree_sha256": bundle_tree_sha256,
            "resolution_ref": a2ui_resolution.result["resolution_ref"],
            "projection_version": "51.0.0-browser"
        }),
    );
    let generation_receipt = read_receipt(&workspace, &generated.result["generation_ref"]);
    assert_eq!(
        generation_receipt["canonical_bundle_tree_sha256"],
        bundle_tree_sha256
    );
    assert_eq!(
        generation_receipt["artifact_manifest_sha256"],
        sha256_file(&bundle_path.join("artifact-manifest.json")).unwrap()
    );
    assert_eq!(
        generation_receipt["source_lock_sha256"],
        sha256_file(&bundle_path.join("locks/source-lock.json")).unwrap()
    );
    let validated = execute(
        &context,
        OperationId::A2uiValidate,
        "d05-browser-a2ui-validate",
        json!({
            "workspace_root": workspace,
            "generation_ref": generated.result["generation_ref"],
            "expected_projection_tree_sha256": generated.result["projection_tree_sha256"],
            "required_evidence_state": "a2ui_generatable"
        }),
    );
    let validation_receipt = read_receipt(&workspace, &validated.result["validation_ref"]);
    assert_eq!(validated.result["valid"], true);
    assert_eq!(
        generated.result["canonical_bundle_tree_sha256"],
        bundle_tree_sha256
    );
    assert_eq!(
        validation_receipt["projection_tree_sha256"],
        generated.result["projection_tree_sha256"]
    );

    let scale_projection = root.join("scale-browser-projection");
    fs::create_dir(&scale_projection).unwrap();
    let mut resources = Vec::with_capacity(10_001);
    for index in 0..10_001_u64 {
        resources.push(WikiRenderResource {
            id: format!("browser-resource-{index:05}"),
            logical_path: format!("scale/docs/{index:05}.md"),
            title: format!("Knowledge item {index:05}"),
            content: if index == 0 {
                "# Browser selected\n<img src=x onerror=globalThis.__GTKG_XSS_SENTINEL__=true> <script>globalThis.__GTKG_XSS_SENTINEL__=true</script> [bad](javascript:alert(1)) <svg><foreignObject>bad</foreignObject></svg>".to_owned()
            } else if index == 10_000 {
                "Production renderer boundary content".to_owned()
            } else {
                format!("Scale browser projection content {index:05}")
            },
        });
    }
    let selected = resources.first().unwrap();
    let expected_last = resources.last().unwrap();
    render_wiki_test_projection(&context, &scale_projection, &resources, &selected.id)
        .expect("production Wiki renderer must emit the scale projection");
    let shard_plan = plan_wiki_shards(resources.len());
    let expected_last_shard = shard_plan.last().unwrap();
    let wiki_index = scale_projection.join("wiki/index.html");
    let scale_tree_sha256 = tree_sha256(&scale_projection).unwrap();
    let wiki_manifest_sha256 =
        sha256_file(&scale_projection.join("wiki/wiki-manifest.json")).unwrap();
    let receipt = json!({
        "schema_version": "gtkg.d05-browser-fixture-receipt/v2",
        "real_integration": {
            "source_inspection_ref": source_inspection_ref,
            "canonical_bundle_path": bundle_path,
            "canonical_bundle_tree_sha256": bundle_tree_sha256,
            "artifact_manifest_sha256": generation_receipt["artifact_manifest_sha256"],
            "source_lock_sha256": generation_receipt["source_lock_sha256"],
            "generation_ref": generated.result["generation_ref"],
            "generation_projection_path": generated.result["projection_path"],
            "generation_projection_tree_sha256": generated.result["projection_tree_sha256"],
            "validation_ref": validated.result["validation_ref"],
            "validated_against_projection_tree_sha256": validation_receipt["projection_tree_sha256"],
            "validation_checks": validated.result["checks"],
            "validated": validated.result["valid"],
            "executed_target_content": generated.result["executed_target_content"],
        },
        "scale_browser_projection": {
            "provenance": "test-only scale data rendered by the production Wiki renderer; resources are not claimed as canonical bundle content",
            "wiki_index": wiki_index,
            "file_url": format!("file://{}", wiki_index.display()),
            "tree_sha256": scale_tree_sha256,
            "wiki_manifest_sha256": wiki_manifest_sha256,
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
        root.join("browser-fixture-receipt.json"),
        serde_json::to_vec_pretty(&receipt).unwrap(),
    )
    .unwrap();
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

fn read_receipt(workspace: &Path, reference: &Value) -> Value {
    let path = workspace.join(reference["path"].as_str().unwrap());
    assert_eq!(sha256_file(&path).unwrap(), reference["sha256"]);
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
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

fn create_template_catalog(catalog: &Path) {
    let staging = catalog.join("summary-template/versions/staging");
    fs::create_dir_all(&staging).unwrap();
    let template = staging.join("template.md");
    fs::write(
        &template,
        "---\ntype: template\ntitle: Summary\ndescription: D05 browser static analysis fixture\nresource: ./template.md\ntags: [fixture]\ngenerated: false\nverified: false\nstatus: validated\nsources: []\nokf_version: '0.2'\ngtkg:\n  schema: gtkg.template/v1\n---\n\n# Summary\n",
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

#[test]
fn emitter_source_is_inert_without_an_explicit_output_directory() {
    assert!(std::env::var_os("GTKG_D05_BROWSER_OUTPUT").is_none());
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap();
    assert!(!workspace.join("browser-fixture-receipt.json").exists());
}
