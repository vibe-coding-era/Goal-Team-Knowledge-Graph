use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use gtkg_core::file_model::{sha256_file, tree_sha256};
use gtkg_core::{CallContext, Dispatcher, EffectPolicy, TransportKind};
use gtkg_protocol::{
    ErrorCode, OperationId, OperationRequest, OperationResponse, OperationStatus,
    canonical_json_sha256,
};
use serde_json::{Value, json};
use tempfile::{TempDir, tempdir};

#[test]
fn twelve_former_pending_operations_have_closed_real_payload_parsers() {
    let fixture = Fixture::new();
    let workspace = fixture.directory("workspace");
    let catalog = fixture.template_catalog();
    let config_path = fixture.valid_config(&workspace, &catalog);
    let current_path = fixture.valid_current();
    let context = fixture.context(EffectPolicy::WorkspaceWrite);

    let cases = [
        (
            OperationId::ConfigValidate,
            json!({"config_path": config_path}),
            None,
        ),
        (
            OperationId::RunCancel,
            json!({"workspace_root": workspace}),
            Some("run-missing"),
        ),
        (
            OperationId::GitPublish,
            json!({
                "workspace_root": workspace,
                "artifact_path": fixture.root.join("artifact"),
                "expected_tree_sha256": digest('1'),
                "repository_root": fixture.root.join("repo"),
                "ref_name": "refs/tags/gtkg-v0.1.0"
            }),
            None,
        ),
        (
            OperationId::CurrentGet,
            json!({
                "current_path": current_path,
                "expected_current_sha256": digest('0')
            }),
            None,
        ),
        (
            OperationId::CurrentActivate,
            json!({
                "workspace_root": workspace,
                "current_root": fixture.root.join("current"),
                "version_path": fixture.root.join("versions/v0.1.0--111111111111"),
                "expected_tree_sha256": digest('2')
            }),
            None,
        ),
        (
            OperationId::TemplateList,
            json!({"catalog_root": catalog}),
            None,
        ),
        (
            OperationId::TemplatePrefetch,
            json!({
                "workspace_root": workspace,
                "resolution_ref": {"path": ".gtkg/missing-resolution.json", "sha256": digest('3')}
            }),
            None,
        ),
        (
            OperationId::TemplateGet,
            json!({
                "workspace_root": workspace,
                "template_ref": {"path": ".gtkg/missing-template.json", "sha256": digest('4')}
            }),
            None,
        ),
        (
            OperationId::TemplateDerive,
            json!({
                "workspace_root": workspace,
                "parent_ref": {"path": ".gtkg/missing-validation.json", "sha256": digest('5')},
                "new_version": "0.2.0",
                "slot_overrides": {"summary": "Human override"}
            }),
            None,
        ),
        (
            OperationId::TemplatePublish,
            json!({
                "workspace_root": workspace,
                "draft_ref": {"path": ".gtkg/template-drafts/draft.json", "sha256": digest('6')},
                "repository_root": fixture.root.join("repo"),
                "version": "0.2.0"
            }),
            None,
        ),
        (
            OperationId::DeliverableDerive,
            json!({
                "workspace_root": workspace,
                "parent_path": fixture.root.join("missing-parent"),
                "expected_parent_tree_sha256": digest('7'),
                "deliverable_id": "knowledge",
                "new_version": "0.2.0",
                "slot_overrides": {"release-notes": "Human note"}
            }),
            None,
        ),
        (
            OperationId::DeliverablePublish,
            json!({
                "workspace_root": workspace,
                "draft_ref": {"path": ".gtkg/deliverable-drafts/draft.json", "sha256": digest('8')},
                "repository_root": fixture.root.join("repo"),
                "version": "0.2.0"
            }),
            None,
        ),
    ];

    for (operation, payload, run_id) in cases {
        let outcome = execute(&context, operation, run_id, payload.clone());
        if let Err(error) = &outcome {
            assert_ne!(
                error.error.code,
                ErrorCode::OperationNotImplemented,
                "{} must have a real handler",
                operation.as_str()
            );
        }

        let mut object = payload.as_object().expect("object payload").clone();
        object.insert("unexpected".to_owned(), Value::Bool(true));
        let error = execute(&context, operation, run_id, Value::Object(object))
            .expect_err("unknown payload field must fail closed");
        assert_eq!(
            error.error.code,
            ErrorCode::InvalidRequest,
            "{} unknown field",
            operation.as_str()
        );
    }
}

#[test]
fn config_and_current_reads_are_exact_digest_bound_and_read_only() {
    let fixture = Fixture::new();
    let workspace = fixture.directory("workspace");
    let catalog = fixture.template_catalog();
    let config_path = fixture.valid_config(&workspace, &catalog);
    let current_path = fixture.valid_current();
    let context = fixture.context(EffectPolicy::ReadOnly);

    let config = execute_ok(
        &context,
        OperationId::ConfigValidate,
        None,
        json!({"config_path": config_path}),
    );
    assert_eq!(config.result["valid"], true);
    assert_eq!(config.result["storage_model"], "okf-and-ordinary-files");
    assert_eq!(config.result["database_backend"], Value::Null);
    assert_eq!(
        config.result["config_sha256"],
        sha256_file(&config_path).expect("config digest")
    );

    let current_digest = sha256_file(&current_path).expect("CURRENT digest");
    let before = fs::read(&current_path).expect("CURRENT bytes");
    let current = execute_ok(
        &context,
        OperationId::CurrentGet,
        None,
        json!({
            "current_path": current_path,
            "expected_current_sha256": current_digest
        }),
    );
    assert_eq!(
        current.result["current"]["schema_version"],
        "gtkg.current/v1"
    );
    assert_eq!(current.result["current_sha256"], current_digest);
    assert_eq!(fs::read(&current_path).expect("CURRENT readback"), before);

    let drift = execute(
        &context,
        OperationId::CurrentGet,
        None,
        json!({
            "current_path": current_path,
            "expected_current_sha256": digest('f')
        }),
    )
    .expect_err("wrong caller-held digest must fail");
    assert_eq!(drift.error.code, ErrorCode::LockMismatch);
}

#[test]
fn template_prefetch_get_and_single_parent_derive_preserve_the_published_parent() {
    let fixture = Fixture::new();
    let workspace = fixture.directory("workspace");
    let catalog = fixture.template_catalog();
    let context = fixture.context(EffectPolicy::WorkspaceWrite);
    let published = only_template_version(&catalog);
    let parent_before = tree_sha256(&published).expect("parent tree digest");

    let listed = execute_ok(
        &context,
        OperationId::TemplateList,
        None,
        json!({"catalog_root": catalog}),
    );
    assert_eq!(
        listed.result["templates"]
            .as_array()
            .expect("templates")
            .len(),
        1
    );
    assert_eq!(
        listed.result["templates"][0]["template_id"],
        "summary-template"
    );
    assert_eq!(
        listed.result["templates"][0]["versions"][0]["version"],
        "0.1.0"
    );

    let resolved = execute_ok(
        &context,
        OperationId::TemplateResolve,
        None,
        json!({
            "workspace_root": workspace,
            "catalog_root": catalog,
            "template_id": "summary-template",
            "version": "0.1.0"
        }),
    );
    let validated = execute_ok(
        &context,
        OperationId::TemplateValidate,
        None,
        json!({
            "workspace_root": workspace,
            "resolution_ref": resolved.result["resolution_ref"]
        }),
    );
    let prefetched = execute_ok(
        &context,
        OperationId::TemplatePrefetch,
        None,
        json!({
            "workspace_root": workspace,
            "resolution_ref": resolved.result["resolution_ref"]
        }),
    );
    assert_eq!(prefetched.result["cache_hit"], false);
    let prefetched_again = execute_ok(
        &context,
        OperationId::TemplatePrefetch,
        None,
        json!({
            "workspace_root": workspace,
            "resolution_ref": resolved.result["resolution_ref"]
        }),
    );
    assert_eq!(prefetched_again.result["cache_hit"], true);
    assert_eq!(
        prefetched_again.result["cache_ref"],
        prefetched.result["cache_ref"]
    );

    let fetched = execute_ok(
        &context,
        OperationId::TemplateGet,
        None,
        json!({
            "workspace_root": workspace,
            "template_ref": prefetched.result["cache_ref"]
        }),
    );
    assert_eq!(
        fetched.result["manifest"]["template_id"],
        "summary-template"
    );
    assert!(
        fetched.result["template_markdown"]
            .as_str()
            .expect("template markdown")
            .contains("# Summary")
    );

    let derived = execute_ok(
        &context,
        OperationId::TemplateDerive,
        None,
        json!({
            "workspace_root": workspace,
            "parent_ref": validated.result["validation_ref"],
            "new_version": "0.2.0",
            "slot_overrides": {"summary": "Human override"}
        }),
    );
    assert_eq!(derived.result["status"], "draft");
    assert_eq!(derived.result["verified"], false);
    assert_eq!(
        derived.result["parent_manifest_sha256"],
        validated.result["manifest_sha256"]
    );
    assert!(
        derived.result["draft_ref"]["sha256"]
            .as_str()
            .is_some_and(|value| value.starts_with("sha256:"))
    );
    assert_eq!(
        tree_sha256(&published).expect("parent readback"),
        parent_before
    );
}

#[test]
fn deliverable_derive_is_a_single_parent_draft_and_publish_is_denied_without_external_grant() {
    let fixture = Fixture::new();
    let workspace = fixture.directory("workspace");
    let parent = fixture.directory("deliverables/knowledge/versions/v0.1.0--parent000000");
    fs::write(parent.join("index.md"), "# Parent\n").expect("parent index");
    fs::write(parent.join("artifact-manifest.json"), b"{}\n").expect("parent manifest");
    let parent_tree = tree_sha256(&parent).expect("parent digest");
    let context = fixture.context(EffectPolicy::WorkspaceWrite);

    let derived = execute_ok(
        &context,
        OperationId::DeliverableDerive,
        None,
        json!({
            "workspace_root": workspace,
            "parent_path": parent,
            "expected_parent_tree_sha256": parent_tree,
            "deliverable_id": "knowledge",
            "new_version": "0.2.0",
            "slot_overrides": {"release-notes": "Human note"}
        }),
    );
    assert_eq!(derived.result["status"], "draft");
    assert_eq!(derived.result["verified"], false);
    assert_eq!(derived.result["parent_tree_sha256"], parent_tree);
    assert_eq!(tree_sha256(&parent).expect("parent readback"), parent_tree);

    let error = execute(
        &context,
        OperationId::DeliverablePublish,
        None,
        json!({
            "workspace_root": workspace,
            "draft_ref": derived.result["draft_ref"],
            "repository_root": fixture.root.join("artifact-repository"),
            "version": "0.2.0"
        }),
    )
    .expect_err("publish requires explicit external grant");
    assert_eq!(error.error.code, ErrorCode::SideEffectDenied);
}

#[test]
fn run_cancel_is_terminal_idempotent_and_run_get_never_repairs_stale_projection() {
    let fixture = Fixture::new();
    let workspace = fixture.directory("workspace");
    let repo = fixture.git_repo();
    let catalog = fixture.template_catalog();
    let context = fixture.context(EffectPolicy::WorkspaceWrite);

    let source = execute_ok(
        &context,
        OperationId::SourceInspect,
        None,
        json!({
            "workspace_root": workspace,
            "repositories": [{
                "repo_id": "source",
                "path": repo,
                "role": "documentation",
                "include": []
            }]
        }),
    );
    let resolved = execute_ok(
        &context,
        OperationId::TemplateResolve,
        None,
        json!({
            "workspace_root": workspace,
            "catalog_root": catalog,
            "template_id": "summary-template",
            "version": "0.1.0"
        }),
    );
    let validated = execute_ok(
        &context,
        OperationId::TemplateValidate,
        None,
        json!({
            "workspace_root": workspace,
            "resolution_ref": resolved.result["resolution_ref"]
        }),
    );
    let mut plan_request = OperationRequest::new(
        OperationId::BuildPlan,
        "d06-plan",
        json!({
            "workspace_root": workspace,
            "mode": "full",
            "source_inspection_ref": source.result["source_inspection_ref"],
            "template_validation_ref": validated.result["validation_ref"],
            "bundle_version": "0.1.0"
        }),
    );
    plan_request.locks = BTreeMap::from([
        (
            "source_inspection".to_owned(),
            source.result["source_inspection_ref"]["sha256"]
                .as_str()
                .expect("source digest")
                .to_owned(),
        ),
        (
            "template_validation".to_owned(),
            validated.result["validation_ref"]["sha256"]
                .as_str()
                .expect("template digest")
                .to_owned(),
        ),
    ]);
    let planned = Dispatcher
        .execute(&context, plan_request)
        .unwrap_or_else(|error| panic!("build.plan failed: {error:#?}"));
    let run_id = planned.run_id.expect("run id");
    let run_dir = workspace.join(".gtkg/runs").join(&run_id);

    let cancelled = execute_ok(
        &context,
        OperationId::RunCancel,
        Some(&run_id),
        json!({"workspace_root": workspace}),
    );
    assert_eq!(cancelled.status, OperationStatus::Cancelled);
    assert_eq!(cancelled.result["state"], "cancelled");
    let event_bytes = fs::read(run_dir.join("events.ndjson")).expect("cancel ledger");

    let replay = execute_ok(
        &context,
        OperationId::RunCancel,
        Some(&run_id),
        json!({"workspace_root": workspace}),
    );
    assert_eq!(replay.status, OperationStatus::Cancelled);
    assert_eq!(
        fs::read(run_dir.join("events.ndjson")).expect("replayed ledger"),
        event_bytes
    );

    fs::remove_file(run_dir.join("state.json")).expect("remove projection");
    let read_only = fixture.context(EffectPolicy::ReadOnly);
    let status = execute_ok(
        &read_only,
        OperationId::RunGet,
        Some(&run_id),
        json!({"workspace_root": workspace}),
    );
    assert_eq!(status.result["state"]["state"], "cancelled");
    assert_eq!(status.result["projected_stale"], true);
    assert!(!run_dir.join("state.json").exists());

    let blocked = execute(
        &context,
        OperationId::BuildPrepare,
        Some(&run_id),
        json!({"workspace_root": workspace}),
    )
    .expect_err("cancelled run is terminal");
    assert_eq!(blocked.error.code, ErrorCode::InvalidState);
}

struct Fixture {
    _temp: TempDir,
    root: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let temp = tempdir().expect("fixture root");
        let root = temp.path().to_path_buf();
        Self { _temp: temp, root }
    }

    fn context(&self, policy: EffectPolicy) -> CallContext {
        CallContext::restricted(TransportKind::Test, vec![self.root.clone()], policy)
            .expect("restricted context")
    }

    fn directory(&self, relative: &str) -> PathBuf {
        let path = self.root.join(relative);
        fs::create_dir_all(&path).expect("fixture directory");
        path
    }

    fn git_repo(&self) -> PathBuf {
        let path = self.directory("source-repo");
        git(&path, &["init"]);
        git(&path, &["config", "user.name", "GTKG Fixture"]);
        git(&path, &["config", "user.email", "fixture@invalid.example"]);
        fs::write(path.join("README.md"), "# Source\n").expect("source");
        git(&path, &["add", "-A"]);
        git(&path, &["commit", "-m", "fixture"]);
        path
    }

    fn template_catalog(&self) -> PathBuf {
        let catalog = self.directory("template-catalog");
        let staging = catalog.join("summary-template/versions/staging");
        fs::create_dir_all(&staging).expect("template staging");
        let template_path = staging.join("template.md");
        fs::write(
            &template_path,
            "---\ntype: template\ntitle: Summary\ndescription: Summary fixture\nresource: ./template.md\ntags: [fixture]\ngenerated: false\nverified: false\nstatus: validated\nsources: []\nokf_version: '0.2'\ngtkg:\n  schema: gtkg.template/v1\n---\n\n# Summary\n",
        )
        .expect("template body");
        let manifest = json!({
            "schema_version": "gtkg.template-manifest/v1",
            "template_id": "summary-template",
            "version": "0.1.0",
            "template_file": "template.md",
            "template_sha256": sha256_file(&template_path).expect("template digest"),
            "slot_ids": ["summary"]
        });
        write_json(&staging.join("template-manifest.json"), &manifest);
        let digest = canonical_json_sha256(&manifest).expect("manifest digest");
        let version = staging
            .parent()
            .expect("versions")
            .join(format!("v0.1.0--{}", &digest[7..19]));
        fs::rename(staging, version).expect("publish template fixture");
        catalog
    }

    fn valid_config(&self, workspace: &Path, catalog: &Path) -> PathBuf {
        let repo = self.directory("configured-repo");
        let config = json!({
            "schema_version": "gtkg.config/v1",
            "workspace_root": workspace,
            "storage_model": "okf-and-ordinary-files",
            "database_backend": null,
            "repository_roots": [repo],
            "template_catalog_roots": [catalog],
            "node_endpoints": [{
                "node_id": "local-worker",
                "transport": "exec",
                "endpoint": "gtkg"
            }]
        });
        let path = self.root.join("gtkg-config.json");
        write_json(&path, &config);
        path
    }

    fn valid_current(&self) -> PathBuf {
        let path = self.root.join("CURRENT.json");
        write_json(
            &path,
            &json!({
                "schema_version": "gtkg.current/v1",
                "deliverable_id": "knowledge",
                "version": "0.1.0",
                "version_path": "versions/v0.1.0--111111111111",
                "tree_sha256": digest('1'),
                "manifest_sha256": digest('2')
            }),
        );
        path
    }
}

fn execute(
    context: &CallContext,
    operation: OperationId,
    run_id: Option<&str>,
    payload: Value,
) -> Result<OperationResponse, gtkg_protocol::ErrorEnvelope> {
    let mut request =
        OperationRequest::new(operation, format!("d06-{}", operation.as_str()), payload);
    request.run_id = run_id.map(str::to_owned);
    Dispatcher.execute(context, request)
}

fn execute_ok(
    context: &CallContext,
    operation: OperationId,
    run_id: Option<&str>,
    payload: Value,
) -> OperationResponse {
    execute(context, operation, run_id, payload)
        .unwrap_or_else(|error| panic!("{} failed: {error:#?}", operation.as_str()))
}

fn only_template_version(catalog: &Path) -> PathBuf {
    fs::read_dir(catalog.join("summary-template/versions"))
        .expect("versions")
        .next()
        .expect("one version")
        .expect("version entry")
        .path()
}

fn write_json(path: &Path, value: &Value) {
    fs::write(path, serde_json::to_vec_pretty(value).expect("JSON bytes")).expect("write JSON");
}

fn git(root: &Path, args: &[&str]) {
    let output = Command::new("/usr/bin/git")
        .arg("-C")
        .arg(root)
        .args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .output()
        .expect("run fixture git");
    assert!(
        output.status.success(),
        "git {} failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn digest(fill: char) -> String {
    format!("sha256:{}", fill.to_string().repeat(64))
}
