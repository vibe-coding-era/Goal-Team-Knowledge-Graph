use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use gtkg_core::file_model::sha256_file;
use gtkg_core::{CallContext, Dispatcher, EffectPolicy, TransportKind};
use gtkg_protocol::{ErrorCode, OperationId, OperationRequest, canonical_json_sha256};
use serde_json::{Value, json};
use tempfile::{TempDir, tempdir};

#[test]
fn event_ledger_recovers_missing_head_and_stale_state_on_next_mutation() {
    let fixture = Fixture::new();
    let context = fixture.context();
    let accepted = prepare_and_accept(&fixture, &context, "10.0.0");
    let run = fixture.workspace.join(".gtkg/runs").join(&accepted.run_id);
    let head = run.join("acceptance-head.json");
    let state = run.join("state.json");
    fs::remove_file(&head).expect("fault: head missing after durable event");
    let mut stale: Value = read_json(&state);
    stale["state"] = json!("awaiting_summary");
    stale["accepted_summaries"] = json!(0);
    write_json(&state, &stale);
    let state_before_get = fs::read(&state).expect("stale state bytes");

    let observed = execute_ok_run(
        &context,
        OperationId::RunGet,
        Some(&accepted.run_id),
        json!({"workspace_root": fixture.workspace}),
    );
    assert_eq!(observed.result["projected_stale"], true);
    assert_eq!(
        fs::read(&state).expect("state after read"),
        state_before_get
    );
    assert!(!head.exists(), "run.get must not repair projections");

    execute_ok_run(
        &context,
        OperationId::SummaryAccept,
        Some(&accepted.run_id),
        json!({
            "workspace_root": fixture.workspace,
            "packet_id": accepted.packet_id,
            "source_sha256": accepted.source_sha256,
            "template_manifest_sha256": accepted.template_sha256,
            "summary_markdown": "accepted summary"
        }),
    );
    let repaired: Value = read_json(&state);
    assert_eq!(repaired["state"], "ready_to_finalize");
    assert_eq!(repaired["accepted_summaries"], 1);
    assert!(
        head.is_file(),
        "mutating replay must rebuild the head projection"
    );
}

#[test]
fn every_bundle_consumer_requires_a_full_external_tree_digest() {
    let fixture = Fixture::new();
    let context = fixture.context();
    let finalized = finalize(&fixture, &context, "10.1.0");

    for (operation, payload) in [
        (
            OperationId::BundleVerify,
            json!({"bundle_path": finalized.bundle}),
        ),
        (
            OperationId::BundleQuery,
            json!({"bundle_path": finalized.bundle, "query": "accepted"}),
        ),
        (
            OperationId::BundleCompare,
            json!({"left_bundle": finalized.bundle, "right_bundle": finalized.bundle}),
        ),
        (
            OperationId::SnapshotCreate,
            json!({
                "workspace_root": fixture.workspace,
                "bundle_path": finalized.bundle,
                "snapshot_version": "10.1.0"
            }),
        ),
    ] {
        assert_eq!(
            execute_error(&context, operation, payload),
            ErrorCode::LockMismatch,
            "{} must require a full external digest",
            operation.as_str()
        );
    }

    execute_ok(
        &context,
        OperationId::BundleVerify,
        json!({
            "bundle_path": finalized.bundle,
            "expected_tree_sha256": finalized.tree_digest
        }),
    );
    execute_ok(
        &context,
        OperationId::BundleQuery,
        json!({
            "bundle_path": finalized.bundle,
            "expected_tree_sha256": finalized.tree_digest,
            "query": "accepted"
        }),
    );
    execute_ok(
        &context,
        OperationId::BundleCompare,
        json!({
            "left_bundle": finalized.bundle,
            "left_expected_tree_sha256": finalized.tree_digest,
            "right_bundle": finalized.bundle,
            "right_expected_tree_sha256": finalized.tree_digest
        }),
    );
    let snapshot = execute_ok(
        &context,
        OperationId::SnapshotCreate,
        json!({
            "workspace_root": fixture.workspace,
            "bundle_path": finalized.bundle,
            "expected_bundle_tree_sha256": finalized.tree_digest,
            "snapshot_version": "10.1.0"
        }),
    );
    let snapshot_path = snapshot.result["snapshot_path"].clone();
    let snapshot_digest = snapshot.result["tree_digest"].clone();
    assert_eq!(
        execute_error(
            &context,
            OperationId::SnapshotVerify,
            json!({"snapshot_path": snapshot_path})
        ),
        ErrorCode::LockMismatch
    );
    execute_ok(
        &context,
        OperationId::SnapshotVerify,
        json!({
            "snapshot_path": snapshot_path,
            "expected_snapshot_tree_sha256": snapshot_digest
        }),
    );
    assert_eq!(
        execute_error(
            &context,
            OperationId::SnapshotRestore,
            json!({
                "workspace_root": fixture.workspace,
                "snapshot_path": snapshot_path,
                "restore_version": "10.1.0"
            })
        ),
        ErrorCode::LockMismatch
    );
    execute_ok(
        &context,
        OperationId::SnapshotRestore,
        json!({
            "workspace_root": fixture.workspace,
            "snapshot_path": snapshot_path,
            "expected_snapshot_tree_sha256": snapshot_digest,
            "restore_version": "10.1.0"
        }),
    );
}

#[test]
fn incremental_baseline_requires_the_callers_full_tree_digest() {
    let fixture = Fixture::new();
    let context = fixture.context();
    let finalized = finalize(&fixture, &context, "10.2.0");
    let receipts = inspect_and_validate(&fixture, &context);

    let missing = plan_request(
        &fixture.workspace,
        "incremental",
        &receipts,
        Some(&finalized.bundle),
        None,
        "10.2.1",
    );
    assert_eq!(
        Dispatcher
            .execute(&context, missing)
            .expect_err("missing baseline digest")
            .error
            .code,
        ErrorCode::LockMismatch
    );
    Dispatcher
        .execute(
            &context,
            plan_request(
                &fixture.workspace,
                "incremental",
                &receipts,
                Some(&finalized.bundle),
                Some(&finalized.tree_digest),
                "10.2.1",
            ),
        )
        .expect("digest-bound incremental plan");
}

#[test]
fn stale_request_staging_is_quarantined_and_retry_can_publish() {
    let fixture = Fixture::new();
    let context = fixture.context();
    let accepted = prepare_and_accept(&fixture, &context, "10.3.0");
    let run = fixture.workspace.join(".gtkg/runs").join(&accepted.run_id);
    let stale = run.join("bundle-staging");
    fs::create_dir_all(&stale).expect("stale staging");
    fs::write(stale.join("partial"), "crash residue").expect("partial staging");

    let finalized = execute_ok_run(
        &context,
        OperationId::BuildFinalize,
        Some(&accepted.run_id),
        json!({"workspace_root": fixture.workspace}),
    );
    let bundle = PathBuf::from(finalized.result["bundle_path"].as_str().expect("bundle"));
    assert!(bundle.is_dir());
    assert!(!bundle.join("partial").exists());
    assert!(!stale.exists());
    let quarantine = run.join("quarantine");
    assert!(quarantine.is_dir());
    assert!(
        fs::read_dir(quarantine)
            .expect("quarantine")
            .next()
            .is_some()
    );
}

struct Fixture {
    _temp: TempDir,
    root: PathBuf,
    workspace: PathBuf,
    repository: PathBuf,
    catalog: PathBuf,
}

struct Receipts {
    source: Value,
    template: Value,
}

struct AcceptedRun {
    run_id: String,
    packet_id: String,
    source_sha256: String,
    template_sha256: String,
}

struct Finalized {
    bundle: PathBuf,
    tree_digest: String,
}

impl Fixture {
    fn new() -> Self {
        let temp = tempdir().expect("tempdir");
        let root = temp.path().to_path_buf();
        let workspace = root.join("workspace");
        let repository = root.join("repo");
        let catalog = root.join("catalog");
        fs::create_dir_all(&workspace).expect("workspace");
        fs::create_dir_all(&repository).expect("repository");
        fs::write(repository.join("README.md"), "source\n").expect("source");
        git(&repository, &["init"]);
        git(&repository, &["config", "user.name", "GTKG Fixture"]);
        git(
            &repository,
            &["config", "user.email", "fixture@invalid.example"],
        );
        git(&repository, &["add", "-A"]);
        git(&repository, &["commit", "-m", "fixture"]);
        create_template_catalog(&catalog);
        Self {
            _temp: temp,
            root,
            workspace,
            repository,
            catalog,
        }
    }

    fn context(&self) -> CallContext {
        CallContext::restricted(
            TransportKind::Test,
            vec![self.root.clone()],
            EffectPolicy::WorkspaceWrite,
        )
        .expect("context")
    }
}

fn finalize(fixture: &Fixture, context: &CallContext, version: &str) -> Finalized {
    let accepted = prepare_and_accept(fixture, context, version);
    let response = execute_ok_run(
        context,
        OperationId::BuildFinalize,
        Some(&accepted.run_id),
        json!({"workspace_root": fixture.workspace}),
    );
    Finalized {
        bundle: PathBuf::from(
            response.result["bundle_path"]
                .as_str()
                .expect("bundle path"),
        ),
        tree_digest: response.result["tree_digest"]
            .as_str()
            .expect("tree digest")
            .to_owned(),
    }
}

fn prepare_and_accept(fixture: &Fixture, context: &CallContext, version: &str) -> AcceptedRun {
    let receipts = inspect_and_validate(fixture, context);
    let planned = Dispatcher
        .execute(
            context,
            plan_request(&fixture.workspace, "full", &receipts, None, None, version),
        )
        .expect("build.plan");
    let run_id = planned.run_id.expect("run id");
    execute_ok_run(
        context,
        OperationId::BuildPrepare,
        Some(&run_id),
        json!({"workspace_root": fixture.workspace}),
    );
    let next = execute_ok_run(
        context,
        OperationId::SummaryNext,
        Some(&run_id),
        json!({"workspace_root": fixture.workspace}),
    );
    let job = &next.result["job"];
    let accepted = AcceptedRun {
        run_id,
        packet_id: job["packet_id"].as_str().expect("packet id").to_owned(),
        source_sha256: job["source_sha256"]
            .as_str()
            .expect("source digest")
            .to_owned(),
        template_sha256: job["template_manifest_sha256"]
            .as_str()
            .expect("template digest")
            .to_owned(),
    };
    execute_ok_run(
        context,
        OperationId::SummaryAccept,
        Some(&accepted.run_id),
        json!({
            "workspace_root": fixture.workspace,
            "packet_id": accepted.packet_id,
            "source_sha256": accepted.source_sha256,
            "template_manifest_sha256": accepted.template_sha256,
            "summary_markdown": "accepted summary"
        }),
    );
    accepted
}

fn inspect_and_validate(fixture: &Fixture, context: &CallContext) -> Receipts {
    let inspected = execute_ok(
        context,
        OperationId::SourceInspect,
        json!({
            "workspace_root": fixture.workspace,
            "repositories": [{
                "repo_id": "repo-a",
                "path": fixture.repository,
                "role": "docs",
                "include": []
            }]
        }),
    );
    let resolved = execute_ok(
        context,
        OperationId::TemplateResolve,
        json!({
            "workspace_root": fixture.workspace,
            "catalog_root": fixture.catalog,
            "template_id": "summary-template",
            "version": "0.1.0"
        }),
    );
    let validated = execute_ok(
        context,
        OperationId::TemplateValidate,
        json!({
            "workspace_root": fixture.workspace,
            "resolution_ref": resolved.result["resolution_ref"]
        }),
    );
    Receipts {
        source: inspected.result["inspection_ref"].clone(),
        template: validated.result["validation_ref"].clone(),
    }
}

fn plan_request(
    workspace: &Path,
    mode: &str,
    receipts: &Receipts,
    baseline: Option<&Path>,
    baseline_digest: Option<&str>,
    version: &str,
) -> OperationRequest {
    let mut request = OperationRequest::new(
        OperationId::BuildPlan,
        format!("recovery-plan-{version}"),
        json!({
            "workspace_root": workspace,
            "mode": mode,
            "source_inspection_ref": receipts.source,
            "template_validation_ref": receipts.template,
            "baseline_bundle": baseline,
            "baseline_tree_sha256": baseline_digest,
            "bundle_version": version
        }),
    );
    request.locks = BTreeMap::from([
        (
            "source_inspection".to_owned(),
            receipts.source["sha256"]
                .as_str()
                .expect("source digest")
                .to_owned(),
        ),
        (
            "template_validation".to_owned(),
            receipts.template["sha256"]
                .as_str()
                .expect("template digest")
                .to_owned(),
        ),
    ]);
    request
}

fn execute_ok(
    context: &CallContext,
    operation: OperationId,
    payload: Value,
) -> gtkg_protocol::OperationResponse {
    execute_ok_run(context, operation, None, payload)
}

fn execute_ok_run(
    context: &CallContext,
    operation: OperationId,
    run_id: Option<&str>,
    payload: Value,
) -> gtkg_protocol::OperationResponse {
    let mut request = OperationRequest::new(
        operation,
        format!("recovery-{}", operation.as_str()),
        payload,
    );
    request.run_id = run_id.map(str::to_owned);
    Dispatcher
        .execute(context, request)
        .unwrap_or_else(|error| panic!("{} failed: {error:#?}", operation.as_str()))
}

fn execute_error(context: &CallContext, operation: OperationId, payload: Value) -> ErrorCode {
    Dispatcher
        .execute(
            context,
            OperationRequest::new(
                operation,
                format!("recovery-error-{}", operation.as_str()),
                payload,
            ),
        )
        .expect_err("operation must fail closed")
        .error
        .code
}

fn create_template_catalog(catalog: &Path) {
    let staging = catalog.join("summary-template/versions/staging");
    fs::create_dir_all(&staging).expect("template staging");
    let template = staging.join("template.md");
    fs::write(
        &template,
        "---\ntype: template\ntitle: Summary\ndescription: Summary fixture\nresource: ./template.md\ntags: [fixture]\ngenerated: false\nverified: false\nstatus: validated\nsources: []\nokf_version: '0.2'\ngtkg:\n  schema: gtkg.template/v1\n---\n\n# Summary\n",
    )
    .expect("template");
    let manifest = json!({
        "schema_version": "gtkg.template-manifest/v1",
        "template_id": "summary-template",
        "version": "0.1.0",
        "template_file": "template.md",
        "template_sha256": sha256_file(&template).expect("digest"),
        "slot_ids": ["summary"]
    });
    write_json(&staging.join("template-manifest.json"), &manifest);
    let digest = canonical_json_sha256(&manifest).expect("manifest digest");
    fs::rename(
        &staging,
        staging
            .parent()
            .expect("versions")
            .join(format!("v0.1.0--{}", &digest[7..19])),
    )
    .expect("publish template");
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
        .expect("git");
    assert!(
        output.status.success(),
        "git {} failed: {}",
        arguments.join(" "),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).expect("read JSON")).expect("parse JSON")
}

fn write_json(path: &Path, value: &Value) {
    fs::write(path, serde_json::to_vec_pretty(value).expect("JSON bytes")).expect("write JSON");
}
