use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use gtkg_core::file_model::{sha256_file, write_index_tree};
use gtkg_core::{CallContext, Dispatcher, EffectPolicy, TransportKind};
use gtkg_protocol::{ErrorCode, OperationId, OperationRequest, canonical_json_sha256};
use serde_json::{Value, json};
use tempfile::tempdir;

#[test]
fn paired_candidate_and_acceptance_receipt_rewrite_is_rejected() {
    let fixture = Fixture::new();
    let context = fixture.context();
    let (run_id, packet_id) = prepare_and_accept(
        &context,
        &fixture.workspace,
        &fixture.repository,
        &fixture.catalog,
    );
    let run = fixture.workspace.join(".gtkg/runs").join(&run_id);
    let candidate_path = run.join("candidates").join(format!("{packet_id}.json"));
    let mut candidate: Value = read_json(&candidate_path);
    candidate["summary_markdown"] = json!("paired rewrite");
    write_json(&candidate_path, &candidate);
    let receipt_path = run.join("accepted").join(format!("{packet_id}.json"));
    let mut receipt: Value = read_json(&receipt_path);
    receipt["candidate_sha256"] = json!(sha256_file(&candidate_path).expect("candidate digest"));
    write_json(&receipt_path, &receipt);

    let error = execute_error_run(
        &context,
        OperationId::BuildFinalize,
        Some(&run_id),
        json!({"workspace_root": fixture.workspace}),
    );
    assert_eq!(error, ErrorCode::LockMismatch);
}

#[test]
fn published_bundle_carries_acceptance_evidence() {
    let fixture = Fixture::new();
    let context = fixture.context();
    let (run_id, _) = prepare_and_accept(
        &context,
        &fixture.workspace,
        &fixture.repository,
        &fixture.catalog,
    );
    let finalized = execute_ok_run(
        &context,
        OperationId::BuildFinalize,
        Some(&run_id),
        json!({"workspace_root": fixture.workspace}),
    );
    let bundle = PathBuf::from(
        finalized.result["bundle_path"]
            .as_str()
            .expect("bundle path"),
    );
    let manifest: Value = read_json(&bundle.join("artifact-manifest.json"));
    let knowledge = &manifest["knowledge"][0];
    let relative = knowledge["acceptance_receipt_path"]
        .as_str()
        .expect("acceptance receipt path");
    let expected = knowledge["acceptance_receipt_sha256"]
        .as_str()
        .expect("acceptance receipt digest");
    assert_eq!(
        sha256_file(&bundle.join(relative)).expect("receipt digest"),
        expected
    );
}

#[test]
fn full_external_tree_digest_rejects_a_coherent_bundle_rewrite() {
    let fixture = Fixture::new();
    let context = fixture.context();
    let (run_id, _) = prepare_and_accept(
        &context,
        &fixture.workspace,
        &fixture.repository,
        &fixture.catalog,
    );
    let finalized = execute_ok_run(
        &context,
        OperationId::BuildFinalize,
        Some(&run_id),
        json!({"workspace_root": fixture.workspace}),
    );
    let bundle = PathBuf::from(
        finalized.result["bundle_path"]
            .as_str()
            .expect("bundle path"),
    );
    let expected_tree_sha256 = finalized.result["tree_digest"]
        .as_str()
        .expect("external full tree digest")
        .to_owned();
    fs::write(
        bundle.join("reports/coherent-rewrite.txt"),
        "coherent rewrite\n",
    )
    .expect("tamper");
    rewrite_bundle_checksums(&bundle);
    write_index_tree(&bundle).expect("rewrite indexes");

    let error = execute_error(
        &context,
        OperationId::BundleVerify,
        json!({
            "bundle_path": bundle,
            "expected_tree_sha256": expected_tree_sha256
        }),
    );
    assert_eq!(error, ErrorCode::BundleInvalid);
}

#[test]
fn git_metadata_roots_must_remain_authorized() {
    let temp = tempdir().expect("tempdir");
    let allowed = temp.path().join("allowed");
    let repository = allowed.join("repo");
    let workspace = allowed.join("workspace");
    let external_git_dir = temp.path().join("external.git");
    fs::create_dir_all(&workspace).expect("workspace");
    run(
        temp.path(),
        &[
            "init",
            "--separate-git-dir",
            external_git_dir.to_str().expect("git dir"),
            repository.to_str().expect("repository"),
        ],
    );
    fs::write(repository.join("README.md"), "source\n").expect("source");
    configure_and_commit(&repository);
    let context = restricted(&allowed);

    let error = execute_error(
        &context,
        OperationId::SourceInspect,
        json!({
            "workspace_root": workspace,
            "repositories": [{
                "repo_id": "repo-a",
                "path": repository,
                "role": "docs",
                "include": []
            }]
        }),
    );
    assert_eq!(error, ErrorCode::PathEscape);
}

#[cfg(unix)]
#[test]
fn template_hardlinks_are_rejected_before_content_read() {
    let temp = tempdir().expect("tempdir");
    let allowed = temp.path().join("allowed");
    let workspace = allowed.join("workspace");
    let catalog = allowed.join("catalog");
    fs::create_dir_all(&workspace).expect("workspace");
    create_template_catalog(&catalog);
    let version = only_version(&catalog);
    let template = version.join("template.md");
    let outside = temp.path().join("outside-template.md");
    fs::copy(&template, &outside).expect("outside template");
    fs::remove_file(&template).expect("remove template");
    fs::hard_link(&outside, &template).expect("hard link fixture");
    let context = restricted(&allowed);

    let error = execute_error(
        &context,
        OperationId::TemplateResolve,
        json!({
            "workspace_root": workspace,
            "catalog_root": catalog,
            "template_id": "summary-template",
            "version": "0.1.0"
        }),
    );
    assert!(matches!(
        error,
        ErrorCode::PathEscape | ErrorCode::SymlinkRejected
    ));
}

struct Fixture {
    _temp: tempfile::TempDir,
    root: PathBuf,
    workspace: PathBuf,
    repository: PathBuf,
    catalog: PathBuf,
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
        run(&repository, &["init"]);
        configure_and_commit(&repository);
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
        restricted(&self.root)
    }
}

fn restricted(root: &Path) -> CallContext {
    CallContext::restricted(
        TransportKind::Test,
        vec![root.to_path_buf()],
        EffectPolicy::WorkspaceWrite,
    )
    .expect("restricted context")
}

fn prepare_and_accept(
    context: &CallContext,
    workspace: &Path,
    repository: &Path,
    catalog: &Path,
) -> (String, String) {
    let inspected = execute_ok(
        context,
        OperationId::SourceInspect,
        json!({
            "workspace_root": workspace,
            "repositories": [{
                "repo_id": "repo-a",
                "path": repository,
                "role": "docs",
                "include": []
            }]
        }),
    );
    let resolved = execute_ok(
        context,
        OperationId::TemplateResolve,
        json!({
            "workspace_root": workspace,
            "catalog_root": catalog,
            "template_id": "summary-template",
            "version": "0.1.0"
        }),
    );
    let validated = execute_ok(
        context,
        OperationId::TemplateValidate,
        json!({
            "workspace_root": workspace,
            "resolution_ref": resolved.result["resolution_ref"]
        }),
    );
    let source_ref = inspected.result["inspection_ref"].clone();
    let template_ref = validated.result["validation_ref"].clone();
    let mut request = OperationRequest::new(
        OperationId::BuildPlan,
        "hardening-build.plan",
        json!({
            "workspace_root": workspace,
            "mode": "full",
            "source_inspection_ref": source_ref,
            "template_validation_ref": template_ref,
            "baseline_bundle": null,
            "bundle_version": "9.1.0"
        }),
    );
    request.locks = BTreeMap::from([
        (
            "source_inspection".to_owned(),
            source_ref["sha256"]
                .as_str()
                .expect("source digest")
                .to_owned(),
        ),
        (
            "template_validation".to_owned(),
            template_ref["sha256"]
                .as_str()
                .expect("template digest")
                .to_owned(),
        ),
    ]);
    let planned = Dispatcher
        .execute(context, request)
        .unwrap_or_else(|error| panic!("build.plan failed: {error:#?}"));
    let run_id = planned.run_id.expect("run id");
    execute_ok_run(
        context,
        OperationId::BuildPrepare,
        Some(&run_id),
        json!({"workspace_root": workspace}),
    );
    let next = execute_ok_run(
        context,
        OperationId::SummaryNext,
        Some(&run_id),
        json!({"workspace_root": workspace}),
    );
    let job = &next.result["job"];
    let packet_id = job["packet_id"].as_str().expect("packet id").to_owned();
    execute_ok_run(
        context,
        OperationId::SummaryAccept,
        Some(&run_id),
        json!({
            "workspace_root": workspace,
            "packet_id": packet_id,
            "source_sha256": job["source_sha256"],
            "template_manifest_sha256": job["template_manifest_sha256"],
            "summary_markdown": "accepted summary"
        }),
    );
    (run_id, packet_id)
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
        format!("hardening-{}", operation.as_str()),
        payload,
    );
    request.run_id = run_id.map(str::to_owned);
    Dispatcher
        .execute(context, request)
        .unwrap_or_else(|error| panic!("{} failed: {error:#?}", operation.as_str()))
}

fn execute_error(context: &CallContext, operation: OperationId, payload: Value) -> ErrorCode {
    execute_error_run(context, operation, None, payload)
}

fn execute_error_run(
    context: &CallContext,
    operation: OperationId,
    run_id: Option<&str>,
    payload: Value,
) -> ErrorCode {
    let mut request = OperationRequest::new(
        operation,
        format!("hardening-{}", operation.as_str()),
        payload,
    );
    request.run_id = run_id.map(str::to_owned);
    Dispatcher
        .execute(context, request)
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

fn only_version(catalog: &Path) -> PathBuf {
    fs::read_dir(catalog.join("summary-template/versions"))
        .expect("versions")
        .next()
        .expect("one version")
        .expect("version entry")
        .path()
}

fn configure_and_commit(repository: &Path) {
    run(repository, &["config", "user.name", "GTKG Fixture"]);
    run(
        repository,
        &["config", "user.email", "fixture@invalid.example"],
    );
    run(repository, &["add", "-A"]);
    run(repository, &["commit", "-m", "fixture"]);
}

fn run(root: &Path, arguments: &[&str]) {
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

fn rewrite_bundle_checksums(root: &Path) {
    let mut files = Vec::new();
    collect_files(root, root, &mut files);
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
            let digest = sha256_file(&root.join(&relative)).expect("checksum digest");
            format!("{}  {}", &digest[7..], relative.to_string_lossy())
        })
        .collect::<Vec<_>>();
    fs::write(
        root.join("checksums.sha256"),
        format!("{}\n", lines.join("\n")),
    )
    .expect("checksums");
}

fn collect_files(root: &Path, directory: &Path, output: &mut Vec<PathBuf>) {
    let mut entries = fs::read_dir(directory)
        .expect("read directory")
        .map(|entry| entry.expect("entry").path())
        .collect::<Vec<_>>();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            collect_files(root, &path, output);
        } else if path.is_file() {
            output.push(
                path.strip_prefix(root)
                    .expect("relative file")
                    .to_path_buf(),
            );
        }
    }
}
