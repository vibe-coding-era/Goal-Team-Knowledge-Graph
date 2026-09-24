use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use gtkg_core::file_model::{sha256_file, tree_sha256, validate_index_tree, write_index_tree};
use gtkg_core::{CallContext, Dispatcher, EffectPolicy, TransportKind};
use gtkg_protocol::{
    ErrorCode, FileReceiptRef, OperationId, OperationRequest, SideEffectClass, SourceKey,
    canonical_json_sha256, operation_definition,
};
use serde_json::{Value, json};
use tempfile::tempdir;

#[test]
fn git_top_level_must_remain_inside_an_authorized_root() {
    let temp = tempdir().expect("tempdir");
    let repository = temp.path().join("repo");
    let docs = repository.join("docs");
    let workspace = temp.path().join("workspace");
    fs::create_dir_all(&docs).expect("docs");
    fs::create_dir_all(&workspace).expect("workspace");
    fs::write(docs.join("visible.md"), "visible\n").expect("visible source");
    fs::write(repository.join("outside.md"), "outside\n").expect("outside source");
    init_and_commit(&repository);

    let context = restricted(&[&workspace, &docs], EffectPolicy::WorkspaceWrite);
    let error = execute_error(
        &context,
        OperationId::SourceInspect,
        json!({
            "workspace_root": workspace,
            "repositories": [{
                "repo_id": "repo-a",
                "path": docs,
                "role": "docs",
                "include": []
            }]
        }),
    );
    assert_eq!(error, ErrorCode::PathEscape);
}

#[test]
fn receipt_embedded_source_and_template_roots_are_reauthorized_on_replay() {
    let temp = tempdir().expect("tempdir");
    let allowed = temp.path().join("allowed");
    let workspace = allowed.join("workspace");
    let repository = temp.path().join("outside-repo");
    let catalog = temp.path().join("outside-catalog");
    fs::create_dir_all(&workspace).expect("workspace");
    fs::create_dir_all(&repository).expect("repository");
    fs::write(repository.join("README.md"), "source\n").expect("source");
    init_and_commit(&repository);
    create_template_catalog(&catalog);

    let broad = restricted(&[temp.path()], EffectPolicy::WorkspaceWrite);
    let inspected = execute_ok(
        &broad,
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
        &broad,
        OperationId::TemplateResolve,
        json!({
            "workspace_root": workspace,
            "catalog_root": catalog,
            "template_id": "summary-template",
            "version": "0.1.0"
        }),
    );
    let validated = execute_ok(
        &broad,
        OperationId::TemplateValidate,
        json!({
            "workspace_root": workspace,
            "resolution_ref": resolved.result["resolution_ref"]
        }),
    );

    let narrow = restricted(&[&allowed], EffectPolicy::WorkspaceWrite);
    let source_ref = reference_for_narrow_root(
        &allowed,
        &inspected.evidence_refs[0],
        inspected.result["inspection_ref"]["sha256"]
            .as_str()
            .expect("source digest"),
    );
    let source_error = gtkg_core::source::load_and_revalidate(&narrow, &workspace, &source_ref)
        .expect_err("receipt-provided source root must be reauthorized");
    assert_eq!(source_error.code, ErrorCode::PathEscape);

    let template_ref = reference_for_narrow_root(
        &allowed,
        &validated.evidence_refs[0],
        validated.result["validation_ref"]["sha256"]
            .as_str()
            .expect("template digest"),
    );
    let template_error =
        gtkg_core::template::load_and_revalidate(&narrow, &workspace, &template_ref)
            .expect_err("receipt-provided template root must be reauthorized");
    assert_eq!(template_error.code, ErrorCode::PathEscape);
}

#[cfg(unix)]
#[test]
fn derived_gtkg_write_paths_reject_preexisting_symlink_escape() {
    let temp = tempdir().expect("tempdir");
    let allowed = temp.path().join("allowed");
    let outside = temp.path().join("outside");
    let repository = allowed.join("repo");
    let workspace = allowed.join("workspace");
    fs::create_dir_all(&repository).expect("repository");
    fs::create_dir_all(&workspace).expect("workspace");
    fs::create_dir_all(&outside).expect("outside");
    fs::write(repository.join("README.md"), "source\n").expect("source");
    init_and_commit(&repository);
    std::os::unix::fs::symlink(&outside, workspace.join(".gtkg")).expect("controlled symlink");

    let context = restricted(&[&allowed], EffectPolicy::WorkspaceWrite);
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
    assert!(
        fs::read_dir(&outside)
            .expect("outside directory")
            .next()
            .is_none()
    );
}

#[test]
fn node_describe_is_not_registered_as_read_only_and_dot_ids_are_rejected() {
    assert_ne!(
        operation_definition(OperationId::NodeDescribe)
            .expect("node.describe definition")
            .side_effect,
        SideEffectClass::Read
    );
    assert!(SourceKey::new("..", "README.md").is_err());
    assert!(SourceKey::new(".", "README.md").is_err());
}

#[test]
fn index_validation_checks_bytes_load_level_and_rendered_links() {
    let bytes = tempdir().expect("bytes fixture");
    fs::write(bytes.path().join("data.txt"), "data").expect("data");
    write_index_tree(bytes.path()).expect("index tree");
    let sidecar = bytes.path().join("index.gtkg.json");
    let source = fs::read_to_string(&sidecar).expect("index sidecar");
    fs::write(&sidecar, source.replacen("\"bytes\": 4", "\"bytes\": 0", 1)).expect("tamper bytes");
    assert!(validate_index_tree(bytes.path()).is_err());

    let links = tempdir().expect("links fixture");
    fs::write(links.path().join("data.txt"), "data").expect("data");
    write_index_tree(links.path()).expect("index tree");
    let index = links.path().join("index.md");
    let source = fs::read_to_string(&index).expect("index");
    fs::write(
        &index,
        source.replacen("* [data.txt](data.txt)", "* [data.txt](forged.txt)", 1),
    )
    .expect("tamper index links");
    assert!(validate_index_tree(links.path()).is_err());

    let level = tempdir().expect("level fixture");
    fs::write(level.path().join("data.txt"), "data").expect("data");
    write_index_tree(level.path()).expect("index tree");
    let sidecar = level.path().join("index.gtkg.json");
    let source = fs::read_to_string(&sidecar).expect("index sidecar");
    fs::write(
        &sidecar,
        source.replacen("\"load_level\": \"L2\"", "\"load_level\": \"L3\"", 1),
    )
    .expect("tamper load level");
    assert!(validate_index_tree(level.path()).is_err());
}

#[test]
fn accepted_summary_digest_is_rechecked_before_finalize() {
    let temp = tempdir().expect("tempdir");
    let repository = temp.path().join("repo");
    let workspace = temp.path().join("workspace");
    let catalog = temp.path().join("catalog");
    fs::create_dir_all(&repository).expect("repository");
    fs::create_dir_all(&workspace).expect("workspace");
    fs::write(repository.join("README.md"), "accepted source\n").expect("source");
    init_and_commit(&repository);
    create_template_catalog(&catalog);
    let context = restricted(&[temp.path()], EffectPolicy::WorkspaceWrite);
    let (run_id, packet_id) = prepare_and_accept(&context, &workspace, &repository, &catalog);

    let candidate = workspace
        .join(".gtkg/runs")
        .join(&run_id)
        .join("candidates")
        .join(format!("{packet_id}.json"));
    let mut value: Value =
        serde_json::from_slice(&fs::read(&candidate).expect("candidate")).expect("candidate JSON");
    value["summary_markdown"] = Value::String("changed after acceptance".to_owned());
    fs::write(
        &candidate,
        serde_json::to_vec_pretty(&value).expect("candidate bytes"),
    )
    .expect("tamper accepted candidate");

    let error = execute_error_run(
        &context,
        OperationId::BuildFinalize,
        Some(&run_id),
        json!({"workspace_root": workspace}),
    );
    assert!(matches!(
        error,
        ErrorCode::LockMismatch | ErrorCode::InvalidState | ErrorCode::BundleInvalid
    ));
}

#[test]
fn bundle_verify_recomputes_knowledge_from_locked_summary_receipts() {
    let temp = tempdir().expect("tempdir");
    let repository = temp.path().join("repo");
    let workspace = temp.path().join("workspace");
    let catalog = temp.path().join("catalog");
    fs::create_dir_all(&repository).expect("repository");
    fs::create_dir_all(&workspace).expect("workspace");
    fs::write(repository.join("README.md"), "derived source\n").expect("source");
    init_and_commit(&repository);
    create_template_catalog(&catalog);
    let context = restricted(&[temp.path()], EffectPolicy::WorkspaceWrite);
    let (run_id, _) = prepare_and_accept(&context, &workspace, &repository, &catalog);
    let finalized = execute_ok_run(
        &context,
        OperationId::BuildFinalize,
        Some(&run_id),
        json!({"workspace_root": workspace}),
    );
    let bundle = PathBuf::from(
        finalized.result["bundle_path"]
            .as_str()
            .expect("bundle path"),
    );
    let manifest_path = bundle.join("artifact-manifest.json");
    let mut manifest: Value = serde_json::from_slice(&fs::read(&manifest_path).expect("manifest"))
        .expect("manifest JSON");
    let knowledge_path = manifest["knowledge"][0]["path"]
        .as_str()
        .expect("knowledge path")
        .to_owned();
    let document_path = bundle.join(&knowledge_path);
    let mut document = fs::read_to_string(&document_path).expect("knowledge document");
    document.push_str("\nforged derived content\n");
    fs::write(&document_path, document).expect("tamper knowledge");
    let digest = sha256_file(&document_path).expect("knowledge digest");
    manifest["knowledge"][0]["sha256"] = Value::String(digest.clone());
    let canonical = manifest["canonical_documents"]
        .as_array_mut()
        .expect("canonical documents")
        .iter_mut()
        .find(|entry| entry["path"] == knowledge_path)
        .expect("canonical knowledge entry");
    canonical["sha256"] = Value::String(digest);
    fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest).expect("manifest bytes"),
    )
    .expect("rewrite manifest");
    rewrite_bundle_checksums(&bundle);
    write_index_tree(&bundle).expect("rewrite index closure");
    let externally_observed_tree = tree_sha256(&bundle).expect("external full tree digest");

    let error = execute_error(
        &context,
        OperationId::BundleVerify,
        json!({
            "bundle_path": bundle,
            "expected_tree_sha256": externally_observed_tree
        }),
    );
    assert_eq!(error, ErrorCode::BundleInvalid);
}

fn restricted(roots: &[&Path], effect: EffectPolicy) -> CallContext {
    CallContext::restricted(
        TransportKind::Test,
        roots.iter().map(|path| path.to_path_buf()).collect(),
        effect,
    )
    .expect("restricted context")
}

fn execute_ok(
    context: &CallContext,
    operation: OperationId,
    payload: Value,
) -> gtkg_protocol::OperationResponse {
    Dispatcher
        .execute(
            context,
            OperationRequest::new(
                operation,
                format!("followup-{}", operation.as_str()),
                payload,
            ),
        )
        .unwrap_or_else(|error| panic!("{} failed: {error:#?}", operation.as_str()))
}

fn execute_error(context: &CallContext, operation: OperationId, payload: Value) -> ErrorCode {
    execute_error_run(context, operation, None, payload)
}

fn execute_ok_run(
    context: &CallContext,
    operation: OperationId,
    run_id: Option<&str>,
    payload: Value,
) -> gtkg_protocol::OperationResponse {
    let mut request = OperationRequest::new(
        operation,
        format!("followup-{}", operation.as_str()),
        payload,
    );
    request.run_id = run_id.map(str::to_owned);
    Dispatcher
        .execute(context, request)
        .unwrap_or_else(|error| panic!("{} failed: {error:#?}", operation.as_str()))
}

fn execute_error_run(
    context: &CallContext,
    operation: OperationId,
    run_id: Option<&str>,
    payload: Value,
) -> ErrorCode {
    let mut request = OperationRequest::new(
        operation,
        format!("followup-{}", operation.as_str()),
        payload,
    );
    request.run_id = run_id.map(str::to_owned);
    Dispatcher
        .execute(context, request)
        .expect_err("operation must fail closed")
        .error
        .code
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
        "followup-plan",
        json!({
            "workspace_root": workspace,
            "mode": "full",
            "source_inspection_ref": source_ref,
            "template_validation_ref": template_ref,
            "baseline_bundle": null,
            "bundle_version": "9.0.0"
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

fn reference_for_narrow_root(root: &Path, absolute: &str, digest: &str) -> FileReceiptRef {
    let canonical_root = fs::canonicalize(root).expect("canonical narrow root");
    let canonical_receipt = fs::canonicalize(absolute).expect("canonical receipt");
    FileReceiptRef {
        path: canonical_receipt
            .strip_prefix(&canonical_root)
            .expect("receipt under narrow root")
            .to_string_lossy()
            .into_owned(),
        sha256: digest.to_owned(),
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
        .expect("fixture git");
    assert!(
        output.status.success(),
        "git {} failed: {}",
        arguments.join(" "),
        String::from_utf8_lossy(&output.stderr)
    );
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
        "template_sha256": gtkg_core::file_model::sha256_file(&template).expect("digest"),
        "slot_ids": ["summary"]
    });
    fs::write(
        staging.join("template-manifest.json"),
        serde_json::to_vec_pretty(&manifest).expect("manifest bytes"),
    )
    .expect("manifest");
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
