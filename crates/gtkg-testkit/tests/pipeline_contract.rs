use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use gtkg_core::file_model::sha256_file;
use gtkg_core::{CallContext, Dispatcher, EffectPolicy, TransportKind};
use gtkg_extract::extract_path;
use gtkg_protocol::{
    OperationId, OperationRequest, OperationResponse, OperationStatus, canonical_json_sha256,
};
use lopdf::content::{Content, Operation};
use lopdf::{Document, Object, Stream, dictionary};
use serde_json::{Value, json};
use tempfile::tempdir;
use zip::CompressionMethod;
use zip::write::SimpleFileOptions;

#[test]
fn real_markdown_openxml_and_pdf_are_extracted_without_target_execution() {
    let temp = tempdir().expect("tempdir");
    let source = temp.path().join("source");
    fs::create_dir_all(&source).expect("source dir");
    fs::write(
        source.join("guide.md"),
        "# Markdown Knowledge\n\nEvidence text.",
    )
    .expect("markdown fixture");
    write_openxml(
        &source.join("brief.docx"),
        "word/document.xml",
        r#"<w:document xmlns:w="w"><w:body><w:p><w:r><w:t>DOCX Evidence</w:t></w:r></w:p></w:body></w:document>"#,
    );
    write_openxml(
        &source.join("book.xlsx"),
        "xl/worksheets/sheet1.xml",
        r#"<worksheet><sheetData><row><c><is><t>XLSX Evidence</t></is></c></row></sheetData></worksheet>"#,
    );
    write_openxml(
        &source.join("slides.pptx"),
        "ppt/slides/slide1.xml",
        r#"<p:sld xmlns:p="p" xmlns:a="a"><p:cSld><a:t>PPTX Evidence</a:t></p:cSld></p:sld>"#,
    );
    write_pdf(&source.join("paper.pdf"), "PDF Evidence");

    for (name, expected) in [
        ("guide.md", "Markdown Knowledge"),
        ("brief.docx", "DOCX Evidence"),
        ("book.xlsx", "XLSX Evidence"),
        ("slides.pptx", "PPTX Evidence"),
        ("paper.pdf", "PDF Evidence"),
    ] {
        let extracted = extract_path(&source.join(name)).expect("static extraction succeeds");
        assert!(
            extracted.text.contains(expected),
            "{name} did not contain {expected}: {}",
            extracted.text
        );
        assert!(!extracted.executed_target_content);
    }
}

#[test]
fn build_summary_bundle_query_compare_and_snapshot_form_a_real_file_pipeline() {
    let temp = tempdir().expect("tempdir");
    let source = temp.path().join("source");
    let workspace = temp.path().join("workspace");
    fs::create_dir_all(&source).expect("source dir");
    fs::write(
        source.join("guide.md"),
        "# Markdown Knowledge\n\nEvidence text.",
    )
    .expect("markdown fixture");
    write_openxml(
        &source.join("brief.docx"),
        "word/document.xml",
        r#"<w:document xmlns:w="w"><w:body><w:t>DOCX Pipeline Evidence</w:t></w:body></w:document>"#,
    );
    write_pdf(&source.join("paper.pdf"), "PDF Pipeline Evidence");

    let built = run_pipeline(&source, &workspace, "full", None, None, "0.1.0");
    assert_eq!(built.finalize.status, OperationStatus::Completed);
    let verify = execute(
        temp.path(),
        OperationId::BundleVerify,
        None,
        json!({
            "bundle_path": built.bundle_path,
            "expected_tree_sha256": built.tree_digest
        }),
    );
    assert_eq!(verify.result["valid"], true);

    let query = execute(
        temp.path(),
        OperationId::BundleQuery,
        None,
        json!({
            "bundle_path": built.bundle_path,
            "expected_tree_sha256": built.tree_digest,
            "query": "Pipeline Evidence"
        }),
    );
    assert!(query.result["matches"].as_array().expect("matches").len() >= 2);

    let compare = execute(
        temp.path(),
        OperationId::BundleCompare,
        None,
        json!({
            "left_bundle": built.bundle_path,
            "left_expected_tree_sha256": built.tree_digest,
            "right_bundle": built.bundle_path,
            "right_expected_tree_sha256": built.tree_digest
        }),
    );
    assert_eq!(
        compare.result["changed_sources"].as_array().unwrap().len(),
        0
    );

    let snapshot = execute(
        temp.path(),
        OperationId::SnapshotCreate,
        None,
        json!({
            "workspace_root": workspace,
            "bundle_path": built.bundle_path,
            "expected_bundle_tree_sha256": built.tree_digest,
            "snapshot_version": "0.1.0"
        }),
    );
    let snapshot_path = snapshot.result["snapshot_path"]
        .as_str()
        .expect("snapshot path");
    let snapshot_tree_digest = snapshot.result["tree_digest"]
        .as_str()
        .expect("snapshot tree digest");
    let snapshot_verify = execute(
        temp.path(),
        OperationId::SnapshotVerify,
        None,
        json!({
            "snapshot_path": snapshot_path,
            "expected_snapshot_tree_sha256": snapshot_tree_digest
        }),
    );
    assert_eq!(snapshot_verify.result["valid"], true);
    let restore = execute(
        temp.path(),
        OperationId::SnapshotRestore,
        None,
        json!({
            "workspace_root": workspace,
            "snapshot_path": snapshot_path,
            "expected_snapshot_tree_sha256": snapshot_tree_digest,
            "restore_version": "0.1.0"
        }),
    );
    assert!(Path::new(restore.result["restored_path"].as_str().unwrap()).is_dir());
}

#[test]
fn incremental_rebuild_matches_full_and_deletions_do_not_leave_ghost_knowledge() {
    let temp = tempdir().expect("tempdir");
    let source = temp.path().join("source");
    fs::create_dir_all(&source).expect("source dir");
    fs::write(source.join("a.md"), "# Stable\n\nPersistent evidence.").expect("A");
    fs::write(
        source.join("b.md"),
        "# Deleted\n\nGhostDeletionMarker must disappear.",
    )
    .expect("B");
    let baseline = run_pipeline(
        &source,
        &temp.path().join("baseline-workspace"),
        "full",
        None,
        None,
        "0.1.0",
    );

    fs::remove_file(source.join("b.md")).expect("delete fixture file");
    let incremental = run_pipeline(
        &source,
        &temp.path().join("incremental-workspace"),
        "incremental",
        Some(&baseline.bundle_path),
        Some(&baseline.tree_digest),
        "0.2.0",
    );
    let fresh = run_pipeline(
        &source,
        &temp.path().join("fresh-workspace"),
        "full",
        None,
        None,
        "0.2.0",
    );
    assert_eq!(incremental.semantic_digest, fresh.semantic_digest);

    let query = execute(
        temp.path(),
        OperationId::BundleQuery,
        None,
        json!({
            "bundle_path": incremental.bundle_path,
            "expected_tree_sha256": incremental.tree_digest,
            "query": "GhostDeletionMarker"
        }),
    );
    assert_eq!(query.result["matches"].as_array().unwrap().len(), 0);
    let compare = execute(
        temp.path(),
        OperationId::BundleCompare,
        None,
        json!({
            "left_bundle": baseline.bundle_path,
            "left_expected_tree_sha256": baseline.tree_digest,
            "right_bundle": incremental.bundle_path,
            "right_expected_tree_sha256": incremental.tree_digest
        }),
    );
    assert_eq!(
        compare.result["deleted_sources"],
        json!([{"repo_id": "fixture-repo", "logical_path": "b.md"}])
    );
}

struct BuiltBundle {
    finalize: OperationResponse,
    bundle_path: String,
    semantic_digest: String,
    tree_digest: String,
}

fn run_pipeline(
    source: &Path,
    workspace: &Path,
    mode: &str,
    baseline: Option<&str>,
    baseline_tree_sha256: Option<&str>,
    version: &str,
) -> BuiltBundle {
    fs::create_dir_all(workspace).expect("workspace");
    prepare_git_repository(source);
    let root = source.parent().expect("fixture root");
    let template_catalog = ensure_template_catalog(root);
    let inspected = execute(
        root,
        OperationId::SourceInspect,
        None,
        json!({
            "workspace_root": workspace,
            "repositories": [{
                "repo_id": "fixture-repo",
                "path": source,
                "role": "documentation",
                "include": []
            }]
        }),
    );
    let source_ref = inspected.result["inspection_ref"].clone();
    let resolved = execute(
        root,
        OperationId::TemplateResolve,
        None,
        json!({
            "workspace_root": workspace,
            "catalog_root": template_catalog,
            "template_id": "summary-template",
            "version": "0.1.0"
        }),
    );
    let validated = execute(
        root,
        OperationId::TemplateValidate,
        None,
        json!({
            "workspace_root": workspace,
            "resolution_ref": resolved.result["resolution_ref"]
        }),
    );
    let template_ref = validated.result["validation_ref"].clone();
    let mut plan_request = OperationRequest::new(
        OperationId::BuildPlan,
        format!("req-build.plan-{version}"),
        json!({
            "workspace_root": workspace,
            "mode": mode,
            "source_inspection_ref": source_ref,
            "template_validation_ref": template_ref,
            "baseline_bundle": baseline,
            "baseline_tree_sha256": baseline_tree_sha256,
            "bundle_version": version
        }),
    );
    plan_request.locks.insert(
        "source_inspection".to_owned(),
        source_ref["sha256"]
            .as_str()
            .expect("source receipt digest")
            .to_owned(),
    );
    plan_request.locks.insert(
        "template_validation".to_owned(),
        template_ref["sha256"]
            .as_str()
            .expect("template receipt digest")
            .to_owned(),
    );
    let plan = dispatch(root, plan_request);
    let run_id = plan.run_id.clone().expect("run id");
    let prepare = execute(
        root,
        OperationId::BuildPrepare,
        Some(&run_id),
        json!({"workspace_root": workspace}),
    );
    assert!(matches!(
        prepare.status,
        OperationStatus::NeedsLlm | OperationStatus::Completed
    ));

    loop {
        let next = execute(
            root,
            OperationId::SummaryNext,
            Some(&run_id),
            json!({"workspace_root": workspace}),
        );
        let Some(job) = next.result.get("job").filter(|value| !value.is_null()) else {
            break;
        };
        let packet_id = job["packet_id"].as_str().expect("packet id");
        let source_path = job["source_path"].as_str().expect("source path");
        let source_sha256 = job["source_sha256"].as_str().expect("source digest");
        let template_sha256 = job["template_manifest_sha256"]
            .as_str()
            .expect("template digest");
        let analysis_text = job["analysis_text"].as_str().expect("analysis text");
        let accepted = execute(
            root,
            OperationId::SummaryAccept,
            Some(&run_id),
            json!({
                "workspace_root": workspace,
                "packet_id": packet_id,
                "source_sha256": source_sha256,
                "template_manifest_sha256": template_sha256,
                "summary_markdown": format!("Summary for {source_path}\n\n{analysis_text}")
            }),
        );
        assert_eq!(accepted.status, OperationStatus::Completed);
    }

    let finalize = execute(
        root,
        OperationId::BuildFinalize,
        Some(&run_id),
        json!({"workspace_root": workspace}),
    );
    let bundle_path = finalize.result["bundle_path"]
        .as_str()
        .expect("bundle path")
        .to_owned();
    let semantic_digest = finalize.result["semantic_digest"]
        .as_str()
        .expect("semantic digest")
        .to_owned();
    let tree_digest = finalize.result["tree_digest"]
        .as_str()
        .expect("tree digest")
        .to_owned();
    BuiltBundle {
        finalize,
        bundle_path,
        semantic_digest,
        tree_digest,
    }
}

fn execute(
    authorized_root: &Path,
    operation: OperationId,
    run_id: Option<&str>,
    payload: Value,
) -> OperationResponse {
    let mut request =
        OperationRequest::new(operation, format!("req-{}", operation.as_str()), payload);
    request.run_id = run_id.map(str::to_owned);
    dispatch(authorized_root, request)
}

fn dispatch(authorized_root: &Path, request: OperationRequest) -> OperationResponse {
    let context = CallContext::restricted(
        TransportKind::Test,
        vec![authorized_root.to_path_buf()],
        EffectPolicy::WorkspaceWrite,
    )
    .expect("restricted test context");
    Dispatcher
        .execute(&context, request)
        .unwrap_or_else(|error| panic!("operation failed: {error:?}"))
}

fn prepare_git_repository(source: &Path) {
    if !source.join(".git").is_dir() {
        git(source, &["init"]);
        git(source, &["config", "user.name", "GTKG Fixture"]);
        git(source, &["config", "user.email", "fixture@invalid.example"]);
    }
    git(source, &["add", "-A"]);
    let status = git_output(source, &["status", "--porcelain"]);
    if !status.trim().is_empty() {
        git(source, &["commit", "-m", "fixture snapshot"]);
    }
}

fn ensure_template_catalog(root: &Path) -> PathBuf {
    let catalog = root.join("template-catalog");
    let versions = catalog.join("summary-template/versions");
    if versions
        .read_dir()
        .ok()
        .and_then(|mut entries| entries.next())
        .is_some()
    {
        return catalog;
    }
    let staging = versions.join("staging");
    fs::create_dir_all(&staging).expect("template staging");
    let template_path = staging.join("template.md");
    fs::write(
        &template_path,
        "---\ntype: template\ntitle: Summary\ndescription: Pipeline summary template\nresource: ./template.md\ntags: [fixture]\ngenerated: false\nverified: false\nstatus: validated\nsources: []\nokf_version: '0.2'\ngtkg:\n  schema: gtkg.template/v1\n  progressive_loading:\n    level: L1\n---\n\n# Summary\n",
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
    fs::write(
        staging.join("template-manifest.json"),
        serde_json::to_vec_pretty(&manifest).expect("template manifest bytes"),
    )
    .expect("template manifest");
    let digest = canonical_json_sha256(&manifest).expect("template manifest digest");
    fs::rename(
        &staging,
        versions.join(format!("v0.1.0--{}", &digest[7..19])),
    )
    .expect("publish template fixture");
    catalog
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
        .expect("run fixture git");
    assert!(
        output.status.success(),
        "git {} failed: {}",
        arguments.join(" "),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn git_output(root: &Path, arguments: &[&str]) -> String {
    let output = Command::new("/usr/bin/git")
        .arg("-C")
        .arg(root)
        .args(arguments)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .output()
        .expect("run fixture git");
    assert!(output.status.success(), "fixture git command failed");
    String::from_utf8(output.stdout).expect("git output")
}

fn write_openxml(path: &Path, member: &str, xml: &str) {
    let file = File::create(path).expect("create OpenXML fixture");
    let mut archive = zip::ZipWriter::new(file);
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
    archive
        .start_file("[Content_Types].xml", options)
        .expect("content types");
    archive
        .write_all(
            b"<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"/>",
        )
        .expect("write content types");
    archive.start_file(member, options).expect("XML member");
    archive.write_all(xml.as_bytes()).expect("write XML");
    archive.finish().expect("finish OpenXML");
}

fn write_pdf(path: &Path, text: &str) {
    let mut document = Document::with_version("1.5");
    let pages_id = document.new_object_id();
    let font_id = document.add_object(dictionary! {
        "Type" => "Font",
        "Subtype" => "Type1",
        "BaseFont" => "Courier",
    });
    let resources_id = document.add_object(dictionary! {
        "Font" => dictionary! { "F1" => font_id },
    });
    let content = Content {
        operations: vec![
            Operation::new("BT", vec![]),
            Operation::new("Tf", vec!["F1".into(), 18.into()]),
            Operation::new("Td", vec![72.into(), 700.into()]),
            Operation::new("Tj", vec![Object::string_literal(text)]),
            Operation::new("ET", vec![]),
        ],
    };
    let content_id = document.add_object(Stream::new(
        dictionary! {},
        content.encode().expect("encode PDF content"),
    ));
    let page_id = document.add_object(dictionary! {
        "Type" => "Page",
        "Parent" => pages_id,
        "Contents" => content_id,
    });
    document.objects.insert(
        pages_id,
        Object::Dictionary(dictionary! {
            "Type" => "Pages",
            "Kids" => vec![page_id.into()],
            "Count" => 1,
            "Resources" => resources_id,
            "MediaBox" => vec![0.into(), 0.into(), 595.into(), 842.into()],
        }),
    );
    let catalog_id = document.add_object(dictionary! {
        "Type" => "Catalog",
        "Pages" => pages_id,
    });
    document.trailer.set("Root", catalog_id);
    document.compress();
    document.save(path).expect("save PDF fixture");
}
