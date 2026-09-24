//! E01 frozen contract: input admission extension and explicit omission reporting.
//!
//! Oracles:
//! (a) .toml/.lock/.json/.yaml/.yml/.sh/.html are statically extracted with facts and
//!     zero target execution, and degrade to text facts instead of failing when the
//!     structured parse fails.
//! (b) unsupported tracked files appear in an explicit omission report with a reason.
//! (c) the omission report is bundled as verifiable evidence.
//! (d) relevant recall over the gold fixture is 100%: every tracked file is either
//!     admitted into the SourceLock or explicitly omitted; nothing is silently skipped.
//! (e) the zero target-execution invariant holds across the full pipeline.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use gtkg_core::file_model::sha256_file;
use gtkg_core::{CallContext, Dispatcher, EffectPolicy, TransportKind};
use gtkg_extract::{extract_path, is_supported_path};
use gtkg_protocol::{
    OperationId, OperationRequest, OperationResponse, OperationStatus, canonical_json_sha256,
};
use serde_json::{Value, json};
use tempfile::tempdir;

const NEW_ADMISSION_EXTENSIONS: [&str; 7] = ["toml", "lock", "json", "yaml", "yml", "sh", "html"];

#[test]
fn newly_admitted_extensions_extract_static_facts_without_execution() {
    let temp = tempdir().expect("tempdir");
    let sentinel = temp.path().join("must-not-exist");
    for extension in NEW_ADMISSION_EXTENSIONS {
        assert!(
            is_supported_path(Path::new(&format!("admitted.{extension}"))),
            "extension .{extension} must be admitted"
        );
    }
    assert!(!is_supported_path(Path::new("payload.bin")));
    let fixtures: [(&str, &str, &str, &[&str]); 7] = [
        (
            "config.toml",
            "[package]\nname = \"gold\"\n\n[dependencies]\nserde = \"1\"\n# touch must-not-exist\n",
            "gtkg-toml-static/v1",
            &["toml_section:package", "toml_key:name"],
        ),
        (
            "Cargo.lock",
            "[[package]]\nname = \"gold\"\nversion = \"0.1.0\"\n",
            "gtkg-lock-static/v1",
            &["toml_section:package", "toml_key:version"],
        ),
        (
            "data.json",
            "{\n  \"name\": \"gold\",\n  \"items\": [{\"id\": 1}]\n}\n",
            "gtkg-json-static/v1",
            &["json_key:name", "json_key:items"],
        ),
        (
            "spec.yaml",
            "kind: gold\nmetadata:\n  name: nested\n",
            "gtkg-yaml-static/v1",
            &["yaml_key:kind", "yaml_key:metadata"],
        ),
        (
            "extra.yml",
            "service: gold\n",
            "gtkg-yaml-static/v1",
            &["yaml_key:service"],
        ),
        (
            "build.sh",
            "#!/bin/sh\nset -eu\npackage() {\n  echo packing\n}\npackage\n",
            "gtkg-shell-static/v1",
            &["shell_function:package", "shell_command:echo"],
        ),
        (
            "page.html",
            "<!doctype html>\n<html><head><title>Gold Page</title></head><body><main id=\"knowledge-root\">Hello</main><script>alert(1)</script></body></html>\n",
            "gtkg-html-static/v1",
            &["html_title:Gold Page", "html_id:knowledge-root"],
        ),
    ];

    for (name, source, extractor_id, expected_facts) in fixtures {
        let path = temp.path().join(name);
        fs::write(&path, source).expect("write admission fixture");
        assert!(is_supported_path(&path), "{name} must be admitted");
        let extracted = extract_path(&path).expect("static extraction succeeds");
        assert_eq!(extracted.extractor_id, extractor_id, "{name}");
        assert!(!extracted.text.is_empty(), "{name} must yield text");
        let observed: BTreeSet<String> = extracted
            .observed_facts
            .iter()
            .map(|fact| format!("{}:{}", fact.kind, fact.marker_id))
            .collect();
        for expected in expected_facts {
            assert!(
                observed.contains(*expected),
                "{name} is missing fact {expected}; observed {observed:?}"
            );
        }
        for fact in &extracted.observed_facts {
            let start = fact.span.start as usize;
            let end = fact.span.end as usize;
            assert_eq!(
                source.as_bytes().get(start..end),
                Some(fact.marker_id.as_bytes()),
                "{name} fact span must select its marker exactly"
            );
        }
        assert_eq!(extracted.target_process_count, 0, "{name}");
        assert!(!extracted.executed_target_content, "{name}");
        assert!(
            !sentinel.exists(),
            "{name} must never execute target content"
        );
    }
}

#[test]
fn structured_parse_failure_degrades_to_text_facts_instead_of_error() {
    let temp = tempdir().expect("tempdir");
    for (name, source) in [
        ("broken.json", "{ this is not json\n"),
        ("broken.yaml", "key: [unclosed\n  - : :\n"),
    ] {
        let path = temp.path().join(name);
        fs::write(&path, source).expect("write broken fixture");
        let extracted = extract_path(&path).expect("parse failure must degrade, not error");
        assert_eq!(extracted.text, source, "{name} keeps the exact source text");
        assert_eq!(
            extracted
                .observations
                .get("structure_mode")
                .map(String::as_str),
            Some("fallback_text"),
            "{name} must record the degraded structure mode"
        );
        assert_eq!(extracted.target_process_count, 0, "{name}");
        assert!(!extracted.executed_target_content, "{name}");
    }
}

#[test]
fn gold_repository_admits_new_types_and_reports_omissions_explicitly() {
    let temp = tempdir().expect("tempdir");
    let source = temp.path().join("source");
    let workspace = temp.path().join("workspace");
    fs::create_dir_all(&source).expect("source dir");
    let gold_files: [(&str, &[u8]); 9] = [
        ("guide.md", b"# Gold Guide\n\nMarkdown evidence.\n"),
        ("config.toml", b"[package]\nname = \"gold\"\n"),
        ("Cargo.lock", b"[[package]]\nname = \"gold\"\nversion = \"0.1.0\"\n"),
        ("data.json", b"{\n  \"name\": \"gold\"\n}\n"),
        ("spec.yaml", b"kind: gold\n"),
        ("extra.yml", b"service: gold\n"),
        ("build.sh", b"#!/bin/sh\npackage() {\n  echo packing\n}\n"),
        (
            "page.html",
            b"<html><head><title>Gold</title></head><body><main id=\"root\">Hi</main></body></html>\n",
        ),
        ("payload.bin", b"\x00\x01\x02\xff\xfe binary payload"),
    ];
    for (name, bytes) in &gold_files {
        fs::write(source.join(name), bytes).expect("write gold fixture");
    }

    let built = run_pipeline(&source, &workspace, "0.1.0");
    assert_eq!(built.finalize.status, OperationStatus::Completed);

    // (a) every supported gold file, including the six newly admitted types, is locked.
    let source_lock = &built.inspection.result["source_lock"];
    let locked_paths: BTreeSet<String> = source_lock["entries"]
        .as_array()
        .expect("source lock entries")
        .iter()
        .map(|entry| {
            entry["logical_path"]
                .as_str()
                .expect("locked logical path")
                .to_owned()
        })
        .collect();
    let expected_admitted: BTreeSet<String> = gold_files
        .iter()
        .map(|(name, _)| (*name).to_owned())
        .filter(|name| name != "payload.bin")
        .collect();
    assert_eq!(locked_paths, expected_admitted, "SourceLock admission set");

    // (b) the unsupported file is explicitly omitted with a reason at inspect time.
    let inspect_omissions = built.inspection.result["omissions"]
        .as_array()
        .expect("inspect omissions");
    assert_eq!(
        inspect_omissions,
        &vec![json!({
            "repo_id": "fixture-repo",
            "logical_path": "payload.bin",
            "reason": "unsupported_extension",
        })],
        "inspect must report the omitted file with its reason"
    );

    // (c) the omission report is bundled as verifiable evidence.
    let bundle_path = PathBuf::from(
        built.finalize.result["bundle_path"]
            .as_str()
            .expect("bundle path"),
    );
    let verify = execute(
        temp.path(),
        OperationId::BundleVerify,
        None,
        json!({
            "bundle_path": bundle_path,
            "expected_tree_sha256": built.finalize.result["tree_digest"]
        }),
    );
    assert_eq!(verify.result["valid"], true);
    let report_path = bundle_path.join("reports/omission-report.json");
    let report: Value = serde_json::from_slice(
        &fs::read(&report_path).expect("bundled omission report must exist"),
    )
    .expect("omission report must be valid JSON");
    assert_eq!(report["schema_version"], "gtkg.omission-report/v1");
    assert_eq!(report["admitted_count"], 8);
    assert_eq!(report["omission_count"], 1);
    assert_eq!(
        report["omissions"].as_array().expect("report omissions"),
        &vec![json!({
            "repo_id": "fixture-repo",
            "logical_path": "payload.bin",
            "reason": "unsupported_extension",
        })]
    );

    // The bundled SourceLock agrees with the inspect-time lock.
    let bundled_lock: Value = serde_json::from_slice(
        &fs::read(bundle_path.join("locks/source-lock.json")).expect("bundled source lock"),
    )
    .expect("bundled source lock JSON");
    let bundled_paths: BTreeSet<String> = bundled_lock["entries"]
        .as_array()
        .expect("bundled entries")
        .iter()
        .map(|entry| entry["logical_path"].as_str().expect("path").to_owned())
        .collect();
    assert_eq!(bundled_paths, expected_admitted);

    // Each admitted source produced bundled summary and analysis evidence with a
    // type-specific extractor and zero target execution.
    let manifest: Value = serde_json::from_slice(
        &fs::read(bundle_path.join("artifact-manifest.json")).expect("artifact manifest"),
    )
    .expect("artifact manifest JSON");
    let knowledge_keys: BTreeSet<String> = manifest["knowledge"]
        .as_array()
        .expect("knowledge entries")
        .iter()
        .map(|entry| {
            entry["source_key"]["logical_path"]
                .as_str()
                .expect("knowledge path")
                .to_owned()
        })
        .collect();
    assert_eq!(knowledge_keys, expected_admitted, "summary coverage");
    let analysis_entries = manifest["analysis"].as_array().expect("analysis entries");
    let analysis_keys: BTreeSet<String> = analysis_entries
        .iter()
        .map(|entry| {
            entry["source_key"]["logical_path"]
                .as_str()
                .expect("analysis path")
                .to_owned()
        })
        .collect();
    assert_eq!(analysis_keys, expected_admitted, "analysis coverage");
    let extractor_ids: BTreeSet<String> = analysis_entries
        .iter()
        .map(|entry| {
            entry["extractor_id"]
                .as_str()
                .expect("extractor id")
                .to_owned()
        })
        .collect();
    for expected in [
        "gtkg-toml-static/v1",
        "gtkg-lock-static/v1",
        "gtkg-json-static/v1",
        "gtkg-yaml-static/v1",
        "gtkg-shell-static/v1",
        "gtkg-html-static/v1",
    ] {
        assert!(
            extractor_ids.contains(expected),
            "bundle is missing extractor {expected}"
        );
    }

    // (e) every bundled analysis packet preserves the zero target-execution invariant.
    for entry in analysis_entries {
        let packet: Value = serde_json::from_slice(
            &fs::read(bundle_path.join(entry["path"].as_str().expect("analysis path")))
                .expect("analysis packet"),
        )
        .expect("analysis packet JSON");
        assert_eq!(packet["target_process_count"], 0);
        assert_eq!(packet["executed_target_content"], false);
    }

    // (d) relevant recall over the gold set is 100% and nothing is silently skipped:
    // every tracked file is either admitted or explicitly omitted.
    let tracked = git_tracked_files(&source);
    assert_eq!(tracked.len(), gold_files.len());
    let omitted: BTreeSet<String> = report["omissions"]
        .as_array()
        .expect("report omissions")
        .iter()
        .map(|entry| entry["logical_path"].as_str().expect("path").to_owned())
        .collect();
    assert!(
        locked_paths.is_disjoint(&omitted),
        "a file must not be both admitted and omitted"
    );
    let accounted: BTreeSet<String> = locked_paths.union(&omitted).cloned().collect();
    assert_eq!(
        accounted, tracked,
        "no tracked file may be silently skipped"
    );
    let relevant = tracked.len() - omitted.len();
    let admitted_relevant = locked_paths.len();
    let recall_percent = admitted_relevant * 100 / relevant.max(1);
    assert_eq!(recall_percent, 100, "relevant recall must be 100%");
}

struct BuiltRun {
    finalize: OperationResponse,
    inspection: OperationResponse,
}

fn run_pipeline(source: &Path, workspace: &Path, version: &str) -> BuiltRun {
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
    assert_eq!(inspected.status, OperationStatus::Completed);
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
            "mode": "full",
            "source_inspection_ref": source_ref,
            "template_validation_ref": template_ref,
            "baseline_bundle": null,
            "baseline_tree_sha256": null,
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
    BuiltRun {
        finalize,
        inspection: inspected,
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

fn git_tracked_files(source: &Path) -> BTreeSet<String> {
    git_output(source, &["ls-files"])
        .lines()
        .map(str::to_owned)
        .collect()
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
