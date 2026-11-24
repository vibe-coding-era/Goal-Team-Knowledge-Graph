//! E07 frozen contract: the five generated architecture documents carry real
//! dependency/structure synthesis instead of a document-count listing.
//!
//! Oracles:
//! (a) each of agent/claude/rules/architecture/design contains the module
//!     structure section with real module paths and defined symbols from the
//!     fixture sources.
//! (b) each document contains the dependency edge section with the resolved
//!     `src/ledger.rs` → `src/model.rs` import and the explicit external
//!     (unknown) dependency, not just counts.
//! (c) the synthesized bodies are deterministic and the bundle stays valid.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use gtkg_core::file_model::sha256_file;
use gtkg_core::okf::parse_okf_concept;
use gtkg_core::{CallContext, Dispatcher, EffectPolicy, TransportKind};
use gtkg_protocol::{OperationId, OperationRequest, OperationResponse, canonical_json_sha256};
use serde_json::{Value, json};
use tempfile::tempdir;

const MODEL_SOURCE: &str = r#"#[derive(Default)]
pub struct Ledger {
    pub entries: u64,
}

impl Ledger {
    pub fn is_empty(&self) -> bool {
        self.entries == 0
    }
}
"#;

const LEDGER_SOURCE: &str = r#"use crate::model::Ledger;
use std::collections::HashMap;

pub fn reconcile(ledger: &Ledger) -> bool {
    ledger.is_empty()
}
"#;

const MARKDOWN_SOURCE: &str = "# Guide\n\nStable documentation.\n";

const ARCH_DOCS: [&str; 5] = ["agent", "claude", "rules", "architecture", "design"];

#[test]
fn architecture_documents_carry_real_structure_and_dependency_synthesis() {
    let temp = tempdir().expect("tempdir");
    let bundle = build_bundle(temp.path(), "workspace");
    let mut distinct = BTreeSet::new();
    for name in ARCH_DOCS {
        let source = fs::read_to_string(bundle.join(format!("knowledge/architecture/{name}.md")))
            .expect("architecture document");
        let document = parse_okf_concept(&source).expect("architecture OKF");
        let body = &document.body;
        let gtkg = document.frontmatter.gtkg.expect("architecture extensions");
        assert_eq!(gtkg["schema"].as_str(), Some("gtkg.architecture/v2"));
        assert_eq!(gtkg["bundle_version"].as_str(), Some("0.1.0"));
        assert_eq!(
            gtkg["generator_version"].as_str(),
            Some(concat!("gtkg/", env!("CARGO_PKG_VERSION")))
        );
        assert_eq!(
            gtkg["document_version"].as_str(),
            Some(concat!("0.1.0+gtkg.", env!("CARGO_PKG_VERSION")))
        );
        assert!(
            body.contains("## Accepted summary insights")
                && body.contains("Summary for src/ledger.rs"),
            "{name}.md must consume accepted summaries"
        );
        let profile_heading = match name {
            "agent" => "## Agent operating contract",
            "claude" => "## Claude context contract",
            "rules" => "## Repository rules",
            "architecture" => "## Architecture view",
            "design" => "## Design decisions",
            _ => unreachable!(),
        };
        assert!(body.contains(profile_heading), "{name}.md profile drifted");
        distinct.insert(source);
        assert!(
            body.contains("## Module structure"),
            "{name}.md must carry a module structure section"
        );
        assert!(
            body.contains("src/ledger.rs") && body.contains("src/model.rs"),
            "{name}.md must name the real fixture modules"
        );
        assert!(
            body.contains("function `reconcile`"),
            "{name}.md must synthesize defined symbols, found:\n{body}"
        );
        assert!(
            body.contains("## Dependency edges"),
            "{name}.md must carry a dependency edge section"
        );
        assert!(
            body.contains("`src/ledger.rs` imports `src/model.rs`"),
            "{name}.md must synthesize the resolved import edge, found:\n{body}"
        );
        assert!(
            body.contains("external `std::collections::HashMap`"),
            "{name}.md must keep external dependencies explicit, found:\n{body}"
        );
    }
    assert_eq!(
        distinct.len(),
        ARCH_DOCS.len(),
        "the five architecture documents must not share one body/template output"
    );
}

#[test]
fn architecture_documents_are_deterministic_and_verifiable() {
    let temp = tempdir().expect("tempdir");
    let first = build_bundle(temp.path(), "workspace-a");
    let second = build_bundle(temp.path(), "workspace-b");
    for name in ARCH_DOCS {
        assert_eq!(
            sha256_file(&first.join(format!("knowledge/architecture/{name}.md")))
                .expect("first digest"),
            sha256_file(&second.join(format!("knowledge/architecture/{name}.md")))
                .expect("second digest"),
            "{name}.md must be byte-identical across independent builds"
        );
    }
}

fn build_bundle(root: &Path, workspace_name: &str) -> PathBuf {
    let source = root.join("source");
    if !source.exists() {
        fs::create_dir_all(source.join("src")).expect("src dir");
        fs::create_dir_all(source.join("docs")).expect("docs dir");
        fs::write(source.join("src/model.rs"), MODEL_SOURCE).expect("model fixture");
        fs::write(source.join("src/ledger.rs"), LEDGER_SOURCE).expect("ledger fixture");
        fs::write(source.join("docs/guide.md"), MARKDOWN_SOURCE).expect("markdown fixture");
        prepare_git_repository(&source);
    }
    let catalog = ensure_template_catalog(root);
    let workspace = root.join(workspace_name);
    fs::create_dir_all(&workspace).expect("workspace dir");
    let context = context(root);
    let inspected = execute_ok(
        &context,
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
    let template_ref = validated.result["validation_ref"].clone();
    let mut plan_request = OperationRequest::new(
        OperationId::BuildPlan,
        "req-build.plan-e07".to_owned(),
        json!({
            "workspace_root": workspace,
            "mode": "full",
            "source_inspection_ref": source_ref,
            "template_validation_ref": template_ref,
            "bundle_version": "0.1.0"
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
    let planned = Dispatcher
        .execute(&context, plan_request)
        .expect("build.plan succeeds");
    let run_id = planned.run_id.clone().expect("run id");
    execute_ok(
        &context,
        OperationId::BuildPrepare,
        Some(&run_id),
        json!({"workspace_root": workspace}),
    );
    loop {
        let next = execute_ok(
            &context,
            OperationId::SummaryNext,
            Some(&run_id),
            json!({"workspace_root": workspace}),
        );
        let Some(job) = next.result.get("job").filter(|value| !value.is_null()) else {
            break;
        };
        let source_path = job["source_path"].as_str().expect("source path");
        execute_ok(
            &context,
            OperationId::SummaryAccept,
            Some(&run_id),
            json!({
                "workspace_root": workspace,
                "packet_id": job["packet_id"],
                "source_sha256": job["source_sha256"],
                "template_manifest_sha256": job["template_manifest_sha256"],
                "summary_markdown": format!("Summary for {source_path}")
            }),
        );
    }
    let finalized = execute_ok(
        &context,
        OperationId::BuildFinalize,
        Some(&run_id),
        json!({"workspace_root": workspace}),
    );
    let bundle_path = PathBuf::from(
        finalized.result["bundle_path"]
            .as_str()
            .expect("bundle path"),
    );
    let verified = execute_ok(
        &context,
        OperationId::BundleVerify,
        None,
        json!({
            "bundle_path": bundle_path,
            "expected_tree_sha256": finalized.result["tree_digest"]
        }),
    );
    assert_eq!(verified.result["valid"], json!(true));
    bundle_path
}

fn context(root: &Path) -> CallContext {
    CallContext::restricted(
        TransportKind::Test,
        vec![root.to_path_buf()],
        EffectPolicy::WorkspaceWrite,
    )
    .expect("restricted context")
}

fn execute_ok(
    context: &CallContext,
    operation: OperationId,
    run_id: Option<&str>,
    payload: Value,
) -> OperationResponse {
    let mut request = OperationRequest::new(
        operation,
        format!("req-e07-{}", operation.as_str()),
        payload,
    );
    request.run_id = run_id.map(str::to_owned);
    Dispatcher
        .execute(context, request)
        .unwrap_or_else(|error| panic!("{} failed: {error:#?}", operation.as_str()))
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
