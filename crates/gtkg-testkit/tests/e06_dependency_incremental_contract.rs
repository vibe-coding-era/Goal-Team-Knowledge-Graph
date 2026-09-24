//! E06 frozen contract: dependency-aware incremental invalidation propagation.
//!
//! Oracles:
//! (a) changing a callee module invalidates its direct and transitive
//!     dependents: the re-summarized exact-set after editing `src/model.rs`
//!     is exactly {model.rs, ledger.rs, main.rs} (recall 100%), while
//!     `docs/guide.md` keeps baseline reuse.
//! (b) changing a leaf module invalidates only itself: the re-summarized
//!     exact-set after editing `src/main.rs` is exactly {main.rs}.
//! (c) fresh/full vs incremental semantic digest equivalence is preserved
//!     under dependency propagation.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use gtkg_core::file_model::sha256_file;
use gtkg_core::{CallContext, Dispatcher, EffectPolicy, TransportKind};
use gtkg_protocol::{OperationId, OperationRequest, OperationResponse, canonical_json_sha256};
use serde_json::{Value, json};
use tempfile::tempdir;

const MODEL_V1: &str = r#"#[derive(Default)]
pub struct Ledger {
    pub entries: u64,
}

impl Ledger {
    pub fn is_empty(&self) -> bool {
        self.entries == 0
    }
}
"#;

const MODEL_V2: &str = r#"#[derive(Default)]
pub struct Ledger {
    pub entries: u64,
    pub archived: bool,
}

impl Ledger {
    pub fn is_empty(&self) -> bool {
        self.entries == 0 && !self.archived
    }
}
"#;

const LEDGER_SOURCE: &str = r#"use crate::model::Ledger;

pub fn reconcile(ledger: &Ledger) -> bool {
    ledger.is_empty()
}
"#;

const MAIN_V1: &str = r#"use crate::ledger;

pub fn main_entry() -> bool {
    ledger::reconcile(&ledger::Ledger::default())
}
"#;

const MAIN_V2: &str = r#"use crate::ledger;

pub fn main_entry() -> bool {
    ledger::reconcile(&ledger::Ledger::default()) && true
}
"#;

const MARKDOWN_SOURCE: &str = "# Guide\n\nStable documentation.\n";

struct Built {
    jobs: Vec<String>,
    prepare: Value,
    semantic_digest: String,
    bundle_path: String,
    tree_digest: String,
}

#[test]
fn callee_change_invalidates_direct_and_transitive_dependents_exactly() {
    let temp = tempdir().expect("tempdir");
    let source = temp.path().join("source");
    write_fixture(&source, MODEL_V1, MAIN_V1);
    let baseline = build(temp.path(), "baseline-workspace", "full", None, "0.1.0");
    assert_eq!(baseline.jobs.len(), 4, "full build summarizes every source");

    fs::write(source.join("src/model.rs"), MODEL_V2).expect("edit callee module");
    prepare_git_repository(&source);
    let incremental = build(
        temp.path(),
        "incremental-workspace",
        "incremental",
        Some(&baseline),
        "0.2.0",
    );
    assert_eq!(
        incremental.jobs,
        vec!["src/ledger.rs", "src/main.rs", "src/model.rs"],
        "changed callee must invalidate its direct and transitive dependents (recall 100%)"
    );
    assert_eq!(incremental.prepare["extracted_count"], json!(3));
    assert_eq!(incremental.prepare["reused_count"], json!(1));

    let fresh = build(temp.path(), "fresh-workspace", "full", None, "0.2.0");
    assert_eq!(
        incremental.semantic_digest, fresh.semantic_digest,
        "dependency-propagated incremental build must equal a fresh full build"
    );
}

#[test]
fn leaf_change_invalidates_only_itself() {
    let temp = tempdir().expect("tempdir");
    let source = temp.path().join("source");
    write_fixture(&source, MODEL_V1, MAIN_V1);
    let baseline = build(temp.path(), "baseline-workspace", "full", None, "0.1.0");

    fs::write(source.join("src/main.rs"), MAIN_V2).expect("edit leaf module");
    prepare_git_repository(&source);
    let incremental = build(
        temp.path(),
        "incremental-workspace",
        "incremental",
        Some(&baseline),
        "0.2.0",
    );
    assert_eq!(
        incremental.jobs,
        vec!["src/main.rs"],
        "a leaf change must not invalidate its dependencies"
    );
    assert_eq!(incremental.prepare["extracted_count"], json!(1));
    assert_eq!(incremental.prepare["reused_count"], json!(3));

    let fresh = build(temp.path(), "fresh-workspace", "full", None, "0.2.0");
    assert_eq!(incremental.semantic_digest, fresh.semantic_digest);
}

fn write_fixture(source: &Path, model: &str, main: &str) {
    fs::create_dir_all(source.join("src")).expect("src dir");
    fs::create_dir_all(source.join("docs")).expect("docs dir");
    fs::write(source.join("src/model.rs"), model).expect("model fixture");
    fs::write(source.join("src/ledger.rs"), LEDGER_SOURCE).expect("ledger fixture");
    fs::write(source.join("src/main.rs"), main).expect("main fixture");
    fs::write(source.join("docs/guide.md"), MARKDOWN_SOURCE).expect("markdown fixture");
    prepare_git_repository(source);
}

fn build(
    root: &Path,
    workspace_name: &str,
    mode: &str,
    baseline: Option<&Built>,
    version: &str,
) -> Built {
    let source = root.join("source");
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
    let mut plan_payload = json!({
        "workspace_root": workspace,
        "mode": mode,
        "source_inspection_ref": source_ref,
        "template_validation_ref": template_ref,
        "bundle_version": version
    });
    if let Some(baseline) = baseline {
        plan_payload["baseline_bundle"] = json!(baseline.bundle_path);
        plan_payload["baseline_tree_sha256"] = json!(baseline.tree_digest);
    }
    let mut plan_request = OperationRequest::new(
        OperationId::BuildPlan,
        format!("req-build.plan-e06-{version}"),
        plan_payload,
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
    let prepare = execute_ok(
        &context,
        OperationId::BuildPrepare,
        Some(&run_id),
        json!({"workspace_root": workspace}),
    );
    let mut jobs = Vec::new();
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
        jobs.push(source_path.to_owned());
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
    Built {
        jobs,
        prepare: prepare.result,
        semantic_digest: finalized.result["semantic_digest"]
            .as_str()
            .expect("semantic digest")
            .to_owned(),
        bundle_path: finalized.result["bundle_path"]
            .as_str()
            .expect("bundle path")
            .to_owned(),
        tree_digest: finalized.result["tree_digest"]
            .as_str()
            .expect("tree digest")
            .to_owned(),
    }
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
        format!("req-e06-{}", operation.as_str()),
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
