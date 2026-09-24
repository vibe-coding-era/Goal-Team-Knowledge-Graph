//! E04 frozen contract: summary claim-span semantic acceptance gate.
//!
//! Claim format (strict, machine-readable): a summary body may contain claim
//! lines of the exact form
//! `- claim: <claim text> | evidence: <ref>[, <ref>...]`
//! where each ref is one of
//! `fact:<kind>:<marker_id>`, `def:<name>`, `import:<module>`,
//! `call:<caller>-><callee>` resolved against the packet's observed facts and
//! E02 semantic records. A `!` prefix negates the ref: the claim asserts the
//! evidence is absent; if it is present the claim contradicts the packet.
//!
//! Oracles:
//! (a) claims whose citations all resolve are accepted; the accept response
//!     reports claim_count/cited_claim_count and the fixture citation
//!     coverage is 100% (>= 90% floor); the cited summary reaches the bundle.
//! (b) unsupported citations (unknown ref, missing evidence segment, empty
//!     claim text) fail closed with E_INVALID_REQUEST and leave no candidate.
//! (c) B16 flip: a contradicting summary (negated ref whose evidence exists)
//!     is rejected and its text never becomes queryable bundle knowledge.
//! (d) backward compatibility: summaries without claim lines are accepted
//!     unchanged with claim_count = 0.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use gtkg_core::file_model::sha256_file;
use gtkg_core::{CallContext, Dispatcher, EffectPolicy, TransportKind};
use gtkg_protocol::{
    ErrorCode, OperationId, OperationRequest, OperationResponse, OperationStatus,
    canonical_json_sha256,
};
use serde_json::{Value, json};
use tempfile::tempdir;

const RUST_SOURCE: &str = r#"use std::collections::HashMap;

pub struct Account {
    pub id: u64,
    pub name: String,
}

impl Account {
    pub fn new(id: u64, name: String) -> Self {
        Self { id, name }
    }
}

pub fn reconcile(account: &Account, store: &HashMap<u64, String>) -> bool {
    account.id > 0 && store.is_empty()
}
"#;

const MARKDOWN_SOURCE: &str = "---\ntype: note\ntitle: Guide\nevidence_ref: \"docs/guide.md\"\n---\n\n# Guide\n\nEvidence text.\n";

#[test]
fn supported_claims_with_full_citations_are_accepted() {
    let temp = tempdir().expect("tempdir");
    let fixture = PreparedRun::start(temp.path());
    let jobs = fixture.collect_jobs(|job| {
        let source_path = job["source_path"].as_str().expect("source path");
        if source_path.ends_with(".rs") {
            [
                format!("Summary for {source_path}"),
                "- claim: reconcile 判定账户与存储状态 | evidence: def:reconcile".to_owned(),
                "- claim: 模块引入 HashMap 集合类型 | evidence: import:std::collections::HashMap"
                    .to_owned(),
                "- claim: reconcile 依赖 store.is_empty 调用 | evidence: call:reconcile->is_empty"
                    .to_owned(),
            ]
            .join("\n")
        } else {
            [
                format!("Summary for {source_path}"),
                "- claim: 文档在 frontmatter 声明了证据引用 | evidence: fact:evidence_ref:docs/guide.md"
                    .to_owned(),
            ]
            .join("\n")
        }
    });
    assert_eq!(jobs, 2);
    let finalized = fixture.finalize();
    assert_eq!(finalized.status, OperationStatus::Completed);
    let bundle_path = finalized.result["bundle_path"].as_str().expect("bundle");
    let tree_digest = finalized.result["tree_digest"]
        .as_str()
        .expect("tree digest");
    let query = fixture.execute_ok(
        OperationId::BundleQuery,
        None,
        json!({
            "bundle_path": bundle_path,
            "expected_tree_sha256": tree_digest,
            "query": "reconcile 判定账户与存储状态"
        }),
    );
    assert!(
        !query.result["matches"]
            .as_array()
            .expect("matches")
            .is_empty(),
        "cited claim text must be queryable bundle knowledge"
    );
}

#[test]
fn unsupported_claim_citations_fail_closed() {
    let temp = tempdir().expect("tempdir");
    let fixture = PreparedRun::start(temp.path());
    let job = fixture.first_job();
    let source_sha256 = job["source_sha256"].clone();
    let template_manifest_sha256 = job["template_manifest_sha256"].clone();
    let packet_id = job["packet_id"].as_str().expect("packet id").to_owned();
    let base = json!({
        "workspace_root": fixture.workspace,
        "packet_id": packet_id,
        "source_sha256": source_sha256,
        "template_manifest_sha256": template_manifest_sha256,
    });
    for (label, markdown) in [
        (
            "unknown def citation",
            "Summary\n\n- claim: 声明不存在的函数 | evidence: def:nonexistent_function",
        ),
        (
            "unknown fact citation",
            "Summary\n\n- claim: 引用不存在的事实 | evidence: fact:evidence_ref:missing.md",
        ),
        (
            "missing evidence segment",
            "Summary\n\n- claim: 没有证据段的声明",
        ),
        (
            "empty claim text",
            "Summary\n\n- claim:  | evidence: def:reconcile",
        ),
        (
            "malformed claim prefix",
            "Summary\n\n- claim:no space | evidence: def:reconcile",
        ),
    ] {
        let mut payload = base.clone();
        payload["summary_markdown"] = json!(markdown);
        let code = fixture.execute_err(OperationId::SummaryAccept, payload);
        assert_eq!(code, ErrorCode::InvalidRequest, "{label} must fail closed");
    }
    assert!(
        !fixture
            .run_dir()
            .join("candidates")
            .join(format!("{packet_id}.json"))
            .exists(),
        "rejected summaries must leave no candidate behind"
    );
}

#[test]
fn contradicting_claim_is_rejected_and_never_enters_the_bundle() {
    let temp = tempdir().expect("tempdir");
    let fixture = PreparedRun::start(temp.path());
    let contradiction = "源文件未定义任何 reconcile 函数";
    let jobs = fixture.collect_jobs(|job| {
        let source_path = job["source_path"].as_str().expect("source path");
        if source_path.ends_with(".rs") {
            let code = fixture.execute_err(
                OperationId::SummaryAccept,
                json!({
                    "workspace_root": fixture.workspace,
                    "packet_id": job["packet_id"],
                    "source_sha256": job["source_sha256"],
                    "template_manifest_sha256": job["template_manifest_sha256"],
                    "summary_markdown": format!(
                        "Summary for {source_path}\n\n- claim: {contradiction} | evidence: !def:reconcile"
                    )
                }),
            );
            assert_eq!(
                code,
                ErrorCode::InvalidRequest,
                "B16: a claim contradicting packet evidence must be rejected"
            );
        }
        if source_path.ends_with(".rs") {
            format!(
                "Summary for {source_path}\n\n- claim: reconcile 存在且有定义 | evidence: def:reconcile"
            )
        } else {
            format!(
                "Summary for {source_path}\n\n- claim: 文档声明了证据引用 | evidence: fact:evidence_ref:docs/guide.md"
            )
        }
    });
    assert_eq!(jobs, 2);
    let finalized = fixture.finalize();
    assert_eq!(finalized.status, OperationStatus::Completed);
    let query = fixture.execute_ok(
        OperationId::BundleQuery,
        None,
        json!({
            "bundle_path": finalized.result["bundle_path"],
            "expected_tree_sha256": finalized.result["tree_digest"],
            "query": contradiction
        }),
    );
    assert_eq!(
        query.result["matches"].as_array().expect("matches").len(),
        0,
        "B16: rejected contradicting text must never become queryable knowledge"
    );
}

#[test]
fn summaries_without_claim_lines_are_unaffected() {
    let temp = tempdir().expect("tempdir");
    let fixture = PreparedRun::start(temp.path());
    let jobs = fixture.collect_jobs(|job| {
        let source_path = job["source_path"].as_str().expect("source path");
        format!("Summary for {source_path}")
    });
    assert_eq!(jobs, 2);
    let finalized = fixture.finalize();
    assert_eq!(finalized.status, OperationStatus::Completed);
}

struct PreparedRun {
    root: PathBuf,
    workspace: PathBuf,
    run_id: String,
}

impl PreparedRun {
    fn start(root: &Path) -> Self {
        let source = root.join("source");
        fs::create_dir_all(source.join("src")).expect("src dir");
        fs::create_dir_all(source.join("docs")).expect("docs dir");
        fs::write(source.join("src/ledger.rs"), RUST_SOURCE).expect("rust fixture");
        fs::write(source.join("docs/guide.md"), MARKDOWN_SOURCE).expect("markdown fixture");
        prepare_git_repository(&source);
        let catalog = ensure_template_catalog(root);
        let workspace = root.join("workspace");
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
            "req-build.plan-e04".to_owned(),
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
        let prepare = execute_ok(
            &context,
            OperationId::BuildPrepare,
            Some(&run_id),
            json!({"workspace_root": workspace}),
        );
        assert!(matches!(
            prepare.status,
            OperationStatus::NeedsLlm | OperationStatus::Completed
        ));
        Self {
            root: root.to_path_buf(),
            workspace,
            run_id,
        }
    }

    fn run_dir(&self) -> PathBuf {
        self.workspace.join(".gtkg/runs").join(&self.run_id)
    }

    fn first_job(&self) -> Value {
        let next = self.execute_ok(
            OperationId::SummaryNext,
            Some(&self.run_id),
            json!({"workspace_root": self.workspace}),
        );
        next.result["job"].clone()
    }

    fn collect_jobs(&self, mut summarize: impl FnMut(&Value) -> String) -> usize {
        let mut jobs = 0_usize;
        loop {
            let next = self.execute_ok(
                OperationId::SummaryNext,
                Some(&self.run_id),
                json!({"workspace_root": self.workspace}),
            );
            let Some(job) = next.result.get("job").filter(|value| !value.is_null()) else {
                break;
            };
            jobs += 1;
            let summary_markdown = summarize(job);
            let accepted = self.execute_ok(
                OperationId::SummaryAccept,
                Some(&self.run_id),
                json!({
                    "workspace_root": self.workspace,
                    "packet_id": job["packet_id"],
                    "source_sha256": job["source_sha256"],
                    "template_manifest_sha256": job["template_manifest_sha256"],
                    "summary_markdown": summary_markdown
                }),
            );
            assert_eq!(accepted.status, OperationStatus::Completed);
            let claim_lines = summary_markdown
                .lines()
                .filter(|line| line.starts_with("- claim: "))
                .count() as u64;
            assert_eq!(
                accepted.result["claim_count"].as_u64(),
                Some(claim_lines),
                "accept response must report the parsed claim count"
            );
            assert_eq!(
                accepted.result["cited_claim_count"].as_u64(),
                Some(claim_lines),
                "every accepted claim must carry a resolved citation"
            );
            if claim_lines > 0 {
                let coverage = accepted.result["cited_claim_count"]
                    .as_u64()
                    .expect("cited") as f64
                    / claim_lines as f64;
                assert!(
                    coverage >= 0.9,
                    "fixture claim citation coverage {coverage} must meet the 90% floor"
                );
            }
        }
        jobs
    }

    fn finalize(&self) -> OperationResponse {
        self.execute_ok(
            OperationId::BuildFinalize,
            Some(&self.run_id),
            json!({"workspace_root": self.workspace}),
        )
    }

    fn execute_ok(
        &self,
        operation: OperationId,
        run_id: Option<&str>,
        payload: Value,
    ) -> OperationResponse {
        let mut request = OperationRequest::new(
            operation,
            format!("req-e04-{}", operation.as_str()),
            payload,
        );
        request.run_id = run_id.map(str::to_owned);
        Dispatcher
            .execute(&context(&self.root), request)
            .unwrap_or_else(|error| panic!("{} failed: {error:#?}", operation.as_str()))
    }

    fn execute_err(&self, operation: OperationId, payload: Value) -> ErrorCode {
        let mut request = OperationRequest::new(
            operation,
            format!("req-e04-error-{}", operation.as_str()),
            payload,
        );
        request.run_id = Some(self.run_id.clone());
        Dispatcher
            .execute(&context(&self.root), request)
            .expect_err("operation must fail")
            .error
            .code
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
        format!("req-e04-{}", operation.as_str()),
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
