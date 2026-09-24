//! E03 frozen contract: SummaryJob facts/symbols supply and model identity binding.
//!
//! Oracles:
//! (a) a real pipeline run over a fixture repository with Rust, Python and
//!     Markdown sources serves summary.next jobs whose packet carries the
//!     observed facts, the E02 semantic records (definitions/imports/calls)
//!     and the template body/constraints (B15 adversarial assertion flipped).
//! (b) a summary declaring a leading `model: <id>` metadata line is accepted
//!     and the exact identity string is bound into the acceptance receipt and
//!     verified by the ledger digest chain.
//! (c) a summary without any declaration is still accepted and its receipt
//!     records the explicit identity "unspecified".
//! (d) packet and receipt serialization is deterministic: two independent
//!     builds over the same sources yield identical packet/receipt digests.
//! (e) tampering with the facts inside a packet file (facts inconsistent with
//!     the locked source digest) fails closed with a lock mismatch.

use std::collections::BTreeMap;
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

const PYTHON_SOURCE: &str = r#"import json
from typing import Optional

class Account:
    def describe(self) -> str:
        return json.dumps({"id": 1})

def reconcile(account: Account) -> Optional[bool]:
    return account.describe() is not None
"#;

const MARKDOWN_SOURCE: &str = "---\ntype: note\ntitle: Guide\nevidence_ref: \"docs/guide.md\"\n---\n\n# Guide\n\nEvidence text.\n";

#[test]
fn summary_next_job_supplies_facts_semantics_and_template_constraints() {
    let temp = tempdir().expect("tempdir");
    let fixture = PreparedRun::start(temp.path(), true);
    let mut saw_code_semantics = 0_usize;
    let mut saw_facts = 0_usize;
    let jobs = fixture.collect_jobs(|job| {
        let source_path = job["source_path"].as_str().expect("source path");
        let facts = job["observed_facts"]
            .as_array()
            .expect("job must carry observed_facts (B15)");
        let observations = job["observations"]
            .as_object()
            .expect("job must carry observations (B15)");
        let template_markdown = job["template_markdown"]
            .as_str()
            .expect("job must carry the template body");
        let slot_ids = job["template_slot_ids"]
            .as_array()
            .expect("job must carry template slot ids");
        let constraints = job["constraints"]
            .as_object()
            .expect("job must carry host constraints");

        assert!(
            template_markdown.contains("# Summary"),
            "template body must be supplied to the host"
        );
        assert_eq!(
            slot_ids,
            &vec![json!("summary")],
            "template slot ids must be supplied"
        );
        assert_eq!(
            constraints["evidence_scope"].as_str(),
            Some("packet_only"),
            "host constraint must restrict generation to packet evidence"
        );
        let identity_rule = constraints["model_identity_rule"]
            .as_str()
            .expect("model identity rule");
        assert!(
            identity_rule.contains("model:"),
            "identity rule must document the declaration line: {identity_rule}"
        );

        if !facts.is_empty() {
            saw_facts += 1;
        }
        if source_path.ends_with(".rs") || source_path.ends_with(".py") {
            let definitions = observations
                .get("semantic_definitions")
                .and_then(Value::as_str)
                .expect("semantic definitions section");
            let imports = observations
                .get("semantic_imports")
                .and_then(Value::as_str)
                .expect("semantic imports section");
            let calls = observations
                .get("semantic_calls")
                .and_then(Value::as_str)
                .expect("semantic calls section");
            assert!(
                !definitions.is_empty() && !imports.is_empty() && !calls.is_empty(),
                "{source_path} must supply definitions/imports/calls to the host"
            );
            assert!(
                observations
                    .get("semantics_digest")
                    .and_then(Value::as_str)
                    .is_some_and(|digest| digest.starts_with("sha256:")),
                "{source_path} must carry the E02 semantics digest"
            );
            saw_code_semantics += 1;
        }
        format!("Summary for {source_path}")
    });
    assert_eq!(jobs, 3, "fixture repository must yield three summary jobs");
    assert_eq!(
        saw_code_semantics, 2,
        "both code files must supply semantics"
    );
    assert!(
        saw_facts >= 1,
        "the markdown evidence_ref fixture must supply non-empty facts"
    );
}

#[test]
fn declared_model_identity_is_bound_into_receipt_and_ledger() {
    let temp = tempdir().expect("tempdir");
    let fixture = PreparedRun::start(temp.path(), false);
    let jobs = fixture.collect_jobs(|job| {
        let source_path = job["source_path"].as_str().expect("source path");
        format!(
            "model: e03-fixture-model-7\ngenerator: e03-testkit-generator\nparameters: {{\"temperature\":0,\"seed\":7}}\n\nSummary for {source_path}"
        )
    });
    assert_eq!(jobs, 1);
    let packet_id = fixture.only_packet_id();
    let receipt_path = fixture
        .run_dir()
        .join("accepted")
        .join(format!("{packet_id}.json"));
    let receipt: Value = serde_json::from_slice(&fs::read(&receipt_path).expect("receipt bytes"))
        .expect("receipt json");
    assert_eq!(
        receipt["model_identity"].as_str(),
        Some("e03-fixture-model-7"),
        "receipt must bind the exact declared identity"
    );
    let ledger = fs::read_to_string(fixture.run_dir().join("acceptance-events.ndjson"))
        .expect("acceptance ledger");
    let event: Value =
        serde_json::from_str(ledger.lines().next().expect("one event")).expect("ledger event json");
    assert_eq!(
        event["acceptance_receipt_sha256"].as_str(),
        Some(sha256_file(&receipt_path).expect("receipt digest").as_str()),
        "ledger event must bind the receipt digest"
    );
    let head: Value = serde_json::from_slice(
        &fs::read(fixture.run_dir().join("acceptance-head.json")).expect("head bytes"),
    )
    .expect("head json");
    assert_eq!(
        head["head_sha256"].as_str(),
        event["event_sha256"].as_str(),
        "acceptance head must pin the ledger tip"
    );
    let finalized = fixture.finalize();
    assert_eq!(finalized.status, OperationStatus::Completed);
}

#[test]
fn summary_without_declaration_is_accepted_as_unspecified() {
    let temp = tempdir().expect("tempdir");
    let fixture = PreparedRun::start(temp.path(), false);
    let jobs = fixture.collect_jobs(|job| {
        let source_path = job["source_path"].as_str().expect("source path");
        format!("Summary for {source_path}")
    });
    assert_eq!(jobs, 1);
    let packet_id = fixture.only_packet_id();
    let receipt: Value = serde_json::from_slice(
        &fs::read(
            fixture
                .run_dir()
                .join("accepted")
                .join(format!("{packet_id}.json")),
        )
        .expect("receipt bytes"),
    )
    .expect("receipt json");
    assert_eq!(
        receipt["model_identity"].as_str(),
        Some("unspecified"),
        "missing declaration must be recorded explicitly as unspecified"
    );
    let finalized = fixture.finalize();
    assert_eq!(finalized.status, OperationStatus::Completed);
}

#[test]
fn packet_and_receipt_serialization_is_deterministic_across_builds() {
    let temp = tempdir().expect("tempdir");
    let digests = |workspace_name: &str| {
        let fixture = PreparedRun::start_named(temp.path(), workspace_name, true);
        fixture.collect_jobs(|job| {
            let source_path = job["source_path"].as_str().expect("source path");
            format!("model: e03-determinism-model\n\nSummary for {source_path}")
        });
        let packets = dir_digests(&fixture.run_dir().join("packets"));
        let receipts = dir_digests(&fixture.run_dir().join("accepted"));
        let finalized = fixture.finalize();
        let semantic_digest = finalized.result["semantic_digest"]
            .as_str()
            .expect("semantic digest")
            .to_owned();
        (packets, receipts, semantic_digest)
    };
    let first = digests("workspace-a");
    let second = digests("workspace-b");
    assert_eq!(first.0, second.0, "packet files must be deterministic");
    assert_eq!(first.1, second.1, "receipt files must be deterministic");
    assert_eq!(first.2, second.2, "semantic digest must be deterministic");
}

#[test]
fn tampered_packet_facts_fail_closed() {
    let temp = tempdir().expect("tempdir");
    let fixture = PreparedRun::start(temp.path(), true);
    let packet_id = fixture.only_packet_id_with_facts();
    let packet_path = fixture
        .run_dir()
        .join("packets")
        .join(format!("{packet_id}.json"));
    let mut packet: Value = serde_json::from_slice(&fs::read(&packet_path).expect("packet bytes"))
        .expect("packet json");
    let marker = packet["observed_facts"][0]["marker_id"]
        .as_str()
        .expect("marker id")
        .to_owned();
    let mut tampered = marker.clone();
    tampered.replace_range(..1, if marker.starts_with('d') { "e" } else { "d" });
    packet["observed_facts"][0]["marker_id"] = json!(tampered);
    fs::write(
        &packet_path,
        serde_json::to_vec_pretty(&packet).expect("tampered packet bytes"),
    )
    .expect("rewrite tampered packet");

    let next_error = fixture.execute_err(
        OperationId::SummaryNext,
        json!({"workspace_root": fixture.workspace}),
    );
    assert_eq!(
        next_error,
        ErrorCode::LockMismatch,
        "serving a tampered packet must fail closed"
    );
    let packet_json: Value = serde_json::from_slice(&fs::read(&packet_path).expect("packet bytes"))
        .expect("packet json");
    let accept_error = fixture.execute_err(
        OperationId::SummaryAccept,
        json!({
            "workspace_root": fixture.workspace,
            "packet_id": packet_id,
            "source_sha256": packet_json["source_sha256"],
            "template_manifest_sha256": packet_json["template_manifest_sha256"],
            "summary_markdown": "Summary over tampered facts"
        }),
    );
    assert_eq!(
        accept_error,
        ErrorCode::LockMismatch,
        "accepting against tampered facts must fail closed"
    );
}

struct PreparedRun {
    root: PathBuf,
    workspace: PathBuf,
    run_id: String,
}

impl PreparedRun {
    fn start(root: &Path, code: bool) -> Self {
        Self::start_named(root, "workspace", code)
    }

    fn start_named(root: &Path, workspace_name: &str, code: bool) -> Self {
        let source = root.join("source");
        fs::create_dir_all(&source).expect("source dir");
        if code {
            fs::create_dir_all(source.join("src")).expect("src dir");
            fs::create_dir_all(source.join("scripts")).expect("scripts dir");
            fs::create_dir_all(source.join("docs")).expect("docs dir");
            fs::write(source.join("src/ledger.rs"), RUST_SOURCE).expect("rust fixture");
            fs::write(source.join("scripts/ledger.py"), PYTHON_SOURCE).expect("python fixture");
            fs::write(source.join("docs/guide.md"), MARKDOWN_SOURCE).expect("markdown fixture");
        } else {
            fs::write(source.join("guide.md"), MARKDOWN_SOURCE).expect("markdown fixture");
        }
        prepare_git_repository(&source);
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
            "req-build.plan-e03".to_owned(),
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
        assert!(
            matches!(
                prepare.status,
                OperationStatus::NeedsLlm | OperationStatus::Completed
            ),
            "build.prepare must reach the summary loop"
        );
        Self {
            root: root.to_path_buf(),
            workspace,
            run_id,
        }
    }

    fn run_dir(&self) -> PathBuf {
        self.workspace.join(".gtkg/runs").join(&self.run_id)
    }

    fn only_packet_id(&self) -> String {
        let mut ids = packet_ids(&self.run_dir());
        assert_eq!(ids.len(), 1, "expected exactly one packet");
        ids.remove(0)
    }

    fn only_packet_id_with_facts(&self) -> String {
        let packets_dir = self.run_dir().join("packets");
        let mut entries: Vec<(String, PathBuf)> = fs::read_dir(&packets_dir)
            .expect("packets dir")
            .map(|entry| entry.expect("packet entry").path())
            .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("json"))
            .map(|path| {
                let packet: Value = serde_json::from_slice(&fs::read(&path).expect("packet bytes"))
                    .expect("packet json");
                (packet, path)
            })
            .filter(|(packet, _)| {
                packet["observed_facts"]
                    .as_array()
                    .is_some_and(|facts| !facts.is_empty())
            })
            .map(|(packet, path)| {
                (
                    packet["packet_id"].as_str().expect("packet id").to_owned(),
                    path,
                )
            })
            .collect();
        entries.sort();
        assert!(
            !entries.is_empty(),
            "fixture must contain at least one packet with facts"
        );
        entries.remove(0).0
    }

    /// Drives the summary loop: for every served job the callback produces the
    /// summary markdown, which is then accepted. Returns the number of jobs.
    fn collect_jobs(&self, mut summarize: impl FnMut(&Value) -> String) -> usize {
        let context = context(&self.root);
        let mut jobs = 0_usize;
        loop {
            let next = execute_ok(
                &context,
                OperationId::SummaryNext,
                Some(&self.run_id),
                json!({"workspace_root": self.workspace}),
            );
            let Some(job) = next.result.get("job").filter(|value| !value.is_null()) else {
                break;
            };
            jobs += 1;
            let summary_markdown = summarize(job);
            let accepted = execute_ok(
                &context,
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
            assert_eq!(accepted.result["accepted"], json!(true));
            if summary_markdown.starts_with("model: ") {
                let declared = summary_markdown
                    .lines()
                    .next()
                    .and_then(|line| line.strip_prefix("model: "))
                    .expect("declared identity");
                assert_eq!(
                    accepted.result["model_identity"].as_str(),
                    Some(declared),
                    "accept response must echo the bound model identity"
                );
            } else {
                assert_eq!(
                    accepted.result["model_identity"].as_str(),
                    Some("unspecified"),
                    "undeclared summaries must echo unspecified identity"
                );
            }
        }
        jobs
    }

    fn finalize(&self) -> OperationResponse {
        execute_ok(
            &context(&self.root),
            OperationId::BuildFinalize,
            Some(&self.run_id),
            json!({"workspace_root": self.workspace}),
        )
    }

    fn execute_err(&self, operation: OperationId, payload: Value) -> ErrorCode {
        let mut request = OperationRequest::new(
            operation,
            format!("req-e03-error-{}", operation.as_str()),
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

fn packet_ids(run_dir: &Path) -> Vec<String> {
    let mut ids: Vec<String> = fs::read_dir(run_dir.join("packets"))
        .expect("packets dir")
        .map(|entry| entry.expect("packet entry").path())
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("json"))
        .map(|path| {
            path.file_stem()
                .expect("packet file stem")
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    ids.sort();
    ids
}

fn dir_digests(directory: &Path) -> BTreeMap<String, String> {
    fs::read_dir(directory)
        .expect("digest dir")
        .map(|entry| entry.expect("dir entry").path())
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("json"))
        .map(|path| {
            (
                path.file_name()
                    .expect("file name")
                    .to_string_lossy()
                    .into_owned(),
                sha256_file(&path).expect("file digest"),
            )
        })
        .collect()
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
        format!("req-e03-{}", operation.as_str()),
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
