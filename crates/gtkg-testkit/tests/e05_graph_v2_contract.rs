//! E05 frozen contract: Knowledge Graph v2 entities, typed edges and the
//! explicit unknown/conflict output contract.
//!
//! Oracles:
//! (a) a real pipeline build over a multi-module Rust fixture emits
//!     module_entity and symbol_entity rows plus typed edges defines /
//!     imports / calls / documents alongside the legacy summarizes
//!     knowledge_entity rows; bundle.verify stays valid.
//! (b) unresolvable references produce explicit `state: "unknown"` edges
//!     carrying the raw target; ambiguous references produce explicit
//!     `state: "conflict"` edges carrying the sorted candidate list.
//! (c) graph.ndjson is deterministic: two independent builds over the same
//!     sources yield byte-identical graph files.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use gtkg_core::file_model::sha256_file;
use gtkg_core::{CallContext, Dispatcher, EffectPolicy, TransportKind};
use gtkg_protocol::{
    OperationId, OperationRequest, OperationResponse, OperationStatus, canonical_json_sha256,
};
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

fn helper() -> bool {
    let ledger = Ledger::default();
    reconcile(&ledger)
}
"#;

const UTIL_A_SOURCE: &str = "pub fn util_a() -> bool {\n    true\n}\n";
const UTIL_B_SOURCE: &str = "pub fn util_b() -> bool {\n    false\n}\n";

const MAIN_SOURCE: &str = r#"use crate::util;

pub fn main_entry() -> bool {
    util::util_a()
}
"#;

fn graph_rows(bundle: &Path) -> Vec<Value> {
    fs::read_to_string(bundle.join("indexes/graph.ndjson"))
        .expect("graph.ndjson")
        .lines()
        .map(|line| serde_json::from_str(line).expect("graph row json"))
        .collect()
}

fn edges<'a>(rows: &'a [Value], relation: &str) -> Vec<&'a Value> {
    rows.iter()
        .filter(|row| row["type"] == "graph_edge" && row["relation"] == relation)
        .collect()
}

#[test]
fn graph_v2_contains_module_and_symbol_entities_with_typed_edges() {
    let temp = tempdir().expect("tempdir");
    let fixture = PreparedRun::start(temp.path());
    let built = fixture.build();
    let rows = graph_rows(&built.bundle_path);

    let module_ids: Vec<&str> = rows
        .iter()
        .filter(|row| row["type"] == "module_entity")
        .filter_map(|row| row["module_id"].as_str())
        .collect();
    for path in [
        "src/model.rs",
        "src/ledger.rs",
        "src/main.rs",
        "src/a/util.rs",
        "src/b/util.rs",
    ] {
        assert!(
            module_ids
                .iter()
                .any(|id| *id == format!("module:fixture-repo:{path}")),
            "missing module entity for {path}"
        );
    }
    let symbol_ids: Vec<&str> = rows
        .iter()
        .filter(|row| row["type"] == "symbol_entity")
        .filter_map(|row| row["symbol_id"].as_str())
        .collect();
    for symbol in [
        "symbol:fixture-repo:src/model.rs:struct:Ledger",
        "symbol:fixture-repo:src/ledger.rs:function:reconcile",
        "symbol:fixture-repo:src/ledger.rs:function:helper",
    ] {
        assert!(
            symbol_ids.contains(&symbol),
            "missing symbol entity {symbol}"
        );
    }

    let defines = edges(&rows, "defines");
    assert!(
        defines.iter().any(|edge| {
            edge["from"] == "module:fixture-repo:src/ledger.rs"
                && edge["to"] == "symbol:fixture-repo:src/ledger.rs:function:reconcile"
                && edge["state"] == "resolved"
        }),
        "module must define its symbols"
    );
    let imports = edges(&rows, "imports");
    assert!(
        imports.iter().any(|edge| {
            edge["from"] == "module:fixture-repo:src/ledger.rs"
                && edge["to"] == "module:fixture-repo:src/model.rs"
                && edge["state"] == "resolved"
        }),
        "ledger must import the model module"
    );
    let calls = edges(&rows, "calls");
    assert!(
        calls.iter().any(|edge| {
            edge["from"] == "symbol:fixture-repo:src/ledger.rs:function:helper"
                && edge["to"] == "symbol:fixture-repo:src/ledger.rs:function:reconcile"
                && edge["state"] == "resolved"
        }),
        "helper must call reconcile"
    );
    assert!(
        calls.iter().any(|edge| {
            edge["from"] == "symbol:fixture-repo:src/ledger.rs:function:reconcile"
                && edge["to"] == "symbol:fixture-repo:src/model.rs:method:is_empty"
                && edge["state"] == "resolved"
        }),
        "reconcile must call Ledger::is_empty across modules"
    );
    let documents = edges(&rows, "documents");
    assert!(
        documents.iter().any(|edge| {
            edge["to"] == "module:fixture-repo:src/ledger.rs" && edge["state"] == "resolved"
        }),
        "knowledge must document the ledger module"
    );
    assert!(
        rows.iter()
            .any(|row| row["type"] == "knowledge_entity" && row["relation"] == "summarizes"),
        "legacy summarizes rows must remain"
    );
    assert_eq!(built.verify.result["valid"], true);
}

#[test]
fn unresolvable_and_ambiguous_references_are_explicit_unknown_or_conflict() {
    let temp = tempdir().expect("tempdir");
    let fixture = PreparedRun::start(temp.path());
    let built = fixture.build();
    let rows = graph_rows(&built.bundle_path);

    let imports = edges(&rows, "imports");
    let unknown_std = imports.iter().find(|edge| {
        edge["from"] == "module:fixture-repo:src/ledger.rs" && edge["state"] == "unknown"
    });
    let unknown_std = unknown_std.expect("std import must be an explicit unknown edge");
    assert_eq!(
        unknown_std["target"].as_str(),
        Some("std::collections::HashMap"),
        "unknown edges must carry the raw target"
    );
    let conflict = imports.iter().find(|edge| {
        edge["from"] == "module:fixture-repo:src/main.rs" && edge["state"] == "conflict"
    });
    let conflict = conflict.expect("crate::util must be an explicit conflict edge");
    assert_eq!(conflict["target"].as_str(), Some("crate::util"));
    assert_eq!(
        conflict["candidates"],
        json!([
            "module:fixture-repo:src/a/util.rs",
            "module:fixture-repo:src/b/util.rs"
        ]),
        "conflict edges must carry the sorted candidate list"
    );

    let calls = edges(&rows, "calls");
    let unknown_call = calls.iter().find(|edge| {
        edge["from"] == "symbol:fixture-repo:src/ledger.rs:function:helper"
            && edge["state"] == "unknown"
    });
    let unknown_call = unknown_call.expect("Ledger::default must be an explicit unknown call");
    assert_eq!(unknown_call["target"].as_str(), Some("default"));
    assert_eq!(built.verify.result["valid"], true);
}

#[test]
fn graph_v2_is_deterministic_across_builds() {
    let temp = tempdir().expect("tempdir");
    let digests = |workspace_name: &str| {
        let fixture = PreparedRun::start_named(temp.path(), workspace_name);
        let built = fixture.build();
        sha256_file(&built.bundle_path.join("indexes/graph.ndjson")).expect("graph digest")
    };
    assert_eq!(
        digests("workspace-a"),
        digests("workspace-b"),
        "graph.ndjson must be byte-identical across independent builds"
    );
}

struct Built {
    bundle_path: PathBuf,
    verify: OperationResponse,
}

struct PreparedRun {
    root: PathBuf,
    workspace: PathBuf,
}

impl PreparedRun {
    fn start(root: &Path) -> Self {
        Self::start_named(root, "workspace")
    }

    fn start_named(root: &Path, workspace_name: &str) -> Self {
        let source = root.join("source");
        fs::create_dir_all(source.join("src/a")).expect("a dir");
        fs::create_dir_all(source.join("src/b")).expect("b dir");
        fs::write(source.join("src/model.rs"), MODEL_SOURCE).expect("model fixture");
        fs::write(source.join("src/ledger.rs"), LEDGER_SOURCE).expect("ledger fixture");
        fs::write(source.join("src/main.rs"), MAIN_SOURCE).expect("main fixture");
        fs::write(source.join("src/a/util.rs"), UTIL_A_SOURCE).expect("util a fixture");
        fs::write(source.join("src/b/util.rs"), UTIL_B_SOURCE).expect("util b fixture");
        prepare_git_repository(&source);
        ensure_template_catalog(root);
        Self {
            root: root.to_path_buf(),
            workspace: root.join(workspace_name),
        }
    }

    fn build(&self) -> Built {
        fs::create_dir_all(&self.workspace).expect("workspace dir");
        let context = context(&self.root);
        let source = self.root.join("source");
        let catalog = self.root.join("template-catalog");
        let inspected = self.execute_ok(
            &context,
            OperationId::SourceInspect,
            None,
            json!({
                "workspace_root": self.workspace,
                "repositories": [{
                    "repo_id": "fixture-repo",
                    "path": source,
                    "role": "documentation",
                    "include": []
                }]
            }),
        );
        let source_ref = inspected.result["inspection_ref"].clone();
        let resolved = self.execute_ok(
            &context,
            OperationId::TemplateResolve,
            None,
            json!({
                "workspace_root": self.workspace,
                "catalog_root": catalog,
                "template_id": "summary-template",
                "version": "0.1.0"
            }),
        );
        let validated = self.execute_ok(
            &context,
            OperationId::TemplateValidate,
            None,
            json!({
                "workspace_root": self.workspace,
                "resolution_ref": resolved.result["resolution_ref"]
            }),
        );
        let template_ref = validated.result["validation_ref"].clone();
        let mut plan_request = OperationRequest::new(
            OperationId::BuildPlan,
            "req-build.plan-e05".to_owned(),
            json!({
                "workspace_root": self.workspace,
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
        self.execute_ok(
            &context,
            OperationId::BuildPrepare,
            Some(&run_id),
            json!({"workspace_root": self.workspace}),
        );
        loop {
            let next = self.execute_ok(
                &context,
                OperationId::SummaryNext,
                Some(&run_id),
                json!({"workspace_root": self.workspace}),
            );
            let Some(job) = next.result.get("job").filter(|value| !value.is_null()) else {
                break;
            };
            let source_path = job["source_path"].as_str().expect("source path");
            self.execute_ok(
                &context,
                OperationId::SummaryAccept,
                Some(&run_id),
                json!({
                    "workspace_root": self.workspace,
                    "packet_id": job["packet_id"],
                    "source_sha256": job["source_sha256"],
                    "template_manifest_sha256": job["template_manifest_sha256"],
                    "summary_markdown": format!("Summary for {source_path}")
                }),
            );
        }
        let finalized = self.execute_ok(
            &context,
            OperationId::BuildFinalize,
            Some(&run_id),
            json!({"workspace_root": self.workspace}),
        );
        assert_eq!(finalized.status, OperationStatus::Completed);
        let bundle_path = PathBuf::from(
            finalized.result["bundle_path"]
                .as_str()
                .expect("bundle path"),
        );
        let verify = self.execute_ok(
            &context,
            OperationId::BundleVerify,
            None,
            json!({
                "bundle_path": bundle_path,
                "expected_tree_sha256": finalized.result["tree_digest"]
            }),
        );
        Built {
            bundle_path,
            verify,
        }
    }

    fn execute_ok(
        &self,
        context: &CallContext,
        operation: OperationId,
        run_id: Option<&str>,
        payload: Value,
    ) -> OperationResponse {
        let mut request = OperationRequest::new(
            operation,
            format!("req-e05-{}", operation.as_str()),
            payload,
        );
        request.run_id = run_id.map(str::to_owned);
        Dispatcher
            .execute(context, request)
            .unwrap_or_else(|error| panic!("{} failed: {error:#?}", operation.as_str()))
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
