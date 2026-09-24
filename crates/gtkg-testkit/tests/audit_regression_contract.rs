use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use gtkg_core::file_model::{sha256_file, tree_sha256};
use gtkg_core::no_db::scan_no_database;
use gtkg_core::okf::parse_okf;
use gtkg_core::{CallContext, Dispatcher, EffectPolicy, TransportKind};
use gtkg_protocol::{
    ErrorCode, OperationId, OperationRequest, OperationResponse, OperationStatus,
    PUBLIC_OPERATIONS, canonical_json_sha256,
};
use serde_json::{Value, json};
use tempfile::{TempDir, tempdir};

#[test]
fn call_context_enforces_authorized_roots_effects_locks_and_symlink_boundaries() {
    let temp = tempdir().expect("tempdir");
    let allowed = temp.path().join("allowed");
    let outside = temp.path().join("outside");
    fs::create_dir_all(&allowed).expect("allowed root");
    fs::create_dir_all(&outside).expect("outside root");

    assert!(
        CallContext::restricted(
            TransportKind::Test,
            vec![PathBuf::from("/")],
            EffectPolicy::WorkspaceWrite,
        )
        .is_err()
    );
    let home = PathBuf::from(std::env::var_os("HOME").expect("HOME"));
    assert!(
        CallContext::restricted(
            TransportKind::Test,
            vec![home],
            EffectPolicy::WorkspaceWrite,
        )
        .is_err()
    );

    let ctx = context(&allowed, EffectPolicy::WorkspaceWrite);
    let outside_error = execute_err(
        &ctx,
        OperationId::BundleVerify,
        None,
        json!({
            "bundle_path": outside,
            "expected_tree_sha256": digest('0')
        }),
    );
    assert_eq!(outside_error, ErrorCode::PathEscape);

    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&outside, allowed.join("escaped-link"))
            .expect("controlled symlink");
        let symlink_error = execute_err(
            &ctx,
            OperationId::BundleVerify,
            None,
            json!({
                "bundle_path": allowed.join("escaped-link"),
                "expected_tree_sha256": digest('0')
            }),
        );
        assert!(matches!(
            symlink_error,
            ErrorCode::PathEscape | ErrorCode::SymlinkRejected
        ));
    }

    let read_only = context(&allowed, EffectPolicy::ReadOnly);
    let effect_error = execute_err(
        &read_only,
        OperationId::SourceInspect,
        None,
        json!({"workspace_root": allowed, "repositories": []}),
    );
    assert_eq!(effect_error, ErrorCode::SideEffectDenied);

    let mut malformed =
        OperationRequest::new(OperationId::SystemDescribe, "malformed-lock", json!({}));
    malformed
        .locks
        .insert("source".to_owned(), "caller-text".to_owned());
    let error = Dispatcher
        .execute(&read_only, malformed)
        .expect_err("non-digest request lock must fail closed");
    assert_eq!(error.error.code, ErrorCode::LockMismatch);
}

#[test]
fn build_plan_consumes_only_revalidated_source_and_template_receipts() {
    let fixture = Fixture::new();
    let repo = fixture.repo("repo-a", &[('A', "README.md")]);
    let template_catalog = fixture.template_catalog();
    let workspace = fixture.root.join("workspace");
    fs::create_dir_all(&workspace).expect("workspace");
    let context = context(&fixture.root, EffectPolicy::WorkspaceWrite);

    let source_ref = inspect(
        &context,
        &workspace,
        &[("repo-a", repo.as_path(), "documentation")],
    );
    let template_ref = resolve_and_validate_template(
        &context,
        &workspace,
        &template_catalog,
        "summary-template",
        "0.1.0",
    );

    let planned = plan(
        &context,
        &workspace,
        "full",
        &source_ref,
        &template_ref,
        None,
        "0.1.0",
    );
    assert_eq!(planned.status, OperationStatus::Completed);

    let forged = execute_err(
        &context,
        OperationId::BuildPlan,
        None,
        json!({
            "workspace_root": workspace,
            "mode": "full",
            "source_lock": {"schema_version": "gtkg.source-lock/v1", "repositories": [], "entries": []},
            "template_lock": {"template": {"id": "forged", "version": "0.1.0", "manifest_sha256": digest('a')}, "slot_ids": []},
            "bundle_version": "0.1.1"
        }),
    );
    assert_eq!(forged, ErrorCode::InvalidRequest);

    fs::write(repo.join("README.md"), "dirty after inspection").expect("dirty source");
    let dirty = plan_error(
        &context,
        &fixture.root.join("dirty-workspace"),
        &source_ref,
        &template_ref,
    );
    assert!(matches!(
        dirty,
        ErrorCode::SourceDirty | ErrorCode::LockMismatch
    ));
    fs::write(repo.join("README.md"), "A\n").expect("restore exact source");

    let template_file = template_version_dir(&template_catalog).join("template.md");
    fs::write(&template_file, "tampered template").expect("tamper template");
    let template_drift = plan_error(
        &context,
        &fixture.root.join("template-drift-workspace"),
        &source_ref,
        &template_ref,
    );
    assert_eq!(template_drift, ErrorCode::LockMismatch);
}

#[test]
fn source_key_keeps_same_logical_path_distinct_across_repositories() {
    let fixture = Fixture::new();
    let repo_a = fixture.repo("repo-a", &[('A', "README.md")]);
    let repo_b = fixture.repo("repo-b", &[('B', "README.md")]);
    let template_catalog = fixture.template_catalog();
    let workspace = fixture.root.join("multi-workspace");
    fs::create_dir_all(&workspace).expect("workspace");
    let context = context(&fixture.root, EffectPolicy::WorkspaceWrite);
    let built = build(
        &context,
        &workspace,
        &[("repo-a", &repo_a, "docs"), ("repo-b", &repo_b, "docs")],
        &template_catalog,
        "full",
        None,
        "0.2.0",
    );
    assert_eq!(built.prepare["extracted_count"], 2);
    assert_eq!(built.summary_jobs, 2);

    let query = execute_ok(
        &context,
        OperationId::BundleQuery,
        None,
        json!({
            "bundle_path": built.bundle_path,
            "expected_tree_sha256": built.tree_digest,
            "query": "README.md"
        }),
    );
    let keys: BTreeSet<_> = query.result["matches"]
        .as_array()
        .expect("query matches")
        .iter()
        .map(|value| {
            (
                value["source_key"]["repo_id"]
                    .as_str()
                    .expect("repo id")
                    .to_owned(),
                value["source_key"]["logical_path"]
                    .as_str()
                    .expect("logical path")
                    .to_owned(),
            )
        })
        .collect();
    assert_eq!(
        keys,
        BTreeSet::from([
            ("repo-a".to_owned(), "README.md".to_owned()),
            ("repo-b".to_owned(), "README.md".to_owned()),
        ])
    );
}

#[test]
fn bundle_verify_checks_every_canonical_okf_resource_and_manifest_digest_closure() {
    let fixture = Fixture::new();
    let repo = fixture.repo("repo-a", &[('A', "README.md")]);
    let template_catalog = fixture.template_catalog();
    let workspace = fixture.root.join("bundle-workspace");
    fs::create_dir_all(&workspace).expect("workspace");
    let context = context(&fixture.root, EffectPolicy::WorkspaceWrite);
    let built = build(
        &context,
        &workspace,
        &[("repo-a", &repo, "docs")],
        &template_catalog,
        "full",
        None,
        "0.3.0",
    );

    for path in markdown_files(&built.bundle_path) {
        let source = fs::read_to_string(&path).expect("canonical Markdown");
        let document = parse_okf(&source).expect("every canonical Markdown parses as OKF v0.2");
        if path.file_name().and_then(|name| name.to_str()) == Some("index.md") {
            // SPEC §8/§12: index files carry markdown links and (at most) an
            // okf_version frontmatter; they have no resource self-reference.
            continue;
        }
        let resource = document
            .frontmatter
            .resource
            .as_deref()
            .expect("concept OKF carries a resource self-reference");
        let resolved = path.parent().expect("document parent").join(resource);
        assert_eq!(
            fs::canonicalize(resolved).expect("resource resolves"),
            fs::canonicalize(&path).expect("document canonical path")
        );
    }

    let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf();
    for relative in [
        "deliverables/goal-team-knowledge-graph/versions/V0.1/PRD.md",
        "deliverables/goal-team-knowledge-graph/versions/V0.1/ARCHITECTURE.md",
        "templates/design-deliverables/versions/V0.1/architecture-template.md",
        "templates/design-deliverables/versions/V0.1/prd-template.md",
    ] {
        parse_okf(&fs::read_to_string(workspace_root.join(relative)).expect("conformance fixture"))
            .unwrap_or_else(|error| panic!("{relative} must conform: {error}"));
    }

    let broken_okf = fixture.root.join("broken-okf");
    copy_tree(&built.bundle_path, &broken_okf);
    let agent = broken_okf.join("knowledge/architecture/agent.md");
    let invalid = fs::read_to_string(&agent)
        .expect("agent OKF")
        .replace("okf_version: '0.2'", "okf_version: '0.1'")
        .replace("okf_version: 0.2", "okf_version: 0.1");
    fs::write(&agent, invalid).expect("break architecture OKF");
    rewrite_checksum(&broken_okf, "knowledge/architecture/agent.md");
    let broken_okf_tree = tree_sha256(&broken_okf).expect("external broken OKF tree digest");
    assert_eq!(
        execute_err(
            &context,
            OperationId::BundleVerify,
            None,
            json!({
                "bundle_path": broken_okf,
                "expected_tree_sha256": broken_okf_tree
            }),
        ),
        ErrorCode::BundleInvalid
    );

    let broken_manifest = fixture.root.join("broken-manifest");
    copy_tree(&built.bundle_path, &broken_manifest);
    let manifest_path = broken_manifest.join("artifact-manifest.json");
    let mut manifest: Value = serde_json::from_slice(&fs::read(&manifest_path).expect("manifest"))
        .expect("manifest JSON");
    manifest["sources"].as_array_mut().expect("sources").clear();
    fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest).expect("manifest bytes"),
    )
    .expect("corrupt manifest closure");
    rewrite_checksum(&broken_manifest, "artifact-manifest.json");
    let broken_manifest_tree =
        tree_sha256(&broken_manifest).expect("external broken manifest tree digest");
    assert_eq!(
        execute_err(
            &context,
            OperationId::BundleVerify,
            None,
            json!({
                "bundle_path": broken_manifest,
                "expected_tree_sha256": broken_manifest_tree
            }),
        ),
        ErrorCode::BundleInvalid
    );
}

#[test]
fn no_database_gate_covers_dependency_file_magic_source_and_daemon_families() {
    let dirty = tempdir().expect("dirty fixture");
    fs::write(
        dirty.path().join("Cargo.lock"),
        [
            "postgres",
            "mysql",
            "mongodb",
            "redis",
            "duckdb",
            "libsql",
            "neo4rs",
            "qdrant-client",
            "surrealdb",
            "lancedb",
        ]
        .into_iter()
        .map(|name| format!("[[package]]\nname = \"{name}\"\nversion = \"0.0.0\"\n"))
        .collect::<String>(),
    )
    .expect("dependency fixture");
    fs::write(dirty.path().join("state.duckdb"), b"DUCKDB\0fixture").expect("file fixture");
    fs::write(
        dirty.path().join("daemon.rs"),
        "redis::Client::open(\"redis://127.0.0.1\"); std::process::Command::new(\"mongod\");",
    )
    .expect("source fixture");
    let findings = scan_no_database(dirty.path()).expect("fixture scan");
    let rules: BTreeSet<_> = findings
        .iter()
        .map(|finding| finding.rule_id.as_str())
        .collect();
    assert!(rules.contains("forbidden_dependency"));
    assert!(rules.contains("forbidden_extension") || rules.contains("forbidden_magic"));
    assert!(rules.contains("forbidden_source_api"));
    assert!(rules.contains("forbidden_daemon"));

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let production_root = manifest_dir
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let production_findings = scan_no_database(production_root).expect("production scan");
    assert!(
        production_findings.is_empty(),
        "fixture findings must not count as production findings: {production_findings:#?}"
    );
}

#[test]
fn incremental_reuses_unchanged_and_only_extracts_and_summarizes_impact_exact_set() {
    let fixture = Fixture::new();
    let repo = fixture.repo_files(
        "repo-a",
        &[
            ("stable.md", "stable\n"),
            ("changed.md", "before\n"),
            ("deleted.md", "delete me\n"),
        ],
    );
    let template_catalog = fixture.template_catalog();
    let context = context(&fixture.root, EffectPolicy::WorkspaceWrite);
    let baseline = build(
        &context,
        &fixture.root.join("baseline-workspace"),
        &[("repo-a", &repo, "docs")],
        &template_catalog,
        "full",
        None,
        "1.0.0",
    );

    fs::write(repo.join("changed.md"), "after\n").expect("change source");
    fs::remove_file(repo.join("deleted.md")).expect("delete source");
    fs::write(repo.join("added.md"), "added\n").expect("add source");
    git(&repo, &["add", "-A"]);
    git(&repo, &["commit", "-m", "incremental delta"]);

    let incremental = build(
        &context,
        &fixture.root.join("incremental-workspace"),
        &[("repo-a", &repo, "docs")],
        &template_catalog,
        "incremental",
        Some(Baseline {
            bundle_path: &baseline.bundle_path,
            tree_digest: &baseline.tree_digest,
        }),
        "2.0.0",
    );
    assert_eq!(incremental.prepare["extracted_count"], 2);
    assert_eq!(incremental.prepare["reused_count"], 1);
    assert_eq!(incremental.prepare["summary_required_count"], 2);
    assert_eq!(incremental.summary_jobs, 2);
    assert_source_key(&incremental.impact["added"], "repo-a", "added.md");
    assert_source_key(&incremental.impact["changed"], "repo-a", "changed.md");
    assert_source_key(&incremental.impact["deleted"], "repo-a", "deleted.md");
    assert_source_key(&incremental.impact["unchanged"], "repo-a", "stable.md");

    let fresh = build(
        &context,
        &fixture.root.join("fresh-workspace"),
        &[("repo-a", &repo, "docs")],
        &template_catalog,
        "full",
        None,
        "2.0.0",
    );
    assert_eq!(fresh.prepare["extracted_count"], 3);
    assert_eq!(fresh.prepare["reused_count"], 0);
    assert_eq!(fresh.summary_jobs, 3);
    assert_eq!(incremental.semantic_digest, fresh.semantic_digest);
}

#[test]
fn source_inspect_uses_git_objects_and_rejects_dirty_untracked_submodule_and_head_drift() {
    let fixture = Fixture::new();
    let repo = fixture.repo("repo-a", &[('A', "README.md")]);
    let workspace = fixture.root.join("inspect-workspace");
    fs::create_dir_all(&workspace).expect("workspace");
    let context = context(&fixture.root, EffectPolicy::WorkspaceWrite);
    let inspected = inspect_response(
        &context,
        &workspace,
        &[("repo-a", repo.as_path(), "documentation")],
    );
    let object = git_bytes(&repo, &["show", "HEAD:README.md"]);
    let object_path = fixture.root.join("object.bin");
    fs::write(&object_path, object).expect("object fixture");
    assert_eq!(
        inspected.result["source_lock"]["entries"][0]["content_sha256"],
        sha256_file(&object_path).expect("object digest")
    );

    fs::write(repo.join("untracked.md"), "untracked").expect("untracked");
    assert_eq!(
        execute_err(
            &context,
            OperationId::SourceInspect,
            None,
            inspect_payload(&workspace, &[("repo-a", repo.as_path(), "docs")]),
        ),
        ErrorCode::SourceDirty
    );
    fs::remove_file(repo.join("untracked.md")).expect("remove untracked");

    let child = fixture.repo("child", &[('C', "child.md")]);
    let parent = fixture.repo("parent", &[('P', "parent.md")]);
    git(
        &parent,
        &[
            "-c",
            "protocol.file.allow=always",
            "submodule",
            "add",
            child.to_str().expect("child path"),
            "modules/child",
        ],
    );
    git(&parent, &["commit", "-am", "add submodule"]);
    let with_submodule = inspect_response(
        &context,
        &fixture.root.join("submodule-workspace"),
        &[("parent", parent.as_path(), "docs")],
    );
    assert_eq!(
        with_submodule.result["source_lock"]["repositories"][0]["submodules"]
            .as_array()
            .expect("submodules")
            .len(),
        1
    );
    fs::write(parent.join("modules/child/child.md"), "dirty child").expect("dirty child");
    assert_eq!(
        execute_err(
            &context,
            OperationId::SourceInspect,
            None,
            inspect_payload(
                &fixture.root.join("dirty-submodule-workspace"),
                &[("parent", parent.as_path(), "docs")],
            ),
        ),
        ErrorCode::SourceDirty
    );
}

#[test]
fn system_and_mcp_discovery_disclose_truthful_operation_availability() {
    let temp = tempdir().expect("tempdir");
    let context = context(temp.path(), EffectPolicy::ReadOnly);
    let response = execute_ok(&context, OperationId::SystemDescribe, None, json!({}));
    let operations = response.result["operations"]
        .as_array()
        .expect("system operations");
    assert_eq!(operations.len(), 34);
    assert_eq!(PUBLIC_OPERATIONS.len(), 34);
    assert_eq!(availability(operations, "system.describe"), "implemented");
    assert_eq!(availability(operations, "config.validate"), "implemented");
    assert_eq!(availability(operations, "a2ui.generate"), "implemented");

    let tools = gtkg_app::mcp_tools();
    assert_eq!(tools.len(), 34);
    for tool in tools {
        let operation =
            OperationId::from_mcp_tool_name(tool["name"].as_str().expect("MCP tool name"))
                .expect("registered MCP operation");
        let expected = availability(operations, operation.as_str());
        assert_eq!(tool["x-gtkg-availability"], expected);
    }
}

struct Fixture {
    _temp: TempDir,
    root: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let temp = tempdir().expect("fixture root");
        let root = temp.path().to_path_buf();
        Self { _temp: temp, root }
    }

    fn repo(&self, name: &str, files: &[(char, &str)]) -> PathBuf {
        let owned = files
            .iter()
            .map(|(content, path)| (*path, format!("{content}\n")))
            .collect::<Vec<_>>();
        let borrowed = owned
            .iter()
            .map(|(path, content)| (*path, content.as_str()))
            .collect::<Vec<_>>();
        self.repo_files(name, &borrowed)
    }

    fn repo_files(&self, name: &str, files: &[(&str, &str)]) -> PathBuf {
        let path = self.root.join(name);
        fs::create_dir_all(&path).expect("repo root");
        git(&path, &["init"]);
        git(&path, &["config", "user.name", "GTKG Fixture"]);
        git(&path, &["config", "user.email", "fixture@invalid.example"]);
        for (relative, content) in files {
            let target = path.join(relative);
            fs::create_dir_all(target.parent().expect("source parent")).expect("source parent");
            fs::write(target, content).expect("source fixture");
        }
        git(&path, &["add", "-A"]);
        git(&path, &["commit", "-m", "fixture"]);
        path
    }

    fn template_catalog(&self) -> PathBuf {
        let catalog = self.root.join("template-catalog");
        let staging = catalog.join("summary-template/versions/staging");
        fs::create_dir_all(&staging).expect("template staging");
        let template_path = staging.join("template.md");
        fs::write(
            &template_path,
            "---\ntype: template\ntitle: Summary\ndescription: Summary fixture\nresource: ./template.md\ntags: [fixture]\ngenerated: false\nverified: false\nstatus: validated\nsources: []\nokf_version: '0.2'\ngtkg:\n  schema: gtkg.template/v1\n---\n\n# Summary\n",
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
            serde_json::to_vec_pretty(&manifest).expect("manifest bytes"),
        )
        .expect("template manifest");
        let digest = canonical_json_sha256(&manifest).expect("manifest digest");
        let version = staging
            .parent()
            .expect("versions root")
            .join(format!("v0.1.0--{}", &digest[7..19]));
        fs::rename(&staging, version).expect("publish fixture template");
        catalog
    }
}

struct Built {
    bundle_path: PathBuf,
    semantic_digest: String,
    tree_digest: String,
    prepare: Value,
    impact: Value,
    summary_jobs: usize,
}

#[derive(Clone, Copy)]
struct Baseline<'a> {
    bundle_path: &'a Path,
    tree_digest: &'a str,
}

fn build(
    context: &CallContext,
    workspace: &Path,
    repositories: &[(&str, &PathBuf, &str)],
    catalog: &Path,
    mode: &str,
    baseline: Option<Baseline<'_>>,
    version: &str,
) -> Built {
    fs::create_dir_all(workspace).expect("build workspace");
    let refs = repositories
        .iter()
        .map(|(id, path, role)| (*id, path.as_path(), *role))
        .collect::<Vec<_>>();
    let source_ref = inspect(context, workspace, &refs);
    let template_ref =
        resolve_and_validate_template(context, workspace, catalog, "summary-template", "0.1.0");
    let planned = plan(
        context,
        workspace,
        mode,
        &source_ref,
        &template_ref,
        baseline,
        version,
    );
    let run_id = planned.run_id.clone().expect("run id");
    let prepare = execute_ok(
        context,
        OperationId::BuildPrepare,
        Some(&run_id),
        json!({"workspace_root": workspace}),
    );
    let mut jobs = 0;
    loop {
        let next = execute_ok(
            context,
            OperationId::SummaryNext,
            Some(&run_id),
            json!({"workspace_root": workspace}),
        );
        let Some(job) = next.result.get("job").filter(|value| !value.is_null()) else {
            break;
        };
        jobs += 1;
        execute_ok(
            context,
            OperationId::SummaryAccept,
            Some(&run_id),
            json!({
                "workspace_root": workspace,
                "packet_id": job["packet_id"],
                "source_sha256": job["source_sha256"],
                "template_manifest_sha256": job["template_manifest_sha256"],
                "summary_markdown": format!(
                    "repo={};path={}\n\n{}",
                    job["repo_id"].as_str().expect("repo id"),
                    job["source_path"].as_str().expect("source path"),
                    job["analysis_text"].as_str().expect("analysis text")
                )
            }),
        );
    }
    let finalized = execute_ok(
        context,
        OperationId::BuildFinalize,
        Some(&run_id),
        json!({"workspace_root": workspace}),
    );
    Built {
        bundle_path: PathBuf::from(
            finalized.result["bundle_path"]
                .as_str()
                .expect("bundle path"),
        ),
        semantic_digest: finalized.result["semantic_digest"]
            .as_str()
            .expect("semantic digest")
            .to_owned(),
        tree_digest: finalized.result["tree_digest"]
            .as_str()
            .expect("tree digest")
            .to_owned(),
        prepare: prepare.result,
        impact: planned.result["impact"].clone(),
        summary_jobs: jobs,
    }
}

fn inspect(context: &CallContext, workspace: &Path, repositories: &[(&str, &Path, &str)]) -> Value {
    inspect_response(context, workspace, repositories).result["inspection_ref"].clone()
}

fn inspect_response(
    context: &CallContext,
    workspace: &Path,
    repositories: &[(&str, &Path, &str)],
) -> OperationResponse {
    execute_ok(
        context,
        OperationId::SourceInspect,
        None,
        inspect_payload(workspace, repositories),
    )
}

fn inspect_payload(workspace: &Path, repositories: &[(&str, &Path, &str)]) -> Value {
    json!({
        "workspace_root": workspace,
        "repositories": repositories.iter().map(|(id, path, role)| json!({
            "repo_id": id,
            "path": path,
            "role": role,
            "include": []
        })).collect::<Vec<_>>()
    })
}

fn resolve_and_validate_template(
    context: &CallContext,
    workspace: &Path,
    catalog: &Path,
    template_id: &str,
    version: &str,
) -> Value {
    let resolved = execute_ok(
        context,
        OperationId::TemplateResolve,
        None,
        json!({
            "workspace_root": workspace,
            "catalog_root": catalog,
            "template_id": template_id,
            "version": version
        }),
    );
    let validated = execute_ok(
        context,
        OperationId::TemplateValidate,
        None,
        json!({
            "workspace_root": workspace,
            "resolution_ref": resolved.result["resolution_ref"]
        }),
    );
    validated.result["validation_ref"].clone()
}

fn plan(
    context: &CallContext,
    workspace: &Path,
    mode: &str,
    source_ref: &Value,
    template_ref: &Value,
    baseline: Option<Baseline<'_>>,
    version: &str,
) -> OperationResponse {
    let mut request = OperationRequest::new(
        OperationId::BuildPlan,
        format!("plan-{version}"),
        json!({
            "workspace_root": workspace,
            "mode": mode,
            "source_inspection_ref": source_ref,
            "template_validation_ref": template_ref,
            "baseline_bundle": baseline.map(|value| value.bundle_path),
            "baseline_tree_sha256": baseline.map(|value| value.tree_digest),
            "bundle_version": version
        }),
    );
    request.locks = BTreeMap::from([
        (
            "source_inspection".to_owned(),
            source_ref["sha256"]
                .as_str()
                .expect("source ref digest")
                .to_owned(),
        ),
        (
            "template_validation".to_owned(),
            template_ref["sha256"]
                .as_str()
                .expect("template ref digest")
                .to_owned(),
        ),
    ]);
    Dispatcher
        .execute(context, request)
        .unwrap_or_else(|error| panic!("build.plan failed: {error:#?}"))
}

fn plan_error(
    context: &CallContext,
    workspace: &Path,
    source_ref: &Value,
    template_ref: &Value,
) -> ErrorCode {
    fs::create_dir_all(workspace).expect("error workspace");
    let mut request = OperationRequest::new(
        OperationId::BuildPlan,
        "expected-plan-error",
        json!({
            "workspace_root": workspace,
            "mode": "full",
            "source_inspection_ref": source_ref,
            "template_validation_ref": template_ref,
            "baseline_bundle": null,
            "bundle_version": "9.9.9"
        }),
    );
    request.locks = BTreeMap::from([
        (
            "source_inspection".to_owned(),
            source_ref["sha256"]
                .as_str()
                .expect("source ref digest")
                .to_owned(),
        ),
        (
            "template_validation".to_owned(),
            template_ref["sha256"]
                .as_str()
                .expect("template ref digest")
                .to_owned(),
        ),
    ]);
    Dispatcher
        .execute(context, request)
        .expect_err("build.plan must fail")
        .error
        .code
}

fn context(root: &Path, policy: EffectPolicy) -> CallContext {
    CallContext::restricted(TransportKind::Test, vec![root.to_path_buf()], policy)
        .expect("restricted context")
}

fn execute_ok(
    context: &CallContext,
    operation: OperationId,
    run_id: Option<&str>,
    payload: Value,
) -> OperationResponse {
    let mut request =
        OperationRequest::new(operation, format!("req-{}", operation.as_str()), payload);
    request.run_id = run_id.map(str::to_owned);
    Dispatcher
        .execute(context, request)
        .unwrap_or_else(|error| panic!("{} failed: {error:#?}", operation.as_str()))
}

fn execute_err(
    context: &CallContext,
    operation: OperationId,
    run_id: Option<&str>,
    payload: Value,
) -> ErrorCode {
    let mut request = OperationRequest::new(
        operation,
        format!("req-error-{}", operation.as_str()),
        payload,
    );
    request.run_id = run_id.map(str::to_owned);
    Dispatcher
        .execute(context, request)
        .expect_err("operation must fail")
        .error
        .code
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

fn git_bytes(root: &Path, arguments: &[&str]) -> Vec<u8> {
    let output = Command::new("/usr/bin/git")
        .arg("-C")
        .arg(root)
        .args(arguments)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .output()
        .expect("run fixture git");
    assert!(output.status.success(), "git command failed");
    output.stdout
}

fn template_version_dir(catalog: &Path) -> PathBuf {
    fs::read_dir(catalog.join("summary-template/versions"))
        .expect("template versions")
        .next()
        .expect("template version")
        .expect("template entry")
        .path()
}

fn markdown_files(root: &Path) -> Vec<PathBuf> {
    fn visit(path: &Path, files: &mut Vec<PathBuf>) {
        for entry in fs::read_dir(path).expect("read canonical tree") {
            let entry = entry.expect("canonical entry");
            let path = entry.path();
            if path.is_dir() {
                visit(&path, files);
            } else if path.extension().and_then(|value| value.to_str()) == Some("md") {
                files.push(path);
            }
        }
    }
    let mut files = Vec::new();
    visit(root, &mut files);
    files.sort();
    files
}

fn copy_tree(source: &Path, target: &Path) {
    fs::create_dir_all(target).expect("copy root");
    for entry in fs::read_dir(source).expect("copy source") {
        let entry = entry.expect("copy entry");
        let destination = target.join(entry.file_name());
        if entry.path().is_dir() {
            copy_tree(&entry.path(), &destination);
        } else {
            fs::copy(entry.path(), destination).expect("copy file");
        }
    }
}

fn rewrite_checksum(root: &Path, relative: &str) {
    let checksum_path = root.join("checksums.sha256");
    let digest = sha256_file(&root.join(relative)).expect("replacement digest");
    let mut found = false;
    let rewritten = fs::read_to_string(&checksum_path)
        .expect("checksums")
        .lines()
        .map(|line| {
            let Some((_, path)) = line.split_once("  ") else {
                return line.to_owned();
            };
            if path == relative {
                found = true;
                format!("{}  {relative}", &digest[7..])
            } else {
                line.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    assert!(found, "checksum entry exists");
    fs::write(checksum_path, format!("{rewritten}\n")).expect("rewrite checksum");
}

fn assert_source_key(values: &Value, repo_id: &str, logical_path: &str) {
    assert!(
        values
            .as_array()
            .expect("source key array")
            .iter()
            .any(|value| { value["repo_id"] == repo_id && value["logical_path"] == logical_path }),
        "missing SourceKey {repo_id}:{logical_path} in {values}"
    );
}

fn availability<'a>(operations: &'a [Value], id: &str) -> &'a str {
    operations
        .iter()
        .find(|value| value["id"] == id)
        .and_then(|value| value["availability"].as_str())
        .unwrap_or_else(|| panic!("missing availability for {id}"))
}

fn digest(character: char) -> String {
    format!("sha256:{}", character.to_string().repeat(64))
}
