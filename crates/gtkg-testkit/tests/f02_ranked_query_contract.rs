//! F02 frozen contract: bundle.query ranked retrieval with Explain output.
//!
//! Oracles:
//! (a) answerable gold queries over a real multi-topic bundle return ranked
//!     matches with scores in descending order; Recall@5 >= 0.85 and
//!     MRR >= 0.75 over the gold set.
//! (b) unanswerable queries return an explicit `no_answer` status with a
//!     reason and an empty match list (no padding hits).
//! (c) ambiguous queries whose top documents tie within the conflict margin
//!     with differing content return an explicit `conflict` status carrying
//!     the candidate set; no-answer/conflict accuracy >= 90%.
//! (d) snippets are match-centered: they contain the hit term even when the
//!     hit sits beyond the first 240 characters of the document.
//! (e) every match carries an evidence pack whose digests re-verify against
//!     the bundle files and the artifact manifest.
//! (f) identical queries over an identical bundle produce byte-identical
//!     results.

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

const AUTHENTICATION_DOC: &str =
    "# 用户认证\n\nJWT token 登录流程：会话管理、密码哈希与多因素认证。\n";
const CACHING_DOC: &str = "# 缓存策略\n\ncache eviction 与 TTL 过期策略。\n\nLRU 淘汰策略适用于热点数据。\n\n缓存命中率监控与告警。\n\n缓存预热在发布窗口执行。\n\n热点数据穿透防护使用布隆过滤器 bloomfilter。\n";
const DATABASE_DOC: &str = "# 数据库迁移\n\ndatabase schema migration 与回滚脚本。\n";
const LOGGING_DOC: &str = "# 日志采集\n\nstructured logging 与 trace 采样率配置。\n";
const PAYMENT_DOC: &str = "# 支付退款\n\npayment refund 与对账差异处理。\n";
const DEPLOYMENT_DOC: &str = "# 部署回滚\n\nkubernetes deployment 滚动升级策略。\n";
const CONVENTIONS_ALPHA_DOC: &str = "# 团队规范\n\n代码评审规范：评审必须在两个工作日内完成。\n";
const CONVENTIONS_BETA_DOC: &str = "# 团队规范\n\n代码评审规范：评审必须在三个工作日内完成。\n";
const LEDGER_SOURCE: &str = r#"pub struct Ledger {
    pub entries: u64,
}

impl Ledger {
    pub fn is_empty(&self) -> bool {
        self.entries == 0
    }
}

pub fn reconcile(ledger: &Ledger) -> bool {
    ledger.is_empty()
}
"#;

/// (query, relevant source logical paths)
const ANSWERABLE_GOLD: &[(&str, &[&str])] = &[
    ("用户认证", &["docs/authentication.md"]),
    ("JWT 登录", &["docs/authentication.md"]),
    ("缓存 TTL", &["docs/caching.md"]),
    ("布隆过滤器", &["docs/caching.md"]),
    ("schema migration", &["docs/database.md"]),
    ("数据库 回滚", &["docs/database.md", "docs/deployment.md"]),
    ("structured logging", &["docs/logging.md"]),
    ("refund 对账", &["docs/payment.md", "src/ledger.rs"]),
    ("kubernetes 部署", &["docs/deployment.md"]),
    ("trace 采样", &["docs/logging.md"]),
    ("reconcile 对账", &["src/ledger.rs"]),
    ("密码哈希", &["docs/authentication.md"]),
];

const UNANSWERABLE_GOLD: &[&str] = &[
    "量子计算",
    "blockchain consensus",
    "图像识别 模型训练",
    "kafka 消息队列",
    "zookeeper 选主",
];

const AMBIGUOUS_GOLD: &[&str] = &["代码评审规范", "评审 工作日", "团队规范 评审"];

#[test]
fn ranked_results_meet_recall_mrr_and_carry_centered_snippets_and_verifiable_evidence() {
    let temp = tempdir().expect("tempdir");
    let fixture = PreparedRun::start(temp.path());
    let built = fixture.build();
    let manifest = artifact_manifest(&built.bundle_path);

    let mut recall_sum = 0.0_f64;
    let mut mrr_sum = 0.0_f64;
    for (query, relevant) in ANSWERABLE_GOLD {
        let result = fixture.query(&built, query);
        assert_eq!(
            result["status"].as_str(),
            Some("answered"),
            "answerable query {query:?} must be answered: {result:#}"
        );
        assert_eq!(result["retrieval_source"], "indexes/search.ndjson");
        assert_eq!(
            result["progressive_load"]["knowledge_documents_loaded_for_ranking"],
            0
        );
        let matches = result["matches"].as_array().expect("matches array");
        assert!(
            !matches.is_empty(),
            "answerable query {query:?} must return ranked matches"
        );
        let scores: Vec<u64> = matches
            .iter()
            .map(|entry| entry["score"].as_u64().expect("integer score"))
            .collect();
        assert!(
            scores.windows(2).all(|pair| pair[0] >= pair[1]),
            "matches for {query:?} must be sorted by descending score: {scores:?}"
        );
        let ranked_paths: Vec<&str> = matches
            .iter()
            .map(|entry| {
                entry["source_key"]["logical_path"]
                    .as_str()
                    .expect("logical path")
            })
            .collect();
        let top5: Vec<&&str> = relevant
            .iter()
            .filter(|path| ranked_paths.iter().take(5).any(|ranked| ranked == *path))
            .collect();
        recall_sum += top5.len() as f64 / relevant.len() as f64;
        let first_rank = ranked_paths
            .iter()
            .position(|ranked| relevant.contains(ranked))
            .map(|index| index + 1);
        mrr_sum += first_rank.map_or(0.0, |rank| 1.0 / rank as f64);

        for entry in matches {
            verify_evidence_pack(&built.bundle_path, &manifest, entry);
            let snippet = entry["snippet"].as_str().expect("snippet");
            let matched_terms: Vec<&str> = entry["matched_terms"]
                .as_array()
                .expect("matched terms")
                .iter()
                .filter_map(Value::as_str)
                .collect();
            assert!(
                !matched_terms.is_empty(),
                "every ranked match must disclose its matched terms"
            );
            let snippet_lower = snippet.to_lowercase();
            assert!(
                matched_terms
                    .iter()
                    .any(|term| snippet_lower.contains(term)),
                "snippet for {query:?} must contain at least one matched term: {snippet:?}"
            );
        }
    }
    let recall_at_5 = recall_sum / ANSWERABLE_GOLD.len() as f64;
    let mrr = mrr_sum / ANSWERABLE_GOLD.len() as f64;
    assert!(
        recall_at_5 >= 0.85,
        "Recall@5 {recall_at_5:.3} below 0.85 over {} gold queries",
        ANSWERABLE_GOLD.len()
    );
    assert!(mrr >= 0.75, "MRR {mrr:.3} below 0.75");

    // (d) match-centered snippet: 布隆过滤器 sits beyond the first 240
    // characters of the caching knowledge document.
    let result = fixture.query(&built, "布隆过滤器");
    let top = &result["matches"].as_array().expect("matches")[0];
    assert_eq!(
        top["source_key"]["logical_path"].as_str(),
        Some("docs/caching.md")
    );
    let snippet = top["snippet"].as_str().expect("snippet");
    assert!(
        snippet.contains("布隆过滤器"),
        "snippet must be centered on the hit: {snippet:?}"
    );
    let snippet_start = top["evidence"]["snippet_char_start"]
        .as_u64()
        .expect("snippet start");
    assert!(
        snippet_start > 0,
        "hit sits beyond the document head, so the window must not start at 0"
    );
    let knowledge_text = fs::read_to_string(
        built
            .bundle_path
            .join(top["knowledge_path"].as_str().expect("knowledge path")),
    )
    .expect("knowledge text");
    let snippet_end = top["evidence"]["snippet_char_end"]
        .as_u64()
        .expect("snippet end") as usize;
    let window: String = knowledge_text
        .chars()
        .skip(snippet_start as usize)
        .take(snippet_end - snippet_start as usize)
        .collect();
    assert!(
        window.contains("布隆过滤器"),
        "declared window must cover the hit term"
    );
    assert!(
        snippet.contains(&window),
        "snippet must embed the declared evidence window"
    );

    // (f) determinism: identical query twice, byte-identical result.
    let first = fixture.query(&built, "缓存 TTL");
    let second = fixture.query(&built, "缓存 TTL");
    assert_eq!(
        serde_json::to_string(&first).expect("serialize first"),
        serde_json::to_string(&second).expect("serialize second"),
        "identical queries must produce byte-identical results"
    );
    assert_eq!(
        canonical_json_sha256(&first).expect("digest first"),
        canonical_json_sha256(&second).expect("digest second"),
    );
}

#[test]
fn no_answer_and_conflict_are_explicit_with_at_least_ninety_percent_accuracy() {
    let temp = tempdir().expect("tempdir");
    let fixture = PreparedRun::start(temp.path());
    let built = fixture.build();

    let total = UNANSWERABLE_GOLD.len() + AMBIGUOUS_GOLD.len();
    let mut correct = 0_usize;
    for query in UNANSWERABLE_GOLD {
        let result = fixture.query(&built, query);
        if result["status"].as_str() == Some("no_answer")
            && result["matches"]
                .as_array()
                .expect("matches array")
                .is_empty()
            && result["reason"]
                .as_str()
                .is_some_and(|reason| !reason.is_empty())
        {
            correct += 1;
        } else {
            panic!("unanswerable query {query:?} must be an explicit no_answer: {result:#}");
        }
    }
    for query in AMBIGUOUS_GOLD {
        let result = fixture.query(&built, query);
        if result["status"].as_str() != Some("conflict") {
            panic!("ambiguous query {query:?} must be an explicit conflict: {result:#}");
        }
        let candidates = result["candidates"]
            .as_array()
            .expect("conflict candidates");
        let candidate_paths: Vec<&str> = candidates
            .iter()
            .filter_map(|entry| entry["knowledge_path"].as_str())
            .collect();
        let candidate_sources: Vec<&str> = candidates
            .iter()
            .filter_map(|entry| entry["source_key"]["logical_path"].as_str())
            .collect();
        let matches = result["matches"].as_array().expect("matches array");
        let match_paths: Vec<&str> = matches
            .iter()
            .filter_map(|entry| entry["knowledge_path"].as_str())
            .collect();
        if candidates.len() >= 2
            && candidate_paths
                .iter()
                .all(|path| match_paths.contains(path))
            && candidate_sources
                .iter()
                .any(|path| path.contains("conventions-alpha"))
            && candidate_sources
                .iter()
                .any(|path| path.contains("conventions-beta"))
            && result["reason"].as_str().is_some_and(|r| !r.is_empty())
        {
            correct += 1;
        } else {
            panic!(
                "conflict for {query:?} must carry both conventions documents as candidates: {result:#}"
            );
        }
    }
    let accuracy = correct as f64 / total as f64;
    assert!(
        accuracy >= 0.9,
        "no-answer/conflict accuracy {accuracy:.3} below 0.90 over {total} queries"
    );
}

fn artifact_manifest(bundle_path: &Path) -> Value {
    serde_json::from_str(
        &fs::read_to_string(bundle_path.join("artifact-manifest.json")).expect("manifest"),
    )
    .expect("manifest json")
}

fn verify_evidence_pack(bundle_path: &Path, manifest: &Value, entry: &Value) {
    let evidence = &entry["evidence"];
    let knowledge_path = evidence["knowledge_path"]
        .as_str()
        .expect("evidence knowledge path");
    assert_eq!(
        entry["knowledge_path"].as_str(),
        Some(knowledge_path),
        "evidence pack must bind the match knowledge path"
    );
    let knowledge_sha256 = evidence["knowledge_sha256"]
        .as_str()
        .expect("evidence knowledge digest");
    let observed = sha256_file(&bundle_path.join(knowledge_path)).expect("recompute digest");
    assert_eq!(
        knowledge_sha256, observed,
        "evidence knowledge digest must re-verify against the bundle file"
    );
    let manifest_entry = manifest["knowledge"]
        .as_array()
        .expect("manifest knowledge")
        .iter()
        .find(|item| item["path"].as_str() == Some(knowledge_path))
        .expect("manifest knowledge entry");
    assert_eq!(
        manifest_entry["sha256"].as_str(),
        Some(knowledge_sha256),
        "evidence digest must match the artifact manifest"
    );
    let source_key = format!(
        "{}:{}",
        entry["source_key"]["repo_id"].as_str().expect("repo id"),
        entry["source_key"]["logical_path"]
            .as_str()
            .expect("logical path")
    );
    let manifest_source = manifest["sources"]
        .as_array()
        .expect("manifest sources")
        .iter()
        .find(|item| {
            format!(
                "{}:{}",
                item["source_key"]["repo_id"].as_str().expect("repo id"),
                item["source_key"]["logical_path"]
                    .as_str()
                    .expect("logical path")
            ) == source_key
        })
        .expect("manifest source entry");
    assert_eq!(
        evidence["source_sha256"].as_str(),
        manifest_source["source_sha256"].as_str(),
        "evidence source digest must match the artifact manifest"
    );
}

struct Built {
    bundle_path: PathBuf,
    tree_digest: String,
}

struct PreparedRun {
    root: PathBuf,
    workspace: PathBuf,
}

impl PreparedRun {
    fn start(root: &Path) -> Self {
        let source = root.join("source");
        fs::create_dir_all(source.join("docs")).expect("docs dir");
        fs::create_dir_all(source.join("src")).expect("src dir");
        fs::write(source.join("docs/authentication.md"), AUTHENTICATION_DOC).expect("auth doc");
        fs::write(source.join("docs/caching.md"), CACHING_DOC).expect("caching doc");
        fs::write(source.join("docs/database.md"), DATABASE_DOC).expect("database doc");
        fs::write(source.join("docs/logging.md"), LOGGING_DOC).expect("logging doc");
        fs::write(source.join("docs/payment.md"), PAYMENT_DOC).expect("payment doc");
        fs::write(source.join("docs/deployment.md"), DEPLOYMENT_DOC).expect("deployment doc");
        fs::write(
            source.join("docs/conventions-alpha.md"),
            CONVENTIONS_ALPHA_DOC,
        )
        .expect("alpha doc");
        fs::write(
            source.join("docs/conventions-beta.md"),
            CONVENTIONS_BETA_DOC,
        )
        .expect("beta doc");
        fs::write(source.join("src/ledger.rs"), LEDGER_SOURCE).expect("ledger source");
        prepare_git_repository(&source);
        ensure_template_catalog(root);
        Self {
            root: root.to_path_buf(),
            workspace: root.join("workspace"),
        }
    }

    fn build(&self) -> Built {
        fs::create_dir_all(&self.workspace).expect("workspace dir");
        let context = context(&self.root);
        let inspected = self.execute_ok(
            &context,
            OperationId::SourceInspect,
            None,
            json!({
                "workspace_root": self.workspace,
                "repositories": [{
                    "repo_id": "fixture-repo",
                    "path": self.root.join("source"),
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
                "catalog_root": self.root.join("template-catalog"),
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
            "req-build.plan-f02".to_owned(),
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
            let analysis_text = job["analysis_text"].as_str().expect("analysis text");
            let summary_markdown = if source_path.ends_with(".rs") {
                format!(
                    "Summary for {source_path}\n\n{analysis_text}\n\n- claim: reconcile 负责对账 | evidence: def:reconcile"
                )
            } else {
                format!("Summary for {source_path}\n\n{analysis_text}")
            };
            self.execute_ok(
                &context,
                OperationId::SummaryAccept,
                Some(&run_id),
                json!({
                    "workspace_root": self.workspace,
                    "packet_id": job["packet_id"],
                    "source_sha256": job["source_sha256"],
                    "template_manifest_sha256": job["template_manifest_sha256"],
                    "summary_markdown": summary_markdown
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
        Built {
            bundle_path: PathBuf::from(
                finalized.result["bundle_path"]
                    .as_str()
                    .expect("bundle path"),
            ),
            tree_digest: finalized.result["tree_digest"]
                .as_str()
                .expect("tree digest")
                .to_owned(),
        }
    }

    fn query(&self, built: &Built, query: &str) -> Value {
        let context = context(&self.root);
        self.execute_ok(
            &context,
            OperationId::BundleQuery,
            None,
            json!({
                "bundle_path": built.bundle_path,
                "expected_tree_sha256": built.tree_digest,
                "query": query
            }),
        )
        .result
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
            format!("req-f02-{}", operation.as_str()),
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
