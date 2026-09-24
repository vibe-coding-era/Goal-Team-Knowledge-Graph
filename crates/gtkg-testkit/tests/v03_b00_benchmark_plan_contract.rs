use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

const PLAN: &str = "deliverables/v03-benchmark/benchmark-plan-v3.json";
const CORPUS: &str = "deliverables/v03-benchmark/corpus-manifest.json";
const QUERIES: &str = "deliverables/v03-benchmark/query-denominator.json";
const TASKS: &str = "deliverables/v03-benchmark/agent-task-denominator.json";
const ENVIRONMENT: &str = "deliverables/v03-benchmark/reference-environment.json";
const PINS: &str = "deliverables/v03-benchmark/pins.json";

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root")
}

fn load(relative: &str) -> Value {
    let path = repo_root().join(relative);
    let bytes = fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|error| panic!("parse {}: {error}", path.display()))
}

fn object(value: &Value) -> &Map<String, Value> {
    value.as_object().expect("JSON object")
}

fn array<'a>(value: &'a Value, key: &str) -> &'a Vec<Value> {
    object(value)[key].as_array().unwrap_or_else(|| panic!("{key} array"))
}

fn string<'a>(value: &'a Value, key: &str) -> &'a str {
    object(value)[key]
        .as_str()
        .unwrap_or_else(|| panic!("{key} string"))
}

fn number(value: &Value, key: &str) -> u64 {
    object(value)[key]
        .as_u64()
        .unwrap_or_else(|| panic!("{key} integer"))
}

fn assert_sha(value: &str) {
    assert_eq!(value.len(), 40, "commit/tree must be full 40-hex");
    assert!(value.bytes().all(|byte| byte.is_ascii_hexdigit()));
}

#[test]
fn benchmark_plan_v3_freezes_the_exact_common_denominator_without_running_it() {
    let plan = load(PLAN);
    assert_eq!(string(&plan, "schema_version"), "gtkg.benchmark-plan/v3");
    assert_eq!(string(&plan, "plan_id"), "v03-b00-r1");
    assert_eq!(string(&plan, "revision"), "r1");
    assert_eq!(string(&plan, "state"), "frozen_with_blockers");
    assert_eq!(string(&plan, "execution_state"), "not_run");

    let systems = array(&plan, "systems")
        .iter()
        .map(|system| string(system, "system_id"))
        .collect::<Vec<_>>();
    assert_eq!(
        systems,
        ["gtkg-v0.3-development", "codegraph-v0.20.1", "graphify-v0.9.52"]
    );
    for system in array(&plan, "systems") {
        assert_eq!(string(system, "execution_state"), "not_run");
        assert!(matches!(
            string(system, "identity_state"),
            "source_frozen" | "source_candidate_frozen"
        ));
    }

    let denominators = &object(&plan)["denominators"];
    assert_eq!(number(denominators, "repository_count"), 8);
    assert_eq!(number(denominators, "query_count"), 300);
    assert_eq!(number(denominators, "agent_task_count"), 30);
    assert_eq!(number(denominators, "repeat_count_per_system"), 3);
    assert_eq!(number(denominators, "planned_agent_run_count"), 270);

    let refs = &object(&plan)["artifact_refs"];
    assert_eq!(string(refs, "corpus"), CORPUS);
    assert_eq!(string(refs, "queries"), QUERIES);
    assert_eq!(string(refs, "agent_tasks"), TASKS);
    assert_eq!(string(refs, "reference_environment"), ENVIRONMENT);
    assert_eq!(string(refs, "pins"), PINS);

    let runner = &object(&plan)["runner_contract"];
    assert_eq!(string(runner, "implementation_state"), "not_available");
    assert_eq!(string(runner, "execution_state"), "not_run");
    assert_eq!(string(runner, "working_directory"), ".");
    assert!(array(runner, "argv_template").len() >= 4);
    assert_eq!(number(runner, "competitor_process_invocation_count"), 0);
}

#[test]
fn corpus_has_eight_license_bound_commit_pins_and_disjoint_splits() {
    let corpus = load(CORPUS);
    assert_eq!(string(&corpus, "schema_version"), "gtkg.benchmark-corpus/v3");
    assert_eq!(string(&corpus, "state"), "frozen_metadata_only");
    assert_eq!(string(&corpus, "source_materialization_state"), "not_run");
    assert_eq!(string(&corpus, "source_execution_state"), "not_run");

    let repositories = array(&corpus, "repositories");
    assert_eq!(repositories.len(), 8);
    let mut ids = BTreeSet::new();
    let mut coordinates = BTreeSet::new();
    let mut language_counts = BTreeMap::<&str, usize>::new();
    let mut split_counts = BTreeMap::<&str, usize>::new();
    for repository in repositories {
        let id = string(repository, "repository_id");
        assert!(ids.insert(id));
        let coordinate = string(repository, "repository");
        let commit = string(repository, "commit");
        let tree = string(repository, "tree");
        assert!(coordinates.insert((coordinate, commit)));
        assert_sha(commit);
        assert_sha(tree);
        assert!(string(repository, "source_url").contains(commit));
        assert!(string(repository, "license_source_url").contains(commit));
        assert!(!string(repository, "license_spdx").is_empty());
        assert_eq!(string(repository, "license_state"), "verified_official_pinned_source");
        *language_counts.entry(string(repository, "language")).or_default() += 1;
        *split_counts.entry(string(repository, "split")).or_default() += 1;
    }
    assert_eq!(
        language_counts,
        BTreeMap::from([("JavaScript", 2), ("Python", 2), ("Rust", 2), ("TypeScript", 2)])
    );
    assert_eq!(
        split_counts,
        BTreeMap::from([("calibration", 2), ("evaluation", 2), ("holdout", 4)])
    );
    let proof = &object(&corpus)["split_proof"];
    assert_eq!(string(proof, "overlap_policy"), "repository_id_and_commit_pairwise_disjoint");
    assert_eq!(object(proof)["all_pairwise_disjoint"], Value::Bool(true));
    assert_eq!(string(proof, "holdout_visibility"), "hidden_from_system_tuning");
}

#[test]
fn query_denominator_contains_300_frozen_questions_and_required_risk_mix() {
    let corpus = load(CORPUS);
    let repository_splits = array(&corpus, "repositories")
        .iter()
        .map(|repository| {
            (
                string(repository, "repository_id").to_owned(),
                string(repository, "split").to_owned(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let denominator = load(QUERIES);
    assert_eq!(string(&denominator, "schema_version"), "gtkg.query-denominator/v3");
    assert_eq!(string(&denominator, "state"), "frozen_unannotated");
    assert_eq!(string(&denominator, "execution_state"), "not_run");
    let queries = array(&denominator, "queries");
    assert_eq!(queries.len(), 300);

    let mut ids = BTreeSet::new();
    let mut special = 0usize;
    let mut kinds = BTreeSet::new();
    for (index, query) in queries.iter().enumerate() {
        let expected_id = format!("bq-{:03}", index + 1);
        assert_eq!(string(query, "query_id"), expected_id);
        assert!(ids.insert(string(query, "query_id")));
        let repository_id = string(query, "repository_id");
        assert_eq!(
            string(query, "split"),
            repository_splits.get(repository_id).expect("known repository")
        );
        let kind = string(query, "query_kind");
        kinds.insert(kind);
        if matches!(kind, "impact" | "no_answer" | "conflict") {
            special += 1;
        }
        let question = string(query, "question");
        assert!(!question.trim().is_empty());
        assert!(!question.contains("TBD"));
        assert_eq!(string(query, "gold_state"), "not_available_pending_annotation");
        assert_eq!(string(query, "execution_state"), "not_run");
    }
    assert_eq!(kinds.len(), 10);
    assert!(special >= 75, "at least 25% must be no-answer/conflict/impact");
    assert_eq!(number(&denominator, "special_risk_query_count"), special as u64);
}

#[test]
fn agent_task_denominator_contains_30_blind_tasks_and_270_planned_runs() {
    let corpus = load(CORPUS);
    let repository_ids = array(&corpus, "repositories")
        .iter()
        .map(|repository| string(repository, "repository_id"))
        .collect::<BTreeSet<_>>();
    let denominator = load(TASKS);
    assert_eq!(string(&denominator, "schema_version"), "gtkg.agent-task-denominator/v3");
    assert_eq!(string(&denominator, "state"), "frozen_with_blockers");
    assert_eq!(string(&denominator, "execution_state"), "not_run");
    assert_eq!(number(&denominator, "system_count"), 3);
    assert_eq!(number(&denominator, "repeat_count_per_system"), 3);
    assert_eq!(number(&denominator, "planned_run_count"), 270);

    let tasks = array(&denominator, "tasks");
    assert_eq!(tasks.len(), 30);
    let mut ids = BTreeSet::new();
    for (index, task) in tasks.iter().enumerate() {
        assert_eq!(string(task, "task_id"), format!("bat-{:02}", index + 1));
        assert!(ids.insert(string(task, "task_id")));
        assert!(repository_ids.contains(string(task, "repository_id")));
        assert!(!string(task, "instruction").trim().is_empty());
        assert!(!string(task, "oracle_summary").trim().is_empty());
        assert_eq!(string(task, "oracle_state"), "frozen_blind_review_contract");
        assert_eq!(string(task, "execution_state"), "not_run");
    }
}

#[test]
fn reference_host_model_grader_and_budget_states_are_truthful_and_frozen() {
    let environment = load(ENVIRONMENT);
    assert_eq!(string(&environment, "schema_version"), "gtkg.benchmark-environment/v3");
    let host = &object(&environment)["reference_host"];
    assert_eq!(string(host, "state"), "frozen_local_readback");
    for key in ["hardware_model", "architecture", "os_name", "os_version", "cpu", "memory_bytes"] {
        assert_ne!(string(host, key), "not_available", "{key} must be read back");
    }
    let browser = &object(&environment)["reference_browser"];
    assert_eq!(string(browser, "state"), "not_available");
    let agent = &object(&environment)["agent_runtime"];
    assert_eq!(string(agent, "model_state"), "blocked");
    assert_eq!(string(agent, "model_id"), "not_available");
    assert_eq!(string(agent, "grader_state"), "blocked");
    assert_eq!(string(agent, "grader_id"), "not_available");
    assert_eq!(string(agent, "provider_price_state"), "not_available");

    let budget = &object(&environment)["agent_budget_policy"];
    assert_eq!(string(budget, "state"), "frozen_policy_model_cost_blocked");
    assert_eq!(number(budget, "max_turns"), 20);
    assert_eq!(number(budget, "max_tool_calls"), 100);
    assert_eq!(number(budget, "max_input_tokens"), 120_000);
    assert_eq!(number(budget, "max_output_tokens"), 20_000);
    assert_eq!(number(budget, "wall_time_seconds"), 1_800);

    let performance = &object(&environment)["performance_budgets"];
    assert_eq!(string(performance, "state"), "frozen_for_reference_host");
    assert_eq!(number(performance, "cold_build_p95_ms"), 180_000);
    assert_eq!(number(performance, "first_query_p95_ms"), 300_000);
    assert_eq!(number(performance, "incremental_update_p95_ms"), 10_000);
    assert_eq!(number(performance, "peak_rss_bytes"), 1_610_612_736);
}

#[test]
fn official_competitor_pins_are_current_candidates_but_not_execution_receipts() {
    let pins = load(PINS);
    assert_eq!(string(&pins, "schema_version"), "gtkg.benchmark-pins/v3");
    assert_eq!(string(&pins, "checked_at"), "2026-08-30");
    assert_eq!(string(&pins, "execution_state"), "not_run");
    let competitors = array(&pins, "competitors");
    assert_eq!(competitors.len(), 2);

    let codegraph = &competitors[0];
    assert_eq!(string(codegraph, "system_id"), "codegraph-v0.20.1");
    assert_eq!(string(codegraph, "version"), "0.20.1");
    assert_eq!(string(codegraph, "commit"), "489ccf1612555510f8367e3e673181f6a1275fe4");
    assert_eq!(string(codegraph, "decision"), "retain_prd_pin_current_latest_stable");
    assert_eq!(string(codegraph, "license_spdx"), "Apache-2.0");

    let graphify = &competitors[1];
    assert_eq!(string(graphify, "system_id"), "graphify-v0.9.52");
    assert_eq!(string(graphify, "version"), "0.9.52");
    assert_eq!(string(graphify, "commit"), "680e3ed8edd3dc1fa1961050912941880b778207");
    assert_eq!(string(graphify, "decision"), "retain_prd_pin_current_latest_stable");
    assert_eq!(string(graphify, "license_spdx"), "Apache-2.0");

    for competitor in competitors {
        assert_eq!(string(competitor, "release_state"), "verified_official_primary_source");
        assert_eq!(string(competitor, "install_state"), "not_run");
        assert_eq!(string(competitor, "export_state"), "not_available");
        assert_eq!(string(competitor, "telemetry_readback_state"), "not_run");
        assert!(string(competitor, "release_url").starts_with("https://github.com/"));
        assert!(string(competitor, "source_url").contains(string(competitor, "commit")));
    }
}
