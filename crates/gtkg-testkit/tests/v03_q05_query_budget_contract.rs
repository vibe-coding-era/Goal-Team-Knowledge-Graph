use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use gtkg_core::v03::query::{
    AdjacencyEdgeInputV1, FileQueryErrorV1, LexicalDocumentV1, build_adjacency_routing_index_v1,
    build_lexical_shard_v1, execute_first_file_query_page_v1, write_file_query_index_v1,
};
use gtkg_core::{CallContext, EffectPolicy, TransportKind};
use gtkg_protocol::FileReceiptRef;
use gtkg_protocol::v03::query::{
    AdjacencyDirectionV1, FileQueryExpectedIdentitiesV1, FileQueryIndexManifestV1,
    FileQueryLookupV1, FileQueryRequestV1, LexicalShardV1, NormalizationCollisionStatusV1,
    QueryResolutionStateV1, QueryResourceBudgetsV1,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

#[path = "support/v03_q05_fixture.rs"]
mod fixture_generator;

use fixture_generator::{
    SCALE_SPECS, ScaleSpec, build_lexical_shards, expected_node_ids, generate_corpus,
};

const REFERENCE_ENVIRONMENT: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../deliverables/v03-benchmark/reference-environment.json"
));
const QUERY_SAMPLE_COUNT: usize = 20;

fn digest(label: &str) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(label.as_bytes())))
}

fn document(node_id: &str, evidence_ref: &str, text: &str) -> LexicalDocumentV1 {
    LexicalDocumentV1 {
        node_id: node_id.to_owned(),
        evidence_ref: evidence_ref.to_owned(),
        text: text.to_owned(),
    }
}

fn edge(edge_id: &str, source: &str, target: &str) -> AdjacencyEdgeInputV1 {
    AdjacencyEdgeInputV1 {
        edge_id: edge_id.to_owned(),
        source_node_id: source.to_owned(),
        target_node_id: target.to_owned(),
        resolution_state: QueryResolutionStateV1::Resolved,
        evidence_ref: format!("evidence:{edge_id}"),
    }
}

fn context(root: &Path) -> Result<CallContext, String> {
    CallContext::restricted(
        TransportKind::Test,
        vec![root.to_path_buf()],
        EffectPolicy::WorkspaceWrite,
    )
    .map_err(|error| error.to_string())
}

fn search(query: &str) -> FileQueryRequestV1 {
    FileQueryRequestV1 {
        lookup: FileQueryLookupV1::Search {
            query: query.to_owned(),
        },
        max_results: 10,
        continuation: None,
    }
}

fn structural() -> FileQueryRequestV1 {
    FileQueryRequestV1 {
        lookup: FileQueryLookupV1::Adjacency {
            node_id: "q05-node-graph-a".to_owned(),
            direction: AdjacencyDirectionV1::Outgoing,
        },
        max_results: 10,
        continuation: None,
    }
}

fn query_identities() -> FileQueryExpectedIdentitiesV1 {
    FileQueryExpectedIdentitiesV1 {
        source_identity: digest("q05-source"),
        graph_identity: digest("q05-graph"),
        overlay_identity: digest("q05-overlay"),
    }
}

struct ScaleIndex {
    workspace: tempfile::TempDir,
    index_root: PathBuf,
    manifest_ref: FileReceiptRef,
    expected: FileQueryExpectedIdentitiesV1,
    corpus_bytes: usize,
    corpus_sha256: String,
    build_ms: u64,
}

impl ScaleIndex {
    fn build(spec: ScaleSpec) -> Result<Self, String> {
        let started = Instant::now();
        let corpus = generate_corpus(spec)?;
        let lexical = build_lexical_shards(&corpus.documents)?;
        let observed = lexical
            .iter()
            .flat_map(|shard| shard.postings.iter().map(|posting| posting.node_id.clone()))
            .collect::<BTreeSet<_>>();
        if observed != expected_node_ids(spec.document_count) {
            return Err("in-memory lexical denominator omitted one or more nodes".to_owned());
        }
        let adjacency = build_adjacency_routing_index_v1(
            &["q05-node-graph-a".to_owned(), "q05-node-graph-b".to_owned()],
            &[edge(
                "q05-edge-graph-a-b",
                "q05-node-graph-a",
                "q05-node-graph-b",
            )],
        )
        .map_err(|error| error.to_string())?;
        let workspace = tempfile::tempdir().map_err(|error| error.to_string())?;
        let index_root = workspace.path().join(".gtkg/query-index");
        let expected = query_identities();
        let manifest_ref = write_file_query_index_v1(
            &context(workspace.path())?,
            &index_root,
            &expected,
            &lexical,
            &adjacency,
        )
        .map_err(|error| error.to_string())?;
        Ok(Self {
            workspace,
            index_root,
            manifest_ref,
            expected,
            corpus_bytes: corpus.canonical_bytes,
            corpus_sha256: corpus.canonical_sha256,
            build_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        })
    }

    fn call_context(&self) -> Result<CallContext, String> {
        context(self.workspace.path())
    }

    fn manifest(&self) -> Result<FileQueryIndexManifestV1, String> {
        let bytes = fs::read(self.index_root.join(&self.manifest_ref.path))
            .map_err(|error| error.to_string())?;
        serde_json::from_slice(&bytes).map_err(|error| error.to_string())
    }

    fn persisted_node_ids(&self) -> Result<BTreeSet<String>, String> {
        let manifest = self.manifest()?;
        let mut nodes = BTreeSet::new();
        for shard_file in manifest
            .shard_files
            .iter()
            .filter(|file| file.shard_kind == gtkg_protocol::v03::query::QueryShardKindV1::Lexical)
        {
            let bytes = fs::read(self.index_root.join(&shard_file.relative_path))
                .map_err(|error| error.to_string())?;
            let shard: LexicalShardV1 =
                serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
            nodes.extend(shard.postings.into_iter().map(|posting| posting.node_id));
        }
        Ok(nodes)
    }

    fn total_index_bytes(&self) -> Result<u64, String> {
        fn visit(path: &Path) -> Result<u64, String> {
            let mut total = 0_u64;
            for entry in fs::read_dir(path).map_err(|error| error.to_string())? {
                let entry = entry.map_err(|error| error.to_string())?;
                let metadata = entry.metadata().map_err(|error| error.to_string())?;
                if metadata.is_dir() {
                    total = total
                        .checked_add(visit(&entry.path())?)
                        .ok_or_else(|| "index byte denominator overflow".to_owned())?;
                } else if metadata.is_file() {
                    total = total
                        .checked_add(metadata.len())
                        .ok_or_else(|| "index byte denominator overflow".to_owned())?;
                } else {
                    return Err("query index contains a non-file, non-directory entry".to_owned());
                }
            }
            Ok(total)
        }
        visit(&self.index_root)
    }
}

fn percentile_nearest_rank(samples: &[u64], percentile: usize) -> Option<u64> {
    if samples.is_empty() || percentile == 0 || percentile > 100 {
        return None;
    }
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let rank = sorted.len().saturating_mul(percentile).div_ceil(100);
    sorted.get(rank.saturating_sub(1)).copied()
}

fn measure_scale(spec: ScaleSpec) -> Result<Value, String> {
    let fixture = ScaleIndex::build(spec)?;
    let persisted_nodes = fixture.persisted_node_ids()?;
    let expected_nodes = expected_node_ids(spec.document_count);
    if persisted_nodes != expected_nodes {
        return Err(format!(
            "persisted denominator mismatch: expected={} observed={}",
            expected_nodes.len(),
            persisted_nodes.len()
        ));
    }
    let total_index_bytes = fixture.total_index_bytes()?;
    let ordinary_io_budget = (total_index_bytes / 20).min(64 * 1024 * 1024);
    let mut search_latency_ms = Vec::with_capacity(QUERY_SAMPLE_COUNT);
    let mut search_bytes = Vec::with_capacity(QUERY_SAMPLE_COUNT);
    let mut structural_latency_ms = Vec::with_capacity(QUERY_SAMPLE_COUNT);
    for sample in 0..QUERY_SAMPLE_COUNT {
        let index = sample * (spec.document_count - 1) / (QUERY_SAMPLE_COUNT - 1);
        let query = format!("q05_symbol_{index:05}");
        let page = execute_first_file_query_page_v1(
            &fixture.call_context()?,
            &fixture.index_root,
            &fixture.manifest_ref,
            &fixture.expected,
            &search(&query),
        )
        .map_err(|error| error.to_string())?;
        if page.lexical_hits.len() != 1
            || page.lexical_hits[0].node_id != format!("q05-node-{index:05}")
            || page.shard_files_opened != 1
            || page.full_graph_read_count != 0
            || page.database_read_count != 0
            || page.network_call_count != 0
            || page.daemon_call_count != 0
        {
            return Err(format!(
                "query oracle failed for denominator={}",
                spec.document_count
            ));
        }
        search_latency_ms.push(page.receipt.latency_ms);
        search_bytes.push(page.receipt.bytes_read);

        let structural_page = execute_first_file_query_page_v1(
            &fixture.call_context()?,
            &fixture.index_root,
            &fixture.manifest_ref,
            &fixture.expected,
            &structural(),
        )
        .map_err(|error| error.to_string())?;
        if structural_page.adjacency_edges.len() != 1
            || structural_page.shard_files_opened != 1
            || structural_page.full_graph_read_count != 0
        {
            return Err(format!(
                "structural query oracle failed for denominator={}",
                spec.document_count
            ));
        }
        structural_latency_ms.push(structural_page.receipt.latency_ms);
    }

    let manifest = fixture.manifest()?;
    let collision = manifest
        .shard_files
        .iter()
        .find(|file| file.shard_id == "q05-lex-00000-00099")
        .ok_or_else(|| "collision shard missing".to_owned())?;
    let collision_shard: LexicalShardV1 = serde_json::from_slice(
        &fs::read(fixture.index_root.join(&collision.relative_path))
            .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    let collision_term = collision_shard
        .normalized_terms
        .iter()
        .find(|term| term.normalized == "café")
        .ok_or_else(|| "normalization collision term missing".to_owned())?;
    if collision_term.collision_status != NormalizationCollisionStatusV1::Ambiguous
        || collision_term.original_forms != ["cafe\u{301}".to_owned(), "café".to_owned()]
    {
        return Err("normalization collision was silently merged".to_owned());
    }

    let search_p50_ms = percentile_nearest_rank(&search_latency_ms, 50).unwrap_or(u64::MAX);
    let search_p95_ms = percentile_nearest_rank(&search_latency_ms, 95).unwrap_or(u64::MAX);
    let structural_p50_ms = percentile_nearest_rank(&structural_latency_ms, 50).unwrap_or(u64::MAX);
    let structural_p95_ms = percentile_nearest_rank(&structural_latency_ms, 95).unwrap_or(u64::MAX);
    let io_p95_bytes = percentile_nearest_rank(&search_bytes, 95).unwrap_or(u64::MAX);
    let budget_failures = [
        (search_p50_ms > 150).then_some("graph_search_p50_ms"),
        (search_p95_ms > 750).then_some("graph_search_p95_ms"),
        (structural_p50_ms > 100).then_some("structural_query_p50_ms"),
        (structural_p95_ms > 500).then_some("structural_query_p95_ms"),
        (io_p95_bytes > ordinary_io_budget).then_some("ordinary_query_bytes_read_p95"),
        (fixture.build_ms > 180_000).then_some("cold_build_observation_ms"),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>();

    Ok(json!({
        "denominator": spec.document_count,
        "documents_per_shard": fixture_generator::DOCUMENTS_PER_SHARD,
        "expected_lexical_shards": spec.document_count.div_ceil(fixture_generator::DOCUMENTS_PER_SHARD),
        "persisted_node_count": persisted_nodes.len(),
        "corpus_canonical_bytes": fixture.corpus_bytes,
        "corpus_sha256": fixture.corpus_sha256,
        "query_sample_count": QUERY_SAMPLE_COUNT,
        "cold_build_observation_ms": fixture.build_ms,
        "cold_build_claim_state": "single_local_observation_not_p95",
        "graph_search_p50_ms": search_p50_ms,
        "graph_search_p95_ms": search_p95_ms,
        "structural_query_p50_ms": structural_p50_ms,
        "structural_query_p95_ms": structural_p95_ms,
        "ordinary_query_bytes_read_p95": io_p95_bytes,
        "total_index_bytes": total_index_bytes,
        "ordinary_query_bytes_read_p95_budget": ordinary_io_budget,
        "ordinary_query_full_graph_read_count": 0,
        "budget_failures": budget_failures,
    }))
}

#[test]
fn q05_oversize_term_is_rejected_before_shard_or_external_io() {
    let workspace = tempfile::tempdir().unwrap();
    let index_root = workspace.path().join(".gtkg/query-index");
    let lexical = [build_lexical_shard_v1(
        "q05-security",
        &[document("q05-node", "evidence:q05", "bounded_query")],
    )
    .unwrap()];
    let adjacency = build_adjacency_routing_index_v1(
        &["q05-a".to_owned(), "q05-b".to_owned()],
        &[edge("q05-edge", "q05-a", "q05-b")],
    )
    .unwrap();
    let expected = query_identities();
    let manifest_ref = write_file_query_index_v1(
        &context(workspace.path()).unwrap(),
        &index_root,
        &expected,
        &lexical,
        &adjacency,
    )
    .unwrap();
    let oversize = "x".repeat(
        usize::try_from(QueryResourceBudgetsV1::v03_frozen().max_term_scalars).unwrap() + 1,
    );
    let observed = execute_first_file_query_page_v1(
        &context(workspace.path()).unwrap(),
        &index_root,
        &manifest_ref,
        &expected,
        &search(&oversize),
    );
    assert_eq!(observed, Err(FileQueryErrorV1::ResourceBudgetExceeded));
}

#[test]
fn q05_scale_denominators_latency_io_and_collision_are_measured_without_omission() {
    let mut observations = Vec::new();
    let mut failures = Vec::new();
    for spec in SCALE_SPECS {
        match measure_scale(spec) {
            Ok(observation) => {
                if observation["budget_failures"]
                    .as_array()
                    .is_some_and(|values| !values.is_empty())
                {
                    failures.push(format!(
                        "denominator={} budget_failures={}",
                        spec.document_count, observation["budget_failures"]
                    ));
                }
                observations.push(observation);
            }
            Err(error) => {
                failures.push(format!("denominator={} {error}", spec.document_count));
                observations.push(json!({
                    "denominator": spec.document_count,
                    "state": "failed",
                    "error": error,
                }));
            }
        }
    }
    println!(
        "Q05_METRICS_JSON={}",
        json!({
            "schema_version": "gtkg.q05-query-budget-observations/v1",
            "scale_denominator": [1_000, 10_000, 10_001],
            "reference_budget_source": "deliverables/v03-benchmark/reference-environment.json",
            "measurements": observations,
            "rss_measurement": "external_harness_required",
            "incremental_update_p95": "blocked_by_q06",
            "install_to_first_query_p95": "blocked_by_u06",
            "explorer_first_meaningful_content_p95": "blocked_by_u03",
        })
    );
    assert!(failures.is_empty(), "{}", failures.join("; "));
}

#[test]
fn q05_reference_host_budget_source_is_frozen_and_not_a_execution_claim() {
    let environment: Value = serde_json::from_str(REFERENCE_ENVIRONMENT).unwrap();
    assert_eq!(
        environment["schema_version"],
        "gtkg.benchmark-environment/v3"
    );
    assert_eq!(environment["execution_state"], "not_run");
    assert_eq!(
        environment["reference_host"]["state"],
        "frozen_local_readback"
    );
    assert_eq!(
        environment["reference_host"]["hardware_model"],
        "MacBook Air (Mac16,12)"
    );
    assert_eq!(environment["reference_host"]["architecture"], "arm64");
    let budgets = &environment["performance_budgets"];
    assert_eq!(budgets["state"], "frozen_for_reference_host");
    assert_eq!(budgets["cold_build_p95_ms"], 180_000);
    assert_eq!(budgets["structural_query_p50_ms"], 100);
    assert_eq!(budgets["structural_query_p95_ms"], 500);
    assert_eq!(budgets["graph_search_p50_ms"], 150);
    assert_eq!(budgets["graph_search_p95_ms"], 750);
    assert_eq!(budgets["peak_rss_bytes"], 1_610_612_736_u64);
}

#[cfg(unix)]
#[test]
fn q05_symlink_and_hardlink_selected_shards_fail_closed_without_escape() {
    use std::os::unix::fs::symlink;

    for kind in ["symlink", "hardlink"] {
        let workspace = tempfile::tempdir().unwrap();
        let index_root = workspace.path().join(".gtkg/query-index");
        let lexical = [build_lexical_shard_v1(
            "q05-path",
            &[document("q05-node", "evidence:q05", "bounded_query")],
        )
        .unwrap()];
        let adjacency = build_adjacency_routing_index_v1(
            &["q05-a".to_owned(), "q05-b".to_owned()],
            &[edge("q05-edge", "q05-a", "q05-b")],
        )
        .unwrap();
        let expected = query_identities();
        let manifest_ref = write_file_query_index_v1(
            &context(workspace.path()).unwrap(),
            &index_root,
            &expected,
            &lexical,
            &adjacency,
        )
        .unwrap();
        let manifest: FileQueryIndexManifestV1 =
            serde_json::from_slice(&fs::read(index_root.join(&manifest_ref.path)).unwrap())
                .unwrap();
        let shard = manifest
            .shard_files
            .iter()
            .find(|shard| shard.shard_id == "q05-path")
            .unwrap();
        let path = index_root.join(&shard.relative_path);
        match kind {
            "symlink" => {
                let saved = path.with_extension("saved");
                fs::rename(&path, &saved).unwrap();
                symlink(&saved, &path).unwrap();
            }
            "hardlink" => fs::hard_link(&path, path.with_extension("linked")).unwrap(),
            _ => unreachable!(),
        }
        assert_eq!(
            execute_first_file_query_page_v1(
                &context(workspace.path()).unwrap(),
                &index_root,
                &manifest_ref,
                &expected,
                &search("bounded_query"),
            ),
            Err(FileQueryErrorV1::UnsafePath),
            "{kind} selected shard must fail closed"
        );
    }
}
