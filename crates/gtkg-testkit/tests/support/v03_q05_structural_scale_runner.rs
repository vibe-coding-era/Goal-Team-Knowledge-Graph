use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use gtkg_core::v03::query::{
    execute_first_file_query_page_v1, file_query_manifest_cache_stats_v1,
    reset_file_query_manifest_cache_v1, write_file_query_index_v1,
};
use gtkg_core::{CallContext, EffectPolicy, TransportKind};
use gtkg_protocol::FileReceiptRef;
use gtkg_protocol::v03::query::{
    AdjacencyDirectionV1, AdjacencyRoutingShardV1, FileQueryExpectedIdentitiesV1,
    FileQueryIndexManifestV1, FileQueryLookupV1, FileQueryRequestV1, LexicalShardV1,
    QueryShardKindV1,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

#[path = "v03_q05_structural_fixture.rs"]
mod structural_fixture;

use structural_fixture::{
    LEXICAL_SHARD_COUNT, STRUCTURAL_SCALE_SPECS, StructuralSamplePair, StructuralScaleSpec,
    build_adjacency_index, build_lexical_shards, expected_edge_ids, expected_node_ids,
    generate_structural_corpus,
};

const QUERY_SAMPLE_COUNT: usize = 20;
const STRUCTURAL_SAMPLE_COUNT: usize = 20;

fn digest(label: &str) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(label.as_bytes())))
}

fn context(root: &Path) -> Result<CallContext, String> {
    CallContext::restricted(
        TransportKind::Test,
        vec![root.to_path_buf()],
        EffectPolicy::WorkspaceWrite,
    )
    .map_err(|error| error.to_string())
}

fn direction_name(direction: AdjacencyDirectionV1) -> &'static str {
    match direction {
        AdjacencyDirectionV1::Outgoing => "outgoing",
        AdjacencyDirectionV1::Incoming => "incoming",
    }
}

fn search(term: &str) -> FileQueryRequestV1 {
    FileQueryRequestV1 {
        lookup: FileQueryLookupV1::Search {
            query: term.to_owned(),
        },
        max_results: 10,
        continuation: None,
    }
}

fn structural(sample: &StructuralSamplePair) -> FileQueryRequestV1 {
    FileQueryRequestV1 {
        lookup: FileQueryLookupV1::Adjacency {
            node_id: sample.node_id.clone(),
            direction: sample.direction,
        },
        max_results: 10,
        continuation: None,
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

struct StructuralScaleIndex {
    workspace: tempfile::TempDir,
    index_root: PathBuf,
    manifest_ref: FileReceiptRef,
    expected: FileQueryExpectedIdentitiesV1,
    samples: Vec<StructuralSamplePair>,
    corpus_bytes: usize,
    corpus_sha256: String,
    build_observation_ms: u64,
}

impl StructuralScaleIndex {
    fn build(spec: StructuralScaleSpec) -> Result<Self, String> {
        let started = Instant::now();
        let corpus = generate_structural_corpus(spec)?;
        let lexical = build_lexical_shards(&corpus.documents)?;
        let adjacency = build_adjacency_index(&corpus)?;
        let adjacency_catalog_bytes = serde_json::to_vec(&adjacency.catalog)
            .map_err(|error| error.to_string())?
            .len();
        let adjacency_shard_count = adjacency.shards.len();
        let workspace = tempfile::tempdir().map_err(|error| error.to_string())?;
        let index_root = workspace.path().join(".gtkg/query-index");
        let expected = FileQueryExpectedIdentitiesV1 {
            source_identity: digest("q05-structural-source"),
            graph_identity: digest("q05-structural-graph"),
            overlay_identity: digest("q05-structural-overlay"),
        };
        let manifest_ref = write_file_query_index_v1(
            &context(workspace.path())?,
            &index_root,
            &expected,
            &lexical,
            &adjacency,
        )
        .map_err(|error| {
            format!(
                "denominator={} lexical_shards={} adjacency_shards={} adjacency_catalog_compact_bytes={} write_error={error}",
                spec.denominator,
                lexical.len(),
                adjacency_shard_count,
                adjacency_catalog_bytes
            )
        })?;
        Ok(Self {
            workspace,
            index_root,
            manifest_ref,
            expected,
            samples: corpus.samples,
            corpus_bytes: corpus.canonical_bytes,
            corpus_sha256: corpus.canonical_sha256,
            build_observation_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
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
                    return Err("query index contains a non-file entry".to_owned());
                }
            }
            Ok(total)
        }
        visit(&self.index_root)
    }
}

struct PersistedDenominator {
    lexical_nodes: u64,
    adjacency_nodes: u64,
    routed_adjacency_nodes: u64,
    adjacency_edges: u64,
    adjacency_records: u64,
}

fn audit_persisted_denominator(
    fixture: &StructuralScaleIndex,
    denominator: usize,
) -> Result<PersistedDenominator, String> {
    let manifest = fixture.manifest()?;
    if manifest.adjacency_catalog.denominator.node_count != denominator as u64
        || manifest.adjacency_catalog.denominator.edge_count != denominator as u64
        || manifest
            .adjacency_catalog
            .denominator
            .adjacency_record_count
            != (denominator as u64) * 2
    {
        return Err("manifest adjacency denominator mismatch".to_owned());
    }
    let expected_nodes = expected_node_ids(denominator);
    let expected_edges = expected_edge_ids(denominator);
    let mut lexical_nodes = BTreeSet::new();
    let catalog_nodes = manifest
        .adjacency_catalog
        .nodes
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut routed_adjacency_nodes = BTreeSet::new();
    let mut adjacency_edges = BTreeSet::new();
    let mut adjacency_records = 0_u64;
    for shard_file in &manifest.shard_files {
        let bytes = fs::read(fixture.index_root.join(&shard_file.relative_path))
            .map_err(|error| error.to_string())?;
        match shard_file.shard_kind {
            QueryShardKindV1::Lexical => {
                let shard: LexicalShardV1 =
                    serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
                lexical_nodes.extend(shard.postings.into_iter().map(|posting| posting.node_id));
            }
            QueryShardKindV1::Adjacency => {
                let shard: AdjacencyRoutingShardV1 =
                    serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
                adjacency_records = adjacency_records
                    .checked_add(u64::try_from(shard.records.len()).unwrap_or(u64::MAX))
                    .ok_or_else(|| "adjacency record denominator overflow".to_owned())?;
                for record in shard.records {
                    routed_adjacency_nodes.insert(record.source_node_id);
                    routed_adjacency_nodes.insert(record.target_node_id);
                    adjacency_edges.insert(record.edge_id);
                }
            }
        }
    }
    if lexical_nodes != expected_nodes
        || catalog_nodes != expected_nodes
        || fixture
            .samples
            .iter()
            .any(|sample| !routed_adjacency_nodes.contains(&sample.node_id))
        || adjacency_edges != expected_edges
        || adjacency_records != (denominator as u64) * 2
    {
        return Err(format!(
            "persisted exact set mismatch: lexical={} adjacency_nodes={} adjacency_edges={} records={adjacency_records}",
            lexical_nodes.len(),
            catalog_nodes.len(),
            adjacency_edges.len()
        ));
    }
    Ok(PersistedDenominator {
        lexical_nodes: lexical_nodes.len() as u64,
        adjacency_nodes: catalog_nodes.len() as u64,
        routed_adjacency_nodes: routed_adjacency_nodes.len() as u64,
        adjacency_edges: adjacency_edges.len() as u64,
        adjacency_records,
    })
}

fn observe_scale(spec: StructuralScaleSpec) -> Result<Value, String> {
    let fixture = StructuralScaleIndex::build(spec)?;
    let persisted = audit_persisted_denominator(&fixture, spec.denominator)?;
    let total_index_bytes = fixture.total_index_bytes()?;
    let ordinary_io_budget = (total_index_bytes / 20).min(64 * 1024 * 1024);
    reset_file_query_manifest_cache_v1();
    let stats_before = file_query_manifest_cache_stats_v1();
    let mut search_latency_ms = Vec::with_capacity(QUERY_SAMPLE_COUNT);
    let mut structural_latency_ms = Vec::with_capacity(STRUCTURAL_SAMPLE_COUNT);
    let mut search_io_bytes = Vec::with_capacity(QUERY_SAMPLE_COUNT);
    let mut structural_io_bytes = Vec::with_capacity(STRUCTURAL_SAMPLE_COUNT);
    let mut full_graph_reads = 0_u64;
    let mut database_reads = 0_u64;
    let mut network_calls = 0_u64;
    let mut daemon_calls = 0_u64;

    for sample in &fixture.samples {
        let search_page = execute_first_file_query_page_v1(
            &fixture.call_context()?,
            &fixture.index_root,
            &fixture.manifest_ref,
            &fixture.expected,
            &search(&sample.search_term),
        )
        .map_err(|error| error.to_string())?;
        if search_page.lexical_hits.len() != 1
            || search_page.lexical_hits[0].node_id != sample.node_id
        {
            return Err(format!(
                "search sample {} returned the wrong node",
                sample.slot
            ));
        }
        search_latency_ms.push(search_page.receipt.latency_ms);
        search_io_bytes.push(search_page.receipt.bytes_read);
        full_graph_reads = full_graph_reads.saturating_add(search_page.full_graph_read_count);
        database_reads = database_reads.saturating_add(search_page.database_read_count);
        network_calls = network_calls.saturating_add(search_page.network_call_count);
        daemon_calls = daemon_calls.saturating_add(search_page.daemon_call_count);

        let structural_page = execute_first_file_query_page_v1(
            &fixture.call_context()?,
            &fixture.index_root,
            &fixture.manifest_ref,
            &fixture.expected,
            &structural(sample),
        )
        .map_err(|error| error.to_string())?;
        if structural_page.adjacency_edges.is_empty() || structural_page.shard_files_opened != 1 {
            return Err(format!(
                "structural sample {} did not route non-empty edges from one shard",
                sample.slot
            ));
        }
        structural_latency_ms.push(structural_page.receipt.latency_ms);
        structural_io_bytes.push(structural_page.receipt.bytes_read);
        full_graph_reads = full_graph_reads.saturating_add(structural_page.full_graph_read_count);
        database_reads = database_reads.saturating_add(structural_page.database_read_count);
        network_calls = network_calls.saturating_add(structural_page.network_call_count);
        daemon_calls = daemon_calls.saturating_add(structural_page.daemon_call_count);
    }

    let stats_after = file_query_manifest_cache_stats_v1();
    let hit_delta = stats_after.hits.saturating_sub(stats_before.hits);
    let miss_delta = stats_after.misses.saturating_sub(stats_before.misses);
    let validation_delta = stats_after
        .full_manifest_validations
        .saturating_sub(stats_before.full_manifest_validations);
    let routing_build_delta = stats_after
        .routing_index_builds
        .saturating_sub(stats_before.routing_index_builds);
    if hit_delta != 39 || miss_delta != 1 || validation_delta != 1 || routing_build_delta != 0 {
        return Err(format!(
            "cache denominator mismatch hits={hit_delta} misses={miss_delta} validations={validation_delta} routing_builds={routing_build_delta}"
        ));
    }

    let search_warm = &search_latency_ms[1..];
    let search_io_warm = &search_io_bytes[1..];
    let search_warm_p50_ms = percentile_nearest_rank(search_warm, 50).unwrap_or(u64::MAX);
    let search_warm_p95_ms = percentile_nearest_rank(search_warm, 95).unwrap_or(u64::MAX);
    let structural_warm_p50_ms =
        percentile_nearest_rank(&structural_latency_ms, 50).unwrap_or(u64::MAX);
    let structural_warm_p95_ms =
        percentile_nearest_rank(&structural_latency_ms, 95).unwrap_or(u64::MAX);
    let search_io_warm_p95 = percentile_nearest_rank(search_io_warm, 95).unwrap_or(u64::MAX);
    let structural_io_warm_p95 =
        percentile_nearest_rank(&structural_io_bytes, 95).unwrap_or(u64::MAX);
    let ordinary_io_warm_p95 = search_io_warm_p95.max(structural_io_warm_p95);
    let is_reference_scale = spec.denominator >= 10_000;
    let gate_failures = if is_reference_scale {
        [
            (search_warm_p50_ms > 150).then_some("graph_search_warm_p50_ms"),
            (search_warm_p95_ms > 750).then_some("graph_search_warm_p95_ms"),
            (structural_warm_p50_ms > 100).then_some("structural_warm_p50_ms"),
            (structural_warm_p95_ms > 500).then_some("structural_warm_p95_ms"),
            (ordinary_io_warm_p95 > ordinary_io_budget)
                .then_some("ordinary_query_io_warm_p95_bytes"),
            (full_graph_reads != 0).then_some("ordinary_query_full_graph_read_count"),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    let disclosed_non_gate_overages = if is_reference_scale {
        Vec::new()
    } else {
        [
            (search_warm_p50_ms > 150).then_some("graph_search_warm_p50_ms"),
            (search_warm_p95_ms > 750).then_some("graph_search_warm_p95_ms"),
            (structural_warm_p50_ms > 100).then_some("structural_warm_p50_ms"),
            (structural_warm_p95_ms > 500).then_some("structural_warm_p95_ms"),
            (ordinary_io_warm_p95 > ordinary_io_budget)
                .then_some("ordinary_query_io_warm_p95_bytes"),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
    };

    Ok(json!({
        "denominator": spec.denominator,
        "gate_applicability": if is_reference_scale { "reference_10k_gate" } else { "denominator_security_smoke_only" },
        "persisted_lexical_nodes": persisted.lexical_nodes,
        "persisted_adjacency_nodes": persisted.adjacency_nodes,
        "persisted_routed_adjacency_nodes": persisted.routed_adjacency_nodes,
        "persisted_adjacency_edges": persisted.adjacency_edges,
        "persisted_adjacency_records": persisted.adjacency_records,
        "lexical_shard_count": LEXICAL_SHARD_COUNT,
        "corpus_canonical_bytes": fixture.corpus_bytes,
        "corpus_sha256": fixture.corpus_sha256,
        "fixture_to_query_index_build_observation_ms": fixture.build_observation_ms,
        "query_sample_count": QUERY_SAMPLE_COUNT,
        "graph_search_warm_sample_count": QUERY_SAMPLE_COUNT - 1,
        "structural_sample_count": STRUCTURAL_SAMPLE_COUNT,
        "structural_warm_sample_count": STRUCTURAL_SAMPLE_COUNT,
        "sampled_node_direction_pairs": fixture.samples.iter().map(|sample| json!({
            "slot": sample.slot,
            "document_index": sample.document_index,
            "node_id": sample.node_id,
            "direction": direction_name(sample.direction),
        })).collect::<Vec<_>>(),
        "graph_search_warm_p50_ms": search_warm_p50_ms,
        "graph_search_warm_p95_ms": search_warm_p95_ms,
        "structural_warm_p50_ms": structural_warm_p50_ms,
        "structural_warm_p95_ms": structural_warm_p95_ms,
        "graph_search_io_warm_p95_bytes": search_io_warm_p95,
        "structural_io_warm_p95_bytes": structural_io_warm_p95,
        "ordinary_query_io_warm_p95_bytes": ordinary_io_warm_p95,
        "ordinary_query_io_warm_p95_budget_bytes": ordinary_io_budget,
        "ordinary_query_full_graph_read_count": full_graph_reads,
        "database_read_count": database_reads,
        "network_call_count": network_calls,
        "daemon_call_count": daemon_calls,
        "total_index_bytes": total_index_bytes,
        "cache_hit_delta": hit_delta,
        "cache_miss_delta": miss_delta,
        "cache_full_manifest_validation_delta": validation_delta,
        "cache_routing_index_build_delta": routing_build_delta,
        "gate_failures": gate_failures,
        "disclosed_non_gate_overages": disclosed_non_gate_overages,
    }))
}

pub fn run_structural_reference_scale_v3() -> Result<Value, String> {
    let mut measurements = Vec::new();
    for spec in STRUCTURAL_SCALE_SPECS {
        measurements.push(observe_scale(spec)?);
    }
    Ok(json!({
        "schema_version": "gtkg.q05-structural-reference-scale-observations/v3",
        "scale_denominator": [1_000, 10_000, 10_001],
        "performance_gate_denominator": [10_000, 10_001],
        "denominator_security_smoke": [1_000],
        "reference_budget_source": "deliverables/v03-benchmark/reference-environment.json",
        "measurements": measurements,
        "rss_measurement": "external_harness_required",
        "incremental_update_p95": "blocked_by_q06",
        "install_to_first_evidence_query_p95": "blocked_by_u06",
        "competitive_performance": "not_run_until_b04",
    }))
}
