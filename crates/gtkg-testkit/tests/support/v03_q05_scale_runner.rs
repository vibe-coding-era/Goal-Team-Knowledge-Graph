use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use gtkg_core::v03::query::{
    AdjacencyEdgeInputV1, build_adjacency_routing_index_v1, execute_first_file_query_page_v1,
    file_query_manifest_cache_stats_v1, reset_file_query_manifest_cache_v1,
    write_file_query_index_v1,
};
use gtkg_core::{CallContext, EffectPolicy, TransportKind};
use gtkg_protocol::FileReceiptRef;
use gtkg_protocol::v03::query::{
    AdjacencyDirectionV1, FileQueryExpectedIdentitiesV1, FileQueryIndexManifestV1,
    FileQueryLookupV1, FileQueryRequestV1, LexicalShardV1, NormalizationCollisionStatusV1,
    QueryResolutionStateV1, QueryShardKindV1,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::fixture_generator::{
    DOCUMENTS_PER_SHARD, ScaleSpec, build_lexical_shards, expected_node_ids, generate_corpus,
};

pub const QUERY_SAMPLE_COUNT: usize = 20;

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

fn edge(edge_id: &str, source: &str, target: &str) -> AdjacencyEdgeInputV1 {
    AdjacencyEdgeInputV1 {
        edge_id: edge_id.to_owned(),
        source_node_id: source.to_owned(),
        target_node_id: target.to_owned(),
        resolution_state: QueryResolutionStateV1::Resolved,
        evidence_ref: format!("evidence:{edge_id}"),
    }
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
        let in_memory_nodes = lexical
            .iter()
            .flat_map(|shard| shard.postings.iter().map(|posting| posting.node_id.clone()))
            .collect::<BTreeSet<_>>();
        if in_memory_nodes != expected_node_ids(spec.document_count) {
            return Err("in-memory scale denominator is incomplete".to_owned());
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
        let expected = FileQueryExpectedIdentitiesV1 {
            source_identity: digest("q05-source"),
            graph_identity: digest("q05-graph"),
            overlay_identity: digest("q05-overlay"),
        };
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

    fn persisted_nodes_and_collision(&self) -> Result<(BTreeSet<String>, bool), String> {
        let manifest = self.manifest()?;
        let mut nodes = BTreeSet::new();
        let mut collision_preserved = false;
        for shard_file in manifest
            .shard_files
            .iter()
            .filter(|file| file.shard_kind == QueryShardKindV1::Lexical)
        {
            let bytes = fs::read(self.index_root.join(&shard_file.relative_path))
                .map_err(|error| error.to_string())?;
            let shard: LexicalShardV1 =
                serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
            nodes.extend(shard.postings.iter().map(|posting| posting.node_id.clone()));
            collision_preserved |= shard.normalized_terms.iter().any(|term| {
                term.normalized == "café"
                    && term.collision_status == NormalizationCollisionStatusV1::Ambiguous
                    && term.original_forms == ["cafe\u{301}".to_owned(), "café".to_owned()]
            });
        }
        Ok((nodes, collision_preserved))
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

fn percentile_nearest_rank(samples: &[u64], percentile: usize) -> Option<u64> {
    if samples.is_empty() || percentile == 0 || percentile > 100 {
        return None;
    }
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let rank = sorted.len().saturating_mul(percentile).div_ceil(100);
    sorted.get(rank.saturating_sub(1)).copied()
}

pub fn observe_scale(spec: ScaleSpec) -> Result<Value, String> {
    let fixture = ScaleIndex::build(spec)?;
    let (persisted_nodes, collision_preserved) = fixture.persisted_nodes_and_collision()?;
    if persisted_nodes != expected_node_ids(spec.document_count) {
        return Err(format!(
            "persisted denominator mismatch: expected={} observed={}",
            spec.document_count,
            persisted_nodes.len()
        ));
    }
    if !collision_preserved {
        return Err("NFC/NFD collision was not preserved as ambiguous".to_owned());
    }

    let total_index_bytes = fixture.total_index_bytes()?;
    let ordinary_io_budget = (total_index_bytes / 20).min(64 * 1024 * 1024);
    reset_file_query_manifest_cache_v1();
    let stats_before = file_query_manifest_cache_stats_v1();
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
                "search oracle failed for denominator={}",
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
                "structural oracle failed for denominator={}",
                spec.document_count
            ));
        }
        structural_latency_ms.push(structural_page.receipt.latency_ms);
    }
    let stats_after = file_query_manifest_cache_stats_v1();
    let validation_delta = stats_after
        .full_manifest_validations
        .saturating_sub(stats_before.full_manifest_validations);
    let routing_build_delta = stats_after
        .routing_index_builds
        .saturating_sub(stats_before.routing_index_builds);
    if validation_delta != 1
        || routing_build_delta > 1
        || stats_after.misses.saturating_sub(stats_before.misses) != 1
        || stats_after.hits.saturating_sub(stats_before.hits)
            < u64::try_from(QUERY_SAMPLE_COUNT * 2 - 1).unwrap()
    {
        return Err(format!(
            "cache hit repeated full work: validations={validation_delta} routing_builds={routing_build_delta} hits={} misses={}",
            stats_after.hits.saturating_sub(stats_before.hits),
            stats_after.misses.saturating_sub(stats_before.misses)
        ));
    }

    let search_p50_ms = percentile_nearest_rank(&search_latency_ms, 50).unwrap_or(u64::MAX);
    let search_p95_ms = percentile_nearest_rank(&search_latency_ms, 95).unwrap_or(u64::MAX);
    let structural_p50_ms = percentile_nearest_rank(&structural_latency_ms, 50).unwrap_or(u64::MAX);
    let structural_p95_ms = percentile_nearest_rank(&structural_latency_ms, 95).unwrap_or(u64::MAX);
    let io_p95_bytes = percentile_nearest_rank(&search_bytes, 95).unwrap_or(u64::MAX);
    let is_reference_scale = spec.document_count >= 10_000;
    let gate_failures = if is_reference_scale {
        [
            (search_p50_ms > 150).then_some("graph_search_p50_ms"),
            (search_p95_ms > 750).then_some("graph_search_p95_ms"),
            (structural_p50_ms > 100).then_some("structural_query_p50_ms"),
            (structural_p95_ms > 500).then_some("structural_query_p95_ms"),
            (io_p95_bytes > ordinary_io_budget).then_some("ordinary_query_bytes_read_p95"),
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
            (search_p50_ms > 150).then_some("graph_search_p50_ms"),
            (search_p95_ms > 750).then_some("graph_search_p95_ms"),
            (structural_p50_ms > 100).then_some("structural_query_p50_ms"),
            (structural_p95_ms > 500).then_some("structural_query_p95_ms"),
            (io_p95_bytes > ordinary_io_budget).then_some("ordinary_query_bytes_read_p95"),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
    };

    Ok(json!({
        "denominator": spec.document_count,
        "gate_applicability": if is_reference_scale { "reference_10k_gate" } else { "denominator_security_smoke_only" },
        "persisted_node_count": persisted_nodes.len(),
        "documents_per_shard": DOCUMENTS_PER_SHARD,
        "expected_lexical_shards": spec.document_count.div_ceil(DOCUMENTS_PER_SHARD),
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
        "ordinary_query_bytes_read_p95_budget": ordinary_io_budget,
        "ordinary_query_full_graph_read_count": 0,
        "total_index_bytes": total_index_bytes,
        "cache_full_manifest_validation_delta": validation_delta,
        "cache_routing_index_build_delta": routing_build_delta,
        "cache_hit_delta": stats_after.hits.saturating_sub(stats_before.hits),
        "cache_miss_delta": stats_after.misses.saturating_sub(stats_before.misses),
        "gate_failures": gate_failures,
        "disclosed_non_gate_overages": disclosed_non_gate_overages,
    }))
}
