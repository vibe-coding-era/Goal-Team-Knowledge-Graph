use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::time::Instant;

use gtkg_core::v03::query::{
    AdjacencyEdgeInputV1, build_adjacency_routing_index_v1, reset_file_query_manifest_cache_v1,
    write_file_query_index_v1,
};
use gtkg_core::{CallContext, EffectPolicy, TransportKind};
use gtkg_protocol::v03::query::{
    FileQueryExpectedIdentitiesV1, FileQueryIndexManifestV1, LexicalShardV1,
    QueryResolutionStateV1, QueryShardKindV1,
};
use serde_json::json;
use sha2::{Digest, Sha256};

#[allow(dead_code)]
#[path = "support/v03_q05_fixture.rs"]
mod fixture_generator;

use fixture_generator::{SCALE_SPECS, build_lexical_shards, expected_node_ids, generate_corpus};

const COLD_BUILD_SAMPLE_COUNT: usize = 20;
const COLD_BUILD_P95_BUDGET_MS: u64 = 180_000;

fn digest(label: &str) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(label.as_bytes())))
}

fn context(root: &Path) -> CallContext {
    CallContext::restricted(
        TransportKind::Test,
        vec![root.to_path_buf()],
        EffectPolicy::WorkspaceWrite,
    )
    .unwrap()
}

fn percentile_nearest_rank(samples: &[u64], percentile: usize) -> u64 {
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let rank = sorted.len().saturating_mul(percentile).div_ceil(100);
    sorted[rank.saturating_sub(1)]
}

#[test]
fn q05_twenty_cold_10k_source_to_query_index_builds_meet_p95_budget() {
    let spec = SCALE_SPECS
        .into_iter()
        .find(|spec| spec.document_count == 10_000)
        .unwrap();
    let expected_nodes = expected_node_ids(spec.document_count);
    let expected = FileQueryExpectedIdentitiesV1 {
        source_identity: digest("q05-cold-source"),
        graph_identity: digest("q05-cold-graph"),
        overlay_identity: digest("q05-cold-overlay"),
    };
    let mut build_ms = Vec::with_capacity(COLD_BUILD_SAMPLE_COUNT);
    let mut manifest_digests = BTreeSet::new();
    let mut index_bytes = Vec::with_capacity(COLD_BUILD_SAMPLE_COUNT);

    for _sample in 0..COLD_BUILD_SAMPLE_COUNT {
        reset_file_query_manifest_cache_v1();
        let workspace = tempfile::tempdir().unwrap();
        let index_root = workspace.path().join(".gtkg/query-index");
        let started = Instant::now();
        let corpus = generate_corpus(spec).unwrap();
        let lexical = build_lexical_shards(&corpus.documents).unwrap();
        let adjacency = build_adjacency_routing_index_v1(
            &["q05-cold-a".to_owned(), "q05-cold-b".to_owned()],
            &[AdjacencyEdgeInputV1 {
                edge_id: "q05-cold-edge".to_owned(),
                source_node_id: "q05-cold-a".to_owned(),
                target_node_id: "q05-cold-b".to_owned(),
                resolution_state: QueryResolutionStateV1::Resolved,
                evidence_ref: "evidence:q05-cold-edge".to_owned(),
            }],
        )
        .unwrap();
        let manifest_ref = write_file_query_index_v1(
            &context(workspace.path()),
            &index_root,
            &expected,
            &lexical,
            &adjacency,
        )
        .unwrap();
        build_ms.push(u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX));
        manifest_digests.insert(manifest_ref.sha256.clone());

        let manifest_bytes = fs::read(index_root.join(&manifest_ref.path)).unwrap();
        let manifest: FileQueryIndexManifestV1 = serde_json::from_slice(&manifest_bytes).unwrap();
        let mut persisted_nodes = BTreeSet::new();
        let mut total_bytes = u64::try_from(manifest_bytes.len()).unwrap();
        for shard_file in manifest
            .shard_files
            .iter()
            .filter(|file| file.shard_kind == QueryShardKindV1::Lexical)
        {
            let bytes = fs::read(index_root.join(&shard_file.relative_path)).unwrap();
            total_bytes = total_bytes
                .checked_add(u64::try_from(bytes.len()).unwrap())
                .unwrap();
            let shard: LexicalShardV1 = serde_json::from_slice(&bytes).unwrap();
            persisted_nodes.extend(shard.postings.into_iter().map(|posting| posting.node_id));
        }
        assert_eq!(persisted_nodes, expected_nodes);
        index_bytes.push(total_bytes);
    }

    let p50_ms = percentile_nearest_rank(&build_ms, 50);
    let p95_ms = percentile_nearest_rank(&build_ms, 95);
    println!(
        "Q05_COLD_BUILD_METRICS_JSON={}",
        json!({
            "schema_version": "gtkg.q05-cold-build-observations/v1",
            "denominator": 10_000,
            "sample_count": COLD_BUILD_SAMPLE_COUNT,
            "percentile": "nearest_rank",
            "p50_ms": p50_ms,
            "p95_ms": p95_ms,
            "p95_budget_ms": COLD_BUILD_P95_BUDGET_MS,
            "samples_ms": build_ms,
            "persisted_node_count_each_run": 10_000,
            "omitted_nodes": 0,
            "manifest_digest_count": manifest_digests.len(),
            "index_bytes_min": index_bytes.iter().min(),
            "index_bytes_max": index_bytes.iter().max(),
            "claim_boundary": "current local reference-host Development cold build; not B04 competitor, install, Release, or business evidence",
        })
    );
    assert_eq!(manifest_digests.len(), 1);
    assert_eq!(index_bytes.iter().min(), index_bytes.iter().max());
    assert!(
        p95_ms <= COLD_BUILD_P95_BUDGET_MS,
        "cold 10k source-to-query-index p95 {p95_ms}ms exceeds {COLD_BUILD_P95_BUDGET_MS}ms"
    );
}
