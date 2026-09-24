use serde_json::Value;
use sha2::{Digest, Sha256};

const FACT_RECEIPT: &str = include_str!(
    "../../../deliverables/v03-development/test-runs/q05-cold-metric-boundary-fact-r3.json"
);
const SOURCE_RUN_LOG: &str = include_str!(
    "../../../deliverables/v03-development/test-runs/q05-cold-build-green-final.log"
);
const METRICS_MARKER: &str = "Q05_COLD_BUILD_METRICS_JSON=";
const EXACT_METRIC_NAME: &str =
    "deterministic LexicalDocument + adjacency -> query-index build p50/p95";

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn nearest_rank(samples: &[u64], percentile: usize) -> u64 {
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let rank = sorted.len().saturating_mul(percentile).div_ceil(100);
    sorted[rank.saturating_sub(1)]
}

fn required<'a>(value: &'a Value, pointer: &str) -> &'a Value {
    value
        .pointer(pointer)
        .unwrap_or_else(|| panic!("missing required fact at {pointer}"))
}

fn as_u64_vec(value: &Value, pointer: &str) -> Vec<u64> {
    required(value, pointer)
        .as_array()
        .unwrap_or_else(|| panic!("{pointer} must be an array"))
        .iter()
        .map(|sample| {
            sample
                .as_u64()
                .unwrap_or_else(|| panic!("{pointer} must contain only u64 samples"))
        })
        .collect()
}

#[test]
fn q05_reclassifies_the_retained_twenty_samples_to_the_exact_measured_boundary() {
    let receipt: Value = serde_json::from_str(FACT_RECEIPT).unwrap();
    assert_eq!(
        required(&receipt, "/schema_version"),
        "gtkg.q05-cold-metric-boundary-fact/v1"
    );
    assert_eq!(required(&receipt, "/task"), "Q05");
    assert_eq!(
        required(&receipt, "/state"),
        "passed_reclassified_without_rerun"
    );

    assert_eq!(
        required(&receipt, "/measurement/metric"),
        EXACT_METRIC_NAME
    );
    assert_eq!(
        required(&receipt, "/measurement/timed_input"),
        "deterministic LexicalDocument corpus plus deterministic adjacency input"
    );
    assert_eq!(
        required(&receipt, "/measurement/timed_output"),
        "ordinary-file query-index artifacts"
    );
    assert_eq!(required(&receipt, "/measurement/sample_count"), 20);
    assert_eq!(
        required(&receipt, "/measurement/percentile_algorithm"),
        "nearest_rank"
    );

    let source_metrics_line = SOURCE_RUN_LOG
        .lines()
        .find_map(|line| line.split_once(METRICS_MARKER).map(|(_, json)| json))
        .expect("retained source run must contain its metrics marker");
    let source_metrics: Value = serde_json::from_str(source_metrics_line).unwrap();
    let retained_samples = as_u64_vec(&source_metrics, "/samples_ms");
    let reclassified_samples = as_u64_vec(&receipt, "/measurement/samples_ms");
    assert_eq!(retained_samples.len(), 20);
    assert_eq!(reclassified_samples, retained_samples);
    assert_eq!(required(&receipt, "/measurement/p50_ms"), 5230);
    assert_eq!(required(&receipt, "/measurement/p95_ms"), 5288);
    assert_eq!(nearest_rank(&retained_samples, 50), 5230);
    assert_eq!(nearest_rank(&retained_samples, 95), 5288);

    assert_eq!(
        required(&receipt, "/provenance/mode"),
        "reclassified_without_rerun"
    );
    assert_eq!(
        required(&receipt, "/provenance/reclassified_without_rerun"),
        true
    );
    assert_eq!(
        required(&receipt, "/provenance/source_run/path"),
        "deliverables/v03-development/test-runs/q05-cold-build-green-final.log"
    );
    let source_run_sha256 = sha256_hex(SOURCE_RUN_LOG.as_bytes());
    assert_eq!(
        required(&receipt, "/provenance/source_run/sha256").as_str(),
        Some(source_run_sha256.as_str())
    );
    assert_eq!(
        required(&receipt, "/provenance/source_run/sample_count"),
        20
    );

    assert_eq!(
        required(&receipt, "/downstream/full_pipeline"),
        "blocked_by_Q06/U06"
    );
    assert_eq!(
        required(&receipt, "/downstream/query_pipeline_equivalence"),
        "blocked_by_Q06"
    );
    assert_eq!(
        required(&receipt, "/downstream/install_to_first_evidence_query"),
        "blocked_by_U06"
    );
    assert_eq!(
        required(&receipt, "/downstream/B04"),
        "not_run_not_promoted"
    );
    assert_eq!(
        required(&receipt, "/downstream/Release"),
        "not_run_not_promoted"
    );

    let measurement_claim = required(&receipt, "/measurement/metric")
        .as_str()
        .unwrap();
    assert!(!measurement_claim.contains("source-to-query-index"));
    assert!(!measurement_claim.contains("source -> query-index"));
}
