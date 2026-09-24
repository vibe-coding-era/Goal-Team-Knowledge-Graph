use std::collections::BTreeSet;

use serde_json::Value;

#[path = "support/v03_q05_structural_scale_runner.rs"]
mod structural_scale_runner;

use structural_scale_runner::run_structural_reference_scale_v3;

fn number(value: &Value, key: &str) -> u64 {
    value[key]
        .as_u64()
        .unwrap_or_else(|| panic!("{key} must be a u64"))
}

fn string<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key]
        .as_str()
        .unwrap_or_else(|| panic!("{key} must be a string"))
}

#[test]
fn q05_structural_scale_uses_same_order_adjacency_and_warm_budget_metrics() {
    let report = run_structural_reference_scale_v3().unwrap();
    assert_eq!(
        report["schema_version"],
        "gtkg.q05-structural-reference-scale-observations/v3"
    );
    assert_eq!(
        report["scale_denominator"],
        serde_json::json!([1_000, 10_000, 10_001])
    );
    assert_eq!(
        report["performance_gate_denominator"],
        serde_json::json!([10_000, 10_001])
    );
    assert_eq!(
        report["denominator_security_smoke"],
        serde_json::json!([1_000])
    );

    let measurements = report["measurements"].as_array().unwrap();
    assert_eq!(measurements.len(), 3);
    let observed_denominators = measurements
        .iter()
        .map(|measurement| number(measurement, "denominator"))
        .collect::<Vec<_>>();
    assert_eq!(observed_denominators, [1_000, 10_000, 10_001]);

    for measurement in measurements {
        let denominator = number(measurement, "denominator");
        assert_eq!(number(measurement, "persisted_lexical_nodes"), denominator);
        assert_eq!(
            number(measurement, "persisted_adjacency_nodes"),
            denominator
        );
        assert_eq!(
            number(measurement, "persisted_adjacency_edges"),
            denominator
        );
        assert_eq!(
            number(measurement, "persisted_adjacency_records"),
            denominator * 2
        );
        assert_eq!(number(measurement, "query_sample_count"), 20);
        assert_eq!(number(measurement, "structural_sample_count"), 20);
        assert_eq!(number(measurement, "cache_hit_delta"), 39);
        assert_eq!(number(measurement, "cache_miss_delta"), 1);
        assert_eq!(
            number(measurement, "cache_full_manifest_validation_delta"),
            1
        );
        assert_eq!(number(measurement, "cache_routing_index_build_delta"), 0);
        assert_eq!(
            number(measurement, "ordinary_query_full_graph_read_count"),
            0
        );
        assert_eq!(number(measurement, "database_read_count"), 0);
        assert_eq!(number(measurement, "network_call_count"), 0);
        assert_eq!(number(measurement, "daemon_call_count"), 0);
        assert!(measurement.get("graph_search_warm_p50_ms").is_some());
        assert!(measurement.get("graph_search_warm_p95_ms").is_some());
        assert!(measurement.get("structural_warm_p50_ms").is_some());
        assert!(measurement.get("structural_warm_p95_ms").is_some());
        assert!(measurement.get("graph_search_p50_ms").is_none());
        assert!(measurement.get("structural_query_p50_ms").is_none());

        let sampled_pairs = measurement["sampled_node_direction_pairs"]
            .as_array()
            .unwrap();
        assert_eq!(sampled_pairs.len(), 20);
        let exact_pairs = sampled_pairs
            .iter()
            .map(|pair| {
                (
                    string(pair, "node_id").to_owned(),
                    string(pair, "direction").to_owned(),
                )
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(exact_pairs.len(), 20);
        let directions = exact_pairs
            .iter()
            .map(|(_, direction)| direction.as_str())
            .collect::<BTreeSet<_>>();
        assert_eq!(directions, BTreeSet::from(["incoming", "outgoing"]));

        let expected_gate = if denominator == 1_000 {
            "denominator_security_smoke_only"
        } else {
            "reference_10k_gate"
        };
        assert_eq!(string(measurement, "gate_applicability"), expected_gate);
        if denominator >= 10_000 {
            assert!(measurement["gate_failures"].as_array().unwrap().is_empty());
        }
    }

    println!("Q05_STRUCTURAL_SCALE_METRICS_JSON={report}");
}
