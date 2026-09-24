use serde_json::json;

#[path = "support/v03_q05_fixture.rs"]
mod fixture_generator;
#[path = "support/v03_q05_scale_runner.rs"]
mod scale_runner;

use fixture_generator::SCALE_SPECS;
use scale_runner::observe_scale;

#[test]
fn q05_reference_scale_budget_and_cache_work_are_current_without_1k_overclaim() {
    let mut observations = Vec::new();
    let mut failures = Vec::new();
    for spec in SCALE_SPECS {
        match observe_scale(spec) {
            Ok(observation) => {
                if observation["gate_failures"]
                    .as_array()
                    .is_some_and(|values| !values.is_empty())
                {
                    failures.push(format!(
                        "denominator={} gate_failures={}",
                        spec.document_count, observation["gate_failures"]
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
        "Q05_SUCCESSOR_METRICS_JSON={}",
        json!({
            "schema_version": "gtkg.q05-reference-scale-observations/v2",
            "scale_denominator": [1_000, 10_000, 10_001],
            "reference_budget_source": "deliverables/v03-benchmark/reference-environment.json",
            "performance_gate_denominator": [10_000, 10_001],
            "denominator_security_smoke": [1_000],
            "measurements": observations,
            "rss_measurement": "external_harness_required",
            "incremental_update_p95": "blocked_by_q06",
            "install_to_first_query_p95": "blocked_by_u06",
            "explorer_first_meaningful_content_p95": "blocked_by_u03",
        })
    );
    assert!(failures.is_empty(), "{}", failures.join("; "));
}
