//! Immutable B01 local environment and external-artifact gate.
//!
//! This case deliberately distinguishes a source pin from a runnable benchmark
//! environment.  It is allowed to observe the local GTKG development binary,
//! but cannot manufacture a CodeGraph or Graphify runtime from a URL, a mock,
//! or an unverified local substitute.

use serde_json::{Map, Value};
use std::fs;
use std::path::{Path, PathBuf};

const RECEIPT: &str = "deliverables/v03-benchmark/receipts/b01-environment-preflight-r1.json";
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

fn string<'a>(value: &'a Value, key: &str) -> &'a str {
    object(value)[key]
        .as_str()
        .unwrap_or_else(|| panic!("{key} string"))
}

fn system<'a>(receipt: &'a Value, system_id: &str) -> &'a Value {
    object(receipt)["systems"]
        .as_array()
        .expect("systems array")
        .iter()
        .find(|candidate| string(candidate, "system_id") == system_id)
        .unwrap_or_else(|| panic!("{system_id} system"))
}

fn pinned_commit<'a>(pins: &'a Value, system_id: &str) -> &'a str {
    object(pins)["competitors"]
        .as_array()
        .expect("competitors array")
        .iter()
        .find(|candidate| string(candidate, "system_id") == system_id)
        .map(|candidate| string(candidate, "commit"))
        .unwrap_or_else(|| panic!("{system_id} pin"))
}

#[test]
fn b01_gtkg_candidate_is_os_sandboxed_without_install_or_telemetry_promotion() {
    let receipt = load(RECEIPT);
    assert_eq!(
        string(&receipt, "schema_version"),
        "gtkg.benchmark-environment-preflight/v1"
    );
    assert_eq!(string(&receipt, "task_id"), "B01");
    assert_eq!(string(&receipt, "run_role"), "red");
    assert_eq!(
        string(&receipt, "state"),
        "blocked_external_competitor_artifacts"
    );

    let gtkg = system(&receipt, "gtkg-v0.3-development");
    assert_eq!(
        string(gtkg, "isolated_environment_state"),
        "observed_os_sandboxed_candidate"
    );
    assert_eq!(
        string(gtkg, "package_install_state"),
        "not_available_no_cli_package_install_surface"
    );
    assert_eq!(
        object(gtkg)["process"]["exit_code"].as_i64(),
        Some(0),
        "the observed candidate process must complete under the offline policy"
    );
    assert_eq!(
        string(&object(gtkg)["offline_lock"], "policy_load_state"),
        "passed"
    );
    assert_eq!(
        string(&object(gtkg)["offline_lock"], "network_probe_state"),
        "not_run_no_synthetic_endpoint_in_scope"
    );
    assert_eq!(string(&object(gtkg)["telemetry"], "state"), "not_readback");
}

#[test]
fn b01_preserves_source_pins_as_non_execution_evidence() {
    let receipt = load(RECEIPT);
    let pins = load(PINS);

    for system_id in ["codegraph-v0.20.1", "graphify-v0.9.52"] {
        let external = system(&receipt, system_id);
        assert_eq!(
            string(external, "source_commit"),
            pinned_commit(&pins, system_id),
            "receipt must bind its blocker to the B00 source pin"
        );
        assert_eq!(
            string(external, "package_install_state"),
            "not_run_prohibited_by_b01_scope"
        );
        assert_eq!(string(external, "telemetry_readback_state"), "not_run");
    }
}

#[test]
fn b01_requires_materialized_verified_competitor_runtimes_before_benchmark_execution() {
    let receipt = load(RECEIPT);
    for system_id in ["codegraph-v0.20.1", "graphify-v0.9.52"] {
        assert_eq!(
            string(system(&receipt, system_id), "exact_artifact_state"),
            "materialized_with_verified_runtime_identity",
            "{system_id} must have a locally readable exact artifact and runtime identity; a B00 source pin is insufficient"
        );
    }
}
