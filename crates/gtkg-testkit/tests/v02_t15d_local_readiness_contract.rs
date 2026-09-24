//! T15D r2 local readiness: contracts for a bounded, non-certifying
//! security/browser/scale preparation harness.

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root")
}

fn json(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).expect("fixture bytes")).expect("valid JSON")
}

#[test]
fn t15d_local_plan_is_explicitly_non_certifying_and_binds_its_real_consumers() {
    let plan = json(&root().join("deliverables/v02-t15d/local-readiness-plan.json"));
    assert_eq!(plan["schema_version"], "gtkg.t15d-local-readiness-plan/v1");
    assert_eq!(plan["status"], "ready_for_local_dry_run");
    assert_eq!(plan["measurement_status"], "not_run");
    assert_eq!(plan["axis_disposition"], "local_preparation_only");
    assert_eq!(plan["claims"]["scale_1k"], "not_run");
    assert_eq!(plan["claims"]["scale_10k"], "not_run");
    assert_eq!(plan["claims"]["scale_10001"], "not_run");
    assert_eq!(plan["claims"]["os_security"], "not_run");
    assert_eq!(plan["claims"]["browser"], "local_loopback_only");
    assert_eq!(plan["consumers"]["runtime"], "T14A");
    assert_eq!(plan["consumers"]["browser"], "T14B");
    assert_eq!(plan["workload"]["warmups"], 5);
    assert_eq!(plan["workload"]["measured_runs"], 100);
    assert_eq!(plan["workload"]["dry_run_max_runs"], 1);
    assert!(plan["host"]["capture_command"].as_str().is_some());
}

#[test]
fn t15d_harness_requires_t14b_receipt_and_preserves_non_claiming_receipt_fields() {
    let harness =
        fs::read_to_string(root().join("crates/gtkg-testkit/browser/v02_t15d_local_readiness.sh"))
            .expect("T15D harness");
    for required in [
        "v02_t14b_local_wiki_e2e.sh",
        "local-browser-evidence.json",
        "local_preparation_only",
        "measurement_status",
        "scale_1k",
        "scale_10k",
        "scale_10001",
        "os_security",
        "not_run",
        "dry-run",
    ] {
        assert!(
            harness.contains(required),
            "missing T15D boundary: {required}"
        );
    }
    for forbidden in [
        "AX-SCALE-SEC Green",
        "OS security pass",
        "1k passed",
        "10k passed",
        "10,001 passed",
    ] {
        assert!(
            !harness.contains(forbidden),
            "T15D local harness overclaims: {forbidden}"
        );
    }
}
