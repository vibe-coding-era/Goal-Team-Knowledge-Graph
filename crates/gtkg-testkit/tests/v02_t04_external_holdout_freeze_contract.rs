//! T04 external-holdout preparation: freeze public-source metadata and split
//! boundaries without executing source bytes or manufacturing annotation gold.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;
use sha2::{Digest, Sha256};

const MANIFEST: &str =
    include_str!("../../../deliverables/v02-t04/frozen-holdout-case-manifest.json");
const PACKET: &str =
    include_str!("../../../deliverables/v02-t04/annotation-adjudication-packet.md");
const CANDIDATES: &str =
    include_str!("../../../deliverables/v02-t04/candidate-external-repositories.json");

fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root")
}

fn object(value: &Value) -> &serde_json::Map<String, Value> {
    value.as_object().expect("JSON object")
}

fn object_mut(value: &mut Value) -> &mut serde_json::Map<String, Value> {
    value.as_object_mut().expect("JSON object")
}

fn string<'a>(object: &'a serde_json::Map<String, Value>, field: &str) -> &'a str {
    object
        .get(field)
        .and_then(Value::as_str)
        .expect("required string field")
}

#[test]
fn frozen_external_case_manifest_binds_public_source_bytes_and_packet_without_gold() {
    let manifest: Value = serde_json::from_str(MANIFEST).expect("manifest JSON");
    let candidates: Value = serde_json::from_str(CANDIDATES).expect("candidate registry JSON");
    let root = repo_root();
    let manifest_object = object(&manifest);
    let candidate_entries = candidates
        .get("candidates")
        .and_then(Value::as_array)
        .expect("candidate entries");
    let candidate_by_repository: BTreeMap<&str, &serde_json::Map<String, Value>> =
        candidate_entries
            .iter()
            .map(object)
            .map(|candidate| (string(candidate, "repository"), candidate))
            .collect();
    let checkout_entries = candidates
        .get("materialized_checkouts")
        .and_then(Value::as_array)
        .expect("materialized checkout entries");
    let checkout_by_candidate: BTreeMap<&str, &serde_json::Map<String, Value>> = checkout_entries
        .iter()
        .map(object)
        .map(|checkout| (string(checkout, "candidate"), checkout))
        .collect();

    assert_eq!(
        string(manifest_object, "schema_version"),
        "gtkg.external-holdout-case-manifest/v1"
    );
    assert_eq!(
        string(manifest_object, "status"),
        "candidate_only_not_annotation_locked"
    );
    assert_eq!(string(manifest_object, "readiness"), "blocked");
    assert!(manifest.get("gold").is_none());

    let binding = object(
        manifest_object
            .get("annotation_binding")
            .expect("annotation binding"),
    );
    assert_eq!(
        string(binding, "packet_path"),
        "deliverables/v02-t04/annotation-adjudication-packet.md"
    );
    assert_eq!(string(binding, "gold_label_state"), "absent");
    assert_eq!(string(binding, "annotation_state"), "planned_not_run");
    assert_eq!(string(binding, "packet_sha256"), sha256(PACKET.as_bytes()));

    let mut payload = manifest.clone();
    object_mut(&mut payload).remove("manifest_sha256");
    assert_eq!(
        string(manifest_object, "manifest_sha256"),
        sha256(&serde_json::to_vec(&payload).expect("canonical JSON"))
    );

    let cases = manifest_object
        .get("cases")
        .and_then(Value::as_array)
        .expect("case list");
    assert_eq!(cases.len(), 8);

    let mut case_ids = BTreeSet::new();
    let mut language_counts = BTreeMap::new();
    let mut split_digests: BTreeMap<&str, BTreeSet<String>> = BTreeMap::new();
    for case in cases {
        let case = object(case);
        assert!(case_ids.insert(string(case, "case_id")));
        assert!(!string(case, "category").is_empty());
        assert!(!string(case, "license").is_empty());
        assert_eq!(string(case, "candidate_status"), "candidate_only");
        let candidate = candidate_by_repository
            .get(string(case, "repository"))
            .expect("case repository must be in the candidate registry");
        assert_eq!(string(case, "commit"), string(candidate, "commit"));
        assert_eq!(string(case, "license"), string(candidate, "license"));
        let checkout = checkout_by_candidate
            .get(string(case, "candidate_id"))
            .expect("case must bind one materialized candidate checkout");
        assert_eq!(string(case, "tree"), string(checkout, "tree"));
        *language_counts
            .entry(string(case, "language"))
            .or_insert(0usize) += 1;

        let source_path = string(case, "source_path");
        assert!(source_path.starts_with("docs/reference/v02-external-corpus-candidates/"));
        assert!(!source_path.contains(".."));
        let source = fs::read(root.join(Path::new(source_path))).expect("frozen source file");
        let source_digest = sha256(&source);
        assert_eq!(string(case, "source_sha256"), source_digest);
        split_digests
            .entry(string(case, "split"))
            .or_default()
            .insert(source_digest);
    }
    assert_eq!(
        language_counts,
        BTreeMap::from([
            ("JavaScript", 2),
            ("Python", 2),
            ("Rust", 2),
            ("TypeScript", 2)
        ])
    );
    assert!(
        split_digests
            .get("calibration")
            .is_some_and(|items| !items.is_empty())
    );
    assert!(
        split_digests
            .get("evaluation")
            .is_some_and(|items| !items.is_empty())
    );
    assert!(
        split_digests
            .get("holdout")
            .is_some_and(|items| !items.is_empty())
    );
    assert!(split_digests["calibration"].is_disjoint(&split_digests["evaluation"]));
    assert!(split_digests["calibration"].is_disjoint(&split_digests["holdout"]));
    assert!(split_digests["evaluation"].is_disjoint(&split_digests["holdout"]));
}
