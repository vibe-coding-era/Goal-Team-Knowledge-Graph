use std::collections::BTreeMap;

use gtkg_core::v03::adapter::verify_external_fact_bundle_v1;
use gtkg_protocol::v03::AdapterKindV1;
use gtkg_protocol::v03::adapter::{
    AdapterDescriptorV1, CandidateFactStateV1, ExternalEdgeFactV1, ExternalEvidenceV1,
    ExternalFactBundleV1, ExternalFactOmissionV1, ExternalNodeFactV1, FactTrustStateV1,
    VerifiedFactReceiptV1, VerifiedResolutionV1,
};
use sha2::{Digest, Sha256};

const SOURCE_PATH: &str = "src/lib.rs";
const SOURCE_SNAPSHOT_SHA256: &str =
    "sha256:1111111111111111111111111111111111111111111111111111111111111111";
const ADAPTER_SCHEMA_SHA256: &str =
    "sha256:2222222222222222222222222222222222222222222222222222222222222222";
const SOURCE_COMMIT: &str = "3333333333333333333333333333333333333333";
const SOURCE_BYTES: &[u8] = b"mod api;\nfn call() { api::run(); }\n";

fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn span_for(bytes: &[u8], needle: &[u8]) -> (u64, u64) {
    let start = bytes
        .windows(needle.len())
        .position(|window| window == needle)
        .expect("test needle must exist");
    (start as u64, (start + needle.len()) as u64)
}

fn descriptor(kind: AdapterKindV1) -> AdapterDescriptorV1 {
    AdapterDescriptorV1 {
        schema_version: "gtkg.adapter-descriptor/v1".to_owned(),
        adapter_id: format!("gtkg.adapter.{}", kind.as_str()),
        kind,
        adapter_version: "0.20.1".to_owned(),
        schema_sha256: ADAPTER_SCHEMA_SHA256.to_owned(),
        source_commit: SOURCE_COMMIT.to_owned(),
        license: "Apache-2.0".to_owned(),
        capabilities: vec!["edges".to_owned(), "nodes".to_owned()],
        trust_policy_id: "gtkg.adapter-trust/v1".to_owned(),
        descriptor_sha256: String::new(),
    }
    .with_computed_digest()
    .expect("pinned descriptor must seal")
}

fn evidence(
    evidence_id: &str,
    needle: &[u8],
    observed_trust: FactTrustStateV1,
) -> ExternalEvidenceV1 {
    let (byte_start, byte_end) = span_for(SOURCE_BYTES, needle);
    ExternalEvidenceV1 {
        evidence_id: evidence_id.to_owned(),
        source_snapshot_sha256: SOURCE_SNAPSHOT_SHA256.to_owned(),
        source_logical_path: SOURCE_PATH.to_owned(),
        source_bytes_sha256: sha256(SOURCE_BYTES),
        byte_start,
        byte_end,
        snippet_sha256: sha256(needle),
        observed_trust,
    }
}

fn bundle(descriptor: &AdapterDescriptorV1) -> ExternalFactBundleV1 {
    ExternalFactBundleV1 {
        schema_version: "gtkg.external-fact-bundle/v1".to_owned(),
        source_snapshot_sha256: SOURCE_SNAPSHOT_SHA256.to_owned(),
        adapter_descriptor_sha256: descriptor.descriptor_sha256.clone(),
        nodes: vec![ExternalNodeFactV1 {
            fact_id: "fact-node-api".to_owned(),
            node_id: "node-api".to_owned(),
            node_kind: "module".to_owned(),
            name: "api".to_owned(),
            candidate_state: CandidateFactStateV1::CandidateExternal,
            trust_state: FactTrustStateV1::Extracted,
            evidence_ids: vec!["evidence-node-api".to_owned()],
        }],
        edges: vec![ExternalEdgeFactV1 {
            fact_id: "fact-edge-call".to_owned(),
            edge_id: "edge-call-api-run".to_owned(),
            edge_kind: "calls".to_owned(),
            source_node_id: "node-call".to_owned(),
            target_reference: "api::run".to_owned(),
            candidate_node_ids: vec!["node-api-run".to_owned(), "node-api-run-alt".to_owned()],
            candidate_state: CandidateFactStateV1::Ambiguous,
            trust_state: FactTrustStateV1::Inferred,
            evidence_ids: vec!["evidence-edge-call".to_owned()],
        }],
        evidence: vec![
            evidence(
                "evidence-edge-call",
                b"api::run()",
                FactTrustStateV1::Inferred,
            ),
            evidence("evidence-node-api", b"mod api", FactTrustStateV1::Extracted),
        ],
        candidate_states: vec![
            CandidateFactStateV1::CandidateExternal,
            CandidateFactStateV1::Ambiguous,
        ],
        discovered_count: 3,
        admitted_count: 2,
        omitted_count: 1,
        omissions: vec![ExternalFactOmissionV1 {
            omitted_id: "fact-unsupported-macro".to_owned(),
            reason: "unsupported_syntax".to_owned(),
        }],
        bundle_sha256: String::new(),
    }
    .with_computed_digest()
    .expect("closed external bundle must seal")
}

fn source_files(bytes: &[u8]) -> BTreeMap<String, Vec<u8>> {
    BTreeMap::from([(SOURCE_PATH.to_owned(), bytes.to_vec())])
}

#[test]
fn a00_freezes_five_adapter_kinds_and_non_canonical_candidate_states() {
    assert_eq!(
        AdapterKindV1::ALL.map(AdapterKindV1::as_str),
        [
            "native",
            "scip",
            "lsp_snapshot",
            "codegraph_export",
            "graphify_export",
        ]
    );
    assert_eq!(
        CandidateFactStateV1::ALL.map(CandidateFactStateV1::as_str),
        ["candidate_external", "ambiguous", "locator_only"]
    );
    assert_eq!(
        FactTrustStateV1::ALL.map(FactTrustStateV1::as_str),
        ["unverified", "ambiguous", "inferred", "extracted"]
    );

    let mut unknown_kind = serde_json::to_value(descriptor(AdapterKindV1::Scip)).unwrap();
    unknown_kind["kind"] = serde_json::json!("floating_unknown");
    assert!(serde_json::from_value::<AdapterDescriptorV1>(unknown_kind).is_err());

    let valid = bundle(&descriptor(AdapterKindV1::Scip));
    let mut injected_resolved = serde_json::to_value(valid).unwrap();
    injected_resolved["nodes"][0]["candidate_state"] = serde_json::json!("resolved_verified");
    assert!(serde_json::from_value::<ExternalFactBundleV1>(injected_resolved).is_err());
}

#[test]
fn a00_descriptor_is_digest_bound_and_rejects_floating_or_license_drift() {
    let expected = descriptor(AdapterKindV1::CodeGraphExport);
    expected
        .validate()
        .expect("sealed descriptor must validate");

    let mut floating = expected.clone();
    floating.adapter_version = "latest".to_owned();
    assert_eq!(
        floating.with_computed_digest().unwrap_err().code(),
        "E_ADAPTER_IDENTITY_MISMATCH"
    );

    let mut unknown_license = expected.clone();
    unknown_license.license = "unknown".to_owned();
    assert_eq!(
        unknown_license.with_computed_digest().unwrap_err().code(),
        "E_ADAPTER_IDENTITY_MISMATCH"
    );

    let mut tampered = expected.clone();
    tampered.license = "MIT".to_owned();
    let error = verify_external_fact_bundle_v1(
        &expected,
        &tampered,
        &bundle(&expected),
        &source_files(SOURCE_BYTES),
        "gtkg.verifier/a00",
    )
    .unwrap_err();
    assert_eq!(error.code(), "E_ADAPTER_IDENTITY_MISMATCH");

    let drifted = tampered
        .with_computed_digest()
        .expect("different pinned descriptor remains structurally valid");
    let error = verify_external_fact_bundle_v1(
        &expected,
        &drifted,
        &bundle(&expected),
        &source_files(SOURCE_BYTES),
        "gtkg.verifier/a00",
    )
    .unwrap_err();
    assert_eq!(error.code(), "E_ADAPTER_IDENTITY_MISMATCH");

    let mut schema_drift = expected.clone();
    schema_drift.schema_sha256 = sha256(b"changed adapter schema");
    let schema_drift = schema_drift.with_computed_digest().unwrap();
    let error = verify_external_fact_bundle_v1(
        &expected,
        &schema_drift,
        &bundle(&expected),
        &source_files(SOURCE_BYTES),
        "gtkg.verifier/a00",
    )
    .unwrap_err();
    assert_eq!(error.code(), "E_ADAPTER_IDENTITY_MISMATCH");
}

#[test]
fn a00_bundle_digest_denominator_and_stable_ids_fail_closed() {
    let descriptor = descriptor(AdapterKindV1::GraphifyExport);
    let valid = bundle(&descriptor);
    valid.validate().expect("sealed bundle must validate");
    assert_eq!(
        valid.discovered_count,
        valid.admitted_count + valid.omitted_count
    );

    let mut invalid_denominator = valid.clone();
    invalid_denominator.discovered_count += 1;
    assert_eq!(
        invalid_denominator
            .with_computed_digest()
            .unwrap_err()
            .code(),
        "E_ADAPTER_DENOMINATOR_INVALID"
    );

    let mut duplicate_id = valid.clone();
    duplicate_id.edges[0].fact_id = duplicate_id.nodes[0].fact_id.clone();
    assert_eq!(
        duplicate_id.with_computed_digest().unwrap_err().code(),
        "E_ADAPTER_BUNDLE_INVALID"
    );

    let mut tampered = valid.clone();
    tampered.nodes[0].name = "tampered".to_owned();
    let error = verify_external_fact_bundle_v1(
        &descriptor,
        &descriptor,
        &tampered,
        &source_files(SOURCE_BYTES),
        "gtkg.verifier/a00",
    )
    .unwrap_err();
    assert_eq!(error.code(), "E_ADAPTER_IDENTITY_MISMATCH");
}

#[test]
fn a00_exact_source_replay_is_the_only_path_to_resolved_verified() {
    let descriptor = descriptor(AdapterKindV1::Native);
    let bundle = bundle(&descriptor);
    let verified = verify_external_fact_bundle_v1(
        &descriptor,
        &descriptor,
        &bundle,
        &source_files(SOURCE_BYTES),
        "gtkg.verifier/a00",
    )
    .expect("exact bytes and pinned identities must verify");

    assert_eq!(verified.resolved_verified_fact_ids, ["fact-node-api"]);
    assert_eq!(verified.false_confirmed, 0);
    assert_eq!(verified.canonical_write_count, 0);
    assert_eq!(verified.receipts.len(), 2);

    let receipts = verified
        .receipts
        .iter()
        .map(|receipt| (receipt.fact_id.as_str(), receipt))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(
        receipts["fact-node-api"].resolution,
        VerifiedResolutionV1::ResolvedVerified
    );
    assert_eq!(
        receipts["fact-edge-call"].resolution,
        VerifiedResolutionV1::Ambiguous
    );
    assert!(
        verified
            .receipts
            .iter()
            .all(|receipt| receipt.validate().is_ok())
    );

    let mut receipt_tamper: VerifiedFactReceiptV1 = receipts["fact-node-api"].clone();
    receipt_tamper.reason = "self_reported_resolved".to_owned();
    assert!(receipt_tamper.validate().is_err());
}

#[test]
fn a00_changed_source_or_missing_span_never_false_confirms() {
    let descriptor = descriptor(AdapterKindV1::LspSnapshot);
    let bundle = bundle(&descriptor);
    let changed = b"mod api;\nfn call() { other::run(); }\n";
    let changed_result = verify_external_fact_bundle_v1(
        &descriptor,
        &descriptor,
        &bundle,
        &source_files(changed),
        "gtkg.verifier/a00",
    )
    .expect("source drift is a typed non-confirming verification outcome");
    let changed_node = changed_result
        .receipts
        .iter()
        .find(|receipt| receipt.fact_id == "fact-node-api")
        .unwrap();
    assert_eq!(changed_node.resolution, VerifiedResolutionV1::LocatorOnly);
    assert_eq!(changed_node.reason, "source_bytes_digest_mismatch");
    assert!(changed_result.resolved_verified_fact_ids.is_empty());
    assert_eq!(changed_result.false_confirmed, 0);

    let mut missing_span = bundle;
    missing_span.nodes[0].evidence_ids.clear();
    let missing_span = missing_span.with_computed_digest().unwrap();
    let missing_result = verify_external_fact_bundle_v1(
        &descriptor,
        &descriptor,
        &missing_span,
        &source_files(SOURCE_BYTES),
        "gtkg.verifier/a00",
    )
    .expect("missing evidence is preserved as a non-confirming outcome");
    let missing_node = missing_result
        .receipts
        .iter()
        .find(|receipt| receipt.fact_id == "fact-node-api")
        .unwrap();
    assert_eq!(missing_node.resolution, VerifiedResolutionV1::LocatorOnly);
    assert_eq!(missing_node.reason, "missing_evidence");
    assert!(missing_result.resolved_verified_fact_ids.is_empty());
    assert_eq!(missing_result.false_confirmed, 0);
}

#[test]
fn a00_inferred_as_extracted_is_rejected_as_trust_laundering() {
    let descriptor = descriptor(AdapterKindV1::Scip);
    let mut laundering = bundle(&descriptor);
    let node_evidence = laundering
        .evidence
        .iter_mut()
        .find(|evidence| evidence.evidence_id == "evidence-node-api")
        .unwrap();
    node_evidence.observed_trust = FactTrustStateV1::Inferred;
    let laundering = laundering.with_computed_digest().unwrap();

    let error = verify_external_fact_bundle_v1(
        &descriptor,
        &descriptor,
        &laundering,
        &source_files(SOURCE_BYTES),
        "gtkg.verifier/a00",
    )
    .unwrap_err();
    assert_eq!(error.code(), "E_TRUST_LAUNDERING");
}
