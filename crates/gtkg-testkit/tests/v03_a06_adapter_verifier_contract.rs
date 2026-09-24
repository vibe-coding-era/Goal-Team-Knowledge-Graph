use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use gtkg_core::v03::adapter::codegraph::{
    CODEGRAPH_EXPORT_SCHEMA_SHA256_V1, CODEGRAPH_PINNED_COMMIT_V1, CODEGRAPH_PINNED_LICENSE_V1,
    CODEGRAPH_PINNED_VERSION_V1, CodeGraphExportPinV1, CodeGraphImportV1,
    import_pinned_codegraph_json_file_v1,
};
use gtkg_core::v03::adapter::graphify::{
    GRAPHIFY_CANONICAL_SCHEMA_SHA256_V2, GRAPHIFY_EXPORT_PY_SHA256_V2,
    GRAPHIFY_EXTRACTION_SPEC_SHA256_V2, GRAPHIFY_LICENSE_SHA256_V2, GRAPHIFY_PINNED_COMMIT_V1,
    GRAPHIFY_PINNED_LICENSE_V1, GRAPHIFY_PINNED_VERSION_V1, GRAPHIFY_PYPROJECT_SHA256_V2,
    GRAPHIFY_VALIDATE_PY_SHA256_V2, GraphifyGraphPinV2, GraphifyImportReceiptV2, GraphifyImportV2,
    import_pinned_graphify_json_file_v2,
};
use gtkg_core::v03::adapter::lsp_snapshot::{
    LspSnapshotFilePinV1, LspSnapshotImportReceiptV1, LspSnapshotImportV1,
    import_pinned_lsp_snapshot_json_file_v1,
};
use gtkg_core::v03::adapter::native::{NativeAdapterOutputV1, adapt_native_path_v1};
use gtkg_core::v03::adapter::scip::{ScipFilePinV1, ScipImportV1, import_pinned_scip_json_file_v1};
use gtkg_core::v03::adapter::verifier::{
    AdapterCollisionKindV1, AdapterFactExpectationV1, AdapterFactIdentityV1, AdapterReceiptRefV1,
    AdapterSemanticOracleV1, AdapterSubmissionV1, MAX_ADAPTER_INPUT_BYTES_V1,
    detect_adapter_collisions_v1, verify_adapter_gate_v1,
};
use gtkg_protocol::canonical_json_sha256;
use gtkg_protocol::v2::{
    SourceBaselineIdentityV2, SourceCaptureModeV2, SourceEligibilityV2,
    SourceSnapshotDenominatorV2, SourceSnapshotEntryV2, SourceSnapshotV2,
};
use gtkg_protocol::v03::AdapterKindV1;
use gtkg_protocol::v03::adapter::FactTrustStateV1;
use serde_json::Value;
use sha2::{Digest, Sha256};

const NATIVE_SOURCE: &str = include_str!("../fixtures/v03_a01/ledger.rs");
const SCIP_FILE_SHA256: &str =
    "sha256:6c1aa34317015297620f517829cbbe1105765f28897a2f3f87c5a622d5672fce";
const SCIP_SOURCE_SNAPSHOT_SHA256: &str =
    "sha256:7a516a066420d92c5b10da8f76f5e8eccf1dd1250d425879dab88f3af4654a20";
const LSP_FILE_SHA256: &str =
    "sha256:34f19599535a24ad43b2c8da9fc74a0df76d36885a7fdb7f8e79cc25839f3841";
const LSP_SOURCE_SNAPSHOT_SHA256: &str =
    "sha256:c45839fdd713b1acb620523e6c9d80ac07fc271113cfad5eb76ef328045e6ddc";
const CODEGRAPH_FILE_SHA256: &str =
    "sha256:66b2bc48661dc6348c2930afc8e368c71a5dd5bdfb580c911c726d4fed70842b";
const GRAPHIFY_FILE_SHA256: &str =
    "sha256:0e2e258daef9182ca2573c561bad47958a56f08a5e5b853ce71bcf9508e4edf0";

fn fixture(path: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(path)
}

fn file_size(path: &Path) -> u64 {
    fs::metadata(path).unwrap().len()
}

fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn native_snapshot() -> SourceSnapshotV2 {
    SourceSnapshotV2 {
        schema_version: "gtkg.source-snapshot/v2".to_owned(),
        capture_mode: SourceCaptureModeV2::DirectoryExact,
        repository_id: "v03-a06-native".to_owned(),
        baseline: SourceBaselineIdentityV2 {
            kind: "directory".to_owned(),
            head: None,
            tree: None,
            status_sha256: sha256(b"v03-a06-native-status"),
        },
        denominator: SourceSnapshotDenominatorV2 {
            discovered_entries: 1,
            admitted_entries: 1,
            omitted_entries: 0,
        },
        inventory: vec![SourceSnapshotEntryV2 {
            logical_path: "ledger.rs".to_owned(),
            content_sha256: sha256(NATIVE_SOURCE.as_bytes()),
            bytes: NATIVE_SOURCE.len() as u64,
        }],
        omissions: Vec::new(),
        exact_set_sha256: String::new(),
        eligibility: SourceEligibilityV2 {
            development_eligible: true,
            source_release_candidate: false,
            environment_ready: false,
            release_ready: false,
        },
    }
    .with_exact_set_digest()
    .unwrap()
}

fn scip_pin() -> ScipFilePinV1 {
    ScipFilePinV1 {
        file_sha256: SCIP_FILE_SHA256.to_owned(),
        schema_version: "scip/0.4-json".to_owned(),
        schema_sha256: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            .to_owned(),
        tool_name: "scip-rust".to_owned(),
        tool_version: "0.3.3".to_owned(),
        tool_commit: "0123456789abcdef0123456789abcdef01234567".to_owned(),
        tool_license: "Apache-2.0".to_owned(),
        source_snapshot_sha256: SCIP_SOURCE_SNAPSHOT_SHA256.to_owned(),
        max_file_bytes: 64 * 1024,
    }
}

fn lsp_pin() -> LspSnapshotFilePinV1 {
    LspSnapshotFilePinV1 {
        file_sha256: LSP_FILE_SHA256.to_owned(),
        schema_version: "gtkg.lsp-snapshot/v1".to_owned(),
        schema_sha256: "sha256:97a36add17cb89ec94b92222e8c4b1673dbb5bd5443644f1f346140ad4dd19c1"
            .to_owned(),
        protocol_version: "3.17".to_owned(),
        position_encoding: "utf-8".to_owned(),
        producer_name: "rust-analyzer".to_owned(),
        producer_version: "2026-08-24".to_owned(),
        producer_commit: "0123456789abcdef0123456789abcdef01234567".to_owned(),
        producer_license: "MIT OR Apache-2.0".to_owned(),
        producer_config_sha256:
            "sha256:9569022226845a35bce92d52c125556785d8a1d67f6e78b900bb3dc02bac9228".to_owned(),
        source_snapshot_sha256: LSP_SOURCE_SNAPSHOT_SHA256.to_owned(),
        max_file_bytes: 64 * 1024,
    }
}

fn codegraph_pin() -> CodeGraphExportPinV1 {
    CodeGraphExportPinV1 {
        file_sha256: CODEGRAPH_FILE_SHA256.to_owned(),
        schema_sha256: CODEGRAPH_EXPORT_SCHEMA_SHA256_V1.to_owned(),
        tool_version: CODEGRAPH_PINNED_VERSION_V1.to_owned(),
        tool_commit: CODEGRAPH_PINNED_COMMIT_V1.to_owned(),
        tool_license: CODEGRAPH_PINNED_LICENSE_V1.to_owned(),
        source_snapshot_sha256:
            "sha256:7777777777777777777777777777777777777777777777777777777777777777".to_owned(),
        max_file_bytes: 64 * 1024,
    }
}

fn graphify_pin() -> GraphifyGraphPinV2 {
    GraphifyGraphPinV2 {
        file_sha256: GRAPHIFY_FILE_SHA256.to_owned(),
        canonical_schema_sha256: GRAPHIFY_CANONICAL_SCHEMA_SHA256_V2.to_owned(),
        tool_version: GRAPHIFY_PINNED_VERSION_V1.to_owned(),
        tool_commit: GRAPHIFY_PINNED_COMMIT_V1.to_owned(),
        tool_license: GRAPHIFY_PINNED_LICENSE_V1.to_owned(),
        export_py_sha256: GRAPHIFY_EXPORT_PY_SHA256_V2.to_owned(),
        validate_py_sha256: GRAPHIFY_VALIDATE_PY_SHA256_V2.to_owned(),
        pyproject_sha256: GRAPHIFY_PYPROJECT_SHA256_V2.to_owned(),
        license_sha256: GRAPHIFY_LICENSE_SHA256_V2.to_owned(),
        extraction_spec_sha256: GRAPHIFY_EXTRACTION_SPEC_SHA256_V2.to_owned(),
        source_snapshot_sha256:
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned(),
        source_repository_commit: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
        max_file_bytes: 64 * 1024,
        max_node_count: 64,
        max_link_count: 64,
        max_hyperedge_count: 16,
    }
}

struct FiveImports {
    native: NativeAdapterOutputV1,
    native_sources: BTreeMap<String, Vec<u8>>,
    scip: ScipImportV1,
    lsp: LspSnapshotImportV1,
    codegraph: CodeGraphImportV1,
    graphify: GraphifyImportV2,
}

impl FiveImports {
    fn load() -> Self {
        let native_path = fixture("fixtures/v03_a01/ledger.rs");
        let native = adapt_native_path_v1(&native_snapshot(), "ledger.rs", &native_path).unwrap();
        let scip_path = fixture("fixtures/v03_a02/valid-scip.json");
        let lsp_path = fixture("fixtures/v03_a03/valid-lsp-snapshot.json");
        let codegraph_path = fixture("fixtures/v03_a04/valid-codegraph.json");
        let graphify_path = fixture("fixtures/v03_a05/strict-graphify-v2.json");
        Self {
            native,
            native_sources: BTreeMap::from([(
                "ledger.rs".to_owned(),
                NATIVE_SOURCE.as_bytes().to_vec(),
            )]),
            scip: import_pinned_scip_json_file_v1(&scip_path, &scip_pin()).unwrap(),
            lsp: import_pinned_lsp_snapshot_json_file_v1(&lsp_path, &lsp_pin()).unwrap(),
            codegraph: import_pinned_codegraph_json_file_v1(&codegraph_path, &codegraph_pin())
                .unwrap(),
            graphify: import_pinned_graphify_json_file_v2(&graphify_path, &graphify_pin()).unwrap(),
        }
    }

    fn submissions(&self) -> Vec<AdapterSubmissionV1<'_>> {
        vec![
            AdapterSubmissionV1 {
                descriptor: &self.native.descriptor,
                bundle: &self.native.bundle,
                source_files: &self.native_sources,
                source_locators: &[],
                receipt: AdapterReceiptRefV1::Native(&self.native.effects),
                input_file_bytes: NATIVE_SOURCE.len() as u64,
                configured_max_file_bytes: 64 * 1024,
            },
            AdapterSubmissionV1 {
                descriptor: &self.scip.descriptor,
                bundle: &self.scip.bundle,
                source_files: &self.scip.source_files,
                source_locators: &[],
                receipt: AdapterReceiptRefV1::Scip(&self.scip.receipt),
                input_file_bytes: file_size(&fixture("fixtures/v03_a02/valid-scip.json")),
                configured_max_file_bytes: scip_pin().max_file_bytes,
            },
            AdapterSubmissionV1 {
                descriptor: &self.lsp.descriptor,
                bundle: &self.lsp.bundle,
                source_files: &self.lsp.source_files,
                source_locators: &[],
                receipt: AdapterReceiptRefV1::Lsp(&self.lsp.receipt),
                input_file_bytes: file_size(&fixture("fixtures/v03_a03/valid-lsp-snapshot.json")),
                configured_max_file_bytes: lsp_pin().max_file_bytes,
            },
            AdapterSubmissionV1 {
                descriptor: &self.codegraph.descriptor,
                bundle: &self.codegraph.bundle,
                source_files: &self.codegraph.source_files,
                source_locators: &[],
                receipt: AdapterReceiptRefV1::CodeGraph(&self.codegraph.receipt),
                input_file_bytes: file_size(&fixture("fixtures/v03_a04/valid-codegraph.json")),
                configured_max_file_bytes: codegraph_pin().max_file_bytes,
            },
            AdapterSubmissionV1 {
                descriptor: &self.graphify.descriptor,
                bundle: &self.graphify.bundle,
                source_files: &self.graphify.source_files,
                source_locators: &self.graphify.source_locators,
                receipt: AdapterReceiptRefV1::GraphifyV2(&self.graphify.receipt),
                input_file_bytes: file_size(&fixture("fixtures/v03_a05/strict-graphify-v2.json")),
                configured_max_file_bytes: graphify_pin().max_file_bytes,
            },
        ]
    }
}

fn oracle(submissions: &[AdapterSubmissionV1<'_>]) -> AdapterSemanticOracleV1 {
    let mut expectations = Vec::new();
    for submission in submissions {
        let names = submission
            .bundle
            .nodes
            .iter()
            .map(|node| (node.node_id.as_str(), node.name.as_str()))
            .collect::<BTreeMap<_, _>>();
        for edge in &submission.bundle.edges {
            let mut accepted_target_references = vec![edge.target_reference.clone()];
            accepted_target_references.extend(
                edge.candidate_node_ids
                    .iter()
                    .filter_map(|node_id| names.get(node_id.as_str()))
                    .map(|name| (*name).to_owned()),
            );
            accepted_target_references.sort();
            accepted_target_references.dedup();
            expectations.push(AdapterFactExpectationV1 {
                adapter_descriptor_sha256: submission.descriptor.descriptor_sha256.clone(),
                fact_id: edge.fact_id.clone(),
                accepted_target_references,
                candidate_node_ids: edge.candidate_node_ids.clone(),
                candidate_state: edge.candidate_state,
                trust_state: edge.trust_state,
            });
        }
    }
    expectations.sort_by(|left, right| {
        (&left.adapter_descriptor_sha256, &left.fact_id)
            .cmp(&(&right.adapter_descriptor_sha256, &right.fact_id))
    });
    AdapterSemanticOracleV1 {
        schema_version: "gtkg.adapter-semantic-oracle/v1".to_owned(),
        expectations,
        oracle_sha256: String::new(),
    }
    .with_computed_digest()
    .unwrap()
}

fn digest_without_receipt(mut encoded: Value) -> String {
    encoded.as_object_mut().unwrap().remove("receipt_sha256");
    canonical_json_sha256(&encoded).unwrap()
}

fn reseal_lsp(receipt: &mut LspSnapshotImportReceiptV1) {
    receipt.receipt_sha256 = digest_without_receipt(serde_json::to_value(&*receipt).unwrap());
}

fn reseal_graphify(receipt: &mut GraphifyImportReceiptV2) {
    receipt.receipt_sha256 = digest_without_receipt(serde_json::to_value(&*receipt).unwrap());
}

#[test]
fn a06_denominator_manifest_binds_five_real_adapter_inputs() {
    let manifest: Value = serde_json::from_slice(
        &fs::read(fixture("fixtures/v03_a06/cross-adapter-denominator.json")).unwrap(),
    )
    .unwrap();
    let inputs = manifest["inputs"].as_array().unwrap();
    assert_eq!(inputs.len(), 5);
    for input in inputs {
        let path = fixture(input["path"].as_str().unwrap());
        assert_eq!(sha256(&fs::read(path).unwrap()), input["sha256"]);
    }
    assert_eq!(manifest["adversarial_cases"].as_array().unwrap().len(), 12);
}

#[test]
fn a06_real_five_adapter_gate_closes_coverage_without_canonical_selection() {
    let imports = FiveImports::load();
    let submissions = imports.submissions();
    let semantic_oracle = oracle(&submissions);
    let first = verify_adapter_gate_v1(&submissions, &semantic_oracle, "gtkg.verifier/a06")
        .expect("five accepted adapters must pass the A06 gate");
    let replay = verify_adapter_gate_v1(&submissions, &semantic_oracle, "gtkg.verifier/a06")
        .expect("identical A06 inputs must be deterministic");

    assert_eq!(first, replay);
    assert_eq!(first.adapter_count, 5);
    assert_eq!(first.adapter_kinds, AdapterKindV1::ALL);
    assert_eq!(first.false_confirmed, 0);
    assert_eq!(first.trust_laundering_count, 0);
    assert_eq!(first.receipt_mismatch_count, 0);
    assert_eq!(first.omission_closure_basis_points, 10_000);
    assert_eq!(
        first.discovered_count,
        first.admitted_count + first.omitted_count
    );
    assert!(first.source_replay_receipt_count > 0);
    assert!(first.resolved_verified_count > 0);
    assert!(!first.canonical_eligible);
    assert!(first.canonical_selected_fact_ids.is_empty());
    assert_eq!(first.canonical_write_count, 0);
    assert_eq!(first.target_execution_count, 0);
    assert_eq!(first.provider_call_count, 0);
    assert_eq!(first.network_call_count, 0);
    assert_eq!(first.write_count, 0);
    assert!(!first.collisions.same_name_conflicts.is_empty());
    first.validate().unwrap();
}

#[test]
fn a06_changed_missing_or_misaligned_source_never_false_confirms() {
    let imports = FiveImports::load();
    let clean = imports.submissions();
    let semantic_oracle = oracle(&clean);

    let changed_sources = BTreeMap::from([(
        "ledger.rs".to_owned(),
        NATIVE_SOURCE.replace("emit", "omit").into_bytes(),
    )]);
    let mut changed = imports.submissions();
    changed[0].source_files = &changed_sources;
    assert_eq!(
        verify_adapter_gate_v1(&changed, &semantic_oracle, "gtkg.verifier/a06")
            .unwrap_err()
            .code(),
        "E_ADAPTER_SOURCE_REPLAY_INCOMPLETE"
    );

    let missing_sources = BTreeMap::new();
    let mut missing = imports.submissions();
    missing[2].source_files = &missing_sources;
    assert_eq!(
        verify_adapter_gate_v1(&missing, &semantic_oracle, "gtkg.verifier/a06")
            .unwrap_err()
            .code(),
        "E_ADAPTER_SOURCE_REPLAY_INCOMPLETE"
    );

    let mut span_bundle = imports.scip.bundle.clone();
    span_bundle.evidence[0].byte_end += 1;
    let span_bundle = span_bundle.with_computed_digest().unwrap();
    let mut span = imports.submissions();
    span[1].bundle = &span_bundle;
    assert_eq!(
        verify_adapter_gate_v1(&span, &semantic_oracle, "gtkg.verifier/a06")
            .unwrap_err()
            .code(),
        "E_ADAPTER_SOURCE_REPLAY_INCOMPLETE"
    );
}

#[test]
fn a06_inferred_evidence_cannot_be_laundered_into_extracted_trust() {
    let imports = FiveImports::load();
    let semantic_oracle = oracle(&imports.submissions());
    let mut laundered_bundle = imports.scip.bundle.clone();
    laundered_bundle.evidence[0].observed_trust = FactTrustStateV1::Inferred;
    let laundered_bundle = laundered_bundle.with_computed_digest().unwrap();
    let mut submissions = imports.submissions();
    submissions[1].bundle = &laundered_bundle;

    assert_eq!(
        verify_adapter_gate_v1(&submissions, &semantic_oracle, "gtkg.verifier/a06")
            .unwrap_err()
            .code(),
        "E_ADAPTER_TRUST_LAUNDERING"
    );
}

#[test]
fn a06_alias_oracle_accepts_alias_but_rejects_wrong_single_known_target() {
    let imports = FiveImports::load();
    let original = imports.submissions();
    let mut semantic_oracle = oracle(&original);
    let original_edge = &imports.lsp.bundle.edges[0];
    let expectation = semantic_oracle
        .expectations
        .iter_mut()
        .find(|item| item.fact_id == original_edge.fact_id)
        .unwrap();
    expectation
        .accepted_target_references
        .push("helper_alias".to_owned());
    expectation.accepted_target_references.sort();
    expectation.accepted_target_references.dedup();
    semantic_oracle = semantic_oracle.with_computed_digest().unwrap();

    let mut alias_bundle = imports.lsp.bundle.clone();
    alias_bundle.edges[0].target_reference = "helper_alias".to_owned();
    let alias_bundle = alias_bundle.with_computed_digest().unwrap();
    let mut alias_receipt = imports.lsp.receipt.clone();
    alias_receipt.bundle_sha256 = alias_bundle.bundle_sha256.clone();
    reseal_lsp(&mut alias_receipt);
    assert!(alias_receipt.validate().is_ok());
    let mut alias_submissions = imports.submissions();
    alias_submissions[2].bundle = &alias_bundle;
    alias_submissions[2].receipt = AdapterReceiptRefV1::Lsp(&alias_receipt);
    verify_adapter_gate_v1(&alias_submissions, &semantic_oracle, "gtkg.verifier/a06")
        .expect("an explicitly bound alias may replay to the same target");

    let expected_target = alias_bundle.edges[0].candidate_node_ids[0].clone();
    let wrong_target = alias_bundle
        .nodes
        .iter()
        .map(|node| node.node_id.clone())
        .find(|node_id| *node_id != expected_target)
        .unwrap();
    let mut wrong_bundle = alias_bundle.clone();
    wrong_bundle.edges[0].candidate_node_ids = vec![wrong_target];
    let wrong_bundle = wrong_bundle.with_computed_digest().unwrap();
    let mut wrong_receipt = alias_receipt;
    wrong_receipt.bundle_sha256 = wrong_bundle.bundle_sha256.clone();
    reseal_lsp(&mut wrong_receipt);
    assert!(wrong_receipt.validate().is_ok());
    let mut wrong_submissions = imports.submissions();
    wrong_submissions[2].bundle = &wrong_bundle;
    wrong_submissions[2].receipt = AdapterReceiptRefV1::Lsp(&wrong_receipt);
    assert_eq!(
        verify_adapter_gate_v1(&wrong_submissions, &semantic_oracle, "gtkg.verifier/a06")
            .unwrap_err()
            .code(),
        "E_ADAPTER_SEMANTIC_MISMATCH"
    );
}

#[test]
fn a06_validate_against_rejects_resealed_balanced_receipt_redistribution() {
    let imports = FiveImports::load();
    let semantic_oracle = oracle(&imports.submissions());

    let mut lsp_receipt = imports.lsp.receipt.clone();
    lsp_receipt.diagnostic_count -= 1;
    lsp_receipt.relationship_count += 1;
    reseal_lsp(&mut lsp_receipt);
    assert!(lsp_receipt.validate().is_ok());
    let mut lsp_submissions = imports.submissions();
    lsp_submissions[2].receipt = AdapterReceiptRefV1::Lsp(&lsp_receipt);
    assert_eq!(
        verify_adapter_gate_v1(&lsp_submissions, &semantic_oracle, "gtkg.verifier/a06")
            .unwrap_err()
            .code(),
        "E_ADAPTER_RECEIPT_MISMATCH"
    );

    let mut graphify_receipt = imports.graphify.receipt.clone();
    graphify_receipt.extracted_relationship_count -= 1;
    graphify_receipt.inferred_relationship_count += 1;
    reseal_graphify(&mut graphify_receipt);
    assert!(graphify_receipt.validate().is_ok());
    let mut graphify_submissions = imports.submissions();
    graphify_submissions[4].receipt = AdapterReceiptRefV1::GraphifyV2(&graphify_receipt);
    assert_eq!(
        verify_adapter_gate_v1(&graphify_submissions, &semantic_oracle, "gtkg.verifier/a06")
            .unwrap_err()
            .code(),
        "E_ADAPTER_RECEIPT_MISMATCH"
    );
}

#[test]
fn a06_gate_adds_the_missing_a03_implementation_level_input_hard_cap() {
    assert!(MAX_ADAPTER_INPUT_BYTES_V1 <= 64 * 1024 * 1024);
    let imports = FiveImports::load();
    let semantic_oracle = oracle(&imports.submissions());

    let mut configured_over = imports.submissions();
    configured_over[2].configured_max_file_bytes = MAX_ADAPTER_INPUT_BYTES_V1 + 1;
    assert_eq!(
        verify_adapter_gate_v1(&configured_over, &semantic_oracle, "gtkg.verifier/a06")
            .unwrap_err()
            .code(),
        "E_ADAPTER_INPUT_BUDGET"
    );

    let mut observed_over = imports.submissions();
    observed_over[2].input_file_bytes = observed_over[2].configured_max_file_bytes + 1;
    assert_eq!(
        verify_adapter_gate_v1(&observed_over, &semantic_oracle, "gtkg.verifier/a06")
            .unwrap_err()
            .code(),
        "E_ADAPTER_INPUT_BUDGET"
    );
}

#[test]
fn a06_cross_adapter_collisions_and_same_names_are_explicit_without_a_winner() {
    let facts = vec![
        AdapterFactIdentityV1 {
            adapter_kind: AdapterKindV1::Native,
            adapter_descriptor_sha256: sha256(b"native"),
            fact_id: "fact-native".to_owned(),
            stable_id: "node-shared".to_owned(),
            name: "Helper".to_owned(),
        },
        AdapterFactIdentityV1 {
            adapter_kind: AdapterKindV1::Scip,
            adapter_descriptor_sha256: sha256(b"scip"),
            fact_id: "fact-scip".to_owned(),
            stable_id: "node-shared".to_owned(),
            name: "helper".to_owned(),
        },
        AdapterFactIdentityV1 {
            adapter_kind: AdapterKindV1::LspSnapshot,
            adapter_descriptor_sha256: sha256(b"lsp"),
            fact_id: "fact-duplicate".to_owned(),
            stable_id: "node-lsp".to_owned(),
            name: "helper".to_owned(),
        },
        AdapterFactIdentityV1 {
            adapter_kind: AdapterKindV1::CodeGraphExport,
            adapter_descriptor_sha256: sha256(b"codegraph"),
            fact_id: "fact-duplicate".to_owned(),
            stable_id: "node-codegraph".to_owned(),
            name: "helper".to_owned(),
        },
    ];
    let report = detect_adapter_collisions_v1(&facts);

    assert!(report.stable_id_collisions.iter().any(|group| {
        group.kind == AdapterCollisionKindV1::StableId && group.key == "node-shared"
    }));
    assert!(report.fact_id_collisions.iter().any(|group| {
        group.kind == AdapterCollisionKindV1::FactId && group.key == "fact-duplicate"
    }));
    assert!(
        report
            .same_name_conflicts
            .iter()
            .any(|group| group.kind == AdapterCollisionKindV1::SameName && group.key == "helper")
    );
    assert!(report.selected_fact_ids.is_empty());
    assert_eq!(report.canonical_write_count, 0);
}

#[test]
fn a06_requires_the_exact_five_adapter_and_complete_oracle_denominators() {
    let imports = FiveImports::load();
    let complete = imports.submissions();
    let semantic_oracle = oracle(&complete);

    let missing = &complete[..4];
    assert_eq!(
        verify_adapter_gate_v1(missing, &semantic_oracle, "gtkg.verifier/a06")
            .unwrap_err()
            .code(),
        "E_ADAPTER_EXACT_SET"
    );

    let mut duplicate = imports.submissions();
    duplicate.push(duplicate[0].clone());
    assert_eq!(
        verify_adapter_gate_v1(&duplicate, &semantic_oracle, "gtkg.verifier/a06")
            .unwrap_err()
            .code(),
        "E_ADAPTER_EXACT_SET"
    );

    let mut incomplete_oracle = semantic_oracle;
    incomplete_oracle.expectations.pop();
    incomplete_oracle = incomplete_oracle.with_computed_digest().unwrap();
    assert_eq!(
        verify_adapter_gate_v1(&complete, &incomplete_oracle, "gtkg.verifier/a06")
            .unwrap_err()
            .code(),
        "E_ADAPTER_ORACLE_INCOMPLETE"
    );
}
