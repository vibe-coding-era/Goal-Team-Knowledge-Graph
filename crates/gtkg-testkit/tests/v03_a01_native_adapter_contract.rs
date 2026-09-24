//! A01 contract: the existing four-language native extractors project through
//! the A00 `ExternalFactBundleV1` boundary without semantic or evidence loss.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use gtkg_core::v03::adapter::native::{adapt_native_path_v1, native_adapter_descriptor_v1};
use gtkg_core::v03::adapter::verify_external_fact_bundle_v1;
use gtkg_extract::{build_typed_ir_v2, extract_path, resolve_local_typed_ir_v2};
use gtkg_protocol::v2::{
    IrResolutionStateV2, SourceBaselineIdentityV2, SourceCaptureModeV2, SourceEligibilityV2,
    SourceSnapshotDenominatorV2, SourceSnapshotEntryV2, SourceSnapshotV2, TypedIrModeV2,
};
use gtkg_protocol::v03::AdapterKindV1;
use gtkg_protocol::v03::adapter::{CandidateFactStateV1, FactTrustStateV1};
use sha2::{Digest, Sha256};

const VALID_CASES: [(&str, &str); 4] = [
    ("ledger.rs", include_str!("../fixtures/v03_a01/ledger.rs")),
    ("ledger.py", include_str!("../fixtures/v03_a01/ledger.py")),
    ("ledger.ts", include_str!("../fixtures/v03_a01/ledger.ts")),
    ("ledger.js", include_str!("../fixtures/v03_a01/ledger.js")),
];

const BROKEN_CASES: [(&str, &str); 4] = [
    ("broken.rs", include_str!("../fixtures/v03_a01/broken.rs")),
    ("broken.py", include_str!("../fixtures/v03_a01/broken.py")),
    ("broken.ts", include_str!("../fixtures/v03_a01/broken.ts")),
    ("broken.js", include_str!("../fixtures/v03_a01/broken.js")),
];

fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/v03_a01")
}

fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn snapshot(cases: &[(&str, &str)]) -> SourceSnapshotV2 {
    let mut inventory = cases
        .iter()
        .map(|(logical_path, source)| SourceSnapshotEntryV2 {
            logical_path: (*logical_path).to_owned(),
            content_sha256: sha256(source.as_bytes()),
            bytes: source.len() as u64,
        })
        .collect::<Vec<_>>();
    inventory.sort_by(|left, right| left.logical_path.cmp(&right.logical_path));
    SourceSnapshotV2 {
        schema_version: "gtkg.source-snapshot/v2".to_owned(),
        capture_mode: SourceCaptureModeV2::DirectoryExact,
        repository_id: "v03-a01-native-fixture".to_owned(),
        baseline: SourceBaselineIdentityV2 {
            kind: "directory".to_owned(),
            head: None,
            tree: None,
            status_sha256: sha256(b"v03-a01-native-fixture-status"),
        },
        denominator: SourceSnapshotDenominatorV2 {
            discovered_entries: inventory.len() as u64,
            admitted_entries: inventory.len() as u64,
            omitted_entries: 0,
        },
        inventory,
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
    .expect("frozen A01 snapshot must seal")
}

fn v02_resolved_ir(
    snapshot: &SourceSnapshotV2,
    logical_path: &str,
    path: &Path,
) -> gtkg_protocol::v2::TypedIrV2 {
    let extracted = extract_path(path).expect("V0.2 static extractor");
    let ir = build_typed_ir_v2(snapshot, logical_path, &extracted).expect("V0.2 typed IR");
    resolve_local_typed_ir_v2(&ir, extracted.text.as_bytes()).expect("V0.2 local resolver")
}

#[test]
fn a01_native_descriptor_and_effect_boundary_are_frozen() {
    let snapshot = snapshot(&VALID_CASES);
    let descriptor = native_adapter_descriptor_v1().expect("native descriptor");
    descriptor.validate().expect("sealed native descriptor");
    assert_eq!(descriptor.kind, AdapterKindV1::Native);
    assert_eq!(descriptor.adapter_id, "gtkg.adapter.native");
    assert_eq!(descriptor.adapter_version, "0.3.0");
    assert_eq!(
        descriptor.capabilities,
        [
            "calls",
            "evidence_readback",
            "imports",
            "inheritance",
            "nodes",
            "static_file_only",
        ]
    );

    for (logical_path, _) in VALID_CASES {
        let output =
            adapt_native_path_v1(&snapshot, logical_path, &fixture_root().join(logical_path))
                .expect(logical_path);
        assert_eq!(output.descriptor, descriptor, "{logical_path}");
        assert_eq!(output.effects.source_file_read_count, 1, "{logical_path}");
        assert_eq!(output.effects.target_process_count, 0, "{logical_path}");
        assert_eq!(output.effects.network_call_count, 0, "{logical_path}");
        assert_eq!(output.effects.write_count, 0, "{logical_path}");
        assert!(!output.effects.executed_target_content, "{logical_path}");
    }
}

#[test]
fn a01_four_languages_preserve_v02_nodes_edges_resolutions_and_evidence() {
    let snapshot = snapshot(&VALID_CASES);
    for (logical_path, source) in VALID_CASES {
        let path = fixture_root().join(logical_path);
        let legacy = v02_resolved_ir(&snapshot, logical_path, &path);
        let output = adapt_native_path_v1(&snapshot, logical_path, &path).expect(logical_path);

        assert_eq!(legacy.mode, TypedIrModeV2::AstSemantic, "{logical_path}");
        assert_eq!(
            output.bundle.nodes.len(),
            legacy.nodes.len(),
            "{logical_path}"
        );
        assert_eq!(
            output.bundle.edges.len(),
            legacy.edges.len(),
            "{logical_path}"
        );
        assert_eq!(
            output.bundle.evidence.len(),
            legacy.evidence.len(),
            "{logical_path}"
        );

        for legacy_node in &legacy.nodes {
            let mapped = output
                .bundle
                .nodes
                .iter()
                .find(|node| node.node_id == legacy_node.id)
                .expect("every V0.2 node must be mapped");
            assert_eq!(mapped.node_kind, legacy_node.kind, "{logical_path}");
            assert_eq!(mapped.name, legacy_node.name, "{logical_path}");
            assert_eq!(
                mapped.evidence_ids, legacy_node.evidence_ids,
                "{logical_path}"
            );
            assert_eq!(
                mapped.candidate_state,
                CandidateFactStateV1::CandidateExternal
            );
            assert_eq!(mapped.trust_state, FactTrustStateV1::Extracted);
        }

        for legacy_edge in &legacy.edges {
            let mapped = output
                .bundle
                .edges
                .iter()
                .find(|edge| edge.edge_id == legacy_edge.id)
                .expect("every V0.2 edge must be mapped");
            assert_eq!(mapped.edge_kind, legacy_edge.kind, "{logical_path}");
            assert_eq!(
                mapped.target_reference, legacy_edge.target_reference,
                "{logical_path}"
            );
            assert_eq!(
                mapped.evidence_ids, legacy_edge.evidence_ids,
                "{logical_path}"
            );
            match legacy_edge.resolution {
                IrResolutionStateV2::Resolved => {
                    assert_eq!(
                        mapped.candidate_state,
                        CandidateFactStateV1::CandidateExternal
                    );
                    assert_eq!(mapped.trust_state, FactTrustStateV1::Extracted);
                    assert_eq!(
                        mapped.candidate_node_ids,
                        legacy_edge
                            .resolved_node_id
                            .iter()
                            .cloned()
                            .collect::<Vec<_>>()
                    );
                }
                IrResolutionStateV2::Ambiguous => {
                    assert_eq!(mapped.candidate_state, CandidateFactStateV1::Ambiguous);
                    assert_eq!(mapped.trust_state, FactTrustStateV1::Ambiguous);
                    assert_eq!(mapped.candidate_node_ids, legacy_edge.candidate_node_ids);
                }
                IrResolutionStateV2::Unresolved | IrResolutionStateV2::NotApplicable => {
                    assert_eq!(mapped.candidate_state, CandidateFactStateV1::LocatorOnly);
                    assert!(mapped.candidate_node_ids.is_empty());
                }
            }
        }

        for evidence in &output.bundle.evidence {
            assert_eq!(evidence.source_logical_path, logical_path);
            assert_eq!(evidence.source_bytes_sha256, sha256(source.as_bytes()));
            let snippet =
                &source.as_bytes()[evidence.byte_start as usize..evidence.byte_end as usize];
            assert_eq!(evidence.snippet_sha256, sha256(snippet), "{logical_path}");
        }
        output
            .bundle
            .validate()
            .expect("A00 common bundle contract");
    }
}

#[test]
fn a01_output_is_byte_deterministic_and_exact_source_replay_verifies() {
    let snapshot = snapshot(&VALID_CASES);
    for (logical_path, source) in VALID_CASES {
        let path = fixture_root().join(logical_path);
        let first = adapt_native_path_v1(&snapshot, logical_path, &path).expect(logical_path);
        let second = adapt_native_path_v1(&snapshot, logical_path, &path).expect(logical_path);
        assert_eq!(first, second, "{logical_path}");
        assert_eq!(
            serde_json::to_vec(&first.bundle).expect("first JSON"),
            serde_json::to_vec(&second.bundle).expect("second JSON"),
            "{logical_path}"
        );

        let source_files = BTreeMap::from([(logical_path.to_owned(), source.as_bytes().to_vec())]);
        let verification = verify_external_fact_bundle_v1(
            &first.descriptor,
            &first.descriptor,
            &first.bundle,
            &source_files,
            "gtkg.verifier/a01",
        )
        .expect("native exact source replay");
        assert_eq!(verification.false_confirmed, 0, "{logical_path}");
        assert_eq!(verification.canonical_write_count, 0, "{logical_path}");
        assert_eq!(
            verification.receipts.len(),
            first.bundle.nodes.len() + first.bundle.edges.len(),
            "{logical_path}"
        );
        let expected_resolved = first
            .bundle
            .nodes
            .iter()
            .map(|node| node.fact_id.as_str())
            .chain(
                first
                    .bundle
                    .edges
                    .iter()
                    .filter(|edge| edge.candidate_state == CandidateFactStateV1::CandidateExternal)
                    .map(|edge| edge.fact_id.as_str()),
            )
            .collect::<BTreeSet<_>>();
        assert_eq!(
            verification
                .resolved_verified_fact_ids
                .iter()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            expected_resolved,
            "{logical_path}"
        );
    }
}

#[test]
fn a01_source_drift_cannot_confirm_native_facts() {
    let snapshot = snapshot(&VALID_CASES);
    let path = fixture_root().join("ledger.rs");
    let output = adapt_native_path_v1(&snapshot, "ledger.rs", &path).expect("Rust native output");
    let changed = include_str!("../fixtures/v03_a01/ledger.rs")
        .replace("emit", "omit")
        .into_bytes();
    let changed_sources = BTreeMap::from([("ledger.rs".to_owned(), changed)]);
    let verification = verify_external_fact_bundle_v1(
        &output.descriptor,
        &output.descriptor,
        &output.bundle,
        &changed_sources,
        "gtkg.verifier/a01",
    )
    .expect("source drift is represented as a non-confirming result");
    assert!(verification.resolved_verified_fact_ids.is_empty());
    assert_eq!(verification.false_confirmed, 0);
    assert!(verification.receipts.iter().all(|receipt| {
        receipt.resolution != gtkg_protocol::v03::adapter::VerifiedResolutionV1::ResolvedVerified
    }));
}

#[test]
fn a01_parser_fallback_is_closed_as_an_explicit_omission() {
    let snapshot = snapshot(&BROKEN_CASES);
    for (logical_path, _) in BROKEN_CASES {
        let path = fixture_root().join(logical_path);
        let legacy = v02_resolved_ir(&snapshot, logical_path, &path);
        assert_eq!(
            legacy.mode,
            TypedIrModeV2::FallbackLexical,
            "{logical_path}"
        );
        let output = adapt_native_path_v1(&snapshot, logical_path, &path).expect(logical_path);
        assert!(output.bundle.nodes.is_empty(), "{logical_path}");
        assert!(output.bundle.edges.is_empty(), "{logical_path}");
        assert!(output.bundle.evidence.is_empty(), "{logical_path}");
        assert_eq!(output.bundle.discovered_count, 1, "{logical_path}");
        assert_eq!(output.bundle.admitted_count, 0, "{logical_path}");
        assert_eq!(output.bundle.omitted_count, 1, "{logical_path}");
        assert_eq!(output.bundle.omissions.len(), 1, "{logical_path}");
        assert_eq!(output.bundle.omissions[0].reason, "parser_fallback_lexical");
        assert!(output.bundle.candidate_states.is_empty(), "{logical_path}");
        output
            .bundle
            .validate()
            .expect("closed fallback denominator");
    }
}

#[test]
fn a01_rejects_snapshot_path_or_language_mismatch_fail_closed() {
    let snapshot = snapshot(&VALID_CASES);
    let wrong_language =
        adapt_native_path_v1(&snapshot, "ledger.py", &fixture_root().join("ledger.rs"))
            .expect_err("Rust bytes cannot satisfy the admitted Python source");
    assert_eq!(wrong_language.code(), "E_V2_IR_SOURCE_NOT_ADMITTED");

    let unsupported_path = fixture_root().join("unsupported.txt");
    fs::write(&unsupported_path, "text").expect("temporary unsupported fixture");
    let unsupported = adapt_native_path_v1(&snapshot, "ledger.rs", &unsupported_path)
        .expect_err("unsupported extractor must fail closed");
    assert_eq!(unsupported.code(), "E_NATIVE_ADAPTER_UNSUPPORTED");
    fs::remove_file(unsupported_path).expect("remove temporary fixture");
}
