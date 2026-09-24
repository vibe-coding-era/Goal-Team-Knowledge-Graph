//! V0.2 T02 contract: Snapshot-bound Typed IR is deterministic, evidence-backed,
//! and never promotes lexical fallback output into semantic facts.

use std::fs;

use gtkg_core::source_v2::{SourceCaptureRequestV2, capture_source_snapshot_v2};
use gtkg_extract::{build_typed_ir_v2, extract_path};
use gtkg_protocol::v2::{
    CapabilityState, IrResolutionStateV2, SourceBaselineIdentityV2, SourceCaptureModeV2,
    SourceEligibilityV2, SourceSnapshotDenominatorV2, SourceSnapshotEntryV2, SourceSnapshotV2,
    TypedIrModeV2,
};
use sha2::{Digest, Sha256};
use tempfile::tempdir;

const SNAPSHOT_DIGEST: &str =
    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn snapshot(logical_path: &str, source: &str) -> SourceSnapshotV2 {
    SourceSnapshotV2 {
        schema_version: "gtkg.source-snapshot/v2".to_owned(),
        capture_mode: SourceCaptureModeV2::DirectoryExact,
        repository_id: "t02-fixture".to_owned(),
        baseline: SourceBaselineIdentityV2 {
            kind: "directory".to_owned(),
            head: None,
            tree: None,
            status_sha256: SNAPSHOT_DIGEST.to_owned(),
        },
        inventory: vec![SourceSnapshotEntryV2 {
            logical_path: logical_path.to_owned(),
            content_sha256: digest(source.as_bytes()),
            bytes: source.len() as u64,
        }],
        omissions: Vec::new(),
        denominator: SourceSnapshotDenominatorV2 {
            discovered_entries: 1,
            admitted_entries: 1,
            omitted_entries: 0,
        },
        exact_set_sha256: String::new(),
        eligibility: SourceEligibilityV2 {
            development_eligible: true,
            source_release_candidate: false,
            environment_ready: false,
            release_ready: false,
        },
    }
    .with_exact_set_digest()
    .expect("fixture snapshot exact set")
}

#[test]
fn capability_state_contract_keeps_all_four_explicit_disclosure_states() {
    let rendered = [
        CapabilityState::Supported,
        CapabilityState::Partial,
        CapabilityState::Unsupported,
        CapabilityState::NotApplicable,
    ]
    .map(|state| serde_json::to_value(state).expect("capability state JSON"));
    assert_eq!(
        rendered,
        [
            serde_json::json!("supported"),
            serde_json::json!("partial"),
            serde_json::json!("unsupported"),
            serde_json::json!("not_applicable"),
        ]
    );
}

fn extract_typed(name: &str, source: &str) -> gtkg_protocol::v2::TypedIrV2 {
    let temp = tempdir().expect("tempdir");
    let path = temp.path().join(name);
    fs::write(&path, source).expect("fixture write");
    let extracted = extract_path(&path).expect("static extract");
    build_typed_ir_v2(&snapshot(name, source), name, &extracted).expect("typed IR build")
}

#[test]
fn four_language_semantics_are_snapshot_bound_with_stable_ids_and_valid_byte_evidence() {
    let fixtures = [
        ("ledger.rs", include_str!("../fixtures/v02_t02/ledger.rs")),
        ("ledger.py", include_str!("../fixtures/v02_t02/ledger.py")),
        ("ledger.ts", include_str!("../fixtures/v02_t02/ledger.ts")),
        ("ledger.js", include_str!("../fixtures/v02_t02/ledger.js")),
    ];

    for (name, source) in fixtures {
        let first = extract_typed(name, source);
        let second = extract_typed(name, source);
        assert_eq!(first.mode, TypedIrModeV2::AstSemantic, "{name}");
        assert!(
            first
                .source_snapshot_exact_set_sha256
                .starts_with("sha256:"),
            "{name} exact-set binding"
        );
        assert_eq!(first.source_logical_path, name);
        assert_eq!(first.source_sha256, digest(source.as_bytes()));
        assert!(!first.nodes.is_empty(), "{name} must have typed nodes");
        assert!(!first.evidence.is_empty(), "{name} must have evidence");
        assert_eq!(first, second, "{name} must be deterministic");
        first
            .validate_for_source(source.as_bytes())
            .unwrap_or_else(|error| panic!("{name}: {error}"));
        assert_eq!(first.capabilities["cfg"], CapabilityState::Unsupported);
        assert_eq!(
            first.capabilities["exception"],
            CapabilityState::Unsupported
        );

        let node_ids: Vec<&str> = first.nodes.iter().map(|node| node.id.as_str()).collect();
        let mut sorted_node_ids = node_ids.clone();
        sorted_node_ids.sort_unstable();
        sorted_node_ids.dedup();
        assert_eq!(
            node_ids, sorted_node_ids,
            "{name} node ids must be stable and unique"
        );
        for evidence in &first.evidence {
            assert!(evidence.id.starts_with("evidence:v2:"), "{name}");
            evidence
                .validate_for_source(name, source.as_bytes())
                .expect("byte evidence must read back exactly");
        }
    }
}

#[test]
fn malformed_code_is_explicit_fallback_lexical_and_never_semantic_ir() {
    let fixtures = [
        ("broken.rs", include_str!("../fixtures/v02_t02/broken.rs")),
        ("broken.py", include_str!("../fixtures/v02_t02/broken.py")),
        ("broken.ts", include_str!("../fixtures/v02_t02/broken.ts")),
        ("broken.js", include_str!("../fixtures/v02_t02/broken.js")),
    ];
    for (name, source) in fixtures {
        let ir = extract_typed(name, source);
        assert_eq!(ir.mode, TypedIrModeV2::FallbackLexical, "{name}");
        assert!(
            ir.nodes.is_empty(),
            "{name} lexical symbols are not typed nodes"
        );
        assert!(
            ir.edges.is_empty(),
            "{name} lexical symbols are not typed edges"
        );
        assert!(
            ir.evidence.is_empty(),
            "{name} lexical symbols have no semantic evidence"
        );
        assert!(ir.validate_for_source(source.as_bytes()).is_ok(), "{name}");
    }
}

#[test]
fn unresolved_reference_is_never_promoted_to_a_resolved_edge_before_t05() {
    let source = include_str!("../fixtures/v02_t02/ambiguous.js");
    let ir = extract_typed("ambiguous.js", source);
    let edge = ir
        .edges
        .iter()
        .find(|edge| edge.target_reference == "run")
        .expect("call edge");
    assert_eq!(edge.resolution, IrResolutionStateV2::Unresolved);
    assert!(edge.candidate_node_ids.is_empty());
    assert!(edge.resolved_node_id.is_none());
}

#[test]
fn source_digest_or_snapshot_admission_mismatch_is_rejected() {
    let temp = tempdir().expect("tempdir");
    let path = temp.path().join("source.rs");
    let source = "fn stable() {}\n";
    fs::write(&path, source).expect("fixture write");
    let extracted = extract_path(&path).expect("static extract");
    let error = build_typed_ir_v2(&snapshot("other.rs", source), "source.rs", &extracted)
        .expect_err("unadmitted source must fail closed");
    assert_eq!(error.code(), "E_V2_IR_SOURCE_NOT_ADMITTED");
}

#[test]
fn extracted_text_digest_mismatch_is_rejected_even_when_the_replacement_has_the_same_length() {
    let temp = tempdir().expect("tempdir");
    let path = temp.path().join("source.rs");
    let source = "fn alpha() {}\n";
    fs::write(&path, source).expect("fixture write");
    let mut extracted = extract_path(&path).expect("static extract");
    extracted.text = "fn beta_() {}\n".to_owned();

    let error = build_typed_ir_v2(&snapshot("source.rs", source), "source.rs", &extracted)
        .expect_err("same-length text tampering must fail closed");
    assert_eq!(error.code(), "E_V2_IR_EXTRACTED_SOURCE_DIGEST_MISMATCH");
}

#[test]
fn snapshot_exact_set_and_denominator_tampering_are_rejected_before_admission() {
    let temp = tempdir().expect("tempdir");
    let path = temp.path().join("source.rs");
    let source = "fn stable() {}\n";
    fs::write(&path, source).expect("fixture write");
    let extracted = extract_path(&path).expect("static extract");

    let mut exact_set_tampered = snapshot("source.rs", source);
    exact_set_tampered.exact_set_sha256 = SNAPSHOT_DIGEST.to_owned();
    let exact_set_error = build_typed_ir_v2(&exact_set_tampered, "source.rs", &extracted)
        .expect_err("tampered exact set must fail closed");
    assert_eq!(exact_set_error.code(), "E_V2_IR_SOURCE_SNAPSHOT_INVALID");

    let mut denominator_tampered = snapshot("source.rs", source);
    denominator_tampered.denominator.admitted_entries = 2;
    let denominator_error = build_typed_ir_v2(&denominator_tampered, "source.rs", &extracted)
        .expect_err("tampered denominator must fail closed");
    assert_eq!(denominator_error.code(), "E_V2_IR_SOURCE_SNAPSHOT_INVALID");
}

#[test]
fn directory_exact_snapshot_from_t01_is_admitted_by_t02_complete_validation() {
    let source_root = tempdir().expect("source root");
    let output_root = tempdir().expect("output root");
    let source_path = source_root.path().join("ledger.rs");
    fs::write(&source_path, include_str!("../fixtures/v02_t02/ledger.rs")).expect("fixture write");
    let snapshot = capture_source_snapshot_v2(&SourceCaptureRequestV2::new(
        SourceCaptureModeV2::DirectoryExact,
        "t02-t01-compatibility",
        source_root.path().to_path_buf(),
        output_root.path().to_path_buf(),
    ))
    .expect("T01 source capture");
    snapshot.validate().expect("T01 complete snapshot contract");
    let extracted = extract_path(&source_path).expect("static extract");
    let ir = build_typed_ir_v2(&snapshot, "ledger.rs", &extracted)
        .expect("T02 must admit a valid T01 capture");
    assert_eq!(ir.mode, TypedIrModeV2::AstSemantic);
}
