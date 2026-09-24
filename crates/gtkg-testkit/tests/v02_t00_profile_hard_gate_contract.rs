//! V0.2 T00 immutable contract: profile-scoped completeness is a hard-gate
//! conjunction, never a weighted score or an empty-denominator shortcut.

use std::collections::BTreeMap;

use gtkg_protocol::v2::{
    CapabilityState, CoverageProfileV1, GateStatus, HardGateReducer, HardGateResultV1, OkfSpecPinV1,
};

fn profile() -> CoverageProfileV1 {
    CoverageProfileV1::new(
        "gtkg.coverage-profile/v1",
        "v02-core",
        ["rust_semantics", "document_locator"],
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    )
    .expect("valid fixture profile")
}

#[test]
fn required_non_passed_gate_blocks_comprehensive_even_at_weighted_100() {
    let profile = profile();
    let reducer = HardGateReducer::new(&profile);
    let results = [
        HardGateResultV1::required(
            "rust_semantics",
            1,
            1,
            GateStatus::Passed,
            CapabilityState::Supported,
        )
        .with_profile_digest(profile.profile_sha256.clone()),
        HardGateResultV1::required(
            "document_locator",
            1,
            0,
            GateStatus::NotRun,
            CapabilityState::Supported,
        )
        .with_profile_digest(profile.profile_sha256.clone()),
    ];

    let outcome = reducer.reduce(&results).expect("well-formed gates");
    assert!(!outcome.comprehensive_for_profile);
    assert_eq!(outcome.blocking_gate_ids, vec!["document_locator"]);
    assert_eq!(outcome.weighted_score, 100);
}

#[test]
fn profile_or_tool_lock_drift_makes_prior_gate_evidence_stale() {
    let profile = profile();
    let reducer = HardGateReducer::new(&profile);
    let result = HardGateResultV1::required(
        "rust_semantics",
        1,
        1,
        GateStatus::Passed,
        CapabilityState::Supported,
    )
    .with_profile_digest("sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");

    let outcome = reducer.reduce(&[result]).expect("well-formed gate");
    assert!(!outcome.comprehensive_for_profile);
    assert_eq!(
        outcome.blocking_gate_ids,
        vec!["document_locator", "rust_semantics"]
    );
    assert_eq!(outcome.stale_gate_ids, vec!["rust_semantics"]);
}

#[test]
fn required_zero_denominator_cannot_be_passed() {
    let profile = profile();
    let reducer = HardGateReducer::new(&profile);
    let result = HardGateResultV1::required(
        "rust_semantics",
        0,
        0,
        GateStatus::Passed,
        CapabilityState::Supported,
    );

    let error = reducer
        .reduce(&[result])
        .expect_err("required 0/0 must fail closed");
    assert_eq!(error.code(), "E_V2_REQUIRED_GATE_EMPTY_DENOMINATOR");
}

#[test]
fn missing_required_gate_or_profile_binding_cannot_produce_comprehensive() {
    let profile = profile();
    let reducer = HardGateReducer::new(&profile);

    let missing_gate = HardGateResultV1::required(
        "rust_semantics",
        1,
        1,
        GateStatus::Passed,
        CapabilityState::Supported,
    )
    .with_profile_digest(profile.profile_sha256.clone());
    let outcome = reducer
        .reduce(&[missing_gate])
        .expect("present gate itself is well formed");
    assert!(!outcome.comprehensive_for_profile);
    assert_eq!(outcome.blocking_gate_ids, vec!["document_locator"]);

    let missing_binding = HardGateResultV1::required(
        "rust_semantics",
        1,
        1,
        GateStatus::Passed,
        CapabilityState::Supported,
    );
    let outcome = reducer
        .reduce(&[missing_binding])
        .expect("missing binding must reduce to stale, not panic");
    assert!(!outcome.comprehensive_for_profile);
    assert_eq!(outcome.stale_gate_ids, vec!["rust_semantics"]);
}

#[test]
fn tampered_deserialized_profile_cannot_be_reduced_as_current() {
    let mut profile = profile();
    profile.budgets.insert("context_tokens".to_owned(), 2);
    let reducer = HardGateReducer::new(&profile);
    let error = reducer
        .reduce(&[])
        .expect_err("digest must bind every frozen profile field");
    assert_eq!(error.code(), "E_V2_PROFILE_INVALID");
}

#[test]
fn canonical_core_is_constructable_and_custom_profile_cannot_claim_product_certification() {
    let digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let mut locks = BTreeMap::new();
    for key in ["adapter", "resolver", "tokenizer", "prompt", "verifier"] {
        locks.insert(key.to_owned(), digest.to_owned());
    }
    let mut budgets = BTreeMap::new();
    budgets.insert("context_tokens".to_owned(), 32_768);
    let mut corpus_refs = BTreeMap::new();
    corpus_refs.insert("product_core".to_owned(), digest.to_owned());
    let mut incomplete_locks = locks.clone();
    incomplete_locks.remove("resolver");
    let missing_lock = CoverageProfileV1::canonical_core(
        incomplete_locks,
        budgets.clone(),
        corpus_refs.clone(),
        digest,
        OkfSpecPinV1 {
            version: "0.2".to_owned(),
            upstream_commit: "62432a095456147ee71e70ac6e4dc0d2dea3ac30".to_owned(),
            raw_sha256: digest.to_owned(),
        },
    )
    .expect_err("canonical core must reject a missing required tool lock");
    assert_eq!(
        missing_lock.to_string(),
        "product-certified core profile is incomplete"
    );
    let mut extra_locks = locks.clone();
    extra_locks.insert("unreviewed_extension".to_owned(), digest.to_owned());
    let extra_lock = CoverageProfileV1::canonical_core(
        extra_locks,
        budgets.clone(),
        corpus_refs.clone(),
        digest,
        OkfSpecPinV1 {
            version: "0.2".to_owned(),
            upstream_commit: "62432a095456147ee71e70ac6e4dc0d2dea3ac30".to_owned(),
            raw_sha256: digest.to_owned(),
        },
    )
    .expect_err("canonical core must reject an unreviewed extra tool lock");
    assert_eq!(
        extra_lock.to_string(),
        "product-certified core profile is incomplete"
    );
    let core = CoverageProfileV1::canonical_core(
        locks,
        budgets,
        corpus_refs,
        digest,
        OkfSpecPinV1 {
            version: "0.2".to_owned(),
            upstream_commit: "62432a095456147ee71e70ac6e4dc0d2dea3ac30".to_owned(),
            raw_sha256: digest.to_owned(),
        },
    )
    .expect("canonical core must be buildable from explicit locks");
    assert!(core.is_product_certified_core());
    assert_ne!(core.profile_sha256, profile().profile_sha256);
    assert!(!profile().is_product_certified_core());
}

#[test]
fn profile_digest_has_field_boundaries_and_detects_cross_field_change() {
    let mut profile = profile();
    profile.required_formats = vec!["test_language".to_owned()];
    profile.required_languages = vec!["test".to_owned()];
    let reducer = HardGateReducer::new(&profile);
    let error = reducer
        .reduce(&[])
        .expect_err("moving bytes between typed fields must invalidate the digest");
    assert_eq!(error.code(), "E_V2_PROFILE_INVALID");
}

#[test]
fn invalid_and_cannot_confirm_required_gate_states_block_comprehensive() {
    let profile = profile();
    let reducer = HardGateReducer::new(&profile);
    for status in [GateStatus::Invalid, GateStatus::CannotConfirm] {
        let results = [
            HardGateResultV1::required(
                "rust_semantics",
                1,
                1,
                GateStatus::Passed,
                CapabilityState::Supported,
            )
            .with_profile_digest(profile.profile_sha256.clone()),
            HardGateResultV1::required(
                "document_locator",
                1,
                0,
                status,
                CapabilityState::Supported,
            )
            .with_profile_digest(profile.profile_sha256.clone()),
        ];
        let outcome = reducer.reduce(&results).expect("well-formed status");
        assert!(!outcome.comprehensive_for_profile, "{status:?} must block");
        assert_eq!(outcome.blocking_gate_ids, vec!["document_locator"]);
    }
}
