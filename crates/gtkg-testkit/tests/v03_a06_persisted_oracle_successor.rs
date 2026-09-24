include!("v03_a06_trusted_gate_successor.rs");

use gtkg_core::v03::adapter::verifier::{
    AdapterGateAuthorityStateV1, AdapterTrustedOracleFixtureV1, verify_adapter_gate_strict_v1,
};

fn persisted_fixture() -> AdapterTrustedOracleFixtureV1 {
    serde_json::from_slice(&fs::read(fixture("fixtures/v03_a06/trusted-oracle-pin.json")).unwrap())
        .unwrap()
}

#[test]
fn a06_strict_gate_deserializes_complete_persisted_oracle_expectations() {
    let trusted_fixture = persisted_fixture();
    trusted_fixture.validate().unwrap();
    assert_eq!(
        trusted_fixture.oracle.oracle_sha256,
        trusted_fixture.pin.expected_oracle_sha256
    );
    assert_eq!(trusted_fixture.oracle.expectations.len(), 12);

    let imports = FiveImports::load();
    let submissions = imports.submissions();
    let receipt =
        verify_adapter_gate_strict_v1(&submissions, &trusted_fixture, "gtkg.verifier/a06-strict")
            .unwrap();
    assert_eq!(
        receipt.authority_state,
        AdapterGateAuthorityStateV1::TrustedFixtureBound
    );
    assert!(receipt.trusted_oracle_pin_sha256.is_some());
    assert!(receipt.trusted_oracle_fixture_sha256.is_some());
    receipt
        .validate_strict_against(&submissions, &trusted_fixture, "gtkg.verifier/a06-strict")
        .unwrap();
}

#[test]
fn a06_strict_gate_rejects_persisted_expectation_content_tamper() {
    let imports = FiveImports::load();
    let submissions = imports.submissions();

    let mut stale_digest = persisted_fixture();
    stale_digest.oracle.expectations[0]
        .accepted_target_references
        .push("tampered-reference".to_owned());
    assert_eq!(
        verify_adapter_gate_strict_v1(&submissions, &stale_digest, "gtkg.verifier/a06-strict")
            .unwrap_err()
            .code(),
        "E_ADAPTER_ORACLE_INVALID"
    );

    let mut rehashed = persisted_fixture();
    rehashed.oracle.expectations[0]
        .accepted_target_references
        .push("tampered-reference".to_owned());
    rehashed.oracle = rehashed.oracle.with_computed_digest().unwrap();
    assert_eq!(
        verify_adapter_gate_strict_v1(&submissions, &rehashed, "gtkg.verifier/a06-strict")
            .unwrap_err()
            .code(),
        "E_ADAPTER_TRUSTED_ORACLE_MISMATCH"
    );

    let mut changed_notes = persisted_fixture();
    changed_notes.review_material["reviewer_role"] = Value::String("candidate".to_owned());
    assert_eq!(
        verify_adapter_gate_strict_v1(&submissions, &changed_notes, "gtkg.verifier/a06-strict")
            .unwrap_err()
            .code(),
        "E_ADAPTER_TRUSTED_ORACLE_MISMATCH"
    );
}

#[test]
fn a06_plain_legacy_receipt_cannot_masquerade_as_strict_authority() {
    let trusted_fixture = persisted_fixture();
    let imports = FiveImports::load();
    let submissions = imports.submissions();

    let legacy = verify_adapter_gate_v1(
        &submissions,
        &trusted_fixture.oracle,
        "gtkg.verifier/a06-strict",
    )
    .unwrap();
    assert_eq!(
        legacy.authority_state,
        AdapterGateAuthorityStateV1::UntrustedLegacy
    );
    assert!(legacy.trusted_oracle_pin_sha256.is_none());
    assert!(legacy.trusted_oracle_fixture_sha256.is_none());
    legacy.validate().unwrap();
    assert_eq!(
        legacy
            .validate_strict_against(&submissions, &trusted_fixture, "gtkg.verifier/a06-strict",)
            .unwrap_err()
            .code(),
        "E_ADAPTER_GATE_RECEIPT_MISMATCH"
    );

    let pin_only = verify_adapter_gate_with_trusted_oracle_v1(
        &submissions,
        &trusted_fixture.oracle,
        &trusted_fixture.pin,
        "gtkg.verifier/a06-strict",
    )
    .unwrap();
    assert_eq!(
        pin_only.authority_state,
        AdapterGateAuthorityStateV1::TrustedPinBound
    );
    assert_eq!(
        pin_only
            .validate_strict_against(&submissions, &trusted_fixture, "gtkg.verifier/a06-strict",)
            .unwrap_err()
            .code(),
        "E_ADAPTER_GATE_RECEIPT_MISMATCH"
    );
}
