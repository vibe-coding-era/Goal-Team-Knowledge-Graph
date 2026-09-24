include!("v03_a06_persisted_oracle_successor.rs");

use gtkg_core::v03::adapter::verifier::{
    SealedInputObservationV1, StrictAdapterSubmissionV1, verify_adapter_gate_sealed_strict_v1,
};

struct ActualAdapterInputs {
    native: Vec<u8>,
    scip: Vec<u8>,
    lsp: Vec<u8>,
    codegraph: Vec<u8>,
    graphify: Vec<u8>,
}

impl ActualAdapterInputs {
    fn load() -> Self {
        Self {
            native: fs::read(fixture("fixtures/v03_a01/ledger.rs")).unwrap(),
            scip: fs::read(fixture("fixtures/v03_a02/valid-scip.json")).unwrap(),
            lsp: fs::read(fixture("fixtures/v03_a03/valid-lsp-snapshot.json")).unwrap(),
            codegraph: fs::read(fixture("fixtures/v03_a04/valid-codegraph.json")).unwrap(),
            graphify: fs::read(fixture("fixtures/v03_a05/strict-graphify-v2.json")).unwrap(),
        }
    }

    fn slices(&self) -> [&[u8]; 5] {
        [
            &self.native,
            &self.scip,
            &self.lsp,
            &self.codegraph,
            &self.graphify,
        ]
    }
}

fn strict_submissions<'a>(
    imports: &'a FiveImports,
    actual: &'a ActualAdapterInputs,
) -> Vec<StrictAdapterSubmissionV1<'a>> {
    imports
        .submissions()
        .into_iter()
        .zip(actual.slices())
        .map(
            |(submission, actual_input_bytes)| StrictAdapterSubmissionV1 {
                submission,
                observation: SealedInputObservationV1 { actual_input_bytes },
            },
        )
        .collect()
}

#[test]
fn a06_sealed_strict_gate_computes_actual_input_len_and_receipt_sha() {
    let trusted_fixture = persisted_fixture();
    let imports = FiveImports::load();
    let actual = ActualAdapterInputs::load();
    let submissions = strict_submissions(&imports, &actual);
    let receipt = verify_adapter_gate_sealed_strict_v1(
        &submissions,
        &trusted_fixture,
        "gtkg.verifier/a06-sealed-strict",
    )
    .unwrap();

    assert_eq!(
        receipt.authority_state,
        AdapterGateAuthorityStateV1::TrustedFixtureInputBound
    );
    assert!(receipt.sealed_input_set_sha256.is_some());
    receipt
        .validate_sealed_strict_against(
            &submissions,
            &trusted_fixture,
            "gtkg.verifier/a06-sealed-strict",
        )
        .unwrap();
}

#[test]
fn a06_legacy_declared_small_cannot_hide_actual_oversize_or_digest_drift() {
    let trusted_fixture = persisted_fixture();
    let imports = FiveImports::load();
    let clean_legacy = imports.submissions();
    verify_adapter_gate_v1(
        &clean_legacy,
        &trusted_fixture.oracle,
        "gtkg.verifier/a06-legacy",
    )
    .expect("legacy predecessor demonstrates that unseen actual bytes are not checked");

    let mut oversized_actual = ActualAdapterInputs::load();
    oversized_actual.lsp = vec![b'x'; (MAX_ADAPTER_INPUT_BYTES_V1 + 1) as usize];
    let mut oversized = strict_submissions(&imports, &oversized_actual);
    oversized[2].submission.input_file_bytes = 1;
    assert_eq!(
        verify_adapter_gate_sealed_strict_v1(
            &oversized,
            &trusted_fixture,
            "gtkg.verifier/a06-sealed-strict"
        )
        .unwrap_err()
        .code(),
        "E_ADAPTER_SEALED_INPUT_MISMATCH"
    );

    let mut drifted_actual = ActualAdapterInputs::load();
    drifted_actual.codegraph = b"different-but-declared-small".to_vec();
    let mut drifted = strict_submissions(&imports, &drifted_actual);
    drifted[3].submission.input_file_bytes = 1;
    assert_eq!(
        verify_adapter_gate_sealed_strict_v1(
            &drifted,
            &trusted_fixture,
            "gtkg.verifier/a06-sealed-strict"
        )
        .unwrap_err()
        .code(),
        "E_ADAPTER_SEALED_INPUT_MISMATCH"
    );
}

#[test]
fn a06_sealed_strict_gate_rejects_configured_max_above_independent_cap() {
    let trusted_fixture = persisted_fixture();
    let imports = FiveImports::load();
    let actual = ActualAdapterInputs::load();
    let mut submissions = strict_submissions(&imports, &actual);
    submissions[2].submission.configured_max_file_bytes = MAX_ADAPTER_INPUT_BYTES_V1 + 1;
    assert_eq!(
        verify_adapter_gate_sealed_strict_v1(
            &submissions,
            &trusted_fixture,
            "gtkg.verifier/a06-sealed-strict"
        )
        .unwrap_err()
        .code(),
        "E_ADAPTER_INPUT_BUDGET"
    );
}
