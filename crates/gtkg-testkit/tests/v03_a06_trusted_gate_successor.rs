include!("v03_a06_adapter_verifier_contract.rs");

use gtkg_core::v03::adapter::codegraph::CodeGraphImportReceiptV1;
use gtkg_core::v03::adapter::verifier::{
    AdapterTrustedOraclePinV1, verify_adapter_gate_with_trusted_oracle_v1,
};

fn trusted_material() -> (Value, AdapterTrustedOraclePinV1) {
    let material: Value = serde_json::from_slice(
        &fs::read(fixture("fixtures/v03_a06/trusted-oracle-pin.json")).unwrap(),
    )
    .unwrap();
    let pin = serde_json::from_value(material["pin"].clone()).unwrap();
    (material, pin)
}

fn reseal_gate(receipt: &mut gtkg_core::v03::adapter::verifier::AdapterGateReceiptV1) {
    receipt.receipt_sha256 = digest_without_receipt(serde_json::to_value(&*receipt).unwrap());
}

fn reseal_codegraph(receipt: &mut CodeGraphImportReceiptV1) {
    receipt.receipt_sha256 = digest_without_receipt(serde_json::to_value(&*receipt).unwrap());
}

#[test]
fn a06_trusted_source_judged_oracle_rejects_a_wrong_clean_self_derived_oracle() {
    let (material, pin) = trusted_material();
    assert_eq!(
        canonical_json_sha256(&material["review_material"]).unwrap(),
        pin.review_material_sha256
    );
    pin.validate().unwrap();

    let imports = FiveImports::load();
    let clean = imports.submissions();
    let clean_oracle = oracle(&clean);
    assert_eq!(clean_oracle.oracle_sha256, pin.expected_oracle_sha256);
    verify_adapter_gate_with_trusted_oracle_v1(
        &clean,
        &clean_oracle,
        &pin,
        "gtkg.verifier/a06-trusted",
    )
    .expect("source-judged clean oracle must match its independently frozen pin");

    let expected_target = imports.lsp.bundle.edges[0].candidate_node_ids[0].clone();
    let wrong_target = imports
        .lsp
        .bundle
        .nodes
        .iter()
        .map(|node| node.node_id.clone())
        .find(|node_id| *node_id != expected_target)
        .unwrap();
    let mut wrong_bundle = imports.lsp.bundle.clone();
    wrong_bundle.edges[0].candidate_node_ids = vec![wrong_target];
    let wrong_bundle = wrong_bundle.with_computed_digest().unwrap();
    let mut wrong_receipt = imports.lsp.receipt.clone();
    wrong_receipt.bundle_sha256 = wrong_bundle.bundle_sha256.clone();
    reseal_lsp(&mut wrong_receipt);
    assert!(wrong_receipt.validate().is_ok());
    let mut wrong = imports.submissions();
    wrong[2].bundle = &wrong_bundle;
    wrong[2].receipt = AdapterReceiptRefV1::Lsp(&wrong_receipt);
    let self_derived = oracle(&wrong);

    verify_adapter_gate_v1(&wrong, &self_derived, "gtkg.verifier/a06-self-derived")
        .expect("predecessor demonstrates why self-derived oracle authority is unsafe");
    assert_eq!(
        verify_adapter_gate_with_trusted_oracle_v1(
            &wrong,
            &self_derived,
            &pin,
            "gtkg.verifier/a06-trusted"
        )
        .unwrap_err()
        .code(),
        "E_ADAPTER_TRUSTED_ORACLE_MISMATCH"
    );
}

#[test]
fn a06_gate_receipt_validate_against_rejects_balanced_resealed_projection_tamper() {
    let (_material, pin) = trusted_material();
    let imports = FiveImports::load();
    let submissions = imports.submissions();
    let semantic_oracle = oracle(&submissions);
    let receipt = verify_adapter_gate_with_trusted_oracle_v1(
        &submissions,
        &semantic_oracle,
        &pin,
        "gtkg.verifier/a06-trusted",
    )
    .unwrap();
    receipt
        .validate_against(
            &submissions,
            &semantic_oracle,
            &pin,
            "gtkg.verifier/a06-trusted",
        )
        .unwrap();

    let mut mutations = Vec::new();

    let mut changed = receipt.clone();
    changed.evidence_count += 1;
    reseal_gate(&mut changed);
    mutations.push(changed);

    let mut changed = receipt.clone();
    changed.source_locator_count -= 1;
    reseal_gate(&mut changed);
    mutations.push(changed);

    let mut changed = receipt.clone();
    changed.resolved_verified_count -= 1;
    reseal_gate(&mut changed);
    mutations.push(changed);

    let mut changed = receipt;
    changed.collisions.same_name_conflicts.pop();
    reseal_gate(&mut changed);
    mutations.push(changed);

    for changed in mutations {
        changed.validate().unwrap();
        assert_eq!(
            changed
                .validate_against(
                    &submissions,
                    &semantic_oracle,
                    &pin,
                    "gtkg.verifier/a06-trusted",
                )
                .unwrap_err()
                .code(),
            "E_ADAPTER_GATE_RECEIPT_MISMATCH"
        );
    }
}

#[test]
fn a06_real_gate_includes_cross_adapter_edge_fact_id_collisions_without_a_winner() {
    let imports = FiveImports::load();
    let collision_id = "cross-adapter-edge-fact-collision".to_owned();

    let mut codegraph_bundle = imports.codegraph.bundle.clone();
    codegraph_bundle.edges[0].fact_id = collision_id.clone();
    let codegraph_bundle = codegraph_bundle.with_computed_digest().unwrap();
    let mut codegraph_receipt = imports.codegraph.receipt.clone();
    codegraph_receipt.bundle_sha256 = codegraph_bundle.bundle_sha256.clone();
    reseal_codegraph(&mut codegraph_receipt);
    assert!(codegraph_receipt.validate().is_ok());

    let mut graphify_bundle = imports.graphify.bundle.clone();
    graphify_bundle.edges[0].fact_id = collision_id.clone();
    let graphify_bundle = graphify_bundle.with_computed_digest().unwrap();
    let mut graphify_receipt = imports.graphify.receipt.clone();
    graphify_receipt.bundle_sha256 = graphify_bundle.bundle_sha256.clone();
    reseal_graphify(&mut graphify_receipt);
    assert!(graphify_receipt.validate().is_ok());

    let mut submissions = imports.submissions();
    submissions[3].bundle = &codegraph_bundle;
    submissions[3].receipt = AdapterReceiptRefV1::CodeGraph(&codegraph_receipt);
    submissions[4].bundle = &graphify_bundle;
    submissions[4].receipt = AdapterReceiptRefV1::GraphifyV2(&graphify_receipt);
    let semantic_oracle = oracle(&submissions);
    let receipt = verify_adapter_gate_v1(
        &submissions,
        &semantic_oracle,
        "gtkg.verifier/a06-edge-collision",
    )
    .unwrap();

    let collision = receipt
        .collisions
        .fact_id_collisions
        .iter()
        .find(|group| group.key == collision_id)
        .expect("real edge facts must participate in Gate collision aggregation");
    assert_eq!(collision.members.len(), 2);
    assert!(collision.selected_fact_id.is_none());
    assert!(receipt.collisions.selected_fact_ids.is_empty());
    assert_eq!(receipt.canonical_write_count, 0);
}
