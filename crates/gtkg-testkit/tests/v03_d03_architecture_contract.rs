use std::collections::{BTreeMap, BTreeSet};

use gtkg_core::v03::validate_architecture_contract_v03;
use gtkg_protocol::v03::{
    ASSISTANT_INSTALL_RECEIPT_IDENTITY_V1, DiscoveryProfileIdV1,
    INSTALL_MANIFEST_IDENTITY_V1, QUERY_INDEX_MANIFEST_IDENTITY_V1,
    QUERY_PLAN_RECEIPT_IDENTITY_V1, adapter_manifest_identity_contracts_v03,
    discovery_profiles_v03, failure_mode_contracts_v03, handler_partitions_v03,
    operation_bindings_v03,
};
use gtkg_protocol::v2::V2_PUBLIC_OPERATIONS;

fn operation_ids(values: &[gtkg_protocol::v2::V2OperationId]) -> Vec<&'static str> {
    values.iter().map(|value| value.as_str()).collect()
}

#[test]
fn d03_freezes_all_46_operation_bindings_and_handler_ownership() {
    let bindings = operation_bindings_v03();
    assert_eq!(bindings.len(), 46);

    let registry_ids = V2_PUBLIC_OPERATIONS
        .iter()
        .map(|definition| definition.id.as_str())
        .collect::<BTreeSet<_>>();
    let binding_ids = bindings
        .iter()
        .map(|binding| binding.operation_id.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(binding_ids, registry_ids);

    let handler_ids = bindings
        .iter()
        .map(|binding| binding.handler_id.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(handler_ids.len(), 46);
    assert!(bindings.iter().all(|binding| {
        binding.schema_sha256.starts_with("sha256:")
            && binding.schema_sha256.len() == 71
            && binding
                .schema_sha256
                .strip_prefix("sha256:")
                .is_some_and(|digest| digest.bytes().all(|byte| byte.is_ascii_hexdigit()))
    }));

    let partition_ids = handler_partitions_v03()
        .iter()
        .flat_map(|partition| partition.operation_ids.iter().copied())
        .collect::<Vec<_>>();
    assert_eq!(partition_ids.len(), 46);
    assert_eq!(partition_ids.iter().copied().collect::<BTreeSet<_>>(), registry_ids);
    validate_architecture_contract_v03().expect("D03 architecture contract must be closed");
}

#[test]
fn d03_freezes_seven_digest_bound_discovery_profiles() {
    let profiles = discovery_profiles_v03();
    assert_eq!(profiles.len(), 7);
    assert_eq!(profiles.iter().filter(|profile| profile.is_default).count(), 1);

    let by_id = profiles
        .iter()
        .map(|profile| (profile.profile_id, profile))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(operation_ids(&by_id[&DiscoveryProfileIdV1::Core].operation_ids), vec![
        "system.describe", "config.validate", "capability.describe", "source.capture",
        "analysis.plan", "analysis.build", "analysis.verify", "build.finalize.v2",
        "context.pack", "graph.search",
    ]);
    assert_eq!(operation_ids(&by_id[&DiscoveryProfileIdV1::Graph].operation_ids), vec![
        "graph.neighbors", "graph.path", "graph.impact", "graph.explain", "graph.trace",
        "graph.search",
    ]);
    assert_eq!(operation_ids(&by_id[&DiscoveryProfileIdV1::Authoring].operation_ids), vec![
        "context.pack", "summary.job.next", "summary.proposal.submit",
        "summary.verification.next", "summary.verification.submit", "summary.accept.v2",
        "analysis.verify", "build.finalize.v2",
    ]);
    assert_eq!(by_id[&DiscoveryProfileIdV1::Lifecycle].operation_ids.len(), 13);
    assert_eq!(by_id[&DiscoveryProfileIdV1::Templates].operation_ids.len(), 9);
    assert_eq!(by_id[&DiscoveryProfileIdV1::A2ui].operation_ids.len(), 4);
    assert_eq!(by_id[&DiscoveryProfileIdV1::All].operation_ids.len(), 46);
    assert!(profiles.iter().all(|profile| profile.validate().is_ok()));
}

#[test]
fn d03_freezes_adapter_query_and_install_identity_manifests() {
    let adapters = adapter_manifest_identity_contracts_v03();
    assert_eq!(adapters.len(), 5);
    assert_eq!(
        adapters.iter().map(|contract| contract.kind.as_str()).collect::<Vec<_>>(),
        vec!["native", "scip", "lsp_snapshot", "codegraph_export", "graphify_export"]
    );
    assert!(adapters.iter().all(|contract| {
        contract.required_identity_fields.contains(&"adapter_id")
            && contract.required_identity_fields.contains(&"schema_sha256")
            && contract.required_identity_fields.contains(&"source_commit")
            && contract.required_identity_fields.contains(&"license")
    }));

    assert!(QUERY_INDEX_MANIFEST_IDENTITY_V1.required_identity_fields.contains(&"source_identity"));
    assert!(QUERY_INDEX_MANIFEST_IDENTITY_V1.required_identity_fields.contains(&"tokenizer_id"));
    assert!(QUERY_PLAN_RECEIPT_IDENTITY_V1.required_identity_fields.contains(&"selected_shards"));
    assert!(QUERY_PLAN_RECEIPT_IDENTITY_V1.required_identity_fields.contains(&"budget"));
    assert!(INSTALL_MANIFEST_IDENTITY_V1.required_identity_fields.contains(&"platform"));
    assert!(INSTALL_MANIFEST_IDENTITY_V1.required_identity_fields.contains(&"files"));
    assert!(ASSISTANT_INSTALL_RECEIPT_IDENTITY_V1.required_identity_fields.contains(&"before_sha256"));
    assert!(ASSISTANT_INSTALL_RECEIPT_IDENTITY_V1.required_identity_fields.contains(&"managed_block_sha256"));
}

#[test]
fn d03_freezes_prd_failure_modes_without_claiming_behavior() {
    let failures = failure_mode_contracts_v03();
    assert_eq!(failures.len(), 18);
    let ids = failures.iter().map(|failure| failure.failure_id).collect::<BTreeSet<_>>();
    assert_eq!(ids.len(), 18);

    let codes = failures
        .iter()
        .map(|failure| (failure.failure_id, failure.code))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(codes["FM-302"], "E_PROFILE_STALE");
    assert_eq!(codes["FM-303"], "E_ADAPTER_IDENTITY_MISMATCH");
    assert_eq!(codes["FM-305"], "E_TRUST_LAUNDERING");
    assert_eq!(codes["FM-306"], "E_QUERY_INDEX_STALE");
    assert_eq!(codes["FM-308"], "E_QUERY_EAGER_READ");
    assert_eq!(codes["FM-312"], "E_INSTALL_CAS_CONFLICT");
    assert!(failures.iter().all(|failure| !failure.required_behavior.is_empty()));
}
