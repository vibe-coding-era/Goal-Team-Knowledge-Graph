//! T08: the V0.2 transport registry is versioned and deliberately honest.

use gtkg_core::{CallContext, Dispatcher, EffectPolicy, TransportKind};
use gtkg_protocol::{
    OperationId, PUBLIC_OPERATIONS,
    v2::{
        CallabilityV2, OperationAvailabilityV2, OperationRequestV2, V1_ONLY_OPERATION_IDS_V2,
        V2_PUBLIC_OPERATIONS, V2ErrorCode, V2OperationId,
    },
};
use serde_json::json;
use tempfile::tempdir;

const V2_OPERATION_IDS: [&str; 46] = [
    "system.describe",
    "config.validate",
    "capability.describe",
    "source.capture",
    "analysis.plan",
    "analysis.build",
    "analysis.verify",
    "build.finalize.v2",
    "context.pack",
    "summary.job.next",
    "summary.proposal.submit",
    "summary.verification.next",
    "summary.verification.submit",
    "summary.accept.v2",
    "run.get",
    "run.cancel",
    "bundle.verify",
    "bundle.compare",
    "bundle.migrate.v1_to_v2",
    "snapshot.create",
    "snapshot.verify",
    "snapshot.restore",
    "git.publish",
    "current.get",
    "current.activate",
    "node.describe",
    "federation.validate",
    "template.list",
    "template.resolve",
    "template.prefetch",
    "template.get",
    "template.validate",
    "template.derive",
    "template.publish",
    "deliverable.derive",
    "deliverable.publish",
    "graph.neighbors",
    "graph.path",
    "graph.impact",
    "graph.explain",
    "graph.trace",
    "graph.search",
    "a2ui.resolve",
    "a2ui.generate",
    "a2ui.get",
    "a2ui.validate",
];

const V1_ONLY_IDS: [&str; 7] = [
    "source.inspect",
    "build.plan",
    "build.prepare",
    "build.finalize",
    "summary.next",
    "summary.accept",
    "bundle.query",
];

#[test]
fn v2_exact_registry_is_complete_and_does_not_mutate_the_frozen_v1_registry() {
    assert_eq!(V2_PUBLIC_OPERATIONS.len(), V2_OPERATION_IDS.len());
    assert_eq!(
        V2_PUBLIC_OPERATIONS
            .iter()
            .map(|definition| definition.id.as_str())
            .collect::<Vec<_>>(),
        V2_OPERATION_IDS,
    );
    assert_eq!(V1_ONLY_OPERATION_IDS_V2, V1_ONLY_IDS);
    for id in V1_ONLY_IDS {
        assert!(V2OperationId::parse(id).is_none(), "{id} leaked into v2");
    }

    // This is intentionally the V0.1 exact set. T08 must not grow it.
    assert_eq!(PUBLIC_OPERATIONS.len(), 34);
    assert_eq!(OperationId::parse("source.capture"), None);
}

#[test]
fn v2_presence_implementation_and_callability_are_separate_axes() {
    let structural = [
        V2OperationId::GraphNeighbors,
        V2OperationId::GraphPath,
        V2OperationId::GraphImpact,
        V2OperationId::GraphExplain,
        V2OperationId::GraphTrace,
        V2OperationId::GraphSearch,
    ];
    assert!(V2_PUBLIC_OPERATIONS.iter().all(|definition| {
        if structural.contains(&definition.id) {
            definition.availability == OperationAvailabilityV2::Implemented
                && definition.callability == CallabilityV2::Callable
        } else {
            definition.availability == OperationAvailabilityV2::NotImplemented
                && definition.callability == CallabilityV2::NotImplemented
        }
    }));
    let disclosure = serde_json::to_value(V2_PUBLIC_OPERATIONS[0]).unwrap();
    assert_eq!(disclosure["availability"], "not_implemented");
    assert_eq!(disclosure["callability"], "not_implemented");
    let graph_disclosure = serde_json::to_value(
        V2_PUBLIC_OPERATIONS
            .iter()
            .find(|definition| definition.id == V2OperationId::GraphNeighbors)
            .expect("registered structural query"),
    )
    .unwrap();
    assert_eq!(graph_disclosure["availability"], "implemented");
    assert_eq!(graph_disclosure["callability"], "callable");
    assert!(
        disclosure.get("availability").is_some() && disclosure.get("callability").is_some(),
        "implementation availability and current callability are separate disclosures",
    );
    assert_eq!(
        [
            CallabilityV2::Callable,
            CallabilityV2::DeniedByPolicy,
            CallabilityV2::MissingHostCapability,
            CallabilityV2::NotImplemented,
        ]
        .len(),
        4,
    );
}

#[test]
fn v2_rejects_v1_only_ids_before_any_handler_and_is_honest_about_unimplemented_ids() {
    let temp = tempdir().expect("temporary authorized root");
    let context = CallContext::restricted(
        TransportKind::Test,
        vec![temp.path().to_path_buf()],
        EffectPolicy::WorkspaceWrite,
    )
    .expect("bounded context");

    for id in V1_ONLY_IDS {
        let error = Dispatcher
            .execute_v2(
                &context,
                OperationRequestV2::new(id, "v2-v1-only", json!({})),
            )
            .expect_err("v1-only id must be version-rejected");
        assert_eq!(error.error.code, V2ErrorCode::OperationVersionUnsupported);
    }

    let error = Dispatcher
        .execute_v2(
            &context,
            OperationRequestV2::new("source.capture", "v2-unimplemented", json!({})),
        )
        .expect_err("registry presence cannot pretend to be an implementation");
    assert_eq!(error.error.code, V2ErrorCode::OperationNotImplemented);
}
