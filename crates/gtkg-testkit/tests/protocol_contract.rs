use std::collections::BTreeMap;

use gtkg_core::{CallContext, Dispatcher};
use gtkg_protocol::{
    ErrorCode, ErrorEnvelope, OperationId, OperationRequest, OperationStatus, PROTOCOL_VERSION,
    PUBLIC_OPERATIONS,
};
use serde_json::json;

#[test]
fn public_operation_registry_is_exact_and_transport_addressable() {
    assert_eq!(PUBLIC_OPERATIONS.len(), 34);
    let ids: Vec<_> = PUBLIC_OPERATIONS
        .iter()
        .map(|item| item.id.as_str())
        .collect();
    assert_eq!(ids.first(), Some(&"system.describe"));
    assert_eq!(ids.last(), Some(&"a2ui.validate"));
    for operation in PUBLIC_OPERATIONS {
        assert_eq!(
            operation.id.mcp_tool_name(),
            format!("gtkg_{}", operation.id.as_str().replace('.', "_"))
        );
        assert_eq!(
            OperationId::parse(operation.id.as_str()),
            Some(operation.id)
        );
    }
}

#[test]
fn request_envelope_round_trips_without_transport_fields() {
    let request = OperationRequest {
        protocol_version: PROTOCOL_VERSION.to_owned(),
        operation_id: OperationId::BuildPlan,
        request_id: "req-contract-1".to_owned(),
        run_id: None,
        idempotency_key: Some("idem-contract-1".to_owned()),
        locks: BTreeMap::from([("source".to_owned(), "sha256:abc".to_owned())]),
        payload: json!({"mode": "full"}),
    };
    let encoded = serde_json::to_string(&request).expect("request serializes");
    let decoded: OperationRequest = serde_json::from_str(&encoded).expect("request parses");
    assert_eq!(decoded, request);
    assert!(!encoded.contains("mcp"));
    assert!(!encoded.contains("cli"));
}

#[test]
fn dispatcher_returns_stable_success_and_error_envelopes() {
    let dispatcher = Dispatcher::default();
    let response = dispatcher
        .execute(
            &CallContext::test(),
            OperationRequest::new(OperationId::SystemDescribe, "req-describe", json!({})),
        )
        .expect("system.describe is implemented");
    assert_eq!(response.status, OperationStatus::Completed);
    assert_eq!(response.request_id, "req-describe");

    let error = dispatcher
        .execute(
            &CallContext::test(),
            OperationRequest {
                protocol_version: "wrong".to_owned(),
                ..OperationRequest::new(OperationId::SystemDescribe, "req-bad", json!({}))
            },
        )
        .expect_err("wrong protocol is rejected");
    assert_eq!(error.error.code, ErrorCode::ProtocolVersionMismatch);
    let reparsed: ErrorEnvelope =
        serde_json::from_str(&serde_json::to_string(&error).expect("error serializes"))
            .expect("error parses");
    assert_eq!(reparsed, error);
}
