use gtkg_protocol::v2::{V2OperationId, validate_v2_operation_payload};
use gtkg_protocol::v04::{PAYLOAD_REVISION, QUERY_POLICY};
use serde_json::{Value, json};
use std::collections::BTreeSet;

/// Inspect both published branches before applying the V0.3 field oracle.
pub fn legacy_payload(operation: V2OperationId, envelope: &Value) -> &Value {
    let payload = &envelope["properties"]["payload"];
    if !matches!(
        operation,
        V2OperationId::GraphSearch | V2OperationId::GraphExplain | V2OperationId::GraphTrace
    ) {
        assert!(payload.get("oneOf").is_none());
        return payload;
    }
    let branches = payload["oneOf"]
        .as_array()
        .expect("explicit revision branches");
    assert_eq!(branches.len(), 2);
    for branch in branches {
        assert_eq!(branch["type"], "object");
        assert_eq!(branch["additionalProperties"], false);
    }
    assert!(branches[0]["properties"].get("payload_revision").is_none());
    assert_eq!(
        branches[1]["properties"]["payload_revision"]["const"],
        PAYLOAD_REVISION
    );
    let mut current = json!({
        "payload_revision": PAYLOAD_REVISION,
        "workspace_root": ".",
        "index_ref": {"path":".gtkg/qk/index.json","sha256":format!("sha256:{}", "a".repeat(64))},
        "max_results": 10
    });
    let optional = if operation == V2OperationId::GraphSearch {
        current["query"] = json!("authentication");
        current["query_policy"] = json!(QUERY_POLICY);
        current["max_tokens"] = json!(1000);
        "continuation"
    } else {
        current["source_path"] = json!("src/lib.rs");
        current["max_depth"] = json!(2);
        "call_id"
    };
    let required = current
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        branches[1]["required"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect::<BTreeSet<_>>(),
        required
    );
    let mut properties = required;
    properties.insert(optional);
    assert_eq!(
        branches[1]["properties"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        properties
    );
    assert!(validate_v2_operation_payload(operation, &current).is_ok());
    current["unknown_field"] = json!(true);
    assert!(validate_v2_operation_payload(operation, &current).is_err());
    current.as_object_mut().unwrap().remove("unknown_field");
    current["payload_revision"] = json!("unsupported-revision");
    assert!(validate_v2_operation_payload(operation, &current).is_err());
    &branches[0]
}
