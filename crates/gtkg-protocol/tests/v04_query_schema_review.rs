//! Exact discovery/runtime agreement for the three explicit QK query policies.
use gtkg_protocol::v04::{self, QUERY_POLICY, SELECTIVE_QUERY_POLICY, REVIEWED_CONTEXT_QUERY_POLICY};
use gtkg_protocol::v2::V2OperationId as Op;
use serde_json::json;

#[test]
fn query_discovery_names_only_supported_policies_and_the_actual_output_limit() {
    let schema=v04::payload_schema(Op::GraphSearch).expect("query schema");
    assert_eq!(schema["properties"]["query_policy"]["enum"],json!([QUERY_POLICY,SELECTIVE_QUERY_POLICY,REVIEWED_CONTEXT_QUERY_POLICY]));
    assert_eq!(schema["properties"]["max_results"]["minimum"],1);
    assert_eq!(schema["properties"]["max_results"]["maximum"],1000);
    assert_eq!(schema["properties"]["max_tokens"]["minimum"],1);
    assert_eq!(schema["properties"]["max_tokens"]["maximum"],8000);
    let pack=v04::payload_schema(Op::ContextPack).expect("pack schema");
    assert_eq!(pack["oneOf"][0],schema);
    let mut payload=json!({"payload_revision":v04::PAYLOAD_REVISION,"workspace_root":"/work","index_ref":{"path":"index.json","sha256":format!("sha256:{}","a".repeat(64))},"query":"public fixture","query_policy":QUERY_POLICY,"max_results":1,"max_tokens":8000,"continuation":null});
    for policy in [QUERY_POLICY,SELECTIVE_QUERY_POLICY,REVIEWED_CONTEXT_QUERY_POLICY] {
        payload["query_policy"]=json!(policy);
        assert!(v04::validate_payload(Op::GraphSearch,&payload).is_ok());
        assert!(v04::validate_payload(Op::ContextPack,&payload).is_ok());
    }
    payload["max_tokens"]=json!(8001);
    assert!(v04::validate_payload(Op::GraphSearch,&payload).is_err());
    payload["max_tokens"]=json!(8000);payload["query_policy"]=json!("unknown");
    assert!(v04::validate_payload(Op::GraphSearch,&payload).is_err());
}
