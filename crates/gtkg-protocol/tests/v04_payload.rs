use gtkg_protocol::v2::{V2OperationId as Op, V2_PUBLIC_OPERATIONS,validate_v2_operation_payload as validate,v2_operation_request_schema as schema};
use gtkg_protocol::v04::{accepts_knowledge_quality_payload,payload_schema};
use serde_json::{Value,json};
const REV:&str="gtkg.knowledge-quality/v0.4-r1";
fn source()->Value{json!({"payload_revision":REV,"repository_id":"agentnine","source_root":"/source","source_commit":"b219175c7c266915c13d987b7768fcf70cf3cbdf","expected_tree":"f86ccc1d260d816121f50ecd62acff81220f4401","output_path":"/work/archive","policy":{"revision":"full-tree-r1","rules":[],"archive_binary":false}})}
#[test]fn accepts_explicit_exact_source_revision(){assert!(validate(Op::SourceCapture,&source()).is_ok(),"explicit commit/tree successor source capture must be callable");}
#[test]fn closed_revision_rejects_typos_mixed_fields_and_unknown_nested_fields(){
 let mut p=source();p["payload_revision"]=json!("typo");assert!(validate(Op::SourceCapture,&p).is_err());
 p=source();p["capture_mode"]=json!("git_commit");assert!(validate(Op::SourceCapture,&p).is_err());
 p=source();p["policy"]["ignore_errors"]=json!(true);assert!(validate(Op::SourceCapture,&p).is_err());
 p=source();p["source_commit"]=json!("HEAD");assert!(validate(Op::SourceCapture,&p).is_err());
}
#[test]fn source_schema_keeps_original_branch(){let s=schema(Op::SourceCapture);let branches=s["properties"]["payload"]["oneOf"].as_array().expect("mutually exclusive old and new schemas");assert_eq!(branches.len(),2);assert_eq!(branches[0]["additionalProperties"],false);assert!(branches[0]["properties"]["capture_mode"].is_object());assert_eq!(branches[1]["properties"]["payload_revision"]["const"],REV);}
#[test]fn old_capture_still_valid_and_public_ids_unchanged(){assert!(validate(Op::SourceCapture,&json!({"capture_mode":"git_commit","repository_id":"r","source_root":"/source","output_path":"/work"})).is_ok());assert_eq!(V2_PUBLIC_OPERATIONS.len(),46);}
#[test]fn revision_does_not_unlock_unrelated_operations(){assert!(validate(Op::GitPublish,&json!({"payload_revision":REV})).is_err());}
#[test]fn knowledge_quality_disclosure_mirrors_the_closed_schema_set(){
 // Discovery must not leave the accepted payload revision implicit: a profile
 // lists operations, so a caller cannot tell which ones reject the V0.4 revision.
 for operation in V2_PUBLIC_OPERATIONS{
  assert_eq!(accepts_knowledge_quality_payload(operation.id),payload_schema(operation.id).is_some(),
   "knowledge-quality payload disclosure drifted from the closed schema set for {}",operation.id.as_str());
 }
 // The revision is additive on a strict subset, never on the whole registry.
 let accepted:Vec<&str>=V2_PUBLIC_OPERATIONS.iter().filter(|o|accepts_knowledge_quality_payload(o.id)).map(|o|o.id.as_str()).collect();
 assert!(accepted.len()<V2_PUBLIC_OPERATIONS.len(),"disclosure must stay a strict subset");
 for op in [Op::GraphNeighbors,Op::GraphPath,Op::GraphImpact]{
  assert!(!accepts_knowledge_quality_payload(op),"{} is reachable only through the default schema",op.as_str());
  assert!(validate(op,&json!({"payload_revision":REV})).is_err(),"{} must reject the knowledge-quality revision",op.as_str());
 }
 for op in [Op::GraphSearch,Op::GraphExplain,Op::GraphTrace]{assert!(accepts_knowledge_quality_payload(op),"{} must accept the knowledge-quality revision",op.as_str());}
}
#[test]fn manifest_plan_and_evidence_query_have_closed_successor_contracts(){
 let r=json!({"path":"archive/manifest.json","sha256":format!("sha256:{}","a".repeat(64))});
 assert!(validate(Op::AnalysisPlan,&json!({"payload_revision":REV,"workspace_root":"/work","artifact_ref":r})).is_ok());
 assert!(validate(Op::GraphSearch,&json!({"payload_revision":REV,"workspace_root":"/work","index_ref":r,"query":"会话是如何恢复的","query_policy":"gtkg.qk.query/v1","max_results":10,"max_tokens":8000,"continuation":null})).is_ok());
}
