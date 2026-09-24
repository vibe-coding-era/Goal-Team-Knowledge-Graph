use gtkg_protocol::v2::{V2OperationId as Op,validate_v2_operation_payload as validate};
use serde_json::{Value,json};
fn payload(prefix:&str)->Value{json!({"payload_revision":"gtkg.knowledge-quality/v0.4-r1","repository_id":"agentnine","source_root":"/source","source_commit":"a".repeat(40),"expected_tree":"b".repeat(40),"output_path":"/workspace/archive","policy":{"revision":"explicit-scope/v1","rules":[{"path_prefix":prefix,"included":false,"rule_id":"exclude-tests","origin":"user","reason":"explicit requested scope"}],"archive_binary":false}})}
#[test]fn explicit_scope_accepts_nested_and_unicode_paths(){for p in ["internal/agent","docs/使用指南.md","frontend/src"]{assert!(validate(Op::SourceCapture,&payload(p)).is_ok(),"legitimate scope path {p}")}}
#[test]fn scope_rejects_escape_and_noncanonical_prefixes(){for p in ["../secret","/tmp","a/../b","a//b","a/./b","a\\b",""]{assert!(validate(Op::SourceCapture,&payload(p)).is_err(),"unsafe scope path {p}")}}
