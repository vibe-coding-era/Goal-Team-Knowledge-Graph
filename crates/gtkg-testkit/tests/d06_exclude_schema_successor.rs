use gtkg_protocol::{OperationId, PUBLIC_OPERATIONS, operation_request_schema};
use serde_json::json;

#[test]
fn v1_source_repository_exclude_restores_the_existing_optional_handler_field() {
    assert_eq!(PUBLIC_OPERATIONS.len(), 34);
    let request = operation_request_schema(OperationId::SourceInspect);
    let repository = &request["properties"]["payload"]["properties"]["repositories"]["items"];

    assert_eq!(repository["type"], "object");
    assert_eq!(repository["additionalProperties"], false);
    assert_eq!(
        repository["properties"]["exclude"],
        json!({
            "type": "array",
            "items": {"type": "string", "minLength": 1}
        })
    );
    assert_eq!(
        repository["properties"]["exclude"],
        repository["properties"]["include"]
    );
    assert_eq!(repository["required"], json!(["repo_id", "path"]));
}
