use std::fs;

use gtkg_core::{CallContext, Dispatcher, EffectPolicy, TransportKind};
use gtkg_protocol::{
    ErrorCode, OperationAvailability, OperationId, OperationRequest, PROTOCOL_VERSION,
    PUBLIC_OPERATIONS,
};
use serde_json::{Value, json};
use tempfile::tempdir;

const OPERATION_IDS: [&str; 34] = [
    "system.describe",
    "config.validate",
    "source.inspect",
    "build.plan",
    "build.prepare",
    "summary.next",
    "summary.accept",
    "build.finalize",
    "run.get",
    "run.cancel",
    "bundle.verify",
    "bundle.query",
    "bundle.compare",
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
    "a2ui.resolve",
    "a2ui.generate",
    "a2ui.get",
    "a2ui.validate",
];

#[test]
fn all_34_public_operations_are_truthfully_implemented_and_internal_work_is_private() {
    assert_eq!(PUBLIC_OPERATIONS.len(), OPERATION_IDS.len());
    assert_eq!(
        PUBLIC_OPERATIONS
            .iter()
            .map(|definition| definition.id.as_str())
            .collect::<Vec<_>>(),
        OPERATION_IDS
    );
    assert!(
        PUBLIC_OPERATIONS
            .iter()
            .all(|definition| definition.availability == OperationAvailability::Implemented)
    );
    assert!(OperationId::parse("node.work.execute").is_none());
    assert!(
        gtkg_app::mcp_tools()
            .iter()
            .all(|tool| tool["name"] != "gtkg_node_work_execute")
    );

    let temp = tempdir().expect("temporary authorized root");
    let context = CallContext::restricted(
        TransportKind::Test,
        vec![temp.path().to_path_buf()],
        EffectPolicy::WorkspaceWrite,
    )
    .expect("bounded context");
    let response = Dispatcher
        .execute(
            &context,
            OperationRequest::new(OperationId::SystemDescribe, "d06-describe", json!({})),
        )
        .expect("system.describe");
    assert_eq!(response.result["public_operation_count"], 34);
    assert_eq!(response.result["implemented_operation_count"], 34);
    assert!(
        response.result["operations"]
            .as_array()
            .expect("operations")
            .iter()
            .all(|operation| operation["availability"] == "implemented")
    );
}

#[test]
fn every_mcp_tool_uses_an_operation_specific_closed_request_schema() {
    let tools = gtkg_app::mcp_tools();
    assert_eq!(tools.len(), OPERATION_IDS.len());
    for (tool, operation_id) in tools.iter().zip(OPERATION_IDS) {
        assert_eq!(
            tool["name"],
            format!("gtkg_{}", operation_id.replace('.', "_"))
        );
        assert_eq!(tool["x-gtkg-operation-id"], operation_id);
        assert_eq!(tool["x-gtkg-availability"], "implemented");

        let schema = &tool["inputSchema"];
        assert_eq!(schema["type"], "object", "{operation_id}");
        assert_eq!(schema["additionalProperties"], false, "{operation_id}");
        assert_eq!(
            schema["required"],
            json!(["protocol_version", "operation_id", "request_id", "payload"]),
            "{operation_id}"
        );
        assert_eq!(
            schema["properties"]["protocol_version"]["const"], PROTOCOL_VERSION,
            "{operation_id}"
        );
        assert_eq!(
            schema["properties"]["operation_id"]["const"], operation_id,
            "{operation_id}"
        );
        assert_eq!(
            schema["properties"]["payload"]["type"], "object",
            "{operation_id}"
        );
        assert_eq!(
            schema["properties"]["payload"]["additionalProperties"], false,
            "{operation_id}"
        );
        assert!(
            schema["properties"]["payload"]["properties"].is_object(),
            "{operation_id} must disclose payload fields"
        );
    }
}

#[test]
fn per_operation_schemas_are_distinct_and_do_not_accept_cross_operation_fields() {
    let tools = gtkg_app::mcp_tools();
    let schema = |id: &str| -> &Value {
        &tools
            .iter()
            .find(|tool| tool["x-gtkg-operation-id"] == id)
            .expect("tool exists")["inputSchema"]
    };
    assert!(
        schema("build.plan")["properties"]["payload"]["properties"]
            .get("source_inspection_ref")
            .is_some()
    );
    assert!(
        schema("build.plan")["properties"]["payload"]["properties"]
            .get("query")
            .is_none()
    );
    assert!(
        schema("bundle.query")["properties"]["payload"]["properties"]
            .get("query")
            .is_some()
    );
    assert!(
        schema("bundle.query")["properties"]["payload"]["properties"]
            .get("source_inspection_ref")
            .is_none()
    );
    assert!(
        schema("run.cancel")["properties"]["payload"]["properties"]
            .get("workspace_root")
            .is_some()
    );
    assert!(
        schema("current.activate")["properties"]["payload"]["properties"]
            .get("current_root")
            .is_some()
    );
}

#[test]
fn denied_effects_use_the_precise_side_effect_code_and_leave_no_files() {
    let temp = tempdir().expect("temporary authorized root");
    let root = temp.path().join("workspace");
    fs::create_dir(&root).expect("workspace");
    let before = directory_entries(&root);

    let read_only = CallContext::restricted(
        TransportKind::Test,
        vec![root.clone()],
        EffectPolicy::ReadOnly,
    )
    .expect("read-only context");
    let error = Dispatcher
        .execute(
            &read_only,
            OperationRequest::new(
                OperationId::SourceInspect,
                "d06-read-denied",
                json!({"workspace_root": root, "repositories": []}),
            ),
        )
        .expect_err("workspace mutation must be denied");
    assert_eq!(error.error.code, ErrorCode::SideEffectDenied);

    let workspace = CallContext::restricted(
        TransportKind::Test,
        vec![root.clone()],
        EffectPolicy::WorkspaceWrite,
    )
    .expect("workspace context");
    for operation in [
        OperationId::GitPublish,
        OperationId::CurrentActivate,
        OperationId::TemplatePublish,
        OperationId::DeliverablePublish,
    ] {
        let error = Dispatcher
            .execute(
                &workspace,
                OperationRequest::new(
                    operation,
                    format!("d06-denied-{}", operation.as_str()),
                    external_payload(operation, &root),
                ),
            )
            .expect_err("external effect must be denied without a grant");
        assert_eq!(error.error.code, ErrorCode::SideEffectDenied);
        assert_eq!(error.error.stage, "effect-policy");
    }
    assert_eq!(directory_entries(&root), before);
}

fn external_payload(operation: OperationId, root: &std::path::Path) -> Value {
    match operation {
        OperationId::GitPublish => json!({
            "workspace_root": root,
            "artifact_path": root.join("artifact"),
            "expected_tree_sha256": digest('1'),
            "repository_root": root.join("repo"),
            "ref_name": "refs/tags/gtkg-v0.1.0"
        }),
        OperationId::CurrentActivate => json!({
            "workspace_root": root,
            "current_root": root.join("current"),
            "version_path": root.join("versions/v0.1.0"),
            "expected_tree_sha256": digest('2')
        }),
        OperationId::TemplatePublish => json!({
            "workspace_root": root,
            "draft_ref": {"path": ".gtkg/template-drafts/draft.json", "sha256": digest('3')},
            "repository_root": root.join("repo"),
            "version": "0.1.0"
        }),
        OperationId::DeliverablePublish => json!({
            "workspace_root": root,
            "draft_ref": {"path": ".gtkg/deliverable-drafts/draft.json", "sha256": digest('4')},
            "repository_root": root.join("repo"),
            "version": "0.1.0"
        }),
        _ => unreachable!("only external operations are used"),
    }
}

fn directory_entries(path: &std::path::Path) -> Vec<String> {
    let mut entries = fs::read_dir(path)
        .expect("read directory")
        .map(|entry| {
            entry
                .expect("entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect::<Vec<_>>();
    entries.sort();
    entries
}

fn digest(fill: char) -> String {
    format!("sha256:{}", fill.to_string().repeat(64))
}
