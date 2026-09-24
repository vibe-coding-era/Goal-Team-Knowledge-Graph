//! Transport-neutral GTKG protocol contracts.

pub mod v03;
pub mod v04;
/// Versioned V0.2 internal contracts.  The v1 public protocol remains frozen
/// until the dedicated T08 version-negotiation surface is implemented.
pub mod v2;

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const PROTOCOL_VERSION: &str = "gtkg.protocol/v1";
pub const CORE_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
pub enum OperationId {
    #[serde(rename = "system.describe")]
    SystemDescribe,
    #[serde(rename = "config.validate")]
    ConfigValidate,
    #[serde(rename = "source.inspect")]
    SourceInspect,
    #[serde(rename = "build.plan")]
    BuildPlan,
    #[serde(rename = "build.prepare")]
    BuildPrepare,
    #[serde(rename = "summary.next")]
    SummaryNext,
    #[serde(rename = "summary.accept")]
    SummaryAccept,
    #[serde(rename = "build.finalize")]
    BuildFinalize,
    #[serde(rename = "run.get")]
    RunGet,
    #[serde(rename = "run.cancel")]
    RunCancel,
    #[serde(rename = "bundle.verify")]
    BundleVerify,
    #[serde(rename = "bundle.query")]
    BundleQuery,
    #[serde(rename = "bundle.compare")]
    BundleCompare,
    #[serde(rename = "snapshot.create")]
    SnapshotCreate,
    #[serde(rename = "snapshot.verify")]
    SnapshotVerify,
    #[serde(rename = "snapshot.restore")]
    SnapshotRestore,
    #[serde(rename = "git.publish")]
    GitPublish,
    #[serde(rename = "current.get")]
    CurrentGet,
    #[serde(rename = "current.activate")]
    CurrentActivate,
    #[serde(rename = "node.describe")]
    NodeDescribe,
    #[serde(rename = "federation.validate")]
    FederationValidate,
    #[serde(rename = "template.list")]
    TemplateList,
    #[serde(rename = "template.resolve")]
    TemplateResolve,
    #[serde(rename = "template.prefetch")]
    TemplatePrefetch,
    #[serde(rename = "template.get")]
    TemplateGet,
    #[serde(rename = "template.validate")]
    TemplateValidate,
    #[serde(rename = "template.derive")]
    TemplateDerive,
    #[serde(rename = "template.publish")]
    TemplatePublish,
    #[serde(rename = "deliverable.derive")]
    DeliverableDerive,
    #[serde(rename = "deliverable.publish")]
    DeliverablePublish,
    #[serde(rename = "a2ui.resolve")]
    A2uiResolve,
    #[serde(rename = "a2ui.generate")]
    A2uiGenerate,
    #[serde(rename = "a2ui.get")]
    A2uiGet,
    #[serde(rename = "a2ui.validate")]
    A2uiValidate,
}

impl OperationId {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SystemDescribe => "system.describe",
            Self::ConfigValidate => "config.validate",
            Self::SourceInspect => "source.inspect",
            Self::BuildPlan => "build.plan",
            Self::BuildPrepare => "build.prepare",
            Self::SummaryNext => "summary.next",
            Self::SummaryAccept => "summary.accept",
            Self::BuildFinalize => "build.finalize",
            Self::RunGet => "run.get",
            Self::RunCancel => "run.cancel",
            Self::BundleVerify => "bundle.verify",
            Self::BundleQuery => "bundle.query",
            Self::BundleCompare => "bundle.compare",
            Self::SnapshotCreate => "snapshot.create",
            Self::SnapshotVerify => "snapshot.verify",
            Self::SnapshotRestore => "snapshot.restore",
            Self::GitPublish => "git.publish",
            Self::CurrentGet => "current.get",
            Self::CurrentActivate => "current.activate",
            Self::NodeDescribe => "node.describe",
            Self::FederationValidate => "federation.validate",
            Self::TemplateList => "template.list",
            Self::TemplateResolve => "template.resolve",
            Self::TemplatePrefetch => "template.prefetch",
            Self::TemplateGet => "template.get",
            Self::TemplateValidate => "template.validate",
            Self::TemplateDerive => "template.derive",
            Self::TemplatePublish => "template.publish",
            Self::DeliverableDerive => "deliverable.derive",
            Self::DeliverablePublish => "deliverable.publish",
            Self::A2uiResolve => "a2ui.resolve",
            Self::A2uiGenerate => "a2ui.generate",
            Self::A2uiGet => "a2ui.get",
            Self::A2uiValidate => "a2ui.validate",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        PUBLIC_OPERATIONS
            .iter()
            .find(|operation| operation.id.as_str() == value)
            .map(|operation| operation.id)
    }

    pub fn from_mcp_tool_name(value: &str) -> Option<Self> {
        PUBLIC_OPERATIONS
            .iter()
            .find(|operation| operation.id.mcp_tool_name() == value)
            .map(|operation| operation.id)
    }

    pub fn mcp_tool_name(self) -> String {
        format!("gtkg_{}", self.as_str().replace('.', "_"))
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum SideEffectClass {
    Read,
    RunLocalWrite,
    CandidateWrite,
    ReceiptWrite,
    CacheWrite,
    DraftWrite,
    VersionWrite,
    GitExternalWrite,
    CurrentWrite,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OperationAvailability {
    Implemented,
    NotImplemented,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct OperationDefinition {
    pub id: OperationId,
    pub side_effect: SideEffectClass,
    pub availability: OperationAvailability,
}

const fn operation(
    id: OperationId,
    side_effect: SideEffectClass,
    availability: OperationAvailability,
) -> OperationDefinition {
    OperationDefinition {
        id,
        side_effect,
        availability,
    }
}

pub const PUBLIC_OPERATIONS: &[OperationDefinition] = &[
    operation(
        OperationId::SystemDescribe,
        SideEffectClass::Read,
        OperationAvailability::Implemented,
    ),
    operation(
        OperationId::ConfigValidate,
        SideEffectClass::Read,
        OperationAvailability::Implemented,
    ),
    operation(
        OperationId::SourceInspect,
        SideEffectClass::RunLocalWrite,
        OperationAvailability::Implemented,
    ),
    operation(
        OperationId::BuildPlan,
        SideEffectClass::RunLocalWrite,
        OperationAvailability::Implemented,
    ),
    operation(
        OperationId::BuildPrepare,
        SideEffectClass::CandidateWrite,
        OperationAvailability::Implemented,
    ),
    operation(
        OperationId::SummaryNext,
        SideEffectClass::Read,
        OperationAvailability::Implemented,
    ),
    operation(
        OperationId::SummaryAccept,
        SideEffectClass::CandidateWrite,
        OperationAvailability::Implemented,
    ),
    operation(
        OperationId::BuildFinalize,
        SideEffectClass::CandidateWrite,
        OperationAvailability::Implemented,
    ),
    operation(
        OperationId::RunGet,
        SideEffectClass::Read,
        OperationAvailability::Implemented,
    ),
    operation(
        OperationId::RunCancel,
        SideEffectClass::RunLocalWrite,
        OperationAvailability::Implemented,
    ),
    operation(
        OperationId::BundleVerify,
        SideEffectClass::ReceiptWrite,
        OperationAvailability::Implemented,
    ),
    operation(
        OperationId::BundleQuery,
        SideEffectClass::Read,
        OperationAvailability::Implemented,
    ),
    operation(
        OperationId::BundleCompare,
        SideEffectClass::Read,
        OperationAvailability::Implemented,
    ),
    operation(
        OperationId::SnapshotCreate,
        SideEffectClass::VersionWrite,
        OperationAvailability::Implemented,
    ),
    operation(
        OperationId::SnapshotVerify,
        SideEffectClass::ReceiptWrite,
        OperationAvailability::Implemented,
    ),
    operation(
        OperationId::SnapshotRestore,
        SideEffectClass::CandidateWrite,
        OperationAvailability::Implemented,
    ),
    operation(
        OperationId::GitPublish,
        SideEffectClass::GitExternalWrite,
        OperationAvailability::Implemented,
    ),
    operation(
        OperationId::CurrentGet,
        SideEffectClass::Read,
        OperationAvailability::Implemented,
    ),
    operation(
        OperationId::CurrentActivate,
        SideEffectClass::CurrentWrite,
        OperationAvailability::Implemented,
    ),
    operation(
        OperationId::NodeDescribe,
        SideEffectClass::RunLocalWrite,
        OperationAvailability::Implemented,
    ),
    operation(
        OperationId::FederationValidate,
        SideEffectClass::ReceiptWrite,
        OperationAvailability::Implemented,
    ),
    operation(
        OperationId::TemplateList,
        SideEffectClass::Read,
        OperationAvailability::Implemented,
    ),
    operation(
        OperationId::TemplateResolve,
        SideEffectClass::RunLocalWrite,
        OperationAvailability::Implemented,
    ),
    operation(
        OperationId::TemplatePrefetch,
        SideEffectClass::CacheWrite,
        OperationAvailability::Implemented,
    ),
    operation(
        OperationId::TemplateGet,
        SideEffectClass::Read,
        OperationAvailability::Implemented,
    ),
    operation(
        OperationId::TemplateValidate,
        SideEffectClass::ReceiptWrite,
        OperationAvailability::Implemented,
    ),
    operation(
        OperationId::TemplateDerive,
        SideEffectClass::DraftWrite,
        OperationAvailability::Implemented,
    ),
    operation(
        OperationId::TemplatePublish,
        SideEffectClass::GitExternalWrite,
        OperationAvailability::Implemented,
    ),
    operation(
        OperationId::DeliverableDerive,
        SideEffectClass::DraftWrite,
        OperationAvailability::Implemented,
    ),
    operation(
        OperationId::DeliverablePublish,
        SideEffectClass::GitExternalWrite,
        OperationAvailability::Implemented,
    ),
    operation(
        OperationId::A2uiResolve,
        SideEffectClass::RunLocalWrite,
        OperationAvailability::Implemented,
    ),
    operation(
        OperationId::A2uiGenerate,
        SideEffectClass::CandidateWrite,
        OperationAvailability::Implemented,
    ),
    operation(
        OperationId::A2uiGet,
        SideEffectClass::Read,
        OperationAvailability::Implemented,
    ),
    operation(
        OperationId::A2uiValidate,
        SideEffectClass::ReceiptWrite,
        OperationAvailability::Implemented,
    ),
];

pub fn operation_definition(id: OperationId) -> Option<&'static OperationDefinition> {
    PUBLIC_OPERATIONS
        .iter()
        .find(|definition| definition.id == id)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OperationPayloadContract {
    pub properties: &'static [&'static str],
    pub required: &'static [&'static str],
}

/// Return the closed, transport-neutral payload field contract for one public
/// operation. The same table drives Dispatcher preflight and MCP discovery.
pub const fn operation_payload_contract(id: OperationId) -> OperationPayloadContract {
    use OperationId::*;
    match id {
        SystemDescribe => contract(&[], &[]),
        ConfigValidate => contract(&["config_path"], &["config_path"]),
        SourceInspect => contract(
            &["workspace_root", "repositories"],
            &["workspace_root", "repositories"],
        ),
        BuildPlan => contract(
            &[
                "workspace_root",
                "mode",
                "source_inspection_ref",
                "template_validation_ref",
                "baseline_bundle",
                "baseline_tree_sha256",
                "bundle_version",
            ],
            &[
                "workspace_root",
                "mode",
                "source_inspection_ref",
                "template_validation_ref",
                "bundle_version",
            ],
        ),
        BuildPrepare | SummaryNext | BuildFinalize | RunGet | RunCancel => {
            contract(&["workspace_root"], &["workspace_root"])
        }
        SummaryAccept => contract(
            &[
                "workspace_root",
                "packet_id",
                "source_sha256",
                "template_manifest_sha256",
                "summary_markdown",
            ],
            &[
                "workspace_root",
                "packet_id",
                "source_sha256",
                "template_manifest_sha256",
                "summary_markdown",
            ],
        ),
        BundleVerify => contract(
            &[
                "bundle_path",
                "expected_tree_sha256",
                "expected_manifest_sha256",
            ],
            &["bundle_path"],
        ),
        BundleQuery => contract(
            &["bundle_path", "expected_tree_sha256", "query"],
            &["bundle_path", "query"],
        ),
        BundleCompare => contract(
            &[
                "left_bundle",
                "left_expected_tree_sha256",
                "right_bundle",
                "right_expected_tree_sha256",
            ],
            &["left_bundle", "right_bundle"],
        ),
        SnapshotCreate => contract(
            &[
                "workspace_root",
                "bundle_path",
                "expected_bundle_tree_sha256",
                "snapshot_version",
            ],
            &["workspace_root", "bundle_path", "snapshot_version"],
        ),
        SnapshotVerify => contract(
            &["snapshot_path", "expected_snapshot_tree_sha256"],
            &["snapshot_path"],
        ),
        SnapshotRestore => contract(
            &[
                "workspace_root",
                "snapshot_path",
                "expected_snapshot_tree_sha256",
                "restore_version",
            ],
            &["workspace_root", "snapshot_path", "restore_version"],
        ),
        GitPublish => contract(
            &[
                "workspace_root",
                "artifact_path",
                "expected_tree_sha256",
                "repository_root",
                "ref_name",
            ],
            &[
                "workspace_root",
                "artifact_path",
                "expected_tree_sha256",
                "repository_root",
                "ref_name",
            ],
        ),
        CurrentGet => contract(
            &["current_path", "expected_current_sha256"],
            &["current_path", "expected_current_sha256"],
        ),
        CurrentActivate => contract(
            &[
                "workspace_root",
                "current_root",
                "version_path",
                "expected_tree_sha256",
            ],
            &[
                "workspace_root",
                "current_root",
                "version_path",
                "expected_tree_sha256",
            ],
        ),
        NodeDescribe => contract(
            &["descriptor", "probe_sandbox", "sandbox_policy"],
            &["descriptor"],
        ),
        FederationValidate => contract(
            &["nodes", "work_units", "shard_results", "workspace_root"],
            &["nodes", "work_units", "shard_results"],
        ),
        TemplateList => contract(&["catalog_root"], &["catalog_root"]),
        TemplateResolve => contract(
            &["workspace_root", "catalog_root", "template_id", "version"],
            &["workspace_root", "catalog_root", "template_id", "version"],
        ),
        TemplatePrefetch => contract(
            &["workspace_root", "resolution_ref"],
            &["workspace_root", "resolution_ref"],
        ),
        TemplateGet => contract(
            &["workspace_root", "template_ref"],
            &["workspace_root", "template_ref"],
        ),
        TemplateValidate => contract(
            &["workspace_root", "resolution_ref"],
            &["workspace_root", "resolution_ref"],
        ),
        TemplateDerive => contract(
            &[
                "workspace_root",
                "parent_ref",
                "new_version",
                "slot_overrides",
            ],
            &[
                "workspace_root",
                "parent_ref",
                "new_version",
                "slot_overrides",
            ],
        ),
        TemplatePublish | DeliverablePublish => contract(
            &["workspace_root", "draft_ref", "repository_root", "version"],
            &["workspace_root", "draft_ref", "repository_root", "version"],
        ),
        DeliverableDerive => contract(
            &[
                "workspace_root",
                "parent_path",
                "expected_parent_tree_sha256",
                "deliverable_id",
                "new_version",
                "slot_overrides",
            ],
            &[
                "workspace_root",
                "parent_path",
                "expected_parent_tree_sha256",
                "deliverable_id",
                "new_version",
                "slot_overrides",
            ],
        ),
        A2uiResolve => contract(
            &[
                "workspace_root",
                "catalog_root",
                "spec_version",
                "profile_id",
                "profile_version",
                "catalog_id",
                "catalog_version",
                "renderer_id",
                "renderer_version",
                "expected_manifest_sha256",
            ],
            &[
                "workspace_root",
                "catalog_root",
                "spec_version",
                "profile_id",
                "profile_version",
                "catalog_id",
                "catalog_version",
                "renderer_id",
                "renderer_version",
                "expected_manifest_sha256",
            ],
        ),
        A2uiGenerate => contract(
            &[
                "workspace_root",
                "bundle_path",
                "expected_bundle_tree_sha256",
                "resolution_ref",
                "projection_version",
            ],
            &[
                "workspace_root",
                "bundle_path",
                "expected_bundle_tree_sha256",
                "resolution_ref",
                "projection_version",
            ],
        ),
        A2uiGet => contract(
            &[
                "workspace_root",
                "generation_ref",
                "expected_projection_tree_sha256",
            ],
            &[
                "workspace_root",
                "generation_ref",
                "expected_projection_tree_sha256",
            ],
        ),
        A2uiValidate => contract(
            &[
                "workspace_root",
                "generation_ref",
                "expected_projection_tree_sha256",
                "required_evidence_state",
                "renderer_smoke_ref",
            ],
            &[
                "workspace_root",
                "generation_ref",
                "expected_projection_tree_sha256",
                "required_evidence_state",
            ],
        ),
    }
}

const fn contract(
    properties: &'static [&'static str],
    required: &'static [&'static str],
) -> OperationPayloadContract {
    OperationPayloadContract {
        properties,
        required,
    }
}

pub fn validate_operation_payload(id: OperationId, payload: &Value) -> Result<(), String> {
    let object = payload
        .as_object()
        .ok_or_else(|| "payload must be a JSON object".to_owned())?;
    let contract = operation_payload_contract(id);
    for field in object.keys() {
        if !contract.properties.contains(&field.as_str()) {
            return Err(format!(
                "unknown field `{field}` for operation {}",
                id.as_str()
            ));
        }
    }
    for required in contract.required {
        if !object.contains_key(*required) {
            return Err(format!(
                "missing required field `{required}` for operation {}",
                id.as_str()
            ));
        }
    }
    Ok(())
}

/// JSON Schema used by both MCP discovery and schema-digest consumers.
pub fn operation_request_schema(id: OperationId) -> Value {
    let contract = operation_payload_contract(id);
    let payload_properties = contract
        .properties
        .iter()
        .map(|field| ((*field).to_owned(), field_schema(id, field)))
        .collect::<serde_json::Map<_, _>>();
    let payload_schema = json!({
        "type": "object",
        "required": contract.required,
        "additionalProperties": false,
        "properties": payload_properties
    });
    json!({
        "type": "object",
        "required": ["protocol_version", "operation_id", "request_id", "payload"],
        "additionalProperties": false,
        "properties": {
            "protocol_version": {"type": "string", "const": PROTOCOL_VERSION},
            "operation_id": {"type": "string", "const": id.as_str()},
            "request_id": {"type": "string", "minLength": 1},
            "run_id": {"type": "string", "minLength": 1},
            "idempotency_key": {"type": "string", "minLength": 1},
            "locks": {
                "type": "object",
                "additionalProperties": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"}
            },
            "payload": payload_schema
        }
    })
}

fn field_schema(id: OperationId, field: &str) -> Value {
    if field.ends_with("_ref") {
        return json!({
            "type": "object",
            "required": ["path", "sha256"],
            "additionalProperties": false,
            "properties": {
                "path": {"type": "string", "minLength": 1},
                "sha256": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"}
            }
        });
    }
    match (id, field) {
        (OperationId::SourceInspect, "repositories") => {
            json!({"type": "array", "items": repository_input_schema()})
        }
        (OperationId::NodeDescribe, "descriptor") => node_descriptor_schema(),
        (OperationId::NodeDescribe, "sandbox_policy") => sandbox_policy_schema(),
        (OperationId::FederationValidate, "nodes") => {
            json!({"type": "array", "items": node_descriptor_schema()})
        }
        (OperationId::FederationValidate, "work_units") => {
            json!({"type": "array", "items": work_unit_schema()})
        }
        (OperationId::FederationValidate, "shard_results") => {
            json!({"type": "array", "items": shard_result_schema()})
        }
        (_, "repositories" | "nodes" | "work_units" | "shard_results") => {
            json!({"type": "array", "items": {}})
        }
        (_, "probe_sandbox") => json!({"type": "boolean"}),
        (_, "descriptor" | "sandbox_policy") => {
            json!({"type": "object", "additionalProperties": false, "properties": {}})
        }
        (_, "slot_overrides") => {
            json!({"type": "object", "additionalProperties": {"type": "string"}})
        }
        _ => json!({"type": "string", "minLength": 1}),
    }
}

fn repository_input_schema() -> Value {
    json!({
        "type": "object",
        "required": ["repo_id", "path"],
        "additionalProperties": false,
        "properties": {
            "repo_id": {"type": "string", "minLength": 1},
            "path": {"type": "string", "minLength": 1},
            "role": {"type": "string", "minLength": 1},
            "include": {"type": "array", "items": {"type": "string", "minLength": 1}},
            "exclude": {"type": "array", "items": {"type": "string", "minLength": 1}}
        }
    })
}

fn node_descriptor_schema() -> Value {
    json!({
        "type": "object",
        "required": [
            "schema_version", "node_id", "logical_address", "transport", "endpoint",
            "binary_sha256", "source_sha256", "protocol_version", "parser_sha256",
            "sandbox_policy_sha256", "platform", "capabilities", "max_parallel",
            "work_unit_kinds"
        ],
        "additionalProperties": false,
        "properties": {
            "schema_version": {"type": "string", "const": "gtkg.node/v1"},
            "node_id": {"type": "string", "minLength": 1},
            "logical_address": {"type": "string", "pattern": "^local://"},
            "transport": {"type": "string", "enum": ["exec", "mcp_stdio"]},
            "endpoint": {"type": "string", "minLength": 1},
            "binary_sha256": digest_schema(),
            "source_sha256": digest_schema(),
            "protocol_version": {"type": "string", "const": PROTOCOL_VERSION},
            "parser_sha256": digest_schema(),
            "sandbox_policy_sha256": digest_schema(),
            "platform": {"type": "string", "minLength": 1},
            "capabilities": string_array_schema(),
            "max_parallel": {"type": "integer", "minimum": 1},
            "work_unit_kinds": string_array_schema()
        }
    })
}

fn sandbox_policy_schema() -> Value {
    json!({
        "type": "object",
        "required": [
            "schema_version", "policy_id", "required_level", "input_roots", "scratch_root",
            "allowed_programs", "deny_network", "deny_target_execution", "limits"
        ],
        "additionalProperties": false,
        "properties": {
            "schema_version": {"type": "string", "const": "gtkg.sandbox-policy/v1"},
            "policy_id": {"type": "string", "minLength": 1},
            "required_level": {"type": "string", "enum": ["SB0", "SB1", "SB2"]},
            "input_roots": string_array_schema(),
            "scratch_root": {"type": "string", "minLength": 1},
            "denied_read_paths": string_array_schema(),
            "allowed_programs": string_array_schema(),
            "allowed_environment": string_array_schema(),
            "deny_network": {"type": "boolean"},
            "deny_target_execution": {"type": "boolean"},
            "limits": {
                "type": "object",
                "required": ["timeout_millis", "max_output_bytes", "max_processes"],
                "additionalProperties": false,
                "properties": {
                    "timeout_millis": {"type": "integer", "minimum": 1},
                    "max_output_bytes": {"type": "integer", "minimum": 1},
                    "max_processes": {"type": "integer", "minimum": 1}
                }
            }
        }
    })
}

fn work_unit_schema() -> Value {
    json!({
        "type": "object",
        "required": [
            "schema_version", "work_id", "kind", "input_sha256", "policy_sha256", "payload"
        ],
        "additionalProperties": false,
        "properties": {
            "schema_version": {"type": "string", "const": "gtkg.work-unit/v1"},
            "work_id": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
            "kind": {"type": "string", "minLength": 1},
            "input_sha256": digest_schema(),
            "policy_sha256": digest_schema(),
            "payload": {
                "type": "object",
                "required": ["source_path"],
                "additionalProperties": false,
                "properties": {
                    "source_path": {"type": "string", "minLength": 1}
                }
            }
        }
    })
}

fn shard_result_schema() -> Value {
    json!({
        "type": "object",
        "required": [
            "schema_version", "work_id", "node_id", "attempt", "output", "output_sha256",
            "canonical_write_count"
        ],
        "additionalProperties": false,
        "properties": {
            "schema_version": {"type": "string", "const": "gtkg.shard-result/v1"},
            "work_id": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
            "node_id": {"type": "string", "minLength": 1},
            "attempt": {"type": "integer", "minimum": 1},
            "output": {},
            "output_sha256": digest_schema(),
            "canonical_write_count": {"type": "integer", "const": 0}
        }
    })
}

fn digest_schema() -> Value {
    json!({"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"})
}

fn string_array_schema() -> Value {
    json!({"type": "array", "items": {"type": "string", "minLength": 1}})
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OperationRequest {
    pub protocol_version: String,
    pub operation_id: OperationId,
    pub request_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    #[serde(default)]
    pub locks: BTreeMap<String, String>,
    #[serde(default)]
    pub payload: Value,
}

impl OperationRequest {
    pub fn new(operation_id: OperationId, request_id: impl Into<String>, payload: Value) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_owned(),
            operation_id,
            request_id: request_id.into(),
            run_id: None,
            idempotency_key: None,
            locks: BTreeMap::new(),
            payload,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OperationStatus {
    Completed,
    CompletedWithFindings,
    NeedsLlm,
    Blocked,
    Failed,
    Conflict,
    Stale,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OperationResponse {
    pub protocol_version: String,
    pub operation_id: OperationId,
    pub request_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    pub status: OperationStatus,
    #[serde(default)]
    pub result: Value,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    #[serde(default)]
    pub warnings: Vec<String>,
}

impl OperationResponse {
    pub fn completed(request: &OperationRequest, result: Value) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_owned(),
            operation_id: request.operation_id,
            request_id: request.request_id.clone(),
            run_id: request.run_id.clone(),
            status: OperationStatus::Completed,
            result,
            evidence_refs: Vec::new(),
            warnings: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum ErrorCode {
    #[serde(rename = "E_PROTOCOL_VERSION_MISMATCH")]
    ProtocolVersionMismatch,
    #[serde(rename = "E_INVALID_REQUEST")]
    InvalidRequest,
    #[serde(rename = "E_OPERATION_NOT_IMPLEMENTED")]
    OperationNotImplemented,
    #[serde(rename = "E_IO")]
    Io,
    #[serde(rename = "E_PATH_ESCAPE")]
    PathEscape,
    #[serde(rename = "E_SCOPE_DENIED")]
    ScopeDenied,
    #[serde(rename = "E_SIDE_EFFECT_DENIED")]
    SideEffectDenied,
    #[serde(rename = "E_SYMLINK_REJECTED")]
    SymlinkRejected,
    #[serde(rename = "E_SOURCE_NOT_GIT")]
    SourceNotGit,
    #[serde(rename = "E_SOURCE_DIRTY")]
    SourceDirty,
    #[serde(rename = "E_LOCK_MISMATCH")]
    LockMismatch,
    #[serde(rename = "E_INVALID_STATE")]
    InvalidState,
    #[serde(rename = "E_OKF_INVALID")]
    OkfInvalid,
    #[serde(rename = "E_INDEX_INVALID")]
    IndexInvalid,
    #[serde(rename = "E_VERSION_IMMUTABLE")]
    VersionImmutable,
    #[serde(rename = "E_DB_FORBIDDEN")]
    DatabaseForbidden,
    #[serde(rename = "E_EXTRACT_UNSUPPORTED")]
    ExtractUnsupported,
    #[serde(rename = "E_EXTRACT_INVALID")]
    ExtractInvalid,
    #[serde(rename = "E_BUNDLE_INVALID")]
    BundleInvalid,
    #[serde(rename = "E_NOT_FOUND")]
    NotFound,
    #[serde(rename = "E_NON_DETERMINISTIC_RESULT")]
    NonDeterministicResult,
    #[serde(rename = "E_SANDBOX_ASSURANCE_UNAVAILABLE")]
    SandboxAssuranceUnavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ErrorDetail {
    pub code: ErrorCode,
    pub message: String,
    pub retryable: bool,
    pub stage: String,
    #[serde(default)]
    pub lock_digests: BTreeMap<String, String>,
    pub recovery_hint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ErrorEnvelope {
    pub protocol_version: String,
    pub request_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    pub error: ErrorDetail,
}

impl ErrorEnvelope {
    pub fn new(
        request: &OperationRequest,
        code: ErrorCode,
        stage: impl Into<String>,
        message: impl Into<String>,
        recovery_hint: impl Into<String>,
    ) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_owned(),
            request_id: request.request_id.clone(),
            run_id: request.run_id.clone(),
            error: ErrorDetail {
                code,
                message: message.into(),
                retryable: false,
                stage: stage.into(),
                lock_digests: request.locks.clone(),
                recovery_hint: recovery_hint.into(),
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GitObjectId {
    pub algorithm: String,
    pub value: String,
}

impl GitObjectId {
    pub fn sha1(value: impl Into<String>) -> Result<Self, ContractValidationError> {
        let object = Self {
            algorithm: "sha1".to_owned(),
            value: value.into(),
        };
        object.validate()?;
        Ok(object)
    }

    pub fn sha256(value: impl Into<String>) -> Result<Self, ContractValidationError> {
        let object = Self {
            algorithm: "sha256".to_owned(),
            value: value.into(),
        };
        object.validate()?;
        Ok(object)
    }

    pub fn validate(&self) -> Result<(), ContractValidationError> {
        let expected = match self.algorithm.as_str() {
            "sha1" => 40,
            "sha256" => 64,
            other => {
                return Err(ContractValidationError::InvalidGitObject(format!(
                    "unsupported Git object algorithm {other}"
                )));
            }
        };
        if self.value.len() != expected || !self.value.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(ContractValidationError::InvalidGitObject(format!(
                "{} object id must contain exactly {expected} hexadecimal characters",
                self.algorithm
            )));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SubmoduleIdentity {
    pub logical_path: String,
    pub commit: GitObjectId,
    pub dirty: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RepositoryIdentity {
    pub repo_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote: Option<String>,
    pub commit: GitObjectId,
    pub tree: GitObjectId,
    pub dirty: bool,
    #[serde(default)]
    pub submodules: Vec<SubmoduleIdentity>,
}

impl RepositoryIdentity {
    pub fn validate(&self) -> Result<(), ContractValidationError> {
        validate_stable_id("repo_id", &self.repo_id)?;
        self.commit.validate()?;
        self.tree.validate()?;
        if self.dirty {
            return Err(ContractValidationError::DirtyRepository(
                self.repo_id.clone(),
            ));
        }
        for submodule in &self.submodules {
            validate_relative_path(&submodule.logical_path)?;
            submodule.commit.validate()?;
            if submodule.dirty {
                return Err(ContractValidationError::DirtyRepository(format!(
                    "{}:{}",
                    self.repo_id, submodule.logical_path
                )));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SourceManifestEntry {
    pub repo_id: String,
    pub logical_path: String,
    pub role: String,
    pub content_sha256: String,
    pub bytes: u64,
}

#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct SourceKey {
    pub repo_id: String,
    pub logical_path: String,
}

impl SourceKey {
    pub fn new(
        repo_id: impl Into<String>,
        logical_path: impl Into<String>,
    ) -> Result<Self, ContractValidationError> {
        let key = Self {
            repo_id: repo_id.into(),
            logical_path: logical_path.into(),
        };
        key.validate()?;
        Ok(key)
    }

    pub fn validate(&self) -> Result<(), ContractValidationError> {
        validate_stable_id("repo_id", &self.repo_id)?;
        validate_relative_path(&self.logical_path)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FileReceiptRef {
    pub path: String,
    pub sha256: String,
}

impl FileReceiptRef {
    pub fn validate(&self) -> Result<(), ContractValidationError> {
        validate_relative_path(&self.path)?;
        validate_sha256(&self.sha256)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SourceLock {
    pub schema_version: String,
    pub repositories: Vec<RepositoryIdentity>,
    pub entries: Vec<SourceManifestEntry>,
}

impl SourceLock {
    pub fn validate(&self) -> Result<(), ContractValidationError> {
        if self.schema_version != "gtkg.source-lock/v1" {
            return Err(ContractValidationError::InvalidVersion(
                self.schema_version.clone(),
            ));
        }
        if self.repositories.is_empty() {
            return Err(ContractValidationError::MissingRepository);
        }
        let mut repository_ids = std::collections::BTreeSet::new();
        for repository in &self.repositories {
            repository.validate()?;
            if !repository_ids.insert(repository.repo_id.as_str()) {
                return Err(ContractValidationError::DuplicateIdentity(
                    repository.repo_id.clone(),
                ));
            }
        }
        let mut entry_ids = std::collections::BTreeSet::new();
        for entry in &self.entries {
            if !repository_ids.contains(entry.repo_id.as_str()) {
                return Err(ContractValidationError::UnknownRepository(
                    entry.repo_id.clone(),
                ));
            }
            validate_relative_path(&entry.logical_path)?;
            validate_stable_id("role", &entry.role)?;
            validate_sha256(&entry.content_sha256)?;
            let key = format!("{}:{}", entry.repo_id, entry.logical_path);
            if !entry_ids.insert(key.clone()) {
                return Err(ContractValidationError::DuplicateIdentity(key));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VersionRef {
    pub id: String,
    pub version: String,
    pub manifest_sha256: String,
}

impl VersionRef {
    pub fn validate(&self) -> Result<(), ContractValidationError> {
        validate_stable_id("version id", &self.id)?;
        let normalized = self.version.to_ascii_lowercase();
        if self.version.is_empty()
            || matches!(normalized.as_str(), "current" | "latest" | "head" | "main")
            || self.version.contains('/')
            || self.version.contains("..")
        {
            return Err(ContractValidationError::FloatingVersion(
                self.version.clone(),
            ));
        }
        validate_sha256(&self.manifest_sha256)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TemplateLock {
    pub template: VersionRef,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<VersionRef>,
    #[serde(default)]
    pub slot_ids: Vec<String>,
}

impl TemplateLock {
    pub fn validate(&self) -> Result<(), ContractValidationError> {
        self.template.validate()?;
        if let Some(parent) = &self.parent {
            parent.validate()?;
            if parent == &self.template {
                return Err(ContractValidationError::TemplateCycle);
            }
        }
        let mut slots = std::collections::BTreeSet::new();
        for slot in &self.slot_ids {
            validate_stable_id("slot id", slot)?;
            if !slots.insert(slot.as_str()) {
                return Err(ContractValidationError::DuplicateIdentity(slot.clone()));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ContractValidationError {
    #[error("invalid Git object: {0}")]
    InvalidGitObject(String),
    #[error("repository is dirty: {0}")]
    DirtyRepository(String),
    #[error("at least one repository is required")]
    MissingRepository,
    #[error("unknown repository: {0}")]
    UnknownRepository(String),
    #[error("duplicate identity: {0}")]
    DuplicateIdentity(String),
    #[error("invalid relative path: {0}")]
    InvalidPath(String),
    #[error("invalid sha256 digest: {0}")]
    InvalidSha256(String),
    #[error("invalid stable identifier for {0}: {1}")]
    InvalidStableId(String, String),
    #[error("floating or unsafe version is forbidden: {0}")]
    FloatingVersion(String),
    #[error("invalid schema version: {0}")]
    InvalidVersion(String),
    #[error("template cannot inherit from itself")]
    TemplateCycle,
    #[error("invalid node descriptor: {0}")]
    InvalidNode(String),
    #[error("invalid work unit: {0}")]
    InvalidWorkUnit(String),
    #[error("invalid shard result: {0}")]
    InvalidShardResult(String),
    #[error("invalid sandbox policy: {0}")]
    InvalidSandboxPolicy(String),
}

/// Assurance promised by a sandbox provider.
///
/// Levels are deliberately ordered so callers can compare a verified level
/// with a policy's required minimum without inventing provider-specific rules.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AssuranceLevel {
    Sb0,
    Sb1,
    Sb2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SandboxProbeState {
    NotRun,
    Passed,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResourceLimits {
    pub timeout_millis: u64,
    pub max_output_bytes: u64,
    pub max_processes: u32,
}

impl ResourceLimits {
    pub fn validate(&self) -> Result<(), ContractValidationError> {
        if self.timeout_millis == 0 {
            return Err(ContractValidationError::InvalidSandboxPolicy(
                "timeout_millis must be greater than zero".to_owned(),
            ));
        }
        if self.max_output_bytes == 0 {
            return Err(ContractValidationError::InvalidSandboxPolicy(
                "max_output_bytes must be greater than zero".to_owned(),
            ));
        }
        if self.max_processes == 0 {
            return Err(ContractValidationError::InvalidSandboxPolicy(
                "max_processes must be greater than zero".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SandboxPolicyLock {
    pub schema_version: String,
    pub policy_id: String,
    pub required_level: AssuranceLevel,
    pub input_roots: Vec<std::path::PathBuf>,
    pub scratch_root: std::path::PathBuf,
    #[serde(default)]
    pub denied_read_paths: Vec<std::path::PathBuf>,
    pub allowed_programs: Vec<String>,
    #[serde(default)]
    pub allowed_environment: Vec<String>,
    pub deny_network: bool,
    pub deny_target_execution: bool,
    pub limits: ResourceLimits,
}

impl SandboxPolicyLock {
    pub fn validate(&self) -> Result<(), ContractValidationError> {
        if self.schema_version != "gtkg.sandbox-policy/v1" {
            return Err(ContractValidationError::InvalidVersion(
                self.schema_version.clone(),
            ));
        }
        validate_stable_id("sandbox policy id", &self.policy_id)?;
        if self.input_roots.is_empty() {
            return Err(ContractValidationError::InvalidSandboxPolicy(
                "at least one input root is required".to_owned(),
            ));
        }
        validate_unique_absolute_paths("input root", &self.input_roots)?;
        validate_absolute_path("scratch root", &self.scratch_root)?;
        validate_unique_absolute_paths("denied read path", &self.denied_read_paths)?;
        if self
            .input_roots
            .iter()
            .any(|root| root.starts_with(&self.scratch_root) || self.scratch_root.starts_with(root))
        {
            return Err(ContractValidationError::InvalidSandboxPolicy(
                "scratch root and input roots must not overlap".to_owned(),
            ));
        }
        if self.denied_read_paths.iter().any(|denied| {
            self.input_roots
                .iter()
                .any(|input| denied.starts_with(input) || input.starts_with(denied))
                || denied.starts_with(&self.scratch_root)
                || self.scratch_root.starts_with(denied)
        }) {
            return Err(ContractValidationError::InvalidSandboxPolicy(
                "denied read paths must not overlap input or scratch roots".to_owned(),
            ));
        }
        if self.allowed_programs.is_empty() {
            return Err(ContractValidationError::InvalidSandboxPolicy(
                "at least one absolute program path is required".to_owned(),
            ));
        }
        let mut programs = std::collections::BTreeSet::new();
        for program in &self.allowed_programs {
            validate_absolute_path("allowed program", std::path::Path::new(program))?;
            if !programs.insert(program.as_str()) {
                return Err(ContractValidationError::DuplicateIdentity(program.clone()));
            }
        }
        let mut environment = std::collections::BTreeSet::new();
        for name in &self.allowed_environment {
            if name.is_empty()
                || !name
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
            {
                return Err(ContractValidationError::InvalidSandboxPolicy(format!(
                    "invalid environment variable name {name}"
                )));
            }
            if !environment.insert(name.as_str()) {
                return Err(ContractValidationError::DuplicateIdentity(name.clone()));
            }
        }
        if self.required_level == AssuranceLevel::Sb2
            && (!self.deny_network || !self.deny_target_execution)
        {
            return Err(ContractValidationError::InvalidSandboxPolicy(
                "SB2 requires deny_network and deny_target_execution".to_owned(),
            ));
        }
        self.limits.validate()
    }

    pub fn digest(&self) -> Result<String, serde_json::Error> {
        canonical_json_sha256(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SandboxProviderDescription {
    pub provider_id: String,
    pub supported_levels: Vec<AssuranceLevel>,
    pub probe_state: SandboxProbeState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified_level: Option<AssuranceLevel>,
}

impl SandboxProviderDescription {
    pub fn validate(&self) -> Result<(), ContractValidationError> {
        validate_stable_id("sandbox provider id", &self.provider_id)?;
        if self.supported_levels.is_empty() {
            return Err(ContractValidationError::InvalidSandboxPolicy(
                "sandbox provider must declare at least one assurance level".to_owned(),
            ));
        }
        let unique: std::collections::BTreeSet<_> = self.supported_levels.iter().copied().collect();
        if unique.len() != self.supported_levels.len() {
            return Err(ContractValidationError::InvalidSandboxPolicy(
                "sandbox provider assurance levels must be unique".to_owned(),
            ));
        }
        match (self.probe_state, self.verified_level) {
            (SandboxProbeState::NotRun | SandboxProbeState::Failed, Some(_)) => {
                Err(ContractValidationError::InvalidSandboxPolicy(
                    "an unverified or failed provider cannot claim a verified level".to_owned(),
                ))
            }
            (SandboxProbeState::Passed, None) => {
                Err(ContractValidationError::InvalidSandboxPolicy(
                    "a passed provider probe must bind a verified level".to_owned(),
                ))
            }
            (_, Some(level)) if !unique.contains(&level) => {
                Err(ContractValidationError::InvalidSandboxPolicy(
                    "verified level is not supported by the provider".to_owned(),
                ))
            }
            _ => Ok(()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SandboxProbeResult {
    pub schema_version: String,
    pub provider_id: String,
    pub policy_sha256: String,
    pub passed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified_level: Option<AssuranceLevel>,
    pub release_ready: bool,
    #[serde(default)]
    pub assertions: BTreeMap<String, bool>,
    #[serde(default)]
    pub findings: Vec<String>,
}

impl SandboxProbeResult {
    pub fn validate(&self) -> Result<(), ContractValidationError> {
        if self.schema_version != "gtkg.sandbox-probe/v1" {
            return Err(ContractValidationError::InvalidVersion(
                self.schema_version.clone(),
            ));
        }
        validate_stable_id("sandbox provider id", &self.provider_id)?;
        validate_sha256(&self.policy_sha256)?;
        if self.assertions.is_empty() {
            return Err(ContractValidationError::InvalidSandboxPolicy(
                "sandbox probe must contain named assertions".to_owned(),
            ));
        }
        for assertion in self.assertions.keys() {
            validate_stable_id("sandbox assertion", assertion)?;
        }
        if self.passed {
            if self.verified_level.is_none() || self.assertions.values().any(|passed| !passed) {
                return Err(ContractValidationError::InvalidSandboxPolicy(
                    "a passed sandbox probe requires a verified level and all assertions true"
                        .to_owned(),
                ));
            }
        } else if self.verified_level.is_some() {
            return Err(ContractValidationError::InvalidSandboxPolicy(
                "a failed sandbox probe cannot claim a verified level".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SandboxReceipt {
    pub schema_version: String,
    pub provider_id: String,
    pub assurance_level: AssuranceLevel,
    pub policy_sha256: String,
    pub command_sha256: String,
    pub input_sha256: String,
    pub limits: ResourceLimits,
    pub success: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    pub exit_reason: String,
    #[serde(default)]
    pub violations: Vec<String>,
    pub target_execution_count: u32,
    pub output_sha256: String,
}

impl SandboxReceipt {
    pub fn validate(&self) -> Result<(), ContractValidationError> {
        if self.schema_version != "gtkg.sandbox-receipt/v1" {
            return Err(ContractValidationError::InvalidVersion(
                self.schema_version.clone(),
            ));
        }
        validate_stable_id("sandbox provider id", &self.provider_id)?;
        for digest in [
            &self.policy_sha256,
            &self.command_sha256,
            &self.input_sha256,
            &self.output_sha256,
        ] {
            validate_sha256(digest)?;
        }
        self.limits.validate()?;
        if self.exit_reason.trim().is_empty() {
            return Err(ContractValidationError::InvalidSandboxPolicy(
                "sandbox receipt exit_reason must not be empty".to_owned(),
            ));
        }
        if self.success && self.exit_code != Some(0) {
            return Err(ContractValidationError::InvalidSandboxPolicy(
                "successful sandbox receipt must have exit code 0".to_owned(),
            ));
        }
        if self.target_execution_count != 0 {
            return Err(ContractValidationError::InvalidSandboxPolicy(
                "target content execution count must be zero".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum NodeTransport {
    Exec,
    McpStdio,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NodeDescriptor {
    pub schema_version: String,
    pub node_id: String,
    pub logical_address: String,
    pub transport: NodeTransport,
    pub endpoint: String,
    pub binary_sha256: String,
    pub source_sha256: String,
    pub protocol_version: String,
    pub parser_sha256: String,
    pub sandbox_policy_sha256: String,
    pub platform: String,
    pub capabilities: Vec<String>,
    pub max_parallel: u32,
    pub work_unit_kinds: Vec<String>,
}

impl NodeDescriptor {
    pub fn validate(&self) -> Result<(), ContractValidationError> {
        if self.schema_version != "gtkg.node/v1" {
            return Err(ContractValidationError::InvalidVersion(
                self.schema_version.clone(),
            ));
        }
        validate_stable_id("node id", &self.node_id)?;
        if self.logical_address != format!("local://{}", self.node_id) {
            return Err(ContractValidationError::InvalidNode(format!(
                "logical_address must be local://{}",
                self.node_id
            )));
        }
        validate_absolute_path("node endpoint", std::path::Path::new(&self.endpoint))?;
        for digest in [
            &self.binary_sha256,
            &self.source_sha256,
            &self.parser_sha256,
            &self.sandbox_policy_sha256,
        ] {
            validate_sha256(digest)?;
        }
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(ContractValidationError::InvalidNode(format!(
                "protocol version must be {PROTOCOL_VERSION}"
            )));
        }
        if self.platform.trim().is_empty() {
            return Err(ContractValidationError::InvalidNode(
                "platform must not be empty".to_owned(),
            ));
        }
        if self.max_parallel == 0 {
            return Err(ContractValidationError::InvalidNode(
                "max_parallel must be greater than zero".to_owned(),
            ));
        }
        validate_unique_stable_ids("capability", &self.capabilities, false)?;
        validate_unique_stable_ids("work unit kind", &self.work_unit_kinds, false)?;
        if self
            .work_unit_kinds
            .iter()
            .any(|kind| !self.capabilities.contains(kind))
        {
            return Err(ContractValidationError::InvalidNode(
                "every work unit kind must be declared as a capability".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NodeSetLock {
    pub schema_version: String,
    pub nodes: Vec<NodeDescriptor>,
}

impl NodeSetLock {
    pub fn new(mut nodes: Vec<NodeDescriptor>) -> Result<Self, ContractValidationError> {
        for node in &nodes {
            node.validate()?;
        }
        nodes.sort_by(|left, right| left.node_id.cmp(&right.node_id));
        let lock = Self {
            schema_version: "gtkg.node-set-lock/v1".to_owned(),
            nodes,
        };
        lock.validate()?;
        Ok(lock)
    }

    pub fn validate(&self) -> Result<(), ContractValidationError> {
        if self.schema_version != "gtkg.node-set-lock/v1" {
            return Err(ContractValidationError::InvalidVersion(
                self.schema_version.clone(),
            ));
        }
        if self.nodes.is_empty() {
            return Err(ContractValidationError::InvalidNode(
                "node set must not be empty".to_owned(),
            ));
        }
        let mut previous: Option<&str> = None;
        for node in &self.nodes {
            node.validate()?;
            if previous.is_some_and(|id| id >= node.node_id.as_str()) {
                return Err(ContractValidationError::InvalidNode(
                    "node set must be uniquely sorted by node_id".to_owned(),
                ));
            }
            previous = Some(&node.node_id);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkUnit {
    pub schema_version: String,
    pub work_id: String,
    pub kind: String,
    pub input_sha256: String,
    pub policy_sha256: String,
    pub payload: Value,
}

impl WorkUnit {
    pub fn new(
        kind: impl Into<String>,
        input_sha256: impl Into<String>,
        policy_sha256: impl Into<String>,
        payload: Value,
    ) -> Result<Self, ContractValidationError> {
        let mut work = Self {
            schema_version: "gtkg.work-unit/v1".to_owned(),
            work_id: String::new(),
            kind: kind.into(),
            input_sha256: input_sha256.into(),
            policy_sha256: policy_sha256.into(),
            payload,
        };
        work.validate_content()?;
        work.work_id = work.expected_work_id().map_err(|error| {
            ContractValidationError::InvalidWorkUnit(format!(
                "cannot canonicalize work unit: {error}"
            ))
        })?;
        Ok(work)
    }

    pub fn validate(&self) -> Result<(), ContractValidationError> {
        self.validate_content()?;
        let expected = self.expected_work_id().map_err(|error| {
            ContractValidationError::InvalidWorkUnit(format!(
                "cannot canonicalize work unit: {error}"
            ))
        })?;
        if self.work_id != expected {
            return Err(ContractValidationError::InvalidWorkUnit(format!(
                "work_id mismatch: expected {expected}"
            )));
        }
        Ok(())
    }

    fn validate_content(&self) -> Result<(), ContractValidationError> {
        if self.schema_version != "gtkg.work-unit/v1" {
            return Err(ContractValidationError::InvalidVersion(
                self.schema_version.clone(),
            ));
        }
        validate_stable_id("work unit kind", &self.kind)?;
        validate_sha256(&self.input_sha256)?;
        validate_sha256(&self.policy_sha256)?;
        let Some(payload) = self.payload.as_object() else {
            return Err(ContractValidationError::InvalidWorkUnit(
                "payload must be a JSON object".to_owned(),
            ));
        };
        if payload.len() != 1
            || payload
                .get("source_path")
                .and_then(Value::as_str)
                .is_none_or(|source_path| source_path.is_empty())
        {
            return Err(ContractValidationError::InvalidWorkUnit(
                "payload must contain exactly one non-empty string source_path".to_owned(),
            ));
        }
        Ok(())
    }

    fn expected_work_id(&self) -> Result<String, serde_json::Error> {
        #[derive(Serialize)]
        struct WorkIdentity<'a> {
            schema_version: &'a str,
            kind: &'a str,
            input_sha256: &'a str,
            policy_sha256: &'a str,
            payload: &'a Value,
        }
        canonical_json_sha256(&WorkIdentity {
            schema_version: &self.schema_version,
            kind: &self.kind,
            input_sha256: &self.input_sha256,
            policy_sha256: &self.policy_sha256,
            payload: &self.payload,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ShardResult {
    pub schema_version: String,
    pub work_id: String,
    pub node_id: String,
    pub attempt: u32,
    pub output: Value,
    pub output_sha256: String,
    /// Workers can never write canonical knowledge. This field is checked by
    /// the coordinator rather than trusted as an informational metric.
    pub canonical_write_count: u32,
}

impl ShardResult {
    pub fn new(
        work: &WorkUnit,
        node_id: impl Into<String>,
        attempt: u32,
        output: Value,
    ) -> Result<Self, ContractValidationError> {
        work.validate()?;
        let output_sha256 = canonical_json_sha256(&output).map_err(|error| {
            ContractValidationError::InvalidShardResult(format!(
                "cannot canonicalize output: {error}"
            ))
        })?;
        let result = Self {
            schema_version: "gtkg.shard-result/v1".to_owned(),
            work_id: work.work_id.clone(),
            node_id: node_id.into(),
            attempt,
            output,
            output_sha256,
            canonical_write_count: 0,
        };
        result.validate()?;
        Ok(result)
    }

    pub fn validate(&self) -> Result<(), ContractValidationError> {
        if self.schema_version != "gtkg.shard-result/v1" {
            return Err(ContractValidationError::InvalidVersion(
                self.schema_version.clone(),
            ));
        }
        validate_sha256(&self.work_id)?;
        validate_stable_id("node id", &self.node_id)?;
        if self.attempt == 0 {
            return Err(ContractValidationError::InvalidShardResult(
                "attempt must be greater than zero".to_owned(),
            ));
        }
        validate_sha256(&self.output_sha256)?;
        let expected = canonical_json_sha256(&self.output).map_err(|error| {
            ContractValidationError::InvalidShardResult(format!(
                "cannot canonicalize output: {error}"
            ))
        })?;
        if self.output_sha256 != expected {
            return Err(ContractValidationError::InvalidShardResult(format!(
                "output digest mismatch: expected {expected}"
            )));
        }
        if self.canonical_write_count != 0 {
            return Err(ContractValidationError::InvalidShardResult(
                "worker canonical_write_count must be zero".to_owned(),
            ));
        }
        Ok(())
    }
}

pub fn validate_sha256(value: &str) -> Result<(), ContractValidationError> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(ContractValidationError::InvalidSha256(value.to_owned()));
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(ContractValidationError::InvalidSha256(value.to_owned()));
    }
    Ok(())
}

pub fn validate_path_identifier(kind: &str, value: &str) -> Result<(), ContractValidationError> {
    if value.is_empty()
        || matches!(value, "." | "..")
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(ContractValidationError::InvalidStableId(
            kind.to_owned(),
            value.to_owned(),
        ));
    }
    Ok(())
}

fn validate_stable_id(kind: &str, value: &str) -> Result<(), ContractValidationError> {
    if value.is_empty()
        || matches!(value, "." | "..")
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(ContractValidationError::InvalidStableId(
            kind.to_owned(),
            value.to_owned(),
        ));
    }
    Ok(())
}

fn validate_relative_path(value: &str) -> Result<(), ContractValidationError> {
    let path = std::path::Path::new(value);
    if value.is_empty()
        || path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir | std::path::Component::RootDir
            )
        })
    {
        return Err(ContractValidationError::InvalidPath(value.to_owned()));
    }
    Ok(())
}

fn validate_absolute_path(
    kind: &str,
    path: &std::path::Path,
) -> Result<(), ContractValidationError> {
    if !path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
    {
        return Err(ContractValidationError::InvalidSandboxPolicy(format!(
            "{kind} must be an absolute normalized path: {}",
            path.display()
        )));
    }
    Ok(())
}

fn validate_unique_absolute_paths(
    kind: &str,
    paths: &[std::path::PathBuf],
) -> Result<(), ContractValidationError> {
    let mut unique = std::collections::BTreeSet::new();
    for path in paths {
        validate_absolute_path(kind, path)?;
        if !unique.insert(path) {
            return Err(ContractValidationError::InvalidSandboxPolicy(format!(
                "duplicate {kind}: {}",
                path.display()
            )));
        }
    }
    Ok(())
}

fn validate_unique_stable_ids(
    kind: &str,
    values: &[String],
    allow_empty: bool,
) -> Result<(), ContractValidationError> {
    if !allow_empty && values.is_empty() {
        return Err(ContractValidationError::InvalidNode(format!(
            "at least one {kind} is required"
        )));
    }
    let mut unique = std::collections::BTreeSet::new();
    for value in values {
        validate_stable_id(kind, value)?;
        if !unique.insert(value.as_str()) {
            return Err(ContractValidationError::DuplicateIdentity(value.clone()));
        }
    }
    Ok(())
}

pub fn canonical_json_sha256<T: Serialize>(value: &T) -> Result<String, serde_json::Error> {
    let value = serde_json::to_value(value)?;
    let canonical = canonicalize_json(value);
    let bytes = serde_json::to_vec(&canonical)?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
}

fn canonicalize_json(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let sorted: BTreeMap<_, _> = map
                .into_iter()
                .map(|(key, value)| (key, canonicalize_json(value)))
                .collect();
            Value::Object(sorted.into_iter().collect())
        }
        Value::Array(values) => Value::Array(values.into_iter().map(canonicalize_json).collect()),
        other => other,
    }
}
