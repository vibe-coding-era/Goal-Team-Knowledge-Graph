//! Shared GTKG adapter discovery helpers.

use std::fs;

use gtkg_protocol::v2::{
    PROTOCOL_VERSION_V2, V2OperationId, V2_PUBLIC_OPERATIONS, v2_operation_request_schema,
};
use gtkg_protocol::v03::OperationBindingV2;
use gtkg_protocol::v03::profiles::{
    OperationProfileErrorV03, discoverable_operation_profile_v03, operation_profile_projection_v03,
};
use gtkg_protocol::{CORE_VERSION, PROTOCOL_VERSION, PUBLIC_OPERATIONS, operation_request_schema};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// Return the MCP tool disclosure derived from the same public registry used by
/// `system.describe`. Unimplemented protocol slots remain visible, but are
/// labelled truthfully and fail closed when called.
pub fn mcp_tools() -> Vec<Value> {
    PUBLIC_OPERATIONS
        .iter()
        .map(|operation| {
            let availability = serde_json::to_value(operation.availability)
                .unwrap_or_else(|_| Value::String("not_implemented".to_owned()));
            json!({
                "name": operation.id.mcp_tool_name(),
                "description": format!("GTKG operation {}", operation.id.as_str()),
                "inputSchema": operation_request_schema(operation.id),
                "x-gtkg-operation-id": operation.id,
                "x-gtkg-side-effect": operation.side_effect,
                "x-gtkg-availability": availability,
            })
        })
        .collect()
}

/// The default closed schema that every public v2 operation accepts.
///
/// A profile lists operations, not payload revisions. Without an explicit
/// disclosure a caller cannot tell that the knowledge-quality revision is
/// additive on only a subset of the listed operations, so discovery reports the
/// accepted revisions per tool instead of leaving it implicit.
pub const DEFAULT_V2_PAYLOAD_REVISION: &str = "gtkg.protocol/v2-default";

/// Every payload revision one v2 operation accepts, in disclosure order.
///
/// The default closed schema is always accepted; the V0.4 knowledge-quality
/// revision is additive and only on the operations that implement it. Sending the
/// knowledge-quality revision to any other operation fails closed at the protocol
/// layer with `operation does not support this payload revision`.
pub fn v2_accepted_payload_revisions(op: V2OperationId) -> Vec<&'static str> {
    let mut revisions = vec![DEFAULT_V2_PAYLOAD_REVISION];
    if gtkg_protocol::v04::accepts_knowledge_quality_payload(op) {
        revisions.push(gtkg_protocol::v04::PAYLOAD_REVISION);
    }
    revisions
}

/// V0.2 discovery is a distinct projection and never broadens the frozen v1
/// MCP surface. Presence, implementation availability, and callability are
/// disclosed independently for every v2 tool.
pub fn mcp_tools_v2() -> Vec<Value> {
    V2_PUBLIC_OPERATIONS
        .iter()
        .map(|operation| {
            let availability = serde_json::to_value(operation.availability)
                .unwrap_or_else(|_| Value::String("not_implemented".to_owned()));
            let callability = serde_json::to_value(operation.callability)
                .unwrap_or_else(|_| Value::String("not_implemented".to_owned()));
            json!({
                "name": operation.id.mcp_tool_name(),
                "description": format!("GTKG v2 operation {}", operation.id.as_str()),
                "inputSchema": v2_operation_request_schema(operation.id),
                "x-gtkg-operation-id": operation.id,
                "x-gtkg-protocol-version": PROTOCOL_VERSION_V2,
                "x-gtkg-side-effect": operation.side_effect,
                "x-gtkg-availability": availability,
                "x-gtkg-callability": callability,
                "x-gtkg-payload-revisions": v2_accepted_payload_revisions(operation.id),
            })
        })
        .collect()
}

fn mcp_tool_from_v03_binding(
    binding: &OperationBindingV2,
    profile_id: &str,
    profile_digest: &str,
) -> Value {
    let availability = serde_json::to_value(binding.availability)
        .unwrap_or_else(|_| Value::String("not_implemented".to_owned()));
    let callability = serde_json::to_value(binding.callability)
        .unwrap_or_else(|_| Value::String("not_implemented".to_owned()));
    json!({
        "name": binding.operation_id.mcp_tool_name(),
        "description": format!("GTKG v2 operation {}", binding.operation_id.as_str()),
        "inputSchema": v2_operation_request_schema(binding.operation_id),
        "x-gtkg-operation-id": binding.operation_id,
        "x-gtkg-protocol-version": PROTOCOL_VERSION_V2,
        "x-gtkg-side-effect": binding.effect,
        "x-gtkg-availability": availability,
        "x-gtkg-callability": callability,
        "x-gtkg-payload-revisions": v2_accepted_payload_revisions(binding.operation_id),
        "x-gtkg-handler-id": binding.handler_id,
        "x-gtkg-schema-sha256": binding.schema_sha256,
        "x-gtkg-profile-id": profile_id,
        "x-gtkg-profile-digest": profile_digest,
    })
}

/// Return the exact live discovery projection for one V0.3 profile.
///
/// The default selection is `core`. Until all operations in a selected profile
/// have real handlers, discovery returns a closed error instead of dead tools.
pub fn v2_profile_discovery(
    profile_id: Option<&str>,
    profile_digest: Option<&str>,
) -> Result<Value, Value> {
    let projection = discoverable_operation_profile_v03(profile_id, profile_digest)
        .map_err(profile_discovery_error)?;
    let selected_profile_id = projection.profile.profile_id.as_str();
    let selected_profile_digest = projection.profile.digest.as_str();
    let tools = projection
        .bindings
        .iter()
        .map(|binding| {
            mcp_tool_from_v03_binding(binding, selected_profile_id, selected_profile_digest)
        })
        .collect::<Vec<_>>();
    Ok(json!({
        "schema_version": "gtkg.discovery-response/v1",
        "profile_id": selected_profile_id,
        "profile_digest": selected_profile_digest,
        "is_default": projection.profile.is_default,
        "tools": tools,
    }))
}

/// Return the exact profile contract identity without exposing dead tools.
///
/// Runtime receipts and MCP initialize bind this projection. Live tools/list
/// separately calls [`v2_profile_discovery`] and still fails closed when any
/// selected operation lacks a real handler.
pub fn v2_profile_contract_identity(
    profile_id: Option<&str>,
    profile_digest: Option<&str>,
) -> Result<Value, Value> {
    let projection = operation_profile_projection_v03(profile_id, profile_digest)
        .map_err(profile_discovery_error)?;
    let profile_id = projection.profile.profile_id.as_str();
    let profile_digest = projection.profile.digest.as_str();
    let bindings = projection
        .bindings
        .iter()
        .map(|binding| {
            json!({
                "operation_id": binding.operation_id,
                "handler_id": binding.handler_id,
                "schema_sha256": binding.schema_sha256,
                "side_effect": binding.effect,
                "availability": binding.availability,
                "callability": binding.callability,
            })
        })
        .collect::<Vec<_>>();
    Ok(json!({
        "schema_version": "gtkg.discovery-profile-contract/v1",
        "profile_id": profile_id,
        "profile_digest": profile_digest,
        "is_default": projection.profile.is_default,
        "profile_operation_count": bindings.len(),
        "bindings": bindings,
    }))
}

fn profile_discovery_error(error: OperationProfileErrorV03) -> Value {
    let message = match error.code() {
        "E_PROFILE_UNKNOWN" => "unknown discovery profile",
        "E_PROFILE_STALE" => "discovery profile digest is stale",
        "E_DEAD_TOOL_EXPOSED" => {
            "selected discovery profile contains operations without implemented handlers"
        }
        _ => "discovery profile contract is invalid",
    };
    let unavailable_operation_ids = error
        .unavailable_operation_ids()
        .iter()
        .map(|operation_id| operation_id.as_str())
        .collect::<Vec<_>>();
    json!({
        "schema_version": "gtkg.discovery-error/v1",
        "code": error.code(),
        "profile_id": error.profile_id(),
        "message": message,
        "selected_operation_count": error.selected_operation_count(),
        "unavailable_operation_ids": unavailable_operation_ids,
        "expected_digest": error.expected_digest(),
        "actual_digest": error.actual_digest(),
        "recovery_hint": match error.code() {
            "E_PROFILE_UNKNOWN" => "select core, graph, authoring, lifecycle, templates, a2ui, or all",
            "E_PROFILE_STALE" => "use the exact current profile digest only after explicit client reconfiguration",
            "E_DEAD_TOOL_EXPOSED" => "install a binary implementing every selected operation or select a fully implemented profile",
            _ => "repair the frozen profile and operation-binding contract",
        },
    })
}

/// Bind adapter discovery to the exact executable bytes and the complete
/// public operation-schema surface used by this process.
pub fn runtime_identity() -> Result<Value, String> {
    let executable = std::env::current_exe()
        .map_err(|error| format!("failed to resolve current gtkg executable: {error}"))?;
    let binary = fs::read(&executable)
        .map_err(|error| format!("failed to read {}: {error}", executable.display()))?;
    let schema = serde_json::to_vec(&mcp_tools())
        .map_err(|error| format!("failed to encode operation schemas: {error}"))?;
    let binary_sha256 = sha256_prefixed(&binary);
    let operation_schema_sha256 = sha256_prefixed(&schema);
    let core_sha256 = sha256_prefixed(
        format!("gtkg-core|{CORE_VERSION}|{PROTOCOL_VERSION}|{operation_schema_sha256}").as_bytes(),
    );
    Ok(json!({
        "binary_sha256": binary_sha256,
        "core_sha256": core_sha256,
        "protocol_version": PROTOCOL_VERSION,
        "operation_schema_sha256": operation_schema_sha256,
    }))
}

/// Bind v2 discovery to the same executable, but to its own immutable schema
/// projection and protocol version.
pub fn runtime_identity_v2() -> Result<Value, String> {
    let executable = std::env::current_exe()
        .map_err(|error| format!("failed to resolve current gtkg executable: {error}"))?;
    let binary = fs::read(&executable)
        .map_err(|error| format!("failed to read {}: {error}", executable.display()))?;
    let schema = serde_json::to_vec(&mcp_tools_v2())
        .map_err(|error| format!("failed to encode v2 operation schemas: {error}"))?;
    let binary_sha256 = sha256_prefixed(&binary);
    let operation_schema_sha256 = sha256_prefixed(&schema);
    let core_sha256 = sha256_prefixed(
        format!("gtkg-core|{CORE_VERSION}|{PROTOCOL_VERSION_V2}|{operation_schema_sha256}")
            .as_bytes(),
    );
    Ok(json!({
        "binary_sha256": binary_sha256,
        "core_sha256": core_sha256,
        "protocol_version": PROTOCOL_VERSION_V2,
        "operation_schema_sha256": operation_schema_sha256,
        "authority": {
            "scope": "local_development_only",
            "external_current_activation": false,
            "release_execution": false,
            "real_provider_execution": false,
        },
    }))
}

/// Bind a profile-aware v2 discovery response to the current executable.
pub fn runtime_identity_v2_for_profile(
    profile_id: Option<&str>,
    profile_digest: Option<&str>,
) -> Result<Value, String> {
    let executable = std::env::current_exe()
        .map_err(|error| format!("failed to resolve current gtkg executable: {error}"))?;
    let binary = fs::read(&executable)
        .map_err(|error| format!("failed to read {}: {error}", executable.display()))?;
    let contract = v2_profile_contract_identity(profile_id, profile_digest)
        .map_err(|error| serde_json::to_string(&error).unwrap_or_else(|_| error.to_string()))?;
    let schema = serde_json::to_vec(&contract)
        .map_err(|error| format!("failed to encode v2 profile contract: {error}"))?;
    let binary_sha256 = sha256_prefixed(&binary);
    let operation_schema_sha256 = sha256_prefixed(&schema);
    let core_sha256 = sha256_prefixed(
        format!("gtkg-core|{CORE_VERSION}|{PROTOCOL_VERSION_V2}|{operation_schema_sha256}")
            .as_bytes(),
    );
    Ok(json!({
        "binary_sha256": binary_sha256,
        "core_sha256": core_sha256,
        "protocol_version": PROTOCOL_VERSION_V2,
        "operation_schema_sha256": operation_schema_sha256,
        "profile_id": contract["profile_id"],
        "profile_digest": contract["profile_digest"],
        "profile_operation_count": contract["profile_operation_count"],
        "profile_contract_sha256": sha256_prefixed(&schema),
        "authority": {
            "scope": "local_development_only",
            "external_current_activation": false,
            "release_execution": false,
            "real_provider_execution": false,
        },
    }))
}

fn sha256_prefixed(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}
