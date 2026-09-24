//! Q04 v2 graph-operation bindings for the Q03 file-query runtime.

#![allow(clippy::result_large_err)]

use std::path::{Component, Path, PathBuf};

use gtkg_protocol::FileReceiptRef;
use gtkg_protocol::v2::{
    OperationRequestV2, OperationResponseV2, PROTOCOL_VERSION_V2, V2ErrorCode, V2ErrorEnvelope,
    V2OperationId,
};
use gtkg_protocol::v03::query::FileQueryExpectedIdentitiesV1;
use serde_json::Value;

use crate::v03::graph_query::{
    FileGraphQueryErrorV1, FileGraphQueryOperationV1, execute_file_graph_operation_v1,
};
use crate::{CallContext, ContextError};

pub(crate) const fn owns(operation_id: V2OperationId) -> bool {
    matches!(
        operation_id,
        V2OperationId::GraphNeighbors
            | V2OperationId::GraphPath
            | V2OperationId::GraphImpact
            | V2OperationId::GraphExplain
            | V2OperationId::GraphTrace
            | V2OperationId::GraphSearch
    )
}

pub(crate) fn execute(
    context: &CallContext,
    request: OperationRequestV2,
    operation_id: V2OperationId,
) -> Result<OperationResponseV2, V2ErrorEnvelope> {
    let object = request.payload.as_object().ok_or_else(|| {
        invalid(
            &request,
            "graph operation payload must be an object bound to the Q03 query index",
        )
    })?;
    let allowed = operation_fields(operation_id);
    if object
        .keys()
        .any(|key| !COMMON_FIELDS.contains(&key.as_str()) && !allowed.contains(&key.as_str()))
    {
        return Err(invalid(
            &request,
            "query_index_path is required and the payload contains an unsupported or legacy full-graph field",
        ));
    }
    let query_root = relative_directory(context, &request, object, "query_index_path")?;
    let evidence_root = relative_directory(context, &request, object, "evidence_index_path")?;
    let query_manifest_ref = parse_field::<FileReceiptRef>(
        &request,
        object,
        "query_manifest_ref",
        "query_manifest_ref must be an exact FileReceiptRef",
    )?;
    let evidence_manifest_ref = parse_field::<FileReceiptRef>(
        &request,
        object,
        "evidence_manifest_ref",
        "evidence_manifest_ref must be an exact FileReceiptRef",
    )?;
    let expected = parse_field::<FileQueryExpectedIdentitiesV1>(
        &request,
        object,
        "expected_identities",
        "expected_identities must bind source, graph, and overlay sha256 identities",
    )?;
    let mut operation_payload = object.clone();
    for &field in COMMON_FIELDS {
        operation_payload.remove(field);
    }
    let operation = match operation_id {
        V2OperationId::GraphNeighbors => FileGraphQueryOperationV1::Neighbors,
        V2OperationId::GraphPath => FileGraphQueryOperationV1::Path,
        V2OperationId::GraphImpact => FileGraphQueryOperationV1::Impact,
        V2OperationId::GraphExplain => FileGraphQueryOperationV1::Explain,
        V2OperationId::GraphTrace => FileGraphQueryOperationV1::Trace,
        V2OperationId::GraphSearch => FileGraphQueryOperationV1::Search,
        _ => {
            return Err(invalid(
                &request,
                "operation is outside the Q04 graph partition",
            ));
        }
    };
    let result = execute_file_graph_operation_v1(
        context,
        &query_root,
        &query_manifest_ref,
        &evidence_root,
        &evidence_manifest_ref,
        &expected,
        operation,
        &Value::Object(operation_payload),
    )
    .map_err(|error| map_error(&request, error))?;
    Ok(OperationResponseV2 {
        protocol_version: PROTOCOL_VERSION_V2.to_owned(),
        operation_id,
        request_id: request.request_id,
        result,
    })
}

const COMMON_FIELDS: &[&str] = &[
    "query_index_path",
    "query_manifest_ref",
    "evidence_index_path",
    "evidence_manifest_ref",
    "expected_identities",
];

const fn operation_fields(operation_id: V2OperationId) -> &'static [&'static str] {
    match operation_id {
        V2OperationId::GraphNeighbors => &[
            "node_id",
            "direction",
            "max_results",
            "continuation",
            "previous_page",
        ],
        V2OperationId::GraphPath => &["source_node_id", "target_node_id", "max_depth"],
        V2OperationId::GraphImpact => &[
            "node_id",
            "max_depth",
            "max_results",
            "continuation",
            "previous_page",
        ],
        V2OperationId::GraphExplain => &["node_id", "max_results", "continuation", "previous_page"],
        V2OperationId::GraphTrace => &["entity_id"],
        V2OperationId::GraphSearch => &["query", "max_results", "continuation"],
        _ => &[],
    }
}

fn relative_directory(
    context: &CallContext,
    request: &OperationRequestV2,
    object: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<PathBuf, V2ErrorEnvelope> {
    let value = object
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| invalid(request, &format!("{field} must be a non-empty string")))?;
    let relative = Path::new(value);
    if relative.is_absolute()
        || relative.components().any(|component| {
            matches!(
                component,
                Component::ParentDir
                    | Component::CurDir
                    | Component::RootDir
                    | Component::Prefix(_)
            )
        })
    {
        return Err(invalid(
            request,
            &format!("{field} must remain below the authorized workspace root"),
        ));
    }
    let workspace = context.workspace_root().ok_or_else(|| {
        invalid(
            request,
            "no authorized workspace root is available for file graph query",
        )
    })?;
    let candidate = workspace.join(relative);
    context
        .authorize_read(&candidate)
        .map_err(|error| map_context_error(request, field, error))?;
    Ok(candidate)
}

fn parse_field<T: serde::de::DeserializeOwned>(
    request: &OperationRequestV2,
    object: &serde_json::Map<String, Value>,
    field: &str,
    message: &str,
) -> Result<T, V2ErrorEnvelope> {
    object
        .get(field)
        .cloned()
        .ok_or_else(|| invalid(request, message))
        .and_then(|value| serde_json::from_value(value).map_err(|_| invalid(request, message)))
}

fn invalid(request: &OperationRequestV2, message: &str) -> V2ErrorEnvelope {
    V2ErrorEnvelope::new(
        request,
        V2ErrorCode::InvalidRequest,
        "file-graph-query",
        message,
        "provide query_index_path, exact manifest refs, expected identities, and only the operation-specific Q04 fields",
    )
}

fn map_context_error(
    request: &OperationRequestV2,
    field: &str,
    error: ContextError,
) -> V2ErrorEnvelope {
    let code = match error {
        ContextError::PathEscape(_) | ContextError::UnsafeRoot(_) => V2ErrorCode::PathEscape,
        ContextError::RootIo { .. } => V2ErrorCode::Io,
        ContextError::MissingRoot | ContextError::InvalidReceipt(_) => V2ErrorCode::InvalidRequest,
    };
    V2ErrorEnvelope::new(
        request,
        code,
        "file-graph-query",
        format!("{field} is not an authorized direct directory: {error}"),
        "place immutable Q03/Q04 index artifacts below the current authorized workspace root",
    )
}

fn map_error(request: &OperationRequestV2, error: FileGraphQueryErrorV1) -> V2ErrorEnvelope {
    let code = match error {
        FileGraphQueryErrorV1::InvalidRequest
        | FileGraphQueryErrorV1::ResourceBudgetExceeded
        | FileGraphQueryErrorV1::ContinuationInvalid => V2ErrorCode::InvalidRequest,
        FileGraphQueryErrorV1::StaleIndex
        | FileGraphQueryErrorV1::IndexInvalid
        | FileGraphQueryErrorV1::EvidenceTampered
        | FileGraphQueryErrorV1::KnowledgeUnattested => V2ErrorCode::IndexInvalid,
        FileGraphQueryErrorV1::UnsafePath => V2ErrorCode::PathEscape,
        FileGraphQueryErrorV1::NotFound => V2ErrorCode::NotFound,
        FileGraphQueryErrorV1::Io => V2ErrorCode::Io,
    };
    V2ErrorEnvelope::new(
        request,
        code,
        "file-graph-query",
        format!("{}: {error}", error.code()),
        "rebuild stale/tampered indices or correct the bounded query without falling back to a full graph read",
    )
}
