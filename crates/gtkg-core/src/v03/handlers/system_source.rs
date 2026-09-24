//! P01 system, config, capability, and source-capture handlers.

#![allow(clippy::result_large_err)]

use std::fs;
use std::path::{Component, Path, PathBuf};

use gtkg_protocol::v2::{
    CapabilityDescribePayloadV2, ConfigValidatePayloadV2, OperationRequestV2, OperationResponseV2,
    PROTOCOL_VERSION_V2, SourceCapturePayloadV2, SystemDescribePayloadV2, V2_PUBLIC_OPERATIONS,
    V2ErrorCode, V2ErrorEnvelope, V2OperationId,
};
use gtkg_protocol::{CORE_VERSION, ErrorCode, OperationId, OperationRequest};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use crate::durable::{DurableErrorKind, publish_immutable_json};
use crate::exact_read::read_bound_regular_file;
use crate::source_v2::{
    CaptureErrorCode, SourceCaptureErrorV2, SourceCaptureRequestV2, capture_source_snapshot_v2,
};
use crate::{CallContext, ContextError};

pub(crate) fn execute(
    context: &CallContext,
    request: OperationRequestV2,
    operation_id: V2OperationId,
) -> Result<OperationResponseV2, V2ErrorEnvelope> {
    match operation_id {
        V2OperationId::SystemDescribe => system_describe(&request),
        V2OperationId::ConfigValidate => config_validate(context, &request),
        V2OperationId::CapabilityDescribe => capability_describe(&request),
        V2OperationId::SourceCapture => source_capture(context, &request),
        _ => Err(error(
            &request,
            V2ErrorCode::OperationNotImplemented,
            "dispatch",
            "operation is outside the P01 handler partition",
            "route the operation through its owning TaskExactSet handler",
        )),
    }
}

fn system_describe(request: &OperationRequestV2) -> Result<OperationResponseV2, V2ErrorEnvelope> {
    let _: SystemDescribePayloadV2 = payload(request)?;
    let implemented_operation_count = V2_PUBLIC_OPERATIONS
        .iter()
        .filter(|definition| {
            definition.availability == gtkg_protocol::v2::OperationAvailabilityV2::Implemented
        })
        .count();
    let callable_operation_count = V2_PUBLIC_OPERATIONS
        .iter()
        .filter(|definition| definition.callability == gtkg_protocol::v2::CallabilityV2::Callable)
        .count();
    Ok(completed(
        request,
        V2OperationId::SystemDescribe,
        json!({
            "product": "gtkg",
            "core_version": CORE_VERSION,
            "protocol_version": PROTOCOL_VERSION_V2,
            "public_operation_count": V2_PUBLIC_OPERATIONS.len(),
            "implemented_operation_count": implemented_operation_count,
            "callable_operation_count": callable_operation_count,
            "operations": V2_PUBLIC_OPERATIONS,
            "database_backend": null,
            "storage_model": "okf-and-ordinary-files",
        }),
    ))
}

fn config_validate(
    context: &CallContext,
    request: &OperationRequestV2,
) -> Result<OperationResponseV2, V2ErrorEnvelope> {
    let payload: ConfigValidatePayloadV2 = payload(request)?;
    let requested_config = requested_path(context, &payload.config_path, request)?;
    if fs::symlink_metadata(&requested_config).is_err()
        && let Some(parent) = requested_config.parent()
    {
        context
            .authorize_read(parent)
            .map_err(|failure| context_error(request, "config.validate", failure))?;
    }
    let config_path = context
        .authorize_read(&requested_config)
        .map_err(|failure| context_error(request, "config.validate", failure))?;
    reject_symlink_components(context, &requested_config, &config_path, request)?;
    let legacy = OperationRequest::new(
        OperationId::ConfigValidate,
        request.request_id.clone(),
        json!({"config_path": config_path}),
    );
    crate::config::validate(context, &legacy)
        .map(|response| completed(request, V2OperationId::ConfigValidate, response.result))
        .map_err(|failure| {
            error(
                request,
                v1_error_code(failure.code),
                failure.stage,
                failure.message,
                failure.recovery_hint,
            )
        })
}

fn capability_describe(
    request: &OperationRequestV2,
) -> Result<OperationResponseV2, V2ErrorEnvelope> {
    let _: CapabilityDescribePayloadV2 = payload(request)?;
    let implemented_operation_ids = V2_PUBLIC_OPERATIONS
        .iter()
        .filter(|definition| {
            definition.availability == gtkg_protocol::v2::OperationAvailabilityV2::Implemented
        })
        .map(|definition| definition.id.as_str())
        .collect::<Vec<_>>();
    let complete_46_operation_product = implemented_operation_ids.len() == 46
        && implemented_operation_ids.len() == V2_PUBLIC_OPERATIONS.len();
    Ok(completed(
        request,
        V2OperationId::CapabilityDescribe,
        json!({
            "schema_version": "gtkg.capability-description/v1",
            "profile_id": "GTKG-V0.3-CORE",
            "storage_model": "okf-and-ordinary-files",
            "database_backend": null,
            "native_languages": ["Rust", "Python", "TypeScript", "JavaScript"],
            "operation_surface": {
                "protocol_version": PROTOCOL_VERSION_V2,
                "public_operation_count": V2_PUBLIC_OPERATIONS.len(),
                "implemented_operation_count": implemented_operation_ids.len(),
                "implemented_operation_ids": implemented_operation_ids,
                "complete_46_operation_product": complete_46_operation_product,
            },
            "source_snapshot": {
                "schema_version": "gtkg.source-snapshot/v2",
                "capture_modes": ["worktree_exact", "directory_exact", "git_commit"],
                "supplied_manifest_transport": "not_implemented_without_trusted_authority",
                "toctou_policy": "fail_closed",
                "output_policy": "caller_authorized_immutable_json",
            },
            "authority": {
                "target_code_execution": false,
                "network_required": false,
                "external_git_write": false,
                "current_write": false,
            },
        }),
    ))
}

fn source_capture(
    context: &CallContext,
    request: &OperationRequestV2,
) -> Result<OperationResponseV2, V2ErrorEnvelope> {
    let payload: SourceCapturePayloadV2 = payload(request)?;
    let source_root = requested_path(context, &payload.source_root, request)?;
    let authorized_source_root = context
        .authorize_read(&source_root)
        .map_err(|failure| context_error(request, "source.capture.path", failure))?;
    reject_symlink_components(context, &source_root, &authorized_source_root, request)?;

    let requested_output = requested_path(context, &payload.output_path, request)?;
    let output_path = context
        .authorize_write(&requested_output)
        .map_err(|failure| context_error(request, "source.capture.path", failure))?;
    reject_symlink_components(context, &requested_output, &output_path, request)?;
    if !output_path
        .components()
        .any(|component| matches!(component, Component::Normal(name) if name == ".gtkg"))
    {
        return Err(error(
            request,
            V2ErrorCode::InvalidRequest,
            "source.capture.output",
            "source snapshot output must be below an authorized .gtkg directory",
            "choose a caller-authorized .gtkg/source-snapshots/*.json output path outside the source root",
        ));
    }
    let output_root = output_path.parent().ok_or_else(|| {
        error(
            request,
            V2ErrorCode::InvalidRequest,
            "source.capture.output",
            "source snapshot output path has no parent",
            "provide an exact JSON output file below an authorized .gtkg directory",
        )
    })?;
    let capture_request = SourceCaptureRequestV2::new(
        payload.capture_mode,
        payload.repository_id,
        authorized_source_root,
        output_root.to_path_buf(),
    );
    let snapshot = capture_source_snapshot_v2(&capture_request)
        .map_err(|failure| capture_error(request, failure))?;
    snapshot.validate().map_err(|failure| {
        error(
            request,
            V2ErrorCode::SourceChanged,
            "source.capture.validate",
            failure.to_string(),
            "recapture the exact source after all source identity changes have stopped",
        )
    })?;

    let persisted = publish_immutable_json(
        context,
        &output_path,
        &snapshot,
        "source.capture.after_temp_sync_before_rename",
    )
    .map_err(|failure| {
        let code = match failure.kind {
            DurableErrorKind::Invalid => V2ErrorCode::InvalidRequest,
            DurableErrorKind::Unauthorized | DurableErrorKind::Unsafe => V2ErrorCode::PathEscape,
            DurableErrorKind::Conflict => V2ErrorCode::SourceSnapshotConflict,
            DurableErrorKind::Io => V2ErrorCode::Io,
        };
        error(
            request,
            code,
            "source.capture.write",
            failure.to_string(),
            "use a caller-authorized private .gtkg output path whose existing bytes match this exact snapshot",
        )
    })?;
    let readback = read_bound_regular_file(context, &persisted).map_err(|failure| {
        error(
            request,
            v1_error_code(failure.code),
            "source.capture.readback",
            format!("{}: {}", failure.path.display(), failure.message),
            "repair the private output path and retry the exact source capture",
        )
    })?;
    let observed = serde_json::from_slice::<gtkg_protocol::v2::SourceSnapshotV2>(&readback.bytes)
        .map_err(|failure| {
        error(
            request,
            V2ErrorCode::SourceSnapshotConflict,
            "source.capture.readback",
            format!("persisted source snapshot is invalid JSON: {failure}"),
            "quarantine the conflicting output and retry with an unused exact path",
        )
    })?;
    observed.validate().map_err(|failure| {
        error(
            request,
            V2ErrorCode::SourceSnapshotConflict,
            "source.capture.readback",
            failure.to_string(),
            "quarantine the conflicting output and retry with an unused exact path",
        )
    })?;
    if observed != snapshot {
        return Err(error(
            request,
            V2ErrorCode::SourceSnapshotConflict,
            "source.capture.readback",
            "persisted SourceSnapshotV2 differs from the captured snapshot",
            "quarantine the conflicting output and retry with an unused exact path",
        ));
    }
    let exact_set_sha256 = snapshot.exact_set_sha256.clone();
    Ok(completed(
        request,
        V2OperationId::SourceCapture,
        json!({
            "snapshot": snapshot,
            "snapshot_ref": {
                "path": requested_output.to_string_lossy(),
                "artifact_sha256": readback.sha256,
                "exact_set_sha256": exact_set_sha256,
                "readback": "passed",
            },
            "canonical_write_count": 0,
            "external_write_count": 0,
        }),
    ))
}

fn payload<T>(request: &OperationRequestV2) -> Result<T, V2ErrorEnvelope>
where
    T: DeserializeOwned,
{
    serde_json::from_value(request.payload.clone()).map_err(|failure| {
        error(
            request,
            V2ErrorCode::InvalidRequest,
            "payload-schema",
            failure.to_string(),
            "use the exact closed payload schema disclosed for this v2 operation",
        )
    })
}

fn requested_path(
    context: &CallContext,
    value: &str,
    request: &OperationRequestV2,
) -> Result<PathBuf, V2ErrorEnvelope> {
    let path = PathBuf::from(value);
    if path.is_absolute() {
        return Ok(path);
    }
    context
        .workspace_root()
        .map(|root| root.join(path))
        .ok_or_else(|| context_error(request, "source.capture.path", ContextError::MissingRoot))
}

fn reject_symlink_components(
    context: &CallContext,
    requested: &Path,
    authorized: &Path,
    request: &OperationRequestV2,
) -> Result<(), V2ErrorEnvelope> {
    let lexical_root = context
        .authorized_lexical_roots()
        .iter()
        .chain(context.authorized_roots())
        .filter(|root| requested == root.as_path() || requested.starts_with(root))
        .max_by_key(|root| root.components().count());
    let (candidate, root) = if let Some(root) = lexical_root {
        (requested, root.as_path())
    } else {
        let root = context
            .authorized_roots()
            .iter()
            .filter(|root| authorized == root.as_path() || authorized.starts_with(root))
            .max_by_key(|root| root.components().count())
            .ok_or_else(|| {
                error(
                    request,
                    V2ErrorCode::PathEscape,
                    "source.capture.path",
                    format!(
                        "path is outside the authorized roots: {}",
                        requested.display()
                    ),
                    "use only paths below an exact caller-authorized root",
                )
            })?;
        (authorized, root.as_path())
    };
    let relative = candidate.strip_prefix(root).map_err(|_| {
        error(
            request,
            V2ErrorCode::PathEscape,
            "source.capture.path",
            format!(
                "path is outside the authorized roots: {}",
                requested.display()
            ),
            "use only paths below an exact caller-authorized root",
        )
    })?;
    let mut cursor = root.to_path_buf();
    for component in relative.components() {
        let Component::Normal(name) = component else {
            return Err(error(
                request,
                V2ErrorCode::PathEscape,
                "source.capture.path",
                format!("unsafe path component in {}", requested.display()),
                "remove relative traversal and retry with an exact authorized path",
            ));
        };
        cursor.push(name);
        match fs::symlink_metadata(&cursor) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(error(
                    request,
                    V2ErrorCode::SymlinkRejected,
                    "source.capture.path",
                    format!("symbolic link is not permitted: {}", cursor.display()),
                    "replace the symlink with a private regular file or directory",
                ));
            }
            Ok(_) => {}
            Err(failure) if failure.kind() == std::io::ErrorKind::NotFound => break,
            Err(failure) => {
                return Err(error(
                    request,
                    V2ErrorCode::Io,
                    "source.capture.path",
                    format!("{}: {failure}", cursor.display()),
                    "repair the caller-authorized path and retry",
                ));
            }
        }
    }
    Ok(())
}

fn capture_error(request: &OperationRequestV2, failure: SourceCaptureErrorV2) -> V2ErrorEnvelope {
    let code = match failure.code() {
        CaptureErrorCode::InvalidRequest
        | CaptureErrorCode::UntrustedAuthority
        | CaptureErrorCode::ManifestMismatch => V2ErrorCode::InvalidRequest,
        CaptureErrorCode::SourceNotGit => V2ErrorCode::SourceNotGit,
        CaptureErrorCode::SourceDirty => V2ErrorCode::SourceDirty,
        CaptureErrorCode::SourceOutputOverlap => V2ErrorCode::SourceOutputOverlap,
        CaptureErrorCode::SymlinkRejected => V2ErrorCode::SymlinkRejected,
        CaptureErrorCode::SnapshotDrift => V2ErrorCode::SourceChanged,
        CaptureErrorCode::Io => V2ErrorCode::Io,
    };
    error(
        request,
        code,
        "source.capture",
        failure.to_string(),
        "repair the exact source/output identity and retry without lowering the capture mode",
    )
}

fn context_error(
    request: &OperationRequestV2,
    stage: &'static str,
    failure: ContextError,
) -> V2ErrorEnvelope {
    let code = match &failure {
        ContextError::PathEscape(_) | ContextError::UnsafeRoot(_) => V2ErrorCode::PathEscape,
        ContextError::RootIo { source, .. } if source.kind() == std::io::ErrorKind::NotFound => {
            V2ErrorCode::NotFound
        }
        ContextError::RootIo { .. } => V2ErrorCode::Io,
        ContextError::MissingRoot | ContextError::InvalidReceipt(_) => V2ErrorCode::InvalidRequest,
    };
    error(
        request,
        code,
        stage,
        failure.to_string(),
        "use only exact paths below a caller-authorized private root",
    )
}

fn v1_error_code(code: ErrorCode) -> V2ErrorCode {
    match code {
        ErrorCode::InvalidRequest => V2ErrorCode::InvalidRequest,
        ErrorCode::PathEscape | ErrorCode::ScopeDenied => V2ErrorCode::PathEscape,
        ErrorCode::SymlinkRejected => V2ErrorCode::SymlinkRejected,
        ErrorCode::SourceNotGit => V2ErrorCode::SourceNotGit,
        ErrorCode::SourceDirty => V2ErrorCode::SourceDirty,
        ErrorCode::DatabaseForbidden => V2ErrorCode::DatabaseForbidden,
        ErrorCode::NotFound => V2ErrorCode::NotFound,
        ErrorCode::Io => V2ErrorCode::Io,
        ErrorCode::SideEffectDenied => V2ErrorCode::SideEffectDenied,
        _ => V2ErrorCode::InvalidRequest,
    }
}

fn completed(
    request: &OperationRequestV2,
    operation_id: V2OperationId,
    result: Value,
) -> OperationResponseV2 {
    OperationResponseV2 {
        protocol_version: PROTOCOL_VERSION_V2.to_owned(),
        operation_id,
        request_id: request.request_id.clone(),
        result,
    }
}

fn error(
    request: &OperationRequestV2,
    code: V2ErrorCode,
    stage: impl Into<String>,
    message: impl Into<String>,
    recovery_hint: impl Into<String>,
) -> V2ErrorEnvelope {
    V2ErrorEnvelope::new(request, code, stage, message, recovery_hint)
}
