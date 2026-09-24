//! P05 v2 bindings for the existing file-only v1 domain implementations.

#![allow(clippy::result_large_err)]

use gtkg_protocol::v2::{
    OperationRequestV2, OperationResponseV2, PROTOCOL_VERSION_V2, V2ErrorCode, V2ErrorEnvelope,
    V2OperationId,
};
use gtkg_protocol::{ErrorCode, OperationId, OperationRequest};

use crate::{CallContext, Dispatcher};

pub(crate) const fn owns(operation_id: V2OperationId) -> bool {
    legacy_operation(operation_id).is_some()
}

pub(crate) fn execute(
    context: &CallContext,
    request: OperationRequestV2,
    operation_id: V2OperationId,
) -> Result<OperationResponseV2, V2ErrorEnvelope> {
    let legacy_id = legacy_operation(operation_id).ok_or_else(|| {
        V2ErrorEnvelope::new(
            &request,
            V2ErrorCode::OperationNotImplemented,
            "dispatch",
            "operation is outside the P05 domain partition",
            "route the operation through its owning TaskExactSet handler",
        )
    })?;
    let legacy_request = OperationRequest::new(
        legacy_id,
        request.request_id.clone(),
        request.payload.clone(),
    );
    match Dispatcher.execute(context, legacy_request) {
        Ok(response) => Ok(OperationResponseV2 {
            protocol_version: PROTOCOL_VERSION_V2.to_owned(),
            operation_id,
            request_id: request.request_id,
            result: response.result,
        }),
        Err(failure) => Err(V2ErrorEnvelope::new(
            &request,
            v1_error_code(failure.error.code),
            failure.error.stage,
            failure.error.message,
            failure.error.recovery_hint,
        )),
    }
}

const fn legacy_operation(operation_id: V2OperationId) -> Option<OperationId> {
    match operation_id {
        V2OperationId::GitPublish => Some(OperationId::GitPublish),
        V2OperationId::CurrentGet => Some(OperationId::CurrentGet),
        V2OperationId::CurrentActivate => Some(OperationId::CurrentActivate),
        V2OperationId::NodeDescribe => Some(OperationId::NodeDescribe),
        V2OperationId::FederationValidate => Some(OperationId::FederationValidate),
        V2OperationId::TemplateList => Some(OperationId::TemplateList),
        V2OperationId::TemplateResolve => Some(OperationId::TemplateResolve),
        V2OperationId::TemplatePrefetch => Some(OperationId::TemplatePrefetch),
        V2OperationId::TemplateGet => Some(OperationId::TemplateGet),
        V2OperationId::TemplateValidate => Some(OperationId::TemplateValidate),
        V2OperationId::TemplateDerive => Some(OperationId::TemplateDerive),
        V2OperationId::TemplatePublish => Some(OperationId::TemplatePublish),
        V2OperationId::DeliverableDerive => Some(OperationId::DeliverableDerive),
        V2OperationId::DeliverablePublish => Some(OperationId::DeliverablePublish),
        V2OperationId::A2uiResolve => Some(OperationId::A2uiResolve),
        V2OperationId::A2uiGenerate => Some(OperationId::A2uiGenerate),
        V2OperationId::A2uiGet => Some(OperationId::A2uiGet),
        V2OperationId::A2uiValidate => Some(OperationId::A2uiValidate),
        _ => None,
    }
}

const fn v1_error_code(code: ErrorCode) -> V2ErrorCode {
    match code {
        ErrorCode::ProtocolVersionMismatch => V2ErrorCode::ProtocolVersionMismatch,
        ErrorCode::InvalidRequest => V2ErrorCode::InvalidRequest,
        ErrorCode::OperationNotImplemented => V2ErrorCode::OperationNotImplemented,
        ErrorCode::Io => V2ErrorCode::Io,
        ErrorCode::PathEscape => V2ErrorCode::PathEscape,
        ErrorCode::ScopeDenied => V2ErrorCode::ScopeDenied,
        ErrorCode::SideEffectDenied => V2ErrorCode::SideEffectDenied,
        ErrorCode::SymlinkRejected => V2ErrorCode::SymlinkRejected,
        ErrorCode::SourceNotGit => V2ErrorCode::SourceNotGit,
        ErrorCode::SourceDirty => V2ErrorCode::SourceDirty,
        ErrorCode::LockMismatch => V2ErrorCode::LockMismatch,
        ErrorCode::InvalidState => V2ErrorCode::InvalidState,
        ErrorCode::OkfInvalid => V2ErrorCode::OkfInvalid,
        ErrorCode::IndexInvalid => V2ErrorCode::IndexInvalid,
        ErrorCode::VersionImmutable => V2ErrorCode::VersionImmutable,
        ErrorCode::DatabaseForbidden => V2ErrorCode::DatabaseForbidden,
        ErrorCode::ExtractUnsupported => V2ErrorCode::ExtractUnsupported,
        ErrorCode::ExtractInvalid => V2ErrorCode::ExtractInvalid,
        ErrorCode::BundleInvalid => V2ErrorCode::BundleInvalid,
        ErrorCode::NotFound => V2ErrorCode::NotFound,
        ErrorCode::NonDeterministicResult => V2ErrorCode::NonDeterministicResult,
        ErrorCode::SandboxAssuranceUnavailable => V2ErrorCode::SandboxAssuranceUnavailable,
    }
}
