//! P03 v2 context and summary handler boundary.

#![allow(clippy::result_large_err)]

use gtkg_protocol::v2::{
    OperationRequestV2, OperationResponseV2, PROTOCOL_VERSION_V2, V2ErrorCode, V2ErrorEnvelope,
    V2OperationId,
};
use serde::de::DeserializeOwned;

use crate::CallContext;
use crate::v03::context_summary;

pub(crate) const fn owns(operation: V2OperationId) -> bool {
    matches!(
        operation,
        V2OperationId::ContextPack
            | V2OperationId::SummaryJobNext
            | V2OperationId::SummaryProposalSubmit
            | V2OperationId::SummaryVerificationNext
            | V2OperationId::SummaryVerificationSubmit
            | V2OperationId::SummaryAcceptV2
    )
}

pub(crate) fn execute(
    context: &CallContext,
    request: OperationRequestV2,
    operation: V2OperationId,
) -> Result<OperationResponseV2, V2ErrorEnvelope> {
    let outcome = match operation {
        V2OperationId::ContextPack => context_summary::context_pack(context, payload(&request)?),
        V2OperationId::SummaryJobNext => {
            context_summary::summary_job_next(context, payload(&request)?)
        }
        V2OperationId::SummaryProposalSubmit => {
            context_summary::proposal_submit(context, payload(&request)?)
        }
        V2OperationId::SummaryVerificationNext => {
            context_summary::verification_next(context, payload(&request)?)
        }
        V2OperationId::SummaryVerificationSubmit => {
            context_summary::verification_submit(context, payload(&request)?)
        }
        V2OperationId::SummaryAcceptV2 => context_summary::accept(context, payload(&request)?),
        _ => {
            return Err(V2ErrorEnvelope::new(
                &request,
                V2ErrorCode::OperationNotImplemented,
                "dispatch",
                "operation is outside the P03 context-summary partition",
                "route the operation through its owning TaskExactSet handler",
            ));
        }
    }
    .map_err(|failure| {
        V2ErrorEnvelope::new(
            &request,
            failure.code,
            failure.stage,
            failure.message,
            failure.recovery_hint,
        )
    })?;
    Ok(OperationResponseV2 {
        protocol_version: PROTOCOL_VERSION_V2.to_owned(),
        operation_id: operation,
        request_id: request.request_id,
        result: outcome.result,
    })
}

fn payload<T>(request: &OperationRequestV2) -> Result<T, V2ErrorEnvelope>
where
    T: DeserializeOwned,
{
    serde_json::from_value(request.payload.clone()).map_err(|error| {
        V2ErrorEnvelope::new(
            request,
            V2ErrorCode::InvalidRequest,
            "payload-schema",
            error.to_string(),
            "use the exact closed P03 payload schema",
        )
    })
}
