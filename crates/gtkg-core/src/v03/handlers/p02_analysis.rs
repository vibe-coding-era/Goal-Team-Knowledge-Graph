//! P02 v2 analysis handler boundary.

#![allow(clippy::result_large_err)]

use gtkg_protocol::v2::{
    OperationRequestV2, OperationResponseV2, PROTOCOL_VERSION_V2, V2ErrorCode, V2ErrorEnvelope,
    V2OperationId,
};
use serde::de::DeserializeOwned;

use crate::CallContext;
use crate::v03::analysis;

pub(crate) const fn owns(operation_id: V2OperationId) -> bool {
    matches!(
        operation_id,
        V2OperationId::AnalysisPlan | V2OperationId::AnalysisBuild | V2OperationId::AnalysisVerify
    )
}

pub(crate) fn execute(
    context: &CallContext,
    request: OperationRequestV2,
    operation_id: V2OperationId,
) -> Result<OperationResponseV2, V2ErrorEnvelope> {
    let outcome = match operation_id {
        V2OperationId::AnalysisPlan => analysis::plan(context, payload(&request)?),
        V2OperationId::AnalysisBuild => analysis::build(context, payload(&request)?),
        V2OperationId::AnalysisVerify => analysis::verify(context, payload(&request)?),
        _ => {
            return Err(V2ErrorEnvelope::new(
                &request,
                V2ErrorCode::OperationNotImplemented,
                "dispatch",
                "operation is outside the P02 analysis partition",
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
    let _receipt = outcome.reference;
    Ok(OperationResponseV2 {
        protocol_version: PROTOCOL_VERSION_V2.to_owned(),
        operation_id,
        request_id: request.request_id,
        result: outcome.summary,
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
            "use the exact closed P02 payload schema",
        )
    })
}
