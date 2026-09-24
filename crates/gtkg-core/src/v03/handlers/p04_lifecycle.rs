//! P04 v2 lifecycle handler boundary.

#![allow(clippy::result_large_err)]

use gtkg_protocol::v2::{
    OperationRequestV2, OperationResponseV2, PROTOCOL_VERSION_V2, V2ErrorCode, V2ErrorEnvelope,
    V2OperationId,
};
use serde::de::DeserializeOwned;

use crate::CallContext;
use crate::v03::lifecycle;

pub(crate) const fn owns(operation: V2OperationId) -> bool {
    matches!(
        operation,
        V2OperationId::BuildFinalizeV2
            | V2OperationId::RunGet
            | V2OperationId::RunCancel
            | V2OperationId::BundleVerify
            | V2OperationId::BundleCompare
            | V2OperationId::BundleMigrateV1ToV2
            | V2OperationId::SnapshotCreate
            | V2OperationId::SnapshotVerify
            | V2OperationId::SnapshotRestore
    )
}

pub(crate) fn execute(
    context: &CallContext,
    request: OperationRequestV2,
    operation: V2OperationId,
) -> Result<OperationResponseV2, V2ErrorEnvelope> {
    let outcome = match operation {
        V2OperationId::BuildFinalizeV2 => lifecycle::finalize(context, payload(&request)?),
        V2OperationId::RunGet => lifecycle::run_get(context, payload(&request)?),
        V2OperationId::RunCancel => lifecycle::run_cancel(context, payload(&request)?),
        V2OperationId::BundleVerify => lifecycle::bundle_verify(context, payload(&request)?),
        V2OperationId::BundleCompare => lifecycle::bundle_compare(context, payload(&request)?),
        V2OperationId::BundleMigrateV1ToV2 => lifecycle::migrate(context, payload(&request)?),
        V2OperationId::SnapshotCreate => lifecycle::snapshot_create(context, payload(&request)?),
        V2OperationId::SnapshotVerify => lifecycle::snapshot_verify(context, payload(&request)?),
        V2OperationId::SnapshotRestore => lifecycle::snapshot_restore(context, payload(&request)?),
        _ => {
            return Err(V2ErrorEnvelope::new(
                &request,
                V2ErrorCode::OperationNotImplemented,
                "dispatch",
                "operation is outside the P04 lifecycle partition",
                "route through the owning handler",
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

fn payload<T: DeserializeOwned>(request: &OperationRequestV2) -> Result<T, V2ErrorEnvelope> {
    serde_json::from_value(request.payload.clone()).map_err(|error| {
        V2ErrorEnvelope::new(
            request,
            V2ErrorCode::InvalidRequest,
            "payload-schema",
            error.to_string(),
            "use the exact closed P04 payload schema",
        )
    })
}
