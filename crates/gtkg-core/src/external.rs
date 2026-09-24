//! Explicit fail-closed boundary for operations that require external grants.

use gtkg_protocol::{ErrorCode, OperationRequest, OperationResponse};

#[derive(Debug)]
pub struct ExternalFailure {
    pub code: ErrorCode,
    pub stage: &'static str,
    pub message: String,
    pub recovery_hint: &'static str,
}

pub fn execute(request: &OperationRequest) -> Result<OperationResponse, ExternalFailure> {
    Err(ExternalFailure {
        code: ErrorCode::SideEffectDenied,
        stage: "effect-policy",
        message: format!(
            "operation {} requires an explicit external write grant",
            request.operation_id.as_str()
        ),
        recovery_hint: "use a separately authorized Release context; Development adapters never grant external writes",
    })
}
