//! V0.3 handler slices bound by their owning Product Surface tasks.

mod p02_analysis;
mod p03_context_summary;
mod p04_lifecycle;
mod p05_domain;
mod q04_graph;
mod system_source;

use gtkg_protocol::v2::{OperationRequestV2, OperationResponseV2, V2ErrorEnvelope, V2OperationId};

use crate::CallContext;

#[allow(clippy::result_large_err)]
pub(crate) fn execute(
    context: &CallContext,
    request: OperationRequestV2,
    operation_id: V2OperationId,
) -> Result<OperationResponseV2, V2ErrorEnvelope> {
    if q04_graph::owns(operation_id) {
        q04_graph::execute(context, request, operation_id)
    } else if p02_analysis::owns(operation_id) {
        p02_analysis::execute(context, request, operation_id)
    } else if p03_context_summary::owns(operation_id) {
        p03_context_summary::execute(context, request, operation_id)
    } else if p04_lifecycle::owns(operation_id) {
        p04_lifecycle::execute(context, request, operation_id)
    } else if p05_domain::owns(operation_id) {
        p05_domain::execute(context, request, operation_id)
    } else {
        system_source::execute(context, request, operation_id)
    }
}
