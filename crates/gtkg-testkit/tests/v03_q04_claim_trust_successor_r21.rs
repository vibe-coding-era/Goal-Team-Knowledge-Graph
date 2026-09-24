//! Q04 r21: lint-clean successor for the frozen r4 claim-trust API contract.
//!
//! The r4 test remains immutable after its observed implementation Red.  This
//! successor keeps the same strict writer signature assertion, but names the
//! function type so the active denominator can be compiled under the project
//! `clippy -D warnings` gate.

use std::path::Path;

use gtkg_core::CallContext;
use gtkg_core::knowledge_overlay_v2::KnowledgeOverlayBuildInputV2;
use gtkg_core::v03::graph_query::{
    FileGraphQueryErrorV1, GraphQueryEntityV1,
    write_graph_query_evidence_index_from_verified_overlay_v1,
};
use gtkg_protocol::FileReceiptRef;
use gtkg_protocol::v03::query::FileQueryExpectedIdentitiesV1;

type StrictVerifiedOverlayWriter = fn(
    &CallContext,
    &Path,
    &FileQueryExpectedIdentitiesV1,
    &FileReceiptRef,
    &str,
    &[GraphQueryEntityV1],
    &KnowledgeOverlayBuildInputV2,
) -> Result<FileReceiptRef, FileGraphQueryErrorV1>;

#[test]
fn q04_strict_writer_signature_remains_available_under_the_active_lint_gate() {
    let strict_writer: StrictVerifiedOverlayWriter =
        write_graph_query_evidence_index_from_verified_overlay_v1;
    let _ = strict_writer;
}
