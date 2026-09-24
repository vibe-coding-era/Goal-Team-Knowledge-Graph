//! T15C local current-OKF four-axis suite.
//!
//! This is a reducer over already-produced local evidence.  It does not fetch
//! a specification, create a reference result, or certify a product.  In
//! particular, a pass is limited to the frozen T03 corpus and the exact T11B
//! and T14A identities supplied by the caller.

use std::path::Path;

use gtkg_protocol::v2::{
    OkfAxisStatusV2, OkfFourAxisVerdictV2, OkfInternalVerdictV2, OkfSpecPinV2,
};
use gtkg_protocol::validate_sha256;

use crate::document_relations::T03RelationBindingV2;
use crate::knowledge_overlay_v2::{KnowledgeOverlayV2, read_knowledge_overlay_v2};
use crate::lifecycle_v2::LifecycleIdentityV2;
use crate::okf::{parse_okf, parse_okf_concept, validate_current_version};
use crate::okf_v2::CurrentNormativeCorpusValidationV2;
use crate::runtime_receipt_v2::{
    LocalRuntimeLifecycleReceiptV2, read_local_runtime_lifecycle_receipt_v2,
};

/// Local documents used to test the two internal profiles.  Consumer and
/// producer inputs are kept separate so a tolerant consumer cannot compensate
/// for a producer that emits an invalid current-profile document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InternalOkfProfileV2 {
    pub consumer_documents: Vec<String>,
    pub producer_documents: Vec<String>,
}

/// Exact inputs to the local T15C reducer.  T03 owns the corpus and pinned
/// runner execution; T11B owns the overlay; T14A owns the local runtime
/// receipt.  T15C only verifies that the facts remain bound together.
#[derive(Debug, Clone)]
pub struct LocalCurrentOkfSuiteInputV2<'a> {
    pub pin: OkfSpecPinV2,
    pub internal_profile: InternalOkfProfileV2,
    pub current_corpus: CurrentNormativeCorpusValidationV2,
    pub t03_receipt_sha256: String,
    pub knowledge_overlay: &'a KnowledgeOverlayV2,
    pub lifecycle_identity: &'a LifecycleIdentityV2,
    pub runtime_receipt: &'a LocalRuntimeLifecycleReceiptV2,
}

/// Readback-only T15C input.  Unlike [`LocalCurrentOkfSuiteInputV2`], all
/// evidence-bearing artifacts are read from exact files before reduction.
pub struct LocalCurrentOkfSuiteReadbackInputV2<'a> {
    pub workspace_root: &'a Path,
    pub pin: OkfSpecPinV2,
    pub internal_profile: InternalOkfProfileV2,
    pub current_corpus: CurrentNormativeCorpusValidationV2,
    pub corpus_manifest_path: &'a Path,
    pub overlay_artifact_root: &'a Path,
    pub lifecycle_identity: &'a LifecycleIdentityV2,
    pub runtime_receipt_path: &'a Path,
    pub runtime_event_path: &'a Path,
    pub cli_mcp_identity_sha256: String,
}

/// The local four-axis observation.  `google_certification` is deliberately a
/// false boolean instead of a nullable marketing claim: this suite cannot
/// produce one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalCurrentOkfSuiteResultV2 {
    pub verdict: OkfFourAxisVerdictV2,
    pub scope: &'static str,
    pub google_certification: bool,
    pub boundary: &'static str,
}

/// Execute the two internal profiles.  Both profiles must have at least one
/// fixed document and use the current profile version.  This is local product
/// evidence only, not an external interoperability result.
pub fn validate_internal_okf_profiles(profile: &InternalOkfProfileV2) -> OkfInternalVerdictV2 {
    let consumer = profile_axis_status(&profile.consumer_documents, false);
    let producer = profile_axis_status(&profile.producer_documents, true);
    OkfInternalVerdictV2::new(consumer, producer)
}

/// Reduces T03/T11B/T14A evidence into independent verdicts.  No axis is
/// allowed to compensate for another.  A locally passed result remains scoped
/// to the frozen corpus and never represents Google certification.
pub fn validate_local_current_okf_suite(
    input: LocalCurrentOkfSuiteInputV2<'_>,
) -> LocalCurrentOkfSuiteResultV2 {
    let internal = validate_internal_okf_profiles(&input.internal_profile);
    let pin_valid = input.pin.validate().is_ok();
    let current_official_format = corpus_axis_status(
        input.current_corpus.official_format.status,
        input.current_corpus.case_count,
        input.current_corpus.receipt_path.is_some(),
        pin_valid,
    );
    let reference_compatibility = corpus_axis_status(
        input.current_corpus.reference_compatibility.status,
        input.current_corpus.case_count,
        input.current_corpus.receipt_path.is_some(),
        pin_valid,
    );
    let curated_profile = curated_profile_axis_status(&input, pin_valid);
    LocalCurrentOkfSuiteResultV2 {
        verdict: OkfFourAxisVerdictV2::new(
            input.pin,
            internal,
            current_official_format,
            reference_compatibility,
            curated_profile,
        ),
        scope: "local_frozen_current_corpus",
        google_certification: false,
        boundary: "Local frozen-corpus observation only; not Google certification or general OKF conformance.",
    }
}

/// Strict T15C entrypoint. T03 receipt bytes/pin, T11B manifest+overlay bytes,
/// and T14A persisted receipt+event are independently read before evaluation.
pub fn validate_local_current_okf_suite_from_readbacks(
    input: LocalCurrentOkfSuiteReadbackInputV2<'_>,
) -> LocalCurrentOkfSuiteResultV2 {
    let internal = validate_internal_okf_profiles(&input.internal_profile);
    let binding = input
        .current_corpus
        .receipt_path
        .as_ref()
        .and_then(|receipt_path| {
            T03RelationBindingV2::from_receipt(
                input.workspace_root,
                input.pin.clone(),
                input.corpus_manifest_path,
                receipt_path,
            )
            .ok()
        });
    let overlay = read_knowledge_overlay_v2(input.overlay_artifact_root).ok();
    let runtime = read_local_runtime_lifecycle_receipt_v2(
        input.runtime_receipt_path,
        input.runtime_event_path,
    )
    .ok();
    let corpus_valid = binding.is_some();
    let current = corpus_axis_status(
        input.current_corpus.official_format.status,
        input.current_corpus.case_count,
        corpus_valid,
        input.pin.validate().is_ok(),
    );
    let reference = corpus_axis_status(
        input.current_corpus.reference_compatibility.status,
        input.current_corpus.case_count,
        corpus_valid,
        input.pin.validate().is_ok(),
    );
    let curated = match (binding, overlay, runtime) {
        (Some(binding), Some(overlay), Some(runtime))
            if runtime.verifier.verifier_sha256 == input.cli_mcp_identity_sha256 =>
        {
            curated_profile_axis_status(
                &LocalCurrentOkfSuiteInputV2 {
                    pin: input.pin.clone(),
                    internal_profile: input.internal_profile,
                    current_corpus: input.current_corpus,
                    t03_receipt_sha256: binding.receipt_sha256,
                    knowledge_overlay: &overlay,
                    lifecycle_identity: input.lifecycle_identity,
                    runtime_receipt: &runtime,
                },
                true,
            )
        }
        _ => OkfAxisStatusV2::Invalid,
    };
    LocalCurrentOkfSuiteResultV2 {
        verdict: OkfFourAxisVerdictV2::new(input.pin, internal, current, reference, curated),
        scope: "local_frozen_current_corpus",
        google_certification: false,
        boundary: "Local frozen-corpus observation only; not Google certification or general OKF conformance.",
    }
}

fn profile_axis_status(documents: &[String], producer: bool) -> OkfAxisStatusV2 {
    if documents.is_empty() {
        return OkfAxisStatusV2::NotRun;
    }
    let all_valid = documents.iter().all(|document| {
        let parsed = if producer {
            parse_okf_concept(document)
        } else {
            parse_okf(document)
        };
        parsed.is_ok_and(|document| validate_current_version(&document.frontmatter).is_ok())
    });
    if all_valid {
        OkfAxisStatusV2::Passed
    } else {
        OkfAxisStatusV2::Failed
    }
}

fn corpus_axis_status(
    observed: OkfAxisStatusV2,
    case_count: usize,
    receipt_present: bool,
    pin_valid: bool,
) -> OkfAxisStatusV2 {
    if !pin_valid {
        return OkfAxisStatusV2::Invalid;
    }
    // T03's Standards-reviewed local corpus is fixed at 13 cases. A caller
    // cannot re-label a smaller ad-hoc sample as this current observation.
    if observed.is_passed() && (case_count != 13 || !receipt_present) {
        return OkfAxisStatusV2::Invalid;
    }
    observed
}

fn curated_profile_axis_status(
    input: &LocalCurrentOkfSuiteInputV2<'_>,
    pin_valid: bool,
) -> OkfAxisStatusV2 {
    if !pin_valid || validate_sha256(&input.t03_receipt_sha256).is_err() {
        return OkfAxisStatusV2::Invalid;
    }
    let runtime_identity_matches = input
        .lifecycle_identity
        .identity_sha256()
        .map(|digest| digest == input.runtime_receipt.selection.lifecycle_identity_sha256)
        .unwrap_or(false);
    if input.runtime_receipt.validate().is_err()
        || input.lifecycle_identity.validate().is_err()
        || !runtime_identity_matches
    {
        return OkfAxisStatusV2::Invalid;
    }
    let overlay = input.knowledge_overlay;
    if overlay.schema_version != "gtkg.knowledge-overlay/v2"
        || overlay.layer != "knowledge_overlay"
        || overlay.nodes.is_empty()
        || validate_sha256(&overlay.overlay_sha256).is_err()
        || input.lifecycle_identity.knowledge_overlay_sha256 != overlay.overlay_sha256
        || input.lifecycle_identity.structural_graph_sha256 != overlay.structural_graph_sha256
    {
        return OkfAxisStatusV2::Invalid;
    }
    let node_provenance_matches = overlay.nodes.iter().all(|node| {
        node.provenance.t03_receipt_sha256 == input.t03_receipt_sha256
            && node.provenance.structural_graph_sha256 == overlay.structural_graph_sha256
    });
    let edge_provenance_matches = overlay.edges.iter().all(|edge| {
        edge.provenance.t03_receipt_sha256 == input.t03_receipt_sha256
            && edge.provenance.structural_graph_sha256 == overlay.structural_graph_sha256
    });
    let has_t03_bound_provenance = overlay.nodes.iter().any(|node| {
        node.kind == "provenance" && node.provenance.t03_receipt_sha256 == input.t03_receipt_sha256
    });
    if node_provenance_matches && edge_provenance_matches && has_t03_bound_provenance {
        OkfAxisStatusV2::Passed
    } else {
        OkfAxisStatusV2::Invalid
    }
}

#[cfg(test)]
mod tests {
    use super::{InternalOkfProfileV2, validate_internal_okf_profiles};
    use gtkg_protocol::v2::OkfAxisStatusV2;

    #[test]
    fn empty_internal_profile_is_not_run_not_passed() {
        let profile = InternalOkfProfileV2 {
            consumer_documents: Vec::new(),
            producer_documents: Vec::new(),
        };
        let verdict = validate_internal_okf_profiles(&profile);
        assert_eq!(verdict.consumer, OkfAxisStatusV2::NotRun);
        assert_eq!(verdict.producer, OkfAxisStatusV2::NotRun);
    }
}
