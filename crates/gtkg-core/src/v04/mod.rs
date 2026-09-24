//! Explicit V0.4 knowledge-quality capability. Existing v1 and v2 paths remain separate.
pub mod analysis;
pub mod artifact;
pub mod authoring;
pub mod graph_projection;
pub mod graph_read;
pub mod index;
pub mod knowledge;
pub mod lifecycle;
pub mod query;
pub mod source;
use crate::{CallContext, ContextError};
use gtkg_protocol::v2::{
    OperationRequestV2, OperationResponseV2, PROTOCOL_VERSION_V2, V2ErrorCode, V2ErrorEnvelope,
    V2OperationId as Op,
};
use gtkg_protocol::v04::{ArtifactPayload, PROFILE_ID, SourcePayload};
use serde_json::{Value, json};

/// A knowledge-quality failure that keeps the dedicated code of the layer that
/// produced it.
///
/// The dispatch used to collapse every failure into `E_INVALID_REQUEST`, so a
/// caller could not tell an unauthorized path from a malformed payload. A code is
/// only taken from layers that already carry one (the authorized-root
/// `ContextError` and the race-resistant exact-read `ErrorCode`). A free-form
/// message stays `E_INVALID_REQUEST` rather than being guessed from prose, so the
/// classification never becomes a string-matching heuristic.
#[derive(Debug)]
pub struct QkError {
    pub(crate) code: V2ErrorCode,
    pub(crate) stage: &'static str,
    pub(crate) message: String,
}

impl QkError {
    pub(crate) fn new(
        code: V2ErrorCode,
        stage: &'static str,
        message: impl Into<String>,
    ) -> Self {
        Self {
            code,
            stage,
            message: message.into(),
        }
    }
    pub(crate) fn invalid(message: impl Into<String>) -> Self {
        Self::new(V2ErrorCode::InvalidRequest, "knowledge-quality", message)
    }
    /// Preserve the dedicated code of an authorized-root failure.
    pub(crate) fn from_context(error: ContextError) -> Self {
        let code = match error {
            ContextError::PathEscape(_) => V2ErrorCode::PathEscape,
            ContextError::UnsafeRoot(_) | ContextError::MissingRoot => V2ErrorCode::ScopeDenied,
            ContextError::RootIo { .. } => V2ErrorCode::Io,
            ContextError::InvalidReceipt(_) => V2ErrorCode::InvalidRequest,
        };
        Self::new(code, "authorized-root", error.to_string())
    }
    /// Preserve the dedicated code of the race-resistant exact-read boundary.
    pub(crate) fn from_exact_read(
        code: gtkg_protocol::ErrorCode,
        message: impl Into<String>,
    ) -> Self {
        Self::new(V2ErrorCode::from_v1(code), "exact-read", message)
    }
}

impl From<String> for QkError {
    fn from(message: String) -> Self {
        Self::invalid(message)
    }
}

impl From<&str> for QkError {
    fn from(message: &str) -> Self {
        Self::invalid(message)
    }
}

/// Compatibility for the older `Result<_, String>` helpers inside this module.
///
/// Such a helper drops the dedicated code back to prose, so a caller that needs
/// the code must return [`QkError`] instead of `String`. This impl keeps the
/// existing wide surface compiling while the coded path is widened deliberately.
impl From<QkError> for String {
    fn from(error: QkError) -> Self {
        error.message
    }
}

#[allow(clippy::result_large_err)]
pub(crate) fn execute(
    context: &CallContext,
    request: OperationRequestV2,
    op: Op,
) -> Result<OperationResponseV2, V2ErrorEnvelope> {
    let result = dispatch(context, &request.payload, op).map_err(|e| {
        V2ErrorEnvelope::new(
            &request,
            e.code,
            e.stage,
            e.message,
            "use exact current successor artifacts within the authorized workspace",
        )
    })?;
    Ok(OperationResponseV2 {
        protocol_version: PROTOCOL_VERSION_V2.into(),
        operation_id: op,
        request_id: request.request_id,
        result,
    })
}
fn dispatch(context: &CallContext, value: &Value, op: Op) -> Result<Value, QkError> {
    match op {
        Op::CapabilityDescribe => Ok(json!({
            "capability_profile": PROFILE_ID,
            "payload_revision": gtkg_protocol::v04::PAYLOAD_REVISION,
            "public_operation_count": 46,
            "default_core_operation_count": 10,
            "query_policies": [
                gtkg_protocol::v04::QUERY_POLICY,
                gtkg_protocol::v04::SELECTIVE_QUERY_POLICY,
                gtkg_protocol::v04::REVIEWED_CONTEXT_QUERY_POLICY
            ],
            "preferred_query_policy": gtkg_protocol::v04::SELECTIVE_QUERY_POLICY,
            "knowledge_query_policy": gtkg_protocol::v04::REVIEWED_CONTEXT_QUERY_POLICY,
            "index_projection_policy": gtkg_protocol::v04::QUERY_POLICY,
            "languages": ["go", "rust", "python", "javascript", "typescript"],
            "storage": "okf-and-ordinary-files",
            "target_execution": false,
            "quality_axes": ["knowledge_ready", "retrieval_ready", "llm_qa_validated"],
            "provider_execution": "host_observed_import_required",
            "go": {
                "context": "darwin-arm64",
                "cgo": false,
                "build_tags": [],
                "capability": "G1 syntax and bounded G2 static binding",
                "runtime_type_resolution": false
            },
            // Boundaries a caller hits in practice. They used to be discoverable
            // only by reading the source, so they are disclosed here instead.
            "boundaries": {
                "authorized_root": "process_working_directory",
                "source_output_policy": "source_root_and_output_path_must_be_disjoint_and_both_under_the_authorized_root",
                "source_output_required_prefix": ".gtkg",
                "source_output_absolute_path_required": true,
                "artifact_root_policy": "fixed_under_workspace_.gtkg/qk",
                "bundle_output_root": ".gtkg/qk/bundles",
                "bundle_output_policy": "caller_named_directory_strictly_within_bundle_output_root",
                "context_budget_unit": "unicode_codepoint",
                "context_budget_measured_model_tokens": false,
                "context_loading": "manifest_then_single_bucket_lazy_read",
                "okf_conformance_in_knowledge_quality_path": "not_wired",
                "okf_google_certification": false,
                "dirty_worktree_check": "not_applicable_reads_exact_commit_blobs",
                "watch_or_daemon": "not_implemented",
                "config_repositories_consumer": "config.validate_only_not_wired_into_capture_or_build",
                "graph_node_and_edge_types": "not_modelled_confirmed_call_edges_only"
            }
        })),
        Op::SourceCapture => {
            let p: SourcePayload =
                serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
            let src = context
                .authorize_read(&p.source_root)
                .map_err(QkError::from_context)?;
            let out = context
                .authorize_write(&p.output_path)
                .map_err(QkError::from_context)?;
            let root = context.workspace_root().ok_or_else(|| {
                QkError::new(
                    V2ErrorCode::ScopeDenied,
                    "authorized-root",
                    "workspace absent",
                )
            })?;
            if !out.starts_with(root) || out.starts_with(&src) || src.starts_with(&out) {
                return Err(QkError::new(
                    V2ErrorCode::SourceOutputOverlap,
                    "source.capture.overlap",
                    "source and workspace archive must be disjoint; output must be in primary workspace",
                ));
            }
            // Preserve requested lexical paths so the source layer can reject symlinks.
            let policy =
                serde_json::from_value(serde_json::to_value(p.policy).map_err(|e| e.to_string())?)
                    .map_err(|e| e.to_string())?;
            let ledger = source::capture(&source::SourceCaptureRequest {
                repository_id: p.repository_id,
                source_root: p.source_root,
                source_commit: p.source_commit,
                expected_tree: p.expected_tree,
                output_path: p.output_path,
                policy,
            })
            .map_err(|e| QkError::new(e.code(), "source.capture", e.to_string()))?;
            let r = artifact::reference(context, root, &out.join(source::LEDGER_FILE))?;
            Ok(
                json!({"status":"captured","artifact_ref":r,"snapshot_id":ledger.snapshot_id,"source_tree":ledger.source_tree,"total_paths":ledger.leaves.len(),"target_execution":false}),
            )
        }
        Op::AnalysisPlan | Op::AnalysisBuild | Op::AnalysisVerify => {
            let p: ArtifactPayload =
                serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
            match op {
                Op::AnalysisPlan => analysis::plan(context, &p),
                Op::AnalysisBuild => analysis::build(context, &p),
                _ => analysis::verify(context, &p),
            }
        }
        Op::SummaryJobNext
        | Op::SummaryProposalSubmit
        | Op::SummaryVerificationNext
        | Op::SummaryVerificationSubmit
        | Op::SummaryAcceptV2 => {
            let p: ArtifactPayload =
                serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
            authoring::execute(context, &p, op).map_err(QkError::from)
        }
        Op::ContextPack if value.get("artifact_ref").is_some() => {
            let p: ArtifactPayload = serde_json::from_value(value.clone()).map_err(|e|e.to_string())?;
            context_pack::execute(context, &p).map_err(QkError::from)
        }
        Op::GraphSearch | Op::ContextPack => {
            let p = serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
            query::search(context, &p).map_err(QkError::from)
        }
        Op::DeliverableDerive => {
            let p: ArtifactPayload =
                serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
            authoring::create_views(context, &p).map_err(QkError::from)
        }
        Op::BuildFinalizeV2 => {
            let p: ArtifactPayload =
                serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
            let (r, _): (serde_json::Value, _) = artifact::read(context, &p.workspace_root, &p.artifact_ref)?;
            if r.get("schema").and_then(serde_json::Value::as_str) == Some("gtkg.qk.semantic-finalize/v1") {
                let request = serde_json::from_value(r).map_err(|e| e.to_string())?;
                let result = lifecycle::finalize_semantic(context, &p.workspace_root, &request)?;
                serde_json::to_value(result).map_err(|e| QkError::invalid(e.to_string()))
            } else {
                let request = serde_json::from_value(r).map_err(|e| e.to_string())?;
                let result = lifecycle::finalize(context, &p.workspace_root, &request)?;
                serde_json::to_value(result).map_err(|e| QkError::invalid(e.to_string()))
            }
        }
        Op::SnapshotRestore => {
            let p: ArtifactPayload =
                serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
            let result = lifecycle::import_any(
                context,
                &lifecycle::BundleLocator {
                    workspace_root: p.workspace_root,
                    manifest_ref: p.artifact_ref,
                },
            )?;
            serde_json::to_value(result).map_err(|e| QkError::invalid(e.to_string()))
        }
        Op::GraphExplain | Op::GraphTrace => {
            let p = serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
            graph_read::execute(context, &p, op).map_err(QkError::from)
        }
        Op::BundleVerify => {
            let p: ArtifactPayload =
                serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
            let result = lifecycle::verify_any(
                context,
                &lifecycle::BundleLocator {
                    workspace_root: p.workspace_root,
                    manifest_ref: p.artifact_ref,
                },
            )?;
            serde_json::to_value(result).map_err(|e| QkError::invalid(e.to_string()))
        }
        Op::BundleMigrateV1ToV2 => {
            let p: ArtifactPayload =
                serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
            let (r, _) = artifact::read(context, &p.workspace_root, &p.artifact_ref)?;
            let result = lifecycle::migrate(context, &p.workspace_root, &r)?;
            serde_json::to_value(result).map_err(|e| QkError::invalid(e.to_string()))
        }
        _ => Err("successor operation implementation pending".into()),
    }
}

pub mod semantic_projection;

pub mod source_context;

pub mod query_meter;

pub mod context_pack;
