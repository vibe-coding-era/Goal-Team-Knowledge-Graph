//! GTKG domain dispatcher and file-only runtime.

pub mod a2ui;
pub mod claim_aware_query_v2;
pub mod claim_v2;
pub mod config;
pub mod context_v2;
pub mod corpus_v2;
pub mod current;
pub mod deliverable;
pub mod document_relations;
mod durable;
mod exact_read;
pub mod external;
pub mod federation;
pub mod file_model;
pub mod graph_v3;
pub mod knowledge_overlay_v2;
pub mod lifecycle_v2;
pub mod no_db;
pub mod node;
pub mod okf;
pub mod okf_current_suite_v2;
pub mod okf_v2;
pub mod pipeline;
pub mod provider_v2;
mod query;
pub mod runtime_receipt_v2;
pub mod sandbox;
pub mod source;
pub mod source_v2;
pub mod structural_query_v3;
pub mod template;
pub mod v03;
pub mod v04;
pub mod wiki_a2ui_v2;

#[path = "v03/handlers/mod.rs"]
mod v03_handlers;

use std::collections::BTreeSet;
use std::fs;
use std::path::{Component, Path, PathBuf};

use gtkg_protocol::v2::{
    CallabilityV2, OperationRequestV2, OperationResponseV2, PROTOCOL_VERSION_V2, V2ErrorCode,
    V2ErrorEnvelope, V2OperationId, v2_operation_definition, validate_v2_operation_payload,
};
use gtkg_protocol::{
    CORE_VERSION, ErrorCode, ErrorEnvelope, FileReceiptRef, OperationAvailability, OperationId,
    OperationRequest, OperationResponse, PROTOCOL_VERSION, PUBLIC_OPERATIONS, SideEffectClass,
    operation_definition, validate_operation_payload, validate_path_identifier, validate_sha256,
};
use serde_json::{Value, json};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportKind {
    Cli,
    McpStdio,
    NodeStdio,
    Test,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EffectPolicy {
    ReadOnly,
    WorkspaceWrite,
}

impl EffectPolicy {
    pub const fn allows(self, effect: SideEffectClass) -> bool {
        match self {
            Self::ReadOnly => matches!(effect, SideEffectClass::Read),
            Self::WorkspaceWrite => !matches!(
                effect,
                SideEffectClass::GitExternalWrite | SideEffectClass::CurrentWrite
            ),
        }
    }
}

#[derive(Debug, Error)]
pub enum ContextError {
    #[error("at least one authorized root is required")]
    MissingRoot,
    #[error("authorized root is unsafe: {0}")]
    UnsafeRoot(PathBuf),
    #[error("authorized root cannot be inspected at {path}: {source}")]
    RootIo {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("path is outside the authorized roots: {0}")]
    PathEscape(PathBuf),
    #[error("invalid receipt reference: {0}")]
    InvalidReceipt(String),
}

#[derive(Debug, Clone)]
pub struct CallContext {
    pub transport: TransportKind,
    pub effect_policy: EffectPolicy,
    authorized_roots: Vec<PathBuf>,
    authorized_lexical_roots: Vec<PathBuf>,
}

impl CallContext {
    pub fn restricted(
        transport: TransportKind,
        roots: Vec<PathBuf>,
        effect_policy: EffectPolicy,
    ) -> Result<Self, ContextError> {
        if roots.is_empty() {
            return Err(ContextError::MissingRoot);
        }
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .and_then(|path| fs::canonicalize(path).ok());
        let mut seen = BTreeSet::new();
        let mut seen_lexical = BTreeSet::new();
        let mut authorized = Vec::new();
        let mut authorized_lexical = Vec::new();
        for root in roots {
            reject_lexical_escape(&root)?;
            if !root.is_absolute() {
                return Err(ContextError::UnsafeRoot(root));
            }
            let metadata = fs::symlink_metadata(&root).map_err(|source| ContextError::RootIo {
                path: root.clone(),
                source,
            })?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(ContextError::UnsafeRoot(root));
            }
            let canonical = fs::canonicalize(&root).map_err(|source| ContextError::RootIo {
                path: root.clone(),
                source,
            })?;
            if canonical == Path::new("/") || home.as_ref() == Some(&canonical) {
                return Err(ContextError::UnsafeRoot(canonical));
            }
            if seen_lexical.insert(root.clone()) {
                authorized_lexical.push(root);
            }
            if seen.insert(canonical.clone()) {
                authorized.push(canonical);
            }
        }
        Ok(Self {
            transport,
            effect_policy,
            authorized_roots: authorized,
            authorized_lexical_roots: authorized_lexical,
        })
    }

    pub fn test() -> Self {
        let mut roots = Vec::new();
        if let Ok(current) = std::env::current_dir() {
            roots.push(current);
        }
        roots.push(std::env::temp_dir());
        Self::restricted(TransportKind::Test, roots, EffectPolicy::WorkspaceWrite).unwrap_or_else(
            |_| Self {
                transport: TransportKind::Test,
                effect_policy: EffectPolicy::WorkspaceWrite,
                authorized_roots: Vec::new(),
                authorized_lexical_roots: Vec::new(),
            },
        )
    }

    pub fn authorized_roots(&self) -> &[PathBuf] {
        &self.authorized_roots
    }

    pub(crate) fn authorized_lexical_roots(&self) -> &[PathBuf] {
        &self.authorized_lexical_roots
    }

    pub fn workspace_root(&self) -> Option<&Path> {
        self.authorized_roots.first().map(PathBuf::as_path)
    }

    pub fn authorize_read(&self, path: &Path) -> Result<PathBuf, ContextError> {
        self.authorize(path, true)
    }

    pub fn authorize_write(&self, path: &Path) -> Result<PathBuf, ContextError> {
        self.authorize(path, false)
    }

    pub fn resolve_receipt(&self, reference: &FileReceiptRef) -> Result<PathBuf, ContextError> {
        reference
            .validate()
            .map_err(|error| ContextError::InvalidReceipt(error.to_string()))?;
        let workspace = self.workspace_root().ok_or(ContextError::MissingRoot)?;
        self.authorize_read(&workspace.join(&reference.path))
    }

    pub fn resolve_workspace_receipt(
        &self,
        workspace_root: &Path,
        reference: &FileReceiptRef,
    ) -> Result<PathBuf, ContextError> {
        reference
            .validate()
            .map_err(|error| ContextError::InvalidReceipt(error.to_string()))?;
        let workspace = self.authorize_read(workspace_root)?;
        let workspace_candidate = workspace.join(&reference.path);
        let context_candidate = self
            .workspace_root()
            .ok_or(ContextError::MissingRoot)?
            .join(&reference.path);
        let workspace_exists = fs::symlink_metadata(&workspace_candidate).is_ok();
        let context_exists = fs::symlink_metadata(&context_candidate).is_ok();

        if workspace_exists {
            let resolved = self.authorize_read(&workspace_candidate)?;
            if context_exists {
                let context_resolved = self.authorize_read(&context_candidate)?;
                if context_resolved != resolved {
                    return Err(ContextError::InvalidReceipt(format!(
                        "ambiguous receipt path resolves in both workspace and context root: {}",
                        reference.path
                    )));
                }
            }
            return Ok(resolved);
        }

        if context_exists {
            let resolved = self.authorize_read(&context_candidate)?;
            return Ok(resolved);
        }

        self.authorize_read(&workspace_candidate)
    }

    fn authorize(&self, path: &Path, must_exist: bool) -> Result<PathBuf, ContextError> {
        reject_lexical_escape(path)?;
        let candidate = if path.is_absolute() {
            path.to_path_buf()
        } else {
            self.workspace_root()
                .ok_or(ContextError::MissingRoot)?
                .join(path)
        };
        let canonical = if must_exist || candidate.exists() {
            fs::canonicalize(&candidate).map_err(|source| ContextError::RootIo {
                path: candidate.clone(),
                source,
            })?
        } else {
            canonicalize_for_write(&candidate)?
        };
        if self
            .authorized_roots
            .iter()
            .any(|root| canonical == *root || canonical.starts_with(root))
        {
            #[cfg(unix)]
            if let Ok(metadata) = fs::metadata(&canonical)
                && metadata.is_file()
            {
                use std::os::unix::fs::MetadataExt;
                if metadata.nlink() > 1 {
                    return Err(ContextError::PathEscape(candidate));
                }
            }
            Ok(canonical)
        } else {
            Err(ContextError::PathEscape(candidate))
        }
    }
}

fn reject_lexical_escape(path: &Path) -> Result<(), ContextError> {
    if path.components().any(|component| {
        matches!(
            component,
            Component::ParentDir | Component::CurDir | Component::Prefix(_)
        )
    }) {
        return Err(ContextError::PathEscape(path.to_path_buf()));
    }
    Ok(())
}

fn canonicalize_for_write(path: &Path) -> Result<PathBuf, ContextError> {
    let mut ancestor = path;
    let mut suffix = Vec::new();
    loop {
        match fs::symlink_metadata(ancestor) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    return Err(ContextError::PathEscape(path.to_path_buf()));
                }
                break;
            }
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(ContextError::RootIo {
                    path: ancestor.to_path_buf(),
                    source,
                });
            }
        }
        let name = ancestor
            .file_name()
            .ok_or_else(|| ContextError::PathEscape(path.to_path_buf()))?;
        suffix.push(name.to_os_string());
        ancestor = ancestor
            .parent()
            .ok_or_else(|| ContextError::PathEscape(path.to_path_buf()))?;
    }
    let mut canonical = fs::canonicalize(ancestor).map_err(|source| ContextError::RootIo {
        path: ancestor.to_path_buf(),
        source,
    })?;
    for component in suffix.into_iter().rev() {
        canonical.push(component);
    }
    Ok(canonical)
}

#[derive(Debug, Default)]
pub struct Dispatcher;

impl Dispatcher {
    /// Execute the V0.2 transport boundary.  V1 remains routed exclusively
    /// through [`Self::execute`]; each callable v2 operation is bound only by
    /// its owning TaskExactSet implementation.
    #[allow(clippy::result_large_err)]
    pub fn execute_v2(
        &self,
        context: &CallContext,
        request: OperationRequestV2,
    ) -> Result<OperationResponseV2, V2ErrorEnvelope> {
        let operation_id = request.resolve_operation()?;
        let definition = v2_operation_definition(operation_id).ok_or_else(|| {
            V2ErrorEnvelope::new(
                &request,
                V2ErrorCode::OperationNotImplemented,
                "dispatch",
                "parsed v2 operation is missing from the registry",
                "rebuild against a coherent v2 protocol registry",
            )
        })?;
        if matches!(
            operation_id,
            V2OperationId::SystemDescribe
                | V2OperationId::ConfigValidate
                | V2OperationId::CapabilityDescribe
                | V2OperationId::SourceCapture
                | V2OperationId::AnalysisPlan
                | V2OperationId::AnalysisBuild
                | V2OperationId::AnalysisVerify
                | V2OperationId::ContextPack
                | V2OperationId::SummaryJobNext
                | V2OperationId::SummaryProposalSubmit
                | V2OperationId::SummaryVerificationNext
                | V2OperationId::SummaryVerificationSubmit
                | V2OperationId::SummaryAcceptV2
                | V2OperationId::BuildFinalizeV2
                | V2OperationId::RunGet
                | V2OperationId::RunCancel
                | V2OperationId::BundleVerify
                | V2OperationId::BundleCompare
                | V2OperationId::BundleMigrateV1ToV2
                | V2OperationId::SnapshotCreate
                | V2OperationId::SnapshotVerify
                | V2OperationId::SnapshotRestore
                | V2OperationId::GitPublish
                | V2OperationId::CurrentGet
                | V2OperationId::CurrentActivate
                | V2OperationId::NodeDescribe
                | V2OperationId::FederationValidate
                | V2OperationId::TemplateList
                | V2OperationId::TemplateResolve
                | V2OperationId::TemplatePrefetch
                | V2OperationId::TemplateGet
                | V2OperationId::TemplateValidate
                | V2OperationId::TemplateDerive
                | V2OperationId::TemplatePublish
                | V2OperationId::DeliverableDerive
                | V2OperationId::DeliverablePublish
                | V2OperationId::GraphNeighbors
                | V2OperationId::GraphPath
                | V2OperationId::GraphImpact
                | V2OperationId::GraphExplain
                | V2OperationId::GraphTrace
                | V2OperationId::GraphSearch
                | V2OperationId::A2uiResolve
                | V2OperationId::A2uiGenerate
                | V2OperationId::A2uiGet
                | V2OperationId::A2uiValidate
        ) {
            if let Err(message) = validate_v2_operation_payload(operation_id, &request.payload) {
                return Err(V2ErrorEnvelope::new(
                    &request,
                    V2ErrorCode::InvalidRequest,
                    "payload-schema",
                    message,
                    "use the exact closed payload schema disclosed for this v2 operation",
                ));
            }
            if !context.effect_policy.allows(definition.side_effect) {
                return Err(V2ErrorEnvelope::new(
                    &request,
                    V2ErrorCode::SideEffectDenied,
                    "effect-policy",
                    format!(
                        "effect {:?} is denied by the current call context",
                        definition.side_effect
                    ),
                    "use a bounded context that authorizes the declared workspace effect",
                ));
            }
            if request.payload.get("payload_revision").is_some() {
                return v04::execute(context, request, operation_id);
            }
            return v03_handlers::execute(context, request, operation_id);
        }
        if operation_id == V2OperationId::GraphSearch {
            return execute_v2_claim_aware_graph_search(context, request);
        }
        if matches!(
            operation_id,
            V2OperationId::GraphNeighbors
                | V2OperationId::GraphPath
                | V2OperationId::GraphImpact
                | V2OperationId::GraphExplain
                | V2OperationId::GraphTrace
        ) {
            return execute_v2_structural_graph_query(context, request, operation_id);
        }
        let (code, stage, message, recovery_hint) = match definition.callability {
            CallabilityV2::NotImplemented => (
                V2ErrorCode::OperationNotImplemented,
                "dispatch",
                format!("operation {} is not implemented yet", operation_id.as_str()),
                "do not treat registry presence as a callable handler; wait for its owning task",
            ),
            CallabilityV2::DeniedByPolicy => (
                V2ErrorCode::SideEffectDenied,
                "effect-policy",
                format!(
                    "operation {} is denied by the current policy",
                    operation_id.as_str()
                ),
                "use a bounded context that authorizes the required side effect",
            ),
            CallabilityV2::MissingHostCapability => (
                V2ErrorCode::MissingHostCapability,
                "host capability",
                format!(
                    "operation {} requires an unavailable host capability",
                    operation_id.as_str()
                ),
                "install or authorize the declared host capability, then rediscover callability",
            ),
            CallabilityV2::Callable => (
                V2ErrorCode::OperationNotImplemented,
                "dispatch",
                format!(
                    "operation {} has no bound v2 handler",
                    operation_id.as_str()
                ),
                "this is a registry invariant violation; do not retry until the handler is bound",
            ),
        };
        Err(V2ErrorEnvelope::new(
            &request,
            code,
            stage,
            message,
            recovery_hint,
        ))
    }

    // The transport-neutral public contract intentionally returns the stable envelope by value.
    #[allow(clippy::result_large_err)]
    pub fn execute(
        &self,
        context: &CallContext,
        request: OperationRequest,
    ) -> Result<OperationResponse, ErrorEnvelope> {
        if request.protocol_version != PROTOCOL_VERSION {
            return Err(ErrorEnvelope::new(
                &request,
                ErrorCode::ProtocolVersionMismatch,
                "protocol",
                format!(
                    "unsupported protocol version {}; expected {PROTOCOL_VERSION}",
                    request.protocol_version
                ),
                "retry with the exact protocol version reported by system.describe",
            ));
        }

        for digest in request.locks.values() {
            if validate_sha256(digest).is_err() {
                return Err(error_without_request_locks(
                    &request,
                    ErrorCode::LockMismatch,
                    "request-lock-validation",
                    "every request lock must be a lowercase full sha256 digest",
                    "replace caller text with exact sha256:<64-lowercase-hex> lock digests",
                ));
            }
        }
        if let Some(run_id) = request.run_id.as_deref()
            && validate_path_identifier("run_id", run_id).is_err()
        {
            return Err(ErrorEnvelope::new(
                &request,
                ErrorCode::InvalidRequest,
                "request-identity",
                "run_id must be a safe generated identifier and cannot be '.' or '..'",
                "use the exact run_id returned by build.plan",
            ));
        }
        if let Some(packet_id) = request
            .payload
            .get("packet_id")
            .and_then(|value| value.as_str())
            && validate_path_identifier("packet_id", packet_id).is_err()
        {
            return Err(ErrorEnvelope::new(
                &request,
                ErrorCode::InvalidRequest,
                "request-identity",
                "packet_id must be the exact safe identifier returned by summary.next",
                "use the unchanged packet_id returned by the current run",
            ));
        }
        let definition = operation_definition(request.operation_id).ok_or_else(|| {
            ErrorEnvelope::new(
                &request,
                ErrorCode::OperationNotImplemented,
                "dispatch",
                "operation is missing from the public registry",
                "use system.describe to inspect the current operation surface",
            )
        })?;
        let payload_validation = validate_operation_payload(request.operation_id, &request.payload)
            .and_then(|()| {
                validate_transport_neutral_payload(request.operation_id, &request.payload)
            });
        if let Err(message) = payload_validation {
            return Err(ErrorEnvelope::new(
                &request,
                ErrorCode::InvalidRequest,
                "payload-schema",
                message,
                "use the operation-specific closed schema disclosed by MCP tools/list",
            ));
        }
        if definition.availability == OperationAvailability::NotImplemented {
            return Err(ErrorEnvelope::new(
                &request,
                ErrorCode::OperationNotImplemented,
                "dispatch",
                format!(
                    "operation {} is not implemented yet",
                    request.operation_id.as_str()
                ),
                "use system.describe to inspect truthful operation availability",
            ));
        }
        if !context.effect_policy.allows(definition.side_effect) {
            return Err(ErrorEnvelope::new(
                &request,
                ErrorCode::SideEffectDenied,
                "effect-policy",
                format!(
                    "effect {:?} is denied by the current call context",
                    definition.side_effect
                ),
                "start a context with the required bounded workspace effect policy",
            ));
        }
        authorize_request_paths(context, &request)?;

        match request.operation_id {
            OperationId::SystemDescribe => Ok(OperationResponse::completed(
                &request,
                json!({
                    "product": "gtkg",
                    "core_version": CORE_VERSION,
                    "protocol_version": PROTOCOL_VERSION,
                    "public_operation_count": PUBLIC_OPERATIONS.len(),
                    "implemented_operation_count": PUBLIC_OPERATIONS.iter().filter(|operation| {
                        operation.availability == OperationAvailability::Implemented
                    }).count(),
                    "operations": PUBLIC_OPERATIONS,
                    "database_backend": null,
                    "storage_model": "okf-and-ordinary-files"
                }),
            )),
            OperationId::ConfigValidate => config::validate(context, &request).map_err(|failure| {
                ErrorEnvelope::new(
                    &request,
                    failure.code,
                    failure.stage,
                    failure.message,
                    failure.recovery_hint,
                )
            }),
            OperationId::CurrentGet => current::get(context, &request).map_err(|failure| {
                ErrorEnvelope::new(
                    &request,
                    failure.code,
                    failure.stage,
                    failure.message,
                    failure.recovery_hint,
                )
            }),
            OperationId::GitPublish
            | OperationId::CurrentActivate
            | OperationId::TemplatePublish
            | OperationId::DeliverablePublish => external::execute(&request).map_err(|failure| {
                ErrorEnvelope::new(
                    &request,
                    failure.code,
                    failure.stage,
                    failure.message,
                    failure.recovery_hint,
                )
            }),
            OperationId::SourceInspect => source::inspect(context, &request).map_err(|failure| {
                ErrorEnvelope::new(
                    &request,
                    failure.code,
                    failure.stage,
                    failure.message,
                    failure.recovery_hint,
                )
            }),
            OperationId::NodeDescribe => node::describe(context, &request).map_err(|failure| {
                ErrorEnvelope::new(
                    &request,
                    failure.code,
                    failure.stage,
                    failure.message,
                    failure.recovery_hint,
                )
            }),
            OperationId::FederationValidate => node::validate_federation(context, &request)
                .map_err(|failure| {
                    ErrorEnvelope::new(
                        &request,
                        failure.code,
                        failure.stage,
                        failure.message,
                        failure.recovery_hint,
                    )
                }),
            OperationId::TemplateResolve => {
                template::resolve(context, &request).map_err(|failure| {
                    ErrorEnvelope::new(
                        &request,
                        failure.code,
                        failure.stage,
                        failure.message,
                        failure.recovery_hint,
                    )
                })
            }
            OperationId::TemplateList => template::list(context, &request).map_err(|failure| {
                ErrorEnvelope::new(
                    &request,
                    failure.code,
                    failure.stage,
                    failure.message,
                    failure.recovery_hint,
                )
            }),
            OperationId::TemplatePrefetch => {
                template::prefetch(context, &request).map_err(|failure| {
                    ErrorEnvelope::new(
                        &request,
                        failure.code,
                        failure.stage,
                        failure.message,
                        failure.recovery_hint,
                    )
                })
            }
            OperationId::TemplateGet => template::get(context, &request).map_err(|failure| {
                ErrorEnvelope::new(
                    &request,
                    failure.code,
                    failure.stage,
                    failure.message,
                    failure.recovery_hint,
                )
            }),
            OperationId::TemplateDerive => template::derive(context, &request).map_err(|failure| {
                ErrorEnvelope::new(
                    &request,
                    failure.code,
                    failure.stage,
                    failure.message,
                    failure.recovery_hint,
                )
            }),
            OperationId::DeliverableDerive => {
                deliverable::derive(context, &request).map_err(|failure| {
                    ErrorEnvelope::new(
                        &request,
                        failure.code,
                        failure.stage,
                        failure.message,
                        failure.recovery_hint,
                    )
                })
            }
            OperationId::TemplateValidate => {
                template::validate(context, &request).map_err(|failure| {
                    ErrorEnvelope::new(
                        &request,
                        failure.code,
                        failure.stage,
                        failure.message,
                        failure.recovery_hint,
                    )
                })
            }
            OperationId::A2uiResolve
            | OperationId::A2uiGenerate
            | OperationId::A2uiGet
            | OperationId::A2uiValidate => a2ui::execute(context, &request).map_err(|failure| {
                ErrorEnvelope::new(
                    &request,
                    failure.code,
                    failure.stage,
                    failure.message,
                    failure.recovery_hint,
                )
            }),
            OperationId::BuildPlan
            | OperationId::BuildPrepare
            | OperationId::SummaryNext
            | OperationId::SummaryAccept
            | OperationId::BuildFinalize
            | OperationId::RunGet
            | OperationId::RunCancel
            | OperationId::BundleVerify
            | OperationId::BundleQuery
            | OperationId::BundleCompare
            | OperationId::SnapshotCreate
            | OperationId::SnapshotVerify
            | OperationId::SnapshotRestore => {
                pipeline::execute(context, &request).map_err(|failure| {
                    ErrorEnvelope::new(
                        &request,
                        failure.code,
                        failure.stage,
                        failure.message,
                        failure.recovery_hint,
                    )
                })
            }
        }
    }
}

#[allow(clippy::result_large_err)]
fn execute_v2_claim_aware_graph_search(
    context: &CallContext,
    request: OperationRequestV2,
) -> Result<OperationResponseV2, V2ErrorEnvelope> {
    let object = request.payload.as_object().ok_or_else(|| {
        V2ErrorEnvelope::new(
            &request,
            V2ErrorCode::InvalidRequest,
            "claim-aware-query",
            "graph.search payload must be a JSON object",
            "provide graph_artifact_path, overlay_artifact_path, and a bounded query",
        )
    })?;
    let graph_root = authorize_v2_query_artifact(context, &request, object, "graph_artifact_path")?;
    let overlay_root =
        authorize_v2_query_artifact(context, &request, object, "overlay_artifact_path")?;
    let mut query_payload = object.clone();
    query_payload.remove("graph_artifact_path");
    query_payload.remove("overlay_artifact_path");
    let result = claim_aware_query_v2::execute_claim_aware_hybrid_query_v2(
        &graph_root,
        &overlay_root,
        &Value::Object(query_payload),
    )
    .map_err(|error| {
        let code = match error {
            claim_aware_query_v2::ClaimAwareQueryErrorV2::InvalidRequest(_) => {
                V2ErrorCode::InvalidRequest
            }
            claim_aware_query_v2::ClaimAwareQueryErrorV2::GraphReadback(_)
            | claim_aware_query_v2::ClaimAwareQueryErrorV2::OverlayReadback(_)
            | claim_aware_query_v2::ClaimAwareQueryErrorV2::BindingMismatch(_) => {
                V2ErrorCode::ClaimAwareQueryReadbackFailed
            }
        };
        V2ErrorEnvelope::new(
            &request,
            code,
            "claim-aware-query",
            format!("{}: {error}", error.code()),
            "use matching verified T11A/T11B artifacts and the closed graph.search request schema",
        )
    })?;
    Ok(OperationResponseV2 {
        protocol_version: PROTOCOL_VERSION_V2.to_owned(),
        operation_id: V2OperationId::GraphSearch,
        request_id: request.request_id,
        result,
    })
}

#[allow(clippy::result_large_err)]
fn authorize_v2_query_artifact(
    context: &CallContext,
    request: &OperationRequestV2,
    object: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<PathBuf, V2ErrorEnvelope> {
    let value = object
        .get(field)
        .and_then(Value::as_str)
        .filter(|path| !path.trim().is_empty())
        .ok_or_else(|| {
            V2ErrorEnvelope::new(
                request,
                V2ErrorCode::InvalidRequest,
                "claim-aware-query",
                format!("{field} must be a non-empty workspace-relative string"),
                "store verified graph and overlay artifact directories below the authorized workspace root",
            )
        })?;
    let relative = Path::new(value);
    if relative.is_absolute()
        || relative.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(V2ErrorEnvelope::new(
            request,
            V2ErrorCode::InvalidRequest,
            "claim-aware-query",
            format!("{field} must remain below the authorized workspace root"),
            "use a relative artifact directory without parent traversal",
        ));
    }
    let workspace = context.workspace_root().ok_or_else(|| {
        V2ErrorEnvelope::new(
            request,
            V2ErrorCode::InvalidRequest,
            "claim-aware-query",
            "no authorized workspace root is available for artifact readback",
            "invoke from a bounded workspace context",
        )
    })?;
    let candidate = workspace.join(relative);
    let lexical_metadata = fs::symlink_metadata(&candidate).map_err(|error| {
        V2ErrorEnvelope::new(
            request,
            V2ErrorCode::InvalidRequest,
            "claim-aware-query",
            format!("{field} cannot be inspected before canonicalization: {error}"),
            "use a real non-symlink artifact directory below the authorized workspace root",
        )
    })?;
    if lexical_metadata.file_type().is_symlink() || !lexical_metadata.is_dir() {
        return Err(V2ErrorEnvelope::new(
            request,
            V2ErrorCode::InvalidRequest,
            "claim-aware-query",
            format!("{field} must name a lexical non-symlink directory"),
            "replace symlinked or non-directory artifact roots with a direct workspace path",
        ));
    }
    context.authorize_read(&candidate).map_err(|error| {
        V2ErrorEnvelope::new(
            request,
            V2ErrorCode::InvalidRequest,
            "claim-aware-query",
            format!("{field} is not authorized: {error}"),
            "place the artifact directory under the current authorized workspace root",
        )
    })
}

#[allow(clippy::result_large_err)]
fn execute_v2_structural_graph_query(
    context: &CallContext,
    request: OperationRequestV2,
    operation_id: V2OperationId,
) -> Result<OperationResponseV2, V2ErrorEnvelope> {
    let object = request.payload.as_object().ok_or_else(|| {
        V2ErrorEnvelope::new(
            &request,
            V2ErrorCode::InvalidRequest,
            "structural-query",
            "graph query payload must be a JSON object",
            "provide graph_artifact_path plus the exact operation-specific structural query fields",
        )
    })?;
    let graph_path = object
        .get("graph_artifact_path")
        .and_then(Value::as_str)
        .filter(|path| !path.trim().is_empty())
        .ok_or_else(|| {
            V2ErrorEnvelope::new(
                &request,
                V2ErrorCode::InvalidRequest,
                "structural-query",
                "graph_artifact_path must be a non-empty workspace-relative string",
                "store a verified T11A graph directory under an authorized workspace root",
            )
        })?;
    let relative = Path::new(graph_path);
    if relative.is_absolute()
        || relative.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(V2ErrorEnvelope::new(
            &request,
            V2ErrorCode::InvalidRequest,
            "structural-query",
            "graph_artifact_path must remain below the authorized workspace root",
            "use a relative graph artifact directory without parent traversal",
        ));
    }
    let workspace = context.workspace_root().ok_or_else(|| {
        V2ErrorEnvelope::new(
            &request,
            V2ErrorCode::InvalidRequest,
            "structural-query",
            "no authorized workspace root is available for Graph readback",
            "invoke from a bounded workspace context",
        )
    })?;
    let graph_root = context
        .authorize_read(&workspace.join(relative))
        .map_err(|error| {
            V2ErrorEnvelope::new(
                &request,
                V2ErrorCode::InvalidRequest,
                "structural-query",
                format!("graph artifact path is not authorized: {error}"),
                "place the graph directory under the current authorized workspace root",
            )
        })?;
    let mut query_payload = object.clone();
    query_payload.remove("graph_artifact_path");
    let operation = match operation_id {
        V2OperationId::GraphNeighbors => structural_query_v3::StructuralQueryOperationV3::Neighbors,
        V2OperationId::GraphPath => structural_query_v3::StructuralQueryOperationV3::Path,
        V2OperationId::GraphImpact => structural_query_v3::StructuralQueryOperationV3::Impact,
        V2OperationId::GraphExplain => structural_query_v3::StructuralQueryOperationV3::Explain,
        V2OperationId::GraphTrace => structural_query_v3::StructuralQueryOperationV3::Trace,
        _ => unreachable!("call site accepts only T12A structural operations"),
    };
    let result = structural_query_v3::execute_structural_query_v3(
        &graph_root,
        operation,
        &Value::Object(query_payload),
    )
    .map_err(|error| {
        let code = if matches!(
            error,
            structural_query_v3::StructuralQueryErrorV3::Readback(_)
        ) {
            V2ErrorCode::StructuralQueryReadbackFailed
        } else {
            V2ErrorCode::InvalidRequest
        };
        V2ErrorEnvelope::new(
            &request,
            code,
            "structural-query",
            format!("{}: {error}", error.code()),
            "use a verified T11A structural-only graph and a bounded operation payload",
        )
    })?;
    Ok(OperationResponseV2 {
        protocol_version: PROTOCOL_VERSION_V2.to_owned(),
        operation_id,
        request_id: request.request_id,
        result,
    })
}

fn validate_transport_neutral_payload(
    operation: OperationId,
    payload: &serde_json::Value,
) -> Result<(), String> {
    if operation != OperationId::SourceInspect {
        return Ok(());
    }
    let object = payload
        .as_object()
        .ok_or_else(|| "payload must be a JSON object".to_owned())?;
    let legacy_keys = ["workspace_root", "repositories"];
    let config_keys = ["config_path", "expected_config_sha256"];
    let legacy_present = legacy_keys
        .iter()
        .filter(|key| object.contains_key(**key))
        .count();
    let config_present = config_keys
        .iter()
        .filter(|key| object.contains_key(**key))
        .count();
    let legacy_complete = legacy_present == legacy_keys.len()
        && legacy_keys
            .iter()
            .all(|key| object.get(*key).is_some_and(|value| !value.is_null()));
    let config_complete = config_present == config_keys.len()
        && config_keys
            .iter()
            .all(|key| object.get(*key).is_some_and(|value| !value.is_null()));
    if (legacy_complete && config_present == 0) || (config_complete && legacy_present == 0) {
        return Ok(());
    }
    Err(
        "source.inspect requires exactly one non-null input mode by key presence: workspace_root + repositories, or config_path + expected_config_sha256"
            .to_owned(),
    )
}

fn error_without_request_locks(
    request: &OperationRequest,
    code: ErrorCode,
    stage: &'static str,
    message: &'static str,
    recovery_hint: &'static str,
) -> ErrorEnvelope {
    let mut envelope = ErrorEnvelope::new(request, code, stage, message, recovery_hint);
    envelope.error.lock_digests.clear();
    envelope
}

#[allow(clippy::result_large_err)]
fn authorize_request_paths(
    context: &CallContext,
    request: &OperationRequest,
) -> Result<(), ErrorEnvelope> {
    authorize_value(context, None, &request.payload).map_err(|error| {
        ErrorEnvelope::new(
            request,
            ErrorCode::PathEscape,
            "path-authorization",
            error.to_string(),
            "use only paths contained by the canonical roots fixed in CallContext",
        )
    })
}

fn authorize_value(
    context: &CallContext,
    key: Option<&str>,
    value: &serde_json::Value,
) -> Result<(), ContextError> {
    let access = key.and_then(path_access);
    if let Some(write) = access {
        match value {
            serde_json::Value::String(path) => {
                if write {
                    context.authorize_write(Path::new(path))?;
                } else {
                    context.authorize_read(Path::new(path))?;
                }
            }
            serde_json::Value::Array(values) => {
                for value in values {
                    authorize_value(context, key, value)?;
                }
            }
            serde_json::Value::Null => {}
            _ => {}
        }
    }
    match value {
        serde_json::Value::Object(values) => {
            let is_file_receipt_ref =
                values.len() == 2 && values.contains_key("path") && values.contains_key("sha256");
            for (child_key, child_value) in values {
                if is_file_receipt_ref && child_key == "path" {
                    // Receipt paths are workspace-relative and are authorized only after the
                    // operation-specific workspace_root has been canonicalized.
                    continue;
                }
                authorize_value(context, Some(child_key), child_value)?;
            }
        }
        serde_json::Value::Array(values) if access.is_none() => {
            for child in values {
                authorize_value(context, None, child)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn path_access(key: &str) -> Option<bool> {
    match key {
        "workspace_root" | "scratch_root" | "current_root" | "repository_root" => Some(true),
        "path" | "source_root" | "catalog_root" | "frontend_root" | "canonical_root"
        | "projection_path" | "bundle_path" | "baseline_bundle" | "left_bundle"
        | "right_bundle" | "snapshot_path" | "input_roots" | "config_path" | "current_path"
        | "artifact_path" | "version_path" | "parent_path" => Some(false),
        _ => None,
    }
}
