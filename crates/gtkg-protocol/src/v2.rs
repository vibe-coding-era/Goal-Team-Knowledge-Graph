//! V0.2 profile-scoped coverage and hard-gate contracts.
//!
//! This module is deliberately internal to the V0.2 implementation track: it
//! does not alter the frozen `gtkg.protocol/v1` operation registry.  T08 owns
//! any future v2 transport projection.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

use crate::{
    ErrorCode, FileReceiptRef, OperationId, SideEffectClass, operation_request_schema,
    validate_operation_payload, validate_sha256,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// The v2 transport is a separate public surface.  It deliberately does not
/// reuse the frozen v1 request type, registry, discovery schema, or errors.
pub const PROTOCOL_VERSION_V2: &str = "gtkg.protocol/v2";

/// These identifiers remain valid only when a caller explicitly selects v1.
/// They are intentionally not parsed into [`V2OperationId`].
pub const V1_ONLY_OPERATION_IDS_V2: [&str; 7] = [
    "source.inspect",
    "build.plan",
    "build.prepare",
    "build.finalize",
    "summary.next",
    "summary.accept",
    "bundle.query",
];

/// Whether an operation has an implementation in this binary. This is not a
/// statement about whether the current call is permitted or executable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OperationAvailabilityV2 {
    Implemented,
    NotImplemented,
}

/// The current invocation result exposed by v2 discovery.  This is a separate
/// axis from registry presence and implementation availability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CallabilityV2 {
    Callable,
    DeniedByPolicy,
    MissingHostCapability,
    NotImplemented,
}

macro_rules! define_v2_operations {
    ($( $variant:ident => $id:literal, $effect:expr; )+ ) => {
        /// The public, closed V0.2 operation identifier set.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema)]
        pub enum V2OperationId {
            $( #[serde(rename = $id)] $variant, )+
        }

        impl V2OperationId {
            pub const fn as_str(self) -> &'static str {
                match self {
                    $( Self::$variant => $id, )+
                }
            }

            pub fn parse(value: &str) -> Option<Self> {
                match value {
                    $( $id => Some(Self::$variant), )+
                    _ => None,
                }
            }

            /// The v2 MCP namespace cannot collide with the frozen v1 tools.
            pub fn mcp_tool_name(self) -> String {
                format!("gtkg_v2_{}", self.as_str().replace('.', "_"))
            }

            pub fn from_mcp_tool_name(value: &str) -> Option<Self> {
                V2_PUBLIC_OPERATIONS
                    .iter()
                    .find(|definition| definition.id.mcp_tool_name() == value)
                    .map(|definition| definition.id)
            }
        }

        /// One truthful v2 operation disclosure. No entry may be inferred as
        /// callable merely because it is present in this registry.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
        pub struct V2OperationDefinition {
            pub id: V2OperationId,
            pub side_effect: SideEffectClass,
            pub availability: OperationAvailabilityV2,
            pub callability: CallabilityV2,
        }

        /// T08 is transport-only: none of the v2 operation handlers are
        /// claimed until their own task supplies executable semantics.
        pub const V2_PUBLIC_OPERATIONS: &[V2OperationDefinition] = &[
            $( V2OperationDefinition {
                id: V2OperationId::$variant,
                side_effect: $effect,
                availability: v2_operation_availability(V2OperationId::$variant),
                callability: v2_operation_callability(V2OperationId::$variant),
            }, )+
        ];
    };
}

/// P04 closes the 46-operation implementation denominator. Availability does
/// not imply permission: external publication and Current activation remain
/// separately denied by callability and the runtime effect policy.
pub const fn v2_operation_availability(_id: V2OperationId) -> OperationAvailabilityV2 {
    OperationAvailabilityV2::Implemented
}

pub const fn v2_operation_callability(id: V2OperationId) -> CallabilityV2 {
    match id {
        V2OperationId::GitPublish
        | V2OperationId::CurrentActivate
        | V2OperationId::TemplatePublish
        | V2OperationId::DeliverablePublish => CallabilityV2::DeniedByPolicy,
        _ => CallabilityV2::Callable,
    }
}

define_v2_operations! {
    SystemDescribe => "system.describe", SideEffectClass::Read;
    ConfigValidate => "config.validate", SideEffectClass::Read;
    CapabilityDescribe => "capability.describe", SideEffectClass::Read;
    SourceCapture => "source.capture", SideEffectClass::RunLocalWrite;
    AnalysisPlan => "analysis.plan", SideEffectClass::RunLocalWrite;
    AnalysisBuild => "analysis.build", SideEffectClass::CandidateWrite;
    AnalysisVerify => "analysis.verify", SideEffectClass::ReceiptWrite;
    BuildFinalizeV2 => "build.finalize.v2", SideEffectClass::CandidateWrite;
    ContextPack => "context.pack", SideEffectClass::Read;
    SummaryJobNext => "summary.job.next", SideEffectClass::Read;
    SummaryProposalSubmit => "summary.proposal.submit", SideEffectClass::CandidateWrite;
    SummaryVerificationNext => "summary.verification.next", SideEffectClass::Read;
    SummaryVerificationSubmit => "summary.verification.submit", SideEffectClass::CandidateWrite;
    SummaryAcceptV2 => "summary.accept.v2", SideEffectClass::CandidateWrite;
    RunGet => "run.get", SideEffectClass::Read;
    RunCancel => "run.cancel", SideEffectClass::RunLocalWrite;
    BundleVerify => "bundle.verify", SideEffectClass::ReceiptWrite;
    BundleCompare => "bundle.compare", SideEffectClass::Read;
    BundleMigrateV1ToV2 => "bundle.migrate.v1_to_v2", SideEffectClass::CandidateWrite;
    SnapshotCreate => "snapshot.create", SideEffectClass::VersionWrite;
    SnapshotVerify => "snapshot.verify", SideEffectClass::ReceiptWrite;
    SnapshotRestore => "snapshot.restore", SideEffectClass::CandidateWrite;
    GitPublish => "git.publish", SideEffectClass::GitExternalWrite;
    CurrentGet => "current.get", SideEffectClass::Read;
    CurrentActivate => "current.activate", SideEffectClass::CurrentWrite;
    NodeDescribe => "node.describe", SideEffectClass::RunLocalWrite;
    FederationValidate => "federation.validate", SideEffectClass::ReceiptWrite;
    TemplateList => "template.list", SideEffectClass::Read;
    TemplateResolve => "template.resolve", SideEffectClass::RunLocalWrite;
    TemplatePrefetch => "template.prefetch", SideEffectClass::CacheWrite;
    TemplateGet => "template.get", SideEffectClass::Read;
    TemplateValidate => "template.validate", SideEffectClass::ReceiptWrite;
    TemplateDerive => "template.derive", SideEffectClass::DraftWrite;
    TemplatePublish => "template.publish", SideEffectClass::GitExternalWrite;
    DeliverableDerive => "deliverable.derive", SideEffectClass::DraftWrite;
    DeliverablePublish => "deliverable.publish", SideEffectClass::GitExternalWrite;
    GraphNeighbors => "graph.neighbors", SideEffectClass::Read;
    GraphPath => "graph.path", SideEffectClass::Read;
    GraphImpact => "graph.impact", SideEffectClass::Read;
    GraphExplain => "graph.explain", SideEffectClass::Read;
    GraphTrace => "graph.trace", SideEffectClass::Read;
    GraphSearch => "graph.search", SideEffectClass::Read;
    A2uiResolve => "a2ui.resolve", SideEffectClass::RunLocalWrite;
    A2uiGenerate => "a2ui.generate", SideEffectClass::CandidateWrite;
    A2uiGet => "a2ui.get", SideEffectClass::Read;
    A2uiValidate => "a2ui.validate", SideEffectClass::ReceiptWrite;
}

pub fn v2_operation_definition(id: V2OperationId) -> Option<&'static V2OperationDefinition> {
    V2_PUBLIC_OPERATIONS
        .iter()
        .find(|definition| definition.id == id)
}

pub fn is_v1_only_operation_for_v2(operation_id: &str) -> bool {
    matches!(
        operation_id,
        "source.inspect"
            | "build.plan"
            | "build.prepare"
            | "build.finalize"
            | "summary.next"
            | "summary.accept"
            | "bundle.query"
    )
}

/// Closed transport envelope schema for one v2 operation. V2 handler-owned
/// payload schemas are intentionally deferred until the operation becomes
/// implemented; the envelope itself is still exact and version-pinned.
pub fn v2_operation_request_schema(id: V2OperationId) -> Value {
    json!({
        "type": "object",
        "required": ["protocol_version", "operation_id", "request_id", "payload"],
        "additionalProperties": false,
        "properties": {
            "protocol_version": {"type": "string", "const": PROTOCOL_VERSION_V2},
            "operation_id": {"type": "string", "const": id.as_str()},
            "request_id": {"type": "string", "minLength": 1},
            "payload": v2_operation_payload_schema(id)
        }
    })
}

fn v2_operation_payload_schema(id: V2OperationId) -> Value {
    let mut old = legacy_v2_operation_payload_schema(id);
    // Preserve local $defs resolution when a generated legacy schema becomes
    // a branch of the explicit successor envelope. This is a schema resource,
    // not a URL fetch or a change to the legacy request semantics.
    if old.get("$defs").is_some() {
        old["$id"] = json!(format!("urn:gtkg:v2:legacy-payload:{}", id.as_str()));
    }
    match crate::v04::payload_schema(id) {
        Some(new) => json!({"oneOf": [old, new]}),
        None => old,
    }
}

fn legacy_v2_operation_payload_schema(id: V2OperationId) -> Value {
    if let Some(legacy_id) = p05_legacy_operation(id) {
        return operation_request_schema(legacy_id)["properties"]["payload"].clone();
    }
    match id {
        V2OperationId::SystemDescribe | V2OperationId::CapabilityDescribe => json!({
            "type": "object",
            "required": [],
            "additionalProperties": false,
            "properties": {}
        }),
        V2OperationId::ConfigValidate => json!({
            "type": "object",
            "required": ["config_path"],
            "additionalProperties": false,
            "properties": {
                "config_path": {"type": "string", "minLength": 1}
            }
        }),
        V2OperationId::SourceCapture => json!({
            "type": "object",
            "required": ["capture_mode", "repository_id", "source_root", "output_path"],
            "additionalProperties": false,
            "properties": {
                "capture_mode": {
                    "type": "string",
                    "enum": ["worktree_exact", "directory_exact", "git_commit"]
                },
                "repository_id": {"type": "string", "minLength": 1},
                "source_root": {"type": "string", "minLength": 1},
                "output_path": {"type": "string", "minLength": 1}
            }
        }),
        V2OperationId::AnalysisPlan => payload_schema::<AnalysisPlanPayloadV2>(),
        V2OperationId::AnalysisBuild => payload_schema::<AnalysisBuildPayloadV2>(),
        V2OperationId::AnalysisVerify => payload_schema::<AnalysisVerifyPayloadV2>(),
        V2OperationId::ContextPack => payload_schema::<ContextPackPayloadV2>(),
        V2OperationId::SummaryJobNext => payload_schema::<SummaryJobNextPayloadV2>(),
        V2OperationId::SummaryProposalSubmit => payload_schema::<SummaryProposalSubmitPayloadV2>(),
        V2OperationId::SummaryVerificationNext => {
            payload_schema::<SummaryVerificationNextPayloadV2>()
        }
        V2OperationId::SummaryVerificationSubmit => {
            payload_schema::<SummaryVerificationSubmitPayloadV2>()
        }
        V2OperationId::SummaryAcceptV2 => payload_schema::<SummaryAcceptPayloadV2>(),
        V2OperationId::BuildFinalizeV2 => payload_schema::<BuildFinalizePayloadV2>(),
        V2OperationId::RunGet => payload_schema::<RunGetPayloadV2>(),
        V2OperationId::RunCancel => payload_schema::<RunCancelPayloadV2>(),
        V2OperationId::BundleVerify => payload_schema::<BundleVerifyPayloadV2>(),
        V2OperationId::BundleCompare => payload_schema::<BundleComparePayloadV2>(),
        V2OperationId::BundleMigrateV1ToV2 => payload_schema::<BundleMigratePayloadV2>(),
        V2OperationId::SnapshotCreate => payload_schema::<SnapshotCreatePayloadV2>(),
        V2OperationId::SnapshotVerify => payload_schema::<SnapshotVerifyPayloadV2>(),
        V2OperationId::SnapshotRestore => payload_schema::<SnapshotRestorePayloadV2>(),
        V2OperationId::GraphNeighbors
        | V2OperationId::GraphPath
        | V2OperationId::GraphImpact
        | V2OperationId::GraphExplain
        | V2OperationId::GraphTrace
        | V2OperationId::GraphSearch => graph_operation_payload_schema(id),
        _ => json!({}),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SystemDescribePayloadV2 {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConfigValidatePayloadV2 {
    pub config_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CapabilityDescribePayloadV2 {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SourceCapturePayloadV2 {
    pub capture_mode: SourceCaptureModeV2,
    pub repository_id: String,
    pub source_root: String,
    pub output_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AnalysisPlanPayloadV2 {
    pub workspace_root: PathBuf,
    pub source_root: PathBuf,
    pub source_snapshot_ref: FileReceiptRef,
    pub adapter_inputs: Vec<AnalysisAdapterInputV2>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AnalysisBuildPayloadV2 {
    pub workspace_root: PathBuf,
    pub plan_ref: FileReceiptRef,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AnalysisVerifyPayloadV2 {
    pub workspace_root: PathBuf,
    pub candidate_ref: FileReceiptRef,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ContextPackPayloadV2 {
    pub workspace_root: PathBuf,
    pub analysis_verification_ref: FileReceiptRef,
    pub max_fact_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SummaryJobNextPayloadV2 {
    pub workspace_root: PathBuf,
    pub analysis_verification_ref: FileReceiptRef,
    pub max_fact_count: u64,
    pub expected_context_pack_sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SummaryFactDecisionStateV2 {
    Supported,
    Abstain,
    Conflict,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SummaryFactDecisionV2 {
    pub fact_receipt_sha256: String,
    pub state: SummaryFactDecisionStateV2,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SummaryProposalSubmitPayloadV2 {
    pub workspace_root: PathBuf,
    pub analysis_verification_ref: FileReceiptRef,
    pub context_pack_sha256: String,
    pub summary_job_sha256: String,
    pub proposer_id: String,
    pub summary_text: String,
    pub decisions: Vec<SummaryFactDecisionV2>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SummaryVerificationNextPayloadV2 {
    pub workspace_root: PathBuf,
    pub proposal_ref: FileReceiptRef,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SummaryVerificationDecisionStateV2 {
    Verified,
    Rejected,
    Conflict,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SummaryVerificationDecisionV2 {
    pub proposal_decision_sha256: String,
    pub state: SummaryVerificationDecisionStateV2,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SummaryVerificationSubmitPayloadV2 {
    pub workspace_root: PathBuf,
    pub proposal_ref: FileReceiptRef,
    pub verification_job_sha256: String,
    pub verifier_id: String,
    pub decisions: Vec<SummaryVerificationDecisionV2>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SummaryAcceptPayloadV2 {
    pub workspace_root: PathBuf,
    pub proposal_ref: FileReceiptRef,
    pub summary_verification_ref: FileReceiptRef,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BuildFinalizePayloadV2 {
    pub workspace_root: PathBuf,
    pub analysis_verification_ref: FileReceiptRef,
    pub accepted_summary_ref: FileReceiptRef,
    pub bundle_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RunGetPayloadV2 {
    pub workspace_root: PathBuf,
    pub run_ref: FileReceiptRef,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RunCancelPayloadV2 {
    pub workspace_root: PathBuf,
    pub run_ref: FileReceiptRef,
    pub expected_run_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BundleVerifyPayloadV2 {
    pub workspace_root: PathBuf,
    pub bundle_ref: FileReceiptRef,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BundleComparePayloadV2 {
    pub workspace_root: PathBuf,
    pub left_bundle_ref: FileReceiptRef,
    pub right_bundle_ref: FileReceiptRef,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BundleMigratePayloadV2 {
    pub workspace_root: PathBuf,
    pub legacy_bundle_path: PathBuf,
    pub expected_legacy_tree_sha256: String,
    pub migration_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SnapshotCreatePayloadV2 {
    pub workspace_root: PathBuf,
    pub bundle_ref: FileReceiptRef,
    pub snapshot_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SnapshotVerifyPayloadV2 {
    pub workspace_root: PathBuf,
    pub snapshot_ref: FileReceiptRef,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SnapshotRestorePayloadV2 {
    pub workspace_root: PathBuf,
    pub snapshot_ref: FileReceiptRef,
    pub expected_snapshot_sha256: String,
    pub restore_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GraphQueryExpectedIdentitiesV2 {
    pub source_identity: String,
    pub graph_identity: String,
    pub overlay_identity: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum GraphQueryDirectionV2 {
    Incoming,
    Outgoing,
    Both,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphNeighborsPayloadV2 {
    pub query_index_path: String,
    pub query_manifest_ref: FileReceiptRef,
    pub evidence_index_path: String,
    pub evidence_manifest_ref: FileReceiptRef,
    pub expected_identities: GraphQueryExpectedIdentitiesV2,
    pub node_id: String,
    pub direction: Option<GraphQueryDirectionV2>,
    pub max_results: Option<u64>,
    pub continuation: Option<String>,
    pub previous_page: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphPathPayloadV2 {
    pub query_index_path: String,
    pub query_manifest_ref: FileReceiptRef,
    pub evidence_index_path: String,
    pub evidence_manifest_ref: FileReceiptRef,
    pub expected_identities: GraphQueryExpectedIdentitiesV2,
    pub source_node_id: String,
    pub target_node_id: String,
    pub max_depth: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphImpactPayloadV2 {
    pub query_index_path: String,
    pub query_manifest_ref: FileReceiptRef,
    pub evidence_index_path: String,
    pub evidence_manifest_ref: FileReceiptRef,
    pub expected_identities: GraphQueryExpectedIdentitiesV2,
    pub node_id: String,
    pub max_depth: Option<u64>,
    pub max_results: Option<u64>,
    pub continuation: Option<String>,
    pub previous_page: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphExplainPayloadV2 {
    pub query_index_path: String,
    pub query_manifest_ref: FileReceiptRef,
    pub evidence_index_path: String,
    pub evidence_manifest_ref: FileReceiptRef,
    pub expected_identities: GraphQueryExpectedIdentitiesV2,
    pub node_id: String,
    pub max_results: Option<u64>,
    pub continuation: Option<String>,
    pub previous_page: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphTracePayloadV2 {
    pub query_index_path: String,
    pub query_manifest_ref: FileReceiptRef,
    pub evidence_index_path: String,
    pub evidence_manifest_ref: FileReceiptRef,
    pub expected_identities: GraphQueryExpectedIdentitiesV2,
    pub entity_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphSearchPayloadV2 {
    pub query_index_path: String,
    pub query_manifest_ref: FileReceiptRef,
    pub evidence_index_path: String,
    pub evidence_manifest_ref: FileReceiptRef,
    pub expected_identities: GraphQueryExpectedIdentitiesV2,
    pub query: String,
    pub max_results: Option<u64>,
    pub continuation: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "adapter_kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AnalysisAdapterInputV2 {
    Native {
        logical_path: String,
    },
    Scip {
        input_path: PathBuf,
        pin: ScipAnalysisPinV2,
    },
    LspSnapshot {
        input_path: PathBuf,
        pin: LspSnapshotAnalysisPinV2,
    },
    Codegraph {
        input_path: PathBuf,
        pin: CodeGraphAnalysisPinV2,
    },
    Graphify {
        input_path: PathBuf,
        pin: GraphifyAnalysisPinV2,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScipAnalysisPinV2 {
    pub file_sha256: String,
    pub schema_version: String,
    pub schema_sha256: String,
    pub tool_name: String,
    pub tool_version: String,
    pub tool_commit: String,
    pub tool_license: String,
    pub source_snapshot_sha256: String,
    #[serde(default)]
    pub selected_source_snapshot_sha256: Option<String>,
    pub max_file_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LspSnapshotAnalysisPinV2 {
    pub file_sha256: String,
    pub schema_version: String,
    pub schema_sha256: String,
    pub protocol_version: String,
    pub position_encoding: String,
    pub producer_name: String,
    pub producer_version: String,
    pub producer_commit: String,
    pub producer_license: String,
    pub producer_config_sha256: String,
    pub source_snapshot_sha256: String,
    #[serde(default)]
    pub selected_source_snapshot_sha256: Option<String>,
    pub max_file_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeGraphAnalysisPinV2 {
    pub file_sha256: String,
    pub schema_sha256: String,
    pub tool_version: String,
    pub tool_commit: String,
    pub tool_license: String,
    pub source_snapshot_sha256: String,
    pub max_file_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GraphifyAnalysisPinV2 {
    pub file_sha256: String,
    pub canonical_schema_sha256: String,
    pub tool_version: String,
    pub tool_commit: String,
    pub tool_license: String,
    pub export_py_sha256: String,
    pub validate_py_sha256: String,
    pub pyproject_sha256: String,
    pub license_sha256: String,
    pub extraction_spec_sha256: String,
    pub source_snapshot_sha256: String,
    pub source_repository_commit: String,
    pub max_file_bytes: u64,
    pub max_node_count: u64,
    pub max_link_count: u64,
    pub max_hyperedge_count: u64,
}

/// Validate the handler-owned P01 payloads before effect or filesystem
/// evaluation. Success for other operations deliberately preserves their
/// owning task's existing validation boundary.
pub fn validate_v2_operation_payload(id: V2OperationId, payload: &Value) -> Result<(), String> {
    if payload.get("payload_revision").is_some() {
        return crate::v04::validate_payload(id, payload);
    }
    if let Some(legacy_id) = p05_legacy_operation(id) {
        return validate_operation_payload(legacy_id, payload)
            .map_err(|error| format!("invalid {} payload: {error}", id.as_str()));
    }
    match id {
        V2OperationId::SystemDescribe => {
            serde_json::from_value::<SystemDescribePayloadV2>(payload.clone())
                .map(|_| ())
                .map_err(|error| format!("invalid system.describe payload: {error}"))
        }
        V2OperationId::ConfigValidate => {
            let payload = serde_json::from_value::<ConfigValidatePayloadV2>(payload.clone())
                .map_err(|error| format!("invalid config.validate payload: {error}"))?;
            if payload.config_path.is_empty() {
                return Err("config_path must not be empty".to_owned());
            }
            Ok(())
        }
        V2OperationId::CapabilityDescribe => {
            serde_json::from_value::<CapabilityDescribePayloadV2>(payload.clone())
                .map(|_| ())
                .map_err(|error| format!("invalid capability.describe payload: {error}"))
        }
        V2OperationId::SourceCapture => {
            let payload = serde_json::from_value::<SourceCapturePayloadV2>(payload.clone())
                .map_err(|error| format!("invalid source.capture payload: {error}"))?;
            if payload.repository_id.is_empty()
                || payload.source_root.is_empty()
                || payload.output_path.is_empty()
            {
                return Err(
                    "repository_id, source_root, and output_path must not be empty".to_owned(),
                );
            }
            if payload.capture_mode == SourceCaptureModeV2::SuppliedManifest {
                return Err(
                    "source.capture transport does not infer supplied-manifest authority"
                        .to_owned(),
                );
            }
            Ok(())
        }
        V2OperationId::AnalysisPlan => {
            let payload = serde_json::from_value::<AnalysisPlanPayloadV2>(payload.clone())
                .map_err(|error| format!("invalid analysis.plan payload: {error}"))?;
            payload
                .source_snapshot_ref
                .validate()
                .map_err(|error| error.to_string())?;
            if payload.adapter_inputs.is_empty() || payload.adapter_inputs.len() > 256 {
                return Err("adapter_inputs must contain between 1 and 256 selections".to_owned());
            }
            Ok(())
        }
        V2OperationId::AnalysisBuild => {
            let payload = serde_json::from_value::<AnalysisBuildPayloadV2>(payload.clone())
                .map_err(|error| format!("invalid analysis.build payload: {error}"))?;
            payload
                .plan_ref
                .validate()
                .map_err(|error| error.to_string())
        }
        V2OperationId::AnalysisVerify => {
            let payload = serde_json::from_value::<AnalysisVerifyPayloadV2>(payload.clone())
                .map_err(|error| format!("invalid analysis.verify payload: {error}"))?;
            payload
                .candidate_ref
                .validate()
                .map_err(|error| error.to_string())
        }
        V2OperationId::ContextPack => {
            let payload = serde_json::from_value::<ContextPackPayloadV2>(payload.clone())
                .map_err(|error| format!("invalid context.pack payload: {error}"))?;
            payload
                .analysis_verification_ref
                .validate()
                .map_err(|error| error.to_string())?;
            validate_fact_budget(payload.max_fact_count)
        }
        V2OperationId::SummaryJobNext => {
            let payload = serde_json::from_value::<SummaryJobNextPayloadV2>(payload.clone())
                .map_err(|error| format!("invalid summary.job.next payload: {error}"))?;
            payload
                .analysis_verification_ref
                .validate()
                .map_err(|error| error.to_string())?;
            validate_sha256(&payload.expected_context_pack_sha256)
                .map_err(|error| error.to_string())?;
            validate_fact_budget(payload.max_fact_count)
        }
        V2OperationId::SummaryProposalSubmit => {
            let payload = serde_json::from_value::<SummaryProposalSubmitPayloadV2>(payload.clone())
                .map_err(|error| format!("invalid summary.proposal.submit payload: {error}"))?;
            payload
                .analysis_verification_ref
                .validate()
                .map_err(|error| error.to_string())?;
            validate_sha256(&payload.context_pack_sha256).map_err(|error| error.to_string())?;
            validate_sha256(&payload.summary_job_sha256).map_err(|error| error.to_string())?;
            validate_summary_identity(&payload.proposer_id)?;
            if payload.summary_text.trim().is_empty() || payload.summary_text.len() > 65_536 {
                return Err("summary_text must contain 1..65536 bytes".to_owned());
            }
            validate_summary_fact_decisions(&payload.decisions)
        }
        V2OperationId::SummaryVerificationNext => {
            let payload =
                serde_json::from_value::<SummaryVerificationNextPayloadV2>(payload.clone())
                    .map_err(|error| {
                        format!("invalid summary.verification.next payload: {error}")
                    })?;
            payload
                .proposal_ref
                .validate()
                .map_err(|error| error.to_string())
        }
        V2OperationId::SummaryVerificationSubmit => {
            let payload =
                serde_json::from_value::<SummaryVerificationSubmitPayloadV2>(payload.clone())
                    .map_err(|error| {
                        format!("invalid summary.verification.submit payload: {error}")
                    })?;
            payload
                .proposal_ref
                .validate()
                .map_err(|error| error.to_string())?;
            validate_sha256(&payload.verification_job_sha256).map_err(|error| error.to_string())?;
            validate_summary_identity(&payload.verifier_id)?;
            validate_summary_verification_decisions(&payload.decisions)
        }
        V2OperationId::SummaryAcceptV2 => {
            let payload = serde_json::from_value::<SummaryAcceptPayloadV2>(payload.clone())
                .map_err(|error| format!("invalid summary.accept.v2 payload: {error}"))?;
            payload
                .proposal_ref
                .validate()
                .map_err(|error| error.to_string())?;
            payload
                .summary_verification_ref
                .validate()
                .map_err(|error| error.to_string())
        }
        V2OperationId::BuildFinalizeV2 => {
            let payload = serde_json::from_value::<BuildFinalizePayloadV2>(payload.clone())
                .map_err(|error| format!("invalid build.finalize.v2 payload: {error}"))?;
            payload
                .analysis_verification_ref
                .validate()
                .map_err(|error| error.to_string())?;
            payload
                .accepted_summary_ref
                .validate()
                .map_err(|error| error.to_string())?;
            validate_lifecycle_version(&payload.bundle_version)
        }
        V2OperationId::RunGet => {
            let payload = serde_json::from_value::<RunGetPayloadV2>(payload.clone())
                .map_err(|error| format!("invalid run.get payload: {error}"))?;
            payload
                .run_ref
                .validate()
                .map_err(|error| error.to_string())
        }
        V2OperationId::RunCancel => {
            let payload = serde_json::from_value::<RunCancelPayloadV2>(payload.clone())
                .map_err(|error| format!("invalid run.cancel payload: {error}"))?;
            payload
                .run_ref
                .validate()
                .map_err(|error| error.to_string())?;
            validate_sha256(&payload.expected_run_sha256).map_err(|error| error.to_string())
        }
        V2OperationId::BundleVerify => {
            let payload = serde_json::from_value::<BundleVerifyPayloadV2>(payload.clone())
                .map_err(|error| format!("invalid bundle.verify payload: {error}"))?;
            payload
                .bundle_ref
                .validate()
                .map_err(|error| error.to_string())
        }
        V2OperationId::BundleCompare => {
            let payload = serde_json::from_value::<BundleComparePayloadV2>(payload.clone())
                .map_err(|error| format!("invalid bundle.compare payload: {error}"))?;
            payload
                .left_bundle_ref
                .validate()
                .map_err(|error| error.to_string())?;
            payload
                .right_bundle_ref
                .validate()
                .map_err(|error| error.to_string())
        }
        V2OperationId::BundleMigrateV1ToV2 => {
            let payload = serde_json::from_value::<BundleMigratePayloadV2>(payload.clone())
                .map_err(|error| format!("invalid bundle.migrate.v1_to_v2 payload: {error}"))?;
            validate_sha256(&payload.expected_legacy_tree_sha256)
                .map_err(|error| error.to_string())?;
            validate_lifecycle_version(&payload.migration_version)
        }
        V2OperationId::SnapshotCreate => {
            let payload = serde_json::from_value::<SnapshotCreatePayloadV2>(payload.clone())
                .map_err(|error| format!("invalid snapshot.create payload: {error}"))?;
            payload
                .bundle_ref
                .validate()
                .map_err(|error| error.to_string())?;
            validate_lifecycle_version(&payload.snapshot_version)
        }
        V2OperationId::SnapshotVerify => {
            let payload = serde_json::from_value::<SnapshotVerifyPayloadV2>(payload.clone())
                .map_err(|error| format!("invalid snapshot.verify payload: {error}"))?;
            payload
                .snapshot_ref
                .validate()
                .map_err(|error| error.to_string())
        }
        V2OperationId::SnapshotRestore => {
            let payload = serde_json::from_value::<SnapshotRestorePayloadV2>(payload.clone())
                .map_err(|error| format!("invalid snapshot.restore payload: {error}"))?;
            payload
                .snapshot_ref
                .validate()
                .map_err(|error| error.to_string())?;
            validate_sha256(&payload.expected_snapshot_sha256)
                .map_err(|error| error.to_string())?;
            validate_lifecycle_version(&payload.restore_version)
        }
        V2OperationId::GraphNeighbors => {
            reject_graph_explicit_nulls(
                payload,
                &["direction", "max_results", "continuation", "previous_page"],
            )?;
            let payload = serde_json::from_value::<GraphNeighborsPayloadV2>(payload.clone())
                .map_err(|error| format!("invalid graph.neighbors payload: {error}"))?;
            validate_graph_common(
                &payload.query_index_path,
                &payload.query_manifest_ref,
                &payload.evidence_index_path,
                &payload.evidence_manifest_ref,
                &payload.expected_identities,
            )?;
            validate_graph_identity(&payload.node_id, "node_id")?;
            validate_graph_max_results(payload.max_results)?;
            validate_graph_continuation_pair(
                payload.continuation.as_deref(),
                payload.previous_page.as_ref(),
            )
        }
        V2OperationId::GraphPath => {
            reject_graph_explicit_nulls(payload, &["max_depth"])?;
            let payload = serde_json::from_value::<GraphPathPayloadV2>(payload.clone())
                .map_err(|error| format!("invalid graph.path payload: {error}"))?;
            validate_graph_common(
                &payload.query_index_path,
                &payload.query_manifest_ref,
                &payload.evidence_index_path,
                &payload.evidence_manifest_ref,
                &payload.expected_identities,
            )?;
            validate_graph_identity(&payload.source_node_id, "source_node_id")?;
            validate_graph_identity(&payload.target_node_id, "target_node_id")?;
            validate_graph_max_depth(payload.max_depth)
        }
        V2OperationId::GraphImpact => {
            reject_graph_explicit_nulls(
                payload,
                &["max_depth", "max_results", "continuation", "previous_page"],
            )?;
            let payload = serde_json::from_value::<GraphImpactPayloadV2>(payload.clone())
                .map_err(|error| format!("invalid graph.impact payload: {error}"))?;
            validate_graph_common(
                &payload.query_index_path,
                &payload.query_manifest_ref,
                &payload.evidence_index_path,
                &payload.evidence_manifest_ref,
                &payload.expected_identities,
            )?;
            validate_graph_identity(&payload.node_id, "node_id")?;
            validate_graph_max_depth(payload.max_depth)?;
            validate_graph_max_results(payload.max_results)?;
            validate_graph_continuation_pair(
                payload.continuation.as_deref(),
                payload.previous_page.as_ref(),
            )
        }
        V2OperationId::GraphExplain => {
            reject_graph_explicit_nulls(
                payload,
                &["max_results", "continuation", "previous_page"],
            )?;
            let payload = serde_json::from_value::<GraphExplainPayloadV2>(payload.clone())
                .map_err(|error| format!("invalid graph.explain payload: {error}"))?;
            validate_graph_common(
                &payload.query_index_path,
                &payload.query_manifest_ref,
                &payload.evidence_index_path,
                &payload.evidence_manifest_ref,
                &payload.expected_identities,
            )?;
            validate_graph_identity(&payload.node_id, "node_id")?;
            validate_graph_max_results(payload.max_results)?;
            validate_graph_continuation_pair(
                payload.continuation.as_deref(),
                payload.previous_page.as_ref(),
            )
        }
        V2OperationId::GraphTrace => {
            let payload = serde_json::from_value::<GraphTracePayloadV2>(payload.clone())
                .map_err(|error| format!("invalid graph.trace payload: {error}"))?;
            validate_graph_common(
                &payload.query_index_path,
                &payload.query_manifest_ref,
                &payload.evidence_index_path,
                &payload.evidence_manifest_ref,
                &payload.expected_identities,
            )?;
            validate_graph_identity(&payload.entity_id, "entity_id")
        }
        V2OperationId::GraphSearch => {
            reject_graph_explicit_nulls(payload, &["max_results", "continuation"])?;
            let payload = serde_json::from_value::<GraphSearchPayloadV2>(payload.clone())
                .map_err(|error| format!("invalid graph.search payload: {error}"))?;
            validate_graph_common(
                &payload.query_index_path,
                &payload.query_manifest_ref,
                &payload.evidence_index_path,
                &payload.evidence_manifest_ref,
                &payload.expected_identities,
            )?;
            if payload.query.trim().is_empty() || payload.query.chars().count() > 512 {
                return Err("query must contain 1..512 Unicode scalars".to_owned());
            }
            validate_graph_max_results(payload.max_results)?;
            validate_graph_continuation(payload.continuation.as_deref())
        }
        _ => Ok(()),
    }
}

fn payload_schema<T: JsonSchema>() -> Value {
    serde_json::to_value(schemars::schema_for!(T)).unwrap_or_else(|_| json!({}))
}

fn graph_operation_payload_schema(id: V2OperationId) -> Value {
    let bounded_string = json!({"type": "string", "minLength": 1, "maxLength": 4096});
    let mut properties = serde_json::Map::from_iter([
        ("query_index_path".to_owned(), bounded_string.clone()),
        (
            "query_manifest_ref".to_owned(),
            payload_schema::<FileReceiptRef>(),
        ),
        ("evidence_index_path".to_owned(), bounded_string.clone()),
        (
            "evidence_manifest_ref".to_owned(),
            payload_schema::<FileReceiptRef>(),
        ),
        (
            "expected_identities".to_owned(),
            payload_schema::<GraphQueryExpectedIdentitiesV2>(),
        ),
    ]);
    let mut required = vec![
        "query_index_path".to_owned(),
        "query_manifest_ref".to_owned(),
        "evidence_index_path".to_owned(),
        "evidence_manifest_ref".to_owned(),
        "expected_identities".to_owned(),
    ];
    let max_results = json!({"type": "integer", "minimum": 1, "maximum": 1000});
    let max_depth = json!({"type": "integer", "minimum": 1, "maximum": 8});
    let continuation = json!({
        "type": "string",
        "minLength": 1,
        "maxLength": 4 * 1024 * 1024
    });
    let previous_page = json!({"type": "object"});
    match id {
        V2OperationId::GraphNeighbors => {
            properties.insert("node_id".to_owned(), bounded_string.clone());
            properties.insert(
                "direction".to_owned(),
                json!({"type": "string", "enum": ["incoming", "outgoing", "both"]}),
            );
            properties.insert("max_results".to_owned(), max_results);
            properties.insert("continuation".to_owned(), continuation);
            properties.insert("previous_page".to_owned(), previous_page);
            required.push("node_id".to_owned());
        }
        V2OperationId::GraphPath => {
            properties.insert("source_node_id".to_owned(), bounded_string.clone());
            properties.insert("target_node_id".to_owned(), bounded_string.clone());
            properties.insert("max_depth".to_owned(), max_depth);
            required.extend(["source_node_id".to_owned(), "target_node_id".to_owned()]);
        }
        V2OperationId::GraphImpact => {
            properties.insert("node_id".to_owned(), bounded_string.clone());
            properties.insert("max_depth".to_owned(), max_depth);
            properties.insert("max_results".to_owned(), max_results);
            properties.insert("continuation".to_owned(), continuation);
            properties.insert("previous_page".to_owned(), previous_page);
            required.push("node_id".to_owned());
        }
        V2OperationId::GraphExplain => {
            properties.insert("node_id".to_owned(), bounded_string.clone());
            properties.insert("max_results".to_owned(), max_results);
            properties.insert("continuation".to_owned(), continuation);
            properties.insert("previous_page".to_owned(), previous_page);
            required.push("node_id".to_owned());
        }
        V2OperationId::GraphTrace => {
            properties.insert("entity_id".to_owned(), bounded_string.clone());
            required.push("entity_id".to_owned());
        }
        V2OperationId::GraphSearch => {
            properties.insert(
                "query".to_owned(),
                json!({"type": "string", "minLength": 1, "maxLength": 512}),
            );
            properties.insert("max_results".to_owned(), max_results);
            properties.insert("continuation".to_owned(), continuation);
            required.push("query".to_owned());
        }
        _ => return json!({}),
    }
    required.sort();
    let all_of = match id {
        V2OperationId::GraphNeighbors
        | V2OperationId::GraphImpact
        | V2OperationId::GraphExplain => {
            vec![json!({
                "if": {"required": ["previous_page"]},
                "then": {"required": ["continuation"]}
            })]
        }
        _ => Vec::new(),
    };
    json!({
        "type": "object",
        "required": required,
        "additionalProperties": false,
        "allOf": all_of,
        "properties": properties,
    })
}

fn validate_graph_common(
    query_index_path: &str,
    query_manifest_ref: &FileReceiptRef,
    evidence_index_path: &str,
    evidence_manifest_ref: &FileReceiptRef,
    expected: &GraphQueryExpectedIdentitiesV2,
) -> Result<(), String> {
    for (label, value) in [
        ("query_index_path", query_index_path),
        ("evidence_index_path", evidence_index_path),
    ] {
        let path = Path::new(value);
        if value.trim().is_empty()
            || value.len() > 4096
            || path.is_absolute()
            || path.components().any(|component| {
                matches!(
                    component,
                    Component::ParentDir
                        | Component::CurDir
                        | Component::RootDir
                        | Component::Prefix(_)
                )
            })
        {
            return Err(format!("{label} must be a safe workspace-relative path"));
        }
    }
    query_manifest_ref
        .validate()
        .map_err(|error| error.to_string())?;
    evidence_manifest_ref
        .validate()
        .map_err(|error| error.to_string())?;
    for value in [
        &expected.source_identity,
        &expected.graph_identity,
        &expected.overlay_identity,
    ] {
        validate_sha256(value).map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn reject_graph_explicit_nulls(payload: &Value, fields: &[&str]) -> Result<(), String> {
    let object = payload
        .as_object()
        .ok_or_else(|| "graph payload must be an object".to_owned())?;
    if let Some(field) = fields
        .iter()
        .find(|field| object.get(**field).is_some_and(Value::is_null))
    {
        return Err(format!("{field} must be omitted instead of null"));
    }
    Ok(())
}

fn validate_graph_identity(value: &str, label: &str) -> Result<(), String> {
    (!value.trim().is_empty() && value.len() <= 4096 && !value.chars().any(char::is_control))
        .then_some(())
        .ok_or_else(|| format!("{label} must be a non-empty bounded identity"))
}

fn validate_graph_max_results(value: Option<u64>) -> Result<(), String> {
    value
        .is_none_or(|value| (1..=1000).contains(&value))
        .then_some(())
        .ok_or_else(|| "max_results must be between 1 and 1000".to_owned())
}

fn validate_graph_max_depth(value: Option<u64>) -> Result<(), String> {
    value
        .is_none_or(|value| (1..=8).contains(&value))
        .then_some(())
        .ok_or_else(|| "max_depth must be between 1 and 8".to_owned())
}

fn validate_graph_continuation(value: Option<&str>) -> Result<(), String> {
    value
        .is_none_or(|value| !value.is_empty() && value.len() <= 4 * 1024 * 1024)
        .then_some(())
        .ok_or_else(|| "continuation must contain 1..4194304 bytes".to_owned())
}

fn validate_graph_continuation_pair(
    continuation: Option<&str>,
    previous_page: Option<&Value>,
) -> Result<(), String> {
    validate_graph_continuation(continuation)?;
    if previous_page.is_some_and(|value| !value.is_object()) {
        return Err("previous_page must be an object".to_owned());
    }
    if continuation.is_none() && previous_page.is_some() {
        return Err("previous_page requires continuation".to_owned());
    }
    Ok(())
}

fn validate_fact_budget(value: u64) -> Result<(), String> {
    (1..=4096)
        .contains(&value)
        .then_some(())
        .ok_or_else(|| "max_fact_count must be between 1 and 4096".to_owned())
}

fn validate_summary_identity(value: &str) -> Result<(), String> {
    (!value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')))
    .then_some(())
    .ok_or_else(|| "summary actor identity is invalid".to_owned())
}

fn validate_summary_fact_decisions(values: &[SummaryFactDecisionV2]) -> Result<(), String> {
    if values.len() > 4096 {
        return Err("summary fact decision denominator exceeds 4096".to_owned());
    }
    for value in values {
        validate_sha256(&value.fact_receipt_sha256).map_err(|error| error.to_string())?;
        if value.reason.trim().is_empty() {
            return Err("summary fact decision reason must not be empty".to_owned());
        }
    }
    Ok(())
}

fn validate_summary_verification_decisions(
    values: &[SummaryVerificationDecisionV2],
) -> Result<(), String> {
    if values.len() > 4096 {
        return Err("summary verification decision denominator exceeds 4096".to_owned());
    }
    for value in values {
        validate_sha256(&value.proposal_decision_sha256).map_err(|error| error.to_string())?;
        if value.reason.trim().is_empty() {
            return Err("summary verification decision reason must not be empty".to_owned());
        }
    }
    Ok(())
}

fn validate_lifecycle_version(value: &str) -> Result<(), String> {
    (!value.is_empty()
        && value.len() <= 128
        && !value.contains('/')
        && !value.contains("..")
        && !matches!(
            value.to_ascii_lowercase().as_str(),
            "current" | "latest" | "head"
        ))
    .then_some(())
    .ok_or_else(|| "lifecycle version must be exact, bounded, and non-floating".to_owned())
}

const fn p05_legacy_operation(id: V2OperationId) -> Option<OperationId> {
    match id {
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

/// A transport-neutral v2 request. The operation id remains a string at this
/// boundary so an attempted v1-only id can produce the mandated version error.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OperationRequestV2 {
    pub protocol_version: String,
    pub operation_id: String,
    pub request_id: String,
    pub payload: Value,
}

impl OperationRequestV2 {
    /// Resolve the envelope before checking profile membership or invoking a handler.
    #[allow(clippy::result_large_err)]
    pub fn resolve_operation(&self) -> Result<V2OperationId, V2ErrorEnvelope> {
        if self.request_id.is_empty() {
            return Err(V2ErrorEnvelope::new(
                self,
                V2ErrorCode::InvalidRequest,
                "request-schema",
                "request_id must not be empty",
                "provide a non-empty request_id that can bind the response to this exact request",
            ));
        }
        if self.protocol_version != PROTOCOL_VERSION_V2 {
            return Err(V2ErrorEnvelope::new(
                self,
                V2ErrorCode::ProtocolVersionMismatch,
                "protocol",
                format!(
                    "unsupported protocol version {}; expected {PROTOCOL_VERSION_V2}",
                    self.protocol_version
                ),
                "select gtkg.protocol/v1 for legacy operations or send the exact v2 protocol version",
            ));
        }
        if is_v1_only_operation_for_v2(&self.operation_id) {
            return Err(V2ErrorEnvelope::new(
                self,
                V2ErrorCode::OperationVersionUnsupported,
                "version-routing",
                format!(
                    "operation {} is v1-only and is unsupported by gtkg.protocol/v2",
                    self.operation_id
                ),
                "retry this exact operation with protocol_version=gtkg.protocol/v1",
            ));
        }
        V2OperationId::parse(&self.operation_id).ok_or_else(|| {
            V2ErrorEnvelope::new(
                self,
                V2ErrorCode::OperationNotImplemented,
                "dispatch",
                "operation is absent from the closed v2 public registry",
                "use v2 discovery to select one of the published operation identifiers",
            )
        })
    }

    pub fn new(
        operation_id: impl Into<String>,
        request_id: impl Into<String>,
        payload: Value,
    ) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION_V2.to_owned(),
            operation_id: operation_id.into(),
            request_id: request_id.into(),
            payload,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OperationResponseV2 {
    pub protocol_version: String,
    pub operation_id: V2OperationId,
    pub request_id: String,
    pub result: Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum V2ErrorCode {
    #[serde(rename = "E_INVALID_REQUEST")]
    InvalidRequest,
    #[serde(rename = "E_OPERATION_VERSION_UNSUPPORTED")]
    OperationVersionUnsupported,
    #[serde(rename = "E_OPERATION_NOT_IMPLEMENTED")]
    OperationNotImplemented,
    #[serde(rename = "E_PROTOCOL_VERSION_MISMATCH")]
    ProtocolVersionMismatch,
    #[serde(rename = "E_SIDE_EFFECT_DENIED")]
    SideEffectDenied,
    #[serde(rename = "E_MISSING_HOST_CAPABILITY")]
    MissingHostCapability,
    #[serde(rename = "E_PATH_ESCAPE")]
    PathEscape,
    #[serde(rename = "E_SYMLINK_REJECTED")]
    SymlinkRejected,
    #[serde(rename = "E_SOURCE_NOT_GIT")]
    SourceNotGit,
    #[serde(rename = "E_SOURCE_DIRTY")]
    SourceDirty,
    #[serde(rename = "E_SOURCE_OUTPUT_OVERLAP")]
    SourceOutputOverlap,
    #[serde(rename = "E_SOURCE_CHANGED")]
    SourceChanged,
    #[serde(rename = "E_SOURCE_SNAPSHOT_CONFLICT")]
    SourceSnapshotConflict,
    #[serde(rename = "E_DB_FORBIDDEN")]
    DatabaseForbidden,
    #[serde(rename = "E_NOT_FOUND")]
    NotFound,
    #[serde(rename = "E_IO")]
    Io,
    #[serde(rename = "E_SCOPE_DENIED")]
    ScopeDenied,
    #[serde(rename = "E_LOCK_MISMATCH")]
    LockMismatch,
    #[serde(rename = "E_INVALID_STATE")]
    InvalidState,
    #[serde(rename = "E_OKF_INVALID")]
    OkfInvalid,
    #[serde(rename = "E_INDEX_INVALID")]
    IndexInvalid,
    #[serde(rename = "E_VERSION_IMMUTABLE")]
    VersionImmutable,
    #[serde(rename = "E_EXTRACT_UNSUPPORTED")]
    ExtractUnsupported,
    #[serde(rename = "E_EXTRACT_INVALID")]
    ExtractInvalid,
    #[serde(rename = "E_BUNDLE_INVALID")]
    BundleInvalid,
    #[serde(rename = "E_NON_DETERMINISTIC_RESULT")]
    NonDeterministicResult,
    #[serde(rename = "E_SANDBOX_ASSURANCE_UNAVAILABLE")]
    SandboxAssuranceUnavailable,
    #[serde(rename = "E_STRUCTURAL_QUERY_READBACK_FAILED")]
    StructuralQueryReadbackFailed,
    #[serde(rename = "E_CLAIM_AWARE_QUERY_READBACK_FAILED")]
    ClaimAwareQueryReadbackFailed,
}

impl V2ErrorCode {
    /// Map a v1 error code onto its v2 counterpart.
    ///
    /// The knowledge-quality dispatch used to collapse every failure into
    /// `E_INVALID_REQUEST`, so a caller could not tell an unauthorized path from a
    /// malformed payload. Layers that already carry a typed code (the exact-read
    /// boundary and the authorized-root context) hand their real code through
    /// instead. The match is exhaustive so a new v1 code cannot be silently
    /// downgraded here.
    pub const fn from_v1(code: ErrorCode) -> Self {
        match code {
            ErrorCode::ProtocolVersionMismatch => Self::ProtocolVersionMismatch,
            ErrorCode::InvalidRequest => Self::InvalidRequest,
            ErrorCode::OperationNotImplemented => Self::OperationNotImplemented,
            ErrorCode::Io => Self::Io,
            ErrorCode::PathEscape => Self::PathEscape,
            ErrorCode::ScopeDenied => Self::ScopeDenied,
            ErrorCode::SideEffectDenied => Self::SideEffectDenied,
            ErrorCode::SymlinkRejected => Self::SymlinkRejected,
            ErrorCode::SourceNotGit => Self::SourceNotGit,
            ErrorCode::SourceDirty => Self::SourceDirty,
            ErrorCode::LockMismatch => Self::LockMismatch,
            ErrorCode::InvalidState => Self::InvalidState,
            ErrorCode::OkfInvalid => Self::OkfInvalid,
            ErrorCode::IndexInvalid => Self::IndexInvalid,
            ErrorCode::VersionImmutable => Self::VersionImmutable,
            ErrorCode::DatabaseForbidden => Self::DatabaseForbidden,
            ErrorCode::ExtractUnsupported => Self::ExtractUnsupported,
            ErrorCode::ExtractInvalid => Self::ExtractInvalid,
            ErrorCode::BundleInvalid => Self::BundleInvalid,
            ErrorCode::NotFound => Self::NotFound,
            ErrorCode::NonDeterministicResult => Self::NonDeterministicResult,
            ErrorCode::SandboxAssuranceUnavailable => Self::SandboxAssuranceUnavailable,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct V2ErrorDetail {
    pub code: V2ErrorCode,
    pub stage: String,
    pub message: String,
    pub recovery_hint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct V2ErrorEnvelope {
    pub protocol_version: String,
    pub request_id: String,
    pub error: V2ErrorDetail,
}

impl V2ErrorEnvelope {
    pub fn invalid_request(request_id: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION_V2.to_owned(),
            request_id: request_id.into(),
            error: V2ErrorDetail {
                code: V2ErrorCode::InvalidRequest,
                stage: "request-schema".to_owned(),
                message: message.into(),
                recovery_hint: "use the exact closed v2 request schema disclosed by MCP tools/list"
                    .to_owned(),
            },
        }
    }

    pub fn new(
        request: &OperationRequestV2,
        code: V2ErrorCode,
        stage: impl Into<String>,
        message: impl Into<String>,
        recovery_hint: impl Into<String>,
    ) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION_V2.to_owned(),
            request_id: request.request_id.clone(),
            error: V2ErrorDetail {
                code,
                stage: stage.into(),
                message: message.into(),
                recovery_hint: recovery_hint.into(),
            },
        }
    }
}

const SHA256_PREFIX: &str = "sha256:";
const CORE_PROFILE_ID: &str = "GTKG-V0.2-CORE";
const CORE_FORMATS: &[&str] = &[
    "Markdown", "PDF", "DOCX", "XLSX", "PPTX", "JSON", "YAML", "TOML", "HTML", "CSS", "SVG",
    "Shell",
];
const CORE_LANGUAGES: &[&str] = &["Rust", "Python", "TypeScript", "JavaScript"];
const CORE_TOOL_LOCKS: &[&str] = &["adapter", "resolver", "tokenizer", "prompt", "verifier"];
const CORE_CAPABILITIES: &[&str] = &[
    "syntax",
    "symbols",
    "scopes",
    "imports",
    "references",
    "types",
    "inheritance",
    "calls",
    "cfg",
    "exception",
    "def_use",
    "state_flow",
    "document_locator",
];
const CORE_GATES: &[&str] = &[
    "source_coverage",
    "document_locator",
    "semantic_ir",
    "claim_grounding",
    "graph_query",
    "current_okf",
    "scale_security",
];
const CORE_RELATIONS: &[&str] = &[
    "contains",
    "defines",
    "imports",
    "references",
    "calls",
    "typed_as",
    "controls",
    "evidence_for",
];

/// Capability truth is independent of a gate result.  A partial or unsupported
/// capability can be disclosed, but cannot be promoted to comprehensive by a
/// passing score elsewhere.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityState {
    Supported,
    Partial,
    Unsupported,
    NotApplicable,
}

/// Evidence state of one profile hard gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum GateStatus {
    Passed,
    Failed,
    Blocked,
    NotRun,
    Stale,
    Invalid,
    CannotConfirm,
}

/// A profile may be complete for its own declared denominator without being
/// the product-certified V0.2 profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProfileKind {
    ProductCertifiedCore,
    Custom,
}

/// Pinned upstream OKF identity required by a profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OkfSpecPinV1 {
    pub version: String,
    pub upstream_commit: String,
    pub raw_sha256: String,
}

/// Exact identity of the external OKF specification a V0.2 validation run is
/// allowed to discuss.  Constructing a pin verifies only its *shape*; it does
/// not fetch an upstream asset or claim that the pinned specification has been
/// conformed to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OkfSpecPinV2 {
    pub version: String,
    pub upstream_commit: String,
    pub raw_sha256: String,
}

impl OkfSpecPinV2 {
    pub fn new(
        version: impl Into<String>,
        upstream_commit: impl Into<String>,
        raw_sha256: impl Into<String>,
    ) -> Result<Self, OkfSpecPinErrorV2> {
        let pin = Self {
            version: version.into(),
            upstream_commit: upstream_commit.into(),
            raw_sha256: raw_sha256.into(),
        };
        pin.validate()?;
        Ok(pin)
    }

    pub fn validate(&self) -> Result<(), OkfSpecPinErrorV2> {
        if self.version.trim().is_empty() || self.upstream_commit.trim().is_empty() {
            return Err(OkfSpecPinErrorV2::Incomplete);
        }
        if !is_sha256(&self.raw_sha256) {
            return Err(OkfSpecPinErrorV2::InvalidRawDigest);
        }
        Ok(())
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum OkfSpecPinErrorV2 {
    #[error("OKF v2 pin has an empty version or upstream commit")]
    Incomplete,
    #[error("OKF v2 pin raw_sha256 must be a lowercase sha256 digest")]
    InvalidRawDigest,
}

impl OkfSpecPinErrorV2 {
    pub const fn code(&self) -> &'static str {
        "E_V2_OKF_PIN_INVALID"
    }
}

/// One conformance outcome. A passed outcome only applies to the axis that
/// emitted it; it never compensates for another axis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OkfAxisStatusV2 {
    Passed,
    Failed,
    Blocked,
    NotRun,
    Stale,
    Invalid,
    CannotConfirm,
}

impl OkfAxisStatusV2 {
    pub const fn is_passed(self) -> bool {
        matches!(self, Self::Passed)
    }
}

/// Internal OKF is one of the four conformance axes, but it has two required
/// sub-verdicts. Both consumer and producer must pass independently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OkfInternalVerdictV2 {
    pub consumer: OkfAxisStatusV2,
    pub producer: OkfAxisStatusV2,
}

impl OkfInternalVerdictV2 {
    pub const fn new(consumer: OkfAxisStatusV2, producer: OkfAxisStatusV2) -> Self {
        Self { consumer, producer }
    }

    /// Reduction is deliberately a conjunction, never a score. The order
    /// makes terminal negative outcomes more informative than merely not-run.
    pub const fn status(self) -> OkfAxisStatusV2 {
        use OkfAxisStatusV2::{Blocked, CannotConfirm, Failed, Invalid, NotRun, Passed, Stale};
        if self.consumer.is_passed() && self.producer.is_passed() {
            Passed
        } else if matches!(self.consumer, Failed) || matches!(self.producer, Failed) {
            Failed
        } else if matches!(self.consumer, Invalid) || matches!(self.producer, Invalid) {
            Invalid
        } else if matches!(self.consumer, Blocked) || matches!(self.producer, Blocked) {
            Blocked
        } else if matches!(self.consumer, CannotConfirm) || matches!(self.producer, CannotConfirm) {
            CannotConfirm
        } else if matches!(self.consumer, Stale) || matches!(self.producer, Stale) {
            Stale
        } else {
            NotRun
        }
    }
}

/// The complete V0.2 OKF conformance state. `current_official_format` and
/// `reference_compatibility` remain distinct from local/internal evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OkfFourAxisVerdictV2 {
    pub pin: OkfSpecPinV2,
    pub internal: OkfInternalVerdictV2,
    pub current_official_format: OkfAxisStatusV2,
    pub reference_compatibility: OkfAxisStatusV2,
    pub curated_profile: OkfAxisStatusV2,
}

impl OkfFourAxisVerdictV2 {
    pub fn new(
        pin: OkfSpecPinV2,
        internal: OkfInternalVerdictV2,
        current_official_format: OkfAxisStatusV2,
        reference_compatibility: OkfAxisStatusV2,
        curated_profile: OkfAxisStatusV2,
    ) -> Self {
        Self {
            pin,
            internal,
            current_official_format,
            reference_compatibility,
            curated_profile,
        }
    }

    pub const fn all_axes_passed(&self) -> bool {
        self.internal.status().is_passed()
            && self.current_official_format.is_passed()
            && self.reference_compatibility.is_passed()
            && self.curated_profile.is_passed()
    }

    pub fn blocking_axis_ids(&self) -> Vec<&'static str> {
        let mut axes = Vec::new();
        if !self.internal.status().is_passed() {
            axes.push("internal");
        }
        if !self.current_official_format.is_passed() {
            axes.push("current_official_format");
        }
        if !self.reference_compatibility.is_passed() {
            axes.push("reference_compatibility");
        }
        if !self.curated_profile.is_passed() {
            axes.push("curated_profile");
        }
        axes
    }
}

/// A minimal, canonical input to the V0.2 coverage denominator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CoverageProfileV1 {
    pub schema_version: String,
    pub profile_id: String,
    pub profile_kind: ProfileKind,
    pub path_roles: BTreeMap<String, Vec<String>>,
    pub required_formats: Vec<String>,
    pub required_languages: Vec<String>,
    pub capability_matrix: BTreeMap<String, CapabilityState>,
    pub tool_locks: BTreeMap<String, String>,
    pub graph_relation_types: Vec<String>,
    pub claim_grounding_policy_sha256: String,
    pub okf_spec: OkfSpecPinV1,
    pub budgets: BTreeMap<String, u64>,
    pub corpus_refs: BTreeMap<String, String>,
    pub required_gate_ids: Vec<String>,
    pub profile_sha256: String,
}

impl CoverageProfileV1 {
    pub fn new<I, S>(
        schema_version: impl Into<String>,
        profile_id: impl Into<String>,
        required_gate_ids: I,
        tool_lock_sha256: impl Into<String>,
    ) -> Result<Self, ProfileError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let schema_version = schema_version.into();
        let profile_id = profile_id.into();
        let tool_lock_sha256 = tool_lock_sha256.into();
        let mut required_gate_ids: Vec<String> =
            required_gate_ids.into_iter().map(Into::into).collect();
        required_gate_ids.sort();
        if schema_version != "gtkg.coverage-profile/v1" {
            return Err(ProfileError::UnsupportedSchema(schema_version));
        }
        if profile_id.trim().is_empty() {
            return Err(ProfileError::EmptyProfileId);
        }
        if required_gate_ids.is_empty() || required_gate_ids.iter().any(|id| id.trim().is_empty()) {
            return Err(ProfileError::EmptyRequiredGateSet);
        }
        if required_gate_ids.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(ProfileError::DuplicateRequiredGate);
        }
        if !is_sha256(&tool_lock_sha256) {
            return Err(ProfileError::InvalidToolLockDigest);
        }
        let mut path_roles = BTreeMap::new();
        path_roles.insert("test_input".to_owned(), vec!["fixtures/**".to_owned()]);
        let mut capability_matrix = BTreeMap::new();
        for gate_id in &required_gate_ids {
            capability_matrix.insert(gate_id.clone(), CapabilityState::Supported);
        }
        let mut tool_locks = BTreeMap::new();
        tool_locks.insert("core".to_owned(), tool_lock_sha256.clone());
        let mut budgets = BTreeMap::new();
        budgets.insert("context_tokens".to_owned(), 1);
        let mut corpus_refs = BTreeMap::new();
        corpus_refs.insert("test_corpus".to_owned(), tool_lock_sha256.clone());
        let mut profile = Self {
            schema_version,
            profile_id,
            profile_kind: ProfileKind::Custom,
            path_roles,
            required_formats: vec!["test".to_owned()],
            required_languages: vec!["test".to_owned()],
            capability_matrix,
            tool_locks,
            graph_relation_types: vec!["test_relation".to_owned()],
            claim_grounding_policy_sha256: tool_lock_sha256.clone(),
            okf_spec: OkfSpecPinV1 {
                version: "test".to_owned(),
                upstream_commit: "test".to_owned(),
                raw_sha256: tool_lock_sha256.clone(),
            },
            budgets,
            corpus_refs,
            required_gate_ids,
            profile_sha256: String::new(),
        };
        profile.profile_sha256 = canonical_profile_digest(&profile);
        profile.validate()?;
        Ok(profile)
    }

    /// Build the only product-certified V0.2 profile. All volatile identities
    /// are caller-supplied and are part of the profile digest.
    pub fn canonical_core(
        tool_locks: BTreeMap<String, String>,
        budgets: BTreeMap<String, u64>,
        corpus_refs: BTreeMap<String, String>,
        claim_grounding_policy_sha256: impl Into<String>,
        okf_spec: OkfSpecPinV1,
    ) -> Result<Self, ProfileError> {
        let path_roles = canonical_core_path_roles();
        let mut capability_matrix = BTreeMap::new();
        for capability in CORE_CAPABILITIES {
            capability_matrix.insert((*capability).to_owned(), CapabilityState::Supported);
        }
        let mut profile = Self {
            schema_version: "gtkg.coverage-profile/v1".to_owned(),
            profile_id: CORE_PROFILE_ID.to_owned(),
            profile_kind: ProfileKind::ProductCertifiedCore,
            path_roles,
            required_formats: CORE_FORMATS.iter().map(|item| (*item).to_owned()).collect(),
            required_languages: CORE_LANGUAGES
                .iter()
                .map(|item| (*item).to_owned())
                .collect(),
            capability_matrix,
            tool_locks,
            graph_relation_types: CORE_RELATIONS
                .iter()
                .map(|item| (*item).to_owned())
                .collect(),
            claim_grounding_policy_sha256: claim_grounding_policy_sha256.into(),
            okf_spec,
            budgets,
            corpus_refs,
            required_gate_ids: CORE_GATES.iter().map(|item| (*item).to_owned()).collect(),
            profile_sha256: String::new(),
        };
        profile.profile_sha256 = canonical_profile_digest(&profile);
        profile.validate()?;
        Ok(profile)
    }

    /// `true` is only possible for the immutable product core profile; custom
    /// profiles may only claim `comprehensive_for_profile:<profile_id>`.
    pub fn is_product_certified_core(&self) -> bool {
        self.profile_kind == ProfileKind::ProductCertifiedCore && self.profile_id == CORE_PROFILE_ID
    }

    pub fn validate(&self) -> Result<(), ProfileError> {
        if self.schema_version != "gtkg.coverage-profile/v1" {
            return Err(ProfileError::UnsupportedSchema(self.schema_version.clone()));
        }
        if self.profile_id.trim().is_empty()
            || self.path_roles.is_empty()
            || self.required_formats.is_empty()
            || self.required_languages.is_empty()
            || self.capability_matrix.is_empty()
            || self.tool_locks.is_empty()
            || self.graph_relation_types.is_empty()
            || self.budgets.is_empty()
            || self.corpus_refs.is_empty()
        {
            return Err(ProfileError::IncompleteProfileContract);
        }
        if self.required_gate_ids.is_empty()
            || self.required_gate_ids.iter().any(|id| id.trim().is_empty())
            || self
                .required_gate_ids
                .windows(2)
                .any(|pair| pair[0] == pair[1])
        {
            return Err(ProfileError::EmptyRequiredGateSet);
        }
        if self
            .tool_locks
            .values()
            .chain(self.corpus_refs.values())
            .any(|digest| !is_sha256(digest))
            || !is_sha256(&self.claim_grounding_policy_sha256)
            || !is_sha256(&self.okf_spec.raw_sha256)
        {
            return Err(ProfileError::InvalidToolLockDigest);
        }
        if self.okf_spec.version.trim().is_empty()
            || self.okf_spec.upstream_commit.trim().is_empty()
        {
            return Err(ProfileError::InvalidOkfPin);
        }
        if self.profile_kind == ProfileKind::ProductCertifiedCore
            && (self.profile_id != CORE_PROFILE_ID
                || !exact_string_set(&self.required_formats, CORE_FORMATS)
                || !exact_string_set(&self.required_languages, CORE_LANGUAGES)
                || !exact_string_set(&self.required_gate_ids, CORE_GATES)
                || self.path_roles != canonical_core_path_roles()
                || !exact_map_keys(&self.capability_matrix, CORE_CAPABILITIES)
                || !exact_map_keys(&self.tool_locks, CORE_TOOL_LOCKS)
                || !exact_string_set(&self.graph_relation_types, CORE_RELATIONS)
                || self
                    .capability_matrix
                    .values()
                    .any(|state| !matches!(state, CapabilityState::Supported)))
        {
            return Err(ProfileError::IncompleteCertifiedCore);
        }
        if self.profile_sha256 != canonical_profile_digest(self) {
            return Err(ProfileError::ProfileDigestMismatch);
        }
        Ok(())
    }
}

/// One observed gate result.  `profile_sha256` binds it to the exact profile
/// and tool lock used for the observation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct HardGateResultV1 {
    pub gate_id: String,
    pub required: bool,
    pub denominator: u64,
    pub numerator: u64,
    pub status: GateStatus,
    pub capability_state: CapabilityState,
    pub profile_sha256: Option<String>,
}

impl HardGateResultV1 {
    pub fn required(
        gate_id: impl Into<String>,
        denominator: u64,
        numerator: u64,
        status: GateStatus,
        capability_state: CapabilityState,
    ) -> Self {
        Self {
            gate_id: gate_id.into(),
            required: true,
            denominator,
            numerator,
            status,
            capability_state,
            profile_sha256: None,
        }
    }

    pub fn with_profile_digest(mut self, profile_sha256: impl Into<String>) -> Self {
        self.profile_sha256 = Some(profile_sha256.into());
        self
    }
}

/// The only allowed reduction for the `comprehensive_for_profile` predicate.
#[derive(Debug, Clone)]
pub struct HardGateReducer<'a> {
    profile: &'a CoverageProfileV1,
}

impl<'a> HardGateReducer<'a> {
    pub const fn new(profile: &'a CoverageProfileV1) -> Self {
        Self { profile }
    }

    pub fn reduce(&self, results: &[HardGateResultV1]) -> Result<HardGateOutcome, HardGateError> {
        self.profile.validate()?;
        let required_ids: BTreeSet<&str> = self
            .profile
            .required_gate_ids
            .iter()
            .map(String::as_str)
            .collect();
        let mut seen = BTreeSet::new();
        let mut blocking_gate_ids = Vec::new();
        let mut stale_gate_ids = Vec::new();
        let mut scored_denominator = 0_u64;
        let mut scored_numerator = 0_u64;

        for result in results {
            if result.gate_id.trim().is_empty() {
                return Err(HardGateError::EmptyGateId);
            }
            if !seen.insert(result.gate_id.as_str()) {
                return Err(HardGateError::DuplicateGate(result.gate_id.clone()));
            }
            if result.numerator > result.denominator {
                return Err(HardGateError::NumeratorExceedsDenominator(
                    result.gate_id.clone(),
                ));
            }
            let profile_required = required_ids.contains(result.gate_id.as_str());
            if result.required != profile_required {
                return Err(HardGateError::RequirednessMismatch(result.gate_id.clone()));
            }
            if result.required && result.denominator == 0 {
                return Err(HardGateError::RequiredGateEmptyDenominator(
                    result.gate_id.clone(),
                ));
            }

            let profile_mismatch =
                result.profile_sha256.as_deref() != Some(self.profile.profile_sha256.as_str());
            let effective_status = if profile_mismatch {
                GateStatus::Stale
            } else {
                result.status
            };

            if matches!(effective_status, GateStatus::Passed) {
                scored_denominator += result.denominator;
                scored_numerator += result.numerator;
            }
            if result.required
                && (!matches!(effective_status, GateStatus::Passed)
                    || !matches!(result.capability_state, CapabilityState::Supported))
            {
                blocking_gate_ids.push(result.gate_id.clone());
            }
            if matches!(effective_status, GateStatus::Stale) {
                stale_gate_ids.push(result.gate_id.clone());
            }
        }

        for required_gate_id in &self.profile.required_gate_ids {
            if !seen.contains(required_gate_id.as_str()) {
                blocking_gate_ids.push(required_gate_id.clone());
            }
        }

        blocking_gate_ids.sort();
        stale_gate_ids.sort();
        let weighted_score = scored_numerator
            .saturating_mul(100)
            .checked_div(scored_denominator)
            .map_or(0, |score| score as u8);
        Ok(HardGateOutcome {
            comprehensive_for_profile: blocking_gate_ids.is_empty(),
            product_certified_profile: self.profile.is_product_certified_core(),
            blocking_gate_ids,
            stale_gate_ids,
            weighted_score,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct HardGateOutcome {
    pub comprehensive_for_profile: bool,
    pub product_certified_profile: bool,
    pub blocking_gate_ids: Vec<String>,
    pub stale_gate_ids: Vec<String>,
    /// Informative only; never an input to completeness.
    pub weighted_score: u8,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProfileError {
    #[error("unsupported coverage profile schema: {0}")]
    UnsupportedSchema(String),
    #[error("profile_id must not be empty")]
    EmptyProfileId,
    #[error("required gate set must be non-empty and contain non-empty ids")]
    EmptyRequiredGateSet,
    #[error("required gate ids must be unique")]
    DuplicateRequiredGate,
    #[error("tool lock must be a sha256 digest")]
    InvalidToolLockDigest,
    #[error("profile contract is missing a required frozen field")]
    IncompleteProfileContract,
    #[error("OKF pin is incomplete")]
    InvalidOkfPin,
    #[error("product-certified core profile is incomplete")]
    IncompleteCertifiedCore,
    #[error("profile digest does not match canonical content")]
    ProfileDigestMismatch,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum HardGateError {
    #[error("invalid coverage profile: {0}")]
    InvalidProfile(#[from] ProfileError),
    #[error("gate_id must not be empty")]
    EmptyGateId,
    #[error("duplicate hard gate result: {0}")]
    DuplicateGate(String),
    #[error("gate numerator exceeds denominator: {0}")]
    NumeratorExceedsDenominator(String),
    #[error("result requiredness differs from the profile: {0}")]
    RequirednessMismatch(String),
    #[error("required hard gate has an empty denominator: {0}")]
    RequiredGateEmptyDenominator(String),
}

impl HardGateError {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidProfile(_) => "E_V2_PROFILE_INVALID",
            Self::RequiredGateEmptyDenominator(_) => "E_V2_REQUIRED_GATE_EMPTY_DENOMINATOR",
            Self::EmptyGateId => "E_V2_GATE_ID_EMPTY",
            Self::DuplicateGate(_) => "E_V2_GATE_DUPLICATE",
            Self::NumeratorExceedsDenominator(_) => "E_V2_GATE_NUMERATOR_EXCEEDS_DENOMINATOR",
            Self::RequirednessMismatch(_) => "E_V2_GATE_REQUIREDNESS_MISMATCH",
        }
    }
}

fn is_sha256(value: &str) -> bool {
    value.len() == SHA256_PREFIX.len() + 64
        && value.starts_with(SHA256_PREFIX)
        && value[SHA256_PREFIX.len()..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn canonical_profile_digest(profile: &CoverageProfileV1) -> String {
    let mut hasher = Sha256::new();
    hash_field(
        &mut hasher,
        "schema_version",
        profile.schema_version.as_bytes(),
    );
    hash_field(&mut hasher, "profile_id", profile.profile_id.as_bytes());
    hash_field(
        &mut hasher,
        "profile_kind",
        match profile.profile_kind {
            ProfileKind::ProductCertifiedCore => b"product_certified_core",
            ProfileKind::Custom => b"custom",
        },
    );
    hash_field(
        &mut hasher,
        "claim_grounding_policy_sha256",
        profile.claim_grounding_policy_sha256.as_bytes(),
    );
    hash_field(
        &mut hasher,
        "okf.version",
        profile.okf_spec.version.as_bytes(),
    );
    hash_field(
        &mut hasher,
        "okf.upstream_commit",
        profile.okf_spec.upstream_commit.as_bytes(),
    );
    hash_field(
        &mut hasher,
        "okf.raw_sha256",
        profile.okf_spec.raw_sha256.as_bytes(),
    );
    hash_field(
        &mut hasher,
        "path_roles.count",
        &(profile.path_roles.len() as u64).to_be_bytes(),
    );
    for (role, paths) in &profile.path_roles {
        hash_field(&mut hasher, "path_role.name", role.as_bytes());
        hash_field(
            &mut hasher,
            "path_role.paths.count",
            &(paths.len() as u64).to_be_bytes(),
        );
        for path in paths {
            hash_field(&mut hasher, "path_role.path", path.as_bytes());
        }
    }
    for (label, values) in [
        ("required_formats", &profile.required_formats),
        ("required_languages", &profile.required_languages),
        ("graph_relation_types", &profile.graph_relation_types),
        ("required_gate_ids", &profile.required_gate_ids),
    ] {
        hash_field(
            &mut hasher,
            &format!("{label}.count"),
            &(values.len() as u64).to_be_bytes(),
        );
        for value in values {
            hash_field(&mut hasher, label, value.as_bytes());
        }
    }
    for (key, value) in &profile.capability_matrix {
        hash_field(&mut hasher, "capability.name", key.as_bytes());
        hash_field(
            &mut hasher,
            "capability.state",
            format!("{value:?}").as_bytes(),
        );
    }
    for (label, values) in [
        ("tool_lock", &profile.tool_locks),
        ("corpus_ref", &profile.corpus_refs),
    ] {
        hash_field(
            &mut hasher,
            &format!("{label}.count"),
            &(values.len() as u64).to_be_bytes(),
        );
        for (key, value) in values {
            hash_field(&mut hasher, &format!("{label}.name"), key.as_bytes());
            hash_field(&mut hasher, &format!("{label}.value"), value.as_bytes());
        }
    }
    for (key, value) in &profile.budgets {
        hash_field(&mut hasher, "budget.name", key.as_bytes());
        hash_field(&mut hasher, "budget.value", &value.to_be_bytes());
    }
    format!("sha256:{:x}", hasher.finalize())
}

fn exact_string_set(values: &[String], expected: &[&str]) -> bool {
    values.len() == expected.len()
        && expected
            .iter()
            .all(|item| values.iter().any(|value| value == item))
}

fn exact_map_keys<T>(values: &BTreeMap<String, T>, expected: &[&str]) -> bool {
    values.len() == expected.len() && expected.iter().all(|item| values.contains_key(*item))
}

fn canonical_core_path_roles() -> BTreeMap<String, Vec<String>> {
    BTreeMap::from([
        ("code".to_owned(), vec!["**/*.rs".to_owned()]),
        (
            "config".to_owned(),
            vec!["**/*.{json,yaml,toml}".to_owned()],
        ),
        (
            "document".to_owned(),
            vec!["**/*.{md,pdf,docx,xlsx,pptx}".to_owned()],
        ),
        ("web".to_owned(), vec!["**/*.{html,css,svg,sh}".to_owned()]),
    ])
}

fn hash_field(hasher: &mut Sha256, label: &str, value: &[u8]) {
    hasher.update((label.len() as u64).to_be_bytes());
    hasher.update(label.as_bytes());
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

/// The V0.2 source-capture modes.  They are deliberately separate from the
/// frozen V1 `source.inspect` transport operation; T08 owns that projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SourceCaptureModeV2 {
    GitCommit,
    WorktreeExact,
    DirectoryExact,
    SuppliedManifest,
}

/// Eligibility is not a release approval.  In particular, a byte-exact dirty
/// worktree can be useful Development input while never being a release-source
/// candidate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SourceEligibilityV2 {
    pub development_eligible: bool,
    pub source_release_candidate: bool,
    pub environment_ready: bool,
    pub release_ready: bool,
}

impl SourceCaptureModeV2 {
    pub const fn default_eligibility(self) -> SourceEligibilityV2 {
        match self {
            Self::GitCommit => SourceEligibilityV2 {
                development_eligible: true,
                source_release_candidate: true,
                environment_ready: false,
                release_ready: false,
            },
            Self::WorktreeExact | Self::DirectoryExact | Self::SuppliedManifest => {
                SourceEligibilityV2 {
                    development_eligible: true,
                    source_release_candidate: false,
                    environment_ready: false,
                    release_ready: false,
                }
            }
        }
    }
}

/// One admitted regular file.  `logical_path` is always relative to the
/// declared source root; symlinks and special files are never represented here.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SourceSnapshotEntryV2 {
    pub logical_path: String,
    pub content_sha256: String,
    pub bytes: u64,
}

/// A visible, reasoned exclusion.  Omission entries participate in the
/// denominator so an excluded path can never disappear silently.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SourceSnapshotOmissionV2 {
    pub logical_path: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SourceSnapshotDenominatorV2 {
    pub discovered_entries: u64,
    pub admitted_entries: u64,
    pub omitted_entries: u64,
}

impl SourceSnapshotDenominatorV2 {
    pub const fn is_closed(&self) -> bool {
        self.discovered_entries == self.admitted_entries + self.omitted_entries
    }
}

/// The baseline observed before and after a capture.  The fields intentionally
/// remain strings so the source layer can bind Git or directory identities
/// without changing the V1 protocol object registry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SourceBaselineIdentityV2 {
    pub kind: String,
    pub head: Option<String>,
    pub tree: Option<String>,
    pub status_sha256: String,
}

/// Internal typed result of the first T01 capture slice.  Later T01 slices
/// may add mode-specific manifests but must preserve this exact accounting
/// contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SourceSnapshotV2 {
    pub schema_version: String,
    pub capture_mode: SourceCaptureModeV2,
    pub repository_id: String,
    pub baseline: SourceBaselineIdentityV2,
    pub inventory: Vec<SourceSnapshotEntryV2>,
    pub omissions: Vec<SourceSnapshotOmissionV2>,
    pub denominator: SourceSnapshotDenominatorV2,
    pub exact_set_sha256: String,
    pub eligibility: SourceEligibilityV2,
}

impl SourceSnapshotV2 {
    /// Recompute the exact-set identity with the same canonical object shape
    /// used by the source-capture boundary.  The denominator and eligibility
    /// are independently validated and therefore are not digest substitutes.
    pub fn with_exact_set_digest(mut self) -> Result<Self, SourceSnapshotValidationErrorV2> {
        self.exact_set_sha256 = canonical_snapshot_exact_set_digest(&self)?;
        Ok(self)
    }

    /// Validate the complete source admission contract before a downstream
    /// stage consumes a single inventory entry.  This deliberately catches
    /// same-length content substitution as well as accounting/digest drift.
    pub fn validate(&self) -> Result<(), SourceSnapshotValidationErrorV2> {
        if self.schema_version != "gtkg.source-snapshot/v2" {
            return Err(SourceSnapshotValidationErrorV2::UnsupportedSchema);
        }
        if self.repository_id.trim().is_empty()
            || self.baseline.kind.trim().is_empty()
            || !is_sha256(&self.baseline.status_sha256)
            || !is_sha256(&self.exact_set_sha256)
            || self
                .baseline
                .head
                .as_deref()
                .is_some_and(|value| value.trim().is_empty())
            || self
                .baseline
                .tree
                .as_deref()
                .is_some_and(|value| value.trim().is_empty())
        {
            return Err(SourceSnapshotValidationErrorV2::InvalidIdentity);
        }
        if self.eligibility != self.capture_mode.default_eligibility() {
            return Err(SourceSnapshotValidationErrorV2::InvalidEligibility);
        }
        if !self.denominator.is_closed()
            || self.denominator.admitted_entries != self.inventory.len() as u64
            || self.denominator.omitted_entries != self.omissions.len() as u64
            || self.denominator.discovered_entries
                != (self.inventory.len() + self.omissions.len()) as u64
        {
            return Err(SourceSnapshotValidationErrorV2::InvalidDenominator);
        }

        let mut admitted_paths = BTreeSet::new();
        let mut previous = None;
        for entry in &self.inventory {
            if !valid_snapshot_logical_path(&entry.logical_path)
                || !is_sha256(&entry.content_sha256)
            {
                return Err(SourceSnapshotValidationErrorV2::InvalidInventory);
            }
            if previous.is_some_and(|path: &str| path >= entry.logical_path.as_str())
                || !admitted_paths.insert(entry.logical_path.as_str())
            {
                return Err(SourceSnapshotValidationErrorV2::InvalidInventory);
            }
            previous = Some(entry.logical_path.as_str());
        }
        let mut previous = None;
        for omission in &self.omissions {
            if !valid_snapshot_logical_path(&omission.logical_path)
                || omission.reason.trim().is_empty()
                || admitted_paths.contains(omission.logical_path.as_str())
            {
                return Err(SourceSnapshotValidationErrorV2::InvalidOmission);
            }
            if previous.is_some_and(|path: &str| path >= omission.logical_path.as_str()) {
                return Err(SourceSnapshotValidationErrorV2::InvalidOmission);
            }
            previous = Some(omission.logical_path.as_str());
        }
        if self.exact_set_sha256 != canonical_snapshot_exact_set_digest(self)? {
            return Err(SourceSnapshotValidationErrorV2::ExactSetDigestMismatch);
        }
        Ok(())
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SourceSnapshotValidationErrorV2 {
    #[error("source snapshot schema is unsupported")]
    UnsupportedSchema,
    #[error("source snapshot identity is invalid")]
    InvalidIdentity,
    #[error("source snapshot eligibility is inconsistent with its capture mode")]
    InvalidEligibility,
    #[error("source snapshot denominator is invalid")]
    InvalidDenominator,
    #[error("source snapshot inventory is invalid")]
    InvalidInventory,
    #[error("source snapshot omission set is invalid")]
    InvalidOmission,
    #[error("source snapshot exact-set digest is stale or invalid")]
    ExactSetDigestMismatch,
    #[error("source snapshot exact-set digest could not be canonicalized")]
    Canonicalization,
}

#[derive(Serialize)]
struct SnapshotExactSet<'a> {
    baseline: &'a SourceBaselineIdentityV2,
    inventory: &'a [SourceSnapshotEntryV2],
    omissions: &'a [SourceSnapshotOmissionV2],
}

fn canonical_snapshot_exact_set_digest(
    snapshot: &SourceSnapshotV2,
) -> Result<String, SourceSnapshotValidationErrorV2> {
    crate::canonical_json_sha256(&SnapshotExactSet {
        baseline: &snapshot.baseline,
        inventory: &snapshot.inventory,
        omissions: &snapshot.omissions,
    })
    .map_err(|_| SourceSnapshotValidationErrorV2::Canonicalization)
}

fn valid_snapshot_logical_path(value: &str) -> bool {
    !value.is_empty()
        && Path::new(value)
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

/// T04 corpus categories.  A local fixture is a contract input only; it is
/// deliberately distinct from an independently pinned external corpus.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CorpusManifestKindV2 {
    Fixture,
    ExternalHoldout,
    Adversarial,
    Scale,
    Security,
}

impl CorpusManifestKindV2 {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fixture => "fixture",
            Self::ExternalHoldout => "external_holdout",
            Self::Adversarial => "adversarial",
            Self::Scale => "scale",
            Self::Security => "security",
        }
    }
}

/// Origin is part of the signed corpus identity.  It is never inferred from a
/// filesystem location, filename, or a successful local test.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CorpusOriginV2 {
    Fixture,
    Synthetic,
    ExternalRepository,
}

/// One exact source pin.  `revision` cannot be a moving selector such as
/// `latest`, `current`, or `HEAD`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CorpusSourcePinV2 {
    pub origin: CorpusOriginV2,
    pub source_id: String,
    pub revision: String,
    pub content_sha256: String,
    pub license_id: String,
}

/// One item in a split.  Both the stable item identifier and its content
/// digest participate in the anti-overfit boundary.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CorpusItemV2 {
    pub item_id: String,
    pub content_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CorpusSplitV2 {
    pub calibration: Vec<CorpusItemV2>,
    pub evaluation: Vec<CorpusItemV2>,
    pub holdout: Vec<CorpusItemV2>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CorpusAnnotationStateV2 {
    FixtureOnly,
    Planned,
    Frozen,
}

/// Frozen annotation provenance.  Fixture-only annotation is explicitly not
/// human adjudication and therefore cannot support an external semantic gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CorpusAnnotationV2 {
    pub state: CorpusAnnotationStateV2,
    pub annotator_ids: Vec<String>,
    pub adjudicator_id: Option<String>,
    pub guideline_sha256: String,
    pub expected_results_sha256: String,
}

/// Host identity is a frozen measurement precondition, not a performance
/// receipt.  Performance remains blocked until a measured workload is run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BenchmarkHostIdentityV2 {
    pub host_id: String,
    pub os_family: String,
    pub architecture: String,
    pub cpu_model: String,
    pub logical_cores: u32,
    pub memory_bytes: u64,
    pub toolchain_sha256: String,
    pub workload_sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CorpusReadinessStatusV2 {
    Ready,
    Blocked,
    NotRun,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CorpusReadinessV2 {
    pub status: CorpusReadinessStatusV2,
    pub blocker_code: Option<String>,
    pub pass_count: u64,
}

impl CorpusReadinessV2 {
    /// Only an explicit ready state can be a pass.  `blocked` is a useful
    /// state disclosure, never a zero-denominator pass.
    pub const fn counts_as_pass(&self) -> bool {
        matches!(self.status, CorpusReadinessStatusV2::Ready) && self.pass_count > 0
    }
}

/// Canonical, exact-set T04 corpus freeze manifest.  It freezes preconditions
/// and split boundaries; it does not claim that an external corpus, provider,
/// host benchmark, or 10k result has been executed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CorpusManifestV2 {
    pub schema_version: String,
    pub manifest_id: String,
    pub revision: String,
    pub kind: CorpusManifestKindV2,
    pub source: CorpusSourcePinV2,
    pub split: CorpusSplitV2,
    pub annotation: CorpusAnnotationV2,
    pub host: BenchmarkHostIdentityV2,
    pub readiness: CorpusReadinessV2,
    pub manifest_sha256: String,
}

impl CorpusManifestV2 {
    pub fn with_manifest_digest(mut self) -> Result<Self, CorpusManifestValidationErrorV2> {
        self.manifest_sha256 = canonical_corpus_manifest_digest(&self)?;
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), CorpusManifestValidationErrorV2> {
        if self.schema_version != "gtkg.corpus-manifest/v2"
            || !valid_corpus_identifier(&self.manifest_id)
            || !valid_locked_revision(&self.revision)
        {
            return Err(CorpusManifestValidationErrorV2::InvalidManifest);
        }
        validate_corpus_source(&self.source)?;
        validate_corpus_split(&self.split)?;
        validate_corpus_annotation(&self.source.origin, &self.annotation)?;
        validate_benchmark_host(&self.host)?;
        validate_corpus_readiness(&self.readiness)?;
        if !is_sha256(&self.manifest_sha256)
            || self.manifest_sha256 != canonical_corpus_manifest_digest(self)?
        {
            return Err(CorpusManifestValidationErrorV2::ManifestDigestMismatch);
        }
        Ok(())
    }

    /// This is intentionally false for fixture/synthetic manifests even if a
    /// caller later changes their local readiness state.  Only an externally
    /// pinned, ready corpus may contribute to an external gate denominator.
    pub const fn counts_toward_external_gate(&self) -> bool {
        matches!(self.source.origin, CorpusOriginV2::ExternalRepository)
            && self.readiness.counts_as_pass()
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CorpusManifestValidationErrorV2 {
    #[error("E_V2_CORPUS_MANIFEST_INVALID")]
    InvalidManifest,
    #[error("E_V2_CORPUS_SOURCE_UNPINNED")]
    SourceUnpinned,
    #[error("E_V2_CORPUS_SPLIT_INVALID")]
    SplitInvalid,
    #[error("E_V2_CORPUS_SPLIT_OVERLAP")]
    SplitOverlap,
    #[error("E_V2_CORPUS_ANNOTATION_INVALID")]
    AnnotationInvalid,
    #[error("E_V2_CORPUS_HOST_INVALID")]
    HostInvalid,
    #[error("E_V2_CORPUS_READINESS_INVALID")]
    ReadinessInvalid,
    #[error("E_V2_CORPUS_MANIFEST_DIGEST_MISMATCH")]
    ManifestDigestMismatch,
    #[error("E_V2_CORPUS_CANONICALIZATION")]
    Canonicalization,
}

impl CorpusManifestValidationErrorV2 {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidManifest => "E_V2_CORPUS_MANIFEST_INVALID",
            Self::SourceUnpinned => "E_V2_CORPUS_SOURCE_UNPINNED",
            Self::SplitInvalid => "E_V2_CORPUS_SPLIT_INVALID",
            Self::SplitOverlap => "E_V2_CORPUS_SPLIT_OVERLAP",
            Self::AnnotationInvalid => "E_V2_CORPUS_ANNOTATION_INVALID",
            Self::HostInvalid => "E_V2_CORPUS_HOST_INVALID",
            Self::ReadinessInvalid => "E_V2_CORPUS_READINESS_INVALID",
            Self::ManifestDigestMismatch => "E_V2_CORPUS_MANIFEST_DIGEST_MISMATCH",
            Self::Canonicalization => "E_V2_CORPUS_CANONICALIZATION",
        }
    }
}

fn validate_corpus_source(
    source: &CorpusSourcePinV2,
) -> Result<(), CorpusManifestValidationErrorV2> {
    if !valid_corpus_identifier(&source.source_id)
        || !valid_locked_revision(&source.revision)
        || !is_sha256(&source.content_sha256)
        || source.license_id.trim().is_empty()
    {
        return Err(CorpusManifestValidationErrorV2::SourceUnpinned);
    }
    Ok(())
}

fn validate_corpus_split(split: &CorpusSplitV2) -> Result<(), CorpusManifestValidationErrorV2> {
    if split.evaluation.is_empty() || split.holdout.is_empty() {
        return Err(CorpusManifestValidationErrorV2::SplitInvalid);
    }
    let mut item_ids = BTreeSet::new();
    let mut digests = BTreeSet::new();
    for item in split
        .calibration
        .iter()
        .chain(&split.evaluation)
        .chain(&split.holdout)
    {
        if !valid_corpus_identifier(&item.item_id) || !is_sha256(&item.content_sha256) {
            return Err(CorpusManifestValidationErrorV2::SplitInvalid);
        }
        if !item_ids.insert(item.item_id.as_str()) || !digests.insert(item.content_sha256.as_str())
        {
            return Err(CorpusManifestValidationErrorV2::SplitOverlap);
        }
    }
    Ok(())
}

fn validate_corpus_annotation(
    origin: &CorpusOriginV2,
    annotation: &CorpusAnnotationV2,
) -> Result<(), CorpusManifestValidationErrorV2> {
    if !is_sha256(&annotation.guideline_sha256) || !is_sha256(&annotation.expected_results_sha256) {
        return Err(CorpusManifestValidationErrorV2::AnnotationInvalid);
    }
    let annotations_are_unique = !annotation.annotator_ids.is_empty()
        && annotation
            .annotator_ids
            .iter()
            .all(|id| valid_corpus_identifier(id))
        && annotation
            .annotator_ids
            .iter()
            .collect::<BTreeSet<_>>()
            .len()
            == annotation.annotator_ids.len();
    if !annotations_are_unique {
        return Err(CorpusManifestValidationErrorV2::AnnotationInvalid);
    }
    match (origin, annotation.state) {
        (
            CorpusOriginV2::Fixture | CorpusOriginV2::Synthetic,
            CorpusAnnotationStateV2::FixtureOnly,
        ) => {
            if annotation.adjudicator_id.is_some() {
                return Err(CorpusManifestValidationErrorV2::AnnotationInvalid);
            }
        }
        (CorpusOriginV2::ExternalRepository, CorpusAnnotationStateV2::Frozen) => {
            if annotation.annotator_ids.len() < 2
                || annotation
                    .adjudicator_id
                    .as_deref()
                    .is_none_or(|id| !valid_corpus_identifier(id))
            {
                return Err(CorpusManifestValidationErrorV2::AnnotationInvalid);
            }
        }
        _ => return Err(CorpusManifestValidationErrorV2::AnnotationInvalid),
    }
    Ok(())
}

fn validate_benchmark_host(
    host: &BenchmarkHostIdentityV2,
) -> Result<(), CorpusManifestValidationErrorV2> {
    if !valid_corpus_identifier(&host.host_id)
        || host.os_family.trim().is_empty()
        || host.architecture.trim().is_empty()
        || host.cpu_model.trim().is_empty()
        || host.logical_cores == 0
        || host.memory_bytes == 0
        || !is_sha256(&host.toolchain_sha256)
        || !is_sha256(&host.workload_sha256)
    {
        return Err(CorpusManifestValidationErrorV2::HostInvalid);
    }
    Ok(())
}

fn validate_corpus_readiness(
    readiness: &CorpusReadinessV2,
) -> Result<(), CorpusManifestValidationErrorV2> {
    match readiness.status {
        CorpusReadinessStatusV2::Ready
            if readiness.blocker_code.is_none() && readiness.pass_count > 0 =>
        {
            Ok(())
        }
        CorpusReadinessStatusV2::Blocked | CorpusReadinessStatusV2::NotRun
            if readiness.pass_count == 0
                && readiness
                    .blocker_code
                    .as_deref()
                    .is_some_and(|code| !code.trim().is_empty()) =>
        {
            Ok(())
        }
        _ => Err(CorpusManifestValidationErrorV2::ReadinessInvalid),
    }
}

fn valid_corpus_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn valid_locked_revision(value: &str) -> bool {
    !value.is_empty()
        && !matches!(value, "HEAD" | "latest" | "current")
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'/'))
}

#[derive(Serialize)]
struct CorpusManifestDigest<'a> {
    schema_version: &'a str,
    manifest_id: &'a str,
    revision: &'a str,
    kind: CorpusManifestKindV2,
    source: &'a CorpusSourcePinV2,
    split: &'a CorpusSplitV2,
    annotation: &'a CorpusAnnotationV2,
    host: &'a BenchmarkHostIdentityV2,
    readiness: &'a CorpusReadinessV2,
}

fn canonical_corpus_manifest_digest(
    manifest: &CorpusManifestV2,
) -> Result<String, CorpusManifestValidationErrorV2> {
    crate::canonical_json_sha256(&CorpusManifestDigest {
        schema_version: &manifest.schema_version,
        manifest_id: &manifest.manifest_id,
        revision: &manifest.revision,
        kind: manifest.kind,
        source: &manifest.source,
        split: &manifest.split,
        annotation: &manifest.annotation,
        host: &manifest.host,
        readiness: &manifest.readiness,
    })
    .map_err(|_| CorpusManifestValidationErrorV2::Canonicalization)
}

/// The only two modes admitted by the T02 Typed IR boundary.  Lexical
/// observations are useful diagnostics, but never become semantic nodes or
/// edges when syntax parsing has failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TypedIrModeV2 {
    AstSemantic,
    FallbackLexical,
}

/// Resolver ownership begins in T05.  T02 preserves the raw reference and
/// explicitly refuses to guess a resolved target.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum IrResolutionStateV2 {
    Resolved,
    Unresolved,
    Ambiguous,
    NotApplicable,
}

/// Byte-exact, source-digest-pinned evidence for a typed fact.  The source is
/// intentionally a logical path plus an admitted blob digest, never a host
/// filesystem path.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvidenceSpanV2 {
    pub id: String,
    pub source_snapshot_exact_set_sha256: String,
    pub source_logical_path: String,
    pub source_sha256: String,
    pub byte_start: u64,
    pub byte_end: u64,
    pub line_start: u64,
    pub line_end: u64,
    pub snippet_sha256: String,
    pub evidence_level: String,
}

impl EvidenceSpanV2 {
    /// Validate the evidence against the exact admitted source bytes.  This is
    /// deliberately byte based: callers must not attempt a lossy Unicode or
    /// line-oriented readback.
    pub fn validate_for_source(
        &self,
        expected_logical_path: &str,
        source_bytes: &[u8],
    ) -> Result<(), TypedIrError> {
        if self.source_logical_path != expected_logical_path {
            return Err(TypedIrError::EvidenceLogicalPathMismatch);
        }
        if !is_sha256(&self.source_sha256)
            || !is_sha256(&self.snippet_sha256)
            || !is_sha256(&self.source_snapshot_exact_set_sha256)
        {
            return Err(TypedIrError::InvalidDigest);
        }
        if self.source_sha256 != digest_sha256(source_bytes) {
            return Err(TypedIrError::EvidenceSourceDigestMismatch);
        }
        let start = usize::try_from(self.byte_start).map_err(|_| TypedIrError::InvalidByteSpan)?;
        let end = usize::try_from(self.byte_end).map_err(|_| TypedIrError::InvalidByteSpan)?;
        let Some(snippet) = source_bytes.get(start..end) else {
            return Err(TypedIrError::InvalidByteSpan);
        };
        if snippet.is_empty() || self.snippet_sha256 != digest_sha256(snippet) {
            return Err(TypedIrError::EvidenceSnippetDigestMismatch);
        }
        let expected_start = line_for_byte(source_bytes, start) as u64;
        let expected_end = line_for_byte(source_bytes, end.saturating_sub(1)) as u64;
        if self.line_start != expected_start || self.line_end != expected_end {
            return Err(TypedIrError::EvidenceLineMismatch);
        }
        Ok(())
    }
}

/// A typed semantic fact.  `scope_id` may reference a synthetic module scope,
/// but `evidence_ids` must always point at byte-verifiable evidence above.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IrNodeV2 {
    pub id: String,
    pub kind: String,
    pub name: String,
    pub scope_id: String,
    pub evidence_ids: Vec<String>,
}

/// A structural relation whose destination stays explicitly unresolved until a
/// language-aware resolver has supplied evidence (T05).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IrEdgeV2 {
    pub id: String,
    pub kind: String,
    pub source_node_id: Option<String>,
    pub target_reference: String,
    pub candidate_node_ids: Vec<String>,
    pub resolved_node_id: Option<String>,
    pub resolution: IrResolutionStateV2,
    pub evidence_ids: Vec<String>,
}

/// The first transport-neutral Typed IR slice.  It binds every semantic fact
/// to one T01 exact-set snapshot but deliberately excludes resolver, type,
/// CFG, def-use and state-flow claims not yet implemented.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TypedIrV2 {
    pub schema_version: String,
    pub source_snapshot_exact_set_sha256: String,
    pub source_logical_path: String,
    pub source_sha256: String,
    /// Exact static extractor identity.  It is digest-bound so a resolver
    /// cannot reinterpret Rust facts as another language from a renamed path.
    pub extractor_id: String,
    pub mode: TypedIrModeV2,
    pub capabilities: BTreeMap<String, CapabilityState>,
    pub evidence: Vec<EvidenceSpanV2>,
    pub nodes: Vec<IrNodeV2>,
    pub edges: Vec<IrEdgeV2>,
    pub typed_ir_sha256: String,
}

impl TypedIrV2 {
    /// Validate the self-contained IR and then read every evidence reference
    /// back from the exact source bytes.
    pub fn validate_for_source(&self, source_bytes: &[u8]) -> Result<(), TypedIrError> {
        if self.schema_version != "gtkg.typed-ir/v2" {
            return Err(TypedIrError::UnsupportedSchema);
        }
        if !extractor_matches_logical_path(&self.extractor_id, &self.source_logical_path) {
            return Err(TypedIrError::ExtractorIdentityMismatch);
        }
        if !is_sha256(&self.source_snapshot_exact_set_sha256)
            || !is_sha256(&self.source_sha256)
            || !is_sha256(&self.typed_ir_sha256)
        {
            return Err(TypedIrError::InvalidDigest);
        }
        if self.source_sha256 != digest_sha256(source_bytes) {
            return Err(TypedIrError::TypedIrSourceDigestMismatch);
        }
        if self.typed_ir_sha256 != canonical_typed_ir_digest(self) {
            return Err(TypedIrError::TypedIrDigestMismatch);
        }
        if self.mode == TypedIrModeV2::FallbackLexical
            && (!self.evidence.is_empty() || !self.nodes.is_empty() || !self.edges.is_empty())
        {
            return Err(TypedIrError::FallbackContainsSemanticFacts);
        }

        let evidence_ids = sorted_unique_ids(self.evidence.iter().map(|item| item.id.as_str()))?;
        let node_ids = sorted_unique_ids(self.nodes.iter().map(|item| item.id.as_str()))?;
        let _edge_ids = sorted_unique_ids(self.edges.iter().map(|item| item.id.as_str()))?;
        for item in &self.evidence {
            if item.source_snapshot_exact_set_sha256 != self.source_snapshot_exact_set_sha256 {
                return Err(TypedIrError::EvidenceSnapshotMismatch);
            }
            item.validate_for_source(&self.source_logical_path, source_bytes)?;
        }
        for node in &self.nodes {
            if node.evidence_ids.is_empty()
                || node
                    .evidence_ids
                    .iter()
                    .any(|id| !evidence_ids.contains(id.as_str()))
            {
                return Err(TypedIrError::DanglingEvidenceReference);
            }
        }
        for edge in &self.edges {
            if edge.evidence_ids.is_empty()
                || edge
                    .evidence_ids
                    .iter()
                    .any(|id| !evidence_ids.contains(id.as_str()))
                || edge
                    .source_node_id
                    .as_deref()
                    .is_some_and(|id| !node_ids.contains(id))
            {
                return Err(TypedIrError::DanglingEvidenceReference);
            }
            match edge.resolution {
                IrResolutionStateV2::Resolved => {
                    let Some(target) = edge.resolved_node_id.as_deref() else {
                        return Err(TypedIrError::InvalidResolutionState);
                    };
                    if !node_ids.contains(target) || !edge.candidate_node_ids.is_empty() {
                        return Err(TypedIrError::InvalidResolutionState);
                    }
                }
                IrResolutionStateV2::Unresolved => {
                    if edge.resolved_node_id.is_some() || !edge.candidate_node_ids.is_empty() {
                        return Err(TypedIrError::InvalidResolutionState);
                    }
                }
                IrResolutionStateV2::Ambiguous => {
                    if edge.resolved_node_id.is_some() || edge.candidate_node_ids.len() < 2 {
                        return Err(TypedIrError::InvalidResolutionState);
                    }
                }
                IrResolutionStateV2::NotApplicable => {}
            }
        }
        Ok(())
    }

    pub fn with_digest(mut self) -> Self {
        self.typed_ir_sha256 = canonical_typed_ir_digest(&self);
        self
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TypedIrError {
    #[error("typed IR source is not admitted by the bound source snapshot")]
    SourceNotAdmitted,
    #[error("extracted source text does not match its declared source digest")]
    ExtractedSourceDigestMismatch,
    #[error("bound source snapshot fails complete admission validation")]
    SourceSnapshotInvalid,
    #[error("typed IR source snapshot denominator is not closed")]
    SourceSnapshotNotClosed,
    #[error("typed IR uses an unsupported schema")]
    UnsupportedSchema,
    #[error("typed IR contains an invalid SHA-256 digest")]
    InvalidDigest,
    #[error("evidence logical path differs from the typed IR source")]
    EvidenceLogicalPathMismatch,
    #[error("evidence source digest does not match source bytes")]
    EvidenceSourceDigestMismatch,
    #[error("evidence byte span is invalid")]
    InvalidByteSpan,
    #[error("evidence snippet digest does not match selected bytes")]
    EvidenceSnippetDigestMismatch,
    #[error("evidence line locator does not match selected bytes")]
    EvidenceLineMismatch,
    #[error("typed IR source digest does not match source bytes")]
    TypedIrSourceDigestMismatch,
    #[error("typed IR digest does not match canonical content")]
    TypedIrDigestMismatch,
    #[error("typed IR extractor identity does not match its logical source path")]
    ExtractorIdentityMismatch,
    #[error("fallback lexical mode contains semantic facts")]
    FallbackContainsSemanticFacts,
    #[error("typed IR IDs must be sorted, unique, and non-empty")]
    InvalidStableIdSet,
    #[error("typed IR references missing evidence or source node")]
    DanglingEvidenceReference,
    #[error("evidence has a different source snapshot binding")]
    EvidenceSnapshotMismatch,
    #[error("edge resolution state is internally inconsistent")]
    InvalidResolutionState,
}

impl TypedIrError {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::SourceNotAdmitted => "E_V2_IR_SOURCE_NOT_ADMITTED",
            Self::ExtractedSourceDigestMismatch => "E_V2_IR_EXTRACTED_SOURCE_DIGEST_MISMATCH",
            Self::SourceSnapshotInvalid => "E_V2_IR_SOURCE_SNAPSHOT_INVALID",
            Self::SourceSnapshotNotClosed => "E_V2_IR_SNAPSHOT_NOT_CLOSED",
            Self::UnsupportedSchema => "E_V2_IR_SCHEMA_UNSUPPORTED",
            Self::InvalidDigest => "E_V2_IR_DIGEST_INVALID",
            Self::EvidenceLogicalPathMismatch => "E_V2_IR_EVIDENCE_PATH_MISMATCH",
            Self::EvidenceSourceDigestMismatch => "E_V2_IR_EVIDENCE_SOURCE_DIGEST_MISMATCH",
            Self::InvalidByteSpan => "E_V2_IR_EVIDENCE_SPAN_INVALID",
            Self::EvidenceSnippetDigestMismatch => "E_V2_IR_EVIDENCE_SNIPPET_DIGEST_MISMATCH",
            Self::EvidenceLineMismatch => "E_V2_IR_EVIDENCE_LINE_MISMATCH",
            Self::TypedIrSourceDigestMismatch => "E_V2_IR_SOURCE_DIGEST_MISMATCH",
            Self::TypedIrDigestMismatch => "E_V2_IR_DIGEST_MISMATCH",
            Self::ExtractorIdentityMismatch => "E_V2_IR_EXTRACTOR_IDENTITY_MISMATCH",
            Self::FallbackContainsSemanticFacts => "E_V2_IR_FALLBACK_HAS_SEMANTIC_FACTS",
            Self::InvalidStableIdSet => "E_V2_IR_ID_SET_INVALID",
            Self::DanglingEvidenceReference => "E_V2_IR_DANGLING_REFERENCE",
            Self::EvidenceSnapshotMismatch => "E_V2_IR_EVIDENCE_SNAPSHOT_MISMATCH",
            Self::InvalidResolutionState => "E_V2_IR_RESOLUTION_INVALID",
        }
    }
}

fn sorted_unique_ids<'a>(
    ids: impl Iterator<Item = &'a str>,
) -> Result<BTreeSet<&'a str>, TypedIrError> {
    let items = ids.collect::<Vec<_>>();
    if items.iter().any(|id| id.is_empty()) || items.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(TypedIrError::InvalidStableIdSet);
    }
    Ok(items.into_iter().collect())
}

fn line_for_byte(source_bytes: &[u8], byte_offset: usize) -> usize {
    source_bytes[..byte_offset]
        .iter()
        .filter(|byte| **byte == b'\n')
        .count()
        + 1
}

fn digest_sha256(value: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(value))
}

fn extractor_matches_logical_path(extractor_id: &str, logical_path: &str) -> bool {
    let extension = std::path::Path::new(logical_path)
        .extension()
        .and_then(|value| value.to_str())
        .map(str::to_ascii_lowercase);
    matches!(
        (extractor_id, extension.as_deref()),
        ("gtkg-code-static-rust/v1", Some("rs"))
            | ("gtkg-code-static-python/v1", Some("py"))
            | ("gtkg-code-static-ts/v1", Some("ts" | "tsx"))
            | ("gtkg-code-static-js/v1", Some("js" | "jsx"))
    )
}

fn canonical_typed_ir_digest(ir: &TypedIrV2) -> String {
    let mut hasher = Sha256::new();
    hash_field(&mut hasher, "schema_version", ir.schema_version.as_bytes());
    hash_field(
        &mut hasher,
        "source_snapshot_exact_set_sha256",
        ir.source_snapshot_exact_set_sha256.as_bytes(),
    );
    hash_field(
        &mut hasher,
        "source_logical_path",
        ir.source_logical_path.as_bytes(),
    );
    hash_field(&mut hasher, "source_sha256", ir.source_sha256.as_bytes());
    hash_field(&mut hasher, "extractor_id", ir.extractor_id.as_bytes());
    hash_field(
        &mut hasher,
        "mode",
        match ir.mode {
            TypedIrModeV2::AstSemantic => b"ast_semantic",
            TypedIrModeV2::FallbackLexical => b"fallback_lexical",
        },
    );
    hash_field(
        &mut hasher,
        "capabilities.count",
        &(ir.capabilities.len() as u64).to_be_bytes(),
    );
    for (name, state) in &ir.capabilities {
        hash_field(&mut hasher, "capability.name", name.as_bytes());
        hash_field(
            &mut hasher,
            "capability.state",
            capability_state_name(*state),
        );
    }
    hash_field(
        &mut hasher,
        "evidence.count",
        &(ir.evidence.len() as u64).to_be_bytes(),
    );
    for evidence in &ir.evidence {
        hash_string_fields(
            &mut hasher,
            "evidence",
            &[
                &evidence.id,
                &evidence.source_snapshot_exact_set_sha256,
                &evidence.source_logical_path,
                &evidence.source_sha256,
                &evidence.byte_start.to_string(),
                &evidence.byte_end.to_string(),
                &evidence.line_start.to_string(),
                &evidence.line_end.to_string(),
                &evidence.snippet_sha256,
                &evidence.evidence_level,
            ],
        );
    }
    hash_field(
        &mut hasher,
        "nodes.count",
        &(ir.nodes.len() as u64).to_be_bytes(),
    );
    for node in &ir.nodes {
        hash_string_fields(
            &mut hasher,
            "node",
            &[&node.id, &node.kind, &node.name, &node.scope_id],
        );
        hash_string_list(&mut hasher, "node.evidence_ids", &node.evidence_ids);
    }
    hash_field(
        &mut hasher,
        "edges.count",
        &(ir.edges.len() as u64).to_be_bytes(),
    );
    for edge in &ir.edges {
        hash_string_fields(
            &mut hasher,
            "edge",
            &[
                &edge.id,
                &edge.kind,
                edge.source_node_id.as_deref().unwrap_or(""),
                &edge.target_reference,
                edge.resolved_node_id.as_deref().unwrap_or(""),
                resolution_state_name(edge.resolution),
            ],
        );
        hash_string_list(
            &mut hasher,
            "edge.candidate_node_ids",
            &edge.candidate_node_ids,
        );
        hash_string_list(&mut hasher, "edge.evidence_ids", &edge.evidence_ids);
    }
    format!("sha256:{:x}", hasher.finalize())
}

fn hash_string_fields(hasher: &mut Sha256, label: &str, fields: &[&str]) {
    hash_field(
        hasher,
        &format!("{label}.count"),
        &(fields.len() as u64).to_be_bytes(),
    );
    for field in fields {
        hash_field(hasher, label, field.as_bytes());
    }
}

fn hash_string_list(hasher: &mut Sha256, label: &str, fields: &[String]) {
    hash_field(
        hasher,
        &format!("{label}.count"),
        &(fields.len() as u64).to_be_bytes(),
    );
    for field in fields {
        hash_field(hasher, label, field.as_bytes());
    }
}

const fn capability_state_name(value: CapabilityState) -> &'static [u8] {
    match value {
        CapabilityState::Supported => b"supported",
        CapabilityState::Partial => b"partial",
        CapabilityState::Unsupported => b"unsupported",
        CapabilityState::NotApplicable => b"not_applicable",
    }
}

const fn resolution_state_name(value: IrResolutionStateV2) -> &'static str {
    match value {
        IrResolutionStateV2::Resolved => "resolved",
        IrResolutionStateV2::Unresolved => "unresolved",
        IrResolutionStateV2::Ambiguous => "ambiguous",
        IrResolutionStateV2::NotApplicable => "not_applicable",
    }
}
