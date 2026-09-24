//! V0.3 architecture identities layered over the frozen v2 operation set.
//!
//! D03 freezes ownership and identity contracts only. It deliberately mirrors
//! current v2 availability/callability and does not claim new handler behavior.

pub mod adapter;
pub mod profiles;
pub mod query;

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::SideEffectClass;
use crate::v2::{
    CallabilityV2, OperationAvailabilityV2, V2_PUBLIC_OPERATIONS, V2OperationId,
    v2_operation_request_schema,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HandlerPartitionV03 {
    SystemConfig,
    SourceAnalysis,
    ContextSummary,
    Run,
    BundleMigration,
    Snapshot,
    GitCurrent,
    NodeFederation,
    Template,
    Deliverable,
    Graph,
    A2ui,
}

impl HandlerPartitionV03 {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SystemConfig => "system_config",
            Self::SourceAnalysis => "source_analysis",
            Self::ContextSummary => "context_summary",
            Self::Run => "run",
            Self::BundleMigration => "bundle_migration",
            Self::Snapshot => "snapshot",
            Self::GitCurrent => "git_current",
            Self::NodeFederation => "node_federation",
            Self::Template => "template",
            Self::Deliverable => "deliverable",
            Self::Graph => "graph",
            Self::A2ui => "a2ui",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationBindingV2 {
    pub operation_id: V2OperationId,
    pub handler_id: String,
    pub schema_sha256: String,
    pub effect: SideEffectClass,
    pub availability: OperationAvailabilityV2,
    pub callability: CallabilityV2,
    pub partition: HandlerPartitionV03,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandlerPartitionContractV03 {
    pub partition: HandlerPartitionV03,
    pub operation_ids: &'static [&'static str],
}

const SYSTEM_CONFIG_OPERATIONS: &[&str] =
    &["system.describe", "config.validate", "capability.describe"];
const SOURCE_ANALYSIS_OPERATIONS: &[&str] = &[
    "source.capture",
    "analysis.plan",
    "analysis.build",
    "analysis.verify",
    "build.finalize.v2",
];
const CONTEXT_SUMMARY_OPERATIONS: &[&str] = &[
    "context.pack",
    "summary.job.next",
    "summary.proposal.submit",
    "summary.verification.next",
    "summary.verification.submit",
    "summary.accept.v2",
];
const RUN_OPERATIONS: &[&str] = &["run.get", "run.cancel"];
const BUNDLE_MIGRATION_OPERATIONS: &[&str] =
    &["bundle.verify", "bundle.compare", "bundle.migrate.v1_to_v2"];
const SNAPSHOT_OPERATIONS: &[&str] = &["snapshot.create", "snapshot.verify", "snapshot.restore"];
const GIT_CURRENT_OPERATIONS: &[&str] = &["git.publish", "current.get", "current.activate"];
const NODE_FEDERATION_OPERATIONS: &[&str] = &["node.describe", "federation.validate"];
const TEMPLATE_OPERATIONS: &[&str] = &[
    "template.list",
    "template.resolve",
    "template.prefetch",
    "template.get",
    "template.validate",
    "template.derive",
    "template.publish",
];
const DELIVERABLE_OPERATIONS: &[&str] = &["deliverable.derive", "deliverable.publish"];
const GRAPH_OPERATIONS: &[&str] = &[
    "graph.neighbors",
    "graph.path",
    "graph.impact",
    "graph.explain",
    "graph.trace",
    "graph.search",
];
const A2UI_OPERATIONS: &[&str] = &["a2ui.resolve", "a2ui.generate", "a2ui.get", "a2ui.validate"];

const HANDLER_PARTITIONS: &[HandlerPartitionContractV03] = &[
    HandlerPartitionContractV03 {
        partition: HandlerPartitionV03::SystemConfig,
        operation_ids: SYSTEM_CONFIG_OPERATIONS,
    },
    HandlerPartitionContractV03 {
        partition: HandlerPartitionV03::SourceAnalysis,
        operation_ids: SOURCE_ANALYSIS_OPERATIONS,
    },
    HandlerPartitionContractV03 {
        partition: HandlerPartitionV03::ContextSummary,
        operation_ids: CONTEXT_SUMMARY_OPERATIONS,
    },
    HandlerPartitionContractV03 {
        partition: HandlerPartitionV03::Run,
        operation_ids: RUN_OPERATIONS,
    },
    HandlerPartitionContractV03 {
        partition: HandlerPartitionV03::BundleMigration,
        operation_ids: BUNDLE_MIGRATION_OPERATIONS,
    },
    HandlerPartitionContractV03 {
        partition: HandlerPartitionV03::Snapshot,
        operation_ids: SNAPSHOT_OPERATIONS,
    },
    HandlerPartitionContractV03 {
        partition: HandlerPartitionV03::GitCurrent,
        operation_ids: GIT_CURRENT_OPERATIONS,
    },
    HandlerPartitionContractV03 {
        partition: HandlerPartitionV03::NodeFederation,
        operation_ids: NODE_FEDERATION_OPERATIONS,
    },
    HandlerPartitionContractV03 {
        partition: HandlerPartitionV03::Template,
        operation_ids: TEMPLATE_OPERATIONS,
    },
    HandlerPartitionContractV03 {
        partition: HandlerPartitionV03::Deliverable,
        operation_ids: DELIVERABLE_OPERATIONS,
    },
    HandlerPartitionContractV03 {
        partition: HandlerPartitionV03::Graph,
        operation_ids: GRAPH_OPERATIONS,
    },
    HandlerPartitionContractV03 {
        partition: HandlerPartitionV03::A2ui,
        operation_ids: A2UI_OPERATIONS,
    },
];

pub const fn handler_partitions_v03() -> &'static [HandlerPartitionContractV03] {
    HANDLER_PARTITIONS
}

fn partition_for(operation_id: V2OperationId) -> HandlerPartitionV03 {
    let operation = operation_id.as_str();
    HANDLER_PARTITIONS
        .iter()
        .find(|partition| partition.operation_ids.contains(&operation))
        .map_or(HandlerPartitionV03::SystemConfig, |value| value.partition)
}

fn schema_sha256(operation_id: V2OperationId) -> String {
    let schema = v2_operation_request_schema(operation_id);
    let bytes = serde_json::to_vec(&schema).unwrap_or_default();
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

pub fn operation_bindings_v03() -> Vec<OperationBindingV2> {
    V2_PUBLIC_OPERATIONS
        .iter()
        .map(|definition| {
            let partition = partition_for(definition.id);
            OperationBindingV2 {
                operation_id: definition.id,
                handler_id: format!("gtkg.v03.{}.{}", partition.as_str(), definition.id.as_str()),
                schema_sha256: schema_sha256(definition.id),
                effect: definition.side_effect,
                availability: definition.availability,
                callability: definition.callability,
                partition,
            }
        })
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DiscoveryProfileIdV1 {
    Core,
    Graph,
    Authoring,
    Lifecycle,
    Templates,
    A2ui,
    All,
}

impl DiscoveryProfileIdV1 {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Core => "core",
            Self::Graph => "graph",
            Self::Authoring => "authoring",
            Self::Lifecycle => "lifecycle",
            Self::Templates => "templates",
            Self::A2ui => "a2ui",
            Self::All => "all",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryProfileV1 {
    pub profile_id: DiscoveryProfileIdV1,
    pub operation_ids: Vec<V2OperationId>,
    pub is_default: bool,
    pub digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscoveryProfileErrorV03 {
    Empty,
    DuplicateOperation,
    DigestMismatch,
}

impl DiscoveryProfileV1 {
    pub fn validate(&self) -> Result<(), DiscoveryProfileErrorV03> {
        if self.operation_ids.is_empty() {
            return Err(DiscoveryProfileErrorV03::Empty);
        }
        if self
            .operation_ids
            .iter()
            .copied()
            .collect::<BTreeSet<_>>()
            .len()
            != self.operation_ids.len()
        {
            return Err(DiscoveryProfileErrorV03::DuplicateOperation);
        }
        if self.digest != profile_digest(self.profile_id, self.is_default, &self.operation_ids) {
            return Err(DiscoveryProfileErrorV03::DigestMismatch);
        }
        Ok(())
    }
}

const CORE_PROFILE_OPERATIONS: &[&str] = &[
    "system.describe",
    "config.validate",
    "capability.describe",
    "source.capture",
    "analysis.plan",
    "analysis.build",
    "analysis.verify",
    "build.finalize.v2",
    "context.pack",
    "graph.search",
];
const AUTHORING_PROFILE_OPERATIONS: &[&str] = &[
    "context.pack",
    "summary.job.next",
    "summary.proposal.submit",
    "summary.verification.next",
    "summary.verification.submit",
    "summary.accept.v2",
    "analysis.verify",
    "build.finalize.v2",
];
const LIFECYCLE_PROFILE_OPERATIONS: &[&str] = &[
    "run.get",
    "run.cancel",
    "bundle.verify",
    "bundle.compare",
    "bundle.migrate.v1_to_v2",
    "snapshot.create",
    "snapshot.verify",
    "snapshot.restore",
    "git.publish",
    "current.get",
    "current.activate",
    "node.describe",
    "federation.validate",
];

pub const DISCOVERY_PROFILE_DIGESTS_V1: &[(DiscoveryProfileIdV1, &str)] = &[
    (
        DiscoveryProfileIdV1::Core,
        "sha256:50263880d66cc5aa09ff9e2e3cf85956ad9dcea09a0f0925609f25bcac5f31a8",
    ),
    (
        DiscoveryProfileIdV1::Graph,
        "sha256:86777e15e4f84ec49c94af68b83ce1910b85b42c6a66dfb61f69f40db878cd38",
    ),
    (
        DiscoveryProfileIdV1::Authoring,
        "sha256:0a4ab7a650741b60d905baa747acd4f30c5d13da9ed61a9eb7e87fe654bffd75",
    ),
    (
        DiscoveryProfileIdV1::Lifecycle,
        "sha256:1f8d7e6b63639aaa31b5eadf27875157ee03ecf6e2bba8b06fdae3551be10895",
    ),
    (
        DiscoveryProfileIdV1::Templates,
        "sha256:dbd30e464b48599be2bd67f4922aabec68c3d7462d148c91b29b8746c3ec3b4a",
    ),
    (
        DiscoveryProfileIdV1::A2ui,
        "sha256:a9b24b739ce003567af3eb0629d51484f191be98d5c3fb8379fa8076ae0f0cac",
    ),
    (
        DiscoveryProfileIdV1::All,
        "sha256:5c718c85bcc4e65a3862ec591138e52506884200fffe9923f78ea6f3cd12826f",
    ),
];

fn operations_from_ids(ids: &[&str]) -> Vec<V2OperationId> {
    ids.iter()
        .filter_map(|operation_id| V2OperationId::parse(operation_id))
        .collect()
}

fn profile_digest(
    profile_id: DiscoveryProfileIdV1,
    is_default: bool,
    operation_ids: &[V2OperationId],
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"gtkg.discovery-profile/v1\0");
    hasher.update(profile_id.as_str().as_bytes());
    hasher.update([u8::from(is_default)]);
    for operation_id in operation_ids {
        hasher.update([0]);
        hasher.update(operation_id.as_str().as_bytes());
    }
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

fn profile(
    profile_id: DiscoveryProfileIdV1,
    operation_ids: Vec<V2OperationId>,
    is_default: bool,
) -> DiscoveryProfileV1 {
    let digest = profile_digest(profile_id, is_default, &operation_ids);
    DiscoveryProfileV1 {
        profile_id,
        operation_ids,
        is_default,
        digest,
    }
}

pub fn discovery_profiles_v03() -> Vec<DiscoveryProfileV1> {
    vec![
        profile(
            DiscoveryProfileIdV1::Core,
            operations_from_ids(CORE_PROFILE_OPERATIONS),
            true,
        ),
        profile(
            DiscoveryProfileIdV1::Graph,
            operations_from_ids(GRAPH_OPERATIONS),
            false,
        ),
        profile(
            DiscoveryProfileIdV1::Authoring,
            operations_from_ids(AUTHORING_PROFILE_OPERATIONS),
            false,
        ),
        profile(
            DiscoveryProfileIdV1::Lifecycle,
            operations_from_ids(LIFECYCLE_PROFILE_OPERATIONS),
            false,
        ),
        profile(
            DiscoveryProfileIdV1::Templates,
            operations_from_ids(&[
                "template.list",
                "template.resolve",
                "template.prefetch",
                "template.get",
                "template.validate",
                "template.derive",
                "template.publish",
                "deliverable.derive",
                "deliverable.publish",
            ]),
            false,
        ),
        profile(
            DiscoveryProfileIdV1::A2ui,
            operations_from_ids(A2UI_OPERATIONS),
            false,
        ),
        profile(
            DiscoveryProfileIdV1::All,
            V2_PUBLIC_OPERATIONS
                .iter()
                .map(|definition| definition.id)
                .collect(),
            false,
        ),
    ]
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdapterKindV1 {
    Native,
    Scip,
    LspSnapshot,
    CodeGraphExport,
    GraphifyExport,
}

impl AdapterKindV1 {
    pub const ALL: [Self; 5] = [
        Self::Native,
        Self::Scip,
        Self::LspSnapshot,
        Self::CodeGraphExport,
        Self::GraphifyExport,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::Scip => "scip",
            Self::LspSnapshot => "lsp_snapshot",
            Self::CodeGraphExport => "codegraph_export",
            Self::GraphifyExport => "graphify_export",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManifestIdentityContractV03 {
    pub schema_id: &'static str,
    pub required_identity_fields: &'static [&'static str],
    pub drift_code: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdapterManifestIdentityContractV03 {
    pub kind: AdapterKindV1,
    pub required_identity_fields: &'static [&'static str],
    pub drift_code: &'static str,
}

const ADAPTER_FIELDS: &[&str] = &[
    "adapter_id",
    "adapter_version",
    "schema_sha256",
    "source_commit",
    "license",
    "capabilities",
    "trust_policy_id",
];
const ADAPTER_IDENTITIES: &[AdapterManifestIdentityContractV03] = &[
    AdapterManifestIdentityContractV03 {
        kind: AdapterKindV1::Native,
        required_identity_fields: ADAPTER_FIELDS,
        drift_code: "E_ADAPTER_IDENTITY_MISMATCH",
    },
    AdapterManifestIdentityContractV03 {
        kind: AdapterKindV1::Scip,
        required_identity_fields: ADAPTER_FIELDS,
        drift_code: "E_ADAPTER_IDENTITY_MISMATCH",
    },
    AdapterManifestIdentityContractV03 {
        kind: AdapterKindV1::LspSnapshot,
        required_identity_fields: ADAPTER_FIELDS,
        drift_code: "E_ADAPTER_IDENTITY_MISMATCH",
    },
    AdapterManifestIdentityContractV03 {
        kind: AdapterKindV1::CodeGraphExport,
        required_identity_fields: ADAPTER_FIELDS,
        drift_code: "E_ADAPTER_IDENTITY_MISMATCH",
    },
    AdapterManifestIdentityContractV03 {
        kind: AdapterKindV1::GraphifyExport,
        required_identity_fields: ADAPTER_FIELDS,
        drift_code: "E_ADAPTER_IDENTITY_MISMATCH",
    },
];

pub const fn adapter_manifest_identity_contracts_v03()
-> &'static [AdapterManifestIdentityContractV03] {
    ADAPTER_IDENTITIES
}

pub const ADAPTER_DESCRIPTOR_IDENTITY_V1: ManifestIdentityContractV03 =
    ManifestIdentityContractV03 {
        schema_id: "gtkg.adapter-descriptor/v1",
        required_identity_fields: ADAPTER_FIELDS,
        drift_code: "E_ADAPTER_IDENTITY_MISMATCH",
    };
pub const EXTERNAL_FACT_BUNDLE_IDENTITY_V1: ManifestIdentityContractV03 =
    ManifestIdentityContractV03 {
        schema_id: "gtkg.external-fact-bundle/v1",
        required_identity_fields: &[
            "source_snapshot_sha256",
            "adapter_descriptor_sha256",
            "nodes",
            "edges",
            "evidence",
            "candidate_states",
            "discovered_count",
            "admitted_count",
            "omitted_count",
            "bundle_sha256",
        ],
        drift_code: "E_ADAPTER_IDENTITY_MISMATCH",
    };
pub const VERIFIED_FACT_RECEIPT_IDENTITY_V1: ManifestIdentityContractV03 =
    ManifestIdentityContractV03 {
        schema_id: "gtkg.verified-fact-receipt/v1",
        required_identity_fields: &[
            "source_replay_sha256",
            "source_span",
            "source_bytes_sha256",
            "resolution",
            "reason",
            "verifier_identity",
        ],
        drift_code: "E_EXTERNAL_EVIDENCE_UNVERIFIED",
    };

pub const QUERY_INDEX_MANIFEST_IDENTITY_V1: ManifestIdentityContractV03 =
    ManifestIdentityContractV03 {
        schema_id: "gtkg.query-index-manifest/v1",
        required_identity_fields: &[
            "source_identity",
            "graph_identity",
            "overlay_identity",
            "tokenizer_id",
            "shards",
            "digests",
            "budgets",
        ],
        drift_code: "E_QUERY_INDEX_STALE",
    };
pub const LEXICAL_SHARD_IDENTITY_V1: ManifestIdentityContractV03 = ManifestIdentityContractV03 {
    schema_id: "gtkg.lexical-shard/v1",
    required_identity_fields: &[
        "unicode_version",
        "normalized_terms",
        "trigrams",
        "fst_sha256",
        "postings",
        "evidence_refs",
    ],
    drift_code: "E_QUERY_INDEX_STALE",
};
pub const ADJACENCY_SHARD_IDENTITY_V1: ManifestIdentityContractV03 = ManifestIdentityContractV03 {
    schema_id: "gtkg.adjacency-shard/v1",
    required_identity_fields: &[
        "node_bucket",
        "direction",
        "edge_ids",
        "resolution_states",
        "raw_bytes_sha256",
    ],
    drift_code: "E_QUERY_INDEX_STALE",
};
pub const QUERY_PLAN_RECEIPT_IDENTITY_V1: ManifestIdentityContractV03 =
    ManifestIdentityContractV03 {
        schema_id: "gtkg.query-plan-receipt/v1",
        required_identity_fields: &[
            "query_sha256",
            "index_manifest_sha256",
            "selected_shards",
            "excluded_shards",
            "bytes_read",
            "latency_ms",
            "budget",
            "truncation",
            "continuation",
        ],
        drift_code: "E_QUERY_INDEX_STALE",
    };
pub const INSTALL_MANIFEST_IDENTITY_V1: ManifestIdentityContractV03 = ManifestIdentityContractV03 {
    schema_id: "gtkg.install-manifest/v1",
    required_identity_fields: &[
        "version",
        "platform",
        "files",
        "modes",
        "digests",
        "destinations",
    ],
    drift_code: "E_INSTALL_IDENTITY_MISMATCH",
};
pub const ASSISTANT_INSTALL_RECEIPT_IDENTITY_V1: ManifestIdentityContractV03 =
    ManifestIdentityContractV03 {
        schema_id: "gtkg.assistant-install-receipt/v1",
        required_identity_fields: &[
            "assistant",
            "platform",
            "scope",
            "target_file",
            "before_sha256",
            "after_sha256",
            "managed_block_sha256",
        ],
        drift_code: "E_INSTALL_CAS_CONFLICT",
    };

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FailureModeContractV03 {
    pub failure_id: &'static str,
    pub code: &'static str,
    pub required_behavior: &'static str,
}

const FAILURE_MODES: &[FailureModeContractV03] = &[
    FailureModeContractV03 {
        failure_id: "FM-301",
        code: "E_DEAD_TOOL_EXPOSED",
        required_behavior: "reject profile discovery while any selected operation is not implemented",
    },
    FailureModeContractV03 {
        failure_id: "FM-302",
        code: "E_PROFILE_STALE",
        required_behavior: "reject digest drift and require an explicit profile revision",
    },
    FailureModeContractV03 {
        failure_id: "FM-303",
        code: "E_ADAPTER_IDENTITY_MISMATCH",
        required_behavior: "reject schema, source commit, or license drift",
    },
    FailureModeContractV03 {
        failure_id: "FM-304",
        code: "E_EXTERNAL_EVIDENCE_UNVERIFIED",
        required_behavior: "cap the relation at locator_only or ambiguous",
    },
    FailureModeContractV03 {
        failure_id: "FM-305",
        code: "E_TRUST_LAUNDERING",
        required_behavior: "reject inferred facts represented as extracted facts",
    },
    FailureModeContractV03 {
        failure_id: "FM-306",
        code: "E_QUERY_INDEX_STALE",
        required_behavior: "require index rebuild without full-graph fallback",
    },
    FailureModeContractV03 {
        failure_id: "FM-307",
        code: "E_QUERY_SHARD_MISS",
        required_behavior: "preserve the raw correctness failure when planning omits a matching shard",
    },
    FailureModeContractV03 {
        failure_id: "FM-308",
        code: "E_QUERY_EAGER_READ",
        required_behavior: "reject ordinary queries that read every graph shard",
    },
    FailureModeContractV03 {
        failure_id: "FM-309",
        code: "E_UNICODE_COLLISION",
        required_behavior: "return an explicit ambiguity or collision receipt",
    },
    FailureModeContractV03 {
        failure_id: "FM-310",
        code: "E_QUERY_BUDGET_EXCEEDED",
        required_behavior: "return explicit truncation and continuation state",
    },
    FailureModeContractV03 {
        failure_id: "FM-311",
        code: "E_INSTALL_TARGET_OCCUPIED",
        required_behavior: "preserve user files and require an explicit managed-block choice",
    },
    FailureModeContractV03 {
        failure_id: "FM-312",
        code: "E_INSTALL_CAS_CONFLICT",
        required_behavior: "stop on concurrent target drift without overwrite",
    },
    FailureModeContractV03 {
        failure_id: "FM-313",
        code: "E_UNSAFE_PRESENTATION_INPUT",
        required_behavior: "sanitize or reject executable labels, markdown, and SVG",
    },
    FailureModeContractV03 {
        failure_id: "FM-314",
        code: "E_BENCHMARK_ENVIRONMENT_DRIFT",
        required_behavior: "invalidate the benchmark run and refreeze the environment",
    },
    FailureModeContractV03 {
        failure_id: "FM-315",
        code: "E_BENCHMARK_DEPENDENCY_UNAVAILABLE",
        required_behavior: "retain the blocked system in the denominator",
    },
    FailureModeContractV03 {
        failure_id: "FM-316",
        code: "NO_SIGNIFICANT_DIFFERENCE",
        required_behavior: "report no significant difference without a superiority claim",
    },
    FailureModeContractV03 {
        failure_id: "FM-317",
        code: "E_COMPLETION_AXIS_VIOLATION",
        required_behavior: "keep development, release, install, current, and business states orthogonal",
    },
    FailureModeContractV03 {
        failure_id: "FM-318",
        code: "E_PACKAGE_BOUNDARY_MISMATCH",
        required_behavior: "fail package and repository boundary validation",
    },
];

pub const fn failure_mode_contracts_v03() -> &'static [FailureModeContractV03] {
    FAILURE_MODES
}
