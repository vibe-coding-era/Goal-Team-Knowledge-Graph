//! Cross-contract validation for the V0.3 D03 architecture freeze.

pub mod adapter;
pub mod analysis;
pub mod assistant_install;
pub mod context_summary;
pub mod evidence_drawer;
pub mod explorer;
pub mod graph_query;
pub mod identity_lifecycle;
pub mod installer;
pub mod lifecycle;
pub mod query;
pub mod query_equivalence;

use std::collections::{BTreeMap, BTreeSet};

use gtkg_protocol::v2::V2_PUBLIC_OPERATIONS;
use gtkg_protocol::v03::{
    ADAPTER_DESCRIPTOR_IDENTITY_V1, ADJACENCY_SHARD_IDENTITY_V1,
    ASSISTANT_INSTALL_RECEIPT_IDENTITY_V1, AdapterKindV1, DiscoveryProfileIdV1,
    EXTERNAL_FACT_BUNDLE_IDENTITY_V1, HandlerPartitionContractV03, HandlerPartitionV03,
    INSTALL_MANIFEST_IDENTITY_V1, LEXICAL_SHARD_IDENTITY_V1, ManifestIdentityContractV03,
    QUERY_INDEX_MANIFEST_IDENTITY_V1, QUERY_PLAN_RECEIPT_IDENTITY_V1,
    VERIFIED_FACT_RECEIPT_IDENTITY_V1, adapter_manifest_identity_contracts_v03,
    discovery_profiles_v03, failure_mode_contracts_v03, handler_partitions_v03,
    operation_bindings_v03,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArchitectureContractErrorV03 {
    OperationCount,
    DuplicateOperation,
    DuplicateHandler,
    PartitionCoverage,
    PartitionOwnership,
    PartitionExactSet,
    ProfileCount,
    ProfileInvalid,
    DefaultProfile,
    AllProfileCoverage,
    ProfileExactSet,
    IdentityExactSet,
    FailureModeExactSet,
}

const EXPECTED_PARTITIONS: &[HandlerPartitionContractV03] = &[
    HandlerPartitionContractV03 {
        partition: HandlerPartitionV03::SystemConfig,
        operation_ids: &["system.describe", "config.validate", "capability.describe"],
    },
    HandlerPartitionContractV03 {
        partition: HandlerPartitionV03::SourceAnalysis,
        operation_ids: &[
            "source.capture",
            "analysis.plan",
            "analysis.build",
            "analysis.verify",
            "build.finalize.v2",
        ],
    },
    HandlerPartitionContractV03 {
        partition: HandlerPartitionV03::ContextSummary,
        operation_ids: &[
            "context.pack",
            "summary.job.next",
            "summary.proposal.submit",
            "summary.verification.next",
            "summary.verification.submit",
            "summary.accept.v2",
        ],
    },
    HandlerPartitionContractV03 {
        partition: HandlerPartitionV03::Run,
        operation_ids: &["run.get", "run.cancel"],
    },
    HandlerPartitionContractV03 {
        partition: HandlerPartitionV03::BundleMigration,
        operation_ids: &["bundle.verify", "bundle.compare", "bundle.migrate.v1_to_v2"],
    },
    HandlerPartitionContractV03 {
        partition: HandlerPartitionV03::Snapshot,
        operation_ids: &["snapshot.create", "snapshot.verify", "snapshot.restore"],
    },
    HandlerPartitionContractV03 {
        partition: HandlerPartitionV03::GitCurrent,
        operation_ids: &["git.publish", "current.get", "current.activate"],
    },
    HandlerPartitionContractV03 {
        partition: HandlerPartitionV03::NodeFederation,
        operation_ids: &["node.describe", "federation.validate"],
    },
    HandlerPartitionContractV03 {
        partition: HandlerPartitionV03::Template,
        operation_ids: &[
            "template.list",
            "template.resolve",
            "template.prefetch",
            "template.get",
            "template.validate",
            "template.derive",
            "template.publish",
        ],
    },
    HandlerPartitionContractV03 {
        partition: HandlerPartitionV03::Deliverable,
        operation_ids: &["deliverable.derive", "deliverable.publish"],
    },
    HandlerPartitionContractV03 {
        partition: HandlerPartitionV03::Graph,
        operation_ids: &[
            "graph.neighbors",
            "graph.path",
            "graph.impact",
            "graph.explain",
            "graph.trace",
            "graph.search",
        ],
    },
    HandlerPartitionContractV03 {
        partition: HandlerPartitionV03::A2ui,
        operation_ids: &["a2ui.resolve", "a2ui.generate", "a2ui.get", "a2ui.validate"],
    },
];

struct ExpectedProfileV03 {
    id: DiscoveryProfileIdV1,
    is_default: bool,
    operation_ids: &'static [&'static str],
    digest: &'static str,
}

const EXPECTED_PROFILES: &[ExpectedProfileV03] = &[
    ExpectedProfileV03 {
        id: DiscoveryProfileIdV1::Core,
        is_default: true,
        operation_ids: &[
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
        ],
        digest: "sha256:50263880d66cc5aa09ff9e2e3cf85956ad9dcea09a0f0925609f25bcac5f31a8",
    },
    ExpectedProfileV03 {
        id: DiscoveryProfileIdV1::Graph,
        is_default: false,
        operation_ids: &[
            "graph.neighbors",
            "graph.path",
            "graph.impact",
            "graph.explain",
            "graph.trace",
            "graph.search",
        ],
        digest: "sha256:86777e15e4f84ec49c94af68b83ce1910b85b42c6a66dfb61f69f40db878cd38",
    },
    ExpectedProfileV03 {
        id: DiscoveryProfileIdV1::Authoring,
        is_default: false,
        operation_ids: &[
            "context.pack",
            "summary.job.next",
            "summary.proposal.submit",
            "summary.verification.next",
            "summary.verification.submit",
            "summary.accept.v2",
            "analysis.verify",
            "build.finalize.v2",
        ],
        digest: "sha256:0a4ab7a650741b60d905baa747acd4f30c5d13da9ed61a9eb7e87fe654bffd75",
    },
    ExpectedProfileV03 {
        id: DiscoveryProfileIdV1::Lifecycle,
        is_default: false,
        operation_ids: &[
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
        ],
        digest: "sha256:1f8d7e6b63639aaa31b5eadf27875157ee03ecf6e2bba8b06fdae3551be10895",
    },
    ExpectedProfileV03 {
        id: DiscoveryProfileIdV1::Templates,
        is_default: false,
        operation_ids: &[
            "template.list",
            "template.resolve",
            "template.prefetch",
            "template.get",
            "template.validate",
            "template.derive",
            "template.publish",
            "deliverable.derive",
            "deliverable.publish",
        ],
        digest: "sha256:dbd30e464b48599be2bd67f4922aabec68c3d7462d148c91b29b8746c3ec3b4a",
    },
    ExpectedProfileV03 {
        id: DiscoveryProfileIdV1::A2ui,
        is_default: false,
        operation_ids: &["a2ui.resolve", "a2ui.generate", "a2ui.get", "a2ui.validate"],
        digest: "sha256:a9b24b739ce003567af3eb0629d51484f191be98d5c3fb8379fa8076ae0f0cac",
    },
    ExpectedProfileV03 {
        id: DiscoveryProfileIdV1::All,
        is_default: false,
        operation_ids: &[],
        digest: "sha256:5c718c85bcc4e65a3862ec591138e52506884200fffe9923f78ea6f3cd12826f",
    },
];

const EXPECTED_FAILURE_MODES: &[(&str, &str, &str)] = &[
    (
        "FM-301",
        "E_DEAD_TOOL_EXPOSED",
        "reject profile discovery while any selected operation is not implemented",
    ),
    (
        "FM-302",
        "E_PROFILE_STALE",
        "reject digest drift and require an explicit profile revision",
    ),
    (
        "FM-303",
        "E_ADAPTER_IDENTITY_MISMATCH",
        "reject schema, source commit, or license drift",
    ),
    (
        "FM-304",
        "E_EXTERNAL_EVIDENCE_UNVERIFIED",
        "cap the relation at locator_only or ambiguous",
    ),
    (
        "FM-305",
        "E_TRUST_LAUNDERING",
        "reject inferred facts represented as extracted facts",
    ),
    (
        "FM-306",
        "E_QUERY_INDEX_STALE",
        "require index rebuild without full-graph fallback",
    ),
    (
        "FM-307",
        "E_QUERY_SHARD_MISS",
        "preserve the raw correctness failure when planning omits a matching shard",
    ),
    (
        "FM-308",
        "E_QUERY_EAGER_READ",
        "reject ordinary queries that read every graph shard",
    ),
    (
        "FM-309",
        "E_UNICODE_COLLISION",
        "return an explicit ambiguity or collision receipt",
    ),
    (
        "FM-310",
        "E_QUERY_BUDGET_EXCEEDED",
        "return explicit truncation and continuation state",
    ),
    (
        "FM-311",
        "E_INSTALL_TARGET_OCCUPIED",
        "preserve user files and require an explicit managed-block choice",
    ),
    (
        "FM-312",
        "E_INSTALL_CAS_CONFLICT",
        "stop on concurrent target drift without overwrite",
    ),
    (
        "FM-313",
        "E_UNSAFE_PRESENTATION_INPUT",
        "sanitize or reject executable labels, markdown, and SVG",
    ),
    (
        "FM-314",
        "E_BENCHMARK_ENVIRONMENT_DRIFT",
        "invalidate the benchmark run and refreeze the environment",
    ),
    (
        "FM-315",
        "E_BENCHMARK_DEPENDENCY_UNAVAILABLE",
        "retain the blocked system in the denominator",
    ),
    (
        "FM-316",
        "NO_SIGNIFICANT_DIFFERENCE",
        "report no significant difference without a superiority claim",
    ),
    (
        "FM-317",
        "E_COMPLETION_AXIS_VIOLATION",
        "keep development, release, install, current, and business states orthogonal",
    ),
    (
        "FM-318",
        "E_PACKAGE_BOUNDARY_MISMATCH",
        "fail package and repository boundary validation",
    ),
];

fn identity_matches(
    actual: ManifestIdentityContractV03,
    schema_id: &str,
    fields: &[&str],
    drift_code: &str,
) -> bool {
    actual.schema_id == schema_id
        && actual.required_identity_fields == fields
        && actual.drift_code == drift_code
}

pub fn validate_architecture_contract_v03() -> Result<(), ArchitectureContractErrorV03> {
    let bindings = operation_bindings_v03();
    if bindings.len() != 46 {
        return Err(ArchitectureContractErrorV03::OperationCount);
    }
    if bindings
        .iter()
        .map(|binding| binding.operation_id)
        .collect::<BTreeSet<_>>()
        .len()
        != bindings.len()
    {
        return Err(ArchitectureContractErrorV03::DuplicateOperation);
    }
    if bindings
        .iter()
        .map(|binding| binding.handler_id.as_str())
        .collect::<BTreeSet<_>>()
        .len()
        != bindings.len()
    {
        return Err(ArchitectureContractErrorV03::DuplicateHandler);
    }

    let mut owners = BTreeMap::<&str, HandlerPartitionV03>::new();
    for partition in handler_partitions_v03() {
        for operation_id in partition.operation_ids {
            if owners.insert(operation_id, partition.partition).is_some() {
                return Err(ArchitectureContractErrorV03::PartitionCoverage);
            }
        }
    }
    if owners.len() != bindings.len() {
        return Err(ArchitectureContractErrorV03::PartitionCoverage);
    }
    if bindings.iter().any(|binding| {
        owners.get(binding.operation_id.as_str()).copied() != Some(binding.partition)
    }) {
        return Err(ArchitectureContractErrorV03::PartitionOwnership);
    }
    if handler_partitions_v03() != EXPECTED_PARTITIONS {
        return Err(ArchitectureContractErrorV03::PartitionExactSet);
    }

    let profiles = discovery_profiles_v03();
    if profiles.len() != 7 {
        return Err(ArchitectureContractErrorV03::ProfileCount);
    }
    if profiles.iter().any(|profile| profile.validate().is_err()) {
        return Err(ArchitectureContractErrorV03::ProfileInvalid);
    }
    if profiles
        .iter()
        .filter(|profile| profile.is_default)
        .map(|profile| profile.profile_id)
        .collect::<Vec<_>>()
        != [DiscoveryProfileIdV1::Core]
    {
        return Err(ArchitectureContractErrorV03::DefaultProfile);
    }
    let binding_ids = bindings
        .iter()
        .map(|binding| binding.operation_id)
        .collect::<BTreeSet<_>>();
    let all_ids = profiles
        .iter()
        .find(|profile| profile.profile_id == DiscoveryProfileIdV1::All)
        .map(|profile| {
            profile
                .operation_ids
                .iter()
                .copied()
                .collect::<BTreeSet<_>>()
        })
        .unwrap_or_default();
    if all_ids != binding_ids {
        return Err(ArchitectureContractErrorV03::AllProfileCoverage);
    }

    for expected in EXPECTED_PROFILES {
        let Some(actual) = profiles
            .iter()
            .find(|profile| profile.profile_id == expected.id)
        else {
            return Err(ArchitectureContractErrorV03::ProfileExactSet);
        };
        let actual_operation_ids = actual
            .operation_ids
            .iter()
            .map(|operation_id| operation_id.as_str())
            .collect::<Vec<_>>();
        let expected_operation_ids = if expected.id == DiscoveryProfileIdV1::All {
            V2_PUBLIC_OPERATIONS
                .iter()
                .map(|definition| definition.id.as_str())
                .collect::<Vec<_>>()
        } else {
            expected.operation_ids.to_vec()
        };
        if actual.is_default != expected.is_default
            || actual_operation_ids != expected_operation_ids
            || actual.digest != expected.digest
        {
            return Err(ArchitectureContractErrorV03::ProfileExactSet);
        }
    }

    let adapters = adapter_manifest_identity_contracts_v03();
    let expected_adapter_kinds = [
        AdapterKindV1::Native,
        AdapterKindV1::Scip,
        AdapterKindV1::LspSnapshot,
        AdapterKindV1::CodeGraphExport,
        AdapterKindV1::GraphifyExport,
    ];
    let adapter_fields = [
        "adapter_id",
        "adapter_version",
        "schema_sha256",
        "source_commit",
        "license",
        "capabilities",
        "trust_policy_id",
    ];
    if adapters.len() != expected_adapter_kinds.len()
        || adapters
            .iter()
            .zip(expected_adapter_kinds)
            .any(|(actual, expected_kind)| {
                actual.kind != expected_kind
                    || actual.required_identity_fields != adapter_fields
                    || actual.drift_code != "E_ADAPTER_IDENTITY_MISMATCH"
            })
        || !identity_matches(
            ADAPTER_DESCRIPTOR_IDENTITY_V1,
            "gtkg.adapter-descriptor/v1",
            &adapter_fields,
            "E_ADAPTER_IDENTITY_MISMATCH",
        )
        || !identity_matches(
            EXTERNAL_FACT_BUNDLE_IDENTITY_V1,
            "gtkg.external-fact-bundle/v1",
            &[
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
            "E_ADAPTER_IDENTITY_MISMATCH",
        )
        || !identity_matches(
            VERIFIED_FACT_RECEIPT_IDENTITY_V1,
            "gtkg.verified-fact-receipt/v1",
            &[
                "source_replay_sha256",
                "source_span",
                "source_bytes_sha256",
                "resolution",
                "reason",
                "verifier_identity",
            ],
            "E_EXTERNAL_EVIDENCE_UNVERIFIED",
        )
        || !identity_matches(
            QUERY_INDEX_MANIFEST_IDENTITY_V1,
            "gtkg.query-index-manifest/v1",
            &[
                "source_identity",
                "graph_identity",
                "overlay_identity",
                "tokenizer_id",
                "shards",
                "digests",
                "budgets",
            ],
            "E_QUERY_INDEX_STALE",
        )
        || !identity_matches(
            LEXICAL_SHARD_IDENTITY_V1,
            "gtkg.lexical-shard/v1",
            &[
                "unicode_version",
                "normalized_terms",
                "trigrams",
                "fst_sha256",
                "postings",
                "evidence_refs",
            ],
            "E_QUERY_INDEX_STALE",
        )
        || !identity_matches(
            ADJACENCY_SHARD_IDENTITY_V1,
            "gtkg.adjacency-shard/v1",
            &[
                "node_bucket",
                "direction",
                "edge_ids",
                "resolution_states",
                "raw_bytes_sha256",
            ],
            "E_QUERY_INDEX_STALE",
        )
        || !identity_matches(
            QUERY_PLAN_RECEIPT_IDENTITY_V1,
            "gtkg.query-plan-receipt/v1",
            &[
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
            "E_QUERY_INDEX_STALE",
        )
        || !identity_matches(
            INSTALL_MANIFEST_IDENTITY_V1,
            "gtkg.install-manifest/v1",
            &[
                "version",
                "platform",
                "files",
                "modes",
                "digests",
                "destinations",
            ],
            "E_INSTALL_IDENTITY_MISMATCH",
        )
        || !identity_matches(
            ASSISTANT_INSTALL_RECEIPT_IDENTITY_V1,
            "gtkg.assistant-install-receipt/v1",
            &[
                "assistant",
                "platform",
                "scope",
                "target_file",
                "before_sha256",
                "after_sha256",
                "managed_block_sha256",
            ],
            "E_INSTALL_CAS_CONFLICT",
        )
    {
        return Err(ArchitectureContractErrorV03::IdentityExactSet);
    }

    let failures = failure_mode_contracts_v03()
        .iter()
        .map(|failure| (failure.failure_id, failure.code, failure.required_behavior))
        .collect::<Vec<_>>();
    if failures != EXPECTED_FAILURE_MODES {
        return Err(ArchitectureContractErrorV03::FailureModeExactSet);
    }
    Ok(())
}
