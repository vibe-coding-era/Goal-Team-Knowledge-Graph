//! Q06 full/incremental file-query equivalence.
//!
//! Q03 persists immutable file-index roots: rewriting a shard identifier with
//! different bytes is deliberately rejected.  This module therefore compares
//! one terminal full build and one terminal incremental reconstruction in
//! separate authorized roots.  The comparison is identity-bound and checks
//! persisted manifests, shard exact sets, and stable query-result digests.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use gtkg_protocol::FileReceiptRef;
use gtkg_protocol::canonical_json_sha256;
use gtkg_protocol::v03::query::{
    AdjacencyRoutingIndexV1, FileQueryIndexManifestV1, FileQueryRequestV1, FileQueryShardV1,
    LexicalShardV1, QueryIndexEquivalenceIdentityErrorV1, QueryIndexEquivalenceIdentityV1,
    QueryShardKindV1,
};
use thiserror::Error;

use crate::CallContext;
use crate::v03::query::{
    AdjacencyEdgeInputV1, AdjacencyIndexErrorV1, AdjacencyIndexStateV1, AdjacencyMutationV1,
    FileQueryErrorV1, FileQueryPageV1, LexicalDocumentV1, LexicalIndexErrorV1, LexicalIndexStateV1,
    LexicalMutationV1, build_adjacency_routing_index_v1, execute_first_file_query_page_v1,
    inspect_file_query_index_v1, plan_file_query_v1, write_file_query_index_v1,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryIndexLexicalGroupV1 {
    pub shard_id: String,
    pub documents: Vec<LexicalDocumentV1>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryIndexEquivalenceInputV1 {
    pub identity: QueryIndexEquivalenceIdentityV1,
    pub lexical_groups: Vec<QueryIndexLexicalGroupV1>,
    pub nodes: Vec<String>,
    pub edges: Vec<AdjacencyEdgeInputV1>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryIndexIdentityComponentV1 {
    Source,
    Adapter,
    Profile,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryIndexEquivalenceMutationV1 {
    Identity {
        component: QueryIndexIdentityComponentV1,
        value: String,
    },
    Lexical {
        shard_id: String,
        document: LexicalDocumentV1,
    },
    LexicalDelete {
        shard_id: String,
        node_id: String,
    },
    GraphNodeUpsert {
        node_id: String,
    },
    GraphNodeDelete {
        node_id: String,
    },
    GraphEdgeUpsert(AdjacencyEdgeInputV1),
    GraphEdgeDelete {
        edge_id: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryIndexEquivalenceQueryResultV1 {
    pub lookup_sha256: String,
    pub full_result_sha256: String,
    pub incremental_result_sha256: String,
    pub full_result_count: u64,
    pub incremental_result_count: u64,
    pub full_lexical_node_ids: Vec<String>,
    pub incremental_lexical_node_ids: Vec<String>,
    pub full_adjacency_edge_ids: Vec<String>,
    pub incremental_adjacency_edge_ids: Vec<String>,
    pub equal: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryIndexEquivalenceReportV1 {
    pub full_manifest_ref: FileReceiptRef,
    pub incremental_manifest_ref: FileReceiptRef,
    pub full_manifest_sha256: String,
    pub incremental_manifest_sha256: String,
    pub terminal_manifest_equal: bool,
    pub full_shard_exact_set: Vec<FileQueryShardV1>,
    pub incremental_shard_exact_set: Vec<FileQueryShardV1>,
    pub shard_exact_set_equal: bool,
    pub query_results: Vec<QueryIndexEquivalenceQueryResultV1>,
    pub stale_count: u64,
    pub ghost_count: u64,
    pub silent_omission_count: u64,
}

#[derive(Debug, Error)]
pub enum QueryIndexEquivalenceErrorV1 {
    #[error("Q06 input is invalid: {0}")]
    InvalidInput(String),
    #[error("Q06 mutation names an unknown lexical shard: {0}")]
    UnknownLexicalShard(String),
    #[error("Q06 mutation updates the same identity component twice")]
    DuplicateIdentityMutation,
    #[error("Q06 incremental reconstruction differs from the declared terminal input")]
    TerminalStateMismatch,
    #[error("Q06 full and incremental builders produced different terminal artifacts")]
    TerminalArtifactMismatch,
    #[error("Q06 full and incremental persisted manifest references differ")]
    TerminalManifestReferenceMismatch,
    #[error("Q06 full and incremental terminal manifests differ")]
    TerminalManifestMismatch,
    #[error("Q06 terminal identity is stale")]
    StaleIdentity,
    #[error(
        "Q06 terminal shard exact set has {ghost_count} ghost(s) and {omission_count} omission(s)"
    )]
    TerminalShardExactSetMismatch {
        ghost_count: u64,
        omission_count: u64,
    },
    #[error("Q06 full and incremental query result digests differ")]
    QueryResultMismatch,
    #[error("Q06 needs at least one terminal query request")]
    EmptyQuerySet,
    #[error("Q06 terminal result serialization failed")]
    Serialization,
    #[error(transparent)]
    Identity(#[from] QueryIndexEquivalenceIdentityErrorV1),
    #[error(transparent)]
    Lexical(#[from] LexicalIndexErrorV1),
    #[error(transparent)]
    Adjacency(#[from] AdjacencyIndexErrorV1),
    #[error(transparent)]
    FileQuery(#[from] FileQueryErrorV1),
}

/// Mutable reconstruction state used only for an explicit Q06 incremental
/// sequence.  Snapshotting is canonical because the underlying query states
/// use sorted maps and sets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryIndexEquivalenceStateV1 {
    identity: QueryIndexEquivalenceIdentityV1,
    lexical_groups: BTreeMap<String, LexicalIndexStateV1>,
    adjacency: AdjacencyIndexStateV1,
}

impl QueryIndexEquivalenceStateV1 {
    pub fn from_input(
        input: &QueryIndexEquivalenceInputV1,
    ) -> Result<Self, QueryIndexEquivalenceErrorV1> {
        input.identity.validate()?;
        if input.lexical_groups.is_empty() {
            return Err(QueryIndexEquivalenceErrorV1::InvalidInput(
                "at least one lexical group is required".to_owned(),
            ));
        }
        let mut lexical_groups = BTreeMap::new();
        for group in &input.lexical_groups {
            if group.shard_id.is_empty()
                || lexical_groups
                    .insert(
                        group.shard_id.clone(),
                        LexicalIndexStateV1::from_documents(&group.documents)?,
                    )
                    .is_some()
            {
                return Err(QueryIndexEquivalenceErrorV1::InvalidInput(
                    "lexical shard identifiers must be non-empty and unique".to_owned(),
                ));
            }
        }
        Ok(Self {
            identity: input.identity.clone(),
            lexical_groups,
            adjacency: AdjacencyIndexStateV1::from_graph(&input.nodes, &input.edges)?,
        })
    }

    pub fn snapshot(&self) -> QueryIndexEquivalenceInputV1 {
        QueryIndexEquivalenceInputV1 {
            identity: self.identity.clone(),
            lexical_groups: self
                .lexical_groups
                .iter()
                .map(|(shard_id, state)| QueryIndexLexicalGroupV1 {
                    shard_id: shard_id.clone(),
                    documents: state.documents(),
                })
                .collect(),
            nodes: self.adjacency.nodes(),
            edges: self.adjacency.edges(),
        }
    }

    /// Applies an atomic mutation batch.  Input state is left unchanged if a
    /// lexical, graph, or identity update is invalid.
    pub fn apply_mutations(
        &mut self,
        mutations: &[QueryIndexEquivalenceMutationV1],
    ) -> Result<(), QueryIndexEquivalenceErrorV1> {
        let mut next = self.clone();
        let mut lexical = BTreeMap::<String, Vec<LexicalMutationV1>>::new();
        let mut graph = Vec::new();
        let mut source = None;
        let mut adapter = None;
        let mut profile = None;

        for mutation in mutations {
            match mutation {
                QueryIndexEquivalenceMutationV1::Identity { component, value } => {
                    let slot = match component {
                        QueryIndexIdentityComponentV1::Source => &mut source,
                        QueryIndexIdentityComponentV1::Adapter => &mut adapter,
                        QueryIndexIdentityComponentV1::Profile => &mut profile,
                    };
                    if slot.replace(value.clone()).is_some() {
                        return Err(QueryIndexEquivalenceErrorV1::DuplicateIdentityMutation);
                    }
                }
                QueryIndexEquivalenceMutationV1::Lexical { shard_id, document } => {
                    lexical
                        .entry(shard_id.clone())
                        .or_default()
                        .push(LexicalMutationV1::Upsert(document.clone()));
                }
                QueryIndexEquivalenceMutationV1::LexicalDelete { shard_id, node_id } => {
                    lexical
                        .entry(shard_id.clone())
                        .or_default()
                        .push(LexicalMutationV1::Delete {
                            node_id: node_id.clone(),
                        });
                }
                QueryIndexEquivalenceMutationV1::GraphNodeUpsert { node_id } => {
                    graph.push(AdjacencyMutationV1::UpsertNode {
                        node_id: node_id.clone(),
                    });
                }
                QueryIndexEquivalenceMutationV1::GraphNodeDelete { node_id } => {
                    graph.push(AdjacencyMutationV1::DeleteNode {
                        node_id: node_id.clone(),
                    });
                }
                QueryIndexEquivalenceMutationV1::GraphEdgeUpsert(edge) => {
                    graph.push(AdjacencyMutationV1::UpsertEdge(edge.clone()));
                }
                QueryIndexEquivalenceMutationV1::GraphEdgeDelete { edge_id } => {
                    graph.push(AdjacencyMutationV1::DeleteEdge {
                        edge_id: edge_id.clone(),
                    });
                }
            }
        }

        for (shard_id, mutations) in lexical {
            let state = next
                .lexical_groups
                .get_mut(&shard_id)
                .ok_or(QueryIndexEquivalenceErrorV1::UnknownLexicalShard(shard_id))?;
            state.apply_mutations(&mutations)?;
        }
        if !graph.is_empty() {
            next.adjacency.apply_mutations(&graph)?;
        }
        if source.is_some() || adapter.is_some() || profile.is_some() {
            next.identity = QueryIndexEquivalenceIdentityV1::new(
                source.unwrap_or_else(|| next.identity.source_identity.clone()),
                adapter.unwrap_or_else(|| next.identity.adapter_identity.clone()),
                profile.unwrap_or_else(|| next.identity.profile_identity.clone()),
            )?;
        }
        *self = next;
        Ok(())
    }

    pub fn persist(
        &self,
        context: &CallContext,
        index_root: &Path,
    ) -> Result<FileReceiptRef, QueryIndexEquivalenceErrorV1> {
        let (lexical, adjacency) = self.build_artifacts()?;
        let expected = self.identity.file_query_expected_identities()?;
        write_file_query_index_v1(context, index_root, &expected, &lexical, &adjacency)
            .map_err(QueryIndexEquivalenceErrorV1::from)
    }

    fn build_artifacts(
        &self,
    ) -> Result<(Vec<LexicalShardV1>, AdjacencyRoutingIndexV1), QueryIndexEquivalenceErrorV1> {
        let lexical = self
            .lexical_groups
            .iter()
            .map(|(shard_id, state)| state.build_shard(shard_id))
            .collect::<Result<Vec<_>, _>>()?;
        let snapshot = self.snapshot();
        let adjacency = build_adjacency_routing_index_v1(&snapshot.nodes, &snapshot.edges)?;
        Ok((lexical, adjacency))
    }
}

/// Reconstructs one terminal state from a full input and one from explicit
/// incremental mutations, persists both immutable roots, and proves their
/// terminal file-index/query equivalence.  The function fails closed instead
/// of emitting non-zero stale, ghost, or omission counts as a success report.
pub fn verify_full_incremental_file_query_equivalence_v1(
    context: &CallContext,
    full_root: &Path,
    incremental_root: &Path,
    base: &QueryIndexEquivalenceInputV1,
    mutations: &[QueryIndexEquivalenceMutationV1],
    terminal: &QueryIndexEquivalenceInputV1,
    requests: &[FileQueryRequestV1],
) -> Result<QueryIndexEquivalenceReportV1, QueryIndexEquivalenceErrorV1> {
    if full_root == incremental_root {
        return Err(QueryIndexEquivalenceErrorV1::InvalidInput(
            "full and incremental roots must be distinct immutable roots".to_owned(),
        ));
    }
    if requests.is_empty() {
        return Err(QueryIndexEquivalenceErrorV1::EmptyQuerySet);
    }

    let full_state = QueryIndexEquivalenceStateV1::from_input(terminal)?;
    let mut incremental_state = QueryIndexEquivalenceStateV1::from_input(base)?;
    incremental_state.apply_mutations(mutations)?;
    if incremental_state.snapshot() != full_state.snapshot() {
        return Err(QueryIndexEquivalenceErrorV1::TerminalStateMismatch);
    }

    let full_artifacts = full_state.build_artifacts()?;
    let incremental_artifacts = incremental_state.build_artifacts()?;
    if full_artifacts != incremental_artifacts {
        return Err(QueryIndexEquivalenceErrorV1::TerminalArtifactMismatch);
    }

    let expected = terminal.identity.file_query_expected_identities()?;
    let full_manifest_ref = full_state.persist(context, full_root)?;
    let incremental_manifest_ref = incremental_state.persist(context, incremental_root)?;
    if full_manifest_ref != incremental_manifest_ref {
        return Err(QueryIndexEquivalenceErrorV1::TerminalManifestReferenceMismatch);
    }

    let full_manifest = inspect_file_query_index_v1(
        context,
        full_root,
        &full_manifest_ref,
        &expected,
        &requests[0],
    )?;
    let incremental_manifest = inspect_file_query_index_v1(
        context,
        incremental_root,
        &incremental_manifest_ref,
        &expected,
        &requests[0],
    )?;
    if full_manifest != incremental_manifest {
        return Err(QueryIndexEquivalenceErrorV1::TerminalManifestMismatch);
    }
    if full_manifest.index.source_identity != expected.source_identity
        || full_manifest.index.graph_identity != expected.graph_identity
        || full_manifest.index.overlay_identity != expected.overlay_identity
    {
        return Err(QueryIndexEquivalenceErrorV1::StaleIdentity);
    }

    let (ghost_count, silent_omission_count) =
        terminal_exact_set_diff(&full_manifest, &full_state, &full_artifacts);
    if ghost_count != 0 || silent_omission_count != 0 {
        return Err(
            QueryIndexEquivalenceErrorV1::TerminalShardExactSetMismatch {
                ghost_count,
                omission_count: silent_omission_count,
            },
        );
    }

    let mut query_results = Vec::with_capacity(requests.len());
    for request in requests {
        let full_plan =
            plan_file_query_v1(context, full_root, &full_manifest_ref, &expected, request)?;
        let incremental_plan = plan_file_query_v1(
            context,
            incremental_root,
            &incremental_manifest_ref,
            &expected,
            request,
        )?;
        if full_plan.manifest_sha256 != incremental_plan.manifest_sha256
            || full_plan.index_manifest_sha256 != incremental_plan.index_manifest_sha256
        {
            return Err(QueryIndexEquivalenceErrorV1::TerminalManifestMismatch);
        }
        let full_page = execute_first_file_query_page_v1(
            context,
            full_root,
            &full_manifest_ref,
            &expected,
            request,
        )?;
        let incremental_page = execute_first_file_query_page_v1(
            context,
            incremental_root,
            &incremental_manifest_ref,
            &expected,
            request,
        )?;
        let full_result_sha256 = stable_result_sha256(&full_page)?;
        let incremental_result_sha256 = stable_result_sha256(&incremental_page)?;
        let (full_lexical_node_ids, full_adjacency_edge_ids) = page_result_ids(&full_page);
        let (incremental_lexical_node_ids, incremental_adjacency_edge_ids) =
            page_result_ids(&incremental_page);
        let equal = full_result_sha256 == incremental_result_sha256;
        if !equal
            || full_lexical_node_ids != incremental_lexical_node_ids
            || full_adjacency_edge_ids != incremental_adjacency_edge_ids
        {
            return Err(QueryIndexEquivalenceErrorV1::QueryResultMismatch);
        }
        query_results.push(QueryIndexEquivalenceQueryResultV1 {
            lookup_sha256: canonical_json_sha256(&request.lookup)
                .map_err(|_| QueryIndexEquivalenceErrorV1::Serialization)?,
            full_result_sha256,
            incremental_result_sha256,
            full_result_count: full_page.total_result_count,
            incremental_result_count: incremental_page.total_result_count,
            full_lexical_node_ids,
            incremental_lexical_node_ids,
            full_adjacency_edge_ids,
            incremental_adjacency_edge_ids,
            equal,
        });
    }

    Ok(QueryIndexEquivalenceReportV1 {
        full_manifest_ref,
        incremental_manifest_ref,
        full_manifest_sha256: full_manifest.manifest_sha256.clone(),
        incremental_manifest_sha256: incremental_manifest.manifest_sha256.clone(),
        terminal_manifest_equal: true,
        full_shard_exact_set: full_manifest.shard_files.clone(),
        incremental_shard_exact_set: incremental_manifest.shard_files.clone(),
        shard_exact_set_equal: true,
        query_results,
        stale_count: 0,
        ghost_count: 0,
        silent_omission_count: 0,
    })
}

fn terminal_exact_set_diff(
    manifest: &FileQueryIndexManifestV1,
    state: &QueryIndexEquivalenceStateV1,
    artifacts: &(Vec<LexicalShardV1>, AdjacencyRoutingIndexV1),
) -> (u64, u64) {
    let expected_shards = artifacts
        .0
        .iter()
        .map(|shard| {
            (
                shard.shard_id.clone(),
                QueryShardKindV1::Lexical,
                shard.raw_bytes_sha256.clone(),
            )
        })
        .chain(artifacts.1.shards.iter().map(|shard| {
            (
                shard.header.shard_id.clone(),
                QueryShardKindV1::Adjacency,
                shard.header.raw_bytes_sha256.clone(),
            )
        }))
        .collect::<BTreeSet<_>>();
    let actual_shards = manifest
        .shard_files
        .iter()
        .map(|shard| {
            (
                shard.shard_id.clone(),
                shard.shard_kind,
                shard.content_sha256.clone(),
            )
        })
        .collect::<BTreeSet<_>>();
    let mut ghost_count = actual_shards.difference(&expected_shards).count() as u64;
    let mut omission_count = expected_shards.difference(&actual_shards).count() as u64;

    let expected_nodes = state.snapshot().nodes.into_iter().collect::<BTreeSet<_>>();
    let actual_nodes = manifest
        .adjacency_catalog
        .nodes
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    ghost_count =
        ghost_count.saturating_add(actual_nodes.difference(&expected_nodes).count() as u64);
    omission_count =
        omission_count.saturating_add(expected_nodes.difference(&actual_nodes).count() as u64);
    let expected_edge_count = state.snapshot().edges.len() as u64;
    if manifest.adjacency_catalog.denominator.edge_count != expected_edge_count {
        omission_count = omission_count.saturating_add(1);
    }
    (ghost_count, omission_count)
}

fn stable_result_sha256(page: &FileQueryPageV1) -> Result<String, QueryIndexEquivalenceErrorV1> {
    canonical_json_sha256(&(
        &page.lexical_hits,
        &page.adjacency_edges,
        page.start_offset,
        page.end_offset,
        page.result_count,
        page.total_result_count,
        page.receipt.truncation,
        page.prior_page_sha256.as_deref(),
    ))
    .map_err(|_| QueryIndexEquivalenceErrorV1::Serialization)
}

fn page_result_ids(page: &FileQueryPageV1) -> (Vec<String>, Vec<String>) {
    let lexical_node_ids = page
        .lexical_hits
        .iter()
        .map(|hit| hit.node_id.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let adjacency_edge_ids = page
        .adjacency_edges
        .iter()
        .map(|edge| edge.edge_id.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    (lexical_node_ids, adjacency_edge_ids)
}
