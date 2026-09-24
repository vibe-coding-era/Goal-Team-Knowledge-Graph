//! Closed Q00 contracts for the V0.3 file-query projection.
//!
//! This module defines identities and data shapes only. Q01-Q06 own index
//! construction, shard routing, query planning, and graph-operation behavior.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::{FileReceiptRef, canonical_json_sha256, validate_sha256};

pub const QUERY_INDEX_MANIFEST_SCHEMA_V1: &str = "gtkg.query-index-manifest/v1";
pub const LEXICAL_SHARD_SCHEMA_V1: &str = "gtkg.lexical-shard/v1";
pub const ADJACENCY_SHARD_SCHEMA_V1: &str = "gtkg.adjacency-shard/v1";
pub const ADJACENCY_ROUTING_CATALOG_SCHEMA_V1: &str = "gtkg.adjacency-routing-catalog/v1";
pub const FILE_QUERY_INDEX_MANIFEST_SCHEMA_V1: &str = "gtkg.file-query-index-manifest/v1";
pub const FILE_QUERY_CONTINUATION_SCHEMA_V1: &str = "gtkg.file-query-continuation/v1";
pub const FILE_QUERY_CURRENT_BINDING_SCHEMA_V1: &str = "gtkg.file-query-current-binding/v1";
pub const QUERY_PLAN_RECEIPT_SCHEMA_V1: &str = "gtkg.query-plan-receipt/v1";
pub const QUERY_INDEX_EQUIVALENCE_IDENTITY_SCHEMA_V1: &str =
    "gtkg.query-index-equivalence-identity/v1";
pub const QUERY_TOKENIZER_ID_V1: &str = "gtkg.query.unicode17-nfc-ascii-cjk-trigram/v1";
pub const QUERY_UNICODE_VERSION_V1: &str = "17.0.0";
pub const QUERY_NORMALIZATION_V1: &str = "NFC";
pub const QUERY_TRIGRAM_SCALAR_WIDTH_V1: u64 = 3;

/// File-level parser and ordinary-query ceilings frozen by Q00. Performance
/// targets remain a distinct Q05/B00 concern.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QueryResourceBudgetsV1 {
    pub max_manifest_bytes: u64,
    pub max_shard_bytes: u64,
    pub max_shard_count: u64,
    pub max_records_per_shard: u64,
    pub max_term_scalars: u64,
    pub max_postings_per_term: u64,
    pub max_selected_shards: u64,
    pub max_query_bytes_read: u64,
    pub max_response_bytes: u64,
}

impl QueryResourceBudgetsV1 {
    pub const fn v03_frozen() -> Self {
        Self {
            max_manifest_bytes: 4 * 1024 * 1024,
            max_shard_bytes: 64 * 1024 * 1024,
            max_shard_count: 4_096,
            max_records_per_shard: 1_000_000,
            max_term_scalars: 512,
            max_postings_per_term: 100_000,
            max_selected_shards: 128,
            max_query_bytes_read: 64 * 1024 * 1024,
            max_response_bytes: 8 * 1024 * 1024,
        }
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum QueryShardKindV1 {
    Lexical,
    Adjacency,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QueryShardDescriptorV1 {
    pub shard_id: String,
    pub shard_kind: QueryShardKindV1,
    pub raw_bytes_sha256: String,
    pub byte_len: u64,
    pub record_count: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QueryShardDenominatorV1 {
    pub discovered_shards: u64,
    pub admitted_shards: u64,
    pub omitted_shards: u64,
}

impl QueryShardDenominatorV1 {
    pub const fn is_closed(self) -> bool {
        self.discovered_shards == self.admitted_shards.saturating_add(self.omitted_shards)
    }

    pub const fn is_non_zero(self) -> bool {
        self.discovered_shards > 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QueryShardCatalogV1 {
    pub denominator: QueryShardDenominatorV1,
    pub entries: Vec<QueryShardDescriptorV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QueryIndexDigestsV1 {
    pub lexical_catalog_sha256: String,
    pub adjacency_catalog_sha256: String,
    pub shard_set_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QueryIndexManifestV1 {
    pub schema_version: String,
    pub source_identity: String,
    pub graph_identity: String,
    pub overlay_identity: String,
    pub tokenizer_id: String,
    pub shards: QueryShardCatalogV1,
    pub digests: QueryIndexDigestsV1,
    pub budgets: QueryResourceBudgetsV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum NormalizationCollisionStatusV1 {
    Unique,
    Ambiguous,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NormalizedTermV1 {
    pub normalized: String,
    pub original_forms: Vec<String>,
    pub collision_status: NormalizationCollisionStatusV1,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LexicalPostingV1 {
    pub normalized_term: String,
    pub node_id: String,
    pub evidence_ref: String,
    pub positions: Vec<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LexicalShardV1 {
    pub schema_version: String,
    pub shard_id: String,
    pub tokenizer_id: String,
    pub unicode_version: String,
    pub normalized_terms: Vec<NormalizedTermV1>,
    pub trigrams: Vec<String>,
    pub fst_sha256: String,
    pub postings: Vec<LexicalPostingV1>,
    pub evidence_refs: Vec<String>,
    pub raw_bytes_sha256: String,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum AdjacencyDirectionV1 {
    Outgoing,
    Incoming,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum QueryResolutionStateV1 {
    Resolved,
    Ambiguous,
    Unresolved,
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AdjacencyShardV1 {
    pub schema_version: String,
    pub shard_id: String,
    pub node_bucket: String,
    pub direction: AdjacencyDirectionV1,
    pub edge_ids: Vec<String>,
    pub resolution_states: Vec<QueryResolutionStateV1>,
    pub raw_bytes_sha256: String,
}

/// One direction-specific structural posting. The `node_id` is the exact
/// routing anchor: it equals the source for outgoing shards and the target for
/// incoming shards. Source/target, resolution, and evidence identities remain
/// attached to the same edge in both directions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AdjacencyEdgeRecordV1 {
    pub node_id: String,
    pub edge_id: String,
    pub source_node_id: String,
    pub target_node_id: String,
    pub resolution_state: QueryResolutionStateV1,
    pub evidence_ref: String,
}

/// Q02 payload layered over the frozen Q00 [`AdjacencyShardV1`] identity
/// header. Q00 callers can continue constructing and validating the original
/// header without knowing this routing projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AdjacencyRoutingShardV1 {
    pub header: AdjacencyShardV1,
    pub records: Vec<AdjacencyEdgeRecordV1>,
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AdjacencyNodeRouteV1 {
    pub node_id: String,
    pub direction: AdjacencyDirectionV1,
    pub shard_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AdjacencyRoutingDenominatorV1 {
    pub node_count: u64,
    pub edge_count: u64,
    pub route_count: u64,
    pub shard_count: u64,
    pub adjacency_record_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AdjacencyRoutingCatalogV1 {
    pub schema_version: String,
    pub graph_identity: String,
    pub nodes: Vec<String>,
    pub routes: Vec<AdjacencyNodeRouteV1>,
    pub shards: Vec<QueryShardDescriptorV1>,
    pub denominator: AdjacencyRoutingDenominatorV1,
    pub raw_bytes_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AdjacencyRoutingIndexV1 {
    pub catalog: AdjacencyRoutingCatalogV1,
    pub shards: Vec<AdjacencyRoutingShardV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LexicalRoutingEntryV1 {
    pub routing_key: String,
    pub shard_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LexicalRoutingCatalogV1 {
    pub entries: Vec<LexicalRoutingEntryV1>,
    pub raw_bytes_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FileQueryShardV1 {
    pub shard_id: String,
    pub shard_kind: QueryShardKindV1,
    pub relative_path: String,
    pub content_sha256: String,
    pub file_sha256: String,
    pub byte_len: u64,
    pub record_count: u64,
    pub term_count: u64,
    pub routing_keys: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FileAdjacencyRouteV1 {
    pub node_id: String,
    pub direction: AdjacencyDirectionV1,
    pub shard_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FileQueryIndexManifestV1 {
    pub schema_version: String,
    pub index: QueryIndexManifestV1,
    pub index_manifest_sha256: String,
    pub lexical_routing_catalog: LexicalRoutingCatalogV1,
    pub adjacency_catalog: AdjacencyRoutingCatalogV1,
    pub adjacency_routes: Vec<FileAdjacencyRouteV1>,
    pub shard_files: Vec<FileQueryShardV1>,
    pub manifest_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FileQueryExpectedIdentitiesV1 {
    pub source_identity: String,
    pub graph_identity: String,
    pub overlay_identity: String,
}

/// Q06's append-only identity binding for an equivalence comparison.  The
/// frozen Q00/Q03 expected-identity shape remains unchanged; this identity is
/// projected onto it so source, adapter, and profile drift each invalidate the
/// appropriate file-index identity without rewriting any existing contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QueryIndexEquivalenceIdentityV1 {
    pub schema_version: String,
    pub source_identity: String,
    pub adapter_identity: String,
    pub profile_identity: String,
    pub terminal_identity_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum QueryIndexEquivalenceIdentityErrorV1 {
    #[error("Q06 identity schema is unsupported")]
    UnsupportedSchema,
    #[error("Q06 {field} is not a sha256 identity")]
    InvalidIdentity { field: &'static str },
    #[error("Q06 terminal identity does not match its source, adapter, and profile")]
    TerminalIdentityMismatch,
    #[error("Q06 identity serialization failed")]
    Serialization,
}

/// Field-level, reviewable comparison of two Q06 source/adapter/profile
/// bindings and the resulting frozen Q03 identity projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QueryIndexEquivalenceProjectionDiffV1 {
    pub source_input_changed: bool,
    pub adapter_input_changed: bool,
    pub profile_input_changed: bool,
    pub source_identity_changed: bool,
    pub graph_identity_changed: bool,
    pub overlay_identity_changed: bool,
    pub terminal_identity_changed: bool,
}

impl QueryIndexEquivalenceIdentityV1 {
    pub fn new(
        source_identity: String,
        adapter_identity: String,
        profile_identity: String,
    ) -> Result<Self, QueryIndexEquivalenceIdentityErrorV1> {
        let mut identity = Self {
            schema_version: QUERY_INDEX_EQUIVALENCE_IDENTITY_SCHEMA_V1.to_owned(),
            source_identity,
            adapter_identity,
            profile_identity,
            terminal_identity_sha256: String::new(),
        };
        identity.validate_components()?;
        identity.terminal_identity_sha256 = identity.content_sha256()?;
        Ok(identity)
    }

    pub fn validate(&self) -> Result<(), QueryIndexEquivalenceIdentityErrorV1> {
        if self.schema_version != QUERY_INDEX_EQUIVALENCE_IDENTITY_SCHEMA_V1 {
            return Err(QueryIndexEquivalenceIdentityErrorV1::UnsupportedSchema);
        }
        self.validate_components()?;
        if self.terminal_identity_sha256 != self.content_sha256()? {
            return Err(QueryIndexEquivalenceIdentityErrorV1::TerminalIdentityMismatch);
        }
        Ok(())
    }

    /// Projects Q06's source/adapter/profile tuple onto the pre-existing Q00
    /// file-query identities.  A profile change affects the overlay; adapter
    /// drift affects graph and overlay; source drift affects all three.
    pub fn file_query_expected_identities(
        &self,
    ) -> Result<FileQueryExpectedIdentitiesV1, QueryIndexEquivalenceIdentityErrorV1> {
        self.validate()?;
        Ok(FileQueryExpectedIdentitiesV1 {
            source_identity: self.source_identity.clone(),
            graph_identity: canonical_json_sha256(&(
                "gtkg.q06.graph-identity/v1",
                self.source_identity.as_str(),
                self.adapter_identity.as_str(),
            ))
            .map_err(|_| QueryIndexEquivalenceIdentityErrorV1::Serialization)?,
            overlay_identity: canonical_json_sha256(&(
                "gtkg.q06.overlay-identity/v1",
                self.source_identity.as_str(),
                self.adapter_identity.as_str(),
                self.profile_identity.as_str(),
            ))
            .map_err(|_| QueryIndexEquivalenceIdentityErrorV1::Serialization)?,
        })
    }

    /// Compares the original input tuple and the resulting Q03 identity
    /// fields. Both sides are validated before a diff is returned, so a
    /// malformed self-rehashed terminal identity cannot be reported as a
    /// harmless unchanged field.
    pub fn file_query_projection_diff(
        &self,
        candidate: &Self,
    ) -> Result<QueryIndexEquivalenceProjectionDiffV1, QueryIndexEquivalenceIdentityErrorV1> {
        self.validate()?;
        candidate.validate()?;
        let current = self.file_query_expected_identities()?;
        let next = candidate.file_query_expected_identities()?;
        Ok(QueryIndexEquivalenceProjectionDiffV1 {
            source_input_changed: self.source_identity != candidate.source_identity,
            adapter_input_changed: self.adapter_identity != candidate.adapter_identity,
            profile_input_changed: self.profile_identity != candidate.profile_identity,
            source_identity_changed: current.source_identity != next.source_identity,
            graph_identity_changed: current.graph_identity != next.graph_identity,
            overlay_identity_changed: current.overlay_identity != next.overlay_identity,
            terminal_identity_changed: self.terminal_identity_sha256
                != candidate.terminal_identity_sha256,
        })
    }

    fn validate_components(&self) -> Result<(), QueryIndexEquivalenceIdentityErrorV1> {
        for (field, value) in [
            ("source_identity", self.source_identity.as_str()),
            ("adapter_identity", self.adapter_identity.as_str()),
            ("profile_identity", self.profile_identity.as_str()),
        ] {
            validate_sha256(value)
                .map_err(|_| QueryIndexEquivalenceIdentityErrorV1::InvalidIdentity { field })?;
        }
        Ok(())
    }

    fn content_sha256(&self) -> Result<String, QueryIndexEquivalenceIdentityErrorV1> {
        canonical_json_sha256(&(
            QUERY_INDEX_EQUIVALENCE_IDENTITY_SCHEMA_V1,
            self.source_identity.as_str(),
            self.adapter_identity.as_str(),
            self.profile_identity.as_str(),
        ))
        .map_err(|_| QueryIndexEquivalenceIdentityErrorV1::Serialization)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FileQueryCurrentBindingV1 {
    pub schema_version: String,
    pub source_identity: String,
    pub graph_identity: String,
    pub overlay_identity: String,
    pub index_manifest_sha256: String,
    pub manifest_ref: FileReceiptRef,
    pub binding_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "query_kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum FileQueryLookupV1 {
    Search {
        query: String,
    },
    Adjacency {
        node_id: String,
        direction: AdjacencyDirectionV1,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FileQueryRequestV1 {
    pub lookup: FileQueryLookupV1,
    pub max_results: u64,
    pub continuation: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FileQueryContinuationV1 {
    pub schema_version: String,
    pub query_sha256: String,
    pub manifest_sha256: String,
    pub index_manifest_sha256: String,
    pub routing_catalog_sha256: String,
    pub selected_shards: Vec<String>,
    pub next_offset: u64,
    pub page_size: u64,
    pub budget: QueryPlanBudgetV1,
    pub prior_plan_sha256: String,
    pub prior_page_sha256: String,
    pub continuation_sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QueryPlanBudgetV1 {
    pub max_selected_shards: u64,
    pub max_bytes_read: u64,
    pub max_response_bytes: u64,
}

impl From<QueryResourceBudgetsV1> for QueryPlanBudgetV1 {
    fn from(value: QueryResourceBudgetsV1) -> Self {
        Self {
            max_selected_shards: value.max_selected_shards,
            max_bytes_read: value.max_query_bytes_read,
            max_response_bytes: value.max_response_bytes,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryTruncationStateV1 {
    NotTruncated,
    Truncated,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QueryPlanReceiptV1 {
    pub schema_version: String,
    pub query_sha256: String,
    pub index_manifest_sha256: String,
    pub selected_shards: Vec<String>,
    pub excluded_shards: Vec<String>,
    pub bytes_read: u64,
    pub latency_ms: u64,
    pub budget: QueryPlanBudgetV1,
    pub truncation: QueryTruncationStateV1,
    pub continuation: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryTokenKindV1 {
    AsciiIdentifier,
    CjkRun,
    UnicodeWord,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QueryTokenV1 {
    pub normalized: String,
    pub kind: QueryTokenKindV1,
    pub trigrams: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QueryTokenizationReceiptV1 {
    pub tokenizer_id: String,
    pub unicode_version: String,
    pub normalization: String,
    pub tokens: Vec<QueryTokenV1>,
}

fn schema_with_id<T: JsonSchema>(schema_id: &str) -> Value {
    let mut schema = serde_json::to_value(schemars::schema_for!(T))
        .expect("JsonSchema serialization is infallible");
    schema
        .as_object_mut()
        .expect("JsonSchema root is an object")
        .insert("$id".to_owned(), Value::String(schema_id.to_owned()));
    schema
}

pub fn query_index_manifest_schema_v1() -> Value {
    schema_with_id::<QueryIndexManifestV1>(QUERY_INDEX_MANIFEST_SCHEMA_V1)
}

pub fn lexical_shard_schema_v1() -> Value {
    schema_with_id::<LexicalShardV1>(LEXICAL_SHARD_SCHEMA_V1)
}

pub fn adjacency_shard_schema_v1() -> Value {
    schema_with_id::<AdjacencyShardV1>(ADJACENCY_SHARD_SCHEMA_V1)
}

pub fn adjacency_routing_catalog_schema_v1() -> Value {
    schema_with_id::<AdjacencyRoutingCatalogV1>(ADJACENCY_ROUTING_CATALOG_SCHEMA_V1)
}

pub fn file_query_index_manifest_schema_v1() -> Value {
    schema_with_id::<FileQueryIndexManifestV1>(FILE_QUERY_INDEX_MANIFEST_SCHEMA_V1)
}

pub fn file_query_continuation_schema_v1() -> Value {
    schema_with_id::<FileQueryContinuationV1>(FILE_QUERY_CONTINUATION_SCHEMA_V1)
}

pub fn file_query_current_binding_schema_v1() -> Value {
    schema_with_id::<FileQueryCurrentBindingV1>(FILE_QUERY_CURRENT_BINDING_SCHEMA_V1)
}

pub fn query_plan_receipt_schema_v1() -> Value {
    schema_with_id::<QueryPlanReceiptV1>(QUERY_PLAN_RECEIPT_SCHEMA_V1)
}
