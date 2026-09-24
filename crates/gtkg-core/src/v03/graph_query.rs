//! Q04 public graph operations over the accepted Q03 file-query runtime.
//!
//! Query selection is delegated to Q03.  This module only opens the selected
//! lexical/adjacency shards and the entity-scoped evidence records needed to
//! preserve the prior Evidence Pack surface.  It never reads a Graph-v3
//! manifest or shard, database, network service, daemon, or provider.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use gtkg_protocol::v03::query::{
    AdjacencyDirectionV1, AdjacencyEdgeRecordV1, AdjacencyRoutingShardV1,
    FileQueryExpectedIdentitiesV1, FileQueryIndexManifestV1, FileQueryLookupV1, FileQueryRequestV1,
    LexicalShardV1, QueryPlanReceiptV1, QueryResolutionStateV1, QueryResourceBudgetsV1,
    QueryShardKindV1, QueryTruncationStateV1,
};
use gtkg_protocol::{FileReceiptRef, canonical_json_sha256, validate_sha256};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;

use super::query::{
    FileQueryErrorV1, FileQueryPageV1, adjacency_routing_shard_content_sha256_v1,
    execute_first_file_query_page_v1, execute_next_file_query_page_v1,
    lexical_shard_content_sha256_v1, validate_file_query_index_manifest_v1,
};
use crate::durable::{DurableErrorKind, publish_immutable_json, publish_private_immutable_json};
use crate::knowledge_overlay_v2::{
    KnowledgeOverlayBuildInputV2, KnowledgeOverlayV2, build_knowledge_overlay_v2,
};
use crate::{CallContext, ContextError};

pub const FILE_GRAPH_EVIDENCE_MANIFEST_SCHEMA_V1: &str = "gtkg.file-graph-evidence-manifest/v1";
pub const FILE_GRAPH_QUERY_RESULT_SCHEMA_V1: &str = "gtkg.file-graph-query-result/v1";
const FILE_GRAPH_CONTINUATION_AUTHORITY_SCHEMA_V1: &str =
    "gtkg.file-graph-continuation-authority/v1";
const FILE_GRAPH_EVIDENCE_RECORD_SCHEMA_V1: &str = "gtkg.file-graph-evidence-record/v1";
const FILE_GRAPH_CONTINUATION_SCHEMA_V1: &str = "gtkg.file-graph-continuation/v1";
const MAX_EVIDENCE_MANIFEST_BYTES: u64 = 8 * 1024 * 1024;
const MAX_EVIDENCE_RECORD_BYTES: u64 = 1024 * 1024;
const MAX_EVIDENCE_RECORDS: usize = 100_000;
const MAX_EVIDENCE_ITEMS_PER_RECORD: usize = 4_096;
const MAX_QUERY_DEPTH: usize = 8;
const MAX_PUBLIC_RESULTS: usize = 1_000;
const MAX_INTERNAL_RESULTS: u64 = 10_000;
const MAX_VISITED_NODES: usize = 10_000;
const MAX_QUERY_PLANS: usize = 10_000;
const MAX_OPERATION_QUERY_BYTES: u64 = 64 * 1024 * 1024;
const MAX_OPERATION_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const MAX_CONTINUATION_BYTES: usize = 4 * 1024 * 1024;
const MAX_CONTINUATION_AUTHORITY_BYTES: u64 = 4 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileGraphQueryOperationV1 {
    Neighbors,
    Path,
    Impact,
    Explain,
    Trace,
    Search,
}

impl FileGraphQueryOperationV1 {
    pub const fn operation_id(self) -> &'static str {
        match self {
            Self::Neighbors => "graph.neighbors",
            Self::Path => "graph.path",
            Self::Impact => "graph.impact",
            Self::Explain => "graph.explain",
            Self::Trace => "graph.trace",
            Self::Search => "graph.search",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "entity_kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum GraphQueryEntityV1 {
    StructuralNode {
        entity_id: String,
        node_kind: String,
        label: String,
        source_logical_path: String,
        structural_provenance: Value,
        evidence: Vec<Value>,
    },
    StructuralEdge {
        entity_id: String,
        edge_kind: String,
        source_node_id: String,
        target_node_id: Option<String>,
        target_reference: String,
        resolution_state: QueryResolutionStateV1,
        candidate_node_ids: Vec<String>,
        structural_provenance: Value,
        evidence: Vec<Value>,
    },
    KnowledgeNode {
        entity_id: String,
        knowledge_kind: String,
        label: String,
        claim_id: String,
        knowledge_state: String,
        structural_evidence_ids: Vec<String>,
        overlay_provenance: Value,
        evidence: Vec<Value>,
    },
}

impl GraphQueryEntityV1 {
    fn entity_id(&self) -> &str {
        match self {
            Self::StructuralNode { entity_id, .. }
            | Self::StructuralEdge { entity_id, .. }
            | Self::KnowledgeNode { entity_id, .. } => entity_id,
        }
    }

    fn evidence(&self) -> &[Value] {
        match self {
            Self::StructuralNode { evidence, .. }
            | Self::StructuralEdge { evidence, .. }
            | Self::KnowledgeNode { evidence, .. } => evidence,
        }
    }

    fn evidence_ids(&self) -> BTreeSet<&str> {
        self.evidence()
            .iter()
            .filter_map(|item| item.get("evidence_id").and_then(Value::as_str))
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileGraphEvidenceRecordV1 {
    schema_version: String,
    entity: GraphQueryEntityV1,
    record_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileGraphEvidenceEntryV1 {
    pub entity_id: String,
    pub relative_path: String,
    pub content_sha256: String,
    pub file_sha256: String,
    pub byte_len: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KnowledgeEvidenceAssuranceV1 {
    StructuralOnly,
    FixtureOnlyUnattested,
    VerifiedOverlayReplay,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileGraphEvidenceManifestV1 {
    pub schema_version: String,
    pub source_identity: String,
    pub graph_identity: String,
    pub overlay_identity: String,
    pub query_manifest_ref: FileReceiptRef,
    pub index_manifest_sha256: String,
    pub knowledge_assurance: KnowledgeEvidenceAssuranceV1,
    pub overlay_replay_sha256: Option<String>,
    pub records: Vec<FileGraphEvidenceEntryV1>,
    pub manifest_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum FileGraphQueryErrorV1 {
    #[error("file graph query request is invalid")]
    InvalidRequest,
    #[error("query index identity is stale")]
    StaleIndex,
    #[error("query index is invalid or tampered")]
    IndexInvalid,
    #[error("selected Evidence Pack record is invalid or tampered")]
    EvidenceTampered,
    #[error("file graph query path is unsafe")]
    UnsafePath,
    #[error("file graph query exceeded a frozen resource budget")]
    ResourceBudgetExceeded,
    #[error("file graph continuation is invalid")]
    ContinuationInvalid,
    #[error("file graph query entity was not found")]
    NotFound,
    #[error("knowledge evidence is not bound to a rebuilt verified overlay input")]
    KnowledgeUnattested,
    #[error("file graph query I/O failed")]
    Io,
}

impl FileGraphQueryErrorV1 {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidRequest => "E_QUERY_INVALID",
            Self::StaleIndex => "E_QUERY_INDEX_STALE",
            Self::IndexInvalid => "E_QUERY_INDEX_INVALID",
            Self::EvidenceTampered => "E_QUERY_EVIDENCE_TAMPERED",
            Self::UnsafePath => "E_QUERY_PATH_UNSAFE",
            Self::ResourceBudgetExceeded => "E_QUERY_BUDGET_EXCEEDED",
            Self::ContinuationInvalid => "E_QUERY_CONTINUATION_INVALID",
            Self::NotFound => "E_QUERY_NO_ANSWER",
            Self::KnowledgeUnattested => "E_QUERY_KNOWLEDGE_UNATTESTED",
            Self::Io => "E_QUERY_IO",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state_kind", rename_all = "snake_case", deny_unknown_fields)]
enum ContinuationStateV1 {
    Search {
        previous_page: Box<FileQueryPageV1>,
    },
    Slice {
        next_offset: u64,
        page_size: u64,
        total_result_count: u64,
        full_result_sha256: String,
        previous_start_offset: u64,
        previous_end_offset: u64,
        previous_result_sha256: String,
        previous_page_sha256: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileGraphContinuationV1 {
    schema_version: String,
    operation: FileGraphQueryOperationV1,
    request_sha256: String,
    evidence_manifest_sha256: String,
    authority_sha256: String,
    state: ContinuationStateV1,
    continuation_sha256: String,
    continuation_mac_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileGraphContinuationAuthorityV1 {
    schema_version: String,
    evidence_manifest_ref: FileReceiptRef,
    key_hex: String,
    authority_sha256: String,
}

struct LoadedContinuationAuthorityV1 {
    authority_sha256: String,
    key: [u8; 32],
}

#[derive(Default)]
struct IssuedSliceContinuationsV1 {
    keys: BTreeSet<String>,
    order: VecDeque<String>,
}

const ISSUED_SLICE_CONTINUATION_CAPACITY: usize = 256;

fn issued_slice_continuations_v1() -> &'static Mutex<IssuedSliceContinuationsV1> {
    static ISSUED: OnceLock<Mutex<IssuedSliceContinuationsV1>> = OnceLock::new();
    ISSUED.get_or_init(|| Mutex::new(IssuedSliceContinuationsV1::default()))
}

fn register_issued_slice_continuation_v1(token: &str) {
    let mut issued = issued_slice_continuations_v1()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    issued.order.retain(|candidate| candidate != token);
    issued.keys.insert(token.to_owned());
    issued.order.push_back(token.to_owned());
    while issued.keys.len() > ISSUED_SLICE_CONTINUATION_CAPACITY {
        if let Some(oldest) = issued.order.pop_front() {
            issued.keys.remove(&oldest);
        } else {
            break;
        }
    }
}

fn consume_issued_slice_continuation_v1(token: &str) -> Result<(), FileGraphQueryErrorV1> {
    let mut issued = issued_slice_continuations_v1()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if !issued.keys.remove(token) {
        return Err(FileGraphQueryErrorV1::ContinuationInvalid);
    }
    issued.order.retain(|candidate| candidate != token);
    Ok(())
}

#[derive(Default)]
struct QueryMetricsV1 {
    plans: Vec<QueryPlanReceiptV1>,
    selected_shards: BTreeSet<String>,
    excluded_shards: BTreeSet<String>,
    bytes_read: u64,
    shard_files_opened: u64,
    full_graph_read_count: u64,
    database_read_count: u64,
    network_call_count: u64,
    daemon_call_count: u64,
    plan_completed_before_shard_read: bool,
}

impl QueryMetricsV1 {
    fn observe(&mut self, page: &FileQueryPageV1) -> Result<(), FileGraphQueryErrorV1> {
        if self.plans.len() >= MAX_QUERY_PLANS {
            return Err(FileGraphQueryErrorV1::ResourceBudgetExceeded);
        }
        self.bytes_read = self
            .bytes_read
            .checked_add(page.receipt.bytes_read)
            .ok_or(FileGraphQueryErrorV1::ResourceBudgetExceeded)?;
        if self.bytes_read > MAX_OPERATION_QUERY_BYTES {
            return Err(FileGraphQueryErrorV1::ResourceBudgetExceeded);
        }
        self.shard_files_opened = self
            .shard_files_opened
            .checked_add(page.shard_files_opened)
            .ok_or(FileGraphQueryErrorV1::ResourceBudgetExceeded)?;
        self.full_graph_read_count = self
            .full_graph_read_count
            .checked_add(page.full_graph_read_count)
            .ok_or(FileGraphQueryErrorV1::ResourceBudgetExceeded)?;
        self.database_read_count = self
            .database_read_count
            .checked_add(page.database_read_count)
            .ok_or(FileGraphQueryErrorV1::ResourceBudgetExceeded)?;
        self.network_call_count = self
            .network_call_count
            .checked_add(page.network_call_count)
            .ok_or(FileGraphQueryErrorV1::ResourceBudgetExceeded)?;
        self.daemon_call_count = self
            .daemon_call_count
            .checked_add(page.daemon_call_count)
            .ok_or(FileGraphQueryErrorV1::ResourceBudgetExceeded)?;
        self.plan_completed_before_shard_read = if self.plans.is_empty() {
            page.plan_completed_before_shard_read
        } else {
            self.plan_completed_before_shard_read && page.plan_completed_before_shard_read
        };
        self.selected_shards
            .extend(page.receipt.selected_shards.iter().cloned());
        self.excluded_shards
            .extend(page.receipt.excluded_shards.iter().cloned());
        self.plans.push(page.receipt.clone());
        Ok(())
    }
}

struct EvidenceReaderV1<'a> {
    context: &'a CallContext,
    root: PathBuf,
    manifest: FileGraphEvidenceManifestV1,
    opened: BTreeMap<String, GraphQueryEntityV1>,
    bytes_read: u64,
}

impl<'a> EvidenceReaderV1<'a> {
    fn open(
        context: &'a CallContext,
        root: &Path,
        manifest_ref: &FileReceiptRef,
        expected: &FileQueryExpectedIdentitiesV1,
        query_manifest_ref: &FileReceiptRef,
        index_manifest_sha256: &str,
        preflight_bytes_read: u64,
    ) -> Result<Self, FileGraphQueryErrorV1> {
        manifest_ref
            .validate()
            .map_err(|_| FileGraphQueryErrorV1::EvidenceTampered)?;
        if !safe_relative_path(&manifest_ref.path, "manifests") {
            return Err(FileGraphQueryErrorV1::UnsafePath);
        }
        let root = authorize_plain_root(context, root)?;
        let read = read_bound_file(
            context,
            &root,
            Path::new(&manifest_ref.path),
            MAX_EVIDENCE_MANIFEST_BYTES,
        )?;
        if read.sha256 != manifest_ref.sha256 {
            return Err(FileGraphQueryErrorV1::EvidenceTampered);
        }
        let manifest: FileGraphEvidenceManifestV1 = serde_json::from_slice(&read.bytes)
            .map_err(|_| FileGraphQueryErrorV1::EvidenceTampered)?;
        validate_evidence_manifest(&manifest)?;
        validate_manifest_assurance(context, &manifest)?;
        if manifest.source_identity != expected.source_identity
            || manifest.graph_identity != expected.graph_identity
            || manifest.overlay_identity != expected.overlay_identity
            || manifest.query_manifest_ref != *query_manifest_ref
            || manifest.index_manifest_sha256 != index_manifest_sha256
        {
            return Err(FileGraphQueryErrorV1::StaleIndex);
        }
        let bytes_read = preflight_bytes_read
            .checked_add(
                u64::try_from(read.bytes.len())
                    .map_err(|_| FileGraphQueryErrorV1::ResourceBudgetExceeded)?,
            )
            .ok_or(FileGraphQueryErrorV1::ResourceBudgetExceeded)?;
        if bytes_read > MAX_OPERATION_QUERY_BYTES {
            return Err(FileGraphQueryErrorV1::ResourceBudgetExceeded);
        }
        Ok(Self {
            context,
            root,
            manifest,
            opened: BTreeMap::new(),
            bytes_read,
        })
    }

    fn entity(&mut self, entity_id: &str) -> Result<&GraphQueryEntityV1, FileGraphQueryErrorV1> {
        if !self.opened.contains_key(entity_id) {
            let entry = self
                .manifest
                .records
                .binary_search_by(|entry| entry.entity_id.as_str().cmp(entity_id))
                .ok()
                .and_then(|index| self.manifest.records.get(index))
                .ok_or(FileGraphQueryErrorV1::NotFound)?
                .clone();
            let read = read_bound_file(
                self.context,
                &self.root,
                Path::new(&entry.relative_path),
                MAX_EVIDENCE_RECORD_BYTES,
            )?;
            if read.sha256 != entry.file_sha256
                || u64::try_from(read.bytes.len()).ok() != Some(entry.byte_len)
            {
                return Err(FileGraphQueryErrorV1::EvidenceTampered);
            }
            let record: FileGraphEvidenceRecordV1 = serde_json::from_slice(&read.bytes)
                .map_err(|_| FileGraphQueryErrorV1::EvidenceTampered)?;
            validate_evidence_record(&record)?;
            let knowledge_allowed = match self.manifest.knowledge_assurance {
                KnowledgeEvidenceAssuranceV1::VerifiedOverlayReplay => true,
                KnowledgeEvidenceAssuranceV1::FixtureOnlyUnattested => {
                    self.context.transport == crate::TransportKind::Test
                }
                KnowledgeEvidenceAssuranceV1::StructuralOnly => false,
            };
            if matches!(record.entity, GraphQueryEntityV1::KnowledgeNode { .. })
                && !knowledge_allowed
            {
                return Err(FileGraphQueryErrorV1::KnowledgeUnattested);
            }
            if record.entity.entity_id() != entity_id
                || record.record_sha256 != entry.content_sha256
            {
                return Err(FileGraphQueryErrorV1::EvidenceTampered);
            }
            self.bytes_read = self
                .bytes_read
                .checked_add(entry.byte_len)
                .ok_or(FileGraphQueryErrorV1::ResourceBudgetExceeded)?;
            if self.bytes_read > MAX_OPERATION_QUERY_BYTES {
                return Err(FileGraphQueryErrorV1::ResourceBudgetExceeded);
            }
            self.opened.insert(entity_id.to_owned(), record.entity);
        }
        self.opened
            .get(entity_id)
            .ok_or(FileGraphQueryErrorV1::EvidenceTampered)
    }

    fn evidence_values(&self) -> Vec<Value> {
        let mut unique = BTreeMap::new();
        for entity in self.opened.values() {
            for evidence in entity.evidence() {
                let key = canonical_json_sha256(evidence)
                    .unwrap_or_else(|_| format!("invalid:{}", unique.len()));
                unique.entry(key).or_insert_with(|| evidence.clone());
            }
        }
        unique.into_values().collect()
    }

    fn opened_record_count(&self) -> u64 {
        u64::try_from(self.opened.len()).unwrap_or(u64::MAX)
    }
}

pub fn write_graph_query_evidence_index_v1(
    context: &CallContext,
    evidence_root: &Path,
    expected: &FileQueryExpectedIdentitiesV1,
    query_manifest_ref: &FileReceiptRef,
    index_manifest_sha256: &str,
    entities: &[GraphQueryEntityV1],
) -> Result<FileReceiptRef, FileGraphQueryErrorV1> {
    let has_knowledge = entities
        .iter()
        .any(|entity| matches!(entity, GraphQueryEntityV1::KnowledgeNode { .. }));
    if has_knowledge && context.transport != crate::TransportKind::Test {
        return Err(FileGraphQueryErrorV1::KnowledgeUnattested);
    }
    let assurance = if has_knowledge {
        KnowledgeEvidenceAssuranceV1::FixtureOnlyUnattested
    } else {
        KnowledgeEvidenceAssuranceV1::StructuralOnly
    };
    write_graph_query_evidence_index_internal(
        context,
        evidence_root,
        expected,
        query_manifest_ref,
        index_manifest_sha256,
        entities,
        assurance,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn write_graph_query_evidence_index_from_verified_overlay_v1(
    context: &CallContext,
    evidence_root: &Path,
    expected: &FileQueryExpectedIdentitiesV1,
    query_manifest_ref: &FileReceiptRef,
    index_manifest_sha256: &str,
    entities: &[GraphQueryEntityV1],
    overlay_input: &KnowledgeOverlayBuildInputV2,
) -> Result<FileReceiptRef, FileGraphQueryErrorV1> {
    let overlay = build_knowledge_overlay_v2(overlay_input)
        .map_err(|_| FileGraphQueryErrorV1::KnowledgeUnattested)?;
    if overlay.source_snapshot_exact_set_sha256 != expected.source_identity
        || overlay.structural_graph_sha256 != expected.graph_identity
        || overlay.overlay_sha256 != expected.overlay_identity
    {
        return Err(FileGraphQueryErrorV1::StaleIndex);
    }
    validate_knowledge_entities_against_overlay(entities, &overlay)?;
    let replay_sha256 =
        canonical_json_sha256(&overlay).map_err(|_| FileGraphQueryErrorV1::KnowledgeUnattested)?;
    write_graph_query_evidence_index_internal(
        context,
        evidence_root,
        expected,
        query_manifest_ref,
        index_manifest_sha256,
        entities,
        KnowledgeEvidenceAssuranceV1::VerifiedOverlayReplay,
        Some(replay_sha256),
    )
}

#[allow(clippy::too_many_arguments)]
fn write_graph_query_evidence_index_internal(
    context: &CallContext,
    evidence_root: &Path,
    expected: &FileQueryExpectedIdentitiesV1,
    query_manifest_ref: &FileReceiptRef,
    index_manifest_sha256: &str,
    entities: &[GraphQueryEntityV1],
    knowledge_assurance: KnowledgeEvidenceAssuranceV1,
    overlay_replay_sha256: Option<String>,
) -> Result<FileReceiptRef, FileGraphQueryErrorV1> {
    validate_expected(expected)?;
    query_manifest_ref
        .validate()
        .map_err(|_| FileGraphQueryErrorV1::InvalidRequest)?;
    validate_sha256(index_manifest_sha256).map_err(|_| FileGraphQueryErrorV1::InvalidRequest)?;
    if entities.is_empty() || entities.len() > MAX_EVIDENCE_RECORDS {
        return Err(FileGraphQueryErrorV1::ResourceBudgetExceeded);
    }
    let evidence_root = authorize_write_root(context, evidence_root)?;
    let mut sorted = entities.to_vec();
    sorted.sort_by(|left, right| left.entity_id().cmp(right.entity_id()));
    if sorted
        .windows(2)
        .any(|pair| pair[0].entity_id() == pair[1].entity_id())
    {
        return Err(FileGraphQueryErrorV1::InvalidRequest);
    }
    let admitted_evidence_ids = sorted
        .iter()
        .filter(|entity| !matches!(entity, GraphQueryEntityV1::KnowledgeNode { .. }))
        .flat_map(GraphQueryEntityV1::evidence_ids)
        .collect::<BTreeSet<_>>();
    for entity in &sorted {
        if let GraphQueryEntityV1::KnowledgeNode {
            structural_evidence_ids,
            ..
        } = entity
            && structural_evidence_ids
                .iter()
                .any(|identity| !admitted_evidence_ids.contains(identity.as_str()))
        {
            return Err(FileGraphQueryErrorV1::InvalidRequest);
        }
    }
    validate_evidence_coverage_against_query_index(
        context,
        &evidence_root,
        query_manifest_ref,
        index_manifest_sha256,
        &sorted,
    )?;
    let mut entries = Vec::with_capacity(sorted.len());
    for entity in sorted {
        validate_entity(&entity)?;
        let mut record = FileGraphEvidenceRecordV1 {
            schema_version: FILE_GRAPH_EVIDENCE_RECORD_SCHEMA_V1.to_owned(),
            entity,
            record_sha256: String::new(),
        };
        record.record_sha256 = evidence_record_content_sha256(&record)?;
        let relative_path = format!(
            "records/{}.json",
            hex::encode(Sha256::digest(record.entity.entity_id().as_bytes()))
        );
        let bytes = serde_json::to_vec_pretty(&record)
            .map_err(|_| FileGraphQueryErrorV1::InvalidRequest)?;
        if bytes.is_empty() || bytes.len() as u64 > MAX_EVIDENCE_RECORD_BYTES {
            return Err(FileGraphQueryErrorV1::ResourceBudgetExceeded);
        }
        publish_immutable_json(
            context,
            &evidence_root.join(&relative_path),
            &record,
            "v03_q04_evidence_record_after_temp_sync_before_rename",
        )
        .map_err(map_durable_error)?;
        entries.push(FileGraphEvidenceEntryV1 {
            entity_id: record.entity.entity_id().to_owned(),
            relative_path,
            content_sha256: record.record_sha256,
            file_sha256: raw_sha256(&bytes),
            byte_len: bytes.len() as u64,
        });
    }
    let mut manifest = FileGraphEvidenceManifestV1 {
        schema_version: FILE_GRAPH_EVIDENCE_MANIFEST_SCHEMA_V1.to_owned(),
        source_identity: expected.source_identity.clone(),
        graph_identity: expected.graph_identity.clone(),
        overlay_identity: expected.overlay_identity.clone(),
        query_manifest_ref: query_manifest_ref.clone(),
        index_manifest_sha256: index_manifest_sha256.to_owned(),
        knowledge_assurance,
        overlay_replay_sha256,
        records: entries,
        manifest_sha256: String::new(),
    };
    manifest.manifest_sha256 = evidence_manifest_content_sha256(&manifest)?;
    validate_evidence_manifest(&manifest)?;
    validate_manifest_assurance(context, &manifest)?;
    let relative_path = format!(
        "manifests/{}.json",
        manifest
            .manifest_sha256
            .strip_prefix("sha256:")
            .ok_or(FileGraphQueryErrorV1::InvalidRequest)?
    );
    let bytes =
        serde_json::to_vec_pretty(&manifest).map_err(|_| FileGraphQueryErrorV1::InvalidRequest)?;
    if bytes.len() as u64 > MAX_EVIDENCE_MANIFEST_BYTES {
        return Err(FileGraphQueryErrorV1::ResourceBudgetExceeded);
    }
    let manifest_ref = FileReceiptRef {
        path: relative_path,
        sha256: raw_sha256(&bytes),
    };
    let manifest_path = evidence_root.join(&manifest_ref.path);
    let manifest_was_present = match fs::symlink_metadata(&manifest_path) {
        Ok(_) => true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(_) => return Err(FileGraphQueryErrorV1::Io),
    };
    if manifest_was_present {
        let existing = read_bound_file(
            context,
            &evidence_root,
            Path::new(&manifest_ref.path),
            MAX_EVIDENCE_MANIFEST_BYTES,
        )?;
        if existing.sha256 != manifest_ref.sha256 || existing.bytes != bytes {
            return Err(FileGraphQueryErrorV1::EvidenceTampered);
        }
        read_continuation_authority_v1(context, &evidence_root, &manifest_ref)?;
        return Ok(manifest_ref);
    }
    create_continuation_authority_v1(context, &evidence_root, &manifest_ref)?;
    crate::durable::pause_at_fault(context, "v03_q04_authority_after_publish_before_manifest")
        .map_err(map_durable_error)?;
    publish_immutable_json(
        context,
        &manifest_path,
        &manifest,
        "v03_q04_evidence_manifest_after_temp_sync_before_rename",
    )
    .map_err(map_durable_error)?;
    Ok(manifest_ref)
}

fn continuation_authority_content_sha256_v1(
    authority: &FileGraphContinuationAuthorityV1,
) -> Result<String, FileGraphQueryErrorV1> {
    let mut content = authority.clone();
    content.authority_sha256.clear();
    canonical_json_sha256(&content).map_err(|_| FileGraphQueryErrorV1::InvalidRequest)
}

fn continuation_authority_relative_path_v1(
    evidence_manifest_ref: &FileReceiptRef,
) -> Result<PathBuf, FileGraphQueryErrorV1> {
    evidence_manifest_ref
        .validate()
        .map_err(|_| FileGraphQueryErrorV1::EvidenceTampered)?;
    let digest = evidence_manifest_ref
        .sha256
        .strip_prefix("sha256:")
        .ok_or(FileGraphQueryErrorV1::EvidenceTampered)?;
    Ok(PathBuf::from(format!("control/{digest}.json")))
}

fn validate_continuation_authority_v1(
    authority: &FileGraphContinuationAuthorityV1,
    evidence_manifest_ref: &FileReceiptRef,
) -> Result<[u8; 32], FileGraphQueryErrorV1> {
    if authority.schema_version != FILE_GRAPH_CONTINUATION_AUTHORITY_SCHEMA_V1
        || authority.evidence_manifest_ref != *evidence_manifest_ref
        || authority.authority_sha256 != continuation_authority_content_sha256_v1(authority)?
        || authority.key_hex.len() != 64
    {
        return Err(FileGraphQueryErrorV1::ContinuationInvalid);
    }
    let bytes =
        hex::decode(&authority.key_hex).map_err(|_| FileGraphQueryErrorV1::ContinuationInvalid)?;
    bytes
        .try_into()
        .map_err(|_| FileGraphQueryErrorV1::ContinuationInvalid)
}

fn read_continuation_authority_v1(
    context: &CallContext,
    evidence_root: &Path,
    evidence_manifest_ref: &FileReceiptRef,
) -> Result<(LoadedContinuationAuthorityV1, u64), FileGraphQueryErrorV1> {
    let relative = continuation_authority_relative_path_v1(evidence_manifest_ref)?;
    let root = authorize_plain_root(context, evidence_root)?;
    let read = read_bound_file(context, &root, &relative, MAX_CONTINUATION_AUTHORITY_BYTES)?;
    let authority: FileGraphContinuationAuthorityV1 = serde_json::from_slice(&read.bytes)
        .map_err(|_| FileGraphQueryErrorV1::ContinuationInvalid)?;
    let key = validate_continuation_authority_v1(&authority, evidence_manifest_ref)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let metadata =
            fs::symlink_metadata(root.join(&relative)).map_err(|_| FileGraphQueryErrorV1::Io)?;
        if !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(FileGraphQueryErrorV1::UnsafePath);
        }
    }
    let bytes_read = u64::try_from(read.bytes.len())
        .map_err(|_| FileGraphQueryErrorV1::ResourceBudgetExceeded)?;
    Ok((
        LoadedContinuationAuthorityV1 {
            authority_sha256: authority.authority_sha256,
            key,
        },
        bytes_read,
    ))
}

fn create_continuation_authority_v1(
    context: &CallContext,
    evidence_root: &Path,
    evidence_manifest_ref: &FileReceiptRef,
) -> Result<(), FileGraphQueryErrorV1> {
    let root = authorize_plain_root(context, evidence_root)?;
    let mut key = [0_u8; 32];
    getrandom::fill(&mut key).map_err(|_| FileGraphQueryErrorV1::Io)?;
    let mut authority = FileGraphContinuationAuthorityV1 {
        schema_version: FILE_GRAPH_CONTINUATION_AUTHORITY_SCHEMA_V1.to_owned(),
        evidence_manifest_ref: evidence_manifest_ref.clone(),
        key_hex: hex::encode(key),
        authority_sha256: String::new(),
    };
    authority.authority_sha256 = continuation_authority_content_sha256_v1(&authority)?;
    let relative = continuation_authority_relative_path_v1(evidence_manifest_ref)?;
    let path = root.join(&relative);
    if path.exists() {
        read_continuation_authority_v1(context, &root, evidence_manifest_ref)?;
        return Ok(());
    }
    match publish_private_immutable_json(
        context,
        &path,
        &authority,
        "v03_q04_continuation_authority_after_temp_sync_before_rename",
    ) {
        Ok(_) => {}
        Err(error) if error.kind == DurableErrorKind::Conflict => {
            read_continuation_authority_v1(context, &root, evidence_manifest_ref)?;
        }
        Err(error) => return Err(map_durable_error(error)),
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn execute_file_graph_operation_v1(
    context: &CallContext,
    query_root: &Path,
    query_manifest_ref: &FileReceiptRef,
    evidence_root: &Path,
    evidence_manifest_ref: &FileReceiptRef,
    expected: &FileQueryExpectedIdentitiesV1,
    operation: FileGraphQueryOperationV1,
    payload: &Value,
) -> Result<Value, FileGraphQueryErrorV1> {
    validate_expected(expected)?;
    let mut preflight_bytes_read = preflight_evidence_identity(
        context,
        evidence_root,
        evidence_manifest_ref,
        expected,
        query_manifest_ref,
    )?;
    let continuation_authority = matches!(
        operation,
        FileGraphQueryOperationV1::Neighbors
            | FileGraphQueryOperationV1::Impact
            | FileGraphQueryOperationV1::Explain
            | FileGraphQueryOperationV1::Search
    )
    .then(|| read_continuation_authority_v1(context, evidence_root, evidence_manifest_ref))
    .transpose()?;
    if let Some((_, bytes_read)) = &continuation_authority {
        preflight_bytes_read = preflight_bytes_read
            .checked_add(*bytes_read)
            .ok_or(FileGraphQueryErrorV1::ResourceBudgetExceeded)?;
    }
    let value = match operation {
        FileGraphQueryOperationV1::Neighbors => execute_neighbors(
            context,
            query_root,
            query_manifest_ref,
            evidence_root,
            evidence_manifest_ref,
            expected,
            payload,
            preflight_bytes_read,
            &continuation_authority
                .as_ref()
                .ok_or(FileGraphQueryErrorV1::ContinuationInvalid)?
                .0,
        ),
        FileGraphQueryOperationV1::Path => execute_path(
            context,
            query_root,
            query_manifest_ref,
            evidence_root,
            evidence_manifest_ref,
            expected,
            payload,
            preflight_bytes_read,
        ),
        FileGraphQueryOperationV1::Impact => execute_impact(
            context,
            query_root,
            query_manifest_ref,
            evidence_root,
            evidence_manifest_ref,
            expected,
            payload,
            preflight_bytes_read,
            &continuation_authority
                .as_ref()
                .ok_or(FileGraphQueryErrorV1::ContinuationInvalid)?
                .0,
        ),
        FileGraphQueryOperationV1::Explain => execute_explain(
            context,
            query_root,
            query_manifest_ref,
            evidence_root,
            evidence_manifest_ref,
            expected,
            payload,
            preflight_bytes_read,
            &continuation_authority
                .as_ref()
                .ok_or(FileGraphQueryErrorV1::ContinuationInvalid)?
                .0,
        ),
        FileGraphQueryOperationV1::Trace => execute_trace(
            context,
            query_root,
            query_manifest_ref,
            evidence_root,
            evidence_manifest_ref,
            expected,
            payload,
            preflight_bytes_read,
        ),
        FileGraphQueryOperationV1::Search => execute_search(
            context,
            query_root,
            query_manifest_ref,
            evidence_root,
            evidence_manifest_ref,
            expected,
            payload,
            preflight_bytes_read,
            &continuation_authority
                .as_ref()
                .ok_or(FileGraphQueryErrorV1::ContinuationInvalid)?
                .0,
        ),
    }?;
    let encoded = serde_json::to_vec(&value).map_err(|_| FileGraphQueryErrorV1::InvalidRequest)?;
    if encoded.len() > MAX_OPERATION_RESPONSE_BYTES {
        return Err(FileGraphQueryErrorV1::ResourceBudgetExceeded);
    }
    Ok(value)
}

fn preflight_evidence_identity(
    context: &CallContext,
    evidence_root: &Path,
    evidence_manifest_ref: &FileReceiptRef,
    expected: &FileQueryExpectedIdentitiesV1,
    query_manifest_ref: &FileReceiptRef,
) -> Result<u64, FileGraphQueryErrorV1> {
    evidence_manifest_ref
        .validate()
        .map_err(|_| FileGraphQueryErrorV1::EvidenceTampered)?;
    if !safe_relative_path(&evidence_manifest_ref.path, "manifests") {
        return Err(FileGraphQueryErrorV1::UnsafePath);
    }
    let root = authorize_plain_root(context, evidence_root)?;
    let read = read_bound_file(
        context,
        &root,
        Path::new(&evidence_manifest_ref.path),
        MAX_EVIDENCE_MANIFEST_BYTES,
    )?;
    if read.sha256 != evidence_manifest_ref.sha256 {
        return Err(FileGraphQueryErrorV1::EvidenceTampered);
    }
    let manifest: FileGraphEvidenceManifestV1 =
        serde_json::from_slice(&read.bytes).map_err(|_| FileGraphQueryErrorV1::EvidenceTampered)?;
    validate_evidence_manifest(&manifest)?;
    validate_manifest_assurance(context, &manifest)?;
    if manifest.source_identity != expected.source_identity
        || manifest.graph_identity != expected.graph_identity
        || manifest.overlay_identity != expected.overlay_identity
        || manifest.query_manifest_ref != *query_manifest_ref
    {
        return Err(FileGraphQueryErrorV1::StaleIndex);
    }
    u64::try_from(read.bytes.len()).map_err(|_| FileGraphQueryErrorV1::ResourceBudgetExceeded)
}

fn validate_manifest_assurance(
    context: &CallContext,
    manifest: &FileGraphEvidenceManifestV1,
) -> Result<(), FileGraphQueryErrorV1> {
    if manifest.knowledge_assurance == KnowledgeEvidenceAssuranceV1::FixtureOnlyUnattested
        && context.transport != crate::TransportKind::Test
    {
        return Err(FileGraphQueryErrorV1::KnowledgeUnattested);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn execute_search(
    context: &CallContext,
    query_root: &Path,
    query_manifest_ref: &FileReceiptRef,
    evidence_root: &Path,
    evidence_manifest_ref: &FileReceiptRef,
    expected: &FileQueryExpectedIdentitiesV1,
    payload: &Value,
    preflight_bytes_read: u64,
    authority: &LoadedContinuationAuthorityV1,
) -> Result<Value, FileGraphQueryErrorV1> {
    let object = closed_object(payload, &["query", "max_results", "continuation"])?;
    let query = required_string(object, "query")?;
    let max_results = bounded_results(object)?;
    let request_sha256 = request_sha256(FileGraphQueryOperationV1::Search, payload)?;
    let continuation = optional_string(object, "continuation")?;
    let mut metrics = QueryMetricsV1::default();
    let page = if let Some(token) = continuation {
        let decoded = decode_continuation(token, authority)?;
        validate_continuation_header(
            &decoded,
            FileGraphQueryOperationV1::Search,
            &request_sha256,
            evidence_manifest_ref,
        )?;
        let ContinuationStateV1::Search { previous_page } = decoded.state else {
            return Err(FileGraphQueryErrorV1::ContinuationInvalid);
        };
        let q03_token = previous_page
            .receipt
            .continuation
            .clone()
            .ok_or(FileGraphQueryErrorV1::ContinuationInvalid)?;
        execute_next_file_query_page_v1(
            context,
            query_root,
            query_manifest_ref,
            expected,
            &previous_page,
            &FileQueryRequestV1 {
                lookup: FileQueryLookupV1::Search {
                    query: query.to_owned(),
                },
                max_results: max_results as u64,
                continuation: Some(q03_token),
            },
        )
        .map_err(map_query_error)?
    } else {
        execute_first_file_query_page_v1(
            context,
            query_root,
            query_manifest_ref,
            expected,
            &FileQueryRequestV1 {
                lookup: FileQueryLookupV1::Search {
                    query: query.to_owned(),
                },
                max_results: max_results as u64,
                continuation: None,
            },
        )
        .map_err(map_query_error)?
    };
    metrics.observe(&page)?;
    let mut reader = EvidenceReaderV1::open(
        context,
        evidence_root,
        evidence_manifest_ref,
        expected,
        query_manifest_ref,
        &page.receipt.index_manifest_sha256,
        preflight_bytes_read,
    )?;
    let mut matches = Vec::new();
    let mut overlay_nodes = Vec::new();
    for hit in &page.lexical_hits {
        let entity = selected_entity(&mut reader, &hit.node_id)?.clone();
        if !entity.evidence_ids().contains(hit.evidence_ref.as_str()) {
            return Err(FileGraphQueryErrorV1::EvidenceTampered);
        }
        let matched_terms = hit.matched_terms.clone();
        let score = u64::try_from(matched_terms.len())
            .ok()
            .and_then(|value| value.checked_mul(100))
            .and_then(|value| value.checked_add(entity.evidence().len() as u64))
            .ok_or(FileGraphQueryErrorV1::ResourceBudgetExceeded)?;
        matches.push(search_match(&entity, matched_terms, score));
        if let GraphQueryEntityV1::KnowledgeNode {
            entity_id,
            knowledge_kind,
            claim_id,
            structural_evidence_ids,
            overlay_provenance,
            ..
        } = entity
        {
            overlay_nodes.push(json!({
                "id": entity_id,
                "kind": knowledge_kind,
                "claim_id": claim_id,
                "structural_evidence_ids": structural_evidence_ids,
                "provenance": overlay_provenance,
            }));
        }
    }
    let truncated = page.receipt.truncation == QueryTruncationStateV1::Truncated;
    let continuation = if truncated {
        Some(encode_continuation(
            FileGraphContinuationV1 {
                schema_version: FILE_GRAPH_CONTINUATION_SCHEMA_V1.to_owned(),
                operation: FileGraphQueryOperationV1::Search,
                request_sha256,
                evidence_manifest_sha256: evidence_manifest_ref.sha256.clone(),
                authority_sha256: authority.authority_sha256.clone(),
                state: ContinuationStateV1::Search {
                    previous_page: Box::new(page),
                },
                continuation_sha256: String::new(),
                continuation_mac_sha256: String::new(),
            },
            authority,
        )?)
    } else {
        None
    };
    let answer_state = if matches.is_empty() {
        "no_answer"
    } else {
        "answered"
    };
    validate_total_read_budget(&metrics, &reader)?;
    let evidence_pack = claim_evidence_pack(
        expected,
        evidence_manifest_ref,
        &reader,
        &metrics,
        overlay_nodes,
    );
    Ok(json!({
        "schema_version": "gtkg.claim-aware-query-result/v2",
        "operation_id": "graph.search",
        "mode": "file_index_claim_aware",
        "result": {
            "query": query,
            "matches": matches,
            "knowledge_conflicts": [],
            "answer_state": answer_state,
            "truncated": truncated,
            "continuation": continuation,
        },
        "evidence_pack": evidence_pack,
    }))
}

#[allow(clippy::too_many_arguments)]
fn execute_neighbors(
    context: &CallContext,
    query_root: &Path,
    query_manifest_ref: &FileReceiptRef,
    evidence_root: &Path,
    evidence_manifest_ref: &FileReceiptRef,
    expected: &FileQueryExpectedIdentitiesV1,
    payload: &Value,
    preflight_bytes_read: u64,
    authority: &LoadedContinuationAuthorityV1,
) -> Result<Value, FileGraphQueryErrorV1> {
    let object = closed_object(
        payload,
        &[
            "node_id",
            "direction",
            "max_results",
            "continuation",
            "previous_page",
        ],
    )?;
    let node_id = required_string(object, "node_id")?;
    let direction = optional_string(object, "direction")?.unwrap_or("both");
    if !matches!(direction, "incoming" | "outgoing" | "both") {
        return Err(FileGraphQueryErrorV1::InvalidRequest);
    }
    let max_results = bounded_results(object)?;
    let request_sha256 = request_sha256(FileGraphQueryOperationV1::Neighbors, payload)?;
    let mut metrics = QueryMetricsV1::default();
    let directions = match direction {
        "incoming" => vec![AdjacencyDirectionV1::Incoming],
        "outgoing" => vec![AdjacencyDirectionV1::Outgoing],
        _ => vec![
            AdjacencyDirectionV1::Incoming,
            AdjacencyDirectionV1::Outgoing,
        ],
    };
    let mut records = Vec::new();
    for query_direction in directions {
        let page = adjacency_page(
            context,
            query_root,
            query_manifest_ref,
            expected,
            node_id,
            query_direction,
        )?;
        metrics.observe(&page)?;
        records.extend(page.adjacency_edges);
    }
    records.sort_by(|left, right| {
        left.edge_id
            .cmp(&right.edge_id)
            .then_with(|| left.node_id.cmp(&right.node_id))
    });
    records.dedup();
    let full_result_sha256 =
        canonical_json_sha256(&records).map_err(|_| FileGraphQueryErrorV1::InvalidRequest)?;
    let (start, end, continuation) = slice_bounds(
        FileGraphQueryOperationV1::Neighbors,
        object,
        &request_sha256,
        evidence_manifest_ref,
        authority,
        max_results,
        &records,
        &full_result_sha256,
    )?;
    let index_manifest_sha256 = first_index_identity(&metrics)?;
    let mut reader = EvidenceReaderV1::open(
        context,
        evidence_root,
        evidence_manifest_ref,
        expected,
        query_manifest_ref,
        index_manifest_sha256,
        preflight_bytes_read,
    )?;
    require_node(reader.entity(node_id)?)?;
    let mut rows = Vec::new();
    for record in &records[start..end] {
        let edge = selected_entity(&mut reader, &record.edge_id)?.clone();
        let edge = require_matching_edge(&edge, record)?;
        rows.push(json!({
            "edge_id": record.edge_id,
            "edge_kind": edge.edge_kind,
            "direction": if record.source_node_id == node_id { "outgoing" } else { "incoming" },
            "neighbor_node_id": if record.source_node_id == node_id { &record.target_node_id } else { &record.source_node_id },
            "target_reference": edge.target_reference,
            "resolution": resolution_name(record.resolution_state),
        }));
    }
    structural_response(
        FileGraphQueryOperationV1::Neighbors,
        json!({"node_id": node_id, "direction": direction, "neighbors": rows}),
        end < records.len(),
        continuation,
        expected,
        evidence_manifest_ref,
        &reader,
        &metrics,
    )
}

#[allow(clippy::too_many_arguments)]
fn execute_path(
    context: &CallContext,
    query_root: &Path,
    query_manifest_ref: &FileReceiptRef,
    evidence_root: &Path,
    evidence_manifest_ref: &FileReceiptRef,
    expected: &FileQueryExpectedIdentitiesV1,
    payload: &Value,
    preflight_bytes_read: u64,
) -> Result<Value, FileGraphQueryErrorV1> {
    let object = closed_object(payload, &["source_node_id", "target_node_id", "max_depth"])?;
    let source = required_string(object, "source_node_id")?;
    let target = required_string(object, "target_node_id")?;
    let max_depth = bounded_depth(object)?;
    let mut metrics = QueryMetricsV1::default();
    let mut queue = VecDeque::from([(source.to_owned(), Vec::<String>::new())]);
    let mut seen = BTreeSet::from([source.to_owned()]);
    let mut found = None;
    while let Some((node_id, edge_ids)) = queue.pop_front() {
        if node_id == target {
            found = Some(edge_ids);
            break;
        }
        if edge_ids.len() == max_depth {
            continue;
        }
        let page = adjacency_page(
            context,
            query_root,
            query_manifest_ref,
            expected,
            &node_id,
            AdjacencyDirectionV1::Outgoing,
        )?;
        metrics.observe(&page)?;
        for edge in page
            .adjacency_edges
            .iter()
            .filter(|edge| edge.resolution_state == QueryResolutionStateV1::Resolved)
        {
            if seen.insert(edge.target_node_id.clone()) {
                if seen.len() > MAX_VISITED_NODES {
                    return Err(FileGraphQueryErrorV1::ResourceBudgetExceeded);
                }
                let mut next = edge_ids.clone();
                next.push(edge.edge_id.clone());
                queue.push_back((edge.target_node_id.clone(), next));
            }
        }
    }
    if metrics.plans.is_empty() {
        let page = adjacency_page(
            context,
            query_root,
            query_manifest_ref,
            expected,
            source,
            AdjacencyDirectionV1::Outgoing,
        )?;
        metrics.observe(&page)?;
    }
    let index_manifest_sha256 = first_index_identity(&metrics)?;
    let mut reader = EvidenceReaderV1::open(
        context,
        evidence_root,
        evidence_manifest_ref,
        expected,
        query_manifest_ref,
        index_manifest_sha256,
        preflight_bytes_read,
    )?;
    require_node(reader.entity(source)?)?;
    require_node(reader.entity(target)?)?;
    let (found_flag, node_ids, edge_ids) = if let Some(edge_ids) = found {
        let mut node_ids = vec![source.to_owned()];
        let mut current = source.to_owned();
        for edge_id in &edge_ids {
            let entity = selected_entity(&mut reader, edge_id)?.clone();
            let GraphQueryEntityV1::StructuralEdge {
                source_node_id,
                target_node_id,
                resolution_state,
                ..
            } = entity
            else {
                return Err(FileGraphQueryErrorV1::EvidenceTampered);
            };
            if source_node_id != current || resolution_state != QueryResolutionStateV1::Resolved {
                return Err(FileGraphQueryErrorV1::EvidenceTampered);
            }
            current = target_node_id.ok_or(FileGraphQueryErrorV1::EvidenceTampered)?;
            node_ids.push(current.clone());
        }
        if current != target {
            return Err(FileGraphQueryErrorV1::EvidenceTampered);
        }
        (true, node_ids, edge_ids)
    } else {
        (false, Vec::new(), Vec::new())
    };
    structural_response(
        FileGraphQueryOperationV1::Path,
        json!({
            "source_node_id": source,
            "target_node_id": target,
            "max_depth": max_depth,
            "found": found_flag,
            "node_ids": node_ids,
            "edge_ids": edge_ids,
        }),
        false,
        None,
        expected,
        evidence_manifest_ref,
        &reader,
        &metrics,
    )
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct ImpactCandidateV1 {
    edge_id: String,
    node_id: Option<String>,
    target_reference: String,
    label: String,
    depth: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct RawImpactCandidateV1 {
    record: AdjacencyEdgeRecordV1,
    depth: usize,
}

#[allow(clippy::too_many_arguments)]
fn execute_impact(
    context: &CallContext,
    query_root: &Path,
    query_manifest_ref: &FileReceiptRef,
    evidence_root: &Path,
    evidence_manifest_ref: &FileReceiptRef,
    expected: &FileQueryExpectedIdentitiesV1,
    payload: &Value,
    preflight_bytes_read: u64,
    authority: &LoadedContinuationAuthorityV1,
) -> Result<Value, FileGraphQueryErrorV1> {
    let object = closed_object(
        payload,
        &[
            "node_id",
            "max_depth",
            "max_results",
            "continuation",
            "previous_page",
        ],
    )?;
    let source = required_string(object, "node_id")?;
    let max_depth = bounded_depth(object)?;
    let max_results = bounded_results(object)?;
    let request_sha256 = request_sha256(FileGraphQueryOperationV1::Impact, payload)?;
    let mut metrics = QueryMetricsV1::default();
    let mut queue = VecDeque::from([(source.to_owned(), 0_usize)]);
    let mut visited = BTreeMap::from([(source.to_owned(), 0_usize)]);
    let mut raw_rows = Vec::new();
    while let Some((node_id, depth)) = queue.pop_front() {
        if depth == max_depth {
            continue;
        }
        let page = adjacency_page(
            context,
            query_root,
            query_manifest_ref,
            expected,
            &node_id,
            AdjacencyDirectionV1::Outgoing,
        )?;
        metrics.observe(&page)?;
        for record in page.adjacency_edges {
            let next_depth = depth + 1;
            if record.resolution_state == QueryResolutionStateV1::Resolved {
                let target = record.target_node_id.clone();
                if visited.get(&target).is_none_or(|known| *known > next_depth) {
                    if visited.len() >= MAX_VISITED_NODES {
                        return Err(FileGraphQueryErrorV1::ResourceBudgetExceeded);
                    }
                    visited.insert(target.clone(), next_depth);
                    queue.push_back((target, next_depth));
                }
            }
            raw_rows.push(RawImpactCandidateV1 {
                record,
                depth: next_depth,
            });
        }
    }
    let index_manifest_sha256 = first_index_identity(&metrics)?;
    let mut reader = EvidenceReaderV1::open(
        context,
        evidence_root,
        evidence_manifest_ref,
        expected,
        query_manifest_ref,
        index_manifest_sha256,
        preflight_bytes_read,
    )?;
    require_node(reader.entity(source)?)?;
    let mut rows = Vec::new();
    for raw in raw_rows {
        let edge_entity = selected_entity(&mut reader, &raw.record.edge_id)?.clone();
        let edge = require_matching_edge(&edge_entity, &raw.record)?;
        match raw.record.resolution_state {
            QueryResolutionStateV1::Resolved => rows.push(ImpactCandidateV1 {
                edge_id: raw.record.edge_id,
                node_id: Some(raw.record.target_node_id),
                target_reference: edge.target_reference,
                label: "confirmed".to_owned(),
                depth: raw.depth,
            }),
            QueryResolutionStateV1::Ambiguous => {
                if edge.candidate_node_ids.is_empty() {
                    return Err(FileGraphQueryErrorV1::EvidenceTampered);
                }
                for candidate in edge.candidate_node_ids {
                    rows.push(ImpactCandidateV1 {
                        edge_id: raw.record.edge_id.clone(),
                        node_id: Some(candidate),
                        target_reference: edge.target_reference.clone(),
                        label: "possible".to_owned(),
                        depth: raw.depth,
                    });
                }
            }
            QueryResolutionStateV1::Unresolved | QueryResolutionStateV1::Unsupported => {
                rows.push(ImpactCandidateV1 {
                    edge_id: raw.record.edge_id,
                    node_id: None,
                    target_reference: edge.target_reference,
                    label: "unknown".to_owned(),
                    depth: raw.depth,
                });
            }
        }
    }
    rows.sort_by(|left, right| {
        left.depth
            .cmp(&right.depth)
            .then_with(|| left.edge_id.cmp(&right.edge_id))
            .then_with(|| left.node_id.cmp(&right.node_id))
    });
    let full_result_sha256 =
        canonical_json_sha256(&rows).map_err(|_| FileGraphQueryErrorV1::InvalidRequest)?;
    let (start, end, continuation) = slice_bounds(
        FileGraphQueryOperationV1::Impact,
        object,
        &request_sha256,
        evidence_manifest_ref,
        authority,
        max_results,
        &rows,
        &full_result_sha256,
    )?;
    for row in &rows[start..end] {
        if let Some(node_id) = &row.node_id {
            require_node(selected_entity(&mut reader, node_id)?)?;
        }
    }
    structural_response(
        FileGraphQueryOperationV1::Impact,
        json!({"node_id": source, "max_depth": max_depth, "impacts": &rows[start..end]}),
        end < rows.len(),
        continuation,
        expected,
        evidence_manifest_ref,
        &reader,
        &metrics,
    )
}

#[allow(clippy::too_many_arguments)]
fn execute_explain(
    context: &CallContext,
    query_root: &Path,
    query_manifest_ref: &FileReceiptRef,
    evidence_root: &Path,
    evidence_manifest_ref: &FileReceiptRef,
    expected: &FileQueryExpectedIdentitiesV1,
    payload: &Value,
    preflight_bytes_read: u64,
    authority: &LoadedContinuationAuthorityV1,
) -> Result<Value, FileGraphQueryErrorV1> {
    let object = closed_object(
        payload,
        &["node_id", "max_results", "continuation", "previous_page"],
    )?;
    let node_id = required_string(object, "node_id")?;
    let max_results = bounded_results(object)?;
    let request_sha256 = request_sha256(FileGraphQueryOperationV1::Explain, payload)?;
    let mut metrics = QueryMetricsV1::default();
    let mut records = Vec::new();
    for direction in [
        AdjacencyDirectionV1::Incoming,
        AdjacencyDirectionV1::Outgoing,
    ] {
        let page = adjacency_page(
            context,
            query_root,
            query_manifest_ref,
            expected,
            node_id,
            direction,
        )?;
        metrics.observe(&page)?;
        records.extend(page.adjacency_edges);
    }
    records.sort_by(|left, right| left.edge_id.cmp(&right.edge_id));
    records.dedup_by(|left, right| left.edge_id == right.edge_id);
    let full_result_sha256 =
        canonical_json_sha256(&records).map_err(|_| FileGraphQueryErrorV1::InvalidRequest)?;
    let (start, end, continuation) = slice_bounds(
        FileGraphQueryOperationV1::Explain,
        object,
        &request_sha256,
        evidence_manifest_ref,
        authority,
        max_results,
        &records,
        &full_result_sha256,
    )?;
    let index_manifest_sha256 = first_index_identity(&metrics)?;
    let mut reader = EvidenceReaderV1::open(
        context,
        evidence_root,
        evidence_manifest_ref,
        expected,
        query_manifest_ref,
        index_manifest_sha256,
        preflight_bytes_read,
    )?;
    let node = reader.entity(node_id)?.clone();
    let node_value = node_value(require_node(&node)?);
    let mut relations = Vec::new();
    for record in &records[start..end] {
        let edge = selected_entity(&mut reader, &record.edge_id)?.clone();
        let edge = require_matching_edge(&edge, record)?;
        relations.push(edge_value(edge));
    }
    structural_response(
        FileGraphQueryOperationV1::Explain,
        json!({"node": node_value, "relations": relations}),
        end < records.len(),
        continuation,
        expected,
        evidence_manifest_ref,
        &reader,
        &metrics,
    )
}

#[allow(clippy::too_many_arguments)]
fn execute_trace(
    context: &CallContext,
    query_root: &Path,
    query_manifest_ref: &FileReceiptRef,
    evidence_root: &Path,
    evidence_manifest_ref: &FileReceiptRef,
    expected: &FileQueryExpectedIdentitiesV1,
    payload: &Value,
    preflight_bytes_read: u64,
) -> Result<Value, FileGraphQueryErrorV1> {
    let object = closed_object(payload, &["entity_id"])?;
    let entity_id = required_string(object, "entity_id")?;
    let page = execute_first_file_query_page_v1(
        context,
        query_root,
        query_manifest_ref,
        expected,
        &FileQueryRequestV1 {
            lookup: FileQueryLookupV1::Search {
                query: entity_id.to_owned(),
            },
            max_results: MAX_INTERNAL_RESULTS,
            continuation: None,
        },
    )
    .map_err(map_query_error)?;
    if page.receipt.truncation == QueryTruncationStateV1::Truncated {
        return Err(FileGraphQueryErrorV1::ResourceBudgetExceeded);
    }
    let mut metrics = QueryMetricsV1::default();
    metrics.observe(&page)?;
    let mut reader = EvidenceReaderV1::open(
        context,
        evidence_root,
        evidence_manifest_ref,
        expected,
        query_manifest_ref,
        &page.receipt.index_manifest_sha256,
        preflight_bytes_read,
    )?;
    let entity = reader.entity(entity_id)?.clone();
    let (entity_kind, provenance, unavailable) = match entity {
        GraphQueryEntityV1::StructuralNode {
            structural_provenance,
            ..
        } => (
            "node",
            structural_provenance,
            vec!["accepted_claim", "okf_verification"],
        ),
        GraphQueryEntityV1::StructuralEdge {
            structural_provenance,
            ..
        } => (
            "edge",
            structural_provenance,
            vec!["accepted_claim", "okf_verification"],
        ),
        GraphQueryEntityV1::KnowledgeNode {
            overlay_provenance, ..
        } => ("knowledge", overlay_provenance, Vec::new()),
    };
    structural_response(
        FileGraphQueryOperationV1::Trace,
        json!({
            "entity_id": entity_id,
            "entity_kind": entity_kind,
            "structural_provenance": provenance,
            "unavailable_lineage": unavailable,
            "reason": if unavailable.is_empty() { "lineage is evidence-bound" } else { "structural-only record does not assert accepted knowledge" },
        }),
        false,
        None,
        expected,
        evidence_manifest_ref,
        &reader,
        &metrics,
    )
}

fn adjacency_page(
    context: &CallContext,
    query_root: &Path,
    query_manifest_ref: &FileReceiptRef,
    expected: &FileQueryExpectedIdentitiesV1,
    node_id: &str,
    direction: AdjacencyDirectionV1,
) -> Result<FileQueryPageV1, FileGraphQueryErrorV1> {
    let page = execute_first_file_query_page_v1(
        context,
        query_root,
        query_manifest_ref,
        expected,
        &FileQueryRequestV1 {
            lookup: FileQueryLookupV1::Adjacency {
                node_id: node_id.to_owned(),
                direction,
            },
            max_results: MAX_INTERNAL_RESULTS,
            continuation: None,
        },
    )
    .map_err(map_query_error)?;
    if page.receipt.truncation == QueryTruncationStateV1::Truncated {
        return Err(FileGraphQueryErrorV1::ResourceBudgetExceeded);
    }
    Ok(page)
}

#[allow(clippy::too_many_arguments)]
fn structural_response(
    operation: FileGraphQueryOperationV1,
    result: Value,
    truncated: bool,
    continuation: Option<String>,
    expected: &FileQueryExpectedIdentitiesV1,
    evidence_manifest_ref: &FileReceiptRef,
    reader: &EvidenceReaderV1<'_>,
    metrics: &QueryMetricsV1,
) -> Result<Value, FileGraphQueryErrorV1> {
    validate_total_read_budget(metrics, reader)?;
    let evidence_pack = structural_evidence_pack(expected, evidence_manifest_ref, reader, metrics);
    Ok(json!({
        "schema_version": "gtkg.structural-query-result/v3",
        "operation_id": operation.operation_id(),
        "mode": "file_index_structural",
        "result": result,
        "truncated": truncated,
        "continuation": continuation,
        "evidence_pack": evidence_pack,
    }))
}

fn validate_total_read_budget(
    metrics: &QueryMetricsV1,
    reader: &EvidenceReaderV1<'_>,
) -> Result<(), FileGraphQueryErrorV1> {
    let total = metrics
        .bytes_read
        .checked_add(reader.bytes_read)
        .ok_or(FileGraphQueryErrorV1::ResourceBudgetExceeded)?;
    if total > MAX_OPERATION_QUERY_BYTES {
        return Err(FileGraphQueryErrorV1::ResourceBudgetExceeded);
    }
    Ok(())
}

fn structural_evidence_pack(
    expected: &FileQueryExpectedIdentitiesV1,
    evidence_manifest_ref: &FileReceiptRef,
    reader: &EvidenceReaderV1<'_>,
    metrics: &QueryMetricsV1,
) -> Value {
    json!({
        "schema_version": "gtkg.structural-evidence-pack/v3",
        "graph_readback": {
            "graph_sha256": expected.graph_identity,
            "source_snapshot_exact_set_sha256": expected.source_identity,
            "layer": "structural_only",
            "knowledge_overlay": null,
            "read_mode": "query_index_identity_bound",
        },
        "evidence": reader.evidence_values(),
        "query_index": query_index_evidence(evidence_manifest_ref, reader, metrics),
    })
}

fn claim_evidence_pack(
    expected: &FileQueryExpectedIdentitiesV1,
    evidence_manifest_ref: &FileReceiptRef,
    reader: &EvidenceReaderV1<'_>,
    metrics: &QueryMetricsV1,
    overlay_nodes: Vec<Value>,
) -> Value {
    json!({
        "schema_version": "gtkg.claim-aware-evidence-pack/v2",
        "graph_readback": {
            "graph_sha256": expected.graph_identity,
            "source_snapshot_exact_set_sha256": expected.source_identity,
            "layer": "structural_only",
            "read_mode": "query_index_identity_bound",
        },
        "overlay_readback": {
            "overlay_sha256": expected.overlay_identity,
            "structural_graph_sha256": expected.graph_identity,
            "source_snapshot_exact_set_sha256": expected.source_identity,
            "layer": "knowledge_overlay",
            "read_mode": "entity_evidence_index",
        },
        "overlay_nodes": overlay_nodes,
        "evidence": reader.evidence_values(),
        "query_index": query_index_evidence(evidence_manifest_ref, reader, metrics),
    })
}

fn query_index_evidence(
    evidence_manifest_ref: &FileReceiptRef,
    reader: &EvidenceReaderV1<'_>,
    metrics: &QueryMetricsV1,
) -> Value {
    json!({
        "schema_version": FILE_GRAPH_QUERY_RESULT_SCHEMA_V1,
        "index_manifest_sha256": metrics.plans.first().map(|plan| plan.index_manifest_sha256.as_str()),
        "evidence_manifest_sha256": reader.manifest.manifest_sha256,
        "evidence_manifest_file_sha256": evidence_manifest_ref.sha256,
        "knowledge_assurance": reader.manifest.knowledge_assurance,
        "overlay_replay_sha256": reader.manifest.overlay_replay_sha256,
        "query_plans": metrics.plans,
        "selected_shards": metrics.selected_shards,
        "excluded_shards": metrics.excluded_shards,
        "bytes_read": metrics.bytes_read,
        "evidence_bytes_read": reader.bytes_read,
        "shard_files_opened": metrics.shard_files_opened,
        "evidence_files_opened": reader.opened_record_count(),
        "full_graph_read_count": metrics.full_graph_read_count,
        "database_read_count": metrics.database_read_count,
        "network_call_count": metrics.network_call_count,
        "daemon_call_count": metrics.daemon_call_count,
        "plan_completed_before_shard_read": metrics.plan_completed_before_shard_read,
    })
}

fn search_match(entity: &GraphQueryEntityV1, matched_terms: Vec<String>, score: u64) -> Value {
    match entity {
        GraphQueryEntityV1::StructuralNode {
            entity_id, label, ..
        } => json!({
            "kind": "structural_node",
            "entity_id": entity_id,
            "label": label,
            "knowledge_state": "structural_only",
            "matched_terms": matched_terms,
            "score": score,
        }),
        GraphQueryEntityV1::StructuralEdge {
            entity_id,
            edge_kind,
            target_reference,
            ..
        } => json!({
            "kind": "structural_edge",
            "entity_id": entity_id,
            "label": format!("{edge_kind} {target_reference}"),
            "knowledge_state": "structural_only",
            "matched_terms": matched_terms,
            "score": score,
        }),
        GraphQueryEntityV1::KnowledgeNode {
            entity_id,
            knowledge_kind,
            label,
            claim_id,
            knowledge_state,
            ..
        } => json!({
            "kind": knowledge_kind,
            "entity_id": entity_id,
            "label": label,
            "claim_id": claim_id,
            "knowledge_state": knowledge_state,
            "matched_terms": matched_terms,
            "score": score,
        }),
    }
}

fn node_value(entity: &GraphQueryEntityV1) -> Value {
    let GraphQueryEntityV1::StructuralNode {
        entity_id,
        node_kind,
        label,
        source_logical_path,
        ..
    } = entity
    else {
        return Value::Null;
    };
    json!({
        "id": entity_id,
        "kind": node_kind,
        "label": label,
        "source_logical_path": source_logical_path,
    })
}

struct EdgeViewV1 {
    entity_id: String,
    edge_kind: String,
    source_node_id: String,
    target_node_id: Option<String>,
    target_reference: String,
    resolution_state: QueryResolutionStateV1,
    candidate_node_ids: Vec<String>,
}

fn require_matching_edge(
    entity: &GraphQueryEntityV1,
    record: &AdjacencyEdgeRecordV1,
) -> Result<EdgeViewV1, FileGraphQueryErrorV1> {
    let GraphQueryEntityV1::StructuralEdge {
        entity_id,
        edge_kind,
        source_node_id,
        target_node_id,
        target_reference,
        resolution_state,
        candidate_node_ids,
        evidence,
        ..
    } = entity
    else {
        return Err(FileGraphQueryErrorV1::EvidenceTampered);
    };
    let evidence_ids = evidence
        .iter()
        .filter_map(|value| value.get("evidence_id").and_then(Value::as_str))
        .collect::<BTreeSet<_>>();
    if entity_id != &record.edge_id
        || source_node_id != &record.source_node_id
        || target_node_id.as_deref() != Some(record.target_node_id.as_str())
        || resolution_state != &record.resolution_state
        || !evidence_ids.contains(record.evidence_ref.as_str())
    {
        return Err(FileGraphQueryErrorV1::EvidenceTampered);
    }
    Ok(EdgeViewV1 {
        entity_id: entity_id.clone(),
        edge_kind: edge_kind.clone(),
        source_node_id: source_node_id.clone(),
        target_node_id: target_node_id.clone(),
        target_reference: target_reference.clone(),
        resolution_state: *resolution_state,
        candidate_node_ids: candidate_node_ids.clone(),
    })
}

fn edge_value(edge: EdgeViewV1) -> Value {
    json!({
        "id": edge.entity_id,
        "kind": edge.edge_kind,
        "source_node_id": edge.source_node_id,
        "target_node_id": edge.target_node_id,
        "target_reference": edge.target_reference,
        "resolution": resolution_name(edge.resolution_state),
        "candidate_node_ids": edge.candidate_node_ids,
    })
}

fn require_node(entity: &GraphQueryEntityV1) -> Result<&GraphQueryEntityV1, FileGraphQueryErrorV1> {
    if matches!(entity, GraphQueryEntityV1::StructuralNode { .. }) {
        Ok(entity)
    } else {
        Err(FileGraphQueryErrorV1::EvidenceTampered)
    }
}

fn selected_entity<'a>(
    reader: &'a mut EvidenceReaderV1<'_>,
    entity_id: &str,
) -> Result<&'a GraphQueryEntityV1, FileGraphQueryErrorV1> {
    reader.entity(entity_id).map_err(|error| {
        if error == FileGraphQueryErrorV1::NotFound {
            FileGraphQueryErrorV1::EvidenceTampered
        } else {
            error
        }
    })
}

fn resolution_name(value: QueryResolutionStateV1) -> &'static str {
    match value {
        QueryResolutionStateV1::Resolved => "resolved",
        QueryResolutionStateV1::Ambiguous => "ambiguous",
        QueryResolutionStateV1::Unresolved => "unresolved",
        QueryResolutionStateV1::Unsupported => "unsupported",
    }
}

fn first_index_identity(metrics: &QueryMetricsV1) -> Result<&str, FileGraphQueryErrorV1> {
    let first = metrics
        .plans
        .first()
        .ok_or(FileGraphQueryErrorV1::IndexInvalid)?;
    if metrics
        .plans
        .iter()
        .any(|plan| plan.index_manifest_sha256 != first.index_manifest_sha256)
    {
        return Err(FileGraphQueryErrorV1::StaleIndex);
    }
    Ok(&first.index_manifest_sha256)
}

#[allow(clippy::too_many_arguments)]
fn slice_bounds<T: Serialize>(
    operation: FileGraphQueryOperationV1,
    object: &Map<String, Value>,
    request_sha256: &str,
    evidence_manifest_ref: &FileReceiptRef,
    authority: &LoadedContinuationAuthorityV1,
    page_size: usize,
    values: &[T],
    full_result_sha256: &str,
) -> Result<(usize, usize, Option<String>), FileGraphQueryErrorV1> {
    let total = values.len();
    let previous_page = object.get("previous_page");
    let start = match optional_string(object, "continuation")? {
        None => {
            if previous_page.is_some() {
                return Err(FileGraphQueryErrorV1::InvalidRequest);
            }
            0
        }
        Some(token) => {
            let decoded = decode_continuation(token, authority)?;
            validate_continuation_header(
                &decoded,
                operation,
                request_sha256,
                evidence_manifest_ref,
            )?;
            let ContinuationStateV1::Slice {
                next_offset,
                page_size: token_page_size,
                total_result_count,
                full_result_sha256: token_result,
                previous_start_offset,
                previous_end_offset,
                previous_result_sha256,
                previous_page_sha256,
            } = decoded.state
            else {
                return Err(FileGraphQueryErrorV1::ContinuationInvalid);
            };
            let previous_start = usize::try_from(previous_start_offset)
                .map_err(|_| FileGraphQueryErrorV1::ContinuationInvalid)?;
            let previous_end = usize::try_from(previous_end_offset)
                .map_err(|_| FileGraphQueryErrorV1::ContinuationInvalid)?;
            let next = usize::try_from(next_offset)
                .map_err(|_| FileGraphQueryErrorV1::ContinuationInvalid)?;
            if token_page_size != page_size as u64
                || total_result_count != total as u64
                || token_result != full_result_sha256
                || previous_start >= previous_end
                || previous_end > total
                || previous_end != next
                || previous_end.checked_sub(previous_start) != Some(page_size)
                || slice_content_sha256(&values[previous_start..previous_end])?
                    != previous_result_sha256
                || canonical_json_sha256(&(
                    operation,
                    request_sha256,
                    full_result_sha256,
                    previous_start,
                    previous_end,
                    previous_result_sha256.as_str(),
                ))
                .map_err(|_| FileGraphQueryErrorV1::ContinuationInvalid)?
                    != previous_page_sha256
            {
                return Err(FileGraphQueryErrorV1::ContinuationInvalid);
            }
            if let Some(previous_page) = previous_page {
                validate_structural_previous_page_v1(
                    previous_page,
                    token,
                    operation,
                    evidence_manifest_ref,
                    &values[previous_start..previous_end],
                    &previous_result_sha256,
                )?;
            } else {
                consume_issued_slice_continuation_v1(token)?;
            }
            next
        }
    };
    let end = start
        .checked_add(page_size)
        .ok_or(FileGraphQueryErrorV1::ResourceBudgetExceeded)?
        .min(total);
    let continuation = if end < total {
        let result_sha256 = slice_content_sha256(&values[start..end])?;
        let page_sha256 = canonical_json_sha256(&(
            operation,
            request_sha256,
            full_result_sha256,
            start,
            end,
            result_sha256.as_str(),
        ))
        .map_err(|_| FileGraphQueryErrorV1::InvalidRequest)?;
        let token = encode_continuation(
            FileGraphContinuationV1 {
                schema_version: FILE_GRAPH_CONTINUATION_SCHEMA_V1.to_owned(),
                operation,
                request_sha256: request_sha256.to_owned(),
                evidence_manifest_sha256: evidence_manifest_ref.sha256.clone(),
                authority_sha256: authority.authority_sha256.clone(),
                state: ContinuationStateV1::Slice {
                    next_offset: end as u64,
                    page_size: page_size as u64,
                    total_result_count: total as u64,
                    full_result_sha256: full_result_sha256.to_owned(),
                    previous_start_offset: start as u64,
                    previous_end_offset: end as u64,
                    previous_result_sha256: result_sha256,
                    previous_page_sha256: page_sha256,
                },
                continuation_sha256: String::new(),
                continuation_mac_sha256: String::new(),
            },
            authority,
        )?;
        register_issued_slice_continuation_v1(&token);
        Some(token)
    } else {
        None
    };
    Ok((start, end, continuation))
}

fn validate_structural_previous_page_v1<T: Serialize>(
    previous_page: &Value,
    token: &str,
    operation: FileGraphQueryOperationV1,
    evidence_manifest_ref: &FileReceiptRef,
    expected_slice: &[T],
    expected_slice_sha256: &str,
) -> Result<(), FileGraphQueryErrorV1> {
    let object = previous_page
        .as_object()
        .ok_or(FileGraphQueryErrorV1::ContinuationInvalid)?;
    let expected_fields = BTreeSet::from([
        "schema_version",
        "operation_id",
        "mode",
        "result",
        "truncated",
        "continuation",
        "evidence_pack",
    ]);
    if object.keys().map(String::as_str).collect::<BTreeSet<_>>() != expected_fields
        || previous_page["schema_version"] != "gtkg.structural-query-result/v3"
        || previous_page["operation_id"] != operation.operation_id()
        || previous_page["mode"] != "file_index_structural"
        || previous_page["truncated"] != true
        || previous_page["continuation"] != token
        || previous_page["evidence_pack"]["query_index"]["evidence_manifest_file_sha256"]
            != evidence_manifest_ref.sha256
    {
        return Err(FileGraphQueryErrorV1::ContinuationInvalid);
    }
    let result_field = match operation {
        FileGraphQueryOperationV1::Neighbors => "neighbors",
        FileGraphQueryOperationV1::Impact => "impacts",
        FileGraphQueryOperationV1::Explain => "relations",
        _ => return Err(FileGraphQueryErrorV1::ContinuationInvalid),
    };
    let observed_slice = previous_page["result"][result_field]
        .as_array()
        .ok_or(FileGraphQueryErrorV1::ContinuationInvalid)?;
    let observed_sha256 = canonical_json_sha256(observed_slice)
        .map_err(|_| FileGraphQueryErrorV1::ContinuationInvalid)?;
    if observed_sha256 != expected_slice_sha256
        || slice_content_sha256(expected_slice)? != expected_slice_sha256
    {
        return Err(FileGraphQueryErrorV1::ContinuationInvalid);
    }
    Ok(())
}

fn slice_content_sha256<T: Serialize>(values: &[T]) -> Result<String, FileGraphQueryErrorV1> {
    canonical_json_sha256(&values.iter().collect::<Vec<_>>())
        .map_err(|_| FileGraphQueryErrorV1::ContinuationInvalid)
}

fn encode_continuation(
    mut continuation: FileGraphContinuationV1,
    authority: &LoadedContinuationAuthorityV1,
) -> Result<String, FileGraphQueryErrorV1> {
    continuation.authority_sha256 = authority.authority_sha256.clone();
    continuation.continuation_mac_sha256.clear();
    continuation.continuation_sha256 = continuation_content_sha256(&continuation)?;
    continuation.continuation_mac_sha256 =
        continuation_mac_sha256_v1(&authority.key, continuation.continuation_sha256.as_bytes());
    let bytes = serde_json::to_vec(&continuation)
        .map_err(|_| FileGraphQueryErrorV1::ContinuationInvalid)?;
    if bytes.len() > MAX_CONTINUATION_BYTES {
        return Err(FileGraphQueryErrorV1::ResourceBudgetExceeded);
    }
    Ok(format!("gtkgq4c1.{}", hex::encode(bytes)))
}

fn decode_continuation(
    token: &str,
    authority: &LoadedContinuationAuthorityV1,
) -> Result<FileGraphContinuationV1, FileGraphQueryErrorV1> {
    let encoded = token
        .strip_prefix("gtkgq4c1.")
        .ok_or(FileGraphQueryErrorV1::ContinuationInvalid)?;
    if encoded.is_empty() || encoded.len() > MAX_CONTINUATION_BYTES.saturating_mul(2) {
        return Err(FileGraphQueryErrorV1::ContinuationInvalid);
    }
    let bytes = hex::decode(encoded).map_err(|_| FileGraphQueryErrorV1::ContinuationInvalid)?;
    let continuation: FileGraphContinuationV1 =
        serde_json::from_slice(&bytes).map_err(|_| FileGraphQueryErrorV1::ContinuationInvalid)?;
    let expected_mac =
        continuation_mac_sha256_v1(&authority.key, continuation.continuation_sha256.as_bytes());
    if continuation.schema_version != FILE_GRAPH_CONTINUATION_SCHEMA_V1
        || continuation.authority_sha256 != authority.authority_sha256
        || continuation.continuation_sha256 != continuation_content_sha256(&continuation)?
        || !constant_time_sha256_eq_v1(&continuation.continuation_mac_sha256, &expected_mac)
    {
        return Err(FileGraphQueryErrorV1::ContinuationInvalid);
    }
    Ok(continuation)
}

fn continuation_content_sha256(
    continuation: &FileGraphContinuationV1,
) -> Result<String, FileGraphQueryErrorV1> {
    let mut content = continuation.clone();
    content.continuation_sha256.clear();
    content.continuation_mac_sha256.clear();
    canonical_json_sha256(&content).map_err(|_| FileGraphQueryErrorV1::ContinuationInvalid)
}

fn continuation_mac_sha256_v1(key: &[u8; 32], message: &[u8]) -> String {
    let mut inner_pad = [0x36_u8; 64];
    let mut outer_pad = [0x5c_u8; 64];
    for (index, value) in key.iter().enumerate() {
        inner_pad[index] ^= value;
        outer_pad[index] ^= value;
    }
    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(message);
    let inner_digest = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner_digest);
    format!("sha256:{}", hex::encode(outer.finalize()))
}

fn constant_time_sha256_eq_v1(observed: &str, expected: &str) -> bool {
    let Some(observed) = observed.strip_prefix("sha256:") else {
        return false;
    };
    let Some(expected) = expected.strip_prefix("sha256:") else {
        return false;
    };
    let (Ok(observed), Ok(expected)) = (hex::decode(observed), hex::decode(expected)) else {
        return false;
    };
    observed.len() == 32
        && expected.len() == 32
        && observed
            .iter()
            .zip(expected.iter())
            .fold(0_u8, |difference, (left, right)| {
                difference | (left ^ right)
            })
            == 0
}

fn validate_continuation_header(
    continuation: &FileGraphContinuationV1,
    operation: FileGraphQueryOperationV1,
    request_sha256: &str,
    evidence_manifest_ref: &FileReceiptRef,
) -> Result<(), FileGraphQueryErrorV1> {
    if continuation.operation != operation
        || continuation.request_sha256 != request_sha256
        || continuation.evidence_manifest_sha256 != evidence_manifest_ref.sha256
    {
        return Err(FileGraphQueryErrorV1::ContinuationInvalid);
    }
    Ok(())
}

fn request_sha256(
    operation: FileGraphQueryOperationV1,
    payload: &Value,
) -> Result<String, FileGraphQueryErrorV1> {
    let mut normalized = payload
        .as_object()
        .ok_or(FileGraphQueryErrorV1::InvalidRequest)?
        .clone();
    normalized.remove("continuation");
    normalized.remove("previous_page");
    canonical_json_sha256(&(operation, normalized))
        .map_err(|_| FileGraphQueryErrorV1::InvalidRequest)
}

fn validate_evidence_coverage_against_query_index(
    context: &CallContext,
    evidence_root: &Path,
    query_manifest_ref: &FileReceiptRef,
    index_manifest_sha256: &str,
    entities: &[GraphQueryEntityV1],
) -> Result<(), FileGraphQueryErrorV1> {
    let query_root = evidence_root
        .parent()
        .ok_or(FileGraphQueryErrorV1::InvalidRequest)?
        .join("query-index");
    let query_root = authorize_plain_root(context, &query_root)?;
    if !safe_relative_path(&query_manifest_ref.path, "manifests") {
        return Err(FileGraphQueryErrorV1::UnsafePath);
    }
    let manifest_read = read_bound_file(
        context,
        &query_root,
        Path::new(&query_manifest_ref.path),
        QueryResourceBudgetsV1::v03_frozen().max_manifest_bytes,
    )?;
    if manifest_read.sha256 != query_manifest_ref.sha256 {
        return Err(FileGraphQueryErrorV1::IndexInvalid);
    }
    let manifest: FileQueryIndexManifestV1 = serde_json::from_slice(&manifest_read.bytes)
        .map_err(|_| FileGraphQueryErrorV1::IndexInvalid)?;
    validate_file_query_index_manifest_v1(&manifest)
        .map_err(|_| FileGraphQueryErrorV1::IndexInvalid)?;
    if manifest.index_manifest_sha256 != index_manifest_sha256 {
        return Err(FileGraphQueryErrorV1::StaleIndex);
    }
    let by_id = entities
        .iter()
        .map(|entity| (entity.entity_id(), entity))
        .collect::<BTreeMap<_, _>>();
    let mut referenced = BTreeSet::new();
    for node_id in &manifest.adjacency_catalog.nodes {
        let entity = by_id
            .get(node_id.as_str())
            .ok_or(FileGraphQueryErrorV1::InvalidRequest)?;
        require_node(entity)?;
        referenced.insert(node_id.clone());
    }
    for shard_file in &manifest.shard_files {
        if !safe_relative_path(&shard_file.relative_path, "shards") {
            return Err(FileGraphQueryErrorV1::IndexInvalid);
        }
        let read = read_bound_file(
            context,
            &query_root,
            Path::new(&shard_file.relative_path),
            QueryResourceBudgetsV1::v03_frozen().max_shard_bytes,
        )?;
        if read.sha256 != shard_file.file_sha256
            || u64::try_from(read.bytes.len()).ok() != Some(shard_file.byte_len)
        {
            return Err(FileGraphQueryErrorV1::IndexInvalid);
        }
        match shard_file.shard_kind {
            QueryShardKindV1::Lexical => {
                let shard: LexicalShardV1 = serde_json::from_slice(&read.bytes)
                    .map_err(|_| FileGraphQueryErrorV1::IndexInvalid)?;
                if shard.shard_id != shard_file.shard_id
                    || shard.raw_bytes_sha256 != shard_file.content_sha256
                    || shard.raw_bytes_sha256 != lexical_shard_content_sha256_v1(&shard)
                {
                    return Err(FileGraphQueryErrorV1::IndexInvalid);
                }
                for posting in &shard.postings {
                    let entity = by_id
                        .get(posting.node_id.as_str())
                        .ok_or(FileGraphQueryErrorV1::InvalidRequest)?;
                    if !entity
                        .evidence_ids()
                        .contains(posting.evidence_ref.as_str())
                    {
                        return Err(FileGraphQueryErrorV1::InvalidRequest);
                    }
                    referenced.insert(posting.node_id.clone());
                }
            }
            QueryShardKindV1::Adjacency => {
                let shard: AdjacencyRoutingShardV1 = serde_json::from_slice(&read.bytes)
                    .map_err(|_| FileGraphQueryErrorV1::IndexInvalid)?;
                if shard.header.shard_id != shard_file.shard_id
                    || shard.header.raw_bytes_sha256 != shard_file.content_sha256
                    || shard.header.raw_bytes_sha256
                        != adjacency_routing_shard_content_sha256_v1(&shard)
                {
                    return Err(FileGraphQueryErrorV1::IndexInvalid);
                }
                for record in &shard.records {
                    let entity = by_id
                        .get(record.edge_id.as_str())
                        .ok_or(FileGraphQueryErrorV1::InvalidRequest)?;
                    require_matching_edge(entity, record)?;
                    referenced.insert(record.edge_id.clone());
                }
            }
        }
    }
    if by_id
        .keys()
        .any(|entity_id| !referenced.contains(*entity_id))
    {
        return Err(FileGraphQueryErrorV1::InvalidRequest);
    }
    Ok(())
}

fn validate_expected(
    expected: &FileQueryExpectedIdentitiesV1,
) -> Result<(), FileGraphQueryErrorV1> {
    for identity in [
        &expected.source_identity,
        &expected.graph_identity,
        &expected.overlay_identity,
    ] {
        validate_sha256(identity).map_err(|_| FileGraphQueryErrorV1::InvalidRequest)?;
    }
    Ok(())
}

fn validate_knowledge_entities_against_overlay(
    entities: &[GraphQueryEntityV1],
    overlay: &KnowledgeOverlayV2,
) -> Result<(), FileGraphQueryErrorV1> {
    let overlay_claims = overlay
        .nodes
        .iter()
        .filter(|node| matches!(node.kind.as_str(), "accepted_claim" | "abstention"))
        .map(|node| (node.id.as_str(), node))
        .collect::<BTreeMap<_, _>>();
    let knowledge_entities = entities
        .iter()
        .filter_map(|entity| {
            matches!(entity, GraphQueryEntityV1::KnowledgeNode { .. })
                .then_some((entity.entity_id(), entity))
        })
        .collect::<BTreeMap<_, _>>();
    if overlay_claims.len() != knowledge_entities.len()
        || overlay_claims
            .keys()
            .any(|identity| !knowledge_entities.contains_key(identity))
    {
        return Err(FileGraphQueryErrorV1::KnowledgeUnattested);
    }
    for (identity, entity) in knowledge_entities {
        let overlay_node = overlay_claims
            .get(identity)
            .ok_or(FileGraphQueryErrorV1::KnowledgeUnattested)?;
        let GraphQueryEntityV1::KnowledgeNode {
            knowledge_kind,
            label,
            claim_id,
            knowledge_state,
            structural_evidence_ids,
            overlay_provenance,
            evidence,
            ..
        } = entity
        else {
            return Err(FileGraphQueryErrorV1::KnowledgeUnattested);
        };
        let expected_state = match overlay_node.kind.as_str() {
            "accepted_claim" => "accepted_grounded",
            "abstention" => "abstention",
            _ => return Err(FileGraphQueryErrorV1::KnowledgeUnattested),
        };
        let evidence_ids = evidence
            .iter()
            .filter_map(|value| value.get("evidence_id").and_then(Value::as_str))
            .collect::<BTreeSet<_>>();
        let expected_evidence_ids = structural_evidence_ids
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        if knowledge_kind != &overlay_node.kind
            || label != &overlay_node.label
            || overlay_node.claim_id.as_deref() != Some(claim_id.as_str())
            || knowledge_state != expected_state
            || structural_evidence_ids != &overlay_node.structural_evidence_ids
            || overlay_provenance
                != &serde_json::to_value(&overlay_node.provenance)
                    .map_err(|_| FileGraphQueryErrorV1::KnowledgeUnattested)?
            || evidence_ids != expected_evidence_ids
        {
            return Err(FileGraphQueryErrorV1::KnowledgeUnattested);
        }
    }
    Ok(())
}

fn validate_entity(entity: &GraphQueryEntityV1) -> Result<(), FileGraphQueryErrorV1> {
    if !valid_identity(entity.entity_id())
        || entity.evidence().is_empty()
        || entity.evidence().len() > MAX_EVIDENCE_ITEMS_PER_RECORD
        || entity.evidence_ids().len() != entity.evidence().len()
    {
        return Err(FileGraphQueryErrorV1::InvalidRequest);
    }
    for evidence in entity.evidence() {
        if !evidence.is_object()
            || evidence
                .get("evidence_id")
                .and_then(Value::as_str)
                .is_none_or(|value| !valid_identity(value))
        {
            return Err(FileGraphQueryErrorV1::InvalidRequest);
        }
    }
    match entity {
        GraphQueryEntityV1::StructuralNode {
            node_kind,
            label,
            source_logical_path,
            structural_provenance,
            ..
        } => {
            if !valid_identity(node_kind)
                || label.trim().is_empty()
                || source_logical_path.trim().is_empty()
                || !structural_provenance.is_object()
            {
                return Err(FileGraphQueryErrorV1::InvalidRequest);
            }
        }
        GraphQueryEntityV1::StructuralEdge {
            edge_kind,
            source_node_id,
            target_node_id,
            target_reference,
            candidate_node_ids,
            structural_provenance,
            ..
        } => {
            if !valid_identity(edge_kind)
                || !valid_identity(source_node_id)
                || target_node_id
                    .as_ref()
                    .is_some_and(|value| !valid_identity(value))
                || target_reference.trim().is_empty()
                || candidate_node_ids
                    .iter()
                    .any(|value| !valid_identity(value))
                || !strictly_sorted(candidate_node_ids)
                || !structural_provenance.is_object()
            {
                return Err(FileGraphQueryErrorV1::InvalidRequest);
            }
        }
        GraphQueryEntityV1::KnowledgeNode {
            knowledge_kind,
            label,
            claim_id,
            knowledge_state,
            structural_evidence_ids,
            overlay_provenance,
            ..
        } => {
            if !matches!(
                (knowledge_kind.as_str(), knowledge_state.as_str()),
                ("accepted_claim", "accepted_grounded") | ("abstention", "abstention")
            ) || label.trim().is_empty()
                || !valid_identity(claim_id)
                || structural_evidence_ids.is_empty()
                || structural_evidence_ids
                    .iter()
                    .any(|value| !valid_identity(value))
                || !strictly_sorted(structural_evidence_ids)
                || !overlay_provenance.is_object()
            {
                return Err(FileGraphQueryErrorV1::InvalidRequest);
            }
        }
    }
    Ok(())
}

fn validate_evidence_record(
    record: &FileGraphEvidenceRecordV1,
) -> Result<(), FileGraphQueryErrorV1> {
    validate_entity(&record.entity).map_err(|_| FileGraphQueryErrorV1::EvidenceTampered)?;
    if record.schema_version != FILE_GRAPH_EVIDENCE_RECORD_SCHEMA_V1
        || record.record_sha256 != evidence_record_content_sha256(record)?
    {
        return Err(FileGraphQueryErrorV1::EvidenceTampered);
    }
    Ok(())
}

fn validate_evidence_manifest(
    manifest: &FileGraphEvidenceManifestV1,
) -> Result<(), FileGraphQueryErrorV1> {
    if manifest.schema_version != FILE_GRAPH_EVIDENCE_MANIFEST_SCHEMA_V1
        || manifest.records.is_empty()
        || manifest.records.len() > MAX_EVIDENCE_RECORDS
        || !strictly_sorted(&manifest.records)
        || manifest.manifest_sha256 != evidence_manifest_content_sha256(manifest)?
        || validate_sha256(&manifest.source_identity).is_err()
        || validate_sha256(&manifest.graph_identity).is_err()
        || validate_sha256(&manifest.overlay_identity).is_err()
        || validate_sha256(&manifest.index_manifest_sha256).is_err()
        || manifest.query_manifest_ref.validate().is_err()
        || match manifest.knowledge_assurance {
            KnowledgeEvidenceAssuranceV1::StructuralOnly
            | KnowledgeEvidenceAssuranceV1::FixtureOnlyUnattested => {
                manifest.overlay_replay_sha256.is_some()
            }
            KnowledgeEvidenceAssuranceV1::VerifiedOverlayReplay => manifest
                .overlay_replay_sha256
                .as_ref()
                .is_none_or(|identity| validate_sha256(identity).is_err()),
        }
    {
        return Err(FileGraphQueryErrorV1::EvidenceTampered);
    }
    for entry in &manifest.records {
        let expected_path = format!(
            "records/{}.json",
            hex::encode(Sha256::digest(entry.entity_id.as_bytes()))
        );
        if !valid_identity(&entry.entity_id)
            || entry.relative_path != expected_path
            || !safe_relative_path(&entry.relative_path, "records")
            || validate_sha256(&entry.content_sha256).is_err()
            || validate_sha256(&entry.file_sha256).is_err()
            || entry.byte_len == 0
            || entry.byte_len > MAX_EVIDENCE_RECORD_BYTES
        {
            return Err(FileGraphQueryErrorV1::EvidenceTampered);
        }
    }
    Ok(())
}

fn evidence_record_content_sha256(
    record: &FileGraphEvidenceRecordV1,
) -> Result<String, FileGraphQueryErrorV1> {
    canonical_json_sha256(&(record.schema_version.as_str(), &record.entity))
        .map_err(|_| FileGraphQueryErrorV1::InvalidRequest)
}

fn evidence_manifest_content_sha256(
    manifest: &FileGraphEvidenceManifestV1,
) -> Result<String, FileGraphQueryErrorV1> {
    canonical_json_sha256(&(
        manifest.schema_version.as_str(),
        manifest.source_identity.as_str(),
        manifest.graph_identity.as_str(),
        manifest.overlay_identity.as_str(),
        &manifest.query_manifest_ref,
        manifest.index_manifest_sha256.as_str(),
        manifest.knowledge_assurance,
        &manifest.overlay_replay_sha256,
        &manifest.records,
    ))
    .map_err(|_| FileGraphQueryErrorV1::InvalidRequest)
}

fn closed_object<'a>(
    value: &'a Value,
    allowed: &[&str],
) -> Result<&'a Map<String, Value>, FileGraphQueryErrorV1> {
    let object = value
        .as_object()
        .ok_or(FileGraphQueryErrorV1::InvalidRequest)?;
    if object.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err(FileGraphQueryErrorV1::InvalidRequest);
    }
    Ok(object)
}

fn required_string<'a>(
    object: &'a Map<String, Value>,
    key: &str,
) -> Result<&'a str, FileGraphQueryErrorV1> {
    object
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or(FileGraphQueryErrorV1::InvalidRequest)
}

fn optional_string<'a>(
    object: &'a Map<String, Value>,
    key: &str,
) -> Result<Option<&'a str>, FileGraphQueryErrorV1> {
    match object.get(key) {
        None => Ok(None),
        Some(value) => value
            .as_str()
            .filter(|value| !value.is_empty())
            .map(Some)
            .ok_or(FileGraphQueryErrorV1::InvalidRequest),
    }
}

fn bounded_results(object: &Map<String, Value>) -> Result<usize, FileGraphQueryErrorV1> {
    bounded_unsigned(object, "max_results", 1, MAX_PUBLIC_RESULTS, 100)
}

fn bounded_depth(object: &Map<String, Value>) -> Result<usize, FileGraphQueryErrorV1> {
    bounded_unsigned(object, "max_depth", 1, MAX_QUERY_DEPTH, 1)
}

fn bounded_unsigned(
    object: &Map<String, Value>,
    key: &str,
    min: usize,
    max: usize,
    default: usize,
) -> Result<usize, FileGraphQueryErrorV1> {
    let Some(value) = object.get(key) else {
        return Ok(default);
    };
    let number = value
        .as_u64()
        .and_then(|number| usize::try_from(number).ok())
        .ok_or(FileGraphQueryErrorV1::InvalidRequest)?;
    if !(min..=max).contains(&number) {
        return Err(FileGraphQueryErrorV1::ResourceBudgetExceeded);
    }
    Ok(number)
}

fn map_query_error(error: FileQueryErrorV1) -> FileGraphQueryErrorV1 {
    match error {
        FileQueryErrorV1::StaleIndex | FileQueryErrorV1::ZeroShardSelection => {
            FileGraphQueryErrorV1::StaleIndex
        }
        FileQueryErrorV1::ResourceBudgetExceeded => FileGraphQueryErrorV1::ResourceBudgetExceeded,
        FileQueryErrorV1::ContinuationInvalid => FileGraphQueryErrorV1::ContinuationInvalid,
        FileQueryErrorV1::UnsafePath => FileGraphQueryErrorV1::UnsafePath,
        FileQueryErrorV1::QueryInvalid => FileGraphQueryErrorV1::InvalidRequest,
        FileQueryErrorV1::Io => FileGraphQueryErrorV1::Io,
        FileQueryErrorV1::InvalidManifest
        | FileQueryErrorV1::ManifestTampered
        | FileQueryErrorV1::ShardTampered
        | FileQueryErrorV1::Contract(_)
        | FileQueryErrorV1::Lexical(_)
        | FileQueryErrorV1::Adjacency(_) => FileGraphQueryErrorV1::IndexInvalid,
    }
}

fn authorize_write_root(
    context: &CallContext,
    root: &Path,
) -> Result<PathBuf, FileGraphQueryErrorV1> {
    context.authorize_write(root).map_err(map_context_error)
}

fn authorize_plain_root(
    context: &CallContext,
    root: &Path,
) -> Result<PathBuf, FileGraphQueryErrorV1> {
    let lexical = fs::symlink_metadata(root).map_err(|_| FileGraphQueryErrorV1::Io)?;
    if lexical.file_type().is_symlink() || !lexical.is_dir() {
        return Err(FileGraphQueryErrorV1::UnsafePath);
    }
    context.authorize_read(root).map_err(map_context_error)
}

struct BoundReadV1 {
    bytes: Vec<u8>,
    sha256: String,
}

fn read_bound_file(
    context: &CallContext,
    root: &Path,
    relative: &Path,
    max_bytes: u64,
) -> Result<BoundReadV1, FileGraphQueryErrorV1> {
    if max_bytes == 0
        || relative.is_absolute()
        || relative.components().any(|component| {
            matches!(
                component,
                Component::ParentDir
                    | Component::CurDir
                    | Component::RootDir
                    | Component::Prefix(_)
            )
        })
    {
        return Err(FileGraphQueryErrorV1::UnsafePath);
    }
    let candidate = root.join(relative);
    let authorized_root = context
        .authorized_lexical_roots()
        .iter()
        .chain(context.authorized_roots())
        .filter(|authorized| candidate == **authorized || candidate.starts_with(authorized))
        .max_by_key(|authorized| authorized.components().count())
        .cloned()
        .ok_or(FileGraphQueryErrorV1::UnsafePath)?;
    let descriptor_path = candidate
        .strip_prefix(&authorized_root)
        .map_err(|_| FileGraphQueryErrorV1::UnsafePath)?;
    let components = descriptor_path
        .components()
        .map(|component| match component {
            Component::Normal(value) => Ok(value.to_os_string()),
            _ => Err(FileGraphQueryErrorV1::UnsafePath),
        })
        .collect::<Result<Vec<OsString>, _>>()?;
    if components.is_empty() {
        return Err(FileGraphQueryErrorV1::UnsafePath);
    }
    let mut file = open_bound_file_descriptor(&authorized_root, &components)?;
    let before = file.metadata().map_err(|_| FileGraphQueryErrorV1::Io)?;
    ensure_private_inode(&before, &before)?;
    if before.len() == 0 || before.len() > max_bytes {
        return Err(FileGraphQueryErrorV1::ResourceBudgetExceeded);
    }
    let authorized = context
        .authorize_read(&candidate)
        .map_err(map_context_error)?;
    let canonical_root =
        fs::canonicalize(&authorized_root).map_err(|_| FileGraphQueryErrorV1::Io)?;
    if authorized != canonical_root.join(descriptor_path) {
        return Err(FileGraphQueryErrorV1::UnsafePath);
    }
    let path_before = fs::symlink_metadata(&candidate).map_err(|_| FileGraphQueryErrorV1::Io)?;
    ensure_private_inode(&path_before, &before)?;
    let limit = max_bytes
        .checked_add(1)
        .ok_or(FileGraphQueryErrorV1::ResourceBudgetExceeded)?;
    let mut bytes = Vec::new();
    file.by_ref()
        .take(limit)
        .read_to_end(&mut bytes)
        .map_err(|_| FileGraphQueryErrorV1::Io)?;
    if bytes.len() as u64 > max_bytes || bytes.len() as u64 != before.len() {
        return Err(FileGraphQueryErrorV1::ResourceBudgetExceeded);
    }
    let after = file.metadata().map_err(|_| FileGraphQueryErrorV1::Io)?;
    let path_after = fs::symlink_metadata(&candidate).map_err(|_| FileGraphQueryErrorV1::Io)?;
    ensure_private_inode(&after, &before)?;
    ensure_private_inode(&path_after, &before)?;
    if after.len() != before.len() {
        return Err(FileGraphQueryErrorV1::EvidenceTampered);
    }
    Ok(BoundReadV1 {
        sha256: raw_sha256(&bytes),
        bytes,
    })
}

#[cfg(unix)]
fn open_bound_file_descriptor(
    authorized_root: &Path,
    components: &[OsString],
) -> Result<File, FileGraphQueryErrorV1> {
    use rustix::fs::{Mode, OFlags, open, openat};

    let directory_flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut directory =
        open(authorized_root, directory_flags, Mode::empty()).map_err(map_bound_open_error)?;
    for (index, component) in components.iter().enumerate() {
        let is_file = index + 1 == components.len();
        let flags = if is_file {
            OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC
        } else {
            directory_flags
        };
        let opened = openat(&directory, component.as_os_str(), flags, Mode::empty())
            .map_err(map_bound_open_error)?;
        if is_file {
            return Ok(File::from(opened));
        }
        directory = opened;
    }
    Err(FileGraphQueryErrorV1::UnsafePath)
}

#[cfg(not(unix))]
fn open_bound_file_descriptor(
    authorized_root: &Path,
    components: &[OsString],
) -> Result<File, FileGraphQueryErrorV1> {
    let mut candidate = authorized_root.to_path_buf();
    for component in components {
        candidate.push(component);
    }
    File::open(candidate).map_err(|_| FileGraphQueryErrorV1::Io)
}

#[cfg(unix)]
fn map_bound_open_error(error: rustix::io::Errno) -> FileGraphQueryErrorV1 {
    if matches!(error, rustix::io::Errno::LOOP | rustix::io::Errno::NOTDIR) {
        FileGraphQueryErrorV1::UnsafePath
    } else if error == rustix::io::Errno::NOENT {
        FileGraphQueryErrorV1::EvidenceTampered
    } else {
        FileGraphQueryErrorV1::Io
    }
}

fn ensure_private_inode(
    observed: &fs::Metadata,
    expected: &fs::Metadata,
) -> Result<(), FileGraphQueryErrorV1> {
    if observed.file_type().is_symlink()
        || !observed.file_type().is_file()
        || !expected.file_type().is_file()
    {
        return Err(FileGraphQueryErrorV1::UnsafePath);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if observed.nlink() != 1
            || expected.nlink() != 1
            || observed.dev() != expected.dev()
            || observed.ino() != expected.ino()
        {
            return Err(FileGraphQueryErrorV1::UnsafePath);
        }
    }
    Ok(())
}

fn safe_relative_path(path: &str, prefix: &str) -> bool {
    let relative = Path::new(path);
    !path.is_empty()
        && !relative.is_absolute()
        && relative.components().count() == 2
        && relative.components().next().is_some_and(
            |component| matches!(component, Component::Normal(value) if value == prefix),
        )
        && relative
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

fn valid_identity(value: &str) -> bool {
    !value.trim().is_empty()
        && value.len() <= 4_096
        && !value.chars().any(char::is_control)
        && !value.contains(['\n', '\r', '\0'])
}

fn strictly_sorted<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn raw_sha256(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn map_context_error(error: ContextError) -> FileGraphQueryErrorV1 {
    match error {
        ContextError::PathEscape(_) | ContextError::UnsafeRoot(_) => {
            FileGraphQueryErrorV1::UnsafePath
        }
        ContextError::MissingRoot | ContextError::InvalidReceipt(_) => {
            FileGraphQueryErrorV1::InvalidRequest
        }
        ContextError::RootIo { .. } => FileGraphQueryErrorV1::Io,
    }
}

fn map_durable_error(error: crate::durable::DurableWriteError) -> FileGraphQueryErrorV1 {
    match error.kind {
        DurableErrorKind::Invalid => FileGraphQueryErrorV1::InvalidRequest,
        DurableErrorKind::Unauthorized | DurableErrorKind::Unsafe => {
            FileGraphQueryErrorV1::UnsafePath
        }
        DurableErrorKind::Conflict => FileGraphQueryErrorV1::EvidenceTampered,
        DurableErrorKind::Io => FileGraphQueryErrorV1::Io,
    }
}
