//! Q00 validation and Unicode 17 tokenization for file-query contracts.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;

use gtkg_protocol::FileReceiptRef;
use gtkg_protocol::v03::query::{
    ADJACENCY_ROUTING_CATALOG_SCHEMA_V1, ADJACENCY_SHARD_SCHEMA_V1, AdjacencyDirectionV1,
    AdjacencyEdgeRecordV1, AdjacencyNodeRouteV1, AdjacencyRoutingCatalogV1,
    AdjacencyRoutingDenominatorV1, AdjacencyRoutingIndexV1, AdjacencyRoutingShardV1,
    AdjacencyShardV1, FILE_QUERY_CONTINUATION_SCHEMA_V1, FILE_QUERY_CURRENT_BINDING_SCHEMA_V1,
    FILE_QUERY_INDEX_MANIFEST_SCHEMA_V1, FileAdjacencyRouteV1, FileQueryContinuationV1,
    FileQueryCurrentBindingV1, FileQueryExpectedIdentitiesV1, FileQueryIndexManifestV1,
    FileQueryLookupV1, FileQueryRequestV1, FileQueryShardV1, LEXICAL_SHARD_SCHEMA_V1,
    LexicalRoutingCatalogV1, LexicalRoutingEntryV1, LexicalShardV1, NormalizationCollisionStatusV1,
    QUERY_INDEX_MANIFEST_SCHEMA_V1, QUERY_NORMALIZATION_V1, QUERY_PLAN_RECEIPT_SCHEMA_V1,
    QUERY_TOKENIZER_ID_V1, QUERY_UNICODE_VERSION_V1, QueryIndexDigestsV1, QueryIndexManifestV1,
    QueryPlanBudgetV1, QueryPlanReceiptV1, QueryResolutionStateV1, QueryResourceBudgetsV1,
    QueryShardCatalogV1, QueryShardDenominatorV1, QueryShardDescriptorV1, QueryShardKindV1,
    QueryTokenKindV1, QueryTokenV1, QueryTokenizationReceiptV1, QueryTruncationStateV1,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;
use unicode_normalization::char::is_combining_mark;
use unicode_normalization::{UNICODE_VERSION, UnicodeNormalization};

#[cfg(not(unix))]
use crate::durable::{DurableErrorKind, publish_immutable_json};
use crate::{CallContext, ContextError};

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum QueryContractErrorV1 {
    #[error("closed schema decode failed for {schema_id}: {message}")]
    SchemaDecode {
        schema_id: &'static str,
        message: String,
    },
    #[error("unsupported schema")]
    UnsupportedSchema,
    #[error("identity is empty or is not a sha256 identity")]
    InvalidIdentity,
    #[error("the tokenizer identity or Unicode data version drifted")]
    TokenizerIdentityMismatch,
    #[error("the frozen Q00 resource budget drifted")]
    FrozenBudgetMismatch,
    #[error("required shard denominator is zero")]
    ZeroDenominator,
    #[error("shard denominator is not closed")]
    DenominatorNotClosed,
    #[error("shard catalog does not match its admitted denominator")]
    DenominatorCountMismatch,
    #[error("shard catalog is incomplete")]
    IncompleteShardCatalog,
    #[error("an ordered exact set is empty, duplicated, or out of order")]
    InvalidExactSet,
    #[error("a resource exceeds its frozen parser budget")]
    ResourceBudgetExceeded,
    #[error("shard catalog digest mismatch")]
    CatalogDigestMismatch,
    #[error("term is not the tokenizer's canonical NFC form")]
    NormalizationMismatch,
    #[error("normalization collision status is inconsistent with original forms")]
    CollisionStatusMismatch,
    #[error("trigram set differs from the frozen scalar-window rule")]
    TrigramMismatch,
    #[error("posting or evidence identity is invalid")]
    InvalidPosting,
    #[error("adjacency edge and resolution vectors are invalid")]
    InvalidAdjacency,
    #[error("query plan does not partition the manifest shard exact set")]
    PlanShardPartitionMismatch,
    #[error("query plan receipt is bound to a different index manifest")]
    ManifestIdentityMismatch,
    #[error("query plan exceeded its bound")]
    PlanBudgetExceeded,
    #[error("a truncated response requires a non-empty continuation")]
    ContinuationRequired,
    #[error("a non-truncated response cannot carry a continuation")]
    UnexpectedContinuation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LexicalDocumentV1 {
    pub node_id: String,
    pub evidence_ref: String,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LexicalMutationV1 {
    Upsert(LexicalDocumentV1),
    Delete { node_id: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LexicalMatchKindV1 {
    ExactIdentifier,
    ExactTerm,
    Phrase,
    CjkTrigram,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LexicalSearchHitV1 {
    pub node_id: String,
    pub evidence_ref: String,
    pub match_kind: LexicalMatchKindV1,
    pub matched_terms: Vec<String>,
    pub positions: Vec<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum LexicalIndexErrorV1 {
    #[error("lexical document identity or text is invalid")]
    InvalidDocument,
    #[error("lexical document node identity is duplicated")]
    DuplicateNode,
    #[error("a mutation batch contains more than one operation for a node")]
    DuplicateMutation,
    #[error("a delete mutation names a document that is not present")]
    MissingDocument,
    #[error("lexical shard identity is invalid")]
    InvalidShardIdentity,
    #[error("lexical query has no searchable token")]
    EmptyQuery,
    #[error("lexical FST dictionary digest does not match its terms")]
    FstDigestMismatch,
    #[error("lexical shard content digest does not match its fields")]
    ContentDigestMismatch,
    #[error(transparent)]
    Contract(#[from] QueryContractErrorV1),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LexicalIndexStateV1 {
    documents: BTreeMap<String, LexicalDocumentV1>,
}

impl LexicalIndexStateV1 {
    pub fn from_documents(documents: &[LexicalDocumentV1]) -> Result<Self, LexicalIndexErrorV1> {
        let mut indexed = BTreeMap::new();
        for document in documents {
            validate_lexical_document(document)?;
            if indexed
                .insert(document.node_id.clone(), document.clone())
                .is_some()
            {
                return Err(LexicalIndexErrorV1::DuplicateNode);
            }
        }
        if indexed.is_empty() {
            return Err(LexicalIndexErrorV1::InvalidDocument);
        }
        Ok(Self { documents: indexed })
    }

    pub fn apply_mutations(
        &mut self,
        mutations: &[LexicalMutationV1],
    ) -> Result<(), LexicalIndexErrorV1> {
        let mut next = self.documents.clone();
        let mut touched = BTreeSet::new();
        for mutation in mutations {
            let node_id = match mutation {
                LexicalMutationV1::Upsert(document) => {
                    validate_lexical_document(document)?;
                    &document.node_id
                }
                LexicalMutationV1::Delete { node_id } => {
                    if !valid_lexical_identity(node_id) {
                        return Err(LexicalIndexErrorV1::InvalidDocument);
                    }
                    node_id
                }
            };
            if !touched.insert(node_id.clone()) {
                return Err(LexicalIndexErrorV1::DuplicateMutation);
            }
            match mutation {
                LexicalMutationV1::Upsert(document) => {
                    next.insert(document.node_id.clone(), document.clone());
                }
                LexicalMutationV1::Delete { node_id } => {
                    if next.remove(node_id).is_none() {
                        return Err(LexicalIndexErrorV1::MissingDocument);
                    }
                }
            }
        }
        if next.is_empty() {
            return Err(LexicalIndexErrorV1::InvalidDocument);
        }
        self.documents = next;
        Ok(())
    }

    pub fn build_shard(&self, shard_id: &str) -> Result<LexicalShardV1, LexicalIndexErrorV1> {
        if !valid_lexical_identity(shard_id) {
            return Err(LexicalIndexErrorV1::InvalidShardIdentity);
        }

        let mut term_forms = BTreeMap::<String, BTreeSet<String>>::new();
        let mut posting_positions = BTreeMap::<(String, String, String), Vec<u64>>::new();
        let mut evidence_refs = BTreeSet::new();
        for document in self.documents.values() {
            evidence_refs.insert(document.evidence_ref.clone());
            for (position, (token, original_form)) in tokenize_document_terms_v1(&document.text)
                .into_iter()
                .enumerate()
            {
                let position = u64::try_from(position)
                    .map_err(|_| QueryContractErrorV1::ResourceBudgetExceeded)?;
                term_forms
                    .entry(token.normalized.clone())
                    .or_default()
                    .insert(original_form);
                posting_positions
                    .entry((
                        token.normalized,
                        document.node_id.clone(),
                        document.evidence_ref.clone(),
                    ))
                    .or_default()
                    .push(position);
            }
        }

        let normalized_terms = term_forms
            .into_iter()
            .map(|(normalized, originals)| {
                let original_forms = originals.into_iter().collect::<Vec<_>>();
                let collision_status = if original_forms.len() == 1 {
                    NormalizationCollisionStatusV1::Unique
                } else {
                    NormalizationCollisionStatusV1::Ambiguous
                };
                gtkg_protocol::v03::query::NormalizedTermV1 {
                    normalized,
                    original_forms,
                    collision_status,
                }
            })
            .collect::<Vec<_>>();
        let trigrams = normalized_terms
            .iter()
            .flat_map(|term| scalar_trigrams(&term.normalized))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let postings = posting_positions
            .into_iter()
            .map(|((normalized_term, node_id, evidence_ref), positions)| {
                gtkg_protocol::v03::query::LexicalPostingV1 {
                    normalized_term,
                    node_id,
                    evidence_ref,
                    positions,
                }
            })
            .collect::<Vec<_>>();
        let fst_sha256 =
            lexical_fst_sha256_v1(normalized_terms.iter().map(|term| term.normalized.as_str()));
        let mut shard = LexicalShardV1 {
            schema_version: LEXICAL_SHARD_SCHEMA_V1.to_owned(),
            shard_id: shard_id.to_owned(),
            tokenizer_id: QUERY_TOKENIZER_ID_V1.to_owned(),
            unicode_version: QUERY_UNICODE_VERSION_V1.to_owned(),
            normalized_terms,
            trigrams,
            fst_sha256,
            postings,
            evidence_refs: evidence_refs.into_iter().collect(),
            raw_bytes_sha256: String::new(),
        };
        shard.raw_bytes_sha256 = lexical_shard_content_sha256_v1(&shard);
        validate_lexical_shard_v1(&shard, &QueryResourceBudgetsV1::v03_frozen())?;
        Ok(shard)
    }

    /// Returns the canonical document exact set after any accepted mutation
    /// batch.  Q06 uses this read-only projection to compare a reconstructed
    /// incremental state with the independently supplied terminal input.
    pub fn documents(&self) -> Vec<LexicalDocumentV1> {
        self.documents.values().cloned().collect()
    }
}

pub fn build_lexical_shard_v1(
    shard_id: &str,
    documents: &[LexicalDocumentV1],
) -> Result<LexicalShardV1, LexicalIndexErrorV1> {
    LexicalIndexStateV1::from_documents(documents)?.build_shard(shard_id)
}

pub fn lexical_shard_content_sha256_v1(shard: &LexicalShardV1) -> String {
    let content = (
        shard.schema_version.as_str(),
        shard.shard_id.as_str(),
        shard.tokenizer_id.as_str(),
        shard.unicode_version.as_str(),
        &shard.normalized_terms,
        &shard.trigrams,
        shard.fst_sha256.as_str(),
        &shard.postings,
        &shard.evidence_refs,
    );
    json_sha256(&content)
}

pub fn search_lexical_shard_v1(
    shard: &LexicalShardV1,
    query: &str,
) -> Result<Vec<LexicalSearchHitV1>, LexicalIndexErrorV1> {
    validate_lexical_shard_v1(shard, &QueryResourceBudgetsV1::v03_frozen())?;
    if shard.fst_sha256
        != lexical_fst_sha256_v1(
            shard
                .normalized_terms
                .iter()
                .map(|term| term.normalized.as_str()),
        )
    {
        return Err(LexicalIndexErrorV1::FstDigestMismatch);
    }
    if shard.raw_bytes_sha256 != lexical_shard_content_sha256_v1(shard) {
        return Err(LexicalIndexErrorV1::ContentDigestMismatch);
    }
    let tokens = tokenize_query_v1(query).tokens;
    if tokens.is_empty() {
        return Err(LexicalIndexErrorV1::EmptyQuery);
    }
    let mut postings_by_term =
        BTreeMap::<&str, Vec<&gtkg_protocol::v03::query::LexicalPostingV1>>::new();
    for posting in &shard.postings {
        postings_by_term
            .entry(posting.normalized_term.as_str())
            .or_default()
            .push(posting);
    }
    if tokens.len() > 1 {
        return Ok(search_phrase(&postings_by_term, &tokens));
    }

    let token = &tokens[0];
    let (candidate_terms, match_kind) = if token.kind == QueryTokenKindV1::CjkRun {
        let mut terms = if token.trigrams.is_empty() {
            shard
                .normalized_terms
                .iter()
                .map(|term| term.normalized.as_str())
                .collect::<BTreeSet<_>>()
        } else {
            let mut trigram_terms = BTreeMap::<String, BTreeSet<&str>>::new();
            for term in &shard.normalized_terms {
                for trigram in scalar_trigrams(&term.normalized) {
                    trigram_terms
                        .entry(trigram)
                        .or_default()
                        .insert(term.normalized.as_str());
                }
            }
            let Some(mut intersection) = trigram_terms.get(&token.trigrams[0]).cloned() else {
                return Ok(Vec::new());
            };
            for trigram in &token.trigrams[1..] {
                let Some(candidate_set) = trigram_terms.get(trigram) else {
                    return Ok(Vec::new());
                };
                intersection.retain(|term| candidate_set.contains(term));
            }
            intersection
        };
        terms.retain(|term| term.contains(&token.normalized));
        (terms, LexicalMatchKindV1::CjkTrigram)
    } else {
        if !lexical_fst_contains_v1(shard, &token.normalized) {
            return Ok(Vec::new());
        }
        (
            BTreeSet::from([token.normalized.as_str()]),
            if token.kind == QueryTokenKindV1::AsciiIdentifier {
                LexicalMatchKindV1::ExactIdentifier
            } else {
                LexicalMatchKindV1::ExactTerm
            },
        )
    };
    Ok(collect_single_term_hits(
        &postings_by_term,
        &candidate_terms,
        match_kind,
    ))
}

fn validate_lexical_document(document: &LexicalDocumentV1) -> Result<(), LexicalIndexErrorV1> {
    if !valid_lexical_identity(&document.node_id)
        || !valid_lexical_identity(&document.evidence_ref)
        || document.text.trim().is_empty()
        || tokenize_document_terms_v1(&document.text).is_empty()
    {
        return Err(LexicalIndexErrorV1::InvalidDocument);
    }
    Ok(())
}

fn tokenize_document_terms_v1(input: &str) -> Vec<(QueryTokenV1, String)> {
    let mut terms = Vec::new();
    let mut buffer = String::new();
    let mut kind = None;
    for character in input.chars() {
        if is_combining_mark(character) && !buffer.is_empty() {
            buffer.push(character);
            continue;
        }
        let next_kind = classify(character);
        if kind == Some(QueryTokenKindV1::AsciiIdentifier)
            && next_kind == Some(QueryTokenKindV1::UnicodeWord)
            && !buffer.contains('_')
        {
            kind = Some(QueryTokenKindV1::UnicodeWord);
            buffer.push(character);
            continue;
        }
        if kind == Some(QueryTokenKindV1::UnicodeWord)
            && next_kind == Some(QueryTokenKindV1::AsciiIdentifier)
            && character.is_ascii_alphanumeric()
        {
            buffer.push(character);
            continue;
        }
        if next_kind != kind {
            push_document_term(&mut terms, &mut buffer);
            kind = next_kind;
        }
        if next_kind.is_some() {
            buffer.push(character);
        }
    }
    push_document_term(&mut terms, &mut buffer);
    terms
}

fn push_document_term(terms: &mut Vec<(QueryTokenV1, String)>, buffer: &mut String) {
    if buffer.is_empty() {
        return;
    }
    let original_form = std::mem::take(buffer);
    let mut normalized = tokenize_query_v1(&original_form).tokens;
    if normalized.len() == 1 {
        if let Some(token) = normalized.pop() {
            terms.push((token, original_form));
        }
        return;
    }
    terms.extend(normalized.into_iter().map(|token| {
        let fallback_form = token.normalized.clone();
        (token, fallback_form)
    }));
}

fn valid_lexical_identity(value: &str) -> bool {
    !value.is_empty()
        && !value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
}

#[derive(Debug, Default)]
struct LexicalFstNodeV1 {
    terminal: bool,
    edges: BTreeMap<char, usize>,
}

fn lexical_fst_nodes_v1<'a>(terms: impl IntoIterator<Item = &'a str>) -> Vec<LexicalFstNodeV1> {
    let mut nodes = vec![LexicalFstNodeV1::default()];
    for term in terms {
        let mut state = 0;
        for character in term.chars() {
            let next = if let Some(next) = nodes[state].edges.get(&character) {
                *next
            } else {
                let next = nodes.len();
                nodes.push(LexicalFstNodeV1::default());
                nodes[state].edges.insert(character, next);
                next
            };
            state = next;
        }
        nodes[state].terminal = true;
    }
    nodes
}

fn lexical_fst_sha256_v1<'a>(terms: impl IntoIterator<Item = &'a str>) -> String {
    let mut bytes = b"gtkg.lexical-fst/v1\0".to_vec();
    let nodes = lexical_fst_nodes_v1(terms);
    bytes.extend_from_slice(&(nodes.len() as u64).to_be_bytes());
    for node in nodes {
        bytes.push(u8::from(node.terminal));
        bytes.extend_from_slice(&(node.edges.len() as u64).to_be_bytes());
        for (character, target) in node.edges {
            bytes.extend_from_slice(&(character as u32).to_be_bytes());
            bytes.extend_from_slice(&(target as u64).to_be_bytes());
        }
    }
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn lexical_fst_contains_v1(shard: &LexicalShardV1, needle: &str) -> bool {
    let nodes = lexical_fst_nodes_v1(
        shard
            .normalized_terms
            .iter()
            .map(|term| term.normalized.as_str()),
    );
    let mut state = 0;
    for character in needle.chars() {
        let Some(next) = nodes[state].edges.get(&character) else {
            return false;
        };
        state = *next;
    }
    nodes[state].terminal
}

fn collect_single_term_hits(
    postings_by_term: &BTreeMap<&str, Vec<&gtkg_protocol::v03::query::LexicalPostingV1>>,
    candidate_terms: &BTreeSet<&str>,
    match_kind: LexicalMatchKindV1,
) -> Vec<LexicalSearchHitV1> {
    let mut matched = BTreeMap::<(String, String), (BTreeSet<String>, BTreeSet<u64>)>::new();
    for term in candidate_terms {
        for posting in postings_by_term.get(term).into_iter().flatten() {
            let entry = matched
                .entry((posting.node_id.clone(), posting.evidence_ref.clone()))
                .or_default();
            entry.0.insert(posting.normalized_term.clone());
            entry.1.extend(posting.positions.iter().copied());
        }
    }
    matched
        .into_iter()
        .map(
            |((node_id, evidence_ref), (matched_terms, positions))| LexicalSearchHitV1 {
                node_id,
                evidence_ref,
                match_kind,
                matched_terms: matched_terms.into_iter().collect(),
                positions: positions.into_iter().collect(),
            },
        )
        .collect()
}

fn search_phrase(
    by_term: &BTreeMap<&str, Vec<&gtkg_protocol::v03::query::LexicalPostingV1>>,
    tokens: &[QueryTokenV1],
) -> Vec<LexicalSearchHitV1> {
    let Some(first_postings) = by_term.get(tokens[0].normalized.as_str()) else {
        return Vec::new();
    };
    let mut hits = Vec::new();
    for first in first_postings {
        let starts = first
            .positions
            .iter()
            .copied()
            .filter(|start| {
                tokens.iter().enumerate().skip(1).all(|(offset, token)| {
                    let Ok(offset) = u64::try_from(offset) else {
                        return false;
                    };
                    let Some(expected) = start.checked_add(offset) else {
                        return false;
                    };
                    by_term
                        .get(token.normalized.as_str())
                        .into_iter()
                        .flatten()
                        .any(|posting| {
                            posting.node_id == first.node_id
                                && posting.evidence_ref == first.evidence_ref
                                && posting.positions.binary_search(&expected).is_ok()
                        })
                })
            })
            .collect::<Vec<_>>();
        if starts.is_empty() {
            continue;
        }
        hits.push(LexicalSearchHitV1 {
            node_id: first.node_id.clone(),
            evidence_ref: first.evidence_ref.clone(),
            match_kind: LexicalMatchKindV1::Phrase,
            matched_terms: tokens
                .iter()
                .map(|token| token.normalized.clone())
                .collect(),
            positions: starts,
        });
    }
    hits
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdjacencyEdgeInputV1 {
    pub edge_id: String,
    pub source_node_id: String,
    pub target_node_id: String,
    pub resolution_state: QueryResolutionStateV1,
    pub evidence_ref: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdjacencyMutationV1 {
    UpsertNode { node_id: String },
    DeleteNode { node_id: String },
    UpsertEdge(AdjacencyEdgeInputV1),
    DeleteEdge { edge_id: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AdjacencyIndexErrorV1 {
    #[error("adjacency node identity is invalid")]
    InvalidNode,
    #[error("adjacency node identity is duplicated")]
    DuplicateNode,
    #[error("adjacency edge identity is invalid")]
    InvalidEdge,
    #[error("adjacency edge identity is duplicated")]
    DuplicateEdge,
    #[error("adjacency edge references a node outside the exact node set")]
    DanglingEdge,
    #[error("an adjacency mutation batch touches the same identity twice")]
    DuplicateMutation,
    #[error("a node mutation deletes a node that is not present")]
    MissingNode,
    #[error("an edge mutation deletes an edge that is not present")]
    MissingEdge,
    #[error("an adjacency route names an unknown node")]
    UnknownNode,
    #[error("an adjacency shard or route identity is invalid")]
    InvalidShard,
    #[error("an adjacency record is duplicated, missing, dangling, or ghosted")]
    GhostEdge,
    #[error("adjacency shard content digest mismatch")]
    ContentDigestMismatch,
    #[error("adjacency routing catalog digest mismatch")]
    CatalogDigestMismatch,
    #[error("adjacency routing denominator is incomplete")]
    DenominatorInvalid,
    #[error("adjacency routing exceeds the frozen Q00 resource budget")]
    ResourceBudgetExceeded,
    #[error(transparent)]
    Contract(#[from] QueryContractErrorV1),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdjacencyIndexStateV1 {
    nodes: BTreeSet<String>,
    edges: BTreeMap<String, AdjacencyEdgeInputV1>,
}

impl AdjacencyIndexStateV1 {
    pub fn from_graph(
        nodes: &[String],
        edges: &[AdjacencyEdgeInputV1],
    ) -> Result<Self, AdjacencyIndexErrorV1> {
        let mut node_set = BTreeSet::new();
        for node_id in nodes {
            validate_adjacency_identity(node_id).map_err(|_| AdjacencyIndexErrorV1::InvalidNode)?;
            if !node_set.insert(node_id.clone()) {
                return Err(AdjacencyIndexErrorV1::DuplicateNode);
            }
        }
        if node_set.is_empty() {
            return Err(AdjacencyIndexErrorV1::InvalidNode);
        }
        let mut edge_map = BTreeMap::new();
        for edge in edges {
            validate_adjacency_edge_input(edge, &node_set)?;
            if edge_map
                .insert(edge.edge_id.clone(), edge.clone())
                .is_some()
            {
                return Err(AdjacencyIndexErrorV1::DuplicateEdge);
            }
        }
        Ok(Self {
            nodes: node_set,
            edges: edge_map,
        })
    }

    pub fn apply_mutations(
        &mut self,
        mutations: &[AdjacencyMutationV1],
    ) -> Result<(), AdjacencyIndexErrorV1> {
        let mut touched = BTreeSet::new();
        for mutation in mutations {
            let key = match mutation {
                AdjacencyMutationV1::UpsertNode { node_id }
                | AdjacencyMutationV1::DeleteNode { node_id } => (0_u8, node_id),
                AdjacencyMutationV1::UpsertEdge(edge) => (1_u8, &edge.edge_id),
                AdjacencyMutationV1::DeleteEdge { edge_id } => (1_u8, edge_id),
            };
            if !touched.insert((key.0, key.1.clone())) {
                return Err(AdjacencyIndexErrorV1::DuplicateMutation);
            }
        }

        let mut next_nodes = self.nodes.clone();
        let mut next_edges = self.edges.clone();
        for mutation in mutations {
            match mutation {
                AdjacencyMutationV1::UpsertNode { node_id } => {
                    validate_adjacency_identity(node_id)
                        .map_err(|_| AdjacencyIndexErrorV1::InvalidNode)?;
                    next_nodes.insert(node_id.clone());
                }
                AdjacencyMutationV1::DeleteNode { node_id } => {
                    if !next_nodes.remove(node_id) {
                        return Err(AdjacencyIndexErrorV1::MissingNode);
                    }
                    next_edges.retain(|_, edge| {
                        edge.source_node_id != *node_id && edge.target_node_id != *node_id
                    });
                }
                AdjacencyMutationV1::UpsertEdge(_) | AdjacencyMutationV1::DeleteEdge { .. } => {}
            }
        }
        if next_nodes.is_empty() {
            return Err(AdjacencyIndexErrorV1::InvalidNode);
        }
        for mutation in mutations {
            match mutation {
                AdjacencyMutationV1::UpsertEdge(edge) => {
                    validate_adjacency_edge_input(edge, &next_nodes)?;
                    next_edges.insert(edge.edge_id.clone(), edge.clone());
                }
                AdjacencyMutationV1::DeleteEdge { edge_id } => {
                    if next_edges.remove(edge_id).is_none() {
                        return Err(AdjacencyIndexErrorV1::MissingEdge);
                    }
                }
                AdjacencyMutationV1::UpsertNode { .. } | AdjacencyMutationV1::DeleteNode { .. } => {
                }
            }
        }
        for edge in next_edges.values() {
            validate_adjacency_edge_input(edge, &next_nodes)?;
        }
        self.nodes = next_nodes;
        self.edges = next_edges;
        Ok(())
    }

    pub fn build_index(&self) -> Result<AdjacencyRoutingIndexV1, AdjacencyIndexErrorV1> {
        build_adjacency_index_from_state(self, &QueryResourceBudgetsV1::v03_frozen())
    }

    /// Returns the canonical node exact set after any accepted mutation batch.
    pub fn nodes(&self) -> Vec<String> {
        self.nodes.iter().cloned().collect()
    }

    /// Returns the canonical edge exact set after any accepted mutation batch.
    pub fn edges(&self) -> Vec<AdjacencyEdgeInputV1> {
        self.edges.values().cloned().collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdjacencyRouteResultV1 {
    pub node_id: String,
    pub direction: AdjacencyDirectionV1,
    pub selected_shard_id: Option<String>,
    pub selected_shard_count: u64,
    pub edges: Vec<AdjacencyEdgeRecordV1>,
    pub full_graph_read_count: u64,
    pub database_read_count: u64,
    pub network_call_count: u64,
    pub daemon_call_count: u64,
}

pub fn build_adjacency_routing_index_v1(
    nodes: &[String],
    edges: &[AdjacencyEdgeInputV1],
) -> Result<AdjacencyRoutingIndexV1, AdjacencyIndexErrorV1> {
    AdjacencyIndexStateV1::from_graph(nodes, edges)?.build_index()
}

pub fn build_adjacency_routing_index_with_budgets_v1(
    nodes: &[String],
    edges: &[AdjacencyEdgeInputV1],
    budgets: &QueryResourceBudgetsV1,
) -> Result<AdjacencyRoutingIndexV1, AdjacencyIndexErrorV1> {
    if *budgets != QueryResourceBudgetsV1::v03_frozen() {
        return Err(AdjacencyIndexErrorV1::ResourceBudgetExceeded);
    }
    let state = AdjacencyIndexStateV1::from_graph(nodes, edges)?;
    build_adjacency_index_from_state(&state, budgets)
}

fn build_adjacency_index_from_state(
    state: &AdjacencyIndexStateV1,
    budgets: &QueryResourceBudgetsV1,
) -> Result<AdjacencyRoutingIndexV1, AdjacencyIndexErrorV1> {
    let mut grouped = BTreeMap::<(String, AdjacencyDirectionV1), Vec<AdjacencyEdgeRecordV1>>::new();
    for edge in state.edges.values() {
        for (node_id, direction) in [
            (&edge.source_node_id, AdjacencyDirectionV1::Outgoing),
            (&edge.target_node_id, AdjacencyDirectionV1::Incoming),
        ] {
            grouped
                .entry((adjacency_node_bucket_v1(node_id), direction))
                .or_default()
                .push(AdjacencyEdgeRecordV1 {
                    node_id: node_id.clone(),
                    edge_id: edge.edge_id.clone(),
                    source_node_id: edge.source_node_id.clone(),
                    target_node_id: edge.target_node_id.clone(),
                    resolution_state: edge.resolution_state,
                    evidence_ref: edge.evidence_ref.clone(),
                });
        }
    }

    let mut routes = BTreeSet::new();
    let mut shards = Vec::with_capacity(grouped.len());
    for ((bucket, direction), mut records) in grouped {
        records.sort_by(|left, right| {
            (&left.node_id, &left.edge_id).cmp(&(&right.node_id, &right.edge_id))
        });
        let shard_id = adjacency_shard_id_v1(&bucket, direction);
        for record in &records {
            routes.insert(AdjacencyNodeRouteV1 {
                node_id: record.node_id.clone(),
                direction,
                shard_id: shard_id.clone(),
            });
        }
        let edge_states = records
            .iter()
            .map(|record| (record.edge_id.clone(), record.resolution_state))
            .collect::<BTreeMap<_, _>>();
        if edge_states.len() != records.len() {
            return Err(AdjacencyIndexErrorV1::DuplicateEdge);
        }
        let mut shard = AdjacencyRoutingShardV1 {
            header: AdjacencyShardV1 {
                schema_version: ADJACENCY_SHARD_SCHEMA_V1.to_owned(),
                shard_id,
                node_bucket: bucket,
                direction,
                edge_ids: edge_states.keys().cloned().collect(),
                resolution_states: edge_states.values().copied().collect(),
                raw_bytes_sha256: String::new(),
            },
            evidence_refs: records
                .iter()
                .map(|record| record.evidence_ref.clone())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
            records,
        };
        shard.header.raw_bytes_sha256 = adjacency_routing_shard_content_sha256_v1(&shard);
        shards.push(shard);
    }
    shards.sort_by(|left, right| left.header.shard_id.cmp(&right.header.shard_id));
    let descriptors = shard_descriptors_without_validation(&shards)?;
    let nodes = state.nodes.iter().cloned().collect::<Vec<_>>();
    let edges = state.edges.values().cloned().collect::<Vec<_>>();
    let mut catalog = AdjacencyRoutingCatalogV1 {
        schema_version: ADJACENCY_ROUTING_CATALOG_SCHEMA_V1.to_owned(),
        graph_identity: adjacency_graph_identity_v1(&nodes, &edges),
        nodes,
        routes: routes.into_iter().collect(),
        shards: descriptors,
        denominator: AdjacencyRoutingDenominatorV1 {
            node_count: count_u64(state.nodes.len())?,
            edge_count: count_u64(state.edges.len())?,
            route_count: 0,
            shard_count: count_u64(shards.len())?,
            adjacency_record_count: state
                .edges
                .len()
                .checked_mul(2)
                .and_then(|count| u64::try_from(count).ok())
                .ok_or(AdjacencyIndexErrorV1::ResourceBudgetExceeded)?,
        },
        raw_bytes_sha256: String::new(),
    };
    catalog.denominator.route_count = count_u64(catalog.routes.len())?;
    catalog.raw_bytes_sha256 = adjacency_routing_catalog_content_sha256_v1(&catalog);
    let index = AdjacencyRoutingIndexV1 { catalog, shards };
    validate_adjacency_routing_index_v1(&index, budgets)?;
    Ok(index)
}

pub fn adjacency_routing_shard_content_sha256_v1(shard: &AdjacencyRoutingShardV1) -> String {
    json_sha256(&(
        shard.header.schema_version.as_str(),
        shard.header.shard_id.as_str(),
        shard.header.node_bucket.as_str(),
        shard.header.direction,
        &shard.header.edge_ids,
        &shard.header.resolution_states,
        &shard.records,
        &shard.evidence_refs,
    ))
}

pub fn adjacency_routing_catalog_content_sha256_v1(catalog: &AdjacencyRoutingCatalogV1) -> String {
    json_sha256(&(
        catalog.schema_version.as_str(),
        catalog.graph_identity.as_str(),
        &catalog.nodes,
        &catalog.routes,
        &catalog.shards,
        catalog.denominator,
    ))
}

pub fn query_adjacency_shard_descriptors_v1(
    index: &AdjacencyRoutingIndexV1,
) -> Result<Vec<QueryShardDescriptorV1>, AdjacencyIndexErrorV1> {
    validate_adjacency_routing_index_v1(index, &QueryResourceBudgetsV1::v03_frozen())?;
    Ok(index.catalog.shards.clone())
}

pub fn validate_adjacency_routing_index_v1(
    index: &AdjacencyRoutingIndexV1,
    budgets: &QueryResourceBudgetsV1,
) -> Result<(), AdjacencyIndexErrorV1> {
    if *budgets != QueryResourceBudgetsV1::v03_frozen() {
        return Err(AdjacencyIndexErrorV1::ResourceBudgetExceeded);
    }
    validate_adjacency_catalog_shape(&index.catalog, budgets)?;
    if index.shards.len() as u64 > budgets.max_shard_count
        || !sorted_or_empty_by(&index.shards, |left, right| {
            left.header.shard_id < right.header.shard_id
        })
    {
        return Err(AdjacencyIndexErrorV1::InvalidShard);
    }

    let nodes = index.catalog.nodes.iter().cloned().collect::<BTreeSet<_>>();
    let mut expected_routes = BTreeSet::new();
    let mut outgoing = BTreeMap::<String, AdjacencyEdgeInputV1>::new();
    let mut incoming = BTreeMap::<String, AdjacencyEdgeInputV1>::new();
    for shard in &index.shards {
        if shard.header.raw_bytes_sha256 != adjacency_routing_shard_content_sha256_v1(shard) {
            return Err(AdjacencyIndexErrorV1::ContentDigestMismatch);
        }
        validate_adjacency_shard_v1(&shard.header, budgets)?;
        validate_routing_shard(
            shard,
            &nodes,
            budgets,
            &mut expected_routes,
            &mut outgoing,
            &mut incoming,
        )?;
    }
    if outgoing != incoming {
        return Err(AdjacencyIndexErrorV1::GhostEdge);
    }
    if expected_routes
        != index
            .catalog
            .routes
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>()
    {
        return Err(AdjacencyIndexErrorV1::InvalidShard);
    }
    let expected_descriptors = shard_descriptors_without_validation(&index.shards)?;
    if expected_descriptors != index.catalog.shards {
        return Err(AdjacencyIndexErrorV1::ContentDigestMismatch);
    }
    let edges = outgoing.values().cloned().collect::<Vec<_>>();
    if index.catalog.graph_identity != adjacency_graph_identity_v1(&index.catalog.nodes, &edges) {
        return Err(AdjacencyIndexErrorV1::ContentDigestMismatch);
    }
    let denominator = index.catalog.denominator;
    let expected_records = denominator
        .edge_count
        .checked_mul(2)
        .ok_or(AdjacencyIndexErrorV1::DenominatorInvalid)?;
    if denominator.node_count != index.catalog.nodes.len() as u64
        || denominator.edge_count != outgoing.len() as u64
        || denominator.route_count != index.catalog.routes.len() as u64
        || denominator.shard_count != index.shards.len() as u64
        || denominator.adjacency_record_count != expected_records
        || denominator.adjacency_record_count
            != index
                .shards
                .iter()
                .map(|shard| shard.records.len() as u64)
                .sum::<u64>()
    {
        return Err(AdjacencyIndexErrorV1::DenominatorInvalid);
    }
    if index.catalog.raw_bytes_sha256 != adjacency_routing_catalog_content_sha256_v1(&index.catalog)
    {
        return Err(AdjacencyIndexErrorV1::CatalogDigestMismatch);
    }
    if index.shards.len() != index.catalog.shards.len()
        || !sorted_or_empty_by(&index.shards, |left, right| {
            left.header.shard_id < right.header.shard_id
        })
    {
        return Err(AdjacencyIndexErrorV1::InvalidShard);
    }
    Ok(())
}

fn validate_adjacency_catalog_shape(
    catalog: &AdjacencyRoutingCatalogV1,
    budgets: &QueryResourceBudgetsV1,
) -> Result<(), AdjacencyIndexErrorV1> {
    if catalog.schema_version != ADJACENCY_ROUTING_CATALOG_SCHEMA_V1
        || !is_sha256(&catalog.graph_identity)
        || !is_sha256(&catalog.raw_bytes_sha256)
        || catalog.nodes.is_empty()
        || !strictly_sorted(&catalog.nodes)
        || catalog
            .nodes
            .iter()
            .any(|node| validate_adjacency_identity(node).is_err())
        || !sorted_or_empty(&catalog.routes)
        || !sorted_or_empty_by(&catalog.shards, |left, right| {
            left.shard_id < right.shard_id
        })
        || catalog.shards.len() as u64 > budgets.max_shard_count
        || serde_json::to_vec(catalog).map_or(true, |bytes| {
            bytes.len() as u64 > budgets.max_manifest_bytes
        })
    {
        return Err(AdjacencyIndexErrorV1::InvalidShard);
    }
    if catalog.denominator.node_count != catalog.nodes.len() as u64
        || catalog.denominator.route_count != catalog.routes.len() as u64
        || catalog.denominator.shard_count != catalog.shards.len() as u64
    {
        return Err(AdjacencyIndexErrorV1::DenominatorInvalid);
    }
    Ok(())
}

fn validate_routing_shard(
    shard: &AdjacencyRoutingShardV1,
    nodes: &BTreeSet<String>,
    budgets: &QueryResourceBudgetsV1,
    expected_routes: &mut BTreeSet<AdjacencyNodeRouteV1>,
    outgoing: &mut BTreeMap<String, AdjacencyEdgeInputV1>,
    incoming: &mut BTreeMap<String, AdjacencyEdgeInputV1>,
) -> Result<(), AdjacencyIndexErrorV1> {
    if shard.records.is_empty()
        || shard.records.len() as u64 > budgets.max_records_per_shard
        || serde_json::to_vec(shard)
            .map_or(true, |bytes| bytes.len() as u64 > budgets.max_shard_bytes)
        || !strictly_sorted_by(&shard.records, |left, right| {
            (&left.node_id, &left.edge_id) < (&right.node_id, &right.edge_id)
        })
        || !strictly_sorted(&shard.evidence_refs)
        || shard.header.shard_id
            != adjacency_shard_id_v1(&shard.header.node_bucket, shard.header.direction)
    {
        return Err(AdjacencyIndexErrorV1::InvalidShard);
    }
    let evidence = shard
        .evidence_refs
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let mut states = BTreeMap::new();
    for record in &shard.records {
        if validate_adjacency_identity(&record.node_id).is_err()
            || validate_adjacency_identity(&record.edge_id).is_err()
            || validate_adjacency_identity(&record.source_node_id).is_err()
            || validate_adjacency_identity(&record.target_node_id).is_err()
            || validate_adjacency_identity(&record.evidence_ref).is_err()
            || !nodes.contains(&record.node_id)
            || !nodes.contains(&record.source_node_id)
            || !nodes.contains(&record.target_node_id)
            || !evidence.contains(record.evidence_ref.as_str())
            || adjacency_node_bucket_v1(&record.node_id) != shard.header.node_bucket
            || match shard.header.direction {
                AdjacencyDirectionV1::Outgoing => record.node_id != record.source_node_id,
                AdjacencyDirectionV1::Incoming => record.node_id != record.target_node_id,
            }
        {
            return Err(AdjacencyIndexErrorV1::GhostEdge);
        }
        if states
            .insert(record.edge_id.clone(), record.resolution_state)
            .is_some()
        {
            return Err(AdjacencyIndexErrorV1::GhostEdge);
        }
        expected_routes.insert(AdjacencyNodeRouteV1 {
            node_id: record.node_id.clone(),
            direction: shard.header.direction,
            shard_id: shard.header.shard_id.clone(),
        });
        let edge = AdjacencyEdgeInputV1 {
            edge_id: record.edge_id.clone(),
            source_node_id: record.source_node_id.clone(),
            target_node_id: record.target_node_id.clone(),
            resolution_state: record.resolution_state,
            evidence_ref: record.evidence_ref.clone(),
        };
        let target = match shard.header.direction {
            AdjacencyDirectionV1::Outgoing => &mut *outgoing,
            AdjacencyDirectionV1::Incoming => &mut *incoming,
        };
        if target.insert(edge.edge_id.clone(), edge).is_some() {
            return Err(AdjacencyIndexErrorV1::GhostEdge);
        }
    }
    if shard.header.edge_ids != states.keys().cloned().collect::<Vec<_>>()
        || shard.header.resolution_states != states.values().copied().collect::<Vec<_>>()
    {
        return Err(AdjacencyIndexErrorV1::GhostEdge);
    }
    Ok(())
}

pub fn route_adjacency_edges_v1(
    index: &AdjacencyRoutingIndexV1,
    node_id: &str,
    direction: AdjacencyDirectionV1,
) -> Result<AdjacencyRouteResultV1, AdjacencyIndexErrorV1> {
    let budgets = QueryResourceBudgetsV1::v03_frozen();
    validate_adjacency_catalog_shape(&index.catalog, &budgets)?;
    if index.catalog.raw_bytes_sha256 != adjacency_routing_catalog_content_sha256_v1(&index.catalog)
    {
        return Err(AdjacencyIndexErrorV1::CatalogDigestMismatch);
    }
    if index.shards.len() != index.catalog.shards.len()
        || !sorted_or_empty_by(&index.shards, |left, right| {
            left.header.shard_id < right.header.shard_id
        })
    {
        return Err(AdjacencyIndexErrorV1::InvalidShard);
    }
    if index
        .catalog
        .nodes
        .binary_search_by(|candidate| candidate.as_str().cmp(node_id))
        .is_err()
    {
        return Err(AdjacencyIndexErrorV1::UnknownNode);
    }
    let route = index
        .catalog
        .routes
        .iter()
        .find(|route| route.node_id == node_id && route.direction == direction);
    let Some(route) = route else {
        return Ok(AdjacencyRouteResultV1 {
            node_id: node_id.to_owned(),
            direction,
            selected_shard_id: None,
            selected_shard_count: 0,
            edges: Vec::new(),
            full_graph_read_count: 0,
            database_read_count: 0,
            network_call_count: 0,
            daemon_call_count: 0,
        });
    };
    let descriptor = index
        .catalog
        .shards
        .iter()
        .find(|descriptor| descriptor.shard_id == route.shard_id)
        .ok_or(AdjacencyIndexErrorV1::InvalidShard)?;
    let shard = index
        .shards
        .iter()
        .find(|shard| shard.header.shard_id == route.shard_id)
        .ok_or(AdjacencyIndexErrorV1::InvalidShard)?;
    if shard.header.raw_bytes_sha256 != adjacency_routing_shard_content_sha256_v1(shard) {
        return Err(AdjacencyIndexErrorV1::ContentDigestMismatch);
    }
    validate_adjacency_shard_v1(&shard.header, &budgets)?;
    let mut selected_routes = BTreeSet::new();
    let mut outgoing = BTreeMap::new();
    let mut incoming = BTreeMap::new();
    validate_routing_shard(
        shard,
        &index.catalog.nodes.iter().cloned().collect(),
        &budgets,
        &mut selected_routes,
        &mut outgoing,
        &mut incoming,
    )?;
    if shard.header.direction != direction || !selected_routes.contains(route) {
        return Err(AdjacencyIndexErrorV1::InvalidShard);
    }
    let expected_descriptor = shard_descriptors_without_validation(std::slice::from_ref(shard))?
        .pop()
        .ok_or(AdjacencyIndexErrorV1::InvalidShard)?;
    if *descriptor != expected_descriptor {
        return Err(AdjacencyIndexErrorV1::ContentDigestMismatch);
    }
    let edges = shard
        .records
        .iter()
        .filter(|record| record.node_id == node_id)
        .cloned()
        .collect::<Vec<_>>();
    if edges.is_empty() {
        return Err(AdjacencyIndexErrorV1::InvalidShard);
    }
    Ok(AdjacencyRouteResultV1 {
        node_id: node_id.to_owned(),
        direction,
        selected_shard_id: Some(route.shard_id.clone()),
        selected_shard_count: 1,
        edges,
        full_graph_read_count: 0,
        database_read_count: 0,
        network_call_count: 0,
        daemon_call_count: 0,
    })
}

fn validate_adjacency_edge_input(
    edge: &AdjacencyEdgeInputV1,
    nodes: &BTreeSet<String>,
) -> Result<(), AdjacencyIndexErrorV1> {
    if validate_adjacency_identity(&edge.edge_id).is_err()
        || validate_adjacency_identity(&edge.source_node_id).is_err()
        || validate_adjacency_identity(&edge.target_node_id).is_err()
        || validate_adjacency_identity(&edge.evidence_ref).is_err()
    {
        return Err(AdjacencyIndexErrorV1::InvalidEdge);
    }
    if !nodes.contains(&edge.source_node_id) || !nodes.contains(&edge.target_node_id) {
        return Err(AdjacencyIndexErrorV1::DanglingEdge);
    }
    Ok(())
}

fn validate_adjacency_identity(value: &str) -> Result<(), ()> {
    if value.is_empty()
        || value.len() > 4_096
        || value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        Err(())
    } else {
        Ok(())
    }
}

fn adjacency_node_bucket_v1(node_id: &str) -> String {
    format!("{:02x}", Sha256::digest(node_id.as_bytes())[0])
}

fn adjacency_shard_id_v1(bucket: &str, direction: AdjacencyDirectionV1) -> String {
    let direction = match direction {
        AdjacencyDirectionV1::Outgoing => "outgoing",
        AdjacencyDirectionV1::Incoming => "incoming",
    };
    format!("adj-{bucket}-{direction}")
}

fn adjacency_graph_identity_v1(nodes: &[String], edges: &[AdjacencyEdgeInputV1]) -> String {
    json_sha256(&("gtkg.adjacency-graph/v1", nodes, edges))
}

fn shard_descriptors_without_validation(
    shards: &[AdjacencyRoutingShardV1],
) -> Result<Vec<QueryShardDescriptorV1>, AdjacencyIndexErrorV1> {
    shards
        .iter()
        .map(|shard| {
            let bytes = serde_json::to_vec(shard)
                .map_err(|_| AdjacencyIndexErrorV1::ResourceBudgetExceeded)?;
            Ok(QueryShardDescriptorV1 {
                shard_id: shard.header.shard_id.clone(),
                shard_kind: QueryShardKindV1::Adjacency,
                raw_bytes_sha256: shard.header.raw_bytes_sha256.clone(),
                byte_len: u64::try_from(bytes.len())
                    .map_err(|_| AdjacencyIndexErrorV1::ResourceBudgetExceeded)?,
                record_count: u64::try_from(shard.records.len())
                    .map_err(|_| AdjacencyIndexErrorV1::ResourceBudgetExceeded)?,
            })
        })
        .collect()
}

fn count_u64(value: usize) -> Result<u64, AdjacencyIndexErrorV1> {
    u64::try_from(value).map_err(|_| AdjacencyIndexErrorV1::ResourceBudgetExceeded)
}

fn sorted_or_empty<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn sorted_or_empty_by<T>(values: &[T], less: impl Fn(&T, &T) -> bool) -> bool {
    values.windows(2).all(|pair| less(&pair[0], &pair[1]))
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum FileQueryErrorV1 {
    #[error("file query manifest is invalid")]
    InvalidManifest,
    #[error("file query manifest content is tampered")]
    ManifestTampered,
    #[error("query index identity is stale and requires rebuild")]
    StaleIndex,
    #[error("routing catalog declared a match but selected no shard")]
    ZeroShardSelection,
    #[error("selected shard bytes or semantic content are tampered")]
    ShardTampered,
    #[error("query index path is unsafe, symlinked, hardlinked, or changed")]
    UnsafePath,
    #[error("file query exceeds a frozen Q00 resource budget")]
    ResourceBudgetExceeded,
    #[error("opaque query continuation is invalid or bound to another query")]
    ContinuationInvalid,
    #[error("file query is empty or unsupported")]
    QueryInvalid,
    #[error("file query I/O failed")]
    Io,
    #[error(transparent)]
    Contract(#[from] QueryContractErrorV1),
    #[error(transparent)]
    Lexical(#[from] LexicalIndexErrorV1),
    #[error(transparent)]
    Adjacency(#[from] AdjacencyIndexErrorV1),
}

impl FileQueryErrorV1 {
    pub const fn requires_rebuild(&self) -> bool {
        matches!(
            self,
            Self::StaleIndex
                | Self::ZeroShardSelection
                | Self::ManifestTampered
                | Self::ShardTampered
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileQueryPlanV1 {
    pub manifest_ref: FileReceiptRef,
    pub manifest_sha256: String,
    pub index_manifest_sha256: String,
    pub routing_catalog_sha256: String,
    pub query_sha256: String,
    pub selected_shards: Vec<String>,
    pub excluded_shards: Vec<String>,
    pub start_offset: u64,
    pub page_size: u64,
    pub prior_page_sha256: Option<String>,
    pub budget: QueryPlanBudgetV1,
    pub plan_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileQueryPageV1 {
    pub receipt: QueryPlanReceiptV1,
    pub plan_sha256: String,
    pub start_offset: u64,
    pub end_offset: u64,
    pub lexical_hits: Vec<LexicalSearchHitV1>,
    pub adjacency_edges: Vec<AdjacencyEdgeRecordV1>,
    pub opened_shards: Vec<String>,
    pub result_count: u64,
    pub total_result_count: u64,
    pub manifest_bytes_read: u64,
    pub shard_bytes_read: u64,
    pub response_bytes: u64,
    pub shard_files_opened: u64,
    pub plan_completed_before_shard_read: bool,
    pub full_graph_read_count: u64,
    pub database_read_count: u64,
    pub network_call_count: u64,
    pub daemon_call_count: u64,
    pub prior_page_sha256: Option<String>,
    pub page_sha256: String,
}

struct PublishedQueryShardV1 {
    descriptor: QueryShardDescriptorV1,
    file: FileQueryShardV1,
}

struct QueryShardPublishSpecV1 {
    shard_id: String,
    shard_kind: QueryShardKindV1,
    content_sha256: String,
    record_count: u64,
    term_count: u64,
    routing_keys: Vec<String>,
}

static QUERY_TEMP_SEQUENCE_V1: AtomicU64 = AtomicU64::new(0);

pub fn lexical_routing_catalog_content_sha256_v1(catalog: &LexicalRoutingCatalogV1) -> String {
    json_sha256(&("gtkg.lexical-routing-catalog/v1", &catalog.entries))
}

fn lexical_routing_keys_for_shard(shard: &LexicalShardV1) -> Vec<String> {
    let mut routing_keys = BTreeSet::new();
    for term in &shard.normalized_terms {
        routing_keys.insert(lexical_term_route_key(&term.normalized));
        let tokens = tokenize_query_v1(&term.normalized).tokens;
        if tokens.len() == 1 && tokens[0].kind == QueryTokenKindV1::CjkRun {
            routing_keys.extend(
                short_cjk_scalar_substrings(&term.normalized)
                    .into_iter()
                    .map(|substring| lexical_short_route_key(&substring)),
            );
        }
    }
    routing_keys.extend(
        shard
            .trigrams
            .iter()
            .map(|trigram| lexical_trigram_route_key(trigram)),
    );
    routing_keys.into_iter().collect()
}

fn adjacency_routing_key(node_id: &str, direction: AdjacencyDirectionV1) -> String {
    let direction = match direction {
        AdjacencyDirectionV1::Outgoing => "out",
        AdjacencyDirectionV1::Incoming => "in",
    };
    format!("adj:{direction}:{}", hex::encode(node_id.as_bytes()))
}

fn adjacency_routing_keys_for_shard(shard: &AdjacencyRoutingShardV1) -> Vec<String> {
    shard
        .records
        .iter()
        .map(|record| adjacency_routing_key(&record.node_id, shard.header.direction))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn complete_file_adjacency_routes(
    catalog: &AdjacencyRoutingCatalogV1,
) -> Vec<FileAdjacencyRouteV1> {
    let routes = catalog
        .routes
        .iter()
        .map(|route| {
            (
                (route.node_id.as_str(), route.direction),
                route.shard_id.clone(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    catalog
        .nodes
        .iter()
        .flat_map(|node_id| {
            [
                AdjacencyDirectionV1::Outgoing,
                AdjacencyDirectionV1::Incoming,
            ]
            .map(|direction| FileAdjacencyRouteV1 {
                node_id: node_id.clone(),
                direction,
                shard_id: routes.get(&(node_id.as_str(), direction)).cloned(),
            })
        })
        .collect()
}

fn lexical_routing_entries_from_files(
    files: &[FileQueryShardV1],
) -> Result<Vec<LexicalRoutingEntryV1>, FileQueryErrorV1> {
    let mut routes = BTreeMap::<String, BTreeSet<String>>::new();
    for file in files
        .iter()
        .filter(|file| file.shard_kind == QueryShardKindV1::Lexical)
    {
        for key in &file.routing_keys {
            if !valid_routing_key(key) {
                return Err(FileQueryErrorV1::InvalidManifest);
            }
            routes
                .entry(key.clone())
                .or_default()
                .insert(file.shard_id.clone());
        }
    }
    Ok(routes
        .into_iter()
        .map(|(routing_key, shard_ids)| LexicalRoutingEntryV1 {
            routing_key,
            shard_ids: shard_ids.into_iter().collect(),
        })
        .collect())
}

fn parse_adjacency_routing_key(
    key: &str,
) -> Result<(String, AdjacencyDirectionV1), FileQueryErrorV1> {
    let (direction, encoded) = if let Some(encoded) = key.strip_prefix("adj:out:") {
        (AdjacencyDirectionV1::Outgoing, encoded)
    } else if let Some(encoded) = key.strip_prefix("adj:in:") {
        (AdjacencyDirectionV1::Incoming, encoded)
    } else {
        return Err(FileQueryErrorV1::InvalidManifest);
    };
    if encoded.is_empty()
        || !encoded.len().is_multiple_of(2)
        || !encoded
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(FileQueryErrorV1::InvalidManifest);
    }
    let node_id = hex::decode(encoded)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .ok_or(FileQueryErrorV1::InvalidManifest)?;
    if validate_adjacency_identity(&node_id).is_err()
        || adjacency_routing_key(&node_id, direction) != key
    {
        return Err(FileQueryErrorV1::InvalidManifest);
    }
    Ok((node_id, direction))
}

type FileAdjacencyRouteMapV1 = BTreeMap<(String, AdjacencyDirectionV1), String>;

fn complete_adjacency_routes_from_files(
    files: &[FileQueryShardV1],
    nodes: &BTreeSet<&str>,
) -> Result<(Vec<FileAdjacencyRouteV1>, FileAdjacencyRouteMapV1), FileQueryErrorV1> {
    let mut nonempty = BTreeMap::new();
    for file in files
        .iter()
        .filter(|file| file.shard_kind == QueryShardKindV1::Adjacency)
    {
        for key in &file.routing_keys {
            let (node_id, direction) = parse_adjacency_routing_key(key)?;
            if !nodes.contains(node_id.as_str())
                || file.shard_id
                    != adjacency_shard_id_v1(&adjacency_node_bucket_v1(&node_id), direction)
                || nonempty
                    .insert((node_id, direction), file.shard_id.clone())
                    .is_some()
            {
                return Err(FileQueryErrorV1::InvalidManifest);
            }
        }
    }
    let routes = nodes
        .iter()
        .flat_map(|node_id| {
            [
                AdjacencyDirectionV1::Outgoing,
                AdjacencyDirectionV1::Incoming,
            ]
            .map(|direction| FileAdjacencyRouteV1 {
                node_id: (*node_id).to_owned(),
                direction,
                shard_id: nonempty.get(&((*node_id).to_owned(), direction)).cloned(),
            })
        })
        .collect();
    Ok((routes, nonempty))
}

pub fn file_query_index_manifest_content_sha256_v1(manifest: &FileQueryIndexManifestV1) -> String {
    json_sha256(&(
        manifest.schema_version.as_str(),
        &manifest.index,
        manifest.index_manifest_sha256.as_str(),
        &manifest.lexical_routing_catalog,
        &manifest.adjacency_catalog,
        &manifest.adjacency_routes,
        &manifest.shard_files,
    ))
}

fn file_query_current_binding_content_sha256(binding: &FileQueryCurrentBindingV1) -> String {
    json_sha256(&(
        binding.schema_version.as_str(),
        binding.source_identity.as_str(),
        binding.graph_identity.as_str(),
        binding.overlay_identity.as_str(),
        binding.index_manifest_sha256.as_str(),
        &binding.manifest_ref,
    ))
}

pub fn write_file_query_index_v1(
    context: &CallContext,
    index_root: &Path,
    expected: &FileQueryExpectedIdentitiesV1,
    lexical_shards: &[LexicalShardV1],
    adjacency: &AdjacencyRoutingIndexV1,
) -> Result<FileReceiptRef, FileQueryErrorV1> {
    write_file_query_index_internal::<fn(&Path), fn(&Path)>(
        context,
        index_root,
        expected,
        lexical_shards,
        adjacency,
        None,
        None,
    )
}

#[cfg(feature = "test-faults")]
pub fn write_file_query_index_with_pre_mkdir_hook_v1<F>(
    context: &CallContext,
    index_root: &Path,
    expected: &FileQueryExpectedIdentitiesV1,
    lexical_shards: &[LexicalShardV1],
    adjacency: &AdjacencyRoutingIndexV1,
    hook: F,
) -> Result<FileReceiptRef, FileQueryErrorV1>
where
    F: FnOnce(&Path),
{
    write_file_query_index_internal(
        context,
        index_root,
        expected,
        lexical_shards,
        adjacency,
        Some(hook),
        None::<fn(&Path)>,
    )
}

#[cfg(feature = "test-faults")]
pub fn write_file_query_index_with_pre_publish_hook_v1<F>(
    context: &CallContext,
    index_root: &Path,
    expected: &FileQueryExpectedIdentitiesV1,
    lexical_shards: &[LexicalShardV1],
    adjacency: &AdjacencyRoutingIndexV1,
    hook: F,
) -> Result<FileReceiptRef, FileQueryErrorV1>
where
    F: FnOnce(&Path),
{
    write_file_query_index_internal(
        context,
        index_root,
        expected,
        lexical_shards,
        adjacency,
        None::<fn(&Path)>,
        Some(hook),
    )
}

fn write_file_query_index_internal<M, P>(
    context: &CallContext,
    index_root: &Path,
    expected: &FileQueryExpectedIdentitiesV1,
    lexical_shards: &[LexicalShardV1],
    adjacency: &AdjacencyRoutingIndexV1,
    pre_mkdir: Option<M>,
    pre_publish: Option<P>,
) -> Result<FileReceiptRef, FileQueryErrorV1>
where
    M: FnOnce(&Path),
    P: FnOnce(&Path),
{
    if ![
        &expected.source_identity,
        &expected.graph_identity,
        &expected.overlay_identity,
    ]
    .into_iter()
    .all(|value| is_sha256(value))
        || lexical_shards.is_empty()
        || adjacency.shards.is_empty()
    {
        return Err(FileQueryErrorV1::InvalidManifest);
    }
    let index_root = absolute_query_candidate(context, index_root)?;
    context
        .authorize_write(&index_root)
        .map_err(file_query_context_error)?;
    create_query_directory_descriptor_first(context, &index_root, pre_mkdir)?;
    create_query_directory_descriptor_first(
        context,
        &index_root.join("shards"),
        None::<fn(&Path)>,
    )?;
    create_query_directory_descriptor_first(
        context,
        &index_root.join("manifests"),
        None::<fn(&Path)>,
    )?;
    create_query_directory_descriptor_first(
        context,
        &index_root.join("binding"),
        None::<fn(&Path)>,
    )?;
    if let Some(hook) = pre_publish {
        hook(&index_root);
    }
    validate_adjacency_routing_index_v1(adjacency, &QueryResourceBudgetsV1::v03_frozen())?;

    let mut identities = BTreeSet::new();
    let mut published = Vec::new();
    let mut lexical_routes = BTreeMap::<String, BTreeSet<String>>::new();
    for shard in lexical_shards {
        validate_lexical_shard_v1(shard, &QueryResourceBudgetsV1::v03_frozen())?;
        if shard.raw_bytes_sha256 != lexical_shard_content_sha256_v1(shard)
            || !identities.insert(shard.shard_id.clone())
        {
            return Err(FileQueryErrorV1::ShardTampered);
        }
        let routing_keys = lexical_routing_keys_for_shard(shard);
        for routing_key in &routing_keys {
            lexical_routes
                .entry(routing_key.clone())
                .or_default()
                .insert(shard.shard_id.clone());
        }
        published.push(publish_query_shard(
            context,
            &index_root,
            QueryShardPublishSpecV1 {
                shard_id: shard.shard_id.clone(),
                shard_kind: QueryShardKindV1::Lexical,
                content_sha256: shard.raw_bytes_sha256.clone(),
                record_count: count_u64(shard.postings.len())
                    .map_err(|_| FileQueryErrorV1::ResourceBudgetExceeded)?,
                term_count: count_u64(shard.normalized_terms.len())
                    .map_err(|_| FileQueryErrorV1::ResourceBudgetExceeded)?,
                routing_keys,
            },
            shard,
        )?);
    }
    for shard in &adjacency.shards {
        if !identities.insert(shard.header.shard_id.clone()) {
            return Err(FileQueryErrorV1::InvalidManifest);
        }
        let routing_keys = adjacency_routing_keys_for_shard(shard);
        published.push(publish_query_shard(
            context,
            &index_root,
            QueryShardPublishSpecV1 {
                shard_id: shard.header.shard_id.clone(),
                shard_kind: QueryShardKindV1::Adjacency,
                content_sha256: shard.header.raw_bytes_sha256.clone(),
                record_count: count_u64(shard.records.len())
                    .map_err(|_| FileQueryErrorV1::ResourceBudgetExceeded)?,
                term_count: 0,
                routing_keys,
            },
            shard,
        )?);
    }
    published.sort_by(|left, right| left.descriptor.shard_id.cmp(&right.descriptor.shard_id));
    let descriptors = published
        .iter()
        .map(|value| value.descriptor.clone())
        .collect::<Vec<_>>();
    let mut file_adjacency_catalog = adjacency.catalog.clone();
    file_adjacency_catalog.shards = descriptors
        .iter()
        .filter(|entry| entry.shard_kind == QueryShardKindV1::Adjacency)
        .cloned()
        .collect();
    file_adjacency_catalog.denominator.shard_count = count_u64(file_adjacency_catalog.shards.len())
        .map_err(|_| FileQueryErrorV1::ResourceBudgetExceeded)?;
    file_adjacency_catalog.raw_bytes_sha256 =
        adjacency_routing_catalog_content_sha256_v1(&file_adjacency_catalog);
    let adjacency_routes = complete_file_adjacency_routes(&file_adjacency_catalog);
    let mut lexical_routing_catalog = LexicalRoutingCatalogV1 {
        entries: lexical_routes
            .into_iter()
            .map(|(routing_key, shard_ids)| LexicalRoutingEntryV1 {
                routing_key,
                shard_ids: shard_ids.into_iter().collect(),
            })
            .collect(),
        raw_bytes_sha256: String::new(),
    };
    lexical_routing_catalog.raw_bytes_sha256 =
        lexical_routing_catalog_content_sha256_v1(&lexical_routing_catalog);
    let budgets = QueryResourceBudgetsV1::v03_frozen();
    let index = QueryIndexManifestV1 {
        schema_version: QUERY_INDEX_MANIFEST_SCHEMA_V1.to_owned(),
        source_identity: expected.source_identity.clone(),
        graph_identity: expected.graph_identity.clone(),
        overlay_identity: expected.overlay_identity.clone(),
        tokenizer_id: QUERY_TOKENIZER_ID_V1.to_owned(),
        shards: QueryShardCatalogV1 {
            denominator: QueryShardDenominatorV1 {
                discovered_shards: count_u64(descriptors.len())
                    .map_err(|_| FileQueryErrorV1::ResourceBudgetExceeded)?,
                admitted_shards: count_u64(descriptors.len())
                    .map_err(|_| FileQueryErrorV1::ResourceBudgetExceeded)?,
                omitted_shards: 0,
            },
            entries: descriptors,
        },
        digests: query_shard_catalog_digests_v1(
            &published
                .iter()
                .map(|value| value.descriptor.clone())
                .collect::<Vec<_>>(),
        ),
        budgets,
    };
    validate_query_index_manifest_v1(&index)?;
    let mut manifest = FileQueryIndexManifestV1 {
        schema_version: FILE_QUERY_INDEX_MANIFEST_SCHEMA_V1.to_owned(),
        index_manifest_sha256: query_index_manifest_sha256_v1(&index),
        index,
        lexical_routing_catalog,
        adjacency_catalog: file_adjacency_catalog,
        adjacency_routes,
        shard_files: published.into_iter().map(|value| value.file).collect(),
        manifest_sha256: String::new(),
    };
    manifest.manifest_sha256 = file_query_index_manifest_content_sha256_v1(&manifest);
    validate_file_query_index_manifest_v1(&manifest)?;
    let path = index_root.join(format!(
        "manifests/{}.json",
        digest_hex_query(&manifest.manifest_sha256)?
    ));
    let manifest_ref = publish_query_json(
        context,
        &index_root,
        &path,
        &manifest,
        budgets.max_manifest_bytes,
    )?;
    let mut binding = FileQueryCurrentBindingV1 {
        schema_version: FILE_QUERY_CURRENT_BINDING_SCHEMA_V1.to_owned(),
        source_identity: expected.source_identity.clone(),
        graph_identity: expected.graph_identity.clone(),
        overlay_identity: expected.overlay_identity.clone(),
        index_manifest_sha256: manifest.index_manifest_sha256.clone(),
        manifest_ref: manifest_ref.clone(),
        binding_sha256: String::new(),
    };
    binding.binding_sha256 = file_query_current_binding_content_sha256(&binding);
    let binding_path = index_root.join("binding/current.json");
    publish_query_json(
        context,
        &index_root,
        &binding_path,
        &binding,
        budgets.max_manifest_bytes,
    )?;
    let manifest_identity = query_file_identity_v1(context, &path, budgets.max_manifest_bytes)?;
    let binding_identity =
        query_file_identity_v1(context, &binding_path, budgets.max_manifest_bytes)?;
    let cache_key = file_query_manifest_cache_key_v1(&index_root, &manifest_ref)?;
    insert_file_query_manifest_cache_v1(
        cache_key,
        FileQueryManifestCacheEntryV1 {
            manifest: Arc::new(manifest),
            manifest_identity,
            binding_identity,
        },
        true,
    );
    Ok(manifest_ref)
}

fn publish_query_shard<T: Serialize>(
    context: &CallContext,
    index_root: &Path,
    spec: QueryShardPublishSpecV1,
    shard: &T,
) -> Result<PublishedQueryShardV1, FileQueryErrorV1> {
    let path_key = hex::encode(Sha256::digest(spec.shard_id.as_bytes()));
    let path = index_root.join(format!("shards/{path_key}.json"));
    let reference = publish_query_json(
        context,
        index_root,
        &path,
        shard,
        QueryResourceBudgetsV1::v03_frozen().max_shard_bytes,
    )?;
    let read = read_query_file_bounded(
        context,
        &index_root.join(&reference.path),
        QueryResourceBudgetsV1::v03_frozen().max_shard_bytes,
    )?;
    let byte_len =
        count_u64(read.bytes.len()).map_err(|_| FileQueryErrorV1::ResourceBudgetExceeded)?;
    Ok(PublishedQueryShardV1 {
        descriptor: QueryShardDescriptorV1 {
            shard_id: spec.shard_id.clone(),
            shard_kind: spec.shard_kind,
            raw_bytes_sha256: spec.content_sha256.clone(),
            byte_len,
            record_count: spec.record_count,
        },
        file: FileQueryShardV1 {
            shard_id: spec.shard_id,
            shard_kind: spec.shard_kind,
            relative_path: reference.path,
            content_sha256: spec.content_sha256,
            file_sha256: read.sha256,
            byte_len,
            record_count: spec.record_count,
            term_count: spec.term_count,
            routing_keys: spec.routing_keys,
        },
    })
}

fn publish_query_json<T: Serialize>(
    context: &CallContext,
    index_root: &Path,
    path: &Path,
    value: &T,
    max_bytes: u64,
) -> Result<FileReceiptRef, FileQueryErrorV1> {
    #[cfg(unix)]
    {
        publish_query_json_dirfd(context, index_root, path, value, max_bytes)
    }
    #[cfg(not(unix))]
    {
        let published =
            publish_immutable_json(context, path, value, "query.after_temp_sync_before_rename")
                .map_err(file_query_durable_error)?;
        let read = read_query_file_bounded(context, &published, max_bytes)?;
        let canonical_index_root =
            fs::canonicalize(index_root).map_err(|_| FileQueryErrorV1::UnsafePath)?;
        let relative = published
            .strip_prefix(&canonical_index_root)
            .map_err(|_| FileQueryErrorV1::UnsafePath)?;
        Ok(FileReceiptRef {
            path: relative.to_string_lossy().into_owned(),
            sha256: read.sha256,
        })
    }
}

#[cfg(unix)]
fn publish_query_json_dirfd<T: Serialize>(
    context: &CallContext,
    index_root: &Path,
    path: &Path,
    value: &T,
    max_bytes: u64,
) -> Result<FileReceiptRef, FileQueryErrorV1> {
    use rustix::fs::{AtFlags, Mode, OFlags, RenameFlags, fchmod, openat, renameat_with, unlinkat};

    context
        .authorize_write(path)
        .map_err(file_query_context_error)?;
    let bytes = serde_json::to_vec_pretty(value).map_err(|_| FileQueryErrorV1::InvalidManifest)?;
    if bytes.len() as u64 > max_bytes {
        return Err(FileQueryErrorV1::ResourceBudgetExceeded);
    }
    let relative = path
        .strip_prefix(index_root)
        .map_err(|_| FileQueryErrorV1::UnsafePath)?;
    let (directory, name) = open_query_publish_parent(context, index_root, relative)?;
    if let Some(observed) = read_query_file_at(&directory, &name, max_bytes)? {
        return if observed.bytes == bytes {
            Ok(FileReceiptRef {
                path: relative.to_string_lossy().into_owned(),
                sha256: observed.sha256,
            })
        } else {
            Err(FileQueryErrorV1::ShardTampered)
        };
    }
    let bytes_sha256 = format!("sha256:{}", hex::encode(Sha256::digest(&bytes)));
    let digest_prefix = bytes_sha256.get(7..23).unwrap_or("invalid-digest");
    let mut temporary = None;
    for _ in 0..16 {
        let sequence = QUERY_TEMP_SEQUENCE_V1.fetch_add(1, Ordering::Relaxed);
        let candidate = OsString::from(format!(
            ".gtkg-query-{}-{sequence}-{digest_prefix}.tmp",
            std::process::id()
        ));
        match openat(
            &directory,
            &candidate,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        ) {
            Ok(descriptor) => {
                let file = File::from(descriptor);
                if fchmod(&file, Mode::from_raw_mode(0o600)).is_err() {
                    drop(file);
                    let _ = unlinkat(&directory, &candidate, AtFlags::empty());
                    return Err(FileQueryErrorV1::Io);
                }
                temporary = Some((candidate, file));
                break;
            }
            Err(error) if error == rustix::io::Errno::EXIST => continue,
            Err(error) => return Err(map_query_open_error(error)),
        }
    }
    let (temporary_name, mut temporary_file) = temporary.ok_or(FileQueryErrorV1::Io)?;
    let mut temporary_exists = true;
    let result = (|| {
        let metadata = temporary_file
            .metadata()
            .map_err(|_| FileQueryErrorV1::Io)?;
        ensure_query_private_inode(&metadata, &metadata)?;
        temporary_file
            .write_all(&bytes)
            .and_then(|()| temporary_file.sync_all())
            .map_err(|_| FileQueryErrorV1::Io)?;
        drop(temporary_file);
        match renameat_with(
            &directory,
            &temporary_name,
            &directory,
            &name,
            RenameFlags::NOREPLACE,
        ) {
            Ok(()) => temporary_exists = false,
            Err(error) if error == rustix::io::Errno::EXIST => {
                let observed = read_query_file_at(&directory, &name, max_bytes)?;
                if observed
                    .as_ref()
                    .is_none_or(|observed| observed.bytes != bytes)
                {
                    return Err(FileQueryErrorV1::ShardTampered);
                }
            }
            Err(error) => return Err(map_query_open_error(error)),
        }
        directory.sync_all().map_err(|_| FileQueryErrorV1::Io)?;
        let observed = read_query_file_at(&directory, &name, max_bytes)?
            .ok_or(FileQueryErrorV1::ShardTampered)?;
        if observed.bytes != bytes || observed.sha256 != bytes_sha256 {
            return Err(FileQueryErrorV1::ShardTampered);
        }
        Ok(FileReceiptRef {
            path: relative.to_string_lossy().into_owned(),
            sha256: observed.sha256,
        })
    })();
    if temporary_exists {
        let _ = unlinkat(&directory, &temporary_name, AtFlags::empty());
        let _ = directory.sync_all();
    }
    result
}

#[cfg(unix)]
fn open_query_publish_parent(
    context: &CallContext,
    index_root: &Path,
    relative: &Path,
) -> Result<(File, OsString), FileQueryErrorV1> {
    use rustix::fs::{Mode, OFlags, open, openat};
    use std::os::unix::fs::MetadataExt;

    let relative_components = relative
        .components()
        .map(|component| match component {
            Component::Normal(name) => Ok(name.to_os_string()),
            _ => Err(FileQueryErrorV1::UnsafePath),
        })
        .collect::<Result<Vec<_>, _>>()?;
    let (name, parents) = relative_components
        .split_last()
        .ok_or(FileQueryErrorV1::UnsafePath)?;
    let authorized_root = context
        .authorized_lexical_roots()
        .iter()
        .chain(context.authorized_roots())
        .filter(|root| index_root == **root || index_root.starts_with(root))
        .max_by_key(|root| root.components().count())
        .cloned()
        .ok_or(FileQueryErrorV1::UnsafePath)?;
    let index_components = index_root
        .strip_prefix(&authorized_root)
        .map_err(|_| FileQueryErrorV1::UnsafePath)?
        .components()
        .map(|component| match component {
            Component::Normal(name) => Ok(name.to_os_string()),
            _ => Err(FileQueryErrorV1::UnsafePath),
        })
        .collect::<Result<Vec<_>, _>>()?;
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let descriptor = open(&authorized_root, flags, Mode::empty()).map_err(map_query_open_error)?;
    let mut directory = File::from(descriptor);
    let opened_root = directory.metadata().map_err(|_| FileQueryErrorV1::Io)?;
    let path_root = fs::symlink_metadata(&authorized_root).map_err(|_| FileQueryErrorV1::Io)?;
    if path_root.file_type().is_symlink()
        || !path_root.is_dir()
        || opened_root.dev() != path_root.dev()
        || opened_root.ino() != path_root.ino()
    {
        return Err(FileQueryErrorV1::UnsafePath);
    }
    for parent in index_components.iter().chain(parents) {
        let opened =
            openat(&directory, parent, flags, Mode::empty()).map_err(map_query_open_error)?;
        directory = File::from(opened);
    }
    Ok((directory, name.clone()))
}

#[cfg(unix)]
fn read_query_file_at(
    directory: &File,
    name: &OsString,
    max_bytes: u64,
) -> Result<Option<QueryBoundReadV1>, FileQueryErrorV1> {
    use rustix::fs::{Mode, OFlags, openat};

    let flags = OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let descriptor = match openat(directory, name, flags, Mode::empty()) {
        Ok(descriptor) => descriptor,
        Err(error) if error == rustix::io::Errno::NOENT => return Ok(None),
        Err(error) => return Err(map_query_open_error(error)),
    };
    let mut file = File::from(descriptor);
    let opened = file.metadata().map_err(|_| FileQueryErrorV1::Io)?;
    ensure_query_private_inode(&opened, &opened)?;
    if opened.len() > max_bytes {
        return Err(FileQueryErrorV1::ResourceBudgetExceeded);
    }
    let mut bytes = Vec::with_capacity(
        usize::try_from(opened.len()).map_err(|_| FileQueryErrorV1::ResourceBudgetExceeded)?,
    );
    std::io::Read::by_ref(&mut file)
        .take(
            max_bytes
                .checked_add(1)
                .ok_or(FileQueryErrorV1::ResourceBudgetExceeded)?,
        )
        .read_to_end(&mut bytes)
        .map_err(|_| FileQueryErrorV1::Io)?;
    if bytes.len() as u64 > max_bytes || bytes.len() as u64 != opened.len() {
        return Err(FileQueryErrorV1::ResourceBudgetExceeded);
    }
    let after = file.metadata().map_err(|_| FileQueryErrorV1::Io)?;
    ensure_query_private_inode(&after, &opened)?;
    let path_descriptor =
        openat(directory, name, flags, Mode::empty()).map_err(map_query_open_error)?;
    let path_metadata = File::from(path_descriptor)
        .metadata()
        .map_err(|_| FileQueryErrorV1::Io)?;
    ensure_query_private_inode(&path_metadata, &opened)?;
    Ok(Some(QueryBoundReadV1 {
        sha256: format!("sha256:{}", hex::encode(Sha256::digest(&bytes))),
        identity: QueryFileIdentityV1::from_metadata(&after),
        bytes,
    }))
}

pub fn validate_file_query_index_manifest_v1(
    manifest: &FileQueryIndexManifestV1,
) -> Result<(), FileQueryErrorV1> {
    if manifest.schema_version != FILE_QUERY_INDEX_MANIFEST_SCHEMA_V1
        || manifest.index_manifest_sha256 != query_index_manifest_sha256_v1(&manifest.index)
        || manifest.lexical_routing_catalog.raw_bytes_sha256
            != lexical_routing_catalog_content_sha256_v1(&manifest.lexical_routing_catalog)
        || manifest.adjacency_catalog.raw_bytes_sha256
            != adjacency_routing_catalog_content_sha256_v1(&manifest.adjacency_catalog)
        || manifest.manifest_sha256 != file_query_index_manifest_content_sha256_v1(manifest)
    {
        return Err(FileQueryErrorV1::ManifestTampered);
    }
    validate_query_index_manifest_v1(&manifest.index)?;
    if manifest.shard_files.is_empty()
        || !strictly_sorted(&manifest.shard_files)
        || serde_json::to_vec(manifest).map_or(true, |bytes| {
            bytes.len() as u64 > manifest.index.budgets.max_manifest_bytes
        })
    {
        return Err(FileQueryErrorV1::InvalidManifest);
    }
    let descriptors = manifest
        .index
        .shards
        .entries
        .iter()
        .map(|entry| (entry.shard_id.as_str(), entry))
        .collect::<BTreeMap<_, _>>();
    if descriptors.len() != manifest.shard_files.len() {
        return Err(FileQueryErrorV1::InvalidManifest);
    }
    for file in &manifest.shard_files {
        let descriptor = descriptors
            .get(file.shard_id.as_str())
            .ok_or(FileQueryErrorV1::InvalidManifest)?;
        let expected_relative_path = format!(
            "shards/{}.json",
            hex::encode(Sha256::digest(file.shard_id.as_bytes()))
        );
        if descriptor.shard_kind != file.shard_kind
            || descriptor.raw_bytes_sha256 != file.content_sha256
            || descriptor.byte_len != file.byte_len
            || descriptor.record_count != file.record_count
            || !is_sha256(&file.content_sha256)
            || !is_sha256(&file.file_sha256)
            || file.byte_len == 0
            || file.record_count == 0
            || file.byte_len > manifest.index.budgets.max_shard_bytes
            || !safe_query_relative_path(&file.relative_path, "shards")
            || file.relative_path != expected_relative_path
            || file.routing_keys.is_empty()
            || !sorted_or_empty(&file.routing_keys)
            || file.routing_keys.len() as u64 > manifest.index.budgets.max_records_per_shard
            || match file.shard_kind {
                QueryShardKindV1::Lexical => {
                    file.term_count == 0
                        || file.routing_keys.iter().any(|key| !valid_routing_key(key))
                }
                QueryShardKindV1::Adjacency => {
                    file.term_count != 0
                        || file
                            .routing_keys
                            .iter()
                            .any(|key| parse_adjacency_routing_key(key).is_err())
                }
            }
        {
            return Err(FileQueryErrorV1::InvalidManifest);
        }
    }
    let lexical_ids = manifest
        .shard_files
        .iter()
        .filter(|file| file.shard_kind == QueryShardKindV1::Lexical)
        .map(|file| file.shard_id.as_str())
        .collect::<BTreeSet<_>>();
    if !sorted_or_empty(&manifest.lexical_routing_catalog.entries) {
        return Err(FileQueryErrorV1::InvalidManifest);
    }
    for entry in &manifest.lexical_routing_catalog.entries {
        if !valid_routing_key(&entry.routing_key)
            || !sorted_or_empty(&entry.shard_ids)
            || entry
                .shard_ids
                .iter()
                .any(|shard_id| !lexical_ids.contains(shard_id.as_str()))
        {
            return Err(FileQueryErrorV1::InvalidManifest);
        }
    }
    let expected_lexical_entries = lexical_routing_entries_from_files(&manifest.shard_files)?;
    if manifest.lexical_routing_catalog.entries.len() != expected_lexical_entries.len()
        || manifest
            .lexical_routing_catalog
            .entries
            .iter()
            .zip(&expected_lexical_entries)
            .any(|(observed, expected)| {
                observed.routing_key != expected.routing_key
                    || (!observed.shard_ids.is_empty() && observed.shard_ids != expected.shard_ids)
            })
    {
        return Err(FileQueryErrorV1::InvalidManifest);
    }
    let adjacency_descriptors = manifest
        .index
        .shards
        .entries
        .iter()
        .filter(|entry| entry.shard_kind == QueryShardKindV1::Adjacency)
        .cloned()
        .collect::<Vec<_>>();
    if adjacency_descriptors != manifest.adjacency_catalog.shards {
        return Err(FileQueryErrorV1::InvalidManifest);
    }
    validate_adjacency_catalog_shape(&manifest.adjacency_catalog, &manifest.index.budgets)?;
    let adjacency_ids = adjacency_descriptors
        .iter()
        .map(|entry| entry.shard_id.as_str())
        .collect::<BTreeSet<_>>();
    let nodes = manifest
        .adjacency_catalog
        .nodes
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let (expected_file_routes, nonempty_file_routes) =
        complete_adjacency_routes_from_files(&manifest.shard_files, &nodes)?;
    if manifest.adjacency_routes != expected_file_routes
        || !sorted_or_empty(&manifest.adjacency_routes)
        || manifest.adjacency_routes.len()
            != manifest
                .adjacency_catalog
                .nodes
                .len()
                .checked_mul(2)
                .ok_or(FileQueryErrorV1::ResourceBudgetExceeded)?
    {
        return Err(FileQueryErrorV1::InvalidManifest);
    }
    let mut route_keys = BTreeSet::new();
    for route in &manifest.adjacency_catalog.routes {
        if !nodes.contains(route.node_id.as_str())
            || !adjacency_ids.contains(route.shard_id.as_str())
            || route.shard_id
                != adjacency_shard_id_v1(&adjacency_node_bucket_v1(&route.node_id), route.direction)
            || !route_keys.insert((route.node_id.as_str(), route.direction))
            || nonempty_file_routes.get(&(route.node_id.clone(), route.direction))
                != Some(&route.shard_id)
        {
            return Err(FileQueryErrorV1::InvalidManifest);
        }
    }
    if nonempty_file_routes.len() != manifest.adjacency_catalog.routes.len() {
        return Err(FileQueryErrorV1::InvalidManifest);
    }
    if adjacency_ids.iter().any(|shard_id| {
        !manifest
            .adjacency_catalog
            .routes
            .iter()
            .any(|route| route.shard_id == *shard_id)
    }) {
        return Err(FileQueryErrorV1::InvalidManifest);
    }
    let adjacency_record_count = adjacency_descriptors
        .iter()
        .try_fold(0_u64, |total, descriptor| {
            total.checked_add(descriptor.record_count)
        })
        .ok_or(FileQueryErrorV1::ResourceBudgetExceeded)?;
    if manifest
        .adjacency_catalog
        .denominator
        .adjacency_record_count
        != adjacency_record_count
        || manifest
            .adjacency_catalog
            .denominator
            .edge_count
            .checked_mul(2)
            != Some(adjacency_record_count)
    {
        return Err(FileQueryErrorV1::InvalidManifest);
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct QueryFileIdentityV1 {
    byte_len: u64,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(unix)]
    mode: u32,
    #[cfg(unix)]
    links: u64,
    #[cfg(unix)]
    modified_seconds: i64,
    #[cfg(unix)]
    modified_nanoseconds: i64,
    #[cfg(unix)]
    changed_seconds: i64,
    #[cfg(unix)]
    changed_nanoseconds: i64,
    #[cfg(not(unix))]
    modified: Option<std::time::SystemTime>,
    #[cfg(not(unix))]
    readonly: bool,
}

impl QueryFileIdentityV1 {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            Self {
                byte_len: metadata.len(),
                device: metadata.dev(),
                inode: metadata.ino(),
                mode: metadata.mode(),
                links: metadata.nlink(),
                modified_seconds: metadata.mtime(),
                modified_nanoseconds: metadata.mtime_nsec(),
                changed_seconds: metadata.ctime(),
                changed_nanoseconds: metadata.ctime_nsec(),
            }
        }
        #[cfg(not(unix))]
        {
            Self {
                byte_len: metadata.len(),
                modified: metadata.modified().ok(),
                readonly: metadata.permissions().readonly(),
            }
        }
    }

    fn same_inode(&self, other: &Self) -> bool {
        #[cfg(unix)]
        {
            self.device == other.device && self.inode == other.inode
        }
        #[cfg(not(unix))]
        {
            self == other
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct FileQueryManifestCacheKeyV1 {
    canonical_index_root: PathBuf,
    manifest_path: String,
    manifest_sha256: String,
}

#[derive(Clone)]
struct FileQueryManifestCacheEntryV1 {
    manifest: Arc<FileQueryIndexManifestV1>,
    manifest_identity: QueryFileIdentityV1,
    binding_identity: QueryFileIdentityV1,
}

#[derive(Default)]
struct FileQueryManifestCacheV1 {
    entries: BTreeMap<FileQueryManifestCacheKeyV1, FileQueryManifestCacheEntryV1>,
    hits: u64,
    misses: u64,
    evictions: u64,
    full_manifest_validations: u64,
    #[cfg(feature = "test-faults")]
    routing_index_builds: u64,
}

const FILE_QUERY_MANIFEST_CACHE_CAPACITY: usize = 8;

fn file_query_manifest_cache_v1() -> &'static Mutex<FileQueryManifestCacheV1> {
    static CACHE: OnceLock<Mutex<FileQueryManifestCacheV1>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(FileQueryManifestCacheV1::default()))
}

fn lock_file_query_manifest_cache_v1() -> std::sync::MutexGuard<'static, FileQueryManifestCacheV1> {
    file_query_manifest_cache_v1()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(feature = "test-faults")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileQueryManifestCacheStatsV1 {
    pub entries: usize,
    pub capacity: usize,
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
    pub full_manifest_validations: u64,
    pub routing_index_builds: u64,
}

#[cfg(feature = "test-faults")]
pub fn file_query_manifest_cache_stats_v1() -> FileQueryManifestCacheStatsV1 {
    let cache = lock_file_query_manifest_cache_v1();
    FileQueryManifestCacheStatsV1 {
        entries: cache.entries.len(),
        capacity: FILE_QUERY_MANIFEST_CACHE_CAPACITY,
        hits: cache.hits,
        misses: cache.misses,
        evictions: cache.evictions,
        full_manifest_validations: cache.full_manifest_validations,
        routing_index_builds: cache.routing_index_builds,
    }
}

#[cfg(feature = "test-faults")]
pub fn reset_file_query_manifest_cache_v1() {
    *lock_file_query_manifest_cache_v1() = FileQueryManifestCacheV1::default();
}

fn record_file_query_manifest_validation_v1() {
    let mut cache = lock_file_query_manifest_cache_v1();
    cache.full_manifest_validations = cache.full_manifest_validations.saturating_add(1);
}

struct PreparedFileQueryV1 {
    plan: FileQueryPlanV1,
    manifest: Arc<FileQueryIndexManifestV1>,
    manifest_identity: QueryFileIdentityV1,
    manifest_bytes_read: u64,
    manifest_path: PathBuf,
    binding_bytes: Option<Vec<u8>>,
    binding_identity: Option<QueryFileIdentityV1>,
    binding_path: Option<PathBuf>,
}

fn file_query_manifest_cache_key_v1(
    index_root: &Path,
    manifest_ref: &FileReceiptRef,
) -> Result<FileQueryManifestCacheKeyV1, FileQueryErrorV1> {
    Ok(FileQueryManifestCacheKeyV1 {
        canonical_index_root: fs::canonicalize(index_root).map_err(|_| FileQueryErrorV1::Io)?,
        manifest_path: manifest_ref.path.clone(),
        manifest_sha256: manifest_ref.sha256.clone(),
    })
}

fn lookup_file_query_manifest_cache_v1(
    key: &FileQueryManifestCacheKeyV1,
    manifest_identity: &QueryFileIdentityV1,
    binding_identity: &QueryFileIdentityV1,
) -> Result<Option<Arc<FileQueryIndexManifestV1>>, FileQueryErrorV1> {
    let mut cache = lock_file_query_manifest_cache_v1();
    let Some(entry) = cache.entries.get(key).cloned() else {
        cache.misses = cache.misses.saturating_add(1);
        return Ok(None);
    };
    if entry.manifest_identity != *manifest_identity {
        cache.entries.remove(key);
        cache.evictions = cache.evictions.saturating_add(1);
        return Err(if entry.manifest_identity.same_inode(manifest_identity) {
            FileQueryErrorV1::ManifestTampered
        } else {
            FileQueryErrorV1::UnsafePath
        });
    }
    if entry.binding_identity != *binding_identity {
        cache.entries.remove(key);
        cache.evictions = cache.evictions.saturating_add(1);
        return Err(if entry.binding_identity.same_inode(binding_identity) {
            FileQueryErrorV1::InvalidManifest
        } else {
            FileQueryErrorV1::UnsafePath
        });
    }
    cache.hits = cache.hits.saturating_add(1);
    Ok(Some(entry.manifest))
}

fn insert_file_query_manifest_cache_v1(
    key: FileQueryManifestCacheKeyV1,
    entry: FileQueryManifestCacheEntryV1,
    count_population_as_miss: bool,
) {
    let mut cache = lock_file_query_manifest_cache_v1();
    if count_population_as_miss {
        cache.misses = cache.misses.saturating_add(1);
    }
    if !cache.entries.contains_key(&key)
        && cache.entries.len() >= FILE_QUERY_MANIFEST_CACHE_CAPACITY
        && let Some(evicted) = cache.entries.keys().next().cloned()
    {
        cache.entries.remove(&evicted);
        cache.evictions = cache.evictions.saturating_add(1);
    }
    cache.entries.insert(key, entry);
}

pub fn plan_file_query_v1(
    context: &CallContext,
    index_root: &Path,
    manifest_ref: &FileReceiptRef,
    expected: &FileQueryExpectedIdentitiesV1,
    request: &FileQueryRequestV1,
) -> Result<FileQueryPlanV1, FileQueryErrorV1> {
    Ok(prepare_file_query(context, index_root, manifest_ref, expected, request, true)?.plan)
}

/// Performs the same strict binding, identity, path, and manifest validation
/// as a first-page query, but returns the validated immutable manifest without
/// opening any selected shard.  Q06 uses this inspection surface to compare
/// independent persistent roots without bypassing Q03's secure reader.
pub fn inspect_file_query_index_v1(
    context: &CallContext,
    index_root: &Path,
    manifest_ref: &FileReceiptRef,
    expected: &FileQueryExpectedIdentitiesV1,
    request: &FileQueryRequestV1,
) -> Result<FileQueryIndexManifestV1, FileQueryErrorV1> {
    let prepared = prepare_file_query(context, index_root, manifest_ref, expected, request, true)?;
    Ok((*prepared.manifest).clone())
}

fn prepare_file_query(
    context: &CallContext,
    index_root: &Path,
    manifest_ref: &FileReceiptRef,
    expected: &FileQueryExpectedIdentitiesV1,
    request: &FileQueryRequestV1,
    strict_binding: bool,
) -> Result<PreparedFileQueryV1, FileQueryErrorV1> {
    manifest_ref
        .validate()
        .map_err(|_| FileQueryErrorV1::InvalidManifest)?;
    if request.max_results == 0 || request.max_results > 10_000 {
        return Err(FileQueryErrorV1::ResourceBudgetExceeded);
    }
    if let FileQueryLookupV1::Search { query } = &request.lookup {
        let max_term_scalars = QueryResourceBudgetsV1::v03_frozen().max_term_scalars;
        if tokenize_query_v1(query).tokens.iter().any(|token| {
            u64::try_from(token.normalized.chars().count()).unwrap_or(u64::MAX) > max_term_scalars
        }) {
            return Err(FileQueryErrorV1::ResourceBudgetExceeded);
        }
    }
    let index_root = absolute_query_candidate(context, index_root)?;
    context
        .authorize_read(&index_root)
        .map_err(file_query_context_error)?;
    verify_query_directory_no_symlink(context, &index_root)?;
    let (binding_bytes, binding_path, binding_identity, binding) = if strict_binding {
        let path = index_root.join("binding/current.json");
        let read = read_query_file_bounded(
            context,
            &path,
            QueryResourceBudgetsV1::v03_frozen().max_manifest_bytes,
        )?;
        let binding: FileQueryCurrentBindingV1 =
            serde_json::from_slice(&read.bytes).map_err(|_| FileQueryErrorV1::InvalidManifest)?;
        if binding.schema_version != FILE_QUERY_CURRENT_BINDING_SCHEMA_V1
            || binding.binding_sha256 != file_query_current_binding_content_sha256(&binding)
            || binding.manifest_ref != *manifest_ref
            || binding.source_identity != expected.source_identity
            || binding.graph_identity != expected.graph_identity
            || binding.overlay_identity != expected.overlay_identity
            || !is_sha256(&binding.index_manifest_sha256)
            || binding.manifest_ref.validate().is_err()
        {
            return Err(FileQueryErrorV1::InvalidManifest);
        }
        (
            Some(read.bytes),
            Some(path),
            Some(read.identity),
            Some(binding),
        )
    } else {
        (None, None, None, None)
    };
    if !safe_query_relative_path(&manifest_ref.path, "manifests") {
        return Err(FileQueryErrorV1::UnsafePath);
    }
    let manifest_path = index_root.join(&manifest_ref.path);
    let observed_manifest_identity = query_file_identity_v1(
        context,
        &manifest_path,
        QueryResourceBudgetsV1::v03_frozen().max_manifest_bytes,
    )?;
    let cache_key = strict_binding
        .then(|| file_query_manifest_cache_key_v1(&index_root, manifest_ref))
        .transpose()?;
    let cached_manifest = match (cache_key.as_ref(), binding_identity.as_ref()) {
        (Some(key), Some(identity)) => {
            lookup_file_query_manifest_cache_v1(key, &observed_manifest_identity, identity)?
        }
        _ => None,
    };
    let cache_was_hit = cached_manifest.is_some();
    let (manifest, manifest_identity, manifest_bytes_read) = if let Some(manifest) = cached_manifest
    {
        (manifest, observed_manifest_identity, 0)
    } else {
        let read = read_query_file_bounded(
            context,
            &manifest_path,
            QueryResourceBudgetsV1::v03_frozen().max_manifest_bytes,
        )?;
        if read.identity != observed_manifest_identity {
            return Err(if read.identity.same_inode(&observed_manifest_identity) {
                FileQueryErrorV1::ManifestTampered
            } else {
                FileQueryErrorV1::UnsafePath
            });
        }
        if read.sha256 != manifest_ref.sha256 {
            return Err(FileQueryErrorV1::ManifestTampered);
        }
        let bytes_read = u64::try_from(read.bytes.len())
            .map_err(|_| FileQueryErrorV1::ResourceBudgetExceeded)?;
        let manifest =
            serde_json::from_slice(&read.bytes).map_err(|_| FileQueryErrorV1::InvalidManifest)?;
        (Arc::new(manifest), read.identity, bytes_read)
    };
    if let Some(token) = request.continuation.as_deref() {
        let continuation = decode_file_query_continuation(token)?;
        if continuation.manifest_sha256 != manifest.manifest_sha256 {
            return Err(FileQueryErrorV1::ContinuationInvalid);
        }
    }
    if !cache_was_hit {
        validate_file_query_index_manifest_v1(&manifest)?;
        record_file_query_manifest_validation_v1();
    }
    if binding
        .as_ref()
        .is_some_and(|binding| binding.index_manifest_sha256 != manifest.index_manifest_sha256)
    {
        return Err(FileQueryErrorV1::InvalidManifest);
    }
    let expected_path = format!(
        "manifests/{}.json",
        digest_hex_query(&manifest.manifest_sha256)?
    );
    if manifest_ref.path != expected_path
        || manifest.index.source_identity != expected.source_identity
        || manifest.index.graph_identity != expected.graph_identity
        || manifest.index.overlay_identity != expected.overlay_identity
        || manifest.index.tokenizer_id != QUERY_TOKENIZER_ID_V1
    {
        return Err(FileQueryErrorV1::StaleIndex);
    }
    let query_sha256 = json_sha256(&request.lookup);
    let (mut selected_shards, known_but_empty) =
        select_file_query_shards(&manifest, &request.lookup)?;
    selected_shards.sort();
    selected_shards.dedup();
    if known_but_empty && selected_shards.is_empty() {
        return Err(FileQueryErrorV1::ZeroShardSelection);
    }
    if selected_shards.len() as u64 > manifest.index.budgets.max_selected_shards {
        return Err(FileQueryErrorV1::ResourceBudgetExceeded);
    }
    let all = manifest
        .shard_files
        .iter()
        .map(|file| file.shard_id.clone())
        .collect::<BTreeSet<_>>();
    if selected_shards
        .iter()
        .any(|shard_id| !all.contains(shard_id))
    {
        return Err(FileQueryErrorV1::InvalidManifest);
    }
    let selected = selected_shards.iter().cloned().collect::<BTreeSet<_>>();
    let excluded_shards = all.difference(&selected).cloned().collect::<Vec<_>>();
    let predicted_shard_bytes = manifest
        .shard_files
        .iter()
        .filter(|file| selected.contains(&file.shard_id))
        .try_fold(0_u64, |total, file| total.checked_add(file.byte_len))
        .ok_or(FileQueryErrorV1::ResourceBudgetExceeded)?;
    let binding_control_bytes = u64::try_from(binding_bytes.as_ref().map_or(0, Vec::len))
        .ok()
        .and_then(|value| value.checked_mul(2))
        .ok_or(FileQueryErrorV1::ResourceBudgetExceeded)?;
    let control_bytes = manifest_bytes_read
        .checked_add(binding_control_bytes)
        .ok_or(FileQueryErrorV1::ResourceBudgetExceeded)?;
    let predicted_total = control_bytes
        .checked_add(predicted_shard_bytes)
        .ok_or(FileQueryErrorV1::ResourceBudgetExceeded)?;
    if predicted_total > manifest.index.budgets.max_query_bytes_read {
        return Err(FileQueryErrorV1::ResourceBudgetExceeded);
    }
    let budget = QueryPlanBudgetV1::from(manifest.index.budgets);
    let routing_catalog_sha256 = json_sha256(&(
        manifest.lexical_routing_catalog.raw_bytes_sha256.as_str(),
        manifest.adjacency_catalog.raw_bytes_sha256.as_str(),
    ));
    let (start_offset, prior_page_sha256) = match request.continuation.as_deref() {
        Some(token) => {
            let continuation = decode_file_query_continuation(token)?;
            if continuation.query_sha256 != query_sha256
                || continuation.manifest_sha256 != manifest.manifest_sha256
                || continuation.index_manifest_sha256 != manifest.index_manifest_sha256
                || continuation.routing_catalog_sha256 != routing_catalog_sha256
                || continuation.selected_shards != selected_shards
                || continuation.page_size != request.max_results
                || continuation.budget != budget
            {
                return Err(FileQueryErrorV1::ContinuationInvalid);
            }
            (
                continuation.next_offset,
                Some(continuation.prior_page_sha256),
            )
        }
        None => (0, None),
    };
    let mut plan = FileQueryPlanV1 {
        manifest_ref: manifest_ref.clone(),
        manifest_sha256: manifest.manifest_sha256.clone(),
        index_manifest_sha256: manifest.index_manifest_sha256.clone(),
        routing_catalog_sha256,
        query_sha256,
        selected_shards,
        excluded_shards,
        start_offset,
        page_size: request.max_results,
        prior_page_sha256,
        budget,
        plan_sha256: String::new(),
    };
    plan.plan_sha256 = file_query_plan_content_sha256(&plan);
    if strict_binding
        && !cache_was_hit
        && let (Some(key), Some(binding_identity)) = (cache_key, binding_identity.as_ref())
    {
        insert_file_query_manifest_cache_v1(
            key,
            FileQueryManifestCacheEntryV1 {
                manifest: Arc::clone(&manifest),
                manifest_identity: manifest_identity.clone(),
                binding_identity: binding_identity.clone(),
            },
            false,
        );
    }
    Ok(PreparedFileQueryV1 {
        plan,
        manifest,
        manifest_identity,
        manifest_bytes_read,
        manifest_path,
        binding_bytes,
        binding_identity,
        binding_path,
    })
}

#[cfg(feature = "test-faults")]
pub fn execute_file_query_page_v1(
    context: &CallContext,
    index_root: &Path,
    manifest_ref: &FileReceiptRef,
    expected: &FileQueryExpectedIdentitiesV1,
    request: &FileQueryRequestV1,
) -> Result<FileQueryPageV1, FileQueryErrorV1> {
    execute_file_query_page_internal::<fn(&Path)>(
        context,
        index_root,
        manifest_ref,
        expected,
        request,
        false,
        None,
    )
}

pub fn execute_first_file_query_page_v1(
    context: &CallContext,
    index_root: &Path,
    manifest_ref: &FileReceiptRef,
    expected: &FileQueryExpectedIdentitiesV1,
    request: &FileQueryRequestV1,
) -> Result<FileQueryPageV1, FileQueryErrorV1> {
    if request.continuation.is_some() {
        return Err(FileQueryErrorV1::ContinuationInvalid);
    }
    execute_file_query_page_internal::<fn(&Path)>(
        context,
        index_root,
        manifest_ref,
        expected,
        request,
        true,
        None,
    )
}

pub fn execute_next_file_query_page_v1(
    context: &CallContext,
    index_root: &Path,
    manifest_ref: &FileReceiptRef,
    expected: &FileQueryExpectedIdentitiesV1,
    previous: &FileQueryPageV1,
    request: &FileQueryRequestV1,
) -> Result<FileQueryPageV1, FileQueryErrorV1> {
    validate_file_query_page_v1(previous)?;
    let expected_token = previous
        .receipt
        .continuation
        .as_deref()
        .ok_or(FileQueryErrorV1::ContinuationInvalid)?;
    if previous.receipt.truncation != QueryTruncationStateV1::Truncated
        || request.continuation.as_deref() != Some(expected_token)
    {
        return Err(FileQueryErrorV1::ContinuationInvalid);
    }
    let continuation = decode_file_query_continuation(expected_token)?;
    if continuation.query_sha256 != previous.receipt.query_sha256
        || continuation.index_manifest_sha256 != previous.receipt.index_manifest_sha256
        || continuation.selected_shards != previous.receipt.selected_shards
        || continuation.next_offset != previous.end_offset
        || continuation.page_size != request.max_results
        || continuation.budget != previous.receipt.budget
        || continuation.prior_plan_sha256 != previous.plan_sha256
        || continuation.prior_page_sha256 != previous.page_sha256
    {
        return Err(FileQueryErrorV1::ContinuationInvalid);
    }
    let next = execute_file_query_page_internal::<fn(&Path)>(
        context,
        index_root,
        manifest_ref,
        expected,
        request,
        true,
        None,
    )?;
    validate_next_page_against_v1(previous, &next)?;
    Ok(next)
}

#[cfg(feature = "test-faults")]
pub fn execute_file_query_page_with_pre_shard_read_hook_v1<F>(
    context: &CallContext,
    index_root: &Path,
    manifest_ref: &FileReceiptRef,
    expected: &FileQueryExpectedIdentitiesV1,
    request: &FileQueryRequestV1,
    hook: F,
) -> Result<FileQueryPageV1, FileQueryErrorV1>
where
    F: FnOnce(&Path),
{
    execute_file_query_page_internal(
        context,
        index_root,
        manifest_ref,
        expected,
        request,
        false,
        Some(hook),
    )
}

fn execute_file_query_page_internal<F>(
    context: &CallContext,
    index_root: &Path,
    manifest_ref: &FileReceiptRef,
    expected: &FileQueryExpectedIdentitiesV1,
    request: &FileQueryRequestV1,
    strict_binding: bool,
    mut pre_shard_read: Option<F>,
) -> Result<FileQueryPageV1, FileQueryErrorV1>
where
    F: FnOnce(&Path),
{
    let started = Instant::now();
    let prepared = prepare_file_query(
        context,
        index_root,
        manifest_ref,
        expected,
        request,
        strict_binding,
    )?;
    let index_root = absolute_query_candidate(context, index_root)?;
    context
        .authorize_read(&index_root)
        .map_err(file_query_context_error)?;
    verify_query_directory_no_symlink(context, &index_root)?;
    let selected = prepared
        .plan
        .selected_shards
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut opened_shards = Vec::new();
    let mut lexical_hits = Vec::new();
    let mut adjacency_edges = Vec::new();
    let mut shard_bytes_read = 0_u64;
    for shard_id in &prepared.plan.selected_shards {
        let file = prepared
            .manifest
            .shard_files
            .iter()
            .find(|file| file.shard_id == *shard_id)
            .ok_or(FileQueryErrorV1::InvalidManifest)?;
        let path = index_root.join(&file.relative_path);
        if let Some(hook) = pre_shard_read.take() {
            hook(&path);
        }
        let read = read_query_file_bounded(
            context,
            &path,
            prepared.manifest.index.budgets.max_shard_bytes,
        )?;
        let observed_len = u64::try_from(read.bytes.len())
            .map_err(|_| FileQueryErrorV1::ResourceBudgetExceeded)?;
        if observed_len != file.byte_len || read.sha256 != file.file_sha256 {
            return Err(FileQueryErrorV1::ShardTampered);
        }
        shard_bytes_read = shard_bytes_read
            .checked_add(observed_len)
            .ok_or(FileQueryErrorV1::ResourceBudgetExceeded)?;
        opened_shards.push(file.shard_id.clone());
        match (&request.lookup, file.shard_kind) {
            (FileQueryLookupV1::Search { query }, QueryShardKindV1::Lexical) => {
                let shard: LexicalShardV1 = serde_json::from_slice(&read.bytes)
                    .map_err(|_| FileQueryErrorV1::ShardTampered)?;
                if shard.shard_id != file.shard_id
                    || shard.raw_bytes_sha256 != file.content_sha256
                    || shard.raw_bytes_sha256 != lexical_shard_content_sha256_v1(&shard)
                    || file.record_count != shard.postings.len() as u64
                    || file.term_count != shard.normalized_terms.len() as u64
                    || file.routing_keys != lexical_routing_keys_for_shard(&shard)
                {
                    return Err(FileQueryErrorV1::ShardTampered);
                }
                validate_lexical_shard_v1(&shard, &prepared.manifest.index.budgets)
                    .map_err(|_| FileQueryErrorV1::ShardTampered)?;
                lexical_hits.extend(
                    search_lexical_shard_v1(&shard, query)
                        .map_err(|_| FileQueryErrorV1::ShardTampered)?,
                );
            }
            (FileQueryLookupV1::Adjacency { node_id, direction }, QueryShardKindV1::Adjacency) => {
                let shard: AdjacencyRoutingShardV1 = serde_json::from_slice(&read.bytes)
                    .map_err(|_| FileQueryErrorV1::ShardTampered)?;
                if shard.header.shard_id != file.shard_id
                    || shard.header.raw_bytes_sha256 != file.content_sha256
                    || shard.header.raw_bytes_sha256
                        != adjacency_routing_shard_content_sha256_v1(&shard)
                    || file.record_count != shard.records.len() as u64
                    || file.term_count != 0
                    || file.routing_keys != adjacency_routing_keys_for_shard(&shard)
                {
                    return Err(FileQueryErrorV1::ShardTampered);
                }
                let routed = route_selected_adjacency_shard_v1(
                    &prepared.manifest.adjacency_catalog,
                    &shard,
                    node_id,
                    *direction,
                )
                .map_err(|_| FileQueryErrorV1::ShardTampered)?;
                adjacency_edges.extend(routed.edges);
            }
            _ => return Err(FileQueryErrorV1::InvalidManifest),
        }
    }
    opened_shards.sort();
    if opened_shards != prepared.plan.selected_shards
        || opened_shards.iter().cloned().collect::<BTreeSet<_>>() != selected
    {
        return Err(FileQueryErrorV1::InvalidManifest);
    }
    lexical_hits.sort_by(|left, right| {
        (&left.node_id, &left.evidence_ref, &left.positions).cmp(&(
            &right.node_id,
            &right.evidence_ref,
            &right.positions,
        ))
    });
    lexical_hits.dedup();
    adjacency_edges.sort_by(|left, right| left.edge_id.cmp(&right.edge_id));
    adjacency_edges.dedup();

    let final_manifest_identity = query_file_identity_v1(
        context,
        &prepared.manifest_path,
        prepared.manifest.index.budgets.max_manifest_bytes,
    )?;
    if final_manifest_identity != prepared.manifest_identity {
        return Err(
            if final_manifest_identity.same_inode(&prepared.manifest_identity) {
                FileQueryErrorV1::ManifestTampered
            } else {
                FileQueryErrorV1::UnsafePath
            },
        );
    }
    if let (Some(path), Some(expected_bytes), Some(expected_identity)) = (
        prepared.binding_path.as_ref(),
        prepared.binding_bytes.as_ref(),
        prepared.binding_identity.as_ref(),
    ) {
        let final_binding = read_query_file_bounded(
            context,
            path,
            prepared.manifest.index.budgets.max_manifest_bytes,
        )?;
        if final_binding.identity != *expected_identity {
            return Err(if final_binding.identity.same_inode(expected_identity) {
                FileQueryErrorV1::InvalidManifest
            } else {
                FileQueryErrorV1::UnsafePath
            });
        }
        if final_binding.bytes != *expected_bytes {
            return Err(FileQueryErrorV1::StaleIndex);
        }
    }
    let binding_bytes_read = u64::try_from(prepared.binding_bytes.as_ref().map_or(0, Vec::len))
        .ok()
        .and_then(|value| value.checked_mul(2))
        .ok_or(FileQueryErrorV1::ResourceBudgetExceeded)?;
    let manifest_bytes_read = prepared
        .manifest_bytes_read
        .checked_add(binding_bytes_read)
        .ok_or(FileQueryErrorV1::ResourceBudgetExceeded)?;
    let bytes_read = manifest_bytes_read
        .checked_add(shard_bytes_read)
        .ok_or(FileQueryErrorV1::ResourceBudgetExceeded)?;
    if bytes_read > prepared.plan.budget.max_bytes_read {
        return Err(FileQueryErrorV1::ResourceBudgetExceeded);
    }

    let total_result_count = match request.lookup {
        FileQueryLookupV1::Search { .. } => count_u64(lexical_hits.len()),
        FileQueryLookupV1::Adjacency { .. } => count_u64(adjacency_edges.len()),
    }
    .map_err(|_| FileQueryErrorV1::ResourceBudgetExceeded)?;
    if prepared.plan.start_offset > total_result_count {
        return Err(FileQueryErrorV1::ContinuationInvalid);
    }
    let start_offset = prepared.plan.start_offset;
    let mut end_offset = start_offset
        .checked_add(prepared.plan.page_size)
        .ok_or(FileQueryErrorV1::ResourceBudgetExceeded)?
        .min(total_result_count);
    let (mut lexical_page, mut adjacency_page) = query_page_slice(
        &request.lookup,
        &lexical_hits,
        &adjacency_edges,
        start_offset,
        end_offset,
    )?;
    let mut response_bytes = query_response_bytes(&lexical_page, &adjacency_page)?;
    while response_bytes > prepared.plan.budget.max_response_bytes && end_offset > start_offset {
        end_offset -= 1;
        (lexical_page, adjacency_page) = query_page_slice(
            &request.lookup,
            &lexical_hits,
            &adjacency_edges,
            start_offset,
            end_offset,
        )?;
        response_bytes = query_response_bytes(&lexical_page, &adjacency_page)?;
    }
    if response_bytes > prepared.plan.budget.max_response_bytes
        || (end_offset == start_offset && start_offset < total_result_count)
    {
        return Err(FileQueryErrorV1::ResourceBudgetExceeded);
    }
    let result_count = end_offset.saturating_sub(start_offset);
    let truncated = end_offset < total_result_count;
    let truncation = if truncated {
        QueryTruncationStateV1::Truncated
    } else {
        QueryTruncationStateV1::NotTruncated
    };
    let receipt = QueryPlanReceiptV1 {
        schema_version: QUERY_PLAN_RECEIPT_SCHEMA_V1.to_owned(),
        query_sha256: prepared.plan.query_sha256.clone(),
        index_manifest_sha256: prepared.plan.index_manifest_sha256.clone(),
        selected_shards: prepared.plan.selected_shards.clone(),
        excluded_shards: prepared.plan.excluded_shards.clone(),
        bytes_read,
        latency_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        budget: prepared.plan.budget,
        truncation,
        continuation: None,
    };
    let mut page = FileQueryPageV1 {
        receipt,
        plan_sha256: prepared.plan.plan_sha256.clone(),
        start_offset,
        end_offset,
        lexical_hits: lexical_page,
        adjacency_edges: adjacency_page,
        opened_shards,
        result_count,
        total_result_count,
        manifest_bytes_read,
        shard_bytes_read,
        response_bytes,
        shard_files_opened: count_u64(selected.len())
            .map_err(|_| FileQueryErrorV1::ResourceBudgetExceeded)?,
        plan_completed_before_shard_read: true,
        full_graph_read_count: 0,
        database_read_count: 0,
        network_call_count: 0,
        daemon_call_count: 0,
        prior_page_sha256: prepared.plan.prior_page_sha256.clone(),
        page_sha256: String::new(),
    };
    page.page_sha256 = file_query_page_content_sha256(&page);
    if truncated {
        page.receipt.continuation = Some(encode_file_query_continuation(
            &prepared.plan,
            end_offset,
            &page.page_sha256,
        )?);
    }
    validate_query_plan_receipt_v1(&page.receipt, &prepared.manifest.index)?;
    validate_file_query_page_v1(&page)?;
    Ok(page)
}

pub fn validate_file_query_page_v1(page: &FileQueryPageV1) -> Result<(), FileQueryErrorV1> {
    let result_count = page
        .lexical_hits
        .len()
        .checked_add(page.adjacency_edges.len())
        .and_then(|value| u64::try_from(value).ok())
        .ok_or(FileQueryErrorV1::ResourceBudgetExceeded)?;
    let observed_response_bytes = query_response_bytes(&page.lexical_hits, &page.adjacency_edges)?;
    let truncated = page.end_offset < page.total_result_count;
    let selected = page
        .receipt
        .selected_shards
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let excluded = page
        .receipt
        .excluded_shards
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if result_count != page.result_count
        || page.end_offset.checked_sub(page.start_offset) != Some(page.result_count)
        || page.end_offset > page.total_result_count
        || page.receipt.schema_version != QUERY_PLAN_RECEIPT_SCHEMA_V1
        || !is_sha256(&page.receipt.query_sha256)
        || !is_sha256(&page.receipt.index_manifest_sha256)
        || !is_sha256(&page.plan_sha256)
        || !is_sha256(&page.page_sha256)
        || page
            .prior_page_sha256
            .as_ref()
            .is_some_and(|value| !is_sha256(value))
        || (page.start_offset == 0) != page.prior_page_sha256.is_none()
        || page.receipt.bytes_read
            != page
                .manifest_bytes_read
                .checked_add(page.shard_bytes_read)
                .ok_or(FileQueryErrorV1::ResourceBudgetExceeded)?
        || page.receipt.bytes_read > page.receipt.budget.max_bytes_read
        || page.receipt.selected_shards.len() as u64 > page.receipt.budget.max_selected_shards
        || !sorted_or_empty(&page.receipt.selected_shards)
        || !sorted_or_empty(&page.receipt.excluded_shards)
        || !selected.is_disjoint(&excluded)
        || page.opened_shards != page.receipt.selected_shards
        || page.shard_files_opened != page.opened_shards.len() as u64
        || (!page.lexical_hits.is_empty() && !page.adjacency_edges.is_empty())
        || page.response_bytes != observed_response_bytes
        || page.response_bytes > page.receipt.budget.max_response_bytes
        || !page.plan_completed_before_shard_read
        || page.full_graph_read_count != 0
        || page.database_read_count != 0
        || page.network_call_count != 0
        || page.daemon_call_count != 0
        || page.page_sha256 != file_query_page_content_sha256(page)
    {
        return Err(FileQueryErrorV1::ManifestTampered);
    }
    match (
        truncated,
        page.receipt.truncation,
        page.receipt.continuation.as_deref(),
    ) {
        (true, QueryTruncationStateV1::Truncated, Some(token)) => {
            let continuation = decode_file_query_continuation(token)?;
            if continuation.query_sha256 != page.receipt.query_sha256
                || continuation.index_manifest_sha256 != page.receipt.index_manifest_sha256
                || continuation.selected_shards != page.receipt.selected_shards
                || continuation.next_offset != page.end_offset
                || continuation.page_size < page.result_count
                || continuation.budget != page.receipt.budget
                || continuation.prior_plan_sha256 != page.plan_sha256
                || continuation.prior_page_sha256 != page.page_sha256
            {
                return Err(FileQueryErrorV1::ContinuationInvalid);
            }
        }
        (false, QueryTruncationStateV1::NotTruncated, None) => {}
        _ => return Err(FileQueryErrorV1::ContinuationInvalid),
    }
    Ok(())
}

pub fn validate_next_page_against_v1(
    previous: &FileQueryPageV1,
    next: &FileQueryPageV1,
) -> Result<(), FileQueryErrorV1> {
    validate_file_query_page_v1(previous)?;
    validate_file_query_page_v1(next)?;
    let token = previous
        .receipt
        .continuation
        .as_deref()
        .ok_or(FileQueryErrorV1::ContinuationInvalid)?;
    let continuation = decode_file_query_continuation(token)?;
    if previous.receipt.truncation != QueryTruncationStateV1::Truncated
        || continuation.query_sha256 != previous.receipt.query_sha256
        || continuation.index_manifest_sha256 != previous.receipt.index_manifest_sha256
        || continuation.selected_shards != previous.receipt.selected_shards
        || continuation.next_offset != previous.end_offset
        || continuation.budget != previous.receipt.budget
        || continuation.prior_plan_sha256 != previous.plan_sha256
        || continuation.prior_page_sha256 != previous.page_sha256
        || next.start_offset != previous.end_offset
        || next.prior_page_sha256.as_deref() != Some(previous.page_sha256.as_str())
        || next.receipt.query_sha256 != previous.receipt.query_sha256
        || next.receipt.index_manifest_sha256 != previous.receipt.index_manifest_sha256
        || next.receipt.selected_shards != previous.receipt.selected_shards
        || next.receipt.excluded_shards != previous.receipt.excluded_shards
        || next.receipt.budget != previous.receipt.budget
        || next.total_result_count != previous.total_result_count
    {
        return Err(FileQueryErrorV1::ContinuationInvalid);
    }
    Ok(())
}

fn file_query_page_content_sha256(page: &FileQueryPageV1) -> String {
    let mut content = page.clone();
    content.receipt.continuation = None;
    content.page_sha256.clear();
    json_sha256(&("gtkg.file-query-page/v1", content))
}

struct QueryBoundReadV1 {
    bytes: Vec<u8>,
    sha256: String,
    identity: QueryFileIdentityV1,
}

fn file_query_context_error(error: ContextError) -> FileQueryErrorV1 {
    match error {
        ContextError::PathEscape(_) | ContextError::UnsafeRoot(_) => FileQueryErrorV1::UnsafePath,
        ContextError::RootIo { source, .. } if source.kind() == std::io::ErrorKind::NotFound => {
            FileQueryErrorV1::ShardTampered
        }
        ContextError::RootIo { .. } => FileQueryErrorV1::Io,
        ContextError::MissingRoot | ContextError::InvalidReceipt(_) => {
            FileQueryErrorV1::InvalidManifest
        }
    }
}

#[cfg(not(unix))]
fn file_query_durable_error(error: crate::durable::DurableWriteError) -> FileQueryErrorV1 {
    match error.kind {
        DurableErrorKind::Invalid => FileQueryErrorV1::InvalidManifest,
        DurableErrorKind::Unauthorized | DurableErrorKind::Unsafe => FileQueryErrorV1::UnsafePath,
        DurableErrorKind::Conflict => FileQueryErrorV1::ShardTampered,
        DurableErrorKind::Io => FileQueryErrorV1::Io,
    }
}

fn digest_hex_query(value: &str) -> Result<&str, FileQueryErrorV1> {
    if !is_sha256(value) {
        return Err(FileQueryErrorV1::InvalidManifest);
    }
    Ok(&value[7..])
}

fn lexical_term_route_key(value: &str) -> String {
    format!("term:{}", hex::encode(value.as_bytes()))
}

fn lexical_trigram_route_key(value: &str) -> String {
    format!("tri:{}", hex::encode(value.as_bytes()))
}

fn lexical_short_route_key(value: &str) -> String {
    format!("short:{}", hex::encode(value.as_bytes()))
}

fn short_cjk_scalar_substrings(value: &str) -> BTreeSet<String> {
    let scalars = value.chars().collect::<Vec<_>>();
    let mut values = BTreeSet::new();
    for length in 1..=2 {
        for window in scalars.windows(length) {
            values.insert(window.iter().collect());
        }
    }
    values
}

fn valid_routing_key(value: &str) -> bool {
    let (kind, encoded) = if let Some(encoded) = value.strip_prefix("term:") {
        ("term", encoded)
    } else if let Some(encoded) = value.strip_prefix("tri:") {
        ("tri", encoded)
    } else if let Some(encoded) = value.strip_prefix("short:") {
        ("short", encoded)
    } else {
        return false;
    };
    if encoded.is_empty()
        || encoded.len() > 4_096
        || !encoded.len().is_multiple_of(2)
        || !encoded
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return false;
    }
    let Some(decoded) = hex::decode(encoded)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
    else {
        return false;
    };
    match kind {
        "term" => {
            let tokens = tokenize_query_v1(&decoded).tokens;
            tokens.len() == 1 && tokens[0].normalized == decoded
        }
        "tri" => decoded.chars().count() == 3 && !decoded.chars().any(char::is_control),
        "short" => {
            let tokens = tokenize_query_v1(&decoded).tokens;
            matches!(decoded.chars().count(), 1 | 2)
                && tokens.len() == 1
                && tokens[0].kind == QueryTokenKindV1::CjkRun
                && tokens[0].normalized == decoded
        }
        _ => false,
    }
}

fn safe_query_relative_path(value: &str, expected_parent: &str) -> bool {
    let path = Path::new(value);
    if path.is_absolute() {
        return false;
    }
    let components = path.components().collect::<Vec<_>>();
    components.len() == 2
        && matches!(components[0], Component::Normal(parent) if parent == expected_parent)
        && matches!(components[1], Component::Normal(file) if {
            let file = file.to_string_lossy();
            let stem = file.strip_suffix(".json");
            stem.is_some_and(|stem| {
                stem.len() == 64
                && stem
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
            })
        })
}

fn select_file_query_shards(
    manifest: &FileQueryIndexManifestV1,
    lookup: &FileQueryLookupV1,
) -> Result<(Vec<String>, bool), FileQueryErrorV1> {
    match lookup {
        FileQueryLookupV1::Search { query } => {
            let tokens = tokenize_query_v1(query).tokens;
            if tokens.is_empty() {
                return Err(FileQueryErrorV1::QueryInvalid);
            }
            let mut routing_keys = Vec::new();
            if tokens.len() == 1
                && tokens[0].kind == QueryTokenKindV1::CjkRun
                && !tokens[0].trigrams.is_empty()
            {
                routing_keys.extend(
                    tokens[0]
                        .trigrams
                        .iter()
                        .map(|trigram| lexical_trigram_route_key(trigram)),
                );
            } else if tokens.len() == 1 && tokens[0].kind == QueryTokenKindV1::CjkRun {
                routing_keys.push(lexical_short_route_key(&tokens[0].normalized));
            } else {
                routing_keys.extend(
                    tokens
                        .iter()
                        .map(|token| lexical_term_route_key(&token.normalized)),
                );
            }
            let mut intersection: Option<BTreeSet<String>> = None;
            for key in routing_keys {
                let Some(shard_ids) = manifest
                    .lexical_routing_catalog
                    .entries
                    .binary_search_by(|entry| entry.routing_key.as_str().cmp(key.as_str()))
                    .ok()
                    .and_then(|index| manifest.lexical_routing_catalog.entries.get(index))
                    .map(|entry| &entry.shard_ids)
                else {
                    return Ok((Vec::new(), false));
                };
                if shard_ids.is_empty() {
                    return Ok((Vec::new(), true));
                }
                let shard_ids = shard_ids.iter().cloned().collect::<BTreeSet<_>>();
                intersection = Some(match intersection {
                    Some(mut current) => {
                        current.retain(|shard_id| shard_ids.contains(shard_id));
                        current
                    }
                    None => shard_ids,
                });
            }
            let selected = intersection
                .unwrap_or_default()
                .into_iter()
                .collect::<Vec<_>>();
            Ok((selected, false))
        }
        FileQueryLookupV1::Adjacency { node_id, direction } => {
            if validate_adjacency_identity(node_id).is_err() {
                return Err(FileQueryErrorV1::QueryInvalid);
            }
            if manifest
                .adjacency_catalog
                .nodes
                .binary_search_by(|candidate| candidate.as_str().cmp(node_id))
                .is_err()
            {
                return Ok((Vec::new(), false));
            }
            let route = manifest
                .adjacency_routes
                .binary_search_by(|route| {
                    route
                        .node_id
                        .as_str()
                        .cmp(node_id)
                        .then_with(|| route.direction.cmp(direction))
                })
                .ok()
                .and_then(|index| manifest.adjacency_routes.get(index))
                .ok_or(FileQueryErrorV1::InvalidManifest)?;
            let selected = route.shard_id.iter().cloned().collect();
            Ok((selected, false))
        }
    }
}

fn file_query_plan_content_sha256(plan: &FileQueryPlanV1) -> String {
    json_sha256(&(
        &plan.manifest_ref,
        plan.manifest_sha256.as_str(),
        plan.index_manifest_sha256.as_str(),
        plan.routing_catalog_sha256.as_str(),
        plan.query_sha256.as_str(),
        &plan.selected_shards,
        &plan.excluded_shards,
        plan.start_offset,
        plan.page_size,
        plan.prior_page_sha256.as_deref(),
        plan.budget,
    ))
}

pub fn file_query_continuation_content_sha256_v1(continuation: &FileQueryContinuationV1) -> String {
    json_sha256(&(
        continuation.schema_version.as_str(),
        continuation.query_sha256.as_str(),
        continuation.manifest_sha256.as_str(),
        continuation.index_manifest_sha256.as_str(),
        continuation.routing_catalog_sha256.as_str(),
        &continuation.selected_shards,
        continuation.next_offset,
        continuation.page_size,
        continuation.budget,
        continuation.prior_plan_sha256.as_str(),
        continuation.prior_page_sha256.as_str(),
    ))
}

fn encode_file_query_continuation(
    plan: &FileQueryPlanV1,
    next_offset: u64,
    prior_page_sha256: &str,
) -> Result<String, FileQueryErrorV1> {
    let mut continuation = FileQueryContinuationV1 {
        schema_version: FILE_QUERY_CONTINUATION_SCHEMA_V1.to_owned(),
        query_sha256: plan.query_sha256.clone(),
        manifest_sha256: plan.manifest_sha256.clone(),
        index_manifest_sha256: plan.index_manifest_sha256.clone(),
        routing_catalog_sha256: plan.routing_catalog_sha256.clone(),
        selected_shards: plan.selected_shards.clone(),
        next_offset,
        page_size: plan.page_size,
        budget: plan.budget,
        prior_plan_sha256: plan.plan_sha256.clone(),
        prior_page_sha256: prior_page_sha256.to_owned(),
        continuation_sha256: String::new(),
    };
    continuation.continuation_sha256 = file_query_continuation_content_sha256_v1(&continuation);
    let bytes =
        serde_json::to_vec(&continuation).map_err(|_| FileQueryErrorV1::ContinuationInvalid)?;
    Ok(format!("gtkgc1.{}", hex::encode(bytes)))
}

fn decode_file_query_continuation(
    token: &str,
) -> Result<FileQueryContinuationV1, FileQueryErrorV1> {
    let encoded = token
        .strip_prefix("gtkgc1.")
        .ok_or(FileQueryErrorV1::ContinuationInvalid)?;
    if encoded.is_empty() || encoded.len() > 65_536 || !encoded.len().is_multiple_of(2) {
        return Err(FileQueryErrorV1::ContinuationInvalid);
    }
    let bytes = hex::decode(encoded).map_err(|_| FileQueryErrorV1::ContinuationInvalid)?;
    let continuation: FileQueryContinuationV1 =
        serde_json::from_slice(&bytes).map_err(|_| FileQueryErrorV1::ContinuationInvalid)?;
    if continuation.schema_version != FILE_QUERY_CONTINUATION_SCHEMA_V1
        || !is_sha256(&continuation.query_sha256)
        || !is_sha256(&continuation.manifest_sha256)
        || !is_sha256(&continuation.index_manifest_sha256)
        || !is_sha256(&continuation.routing_catalog_sha256)
        || !is_sha256(&continuation.prior_plan_sha256)
        || !is_sha256(&continuation.prior_page_sha256)
        || continuation.next_offset == 0
        || continuation.page_size == 0
        || !sorted_or_empty(&continuation.selected_shards)
        || continuation.continuation_sha256
            != file_query_continuation_content_sha256_v1(&continuation)
    {
        return Err(FileQueryErrorV1::ContinuationInvalid);
    }
    Ok(continuation)
}

fn query_page_slice(
    lookup: &FileQueryLookupV1,
    lexical_hits: &[LexicalSearchHitV1],
    adjacency_edges: &[AdjacencyEdgeRecordV1],
    start_offset: u64,
    end_offset: u64,
) -> Result<(Vec<LexicalSearchHitV1>, Vec<AdjacencyEdgeRecordV1>), FileQueryErrorV1> {
    let start =
        usize::try_from(start_offset).map_err(|_| FileQueryErrorV1::ResourceBudgetExceeded)?;
    let end = usize::try_from(end_offset).map_err(|_| FileQueryErrorV1::ResourceBudgetExceeded)?;
    if start > end {
        return Err(FileQueryErrorV1::ContinuationInvalid);
    }
    match lookup {
        FileQueryLookupV1::Search { .. } => lexical_hits
            .get(start..end)
            .map(|values| (values.to_vec(), Vec::new()))
            .ok_or(FileQueryErrorV1::ContinuationInvalid),
        FileQueryLookupV1::Adjacency { .. } => adjacency_edges
            .get(start..end)
            .map(|values| (Vec::new(), values.to_vec()))
            .ok_or(FileQueryErrorV1::ContinuationInvalid),
    }
}

fn query_response_bytes(
    lexical_hits: &[LexicalSearchHitV1],
    adjacency_edges: &[AdjacencyEdgeRecordV1],
) -> Result<u64, FileQueryErrorV1> {
    serde_json::to_vec(&(lexical_hits, adjacency_edges))
        .ok()
        .and_then(|bytes| u64::try_from(bytes.len()).ok())
        .ok_or(FileQueryErrorV1::ResourceBudgetExceeded)
}

fn route_selected_adjacency_shard_v1(
    catalog: &AdjacencyRoutingCatalogV1,
    shard: &AdjacencyRoutingShardV1,
    node_id: &str,
    direction: AdjacencyDirectionV1,
) -> Result<AdjacencyRouteResultV1, AdjacencyIndexErrorV1> {
    let budgets = QueryResourceBudgetsV1::v03_frozen();
    validate_adjacency_catalog_shape(catalog, &budgets)?;
    if catalog.raw_bytes_sha256 != adjacency_routing_catalog_content_sha256_v1(catalog) {
        return Err(AdjacencyIndexErrorV1::CatalogDigestMismatch);
    }
    if catalog
        .nodes
        .binary_search_by(|candidate| candidate.as_str().cmp(node_id))
        .is_err()
    {
        return Err(AdjacencyIndexErrorV1::UnknownNode);
    }
    let route = catalog
        .routes
        .iter()
        .find(|route| route.node_id == node_id && route.direction == direction)
        .ok_or(AdjacencyIndexErrorV1::InvalidShard)?;
    let descriptor = catalog
        .shards
        .iter()
        .find(|descriptor| descriptor.shard_id == route.shard_id)
        .ok_or(AdjacencyIndexErrorV1::InvalidShard)?;
    if descriptor.shard_kind != QueryShardKindV1::Adjacency
        || descriptor.raw_bytes_sha256 != shard.header.raw_bytes_sha256
        || descriptor.record_count != shard.records.len() as u64
        || shard.header.shard_id != route.shard_id
        || shard.header.direction != direction
        || shard.header.raw_bytes_sha256 != adjacency_routing_shard_content_sha256_v1(shard)
    {
        return Err(AdjacencyIndexErrorV1::ContentDigestMismatch);
    }
    validate_adjacency_shard_v1(&shard.header, &budgets)?;
    let nodes = catalog.nodes.iter().cloned().collect::<BTreeSet<_>>();
    let mut observed_routes = BTreeSet::new();
    let mut outgoing = BTreeMap::new();
    let mut incoming = BTreeMap::new();
    validate_routing_shard(
        shard,
        &nodes,
        &budgets,
        &mut observed_routes,
        &mut outgoing,
        &mut incoming,
    )?;
    let expected_routes = catalog
        .routes
        .iter()
        .filter(|candidate| candidate.shard_id == shard.header.shard_id)
        .cloned()
        .collect::<BTreeSet<_>>();
    if observed_routes != expected_routes {
        return Err(AdjacencyIndexErrorV1::InvalidShard);
    }
    let edges = shard
        .records
        .iter()
        .filter(|record| record.node_id == node_id)
        .cloned()
        .collect::<Vec<_>>();
    if edges.is_empty() {
        return Err(AdjacencyIndexErrorV1::InvalidShard);
    }
    Ok(AdjacencyRouteResultV1 {
        node_id: node_id.to_owned(),
        direction,
        selected_shard_id: Some(route.shard_id.clone()),
        selected_shard_count: 1,
        edges,
        full_graph_read_count: 0,
        database_read_count: 0,
        network_call_count: 0,
        daemon_call_count: 0,
    })
}

fn absolute_query_candidate(
    context: &CallContext,
    requested_path: &Path,
) -> Result<PathBuf, FileQueryErrorV1> {
    if requested_path.components().any(|component| {
        matches!(
            component,
            Component::ParentDir | Component::CurDir | Component::Prefix(_)
        )
    }) {
        return Err(FileQueryErrorV1::UnsafePath);
    }
    if requested_path.is_absolute() {
        Ok(requested_path.to_path_buf())
    } else {
        context
            .workspace_root()
            .map(|root| root.join(requested_path))
            .ok_or(FileQueryErrorV1::InvalidManifest)
    }
}

#[cfg(unix)]
fn create_query_directory_descriptor_first<F>(
    context: &CallContext,
    candidate: &Path,
    pre_mkdir: Option<F>,
) -> Result<(), FileQueryErrorV1>
where
    F: FnOnce(&Path),
{
    use rustix::fs::{Mode, OFlags, mkdirat, open, openat};
    use std::os::unix::fs::MetadataExt;

    let authorized_root = context
        .authorized_lexical_roots()
        .iter()
        .chain(context.authorized_roots())
        .filter(|root| candidate == **root || candidate.starts_with(root))
        .max_by_key(|root| root.components().count())
        .cloned()
        .ok_or(FileQueryErrorV1::UnsafePath)?;
    let relative = candidate
        .strip_prefix(&authorized_root)
        .map_err(|_| FileQueryErrorV1::UnsafePath)?;
    let components = relative
        .components()
        .map(|component| match component {
            Component::Normal(name) => Ok(name.to_os_string()),
            _ => Err(FileQueryErrorV1::UnsafePath),
        })
        .collect::<Result<Vec<OsString>, _>>()?;
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let root = open(&authorized_root, flags, Mode::empty()).map_err(map_query_open_error)?;
    let mut directory = File::from(root);
    let root_metadata = directory.metadata().map_err(|_| FileQueryErrorV1::Io)?;
    let path_root_metadata =
        fs::symlink_metadata(&authorized_root).map_err(|_| FileQueryErrorV1::Io)?;
    if !root_metadata.is_dir()
        || path_root_metadata.file_type().is_symlink()
        || !path_root_metadata.is_dir()
        || root_metadata.dev() != path_root_metadata.dev()
        || root_metadata.ino() != path_root_metadata.ino()
    {
        return Err(FileQueryErrorV1::UnsafePath);
    }
    if let Some(hook) = pre_mkdir {
        hook(candidate);
    }
    for component in &components {
        let opened = match openat(&directory, component.as_os_str(), flags, Mode::empty()) {
            Ok(opened) => opened,
            Err(error) if error == rustix::io::Errno::NOENT => {
                match mkdirat(
                    &directory,
                    component.as_os_str(),
                    Mode::from_raw_mode(0o700),
                ) {
                    Ok(()) => {}
                    Err(race) if race == rustix::io::Errno::EXIST => {}
                    Err(error) => return Err(map_query_open_error(error)),
                }
                directory.sync_all().map_err(|_| FileQueryErrorV1::Io)?;
                openat(&directory, component.as_os_str(), flags, Mode::empty())
                    .map_err(map_query_open_error)?
            }
            Err(error) => return Err(map_query_open_error(error)),
        };
        directory = File::from(opened);
    }
    directory.sync_all().map_err(|_| FileQueryErrorV1::Io)?;
    let opened_metadata = directory.metadata().map_err(|_| FileQueryErrorV1::Io)?;
    let path_metadata = fs::symlink_metadata(candidate).map_err(|_| FileQueryErrorV1::Io)?;
    if !opened_metadata.is_dir()
        || path_metadata.file_type().is_symlink()
        || !path_metadata.is_dir()
        || opened_metadata.dev() != path_metadata.dev()
        || opened_metadata.ino() != path_metadata.ino()
    {
        return Err(FileQueryErrorV1::UnsafePath);
    }
    let authorized = context
        .authorize_read(candidate)
        .map_err(file_query_context_error)?;
    let canonical_root = fs::canonicalize(&authorized_root).map_err(|_| FileQueryErrorV1::Io)?;
    if authorized != canonical_root.join(relative) {
        return Err(FileQueryErrorV1::UnsafePath);
    }
    Ok(())
}

#[cfg(not(unix))]
fn create_query_directory_descriptor_first<F>(
    _context: &CallContext,
    _candidate: &Path,
    _pre_mkdir: Option<F>,
) -> Result<(), FileQueryErrorV1>
where
    F: FnOnce(&Path),
{
    Err(FileQueryErrorV1::UnsafePath)
}

fn verify_query_directory_no_symlink(
    context: &CallContext,
    candidate: &Path,
) -> Result<(), FileQueryErrorV1> {
    let authorized_root = context
        .authorized_lexical_roots()
        .iter()
        .chain(context.authorized_roots())
        .filter(|root| candidate == **root || candidate.starts_with(root))
        .max_by_key(|root| root.components().count())
        .cloned()
        .ok_or(FileQueryErrorV1::UnsafePath)?;
    let relative = candidate
        .strip_prefix(&authorized_root)
        .map_err(|_| FileQueryErrorV1::UnsafePath)?;
    let components = relative
        .components()
        .map(|component| match component {
            Component::Normal(name) => Ok(name.to_os_string()),
            _ => Err(FileQueryErrorV1::UnsafePath),
        })
        .collect::<Result<Vec<OsString>, _>>()?;
    let authorized = context
        .authorize_read(candidate)
        .map_err(file_query_context_error)?;
    let canonical_root = fs::canonicalize(&authorized_root).map_err(|_| FileQueryErrorV1::Io)?;
    if authorized != canonical_root.join(relative) {
        return Err(FileQueryErrorV1::UnsafePath);
    }
    let path_metadata = fs::symlink_metadata(candidate).map_err(|_| FileQueryErrorV1::Io)?;
    if path_metadata.file_type().is_symlink() || !path_metadata.file_type().is_dir() {
        return Err(FileQueryErrorV1::UnsafePath);
    }
    verify_query_directory_descriptor(&authorized_root, &components, &path_metadata)
}

#[cfg(unix)]
fn verify_query_directory_descriptor(
    authorized_root: &Path,
    components: &[OsString],
    path_metadata: &fs::Metadata,
) -> Result<(), FileQueryErrorV1> {
    use rustix::fs::{Mode, OFlags, open, openat};
    use std::os::unix::fs::MetadataExt;

    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut directory =
        open(authorized_root, flags, Mode::empty()).map_err(map_query_open_error)?;
    for component in components {
        directory = openat(&directory, component.as_os_str(), flags, Mode::empty())
            .map_err(map_query_open_error)?;
    }
    let opened = File::from(directory)
        .metadata()
        .map_err(|_| FileQueryErrorV1::Io)?;
    if !opened.file_type().is_dir()
        || path_metadata.dev() != opened.dev()
        || path_metadata.ino() != opened.ino()
    {
        return Err(FileQueryErrorV1::UnsafePath);
    }
    Ok(())
}

#[cfg(not(unix))]
fn verify_query_directory_descriptor(
    _authorized_root: &Path,
    _components: &[OsString],
    _path_metadata: &fs::Metadata,
) -> Result<(), FileQueryErrorV1> {
    Ok(())
}

fn read_query_file_bounded(
    context: &CallContext,
    requested_path: &Path,
    max_bytes: u64,
) -> Result<QueryBoundReadV1, FileQueryErrorV1> {
    if max_bytes == 0
        || requested_path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::CurDir | Component::Prefix(_)
            )
        })
    {
        return Err(FileQueryErrorV1::UnsafePath);
    }
    let candidate = if requested_path.is_absolute() {
        requested_path.to_path_buf()
    } else {
        context
            .workspace_root()
            .ok_or(FileQueryErrorV1::InvalidManifest)?
            .join(requested_path)
    };
    let authorized_root = context
        .authorized_lexical_roots()
        .iter()
        .chain(context.authorized_roots())
        .filter(|root| candidate == **root || candidate.starts_with(root))
        .max_by_key(|root| root.components().count())
        .cloned()
        .ok_or(FileQueryErrorV1::UnsafePath)?;
    let relative = candidate
        .strip_prefix(&authorized_root)
        .map_err(|_| FileQueryErrorV1::UnsafePath)?;
    let components = relative
        .components()
        .map(|component| match component {
            Component::Normal(name) => Ok(name.to_os_string()),
            _ => Err(FileQueryErrorV1::UnsafePath),
        })
        .collect::<Result<Vec<OsString>, _>>()?;
    if components.is_empty() {
        return Err(FileQueryErrorV1::UnsafePath);
    }
    let mut file = open_query_file_descriptor(&authorized_root, &components)?;
    let opened = file.metadata().map_err(|_| FileQueryErrorV1::Io)?;
    if !opened.file_type().is_file() {
        return Err(FileQueryErrorV1::UnsafePath);
    }
    ensure_query_private_inode(&opened, &opened)?;
    if opened.len() > max_bytes {
        return Err(FileQueryErrorV1::ResourceBudgetExceeded);
    }
    let authorized = context
        .authorize_read(&candidate)
        .map_err(file_query_context_error)?;
    let canonical_root = fs::canonicalize(&authorized_root).map_err(|_| FileQueryErrorV1::Io)?;
    if authorized != canonical_root.join(relative) {
        return Err(FileQueryErrorV1::UnsafePath);
    }
    let before = fs::symlink_metadata(&candidate).map_err(|_| FileQueryErrorV1::ShardTampered)?;
    ensure_query_private_inode(&before, &opened)?;
    let limit = max_bytes
        .checked_add(1)
        .ok_or(FileQueryErrorV1::ResourceBudgetExceeded)?;
    let mut bytes = Vec::with_capacity(
        usize::try_from(opened.len()).map_err(|_| FileQueryErrorV1::ResourceBudgetExceeded)?,
    );
    std::io::Read::by_ref(&mut file)
        .take(limit)
        .read_to_end(&mut bytes)
        .map_err(|_| FileQueryErrorV1::Io)?;
    if bytes.len() as u64 > max_bytes {
        return Err(FileQueryErrorV1::ResourceBudgetExceeded);
    }
    let after_opened = file.metadata().map_err(|_| FileQueryErrorV1::Io)?;
    let after_path =
        fs::symlink_metadata(&candidate).map_err(|_| FileQueryErrorV1::ShardTampered)?;
    ensure_query_private_inode(&after_opened, &opened)?;
    ensure_query_private_inode(&after_path, &opened)?;
    if after_opened.len() != opened.len() || bytes.len() as u64 != opened.len() {
        return Err(FileQueryErrorV1::ShardTampered);
    }
    Ok(QueryBoundReadV1 {
        sha256: format!("sha256:{}", hex::encode(Sha256::digest(&bytes))),
        identity: QueryFileIdentityV1::from_metadata(&after_opened),
        bytes,
    })
}

fn query_file_identity_v1(
    context: &CallContext,
    requested_path: &Path,
    max_bytes: u64,
) -> Result<QueryFileIdentityV1, FileQueryErrorV1> {
    if max_bytes == 0
        || requested_path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::CurDir | Component::Prefix(_)
            )
        })
    {
        return Err(FileQueryErrorV1::UnsafePath);
    }
    let candidate = if requested_path.is_absolute() {
        requested_path.to_path_buf()
    } else {
        context
            .workspace_root()
            .ok_or(FileQueryErrorV1::InvalidManifest)?
            .join(requested_path)
    };
    let authorized_root = context
        .authorized_lexical_roots()
        .iter()
        .chain(context.authorized_roots())
        .filter(|root| candidate == **root || candidate.starts_with(root))
        .max_by_key(|root| root.components().count())
        .cloned()
        .ok_or(FileQueryErrorV1::UnsafePath)?;
    let relative = candidate
        .strip_prefix(&authorized_root)
        .map_err(|_| FileQueryErrorV1::UnsafePath)?;
    let components = relative
        .components()
        .map(|component| match component {
            Component::Normal(name) => Ok(name.to_os_string()),
            _ => Err(FileQueryErrorV1::UnsafePath),
        })
        .collect::<Result<Vec<OsString>, _>>()?;
    if components.is_empty() {
        return Err(FileQueryErrorV1::UnsafePath);
    }
    let file = open_query_file_descriptor(&authorized_root, &components)?;
    let opened = file.metadata().map_err(|_| FileQueryErrorV1::Io)?;
    if !opened.file_type().is_file() || opened.len() > max_bytes {
        return Err(if opened.len() > max_bytes {
            FileQueryErrorV1::ResourceBudgetExceeded
        } else {
            FileQueryErrorV1::UnsafePath
        });
    }
    ensure_query_private_inode(&opened, &opened)?;
    let authorized = context
        .authorize_read(&candidate)
        .map_err(file_query_context_error)?;
    let canonical_root = fs::canonicalize(&authorized_root).map_err(|_| FileQueryErrorV1::Io)?;
    if authorized != canonical_root.join(relative) {
        return Err(FileQueryErrorV1::UnsafePath);
    }
    let path_metadata =
        fs::symlink_metadata(&candidate).map_err(|_| FileQueryErrorV1::ShardTampered)?;
    let final_opened = file.metadata().map_err(|_| FileQueryErrorV1::Io)?;
    ensure_query_private_inode(&path_metadata, &opened)?;
    ensure_query_private_inode(&final_opened, &opened)?;
    Ok(QueryFileIdentityV1::from_metadata(&final_opened))
}

#[cfg(unix)]
fn open_query_file_descriptor(
    authorized_root: &Path,
    components: &[OsString],
) -> Result<File, FileQueryErrorV1> {
    use rustix::fs::{Mode, OFlags, open, openat};

    let directory_flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut directory =
        open(authorized_root, directory_flags, Mode::empty()).map_err(map_query_open_error)?;
    for (index, component) in components.iter().enumerate() {
        let is_file = index + 1 == components.len();
        let flags = if is_file {
            OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC
        } else {
            directory_flags
        };
        let opened = openat(&directory, component.as_os_str(), flags, Mode::empty())
            .map_err(map_query_open_error)?;
        if is_file {
            return Ok(File::from(opened));
        }
        directory = opened;
    }
    Err(FileQueryErrorV1::UnsafePath)
}

#[cfg(unix)]
fn map_query_open_error(error: rustix::io::Errno) -> FileQueryErrorV1 {
    if matches!(error, rustix::io::Errno::LOOP | rustix::io::Errno::NOTDIR) {
        FileQueryErrorV1::UnsafePath
    } else if error == rustix::io::Errno::NOENT {
        FileQueryErrorV1::ShardTampered
    } else {
        FileQueryErrorV1::Io
    }
}

#[cfg(not(unix))]
fn open_query_file_descriptor(
    authorized_root: &Path,
    components: &[OsString],
) -> Result<File, FileQueryErrorV1> {
    let mut candidate = authorized_root.to_path_buf();
    for component in components {
        candidate.push(component);
    }
    File::open(candidate).map_err(|_| FileQueryErrorV1::Io)
}

fn ensure_query_private_inode(
    path_metadata: &fs::Metadata,
    opened_metadata: &fs::Metadata,
) -> Result<(), FileQueryErrorV1> {
    if path_metadata.file_type().is_symlink()
        || !path_metadata.file_type().is_file()
        || !opened_metadata.file_type().is_file()
    {
        return Err(FileQueryErrorV1::UnsafePath);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if path_metadata.nlink() != 1
            || opened_metadata.nlink() != 1
            || path_metadata.dev() != opened_metadata.dev()
            || path_metadata.ino() != opened_metadata.ino()
        {
            return Err(FileQueryErrorV1::UnsafePath);
        }
    }
    Ok(())
}

pub fn tokenize_query_v1(input: &str) -> QueryTokenizationReceiptV1 {
    assert_eq!(
        UNICODE_VERSION,
        (17, 0, 0),
        "Q00 tokenizer must fail closed on Unicode data drift"
    );
    let input = input.nfc().collect::<String>();
    let mut tokens = Vec::new();
    let mut buffer = String::new();
    let mut kind = None;

    for character in input.chars() {
        let next_kind = classify(character);
        if kind == Some(QueryTokenKindV1::AsciiIdentifier)
            && next_kind == Some(QueryTokenKindV1::UnicodeWord)
            && !buffer.contains('_')
        {
            kind = Some(QueryTokenKindV1::UnicodeWord);
            buffer.push(character);
            continue;
        }
        if kind == Some(QueryTokenKindV1::UnicodeWord)
            && next_kind == Some(QueryTokenKindV1::AsciiIdentifier)
            && character.is_ascii_alphanumeric()
        {
            buffer.push(character);
            continue;
        }
        if next_kind != kind {
            push_token(&mut tokens, &mut buffer, kind);
            kind = next_kind;
        }
        if next_kind.is_some() {
            buffer.push(character);
        }
    }
    push_token(&mut tokens, &mut buffer, kind);

    QueryTokenizationReceiptV1 {
        tokenizer_id: QUERY_TOKENIZER_ID_V1.to_owned(),
        unicode_version: QUERY_UNICODE_VERSION_V1.to_owned(),
        normalization: QUERY_NORMALIZATION_V1.to_owned(),
        tokens,
    }
}

fn classify(character: char) -> Option<QueryTokenKindV1> {
    if character.is_ascii_alphanumeric() || character == '_' {
        Some(QueryTokenKindV1::AsciiIdentifier)
    } else if is_cjk(character) {
        Some(QueryTokenKindV1::CjkRun)
    } else if character.is_alphanumeric() {
        Some(QueryTokenKindV1::UnicodeWord)
    } else {
        None
    }
}

fn push_token(tokens: &mut Vec<QueryTokenV1>, buffer: &mut String, kind: Option<QueryTokenKindV1>) {
    let Some(kind) = kind else {
        buffer.clear();
        return;
    };
    if buffer.is_empty() {
        return;
    }
    let lowered = match kind {
        QueryTokenKindV1::CjkRun => std::mem::take(buffer),
        QueryTokenKindV1::AsciiIdentifier => {
            let value = buffer.to_ascii_lowercase();
            buffer.clear();
            value
        }
        QueryTokenKindV1::UnicodeWord => {
            let value = buffer
                .chars()
                .flat_map(char::to_lowercase)
                .collect::<String>();
            buffer.clear();
            value.nfc().collect()
        }
    };
    tokens.push(QueryTokenV1 {
        trigrams: scalar_trigrams(&lowered),
        normalized: lowered,
        kind,
    });
}

fn is_cjk(character: char) -> bool {
    matches!(character as u32,
        0x3400..=0x4dbf | 0x4e00..=0x9fff | 0xf900..=0xfaff |
        0x20000..=0x2ee5f | 0x30000..=0x33479 |
        0x3040..=0x30ff | 0x31f0..=0x31ff |
        0x1100..=0x11ff | 0x3130..=0x318f | 0xa960..=0xa97f |
        0xac00..=0xd7af | 0xd7b0..=0xd7ff)
}

fn scalar_trigrams(value: &str) -> Vec<String> {
    let scalars = value.chars().collect::<Vec<_>>();
    if scalars.len() < 3 {
        return Vec::new();
    }
    let mut seen = BTreeSet::new();
    let mut trigrams = Vec::new();
    for window in scalars.windows(3) {
        let trigram = window.iter().collect::<String>();
        if seen.insert(trigram.clone()) {
            trigrams.push(trigram);
        }
    }
    trigrams
}

pub fn query_shard_catalog_digests_v1(entries: &[QueryShardDescriptorV1]) -> QueryIndexDigestsV1 {
    let lexical = entries
        .iter()
        .filter(|entry| entry.shard_kind == QueryShardKindV1::Lexical)
        .collect::<Vec<_>>();
    let adjacency = entries
        .iter()
        .filter(|entry| entry.shard_kind == QueryShardKindV1::Adjacency)
        .collect::<Vec<_>>();
    QueryIndexDigestsV1 {
        lexical_catalog_sha256: json_sha256(&lexical),
        adjacency_catalog_sha256: json_sha256(&adjacency),
        shard_set_sha256: json_sha256(&entries),
    }
}

pub fn validate_query_index_manifest_v1(
    manifest: &QueryIndexManifestV1,
) -> Result<(), QueryContractErrorV1> {
    if manifest.schema_version != QUERY_INDEX_MANIFEST_SCHEMA_V1 {
        return Err(QueryContractErrorV1::UnsupportedSchema);
    }
    if ![
        &manifest.source_identity,
        &manifest.graph_identity,
        &manifest.overlay_identity,
    ]
    .iter()
    .all(|value| is_sha256(value))
    {
        return Err(QueryContractErrorV1::InvalidIdentity);
    }
    validate_tokenizer(&manifest.tokenizer_id, QUERY_UNICODE_VERSION_V1)?;
    if manifest.budgets != QueryResourceBudgetsV1::v03_frozen() {
        return Err(QueryContractErrorV1::FrozenBudgetMismatch);
    }
    if serde_json::to_vec(manifest).map_or(true, |bytes| {
        bytes.len() as u64 > manifest.budgets.max_manifest_bytes
    }) {
        return Err(QueryContractErrorV1::ResourceBudgetExceeded);
    }
    if !manifest.shards.denominator.is_non_zero() {
        return Err(QueryContractErrorV1::ZeroDenominator);
    }
    if !manifest.shards.denominator.is_closed() {
        return Err(QueryContractErrorV1::DenominatorNotClosed);
    }
    if manifest.shards.denominator.admitted_shards != manifest.shards.entries.len() as u64 {
        return Err(QueryContractErrorV1::DenominatorCountMismatch);
    }
    if manifest.shards.entries.len() as u64 > manifest.budgets.max_shard_count
        || !strictly_sorted_by(&manifest.shards.entries, |left, right| {
            left.shard_id < right.shard_id
        })
    {
        return Err(QueryContractErrorV1::InvalidExactSet);
    }
    for entry in &manifest.shards.entries {
        if entry.shard_id.is_empty()
            || !is_sha256(&entry.raw_bytes_sha256)
            || entry.byte_len == 0
            || entry.record_count == 0
            || entry.byte_len > manifest.budgets.max_shard_bytes
            || entry.record_count > manifest.budgets.max_records_per_shard
        {
            return Err(QueryContractErrorV1::ResourceBudgetExceeded);
        }
    }
    let kinds = manifest
        .shards
        .entries
        .iter()
        .map(|entry| entry.shard_kind)
        .collect::<BTreeSet<_>>();
    if kinds != BTreeSet::from([QueryShardKindV1::Lexical, QueryShardKindV1::Adjacency]) {
        return Err(QueryContractErrorV1::IncompleteShardCatalog);
    }
    if manifest.digests != query_shard_catalog_digests_v1(&manifest.shards.entries) {
        return Err(QueryContractErrorV1::CatalogDigestMismatch);
    }
    Ok(())
}

pub fn validate_lexical_shard_v1(
    shard: &LexicalShardV1,
    budgets: &QueryResourceBudgetsV1,
) -> Result<(), QueryContractErrorV1> {
    if shard.schema_version != LEXICAL_SHARD_SCHEMA_V1 {
        return Err(QueryContractErrorV1::UnsupportedSchema);
    }
    validate_tokenizer(&shard.tokenizer_id, &shard.unicode_version)?;
    if shard.shard_id.is_empty()
        || !is_sha256(&shard.fst_sha256)
        || !is_sha256(&shard.raw_bytes_sha256)
        || serde_json::to_vec(shard)
            .map_or(true, |bytes| bytes.len() as u64 > budgets.max_shard_bytes)
    {
        return Err(QueryContractErrorV1::InvalidIdentity);
    }
    if shard.normalized_terms.is_empty()
        || !strictly_sorted_by(&shard.normalized_terms, |left, right| {
            left.normalized < right.normalized
        })
        || !strictly_sorted(&shard.trigrams)
        || !strictly_sorted(&shard.postings)
        || !strictly_sorted(&shard.evidence_refs)
    {
        return Err(QueryContractErrorV1::InvalidExactSet);
    }

    let mut expected_trigrams = BTreeSet::new();
    let mut terms = BTreeSet::new();
    for term in &shard.normalized_terms {
        if term.normalized.is_empty()
            || term.normalized.chars().count() as u64 > budgets.max_term_scalars
            || term.normalized.nfc().collect::<String>() != term.normalized
            || term.original_forms.is_empty()
            || !strictly_sorted(&term.original_forms)
        {
            return Err(QueryContractErrorV1::NormalizationMismatch);
        }
        for original in &term.original_forms {
            let tokens = tokenize_query_v1(original).tokens;
            if tokens.len() != 1 || tokens[0].normalized != term.normalized {
                return Err(QueryContractErrorV1::NormalizationMismatch);
            }
        }
        let expected_status = if term.original_forms.len() == 1 {
            NormalizationCollisionStatusV1::Unique
        } else {
            NormalizationCollisionStatusV1::Ambiguous
        };
        if term.collision_status != expected_status {
            return Err(QueryContractErrorV1::CollisionStatusMismatch);
        }
        terms.insert(term.normalized.as_str());
        expected_trigrams.extend(scalar_trigrams(&term.normalized));
    }
    if shard.trigrams.iter().cloned().collect::<BTreeSet<_>>() != expected_trigrams {
        return Err(QueryContractErrorV1::TrigramMismatch);
    }

    let evidence = shard
        .evidence_refs
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let mut posting_counts = BTreeMap::<&str, u64>::new();
    for posting in &shard.postings {
        if !terms.contains(posting.normalized_term.as_str())
            || posting.node_id.is_empty()
            || !evidence.contains(posting.evidence_ref.as_str())
            || posting.positions.is_empty()
            || !strictly_sorted(&posting.positions)
        {
            return Err(QueryContractErrorV1::InvalidPosting);
        }
        *posting_counts.entry(&posting.normalized_term).or_default() += 1;
    }
    if posting_counts
        .values()
        .any(|count| *count > budgets.max_postings_per_term)
    {
        return Err(QueryContractErrorV1::ResourceBudgetExceeded);
    }
    Ok(())
}

pub fn validate_adjacency_shard_v1(
    shard: &AdjacencyShardV1,
    budgets: &QueryResourceBudgetsV1,
) -> Result<(), QueryContractErrorV1> {
    if shard.schema_version != ADJACENCY_SHARD_SCHEMA_V1 {
        return Err(QueryContractErrorV1::UnsupportedSchema);
    }
    if shard.shard_id.is_empty()
        || shard.node_bucket.is_empty()
        || !is_sha256(&shard.raw_bytes_sha256)
    {
        return Err(QueryContractErrorV1::InvalidIdentity);
    }
    if shard.edge_ids.is_empty()
        || shard.edge_ids.len() != shard.resolution_states.len()
        || !strictly_sorted(&shard.edge_ids)
    {
        return Err(QueryContractErrorV1::InvalidAdjacency);
    }
    if shard.edge_ids.len() as u64 > budgets.max_records_per_shard
        || serde_json::to_vec(shard)
            .map_or(true, |bytes| bytes.len() as u64 > budgets.max_shard_bytes)
    {
        return Err(QueryContractErrorV1::ResourceBudgetExceeded);
    }
    Ok(())
}

pub fn validate_query_plan_receipt_v1(
    receipt: &QueryPlanReceiptV1,
    manifest: &QueryIndexManifestV1,
) -> Result<(), QueryContractErrorV1> {
    validate_query_index_manifest_v1(manifest)?;
    if receipt.schema_version != QUERY_PLAN_RECEIPT_SCHEMA_V1 {
        return Err(QueryContractErrorV1::UnsupportedSchema);
    }
    if !is_sha256(&receipt.query_sha256) || !is_sha256(&receipt.index_manifest_sha256) {
        return Err(QueryContractErrorV1::InvalidIdentity);
    }
    if receipt.index_manifest_sha256 != query_index_manifest_sha256_v1(manifest) {
        return Err(QueryContractErrorV1::ManifestIdentityMismatch);
    }
    if receipt.budget != QueryPlanBudgetV1::from(manifest.budgets) {
        return Err(QueryContractErrorV1::FrozenBudgetMismatch);
    }
    if !sorted_unique(&receipt.selected_shards) || !sorted_unique(&receipt.excluded_shards) {
        return Err(QueryContractErrorV1::InvalidExactSet);
    }
    let selected = receipt
        .selected_shards
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let excluded = receipt
        .excluded_shards
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let all = manifest
        .shards
        .entries
        .iter()
        .map(|entry| entry.shard_id.clone())
        .collect::<BTreeSet<_>>();
    if !selected.is_disjoint(&excluded)
        || selected.union(&excluded).cloned().collect::<BTreeSet<_>>() != all
    {
        return Err(QueryContractErrorV1::PlanShardPartitionMismatch);
    }
    if receipt.selected_shards.len() as u64 > receipt.budget.max_selected_shards
        || receipt.bytes_read > receipt.budget.max_bytes_read
        || receipt.budget.max_response_bytes == 0
    {
        return Err(QueryContractErrorV1::PlanBudgetExceeded);
    }
    match (receipt.truncation, receipt.continuation.as_deref()) {
        (QueryTruncationStateV1::Truncated, None | Some("")) => {
            Err(QueryContractErrorV1::ContinuationRequired)
        }
        (QueryTruncationStateV1::NotTruncated, Some(_)) => {
            Err(QueryContractErrorV1::UnexpectedContinuation)
        }
        _ => Ok(()),
    }
}

pub fn query_index_manifest_sha256_v1(manifest: &QueryIndexManifestV1) -> String {
    json_sha256(manifest)
}

pub fn validate_query_index_manifest_json_v1(
    value: &Value,
) -> Result<QueryIndexManifestV1, QueryContractErrorV1> {
    let manifest = decode(value, QUERY_INDEX_MANIFEST_SCHEMA_V1)?;
    validate_query_index_manifest_v1(&manifest)?;
    Ok(manifest)
}

pub fn validate_lexical_shard_json_v1(
    value: &Value,
    budgets: &QueryResourceBudgetsV1,
) -> Result<LexicalShardV1, QueryContractErrorV1> {
    let shard = decode(value, LEXICAL_SHARD_SCHEMA_V1)?;
    validate_lexical_shard_v1(&shard, budgets)?;
    Ok(shard)
}

pub fn validate_adjacency_shard_json_v1(
    value: &Value,
    budgets: &QueryResourceBudgetsV1,
) -> Result<AdjacencyShardV1, QueryContractErrorV1> {
    let shard = decode(value, ADJACENCY_SHARD_SCHEMA_V1)?;
    validate_adjacency_shard_v1(&shard, budgets)?;
    Ok(shard)
}

pub fn validate_query_plan_receipt_json_v1(
    value: &Value,
    manifest: &QueryIndexManifestV1,
) -> Result<QueryPlanReceiptV1, QueryContractErrorV1> {
    let receipt = decode(value, QUERY_PLAN_RECEIPT_SCHEMA_V1)?;
    validate_query_plan_receipt_v1(&receipt, manifest)?;
    Ok(receipt)
}

fn decode<T: DeserializeOwned>(
    value: &Value,
    schema_id: &'static str,
) -> Result<T, QueryContractErrorV1> {
    serde_json::from_value(value.clone()).map_err(|error| QueryContractErrorV1::SchemaDecode {
        schema_id,
        message: error.to_string(),
    })
}

fn validate_tokenizer(id: &str, unicode_version: &str) -> Result<(), QueryContractErrorV1> {
    if id != QUERY_TOKENIZER_ID_V1
        || unicode_version != QUERY_UNICODE_VERSION_V1
        || UNICODE_VERSION != (17, 0, 0)
    {
        return Err(QueryContractErrorV1::TokenizerIdentityMismatch);
    }
    Ok(())
}

fn json_sha256<T: serde::Serialize>(value: &T) -> String {
    let bytes = serde_json::to_vec(value).expect("serializing protocol values is infallible");
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn strictly_sorted<T: Ord>(values: &[T]) -> bool {
    !values.is_empty() && values.windows(2).all(|pair| pair[0] < pair[1])
}

fn sorted_unique<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn strictly_sorted_by<T>(values: &[T], less: impl Fn(&T, &T) -> bool) -> bool {
    !values.is_empty() && values.windows(2).all(|pair| less(&pair[0], &pair[1]))
}
