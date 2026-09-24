//! V0.2 T07 local-only ContextPack selection.
//!
//! The closed tokenizer below is a deterministic local approximation for
//! budget enforcement. It is not a provider tokenizer and never claims
//! provider token accuracy. Every selected chunk is bound to a source snapshot,
//! exact source bytes, and an evidence span before it can enter a pack.

use std::collections::BTreeSet;

use gtkg_protocol::{canonical_json_sha256, validate_sha256};
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

const CONTEXT_PACK_SCHEMA: &str = "gtkg.context-pack/v2";
pub const LOCAL_TOKENIZER_ID_V2: &str = "gtkg.local.utf8-word/v1";
/// SHA-256 of the fixed local tokenizer implementation descriptor:
/// `gtkg.local.utf8-word/v1` plus its documented segmentation rules.
pub const LOCAL_TOKENIZER_IMPLEMENTATION_SHA256_V2: &str =
    "sha256:5bf3e4d18438e4da46bb3c752ea89400ecb47d4fd2b9a67300e1b2e54bbe45d3";
const TOKEN_ESTIMATION_DISCLAIMER: &str = "local_deterministic_estimate_not_provider_accurate";
const LOCAL_TOKENIZER_DESCRIPTOR_V2: &str =
    "gtkg.local.utf8-word/v1\nunicode-alphanumeric-underscore-runs\nnon-whitespace-delimiters\n";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LocalTokenizerV2 {
    pub id: String,
    pub implementation_sha256: String,
}

impl LocalTokenizerV2 {
    pub fn controlled_local() -> Self {
        Self {
            id: LOCAL_TOKENIZER_ID_V2.to_owned(),
            implementation_sha256: LOCAL_TOKENIZER_IMPLEMENTATION_SHA256_V2.to_owned(),
        }
    }
}

/// Recompute the identity from the canonical descriptor at runtime. A source
/// edit to segmentation rules therefore fails closed until the pinned identity
/// is deliberately renewed and independently reviewed.
pub fn local_tokenizer_implementation_sha256_v2() -> String {
    sha256(LOCAL_TOKENIZER_DESCRIPTOR_V2.as_bytes())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ContextSourceV2 {
    pub source_snapshot_exact_set_sha256: String,
    pub source_logical_path: String,
    pub source_sha256: String,
    pub source: String,
}

impl ContextSourceV2 {
    pub fn new(
        source_snapshot_exact_set_sha256: impl Into<String>,
        source_logical_path: impl Into<String>,
        source: impl Into<String>,
    ) -> Self {
        let source = source.into();
        Self {
            source_snapshot_exact_set_sha256: source_snapshot_exact_set_sha256.into(),
            source_logical_path: source_logical_path.into(),
            source_sha256: sha256(source.as_bytes()),
            source,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ContextEvidenceRefV2 {
    pub evidence_id: String,
    pub source_snapshot_exact_set_sha256: String,
    pub source_sha256: String,
    pub byte_start: u64,
    pub byte_end: u64,
    pub snippet_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ContextChunkV2 {
    pub chunk_id: String,
    pub lane: String,
    pub graph_distance: u32,
    pub source_snapshot_exact_set_sha256: String,
    pub source_logical_path: String,
    pub source_sha256: String,
    pub evidence: ContextEvidenceRefV2,
    pub content_sha256: String,
    pub content: String,
}

impl ContextChunkV2 {
    pub fn new(
        chunk_id: impl Into<String>,
        lane: impl Into<String>,
        graph_distance: u32,
        source: &ContextSourceV2,
        byte_start: u64,
        byte_end: u64,
        evidence_id: impl Into<String>,
    ) -> Result<Self, ContextPackErrorV2> {
        let start = usize::try_from(byte_start)
            .map_err(|_| ContextPackErrorV2::EvidenceInvalid("byte_start".to_owned()))?;
        let end = usize::try_from(byte_end)
            .map_err(|_| ContextPackErrorV2::EvidenceInvalid("byte_end".to_owned()))?;
        let content = source
            .source
            .get(start..end)
            .ok_or_else(|| ContextPackErrorV2::EvidenceInvalid("source span".to_owned()))?
            .to_owned();
        if content.is_empty() {
            return Err(ContextPackErrorV2::EvidenceInvalid(
                "source span is empty".to_owned(),
            ));
        }
        Ok(Self {
            chunk_id: chunk_id.into(),
            lane: lane.into(),
            graph_distance,
            source_snapshot_exact_set_sha256: source.source_snapshot_exact_set_sha256.clone(),
            source_logical_path: source.source_logical_path.clone(),
            source_sha256: source.source_sha256.clone(),
            evidence: ContextEvidenceRefV2 {
                evidence_id: evidence_id.into(),
                source_snapshot_exact_set_sha256: source.source_snapshot_exact_set_sha256.clone(),
                source_sha256: source.source_sha256.clone(),
                byte_start,
                byte_end,
                snippet_sha256: sha256(content.as_bytes()),
            },
            content_sha256: sha256(content.as_bytes()),
            content,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextPackRequestV2 {
    pub source_snapshot_exact_set_sha256: String,
    pub tokenizer: LocalTokenizerV2,
    pub token_budget: u64,
    pub required_chunk_ids: Vec<String>,
    pub sources: Vec<ContextSourceV2>,
    pub chunks: Vec<ContextChunkV2>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ContextSelectionReceiptV2 {
    pub chunk_id: String,
    pub lane: String,
    pub graph_distance: u32,
    pub source_snapshot_exact_set_sha256: String,
    pub source_logical_path: String,
    pub source_sha256: String,
    pub evidence: ContextEvidenceRefV2,
    /// Stable immutable ref derived from snapshot, source, evidence span and bytes digest.
    pub immutable_content_ref: String,
    pub content_sha256: String,
    pub token_count: u64,
    pub selection_reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ContextExclusionReceiptV2 {
    pub chunk_id: String,
    pub lane: String,
    pub graph_distance: u32,
    pub source_snapshot_exact_set_sha256: String,
    pub source_logical_path: String,
    pub source_sha256: String,
    pub evidence: ContextEvidenceRefV2,
    pub immutable_content_ref: String,
    pub content_sha256: String,
    pub token_count: u64,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ContextPackV2 {
    pub schema_version: String,
    pub source_snapshot_exact_set_sha256: String,
    pub tokenizer: LocalTokenizerV2,
    pub token_estimation: String,
    pub token_budget: u64,
    pub selected_token_count: u64,
    pub selected: Vec<ContextSelectionReceiptV2>,
    pub excluded: Vec<ContextExclusionReceiptV2>,
    pub context_pack_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextSelectedBytesV2 {
    chunk_id: String,
    immutable_content_ref: String,
    content_sha256: String,
    content: String,
    /// Capability minted only by `ContextPackV2::read_selected_bytes` after
    /// it has replayed the exact T07 request and receipt. Its fields stay
    /// crate-private so another crate cannot hand-craft format-valid refs.
    capability: ContextSelectedCapabilityV2,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ContextSelectedCapabilityV2 {
    read_boundary: &'static str,
    source_snapshot_exact_set_sha256: String,
    context_pack_sha256: String,
    selected_context_sha256: String,
}

/// The sealed T07 provenance available to in-crate consumers such as T09.
/// It deliberately has no public constructor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ContextSelectedBindingV2 {
    pub source_snapshot_exact_set_sha256: String,
    pub context_pack_sha256: String,
    pub selected_context_sha256: String,
}

impl ContextSelectedBytesV2 {
    pub fn chunk_id(&self) -> &str {
        &self.chunk_id
    }

    pub fn immutable_content_ref(&self) -> &str {
        &self.immutable_content_ref
    }

    pub fn content_sha256(&self) -> &str {
        &self.content_sha256
    }

    pub fn content(&self) -> &str {
        &self.content
    }
}

/// Validate a sealed batch minted by T07 and return its exact binding. This
/// is `pub(crate)` on purpose: external consumers can pass the opaque values
/// to the T09 bridge but cannot mint or reinterpret the capability.
pub(crate) fn selected_binding_v2(
    selected: &[ContextSelectedBytesV2],
) -> Result<ContextSelectedBindingV2, ContextPackErrorV2> {
    let Some(first) = selected.first() else {
        return Err(ContextPackErrorV2::ReceiptMismatch);
    };
    if first.capability.read_boundary != "gtkg.context-pack/v2:selected-read" {
        return Err(ContextPackErrorV2::ReceiptMismatch);
    }
    let expected = ContextSelectedBindingV2 {
        source_snapshot_exact_set_sha256: first.capability.source_snapshot_exact_set_sha256.clone(),
        context_pack_sha256: first.capability.context_pack_sha256.clone(),
        selected_context_sha256: first.capability.selected_context_sha256.clone(),
    };
    if !valid_sha256(&expected.source_snapshot_exact_set_sha256)
        || !valid_sha256(&expected.context_pack_sha256)
        || !valid_sha256(&expected.selected_context_sha256)
    {
        return Err(ContextPackErrorV2::ReceiptMismatch);
    }
    for item in selected {
        if item.capability.read_boundary != "gtkg.context-pack/v2:selected-read"
            || item.capability.source_snapshot_exact_set_sha256
                != expected.source_snapshot_exact_set_sha256
            || item.capability.context_pack_sha256 != expected.context_pack_sha256
            || item.capability.selected_context_sha256 != expected.selected_context_sha256
            || !valid_context_selected_item(item)
        {
            return Err(ContextPackErrorV2::ReceiptMismatch);
        }
    }
    if canonical_selected_context_digest(selected)? != expected.selected_context_sha256 {
        return Err(ContextPackErrorV2::ReceiptMismatch);
    }
    Ok(expected)
}

impl ContextPackV2 {
    /// Validate an already materialized receipt, including the self digest.
    pub fn validate(&self) -> Result<(), ContextPackErrorV2> {
        if self.schema_version != CONTEXT_PACK_SCHEMA
            || self.token_estimation != TOKEN_ESTIMATION_DISCLAIMER
            || self.token_budget == 0
            || self.selected_token_count > self.token_budget
        {
            return Err(ContextPackErrorV2::InvalidRequest(
                "invalid ContextPack receipt header".to_owned(),
            ));
        }
        validate_tokenizer(&self.tokenizer)?;
        if !valid_sha256(&self.source_snapshot_exact_set_sha256) {
            return Err(ContextPackErrorV2::SourceBindingMismatch);
        }
        let mut chunk_ids = BTreeSet::new();
        let mut selected_tokens = 0_u64;
        for item in &self.selected {
            selected_tokens = selected_tokens
                .checked_add(item.token_count)
                .ok_or(ContextPackErrorV2::TokenBudgetExceeded)?;
            validate_receipt_item(item, &self.source_snapshot_exact_set_sha256, &mut chunk_ids)?;
        }
        for item in &self.excluded {
            validate_receipt_item(item, &self.source_snapshot_exact_set_sha256, &mut chunk_ids)?;
            if item.reason != "budget_exceeded" {
                return Err(ContextPackErrorV2::InvalidRequest(
                    "unrecognized exclusion reason".to_owned(),
                ));
            }
        }
        if selected_tokens != self.selected_token_count {
            return Err(ContextPackErrorV2::ReceiptMismatch);
        }
        if canonical_context_pack_digest(self)? != self.context_pack_sha256 {
            return Err(ContextPackErrorV2::PackDigestMismatch);
        }
        Ok(())
    }

    /// Rebuild against immutable input to detect missing selection/exclusion
    /// entries as well as receipt mutation.
    pub fn validate_against_request(
        &self,
        request: &ContextPackRequestV2,
    ) -> Result<(), ContextPackErrorV2> {
        self.validate()?;
        if &build_context_pack_v2(request)? != self {
            return Err(ContextPackErrorV2::ReceiptMismatch);
        }
        Ok(())
    }

    /// The only T07 read boundary for downstream local consumers (including
    /// T09). It first replays the exact request and receipt, then returns only
    /// selected content bytes whose immutable locator and digest still match.
    pub fn read_selected_bytes(
        &self,
        request: &ContextPackRequestV2,
    ) -> Result<Vec<ContextSelectedBytesV2>, ContextPackErrorV2> {
        self.validate_against_request(request)?;
        let mut selected = self
            .selected
            .iter()
            .map(|selection| {
                let chunk = request
                    .chunks
                    .iter()
                    .find(|chunk| chunk.chunk_id == selection.chunk_id)
                    .ok_or(ContextPackErrorV2::ReceiptMismatch)?;
                if chunk.content_sha256 != selection.content_sha256
                    || immutable_content_ref(
                        &chunk.source_snapshot_exact_set_sha256,
                        &chunk.source_sha256,
                        &chunk.evidence,
                        &chunk.content_sha256,
                    ) != selection.immutable_content_ref
                {
                    return Err(ContextPackErrorV2::ReceiptMismatch);
                }
                Ok(ContextSelectedBytesV2 {
                    chunk_id: chunk.chunk_id.clone(),
                    immutable_content_ref: selection.immutable_content_ref.clone(),
                    content_sha256: chunk.content_sha256.clone(),
                    content: chunk.content.clone(),
                    capability: ContextSelectedCapabilityV2 {
                        read_boundary: "gtkg.context-pack/v2:selected-read",
                        source_snapshot_exact_set_sha256: self
                            .source_snapshot_exact_set_sha256
                            .clone(),
                        context_pack_sha256: self.context_pack_sha256.clone(),
                        selected_context_sha256: String::new(),
                    },
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let selected_context_sha256 = canonical_selected_context_digest(&selected)?;
        for item in &mut selected {
            item.capability.selected_context_sha256 = selected_context_sha256.clone();
        }
        selected_binding_v2(&selected)?;
        Ok(selected)
    }

    /// Rebuild the receipt digest for validators and adversarial tests. This
    /// does not authorize consumption; consumers must use `read_selected_bytes`.
    pub fn recompute_digest(&self) -> Result<String, ContextPackErrorV2> {
        canonical_context_pack_digest(self)
    }
}

trait ReceiptItem {
    fn chunk_id(&self) -> &str;
    fn source_snapshot(&self) -> &str;
    fn source_path(&self) -> &str;
    fn source_sha(&self) -> &str;
    fn evidence(&self) -> &ContextEvidenceRefV2;
    fn content_ref(&self) -> &str;
    fn content_sha(&self) -> &str;
}

impl ReceiptItem for ContextSelectionReceiptV2 {
    fn chunk_id(&self) -> &str {
        &self.chunk_id
    }
    fn source_snapshot(&self) -> &str {
        &self.source_snapshot_exact_set_sha256
    }
    fn source_path(&self) -> &str {
        &self.source_logical_path
    }
    fn source_sha(&self) -> &str {
        &self.source_sha256
    }
    fn evidence(&self) -> &ContextEvidenceRefV2 {
        &self.evidence
    }
    fn content_ref(&self) -> &str {
        &self.immutable_content_ref
    }
    fn content_sha(&self) -> &str {
        &self.content_sha256
    }
}

impl ReceiptItem for ContextExclusionReceiptV2 {
    fn chunk_id(&self) -> &str {
        &self.chunk_id
    }
    fn source_snapshot(&self) -> &str {
        &self.source_snapshot_exact_set_sha256
    }
    fn source_path(&self) -> &str {
        &self.source_logical_path
    }
    fn source_sha(&self) -> &str {
        &self.source_sha256
    }
    fn evidence(&self) -> &ContextEvidenceRefV2 {
        &self.evidence
    }
    fn content_ref(&self) -> &str {
        &self.immutable_content_ref
    }
    fn content_sha(&self) -> &str {
        &self.content_sha256
    }
}

fn validate_receipt_item(
    item: &impl ReceiptItem,
    expected_snapshot: &str,
    chunk_ids: &mut BTreeSet<String>,
) -> Result<(), ContextPackErrorV2> {
    if item.chunk_id().is_empty()
        || item.source_path().is_empty()
        || !chunk_ids.insert(item.chunk_id().to_owned())
        || item.evidence().evidence_id.is_empty()
        || item.source_snapshot() != expected_snapshot
        || item.source_snapshot() != item.evidence().source_snapshot_exact_set_sha256
        || item.source_sha() != item.evidence().source_sha256
        || !valid_sha256(item.source_snapshot())
        || !valid_sha256(item.source_sha())
        || !valid_sha256(&item.evidence().snippet_sha256)
        || !valid_sha256(item.content_sha())
        || item.evidence().byte_start >= item.evidence().byte_end
        || item.content_ref()
            != immutable_content_ref(
                item.source_snapshot(),
                item.source_sha(),
                item.evidence(),
                item.content_sha(),
            )
    {
        return Err(ContextPackErrorV2::ReceiptMismatch);
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextPackErrorCodeV2 {
    InvalidRequest,
    TokenizerUnsupported,
    TokenizerIdentityInvalid,
    SourceBindingMismatch,
    EvidenceInvalid,
    ChunkDigestMismatch,
    TokenBudgetExceeded,
    PackDigestMismatch,
    ReceiptMismatch,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ContextPackErrorV2 {
    #[error("invalid ContextPack request: {0}")]
    InvalidRequest(String),
    #[error("ContextPack only supports the closed local tokenizer")]
    TokenizerUnsupported,
    #[error("local tokenizer identity differs from the controlled implementation")]
    TokenizerIdentityInvalid,
    #[error("source snapshot or source bytes are not bound exactly")]
    SourceBindingMismatch,
    #[error("chunk evidence is invalid: {0}")]
    EvidenceInvalid(String),
    #[error("chunk content no longer matches its declared digest: {0}")]
    ChunkDigestMismatch(String),
    #[error("required ContextPack content exceeds the token budget")]
    TokenBudgetExceeded,
    #[error("ContextPack canonical digest does not match its receipt")]
    PackDigestMismatch,
    #[error("ContextPack receipt does not exactly match its immutable request")]
    ReceiptMismatch,
}

impl ContextPackErrorV2 {
    pub const fn code(&self) -> ContextPackErrorCodeV2 {
        match self {
            Self::InvalidRequest(_) => ContextPackErrorCodeV2::InvalidRequest,
            Self::TokenizerUnsupported => ContextPackErrorCodeV2::TokenizerUnsupported,
            Self::TokenizerIdentityInvalid => ContextPackErrorCodeV2::TokenizerIdentityInvalid,
            Self::SourceBindingMismatch => ContextPackErrorCodeV2::SourceBindingMismatch,
            Self::EvidenceInvalid(_) => ContextPackErrorCodeV2::EvidenceInvalid,
            Self::ChunkDigestMismatch(_) => ContextPackErrorCodeV2::ChunkDigestMismatch,
            Self::TokenBudgetExceeded => ContextPackErrorCodeV2::TokenBudgetExceeded,
            Self::PackDigestMismatch => ContextPackErrorCodeV2::PackDigestMismatch,
            Self::ReceiptMismatch => ContextPackErrorCodeV2::ReceiptMismatch,
        }
    }
}

/// Build one local ContextPack. Candidates are sorted independent of caller
/// order: required chunks first, then lane priority (`focus`, `direct`,
/// `neighbor`, `evidence`, other), graph distance, logical path and chunk id.
/// Required content never truncates: when it cannot fit, this returns
/// [`ContextPackErrorV2::TokenBudgetExceeded`] and creates no pack.
pub fn build_context_pack_v2(
    request: &ContextPackRequestV2,
) -> Result<ContextPackV2, ContextPackErrorV2> {
    validate_request(request)?;
    let required = request
        .required_chunk_ids
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut candidates = request.chunks.iter().collect::<Vec<_>>();
    candidates.sort_by(|left, right| {
        candidate_key(left, required.contains(&left.chunk_id))
            .cmp(&candidate_key(right, required.contains(&right.chunk_id)))
    });

    let mut selected = Vec::new();
    let mut excluded = Vec::new();
    let mut selected_token_count = 0_u64;
    for chunk in candidates {
        let token_count = local_token_count(&chunk.content);
        let is_required = required.contains(&chunk.chunk_id);
        let fits = selected_token_count
            .checked_add(token_count)
            .is_some_and(|next| next <= request.token_budget);
        if is_required && !fits {
            return Err(ContextPackErrorV2::TokenBudgetExceeded);
        }
        let immutable_content_ref = immutable_content_ref(
            &chunk.source_snapshot_exact_set_sha256,
            &chunk.source_sha256,
            &chunk.evidence,
            &chunk.content_sha256,
        );
        if fits {
            selected_token_count += token_count;
            selected.push(ContextSelectionReceiptV2 {
                chunk_id: chunk.chunk_id.clone(),
                lane: chunk.lane.clone(),
                graph_distance: chunk.graph_distance,
                source_snapshot_exact_set_sha256: chunk.source_snapshot_exact_set_sha256.clone(),
                source_logical_path: chunk.source_logical_path.clone(),
                source_sha256: chunk.source_sha256.clone(),
                evidence: chunk.evidence.clone(),
                immutable_content_ref,
                content_sha256: chunk.content_sha256.clone(),
                token_count,
                selection_reason: if is_required {
                    "required"
                } else {
                    "ranked_within_budget"
                }
                .to_owned(),
            });
        } else {
            excluded.push(ContextExclusionReceiptV2 {
                chunk_id: chunk.chunk_id.clone(),
                lane: chunk.lane.clone(),
                graph_distance: chunk.graph_distance,
                source_snapshot_exact_set_sha256: chunk.source_snapshot_exact_set_sha256.clone(),
                source_logical_path: chunk.source_logical_path.clone(),
                source_sha256: chunk.source_sha256.clone(),
                evidence: chunk.evidence.clone(),
                immutable_content_ref,
                content_sha256: chunk.content_sha256.clone(),
                token_count,
                reason: "budget_exceeded".to_owned(),
            });
        }
    }
    let mut pack = ContextPackV2 {
        schema_version: CONTEXT_PACK_SCHEMA.to_owned(),
        source_snapshot_exact_set_sha256: request.source_snapshot_exact_set_sha256.clone(),
        tokenizer: request.tokenizer.clone(),
        token_estimation: TOKEN_ESTIMATION_DISCLAIMER.to_owned(),
        token_budget: request.token_budget,
        selected_token_count,
        selected,
        excluded,
        context_pack_sha256: String::new(),
    };
    pack.context_pack_sha256 = canonical_context_pack_digest(&pack)?;
    Ok(pack)
}

fn validate_request(request: &ContextPackRequestV2) -> Result<(), ContextPackErrorV2> {
    if request.token_budget == 0 || request.chunks.is_empty() {
        return Err(ContextPackErrorV2::InvalidRequest(
            "token_budget and candidate chunks must be non-empty".to_owned(),
        ));
    }
    validate_tokenizer(&request.tokenizer)?;
    if !valid_sha256(&request.source_snapshot_exact_set_sha256) {
        return Err(ContextPackErrorV2::SourceBindingMismatch);
    }
    let mut source_paths = BTreeSet::new();
    for source in &request.sources {
        if source.source_logical_path.is_empty()
            || !source_paths.insert(source.source_logical_path.as_str())
            || source.source_snapshot_exact_set_sha256 != request.source_snapshot_exact_set_sha256
            || !valid_sha256(&source.source_sha256)
            || source.source_sha256 != sha256(source.source.as_bytes())
        {
            return Err(ContextPackErrorV2::SourceBindingMismatch);
        }
    }
    let mut ids = BTreeSet::new();
    for chunk in &request.chunks {
        if chunk.chunk_id.is_empty()
            || chunk.lane.is_empty()
            || chunk.source_logical_path.is_empty()
            || chunk.content.is_empty()
            || !ids.insert(chunk.chunk_id.as_str())
        {
            return Err(ContextPackErrorV2::InvalidRequest(
                "chunks need non-empty, unique IDs and source content".to_owned(),
            ));
        }
        let source = request
            .sources
            .iter()
            .find(|source| source.source_logical_path == chunk.source_logical_path)
            .ok_or(ContextPackErrorV2::SourceBindingMismatch)?;
        validate_chunk_binding(request, source, chunk)?;
    }
    let mut required_ids = BTreeSet::new();
    for id in &request.required_chunk_ids {
        if id.is_empty() || !required_ids.insert(id.as_str()) || !ids.contains(id.as_str()) {
            return Err(ContextPackErrorV2::InvalidRequest(
                "required_chunk_ids must be unique admitted chunk IDs".to_owned(),
            ));
        }
    }
    Ok(())
}

fn validate_tokenizer(tokenizer: &LocalTokenizerV2) -> Result<(), ContextPackErrorV2> {
    if tokenizer.id != LOCAL_TOKENIZER_ID_V2 {
        return Err(ContextPackErrorV2::TokenizerUnsupported);
    }
    let runtime_identity = local_tokenizer_implementation_sha256_v2();
    if runtime_identity != LOCAL_TOKENIZER_IMPLEMENTATION_SHA256_V2
        || tokenizer.implementation_sha256 != runtime_identity
    {
        return Err(ContextPackErrorV2::TokenizerIdentityInvalid);
    }
    Ok(())
}

fn validate_chunk_binding(
    request: &ContextPackRequestV2,
    source: &ContextSourceV2,
    chunk: &ContextChunkV2,
) -> Result<(), ContextPackErrorV2> {
    if chunk.source_snapshot_exact_set_sha256 != request.source_snapshot_exact_set_sha256
        || chunk.source_snapshot_exact_set_sha256 != source.source_snapshot_exact_set_sha256
        || chunk.source_sha256 != source.source_sha256
        || chunk.evidence.source_snapshot_exact_set_sha256
            != request.source_snapshot_exact_set_sha256
        || chunk.evidence.source_sha256 != source.source_sha256
        || chunk.evidence.evidence_id.is_empty()
    {
        return Err(ContextPackErrorV2::SourceBindingMismatch);
    }
    let start = usize::try_from(chunk.evidence.byte_start)
        .map_err(|_| ContextPackErrorV2::EvidenceInvalid("byte_start".to_owned()))?;
    let end = usize::try_from(chunk.evidence.byte_end)
        .map_err(|_| ContextPackErrorV2::EvidenceInvalid("byte_end".to_owned()))?;
    let evidence = source
        .source
        .get(start..end)
        .ok_or_else(|| ContextPackErrorV2::EvidenceInvalid("source span".to_owned()))?;
    if evidence.is_empty()
        || chunk.content != evidence
        || chunk.content_sha256 != sha256(chunk.content.as_bytes())
        || chunk.evidence.snippet_sha256 != sha256(evidence.as_bytes())
    {
        return Err(ContextPackErrorV2::ChunkDigestMismatch(
            chunk.chunk_id.clone(),
        ));
    }
    Ok(())
}

fn candidate_key(chunk: &ContextChunkV2, is_required: bool) -> (u8, u8, u32, &str, &str) {
    (
        if is_required { 0 } else { 1 },
        lane_priority(&chunk.lane),
        chunk.graph_distance,
        &chunk.source_logical_path,
        &chunk.chunk_id,
    )
}

fn lane_priority(lane: &str) -> u8 {
    match lane {
        "focus" => 0,
        "direct" => 1,
        "neighbor" => 2,
        "evidence" => 3,
        _ => 4,
    }
}

/// Counts contiguous Unicode alphanumeric/underscore runs and each
/// non-whitespace delimiter; it is deliberately not a provider tokenizer.
fn local_token_count(content: &str) -> u64 {
    let mut count = 0_u64;
    let mut in_word = false;
    for character in content.chars() {
        if character.is_alphanumeric() || character == '_' {
            if !in_word {
                count += 1;
                in_word = true;
            }
        } else {
            in_word = false;
            if !character.is_whitespace() {
                count += 1;
            }
        }
    }
    count
}

fn immutable_content_ref(
    snapshot_sha256: &str,
    source_sha256: &str,
    evidence: &ContextEvidenceRefV2,
    content_sha256: &str,
) -> String {
    format!(
        "context-content:v2:{snapshot_sha256}:{source_sha256}:{}:{}:{content_sha256}",
        evidence.byte_start, evidence.byte_end
    )
}

fn valid_sha256(value: &str) -> bool {
    validate_sha256(value).is_ok()
}

fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn valid_context_selected_item(item: &ContextSelectedBytesV2) -> bool {
    !item.chunk_id.is_empty()
        && !item.content.is_empty()
        && valid_sha256(&item.content_sha256)
        && item.content_sha256 == sha256(item.content.as_bytes())
        && item
            .immutable_content_ref
            .starts_with("context-content:v2:")
}

fn canonical_selected_context_digest(
    selected: &[ContextSelectedBytesV2],
) -> Result<String, ContextPackErrorV2> {
    #[derive(Serialize)]
    struct SelectedRef<'a> {
        chunk_id: &'a str,
        immutable_content_ref: &'a str,
        content_sha256: &'a str,
    }
    let refs = selected
        .iter()
        .map(|item| SelectedRef {
            chunk_id: &item.chunk_id,
            immutable_content_ref: &item.immutable_content_ref,
            content_sha256: &item.content_sha256,
        })
        .collect::<Vec<_>>();
    canonical_json_sha256(&refs)
        .map_err(|error| ContextPackErrorV2::InvalidRequest(error.to_string()))
}

fn canonical_context_pack_digest(pack: &ContextPackV2) -> Result<String, ContextPackErrorV2> {
    #[derive(Serialize)]
    struct DigestView<'a> {
        schema_version: &'a str,
        source_snapshot_exact_set_sha256: &'a str,
        tokenizer: &'a LocalTokenizerV2,
        token_estimation: &'a str,
        token_budget: u64,
        selected_token_count: u64,
        selected: &'a [ContextSelectionReceiptV2],
        excluded: &'a [ContextExclusionReceiptV2],
    }
    canonical_json_sha256(&DigestView {
        schema_version: &pack.schema_version,
        source_snapshot_exact_set_sha256: &pack.source_snapshot_exact_set_sha256,
        tokenizer: &pack.tokenizer,
        token_estimation: &pack.token_estimation,
        token_budget: pack.token_budget,
        selected_token_count: pack.selected_token_count,
        selected: &pack.selected,
        excluded: &pack.excluded,
    })
    .map_err(|error| ContextPackErrorV2::InvalidRequest(error.to_string()))
}
