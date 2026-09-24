//! V0.2 T10 local claim verification and explicit abstention.
//!
//! This boundary deliberately does not interpret an LLM response or invoke a
//! Provider.  It verifies a deliberately small claim language against T02
//! byte evidence that is also present in the sealed T07 selection bound by a
//! T09 job.  T03 and T04 receipts are mandatory provenance inputs, not an
//! external-evaluation shortcut.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use gtkg_protocol::v2::{EvidenceSpanV2, TypedIrV2};
use gtkg_protocol::{canonical_json_sha256, validate_sha256};
use serde::Serialize;
use thiserror::Error;

use crate::CallContext;
use crate::context_v2::{ContextSelectedBytesV2, selected_binding_v2};
use crate::corpus_v2::{LocalCorpusFreezeReceiptV2, load_local_corpus_manifest_v2};
use crate::document_relations::T03RelationBindingV2;
use crate::provider_v2::SummaryJobV2;

const RECEIPT_SCHEMA: &str = "gtkg.claim-verification-receipt/v2";
const ACCEPTED_SET_SCHEMA: &str = "gtkg.accepted-claim-set/v2";
const VERIFIER_ID: &str = "gtkg.local.atomic-claim-verifier/v2";
const VERIFIER_POLICY: &str = "exact_t02_evidence_in_t07_selected_context/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimPolarityV2 {
    Positive,
    Negative,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimModalityV2 {
    Asserted,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskClassV2 {
    Normal,
    High,
}

/// Each citation identifies one T02 byte span and the T07 chunk that must
/// contain the exact span.  Callers cannot replace citation coverage with a
/// bare link or a non-selected source fragment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ClaimEvidenceRefV2 {
    pub evidence_id: String,
    pub context_chunk_id: String,
    pub source_snapshot_exact_set_sha256: String,
    pub source_logical_path: String,
    pub source_sha256: String,
    pub byte_start: u64,
    pub byte_end: u64,
    pub snippet_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AtomicClaimV2 {
    pub claim_id: String,
    pub subject: String,
    pub predicate: String,
    pub object: String,
    pub polarity: ClaimPolarityV2,
    pub modality: ClaimModalityV2,
    pub natural_language: String,
    pub evidence: Vec<ClaimEvidenceRefV2>,
    pub risk_class: RiskClassV2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimVerificationStateV2 {
    Entailed,
    Unknown,
    Unsupported,
    Contradicted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AbstentionReasonV2 {
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AbstentionV2 {
    pub claim_id: String,
    pub target: String,
    pub reason: AbstentionReasonV2,
    pub candidate_evidence_ids: Vec<String>,
    pub retryable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ClaimVerificationRecordV2 {
    pub claim_id: String,
    pub state: ClaimVerificationStateV2,
    pub evidence_ids: Vec<String>,
    pub detail_code: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ClaimCoverageV2 {
    pub claim_count: u64,
    pub cited_claims: u64,
    pub covered_claims: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ClaimVerificationReceiptV2 {
    pub schema_version: String,
    pub verifier_id: String,
    pub verifier_policy: String,
    pub source_snapshot_exact_set_sha256: String,
    pub typed_ir_sha256: String,
    pub summary_job_sha256: String,
    pub t03_receipt_sha256: String,
    pub t04_manifest_sha256: String,
    /// Digest of the complete, ordered AtomicClaim proposal set.  Accepted
    /// claim identifiers alone are not sufficient for a later graph builder:
    /// without this binding a caller could keep an ID and replace its
    /// subject/predicate/object or citations after T10 has verified it.
    pub proposal_set_sha256: String,
    pub claims: Vec<ClaimVerificationRecordV2>,
    pub coverage: ClaimCoverageV2,
    pub receipt_sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimSetStateV2 {
    AcceptedGrounded,
    AcceptedPartialWithAbstention,
    NoSemanticClaim,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AcceptedClaimSetV2 {
    pub schema_version: String,
    pub source_snapshot_exact_set_sha256: String,
    pub verification_receipt_sha256: String,
    pub state: ClaimSetStateV2,
    pub accepted_claim_ids: Vec<String>,
    pub abstentions: Vec<AbstentionV2>,
    pub accepted_claim_set_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimVerificationOutputV2 {
    pub receipt: ClaimVerificationReceiptV2,
    pub accepted: AcceptedClaimSetV2,
}

/// Canonical identity of the complete proposal payload consumed by T10.
///
/// This is public because T11B must prove that its overlay is built from the
/// exact claims that T10 verified, rather than merely from reused claim IDs.
pub fn claim_proposal_set_digest(
    claims: &[AtomicClaimV2],
) -> Result<String, ClaimVerificationErrorV2> {
    if claims.is_empty() || !unique(claims.iter().map(|claim| claim.claim_id.as_str())) {
        return Err(ClaimVerificationErrorV2::InvalidProposalSet);
    }
    let mut canonical = claims.to_vec();
    canonical.sort_by(|left, right| left.claim_id.cmp(&right.claim_id));
    canonical_json_sha256(&canonical).map_err(|_| ClaimVerificationErrorV2::InvalidProposalSet)
}

/// Inputs are references only so the verifier cannot silently mint a T02,
/// T03, T04 or T09 evidence object.  Selected context remains the sealed T07
/// capability; all evidence must be covered by it before acceptance.
pub struct ClaimVerificationInputV2<'a> {
    pub source_bytes: &'a [u8],
    pub typed_ir: &'a TypedIrV2,
    pub selected_context: &'a [ContextSelectedBytesV2],
    pub summary_job: &'a SummaryJobV2,
    pub t03_evidence: &'a T03ClaimEvidenceV2,
    pub t04_evidence: &'a T04ClaimEvidenceV2,
}

/// A T03 receipt can enter claim verification only through the exact
/// `from_receipt` readback. Its inner binding is private so callers cannot
/// forge structurally plausible digest strings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct T03ClaimEvidenceV2 {
    binding: T03RelationBindingV2,
}

impl T03ClaimEvidenceV2 {
    pub fn from_receipt(
        workspace_root: &Path,
        raw_spec_pin: gtkg_protocol::v2::OkfSpecPinV2,
        corpus_manifest_path: &Path,
        receipt_path: &Path,
    ) -> Result<Self, ClaimVerificationErrorV2> {
        let binding = T03RelationBindingV2::from_receipt(
            workspace_root,
            raw_spec_pin,
            corpus_manifest_path,
            receipt_path,
        )
        .map_err(|_| ClaimVerificationErrorV2::T03BindingInvalid)?;
        Ok(Self { binding })
    }
}

/// A T04 receipt is loaded again through its restricted loader rather than
/// accepted as a caller-constructed manifest. This local verifier continues
/// to reject any receipt that counts as external evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct T04ClaimEvidenceV2 {
    receipt: LocalCorpusFreezeReceiptV2,
}

impl T04ClaimEvidenceV2 {
    pub fn load_local(
        context: &CallContext,
        manifest_path: &Path,
    ) -> Result<Self, ClaimVerificationErrorV2> {
        let receipt = load_local_corpus_manifest_v2(context, manifest_path)
            .map_err(|_| ClaimVerificationErrorV2::T04ReceiptInvalid)?;
        Ok(Self { receipt })
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ClaimVerificationErrorV2 {
    #[error("T02 typed IR is invalid: {0}")]
    TypedIr(String),
    #[error("T09 SummaryJob is invalid")]
    SummaryJobInvalid,
    #[error("T07 selected context is invalid")]
    SelectedContextInvalid,
    #[error("T02/T07/T09 snapshot bindings do not match")]
    SnapshotBindingMismatch,
    #[error("T03 binding is invalid")]
    T03BindingInvalid,
    #[error("T04 local corpus receipt is invalid")]
    T04ReceiptInvalid,
    #[error("claim proposal set is invalid")]
    InvalidProposalSet,
    #[error("claim receipt is invalid")]
    InvalidReceipt,
    #[error("accepted claim set is invalid")]
    InvalidAcceptedSet,
}

impl ClaimVerificationReceiptV2 {
    pub fn recompute_digest(&self) -> Result<String, ClaimVerificationErrorV2> {
        #[derive(Serialize)]
        struct DigestView<'a> {
            schema_version: &'a str,
            verifier_id: &'a str,
            verifier_policy: &'a str,
            source_snapshot_exact_set_sha256: &'a str,
            typed_ir_sha256: &'a str,
            summary_job_sha256: &'a str,
            t03_receipt_sha256: &'a str,
            t04_manifest_sha256: &'a str,
            proposal_set_sha256: &'a str,
            claims: &'a [ClaimVerificationRecordV2],
            coverage: &'a ClaimCoverageV2,
        }
        canonical_json_sha256(&DigestView {
            schema_version: &self.schema_version,
            verifier_id: &self.verifier_id,
            verifier_policy: &self.verifier_policy,
            source_snapshot_exact_set_sha256: &self.source_snapshot_exact_set_sha256,
            typed_ir_sha256: &self.typed_ir_sha256,
            summary_job_sha256: &self.summary_job_sha256,
            t03_receipt_sha256: &self.t03_receipt_sha256,
            t04_manifest_sha256: &self.t04_manifest_sha256,
            proposal_set_sha256: &self.proposal_set_sha256,
            claims: &self.claims,
            coverage: &self.coverage,
        })
        .map_err(|_| ClaimVerificationErrorV2::InvalidReceipt)
    }

    pub fn validate(&self) -> Result<(), ClaimVerificationErrorV2> {
        if self.schema_version != RECEIPT_SCHEMA
            || self.verifier_id != VERIFIER_ID
            || self.verifier_policy != VERIFIER_POLICY
            || !is_sha256(&self.source_snapshot_exact_set_sha256)
            || !is_sha256(&self.typed_ir_sha256)
            || !is_sha256(&self.summary_job_sha256)
            || !is_sha256(&self.t03_receipt_sha256)
            || !is_sha256(&self.t04_manifest_sha256)
            || !is_sha256(&self.proposal_set_sha256)
            || !is_sha256(&self.receipt_sha256)
            || self.receipt_sha256 != self.recompute_digest()?
            || self.coverage.claim_count != self.claims.len() as u64
            || self.coverage.cited_claims > self.coverage.claim_count
            || self.coverage.covered_claims > self.coverage.cited_claims
            || !sorted_unique(self.claims.iter().map(|record| record.claim_id.as_str()))
        {
            return Err(ClaimVerificationErrorV2::InvalidReceipt);
        }
        Ok(())
    }
}

impl AcceptedClaimSetV2 {
    pub fn recompute_digest(&self) -> Result<String, ClaimVerificationErrorV2> {
        #[derive(Serialize)]
        struct DigestView<'a> {
            schema_version: &'a str,
            source_snapshot_exact_set_sha256: &'a str,
            verification_receipt_sha256: &'a str,
            state: ClaimSetStateV2,
            accepted_claim_ids: &'a [String],
            abstentions: &'a [AbstentionV2],
        }
        canonical_json_sha256(&DigestView {
            schema_version: &self.schema_version,
            source_snapshot_exact_set_sha256: &self.source_snapshot_exact_set_sha256,
            verification_receipt_sha256: &self.verification_receipt_sha256,
            state: self.state,
            accepted_claim_ids: &self.accepted_claim_ids,
            abstentions: &self.abstentions,
        })
        .map_err(|_| ClaimVerificationErrorV2::InvalidAcceptedSet)
    }

    pub fn validate(
        &self,
        receipt: &ClaimVerificationReceiptV2,
    ) -> Result<(), ClaimVerificationErrorV2> {
        receipt.validate()?;
        let record_states: BTreeMap<&str, ClaimVerificationStateV2> = receipt
            .claims
            .iter()
            .map(|record| (record.claim_id.as_str(), record.state))
            .collect();
        let entailed_ids = receipt
            .claims
            .iter()
            .filter(|record| record.state == ClaimVerificationStateV2::Entailed)
            .map(|record| record.claim_id.as_str())
            .collect::<Vec<_>>();
        let unknown_ids = receipt
            .claims
            .iter()
            .filter(|record| record.state == ClaimVerificationStateV2::Unknown)
            .map(|record| record.claim_id.as_str())
            .collect::<Vec<_>>();
        let accepted_are_entailed = self
            .accepted_claim_ids
            .iter()
            .map(String::as_str)
            .eq(entailed_ids.iter().copied());
        let abstention_ids = self
            .abstentions
            .iter()
            .map(|abstention| abstention.claim_id.as_str())
            .collect::<Vec<_>>();
        let abstentions_are_unknown = abstention_ids
            .iter()
            .copied()
            .eq(unknown_ids.iter().copied())
            && self.abstentions.iter().all(|abstention| {
                abstention.reason == AbstentionReasonV2::Unknown
                    && record_states.get(abstention.claim_id.as_str())
                        == Some(&ClaimVerificationStateV2::Unknown)
                    && !abstention.candidate_evidence_ids.is_empty()
            });
        let valid_state = match self.state {
            ClaimSetStateV2::AcceptedGrounded => {
                !self.accepted_claim_ids.is_empty()
                    && self.abstentions.is_empty()
                    && receipt
                        .claims
                        .iter()
                        .all(|record| record.state == ClaimVerificationStateV2::Entailed)
            }
            ClaimSetStateV2::AcceptedPartialWithAbstention => {
                !self.accepted_claim_ids.is_empty()
                    && !self.abstentions.is_empty()
                    && receipt.claims.iter().all(|record| {
                        matches!(
                            record.state,
                            ClaimVerificationStateV2::Entailed | ClaimVerificationStateV2::Unknown
                        )
                    })
            }
            ClaimSetStateV2::NoSemanticClaim => {
                self.accepted_claim_ids.is_empty()
                    && !self.abstentions.is_empty()
                    && receipt
                        .claims
                        .iter()
                        .all(|record| record.state == ClaimVerificationStateV2::Unknown)
            }
            ClaimSetStateV2::Rejected => {
                self.accepted_claim_ids.is_empty()
                    && self.abstentions.is_empty()
                    && receipt.claims.iter().any(|record| {
                        matches!(
                            record.state,
                            ClaimVerificationStateV2::Unsupported
                                | ClaimVerificationStateV2::Contradicted
                        )
                    })
            }
        };
        if self.schema_version != ACCEPTED_SET_SCHEMA
            || self.source_snapshot_exact_set_sha256 != receipt.source_snapshot_exact_set_sha256
            || self.verification_receipt_sha256 != receipt.receipt_sha256
            || !is_sha256(&self.accepted_claim_set_sha256)
            || self.accepted_claim_set_sha256 != self.recompute_digest()?
            || !sorted_unique(self.accepted_claim_ids.iter().map(String::as_str))
            || !sorted_unique(self.abstentions.iter().map(|item| item.claim_id.as_str()))
            || (self.state != ClaimSetStateV2::Rejected
                && (!accepted_are_entailed || !abstentions_are_unknown))
            || !valid_state
        {
            return Err(ClaimVerificationErrorV2::InvalidAcceptedSet);
        }
        Ok(())
    }
}

/// Verify local atomic claims. Exact matching is intentional for this first
/// non-LLM slice: it makes a support judgement replayable, and unsupported
/// semantic paraphrases remain rejected rather than guessed as grounded.
pub fn verify_atomic_claims_v2(
    input: ClaimVerificationInputV2<'_>,
    claims: &[AtomicClaimV2],
) -> Result<ClaimVerificationOutputV2, ClaimVerificationErrorV2> {
    validate_input(&input)?;
    if claims.is_empty() || !unique(claims.iter().map(|claim| claim.claim_id.as_str())) {
        return Err(ClaimVerificationErrorV2::InvalidProposalSet);
    }

    let conflicts = conflicting_claim_ids(claims);
    let mut records = Vec::with_capacity(claims.len());
    let mut abstentions = Vec::new();
    for claim in claims {
        let (mut state, detail_code, evidence_ids) = evaluate_claim(&input, claim)?;
        if conflicts.contains(claim.claim_id.as_str()) {
            state = ClaimVerificationStateV2::Contradicted;
        }
        if state == ClaimVerificationStateV2::Unknown {
            abstentions.push(AbstentionV2 {
                claim_id: claim.claim_id.clone(),
                target: claim.natural_language.clone(),
                reason: AbstentionReasonV2::Unknown,
                candidate_evidence_ids: evidence_ids.clone(),
                retryable: true,
            });
        }
        records.push(ClaimVerificationRecordV2 {
            claim_id: claim.claim_id.clone(),
            state,
            evidence_ids,
            detail_code: if state == ClaimVerificationStateV2::Contradicted {
                "E_V2_CLAIM_CONTRADICTION".to_owned()
            } else {
                detail_code
            },
        });
    }
    records.sort_by(|left, right| left.claim_id.cmp(&right.claim_id));
    abstentions.sort_by(|left, right| left.claim_id.cmp(&right.claim_id));
    let coverage = ClaimCoverageV2 {
        claim_count: records.len() as u64,
        cited_claims: records
            .iter()
            .filter(|record| !record.evidence_ids.is_empty())
            .count() as u64,
        covered_claims: records
            .iter()
            .filter(|record| record.state == ClaimVerificationStateV2::Entailed)
            .count() as u64,
    };
    let mut receipt = ClaimVerificationReceiptV2 {
        schema_version: RECEIPT_SCHEMA.to_owned(),
        verifier_id: VERIFIER_ID.to_owned(),
        verifier_policy: VERIFIER_POLICY.to_owned(),
        source_snapshot_exact_set_sha256: input.typed_ir.source_snapshot_exact_set_sha256.clone(),
        typed_ir_sha256: input.typed_ir.typed_ir_sha256.clone(),
        summary_job_sha256: input.summary_job.job_sha256.clone(),
        t03_receipt_sha256: input.t03_evidence.binding.receipt_sha256.clone(),
        t04_manifest_sha256: input.t04_evidence.receipt.manifest.manifest_sha256.clone(),
        proposal_set_sha256: claim_proposal_set_digest(claims)?,
        claims: records,
        coverage,
        receipt_sha256: String::new(),
    };
    receipt.receipt_sha256 = receipt.recompute_digest()?;
    receipt.validate()?;

    let mut accepted_claim_ids: Vec<String> = receipt
        .claims
        .iter()
        .filter(|record| record.state == ClaimVerificationStateV2::Entailed)
        .map(|record| record.claim_id.clone())
        .collect();
    let state = if receipt.claims.iter().any(|record| {
        matches!(
            record.state,
            ClaimVerificationStateV2::Unsupported | ClaimVerificationStateV2::Contradicted
        )
    }) {
        ClaimSetStateV2::Rejected
    } else if accepted_claim_ids.is_empty() {
        ClaimSetStateV2::NoSemanticClaim
    } else if abstentions.is_empty() {
        ClaimSetStateV2::AcceptedGrounded
    } else {
        ClaimSetStateV2::AcceptedPartialWithAbstention
    };
    if state == ClaimSetStateV2::Rejected {
        accepted_claim_ids.clear();
        abstentions.clear();
    }
    let mut accepted = AcceptedClaimSetV2 {
        schema_version: ACCEPTED_SET_SCHEMA.to_owned(),
        source_snapshot_exact_set_sha256: input.typed_ir.source_snapshot_exact_set_sha256.clone(),
        verification_receipt_sha256: receipt.receipt_sha256.clone(),
        state,
        accepted_claim_ids,
        abstentions,
        accepted_claim_set_sha256: String::new(),
    };
    accepted.accepted_claim_set_sha256 = accepted.recompute_digest()?;
    accepted.validate(&receipt)?;
    Ok(ClaimVerificationOutputV2 { receipt, accepted })
}

fn validate_input(input: &ClaimVerificationInputV2<'_>) -> Result<(), ClaimVerificationErrorV2> {
    input
        .typed_ir
        .validate_for_source(input.source_bytes)
        .map_err(|error| ClaimVerificationErrorV2::TypedIr(error.to_string()))?;
    input
        .summary_job
        .validate()
        .map_err(|_| ClaimVerificationErrorV2::SummaryJobInvalid)?;
    let selected = selected_binding_v2(input.selected_context)
        .map_err(|_| ClaimVerificationErrorV2::SelectedContextInvalid)?;
    if selected.source_snapshot_exact_set_sha256 != input.typed_ir.source_snapshot_exact_set_sha256
        || input.summary_job.source_snapshot_exact_set_sha256
            != input.typed_ir.source_snapshot_exact_set_sha256
        || input.summary_job.context_pack_sha256 != selected.context_pack_sha256
        || input.summary_job.selected_context_sha256 != selected.selected_context_sha256
    {
        return Err(ClaimVerificationErrorV2::SnapshotBindingMismatch);
    }
    input
        .t03_evidence
        .binding
        .raw_spec_pin
        .validate()
        .map_err(|_| ClaimVerificationErrorV2::T03BindingInvalid)?;
    if !is_sha256(&input.t03_evidence.binding.corpus_manifest_sha256)
        || !is_sha256(&input.t03_evidence.binding.receipt_sha256)
        || input.t03_evidence.binding.corpus_id.trim().is_empty()
    {
        return Err(ClaimVerificationErrorV2::T03BindingInvalid);
    }
    input
        .t04_evidence
        .receipt
        .manifest
        .validate()
        .map_err(|_| ClaimVerificationErrorV2::T04ReceiptInvalid)?;
    if input.t04_evidence.receipt.counts_toward_external_gate() {
        return Err(ClaimVerificationErrorV2::T04ReceiptInvalid);
    }
    Ok(())
}

fn evaluate_claim(
    input: &ClaimVerificationInputV2<'_>,
    claim: &AtomicClaimV2,
) -> Result<(ClaimVerificationStateV2, String, Vec<String>), ClaimVerificationErrorV2> {
    if !valid_claim(claim) {
        return Ok((
            ClaimVerificationStateV2::Unsupported,
            "E_V2_CLAIM_PROPOSAL_INVALID".to_owned(),
            Vec::new(),
        ));
    }
    let evidence_by_id: BTreeMap<&str, &EvidenceSpanV2> = input
        .typed_ir
        .evidence
        .iter()
        .map(|evidence| (evidence.id.as_str(), evidence))
        .collect();
    let mut evidence_ids = Vec::with_capacity(claim.evidence.len());
    let mut exact_support = true;
    for citation in &claim.evidence {
        let Some(evidence) = evidence_by_id.get(citation.evidence_id.as_str()) else {
            exact_support = false;
            continue;
        };
        if !citation_matches_t02(citation, evidence) {
            exact_support = false;
            continue;
        }
        let Some(snippet) = source_span(input.source_bytes, evidence) else {
            exact_support = false;
            continue;
        };
        let selected = input
            .selected_context
            .iter()
            .find(|chunk| chunk.chunk_id() == citation.context_chunk_id);
        let expected_context_ref = format!(
            "context-content:v2:{}:{}:{}:{}:{}",
            citation.source_snapshot_exact_set_sha256,
            citation.source_sha256,
            citation.byte_start,
            citation.byte_end,
            citation.snippet_sha256,
        );
        if selected.is_none_or(|chunk| {
            chunk.content() != snippet
                || chunk.content_sha256() != citation.snippet_sha256
                || chunk.immutable_content_ref() != expected_context_ref
        }) || normalize(snippet) != normalize(&claim.natural_language)
        {
            exact_support = false;
        }
        evidence_ids.push(citation.evidence_id.clone());
    }
    evidence_ids.sort();
    evidence_ids.dedup();
    let distinct_evidence_spans = claim
        .evidence
        .iter()
        .map(|citation| {
            (
                citation.source_sha256.as_str(),
                citation.byte_start,
                citation.byte_end,
            )
        })
        .collect::<BTreeSet<_>>();
    if claim.risk_class == RiskClassV2::High && distinct_evidence_spans.len() < 2 {
        exact_support = false;
    }
    if !exact_support || evidence_ids.len() != claim.evidence.len() {
        return Ok((
            ClaimVerificationStateV2::Unsupported,
            "E_V2_CLAIM_CITATION_OR_ENTAILMENT".to_owned(),
            evidence_ids,
        ));
    }
    if claim.modality == ClaimModalityV2::Unknown {
        return Ok((
            ClaimVerificationStateV2::Unknown,
            "E_V2_CLAIM_UNKNOWN_ABSTAINED".to_owned(),
            evidence_ids,
        ));
    }
    Ok((
        ClaimVerificationStateV2::Entailed,
        "E_V2_CLAIM_EXACT_LOCAL_ENTAILMENT".to_owned(),
        evidence_ids,
    ))
}

fn citation_matches_t02(citation: &ClaimEvidenceRefV2, evidence: &EvidenceSpanV2) -> bool {
    citation.source_snapshot_exact_set_sha256 == evidence.source_snapshot_exact_set_sha256
        && citation.source_logical_path == evidence.source_logical_path
        && citation.source_sha256 == evidence.source_sha256
        && citation.byte_start == evidence.byte_start
        && citation.byte_end == evidence.byte_end
        && citation.snippet_sha256 == evidence.snippet_sha256
}

fn conflicting_claim_ids(claims: &[AtomicClaimV2]) -> BTreeSet<&str> {
    let mut by_fact: BTreeMap<(&str, &str, &str), (bool, bool)> = BTreeMap::new();
    for claim in claims
        .iter()
        .filter(|claim| claim.modality == ClaimModalityV2::Asserted)
    {
        let entry = by_fact
            .entry((&claim.subject, &claim.predicate, &claim.object))
            .or_default();
        match claim.polarity {
            ClaimPolarityV2::Positive => entry.0 = true,
            ClaimPolarityV2::Negative => entry.1 = true,
        }
    }
    claims
        .iter()
        .filter(|claim| {
            claim.modality == ClaimModalityV2::Asserted
                && by_fact
                    .get(&(&claim.subject, &claim.predicate, &claim.object))
                    .is_some_and(|(positive, negative)| *positive && *negative)
        })
        .map(|claim| claim.claim_id.as_str())
        .collect()
}

fn source_span<'a>(source: &'a [u8], evidence: &EvidenceSpanV2) -> Option<&'a str> {
    let start = usize::try_from(evidence.byte_start).ok()?;
    let end = usize::try_from(evidence.byte_end).ok()?;
    std::str::from_utf8(source.get(start..end)?).ok()
}

fn valid_claim(claim: &AtomicClaimV2) -> bool {
    valid_identifier(&claim.claim_id)
        && !claim.subject.trim().is_empty()
        && !claim.predicate.trim().is_empty()
        && !claim.object.trim().is_empty()
        && !claim.natural_language.trim().is_empty()
        && !claim.evidence.is_empty()
        && unique(claim.evidence.iter().map(|item| item.evidence_id.as_str()))
        && claim.evidence.iter().all(valid_citation)
}

fn valid_citation(citation: &ClaimEvidenceRefV2) -> bool {
    valid_identifier(&citation.context_chunk_id)
        && !citation.source_logical_path.is_empty()
        && citation.byte_start < citation.byte_end
        && is_sha256(&citation.source_snapshot_exact_set_sha256)
        && is_sha256(&citation.source_sha256)
        && is_sha256(&citation.snippet_sha256)
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

fn sorted_unique<'a>(values: impl Iterator<Item = &'a str>) -> bool {
    let mut previous = None;
    for value in values {
        if previous.is_some_and(|last| last >= value) {
            return false;
        }
        previous = Some(value);
    }
    true
}

fn unique<'a>(mut values: impl Iterator<Item = &'a str>) -> bool {
    let mut seen = BTreeSet::new();
    values.all(|value| seen.insert(value))
}

fn normalize(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn is_sha256(value: &str) -> bool {
    validate_sha256(value).is_ok()
}
