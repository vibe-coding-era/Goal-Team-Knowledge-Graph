//! P03 claim-free context and independently verified summary candidates.

use std::collections::BTreeSet;
use std::path::Path;

use gtkg_protocol::v2::{
    ContextPackPayloadV2, SummaryAcceptPayloadV2, SummaryFactDecisionStateV2,
    SummaryJobNextPayloadV2, SummaryProposalSubmitPayloadV2, SummaryVerificationDecisionStateV2,
    SummaryVerificationNextPayloadV2, SummaryVerificationSubmitPayloadV2, V2ErrorCode,
};
use gtkg_protocol::v03::adapter::{VerifiedFactReceiptV1, VerifiedResolutionV1};
use gtkg_protocol::{FileReceiptRef, canonical_json_sha256};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::durable::{DurableErrorKind, publish_immutable_json};
use crate::exact_read::{ExactReadFailure, read_bound_regular_file};
use crate::v03::analysis::validate_verification_chain_v1;
use crate::{CallContext, ContextError};

const P02_VERIFICATION_SCHEMA: &str = "gtkg.analysis-verification/v1";
const CONTEXT_SCHEMA: &str = "gtkg.claim-free-context-pack/v1";
const JOB_SCHEMA: &str = "gtkg.summary-job/v1";
const PROPOSAL_SCHEMA: &str = "gtkg.summary-proposal/v1";
const VERIFICATION_JOB_SCHEMA: &str = "gtkg.summary-verification-job/v1";
const SUMMARY_VERIFICATION_SCHEMA: &str = "gtkg.summary-verification/v1";
const ACCEPTED_SCHEMA: &str = "gtkg.accepted-summary-candidate/v1";

#[derive(Debug)]
pub(crate) struct SummaryFailureV1 {
    pub code: V2ErrorCode,
    pub stage: &'static str,
    pub message: String,
    pub recovery_hint: &'static str,
}

#[derive(Debug)]
pub(crate) struct SummaryResultV1 {
    pub result: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct P02VerificationRunV1 {
    selection_id: String,
    adapter_descriptor_sha256: String,
    bundle_sha256: String,
    fact_receipts: Vec<VerifiedFactReceiptV1>,
    resolved_verified_count: u64,
    ambiguous_count: u64,
    locator_only_count: u64,
    false_confirmed: u64,
    canonical_write_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct P02VerificationArtifactV1 {
    schema_version: String,
    candidate_ref: FileReceiptRef,
    candidate_sha256: String,
    plan_sha256: String,
    source_snapshot_exact_set_sha256: String,
    adapter_verifications: Vec<P02VerificationRunV1>,
    resolved_verified_count: u64,
    ambiguous_count: u64,
    locator_only_count: u64,
    false_confirmed: u64,
    target_execution_count: u64,
    network_call_count: u64,
    provider_call_count: u64,
    canonical_write_count: u64,
    current_write_count: u64,
    a06_cross_adapter_status: String,
    collision_check: String,
    canonical_eligible: bool,
    verification_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ContextFactV1 {
    fact_id: String,
    receipt_sha256: String,
    resolution: VerifiedResolutionV1,
    reason: String,
    source_snapshot_sha256: String,
    adapter_descriptor_sha256: String,
    bundle_sha256: String,
    evidence_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClaimFreeContextV1 {
    schema_version: String,
    analysis_verification_ref: FileReceiptRef,
    analysis_verification_sha256: String,
    source_snapshot_exact_set_sha256: String,
    max_fact_count: u64,
    total_fact_count: u64,
    selected_fact_count: u64,
    excluded_fact_count: u64,
    facts: Vec<ContextFactV1>,
    claim_count: u64,
    claim_free: bool,
    a06_cross_adapter_status: String,
    collision_check: String,
    canonical_eligible: bool,
    context_pack_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SummaryJobV1 {
    schema_version: String,
    analysis_verification_ref: FileReceiptRef,
    analysis_verification_sha256: String,
    context_pack_sha256: String,
    source_snapshot_exact_set_sha256: String,
    fact_receipt_sha256s: Vec<String>,
    claim_free: bool,
    provider_call_count: u64,
    network_call_count: u64,
    summary_job_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProposalDecisionV1 {
    fact_receipt_sha256: String,
    state: SummaryFactDecisionStateV2,
    reason: String,
    proposal_decision_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SummaryProposalV1 {
    schema_version: String,
    analysis_verification_ref: FileReceiptRef,
    analysis_verification_sha256: String,
    source_snapshot_exact_set_sha256: String,
    context_pack_sha256: String,
    summary_job_sha256: String,
    max_fact_count: u64,
    proposer_id: String,
    proposer_note: String,
    decisions: Vec<ProposalDecisionV1>,
    supported_count: u64,
    abstention_count: u64,
    conflict_count: u64,
    provider_call_count: u64,
    network_call_count: u64,
    canonical_write_count: u64,
    proposal_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct VerificationJobDecisionV1 {
    proposal_decision_sha256: String,
    fact_receipt_sha256: String,
    proposal_state: SummaryFactDecisionStateV2,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SummaryVerificationJobV1 {
    schema_version: String,
    proposal_ref: FileReceiptRef,
    proposal_sha256: String,
    context_pack_sha256: String,
    source_snapshot_exact_set_sha256: String,
    proposer_id: String,
    decisions: Vec<VerificationJobDecisionV1>,
    verification_job_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SummaryVerificationDecisionReceiptV1 {
    proposal_decision_sha256: String,
    state: SummaryVerificationDecisionStateV2,
    reason: String,
    decision_receipt_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SummaryVerificationV1 {
    schema_version: String,
    proposal_ref: FileReceiptRef,
    proposal_sha256: String,
    verification_job_sha256: String,
    context_pack_sha256: String,
    source_snapshot_exact_set_sha256: String,
    verifier_id: String,
    actor_independence_state: String,
    decisions: Vec<SummaryVerificationDecisionReceiptV1>,
    verified_count: u64,
    rejected_count: u64,
    conflict_count: u64,
    provider_call_count: u64,
    network_call_count: u64,
    canonical_write_count: u64,
    summary_verification_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AssertedClaimV1 {
    fact_receipt_sha256: String,
    proposal_decision_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AcceptedSummaryCandidateV1 {
    schema_version: String,
    proposal_ref: FileReceiptRef,
    proposal_sha256: String,
    summary_verification_ref: FileReceiptRef,
    summary_verification_sha256: String,
    context_pack_sha256: String,
    source_snapshot_exact_set_sha256: String,
    proposer_note: String,
    verified_summary_text: Option<String>,
    asserted_claims: Vec<AssertedClaimV1>,
    status: String,
    actor_independence_state: String,
    a06_cross_adapter_status: String,
    collision_check: String,
    canonical_eligible: bool,
    provider_call_count: u64,
    network_call_count: u64,
    git_external_write_count: u64,
    current_write_count: u64,
    canonical_write_count: u64,
    accepted_summary_sha256: String,
}

pub(crate) fn context_pack(
    context: &CallContext,
    payload: ContextPackPayloadV2,
) -> Result<SummaryResultV1, SummaryFailureV1> {
    let workspace = context
        .authorize_read(&payload.workspace_root)
        .map_err(context_failure)?;
    let verification =
        load_p02_verification(context, &workspace, &payload.analysis_verification_ref)?;
    let pack = build_context(
        payload.analysis_verification_ref,
        &verification,
        payload.max_fact_count,
    )?;
    Ok(SummaryResultV1 {
        result: json!({
            "context_pack": pack,
            "context_pack_sha256": pack.context_pack_sha256,
            "provider_call_count": 0,
            "network_call_count": 0,
            "canonical_write_count": 0,
        }),
    })
}

pub(crate) fn summary_job_next(
    context: &CallContext,
    payload: SummaryJobNextPayloadV2,
) -> Result<SummaryResultV1, SummaryFailureV1> {
    let workspace = context
        .authorize_read(&payload.workspace_root)
        .map_err(context_failure)?;
    let verification =
        load_p02_verification(context, &workspace, &payload.analysis_verification_ref)?;
    let pack = build_context(
        payload.analysis_verification_ref,
        &verification,
        payload.max_fact_count,
    )?;
    if pack.context_pack_sha256 != payload.expected_context_pack_sha256 {
        return Err(lock("summary.job.next", "context pack digest mismatch"));
    }
    let job = build_job(&pack)?;
    Ok(SummaryResultV1 {
        result: json!({
            "summary_job": job,
            "summary_job_sha256": job.summary_job_sha256,
            "provider_call_count": 0,
            "network_call_count": 0,
            "canonical_write_count": 0,
        }),
    })
}

pub(crate) fn proposal_submit(
    context: &CallContext,
    payload: SummaryProposalSubmitPayloadV2,
) -> Result<SummaryResultV1, SummaryFailureV1> {
    let workspace = context
        .authorize_write(&payload.workspace_root)
        .map_err(context_failure)?;
    let verification =
        load_p02_verification(context, &workspace, &payload.analysis_verification_ref)?;
    let pack = find_context(
        payload.analysis_verification_ref.clone(),
        &verification,
        &payload.context_pack_sha256,
    )?;
    let job = build_job(&pack)?;
    if job.summary_job_sha256 != payload.summary_job_sha256 {
        return Err(lock(
            "summary.proposal.submit",
            "summary job digest mismatch",
        ));
    }
    let proposal = build_proposal(&pack, &job, payload)?;
    let path = workspace.join(format!(
        ".gtkg/summary/proposals/{}.json",
        digest_hex(&proposal.proposal_sha256)?
    ));
    let reference = publish(
        context,
        &workspace,
        &path,
        &proposal,
        "summary.proposal.submit",
    )?;
    Ok(SummaryResultV1 {
        result: json!({
            "proposal_ref": reference,
            "proposal_sha256": proposal.proposal_sha256,
            "decision_count": proposal.decisions.len(),
            "supported_count": proposal.supported_count,
            "abstention_count": proposal.abstention_count,
            "conflict_count": proposal.conflict_count,
            "provider_call_count": 0,
            "network_call_count": 0,
            "canonical_write_count": 0,
        }),
    })
}

pub(crate) fn verification_next(
    context: &CallContext,
    payload: SummaryVerificationNextPayloadV2,
) -> Result<SummaryResultV1, SummaryFailureV1> {
    let workspace = context
        .authorize_read(&payload.workspace_root)
        .map_err(context_failure)?;
    let proposal: SummaryProposalV1 = load_artifact(
        context,
        &workspace,
        &payload.proposal_ref,
        "summary.verification.next",
    )?;
    validate_proposal_shape(&proposal)?;
    validate_semantic_ref(
        &payload.proposal_ref,
        "proposals",
        &proposal.proposal_sha256,
        "summary.verification.next",
    )?;
    validate_proposal_chain(context, &workspace, &proposal)?;
    let job = build_verification_job(payload.proposal_ref, &proposal)?;
    Ok(SummaryResultV1 {
        result: json!({
            "verification_job": job,
            "verification_job_sha256": job.verification_job_sha256,
            "provider_call_count": 0,
            "network_call_count": 0,
            "canonical_write_count": 0,
        }),
    })
}

pub(crate) fn verification_submit(
    context: &CallContext,
    payload: SummaryVerificationSubmitPayloadV2,
) -> Result<SummaryResultV1, SummaryFailureV1> {
    let workspace = context
        .authorize_write(&payload.workspace_root)
        .map_err(context_failure)?;
    let proposal: SummaryProposalV1 = load_artifact(
        context,
        &workspace,
        &payload.proposal_ref,
        "summary.verification.submit",
    )?;
    validate_proposal_shape(&proposal)?;
    validate_semantic_ref(
        &payload.proposal_ref,
        "proposals",
        &proposal.proposal_sha256,
        "summary.verification.submit",
    )?;
    validate_proposal_chain(context, &workspace, &proposal)?;
    if payload.verifier_id == proposal.proposer_id {
        return Err(invalid(
            "summary.verification.submit",
            "verifier identity must be independent from proposer identity",
        ));
    }
    let job = build_verification_job(payload.proposal_ref.clone(), &proposal)?;
    if job.verification_job_sha256 != payload.verification_job_sha256 {
        return Err(lock(
            "summary.verification.submit",
            "verification job digest mismatch",
        ));
    }
    let verification = build_summary_verification(&proposal, &job, payload)?;
    let path = workspace.join(format!(
        ".gtkg/summary/verifications/{}.json",
        digest_hex(&verification.summary_verification_sha256)?
    ));
    let reference = publish(
        context,
        &workspace,
        &path,
        &verification,
        "summary.verification.submit",
    )?;
    Ok(SummaryResultV1 {
        result: json!({
            "summary_verification_ref": reference,
            "summary_verification_sha256": verification.summary_verification_sha256,
            "verified_count": verification.verified_count,
            "rejected_count": verification.rejected_count,
            "conflict_count": verification.conflict_count,
            "provider_call_count": 0,
            "network_call_count": 0,
            "canonical_write_count": 0,
        }),
    })
}

pub(crate) fn accept(
    context: &CallContext,
    payload: SummaryAcceptPayloadV2,
) -> Result<SummaryResultV1, SummaryFailureV1> {
    let workspace = context
        .authorize_write(&payload.workspace_root)
        .map_err(context_failure)?;
    let proposal: SummaryProposalV1 = load_artifact(
        context,
        &workspace,
        &payload.proposal_ref,
        "summary.accept.v2",
    )?;
    validate_proposal(&proposal)?;
    validate_semantic_ref(
        &payload.proposal_ref,
        "proposals",
        &proposal.proposal_sha256,
        "summary.accept.v2",
    )?;
    validate_proposal_chain(context, &workspace, &proposal)?;
    let verification: SummaryVerificationV1 = load_artifact(
        context,
        &workspace,
        &payload.summary_verification_ref,
        "summary.accept.v2",
    )?;
    validate_summary_verification(&verification)?;
    validate_semantic_ref(
        &payload.summary_verification_ref,
        "verifications",
        &verification.summary_verification_sha256,
        "summary.accept.v2",
    )?;
    validate_summary_verification_chain(&proposal, &verification)?;
    if verification.proposal_ref != payload.proposal_ref
        || verification.proposal_sha256 != proposal.proposal_sha256
        || proposal.conflict_count != 0
        || verification.rejected_count != 0
        || verification.conflict_count != 0
        || verification.verified_count != proposal.decisions.len() as u64
    {
        return Err(invalid_state(
            "summary.accept.v2",
            "proposal conflicts or verification denominator block acceptance",
        ));
    }
    let mut accepted = AcceptedSummaryCandidateV1 {
        schema_version: ACCEPTED_SCHEMA.to_owned(),
        proposal_ref: payload.proposal_ref,
        proposal_sha256: proposal.proposal_sha256,
        summary_verification_ref: payload.summary_verification_ref,
        summary_verification_sha256: verification.summary_verification_sha256,
        context_pack_sha256: proposal.context_pack_sha256,
        source_snapshot_exact_set_sha256: proposal.source_snapshot_exact_set_sha256,
        proposer_note: proposal.proposer_note,
        verified_summary_text: None,
        asserted_claims: proposal
            .decisions
            .iter()
            .filter(|decision| decision.state == SummaryFactDecisionStateV2::Supported)
            .map(|decision| AssertedClaimV1 {
                fact_receipt_sha256: decision.fact_receipt_sha256.clone(),
                proposal_decision_sha256: decision.proposal_decision_sha256.clone(),
            })
            .collect(),
        status: "candidate_accepted".to_owned(),
        actor_independence_state: verification.actor_independence_state,
        a06_cross_adapter_status: "not_run".to_owned(),
        collision_check: "not_run".to_owned(),
        canonical_eligible: false,
        provider_call_count: 0,
        network_call_count: 0,
        git_external_write_count: 0,
        current_write_count: 0,
        canonical_write_count: 0,
        accepted_summary_sha256: String::new(),
    };
    accepted.accepted_summary_sha256 =
        digest_without(&accepted, "accepted_summary_sha256", "summary.accept.v2")?;
    let path = workspace.join(format!(
        ".gtkg/summary/accepted/{}.json",
        digest_hex(&accepted.accepted_summary_sha256)?
    ));
    let reference = publish(context, &workspace, &path, &accepted, "summary.accept.v2")?;
    Ok(SummaryResultV1 {
        result: json!({
            "accepted_summary_ref": reference,
            "accepted_summary_sha256": accepted.accepted_summary_sha256,
            "status": accepted.status,
            "asserted_claim_count": accepted.asserted_claims.len(),
            "actor_independence_state": accepted.actor_independence_state,
            "a06_cross_adapter_status": "not_run",
            "collision_check": "not_run",
            "canonical_eligible": false,
            "provider_call_count": 0,
            "network_call_count": 0,
            "git_external_write_count": 0,
            "current_write_count": 0,
            "canonical_write_count": 0,
        }),
    })
}

/// Read-only validation boundary for P04. The accepted candidate, proposal,
/// independent verification, and complete P02 chain are replayed without any
/// filesystem write or authority promotion.
pub(crate) fn validate_accepted_summary_chain_v1(
    context: &CallContext,
    workspace_root: &Path,
    reference: &FileReceiptRef,
) -> Result<Value, SummaryFailureV1> {
    let workspace = context
        .authorize_read(workspace_root)
        .map_err(context_failure)?;
    let accepted: AcceptedSummaryCandidateV1 =
        load_artifact(context, &workspace, reference, "summary.validate-chain")?;
    validate_semantic_ref(
        reference,
        "accepted",
        &accepted.accepted_summary_sha256,
        "summary.validate-chain",
    )?;
    if accepted.schema_version != ACCEPTED_SCHEMA
        || accepted.status != "candidate_accepted"
        || accepted.verified_summary_text.is_some()
        || accepted.actor_independence_state != "declared_distinct_not_attested"
        || accepted.a06_cross_adapter_status != "not_run"
        || accepted.collision_check != "not_run"
        || accepted.canonical_eligible
        || accepted.provider_call_count != 0
        || accepted.network_call_count != 0
        || accepted.git_external_write_count != 0
        || accepted.current_write_count != 0
        || accepted.canonical_write_count != 0
        || accepted.accepted_summary_sha256
            != digest_without(
                &accepted,
                "accepted_summary_sha256",
                "summary.validate-chain",
            )?
    {
        return Err(invalid_state(
            "summary.validate-chain",
            "accepted summary candidate is invalid or tampered",
        ));
    }
    let proposal: SummaryProposalV1 = load_artifact(
        context,
        &workspace,
        &accepted.proposal_ref,
        "summary.validate-chain",
    )?;
    validate_proposal(&proposal)?;
    validate_semantic_ref(
        &accepted.proposal_ref,
        "proposals",
        &proposal.proposal_sha256,
        "summary.validate-chain",
    )?;
    validate_proposal_chain(context, &workspace, &proposal)?;
    let verification: SummaryVerificationV1 = load_artifact(
        context,
        &workspace,
        &accepted.summary_verification_ref,
        "summary.validate-chain",
    )?;
    validate_summary_verification(&verification)?;
    validate_semantic_ref(
        &accepted.summary_verification_ref,
        "verifications",
        &verification.summary_verification_sha256,
        "summary.validate-chain",
    )?;
    validate_summary_verification_chain(&proposal, &verification)?;
    let expected_claims = proposal
        .decisions
        .iter()
        .filter(|decision| decision.state == SummaryFactDecisionStateV2::Supported)
        .map(|decision| AssertedClaimV1 {
            fact_receipt_sha256: decision.fact_receipt_sha256.clone(),
            proposal_decision_sha256: decision.proposal_decision_sha256.clone(),
        })
        .collect::<Vec<_>>();
    if accepted.proposal_sha256 != proposal.proposal_sha256
        || accepted.summary_verification_sha256 != verification.summary_verification_sha256
        || accepted.context_pack_sha256 != proposal.context_pack_sha256
        || accepted.source_snapshot_exact_set_sha256 != proposal.source_snapshot_exact_set_sha256
        || accepted.proposer_note != proposal.proposer_note
        || accepted.actor_independence_state != verification.actor_independence_state
        || accepted.asserted_claims != expected_claims
        || proposal.conflict_count != 0
        || verification.rejected_count != 0
        || verification.conflict_count != 0
        || verification.verified_count != proposal.decisions.len() as u64
    {
        return Err(invalid_state(
            "summary.validate-chain",
            "accepted summary differs from replayed proposal/verification chain",
        ));
    }
    serde_json::to_value(accepted)
        .map_err(|error| invalid_state("summary.validate-chain", error.to_string()))
}

fn build_context(
    reference: FileReceiptRef,
    verification: &P02VerificationArtifactV1,
    max_fact_count: u64,
) -> Result<ClaimFreeContextV1, SummaryFailureV1> {
    let mut facts = verification
        .adapter_verifications
        .iter()
        .flat_map(|run| run.fact_receipts.iter())
        .map(|receipt| ContextFactV1 {
            fact_id: receipt.fact_id.clone(),
            receipt_sha256: receipt.receipt_sha256.clone(),
            resolution: receipt.resolution,
            reason: receipt.reason.clone(),
            source_snapshot_sha256: receipt.source_snapshot_sha256.clone(),
            adapter_descriptor_sha256: receipt.adapter_descriptor_sha256.clone(),
            bundle_sha256: receipt.bundle_sha256.clone(),
            evidence_ids: receipt.evidence_ids.clone(),
        })
        .collect::<Vec<_>>();
    facts.sort_by(|left, right| left.receipt_sha256.cmp(&right.receipt_sha256));
    if facts
        .windows(2)
        .any(|pair| pair[0].receipt_sha256 == pair[1].receipt_sha256)
    {
        return Err(invalid_state(
            "context.pack",
            "duplicate fact receipt identity",
        ));
    }
    let total_fact_count = facts.len() as u64;
    facts.truncate(max_fact_count as usize);
    let selected_fact_count = facts.len() as u64;
    let mut pack = ClaimFreeContextV1 {
        schema_version: CONTEXT_SCHEMA.to_owned(),
        analysis_verification_ref: reference,
        analysis_verification_sha256: verification.verification_sha256.clone(),
        source_snapshot_exact_set_sha256: verification.source_snapshot_exact_set_sha256.clone(),
        max_fact_count,
        total_fact_count,
        selected_fact_count,
        excluded_fact_count: total_fact_count.saturating_sub(selected_fact_count),
        facts,
        claim_count: 0,
        claim_free: true,
        a06_cross_adapter_status: verification.a06_cross_adapter_status.clone(),
        collision_check: verification.collision_check.clone(),
        canonical_eligible: false,
        context_pack_sha256: String::new(),
    };
    pack.context_pack_sha256 = digest_without(&pack, "context_pack_sha256", "context.pack")?;
    Ok(pack)
}

fn find_context(
    reference: FileReceiptRef,
    verification: &P02VerificationArtifactV1,
    expected: &str,
) -> Result<ClaimFreeContextV1, SummaryFailureV1> {
    for max in 1..=4096 {
        let pack = build_context(reference.clone(), verification, max as u64)?;
        if pack.context_pack_sha256 == expected {
            return Ok(pack);
        }
    }
    Err(lock(
        "summary.proposal.submit",
        "context pack digest is not reproducible from sealed verification",
    ))
}

fn build_job(pack: &ClaimFreeContextV1) -> Result<SummaryJobV1, SummaryFailureV1> {
    let mut job = SummaryJobV1 {
        schema_version: JOB_SCHEMA.to_owned(),
        analysis_verification_ref: pack.analysis_verification_ref.clone(),
        analysis_verification_sha256: pack.analysis_verification_sha256.clone(),
        context_pack_sha256: pack.context_pack_sha256.clone(),
        source_snapshot_exact_set_sha256: pack.source_snapshot_exact_set_sha256.clone(),
        fact_receipt_sha256s: pack
            .facts
            .iter()
            .map(|fact| fact.receipt_sha256.clone())
            .collect(),
        claim_free: true,
        provider_call_count: 0,
        network_call_count: 0,
        summary_job_sha256: String::new(),
    };
    job.summary_job_sha256 = digest_without(&job, "summary_job_sha256", "summary.job.next")?;
    Ok(job)
}

fn build_proposal(
    pack: &ClaimFreeContextV1,
    job: &SummaryJobV1,
    payload: SummaryProposalSubmitPayloadV2,
) -> Result<SummaryProposalV1, SummaryFailureV1> {
    let facts = pack
        .facts
        .iter()
        .map(|fact| (fact.receipt_sha256.as_str(), fact))
        .collect::<std::collections::BTreeMap<_, _>>();
    if payload.decisions.len() != facts.len() {
        return Err(invalid(
            "summary.proposal.submit",
            "proposal decision denominator must equal context fact denominator",
        ));
    }
    let mut seen = BTreeSet::new();
    let mut decisions = Vec::new();
    for decision in payload.decisions {
        let fact = facts
            .get(decision.fact_receipt_sha256.as_str())
            .ok_or_else(|| invalid("summary.proposal.submit", "decision uses unknown fact"))?;
        if !seen.insert(decision.fact_receipt_sha256.clone()) {
            return Err(invalid(
                "summary.proposal.submit",
                "duplicate fact decision",
            ));
        }
        if decision.state == SummaryFactDecisionStateV2::Supported
            && fact.resolution != VerifiedResolutionV1::ResolvedVerified
        {
            return Err(invalid_state(
                "summary.proposal.submit",
                "unresolved fact cannot be marked supported",
            ));
        }
        let mut receipt = ProposalDecisionV1 {
            fact_receipt_sha256: decision.fact_receipt_sha256,
            state: decision.state,
            reason: decision.reason,
            proposal_decision_sha256: String::new(),
        };
        receipt.proposal_decision_sha256 = digest_without(
            &receipt,
            "proposal_decision_sha256",
            "summary.proposal.submit",
        )?;
        decisions.push(receipt);
    }
    decisions.sort_by(|left, right| left.fact_receipt_sha256.cmp(&right.fact_receipt_sha256));
    let mut proposal = SummaryProposalV1 {
        schema_version: PROPOSAL_SCHEMA.to_owned(),
        analysis_verification_ref: pack.analysis_verification_ref.clone(),
        analysis_verification_sha256: pack.analysis_verification_sha256.clone(),
        source_snapshot_exact_set_sha256: pack.source_snapshot_exact_set_sha256.clone(),
        context_pack_sha256: pack.context_pack_sha256.clone(),
        summary_job_sha256: job.summary_job_sha256.clone(),
        max_fact_count: pack.max_fact_count,
        proposer_id: payload.proposer_id,
        proposer_note: payload.summary_text,
        supported_count: count_fact_state(&decisions, SummaryFactDecisionStateV2::Supported),
        abstention_count: count_fact_state(&decisions, SummaryFactDecisionStateV2::Abstain),
        conflict_count: count_fact_state(&decisions, SummaryFactDecisionStateV2::Conflict),
        decisions,
        provider_call_count: 0,
        network_call_count: 0,
        canonical_write_count: 0,
        proposal_sha256: String::new(),
    };
    proposal.proposal_sha256 =
        digest_without(&proposal, "proposal_sha256", "summary.proposal.submit")?;
    Ok(proposal)
}

fn build_verification_job(
    proposal_ref: FileReceiptRef,
    proposal: &SummaryProposalV1,
) -> Result<SummaryVerificationJobV1, SummaryFailureV1> {
    let mut job = SummaryVerificationJobV1 {
        schema_version: VERIFICATION_JOB_SCHEMA.to_owned(),
        proposal_ref,
        proposal_sha256: proposal.proposal_sha256.clone(),
        context_pack_sha256: proposal.context_pack_sha256.clone(),
        source_snapshot_exact_set_sha256: proposal.source_snapshot_exact_set_sha256.clone(),
        proposer_id: proposal.proposer_id.clone(),
        decisions: proposal
            .decisions
            .iter()
            .map(|decision| VerificationJobDecisionV1 {
                proposal_decision_sha256: decision.proposal_decision_sha256.clone(),
                fact_receipt_sha256: decision.fact_receipt_sha256.clone(),
                proposal_state: decision.state,
            })
            .collect(),
        verification_job_sha256: String::new(),
    };
    job.verification_job_sha256 =
        digest_without(&job, "verification_job_sha256", "summary.verification.next")?;
    Ok(job)
}

fn build_summary_verification(
    proposal: &SummaryProposalV1,
    job: &SummaryVerificationJobV1,
    payload: SummaryVerificationSubmitPayloadV2,
) -> Result<SummaryVerificationV1, SummaryFailureV1> {
    if payload.decisions.len() != job.decisions.len() {
        return Err(invalid(
            "summary.verification.submit",
            "verification decision denominator must equal proposal denominator",
        ));
    }
    let expected = job
        .decisions
        .iter()
        .map(|decision| decision.proposal_decision_sha256.as_str())
        .collect::<BTreeSet<_>>();
    let mut seen = BTreeSet::new();
    let mut decisions = Vec::new();
    for decision in payload.decisions {
        if !expected.contains(decision.proposal_decision_sha256.as_str())
            || !seen.insert(decision.proposal_decision_sha256.clone())
        {
            return Err(invalid(
                "summary.verification.submit",
                "verification decision identity is missing, duplicate, or unknown",
            ));
        }
        let mut receipt = SummaryVerificationDecisionReceiptV1 {
            proposal_decision_sha256: decision.proposal_decision_sha256,
            state: decision.state,
            reason: decision.reason,
            decision_receipt_sha256: String::new(),
        };
        receipt.decision_receipt_sha256 = digest_without(
            &receipt,
            "decision_receipt_sha256",
            "summary.verification.submit",
        )?;
        decisions.push(receipt);
    }
    decisions.sort_by(|left, right| {
        left.proposal_decision_sha256
            .cmp(&right.proposal_decision_sha256)
    });
    let mut verification = SummaryVerificationV1 {
        schema_version: SUMMARY_VERIFICATION_SCHEMA.to_owned(),
        proposal_ref: job.proposal_ref.clone(),
        proposal_sha256: proposal.proposal_sha256.clone(),
        verification_job_sha256: job.verification_job_sha256.clone(),
        context_pack_sha256: proposal.context_pack_sha256.clone(),
        source_snapshot_exact_set_sha256: proposal.source_snapshot_exact_set_sha256.clone(),
        verifier_id: payload.verifier_id,
        actor_independence_state: "declared_distinct_not_attested".to_owned(),
        verified_count: count_verification_state(
            &decisions,
            SummaryVerificationDecisionStateV2::Verified,
        ),
        rejected_count: count_verification_state(
            &decisions,
            SummaryVerificationDecisionStateV2::Rejected,
        ),
        conflict_count: count_verification_state(
            &decisions,
            SummaryVerificationDecisionStateV2::Conflict,
        ),
        decisions,
        provider_call_count: 0,
        network_call_count: 0,
        canonical_write_count: 0,
        summary_verification_sha256: String::new(),
    };
    verification.summary_verification_sha256 = digest_without(
        &verification,
        "summary_verification_sha256",
        "summary.verification.submit",
    )?;
    Ok(verification)
}

fn validate_proposal_shape(proposal: &SummaryProposalV1) -> Result<(), SummaryFailureV1> {
    let denominator = proposal
        .supported_count
        .checked_add(proposal.abstention_count)
        .and_then(|value| value.checked_add(proposal.conflict_count));
    if proposal.schema_version != PROPOSAL_SCHEMA
        || proposal.decisions.is_empty()
        || denominator != Some(proposal.decisions.len() as u64)
        || proposal.proposer_id.is_empty()
        || proposal.proposer_note.trim().is_empty()
        || proposal.provider_call_count != 0
        || proposal.network_call_count != 0
        || proposal.canonical_write_count != 0
        || proposal.proposal_sha256
            != digest_without(proposal, "proposal_sha256", "summary.proposal")?
    {
        return Err(invalid_state(
            "summary.proposal",
            "proposal is invalid or tampered",
        ));
    }
    Ok(())
}

fn validate_proposal(proposal: &SummaryProposalV1) -> Result<(), SummaryFailureV1> {
    validate_proposal_shape(proposal)?;
    if proposal.supported_count
        != count_fact_state(&proposal.decisions, SummaryFactDecisionStateV2::Supported)
        || proposal.abstention_count
            != count_fact_state(&proposal.decisions, SummaryFactDecisionStateV2::Abstain)
        || proposal.conflict_count
            != count_fact_state(&proposal.decisions, SummaryFactDecisionStateV2::Conflict)
    {
        return Err(invalid_state(
            "summary.proposal",
            "proposal state counters differ from exact decisions",
        ));
    }
    Ok(())
}

fn validate_proposal_chain(
    context: &CallContext,
    workspace: &Path,
    proposal: &SummaryProposalV1,
) -> Result<(), SummaryFailureV1> {
    let verification =
        load_p02_verification(context, workspace, &proposal.analysis_verification_ref)?;
    if verification.verification_sha256 != proposal.analysis_verification_sha256
        || verification.source_snapshot_exact_set_sha256
            != proposal.source_snapshot_exact_set_sha256
    {
        return Err(invalid_state(
            "summary.proposal",
            "proposal P02 verification identity drifted",
        ));
    }
    let pack = build_context(
        proposal.analysis_verification_ref.clone(),
        &verification,
        proposal.max_fact_count,
    )?;
    let job = build_job(&pack)?;
    if pack.context_pack_sha256 != proposal.context_pack_sha256
        || job.summary_job_sha256 != proposal.summary_job_sha256
    {
        return Err(invalid_state(
            "summary.proposal",
            "proposal context or job identity is not reproducible",
        ));
    }
    let facts = pack
        .facts
        .iter()
        .map(|fact| (fact.receipt_sha256.as_str(), fact))
        .collect::<std::collections::BTreeMap<_, _>>();
    let mut seen = BTreeSet::new();
    for decision in &proposal.decisions {
        let fact = facts
            .get(decision.fact_receipt_sha256.as_str())
            .ok_or_else(|| {
                invalid_state("summary.proposal", "proposal decision fact is unknown")
            })?;
        if !seen.insert(decision.fact_receipt_sha256.as_str())
            || decision.proposal_decision_sha256
                != digest_without(decision, "proposal_decision_sha256", "summary.proposal")?
            || (decision.state == SummaryFactDecisionStateV2::Supported
                && fact.resolution != VerifiedResolutionV1::ResolvedVerified)
        {
            return Err(invalid_state(
                "summary.proposal",
                "proposal decision is duplicate, tampered, or launders unresolved evidence",
            ));
        }
    }
    if seen.len() != facts.len() {
        return Err(invalid_state(
            "summary.proposal",
            "proposal decision denominator is incomplete",
        ));
    }
    Ok(())
}

fn validate_summary_verification(
    verification: &SummaryVerificationV1,
) -> Result<(), SummaryFailureV1> {
    let denominator = verification
        .verified_count
        .checked_add(verification.rejected_count)
        .and_then(|value| value.checked_add(verification.conflict_count));
    if verification.schema_version != SUMMARY_VERIFICATION_SCHEMA
        || denominator != Some(verification.decisions.len() as u64)
        || verification.provider_call_count != 0
        || verification.network_call_count != 0
        || verification.canonical_write_count != 0
        || verification.actor_independence_state != "declared_distinct_not_attested"
        || verification.verified_count
            != count_verification_state(
                &verification.decisions,
                SummaryVerificationDecisionStateV2::Verified,
            )
        || verification.rejected_count
            != count_verification_state(
                &verification.decisions,
                SummaryVerificationDecisionStateV2::Rejected,
            )
        || verification.conflict_count
            != count_verification_state(
                &verification.decisions,
                SummaryVerificationDecisionStateV2::Conflict,
            )
        || verification.summary_verification_sha256
            != digest_without(
                verification,
                "summary_verification_sha256",
                "summary.verification",
            )?
    {
        return Err(invalid_state(
            "summary.verification",
            "summary verification is invalid or tampered",
        ));
    }
    Ok(())
}

fn validate_summary_verification_chain(
    proposal: &SummaryProposalV1,
    verification: &SummaryVerificationV1,
) -> Result<(), SummaryFailureV1> {
    if verification.proposal_sha256 != proposal.proposal_sha256
        || verification.context_pack_sha256 != proposal.context_pack_sha256
        || verification.source_snapshot_exact_set_sha256
            != proposal.source_snapshot_exact_set_sha256
        || verification.verifier_id == proposal.proposer_id
    {
        return Err(invalid_state(
            "summary.verification",
            "verification is not independently bound to the proposal chain",
        ));
    }
    let job = build_verification_job(verification.proposal_ref.clone(), proposal)?;
    if job.verification_job_sha256 != verification.verification_job_sha256 {
        return Err(invalid_state(
            "summary.verification",
            "verification job identity drifted",
        ));
    }
    let expected = job
        .decisions
        .iter()
        .map(|decision| decision.proposal_decision_sha256.as_str())
        .collect::<BTreeSet<_>>();
    let mut seen = BTreeSet::new();
    for decision in &verification.decisions {
        if !expected.contains(decision.proposal_decision_sha256.as_str())
            || !seen.insert(decision.proposal_decision_sha256.as_str())
            || decision.decision_receipt_sha256
                != digest_without(decision, "decision_receipt_sha256", "summary.verification")?
        {
            return Err(invalid_state(
                "summary.verification",
                "verification decision identity or digest is invalid",
            ));
        }
    }
    if seen.len() != expected.len() {
        return Err(invalid_state(
            "summary.verification",
            "verification decision denominator is incomplete",
        ));
    }
    Ok(())
}

fn load_p02_verification(
    context: &CallContext,
    workspace: &Path,
    reference: &FileReceiptRef,
) -> Result<P02VerificationArtifactV1, SummaryFailureV1> {
    let encoded =
        validate_verification_chain_v1(context, workspace, reference).map_err(|error| {
            SummaryFailureV1 {
                code: error.code,
                stage: "context.pack",
                message: error.message,
                recovery_hint: "rebuild P02 verification from the exact candidate/source chain",
            }
        })?;
    let verification: P02VerificationArtifactV1 = serde_json::from_value(encoded)
        .map_err(|error| invalid_state("context.pack", error.to_string()))?;
    let expected_path = format!(
        ".gtkg/analysis/verifications/{}.json",
        digest_hex(&verification.verification_sha256)?
    );
    let count = verification
        .resolved_verified_count
        .checked_add(verification.ambiguous_count)
        .and_then(|value| value.checked_add(verification.locator_only_count));
    let fact_count = verification
        .adapter_verifications
        .iter()
        .map(|run| run.fact_receipts.len() as u64)
        .try_fold(0_u64, |total, value| total.checked_add(value));
    if verification.schema_version != P02_VERIFICATION_SCHEMA
        || reference.path != expected_path
        || verification.false_confirmed != 0
        || verification.target_execution_count != 0
        || verification.network_call_count != 0
        || verification.provider_call_count != 0
        || verification.canonical_write_count != 0
        || verification.current_write_count != 0
        || verification.a06_cross_adapter_status != "not_run"
        || verification.collision_check != "not_run"
        || verification.canonical_eligible
        || count != fact_count
        || verification.verification_sha256
            != digest_without(&verification, "verification_sha256", "context.pack")?
    {
        return Err(invalid_state(
            "context.pack",
            "P02 verification receipt is invalid or unsafe for context",
        ));
    }
    let mut resolved = 0_u64;
    let mut ambiguous = 0_u64;
    let mut locator = 0_u64;
    for run in &verification.adapter_verifications {
        if run.false_confirmed != 0 || run.canonical_write_count != 0 {
            return Err(invalid_state(
                "context.pack",
                "P02 per-adapter verification reports forbidden effects",
            ));
        }
        let run_resolved = run
            .fact_receipts
            .iter()
            .filter(|receipt| receipt.resolution == VerifiedResolutionV1::ResolvedVerified)
            .count() as u64;
        let run_ambiguous = run
            .fact_receipts
            .iter()
            .filter(|receipt| receipt.resolution == VerifiedResolutionV1::Ambiguous)
            .count() as u64;
        let run_locator = run
            .fact_receipts
            .iter()
            .filter(|receipt| receipt.resolution == VerifiedResolutionV1::LocatorOnly)
            .count() as u64;
        if run_resolved != run.resolved_verified_count
            || run_ambiguous != run.ambiguous_count
            || run_locator != run.locator_only_count
        {
            return Err(invalid_state(
                "context.pack",
                "P02 per-adapter verification denominator drifted",
            ));
        }
        resolved = resolved
            .checked_add(run_resolved)
            .ok_or_else(|| invalid_state("context.pack", "resolved denominator overflow"))?;
        ambiguous = ambiguous
            .checked_add(run_ambiguous)
            .ok_or_else(|| invalid_state("context.pack", "ambiguous denominator overflow"))?;
        locator = locator
            .checked_add(run_locator)
            .ok_or_else(|| invalid_state("context.pack", "locator denominator overflow"))?;
        for receipt in &run.fact_receipts {
            receipt
                .validate()
                .map_err(|error| invalid_state("context.pack", error.to_string()))?;
        }
    }
    if resolved != verification.resolved_verified_count
        || ambiguous != verification.ambiguous_count
        || locator != verification.locator_only_count
    {
        return Err(invalid_state(
            "context.pack",
            "P02 aggregate verification denominator drifted",
        ));
    }
    Ok(verification)
}

fn load_artifact<T>(
    context: &CallContext,
    workspace: &Path,
    reference: &FileReceiptRef,
    stage: &'static str,
) -> Result<T, SummaryFailureV1>
where
    T: for<'de> Deserialize<'de>,
{
    let path = context
        .resolve_workspace_receipt(workspace, reference)
        .map_err(context_failure)?;
    let read = read_bound_regular_file(context, &path).map_err(exact_failure)?;
    if read.sha256 != reference.sha256 {
        return Err(lock(stage, "artifact receipt digest mismatch"));
    }
    serde_json::from_slice(&read.bytes).map_err(|error| invalid_state(stage, error.to_string()))
}

fn publish<T: Serialize>(
    context: &CallContext,
    workspace: &Path,
    path: &Path,
    value: &T,
    stage: &'static str,
) -> Result<FileReceiptRef, SummaryFailureV1> {
    let path = publish_immutable_json(
        context,
        path,
        value,
        "summary.after_temp_sync_before_rename",
    )
    .map_err(|error| durable_failure(stage, error.kind, error.to_string()))?;
    let read = read_bound_regular_file(context, &path).map_err(exact_failure)?;
    let relative = path
        .strip_prefix(workspace)
        .map_err(|_| invalid_state(stage, "summary artifact escaped workspace"))?;
    Ok(FileReceiptRef {
        path: relative.to_string_lossy().into_owned(),
        sha256: read.sha256,
    })
}

fn validate_semantic_ref(
    reference: &FileReceiptRef,
    partition: &str,
    semantic_sha256: &str,
    stage: &'static str,
) -> Result<(), SummaryFailureV1> {
    let expected = format!(
        ".gtkg/summary/{partition}/{}.json",
        digest_hex(semantic_sha256)?
    );
    if reference.path != expected {
        return Err(invalid_state(
            stage,
            "summary semantic path binding mismatch",
        ));
    }
    Ok(())
}

fn digest_without<T: Serialize>(
    value: &T,
    field: &str,
    stage: &'static str,
) -> Result<String, SummaryFailureV1> {
    let mut encoded =
        serde_json::to_value(value).map_err(|error| invalid_state(stage, error.to_string()))?;
    encoded
        .as_object_mut()
        .ok_or_else(|| invalid_state(stage, "summary artifact must be an object"))?
        .remove(field);
    canonical_json_sha256(&encoded).map_err(|error| invalid_state(stage, error.to_string()))
}

fn digest_hex(value: &str) -> Result<&str, SummaryFailureV1> {
    value
        .strip_prefix("sha256:")
        .ok_or_else(|| invalid_state("summary.identity", "semantic digest is malformed"))
}

fn count_fact_state(values: &[ProposalDecisionV1], state: SummaryFactDecisionStateV2) -> u64 {
    values.iter().filter(|value| value.state == state).count() as u64
}

fn count_verification_state(
    values: &[SummaryVerificationDecisionReceiptV1],
    state: SummaryVerificationDecisionStateV2,
) -> u64 {
    values.iter().filter(|value| value.state == state).count() as u64
}

fn context_failure(error: ContextError) -> SummaryFailureV1 {
    SummaryFailureV1 {
        code: V2ErrorCode::PathEscape,
        stage: "summary.path",
        message: error.to_string(),
        recovery_hint: "use only caller-authorized workspace receipt paths",
    }
}

fn exact_failure(error: ExactReadFailure) -> SummaryFailureV1 {
    SummaryFailureV1 {
        code: match error.code {
            gtkg_protocol::ErrorCode::PathEscape => V2ErrorCode::PathEscape,
            gtkg_protocol::ErrorCode::SymlinkRejected => V2ErrorCode::SymlinkRejected,
            gtkg_protocol::ErrorCode::NotFound => V2ErrorCode::NotFound,
            _ => V2ErrorCode::Io,
        },
        stage: "summary.readback",
        message: format!("{}: {}", error.path.display(), error.message),
        recovery_hint: "repair the exact private receipt and retry",
    }
}

fn durable_failure(
    stage: &'static str,
    kind: DurableErrorKind,
    message: String,
) -> SummaryFailureV1 {
    SummaryFailureV1 {
        code: match kind {
            DurableErrorKind::Conflict => V2ErrorCode::InvalidState,
            DurableErrorKind::Unauthorized | DurableErrorKind::Unsafe => V2ErrorCode::PathEscape,
            DurableErrorKind::Invalid => V2ErrorCode::InvalidRequest,
            DurableErrorKind::Io => V2ErrorCode::Io,
        },
        stage,
        message,
        recovery_hint: "use immutable non-conflicting summary receipt storage",
    }
}

fn invalid(stage: &'static str, message: impl Into<String>) -> SummaryFailureV1 {
    SummaryFailureV1 {
        code: V2ErrorCode::InvalidRequest,
        stage,
        message: message.into(),
        recovery_hint: "use the exact closed P03 summary contract",
    }
}

fn invalid_state(stage: &'static str, message: impl Into<String>) -> SummaryFailureV1 {
    SummaryFailureV1 {
        code: V2ErrorCode::InvalidState,
        stage,
        message: message.into(),
        recovery_hint: "discard the inconsistent summary chain and replay from P02 verification",
    }
}

fn lock(stage: &'static str, message: impl Into<String>) -> SummaryFailureV1 {
    SummaryFailureV1 {
        code: V2ErrorCode::LockMismatch,
        stage,
        message: message.into(),
        recovery_hint: "use the exact current semantic digest returned by the predecessor",
    }
}
