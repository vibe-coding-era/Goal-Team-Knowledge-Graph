//! Typed authoring imports and Core-owned accepted OKF artifacts.
use super::knowledge::*;
use crate::CallContext;
use gtkg_protocol::{FileReceiptRef, v2::V2OperationId, v04::ArtifactPayload};
use serde::{Deserialize, Serialize};
use serde_json::Value;
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobRequest {
    pub verified_ref: FileReceiptRef,
    pub input: KnowledgeInput,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobArtifact {
    pub verified_ref: FileReceiptRef,
    pub job: KnowledgeJob,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProposalRequest {
    pub job_ref: FileReceiptRef,
    pub candidate: KnowledgeCandidate,
    pub execution_record: Option<GenerationExecutionRecord>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProposalArtifact {
    pub job_ref: FileReceiptRef,
    pub proposal: KnowledgeProposal,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewRequest {
    pub proposal_ref: FileReceiptRef,
    pub reviews: Vec<IndependentReview>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewArtifact {
    pub proposal_ref: FileReceiptRef,
    pub verification: KnowledgeVerification,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptedArtifact {
    pub review_ref: FileReceiptRef,
    pub job_ref: FileReceiptRef,
    pub accepted: AcceptedKnowledge,
    pub okf_ref: FileReceiptRef,
}

use super::{
    analysis,
    artifact::{self, QkResult},
    source,
};
use serde_json::json;
use std::path::Path;
pub fn load_verified_sources(
    context: &CallContext,
    root: &Path,
    verified_ref: &FileReceiptRef,
) -> QkResult<(analysis::VerifiedAnalysis, KnowledgeSources)> {
    let (v, c, l, archive, mut raw) = analysis::load_verified(context, root, verified_ref)?;
    for leaf in &l.leaves {
        if leaf.scope == source::Scope::Included
            && leaf.text == source::TextStatus::Extracted
            && !raw.contains_key(&leaf.path)
        {
            let sha = leaf.object_sha256.as_ref().ok_or("source_unavailable")?;
            raw.insert(
                leaf.path.clone(),
                source::read_object(&archive, sha).map_err(|e| e.to_string())?,
            );
        }
    }
    let s = KnowledgeSources {
        raw_sources: raw,
        context: v.context.clone(),
        call_proofs: c.proofs,
    };
    Ok((v, s))
}
fn sources(
    context: &CallContext,
    root: &Path,
    verified_ref: &FileReceiptRef,
    _input: &KnowledgeInput,
) -> QkResult<KnowledgeSources> {
    load_verified_sources(context, root, verified_ref).map(|(_, s)| s)
}
fn job(
    context: &CallContext,
    root: &Path,
    reference: &FileReceiptRef,
) -> QkResult<(JobArtifact, KnowledgeSources)> {
    let (j, _): (JobArtifact, _) = artifact::read(context, root, reference)?;
    let s = sources(context, root, &j.verified_ref, &j.job.input)?;
    if prepare_job(&j.job.input, &s).map_err(|e| e.to_string())? != j.job {
        return Err("job artifact was changed".into());
    }
    Ok((j, s))
}
fn proposal(
    context: &CallContext,
    root: &Path,
    reference: &FileReceiptRef,
) -> QkResult<(ProposalArtifact, JobArtifact, KnowledgeSources)> {
    let (p, _): (ProposalArtifact, _) = artifact::read(context, root, reference)?;
    let (j, s) = job(context, root, &p.job_ref)?;
    if submit_proposal(
        &j.job,
        &p.proposal.candidate,
        p.proposal.execution_record.as_ref(),
        &s,
    )
    .map_err(|e| e.to_string())?
        != p.proposal
    {
        return Err("proposal artifact was changed".into());
    }
    Ok((p, j, s))
}
pub fn accepted_chain(
    context: &CallContext,
    root: &Path,
    reference: &FileReceiptRef,
) -> QkResult<(
    AcceptedArtifact,
    JobArtifact,
    ProposalArtifact,
    ReviewArtifact,
    KnowledgeSources,
)> {
    let (a, _): (AcceptedArtifact, _) = artifact::read(context, root, reference)?;
    let (r, _): (ReviewArtifact, _) = artifact::read(context, root, &a.review_ref)?;
    let (p, j, s) = proposal(context, root, &r.proposal_ref)?;
    let current = accept(&j.job, &p.proposal, &r.verification, &s).map_err(|e| e.to_string())?;
    if current != a.accepted || a.job_ref != p.job_ref {
        return Err("accepted knowledge artifact mismatch".into());
    }
    let text = render_okf(&j.job, &current);
    let raw = crate::exact_read::read_bound_regular_file(context, &root.join(&a.okf_ref.path))
        .map_err(|e| e.message)?;
    a.okf_ref.validate().map_err(|e| e.to_string())?;
    if raw.sha256 != a.okf_ref.sha256 || raw.bytes != text.as_bytes() {
        return Err("accepted OKF/source chain mismatch".into());
    }
    Ok((a, j, p, r, s))
}
/// Canonical statement used by OKF and derived contexts; never uses free-form prose.
pub fn render_claim_body(body: &ClaimBody) -> String {
    match body {
        ClaimBody::Structural {
            predicate: Predicate::Declares { path, name, kind },
            polarity,
        } => format!(
            "{} 中{}声明 {} {}",
            path,
            if *polarity { "" } else { "未" },
            kind,
            name
        ),
        ClaimBody::Structural {
            predicate:
                Predicate::Calls {
                    source_path,
                    target_path,
                    target_id,
                    ..
                },
            ..
        } => format!(
            "{} 的调用点静态绑定到 {} 的 {}",
            source_path, target_path, target_id
        ),
        ClaimBody::Interpretive {
            proposition,
            epistemic,
            version_condition,
        } => format!(
            "{}（{:?}；条件：{}）",
            proposition, epistemic, version_condition
        ),
    }
}
pub fn render_okf(job: &KnowledgeJob, accepted: &AcceptedKnowledge) -> String {
    let mut text = format!(
        "---\ntype: accepted_knowledge\nanalysis_context_digest: {}\njob_digest: {}\nknowledge_ready: {}\nllm_qa_validated: false\n---\n\n# 已接受知识\n\n保证：{}\n\n",
        job.analysis_context_digest,
        job.job_digest,
        accepted.knowledge_ready,
        accepted.execution_assurance
    );
    for claim in &accepted.supported_claims {
        let body = render_claim_body(&claim.body);
        text.push_str(&format!("## {}\n\n{}\n\n", claim.understanding_item, body));
        for c in &claim.citations {
            text.push_str(&format!(
                "- 来源：`{}`，行 {}–{}，字节 {}–{}，{}\n",
                c.path,
                c.span.line_start,
                c.span.line_end,
                c.span.byte_start,
                c.span.byte_end,
                c.file_sha256
            ));
        }
        text.push('\n');
    }
    text
}
pub fn execute(
    context: &CallContext,
    payload: &ArtifactPayload,
    op: V2OperationId,
) -> QkResult<Value> {
    let root = artifact::workspace(context, &payload.workspace_root)?;
    match op {
        V2OperationId::SummaryJobNext => {
            let (i, _): (JobRequest, _) = artifact::read(context, &root, &payload.artifact_ref)?;
            let s = sources(context, &root, &i.verified_ref, &i.input)?;
            let j = prepare_job(&i.input, &s).map_err(|e| e.to_string())?;
            let out = JobArtifact {
                verified_ref: i.verified_ref,
                job: j,
            };
            Ok(
                json!({"status":"needs_authoring","job_artifact":out,"persistence":"host_staged_input","execution_evidence":"not_run"}),
            )
        }
        V2OperationId::SummaryProposalSubmit => {
            let (i, _): (ProposalRequest, _) =
                artifact::read(context, &root, &payload.artifact_ref)?;
            let (j, s) = job(context, &root, &i.job_ref)?;
            let proposal = submit_proposal(&j.job, &i.candidate, i.execution_record.as_ref(), &s)
                .map_err(|e| e.to_string())?;
            let state = proposal.state.clone();
            let p = ProposalArtifact {
                job_ref: i.job_ref,
                proposal,
            };
            let r = artifact::publish(context, &root, "proposals", &p)?;
            Ok(json!({"status":state,"artifact_ref":r}))
        }
        V2OperationId::SummaryVerificationNext => {
            let (p, _, _) = proposal(context, &root, &payload.artifact_ref)?;
            let digests=p.proposal.candidate.claims.iter().map(|c|Ok(json!({"claim_id":c.claim_id,"claim_digest":claim_digest(c).map_err(|e|e.to_string())?}))).collect::<QkResult<Vec<_>>>()?;
            Ok(
                json!({"status":"needs_two_independent_reviews","proposal_digest":p.proposal.proposal_digest,"claims":digests}),
            )
        }
        V2OperationId::SummaryVerificationSubmit => {
            let (i, _): (ReviewRequest, _) = artifact::read(context, &root, &payload.artifact_ref)?;
            let (p, j, s) = proposal(context, &root, &i.proposal_ref)?;
            let verification =
                review_proposal(&j.job, &p.proposal, &i.reviews, &s).map_err(|e| e.to_string())?;
            let r = artifact::publish(
                context,
                &root,
                "knowledge-reviews",
                &ReviewArtifact {
                    proposal_ref: i.proposal_ref,
                    verification,
                },
            )?;
            Ok(json!({"status":"reviewed","artifact_ref":r}))
        }
        V2OperationId::SummaryAcceptV2 => {
            let (r, _): (ReviewArtifact, _) =
                artifact::read(context, &root, &payload.artifact_ref)?;
            let (p, j, s) = proposal(context, &root, &r.proposal_ref)?;
            let accepted =
                accept(&j.job, &p.proposal, &r.verification, &s).map_err(|e| e.to_string())?;
            let okf = artifact::publish_text(
                context,
                &root,
                "knowledge",
                &render_okf(&j.job, &accepted),
            )?;
            let a = AcceptedArtifact {
                review_ref: payload.artifact_ref.clone(),
                job_ref: p.job_ref,
                accepted,
                okf_ref: okf.clone(),
            };
            let reference = artifact::publish(context, &root, "accepted", &a)?;
            Ok(
                json!({"status":"accepted_declared_scope","artifact_ref":reference,"okf_ref":okf,"knowledge_ready":a.accepted.knowledge_ready,"llm_qa_validated":false,"execution_assurance":a.accepted.execution_assurance}),
            )
        }
        _ => Err("operation outside authoring partition".into()),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ViewsRequest {
    pub verified_ref: FileReceiptRef,
    pub input: ProjectKnowledgeInput,
    pub accepted_refs: Vec<FileReceiptRef>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ViewsArtifact {
    pub verified_ref: FileReceiptRef,
    pub input: ProjectKnowledgeInput,
    pub accepted_refs: Vec<FileReceiptRef>,
    pub views: ProjectKnowledgeViews,
}
pub fn load_chain(
    context: &CallContext,
    root: &Path,
    review_ref: &FileReceiptRef,
) -> QkResult<KnowledgeChain> {
    let (r, _): (ReviewArtifact, _) = artifact::read(context, root, review_ref)?;
    let (p, j, s) = proposal(context, root, &r.proposal_ref)?;
    accept(&j.job, &p.proposal, &r.verification, &s).map_err(|e| e.to_string())?;
    Ok(KnowledgeChain {
        job: j.job,
        proposal: p.proposal,
        verification: r.verification,
    })
}
pub fn replay_views(
    context: &CallContext,
    root: &Path,
    reference: &FileReceiptRef,
) -> QkResult<ViewsArtifact> {
    let (v, _): (ViewsArtifact, _) = artifact::read(context, root, reference)?;
    let computed = make_views(
        context,
        root,
        &ViewsRequest {
            verified_ref: v.verified_ref.clone(),
            input: v.input.clone(),
            accepted_refs: v.accepted_refs.clone(),
        },
    )?;
    if computed.views != v.views {
        return Err("project views/source/accepted chain mismatch".into());
    }
    Ok(v)
}
fn make_views(context: &CallContext, root: &Path, input: &ViewsRequest) -> QkResult<ViewsArtifact> {
    let (_, s) = load_verified_sources(context, root, &input.verified_ref)?;
    let mut chains = vec![];
    for reference in &input.accepted_refs {
        let (a, j, p, r, _) = accepted_chain(context, root, reference)?;
        if j.verified_ref != input.verified_ref {
            return Err("mixed source revisions in project knowledge".into());
        }
        let _ = a;
        chains.push(KnowledgeChain {
            job: j.job,
            proposal: p.proposal,
            verification: r.verification,
        });
    }
    let views = project_views(&input.input, &chains, &s).map_err(|e| e.to_string())?;
    Ok(ViewsArtifact {
        verified_ref: input.verified_ref.clone(),
        input: input.input.clone(),
        accepted_refs: input.accepted_refs.clone(),
        views,
    })
}
pub fn create_views(context: &CallContext, payload: &ArtifactPayload) -> QkResult<Value> {
    let root = artifact::workspace(context, &payload.workspace_root)?;
    let (i, _): (ViewsRequest, _) = artifact::read(context, &root, &payload.artifact_ref)?;
    let v = make_views(context, &root, &i)?;
    let r = artifact::publish(context, &root, "project-views", &v)?;
    Ok(json!({"artifact_ref":r,"status":"projected_declared_scope","views":v.views}))
}
