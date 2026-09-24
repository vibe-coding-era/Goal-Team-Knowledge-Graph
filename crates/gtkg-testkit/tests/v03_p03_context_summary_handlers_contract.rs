//! P03 immutable contract: sealed P02 verification -> claim-free context ->
//! proposal -> independent verification -> non-canonical accepted candidate.

use std::fs;
use std::path::Path;

use gtkg_core::{CallContext, Dispatcher, EffectPolicy, TransportKind};
use gtkg_protocol::FileReceiptRef;
use gtkg_protocol::v2::{
    CallabilityV2, OperationAvailabilityV2, OperationRequestV2, V2_PUBLIC_OPERATIONS, V2ErrorCode,
    V2OperationId, v2_operation_definition, v2_operation_request_schema,
};
use serde_json::{Value, json};

const P03_OPERATIONS: [V2OperationId; 6] = [
    V2OperationId::ContextPack,
    V2OperationId::SummaryJobNext,
    V2OperationId::SummaryProposalSubmit,
    V2OperationId::SummaryVerificationNext,
    V2OperationId::SummaryVerificationSubmit,
    V2OperationId::SummaryAcceptV2,
];

#[test]
fn p03_promotes_exactly_six_handlers_with_closed_payloads() {
    for operation in P03_OPERATIONS {
        let definition = v2_operation_definition(operation).unwrap();
        assert_eq!(
            definition.availability,
            OperationAvailabilityV2::Implemented
        );
        assert_eq!(definition.callability, CallabilityV2::Callable);
        let payload = &v2_operation_request_schema(operation)["properties"]["payload"];
        assert_eq!(payload["type"], "object");
        assert_eq!(payload["additionalProperties"], false);
    }
    assert_eq!(
        V2_PUBLIC_OPERATIONS
            .iter()
            .filter(|definition| definition.availability == OperationAvailabilityV2::Implemented)
            .count(),
        37
    );
    assert_eq!(
        v2_operation_definition(V2OperationId::BuildFinalizeV2)
            .unwrap()
            .availability,
        OperationAvailabilityV2::NotImplemented
    );
}

#[test]
fn p03_full_flow_preserves_abstention_and_a06_not_run_without_canonical_write() {
    let fixture = Fixture::new();
    let context = fixture.context(EffectPolicy::WorkspaceWrite);
    let packed = Dispatcher
        .execute_v2(
            &fixture.context(EffectPolicy::ReadOnly),
            fixture.context_request("p03-pack"),
        )
        .unwrap();
    assert_eq!(packed.result["context_pack"]["claim_count"], 0);
    assert_eq!(packed.result["context_pack"]["claim_free"], true);
    assert_eq!(
        packed.result["context_pack"]["a06_cross_adapter_status"],
        "not_run"
    );
    assert_eq!(packed.result["canonical_write_count"], 0);

    let job = Dispatcher
        .execute_v2(
            &fixture.context(EffectPolicy::ReadOnly),
            OperationRequestV2::new(
                "summary.job.next",
                "p03-job",
                json!({
                    "workspace_root": fixture.root(),
                    "analysis_verification_ref": fixture.verification_ref,
                    "max_fact_count": 128,
                    "expected_context_pack_sha256": packed.result["context_pack_sha256"]
                }),
            ),
        )
        .unwrap();
    assert_eq!(job.result["summary_job"]["claim_free"], true);
    assert_eq!(job.result["provider_call_count"], 0);

    let decisions = packed.result["context_pack"]["facts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|fact| {
            json!({
                "fact_receipt_sha256": fact["receipt_sha256"],
                "state": if fact["resolution"] == "resolved_verified" {"supported"} else {"abstain"},
                "reason": if fact["resolution"] == "resolved_verified" {"exact_source_replay"} else {"not_resolved"}
            })
        })
        .collect::<Vec<_>>();
    let proposal = Dispatcher
        .execute_v2(
            &context,
            OperationRequestV2::new(
                "summary.proposal.submit",
                "p03-proposal",
                json!({
                    "workspace_root": fixture.root(),
                    "analysis_verification_ref": fixture.verification_ref,
                    "context_pack_sha256": packed.result["context_pack_sha256"],
                    "summary_job_sha256": job.result["summary_job_sha256"],
                    "proposer_id": "local-proposer",
                    "summary_text": "Verified source facts with explicit abstention.",
                    "decisions": decisions
                }),
            ),
        )
        .unwrap();
    let proposal_ref = fixture.assert_receipt(&proposal.result["proposal_ref"]);
    assert_eq!(proposal.result["provider_call_count"], 0);
    assert_eq!(proposal.result["canonical_write_count"], 0);

    let verification_job = Dispatcher
        .execute_v2(
            &fixture.context(EffectPolicy::ReadOnly),
            OperationRequestV2::new(
                "summary.verification.next",
                "p03-verification-job",
                json!({"workspace_root": fixture.root(), "proposal_ref": proposal_ref}),
            ),
        )
        .unwrap();
    let verification_decisions = verification_job.result["verification_job"]["decisions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|decision| {
            json!({
                "proposal_decision_sha256": decision["proposal_decision_sha256"],
                "state": "verified",
                "reason": "independent_exact_receipt_check"
            })
        })
        .collect::<Vec<_>>();
    let verified = Dispatcher
        .execute_v2(
            &context,
            OperationRequestV2::new(
                "summary.verification.submit",
                "p03-verification-submit",
                json!({
                    "workspace_root": fixture.root(),
                    "proposal_ref": proposal_ref,
                    "verification_job_sha256": verification_job.result["verification_job_sha256"],
                    "verifier_id": "independent-verifier",
                    "decisions": verification_decisions
                }),
            ),
        )
        .unwrap();
    let summary_verification_ref =
        fixture.assert_receipt(&verified.result["summary_verification_ref"]);
    let accepted = Dispatcher
        .execute_v2(
            &context,
            OperationRequestV2::new(
                "summary.accept.v2",
                "p03-accept",
                json!({
                    "workspace_root": fixture.root(),
                    "proposal_ref": proposal_ref,
                    "summary_verification_ref": summary_verification_ref
                }),
            ),
        )
        .unwrap();
    fixture.assert_receipt(&accepted.result["accepted_summary_ref"]);
    assert_eq!(accepted.result["status"], "candidate_accepted");
    assert_eq!(accepted.result["a06_cross_adapter_status"], "not_run");
    assert_eq!(accepted.result["canonical_eligible"], false);
    assert_eq!(accepted.result["canonical_write_count"], 0);
    assert_eq!(accepted.result["current_write_count"], 0);
    assert_eq!(accepted.result["provider_call_count"], 0);
    assert_eq!(accepted.result["network_call_count"], 0);
}

#[test]
fn p03_conflict_tamper_and_non_independent_verifier_fail_closed() {
    let fixture = Fixture::new();
    let packed = Dispatcher
        .execute_v2(
            &fixture.context(EffectPolicy::ReadOnly),
            fixture.context_request("p03-negative-pack"),
        )
        .unwrap();
    let job = Dispatcher
        .execute_v2(
            &fixture.context(EffectPolicy::ReadOnly),
            OperationRequestV2::new(
                "summary.job.next",
                "p03-negative-job",
                json!({
                    "workspace_root": fixture.root(),
                    "analysis_verification_ref": fixture.verification_ref,
                    "max_fact_count": 128,
                    "expected_context_pack_sha256": packed.result["context_pack_sha256"]
                }),
            ),
        )
        .unwrap();
    let facts = packed.result["context_pack"]["facts"].as_array().unwrap();
    let decisions = facts
        .iter()
        .enumerate()
        .map(|(index, fact)| {
            json!({
                "fact_receipt_sha256": fact["receipt_sha256"],
                "state": if index == 0 {"conflict"} else {"abstain"},
                "reason": "independent_conflict"
            })
        })
        .collect::<Vec<_>>();
    let proposal = Dispatcher
        .execute_v2(
            &fixture.context(EffectPolicy::WorkspaceWrite),
            OperationRequestV2::new(
                "summary.proposal.submit",
                "p03-conflict-proposal",
                json!({
                    "workspace_root": fixture.root(),
                    "analysis_verification_ref": fixture.verification_ref,
                    "context_pack_sha256": packed.result["context_pack_sha256"],
                    "summary_job_sha256": job.result["summary_job_sha256"],
                    "proposer_id": "same-identity",
                    "summary_text": "Conflict must block acceptance.",
                    "decisions": decisions
                }),
            ),
        )
        .unwrap();
    let proposal_ref = fixture.assert_receipt(&proposal.result["proposal_ref"]);
    let next = Dispatcher
        .execute_v2(
            &fixture.context(EffectPolicy::ReadOnly),
            OperationRequestV2::new(
                "summary.verification.next",
                "p03-conflict-next",
                json!({"workspace_root": fixture.root(), "proposal_ref": proposal_ref}),
            ),
        )
        .unwrap();
    let same_identity = Dispatcher
        .execute_v2(
            &fixture.context(EffectPolicy::WorkspaceWrite),
            OperationRequestV2::new(
                "summary.verification.submit",
                "p03-same-verifier",
                json!({
                    "workspace_root": fixture.root(),
                    "proposal_ref": proposal_ref,
                    "verification_job_sha256": next.result["verification_job_sha256"],
                    "verifier_id": "same-identity",
                    "decisions": []
                }),
            ),
        )
        .unwrap_err();
    assert_eq!(same_identity.error.code, V2ErrorCode::InvalidRequest);

    let wrong_context = Dispatcher
        .execute_v2(
            &fixture.context(EffectPolicy::WorkspaceWrite),
            OperationRequestV2::new(
                "summary.proposal.submit",
                "p03-context-tamper",
                json!({
                    "workspace_root": fixture.root(),
                    "analysis_verification_ref": fixture.verification_ref,
                    "context_pack_sha256": digest('f'),
                    "summary_job_sha256": job.result["summary_job_sha256"],
                    "proposer_id": "other",
                    "summary_text": "tamper",
                    "decisions": []
                }),
            ),
        )
        .unwrap_err();
    assert_eq!(wrong_context.error.code, V2ErrorCode::LockMismatch);
}

#[test]
fn p03_write_handlers_respect_read_only_and_unknown_fields() {
    let fixture = Fixture::new();
    let mut invalid = fixture.context_request("p03-unknown");
    invalid.payload["unexpected"] = json!(true);
    let unknown = Dispatcher
        .execute_v2(&fixture.context(EffectPolicy::ReadOnly), invalid)
        .unwrap_err();
    assert_eq!(unknown.error.code, V2ErrorCode::InvalidRequest);
    assert_eq!(unknown.error.stage, "payload-schema");

    let denied = Dispatcher
        .execute_v2(
            &fixture.context(EffectPolicy::ReadOnly),
            OperationRequestV2::new(
                "summary.proposal.submit",
                "p03-readonly-denied",
                json!({
                    "workspace_root": fixture.root(),
                    "analysis_verification_ref": fixture.verification_ref,
                    "context_pack_sha256": digest('1'),
                    "summary_job_sha256": digest('2'),
                    "proposer_id": "p",
                    "summary_text": "x",
                    "decisions": []
                }),
            ),
        )
        .unwrap_err();
    assert_eq!(denied.error.code, V2ErrorCode::SideEffectDenied);
}

struct Fixture {
    workspace: tempfile::TempDir,
    verification_ref: FileReceiptRef,
}

impl Fixture {
    fn new() -> Self {
        let workspace = tempfile::tempdir().unwrap();
        let source_root = workspace.path().join("source");
        fs::create_dir(&source_root).unwrap();
        fs::write(
            source_root.join("lib.rs"),
            "fn main() { helper(); }\nfn helper() {}\n",
        )
        .unwrap();
        let context = CallContext::restricted(
            TransportKind::Test,
            vec![workspace.path().to_path_buf()],
            EffectPolicy::WorkspaceWrite,
        )
        .unwrap();
        let snapshot_path = workspace.path().join(".gtkg/source-snapshots/source.json");
        let captured = Dispatcher
            .execute_v2(
                &context,
                OperationRequestV2::new(
                    "source.capture",
                    "p03-source",
                    json!({
                        "capture_mode": "directory_exact",
                        "repository_id": "p03",
                        "source_root": source_root,
                        "output_path": snapshot_path,
                    }),
                ),
            )
            .unwrap();
        let snapshot_ref = FileReceiptRef {
            path: ".gtkg/source-snapshots/source.json".to_owned(),
            sha256: captured.result["snapshot_ref"]["artifact_sha256"]
                .as_str()
                .unwrap()
                .to_owned(),
        };
        let plan = Dispatcher
            .execute_v2(
                &context,
                OperationRequestV2::new(
                    "analysis.plan",
                    "p03-plan",
                    json!({
                        "workspace_root": workspace.path(),
                        "source_root": source_root,
                        "source_snapshot_ref": snapshot_ref,
                        "adapter_inputs": [{"adapter_kind": "native", "logical_path": "lib.rs"}]
                    }),
                ),
            )
            .unwrap();
        let plan_ref: FileReceiptRef =
            serde_json::from_value(plan.result["plan_ref"].clone()).unwrap();
        let build = Dispatcher
            .execute_v2(
                &context,
                OperationRequestV2::new(
                    "analysis.build",
                    "p03-build",
                    json!({"workspace_root": workspace.path(), "plan_ref": plan_ref}),
                ),
            )
            .unwrap();
        let candidate_ref: FileReceiptRef =
            serde_json::from_value(build.result["candidate_ref"].clone()).unwrap();
        let verify = Dispatcher
            .execute_v2(
                &context,
                OperationRequestV2::new(
                    "analysis.verify",
                    "p03-verify",
                    json!({"workspace_root": workspace.path(), "candidate_ref": candidate_ref}),
                ),
            )
            .unwrap();
        Self {
            workspace,
            verification_ref: serde_json::from_value(verify.result["verification_ref"].clone())
                .unwrap(),
        }
    }

    fn root(&self) -> &Path {
        self.workspace.path()
    }

    fn context(&self, policy: EffectPolicy) -> CallContext {
        CallContext::restricted(TransportKind::Test, vec![self.root().to_path_buf()], policy)
            .unwrap()
    }

    fn context_request(&self, request_id: &str) -> OperationRequestV2 {
        OperationRequestV2::new(
            "context.pack",
            request_id,
            json!({
                "workspace_root": self.root(),
                "analysis_verification_ref": self.verification_ref,
                "max_fact_count": 128
            }),
        )
    }

    fn assert_receipt(&self, value: &Value) -> FileReceiptRef {
        let reference: FileReceiptRef = serde_json::from_value(value.clone()).unwrap();
        assert!(self.root().join(&reference.path).is_file());
        reference
    }
}

fn digest(character: char) -> String {
    format!("sha256:{}", character.to_string().repeat(64))
}
