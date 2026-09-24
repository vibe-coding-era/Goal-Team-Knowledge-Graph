//! Reuses frozen P04/A06 integration fixtures to construct I00's real inputs.
//!
//! The wrappers deliberately keep the existing task files immutable: I00 only
//! consumes a finalized P02/P03 rebuild, a migrated v1 candidate, and the
//! sealed A06 gate that those predecessors already prove independently.

use std::fs;

use gtkg_core::{CallContext, Dispatcher, EffectPolicy, TransportKind};
use gtkg_protocol::FileReceiptRef;
use gtkg_protocol::v2::OperationRequestV2;
use serde_json::{Value, json};

#[allow(clippy::assertions_on_constants, dead_code)]
mod a06_sealed_gate {
    include!("../v03_a06_sealed_input_successor.rs");

    pub(super) fn materialize() -> gtkg_core::v03::adapter::verifier::AdapterGateReceiptV1 {
        let trusted_fixture = persisted_fixture();
        let imports = FiveImports::load();
        let actual = ActualAdapterInputs::load();
        let submissions = strict_submissions(&imports, &actual);
        verify_adapter_gate_sealed_strict_v1(
            &submissions,
            &trusted_fixture,
            "gtkg.verifier/a06-sealed-strict",
        )
        .unwrap()
    }
}

pub(crate) fn finalized_candidate() -> (tempfile::TempDir, gtkg_protocol::FileReceiptRef) {
    let workspace = tempfile::tempdir().unwrap();
    let source = workspace.path().join("source");
    fs::create_dir(&source).unwrap();
    fs::write(
        source.join("lib.rs"),
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
    let captured = execute(
        &context,
        "source.capture",
        "i00-source",
        json!({
            "capture_mode": "directory_exact",
            "repository_id": "i00",
            "source_root": source,
            "output_path": snapshot_path
        }),
    );
    let snapshot_ref = FileReceiptRef {
        path: ".gtkg/source-snapshots/source.json".to_owned(),
        sha256: captured.result["snapshot_ref"]["artifact_sha256"]
            .as_str()
            .unwrap()
            .to_owned(),
    };
    let plan = execute(
        &context,
        "analysis.plan",
        "i00-plan",
        json!({
            "workspace_root": workspace.path(),
            "source_root": workspace.path().join("source"),
            "source_snapshot_ref": snapshot_ref,
            "adapter_inputs": [{"adapter_kind": "native", "logical_path": "lib.rs"}]
        }),
    );
    let plan_ref: FileReceiptRef = serde_json::from_value(plan.result["plan_ref"].clone()).unwrap();
    let build = execute(
        &context,
        "analysis.build",
        "i00-build",
        json!({"workspace_root": workspace.path(), "plan_ref": plan_ref}),
    );
    let candidate_ref: FileReceiptRef =
        serde_json::from_value(build.result["candidate_ref"].clone()).unwrap();
    let analysis = execute(
        &context,
        "analysis.verify",
        "i00-analysis",
        json!({"workspace_root": workspace.path(), "candidate_ref": candidate_ref}),
    );
    let analysis_ref: FileReceiptRef =
        serde_json::from_value(analysis.result["verification_ref"].clone()).unwrap();
    let packed = execute(
        &context,
        "context.pack",
        "i00-pack",
        json!({
            "workspace_root": workspace.path(),
            "analysis_verification_ref": analysis_ref,
            "max_fact_count": 128
        }),
    );
    let job = execute(
        &context,
        "summary.job.next",
        "i00-job",
        json!({
            "workspace_root": workspace.path(),
            "analysis_verification_ref": analysis_ref,
            "max_fact_count": 128,
            "expected_context_pack_sha256": packed.result["context_pack_sha256"]
        }),
    );
    let decisions = packed.result["context_pack"]["facts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|fact| {
            json!({
                "fact_receipt_sha256": fact["receipt_sha256"],
                "state": "supported",
                "reason": "exact_source_replay"
            })
        })
        .collect::<Vec<_>>();
    let proposal = execute(
        &context,
        "summary.proposal.submit",
        "i00-proposal",
        json!({
            "workspace_root": workspace.path(),
            "analysis_verification_ref": analysis_ref,
            "context_pack_sha256": packed.result["context_pack_sha256"],
            "summary_job_sha256": job.result["summary_job_sha256"],
            "proposer_id": "i00-proposer",
            "summary_text": "Candidate facts only.",
            "decisions": decisions
        }),
    );
    let proposal_ref: FileReceiptRef =
        serde_json::from_value(proposal.result["proposal_ref"].clone()).unwrap();
    let verification_job = execute(
        &context,
        "summary.verification.next",
        "i00-verification-job",
        json!({"workspace_root": workspace.path(), "proposal_ref": proposal_ref}),
    );
    let verification_decisions = verification_job.result["verification_job"]["decisions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|decision| {
            json!({
                "proposal_decision_sha256": decision["proposal_decision_sha256"],
                "state": "verified",
                "reason": "reviewed"
            })
        })
        .collect::<Vec<_>>();
    let summary_verification = execute(
        &context,
        "summary.verification.submit",
        "i00-verification",
        json!({
            "workspace_root": workspace.path(),
            "proposal_ref": proposal_ref,
            "verification_job_sha256": verification_job.result["verification_job_sha256"],
            "verifier_id": "i00-verifier",
            "decisions": verification_decisions
        }),
    );
    let summary_verification_ref: FileReceiptRef =
        serde_json::from_value(summary_verification.result["summary_verification_ref"].clone())
            .unwrap();
    let accepted = execute(
        &context,
        "summary.accept.v2",
        "i00-accept",
        json!({
            "workspace_root": workspace.path(),
            "proposal_ref": proposal_ref,
            "summary_verification_ref": summary_verification_ref
        }),
    );
    let accepted_ref: FileReceiptRef =
        serde_json::from_value(accepted.result["accepted_summary_ref"].clone()).unwrap();
    let finalized = execute(
        &context,
        "build.finalize.v2",
        "i00-finalize-rebuild",
        json!({
            "workspace_root": workspace.path(),
            "analysis_verification_ref": analysis_ref,
            "accepted_summary_ref": accepted_ref,
            "bundle_version": "i00-candidate"
        }),
    );
    let bundle_ref: FileReceiptRef =
        serde_json::from_value(finalized.result["bundle_ref"].clone()).unwrap();
    assert!(workspace.path().join(&bundle_ref.path).is_file());
    (workspace, bundle_ref)
}

pub(crate) fn sealed_a06_gate() -> gtkg_core::v03::adapter::verifier::AdapterGateReceiptV1 {
    a06_sealed_gate::materialize()
}

fn execute(
    context: &CallContext,
    operation_id: &str,
    request_id: &str,
    payload: Value,
) -> gtkg_protocol::v2::OperationResponseV2 {
    Dispatcher
        .execute_v2(
            context,
            OperationRequestV2::new(operation_id, request_id, payload),
        )
        .unwrap()
}
