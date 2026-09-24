//! P04 immutable contract: candidate-only finalize, event-sourced run state,
//! bundle/migration validation, and replay-only snapshots.

use std::fs;
use std::path::Path;

use gtkg_core::file_model::tree_sha256;
use gtkg_core::{CallContext, Dispatcher, EffectPolicy, TransportKind};
use gtkg_protocol::FileReceiptRef;
use gtkg_protocol::v2::{
    OperationAvailabilityV2, OperationRequestV2, V2_PUBLIC_OPERATIONS, V2ErrorCode, V2OperationId,
    v2_operation_definition, v2_operation_request_schema,
};
use serde_json::{Value, json};

const P04_OPERATIONS: [V2OperationId; 9] = [
    V2OperationId::BuildFinalizeV2,
    V2OperationId::RunGet,
    V2OperationId::RunCancel,
    V2OperationId::BundleVerify,
    V2OperationId::BundleCompare,
    V2OperationId::BundleMigrateV1ToV2,
    V2OperationId::SnapshotCreate,
    V2OperationId::SnapshotVerify,
    V2OperationId::SnapshotRestore,
];

#[test]
fn p04_promotes_exactly_nine_closed_handlers_and_completes_availability_only() {
    for operation in P04_OPERATIONS {
        assert_eq!(
            v2_operation_definition(operation).unwrap().availability,
            OperationAvailabilityV2::Implemented
        );
        let payload = &v2_operation_request_schema(operation)["properties"]["payload"];
        assert_eq!(payload["type"], "object");
        assert_eq!(payload["additionalProperties"], false);
    }
    assert_eq!(
        V2_PUBLIC_OPERATIONS
            .iter()
            .filter(|definition| definition.availability == OperationAvailabilityV2::Implemented)
            .count(),
        46
    );
}

#[test]
fn p04_finalize_run_bundle_snapshot_and_replay_remain_non_canonical() {
    let fixture = Fixture::new();
    let context = fixture.context(EffectPolicy::WorkspaceWrite);
    let finalized = Dispatcher
        .execute_v2(&context, fixture.finalize_request("p04-finalize"))
        .unwrap();
    assert_eq!(finalized.result["status"], "candidate_ready");
    assert_eq!(finalized.result["canonical_eligible"], false);
    assert_eq!(finalized.result["a06_cross_adapter_status"], "not_run");
    assert_eq!(finalized.result["current_write_count"], 0);
    let bundle_ref = fixture.assert_receipt(&finalized.result["bundle_ref"]);
    let run_ref = fixture.assert_receipt(&finalized.result["run_ref"]);

    let run = Dispatcher
        .execute_v2(
            &fixture.context(EffectPolicy::ReadOnly),
            OperationRequestV2::new(
                "run.get",
                "p04-run-get",
                json!({"workspace_root": fixture.root(), "run_ref": run_ref}),
            ),
        )
        .unwrap();
    assert_eq!(run.result["status"], "candidate_ready");
    let cancelled = Dispatcher
        .execute_v2(
            &context,
            OperationRequestV2::new(
                "run.cancel",
                "p04-run-cancel",
                json!({
                    "workspace_root": fixture.root(),
                    "run_ref": run_ref,
                    "expected_run_sha256": run_ref.sha256
                }),
            ),
        )
        .unwrap();
    assert_eq!(cancelled.result["status"], "cancelled");
    let cancelled_ref = fixture.assert_receipt(&cancelled.result["run_ref"]);
    let cancelled_get = Dispatcher
        .execute_v2(
            &fixture.context(EffectPolicy::ReadOnly),
            OperationRequestV2::new(
                "run.get",
                "p04-run-get-cancelled",
                json!({"workspace_root": fixture.root(), "run_ref": cancelled_ref}),
            ),
        )
        .unwrap();
    assert_eq!(cancelled_get.result["status"], "cancelled");

    let verified = Dispatcher
        .execute_v2(
            &context,
            OperationRequestV2::new(
                "bundle.verify",
                "p04-bundle-verify",
                json!({"workspace_root": fixture.root(), "bundle_ref": bundle_ref}),
            ),
        )
        .unwrap();
    assert_eq!(verified.result["verified"], true);
    assert_eq!(verified.result["canonical_eligible"], false);
    fixture.assert_receipt(&verified.result["bundle_verification_ref"]);

    let compared = Dispatcher
        .execute_v2(
            &fixture.context(EffectPolicy::ReadOnly),
            OperationRequestV2::new(
                "bundle.compare",
                "p04-bundle-compare",
                json!({
                    "workspace_root": fixture.root(),
                    "left_bundle_ref": bundle_ref,
                    "right_bundle_ref": bundle_ref
                }),
            ),
        )
        .unwrap();
    assert_eq!(compared.result["equal"], true);
    assert_eq!(compared.result["write_count"], 0);

    let snapshot = Dispatcher
        .execute_v2(
            &context,
            OperationRequestV2::new(
                "snapshot.create",
                "p04-snapshot-create",
                json!({
                    "workspace_root": fixture.root(),
                    "bundle_ref": bundle_ref,
                    "snapshot_version": "0.3.0-candidate"
                }),
            ),
        )
        .unwrap();
    let snapshot_ref = fixture.assert_receipt(&snapshot.result["snapshot_ref"]);
    assert_eq!(snapshot.result["replay_only"], true);
    let snapshot_verified = Dispatcher
        .execute_v2(
            &context,
            OperationRequestV2::new(
                "snapshot.verify",
                "p04-snapshot-verify",
                json!({"workspace_root": fixture.root(), "snapshot_ref": snapshot_ref}),
            ),
        )
        .unwrap();
    fixture.assert_receipt(&snapshot_verified.result["snapshot_verification_ref"]);
    let restored = Dispatcher
        .execute_v2(
            &context,
            OperationRequestV2::new(
                "snapshot.restore",
                "p04-snapshot-restore",
                json!({
                    "workspace_root": fixture.root(),
                    "snapshot_ref": snapshot_ref,
                    "expected_snapshot_sha256": snapshot_ref.sha256,
                    "restore_version": "restore-0.3.0"
                }),
            ),
        )
        .unwrap();
    fixture.assert_receipt(&restored.result["restore_ref"]);
    assert_eq!(restored.result["replay"], true);
    for field in [
        "adapter_refresh_count",
        "index_write_count",
        "assistant_config_write_count",
        "network_call_count",
        "current_write_count",
        "canonical_write_count",
    ] {
        assert_eq!(restored.result[field], 0, "{field}");
    }
}

#[test]
fn p04_migration_preserves_legacy_not_proven_and_migration_gap() {
    let fixture = Fixture::new();
    let legacy = fixture.root().join("legacy-bundle");
    fs::create_dir(&legacy).unwrap();
    fs::write(
        legacy.join("manifest.json"),
        serde_json::to_vec_pretty(&json!({
            "schema_version": "gtkg.bundle/v1",
            "status": "legacy"
        }))
        .unwrap(),
    )
    .unwrap();
    let legacy_tree = tree_sha256(&legacy).unwrap();
    let migrated = Dispatcher
        .execute_v2(
            &fixture.context(EffectPolicy::WorkspaceWrite),
            OperationRequestV2::new(
                "bundle.migrate.v1_to_v2",
                "p04-migrate",
                json!({
                    "workspace_root": fixture.root(),
                    "legacy_bundle_path": legacy,
                    "expected_legacy_tree_sha256": legacy_tree,
                    "migration_version": "migration-0.3.0"
                }),
            ),
        )
        .unwrap();
    let migrated_ref = fixture.assert_receipt(&migrated.result["bundle_ref"]);
    assert_eq!(migrated.result["provenance_state"], "not_proven");
    assert_eq!(migrated.result["migration_gap"], true);
    assert_eq!(migrated.result["canonical_eligible"], false);
    let verified = Dispatcher
        .execute_v2(
            &fixture.context(EffectPolicy::WorkspaceWrite),
            OperationRequestV2::new(
                "bundle.verify",
                "p04-migrated-verify",
                json!({"workspace_root": fixture.root(), "bundle_ref": migrated_ref}),
            ),
        )
        .unwrap();
    assert_eq!(verified.result["provenance_state"], "not_proven");
    assert_eq!(verified.result["migration_gap"], true);
}

#[test]
fn p04_closed_effect_cas_and_tamper_boundaries_fail_closed() {
    let fixture = Fixture::new();
    let mut invalid = fixture.finalize_request("p04-unknown");
    invalid.payload["unexpected"] = json!(true);
    let unknown = Dispatcher
        .execute_v2(&fixture.context(EffectPolicy::WorkspaceWrite), invalid)
        .unwrap_err();
    assert_eq!(unknown.error.code, V2ErrorCode::InvalidRequest);

    let denied = Dispatcher
        .execute_v2(
            &fixture.context(EffectPolicy::ReadOnly),
            fixture.finalize_request("p04-readonly"),
        )
        .unwrap_err();
    assert_eq!(denied.error.code, V2ErrorCode::SideEffectDenied);

    let finalized = Dispatcher
        .execute_v2(
            &fixture.context(EffectPolicy::WorkspaceWrite),
            fixture.finalize_request("p04-negative-finalize"),
        )
        .unwrap();
    let run_ref = fixture.assert_receipt(&finalized.result["run_ref"]);
    let cas = Dispatcher
        .execute_v2(
            &fixture.context(EffectPolicy::WorkspaceWrite),
            OperationRequestV2::new(
                "run.cancel",
                "p04-run-cas",
                json!({
                    "workspace_root": fixture.root(),
                    "run_ref": run_ref,
                    "expected_run_sha256": digest('f')
                }),
            ),
        )
        .unwrap_err();
    assert_eq!(cas.error.code, V2ErrorCode::LockMismatch);
}

struct Fixture {
    workspace: tempfile::TempDir,
    analysis_verification_ref: FileReceiptRef,
    accepted_summary_ref: FileReceiptRef,
}

impl Fixture {
    fn new() -> Self {
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
        let captured = Dispatcher
            .execute_v2(
                &context,
                OperationRequestV2::new(
                    "source.capture",
                    "p04-source",
                    json!({
                        "capture_mode": "directory_exact",
                        "repository_id": "p04",
                        "source_root": source,
                        "output_path": snapshot_path
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
                    "p04-plan",
                    json!({
                        "workspace_root": workspace.path(),
                        "source_root": source,
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
                    "p04-build",
                    json!({"workspace_root": workspace.path(), "plan_ref": plan_ref}),
                ),
            )
            .unwrap();
        let candidate_ref: FileReceiptRef =
            serde_json::from_value(build.result["candidate_ref"].clone()).unwrap();
        let analysis = Dispatcher
            .execute_v2(
                &context,
                OperationRequestV2::new(
                    "analysis.verify",
                    "p04-analysis",
                    json!({"workspace_root": workspace.path(), "candidate_ref": candidate_ref}),
                ),
            )
            .unwrap();
        let analysis_verification_ref: FileReceiptRef =
            serde_json::from_value(analysis.result["verification_ref"].clone()).unwrap();
        let packed = Dispatcher
            .execute_v2(
                &context,
                OperationRequestV2::new(
                    "context.pack",
                    "p04-pack",
                    json!({
                        "workspace_root": workspace.path(),
                        "analysis_verification_ref": analysis_verification_ref,
                        "max_fact_count": 128
                    }),
                ),
            )
            .unwrap();
        let job = Dispatcher
            .execute_v2(
                &context,
                OperationRequestV2::new(
                    "summary.job.next",
                    "p04-job",
                    json!({
                        "workspace_root": workspace.path(),
                        "analysis_verification_ref": analysis_verification_ref,
                        "max_fact_count": 128,
                        "expected_context_pack_sha256": packed.result["context_pack_sha256"]
                    }),
                ),
            )
            .unwrap();
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
        let proposal = Dispatcher
            .execute_v2(
                &context,
                OperationRequestV2::new(
                    "summary.proposal.submit",
                    "p04-proposal",
                    json!({
                        "workspace_root": workspace.path(),
                        "analysis_verification_ref": analysis_verification_ref,
                        "context_pack_sha256": packed.result["context_pack_sha256"],
                        "summary_job_sha256": job.result["summary_job_sha256"],
                        "proposer_id": "p04-proposer",
                        "summary_text": "Candidate facts only.",
                        "decisions": decisions
                    }),
                ),
            )
            .unwrap();
        let proposal_ref: FileReceiptRef =
            serde_json::from_value(proposal.result["proposal_ref"].clone()).unwrap();
        let verification_job = Dispatcher
            .execute_v2(
                &context,
                OperationRequestV2::new(
                    "summary.verification.next",
                    "p04-verification-job",
                    json!({"workspace_root": workspace.path(), "proposal_ref": proposal_ref}),
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
                    "reason": "reviewed"
                })
            })
            .collect::<Vec<_>>();
        let summary_verification = Dispatcher
            .execute_v2(
                &context,
                OperationRequestV2::new(
                    "summary.verification.submit",
                    "p04-verification",
                    json!({
                        "workspace_root": workspace.path(),
                        "proposal_ref": proposal_ref,
                        "verification_job_sha256": verification_job.result["verification_job_sha256"],
                        "verifier_id": "p04-verifier",
                        "decisions": verification_decisions
                    }),
                ),
            )
            .unwrap();
        let summary_verification_ref: FileReceiptRef =
            serde_json::from_value(summary_verification.result["summary_verification_ref"].clone())
                .unwrap();
        let accepted = Dispatcher
            .execute_v2(
                &context,
                OperationRequestV2::new(
                    "summary.accept.v2",
                    "p04-accept",
                    json!({
                        "workspace_root": workspace.path(),
                        "proposal_ref": proposal_ref,
                        "summary_verification_ref": summary_verification_ref
                    }),
                ),
            )
            .unwrap();
        Self {
            workspace,
            analysis_verification_ref,
            accepted_summary_ref: serde_json::from_value(
                accepted.result["accepted_summary_ref"].clone(),
            )
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

    fn finalize_request(&self, request_id: &str) -> OperationRequestV2 {
        OperationRequestV2::new(
            "build.finalize.v2",
            request_id,
            json!({
                "workspace_root": self.root(),
                "analysis_verification_ref": self.analysis_verification_ref,
                "accepted_summary_ref": self.accepted_summary_ref,
                "bundle_version": "0.3.0-candidate"
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
