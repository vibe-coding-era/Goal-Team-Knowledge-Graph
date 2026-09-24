//! P04 successor: all-abstention remains partial and a rehashed accepted
//! summary that invents an asserted locator claim cannot finalize.

use std::fs;
use std::path::Path;

use gtkg_core::{CallContext, Dispatcher, EffectPolicy, TransportKind};
use gtkg_protocol::v2::{OperationRequestV2, V2ErrorCode};
use gtkg_protocol::{FileReceiptRef, canonical_json_sha256};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

#[test]
fn p04_all_abstention_is_partial_and_forged_accepted_claim_is_rejected() {
    let fixture = Fixture::new();
    let finalized = Dispatcher
        .execute_v2(
            &fixture.context(),
            fixture.finalize("p04-abstention-finalize", fixture.accepted_ref.clone()),
        )
        .unwrap();
    assert_eq!(finalized.result["partial"], true);
    assert_eq!(finalized.result["canonical_eligible"], false);
    let bundle_ref: FileReceiptRef =
        serde_json::from_value(finalized.result["bundle_ref"].clone()).unwrap();
    let bundle: Value =
        serde_json::from_slice(&fs::read(fixture.root().join(bundle_ref.path)).unwrap()).unwrap();
    assert_eq!(bundle["asserted_claim_receipt_sha256s"], json!([]));

    let mut accepted: Value =
        serde_json::from_slice(&fs::read(fixture.root().join(&fixture.accepted_ref.path)).unwrap())
            .unwrap();
    let analysis: Value =
        serde_json::from_slice(&fs::read(fixture.root().join(&fixture.analysis_ref.path)).unwrap())
            .unwrap();
    let locator_receipt =
        analysis["adapter_verifications"][0]["fact_receipts"][0]["receipt_sha256"]
            .as_str()
            .unwrap();
    accepted["asserted_claims"] = json!([{
        "fact_receipt_sha256": locator_receipt,
        "proposal_decision_sha256": digest('f')
    }]);
    let forged_ref = fixture.forge_accepted(accepted);
    let error = Dispatcher
        .execute_v2(
            &fixture.context(),
            fixture.finalize("p04-forged-accepted", forged_ref),
        )
        .unwrap_err();
    assert_eq!(error.error.code, V2ErrorCode::InvalidState);
}

struct Fixture {
    workspace: tempfile::TempDir,
    analysis_ref: FileReceiptRef,
    accepted_ref: FileReceiptRef,
}

impl Fixture {
    fn new() -> Self {
        let workspace = tempfile::tempdir().unwrap();
        let source = workspace.path().join("source");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("lib.rs"), "fn locator() {}\n").unwrap();
        let codegraph = workspace.path().join("codegraph.json");
        fs::write(
            &codegraph,
            fs::read(
                Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/v03_a04/valid-codegraph.json"),
            )
            .unwrap(),
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
                    "p04-chain-source",
                    json!({
                        "capture_mode": "directory_exact",
                        "repository_id": "p04-chain",
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
        let snapshot_exact = captured.result["snapshot"]["exact_set_sha256"]
            .as_str()
            .unwrap();
        let plan = Dispatcher
            .execute_v2(
                &context,
                OperationRequestV2::new(
                    "analysis.plan",
                    "p04-chain-plan",
                    json!({
                        "workspace_root": workspace.path(),
                        "source_root": source,
                        "source_snapshot_ref": snapshot_ref,
                        "adapter_inputs": [{
                            "adapter_kind": "codegraph",
                            "input_path": codegraph,
                            "pin": {
                                "file_sha256": "sha256:66b2bc48661dc6348c2930afc8e368c71a5dd5bdfb580c911c726d4fed70842b",
                                "schema_sha256": "sha256:b7a9743ee957d11268c5e1c2342c14d6071ae3a69ed1ed52ada0e6ab997fd1f0",
                                "tool_version": "0.20.1",
                                "tool_commit": "489ccf1612555510f8367e3e673181f6a1275fe4",
                                "tool_license": "Apache-2.0",
                                "source_snapshot_sha256": snapshot_exact,
                                "max_file_bytes": 65536
                            }
                        }]
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
                    "p04-chain-build",
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
                    "p04-chain-analysis",
                    json!({"workspace_root": workspace.path(), "candidate_ref": candidate_ref}),
                ),
            )
            .unwrap();
        let analysis_ref: FileReceiptRef =
            serde_json::from_value(analysis.result["verification_ref"].clone()).unwrap();
        let packed = Dispatcher
            .execute_v2(
                &context,
                OperationRequestV2::new(
                    "context.pack",
                    "p04-chain-pack",
                    json!({
                        "workspace_root": workspace.path(),
                        "analysis_verification_ref": analysis_ref,
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
                    "p04-chain-job",
                    json!({
                        "workspace_root": workspace.path(),
                        "analysis_verification_ref": analysis_ref,
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
                    "state": "abstain",
                    "reason": "locator_only"
                })
            })
            .collect::<Vec<_>>();
        let proposal = Dispatcher
            .execute_v2(
                &context,
                OperationRequestV2::new(
                    "summary.proposal.submit",
                    "p04-chain-proposal",
                    json!({
                        "workspace_root": workspace.path(),
                        "analysis_verification_ref": analysis_ref,
                        "context_pack_sha256": packed.result["context_pack_sha256"],
                        "summary_job_sha256": job.result["summary_job_sha256"],
                        "proposer_id": "p04-chain-proposer",
                        "summary_text": "Untrusted note.",
                        "decisions": decisions
                    }),
                ),
            )
            .unwrap();
        let proposal_ref: FileReceiptRef =
            serde_json::from_value(proposal.result["proposal_ref"].clone()).unwrap();
        let next = Dispatcher
            .execute_v2(
                &context,
                OperationRequestV2::new(
                    "summary.verification.next",
                    "p04-chain-next",
                    json!({"workspace_root": workspace.path(), "proposal_ref": proposal_ref}),
                ),
            )
            .unwrap();
        let verification_decisions = next.result["verification_job"]["decisions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|decision| {
                json!({
                    "proposal_decision_sha256": decision["proposal_decision_sha256"],
                    "state": "verified",
                    "reason": "abstention_confirmed"
                })
            })
            .collect::<Vec<_>>();
        let verified = Dispatcher
            .execute_v2(
                &context,
                OperationRequestV2::new(
                    "summary.verification.submit",
                    "p04-chain-verification",
                    json!({
                        "workspace_root": workspace.path(),
                        "proposal_ref": proposal_ref,
                        "verification_job_sha256": next.result["verification_job_sha256"],
                        "verifier_id": "p04-chain-verifier",
                        "decisions": verification_decisions
                    }),
                ),
            )
            .unwrap();
        let verification_ref: FileReceiptRef =
            serde_json::from_value(verified.result["summary_verification_ref"].clone()).unwrap();
        let accepted = Dispatcher
            .execute_v2(
                &context,
                OperationRequestV2::new(
                    "summary.accept.v2",
                    "p04-chain-accept",
                    json!({
                        "workspace_root": workspace.path(),
                        "proposal_ref": proposal_ref,
                        "summary_verification_ref": verification_ref
                    }),
                ),
            )
            .unwrap();
        Self {
            workspace,
            analysis_ref,
            accepted_ref: serde_json::from_value(accepted.result["accepted_summary_ref"].clone())
                .unwrap(),
        }
    }

    fn root(&self) -> &Path {
        self.workspace.path()
    }

    fn context(&self) -> CallContext {
        CallContext::restricted(
            TransportKind::Test,
            vec![self.root().to_path_buf()],
            EffectPolicy::WorkspaceWrite,
        )
        .unwrap()
    }

    fn finalize(&self, request_id: &str, accepted: FileReceiptRef) -> OperationRequestV2 {
        OperationRequestV2::new(
            "build.finalize.v2",
            request_id,
            json!({
                "workspace_root": self.root(),
                "analysis_verification_ref": self.analysis_ref,
                "accepted_summary_ref": accepted,
                "bundle_version": "0.3.0-chain"
            }),
        )
    }

    fn forge_accepted(&self, mut value: Value) -> FileReceiptRef {
        let mut semantic = value.clone();
        semantic
            .as_object_mut()
            .unwrap()
            .remove("accepted_summary_sha256");
        let digest = canonical_json_sha256(&semantic).unwrap();
        value["accepted_summary_sha256"] = json!(digest);
        let bytes = serde_json::to_vec_pretty(&value).unwrap();
        let path = self.root().join(format!(
            ".gtkg/summary/accepted/{}.json",
            digest.strip_prefix("sha256:").unwrap()
        ));
        fs::write(&path, &bytes).unwrap();
        FileReceiptRef {
            path: path
                .strip_prefix(self.root())
                .unwrap()
                .to_string_lossy()
                .into_owned(),
            sha256: sha256(&bytes),
        }
    }
}

fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn digest(character: char) -> String {
    format!("sha256:{}", character.to_string().repeat(64))
}
