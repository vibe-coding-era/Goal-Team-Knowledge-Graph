//! P03 trust successor: locator facts require abstention and rehashed proposal
//! JSON cannot detach from the sealed P02/context/job chain.

use std::fs;
use std::path::Path;

use gtkg_core::{CallContext, Dispatcher, EffectPolicy, TransportKind};
use gtkg_protocol::v2::{OperationRequestV2, V2ErrorCode};
use gtkg_protocol::{FileReceiptRef, canonical_json_sha256};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

#[test]
fn p03_locator_facts_abstain_and_rehashed_chain_tamper_is_rejected() {
    let fixture = Fixture::new();
    let context = fixture.context(EffectPolicy::WorkspaceWrite);
    let packed = Dispatcher
        .execute_v2(
            &fixture.context(EffectPolicy::ReadOnly),
            fixture.pack_request("p03-trust-pack"),
        )
        .unwrap();
    let facts = packed.result["context_pack"]["facts"].as_array().unwrap();
    assert_eq!(facts.len(), 8);
    assert!(
        facts
            .iter()
            .all(|fact| fact["resolution"] == "locator_only")
    );
    let job = Dispatcher
        .execute_v2(
            &fixture.context(EffectPolicy::ReadOnly),
            OperationRequestV2::new(
                "summary.job.next",
                "p03-trust-job",
                json!({
                    "workspace_root": fixture.root(),
                    "analysis_verification_ref": fixture.verification_ref,
                    "max_fact_count": 128,
                    "expected_context_pack_sha256": packed.result["context_pack_sha256"]
                }),
            ),
        )
        .unwrap();

    let supported = facts
        .iter()
        .map(|fact| {
            json!({
                "fact_receipt_sha256": fact["receipt_sha256"],
                "state": "supported",
                "reason": "attempted_laundering"
            })
        })
        .collect::<Vec<_>>();
    let laundering = Dispatcher
        .execute_v2(
            &context,
            fixture.proposal_request("p03-trust-launder", &packed.result, &job.result, supported),
        )
        .unwrap_err();
    assert_eq!(laundering.error.code, V2ErrorCode::InvalidState);

    let abstentions = facts
        .iter()
        .map(|fact| {
            json!({
                "fact_receipt_sha256": fact["receipt_sha256"],
                "state": "abstain",
                "reason": "missing_exact_source_evidence"
            })
        })
        .collect::<Vec<_>>();
    let proposal = Dispatcher
        .execute_v2(
            &context,
            fixture.proposal_request(
                "p03-trust-proposal",
                &packed.result,
                &job.result,
                abstentions,
            ),
        )
        .unwrap();
    assert_eq!(proposal.result["abstention_count"], 8);
    assert_eq!(proposal.result["supported_count"], 0);
    let proposal_ref: FileReceiptRef =
        serde_json::from_value(proposal.result["proposal_ref"].clone()).unwrap();

    let mut tampered: Value =
        serde_json::from_slice(&fs::read(fixture.root().join(&proposal_ref.path)).unwrap())
            .unwrap();
    tampered["context_pack_sha256"] = json!(digest('f'));
    let mut semantic = tampered.clone();
    semantic.as_object_mut().unwrap().remove("proposal_sha256");
    let proposal_sha256 = canonical_json_sha256(&semantic).unwrap();
    tampered["proposal_sha256"] = json!(proposal_sha256);
    let bytes = serde_json::to_vec_pretty(&tampered).unwrap();
    let path = fixture.root().join(format!(
        ".gtkg/summary/proposals/{}.json",
        proposal_sha256.strip_prefix("sha256:").unwrap()
    ));
    fs::write(&path, &bytes).unwrap();
    let tampered_ref = FileReceiptRef {
        path: path
            .strip_prefix(fixture.root())
            .unwrap()
            .to_string_lossy()
            .into_owned(),
        sha256: sha256(&bytes),
    };
    let error = Dispatcher
        .execute_v2(
            &fixture.context(EffectPolicy::ReadOnly),
            OperationRequestV2::new(
                "summary.verification.next",
                "p03-trust-tamper",
                json!({"workspace_root": fixture.root(), "proposal_ref": tampered_ref}),
            ),
        )
        .unwrap_err();
    assert_eq!(error.error.code, V2ErrorCode::InvalidState);
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
        fs::write(source_root.join("lib.rs"), "fn locator_source() {}\n").unwrap();
        let input_path = workspace.path().join("codegraph.json");
        fs::write(
            &input_path,
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
                    "p03-trust-source",
                    json!({
                        "capture_mode": "directory_exact",
                        "repository_id": "p03-trust",
                        "source_root": source_root,
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
                    "p03-trust-plan",
                    json!({
                        "workspace_root": workspace.path(),
                        "source_root": source_root,
                        "source_snapshot_ref": snapshot_ref,
                        "adapter_inputs": [{
                            "adapter_kind": "codegraph",
                            "input_path": input_path,
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
                    "p03-trust-build",
                    json!({"workspace_root": workspace.path(), "plan_ref": plan_ref}),
                ),
            )
            .unwrap();
        let candidate_ref: FileReceiptRef =
            serde_json::from_value(build.result["candidate_ref"].clone()).unwrap();
        let verification = Dispatcher
            .execute_v2(
                &context,
                OperationRequestV2::new(
                    "analysis.verify",
                    "p03-trust-verify",
                    json!({"workspace_root": workspace.path(), "candidate_ref": candidate_ref}),
                ),
            )
            .unwrap();
        Self {
            workspace,
            verification_ref: serde_json::from_value(
                verification.result["verification_ref"].clone(),
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

    fn pack_request(&self, request_id: &str) -> OperationRequestV2 {
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

    fn proposal_request(
        &self,
        request_id: &str,
        packed: &Value,
        job: &Value,
        decisions: Vec<Value>,
    ) -> OperationRequestV2 {
        OperationRequestV2::new(
            "summary.proposal.submit",
            request_id,
            json!({
                "workspace_root": self.root(),
                "analysis_verification_ref": self.verification_ref,
                "context_pack_sha256": packed["context_pack_sha256"],
                "summary_job_sha256": job["summary_job_sha256"],
                "proposer_id": "trust-proposer",
                "summary_text": "Locator-only facts require abstention.",
                "decisions": decisions
            }),
        )
    }
}

fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn digest(character: char) -> String {
    format!("sha256:{}", character.to_string().repeat(64))
}
