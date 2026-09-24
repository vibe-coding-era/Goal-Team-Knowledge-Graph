//! P03 P0 successor: self-consistent forged P02 facts and rehashed summary
//! counters must not pass, and proposer prose never becomes a verified claim.

use std::fs;
use std::path::Path;

use gtkg_core::{CallContext, Dispatcher, EffectPolicy, TransportKind};
use gtkg_protocol::v2::{OperationRequestV2, V2ErrorCode};
use gtkg_protocol::v03::adapter::{
    VerifiedFactReceiptInputV1, VerifiedFactReceiptV1, VerifiedResolutionV1, VerifiedSourceSpanV1,
};
use gtkg_protocol::{FileReceiptRef, canonical_json_sha256};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

#[test]
fn p03_rejects_structurally_valid_p02_fact_not_replayed_from_candidate() {
    let fixture = Fixture::new();
    let path = fixture.root().join(&fixture.analysis_verification_ref.path);
    let mut verification: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    let original: VerifiedFactReceiptV1 = serde_json::from_value(
        verification["adapter_verifications"][0]["fact_receipts"][0].clone(),
    )
    .unwrap();
    let forged = VerifiedFactReceiptV1::new(VerifiedFactReceiptInputV1 {
        fact_id: original.fact_id,
        resolution: VerifiedResolutionV1::ResolvedVerified,
        reason: "exact_source_replay".to_owned(),
        source_snapshot_sha256: original.source_snapshot_sha256,
        adapter_descriptor_sha256: original.adapter_descriptor_sha256,
        bundle_sha256: original.bundle_sha256,
        source_spans: vec![VerifiedSourceSpanV1 {
            evidence_id: "forged-evidence".to_owned(),
            source_logical_path: "lib.rs".to_owned(),
            source_bytes_sha256: digest('1'),
            byte_start: 0,
            byte_end: 1,
            snippet_sha256: digest('2'),
        }],
        evidence_ids: vec!["forged-evidence".to_owned()],
        verifier_identity: "gtkg.verifier/forged".to_owned(),
    })
    .unwrap();
    verification["adapter_verifications"][0]["fact_receipts"][0] =
        serde_json::to_value(forged).unwrap();
    verification["adapter_verifications"][0]["resolved_verified_count"] = json!(1);
    verification["adapter_verifications"][0]["locator_only_count"] = json!(7);
    verification["resolved_verified_count"] = json!(1);
    verification["locator_only_count"] = json!(7);
    let forged_ref = fixture.forge(
        verification,
        "verification_sha256",
        ".gtkg/analysis/verifications",
    );
    let error = Dispatcher
        .execute_v2(
            &fixture.context(EffectPolicy::ReadOnly),
            fixture.context_request("p03-forged-p02", forged_ref),
        )
        .unwrap_err();
    assert_eq!(error.error.code, V2ErrorCode::InvalidState);
}

#[test]
fn p03_rejects_rehashed_proposal_conflict_and_verification_rejection_counts() {
    let fixture = Fixture::new();
    let (packed, job) = fixture.pack_and_job();
    let count = packed["context_pack"]["facts"].as_array().unwrap().len();

    let mut conflict_states = vec!["abstain"; count];
    conflict_states[0] = "conflict";
    let conflict = fixture.proposal(&packed, &job, &conflict_states, "conflicted note");
    let conflict_ref: FileReceiptRef =
        serde_json::from_value(conflict["proposal_ref"].clone()).unwrap();
    let mut proposal: Value =
        serde_json::from_slice(&fs::read(fixture.root().join(&conflict_ref.path)).unwrap())
            .unwrap();
    proposal["conflict_count"] = json!(0);
    proposal["abstention_count"] = json!(count);
    let forged_proposal_ref = fixture.forge(proposal, "proposal_sha256", ".gtkg/summary/proposals");
    let verified = fixture.verify(&forged_proposal_ref, None);
    let accepted = Dispatcher.execute_v2(
        &fixture.context(EffectPolicy::WorkspaceWrite),
        fixture.accept_request("p03-forged-conflict", forged_proposal_ref, verified),
    );
    assert_invalid_state(accepted);

    let abstain_states = vec!["abstain"; count];
    let clean = fixture.proposal(&packed, &job, &abstain_states, "abstained note");
    let clean_ref: FileReceiptRef = serde_json::from_value(clean["proposal_ref"].clone()).unwrap();
    let rejected = fixture.verify(&clean_ref, Some(0));
    let mut verification: Value =
        serde_json::from_slice(&fs::read(fixture.root().join(&rejected.path)).unwrap()).unwrap();
    verification["rejected_count"] = json!(0);
    verification["verified_count"] = json!(count);
    let forged_verification_ref = fixture.forge(
        verification,
        "summary_verification_sha256",
        ".gtkg/summary/verifications",
    );
    let accepted = Dispatcher.execute_v2(
        &fixture.context(EffectPolicy::WorkspaceWrite),
        fixture.accept_request("p03-forged-rejected", clean_ref, forged_verification_ref),
    );
    assert_invalid_state(accepted);
}

#[test]
fn p03_affirmative_proposer_note_with_all_abstentions_yields_no_asserted_claims() {
    let fixture = Fixture::new();
    let (packed, job) = fixture.pack_and_job();
    let count = packed["context_pack"]["facts"].as_array().unwrap().len();
    let note = "Every component is definitely production-safe.";
    let proposal = fixture.proposal(&packed, &job, &vec!["abstain"; count], note);
    let proposal_ref: FileReceiptRef =
        serde_json::from_value(proposal["proposal_ref"].clone()).unwrap();
    let verification_ref = fixture.verify(&proposal_ref, None);
    let accepted = Dispatcher
        .execute_v2(
            &fixture.context(EffectPolicy::WorkspaceWrite),
            fixture.accept_request("p03-note-accept", proposal_ref, verification_ref),
        )
        .unwrap();
    let accepted_ref: FileReceiptRef =
        serde_json::from_value(accepted.result["accepted_summary_ref"].clone()).unwrap();
    let artifact: Value =
        serde_json::from_slice(&fs::read(fixture.root().join(&accepted_ref.path)).unwrap())
            .unwrap();
    assert_eq!(artifact["asserted_claims"], json!([]));
    assert_eq!(artifact["proposer_note"], note);
    assert_eq!(artifact["verified_summary_text"], Value::Null);
    assert_eq!(
        artifact["actor_independence_state"],
        "declared_distinct_not_attested"
    );
    assert_eq!(accepted.result["asserted_claim_count"], 0);
    assert_eq!(accepted.result["canonical_eligible"], false);
}

fn assert_invalid_state(
    result: Result<gtkg_protocol::v2::OperationResponseV2, gtkg_protocol::v2::V2ErrorEnvelope>,
) {
    let error = result.unwrap_err();
    assert_eq!(error.error.code, V2ErrorCode::InvalidState);
}

struct Fixture {
    workspace: tempfile::TempDir,
    analysis_verification_ref: FileReceiptRef,
}

impl Fixture {
    fn new() -> Self {
        let workspace = tempfile::tempdir().unwrap();
        let source_root = workspace.path().join("source");
        fs::create_dir(&source_root).unwrap();
        fs::write(source_root.join("lib.rs"), "fn locator() {}\n").unwrap();
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
                    "p03-forgery-source",
                    json!({
                        "capture_mode": "directory_exact",
                        "repository_id": "p03-forgery",
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
                    "p03-forgery-plan",
                    json!({
                        "workspace_root": workspace.path(),
                        "source_root": source_root,
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
                    "p03-forgery-build",
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
                    "p03-forgery-verify",
                    json!({"workspace_root": workspace.path(), "candidate_ref": candidate_ref}),
                ),
            )
            .unwrap();
        Self {
            workspace,
            analysis_verification_ref: serde_json::from_value(
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

    fn context_request(&self, request_id: &str, reference: FileReceiptRef) -> OperationRequestV2 {
        OperationRequestV2::new(
            "context.pack",
            request_id,
            json!({
                "workspace_root": self.root(),
                "analysis_verification_ref": reference,
                "max_fact_count": 128
            }),
        )
    }

    fn pack_and_job(&self) -> (Value, Value) {
        let packed = Dispatcher
            .execute_v2(
                &self.context(EffectPolicy::ReadOnly),
                self.context_request("p03-forgery-pack", self.analysis_verification_ref.clone()),
            )
            .unwrap()
            .result;
        let job = Dispatcher
            .execute_v2(
                &self.context(EffectPolicy::ReadOnly),
                OperationRequestV2::new(
                    "summary.job.next",
                    "p03-forgery-job",
                    json!({
                        "workspace_root": self.root(),
                        "analysis_verification_ref": self.analysis_verification_ref,
                        "max_fact_count": 128,
                        "expected_context_pack_sha256": packed["context_pack_sha256"]
                    }),
                ),
            )
            .unwrap()
            .result;
        (packed, job)
    }

    fn proposal(&self, packed: &Value, job: &Value, states: &[&str], note: &str) -> Value {
        let facts = packed["context_pack"]["facts"].as_array().unwrap();
        let decisions = facts
            .iter()
            .zip(states)
            .map(|(fact, state)| {
                json!({
                    "fact_receipt_sha256": fact["receipt_sha256"],
                    "state": state,
                    "reason": format!("{state}_by_test")
                })
            })
            .collect::<Vec<_>>();
        Dispatcher
            .execute_v2(
                &self.context(EffectPolicy::WorkspaceWrite),
                OperationRequestV2::new(
                    "summary.proposal.submit",
                    "p03-forgery-proposal",
                    json!({
                        "workspace_root": self.root(),
                        "analysis_verification_ref": self.analysis_verification_ref,
                        "context_pack_sha256": packed["context_pack_sha256"],
                        "summary_job_sha256": job["summary_job_sha256"],
                        "proposer_id": "proposer",
                        "summary_text": note,
                        "decisions": decisions
                    }),
                ),
            )
            .unwrap()
            .result
    }

    fn verify(
        &self,
        proposal_ref: &FileReceiptRef,
        rejected_index: Option<usize>,
    ) -> FileReceiptRef {
        let next = Dispatcher
            .execute_v2(
                &self.context(EffectPolicy::ReadOnly),
                OperationRequestV2::new(
                    "summary.verification.next",
                    "p03-forgery-next",
                    json!({"workspace_root": self.root(), "proposal_ref": proposal_ref}),
                ),
            )
            .unwrap();
        let decisions = next.result["verification_job"]["decisions"]
            .as_array()
            .unwrap()
            .iter()
            .enumerate()
            .map(|(index, decision)| {
                json!({
                    "proposal_decision_sha256": decision["proposal_decision_sha256"],
                    "state": if rejected_index == Some(index) {"rejected"} else {"verified"},
                    "reason": "reviewed"
                })
            })
            .collect::<Vec<_>>();
        let submitted = Dispatcher
            .execute_v2(
                &self.context(EffectPolicy::WorkspaceWrite),
                OperationRequestV2::new(
                    "summary.verification.submit",
                    "p03-forgery-submit",
                    json!({
                        "workspace_root": self.root(),
                        "proposal_ref": proposal_ref,
                        "verification_job_sha256": next.result["verification_job_sha256"],
                        "verifier_id": "verifier",
                        "decisions": decisions
                    }),
                ),
            )
            .unwrap();
        serde_json::from_value(submitted.result["summary_verification_ref"].clone()).unwrap()
    }

    fn accept_request(
        &self,
        request_id: &str,
        proposal_ref: FileReceiptRef,
        verification_ref: FileReceiptRef,
    ) -> OperationRequestV2 {
        OperationRequestV2::new(
            "summary.accept.v2",
            request_id,
            json!({
                "workspace_root": self.root(),
                "proposal_ref": proposal_ref,
                "summary_verification_ref": verification_ref
            }),
        )
    }

    fn forge(&self, mut value: Value, digest_field: &str, partition: &str) -> FileReceiptRef {
        let mut semantic = value.clone();
        semantic.as_object_mut().unwrap().remove(digest_field);
        let digest = canonical_json_sha256(&semantic).unwrap();
        value[digest_field] = json!(digest);
        let bytes = serde_json::to_vec_pretty(&value).unwrap();
        let path = self.root().join(format!(
            "{partition}/{}.json",
            digest.strip_prefix("sha256:").unwrap()
        ));
        fs::create_dir_all(path.parent().unwrap()).unwrap();
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
