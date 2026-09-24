//! Same-source P02/P03 rebuild plus full A06 strict-gate replay material.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use gtkg_core::v03::lifecycle::{
    A06SourceBoundAdapterReceiptV1, A06SourceBoundAdapterReplayV1,
    A06SourceBoundGateAttestationInputV1, A06SourceImageEntryV1,
};
use gtkg_core::{CallContext, Dispatcher, EffectPolicy, TransportKind};
use gtkg_protocol::FileReceiptRef;
use gtkg_protocol::v2::OperationRequestV2;
use gtkg_protocol::v03::AdapterKindV1;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

#[allow(clippy::assertions_on_constants, dead_code)]
mod a06_sealed_gate {
    include!("../v03_a06_sealed_input_successor.rs");

    pub(super) fn materialize(shared_lsp_ledger: bool) -> super::GateMaterial {
        let trusted_fixture = persisted_fixture();
        let mut imports = FiveImports::load();
        if shared_lsp_ledger {
            let ledger = imports.native_sources["ledger.rs"].clone();
            imports
                .lsp
                .source_files
                .insert("ledger.rs".to_owned(), ledger);
            imports.lsp.receipt.document_count += 1;
            reseal_lsp(&mut imports.lsp.receipt);
        }
        let actual = ActualAdapterInputs::load();
        let submissions = strict_submissions(&imports, &actual);
        let gate = verify_adapter_gate_sealed_strict_v1(
            &submissions,
            &trusted_fixture,
            "gtkg.verifier/a06-sealed-strict",
        )
        .unwrap();
        let adapters = submissions
            .into_iter()
            .map(|strict| {
                let submission = strict.submission;
                super::AdapterMaterial {
                    adapter_kind: submission.descriptor.kind,
                    descriptor: submission.descriptor.clone(),
                    bundle: submission.bundle.clone(),
                    receipt: match submission.receipt {
                        AdapterReceiptRefV1::Native(effects) => {
                            super::A06SourceBoundAdapterReceiptV1::Native {
                                source_file_read_count: effects.source_file_read_count,
                                target_process_count: effects.target_process_count,
                                network_call_count: effects.network_call_count,
                                write_count: effects.write_count,
                                executed_target_content: effects.executed_target_content,
                            }
                        }
                        AdapterReceiptRefV1::Scip(receipt) => {
                            super::A06SourceBoundAdapterReceiptV1::Scip(receipt.clone())
                        }
                        AdapterReceiptRefV1::Lsp(receipt) => {
                            super::A06SourceBoundAdapterReceiptV1::Lsp(receipt.clone())
                        }
                        AdapterReceiptRefV1::CodeGraph(receipt) => {
                            super::A06SourceBoundAdapterReceiptV1::CodeGraph(receipt.clone())
                        }
                        AdapterReceiptRefV1::GraphifyV2(receipt) => {
                            super::A06SourceBoundAdapterReceiptV1::Graphify(receipt.clone())
                        }
                    },
                    source_files: (*submission.source_files).clone(),
                    source_locators: submission.source_locators.to_vec(),
                    actual_input: strict.observation.actual_input_bytes.to_vec(),
                    configured_max_file_bytes: submission.configured_max_file_bytes,
                }
            })
            .collect();
        super::GateMaterial {
            gate,
            trusted_fixture,
            adapters,
        }
    }
}

struct AdapterMaterial {
    adapter_kind: AdapterKindV1,
    descriptor: gtkg_protocol::v03::adapter::AdapterDescriptorV1,
    bundle: gtkg_protocol::v03::adapter::ExternalFactBundleV1,
    receipt: A06SourceBoundAdapterReceiptV1,
    source_files: BTreeMap<String, Vec<u8>>,
    source_locators: Vec<gtkg_core::v03::adapter::graphify::GraphifySourceLocatorV1>,
    actual_input: Vec<u8>,
    configured_max_file_bytes: u64,
}

struct GateMaterial {
    gate: gtkg_core::v03::adapter::verifier::AdapterGateReceiptV1,
    trusted_fixture: gtkg_core::v03::adapter::verifier::AdapterTrustedOracleFixtureV1,
    adapters: Vec<AdapterMaterial>,
}

pub(crate) struct Candidate {
    pub workspace: tempfile::TempDir,
    pub bundle_ref: FileReceiptRef,
    pub source_snapshot_ref: FileReceiptRef,
    pub analysis_verification_ref: FileReceiptRef,
    pub gate: gtkg_core::v03::adapter::verifier::AdapterGateReceiptV1,
    trusted_fixture: gtkg_core::v03::adapter::verifier::AdapterTrustedOracleFixtureV1,
    adapters: Vec<A06SourceBoundAdapterReplayV1>,
    source_image: Vec<A06SourceImageEntryV1>,
}

impl Candidate {
    pub fn persist_gate(&self) -> FileReceiptRef {
        let semantic = self.gate.receipt_sha256.strip_prefix("sha256:").unwrap();
        persist_json(
            self.workspace.path(),
            &format!(".gtkg/a06/gates/{semantic}.json"),
            serde_json::to_vec_pretty(&self.gate).unwrap(),
        )
    }

    pub fn persist_trusted_fixture(&self) -> FileReceiptRef {
        let semantic = self.trusted_fixture.canonical_sha256().unwrap();
        let semantic = semantic.strip_prefix("sha256:").unwrap();
        persist_json(
            self.workspace.path(),
            &format!(".gtkg/a06/trusted-fixtures/{semantic}.json"),
            serde_json::to_vec_pretty(&self.trusted_fixture).unwrap(),
        )
    }

    pub fn attestation_input(
        &self,
        a06_gate_ref: FileReceiptRef,
        trusted_oracle_fixture_ref: FileReceiptRef,
    ) -> A06SourceBoundGateAttestationInputV1 {
        A06SourceBoundGateAttestationInputV1 {
            analysis_verification_ref: self.analysis_verification_ref.clone(),
            source_snapshot_ref: self.source_snapshot_ref.clone(),
            a06_gate_ref,
            trusted_oracle_fixture_ref,
            verifier_identity: self.gate.verifier_identity.clone(),
            adapters: self.adapters.clone(),
            source_image: self.source_image.clone(),
        }
    }
}

pub(crate) fn same_source_candidate() -> Candidate {
    build_candidate(false, false)
}

pub(crate) fn foreign_source_candidate() -> Candidate {
    build_candidate(true, false)
}

pub(crate) fn shared_source_candidate() -> Candidate {
    build_candidate(false, true)
}

fn build_candidate(drift_ledger: bool, shared_lsp_ledger: bool) -> Candidate {
    let material = a06_sealed_gate::materialize(shared_lsp_ledger);
    let workspace = tempfile::tempdir().unwrap();
    let source_root = workspace.path().join("source");
    fs::create_dir(&source_root).unwrap();

    let mut source_files = BTreeMap::<String, Vec<u8>>::new();
    for adapter in &material.adapters {
        for (logical_path, bytes) in &adapter.source_files {
            match source_files.get(logical_path) {
                Some(previous) => assert_eq!(previous, bytes, "conflicting source fixture"),
                None => {
                    source_files.insert(logical_path.clone(), bytes.clone());
                }
            }
        }
    }
    if drift_ledger {
        source_files.insert(
            "ledger.rs".to_owned(),
            b"pub fn changed_source() {}\n".to_vec(),
        );
    }
    for (logical_path, bytes) in &source_files {
        write_relative(&source_root, logical_path, bytes);
    }

    let mut external_inputs = BTreeMap::<String, FileReceiptRef>::new();
    for adapter in &material.adapters {
        let reference = match adapter.adapter_kind {
            AdapterKindV1::Native => file_ref(
                workspace.path(),
                "source/ledger.rs",
                &fs::read(source_root.join("ledger.rs")).unwrap(),
            ),
            kind => {
                let relative = format!("adapter-inputs/{}.json", kind.as_str());
                write_relative(workspace.path(), &relative, &adapter.actual_input);
                file_ref(workspace.path(), &relative, &adapter.actual_input)
            }
        };
        external_inputs.insert(adapter.adapter_kind.as_str().to_owned(), reference);
    }

    let source_image = source_files
        .iter()
        .map(|(logical_path, bytes)| A06SourceImageEntryV1 {
            logical_path: logical_path.clone(),
            file_ref: file_ref(workspace.path(), &format!("source/{logical_path}"), bytes),
            bytes: bytes.len() as u64,
        })
        .collect::<Vec<_>>();
    let adapters = material
        .adapters
        .iter()
        .map(|adapter| A06SourceBoundAdapterReplayV1 {
            adapter_kind: adapter.adapter_kind,
            descriptor: adapter.descriptor.clone(),
            bundle: adapter.bundle.clone(),
            receipt: adapter.receipt.clone(),
            input_ref: external_inputs
                .get(adapter.adapter_kind.as_str())
                .unwrap()
                .clone(),
            input_bytes: adapter.actual_input.len() as u64,
            configured_max_file_bytes: adapter.configured_max_file_bytes,
            source_file_logical_paths: adapter.source_files.keys().cloned().collect(),
            source_locators: adapter.source_locators.clone(),
        })
        .collect::<Vec<_>>();

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
        "i00-v2-source",
        json!({
            "capture_mode": "directory_exact",
            "repository_id": "i00-v2",
            "source_root": source_root,
            "output_path": snapshot_path
        }),
    );
    let source_snapshot_ref = FileReceiptRef {
        path: ".gtkg/source-snapshots/source.json".to_owned(),
        sha256: captured.result["snapshot_ref"]["artifact_sha256"]
            .as_str()
            .unwrap()
            .to_owned(),
    };
    let native_paths = source_files.keys().cloned().collect::<Vec<_>>();
    let plan = execute(
        &context,
        "analysis.plan",
        "i00-v2-plan",
        json!({
            "workspace_root": workspace.path(),
            "source_root": workspace.path().join("source"),
            "source_snapshot_ref": source_snapshot_ref,
            "adapter_inputs": native_paths.into_iter().map(|logical_path| json!({
                "adapter_kind": "native", "logical_path": logical_path
            })).collect::<Vec<_>>()
        }),
    );
    let plan_ref: FileReceiptRef = serde_json::from_value(plan.result["plan_ref"].clone()).unwrap();
    let build = execute(
        &context,
        "analysis.build",
        "i00-v2-build",
        json!({"workspace_root": workspace.path(), "plan_ref": plan_ref}),
    );
    let candidate_ref: FileReceiptRef =
        serde_json::from_value(build.result["candidate_ref"].clone()).unwrap();
    let analysis = execute(
        &context,
        "analysis.verify",
        "i00-v2-analysis",
        json!({"workspace_root": workspace.path(), "candidate_ref": candidate_ref}),
    );
    let analysis_verification_ref: FileReceiptRef =
        serde_json::from_value(analysis.result["verification_ref"].clone()).unwrap();
    let packed = execute(
        &context,
        "context.pack",
        "i00-v2-pack",
        json!({
            "workspace_root": workspace.path(),
            "analysis_verification_ref": analysis_verification_ref,
            "max_fact_count": 128
        }),
    );
    let job = execute(
        &context,
        "summary.job.next",
        "i00-v2-job",
        json!({
            "workspace_root": workspace.path(),
            "analysis_verification_ref": analysis_verification_ref,
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
                "state": if fact["resolution"] == "resolved_verified" {"supported"} else {"abstain"},
                "reason": if fact["resolution"] == "resolved_verified" {"exact_source_replay"} else {"not_resolved"}
            })
        })
        .collect::<Vec<_>>();
    let proposal = execute(
        &context,
        "summary.proposal.submit",
        "i00-v2-proposal",
        json!({
            "workspace_root": workspace.path(),
            "analysis_verification_ref": analysis_verification_ref,
            "context_pack_sha256": packed.result["context_pack_sha256"],
            "summary_job_sha256": job.result["summary_job_sha256"],
            "proposer_id": "i00-v2-proposer",
            "summary_text": "Candidate facts only.",
            "decisions": decisions
        }),
    );
    let proposal_ref: FileReceiptRef =
        serde_json::from_value(proposal.result["proposal_ref"].clone()).unwrap();
    let verification_job = execute(
        &context,
        "summary.verification.next",
        "i00-v2-verification-job",
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
        "i00-v2-verification",
        json!({
            "workspace_root": workspace.path(),
            "proposal_ref": proposal_ref,
            "verification_job_sha256": verification_job.result["verification_job_sha256"],
            "verifier_id": "i00-v2-verifier",
            "decisions": verification_decisions
        }),
    );
    let summary_verification_ref: FileReceiptRef =
        serde_json::from_value(summary_verification.result["summary_verification_ref"].clone())
            .unwrap();
    let accepted = execute(
        &context,
        "summary.accept.v2",
        "i00-v2-accept",
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
        "i00-v2-finalize",
        json!({
            "workspace_root": workspace.path(),
            "analysis_verification_ref": analysis_verification_ref,
            "accepted_summary_ref": accepted_ref,
            "bundle_version": "i00-v2-candidate"
        }),
    );
    let bundle_ref: FileReceiptRef =
        serde_json::from_value(finalized.result["bundle_ref"].clone()).unwrap();
    Candidate {
        workspace,
        bundle_ref,
        source_snapshot_ref,
        analysis_verification_ref,
        gate: material.gate,
        trusted_fixture: material.trusted_fixture,
        adapters,
        source_image,
    }
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

fn persist_json(root: &Path, relative: &str, bytes: Vec<u8>) -> FileReceiptRef {
    let path = root.join(relative);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, &bytes).unwrap();
    file_ref(root, relative, &bytes)
}

fn write_relative(root: &Path, relative: &str, bytes: &[u8]) {
    let path = root.join(relative);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, bytes).unwrap();
}

fn file_ref(root: &Path, relative: &str, bytes: &[u8]) -> FileReceiptRef {
    assert!(root.join(relative).is_file());
    FileReceiptRef {
        path: relative.to_owned(),
        sha256: sha256_prefixed(bytes),
    }
}

fn sha256_prefixed(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}
