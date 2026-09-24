//! P04 immutable candidate lifecycle, event-sourced runs, migration and replay.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

use gtkg_protocol::v2::{
    BuildFinalizePayloadV2, BundleComparePayloadV2, BundleMigratePayloadV2, BundleVerifyPayloadV2,
    RunCancelPayloadV2, RunGetPayloadV2, SnapshotCreatePayloadV2, SnapshotRestorePayloadV2,
    SnapshotVerifyPayloadV2, SourceSnapshotV2, SummaryFactDecisionStateV2,
    SummaryVerificationDecisionStateV2, V2ErrorCode,
};
use gtkg_protocol::v03::AdapterKindV1;
use gtkg_protocol::v03::adapter::{AdapterDescriptorV1, ExternalFactBundleV1};
use gtkg_protocol::{FileReceiptRef, canonical_json_sha256};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::durable::{DurableErrorKind, publish_immutable_json};
use crate::exact_read::{ExactReadFailure, read_bound_regular_file};
use crate::v03::adapter::codegraph::CodeGraphImportReceiptV1;
use crate::v03::adapter::graphify::{GraphifyImportReceiptV2, GraphifySourceLocatorV1};
use crate::v03::adapter::lsp_snapshot::LspSnapshotImportReceiptV1;
use crate::v03::adapter::native::NativeAdapterEffectsV1;
use crate::v03::adapter::scip::ScipImportReceiptV1;
use crate::v03::adapter::verifier::{
    AdapterGateAuthorityStateV1, AdapterGateReceiptV1, AdapterReceiptRefV1, AdapterSubmissionV1,
    AdapterTrustedOracleFixtureV1, SealedInputObservationV1, StrictAdapterSubmissionV1,
    verify_adapter_gate_sealed_strict_v1,
};
use crate::v03::analysis::validate_verification_chain_v1;
use crate::v03::context_summary::validate_accepted_summary_chain_v1;
use crate::{CallContext, ContextError};

const BUNDLE_SCHEMA: &str = "gtkg.candidate-bundle/v2";
const RUN_SCHEMA: &str = "gtkg.lifecycle-run-state/v1";
const BUNDLE_VERIFICATION_SCHEMA: &str = "gtkg.bundle-verification/v2";
const SNAPSHOT_SCHEMA: &str = "gtkg.replay-snapshot/v2";
const SNAPSHOT_VERIFICATION_SCHEMA: &str = "gtkg.snapshot-verification/v2";
const RESTORE_SCHEMA: &str = "gtkg.replay-restore/v2";
const A06_TRUSTED_GATE_EXPECTATION_SCHEMA: &str = "gtkg.a06-trusted-gate-expectation/v1";
const A06_SOURCE_BOUND_ATTESTATION_SCHEMA: &str = "gtkg.a06-source-bound-attestation/v1";
const MIGRATION_PROVENANCE_SCHEMA: &str = "gtkg.migration-rebuild-provenance/v1";
const MIGRATION_PROVENANCE_V2_SCHEMA: &str = "gtkg.migration-rebuild-provenance/v2";
const LEGACY_BUNDLE_SCHEMA: &str = "gtkg.bundle/v1";
const MAX_LEGACY_TREE_ENTRIES: u64 = 8_192;
const MAX_LEGACY_TREE_DEPTH: usize = 64;
const MAX_LEGACY_TREE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_LEGACY_FILE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_LEGACY_MANIFEST_BYTES: usize = 1024 * 1024;

#[derive(Debug)]
pub struct LifecycleFailureV1 {
    pub code: V2ErrorCode,
    pub stage: &'static str,
    pub message: String,
    pub recovery_hint: &'static str,
}

#[derive(Debug)]
pub(crate) struct LifecycleResultV1 {
    pub result: Value,
}

/// An I00 caller-held pin for a sealed A06 verifier receipt.  The expectation
/// is intentionally external to the migrated legacy bundle: migration does
/// not get to select or upgrade its own provenance authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct A06TrustedGateExpectationV1 {
    schema_version: String,
    source_snapshot_exact_set_sha256: String,
    a06_gate_receipt_sha256: String,
    trusted_oracle_pin_sha256: String,
    trusted_oracle_fixture_sha256: String,
    sealed_input_set_sha256: String,
    expectation_sha256: String,
}

impl A06TrustedGateExpectationV1 {
    pub fn new(
        source_snapshot_exact_set_sha256: String,
        a06_gate_receipt_sha256: String,
        trusted_oracle_pin_sha256: String,
        trusted_oracle_fixture_sha256: String,
        sealed_input_set_sha256: String,
    ) -> Result<Self, LifecycleFailureV1> {
        let mut expectation = Self {
            schema_version: A06_TRUSTED_GATE_EXPECTATION_SCHEMA.to_owned(),
            source_snapshot_exact_set_sha256,
            a06_gate_receipt_sha256,
            trusted_oracle_pin_sha256,
            trusted_oracle_fixture_sha256,
            sealed_input_set_sha256,
            expectation_sha256: String::new(),
        };
        expectation.expectation_sha256 = digest_without(
            &expectation,
            "expectation_sha256",
            "migration.provenance.expectation",
        )?;
        expectation.validate()?;
        Ok(expectation)
    }

    /// Produces a distinct pin for a changed source identity.  A caller must
    /// still present it to `bind_migration_rebuild_provenance_v1`, where it is
    /// compared against the replayed rebuilt bundle before publication.
    pub fn with_source_snapshot_exact_set_sha256(
        &self,
        source_snapshot_exact_set_sha256: String,
    ) -> Self {
        let mut expectation = self.clone();
        expectation.source_snapshot_exact_set_sha256 = source_snapshot_exact_set_sha256;
        expectation.expectation_sha256 = digest_without(
            &expectation,
            "expectation_sha256",
            "migration.provenance.expectation",
        )
        .unwrap_or_default();
        expectation
    }

    fn validate(&self) -> Result<(), LifecycleFailureV1> {
        if self.schema_version != A06_TRUSTED_GATE_EXPECTATION_SCHEMA
            || !valid_sha256(&self.source_snapshot_exact_set_sha256)
            || !valid_sha256(&self.a06_gate_receipt_sha256)
            || !valid_sha256(&self.trusted_oracle_pin_sha256)
            || !valid_sha256(&self.trusted_oracle_fixture_sha256)
            || !valid_sha256(&self.sealed_input_set_sha256)
            || self.expectation_sha256
                != digest_without(
                    self,
                    "expectation_sha256",
                    "migration.provenance.expectation",
                )?
        {
            return Err(invalid_state(
                "migration.provenance.expectation",
                "A06 trusted gate expectation is invalid or tampered",
            ));
        }
        Ok(())
    }
}

/// Durable local-development join for I00.  It records that a legacy bundle
/// remains a non-authoritative historical input while a separate exact v2
/// rebuild has passed its own P02/P03 replay and is bound to a caller-held,
/// sealed A06 gate expectation.  This is deliberately not a Current selector.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationRebuildProvenanceV1 {
    schema_version: String,
    pub migration_bundle_ref: FileReceiptRef,
    migration_bundle_sha256: String,
    legacy_tree_sha256: String,
    pub legacy_provenance_state: String,
    pub migration_gap: bool,
    pub rebuilt_bundle_ref: FileReceiptRef,
    rebuilt_bundle_sha256: String,
    rebuilt_source_snapshot_exact_set_sha256: String,
    a06_gate_ref: FileReceiptRef,
    a06_gate_file_sha256: String,
    a06_gate_receipt_sha256: String,
    a06_trusted_gate_expectation: A06TrustedGateExpectationV1,
    pub provenance_state: String,
    pub canonical_eligible: bool,
    pub current_write_count: u64,
    pub canonical_write_count: u64,
    pub replay_canonical_write_count: u64,
    migration_provenance_sha256: String,
    #[serde(skip)]
    file_ref: Option<FileReceiptRef>,
}

impl MigrationRebuildProvenanceV1 {
    pub fn file_receipt_ref(&self) -> Result<FileReceiptRef, LifecycleFailureV1> {
        self.file_ref.clone().ok_or_else(|| {
            invalid_state(
                "migration.provenance.read",
                "migration provenance has no bound immutable file receipt",
            )
        })
    }
}

/// One exact source image entry consumed by the source-bound A06 replay.  The
/// `FileReceiptRef` is read again during every I00/I01 validation; it is not a
/// caller assertion about the source bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct A06SourceImageEntryV1 {
    pub logical_path: String,
    pub file_ref: FileReceiptRef,
    pub bytes: u64,
}

/// Serializable form of the five adapter import receipts.  The verifier's
/// borrowed receipt enum is recreated from this immutable form before calling
/// `verify_adapter_gate_sealed_strict_v1`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "receipt", rename_all = "snake_case")]
pub enum A06SourceBoundAdapterReceiptV1 {
    Native {
        source_file_read_count: u64,
        target_process_count: u64,
        network_call_count: u64,
        write_count: u64,
        executed_target_content: bool,
    },
    Scip(ScipImportReceiptV1),
    Lsp(LspSnapshotImportReceiptV1),
    CodeGraph(CodeGraphImportReceiptV1),
    Graphify(GraphifyImportReceiptV2),
}

/// Replay material for one adapter in a source-bound A06 gate.  `input_ref`
/// pins the frozen export/native input; `source_file_logical_paths` selects
/// exact bytes from the SourceSnapshot image rather than accepting an
/// independently supplied source map.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct A06SourceBoundAdapterReplayV1 {
    pub adapter_kind: AdapterKindV1,
    pub descriptor: AdapterDescriptorV1,
    pub bundle: ExternalFactBundleV1,
    pub receipt: A06SourceBoundAdapterReceiptV1,
    pub input_ref: FileReceiptRef,
    pub input_bytes: u64,
    pub configured_max_file_bytes: u64,
    pub source_file_logical_paths: Vec<String>,
    pub source_locators: Vec<GraphifySourceLocatorV1>,
}

/// Input accepted only to publish an immutable source-bound A06 attestation.
/// Every reference is read back and the full strict verifier is recomputed
/// before the object receives a receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct A06SourceBoundGateAttestationInputV1 {
    pub analysis_verification_ref: FileReceiptRef,
    pub source_snapshot_ref: FileReceiptRef,
    pub a06_gate_ref: FileReceiptRef,
    pub trusted_oracle_fixture_ref: FileReceiptRef,
    pub verifier_identity: String,
    pub adapters: Vec<A06SourceBoundAdapterReplayV1>,
    pub source_image: Vec<A06SourceImageEntryV1>,
}

/// Immutable source-bound proof that the persisted A06 gate recomputes from
/// exactly the same source image as a P02/P03 rebuild.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct A06SourceBoundGateAttestationV1 {
    schema_version: String,
    analysis_verification_ref: FileReceiptRef,
    analysis_verification_sha256: String,
    source_snapshot_ref: FileReceiptRef,
    source_snapshot_exact_set_sha256: String,
    a06_gate_ref: FileReceiptRef,
    a06_gate_receipt_sha256: String,
    trusted_oracle_fixture_ref: FileReceiptRef,
    trusted_oracle_fixture_sha256: String,
    verifier_identity: String,
    adapters: Vec<A06SourceBoundAdapterReplayV1>,
    source_image: Vec<A06SourceImageEntryV1>,
    attestation_sha256: String,
    #[serde(skip)]
    file_ref: Option<FileReceiptRef>,
}

impl A06SourceBoundGateAttestationV1 {
    pub fn file_receipt_ref(&self) -> Result<FileReceiptRef, LifecycleFailureV1> {
        self.file_ref.clone().ok_or_else(|| {
            invalid_state(
                "migration.a06-attestation",
                "source-bound A06 attestation has no immutable file receipt",
            )
        })
    }
}

/// Source-bound I00 successor.  V1 records remain historical/non-source-bound
/// and cannot satisfy this V2 path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationRebuildProvenanceV2 {
    schema_version: String,
    pub migration_bundle_ref: FileReceiptRef,
    migration_bundle_sha256: String,
    legacy_tree_sha256: String,
    pub legacy_provenance_state: String,
    pub migration_gap: bool,
    pub rebuilt_bundle_ref: FileReceiptRef,
    rebuilt_bundle_sha256: String,
    analysis_verification_ref: FileReceiptRef,
    rebuilt_source_snapshot_exact_set_sha256: String,
    a06_source_attestation_ref: FileReceiptRef,
    a06_source_attestation_sha256: String,
    a06_gate_ref: FileReceiptRef,
    a06_gate_receipt_sha256: String,
    pub provenance_state: String,
    pub canonical_eligible: bool,
    pub current_write_count: u64,
    pub canonical_write_count: u64,
    pub replay_canonical_write_count: u64,
    migration_provenance_sha256: String,
    #[serde(skip)]
    file_ref: Option<FileReceiptRef>,
}

/// Read-only identities extracted only after revalidating the immutable I00
/// provenance and its source-bound strict A06 attestation.  I01 consumes this
/// projection instead of accepting a caller-selected adapter digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceBoundIdentityReadbackV2 {
    pub provenance_ref: FileReceiptRef,
    pub source_identity: String,
    pub bundle_identity: String,
    pub adapter_replay_identity: String,
    pub a06_source_attestation_identity: String,
    pub a06_gate_receipt_identity: String,
}

impl MigrationRebuildProvenanceV2 {
    /// I01's read-only selector needs the exact identities already checked by
    /// the source-bound V2 provenance reader.  Exposing them as borrows does
    /// not grant write, promotion, or reconstruction authority.
    pub fn rebuilt_bundle_sha256(&self) -> &str {
        &self.rebuilt_bundle_sha256
    }

    pub fn rebuilt_source_snapshot_exact_set_sha256(&self) -> &str {
        &self.rebuilt_source_snapshot_exact_set_sha256
    }

    pub fn a06_source_attestation_sha256(&self) -> &str {
        &self.a06_source_attestation_sha256
    }

    pub fn a06_gate_receipt_sha256(&self) -> &str {
        &self.a06_gate_receipt_sha256
    }

    pub fn file_receipt_ref(&self) -> Result<FileReceiptRef, LifecycleFailureV1> {
        self.file_ref.clone().ok_or_else(|| {
            invalid_state(
                "migration.provenance.v2.read",
                "source-bound migration provenance has no immutable file receipt",
            )
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AssertedClaimV1 {
    fact_receipt_sha256: String,
    proposal_decision_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AcceptedSummaryViewV1 {
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProposalDecisionViewV1 {
    fact_receipt_sha256: String,
    state: SummaryFactDecisionStateV2,
    reason: String,
    proposal_decision_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProposalViewV1 {
    schema_version: String,
    analysis_verification_ref: FileReceiptRef,
    analysis_verification_sha256: String,
    source_snapshot_exact_set_sha256: String,
    context_pack_sha256: String,
    summary_job_sha256: String,
    max_fact_count: u64,
    proposer_id: String,
    proposer_note: String,
    decisions: Vec<ProposalDecisionViewV1>,
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
struct VerificationDecisionViewV1 {
    proposal_decision_sha256: String,
    state: SummaryVerificationDecisionStateV2,
    reason: String,
    decision_receipt_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SummaryVerificationViewV1 {
    schema_version: String,
    proposal_ref: FileReceiptRef,
    proposal_sha256: String,
    verification_job_sha256: String,
    context_pack_sha256: String,
    source_snapshot_exact_set_sha256: String,
    verifier_id: String,
    actor_independence_state: String,
    decisions: Vec<VerificationDecisionViewV1>,
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
struct CandidateBundleV2 {
    schema_version: String,
    bundle_kind: String,
    bundle_version: String,
    source_snapshot_exact_set_sha256: Option<String>,
    analysis_verification_ref: Option<FileReceiptRef>,
    analysis_verification_sha256: Option<String>,
    accepted_summary_ref: Option<FileReceiptRef>,
    accepted_summary_sha256: Option<String>,
    legacy_bundle_path: Option<PathBuf>,
    legacy_tree_sha256: Option<String>,
    fact_receipt_sha256s: Vec<String>,
    asserted_claim_receipt_sha256s: Vec<String>,
    provenance_state: String,
    migration_gap: bool,
    partial: bool,
    a06_cross_adapter_status: String,
    collision_check: String,
    canonical_eligible: bool,
    git_external_write_count: u64,
    current_write_count: u64,
    canonical_write_count: u64,
    bundle_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RunStatusV1 {
    CandidateReady,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RunStateV1 {
    schema_version: String,
    run_id: String,
    bundle_ref: FileReceiptRef,
    bundle_sha256: String,
    status: RunStatusV1,
    previous_run_ref: Option<FileReceiptRef>,
    cancellation_count: u64,
    current_write_count: u64,
    canonical_write_count: u64,
    run_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BundleVerificationV2 {
    schema_version: String,
    bundle_ref: FileReceiptRef,
    bundle_sha256: String,
    bundle_kind: String,
    provenance_state: String,
    migration_gap: bool,
    canonical_eligible: bool,
    verified: bool,
    verification_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SnapshotV2 {
    schema_version: String,
    snapshot_version: String,
    bundle_ref: FileReceiptRef,
    bundle_sha256: String,
    replay_only: bool,
    canonical_eligible: bool,
    current_write_count: u64,
    canonical_write_count: u64,
    snapshot_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SnapshotVerificationV2 {
    schema_version: String,
    snapshot_ref: FileReceiptRef,
    snapshot_sha256: String,
    bundle_sha256: String,
    replay_only: bool,
    verified: bool,
    verification_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RestoreV2 {
    schema_version: String,
    restore_version: String,
    snapshot_ref: FileReceiptRef,
    snapshot_sha256: String,
    bundle_ref: FileReceiptRef,
    bundle_sha256: String,
    replay: bool,
    adapter_refresh_count: u64,
    index_write_count: u64,
    assistant_config_write_count: u64,
    network_call_count: u64,
    git_external_write_count: u64,
    current_write_count: u64,
    canonical_write_count: u64,
    restore_sha256: String,
}

pub(crate) fn finalize(
    context: &CallContext,
    payload: BuildFinalizePayloadV2,
) -> Result<LifecycleResultV1, LifecycleFailureV1> {
    let workspace = context
        .authorize_write(&payload.workspace_root)
        .map_err(context_failure)?;
    let analysis =
        validate_verification_chain_v1(context, &workspace, &payload.analysis_verification_ref)
            .map_err(map_analysis)?;
    let accepted: AcceptedSummaryViewV1 = load_artifact(
        context,
        &workspace,
        &payload.accepted_summary_ref,
        "build.finalize.v2",
    )?;
    validate_accepted_summary(
        context,
        &workspace,
        &payload.accepted_summary_ref,
        &accepted,
        &analysis,
        &payload.analysis_verification_ref,
    )?;
    let fact_receipts = analysis["adapter_verifications"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|run| run["fact_receipts"].as_array().into_iter().flatten())
        .filter_map(|receipt| receipt["receipt_sha256"].as_str())
        .map(str::to_owned)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let mut bundle = CandidateBundleV2 {
        schema_version: BUNDLE_SCHEMA.to_owned(),
        bundle_kind: "finalized_candidate".to_owned(),
        bundle_version: payload.bundle_version,
        source_snapshot_exact_set_sha256: analysis["source_snapshot_exact_set_sha256"]
            .as_str()
            .map(str::to_owned),
        analysis_verification_ref: Some(payload.analysis_verification_ref),
        analysis_verification_sha256: analysis["verification_sha256"].as_str().map(str::to_owned),
        accepted_summary_ref: Some(payload.accepted_summary_ref),
        accepted_summary_sha256: Some(accepted.accepted_summary_sha256),
        legacy_bundle_path: None,
        legacy_tree_sha256: None,
        fact_receipt_sha256s: fact_receipts,
        asserted_claim_receipt_sha256s: accepted
            .asserted_claims
            .into_iter()
            .map(|claim| claim.fact_receipt_sha256)
            .collect(),
        provenance_state: "verified_candidate".to_owned(),
        migration_gap: false,
        partial: true,
        a06_cross_adapter_status: "not_run".to_owned(),
        collision_check: "not_run".to_owned(),
        canonical_eligible: false,
        git_external_write_count: 0,
        current_write_count: 0,
        canonical_write_count: 0,
        bundle_sha256: String::new(),
    };
    bundle.bundle_sha256 = digest_without(&bundle, "bundle_sha256", "build.finalize.v2")?;
    let bundle_path = workspace.join(format!(
        ".gtkg/lifecycle/bundles/{}.json",
        digest_hex(&bundle.bundle_sha256)?
    ));
    let bundle_ref = publish(
        context,
        &workspace,
        &bundle_path,
        &bundle,
        "build.finalize.v2",
    )?;
    let run_id = format!("run-{}", &digest_hex(&bundle.bundle_sha256)?[..24]);
    let mut run = RunStateV1 {
        schema_version: RUN_SCHEMA.to_owned(),
        run_id: run_id.clone(),
        bundle_ref: bundle_ref.clone(),
        bundle_sha256: bundle.bundle_sha256.clone(),
        status: RunStatusV1::CandidateReady,
        previous_run_ref: None,
        cancellation_count: 0,
        current_write_count: 0,
        canonical_write_count: 0,
        run_sha256: String::new(),
    };
    run.run_sha256 = digest_without(&run, "run_sha256", "build.finalize.v2")?;
    let run_path = run_path(&workspace, &run)?;
    let run_ref = publish(context, &workspace, &run_path, &run, "build.finalize.v2")?;
    Ok(LifecycleResultV1 {
        result: json!({
            "bundle_ref": bundle_ref,
            "bundle_sha256": bundle.bundle_sha256,
            "run_ref": run_ref,
            "run_id": run_id,
            "status": "candidate_ready",
            "local_receipt_write_count": 2,
            "partial": true,
            "a06_cross_adapter_status": "not_run",
            "canonical_eligible": false,
            "git_external_write_count": 0,
            "current_write_count": 0,
            "canonical_write_count": 0,
        }),
    })
}

pub(crate) fn run_get(
    context: &CallContext,
    payload: RunGetPayloadV2,
) -> Result<LifecycleResultV1, LifecycleFailureV1> {
    let workspace = context
        .authorize_read(&payload.workspace_root)
        .map_err(context_failure)?;
    let run: RunStateV1 = load_artifact(context, &workspace, &payload.run_ref, "run.get")?;
    validate_run_chain(context, &workspace, &payload.run_ref, &run)?;
    Ok(run_result(payload.run_ref, &run, 0))
}

pub(crate) fn run_cancel(
    context: &CallContext,
    payload: RunCancelPayloadV2,
) -> Result<LifecycleResultV1, LifecycleFailureV1> {
    let workspace = context
        .authorize_write(&payload.workspace_root)
        .map_err(context_failure)?;
    if payload.expected_run_sha256 != payload.run_ref.sha256 {
        return Err(lock("run.cancel", "run CAS digest mismatch"));
    }
    let run: RunStateV1 = load_artifact(context, &workspace, &payload.run_ref, "run.cancel")?;
    validate_run_chain(context, &workspace, &payload.run_ref, &run)?;
    if run.status == RunStatusV1::Cancelled {
        return Ok(run_result(payload.run_ref, &run, 0));
    }
    let mut cancelled = RunStateV1 {
        schema_version: RUN_SCHEMA.to_owned(),
        run_id: run.run_id,
        bundle_ref: run.bundle_ref,
        bundle_sha256: run.bundle_sha256,
        status: RunStatusV1::Cancelled,
        previous_run_ref: Some(payload.run_ref),
        cancellation_count: run
            .cancellation_count
            .checked_add(1)
            .ok_or_else(|| invalid_state("run.cancel", "cancellation count overflow"))?,
        current_write_count: 0,
        canonical_write_count: 0,
        run_sha256: String::new(),
    };
    cancelled.run_sha256 = digest_without(&cancelled, "run_sha256", "run.cancel")?;
    let path = run_path(&workspace, &cancelled)?;
    let reference = publish(context, &workspace, &path, &cancelled, "run.cancel")?;
    Ok(run_result(reference, &cancelled, 1))
}

pub(crate) fn bundle_verify(
    context: &CallContext,
    payload: BundleVerifyPayloadV2,
) -> Result<LifecycleResultV1, LifecycleFailureV1> {
    let workspace = context
        .authorize_write(&payload.workspace_root)
        .map_err(context_failure)?;
    let bundle = load_validate_bundle(context, &workspace, &payload.bundle_ref)?;
    let mut receipt = BundleVerificationV2 {
        schema_version: BUNDLE_VERIFICATION_SCHEMA.to_owned(),
        bundle_ref: payload.bundle_ref,
        bundle_sha256: bundle.bundle_sha256,
        bundle_kind: bundle.bundle_kind,
        provenance_state: bundle.provenance_state,
        migration_gap: bundle.migration_gap,
        canonical_eligible: false,
        verified: true,
        verification_sha256: String::new(),
    };
    receipt.verification_sha256 = digest_without(&receipt, "verification_sha256", "bundle.verify")?;
    let path = workspace.join(format!(
        ".gtkg/lifecycle/bundle-verifications/{}.json",
        digest_hex(&receipt.verification_sha256)?
    ));
    let reference = publish(context, &workspace, &path, &receipt, "bundle.verify")?;
    Ok(LifecycleResultV1 {
        result: json!({
            "bundle_verification_ref": reference,
            "verification_sha256": receipt.verification_sha256,
            "verified": true,
            "bundle_kind": receipt.bundle_kind,
            "provenance_state": receipt.provenance_state,
            "migration_gap": receipt.migration_gap,
            "canonical_eligible": false,
            "local_receipt_write_count": 1,
            "current_write_count": 0,
            "canonical_write_count": 0,
        }),
    })
}

pub(crate) fn bundle_compare(
    context: &CallContext,
    payload: BundleComparePayloadV2,
) -> Result<LifecycleResultV1, LifecycleFailureV1> {
    let workspace = context
        .authorize_read(&payload.workspace_root)
        .map_err(context_failure)?;
    let left = load_validate_bundle(context, &workspace, &payload.left_bundle_ref)?;
    let right = load_validate_bundle(context, &workspace, &payload.right_bundle_ref)?;
    Ok(LifecycleResultV1 {
        result: json!({
            "left_bundle_sha256": left.bundle_sha256,
            "right_bundle_sha256": right.bundle_sha256,
            "equal": left == right,
            "bundle_kind_changed": left.bundle_kind != right.bundle_kind,
            "provenance_changed": left.provenance_state != right.provenance_state,
            "write_count": 0,
            "network_call_count": 0,
            "current_write_count": 0,
            "canonical_write_count": 0,
        }),
    })
}

pub(crate) fn migrate(
    context: &CallContext,
    payload: BundleMigratePayloadV2,
) -> Result<LifecycleResultV1, LifecycleFailureV1> {
    let workspace = context
        .authorize_write(&payload.workspace_root)
        .map_err(context_failure)?;
    let legacy_relative = legacy_workspace_relative_path(
        context,
        &payload.workspace_root,
        &workspace,
        &payload.legacy_bundle_path,
        "bundle.migrate",
    )?;
    if legacy_relative == Path::new(".gtkg/lifecycle")
        || legacy_relative.starts_with(".gtkg/lifecycle")
    {
        return Err(invalid(
            "bundle.migrate",
            "legacy source and lifecycle output must not overlap",
        ));
    }
    let before =
        validate_legacy_bundle_tree(context, &workspace, &legacy_relative, "bundle.migrate")?;
    if before != payload.expected_legacy_tree_sha256 {
        return Err(lock("bundle.migrate", "legacy tree digest mismatch"));
    }
    let mut bundle = CandidateBundleV2 {
        schema_version: BUNDLE_SCHEMA.to_owned(),
        bundle_kind: "migrated_legacy_candidate".to_owned(),
        bundle_version: payload.migration_version,
        source_snapshot_exact_set_sha256: None,
        analysis_verification_ref: None,
        analysis_verification_sha256: None,
        accepted_summary_ref: None,
        accepted_summary_sha256: None,
        legacy_bundle_path: Some(legacy_relative.clone()),
        legacy_tree_sha256: Some(before.clone()),
        fact_receipt_sha256s: Vec::new(),
        asserted_claim_receipt_sha256s: Vec::new(),
        provenance_state: "not_proven".to_owned(),
        migration_gap: true,
        partial: true,
        a06_cross_adapter_status: "not_run".to_owned(),
        collision_check: "not_run".to_owned(),
        canonical_eligible: false,
        git_external_write_count: 0,
        current_write_count: 0,
        canonical_write_count: 0,
        bundle_sha256: String::new(),
    };
    bundle.bundle_sha256 = digest_without(&bundle, "bundle_sha256", "bundle.migrate")?;
    let path = workspace.join(format!(
        ".gtkg/lifecycle/bundles/{}.json",
        digest_hex(&bundle.bundle_sha256)?
    ));
    let reference = publish(context, &workspace, &path, &bundle, "bundle.migrate")?;
    let after =
        validate_legacy_bundle_tree(context, &workspace, &legacy_relative, "bundle.migrate")?;
    if before != after {
        return Err(invalid_state(
            "bundle.migrate",
            "legacy bundle changed during migration",
        ));
    }
    Ok(LifecycleResultV1 {
        result: json!({
            "bundle_ref": reference,
            "bundle_sha256": bundle.bundle_sha256,
            "provenance_state": "not_proven",
            "migration_gap": true,
            "canonical_eligible": false,
            "local_receipt_write_count": 1,
            "legacy_write_count": 0,
            "current_write_count": 0,
            "canonical_write_count": 0,
        }),
    })
}

/// Creates the immutable I00 provenance join.  The legacy object is never
/// relabeled: only an independently replayed finalized bundle can be linked to
/// it, and the caller must provide the sealed A06 expectation that is checked
/// before the join is written.
pub fn bind_migration_rebuild_provenance_v1(
    context: &CallContext,
    workspace_root: &Path,
    migration_bundle_ref: FileReceiptRef,
    rebuilt_bundle_ref: FileReceiptRef,
    a06_gate_ref: FileReceiptRef,
    a06_trusted_gate_expectation: A06TrustedGateExpectationV1,
) -> Result<MigrationRebuildProvenanceV1, LifecycleFailureV1> {
    let workspace = context
        .authorize_write(workspace_root)
        .map_err(context_failure)?;
    a06_trusted_gate_expectation.validate()?;
    let migrated = load_validate_bundle(context, &workspace, &migration_bundle_ref)?;
    let rebuilt = load_validate_bundle(context, &workspace, &rebuilt_bundle_ref)?;
    let legacy_tree_sha256 = migrated
        .legacy_tree_sha256
        .clone()
        .ok_or_else(|| invalid_state("migration.provenance.bind", "missing legacy tree"))?;
    let rebuilt_source_snapshot_exact_set_sha256 = rebuilt
        .source_snapshot_exact_set_sha256
        .clone()
        .ok_or_else(|| {
            invalid_state(
                "migration.provenance.bind",
                "rebuilt bundle is missing the exact source snapshot",
            )
        })?;
    let mut provenance = MigrationRebuildProvenanceV1 {
        schema_version: MIGRATION_PROVENANCE_SCHEMA.to_owned(),
        migration_bundle_ref,
        migration_bundle_sha256: migrated.bundle_sha256,
        legacy_tree_sha256,
        legacy_provenance_state: migrated.provenance_state,
        migration_gap: migrated.migration_gap,
        rebuilt_bundle_ref,
        rebuilt_bundle_sha256: rebuilt.bundle_sha256,
        rebuilt_source_snapshot_exact_set_sha256,
        a06_gate_ref,
        a06_gate_file_sha256: String::new(),
        a06_gate_receipt_sha256: String::new(),
        a06_trusted_gate_expectation,
        provenance_state: "rebuild_bound_not_promoted".to_owned(),
        canonical_eligible: false,
        current_write_count: 0,
        canonical_write_count: 0,
        replay_canonical_write_count: 0,
        migration_provenance_sha256: String::new(),
        file_ref: None,
    };
    provenance.a06_gate_file_sha256 = provenance.a06_gate_ref.sha256.clone();
    let gate: AdapterGateReceiptV1 = load_artifact(
        context,
        &workspace,
        &provenance.a06_gate_ref,
        "migration.provenance.bind",
    )?;
    provenance.a06_gate_receipt_sha256 = gate.receipt_sha256.clone();
    provenance.migration_provenance_sha256 = digest_without(
        &provenance,
        "migration_provenance_sha256",
        "migration.provenance.bind",
    )?;
    validate_migration_rebuild_provenance(
        context,
        &workspace,
        &provenance,
        &provenance.a06_trusted_gate_expectation,
    )
    .map_err(|failure| LifecycleFailureV1 {
        code: failure.code,
        stage: "migration.provenance.bind",
        message: failure.message,
        recovery_hint: failure.recovery_hint,
    })?;
    let path = workspace.join(format!(
        ".gtkg/lifecycle/migration-provenance/{}.json",
        digest_hex(&provenance.migration_provenance_sha256)?
    ));
    let reference = publish(
        context,
        &workspace,
        &path,
        &provenance,
        "migration.provenance.bind",
    )?;
    provenance.file_ref = Some(reference);
    Ok(provenance)
}

/// Read-only validation for I01 and later Current lifecycle consumers.  The
/// caller-held expectation is intentionally supplied again, so a rehashed
/// workspace-local provenance record cannot replace the trusted gate pin.
pub fn validate_migration_rebuild_provenance_v1(
    context: &CallContext,
    workspace_root: &Path,
    provenance_ref: &FileReceiptRef,
    expected_a06_gate: &A06TrustedGateExpectationV1,
) -> Result<MigrationRebuildProvenanceV1, LifecycleFailureV1> {
    let workspace = context
        .authorize_read(workspace_root)
        .map_err(context_failure)?;
    expected_a06_gate.validate()?;
    let mut provenance: MigrationRebuildProvenanceV1 = load_artifact(
        context,
        &workspace,
        provenance_ref,
        "migration.provenance.read",
    )?;
    validate_semantic_ref(
        provenance_ref,
        "lifecycle/migration-provenance",
        &provenance.migration_provenance_sha256,
        "migration.provenance.read",
    )?;
    validate_migration_rebuild_provenance(context, &workspace, &provenance, expected_a06_gate)?;
    provenance.file_ref = Some(provenance_ref.clone());
    Ok(provenance)
}

/// Publishes the source-bound A06 evidence required by I00 V2.  The caller
/// supplies only exact references and replay material; no caller-provided
/// source digest or trust-state assertion is accepted.
pub fn publish_a06_source_bound_gate_attestation_v1(
    context: &CallContext,
    workspace_root: &Path,
    input: A06SourceBoundGateAttestationInputV1,
) -> Result<A06SourceBoundGateAttestationV1, LifecycleFailureV1> {
    let workspace = context
        .authorize_write(workspace_root)
        .map_err(context_failure)?;
    let analysis =
        validate_verification_chain_v1(context, &workspace, &input.analysis_verification_ref)
            .map_err(map_analysis)?;
    let analysis_verification_sha256 = analysis["verification_sha256"]
        .as_str()
        .ok_or_else(|| {
            invalid_state(
                "migration.a06-attestation",
                "P02 verification is missing its exact identity",
            )
        })?
        .to_owned();
    let snapshot = load_source_snapshot_v2(
        context,
        &workspace,
        &input.source_snapshot_ref,
        "migration.a06-attestation",
    )?;
    if analysis["source_snapshot_exact_set_sha256"].as_str()
        != Some(snapshot.exact_set_sha256.as_str())
    {
        return Err(lock(
            "migration.a06-attestation",
            "P02 verification source identity differs from source-bound A06 input",
        ));
    }
    let gate: AdapterGateReceiptV1 = load_artifact(
        context,
        &workspace,
        &input.a06_gate_ref,
        "migration.a06-attestation",
    )?;
    validate_semantic_ref(
        &input.a06_gate_ref,
        "a06/gates",
        &gate.receipt_sha256,
        "migration.a06-attestation",
    )?;
    let trusted_fixture: AdapterTrustedOracleFixtureV1 = load_artifact(
        context,
        &workspace,
        &input.trusted_oracle_fixture_ref,
        "migration.a06-attestation",
    )?;
    let trusted_oracle_fixture_sha256 = trusted_fixture.canonical_sha256().map_err(|error| {
        invalid_state(
            "migration.a06-attestation",
            format!("trusted A06 fixture is invalid: {error}"),
        )
    })?;
    let mut attestation = A06SourceBoundGateAttestationV1 {
        schema_version: A06_SOURCE_BOUND_ATTESTATION_SCHEMA.to_owned(),
        analysis_verification_ref: input.analysis_verification_ref,
        analysis_verification_sha256,
        source_snapshot_ref: input.source_snapshot_ref,
        source_snapshot_exact_set_sha256: snapshot.exact_set_sha256,
        a06_gate_ref: input.a06_gate_ref,
        a06_gate_receipt_sha256: gate.receipt_sha256,
        trusted_oracle_fixture_ref: input.trusted_oracle_fixture_ref,
        trusted_oracle_fixture_sha256,
        verifier_identity: input.verifier_identity,
        adapters: input.adapters,
        source_image: input.source_image,
        attestation_sha256: String::new(),
        file_ref: None,
    };
    attestation.attestation_sha256 = digest_without(
        &attestation,
        "attestation_sha256",
        "migration.a06-attestation",
    )?;
    validate_a06_source_bound_attestation(context, &workspace, &attestation)?;
    let path = workspace.join(format!(
        ".gtkg/lifecycle/a06-source-attestations/{}.json",
        digest_hex(&attestation.attestation_sha256)?
    ));
    let reference = publish(
        context,
        &workspace,
        &path,
        &attestation,
        "migration.a06-attestation",
    )?;
    attestation.file_ref = Some(reference);
    Ok(attestation)
}

/// Creates the only I00 provenance form eligible for a later I01 identity
/// join.  V1 provenance intentionally remains readable historical evidence
/// but is not accepted on this source-bound V2 route.
pub fn bind_migration_rebuild_provenance_source_bound_v2(
    context: &CallContext,
    workspace_root: &Path,
    migration_bundle_ref: FileReceiptRef,
    rebuilt_bundle_ref: FileReceiptRef,
    a06_source_attestation_ref: FileReceiptRef,
) -> Result<MigrationRebuildProvenanceV2, LifecycleFailureV1> {
    let workspace = context
        .authorize_write(workspace_root)
        .map_err(context_failure)?;
    let migrated = load_validate_bundle(context, &workspace, &migration_bundle_ref)?;
    let rebuilt = load_validate_bundle(context, &workspace, &rebuilt_bundle_ref)?;
    let attestation = load_validate_a06_source_bound_attestation(
        context,
        &workspace,
        &a06_source_attestation_ref,
    )?;
    let legacy_tree_sha256 = migrated
        .legacy_tree_sha256
        .clone()
        .ok_or_else(|| invalid_state("migration.provenance.v2.bind", "missing legacy tree"))?;
    let analysis_ref = rebuilt.analysis_verification_ref.clone().ok_or_else(|| {
        invalid_state(
            "migration.provenance.v2.bind",
            "rebuilt bundle is missing the replayable P02 verification reference",
        )
    })?;
    let rebuilt_source_snapshot_exact_set_sha256 = rebuilt
        .source_snapshot_exact_set_sha256
        .clone()
        .ok_or_else(|| {
            invalid_state(
                "migration.provenance.v2.bind",
                "rebuilt bundle is missing the exact source snapshot",
            )
        })?;
    if rebuilt.bundle_kind != "finalized_candidate"
        || attestation.analysis_verification_ref != analysis_ref
        || rebuilt.analysis_verification_sha256.as_deref()
            != Some(attestation.analysis_verification_sha256.as_str())
        || attestation.source_snapshot_exact_set_sha256 != rebuilt_source_snapshot_exact_set_sha256
    {
        return Err(lock(
            "migration.provenance.v2.bind",
            "source-bound A06 attestation is not the exact P02/P03 rebuild lineage",
        ));
    }
    let mut provenance = MigrationRebuildProvenanceV2 {
        schema_version: MIGRATION_PROVENANCE_V2_SCHEMA.to_owned(),
        migration_bundle_ref,
        migration_bundle_sha256: migrated.bundle_sha256,
        legacy_tree_sha256,
        legacy_provenance_state: migrated.provenance_state,
        migration_gap: migrated.migration_gap,
        rebuilt_bundle_ref,
        rebuilt_bundle_sha256: rebuilt.bundle_sha256,
        analysis_verification_ref: analysis_ref,
        rebuilt_source_snapshot_exact_set_sha256,
        a06_source_attestation_ref,
        a06_source_attestation_sha256: attestation.attestation_sha256.clone(),
        a06_gate_ref: attestation.a06_gate_ref.clone(),
        a06_gate_receipt_sha256: attestation.a06_gate_receipt_sha256.clone(),
        provenance_state: "source_bound_rebuild_not_promoted".to_owned(),
        canonical_eligible: false,
        current_write_count: 0,
        canonical_write_count: 0,
        replay_canonical_write_count: 0,
        migration_provenance_sha256: String::new(),
        file_ref: None,
    };
    provenance.migration_provenance_sha256 = digest_without(
        &provenance,
        "migration_provenance_sha256",
        "migration.provenance.v2.bind",
    )?;
    validate_migration_rebuild_provenance_v2(context, &workspace, &provenance)?;
    let path = workspace.join(format!(
        ".gtkg/lifecycle/migration-provenance-v2/{}.json",
        digest_hex(&provenance.migration_provenance_sha256)?
    ));
    let reference = publish(
        context,
        &workspace,
        &path,
        &provenance,
        "migration.provenance.v2.bind",
    )?;
    provenance.file_ref = Some(reference);
    Ok(provenance)
}

/// Read-only replay validation for I01.  It replays the source-bound strict
/// A06 gate rather than accepting a caller-provided source digest tuple.
pub fn validate_migration_rebuild_provenance_source_bound_v2(
    context: &CallContext,
    workspace_root: &Path,
    provenance_ref: &FileReceiptRef,
) -> Result<MigrationRebuildProvenanceV2, LifecycleFailureV1> {
    let workspace = context
        .authorize_read(workspace_root)
        .map_err(context_failure)?;
    let mut provenance: MigrationRebuildProvenanceV2 = load_artifact(
        context,
        &workspace,
        provenance_ref,
        "migration.provenance.v2.read",
    )?;
    validate_semantic_ref(
        provenance_ref,
        "lifecycle/migration-provenance-v2",
        &provenance.migration_provenance_sha256,
        "migration.provenance.v2.read",
    )?;
    validate_migration_rebuild_provenance_v2(context, &workspace, &provenance)?;
    provenance.file_ref = Some(provenance_ref.clone());
    Ok(provenance)
}

/// Securely projects I00's actual source/bundle/five-adapter replay identity
/// for I01.  This is read-only: it neither promotes a candidate nor writes a
/// Current, canonical, or Replay artifact.
pub fn read_source_bound_identity_v2(
    context: &CallContext,
    workspace_root: &Path,
    provenance_ref: &FileReceiptRef,
) -> Result<SourceBoundIdentityReadbackV2, LifecycleFailureV1> {
    let workspace = context
        .authorize_read(workspace_root)
        .map_err(context_failure)?;
    let provenance =
        validate_migration_rebuild_provenance_source_bound_v2(context, &workspace, provenance_ref)?;
    let attestation = load_validate_a06_source_bound_attestation(
        context,
        &workspace,
        &provenance.a06_source_attestation_ref,
    )?;
    let adapter_replay_identity = canonical_json_sha256(&(
        "gtkg.i01.adapter-replay/v1",
        &attestation.adapters,
        &attestation.source_image,
    ))
    .map_err(|_| {
        invalid_state(
            "migration.provenance.v2.read",
            "source-bound adapter replay identity could not be serialized",
        )
    })?;
    Ok(SourceBoundIdentityReadbackV2 {
        provenance_ref: provenance.file_receipt_ref()?,
        source_identity: provenance.rebuilt_source_snapshot_exact_set_sha256,
        bundle_identity: provenance.rebuilt_bundle_sha256,
        adapter_replay_identity,
        a06_source_attestation_identity: provenance.a06_source_attestation_sha256,
        a06_gate_receipt_identity: provenance.a06_gate_receipt_sha256,
    })
}

pub(crate) fn snapshot_create(
    context: &CallContext,
    payload: SnapshotCreatePayloadV2,
) -> Result<LifecycleResultV1, LifecycleFailureV1> {
    let workspace = context
        .authorize_write(&payload.workspace_root)
        .map_err(context_failure)?;
    let bundle = load_validate_bundle(context, &workspace, &payload.bundle_ref)?;
    let mut snapshot = SnapshotV2 {
        schema_version: SNAPSHOT_SCHEMA.to_owned(),
        snapshot_version: payload.snapshot_version,
        bundle_ref: payload.bundle_ref,
        bundle_sha256: bundle.bundle_sha256,
        replay_only: true,
        canonical_eligible: false,
        current_write_count: 0,
        canonical_write_count: 0,
        snapshot_sha256: String::new(),
    };
    snapshot.snapshot_sha256 = digest_without(&snapshot, "snapshot_sha256", "snapshot.create")?;
    let path = workspace.join(format!(
        ".gtkg/lifecycle/snapshots/{}.json",
        digest_hex(&snapshot.snapshot_sha256)?
    ));
    let reference = publish(context, &workspace, &path, &snapshot, "snapshot.create")?;
    Ok(LifecycleResultV1 {
        result: json!({
            "snapshot_ref": reference,
            "snapshot_sha256": snapshot.snapshot_sha256,
            "replay_only": true,
            "canonical_eligible": false,
            "local_receipt_write_count": 1,
            "current_write_count": 0,
            "canonical_write_count": 0,
        }),
    })
}

pub(crate) fn snapshot_verify(
    context: &CallContext,
    payload: SnapshotVerifyPayloadV2,
) -> Result<LifecycleResultV1, LifecycleFailureV1> {
    let workspace = context
        .authorize_write(&payload.workspace_root)
        .map_err(context_failure)?;
    let snapshot = load_validate_snapshot(context, &workspace, &payload.snapshot_ref)?;
    let mut receipt = SnapshotVerificationV2 {
        schema_version: SNAPSHOT_VERIFICATION_SCHEMA.to_owned(),
        snapshot_ref: payload.snapshot_ref,
        snapshot_sha256: snapshot.snapshot_sha256,
        bundle_sha256: snapshot.bundle_sha256,
        replay_only: true,
        verified: true,
        verification_sha256: String::new(),
    };
    receipt.verification_sha256 =
        digest_without(&receipt, "verification_sha256", "snapshot.verify")?;
    let path = workspace.join(format!(
        ".gtkg/lifecycle/snapshot-verifications/{}.json",
        digest_hex(&receipt.verification_sha256)?
    ));
    let reference = publish(context, &workspace, &path, &receipt, "snapshot.verify")?;
    Ok(LifecycleResultV1 {
        result: json!({
            "snapshot_verification_ref": reference,
            "verification_sha256": receipt.verification_sha256,
            "verified": true,
            "replay_only": true,
            "local_receipt_write_count": 1,
            "current_write_count": 0,
            "canonical_write_count": 0,
        }),
    })
}

pub(crate) fn snapshot_restore(
    context: &CallContext,
    payload: SnapshotRestorePayloadV2,
) -> Result<LifecycleResultV1, LifecycleFailureV1> {
    let workspace = context
        .authorize_write(&payload.workspace_root)
        .map_err(context_failure)?;
    if payload.expected_snapshot_sha256 != payload.snapshot_ref.sha256 {
        return Err(lock("snapshot.restore", "snapshot CAS digest mismatch"));
    }
    let snapshot = load_validate_snapshot(context, &workspace, &payload.snapshot_ref)?;
    let mut restore = RestoreV2 {
        schema_version: RESTORE_SCHEMA.to_owned(),
        restore_version: payload.restore_version,
        snapshot_ref: payload.snapshot_ref,
        snapshot_sha256: snapshot.snapshot_sha256,
        bundle_ref: snapshot.bundle_ref,
        bundle_sha256: snapshot.bundle_sha256,
        replay: true,
        adapter_refresh_count: 0,
        index_write_count: 0,
        assistant_config_write_count: 0,
        network_call_count: 0,
        git_external_write_count: 0,
        current_write_count: 0,
        canonical_write_count: 0,
        restore_sha256: String::new(),
    };
    restore.restore_sha256 = digest_without(&restore, "restore_sha256", "snapshot.restore")?;
    let path = workspace.join(format!(
        ".gtkg/lifecycle/restores/{}.json",
        digest_hex(&restore.restore_sha256)?
    ));
    let reference = publish(context, &workspace, &path, &restore, "snapshot.restore")?;
    Ok(LifecycleResultV1 {
        result: json!({
            "restore_ref": reference,
            "restore_sha256": restore.restore_sha256,
            "replay": true,
            "local_receipt_write_count": 1,
            "adapter_refresh_count": 0,
            "index_write_count": 0,
            "assistant_config_write_count": 0,
            "network_call_count": 0,
            "git_external_write_count": 0,
            "current_write_count": 0,
            "canonical_write_count": 0,
        }),
    })
}

fn validate_accepted_summary(
    context: &CallContext,
    workspace: &Path,
    reference: &FileReceiptRef,
    accepted: &AcceptedSummaryViewV1,
    analysis: &Value,
    analysis_ref: &FileReceiptRef,
) -> Result<(), LifecycleFailureV1> {
    let replayed =
        validate_accepted_summary_chain_v1(context, workspace, reference).map_err(|error| {
            LifecycleFailureV1 {
                code: error.code,
                stage: "build.finalize.v2",
                message: error.message,
                recovery_hint: "rebuild P03 acceptance from the exact P02/P03 chain",
            }
        })?;
    let replayed: AcceptedSummaryViewV1 = serde_json::from_value(replayed)
        .map_err(|error| invalid_state("build.finalize.v2", error.to_string()))?;
    if &replayed != accepted {
        return Err(invalid_state(
            "build.finalize.v2",
            "accepted summary differs from P03 chain replay",
        ));
    }
    validate_semantic_ref(
        reference,
        "summary/accepted",
        &accepted.accepted_summary_sha256,
        "build.finalize.v2",
    )?;
    if accepted.schema_version != "gtkg.accepted-summary-candidate/v1"
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
            != digest_without(accepted, "accepted_summary_sha256", "build.finalize.v2")?
        || analysis["source_snapshot_exact_set_sha256"] != accepted.source_snapshot_exact_set_sha256
    {
        return Err(invalid_state(
            "build.finalize.v2",
            "accepted summary chain is invalid",
        ));
    }
    let proposal: ProposalViewV1 = load_artifact(
        context,
        workspace,
        &accepted.proposal_ref,
        "build.finalize.v2",
    )?;
    let verification: SummaryVerificationViewV1 = load_artifact(
        context,
        workspace,
        &accepted.summary_verification_ref,
        "build.finalize.v2",
    )?;
    validate_semantic_ref(
        &accepted.proposal_ref,
        "summary/proposals",
        &proposal.proposal_sha256,
        "build.finalize.v2",
    )?;
    validate_semantic_ref(
        &accepted.summary_verification_ref,
        "summary/verifications",
        &verification.summary_verification_sha256,
        "build.finalize.v2",
    )?;
    validate_proposal_view(&proposal)?;
    validate_summary_verification_view(&proposal, &verification)?;
    if proposal.analysis_verification_ref != *analysis_ref
        || analysis["verification_sha256"] != proposal.analysis_verification_sha256
        || proposal.source_snapshot_exact_set_sha256 != accepted.source_snapshot_exact_set_sha256
        || proposal.proposal_sha256 != accepted.proposal_sha256
        || proposal.conflict_count != 0
        || verification.proposal_ref != accepted.proposal_ref
        || verification.proposal_sha256 != proposal.proposal_sha256
        || verification.summary_verification_sha256 != accepted.summary_verification_sha256
        || verification.rejected_count != 0
        || verification.conflict_count != 0
        || verification.verified_count != verification.decisions.len() as u64
        || verification.actor_independence_state != "declared_distinct_not_attested"
        || accepted.proposer_note != proposal.proposer_note
        || accepted.context_pack_sha256 != proposal.context_pack_sha256
    {
        return Err(invalid_state(
            "build.finalize.v2",
            "summary predecessor chain is invalid",
        ));
    }
    let resolved = analysis["adapter_verifications"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|run| run["fact_receipts"].as_array().into_iter().flatten())
        .filter(|receipt| receipt["resolution"] == "resolved_verified")
        .filter_map(|receipt| receipt["receipt_sha256"].as_str())
        .collect::<BTreeSet<_>>();
    if accepted
        .asserted_claims
        .iter()
        .any(|claim| !resolved.contains(claim.fact_receipt_sha256.as_str()))
    {
        return Err(invalid_state(
            "build.finalize.v2",
            "summary claim is not P02-resolved",
        ));
    }
    let expected_claims = proposal
        .decisions
        .iter()
        .filter(|decision| decision.state == SummaryFactDecisionStateV2::Supported)
        .map(|decision| AssertedClaimV1 {
            fact_receipt_sha256: decision.fact_receipt_sha256.clone(),
            proposal_decision_sha256: decision.proposal_decision_sha256.clone(),
        })
        .collect::<Vec<_>>();
    if accepted.asserted_claims != expected_claims {
        return Err(invalid_state(
            "build.finalize.v2",
            "accepted claims differ from supported proposal decisions",
        ));
    }
    Ok(())
}

fn validate_proposal_view(proposal: &ProposalViewV1) -> Result<(), LifecycleFailureV1> {
    let supported = proposal
        .decisions
        .iter()
        .filter(|decision| decision.state == SummaryFactDecisionStateV2::Supported)
        .count() as u64;
    let abstained = proposal
        .decisions
        .iter()
        .filter(|decision| decision.state == SummaryFactDecisionStateV2::Abstain)
        .count() as u64;
    let conflicted = proposal
        .decisions
        .iter()
        .filter(|decision| decision.state == SummaryFactDecisionStateV2::Conflict)
        .count() as u64;
    let mut fact_ids = BTreeSet::new();
    let mut decision_ids = BTreeSet::new();
    for decision in &proposal.decisions {
        if !fact_ids.insert(decision.fact_receipt_sha256.as_str())
            || !decision_ids.insert(decision.proposal_decision_sha256.as_str())
            || decision.proposal_decision_sha256
                != digest_without(decision, "proposal_decision_sha256", "build.finalize.v2")?
        {
            return Err(invalid_state(
                "build.finalize.v2",
                "proposal decision identity is invalid",
            ));
        }
    }
    if proposal.schema_version != "gtkg.summary-proposal/v1"
        || proposal.decisions.is_empty()
        || proposal.supported_count != supported
        || proposal.abstention_count != abstained
        || proposal.conflict_count != conflicted
        || proposal.provider_call_count != 0
        || proposal.network_call_count != 0
        || proposal.canonical_write_count != 0
        || proposal.proposal_sha256
            != digest_without(proposal, "proposal_sha256", "build.finalize.v2")?
    {
        return Err(invalid_state(
            "build.finalize.v2",
            "proposal is invalid or tampered",
        ));
    }
    Ok(())
}

fn validate_summary_verification_view(
    proposal: &ProposalViewV1,
    verification: &SummaryVerificationViewV1,
) -> Result<(), LifecycleFailureV1> {
    let verified = verification
        .decisions
        .iter()
        .filter(|decision| decision.state == SummaryVerificationDecisionStateV2::Verified)
        .count() as u64;
    let rejected = verification
        .decisions
        .iter()
        .filter(|decision| decision.state == SummaryVerificationDecisionStateV2::Rejected)
        .count() as u64;
    let conflicted = verification
        .decisions
        .iter()
        .filter(|decision| decision.state == SummaryVerificationDecisionStateV2::Conflict)
        .count() as u64;
    let expected = proposal
        .decisions
        .iter()
        .map(|decision| decision.proposal_decision_sha256.as_str())
        .collect::<BTreeSet<_>>();
    let mut observed = BTreeSet::new();
    for decision in &verification.decisions {
        if !expected.contains(decision.proposal_decision_sha256.as_str())
            || !observed.insert(decision.proposal_decision_sha256.as_str())
            || decision.decision_receipt_sha256
                != digest_without(decision, "decision_receipt_sha256", "build.finalize.v2")?
        {
            return Err(invalid_state(
                "build.finalize.v2",
                "verification decision identity is invalid",
            ));
        }
    }
    if verification.schema_version != "gtkg.summary-verification/v1"
        || observed != expected
        || verification.verified_count != verified
        || verification.rejected_count != rejected
        || verification.conflict_count != conflicted
        || verification.verifier_id == proposal.proposer_id
        || verification.actor_independence_state != "declared_distinct_not_attested"
        || verification.provider_call_count != 0
        || verification.network_call_count != 0
        || verification.canonical_write_count != 0
        || verification.summary_verification_sha256
            != digest_without(
                verification,
                "summary_verification_sha256",
                "build.finalize.v2",
            )?
    {
        return Err(invalid_state(
            "build.finalize.v2",
            "summary verification is invalid or tampered",
        ));
    }
    Ok(())
}

fn legacy_workspace_relative_path(
    context: &CallContext,
    requested_workspace: &Path,
    workspace: &Path,
    requested_legacy: &Path,
    stage: &'static str,
) -> Result<PathBuf, LifecycleFailureV1> {
    let relative = if requested_legacy.is_absolute() {
        requested_legacy
            .strip_prefix(requested_workspace)
            .or_else(|_| requested_legacy.strip_prefix(workspace))
            .map(Path::to_path_buf)
            .map_err(|_| LifecycleFailureV1 {
                code: V2ErrorCode::PathEscape,
                stage,
                message: "legacy bundle must be inside the authorized workspace".to_owned(),
                recovery_hint: "copy the v1 bundle into the workspace before migration",
            })?
    } else {
        requested_legacy.to_path_buf()
    };
    validate_legacy_relative_path(&relative, stage)?;
    let candidate = workspace.join(&relative);
    let authorized = context
        .authorize_read(&candidate)
        .map_err(context_failure)?;
    if authorized != candidate {
        return Err(LifecycleFailureV1 {
            code: V2ErrorCode::PathEscape,
            stage,
            message: "legacy bundle path changed identity or traversed a symlink".to_owned(),
            recovery_hint: "use a private symlink-free legacy directory",
        });
    }
    Ok(relative)
}

fn validate_legacy_relative_path(
    relative: &Path,
    stage: &'static str,
) -> Result<(), LifecycleFailureV1> {
    let components = relative.components().collect::<Vec<_>>();
    if relative.is_absolute()
        || components.is_empty()
        || components.len() > MAX_LEGACY_TREE_DEPTH
        || components
            .iter()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(LifecycleFailureV1 {
            code: V2ErrorCode::PathEscape,
            stage,
            message: "legacy bundle reference must be a bounded workspace-relative path".to_owned(),
            recovery_hint: "store a normal relative legacy bundle path",
        });
    }
    Ok(())
}

fn validate_legacy_bundle_tree(
    context: &CallContext,
    workspace: &Path,
    relative: &Path,
    stage: &'static str,
) -> Result<String, LifecycleFailureV1> {
    validate_legacy_relative_path(relative, stage)?;
    let candidate = workspace.join(relative);
    let authorized = context
        .authorize_read(&candidate)
        .map_err(context_failure)?;
    if authorized != candidate {
        return Err(LifecycleFailureV1 {
            code: V2ErrorCode::PathEscape,
            stage,
            message: "stored legacy path escaped the authorized workspace".to_owned(),
            recovery_hint: "rebuild the migrated candidate from an in-workspace v1 bundle",
        });
    }
    let mut files = collect_legacy_tree_files(workspace, relative, stage)?;
    files.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    if files
        .windows(2)
        .any(|pair| pair[0].relative_path == pair[1].relative_path)
    {
        return Err(invalid_state(stage, "legacy tree contains duplicate paths"));
    }
    let manifest = files
        .iter()
        .find(|file| file.relative_path == "manifest.json")
        .ok_or_else(|| invalid(stage, "legacy bundle is missing exact root manifest.json"))?;
    if manifest.bytes.len() > MAX_LEGACY_MANIFEST_BYTES {
        return Err(invalid(
            stage,
            "legacy manifest exceeds the migration bound",
        ));
    }
    let value: Value = serde_json::from_slice(&manifest.bytes)
        .map_err(|error| invalid(stage, format!("legacy manifest is malformed: {error}")))?;
    if value
        .as_object()
        .and_then(|object| object.get("schema_version"))
        .and_then(Value::as_str)
        != Some(LEGACY_BUNDLE_SCHEMA)
    {
        return Err(invalid(
            stage,
            "legacy manifest schema_version must be gtkg.bundle/v1",
        ));
    }
    let mut hasher = Sha256::new();
    for file in files {
        hasher.update(file.relative_path.as_bytes());
        hasher.update([0]);
        hasher.update(&file.bytes);
        hasher.update([0xff]);
    }
    Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
}

#[derive(Debug)]
struct LegacyTreeFileV1 {
    relative_path: String,
    bytes: Vec<u8>,
}

#[cfg(unix)]
fn collect_legacy_tree_files(
    workspace: &Path,
    relative: &Path,
    stage: &'static str,
) -> Result<Vec<LegacyTreeFileV1>, LifecycleFailureV1> {
    use rustix::fs::{Mode, OFlags, fstat, open, openat};

    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut directory = open(workspace, flags, Mode::empty())
        .map_err(|error| legacy_io(stage, workspace, error))?;
    for component in relative.components() {
        let Component::Normal(name) = component else {
            return Err(invalid(
                stage,
                "legacy path contains a non-normal component",
            ));
        };
        directory = openat(&directory, name, flags, Mode::empty())
            .map_err(|error| legacy_io(stage, &workspace.join(relative), error))?;
    }
    let root_identity =
        fstat(&directory).map_err(|error| legacy_io(stage, &workspace.join(relative), error))?;
    let mut files = Vec::new();
    let mut entry_count = 0_u64;
    let mut byte_count = 0_u64;
    collect_legacy_directory(
        &directory,
        Path::new(""),
        0,
        &mut entry_count,
        &mut byte_count,
        &mut files,
        stage,
    )?;
    let root_after =
        fstat(&directory).map_err(|error| legacy_io(stage, &workspace.join(relative), error))?;
    if !same_legacy_stat(&root_identity, &root_after) {
        return Err(invalid_state(
            stage,
            "legacy root changed identity during traversal",
        ));
    }
    let mut reopened = open(workspace, flags, Mode::empty())
        .map_err(|error| legacy_io(stage, workspace, error))?;
    for component in relative.components() {
        let Component::Normal(name) = component else {
            return Err(invalid(
                stage,
                "legacy path contains a non-normal component",
            ));
        };
        reopened = openat(&reopened, name, flags, Mode::empty())
            .map_err(|error| legacy_io(stage, &workspace.join(relative), error))?;
    }
    let reopened_identity =
        fstat(&reopened).map_err(|error| legacy_io(stage, &workspace.join(relative), error))?;
    if !same_legacy_stat(&root_identity, &reopened_identity) {
        return Err(invalid_state(
            stage,
            "legacy root was replaced during traversal",
        ));
    }
    Ok(files)
}

#[cfg(unix)]
#[allow(clippy::too_many_arguments)]
fn collect_legacy_directory(
    directory: &rustix::fd::OwnedFd,
    relative: &Path,
    depth: usize,
    entry_count: &mut u64,
    byte_count: &mut u64,
    files: &mut Vec<LegacyTreeFileV1>,
    stage: &'static str,
) -> Result<(), LifecycleFailureV1> {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::fs::MetadataExt;

    use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags, fstat, openat, statat};

    if depth > MAX_LEGACY_TREE_DEPTH {
        return Err(invalid(stage, "legacy tree exceeds the maximum depth"));
    }
    let mut reader =
        Dir::read_from(directory).map_err(|error| legacy_io(stage, relative, error))?;
    let mut names = Vec::new();
    while let Some(entry) = reader.read() {
        let entry = entry.map_err(|error| legacy_io(stage, relative, error))?;
        let name = entry.file_name().to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        if name.is_empty() || name.len() > 255 || std::str::from_utf8(name).is_err() {
            return Err(invalid(stage, "legacy tree contains an invalid file name"));
        }
        names.push(OsString::from_vec(name.to_vec()));
    }
    names.sort();
    for name in names {
        *entry_count = entry_count
            .checked_add(1)
            .ok_or_else(|| invalid(stage, "legacy entry counter overflow"))?;
        if *entry_count > MAX_LEGACY_TREE_ENTRIES {
            return Err(invalid(stage, "legacy tree exceeds the entry bound"));
        }
        let child_relative = relative.join(&name);
        let before = statat(directory, name.as_os_str(), AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|error| legacy_io(stage, &child_relative, error))?;
        match FileType::from_raw_mode(before.st_mode) {
            FileType::Directory => {
                let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
                let child = openat(directory, name.as_os_str(), flags, Mode::empty())
                    .map_err(|error| legacy_io(stage, &child_relative, error))?;
                let opened =
                    fstat(&child).map_err(|error| legacy_io(stage, &child_relative, error))?;
                if !same_legacy_stat(&before, &opened) {
                    return Err(invalid_state(
                        stage,
                        "legacy directory changed identity before traversal",
                    ));
                }
                collect_legacy_directory(
                    &child,
                    &child_relative,
                    depth + 1,
                    entry_count,
                    byte_count,
                    files,
                    stage,
                )?;
                let opened_after =
                    fstat(&child).map_err(|error| legacy_io(stage, &child_relative, error))?;
                let linked_after = statat(directory, name.as_os_str(), AtFlags::SYMLINK_NOFOLLOW)
                    .map_err(|error| legacy_io(stage, &child_relative, error))?;
                if !same_legacy_stat(&before, &opened_after)
                    || !same_legacy_stat(&before, &linked_after)
                {
                    return Err(invalid_state(
                        stage,
                        "legacy directory changed identity during traversal",
                    ));
                }
            }
            FileType::RegularFile => {
                if before.st_nlink > 1 {
                    return Err(invalid(stage, "legacy tree contains a hard-linked file"));
                }
                let declared_len = u64::try_from(before.st_size)
                    .map_err(|_| invalid(stage, "legacy file length is invalid"))?;
                if declared_len > MAX_LEGACY_FILE_BYTES {
                    return Err(invalid(stage, "legacy file exceeds the per-file bound"));
                }
                let remaining = MAX_LEGACY_TREE_BYTES
                    .checked_sub(*byte_count)
                    .ok_or_else(|| invalid(stage, "legacy tree exceeds the byte bound"))?;
                let flags = OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC;
                let opened = openat(directory, name.as_os_str(), flags, Mode::empty())
                    .map_err(|error| legacy_io(stage, &child_relative, error))?;
                let mut file = File::from(opened);
                let metadata = file
                    .metadata()
                    .map_err(|error| legacy_std_io(stage, &child_relative, error))?;
                if !metadata.is_file()
                    || metadata.nlink() > 1
                    || metadata.dev() != before.st_dev as u64
                    || metadata.ino() != before.st_ino
                    || metadata.len() != declared_len
                {
                    return Err(invalid_state(
                        stage,
                        "legacy file changed identity before read",
                    ));
                }
                let read_bound = remaining.min(MAX_LEGACY_FILE_BYTES);
                let mut bytes = Vec::new();
                std::io::Read::by_ref(&mut file)
                    .take(read_bound.saturating_add(1))
                    .read_to_end(&mut bytes)
                    .map_err(|error| legacy_std_io(stage, &child_relative, error))?;
                let observed_len = u64::try_from(bytes.len())
                    .map_err(|_| invalid(stage, "legacy file length overflow"))?;
                if observed_len > read_bound || observed_len != declared_len {
                    return Err(invalid_state(
                        stage,
                        "legacy file changed length or exceeded the read bound",
                    ));
                }
                let metadata_after = file
                    .metadata()
                    .map_err(|error| legacy_std_io(stage, &child_relative, error))?;
                let linked_after = statat(directory, name.as_os_str(), AtFlags::SYMLINK_NOFOLLOW)
                    .map_err(|error| legacy_io(stage, &child_relative, error))?;
                if metadata_after.dev() != metadata.dev()
                    || metadata_after.ino() != metadata.ino()
                    || metadata_after.len() != metadata.len()
                    || metadata_after.nlink() > 1
                    || !same_legacy_stat(&before, &linked_after)
                {
                    return Err(invalid_state(
                        stage,
                        "legacy file changed identity during read",
                    ));
                }
                *byte_count = byte_count
                    .checked_add(observed_len)
                    .ok_or_else(|| invalid(stage, "legacy byte counter overflow"))?;
                files.push(LegacyTreeFileV1 {
                    relative_path: child_relative
                        .to_str()
                        .ok_or_else(|| invalid(stage, "legacy path must be UTF-8"))?
                        .to_owned(),
                    bytes,
                });
            }
            _ => {
                return Err(invalid(
                    stage,
                    "legacy tree contains a symlink or unsupported filesystem entry",
                ));
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn same_legacy_stat(left: &rustix::fs::Stat, right: &rustix::fs::Stat) -> bool {
    use rustix::fs::FileType;

    left.st_dev == right.st_dev
        && left.st_ino == right.st_ino
        && FileType::from_raw_mode(left.st_mode) == FileType::from_raw_mode(right.st_mode)
}

#[cfg(unix)]
fn legacy_io(stage: &'static str, path: &Path, error: rustix::io::Errno) -> LifecycleFailureV1 {
    legacy_std_io(
        stage,
        path,
        std::io::Error::from_raw_os_error(error.raw_os_error()),
    )
}

fn legacy_std_io(stage: &'static str, path: &Path, error: std::io::Error) -> LifecycleFailureV1 {
    LifecycleFailureV1 {
        code: if error.kind() == std::io::ErrorKind::NotFound {
            V2ErrorCode::NotFound
        } else {
            V2ErrorCode::InvalidState
        },
        stage,
        message: format!("legacy tree read failed at {}: {error}", path.display()),
        recovery_hint: "use an immutable private v1 bundle inside the workspace",
    }
}

#[cfg(not(unix))]
fn collect_legacy_tree_files(
    _workspace: &Path,
    _relative: &Path,
    stage: &'static str,
) -> Result<Vec<LegacyTreeFileV1>, LifecycleFailureV1> {
    Err(invalid_state(
        stage,
        "secure descriptor-bound legacy migration is unavailable on this platform",
    ))
}

fn load_validate_bundle(
    context: &CallContext,
    workspace: &Path,
    reference: &FileReceiptRef,
) -> Result<CandidateBundleV2, LifecycleFailureV1> {
    let bundle: CandidateBundleV2 = load_artifact(context, workspace, reference, "bundle.read")?;
    validate_semantic_ref(
        reference,
        "lifecycle/bundles",
        &bundle.bundle_sha256,
        "bundle.read",
    )?;
    let valid_kind = match bundle.bundle_kind.as_str() {
        "finalized_candidate" => {
            bundle.analysis_verification_ref.is_some()
                && bundle.accepted_summary_ref.is_some()
                && bundle.legacy_bundle_path.is_none()
                && bundle.legacy_tree_sha256.is_none()
                && bundle.provenance_state == "verified_candidate"
                && !bundle.migration_gap
        }
        "migrated_legacy_candidate" => {
            bundle.legacy_bundle_path.is_some()
                && bundle.legacy_tree_sha256.is_some()
                && bundle.provenance_state == "not_proven"
                && bundle.migration_gap
                && bundle.analysis_verification_ref.is_none()
                && bundle.accepted_summary_ref.is_none()
                && bundle.source_snapshot_exact_set_sha256.is_none()
                && bundle.fact_receipt_sha256s.is_empty()
                && bundle.asserted_claim_receipt_sha256s.is_empty()
        }
        _ => false,
    };
    if bundle.schema_version != BUNDLE_SCHEMA
        || !valid_kind
        || !valid_lifecycle_version(&bundle.bundle_version)
        || !bundle.partial
        || bundle.a06_cross_adapter_status != "not_run"
        || bundle.collision_check != "not_run"
        || bundle.canonical_eligible
        || bundle.git_external_write_count != 0
        || bundle.current_write_count != 0
        || bundle.canonical_write_count != 0
        || bundle.bundle_sha256 != digest_without(&bundle, "bundle_sha256", "bundle.read")?
    {
        return Err(invalid_state(
            "bundle.read",
            "bundle is invalid or tampered",
        ));
    }
    if !sorted_unique_or_empty(&bundle.fact_receipt_sha256s)
        || !sorted_unique_or_empty(&bundle.asserted_claim_receipt_sha256s)
        || bundle
            .asserted_claim_receipt_sha256s
            .iter()
            .any(|claim| bundle.fact_receipt_sha256s.binary_search(claim).is_err())
    {
        return Err(invalid_state(
            "bundle.read",
            "bundle fact or asserted-claim exact set is invalid",
        ));
    }
    if bundle.bundle_kind == "finalized_candidate" {
        let analysis_ref = bundle
            .analysis_verification_ref
            .as_ref()
            .ok_or_else(|| invalid_state("bundle.read", "missing analysis reference"))?;
        let accepted_ref = bundle
            .accepted_summary_ref
            .as_ref()
            .ok_or_else(|| invalid_state("bundle.read", "missing summary reference"))?;
        let analysis = validate_verification_chain_v1(context, workspace, analysis_ref)
            .map_err(map_analysis)?;
        let accepted: AcceptedSummaryViewV1 =
            load_artifact(context, workspace, accepted_ref, "bundle.read")?;
        validate_accepted_summary(
            context,
            workspace,
            accepted_ref,
            &accepted,
            &analysis,
            analysis_ref,
        )?;
        let expected_facts = analysis["adapter_verifications"]
            .as_array()
            .into_iter()
            .flatten()
            .flat_map(|run| run["fact_receipts"].as_array().into_iter().flatten())
            .filter_map(|receipt| receipt["receipt_sha256"].as_str())
            .map(str::to_owned)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let expected_claims = accepted
            .asserted_claims
            .iter()
            .map(|claim| claim.fact_receipt_sha256.clone())
            .collect::<Vec<_>>();
        if bundle.analysis_verification_sha256.as_deref()
            != analysis["verification_sha256"].as_str()
            || bundle.accepted_summary_sha256.as_deref()
                != Some(accepted.accepted_summary_sha256.as_str())
            || bundle.source_snapshot_exact_set_sha256.as_deref()
                != analysis["source_snapshot_exact_set_sha256"].as_str()
            || bundle.fact_receipt_sha256s != expected_facts
            || bundle.asserted_claim_receipt_sha256s != expected_claims
        {
            return Err(invalid_state(
                "bundle.read",
                "finalized bundle differs from replayed P02/P03 chain",
            ));
        }
    }
    if bundle.bundle_kind == "migrated_legacy_candidate" {
        let path = bundle
            .legacy_bundle_path
            .as_ref()
            .ok_or_else(|| invalid_state("bundle.read", "missing legacy bundle path"))?;
        let expected = bundle
            .legacy_tree_sha256
            .as_ref()
            .ok_or_else(|| invalid_state("bundle.read", "missing legacy tree identity"))?;
        let observed = validate_legacy_bundle_tree(context, workspace, path, "bundle.read")?;
        if observed != *expected {
            return Err(lock("bundle.read", "legacy bundle tree drifted"));
        }
    }
    Ok(bundle)
}

fn validate_migration_rebuild_provenance(
    context: &CallContext,
    workspace: &Path,
    provenance: &MigrationRebuildProvenanceV1,
    expected_a06_gate: &A06TrustedGateExpectationV1,
) -> Result<(), LifecycleFailureV1> {
    if provenance.schema_version != MIGRATION_PROVENANCE_SCHEMA
        || provenance.provenance_state != "rebuild_bound_not_promoted"
        || provenance.canonical_eligible
        || provenance.current_write_count != 0
        || provenance.canonical_write_count != 0
        || provenance.replay_canonical_write_count != 0
        || provenance.a06_gate_file_sha256 != provenance.a06_gate_ref.sha256
        || provenance.a06_trusted_gate_expectation != *expected_a06_gate
        || provenance.migration_provenance_sha256
            != digest_without(
                provenance,
                "migration_provenance_sha256",
                "migration.provenance.read",
            )?
    {
        return Err(invalid_state(
            "migration.provenance.read",
            "migration provenance record is invalid or tampered",
        ));
    }
    let migrated = load_validate_bundle(context, workspace, &provenance.migration_bundle_ref)?;
    if migrated.bundle_kind != "migrated_legacy_candidate"
        || migrated.bundle_sha256 != provenance.migration_bundle_sha256
        || migrated.provenance_state != "not_proven"
        || !migrated.migration_gap
        || provenance.legacy_provenance_state != "not_proven"
        || !provenance.migration_gap
        || migrated.legacy_tree_sha256.as_deref() != Some(provenance.legacy_tree_sha256.as_str())
    {
        return Err(invalid_state(
            "migration.provenance.read",
            "legacy migration was laundered or its exact tree identity drifted",
        ));
    }
    let rebuilt = load_validate_bundle(context, workspace, &provenance.rebuilt_bundle_ref)?;
    let rebuilt_source_snapshot = rebuilt
        .source_snapshot_exact_set_sha256
        .as_deref()
        .ok_or_else(|| {
            invalid_state(
                "migration.provenance.read",
                "rebuilt bundle is missing the exact source snapshot",
            )
        })?;
    if rebuilt.bundle_kind != "finalized_candidate"
        || rebuilt.bundle_sha256 != provenance.rebuilt_bundle_sha256
        || rebuilt_source_snapshot != provenance.rebuilt_source_snapshot_exact_set_sha256
        || rebuilt_source_snapshot != expected_a06_gate.source_snapshot_exact_set_sha256
    {
        return Err(lock(
            "migration.provenance.read",
            "rebuild source identity does not match the frozen A06 gate expectation",
        ));
    }
    let gate: AdapterGateReceiptV1 = load_artifact(
        context,
        workspace,
        &provenance.a06_gate_ref,
        "migration.provenance.read",
    )?;
    validate_semantic_ref(
        &provenance.a06_gate_ref,
        "a06/gates",
        &gate.receipt_sha256,
        "migration.provenance.read",
    )?;
    gate.validate().map_err(|error| {
        invalid_state(
            "migration.provenance.read",
            format!("A06 gate receipt is invalid: {error}"),
        )
    })?;
    if gate.authority_state != AdapterGateAuthorityStateV1::TrustedFixtureInputBound
        || gate.receipt_sha256 != provenance.a06_gate_receipt_sha256
        || gate.receipt_sha256 != expected_a06_gate.a06_gate_receipt_sha256
        || gate.trusted_oracle_pin_sha256.as_deref()
            != Some(expected_a06_gate.trusted_oracle_pin_sha256.as_str())
        || gate.trusted_oracle_fixture_sha256.as_deref()
            != Some(expected_a06_gate.trusted_oracle_fixture_sha256.as_str())
        || gate.sealed_input_set_sha256.as_deref()
            != Some(expected_a06_gate.sealed_input_set_sha256.as_str())
    {
        return Err(lock(
            "migration.provenance.read",
            "A06 gate is stale, unsealed, or differs from the caller-held trusted expectation",
        ));
    }
    Ok(())
}

fn load_source_snapshot_v2(
    context: &CallContext,
    workspace: &Path,
    reference: &FileReceiptRef,
    stage: &'static str,
) -> Result<SourceSnapshotV2, LifecycleFailureV1> {
    let snapshot: SourceSnapshotV2 = load_artifact(context, workspace, reference, stage)?;
    snapshot
        .validate()
        .map_err(|error| invalid_state(stage, format!("source snapshot is invalid: {error}")))?;
    Ok(snapshot)
}

fn load_validate_a06_source_bound_attestation(
    context: &CallContext,
    workspace: &Path,
    reference: &FileReceiptRef,
) -> Result<A06SourceBoundGateAttestationV1, LifecycleFailureV1> {
    let mut attestation: A06SourceBoundGateAttestationV1 = load_artifact(
        context,
        workspace,
        reference,
        "migration.a06-attestation.read",
    )?;
    validate_semantic_ref(
        reference,
        "lifecycle/a06-source-attestations",
        &attestation.attestation_sha256,
        "migration.a06-attestation.read",
    )?;
    validate_a06_source_bound_attestation(context, workspace, &attestation)?;
    attestation.file_ref = Some(reference.clone());
    Ok(attestation)
}

fn validate_a06_source_bound_attestation(
    context: &CallContext,
    workspace: &Path,
    attestation: &A06SourceBoundGateAttestationV1,
) -> Result<(), LifecycleFailureV1> {
    if attestation.schema_version != A06_SOURCE_BOUND_ATTESTATION_SCHEMA
        || !valid_sha256(&attestation.analysis_verification_sha256)
        || !valid_sha256(&attestation.source_snapshot_exact_set_sha256)
        || !valid_sha256(&attestation.a06_gate_receipt_sha256)
        || !valid_sha256(&attestation.trusted_oracle_fixture_sha256)
        || !valid_sha256(&attestation.attestation_sha256)
        || attestation.verifier_identity.trim().is_empty()
        || attestation.verifier_identity.contains("..")
        || attestation.attestation_sha256
            != digest_without(
                attestation,
                "attestation_sha256",
                "migration.a06-attestation",
            )?
    {
        return Err(invalid_state(
            "migration.a06-attestation",
            "source-bound A06 attestation is invalid or tampered",
        ));
    }
    let analysis =
        validate_verification_chain_v1(context, workspace, &attestation.analysis_verification_ref)
            .map_err(map_analysis)?;
    if analysis["verification_sha256"].as_str()
        != Some(attestation.analysis_verification_sha256.as_str())
    {
        return Err(lock(
            "migration.a06-attestation",
            "P02 verification reference differs from its attested identity",
        ));
    }
    let snapshot = load_source_snapshot_v2(
        context,
        workspace,
        &attestation.source_snapshot_ref,
        "migration.a06-attestation",
    )?;
    if snapshot.exact_set_sha256 != attestation.source_snapshot_exact_set_sha256
        || analysis["source_snapshot_exact_set_sha256"].as_str()
            != Some(snapshot.exact_set_sha256.as_str())
    {
        return Err(lock(
            "migration.a06-attestation",
            "source image is not the exact P02/P03 source snapshot",
        ));
    }
    let source_image = load_source_image(context, workspace, &snapshot, &attestation.source_image)?;
    let gate: AdapterGateReceiptV1 = load_artifact(
        context,
        workspace,
        &attestation.a06_gate_ref,
        "migration.a06-attestation",
    )?;
    validate_semantic_ref(
        &attestation.a06_gate_ref,
        "a06/gates",
        &gate.receipt_sha256,
        "migration.a06-attestation",
    )?;
    gate.validate().map_err(|error| {
        invalid_state(
            "migration.a06-attestation",
            format!("persisted A06 gate is invalid: {error}"),
        )
    })?;
    if gate.authority_state != AdapterGateAuthorityStateV1::TrustedFixtureInputBound
        || gate.receipt_sha256 != attestation.a06_gate_receipt_sha256
    {
        return Err(lock(
            "migration.a06-attestation",
            "persisted A06 gate is not the attested sealed gate",
        ));
    }
    let trusted_fixture: AdapterTrustedOracleFixtureV1 = load_artifact(
        context,
        workspace,
        &attestation.trusted_oracle_fixture_ref,
        "migration.a06-attestation",
    )?;
    let fixture_sha = trusted_fixture.canonical_sha256().map_err(|error| {
        invalid_state(
            "migration.a06-attestation",
            format!("trusted A06 fixture is invalid: {error}"),
        )
    })?;
    if fixture_sha != attestation.trusted_oracle_fixture_sha256
        || gate.trusted_oracle_fixture_sha256.as_deref() != Some(fixture_sha.as_str())
        || gate.trusted_oracle_pin_sha256.as_deref()
            != Some(trusted_fixture.pin.pin_sha256.as_str())
        || gate.oracle_sha256 != trusted_fixture.oracle.oracle_sha256
    {
        return Err(lock(
            "migration.a06-attestation",
            "persisted A06 gate differs from its exact trusted fixture",
        ));
    }
    let replayed = replay_source_bound_a06_gate(
        context,
        workspace,
        attestation,
        &source_image,
        &trusted_fixture,
    )?;
    if replayed != gate {
        return Err(lock(
            "migration.a06-attestation",
            "full strict A06 replay differs from the persisted gate",
        ));
    }
    Ok(())
}

fn load_source_image(
    context: &CallContext,
    workspace: &Path,
    snapshot: &SourceSnapshotV2,
    entries: &[A06SourceImageEntryV1],
) -> Result<BTreeMap<String, Vec<u8>>, LifecycleFailureV1> {
    if !snapshot.omissions.is_empty() || entries.len() != snapshot.inventory.len() {
        return Err(lock(
            "migration.a06-attestation",
            "source image must cover the exact admitted snapshot with no omissions",
        ));
    }
    let mut image = BTreeMap::new();
    for entry in entries {
        let snapshot_entry = snapshot
            .inventory
            .iter()
            .find(|candidate| candidate.logical_path == entry.logical_path)
            .ok_or_else(|| {
                lock(
                    "migration.a06-attestation",
                    "source image contains a path outside the exact snapshot",
                )
            })?;
        if entry.bytes != snapshot_entry.bytes
            || entry.file_ref.sha256 != snapshot_entry.content_sha256
        {
            return Err(lock(
                "migration.a06-attestation",
                "source image entry differs from the snapshot inventory",
            ));
        }
        let bytes = read_reference_bytes(
            context,
            workspace,
            &entry.file_ref,
            "migration.a06-attestation",
        )?;
        if bytes.len() as u64 != entry.bytes
            || image.insert(entry.logical_path.clone(), bytes).is_some()
        {
            return Err(lock(
                "migration.a06-attestation",
                "source image contains duplicate or length-drifted entries",
            ));
        }
    }
    if image.len() != snapshot.inventory.len()
        || snapshot
            .inventory
            .iter()
            .any(|entry| !image.contains_key(&entry.logical_path))
    {
        return Err(lock(
            "migration.a06-attestation",
            "source image is incomplete for the exact snapshot",
        ));
    }
    Ok(image)
}

fn read_reference_bytes(
    context: &CallContext,
    workspace: &Path,
    reference: &FileReceiptRef,
    stage: &'static str,
) -> Result<Vec<u8>, LifecycleFailureV1> {
    let path = context
        .resolve_workspace_receipt(workspace, reference)
        .map_err(context_failure)?;
    let read = read_bound_regular_file(context, &path).map_err(exact_failure)?;
    if read.sha256 != reference.sha256 {
        return Err(lock(stage, "exact source receipt digest mismatch"));
    }
    Ok(read.bytes)
}

#[derive(Debug)]
struct ReplayedSourceBoundAdapterV1 {
    manifest: A06SourceBoundAdapterReplayV1,
    source_files: BTreeMap<String, Vec<u8>>,
    input_bytes: Vec<u8>,
}

fn replay_source_bound_a06_gate(
    context: &CallContext,
    workspace: &Path,
    attestation: &A06SourceBoundGateAttestationV1,
    source_image: &BTreeMap<String, Vec<u8>>,
    trusted_fixture: &AdapterTrustedOracleFixtureV1,
) -> Result<AdapterGateReceiptV1, LifecycleFailureV1> {
    if attestation.adapters.len() != AdapterKindV1::ALL.len() {
        return Err(lock(
            "migration.a06-attestation",
            "source-bound A06 replay requires exactly the frozen five adapters",
        ));
    }
    let mut covered_source_files = BTreeSet::new();
    let mut native = None;
    let mut scip = None;
    let mut lsp = None;
    let mut codegraph = None;
    let mut graphify = None;
    for manifest in &attestation.adapters {
        let material = materialize_source_bound_adapter(
            context,
            workspace,
            manifest,
            source_image,
            &mut covered_source_files,
        )?;
        let target = match manifest.adapter_kind {
            AdapterKindV1::Native => &mut native,
            AdapterKindV1::Scip => &mut scip,
            AdapterKindV1::LspSnapshot => &mut lsp,
            AdapterKindV1::CodeGraphExport => &mut codegraph,
            AdapterKindV1::GraphifyExport => &mut graphify,
        };
        if target.replace(material).is_some() {
            return Err(lock(
                "migration.a06-attestation",
                "source-bound A06 replay contains a duplicate adapter kind",
            ));
        }
    }
    if covered_source_files.len() != source_image.len()
        || source_image
            .keys()
            .any(|logical_path| !covered_source_files.contains(logical_path))
    {
        return Err(lock(
            "migration.a06-attestation",
            "adapter replay source files do not cover the exact source image",
        ));
    }
    let native =
        native.ok_or_else(|| lock("migration.a06-attestation", "missing native replay"))?;
    let scip = scip.ok_or_else(|| lock("migration.a06-attestation", "missing SCIP replay"))?;
    let lsp = lsp.ok_or_else(|| lock("migration.a06-attestation", "missing LSP replay"))?;
    let codegraph =
        codegraph.ok_or_else(|| lock("migration.a06-attestation", "missing CodeGraph replay"))?;
    let graphify =
        graphify.ok_or_else(|| lock("migration.a06-attestation", "missing Graphify replay"))?;
    let native_effects = native_effects(&native.manifest.receipt)?;
    let scip_receipt = scip_receipt(&scip.manifest.receipt)?;
    let lsp_receipt = lsp_receipt(&lsp.manifest.receipt)?;
    let codegraph_receipt = codegraph_receipt(&codegraph.manifest.receipt)?;
    let graphify_receipt = graphify_receipt(&graphify.manifest.receipt)?;
    let submissions = [
        strict_submission(&native, AdapterReceiptRefV1::Native(&native_effects)),
        strict_submission(&scip, AdapterReceiptRefV1::Scip(scip_receipt)),
        strict_submission(&lsp, AdapterReceiptRefV1::Lsp(lsp_receipt)),
        strict_submission(
            &codegraph,
            AdapterReceiptRefV1::CodeGraph(codegraph_receipt),
        ),
        strict_submission(&graphify, AdapterReceiptRefV1::GraphifyV2(graphify_receipt)),
    ];
    verify_adapter_gate_sealed_strict_v1(
        &submissions,
        trusted_fixture,
        &attestation.verifier_identity,
    )
    .map_err(|error| {
        lock(
            "migration.a06-attestation",
            format!("strict source-bound A06 replay failed: {error}"),
        )
    })
}

fn materialize_source_bound_adapter(
    context: &CallContext,
    workspace: &Path,
    manifest: &A06SourceBoundAdapterReplayV1,
    source_image: &BTreeMap<String, Vec<u8>>,
    covered_source_files: &mut BTreeSet<String>,
) -> Result<ReplayedSourceBoundAdapterV1, LifecycleFailureV1> {
    if manifest.descriptor.kind != manifest.adapter_kind
        || !receipt_matches_kind(manifest.adapter_kind, &manifest.receipt)
        || !sorted_unique_or_empty(&manifest.source_file_logical_paths)
    {
        return Err(lock(
            "migration.a06-attestation",
            "adapter replay manifest kind or source-file set is invalid",
        ));
    }
    let input_bytes = read_reference_bytes(
        context,
        workspace,
        &manifest.input_ref,
        "migration.a06-attestation",
    )?;
    if input_bytes.len() as u64 != manifest.input_bytes {
        return Err(lock(
            "migration.a06-attestation",
            "adapter replay input length differs from the immutable manifest",
        ));
    }
    let mut source_files = BTreeMap::new();
    for logical_path in &manifest.source_file_logical_paths {
        let bytes = source_image.get(logical_path).ok_or_else(|| {
            lock(
                "migration.a06-attestation",
                "adapter replay references a source file outside the source image",
            )
        })?;
        covered_source_files.insert(logical_path.clone());
        source_files.insert(logical_path.clone(), bytes.clone());
    }
    Ok(ReplayedSourceBoundAdapterV1 {
        manifest: manifest.clone(),
        source_files,
        input_bytes,
    })
}

fn strict_submission<'a>(
    material: &'a ReplayedSourceBoundAdapterV1,
    receipt: AdapterReceiptRefV1<'a>,
) -> StrictAdapterSubmissionV1<'a> {
    StrictAdapterSubmissionV1 {
        submission: AdapterSubmissionV1 {
            descriptor: &material.manifest.descriptor,
            bundle: &material.manifest.bundle,
            source_files: &material.source_files,
            source_locators: &material.manifest.source_locators,
            receipt,
            input_file_bytes: material.manifest.input_bytes,
            configured_max_file_bytes: material.manifest.configured_max_file_bytes,
        },
        observation: SealedInputObservationV1 {
            actual_input_bytes: &material.input_bytes,
        },
    }
}

fn receipt_matches_kind(kind: AdapterKindV1, receipt: &A06SourceBoundAdapterReceiptV1) -> bool {
    matches!(
        (kind, receipt),
        (
            AdapterKindV1::Native,
            A06SourceBoundAdapterReceiptV1::Native { .. }
        ) | (AdapterKindV1::Scip, A06SourceBoundAdapterReceiptV1::Scip(_))
            | (
                AdapterKindV1::LspSnapshot,
                A06SourceBoundAdapterReceiptV1::Lsp(_)
            )
            | (
                AdapterKindV1::CodeGraphExport,
                A06SourceBoundAdapterReceiptV1::CodeGraph(_)
            )
            | (
                AdapterKindV1::GraphifyExport,
                A06SourceBoundAdapterReceiptV1::Graphify(_)
            )
    )
}

fn native_effects(
    receipt: &A06SourceBoundAdapterReceiptV1,
) -> Result<NativeAdapterEffectsV1, LifecycleFailureV1> {
    match receipt {
        A06SourceBoundAdapterReceiptV1::Native {
            source_file_read_count,
            target_process_count,
            network_call_count,
            write_count,
            executed_target_content,
        } => Ok(NativeAdapterEffectsV1 {
            source_file_read_count: *source_file_read_count,
            target_process_count: *target_process_count,
            network_call_count: *network_call_count,
            write_count: *write_count,
            executed_target_content: *executed_target_content,
        }),
        _ => Err(lock(
            "migration.a06-attestation",
            "native replay has the wrong receipt variant",
        )),
    }
}

fn scip_receipt(
    receipt: &A06SourceBoundAdapterReceiptV1,
) -> Result<&ScipImportReceiptV1, LifecycleFailureV1> {
    match receipt {
        A06SourceBoundAdapterReceiptV1::Scip(receipt) => Ok(receipt),
        _ => Err(lock(
            "migration.a06-attestation",
            "SCIP replay has the wrong receipt variant",
        )),
    }
}

fn lsp_receipt(
    receipt: &A06SourceBoundAdapterReceiptV1,
) -> Result<&LspSnapshotImportReceiptV1, LifecycleFailureV1> {
    match receipt {
        A06SourceBoundAdapterReceiptV1::Lsp(receipt) => Ok(receipt),
        _ => Err(lock(
            "migration.a06-attestation",
            "LSP replay has the wrong receipt variant",
        )),
    }
}

fn codegraph_receipt(
    receipt: &A06SourceBoundAdapterReceiptV1,
) -> Result<&CodeGraphImportReceiptV1, LifecycleFailureV1> {
    match receipt {
        A06SourceBoundAdapterReceiptV1::CodeGraph(receipt) => Ok(receipt),
        _ => Err(lock(
            "migration.a06-attestation",
            "CodeGraph replay has the wrong receipt variant",
        )),
    }
}

fn graphify_receipt(
    receipt: &A06SourceBoundAdapterReceiptV1,
) -> Result<&GraphifyImportReceiptV2, LifecycleFailureV1> {
    match receipt {
        A06SourceBoundAdapterReceiptV1::Graphify(receipt) => Ok(receipt),
        _ => Err(lock(
            "migration.a06-attestation",
            "Graphify replay has the wrong receipt variant",
        )),
    }
}

fn validate_migration_rebuild_provenance_v2(
    context: &CallContext,
    workspace: &Path,
    provenance: &MigrationRebuildProvenanceV2,
) -> Result<(), LifecycleFailureV1> {
    if provenance.schema_version != MIGRATION_PROVENANCE_V2_SCHEMA
        || provenance.provenance_state != "source_bound_rebuild_not_promoted"
        || provenance.canonical_eligible
        || provenance.current_write_count != 0
        || provenance.canonical_write_count != 0
        || provenance.replay_canonical_write_count != 0
        || provenance.migration_provenance_sha256
            != digest_without(
                provenance,
                "migration_provenance_sha256",
                "migration.provenance.v2.read",
            )?
    {
        return Err(invalid_state(
            "migration.provenance.v2.read",
            "source-bound migration provenance is invalid or tampered",
        ));
    }
    let migrated = load_validate_bundle(context, workspace, &provenance.migration_bundle_ref)?;
    if migrated.bundle_kind != "migrated_legacy_candidate"
        || migrated.bundle_sha256 != provenance.migration_bundle_sha256
        || migrated.provenance_state != "not_proven"
        || !migrated.migration_gap
        || provenance.legacy_provenance_state != "not_proven"
        || !provenance.migration_gap
        || migrated.legacy_tree_sha256.as_deref() != Some(provenance.legacy_tree_sha256.as_str())
    {
        return Err(invalid_state(
            "migration.provenance.v2.read",
            "legacy migration was laundered or its exact tree identity drifted",
        ));
    }
    let rebuilt = load_validate_bundle(context, workspace, &provenance.rebuilt_bundle_ref)?;
    let analysis_ref = rebuilt.analysis_verification_ref.as_ref().ok_or_else(|| {
        invalid_state(
            "migration.provenance.v2.read",
            "rebuilt bundle is missing P02 verification",
        )
    })?;
    let source_snapshot = rebuilt
        .source_snapshot_exact_set_sha256
        .as_deref()
        .ok_or_else(|| {
            invalid_state(
                "migration.provenance.v2.read",
                "rebuilt bundle is missing source identity",
            )
        })?;
    let attestation = load_validate_a06_source_bound_attestation(
        context,
        workspace,
        &provenance.a06_source_attestation_ref,
    )?;
    if rebuilt.bundle_kind != "finalized_candidate"
        || rebuilt.bundle_sha256 != provenance.rebuilt_bundle_sha256
        || analysis_ref != &provenance.analysis_verification_ref
        || attestation.analysis_verification_ref != provenance.analysis_verification_ref
        || source_snapshot != provenance.rebuilt_source_snapshot_exact_set_sha256
        || attestation.source_snapshot_exact_set_sha256
            != provenance.rebuilt_source_snapshot_exact_set_sha256
        || attestation.attestation_sha256 != provenance.a06_source_attestation_sha256
        || attestation.a06_gate_ref != provenance.a06_gate_ref
        || attestation.a06_gate_receipt_sha256 != provenance.a06_gate_receipt_sha256
    {
        return Err(lock(
            "migration.provenance.v2.read",
            "source-bound provenance does not match the exact rebuilt A06 lineage",
        ));
    }
    Ok(())
}

fn load_validate_snapshot(
    context: &CallContext,
    workspace: &Path,
    reference: &FileReceiptRef,
) -> Result<SnapshotV2, LifecycleFailureV1> {
    let snapshot: SnapshotV2 = load_artifact(context, workspace, reference, "snapshot.read")?;
    validate_semantic_ref(
        reference,
        "lifecycle/snapshots",
        &snapshot.snapshot_sha256,
        "snapshot.read",
    )?;
    let bundle = load_validate_bundle(context, workspace, &snapshot.bundle_ref)?;
    if snapshot.schema_version != SNAPSHOT_SCHEMA
        || !valid_lifecycle_version(&snapshot.snapshot_version)
        || snapshot.bundle_sha256 != bundle.bundle_sha256
        || !snapshot.replay_only
        || snapshot.canonical_eligible
        || snapshot.current_write_count != 0
        || snapshot.canonical_write_count != 0
        || snapshot.snapshot_sha256
            != digest_without(&snapshot, "snapshot_sha256", "snapshot.read")?
    {
        return Err(invalid_state(
            "snapshot.read",
            "snapshot is invalid or tampered",
        ));
    }
    Ok(snapshot)
}

fn validate_run(reference: &FileReceiptRef, run: &RunStateV1) -> Result<(), LifecycleFailureV1> {
    validate_semantic_ref(
        reference,
        &format!("lifecycle/runs/{}/states", run.run_id),
        &run.run_sha256,
        "run.read",
    )?;
    if run.schema_version != RUN_SCHEMA
        || run.current_write_count != 0
        || run.canonical_write_count != 0
        || run.run_sha256 != digest_without(run, "run_sha256", "run.read")?
    {
        return Err(invalid_state(
            "run.read",
            "run state is invalid or tampered",
        ));
    }
    Ok(())
}

fn validate_run_chain(
    context: &CallContext,
    workspace: &Path,
    reference: &FileReceiptRef,
    run: &RunStateV1,
) -> Result<(), LifecycleFailureV1> {
    validate_run(reference, run)?;
    let bundle = load_validate_bundle(context, workspace, &run.bundle_ref)?;
    if bundle.bundle_sha256 != run.bundle_sha256 {
        return Err(invalid_state("run.read", "run bundle identity drifted"));
    }
    match (&run.status, &run.previous_run_ref, run.cancellation_count) {
        (RunStatusV1::CandidateReady, None, 0) => Ok(()),
        (RunStatusV1::Cancelled, Some(previous_ref), 1) => {
            let previous: RunStateV1 = load_artifact(context, workspace, previous_ref, "run.read")?;
            validate_run(previous_ref, &previous)?;
            if previous.status != RunStatusV1::CandidateReady
                || previous.previous_run_ref.is_some()
                || previous.cancellation_count != 0
                || previous.run_id != run.run_id
                || previous.bundle_ref != run.bundle_ref
                || previous.bundle_sha256 != run.bundle_sha256
            {
                return Err(invalid_state(
                    "run.read",
                    "cancelled run predecessor is invalid",
                ));
            }
            Ok(())
        }
        _ => Err(invalid_state(
            "run.read",
            "run status transition is invalid",
        )),
    }
}

fn run_path(workspace: &Path, run: &RunStateV1) -> Result<PathBuf, LifecycleFailureV1> {
    Ok(workspace.join(format!(
        ".gtkg/lifecycle/runs/{}/states/{}.json",
        run.run_id,
        digest_hex(&run.run_sha256)?
    )))
}

fn run_result(
    reference: FileReceiptRef,
    run: &RunStateV1,
    local_receipt_write_count: u64,
) -> LifecycleResultV1 {
    LifecycleResultV1 {
        result: json!({
            "run_ref": reference,
            "run_id": run.run_id,
            "bundle_ref": run.bundle_ref,
            "bundle_sha256": run.bundle_sha256,
            "status": run.status,
            "cancellation_count": run.cancellation_count,
            "local_receipt_write_count": local_receipt_write_count,
            "current_write_count": 0,
            "canonical_write_count": 0,
        }),
    }
}

fn load_artifact<T>(
    context: &CallContext,
    workspace: &Path,
    reference: &FileReceiptRef,
    stage: &'static str,
) -> Result<T, LifecycleFailureV1>
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
) -> Result<FileReceiptRef, LifecycleFailureV1> {
    let path = publish_immutable_json(
        context,
        path,
        value,
        "lifecycle.after_temp_sync_before_rename",
    )
    .map_err(|error| durable_failure(stage, error.kind, error.to_string()))?;
    let read = read_bound_regular_file(context, &path).map_err(exact_failure)?;
    Ok(FileReceiptRef {
        path: path
            .strip_prefix(workspace)
            .map_err(|_| invalid_state(stage, "artifact escaped workspace"))?
            .to_string_lossy()
            .into_owned(),
        sha256: read.sha256,
    })
}

fn validate_semantic_ref(
    reference: &FileReceiptRef,
    partition: &str,
    semantic: &str,
    stage: &'static str,
) -> Result<(), LifecycleFailureV1> {
    let expected = format!(".gtkg/{partition}/{}.json", digest_hex(semantic)?);
    if reference.path != expected {
        return Err(invalid_state(stage, "semantic path binding mismatch"));
    }
    Ok(())
}

fn digest_without<T: Serialize>(
    value: &T,
    field: &str,
    stage: &'static str,
) -> Result<String, LifecycleFailureV1> {
    let mut encoded =
        serde_json::to_value(value).map_err(|error| invalid_state(stage, error.to_string()))?;
    encoded
        .as_object_mut()
        .ok_or_else(|| invalid_state(stage, "artifact must be object"))?
        .remove(field);
    canonical_json_sha256(&encoded).map_err(|error| invalid_state(stage, error.to_string()))
}

fn digest_hex(value: &str) -> Result<&str, LifecycleFailureV1> {
    value
        .strip_prefix("sha256:")
        .ok_or_else(|| invalid_state("lifecycle.identity", "invalid digest"))
}

fn valid_sha256(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64
            && digest.bytes().all(|byte| {
                byte.is_ascii_digit() || (byte.is_ascii_lowercase() && matches!(byte, b'a'..=b'f'))
            })
    })
}

fn sorted_unique_or_empty(values: &[String]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn valid_lifecycle_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && !value.contains('/')
        && !value.contains("..")
        && !matches!(
            value.to_ascii_lowercase().as_str(),
            "current" | "latest" | "head"
        )
}
fn map_analysis(error: crate::v03::analysis::AnalysisFailureV1) -> LifecycleFailureV1 {
    LifecycleFailureV1 {
        code: error.code,
        stage: "build.finalize.v2",
        message: error.message,
        recovery_hint: "rebuild P02 verification",
    }
}
fn context_failure(error: ContextError) -> LifecycleFailureV1 {
    LifecycleFailureV1 {
        code: V2ErrorCode::PathEscape,
        stage: "lifecycle.path",
        message: error.to_string(),
        recovery_hint: "use authorized private paths",
    }
}
fn exact_failure(error: ExactReadFailure) -> LifecycleFailureV1 {
    LifecycleFailureV1 {
        code: match error.code {
            gtkg_protocol::ErrorCode::PathEscape => V2ErrorCode::PathEscape,
            gtkg_protocol::ErrorCode::SymlinkRejected => V2ErrorCode::SymlinkRejected,
            gtkg_protocol::ErrorCode::NotFound => V2ErrorCode::NotFound,
            _ => V2ErrorCode::Io,
        },
        stage: "lifecycle.readback",
        message: format!("{}: {}", error.path.display(), error.message),
        recovery_hint: "repair exact receipt",
    }
}
fn durable_failure(
    stage: &'static str,
    kind: DurableErrorKind,
    message: String,
) -> LifecycleFailureV1 {
    LifecycleFailureV1 {
        code: match kind {
            DurableErrorKind::Conflict => V2ErrorCode::InvalidState,
            DurableErrorKind::Unauthorized | DurableErrorKind::Unsafe => V2ErrorCode::PathEscape,
            DurableErrorKind::Invalid => V2ErrorCode::InvalidRequest,
            DurableErrorKind::Io => V2ErrorCode::Io,
        },
        stage,
        message,
        recovery_hint: "use non-conflicting immutable lifecycle storage",
    }
}
fn invalid(stage: &'static str, message: impl Into<String>) -> LifecycleFailureV1 {
    LifecycleFailureV1 {
        code: V2ErrorCode::InvalidRequest,
        stage,
        message: message.into(),
        recovery_hint: "use closed P04 contract",
    }
}
fn invalid_state(stage: &'static str, message: impl Into<String>) -> LifecycleFailureV1 {
    LifecycleFailureV1 {
        code: V2ErrorCode::InvalidState,
        stage,
        message: message.into(),
        recovery_hint: "replay lifecycle chain",
    }
}
fn lock(stage: &'static str, message: impl Into<String>) -> LifecycleFailureV1 {
    LifecycleFailureV1 {
        code: V2ErrorCode::LockMismatch,
        stage,
        message: message.into(),
        recovery_hint: "use exact current digest",
    }
}
