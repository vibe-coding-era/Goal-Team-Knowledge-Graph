//! V0.2 T10: local claim verification accepts only byte-grounded claims and
//! makes every uncertainty explicit.  It never invokes a Provider.

use std::path::{Path, PathBuf};

use gtkg_core::claim_v2::{
    AbstentionReasonV2, AtomicClaimV2, ClaimEvidenceRefV2, ClaimModalityV2, ClaimPolarityV2,
    ClaimSetStateV2, ClaimVerificationInputV2, ClaimVerificationStateV2, RiskClassV2,
    T03ClaimEvidenceV2, T04ClaimEvidenceV2, verify_atomic_claims_v2,
};
use gtkg_core::context_v2::{
    ContextChunkV2, ContextPackRequestV2, ContextSourceV2, LocalTokenizerV2, build_context_pack_v2,
};
use gtkg_core::provider_v2::SummaryJobV2;
use gtkg_core::{CallContext, TransportKind};
use gtkg_extract::{build_typed_ir_v2, extract_path};
use gtkg_protocol::v2::{
    OkfSpecPinV2, SourceBaselineIdentityV2, SourceCaptureModeV2, SourceEligibilityV2,
    SourceSnapshotDenominatorV2, SourceSnapshotEntryV2, SourceSnapshotV2,
};
use sha2::{Digest, Sha256};
use tempfile::tempdir;

const SNAPSHOT: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const CURRENT_PIN_SHA256: &str =
    "sha256:26aa5da029278939f914e578107242d9607d4f2dc5fe153272b82f9ed1030101";

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn snapshot(path: &str, source: &str) -> SourceSnapshotV2 {
    SourceSnapshotV2 {
        schema_version: "gtkg.source-snapshot/v2".to_owned(),
        capture_mode: SourceCaptureModeV2::DirectoryExact,
        repository_id: "t10-fixture".to_owned(),
        baseline: SourceBaselineIdentityV2 {
            kind: "directory".to_owned(),
            head: None,
            tree: None,
            status_sha256: SNAPSHOT.to_owned(),
        },
        inventory: vec![SourceSnapshotEntryV2 {
            logical_path: path.to_owned(),
            content_sha256: digest(source.as_bytes()),
            bytes: source.len() as u64,
        }],
        omissions: Vec::new(),
        denominator: SourceSnapshotDenominatorV2 {
            discovered_entries: 1,
            admitted_entries: 1,
            omitted_entries: 0,
        },
        exact_set_sha256: String::new(),
        eligibility: SourceEligibilityV2 {
            development_eligible: true,
            source_release_candidate: false,
            environment_ready: false,
            release_ready: false,
        },
    }
    .with_exact_set_digest()
    .expect("snapshot")
}

fn t03_binding() -> T03ClaimEvidenceV2 {
    T03ClaimEvidenceV2::from_receipt(
        &workspace_root(),
        OkfSpecPinV2::new(
            "0.2",
            "62432a095456147ee71e70ac6e4dc0d2dea3ac30",
            CURRENT_PIN_SHA256,
        )
        .expect("pin"),
        &workspace_root().join("deliverables/v02-t03/current-okf-normative-corpus.json"),
        &workspace_root().join("deliverables/v02-t03/current-okf-normative-corpus-receipt.json"),
    )
    .expect("sealed T03 receipt")
}

fn t04_receipt() -> T04ClaimEvidenceV2 {
    let context = CallContext::restricted(
        TransportKind::Test,
        vec![workspace_root()],
        gtkg_core::EffectPolicy::ReadOnly,
    )
    .expect("test context");
    T04ClaimEvidenceV2::load_local(
        &context,
        &workspace_root().join("crates/gtkg-testkit/fixtures/v02_t04/local-corpus-contract.json"),
    )
    .expect("sealed T04 local corpus")
}

fn fixture() -> (
    Vec<u8>,
    gtkg_protocol::v2::TypedIrV2,
    Vec<gtkg_core::context_v2::ContextSelectedBytesV2>,
    SummaryJobV2,
) {
    let source = b"fn stable() {}\n".to_vec();
    let temp = tempdir().expect("temp");
    let path = temp.path().join("stable.rs");
    std::fs::write(&path, &source).expect("write");
    let ir = build_typed_ir_v2(
        &snapshot("stable.rs", std::str::from_utf8(&source).expect("utf8")),
        "stable.rs",
        &extract_path(&path).expect("extract"),
    )
    .expect("T02 IR");
    let context_source = ContextSourceV2::new(
        ir.source_snapshot_exact_set_sha256.clone(),
        "stable.rs",
        std::str::from_utf8(&source).expect("utf8"),
    );
    let evidence = ir.evidence.first().expect("T02 evidence");
    let chunk = ContextChunkV2::new(
        "stable",
        "focus",
        0,
        &context_source,
        evidence.byte_start,
        evidence.byte_end,
        evidence.id.clone(),
    )
    .expect("chunk");
    let request = ContextPackRequestV2 {
        source_snapshot_exact_set_sha256: ir.source_snapshot_exact_set_sha256.clone(),
        tokenizer: LocalTokenizerV2::controlled_local(),
        token_budget: 10,
        required_chunk_ids: vec!["stable".to_owned()],
        sources: vec![context_source],
        chunks: vec![chunk],
    };
    let selected = build_context_pack_v2(&request)
        .expect("T07 pack")
        .read_selected_bytes(&request)
        .expect("sealed T07 bytes");
    let job = SummaryJobV2::local_only("job.t10", &selected).expect("T09 job");
    (source, ir, selected, job)
}

fn grounded_claim(ir: &gtkg_protocol::v2::TypedIrV2, source: &[u8]) -> AtomicClaimV2 {
    let evidence = ir.evidence.first().expect("IR evidence");
    AtomicClaimV2 {
        claim_id: "claim-stable".to_owned(),
        subject: "stable".to_owned(),
        predicate: "is_declared".to_owned(),
        object: "function".to_owned(),
        polarity: ClaimPolarityV2::Positive,
        modality: ClaimModalityV2::Asserted,
        natural_language: String::from_utf8(
            source[evidence.byte_start as usize..evidence.byte_end as usize].to_vec(),
        )
        .expect("evidence utf8"),
        evidence: vec![ClaimEvidenceRefV2 {
            evidence_id: evidence.id.clone(),
            context_chunk_id: "stable".to_owned(),
            source_snapshot_exact_set_sha256: evidence.source_snapshot_exact_set_sha256.clone(),
            source_logical_path: evidence.source_logical_path.clone(),
            source_sha256: evidence.source_sha256.clone(),
            byte_start: evidence.byte_start,
            byte_end: evidence.byte_end,
            snippet_sha256: evidence.snippet_sha256.clone(),
        }],
        risk_class: RiskClassV2::Normal,
    }
}

#[test]
fn grounded_claims_require_exact_t02_evidence_t07_context_and_t09_job_binding() {
    let (source, ir, selected, job) = fixture();
    let result = verify_atomic_claims_v2(
        ClaimVerificationInputV2 {
            source_bytes: &source,
            typed_ir: &ir,
            selected_context: &selected,
            summary_job: &job,
            t03_evidence: &t03_binding(),
            t04_evidence: &t04_receipt(),
        },
        &[grounded_claim(&ir, &source)],
    )
    .expect("grounded local verification");
    assert_eq!(result.accepted.state, ClaimSetStateV2::AcceptedGrounded);
    assert_eq!(
        result.receipt.claims[0].state,
        ClaimVerificationStateV2::Entailed
    );
    assert!(result.accepted.abstentions.is_empty());
    result.receipt.validate().expect("self-bound receipt");
    result
        .accepted
        .validate(&result.receipt)
        .expect("accepted set");
}

#[test]
fn unknown_becomes_explicit_abstention_but_all_abstain_is_not_accepted() {
    let (source, ir, selected, job) = fixture();
    let mut unknown = grounded_claim(&ir, &source);
    unknown.claim_id = "claim-unknown".to_owned();
    unknown.modality = ClaimModalityV2::Unknown;
    let result = verify_atomic_claims_v2(
        ClaimVerificationInputV2 {
            source_bytes: &source,
            typed_ir: &ir,
            selected_context: &selected,
            summary_job: &job,
            t03_evidence: &t03_binding(),
            t04_evidence: &t04_receipt(),
        },
        &[unknown],
    )
    .expect("unknown is an explicit abstention, not a transport error");
    assert_eq!(
        result.receipt.claims[0].state,
        ClaimVerificationStateV2::Unknown
    );
    assert_eq!(result.accepted.state, ClaimSetStateV2::NoSemanticClaim);
    assert_eq!(
        result.accepted.abstentions[0].reason,
        AbstentionReasonV2::Unknown
    );

    let grounded = grounded_claim(&ir, &source);
    let mut partial_unknown = grounded_claim(&ir, &source);
    partial_unknown.claim_id = "claim-unknown-partial".to_owned();
    partial_unknown.modality = ClaimModalityV2::Unknown;
    let partial = verify_atomic_claims_v2(
        ClaimVerificationInputV2 {
            source_bytes: &source,
            typed_ir: &ir,
            selected_context: &selected,
            summary_job: &job,
            t03_evidence: &t03_binding(),
            t04_evidence: &t04_receipt(),
        },
        &[grounded, partial_unknown],
    )
    .expect("a grounded claim plus explicit abstention is partial, not fully grounded");
    assert_eq!(
        partial.accepted.state,
        ClaimSetStateV2::AcceptedPartialWithAbstention
    );
}

#[test]
fn contradiction_or_uncovered_citation_cannot_escape_into_an_accepted_set() {
    let (source, ir, selected, job) = fixture();
    let positive = grounded_claim(&ir, &source);
    let mut negative = grounded_claim(&ir, &source);
    negative.claim_id = "claim-stable-negative".to_owned();
    negative.polarity = ClaimPolarityV2::Negative;
    let conflicting = verify_atomic_claims_v2(
        ClaimVerificationInputV2 {
            source_bytes: &source,
            typed_ir: &ir,
            selected_context: &selected,
            summary_job: &job,
            t03_evidence: &t03_binding(),
            t04_evidence: &t04_receipt(),
        },
        &[positive, negative],
    )
    .expect("conflict produces a receipt");
    assert_eq!(conflicting.accepted.state, ClaimSetStateV2::Rejected);
    assert!(
        conflicting
            .receipt
            .claims
            .iter()
            .all(|claim| claim.state == ClaimVerificationStateV2::Contradicted)
    );

    let mut uncovered = grounded_claim(&ir, &source);
    uncovered.evidence[0].context_chunk_id = "not-selected".to_owned();
    let rejected = verify_atomic_claims_v2(
        ClaimVerificationInputV2 {
            source_bytes: &source,
            typed_ir: &ir,
            selected_context: &selected,
            summary_job: &job,
            t03_evidence: &t03_binding(),
            t04_evidence: &t04_receipt(),
        },
        &[uncovered],
    )
    .expect("uncovered claim produces a receipt");
    assert_eq!(rejected.accepted.state, ClaimSetStateV2::Rejected);
    assert_eq!(rejected.receipt.coverage.covered_claims, 0);
}

#[test]
fn repeated_or_tampered_snippets_cannot_substitute_a_different_t02_span() {
    let (source, ir, selected, job) = fixture();
    let mut wrong_span = grounded_claim(&ir, &source);
    wrong_span.evidence[0].byte_start += 1;
    let result = verify_atomic_claims_v2(
        ClaimVerificationInputV2 {
            source_bytes: &source,
            typed_ir: &ir,
            selected_context: &selected,
            summary_job: &job,
            t03_evidence: &t03_binding(),
            t04_evidence: &t04_receipt(),
        },
        &[wrong_span],
    )
    .expect("a citation mismatch is an observed rejection");
    assert_eq!(result.accepted.state, ClaimSetStateV2::Rejected);
    assert_eq!(
        result.receipt.claims[0].state,
        ClaimVerificationStateV2::Unsupported
    );
}

#[test]
fn t03_and_t04_evidence_can_only_enter_through_their_restricted_readbacks() {
    let temporary = tempfile::tempdir().expect("temporary evidence");
    let fake_t03 = temporary.path().join("fake-t03.json");
    let current_t03 = std::fs::read_to_string(
        workspace_root().join("deliverables/v02-t03/current-okf-normative-corpus.json"),
    )
    .expect("read frozen T03 manifest");
    std::fs::write(
        &fake_t03,
        current_t03.replace(
            CURRENT_PIN_SHA256,
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        ),
    )
    .expect("write fake T03");
    assert!(
        T03ClaimEvidenceV2::from_receipt(
            &workspace_root(),
            OkfSpecPinV2::new(
                "0.2",
                "62432a095456147ee71e70ac6e4dc0d2dea3ac30",
                CURRENT_PIN_SHA256,
            )
            .expect("pin"),
            &fake_t03,
            &workspace_root()
                .join("deliverables/v02-t03/current-okf-normative-corpus-receipt.json"),
        )
        .is_err()
    );

    let fake_t04 = temporary.path().join("fake-t04.json");
    let current_t04 = std::fs::read_to_string(
        workspace_root().join("crates/gtkg-testkit/fixtures/v02_t04/local-corpus-contract.json"),
    )
    .expect("read frozen T04 manifest");
    std::fs::write(&fake_t04, current_t04.replace("fixture-r1", "HEAD")).expect("write fake T04");
    let context = CallContext::restricted(
        TransportKind::Test,
        vec![temporary.path().to_path_buf()],
        gtkg_core::EffectPolicy::ReadOnly,
    )
    .expect("temporary restricted context");
    assert!(T04ClaimEvidenceV2::load_local(&context, &fake_t04).is_err());
}

#[test]
fn accepted_sets_must_exactly_partition_every_entailed_and_unknown_receipt_record() {
    let (source, ir, selected, job) = fixture();
    let grounded = grounded_claim(&ir, &source);
    let mut unknown = grounded_claim(&ir, &source);
    unknown.claim_id = "claim-unknown-partition".to_owned();
    unknown.modality = ClaimModalityV2::Unknown;
    let result = verify_atomic_claims_v2(
        ClaimVerificationInputV2 {
            source_bytes: &source,
            typed_ir: &ir,
            selected_context: &selected,
            summary_job: &job,
            t03_evidence: &t03_binding(),
            t04_evidence: &t04_receipt(),
        },
        &[grounded, unknown],
    )
    .expect("partial accepted set");
    let mut omitted = result.accepted.clone();
    omitted.accepted_claim_ids.clear();
    omitted.accepted_claim_set_sha256 = omitted.recompute_digest().expect("self digest only");
    assert!(omitted.validate(&result.receipt).is_err());
}

#[test]
fn high_risk_claims_require_distinct_t02_spans_not_duplicate_citations() {
    let (source, ir, selected, job) = fixture();
    let mut high_risk = grounded_claim(&ir, &source);
    high_risk.claim_id = "claim-high-risk".to_owned();
    high_risk.risk_class = RiskClassV2::High;
    high_risk.evidence.push(high_risk.evidence[0].clone());
    let result = verify_atomic_claims_v2(
        ClaimVerificationInputV2 {
            source_bytes: &source,
            typed_ir: &ir,
            selected_context: &selected,
            summary_job: &job,
            t03_evidence: &t03_binding(),
            t04_evidence: &t04_receipt(),
        },
        &[high_risk],
    )
    .expect("duplicate evidence produces a receipt");
    assert_eq!(result.accepted.state, ClaimSetStateV2::Rejected);
    assert_eq!(
        result.receipt.claims[0].state,
        ClaimVerificationStateV2::Unsupported
    );
}

#[test]
fn mixed_entailed_and_rejected_proposals_return_a_valid_auditable_rejected_set() {
    let (source, ir, selected, job) = fixture();
    let entailed = grounded_claim(&ir, &source);
    let mut uncovered = grounded_claim(&ir, &source);
    uncovered.claim_id = "claim-uncovered-mixed".to_owned();
    uncovered.evidence[0].context_chunk_id = "not-selected".to_owned();
    let unsupported = verify_atomic_claims_v2(
        ClaimVerificationInputV2 {
            source_bytes: &source,
            typed_ir: &ir,
            selected_context: &selected,
            summary_job: &job,
            t03_evidence: &t03_binding(),
            t04_evidence: &t04_receipt(),
        },
        &[entailed.clone(), uncovered],
    )
    .expect("mixed unsupported proposal is an auditable rejection");
    assert_eq!(unsupported.accepted.state, ClaimSetStateV2::Rejected);
    assert!(unsupported.accepted.accepted_claim_ids.is_empty());
    assert!(unsupported.accepted.abstentions.is_empty());
    unsupported
        .accepted
        .validate(&unsupported.receipt)
        .expect("rejected representation remains self-valid");
    assert!(
        unsupported
            .receipt
            .claims
            .iter()
            .any(|record| record.state == ClaimVerificationStateV2::Entailed)
    );
    assert!(
        unsupported
            .receipt
            .claims
            .iter()
            .any(|record| record.state == ClaimVerificationStateV2::Unsupported)
    );

    let mut conflict_positive = entailed;
    conflict_positive.claim_id = "claim-conflict-positive".to_owned();
    conflict_positive.subject = "conflict".to_owned();
    let mut conflict_negative = conflict_positive.clone();
    conflict_negative.claim_id = "claim-conflict-negative".to_owned();
    conflict_negative.polarity = ClaimPolarityV2::Negative;
    let contradicted = verify_atomic_claims_v2(
        ClaimVerificationInputV2 {
            source_bytes: &source,
            typed_ir: &ir,
            selected_context: &selected,
            summary_job: &job,
            t03_evidence: &t03_binding(),
            t04_evidence: &t04_receipt(),
        },
        &[
            grounded_claim(&ir, &source),
            conflict_positive,
            conflict_negative,
        ],
    )
    .expect("mixed contradicted proposal is an auditable rejection");
    assert_eq!(contradicted.accepted.state, ClaimSetStateV2::Rejected);
    assert!(contradicted.accepted.accepted_claim_ids.is_empty());
    contradicted
        .accepted
        .validate(&contradicted.receipt)
        .expect("contradicted rejection remains self-valid");
    assert!(
        contradicted
            .receipt
            .claims
            .iter()
            .any(|record| record.state == ClaimVerificationStateV2::Entailed)
    );
    assert!(
        contradicted
            .receipt
            .claims
            .iter()
            .any(|record| record.state == ClaimVerificationStateV2::Contradicted)
    );
}
