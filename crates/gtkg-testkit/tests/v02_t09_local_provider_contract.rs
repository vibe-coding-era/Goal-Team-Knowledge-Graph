//! V0.2 T09: a local-only provider bridge may consume only T07 selected bytes.
//! It records binding metadata and never performs or claims a real Provider call.

use gtkg_core::context_v2::{
    ContextChunkV2, ContextPackRequestV2, ContextSourceV2, LocalTokenizerV2, build_context_pack_v2,
};
use gtkg_core::provider_v2::{
    LocalProviderBridgeV2, LocalProviderConfigV2, ProviderBridgeErrorV2, SummaryJobV2,
};
use sha2::{Digest, Sha256};

const SNAPSHOT: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn selected_bytes() -> Vec<gtkg_core::context_v2::ContextSelectedBytesV2> {
    let source = ContextSourceV2::new(SNAPSHOT, "src/selected.rs", "selected only");
    let chunk = ContextChunkV2::new("selected", "focus", 0, &source, 0, 13, "evidence:selected")
        .expect("valid selected chunk");
    let request = ContextPackRequestV2 {
        source_snapshot_exact_set_sha256: SNAPSHOT.to_owned(),
        tokenizer: LocalTokenizerV2::controlled_local(),
        token_budget: 10,
        required_chunk_ids: vec!["selected".to_owned()],
        sources: vec![source],
        chunks: vec![chunk],
    };
    build_context_pack_v2(&request)
        .expect("pack")
        .read_selected_bytes(&request)
        .expect("sole T07 read boundary")
}

#[test]
fn missing_provider_identity_fails_closed_and_records_metadata_only_attempt() {
    let mut bridge = LocalProviderBridgeV2::new(LocalProviderConfigV2::unavailable());
    let selected = selected_bytes();
    let job = SummaryJobV2::local_only("job.t09", &selected).expect("T07-bound job");
    assert_eq!(
        bridge.attempt(&job, &selected),
        Err(ProviderBridgeErrorV2::ProviderIdentityMissing)
    );
    let receipt = &bridge.attempts()[0];
    assert_eq!(receipt.outcome_code, "E_PROVIDER_IDENTITY");
    assert_eq!(receipt.first_failure_attempt, 1);
    assert!(!receipt.real_provider_call);
    assert!(receipt.provider_identity.is_none());
    assert_eq!(receipt.selected_context.len(), 1);
    receipt
        .validate()
        .expect("metadata-only receipt is self-bound");
}

#[test]
fn unavailable_or_not_implemented_local_provider_stays_fail_closed_and_append_only() {
    let selected = selected_bytes();
    let job = SummaryJobV2::local_only("job.t09", &selected).expect("T07-bound job");
    let mut unavailable = LocalProviderConfigV2::available_local_stub("local.stub");
    unavailable.availability = gtkg_core::provider_v2::LocalProviderAvailabilityV2::Unavailable;
    let mut bridge = LocalProviderBridgeV2::new(unavailable);

    assert_eq!(
        bridge.attempt(&job, &selected),
        Err(ProviderBridgeErrorV2::LocalProviderUnavailable)
    );
    assert_eq!(
        bridge.attempt(&job, &selected),
        Err(ProviderBridgeErrorV2::LocalProviderUnavailable)
    );
    assert_eq!(bridge.attempts().len(), 2);
    assert_eq!(bridge.attempts()[1].first_failure_attempt, 1);
    assert_eq!(
        bridge.attempts()[1].previous_receipt_sha256.as_deref(),
        Some(bridge.attempts()[0].receipt_sha256.as_str())
    );

    let mut no_execution =
        LocalProviderBridgeV2::new(LocalProviderConfigV2::available_local_stub("local.stub"));
    assert_eq!(
        no_execution.attempt(&job, &selected),
        Err(ProviderBridgeErrorV2::LocalProviderNotImplemented)
    );
    let receipt = &no_execution.attempts()[0];
    assert!(!receipt.real_provider_call);
    assert_eq!(receipt.tokenizer.id, "gtkg.local.utf8-word/v1");
    assert_eq!(
        receipt.content_policy.policy_id,
        "gtkg.local-only.no-egress/v1"
    );
    assert!(receipt.transport_identity.is_some());
    assert!(receipt.provider_identity.is_some());
    assert!(receipt.validate().is_ok());
    let serialized = serde_json::to_string(receipt).expect("receipt JSON");
    assert!(
        !serialized.contains("selected only"),
        "attempt receipts must not persist ContextSelectedBytesV2 content"
    );
}

#[test]
fn selected_bytes_are_opaque_and_a_job_rejects_a_different_t07_snapshot() {
    let selected = selected_bytes();
    let job = SummaryJobV2::local_only("job.t09", &selected).expect("T07-bound job");
    let other_snapshot = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let source = ContextSourceV2::new(other_snapshot, "src/other.rs", "different selected");
    let chunk = ContextChunkV2::new("other", "focus", 0, &source, 0, 18, "evidence:other")
        .expect("valid selected chunk");
    let request = ContextPackRequestV2 {
        source_snapshot_exact_set_sha256: other_snapshot.to_owned(),
        tokenizer: LocalTokenizerV2::controlled_local(),
        token_budget: 10,
        required_chunk_ids: vec!["other".to_owned()],
        sources: vec![source],
        chunks: vec![chunk],
    };
    let other = build_context_pack_v2(&request)
        .expect("pack")
        .read_selected_bytes(&request)
        .expect("sole T07 read boundary");
    let mut bridge =
        LocalProviderBridgeV2::new(LocalProviderConfigV2::available_local_stub("local.stub"));
    assert_eq!(
        bridge.attempt(&job, &other),
        Err(ProviderBridgeErrorV2::ContextJobMismatch)
    );
    assert_eq!(
        bridge.attempts().len(),
        1,
        "a valid T07 batch that mismatches the job must preserve its blocked attempt"
    );
}

#[test]
fn same_snapshot_but_different_context_pack_cannot_be_substituted_for_the_job() {
    let selected = selected_bytes();
    let job = SummaryJobV2::local_only("job.t09", &selected).expect("T07-bound job");
    let source = ContextSourceV2::new(SNAPSHOT, "src/other.rs", "same snapshot different pack");
    let chunk = ContextChunkV2::new("other", "focus", 0, &source, 0, 27, "evidence:other")
        .expect("valid selected chunk");
    let request = ContextPackRequestV2 {
        source_snapshot_exact_set_sha256: SNAPSHOT.to_owned(),
        tokenizer: LocalTokenizerV2::controlled_local(),
        token_budget: 10,
        required_chunk_ids: vec!["other".to_owned()],
        sources: vec![source],
        chunks: vec![chunk],
    };
    let other = build_context_pack_v2(&request)
        .expect("second pack")
        .read_selected_bytes(&request)
        .expect("T07 bytes");
    let mut bridge =
        LocalProviderBridgeV2::new(LocalProviderConfigV2::available_local_stub("local.stub"));
    assert_eq!(
        bridge.attempt(&job, &other),
        Err(ProviderBridgeErrorV2::ContextJobMismatch)
    );
    assert_eq!(
        bridge.attempts().len(),
        1,
        "bound mismatch is an attempt receipt"
    );
}

#[test]
fn format_valid_fake_context_ref_is_rejected_before_t09_can_receive_it() {
    let source = ContextSourceV2::new(SNAPSHOT, "src/selected.rs", "selected only");
    let chunk = ContextChunkV2::new("selected", "focus", 0, &source, 0, 13, "evidence:selected")
        .expect("valid selected chunk");
    let request = ContextPackRequestV2 {
        source_snapshot_exact_set_sha256: SNAPSHOT.to_owned(),
        tokenizer: LocalTokenizerV2::controlled_local(),
        token_budget: 10,
        required_chunk_ids: vec!["selected".to_owned()],
        sources: vec![source],
        chunks: vec![chunk],
    };
    let mut pack = build_context_pack_v2(&request).expect("pack");
    pack.selected[0].immutable_content_ref = concat!(
        "context-content:v2:sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb:",
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:0:13:",
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    )
    .to_owned();
    pack.context_pack_sha256 = pack.recompute_digest().expect("format-valid self digest");
    assert!(
        pack.read_selected_bytes(&request).is_err(),
        "T07 replay rejects a format-valid but request-inexact ref"
    );
}

#[test]
fn receipt_chain_rejects_non_adjacent_or_relinked_entries() {
    let selected = selected_bytes();
    let job = SummaryJobV2::local_only("job.t09", &selected).expect("T07-bound job");
    let mut bridge = LocalProviderBridgeV2::new(LocalProviderConfigV2::unavailable());
    let _ = bridge.attempt(&job, &selected);
    let _ = bridge.attempt(&job, &selected);
    let mut relinked = bridge.attempts()[1].clone();
    relinked.previous_receipt_sha256 = None;
    relinked.receipt_sha256 = relinked.recompute_digest().expect("self digest only");
    assert_eq!(
        gtkg_core::provider_v2::ProviderAttemptReceiptV2::validate_chain(
            Some(&bridge.attempts()[0]),
            &relinked,
        ),
        Err(ProviderBridgeErrorV2::ReceiptMismatch)
    );
}

#[test]
fn adapter_and_transport_identity_require_descriptor_bytes_not_label_hashes() {
    let selected = selected_bytes();
    let job = SummaryJobV2::local_only("job.t09", &selected).expect("T07-bound job");

    let mut label_hashed_adapter = LocalProviderConfigV2::available_local_stub("local.stub");
    label_hashed_adapter
        .provider_identity
        .as_mut()
        .expect("configured identity")
        .implementation_sha256 = format!("sha256:{:x}", Sha256::digest(b"local.stub"));
    let mut adapter_bridge = LocalProviderBridgeV2::new(label_hashed_adapter);
    assert_eq!(
        adapter_bridge.attempt(&job, &selected),
        Err(ProviderBridgeErrorV2::ProviderIdentityInvalid)
    );
    assert_eq!(adapter_bridge.attempts().len(), 1);
    assert!(adapter_bridge.attempts()[0].validate().is_ok());

    let mut label_hashed_transport = LocalProviderConfigV2::available_local_stub("local.stub");
    let transport_id = label_hashed_transport
        .transport_identity
        .as_ref()
        .expect("configured transport")
        .transport_id
        .clone();
    label_hashed_transport
        .transport_identity
        .as_mut()
        .expect("configured transport")
        .implementation_sha256 = format!("sha256:{:x}", Sha256::digest(transport_id.as_bytes()));
    let mut transport_bridge = LocalProviderBridgeV2::new(label_hashed_transport);
    assert_eq!(
        transport_bridge.attempt(&job, &selected),
        Err(ProviderBridgeErrorV2::TransportIdentityInvalid)
    );
    assert_eq!(transport_bridge.attempts().len(), 1);
    assert!(transport_bridge.attempts()[0].validate().is_ok());
}
