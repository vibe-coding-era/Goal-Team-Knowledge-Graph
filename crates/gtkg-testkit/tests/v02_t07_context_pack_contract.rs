//! V0.2 T07: local ContextPack selection must be deterministic, budget-bound,
//! and snapshot/evidence-bound without claiming provider token accuracy.

use gtkg_core::context_v2::{
    ContextChunkV2, ContextPackErrorCodeV2, ContextPackRequestV2, ContextSourceV2,
    LOCAL_TOKENIZER_IMPLEMENTATION_SHA256_V2, LocalTokenizerV2, build_context_pack_v2,
    local_tokenizer_implementation_sha256_v2,
};

const SNAPSHOT: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn source(id: &str, text: &str) -> ContextSourceV2 {
    ContextSourceV2::new(SNAPSHOT, format!("src/{id}.rs"), text)
}

fn chunk(id: &str, lane: &str, distance: u32, text: &str) -> (ContextSourceV2, ContextChunkV2) {
    let source = source(id, text);
    let chunk = ContextChunkV2::new(
        id,
        lane,
        distance,
        &source,
        0,
        text.len() as u64,
        format!("evidence:{id}"),
    )
    .expect("valid source span");
    (source, chunk)
}

fn request(chunks: Vec<(ContextSourceV2, ContextChunkV2)>) -> ContextPackRequestV2 {
    let (sources, chunks): (Vec<_>, Vec<_>) = chunks.into_iter().unzip();
    ContextPackRequestV2 {
        source_snapshot_exact_set_sha256: SNAPSHOT.to_owned(),
        tokenizer: LocalTokenizerV2::controlled_local(),
        token_budget: 5,
        required_chunk_ids: vec!["a".to_owned()],
        sources,
        chunks,
    }
}

#[test]
fn deterministic_pack_uses_controlled_tokenizer_and_discloses_every_candidate() {
    let chunks = vec![
        chunk("c", "neighbor", 1, "one two three"),
        chunk("b", "focus", 2, "one two"),
        chunk("a", "focus", 0, "one"),
    ];
    let first = build_context_pack_v2(&request(chunks.clone())).expect("context pack");
    let mut reversed = chunks;
    reversed.reverse();
    let second = build_context_pack_v2(&request(reversed)).expect("deterministic context pack");

    assert_eq!(first, second);
    assert_eq!(first.schema_version, "gtkg.context-pack/v2");
    assert_eq!(
        first.tokenizer.implementation_sha256,
        LOCAL_TOKENIZER_IMPLEMENTATION_SHA256_V2
    );
    assert_eq!(
        local_tokenizer_implementation_sha256_v2(),
        LOCAL_TOKENIZER_IMPLEMENTATION_SHA256_V2,
        "the canonical segmentation descriptor must match the reviewed identity"
    );
    assert_eq!(
        first.token_estimation,
        "local_deterministic_estimate_not_provider_accurate"
    );
    assert_eq!(
        first
            .selected
            .iter()
            .map(|item| item.chunk_id.as_str())
            .collect::<Vec<_>>(),
        vec!["a", "b"]
    );
    assert_eq!(first.excluded[0].chunk_id, "c");
    assert_eq!(first.excluded[0].reason, "budget_exceeded");
    assert!(
        first.selected[0]
            .immutable_content_ref
            .starts_with("context-content:v2:sha256:")
    );
    assert_eq!(first.selected_token_count, 3);
    assert_eq!(first.selected.len() + first.excluded.len(), 3);
    first.validate().expect("canonical receipt");
    assert_eq!(
        first
            .read_selected_bytes(&request(vec![
                chunk("c", "neighbor", 1, "one two three"),
                chunk("b", "focus", 2, "one two"),
                chunk("a", "focus", 0, "one"),
            ]))
            .expect("validated consumer read")
            .iter()
            .map(|item| item.content())
            .collect::<Vec<_>>(),
        vec!["one", "one two"]
    );
}

#[test]
fn same_id_but_wrong_implementation_digest_is_rejected() {
    let mut request = request(vec![chunk("a", "focus", 0, "one")]);
    request.tokenizer.implementation_sha256 =
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned();
    assert_eq!(
        build_context_pack_v2(&request)
            .expect_err("format-correct but untrusted implementation")
            .code(),
        ContextPackErrorCodeV2::TokenizerIdentityInvalid
    );
}

#[test]
fn tampered_source_snapshot_or_evidence_is_rejected_before_selection() {
    let mut source_tamper = request(vec![chunk("a", "focus", 0, "one")]);
    source_tamper.sources[0].source.push('!');
    assert_eq!(
        build_context_pack_v2(&source_tamper)
            .expect_err("source bytes no longer match digest")
            .code(),
        ContextPackErrorCodeV2::SourceBindingMismatch
    );

    let mut snapshot_tamper = request(vec![chunk("a", "focus", 0, "one")]);
    snapshot_tamper.chunks[0].source_snapshot_exact_set_sha256 =
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned();
    assert_eq!(
        build_context_pack_v2(&snapshot_tamper)
            .expect_err("chunk has a different source snapshot")
            .code(),
        ContextPackErrorCodeV2::SourceBindingMismatch
    );

    let mut evidence_tamper = request(vec![chunk("a", "focus", 0, "one")]);
    evidence_tamper.chunks[0].evidence.snippet_sha256 =
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned();
    assert_eq!(
        build_context_pack_v2(&evidence_tamper)
            .expect_err("evidence bytes are immutable")
            .code(),
        ContextPackErrorCodeV2::ChunkDigestMismatch
    );
}

#[test]
fn missing_selection_and_tampered_pack_digest_fail_receipt_validation() {
    let request = request(vec![
        chunk("a", "focus", 0, "one"),
        chunk("b", "focus", 1, "two"),
    ]);
    let pack = build_context_pack_v2(&request).expect("pack");

    let mut missing_selection = pack.clone();
    missing_selection.selected.pop();
    assert_eq!(
        missing_selection
            .validate_against_request(&request)
            .expect_err("selection receipt cannot disappear")
            .code(),
        ContextPackErrorCodeV2::ReceiptMismatch
    );

    let mut tampered_digest = pack;
    tampered_digest.context_pack_sha256 =
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned();
    assert_eq!(
        tampered_digest
            .validate()
            .expect_err("canonical digest rebuild")
            .code(),
        ContextPackErrorCodeV2::PackDigestMismatch
    );
}

#[test]
fn recomputed_digest_cannot_authorize_a_tampered_selection_reason_or_consumer_read() {
    let request = request(vec![
        chunk("a", "focus", 0, "one"),
        chunk("b", "focus", 1, "two"),
    ]);
    let mut pack = build_context_pack_v2(&request).expect("pack");
    pack.selected[0].selection_reason = "ranked_within_budget".to_owned();
    pack.context_pack_sha256 = pack.recompute_digest().expect("recomputed self digest");
    assert!(
        pack.validate().is_ok(),
        "self digest alone is not an authorization"
    );
    assert_eq!(
        pack.validate_against_request(&request)
            .expect_err("request-bound replay rejects semantic receipt tamper")
            .code(),
        ContextPackErrorCodeV2::ReceiptMismatch
    );
    assert_eq!(
        pack.read_selected_bytes(&request)
            .expect_err("T09 must not consume an unbound pack")
            .code(),
        ContextPackErrorCodeV2::ReceiptMismatch
    );
}

#[test]
fn empty_candidate_set_and_exact_tie_breaks_fail_closed_or_stay_deterministic() {
    let empty = ContextPackRequestV2 {
        source_snapshot_exact_set_sha256: SNAPSHOT.to_owned(),
        tokenizer: LocalTokenizerV2::controlled_local(),
        token_budget: 1,
        required_chunk_ids: Vec::new(),
        sources: Vec::new(),
        chunks: Vec::new(),
    };
    assert_eq!(
        build_context_pack_v2(&empty)
            .expect_err("empty coverage has no ContextPack")
            .code(),
        ContextPackErrorCodeV2::InvalidRequest
    );

    let mut tie = request(vec![
        chunk("b", "focus", 0, "one"),
        chunk("a", "focus", 0, "one"),
    ]);
    tie.required_chunk_ids.clear();
    tie.token_budget = 1;
    let pack = build_context_pack_v2(&tie).expect("tie break");
    assert_eq!(pack.selected[0].chunk_id, "a");
    assert_eq!(pack.excluded[0].chunk_id, "b");
}

#[test]
fn required_chunk_that_cannot_fit_fails_closed_without_a_truncated_pack() {
    let request = ContextPackRequestV2 {
        token_budget: 2,
        ..request(vec![chunk("a", "focus", 0, "one two three")])
    };
    assert_eq!(
        build_context_pack_v2(&request)
            .expect_err("required content cannot silently truncate")
            .code(),
        ContextPackErrorCodeV2::TokenBudgetExceeded
    );
}
