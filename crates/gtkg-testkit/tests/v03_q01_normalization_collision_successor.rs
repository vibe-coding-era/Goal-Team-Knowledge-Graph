use gtkg_core::v03::query::{LexicalDocumentV1, build_lexical_shard_v1};
use gtkg_protocol::v03::query::NormalizationCollisionStatusV1;

#[test]
fn successor_builder_preserves_original_forms_and_marks_normalization_collision() {
    let shard = build_lexical_shard_v1(
        "lex-main",
        &[
            LexicalDocumentV1 {
                node_id: "node-nfd".to_owned(),
                evidence_ref: "ev-nfd".to_owned(),
                text: "cafe\u{301}".to_owned(),
            },
            LexicalDocumentV1 {
                node_id: "node-nfc".to_owned(),
                evidence_ref: "ev-nfc".to_owned(),
                text: "café".to_owned(),
            },
        ],
    )
    .expect("build collision-aware shard");

    assert_eq!(shard.normalized_terms.len(), 1);
    assert_eq!(shard.normalized_terms[0].normalized, "café");
    assert_eq!(
        shard.normalized_terms[0].original_forms,
        ["cafe\u{301}", "café"]
    );
    assert_eq!(
        shard.normalized_terms[0].collision_status,
        NormalizationCollisionStatusV1::Ambiguous
    );
}
