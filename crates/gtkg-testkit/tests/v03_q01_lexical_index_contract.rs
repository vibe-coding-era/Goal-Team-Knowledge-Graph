use gtkg_core::v03::query::{
    LexicalDocumentV1, LexicalIndexErrorV1, LexicalIndexStateV1, LexicalMatchKindV1,
    LexicalMutationV1, build_lexical_shard_v1, lexical_shard_content_sha256_v1,
    search_lexical_shard_v1,
};

fn document(node_id: &str, evidence_ref: &str, text: &str) -> LexicalDocumentV1 {
    LexicalDocumentV1 {
        node_id: node_id.to_owned(),
        evidence_ref: evidence_ref.to_owned(),
        text: text.to_owned(),
    }
}

#[test]
fn q01_full_build_is_order_independent_and_has_content_bound_fst_and_raw_digests() {
    let left = vec![
        document("node-auth", "ev-auth", "HTTPServer_2 validates user token"),
        document("node-cjk", "ev-cjk", "用户认证流程"),
    ];
    let right = vec![left[1].clone(), left[0].clone()];

    let first = build_lexical_shard_v1("lex-main", &left).expect("first deterministic build");
    let second = build_lexical_shard_v1("lex-main", &right).expect("reordered build");

    assert_eq!(first, second);
    assert_eq!(
        first.raw_bytes_sha256,
        lexical_shard_content_sha256_v1(&first)
    );
    assert_ne!(first.fst_sha256, first.raw_bytes_sha256);
    assert_eq!(first.normalized_terms.len(), 5);
    assert_eq!(first.postings.len(), 5);
}

#[test]
fn q01_search_uses_exact_identifier_phrase_and_cjk_trigram_candidates() {
    let shard = build_lexical_shard_v1(
        "lex-main",
        &[
            document("node-auth", "ev-auth", "HTTPServer_2 validates user token"),
            document(
                "node-decoy",
                "ev-decoy",
                "HTTPServer_20 validates token user",
            ),
            document("node-cjk", "ev-cjk", "用户认证流程"),
        ],
    )
    .expect("build lexical shard");

    let exact = search_lexical_shard_v1(&shard, "HTTPServer_2").expect("exact identifier query");
    assert_eq!(exact.len(), 1);
    assert_eq!(exact[0].node_id, "node-auth");
    assert_eq!(exact[0].match_kind, LexicalMatchKindV1::ExactIdentifier);

    let phrase = search_lexical_shard_v1(&shard, "validates user token").expect("phrase query");
    assert_eq!(phrase.len(), 1);
    assert_eq!(phrase[0].node_id, "node-auth");
    assert_eq!(phrase[0].match_kind, LexicalMatchKindV1::Phrase);

    let cjk = search_lexical_shard_v1(&shard, "用户认证").expect("CJK trigram query");
    assert_eq!(cjk.len(), 1);
    assert_eq!(cjk[0].node_id, "node-cjk");
    assert_eq!(cjk[0].match_kind, LexicalMatchKindV1::CjkTrigram);

    assert!(
        search_lexical_shard_v1(&shard, "missing_symbol")
            .unwrap()
            .is_empty()
    );
    assert!(
        search_lexical_shard_v1(&shard, "认证用户")
            .unwrap()
            .is_empty()
    );
}

#[test]
fn q01_incremental_add_change_delete_is_byte_equivalent_to_full_rebuild() {
    let mut incremental = LexicalIndexStateV1::from_documents(&[
        document("node-a", "ev-a", "alpha old_value"),
        document("node-delete", "ev-delete", "stale ghost posting"),
    ])
    .expect("base state");
    incremental
        .apply_mutations(&[
            LexicalMutationV1::Upsert(document("node-a", "ev-a2", "alpha current_value")),
            LexicalMutationV1::Delete {
                node_id: "node-delete".to_owned(),
            },
            LexicalMutationV1::Upsert(document("node-add", "ev-add", "新增节点 用户认证")),
        ])
        .expect("incremental mutation");
    let incremental_shard = incremental
        .build_shard("lex-main")
        .expect("incremental build");

    let full_shard = build_lexical_shard_v1(
        "lex-main",
        &[
            document("node-a", "ev-a2", "alpha current_value"),
            document("node-add", "ev-add", "新增节点 用户认证"),
        ],
    )
    .expect("full rebuild");

    assert_eq!(incremental_shard, full_shard);
    assert!(
        search_lexical_shard_v1(&incremental_shard, "stale")
            .unwrap()
            .is_empty()
    );
    assert!(
        search_lexical_shard_v1(&incremental_shard, "old_value")
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        search_lexical_shard_v1(&incremental_shard, "current_value").unwrap()[0].node_id,
        "node-a"
    );
}

#[test]
fn q01_invalid_or_ambiguous_document_sets_fail_closed() {
    let duplicate = [
        document("node", "ev-a", "alpha"),
        document("node", "ev-b", "beta"),
    ];
    assert_eq!(
        build_lexical_shard_v1("lex-main", &duplicate),
        Err(LexicalIndexErrorV1::DuplicateNode)
    );
    assert_eq!(
        build_lexical_shard_v1("lex-main", &[document("", "ev", "alpha")]),
        Err(LexicalIndexErrorV1::InvalidDocument)
    );

    let shard = build_lexical_shard_v1("lex-main", &[document("node", "ev", "alpha")])
        .expect("valid shard");
    assert_eq!(
        search_lexical_shard_v1(&shard, "   "),
        Err(LexicalIndexErrorV1::EmptyQuery)
    );
}
