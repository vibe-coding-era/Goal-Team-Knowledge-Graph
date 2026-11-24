use gtkg_core::v03::query::{
    QueryContractErrorV1, query_index_manifest_sha256_v1, query_shard_catalog_digests_v1,
    tokenize_query_v1, validate_adjacency_shard_json_v1, validate_adjacency_shard_v1,
    validate_lexical_shard_json_v1, validate_lexical_shard_v1,
    validate_query_index_manifest_json_v1, validate_query_index_manifest_v1,
    validate_query_plan_receipt_json_v1, validate_query_plan_receipt_v1,
};
use gtkg_protocol::v03::query::{
    ADJACENCY_SHARD_SCHEMA_V1, AdjacencyDirectionV1, AdjacencyShardV1, LEXICAL_SHARD_SCHEMA_V1,
    LexicalPostingV1, LexicalShardV1, NormalizationCollisionStatusV1, NormalizedTermV1,
    QUERY_INDEX_MANIFEST_SCHEMA_V1, QUERY_PLAN_RECEIPT_SCHEMA_V1, QUERY_TOKENIZER_ID_V1,
    QUERY_UNICODE_VERSION_V1, QueryIndexManifestV1, QueryPlanBudgetV1, QueryPlanReceiptV1,
    QueryResolutionStateV1, QueryResourceBudgetsV1, QueryShardCatalogV1, QueryShardDenominatorV1,
    QueryShardDescriptorV1, QueryShardKindV1, QueryTokenKindV1, QueryTruncationStateV1,
    adjacency_shard_schema_v1, lexical_shard_schema_v1, query_index_manifest_schema_v1,
    query_plan_receipt_schema_v1,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

fn sha256(label: &str) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(label.as_bytes())))
}

fn descriptors() -> Vec<QueryShardDescriptorV1> {
    vec![
        QueryShardDescriptorV1 {
            shard_id: "adj-000".to_owned(),
            shard_kind: QueryShardKindV1::Adjacency,
            raw_bytes_sha256: sha256("adj-000"),
            byte_len: 4_096,
            record_count: 2,
        },
        QueryShardDescriptorV1 {
            shard_id: "lex-000".to_owned(),
            shard_kind: QueryShardKindV1::Lexical,
            raw_bytes_sha256: sha256("lex-000"),
            byte_len: 8_192,
            record_count: 3,
        },
    ]
}

fn manifest() -> QueryIndexManifestV1 {
    let entries = descriptors();
    QueryIndexManifestV1 {
        schema_version: QUERY_INDEX_MANIFEST_SCHEMA_V1.to_owned(),
        source_identity: sha256("source"),
        graph_identity: sha256("graph"),
        overlay_identity: sha256("overlay"),
        tokenizer_id: QUERY_TOKENIZER_ID_V1.to_owned(),
        digests: query_shard_catalog_digests_v1(&entries),
        shards: QueryShardCatalogV1 {
            denominator: QueryShardDenominatorV1 {
                discovered_shards: 2,
                admitted_shards: 2,
                omitted_shards: 0,
            },
            entries,
        },
        budgets: QueryResourceBudgetsV1::v03_frozen(),
    }
}

fn lexical_shard() -> LexicalShardV1 {
    LexicalShardV1 {
        schema_version: LEXICAL_SHARD_SCHEMA_V1.to_owned(),
        shard_id: "lex-000".to_owned(),
        tokenizer_id: QUERY_TOKENIZER_ID_V1.to_owned(),
        unicode_version: QUERY_UNICODE_VERSION_V1.to_owned(),
        normalized_terms: vec![
            NormalizedTermV1 {
                normalized: "café".to_owned(),
                original_forms: vec!["cafe\u{301}".to_owned(), "café".to_owned()],
                collision_status: NormalizationCollisionStatusV1::Ambiguous,
            },
            NormalizedTermV1 {
                normalized: "用户认证".to_owned(),
                original_forms: vec!["用户认证".to_owned()],
                collision_status: NormalizationCollisionStatusV1::Unique,
            },
        ],
        trigrams: vec![
            "afé".to_owned(),
            "caf".to_owned(),
            "户认证".to_owned(),
            "用户认".to_owned(),
        ],
        fst_sha256: sha256("fst"),
        postings: vec![
            LexicalPostingV1 {
                normalized_term: "café".to_owned(),
                node_id: "node-cafe".to_owned(),
                evidence_ref: "ev-cafe".to_owned(),
                positions: vec![0],
            },
            LexicalPostingV1 {
                normalized_term: "用户认证".to_owned(),
                node_id: "node-user".to_owned(),
                evidence_ref: "ev-user".to_owned(),
                positions: vec![3],
            },
        ],
        evidence_refs: vec!["ev-cafe".to_owned(), "ev-user".to_owned()],
        raw_bytes_sha256: sha256("lex-000"),
    }
}

fn adjacency_shard() -> AdjacencyShardV1 {
    AdjacencyShardV1 {
        schema_version: ADJACENCY_SHARD_SCHEMA_V1.to_owned(),
        shard_id: "adj-000".to_owned(),
        node_bucket: "00-0f".to_owned(),
        direction: AdjacencyDirectionV1::Outgoing,
        edge_ids: vec!["edge-01".to_owned(), "edge-02".to_owned()],
        resolution_states: vec![
            QueryResolutionStateV1::Resolved,
            QueryResolutionStateV1::Ambiguous,
        ],
        raw_bytes_sha256: sha256("adj-000"),
    }
}

fn plan_receipt() -> QueryPlanReceiptV1 {
    QueryPlanReceiptV1 {
        schema_version: QUERY_PLAN_RECEIPT_SCHEMA_V1.to_owned(),
        query_sha256: sha256("用户认证"),
        index_manifest_sha256: query_index_manifest_sha256_v1(&manifest()),
        selected_shards: vec!["lex-000".to_owned()],
        excluded_shards: vec!["adj-000".to_owned()],
        bytes_read: 8_192,
        latency_ms: 2,
        budget: QueryPlanBudgetV1::from(QueryResourceBudgetsV1::v03_frozen()),
        truncation: QueryTruncationStateV1::NotTruncated,
        continuation: None,
    }
}

fn assert_root_schema_is_closed(schema: &Value, expected_id: &str) {
    assert_eq!(schema["$id"], expected_id);
    assert_eq!(schema["additionalProperties"], false);
    assert_eq!(schema["type"], "object");
}

#[test]
fn q00_freezes_unicode_17_nfc_ascii_cjk_and_scalar_trigrams() {
    let tokenized = tokenize_query_v1("HTTPServer_2 用户认证 cafe\u{301}");
    assert_eq!(tokenized.tokenizer_id, QUERY_TOKENIZER_ID_V1);
    assert_eq!(tokenized.unicode_version, "17.0.0");
    assert_eq!(tokenized.normalization, "NFC");
    assert_eq!(tokenized.tokens.len(), 3);

    assert_eq!(tokenized.tokens[0].kind, QueryTokenKindV1::AsciiIdentifier);
    assert_eq!(tokenized.tokens[0].normalized, "httpserver_2");
    assert_eq!(
        tokenized.tokens[0].trigrams,
        [
            "htt", "ttp", "tps", "pse", "ser", "erv", "rve", "ver", "er_", "r_2"
        ]
    );

    assert_eq!(tokenized.tokens[1].kind, QueryTokenKindV1::CjkRun);
    assert_eq!(tokenized.tokens[1].normalized, "用户认证");
    assert_eq!(tokenized.tokens[1].trigrams, ["用户认", "户认证"]);

    assert_eq!(tokenized.tokens[2].kind, QueryTokenKindV1::UnicodeWord);
    assert_eq!(tokenized.tokens[2].normalized, "café");
    assert_eq!(tokenized.tokens[2].trigrams, ["caf", "afé"]);
}

#[test]
fn q00_manifest_has_non_zero_closed_denominator_and_frozen_budgets() {
    let manifest = manifest();
    validate_query_index_manifest_v1(&manifest).expect("valid closed query manifest");

    let mut zero = manifest.clone();
    zero.shards.entries.clear();
    zero.shards.denominator = QueryShardDenominatorV1 {
        discovered_shards: 0,
        admitted_shards: 0,
        omitted_shards: 0,
    };
    zero.digests = query_shard_catalog_digests_v1(&zero.shards.entries);
    assert_eq!(
        validate_query_index_manifest_v1(&zero),
        Err(QueryContractErrorV1::ZeroDenominator)
    );

    let mut open = manifest.clone();
    open.shards.denominator.discovered_shards = 3;
    assert_eq!(
        validate_query_index_manifest_v1(&open),
        Err(QueryContractErrorV1::DenominatorNotClosed)
    );

    let mut budget_drift = manifest;
    budget_drift.budgets.max_response_bytes -= 1;
    assert_eq!(
        validate_query_index_manifest_v1(&budget_drift),
        Err(QueryContractErrorV1::FrozenBudgetMismatch)
    );
}

#[test]
fn q00_lexical_collision_status_is_explicit_and_cannot_be_silently_merged() {
    let shard = lexical_shard();
    validate_lexical_shard_v1(&shard, &QueryResourceBudgetsV1::v03_frozen())
        .expect("valid lexical identity");

    let mut laundered = shard;
    laundered.normalized_terms[0].collision_status = NormalizationCollisionStatusV1::Unique;
    assert_eq!(
        validate_lexical_shard_v1(&laundered, &QueryResourceBudgetsV1::v03_frozen()),
        Err(QueryContractErrorV1::CollisionStatusMismatch)
    );
}

#[test]
fn q00_adjacency_and_query_plan_identities_are_closed_and_budget_bound() {
    let adjacency = adjacency_shard();
    validate_adjacency_shard_v1(&adjacency, &QueryResourceBudgetsV1::v03_frozen())
        .expect("valid adjacency identity");

    let manifest = manifest();
    let receipt = plan_receipt();
    validate_query_plan_receipt_v1(&receipt, &manifest).expect("valid plan receipt identity");

    let mut over_budget = receipt.clone();
    over_budget.bytes_read = over_budget.budget.max_bytes_read + 1;
    assert_eq!(
        validate_query_plan_receipt_v1(&over_budget, &manifest),
        Err(QueryContractErrorV1::PlanBudgetExceeded)
    );

    let mut silent = receipt;
    silent.truncation = QueryTruncationStateV1::Truncated;
    assert_eq!(
        validate_query_plan_receipt_v1(&silent, &manifest),
        Err(QueryContractErrorV1::ContinuationRequired)
    );
}

#[test]
fn q00_generated_schemas_and_json_validators_reject_unknown_fields() {
    assert_root_schema_is_closed(
        &query_index_manifest_schema_v1(),
        QUERY_INDEX_MANIFEST_SCHEMA_V1,
    );
    assert_root_schema_is_closed(&lexical_shard_schema_v1(), LEXICAL_SHARD_SCHEMA_V1);
    assert_root_schema_is_closed(&adjacency_shard_schema_v1(), ADJACENCY_SHARD_SCHEMA_V1);
    assert_root_schema_is_closed(
        &query_plan_receipt_schema_v1(),
        QUERY_PLAN_RECEIPT_SCHEMA_V1,
    );

    let mut manifest_json = serde_json::to_value(manifest()).expect("serialize manifest");
    manifest_json["budgets"]["unexpected"] = Value::Bool(true);
    assert!(matches!(
        validate_query_index_manifest_json_v1(&manifest_json),
        Err(QueryContractErrorV1::SchemaDecode { .. })
    ));

    let mut lexical_json = serde_json::to_value(lexical_shard()).expect("serialize lexical");
    lexical_json["unexpected"] = Value::Bool(true);
    assert!(matches!(
        validate_lexical_shard_json_v1(&lexical_json, &QueryResourceBudgetsV1::v03_frozen()),
        Err(QueryContractErrorV1::SchemaDecode { .. })
    ));

    let mut adjacency_json = serde_json::to_value(adjacency_shard()).expect("serialize adjacency");
    adjacency_json["unexpected"] = Value::Bool(true);
    assert!(matches!(
        validate_adjacency_shard_json_v1(&adjacency_json, &QueryResourceBudgetsV1::v03_frozen()),
        Err(QueryContractErrorV1::SchemaDecode { .. })
    ));

    let mut plan_json = serde_json::to_value(plan_receipt()).expect("serialize plan");
    plan_json["budget"]["unexpected"] = Value::Bool(true);
    assert!(matches!(
        validate_query_plan_receipt_json_v1(&plan_json, &manifest()),
        Err(QueryContractErrorV1::SchemaDecode { .. })
    ));
}
