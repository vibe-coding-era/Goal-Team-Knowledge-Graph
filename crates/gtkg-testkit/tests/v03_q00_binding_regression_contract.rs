use gtkg_core::v03::query::{
    QueryContractErrorV1, query_index_manifest_sha256_v1, query_shard_catalog_digests_v1,
    tokenize_query_v1, validate_query_plan_receipt_v1,
};
use gtkg_protocol::v03::query::{
    QUERY_INDEX_MANIFEST_SCHEMA_V1, QUERY_PLAN_RECEIPT_SCHEMA_V1, QUERY_TOKENIZER_ID_V1,
    QueryIndexManifestV1, QueryPlanBudgetV1, QueryPlanReceiptV1, QueryResourceBudgetsV1,
    QueryShardCatalogV1, QueryShardDenominatorV1, QueryShardDescriptorV1, QueryShardKindV1,
    QueryTokenKindV1, QueryTruncationStateV1,
};
use sha2::{Digest, Sha256};

fn sha256(value: &str) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(value.as_bytes())))
}

fn manifest() -> QueryIndexManifestV1 {
    let entries = vec![
        QueryShardDescriptorV1 {
            shard_id: "adj-000".to_owned(),
            shard_kind: QueryShardKindV1::Adjacency,
            raw_bytes_sha256: sha256("adj"),
            byte_len: 32,
            record_count: 1,
        },
        QueryShardDescriptorV1 {
            shard_id: "lex-000".to_owned(),
            shard_kind: QueryShardKindV1::Lexical,
            raw_bytes_sha256: sha256("lex"),
            byte_len: 64,
            record_count: 1,
        },
    ];
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

fn receipt(manifest: &QueryIndexManifestV1) -> QueryPlanReceiptV1 {
    QueryPlanReceiptV1 {
        schema_version: QUERY_PLAN_RECEIPT_SCHEMA_V1.to_owned(),
        query_sha256: sha256("query"),
        index_manifest_sha256: query_index_manifest_sha256_v1(manifest),
        selected_shards: vec!["lex-000".to_owned()],
        excluded_shards: vec!["adj-000".to_owned()],
        bytes_read: 64,
        latency_ms: 1,
        budget: QueryPlanBudgetV1::from(manifest.budgets),
        truncation: QueryTruncationStateV1::NotTruncated,
        continuation: None,
    }
}

#[test]
fn query_plan_receipt_binds_the_exact_manifest_bytes() {
    let manifest = manifest();
    let receipt = receipt(&manifest);
    validate_query_plan_receipt_v1(&receipt, &manifest).expect("exact manifest binding");

    let mut stale = receipt;
    stale.index_manifest_sha256 = sha256("different manifest");
    assert_eq!(
        validate_query_plan_receipt_v1(&stale, &manifest),
        Err(QueryContractErrorV1::ManifestIdentityMismatch)
    );
}

#[test]
fn sha256_identities_reject_uppercase_non_canonical_hex() {
    let manifest = manifest();
    let mut receipt = receipt(&manifest);
    receipt.query_sha256 = receipt.query_sha256.to_ascii_uppercase();
    assert_eq!(
        validate_query_plan_receipt_v1(&receipt, &manifest),
        Err(QueryContractErrorV1::InvalidIdentity)
    );
}

#[test]
fn unicode_17_extension_h_and_i_boundaries_are_cjk_runs() {
    let extension_h = char::from_u32(0x323b0).expect("Extension H scalar");
    let extension_i_end = char::from_u32(0x33479).expect("Extension I end scalar");
    let tokenized = tokenize_query_v1(&format!("{extension_h}{extension_i_end}"));
    assert_eq!(tokenized.tokens.len(), 1);
    assert_eq!(tokenized.tokens[0].kind, QueryTokenKindV1::CjkRun);
}
