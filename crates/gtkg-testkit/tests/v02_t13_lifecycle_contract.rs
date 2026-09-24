//! V0.2 T13: local lifecycle semantics are deterministic, replay-safe, and
//! deliberately distinct from externally authorised Current activation.

use gtkg_core::lifecycle_v2::{
    ArtifactSelectorV2, ArtifactStageV2, BundleDispositionV2, BundleFormatV2, LifecycleIdentityV2,
    LocalLifecycleStoreV2, LocalVersionV2, MutationKindV2, PostActivationReadbackReceiptV2,
    compare_full_and_incremental_v2, invalidation_closure_v2, migrate_v1_for_replay_v2,
};

fn digest(byte: char) -> String {
    format!("sha256:{}", byte.to_string().repeat(64))
}

fn identity(seed: char) -> LifecycleIdentityV2 {
    LifecycleIdentityV2 {
        source_snapshot_exact_set_sha256: digest(seed),
        local_resolver_profile_sha256: digest('b'),
        document_relation_receipts_sha256: digest('c'),
        context_pack_sha256: digest('d'),
        claim_verification_receipt_sha256: digest('e'),
        structural_graph_sha256: digest('f'),
        knowledge_overlay_sha256: digest('0'),
    }
}

fn version(
    id: &str,
    format: BundleFormatV2,
    disposition: BundleDispositionV2,
    seed: char,
) -> LocalVersionV2 {
    LocalVersionV2 {
        version_id: id.to_owned(),
        format,
        immutable_bundle_sha256: digest(seed),
        identity: identity(seed),
        disposition,
    }
}

#[test]
fn mutation_matrix_is_conservative_and_full_incremental_identity_must_match() {
    use ArtifactStageV2::*;
    let source = invalidation_closure_v2(MutationKindV2::SourceSnapshot);
    assert_eq!(source.len(), 7);
    assert!(source.contains(&T01SourceSnapshot));
    assert!(source.contains(&T11BKnowledgeOverlay));

    let resolver = invalidation_closure_v2(MutationKindV2::LocalResolver);
    assert_eq!(
        resolver,
        [
            T05LocalResolver,
            T10ClaimVerification,
            T11AStructuralGraph,
            T11BKnowledgeOverlay
        ]
        .into_iter()
        .collect()
    );
    assert_eq!(
        invalidation_closure_v2(MutationKindV2::DocumentRelations),
        [
            T06DocumentRelations,
            T11AStructuralGraph,
            T11BKnowledgeOverlay
        ]
        .into_iter()
        .collect()
    );
    assert_eq!(
        invalidation_closure_v2(MutationKindV2::ContextPack),
        [T07ContextPack, T10ClaimVerification, T11BKnowledgeOverlay]
            .into_iter()
            .collect()
    );

    let same = compare_full_and_incremental_v2(
        MutationKindV2::SourceSnapshot,
        &identity('a'),
        &identity('a'),
    )
    .expect("comparison");
    assert!(same.equal);
    let different = compare_full_and_incremental_v2(
        MutationKindV2::SourceSnapshot,
        &identity('a'),
        &identity('1'),
    )
    .expect("comparison");
    assert!(
        !different.equal,
        "a changed T01 identity cannot pass incremental equality"
    );
}

#[test]
fn current_and_replay_are_tagged_and_replay_has_zero_writes_for_v1_and_v2() {
    let v1 = version(
        "v1-frozen",
        BundleFormatV2::V1,
        BundleDispositionV2::ReplayOnly,
        '1',
    );
    let v2 = version(
        "v2-ready",
        BundleFormatV2::V2,
        BundleDispositionV2::CurrentEligible,
        '2',
    );
    let store = LocalLifecycleStoreV2::new(vec![v1, v2], Some("v2-ready")).expect("store");
    let current_digest = store.current_digest().expect("digest").expect("pointer");
    let current = store
        .select(ArtifactSelectorV2::Current {
            expected_current_sha256: current_digest,
        })
        .expect("current read");
    assert_eq!(current.version_id, "v2-ready");
    let replay_v1 = store
        .select(ArtifactSelectorV2::Replay {
            version_id: "v1-frozen".to_owned(),
        })
        .expect("v1 replay");
    let replay_v2 = store
        .select(ArtifactSelectorV2::Replay {
            version_id: "v2-ready".to_owned(),
        })
        .expect("v2 replay");
    assert_eq!(replay_v1.canonical_write_count, 0);
    assert_eq!(replay_v2.canonical_write_count, 0);
    assert_eq!(
        store.canonical_write_count(),
        0,
        "replay cannot write canonical state"
    );
}

#[test]
fn v1_migration_preserves_source_bytes_and_can_only_be_replayed() {
    let bytes = b"legacy summary: an unverified claim\n".to_vec();
    let before = bytes.clone();
    let migration =
        migrate_v1_for_replay_v2("v1-frozen", &digest('9'), &bytes).expect("migration descriptor");
    assert_eq!(bytes, before, "migration must not rewrite v1 bytes");
    assert_eq!(migration.disposition, BundleDispositionV2::ReplayOnly);
    assert_eq!(migration.semantic_state, "not_proven");
    assert_eq!(migration.migration_gap, "fresh_v2_source_rebuild_required");
}

#[test]
fn cas_conflict_writes_nothing_and_failed_readback_allows_one_compensating_rollback() {
    let previous = version(
        "v2-prev",
        BundleFormatV2::V2,
        BundleDispositionV2::CurrentEligible,
        '3',
    );
    let suspect = version(
        "v2-suspect",
        BundleFormatV2::V2,
        BundleDispositionV2::CurrentEligible,
        '4',
    );
    let mut store =
        LocalLifecycleStoreV2::new(vec![previous, suspect], Some("v2-prev")).expect("store");
    let old = store
        .current_digest()
        .expect("old result")
        .expect("old digest");
    let error = store
        .activate_local_cas(&digest('8'), "v2-suspect")
        .expect_err("wrong CAS must fail");
    assert_eq!(error.code(), "E_V2_LIFECYCLE_CAS_CONFLICT");
    assert_eq!(store.canonical_write_count(), 0);
    let post = store
        .activate_local_cas(&old, "v2-suspect")
        .expect("local activation");
    assert_eq!(store.canonical_write_count(), 1);
    let current = store
        .select(ArtifactSelectorV2::Current {
            expected_current_sha256: post.clone(),
        })
        .expect("exact post-activation readback");
    let receipt = PostActivationReadbackReceiptV2::failed(
        post.clone(),
        post.clone(),
        current.lifecycle_identity_sha256.clone(),
        current.lifecycle_identity_sha256,
        "downstream_exact_verification_failed",
    )
    .expect("typed failure receipt");
    let rollback = store
        .rollback_after_failed_readback_local(&receipt, "v2-prev", "v2-suspect")
        .expect("compensating rollback");
    assert_eq!(rollback, old);
    assert_eq!(store.canonical_write_count(), 2);
    let before_conflict = store.canonical_write_count();
    let conflict = store
        .rollback_after_failed_readback_local(&receipt, "v2-prev", "v2-suspect")
        .expect_err("stale rollback");
    assert_eq!(conflict.code(), "E_V2_LIFECYCLE_CAS_CONFLICT");
    assert_eq!(
        store.canonical_write_count(),
        before_conflict,
        "CAS conflict must write zero times"
    );
}

#[test]
fn initial_current_rejects_replay_only_and_quarantined_versions_without_writing() {
    let replay_only = version(
        "v1-frozen",
        BundleFormatV2::V1,
        BundleDispositionV2::ReplayOnly,
        '7',
    );
    let error = LocalLifecycleStoreV2::new(vec![replay_only], Some("v1-frozen"))
        .expect_err("replay-only cannot seed Current");
    assert_eq!(error.code(), "E_V2_LIFECYCLE_NOT_CURRENT_ELIGIBLE");

    let quarantined = version(
        "v2-quarantined",
        BundleFormatV2::V2,
        BundleDispositionV2::Quarantined,
        '8',
    );
    let error = LocalLifecycleStoreV2::new(vec![quarantined], Some("v2-quarantined"))
        .expect_err("quarantined cannot seed Current");
    assert_eq!(error.code(), "E_V2_LIFECYCLE_NOT_CURRENT_ELIGIBLE");
}

#[test]
fn rollback_receipt_rejects_nonfailed_or_mismatched_readback_without_writing() {
    let previous = version(
        "v2-prev",
        BundleFormatV2::V2,
        BundleDispositionV2::CurrentEligible,
        'a',
    );
    let suspect = version(
        "v2-suspect",
        BundleFormatV2::V2,
        BundleDispositionV2::CurrentEligible,
        'b',
    );
    let mut store =
        LocalLifecycleStoreV2::new(vec![previous, suspect], Some("v2-prev")).expect("store");
    let previous_digest = store.current_digest().expect("digest").expect("pointer");
    let post = store
        .activate_local_cas(&previous_digest, "v2-suspect")
        .expect("activate");
    let selected = store
        .select(ArtifactSelectorV2::Current {
            expected_current_sha256: post.clone(),
        })
        .expect("select");
    let writes = store.canonical_write_count();
    let passed = PostActivationReadbackReceiptV2::passed(
        post.clone(),
        selected.lifecycle_identity_sha256.clone(),
    )
    .expect("passed receipt");
    let error = store
        .rollback_after_failed_readback_local(&passed, "v2-prev", "v2-suspect")
        .expect_err("passed readback cannot rollback");
    assert_eq!(error.code(), "E_V2_LIFECYCLE_ROLLBACK_NOT_PERMITTED");
    assert_eq!(store.canonical_write_count(), writes);

    let mismatch = PostActivationReadbackReceiptV2::failed(
        post,
        digest('c'),
        selected.lifecycle_identity_sha256.clone(),
        selected.lifecycle_identity_sha256,
        "pointer_readback_mismatch",
    )
    .expect("failed mismatch receipt");
    let error = store
        .rollback_after_failed_readback_local(&mismatch, "v2-prev", "v2-suspect")
        .expect_err("stale observed pointer cannot rollback");
    assert_eq!(error.code(), "E_V2_LIFECYCLE_CAS_CONFLICT");
    assert_eq!(store.canonical_write_count(), writes);
}

#[test]
fn replay_only_and_quarantined_versions_cannot_be_current_activated() {
    let ready = version(
        "v2-ready",
        BundleFormatV2::V2,
        BundleDispositionV2::CurrentEligible,
        '5',
    );
    let replay = version(
        "v1-frozen",
        BundleFormatV2::V1,
        BundleDispositionV2::ReplayOnly,
        '6',
    );
    let mut store =
        LocalLifecycleStoreV2::new(vec![ready, replay], Some("v2-ready")).expect("store");
    let current = store
        .current_digest()
        .expect("current result")
        .expect("current digest");
    let error = store
        .activate_local_cas(&current, "v1-frozen")
        .expect_err("legacy is replay-only");
    assert_eq!(error.code(), "E_V2_LIFECYCLE_NOT_CURRENT_ELIGIBLE");
    assert_eq!(store.canonical_write_count(), 0);
    store.quarantine_version("v2-ready").expect("quarantine");
    let error = store
        .activate_local_cas(&current, "v2-ready")
        .expect_err("quarantine cannot activate");
    assert_eq!(error.code(), "E_V2_LIFECYCLE_NOT_CURRENT_ELIGIBLE");
}
