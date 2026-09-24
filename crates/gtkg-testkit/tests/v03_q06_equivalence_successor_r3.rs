#[path = "support/v03_q06_equivalence_successor_r3_fixture.rs"]
mod fixture;

use gtkg_core::v03::query_equivalence::{
    QueryIndexEquivalenceErrorV1, QueryIndexEquivalenceMutationV1,
    QueryIndexEquivalenceStateV1, verify_full_incremental_file_query_equivalence_v1,
};
use gtkg_core::{CallContext, EffectPolicy, TransportKind};

#[test]
fn q06_r3_projects_base_to_adapter_and_profile_identity_field_diffs_exactly() {
    let base = fixture::identity("source-base", "adapter-base", "profile-base");
    let adapter = fixture::identity("source-base", "adapter-next", "profile-base");
    let profile = fixture::identity("source-base", "adapter-base", "profile-next");
    let source = fixture::identity("source-next", "adapter-base", "profile-base");

    let adapter_diff = base.file_query_projection_diff(&adapter).unwrap();
    assert!(!adapter_diff.source_input_changed);
    assert!(adapter_diff.adapter_input_changed);
    assert!(!adapter_diff.profile_input_changed);
    assert!(!adapter_diff.source_identity_changed);
    assert!(adapter_diff.graph_identity_changed);
    assert!(adapter_diff.overlay_identity_changed);
    assert!(adapter_diff.terminal_identity_changed);

    let profile_diff = base.file_query_projection_diff(&profile).unwrap();
    assert!(!profile_diff.source_input_changed);
    assert!(!profile_diff.adapter_input_changed);
    assert!(profile_diff.profile_input_changed);
    assert!(!profile_diff.source_identity_changed);
    assert!(!profile_diff.graph_identity_changed);
    assert!(profile_diff.overlay_identity_changed);
    assert!(profile_diff.terminal_identity_changed);

    let source_diff = base.file_query_projection_diff(&source).unwrap();
    assert!(source_diff.source_input_changed);
    assert!(!source_diff.adapter_input_changed);
    assert!(!source_diff.profile_input_changed);
    assert!(source_diff.source_identity_changed);
    assert!(source_diff.graph_identity_changed);
    assert!(source_diff.overlay_identity_changed);
    assert!(source_diff.terminal_identity_changed);
}

#[test]
fn q06_r3_mixed_invalid_batch_is_atomic_and_terminal_mismatch_fails_closed() {
    let base = fixture::base_input();
    let mut state = QueryIndexEquivalenceStateV1::from_input(&base).unwrap();
    let before = state.snapshot();
    let error = state
        .apply_mutations(&[
            QueryIndexEquivalenceMutationV1::Lexical {
                shard_id: "lex-main".to_owned(),
                document: fixture::document("node-delta", "delta must not commit"),
            },
            QueryIndexEquivalenceMutationV1::GraphEdgeUpsert(fixture::edge(
                "edge-alpha-missing",
                "node-alpha",
                "node-missing",
            )),
        ])
        .unwrap_err();
    assert!(matches!(error, QueryIndexEquivalenceErrorV1::Adjacency(_)));
    assert_eq!(state.snapshot(), before);

    let workspace = tempfile::tempdir().unwrap();
    let context = CallContext::restricted(
        TransportKind::Test,
        vec![workspace.path().to_path_buf()],
        EffectPolicy::WorkspaceWrite,
    )
    .unwrap();
    let terminal = fixture::edge_replacement_terminal();
    let error = verify_full_incremental_file_query_equivalence_v1(
        &context,
        &workspace.path().join("full"),
        &workspace.path().join("incremental"),
        &base,
        &[QueryIndexEquivalenceMutationV1::Identity {
            component: gtkg_core::v03::query_equivalence::QueryIndexIdentityComponentV1::Source,
            value: fixture::digest("source-edge-replacement"),
        }],
        &terminal,
        &[fixture::adjacency_alpha()],
    )
    .unwrap_err();
    assert!(matches!(
        error,
        QueryIndexEquivalenceErrorV1::TerminalStateMismatch
    ));
}

#[test]
fn q06_r3_same_cardinality_edge_replacement_exposes_actual_edge_ids() {
    let base = fixture::base_input();
    let terminal = fixture::edge_replacement_terminal();
    let workspace = tempfile::tempdir().unwrap();
    let context = CallContext::restricted(
        TransportKind::Test,
        vec![workspace.path().to_path_buf()],
        EffectPolicy::WorkspaceWrite,
    )
    .unwrap();
    let report = verify_full_incremental_file_query_equivalence_v1(
        &context,
        &workspace.path().join("full"),
        &workspace.path().join("incremental"),
        &base,
        &fixture::edge_replacement_mutations(),
        &terminal,
        &[fixture::adjacency_alpha()],
    )
    .unwrap();
    let result = &report.query_results[0];
    assert_eq!(
        result.full_adjacency_edge_ids,
        ["edge-alpha-beta", "edge-alpha-gamma-replacement"]
    );
    assert_eq!(
        result.incremental_adjacency_edge_ids,
        ["edge-alpha-beta", "edge-alpha-gamma-replacement"]
    );
    assert!(!result
        .full_adjacency_edge_ids
        .contains(&"edge-alpha-gamma".to_owned()));
    assert_eq!(result.full_result_count, 2);
    assert_eq!(result.incremental_result_count, 2);
}
