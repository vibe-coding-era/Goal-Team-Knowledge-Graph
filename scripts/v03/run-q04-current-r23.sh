#!/usr/bin/env bash
set -euo pipefail

# r23 names every current Q04 case exactly once. Successor test files that
# include a frozen predecessor are never run wholesale: their distinct
# successor case is selected with --exact and serialized to prevent a helper
# child from racing its parent fixture.
run_case() {
  local target="$1"
  local case_name="$2"
  cargo test --locked -p gtkg-testkit --test "$target" "$case_name" \
    -- --exact --test-threads=1
}

run_case v03_q04_file_graph_operations \
  q04_continuation_is_bound_and_tamper_fails_closed
run_case v03_q04_file_graph_operations \
  q04_dispatcher_uses_only_new_index_payload_and_preserves_read_policy
run_case v03_q04_file_graph_operations \
  q04_runs_300_gold_queries_through_file_indices_with_evidence_pack_parity
run_case v03_q04_file_graph_operations \
  q04_search_preserves_claim_state_and_returns_explicit_no_answer
run_case v03_q04_file_graph_operations \
  q04_stale_identity_budget_and_evidence_tamper_fail_closed
run_case v03_q04_public_schema_successor \
  q04_graph_profile_discovery_projects_the_same_six_input_schemas
run_case v03_q04_continuation_attack_successor \
  q04_self_rehashed_slice_cursor_cannot_repeat_or_skip_the_actual_predecessor_page
run_case v03_q04_claim_trust_successor \
  q04_unsealed_or_cross_state_knowledge_cannot_enter_a_production_evidence_index
run_case v03_q04_boundary_successor \
  q04_dispatcher_rejects_a_lexical_evidence_root_symlink_before_canonicalization
run_case v03_q04_boundary_successor \
  q04_evidence_bytes_account_for_preflight_manifest_replay
run_case v03_q04_boundary_successor \
  q04_trace_routes_exact_entity_id_even_when_human_text_does_not_contain_it
run_case v03_q04_balanced_continuation_successor_r8 \
  q04_r8_balanced_slice_rewrite_cannot_claim_an_unissued_predecessor
run_case v03_q04_public_schema_successor_r10 \
  q04_r10_closed_schemas_include_previous_page_only_for_structural_slices
run_case v03_q04_continuation_authority_successor \
  q04_continuation_requires_private_persistent_authority_not_fabricated_page_content
run_case v03_q04_continuation_transport_successor_r12 \
  q04_r12_previous_page_has_cross_process_and_concurrent_semantic_parity
run_case v03_q04_authority_determinism_successor_r15 \
  q04_r15_same_input_rebuild_reuses_deterministic_manifest_and_private_authority
run_case v03_q04_authority_crash_recovery_successor \
  q04_crash_after_private_authority_before_manifest_recovers_deterministically
run_case v03_q04_transport_process_successor_r17 \
  q04_r17_one_shot_process_and_parallel_consumers_preserve_semantic_continuation
run_case v03_q04_previous_page_schema_successor_r18 \
  q04_optional_fields_reject_explicit_null_exactly_as_the_public_schema_does
run_case v03_q04_previous_page_schema_successor_r18 \
  q04_previous_page_schema_requires_continuation_exactly_where_runtime_does
run_case v03_q04_previous_page_schema_successor_r18 \
  q04_query_budget_uses_unicode_scalar_count_at_schema_and_runtime
run_case v03_q04_one_shot_continuation_successor_r20 \
  q04_r19_no_previous_page_cursor_is_accepted_once_then_replay_fails_closed
run_case v03_q04_claim_trust_successor_r21 \
  q04_strict_writer_signature_remains_available_under_the_active_lint_gate

rustfmt --check --edition 2024 \
  crates/gtkg-testkit/tests/v03_q04_claim_trust_successor_r21.rs
cargo check --locked -p gtkg-core
cargo clippy --locked -p gtkg-core -p gtkg-protocol -p gtkg-app -- -D warnings
cargo clippy --locked -p gtkg-testkit --test v03_q04_claim_trust_successor_r21 -- -D warnings
