#!/usr/bin/env bash
set -euo pipefail

# Q04's immutable predecessor tests deliberately remain on disk.  This runner
# invokes only the active successor filters where a predecessor is known to be
# superseded, while still running the frozen behavioural r4 test itself.
run_test() {
  local target="$1"
  shift
  cargo test --locked -p gtkg-testkit --test "$target" --quiet "$@"
}

run_test v03_q04_file_graph_operations
run_test v03_q04_continuation_attack_successor
run_test v03_q04_claim_trust_successor
run_test v03_q04_boundary_successor
run_test v03_q04_balanced_continuation_successor_r8
run_test v03_q04_public_schema_successor_r10 \
  q04_r10_closed_schemas_include_previous_page_only_for_structural_slices
run_test v03_q04_continuation_authority_successor
run_test v03_q04_continuation_transport_successor_r12 \
  q04_r12_previous_page_has_cross_process_and_concurrent_semantic_parity
run_test v03_q04_authority_determinism_successor_r15
run_test v03_q04_authority_crash_recovery_successor
run_test v03_q04_transport_process_successor_r17
run_test v03_q04_previous_page_schema_successor_r18
run_test v03_q04_one_shot_continuation_successor_r20
run_test v03_q04_claim_trust_successor_r21

rustfmt --check --edition 2024 \
  crates/gtkg-testkit/tests/v03_q04_claim_trust_successor_r21.rs
cargo check --locked -p gtkg-core
cargo clippy --locked -p gtkg-core -p gtkg-protocol -p gtkg-app -- -D warnings
cargo clippy --locked -p gtkg-testkit --test v03_q04_claim_trust_successor_r21 -- -D warnings
