#!/bin/sh
# Execute the bounded commands printed by docs/v03-product/U05-local-development.md.
#
# This harness accepts only a freshly-created private temporary output root. It
# does not install a package, modify a real assistant configuration, activate
# Current, contact a provider, or write outside that root and Cargo's normal
# build cache.
set -eu

if [ "$#" -ne 2 ]; then
  echo "usage: $0 CASE OUTPUT_ROOT" >&2
  echo "CASE: quickstart|privacy|telemetry|recovery|performance|uninstall|all" >&2
  exit 64
fi

case_name=$1
output_root=$2
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)

case "$case_name" in
  quickstart|privacy|telemetry|recovery|performance|uninstall|all) ;;
  *)
    echo "unknown U05 documentation case: $case_name" >&2
    exit 64
    ;;
esac

[ -d "$output_root" ] || {
  echo "U05 output root must be an existing private temporary directory" >&2
  exit 64
}
output_root=$(CDPATH= cd -- "$output_root" && pwd -P)
case "$output_root" in
  /private/tmp/gtkg-u05-docs-* | /tmp/gtkg-u05-docs-*) ;;
  *)
    echo "refusing non-isolated U05 output root: $output_root" >&2
    exit 73
    ;;
esac
[ ! -e "$output_root/u05-docs-as-tests-receipt.json" ] || {
  echo "refusing to overwrite an existing U05 receipt" >&2
  exit 73
}
if [ "$case_name" = all ] \
  && [ -n "$(find "$output_root" -mindepth 1 -maxdepth 1 -print -quit)" ]; then
  echo "the all case requires a new empty U05 output root" >&2
  exit 73
fi

run_cargo_test() {
  label=$1
  test_target=$2
  test_name=$3
  cargo test --locked -p gtkg-testkit --test "$test_target" -- --exact "$test_name" --nocapture \
    >"$output_root/$label.stdout.log" 2>"$output_root/$label.stderr.log"
}

write_case_receipt() {
  label=$1
  state=$2
  command_summary=$3
  printf '%s\n' \
    '{' \
    '  "schema_version":"gtkg.u05-docs-case-receipt/v1",' \
    "  \"case\":\"$label\", " \
    "  \"state\":\"$state\", " \
    '  "scope":"local_development_only",' \
    "  \"command_summary\":\"$command_summary\"" \
    '}' >"$output_root/$label.receipt.json"
}

run_quickstart() {
  (
    cd "$repo_root"
    cargo build --locked -p gtkg-app --bin gtkg \
      >"$output_root/quickstart-build.stdout.log" \
      2>"$output_root/quickstart-build.stderr.log"
    ./target/debug/gtkg v2-discover --profile core --output json \
      >"$output_root/quickstart-discovery.json"
    grep -F '"profile_id":"core"' "$output_root/quickstart-discovery.json" >/dev/null
    profile_tool_count=$(grep -o '"name":"gtkg_v2_[^"]*"' "$output_root/quickstart-discovery.json" | wc -l | tr -d ' ')
    [ "$profile_tool_count" -eq 10 ]
    printf '%s\n' \
      '{"protocol_version":"gtkg.protocol/v2","operation_id":"system.describe","request_id":"u05-quickstart","payload":{}}' \
      | ./target/debug/gtkg v2-op system.describe --profile core --request - --output json \
      >"$output_root/quickstart-system-describe.json"
    grep -F '"scope":"local_development_only"' "$output_root/quickstart-system-describe.json" >/dev/null
    grep -F '"database_backend":null' "$output_root/quickstart-system-describe.json" >/dev/null
  )
  write_case_receipt quickstart passed "build_v2_discovery_system_describe"
}

run_privacy() {
  (
    cd "$repo_root"
    run_cargo_test \
      privacy \
      v03_u02_ownership_bounds_successor \
      successor_preview_redacts_values_and_bounds_profile_and_concurrent_growth
  )
  write_case_receipt privacy passed "u02_receipt_redaction_and_bounds"
}

run_telemetry() {
  (
    cd "$repo_root"
    run_cargo_test \
      telemetry \
      v03_u04_evidence_drawer \
      u04_builds_a_receipt_bound_current_replay_drawer_from_actual_q04_evidence
  )
  write_case_receipt telemetry passed "u04_local_projection_network_counter"
}

run_recovery() {
  (
    cd "$repo_root"
    run_cargo_test \
      recovery \
      v03_u01_fixed_temp_lifecycle_successor_r7 \
      u01_r7_fixed_root_dry_run_fault_rollback_upgrade_rollback_uninstall_and_reinstall
  )
  write_case_receipt recovery passed "u01_isolated_fault_rollback_and_readback"
}

run_performance() {
  performance_dir="$output_root/performance-q05"
  set +e
  (
    cd "$repo_root"
    scripts/v03/run-q05-reference-scale-r3.sh "$performance_dir"
  ) >"$output_root/performance.stdout.log" 2>"$output_root/performance.stderr.log"
  performance_exit=$?
  set -e

  receipt="$performance_dir/receipt.json"
  [ -f "$receipt" ] || {
    echo "Q05 performance harness did not write a receipt" >&2
    exit 70
  }
  if grep -F '"state": "passed"' "$receipt" >/dev/null; then
    [ "$performance_exit" -eq 0 ] || {
      echo "Q05 passed receipt with nonzero exit" >&2
      exit 70
    }
    performance_state=passed
  elif grep -F '"state": "blocked"' "$receipt" >/dev/null; then
    [ "$performance_exit" -ne 0 ] || {
      echo "Q05 blocked receipt unexpectedly returned success" >&2
      exit 70
    }
    performance_state=blocked_reference_host_or_measurement
  else
    echo "Q05 performance result is neither passed nor documented blocked" >&2
    exit 1
  fi
  write_case_receipt performance "$performance_state" "q05_reference_scale_harness"
}

run_uninstall() {
  (
    cd "$repo_root"
    run_cargo_test \
      uninstall \
      v03_u02_ownership_bounds_successor \
      successor_fresh_uninstall_keeps_safe_empty_residue_without_racy_unlink
  )
  write_case_receipt uninstall passed "u02_safe_empty_residue_uninstall"
}

run_case() {
  [ ! -e "$output_root/$1.receipt.json" ] || {
    echo "refusing to overwrite an existing U05 $1 case receipt" >&2
    exit 73
  }
  case "$1" in
    quickstart) run_quickstart ;;
    privacy) run_privacy ;;
    telemetry) run_telemetry ;;
    recovery) run_recovery ;;
    performance) run_performance ;;
    uninstall) run_uninstall ;;
  esac
}

write_summary_receipt() {
  performance_state=$(sed -n 's/.*"state":"\([^"]*\)".*/\1/p' "$output_root/performance.receipt.json")
  [ -n "$performance_state" ] || performance_state=invalid_missing_case_receipt
  printf '%s\n' \
    '{' \
    '  "schema_version":"gtkg.u05-docs-as-tests-receipt/v1",' \
    '  "scope":"local_development_only",' \
    '  "release_state":"not_run",' \
    '  "current_activation":"not_run",' \
    '  "external_runtime":"not_run",' \
    '  "b01":"blocked",' \
    '  "cases":{' \
    '    "quickstart":"passed",' \
    '    "privacy":"passed",' \
    '    "telemetry":"passed",' \
    '    "recovery":"passed",' \
    "    \"performance\":\"$performance_state\", " \
    '    "uninstall":"passed"' \
    '  }' \
    '}' >"$output_root/u05-docs-as-tests-receipt.json"
}

if [ "$case_name" = all ]; then
  for documented_case in quickstart privacy telemetry recovery performance uninstall; do
    run_case "$documented_case"
  done
  write_summary_receipt
else
  run_case "$case_name"
fi
