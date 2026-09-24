#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
  echo "usage: $0 NEW_OUTPUT_DIRECTORY" >&2
  exit 64
fi

output_dir=$1
if [ -e "$output_dir" ]; then
  echo "refusing to overwrite existing output directory: $output_dir" >&2
  exit 73
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)
reference_environment="$repo_root/deliverables/v03-benchmark/reference-environment.json"
test_file="$repo_root/crates/gtkg-testkit/tests/v03_q05_scale_budget_successor.rs"
runner_file="$repo_root/crates/gtkg-testkit/tests/support/v03_q05_scale_runner.rs"
fixture_file="$repo_root/crates/gtkg-testkit/tests/support/v03_q05_fixture.rs"
query_source="$repo_root/crates/gtkg-core/src/v03/query.rs"
query_protocol="$repo_root/crates/gtkg-protocol/src/v03/query.rs"

for command in cargo jq shasum sysctl sw_vers uname awk sed tail; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "required command unavailable: $command" >&2
    exit 69
  }
done
[ -x /usr/bin/time ] || {
  echo "/usr/bin/time is unavailable" >&2
  exit 69
}

mkdir -p "$output_dir"
compile_log="$output_dir/compile.ndjson"
stdout_log="$output_dir/test.stdout.log"
time_log="$output_dir/time.stderr.log"
receipt="$output_dir/receipt.json"

cd "$repo_root"
cargo test -p gtkg-testkit --test v03_q05_scale_budget_successor --no-run \
  --message-format=json-render-diagnostics >"$compile_log"
test_binary=$(jq -r '
  select(.reason == "compiler-artifact")
  | select(.target.name == "v03_q05_scale_budget_successor")
  | .executable // empty
' "$compile_log" | tail -n 1)
[ -n "$test_binary" ] && [ -x "$test_binary" ] || {
  echo "compiled Q05 successor test binary was not found" >&2
  exit 70
}

set +e
/usr/bin/time -l "$test_binary" --nocapture --test-threads=1 \
  >"$stdout_log" 2>"$time_log"
test_exit=$?
set -e

metrics_json=$(sed -n 's/.*Q05_SUCCESSOR_METRICS_JSON=//p' "$stdout_log" | tail -n 1)
[ -n "$metrics_json" ] || metrics_json=null
max_rss_bytes=$(awk '/maximum resident set size/{print $1}' "$time_log" | tail -n 1)
block_inputs=$(awk '/block input operations/{print $1}' "$time_log" | tail -n 1)
block_outputs=$(awk '/block output operations/{print $1}' "$time_log" | tail -n 1)
[ -n "$max_rss_bytes" ] || max_rss_bytes=null
[ -n "$block_inputs" ] || block_inputs=null
[ -n "$block_outputs" ] || block_outputs=null

hardware_model=$(sysctl -n hw.model)
architecture=$(uname -m)
os_version=$(sw_vers -productVersion)
reference_model=$(jq -r '.reference_host.hardware_model' "$reference_environment")
reference_arch=$(jq -r '.reference_host.architecture' "$reference_environment")
reference_os=$(jq -r '.reference_host.os_version' "$reference_environment")
host_binding_state=matched
if [ "MacBook Air ($hardware_model)" != "$reference_model" ] \
  || [ "$architecture" != "$reference_arch" ] \
  || [ "$os_version" != "$reference_os" ]; then
  host_binding_state=blocked_identity_mismatch
fi

peak_rss_budget=$(jq -r '.performance_budgets.peak_rss_bytes' "$reference_environment")
rss_state=passed_current_local_measurement
if [ "$max_rss_bytes" = null ]; then
  rss_state=blocked_measurement_unavailable
elif [ "$max_rss_bytes" -gt "$peak_rss_budget" ]; then
  rss_state=failed_budget_exceeded
fi

metrics_state=passed
if [ "$metrics_json" = null ]; then
  metrics_state=invalid_missing_metrics
elif ! printf '%s\n' "$metrics_json" | jq -e '
  .performance_gate_denominator == [10000, 10001]
  and ([.measurements[] | select(.denominator >= 10000) | .gate_failures | length] | all(. == 0))
  and ([.measurements[] | .persisted_node_count == .denominator] | all)
  and ([.measurements[] | .ordinary_query_full_graph_read_count] | all(. == 0))
' >/dev/null; then
  metrics_state=failed_or_invalid
fi

run_state=passed
if [ "$host_binding_state" != matched ] || [ "$rss_state" = blocked_measurement_unavailable ]; then
  run_state=blocked
elif [ "$test_exit" -ne 0 ] \
  || [ "$rss_state" = failed_budget_exceeded ] \
  || [ "$metrics_state" != passed ]; then
  run_state=failed
fi

jq -n \
  --arg state "$run_state" \
  --arg metrics_state "$metrics_state" \
  --arg host_binding_state "$host_binding_state" \
  --arg hardware_model "$hardware_model" \
  --arg architecture "$architecture" \
  --arg os_version "$os_version" \
  --arg rss_state "$rss_state" \
  --argjson test_exit "$test_exit" \
  --argjson max_rss_bytes "$max_rss_bytes" \
  --argjson peak_rss_budget "$peak_rss_budget" \
  --argjson block_inputs "$block_inputs" \
  --argjson block_outputs "$block_outputs" \
  --argjson metrics "$metrics_json" \
  --arg reference_environment_sha256 "$(shasum -a 256 "$reference_environment" | awk '{print $1}')" \
  --arg test_file_sha256 "$(shasum -a 256 "$test_file" | awk '{print $1}')" \
  --arg runner_file_sha256 "$(shasum -a 256 "$runner_file" | awk '{print $1}')" \
  --arg fixture_file_sha256 "$(shasum -a 256 "$fixture_file" | awk '{print $1}')" \
  --arg query_source_sha256 "$(shasum -a 256 "$query_source" | awk '{print $1}')" \
  --arg query_protocol_sha256 "$(shasum -a 256 "$query_protocol" | awk '{print $1}')" \
  --arg harness_file_sha256 "$(shasum -a 256 "$0" | awk '{print $1}')" \
  --arg compile_log_sha256 "$(shasum -a 256 "$compile_log" | awk '{print $1}')" \
  --arg stdout_log_sha256 "$(shasum -a 256 "$stdout_log" | awk '{print $1}')" \
  --arg time_log_sha256 "$(shasum -a 256 "$time_log" | awk '{print $1}')" \
  '{
    schema_version: "gtkg.q05-reference-scale-run/v3",
    state: $state,
    phase: "development",
    claim_boundary: "current local reference-host query measurement; not B04 competitive, Release, install, or business evidence",
    exact_argv: ["v03_q05_scale_budget_successor", "--nocapture", "--test-threads=1"],
    cwd: "repository_root",
    test_exit_code: $test_exit,
    metrics_state: $metrics_state,
    host: {
      binding_state: $host_binding_state,
      hardware_model: $hardware_model,
      architecture: $architecture,
      os_version: $os_version,
      reference_environment_sha256: $reference_environment_sha256
    },
    rss: {
      state: $rss_state,
      observed_peak_bytes: $max_rss_bytes,
      budget_bytes: $peak_rss_budget,
      measurement_tool: "/usr/bin/time -l exact successor test binary"
    },
    process_io: {
      block_input_operations: $block_inputs,
      block_output_operations: $block_outputs
    },
    bindings: {
      test_file_sha256: $test_file_sha256,
      runner_file_sha256: $runner_file_sha256,
      fixture_file_sha256: $fixture_file_sha256,
      query_source_sha256: $query_source_sha256,
      query_protocol_sha256: $query_protocol_sha256,
      harness_file_sha256: $harness_file_sha256,
      compile_log_sha256: $compile_log_sha256,
      stdout_log_sha256: $stdout_log_sha256,
      time_log_sha256: $time_log_sha256
    },
    metrics: $metrics
  }' >"$receipt"

cat "$receipt"
if [ "$run_state" = passed ]; then
  exit 0
fi
if [ "$test_exit" -ne 0 ]; then
  exit "$test_exit"
fi
exit 1
