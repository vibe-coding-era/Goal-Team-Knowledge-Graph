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
test_file="$repo_root/crates/gtkg-testkit/tests/v03_q05_query_budget_contract.rs"
fixture_file="$repo_root/crates/gtkg-testkit/tests/support/v03_q05_fixture.rs"

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
cargo test -p gtkg-testkit --test v03_q05_query_budget_contract --no-run \
  --message-format=json-render-diagnostics >"$compile_log"

test_binary=$(jq -r '
  select(.reason == "compiler-artifact")
  | select(.target.name == "v03_q05_query_budget_contract")
  | .executable // empty
' "$compile_log" | tail -n 1)
[ -n "$test_binary" ] && [ -x "$test_binary" ] || {
  echo "compiled Q05 test binary was not found" >&2
  exit 70
}

set +e
/usr/bin/time -l "$test_binary" --nocapture --test-threads=1 \
  >"$stdout_log" 2>"$time_log"
test_exit=$?
set -e

metrics_json=$(sed -n 's/^Q05_METRICS_JSON=//p' "$stdout_log" | tail -n 1)
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
rss_state=measured
if [ "$max_rss_bytes" = null ]; then
  rss_state=blocked_measurement_unavailable
elif [ "$max_rss_bytes" -gt "$peak_rss_budget" ]; then
  rss_state=failed_budget_exceeded
else
  rss_state=passed_current_local_measurement
fi

run_state=passed
if [ "$host_binding_state" != matched ]; then
  run_state=blocked
elif [ "$test_exit" -ne 0 ] || [ "$rss_state" != passed_current_local_measurement ]; then
  run_state=failed
fi

jq -n \
  --arg schema_version "gtkg.q05-query-budget-run/v1" \
  --arg state "$run_state" \
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
  --arg fixture_file_sha256 "$(shasum -a 256 "$fixture_file" | awk '{print $1}')" \
  --arg compile_log_sha256 "$(shasum -a 256 "$compile_log" | awk '{print $1}')" \
  --arg stdout_log_sha256 "$(shasum -a 256 "$stdout_log" | awk '{print $1}')" \
  --arg time_log_sha256 "$(shasum -a 256 "$time_log" | awk '{print $1}')" \
  '{
    schema_version: $schema_version,
    state: $state,
    phase: "development",
    claim_boundary: "current local reference-host measurement; not B04, Release, install, or business evidence",
    exact_argv: ["v03_q05_query_budget_contract", "--nocapture", "--test-threads=1"],
    cwd: "repository_root",
    test_exit_code: $test_exit,
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
      measurement_tool: "/usr/bin/time -l exact test binary"
    },
    process_io: {
      block_input_operations: $block_inputs,
      block_output_operations: $block_outputs,
      query_logical_io: $metrics
    },
    bindings: {
      test_file_sha256: $test_file_sha256,
      fixture_file_sha256: $fixture_file_sha256,
      compile_log_sha256: $compile_log_sha256,
      stdout_log_sha256: $stdout_log_sha256,
      time_log_sha256: $time_log_sha256
    },
    metrics: $metrics
  }' >"$receipt"

cat "$receipt"
exit "$test_exit"
