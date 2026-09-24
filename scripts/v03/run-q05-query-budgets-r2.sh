#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
  echo "usage: $0 NEW_OUTPUT_DIRECTORY" >&2
  exit 64
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
predecessor="$script_dir/run-q05-query-budgets.sh"
output_dir=$1

set +e
"$predecessor" "$output_dir" >"$output_dir.runner-r1.log" 2>&1
test_exit=$?
set -e

stdout_log="$output_dir/test.stdout.log"
receipt_r1="$output_dir/receipt.json"
[ -f "$stdout_log" ] && [ -f "$receipt_r1" ] || {
  cat "$output_dir.runner-r1.log" >&2
  exit 70
}

metrics_json=$(sed -n 's/.*Q05_METRICS_JSON=//p' "$stdout_log" | tail -n 1)
[ -n "$metrics_json" ] || metrics_json=null
mv "$receipt_r1" "$output_dir/receipt-r1.json"

jq \
  --argjson metrics "$metrics_json" \
  --arg harness_sha256 "$(shasum -a 256 "$0" | awk '{print $1}')" \
  --arg predecessor_harness_sha256 "$(shasum -a 256 "$predecessor" | awk '{print $1}')" \
  '.schema_version = "gtkg.q05-query-budget-run/v2"
   | .harness_revision = 2
   | .predecessor_harness_sha256 = $predecessor_harness_sha256
   | .bindings.harness_file_sha256 = $harness_sha256
   | .metrics = $metrics
   | .process_io.query_logical_io = $metrics' \
  "$output_dir/receipt-r1.json" >"$output_dir/receipt.json"

cat "$output_dir/receipt.json"
exit "$test_exit"
