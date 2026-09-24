#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "usage: $0 BROWSER_OUTPUT_DIRECTORY" >&2
  exit 64
fi

output_dir=$1
policy_receipt="$output_dir/process-policy.json"
if [ ! -f "$policy_receipt" ]; then
  echo "missing required U04 process-policy receipt: $policy_receipt" >&2
  exit 2
fi

jq -e '
  .schema_version == "gtkg.u04-browser-process-policy/v2" and
  .state == "partial" and
  .mechanism == "locked npx offline cache" and
  .os_process_network_enforcement == "not_enforced" and
  .page_remote_claim == "browser-page-observed-only" and
  .npm_config_offline == true and
  (.runner_sha256 | startswith("sha256:")) and
  (.invocation_count | tonumber) > 0
' "$policy_receipt" >/dev/null
