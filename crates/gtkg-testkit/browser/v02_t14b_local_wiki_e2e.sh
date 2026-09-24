#!/usr/bin/env bash
# T14B: generate a T12B/T13-bound local projection and exercise it only with
# the locked local Playwright dependency tree. No remote provider is involved.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
HARNESS_ROOT="$REPO_ROOT/crates/gtkg-testkit/browser/h05-a2ui-lit"
OUTPUT_ROOT="${GTKG_T14B_BROWSER_OUTPUT:-$(mktemp -d "${TMPDIR:-/tmp}/gtkg-t14b-browser.XXXXXX")}" 

mkdir -p "$OUTPUT_ROOT"
if [[ -n "$(find "$OUTPUT_ROOT" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
  echo "GTKG_T14B_BROWSER_OUTPUT must be empty" >&2
  exit 2
fi
if [[ ! -d "$HARNESS_ROOT/node_modules/playwright" ]]; then
  echo "locked local Playwright dependency is unavailable" >&2
  exit 2
fi

(
  cd "$REPO_ROOT"
  GTKG_T14B_BROWSER_OUTPUT="$OUTPUT_ROOT" cargo test -p gtkg-testkit \
    --test v02_t14b_local_wiki_a2ui_contract emit_t14b_local_wiki_browser_fixture \
    -- --ignored --exact --nocapture --test-threads=1
)

node "$HARNESS_ROOT/run-t14b-local-wiki.mjs" \
  "$OUTPUT_ROOT/site" \
  "$OUTPUT_ROOT/receipt.json" \
  "$OUTPUT_ROOT/local-browser-evidence.json"

jq -e '
  .browser_execution == "local_loopback_only" and
  .evidence_state == "a2ui_generatable" and
  .renderer_replicable == "not_claimed" and
  .provider_calls == 0 and
  .target_execution_count == 0 and
  .fixture_receipt_verified == true and
  .site_replacement_rejected == true and
  (.local_page_reads >= 1)
' "$OUTPUT_ROOT/local-browser-evidence.json" >/dev/null

echo "T14B_OUTPUT=$OUTPUT_ROOT"
