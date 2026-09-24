#!/usr/bin/env bash
# H05: real official @a2ui/lit renderer consumes the exact GTKG stream.jsonl.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
HARNESS_ROOT="$REPO_ROOT/crates/gtkg-testkit/browser/h05-a2ui-lit"
OUTPUT_ROOT="${GTKG_H05_BROWSER_OUTPUT:-$(mktemp -d "${TMPDIR:-/tmp}/gtkg-h05-browser.XXXXXX")}" 
mkdir -p "$OUTPUT_ROOT"
if [[ -n "$(find "$OUTPUT_ROOT" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
  echo "GTKG_H05_BROWSER_OUTPUT must be a new empty directory" >&2
  exit 2
fi

EMITTER_ROOT="$OUTPUT_ROOT/emitter"
SITE_ROOT="$OUTPUT_ROOT/site"
mkdir -p "$EMITTER_ROOT"

(
  cd "$REPO_ROOT"
  GTKG_H05_CURRENT_OUTPUT="$EMITTER_ROOT" cargo test -p gtkg-testkit \
    --test g04_browser_fixture_emitter emit_h05_current_source_fixture \
    -- --ignored --exact --nocapture --test-threads=1
)

FIXTURE_RECEIPT="$EMITTER_ROOT/h05-current-source-receipt.json"
WORKSPACE="$(jq -er '.workspace' "$FIXTURE_RECEIPT")"
PROJECTION="$(jq -er '.projection_path' "$FIXTURE_RECEIPT")"
GENERATION_RECEIPT="$(jq -er '.generation_receipt_path' "$FIXTURE_RECEIPT")"
STREAM="$(jq -er '.stream_path' "$FIXTURE_RECEIPT")"

npm --prefix "$HARNESS_ROOT" run build -- --outDir "$SITE_ROOT" --emptyOutDir
node "$HARNESS_ROOT/prepare-stream.mjs" "$STREAM" "$SITE_ROOT/stream.js"

EVIDENCE_DIR="$WORKSPACE/.gtkg/a2ui/browser-evidence"
ARTIFACT_DIR="$EVIDENCE_DIR/h05-artifacts"
EVIDENCE="$EVIDENCE_DIR/smoke-h05-v2.json"
mkdir -p "$ARTIFACT_DIR"
node "$HARNESS_ROOT/run-browser.mjs" \
  "$SITE_ROOT" \
  "$PROJECTION" \
  "$GENERATION_RECEIPT" \
  "$EVIDENCE" \
  "$ARTIFACT_DIR" \
  "$HARNESS_ROOT/package-lock.json" \
  "$REPO_ROOT/crates/gtkg-core/vendor/a2ui/v0_9_1/client_to_server.json" \
  "$REPO_ROOT/crates/gtkg-core/vendor/a2ui/v0_9_1/official_lit_renderer_lock.json" \
  "$HARNESS_ROOT"

(
  cd "$REPO_ROOT"
  GTKG_H05_BROWSER_OUTPUT="$OUTPUT_ROOT" cargo test -p gtkg-testkit \
    --test h05_official_renderer_contract validate_h05_renderer_replicable_with_browser_evidence \
    -- --ignored --exact --nocapture --test-threads=1
)

jq -e '.validation.observed_evidence_state == "renderer_replicable" and .verified_replica == "not_run_fail_closed"' \
  "$OUTPUT_ROOT/h05-validation.json" >/dev/null
echo "H05_OUTPUT=$OUTPUT_ROOT"
