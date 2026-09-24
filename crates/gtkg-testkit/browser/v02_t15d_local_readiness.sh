#!/usr/bin/env bash
# T15D r2: bounded local security/browser/scale preparation.
# This is a dry-run harness, not a 1k/10k/10,001 measurement, OS-security
# validation, or AX-SCALE-SEC acceptance gate.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
PLAN="$REPO_ROOT/deliverables/v02-t15d/local-readiness-plan.json"
T14B="$REPO_ROOT/crates/gtkg-testkit/browser/v02_t14b_local_wiki_e2e.sh"
OUTPUT_ROOT="${GTKG_T15D_LOCAL_OUTPUT:-$(mktemp -d "${TMPDIR:-/tmp}/gtkg-t15d-local.XXXXXX")}" 

[[ -f "$PLAN" ]] || { echo "T15D local readiness plan is unavailable" >&2; exit 2; }
[[ -x "$T14B" ]] || { echo "T14B local browser harness is unavailable" >&2; exit 2; }
mkdir -p "$OUTPUT_ROOT"
if [[ -n "$(find "$OUTPUT_ROOT" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
  echo "GTKG_T15D_LOCAL_OUTPUT must be empty" >&2
  exit 2
fi

jq -e '
  .schema_version == "gtkg.t15d-local-readiness-plan/v1" and
  .status == "ready_for_local_dry_run" and
  .measurement_status == "not_run" and
  .axis_disposition == "local_preparation_only" and
  .workload.dry_run_max_runs == 1 and
  .claims.scale_1k == "not_run" and
  .claims.scale_10k == "not_run" and
  .claims.scale_10001 == "not_run" and
  .claims.os_security == "not_run" and
  .claims.browser == "local_loopback_only"
' "$PLAN" >/dev/null

# Exactly one browser smoke run is delegated to the T14B consumer. It has no
# scale denominator and no access to a Provider or external renderer.
T14B_OUTPUT="$OUTPUT_ROOT/t14b" GTKG_T14B_BROWSER_OUTPUT="$OUTPUT_ROOT/t14b" "$T14B"
T14B_EVIDENCE="$OUTPUT_ROOT/t14b/local-browser-evidence.json"
jq -e '
  .browser_execution == "local_loopback_only" and
  .evidence_state == "a2ui_generatable" and
  .renderer_replicable == "not_claimed" and
  .provider_calls == 0 and
  .target_execution_count == 0 and
  .fixture_receipt_verified == true and
  .site_replacement_rejected == true and
  (.local_page_reads >= 1)
' "$T14B_EVIDENCE" >/dev/null

HOST_FILE="$OUTPUT_ROOT/host.txt"
{
  uname -srm
  sw_vers 2>/dev/null || true
  sysctl -n hw.memsize 2>/dev/null || true
} > "$HOST_FILE"

PLAN_SHA256="sha256:$(shasum -a 256 "$PLAN" | awk '{print $1}')"
HARNESS_SHA256="sha256:$(shasum -a 256 "$0" | awk '{print $1}')"
T14B_EVIDENCE_SHA256="sha256:$(shasum -a 256 "$T14B_EVIDENCE" | awk '{print $1}')"
HOST_SHA256="sha256:$(shasum -a 256 "$HOST_FILE" | awk '{print $1}')"
jq -n \
  --arg schema "gtkg.t15d-local-readiness-receipt/v1" \
  --arg plan_sha256 "$PLAN_SHA256" \
  --arg harness_sha256 "$HARNESS_SHA256" \
  --arg t14b_evidence_sha256 "$T14B_EVIDENCE_SHA256" \
  --arg host_sha256 "$HOST_SHA256" \
  --arg date_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  '{
    schema_version: $schema,
    executed_at_utc: $date_utc,
    axis_disposition: "local_preparation_only",
    measurement_status: "not_run",
    dry_run: {browser_runs: 1, workload_runs: 0, provider_calls: 0},
    claims: {
      scale_1k: "not_run",
      scale_10k: "not_run",
      scale_10001: "not_run",
      os_security: "not_run",
      browser: "local_loopback_only",
      release: "not_run"
    },
    inputs: {
      plan_sha256: $plan_sha256,
      harness_sha256: $harness_sha256,
      t14b_evidence_sha256: $t14b_evidence_sha256,
      host_sha256: $host_sha256
    }
  }' > "$OUTPUT_ROOT/local-readiness-receipt.json"

jq -e '
  .axis_disposition == "local_preparation_only" and
  .measurement_status == "not_run" and
  .dry_run.browser_runs == 1 and
  .dry_run.workload_runs == 0 and
  .dry_run.provider_calls == 0 and
  .claims.scale_1k == "not_run" and
  .claims.scale_10k == "not_run" and
  .claims.scale_10001 == "not_run" and
  .claims.os_security == "not_run" and
  .claims.browser == "local_loopback_only"
' "$OUTPUT_ROOT/local-readiness-receipt.json" >/dev/null

echo "T15D_LOCAL_DRY_RUN_PASS output=$OUTPUT_ROOT receipt=$OUTPUT_ROOT/local-readiness-receipt.json"
