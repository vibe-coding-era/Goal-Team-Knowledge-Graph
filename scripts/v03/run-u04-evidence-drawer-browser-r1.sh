#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "usage: $0 OUTPUT_DIRECTORY" >&2
  exit 64
fi

output_dir=$1
repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
if [[ "$output_dir" != /* ]]; then
  output_dir="$repo_root/$output_dir"
fi
if [ -e "$output_dir" ]; then
  echo "refusing to overwrite existing output directory: $output_dir" >&2
  exit 73
fi

pwcli="$repo_root/crates/gtkg-testkit/browser/playwright_cli_locked.sh"
config="$repo_root/crates/gtkg-testkit/browser/d05_playwright_cli.config.json"
u04_network_policy="$repo_root/scripts/v03/u04-browser-network-deny-r5.sb"
if ! command -v npx >/dev/null 2>&1 || [ ! -x "$pwcli" ] || [ ! -f "$u04_network_policy" ]; then
  echo "locked local Playwright CLI or offline-cache prerequisites are unavailable" >&2
  exit 2
fi
u04_runner_sha256="sha256:$(shasum -a 256 "$pwcli" | awk '{print $1}')"
u04_pwcli_invocation_count=0
run_pwcli() {
  u04_pwcli_invocation_count=$((u04_pwcli_invocation_count + 1))
  NPM_CONFIG_OFFLINE=true npm_config_offline=true "$pwcli" "$@"
}

mkdir -m 700 "$output_dir"
fixture_log=$(mktemp "${TMPDIR:-/tmp}/gtkg-u04-r1-fixture.XXXXXX")
session="gtkg-u04-r1-$$"
trap 'rm -f "$fixture_log"; run_pwcli --session "$session" close >/dev/null 2>&1 || true' EXIT

(
  cd "$repo_root"
  GTKG_U04_BROWSER_OUTPUT_PARENT="$output_dir" cargo test --locked -p gtkg-testkit \
    --test v03_u04_evidence_drawer emit_u04_actual_q04_browser_fixture \
    -- --ignored --exact --nocapture --test-threads=1
) >"$fixture_log" 2>&1
mv "$fixture_log" "$output_dir/fixture.log"

receipt="$output_dir/browser-fixture-receipt.json"
site_root=$(jq -er '.site_root' "$receipt")
file_url="file://$site_root/index.html"

jq -s -e '
  length == 3 and
  .[0].createSurface.catalogId == "https://a2ui.org/specification/v0_9/catalogs/basic/catalog.json" and
  .[2].updateDataModel.value as $data |
  (["records","source_evidence","relations","claim_states","unknown","conflicts","current","replay","provenance"] | all(.[]; $data[.] != null)) and
  (["source_evidence_json","relations_json","claim_states_json","unknown_json","conflicts_json"] | all(.[]; ($data[.] | type) == "string" and ($data[.] | length) > 0))
' "$site_root/a2ui/stream.jsonl" >"$output_dir/a2ui-model-observed.json"

run_pwcli --session "$session" open about:blank --config "$config" >"$output_dir/browser-open.log" 2>&1
run_pwcli --session "$session" run-code 'async (page) => {
  page.__u04Requests = [];
  page.on("request", (request) => page.__u04Requests.push(request.url()));
  await page.addInitScript(() => {
    globalThis.__u04Errors = [];
    globalThis.addEventListener("error", (event) => globalThis.__u04Errors.push(String(event.message)));
    globalThis.addEventListener("securitypolicyviolation", (event) => globalThis.__u04Errors.push("csp:" + event.violatedDirective));
  });
}' >"$output_dir/browser-setup.log" 2>&1
run_pwcli --session "$session" network-state-set offline >"$output_dir/browser-offline.log" 2>&1
run_pwcli --session "$session" goto "$file_url" >"$output_dir/browser-goto.log" 2>&1
run_pwcli --session "$session" snapshot >"$output_dir/browser-snapshot-initial.txt" 2>&1
test -s "$output_dir/browser-snapshot-initial.txt"

run_pwcli --session "$session" run-code 'async (page) => {
  const injectedLabel = "Current <img src=x onerror=globalThis.__u04_xss=true> origin";
  const record = page.getByRole("button", {name: injectedLabel, exact: true});
  if (await record.count() !== 1 || !await record.isVisible()) throw new Error("injected Q04 label is not a visible native button");
  await record.click();
  const current = page.getByRole("button", {name: "Current", exact: true});
  const replay = page.getByRole("button", {name: "Replay", exact: true});
  await replay.click();
  const replayState = await page.locator("#drawer-state").textContent();
  const replayPressed = await replay.getAttribute("aria-pressed");
  await current.click();
  const currentState = await page.locator("#drawer-state").textContent();
  const currentPressed = await current.getAttribute("aria-pressed");
  const remote = page.__u04Requests.filter((url) => /^https?:\/\//i.test(url));
  const result = await page.evaluate(() => ({
    protocol: location.protocol,
    ui: globalThis.__GTKG_U04__,
    xss: globalThis.__u04_xss === true || globalThis.__GTKG_U04_XSS__ !== false,
    errors: globalThis.__u04Errors,
    csp: document.querySelector("meta[http-equiv=Content-Security-Policy]").content,
    scripts: [...document.scripts].map((script) => script.src).filter(Boolean),
    links: [...document.querySelectorAll("link[href]")].map((link) => link.href),
    recordCount: document.querySelectorAll("button[data-record-id]").length,
    evidence: document.getElementById("drawer-evidence").textContent,
    facts: document.getElementById("drawer-facts").textContent,
    level: document.getElementById("evidence-level").textContent
  }));
  result.remote = remote;
  result.replay = {state: replayState, pressed: replayPressed};
  result.current = {state: currentState, pressed: currentPressed};
  if (result.protocol !== "file:") throw new Error("expected local file protocol");
  if (result.xss || result.errors.length || result.remote.length || result.scripts.length || result.links.length) throw new Error("offline/XSS/CSP drift: " + JSON.stringify(result));
  if (result.recordCount < 1 || !result.evidence.includes("evidence:node-origin") || !result.facts.includes("resolved") || !result.facts.includes("ambiguous") || !result.facts.includes("unsupported") || !result.facts.includes("accepted_grounded") || !result.facts.includes("abstention") || !result.facts.includes("no_answer") || !result.level.includes("fixture_only_unattested")) throw new Error("actual Q04 state/evidence missing: " + JSON.stringify(result));
  if (!result.replay.state.includes("replay_read_only") || result.replay.pressed !== "true" || !result.current.state.includes("current_discovery_only") || result.current.pressed !== "true" || result.ui.mode !== "current") throw new Error("Current/Replay separation drift: " + JSON.stringify(result));
  return result;
}' --raw >"$output_dir/browser-observed.json" 2>&1
run_pwcli --session "$session" snapshot >"$output_dir/browser-snapshot-final.txt" 2>&1
test -s "$output_dir/browser-snapshot-final.txt"
run_pwcli --session "$session" console error >"$output_dir/browser-console-error.log" 2>&1
run_pwcli --session "$session" requests >"$output_dir/browser-requests.log" 2>&1

fixture_receipt_sha256="sha256:$(shasum -a 256 "$receipt" | awk '{print $1}')"
observed_sha256="sha256:$(shasum -a 256 "$output_dir/browser-observed.json" | awk '{print $1}')"
snapshot_sha256="sha256:$(shasum -a 256 "$output_dir/browser-snapshot-final.txt" | awk '{print $1}')"
a2ui_model_sha256="sha256:$(shasum -a 256 "$output_dir/a2ui-model-observed.json" | awk '{print $1}')"
jq -n \
  --arg runner_sha256 "$u04_runner_sha256" \
  --argjson invocation_count "$u04_pwcli_invocation_count" \
  '{schema_version:"gtkg.u04-browser-process-policy/v2",state:"partial",mechanism:"locked npx offline cache",runner_sha256:$runner_sha256,npm_config_offline:true,invocation_count:$invocation_count,os_process_network_enforcement:"not_enforced",page_remote_claim:"browser-page-observed-only",sandbox_attempts:{state:"failed_incompatible",artifacts:["u04-browser-green-r10/browser-open.log","u04-browser-green-r11/browser-open.log","u04-browser-green-r12/browser-open.log","u04-browser-green-r13/browser-open.log"],reason:"sandbox-exec network denial prevented Chromium from starting its required local session"},claim_boundary:"NPM package resolution is cache-only and fails closed when unavailable. Browser page requests are observed separately. This receipt does not claim that the Chromium process has OS-level remote-egress denial."}' \
  >"$output_dir/process-policy.json"
process_policy_sha256="sha256:$(shasum -a 256 "$output_dir/process-policy.json" | awk '{print $1}')"

jq -e '
  .protocol == "file:" and
  .xss == false and
  (.errors | length) == 0 and
  (.remote | length) == 0 and
  (.scripts | length) == 0 and
  (.links | length) == 0 and
  .replay.pressed == "true" and
  .current.pressed == "true" and
  (.replay.state | contains("replay_read_only")) and
  (.current.state | contains("current_discovery_only")) and
  (.evidence | contains("evidence:node-origin")) and
  (.facts | contains("resolved")) and
  (.facts | contains("ambiguous")) and
  (.facts | contains("unsupported")) and
  (.facts | contains("accepted_grounded")) and
  (.facts | contains("abstention")) and
  (.facts | contains("no_answer")) and
  (.level | contains("fixture_only_unattested"))
' "$output_dir/browser-observed.json" >/dev/null

jq -n \
  --arg fixture_receipt_sha256 "$fixture_receipt_sha256" \
  --arg observed_sha256 "$observed_sha256" \
  --arg snapshot_sha256 "$snapshot_sha256" \
  --arg a2ui_model_sha256 "$a2ui_model_sha256" \
  --arg process_policy_sha256 "$process_policy_sha256" \
  '{schema_version:"gtkg.u04-browser-evidence/v4",state:"passed",browser_execution:"local_file_offline",fixture_receipt_sha256:$fixture_receipt_sha256,observed_sha256:$observed_sha256,browser_snapshot_sha256:$snapshot_sha256,a2ui_model_sha256:$a2ui_model_sha256,process_policy_sha256:$process_policy_sha256,current_replay_separation:true,actual_q04_evidence:true,official_a2ui_catalog_stream:true,package_resolution_network:"npm_offline_cache",os_process_network_enforcement:"not_verified",page_remote_observation:"browser-page-observed-only",page_network_calls:0,cdn_calls:0,database_reads:0,target_execution_count:0,xss_executed:false}' \
  >"$output_dir/browser-evidence.json"
cat "$output_dir/browser-evidence.json"
