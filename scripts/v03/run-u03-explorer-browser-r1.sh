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
if ! command -v npx >/dev/null 2>&1 || [ ! -x "$pwcli" ]; then
  echo "locked local Playwright CLI prerequisites are unavailable" >&2
  exit 2
fi

fixture_log=$(mktemp "${TMPDIR:-/tmp}/gtkg-u03-fixture.XXXXXX")
trap 'rm -f "$fixture_log"; "$pwcli" --session "$session" close >/dev/null 2>&1 || true' EXIT
session="gtkg-u03-$$"

(
  cd "$repo_root"
  GTKG_U03_BROWSER_OUTPUT="$output_dir" cargo test --locked -p gtkg-testkit \
    --test v03_u03_explorer_contract emit_u03_real_explorer_browser_fixture \
    -- --ignored --exact --nocapture --test-threads=1
) >"$fixture_log" 2>&1
mv "$fixture_log" "$output_dir/fixture.log"

receipt="$output_dir/browser-fixture-receipt.json"
site_root=$(jq -er '.site_root' "$receipt")
file_url="file://$site_root/index.html"

"$pwcli" --session "$session" open about:blank --config "$config" >"$output_dir/browser-open.log" 2>&1
"$pwcli" --session "$session" run-code 'async (page) => {
  page.__u03Requests = [];
  page.on("request", (request) => page.__u03Requests.push(request.url()));
  await page.addInitScript(() => {
    globalThis.__u03Errors = [];
    globalThis.addEventListener("error", (event) => globalThis.__u03Errors.push(String(event.message)));
    globalThis.addEventListener("securitypolicyviolation", (event) => globalThis.__u03Errors.push("csp:" + event.violatedDirective));
  });
}' >"$output_dir/browser-setup.log" 2>&1
"$pwcli" --session "$session" goto "$file_url" >"$output_dir/browser-goto.log" 2>&1
"$pwcli" --session "$session" network-state-set offline >"$output_dir/browser-offline.log" 2>&1
"$pwcli" --session "$session" snapshot >"$output_dir/browser-snapshot-initial.txt" 2>&1
"$pwcli" --session "$session" run-code 'async (page) => {
  await page.getByRole("searchbox", {name: "Search verified graph"}).fill("auth");
  const record = page.locator("[data-entity-id=node-a]");
  await record.focus();
  await record.press("Enter");
  await page.getByRole("button", {name: "Show neighbors"}).click();
  const neighbors = await page.locator("#view-output").textContent();
  await page.getByRole("button", {name: "Show path"}).click();
  const path = await page.locator("#view-output").textContent();
  await page.getByRole("button", {name: "Show impact"}).click();
  const impact = await page.locator("#view-output").textContent();
  await page.getByRole("button", {name: "Show trace"}).click();
  const trace = await page.locator("#view-output").textContent();
  const result = await page.evaluate(() => ({
    protocol: location.protocol,
    selected: globalThis.__GTKG_U03_EVIDENCE__,
    xss: globalThis.__u03_xss === true || globalThis.__GTKG_U03_XSS__ !== false,
    errors: globalThis.__u03Errors,
    recordCount: document.querySelectorAll("[data-entity-id]").length,
    evidence: document.getElementById("selected-evidence").textContent,
    csp: document.querySelector("meta[http-equiv=Content-Security-Policy]").content,
    scripts: [...document.scripts].map((script) => script.src).filter(Boolean),
    links: [...document.querySelectorAll("link[href]")].map((link) => link.href)
  }));
  result.neighbors = neighbors; result.path = path; result.impact = impact; result.trace = trace;
  result.remote = page.__u03Requests.filter((url) => /^https?:\/\//i.test(url));
  if (result.protocol !== "file:") throw new Error("expected local file protocol");
  if (!result.selected || result.selected.selected_id !== "node-a") throw new Error("keyboard selection did not bind node-a");
  if (result.xss || result.errors.length || result.remote.length || result.scripts.length || result.links.length) throw new Error("offline/XSS/CSP drift: " + JSON.stringify(result));
  if (!result.evidence.includes("evidence:node-a") || !result.neighbors.includes("node-b") || !result.path.includes("edge-a-b") || !result.impact.includes("node-b") || !result.trace.includes("node-a")) throw new Error("real Q04 view data missing: " + JSON.stringify(result));
  return result;
}' --raw >"$output_dir/browser-observed.json" 2>&1
"$pwcli" --session "$session" snapshot >"$output_dir/browser-snapshot-final.txt" 2>&1
"$pwcli" --session "$session" console error >"$output_dir/browser-console-error.log" 2>&1
"$pwcli" --session "$session" requests >"$output_dir/browser-requests.log" 2>&1

jq -e '
  .protocol == "file:" and
  .selected.selected_id == "node-a" and
  .xss == false and
  (.errors | length) == 0 and
  (.remote | length) == 0 and
  (.scripts | length) == 0 and
  (.links | length) == 0 and
  (.evidence | contains("evidence:node-a")) and
  (.neighbors | contains("node-b")) and
  (.path | contains("edge-a-b")) and
  (.impact | contains("node-b")) and
  (.trace | contains("node-a"))
' "$output_dir/browser-observed.json" >/dev/null

jq -n \
  --arg fixture_receipt_sha256 "sha256:$(shasum -a 256 "$receipt" | awk '{print $1}')" \
  --arg observed_sha256 "sha256:$(shasum -a 256 "$output_dir/browser-observed.json" | awk '{print $1}')" \
  --arg browser_snapshot_sha256 "sha256:$(shasum -a 256 "$output_dir/browser-snapshot-final.txt" | awk '{print $1}')" \
  '{schema_version:"gtkg.u03-browser-evidence/v1",state:"passed",browser_execution:"local_file_offline",fixture_receipt_sha256:$fixture_receipt_sha256,observed_sha256:$observed_sha256,browser_snapshot_sha256:$browser_snapshot_sha256,network_calls:0,target_execution_count:0,cdn_calls:0,xss_executed:false}' \
  >"$output_dir/browser-evidence.json"
cat "$output_dir/browser-evidence.json"
