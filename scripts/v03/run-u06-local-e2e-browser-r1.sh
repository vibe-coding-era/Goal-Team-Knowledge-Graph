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

mkdir -m 700 "$output_dir"
build_log="$output_dir/cargo-build.log"
fixture_log="$output_dir/u06-fixture.log"
build_log_tmp=$(mktemp "${TMPDIR:-/tmp}/gtkg-u06-build.XXXXXX")
fixture_log_tmp=$(mktemp "${TMPDIR:-/tmp}/gtkg-u06-fixture.XXXXXX")
session="gtkg-u06-r1-$$"
trap 'rm -f "$build_log_tmp" "$fixture_log_tmp"; NPM_CONFIG_OFFLINE=true npm_config_offline=true "$pwcli" --session "$session" close >/dev/null 2>&1 || true' EXIT

(
  cd "$repo_root"
  cargo build --locked --offline -p gtkg-app --bin gtkg
) >"$build_log_tmp" 2>&1
binary="$repo_root/target/debug/gtkg"
if [ ! -x "$binary" ]; then
  echo "expected current local binary is absent or not executable: $binary" >&2
  exit 2
fi
binary_sha256="sha256:$(shasum -a 256 "$binary" | awk '{print $1}')"
test_source="$repo_root/crates/gtkg-testkit/tests/v03_u06_local_e2e_successor_r2.rs"
test_source_sha256="sha256:$(shasum -a 256 "$test_source" | awk '{print $1}')"

(
  cd "$repo_root"
  GTKG_U06_BROWSER_OUTPUT_PARENT="$output_dir" \
  U06_SOURCE_BINARY="$binary" \
  U06_SOURCE_BINARY_SHA256="$binary_sha256" \
  U06_TEST_SOURCE_R2_SHA256="$test_source_sha256" \
  TMPDIR="/private/tmp" \
  cargo test --locked -p gtkg-testkit --test v03_u06_local_e2e_successor_r2 \
    emit_u06_r2_browser_fixture -- --ignored --exact --nocapture --test-threads=1
) >"$fixture_log_tmp" 2>&1

mv "$build_log_tmp" "$build_log"
mv "$fixture_log_tmp" "$fixture_log"

fixture="$output_dir/u06-browser-fixture-receipt.json"
site_root=$(jq -er '.site_root' "$fixture")
file_url="file://$site_root/index.html"
jq -e '
  .schema_version == "gtkg.u06-browser-fixture/v2" and
  .install.action == "install" and .install.readback_verified == true and
  .uninstall.action == "uninstall" and .uninstall.readback_verified == true and
  .source_binary_sha256 == .installed_binary_sha256 and
  .query_operation == "graph.search" and
  .target_project_execution_count == 0 and
  .network_calls == 0 and .database_reads == 0
' "$fixture" >"$output_dir/u06-fixture-assertion.json"

NPM_CONFIG_OFFLINE=true npm_config_offline=true "$pwcli" --session "$session" open about:blank --config "$config" >"$output_dir/browser-open.log" 2>&1
NPM_CONFIG_OFFLINE=true npm_config_offline=true "$pwcli" --session "$session" run-code 'async (page) => {
  page.__u06Requests = [];
  page.on("request", (request) => page.__u06Requests.push(request.url()));
  await page.addInitScript(() => {
    globalThis.__u06Errors = [];
    globalThis.addEventListener("error", (event) => globalThis.__u06Errors.push(String(event.message)));
    globalThis.addEventListener("securitypolicyviolation", (event) => globalThis.__u06Errors.push("csp:" + event.violatedDirective));
  });
}' >"$output_dir/browser-setup.log" 2>&1
NPM_CONFIG_OFFLINE=true npm_config_offline=true "$pwcli" --session "$session" network-state-set offline >"$output_dir/browser-offline.log" 2>&1
NPM_CONFIG_OFFLINE=true npm_config_offline=true "$pwcli" --session "$session" goto "$file_url" >"$output_dir/browser-goto.log" 2>&1
NPM_CONFIG_OFFLINE=true npm_config_offline=true "$pwcli" --session "$session" snapshot >"$output_dir/browser-snapshot-initial.txt" 2>&1
test -s "$output_dir/browser-snapshot-initial.txt"

NPM_CONFIG_OFFLINE=true npm_config_offline=true "$pwcli" --session "$session" run-code 'async (page) => {
  const label = "U06 <img src=x onerror=globalThis.__u06_xss=true> installed evidence";
  const search = page.getByRole("searchbox", {name: "Search verified graph"});
  await search.fill("u06");
  const record = page.getByRole("button", {name: label, exact: true});
  if (await record.count() !== 1 || !await record.isVisible()) throw new Error("installed evidence record is not visible native button");
  await record.click();
  await page.getByRole("button", {name: "Show neighbors"}).click();
  const neighbors = await page.locator("#view-output").textContent();
  await page.getByRole("button", {name: "Show path"}).click();
  const path = await page.locator("#view-output").textContent();
  await page.getByRole("button", {name: "Show impact"}).click();
  const impact = await page.locator("#view-output").textContent();
  await page.getByRole("button", {name: "Show trace"}).click();
  const trace = await page.locator("#view-output").textContent();
  const remote = page.__u06Requests.filter((url) => /^https?:\/\//i.test(url));
  const result = await page.evaluate(() => ({
    protocol: location.protocol,
    selected: globalThis.__GTKG_U03_EVIDENCE__,
    xss: globalThis.__u06_xss === true || globalThis.__GTKG_U03_XSS__ !== false,
    errors: globalThis.__u06Errors,
    csp: document.querySelector("meta[http-equiv=Content-Security-Policy]").content,
    scripts: [...document.scripts].map((script) => script.src).filter(Boolean),
    links: [...document.querySelectorAll("link[href]")].map((link) => link.href),
    evidence: document.getElementById("selected-evidence").textContent,
    recordCount: document.querySelectorAll("[data-entity-id]").length
  }));
  result.remote = remote; result.neighbors = neighbors; result.path = path; result.impact = impact; result.trace = trace;
  if (result.protocol !== "file:" || result.xss || result.errors.length || result.remote.length || result.scripts.length || result.links.length) throw new Error("offline/XSS/CSP drift: " + JSON.stringify(result));
  if (!result.selected || result.selected.selected_id !== "node-a" || !result.evidence.includes("evidence:node-a") || !result.neighbors.includes("node-b") || !result.path.includes("edge-a-b") || !result.impact.includes("node-b") || !result.trace.includes("node-a")) throw new Error("installed Q04/Explorer journey is incomplete: " + JSON.stringify(result));
  return result;
}' --raw >"$output_dir/browser-observed.json" 2>&1
NPM_CONFIG_OFFLINE=true npm_config_offline=true "$pwcli" --session "$session" snapshot >"$output_dir/browser-snapshot-final.txt" 2>&1
test -s "$output_dir/browser-snapshot-final.txt"
NPM_CONFIG_OFFLINE=true npm_config_offline=true "$pwcli" --session "$session" console error >"$output_dir/browser-console-error.log" 2>&1
NPM_CONFIG_OFFLINE=true npm_config_offline=true "$pwcli" --session "$session" requests >"$output_dir/browser-requests.log" 2>&1

fixture_sha256="sha256:$(shasum -a 256 "$fixture" | awk '{print $1}')"
observed_sha256="sha256:$(shasum -a 256 "$output_dir/browser-observed.json" | awk '{print $1}')"
snapshot_sha256="sha256:$(shasum -a 256 "$output_dir/browser-snapshot-final.txt" | awk '{print $1}')"
build_sha256="sha256:$(shasum -a 256 "$build_log" | awk '{print $1}')"
fixture_log_sha256="sha256:$(shasum -a 256 "$fixture_log" | awk '{print $1}')"

jq -e '
  .protocol == "file:" and .xss == false and
  (.errors | length) == 0 and (.remote | length) == 0 and
  (.scripts | length) == 0 and (.links | length) == 0 and
  .selected.selected_id == "node-a" and
  (.evidence | contains("evidence:node-a")) and
  (.neighbors | contains("node-b")) and
  (.path | contains("edge-a-b")) and
  (.impact | contains("node-b")) and
  (.trace | contains("node-a"))
' "$output_dir/browser-observed.json" >/dev/null

jq -n \
  --arg fixture_sha256 "$fixture_sha256" \
  --arg observed_sha256 "$observed_sha256" \
  --arg snapshot_sha256 "$snapshot_sha256" \
  --arg build_sha256 "$build_sha256" \
  --arg fixture_log_sha256 "$fixture_log_sha256" \
  '{schema_version:"gtkg.u06-browser-evidence/v1",state:"passed",browser_execution:"local_file_offline",fixture_sha256:$fixture_sha256,observed_sha256:$observed_sha256,browser_snapshot_sha256:$snapshot_sha256,build_log_sha256:$build_sha256,fixture_log_sha256:$fixture_log_sha256,package_resolution_network:"npm_offline_cache",page_network_calls:0,cdn_calls:0,database_reads:0,target_project_execution_count:0,system_install:false,current_activation:false,release:false,xss_executed:false,process_egress_boundary:"browser page request observation only; OS process-wide egress enforcement not verified"}' \
  >"$output_dir/u06-browser-evidence.json"
cat "$output_dir/u06-browser-evidence.json"
