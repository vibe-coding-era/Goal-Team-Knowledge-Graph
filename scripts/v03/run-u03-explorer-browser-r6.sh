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
fixture_log=$(mktemp "${TMPDIR:-/tmp}/gtkg-u03-r6-fixture.XXXXXX")
session="gtkg-u03-r6-$$"
trap 'rm -f "$fixture_log"; "$pwcli" --session "$session" close >/dev/null 2>&1 || true' EXIT

(
  cd "$repo_root"
  GTKG_U03_BROWSER_OUTPUT_PARENT="$output_dir" cargo test --locked -p gtkg-testkit \
    --test v03_u03_explorer_successor_r3 emit_u03_capability_bound_browser_fixture_r3 \
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
test -s "$output_dir/browser-snapshot-initial.txt"

"$pwcli" --session "$session" run-code 'async (page) => {
  const label = "Auth <img src=x onerror=window.__u03_xss=true>";
  const search = page.getByRole("searchbox", {name: "Search verified graph"});
  await search.fill("auth");
  await search.press("Tab");
  const list = page.getByRole("list", {name: "Verified graph results"});
  const record = page.getByRole("button", {name: label, exact: true});
  if (await record.count() !== 1 || !await record.isVisible()) throw new Error("record is not a visible native button");
  const before = await record.evaluate((element) => {
    const style = getComputedStyle(element);
    return {
      focused: document.activeElement === element,
      focusVisible: element.matches(":focus-visible"),
      tabIndex: element.tabIndex,
      role: element.getAttribute("role"),
      ariaPressed: element.getAttribute("aria-pressed"),
      buttonTag: element.tagName,
      listTag: element.closest("ul")?.tagName,
      parentTag: element.parentElement?.tagName,
      parentRole: element.parentElement?.getAttribute("role"),
      outlineStyle: style.outlineStyle,
      outlineWidth: style.outlineWidth
    };
  });
  const listItemCount = await list.getByRole("listitem").count();
  await page.keyboard.press("Enter");
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
  result.a11y = { before, listItemCount };
  result.neighbors = neighbors; result.path = path; result.impact = impact; result.trace = trace;
  result.remote = page.__u03Requests.filter((url) => /^https?:\/\//i.test(url));
  if (result.protocol !== "file:") throw new Error("expected local file protocol");
  if (!result.selected || result.selected.selected_id !== "node-a") throw new Error("keyboard Enter did not bind node-a");
  if (result.xss || result.errors.length || result.remote.length || result.scripts.length || result.links.length) throw new Error("offline/XSS/CSP drift: " + JSON.stringify(result));
  if (!result.evidence.includes("evidence:node-a") || !result.neighbors.includes("node-b") || !result.path.includes("edge-a-b") || !result.impact.includes("node-b") || !result.trace.includes("node-a")) throw new Error("real Q04 view data missing: " + JSON.stringify(result));
  if (!before.focused || !before.focusVisible || before.tabIndex !== 0 || before.role !== null || before.ariaPressed !== "true" || before.buttonTag !== "BUTTON" || before.listTag !== "UL" || before.parentTag !== "LI" || before.parentRole !== null || before.outlineStyle === "none" || parseFloat(before.outlineWidth) < 3 || listItemCount !== 1) throw new Error("accessible list/button/focus semantics drift: " + JSON.stringify(result));
  return result;
}' --raw >"$output_dir/browser-observed.json" 2>&1
"$pwcli" --session "$session" snapshot >"$output_dir/browser-snapshot-final.txt" 2>&1
if [ ! -s "$output_dir/browser-snapshot-final.txt" ]; then
  "$pwcli" --session "$session" snapshot >"$output_dir/browser-snapshot-final.txt" 2>&1
fi
test -s "$output_dir/browser-snapshot-final.txt"
"$pwcli" --session "$session" console error >"$output_dir/browser-console-error.log" 2>&1
"$pwcli" --session "$session" requests >"$output_dir/browser-requests.log" 2>&1

fixture_receipt_sha256="sha256:$(shasum -a 256 "$receipt" | awk '{print $1}')"
observed_sha256="sha256:$(shasum -a 256 "$output_dir/browser-observed.json" | awk '{print $1}')"
browser_snapshot_sha256="sha256:$(shasum -a 256 "$output_dir/browser-snapshot-final.txt" | awk '{print $1}')"
jq -n \
  --arg fixture_receipt_sha256 "$fixture_receipt_sha256" \
  --arg observed_sha256 "$observed_sha256" \
  --arg browser_snapshot_sha256 "$browser_snapshot_sha256" \
  '{schema_version:"gtkg.u03-manual-a11y-checklist/v1",state:"manual_confirmation_required",fixture_receipt_sha256:$fixture_receipt_sha256,observed_sha256:$observed_sha256,browser_snapshot_sha256:$browser_snapshot_sha256,checks:[{id:"keyboard",automated_state:"passed",automated_evidence:"Search focus then Tab reached the record and Enter selected node-a.",manual_action:"Using only a physical keyboard, verify Tab order, Shift+Tab return, Enter and Space selection after filtering.",manual_state:"required"},{id:"focus",automated_state:"passed",automated_evidence:"Focused record had :focus-visible with a 3px-or-greater outline.",manual_action:"Visually verify focus remains conspicuous in light/dark system appearance and at browser zoom.",manual_state:"required"},{id:"screen_reader_semantics",automated_state:"passed",automated_evidence:"Native UL > LI > BUTTON structure and accessible button name were observed.",manual_action:"With VoiceOver or another target screen reader, verify announced list count, button name, selected state and evidence update.",manual_state:"required"},{id:"contrast",automated_state:"token_review_required",automated_evidence:"Rendered tokens are #edf2f7 text and #60a5fa focus outline on #10151f background.",manual_action:"Use a contrast checker on the actual rendered browser colors, including focus outline and forced-colors/high-contrast settings.",manual_state:"required"}]}' \
  >"$output_dir/manual-a11y-checklist.json"
manual_a11y_checklist_sha256="sha256:$(shasum -a 256 "$output_dir/manual-a11y-checklist.json" | awk '{print $1}')"

jq -e '
  .protocol == "file:" and
  .selected.selected_id == "node-a" and
  .xss == false and
  (.errors | length) == 0 and
  (.remote | length) == 0 and
  (.scripts | length) == 0 and
  (.links | length) == 0 and
  .a11y.before.focused == true and
  .a11y.before.focusVisible == true and
  .a11y.before.role == null and
  .a11y.before.ariaPressed == "true" and
  .a11y.before.buttonTag == "BUTTON" and
  .a11y.before.listTag == "UL" and
  .a11y.before.parentTag == "LI" and
  .a11y.listItemCount == 1 and
  (.evidence | contains("evidence:node-a")) and
  (.neighbors | contains("node-b")) and
  (.path | contains("edge-a-b")) and
  (.impact | contains("node-b")) and
  (.trace | contains("node-a"))
' "$output_dir/browser-observed.json" >/dev/null

jq -n \
  --arg fixture_receipt_sha256 "$fixture_receipt_sha256" \
  --arg observed_sha256 "$observed_sha256" \
  --arg browser_snapshot_sha256 "$browser_snapshot_sha256" \
  --arg manual_a11y_checklist_sha256 "$manual_a11y_checklist_sha256" \
  '{schema_version:"gtkg.u03-browser-evidence/v3",state:"passed",browser_execution:"local_file_offline",fixture_receipt_sha256:$fixture_receipt_sha256,observed_sha256:$observed_sha256,browser_snapshot_sha256:$browser_snapshot_sha256,manual_a11y_checklist_sha256:$manual_a11y_checklist_sha256,capability_bound_output_root:true,native_button_semantics:true,network_calls:0,target_execution_count:0,cdn_calls:0,xss_executed:false}' \
  >"$output_dir/browser-evidence.json"
cat "$output_dir/browser-evidence.json"
