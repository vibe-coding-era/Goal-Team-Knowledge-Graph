#!/usr/bin/env bash
# I06: Codex-inspired production Wiki shell, responsive Split Pane, search,
# keyboard, security, screenshots, and deterministic self-replay evidence.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
PWCLI="${PWCLI:-$REPO_ROOT/crates/gtkg-testkit/browser/playwright_cli_locked.sh}"
PWCONFIG="$REPO_ROOT/crates/gtkg-testkit/browser/d05_playwright_cli.config.json"
PIXEL_DIFF="$REPO_ROOT/crates/gtkg-testkit/browser/support/pixel_diff.py"
PWLOCK="$REPO_ROOT/crates/gtkg-testkit/browser/playwright_cli.lock.json"
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$"
OUT_ROOT="${GTKG_I06_OUTPUT:-$REPO_ROOT/output/playwright/i06-codex-wiki/$RUN_ID}"
PUBLISH_ROOT="${GTKG_I06_PUBLISH_ROOT:-$REPO_ROOT/deliverables/codex-wiki-reverse/evidence}"
FIXTURE_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/gtkg-i06-codex-wiki.XXXXXX")"

command -v npx >/dev/null 2>&1 || { echo "npx is required" >&2; exit 2; }
[[ -x "$PWCLI" ]] || { echo "locked Playwright CLI is unavailable" >&2; exit 2; }
[[ -f "$PIXEL_DIFF" ]] || { echo "repo-local pixel diff runner is unavailable" >&2; exit 2; }
ROOT_IDENTITY="$(python3 -B "$PIXEL_DIFF" --prepare-roots \
  --repo-root "$REPO_ROOT" --output-root "$OUT_ROOT" --publish-root "$PUBLISH_ROOT")"

(
  cd "$REPO_ROOT"
  GTKG_D05_BROWSER_OUTPUT="$FIXTURE_ROOT" cargo test -p gtkg-testkit \
    --test d05_browser_fixture_emitter emit_d05_file_wiki_browser_fixture \
    -- --ignored --exact --nocapture --test-threads=1
)
RECEIPT="$FIXTURE_ROOT/browser-fixture-receipt.json"
FILE_URL="$(jq -er '.scale_browser_projection.file_url' "$RECEIPT")"
RESOURCE_COUNT="$(jq -er '.scale_browser_projection.resource_count' "$RECEIPT")"
[[ "$FILE_URL" == file://* && "$RESOURCE_COUNT" == "10001" ]]

run_code() {
  "$PWCLI" --session "$1" run-code --json "$2" | jq -er '
    if .result == null then error((.error // .) | tostring)
    elif (.result | type) == "string" then (.result | fromjson)
    else .result end'
}

secure_writer_raw() {
  python3 -B "$PIXEL_DIFF" --secure-write --repo-root "$REPO_ROOT" \
    --identity-token "$ROOT_IDENTITY" --relative-path "$1" --encoding raw
}

secure_writer_json() {
  python3 -B "$PIXEL_DIFF" --secure-write --repo-root "$REPO_ROOT" \
    --identity-token "$ROOT_IDENTITY" --relative-path "$1" --encoding raw
}

secure_writer_base64() {
  python3 -B "$PIXEL_DIFF" --secure-write --repo-root "$REPO_ROOT" \
    --identity-token "$ROOT_IDENTITY" --relative-path "$1" --encoding base64
}

secure_screenshot() {
  "$PWCLI" --session "$1" run-code --json 'async (page) => (await page.screenshot({type:"png"})).toString("base64")' | jq -jr '
    if .result == null then error((.error // .) | tostring)
    elif (.result | type) == "string" then (.result | fromjson)
    else error("screenshot result is not base64") end' | secure_writer_base64 "$2"
}

install_observers() {
  "$PWCLI" --session "$1" run-code 'async (page) => {
    page.__i06Requests = [];
    page.__i06Errors = [];
    page.on("request", (request) => page.__i06Requests.push(request.url()));
    page.on("console", (message) => { if (message.type() === "error") page.__i06Errors.push(message.text()); });
    page.on("pageerror", (error) => page.__i06Errors.push(String(error)));
    await page.addInitScript(() => {
      globalThis.__I06_CSP__ = [];
      globalThis.addEventListener("securitypolicyviolation", (event) => globalThis.__I06_CSP__.push(event.violatedDirective));
    });
  }' >/dev/null
}

collect_security() {
  run_code "$1" "async (page) => {
    const observed = await page.evaluate(() => ({
      csp_violations: globalThis.__I06_CSP__ || [],
      xss_sentinel: globalThis.__GTKG_XSS_SENTINEL__,
      target_execution_count: globalThis.__GTKG_BROWSER_EVIDENCE__?.target_execution_count
    }));
    const remoteRequests = page.__i06Requests.filter((url) => /^https?:\\/\\//i.test(url));
    const probeUrl = 'https://gtkg.invalid/__offline_probe__';
    return JSON.stringify({
      session: '$2',
      offline: true,
      remote_probe: page.__i06OfflineProbe,
      expected_remote_requests: page.__i06ProbeRequests.filter((url) => url === probeUrl),
      unexpected_remote_requests: page.__i06ProbeRequests.filter((url) => url !== probeUrl),
      remote_requests: remoteRequests,
      console_errors: page.__i06Errors,
      csp_violations: observed.csp_violations,
      target_execution_count: observed.target_execution_count,
      xss_sentinel: observed.xss_sentinel
    });
  }"
}

run_offline_probe() {
  run_code "$1" 'async (page) => {
    const url = "https://gtkg.invalid/__offline_probe__";
    const observed = await page.evaluate(async (probeUrl) => {
      try {
        await fetch(probeUrl, {cache:"no-store"});
        return {url:probeUrl,failed:false,error:""};
      } catch (error) {
        return {url:probeUrl,failed:true,error:String(error)};
      }
    }, url);
    observed.console_errors_at_probe = [...page.__i06Errors];
    observed.csp_violations_at_probe = await page.evaluate(() => globalThis.__I06_CSP__ || []);
    page.__i06OfflineProbe = observed;
    page.__i06ProbeRequests = page.__i06Requests.filter((requestUrl) => /^https?:\/\//i.test(requestUrl));
    page.__i06Requests = [];
    page.__i06Errors = [];
    return JSON.stringify(observed);
  }' >/dev/null
}

SESSION_A="gtkg-i06-a-$$"
SESSION_B="gtkg-i06-b-$$"
trap '"$PWCLI" --session "$SESSION_A" close >/dev/null 2>&1 || true; "$PWCLI" --session "$SESSION_B" close >/dev/null 2>&1 || true' EXIT

"$PWCLI" --session "$SESSION_A" open about:blank --config "$PWCONFIG"
install_observers "$SESSION_A"
"$PWCLI" --session "$SESSION_A" network-state-set offline
run_offline_probe "$SESSION_A"
"$PWCLI" --session "$SESSION_A" resize 1440 900
"$PWCLI" --session "$SESSION_A" goto "$FILE_URL"
"$PWCLI" --session "$SESSION_A" snapshot

DESKTOP_INITIAL="$(run_code "$SESSION_A" 'async (page) => {
  const metrics = await page.evaluate(() => {
    const box = (selector) => {
      const rect = document.querySelector(selector).getBoundingClientRect();
      return {x: rect.x, y: rect.y, width: rect.width, height: rect.height};
    };
    return {
      viewport: {width: innerWidth, height: innerHeight},
      titlebar: box("[data-region=titlebar]"),
      sidebar: box("[data-region=left-index]"),
      content: box("[data-region=right-content]"),
      context: box("[data-region=context-panel]"),
      statusbar: box("[data-region=statusbar]"),
      horizontal_overflow: document.documentElement.scrollWidth > innerWidth || document.body.scrollWidth > innerWidth,
      selected_title: document.querySelector("#selected-title").textContent,
      selected_content: document.querySelector("#selected-content").textContent,
      search_name: document.querySelector("#knowledge-search").getAttribute("aria-label"),
      separators: [...document.querySelectorAll("[role=separator]")].map((node) => ({orientation:node.getAttribute("aria-orientation"), now:Number(node.getAttribute("aria-valuenow"))})),
      evidence: globalThis.__GTKG_BROWSER_EVIDENCE__,
      csp: globalThis.__I06_CSP__,
      xss: globalThis.__GTKG_XSS_SENTINEL__
    };
  });
  metrics.remote_requests = page.__i06Requests.filter((url) => /^https?:\/\//i.test(url));
  metrics.console_errors = page.__i06Errors;
  if (Math.abs(metrics.titlebar.height - 44) > 1 || Math.abs(metrics.statusbar.height - 28) > 1) throw new Error("desktop bar geometry drift: " + JSON.stringify(metrics));
  if (Math.abs(metrics.sidebar.width - 268) > 2 || Math.abs(metrics.context.width - 320) > 2 || metrics.content.width < 700) throw new Error("desktop pane geometry drift: " + JSON.stringify(metrics));
  if (metrics.horizontal_overflow || metrics.search_name !== "Search knowledge" || metrics.separators.length !== 2) throw new Error("desktop accessibility/overflow drift: " + JSON.stringify(metrics));
  if (!metrics.selected_content.startsWith("# Browser selected") || metrics.evidence.target_execution_count !== 0 || metrics.evidence.layout !== "codex_workspace") throw new Error("content decode/evidence drift: " + JSON.stringify(metrics));
  if (metrics.remote_requests.length || metrics.console_errors.length || metrics.csp.length || metrics.xss !== false) throw new Error("desktop security drift: " + JSON.stringify(metrics));
  return JSON.stringify(metrics);
}')"
secure_screenshot "$SESSION_A" "generated/desktop-initial.png"

DESKTOP_SEARCH="$(run_code "$SESSION_A" 'async (page) => {
  await page.getByRole("button", {name:"Load last shard"}).click();
  await page.waitForFunction(() => globalThis.__GTKG_LAST_SHARD__?.id === "00039");
  await page.getByRole("searchbox", {name:"Search knowledge"}).fill("Knowledge item 10000");
  const buttons = page.locator("#selected-nav .knowledge-item");
  await buttons.first().waitFor();
  const count = await buttons.count();
  const result = await buttons.first().textContent();
  if (count !== 1 || !result.includes("Knowledge item 10000")) throw new Error("search result drift: " + JSON.stringify({count,result}));
  const contentRequests = page.__i06Requests.filter((url) => url.includes("/content/"));
  if (contentRequests.length !== 0) throw new Error("search preloaded content shard: " + JSON.stringify(contentRequests));
  return JSON.stringify({query:"Knowledge item 10000",result_count:count,content_shards_loaded:contentRequests.length});
}')"
secure_screenshot "$SESSION_A" "generated/desktop-search.png"

DESKTOP_SELECTED="$(run_code "$SESSION_A" 'async (page) => {
  await page.locator("[data-resource-id=browser-resource-10000]").click();
  await page.waitForFunction(() => globalThis.__GTKG_BROWSER_EVIDENCE__.selected_id === "browser-resource-10000");
  const selected = await page.evaluate(() => ({
    id: globalThis.__GTKG_BROWSER_EVIDENCE__.selected_id,
    title: document.querySelector("#selected-title").textContent,
    content: document.querySelector("#selected-content").textContent,
    current: document.querySelector("[aria-current=page]")?.dataset.resourceId,
    context: document.querySelector("#context-id").textContent
  }));
  if (selected.id !== "browser-resource-10000" || selected.title !== "Knowledge item 10000" || selected.content !== "Production renderer boundary content" || selected.current !== selected.id || selected.context !== selected.id) throw new Error("selection drift: " + JSON.stringify(selected));
  return JSON.stringify(selected);
}')"
secure_screenshot "$SESSION_A" "generated/desktop-selected.png"

DESKTOP_COLLAPSE="$(run_code "$SESSION_A" 'async (page) => {
  const contentBefore = await page.locator("[data-region=right-content]").evaluate((node) => node.getBoundingClientRect().width);
  await page.locator("#toggle-left").click();
  const collapsed = await page.locator("#wiki-shell").getAttribute("data-left-collapsed");
  const contentAfter = await page.locator("[data-region=right-content]").evaluate((node) => node.getBoundingClientRect().width);
  const expanded = await page.locator("#toggle-left").getAttribute("aria-expanded");
  const sidebar = await page.locator("[data-region=left-index]").evaluate((node) => ({inert:node.inert,hidden:node.getAttribute("aria-hidden"),width:node.getBoundingClientRect().width}));
  if (collapsed !== "true" || expanded !== "false" || contentAfter <= contentBefore + 250 || !sidebar.inert || sidebar.hidden !== "true" || sidebar.width > 1.5) throw new Error("collapse drift: " + JSON.stringify({collapsed,expanded,contentBefore,contentAfter,sidebar}));
  return JSON.stringify({content_before:contentBefore,content_after:contentAfter,content_gain:contentAfter-contentBefore,sidebar});
}')"
secure_screenshot "$SESSION_A" "generated/desktop-collapsed.png"
DESKTOP_RESIZE="$(run_code "$SESSION_A" 'async (page) => {
  await page.locator("#toggle-left").click();
  const splitter = page.locator("#left-splitter");
  const before = Number(await splitter.getAttribute("aria-valuenow"));
  await splitter.focus();
  await page.keyboard.press("ArrowRight");
  const after = Number(await splitter.getAttribute("aria-valuenow"));
  const outline = await splitter.evaluate((node) => { const style=getComputedStyle(node); return {style:style.outlineStyle,width:style.outlineWidth}; });
  if (after !== before + 12 || outline.style === "none" || Number.parseFloat(outline.width) < 2) throw new Error("keyboard splitter/focus drift: " + JSON.stringify({before,after,outline}));
  return JSON.stringify({splitter_before:before,splitter_after:after,focus_outline:outline});
}')"
secure_screenshot "$SESSION_A" "generated/desktop-resized.png"
SECURITY_A="$(collect_security "$SESSION_A" "A")"
"$PWCLI" --session "$SESSION_A" close

# Independent browser process for deterministic desktop replay and mobile behavior.
"$PWCLI" --session "$SESSION_B" open about:blank --config "$PWCONFIG"
install_observers "$SESSION_B"
"$PWCLI" --session "$SESSION_B" network-state-set offline
run_offline_probe "$SESSION_B"
"$PWCLI" --session "$SESSION_B" resize 1440 900
"$PWCLI" --session "$SESSION_B" goto "$FILE_URL"
secure_screenshot "$SESSION_B" "generated/desktop-initial-replay.png"
"$PWCLI" --session "$SESSION_B" resize 390 844
"$PWCLI" --session "$SESSION_B" goto "$FILE_URL"
"$PWCLI" --session "$SESSION_B" snapshot
secure_screenshot "$SESSION_B" "generated/mobile-initial.png"
MOBILE_OPEN="$(run_code "$SESSION_B" 'async (page) => {
  const initial = await page.evaluate(() => ({
    left_collapsed: document.querySelector("#wiki-shell").dataset.leftCollapsed,
    sidebar_inert: document.querySelector("[data-region=left-index]").inert,
    sidebar_aria_hidden: document.querySelector("[data-region=left-index]").getAttribute("aria-hidden"),
    context_display: getComputedStyle(document.querySelector("[data-region=context-panel]")).display,
    content_width: document.querySelector("[data-region=right-content]").getBoundingClientRect().width,
    overflow: document.documentElement.scrollWidth > innerWidth || document.body.scrollWidth > innerWidth
  }));
  if (initial.left_collapsed !== "true" || !initial.sidebar_inert || initial.sidebar_aria_hidden !== "true" || initial.context_display !== "none" || initial.content_width < 388 || initial.overflow) throw new Error("mobile initial drift: " + JSON.stringify(initial));
  const menu = page.locator("#mobile-menu");
  await menu.click();
  const open = await page.evaluate(() => ({collapsed:document.querySelector("#wiki-shell").dataset.leftCollapsed,scrim_hidden:document.querySelector("#mobile-scrim").hidden,active:document.activeElement?.id,sidebar_inert:document.querySelector("[data-region=left-index]").inert,content_inert:document.querySelector("[data-region=right-content]").inert}));
  if (open.collapsed !== "false" || open.scrim_hidden || open.active !== "knowledge-search" || open.sidebar_inert || !open.content_inert) throw new Error("mobile drawer open drift: " + JSON.stringify(open));
  return JSON.stringify({initial,open});
}')"
secure_screenshot "$SESSION_B" "generated/mobile-drawer-open.png"
MOBILE_CLOSED="$(run_code "$SESSION_B" 'async (page) => {
  await page.keyboard.press("Escape");
  const closed = await page.evaluate(() => ({collapsed:document.querySelector("#wiki-shell").dataset.leftCollapsed,scrim_hidden:document.querySelector("#mobile-scrim").hidden,active:document.activeElement?.id,sidebar_inert:document.querySelector("[data-region=left-index]").inert,content_inert:document.querySelector("[data-region=right-content]").inert}));
  if (closed.collapsed !== "true" || !closed.scrim_hidden || closed.active !== "mobile-menu" || !closed.sidebar_inert || closed.content_inert) throw new Error("mobile drawer close/focus drift: " + JSON.stringify(closed));
  await page.keyboard.press("Tab");
  const tabTarget = await page.evaluate(() => document.activeElement?.id || document.activeElement?.getAttribute("aria-label"));
  if (["knowledge-search", "load-first-shard", "load-last-shard"].includes(tabTarget)) throw new Error("closed drawer leaked into tab order: " + tabTarget);
  closed.next_tab_target = tabTarget;
  return JSON.stringify(closed);
}')"
secure_screenshot "$SESSION_B" "generated/mobile-closed-focus.png"
SECURITY_B="$(collect_security "$SESSION_B" "B")"
"$PWCLI" --session "$SESSION_B" close

python3 "$PIXEL_DIFF" \
  --repo-root "$REPO_ROOT" --output-identity-token "$ROOT_IDENTITY" \
  --baseline "$OUT_ROOT/generated/desktop-initial.png" \
  --candidate "$OUT_ROOT/generated/desktop-initial-replay.png" \
  --diff "$OUT_ROOT/diff/desktop-self-replay.png" \
  --metrics "$OUT_ROOT/diff/desktop-self-replay.metrics.json" \
  --max-diff-ratio 0 --max-mae 0.001 --per-channel-threshold 12

if [[ -f "$PUBLISH_ROOT/source/wiki-before-desktop.png" ]]; then
  python3 "$PIXEL_DIFF" \
    --repo-root "$REPO_ROOT" --output-identity-token "$ROOT_IDENTITY" \
    --baseline "$PUBLISH_ROOT/source/wiki-before-desktop.png" \
    --candidate "$OUT_ROOT/generated/desktop-initial.png" \
    --diff "$OUT_ROOT/diff/before-vs-codex-style.png" \
    --metrics "$OUT_ROOT/diff/before-vs-codex-style.metrics.json" \
    --max-diff-ratio 1 --max-mae 255
fi

PERSISTED_FIXTURE="$OUT_ROOT/e2e/browser-fixture-receipt.json"
python3 -B "$PIXEL_DIFF" --sanitize-json --repo-root "$REPO_ROOT" \
  --ephemeral-root "$FIXTURE_ROOT" --input-json "$RECEIPT" --output-json - | \
  secure_writer_raw "e2e/browser-fixture-receipt.json"

node - "$DESKTOP_INITIAL" "$DESKTOP_SEARCH" "$DESKTOP_SELECTED" "$DESKTOP_COLLAPSE" "$DESKTOP_RESIZE" "$MOBILE_OPEN" "$MOBILE_CLOSED" "$SECURITY_A" "$SECURITY_B" "$PERSISTED_FIXTURE" "$REPO_ROOT" "$REPO_ROOT/crates/gtkg-core/src/a2ui.rs" "$REPO_ROOT/crates/gtkg-testkit/browser/i06_codex_wiki_e2e_contract.sh" "$PIXEL_DIFF" "$PWCLI" "$PWLOCK" "$PWCONFIG" "$OUT_ROOT/diff/desktop-self-replay.metrics.json" <<'NODE' | secure_writer_json "e2e/codex-wiki-e2e.json"
const fs = require('node:fs');
const crypto = require('node:crypto');
const [initial, search, selected, collapse, resize, mobileOpen, mobileClosed, securityA, securityB, fixture, repoRoot, sourcePath, harnessPath, pixelDiffPath, wrapperPath, lockPath, configPath, metricsPath] = process.argv.slice(2);
const sha256 = (path) => `sha256:${crypto.createHash('sha256').update(fs.readFileSync(path)).digest('hex')}`;
const portable = (path) => path.slice(`${repoRoot}/`.length);
const fixtureValue = JSON.parse(fs.readFileSync(fixture, 'utf8'));
const selfReplayMetrics = JSON.parse(fs.readFileSync(metricsPath, 'utf8'));
const securityObservations = [JSON.parse(securityA), JSON.parse(securityB)];
for (const item of securityObservations) {
  item.remote_probe.classification = item.offline === true && item.remote_probe.failed && item.expected_remote_requests.length === 1 && item.remote_probe.console_errors_at_probe.length > 0 && item.remote_probe.console_errors_at_probe.every((error) => error.includes('ERR_INTERNET_DISCONNECTED')) && item.remote_probe.csp_violations_at_probe.length === 0 ? 'offline_transport_failure' : 'invalid_probe_observation';
}
if (securityObservations.some((item) => item.remote_probe.classification !== 'offline_transport_failure' || item.unexpected_remote_requests.length || item.remote_requests.length || item.console_errors.length || item.csp_violations.length || item.target_execution_count !== 0 || item.xss_sentinel !== false || item.offline !== true)) {
  throw new Error(`security observation drift: ${JSON.stringify(securityObservations)}`);
}
const security = {
  observed_sessions: securityObservations.length,
  offline_probe_failures: securityObservations.filter((item) => item.remote_probe.failed).length,
  unexpected_remote_requests: securityObservations.reduce((total, item) => total + item.unexpected_remote_requests.length, 0),
  remote_requests: securityObservations.reduce((total, item) => total + item.remote_requests.length, 0),
  console_errors: securityObservations.reduce((total, item) => total + item.console_errors.length, 0),
  csp_violations: securityObservations.reduce((total, item) => total + item.csp_violations.length, 0),
  target_execution_count: securityObservations.reduce((total, item) => total + item.target_execution_count, 0),
  xss_sentinel: securityObservations.some((item) => item.xss_sentinel !== false)
};
const receipt = {
  schema_version: 'gtkg.codex-wiki-e2e/v1',
  result: 'passed',
  fixture_receipt: 'e2e/browser-fixture-receipt.json',
  fixture_receipt_sha256: sha256(fixture),
  projection_tree_sha256: fixtureValue.scale_browser_projection.tree_sha256,
  wiki_manifest_sha256: fixtureValue.scale_browser_projection.wiki_manifest_sha256,
  source: {path: portable(sourcePath), sha256: sha256(sourcePath)},
  harness: {path: portable(harnessPath), sha256: sha256(harnessPath)},
  pixel_diff: {path: portable(pixelDiffPath), sha256: sha256(pixelDiffPath)},
  playwright: {
    offline: securityObservations.every((item) => item.offline === true),
    wrapper: {path: portable(wrapperPath), sha256: sha256(wrapperPath)},
    lock: {path: portable(lockPath), sha256: sha256(lockPath)},
    config: {path: portable(configPath), sha256: sha256(configPath)}
  },
  self_replay_metrics: {
    path: 'diff/desktop-self-replay.metrics.json',
    sha256: sha256(metricsPath),
    passed: selfReplayMetrics.passed,
    changed_pixels: selfReplayMetrics.changed_pixels,
    pixel_diff_ratio: selfReplayMetrics.pixel_diff_ratio,
    mean_absolute_error: selfReplayMetrics.mean_absolute_error,
    max_channel_delta: selfReplayMetrics.max_channel_delta
  },
  viewports: ['1440x900', '390x844'],
  states: {initial: JSON.parse(initial), search: JSON.parse(search), selected: JSON.parse(selected), panes: {collapse:JSON.parse(collapse),resize:JSON.parse(resize)}, mobile: {...JSON.parse(mobileOpen), closed:JSON.parse(mobileClosed)}},
  security_observations: securityObservations,
  security,
  candidate_self_replay: selfReplayMetrics.passed && selfReplayMetrics.changed_pixels === 0 ? 'passed_thresholded_diff_0_antialias_delta_12' : 'failed',
  codex_reference_comparison: 'not_applicable_reference_blocked',
  full_pixel_equivalence: 'not_claimed'
};
process.stdout.write(`${JSON.stringify(receipt, null, 2)}\n`);
NODE

python3 -B "$PIXEL_DIFF" --publish-evidence --repo-root "$REPO_ROOT" \
  --run-root "$OUT_ROOT" --publish-root "$PUBLISH_ROOT"
echo "I06_CODEX_WIKI_PASS output=$OUT_ROOT evidence=$PUBLISH_ROOT"
