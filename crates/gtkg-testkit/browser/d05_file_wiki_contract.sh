#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
# F03/B17: default to the in-repo pinned runner; PWCLI env still overrides.
PWCLI="${PWCLI:-$REPO_ROOT/crates/gtkg-testkit/browser/playwright_cli_locked.sh}"
PWCONFIG="$REPO_ROOT/crates/gtkg-testkit/browser/d05_playwright_cli.config.json"

if ! command -v npx >/dev/null 2>&1; then
  echo "npx is required by the Playwright CLI wrapper" >&2
  exit 2
fi
if [[ ! -x "$PWCLI" ]]; then
  echo "Playwright CLI wrapper is not executable: $PWCLI" >&2
  exit 2
fi

BROWSER_ROOT="${GTKG_D05_BROWSER_OUTPUT:-$(mktemp -d "${TMPDIR:-/tmp}/gtkg-d05-browser.XXXXXX")}"
mkdir -p "$BROWSER_ROOT"
if [[ -n "$(find "$BROWSER_ROOT" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
  echo "GTKG_D05_BROWSER_OUTPUT must be a new empty directory" >&2
  exit 2
fi

(
  cd "$REPO_ROOT"
  GTKG_D05_BROWSER_OUTPUT="$BROWSER_ROOT" cargo test -p gtkg-testkit --test d05_browser_fixture_emitter emit_d05_file_wiki_browser_fixture -- --ignored --exact --nocapture --test-threads=1
)

RECEIPT="$BROWSER_ROOT/browser-fixture-receipt.json"
jq -e '
  .schema_version == "gtkg.d05-browser-fixture-receipt/v2" and
  .real_integration.validated == true and
  .real_integration.executed_target_content == false and
  (.real_integration.canonical_bundle_tree_sha256 | test("^sha256:[0-9a-f]{64}$")) and
  (.real_integration.artifact_manifest_sha256 | test("^sha256:[0-9a-f]{64}$")) and
  (.real_integration.source_lock_sha256 | test("^sha256:[0-9a-f]{64}$")) and
  (.real_integration.generation_ref.sha256 | test("^sha256:[0-9a-f]{64}$")) and
  (.real_integration.validation_ref.sha256 | test("^sha256:[0-9a-f]{64}$")) and
  .real_integration.generation_projection_tree_sha256 ==
    .real_integration.validated_against_projection_tree_sha256 and
  .scale_browser_projection.resource_count == 10001 and
  .scale_browser_projection.offline == true and
  (.scale_browser_projection.tree_sha256 | test("^sha256:[0-9a-f]{64}$")) and
  (.scale_browser_projection.wiki_manifest_sha256 | test("^sha256:[0-9a-f]{64}$")) and
  (.scale_browser_projection.provenance |
    contains("resources are not claimed as canonical bundle content"))
' "$RECEIPT" >/dev/null

FILE_URL="$(jq -er '.scale_browser_projection.file_url' "$RECEIPT")"
RESOURCE_COUNT="$(jq -er '.scale_browser_projection.resource_count' "$RECEIPT")"
EXPECTED_INITIAL_REQUESTS="$(jq -c '.scale_browser_projection.expected_initial_requests | sort' "$RECEIPT")"
EXPECTED_INITIAL_ID="$(jq -c '.scale_browser_projection.expected_initial.id' "$RECEIPT")"
EXPECTED_INITIAL_TITLE="$(jq -c '.scale_browser_projection.expected_initial.title' "$RECEIPT")"
EXPECTED_INITIAL_CONTENT="$(jq -c '.scale_browser_projection.expected_initial.content' "$RECEIPT")"
EXPECTED_LAST_ID="$(jq -c '.scale_browser_projection.expected_last.id' "$RECEIPT")"
EXPECTED_LAST_TITLE="$(jq -c '.scale_browser_projection.expected_last.title' "$RECEIPT")"
EXPECTED_LAST_CONTENT="$(jq -c '.scale_browser_projection.expected_last.content' "$RECEIPT")"
EXPECTED_LAST_SHARD_ID="$(jq -c '.scale_browser_projection.expected_last_shard.id' "$RECEIPT")"
EXPECTED_LAST_SHARD_COUNT="$(jq -er '.scale_browser_projection.expected_last_shard.entry_count' "$RECEIPT")"
if [[ "$FILE_URL" != file://* || "$RESOURCE_COUNT" != "10001" ]]; then
  echo "browser fixture receipt did not bind file:// and 10,001 resources" >&2
  exit 1
fi

SESSION="gtkg-d05-$$"
trap '"$PWCLI" --session "$SESSION" close >/dev/null 2>&1 || true' EXIT

"$PWCLI" --session "$SESSION" open about:blank --config "$PWCONFIG"
"$PWCLI" --session "$SESSION" run-code 'async (page) => {
  page.__gtkgD05Requests = [];
  page.on("request", (request) => { page.__gtkgD05Requests.push(request.url()); });
  await page.addInitScript(() => {
    globalThis.__GTKG_PRELOAD_EVIDENCE__ = {errors: 0, csp_violations: []};
    globalThis.addEventListener("error", () => { globalThis.__GTKG_PRELOAD_EVIDENCE__.errors += 1; });
    globalThis.addEventListener("unhandledrejection", () => { globalThis.__GTKG_PRELOAD_EVIDENCE__.errors += 1; });
    globalThis.addEventListener("securitypolicyviolation", (event) => { globalThis.__GTKG_PRELOAD_EVIDENCE__.csp_violations.push(event.violatedDirective); });
  });
}'
"$PWCLI" --session "$SESSION" network-state-set offline
"$PWCLI" --session "$SESSION" goto "$FILE_URL"
"$PWCLI" --session "$SESSION" snapshot

"$PWCLI" --session "$SESSION" run-code "async (page) => {
  const expectedRequests = $EXPECTED_INITIAL_REQUESTS;
  const expectedInitial = {
    id: $EXPECTED_INITIAL_ID,
    title: $EXPECTED_INITIAL_TITLE,
    content: $EXPECTED_INITIAL_CONTENT
  };
  const result = await page.evaluate(() => ({
    protocol: location.protocol,
    left: Boolean(document.querySelector('[data-region=left-index]')),
    right: Boolean(document.querySelector('[data-region=right-content]')),
    selectedTitle: document.querySelector('#selected-title').textContent,
    selectedContent: document.querySelector('#selected-content').textContent,
    xss: globalThis.__GTKG_XSS_SENTINEL__,
    evidence: globalThis.__GTKG_BROWSER_EVIDENCE__,
    preload: globalThis.__GTKG_PRELOAD_EVIDENCE__,
    visibleStates: [...document.querySelectorAll('[data-ui-state]:not([hidden])')].map((node) => node.dataset.uiState)
  }));
  result.resources = page.__gtkgD05Requests.map((url) => {
    const marker = '/wiki/';
    if (!url.includes(marker)) throw new Error('request escaped Wiki root: ' + url);
    return decodeURIComponent(url.slice(url.indexOf(marker) + marker.length));
  }).sort();
  result.remote = page.__gtkgD05Requests.filter((url) => /^https?:\/\//i.test(url));
  if (result.protocol !== 'file:') throw new Error('expected file:, got ' + result.protocol);
  if (JSON.stringify(result.resources) !== JSON.stringify(expectedRequests)) throw new Error('initial resource exact-set drift: ' + JSON.stringify(result.resources));
  if (result.remote.length !== 0) throw new Error('remote requests observed: ' + JSON.stringify(result.remote));
  if (!result.left || !result.right) throw new Error('left/right Wiki regions missing');
  if (result.xss !== false || result.selectedTitle !== expectedInitial.title || result.selectedContent !== expectedInitial.content) throw new Error('selected content or XSS inertness drifted');
  if (result.evidence.resource_count !== 10001 || result.evidence.selected_id !== expectedInitial.id || result.evidence.target_execution_count !== 0) throw new Error('resource, selection, or target-execution evidence drifted');
  if (result.evidence.console_errors !== 0 || result.preload.errors !== 0 || result.preload.csp_violations.length !== 0) throw new Error('browser errors observed: ' + JSON.stringify(result));
  if (JSON.stringify(result.visibleStates) !== JSON.stringify(['normal'])) throw new Error('initial state drift: ' + JSON.stringify(result.visibleStates));
  return result;
}"

"$PWCLI" --session "$SESSION" run-code "async (page) => {
  const expectedLast = {
    id: $EXPECTED_LAST_ID,
    title: $EXPECTED_LAST_TITLE,
    content: $EXPECTED_LAST_CONTENT
  };
  const expectedShard = {
    id: $EXPECTED_LAST_SHARD_ID,
    count: $EXPECTED_LAST_SHARD_COUNT
  };
  const states = ['normal', 'loading', 'empty', 'error', 'permission', 'disabled'];
  for (const state of states) {
    const observed = await page.evaluate((selected) => {
      globalThis.__GTKG_SHOW_STATE__(selected);
      const buttons = [...document.querySelectorAll('button')];
      return {
        visible: [...document.querySelectorAll('[data-ui-state]:not([hidden])')].map((node) => node.dataset.uiState),
        ariaBusy: document.querySelector('[data-region=right-content]').getAttribute('aria-busy'),
        buttonCount: buttons.length,
        buttonsDisabled: buttons.every((button) => button.disabled),
        content: document.querySelector('#selected-content').textContent
      };
    }, state);
    if (JSON.stringify(observed.visible) !== JSON.stringify([state])) throw new Error('state isolation drift for ' + state + ': ' + JSON.stringify(observed));
    if ((state === 'loading') !== (observed.ariaBusy === 'true')) throw new Error('loading aria-busy drift: ' + JSON.stringify(observed));
    if (observed.buttonCount === 0 || (state === 'disabled') !== observed.buttonsDisabled) throw new Error('real disabled control drift: ' + JSON.stringify(observed));
    if (state === 'permission' && observed.content !== '') throw new Error('permission state leaked selected content: ' + JSON.stringify(observed));
  }
  await page.evaluate(() => globalThis.__GTKG_SHOW_STATE__('normal'));
  await page.getByRole('button', {name: 'Load last shard'}).click();
  await page.waitForFunction(
    (expected) => globalThis.__GTKG_LAST_SHARD__?.id === expected.id && globalThis.__GTKG_LAST_SHARD__?.count === expected.count,
    expectedShard
  );
  await page.getByRole('button', {name: expectedLast.title}).click();
  await page.waitForFunction(
    (expected) => globalThis.__GTKG_BROWSER_EVIDENCE__?.selected_id === expected,
    expectedLast.id
  );
  const result = await page.evaluate(() => ({
    shard: globalThis.__GTKG_LAST_SHARD__,
    contentShard: globalThis.__GTKG_LAST_CONTENT_SHARD__,
    selectedId: globalThis.__GTKG_BROWSER_EVIDENCE__.selected_id,
    selectedTitle: document.querySelector('#selected-title').textContent,
    selectedContent: document.querySelector('#selected-content').textContent,
    evidenceErrors: globalThis.__GTKG_BROWSER_EVIDENCE__.console_errors,
    preloadErrors: globalThis.__GTKG_PRELOAD_EVIDENCE__.errors,
    csp: globalThis.__GTKG_PRELOAD_EVIDENCE__.csp_violations,
    xss: globalThis.__GTKG_XSS_SENTINEL__
  }));
  result.remote = page.__gtkgD05Requests.filter((url) => /^https?:\/\//i.test(url));
  if (result.shard.id !== expectedShard.id || result.shard.count !== expectedShard.count) throw new Error('last catalog shard evidence drifted: ' + JSON.stringify(result));
  if (result.contentShard.id !== expectedShard.id || result.contentShard.count !== expectedShard.count) throw new Error('last content shard evidence drifted: ' + JSON.stringify(result));
  if (result.selectedId !== expectedLast.id || result.selectedTitle !== expectedLast.title || result.selectedContent !== expectedLast.content) throw new Error('last resource selection drifted: ' + JSON.stringify(result));
  if (result.remote.length !== 0 || result.evidenceErrors !== 0 || result.preloadErrors !== 0 || result.csp.length !== 0 || result.xss !== false) throw new Error('offline/error/XSS evidence drifted: ' + JSON.stringify(result));
  return result;
}"

"$PWCLI" --session "$SESSION" snapshot
"$PWCLI" --session "$SESSION" console error
"$PWCLI" --session "$SESSION" requests
echo "D05_BROWSER_PASS receipt=$RECEIPT file_url=$FILE_URL resource_count=$RESOURCE_COUNT"
