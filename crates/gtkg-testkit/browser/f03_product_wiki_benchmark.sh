#!/usr/bin/env bash
# F03/B17: product Wiki browser benchmark against the real 10,001-resource
# file:// projection emitted by the frozen D05 fixture emitter.
# Writes a receipt JSON to output/playwright/f03-wiki-benchmark/ (gitignored).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
PWCLI="${PWCLI:-$REPO_ROOT/crates/gtkg-testkit/browser/playwright_cli_locked.sh}"
PWCONFIG="$REPO_ROOT/crates/gtkg-testkit/browser/d05_playwright_cli.config.json"
LOCK_RECORD="$REPO_ROOT/crates/gtkg-testkit/browser/playwright_cli.lock.json"
OUT_DIR="${GTKG_F03_BENCHMARK_OUTPUT:-$REPO_ROOT/output/playwright/f03-wiki-benchmark}"

if ! command -v npx >/dev/null 2>&1; then
  echo "npx is required by the locked Playwright CLI runner" >&2
  exit 2
fi
if [[ ! -x "$PWCLI" ]]; then
  echo "Playwright CLI runner is not executable: $PWCLI" >&2
  exit 2
fi
mkdir -p "$OUT_DIR"

BROWSER_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/gtkg-f03-benchmark.XXXXXX")"
(
  cd "$REPO_ROOT"
  GTKG_D05_BROWSER_OUTPUT="$BROWSER_ROOT" cargo test -p gtkg-testkit --test d05_browser_fixture_emitter emit_d05_file_wiki_browser_fixture -- --ignored --exact --nocapture --test-threads=1
)

FIXTURE_RECEIPT="$BROWSER_ROOT/browser-fixture-receipt.json"
FILE_URL="$(jq -er '.scale_browser_projection.file_url' "$FIXTURE_RECEIPT")"
RESOURCE_COUNT="$(jq -er '.scale_browser_projection.resource_count' "$FIXTURE_RECEIPT")"
PROJECTION_TREE_SHA256="$(jq -er '.scale_browser_projection.tree_sha256' "$FIXTURE_RECEIPT")"
EXPECTED_LAST_TITLE="$(jq -c '.scale_browser_projection.expected_last.title' "$FIXTURE_RECEIPT")"
EXPECTED_LAST_ID="$(jq -c '.scale_browser_projection.expected_last.id' "$FIXTURE_RECEIPT")"
EXPECTED_LAST_CONTENT="$(jq -c '.scale_browser_projection.expected_last.content' "$FIXTURE_RECEIPT")"
if [[ "$FILE_URL" != file://* || "$RESOURCE_COUNT" != "10001" ]]; then
  echo "fixture receipt did not bind file:// and 10,001 resources" >&2
  exit 1
fi

now_ms() { node -e 'process.stdout.write(String(Date.now()))'; }
run_code() {
  "$PWCLI" --session "$SESSION" run-code --json "$1" | jq -er '
    if .result == null then error((.error // .) | tostring)
    elif (.result | type) == "string" then (.result | fromjson)
    else .result end'
}

SESSION="gtkg-f03-$$"
trap '"$PWCLI" --session "$SESSION" close >/dev/null 2>&1 || true' EXIT

"$PWCLI" --session "$SESSION" open about:blank --config "$PWCONFIG"
"$PWCLI" --session "$SESSION" run-code 'async (page) => {
  page.__gtkgF03Requests = [];
  page.on("request", (request) => { page.__gtkgF03Requests.push(request.url()); });
  await page.addInitScript(() => {
    globalThis.__GTKG_PRELOAD_EVIDENCE__ = {errors: 0, csp_violations: []};
    globalThis.addEventListener("error", () => { globalThis.__GTKG_PRELOAD_EVIDENCE__.errors += 1; });
    globalThis.addEventListener("unhandledrejection", () => { globalThis.__GTKG_PRELOAD_EVIDENCE__.errors += 1; });
    globalThis.addEventListener("securitypolicyviolation", (event) => { globalThis.__GTKG_PRELOAD_EVIDENCE__.csp_violations.push(event.violatedDirective); });
  });
}'
"$PWCLI" --session "$SESSION" network-state-set offline
"$PWCLI" --session "$SESSION" resize 1280 800

GOTO_T0="$(now_ms)"
"$PWCLI" --session "$SESSION" goto "$FILE_URL"
GOTO_WALL_MS=$(( $(now_ms) - GOTO_T0 ))

run_code 'async (page) => {
  const navigation = await page.evaluate(() => {
    const entry = performance.getEntriesByType("navigation")[0];
    return {
      duration_ms: entry.duration,
      dom_content_loaded_ms: entry.domContentLoadedEventEnd,
      load_event_ms: entry.loadEventEnd,
      response_end_ms: entry.responseEnd
    };
  });
  const state = await page.evaluate(() => ({
    protocol: location.protocol,
    left: Boolean(document.querySelector("[data-region=left-index]")),
    right: Boolean(document.querySelector("[data-region=right-content]")),
    evidence: globalThis.__GTKG_BROWSER_EVIDENCE__,
    xss: globalThis.__GTKG_XSS_SENTINEL__
  }));
  if (state.protocol !== "file:") throw new Error("expected file:, got " + state.protocol);
  if (!state.left || !state.right) throw new Error("left/right Wiki regions missing");
  if (state.xss !== false) throw new Error("XSS sentinel fired on initial load");
  if (state.evidence.resource_count !== 10001 || state.evidence.target_execution_count !== 0) throw new Error("initial evidence drifted");
  return JSON.stringify({navigation, initial_state_ok: true});
}' > "$OUT_DIR/initial.json"

# Shard-load latency: 16 first-time catalog shard loads sampled across all 40 shards.
run_code 'async (page) => {
  const indices = [0, 2, 5, 8, 11, 14, 17, 20, 23, 26, 29, 32, 35, 37, 38, 39];
  const samples = await page.evaluate(async (shardIndices) => {
    const root = globalThis.__GTKG_ROOT__;
    const results = [];
    for (const index of shardIndices) {
      const shard = root.shards[index];
      const t0 = performance.now();
      await new Promise((resolve, reject) => {
        const script = document.createElement("script");
        script.src = shard.path;
        script.onload = resolve;
        script.onerror = () => reject(new Error("shard load failed: " + shard.path));
        document.head.append(script);
      });
      const elapsed = performance.now() - t0;
      if (globalThis.__GTKG_LAST_SHARD__?.id !== shard.id) throw new Error("shard registration drift: " + shard.id);
      results.push({shard_id: shard.id, entry_count: globalThis.__GTKG_LAST_SHARD__.count, load_ms: elapsed});
    }
    return results;
  }, indices);
  if (samples.length !== indices.length) throw new Error("shard sample count drift");
  return JSON.stringify(samples);
}' > "$OUT_DIR/shards.json"

# Selection latency: entries across left/right panes, including resource #10,000.
run_code "async (page) => {
  const expectedLast = {id: $EXPECTED_LAST_ID, title: $EXPECTED_LAST_TITLE, content: $EXPECTED_LAST_CONTENT};
  const targets = [
    {name: 'Knowledge item 00005', id: 'browser-resource-00005', shard: '00000'},
    {name: 'Knowledge item 00200', id: 'browser-resource-00200', shard: '00000'},
    {name: 'Knowledge item 05300', id: 'browser-resource-05300', shard: '00020'},
    {name: 'Knowledge item 09200', id: 'browser-resource-09200', shard: '00035'},
    {name: 'Knowledge item 09990', id: 'browser-resource-09990', shard: '00039'},
    {name: expectedLast.title, id: expectedLast.id, shard: '00039'}
  ];
  const samples = [];
  for (const target of targets) {
    // The nav pane renders only the most recently registered shard; re-render
    // the target's shard first (already fetched during sampling, so cached).
    await page.evaluate(async (shardId) => {
      if (globalThis.__GTKG_LAST_SHARD__?.id === shardId) return;
      const shard = globalThis.__GTKG_ROOT__.shards.find((candidate) => candidate.id === shardId);
      await new Promise((resolve, reject) => {
        const script = document.createElement('script');
        script.src = shard.path;
        script.onload = resolve;
        script.onerror = () => reject(new Error('shard re-render failed: ' + shard.path));
        document.head.append(script);
      });
      if (globalThis.__GTKG_LAST_SHARD__?.id !== shardId) throw new Error('shard re-render drift: ' + shardId);
    }, target.shard);
    await page.evaluate(() => { globalThis.__F03_SELECT_T0__ = performance.now(); });
    await page.getByRole('button', {name: target.name, exact: true}).click();
    await page.waitForFunction((id) => globalThis.__GTKG_BROWSER_EVIDENCE__?.selected_id === id, target.id);
    const elapsed = await page.evaluate(() => performance.now() - globalThis.__F03_SELECT_T0__);
    samples.push({resource_id: target.id, select_ms: elapsed});
  }
  const last = await page.evaluate(() => ({
    title: document.querySelector('#selected-title').textContent,
    content: document.querySelector('#selected-content').textContent
  }));
  if (last.title !== expectedLast.title || last.content !== expectedLast.content) throw new Error('resource #10000 selection drifted: ' + JSON.stringify(last));
  return JSON.stringify(samples);
}" > "$OUT_DIR/selections.json"

# Feature probe (search), JS heap, horizontal overflow, and final invariants.
run_code 'async (page) => {
  const probe = await page.evaluate(() => ({
    search_controls: document.querySelectorAll("input[type=search], input[name*=search i], input[placeholder*=search i], [role=search], [data-search]").length,
    input_elements: document.querySelectorAll("input").length,
    js_heap_used_bytes: globalThis.performance?.memory?.usedJSHeapSize ?? null,
    js_heap_total_bytes: globalThis.performance?.memory?.totalJSHeapSize ?? null,
    inner_width: window.innerWidth,
    document_scroll_width: document.documentElement.scrollWidth,
    body_scroll_width: document.body.scrollWidth
  }));
  const invariant = await page.evaluate(() => ({
    evidence: globalThis.__GTKG_BROWSER_EVIDENCE__,
    preload: globalThis.__GTKG_PRELOAD_EVIDENCE__,
    xss: globalThis.__GTKG_XSS_SENTINEL__
  }));
  invariant.remote_requests = page.__gtkgF03Requests.filter((url) => /^https?:\/\//i.test(url));
  invariant.total_requests = page.__gtkgF03Requests.length;
  if (invariant.evidence.console_errors !== 0 || invariant.preload.errors !== 0) throw new Error("console errors observed: " + JSON.stringify(invariant));
  if (invariant.preload.csp_violations.length !== 0) throw new Error("CSP violations observed: " + JSON.stringify(invariant));
  if (invariant.xss !== false) throw new Error("XSS sentinel fired");
  if (invariant.remote_requests.length !== 0) throw new Error("remote requests observed: " + JSON.stringify(invariant.remote_requests));
  if (invariant.evidence.target_execution_count !== 0) throw new Error("target content executed");
  const horizontalOverflow = probe.document_scroll_width > probe.inner_width || probe.body_scroll_width > probe.inner_width;
  return JSON.stringify({probe, invariant, horizontal_overflow: horizontalOverflow});
}' > "$OUT_DIR/probe.json"

CONSOLE_ERRORS="$("$PWCLI" --session "$SESSION" console error --json | jq '[.. | objects | select(has("text"))] | length' 2>/dev/null || echo null)"

LOCK_VERSION="$(jq -er '.version' "$LOCK_RECORD")"
LOCK_SHA256="sha256:$(shasum -a 256 "$LOCK_RECORD" | cut -d' ' -f1)"

p95() { jq 'sort | .[(length * 0.95 | ceil) - 1]'; }

jq -n \
  --arg schema "gtkg.f03-wiki-browser-benchmark/v1" \
  --argjson lock_version "\"$LOCK_VERSION\"" \
  --arg lock_sha256 "$LOCK_SHA256" \
  --slurpfile lock_record "$LOCK_RECORD" \
  --arg file_url "$FILE_URL" \
  --argjson resource_count "$RESOURCE_COUNT" \
  --arg projection_tree_sha256 "$PROJECTION_TREE_SHA256" \
  --argjson goto_wall_ms "$GOTO_WALL_MS" \
  --slurpfile initial "$OUT_DIR/initial.json" \
  --slurpfile shards "$OUT_DIR/shards.json" \
  --slurpfile selections "$OUT_DIR/selections.json" \
  --slurpfile probe "$OUT_DIR/probe.json" \
  --argjson shard_p95 "$(jq '[.[].load_ms]' "$OUT_DIR/shards.json" | p95)" \
  --argjson selection_p95 "$(jq '[.[].select_ms]' "$OUT_DIR/selections.json" | p95)" \
  --argjson console_errors "${CONSOLE_ERRORS:-null}" \
  --arg os "$(uname -srm)" \
  --arg node "$(node --version)" \
  --arg date_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  '{
    schema_version: $schema,
    playwright_cli: {package: $lock_record[0].package, version: $lock_version, lock_record_sha256: $lock_sha256, lock_record: $lock_record[0]},
    environment: {os: $os, node: $node, viewport: "1280x800", network: "offline", date_utc: $date_utc},
    fixture: {file_url: $file_url, resource_count: $resource_count, projection_tree_sha256: $projection_tree_sha256, provenance: "real D03 pipeline bundle via frozen d05_browser_fixture_emitter"},
    initial_load: {goto_wall_ms: $goto_wall_ms, navigation: $initial[0].navigation},
    shard_loads: {samples: $shards[0], sample_count: ($shards[0] | length), p95_ms: $shard_p95},
    selections: {samples: $selections[0], sample_count: ($selections[0] | length), p95_ms: $selection_p95, includes_resource_10000: true},
    search_feature: (if $probe[0].probe.search_controls > 0 then "present" else "absent" end),
    search_note: (if $probe[0].probe.search_controls > 0 then null else "product Wiki currently has no search feature; no search benchmark executed" end),
    js_heap: {used_bytes: $probe[0].probe.js_heap_used_bytes, total_bytes: $probe[0].probe.js_heap_total_bytes, note: (if $probe[0].probe.js_heap_used_bytes == null then "performance.memory unavailable in this browser" else null end)},
    horizontal_overflow: $probe[0].horizontal_overflow,
    invariants: {
      console_errors: $console_errors,
      page_error_count: $probe[0].invariant.evidence.console_errors,
      preload_errors: $probe[0].invariant.preload.errors,
      remote_requests: ($probe[0].invariant.remote_requests | length),
      total_file_requests: $probe[0].invariant.total_requests,
      csp_violations: ($probe[0].invariant.preload.csp_violations | length),
      xss_sentinel: $probe[0].invariant.xss,
      target_execution_count: $probe[0].invariant.evidence.target_execution_count
    }
  }' > "$OUT_DIR/f03-wiki-benchmark-receipt.json"

echo "F03_BENCHMARK_PASS receipt=$OUT_DIR/f03-wiki-benchmark-receipt.json resource_count=$RESOURCE_COUNT goto_wall_ms=$GOTO_WALL_MS shard_p95_ms=$(jq '.shard_loads.p95_ms' "$OUT_DIR/f03-wiki-benchmark-receipt.json") selection_p95_ms=$(jq '.selections.p95_ms' "$OUT_DIR/f03-wiki-benchmark-receipt.json")"
