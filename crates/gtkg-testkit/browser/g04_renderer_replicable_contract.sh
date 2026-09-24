#!/usr/bin/env bash
# G04 frozen contract: OD-003/OD-004 renderer_replicable browser evidence.
#
# Flow (all offline, locked runner only):
#   1. run-a and run-b: two independent processes of the same test binary emit the
#      deterministic frozen Wiki fixture (production renderer) plus a real
#      D03 -> A2UI generation; their frozen fixture tree digests must be identical.
#   2. Locked Playwright smoke on run-a: page renders, the six UI states
#      ('normal', 'loading', 'empty', 'error', 'permission', 'disabled') isolate,
#      remote requests = 0, console errors = 0, CSP violations = 0,
#      target execution = 0, XSS payload inert; then 6 states x 3 regions
#      (full, left-index, right-content) screenshots per run.
#   3. Same-build replay: run-a vs run-b screenshots must be pixel identical
#      (diff = 0, hard oracle; byte equality first, exact pixel diff fallback).
#   4. Cross-build replay: run-c is emitted by a --release build of the same
#      source; its screenshots are diffed against run-a and the measured maximum
#      must stay within CROSS_BUILD_PIXEL_THRESHOLD (frozen from G04 measurement;
#      see gtkg-testkit/tests/g04_renderer_replicable_contract.rs).
#   5. The measured evidence is published as gtkg.a2ui-renderer-smoke/v1 into the
#      run-a workspace and a2ui.validate must grant renderer_replicable while
#      verified_replica stays fail-closed.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
# F03/B17: default to the in-repo pinned runner; PWCLI env still overrides.
PWCLI="${PWCLI:-$REPO_ROOT/crates/gtkg-testkit/browser/playwright_cli_locked.sh}"
PWCONFIG="$REPO_ROOT/crates/gtkg-testkit/browser/d05_playwright_cli.config.json"
# G04 measured cross-build replay threshold (debug vs release): the projection
# bytes are a pure function of the frozen fixture (identical tree digest across
# builds), so the pinned Chromium renders identical pixels; measured max diff = 0.
CROSS_BUILD_PIXEL_THRESHOLD=0

if ! command -v npx >/dev/null 2>&1; then
  echo "npx is required by the Playwright CLI wrapper" >&2
  exit 2
fi
if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required by the G04 harness" >&2
  exit 2
fi
if [[ ! -x "$PWCLI" ]]; then
  echo "Playwright CLI wrapper is not executable: $PWCLI" >&2
  exit 2
fi

BROWSER_ROOT="${GTKG_G04_BROWSER_OUTPUT:-$(mktemp -d "${TMPDIR:-/tmp}/gtkg-g04-browser.XXXXXX")}"
mkdir -p "$BROWSER_ROOT"
if [[ -n "$(find "$BROWSER_ROOT" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
  echo "GTKG_G04_BROWSER_OUTPUT must be a new empty directory" >&2
  exit 2
fi

RUN_A="$BROWSER_ROOT/run-a"
RUN_B="$BROWSER_ROOT/run-b"
RUN_C="$BROWSER_ROOT/run-c"
mkdir -p "$RUN_A" "$RUN_B" "$RUN_C"
trap 'for name in run-a run-b run-c; do "$PWCLI" --session "gtkg-g04-$name-$$" close >/dev/null 2>&1 || true; done' EXIT

emit_fixture() { # $1 = run dir, $2 = cargo profile flags (may be empty)
  local dir="$1"
  shift
  (
    cd "$REPO_ROOT"
    GTKG_G04_BROWSER_OUTPUT="$dir" cargo test -p gtkg-testkit "$@" \
      --test g04_browser_fixture_emitter emit_g04_browser_fixture \
      -- --ignored --exact --nocapture --test-threads=1
  )
}

echo "== G04 emit run-a (debug, process 1) =="
emit_fixture "$RUN_A"
echo "== G04 emit run-b (debug, process 2) =="
emit_fixture "$RUN_B"

RECEIPT_A="$RUN_A/g04-browser-fixture-receipt.json"
RECEIPT_B="$RUN_B/g04-browser-fixture-receipt.json"
jq -e '.schema_version == "gtkg.g04-browser-fixture-receipt/v1"' "$RECEIPT_A" >/dev/null
jq -e '.schema_version == "gtkg.g04-browser-fixture-receipt/v1"' "$RECEIPT_B" >/dev/null
TREE_A="$(jq -er '.frozen.tree_sha256' "$RECEIPT_A")"
TREE_B="$(jq -er '.frozen.tree_sha256' "$RECEIPT_B")"
if [[ "$TREE_A" != "$TREE_B" ]]; then
  echo "same-build frozen fixture tree digest drifted: $TREE_A vs $TREE_B" >&2
  exit 1
fi

PW_VERSION="$(jq -er '.version' "$REPO_ROOT/crates/gtkg-testkit/browser/playwright_cli.lock.json")"

browse_run() { # $1 = run dir, $2 = "check" | "shots"
  local dir="$1" mode="$2"
  local receipt="$dir/g04-browser-fixture-receipt.json"
  local file_url expected_requests expected_initial expected_last expected_shard session shots
  file_url="$(jq -er '.frozen.file_url' "$receipt")"
  expected_requests="$(jq -c '.frozen.expected_initial_requests | sort' "$receipt")"
  expected_initial="$(jq -c '.frozen.expected_initial' "$receipt")"
  expected_last="$(jq -c '.frozen.expected_last' "$receipt")"
  expected_shard="$(jq -c '.frozen.expected_last_shard | {id, count: .entry_count}' "$receipt")"
  session="gtkg-g04-$(basename "$dir")-$$"
  shots="$dir/shots"
  mkdir -p "$shots"

  "$PWCLI" --session "$session" open about:blank --config "$PWCONFIG" >/dev/null
  "$PWCLI" --session "$session" run-code 'async (page) => {
    await page.setViewportSize({width: 1280, height: 800});
    page.__gtkgG04Requests = [];
    page.on("request", (request) => { page.__gtkgG04Requests.push(request.url()); });
    await page.addInitScript(() => {
      globalThis.__GTKG_PRELOAD_EVIDENCE__ = {errors: 0, csp_violations: []};
      globalThis.addEventListener("error", () => { globalThis.__GTKG_PRELOAD_EVIDENCE__.errors += 1; });
      globalThis.addEventListener("unhandledrejection", () => { globalThis.__GTKG_PRELOAD_EVIDENCE__.errors += 1; });
      globalThis.addEventListener("securitypolicyviolation", (event) => { globalThis.__GTKG_PRELOAD_EVIDENCE__.csp_violations.push(event.violatedDirective); });
    });
  }' >/dev/null
  "$PWCLI" --session "$session" network-state-set offline >/dev/null
  "$PWCLI" --session "$session" goto "$file_url" >/dev/null

  "$PWCLI" --session "$session" run-code "async (page) => {
    const check = $( [[ "$mode" == check ]] && echo true || echo false );
    const states = ['normal', 'loading', 'empty', 'error', 'permission', 'disabled'];
    const expectedRequests = $expected_requests;
    const expectedInitial = $expected_initial;
    const expectedLast = $expected_last;
    const expectedShard = $expected_shard;
    const out = '$shots';

    const initial = await page.evaluate(() => ({
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
    initial.resources = page.__gtkgG04Requests.map((url) => {
      const marker = '/wiki/';
      if (!url.includes(marker)) throw new Error('request escaped Wiki root: ' + url);
      return decodeURIComponent(url.slice(url.indexOf(marker) + marker.length));
    }).sort();
    initial.remote = page.__gtkgG04Requests.filter((url) => /^https?:\/\//i.test(url));
    if (check) {
      if (initial.protocol !== 'file:') throw new Error('expected file:, got ' + initial.protocol);
      if (JSON.stringify(initial.resources) !== JSON.stringify(expectedRequests)) throw new Error('initial resource exact-set drift: ' + JSON.stringify(initial.resources));
      if (initial.remote.length !== 0) throw new Error('remote requests observed: ' + JSON.stringify(initial.remote));
      if (!initial.left || !initial.right) throw new Error('left/right Wiki regions missing');
      if (initial.xss !== false || initial.selectedTitle !== expectedInitial.title || initial.selectedContent !== expectedInitial.content) throw new Error('selected content or XSS inertness drifted');
      if (initial.evidence.resource_count !== 300 || initial.evidence.selected_id !== expectedInitial.id || initial.evidence.target_execution_count !== 0) throw new Error('resource, selection, or target-execution evidence drifted');
      if (initial.evidence.console_errors !== 0 || initial.preload.errors !== 0 || initial.preload.csp_violations.length !== 0) throw new Error('browser errors observed: ' + JSON.stringify(initial));
      if (JSON.stringify(initial.visibleStates) !== JSON.stringify(['normal'])) throw new Error('initial state drift: ' + JSON.stringify(initial.visibleStates));
    }

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
      if (check) {
        if (JSON.stringify(observed.visible) !== JSON.stringify([state])) throw new Error('state isolation drift for ' + state + ': ' + JSON.stringify(observed));
        if ((state === 'loading') !== (observed.ariaBusy === 'true')) throw new Error('loading aria-busy drift: ' + JSON.stringify(observed));
        if (observed.buttonCount === 0 || (state === 'disabled') !== observed.buttonsDisabled) throw new Error('real disabled control drift: ' + JSON.stringify(observed));
        if (state === 'permission' && observed.content !== '') throw new Error('permission state leaked selected content: ' + JSON.stringify(observed));
      }
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
    const after = await page.evaluate(() => ({
      selectedTitle: document.querySelector('#selected-title').textContent,
      selectedContent: document.querySelector('#selected-content').textContent,
      evidenceErrors: globalThis.__GTKG_BROWSER_EVIDENCE__.console_errors,
      preloadErrors: globalThis.__GTKG_PRELOAD_EVIDENCE__.errors,
      csp: globalThis.__GTKG_PRELOAD_EVIDENCE__.csp_violations,
      xss: globalThis.__GTKG_XSS_SENTINEL__
    }));
    after.remote = page.__gtkgG04Requests.filter((url) => /^https?:\/\//i.test(url));
    if (check) {
      if (after.selectedTitle !== expectedLast.title || after.selectedContent !== expectedLast.content) throw new Error('last resource selection drifted: ' + JSON.stringify(after));
      if (after.remote.length !== 0 || after.evidenceErrors !== 0 || after.preloadErrors !== 0 || after.csp.length !== 0 || after.xss !== false) throw new Error('offline/error/XSS evidence drifted: ' + JSON.stringify(after));
    }

    for (const state of states) {
      await page.evaluate((selected) => globalThis.__GTKG_SHOW_STATE__(selected), state);
      await page.screenshot({path: out + '/' + state + '-full.png'});
      const left = await page.locator('[data-region=left-index]').boundingBox();
      await page.screenshot({path: out + '/' + state + '-left-index.png', clip: left});
      const right = await page.locator('[data-region=right-content]').boundingBox();
      await page.screenshot({path: out + '/' + state + '-right-content.png', clip: right});
    }
    await page.evaluate(() => globalThis.__GTKG_SHOW_STATE__('normal'));
    return {shots: out};
  }"

  "$PWCLI" --session "$session" close >/dev/null
}

pixel_diff() { # $1 = png a, $2 = png b -> prints differing pixel count
  python3 - "$1" "$2" <<'PYEOF'
import struct, sys, zlib

def decode(path):
    data = open(path, "rb").read()
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        raise SystemExit(f"not a PNG: {path}")
    offset, idat, width, height, bit_depth, color_type, interlace = 8, b"", 0, 0, 8, 6, 0
    while offset < len(data):
        (length,) = struct.unpack(">I", data[offset:offset + 4])
        kind = data[offset + 4:offset + 8]
        body = data[offset + 8:offset + 8 + length]
        if kind == b"IHDR":
            width, height, bit_depth, color_type, _, _, interlace = struct.unpack(">IIBBBBB", body)
        elif kind == b"IDAT":
            idat += body
        offset += 12 + length
    if bit_depth != 8 or color_type != 6 or interlace != 0:
        raise SystemExit(f"unsupported PNG encoding in {path}: depth={bit_depth} type={color_type} interlace={interlace}")
    raw = zlib.decompress(idat)
    stride = width * 4
    pixels = bytearray(width * height * 4)
    previous = bytearray(stride)
    source = 0
    for row in range(height):
        filter_kind = raw[source]
        source += 1
        line = bytearray(raw[source:source + stride])
        source += stride
        for column in range(stride):
            left = line[column - 4] if column >= 4 else 0
            up = previous[column]
            up_left = previous[column - 4] if column >= 4 else 0
            if filter_kind == 1:
                line[column] = (line[column] + left) & 0xFF
            elif filter_kind == 2:
                line[column] = (line[column] + up) & 0xFF
            elif filter_kind == 3:
                line[column] = (line[column] + ((left + up) >> 1)) & 0xFF
            elif filter_kind == 4:
                p = left + up - up_left
                pa, pb, pc = abs(p - left), abs(p - up), abs(p - up_left)
                predictor = left if (pa <= pb and pa <= pc) else (up if pb <= pc else up_left)
                line[column] = (line[column] + predictor) & 0xFF
            elif filter_kind != 0:
                raise SystemExit(f"unknown PNG filter {filter_kind} in {path}")
        pixels[row * stride:(row + 1) * stride] = line
        previous = line
    return width, height, bytes(pixels)

wa, ha, a = decode(sys.argv[1])
wb, hb, b = decode(sys.argv[2])
if (wa, ha) != (wb, hb):
    raise SystemExit(f"dimension mismatch: {wa}x{ha} vs {wb}x{hb}")
diff = sum(1 for i in range(0, len(a), 4) if a[i:i + 4] != b[i:i + 4])
print(diff)
PYEOF
}

diff_shots() { # $1 = shots dir a, $2 = shots dir b -> prints "pairs byte_equal pixel_diff_max"
  local pairs=0 equal=0 max_diff=0 name diff
  for path_a in "$1"/*.png; do
    name="$(basename "$path_a")"
    pairs=$((pairs + 1))
    if cmp -s "$path_a" "$2/$name"; then
      equal=$((equal + 1))
    else
      diff="$(pixel_diff "$path_a" "$2/$name")"
      if (( diff > max_diff )); then
        max_diff=$diff
      fi
    fi
  done
  echo "$pairs $equal $max_diff"
}

echo "== G04 browser smoke + screenshots run-a (locked Playwright) =="
browse_run "$RUN_A" check
echo "== G04 screenshots run-b (same binary, independent process) =="
browse_run "$RUN_B" shots

read -r SAME_PAIRS SAME_EQUAL SAME_MAX <<<"$(diff_shots "$RUN_A/shots" "$RUN_B/shots")"
if [[ "$SAME_PAIRS" != "18" ]]; then
  echo "expected 6 states x 3 regions = 18 screenshot pairs, got $SAME_PAIRS" >&2
  exit 1
fi
if [[ "$SAME_MAX" != "0" ]]; then
  echo "same-build replay pixel diff must be 0, measured max $SAME_MAX (byte-equal pairs $SAME_EQUAL/18)" >&2
  exit 1
fi
echo "G04 same-build replay: pairs=18 byte_equal=$SAME_EQUAL pixel_diff_max=0"

echo "== G04 emit run-c (release build of the same source) =="
emit_fixture "$RUN_C" --release
RECEIPT_C="$RUN_C/g04-browser-fixture-receipt.json"
TREE_C="$(jq -er '.frozen.tree_sha256' "$RECEIPT_C")"
if [[ "$TREE_C" != "$TREE_A" ]]; then
  echo "cross-build frozen fixture tree digest drifted: $TREE_A vs $TREE_C" >&2
  exit 1
fi
echo "== G04 screenshots run-c (cross-build replay) =="
browse_run "$RUN_C" shots
read -r CROSS_PAIRS CROSS_EQUAL CROSS_MAX <<<"$(diff_shots "$RUN_A/shots" "$RUN_C/shots")"
if [[ "$CROSS_PAIRS" != "18" ]]; then
  echo "expected 18 cross-build screenshot pairs, got $CROSS_PAIRS" >&2
  exit 1
fi
if (( CROSS_MAX > CROSS_BUILD_PIXEL_THRESHOLD )); then
  echo "cross-build replay pixel diff $CROSS_MAX exceeds frozen threshold $CROSS_BUILD_PIXEL_THRESHOLD" >&2
  exit 1
fi
echo "G04 cross-build replay: pairs=18 byte_equal=$CROSS_EQUAL pixel_diff_max=$CROSS_MAX threshold=$CROSS_BUILD_PIXEL_THRESHOLD"

WORKSPACE_A="$(jq -er '.workspace' "$RECEIPT_A")"
EVIDENCE_DIR="$WORKSPACE_A/.gtkg/a2ui/browser-evidence"
mkdir -p "$EVIDENCE_DIR"
jq -n \
  --arg projection "$(jq -er '.projection_tree_sha256' "$RECEIPT_A")" \
  --arg catalog_id "$(jq -er '.a2ui_lock.catalog_id' "$RECEIPT_A")" \
  --arg catalog_version "$(jq -er '.a2ui_lock.catalog_version' "$RECEIPT_A")" \
  --arg catalog_sha256 "$(jq -er '.a2ui_lock.catalog_sha256' "$RECEIPT_A")" \
  --arg renderer_id "$(jq -er '.a2ui_lock.renderer_id' "$RECEIPT_A")" \
  --arg renderer_version "$(jq -er '.a2ui_lock.renderer_version' "$RECEIPT_A")" \
  --arg renderer_sha256 "$(jq -er '.a2ui_lock.renderer_sha256' "$RECEIPT_A")" \
  --arg index_html "$(jq -er '.wiki_shell_sha256.index_html' "$RECEIPT_A")" \
  --arg wiki_css "$(jq -er '.wiki_shell_sha256.wiki_css' "$RECEIPT_A")" \
  --arg wiki_js "$(jq -er '.wiki_shell_sha256.wiki_js' "$RECEIPT_A")" \
  --arg pw_version "$PW_VERSION" \
  --argjson cross_max "$CROSS_MAX" \
  --argjson cross_threshold "$CROSS_BUILD_PIXEL_THRESHOLD" \
  '{
    schema_version: "gtkg.a2ui-renderer-smoke/v1",
    projection_tree_sha256: $projection,
    catalog_id: $catalog_id,
    catalog_version: $catalog_version,
    catalog_sha256: $catalog_sha256,
    renderer_id: $renderer_id,
    renderer_version: $renderer_version,
    renderer_sha256: $renderer_sha256,
    wiki_shell_sha256: {index_html: $index_html, wiki_css: $wiki_css, wiki_js: $wiki_js},
    browser: {
      engine: "chromium",
      playwright_cli_package: "@playwright/cli",
      playwright_cli_version: $pw_version
    },
    states: ["normal", "loading", "empty", "error", "permission", "disabled"],
    regions: ["full", "left-index", "right-content"],
    remote_request_count: 0,
    console_error_count: 0,
    csp_violation_count: 0,
    target_execution_count: 0,
    xss_sentinel_tripped: false,
    same_build_replay: {independent_processes: 2, screenshot_pairs: 18, pixel_diff_max: 0},
    cross_build_replay: {
      builds: ["debug", "release"],
      pixel_diff_max: $cross_max,
      threshold: $cross_threshold,
      explanation: "G04 measured: projection bytes are a pure function of the frozen fixture (identical tree digest across builds), so the pinned Chromium emits identical pixels."
    }
  }' > "$EVIDENCE_DIR/smoke-g04.json"

echo "== G04 finalizer: a2ui.validate with measured browser evidence =="
(
  cd "$REPO_ROOT"
  GTKG_G04_BROWSER_OUTPUT="$RUN_A" cargo test -p gtkg-testkit \
    --test g04_browser_fixture_emitter validate_g04_renderer_replicable_with_browser_evidence \
    -- --ignored --exact --nocapture --test-threads=1
)

jq -n \
  --arg tree "$TREE_A" \
  --argjson same_equal "$SAME_EQUAL" \
  --argjson cross_equal "$CROSS_EQUAL" \
  --argjson cross_max "$CROSS_MAX" \
  --argjson cross_threshold "$CROSS_BUILD_PIXEL_THRESHOLD" \
  '{
    schema_version: "gtkg.g04-renderer-replicable-receipt/v1",
    frozen_tree_sha256: $tree,
    smoke: {remote_request_count: 0, console_error_count: 0, csp_violation_count: 0, target_execution_count: 0, states: 6, regions: 3},
    same_build_replay: {independent_processes: 2, screenshot_pairs: 18, byte_equal_pairs: $same_equal, pixel_diff_max: 0},
    cross_build_replay: {builds: ["debug", "release"], screenshot_pairs: 18, byte_equal_pairs: $cross_equal, pixel_diff_max: $cross_max, threshold: $cross_threshold},
    validate_renderer_replicable: "granted",
    validate_verified_replica: "fail_closed"
  }' > "$BROWSER_ROOT/g04-renderer-replicable-receipt.json"

echo "G04_RENDERER_REPLICABLE_PASS receipt=$BROWSER_ROOT/g04-renderer-replicable-receipt.json same_build_pixel_diff=0 cross_build_pixel_diff=$CROSS_MAX threshold=$CROSS_BUILD_PIXEL_THRESHOLD"
