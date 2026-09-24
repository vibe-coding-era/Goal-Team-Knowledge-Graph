#!/usr/bin/env bash
# One automated pass over every GTKG workspace under a root directory.
#
# GTKG has no daemon, no file watcher and no Git hook - that is a design
# property, not a gap. "Run automatically" therefore means: let an external
# scheduler (launchd, systemd, cron, CI) call this script on an interval. This
# script is the whole automation surface; it is safe to run by hand.
#
# Usage: gtkg-pipeline.sh [workspace-root] [stages]
#   workspace-root  default $GTKG_ROOT or ~/gtkg
#   stages          default "all"; any driver stage list, e.g. "capture" or "job"
set -uo pipefail

ROOT="${1:-${GTKG_ROOT:-$HOME/gtkg}}"
STAGES="${2:-all}"
GTKG_BIN="${GTKG_BIN:-$(command -v gtkg || echo "$HOME/.local/bin/gtkg")}"
DRIVER="${GTKG_DRIVER:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/scripts/v04_host_authoring.py}"
LOG_DIR="$ROOT/logs"

# Secrets come from a mode-0600 env file, never from the launchd plist and never
# from this repository.
if [ -f "$ROOT/.env" ]; then
  set -a; . "$ROOT/.env"; set +a
fi

mkdir -p "$LOG_DIR"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
LOG="$LOG_DIR/pipeline-$STAMP.log"
exec > >(tee -a "$LOG") 2>&1

echo "=== gtkg pipeline $STAMP ==="
echo "root    $ROOT"
echo "binary  $GTKG_BIN"
echo "driver  $DRIVER"
echo "stages  $STAGES"

[ -x "$GTKG_BIN" ] || { echo "fatal: gtkg binary not executable: $GTKG_BIN"; exit 2; }
[ -f "$DRIVER" ]   || { echo "fatal: driver not found: $DRIVER"; exit 2; }
command -v python3 >/dev/null || { echo "fatal: python3 required"; exit 2; }

if [ -z "${DEEPSEEK_API_KEY:-}" ]; then
  echo "warning: DEEPSEEK_API_KEY is not set; the authoring stages will fail closed."
  echo "         (capture/analyze/job stages still run and are useful on their own)"
fi

export GTKG_BIN
FAILED=0
RAN=0

shopt -s nullglob
for cfg in "$ROOT"/workspaces/*/gtkg-run.json "$ROOT"/*/gtkg-run.json; do
  WS="$(dirname "$cfg")"
  RAN=$((RAN + 1))
  echo
  echo "--- workspace $WS"

  # Skip a workspace whose pinned commit already produced a verified bundle, so a
  # 6-hourly timer does not burn a model call on an unchanged source. GTKG_FORCE=1
  # re-runs regardless.
  if [ "${GTKG_FORCE:-0}" != "1" ] && python3 - "$WS" <<'PYCHECK'
import json, pathlib, sys
ws = pathlib.Path(sys.argv[1])
ledger = ws / ".gtkg" / "host" / "runs.json"
cfg = ws / "gtkg-run.json"
if not ledger.exists() or not cfg.exists():
    raise SystemExit(1)
commit = json.loads(cfg.read_text()).get("source_commit")
runs = json.loads(ledger.read_text())
ok = any(r.get("source_commit") == commit and r.get("status") for r in runs)
print(f"    already verified for commit {str(commit)[:12]}; skipping (GTKG_FORCE=1 to override)")
raise SystemExit(0 if ok else 1)
PYCHECK
  then
    echo "--- skipped: $WS"
    continue
  fi
  # The authorized root is the process cwd, and the source, the host inputs and
  # every produced bundle must live under it, so the driver always runs from the
  # workspace root.
  if ( cd "$WS" && python3 "$DRIVER" "$STAGES" ); then
    echo "--- ok: $WS"
  else
    echo "--- FAILED: $WS"
    FAILED=$((FAILED + 1))
  fi
done
shopt -u nullglob

echo
echo "=== $RAN workspace(s), $FAILED failure(s) ==="
echo "log: $LOG"
[ "$FAILED" -eq 0 ] || exit 1
