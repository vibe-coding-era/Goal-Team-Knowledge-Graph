#!/usr/bin/env bash
# Serve the knowledge GTKG produced, two ways.
#
#   gtkg-serve.sh mcp  [profile]   MCP stdio for an agent host (no network listener)
#   gtkg-serve.sh http [port]      static HTTP over one workspace's bundles (local only)
#
# GTKG itself opens no listening socket, so the HTTP mode is a plain static file
# server over the produced bundle - it is a viewer, not part of the product.
set -euo pipefail

MODE="${1:-mcp}"
GTKG_BIN="${GTKG_BIN:-$(command -v gtkg || echo "$HOME/.local/bin/gtkg")}"
ROOT="${GTKG_ROOT:-$HOME/gtkg}"

case "$MODE" in
  mcp)
    PROFILE="${2:-core}"
    exec "$GTKG_BIN" mcp serve --protocol v2 --profile "$PROFILE" --stdio
    ;;
  http)
    PORT="${2:-8421}"
    WS="${3:-}"
    if [ -z "$WS" ]; then
      # An unmatched glob must not kill the script: this runs under `set -e`
      # with `pipefail`, and BSD ls exits non-zero on a missing operand.
      WS="$( { ls -d "$ROOT"/workspaces/*/gtkg-run.json "$ROOT"/*/gtkg-run.json 2>/dev/null || true; } \
            | head -1 | xargs dirname 2>/dev/null || true )"
    fi
    [ -n "$WS" ] || { echo "error: no workspace found under $ROOT" >&2; exit 2; }
    BUNDLES="$WS/.gtkg/qk/bundles"
    [ -d "$BUNDLES" ] || { echo "error: no bundle directory at $BUNDLES" >&2; exit 2; }

    # Each run finalizes its own stamped bundle, so serve the newest one rather
    # than the parent directory of all of them. Use "http <port> <ws> <name>" to
    # pin an exact bundle.
    PIN="${4:-}"
    if [ -n "$PIN" ]; then
      [ -d "$BUNDLES/$PIN" ] || { echo "error: no bundle named $PIN" >&2; exit 2; }
      SERVE="$BUNDLES/$PIN"
    else
      SERVE="$(find "$BUNDLES" -maxdepth 1 -mindepth 1 -type d | sort | tail -1)"
      [ -n "$SERVE" ] || { echo "error: no finalized bundle yet" >&2; exit 2; }
    fi

    echo "workspace $WS"
    echo "serving   $(basename "$SERVE")"
    echo "url       http://127.0.0.1:$PORT/   (loopback only; ctrl-c to stop)"
    echo "entry     http://127.0.0.1:$PORT/.gtkg/qk/knowledge/"
    exec python3 -m http.server "$PORT" --bind 127.0.0.1 --directory "$SERVE"
    ;;
  *)
    echo "usage: gtkg-serve.sh [mcp|http] [profile|port] [workspace]" >&2
    exit 2
    ;;
esac
