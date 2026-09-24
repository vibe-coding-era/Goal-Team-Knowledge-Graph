#!/usr/bin/env bash
# F03/B17: in-repo Playwright CLI runner pinned to the exact version recorded in
# playwright_cli.lock.json. Never reference a floating tag here; bump the lock
# record and this pin together and re-run the F03 contract.
set -euo pipefail

PINNED_PACKAGE="@playwright/cli@0.1.18"

if ! command -v npx >/dev/null 2>&1; then
  echo "Error: npx is required but not found on PATH." >&2
  exit 1
fi

has_session_flag="false"
for arg in "$@"; do
  case "$arg" in
    --session|--session=*)
      has_session_flag="true"
      break
      ;;
  esac
done

cmd=(npx --yes --package "$PINNED_PACKAGE" playwright-cli)
if [[ "${has_session_flag}" != "true" && -n "${PLAYWRIGHT_CLI_SESSION:-}" ]]; then
  cmd+=(--session "${PLAYWRIGHT_CLI_SESSION}")
fi
cmd+=("$@")

exec "${cmd[@]}"
