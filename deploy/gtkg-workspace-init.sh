#!/usr/bin/env bash
# Create one GTKG workspace from a Git repository and scaffold its run config.
#
# Layout the authorization model forces (authorized root is the process cwd, and
# both the source and every output must live under it):
#
#   <workspace>/<repo>/          the source checkout, pinned
#   <workspace>/gtkg-run.json    the run config the driver reads
#   <workspace>/.gtkg/           all runtime state and produced bundles
#
# Usage: gtkg-workspace-init.sh <git-url-or-path> <workspace-dir> [repo-name]
set -euo pipefail

REPO_SRC="${1:?usage: gtkg-workspace-init.sh <git-url-or-path> <workspace-dir> [repo-name]}"
WS="${2:?usage: gtkg-workspace-init.sh <git-url-or-path> <workspace-dir> [repo-name]}"
NAME="${3:-$(basename "${REPO_SRC%.git}")}"

say() { printf '%s\n' "$*"; }

mkdir -p "$WS"
WS="$(cd "$WS" && pwd -P)"          # resolve /tmp -> /private/tmp on macOS
REPO_DIR="$WS/$NAME"

if [ -d "$REPO_DIR/.git" ]; then
  say "==> source checkout already present: $REPO_DIR"
else
  say "==> cloning $REPO_SRC -> $REPO_DIR"
  git clone --quiet "$REPO_SRC" "$REPO_DIR"
fi

git -C "$REPO_DIR" diff --quiet && git -C "$REPO_DIR" diff --cached --quiet \
  || { printf 'error: %s has uncommitted changes\n' "$REPO_DIR" >&2; exit 1; }

COMMIT="$(git -C "$REPO_DIR" rev-parse HEAD)"
TREE="$(git -C "$REPO_DIR" rev-parse 'HEAD^{tree}')"
say "==> pinned commit $COMMIT"
say "==> pinned tree   $TREE"

python3 - "$WS" "$NAME" "$COMMIT" "$TREE" <<'PY'
import json, pathlib, sys
ws, name, commit, tree = sys.argv[1:5]
cfg_path = pathlib.Path(ws) / "gtkg-run.json"
if cfg_path.exists():
    print(f"==> run config already exists, leaving it alone: {cfg_path}")
    raise SystemExit(0)
cfg = {
    "repo_id": name,
    "source_root": name,
    "source_commit": commit,
    "expected_tree": tree,
    "project_name": name,
    "inventory_id": f"{name}@{commit[:12]}",
    "version_condition": f"{name}@{commit}",
    "job_id": f"{name}-semantic-understanding-r1",
    "understanding_items": [],
    "prompt": (
        "Explain the supplied source windows so that an engineer who has never seen "
        "this project can navigate it. State only what the supplied bytes show; cite "
        "the exact span you used for every claim."
    ),
    "windows": {},
    "max_context_units": 7500,
    "bundle_name": f"{name}-r1",
    "author_id": "deepseek-flash-author",
    "reviewer_ids": ["deepseek-flash-reviewer-a", "deepseek-flash-reviewer-b"],
    "modules": [],
}
cfg_path.write_text(json.dumps(cfg, indent=2) + "\n")
print(f"==> wrote {cfg_path}")
print("    NEXT: fill in understanding_items, windows and modules, then run")
print(f"          gtkg-pipeline.sh {ws}")
PY
