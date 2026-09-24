#!/usr/bin/env bash
# Interactive shell over the gtkg CLI.
#
# GTKG has no REPL of its own: every operation is a separate process and all
# state lives in the workspace `.gtkg/` directory. This is a thin prompt that
# keeps the binary, the workspace and the envelope shape pinned, so exploring the
# 46 operations does not mean retyping JSON envelopes by hand.
#
#   gtkg-shell.sh [workspace]
#
# Nothing here is part of the product; it only shells out to the real CLI.
set -uo pipefail

GTKG_BIN="${GTKG_BIN:-$(command -v gtkg || echo "$HOME/.local/bin/gtkg")}"
ROOT="${GTKG_ROOT:-$HOME/gtkg}"

if [ $# -ge 1 ]; then
  WS="$1"
else
  WS="$( { ls -d "$ROOT"/workspaces/*/gtkg-run.json "$ROOT"/*/gtkg-run.json 2>/dev/null || true; } \
        | head -1 | xargs dirname 2>/dev/null || true )"
  [ -n "${WS:-}" ] || WS="$ROOT"
fi
if [ -d "$WS" ]; then cd "$WS" || exit 2; else echo "workspace not found: $WS" >&2; exit 2; fi
WS="$PWD"

[ -x "$GTKG_BIN" ] || { echo "gtkg binary not executable: $GTKG_BIN" >&2; exit 2; }

DIM=$'\033[2m'; B=$'\033[1m'; G=$'\033[32m'; R=$'\033[31m'; Y=$'\033[33m'; Z=$'\033[0m'

# Python helpers are single-quoted for the shell, so their source must never use
# a single quote and must never escape a quote inside an f-string expression
# (a backslash inside {...} is a syntax error). Double quotes plus % only.
PY_PROFILE='import json,sys
d=json.load(sys.stdin)
print("profile %s  digest %s...  %d tools" % (d["profile_id"], d["profile_digest"][:22], len(d["tools"])))
for t in d["tools"]:
    revs=",".join(r.replace("gtkg.protocol/v2-default","default").replace("gtkg.knowledge-quality/v0.4-r1","v0.4") for r in t["x-gtkg-payload-revisions"])
    print("  %-22s %-20s [%s]" % (t["x-gtkg-operation-id"], t["x-gtkg-side-effect"], revs))'

PY_PRETTY='import json,sys
print(json.dumps(json.load(sys.stdin), indent=2, ensure_ascii=False))'

PY_CONFIG='import json
c=json.load(open("gtkg-run.json"))
print("  repo      %s @ %s" % (c.get("repo_id"), str(c.get("source_commit"))[:12]))
print("  items     %d  windows %d" % (len(c.get("understanding_items", [])), len(c.get("windows", {}))))'

PY_STATUS='import json
c=json.load(open("gtkg-run.json"))
print("  repo      %s" % c["repo_id"])
print("  commit    %s" % c["source_commit"])
print("  tree      %s" % c["expected_tree"])
print("  bundle    %s" % c["bundle_name"])'

PY_RUNS='import json
h=json.load(open(".gtkg/host/runs.json"))
print("  runs      %d" % len(h))
for r in h[-3:]:
    print("    %s  %s  %s files" % (r["run_at_utc"][:19], r["bundle_name"], r.get("verified_files")))'

send() {
  local op="$1" payload="${2:-}"
  # An explicitly empty argument does not trigger a ${2:-default}, so normalise.
  [ -z "${payload// }" ] && payload="{}"
  local envelope out rc
  # v1 takes `locks`; v2's envelope is closed and rejects it.
  if [ "$PROTO" = "gtkg.protocol/v1" ]; then
    envelope="$(printf '{"protocol_version":"%s","operation_id":"%s","request_id":"shell-%s","locks":{},"payload":%s}' \
      "$PROTO" "$op" "$(date +%s)" "$payload")"
    out="$(printf '%s\n' "$envelope" | "$GTKG_BIN" --strict-exit op "$op" --request - --output json 2>&1)"; rc=$?
  else
    envelope="$(printf '{"protocol_version":"%s","operation_id":"%s","request_id":"shell-%s","payload":%s}' \
      "$PROTO" "$op" "$(date +%s)" "$payload")"
    out="$(printf '%s\n' "$envelope" | "$GTKG_BIN" --strict-exit v2-op "$op" --profile "$PROFILE" --request - --output json 2>&1)"; rc=$?
  fi
  if [ $rc -ne 0 ]; then printf '%s%s%s\n' "$R" "$out" "$Z"; return 1; fi
  printf '%s\n' "$out" | python3 -c "$PY_PRETTY" 2>/dev/null || printf '%s\n' "$out"
}

status_text() {
  printf 'workspace %s\n' "$WS"
  [ -f gtkg-run.json ] && python3 -c "$PY_STATUS" 2>/dev/null
  if [ -f .gtkg/host/runs.json ]; then
    python3 -c "$PY_RUNS" 2>/dev/null
  else
    printf '  %sno run ledger yet%s\n' "$Y" "$Z"
  fi
  [ -d .gtkg/qk/knowledge ] && printf '  knowledge %s doc(s)\n' "$(find .gtkg/qk/knowledge -name '*.md' | wc -l | tr -d ' ')"
  if [ -d .gtkg/qk/bundles ]; then
    printf '  bundles\n'
    find .gtkg/qk/bundles -maxdepth 1 -mindepth 1 -type d | sort | tail -3 | sed 's/^/    /'
  fi
}

doc_text() {
  local f
  f="$(find .gtkg/qk/knowledge -name '*.md' 2>/dev/null | sort | tail -1)"
  if [ -z "$f" ]; then printf '%sno knowledge document in this workspace%s\n' "$Y" "$Z"; return 1; fi
  printf '%s%s%s\n' "$DIM" "$f" "$Z"
  cat "$f"
}

help_text() {
  cat <<'EOF'
  help                     this list
  status                   workspace, run ledger and finalized bundles
  doc                      print the newest accepted knowledge document
  profiles                 list the seven discovery profiles
  profile <name>           set the default v2 profile
  tools [profile]          list the tools in a discovery profile
  discover [profile]       full tool projection for a profile (JSON)
  op <id> [payload-json]   run a v1 operation   (34 of them)
  v2op <id> [payload-json] run a v2 operation   (46 of them)
  raw <id> [payload-json]  same but print the raw envelope
  ws <path>                switch workspace
  quit / exit              leave
EOF
}

printf '%s%s gtkg shell %s%s  binary %s\n' "$B" "$G" "$("$GTKG_BIN" --version | awk '{print $2}')" "$Z" "$GTKG_BIN"
printf '  workspace %s%s%s\n' "$DIM" "$WS" "$Z"
[ -f gtkg-run.json ] && python3 -c "$PY_CONFIG" 2>/dev/null
printf '  type %shelp%s for commands, %squit%s to exit\n\n' "$B" "$Z" "$B" "$Z"

PROTO="gtkg.protocol/v2"
PROFILE="core"

while true; do
  printf '%sgtkg:%s%s> ' "$G" "$(basename "$WS")" "$Z"
  IFS= read -r line || { printf '\n'; break; }
  [ -z "${line// }" ] && continue
  # `read` puts everything after the second word into payload, spaces included.
  # Slicing with ${rest#* } instead returns the operation id itself when there is
  # no payload, which then gets sent as the JSON body.
  cmd=""; arg1=""; payload=""
  read -r cmd arg1 payload <<< "$line"

  case "$cmd" in
    quit|exit|q) break ;;
    help|h|'?') help_text ;;
    status|st) status_text ;;
    doc|show) doc_text ;;
    profiles) printf '  core graph authoring lifecycle templates a2ui all\n' ;;
    profile)
      case "$arg1" in
        core|graph|authoring|lifecycle|templates|a2ui|all) PROFILE="$arg1"; printf 'profile = %s\n' "$PROFILE" ;;
        *) printf 'unknown profile %s (core graph authoring lifecycle templates a2ui all)\n' "${arg1:-<none>}" ;;
      esac ;;
    tools)
      p="${arg1:-$PROFILE}"
      out="$("$GTKG_BIN" v2-discover --profile "$p" 2>/dev/null)"
      if [ -z "$out" ]; then printf '%sdiscovery failed for profile %s%s\n' "$R" "$p" "$Z"
      else printf '%s\n' "$out" | python3 -c "$PY_PROFILE" 2>/dev/null || printf '%s\n' "$out"; fi ;;
    discover)
      p="${arg1:-$PROFILE}"
      "$GTKG_BIN" v2-discover --profile "$p" 2>/dev/null | python3 -c "$PY_PRETTY" 2>/dev/null ;;
    ws)
      if [ -n "$arg1" ] && [ -d "$arg1" ]; then WS="$(cd "$arg1" && pwd)"; cd "$WS" || true; printf 'workspace = %s\n' "$WS"
      else printf 'usage: ws <path>\n'; fi ;;
    op)
      [ -z "$arg1" ] && { printf 'usage: op <operation-id> [payload-json]\n'; continue; }
      PROTO="gtkg.protocol/v1"; send "$arg1" "$payload"; PROTO="gtkg.protocol/v2" ;;
    v2op)
      [ -z "$arg1" ] && { printf 'usage: v2op <operation-id> [payload-json]\n'; continue; }
      send "$arg1" "$payload" ;;
    raw)
      [ -z "$arg1" ] && { printf 'usage: raw <operation-id> [payload-json]\n'; continue; }
      p="$payload"; [ -z "${p// }" ] && p="{}"
      printf '{"protocol_version":"gtkg.protocol/v2","operation_id":"%s","request_id":"raw","payload":%s}\n' \
        "$arg1" "$p" | "$GTKG_BIN" v2-op "$arg1" --profile "$PROFILE" --request - --output json ;;
    *) printf '%sunknown command: %s%s  (try help)\n' "$R" "$cmd" "$Z" ;;
  esac
done
printf 'bye\n'
