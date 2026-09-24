#!/usr/bin/env bash
# Install the gtkg binary into a user-local prefix and verify its identity.
#
# GTKG ships no packaged installer and no release channel: git.publish,
# current.activate and template.publish are all denied_by_policy in the current
# build. This script therefore does the plain Unix thing - build, copy, verify -
# and refuses to claim anything it did not check.
set -euo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PREFIX="${GTKG_PREFIX:-$HOME/.local}"
BIN_DIR="$PREFIX/bin"
MANIFEST_DIR="$PREFIX/share/gtkg"

say() { printf '%s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

command -v cargo >/dev/null || die "cargo is required (rust 1.96+)"
cd "$SRC"

say "==> building release binary (locked, offline)"
cargo build --release --locked --offline -p gtkg-app --bin gtkg

say "==> installing to $BIN_DIR/gtkg"
mkdir -p "$BIN_DIR" "$MANIFEST_DIR"
install -m 0755 target/release/gtkg "$BIN_DIR/gtkg"

say "==> verifying identity"
VERSION="$("$BIN_DIR/gtkg" --version)"
DISCOVERY="$("$BIN_DIR/gtkg" op system.describe --request - --output json <<'JSON'
{"protocol_version":"gtkg.protocol/v1","operation_id":"system.describe","request_id":"install-verify","locks":{},"payload":{}}
JSON
)"
python3 - "$VERSION" "$DISCOVERY" <<'PY'
import json, sys
version, raw = sys.argv[1], sys.argv[2]
d = json.loads(raw)
if d.get("status") != "completed":
    raise SystemExit(f"system.describe did not complete: {d.get('status')}")
r = d["result"]
assert r["public_operation_count"] == 34, r["public_operation_count"]
assert r["storage_model"] == "okf-and-ordinary-files", r["storage_model"]
print(f"    {version}")
print(f"    protocol   {r['protocol_version']}")
print(f"    operations {r['implemented_operation_count']}/{r['public_operation_count']} implemented")
print(f"    storage    {r['storage_model']} (database_backend={r['database_backend']})")
print(f"    binary     {r['identity']['binary_sha256']}")
print(f"    core       {r['identity']['core_sha256']}")
PY

say "==> writing install manifest"
python3 - "$BIN_DIR/gtkg" "$MANIFEST_DIR/install-manifest.json" "$SRC" <<'PY'
import hashlib, json, pathlib, sys, datetime
binary, out, src = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]), sys.argv[3]
data = binary.read_bytes()
json.dump({
    "schema_version": "gtkg.local-install-manifest/v1",
    "installed_at_utc": datetime.datetime.now(datetime.UTC).isoformat(),
    "source_checkout": src,
    "binary_path": str(binary),
    "binary_sha256": "sha256:" + hashlib.sha256(data).hexdigest(),
    "binary_size_bytes": len(data),
    "install_scope": "user_local",
    "non_claims": {
        "release_published": False,
        "system_installed": False,
        "current_activated": False,
        "reproducible_build_verified": False,
    },
}, open(out, "w"), indent=2)
print(f"    {out}")
PY

case ":$PATH:" in
  *":$BIN_DIR:"*) say "==> $BIN_DIR is already on PATH" ;;
  *) say "==> add $BIN_DIR to PATH:  export PATH=\"$BIN_DIR:\$PATH\"" ;;
esac
say "done."
