#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
  echo "usage: $0 OUTPUT_DIRECTORY" >&2
  exit 64
fi
output_dir=$1
if [ -e "$output_dir" ]; then
  echo "refusing to overwrite existing output directory: $output_dir" >&2
  exit 73
fi
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)
mkdir -p "$output_dir"
build_log="$output_dir/build.log"
test_log="$output_dir/test.log"
v1_log="$output_dir/v1.log"
cd "$repo_root"
cargo build --locked -p gtkg-app --bin gtkg >"$build_log" 2>&1
binary="$repo_root/target/debug/gtkg"
[ -x "$binary" ] || { echo "missing rebuilt binary" >&2; exit 70; }
binary_sha="sha256:$(shasum -a 256 "$binary" | awk '{print $1}')"
GTKG_BIN="$binary" P06_BINARY_SHA256="$binary_sha" \
  cargo test --locked -p gtkg-testkit --test v03_p06_current_transport_successor_r5 \
  -- --nocapture --test-threads=1 >"$test_log" 2>&1
GTKG_BIN="$binary" \
  cargo test --locked -p gtkg-testkit --test v03_p06_transport_e2e_contract \
  p06_v1_34_registry_schema_and_default_mcp_surface_remain_frozen \
  -- --exact --nocapture --test-threads=1 >"$v1_log" 2>&1
jq -n \
  --arg binary_sha256 "$binary_sha" \
  --arg build_log_sha256 "$(shasum -a 256 "$build_log" | awk '{print $1}')" \
  --arg test_log_sha256 "$(shasum -a 256 "$test_log" | awk '{print $1}')" \
  --arg v1_log_sha256 "$(shasum -a 256 "$v1_log" | awk '{print $1}')" \
  '{schema_version:"gtkg.p06-current-transport-run/v2",binary_sha256:$binary_sha256,build_log_sha256:$build_log_sha256,test_log_sha256:$test_log_sha256,v1_log_sha256:$v1_log_sha256,claim_boundary:"local Development transport only"}' \
  >"$output_dir/receipt.json"
cat "$output_dir/receipt.json"
