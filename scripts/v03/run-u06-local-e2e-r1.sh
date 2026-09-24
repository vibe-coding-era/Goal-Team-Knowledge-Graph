#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "usage: $0 OUTPUT_DIRECTORY" >&2
  exit 64
fi

output_dir=$1
repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
if [[ "$output_dir" != /* ]]; then
  output_dir="$repo_root/$output_dir"
fi
if [ -e "$output_dir" ]; then
  echo "refusing to overwrite existing output directory: $output_dir" >&2
  exit 73
fi

mkdir -m 700 "$output_dir"
build_log="$output_dir/cargo-build.log"
test_log="$output_dir/u06-test.log"
(
  cd "$repo_root"
  cargo build --locked --offline -p gtkg-app --bin gtkg
) >"$build_log" 2>&1

binary="$repo_root/target/debug/gtkg"
if [ ! -x "$binary" ]; then
  echo "expected current local binary is absent or not executable: $binary" >&2
  exit 2
fi
binary_sha256="sha256:$(shasum -a 256 "$binary" | awk '{print $1}')"
test_source="$repo_root/crates/gtkg-testkit/tests/v03_u06_local_e2e_successor_r2.rs"
test_source_sha256="sha256:$(shasum -a 256 "$test_source" | awk '{print $1}')"

(
  cd "$repo_root"
  U06_SOURCE_BINARY="$binary" \
  U06_SOURCE_BINARY_SHA256="$binary_sha256" \
  U06_TEST_SOURCE_R2_SHA256="$test_source_sha256" \
  TMPDIR="/private/tmp" \
  cargo test --locked -p gtkg-testkit --test v03_u06_local_e2e_successor_r2 -- --nocapture
) >"$test_log" 2>&1

build_log_sha256="sha256:$(shasum -a 256 "$build_log" | awk '{print $1}')"
test_log_sha256="sha256:$(shasum -a 256 "$test_log" | awk '{print $1}')"
jq -n \
  --arg binary "$binary" \
  --arg binary_sha256 "$binary_sha256" \
  --arg test_source_sha256 "$test_source_sha256" \
  --arg build_log_sha256 "$build_log_sha256" \
  --arg test_log_sha256 "$test_log_sha256" \
  '{schema_version:"gtkg.u06-local-e2e-run/v2",state:"passed",build:{argv:["cargo","build","--locked","--offline","-p","gtkg-app","--bin","gtkg"],binary:$binary,binary_sha256:$binary_sha256,log_sha256:$build_log_sha256},test:{target:"v03_u06_local_e2e_successor_r2",test_source_sha256:$test_source_sha256,log_sha256:$test_log_sha256},scope:{system_install:false,current_activation:false,release:false,target_project_execution:false,database:false,network:"Q04 query counters zero; page-level browser observation is recorded separately"}}' \
  >"$output_dir/u06-local-e2e-run.json"
cat "$output_dir/u06-local-e2e-run.json"
