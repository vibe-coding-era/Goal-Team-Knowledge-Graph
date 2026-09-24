#!/usr/bin/env bash
# Freeze I01 r2 only after its source-bound readback and the current local U06
# installed-binary E2E both pass. All output stays below one private temp root.
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
case "$output_dir" in
  /private/tmp/gtkg-i01-r2-* | /tmp/gtkg-i01-r2-*) ;;
  *)
    echo "refusing non-isolated I01 r2 output directory: $output_dir" >&2
    exit 73
    ;;
esac

mkdir -m 700 "$output_dir"
build_log="$output_dir/cargo-build.log"
test_log="$output_dir/i01-r2-test.log"
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
(
  cd "$repo_root"
  I01_SOURCE_BINARY="$binary" \
  I01_SOURCE_BINARY_SHA256="$binary_sha256" \
  cargo test --locked -p gtkg-testkit --test v03_i01_identity_join_successor_r2 \
    -- --nocapture --test-threads=1
) >"$test_log" 2>&1

"$repo_root/scripts/v03/run-u06-local-e2e-r1.sh" "$output_dir/u06-current-binary"
u06_receipt="$output_dir/u06-current-binary/u06-local-e2e-run.json"
u06_binary_sha256=$(jq -er '.build.binary_sha256' "$u06_receipt")
if [ "$u06_binary_sha256" != "$binary_sha256" ]; then
  echo "I01 current binary does not match the U06 local E2E binary readback" >&2
  exit 70
fi

test_source="$repo_root/crates/gtkg-testkit/tests/v03_i01_identity_join_successor_r2.rs"
identity_source="$repo_root/crates/gtkg-core/src/v03/identity_lifecycle.rs"
installer_source="$repo_root/crates/gtkg-core/src/v03/installer.rs"
lifecycle_source="$repo_root/crates/gtkg-core/src/v03/lifecycle.rs"
test_source_sha256="sha256:$(shasum -a 256 "$test_source" | awk '{print $1}')"
identity_source_sha256="sha256:$(shasum -a 256 "$identity_source" | awk '{print $1}')"
installer_source_sha256="sha256:$(shasum -a 256 "$installer_source" | awk '{print $1}')"
lifecycle_source_sha256="sha256:$(shasum -a 256 "$lifecycle_source" | awk '{print $1}')"
build_log_sha256="sha256:$(shasum -a 256 "$build_log" | awk '{print $1}')"
test_log_sha256="sha256:$(shasum -a 256 "$test_log" | awk '{print $1}')"
u06_receipt_sha256="sha256:$(shasum -a 256 "$u06_receipt" | awk '{print $1}')"

jq -n \
  --arg binary_sha256 "$binary_sha256" \
  --arg test_source_sha256 "$test_source_sha256" \
  --arg identity_source_sha256 "$identity_source_sha256" \
  --arg installer_source_sha256 "$installer_source_sha256" \
  --arg lifecycle_source_sha256 "$lifecycle_source_sha256" \
  --arg build_log_sha256 "$build_log_sha256" \
  --arg test_log_sha256 "$test_log_sha256" \
  --arg u06_receipt_sha256 "$u06_receipt_sha256" \
  --arg u06_binary_sha256 "$u06_binary_sha256" \
  '{schema_version:"gtkg.i01-identity-join-run/v2",state:"passed",scope:"local_development_read_only",binary_sha256:$binary_sha256,test:{target:"v03_i01_identity_join_successor_r2",test_source_sha256:$test_source_sha256,log_sha256:$test_log_sha256},sources:{identity_lifecycle_sha256:$identity_source_sha256,installer_sha256:$installer_source_sha256,lifecycle_sha256:$lifecycle_source_sha256},build_log_sha256:$build_log_sha256,u06_current_binary_receipt_sha256:$u06_receipt_sha256,u06_current_binary_sha256:$u06_binary_sha256,u06_current_binary_matches_i01:true,side_effects:{current_activation:false,current_write_count:0,canonical_write_count:0,replay_write_count:0,system_install:false,release:false,network:false,database:false,target_project_execution:false}}' \
  >"$output_dir/i01-identity-join-run.json"
cat "$output_dir/i01-identity-join-run.json"
