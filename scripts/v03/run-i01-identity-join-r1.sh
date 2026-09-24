#!/usr/bin/env bash
# Re-run the I01 local, read-only identity lifecycle contract under a fresh
# private output directory. This never activates Current or performs a system
# installation; the test's U01 fixture uses an isolated temporary capability.
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
  /private/tmp/gtkg-i01-* | /tmp/gtkg-i01-*) ;;
  *)
    echo "refusing non-isolated I01 output directory: $output_dir" >&2
    exit 73
    ;;
esac

mkdir -m 700 "$output_dir"
test_log="$output_dir/i01-test.log"
(
  cd "$repo_root"
  cargo test --locked -p gtkg-testkit --test v03_i01_identity_join_contract \
    -- --nocapture --test-threads=1
) >"$test_log" 2>&1

test_source="$repo_root/crates/gtkg-testkit/tests/v03_i01_identity_join_contract.rs"
module_source="$repo_root/crates/gtkg-core/src/v03/identity_lifecycle.rs"
lifecycle_source="$repo_root/crates/gtkg-core/src/v03/lifecycle.rs"
module_root="$repo_root/crates/gtkg-core/src/v03.rs"
test_source_sha256="sha256:$(shasum -a 256 "$test_source" | awk '{print $1}')"
module_source_sha256="sha256:$(shasum -a 256 "$module_source" | awk '{print $1}')"
lifecycle_source_sha256="sha256:$(shasum -a 256 "$lifecycle_source" | awk '{print $1}')"
module_root_sha256="sha256:$(shasum -a 256 "$module_root" | awk '{print $1}')"
test_log_sha256="sha256:$(shasum -a 256 "$test_log" | awk '{print $1}')"

jq -n \
  --arg test_source_sha256 "$test_source_sha256" \
  --arg module_source_sha256 "$module_source_sha256" \
  --arg lifecycle_source_sha256 "$lifecycle_source_sha256" \
  --arg module_root_sha256 "$module_root_sha256" \
  --arg test_log_sha256 "$test_log_sha256" \
  '{schema_version:"gtkg.i01-identity-join-run/v1",state:"passed",scope:"local_development_read_only",test:{target:"v03_i01_identity_join_contract",test_source_sha256:$test_source_sha256,log_sha256:$test_log_sha256},sources:{identity_lifecycle_sha256:$module_source_sha256,lifecycle_sha256:$lifecycle_source_sha256,v03_module_sha256:$module_root_sha256},side_effects:{current_activation:false,current_write_count:0,canonical_write_count:0,replay_write_count:0,system_install:false,release:false,network:false,database:false,target_project_execution:false}}' \
  >"$output_dir/i01-identity-join-run.json"
cat "$output_dir/i01-identity-join-run.json"
