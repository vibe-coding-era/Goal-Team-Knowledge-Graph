#!/usr/bin/env bash
set -euo pipefail

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
cd "$repo_root"
mkdir -p "$output_dir"

source_files() {
  printf '%s\n' \
    Cargo.toml Cargo.lock \
    crates/gtkg-app/Cargo.toml \
    crates/gtkg-core/Cargo.toml \
    crates/gtkg-protocol/Cargo.toml \
    crates/gtkg-extract/Cargo.toml \
    crates/gtkg-testkit/Cargo.toml \
    crates/gtkg-testkit/tests/v03_p06_current_transport_successor_r6.rs \
    crates/gtkg-testkit/fixtures/v03_p06/transport-payloads.json \
    crates/gtkg-testkit/fixtures/v03_p06/transport-graph-payloads-current-r6.json \
    scripts/v03/run-p06-current-transport-r6.sh
  find crates/gtkg-app/src crates/gtkg-core/src crates/gtkg-protocol/src \
    crates/gtkg-extract/src crates/gtkg-testkit/src -type f -name '*.rs' -print
  find crates/gtkg-core/vendor/a2ui/v0_9_1 -type f -name '*.json' -print
}

make_source_manifest() {
  source_files | LC_ALL=C sort -u | while IFS= read -r path; do
    [ -f "$path" ] || { echo "missing source-scope input: $path" >&2; exit 70; }
    shasum -a 256 "$path"
  done
}

pre_manifest="$output_dir/source-manifest-pre.sha256"
post_build_manifest="$output_dir/source-manifest-post-build.sha256"
post_test_manifest="$output_dir/source-manifest-post-test.sha256"
make_source_manifest >"$pre_manifest"
source_manifest_sha256="sha256:$(shasum -a 256 "$pre_manifest" | awk '{print $1}')"

build_log="$output_dir/build.log"
compile_log="$output_dir/test-compile.log"
test_log="$output_dir/test.log"
cargo build --locked -p gtkg-app --bin gtkg >"$build_log" 2>&1
binary="$repo_root/target/debug/gtkg"
[ -x "$binary" ] || { echo "missing rebuilt binary" >&2; exit 70; }
binary_sha256="sha256:$(shasum -a 256 "$binary" | awk '{print $1}')"

make_source_manifest >"$post_build_manifest"
cmp -s "$pre_manifest" "$post_build_manifest" || {
  echo "source-scope drift during binary build" >&2
  diff -u "$pre_manifest" "$post_build_manifest" >&2 || true
  exit 70
}

cargo test --locked -p gtkg-testkit --test v03_p06_current_transport_successor_r6 \
  --no-run --message-format=json >"$compile_log" 2>&1
test_executable=$(grep '^{' "$compile_log" | jq -r 'select(.reason == "compiler-artifact" and .target.name == "v03_p06_current_transport_successor_r6") | .executable' | tail -n 1)
[ -n "$test_executable" ] && [ -x "$test_executable" ] || {
  echo "unable to locate r6 test executable" >&2
  exit 70
}
test_executable_sha256="sha256:$(shasum -a 256 "$test_executable" | awk '{print $1}')"
test_source_sha256="sha256:$(shasum -a 256 crates/gtkg-testkit/tests/v03_p06_current_transport_successor_r6.rs | awk '{print $1}')"
base_fixture_sha256="sha256:$(shasum -a 256 crates/gtkg-testkit/fixtures/v03_p06/transport-payloads.json | awk '{print $1}')"
graph_fixture_sha256="sha256:$(shasum -a 256 crates/gtkg-testkit/fixtures/v03_p06/transport-graph-payloads-current-r6.json | awk '{print $1}')"
harness_sha256="sha256:$(shasum -a 256 scripts/v03/run-p06-current-transport-r6.sh | awk '{print $1}')"

GTKG_BIN="$binary" \
P06_BINARY_SHA256="$binary_sha256" \
P06_TEST_EXECUTABLE="$test_executable" \
P06_TEST_EXECUTABLE_SHA256="$test_executable_sha256" \
P06_TEST_SOURCE_SHA256="$test_source_sha256" \
P06_BASE_FIXTURE_SHA256="$base_fixture_sha256" \
P06_GRAPH_FIXTURE_SHA256="$graph_fixture_sha256" \
P06_HARNESS_SHA256="$harness_sha256" \
P06_SOURCE_MANIFEST_PATH="$pre_manifest" \
P06_SOURCE_MANIFEST_SHA256="$source_manifest_sha256" \
  "$test_executable" --exact p06_r6_sha_bound_current_binary_full_transport_profile_and_v1_contract \
  --nocapture --test-threads=1 >"$test_log" 2>&1

make_source_manifest >"$post_test_manifest"
cmp -s "$pre_manifest" "$post_test_manifest" || {
  echo "source-scope drift during current-binary test" >&2
  diff -u "$pre_manifest" "$post_test_manifest" >&2 || true
  exit 70
}

jq -n \
  --arg baseline_commit "$(git rev-parse HEAD)" \
  --arg binary_sha256 "$binary_sha256" \
  --arg test_executable_sha256 "$test_executable_sha256" \
  --arg test_source_sha256 "$test_source_sha256" \
  --arg base_fixture_sha256 "$base_fixture_sha256" \
  --arg graph_fixture_sha256 "$graph_fixture_sha256" \
  --arg harness_sha256 "$harness_sha256" \
  --arg source_manifest_sha256 "$source_manifest_sha256" \
  --arg build_log_sha256 "sha256:$(shasum -a 256 "$build_log" | awk '{print $1}')" \
  --arg compile_log_sha256 "sha256:$(shasum -a 256 "$compile_log" | awk '{print $1}')" \
  --arg test_log_sha256 "sha256:$(shasum -a 256 "$test_log" | awk '{print $1}')" \
  --arg pre_manifest_sha256 "$source_manifest_sha256" \
  --arg post_build_manifest_sha256 "sha256:$(shasum -a 256 "$post_build_manifest" | awk '{print $1}')" \
  --arg post_test_manifest_sha256 "sha256:$(shasum -a 256 "$post_test_manifest" | awk '{print $1}')" \
  --arg output_dir "$output_dir" \
  '{
    schema_version:"gtkg.p06-current-transport-run/v3",
    phase:"development",
    baseline_commit:$baseline_commit,
    binary_sha256:$binary_sha256,
    test_executable_sha256:$test_executable_sha256,
    bindings:{test_source_sha256:$test_source_sha256,base_fixture_sha256:$base_fixture_sha256,graph_fixture_sha256:$graph_fixture_sha256,harness_sha256:$harness_sha256,source_manifest_sha256:$source_manifest_sha256},
    source_manifest_algorithm:"path-sorted UTF-8 lines <sha256><two spaces><repo_relative_path><newline>",
    raw_artifacts:{
      build:{path:($output_dir+"/build.log"),sha256:$build_log_sha256},
      test_compile:{path:($output_dir+"/test-compile.log"),sha256:$compile_log_sha256},
      test_run:{path:($output_dir+"/test.log"),sha256:$test_log_sha256},
      source_manifest_pre:{path:($output_dir+"/source-manifest-pre.sha256"),sha256:$pre_manifest_sha256},
      source_manifest_post_build:{path:($output_dir+"/source-manifest-post-build.sha256"),sha256:$post_build_manifest_sha256},
      source_manifest_post_test:{path:($output_dir+"/source-manifest-post-test.sha256"),sha256:$post_test_manifest_sha256}
    },
    source_scope_drift:false,
    claim_boundary:"local Development SHA-bound CLI/MCP transport/profile/v1 evidence only; Release, install, Current, Benchmark, external runtime and business remain not_run"
  }' >"$output_dir/receipt.json"

cat "$output_dir/receipt.json"
