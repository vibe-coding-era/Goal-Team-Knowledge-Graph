#!/bin/zsh
# B01 local-only preflight.  It never checks out, installs, or invokes a competitor.
set -euo pipefail

b01_script_dir=${0:A:h}
b01_repo_root=${b01_script_dir:h:h}
b01_receipt=${1:-"$b01_repo_root/deliverables/v03-benchmark/receipts/b01-environment-preflight-r1.json"}
b01_log_dir=${b01_receipt:r}
b01_policy="$b01_script_dir/b01-offline-deny.sb"
b01_plan="$b01_repo_root/deliverables/v03-benchmark/benchmark-plan-v3.json"
b01_pins="$b01_repo_root/deliverables/v03-benchmark/pins.json"
b01_binary="$b01_repo_root/target/debug/gtkg"

if [[ -e "$b01_receipt" || -e "$b01_log_dir" ]]; then
  print -u2 -- "refusing to overwrite B01 evidence: $b01_receipt"
  exit 64
fi

mkdir -p "$b01_log_dir"
(
  cd "$b01_repo_root"
  cargo build --locked --offline -p gtkg-app --bin gtkg
) >"$b01_log_dir/build.log" 2>&1

if [[ ! -x "$b01_binary" ]]; then
  print -u2 -- "current GTKG binary was not produced: $b01_binary"
  exit 65
fi

b01_isolated_root=$(mktemp -d /private/tmp/gtkg-b01-environment.XXXXXX)
b01_home_dir="$b01_isolated_root/home"
b01_cache_dir="$b01_isolated_root/cache"
b01_tmp_dir="$b01_isolated_root/tmp"
b01_bin_dir="$b01_isolated_root/bin"
mkdir -p "$b01_home_dir" "$b01_cache_dir" "$b01_tmp_dir" "$b01_bin_dir"
chmod 700 "$b01_isolated_root" "$b01_home_dir" "$b01_cache_dir" "$b01_tmp_dir" "$b01_bin_dir"
cp "$b01_binary" "$b01_bin_dir/gtkg"
chmod 700 "$b01_bin_dir/gtkg"

set +e
env -i \
  PATH="/usr/bin:/bin" \
  HOME="$b01_home_dir" \
  TMPDIR="$b01_tmp_dir" \
  XDG_CACHE_HOME="$b01_cache_dir" \
  OTEL_SDK_DISABLED=true \
  GTKG_B01_TELEMETRY_POLICY=network_denied_not_readback \
  /usr/bin/sandbox-exec -f "$b01_policy" "$b01_bin_dir/gtkg" --help \
  >"$b01_log_dir/gtkg-help.stdout.log" \
  2>"$b01_log_dir/gtkg-help.stderr.log"
b01_gtkg_exit=$?
set -e

b01_sha() {
  shasum -a 256 "$1" | awk '{print $1}'
}

b01_git_head=$(git -C "$b01_repo_root" rev-parse HEAD)
b01_git_tree=$(git -C "$b01_repo_root" rev-parse HEAD^{tree})
b01_status_sha=$(git -C "$b01_repo_root" status --porcelain=v1 | shasum -a 256 | awk '{print $1}')
b01_codegraph_commit=$(jq -r '.competitors[] | select(.system_id == "codegraph-v0.20.1") | .commit' "$b01_pins")
b01_graphify_commit=$(jq -r '.competitors[] | select(.system_id == "graphify-v0.9.52") | .commit' "$b01_pins")

jq -n \
  --arg receipt_id "v03-b01-environment-preflight-red-r1" \
  --arg captured_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg git_head "$b01_git_head" \
  --arg git_tree "$b01_git_tree" \
  --arg status_sha256 "sha256:$b01_status_sha" \
  --arg binary_sha256 "sha256:$(b01_sha "$b01_binary")" \
  --arg policy_sha256 "sha256:$(b01_sha "$b01_policy")" \
  --arg plan_sha256 "sha256:$(b01_sha "$b01_plan")" \
  --arg pins_sha256 "sha256:$(b01_sha "$b01_pins")" \
  --arg build_log_sha256 "sha256:$(b01_sha "$b01_log_dir/build.log")" \
  --arg help_stdout_sha256 "sha256:$(b01_sha "$b01_log_dir/gtkg-help.stdout.log")" \
  --arg help_stderr_sha256 "sha256:$(b01_sha "$b01_log_dir/gtkg-help.stderr.log")" \
  --arg codegraph_commit "$b01_codegraph_commit" \
  --arg graphify_commit "$b01_graphify_commit" \
  --argjson gtkg_exit "$b01_gtkg_exit" \
  '{
    schema_version: "gtkg.benchmark-environment-preflight/v1",
    receipt_id: $receipt_id,
    task_id: "B01",
    run_role: "red",
    state: "blocked_external_competitor_artifacts",
    captured_at: $captured_at,
    scope: {
      mode: "local_preflight_only",
      prohibited_actions: [
        "external_checkout",
        "remote_read_or_write",
        "competitor_package_install",
        "competitor_process_invocation",
        "synthetic_competitor_or_mock"
      ]
    },
    bindings: {
      benchmark_plan: {path: "deliverables/v03-benchmark/benchmark-plan-v3.json", sha256: $plan_sha256},
      competitor_pins: {path: "deliverables/v03-benchmark/pins.json", sha256: $pins_sha256}
    },
    systems: [
      {
        system_id: "gtkg-v0.3-development",
        source_identity: {git_head: $git_head, git_tree: $git_tree, working_tree_status_sha256: $status_sha256},
        binary_sha256: $binary_sha256,
        package_install_state: "not_available_no_cli_package_install_surface",
        isolated_environment_state: "observed_os_sandboxed_candidate",
        retained_isolated_root: "private_tmp_owner_only_for_receipt_readback",
        process: {
          argv: ["sandbox-exec", "-f", "scripts/v03/b01-offline-deny.sb", "gtkg", "--help"],
          exit_code: $gtkg_exit,
          stdout_sha256: $help_stdout_sha256,
          stderr_sha256: $help_stderr_sha256
        },
        offline_lock: {
          mechanism: "macOS sandbox-exec",
          policy_path: "scripts/v03/b01-offline-deny.sb",
          policy_sha256: $policy_sha256,
          policy_load_state: (if $gtkg_exit == 0 then "passed" else "failed" end),
          network_probe_state: "not_run_no_synthetic_endpoint_in_scope",
          claim_boundary: "the sandbox profile denies network* for the observed GTKG help process; no telemetry endpoint or egress-attempt trace was introduced"
        },
        telemetry: {
          environment_policy: "OTEL_SDK_DISABLED=true plus OS network deny",
          state: "not_readback",
          claim_boundary: "the candidate process was not instrumented with a telemetry receiver and the environment variable is not a product telemetry readback"
        },
        build: {argv: ["cargo", "build", "--locked", "--offline", "-p", "gtkg-app", "--bin", "gtkg"], log_sha256: $build_log_sha256}
      },
      {
        system_id: "codegraph-v0.20.1",
        source_commit: $codegraph_commit,
        exact_artifact_state: "blocked_missing_exact_artifact",
        package_install_state: "not_run_prohibited_by_b01_scope",
        process_state: "not_run",
        telemetry_readback_state: "not_run",
        blocker: "B00 pins.json records only a source pin and export_state=not_available; no authorized local exact package/export/runtime artifact path exists in the frozen benchmark inputs"
      },
      {
        system_id: "graphify-v0.9.52",
        source_commit: $graphify_commit,
        exact_artifact_state: "blocked_missing_exact_artifact",
        package_install_state: "not_run_prohibited_by_b01_scope",
        process_state: "not_run",
        telemetry_readback_state: "not_run",
        blocker: "B00 pins.json records only a source pin and export_state=not_available; no authorized local exact package/export/runtime artifact path exists in the frozen benchmark inputs"
      }
    ],
    first_failure: {
      failure_class: "missing_authorized_external_runtime_artifacts",
      evidence: "both competitor pin records declare export_state=not_available; B01 scope prohibits obtaining or substituting artifacts"
    },
    downstream_closure: {
      direct: ["B02", "B03", "B04"],
      transitive: ["B05", "B06", "I02", "I03", "I04"],
      independent_existing_blockers: ["B00-MODEL", "B00-GRADER", "B00-RUNNER"]
    },
    non_claims: [
      "GTKG local candidate observation is not a formal installation, Release, Current activation, or benchmark result.",
      "CodeGraph and Graphify were not checked out, installed, invoked, or replaced with fixtures.",
      "The offline profile is an observed macOS sandbox policy for one GTKG help process; telemetry readback and all-system runtime equivalence remain unavailable."
    ]
  }' >"$b01_receipt"

print -- "$b01_receipt"
exit 0
