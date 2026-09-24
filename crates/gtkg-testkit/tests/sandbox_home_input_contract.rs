#![cfg(target_os = "macos")]

use std::collections::BTreeMap;
use std::fs;

use gtkg_core::sandbox::{MacOsSandboxExecProvider, SandboxCommand, SandboxProvider};
use gtkg_protocol::{AssuranceLevel, ResourceLimits, SandboxPolicyLock};
use tempfile::tempdir_in;

#[test]
fn sb2_reopens_only_the_locked_input_root_inside_home() {
    // Rev 18 G05 trusted plumbing delta: the fixture previously lived under the
    // workspace `target/` directory, which silently assumed workspace ⊆ $HOME and
    // failed for any out-of-HOME checkout (e.g. Release staging). The fixture now
    // lives directly under canonical $HOME so the HOME-contained scenario holds
    // for every workspace location. All SB2 security oracles are unchanged.
    let home =
        fs::canonicalize(std::env::var_os("HOME").expect("HOME is set")).expect("canonical HOME");

    let input_temp = tempdir_in(&home).expect("HOME-contained input root");
    let scratch_temp = tempdir_in(&home).expect("independent scratch root");
    let input_root = fs::canonicalize(input_temp.path()).expect("canonical input root");
    let scratch = fs::canonicalize(scratch_temp.path()).expect("canonical scratch root");
    assert!(
        input_root.starts_with(&home),
        "fixture must exercise a HOME-contained input"
    );

    let input = input_root.join("data.md");
    let output = scratch.join("observed.txt");
    fs::write(&input, "literal home data\nsecond line").expect("input fixture");

    let policy = SandboxPolicyLock {
        schema_version: "gtkg.sandbox-policy/v1".to_owned(),
        policy_id: "home-contained-input".to_owned(),
        required_level: AssuranceLevel::Sb2,
        input_roots: vec![input_root],
        scratch_root: scratch,
        denied_read_paths: Vec::new(),
        allowed_programs: vec!["/bin/sh".to_owned()],
        allowed_environment: Vec::new(),
        deny_network: true,
        deny_target_execution: true,
        limits: ResourceLimits {
            timeout_millis: 5_000,
            max_output_bytes: 64 * 1024,
            max_processes: 1,
        },
    };
    let provider = MacOsSandboxExecProvider::new();
    let probe = provider.probe(&policy).expect("policy-bound SB2 probe");
    assert!(probe.passed, "probe findings: {probe:#?}");

    let receipt = provider
        .execute(
            &policy,
            &probe,
            &SandboxCommand {
                program: "/bin/sh".to_owned(),
                arguments: vec![
                    "-c".to_owned(),
                    "IFS= read -r first < \"$1\"; printf '%s' \"$first\" > \"$2\"".to_owned(),
                    "gtkg-static-reader".to_owned(),
                    input.to_string_lossy().into_owned(),
                    output.to_string_lossy().into_owned(),
                ],
                environment: BTreeMap::new(),
            },
        )
        .expect("SB2 execution receipt");

    assert!(receipt.success, "sandbox receipt: {receipt:#?}");
    assert_eq!(
        fs::read_to_string(output).expect("scratch output"),
        "literal home data"
    );
}
