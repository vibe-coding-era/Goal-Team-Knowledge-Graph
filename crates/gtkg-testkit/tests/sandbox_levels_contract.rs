use std::collections::BTreeMap;
use std::fs;

use gtkg_core::sandbox::{
    CleanProcessProvider, LogicalGuardProvider, SandboxCommand, SandboxProvider,
};
use gtkg_protocol::{AssuranceLevel, ErrorCode, ResourceLimits, SandboxPolicyLock};
use tempfile::tempdir;

#[test]
fn sb0_and_sb1_are_exact_and_never_satisfy_a_stronger_request() {
    let temp = tempdir().expect("tempdir");
    let input_root = temp.path().join("input");
    let scratch = temp.path().join("scratch");
    fs::create_dir_all(&input_root).expect("input");
    fs::create_dir_all(&scratch).expect("scratch");
    let input = input_root.join("data.md");
    fs::write(&input, "literal data\nsecond line").expect("fixture");

    let sb0 = policy(AssuranceLevel::Sb0, &input_root, &scratch);
    let logical = LogicalGuardProvider;
    let sb0_probe = logical.probe(&sb0).expect("SB0 probe");
    assert_eq!(sb0_probe.verified_level, Some(AssuranceLevel::Sb0));
    let sb0_output = scratch.join("sb0.txt");
    let receipt = logical
        .execute(&sb0, &sb0_probe, &reader(&input, &sb0_output))
        .expect("SB0 guarded read");
    assert_eq!(receipt.assurance_level, AssuranceLevel::Sb0);
    assert_eq!(
        fs::read_to_string(sb0_output).expect("SB0 output"),
        "literal data"
    );

    let sb1_required = policy(AssuranceLevel::Sb1, &input_root, &scratch);
    let insufficient = logical
        .probe(&sb1_required)
        .expect("SB0 reports insufficiency as evidence");
    assert!(!insufficient.passed);
    let error = logical
        .execute(
            &sb1_required,
            &insufficient,
            &reader(&input, &scratch.join("must-not-write.txt")),
        )
        .expect_err("SB0 must not downgrade an SB1 request");
    assert_eq!(error.code, ErrorCode::SandboxAssuranceUnavailable);
    assert!(!scratch.join("must-not-write.txt").exists());

    let process = CleanProcessProvider;
    let sb1_probe = process.probe(&sb1_required).expect("SB1 process probe");
    assert_eq!(sb1_probe.verified_level, Some(AssuranceLevel::Sb1));
    let sb1_output = scratch.join("sb1.txt");
    let receipt = process
        .execute(&sb1_required, &sb1_probe, &reader(&input, &sb1_output))
        .expect("SB1 process read");
    assert_eq!(receipt.assurance_level, AssuranceLevel::Sb1);
    assert_eq!(receipt.target_execution_count, 0);

    let sb2_required = policy(AssuranceLevel::Sb2, &input_root, &scratch);
    let insufficient = process
        .probe(&sb2_required)
        .expect("SB1 reports insufficiency as evidence");
    assert!(!insufficient.passed);
    assert_eq!(insufficient.verified_level, None);
}

fn policy(
    level: AssuranceLevel,
    input: &std::path::Path,
    scratch: &std::path::Path,
) -> SandboxPolicyLock {
    SandboxPolicyLock {
        schema_version: "gtkg.sandbox-policy/v1".to_owned(),
        policy_id: format!("exact-{level:?}").to_ascii_lowercase(),
        required_level: level,
        input_roots: vec![input.to_path_buf()],
        scratch_root: scratch.to_path_buf(),
        denied_read_paths: Vec::new(),
        allowed_programs: vec!["/bin/sh".to_owned()],
        allowed_environment: Vec::new(),
        deny_network: true,
        deny_target_execution: true,
        limits: ResourceLimits {
            timeout_millis: 2_000,
            max_output_bytes: 16 * 1024,
            max_processes: 1,
        },
    }
}

fn reader(input: &std::path::Path, output: &std::path::Path) -> SandboxCommand {
    SandboxCommand {
        program: "/bin/sh".to_owned(),
        arguments: vec![
            "-c".to_owned(),
            "IFS= read -r first < \"$1\"; printf '%s' \"$first\" > \"$2\"".to_owned(),
            "gtkg-static-reader".to_owned(),
            input.to_string_lossy().into_owned(),
            output.to_string_lossy().into_owned(),
        ],
        environment: BTreeMap::new(),
    }
}
