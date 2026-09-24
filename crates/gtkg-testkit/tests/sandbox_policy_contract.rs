use gtkg_core::sandbox::{
    CleanProcessProvider, LogicalGuardProvider, MacOsSandboxExecProvider, SandboxProvider,
};
use gtkg_protocol::{AssuranceLevel, ResourceLimits, SandboxPolicyLock};

#[test]
fn provider_descriptions_are_exact_and_policy_roots_cannot_overlap() {
    assert_eq!(
        LogicalGuardProvider.describe().supported_levels,
        vec![AssuranceLevel::Sb0]
    );
    assert_eq!(
        CleanProcessProvider.describe().supported_levels,
        vec![AssuranceLevel::Sb1]
    );
    assert_eq!(
        MacOsSandboxExecProvider::new().describe().supported_levels,
        vec![AssuranceLevel::Sb2]
    );

    let policy = SandboxPolicyLock {
        schema_version: "gtkg.sandbox-policy/v1".to_owned(),
        policy_id: "overlap-must-fail".to_owned(),
        required_level: AssuranceLevel::Sb2,
        input_roots: vec!["/tmp/gtkg/input".into()],
        scratch_root: "/tmp/gtkg/input/scratch".into(),
        denied_read_paths: Vec::new(),
        allowed_programs: vec!["/bin/sh".to_owned()],
        allowed_environment: Vec::new(),
        deny_network: true,
        deny_target_execution: true,
        limits: ResourceLimits {
            timeout_millis: 1_000,
            max_output_bytes: 1_024,
            max_processes: 1,
        },
    };
    assert!(policy.validate().is_err());
}
