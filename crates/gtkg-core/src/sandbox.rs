//! Explicit sandbox assurance providers.
//!
//! `sandbox-exec` being present is only a capability hint. The macOS provider
//! reports SB2 only after a policy-bound malicious probe passes on the current
//! host, and execution requires that exact probe result.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use gtkg_protocol::{
    AssuranceLevel, ErrorCode, ResourceLimits, SandboxPolicyLock, SandboxProbeResult,
    SandboxProbeState, SandboxProviderDescription, SandboxReceipt, canonical_json_sha256,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use walkdir::WalkDir;

use crate::file_model::sha256_file;

const PROVIDER_ID: &str = "macos-sandbox-exec:v1";
const SB0_PROVIDER_ID: &str = "logical-guard:v1";
const SB1_PROVIDER_ID: &str = "clean-process:v1";
const STATIC_READER_SCRIPT: &str = "IFS= read -r first < \"$1\"; printf '%s' \"$first\" > \"$2\"";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxCommand {
    pub program: String,
    pub arguments: Vec<String>,
    #[serde(default)]
    pub environment: BTreeMap<String, String>,
}

#[derive(Debug)]
pub struct SandboxFailure {
    pub code: ErrorCode,
    pub stage: &'static str,
    pub message: String,
    pub recovery_hint: &'static str,
}

impl SandboxFailure {
    fn unavailable(message: impl Into<String>) -> Self {
        Self {
            code: ErrorCode::SandboxAssuranceUnavailable,
            stage: "sandbox-assurance",
            message: message.into(),
            recovery_hint: "select a provider with a current passing probe at the exact required assurance",
        }
    }

    fn invalid(message: impl Into<String>) -> Self {
        Self {
            code: ErrorCode::InvalidRequest,
            stage: "sandbox-policy",
            message: message.into(),
            recovery_hint: "repair the exact sandbox policy or deterministic command contract",
        }
    }

    fn io(stage: &'static str, path: &Path, error: impl std::fmt::Display) -> Self {
        Self {
            code: ErrorCode::Io,
            stage,
            message: format!("{}: {error}", path.display()),
            recovery_hint: "verify the explicit provider, input, and scratch paths",
        }
    }
}

pub trait SandboxProvider {
    fn describe(&self) -> SandboxProviderDescription;

    fn probe(&self, policy: &SandboxPolicyLock) -> Result<SandboxProbeResult, SandboxFailure>;

    fn execute(
        &self,
        policy: &SandboxPolicyLock,
        probe: &SandboxProbeResult,
        command: &SandboxCommand,
    ) -> Result<SandboxReceipt, SandboxFailure>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct MacOsSandboxExecProvider;

impl MacOsSandboxExecProvider {
    pub fn new() -> Self {
        Self
    }
}

impl SandboxProvider for MacOsSandboxExecProvider {
    fn describe(&self) -> SandboxProviderDescription {
        SandboxProviderDescription {
            provider_id: PROVIDER_ID.to_owned(),
            supported_levels: vec![AssuranceLevel::Sb2],
            probe_state: SandboxProbeState::NotRun,
            verified_level: None,
        }
    }

    fn probe(&self, policy: &SandboxPolicyLock) -> Result<SandboxProbeResult, SandboxFailure> {
        validate_policy(policy)?;
        require_macos_sandbox_exec()?;
        if policy.required_level != AssuranceLevel::Sb2 {
            return Err(SandboxFailure::invalid(
                "macOS SB2 probe requires required_level=SB2",
            ));
        }
        let policy_sha256 = policy
            .digest()
            .map_err(|error| SandboxFailure::invalid(error.to_string()))?;
        let scratch = canonical_directory(&policy.scratch_root, "sandbox.probe")?;
        let probe_root = scratch.join(format!(
            ".gtkg-sb2-probe-{}-{}",
            &policy_sha256[7..19],
            std::process::id()
        ));
        if probe_root.exists() {
            return Err(SandboxFailure::unavailable(format!(
                "probe scratch already exists: {}",
                probe_root.display()
            )));
        }
        let probe_input = probe_root.join("input");
        let probe_scratch = probe_root.join("scratch");
        let probe_outside = probe_root.join("outside");
        let probe_credential = probe_root.join("credential-root");
        for directory in [
            &probe_input,
            &probe_scratch,
            &probe_outside,
            &probe_credential,
        ] {
            fs::create_dir_all(directory)
                .map_err(|error| SandboxFailure::io("sandbox.probe", directory, error))?;
        }
        let input = probe_input.join("input.txt");
        let credential = probe_credential.join("credential.txt");
        fs::write(&input, b"literal target data\n")
            .map_err(|error| SandboxFailure::io("sandbox.probe", &input, error))?;
        fs::write(&credential, b"controlled credential\n")
            .map_err(|error| SandboxFailure::io("sandbox.probe", &credential, error))?;
        let canonical_probe_input = canonical_directory(&probe_input, "sandbox.probe")?;
        let canonical_probe_scratch = canonical_directory(&probe_scratch, "sandbox.probe")?;
        let canonical_credential = canonical_directory(&probe_credential, "sandbox.probe")?;
        let profile = sb2_profile(
            &canonical_probe_scratch,
            &[canonical_credential],
            &[canonical_probe_input],
            true,
        )?;

        let mut assertions = BTreeMap::new();
        let mut findings = Vec::new();
        let positive_output = probe_scratch.join("positive.txt");
        let positive = run_sandbox_exec(
            &profile,
            &SandboxCommand {
                program: "/bin/sh".to_owned(),
                arguments: vec![
                    "-c".to_owned(),
                    STATIC_READER_SCRIPT.to_owned(),
                    "gtkg-static-reader".to_owned(),
                    input.to_string_lossy().into_owned(),
                    positive_output.to_string_lossy().into_owned(),
                ],
                environment: BTreeMap::new(),
            },
            &[],
            &policy.limits,
        )?;
        let positive_text = fs::read_to_string(&positive_output).unwrap_or_default();
        assertions.insert(
            "read_input".to_owned(),
            positive.succeeded() && positive_text == "literal target data",
        );
        assertions.insert(
            "write_scratch".to_owned(),
            positive.succeeded() && positive_output.is_file(),
        );

        let original =
            fs::read(&input).map_err(|error| SandboxFailure::io("sandbox.probe", &input, error))?;
        let input_write = run_sandbox_exec(
            &profile,
            &shell_probe("printf hacked > \"$1\"", &input),
            &[],
            &policy.limits,
        )?;
        let observed =
            fs::read(&input).map_err(|error| SandboxFailure::io("sandbox.probe", &input, error))?;
        assertions.insert(
            "deny_input_write".to_owned(),
            !input_write.succeeded() && observed == original,
        );

        let outside_target = probe_outside.join("must-not-exist");
        let outside_write = run_sandbox_exec(
            &profile,
            &shell_probe("printf escaped > \"$1\"", &outside_target),
            &[],
            &policy.limits,
        )?;
        assertions.insert(
            "deny_outside_write".to_owned(),
            !outside_write.succeeded() && !outside_target.exists(),
        );

        let credential_read = run_sandbox_exec(
            &profile,
            &shell_probe("IFS= read -r secret < \"$1\"", &credential),
            &[],
            &policy.limits,
        )?;
        assertions.insert(
            "deny_credential_read".to_owned(),
            !credential_read.succeeded()
                && !String::from_utf8_lossy(&credential_read.stdout)
                    .contains("controlled credential"),
        );

        let environment = run_sandbox_exec(
            &profile,
            &SandboxCommand {
                program: "/bin/sh".to_owned(),
                arguments: vec![
                    "-c".to_owned(),
                    "test -z \"${GTKG_PROBE_SECRET+x}\"".to_owned(),
                ],
                environment: BTreeMap::from([(
                    "GTKG_PROBE_SECRET".to_owned(),
                    "must-not-pass".to_owned(),
                )]),
            },
            &[],
            &policy.limits,
        )?;
        assertions.insert("clear_environment".to_owned(), environment.succeeded());

        let child = run_sandbox_exec(
            &profile,
            &SandboxCommand {
                program: "/bin/sh".to_owned(),
                arguments: vec![
                    "-c".to_owned(),
                    "/usr/bin/true; printf child-ran".to_owned(),
                ],
                environment: BTreeMap::new(),
            },
            &[],
            &policy.limits,
        )?;
        assertions.insert(
            "deny_child_exec".to_owned(),
            !child.succeeded() && !String::from_utf8_lossy(&child.stdout).contains("child-ran"),
        );

        let network_denied = probe_network(&profile, &policy.limits)?;
        assertions.insert("deny_network".to_owned(), network_denied);

        for (assertion, passed) in &assertions {
            if !passed {
                findings.push(format!("sandbox assertion failed: {assertion}"));
            }
        }
        let passed = assertions.len() == 8 && assertions.values().all(|value| *value);
        if passed {
            fs::remove_dir_all(&probe_root)
                .map_err(|error| SandboxFailure::io("sandbox.probe", &probe_root, error))?;
        } else {
            findings.push(format!(
                "failed probe evidence retained at {}",
                probe_root.display()
            ));
        }
        validated_probe(SandboxProbeResult {
            schema_version: "gtkg.sandbox-probe/v1".to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            policy_sha256,
            passed,
            verified_level: passed.then_some(AssuranceLevel::Sb2),
            release_ready: false,
            assertions,
            findings,
        })
    }

    fn execute(
        &self,
        policy: &SandboxPolicyLock,
        probe: &SandboxProbeResult,
        command: &SandboxCommand,
    ) -> Result<SandboxReceipt, SandboxFailure> {
        validate_policy(policy)?;
        require_macos_sandbox_exec()?;
        require_probe(policy, probe, PROVIDER_ID, AssuranceLevel::Sb2)?;
        let (input, output) = validate_static_reader_command(policy, command)?;
        let canonical_scratch = canonical_directory(&policy.scratch_root, "sandbox.execute")?;
        let denied = canonical_denied_paths(policy)?;
        let allowed_inputs = policy
            .input_roots
            .iter()
            .map(|root| canonical_directory(root, "sandbox.execute"))
            .collect::<Result<Vec<_>, _>>()?;
        let profile = sb2_profile(
            &canonical_scratch,
            &denied,
            &allowed_inputs,
            policy.deny_network,
        )?;
        let execution = run_sandbox_exec(
            &profile,
            command,
            &policy.allowed_environment,
            &policy.limits,
        )?;
        receipt(
            PROVIDER_ID,
            AssuranceLevel::Sb2,
            policy,
            command,
            &input,
            &output,
            execution,
        )
    }
}

/// SB0 performs only deterministic logical guards and never claims OS isolation.
#[derive(Debug, Default, Clone, Copy)]
pub struct LogicalGuardProvider;

impl SandboxProvider for LogicalGuardProvider {
    fn describe(&self) -> SandboxProviderDescription {
        SandboxProviderDescription {
            provider_id: SB0_PROVIDER_ID.to_owned(),
            supported_levels: vec![AssuranceLevel::Sb0],
            probe_state: SandboxProbeState::NotRun,
            verified_level: None,
        }
    }

    fn probe(&self, policy: &SandboxPolicyLock) -> Result<SandboxProbeResult, SandboxFailure> {
        validate_policy(policy)?;
        let policy_sha256 = policy
            .digest()
            .map_err(|error| SandboxFailure::invalid(error.to_string()))?;
        let exact = policy.required_level == AssuranceLevel::Sb0;
        validated_probe(SandboxProbeResult {
            schema_version: "gtkg.sandbox-probe/v1".to_owned(),
            provider_id: SB0_PROVIDER_ID.to_owned(),
            policy_sha256,
            passed: exact,
            verified_level: exact.then_some(AssuranceLevel::Sb0),
            release_ready: false,
            assertions: BTreeMap::from([("logical_path_guards".to_owned(), true)]),
            findings: (!exact)
                .then(|| "SB0 cannot satisfy an SB1/SB2 policy".to_owned())
                .into_iter()
                .collect(),
        })
    }

    fn execute(
        &self,
        policy: &SandboxPolicyLock,
        probe: &SandboxProbeResult,
        command: &SandboxCommand,
    ) -> Result<SandboxReceipt, SandboxFailure> {
        require_probe(policy, probe, SB0_PROVIDER_ID, AssuranceLevel::Sb0)?;
        let (input, output) = validate_static_reader_command(policy, command)?;
        let source = fs::read_to_string(&input)
            .map_err(|error| SandboxFailure::io("sandbox.sb0", &input, error))?;
        let first = source.lines().next().unwrap_or_default();
        fs::write(&output, first)
            .map_err(|error| SandboxFailure::io("sandbox.sb0", &output, error))?;
        receipt(
            SB0_PROVIDER_ID,
            AssuranceLevel::Sb0,
            policy,
            command,
            &input,
            &output,
            RawExecution::synthetic_success(),
        )
    }
}

/// SB1 adds an isolated child process, clean environment, timeout, and output limit.
#[derive(Debug, Default, Clone, Copy)]
pub struct CleanProcessProvider;

impl SandboxProvider for CleanProcessProvider {
    fn describe(&self) -> SandboxProviderDescription {
        SandboxProviderDescription {
            provider_id: SB1_PROVIDER_ID.to_owned(),
            supported_levels: vec![AssuranceLevel::Sb1],
            probe_state: SandboxProbeState::NotRun,
            verified_level: None,
        }
    }

    fn probe(&self, policy: &SandboxPolicyLock) -> Result<SandboxProbeResult, SandboxFailure> {
        validate_policy(policy)?;
        let policy_sha256 = policy
            .digest()
            .map_err(|error| SandboxFailure::invalid(error.to_string()))?;
        let exact = policy.required_level == AssuranceLevel::Sb1;
        validated_probe(SandboxProbeResult {
            schema_version: "gtkg.sandbox-probe/v1".to_owned(),
            provider_id: SB1_PROVIDER_ID.to_owned(),
            policy_sha256,
            passed: exact,
            verified_level: exact.then_some(AssuranceLevel::Sb1),
            release_ready: false,
            assertions: BTreeMap::from([
                ("separate_process".to_owned(), true),
                ("clean_environment".to_owned(), true),
                ("bounded_execution".to_owned(), true),
            ]),
            findings: (!exact)
                .then(|| "SB1 cannot satisfy an SB0-exact or SB2 policy".to_owned())
                .into_iter()
                .collect(),
        })
    }

    fn execute(
        &self,
        policy: &SandboxPolicyLock,
        probe: &SandboxProbeResult,
        command: &SandboxCommand,
    ) -> Result<SandboxReceipt, SandboxFailure> {
        require_probe(policy, probe, SB1_PROVIDER_ID, AssuranceLevel::Sb1)?;
        let (input, output) = validate_static_reader_command(policy, command)?;
        let execution = run_plain_process(
            command,
            &policy.allowed_environment,
            &policy.scratch_root,
            &policy.limits,
        )?;
        receipt(
            SB1_PROVIDER_ID,
            AssuranceLevel::Sb1,
            policy,
            command,
            &input,
            &output,
            execution,
        )
    }
}

fn validate_policy(policy: &SandboxPolicyLock) -> Result<(), SandboxFailure> {
    policy
        .validate()
        .map_err(|error| SandboxFailure::invalid(error.to_string()))?;
    for root in &policy.input_roots {
        canonical_directory(root, "sandbox-policy")?;
    }
    canonical_directory(&policy.scratch_root, "sandbox-policy")?;
    for denied in &policy.denied_read_paths {
        if !denied.exists() {
            return Err(SandboxFailure::invalid(format!(
                "denied read path does not exist: {}",
                denied.display()
            )));
        }
    }
    Ok(())
}

fn require_macos_sandbox_exec() -> Result<(), SandboxFailure> {
    if !cfg!(target_os = "macos") {
        return Err(SandboxFailure::unavailable(
            "macos sandbox-exec provider is unavailable on this platform",
        ));
    }
    let path = Path::new("/usr/bin/sandbox-exec");
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| SandboxFailure::io("sandbox-probe", path, error))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(SandboxFailure::unavailable(
            "/usr/bin/sandbox-exec is not a regular provider binary",
        ));
    }
    Ok(())
}

fn require_probe(
    policy: &SandboxPolicyLock,
    probe: &SandboxProbeResult,
    provider_id: &str,
    exact_level: AssuranceLevel,
) -> Result<(), SandboxFailure> {
    validate_policy(policy)?;
    let digest = policy
        .digest()
        .map_err(|error| SandboxFailure::invalid(error.to_string()))?;
    if policy.required_level != exact_level
        || probe.provider_id != provider_id
        || probe.policy_sha256 != digest
        || !probe.passed
        || probe.verified_level != Some(exact_level)
    {
        return Err(SandboxFailure::unavailable(format!(
            "provider {provider_id} lacks a passing exact {exact_level:?} probe for policy {}",
            policy.policy_id
        )));
    }
    Ok(())
}

fn validate_static_reader_command(
    policy: &SandboxPolicyLock,
    command: &SandboxCommand,
) -> Result<(PathBuf, PathBuf), SandboxFailure> {
    if !policy
        .allowed_programs
        .iter()
        .any(|program| program == &command.program)
    {
        return Err(SandboxFailure::invalid(format!(
            "program is not policy-allowlisted: {}",
            command.program
        )));
    }
    if command.program != "/bin/sh"
        || command.arguments.len() != 5
        || command.arguments[0] != "-c"
        || command.arguments[1] != STATIC_READER_SCRIPT
        || command.arguments[2] != "gtkg-static-reader"
    {
        return Err(SandboxFailure::invalid(
            "V0.1 only permits the fixed static-reader command contract",
        ));
    }
    let input = canonical_file(Path::new(&command.arguments[3]), "sandbox.execute")?;
    let allowed_input = policy.input_roots.iter().try_fold(false, |matched, root| {
        let canonical = canonical_directory(root, "sandbox.execute")?;
        Ok::<_, SandboxFailure>(matched || input.starts_with(canonical))
    })?;
    if !allowed_input {
        return Err(SandboxFailure::invalid(format!(
            "input is outside locked roots: {}",
            input.display()
        )));
    }
    let output = PathBuf::from(&command.arguments[4]);
    let parent = output
        .parent()
        .ok_or_else(|| SandboxFailure::invalid("output path has no parent"))?;
    let canonical_parent = canonical_directory(parent, "sandbox.execute")?;
    let scratch = canonical_directory(&policy.scratch_root, "sandbox.execute")?;
    if !canonical_parent.starts_with(&scratch) {
        return Err(SandboxFailure::invalid(format!(
            "output is outside scratch: {}",
            output.display()
        )));
    }
    if output.exists() {
        return Err(SandboxFailure::invalid(format!(
            "immutable sandbox output already exists: {}",
            output.display()
        )));
    }
    Ok((
        input,
        canonical_parent.join(
            output
                .file_name()
                .ok_or_else(|| SandboxFailure::invalid("output path has no filename"))?,
        ),
    ))
}

fn canonical_denied_paths(policy: &SandboxPolicyLock) -> Result<Vec<PathBuf>, SandboxFailure> {
    let mut denied = Vec::new();
    for path in &policy.denied_read_paths {
        denied.push(
            fs::canonicalize(path)
                .map_err(|error| SandboxFailure::io("sandbox-policy", path, error))?,
        );
    }
    if let Some(home) = std::env::var_os("HOME") {
        let home = PathBuf::from(home);
        if home.exists() {
            denied.push(
                fs::canonicalize(&home)
                    .map_err(|error| SandboxFailure::io("sandbox-policy", &home, error))?,
            );
        }
    }
    denied.sort();
    denied.dedup();
    Ok(denied)
}

fn sb2_profile(
    scratch: &Path,
    denied_read_paths: &[PathBuf],
    allowed_input_roots: &[PathBuf],
    deny_network: bool,
) -> Result<String, SandboxFailure> {
    let scratch = profile_path(scratch)?;
    let mut profile = String::from(
        "(version 1)(deny default)(allow process*)(deny process-fork)(allow file-read*)",
    );
    for denied in denied_read_paths {
        profile.push_str(&format!(
            "(deny file-read* (subpath \"{}\"))",
            profile_path(denied)?
        ));
    }
    for allowed in allowed_input_roots {
        profile.push_str(&format!(
            "(allow file-read* (subpath \"{}\"))",
            profile_path(allowed)?
        ));
    }
    profile.push_str(&format!("(allow file-write* (subpath \"{scratch}\"))"));
    if deny_network {
        profile.push_str("(deny network*)");
    }
    Ok(profile)
}

fn profile_path(path: &Path) -> Result<String, SandboxFailure> {
    let value = path.to_str().ok_or_else(|| {
        SandboxFailure::invalid(format!("sandbox path is not UTF-8: {}", path.display()))
    })?;
    if value.contains(['\0', '\n', '\r']) {
        return Err(SandboxFailure::invalid("unsafe sandbox profile path"));
    }
    Ok(value.replace('\\', "\\\\").replace('"', "\\\""))
}

fn shell_probe(script: &str, path: &Path) -> SandboxCommand {
    SandboxCommand {
        program: "/bin/sh".to_owned(),
        arguments: vec![
            "-c".to_owned(),
            script.to_owned(),
            "gtkg-probe".to_owned(),
            path.to_string_lossy().into_owned(),
        ],
        environment: BTreeMap::new(),
    }
}

fn probe_network(profile: &str, limits: &ResourceLimits) -> Result<bool, SandboxFailure> {
    let version = run_sandbox_exec(
        profile,
        &SandboxCommand {
            program: "/usr/bin/curl".to_owned(),
            arguments: vec!["--version".to_owned()],
            environment: BTreeMap::new(),
        },
        &[],
        limits,
    )?;
    if !version.succeeded() {
        return Ok(false);
    }
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|error| {
        SandboxFailure::io("sandbox.probe-network", Path::new("127.0.0.1"), error)
    })?;
    let address = listener.local_addr().map_err(|error| {
        SandboxFailure::io("sandbox.probe-network", Path::new("127.0.0.1"), error)
    })?;
    let network = run_sandbox_exec(
        profile,
        &SandboxCommand {
            program: "/usr/bin/curl".to_owned(),
            arguments: vec![
                "--silent".to_owned(),
                "--show-error".to_owned(),
                "--max-time".to_owned(),
                "1".to_owned(),
                format!("http://{address}"),
            ],
            environment: BTreeMap::new(),
        },
        &[],
        limits,
    )?;
    listener.set_nonblocking(true).map_err(|error| {
        SandboxFailure::io("sandbox.probe-network", Path::new("listener"), error)
    })?;
    let connected = match listener.accept() {
        Ok(_) => true,
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => false,
        Err(error) => {
            return Err(SandboxFailure::io(
                "sandbox.probe-network",
                Path::new("listener"),
                error,
            ));
        }
    };
    Ok(!network.succeeded() && !connected)
}

fn run_sandbox_exec(
    profile: &str,
    command: &SandboxCommand,
    allowed_environment: &[String],
    limits: &ResourceLimits,
) -> Result<RawExecution, SandboxFailure> {
    let mut process = Command::new("/usr/bin/sandbox-exec");
    process.arg("-p").arg(profile).arg(&command.program);
    process.args(&command.arguments);
    configure_process_environment(&mut process, command, allowed_environment, None);
    run_child(process, limits, "sandbox.execute")
}

fn run_plain_process(
    command: &SandboxCommand,
    allowed_environment: &[String],
    scratch: &Path,
    limits: &ResourceLimits,
) -> Result<RawExecution, SandboxFailure> {
    let mut process = Command::new(&command.program);
    process.args(&command.arguments);
    configure_process_environment(&mut process, command, allowed_environment, Some(scratch));
    run_child(process, limits, "sandbox.sb1")
}

fn configure_process_environment(
    process: &mut Command,
    command: &SandboxCommand,
    allowed_environment: &[String],
    scratch: Option<&Path>,
) {
    process
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(scratch) = scratch {
        process.env("TMPDIR", scratch);
    }
    for key in allowed_environment {
        if let Some(value) = command.environment.get(key) {
            process.env(key, value);
        }
    }
}

fn run_child(
    mut process: Command,
    limits: &ResourceLimits,
    stage: &'static str,
) -> Result<RawExecution, SandboxFailure> {
    let mut child = process.spawn().map_err(|error| SandboxFailure {
        code: ErrorCode::SandboxAssuranceUnavailable,
        stage,
        message: format!("failed to spawn sandbox provider: {error}"),
        recovery_hint: "install and probe the exact declared sandbox provider",
    })?;
    let started = Instant::now();
    let timeout = Duration::from_millis(limits.timeout_millis);
    let mut timed_out = false;
    let status = loop {
        if let Some(status) = child.try_wait().map_err(|error| SandboxFailure {
            code: ErrorCode::Io,
            stage,
            message: format!("failed to poll sandbox process: {error}"),
            recovery_hint: "retry the pure WorkUnit with a healthy local provider",
        })? {
            break status;
        }
        if started.elapsed() >= timeout {
            timed_out = true;
            child.kill().map_err(|error| SandboxFailure {
                code: ErrorCode::Io,
                stage,
                message: format!("failed to terminate timed out sandbox process: {error}"),
                recovery_hint: "inspect the local provider and resource limits",
            })?;
            break child.wait().map_err(|error| SandboxFailure {
                code: ErrorCode::Io,
                stage,
                message: format!("failed to reap sandbox process: {error}"),
                recovery_hint: "inspect the local provider and resource limits",
            })?;
        }
        thread::sleep(Duration::from_millis(5));
    };
    let output = child.wait_with_output().map_err(|error| SandboxFailure {
        code: ErrorCode::Io,
        stage,
        message: format!("failed to collect sandbox output: {error}"),
        recovery_hint: "retry the pure WorkUnit with bounded output",
    })?;
    let output_bytes = output.stdout.len().saturating_add(output.stderr.len()) as u64;
    Ok(RawExecution {
        status,
        stdout: output.stdout,
        stderr: output.stderr,
        timed_out,
        output_exceeded: output_bytes > limits.max_output_bytes,
    })
}

fn receipt(
    provider_id: &str,
    assurance_level: AssuranceLevel,
    policy: &SandboxPolicyLock,
    command: &SandboxCommand,
    input: &Path,
    output: &Path,
    execution: RawExecution,
) -> Result<SandboxReceipt, SandboxFailure> {
    let policy_sha256 = policy
        .digest()
        .map_err(|error| SandboxFailure::invalid(error.to_string()))?;
    let command_sha256 = canonical_json_sha256(command)
        .map_err(|error| SandboxFailure::invalid(error.to_string()))?;
    let input_sha256 =
        sha256_file(input).map_err(|error| SandboxFailure::io("sandbox.receipt", input, error))?;
    let mut violations = Vec::new();
    if execution.timed_out {
        violations.push("timeout".to_owned());
    }
    if execution.output_exceeded {
        violations.push("output_limit".to_owned());
    }
    if !execution.status.success() {
        let diagnostic = String::from_utf8_lossy(&execution.stderr);
        if !diagnostic.trim().is_empty() {
            violations.push(format!("process: {}", diagnostic.trim()));
        }
    }
    let success = execution.succeeded();
    let output_sha256 = if success && output.is_file() {
        sha256_file(output).map_err(|error| SandboxFailure::io("sandbox.receipt", output, error))?
    } else {
        digest_output(&execution.stdout, &execution.stderr)
    };
    let receipt = SandboxReceipt {
        schema_version: "gtkg.sandbox-receipt/v1".to_owned(),
        provider_id: provider_id.to_owned(),
        assurance_level,
        policy_sha256,
        command_sha256,
        input_sha256,
        limits: policy.limits.clone(),
        success,
        exit_code: execution.status.code(),
        exit_reason: if execution.timed_out {
            "timeout".to_owned()
        } else if execution.output_exceeded {
            "output_limit".to_owned()
        } else if execution.status.success() {
            "completed".to_owned()
        } else {
            "nonzero_exit".to_owned()
        },
        violations,
        target_execution_count: 0,
        output_sha256,
    };
    receipt
        .validate()
        .map_err(|error| SandboxFailure::invalid(error.to_string()))?;
    Ok(receipt)
}

fn validated_probe(result: SandboxProbeResult) -> Result<SandboxProbeResult, SandboxFailure> {
    result
        .validate()
        .map_err(|error| SandboxFailure::invalid(error.to_string()))?;
    Ok(result)
}

fn canonical_directory(path: &Path, stage: &'static str) -> Result<PathBuf, SandboxFailure> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| SandboxFailure::io(stage, path, error))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(SandboxFailure::invalid(format!(
            "directory must be real and non-symlink: {}",
            path.display()
        )));
    }
    fs::canonicalize(path).map_err(|error| SandboxFailure::io(stage, path, error))
}

fn canonical_file(path: &Path, stage: &'static str) -> Result<PathBuf, SandboxFailure> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| SandboxFailure::io(stage, path, error))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(SandboxFailure::invalid(format!(
            "input must be a real regular file: {}",
            path.display()
        )));
    }
    let canonical =
        fs::canonicalize(path).map_err(|error| SandboxFailure::io(stage, path, error))?;
    for ancestor in WalkDir::new(
        path.parent()
            .ok_or_else(|| SandboxFailure::invalid("input has no parent"))?,
    )
    .max_depth(1)
    .follow_links(false)
    {
        let ancestor = ancestor.map_err(|error| SandboxFailure::invalid(error.to_string()))?;
        if ancestor.path() == path && ancestor.file_type().is_symlink() {
            return Err(SandboxFailure::invalid("symlink input is forbidden"));
        }
    }
    Ok(canonical)
}

fn digest_output(stdout: &[u8], stderr: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(stdout);
    hasher.update([0]);
    hasher.update(stderr);
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

#[derive(Debug)]
struct RawExecution {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    timed_out: bool,
    output_exceeded: bool,
}

impl RawExecution {
    fn synthetic_success() -> Self {
        Self {
            status: success_exit_status(),
            stdout: Vec::new(),
            stderr: Vec::new(),
            timed_out: false,
            output_exceeded: false,
        }
    }

    fn succeeded(&self) -> bool {
        self.status.success() && !self.timed_out && !self.output_exceeded
    }
}

#[cfg(unix)]
fn success_exit_status() -> ExitStatus {
    use std::os::unix::process::ExitStatusExt;
    ExitStatus::from_raw(0)
}

#[cfg(not(unix))]
fn success_exit_status() -> ExitStatus {
    Command::new("true")
        .status()
        .expect("the fallback success status command must exist")
}
