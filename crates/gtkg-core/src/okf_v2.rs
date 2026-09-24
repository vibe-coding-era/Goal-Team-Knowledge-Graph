//! V0.2 OKF conformance evidence helpers.
//!
//! These functions validate local prerequisites only. They intentionally do
//! not fetch network resources, execute a third-party reference runner, or
//! elevate a historical fixture into current external conformance.

use std::fs;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

use gtkg_protocol::v2::{OkfAxisStatusV2, OkfSpecPinV2};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::okf::{parse_okf, parse_okf_concept};

/// A local observation that can be attached to one of the four OKF axes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OkfAxisEvidenceV2 {
    pub status: OkfAxisStatusV2,
    pub code: &'static str,
    pub detail: String,
}

const EXTERNAL_ASSET_MANIFEST_SCHEMA: &str = "gtkg.external-asset-manifest/v1";
const CURRENT_OKF_RAW_KIND: &str = "upstream_spec_raw";
const REFERENCE_RUNNER_MANIFEST_SCHEMA: &str = "gtkg.reference-runner-manifest/v1";
const REFERENCE_RUNNER_REPOSITORY: &str = "W4G1/okf";
const REFERENCE_RUNNER_LICENSE: &str = "Apache-2.0";
const REFERENCE_RUNNER_COMMAND: &str = "cargo run --locked -q -p okf --no-default-features --features validator -- validate <bundle> --json";
const HISTORICAL_H01_SMOKE_INPUT: &str = "crates/gtkg-testkit/fixtures/h01_okf/bundle";
const REFERENCE_RUNNER_UNTRACKED_POLICY: &str = "only_manifest";
const REFERENCE_RUNNER_MANIFEST_FILENAME: &str = "MANIFEST.json";

#[derive(Debug, Deserialize)]
struct CurrentOkfRawAssetManifest {
    schema_version: String,
    asset_id: String,
    kind: String,
    source_url: String,
    upstream_repository: String,
    upstream_commit: String,
    relative_path: String,
    sha256: String,
    bytes: u64,
    license_status: String,
    acquired_at: String,
    purpose: String,
}

#[derive(Debug, Deserialize)]
struct ReferenceRunnerManifest {
    schema_version: String,
    runner_id: String,
    repository: String,
    commit: String,
    license: String,
    protocol_claim: String,
    checkout_path: String,
    validation_command: String,
    host_rustc: String,
    smoke_input: String,
    smoke_result: ReferenceRunnerSmokeResult,
    untracked_policy: String,
    boundary: String,
}

#[derive(Debug, Deserialize)]
struct ReferenceRunnerSmokeResult {
    okf_version: String,
    conformant: bool,
    error_count: u64,
    warning_count: u64,
    info_count: u64,
}

/// A local reference-runner observation. `runner_available` means only that
/// the locked local runner can be identified; it is deliberately separate from
/// a current-corpus reference-compatibility execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReferenceRunnerValidationV2 {
    pub runner_available: bool,
    pub availability: OkfAxisEvidenceV2,
    pub current_corpus_reference_compatibility: OkfAxisEvidenceV2,
}

/// Check whether a caller supplied the exact raw asset named by the current
/// pin. Exact bytes are only a prerequisite: without a frozen normative corpus
/// and executed cases, this remains `not_run`, never external conformance.
pub fn validate_current_okf_raw_asset(
    pin: &OkfSpecPinV2,
    raw_asset: Option<&Path>,
) -> OkfAxisEvidenceV2 {
    if let Err(error) = pin.validate() {
        return OkfAxisEvidenceV2 {
            status: OkfAxisStatusV2::Invalid,
            code: error.code(),
            detail: format!("invalid V0.2 OKF pin: {error}"),
        };
    }
    let Some(raw_asset) = raw_asset else {
        return OkfAxisEvidenceV2 {
            status: OkfAxisStatusV2::CannotConfirm,
            code: "E_V2_OKF_CURRENT_RAW_ASSET_MISSING",
            detail: "the locally required raw asset for this pin is absent; this is not current OKF conformance".to_owned(),
        };
    };
    let bytes = match fs::read(raw_asset) {
        Ok(bytes) => bytes,
        Err(error) => {
            return OkfAxisEvidenceV2 {
                status: OkfAxisStatusV2::CannotConfirm,
                code: "E_V2_OKF_CURRENT_RAW_ASSET_UNREADABLE",
                detail: format!(
                    "cannot read local raw OKF asset {}: {error}; this is not current OKF conformance",
                    raw_asset.display()
                ),
            };
        }
    };
    let observed = format!("sha256:{:x}", Sha256::digest(bytes));
    if observed != pin.raw_sha256 {
        return OkfAxisEvidenceV2 {
            status: OkfAxisStatusV2::CannotConfirm,
            code: "E_V2_OKF_CURRENT_RAW_ASSET_DIGEST_MISMATCH",
            detail: format!(
                "local raw OKF asset {} has {observed}, expected {}; this is not current OKF conformance",
                raw_asset.display(),
                pin.raw_sha256
            ),
        };
    }
    OkfAxisEvidenceV2 {
        status: OkfAxisStatusV2::NotRun,
        code: "E_V2_OKF_CURRENT_NORMATIVE_CORPUS_NOT_RUN",
        detail: "the exact pinned raw asset is available locally, but no current normative corpus has been executed; this is not current OKF conformance".to_owned(),
    }
}

/// Validate the local acquisition manifest together with the raw bytes named
/// by a V0.2 OKF pin. This remains a prerequisite, not a normative-corpus or
/// reference-runner result.
pub fn validate_current_okf_raw_asset_manifest(
    pin: &OkfSpecPinV2,
    raw_asset: &Path,
    manifest_path: &Path,
) -> OkfAxisEvidenceV2 {
    let manifest_bytes = match fs::read(manifest_path) {
        Ok(bytes) => bytes,
        Err(error) => {
            return OkfAxisEvidenceV2 {
                status: OkfAxisStatusV2::CannotConfirm,
                code: "E_V2_OKF_CURRENT_RAW_MANIFEST_UNREADABLE",
                detail: format!(
                    "cannot read local OKF raw-asset manifest {}: {error}; this is not current OKF conformance",
                    manifest_path.display()
                ),
            };
        }
    };
    let manifest = match serde_json::from_slice::<CurrentOkfRawAssetManifest>(&manifest_bytes) {
        Ok(manifest) => manifest,
        Err(error) => {
            return OkfAxisEvidenceV2 {
                status: OkfAxisStatusV2::CannotConfirm,
                code: "E_V2_OKF_CURRENT_RAW_MANIFEST_INVALID",
                detail: format!(
                    "local OKF raw-asset manifest {} is not valid JSON: {error}; this is not current OKF conformance",
                    manifest_path.display()
                ),
            };
        }
    };
    let raw_bytes = match fs::read(raw_asset) {
        Ok(bytes) => bytes,
        Err(error) => {
            return OkfAxisEvidenceV2 {
                status: OkfAxisStatusV2::CannotConfirm,
                code: "E_V2_OKF_CURRENT_RAW_ASSET_UNREADABLE",
                detail: format!(
                    "cannot read local raw OKF asset {}: {error}; this is not current OKF conformance",
                    raw_asset.display()
                ),
            };
        }
    };
    let asset_filename = raw_asset.file_name().and_then(|name| name.to_str());
    let manifest_matches_pin = manifest.schema_version == EXTERNAL_ASSET_MANIFEST_SCHEMA
        && manifest.kind == CURRENT_OKF_RAW_KIND
        && !manifest.asset_id.trim().is_empty()
        && !manifest.upstream_repository.trim().is_empty()
        && manifest.upstream_commit == pin.upstream_commit
        && manifest.sha256 == pin.raw_sha256
        && manifest.bytes == raw_bytes.len() as u64
        && asset_filename.is_some_and(|filename| manifest.relative_path == filename)
        && manifest.source_url.contains(&manifest.upstream_commit)
        && !manifest.license_status.trim().is_empty()
        && !manifest.acquired_at.trim().is_empty()
        && !manifest.purpose.trim().is_empty();
    if !manifest_matches_pin {
        return OkfAxisEvidenceV2 {
            status: OkfAxisStatusV2::CannotConfirm,
            code: "E_V2_OKF_CURRENT_RAW_MANIFEST_MISMATCH",
            detail: format!(
                "local OKF raw-asset manifest {} does not bind schema, identity, path, bytes, digest, and acquisition metadata to the current pin; this is not current OKF conformance",
                manifest_path.display()
            ),
        };
    }
    validate_current_okf_raw_asset(pin, Some(raw_asset))
}

/// A missing reference implementation is an environmental blocker, not a
/// failed compatibility result. Presence alone remains `not_run`: executing
/// the pinned reference suite belongs to the dedicated external runner task.
pub fn validate_reference_runner(reference_runner: Option<&Path>) -> OkfAxisEvidenceV2 {
    let Some(reference_runner) = reference_runner else {
        return OkfAxisEvidenceV2 {
            status: OkfAxisStatusV2::Blocked,
            code: "E_V2_OKF_REFERENCE_RUNNER_MISSING",
            detail: "no pinned local OKF reference runner is available; reference compatibility is blocked".to_owned(),
        };
    };
    match fs::metadata(reference_runner) {
        Ok(metadata) if metadata.is_file() => OkfAxisEvidenceV2 {
            status: OkfAxisStatusV2::NotRun,
            code: "E_V2_OKF_REFERENCE_SUITE_NOT_RUN",
            detail:
                "a local reference runner is present, but its pinned required suite has not run"
                    .to_owned(),
        },
        Ok(_) => OkfAxisEvidenceV2 {
            status: OkfAxisStatusV2::Blocked,
            code: "E_V2_OKF_REFERENCE_RUNNER_INVALID",
            detail: format!(
                "reference runner {} is not a regular file; reference compatibility is blocked",
                reference_runner.display()
            ),
        },
        Err(error) => OkfAxisEvidenceV2 {
            status: OkfAxisStatusV2::Blocked,
            code: "E_V2_OKF_REFERENCE_RUNNER_MISSING",
            detail: format!(
                "cannot read reference runner {}: {error}; reference compatibility is blocked",
                reference_runner.display()
            ),
        },
    }
}

/// Validate the checked-out, third-party runner *identity* without executing
/// it. The runner command is compared to the fixed, reviewed command string;
/// it is never read from the manifest and executed. A successful result only
/// reports `runner_available`; current corpus/reference compatibility remains
/// `not_run` until a dedicated corpus run has its own receipt.
pub fn validate_reference_runner_manifest(
    workspace_root: &Path,
    manifest_path: &Path,
) -> ReferenceRunnerValidationV2 {
    let manifest_bytes = match fs::read(manifest_path) {
        Ok(bytes) => bytes,
        Err(error) => {
            return reference_runner_unavailable(
                OkfAxisStatusV2::Blocked,
                "E_V2_OKF_REFERENCE_RUNNER_MANIFEST_UNREADABLE",
                format!(
                    "cannot read reference-runner manifest {}: {error}",
                    manifest_path.display()
                ),
            );
        }
    };
    let manifest = match serde_json::from_slice::<ReferenceRunnerManifest>(&manifest_bytes) {
        Ok(manifest) => manifest,
        Err(error) => {
            return reference_runner_unavailable(
                OkfAxisStatusV2::Invalid,
                "E_V2_OKF_REFERENCE_RUNNER_MANIFEST_INVALID",
                format!(
                    "reference-runner manifest {} is not valid JSON: {error}",
                    manifest_path.display()
                ),
            );
        }
    };
    let workspace_root = match fs::canonicalize(workspace_root) {
        Ok(path) => path,
        Err(error) => {
            return reference_runner_unavailable(
                OkfAxisStatusV2::Blocked,
                "E_V2_OKF_REFERENCE_RUNNER_WORKSPACE_UNREADABLE",
                format!(
                    "cannot resolve workspace root {}: {error}",
                    workspace_root.display()
                ),
            );
        }
    };
    let checkout_relative = Path::new(&manifest.checkout_path);
    if checkout_relative.is_absolute()
        || checkout_relative.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return reference_runner_unavailable(
            OkfAxisStatusV2::Invalid,
            "E_V2_OKF_REFERENCE_RUNNER_CHECKOUT_INVALID",
            "reference-runner manifest checkout_path must be a workspace-relative path without traversal".to_owned(),
        );
    }
    let checkout = workspace_root.join(checkout_relative);
    let checkout = match fs::canonicalize(&checkout) {
        Ok(path) if path.starts_with(&workspace_root) && path.is_dir() => path,
        Ok(path) => {
            return reference_runner_unavailable(
                OkfAxisStatusV2::Invalid,
                "E_V2_OKF_REFERENCE_RUNNER_CHECKOUT_INVALID",
                format!(
                    "reference-runner checkout {} is not a directory inside the workspace",
                    path.display()
                ),
            );
        }
        Err(error) => {
            return reference_runner_unavailable(
                OkfAxisStatusV2::Blocked,
                "E_V2_OKF_REFERENCE_RUNNER_CHECKOUT_MISSING",
                format!(
                    "cannot resolve reference-runner checkout {}: {error}",
                    checkout.display()
                ),
            );
        }
    };
    let manifest_parent = manifest_path
        .parent()
        .and_then(|parent| fs::canonicalize(parent).ok());
    let manifest_filename = manifest_path.file_name().and_then(|name| name.to_str());
    let identity_fields_valid = manifest.schema_version == REFERENCE_RUNNER_MANIFEST_SCHEMA
        && !manifest.runner_id.trim().is_empty()
        && manifest.repository == REFERENCE_RUNNER_REPOSITORY
        && is_git_commit(&manifest.commit)
        && manifest.license == REFERENCE_RUNNER_LICENSE
        && !manifest.protocol_claim.trim().is_empty()
        && manifest.validation_command == REFERENCE_RUNNER_COMMAND
        && !manifest.host_rustc.trim().is_empty()
        && manifest.smoke_input == HISTORICAL_H01_SMOKE_INPUT
        && manifest.smoke_result.okf_version == "0.2"
        && manifest.smoke_result.conformant
        && manifest.smoke_result.error_count == 0
        && manifest.smoke_result.warning_count > 0
        && manifest.smoke_result.info_count > 0
        && manifest.untracked_policy == REFERENCE_RUNNER_UNTRACKED_POLICY
        && manifest.boundary.contains("historical H01 fixture")
        && manifest
            .boundary
            .contains("does not prove current official-format or reference compatibility")
        && manifest_parent.as_ref() == Some(&checkout)
        && manifest_filename == Some(REFERENCE_RUNNER_MANIFEST_FILENAME)
        && checkout.join("Cargo.toml").is_file()
        && checkout.join("Cargo.lock").is_file()
        && checkout.join("crates/okf/Cargo.toml").is_file()
        && workspace_root.join(HISTORICAL_H01_SMOKE_INPUT).is_dir();
    if !identity_fields_valid {
        return reference_runner_unavailable(
            OkfAxisStatusV2::Invalid,
            "E_V2_OKF_REFERENCE_RUNNER_MANIFEST_MISMATCH",
            "reference-runner manifest does not bind the reviewed repository, commit, command, checkout, smoke boundary, and required files".to_owned(),
        );
    }
    let observed_commit = match Command::new("git")
        .arg("-C")
        .arg(&checkout)
        .args(["rev-parse", "HEAD"])
        .output()
    {
        Ok(output) if output.status.success() => {
            String::from_utf8_lossy(&output.stdout).trim().to_owned()
        }
        Ok(output) => {
            return reference_runner_unavailable(
                OkfAxisStatusV2::Blocked,
                "E_V2_OKF_REFERENCE_RUNNER_CHECKOUT_UNVERIFIABLE",
                format!(
                    "cannot read reference-runner checkout commit: {}",
                    String::from_utf8_lossy(&output.stderr).trim()
                ),
            );
        }
        Err(error) => {
            return reference_runner_unavailable(
                OkfAxisStatusV2::Blocked,
                "E_V2_OKF_REFERENCE_RUNNER_CHECKOUT_UNVERIFIABLE",
                format!("cannot invoke git to inspect reference-runner checkout: {error}"),
            );
        }
    };
    if observed_commit != manifest.commit {
        return reference_runner_unavailable(
            OkfAxisStatusV2::Invalid,
            "E_V2_OKF_REFERENCE_RUNNER_COMMIT_MISMATCH",
            format!(
                "reference-runner checkout has commit {observed_commit}, expected {}",
                manifest.commit
            ),
        );
    }
    if let Err(validation) = validate_reference_runner_checkout_cleanliness(&checkout) {
        return validation;
    }
    ReferenceRunnerValidationV2 {
        runner_available: true,
        availability: OkfAxisEvidenceV2 {
            status: OkfAxisStatusV2::Passed,
            code: "I_V2_OKF_REFERENCE_RUNNER_AVAILABLE",
            detail: format!(
                "pinned {} at {} is locally available; no third-party command was executed",
                manifest.repository, manifest.commit
            ),
        },
        current_corpus_reference_compatibility: OkfAxisEvidenceV2 {
            status: OkfAxisStatusV2::NotRun,
            code: "E_V2_OKF_CURRENT_CORPUS_REFERENCE_COMPATIBILITY_NOT_RUN",
            detail: "the runner is available, but no frozen current corpus has been run against it; the historical H01 smoke result is not current reference compatibility".to_owned(),
        },
    }
}

/// The third-party checkout is part of the runner identity. We therefore
/// reject staged, unstaged, and unexpected untracked content rather than
/// treating the manifest's pinned HEAD as sufficient. The sole permitted
/// untracked path is the GTKG-owned MANIFEST.json that records the reviewed
/// external checkout; ignored build output remains governed by the upstream
/// checkout's own ignore rules and is never accepted as runner input.
fn validate_reference_runner_checkout_cleanliness(
    checkout: &Path,
) -> Result<(), ReferenceRunnerValidationV2> {
    for (args, code, label) in [
        (
            ["diff", "--cached", "--quiet"].as_slice(),
            "E_V2_OKF_REFERENCE_RUNNER_INDEX_DIRTY",
            "staged/index",
        ),
        (
            ["diff", "--quiet"].as_slice(),
            "E_V2_OKF_REFERENCE_RUNNER_WORKTREE_DIRTY",
            "tracked worktree",
        ),
    ] {
        let output = match Command::new("git")
            .arg("-C")
            .arg(checkout)
            .args(args)
            .output()
        {
            Ok(output) => output,
            Err(error) => {
                return Err(reference_runner_unavailable(
                    OkfAxisStatusV2::Blocked,
                    "E_V2_OKF_REFERENCE_RUNNER_CHECKOUT_UNVERIFIABLE",
                    format!("cannot invoke git to inspect reference-runner {label}: {error}"),
                ));
            }
        };
        if output.status.code() == Some(1) {
            return Err(reference_runner_unavailable(
                OkfAxisStatusV2::Invalid,
                code,
                format!(
                    "reference-runner checkout has {label} drift; only the pinned clean checkout is accepted"
                ),
            ));
        }
        if !output.status.success() {
            return Err(reference_runner_unavailable(
                OkfAxisStatusV2::Blocked,
                "E_V2_OKF_REFERENCE_RUNNER_CHECKOUT_UNVERIFIABLE",
                format!(
                    "cannot inspect reference-runner {label}: {}",
                    String::from_utf8_lossy(&output.stderr).trim()
                ),
            ));
        }
    }

    let output = match Command::new("git")
        .arg("-C")
        .arg(checkout)
        .args(["ls-files", "--others", "--exclude-standard", "-z"])
        .output()
    {
        Ok(output) => output,
        Err(error) => {
            return Err(reference_runner_unavailable(
                OkfAxisStatusV2::Blocked,
                "E_V2_OKF_REFERENCE_RUNNER_CHECKOUT_UNVERIFIABLE",
                format!("cannot invoke git to inspect reference-runner untracked files: {error}"),
            ));
        }
    };
    if !output.status.success() {
        return Err(reference_runner_unavailable(
            OkfAxisStatusV2::Blocked,
            "E_V2_OKF_REFERENCE_RUNNER_CHECKOUT_UNVERIFIABLE",
            format!(
                "cannot inspect reference-runner untracked files: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ),
        ));
    }
    let untracked = output
        .stdout
        .split(|byte| *byte == b'\0')
        .filter(|entry| !entry.is_empty())
        .map(String::from_utf8_lossy)
        .collect::<Vec<_>>();
    if untracked.len() != 1 || untracked[0] != REFERENCE_RUNNER_MANIFEST_FILENAME {
        return Err(reference_runner_unavailable(
            OkfAxisStatusV2::Invalid,
            "E_V2_OKF_REFERENCE_RUNNER_UNTRACKED_POLICY_VIOLATION",
            format!(
                "reference-runner checkout violates untracked_policy={REFERENCE_RUNNER_UNTRACKED_POLICY}; expected only {REFERENCE_RUNNER_MANIFEST_FILENAME}, found {:?}",
                untracked
            ),
        ));
    }
    Ok(())
}

fn reference_runner_unavailable(
    availability_status: OkfAxisStatusV2,
    code: &'static str,
    detail: String,
) -> ReferenceRunnerValidationV2 {
    ReferenceRunnerValidationV2 {
        runner_available: false,
        availability: OkfAxisEvidenceV2 {
            status: availability_status,
            code,
            detail,
        },
        current_corpus_reference_compatibility: OkfAxisEvidenceV2 {
            status: OkfAxisStatusV2::Blocked,
            code: "E_V2_OKF_REFERENCE_COMPATIBILITY_RUNNER_UNAVAILABLE",
            detail: "current corpus/reference compatibility is blocked because the pinned local runner is unavailable or invalid".to_owned(),
        },
    }
}

fn is_git_commit(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

const CURRENT_NORMATIVE_CORPUS_SCHEMA: &str = "gtkg.current-okf-normative-corpus/v1";
const CURRENT_NORMATIVE_FIXTURE_ROOT: &str =
    "crates/gtkg-testkit/fixtures/v02_t03/current-okf-v0.2";
const CURRENT_NORMATIVE_RECEIPT_PATH: &str =
    "deliverables/v02-t03/current-okf-normative-corpus-receipt.json";
const CURRENT_NORMATIVE_RAW_SPEC: &str = "docs/external-specs/okf-v0.2-62432a/SPEC.md";
const CURRENT_NORMATIVE_RAW_MANIFEST: &str = "docs/external-specs/okf-v0.2-62432a/MANIFEST.json";
const CURRENT_NORMATIVE_RUNNER_MANIFEST: &str =
    "docs/reference/okf-v0.2-reference-W4G1/MANIFEST.json";
const REQUIRED_CURRENT_NORMATIVE_FAMILIES: [&str; 9] = [
    "concept_minimum",
    "reserved_names",
    "extensions",
    "provenance",
    "trust_lifecycle",
    "links_paths",
    "progressive_index",
    "logs",
    "attested_computation",
];

#[derive(Debug, Deserialize)]
struct CurrentNormativeCorpusManifest {
    schema_version: String,
    corpus_id: String,
    status: String,
    boundary: String,
    raw_spec: CurrentNormativeRawSpec,
    reference_runner_manifest: String,
    fixture_root: String,
    receipt_path: String,
    cases: Vec<CurrentNormativeCase>,
}

#[derive(Debug, Deserialize)]
struct CurrentNormativeRawSpec {
    path: String,
    manifest: String,
    upstream_commit: String,
    sha256: String,
}

#[derive(Debug, Deserialize)]
struct CurrentNormativeCase {
    id: String,
    family: String,
    bundle: String,
    gtkg_input: String,
    gtkg_mode: String,
    spec_section: String,
    line_start: usize,
    line_end: usize,
    input_digests: Vec<CurrentNormativeInputDigest>,
    expected_gtkg: String,
    expected_runner: String,
}

#[derive(Debug, Deserialize)]
struct CurrentNormativeInputDigest {
    path: String,
    sha256: String,
}

#[derive(Debug, Deserialize)]
struct ReferenceRunnerReport {
    conformant: bool,
    error_count: u64,
    warning_count: u64,
}

/// The result of executing the Standards-reviewed, current local corpus.
///
/// It proves only this exact corpus observation. It does not claim Google
/// certification or general interoperability with all OKF implementations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurrentNormativeCorpusValidationV2 {
    pub official_format: OkfAxisEvidenceV2,
    pub reference_compatibility: OkfAxisEvidenceV2,
    pub case_count: usize,
    pub receipt_path: Option<PathBuf>,
}

/// Execute the frozen T03 corpus through GTKG's consumer and the separately
/// pinned W4G1 runner. The fixed command is never supplied by the corpus
/// manifest. Runner warnings are retained as receipt advisories; unavailable
/// runner, input/manifest drift, unexpected runner errors, or disposition
/// mismatch fail closed.
pub fn validate_current_normative_corpus(
    workspace_root: &Path,
    pin: &OkfSpecPinV2,
    corpus_manifest_path: &Path,
) -> CurrentNormativeCorpusValidationV2 {
    let workspace_root = match fs::canonicalize(workspace_root) {
        Ok(path) => path,
        Err(error) => {
            return normative_corpus_failure(
                OkfAxisStatusV2::Blocked,
                "E_V2_OKF_CURRENT_CORPUS_WORKSPACE_UNREADABLE",
                format!(
                    "cannot resolve workspace root {}: {error}",
                    workspace_root.display()
                ),
            );
        }
    };
    if let Err(error) = pin.validate() {
        return normative_corpus_failure(
            OkfAxisStatusV2::Invalid,
            error.code(),
            format!("invalid V0.2 OKF pin for current corpus: {error}"),
        );
    }
    let corpus_bytes = match fs::read(corpus_manifest_path) {
        Ok(bytes) => bytes,
        Err(error) => {
            return normative_corpus_failure(
                OkfAxisStatusV2::Blocked,
                "E_V2_OKF_CURRENT_CORPUS_MANIFEST_UNREADABLE",
                format!(
                    "cannot read current normative corpus manifest {}: {error}",
                    corpus_manifest_path.display()
                ),
            );
        }
    };
    let corpus = match serde_json::from_slice::<CurrentNormativeCorpusManifest>(&corpus_bytes) {
        Ok(corpus) => corpus,
        Err(error) => {
            return normative_corpus_failure(
                OkfAxisStatusV2::Invalid,
                "E_V2_OKF_CURRENT_CORPUS_MANIFEST_INVALID",
                format!(
                    "current normative corpus manifest {} is not valid JSON: {error}",
                    corpus_manifest_path.display()
                ),
            );
        }
    };
    if let Err(detail) = validate_normative_manifest(&corpus, pin) {
        return normative_corpus_failure(
            OkfAxisStatusV2::Invalid,
            "E_V2_OKF_CURRENT_CORPUS_MANIFEST_MISMATCH",
            detail,
        );
    }
    let raw_asset = workspace_root.join(CURRENT_NORMATIVE_RAW_SPEC);
    let raw_manifest = workspace_root.join(CURRENT_NORMATIVE_RAW_MANIFEST);
    let raw_asset_result = validate_current_okf_raw_asset_manifest(pin, &raw_asset, &raw_manifest);
    if raw_asset_result.status != OkfAxisStatusV2::NotRun {
        return normative_corpus_failure(
            raw_asset_result.status,
            raw_asset_result.code,
            raw_asset_result.detail,
        );
    }
    if let Err(detail) = validate_spec_line_ranges(&raw_asset, &corpus.cases) {
        return normative_corpus_failure(
            OkfAxisStatusV2::Invalid,
            "E_V2_OKF_CURRENT_CORPUS_SPEC_CITATION_INVALID",
            detail,
        );
    }
    let runner_manifest = workspace_root.join(CURRENT_NORMATIVE_RUNNER_MANIFEST);
    let runner = validate_reference_runner_manifest(&workspace_root, &runner_manifest);
    if !runner.runner_available {
        return normative_corpus_failure(
            runner.availability.status,
            runner.availability.code,
            runner.availability.detail,
        );
    }
    let fixture_root = workspace_root.join(CURRENT_NORMATIVE_FIXTURE_ROOT);
    let receipt_path = workspace_root.join(CURRENT_NORMATIVE_RECEIPT_PATH);
    let checkout = workspace_root.join("docs/reference/okf-v0.2-reference-W4G1");
    let mut mismatch_ids = Vec::new();
    let mut unexpected_error_ids = Vec::new();
    let mut warning_ids = Vec::new();
    let mut receipts = Vec::new();
    for case in &corpus.cases {
        match run_normative_case(&fixture_root, &checkout, case) {
            Ok(receipt) => {
                if !receipt.disposition_matches {
                    mismatch_ids.push(case.id.clone());
                }
                if !receipt.runner_errors_match_expected_disposition {
                    unexpected_error_ids.push(case.id.clone());
                }
                if receipt.runner_warning_count > 0 {
                    warning_ids.push(case.id.clone());
                }
                receipts.push(receipt);
            }
            Err(detail) => {
                return normative_corpus_failure(
                    OkfAxisStatusV2::Invalid,
                    "E_V2_OKF_CURRENT_CORPUS_CASE_INVALID",
                    detail,
                );
            }
        }
    }
    let (status, code, detail) = if !mismatch_ids.is_empty() {
        (
            OkfAxisStatusV2::Failed,
            "E_V2_OKF_CURRENT_CORPUS_DISPOSITION_MISMATCH",
            format!(
                "GTKG consumer or pinned reference runner differed from the frozen expected disposition for cases {}",
                mismatch_ids.join(", ")
            ),
        )
    } else if !unexpected_error_ids.is_empty() {
        (
            OkfAxisStatusV2::Failed,
            "E_V2_OKF_CURRENT_CORPUS_RUNNER_ERROR_UNEXPECTED",
            format!(
                "pinned reference runner emitted errors inconsistent with the frozen disposition for cases {}",
                unexpected_error_ids.join(", ")
            ),
        )
    } else if !warning_ids.is_empty() {
        (
            OkfAxisStatusV2::Passed,
            "I_V2_OKF_CURRENT_CORPUS_ADVISORIES_PRESENT",
            format!(
                "all {} frozen current-corpus cases matched both consumers; runner warnings for cases {} are recorded as advisory evidence, not hidden; this is not Google certification",
                corpus.cases.len(),
                warning_ids.join(", ")
            ),
        )
    } else {
        (
            OkfAxisStatusV2::Passed,
            "I_V2_OKF_CURRENT_NORMATIVE_CORPUS_PASSED",
            format!(
                "all {} frozen current-corpus cases matched both consumers without runner advisories; this is not Google certification",
                corpus.cases.len()
            ),
        )
    };
    let receipt = serde_json::json!({
        "schema_version": "gtkg.current-okf-normative-corpus-receipt/v1",
        "corpus_id": corpus.corpus_id,
        "status": status_name(status),
        "code": code,
        "detail": detail,
        "case_count": corpus.cases.len(),
        "runner_warning_case_ids": warning_ids,
        "disposition_mismatch_case_ids": mismatch_ids,
        "runner_unexpected_error_case_ids": unexpected_error_ids,
        "cases": receipts,
        "boundary": "Local frozen-corpus observation only; not Google certification or general OKF conformance."
    });
    if let Err(error) = write_normative_receipt(&receipt_path, &receipt) {
        return normative_corpus_failure(
            OkfAxisStatusV2::Blocked,
            "E_V2_OKF_CURRENT_CORPUS_RECEIPT_UNWRITABLE",
            format!(
                "cannot save current-corpus receipt {}: {error}",
                receipt_path.display()
            ),
        );
    }
    let evidence = OkfAxisEvidenceV2 {
        status,
        code,
        detail,
    };
    CurrentNormativeCorpusValidationV2 {
        official_format: evidence.clone(),
        reference_compatibility: evidence,
        case_count: corpus.cases.len(),
        receipt_path: Some(receipt_path),
    }
}

#[derive(serde::Serialize)]
struct CurrentNormativeCaseReceipt {
    id: String,
    gtkg_accepted: bool,
    expected_gtkg: String,
    runner_conformant: bool,
    expected_runner: String,
    runner_error_count: u64,
    runner_warning_count: u64,
    disposition_matches: bool,
    runner_errors_match_expected_disposition: bool,
}

fn run_normative_case(
    fixture_root: &Path,
    checkout: &Path,
    case: &CurrentNormativeCase,
) -> Result<CurrentNormativeCaseReceipt, String> {
    validate_case_shape(case)?;
    let bundle = safe_child_path(fixture_root, &case.bundle)?;
    if !bundle.is_dir() {
        return Err(format!(
            "case {} bundle {} is not a directory",
            case.id,
            bundle.display()
        ));
    }
    for digest in &case.input_digests {
        let input = safe_child_path(&bundle, &digest.path)?;
        let bytes = fs::read(&input).map_err(|error| {
            format!("case {} cannot read {}: {error}", case.id, input.display())
        })?;
        let observed = format!("sha256:{:x}", Sha256::digest(bytes));
        if observed != digest.sha256 {
            return Err(format!(
                "case {} input digest mismatch for {}: observed {observed}, expected {}",
                case.id,
                input.display(),
                digest.sha256
            ));
        }
    }
    let gtkg_input = safe_child_path(&bundle, &case.gtkg_input)?;
    let source = fs::read_to_string(&gtkg_input).map_err(|error| {
        format!(
            "case {} cannot read GTKG input {}: {error}",
            case.id,
            gtkg_input.display()
        )
    })?;
    let gtkg_accepted = match case.gtkg_mode.as_str() {
        "concept" => parse_okf_concept(&source).is_ok(),
        "document" => parse_okf(&source).is_ok(),
        _ => return Err(format!("case {} has an invalid gtkg_mode", case.id)),
    };
    let output = Command::new("cargo")
        .current_dir(checkout)
        .args([
            "run",
            "--locked",
            "-q",
            "-p",
            "okf",
            "--no-default-features",
            "--features",
            "validator",
            "--",
            "validate",
        ])
        .arg(&bundle)
        .arg("--json")
        .output()
        .map_err(|error| {
            format!(
                "case {} cannot invoke pinned reference runner: {error}",
                case.id
            )
        })?;
    let runner: ReferenceRunnerReport =
        serde_json::from_slice(&output.stdout).map_err(|error| {
            format!(
                "case {} reference runner did not emit a valid JSON report: {error}; stderr: {}",
                case.id,
                String::from_utf8_lossy(&output.stderr).trim()
            )
        })?;
    if output.status.success() != runner.conformant {
        return Err(format!(
            "case {} reference runner exit status {} disagrees with JSON conformant={}",
            case.id, output.status, runner.conformant
        ));
    }
    let expected_gtkg = case.expected_gtkg == "accept";
    let expected_runner = case.expected_runner == "conformant";
    let disposition_matches =
        gtkg_accepted == expected_gtkg && runner.conformant == expected_runner;
    let runner_errors_match_expected_disposition =
        runner_errors_match_frozen_disposition(expected_runner, runner.error_count);
    Ok(CurrentNormativeCaseReceipt {
        id: case.id.clone(),
        gtkg_accepted,
        expected_gtkg: case.expected_gtkg.clone(),
        runner_conformant: runner.conformant,
        expected_runner: case.expected_runner.clone(),
        runner_error_count: runner.error_count,
        runner_warning_count: runner.warning_count,
        disposition_matches,
        runner_errors_match_expected_disposition,
    })
}

fn runner_errors_match_frozen_disposition(expected_conformant: bool, error_count: u64) -> bool {
    if expected_conformant {
        error_count == 0
    } else {
        error_count > 0
    }
}

fn validate_normative_manifest(
    corpus: &CurrentNormativeCorpusManifest,
    pin: &OkfSpecPinV2,
) -> Result<(), String> {
    let scalar_fields_valid = corpus.schema_version == CURRENT_NORMATIVE_CORPUS_SCHEMA
        && !corpus.corpus_id.trim().is_empty()
        && corpus.status == "frozen_for_execution"
        && corpus.boundary.contains("not a Google certification")
        && corpus.raw_spec.path == CURRENT_NORMATIVE_RAW_SPEC
        && corpus.raw_spec.manifest == CURRENT_NORMATIVE_RAW_MANIFEST
        && corpus.raw_spec.upstream_commit == pin.upstream_commit
        && corpus.raw_spec.sha256 == pin.raw_sha256
        && corpus.reference_runner_manifest == CURRENT_NORMATIVE_RUNNER_MANIFEST
        && corpus.fixture_root == CURRENT_NORMATIVE_FIXTURE_ROOT
        && corpus.receipt_path == CURRENT_NORMATIVE_RECEIPT_PATH
        && corpus.cases.len() == 13;
    if !scalar_fields_valid {
        return Err("current normative corpus manifest does not bind the reviewed schema, exact pin, runner, fixture root, receipt path, and case count".to_owned());
    }
    let mut ids = std::collections::BTreeSet::new();
    let mut families = std::collections::BTreeSet::new();
    for case in &corpus.cases {
        validate_case_shape(case)?;
        if !ids.insert(&case.id) {
            return Err(format!(
                "current normative corpus has duplicate case id {}",
                case.id
            ));
        }
        families.insert(case.family.as_str());
    }
    if REQUIRED_CURRENT_NORMATIVE_FAMILIES
        .iter()
        .any(|family| !families.contains(family))
    {
        return Err(
            "current normative corpus does not cover every required case family".to_owned(),
        );
    }
    Ok(())
}

fn validate_case_shape(case: &CurrentNormativeCase) -> Result<(), String> {
    let expected_shape = !case.id.trim().is_empty()
        && !case.family.trim().is_empty()
        && !case.bundle.trim().is_empty()
        && !case.gtkg_input.trim().is_empty()
        && matches!(case.gtkg_mode.as_str(), "concept" | "document")
        && case.spec_section.starts_with('§')
        && case.line_start > 0
        && case.line_start <= case.line_end
        && !case.input_digests.is_empty()
        && matches!(case.expected_gtkg.as_str(), "accept" | "reject")
        && matches!(
            case.expected_runner.as_str(),
            "conformant" | "nonconformant"
        )
        && !case.bundle.to_ascii_lowercase().contains("h01")
        && !case.gtkg_input.to_ascii_lowercase().contains("h01");
    if !expected_shape {
        return Err(format!("case {} has an invalid frozen shape", case.id));
    }
    for digest in &case.input_digests {
        if digest.path.trim().is_empty()
            || digest.path.to_ascii_lowercase().contains("h01")
            || !digest.sha256.starts_with("sha256:")
            || digest.sha256.len() != 71
            || !digest.sha256[7..]
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(format!(
                "case {} has an invalid input digest declaration",
                case.id
            ));
        }
    }
    Ok(())
}

fn validate_spec_line_ranges(
    raw_spec: &Path,
    cases: &[CurrentNormativeCase],
) -> Result<(), String> {
    let text = fs::read_to_string(raw_spec).map_err(|error| {
        format!(
            "cannot read pinned raw spec {} for cited line validation: {error}",
            raw_spec.display()
        )
    })?;
    let line_count = text.lines().count();
    for case in cases {
        if case.line_end > line_count {
            return Err(format!(
                "case {} cites {} lines {}-{} beyond pinned raw spec length {line_count}",
                case.id, case.spec_section, case.line_start, case.line_end
            ));
        }
    }
    Ok(())
}

fn safe_child_path(root: &Path, relative: &str) -> Result<PathBuf, String> {
    let path = Path::new(relative);
    if path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(format!("corpus relative path {relative:?} is unsafe"));
    }
    Ok(root.join(path))
}

fn write_normative_receipt(path: &Path, receipt: &serde_json::Value) -> std::io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "receipt path has no parent",
        )
    })?;
    if !parent.is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "receipt parent directory is missing",
        ));
    }
    let bytes = serde_json::to_vec_pretty(receipt).map_err(std::io::Error::other)?;
    fs::write(path, bytes)
}

fn status_name(status: OkfAxisStatusV2) -> &'static str {
    match status {
        OkfAxisStatusV2::Passed => "passed",
        OkfAxisStatusV2::Failed => "failed",
        OkfAxisStatusV2::Blocked => "blocked",
        OkfAxisStatusV2::NotRun => "not_run",
        OkfAxisStatusV2::Stale => "stale",
        OkfAxisStatusV2::CannotConfirm => "cannot_confirm",
        OkfAxisStatusV2::Invalid => "invalid",
    }
}

fn normative_corpus_failure(
    status: OkfAxisStatusV2,
    code: &'static str,
    detail: String,
) -> CurrentNormativeCorpusValidationV2 {
    let evidence = OkfAxisEvidenceV2 {
        status,
        code,
        detail,
    };
    CurrentNormativeCorpusValidationV2 {
        official_format: evidence.clone(),
        reference_compatibility: evidence,
        case_count: 0,
        receipt_path: None,
    }
}

#[cfg(test)]
mod tests {
    use super::runner_errors_match_frozen_disposition;

    #[test]
    fn runner_errors_are_allowed_only_for_a_frozen_nonconformant_disposition() {
        assert!(runner_errors_match_frozen_disposition(true, 0));
        assert!(!runner_errors_match_frozen_disposition(true, 1));
        assert!(runner_errors_match_frozen_disposition(false, 1));
        assert!(!runner_errors_match_frozen_disposition(false, 0));
    }
}
