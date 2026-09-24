//! F03 frozen contract: B17 Playwright runtime lock (in-repo, version-pinned).
//!
//! Oracles:
//! (a) the in-repo locked runner `browser/playwright_cli_locked.sh` exists, is
//!     a bash script, and references an exact pinned `@playwright/cli@<version>`
//!     package spec without any floating tag (`@latest`).
//! (b) the git-tracked lock record `browser/playwright_cli.lock.json` parses as
//!     schema `gtkg.playwright-cli-lock/v1` and its `version` field matches the
//!     version pinned inside the locked runner.
//! (c) the lock record carries a parseable UTC resolution timestamp and a
//!     dist integrity field in `sha512-` form.
//! (d) the D05 browser shell contract defaults `PWCLI` to the in-repo locked
//!     runner while preserving the `PWCLI` environment override.

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("gtkg-testkit must live at <repo>/crates/gtkg-testkit")
        .to_owned()
}

fn locked_runner_source() -> String {
    let path = repo_root().join("crates/gtkg-testkit/browser/playwright_cli_locked.sh");
    fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!("locked runner {} must be readable: {error}", path.display())
    })
}

fn extract_pinned_version(runner: &str) -> String {
    let marker = "PINNED_PACKAGE=\"@playwright/cli@";
    let start = runner
        .find(marker)
        .unwrap_or_else(|| panic!("locked runner must pin {marker}<version>\""));
    let rest = &runner[start + marker.len()..];
    let end = rest
        .find('"')
        .expect("pinned package spec must be terminated by a quote");
    let version = &rest[..end];
    assert!(!version.is_empty(), "pinned version must not be empty");
    version.to_owned()
}

#[test]
fn locked_runner_exists_and_pins_exact_version() {
    let runner = locked_runner_source();
    assert!(
        runner.starts_with("#!/usr/bin/env bash"),
        "locked runner must be a bash script"
    );
    assert!(
        !runner.contains("@playwright/cli@latest"),
        "locked runner must not reference @playwright/cli@latest"
    );
    assert!(
        !runner.contains("@latest"),
        "locked runner must not reference any floating @latest tag"
    );
    let version = extract_pinned_version(&runner);
    assert!(
        version
            .chars()
            .all(|character| character.is_ascii_alphanumeric()
                || matches!(character, '.' | '-' | '+')),
        "pinned version must be an exact semver spec, got {version:?}"
    );
    assert!(
        version.split('.').count() >= 3,
        "pinned version must include major.minor.patch, got {version:?}"
    );
}

#[test]
fn lock_record_parses_and_matches_runner_version() {
    let lock_path = repo_root().join("crates/gtkg-testkit/browser/playwright_cli.lock.json");
    let lock: Value =
        serde_json::from_slice(&fs::read(&lock_path).unwrap_or_else(|error| {
            panic!("lock record {} must exist: {error}", lock_path.display())
        }))
        .expect("lock record must parse as JSON");
    assert_eq!(
        lock["schema_version"], "gtkg.playwright-cli-lock/v1",
        "lock record schema drift"
    );
    assert_eq!(
        lock["package"], "@playwright/cli",
        "lock record package drift"
    );
    let runner_version = extract_pinned_version(&locked_runner_source());
    assert_eq!(
        lock["version"].as_str().expect("lock record version"),
        runner_version,
        "lock record version must match the version pinned in the locked runner"
    );
    let resolved_at = lock["resolved_at_utc"]
        .as_str()
        .expect("lock record must carry resolved_at_utc");
    assert!(
        resolved_at.len() == 20
            && resolved_at.ends_with('Z')
            && resolved_at.as_bytes()[4] == b'-'
            && resolved_at.as_bytes()[7] == b'-'
            && resolved_at.as_bytes()[10] == b'T'
            && resolved_at[11..].chars().filter(|c| *c == ':').count() == 2
            && resolved_at[..19]
                .chars()
                .all(|c| c.is_ascii_digit() || matches!(c, '-' | 'T' | ':')),
        "resolved_at_utc must be an ISO-8601 UTC timestamp, got {resolved_at:?}"
    );
    let integrity = lock["dist"]["integrity"]
        .as_str()
        .expect("lock record must carry dist.integrity");
    assert!(
        integrity.starts_with("sha512-") && integrity.len() > 16,
        "dist.integrity must be a sha512 SRI value, got {integrity:?}"
    );
}

#[test]
fn d05_shell_contract_defaults_to_locked_runner() {
    let d05_path = repo_root().join("crates/gtkg-testkit/browser/d05_file_wiki_contract.sh");
    let d05 = fs::read_to_string(&d05_path).expect("d05 shell contract must be readable");
    assert!(
        d05.contains(
            "PWCLI=\"${PWCLI:-$REPO_ROOT/crates/gtkg-testkit/browser/playwright_cli_locked.sh}\""
        ),
        "d05 must default PWCLI to the in-repo locked runner"
    );
    assert!(
        !d05.contains("/.codex/skills/playwright/"),
        "d05 must not depend on the external codex playwright wrapper"
    );
    assert!(
        !d05.contains("@playwright/cli@latest"),
        "d05 must not reference @playwright/cli@latest"
    );
}
