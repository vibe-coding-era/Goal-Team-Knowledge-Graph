//! Post-r1 U01 ownership and rollback hardening checks.

use std::fs;
use std::path::{Path, PathBuf};

use gtkg_core::v03::installer::{
    InstallErrorV1, InstallManifestV1, apply_install_v1, preview_install_v1, preview_rollback_v1,
    preview_upgrade_v1, uninstall_v1,
};

fn fixture(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures/v03_u01")
        .join(relative)
}

fn manifest(version: &str) -> InstallManifestV1 {
    serde_json::from_slice(&fs::read(fixture(&format!("{version}/install-manifest.json"))).unwrap())
        .unwrap()
}

fn install_v1(target: &Path) -> gtkg_core::v03::installer::InstallReceiptV1 {
    let manifest = manifest("v1");
    let preview = preview_install_v1(&fixture("v1"), target, &manifest).unwrap();
    apply_install_v1(target, &preview).unwrap()
}

#[test]
fn u01_rejects_managed_file_drift_and_receipt_manipulation_before_uninstall() {
    let target = tempfile::tempdir().unwrap();
    let receipt = install_v1(target.path());
    fs::write(target.path().join("bin/gtkg"), b"user replacement\n").unwrap();

    assert_eq!(
        uninstall_v1(target.path(), &receipt),
        Err(InstallErrorV1::CasConflict)
    );
    assert_eq!(
        fs::read(target.path().join("bin/gtkg")).unwrap(),
        b"user replacement\n"
    );

    let second_target = tempfile::tempdir().unwrap();
    let mut forged = install_v1(second_target.path());
    forged.managed_files.clear();
    assert_eq!(
        uninstall_v1(second_target.path(), &forged),
        Err(InstallErrorV1::IntegrityMismatch)
    );
    assert!(second_target.path().join("bin/gtkg").is_file());
}

#[test]
fn u01_allows_rollback_only_from_the_state_recorded_upgrade_predecessor() {
    let target = tempfile::tempdir().unwrap();
    let v1 = manifest("v1");
    let installed = install_v1(target.path());
    assert_eq!(
        preview_rollback_v1(&fixture("v1"), target.path(), &v1, &installed),
        Err(InstallErrorV1::RollbackForbidden)
    );

    let v2 = manifest("v2");
    let upgraded = apply_install_v1(
        target.path(),
        &preview_upgrade_v1(&fixture("v2"), target.path(), &v2).unwrap(),
    )
    .unwrap();
    let mut forged = upgraded.clone();
    forged.previous_manifest_sha256 =
        Some("sha256:0000000000000000000000000000000000000000000000000000000000000000".to_owned());
    assert_eq!(
        preview_rollback_v1(&fixture("v1"), target.path(), &v1, &forged),
        Err(InstallErrorV1::RollbackForbidden)
    );
    assert!(preview_rollback_v1(&fixture("v1"), target.path(), &v1, &upgraded).is_ok());
}

#[cfg(unix)]
#[test]
fn u01_rejects_a_symlinked_state_record_before_any_managed_removal() {
    use std::os::unix::fs::symlink;

    let target = tempfile::tempdir().unwrap();
    let receipt = install_v1(target.path());
    let state = target.path().join(".gtkg-install/manifest.json");
    let outside = target.path().join("user-state.json");
    fs::write(&outside, b"user-owned state\n").unwrap();
    fs::remove_file(&state).unwrap();
    symlink(&outside, &state).unwrap();

    assert_eq!(
        uninstall_v1(target.path(), &receipt),
        Err(InstallErrorV1::PathEscape)
    );
    assert!(target.path().join("bin/gtkg").is_file());
    assert_eq!(fs::read(&outside).unwrap(), b"user-owned state\n");
}
