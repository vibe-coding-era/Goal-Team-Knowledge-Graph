//! Immutable U01 local installer contract.

use std::fs;
use std::path::{Path, PathBuf};

use gtkg_core::v03::installer::{
    InstallErrorV1, InstallManifestV1, apply_install_v1, preview_install_v1,
    preview_rollback_v1, preview_upgrade_v1, uninstall_v1,
};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

fn fixture(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures/v03_u01")
        .join(relative)
}

fn manifest(version: &str) -> InstallManifestV1 {
    let bytes = fs::read(fixture(&format!("{version}/install-manifest.json"))).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn fresh_root() -> TempDir {
    tempfile::tempdir().unwrap()
}

#[test]
fn u01_dry_run_fresh_upgrade_restricted_rollback_and_exact_uninstall() {
    let target = fresh_root();
    fs::write(target.path().join("keep.txt"), b"user-owned\n").unwrap();
    let v1 = manifest("v1");

    let dry_run = preview_install_v1(&fixture("v1"), target.path(), &v1).unwrap();
    assert_eq!(dry_run.write_count(), 0);
    assert!(!target.path().join("bin/gtkg").exists());
    assert!(!target.path().join(".gtkg-install/manifest.json").exists());

    let installed = apply_install_v1(target.path(), &dry_run).unwrap();
    assert!(installed.readback_verified);
    assert_eq!(fs::read(target.path().join("bin/gtkg")).unwrap(), b"gtkg fixture binary v1\n");
    assert_eq!(fs::read(target.path().join("keep.txt")).unwrap(), b"user-owned\n");
    assert!(target.path().join(".gtkg-install/manifest.json").is_file());

    assert_eq!(
        preview_install_v1(&fixture("v1"), target.path(), &v1),
        Err(InstallErrorV1::NoClobber)
    );

    let v2 = manifest("v2");
    let upgrade_preview = preview_upgrade_v1(&fixture("v2"), target.path(), &v2).unwrap();
    let upgraded = apply_install_v1(target.path(), &upgrade_preview).unwrap();
    assert_eq!(upgraded.previous_manifest_sha256, Some(installed.manifest_sha256.clone()));
    assert_eq!(fs::read(target.path().join("bin/gtkg")).unwrap(), b"gtkg fixture binary v2\n");
    assert!(!target.path().join("share/gtkg/README.txt").exists());
    assert!(target.path().join("share/gtkg/UPGRADE.txt").is_file());

    let rollback_preview = preview_rollback_v1(&fixture("v1"), target.path(), &v1, &upgraded).unwrap();
    let rolled_back = apply_install_v1(target.path(), &rollback_preview).unwrap();
    assert_eq!(rolled_back.manifest_sha256, installed.manifest_sha256);
    assert_eq!(fs::read(target.path().join("bin/gtkg")).unwrap(), b"gtkg fixture binary v1\n");
    assert!(target.path().join("share/gtkg/README.txt").is_file());
    assert!(!target.path().join("share/gtkg/UPGRADE.txt").exists());

    let removed = uninstall_v1(target.path(), &rolled_back).unwrap();
    assert!(removed.readback_verified);
    assert!(!target.path().join("bin/gtkg").exists());
    assert!(!target.path().join("share/gtkg/README.txt").exists());
    assert!(!target.path().join(".gtkg-install/manifest.json").exists());
    assert_eq!(fs::read(target.path().join("keep.txt")).unwrap(), b"user-owned\n");
}

#[cfg(unix)]
#[test]
fn u01_rejects_symlink_hardlink_cas_and_unmanaged_upgrade_destination() {
    use std::os::unix::fs::symlink;

    let v1 = manifest("v1");
    let v2 = manifest("v2");

    let symlink_target = fresh_root();
    fs::create_dir(symlink_target.path().join("outside")).unwrap();
    symlink(symlink_target.path().join("outside"), symlink_target.path().join("bin")).unwrap();
    assert_eq!(
        preview_install_v1(&fixture("v1"), symlink_target.path(), &v1),
        Err(InstallErrorV1::PathEscape)
    );

    let hardlink_target = fresh_root();
    fs::create_dir(hardlink_target.path().join("bin")).unwrap();
    fs::write(hardlink_target.path().join("user-file"), b"do not replace\n").unwrap();
    fs::hard_link(
        hardlink_target.path().join("user-file"),
        hardlink_target.path().join("bin/gtkg"),
    )
    .unwrap();
    assert_eq!(
        preview_install_v1(&fixture("v1"), hardlink_target.path(), &v1),
        Err(InstallErrorV1::UnsafeTarget)
    );

    let cas_target = fresh_root();
    let preview = preview_install_v1(&fixture("v1"), cas_target.path(), &v1).unwrap();
    fs::create_dir(cas_target.path().join("bin")).unwrap();
    fs::write(cas_target.path().join("bin/gtkg"), b"raced user file\n").unwrap();
    assert_eq!(
        apply_install_v1(cas_target.path(), &preview),
        Err(InstallErrorV1::CasConflict)
    );
    assert_eq!(
        fs::read(cas_target.path().join("bin/gtkg")).unwrap(),
        b"raced user file\n"
    );

    let upgrade_target = fresh_root();
    let installed = apply_install_v1(
        upgrade_target.path(),
        &preview_install_v1(&fixture("v1"), upgrade_target.path(), &v1).unwrap(),
    )
    .unwrap();
    assert_eq!(installed.manifest_sha256, sha256(&serde_json::to_vec(&v1).unwrap()));
    fs::create_dir_all(upgrade_target.path().join("share/gtkg")).unwrap();
    fs::write(
        upgrade_target.path().join("share/gtkg/UPGRADE.txt"),
        b"user-owned upgrade note\n",
    )
    .unwrap();
    assert_eq!(
        preview_upgrade_v1(&fixture("v2"), upgrade_target.path(), &v2),
        Err(InstallErrorV1::NoClobber)
    );
}
