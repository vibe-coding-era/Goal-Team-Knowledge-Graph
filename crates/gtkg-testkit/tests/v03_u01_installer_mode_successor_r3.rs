//! U01 private metadata mode hardening successor.

#[cfg(unix)]
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use std::path::{Path, PathBuf};

#[cfg(unix)]
use gtkg_core::v03::installer::{
    InstallErrorV1, InstallManifestV1, apply_install_v1, preview_install_v1, preview_upgrade_v1,
    uninstall_v1,
};

#[cfg(unix)]
fn fixture(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures/v03_u01")
        .join(relative)
}

#[cfg(unix)]
fn manifest(version: &str) -> InstallManifestV1 {
    serde_json::from_slice(&fs::read(fixture(&format!("{version}/install-manifest.json"))).unwrap())
        .unwrap()
}

#[cfg(unix)]
fn install_v1(target: &Path) -> gtkg_core::v03::installer::InstallReceiptV1 {
    let manifest = manifest("v1");
    let preview = preview_install_v1(&fixture("v1"), target, &manifest).unwrap();
    apply_install_v1(target, &preview).unwrap()
}

#[cfg(unix)]
#[test]
fn u01_rejects_nonprivate_state_manifest_and_state_directory_modes() {
    let file_target = tempfile::tempdir().unwrap();
    let receipt = install_v1(file_target.path());
    let state = file_target.path().join(".gtkg-install/manifest.json");
    fs::set_permissions(&state, fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(
        uninstall_v1(file_target.path(), &receipt),
        Err(InstallErrorV1::IntegrityMismatch)
    );
    assert!(file_target.path().join("bin/gtkg").is_file());

    let directory_target = tempfile::tempdir().unwrap();
    install_v1(directory_target.path());
    let state_dir = directory_target.path().join(".gtkg-install");
    fs::set_permissions(&state_dir, fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(
        preview_upgrade_v1(&fixture("v2"), directory_target.path(), &manifest("v2")),
        Err(InstallErrorV1::IntegrityMismatch)
    );
    assert!(directory_target.path().join("bin/gtkg").is_file());
}

#[cfg(not(unix))]
#[test]
fn u01_metadata_mode_successor_is_unavailable_without_unix_dirfd_semantics() {
    assert!(true);
}
