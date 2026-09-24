//! Rustfmt-clean fixed-root lifecycle successor for U01 r7.

#[cfg(unix)]
use std::fs;
#[cfg(unix)]
use std::path::{Path, PathBuf};

#[cfg(unix)]
use gtkg_core::v03::installer::{
    InstallErrorV1, InstallManifestV1, apply_install_with_capability_v1,
    apply_install_with_cleanup_fault_v1, create_isolated_root_v1,
    preview_install_with_capability_v1, preview_rollback_with_capability_v1,
    preview_upgrade_with_capability_v1, uninstall_with_capability_v1,
};

#[cfg(unix)]
fn fixed_system_temp_root() -> &'static Path {
    if cfg!(target_os = "macos") {
        Path::new("/private/tmp")
    } else {
        Path::new("/tmp")
    }
}

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
fn fixed_parent() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("gtkg-u01-r7-lifecycle-")
        .tempdir_in(fixed_system_temp_root())
        .unwrap()
}

#[cfg(unix)]
#[test]
fn u01_r7_fixed_root_dry_run_fault_rollback_upgrade_rollback_uninstall_and_reinstall() {
    let parent = fixed_parent();
    let root = create_isolated_root_v1(parent.path()).unwrap();
    let v1 = manifest("v1");
    let v2 = manifest("v2");

    let dry_run = preview_install_with_capability_v1(&fixture("v1"), &root, &v1).unwrap();
    assert_eq!(dry_run.write_count(), 0);
    assert!(!root.path().join("bin/gtkg").exists());
    let installed = apply_install_with_capability_v1(&root, &dry_run).unwrap();

    let fault_preview = preview_upgrade_with_capability_v1(&fixture("v2"), &root, &v2).unwrap();
    assert_eq!(
        apply_install_with_cleanup_fault_v1(&root, &fault_preview, 1),
        Err(InstallErrorV1::TestFaultInjected)
    );
    assert_eq!(
        fs::read(root.path().join("bin/gtkg")).unwrap(),
        b"gtkg fixture binary v1\n"
    );
    assert!(root.path().join("share/gtkg/README.txt").is_file());
    assert!(!root.path().join("share/gtkg/UPGRADE.txt").exists());

    let upgrade_preview = preview_upgrade_with_capability_v1(&fixture("v2"), &root, &v2).unwrap();
    let upgraded = apply_install_with_capability_v1(&root, &upgrade_preview).unwrap();
    assert_eq!(
        upgraded.previous_manifest_sha256,
        Some(installed.manifest_sha256.clone())
    );
    assert!(root.path().join("share/gtkg/UPGRADE.txt").is_file());

    let rollback_preview =
        preview_rollback_with_capability_v1(&fixture("v1"), &root, &v1, &upgraded).unwrap();
    let rolled_back = apply_install_with_capability_v1(&root, &rollback_preview).unwrap();
    assert_eq!(rolled_back.manifest_sha256, installed.manifest_sha256);
    assert!(root.path().join("share/gtkg/README.txt").is_file());
    assert!(!root.path().join("share/gtkg/UPGRADE.txt").exists());

    let removed = uninstall_with_capability_v1(&root, &rolled_back).unwrap();
    assert!(removed.readback_verified);
    assert!(!root.path().join(".gtkg-install").exists());
    assert!(!root.path().join("bin/gtkg").exists());
    assert!(
        apply_install_with_capability_v1(
            &root,
            &preview_install_with_capability_v1(&fixture("v1"), &root, &v1).unwrap()
        )
        .unwrap()
        .readback_verified
    );
}

#[cfg(not(unix))]
#[test]
fn u01_r7_fixed_root_lifecycle_requires_unix_dirfd_semantics() {
    assert!(true);
}
