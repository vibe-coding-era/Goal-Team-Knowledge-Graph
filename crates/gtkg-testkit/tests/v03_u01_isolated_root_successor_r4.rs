//! U01 r4 strict isolated-root, rollback-cleanup, and reinstall contract.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use gtkg_core::v03::installer::{
    InstallErrorV1, InstallManifestV1, apply_install_v1,
    apply_install_with_capability_v1, apply_install_with_cleanup_fault_v1,
    create_isolated_root_v1, preview_install_v1, preview_install_with_capability_v1,
    preview_upgrade_with_capability_v1, uninstall_v1, uninstall_with_capability_v1,
};
use sha2::{Digest, Sha256};

fn fixture(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures/v03_u01")
        .join(relative)
}

fn manifest(version: &str) -> InstallManifestV1 {
    serde_json::from_slice(&fs::read(fixture(&format!("{version}/install-manifest.json"))).unwrap())
        .unwrap()
}

fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn isolated_root() -> (tempfile::TempDir, gtkg_core::v03::installer::IsolatedInstallRootV1) {
    let parent = tempfile::tempdir().unwrap();
    let root = create_isolated_root_v1(parent.path()).unwrap();
    (parent, root)
}

fn install_v1(
    root: &gtkg_core::v03::installer::IsolatedInstallRootV1,
) -> gtkg_core::v03::installer::InstallReceiptV1 {
    let manifest = manifest("v1");
    let preview = preview_install_with_capability_v1(&fixture("v1"), root, &manifest).unwrap();
    apply_install_with_capability_v1(root, &preview).unwrap()
}

#[test]
fn u01_r4_raw_target_apis_reject_existing_arbitrary_home_system_and_symlink_roots() {
    let manifest = manifest("v1");
    let arbitrary_parent = tempfile::tempdir_in(Path::new(env!("CARGO_MANIFEST_DIR"))).unwrap();
    assert_eq!(
        preview_install_v1(&fixture("v1"), arbitrary_parent.path(), &manifest),
        Err(InstallErrorV1::IsolationRequired)
    );
    assert_eq!(
        preview_install_v1(&fixture("v1"), Path::new("/"), &manifest),
        Err(InstallErrorV1::IsolationRequired)
    );
    if let Some(home) = std::env::var_os("HOME") {
        assert_eq!(
            preview_install_v1(&fixture("v1"), Path::new(&home), &manifest),
            Err(InstallErrorV1::IsolationRequired)
        );
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;

        let target = tempfile::tempdir().unwrap();
        let link_parent = tempfile::tempdir().unwrap();
        let link = link_parent.path().join("target-link");
        symlink(target.path(), &link).unwrap();
        assert_eq!(
            preview_install_v1(&fixture("v1"), &link, &manifest),
            Err(InstallErrorV1::IsolationRequired)
        );
    }
}

#[test]
fn u01_r4_capability_binds_preview_apply_and_uninstall_to_one_created_root() {
    let (_parent_a, root_a) = isolated_root();
    let (_parent_b, root_b) = isolated_root();
    let manifest = manifest("v1");
    let preview = preview_install_with_capability_v1(&fixture("v1"), &root_a, &manifest).unwrap();
    assert_eq!(
        apply_install_with_capability_v1(&root_b, &preview),
        Err(InstallErrorV1::CapabilityMismatch)
    );
    assert!(!root_a.path().join("bin/gtkg").exists());
    assert!(!root_b.path().join("bin/gtkg").exists());

    let installed = apply_install_with_capability_v1(&root_a, &preview).unwrap();
    assert_eq!(installed.capability_id, root_a.capability_id());
    assert_eq!(installed.capability_digest, root_a.capability_digest());
    assert_eq!(
        uninstall_with_capability_v1(&root_b, &installed),
        Err(InstallErrorV1::CapabilityMismatch)
    );
    assert!(root_a.path().join("bin/gtkg").is_file());
}

#[test]
fn u01_r4_uninstall_requires_private_state_mode_then_removes_state_dir_for_reinstall() {
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    let (_parent, root) = isolated_root();
    let receipt = install_v1(&root);
    #[cfg(unix)]
    {
        let state_dir = root.path().join(".gtkg-install");
        fs::set_permissions(&state_dir, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            uninstall_with_capability_v1(&root, &receipt),
            Err(InstallErrorV1::IntegrityMismatch)
        );
        fs::set_permissions(&state_dir, fs::Permissions::from_mode(0o700)).unwrap();
    }

    let removed = uninstall_with_capability_v1(&root, &receipt).unwrap();
    assert!(removed.readback_verified);
    assert!(!root.path().join(".gtkg-install").exists());
    let reinstalled = install_v1(&root);
    assert!(reinstalled.readback_verified);
    assert!(root.path().join("bin/gtkg").is_file());
}

#[test]
fn u01_r4_backup_cleanup_fault_rolls_back_all_payload_and_state_then_allows_reinstall() {
    let (_parent, root) = isolated_root();
    let v1_receipt = install_v1(&root);
    let v2 = manifest("v2");
    let preview = preview_upgrade_with_capability_v1(&fixture("v2"), &root, &v2).unwrap();
    assert_eq!(
        apply_install_with_cleanup_fault_v1(&root, &preview, 1),
        Err(InstallErrorV1::TestFaultInjected)
    );
    assert_eq!(fs::read(root.path().join("bin/gtkg")).unwrap(), b"gtkg fixture binary v1\n");
    assert!(root.path().join("share/gtkg/README.txt").is_file());
    assert!(!root.path().join("share/gtkg/UPGRADE.txt").exists());
    assert!(root.path().join(".gtkg-install/manifest.json").is_file());
    for directory in [root.path().join("bin"), root.path().join("share/gtkg"), root.path().join(".gtkg-install")] {
        let entries = fs::read_dir(directory).unwrap().count();
        assert!(entries <= 1, "no orphaned transaction temporary entries");
    }

    let removed = uninstall_with_capability_v1(&root, &v1_receipt).unwrap();
    assert!(removed.readback_verified);
    assert!(!root.path().join(".gtkg-install").exists());
    assert!(install_v1(&root).readback_verified);
}

#[test]
fn u01_r4_rejects_group_or_world_writable_payload_modes() {
    let (_parent, root) = isolated_root();
    let mut invalid = manifest("v1");
    invalid.modes = BTreeMap::from([
        ("bin/gtkg".to_owned(), 0o775),
        ("share/gtkg/README.txt".to_owned(), 0o644),
    ]);
    assert_eq!(
        preview_install_with_capability_v1(&fixture("v1"), &root, &invalid),
        Err(InstallErrorV1::InvalidManifest)
    );
    assert_eq!(
        sha256(&fs::read(fixture("v1/bin/gtkg")).unwrap()),
        manifest("v1").digests["bin/gtkg"]
    );
}

#[test]
fn u01_r4_raw_apply_and_uninstall_reject_even_a_capability_bound_preview_and_receipt() {
    let (_parent, root) = isolated_root();
    let manifest = manifest("v1");
    let preview = preview_install_with_capability_v1(&fixture("v1"), &root, &manifest).unwrap();
    assert_eq!(
        apply_install_v1(root.path(), &preview),
        Err(InstallErrorV1::IsolationRequired)
    );
    let receipt = apply_install_with_capability_v1(&root, &preview).unwrap();
    assert_eq!(
        uninstall_v1(root.path(), &receipt),
        Err(InstallErrorV1::IsolationRequired)
    );
    assert!(root.path().join("bin/gtkg").is_file());
}
