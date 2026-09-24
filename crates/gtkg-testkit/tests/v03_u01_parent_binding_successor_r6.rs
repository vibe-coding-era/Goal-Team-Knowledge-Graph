//! U01 r6 parent-fd and parent-trust hardening contract.

#[cfg(unix)]
use std::ffi::OsStr;
#[cfg(unix)]
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::{PermissionsExt, symlink};
#[cfg(unix)]
use std::path::Path;

#[cfg(unix)]
use gtkg_core::v03::installer::{
    InstallErrorV1, create_isolated_root_v1,
    create_isolated_root_v1_with_post_mkdir_hook,
};

#[cfg(unix)]
fn create_owner_only_directory(path: &Path) {
    fs::create_dir(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

#[cfg(unix)]
fn entry_count(path: &Path) -> usize {
    fs::read_dir(path).unwrap().count()
}

#[cfg(unix)]
#[test]
fn u01_r6_parent_swap_after_mkdir_is_rejected_and_original_child_is_cleaned() {
    let outer = tempfile::tempdir().unwrap();
    let authorized = outer.path().join("authorized");
    let moved = outer.path().join("moved-original");
    let attacker = outer.path().join("attacker");
    create_owner_only_directory(&authorized);
    create_owner_only_directory(&attacker);

    let result = create_isolated_root_v1_with_post_mkdir_hook(
        &authorized,
        |parent: &Path, child: &OsStr| {
            fs::rename(parent, &moved).unwrap();
            fs::create_dir(attacker.join(child)).unwrap();
            symlink(&attacker, parent).unwrap();
        },
    );
    assert_eq!(result, Err(InstallErrorV1::CapabilityMismatch));
    assert_eq!(entry_count(&moved), 0, "original parent has no orphan child");
    assert_eq!(entry_count(&attacker), 1, "only test-created attacker child exists");
    assert!(authorized.is_symlink());
}

#[cfg(unix)]
#[test]
fn u01_r6_symlink_and_group_or_world_writable_system_temp_descendants_reject_zero_write() {
    let outer = tempfile::tempdir().unwrap();
    let real = outer.path().join("real-parent");
    let linked = outer.path().join("linked-parent");
    create_owner_only_directory(&real);
    symlink(&real, &linked).unwrap();
    assert_eq!(
        create_isolated_root_v1(&linked),
        Err(InstallErrorV1::PathEscape)
    );
    assert_eq!(entry_count(&real), 0);

    for (name, mode) in [("group-writable", 0o770), ("world-writable", 0o777)] {
        let ambiguous = outer.path().join(name);
        fs::create_dir(&ambiguous).unwrap();
        fs::set_permissions(&ambiguous, fs::Permissions::from_mode(mode)).unwrap();
        assert_eq!(
            create_isolated_root_v1(&ambiguous),
            Err(InstallErrorV1::IsolationRequired)
        );
        assert_eq!(entry_count(&ambiguous), 0, "{name} parent remains unchanged");
    }
}

#[cfg(unix)]
#[test]
fn u01_r6_owner_only_system_temp_parent_creates_a_0700_child() {
    let parent = tempfile::tempdir().unwrap();
    let root = create_isolated_root_v1(parent.path()).unwrap();
    let mode = fs::metadata(root.path()).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o700);
    assert_eq!(entry_count(root.path()), 0);
}

#[cfg(not(unix))]
#[test]
fn u01_r6_parent_binding_requires_unix_dirfd_semantics() {
    assert!(true);
}
