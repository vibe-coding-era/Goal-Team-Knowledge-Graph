//! Fixed-root permission and symlink security companion for U01 r7.

#[cfg(unix)]
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::{PermissionsExt, symlink};
#[cfg(unix)]
use std::path::Path;

#[cfg(unix)]
use gtkg_core::v03::installer::{InstallErrorV1, create_isolated_root_v1};

#[cfg(unix)]
fn fixed_system_temp_root() -> &'static Path {
    if cfg!(target_os = "macos") {
        Path::new("/private/tmp")
    } else {
        Path::new("/tmp")
    }
}

#[cfg(unix)]
fn fixed_parent() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("gtkg-u01-r7-security-")
        .tempdir_in(fixed_system_temp_root())
        .unwrap()
}

#[cfg(unix)]
#[test]
fn u01_r7_fixed_root_rejects_symlink_and_writable_parent_descendants_zero_write() {
    let outer = fixed_parent();
    let real = outer.path().join("real-parent");
    let linked = outer.path().join("linked-parent");
    fs::create_dir(&real).unwrap();
    fs::set_permissions(&real, fs::Permissions::from_mode(0o700)).unwrap();
    symlink(&real, &linked).unwrap();
    assert_eq!(
        create_isolated_root_v1(&linked),
        Err(InstallErrorV1::PathEscape)
    );
    assert_eq!(fs::read_dir(&real).unwrap().count(), 0);

    for (name, mode) in [("group-writable", 0o770), ("world-writable", 0o777)] {
        let parent = outer.path().join(name);
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(mode)).unwrap();
        assert_eq!(
            create_isolated_root_v1(&parent),
            Err(InstallErrorV1::IsolationRequired)
        );
        assert_eq!(fs::read_dir(&parent).unwrap().count(), 0);
    }
}

#[cfg(not(unix))]
#[test]
fn u01_r7_fixed_root_security_requires_unix_dirfd_semantics() {
    assert!(true);
}
