//! U01 r7 fixed-system-temp and use-time parent-binding contract.

#[cfg(unix)]
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::{PermissionsExt, symlink};
#[cfg(unix)]
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::process::Command;

#[cfg(unix)]
use gtkg_core::v03::installer::{
    InstallErrorV1, InstallManifestV1, create_isolated_root_v1, preview_install_with_capability_v1,
};

#[cfg(unix)]
const CHILD_ENV: &str = "GTKG_U01_R7_TMPDIR_CHILD";

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
        .prefix("gtkg-u01-r7-")
        .tempdir_in(fixed_system_temp_root())
        .unwrap()
}

#[cfg(unix)]
fn run_child(tmpdir: Option<&Path>) {
    let executable = std::env::current_exe().unwrap();
    let mut command = Command::new(executable);
    command
        .arg("--exact")
        .arg("u01_r7_child_fixed_system_temp_is_independent_of_tmpdir")
        .arg("--nocapture")
        .env(CHILD_ENV, "1");
    match tmpdir {
        Some(tmpdir) => {
            command.env("TMPDIR", tmpdir);
        }
        None => {
            command.env_remove("TMPDIR");
        }
    }
    let status = command.status().unwrap();
    assert!(
        status.success(),
        "child TMPDIR policy check failed: {status}"
    );
}

#[cfg(unix)]
#[test]
fn u01_r7_fixed_temp_parent_policy_is_independent_of_unset_or_forged_tmpdir() {
    if std::env::var_os(CHILD_ENV).is_some() {
        return;
    }
    run_child(None);
    run_child(Some(Path::new("/definitely-forged-gtkg-tmpdir")));
    run_child(Some(Path::new("/private/tmp")));
}

#[cfg(unix)]
#[test]
fn u01_r7_rejects_user_parent_while_accepting_only_fixed_system_temp_descendant() {
    let user_parent = tempfile::tempdir_in(Path::new(env!("CARGO_MANIFEST_DIR"))).unwrap();
    assert_eq!(
        create_isolated_root_v1(user_parent.path()),
        Err(InstallErrorV1::IsolationRequired)
    );
    assert_eq!(fs::read_dir(user_parent.path()).unwrap().count(), 0);

    let parent = fixed_parent();
    let root = create_isolated_root_v1(parent.path()).unwrap();
    let mode = fs::metadata(root.path()).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o700);
}

#[cfg(unix)]
#[test]
fn u01_r7_use_time_parent_swap_rejects_before_install_writes() {
    let outer = fixed_parent();
    let authorized = outer.path().join("authorized");
    let moved = outer.path().join("moved-original");
    let attacker = outer.path().join("attacker");
    fs::create_dir(&authorized).unwrap();
    fs::set_permissions(&authorized, fs::Permissions::from_mode(0o700)).unwrap();
    fs::create_dir(&attacker).unwrap();
    fs::set_permissions(&attacker, fs::Permissions::from_mode(0o700)).unwrap();
    let root = create_isolated_root_v1(&authorized).unwrap();
    let child_name = root.path().file_name().unwrap().to_owned();

    fs::rename(&authorized, &moved).unwrap();
    symlink(&attacker, &authorized).unwrap();
    assert_eq!(
        preview_install_with_capability_v1(&fixture("v1"), &root, &manifest("v1")),
        Err(InstallErrorV1::CapabilityMismatch)
    );
    assert_eq!(fs::read_dir(&attacker).unwrap().count(), 0);
    assert_eq!(fs::read_dir(moved.join(child_name)).unwrap().count(), 0);
}

#[cfg(unix)]
#[test]
fn u01_r7_child_fixed_system_temp_is_independent_of_tmpdir() {
    if std::env::var_os(CHILD_ENV).is_none() {
        return;
    }
    let parent = fixed_parent();
    let root = create_isolated_root_v1(parent.path()).expect("fixed system temp parent is allowed");
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
}

#[cfg(not(unix))]
#[test]
fn u01_r7_fixed_temp_parent_requires_unix_dirfd_semantics() {
    assert!(true);
}
