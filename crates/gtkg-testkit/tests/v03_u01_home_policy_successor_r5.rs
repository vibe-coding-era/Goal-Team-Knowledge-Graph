//! U01 r5: mutable HOME must not control isolated-root authority.

use std::path::Path;
use std::process::Command;

use gtkg_core::v03::installer::{InstallErrorV1, create_isolated_root_v1};

const CHILD_ENV: &str = "GTKG_U01_R5_HOME_CHILD";

fn run_child(home: Option<&Path>) {
    let executable = std::env::current_exe().unwrap();
    let mut command = Command::new(executable);
    command
        .arg("--exact")
        .arg("u01_r5_child_home_environment_does_not_change_system_temp_capability")
        .arg("--nocapture")
        .env(CHILD_ENV, "1");
    match home {
        Some(home) => {
            command.env("HOME", home);
        }
        None => {
            command.env_remove("HOME");
        }
    }
    let status = command.status().unwrap();
    assert!(status.success(), "child HOME policy check failed: {status}");
}

#[test]
fn u01_r5_parent_policy_is_independent_of_unset_or_forged_home() {
    if std::env::var_os(CHILD_ENV).is_some() {
        return;
    }
    run_child(None);
    run_child(Some(Path::new("/")));
    run_child(Some(Path::new("/definitely-forged-gtkg-home")));
}

#[test]
fn u01_r5_rejects_system_and_user_parents_without_writing_them() {
    assert_eq!(
        create_isolated_root_v1(Path::new("/")),
        Err(InstallErrorV1::IsolationRequired)
    );
    let user_parent = tempfile::tempdir_in(Path::new(env!("CARGO_MANIFEST_DIR"))).unwrap();
    assert_eq!(
        create_isolated_root_v1(user_parent.path()),
        Err(InstallErrorV1::IsolationRequired)
    );
    assert_eq!(fs_entry_count(user_parent.path()), 0);
}

#[test]
fn u01_r5_child_home_environment_does_not_change_system_temp_capability() {
    if std::env::var_os(CHILD_ENV).is_none() {
        return;
    }
    let parent = tempfile::tempdir().unwrap();
    let root = create_isolated_root_v1(parent.path()).expect("system temporary parent is allowed");
    assert!(root.path().is_dir());
    assert_eq!(fs_entry_count(root.path()), 0);
}

fn fs_entry_count(path: &Path) -> usize {
    std::fs::read_dir(path).unwrap().count()
}
