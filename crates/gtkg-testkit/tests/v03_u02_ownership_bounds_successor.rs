use std::fs;

use gtkg_core::v03::assistant_install::{
    AssistantInstallErrorV2, AssistantKindV1, AssistantManagedBlockV2, AssistantScopeV1,
    MAX_ASSISTANT_CONFIG_BYTES_V2, apply_assistant_install_v2,
    apply_assistant_install_v2_with_precommit_hook, assistant_target_file_v2,
    preview_assistant_install_v2, uninstall_assistant_block_with_receipt_v2,
};
use sha2::{Digest, Sha256};
use tempfile::tempdir;

fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn block() -> AssistantManagedBlockV2 {
    AssistantManagedBlockV2 {
        assistant: AssistantKindV1::Cursor,
        scope: AssistantScopeV1::Project,
        profile_id: "core".to_owned(),
    }
}

#[test]
fn successor_recursive_duplicate_keys_fail_closed_before_ownership_matching() {
    let root = tempdir().unwrap();
    let target = root.path().join(assistant_target_file_v2(
        AssistantKindV1::Cursor,
        AssistantScopeV1::Project,
    ));
    fs::create_dir_all(target.parent().unwrap()).unwrap();
    let duplicate = br#"{"mcpServers":{"gtkg":{"command":"user","command":"gtkg","args":["mcp","serve","--protocol","v2","--profile","core","--stdio"],"env":{"GTKG_MANAGED_CONFIG_SCHEMA":"user","GTKG_MANAGED_CONFIG_SCHEMA":"gtkg.assistant-native-entry/v2","GTKG_MANAGED_PARENT_CREATED":"0","GTKG_MANAGED_FILE_CREATED":"0"}}}}"#;
    fs::write(&target, duplicate).unwrap();
    assert_eq!(
        preview_assistant_install_v2(root.path(), &sha256(duplicate), &block()),
        Err(AssistantInstallErrorV2::InvalidNativeConfig)
    );
}

#[cfg(unix)]
#[test]
fn successor_fresh_uninstall_keeps_safe_empty_residue_without_racy_unlink() {
    let root = tempdir().unwrap();
    let target = root.path().join(assistant_target_file_v2(
        AssistantKindV1::Cursor,
        AssistantScopeV1::Project,
    ));
    let preview = preview_assistant_install_v2(root.path(), &sha256(b""), &block()).unwrap();
    let installed = apply_assistant_install_v2(root.path(), &preview).unwrap();
    assert!(target.is_file());
    assert_eq!(installed.directory_create_count, 1);

    let removed = uninstall_assistant_block_with_receipt_v2(root.path(), &installed).unwrap();
    assert!(!removed.target_removed);
    assert_eq!(removed.directory_remove_count, 0);
    assert!(target.is_file());
    assert_eq!(fs::read(&target).unwrap(), b"{}");
    assert!(target.parent().unwrap().is_dir());
}

#[test]
fn successor_preexisting_empty_file_is_not_laundered_as_gtkg_created() {
    let root = tempdir().unwrap();
    let target = root.path().join(assistant_target_file_v2(
        AssistantKindV1::Cursor,
        AssistantScopeV1::Project,
    ));
    fs::create_dir_all(target.parent().unwrap()).unwrap();
    fs::write(&target, b"").unwrap();
    let preview = preview_assistant_install_v2(root.path(), &sha256(b""), &block()).unwrap();
    let installed = apply_assistant_install_v2(root.path(), &preview).unwrap();
    let removed = uninstall_assistant_block_with_receipt_v2(root.path(), &installed).unwrap();
    assert!(!removed.target_removed);
    assert!(target.is_file());
    assert_eq!(fs::read(&target).unwrap(), b"");
}

#[test]
fn successor_preview_redacts_values_and_bounds_profile_and_concurrent_growth() {
    let root = tempdir().unwrap();
    let target = root.path().join(assistant_target_file_v2(
        AssistantKindV1::Cursor,
        AssistantScopeV1::Project,
    ));
    fs::create_dir_all(target.parent().unwrap()).unwrap();
    let secret = br#"{"api_token":"do-not-print"}"#;
    fs::write(&target, secret).unwrap();
    let preview = preview_assistant_install_v2(root.path(), &sha256(secret), &block()).unwrap();
    assert!(!format!("{preview:?}").contains("do-not-print"));

    let mut long_profile = block();
    long_profile.profile_id = "a".repeat(65);
    assert_eq!(
        preview_assistant_install_v2(root.path(), &sha256(secret), &long_profile),
        Err(AssistantInstallErrorV2::InvalidManagedBlock)
    );

    fs::write(
        &target,
        vec![b' '; (MAX_ASSISTANT_CONFIG_BYTES_V2 + 1) as usize],
    )
    .unwrap();
    assert_eq!(
        preview_assistant_install_v2(root.path(), &sha256(&fs::read(&target).unwrap()), &block()),
        Err(AssistantInstallErrorV2::InvalidNativeConfig)
    );
}

#[cfg(unix)]
#[test]
fn successor_missing_target_noreplace_preserves_concurrent_creation() {
    let root = tempdir().unwrap();
    let target = root.path().join(assistant_target_file_v2(
        AssistantKindV1::Cursor,
        AssistantScopeV1::Project,
    ));
    fs::create_dir_all(target.parent().unwrap()).unwrap();
    let concurrent = br#"{"custom":{"concurrent":true}}"#;
    let preview = preview_assistant_install_v2(root.path(), &sha256(b""), &block()).unwrap();
    let result =
        apply_assistant_install_v2_with_precommit_hook(root.path(), &preview, |target_path| {
            fs::write(target_path, concurrent).unwrap()
        });
    assert_eq!(result, Err(AssistantInstallErrorV2::CasConflict));
    assert_eq!(fs::read(&target).unwrap(), concurrent);
}

#[test]
fn successor_install_receipt_cannot_be_replayed_against_an_identical_other_root() {
    let root_a = tempdir().unwrap();
    let root_b = tempdir().unwrap();
    let preview_a = preview_assistant_install_v2(root_a.path(), &sha256(b""), &block()).unwrap();
    let preview_b = preview_assistant_install_v2(root_b.path(), &sha256(b""), &block()).unwrap();
    let receipt_a = apply_assistant_install_v2(root_a.path(), &preview_a).unwrap();
    let receipt_b = apply_assistant_install_v2(root_b.path(), &preview_b).unwrap();
    assert_eq!(receipt_a.after_sha256, receipt_b.after_sha256);

    let target_b = root_b.path().join(assistant_target_file_v2(
        AssistantKindV1::Cursor,
        AssistantScopeV1::Project,
    ));
    let before = fs::read(&target_b).unwrap();
    assert_eq!(
        uninstall_assistant_block_with_receipt_v2(root_b.path(), &receipt_a),
        Err(AssistantInstallErrorV2::CasConflict)
    );
    assert_eq!(fs::read(&target_b).unwrap(), before);

    uninstall_assistant_block_with_receipt_v2(root_b.path(), &receipt_b).unwrap();
}
