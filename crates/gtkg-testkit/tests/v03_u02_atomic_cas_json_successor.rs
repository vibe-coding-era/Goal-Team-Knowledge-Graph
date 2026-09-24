use std::fs;

use gtkg_core::v03::assistant_install::{
    AssistantInstallErrorV2, AssistantKindV1, AssistantManagedBlockV2, AssistantScopeV1,
    apply_assistant_install_v2, apply_assistant_install_v2_with_precommit_hook,
    assistant_target_file_v2, preview_assistant_install_v2, uninstall_assistant_block_v2,
};
use sha2::{Digest, Sha256};
use tempfile::tempdir;

fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn cursor_block() -> AssistantManagedBlockV2 {
    AssistantManagedBlockV2 {
        assistant: AssistantKindV1::Cursor,
        scope: AssistantScopeV1::Project,
        profile_id: "core".to_owned(),
    }
}

#[cfg(unix)]
#[test]
fn successor_atomic_exchange_detects_the_final_check_replace_race() {
    let root = tempdir().unwrap();
    let target = root.path().join(assistant_target_file_v2(
        AssistantKindV1::Cursor,
        AssistantScopeV1::Project,
    ));
    fs::create_dir_all(target.parent().unwrap()).unwrap();
    let original = br#"{"custom":{"keep":true}}"#;
    fs::write(&target, original).unwrap();
    let preview = preview_assistant_install_v2(root.path(), &sha256(original), &cursor_block())
        .expect("preview exact original inode");

    let result =
        apply_assistant_install_v2_with_precommit_hook(root.path(), &preview, |target_path| {
            let replacement = target_path.with_extension("race-replacement");
            fs::write(&replacement, original).unwrap();
            fs::rename(replacement, target_path).unwrap();
        });
    assert_eq!(result, Err(AssistantInstallErrorV2::CasConflict));
    assert_eq!(fs::read(&target).unwrap(), original);
    assert!(
        fs::read_dir(target.parent().unwrap())
            .unwrap()
            .all(|entry| !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".gtkg-"))
    );
}

#[test]
fn successor_json_patch_preserves_all_non_managed_bytes_and_uninstall_is_exact() {
    let root = tempdir().unwrap();
    let target = root.path().join(assistant_target_file_v2(
        AssistantKindV1::Cursor,
        AssistantScopeV1::Project,
    ));
    fs::create_dir_all(target.parent().unwrap()).unwrap();
    let original = b"{\n  \"z\" : 1,\n  \"custom\" : { \"keep\" : true },\n  \"a\" : 2\n}";
    let preserved = b"\"custom\" : { \"keep\" : true }";
    fs::write(&target, original).unwrap();

    let preview = preview_assistant_install_v2(root.path(), &sha256(original), &cursor_block())
        .expect("native JSON preview");
    let receipt = apply_assistant_install_v2(root.path(), &preview).expect("native JSON apply");
    let installed = fs::read(&target).unwrap();
    assert!(
        installed
            .windows(preserved.len())
            .any(|window| window == preserved)
    );

    uninstall_assistant_block_v2(root.path(), &receipt.after_sha256, &cursor_block())
        .expect("exact managed-entry uninstall");
    assert_eq!(fs::read(&target).unwrap(), original);
}
