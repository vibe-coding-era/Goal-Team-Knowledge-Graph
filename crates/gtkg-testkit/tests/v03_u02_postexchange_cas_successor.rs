use std::fs;

use gtkg_core::v03::assistant_install::{
    AssistantInstallErrorV2, AssistantKindV1, AssistantManagedBlockV2, AssistantScopeV1,
    apply_assistant_install_v2_with_postexchange_hook, assistant_target_file_v2,
    preview_assistant_install_v2,
};
use sha2::{Digest, Sha256};
use tempfile::tempdir;

fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

#[cfg(unix)]
#[test]
fn successor_postexchange_race_preserves_the_concurrent_target_without_stale_rollback() {
    let root = tempdir().unwrap();
    let target = root.path().join(assistant_target_file_v2(
        AssistantKindV1::Cursor,
        AssistantScopeV1::Project,
    ));
    fs::create_dir_all(target.parent().unwrap()).unwrap();
    let original = br#"{"custom":{"before":true}}"#;
    let concurrent = br#"{"custom":{"concurrent":true}}"#;
    fs::write(&target, original).unwrap();
    let block = AssistantManagedBlockV2 {
        assistant: AssistantKindV1::Cursor,
        scope: AssistantScopeV1::Project,
        profile_id: "core".to_owned(),
    };
    let preview = preview_assistant_install_v2(root.path(), &sha256(original), &block).unwrap();

    let result =
        apply_assistant_install_v2_with_postexchange_hook(root.path(), &preview, |target_path| {
            let replacement = target_path.with_extension("postexchange-replacement");
            fs::write(&replacement, concurrent).unwrap();
            fs::rename(replacement, target_path).unwrap();
        });

    assert_eq!(result, Err(AssistantInstallErrorV2::CasConflict));
    assert_eq!(fs::read(&target).unwrap(), concurrent);
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
