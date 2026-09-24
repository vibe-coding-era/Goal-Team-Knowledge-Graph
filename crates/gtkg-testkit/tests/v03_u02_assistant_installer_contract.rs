use gtkg_core::v03::assistant_install::{
    AssistantInstallErrorV1, AssistantKindV1, AssistantManagedBlockV1, AssistantScopeV1,
    apply_assistant_install_v1, preview_assistant_install_v1, uninstall_assistant_block_v1,
};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use tempfile::tempdir;

fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn block(assistant: AssistantKindV1, scope: AssistantScopeV1) -> AssistantManagedBlockV1 {
    AssistantManagedBlockV1 {
        assistant,
        scope,
        profile_id: "core".to_owned(),
        server_command: "gtkg mcp serve --protocol v2 --profile core --stdio".to_owned(),
    }
}

#[test]
fn four_assistants_and_two_scopes_preserve_user_content_and_exact_readback() {
    let root = tempdir().unwrap();
    for assistant in AssistantKindV1::ALL {
        for scope in AssistantScopeV1::ALL {
            let relative = format!("{}/{}.conf", scope.as_str(), assistant.as_str());
            let target = root.path().join(&relative);
            fs::create_dir_all(target.parent().unwrap()).unwrap();
            let user = format!("user_setting={}-{}\n", assistant.as_str(), scope.as_str());
            fs::write(&target, &user).unwrap();
            let expected_before = sha256(user.as_bytes());
            let preview = preview_assistant_install_v1(
                root.path(),
                Path::new(&relative),
                &expected_before,
                &block(assistant, scope),
            )
            .unwrap();
            assert_eq!(preview.write_count, 0);
            assert_eq!(preview.secret_count, 0);
            assert_eq!(preview.before_sha256, expected_before);
            assert!(preview.changed);
            assert!(!preview.diff_summary.is_empty());

            let receipt = apply_assistant_install_v1(root.path(), &preview).unwrap();
            assert_eq!(receipt.write_count, 1);
            assert_eq!(receipt.after_sha256, preview.after_sha256);
            assert_eq!(receipt.managed_block_sha256, preview.managed_block_sha256);
            assert_eq!(receipt.target_path, relative);
            assert_eq!(receipt.secret_count, 0);
            let observed = fs::read_to_string(&target).unwrap();
            assert!(observed.starts_with(&user));
            assert_eq!(observed.matches("# >>> GTKG managed:").count(), 1);
            assert_eq!(observed.matches("# <<< GTKG managed:").count(), 1);
        }
    }
}

#[test]
fn concurrent_drift_and_duplicate_managed_blocks_fail_closed() {
    let root = tempdir().unwrap();
    let target = root.path().join("project/codex.conf");
    fs::create_dir_all(target.parent().unwrap()).unwrap();
    fs::write(&target, "user=true\n").unwrap();
    let preview = preview_assistant_install_v1(
        root.path(),
        Path::new("project/codex.conf"),
        &sha256(b"user=true\n"),
        &block(AssistantKindV1::Codex, AssistantScopeV1::Project),
    )
    .unwrap();
    fs::write(&target, "user=changed\n").unwrap();
    assert_eq!(
        apply_assistant_install_v1(root.path(), &preview),
        Err(AssistantInstallErrorV1::CasConflict)
    );

    let marker = "# >>> GTKG managed: codex:project\nx\n# <<< GTKG managed: codex:project\n";
    fs::write(&target, format!("{marker}{marker}")).unwrap();
    assert_eq!(
        preview_assistant_install_v1(
            root.path(),
            Path::new("project/codex.conf"),
            &sha256(format!("{marker}{marker}").as_bytes()),
            &block(AssistantKindV1::Codex, AssistantScopeV1::Project),
        ),
        Err(AssistantInstallErrorV1::DuplicateManagedBlock)
    );
}

#[test]
fn uninstall_removes_only_the_managed_block() {
    let root = tempdir().unwrap();
    let relative = Path::new("user/gemini.conf");
    let target = root.path().join(relative);
    fs::create_dir_all(target.parent().unwrap()).unwrap();
    fs::write(&target, "user=keep\n").unwrap();
    let preview = preview_assistant_install_v1(
        root.path(),
        relative,
        &sha256(b"user=keep\n"),
        &block(AssistantKindV1::Gemini, AssistantScopeV1::User),
    )
    .unwrap();
    let installed = apply_assistant_install_v1(root.path(), &preview).unwrap();
    let removed = uninstall_assistant_block_v1(
        root.path(),
        relative,
        &installed.after_sha256,
        AssistantKindV1::Gemini,
        AssistantScopeV1::User,
    )
    .unwrap();
    assert_eq!(removed.write_count, 1);
    assert_eq!(fs::read_to_string(target).unwrap(), "user=keep\n");
}

#[cfg(unix)]
#[test]
fn symlink_escape_and_injected_commands_are_rejected() {
    use std::os::unix::fs::symlink;
    let root = tempdir().unwrap();
    let outside = tempdir().unwrap();
    symlink(outside.path(), root.path().join("escape")).unwrap();
    assert_eq!(
        preview_assistant_install_v1(
            root.path(),
            Path::new("escape/config"),
            &sha256(b""),
            &block(AssistantKindV1::Claude, AssistantScopeV1::User),
        ),
        Err(AssistantInstallErrorV1::PathEscape)
    );

    let mut injected = block(AssistantKindV1::Cursor, AssistantScopeV1::Project);
    injected.server_command.push_str("\nsteal_secret=true");
    assert_eq!(
        preview_assistant_install_v1(
            root.path(),
            Path::new("safe/config"),
            &sha256(b""),
            &injected,
        ),
        Err(AssistantInstallErrorV1::InvalidManagedBlock)
    );
}
