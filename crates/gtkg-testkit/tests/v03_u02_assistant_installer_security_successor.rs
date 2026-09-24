use std::fs;

use gtkg_core::v03::assistant_install::{
    ASSISTANT_INSTALL_RECEIPT_SCHEMA_V2, AssistantInstallErrorV2, AssistantKindV1,
    AssistantManagedBlockV2, AssistantScopeV1, apply_assistant_install_v2,
    assistant_target_file_v2, preview_assistant_install_v2, uninstall_assistant_block_v2,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tempfile::tempdir;

fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn block(assistant: AssistantKindV1, scope: AssistantScopeV1) -> AssistantManagedBlockV2 {
    AssistantManagedBlockV2 {
        assistant,
        scope,
        profile_id: "core".to_owned(),
    }
}

fn seed(assistant: AssistantKindV1) -> Vec<u8> {
    match assistant {
        AssistantKindV1::Codex => {
            b"model = \"gpt-5.6\"\nuser_setting = true\napi_token = \"not-a-real-secret\"".to_vec()
        }
        AssistantKindV1::Claude | AssistantKindV1::Cursor | AssistantKindV1::Gemini => {
            br#"{"custom":{"keep":true},"api_token":"not-a-real-secret"}"#.to_vec()
        }
    }
}

fn assert_native_entry(assistant: AssistantKindV1, bytes: &[u8]) {
    match assistant {
        AssistantKindV1::Codex => {
            let text = std::str::from_utf8(bytes).unwrap();
            assert!(text.contains("[mcp_servers.gtkg]"));
            assert!(text.contains("command = \"gtkg\""));
            assert!(text.contains("\"--profile\", \"core\""));
            assert!(text.contains("user_setting = true"));
        }
        AssistantKindV1::Claude | AssistantKindV1::Cursor | AssistantKindV1::Gemini => {
            let value: Value = serde_json::from_slice(bytes).unwrap();
            assert_eq!(value["custom"]["keep"], true);
            assert_eq!(value["api_token"], "not-a-real-secret");
            assert_eq!(value["mcpServers"]["gtkg"]["command"], "gtkg");
            assert_eq!(
                value["mcpServers"]["gtkg"]["args"],
                serde_json::json!([
                    "mcp",
                    "serve",
                    "--protocol",
                    "v2",
                    "--profile",
                    "core",
                    "--stdio"
                ])
            );
        }
    }
}

#[test]
fn successor_uses_native_formats_for_four_assistants_and_two_scopes() {
    for assistant in AssistantKindV1::ALL {
        for scope in AssistantScopeV1::ALL {
            let root = tempdir().unwrap();
            let relative = assistant_target_file_v2(assistant, scope);
            let target = root.path().join(relative);
            fs::create_dir_all(target.parent().unwrap()).unwrap();
            let original = seed(assistant);
            fs::write(&target, &original).unwrap();

            let preview = preview_assistant_install_v2(
                root.path(),
                &sha256(&original),
                &block(assistant, scope),
            )
            .unwrap();
            assert!(preview.changed);
            assert_eq!(preview.write_count, 0);
            assert_eq!(preview.secret_output_count, 0);
            assert_eq!(preview.sensitive_value_count, 1);

            let receipt = apply_assistant_install_v2(root.path(), &preview).unwrap();
            assert_eq!(receipt.schema_version, ASSISTANT_INSTALL_RECEIPT_SCHEMA_V2);
            assert_eq!(receipt.target_file, relative);
            assert_eq!(receipt.assistant, assistant);
            assert_eq!(receipt.scope, scope);
            assert_eq!(receipt.write_count, 1);
            assert_eq!(receipt.secret_output_count, 0);
            assert!(!receipt.platform.is_empty());
            let installed = fs::read(&target).unwrap();
            assert!(!installed.ends_with(b"\n"));
            assert_native_entry(assistant, &installed);

            let removed = uninstall_assistant_block_v2(
                root.path(),
                &receipt.after_sha256,
                &block(assistant, scope),
            )
            .unwrap();
            assert_eq!(removed.write_count, 1);
            let after_remove = fs::read(&target).unwrap();
            assert!(!after_remove.ends_with(b"\n"));
            match assistant {
                AssistantKindV1::Codex => {
                    let text = std::str::from_utf8(&after_remove).unwrap();
                    assert!(text.contains("model = \"gpt-5.6\""));
                    assert!(text.contains("user_setting = true"));
                    assert!(!text.contains("mcp_servers.gtkg"));
                }
                _ => {
                    let value: Value = serde_json::from_slice(&after_remove).unwrap();
                    assert_eq!(value["custom"]["keep"], true);
                    assert_eq!(value["api_token"], "not-a-real-secret");
                    assert!(value.get("mcpServers").is_none());
                }
            }
        }
    }
}

#[cfg(unix)]
#[test]
fn successor_noop_does_not_write_and_same_bytes_inode_replacement_conflicts() {
    use std::os::unix::fs::MetadataExt;

    let root = tempdir().unwrap();
    let assistant = AssistantKindV1::Cursor;
    let scope = AssistantScopeV1::Project;
    let target = root.path().join(assistant_target_file_v2(assistant, scope));
    fs::create_dir_all(target.parent().unwrap()).unwrap();
    fs::write(&target, seed(assistant)).unwrap();

    let first = preview_assistant_install_v2(
        root.path(),
        &sha256(&fs::read(&target).unwrap()),
        &block(assistant, scope),
    )
    .unwrap();
    let installed = apply_assistant_install_v2(root.path(), &first).unwrap();
    let noop = preview_assistant_install_v2(
        root.path(),
        &installed.after_sha256,
        &block(assistant, scope),
    )
    .unwrap();
    assert!(!noop.changed);
    let inode_before = fs::metadata(&target).unwrap().ino();
    let noop_receipt = apply_assistant_install_v2(root.path(), &noop).unwrap();
    assert_eq!(noop_receipt.write_count, 0);
    assert_eq!(fs::metadata(&target).unwrap().ino(), inode_before);

    let conflict_preview = preview_assistant_install_v2(
        root.path(),
        &installed.after_sha256,
        &block(assistant, scope),
    )
    .unwrap();
    let same_bytes = fs::read(&target).unwrap();
    let replacement = target.with_extension("replacement");
    fs::write(&replacement, &same_bytes).unwrap();
    fs::rename(&replacement, &target).unwrap();
    assert_eq!(
        apply_assistant_install_v2(root.path(), &conflict_preview),
        Err(AssistantInstallErrorV2::CasConflict)
    );
}

#[cfg(unix)]
#[test]
fn successor_dirfd_walk_rejects_parent_symlink_swap_and_leaves_no_temp() {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let root = tempdir().unwrap();
    let outside = tempdir().unwrap();
    let assistant = AssistantKindV1::Cursor;
    let scope = AssistantScopeV1::Project;
    let relative = assistant_target_file_v2(assistant, scope);
    let target = root.path().join(relative);
    fs::create_dir_all(target.parent().unwrap()).unwrap();
    fs::write(&target, seed(assistant)).unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();

    let preview = preview_assistant_install_v2(
        root.path(),
        &sha256(&fs::read(&target).unwrap()),
        &block(assistant, scope),
    )
    .unwrap();
    let original_parent = root.path().join(".cursor");
    let saved_parent = root.path().join(".cursor-saved");
    fs::rename(&original_parent, &saved_parent).unwrap();
    symlink(outside.path(), &original_parent).unwrap();
    assert_eq!(
        apply_assistant_install_v2(root.path(), &preview),
        Err(AssistantInstallErrorV2::PathEscape)
    );
    assert!(fs::read_dir(outside.path()).unwrap().next().is_none());

    fs::remove_file(&original_parent).unwrap();
    fs::rename(&saved_parent, &original_parent).unwrap();
    let receipt = apply_assistant_install_v2(root.path(), &preview).unwrap();
    assert_eq!(receipt.target_mode, 0o600);
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
fn successor_rejects_malformed_native_config_and_profile_injection() {
    for (assistant, invalid) in [
        (AssistantKindV1::Codex, b"[broken".as_slice()),
        (AssistantKindV1::Claude, b"{broken".as_slice()),
        (AssistantKindV1::Cursor, b"[]".as_slice()),
        (AssistantKindV1::Gemini, b"null".as_slice()),
    ] {
        let root = tempdir().unwrap();
        let scope = AssistantScopeV1::Project;
        let target = root.path().join(assistant_target_file_v2(assistant, scope));
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::write(&target, invalid).unwrap();
        assert_eq!(
            preview_assistant_install_v2(root.path(), &sha256(invalid), &block(assistant, scope)),
            Err(AssistantInstallErrorV2::InvalidNativeConfig)
        );
    }

    let root = tempdir().unwrap();
    let mut injected = block(AssistantKindV1::Gemini, AssistantScopeV1::Project);
    injected.profile_id = "core\ncommand=steal".to_owned();
    assert_eq!(
        preview_assistant_install_v2(root.path(), &sha256(b""), &injected),
        Err(AssistantInstallErrorV2::InvalidManagedBlock)
    );
}
