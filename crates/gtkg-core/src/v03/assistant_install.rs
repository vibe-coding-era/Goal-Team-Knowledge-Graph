//! U02 parser-aware assistant managed-block installation.

use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use toml_edit::{Array, DocumentMut, InlineTable, Item, Table, value};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssistantKindV1 {
    Codex,
    Claude,
    Cursor,
    Gemini,
}

impl AssistantKindV1 {
    pub const ALL: [Self; 4] = [Self::Codex, Self::Claude, Self::Cursor, Self::Gemini];
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Codex => "codex",
            Self::Claude => "claude",
            Self::Cursor => "cursor",
            Self::Gemini => "gemini",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssistantScopeV1 {
    User,
    Project,
}

impl AssistantScopeV1 {
    pub const ALL: [Self; 2] = [Self::User, Self::Project];
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Project => "project",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssistantManagedBlockV1 {
    pub assistant: AssistantKindV1,
    pub scope: AssistantScopeV1,
    pub profile_id: String,
    pub server_command: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssistantInstallPreviewV1 {
    pub assistant: AssistantKindV1,
    pub scope: AssistantScopeV1,
    pub target_path: String,
    pub before_sha256: String,
    pub after_sha256: String,
    pub managed_block_sha256: String,
    pub changed: bool,
    pub diff_summary: String,
    pub write_count: u64,
    pub secret_count: u64,
    root: PathBuf,
    after_content: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssistantInstallReceiptV1 {
    pub assistant: AssistantKindV1,
    pub scope: AssistantScopeV1,
    pub target_path: String,
    pub before_sha256: String,
    pub after_sha256: String,
    pub managed_block_sha256: String,
    pub write_count: u64,
    pub secret_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AssistantInstallErrorV1 {
    #[error("target path escaped the authorized root")]
    PathEscape,
    #[error("assistant target changed since preview")]
    CasConflict,
    #[error("duplicate managed blocks")]
    DuplicateManagedBlock,
    #[error("managed block is invalid")]
    InvalidManagedBlock,
    #[error("assistant target I/O failed")]
    Io,
}

pub fn preview_assistant_install_v1(
    root: &Path,
    relative: &Path,
    expected_before_sha256: &str,
    block: &AssistantManagedBlockV1,
) -> Result<AssistantInstallPreviewV1, AssistantInstallErrorV1> {
    validate_block(block)?;
    let (root, target, relative_text) = safe_target(root, relative)?;
    let before = read_optional(&target)?;
    if sha256(&before) != expected_before_sha256 {
        return Err(AssistantInstallErrorV1::CasConflict);
    }
    let before_text = String::from_utf8(before.clone())
        .map_err(|_| AssistantInstallErrorV1::InvalidManagedBlock)?;
    let managed = render_block(block);
    let after_text = replace_or_append_block(&before_text, block, &managed)?;
    let after_content = after_text.into_bytes();
    Ok(AssistantInstallPreviewV1 {
        assistant: block.assistant,
        scope: block.scope,
        target_path: relative_text,
        before_sha256: sha256(&before),
        after_sha256: sha256(&after_content),
        managed_block_sha256: sha256(managed.as_bytes()),
        changed: before != after_content,
        diff_summary: format!(
            "managed {}:{} block; before={} after={}",
            block.assistant.as_str(),
            block.scope.as_str(),
            before.len(),
            after_content.len()
        ),
        write_count: 0,
        secret_count: 0,
        root,
        after_content,
    })
}

pub fn apply_assistant_install_v1(
    root: &Path,
    preview: &AssistantInstallPreviewV1,
) -> Result<AssistantInstallReceiptV1, AssistantInstallErrorV1> {
    let (observed_root, target, _) = safe_target(root, Path::new(&preview.target_path))?;
    if observed_root != preview.root || sha256(&read_optional(&target)?) != preview.before_sha256 {
        return Err(AssistantInstallErrorV1::CasConflict);
    }
    write_atomic(&target, &preview.after_content)?;
    let observed = read_optional(&target)?;
    if sha256(&observed) != preview.after_sha256 {
        return Err(AssistantInstallErrorV1::Io);
    }
    Ok(AssistantInstallReceiptV1 {
        assistant: preview.assistant,
        scope: preview.scope,
        target_path: preview.target_path.clone(),
        before_sha256: preview.before_sha256.clone(),
        after_sha256: preview.after_sha256.clone(),
        managed_block_sha256: preview.managed_block_sha256.clone(),
        write_count: u64::from(preview.changed),
        secret_count: 0,
    })
}

pub fn uninstall_assistant_block_v1(
    root: &Path,
    relative: &Path,
    expected_before_sha256: &str,
    assistant: AssistantKindV1,
    scope: AssistantScopeV1,
) -> Result<AssistantInstallReceiptV1, AssistantInstallErrorV1> {
    let (root, target, relative_text) = safe_target(root, relative)?;
    let before = read_optional(&target)?;
    if sha256(&before) != expected_before_sha256 {
        return Err(AssistantInstallErrorV1::CasConflict);
    }
    let before_text = String::from_utf8(before.clone())
        .map_err(|_| AssistantInstallErrorV1::InvalidManagedBlock)?;
    let after_content = remove_block(&before_text, assistant, scope)?.into_bytes();
    let managed_block_sha256 = sha256(marker_pair(assistant, scope).as_bytes());
    let preview = AssistantInstallPreviewV1 {
        assistant,
        scope,
        target_path: relative_text,
        before_sha256: sha256(&before),
        after_sha256: sha256(&after_content),
        managed_block_sha256,
        changed: before != after_content,
        diff_summary: "remove managed block".to_owned(),
        write_count: 0,
        secret_count: 0,
        root,
        after_content,
    };
    apply_assistant_install_v1(preview.root.as_path(), &preview)
}

fn validate_block(block: &AssistantManagedBlockV1) -> Result<(), AssistantInstallErrorV1> {
    if block.profile_id.trim().is_empty()
        || block
            .profile_id
            .contains(|ch: char| ch.is_whitespace() || ch.is_control())
        || block.server_command.trim().is_empty()
        || block.server_command.contains(['\n', '\r', '\0'])
    {
        return Err(AssistantInstallErrorV1::InvalidManagedBlock);
    }
    Ok(())
}

fn render_block(block: &AssistantManagedBlockV1) -> String {
    let label = format!("{}:{}", block.assistant.as_str(), block.scope.as_str());
    format!(
        "# >>> GTKG managed: {label}\nprofile={}\ncommand={}\n# <<< GTKG managed: {label}\n",
        block.profile_id, block.server_command
    )
}

fn marker_pair(assistant: AssistantKindV1, scope: AssistantScopeV1) -> String {
    let label = format!("{}:{}", assistant.as_str(), scope.as_str());
    format!("# >>> GTKG managed: {label}\n# <<< GTKG managed: {label}\n")
}

fn markers(assistant: AssistantKindV1, scope: AssistantScopeV1) -> (String, String) {
    let label = format!("{}:{}", assistant.as_str(), scope.as_str());
    (
        format!("# >>> GTKG managed: {label}\n"),
        format!("# <<< GTKG managed: {label}\n"),
    )
}

fn replace_or_append_block(
    source: &str,
    block: &AssistantManagedBlockV1,
    managed: &str,
) -> Result<String, AssistantInstallErrorV1> {
    let (start, end) = markers(block.assistant, block.scope);
    let starts = source.match_indices(&start).collect::<Vec<_>>();
    let ends = source.match_indices(&end).collect::<Vec<_>>();
    if starts.len() > 1 || ends.len() > 1 || starts.len() != ends.len() {
        return Err(AssistantInstallErrorV1::DuplicateManagedBlock);
    }
    if let (Some((start_at, _)), Some((end_at, _))) = (starts.first(), ends.first()) {
        if end_at < start_at {
            return Err(AssistantInstallErrorV1::InvalidManagedBlock);
        }
        let end_at = end_at + end.len();
        return Ok(format!(
            "{}{}{}",
            &source[..*start_at],
            managed,
            &source[end_at..]
        ));
    }
    let separator = if source.is_empty() || source.ends_with('\n') {
        ""
    } else {
        "\n"
    };
    Ok(format!("{source}{separator}{managed}"))
}

fn remove_block(
    source: &str,
    assistant: AssistantKindV1,
    scope: AssistantScopeV1,
) -> Result<String, AssistantInstallErrorV1> {
    let (start, end) = markers(assistant, scope);
    let starts = source.match_indices(&start).collect::<Vec<_>>();
    let ends = source.match_indices(&end).collect::<Vec<_>>();
    if starts.len() != 1 || ends.len() != 1 || ends[0].0 < starts[0].0 {
        return Err(AssistantInstallErrorV1::InvalidManagedBlock);
    }
    let end_at = ends[0].0 + end.len();
    Ok(format!("{}{}", &source[..starts[0].0], &source[end_at..]))
}

fn safe_target(
    root: &Path,
    relative: &Path,
) -> Result<(PathBuf, PathBuf, String), AssistantInstallErrorV1> {
    if relative.is_absolute()
        || relative.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(AssistantInstallErrorV1::PathEscape);
    }
    let root_meta = fs::symlink_metadata(root).map_err(|_| AssistantInstallErrorV1::Io)?;
    if root_meta.file_type().is_symlink() || !root_meta.is_dir() {
        return Err(AssistantInstallErrorV1::PathEscape);
    }
    let root = fs::canonicalize(root).map_err(|_| AssistantInstallErrorV1::Io)?;
    let mut cursor = root.clone();
    for component in relative.components() {
        let Component::Normal(part) = component else {
            return Err(AssistantInstallErrorV1::PathEscape);
        };
        cursor.push(part);
        if let Ok(metadata) = fs::symlink_metadata(&cursor)
            && metadata.file_type().is_symlink()
        {
            return Err(AssistantInstallErrorV1::PathEscape);
        }
    }
    if !cursor.starts_with(&root) {
        return Err(AssistantInstallErrorV1::PathEscape);
    }
    let relative_text = relative
        .to_str()
        .filter(|text| !text.is_empty() && !text.contains('\\'))
        .ok_or(AssistantInstallErrorV1::PathEscape)?
        .to_owned();
    Ok((root, cursor, relative_text))
}

fn read_optional(path: &Path) -> Result<Vec<u8>, AssistantInstallErrorV1> {
    match fs::read(path) {
        Ok(bytes) => Ok(bytes),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(_) => Err(AssistantInstallErrorV1::Io),
    }
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), AssistantInstallErrorV1> {
    let parent = path.parent().ok_or(AssistantInstallErrorV1::PathEscape)?;
    fs::create_dir_all(parent).map_err(|_| AssistantInstallErrorV1::Io)?;
    let temp = parent.join(format!(".gtkg-managed-{}.tmp", std::process::id()));
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temp)
        .map_err(|_| AssistantInstallErrorV1::Io)?;
    file.write_all(bytes)
        .map_err(|_| AssistantInstallErrorV1::Io)?;
    file.sync_all().map_err(|_| AssistantInstallErrorV1::Io)?;
    fs::rename(&temp, path).map_err(|_| AssistantInstallErrorV1::Io)?;
    Ok(())
}

fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

pub const ASSISTANT_INSTALL_RECEIPT_SCHEMA_V2: &str = "gtkg.assistant-install-receipt/v2";
pub const MAX_ASSISTANT_CONFIG_BYTES_V2: u64 = 4 * 1024 * 1024;

static ASSISTANT_TEMP_SEQUENCE_V2: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssistantManagedBlockV2 {
    pub assistant: AssistantKindV1,
    pub scope: AssistantScopeV1,
    pub profile_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssistantInstallReceiptV2 {
    pub schema_version: String,
    pub platform: String,
    pub assistant: AssistantKindV1,
    pub scope: AssistantScopeV1,
    pub target_file: String,
    pub root_identity_sha256: String,
    pub profile_id: String,
    pub before_sha256: String,
    pub after_sha256: String,
    pub managed_block_sha256: String,
    pub write_count: u64,
    pub directory_create_count: u64,
    pub sensitive_value_count: u64,
    pub secret_output_count: u64,
    pub target_mode: u32,
    pub target_removed: bool,
    pub directory_remove_count: u64,
    pub readback_verified: bool,
}

#[derive(Clone, PartialEq, Eq)]
pub struct AssistantInstallPreviewV2 {
    pub assistant: AssistantKindV1,
    pub scope: AssistantScopeV1,
    pub target_file: String,
    pub profile_id: String,
    pub before_sha256: String,
    pub after_sha256: String,
    pub managed_block_sha256: String,
    pub changed: bool,
    pub diff_summary: String,
    pub write_count: u64,
    pub sensitive_value_count: u64,
    pub secret_output_count: u64,
    root: PathBuf,
    root_identity: AssistantFsIdentityV2,
    before_identity: Option<AssistantFsIdentityV2>,
    target_mode: u32,
    after_content: Vec<u8>,
}

impl std::fmt::Debug for AssistantInstallPreviewV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AssistantInstallPreviewV2")
            .field("assistant", &self.assistant)
            .field("scope", &self.scope)
            .field("target_file", &self.target_file)
            .field("profile_id", &self.profile_id)
            .field("before_sha256", &self.before_sha256)
            .field("after_sha256", &self.after_sha256)
            .field("managed_block_sha256", &self.managed_block_sha256)
            .field("changed", &self.changed)
            .field("diff_summary", &self.diff_summary)
            .field("write_count", &self.write_count)
            .field("sensitive_value_count", &self.sensitive_value_count)
            .field("secret_output_count", &self.secret_output_count)
            .field("after_content_len", &self.after_content.len())
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AssistantInstallErrorV2 {
    #[error("assistant managed block is invalid")]
    InvalidManagedBlock,
    #[error("assistant native configuration is invalid")]
    InvalidNativeConfig,
    #[error("assistant native configuration has a conflicting gtkg entry")]
    ManagedEntryConflict,
    #[error("assistant native configuration has no managed gtkg entry")]
    ManagedEntryMissing,
    #[error("assistant target path escaped its authorized root")]
    PathEscape,
    #[error("assistant target changed since preview")]
    CasConflict,
    #[error("assistant target is a hard link or non-regular file")]
    UnsafeTarget,
    #[error("assistant install requires Unix dirfd semantics")]
    UnsupportedPlatform,
    #[error("assistant target I/O failed")]
    Io,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AssistantFsIdentityV2 {
    device: u64,
    inode: u64,
    mode: u32,
}

#[derive(Debug, Clone)]
struct AssistantObservedFileV2 {
    bytes: Vec<u8>,
    identity: Option<AssistantFsIdentityV2>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AssistantConfigActionV2 {
    Install,
    Uninstall,
}

pub const fn assistant_target_file_v2(
    assistant: AssistantKindV1,
    scope: AssistantScopeV1,
) -> &'static str {
    match (assistant, scope) {
        (AssistantKindV1::Codex, AssistantScopeV1::User) => ".codex/config.toml",
        (AssistantKindV1::Codex, AssistantScopeV1::Project) => ".codex/config.toml",
        (AssistantKindV1::Claude, AssistantScopeV1::User) => ".claude.json",
        (AssistantKindV1::Claude, AssistantScopeV1::Project) => ".mcp.json",
        (AssistantKindV1::Cursor, AssistantScopeV1::User) => ".cursor/mcp.json",
        (AssistantKindV1::Cursor, AssistantScopeV1::Project) => ".cursor/mcp.json",
        (AssistantKindV1::Gemini, AssistantScopeV1::User) => ".gemini/settings.json",
        (AssistantKindV1::Gemini, AssistantScopeV1::Project) => ".gemini/settings.json",
    }
}

pub fn preview_assistant_install_v2(
    root: &Path,
    expected_before_sha256: &str,
    block: &AssistantManagedBlockV2,
) -> Result<AssistantInstallPreviewV2, AssistantInstallErrorV2> {
    preview_assistant_change_v2(
        root,
        expected_before_sha256,
        block,
        AssistantConfigActionV2::Install,
    )
}

pub fn uninstall_assistant_block_v2(
    root: &Path,
    expected_before_sha256: &str,
    block: &AssistantManagedBlockV2,
) -> Result<AssistantInstallReceiptV2, AssistantInstallErrorV2> {
    let preview = preview_assistant_change_v2(
        root,
        expected_before_sha256,
        block,
        AssistantConfigActionV2::Uninstall,
    )?;
    apply_assistant_install_v2(root, &preview)
}

pub fn preview_assistant_uninstall_v2(
    root: &Path,
    expected_before_sha256: &str,
    block: &AssistantManagedBlockV2,
) -> Result<AssistantInstallPreviewV2, AssistantInstallErrorV2> {
    preview_assistant_change_v2(
        root,
        expected_before_sha256,
        block,
        AssistantConfigActionV2::Uninstall,
    )
}

pub fn uninstall_assistant_block_with_receipt_v2(
    root: &Path,
    install_receipt: &AssistantInstallReceiptV2,
) -> Result<AssistantInstallReceiptV2, AssistantInstallErrorV2> {
    if install_receipt.schema_version != ASSISTANT_INSTALL_RECEIPT_SCHEMA_V2
        || !install_receipt.readback_verified
        || install_receipt.write_count != 1
        || install_receipt.secret_output_count != 0
        || install_receipt.target_file
            != assistant_target_file_v2(install_receipt.assistant, install_receipt.scope)
    {
        return Err(AssistantInstallErrorV2::InvalidManagedBlock);
    }
    let block = AssistantManagedBlockV2 {
        assistant: install_receipt.assistant,
        scope: install_receipt.scope,
        profile_id: install_receipt.profile_id.clone(),
    };
    if managed_block_sha256_v2(&block) != install_receipt.managed_block_sha256 {
        return Err(AssistantInstallErrorV2::InvalidManagedBlock);
    }
    let preview = preview_assistant_uninstall_v2(root, &install_receipt.after_sha256, &block)?;
    if assistant_root_identity_sha256_v2(&preview.root_identity)
        != install_receipt.root_identity_sha256
        || preview.before_sha256 != install_receipt.after_sha256
        || preview.managed_block_sha256 != install_receipt.managed_block_sha256
    {
        return Err(AssistantInstallErrorV2::CasConflict);
    }
    apply_assistant_install_v2(root, &preview)
}

fn preview_assistant_change_v2(
    root: &Path,
    expected_before_sha256: &str,
    block: &AssistantManagedBlockV2,
    action: AssistantConfigActionV2,
) -> Result<AssistantInstallPreviewV2, AssistantInstallErrorV2> {
    validate_managed_block_v2(block)?;
    if !is_canonical_sha256_v2(expected_before_sha256) {
        return Err(AssistantInstallErrorV2::CasConflict);
    }
    let (root, root_file, root_identity) = open_root_v2(root)?;
    let relative = Path::new(assistant_target_file_v2(block.assistant, block.scope));
    let observed = match walk_parent_v2(root_file, relative, false)? {
        AssistantParentV2::Missing => AssistantObservedFileV2 {
            bytes: Vec::new(),
            identity: None,
        },
        AssistantParentV2::Ready {
            directory, name, ..
        } => read_at_v2(&directory, &name)?,
    };
    let before_sha256 = sha256(&observed.bytes);
    if before_sha256 != expected_before_sha256 {
        return Err(AssistantInstallErrorV2::CasConflict);
    }
    let file_was_missing = observed.identity.is_none();
    let (after_content, sensitive_value_count) =
        render_native_config_v2(&observed.bytes, block, action, file_was_missing)?;
    let managed_block_sha256 = managed_block_sha256_v2(block);
    let after_sha256 = sha256(&after_content);
    let target_mode = observed
        .identity
        .as_ref()
        .map_or(0o600, |identity| identity.mode);
    Ok(AssistantInstallPreviewV2 {
        assistant: block.assistant,
        scope: block.scope,
        target_file: assistant_target_file_v2(block.assistant, block.scope).to_owned(),
        profile_id: block.profile_id.clone(),
        before_sha256,
        after_sha256,
        managed_block_sha256,
        changed: observed.bytes != after_content,
        diff_summary: format!(
            "native {} {}:{} entry; before={} after={}",
            match action {
                AssistantConfigActionV2::Install => "install",
                AssistantConfigActionV2::Uninstall => "uninstall",
            },
            block.assistant.as_str(),
            block.scope.as_str(),
            observed.bytes.len(),
            after_content.len()
        ),
        write_count: 0,
        sensitive_value_count,
        secret_output_count: 0,
        root,
        root_identity,
        before_identity: observed.identity,
        target_mode,
        after_content,
    })
}

fn validate_managed_block_v2(
    block: &AssistantManagedBlockV2,
) -> Result<(), AssistantInstallErrorV2> {
    if block.profile_id.is_empty()
        || block.profile_id.len() > 64
        || !block.profile_id.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
    {
        return Err(AssistantInstallErrorV2::InvalidManagedBlock);
    }
    Ok(())
}

fn assistant_stdio_args_v2(profile_id: &str) -> Vec<String> {
    [
        "mcp",
        "serve",
        "--protocol",
        "v2",
        "--profile",
        profile_id,
        "--stdio",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

fn managed_block_sha256_v2(block: &AssistantManagedBlockV2) -> String {
    let identity = (
        "gtkg.assistant-native-entry/v2",
        block.assistant.as_str(),
        block.scope.as_str(),
        block.profile_id.as_str(),
        "gtkg",
        assistant_stdio_args_v2(&block.profile_id),
    );
    sha256(&serde_json::to_vec(&identity).expect("native entry identity is serializable"))
}

fn render_native_config_v2(
    before: &[u8],
    block: &AssistantManagedBlockV2,
    action: AssistantConfigActionV2,
    file_was_missing: bool,
) -> Result<(Vec<u8>, u64), AssistantInstallErrorV2> {
    match block.assistant {
        AssistantKindV1::Codex => render_codex_toml_v2(before, block, action, file_was_missing),
        AssistantKindV1::Claude | AssistantKindV1::Cursor | AssistantKindV1::Gemini => {
            render_mcp_json_v2(before, block, action, file_was_missing)
        }
    }
}

fn desired_codex_item_v2(
    block: &AssistantManagedBlockV2,
    parent_created: bool,
    file_created: bool,
    original_empty: bool,
) -> Item {
    let mut table = Table::new();
    table.set_implicit(false);
    table.insert("command", value("gtkg"));
    let mut args = Array::new();
    for argument in assistant_stdio_args_v2(&block.profile_id) {
        args.push(argument);
    }
    table.insert("args", value(args));
    let mut env = InlineTable::new();
    env.insert(
        "GTKG_MANAGED_CONFIG_SCHEMA",
        "gtkg.assistant-native-entry/v2".into(),
    );
    env.insert(
        "GTKG_MANAGED_PARENT_CREATED",
        if parent_created { "1" } else { "0" }.into(),
    );
    env.insert(
        "GTKG_MANAGED_FILE_CREATED",
        if file_created { "1" } else { "0" }.into(),
    );
    env.insert(
        "GTKG_MANAGED_ORIGINAL_EMPTY",
        if original_empty { "1" } else { "0" }.into(),
    );
    table.insert("env", value(env));
    Item::Table(table)
}

fn render_codex_toml_v2(
    before: &[u8],
    block: &AssistantManagedBlockV2,
    action: AssistantConfigActionV2,
    file_was_missing: bool,
) -> Result<(Vec<u8>, u64), AssistantInstallErrorV2> {
    let source =
        std::str::from_utf8(before).map_err(|_| AssistantInstallErrorV2::InvalidNativeConfig)?;
    let mut document = if source.is_empty() {
        DocumentMut::new()
    } else {
        source
            .parse::<DocumentMut>()
            .map_err(|_| AssistantInstallErrorV2::InvalidNativeConfig)?
    };
    let sensitive_value_count = count_sensitive_toml_values_v2(source);
    let root = document.as_table_mut();
    let parent_created = !root.contains_key("mcp_servers");
    let desired = desired_codex_item_v2(
        block,
        parent_created,
        file_was_missing,
        before.is_empty() && !file_was_missing,
    );
    if parent_created {
        if action == AssistantConfigActionV2::Uninstall {
            return Err(AssistantInstallErrorV2::ManagedEntryMissing);
        }
        let mut servers = Table::new();
        servers.set_implicit(true);
        root.insert("mcp_servers", Item::Table(servers));
    }
    let servers = root
        .get_mut("mcp_servers")
        .and_then(Item::as_table_mut)
        .ok_or(AssistantInstallErrorV2::InvalidNativeConfig)?;
    let mut uninstall_flags = None;
    match action {
        AssistantConfigActionV2::Install => match servers.get("gtkg") {
            Some(existing) if codex_item_flags_v2(existing, block).is_some() => {
                return Ok((before.to_vec(), sensitive_value_count));
            }
            Some(_) => return Err(AssistantInstallErrorV2::ManagedEntryConflict),
            None => {
                servers.insert("gtkg", desired);
            }
        },
        AssistantConfigActionV2::Uninstall => {
            let existing = servers
                .get("gtkg")
                .ok_or(AssistantInstallErrorV2::ManagedEntryMissing)?;
            uninstall_flags = Some(
                codex_item_flags_v2(existing, block)
                    .ok_or(AssistantInstallErrorV2::ManagedEntryConflict)?,
            );
            servers.remove("gtkg");
        }
    }
    if servers.is_empty() && uninstall_flags.is_some_and(|(created, _, _)| created) {
        root.remove("mcp_servers");
    }
    if uninstall_flags
        .is_some_and(|(_, file_created, original_empty)| file_created || original_empty)
        && root.is_empty()
    {
        return Ok((Vec::new(), sensitive_value_count));
    }
    let rendered = restore_line_suffix_v2(document.to_string().into_bytes(), before);
    Ok((rendered, sensitive_value_count))
}

fn codex_item_flags_v2(item: &Item, block: &AssistantManagedBlockV2) -> Option<(bool, bool, bool)> {
    let table = item.as_table()?;
    if table.len() != 3 || table.get("command").and_then(Item::as_str) != Some("gtkg") {
        return None;
    }
    let args = table.get("args").and_then(Item::as_array)?;
    if !args
        .iter()
        .filter_map(|item| item.as_str())
        .eq(assistant_stdio_args_v2(&block.profile_id)
            .iter()
            .map(String::as_str))
        || !args.iter().all(|item| item.as_str().is_some())
    {
        return None;
    }
    let env = table.get("env").and_then(Item::as_inline_table)?;
    if env.len() != 4
        || env
            .get("GTKG_MANAGED_CONFIG_SCHEMA")
            .and_then(|value| value.as_str())
            != Some("gtkg.assistant-native-entry/v2")
    {
        return None;
    }
    let parent_created = match env
        .get("GTKG_MANAGED_PARENT_CREATED")
        .and_then(|value| value.as_str())?
    {
        "1" => true,
        "0" => false,
        _ => return None,
    };
    let file_created = match env
        .get("GTKG_MANAGED_FILE_CREATED")
        .and_then(|value| value.as_str())?
    {
        "1" => true,
        "0" => false,
        _ => return None,
    };
    let original_empty = match env
        .get("GTKG_MANAGED_ORIGINAL_EMPTY")
        .and_then(|value| value.as_str())?
    {
        "1" => true,
        "0" => false,
        _ => return None,
    };
    Some((parent_created, file_created, original_empty))
}

fn desired_json_server_v2(
    block: &AssistantManagedBlockV2,
    parent_created: bool,
    file_created: bool,
    original_empty: bool,
) -> serde_json::Value {
    serde_json::json!({
        "command": "gtkg",
        "args": assistant_stdio_args_v2(&block.profile_id),
        "env": {
            "GTKG_MANAGED_CONFIG_SCHEMA": "gtkg.assistant-native-entry/v2",
            "GTKG_MANAGED_PARENT_CREATED": if parent_created { "1" } else { "0" },
            "GTKG_MANAGED_FILE_CREATED": if file_created { "1" } else { "0" },
            "GTKG_MANAGED_ORIGINAL_EMPTY": if original_empty { "1" } else { "0" }
        }
    })
}

fn render_mcp_json_v2(
    before: &[u8],
    block: &AssistantManagedBlockV2,
    action: AssistantConfigActionV2,
    file_was_missing: bool,
) -> Result<(Vec<u8>, u64), AssistantInstallErrorV2> {
    let base = if before.is_empty() {
        b"{}".as_slice()
    } else {
        before
    };
    let document: serde_json::Value =
        serde_json::from_slice(base).map_err(|_| AssistantInstallErrorV2::InvalidNativeConfig)?;
    let sensitive_value_count = count_sensitive_json_values_v2(&document);
    document
        .as_object()
        .ok_or(AssistantInstallErrorV2::InvalidNativeConfig)?;
    let root = scan_json_object_v2(base, 0)?;
    reject_duplicate_json_keys_v2(&root)?;
    let mcp_index = root
        .members
        .iter()
        .position(|member| member.key == "mcpServers");

    let rendered = match (action, mcp_index) {
        (AssistantConfigActionV2::Install, None) => {
            let desired = desired_json_server_v2(
                block,
                true,
                file_was_missing,
                before.is_empty() && !file_was_missing,
            );
            let member = format!(
                "\"mcpServers\":{{\"gtkg\":{}}}",
                serde_json::to_string(&desired)
                    .map_err(|_| AssistantInstallErrorV2::InvalidNativeConfig)?
            );
            insert_json_member_v2(base, &root, member.as_bytes())
        }
        (AssistantConfigActionV2::Uninstall, None) => {
            return Err(AssistantInstallErrorV2::ManagedEntryMissing);
        }
        (_, Some(index)) => {
            let mcp_member = &root.members[index];
            let servers = scan_json_object_v2(base, mcp_member.value_start)?;
            if servers.value_end != mcp_member.value_end {
                return Err(AssistantInstallErrorV2::InvalidNativeConfig);
            }
            reject_duplicate_json_keys_v2(&servers)?;
            let gtkg_index = servers
                .members
                .iter()
                .position(|member| member.key == "gtkg");
            match (action, gtkg_index) {
                (AssistantConfigActionV2::Install, None) => {
                    let desired = desired_json_server_v2(block, false, false, false);
                    let member = format!(
                        "\"gtkg\":{}",
                        serde_json::to_string(&desired)
                            .map_err(|_| AssistantInstallErrorV2::InvalidNativeConfig)?
                    );
                    insert_json_member_v2(base, &servers, member.as_bytes())
                }
                (AssistantConfigActionV2::Install, Some(gtkg_index)) => {
                    let member = &servers.members[gtkg_index];
                    validate_managed_json_object_v2(base, member)?;
                    let observed: serde_json::Value =
                        serde_json::from_slice(&base[member.value_start..member.value_end])
                            .map_err(|_| AssistantInstallErrorV2::InvalidNativeConfig)?;
                    if json_managed_entry_flags_v2(&observed, block).is_some() {
                        before.to_vec()
                    } else {
                        return Err(AssistantInstallErrorV2::ManagedEntryConflict);
                    }
                }
                (AssistantConfigActionV2::Uninstall, None) => {
                    return Err(AssistantInstallErrorV2::ManagedEntryMissing);
                }
                (AssistantConfigActionV2::Uninstall, Some(gtkg_index)) => {
                    let member = &servers.members[gtkg_index];
                    validate_managed_json_object_v2(base, member)?;
                    let observed: serde_json::Value =
                        serde_json::from_slice(&base[member.value_start..member.value_end])
                            .map_err(|_| AssistantInstallErrorV2::InvalidNativeConfig)?;
                    let Some((parent_created, file_created, original_empty)) =
                        json_managed_entry_flags_v2(&observed, block)
                    else {
                        return Err(AssistantInstallErrorV2::ManagedEntryConflict);
                    };
                    if parent_created && servers.members.len() == 1 {
                        if root.members.len() == 1 {
                            if original_empty {
                                Vec::new()
                            } else if file_created {
                                b"{}".to_vec()
                            } else {
                                remove_json_member_v2(base, &root, index)
                            }
                        } else {
                            remove_json_member_v2(base, &root, index)
                        }
                    } else {
                        remove_json_member_v2(base, &servers, gtkg_index)
                    }
                }
            }
        }
    };
    Ok((rendered, sensitive_value_count))
}

fn validate_managed_json_object_v2(
    bytes: &[u8],
    member: &JsonMemberSpanV2,
) -> Result<(), AssistantInstallErrorV2> {
    let managed = scan_json_object_v2(bytes, member.value_start)?;
    if managed.value_end != member.value_end {
        return Err(AssistantInstallErrorV2::InvalidNativeConfig);
    }
    reject_duplicate_json_keys_v2(&managed)?;
    if let Some(env_member) = managed.members.iter().find(|item| item.key == "env") {
        let env = scan_json_object_v2(bytes, env_member.value_start)?;
        if env.value_end != env_member.value_end {
            return Err(AssistantInstallErrorV2::InvalidNativeConfig);
        }
        reject_duplicate_json_keys_v2(&env)?;
    }
    Ok(())
}

fn json_managed_entry_flags_v2(
    value: &serde_json::Value,
    block: &AssistantManagedBlockV2,
) -> Option<(bool, bool, bool)> {
    let object = value.as_object()?;
    if object.len() != 3
        || object.get("command")?.as_str()? != "gtkg"
        || object.get("args")?
            != &serde_json::Value::Array(
                assistant_stdio_args_v2(&block.profile_id)
                    .into_iter()
                    .map(serde_json::Value::String)
                    .collect(),
            )
    {
        return None;
    }
    let env = object.get("env")?.as_object()?;
    if env.len() != 4
        || env.get("GTKG_MANAGED_CONFIG_SCHEMA")?.as_str()? != "gtkg.assistant-native-entry/v2"
    {
        return None;
    }
    let parent_created = match env.get("GTKG_MANAGED_PARENT_CREATED")?.as_str()? {
        "1" => true,
        "0" => false,
        _ => return None,
    };
    let file_created = match env.get("GTKG_MANAGED_FILE_CREATED")?.as_str()? {
        "1" => true,
        "0" => false,
        _ => return None,
    };
    let original_empty = match env.get("GTKG_MANAGED_ORIGINAL_EMPTY")?.as_str()? {
        "1" => true,
        "0" => false,
        _ => return None,
    };
    Some((parent_created, file_created, original_empty))
}

#[derive(Debug)]
struct JsonMemberSpanV2 {
    key: String,
    key_start: usize,
    value_start: usize,
    value_end: usize,
    comma_before: Option<usize>,
    comma_after: Option<usize>,
}

#[derive(Debug)]
struct JsonObjectSpanV2 {
    value_end: usize,
    close: usize,
    members: Vec<JsonMemberSpanV2>,
}

fn scan_json_object_v2(
    bytes: &[u8],
    start: usize,
) -> Result<JsonObjectSpanV2, AssistantInstallErrorV2> {
    let mut cursor = skip_json_space_v2(bytes, start);
    if bytes.get(cursor) != Some(&b'{') {
        return Err(AssistantInstallErrorV2::InvalidNativeConfig);
    }
    cursor += 1;
    let mut members = Vec::new();
    let mut comma_before = None;
    loop {
        cursor = skip_json_space_v2(bytes, cursor);
        if bytes.get(cursor) == Some(&b'}') {
            return Ok(JsonObjectSpanV2 {
                value_end: cursor + 1,
                close: cursor,
                members,
            });
        }
        let key_start = cursor;
        let key_end = scan_json_string_end_v2(bytes, key_start)?;
        let key: String = serde_json::from_slice(&bytes[key_start..key_end])
            .map_err(|_| AssistantInstallErrorV2::InvalidNativeConfig)?;
        cursor = skip_json_space_v2(bytes, key_end);
        if bytes.get(cursor) != Some(&b':') {
            return Err(AssistantInstallErrorV2::InvalidNativeConfig);
        }
        cursor = skip_json_space_v2(bytes, cursor + 1);
        let value_start = cursor;
        let value_end = scan_json_value_end_v2(bytes, value_start)?;
        cursor = skip_json_space_v2(bytes, value_end);
        let comma_after = if bytes.get(cursor) == Some(&b',') {
            Some(cursor)
        } else if bytes.get(cursor) == Some(&b'}') {
            None
        } else {
            return Err(AssistantInstallErrorV2::InvalidNativeConfig);
        };
        members.push(JsonMemberSpanV2 {
            key,
            key_start,
            value_start,
            value_end,
            comma_before,
            comma_after,
        });
        if let Some(comma) = comma_after {
            comma_before = Some(comma);
            cursor = comma + 1;
        }
    }
}

fn scan_json_string_end_v2(bytes: &[u8], start: usize) -> Result<usize, AssistantInstallErrorV2> {
    if bytes.get(start) != Some(&b'"') {
        return Err(AssistantInstallErrorV2::InvalidNativeConfig);
    }
    let mut cursor = start + 1;
    let mut escaped = false;
    while let Some(byte) = bytes.get(cursor) {
        if escaped {
            escaped = false;
        } else if *byte == b'\\' {
            escaped = true;
        } else if *byte == b'"' {
            return Ok(cursor + 1);
        }
        cursor += 1;
    }
    Err(AssistantInstallErrorV2::InvalidNativeConfig)
}

fn scan_json_value_end_v2(bytes: &[u8], start: usize) -> Result<usize, AssistantInstallErrorV2> {
    match bytes.get(start) {
        Some(b'"') => scan_json_string_end_v2(bytes, start),
        Some(b'{') | Some(b'[') => {
            let mut stack = vec![
                *bytes
                    .get(start)
                    .ok_or(AssistantInstallErrorV2::InvalidNativeConfig)?,
            ];
            let mut cursor = start + 1;
            while let Some(byte) = bytes.get(cursor) {
                match *byte {
                    b'"' => cursor = scan_json_string_end_v2(bytes, cursor)?,
                    b'{' | b'[' => {
                        stack.push(*byte);
                        cursor += 1;
                    }
                    b'}' => {
                        if stack.pop() != Some(b'{') {
                            return Err(AssistantInstallErrorV2::InvalidNativeConfig);
                        }
                        cursor += 1;
                        if stack.is_empty() {
                            return Ok(cursor);
                        }
                    }
                    b']' => {
                        if stack.pop() != Some(b'[') {
                            return Err(AssistantInstallErrorV2::InvalidNativeConfig);
                        }
                        cursor += 1;
                        if stack.is_empty() {
                            return Ok(cursor);
                        }
                    }
                    _ => cursor += 1,
                }
            }
            Err(AssistantInstallErrorV2::InvalidNativeConfig)
        }
        Some(_) => {
            let mut cursor = start;
            while let Some(byte) = bytes.get(cursor) {
                if matches!(byte, b',' | b'}' | b']') || byte.is_ascii_whitespace() {
                    break;
                }
                cursor += 1;
            }
            if cursor == start {
                Err(AssistantInstallErrorV2::InvalidNativeConfig)
            } else {
                Ok(cursor)
            }
        }
        None => Err(AssistantInstallErrorV2::InvalidNativeConfig),
    }
}

fn skip_json_space_v2(bytes: &[u8], mut cursor: usize) -> usize {
    while bytes
        .get(cursor)
        .is_some_and(|byte| byte.is_ascii_whitespace())
    {
        cursor += 1;
    }
    cursor
}

fn reject_duplicate_json_keys_v2(object: &JsonObjectSpanV2) -> Result<(), AssistantInstallErrorV2> {
    let mut keys = std::collections::BTreeSet::new();
    if object
        .members
        .iter()
        .any(|member| !keys.insert(member.key.as_str()))
    {
        return Err(AssistantInstallErrorV2::InvalidNativeConfig);
    }
    Ok(())
}

fn insert_json_member_v2(bytes: &[u8], object: &JsonObjectSpanV2, member: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(bytes.len() + member.len() + 1);
    output.extend_from_slice(&bytes[..object.close]);
    if !object.members.is_empty() {
        output.push(b',');
    }
    output.extend_from_slice(member);
    output.extend_from_slice(&bytes[object.close..]);
    output
}

fn remove_json_member_v2(bytes: &[u8], object: &JsonObjectSpanV2, index: usize) -> Vec<u8> {
    let member = &object.members[index];
    let (remove_start, remove_end) = if let Some(comma) = member.comma_before {
        (comma, member.value_end)
    } else if let Some(comma) = member.comma_after {
        (member.key_start, comma + 1)
    } else {
        (member.key_start, member.value_end)
    };
    let mut output = Vec::with_capacity(bytes.len() - (remove_end - remove_start));
    output.extend_from_slice(&bytes[..remove_start]);
    output.extend_from_slice(&bytes[remove_end..]);
    output
}

fn restore_line_suffix_v2(mut rendered: Vec<u8>, original: &[u8]) -> Vec<u8> {
    while rendered
        .last()
        .is_some_and(|byte| matches!(byte, b'\r' | b'\n'))
    {
        rendered.pop();
    }
    let suffix_at = original
        .iter()
        .rposition(|byte| !matches!(byte, b'\r' | b'\n'))
        .map_or(0, |index| index + 1);
    rendered.extend_from_slice(&original[suffix_at..]);
    rendered
}

fn count_sensitive_toml_values_v2(source: &str) -> u64 {
    source.parse::<DocumentMut>().ok().map_or(0, |document| {
        count_sensitive_toml_table_v2(document.as_table())
    })
}

fn count_sensitive_toml_table_v2(table: &Table) -> u64 {
    table
        .iter()
        .map(|(key, item)| {
            u64::from(is_sensitive_key_v2(key) && !item.is_none())
                + count_sensitive_toml_item_v2(item)
        })
        .sum()
}

fn count_sensitive_toml_item_v2(item: &Item) -> u64 {
    match item {
        Item::None => 0,
        Item::Value(value) => count_sensitive_toml_value_v2(value),
        Item::Table(table) => count_sensitive_toml_table_v2(table),
        Item::ArrayOfTables(tables) => tables.iter().map(count_sensitive_toml_table_v2).sum(),
    }
}

fn count_sensitive_toml_value_v2(value: &toml_edit::Value) -> u64 {
    if let Some(table) = value.as_inline_table() {
        return table
            .iter()
            .map(|(key, value)| {
                u64::from(is_sensitive_key_v2(key)) + count_sensitive_toml_value_v2(value)
            })
            .sum();
    }
    if let Some(array) = value.as_array() {
        return array.iter().map(count_sensitive_toml_value_v2).sum();
    }
    0
}

fn count_sensitive_json_values_v2(value: &serde_json::Value) -> u64 {
    match value {
        serde_json::Value::Object(map) => map
            .iter()
            .map(|(key, value)| {
                u64::from(is_sensitive_key_v2(key) && !value.is_null())
                    + count_sensitive_json_values_v2(value)
            })
            .sum(),
        serde_json::Value::Array(values) => values.iter().map(count_sensitive_json_values_v2).sum(),
        _ => 0,
    }
}

fn is_sensitive_key_v2(key: &str) -> bool {
    let key = key.trim().trim_matches(['\'', '"']).to_ascii_lowercase();
    ["secret", "token", "password", "credential", "api_key"]
        .iter()
        .any(|needle| key.contains(needle))
}

fn is_canonical_sha256_v2(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

pub fn apply_assistant_install_v2(
    root: &Path,
    preview: &AssistantInstallPreviewV2,
) -> Result<AssistantInstallReceiptV2, AssistantInstallErrorV2> {
    apply_assistant_install_v2_internal::<fn(&Path), fn(&Path)>(root, preview, None, None)
}

#[cfg(feature = "test-faults")]
pub fn apply_assistant_install_v2_with_precommit_hook<F>(
    root: &Path,
    preview: &AssistantInstallPreviewV2,
    hook: F,
) -> Result<AssistantInstallReceiptV2, AssistantInstallErrorV2>
where
    F: FnOnce(&Path),
{
    apply_assistant_install_v2_internal::<F, fn(&Path)>(root, preview, Some(hook), None)
}

#[cfg(feature = "test-faults")]
pub fn apply_assistant_install_v2_with_postexchange_hook<F>(
    root: &Path,
    preview: &AssistantInstallPreviewV2,
    hook: F,
) -> Result<AssistantInstallReceiptV2, AssistantInstallErrorV2>
where
    F: FnOnce(&Path),
{
    apply_assistant_install_v2_internal::<fn(&Path), F>(root, preview, None, Some(hook))
}

fn apply_assistant_install_v2_internal<F, G>(
    root: &Path,
    preview: &AssistantInstallPreviewV2,
    precommit_hook: Option<F>,
    postexchange_hook: Option<G>,
) -> Result<AssistantInstallReceiptV2, AssistantInstallErrorV2>
where
    F: FnOnce(&Path),
    G: FnOnce(&Path),
{
    let (observed_root, root_file, root_identity) = open_root_v2(root)?;
    if observed_root != preview.root || !root_identity.same_object(&preview.root_identity) {
        return Err(AssistantInstallErrorV2::CasConflict);
    }
    let relative = Path::new(&preview.target_file);
    let AssistantParentV2::Ready {
        directory,
        name,
        created_count,
    } = walk_parent_v2(root_file, relative, true)?
    else {
        return Err(AssistantInstallErrorV2::Io);
    };
    let observed = read_at_v2(&directory, &name)?;
    if sha256(&observed.bytes) != preview.before_sha256
        || observed.identity != preview.before_identity
    {
        return Err(AssistantInstallErrorV2::CasConflict);
    }
    if !preview.changed {
        return Ok(receipt_from_preview_v2(
            preview,
            0,
            created_count,
            observed
                .identity
                .as_ref()
                .map_or(preview.target_mode, |identity| identity.mode),
            false,
            0,
        ));
    }

    let (temp_name, mut temporary) =
        create_private_temp_v2(&directory, preview.target_mode, &preview.after_sha256)?;
    let temp_observed = read_at_v2(&directory, &temp_name)?;
    let temp_identity = temp_observed.identity.ok_or(AssistantInstallErrorV2::Io)?;
    let mut temp_exists = true;
    let result = (|| {
        temporary
            .write_all(&preview.after_content)
            .map_err(|_| AssistantInstallErrorV2::Io)?;
        temporary
            .sync_all()
            .map_err(|_| AssistantInstallErrorV2::Io)?;
        drop(temporary);

        let before_rename = read_at_v2(&directory, &name)?;
        if sha256(&before_rename.bytes) != preview.before_sha256
            || before_rename.identity != preview.before_identity
        {
            return Err(AssistantInstallErrorV2::CasConflict);
        }
        if let Some(hook) = precommit_hook {
            hook(&preview.root.join(&preview.target_file));
        }

        if preview.before_identity.is_some() {
            exchange_entries_v2(&directory, &temp_name, &name)?;
            let displaced = match read_at_v2(&directory, &temp_name) {
                Ok(displaced) => displaced,
                Err(error) => {
                    if rollback_exchange_if_owned_v2(
                        &directory,
                        &temp_name,
                        &name,
                        &temp_identity,
                        &preview.after_sha256,
                    )? {
                        directory
                            .sync_all()
                            .map_err(|_| AssistantInstallErrorV2::Io)?;
                    }
                    return Err(error);
                }
            };
            if sha256(&displaced.bytes) != preview.before_sha256
                || displaced.identity != preview.before_identity
            {
                if rollback_exchange_if_owned_v2(
                    &directory,
                    &temp_name,
                    &name,
                    &temp_identity,
                    &preview.after_sha256,
                )? {
                    directory
                        .sync_all()
                        .map_err(|_| AssistantInstallErrorV2::Io)?;
                } else {
                    rustix::fs::unlinkat(&directory, &temp_name, rustix::fs::AtFlags::empty())
                        .map_err(|_| AssistantInstallErrorV2::Io)?;
                    temp_exists = false;
                }
                return Err(AssistantInstallErrorV2::CasConflict);
            }
        } else {
            rename_noreplace_v2(&directory, &temp_name, &name)?;
            temp_exists = false;
        }
        if let Some(hook) = postexchange_hook {
            hook(&preview.root.join(&preview.target_file));
        }
        directory
            .sync_all()
            .map_err(|_| AssistantInstallErrorV2::Io)?;
        let readback = match read_at_v2(&directory, &name) {
            Ok(readback) => readback,
            Err(error) => {
                if preview.before_identity.is_some() {
                    let _ =
                        rustix::fs::unlinkat(&directory, &temp_name, rustix::fs::AtFlags::empty());
                    temp_exists = false;
                }
                return Err(error);
            }
        };
        if sha256(&readback.bytes) != preview.after_sha256
            || readback
                .identity
                .as_ref()
                .is_none_or(|identity| !identity.same_object(&temp_identity))
        {
            if preview.before_identity.is_some() {
                rustix::fs::unlinkat(&directory, &temp_name, rustix::fs::AtFlags::empty())
                    .map_err(|_| AssistantInstallErrorV2::Io)?;
                temp_exists = false;
                directory
                    .sync_all()
                    .map_err(|_| AssistantInstallErrorV2::Io)?;
            }
            return Err(AssistantInstallErrorV2::CasConflict);
        }
        if preview.before_identity.is_some() {
            rustix::fs::unlinkat(&directory, &temp_name, rustix::fs::AtFlags::empty())
                .map_err(|_| AssistantInstallErrorV2::Io)?;
            temp_exists = false;
            directory
                .sync_all()
                .map_err(|_| AssistantInstallErrorV2::Io)?;
        }
        let target_mode = readback
            .identity
            .as_ref()
            .map_or(preview.target_mode, |identity| identity.mode);
        Ok(receipt_from_preview_v2(
            preview,
            1,
            created_count,
            target_mode,
            false,
            0,
        ))
    })();
    if temp_exists {
        let observed_temp = read_at_v2(&directory, &temp_name).ok();
        if observed_temp
            .as_ref()
            .and_then(|observed| observed.identity.as_ref())
            .is_some_and(|identity| identity.same_object(&temp_identity))
        {
            let _ = rustix::fs::unlinkat(&directory, &temp_name, rustix::fs::AtFlags::empty());
            let _ = directory.sync_all();
        }
    }
    result
}

fn rollback_exchange_if_owned_v2(
    directory: &File,
    temporary: &OsStr,
    target: &OsStr,
    installed_identity: &AssistantFsIdentityV2,
    installed_sha256: &str,
) -> Result<bool, AssistantInstallErrorV2> {
    let current = read_at_v2(directory, target)?;
    let still_owned = sha256(&current.bytes) == installed_sha256
        && current
            .identity
            .as_ref()
            .is_some_and(|identity| identity.same_object(installed_identity));
    if still_owned {
        exchange_entries_v2(directory, temporary, target)?;
    }
    Ok(still_owned)
}

#[cfg(any(target_os = "macos", target_os = "ios", target_os = "linux"))]
fn exchange_entries_v2(
    directory: &File,
    temporary: &OsStr,
    target: &OsStr,
) -> Result<(), AssistantInstallErrorV2> {
    rustix::fs::renameat_with(
        directory,
        temporary,
        directory,
        target,
        rustix::fs::RenameFlags::EXCHANGE,
    )
    .map_err(|error| {
        if error == rustix::io::Errno::NOENT {
            AssistantInstallErrorV2::CasConflict
        } else {
            AssistantInstallErrorV2::Io
        }
    })
}

#[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "linux")))]
fn exchange_entries_v2(
    _directory: &File,
    _temporary: &OsStr,
    _target: &OsStr,
) -> Result<(), AssistantInstallErrorV2> {
    Err(AssistantInstallErrorV2::UnsupportedPlatform)
}

#[cfg(any(target_os = "macos", target_os = "ios", target_os = "linux"))]
fn rename_noreplace_v2(
    directory: &File,
    temporary: &OsStr,
    target: &OsStr,
) -> Result<(), AssistantInstallErrorV2> {
    rustix::fs::renameat_with(
        directory,
        temporary,
        directory,
        target,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .map_err(|error| {
        if error == rustix::io::Errno::EXIST {
            AssistantInstallErrorV2::CasConflict
        } else {
            AssistantInstallErrorV2::Io
        }
    })
}

#[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "linux")))]
fn rename_noreplace_v2(
    _directory: &File,
    _temporary: &OsStr,
    _target: &OsStr,
) -> Result<(), AssistantInstallErrorV2> {
    Err(AssistantInstallErrorV2::UnsupportedPlatform)
}

fn receipt_from_preview_v2(
    preview: &AssistantInstallPreviewV2,
    write_count: u64,
    directory_create_count: u64,
    target_mode: u32,
    target_removed: bool,
    directory_remove_count: u64,
) -> AssistantInstallReceiptV2 {
    AssistantInstallReceiptV2 {
        schema_version: ASSISTANT_INSTALL_RECEIPT_SCHEMA_V2.to_owned(),
        platform: format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
        assistant: preview.assistant,
        scope: preview.scope,
        target_file: preview.target_file.clone(),
        root_identity_sha256: assistant_root_identity_sha256_v2(&preview.root_identity),
        profile_id: preview.profile_id.clone(),
        before_sha256: preview.before_sha256.clone(),
        after_sha256: preview.after_sha256.clone(),
        managed_block_sha256: preview.managed_block_sha256.clone(),
        write_count,
        directory_create_count,
        sensitive_value_count: preview.sensitive_value_count,
        secret_output_count: 0,
        target_mode,
        target_removed,
        directory_remove_count,
        readback_verified: true,
    }
}

impl AssistantFsIdentityV2 {
    fn same_object(&self, other: &Self) -> bool {
        self.device == other.device && self.inode == other.inode
    }
}

fn assistant_root_identity_sha256_v2(identity: &AssistantFsIdentityV2) -> String {
    sha256(
        &serde_json::to_vec(&(
            "gtkg.assistant-root-identity/v1",
            identity.device,
            identity.inode,
        ))
        .expect("root identity is serializable"),
    )
}

enum AssistantParentV2 {
    Missing,
    Ready {
        directory: File,
        name: OsString,
        created_count: u64,
    },
}

#[cfg(unix)]
fn open_root_v2(
    root: &Path,
) -> Result<(PathBuf, File, AssistantFsIdentityV2), AssistantInstallErrorV2> {
    use std::os::unix::fs::MetadataExt;

    let descriptor = rustix::fs::open(
        root,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|_| AssistantInstallErrorV2::PathEscape)?;
    let file = File::from(descriptor);
    let metadata = file.metadata().map_err(|_| AssistantInstallErrorV2::Io)?;
    if !metadata.is_dir() {
        return Err(AssistantInstallErrorV2::PathEscape);
    }
    let canonical = fs::canonicalize(root).map_err(|_| AssistantInstallErrorV2::Io)?;
    let identity = AssistantFsIdentityV2 {
        device: metadata.dev(),
        inode: metadata.ino(),
        mode: metadata.mode() & 0o777,
    };
    Ok((canonical, file, identity))
}

#[cfg(not(unix))]
fn open_root_v2(
    _root: &Path,
) -> Result<(PathBuf, File, AssistantFsIdentityV2), AssistantInstallErrorV2> {
    Err(AssistantInstallErrorV2::UnsupportedPlatform)
}

#[cfg(unix)]
fn walk_parent_v2(
    mut directory: File,
    relative: &Path,
    create: bool,
) -> Result<AssistantParentV2, AssistantInstallErrorV2> {
    let components = relative
        .components()
        .map(|component| match component {
            Component::Normal(value) => Ok(value.to_os_string()),
            _ => Err(AssistantInstallErrorV2::PathEscape),
        })
        .collect::<Result<Vec<_>, _>>()?;
    let Some((name, parents)) = components.split_last() else {
        return Err(AssistantInstallErrorV2::PathEscape);
    };
    let mut created_count = 0_u64;
    let flags = rustix::fs::OFlags::RDONLY
        | rustix::fs::OFlags::DIRECTORY
        | rustix::fs::OFlags::NOFOLLOW
        | rustix::fs::OFlags::CLOEXEC;
    for component in parents {
        let opened =
            match rustix::fs::openat(&directory, component, flags, rustix::fs::Mode::empty()) {
                Ok(opened) => opened,
                Err(error) if error == rustix::io::Errno::NOENT && !create => {
                    return Ok(AssistantParentV2::Missing);
                }
                Err(error) if error == rustix::io::Errno::NOENT && create => {
                    match rustix::fs::mkdirat(
                        &directory,
                        component,
                        rustix::fs::Mode::from_raw_mode(0o700),
                    ) {
                        Ok(()) => created_count += 1,
                        Err(race) if race == rustix::io::Errno::EXIST => {}
                        Err(_) => return Err(AssistantInstallErrorV2::Io),
                    }
                    directory
                        .sync_all()
                        .map_err(|_| AssistantInstallErrorV2::Io)?;
                    rustix::fs::openat(&directory, component, flags, rustix::fs::Mode::empty())
                        .map_err(map_dirfd_error_v2)?
                }
                Err(error) => return Err(map_dirfd_error_v2(error)),
            };
        directory = File::from(opened);
    }
    Ok(AssistantParentV2::Ready {
        directory,
        name: name.clone(),
        created_count,
    })
}

#[cfg(not(unix))]
fn walk_parent_v2(
    _directory: File,
    _relative: &Path,
    _create: bool,
) -> Result<AssistantParentV2, AssistantInstallErrorV2> {
    Err(AssistantInstallErrorV2::UnsupportedPlatform)
}

#[cfg(unix)]
fn map_dirfd_error_v2(error: rustix::io::Errno) -> AssistantInstallErrorV2 {
    if matches!(error, rustix::io::Errno::LOOP | rustix::io::Errno::NOTDIR) {
        AssistantInstallErrorV2::PathEscape
    } else {
        AssistantInstallErrorV2::Io
    }
}

#[cfg(unix)]
fn read_at_v2(
    directory: &File,
    name: &OsStr,
) -> Result<AssistantObservedFileV2, AssistantInstallErrorV2> {
    use std::os::unix::fs::MetadataExt;

    let descriptor = match rustix::fs::openat(
        directory,
        name,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::NONBLOCK
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    ) {
        Ok(descriptor) => descriptor,
        Err(error) if error == rustix::io::Errno::NOENT => {
            return Ok(AssistantObservedFileV2 {
                bytes: Vec::new(),
                identity: None,
            });
        }
        Err(error) => return Err(map_dirfd_error_v2(error)),
    };
    let mut file = File::from(descriptor);
    let metadata = file.metadata().map_err(|_| AssistantInstallErrorV2::Io)?;
    if !metadata.is_file() || metadata.nlink() != 1 {
        return Err(AssistantInstallErrorV2::UnsafeTarget);
    }
    if metadata.len() > MAX_ASSISTANT_CONFIG_BYTES_V2 {
        return Err(AssistantInstallErrorV2::InvalidNativeConfig);
    }
    let capacity = usize::try_from(metadata.len()).map_err(|_| AssistantInstallErrorV2::Io)?;
    let mut bytes = Vec::with_capacity(capacity);
    Read::by_ref(&mut file)
        .take(MAX_ASSISTANT_CONFIG_BYTES_V2 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| AssistantInstallErrorV2::Io)?;
    if bytes.len() as u64 > MAX_ASSISTANT_CONFIG_BYTES_V2 {
        return Err(AssistantInstallErrorV2::InvalidNativeConfig);
    }
    let after = file.metadata().map_err(|_| AssistantInstallErrorV2::Io)?;
    if metadata.dev() != after.dev()
        || metadata.ino() != after.ino()
        || metadata.len() != after.len()
    {
        return Err(AssistantInstallErrorV2::CasConflict);
    }
    Ok(AssistantObservedFileV2 {
        bytes,
        identity: Some(AssistantFsIdentityV2 {
            device: metadata.dev(),
            inode: metadata.ino(),
            mode: metadata.mode() & 0o777,
        }),
    })
}

#[cfg(not(unix))]
fn read_at_v2(
    _directory: &File,
    _name: &OsStr,
) -> Result<AssistantObservedFileV2, AssistantInstallErrorV2> {
    Err(AssistantInstallErrorV2::UnsupportedPlatform)
}

#[cfg(unix)]
fn create_private_temp_v2(
    directory: &File,
    mode: u32,
    after_sha256: &str,
) -> Result<(OsString, File), AssistantInstallErrorV2> {
    let raw_mode = u16::try_from(mode & 0o777).map_err(|_| AssistantInstallErrorV2::Io)?;
    for _ in 0..16 {
        let sequence = ASSISTANT_TEMP_SEQUENCE_V2.fetch_add(1, Ordering::Relaxed);
        let digest_prefix = after_sha256.get(7..23).unwrap_or("invalid-digest");
        let name = OsString::from(format!(
            ".gtkg-{}-{sequence}-{digest_prefix}.tmp",
            std::process::id()
        ));
        match rustix::fs::openat(
            directory,
            &name,
            rustix::fs::OFlags::WRONLY
                | rustix::fs::OFlags::CREATE
                | rustix::fs::OFlags::EXCL
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::from_raw_mode(raw_mode),
        ) {
            Ok(descriptor) => {
                let file = File::from(descriptor);
                if rustix::fs::fchmod(&file, rustix::fs::Mode::from_raw_mode(raw_mode)).is_err() {
                    drop(file);
                    let _ = rustix::fs::unlinkat(directory, &name, rustix::fs::AtFlags::empty());
                    return Err(AssistantInstallErrorV2::Io);
                }
                return Ok((name, file));
            }
            Err(error) if error == rustix::io::Errno::EXIST => continue,
            Err(error) => return Err(map_dirfd_error_v2(error)),
        }
    }
    Err(AssistantInstallErrorV2::Io)
}

#[cfg(not(unix))]
fn create_private_temp_v2(
    _directory: &File,
    _mode: u32,
    _after_sha256: &str,
) -> Result<(OsString, File), AssistantInstallErrorV2> {
    Err(AssistantInstallErrorV2::UnsupportedPlatform)
}
