//! U01 isolated, file-descriptor-bound package installation.
//!
//! This module deliberately has no knowledge of a real user home, PATH, Current, or release
//! assets. Callers must pass both a package root and an already-created isolated target root.
//! Every relative path is walked through `openat`/`O_NOFOLLOW`; a manifest only ever grants the
//! exact files it names.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const INSTALL_MANIFEST_SCHEMA_V1: &str = "gtkg.install-manifest/v1";
pub const INSTALL_RECEIPT_SCHEMA_V1: &str = "gtkg.install-receipt/v1";
pub const MAX_INSTALL_FILE_BYTES_V1: u64 = 64 * 1024 * 1024;
pub const MAX_INSTALL_TOTAL_BYTES_V1: u64 = 256 * 1024 * 1024;

const INSTALL_STATE_SCHEMA_V1: &str = "gtkg.install-state/v1";
const INSTALL_STATE_DIR_V1: &str = ".gtkg-install";
const INSTALL_STATE_FILE_V1: &str = ".gtkg-install/manifest.json";
const INSTALL_TEMP_ATTEMPTS_V1: usize = 32;

static INSTALL_TEMP_SEQUENCE_V1: AtomicU64 = AtomicU64::new(1);

#[cfg(unix)]
type PostMkdirHookV1<'a> = dyn FnMut(&Path, &OsStr) + 'a;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallManifestV1 {
    pub schema_version: String,
    pub version: String,
    pub platform: String,
    /// Package-relative source paths. Map keys in `modes`, `digests`, and `destinations` must be
    /// exactly this set.
    pub files: Vec<String>,
    pub modes: BTreeMap<String, u32>,
    pub digests: BTreeMap<String, String>,
    pub destinations: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallActionV1 {
    Install,
    Upgrade,
    Rollback,
    Uninstall,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallReceiptV1 {
    pub schema_version: String,
    pub action: InstallActionV1,
    pub version: String,
    pub platform: String,
    pub manifest_sha256: String,
    pub previous_manifest_sha256: Option<String>,
    pub root_identity_sha256: String,
    pub capability_id: String,
    pub capability_digest: String,
    pub managed_files: Vec<String>,
    pub managed_file_write_count: u64,
    pub managed_file_remove_count: u64,
    pub metadata_write_count: u64,
    pub dry_run: bool,
    pub readback_verified: bool,
}

/// Read-only proof returned after a descriptor-bound re-read of one isolated
/// installation.  It is intentionally not a system-install or Current claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IsolatedInstallIdentityReadbackV1 {
    pub manifest_sha256: String,
    pub binary_sha256: String,
    pub root_identity_sha256: String,
    pub capability_id: String,
    pub capability_digest: String,
    pub readback_verified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum InstallErrorV1 {
    #[error("install manifest is invalid")]
    InvalidManifest,
    #[error("install path escaped its authorized root")]
    PathEscape,
    #[error("install target is a symlink, hard link, or non-regular file")]
    UnsafeTarget,
    #[error("an explicit isolated-root capability is required")]
    IsolationRequired,
    #[error("the isolated-root capability does not match the target, preview, state, or receipt")]
    CapabilityMismatch,
    #[error("install would clobber an unmanaged path")]
    NoClobber,
    #[error("install input or target changed since preview")]
    CasConflict,
    #[error("install source or managed-state digest does not match")]
    IntegrityMismatch,
    #[error("rollback is not authorized by the current managed state")]
    RollbackForbidden,
    #[error("installer requires Unix dirfd semantics")]
    UnsupportedPlatform,
    #[error("installer I/O failed")]
    Io,
    #[error("deterministic installer test fault injected")]
    TestFaultInjected,
}

/// A non-serializable capability for one newly-created, owner-only isolated target root.
///
/// The constructor is the only production path that can mint this value. It is deliberately not
/// reconstructible from a pathname or receipt, so a raw target path cannot gain installer write
/// authority merely by resembling a temporary directory.
#[derive(Clone, PartialEq, Eq)]
pub struct IsolatedInstallRootV1 {
    root: PathBuf,
    identity: FsIdentityV1,
    parent_root: PathBuf,
    parent_identity: FsIdentityV1,
    child_name: OsString,
    capability_id: String,
    capability_digest: String,
}

impl std::fmt::Debug for IsolatedInstallRootV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IsolatedInstallRootV1")
            .field("root", &self.root)
            .field("parent_root", &self.parent_root)
            .field("capability_id", &self.capability_id)
            .field("capability_digest", &self.capability_digest)
            .finish_non_exhaustive()
    }
}

impl IsolatedInstallRootV1 {
    pub fn path(&self) -> &Path {
        &self.root
    }

    pub fn capability_id(&self) -> String {
        self.capability_id.clone()
    }

    pub fn capability_digest(&self) -> String {
        self.capability_digest.clone()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct InstallPreviewV1 {
    action: InstallActionV1,
    manifest: InstallManifestV1,
    manifest_sha256: String,
    previous_manifest_sha256: Option<String>,
    target_root: PathBuf,
    target_identity: FsIdentityV1,
    capability_id: String,
    capability_digest: String,
    state_directory_before: Option<FsIdentityV1>,
    state_before: ObservedFileV1,
    files: Vec<PlannedFileV1>,
    removals: Vec<PlannedRemovalV1>,
    state_after: Vec<u8>,
}

impl std::fmt::Debug for InstallPreviewV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("InstallPreviewV1")
            .field("action", &self.action)
            .field("version", &self.manifest.version)
            .field("platform", &self.manifest.platform)
            .field("manifest_sha256", &self.manifest_sha256)
            .field("previous_manifest_sha256", &self.previous_manifest_sha256)
            .field("file_count", &self.files.len())
            .field("removal_count", &self.removals.len())
            .field("write_count", &self.write_count())
            .finish_non_exhaustive()
    }
}

impl InstallPreviewV1 {
    /// A preview is the U01 dry-run surface: no target directory is created or modified.
    pub fn write_count(&self) -> u64 {
        0
    }

    pub fn manifest_sha256(&self) -> &str {
        &self.manifest_sha256
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InstallStateV1 {
    schema_version: String,
    manifest: InstallManifestV1,
    manifest_sha256: String,
    previous_manifest_sha256: Option<String>,
    root_identity_sha256: String,
    capability_id: String,
    capability_digest: String,
    managed_files: Vec<ManagedFileV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManagedFileV1 {
    destination: String,
    sha256: String,
    mode: u32,
}

#[derive(Debug, Clone)]
struct ValidatedManifestV1 {
    manifest_sha256: String,
    files: Vec<ValidatedFileV1>,
}

#[derive(Debug, Clone)]
struct ValidatedFileV1 {
    source: String,
    destination: String,
    sha256: String,
    mode: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PayloadFileV1 {
    destination: String,
    sha256: String,
    mode: u32,
    bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PlannedFileV1 {
    payload: PayloadFileV1,
    before: ObservedFileV1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PlannedRemovalV1 {
    destination: String,
    before: ObservedFileV1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FsIdentityV1 {
    device: u64,
    inode: u64,
    owner: u32,
    mode: u32,
}

impl FsIdentityV1 {
    fn same_object(&self, other: &Self) -> bool {
        self.device == other.device && self.inode == other.inode
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ObservedFileV1 {
    bytes: Vec<u8>,
    identity: Option<FsIdentityV1>,
}

impl ObservedFileV1 {
    fn absent() -> Self {
        Self {
            bytes: Vec::new(),
            identity: None,
        }
    }

    fn matches(&self, other: &Self) -> bool {
        self.bytes == other.bytes && self.identity == other.identity
    }
}

enum ParentV1 {
    Missing,
    Ready { directory: File, name: OsString },
}

enum AppliedChangeV1 {
    Created {
        directory: File,
        target: OsString,
        new: ObservedFileV1,
    },
    Replaced {
        directory: File,
        target: OsString,
        backup: OsString,
        before: ObservedFileV1,
        new: ObservedFileV1,
    },
    Removed {
        directory: File,
        target: OsString,
        backup: OsString,
        before: ObservedFileV1,
    },
}

/// Create a fresh `0700` target below one caller-authorized, owner-only temporary parent and
/// return the non-serializable capability required by the strict installer APIs.
#[cfg(unix)]
pub fn create_isolated_root_v1(
    authorized_temp_parent: &Path,
) -> Result<IsolatedInstallRootV1, InstallErrorV1> {
    create_isolated_root_internal_v1(authorized_temp_parent, None)
}

#[cfg(all(unix, feature = "test-faults"))]
pub fn create_isolated_root_v1_with_post_mkdir_hook<F>(
    authorized_temp_parent: &Path,
    hook: F,
) -> Result<IsolatedInstallRootV1, InstallErrorV1>
where
    F: FnOnce(&Path, &OsStr),
{
    let mut hook = Some(hook);
    let mut invoke = move |parent: &Path, child: &OsStr| {
        if let Some(hook) = hook.take() {
            hook(parent, child);
        }
    };
    create_isolated_root_internal_v1(authorized_temp_parent, Some(&mut invoke))
}

#[cfg(unix)]
fn create_isolated_root_internal_v1<'a>(
    authorized_temp_parent: &Path,
    post_mkdir_hook: Option<&'a mut PostMkdirHookV1<'a>>,
) -> Result<IsolatedInstallRootV1, InstallErrorV1> {
    use std::os::unix::fs::MetadataExt;

    let (parent_path, parent_file, parent_identity) = open_root_v1(authorized_temp_parent)?;
    validate_authorized_temp_parent_v1(&parent_path, &parent_identity)?;
    let mut nonce = [0_u8; 16];
    getrandom::fill(&mut nonce).map_err(|_| InstallErrorV1::Io)?;
    let mut post_mkdir_hook = post_mkdir_hook;
    for attempt in 0..INSTALL_TEMP_ATTEMPTS_V1 {
        let name = OsString::from(format!(
            ".gtkg-isolated-{}-{attempt}-{}",
            std::process::id(),
            hex::encode(&nonce[..8])
        ));
        match rustix::fs::mkdirat(&parent_file, &name, rustix::fs::Mode::from_raw_mode(0o700)) {
            Ok(()) => {}
            Err(error) if error == rustix::io::Errno::EXIST => continue,
            Err(_) => return Err(InstallErrorV1::Io),
        }
        parent_file.sync_all().map_err(|_| InstallErrorV1::Io)?;
        if let Some(hook) = post_mkdir_hook.as_deref_mut() {
            hook(&parent_path, &name);
        }
        let descriptor = rustix::fs::openat(
            &parent_file,
            &name,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|_| InstallErrorV1::CapabilityMismatch)?;
        let file = File::from(descriptor);
        let metadata = file.metadata().map_err(|_| InstallErrorV1::Io)?;
        if !metadata.is_dir() {
            return Err(InstallErrorV1::CapabilityMismatch);
        }
        let mut identity = FsIdentityV1 {
            device: metadata.dev(),
            inode: metadata.ino(),
            owner: metadata.uid(),
            mode: metadata.mode() & 0o777,
        };
        rustix::fs::fchmod(&file, rustix::fs::Mode::from_raw_mode(0o700))
            .map_err(|_| InstallErrorV1::Io)?;
        file.sync_all().map_err(|_| InstallErrorV1::Io)?;
        parent_file.sync_all().map_err(|_| InstallErrorV1::Io)?;
        let metadata = file.metadata().map_err(|_| InstallErrorV1::Io)?;
        identity.owner = metadata.uid();
        identity.mode = metadata.mode() & 0o777;
        drop(file);
        if identity.mode != 0o700 || identity.owner != parent_identity.owner {
            let _ = remove_created_child_v1(&parent_file, &name, &identity);
            return Err(InstallErrorV1::Io);
        }
        if !parent_path_still_bound_v1(&parent_path, &parent_identity) {
            let _ = remove_created_child_v1(&parent_file, &name, &identity);
            return Err(InstallErrorV1::CapabilityMismatch);
        }
        let root = parent_path.join(&name);
        let capability_id = format!("ir1-{}", hex::encode(&nonce[..8]));
        let capability_digest = sha256_v1(
            &serde_json::to_vec(&(
                "gtkg.isolated-root-capability/v1",
                parent_path.to_string_lossy().to_string(),
                parent_identity.device,
                parent_identity.inode,
                parent_identity.owner,
                name.to_string_lossy().to_string(),
                identity.device,
                identity.inode,
                identity.owner,
                &nonce,
            ))
            .map_err(|_| InstallErrorV1::Io)?,
        );
        return Ok(IsolatedInstallRootV1 {
            root,
            identity,
            parent_root: parent_path.clone(),
            parent_identity: parent_identity.clone(),
            child_name: name,
            capability_id,
            capability_digest,
        });
    }
    Err(InstallErrorV1::Io)
}

#[cfg(not(unix))]
pub fn create_isolated_root_v1(
    _authorized_temp_parent: &Path,
) -> Result<IsolatedInstallRootV1, InstallErrorV1> {
    Err(InstallErrorV1::UnsupportedPlatform)
}

/// Legacy raw-path entry point retained only so historical U01 fixtures remain readable.
///
/// It never installs: production and test-feature builds both fail closed. Current callers must
/// use `create_isolated_root_v1` and `preview_install_with_capability_v1`.
pub fn preview_install_v1(
    _package_root: &Path,
    _target_root: &Path,
    _manifest: &InstallManifestV1,
) -> Result<InstallPreviewV1, InstallErrorV1> {
    Err(InstallErrorV1::IsolationRequired)
}

pub fn preview_upgrade_v1(
    _package_root: &Path,
    _target_root: &Path,
    _manifest: &InstallManifestV1,
) -> Result<InstallPreviewV1, InstallErrorV1> {
    Err(InstallErrorV1::IsolationRequired)
}

pub fn preview_rollback_v1(
    _package_root: &Path,
    _target_root: &Path,
    _predecessor: &InstallManifestV1,
    _current_receipt: &InstallReceiptV1,
) -> Result<InstallPreviewV1, InstallErrorV1> {
    Err(InstallErrorV1::IsolationRequired)
}

pub fn apply_install_v1(
    _target_root: &Path,
    _preview: &InstallPreviewV1,
) -> Result<InstallReceiptV1, InstallErrorV1> {
    Err(InstallErrorV1::IsolationRequired)
}

pub fn uninstall_v1(
    _target_root: &Path,
    _install_receipt: &InstallReceiptV1,
) -> Result<InstallReceiptV1, InstallErrorV1> {
    Err(InstallErrorV1::IsolationRequired)
}

pub fn preview_install_with_capability_v1(
    package_root: &Path,
    isolated_root: &IsolatedInstallRootV1,
    manifest: &InstallManifestV1,
) -> Result<InstallPreviewV1, InstallErrorV1> {
    preview_change_v1(
        InstallActionV1::Install,
        package_root,
        isolated_root,
        manifest,
        None,
    )
}

pub fn preview_upgrade_with_capability_v1(
    package_root: &Path,
    isolated_root: &IsolatedInstallRootV1,
    manifest: &InstallManifestV1,
) -> Result<InstallPreviewV1, InstallErrorV1> {
    preview_change_v1(
        InstallActionV1::Upgrade,
        package_root,
        isolated_root,
        manifest,
        None,
    )
}

pub fn preview_rollback_with_capability_v1(
    package_root: &Path,
    isolated_root: &IsolatedInstallRootV1,
    predecessor: &InstallManifestV1,
    current_receipt: &InstallReceiptV1,
) -> Result<InstallPreviewV1, InstallErrorV1> {
    let predecessor_sha256 = manifest_sha256_v1(predecessor)?;
    if current_receipt.schema_version != INSTALL_RECEIPT_SCHEMA_V1
        || current_receipt.action != InstallActionV1::Upgrade
        || !current_receipt.readback_verified
        || current_receipt.dry_run
        || current_receipt.previous_manifest_sha256.as_deref() != Some(&predecessor_sha256)
    {
        return Err(InstallErrorV1::RollbackForbidden);
    }
    if current_receipt.capability_id != isolated_root.capability_id
        || current_receipt.capability_digest != isolated_root.capability_digest
    {
        return Err(InstallErrorV1::CapabilityMismatch);
    }
    let (_, target_file, target_identity) = open_isolated_root_v1(isolated_root)?;
    require_private_state_directory_v1(&target_file)?;
    let (state, _) = read_state_v1(&target_file)?;
    let state = state.ok_or(InstallErrorV1::RollbackForbidden)?;
    verify_state_v1(&target_file, &state, &target_identity, isolated_root)?;
    if state.manifest_sha256 != current_receipt.manifest_sha256
        || state.previous_manifest_sha256.as_deref() != Some(&predecessor_sha256)
        || current_receipt.root_identity_sha256 != state.root_identity_sha256
    {
        return Err(InstallErrorV1::RollbackForbidden);
    }
    preview_change_v1(
        InstallActionV1::Rollback,
        package_root,
        isolated_root,
        predecessor,
        Some(current_receipt),
    )
}

pub fn apply_install_with_capability_v1(
    isolated_root: &IsolatedInstallRootV1,
    preview: &InstallPreviewV1,
) -> Result<InstallReceiptV1, InstallErrorV1> {
    apply_install_with_capability_internal_v1(isolated_root, preview, None)
}

/// Reopens an already installed isolated root through its non-serializable
/// capability and verifies the receipt, on-disk state, manifest, and managed
/// `bin/gtkg` bytes without writing anything.
pub fn read_isolated_install_identity_with_capability_v1(
    isolated_root: &IsolatedInstallRootV1,
    expected_manifest: &InstallManifestV1,
    install_receipt: &InstallReceiptV1,
) -> Result<IsolatedInstallIdentityReadbackV1, InstallErrorV1> {
    let expected_manifest_sha256 = manifest_sha256_v1(expected_manifest)?;
    if install_receipt.schema_version != INSTALL_RECEIPT_SCHEMA_V1
        || !matches!(
            install_receipt.action,
            InstallActionV1::Install | InstallActionV1::Upgrade | InstallActionV1::Rollback
        )
        || install_receipt.dry_run
        || !install_receipt.readback_verified
        || install_receipt.manifest_sha256 != expected_manifest_sha256
        || install_receipt.capability_id != isolated_root.capability_id
        || install_receipt.capability_digest != isolated_root.capability_digest
    {
        return Err(InstallErrorV1::IntegrityMismatch);
    }
    let (_, target_file, target_identity) = open_isolated_root_v1(isolated_root)?;
    let root_identity_sha256 = root_identity_sha256_v1(&target_identity);
    if root_identity_sha256 != install_receipt.root_identity_sha256 {
        return Err(InstallErrorV1::CasConflict);
    }
    require_private_state_directory_v1(&target_file)?;
    let (state, _) = read_state_v1(&target_file)?;
    let state = state.ok_or(InstallErrorV1::IntegrityMismatch)?;
    if state.manifest != *expected_manifest
        || state.manifest_sha256 != expected_manifest_sha256
        || state.root_identity_sha256 != root_identity_sha256
        || state.manifest.version != install_receipt.version
        || state.manifest.platform != install_receipt.platform
        || install_receipt.managed_files
            != state
                .managed_files
                .iter()
                .map(|file| file.destination.clone())
                .collect::<Vec<_>>()
    {
        return Err(InstallErrorV1::IntegrityMismatch);
    }
    verify_state_v1(&target_file, &state, &target_identity, isolated_root)?;
    let binary_path = Path::new("bin/gtkg");
    let expected_binary_sha256 = expected_manifest
        .digests
        .get("bin/gtkg")
        .ok_or(InstallErrorV1::InvalidManifest)?;
    let managed_binary = state
        .managed_files
        .iter()
        .find(|file| file.destination == "bin/gtkg")
        .ok_or(InstallErrorV1::IntegrityMismatch)?;
    let observed_binary = read_relative_v1(&target_file, binary_path)?;
    if !matches_managed_file_v1(&observed_binary, managed_binary)
        || sha256_v1(&observed_binary.bytes) != *expected_binary_sha256
    {
        return Err(InstallErrorV1::IntegrityMismatch);
    }
    Ok(IsolatedInstallIdentityReadbackV1 {
        manifest_sha256: expected_manifest_sha256,
        binary_sha256: expected_binary_sha256.clone(),
        root_identity_sha256,
        capability_id: isolated_root.capability_id.clone(),
        capability_digest: isolated_root.capability_digest.clone(),
        readback_verified: true,
    })
}

#[cfg(feature = "test-faults")]
pub fn apply_install_with_cleanup_fault_v1(
    isolated_root: &IsolatedInstallRootV1,
    preview: &InstallPreviewV1,
    fail_after_backup_cleanup: u64,
) -> Result<InstallReceiptV1, InstallErrorV1> {
    apply_install_with_capability_internal_v1(
        isolated_root,
        preview,
        Some(fail_after_backup_cleanup),
    )
}

fn apply_install_with_capability_internal_v1(
    isolated_root: &IsolatedInstallRootV1,
    preview: &InstallPreviewV1,
    fail_after_backup_cleanup: Option<u64>,
) -> Result<InstallReceiptV1, InstallErrorV1> {
    let (observed_root, target_file, target_identity) = open_isolated_root_v1(isolated_root)?;
    if observed_root != preview.target_root
        || !target_identity.same_object(&preview.target_identity)
        || preview.capability_id != isolated_root.capability_id
        || preview.capability_digest != isolated_root.capability_digest
    {
        return Err(InstallErrorV1::CapabilityMismatch);
    }
    let state_directory = directory_identity_v1(&target_file, OsStr::new(INSTALL_STATE_DIR_V1))?;
    if state_directory != preview.state_directory_before {
        return Err(InstallErrorV1::CasConflict);
    }
    let (_, observed_state) = read_state_v1(&target_file)?;
    if !preview.state_before.matches(&observed_state) {
        return Err(InstallErrorV1::CasConflict);
    }
    for planned in &preview.files {
        let observed = read_relative_v1(&target_file, Path::new(&planned.payload.destination))?;
        if !planned.before.matches(&observed) {
            return Err(InstallErrorV1::CasConflict);
        }
    }
    for removal in &preview.removals {
        let observed = read_relative_v1(&target_file, Path::new(&removal.destination))?;
        if !removal.before.matches(&observed) {
            return Err(InstallErrorV1::CasConflict);
        }
    }

    let mut changes = Vec::new();
    let result = (|| {
        for planned in &preview.files {
            changes.push(stage_write_v1(
                &target_file,
                Path::new(&planned.payload.destination),
                &planned.before,
                &planned.payload.bytes,
                planned.payload.mode,
            )?);
        }
        for removal in &preview.removals {
            changes.push(stage_remove_v1(
                &target_file,
                Path::new(&removal.destination),
                &removal.before,
            )?);
        }
        changes.push(stage_write_v1(
            &target_file,
            Path::new(INSTALL_STATE_FILE_V1),
            &preview.state_before,
            &preview.state_after,
            0o600,
        )?);
        let (state, _) = read_state_v1(&target_file)?;
        let state = state.ok_or(InstallErrorV1::Io)?;
        verify_state_v1(&target_file, &state, &target_identity, isolated_root)?;
        if state.manifest_sha256 != preview.manifest_sha256
            || state.previous_manifest_sha256 != preview.previous_manifest_sha256
        {
            return Err(InstallErrorV1::CasConflict);
        }
        commit_changes_v1(&mut changes, fail_after_backup_cleanup)?;
        Ok(receipt_from_preview_v1(preview, &target_identity))
    })();
    if result.is_err() && !rollback_changes_v1(&mut changes) {
        return Err(InstallErrorV1::CasConflict);
    }
    result
}

pub fn uninstall_with_capability_v1(
    isolated_root: &IsolatedInstallRootV1,
    install_receipt: &InstallReceiptV1,
) -> Result<InstallReceiptV1, InstallErrorV1> {
    if install_receipt.schema_version != INSTALL_RECEIPT_SCHEMA_V1
        || !install_receipt.readback_verified
        || install_receipt.dry_run
        || install_receipt.action == InstallActionV1::Uninstall
    {
        return Err(InstallErrorV1::IntegrityMismatch);
    }
    if install_receipt.capability_id != isolated_root.capability_id
        || install_receipt.capability_digest != isolated_root.capability_digest
    {
        return Err(InstallErrorV1::CapabilityMismatch);
    }
    let (_, target_file, target_identity) = open_isolated_root_v1(isolated_root)?;
    let state_directory = require_private_state_directory_v1(&target_file)?;
    if root_identity_sha256_v1(&target_identity) != install_receipt.root_identity_sha256 {
        return Err(InstallErrorV1::CasConflict);
    }
    let (state, state_before) = read_state_v1(&target_file)?;
    let state = state.ok_or(InstallErrorV1::IntegrityMismatch)?;
    if state.manifest_sha256 != install_receipt.manifest_sha256
        || state.root_identity_sha256 != install_receipt.root_identity_sha256
        || state.manifest.version != install_receipt.version
        || state.manifest.platform != install_receipt.platform
        || install_receipt.managed_files
            != state
                .managed_files
                .iter()
                .map(|file| file.destination.clone())
                .collect::<Vec<_>>()
    {
        return Err(InstallErrorV1::IntegrityMismatch);
    }
    verify_state_v1(&target_file, &state, &target_identity, isolated_root)?;
    let mut changes = Vec::new();
    let result = (|| {
        for managed in &state.managed_files {
            let observed = read_relative_v1(&target_file, Path::new(&managed.destination))?;
            if !matches_managed_file_v1(&observed, managed) {
                return Err(InstallErrorV1::CasConflict);
            }
            changes.push(stage_remove_v1(
                &target_file,
                Path::new(&managed.destination),
                &observed,
            )?);
        }
        if directory_identity_v1(&target_file, OsStr::new(INSTALL_STATE_DIR_V1))?
            != Some(state_directory.clone())
        {
            return Err(InstallErrorV1::CasConflict);
        }
        changes.push(stage_remove_v1(
            &target_file,
            Path::new(INSTALL_STATE_FILE_V1),
            &state_before,
        )?);
        if read_relative_v1(&target_file, Path::new(INSTALL_STATE_FILE_V1))?
            .identity
            .is_some()
        {
            return Err(InstallErrorV1::Io);
        }
        for managed in &state.managed_files {
            if read_relative_v1(&target_file, Path::new(&managed.destination))?
                .identity
                .is_some()
            {
                return Err(InstallErrorV1::Io);
            }
        }
        commit_changes_v1(&mut changes, None)?;
        remove_empty_private_state_directory_v1(&target_file, &state_directory)?;
        Ok(InstallReceiptV1 {
            schema_version: INSTALL_RECEIPT_SCHEMA_V1.to_owned(),
            action: InstallActionV1::Uninstall,
            version: state.manifest.version,
            platform: state.manifest.platform,
            manifest_sha256: state.manifest_sha256,
            previous_manifest_sha256: None,
            root_identity_sha256: root_identity_sha256_v1(&target_identity),
            capability_id: isolated_root.capability_id.clone(),
            capability_digest: isolated_root.capability_digest.clone(),
            managed_files: state
                .managed_files
                .iter()
                .map(|file| file.destination.clone())
                .collect(),
            managed_file_write_count: 0,
            managed_file_remove_count: state.managed_files.len() as u64,
            metadata_write_count: 0,
            dry_run: false,
            readback_verified: true,
        })
    })();
    if result.is_err() && !rollback_changes_v1(&mut changes) {
        return Err(InstallErrorV1::CasConflict);
    }
    result
}

fn preview_change_v1(
    action: InstallActionV1,
    package_root: &Path,
    isolated_root: &IsolatedInstallRootV1,
    manifest: &InstallManifestV1,
    rollback_receipt: Option<&InstallReceiptV1>,
) -> Result<InstallPreviewV1, InstallErrorV1> {
    let validated = validate_manifest_v1(manifest)?;
    let (_, package_file, package_identity) = open_root_v1(package_root)?;
    let (target_root, target_file, target_identity) = open_isolated_root_v1(isolated_root)?;
    if package_identity.same_object(&target_identity) {
        return Err(InstallErrorV1::PathEscape);
    }
    let payloads = read_payloads_v1(&package_file, &validated)?;
    let state_directory_before =
        directory_identity_v1(&target_file, OsStr::new(INSTALL_STATE_DIR_V1))?;
    if matches!(action, InstallActionV1::Upgrade | InstallActionV1::Rollback) {
        require_private_state_directory_v1(&target_file)?;
    }
    let (state, state_before) = read_state_v1(&target_file)?;

    let (previous_manifest_sha256, previous_managed) = match action {
        InstallActionV1::Install => {
            if state.is_some() || state_directory_before.is_some() {
                return Err(InstallErrorV1::NoClobber);
            }
            (None, Vec::new())
        }
        InstallActionV1::Upgrade | InstallActionV1::Rollback => {
            let state = state.ok_or(InstallErrorV1::IntegrityMismatch)?;
            verify_state_v1(&target_file, &state, &target_identity, isolated_root)?;
            if action == InstallActionV1::Rollback {
                let receipt = rollback_receipt.ok_or(InstallErrorV1::RollbackForbidden)?;
                if receipt.manifest_sha256 != state.manifest_sha256
                    || receipt.root_identity_sha256 != state.root_identity_sha256
                    || receipt.previous_manifest_sha256.as_deref()
                        != Some(&validated.manifest_sha256)
                    || state.previous_manifest_sha256.as_deref() != Some(&validated.manifest_sha256)
                {
                    return Err(InstallErrorV1::RollbackForbidden);
                }
            }
            (Some(state.manifest_sha256.clone()), state.managed_files)
        }
        InstallActionV1::Uninstall => return Err(InstallErrorV1::InvalidManifest),
    };

    let old_by_destination = previous_managed
        .iter()
        .map(|file| (file.destination.as_str(), file))
        .collect::<BTreeMap<_, _>>();
    let mut files = Vec::with_capacity(payloads.len());
    for payload in payloads {
        let observed = read_relative_v1(&target_file, Path::new(&payload.destination))?;
        if let Some(old) = old_by_destination.get(payload.destination.as_str()) {
            if !matches_managed_file_v1(&observed, old) {
                return Err(InstallErrorV1::CasConflict);
            }
        } else if observed.identity.is_some() {
            return Err(InstallErrorV1::NoClobber);
        }
        files.push(PlannedFileV1 {
            payload,
            before: observed,
        });
    }

    let new_destinations = files
        .iter()
        .map(|file| file.payload.destination.as_str())
        .collect::<BTreeSet<_>>();
    let mut removals = Vec::new();
    for old in previous_managed {
        if !new_destinations.contains(old.destination.as_str()) {
            let observed = read_relative_v1(&target_file, Path::new(&old.destination))?;
            if !matches_managed_file_v1(&observed, &old) {
                return Err(InstallErrorV1::CasConflict);
            }
            removals.push(PlannedRemovalV1 {
                destination: old.destination,
                before: observed,
            });
        }
    }

    let state_after_previous_manifest_sha256 = previous_manifest_sha256.clone();
    let state_after = InstallStateV1 {
        schema_version: INSTALL_STATE_SCHEMA_V1.to_owned(),
        manifest: manifest.clone(),
        manifest_sha256: validated.manifest_sha256.clone(),
        previous_manifest_sha256: state_after_previous_manifest_sha256.clone(),
        root_identity_sha256: root_identity_sha256_v1(&target_identity),
        capability_id: isolated_root.capability_id.clone(),
        capability_digest: isolated_root.capability_digest.clone(),
        managed_files: files
            .iter()
            .map(|file| ManagedFileV1 {
                destination: file.payload.destination.clone(),
                sha256: file.payload.sha256.clone(),
                mode: file.payload.mode,
            })
            .collect(),
    };
    let state_after = serde_json::to_vec(&state_after).map_err(|_| InstallErrorV1::Io)?;
    Ok(InstallPreviewV1 {
        action,
        manifest: manifest.clone(),
        manifest_sha256: validated.manifest_sha256,
        previous_manifest_sha256: state_after_previous_manifest_sha256,
        target_root,
        target_identity,
        capability_id: isolated_root.capability_id.clone(),
        capability_digest: isolated_root.capability_digest.clone(),
        state_directory_before,
        state_before,
        files,
        removals,
        state_after,
    })
}

fn receipt_from_preview_v1(
    preview: &InstallPreviewV1,
    target_identity: &FsIdentityV1,
) -> InstallReceiptV1 {
    InstallReceiptV1 {
        schema_version: INSTALL_RECEIPT_SCHEMA_V1.to_owned(),
        action: preview.action,
        version: preview.manifest.version.clone(),
        platform: preview.manifest.platform.clone(),
        manifest_sha256: preview.manifest_sha256.clone(),
        previous_manifest_sha256: preview.previous_manifest_sha256.clone(),
        root_identity_sha256: root_identity_sha256_v1(target_identity),
        capability_id: preview.capability_id.clone(),
        capability_digest: preview.capability_digest.clone(),
        managed_files: preview
            .files
            .iter()
            .map(|file| file.payload.destination.clone())
            .collect(),
        managed_file_write_count: preview.files.len() as u64,
        managed_file_remove_count: preview.removals.len() as u64,
        metadata_write_count: 1,
        dry_run: false,
        readback_verified: true,
    }
}

fn validate_manifest_v1(
    manifest: &InstallManifestV1,
) -> Result<ValidatedManifestV1, InstallErrorV1> {
    if manifest.schema_version != INSTALL_MANIFEST_SCHEMA_V1
        || !valid_label_v1(&manifest.version, 128)
        || !valid_label_v1(&manifest.platform, 128)
        || manifest.files.is_empty()
    {
        return Err(InstallErrorV1::InvalidManifest);
    }
    let files = manifest.files.iter().collect::<BTreeSet<_>>();
    if files.len() != manifest.files.len() {
        return Err(InstallErrorV1::InvalidManifest);
    }
    let mode_keys = manifest.modes.keys().collect::<BTreeSet<_>>();
    let digest_keys = manifest.digests.keys().collect::<BTreeSet<_>>();
    let destination_keys = manifest.destinations.keys().collect::<BTreeSet<_>>();
    if files != mode_keys || files != digest_keys || files != destination_keys {
        return Err(InstallErrorV1::InvalidManifest);
    }
    let mut destinations = BTreeSet::new();
    let mut validated = Vec::with_capacity(manifest.files.len());
    for source in &manifest.files {
        let source_path = safe_relative_path_v1(source)?;
        let destination = manifest
            .destinations
            .get(source)
            .ok_or(InstallErrorV1::InvalidManifest)?;
        let destination_path = safe_relative_path_v1(destination)?;
        if destination == INSTALL_STATE_FILE_V1
            || destination == INSTALL_STATE_DIR_V1
            || destination.starts_with(&format!("{INSTALL_STATE_DIR_V1}/"))
            || !destinations.insert(destination.clone())
        {
            return Err(InstallErrorV1::InvalidManifest);
        }
        let mode = *manifest
            .modes
            .get(source)
            .ok_or(InstallErrorV1::InvalidManifest)?;
        if !valid_file_mode_v1(mode) {
            return Err(InstallErrorV1::InvalidManifest);
        }
        let digest = manifest
            .digests
            .get(source)
            .ok_or(InstallErrorV1::InvalidManifest)?;
        if !is_canonical_sha256_v1(digest) {
            return Err(InstallErrorV1::InvalidManifest);
        }
        let source = source_path
            .to_str()
            .ok_or(InstallErrorV1::InvalidManifest)?
            .to_owned();
        let destination = destination_path
            .to_str()
            .ok_or(InstallErrorV1::InvalidManifest)?
            .to_owned();
        validated.push(ValidatedFileV1 {
            source,
            destination,
            sha256: digest.clone(),
            mode,
        });
    }
    validated.sort_by(|left, right| left.destination.cmp(&right.destination));
    Ok(ValidatedManifestV1 {
        manifest_sha256: manifest_sha256_v1(manifest)?,
        files: validated,
    })
}

fn manifest_sha256_v1(manifest: &InstallManifestV1) -> Result<String, InstallErrorV1> {
    serde_json::to_vec(manifest)
        .map(|bytes| sha256_v1(&bytes))
        .map_err(|_| InstallErrorV1::InvalidManifest)
}

fn valid_label_v1(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn valid_file_mode_v1(mode: u32) -> bool {
    (mode & !0o777) == 0 && (mode & 0o600) == 0o600 && (mode & 0o022) == 0
}

fn is_canonical_sha256_v1(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn safe_relative_path_v1(value: &str) -> Result<PathBuf, InstallErrorV1> {
    if value.is_empty() || value.contains('\\') || value.contains('\0') {
        return Err(InstallErrorV1::InvalidManifest);
    }
    let path = Path::new(value);
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(InstallErrorV1::InvalidManifest);
    }
    Ok(path.to_path_buf())
}

fn read_payloads_v1(
    package_root: &File,
    manifest: &ValidatedManifestV1,
) -> Result<Vec<PayloadFileV1>, InstallErrorV1> {
    let mut payloads = Vec::with_capacity(manifest.files.len());
    let mut total_bytes = 0_u64;
    for file in &manifest.files {
        let observed = read_relative_v1(package_root, Path::new(&file.source))?;
        if observed.identity.is_none() {
            return Err(InstallErrorV1::IntegrityMismatch);
        }
        if sha256_v1(&observed.bytes) != file.sha256 {
            return Err(InstallErrorV1::IntegrityMismatch);
        }
        total_bytes = total_bytes
            .checked_add(observed.bytes.len() as u64)
            .ok_or(InstallErrorV1::IntegrityMismatch)?;
        if total_bytes > MAX_INSTALL_TOTAL_BYTES_V1 {
            return Err(InstallErrorV1::IntegrityMismatch);
        }
        payloads.push(PayloadFileV1 {
            destination: file.destination.clone(),
            sha256: file.sha256.clone(),
            mode: file.mode,
            bytes: observed.bytes,
        });
    }
    Ok(payloads)
}

fn read_state_v1(root: &File) -> Result<(Option<InstallStateV1>, ObservedFileV1), InstallErrorV1> {
    let observed = read_relative_v1(root, Path::new(INSTALL_STATE_FILE_V1))?;
    if observed.identity.is_none() {
        return Ok((None, observed));
    }
    if observed
        .identity
        .as_ref()
        .is_none_or(|identity| identity.mode != 0o600)
    {
        return Err(InstallErrorV1::IntegrityMismatch);
    }
    let state = serde_json::from_slice::<InstallStateV1>(&observed.bytes)
        .map_err(|_| InstallErrorV1::IntegrityMismatch)?;
    if state.schema_version != INSTALL_STATE_SCHEMA_V1
        || !valid_label_v1(&state.capability_id, 64)
        || !is_canonical_sha256_v1(&state.capability_digest)
    {
        return Err(InstallErrorV1::IntegrityMismatch);
    }
    validate_manifest_v1(&state.manifest)?;
    if state.manifest_sha256 != manifest_sha256_v1(&state.manifest)?
        || state.managed_files.is_empty()
        || state.managed_files.len() != state.manifest.files.len()
    {
        return Err(InstallErrorV1::IntegrityMismatch);
    }
    Ok((Some(state), observed))
}

fn verify_state_v1(
    root: &File,
    state: &InstallStateV1,
    root_identity: &FsIdentityV1,
    isolated_root: &IsolatedInstallRootV1,
) -> Result<(), InstallErrorV1> {
    if state.root_identity_sha256 != root_identity_sha256_v1(root_identity) {
        return Err(InstallErrorV1::CasConflict);
    }
    if state.capability_id != isolated_root.capability_id
        || state.capability_digest != isolated_root.capability_digest
    {
        return Err(InstallErrorV1::CapabilityMismatch);
    }
    let validated = validate_manifest_v1(&state.manifest)?;
    if state.manifest_sha256 != validated.manifest_sha256 {
        return Err(InstallErrorV1::IntegrityMismatch);
    }
    let expected = validated
        .files
        .iter()
        .map(|file| (&file.destination, (&file.sha256, file.mode)))
        .collect::<BTreeMap<_, _>>();
    let actual = state
        .managed_files
        .iter()
        .map(|file| (&file.destination, (&file.sha256, file.mode)))
        .collect::<BTreeMap<_, _>>();
    if expected != actual {
        return Err(InstallErrorV1::IntegrityMismatch);
    }
    for managed in &state.managed_files {
        let observed = read_relative_v1(root, Path::new(&managed.destination))?;
        if !matches_managed_file_v1(&observed, managed) {
            return Err(InstallErrorV1::CasConflict);
        }
    }
    Ok(())
}

fn matches_managed_file_v1(observed: &ObservedFileV1, managed: &ManagedFileV1) -> bool {
    observed.identity.as_ref().is_some_and(|identity| {
        sha256_v1(&observed.bytes) == managed.sha256 && identity.mode == managed.mode
    })
}

fn stage_write_v1(
    root: &File,
    relative: &Path,
    expected_before: &ObservedFileV1,
    after: &[u8],
    mode: u32,
) -> Result<AppliedChangeV1, InstallErrorV1> {
    let ParentV1::Ready { directory, name } = walk_parent_v1(
        root.try_clone().map_err(|_| InstallErrorV1::Io)?,
        relative,
        true,
    )?
    else {
        return Err(InstallErrorV1::Io);
    };
    let current = read_at_v1(&directory, &name)?;
    if !expected_before.matches(&current) {
        return Err(InstallErrorV1::CasConflict);
    }
    let (temporary_name, mut temporary) = create_temp_v1(&directory, mode, &sha256_v1(after))?;
    let temporary_observed = read_at_v1(&directory, &temporary_name)?;
    let cleanup_directory = directory.try_clone().map_err(|_| InstallErrorV1::Io)?;
    let cleanup_name = temporary_name.clone();
    let mut temporary_exists = true;
    let result = (|| {
        temporary.write_all(after).map_err(|_| InstallErrorV1::Io)?;
        temporary.sync_all().map_err(|_| InstallErrorV1::Io)?;
        drop(temporary);
        let prepared = read_at_v1(&directory, &temporary_name)?;
        if prepared.identity != temporary_observed.identity
            || sha256_v1(&prepared.bytes) != sha256_v1(after)
        {
            return Err(InstallErrorV1::Io);
        }
        let before_rename = read_at_v1(&directory, &name)?;
        if !expected_before.matches(&before_rename) {
            return Err(InstallErrorV1::CasConflict);
        }
        if expected_before.identity.is_some() {
            exchange_entries_v1(&directory, &temporary_name, &name)?;
            let installed = read_at_v1(&directory, &name)?;
            let displaced = read_at_v1(&directory, &temporary_name)?;
            if !installed.matches(&prepared) || !displaced.matches(expected_before) {
                let _ = rollback_exchange_v1(
                    &directory,
                    &temporary_name,
                    &name,
                    &prepared,
                    expected_before,
                );
                return Err(InstallErrorV1::CasConflict);
            }
            if directory.sync_all().is_err() {
                let restored = rollback_exchange_v1(
                    &directory,
                    &temporary_name,
                    &name,
                    &prepared,
                    expected_before,
                )?;
                if !restored {
                    return Err(InstallErrorV1::CasConflict);
                }
                return Err(InstallErrorV1::Io);
            }
            temporary_exists = false;
            Ok(AppliedChangeV1::Replaced {
                directory,
                target: name,
                backup: temporary_name,
                before: expected_before.clone(),
                new: prepared,
            })
        } else {
            rename_noreplace_v1(&directory, &temporary_name, &name)?;
            temporary_exists = false;
            let installed = read_at_v1(&directory, &name)?;
            if !installed.matches(&prepared) {
                let _ = unlink_if_matches_v1(&directory, &name, &prepared);
                return Err(InstallErrorV1::CasConflict);
            }
            if directory.sync_all().is_err() {
                let _ = unlink_if_matches_v1(&directory, &name, &prepared);
                return Err(InstallErrorV1::Io);
            }
            Ok(AppliedChangeV1::Created {
                directory,
                target: name,
                new: prepared,
            })
        }
    })();
    if temporary_exists {
        let _ = unlink_if_owned_v1(&cleanup_directory, &cleanup_name, &temporary_observed);
    }
    result
}

fn stage_remove_v1(
    root: &File,
    relative: &Path,
    expected_before: &ObservedFileV1,
) -> Result<AppliedChangeV1, InstallErrorV1> {
    if expected_before.identity.is_none() {
        return Err(InstallErrorV1::CasConflict);
    }
    let ParentV1::Ready { directory, name } = walk_parent_v1(
        root.try_clone().map_err(|_| InstallErrorV1::Io)?,
        relative,
        false,
    )?
    else {
        return Err(InstallErrorV1::CasConflict);
    };
    let current = read_at_v1(&directory, &name)?;
    if !expected_before.matches(&current) {
        return Err(InstallErrorV1::CasConflict);
    }
    let (temporary_name, temporary) = create_temp_v1(&directory, 0o600, "remove")?;
    let empty = read_at_v1(&directory, &temporary_name)?;
    drop(temporary);
    let cleanup_directory = directory.try_clone().map_err(|_| InstallErrorV1::Io)?;
    let cleanup_name = temporary_name.clone();
    let mut temporary_exists = true;
    let result = (|| {
        let before_exchange = read_at_v1(&directory, &name)?;
        if !expected_before.matches(&before_exchange) {
            return Err(InstallErrorV1::CasConflict);
        }
        exchange_entries_v1(&directory, &temporary_name, &name)?;
        let placeholder = read_at_v1(&directory, &name)?;
        let displaced = read_at_v1(&directory, &temporary_name)?;
        if !placeholder.matches(&empty) || !displaced.matches(expected_before) {
            let _ =
                rollback_exchange_v1(&directory, &temporary_name, &name, &empty, expected_before);
            return Err(InstallErrorV1::CasConflict);
        }
        rustix::fs::unlinkat(&directory, &name, rustix::fs::AtFlags::empty())
            .map_err(|_| InstallErrorV1::Io)?;
        if directory.sync_all().is_err() {
            let restored = restore_removed_v1(&directory, &temporary_name, &name, expected_before)?;
            if !restored {
                return Err(InstallErrorV1::CasConflict);
            }
            return Err(InstallErrorV1::Io);
        }
        temporary_exists = false;
        Ok(AppliedChangeV1::Removed {
            directory,
            target: name,
            backup: temporary_name,
            before: expected_before.clone(),
        })
    })();
    if temporary_exists {
        let _ = unlink_if_owned_v1(&cleanup_directory, &cleanup_name, &empty);
    }
    result
}

fn commit_changes_v1(
    changes: &mut Vec<AppliedChangeV1>,
    fail_after_backup_cleanup: Option<u64>,
) -> Result<(), InstallErrorV1> {
    let mut cleanup_count = 0_u64;
    for change in changes.iter() {
        match change {
            AppliedChangeV1::Created { .. } => {}
            AppliedChangeV1::Replaced {
                directory,
                backup,
                before,
                ..
            }
            | AppliedChangeV1::Removed {
                directory,
                backup,
                before,
                ..
            } => {
                let observed = read_at_v1(directory, backup)?;
                if !before.matches(&observed) {
                    return Err(InstallErrorV1::CasConflict);
                }
                rustix::fs::unlinkat(directory, backup, rustix::fs::AtFlags::empty())
                    .map_err(|_| InstallErrorV1::Io)?;
                directory.sync_all().map_err(|_| InstallErrorV1::Io)?;
                cleanup_count = cleanup_count.saturating_add(1);
                if fail_after_backup_cleanup == Some(cleanup_count) {
                    return Err(InstallErrorV1::TestFaultInjected);
                }
            }
        }
    }
    changes.clear();
    Ok(())
}

fn rollback_changes_v1(changes: &mut Vec<AppliedChangeV1>) -> bool {
    let mut restored = true;
    while let Some(change) = changes.pop() {
        let result = match change {
            AppliedChangeV1::Created {
                directory,
                target,
                new,
            } => unlink_if_matches_v1(&directory, &target, &new),
            AppliedChangeV1::Replaced {
                directory,
                target,
                backup,
                before,
                new,
            } => rollback_replaced_change_v1(&directory, &backup, &target, &before, &new),
            AppliedChangeV1::Removed {
                directory,
                target,
                backup,
                before,
            } => rollback_removed_change_v1(&directory, &backup, &target, &before),
        };
        restored &= result.unwrap_or(false);
    }
    restored
}

fn rollback_replaced_change_v1(
    directory: &File,
    backup: &OsStr,
    target: &OsStr,
    before: &ObservedFileV1,
    new: &ObservedFileV1,
) -> Result<bool, InstallErrorV1> {
    let backup_observed = read_at_v1(directory, backup)?;
    if backup_observed.matches(before) {
        if !read_at_v1(directory, target)?.matches(new) {
            return Ok(false);
        }
        exchange_entries_v1(directory, backup, target)?;
        let restored = read_at_v1(directory, target)?;
        let displaced = read_at_v1(directory, backup)?;
        if !restored.matches(before) || !displaced.matches(new) {
            return Ok(false);
        }
        unlink_if_matches_v1(directory, backup, new)?;
        return Ok(true);
    }
    if backup_observed.identity.is_none() {
        return restore_replaced_from_bytes_v1(directory, target, before, new);
    }
    Ok(false)
}

fn rollback_removed_change_v1(
    directory: &File,
    backup: &OsStr,
    target: &OsStr,
    before: &ObservedFileV1,
) -> Result<bool, InstallErrorV1> {
    let backup_observed = read_at_v1(directory, backup)?;
    if backup_observed.matches(before) {
        return restore_removed_v1(directory, backup, target, before);
    }
    if backup_observed.identity.is_none() {
        return restore_removed_from_bytes_v1(directory, target, before);
    }
    Ok(false)
}

fn restore_replaced_from_bytes_v1(
    directory: &File,
    target: &OsStr,
    before: &ObservedFileV1,
    new: &ObservedFileV1,
) -> Result<bool, InstallErrorV1> {
    if !read_at_v1(directory, target)?.matches(new) {
        return Ok(false);
    }
    let mode = before
        .identity
        .as_ref()
        .map(|identity| identity.mode)
        .ok_or(InstallErrorV1::CasConflict)?;
    let (temporary, prepared) = create_written_temp_v1(directory, &before.bytes, mode, "rollback")?;
    let result = (|| {
        exchange_entries_v1(directory, &temporary, target)?;
        let restored = read_at_v1(directory, target)?;
        let displaced = read_at_v1(directory, &temporary)?;
        if !matches_bytes_and_mode_v1(&restored, before) || !displaced.matches(new) {
            return Ok(false);
        }
        unlink_if_matches_v1(directory, &temporary, new)?;
        Ok(true)
    })();
    if result.is_err() {
        let _ = unlink_if_owned_v1(directory, &temporary, &prepared);
    }
    result
}

fn restore_removed_from_bytes_v1(
    directory: &File,
    target: &OsStr,
    before: &ObservedFileV1,
) -> Result<bool, InstallErrorV1> {
    if read_at_v1(directory, target)?.identity.is_some() {
        return Ok(false);
    }
    let mode = before
        .identity
        .as_ref()
        .map(|identity| identity.mode)
        .ok_or(InstallErrorV1::CasConflict)?;
    let (temporary, prepared) = create_written_temp_v1(directory, &before.bytes, mode, "restore")?;
    let result = (|| {
        rename_noreplace_v1(directory, &temporary, target)?;
        let restored = read_at_v1(directory, target)?;
        if !matches_bytes_and_mode_v1(&restored, before) {
            return Ok(false);
        }
        Ok(true)
    })();
    if result.is_err() {
        let _ = unlink_if_owned_v1(directory, &temporary, &prepared);
    }
    result
}

fn create_written_temp_v1(
    directory: &File,
    bytes: &[u8],
    mode: u32,
    label: &str,
) -> Result<(OsString, ObservedFileV1), InstallErrorV1> {
    let (name, mut file) = create_temp_v1(directory, mode, label)?;
    let initial = read_at_v1(directory, &name)?;
    let result = (|| {
        file.write_all(bytes).map_err(|_| InstallErrorV1::Io)?;
        file.sync_all().map_err(|_| InstallErrorV1::Io)?;
        drop(file);
        let prepared = read_at_v1(directory, &name)?;
        if prepared.identity != initial.identity || prepared.bytes != bytes {
            return Err(InstallErrorV1::Io);
        }
        Ok(prepared)
    })();
    match result {
        Ok(prepared) => Ok((name, prepared)),
        Err(error) => {
            let _ = unlink_if_owned_v1(directory, &name, &initial);
            Err(error)
        }
    }
}

fn matches_bytes_and_mode_v1(observed: &ObservedFileV1, expected: &ObservedFileV1) -> bool {
    observed.bytes == expected.bytes
        && observed.identity.as_ref().is_some_and(|identity| {
            expected
                .identity
                .as_ref()
                .is_some_and(|expected_identity| identity.mode == expected_identity.mode)
        })
}

fn rollback_exchange_v1(
    directory: &File,
    backup: &OsStr,
    target: &OsStr,
    expected_target: &ObservedFileV1,
    expected_backup: &ObservedFileV1,
) -> Result<bool, InstallErrorV1> {
    let target_observed = read_at_v1(directory, target)?;
    let backup_observed = read_at_v1(directory, backup)?;
    if !target_observed.matches(expected_target) || !backup_observed.matches(expected_backup) {
        return Ok(false);
    }
    exchange_entries_v1(directory, backup, target)?;
    directory.sync_all().map_err(|_| InstallErrorV1::Io)?;
    Ok(true)
}

fn restore_removed_v1(
    directory: &File,
    backup: &OsStr,
    target: &OsStr,
    expected_backup: &ObservedFileV1,
) -> Result<bool, InstallErrorV1> {
    if read_at_v1(directory, target)?.identity.is_some()
        || !read_at_v1(directory, backup)?.matches(expected_backup)
    {
        return Ok(false);
    }
    rename_noreplace_v1(directory, backup, target)?;
    directory.sync_all().map_err(|_| InstallErrorV1::Io)?;
    Ok(true)
}

fn unlink_if_matches_v1(
    directory: &File,
    name: &OsStr,
    expected: &ObservedFileV1,
) -> Result<bool, InstallErrorV1> {
    if !read_at_v1(directory, name)?.matches(expected) {
        return Ok(false);
    }
    rustix::fs::unlinkat(directory, name, rustix::fs::AtFlags::empty())
        .map_err(|_| InstallErrorV1::Io)?;
    directory.sync_all().map_err(|_| InstallErrorV1::Io)?;
    Ok(true)
}

fn unlink_if_owned_v1(
    directory: &File,
    name: &OsStr,
    expected: &ObservedFileV1,
) -> Result<bool, InstallErrorV1> {
    let observed = read_at_v1(directory, name)?;
    if observed.identity != expected.identity {
        return Ok(false);
    }
    rustix::fs::unlinkat(directory, name, rustix::fs::AtFlags::empty())
        .map_err(|_| InstallErrorV1::Io)?;
    directory.sync_all().map_err(|_| InstallErrorV1::Io)?;
    Ok(true)
}

#[cfg(unix)]
fn open_root_v1(root: &Path) -> Result<(PathBuf, File, FsIdentityV1), InstallErrorV1> {
    use std::fs;
    use std::os::unix::fs::MetadataExt;

    let descriptor = rustix::fs::open(
        root,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|_| InstallErrorV1::PathEscape)?;
    let file = File::from(descriptor);
    let metadata = file.metadata().map_err(|_| InstallErrorV1::Io)?;
    if !metadata.is_dir() {
        return Err(InstallErrorV1::PathEscape);
    }
    let canonical = fs::canonicalize(root).map_err(|_| InstallErrorV1::Io)?;
    Ok((
        canonical,
        file,
        FsIdentityV1 {
            device: metadata.dev(),
            inode: metadata.ino(),
            owner: metadata.uid(),
            mode: metadata.mode() & 0o777,
        },
    ))
}

#[cfg(unix)]
fn validate_authorized_temp_parent_v1(
    parent: &Path,
    identity: &FsIdentityV1,
) -> Result<(), InstallErrorV1> {
    let system_temp = canonical_system_temp_area_v1()?;
    if parent == Path::new("/")
        || parent == system_temp
        || !parent.starts_with(&system_temp)
        || (identity.mode & 0o022) != 0
        || identity.owner != rustix::process::getuid().as_raw()
        || !parent_acl_unambiguous_v1(parent)?
    {
        return Err(InstallErrorV1::IsolationRequired);
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn parent_acl_unambiguous_v1(parent: &Path) -> Result<bool, InstallErrorV1> {
    let output = std::process::Command::new("/bin/ls")
        .arg("-lde")
        .arg(parent)
        .output()
        .map_err(|_| InstallErrorV1::IsolationRequired)?;
    if !output.status.success() {
        return Err(InstallErrorV1::IsolationRequired);
    }
    let stdout = String::from_utf8(output.stdout).map_err(|_| InstallErrorV1::IsolationRequired)?;
    let mode = stdout
        .lines()
        .next()
        .and_then(|line| line.split_ascii_whitespace().next())
        .ok_or(InstallErrorV1::IsolationRequired)?;
    Ok(!mode.ends_with('+'))
}

#[cfg(not(target_os = "macos"))]
fn parent_acl_unambiguous_v1(_parent: &Path) -> Result<bool, InstallErrorV1> {
    Ok(true)
}

#[cfg(unix)]
fn canonical_system_temp_area_v1() -> Result<PathBuf, InstallErrorV1> {
    let fixed = if cfg!(target_os = "macos") {
        Path::new("/private/tmp")
    } else {
        Path::new("/tmp")
    };
    let canonical = std::fs::canonicalize(fixed).map_err(|_| InstallErrorV1::IsolationRequired)?;
    if canonical != fixed || canonical == Path::new("/") {
        return Err(InstallErrorV1::IsolationRequired);
    }
    Ok(canonical)
}

#[cfg(unix)]
fn parent_path_still_bound_v1(parent: &Path, expected: &FsIdentityV1) -> bool {
    match open_root_v1(parent) {
        Ok((observed_path, _, observed)) => observed_path == parent && observed == *expected,
        Err(_) => false,
    }
}

#[cfg(unix)]
fn remove_created_child_v1(
    parent: &File,
    name: &OsStr,
    expected: &FsIdentityV1,
) -> Result<bool, InstallErrorV1> {
    use std::os::unix::fs::MetadataExt;

    let descriptor = rustix::fs::openat(
        parent,
        name,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|_| InstallErrorV1::CapabilityMismatch)?;
    let child = File::from(descriptor);
    let metadata = child.metadata().map_err(|_| InstallErrorV1::Io)?;
    let observed = FsIdentityV1 {
        device: metadata.dev(),
        inode: metadata.ino(),
        owner: metadata.uid(),
        mode: metadata.mode() & 0o777,
    };
    drop(child);
    if observed != *expected {
        return Ok(false);
    }
    rustix::fs::unlinkat(parent, name, rustix::fs::AtFlags::REMOVEDIR)
        .map_err(|_| InstallErrorV1::Io)?;
    parent.sync_all().map_err(|_| InstallErrorV1::Io)?;
    Ok(true)
}

fn open_isolated_root_v1(
    isolated_root: &IsolatedInstallRootV1,
) -> Result<(PathBuf, File, FsIdentityV1), InstallErrorV1> {
    #[cfg(unix)]
    use std::os::unix::fs::MetadataExt;

    let (parent_root, parent_file, parent_identity) =
        open_root_v1(&isolated_root.parent_root).map_err(|_| InstallErrorV1::CapabilityMismatch)?;
    if parent_root != isolated_root.parent_root
        || parent_identity != isolated_root.parent_identity
        || validate_authorized_temp_parent_v1(&parent_root, &parent_identity).is_err()
    {
        return Err(InstallErrorV1::CapabilityMismatch);
    }
    #[cfg(unix)]
    let descriptor = rustix::fs::openat(
        &parent_file,
        &isolated_root.child_name,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|_| InstallErrorV1::CapabilityMismatch)?;
    #[cfg(unix)]
    let file = File::from(descriptor);
    #[cfg(unix)]
    let metadata = file.metadata().map_err(|_| InstallErrorV1::Io)?;
    #[cfg(unix)]
    let identity = FsIdentityV1 {
        device: metadata.dev(),
        inode: metadata.ino(),
        owner: metadata.uid(),
        mode: metadata.mode() & 0o777,
    };
    #[cfg(not(unix))]
    let (file, identity) = return Err(InstallErrorV1::UnsupportedPlatform);
    let root = parent_root.join(&isolated_root.child_name);
    if root != isolated_root.root
        || identity != isolated_root.identity
        || identity.mode != 0o700
        || !parent_path_still_bound_v1(&parent_root, &parent_identity)
        || !valid_label_v1(&isolated_root.capability_id, 64)
        || !is_canonical_sha256_v1(&isolated_root.capability_digest)
    {
        return Err(InstallErrorV1::CapabilityMismatch);
    }
    Ok((root, file, identity))
}

fn require_private_state_directory_v1(root: &File) -> Result<FsIdentityV1, InstallErrorV1> {
    let identity = directory_identity_v1(root, OsStr::new(INSTALL_STATE_DIR_V1))?
        .ok_or(InstallErrorV1::IntegrityMismatch)?;
    if identity.mode != 0o700 {
        return Err(InstallErrorV1::IntegrityMismatch);
    }
    Ok(identity)
}

#[cfg(unix)]
fn remove_empty_private_state_directory_v1(
    root: &File,
    expected: &FsIdentityV1,
) -> Result<(), InstallErrorV1> {
    let observed = require_private_state_directory_v1(root)?;
    if observed != *expected {
        return Err(InstallErrorV1::CasConflict);
    }
    rustix::fs::unlinkat(
        root,
        OsStr::new(INSTALL_STATE_DIR_V1),
        rustix::fs::AtFlags::REMOVEDIR,
    )
    .map_err(|error| {
        if matches!(
            error,
            rustix::io::Errno::NOTEMPTY | rustix::io::Errno::EXIST
        ) {
            InstallErrorV1::CasConflict
        } else {
            InstallErrorV1::Io
        }
    })?;
    root.sync_all().map_err(|_| InstallErrorV1::Io)?;
    if directory_identity_v1(root, OsStr::new(INSTALL_STATE_DIR_V1))?.is_some() {
        return Err(InstallErrorV1::Io);
    }
    Ok(())
}

#[cfg(not(unix))]
fn remove_empty_private_state_directory_v1(
    _root: &File,
    _expected: &FsIdentityV1,
) -> Result<(), InstallErrorV1> {
    Err(InstallErrorV1::UnsupportedPlatform)
}

#[cfg(not(unix))]
fn open_root_v1(_root: &Path) -> Result<(PathBuf, File, FsIdentityV1), InstallErrorV1> {
    Err(InstallErrorV1::UnsupportedPlatform)
}

#[cfg(unix)]
fn directory_identity_v1(
    root: &File,
    name: &OsStr,
) -> Result<Option<FsIdentityV1>, InstallErrorV1> {
    use std::os::unix::fs::MetadataExt;

    let descriptor = match rustix::fs::openat(
        root,
        name,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    ) {
        Ok(value) => value,
        Err(error) if error == rustix::io::Errno::NOENT => return Ok(None),
        Err(error) => return Err(map_dirfd_error_v1(error)),
    };
    let file = File::from(descriptor);
    let metadata = file.metadata().map_err(|_| InstallErrorV1::Io)?;
    if !metadata.is_dir() {
        return Err(InstallErrorV1::PathEscape);
    }
    Ok(Some(FsIdentityV1 {
        device: metadata.dev(),
        inode: metadata.ino(),
        owner: metadata.uid(),
        mode: metadata.mode() & 0o777,
    }))
}

#[cfg(not(unix))]
fn directory_identity_v1(
    _root: &File,
    _name: &OsStr,
) -> Result<Option<FsIdentityV1>, InstallErrorV1> {
    Err(InstallErrorV1::UnsupportedPlatform)
}

#[cfg(unix)]
fn walk_parent_v1(
    mut directory: File,
    relative: &Path,
    create: bool,
) -> Result<ParentV1, InstallErrorV1> {
    let components = relative
        .components()
        .map(|component| match component {
            Component::Normal(value) => Ok(value.to_os_string()),
            _ => Err(InstallErrorV1::PathEscape),
        })
        .collect::<Result<Vec<_>, _>>()?;
    let Some((name, parents)) = components.split_last() else {
        return Err(InstallErrorV1::PathEscape);
    };
    let flags = rustix::fs::OFlags::RDONLY
        | rustix::fs::OFlags::DIRECTORY
        | rustix::fs::OFlags::NOFOLLOW
        | rustix::fs::OFlags::CLOEXEC;
    for component in parents {
        let opened =
            match rustix::fs::openat(&directory, component, flags, rustix::fs::Mode::empty()) {
                Ok(value) => value,
                Err(error) if error == rustix::io::Errno::NOENT && !create => {
                    return Ok(ParentV1::Missing);
                }
                Err(error) if error == rustix::io::Errno::NOENT && create => {
                    match rustix::fs::mkdirat(
                        &directory,
                        component,
                        rustix::fs::Mode::from_raw_mode(0o700),
                    ) {
                        Ok(()) => {}
                        Err(race) if race == rustix::io::Errno::EXIST => {}
                        Err(_) => return Err(InstallErrorV1::Io),
                    }
                    directory.sync_all().map_err(|_| InstallErrorV1::Io)?;
                    rustix::fs::openat(&directory, component, flags, rustix::fs::Mode::empty())
                        .map_err(map_dirfd_error_v1)?
                }
                Err(error) => return Err(map_dirfd_error_v1(error)),
            };
        directory = File::from(opened);
    }
    Ok(ParentV1::Ready {
        directory,
        name: name.clone(),
    })
}

#[cfg(not(unix))]
fn walk_parent_v1(
    _directory: File,
    _relative: &Path,
    _create: bool,
) -> Result<ParentV1, InstallErrorV1> {
    Err(InstallErrorV1::UnsupportedPlatform)
}

fn read_relative_v1(root: &File, relative: &Path) -> Result<ObservedFileV1, InstallErrorV1> {
    match walk_parent_v1(
        root.try_clone().map_err(|_| InstallErrorV1::Io)?,
        relative,
        false,
    )? {
        ParentV1::Missing => Ok(ObservedFileV1::absent()),
        ParentV1::Ready {
            directory, name, ..
        } => read_at_v1(&directory, &name),
    }
}

#[cfg(unix)]
fn read_at_v1(directory: &File, name: &OsStr) -> Result<ObservedFileV1, InstallErrorV1> {
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
        Ok(value) => value,
        Err(error) if error == rustix::io::Errno::NOENT => return Ok(ObservedFileV1::absent()),
        Err(error) => return Err(map_dirfd_error_v1(error)),
    };
    let mut file = File::from(descriptor);
    let metadata = file.metadata().map_err(|_| InstallErrorV1::Io)?;
    if !metadata.is_file() || metadata.nlink() != 1 {
        return Err(InstallErrorV1::UnsafeTarget);
    }
    if metadata.len() > MAX_INSTALL_FILE_BYTES_V1 {
        return Err(InstallErrorV1::IntegrityMismatch);
    }
    let capacity = usize::try_from(metadata.len()).map_err(|_| InstallErrorV1::Io)?;
    let mut bytes = Vec::with_capacity(capacity);
    Read::by_ref(&mut file)
        .take(MAX_INSTALL_FILE_BYTES_V1 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| InstallErrorV1::Io)?;
    if bytes.len() as u64 > MAX_INSTALL_FILE_BYTES_V1 {
        return Err(InstallErrorV1::IntegrityMismatch);
    }
    let after = file.metadata().map_err(|_| InstallErrorV1::Io)?;
    if metadata.dev() != after.dev()
        || metadata.ino() != after.ino()
        || metadata.len() != after.len()
        || metadata.nlink() != after.nlink()
    {
        return Err(InstallErrorV1::CasConflict);
    }
    Ok(ObservedFileV1 {
        bytes,
        identity: Some(FsIdentityV1 {
            device: metadata.dev(),
            inode: metadata.ino(),
            owner: metadata.uid(),
            mode: metadata.mode() & 0o777,
        }),
    })
}

#[cfg(not(unix))]
fn read_at_v1(_directory: &File, _name: &OsStr) -> Result<ObservedFileV1, InstallErrorV1> {
    Err(InstallErrorV1::UnsupportedPlatform)
}

#[cfg(unix)]
fn create_temp_v1(
    directory: &File,
    mode: u32,
    label: &str,
) -> Result<(OsString, File), InstallErrorV1> {
    let raw_mode = u16::try_from(mode & 0o777).map_err(|_| InstallErrorV1::Io)?;
    for _ in 0..INSTALL_TEMP_ATTEMPTS_V1 {
        let sequence = INSTALL_TEMP_SEQUENCE_V1.fetch_add(1, Ordering::Relaxed);
        let label = label.get(..16).unwrap_or(label);
        let name = OsString::from(format!(
            ".gtkg-install-{}-{sequence}-{label}.tmp",
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
                    return Err(InstallErrorV1::Io);
                }
                return Ok((name, file));
            }
            Err(error) if error == rustix::io::Errno::EXIST => continue,
            Err(error) => return Err(map_dirfd_error_v1(error)),
        }
    }
    Err(InstallErrorV1::Io)
}

#[cfg(not(unix))]
fn create_temp_v1(
    _directory: &File,
    _mode: u32,
    _label: &str,
) -> Result<(OsString, File), InstallErrorV1> {
    Err(InstallErrorV1::UnsupportedPlatform)
}

#[cfg(any(target_os = "macos", target_os = "ios", target_os = "linux"))]
fn exchange_entries_v1(
    directory: &File,
    left: &OsStr,
    right: &OsStr,
) -> Result<(), InstallErrorV1> {
    rustix::fs::renameat_with(
        directory,
        left,
        directory,
        right,
        rustix::fs::RenameFlags::EXCHANGE,
    )
    .map_err(|error| {
        if error == rustix::io::Errno::NOENT {
            InstallErrorV1::CasConflict
        } else {
            InstallErrorV1::Io
        }
    })
}

#[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "linux")))]
fn exchange_entries_v1(
    _directory: &File,
    _left: &OsStr,
    _right: &OsStr,
) -> Result<(), InstallErrorV1> {
    Err(InstallErrorV1::UnsupportedPlatform)
}

#[cfg(any(target_os = "macos", target_os = "ios", target_os = "linux"))]
fn rename_noreplace_v1(
    directory: &File,
    left: &OsStr,
    right: &OsStr,
) -> Result<(), InstallErrorV1> {
    rustix::fs::renameat_with(
        directory,
        left,
        directory,
        right,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .map_err(|error| {
        if error == rustix::io::Errno::EXIST {
            InstallErrorV1::CasConflict
        } else {
            InstallErrorV1::Io
        }
    })
}

#[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "linux")))]
fn rename_noreplace_v1(
    _directory: &File,
    _left: &OsStr,
    _right: &OsStr,
) -> Result<(), InstallErrorV1> {
    Err(InstallErrorV1::UnsupportedPlatform)
}

#[cfg(unix)]
fn map_dirfd_error_v1(error: rustix::io::Errno) -> InstallErrorV1 {
    if matches!(error, rustix::io::Errno::LOOP | rustix::io::Errno::NOTDIR) {
        InstallErrorV1::PathEscape
    } else {
        InstallErrorV1::Io
    }
}

fn root_identity_sha256_v1(identity: &FsIdentityV1) -> String {
    let bytes = serde_json::to_vec(&(
        "gtkg.install-root-identity/v2",
        identity.device,
        identity.inode,
        identity.owner,
    ))
    .expect("root identity tuple is serializable");
    sha256_v1(&bytes)
}

fn sha256_v1(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}
