//! Crash-replayable, no-clobber publication for immutable JSON receipts.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use gtkg_protocol::canonical_json_sha256;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{CallContext, ContextError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DurableErrorKind {
    Invalid,
    Unauthorized,
    Unsafe,
    Conflict,
    Io,
}

#[derive(Debug)]
pub(crate) struct DurableWriteError {
    pub kind: DurableErrorKind,
    pub path: PathBuf,
    pub message: String,
}

impl std::fmt::Display for DurableWriteError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.path.display(), self.message)
    }
}

pub(crate) fn publish_immutable_json<T>(
    context: &CallContext,
    path: &Path,
    value: &T,
    fault_point: &'static str,
) -> Result<PathBuf, DurableWriteError>
where
    T: Serialize,
{
    let expected_bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| invalid(path, format!("receipt serialization failed: {error}")))?;
    let expected_canonical = canonical_json_sha256(value)
        .map_err(|error| invalid(path, format!("receipt digest failed: {error}")))?;
    publish_immutable_bytes(
        context,
        path,
        &expected_bytes,
        &expected_canonical,
        fault_point,
        false,
    )
}

pub(crate) fn publish_private_immutable_json<T>(
    context: &CallContext,
    path: &Path,
    value: &T,
    fault_point: &'static str,
) -> Result<PathBuf, DurableWriteError>
where
    T: Serialize,
{
    let expected_bytes = serde_json::to_vec_pretty(value).map_err(|error| {
        invalid(
            path,
            format!("private receipt serialization failed: {error}"),
        )
    })?;
    let expected_canonical = canonical_json_sha256(value)
        .map_err(|error| invalid(path, format!("private receipt digest failed: {error}")))?;
    publish_immutable_bytes(
        context,
        path,
        &expected_bytes,
        &expected_canonical,
        fault_point,
        true,
    )
}

fn publish_immutable_bytes(
    context: &CallContext,
    requested_path: &Path,
    expected_bytes: &[u8],
    expected_canonical: &str,
    fault_point: &'static str,
    private: bool,
) -> Result<PathBuf, DurableWriteError> {
    #[cfg(not(unix))]
    if private {
        return Err(unsafe_path(
            requested_path,
            "private immutable receipts require Unix owner-only permissions",
        ));
    }
    let requested_parent = requested_path
        .parent()
        .ok_or_else(|| invalid(requested_path, "receipt path has no parent"))?;
    let file_name = requested_path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| invalid(requested_path, "receipt filename is not UTF-8"))?;
    let parent = authorize_write(context, requested_parent)?;
    fs::create_dir_all(&parent).map_err(|error| io(&parent, error))?;
    let parent = authorize_write(context, &parent)?;
    ensure_directory(&parent)?;
    let path = parent.join(file_name);
    let temporary = parent.join(format!(".{file_name}.receipt.tmp"));
    let path = authorize_candidate(context, &path)?;
    let temporary = authorize_candidate(context, &temporary)?;
    let _publish_guard = PublishGuard::acquire(context, &path)?;

    if let Some(observed) = read_regular_if_present(&path)? {
        if matches_expected(&observed, expected_bytes, expected_canonical) {
            if private && !is_owner_private_file(&path)? {
                return Err(conflict(
                    &path,
                    "matching private receipt is not owner-only",
                ));
            }
            clean_temporary(context, &temporary, expected_bytes, expected_canonical)?;
            sync_directory(&parent)?;
            return Ok(path);
        }
        if serde_json::from_slice::<serde_json::Value>(&observed).is_ok() {
            return Err(conflict(
                &path,
                "immutable receipt content conflicts with the requested receipt",
            ));
        }
        quarantine_temporary(context, &path)?;
    }

    let temporary_is_ready = match read_regular_if_present(&temporary)? {
        Some(observed) if matches_expected(&observed, expected_bytes, expected_canonical) => {
            if private && !is_owner_private_file(&temporary)? {
                quarantine_temporary(context, &temporary)?;
                false
            } else {
                sync_file(&temporary)?;
                true
            }
        }
        Some(_) => {
            quarantine_temporary(context, &temporary)?;
            false
        }
        None => false,
    };

    if !temporary_is_ready {
        write_new_temporary(context, &temporary, expected_bytes, fault_point, private)?;
    } else {
        maybe_pause_after_full_sync(context, fault_point)?;
    }

    match rename_no_replace(&temporary, &path) {
        Ok(()) => {
            if private && !is_owner_private_file(&path)? {
                return Err(unsafe_path(
                    &path,
                    "private receipt lost owner-only permissions before directory sync",
                ));
            }
            sync_directory(&parent)?;
            Ok(path)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let observed = read_regular_if_present(&path)?.ok_or_else(|| {
                io_message(
                    &path,
                    "atomic no-replace reported an existing target that cannot be read",
                )
            })?;
            if matches_expected(&observed, expected_bytes, expected_canonical) {
                if private && !is_owner_private_file(&path)? {
                    return Err(conflict(
                        &path,
                        "concurrent private receipt is not owner-only",
                    ));
                }
                remove_regular(&temporary)?;
                sync_directory(&parent)?;
                Ok(path)
            } else {
                quarantine_temporary(context, &temporary)?;
                Err(conflict(
                    &path,
                    "concurrent immutable receipt content conflicts with the requested receipt",
                ))
            }
        }
        Err(error) => Err(io(&path, error)),
    }
}

fn write_new_temporary(
    context: &CallContext,
    path: &Path,
    bytes: &[u8],
    fault_point: &'static str,
    private: bool,
) -> Result<(), DurableWriteError> {
    let path = authorize_candidate(context, path)?;
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        if private {
            options.mode(0o600);
        }
    }
    let mut file = options.open(&path).map_err(|error| io(&path, error))?;
    verify_open_identity(&path, &file)?;
    if private && !is_owner_private_file(&path)? {
        return Err(unsafe_path(
            &path,
            "new private receipt is not owner-only at creation",
        ));
    }

    if fault_active(context, fault_point) && fault_point.ends_with("after_partial_temp_write") {
        let partial_length = if bytes.len() > 1 {
            (bytes.len() / 2).max(1)
        } else {
            bytes.len()
        };
        file.write_all(&bytes[..partial_length])
            .and_then(|()| file.sync_all())
            .map_err(|error| io(&path, error))?;
        pause_at_fault(context, fault_point)?;
    }

    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| io(&path, error))?;
    drop(file);
    maybe_pause_after_full_sync(context, fault_point)
}

fn maybe_pause_after_full_sync(
    context: &CallContext,
    fault_point: &'static str,
) -> Result<(), DurableWriteError> {
    if fault_active(context, fault_point) && fault_point.ends_with("after_temp_sync_before_rename")
    {
        pause_at_fault(context, fault_point)?;
    }
    Ok(())
}

fn clean_temporary(
    context: &CallContext,
    path: &Path,
    expected_bytes: &[u8],
    expected_canonical: &str,
) -> Result<(), DurableWriteError> {
    let Some(observed) = read_regular_if_present(path)? else {
        return Ok(());
    };
    if matches_expected(&observed, expected_bytes, expected_canonical) {
        remove_regular(path)
    } else {
        quarantine_temporary(context, path)
    }
}

fn quarantine_temporary(context: &CallContext, temporary: &Path) -> Result<(), DurableWriteError> {
    let Some(bytes) = read_regular_if_present(temporary)? else {
        return Ok(());
    };
    let gtkg_root = temporary
        .ancestors()
        .find(|ancestor| ancestor.file_name().is_some_and(|name| name == ".gtkg"))
        .ok_or_else(|| invalid(temporary, "receipt temporary is not under a .gtkg root"))?;
    let quarantine = authorize_write(context, &gtkg_root.join("quarantine/receipts"))?;
    fs::create_dir_all(&quarantine).map_err(|error| io(&quarantine, error))?;
    let quarantine = authorize_write(context, &quarantine)?;
    ensure_directory(&quarantine)?;
    let path_digest = hex::encode(Sha256::digest(temporary.to_string_lossy().as_bytes()));
    let bytes_digest = hex::encode(Sha256::digest(&bytes));
    let file_name = temporary
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| invalid(temporary, "temporary filename is not UTF-8"))?;
    let destination = quarantine.join(format!(
        "{}-{file_name}-{}.crash",
        &path_digest[..16],
        &bytes_digest[..16]
    ));
    let destination = authorize_candidate(context, &destination)?;
    match rename_no_replace(temporary, &destination) {
        Ok(()) => {
            sync_parent(temporary)?;
            sync_directory(&quarantine)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let existing = read_regular_if_present(&destination)?.ok_or_else(|| {
                io_message(
                    &destination,
                    "quarantine target disappeared during recovery",
                )
            })?;
            if existing != bytes {
                return Err(conflict(
                    &destination,
                    "quarantine digest collision contains different bytes",
                ));
            }
            remove_regular(temporary)?;
            sync_parent(temporary)
        }
        Err(error) => Err(io(&destination, error)),
    }
}

fn matches_expected(observed: &[u8], expected: &[u8], canonical: &str) -> bool {
    if observed != expected {
        return false;
    }
    serde_json::from_slice::<serde_json::Value>(observed)
        .ok()
        .and_then(|value| canonical_json_sha256(&value).ok())
        .is_some_and(|observed_canonical| observed_canonical == canonical)
}

fn read_regular_if_present(path: &Path) -> Result<Option<Vec<u8>>, DurableWriteError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(io(path, error)),
    };
    ensure_regular_metadata(path, &metadata)?;
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|error| io(path, error))?;
    verify_open_identity(path, &file)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|error| io(path, error))?;
    Ok(Some(bytes))
}

fn remove_regular(path: &Path) -> Result<(), DurableWriteError> {
    if read_regular_if_present(path)?.is_some() {
        fs::remove_file(path).map_err(|error| io(path, error))?;
    }
    Ok(())
}

fn sync_file(path: &Path) -> Result<(), DurableWriteError> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|error| io(path, error))?;
    verify_open_identity(path, &file)?;
    file.sync_all().map_err(|error| io(path, error))
}

fn verify_open_identity(path: &Path, file: &File) -> Result<(), DurableWriteError> {
    let path_metadata = fs::symlink_metadata(path).map_err(|error| io(path, error))?;
    let file_metadata = file.metadata().map_err(|error| io(path, error))?;
    ensure_regular_metadata(path, &path_metadata)?;
    if !file_metadata.is_file() {
        return Err(unsafe_path(path, "opened receipt is not a regular file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if file_metadata.nlink() > 1
            || path_metadata.dev() != file_metadata.dev()
            || path_metadata.ino() != file_metadata.ino()
        {
            return Err(unsafe_path(
                path,
                "receipt path identity changed or is hardlinked",
            ));
        }
    }
    Ok(())
}

fn ensure_regular_metadata(path: &Path, metadata: &fs::Metadata) -> Result<(), DurableWriteError> {
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(unsafe_path(path, "receipt path is not a regular file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() > 1 {
            return Err(unsafe_path(path, "receipt path is hardlinked"));
        }
    }
    Ok(())
}

fn is_owner_private_file(path: &Path) -> Result<bool, DurableWriteError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| io(path, error))?;
    ensure_regular_metadata(path, &metadata)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        Ok(metadata.permissions().mode() & 0o077 == 0)
    }
    #[cfg(not(unix))]
    {
        Ok(false)
    }
}

fn ensure_directory(path: &Path) -> Result<(), DurableWriteError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| io(path, error))?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(unsafe_path(
            path,
            "receipt parent is not a private directory",
        ));
    }
    Ok(())
}

struct PublishGuard {
    file: File,
}

impl PublishGuard {
    fn acquire(context: &CallContext, receipt: &Path) -> Result<Self, DurableWriteError> {
        let gtkg_root = receipt
            .ancestors()
            .find(|ancestor| ancestor.file_name().is_some_and(|name| name == ".gtkg"))
            .ok_or_else(|| invalid(receipt, "immutable receipt is not under a .gtkg root"))?;
        let lock_directory = authorize_write(context, &gtkg_root.join("locks/receipts"))?;
        fs::create_dir_all(&lock_directory).map_err(|error| io(&lock_directory, error))?;
        let lock_directory = authorize_write(context, &lock_directory)?;
        ensure_directory(&lock_directory)?;
        let path_digest = hex::encode(Sha256::digest(receipt.to_string_lossy().as_bytes()));
        let lock_path =
            authorize_candidate(context, &lock_directory.join(format!("{path_digest}.lock")))?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(|error| io(&lock_path, error))?;
        verify_open_identity(&lock_path, &file)?;
        file.lock().map_err(|error| io(&lock_path, error))?;
        Ok(Self { file })
    }
}

impl Drop for PublishGuard {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

fn authorize_candidate(context: &CallContext, path: &Path) -> Result<PathBuf, DurableWriteError> {
    if let Ok(metadata) = fs::symlink_metadata(path) {
        ensure_regular_metadata(path, &metadata)?;
    }
    authorize_write(context, path)
}

fn authorize_write(context: &CallContext, path: &Path) -> Result<PathBuf, DurableWriteError> {
    context
        .authorize_write(path)
        .map_err(|error| unauthorized(path, error))
}

fn sync_parent(path: &Path) -> Result<(), DurableWriteError> {
    let parent = path
        .parent()
        .ok_or_else(|| invalid(path, "path has no parent directory"))?;
    sync_directory(parent)
}

pub(crate) fn sync_directory(path: &Path) -> Result<(), DurableWriteError> {
    #[cfg(unix)]
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| io(path, error))?;
    Ok(())
}

#[cfg(any(
    target_vendor = "apple",
    target_os = "linux",
    target_os = "android",
    target_os = "redox"
))]
pub(crate) fn rename_no_replace(source: &Path, target: &Path) -> std::io::Result<()> {
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        source,
        rustix::fs::CWD,
        target,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .map_err(|error| std::io::Error::from_raw_os_error(error.raw_os_error()))
}

#[cfg(not(any(
    target_vendor = "apple",
    target_os = "linux",
    target_os = "android",
    target_os = "redox"
)))]
pub(crate) fn rename_no_replace(_source: &Path, _target: &Path) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "atomic no-replace is unavailable on this platform",
    ))
}

#[cfg(feature = "test-faults")]
fn fault_active(context: &CallContext, point: &str) -> bool {
    context.transport == crate::TransportKind::Test
        && std::env::var("GTKG_TEST_FAULT_POINT").as_deref() == Ok(point)
}

#[cfg(not(feature = "test-faults"))]
fn fault_active(_context: &CallContext, _point: &str) -> bool {
    false
}

#[cfg(feature = "test-faults")]
pub(crate) fn pause_at_fault(context: &CallContext, point: &str) -> Result<(), DurableWriteError> {
    if !fault_active(context, point) {
        return Ok(());
    }
    let ready = std::env::var_os("GTKG_TEST_FAULT_READY")
        .map(PathBuf::from)
        .ok_or_else(|| invalid(Path::new(point), "fault ready path is missing"))?;
    let ready = authorize_candidate(context, &ready)?;
    let parent = ready
        .parent()
        .ok_or_else(|| invalid(&ready, "fault ready path has no parent"))?;
    fs::create_dir_all(parent).map_err(|error| io(parent, error))?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&ready)
        .map_err(|error| io(&ready, error))?;
    file.write_all(point.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|error| io(&ready, error))?;
    sync_directory(parent)?;
    loop {
        std::thread::park_timeout(std::time::Duration::from_secs(1));
    }
}

#[cfg(not(feature = "test-faults"))]
pub(crate) fn pause_at_fault(
    _context: &CallContext,
    _point: &str,
) -> Result<(), DurableWriteError> {
    Ok(())
}

fn invalid(path: &Path, message: impl Into<String>) -> DurableWriteError {
    DurableWriteError {
        kind: DurableErrorKind::Invalid,
        path: path.to_path_buf(),
        message: message.into(),
    }
}

fn unauthorized(path: &Path, error: ContextError) -> DurableWriteError {
    DurableWriteError {
        kind: DurableErrorKind::Unauthorized,
        path: path.to_path_buf(),
        message: error.to_string(),
    }
}

fn unsafe_path(path: &Path, message: impl Into<String>) -> DurableWriteError {
    DurableWriteError {
        kind: DurableErrorKind::Unsafe,
        path: path.to_path_buf(),
        message: message.into(),
    }
}

fn conflict(path: &Path, message: impl Into<String>) -> DurableWriteError {
    DurableWriteError {
        kind: DurableErrorKind::Conflict,
        path: path.to_path_buf(),
        message: message.into(),
    }
}

fn io(path: &Path, error: std::io::Error) -> DurableWriteError {
    DurableWriteError {
        kind: DurableErrorKind::Io,
        path: path.to_path_buf(),
        message: error.to_string(),
    }
}

fn io_message(path: &Path, message: impl Into<String>) -> DurableWriteError {
    DurableWriteError {
        kind: DurableErrorKind::Io,
        path: path.to_path_buf(),
        message: message.into(),
    }
}
