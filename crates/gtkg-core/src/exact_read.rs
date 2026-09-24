//! Race-resistant reads that bind returned bytes to one opened regular inode.

use std::fs::{self, File};
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::time::Instant;

use gtkg_protocol::ErrorCode;
use sha2::{Digest, Sha256};

use crate::{CallContext, ContextError};

#[derive(Debug)]
pub(crate) struct BoundRead {
    pub bytes: Vec<u8>,
    pub sha256: String,
}

#[derive(Debug)]
pub(crate) struct ExactReadFailure {
    pub code: ErrorCode,
    pub path: PathBuf,
    pub message: String,
}

pub(crate) fn read_bound_regular_file(
    context: &CallContext,
    requested_path: &Path,
) -> Result<BoundRead, ExactReadFailure> {
    let (candidate, authorized_root) = lexical_authorized_candidate(context, requested_path)?;
    reject_requested_symlink_components(&authorized_root, &candidate)?;
    let mut file = open_without_following_symlinks(&authorized_root, &candidate)?;
    let file_metadata = file
        .metadata()
        .map_err(|error| io_failure(&candidate, error))?;
    if !file_metadata.file_type().is_file() {
        return Err(unsafe_failure(
            &candidate,
            "exact read opened handle is not a regular file",
        ));
    }
    let path = context
        .authorize_read(requested_path)
        .map_err(|error| context_failure(requested_path, error))?;
    let relative = candidate
        .strip_prefix(&authorized_root)
        .map_err(|_| path_escape_failure(&candidate))?;
    let expected_path = fs::canonicalize(&authorized_root)
        .map_err(|error| io_failure(&authorized_root, error))?
        .join(relative);
    if path != expected_path {
        return Err(unsafe_failure(
            requested_path,
            "exact read request path changed identity during authorization",
        ));
    }
    let path_metadata = fs::symlink_metadata(&path).map_err(|error| io_failure(&path, error))?;
    if path_metadata.file_type().is_symlink() || !path_metadata.file_type().is_file() {
        return Err(unsafe_failure(&path, "exact read requires a regular file"));
    }
    ensure_same_private_inode(&path, &path_metadata, &file_metadata)?;

    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|error| io_failure(&path, error))?;

    reject_requested_symlink_components(&authorized_root, &candidate)?;
    let path_metadata_after =
        fs::symlink_metadata(&path).map_err(|error| io_failure(&path, error))?;
    ensure_same_private_inode(&path, &path_metadata_after, &file_metadata)?;
    Ok(BoundRead {
        sha256: sha256_bytes(&bytes),
        bytes,
    })
}

/// Bound the bytes read from the opened inode. Actual bytes survive every error.
/// The deadline is cooperative: a blocking OS read is not preempted.
pub(crate) fn read_bound_regular_file_limited(
    context: &CallContext,
    requested_path: &Path,
    max_bytes: u64,
    deadline: Option<Instant>,
    actual_bytes: &mut u64,
) -> Result<BoundRead, ExactReadFailure> {
    let check_time = || {
        if deadline.is_some_and(|d| Instant::now() >= d) {
            Err(ExactReadFailure {
                code: ErrorCode::InvalidRequest,
                path: requested_path.to_path_buf(),
                message: "E_QUERY_WALL_TIME_BUDGET".into(),
            })
        } else {
            Ok(())
        }
    };
    check_time()?;
    let (candidate, authorized_root) = lexical_authorized_candidate(context, requested_path)?;
    reject_requested_symlink_components(&authorized_root, &candidate)?;
    let mut file = open_without_following_symlinks(&authorized_root, &candidate)?;
    let opened = file.metadata().map_err(|e| io_failure(&candidate, e))?;
    if !opened.file_type().is_file() {
        return Err(unsafe_failure(
            &candidate,
            "exact read opened handle is not a regular file",
        ));
    }
    let path = context
        .authorize_read(requested_path)
        .map_err(|e| context_failure(requested_path, e))?;
    let relative = candidate
        .strip_prefix(&authorized_root)
        .map_err(|_| path_escape_failure(&candidate))?;
    let expected_path = fs::canonicalize(&authorized_root)
        .map_err(|e| io_failure(&authorized_root, e))?
        .join(relative);
    if path != expected_path {
        return Err(unsafe_failure(
            requested_path,
            "exact read request path changed identity during authorization",
        ));
    }
    let before = fs::symlink_metadata(&path).map_err(|e| io_failure(&path, e))?;
    ensure_same_private_inode(&path, &before, &opened)?;
    let limit_error = || ExactReadFailure {
        code: ErrorCode::InvalidRequest,
        path: path.clone(),
        message: "E_EXACT_READ_BYTE_LIMIT".into(),
    };
    // Fail before reading an already oversized file. This is a handle-bound
    // preflight, followed by an enforced read limit, not pathname prediction.
    if opened.len() > max_bytes {
        return Err(limit_error());
    }
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 16 * 1024];
    loop {
        check_time()?;
        let room = max_bytes.saturating_sub(bytes.len() as u64);
        if room == 0 {
            let current = file.metadata().map_err(|e| io_failure(&path, e))?;
            if current.len() != bytes.len() as u64 {
                return Err(limit_error());
            }
            break;
        }
        let wanted = room.min(buffer.len() as u64) as usize;
        let n = match file.read(&mut buffer[..wanted]) {
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(io_failure(&path, e)),
        };
        *actual_bytes = actual_bytes.saturating_add(n as u64);
        bytes.extend_from_slice(&buffer[..n]);
        if n == 0 {
            break;
        }
    }
    check_time()?;
    reject_requested_symlink_components(&authorized_root, &candidate)?;
    let after = fs::symlink_metadata(&path).map_err(|e| io_failure(&path, e))?;
    let handle_after = file.metadata().map_err(|e| io_failure(&path, e))?;
    ensure_same_private_inode(&path, &after, &opened)?;
    if after.len() != bytes.len() as u64
        || handle_after.len() != bytes.len() as u64
        || opened.len() != bytes.len() as u64
    {
        return Err(unsafe_failure(
            &path,
            "exact read length changed during bounded read",
        ));
    }
    Ok(BoundRead {
        sha256: sha256_bytes(&bytes),
        bytes,
    })
}

fn lexical_authorized_candidate(
    context: &CallContext,
    requested_path: &Path,
) -> Result<(PathBuf, PathBuf), ExactReadFailure> {
    if requested_path.components().any(|component| {
        matches!(
            component,
            Component::ParentDir | Component::CurDir | Component::Prefix(_)
        )
    }) {
        return Err(path_escape_failure(requested_path));
    }
    let candidate = if requested_path.is_absolute() {
        requested_path.to_path_buf()
    } else {
        context
            .workspace_root()
            .ok_or_else(|| path_escape_failure(requested_path))?
            .join(requested_path)
    };
    let authorized_root = context
        .authorized_lexical_roots()
        .iter()
        .chain(context.authorized_roots())
        .filter(|root| candidate == **root || candidate.starts_with(root))
        .max_by_key(|root| root.components().count())
        .cloned()
        .ok_or_else(|| path_escape_failure(requested_path))?;
    Ok((candidate, authorized_root))
}

fn reject_requested_symlink_components(
    authorized_root: &Path,
    candidate: &Path,
) -> Result<(), ExactReadFailure> {
    let root_metadata = fs::symlink_metadata(authorized_root)
        .map_err(|error| io_failure(authorized_root, error))?;
    if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
        return Err(unsafe_failure(
            authorized_root,
            "exact read authorized root is not a symlink-free directory",
        ));
    }
    let relative = candidate
        .strip_prefix(authorized_root)
        .map_err(|_| path_escape_failure(candidate))?;
    let components = relative.components().collect::<Vec<_>>();
    let mut cursor = authorized_root.to_path_buf();
    for (index, component) in components.iter().enumerate() {
        let Component::Normal(name) = component else {
            return Err(path_escape_failure(candidate));
        };
        cursor.push(name);
        let metadata = fs::symlink_metadata(&cursor).map_err(|error| io_failure(&cursor, error))?;
        if metadata.file_type().is_symlink() {
            return Err(unsafe_failure(
                &cursor,
                "exact read request path contains a symlink",
            ));
        }
        let is_final = index + 1 == components.len();
        if is_final && !metadata.file_type().is_file() {
            return Err(unsafe_failure(
                &cursor,
                "exact read final endpoint is not a regular file",
            ));
        }
        if !is_final && !metadata.is_dir() {
            return Err(unsafe_failure(
                &cursor,
                "exact read request path contains a non-directory component",
            ));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn open_without_following_symlinks(
    authorized_root: &Path,
    candidate: &Path,
) -> Result<File, ExactReadFailure> {
    use rustix::fs::{Mode, OFlags, open, openat};

    let relative = candidate
        .strip_prefix(authorized_root)
        .map_err(|_| path_escape_failure(candidate))?;
    let components = relative
        .components()
        .map(|component| match component {
            Component::Normal(name) => Ok(name.to_os_string()),
            _ => Err(path_escape_failure(candidate)),
        })
        .collect::<Result<Vec<_>, _>>()?;
    if components.is_empty() {
        return Err(unsafe_failure(
            candidate,
            "exact read requires a regular file below an authorized root",
        ));
    }
    let directory_flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut directory = open(authorized_root, directory_flags, Mode::empty())
        .map_err(|error| rustix_failure(authorized_root, error))?;
    for (index, component) in components.iter().enumerate() {
        let is_file = index + 1 == components.len();
        let flags = if is_file {
            OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC
        } else {
            directory_flags
        };
        let opened = openat(&directory, component.as_os_str(), flags, Mode::empty())
            .map_err(|error| rustix_failure(candidate, error))?;
        if is_file {
            return Ok(File::from(opened));
        }
        directory = opened;
    }
    Err(unsafe_failure(candidate, "exact read path is empty"))
}

#[cfg(not(unix))]
fn open_without_following_symlinks(
    _authorized_root: &Path,
    candidate: &Path,
) -> Result<File, ExactReadFailure> {
    File::open(candidate).map_err(|error| io_failure(candidate, error))
}

#[cfg(unix)]
fn rustix_failure(path: &Path, error: rustix::io::Errno) -> ExactReadFailure {
    io_failure(
        path,
        std::io::Error::from_raw_os_error(error.raw_os_error()),
    )
}

fn ensure_same_private_inode(
    path: &Path,
    path_metadata: &fs::Metadata,
    file_metadata: &fs::Metadata,
) -> Result<(), ExactReadFailure> {
    if path_metadata.file_type().is_symlink()
        || !path_metadata.file_type().is_file()
        || !file_metadata.file_type().is_file()
    {
        return Err(unsafe_failure(
            path,
            "exact read inode is not a regular file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if path_metadata.nlink() > 1
            || file_metadata.nlink() > 1
            || path_metadata.dev() != file_metadata.dev()
            || path_metadata.ino() != file_metadata.ino()
        {
            return Err(unsafe_failure(
                path,
                "exact read path and opened private inode do not match",
            ));
        }
    }
    Ok(())
}

fn sha256_bytes(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!("sha256:{}", hex::encode(digest))
}

fn context_failure(path: &Path, error: ContextError) -> ExactReadFailure {
    let code = match &error {
        ContextError::PathEscape(_) | ContextError::UnsafeRoot(_) => ErrorCode::PathEscape,
        ContextError::RootIo { source, .. } if source.kind() == std::io::ErrorKind::NotFound => {
            ErrorCode::NotFound
        }
        ContextError::RootIo { .. } => ErrorCode::Io,
        ContextError::MissingRoot | ContextError::InvalidReceipt(_) => ErrorCode::InvalidRequest,
    };
    ExactReadFailure {
        code,
        path: path.to_path_buf(),
        message: error.to_string(),
    }
}

fn unsafe_failure(path: &Path, message: impl Into<String>) -> ExactReadFailure {
    ExactReadFailure {
        code: ErrorCode::SymlinkRejected,
        path: path.to_path_buf(),
        message: message.into(),
    }
}

fn path_escape_failure(path: &Path) -> ExactReadFailure {
    ExactReadFailure {
        code: ErrorCode::PathEscape,
        path: path.to_path_buf(),
        message: "exact read path is outside the lexical authorized roots".to_owned(),
    }
}

fn io_failure(path: &Path, error: std::io::Error) -> ExactReadFailure {
    ExactReadFailure {
        code: if error.kind() == std::io::ErrorKind::NotFound {
            ErrorCode::NotFound
        } else {
            ErrorCode::Io
        },
        path: path.to_path_buf(),
        message: error.to_string(),
    }
}
