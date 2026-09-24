//! V0.2 internal source-capture boundary.
//!
//! This first T01 slice deliberately has no transport wiring.  It establishes
//! the fail-closed filesystem and eligibility contract that later capture-mode
//! implementations and T08 may consume.

use std::ffi::OsStr;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

use gtkg_protocol::v2::{
    SourceBaselineIdentityV2, SourceCaptureModeV2, SourceSnapshotDenominatorV2,
    SourceSnapshotEntryV2, SourceSnapshotOmissionV2, SourceSnapshotV2,
};
use gtkg_protocol::{ErrorCode, canonical_json_sha256, validate_sha256};
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

const SNAPSHOT_SCHEMA: &str = "gtkg.source-snapshot/v2";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceCaptureRequestV2 {
    pub capture_mode: SourceCaptureModeV2,
    pub repository_id: String,
    pub source_root: PathBuf,
    pub output_root: PathBuf,
}

/// A caller-supplied manifest is only eligible when it is bound to the
/// trusted authority selected by the caller's enclosing policy.  The capture
/// layer does not infer trust from a string inside the manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedManifestAuthorityV2 {
    pub authority_id: String,
}

impl TrustedManifestAuthorityV2 {
    pub fn new(authority_id: impl Into<String>) -> Self {
        Self {
            authority_id: authority_id.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SuppliedManifestV2 {
    pub authority_id: String,
    pub entries: Vec<SourceSnapshotEntryV2>,
    pub omissions: Vec<SourceSnapshotOmissionV2>,
}

impl SuppliedManifestV2 {
    pub fn new(
        authority_id: impl Into<String>,
        entries: Vec<SourceSnapshotEntryV2>,
        omissions: Vec<SourceSnapshotOmissionV2>,
    ) -> Self {
        Self {
            authority_id: authority_id.into(),
            entries,
            omissions,
        }
    }
}

impl SourceCaptureRequestV2 {
    pub fn new(
        capture_mode: SourceCaptureModeV2,
        repository_id: impl Into<String>,
        source_root: PathBuf,
        output_root: PathBuf,
    ) -> Self {
        Self {
            capture_mode,
            repository_id: repository_id.into(),
            source_root,
            output_root,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureErrorCode {
    InvalidRequest,
    SourceNotGit,
    SourceDirty,
    SourceOutputOverlap,
    SymlinkRejected,
    SnapshotDrift,
    UntrustedAuthority,
    ManifestMismatch,
    Io,
}

#[derive(Debug, Error)]
pub enum SourceCaptureErrorV2 {
    #[error("invalid source capture request: {0}")]
    InvalidRequest(String),
    #[error("source is not a readable Git worktree: {0}")]
    SourceNotGit(PathBuf),
    #[error("Git commit capture requires a clean worktree: {0}")]
    SourceDirty(PathBuf),
    #[error("source root and output root overlap: source={source_root}, output={output_root}")]
    SourceOutputOverlap {
        source_root: PathBuf,
        output_root: PathBuf,
    },
    #[error("symbolic links are not permitted in a SourceSnapshotV2: {0}")]
    SymlinkRejected(PathBuf),
    #[error("source changed while SourceSnapshotV2 was being captured: {0}")]
    SnapshotDrift(PathBuf),
    #[error("supplied manifest lacks the caller-selected trusted authority")]
    UntrustedAuthority,
    #[error("supplied manifest does not exactly match source readback")]
    ManifestMismatch,
    #[error("source capture I/O failed at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

impl SourceCaptureErrorV2 {
    pub const fn code(&self) -> CaptureErrorCode {
        match self {
            Self::InvalidRequest(_) => CaptureErrorCode::InvalidRequest,
            Self::SourceNotGit(_) => CaptureErrorCode::SourceNotGit,
            Self::SourceDirty(_) => CaptureErrorCode::SourceDirty,
            Self::SourceOutputOverlap { .. } => CaptureErrorCode::SourceOutputOverlap,
            Self::SymlinkRejected(_) => CaptureErrorCode::SymlinkRejected,
            Self::SnapshotDrift(_) => CaptureErrorCode::SnapshotDrift,
            Self::UntrustedAuthority => CaptureErrorCode::UntrustedAuthority,
            Self::ManifestMismatch => CaptureErrorCode::ManifestMismatch,
            Self::Io { .. } => CaptureErrorCode::Io,
        }
    }
}

/// Capture a source snapshot without any testing observer.
pub fn capture_source_snapshot_v2(
    request: &SourceCaptureRequestV2,
) -> Result<SourceSnapshotV2, SourceCaptureErrorV2> {
    capture_source_snapshot_v2_with_phases(request, |_| {}, || {})
}

/// Testable internal capture contract.  The observer is invoked after a file's
/// first metadata read and before its bytes are read; it lets the contract test
/// exercise the otherwise timing-dependent TOCTOU failure path.
pub fn capture_source_snapshot_v2_with_observer<F>(
    request: &SourceCaptureRequestV2,
    before_file_read: F,
) -> Result<SourceSnapshotV2, SourceCaptureErrorV2>
where
    F: FnMut(&Path),
{
    capture_source_snapshot_v2_with_phases(request, before_file_read, || {})
}

/// Testable internal capture contract with an explicit boundary between the
/// initial directory inventory and its mandatory full readback.  Production
/// callers use [`capture_source_snapshot_v2`].
pub fn capture_source_snapshot_v2_with_phases<F, G>(
    request: &SourceCaptureRequestV2,
    mut before_file_read: F,
    mut after_inventory: G,
) -> Result<SourceSnapshotV2, SourceCaptureErrorV2>
where
    F: FnMut(&Path),
    G: FnMut(),
{
    validate_repository_id(&request.repository_id)?;
    let source_root = checked_source_root(&request.source_root)?;
    let output_root = checked_output_root(&request.output_root)?;
    reject_overlap(&source_root, &output_root)?;

    match request.capture_mode {
        SourceCaptureModeV2::WorktreeExact => {
            capture_worktree_exact(request, &source_root, &mut before_file_read)
        }
        SourceCaptureModeV2::DirectoryExact => capture_directory_exact(
            request,
            &source_root,
            &mut before_file_read,
            &mut after_inventory,
        ),
        SourceCaptureModeV2::GitCommit => capture_git_commit(request, &source_root),
        SourceCaptureModeV2::SuppliedManifest => Err(SourceCaptureErrorV2::InvalidRequest(
            "use capture_supplied_manifest_v2 with an explicit trusted authority".to_owned(),
        )),
    }
}

fn capture_worktree_exact<F>(
    request: &SourceCaptureRequestV2,
    source_root: &Path,
    before_file_read: &mut F,
) -> Result<SourceSnapshotV2, SourceCaptureErrorV2>
where
    F: FnMut(&Path),
{
    let baseline_before = git_baseline(source_root, "worktree_exact")?;
    let (inventory, omissions) = collect_inventory(source_root, before_file_read)?;
    let baseline_after = git_baseline(source_root, "worktree_exact")?;
    if baseline_before != baseline_after {
        return Err(SourceCaptureErrorV2::SnapshotDrift(
            source_root.to_path_buf(),
        ));
    }
    build_snapshot(request, baseline_after, inventory, omissions)
}

fn capture_directory_exact<F>(
    request: &SourceCaptureRequestV2,
    source_root: &Path,
    before_file_read: &mut F,
    after_inventory: &mut impl FnMut(),
) -> Result<SourceSnapshotV2, SourceCaptureErrorV2>
where
    F: FnMut(&Path),
{
    let (inventory, omissions) = collect_inventory(source_root, before_file_read)?;
    after_inventory();
    let (readback_inventory, readback_omissions) = collect_inventory(source_root, &mut |_| {})?;
    if inventory != readback_inventory || omissions != readback_omissions {
        return Err(SourceCaptureErrorV2::SnapshotDrift(
            source_root.to_path_buf(),
        ));
    }
    let baseline = SourceBaselineIdentityV2 {
        kind: "directory_exact".to_owned(),
        head: None,
        tree: None,
        status_sha256: canonical_json_sha256(&(inventory.clone(), omissions.clone()))
            .map_err(|error| SourceCaptureErrorV2::InvalidRequest(error.to_string()))?,
    };
    build_snapshot(request, baseline, inventory, omissions)
}

fn capture_git_commit(
    request: &SourceCaptureRequestV2,
    source_root: &Path,
) -> Result<SourceSnapshotV2, SourceCaptureErrorV2> {
    let status_before = git_status(source_root)?;
    if !status_before.is_empty() {
        return Err(SourceCaptureErrorV2::SourceDirty(source_root.to_path_buf()));
    }
    let baseline_before = git_baseline(source_root, "git_commit")?;
    let (inventory, omissions) = collect_git_blob_inventory(source_root)?;
    let status_after = git_status(source_root)?;
    let baseline_after = git_baseline(source_root, "git_commit")?;
    if !status_after.is_empty() || baseline_before != baseline_after {
        return Err(SourceCaptureErrorV2::SnapshotDrift(
            source_root.to_path_buf(),
        ));
    }
    build_snapshot(request, baseline_after, inventory, omissions)
}

/// Capture a caller-supplied manifest only after binding it to an explicit
/// trusted authority and re-reading every supplied entry through the same
/// no-follow source boundary used for directory capture.
pub fn capture_supplied_manifest_v2(
    request: &SourceCaptureRequestV2,
    trusted_authority: Option<&TrustedManifestAuthorityV2>,
    manifest: &SuppliedManifestV2,
) -> Result<SourceSnapshotV2, SourceCaptureErrorV2> {
    if request.capture_mode != SourceCaptureModeV2::SuppliedManifest {
        return Err(SourceCaptureErrorV2::InvalidRequest(
            "supplied manifest API requires supplied_manifest capture mode".to_owned(),
        ));
    }
    validate_repository_id(&request.repository_id)?;
    validate_repository_id(&manifest.authority_id)?;
    let authority = trusted_authority.ok_or(SourceCaptureErrorV2::UntrustedAuthority)?;
    validate_repository_id(&authority.authority_id)?;
    if authority.authority_id != manifest.authority_id {
        return Err(SourceCaptureErrorV2::UntrustedAuthority);
    }
    let source_root = checked_source_root(&request.source_root)?;
    let output_root = checked_output_root(&request.output_root)?;
    reject_overlap(&source_root, &output_root)?;
    validate_manifest_entries(&manifest.entries)?;
    validate_manifest_omissions(&manifest.omissions)?;
    let (inventory, omissions) = collect_inventory(&source_root, &mut |_| {})?;
    if inventory != manifest.entries || omissions != manifest.omissions {
        return Err(SourceCaptureErrorV2::ManifestMismatch);
    }
    let baseline = SourceBaselineIdentityV2 {
        kind: "supplied_manifest".to_owned(),
        head: None,
        tree: None,
        status_sha256: canonical_json_sha256(&(authority.authority_id.as_str(), manifest))
            .map_err(|error| SourceCaptureErrorV2::InvalidRequest(error.to_string()))?,
    };
    build_snapshot(request, baseline, inventory, omissions)
}

fn build_snapshot(
    request: &SourceCaptureRequestV2,
    baseline: SourceBaselineIdentityV2,
    inventory: Vec<SourceSnapshotEntryV2>,
    omissions: Vec<SourceSnapshotOmissionV2>,
) -> Result<SourceSnapshotV2, SourceCaptureErrorV2> {
    let denominator = SourceSnapshotDenominatorV2 {
        discovered_entries: (inventory.len() + omissions.len()) as u64,
        admitted_entries: inventory.len() as u64,
        omitted_entries: omissions.len() as u64,
    };
    debug_assert!(denominator.is_closed());
    let exact_set_sha256 = canonical_json_sha256(&ExactSet {
        baseline: &baseline,
        inventory: &inventory,
        omissions: &omissions,
    })
    .map_err(|error| SourceCaptureErrorV2::InvalidRequest(error.to_string()))?;
    Ok(SourceSnapshotV2 {
        schema_version: SNAPSHOT_SCHEMA.to_owned(),
        capture_mode: request.capture_mode,
        repository_id: request.repository_id.clone(),
        baseline,
        inventory,
        omissions,
        denominator,
        exact_set_sha256,
        eligibility: request.capture_mode.default_eligibility(),
    })
}

#[derive(Serialize)]
struct ExactSet<'a> {
    baseline: &'a SourceBaselineIdentityV2,
    inventory: &'a [SourceSnapshotEntryV2],
    omissions: &'a [SourceSnapshotOmissionV2],
}

fn collect_inventory<F>(
    source_root: &Path,
    before_file_read: &mut F,
) -> Result<(Vec<SourceSnapshotEntryV2>, Vec<SourceSnapshotOmissionV2>), SourceCaptureErrorV2>
where
    F: FnMut(&Path),
{
    let context = crate::CallContext::restricted(
        crate::TransportKind::Cli,
        vec![source_root.to_path_buf()],
        crate::EffectPolicy::ReadOnly,
    )
    .map_err(|error| SourceCaptureErrorV2::InvalidRequest(error.to_string()))?;
    let mut inventory = Vec::new();
    let mut omissions = Vec::new();
    collect_directory(
        source_root,
        Path::new(""),
        &mut inventory,
        &mut omissions,
        &context,
        before_file_read,
    )?;
    inventory.sort();
    omissions.sort();
    Ok((inventory, omissions))
}

fn collect_directory<F>(
    source_root: &Path,
    relative: &Path,
    inventory: &mut Vec<SourceSnapshotEntryV2>,
    omissions: &mut Vec<SourceSnapshotOmissionV2>,
    context: &crate::CallContext,
    before_file_read: &mut F,
) -> Result<(), SourceCaptureErrorV2>
where
    F: FnMut(&Path),
{
    let directory = source_root.join(relative);
    let mut children = fs::read_dir(&directory)
        .map_err(|source| io_error(&directory, source))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| io_error(&directory, source))?;
    children.sort_by_key(|entry| entry.file_name());

    for child in children {
        let path = child.path();
        let child_relative = relative.join(child.file_name());
        let logical_path = logical_path(&child_relative)?;
        let metadata = fs::symlink_metadata(&path).map_err(|source| io_error(&path, source))?;
        if metadata.file_type().is_symlink() {
            return Err(SourceCaptureErrorV2::SymlinkRejected(path));
        }
        if is_default_exclusion(&child_relative) {
            omissions.push(SourceSnapshotOmissionV2 {
                logical_path,
                reason: "default_generated_or_git_metadata_exclusion".to_owned(),
            });
            continue;
        }
        if metadata.is_dir() {
            collect_directory(
                source_root,
                &child_relative,
                inventory,
                omissions,
                context,
                before_file_read,
            )?;
        } else if metadata.is_file() {
            let before = file_fingerprint(&metadata);
            before_file_read(&path);
            let bound = crate::exact_read::read_bound_regular_file(context, &path)
                .map_err(exact_read_failure)?;
            let after = fs::symlink_metadata(&path).map_err(|source| io_error(&path, source))?;
            if after.file_type().is_symlink() {
                return Err(SourceCaptureErrorV2::SymlinkRejected(path));
            }
            if !after.is_file() || before != file_fingerprint(&after) {
                return Err(SourceCaptureErrorV2::SnapshotDrift(path));
            }
            inventory.push(SourceSnapshotEntryV2 {
                logical_path,
                content_sha256: bound.sha256,
                bytes: bound.bytes.len() as u64,
            });
        } else {
            return Err(SourceCaptureErrorV2::InvalidRequest(format!(
                "source contains a non-regular entry: {}",
                path.display()
            )));
        }
    }
    Ok(())
}

fn collect_git_blob_inventory(
    root: &Path,
) -> Result<(Vec<SourceSnapshotEntryV2>, Vec<SourceSnapshotOmissionV2>), SourceCaptureErrorV2> {
    let output = git_bytes(root, &["ls-tree", "-r", "-z", "--full-tree", "HEAD"])?;
    let mut inventory = Vec::new();
    let mut omissions = Vec::new();
    for record in output
        .split(|byte| *byte == b'\0')
        .filter(|record| !record.is_empty())
    {
        let tab = record
            .iter()
            .position(|byte| *byte == b'\t')
            .ok_or_else(|| {
                SourceCaptureErrorV2::InvalidRequest("malformed git ls-tree record".to_owned())
            })?;
        let header = std::str::from_utf8(&record[..tab]).map_err(|_| {
            SourceCaptureErrorV2::InvalidRequest("non-UTF-8 git ls-tree header".to_owned())
        })?;
        let mut fields = header.split_whitespace();
        let mode = fields
            .next()
            .ok_or_else(|| SourceCaptureErrorV2::InvalidRequest("missing git mode".to_owned()))?;
        let kind = fields.next().ok_or_else(|| {
            SourceCaptureErrorV2::InvalidRequest("missing git object kind".to_owned())
        })?;
        let object = fields.next().ok_or_else(|| {
            SourceCaptureErrorV2::InvalidRequest("missing git object id".to_owned())
        })?;
        if fields.next().is_some() {
            return Err(SourceCaptureErrorV2::InvalidRequest(
                "malformed git ls-tree header".to_owned(),
            ));
        }
        let logical_path = std::str::from_utf8(&record[tab + 1..])
            .map_err(|_| SourceCaptureErrorV2::InvalidRequest("non-UTF-8 Git path".to_owned()))?
            .to_owned();
        let path = Path::new(&logical_path);
        validate_logical_path(path)?;
        if mode == "120000" {
            return Err(SourceCaptureErrorV2::SymlinkRejected(root.join(path)));
        }
        if kind != "blob" || !matches!(mode, "100644" | "100755") {
            return Err(SourceCaptureErrorV2::InvalidRequest(format!(
                "unsupported Git tree entry {mode} {kind} for {logical_path}"
            )));
        }
        if is_default_exclusion(path) {
            omissions.push(SourceSnapshotOmissionV2 {
                logical_path,
                reason: "default_generated_or_git_metadata_exclusion".to_owned(),
            });
            continue;
        }
        let bytes = git_bytes(root, &["cat-file", "blob", object])?;
        inventory.push(SourceSnapshotEntryV2 {
            logical_path,
            content_sha256: sha256_bytes(&bytes),
            bytes: bytes.len() as u64,
        });
    }
    inventory.sort();
    omissions.sort();
    Ok((inventory, omissions))
}

fn git_baseline(root: &Path, kind: &str) -> Result<SourceBaselineIdentityV2, SourceCaptureErrorV2> {
    let top_level = git(root, &["rev-parse", "--show-toplevel"])?;
    if fs::canonicalize(top_level.trim()).map_err(|source| io_error(root, source))? != root {
        return Err(SourceCaptureErrorV2::SourceNotGit(root.to_path_buf()));
    }
    let head = git(root, &["rev-parse", "HEAD"])?;
    let tree = git(root, &["rev-parse", "HEAD^{tree}"])?;
    let status = git_bytes(
        root,
        &["status", "--porcelain=v1", "--untracked-files=all", "-z"],
    )?;
    Ok(SourceBaselineIdentityV2 {
        kind: kind.to_owned(),
        head: Some(head.trim().to_owned()),
        tree: Some(tree.trim().to_owned()),
        status_sha256: sha256_bytes(&status),
    })
}

fn git_status(root: &Path) -> Result<Vec<u8>, SourceCaptureErrorV2> {
    git_bytes(
        root,
        &["status", "--porcelain=v1", "--untracked-files=all", "-z"],
    )
}

fn git(root: &Path, arguments: &[&str]) -> Result<String, SourceCaptureErrorV2> {
    String::from_utf8(git_bytes(root, arguments)?)
        .map_err(|_| SourceCaptureErrorV2::SourceNotGit(root.to_path_buf()))
}

fn git_bytes(root: &Path, arguments: &[&str]) -> Result<Vec<u8>, SourceCaptureErrorV2> {
    let output = Command::new("/usr/bin/git")
        .arg("-C")
        .arg(root)
        .args(arguments)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .map_err(|source| io_error(root, source))?;
    if !output.status.success() {
        return Err(SourceCaptureErrorV2::SourceNotGit(root.to_path_buf()));
    }
    Ok(output.stdout)
}

fn checked_source_root(path: &Path) -> Result<PathBuf, SourceCaptureErrorV2> {
    let metadata = fs::symlink_metadata(path).map_err(|source| io_error(path, source))?;
    if metadata.file_type().is_symlink() {
        return Err(SourceCaptureErrorV2::SymlinkRejected(path.to_path_buf()));
    }
    if !metadata.is_dir() {
        return Err(SourceCaptureErrorV2::InvalidRequest(format!(
            "source root is not a directory: {}",
            path.display()
        )));
    }
    fs::canonicalize(path).map_err(|source| io_error(path, source))
}

fn checked_output_root(path: &Path) -> Result<PathBuf, SourceCaptureErrorV2> {
    let absolute = normalized_absolute(path)?;
    if let Ok(metadata) = fs::symlink_metadata(&absolute) {
        if metadata.file_type().is_symlink() {
            return Err(SourceCaptureErrorV2::SymlinkRejected(absolute));
        }
        return fs::canonicalize(path).map_err(|source| io_error(path, source));
    }
    canonicalize_missing_path(&absolute)
}

/// Canonicalize the deepest existing ancestor and append the missing lexical
/// suffix.  This preserves source/output overlap checks on macOS where `/var`
/// and `/private/var` can name the same directory.
fn canonicalize_missing_path(path: &Path) -> Result<PathBuf, SourceCaptureErrorV2> {
    let mut existing = path.to_path_buf();
    let mut missing = Vec::new();
    while fs::symlink_metadata(&existing).is_err() {
        let name = existing.file_name().ok_or_else(|| {
            SourceCaptureErrorV2::InvalidRequest(format!(
                "output root has no existing ancestor: {}",
                path.display()
            ))
        })?;
        missing.push(name.to_os_string());
        if !existing.pop() {
            return Err(SourceCaptureErrorV2::InvalidRequest(format!(
                "output root has no existing ancestor: {}",
                path.display()
            )));
        }
    }
    let metadata = fs::symlink_metadata(&existing).map_err(|source| io_error(&existing, source))?;
    if metadata.file_type().is_symlink() {
        return Err(SourceCaptureErrorV2::SymlinkRejected(existing));
    }
    let mut canonical =
        fs::canonicalize(&existing).map_err(|source| io_error(&existing, source))?;
    for segment in missing.into_iter().rev() {
        canonical.push(segment);
    }
    Ok(canonical)
}

fn reject_overlap(source: &Path, output: &Path) -> Result<(), SourceCaptureErrorV2> {
    if source.starts_with(output) || output.starts_with(source) {
        return Err(SourceCaptureErrorV2::SourceOutputOverlap {
            source_root: source.to_path_buf(),
            output_root: output.to_path_buf(),
        });
    }
    Ok(())
}

fn normalized_absolute(path: &Path) -> Result<PathBuf, SourceCaptureErrorV2> {
    let raw = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|source| io_error(path, source))?
            .join(path)
    };
    let mut normalized = PathBuf::new();
    for component in raw.components() {
        match component {
            Component::Prefix(_) | Component::RootDir => normalized.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(SourceCaptureErrorV2::InvalidRequest(format!(
                    "source/output roots must not contain parent traversal: {}",
                    path.display()
                )));
            }
            Component::Normal(segment) => normalized.push(segment),
        }
    }
    Ok(normalized)
}

fn validate_repository_id(value: &str) -> Result<(), SourceCaptureErrorV2> {
    if value.is_empty()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(SourceCaptureErrorV2::InvalidRequest(
            "repository_id must be a non-empty ASCII identifier".to_owned(),
        ));
    }
    Ok(())
}

fn logical_path(path: &Path) -> Result<String, SourceCaptureErrorV2> {
    validate_logical_path(path)?;
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| SourceCaptureErrorV2::InvalidRequest("source path is not UTF-8".to_owned()))
}

fn validate_logical_path(path: &Path) -> Result<(), SourceCaptureErrorV2> {
    if path
        .components()
        .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(SourceCaptureErrorV2::InvalidRequest(format!(
            "unsafe source path: {}",
            path.display()
        )));
    }
    Ok(())
}

fn validate_manifest_entries(
    entries: &[SourceSnapshotEntryV2],
) -> Result<(), SourceCaptureErrorV2> {
    let mut previous = None;
    for entry in entries {
        validate_logical_path(Path::new(&entry.logical_path))?;
        validate_sha256(&entry.content_sha256)
            .map_err(|error| SourceCaptureErrorV2::InvalidRequest(error.to_string()))?;
        if previous.is_some_and(|path: &str| path >= entry.logical_path.as_str()) {
            return Err(SourceCaptureErrorV2::InvalidRequest(
                "supplied manifest entries must be strictly sorted and unique".to_owned(),
            ));
        }
        previous = Some(entry.logical_path.as_str());
    }
    Ok(())
}

fn validate_manifest_omissions(
    omissions: &[SourceSnapshotOmissionV2],
) -> Result<(), SourceCaptureErrorV2> {
    let mut previous = None;
    for omission in omissions {
        validate_logical_path(Path::new(&omission.logical_path))?;
        if omission.reason.trim().is_empty() {
            return Err(SourceCaptureErrorV2::InvalidRequest(
                "supplied manifest omission reason must not be empty".to_owned(),
            ));
        }
        if previous.is_some_and(|path: &str| path >= omission.logical_path.as_str()) {
            return Err(SourceCaptureErrorV2::InvalidRequest(
                "supplied manifest omissions must be strictly sorted and unique".to_owned(),
            ));
        }
        previous = Some(omission.logical_path.as_str());
    }
    Ok(())
}

fn is_default_exclusion(path: &Path) -> bool {
    path.components()
        .next()
        .and_then(|component| match component {
            Component::Normal(segment) => OsStr::to_str(segment),
            _ => None,
        })
        .is_some_and(|name| {
            matches!(
                name,
                ".git" | ".gtkg" | "target" | "current" | "audit" | "receipts" | "generated"
            )
        })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileFingerprint {
    bytes: u64,
    modified: Option<std::time::SystemTime>,
}

fn file_fingerprint(metadata: &fs::Metadata) -> FileFingerprint {
    FileFingerprint {
        bytes: metadata.len(),
        modified: metadata.modified().ok(),
    }
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn io_error(path: &Path, source: std::io::Error) -> SourceCaptureErrorV2 {
    SourceCaptureErrorV2::Io {
        path: path.to_path_buf(),
        source,
    }
}

fn exact_read_failure(error: crate::exact_read::ExactReadFailure) -> SourceCaptureErrorV2 {
    match error.code {
        ErrorCode::SymlinkRejected => SourceCaptureErrorV2::SymlinkRejected(error.path),
        ErrorCode::PathEscape | ErrorCode::ScopeDenied => {
            SourceCaptureErrorV2::InvalidRequest(error.message)
        }
        _ => SourceCaptureErrorV2::SnapshotDrift(error.path),
    }
}
