//! Exact Git source inventory and content-addressed, transferable source archives.
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use thiserror::Error;

pub const LEDGER_FILE: &str = "source-coverage-ledger.json";
pub const PAGE_FILES: usize = 128;
pub const PAGE_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceCaptureRequest {
    pub repository_id: String,
    pub source_root: PathBuf,
    pub source_commit: String,
    pub expected_tree: String,
    pub output_path: PathBuf,
    pub policy: ScopePolicy,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopePolicy {
    pub revision: String,
    pub rules: Vec<ScopeRule>,
    pub archive_binary: bool,
}
impl Default for ScopePolicy {
    fn default() -> Self {
        Self {
            revision: "scope-all-tracked/v1".into(),
            rules: vec![],
            archive_binary: false,
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeRule {
    pub path_prefix: String,
    pub included: bool,
    pub rule_id: String,
    pub origin: String,
    pub reason: String,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    Included,
    Excluded,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureStatus {
    Captured,
    Unsupported,
    Failed,
    NotRequested,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TextStatus {
    Extracted,
    Partial,
    Unsupported,
    Failed,
    NotApplicable,
    NotRequested,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticStatus {
    Analyzed,
    Partial,
    Unsupported,
    Failed,
    NotApplicable,
    NotRequested,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MainRoute {
    Code,
    Text,
    Binary,
    Document,
    Symlink,
    Gitlink,
    Unsupported,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceLeaf {
    pub path: String,
    pub mode: String,
    pub object_kind: String,
    pub git_oid: String,
    pub scope: Scope,
    pub matched_rule: String,
    pub rule_origin: String,
    pub scope_reason: String,
    pub capture: CaptureStatus,
    pub capture_reason: String,
    pub text: TextStatus,
    pub text_reason: String,
    pub semantic: SemanticStatus,
    pub semantic_reason: String,
    pub main_route: MainRoute,
    pub language: Option<String>,
    pub byte_len: u64,
    pub content_sha256: Option<String>,
    pub object_sha256: Option<String>,
    pub extracted_text_sha256: Option<String>,
    pub availability_reason: String,
    pub oversized_streamed: bool,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchiveRef {
    pub path: String,
    pub bytes: u64,
    pub sha256: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectionPage {
    pub schema_version: String,
    pub snapshot_id: String,
    pub policy_sha256: String,
    pub page_index: usize,
    pub total_pages: usize,
    pub total_files: usize,
    pub paths: Vec<String>,
    pub files_sha256: String,
    pub source_bytes: u64,
    pub oversized_streamed: bool,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnalysisSelectionManifest {
    pub schema_version: String,
    pub snapshot_id: String,
    pub policy_sha256: String,
    pub total_files: usize,
    pub files_sha256: String,
    pub pages: Vec<ArchiveRef>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceObjectManifest {
    pub schema_version: String,
    pub snapshot_id: String,
    pub objects: Vec<ArchiveRef>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceCoverageLedger {
    pub schema_version: String,
    pub repository_id: String,
    pub source_commit: String,
    pub source_tree: String,
    pub policy: ScopePolicy,
    pub policy_sha256: String,
    pub snapshot_id: String,
    pub leaves_sha256: String,
    pub leaves: Vec<SourceLeaf>,
    pub selection_manifest: ArchiveRef,
    pub object_manifest: ArchiveRef,
}
#[derive(Debug, Error)]
pub enum SourceError {
    #[error("source archive implementation pending")]
    NotImplemented,
    #[error("unsafe source or archive path: {0}")]
    UnsafePath(String),
    #[error("source identity mismatch: {0}")]
    IdentityMismatch(String),
    #[error("invalid source archive: {0}")]
    InvalidArchive(String),
    #[error("Git source unavailable: {0}")]
    Git(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

impl SourceError {
    /// The dedicated v2 code for this source failure.
    ///
    /// `Git` covers every failure of the sanitized `git` subprocess, including a
    /// root that is not a repository at all. It therefore cannot claim
    /// `E_SOURCE_NOT_GIT` without guessing and maps to `E_IO` instead; the
    /// identity checks that *do* know the answer report `E_SOURCE_CHANGED`.
    pub fn code(&self) -> gtkg_protocol::v2::V2ErrorCode {
        use gtkg_protocol::v2::V2ErrorCode as Code;
        match self {
            Self::NotImplemented => Code::OperationNotImplemented,
            Self::UnsafePath(_) => Code::PathEscape,
            Self::IdentityMismatch(_) => Code::SourceChanged,
            Self::InvalidArchive(_) => Code::InvalidRequest,
            Self::Git(_) | Self::Io(_) => Code::Io,
            Self::Json(_) => Code::InvalidRequest,
        }
    }
}

use rustix::fs::{Mode, OFlags};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Component;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

const LEDGER_SCHEMA: &str = "gtkg.qk.source-coverage-ledger/v1";
const SELECTION_SCHEMA: &str = "gtkg.qk.analysis-selection-manifest/v1";
const OBJECT_SCHEMA: &str = "gtkg.qk.source-object-manifest/v1";
const PAGE_SCHEMA: &str = "gtkg.qk.analysis-selection-page/v1";
static TEMP_ID: AtomicU64 = AtomicU64::new(0);
fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn json_hash<T: Serialize>(value: &T) -> Result<String, SourceError> {
    Ok(hash(&serde_json::to_vec(value)?))
}
fn invalid(message: impl Into<String>) -> SourceError {
    SourceError::InvalidArchive(message.into())
}
fn valid_hex(value: &str, size: usize) -> bool {
    value.len() == size
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn validate_oid(value: &str) -> Result<(), SourceError> {
    if valid_hex(value, 40) || valid_hex(value, 64) {
        Ok(())
    } else {
        Err(SourceError::IdentityMismatch(
            "expected exact lowercase object ID".into(),
        ))
    }
}
fn validate_relative(path: &str) -> Result<(), SourceError> {
    if path.is_empty()
        || path.contains('\0')
        || path.contains('\\')
        || path
            .split('/')
            .any(|s| s.is_empty() || s == "." || s == "..")
        || !Path::new(path)
            .components()
            .all(|c| matches!(c, Component::Normal(_)))
    {
        return Err(SourceError::UnsafePath(path.into()));
    }
    Ok(())
}
fn policy_valid(policy: &ScopePolicy) -> Result<(), SourceError> {
    if policy.revision.is_empty() {
        return Err(invalid("empty policy revision"));
    }
    let mut ids = BTreeSet::new();
    for rule in &policy.rules {
        validate_relative(&rule.path_prefix)?;
        if rule.rule_id.is_empty()
            || rule.origin.is_empty()
            || rule.reason.is_empty()
            || !ids.insert(&rule.rule_id)
        {
            return Err(invalid("scope rules need unique ID, origin and reason"));
        }
    }
    Ok(())
}
fn scope_rule(path: &str, policy: &ScopePolicy) -> (Scope, String, String, String) {
    for r in &policy.rules {
        if path == r.path_prefix
            || path
                .strip_prefix(&r.path_prefix)
                .is_some_and(|s| s.starts_with('/'))
        {
            return (
                if r.included {
                    Scope::Included
                } else {
                    Scope::Excluded
                },
                r.rule_id.clone(),
                r.origin.clone(),
                r.reason.clone(),
            );
        }
    }
    (
        Scope::Included,
        "default-all-tracked".into(),
        "frozen-policy".into(),
        "all tracked leaves included by default".into(),
    )
}
fn snapshot_id(repo: &str, commit: &str, tree: &str, policy: &str) -> Result<String, SourceError> {
    json_hash(&(LEDGER_SCHEMA, repo, commit, tree, policy))
}
fn clean_git(root: &Path) -> Command {
    let mut c = Command::new("git");
    c.arg("--no-replace-objects")
        .arg("-C")
        .arg(root)
        .args([
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.hooksPath=/dev/null",
        ])
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .env("GIT_NO_LAZY_FETCH", "1")
        .env("GIT_ALLOW_PROTOCOL", "")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null");
    for name in [
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_PARAMETERS",
    ] {
        c.env_remove(name);
    }
    c
}
fn git_bytes(root: &Path, args: &[&str]) -> Result<Vec<u8>, SourceError> {
    let o = clean_git(root).args(args).output()?;
    if !o.status.success() {
        return Err(SourceError::Git(String::from_utf8_lossy(&o.stderr).into()));
    }
    Ok(o.stdout)
}
fn real_directory(path: &Path) -> Result<PathBuf, SourceError> {
    if path
        .components()
        .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return Err(SourceError::UnsafePath(path.display().to_string()));
    }
    let m = fs::symlink_metadata(path)?;
    if m.file_type().is_symlink() || !m.is_dir() {
        return Err(SourceError::UnsafePath(path.display().to_string()));
    }
    Ok(fs::canonicalize(path)?)
}
fn output_location(path: &Path) -> Result<PathBuf, SourceError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return Err(SourceError::UnsafePath(path.display().to_string()));
    }
    if fs::symlink_metadata(path).is_ok() {
        return real_directory(path);
    }
    let parent = path
        .parent()
        .ok_or_else(|| SourceError::UnsafePath(path.display().to_string()))?;
    let parent = if parent.exists() {
        real_directory(parent)?
    } else {
        output_location(parent)?
    };
    Ok(parent.join(
        path.file_name()
            .ok_or_else(|| invalid("output filename missing"))?,
    ))
}
fn errno(e: rustix::io::Errno) -> SourceError {
    SourceError::Io(std::io::Error::from_raw_os_error(e.raw_os_error()))
}
/// All archive operations are relative to pinned, no-follow directory handles.
struct Archive {
    directory: File,
}
impl Archive {
    fn open(root: &Path) -> Result<Self, SourceError> {
        let root = real_directory(root)?;
        let fd = rustix::fs::open(
            &root,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(errno)?;
        Ok(Self {
            directory: File::from(fd),
        })
    }
    fn parent(&self, path: &str, create: bool) -> Result<(File, String), SourceError> {
        validate_relative(path)?;
        let mut parts: Vec<_> = path.split('/').collect();
        let name = parts
            .pop()
            .ok_or_else(|| invalid("empty path"))?
            .to_string();
        let mut dir = self.directory.try_clone()?;
        for part in parts {
            if create {
                match rustix::fs::mkdirat(&dir, part, Mode::RUSR | Mode::WUSR | Mode::XUSR) {
                    Ok(()) => {}
                    Err(e) if e == rustix::io::Errno::EXIST => {}
                    Err(e) => return Err(errno(e)),
                }
            }
            dir = File::from(
                rustix::fs::openat(
                    &dir,
                    part,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(errno)?,
            );
        }
        Ok((dir, name))
    }
    fn open_file(&self, path: &str) -> Result<File, SourceError> {
        let (dir, name) = self.parent(path, false)?;
        let f = File::from(
            rustix::fs::openat(
                &dir,
                name.as_str(),
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(errno)?,
        );
        let m = f.metadata()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if m.nlink() != 1 {
                return Err(invalid("archive object must be a private inode"));
            }
        }
        if !m.is_file() {
            return Err(invalid("archive object is not a regular file"));
        }
        Ok(f)
    }
    fn read(&self, path: &str) -> Result<Vec<u8>, SourceError> {
        let mut f = self.open_file(path)?;
        let mut bytes = Vec::new();
        f.read_to_end(&mut bytes)?;
        Ok(bytes)
    }
    fn exists(&self, path: &str) -> Result<bool, SourceError> {
        match self.open_file(path) {
            Ok(_) => Ok(true),
            Err(SourceError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }
    fn temporary(&self) -> Result<(String, File), SourceError> {
        loop {
            let name = format!(
                ".pending-{}-{}",
                std::process::id(),
                TEMP_ID.fetch_add(1, Ordering::Relaxed)
            );
            match rustix::fs::openat(
                &self.directory,
                name.as_str(),
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            ) {
                Ok(fd) => return Ok((name, File::from(fd))),
                Err(e) if e == rustix::io::Errno::EXIST => continue,
                Err(e) => return Err(errno(e)),
            }
        }
    }
    fn remove_temp(&self, name: &str) -> Result<(), SourceError> {
        rustix::fs::unlinkat(&self.directory, name, rustix::fs::AtFlags::empty()).map_err(errno)
    }
    fn commit_temp(&self, temp: &str, target: &str, expected: &str) -> Result<(), SourceError> {
        let (dir, name) = self.parent(target, true)?;
        match rustix::fs::renameat_with(
            &self.directory,
            temp,
            &dir,
            name.as_str(),
            rustix::fs::RenameFlags::NOREPLACE,
        ) {
            Ok(()) => {
                dir.sync_all()?;
                Ok(())
            }
            Err(e) if e == rustix::io::Errno::EXIST => {
                if self.file_digest(target)?.0 != expected {
                    return Err(invalid(format!("existing artifact changed: {target}")));
                }
                self.remove_temp(temp)
            }
            Err(e) => Err(errno(e)),
        }
    }
    fn file_digest(&self, path: &str) -> Result<(String, u64), SourceError> {
        let mut f = self.open_file(path)?;
        let mut h = Sha256::new();
        let mut total = 0;
        let mut buf = [0; 65536];
        loop {
            let n = f.read(&mut buf)?;
            if n == 0 {
                break;
            }
            h.update(&buf[..n]);
            total += n as u64;
        }
        Ok((hex::encode(h.finalize()), total))
    }
    fn write(&self, path: &str, bytes: &[u8]) -> Result<ArchiveRef, SourceError> {
        let digest = hash(bytes);
        let (temp, mut file) = self.temporary()?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        self.commit_temp(&temp, path, &digest)?;
        Ok(ArchiveRef {
            path: path.into(),
            bytes: bytes.len() as u64,
            sha256: digest,
        })
    }
    fn write_json<T: Serialize>(&self, path: &str, value: &T) -> Result<ArchiveRef, SourceError> {
        self.write(path, &serde_json::to_vec(value)?)
    }
    fn read_ref(&self, r: &ArchiveRef) -> Result<Vec<u8>, SourceError> {
        if !valid_hex(&r.sha256, 64) {
            return Err(invalid("invalid reference digest"));
        }
        let b = self.read(&r.path)?;
        if b.len() as u64 != r.bytes || hash(&b) != r.sha256 {
            return Err(invalid(format!("reference digest mismatch: {}", r.path)));
        }
        Ok(b)
    }
}
struct BlobReader {
    child: Child,
    input: Option<ChildStdin>,
    output: BufReader<ChildStdout>,
}
#[derive(Clone)]
struct Blob {
    digest: String,
    bytes: u64,
    utf8_text: bool,
    temp: String,
}
impl BlobReader {
    fn new(root: &Path) -> Result<Self, SourceError> {
        let mut child = clean_git(root)
            .args(["cat-file", "--batch"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let input = child
            .stdin
            .take()
            .ok_or_else(|| invalid("cat-file stdin unavailable"))?;
        let output = child
            .stdout
            .take()
            .ok_or_else(|| invalid("cat-file stdout unavailable"))?;
        Ok(Self {
            child,
            input: Some(input),
            output: BufReader::new(output),
        })
    }
    fn read(&mut self, oid: &str, archive: &Archive) -> Result<Blob, SourceError> {
        let input = self
            .input
            .as_mut()
            .ok_or_else(|| invalid("cat-file already closed"))?;
        writeln!(input, "{oid}")?;
        input.flush()?;
        let mut header = String::new();
        self.output.read_line(&mut header)?;
        let pieces: Vec<_> = header.split_whitespace().collect();
        if pieces.len() != 3 || pieces[0] != oid || pieces[1] != "blob" {
            return Err(SourceError::Git(
                "cat-file returned wrong object identity/type".into(),
            ));
        }
        let bytes: u64 = pieces[2]
            .parse()
            .map_err(|_| invalid("cat-file malformed size"))?;
        let (temp, mut file) = archive.temporary()?;
        let mut left = bytes;
        let mut hash = Sha256::new();
        let mut buf = [0u8; 65536];
        let mut utf8 = true;
        let mut carry = Vec::new();
        while left > 0 {
            let n =
                usize::try_from(left.min(buf.len() as u64)).map_err(|_| invalid("blob size"))?;
            self.output.read_exact(&mut buf[..n])?;
            file.write_all(&buf[..n])?;
            hash.update(&buf[..n]);
            left -= n as u64;
            if utf8 {
                if buf[..n].contains(&0) {
                    utf8 = false;
                } else {
                    carry.extend_from_slice(&buf[..n]);
                    match std::str::from_utf8(&carry) {
                        Ok(_) => carry.clear(),
                        Err(e) if e.error_len().is_none() => {
                            let rest = carry[e.valid_up_to()..].to_vec();
                            carry = rest;
                        }
                        Err(_) => utf8 = false,
                    }
                }
            }
        }
        let mut newline = [0];
        self.output.read_exact(&mut newline)?;
        if newline[0] != b'\n' {
            return Err(invalid("cat-file missing separator"));
        }
        file.sync_all()?;
        if !carry.is_empty() {
            utf8 = false;
        }
        Ok(Blob {
            digest: hex::encode(hash.finalize()),
            bytes,
            utf8_text: utf8,
            temp,
        })
    }
    fn finish(&mut self) -> Result<(), SourceError> {
        self.input.take();
        if !self.child.wait()?.success() {
            return Err(SourceError::Git("cat-file failed".into()));
        }
        Ok(())
    }
}
impl Drop for BlobReader {
    fn drop(&mut self) {
        self.input.take();
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
fn route(path: &str, mode: &str, kind: &str) -> (MainRoute, Option<String>) {
    if mode == "120000" {
        return (MainRoute::Symlink, None);
    }
    if mode == "160000" || kind == "commit" {
        return (MainRoute::Gitlink, None);
    }
    if kind != "blob" || !matches!(mode, "100644" | "100755") {
        return (MainRoute::Unsupported, None);
    }
    let ext = Path::new(path)
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let language = match ext.as_str() {
        "go" => Some("go"),
        "rs" => Some("rust"),
        "py" => Some("python"),
        "ts" | "tsx" => Some("typescript"),
        "js" | "jsx" | "mjs" | "cjs" => Some("javascript"),
        _ => None,
    };
    if let Some(l) = language {
        return (MainRoute::Code, Some(l.into()));
    }
    if matches!(
        ext.as_str(),
        "pdf" | "doc" | "docx" | "ppt" | "pptx" | "xls" | "xlsx" | "odt"
    ) {
        return (MainRoute::Document, None);
    }
    if matches!(
        ext.as_str(),
        "png"
            | "jpg"
            | "jpeg"
            | "gif"
            | "ico"
            | "woff"
            | "woff2"
            | "ttf"
            | "otf"
            | "zip"
            | "gz"
            | "tar"
            | "mp4"
            | "mp3"
            | "webp"
            | "wasm"
            | "bin"
            | "dylib"
            | "so"
            | "exe"
    ) {
        return (MainRoute::Binary, None);
    }
    (MainRoute::Text, None)
}
fn inventory(
    root: &Path,
    commit: &str,
    policy: &ScopePolicy,
) -> Result<Vec<SourceLeaf>, SourceError> {
    let raw = git_bytes(root, &["ls-tree", "-r", "-z", "-l", "--full-tree", commit])?;
    let mut leaves = Vec::new();
    for record in raw.split(|b| *b == 0).filter(|b| !b.is_empty()) {
        let sep = record
            .iter()
            .position(|b| *b == b'\t')
            .ok_or_else(|| invalid("malformed tree entry"))?;
        let fields = std::str::from_utf8(&record[..sep])
            .map_err(|_| invalid("invalid tree header"))?
            .split_whitespace()
            .collect::<Vec<_>>();
        if fields.len() != 4 {
            return Err(invalid("malformed tree header"));
        }
        let path = std::str::from_utf8(&record[sep + 1..])
            .map_err(|_| invalid("non-UTF8 Git path: enumeration cannot be complete"))?
            .to_owned();
        validate_relative(&path)?;
        validate_oid(fields[2])?;
        let (mode, kind) = (fields[0], fields[1]);
        let bytes = if fields[3] == "-" {
            0
        } else {
            fields[3]
                .parse()
                .map_err(|_| invalid("tree size is invalid"))?
        };
        let (main_route, language) = route(&path, mode, kind);
        let (scope, matched_rule, rule_origin, scope_reason) = scope_rule(&path, policy);
        let mut l = SourceLeaf {
            path,
            mode: mode.into(),
            object_kind: kind.into(),
            git_oid: fields[2].into(),
            scope,
            matched_rule,
            rule_origin,
            scope_reason,
            capture: CaptureStatus::NotRequested,
            capture_reason: "scope_excluded".into(),
            text: TextStatus::NotRequested,
            text_reason: "scope_excluded".into(),
            semantic: SemanticStatus::NotRequested,
            semantic_reason: "scope_excluded".into(),
            main_route,
            language,
            byte_len: bytes,
            content_sha256: None,
            object_sha256: None,
            extracted_text_sha256: None,
            availability_reason: "scope_excluded".into(),
            oversized_streamed: false,
        };
        if scope == Scope::Included
            && matches!(
                main_route,
                MainRoute::Symlink | MainRoute::Gitlink | MainRoute::Unsupported
            )
        {
            l.capture = CaptureStatus::Unsupported;
            l.capture_reason = "non_regular_git_leaf".into();
            l.text = TextStatus::NotApplicable;
            l.text_reason = "non_regular_git_leaf".into();
            l.semantic = SemanticStatus::NotApplicable;
            l.semantic_reason = "non_regular_git_leaf".into();
            l.availability_reason = "non_regular_git_leaf_not_followed".into();
        }
        leaves.push(l);
    }
    leaves.sort_by(|a, b| a.path.cmp(&b.path));
    if leaves.windows(2).any(|p| p[0].path == p[1].path) {
        return Err(invalid("duplicate Git leaf"));
    }
    Ok(leaves)
}

/// Capture a complete exact-tree ledger. No worktree body or target program is read/executed.
pub fn capture(request: &SourceCaptureRequest) -> Result<SourceCoverageLedger, SourceError> {
    policy_valid(&request.policy)?;
    validate_oid(&request.source_commit)?;
    validate_oid(&request.expected_tree)?;
    if request.repository_id.is_empty() {
        return Err(invalid("repository ID missing"));
    }
    let source = real_directory(&request.source_root)?;
    let output = output_location(&request.output_path)?;
    if source.starts_with(&output) || output.starts_with(&source) {
        return Err(SourceError::UnsafePath("source/output overlap".into()));
    }
    let tree = String::from_utf8(git_bytes(
        &source,
        &["rev-parse", &format!("{}^{{tree}}", request.source_commit)],
    )?)
    .map_err(|_| invalid("tree ID is not UTF8"))?
    .trim()
    .to_owned();
    if tree != request.expected_tree {
        return Err(SourceError::IdentityMismatch(
            "expected tree differs from exact commit".into(),
        ));
    }
    if git_bytes(&source, &["cat-file", "-t", &request.source_commit])? != b"commit\n" {
        return Err(SourceError::IdentityMismatch(
            "source object is not a commit".into(),
        ));
    }
    let policy_sha256 = json_hash(&request.policy)?;
    let snapshot = snapshot_id(
        &request.repository_id,
        &request.source_commit,
        &tree,
        &policy_sha256,
    )?;
    fs::create_dir_all(&output)?;
    let archive = Archive::open(&output)?;
    let checkpoint = serde_json::json!({"schema_version":"gtkg.qk.source-checkpoint/v1","snapshot_id":snapshot,"source_commit":request.source_commit,"source_tree":tree,"policy_sha256":policy_sha256});
    if archive.exists("checkpoint.json")? {
        if archive.read("checkpoint.json")? != serde_json::to_vec(&checkpoint)? {
            return Err(SourceError::IdentityMismatch(
                "archive checkpoint belongs to different source/policy".into(),
            ));
        }
    } else {
        if fs::read_dir(&output)?.next().is_some() {
            return Err(invalid("nonempty archive has no identity checkpoint"));
        }
        archive.write_json("checkpoint.json", &checkpoint)?;
    }
    if archive.exists(LEDGER_FILE)? {
        let ledger = load_archive(&output)?;
        if ledger.snapshot_id != snapshot {
            return Err(SourceError::IdentityMismatch(
                "archive snapshot changed".into(),
            ));
        }
        return Ok(ledger);
    }
    let mut leaves = inventory(&source, &request.source_commit, &request.policy)?;
    let mut batch = BlobReader::new(&source)?;
    let mut blobs: BTreeMap<String, Blob> = BTreeMap::new();
    let mut objects: BTreeMap<String, ArchiveRef> = BTreeMap::new();
    for leaf in &mut leaves {
        if leaf.scope == Scope::Excluded
            || !matches!(
                leaf.main_route,
                MainRoute::Code | MainRoute::Text | MainRoute::Binary | MainRoute::Document
            )
        {
            continue;
        }
        let blob = if let Some(b) = blobs.get(&leaf.git_oid) {
            b.clone()
        } else {
            let b = batch.read(&leaf.git_oid, &archive)?;
            blobs.insert(leaf.git_oid.clone(), b.clone());
            b
        };
        if blob.bytes != leaf.byte_len {
            return Err(SourceError::IdentityMismatch(
                "blob size differs from exact tree".into(),
            ));
        }
        leaf.content_sha256 = Some(blob.digest.clone());
        leaf.capture = CaptureStatus::Captured;
        leaf.capture_reason = "exact_git_blob_read".into();
        leaf.oversized_streamed = blob.bytes > PAGE_BYTES;
        let is_text =
            blob.utf8_text && matches!(leaf.main_route, MainRoute::Code | MainRoute::Text);
        if is_text {
            leaf.text = TextStatus::Extracted;
            leaf.text_reason = "utf8_original_bytes".into();
            leaf.extracted_text_sha256 = Some(blob.digest.clone());
            leaf.semantic = if leaf.main_route == MainRoute::Code {
                SemanticStatus::NotRequested
            } else {
                SemanticStatus::NotApplicable
            };
            leaf.semantic_reason = if leaf.main_route == MainRoute::Code {
                "semantic_adapter_not_run"
            } else {
                "static_text_not_code"
            }
            .into();
        } else {
            leaf.text = if matches!(
                leaf.main_route,
                MainRoute::Code | MainRoute::Text | MainRoute::Document
            ) {
                TextStatus::Unsupported
            } else {
                TextStatus::NotApplicable
            };
            leaf.text_reason = if leaf.main_route == MainRoute::Document {
                "document_extractor_not_verified"
            } else {
                "non_utf8_or_binary_content"
            }
            .into();
            leaf.semantic = if leaf.main_route == MainRoute::Code {
                SemanticStatus::Unsupported
            } else {
                SemanticStatus::NotApplicable
            };
            leaf.semantic_reason = "text_unavailable_or_non_code".into();
            if leaf.main_route == MainRoute::Text {
                leaf.main_route = MainRoute::Binary;
            }
        }
        if is_text || request.policy.archive_binary {
            let object_path = format!("objects/{}", blob.digest);
            if !objects.contains_key(&blob.digest) {
                if archive.exists(&blob.temp)? {
                    archive.commit_temp(&blob.temp, &object_path, &blob.digest)?;
                } else if archive.file_digest(&object_path)? != (blob.digest.clone(), blob.bytes) {
                    return Err(invalid("cached object changed"));
                }
                objects.insert(
                    blob.digest.clone(),
                    ArchiveRef {
                        path: object_path,
                        bytes: blob.bytes,
                        sha256: blob.digest.clone(),
                    },
                );
            }
            leaf.object_sha256 = Some(blob.digest.clone());
            leaf.availability_reason = "archived_content_addressed_bytes".into();
        } else {
            leaf.availability_reason = "non_text_bytes_not_archived_by_policy".into();
        }
    }
    batch.finish()?;
    for blob in blobs.values() {
        if archive.exists(&blob.temp)? {
            archive.remove_temp(&blob.temp)?;
        }
    }
    let selected: Vec<&SourceLeaf> = leaves
        .iter()
        .filter(|l| l.scope == Scope::Included)
        .collect();
    let paths: Vec<String> = selected.iter().map(|l| l.path.clone()).collect();
    let mut groups: Vec<Vec<&SourceLeaf>> = Vec::new();
    let mut group = Vec::new();
    let mut size = 0u64;
    for leaf in selected {
        if !group.is_empty()
            && (group.len() >= PAGE_FILES || size.saturating_add(leaf.byte_len) > PAGE_BYTES)
        {
            groups.push(std::mem::take(&mut group));
            size = 0;
        }
        size += leaf.byte_len;
        group.push(leaf);
        if leaf.byte_len > PAGE_BYTES {
            groups.push(std::mem::take(&mut group));
            size = 0;
        }
    }
    if !group.is_empty() {
        groups.push(group);
    }
    let total_pages = groups.len();
    let mut pages = Vec::new();
    for (index, group) in groups.into_iter().enumerate() {
        let page_paths: Vec<String> = group.iter().map(|l| l.path.clone()).collect();
        let bytes = group.iter().map(|l| l.byte_len).sum();
        let page = SelectionPage {
            schema_version: PAGE_SCHEMA.into(),
            snapshot_id: snapshot.clone(),
            policy_sha256: policy_sha256.clone(),
            page_index: index,
            total_pages,
            total_files: paths.len(),
            files_sha256: json_hash(&page_paths)?,
            paths: page_paths,
            source_bytes: bytes,
            oversized_streamed: bytes > PAGE_BYTES,
        };
        pages.push(archive.write_json(&format!("pages/{index:06}.json"), &page)?);
    }
    let selection = AnalysisSelectionManifest {
        schema_version: SELECTION_SCHEMA.into(),
        snapshot_id: snapshot.clone(),
        policy_sha256: policy_sha256.clone(),
        total_files: paths.len(),
        files_sha256: json_hash(&paths)?,
        pages,
    };
    let object_manifest = SourceObjectManifest {
        schema_version: OBJECT_SCHEMA.into(),
        snapshot_id: snapshot.clone(),
        objects: objects.into_values().collect(),
    };
    let ledger = SourceCoverageLedger {
        schema_version: LEDGER_SCHEMA.into(),
        repository_id: request.repository_id.clone(),
        source_commit: request.source_commit.clone(),
        source_tree: tree,
        policy: request.policy.clone(),
        policy_sha256,
        snapshot_id: snapshot,
        leaves_sha256: json_hash(&leaves)?,
        leaves,
        selection_manifest: archive.write_json("analysis-selection-manifest.json", &selection)?,
        object_manifest: archive.write_json("source-object-manifest.json", &object_manifest)?,
    };
    // Publish the root last. Incomplete attempts retain the same checkpoint and immutable files.
    let bytes = serde_json::to_vec(&ledger)?;
    archive.write("source-coverage-ledger.sha256", hash(&bytes).as_bytes())?;
    archive.write(LEDGER_FILE, &bytes)?;
    load_archive(&output)
}

/// Verify a sealed archive without touching the original repository.
pub fn load_archive(root: &Path) -> Result<SourceCoverageLedger, SourceError> {
    let a = Archive::open(root)?;
    let raw = a.read(LEDGER_FILE)?;
    if a.read("source-coverage-ledger.sha256")? != hash(&raw).as_bytes() {
        return Err(invalid("ledger digest mismatch"));
    }
    let l: SourceCoverageLedger = serde_json::from_slice(&raw)?;
    policy_valid(&l.policy)?;
    validate_oid(&l.source_commit)?;
    validate_oid(&l.source_tree)?;
    if l.schema_version != LEDGER_SCHEMA
        || json_hash(&l.policy)? != l.policy_sha256
        || snapshot_id(
            &l.repository_id,
            &l.source_commit,
            &l.source_tree,
            &l.policy_sha256,
        )? != l.snapshot_id
        || json_hash(&l.leaves)? != l.leaves_sha256
    {
        return Err(invalid("ledger identity/set digest mismatch"));
    }
    let checkpoint: serde_json::Value = serde_json::from_slice(&a.read("checkpoint.json")?)?;
    if checkpoint["snapshot_id"] != l.snapshot_id {
        return Err(invalid("checkpoint snapshot differs"));
    }
    let mut path_map = BTreeMap::new();
    let mut selected = Vec::new();
    let mut expected_objects = BTreeMap::new();
    for leaf in &l.leaves {
        validate_relative(&leaf.path)?;
        validate_oid(&leaf.git_oid)?;
        if path_map.insert(leaf.path.clone(), leaf).is_some() {
            return Err(invalid("duplicate leaf"));
        }
        let (scope, id, origin, reason) = scope_rule(&leaf.path, &l.policy);
        if leaf.scope != scope
            || leaf.matched_rule != id
            || leaf.rule_origin != origin
            || leaf.scope_reason != reason
            || leaf.capture_reason.is_empty()
            || leaf.text_reason.is_empty()
            || leaf.semantic_reason.is_empty()
            || leaf.availability_reason.is_empty()
        {
            return Err(invalid("scope or stage explanation mismatch"));
        }
        if scope == Scope::Included {
            selected.push(leaf.path.clone());
        } else if leaf.capture != CaptureStatus::NotRequested
            || leaf.text != TextStatus::NotRequested
            || leaf.semantic != SemanticStatus::NotRequested
            || leaf.object_sha256.is_some()
        {
            return Err(invalid("excluded leaf has requested stages"));
        }
        if let Some(digest) = &leaf.object_sha256 {
            if leaf.content_sha256.as_ref() != Some(digest) || !valid_hex(digest, 64) {
                return Err(invalid("body identity mismatch"));
            }
            if let Some(old) = expected_objects.insert(digest.clone(), leaf.byte_len)
                && old != leaf.byte_len
            {
                return Err(invalid("same object has inconsistent size"));
            }
        }
        if leaf.text == TextStatus::Extracted
            && (leaf.extracted_text_sha256 != leaf.content_sha256 || leaf.object_sha256.is_none())
        {
            return Err(invalid("extracted text missing archived content"));
        }
    }
    if l.leaves.windows(2).any(|pair| pair[0].path >= pair[1].path) {
        return Err(invalid("ledger not in canonical path order"));
    }
    let m: AnalysisSelectionManifest = serde_json::from_slice(&a.read_ref(&l.selection_manifest)?)?;
    if m.schema_version != SELECTION_SCHEMA
        || m.snapshot_id != l.snapshot_id
        || m.policy_sha256 != l.policy_sha256
        || m.total_files != selected.len()
        || m.files_sha256 != json_hash(&selected)?
    {
        return Err(invalid("selection identity/set mismatch"));
    }
    let mut seen_refs = BTreeSet::new();
    let mut all = Vec::new();
    for (index, r) in m.pages.iter().enumerate() {
        if r.path != format!("pages/{index:06}.json") || !seen_refs.insert(&r.path) {
            return Err(invalid("page order/duplicate mismatch"));
        }
        let p: SelectionPage = serde_json::from_slice(&a.read_ref(r)?)?;
        if p.schema_version != PAGE_SCHEMA
            || p.snapshot_id != l.snapshot_id
            || p.policy_sha256 != l.policy_sha256
            || p.page_index != index
            || p.total_pages != m.pages.len()
            || p.total_files != m.total_files
            || p.paths.is_empty()
            || p.paths.len() > PAGE_FILES
            || p.files_sha256 != json_hash(&p.paths)?
        {
            return Err(invalid("page identity/budget mismatch"));
        }
        let mut bytes = 0u64;
        for path in &p.paths {
            let leaf = path_map
                .get(path)
                .ok_or_else(|| invalid("page contains unknown leaf"))?;
            bytes = bytes
                .checked_add(leaf.byte_len)
                .ok_or_else(|| invalid("page byte count overflow"))?;
        }
        if bytes != p.source_bytes
            || p.oversized_streamed != (bytes > PAGE_BYTES)
            || (bytes > PAGE_BYTES && p.paths.len() != 1)
        {
            return Err(invalid("page byte budget mismatch"));
        }
        all.extend(p.paths);
    }
    if all != selected {
        return Err(invalid("missing, duplicate or out-of-order selected paths"));
    }
    let objects: SourceObjectManifest = serde_json::from_slice(&a.read_ref(&l.object_manifest)?)?;
    if objects.schema_version != OBJECT_SCHEMA || objects.snapshot_id != l.snapshot_id {
        return Err(invalid("object manifest identity mismatch"));
    }
    let mut actual_objects = BTreeMap::new();
    for r in &objects.objects {
        if r.path != format!("objects/{}", r.sha256)
            || !valid_hex(&r.sha256, 64)
            || actual_objects.insert(r.sha256.clone(), r.bytes).is_some()
        {
            return Err(invalid("invalid/duplicate object reference"));
        }
        if a.file_digest(&r.path)? != (r.sha256.clone(), r.bytes) {
            return Err(invalid("archived object digest mismatch"));
        }
    }
    if actual_objects != expected_objects {
        return Err(invalid("object manifest exact set mismatch"));
    }
    Ok(l)
}
/// Read original archived bytes; a missing body stays source-unavailable, never a metadata fallback.
pub fn read_object(root: &Path, digest: &str) -> Result<Vec<u8>, SourceError> {
    if !valid_hex(digest, 64) {
        return Err(SourceError::UnsafePath(
            "object digest must be lowercase SHA256".into(),
        ));
    }
    let a = Archive::open(root)?;
    let bytes = a.read(&format!("objects/{digest}"))?;
    if hash(&bytes) != digest {
        return Err(invalid("archived object digest mismatch"));
    }
    Ok(bytes)
}

/// Reuse the pinned-directory, no-replace byte writer for Core-owned OKF artifacts.
pub(crate) fn write_workspace_object(
    root: &Path,
    relative: &str,
    bytes: &[u8],
) -> Result<ArchiveRef, SourceError> {
    if !relative.starts_with(".gtkg/qk/") {
        return Err(invalid("QK object must remain under .gtkg/qk"));
    }
    Archive::open(root)?.write(relative, bytes)
}
