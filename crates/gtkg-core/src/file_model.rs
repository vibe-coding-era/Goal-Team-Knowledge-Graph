use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use walkdir::WalkDir;

const INDEX_FILE: &str = "index.md";
const INDEX_SIDECAR_FILE: &str = "index.gtkg.json";
const INDEX_SIDECAR_SCHEMA: &str = "gtkg.index-sidecar/v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IndexEntry {
    pub path: String,
    pub kind: IndexEntryKind,
    pub sha256: String,
    pub bytes: u64,
    pub load_level: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IndexEntryKind {
    File,
    Directory,
}

/// Machine metadata for a directory index (digest/bytes/load-level exact
/// set). Written as the sibling `index.gtkg.json` sidecar so `index.md`
/// stays a pure SPEC §8 markdown-links document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IndexSidecar {
    pub schema_version: String,
    pub title: String,
    pub load_level: String,
    pub entries: Vec<IndexEntry>,
}

#[derive(Debug, Error)]
pub enum FileModelError {
    #[error("file operation failed at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("walk failed: {0}")]
    Walk(#[from] walkdir::Error),
    #[error("invalid OKF index: {0}")]
    Okf(#[from] crate::okf::OkfError),
    #[error("invalid index sidecar JSON: {0}")]
    IndexJson(#[from] serde_json::Error),
    #[error("directory is missing its index file: {0}")]
    MissingIndex(PathBuf),
    #[error("index closure mismatch in {path}; expected {expected:?}, observed {observed:?}")]
    ClosureMismatch {
        path: PathBuf,
        expected: Vec<String>,
        observed: Vec<String>,
    },
    #[error("duplicate index entry in {path}: {entry}")]
    DuplicateEntry { path: PathBuf, entry: String },
    #[error("index digest mismatch for {0}")]
    DigestMismatch(PathBuf),
    #[error("symbolic links are not allowed in canonical trees: {0}")]
    Symlink(PathBuf),
    #[error("hard links are not allowed in canonical trees: {0}")]
    Hardlink(PathBuf),
    #[error("published version is immutable: {0}")]
    VersionImmutable(String),
    #[error("unsafe version label: {0}")]
    UnsafeVersion(String),
    #[error("path has no UTF-8 file name: {0}")]
    NonUtf8Path(PathBuf),
}

pub fn write_index_tree(root: &Path) -> Result<(), FileModelError> {
    if !root.is_dir() {
        return Err(io_error(
            root,
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "index root is not a directory",
            ),
        ));
    }
    write_directory_index(root, root)
}

fn write_directory_index(root: &Path, directory: &Path) -> Result<(), FileModelError> {
    let mut children = read_children(directory)?;
    children.sort();
    for child in &children {
        let metadata = fs::symlink_metadata(child).map_err(|source| io_error(child, source))?;
        if metadata.file_type().is_symlink() {
            return Err(FileModelError::Symlink(child.clone()));
        }
        reject_hardlink(child, &metadata)?;
        if metadata.is_dir() {
            write_directory_index(root, child)?;
        }
    }

    let entries = build_index_entries(&children)?;
    let (document, sidecar) = render_index_documents(root, directory, &entries)?;
    let index_path = directory.join(INDEX_FILE);
    fs::write(&index_path, document).map_err(|source| io_error(&index_path, source))?;
    let sidecar_path = directory.join(INDEX_SIDECAR_FILE);
    fs::write(&sidecar_path, sidecar).map_err(|source| io_error(&sidecar_path, source))
}

pub fn validate_index_tree(root: &Path) -> Result<(), FileModelError> {
    for entry in WalkDir::new(root).follow_links(false).sort_by_file_name() {
        let entry = entry?;
        if entry.file_type().is_symlink() {
            return Err(FileModelError::Symlink(entry.path().to_path_buf()));
        }
        reject_hardlink(entry.path(), &entry.metadata()?)?;
        if entry.file_type().is_dir() {
            validate_directory_index(root, entry.path())?;
        }
    }
    Ok(())
}

fn validate_directory_index(root: &Path, directory: &Path) -> Result<(), FileModelError> {
    let index_path = directory.join(INDEX_FILE);
    if !index_path.is_file() {
        return Err(FileModelError::MissingIndex(index_path));
    }
    let sidecar_path = directory.join(INDEX_SIDECAR_FILE);
    if !sidecar_path.is_file() {
        return Err(FileModelError::MissingIndex(sidecar_path));
    }
    let source = fs::read_to_string(&index_path).map_err(|source| io_error(&index_path, source))?;
    let sidecar_source =
        fs::read_to_string(&sidecar_path).map_err(|source| io_error(&sidecar_path, source))?;
    let sidecar: IndexSidecar = serde_json::from_str(&sidecar_source)?;
    if sidecar.schema_version != INDEX_SIDECAR_SCHEMA {
        return Err(FileModelError::ClosureMismatch {
            path: directory.to_path_buf(),
            expected: vec![INDEX_SIDECAR_SCHEMA.to_owned()],
            observed: vec![sidecar.schema_version.clone()],
        });
    }
    let entries = sidecar.entries;
    let mut observed = BTreeMap::new();
    for entry in &entries {
        if observed.insert(entry.path.clone(), entry).is_some() {
            return Err(FileModelError::DuplicateEntry {
                path: directory.to_path_buf(),
                entry: entry.path.clone(),
            });
        }
    }
    let mut children = read_children(directory)?;
    children.sort();
    let expected_entries = build_index_entries(&children)?;
    let expected: BTreeSet<String> = expected_entries
        .iter()
        .map(|entry| entry.path.clone())
        .collect();
    let observed_set: BTreeSet<String> = observed.keys().cloned().collect();
    if expected != observed_set {
        return Err(FileModelError::ClosureMismatch {
            path: directory.to_path_buf(),
            expected: expected.into_iter().collect(),
            observed: observed_set.into_iter().collect(),
        });
    }
    if entries != expected_entries {
        return Err(FileModelError::ClosureMismatch {
            path: directory.to_path_buf(),
            expected: expected_entries
                .iter()
                .map(|entry| format!("{entry:?}"))
                .collect(),
            observed: entries.iter().map(|entry| format!("{entry:?}")).collect(),
        });
    }
    let (expected_document, expected_sidecar) =
        render_index_documents(root, directory, &expected_entries)?;
    if source != expected_document {
        return Err(FileModelError::ClosureMismatch {
            path: index_path,
            expected: vec!["deterministically rendered index".to_owned()],
            observed: vec!["index bytes differ".to_owned()],
        });
    }
    if sidecar_source != expected_sidecar {
        return Err(FileModelError::ClosureMismatch {
            path: sidecar_path,
            expected: vec!["deterministically rendered index sidecar".to_owned()],
            observed: vec!["index sidecar bytes differ".to_owned()],
        });
    }
    Ok(())
}

fn build_index_entries(children: &[PathBuf]) -> Result<Vec<IndexEntry>, FileModelError> {
    let mut entries = Vec::new();
    for child in children {
        if matches!(
            child.file_name().and_then(|name| name.to_str()),
            Some(INDEX_FILE | INDEX_SIDECAR_FILE)
        ) {
            continue;
        }
        let metadata = fs::symlink_metadata(child).map_err(|source| io_error(child, source))?;
        if metadata.file_type().is_symlink() {
            return Err(FileModelError::Symlink(child.clone()));
        }
        reject_hardlink(child, &metadata)?;
        let name = child
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| FileModelError::NonUtf8Path(child.clone()))?
            .to_owned();
        let (kind, digest_path, bytes, load_level) = if metadata.is_dir() {
            let index = child.join(INDEX_FILE);
            let index_metadata = fs::metadata(&index).map_err(|source| io_error(&index, source))?;
            (
                IndexEntryKind::Directory,
                index,
                index_metadata.len(),
                "L1".to_owned(),
            )
        } else if metadata.is_file() {
            (
                IndexEntryKind::File,
                child.clone(),
                metadata.len(),
                "L2".to_owned(),
            )
        } else {
            return Err(io_error(
                child,
                std::io::Error::new(std::io::ErrorKind::InvalidData, "unsupported file type"),
            ));
        };
        entries.push(IndexEntry {
            path: name,
            kind,
            sha256: sha256_file(&digest_path)?,
            bytes,
            load_level,
        });
    }
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(entries)
}

fn index_title(root: &Path, directory: &Path) -> String {
    directory
        .strip_prefix(root)
        .ok()
        .filter(|path| !path.as_os_str().is_empty())
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_else(|| "root".to_owned())
}

pub fn publish_immutable_version(
    staging: &Path,
    versions_root: &Path,
    version: &str,
) -> Result<PathBuf, FileModelError> {
    validate_version(version)?;
    validate_index_tree(staging)?;
    let digest = tree_sha256(staging)?;
    fs::create_dir_all(versions_root).map_err(|source| io_error(versions_root, source))?;
    let prefix = format!("v{version}--");
    for entry in fs::read_dir(versions_root).map_err(|source| io_error(versions_root, source))? {
        let entry = entry.map_err(|source| io_error(versions_root, source))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with(&prefix) {
            if name == format!("{prefix}{}", &digest[7..19]) {
                return Ok(entry.path());
            }
            return Err(FileModelError::VersionImmutable(version.to_owned()));
        }
    }
    let target = versions_root.join(format!("{prefix}{}", &digest[7..19]));
    fs::rename(staging, &target).map_err(|source| io_error(&target, source))?;
    Ok(target)
}

pub fn tree_sha256(root: &Path) -> Result<String, FileModelError> {
    let mut hasher = Sha256::new();
    for entry in WalkDir::new(root).follow_links(false).sort_by_file_name() {
        let entry = entry?;
        if entry.file_type().is_symlink() {
            return Err(FileModelError::Symlink(entry.path().to_path_buf()));
        }
        reject_hardlink(entry.path(), &entry.metadata()?)?;
        if !entry.file_type().is_file() {
            continue;
        }
        let relative = entry
            .path()
            .strip_prefix(root)
            .map_err(|_| FileModelError::DigestMismatch(entry.path().to_path_buf()))?;
        hasher.update(relative.to_string_lossy().as_bytes());
        hasher.update([0]);
        let mut file =
            fs::File::open(entry.path()).map_err(|source| io_error(entry.path(), source))?;
        let mut buffer = [0_u8; 16 * 1024];
        loop {
            let count = file
                .read(&mut buffer)
                .map_err(|source| io_error(entry.path(), source))?;
            if count == 0 {
                break;
            }
            hasher.update(&buffer[..count]);
        }
        hasher.update([0xff]);
    }
    Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
}

fn reject_hardlink(path: &Path, metadata: &fs::Metadata) -> Result<(), FileModelError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.is_file() && metadata.nlink() > 1 {
            return Err(FileModelError::Hardlink(path.to_path_buf()));
        }
    }
    Ok(())
}

pub fn sha256_file(path: &Path) -> Result<String, FileModelError> {
    let bytes = fs::read(path).map_err(|source| io_error(path, source))?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
}

fn read_children(directory: &Path) -> Result<Vec<PathBuf>, FileModelError> {
    fs::read_dir(directory)
        .map_err(|source| io_error(directory, source))?
        .map(|entry| {
            entry
                .map(|entry| entry.path())
                .map_err(|source| io_error(directory, source))
        })
        .collect()
}

/// Renders the deterministic pair for one directory: a SPEC §8 `index.md`
/// (markdown links only; the bundle root additionally carries the SPEC §12
/// `okf_version` frontmatter) and the `index.gtkg.json` sidecar holding the
/// machine metadata (exact-set digests, bytes, load levels).
fn render_index_documents(
    root: &Path,
    directory: &Path,
    entries: &[IndexEntry],
) -> Result<(String, String), FileModelError> {
    let title = index_title(root, directory);
    let mut document = String::new();
    if directory == root {
        document.push_str("---\nokf_version: \"0.2\"\n---\n\n");
    }
    document.push_str(&format!("# Index: {title}\n"));
    if !entries.is_empty() {
        document.push('\n');
        for entry in entries {
            match entry.kind {
                IndexEntryKind::Directory => {
                    document.push_str(&format!("* [{0}]({0}/)\n", entry.path));
                }
                IndexEntryKind::File => {
                    document.push_str(&format!("* [{0}]({0})\n", entry.path));
                }
            }
        }
    }
    let sidecar = IndexSidecar {
        schema_version: INDEX_SIDECAR_SCHEMA.to_owned(),
        title,
        load_level: "L0".to_owned(),
        entries: entries.to_vec(),
    };
    let mut sidecar_json = serde_json::to_string_pretty(&sidecar)?;
    sidecar_json.push('\n');
    Ok((document, sidecar_json))
}

fn validate_version(version: &str) -> Result<(), FileModelError> {
    let lower = version.to_ascii_lowercase();
    if version.is_empty()
        || matches!(lower.as_str(), "current" | "latest" | "head" | "main")
        || version.contains('/')
        || version.contains("..")
        || !version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        return Err(FileModelError::UnsafeVersion(version.to_owned()));
    }
    Ok(())
}

fn io_error(path: &Path, source: std::io::Error) -> FileModelError {
    FileModelError::Io {
        path: path.to_path_buf(),
        source,
    }
}
