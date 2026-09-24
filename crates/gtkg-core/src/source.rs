//! Read-only Git-object source inventory and content-addressed inspection receipts.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

use gtkg_extract::is_supported_path;
use gtkg_protocol::{
    ErrorCode, FileReceiptRef, GitObjectId, OperationRequest, OperationResponse,
    RepositoryIdentity, SourceKey, SourceLock, SourceManifestEntry, SubmoduleIdentity,
    canonical_json_sha256, validate_sha256,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::durable::{DurableErrorKind, DurableWriteError, publish_immutable_json};
use crate::file_model::sha256_file;

const RECEIPT_SCHEMA: &str = "gtkg.source-inspection-receipt/v1";

#[derive(Debug)]
pub struct SourceFailure {
    pub code: ErrorCode,
    pub stage: &'static str,
    pub message: String,
    pub recovery_hint: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceCheckout {
    pub repo_id: String,
    pub canonical_root: PathBuf,
    pub role: String,
    pub include: Vec<String>,
    #[serde(default)]
    pub exclude: Vec<String>,
}

/// Explicit record of a tracked file that inspection refused to admit. Omissions
/// are evidence: nothing is ever skipped silently.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceOmission {
    pub repo_id: String,
    pub logical_path: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceInspectionReceipt {
    pub schema_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_sha256: Option<String>,
    pub source_lock_sha256: String,
    pub source_lock: SourceLock,
    pub checkouts: Vec<SourceCheckout>,
    pub omissions: Vec<SourceOmission>,
}

#[derive(Debug, Clone)]
pub struct VerifiedSourceInspection {
    pub source_lock: SourceLock,
    pub repo_roots: BTreeMap<String, PathBuf>,
    pub receipt_sha256: String,
    pub omissions: Vec<SourceOmission>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InspectPayload {
    workspace_root: PathBuf,
    repositories: Vec<RepositoryInput>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RepositoryInput {
    repo_id: String,
    path: PathBuf,
    #[serde(default = "default_role")]
    role: String,
    #[serde(default)]
    include: Vec<String>,
    #[serde(default)]
    exclude: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GitReadback {
    head: GitObjectId,
    tree: GitObjectId,
    status: Vec<u8>,
}

struct InspectedRepository {
    identity: RepositoryIdentity,
    checkout: SourceCheckout,
    entries: Vec<SourceManifestEntry>,
    omissions: Vec<SourceOmission>,
}

pub fn inspect(
    context: &crate::CallContext,
    request: &OperationRequest,
) -> Result<OperationResponse, SourceFailure> {
    let payload: InspectPayload =
        serde_json::from_value(request.payload.clone()).map_err(|error| {
            failure(
                ErrorCode::InvalidRequest,
                format!("invalid source.inspect payload: {error}"),
            )
        })?;
    // V1 has one frozen input schema: workspace_root plus repositories. The
    // earlier config-file branch could never be admitted by that schema and
    // therefore belonged to neither public version. V2 owns any future
    // config-bound source capture contract under a distinct operation id.
    //
    // `config_sha256` is the documented vestige of that branch: the receipt field
    // and its validator are retained only so already-published receipts keep their
    // frozen shape. It is always None here, and `gtkg.config/v2` repositories are
    // consumed by `config.validate` alone - nothing in the capture or build
    // pipeline reads them. Wiring them is a contract change, not a repair.
    let workspace_root = payload.workspace_root;
    let repository_inputs = payload.repositories;
    let config_sha256 = None;
    let workspace_root = context
        .authorize_write(&workspace_root)
        .map_err(context_failure)?;
    fs::create_dir_all(&workspace_root).map_err(|error| io_failure(&workspace_root, error))?;
    validate_workspace_root(&workspace_root)?;
    if repository_inputs.is_empty() {
        return Err(failure(
            ErrorCode::InvalidRequest,
            "source.inspect requires at least one repository",
        ));
    }

    let mut seen_ids = BTreeSet::new();
    let mut repositories = Vec::new();
    let mut entries = Vec::new();
    let mut checkouts = Vec::new();
    let mut omissions = Vec::new();
    for input in &repository_inputs {
        if !seen_ids.insert(input.repo_id.as_str()) {
            return Err(failure(
                ErrorCode::InvalidRequest,
                format!("duplicate repo_id: {}", input.repo_id),
            ));
        }
        let mut authorized_input = input.clone();
        authorized_input.path = context
            .authorize_read(&input.path)
            .map_err(context_failure)?;
        let inspected = inspect_repository(context, &authorized_input)?;
        repositories.push(inspected.identity);
        entries.extend(inspected.entries);
        checkouts.push(inspected.checkout);
        omissions.extend(inspected.omissions);
    }
    repositories.sort_by(|left, right| left.repo_id.cmp(&right.repo_id));
    entries.sort_by(|left, right| {
        (&left.repo_id, &left.logical_path).cmp(&(&right.repo_id, &right.logical_path))
    });
    checkouts.sort_by(|left, right| left.repo_id.cmp(&right.repo_id));
    omissions.sort();
    let source_lock = SourceLock {
        schema_version: "gtkg.source-lock/v1".to_owned(),
        repositories,
        entries,
    };
    source_lock.validate().map_err(|error| {
        failure(
            ErrorCode::LockMismatch,
            format!("generated SourceLock is invalid: {error}"),
        )
    })?;
    let source_lock_sha256 = canonical_json_sha256(&source_lock)
        .map_err(|error| failure(ErrorCode::InvalidRequest, error.to_string()))?;
    let receipt = SourceInspectionReceipt {
        schema_version: RECEIPT_SCHEMA.to_owned(),
        config_sha256: config_sha256.clone(),
        source_lock_sha256: source_lock_sha256.clone(),
        source_lock: source_lock.clone(),
        checkouts,
        omissions: omissions.clone(),
    };
    let identity = canonical_json_sha256(&receipt)
        .map_err(|error| failure(ErrorCode::InvalidRequest, error.to_string()))?;
    let inspection_id = format!("inspect-{}", &identity[7..31]);
    let receipt_path = workspace_root
        .join(".gtkg/inspections")
        .join(&inspection_id)
        .join("inspection-receipt.json");
    let receipt_path = context
        .authorize_write(&receipt_path)
        .map_err(context_failure)?;
    let receipt_path = write_immutable_json(context, &receipt_path, &receipt)?;
    let relative_path = receipt_path
        .strip_prefix(
            context
                .workspace_root()
                .ok_or_else(|| context_failure(crate::ContextError::MissingRoot))?,
        )
        .map_err(|_| {
            failure_at(
                "source.receipt",
                ErrorCode::PathEscape,
                "inspection receipt is outside the context workspace",
            )
        })?
        .to_string_lossy()
        .into_owned();
    let receipt_ref = FileReceiptRef {
        path: relative_path,
        sha256: sha256_file(&receipt_path).map_err(|error| io_failure(&receipt_path, error))?,
    };
    let mut response = OperationResponse::completed(
        request,
        json!({
            "inspection_id": inspection_id,
            "inspection_ref": receipt_ref,
            "source_inspection_ref": receipt_ref,
            "source_lock_digest": source_lock_sha256,
            "source_lock": source_lock,
            "config_sha256": config_sha256,
            "omission_count": omissions.len(),
            "omissions": omissions,
        }),
    );
    response.run_id = Some(inspection_id);
    response.evidence_refs = vec![receipt_path.to_string_lossy().into_owned()];
    Ok(response)
}

/// Resolves a workspace-relative receipt, verifies its digest, and repeats Git inspection.
pub fn load_and_revalidate(
    context: &crate::CallContext,
    workspace_root: &Path,
    reference: &FileReceiptRef,
) -> Result<VerifiedSourceInspection, SourceFailure> {
    reference.validate().map_err(|error| {
        failure_at("source.receipt", ErrorCode::LockMismatch, error.to_string())
    })?;
    let path = context
        .resolve_workspace_receipt(workspace_root, reference)
        .map_err(context_failure)?;
    load_and_revalidate_path(context, &path, &reference.sha256)
}

pub fn load_and_revalidate_path(
    context: &crate::CallContext,
    path: &Path,
    expected_sha256: &str,
) -> Result<VerifiedSourceInspection, SourceFailure> {
    let observed = sha256_file(path).map_err(|error| io_failure(path, error))?;
    if observed != expected_sha256 {
        return Err(failure_at(
            "source.receipt",
            ErrorCode::LockMismatch,
            format!("inspection receipt digest mismatch: {}", path.display()),
        ));
    }
    let receipt: SourceInspectionReceipt = serde_json::from_slice(
        &fs::read(path).map_err(|error| io_failure(path, error))?,
    )
    .map_err(|error| {
        failure_at(
            "source.receipt",
            ErrorCode::LockMismatch,
            format!("invalid inspection receipt: {error}"),
        )
    })?;
    if let Some(config_sha256) = &receipt.config_sha256 {
        validate_sha256(config_sha256).map_err(|error| {
            failure_at(
                "source.receipt",
                ErrorCode::LockMismatch,
                format!("invalid receipt config digest: {error}"),
            )
        })?;
    }
    validate_receipt_path(path, &receipt)?;
    receipt.source_lock.validate().map_err(|error| {
        failure_at(
            "source.receipt",
            ErrorCode::LockMismatch,
            format!("invalid receipt SourceLock: {error}"),
        )
    })?;
    if canonical_json_sha256(&receipt.source_lock).ok().as_deref()
        != Some(&receipt.source_lock_sha256)
    {
        return Err(failure_at(
            "source.receipt",
            ErrorCode::LockMismatch,
            "inspection receipt SourceLock digest mismatch",
        ));
    }

    let mut repositories = Vec::new();
    let mut entries = Vec::new();
    let mut omissions = Vec::new();
    let mut repo_roots = BTreeMap::new();
    for checkout in &receipt.checkouts {
        if repo_roots
            .insert(checkout.repo_id.clone(), checkout.canonical_root.clone())
            .is_some()
        {
            return Err(failure_at(
                "source.receipt",
                ErrorCode::LockMismatch,
                format!("duplicate checkout repo_id: {}", checkout.repo_id),
            ));
        }
        let current = inspect_repository(
            context,
            &RepositoryInput {
                repo_id: checkout.repo_id.clone(),
                path: checkout.canonical_root.clone(),
                role: checkout.role.clone(),
                include: checkout.include.clone(),
                exclude: checkout.exclude.clone(),
            },
        )?;
        if current.checkout != *checkout {
            return Err(failure_at(
                "source.receipt",
                ErrorCode::LockMismatch,
                format!("checkout scope drift: {}", checkout.repo_id),
            ));
        }
        repositories.push(current.identity);
        entries.extend(current.entries);
        omissions.extend(current.omissions);
    }
    repositories.sort_by(|left, right| left.repo_id.cmp(&right.repo_id));
    entries.sort_by(|left, right| {
        (&left.repo_id, &left.logical_path).cmp(&(&right.repo_id, &right.logical_path))
    });
    omissions.sort();
    if repositories != receipt.source_lock.repositories || entries != receipt.source_lock.entries {
        return Err(failure_at(
            "source.receipt",
            ErrorCode::LockMismatch,
            "current Git objects do not match the inspection receipt",
        ));
    }
    if omissions != receipt.omissions {
        return Err(failure_at(
            "source.receipt",
            ErrorCode::LockMismatch,
            "current Git objects drifted from the receipt omission set",
        ));
    }
    Ok(VerifiedSourceInspection {
        source_lock: receipt.source_lock,
        repo_roots,
        receipt_sha256: observed,
        omissions,
    })
}

/// Reads a regular blob from the locked commit object, never the mutable worktree.
pub fn read_locked_blob(
    verified: &VerifiedSourceInspection,
    key: &SourceKey,
) -> Result<Vec<u8>, SourceFailure> {
    key.validate()
        .map_err(|error| failure_at("source.read", ErrorCode::LockMismatch, error.to_string()))?;
    let entry = verified
        .source_lock
        .entries
        .iter()
        .find(|entry| entry.repo_id == key.repo_id && entry.logical_path == key.logical_path)
        .ok_or_else(|| {
            failure_at(
                "source.read",
                ErrorCode::LockMismatch,
                format!("source is not locked: {}:{}", key.repo_id, key.logical_path),
            )
        })?;
    let repository = verified
        .source_lock
        .repositories
        .iter()
        .find(|repository| repository.repo_id == key.repo_id)
        .ok_or_else(|| failure(ErrorCode::LockMismatch, "locked repository is missing"))?;
    let root = verified.repo_roots.get(&key.repo_id).ok_or_else(|| {
        failure(
            ErrorCode::LockMismatch,
            "verified repository root is missing",
        )
    })?;
    let oid = tree_blob_oid(root, &repository.commit.value, &key.logical_path)?;
    let bytes = git_bytes(root, &["cat-file", "blob", &oid])?;
    if bytes.len() as u64 != entry.bytes || sha256_bytes(&bytes) != entry.content_sha256 {
        return Err(failure_at(
            "source.read",
            ErrorCode::LockMismatch,
            format!(
                "locked Git blob digest mismatch: {}:{}",
                key.repo_id, key.logical_path
            ),
        ));
    }
    Ok(bytes)
}

fn inspect_repository(
    context: &crate::CallContext,
    input: &RepositoryInput,
) -> Result<InspectedRepository, SourceFailure> {
    validate_identifier("repo_id", &input.repo_id)?;
    validate_identifier("role", &input.role)?;
    let mut include = input.include.clone();
    for prefix in &include {
        validate_relative(prefix.trim_end_matches('/'))?;
    }
    include.sort();
    include.dedup();
    let mut exclude = input.exclude.clone();
    for prefix in &exclude {
        validate_relative(prefix.trim_end_matches('/'))?;
    }
    exclude.sort();
    exclude.dedup();
    preauthorize_git_marker(context, &input.path)?;
    let root = git_root(&input.path)?;
    let root = context.authorize_read(&root).map_err(context_failure)?;
    authorize_git_metadata(context, &root)?;
    let before = readback(&root)?;
    ensure_clean(&root, &before.status)?;
    let identity = RepositoryIdentity {
        repo_id: input.repo_id.clone(),
        remote: git_optional(&root, &["remote", "get-url", "origin"])?,
        commit: before.head.clone(),
        tree: before.tree.clone(),
        dirty: false,
        submodules: inspect_submodules(&root)?,
    };
    identity.validate().map_err(|error| {
        failure(
            ErrorCode::LockMismatch,
            format!("invalid Git identity for {}: {error}", input.repo_id),
        )
    })?;
    let (entries, omissions) =
        entries_from_tree(&root, &identity, &input.role, &include, &exclude)?;
    let after = readback(&root)?;
    ensure_clean(&root, &after.status)?;
    if before != after {
        return Err(failure(
            ErrorCode::LockMismatch,
            format!(
                "Git HEAD/tree/status drifted while inspecting {}",
                root.display()
            ),
        ));
    }
    Ok(InspectedRepository {
        identity,
        checkout: SourceCheckout {
            repo_id: input.repo_id.clone(),
            canonical_root: root,
            role: input.role.clone(),
            include,
            exclude,
        },
        entries,
        omissions,
    })
}

fn entries_from_tree(
    root: &Path,
    identity: &RepositoryIdentity,
    role: &str,
    include: &[String],
    exclude: &[String],
) -> Result<(Vec<SourceManifestEntry>, Vec<SourceOmission>), SourceFailure> {
    let output = git_bytes(
        root,
        &["ls-tree", "-r", "-z", "--full-tree", &identity.commit.value],
    )?;
    let mut entries = Vec::new();
    let mut omissions = Vec::new();
    for record in output
        .split(|byte| *byte == 0)
        .filter(|value| !value.is_empty())
    {
        let tab = record
            .iter()
            .position(|byte| *byte == b'\t')
            .ok_or_else(|| failure(ErrorCode::LockMismatch, "malformed git ls-tree record"))?;
        let header = std::str::from_utf8(&record[..tab])
            .map_err(|error| failure(ErrorCode::LockMismatch, error.to_string()))?;
        let logical_path = std::str::from_utf8(&record[tab + 1..]).map_err(|error| {
            failure(
                ErrorCode::InvalidRequest,
                format!("Git path is not UTF-8: {error}"),
            )
        })?;
        validate_relative(logical_path)?;
        let fields = header.split_whitespace().collect::<Vec<_>>();
        if fields.len() != 3 {
            return Err(failure(
                ErrorCode::LockMismatch,
                "malformed git ls-tree header",
            ));
        }
        let (mode, kind, oid) = (fields[0], fields[1], fields[2]);
        if mode == "120000" {
            return Err(SourceFailure {
                code: ErrorCode::SymlinkRejected,
                stage: "source.inspect",
                message: format!("tracked symlink rejected: {logical_path}"),
                recovery_hint: "replace the symlink with an explicitly locked regular file",
            });
        }
        if mode == "160000" || kind == "commit" {
            continue;
        }
        if kind != "blob" || !matches!(mode, "100644" | "100755") {
            return Err(failure(
                ErrorCode::LockMismatch,
                format!("unsupported Git object {mode} {kind}: {logical_path}"),
            ));
        }
        if !include.is_empty()
            && !include
                .iter()
                .any(|prefix| path_matches_prefix(logical_path, prefix))
        {
            continue;
        }
        if exclude
            .iter()
            .any(|prefix| path_matches_prefix(logical_path, prefix))
        {
            continue;
        }
        if !is_supported_path(Path::new(logical_path)) {
            let reason = if Path::new(logical_path).extension().is_some() {
                "unsupported_extension"
            } else {
                "missing_extension"
            };
            omissions.push(SourceOmission {
                repo_id: identity.repo_id.clone(),
                logical_path: logical_path.to_owned(),
                reason: reason.to_owned(),
            });
            continue;
        }
        let bytes = git_bytes(root, &["cat-file", "blob", oid])?;
        entries.push(SourceManifestEntry {
            repo_id: identity.repo_id.clone(),
            logical_path: logical_path.to_owned(),
            role: role.to_owned(),
            content_sha256: sha256_bytes(&bytes),
            bytes: bytes.len() as u64,
        });
    }
    entries.sort_by(|left, right| left.logical_path.cmp(&right.logical_path));
    omissions.sort();
    Ok((entries, omissions))
}

fn readback(root: &Path) -> Result<GitReadback, SourceFailure> {
    Ok(GitReadback {
        head: parse_oid(&git(root, &["rev-parse", "HEAD"])?)?,
        tree: parse_oid(&git(root, &["rev-parse", "HEAD^{tree}"])?)?,
        status: git_bytes(
            root,
            &[
                "status",
                "--porcelain=v1",
                "-z",
                "--untracked-files=all",
                "--ignore-submodules=none",
            ],
        )?,
    })
}

fn ensure_clean(root: &Path, status: &[u8]) -> Result<(), SourceFailure> {
    if status.is_empty() {
        return Ok(());
    }
    Err(SourceFailure {
        code: ErrorCode::SourceDirty,
        stage: "source.inspect",
        message: format!(
            "repository {} is dirty or has untracked content",
            root.display()
        ),
        recovery_hint: "commit, stash, or explicitly remove all tracked and untracked changes",
    })
}

fn git_root(path: &Path) -> Result<PathBuf, SourceFailure> {
    let output = git(path, &["rev-parse", "--show-toplevel"])?;
    let raw = PathBuf::from(output.trim());
    let root = fs::canonicalize(&raw).map_err(|error| io_failure(&raw, error))?;
    if !root.is_dir() {
        return Err(failure(
            ErrorCode::SourceNotGit,
            "Git root is not a directory",
        ));
    }
    Ok(root)
}

fn preauthorize_git_marker(
    context: &crate::CallContext,
    input: &Path,
) -> Result<(), SourceFailure> {
    let mut cursor = if input.is_dir() {
        input.to_path_buf()
    } else {
        input
            .parent()
            .ok_or_else(|| failure(ErrorCode::SourceNotGit, "Git input has no parent"))?
            .to_path_buf()
    };
    loop {
        context.authorize_read(&cursor).map_err(context_failure)?;
        let marker = cursor.join(".git");
        match fs::symlink_metadata(&marker) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(failure(
                    ErrorCode::PathEscape,
                    format!("Git marker symlink rejected: {}", marker.display()),
                ));
            }
            Ok(metadata) if metadata.is_dir() => {
                context.authorize_read(&marker).map_err(context_failure)?;
                return Ok(());
            }
            Ok(metadata) if metadata.is_file() => {
                let marker = context.authorize_read(&marker).map_err(context_failure)?;
                let source =
                    fs::read_to_string(&marker).map_err(|error| io_failure(&marker, error))?;
                let target = source
                    .strip_prefix("gitdir:")
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| failure(ErrorCode::SourceNotGit, "malformed .git file"))?;
                let raw = PathBuf::from(target);
                let git_dir = if raw.is_absolute() {
                    raw
                } else {
                    cursor.join(raw)
                };
                context.authorize_read(&git_dir).map_err(context_failure)?;
                return Ok(());
            }
            Ok(_) => {
                return Err(failure(
                    ErrorCode::SourceNotGit,
                    format!("invalid Git marker: {}", marker.display()),
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(io_failure(&marker, error)),
        }
        if context
            .authorized_roots()
            .iter()
            .any(|root| root == &cursor)
        {
            break;
        }
        let Some(parent) = cursor.parent() else {
            break;
        };
        cursor = parent.to_path_buf();
    }
    Err(failure(
        ErrorCode::PathEscape,
        "no Git worktree marker was found before the authorization boundary",
    ))
}

fn authorize_git_metadata(context: &crate::CallContext, root: &Path) -> Result<(), SourceFailure> {
    let git_dir_raw = PathBuf::from(git(root, &["rev-parse", "--absolute-git-dir"])?.trim());
    let git_dir = context
        .authorize_read(&git_dir_raw)
        .map_err(context_failure)?;
    let common_raw = PathBuf::from(git(root, &["rev-parse", "--git-common-dir"])?.trim());
    let common_candidate = if common_raw.is_absolute() {
        common_raw
    } else {
        root.join(common_raw)
    };
    let common_dir = context
        .authorize_read(&common_candidate)
        .map_err(context_failure)?;
    if !git_dir.is_dir() || !common_dir.is_dir() {
        return Err(failure(
            ErrorCode::SourceNotGit,
            "Git metadata roots must be readable directories",
        ));
    }

    let alternates_path = common_dir.join("objects/info/alternates");
    match fs::symlink_metadata(&alternates_path) {
        Ok(_) => {
            let alternates_path = context
                .authorize_read(&alternates_path)
                .map_err(context_failure)?;
            let contents = fs::read_to_string(&alternates_path)
                .map_err(|error| io_failure(&alternates_path, error))?;
            for alternate in contents.lines().filter(|line| !line.trim().is_empty()) {
                let raw = PathBuf::from(alternate);
                let candidate = if raw.is_absolute() {
                    raw
                } else {
                    common_dir.join("objects").join(raw)
                };
                context
                    .authorize_read(&candidate)
                    .map_err(context_failure)?;
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(io_failure(&alternates_path, error)),
    }
    Ok(())
}

fn inspect_submodules(root: &Path) -> Result<Vec<SubmoduleIdentity>, SourceFailure> {
    // Its leading status byte is evidence; a generic trimmed optional reader would corrupt it.
    let output = git(root, &["submodule", "status", "--recursive"])?;
    let mut identities = Vec::new();
    for line in output.lines().filter(|line| !line.trim().is_empty()) {
        let prefix = line.as_bytes().first().copied().unwrap_or(b' ');
        let remainder = line.trim_start_matches([' ', '-', '+', 'U']);
        let mut fields = remainder.split_whitespace();
        let oid = fields
            .next()
            .ok_or_else(|| failure(ErrorCode::LockMismatch, "malformed submodule status"))?;
        let logical_path = fields
            .next()
            .ok_or_else(|| failure(ErrorCode::LockMismatch, "malformed submodule path"))?;
        validate_relative(logical_path)?;
        if prefix != b' ' {
            return Err(SourceFailure {
                code: ErrorCode::SourceDirty,
                stage: "source.inspect",
                message: format!("submodule is unclean or uninitialized: {logical_path}"),
                recovery_hint: "initialize and checkout the exact clean submodule commit",
            });
        }
        identities.push(SubmoduleIdentity {
            logical_path: logical_path.to_owned(),
            commit: parse_oid(oid)?,
            dirty: false,
        });
    }
    identities.sort_by(|left, right| left.logical_path.cmp(&right.logical_path));
    Ok(identities)
}

fn tree_blob_oid(root: &Path, commit: &str, path: &str) -> Result<String, SourceFailure> {
    let output = git_bytes(root, &["ls-tree", "-z", commit, "--", path])?;
    let record = output
        .split(|byte| *byte == 0)
        .find(|value| !value.is_empty())
        .ok_or_else(|| failure_at("source.read", ErrorCode::LockMismatch, "Git blob not found"))?;
    let tab = record
        .iter()
        .position(|byte| *byte == b'\t')
        .ok_or_else(|| {
            failure_at(
                "source.read",
                ErrorCode::LockMismatch,
                "malformed ls-tree record",
            )
        })?;
    let header = std::str::from_utf8(&record[..tab])
        .map_err(|error| failure(ErrorCode::LockMismatch, error.to_string()))?;
    let fields = header.split_whitespace().collect::<Vec<_>>();
    if fields.len() != 3 || fields[1] != "blob" || fields[0] == "120000" {
        return Err(failure_at(
            "source.read",
            ErrorCode::LockMismatch,
            "locked path is not a regular blob",
        ));
    }
    Ok(fields[2].to_owned())
}

fn validate_receipt_path(
    path: &Path,
    receipt: &SourceInspectionReceipt,
) -> Result<(), SourceFailure> {
    if receipt.schema_version != RECEIPT_SCHEMA {
        return Err(failure_at(
            "source.receipt",
            ErrorCode::LockMismatch,
            "unsupported inspection receipt schema",
        ));
    }
    let identity = canonical_json_sha256(receipt)
        .map_err(|error| failure(ErrorCode::LockMismatch, error.to_string()))?;
    let expected = format!("inspect-{}", &identity[7..31]);
    let observed = path
        .parent()
        .and_then(Path::file_name)
        .and_then(|value| value.to_str())
        .unwrap_or_default();
    if observed != expected
        || path.file_name().and_then(|value| value.to_str()) != Some("inspection-receipt.json")
    {
        return Err(failure_at(
            "source.receipt",
            ErrorCode::LockMismatch,
            "inspection receipt is not at its content-addressed path",
        ));
    }
    Ok(())
}

fn write_immutable_json<T: Serialize>(
    context: &crate::CallContext,
    path: &Path,
    value: &T,
) -> Result<PathBuf, SourceFailure> {
    publish_immutable_json(
        context,
        path,
        value,
        "source.inspect.receipt.after_partial_temp_write",
    )
    .map_err(durable_failure)
}

fn durable_failure(error: DurableWriteError) -> SourceFailure {
    let code = match error.kind {
        DurableErrorKind::Invalid => ErrorCode::InvalidRequest,
        DurableErrorKind::Unauthorized => ErrorCode::PathEscape,
        DurableErrorKind::Unsafe => ErrorCode::SymlinkRejected,
        DurableErrorKind::Conflict => ErrorCode::LockMismatch,
        DurableErrorKind::Io => ErrorCode::Io,
    };
    failure_at("source.receipt", code, error.to_string())
}

fn parse_oid(value: &str) -> Result<GitObjectId, SourceFailure> {
    let value = value.trim();
    let result = match value.len() {
        40 => GitObjectId::sha1(value),
        64 => GitObjectId::sha256(value),
        _ => {
            return Err(failure(
                ErrorCode::LockMismatch,
                format!("unsupported Git object id length: {}", value.len()),
            ));
        }
    };
    result.map_err(|error| failure(ErrorCode::LockMismatch, error.to_string()))
}

fn git(root: &Path, arguments: &[&str]) -> Result<String, SourceFailure> {
    String::from_utf8(git_bytes(root, arguments)?).map_err(|error| {
        failure(
            ErrorCode::SourceNotGit,
            format!("Git emitted non-UTF-8 output: {error}"),
        )
    })
}

fn git_optional(root: &Path, arguments: &[&str]) -> Result<Option<String>, SourceFailure> {
    let output = git_command(root, arguments)?;
    if !output.status.success() {
        return Ok(None);
    }
    let value = String::from_utf8(output.stdout)
        .map_err(|error| failure(ErrorCode::SourceNotGit, error.to_string()))?;
    let trimmed = value.trim();
    Ok((!trimmed.is_empty()).then(|| trimmed.to_owned()))
}

fn git_bytes(root: &Path, arguments: &[&str]) -> Result<Vec<u8>, SourceFailure> {
    let output = git_command(root, arguments)?;
    if !output.status.success() {
        return Err(SourceFailure {
            code: ErrorCode::SourceNotGit,
            stage: "source.inspect",
            message: format!(
                "git {} failed in {}: {}",
                arguments.join(" "),
                root.display(),
                String::from_utf8_lossy(&output.stderr).trim()
            ),
            recovery_hint: "provide an existing clean Git worktree with readable objects",
        });
    }
    Ok(output.stdout)
}

fn git_command(root: &Path, arguments: &[&str]) -> Result<std::process::Output, SourceFailure> {
    Command::new("/usr/bin/git")
        .arg("-C")
        .arg(root)
        .args(arguments)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .map_err(|error| {
            failure(
                ErrorCode::SourceNotGit,
                format!("failed to run git: {error}"),
            )
        })
}

fn validate_workspace_root(path: &Path) -> Result<(), SourceFailure> {
    if !path.is_absolute() {
        return Err(failure(
            ErrorCode::InvalidRequest,
            "workspace_root must be absolute",
        ));
    }
    let metadata = fs::symlink_metadata(path).map_err(|error| io_failure(path, error))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(failure(
            ErrorCode::InvalidRequest,
            "workspace_root must be an existing real directory",
        ));
    }
    Ok(())
}

fn validate_relative(value: &str) -> Result<(), SourceFailure> {
    let path = Path::new(value);
    if value.is_empty()
        || path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(failure(
            ErrorCode::PathEscape,
            format!("unsafe path: {value}"),
        ));
    }
    Ok(())
}

fn validate_identifier(name: &str, value: &str) -> Result<(), SourceFailure> {
    if value.is_empty()
        || matches!(value, "." | "..")
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(failure(
            ErrorCode::InvalidRequest,
            format!("invalid {name}: {value}"),
        ));
    }
    Ok(())
}

fn path_matches_prefix(path: &str, prefix: &str) -> bool {
    let prefix = prefix.trim_end_matches('/');
    path == prefix
        || path
            .strip_prefix(prefix)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn default_role() -> String {
    "source".to_owned()
}

fn io_failure(path: &Path, error: impl std::fmt::Display) -> SourceFailure {
    SourceFailure {
        code: ErrorCode::Io,
        stage: "source.inspect",
        message: format!("{}: {error}", path.display()),
        recovery_hint: "verify the explicit workspace and repository permissions",
    }
}

fn context_failure(error: crate::ContextError) -> SourceFailure {
    let code = match error {
        crate::ContextError::PathEscape(_) | crate::ContextError::UnsafeRoot(_) => {
            ErrorCode::PathEscape
        }
        crate::ContextError::MissingRoot | crate::ContextError::InvalidReceipt(_) => {
            ErrorCode::InvalidRequest
        }
        crate::ContextError::RootIo { .. } => ErrorCode::Io,
    };
    failure_at("source.authorization", code, error.to_string())
}

fn failure(code: ErrorCode, message: impl Into<String>) -> SourceFailure {
    failure_at("source.inspect", code, message)
}

fn failure_at(stage: &'static str, code: ErrorCode, message: impl Into<String>) -> SourceFailure {
    SourceFailure {
        code,
        stage,
        message: message.into(),
        recovery_hint: "provide an explicit existing clean Git worktree and retry",
    }
}
