//! Exact, file-only deliverable draft derivation.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Component, Path, PathBuf};

use gtkg_protocol::{
    ErrorCode, FileReceiptRef, OperationRequest, OperationResponse, canonical_json_sha256,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::durable::{DurableErrorKind, DurableWriteError, publish_immutable_json};
use crate::file_model::{FileModelError, sha256_file, tree_sha256};

const DRAFT_SCHEMA: &str = "gtkg.deliverable-draft-receipt/v1";

#[derive(Debug)]
pub struct DeliverableFailure {
    pub code: ErrorCode,
    pub stage: &'static str,
    pub message: String,
    pub recovery_hint: &'static str,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DerivePayload {
    workspace_root: PathBuf,
    parent_path: PathBuf,
    expected_parent_tree_sha256: String,
    deliverable_id: String,
    new_version: String,
    slot_overrides: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeliverableDraftReceipt {
    schema_version: String,
    parent_path: PathBuf,
    parent_tree_sha256: String,
    deliverable_id: String,
    new_version: String,
    slot_overrides: BTreeMap<String, String>,
    status: String,
    verified: bool,
}

pub fn derive(
    context: &crate::CallContext,
    request: &OperationRequest,
) -> Result<OperationResponse, DeliverableFailure> {
    let payload: DerivePayload =
        serde_json::from_value(request.payload.clone()).map_err(|error| {
            failure(
                "deliverable.derive",
                ErrorCode::InvalidRequest,
                format!("invalid deliverable.derive payload: {error}"),
            )
        })?;
    validate_digest(&payload.expected_parent_tree_sha256)?;
    validate_identifier("deliverable_id", &payload.deliverable_id)?;
    validate_version(&payload.new_version)?;
    for slot_id in payload.slot_overrides.keys() {
        validate_identifier("slot_id", slot_id)?;
    }

    let workspace = context
        .authorize_write(&payload.workspace_root)
        .map_err(context_failure)?;
    let parent = context
        .authorize_read(&payload.parent_path)
        .map_err(context_failure)?;
    reject_symlink_components(context, &parent, "deliverable.derive")?;
    reject_requested_symlink_suffix(context, &payload.parent_path, &parent, "deliverable.derive")?;
    ensure_directory(&parent, "deliverable.derive")?;
    let observed_parent_tree =
        tree_sha256(&parent).map_err(|error| tree_failure("deliverable.derive", error))?;
    if observed_parent_tree != payload.expected_parent_tree_sha256 {
        return Err(failure(
            "deliverable.derive",
            ErrorCode::LockMismatch,
            format!(
                "parent tree digest mismatch: expected {}, observed {observed_parent_tree}",
                payload.expected_parent_tree_sha256
            ),
        ));
    }

    let draft_root = context
        .authorize_write(&workspace.join(".gtkg/deliverable-drafts"))
        .map_err(context_failure)?;
    if draft_root.starts_with(&parent) || parent.starts_with(&draft_root) {
        return Err(failure(
            "deliverable.derive",
            ErrorCode::PathEscape,
            "published parent and mutable draft storage must not overlap",
        ));
    }

    let receipt = DeliverableDraftReceipt {
        schema_version: DRAFT_SCHEMA.to_owned(),
        parent_path: parent.clone(),
        parent_tree_sha256: observed_parent_tree.clone(),
        deliverable_id: payload.deliverable_id.clone(),
        new_version: payload.new_version.clone(),
        slot_overrides: payload.slot_overrides,
        status: "draft".to_owned(),
        verified: false,
    };
    let identity = canonical_json_sha256(&receipt).map_err(|error| {
        failure(
            "deliverable.derive",
            ErrorCode::InvalidRequest,
            error.to_string(),
        )
    })?;
    let draft_id = identity[7..].to_owned();
    let path = context
        .authorize_write(&draft_root.join(&draft_id).join("draft.json"))
        .map_err(context_failure)?;
    let path = publish_immutable_json(
        context,
        &path,
        &receipt,
        "deliverable.draft.after_partial_temp_write",
    )
    .map_err(|error| durable_failure("deliverable.derive", error))?;

    let parent_after =
        tree_sha256(&parent).map_err(|error| tree_failure("deliverable.derive", error))?;
    if parent_after != observed_parent_tree {
        return Err(failure(
            "deliverable.derive",
            ErrorCode::LockMismatch,
            "published parent changed while deriving the draft",
        ));
    }

    let reference = file_reference(context, &path)?;
    let mut response = OperationResponse::completed(
        request,
        json!({
            "draft_id": draft_id,
            "draft_ref": reference,
            "deliverable_id": payload.deliverable_id,
            "new_version": payload.new_version,
            "parent_tree_sha256": observed_parent_tree,
            "status": "draft",
            "verified": false,
        }),
    );
    response.evidence_refs = vec![path.to_string_lossy().into_owned()];
    Ok(response)
}

fn file_reference(
    context: &crate::CallContext,
    path: &Path,
) -> Result<FileReceiptRef, DeliverableFailure> {
    let root = context.workspace_root().ok_or_else(|| {
        failure(
            "deliverable.receipt",
            ErrorCode::InvalidRequest,
            "missing workspace root",
        )
    })?;
    let relative = path.strip_prefix(root).map_err(|_| {
        failure(
            "deliverable.receipt",
            ErrorCode::PathEscape,
            "deliverable receipt is outside the context workspace",
        )
    })?;
    Ok(FileReceiptRef {
        path: relative.to_string_lossy().into_owned(),
        sha256: sha256_file(path).map_err(|error| tree_failure("deliverable.receipt", error))?,
    })
}

fn reject_symlink_components(
    context: &crate::CallContext,
    path: &Path,
    stage: &'static str,
) -> Result<(), DeliverableFailure> {
    let candidate = if path.is_absolute() {
        path.to_path_buf()
    } else {
        context
            .workspace_root()
            .ok_or_else(|| failure(stage, ErrorCode::InvalidRequest, "missing workspace root"))?
            .join(path)
    };
    let root = context
        .authorized_roots()
        .iter()
        .filter(|root| candidate == **root || candidate.starts_with(root))
        .max_by_key(|root| root.components().count())
        .ok_or_else(|| {
            failure(
                stage,
                ErrorCode::PathEscape,
                format!(
                    "path is outside the authorized roots: {}",
                    candidate.display()
                ),
            )
        })?;
    let relative = candidate.strip_prefix(root).map_err(|_| {
        failure(
            stage,
            ErrorCode::PathEscape,
            format!(
                "path is outside the authorized root: {}",
                candidate.display()
            ),
        )
    })?;
    let mut current = root.clone();
    for component in relative.components() {
        if !matches!(component, Component::Normal(_)) {
            return Err(failure(
                stage,
                ErrorCode::PathEscape,
                format!("unsafe path component: {}", candidate.display()),
            ));
        }
        current.push(component.as_os_str());
        let metadata =
            fs::symlink_metadata(&current).map_err(|error| io_failure(stage, &current, error))?;
        if metadata.file_type().is_symlink() {
            return Err(failure(
                stage,
                ErrorCode::SymlinkRejected,
                format!("deliverable symlink rejected: {}", current.display()),
            ));
        }
    }
    Ok(())
}

fn reject_requested_symlink_suffix(
    context: &crate::CallContext,
    requested: &Path,
    canonical: &Path,
    stage: &'static str,
) -> Result<(), DeliverableFailure> {
    let requested = if requested.is_absolute() {
        requested.to_path_buf()
    } else {
        context
            .workspace_root()
            .ok_or_else(|| failure(stage, ErrorCode::InvalidRequest, "missing workspace root"))?
            .join(requested)
    };
    let authorized_root = context
        .authorized_roots()
        .iter()
        .filter(|root| canonical == root.as_path() || canonical.starts_with(root))
        .max_by_key(|root| root.components().count())
        .ok_or_else(|| {
            failure(
                stage,
                ErrorCode::PathEscape,
                format!(
                    "path is outside the authorized roots: {}",
                    canonical.display()
                ),
            )
        })?;
    let requested_root = requested
        .ancestors()
        .find(|ancestor| {
            fs::canonicalize(ancestor)
                .map(|observed| observed == *authorized_root)
                .unwrap_or(false)
        })
        .ok_or_else(|| {
            failure(
                stage,
                ErrorCode::PathEscape,
                format!(
                    "requested path has no authorized canonical prefix: {}",
                    requested.display()
                ),
            )
        })?;
    let relative = requested.strip_prefix(requested_root).map_err(|_| {
        failure(
            stage,
            ErrorCode::PathEscape,
            format!("unsafe requested path: {}", requested.display()),
        )
    })?;
    let mut current = requested_root.to_path_buf();
    for component in relative.components() {
        if !matches!(component, Component::Normal(_)) {
            return Err(failure(
                stage,
                ErrorCode::PathEscape,
                format!("unsafe requested path component: {}", requested.display()),
            ));
        }
        current.push(component.as_os_str());
        let metadata =
            fs::symlink_metadata(&current).map_err(|error| io_failure(stage, &current, error))?;
        if metadata.file_type().is_symlink() {
            return Err(failure(
                stage,
                ErrorCode::SymlinkRejected,
                format!("deliverable symlink rejected: {}", current.display()),
            ));
        }
    }
    let observed =
        fs::canonicalize(&requested).map_err(|error| io_failure(stage, &requested, error))?;
    if observed != canonical {
        return Err(failure(
            stage,
            ErrorCode::LockMismatch,
            "path identity changed during authorization",
        ));
    }
    Ok(())
}

fn ensure_directory(path: &Path, stage: &'static str) -> Result<(), DeliverableFailure> {
    let metadata = fs::symlink_metadata(path).map_err(|error| io_failure(stage, path, error))?;
    if metadata.file_type().is_symlink() {
        return Err(failure(
            stage,
            ErrorCode::SymlinkRejected,
            format!("deliverable symlink rejected: {}", path.display()),
        ));
    }
    if !metadata.is_dir() {
        return Err(failure(
            stage,
            ErrorCode::InvalidRequest,
            format!("deliverable parent is not a directory: {}", path.display()),
        ));
    }
    Ok(())
}

fn validate_identifier(name: &str, value: &str) -> Result<(), DeliverableFailure> {
    if value.is_empty()
        || matches!(value, "." | "..")
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(failure(
            "deliverable.derive",
            ErrorCode::InvalidRequest,
            format!("invalid {name}: {value}"),
        ));
    }
    Ok(())
}

fn validate_version(value: &str) -> Result<(), DeliverableFailure> {
    validate_identifier("version", value)?;
    if matches!(
        value.to_ascii_lowercase().as_str(),
        "latest" | "current" | "main" | "head"
    ) {
        return Err(failure(
            "deliverable.derive",
            ErrorCode::InvalidRequest,
            "floating deliverable versions are forbidden",
        ));
    }
    Ok(())
}

fn validate_digest(value: &str) -> Result<(), DeliverableFailure> {
    if value.len() != 71
        || !value.starts_with("sha256:")
        || !value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(failure(
            "deliverable.derive",
            ErrorCode::LockMismatch,
            "expected_parent_tree_sha256 must be a full lowercase sha256 digest",
        ));
    }
    Ok(())
}

fn durable_failure(stage: &'static str, error: DurableWriteError) -> DeliverableFailure {
    let code = match error.kind {
        DurableErrorKind::Invalid => ErrorCode::InvalidRequest,
        DurableErrorKind::Unauthorized => ErrorCode::PathEscape,
        DurableErrorKind::Unsafe => ErrorCode::SymlinkRejected,
        DurableErrorKind::Conflict => ErrorCode::LockMismatch,
        DurableErrorKind::Io => ErrorCode::Io,
    };
    failure(stage, code, error.to_string())
}

fn tree_failure(stage: &'static str, error: FileModelError) -> DeliverableFailure {
    let code = match &error {
        FileModelError::Symlink(_) => ErrorCode::SymlinkRejected,
        FileModelError::Hardlink(_) => ErrorCode::PathEscape,
        FileModelError::Io { .. } | FileModelError::Walk(_) => ErrorCode::Io,
        _ => ErrorCode::LockMismatch,
    };
    failure(stage, code, error.to_string())
}

fn context_failure(error: crate::ContextError) -> DeliverableFailure {
    let code = match error {
        crate::ContextError::PathEscape(_) | crate::ContextError::UnsafeRoot(_) => {
            ErrorCode::PathEscape
        }
        crate::ContextError::MissingRoot | crate::ContextError::InvalidReceipt(_) => {
            ErrorCode::InvalidRequest
        }
        crate::ContextError::RootIo { .. } => ErrorCode::Io,
    };
    failure("deliverable.authorization", code, error.to_string())
}

fn io_failure(
    stage: &'static str,
    path: &Path,
    error: impl std::fmt::Display,
) -> DeliverableFailure {
    DeliverableFailure {
        code: ErrorCode::Io,
        stage,
        message: format!("{}: {error}", path.display()),
        recovery_hint: "verify the exact deliverable parent and workspace permissions",
    }
}

fn failure(stage: &'static str, code: ErrorCode, message: impl Into<String>) -> DeliverableFailure {
    DeliverableFailure {
        code,
        stage,
        message: message.into(),
        recovery_hint: "use one exact immutable parent tree and a new non-floating version",
    }
}
