//! Exact, read-only CURRENT discovery. Activation remains externally granted.

use std::path::{Component, PathBuf};

use gtkg_protocol::{
    ErrorCode, OperationRequest, OperationResponse, validate_path_identifier, validate_sha256,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::CallContext;
use crate::exact_read::{ExactReadFailure, read_bound_regular_file};

#[derive(Debug)]
pub struct CurrentFailure {
    pub code: ErrorCode,
    pub stage: &'static str,
    pub message: String,
    pub recovery_hint: &'static str,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CurrentGetPayload {
    current_path: PathBuf,
    expected_current_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CurrentDocument {
    schema_version: String,
    deliverable_id: String,
    version: String,
    version_path: String,
    tree_sha256: String,
    manifest_sha256: String,
}

pub fn get(
    context: &CallContext,
    request: &OperationRequest,
) -> Result<OperationResponse, CurrentFailure> {
    let payload: CurrentGetPayload = serde_json::from_value(request.payload.clone())
        .map_err(|error| invalid(format!("invalid current.get payload: {error}")))?;
    validate_sha256(&payload.expected_current_sha256)
        .map_err(|error| invalid(error.to_string()))?;
    let bound = read_bound_regular_file(context, &payload.current_path).map_err(exact_failure)?;
    if bound.sha256 != payload.expected_current_sha256 {
        return Err(lock("caller-held CURRENT digest does not match"));
    }
    let current: CurrentDocument = serde_json::from_slice(&bound.bytes)
        .map_err(|error| invalid(format!("invalid CURRENT document: {error}")))?;
    validate_document(&current)?;
    Ok(OperationResponse::completed(
        request,
        json!({
            "current": current,
            "current_sha256": bound.sha256,
            "discovery_only": true,
        }),
    ))
}

fn validate_document(current: &CurrentDocument) -> Result<(), CurrentFailure> {
    if current.schema_version != "gtkg.current/v1" {
        return Err(invalid("unsupported CURRENT schema"));
    }
    validate_path_identifier("deliverable_id", &current.deliverable_id)
        .map_err(|error| invalid(error.to_string()))?;
    validate_version(&current.version)?;
    validate_sha256(&current.tree_sha256).map_err(|error| invalid(error.to_string()))?;
    validate_sha256(&current.manifest_sha256).map_err(|error| invalid(error.to_string()))?;
    let path = std::path::Path::new(&current.version_path);
    if path.is_absolute()
        || current.version_path.is_empty()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(invalid("CURRENT version_path must be a safe relative path"));
    }
    Ok(())
}

fn validate_version(version: &str) -> Result<(), CurrentFailure> {
    let floating = version.to_ascii_lowercase();
    if version.is_empty()
        || version.contains('/')
        || version.contains("..")
        || matches!(floating.as_str(), "current" | "latest" | "head" | "main")
    {
        return Err(invalid("CURRENT version must be exact and non-floating"));
    }
    Ok(())
}

fn invalid(message: impl Into<String>) -> CurrentFailure {
    CurrentFailure {
        code: ErrorCode::InvalidRequest,
        stage: "current.get",
        message: message.into(),
        recovery_hint: "repair the exact gtkg.current/v1 discovery document",
    }
}

fn lock(message: impl Into<String>) -> CurrentFailure {
    CurrentFailure {
        code: ErrorCode::LockMismatch,
        stage: "current.get",
        message: message.into(),
        recovery_hint: "obtain the current caller-held full digest and retry",
    }
}

fn exact_failure(error: ExactReadFailure) -> CurrentFailure {
    CurrentFailure {
        code: error.code,
        stage: "current.get",
        message: format!("{}: {}", error.path.display(), error.message),
        recovery_hint: "provide an existing stable CURRENT file",
    }
}
