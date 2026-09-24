//! Exact local template resolution, validation, and replayable receipts.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};

use gtkg_protocol::{
    ErrorCode, FileReceiptRef, OperationRequest, OperationResponse, TemplateLock, VersionRef,
    canonical_json_sha256,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::durable::{DurableErrorKind, DurableWriteError, publish_immutable_json};
use crate::file_model::{sha256_file, tree_sha256};

const MANIFEST_SCHEMA: &str = "gtkg.template-manifest/v1";
const RESOLUTION_SCHEMA: &str = "gtkg.template-resolution-receipt/v1";
const VALIDATION_SCHEMA: &str = "gtkg.template-validation-receipt/v1";
const CACHE_SCHEMA: &str = "gtkg.template-cache-receipt/v1";
const DRAFT_SCHEMA: &str = "gtkg.template-draft-receipt/v1";

#[derive(Debug)]
pub struct TemplateFailure {
    pub code: ErrorCode,
    pub stage: &'static str,
    pub message: String,
    pub recovery_hint: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemplateManifest {
    pub schema_version: String,
    pub template_id: String,
    pub version: String,
    pub template_file: String,
    pub template_sha256: String,
    pub slot_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemplateResolutionReceipt {
    pub schema_version: String,
    pub package_root: PathBuf,
    pub package_tree_sha256: String,
    pub manifest_sha256: String,
    pub manifest: TemplateManifest,
    pub template_lock: TemplateLock,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemplateValidationReceipt {
    pub schema_version: String,
    pub resolution_receipt_sha256: String,
    pub package_root: PathBuf,
    pub package_tree_sha256: String,
    pub manifest_sha256: String,
    pub manifest: TemplateManifest,
    pub template_lock: TemplateLock,
}

#[derive(Debug, Clone)]
pub struct VerifiedTemplateValidation {
    pub template_lock: TemplateLock,
    pub package_root: PathBuf,
    pub package_tree_sha256: String,
    pub manifest: TemplateManifest,
    pub manifest_sha256: String,
    pub receipt_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct TemplateCatalogEntry {
    template_id: String,
    versions: Vec<TemplateCatalogVersion>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct TemplateCatalogVersion {
    version: String,
    manifest_sha256: String,
    package_tree_sha256: String,
    template_sha256: String,
    slot_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TemplateCacheReceipt {
    schema_version: String,
    resolution_receipt_sha256: String,
    package_tree_sha256: String,
    manifest_sha256: String,
    manifest: TemplateManifest,
    template_lock: TemplateLock,
    template_markdown: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TemplateDraftReceipt {
    schema_version: String,
    parent_validation_sha256: String,
    parent_manifest_sha256: String,
    parent_template_lock: TemplateLock,
    template_id: String,
    parent_version: String,
    new_version: String,
    slot_overrides: BTreeMap<String, String>,
    status: String,
    verified: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ListPayload {
    catalog_root: PathBuf,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResolvePayload {
    workspace_root: PathBuf,
    catalog_root: PathBuf,
    template_id: String,
    version: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ValidatePayload {
    workspace_root: PathBuf,
    resolution_ref: FileReceiptRef,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrefetchPayload {
    workspace_root: PathBuf,
    resolution_ref: FileReceiptRef,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GetPayload {
    workspace_root: PathBuf,
    template_ref: FileReceiptRef,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DerivePayload {
    workspace_root: PathBuf,
    parent_ref: FileReceiptRef,
    new_version: String,
    slot_overrides: BTreeMap<String, String>,
}

pub fn list(
    context: &crate::CallContext,
    request: &OperationRequest,
) -> Result<OperationResponse, TemplateFailure> {
    let payload: ListPayload =
        serde_json::from_value(request.payload.clone()).map_err(|error| {
            failure(
                "template.list",
                ErrorCode::InvalidRequest,
                format!("invalid template.list payload: {error}"),
            )
        })?;
    let catalog = context
        .authorize_read(&payload.catalog_root)
        .map_err(context_failure)?;
    reject_symlink_components(context, &catalog, "template.list")?;
    reject_requested_symlink_suffix(context, &payload.catalog_root, &catalog, "template.list")?;
    ensure_directory(&catalog, "template.list")?;

    let mut templates = Vec::new();
    for entry in sorted_directory_entries(&catalog, "template.list")? {
        let metadata = fs::symlink_metadata(&entry)
            .map_err(|error| io_failure("template.list", &entry, error))?;
        if metadata.file_type().is_symlink() {
            return Err(symlink_failure("template.list", &entry));
        }
        if metadata.is_file() {
            reject_hardlink(&entry, "template.list")?;
            continue;
        }
        if !metadata.is_dir() {
            return Err(lock_failure(
                "template.list",
                format!("unsupported catalog entry: {}", entry.display()),
            ));
        }

        let template_id = utf8_file_name(&entry, "template.list")?.to_owned();
        validate_identifier("template_id", &template_id)?;
        let requested_versions_root = entry.join("versions");
        let versions_root = context
            .authorize_read(&requested_versions_root)
            .map_err(context_failure)?;
        reject_symlink_components(context, &versions_root, "template.list")?;
        reject_requested_symlink_suffix(
            context,
            &requested_versions_root,
            &versions_root,
            "template.list",
        )?;
        ensure_directory(&versions_root, "template.list")?;

        let mut versions = Vec::new();
        for version_path in sorted_directory_entries(&versions_root, "template.list")? {
            let metadata = fs::symlink_metadata(&version_path)
                .map_err(|error| io_failure("template.list", &version_path, error))?;
            if metadata.file_type().is_symlink() {
                return Err(symlink_failure("template.list", &version_path));
            }
            if metadata.is_file() {
                reject_hardlink(&version_path, "template.list")?;
                continue;
            }
            if !metadata.is_dir() {
                return Err(lock_failure(
                    "template.list",
                    format!(
                        "unsupported template version entry: {}",
                        version_path.display()
                    ),
                ));
            }
            let verified = validate_package(context, &version_path)?;
            if verified.manifest.template_id != template_id {
                return Err(lock_failure(
                    "template.list",
                    "template package identity does not match its catalog directory",
                ));
            }
            versions.push(TemplateCatalogVersion {
                version: verified.manifest.version.clone(),
                manifest_sha256: verified.manifest_sha256,
                package_tree_sha256: verified.package_tree_sha256,
                template_sha256: verified.manifest.template_sha256.clone(),
                slot_ids: verified.manifest.slot_ids.clone(),
            });
        }
        versions.sort_by(|left, right| left.version.cmp(&right.version));
        if versions.is_empty() {
            return Err(lock_failure(
                "template.list",
                format!("template {template_id} has no exact versions"),
            ));
        }
        templates.push(TemplateCatalogEntry {
            template_id,
            versions,
        });
    }
    templates.sort_by(|left, right| left.template_id.cmp(&right.template_id));

    Ok(OperationResponse::completed(
        request,
        json!({"templates": templates}),
    ))
}

pub fn resolve(
    context: &crate::CallContext,
    request: &OperationRequest,
) -> Result<OperationResponse, TemplateFailure> {
    let payload: ResolvePayload =
        serde_json::from_value(request.payload.clone()).map_err(|error| {
            failure(
                "template.resolve",
                ErrorCode::InvalidRequest,
                format!("invalid template.resolve payload: {error}"),
            )
        })?;
    validate_identifier("template_id", &payload.template_id)?;
    validate_version(&payload.version)?;
    let workspace = context
        .authorize_write(&payload.workspace_root)
        .map_err(context_failure)?;
    let catalog = context
        .authorize_read(&payload.catalog_root)
        .map_err(context_failure)?;
    reject_symlink_components(context, &catalog, "template.resolve")?;
    reject_requested_symlink_suffix(context, &payload.catalog_root, &catalog, "template.resolve")?;
    let verified = resolve_package(context, &catalog, &payload.template_id, &payload.version)?;
    let receipt = TemplateResolutionReceipt {
        schema_version: RESOLUTION_SCHEMA.to_owned(),
        package_root: verified.package_root.clone(),
        package_tree_sha256: verified.package_tree_sha256.clone(),
        manifest_sha256: verified.manifest_sha256.clone(),
        manifest: verified.manifest.clone(),
        template_lock: verified.template_lock.clone(),
    };
    let identity = canonical_json_sha256(&receipt).map_err(|error| {
        failure(
            "template.resolve",
            ErrorCode::InvalidRequest,
            error.to_string(),
        )
    })?;
    let resolution_id = format!("resolve-{}", &identity[7..31]);
    let path = workspace
        .join(".gtkg/template-resolutions")
        .join(&resolution_id)
        .join("resolution-receipt.json");
    let path = context.authorize_write(&path).map_err(context_failure)?;
    let path = write_immutable_json(context, &path, &receipt, "template.resolve")?;
    let reference = file_reference(context, &path)?;
    let mut response = OperationResponse::completed(
        request,
        json!({
            "resolution_id": resolution_id,
            "resolution_ref": reference,
            "template_lock": verified.template_lock,
            "manifest_sha256": verified.manifest_sha256,
            "package_tree_sha256": verified.package_tree_sha256,
        }),
    );
    response.run_id = Some(resolution_id);
    response.evidence_refs = vec![path.to_string_lossy().into_owned()];
    Ok(response)
}

pub fn validate(
    context: &crate::CallContext,
    request: &OperationRequest,
) -> Result<OperationResponse, TemplateFailure> {
    let payload: ValidatePayload =
        serde_json::from_value(request.payload.clone()).map_err(|error| {
            failure(
                "template.validate",
                ErrorCode::InvalidRequest,
                format!("invalid template.validate payload: {error}"),
            )
        })?;
    let workspace = context
        .authorize_write(&payload.workspace_root)
        .map_err(context_failure)?;
    let resolution = load_and_revalidate_resolution(context, &workspace, &payload.resolution_ref)?;
    let receipt = TemplateValidationReceipt {
        schema_version: VALIDATION_SCHEMA.to_owned(),
        resolution_receipt_sha256: payload.resolution_ref.sha256,
        package_root: resolution.package_root.clone(),
        package_tree_sha256: resolution.package_tree_sha256.clone(),
        manifest_sha256: resolution.manifest_sha256.clone(),
        manifest: resolution.manifest.clone(),
        template_lock: resolution.template_lock.clone(),
    };
    let identity = canonical_json_sha256(&receipt).map_err(|error| {
        failure(
            "template.validate",
            ErrorCode::InvalidRequest,
            error.to_string(),
        )
    })?;
    let validation_id = format!("validate-{}", &identity[7..31]);
    let path = workspace
        .join(".gtkg/template-validations")
        .join(&validation_id)
        .join("validation-receipt.json");
    let path = context.authorize_write(&path).map_err(context_failure)?;
    let path = write_immutable_json(context, &path, &receipt, "template.validate")?;
    let reference = file_reference(context, &path)?;
    let mut response = OperationResponse::completed(
        request,
        json!({
            "validation_id": validation_id,
            "validation_ref": reference,
            "template_lock": resolution.template_lock,
            "manifest_sha256": resolution.manifest_sha256,
            "package_tree_sha256": resolution.package_tree_sha256,
        }),
    );
    response.run_id = Some(validation_id);
    response.evidence_refs = vec![path.to_string_lossy().into_owned()];
    Ok(response)
}

pub fn prefetch(
    context: &crate::CallContext,
    request: &OperationRequest,
) -> Result<OperationResponse, TemplateFailure> {
    let payload: PrefetchPayload =
        serde_json::from_value(request.payload.clone()).map_err(|error| {
            failure(
                "template.prefetch",
                ErrorCode::InvalidRequest,
                format!("invalid template.prefetch payload: {error}"),
            )
        })?;
    let workspace = context
        .authorize_write(&payload.workspace_root)
        .map_err(context_failure)?;
    let resolution = load_and_revalidate_resolution(context, &workspace, &payload.resolution_ref)?;
    let template_path = safe_join(&resolution.package_root, &resolution.manifest.template_file)?;
    reject_symlink_components(context, &template_path, "template.prefetch")?;
    reject_hardlink(&template_path, "template.prefetch")?;
    let template_markdown = fs::read_to_string(&template_path)
        .map_err(|error| io_failure("template.prefetch", &template_path, error))?;
    if sha256_bytes(template_markdown.as_bytes()) != resolution.manifest.template_sha256 {
        return Err(lock_failure(
            "template.prefetch",
            "template bytes drifted after resolution revalidation",
        ));
    }

    let receipt = TemplateCacheReceipt {
        schema_version: CACHE_SCHEMA.to_owned(),
        resolution_receipt_sha256: resolution.receipt_sha256,
        package_tree_sha256: resolution.package_tree_sha256.clone(),
        manifest_sha256: resolution.manifest_sha256.clone(),
        manifest: resolution.manifest.clone(),
        template_lock: resolution.template_lock.clone(),
        template_markdown,
    };
    let identity = canonical_json_sha256(&receipt).map_err(|error| {
        failure(
            "template.prefetch",
            ErrorCode::InvalidRequest,
            error.to_string(),
        )
    })?;
    let cache_id = identity[7..].to_owned();
    let path = workspace
        .join(".gtkg/cache/templates")
        .join(&cache_id)
        .join("template-cache.json");
    let path = context.authorize_write(&path).map_err(context_failure)?;
    let cache_hit = existing_json_matches(&path, &receipt, "template.prefetch")?;
    let path = write_immutable_json(context, &path, &receipt, "template.prefetch")?;
    let reference = file_reference(context, &path)?;
    let mut response = OperationResponse::completed(
        request,
        json!({
            "cache_id": cache_id,
            "cache_ref": reference,
            "cache_hit": cache_hit,
            "template_lock": resolution.template_lock,
            "manifest_sha256": resolution.manifest_sha256,
            "package_tree_sha256": resolution.package_tree_sha256,
        }),
    );
    response.evidence_refs = vec![path.to_string_lossy().into_owned()];
    Ok(response)
}

pub fn get(
    context: &crate::CallContext,
    request: &OperationRequest,
) -> Result<OperationResponse, TemplateFailure> {
    let payload: GetPayload = serde_json::from_value(request.payload.clone()).map_err(|error| {
        failure(
            "template.get",
            ErrorCode::InvalidRequest,
            format!("invalid template.get payload: {error}"),
        )
    })?;
    let workspace = context
        .authorize_read(&payload.workspace_root)
        .map_err(context_failure)?;
    let path = resolve_reference(context, &workspace, &payload.template_ref, "template.get")?;
    verify_file_digest(&path, &payload.template_ref.sha256, "template.get")?;
    let receipt: TemplateCacheReceipt = read_json(&path, "template.get")?;
    validate_cache_receipt(&path, &receipt)?;

    let mut response = OperationResponse::completed(
        request,
        json!({
            "cache_ref": payload.template_ref,
            "manifest": receipt.manifest,
            "template_markdown": receipt.template_markdown,
            "template_lock": receipt.template_lock,
            "manifest_sha256": receipt.manifest_sha256,
            "package_tree_sha256": receipt.package_tree_sha256,
        }),
    );
    response.evidence_refs = vec![path.to_string_lossy().into_owned()];
    Ok(response)
}

pub fn derive(
    context: &crate::CallContext,
    request: &OperationRequest,
) -> Result<OperationResponse, TemplateFailure> {
    let payload: DerivePayload =
        serde_json::from_value(request.payload.clone()).map_err(|error| {
            failure(
                "template.derive",
                ErrorCode::InvalidRequest,
                format!("invalid template.derive payload: {error}"),
            )
        })?;
    validate_version(&payload.new_version)?;
    let workspace = context
        .authorize_write(&payload.workspace_root)
        .map_err(context_failure)?;
    let parent = load_and_revalidate_validation(context, &workspace, &payload.parent_ref)?;
    if payload.new_version == parent.manifest.version {
        return Err(failure(
            "template.derive",
            ErrorCode::InvalidRequest,
            "derived template version must differ from its parent version",
        ));
    }
    for slot_id in payload.slot_overrides.keys() {
        validate_identifier("slot_id", slot_id)?;
        if !parent.manifest.slot_ids.contains(slot_id) {
            return Err(lock_failure(
                "template.derive",
                format!("slot override is not declared by the parent template: {slot_id}"),
            ));
        }
    }

    let receipt = TemplateDraftReceipt {
        schema_version: DRAFT_SCHEMA.to_owned(),
        parent_validation_sha256: parent.receipt_sha256.clone(),
        parent_manifest_sha256: parent.manifest_sha256.clone(),
        parent_template_lock: parent.template_lock.clone(),
        template_id: parent.manifest.template_id.clone(),
        parent_version: parent.manifest.version.clone(),
        new_version: payload.new_version.clone(),
        slot_overrides: payload.slot_overrides.clone(),
        status: "draft".to_owned(),
        verified: false,
    };
    let identity = canonical_json_sha256(&receipt).map_err(|error| {
        failure(
            "template.derive",
            ErrorCode::InvalidRequest,
            error.to_string(),
        )
    })?;
    let draft_id = identity[7..].to_owned();
    let path = workspace
        .join(".gtkg/template-drafts")
        .join(&draft_id)
        .join("draft.json");
    let path = context.authorize_write(&path).map_err(context_failure)?;
    let path = write_immutable_json(context, &path, &receipt, "template.derive")?;

    let parent_after = validate_package(context, &parent.package_root)?;
    if parent_after.package_tree_sha256 != parent.package_tree_sha256
        || parent_after.manifest_sha256 != parent.manifest_sha256
    {
        return Err(lock_failure(
            "template.derive",
            "published parent changed while deriving the draft",
        ));
    }

    let reference = file_reference(context, &path)?;
    let mut response = OperationResponse::completed(
        request,
        json!({
            "draft_id": draft_id,
            "draft_ref": reference,
            "template_id": parent.manifest.template_id,
            "new_version": payload.new_version,
            "parent_manifest_sha256": parent.manifest_sha256,
            "parent_tree_sha256": parent.package_tree_sha256,
            "status": "draft",
            "verified": false,
        }),
    );
    response.evidence_refs = vec![path.to_string_lossy().into_owned()];
    Ok(response)
}

pub fn load_and_revalidate_validation(
    context: &crate::CallContext,
    workspace_root: &Path,
    reference: &FileReceiptRef,
) -> Result<VerifiedTemplateValidation, TemplateFailure> {
    let path = resolve_reference(context, workspace_root, reference, "template.validation")?;
    let observed = verify_file_digest(&path, &reference.sha256, "template.validation")?;
    let receipt: TemplateValidationReceipt = read_json(&path, "template.validation")?;
    if receipt.schema_version != VALIDATION_SCHEMA {
        return Err(lock_failure(
            "template.validation",
            "unsupported validation receipt schema",
        ));
    }
    validate_content_addressed_path(&path, "validate", "validation-receipt.json", &receipt)?;
    let current = validate_package(context, &receipt.package_root)?;
    if current.template_lock != receipt.template_lock
        || current.manifest != receipt.manifest
        || current.manifest_sha256 != receipt.manifest_sha256
        || current.package_tree_sha256 != receipt.package_tree_sha256
    {
        return Err(lock_failure(
            "template.validation",
            "template package drifted from validation receipt",
        ));
    }
    Ok(VerifiedTemplateValidation {
        template_lock: receipt.template_lock,
        package_root: receipt.package_root,
        package_tree_sha256: receipt.package_tree_sha256,
        manifest: receipt.manifest,
        manifest_sha256: receipt.manifest_sha256,
        receipt_sha256: observed,
    })
}

/// Pipeline-facing alias: build operations only accept validation receipts.
pub fn load_and_revalidate(
    context: &crate::CallContext,
    workspace_root: &Path,
    reference: &FileReceiptRef,
) -> Result<VerifiedTemplateValidation, TemplateFailure> {
    load_and_revalidate_validation(context, workspace_root, reference)
}

fn load_and_revalidate_resolution(
    context: &crate::CallContext,
    workspace_root: &Path,
    reference: &FileReceiptRef,
) -> Result<VerifiedTemplateValidation, TemplateFailure> {
    let path = resolve_reference(context, workspace_root, reference, "template.resolution")?;
    let observed = verify_file_digest(&path, &reference.sha256, "template.resolution")?;
    let receipt: TemplateResolutionReceipt = read_json(&path, "template.resolution")?;
    if receipt.schema_version != RESOLUTION_SCHEMA {
        return Err(lock_failure(
            "template.resolution",
            "unsupported resolution receipt schema",
        ));
    }
    validate_content_addressed_path(&path, "resolve", "resolution-receipt.json", &receipt)?;
    let current = validate_package(context, &receipt.package_root)?;
    if current.template_lock != receipt.template_lock
        || current.manifest != receipt.manifest
        || current.manifest_sha256 != receipt.manifest_sha256
        || current.package_tree_sha256 != receipt.package_tree_sha256
    {
        return Err(lock_failure(
            "template.resolution",
            "template package drifted from resolution receipt",
        ));
    }
    Ok(VerifiedTemplateValidation {
        template_lock: receipt.template_lock,
        package_root: receipt.package_root,
        package_tree_sha256: receipt.package_tree_sha256,
        manifest: receipt.manifest,
        manifest_sha256: receipt.manifest_sha256,
        receipt_sha256: observed,
    })
}

fn resolve_package(
    context: &crate::CallContext,
    catalog: &Path,
    template_id: &str,
    version: &str,
) -> Result<VerifiedTemplateValidation, TemplateFailure> {
    let versions = catalog.join(template_id).join("versions");
    reject_symlink(&versions, "template.resolve")?;
    let versions = context.authorize_read(&versions).map_err(context_failure)?;
    let prefix = format!("v{version}--");
    let mut candidates = fs::read_dir(&versions)
        .map_err(|error| io_failure("template.resolve", &versions, error))?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| io_failure("template.resolve", &versions, error))?;
    candidates.retain(|path| {
        path.file_name()
            .and_then(|value| value.to_str())
            .is_some_and(|name| name.starts_with(&prefix))
    });
    candidates.sort();
    if candidates.len() != 1 {
        return Err(failure(
            "template.resolve",
            ErrorCode::LockMismatch,
            format!(
                "expected exactly one exact template version {template_id}@{version}, found {}",
                candidates.len()
            ),
        ));
    }
    let verified = validate_package(context, &candidates[0])?;
    if verified.manifest.template_id != template_id || verified.manifest.version != version {
        return Err(lock_failure(
            "template.resolve",
            "template manifest identity does not match requested exact version",
        ));
    }
    Ok(verified)
}

fn validate_package(
    context: &crate::CallContext,
    root: &Path,
) -> Result<VerifiedTemplateValidation, TemplateFailure> {
    reject_symlink(root, "template.validate")?;
    let root = context.authorize_read(root).map_err(context_failure)?;
    let manifest_path = root.join("template-manifest.json");
    reject_symlink(&manifest_path, "template.validate")?;
    reject_hardlink(&manifest_path, "template.validate")?;
    let manifest: TemplateManifest = read_json(&manifest_path, "template.validate")?;
    if manifest.schema_version != MANIFEST_SCHEMA {
        return Err(lock_failure(
            "template.validate",
            "unsupported template manifest schema",
        ));
    }
    validate_identifier("template_id", &manifest.template_id)?;
    validate_version(&manifest.version)?;
    validate_relative(&manifest.template_file)?;
    validate_digest(&manifest.template_sha256)?;
    let mut slots = BTreeSet::new();
    for slot in &manifest.slot_ids {
        validate_identifier("slot_id", slot)?;
        if !slots.insert(slot.as_str()) {
            return Err(lock_failure(
                "template.validate",
                format!("duplicate template slot: {slot}"),
            ));
        }
    }
    let manifest_sha256 = canonical_json_sha256(&manifest).map_err(|error| {
        failure(
            "template.validate",
            ErrorCode::LockMismatch,
            error.to_string(),
        )
    })?;
    let expected_dir = format!("v{}--{}", manifest.version, &manifest_sha256[7..19]);
    if root.file_name().and_then(|value| value.to_str()) != Some(&expected_dir) {
        return Err(lock_failure(
            "template.validate",
            "template directory does not match canonical manifest digest",
        ));
    }
    let template_path = safe_join(&root, &manifest.template_file)?;
    reject_symlink(&template_path, "template.validate")?;
    reject_hardlink(&template_path, "template.validate")?;
    if sha256_file(&template_path)
        .map_err(|error| io_failure("template.validate", &template_path, error))?
        != manifest.template_sha256
    {
        return Err(lock_failure(
            "template.validate",
            "template file digest mismatch",
        ));
    }
    let source = fs::read_to_string(&template_path)
        .map_err(|error| io_failure("template.validate", &template_path, error))?;
    let document = crate::okf::parse_okf_concept(&source).map_err(|error| {
        failure(
            "template.validate",
            ErrorCode::OkfInvalid,
            format!("{}: {error}", template_path.display()),
        )
    })?;
    crate::okf::validate_current_version(&document.frontmatter).map_err(|error| {
        failure(
            "template.validate",
            ErrorCode::OkfInvalid,
            format!("{}: {error}", template_path.display()),
        )
    })?;
    if document.frontmatter.kind != "template"
        || document
            .frontmatter
            .gtkg
            .as_ref()
            .and_then(|gtkg| gtkg.get("schema"))
            .and_then(serde_yaml::Value::as_str)
            != Some("gtkg.template/v1")
    {
        return Err(failure(
            "template.validate",
            ErrorCode::OkfInvalid,
            "template file must use type=template and gtkg.template/v1",
        ));
    }
    let resource_ref = document.frontmatter.resource.as_deref().ok_or_else(|| {
        failure(
            "template.validate",
            ErrorCode::OkfInvalid,
            "template OKF requires a resource self-reference",
        )
    })?;
    let resource = fs::canonicalize(
        template_path
            .parent()
            .ok_or_else(|| lock_failure("template.validate", "template has no parent"))?
            .join(resource_ref),
    )
    .map_err(|error| io_failure("template.validate", &template_path, error))?;
    if resource
        != fs::canonicalize(&template_path)
            .map_err(|error| io_failure("template.validate", &template_path, error))?
    {
        return Err(failure(
            "template.validate",
            ErrorCode::OkfInvalid,
            "template OKF resource does not resolve to the template file",
        ));
    }
    let template_lock = TemplateLock {
        template: VersionRef {
            id: manifest.template_id.clone(),
            version: manifest.version.clone(),
            manifest_sha256: manifest_sha256.clone(),
        },
        parent: None,
        slot_ids: manifest.slot_ids.clone(),
    };
    template_lock.validate().map_err(|error| {
        failure(
            "template.validate",
            ErrorCode::LockMismatch,
            error.to_string(),
        )
    })?;
    let package_tree_sha256 =
        tree_sha256(&root).map_err(|error| lock_failure("template.validate", error.to_string()))?;
    Ok(VerifiedTemplateValidation {
        template_lock,
        package_root: root,
        package_tree_sha256,
        manifest,
        manifest_sha256,
        receipt_sha256: String::new(),
    })
}

fn resolve_reference(
    context: &crate::CallContext,
    workspace_root: &Path,
    reference: &FileReceiptRef,
    stage: &'static str,
) -> Result<PathBuf, TemplateFailure> {
    reference
        .validate()
        .map_err(|error| failure(stage, ErrorCode::LockMismatch, error.to_string()))?;
    let path = context
        .resolve_workspace_receipt(workspace_root, reference)
        .map_err(context_failure)?;
    reject_symlink_components(context, &path, stage)?;
    let workspace_candidate = workspace_root.join(&reference.path);
    let context_candidate = context
        .workspace_root()
        .ok_or_else(|| failure(stage, ErrorCode::InvalidRequest, "missing workspace root"))?
        .join(&reference.path);
    for candidate in [workspace_candidate, context_candidate] {
        if fs::symlink_metadata(&candidate).is_ok()
            && fs::canonicalize(&candidate)
                .map(|observed| observed == path)
                .unwrap_or(false)
        {
            reject_requested_symlink_suffix(context, &candidate, &path, stage)?;
        }
    }
    Ok(path)
}

fn file_reference(
    context: &crate::CallContext,
    path: &Path,
) -> Result<FileReceiptRef, TemplateFailure> {
    let root = context.workspace_root().ok_or_else(|| {
        failure(
            "template.receipt",
            ErrorCode::InvalidRequest,
            "missing root",
        )
    })?;
    let relative = path.strip_prefix(root).map_err(|_| {
        failure(
            "template.receipt",
            ErrorCode::PathEscape,
            "template receipt is outside the context workspace",
        )
    })?;
    Ok(FileReceiptRef {
        path: relative.to_string_lossy().into_owned(),
        sha256: sha256_file(path).map_err(|error| io_failure("template.receipt", path, error))?,
    })
}

fn verify_file_digest(
    path: &Path,
    expected: &str,
    stage: &'static str,
) -> Result<String, TemplateFailure> {
    let observed = sha256_file(path).map_err(|error| io_failure(stage, path, error))?;
    if observed != expected {
        return Err(lock_failure(stage, "template receipt digest mismatch"));
    }
    Ok(observed)
}

fn validate_content_addressed_path<T: Serialize>(
    path: &Path,
    prefix: &str,
    file_name: &str,
    receipt: &T,
) -> Result<(), TemplateFailure> {
    let digest = canonical_json_sha256(receipt)
        .map_err(|error| lock_failure("template.receipt", error.to_string()))?;
    let expected = format!("{prefix}-{}", &digest[7..31]);
    if path
        .parent()
        .and_then(Path::file_name)
        .and_then(|v| v.to_str())
        != Some(&expected)
        || path.file_name().and_then(|value| value.to_str()) != Some(file_name)
    {
        return Err(lock_failure(
            "template.receipt",
            "template receipt is not at its content-addressed path",
        ));
    }
    Ok(())
}

fn validate_cache_receipt(
    path: &Path,
    receipt: &TemplateCacheReceipt,
) -> Result<(), TemplateFailure> {
    if receipt.schema_version != CACHE_SCHEMA {
        return Err(lock_failure(
            "template.get",
            "unsupported template cache receipt schema",
        ));
    }
    validate_digest(&receipt.resolution_receipt_sha256)?;
    validate_digest(&receipt.package_tree_sha256)?;
    validate_digest(&receipt.manifest_sha256)?;
    validate_manifest_shape(&receipt.manifest, "template.get")?;
    let observed_manifest = canonical_json_sha256(&receipt.manifest)
        .map_err(|error| lock_failure("template.get", error.to_string()))?;
    if observed_manifest != receipt.manifest_sha256 {
        return Err(lock_failure(
            "template.get",
            "cached template manifest digest mismatch",
        ));
    }
    receipt
        .template_lock
        .validate()
        .map_err(|error| lock_failure("template.get", error.to_string()))?;
    if receipt.template_lock.parent.is_some()
        || receipt.template_lock.template.id != receipt.manifest.template_id
        || receipt.template_lock.template.version != receipt.manifest.version
        || receipt.template_lock.template.manifest_sha256 != receipt.manifest_sha256
        || receipt.template_lock.slot_ids != receipt.manifest.slot_ids
    {
        return Err(lock_failure(
            "template.get",
            "cached TemplateLock does not match the cached manifest",
        ));
    }
    if sha256_bytes(receipt.template_markdown.as_bytes()) != receipt.manifest.template_sha256 {
        return Err(lock_failure(
            "template.get",
            "cached template markdown digest mismatch",
        ));
    }

    let identity = canonical_json_sha256(receipt)
        .map_err(|error| lock_failure("template.get", error.to_string()))?;
    let parent = path
        .parent()
        .ok_or_else(|| lock_failure("template.get", "cache receipt has no parent"))?;
    let templates = parent
        .parent()
        .ok_or_else(|| lock_failure("template.get", "cache receipt has no templates root"))?;
    let cache = templates
        .parent()
        .ok_or_else(|| lock_failure("template.get", "cache receipt has no cache root"))?;
    let gtkg = cache
        .parent()
        .ok_or_else(|| lock_failure("template.get", "cache receipt has no .gtkg root"))?;
    if path.file_name().and_then(|name| name.to_str()) != Some("template-cache.json")
        || parent.file_name().and_then(|name| name.to_str()) != Some(&identity[7..])
        || templates.file_name().and_then(|name| name.to_str()) != Some("templates")
        || cache.file_name().and_then(|name| name.to_str()) != Some("cache")
        || gtkg.file_name().and_then(|name| name.to_str()) != Some(".gtkg")
    {
        return Err(lock_failure(
            "template.get",
            "template cache receipt is not at its full content-addressed path",
        ));
    }
    Ok(())
}

fn existing_json_matches<T>(
    path: &Path,
    value: &T,
    stage: &'static str,
) -> Result<bool, TemplateFailure>
where
    T: Serialize,
{
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(io_failure(stage, path, error)),
    };
    if metadata.file_type().is_symlink() {
        return Err(symlink_failure(stage, path));
    }
    if !metadata.is_file() {
        return Err(lock_failure(
            stage,
            format!(
                "immutable JSON path is not a regular file: {}",
                path.display()
            ),
        ));
    }
    reject_hardlink(path, stage)?;
    let expected = serde_json::to_vec_pretty(value)
        .map_err(|error| failure(stage, ErrorCode::InvalidRequest, error.to_string()))?;
    let observed = fs::read(path).map_err(|error| io_failure(stage, path, error))?;
    Ok(observed == expected)
}

fn validate_manifest_shape(
    manifest: &TemplateManifest,
    stage: &'static str,
) -> Result<(), TemplateFailure> {
    if manifest.schema_version != MANIFEST_SCHEMA {
        return Err(lock_failure(stage, "unsupported template manifest schema"));
    }
    validate_identifier("template_id", &manifest.template_id)?;
    validate_version(&manifest.version)?;
    validate_relative(&manifest.template_file)?;
    validate_digest(&manifest.template_sha256)?;
    let mut slots = BTreeSet::new();
    for slot in &manifest.slot_ids {
        validate_identifier("slot_id", slot)?;
        if !slots.insert(slot.as_str()) {
            return Err(lock_failure(
                stage,
                format!("duplicate template slot: {slot}"),
            ));
        }
    }
    Ok(())
}

fn read_json<T: for<'de> Deserialize<'de>>(
    path: &Path,
    stage: &'static str,
) -> Result<T, TemplateFailure> {
    serde_json::from_slice(&fs::read(path).map_err(|error| io_failure(stage, path, error))?)
        .map_err(|error| failure(stage, ErrorCode::LockMismatch, error.to_string()))
}

fn write_immutable_json<T: Serialize>(
    context: &crate::CallContext,
    path: &Path,
    value: &T,
    stage: &'static str,
) -> Result<PathBuf, TemplateFailure> {
    publish_immutable_json(
        context,
        path,
        value,
        "template.receipt.after_partial_temp_write",
    )
    .map_err(|error| durable_failure(stage, error))
}

fn durable_failure(stage: &'static str, error: DurableWriteError) -> TemplateFailure {
    let code = match error.kind {
        DurableErrorKind::Invalid => ErrorCode::InvalidRequest,
        DurableErrorKind::Unauthorized => ErrorCode::PathEscape,
        DurableErrorKind::Unsafe => ErrorCode::SymlinkRejected,
        DurableErrorKind::Conflict => ErrorCode::LockMismatch,
        DurableErrorKind::Io => ErrorCode::Io,
    };
    failure(stage, code, error.to_string())
}

fn safe_join(root: &Path, relative: &str) -> Result<PathBuf, TemplateFailure> {
    validate_relative(relative)?;
    let joined = root.join(relative);
    reject_symlink(&joined, "template.validate")?;
    let canonical = fs::canonicalize(&joined)
        .map_err(|error| io_failure("template.validate", &joined, error))?;
    if !canonical.starts_with(root) {
        return Err(failure(
            "template.validate",
            ErrorCode::PathEscape,
            "template path escapes its package",
        ));
    }
    Ok(canonical)
}

fn reject_symlink(path: &Path, stage: &'static str) -> Result<(), TemplateFailure> {
    let metadata = fs::symlink_metadata(path).map_err(|error| io_failure(stage, path, error))?;
    if metadata.file_type().is_symlink() {
        return Err(failure(
            stage,
            ErrorCode::SymlinkRejected,
            format!("template symlink rejected: {}", path.display()),
        ));
    }
    Ok(())
}

fn reject_hardlink(path: &Path, stage: &'static str) -> Result<(), TemplateFailure> {
    let metadata = fs::metadata(path).map_err(|error| io_failure(stage, path, error))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.is_file() && metadata.nlink() > 1 {
            return Err(failure(
                stage,
                ErrorCode::PathEscape,
                format!("template hardlink rejected: {}", path.display()),
            ));
        }
    }
    Ok(())
}

fn reject_symlink_components(
    context: &crate::CallContext,
    path: &Path,
    stage: &'static str,
) -> Result<(), TemplateFailure> {
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
            return Err(symlink_failure(stage, &current));
        }
    }
    Ok(())
}

fn reject_requested_symlink_suffix(
    context: &crate::CallContext,
    requested: &Path,
    canonical: &Path,
    stage: &'static str,
) -> Result<(), TemplateFailure> {
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
            return Err(symlink_failure(stage, &current));
        }
    }
    let observed =
        fs::canonicalize(&requested).map_err(|error| io_failure(stage, &requested, error))?;
    if observed != canonical {
        return Err(lock_failure(
            stage,
            "path identity changed during authorization",
        ));
    }
    Ok(())
}

fn sorted_directory_entries(
    directory: &Path,
    stage: &'static str,
) -> Result<Vec<PathBuf>, TemplateFailure> {
    let mut entries = fs::read_dir(directory)
        .map_err(|error| io_failure(stage, directory, error))?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| io_failure(stage, directory, error))?;
    entries.sort();
    Ok(entries)
}

fn ensure_directory(path: &Path, stage: &'static str) -> Result<(), TemplateFailure> {
    let metadata = fs::symlink_metadata(path).map_err(|error| io_failure(stage, path, error))?;
    if metadata.file_type().is_symlink() {
        return Err(symlink_failure(stage, path));
    }
    if !metadata.is_dir() {
        return Err(lock_failure(
            stage,
            format!("expected directory: {}", path.display()),
        ));
    }
    Ok(())
}

fn utf8_file_name<'a>(path: &'a Path, stage: &'static str) -> Result<&'a str, TemplateFailure> {
    path.file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            failure(
                stage,
                ErrorCode::InvalidRequest,
                format!("path has no UTF-8 filename: {}", path.display()),
            )
        })
}

fn symlink_failure(stage: &'static str, path: &Path) -> TemplateFailure {
    failure(
        stage,
        ErrorCode::SymlinkRejected,
        format!("template symlink rejected: {}", path.display()),
    )
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn validate_relative(value: &str) -> Result<(), TemplateFailure> {
    let path = Path::new(value);
    if value.is_empty()
        || path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir
                    | Component::CurDir
                    | Component::RootDir
                    | Component::Prefix(_)
            )
        })
    {
        return Err(failure(
            "template.validate",
            ErrorCode::PathEscape,
            format!("unsafe template path: {value}"),
        ));
    }
    Ok(())
}

fn validate_identifier(name: &str, value: &str) -> Result<(), TemplateFailure> {
    if value.is_empty()
        || matches!(value, "." | "..")
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(failure(
            "template.validate",
            ErrorCode::InvalidRequest,
            format!("invalid {name}: {value}"),
        ));
    }
    Ok(())
}

fn validate_version(value: &str) -> Result<(), TemplateFailure> {
    validate_identifier("version", value)?;
    if matches!(
        value.to_ascii_lowercase().as_str(),
        "latest" | "current" | "main" | "head"
    ) {
        return Err(failure(
            "template.resolve",
            ErrorCode::InvalidRequest,
            "floating template versions are forbidden",
        ));
    }
    Ok(())
}

fn validate_digest(value: &str) -> Result<(), TemplateFailure> {
    if value.len() != 71
        || !value.starts_with("sha256:")
        || !value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(lock_failure(
            "template.validate",
            "invalid template sha256 digest",
        ));
    }
    Ok(())
}

fn context_failure(error: crate::ContextError) -> TemplateFailure {
    let code = match error {
        crate::ContextError::PathEscape(_) | crate::ContextError::UnsafeRoot(_) => {
            ErrorCode::PathEscape
        }
        crate::ContextError::MissingRoot | crate::ContextError::InvalidReceipt(_) => {
            ErrorCode::InvalidRequest
        }
        crate::ContextError::RootIo { .. } => ErrorCode::Io,
    };
    failure("template.authorization", code, error.to_string())
}

fn io_failure(stage: &'static str, path: &Path, error: impl std::fmt::Display) -> TemplateFailure {
    TemplateFailure {
        code: ErrorCode::Io,
        stage,
        message: format!("{}: {error}", path.display()),
        recovery_hint: "verify the exact template catalog and workspace permissions",
    }
}

fn lock_failure(stage: &'static str, message: impl Into<String>) -> TemplateFailure {
    failure(stage, ErrorCode::LockMismatch, message)
}

fn failure(stage: &'static str, code: ErrorCode, message: impl Into<String>) -> TemplateFailure {
    TemplateFailure {
        code,
        stage,
        message: message.into(),
        recovery_hint: "resolve and validate an exact immutable template package",
    }
}
