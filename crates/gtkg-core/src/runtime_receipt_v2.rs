//! T14A local runtime receipt boundary.
//!
//! This records a completed *local* lifecycle readback without promoting it
//! to an external Current activation, Release, or provider receipt. The
//! receipt and event are immutable files, so another local process can inspect
//! the exact authority and verifier identity used by this run.

use std::fs;
use std::path::{Component, Path, PathBuf};

use gtkg_protocol::{canonical_json_sha256, validate_path_identifier, validate_sha256};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::CallContext;
use crate::durable::{DurableErrorKind, publish_immutable_json};
use crate::lifecycle_v2::{
    ExactReadbackStatusV2, PostActivationReadbackReceiptV2, SelectionReceiptV2,
};

pub const LOCAL_RUNTIME_RECEIPT_SCHEMA_V2: &str = "gtkg.local-runtime-receipt/v2";
pub const LOCAL_RUNTIME_EVENT_SCHEMA_V2: &str = "gtkg.local-runtime-event/v2";

/// Deliberately narrower than public `current.activate` authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalRuntimeAuthorityV2 {
    pub authority_id: String,
    pub scope: String,
    pub external_current_activation: bool,
    pub release_execution: bool,
    pub real_provider_execution: bool,
}

impl LocalRuntimeAuthorityV2 {
    pub fn local_development(authority_id: impl Into<String>) -> Self {
        Self {
            authority_id: authority_id.into(),
            scope: "local_development_only".to_owned(),
            external_current_activation: false,
            release_execution: false,
            real_provider_execution: false,
        }
    }

    fn validate(&self) -> Result<(), RuntimeReceiptErrorV2> {
        if validate_path_identifier("authority_id", &self.authority_id).is_err()
            || self.scope != "local_development_only"
            || self.external_current_activation
            || self.release_execution
            || self.real_provider_execution
        {
            return Err(RuntimeReceiptErrorV2::Invalid(
                "runtime authority must be local_development_only and non-release".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Immutable verifier identity, not a mutable display name or host setting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeVerifierIdentityV2 {
    pub verifier_id: String,
    pub verifier_sha256: String,
}

impl RuntimeVerifierIdentityV2 {
    fn validate(&self) -> Result<(), RuntimeReceiptErrorV2> {
        if validate_path_identifier("verifier_id", &self.verifier_id).is_err() {
            return Err(RuntimeReceiptErrorV2::Invalid(
                "verifier_id must be a safe immutable identifier".to_owned(),
            ));
        }
        validate_sha256(&self.verifier_sha256).map_err(|error| {
            RuntimeReceiptErrorV2::Invalid(format!("verifier_sha256 is invalid: {error}"))
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalRuntimeLifecycleReceiptV2 {
    pub schema_version: String,
    pub receipt_id: String,
    pub authority: LocalRuntimeAuthorityV2,
    pub verifier: RuntimeVerifierIdentityV2,
    pub selection: SelectionReceiptV2,
    pub readback: PostActivationReadbackReceiptV2,
}

impl LocalRuntimeLifecycleReceiptV2 {
    pub fn validate(&self) -> Result<(), RuntimeReceiptErrorV2> {
        if self.schema_version != LOCAL_RUNTIME_RECEIPT_SCHEMA_V2
            || validate_path_identifier("receipt_id", &self.receipt_id).is_err()
        {
            return Err(RuntimeReceiptErrorV2::Invalid(
                "runtime receipt schema or receipt_id is invalid".to_owned(),
            ));
        }
        self.authority.validate()?;
        self.verifier.validate()?;
        self.readback
            .validate()
            .map_err(|error| RuntimeReceiptErrorV2::Invalid(error.to_string()))?;
        for (field, digest) in [
            (
                "selection version bundle",
                &self.selection.version_bundle_sha256,
            ),
            (
                "selection lifecycle identity",
                &self.selection.lifecycle_identity_sha256,
            ),
        ] {
            validate_sha256(digest).map_err(|error| {
                RuntimeReceiptErrorV2::Invalid(format!("{field} digest is invalid: {error}"))
            })?;
        }
        if self.readback.status != ExactReadbackStatusV2::Passed
            || self.readback.expected_lifecycle_identity_sha256
                != self.selection.lifecycle_identity_sha256
            || self.readback.observed_lifecycle_identity_sha256
                != self.selection.lifecycle_identity_sha256
        {
            return Err(RuntimeReceiptErrorV2::Invalid(
                "runtime receipt must bind a selection to passed local readback".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn receipt_sha256(&self) -> Result<String, RuntimeReceiptErrorV2> {
        self.validate()?;
        canonical_json_sha256(self)
            .map_err(|error| RuntimeReceiptErrorV2::Invalid(format!("receipt digest: {error}")))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalRuntimeLifecycleEventV2 {
    pub schema_version: String,
    pub sequence: u64,
    pub receipt_id: String,
    pub receipt_sha256: String,
    pub authority_id: String,
    pub verifier_sha256: String,
    pub previous_event_sha256: Option<String>,
    pub event_sha256: String,
}

impl LocalRuntimeLifecycleEventV2 {
    fn validate(&self) -> Result<(), RuntimeReceiptErrorV2> {
        if self.schema_version != LOCAL_RUNTIME_EVENT_SCHEMA_V2
            || self.sequence != 0
            || validate_path_identifier("receipt_id", &self.receipt_id).is_err()
            || validate_path_identifier("authority_id", &self.authority_id).is_err()
            || self.previous_event_sha256.is_some()
        {
            return Err(RuntimeReceiptErrorV2::Invalid(
                "runtime event is not the immutable single-receipt local event shape".to_owned(),
            ));
        }
        for (field, digest) in [
            ("receipt_sha256", &self.receipt_sha256),
            ("verifier_sha256", &self.verifier_sha256),
        ] {
            validate_sha256(digest).map_err(|error| {
                RuntimeReceiptErrorV2::Invalid(format!("{field} is invalid: {error}"))
            })?;
        }
        if event_sha256(self)? != self.event_sha256 {
            return Err(RuntimeReceiptErrorV2::Invalid(
                "runtime event digest does not bind its exact receipt".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalRuntimeReceiptPathsV2 {
    pub receipt_path: PathBuf,
    pub event_path: PathBuf,
    pub event_sha256: String,
}

/// Independently read persisted T14A evidence.  This refuses a caller-created
/// in-memory receipt: both immutable files must parse, validate, and bind each
/// other before their authority or verifier identity is reusable.
pub fn read_local_runtime_lifecycle_receipt_v2(
    receipt_path: &Path,
    event_path: &Path,
) -> Result<LocalRuntimeLifecycleReceiptV2, RuntimeReceiptErrorV2> {
    let receipt_bytes = read_regular_file(receipt_path)?;
    let receipt: LocalRuntimeLifecycleReceiptV2 = serde_json::from_slice(&receipt_bytes)
        .map_err(|error| RuntimeReceiptErrorV2::Readback(format!("receipt JSON: {error}")))?;
    receipt.validate()?;
    let event_bytes = read_regular_file(event_path)?;
    let event: LocalRuntimeLifecycleEventV2 = serde_json::from_slice(&event_bytes)
        .map_err(|error| RuntimeReceiptErrorV2::Readback(format!("event JSON: {error}")))?;
    event.validate()?;
    if event.receipt_id != receipt.receipt_id
        || event.receipt_sha256 != receipt.receipt_sha256()?
        || event.authority_id != receipt.authority.authority_id
        || event.verifier_sha256 != receipt.verifier.verifier_sha256
    {
        return Err(RuntimeReceiptErrorV2::Readback(
            "persisted runtime event does not bind the exact receipt authority and verifier"
                .to_owned(),
        ));
    }
    Ok(receipt)
}

fn read_regular_file(path: &Path) -> Result<Vec<u8>, RuntimeReceiptErrorV2> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| RuntimeReceiptErrorV2::Readback(format!("{}: {error}", path.display())))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(RuntimeReceiptErrorV2::Readback(format!(
            "{} is not a regular non-symlink runtime evidence file",
            path.display()
        )));
    }
    fs::read(path)
        .map_err(|error| RuntimeReceiptErrorV2::Readback(format!("{}: {error}", path.display())))
}

/// Persist a receipt and an immutable event. It never writes `release/current`,
/// a network target, or a mutable shared ledger.
pub fn persist_local_runtime_lifecycle_receipt_v2(
    context: &CallContext,
    evidence_root: &Path,
    receipt: &LocalRuntimeLifecycleReceiptV2,
) -> Result<LocalRuntimeReceiptPathsV2, RuntimeReceiptErrorV2> {
    let components = evidence_root.components().collect::<Vec<_>>();
    let has_gtkg_root = components
        .iter()
        .any(|component| matches!(component, Component::Normal(part) if *part == ".gtkg"));
    let targets_release_or_current = components.iter().any(|component| {
        matches!(component, Component::Normal(part) if *part == "release" || *part == "current")
    });
    if !has_gtkg_root || targets_release_or_current {
        return Err(RuntimeReceiptErrorV2::Invalid(
            "local runtime evidence must stay below .gtkg and must not target release/current"
                .to_owned(),
        ));
    }
    let receipt_sha256 = receipt.receipt_sha256()?;
    let receipt_path = evidence_root
        .join("receipts")
        .join(format!("{}.json", receipt.receipt_id));
    let published_receipt = publish_immutable_json(
        context,
        &receipt_path,
        receipt,
        "t14a.runtime_receipt.after_temp_sync_before_rename",
    )
    .map_err(map_durable)?;
    let mut event = LocalRuntimeLifecycleEventV2 {
        schema_version: LOCAL_RUNTIME_EVENT_SCHEMA_V2.to_owned(),
        sequence: 0,
        receipt_id: receipt.receipt_id.clone(),
        receipt_sha256,
        authority_id: receipt.authority.authority_id.clone(),
        verifier_sha256: receipt.verifier.verifier_sha256.clone(),
        previous_event_sha256: None,
        event_sha256: String::new(),
    };
    event.event_sha256 = event_sha256(&event)?;
    event.validate()?;
    let event_name = event.event_sha256.strip_prefix("sha256:").ok_or_else(|| {
        RuntimeReceiptErrorV2::Invalid("event digest lost sha256 prefix".to_owned())
    })?;
    let event_path = evidence_root
        .join("events")
        .join(format!("{event_name}.json"));
    let published_event = publish_immutable_json(
        context,
        &event_path,
        &event,
        "t14a.runtime_event.after_temp_sync_before_rename",
    )
    .map_err(map_durable)?;
    Ok(LocalRuntimeReceiptPathsV2 {
        receipt_path: published_receipt,
        event_path: published_event,
        event_sha256: event.event_sha256,
    })
}

fn event_sha256(event: &LocalRuntimeLifecycleEventV2) -> Result<String, RuntimeReceiptErrorV2> {
    canonical_json_sha256(&serde_json::json!({
        "schema_version": event.schema_version,
        "sequence": event.sequence,
        "receipt_id": event.receipt_id,
        "receipt_sha256": event.receipt_sha256,
        "authority_id": event.authority_id,
        "verifier_sha256": event.verifier_sha256,
        "previous_event_sha256": event.previous_event_sha256,
    }))
    .map_err(|error| RuntimeReceiptErrorV2::Invalid(format!("event digest: {error}")))
}

fn map_durable(error: crate::durable::DurableWriteError) -> RuntimeReceiptErrorV2 {
    let code = match error.kind {
        DurableErrorKind::Conflict => "E_V2_RUNTIME_RECEIPT_CONFLICT",
        DurableErrorKind::Unauthorized | DurableErrorKind::Unsafe => {
            "E_V2_RUNTIME_RECEIPT_UNAUTHORIZED"
        }
        DurableErrorKind::Invalid => "E_V2_RUNTIME_RECEIPT_INVALID",
        DurableErrorKind::Io => "E_V2_RUNTIME_RECEIPT_IO",
    };
    RuntimeReceiptErrorV2::Persist(format!("{code}: {error}"))
}

#[derive(Debug, Error)]
pub enum RuntimeReceiptErrorV2 {
    #[error("invalid local runtime receipt: {0}")]
    Invalid(String),
    #[error("local runtime receipt persistence failed: {0}")]
    Persist(String),
    #[error("local runtime receipt readback failed: {0}")]
    Readback(String),
}
