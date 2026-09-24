//! V0.2 T13 local lifecycle, invalidation, Current/Replay, and migration.
//!
//! This is intentionally an in-memory, file-free model.  It binds the
//! immutable identities produced by T01/T05/T06/T07/T10/T11A/T11B and gives
//! callers deterministic invalidation and recovery decisions.  It does not
//! activate `release/current`, write a repository pointer, or contact an
//! external system; those remain separately authorised operations.

use std::collections::{BTreeMap, BTreeSet};

use gtkg_protocol::{canonical_json_sha256, validate_sha256};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use thiserror::Error;

pub const LIFECYCLE_SCHEMA_V2: &str = "gtkg.local-lifecycle/v2";

/// The seven immutable identities that T13 is allowed to connect.  Every
/// identity is a full `sha256:` digest, so a same-name artifact cannot be
/// substituted after an invalidation decision has been made.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleIdentityV2 {
    pub source_snapshot_exact_set_sha256: String,
    pub local_resolver_profile_sha256: String,
    pub document_relation_receipts_sha256: String,
    pub context_pack_sha256: String,
    pub claim_verification_receipt_sha256: String,
    pub structural_graph_sha256: String,
    pub knowledge_overlay_sha256: String,
}

impl LifecycleIdentityV2 {
    pub fn validate(&self) -> Result<(), LifecycleErrorV2> {
        for (name, digest) in [
            (
                "T01 source snapshot",
                &self.source_snapshot_exact_set_sha256,
            ),
            ("T05 resolver profile", &self.local_resolver_profile_sha256),
            (
                "T06 relation receipts",
                &self.document_relation_receipts_sha256,
            ),
            ("T07 context pack", &self.context_pack_sha256),
            (
                "T10 verification receipt",
                &self.claim_verification_receipt_sha256,
            ),
            ("T11A structural graph", &self.structural_graph_sha256),
            ("T11B knowledge overlay", &self.knowledge_overlay_sha256),
        ] {
            validate_sha256(digest).map_err(|error| {
                LifecycleErrorV2::InvalidInput(format!("{name} digest invalid: {error}"))
            })?;
        }
        Ok(())
    }

    pub fn identity_sha256(&self) -> Result<String, LifecycleErrorV2> {
        self.validate()?;
        canonical_json_sha256(self)
            .map_err(|error| LifecycleErrorV2::InvalidInput(format!("identity digest: {error}")))
    }
}

/// A mutation is stated at its first affected producer.  Consumers are
/// invalidated through the fixed dataflow, never through directory scanning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationKindV2 {
    SourceSnapshot,
    LocalResolver,
    DocumentRelations,
    ContextPack,
    ClaimVerification,
    StructuralGraph,
    KnowledgeOverlay,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactStageV2 {
    T01SourceSnapshot,
    T05LocalResolver,
    T06DocumentRelations,
    T07ContextPack,
    T10ClaimVerification,
    T11AStructuralGraph,
    T11BKnowledgeOverlay,
}

/// The exact, conservative invalidation closure for each mutation.  This is
/// public so a full rebuild and an incremental rebuild can be compared using
/// the same matrix rather than two subtly different implementations.
pub fn invalidation_closure_v2(mutation: MutationKindV2) -> BTreeSet<ArtifactStageV2> {
    use ArtifactStageV2::*;
    match mutation {
        MutationKindV2::SourceSnapshot => [
            T01SourceSnapshot,
            T05LocalResolver,
            T06DocumentRelations,
            T07ContextPack,
            T10ClaimVerification,
            T11AStructuralGraph,
            T11BKnowledgeOverlay,
        ]
        .into_iter()
        .collect(),
        MutationKindV2::LocalResolver => [
            T05LocalResolver,
            T10ClaimVerification,
            T11AStructuralGraph,
            T11BKnowledgeOverlay,
        ]
        .into_iter()
        .collect(),
        MutationKindV2::DocumentRelations => [
            T06DocumentRelations,
            T11AStructuralGraph,
            T11BKnowledgeOverlay,
        ]
        .into_iter()
        .collect(),
        MutationKindV2::ContextPack => [T07ContextPack, T10ClaimVerification, T11BKnowledgeOverlay]
            .into_iter()
            .collect(),
        MutationKindV2::ClaimVerification => [T10ClaimVerification, T11BKnowledgeOverlay]
            .into_iter()
            .collect(),
        MutationKindV2::StructuralGraph => [T11AStructuralGraph, T11BKnowledgeOverlay]
            .into_iter()
            .collect(),
        MutationKindV2::KnowledgeOverlay => [T11BKnowledgeOverlay].into_iter().collect(),
    }
}

/// A deterministic comparison record.  Incremental mode is accepted only
/// when it produces exactly the same identity as a full rebuild for the same
/// mutation closure; a merely equivalent display or file name is insufficient.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RebuildEqualityV2 {
    pub mutation: MutationKindV2,
    pub invalidated_stages: BTreeSet<ArtifactStageV2>,
    pub full_identity_sha256: String,
    pub incremental_identity_sha256: String,
    pub equal: bool,
}

pub fn compare_full_and_incremental_v2(
    mutation: MutationKindV2,
    full: &LifecycleIdentityV2,
    incremental: &LifecycleIdentityV2,
) -> Result<RebuildEqualityV2, LifecycleErrorV2> {
    let full_identity_sha256 = full.identity_sha256()?;
    let incremental_identity_sha256 = incremental.identity_sha256()?;
    Ok(RebuildEqualityV2 {
        mutation,
        invalidated_stages: invalidation_closure_v2(mutation),
        equal: full_identity_sha256 == incremental_identity_sha256,
        full_identity_sha256,
        incremental_identity_sha256,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BundleFormatV2 {
    V1,
    V2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BundleDispositionV2 {
    CurrentEligible,
    ReplayOnly,
    Quarantined,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalVersionV2 {
    pub version_id: String,
    pub format: BundleFormatV2,
    pub immutable_bundle_sha256: String,
    pub identity: LifecycleIdentityV2,
    pub disposition: BundleDispositionV2,
}

impl LocalVersionV2 {
    pub fn validate(&self) -> Result<(), LifecycleErrorV2> {
        if self.version_id.is_empty()
            || self.version_id.contains('/')
            || self.version_id.contains("..")
            || matches!(self.version_id.as_str(), "current" | "latest" | "HEAD")
        {
            return Err(LifecycleErrorV2::InvalidInput(
                "version_id must be immutable and non-floating".to_owned(),
            ));
        }
        validate_sha256(&self.immutable_bundle_sha256).map_err(|error| {
            LifecycleErrorV2::InvalidInput(format!("bundle digest invalid: {error}"))
        })?;
        self.identity.validate()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum ArtifactSelectorV2 {
    Current { expected_current_sha256: String },
    Replay { version_id: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentPointerV2 {
    pub schema_version: String,
    pub version_id: String,
    pub version_bundle_sha256: String,
    pub lifecycle_identity_sha256: String,
}

impl CurrentPointerV2 {
    pub fn digest(&self) -> Result<String, LifecycleErrorV2> {
        canonical_json_sha256(self)
            .map_err(|error| LifecycleErrorV2::InvalidInput(format!("current digest: {error}")))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectionReceiptV2 {
    pub selector: ArtifactSelectorV2,
    pub version_id: String,
    pub version_bundle_sha256: String,
    pub lifecycle_identity_sha256: String,
    /// `select` is read-only even when the selector is `current`.
    pub canonical_write_count: u64,
}

/// Typed exact readback evidence after a successful local CAS.  Recovery
/// cannot be authorised by a freely supplied boolean: it must bind both the
/// expected activation pointer and the independently observed pointer/identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExactReadbackStatusV2 {
    Passed,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostActivationReadbackReceiptV2 {
    pub schema_version: String,
    pub status: ExactReadbackStatusV2,
    pub expected_current_sha256: String,
    pub observed_current_sha256: String,
    pub expected_lifecycle_identity_sha256: String,
    pub observed_lifecycle_identity_sha256: String,
    pub failure_code: Option<String>,
}

impl PostActivationReadbackReceiptV2 {
    pub fn passed(
        current_sha256: String,
        lifecycle_identity_sha256: String,
    ) -> Result<Self, LifecycleErrorV2> {
        let receipt = Self {
            schema_version: "gtkg.post-activation-readback/v2".to_owned(),
            status: ExactReadbackStatusV2::Passed,
            expected_current_sha256: current_sha256.clone(),
            observed_current_sha256: current_sha256,
            expected_lifecycle_identity_sha256: lifecycle_identity_sha256.clone(),
            observed_lifecycle_identity_sha256: lifecycle_identity_sha256,
            failure_code: None,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn failed(
        expected_current_sha256: String,
        observed_current_sha256: String,
        expected_lifecycle_identity_sha256: String,
        observed_lifecycle_identity_sha256: String,
        failure_code: &str,
    ) -> Result<Self, LifecycleErrorV2> {
        let receipt = Self {
            schema_version: "gtkg.post-activation-readback/v2".to_owned(),
            status: ExactReadbackStatusV2::Failed,
            expected_current_sha256,
            observed_current_sha256,
            expected_lifecycle_identity_sha256,
            observed_lifecycle_identity_sha256,
            failure_code: Some(failure_code.to_owned()),
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn validate(&self) -> Result<(), LifecycleErrorV2> {
        if self.schema_version != "gtkg.post-activation-readback/v2" {
            return Err(LifecycleErrorV2::InvalidInput(
                "unsupported post-activation readback schema".to_owned(),
            ));
        }
        for (name, digest) in [
            ("expected CURRENT", &self.expected_current_sha256),
            ("observed CURRENT", &self.observed_current_sha256),
            (
                "expected lifecycle identity",
                &self.expected_lifecycle_identity_sha256,
            ),
            (
                "observed lifecycle identity",
                &self.observed_lifecycle_identity_sha256,
            ),
        ] {
            validate_sha256(digest).map_err(|error| {
                LifecycleErrorV2::InvalidInput(format!("{name} digest invalid: {error}"))
            })?;
        }
        match self.status {
            ExactReadbackStatusV2::Passed
                if self.failure_code.is_none()
                    && self.expected_current_sha256 == self.observed_current_sha256
                    && self.expected_lifecycle_identity_sha256
                        == self.observed_lifecycle_identity_sha256 =>
            {
                Ok(())
            }
            ExactReadbackStatusV2::Failed
                if self
                    .failure_code
                    .as_deref()
                    .is_some_and(|code| !code.trim().is_empty()) =>
            {
                Ok(())
            }
            _ => Err(LifecycleErrorV2::InvalidInput(
                "post-activation readback status and bindings conflict".to_owned(),
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalLifecycleStoreV2 {
    versions: BTreeMap<String, LocalVersionV2>,
    current: Option<CurrentPointerV2>,
    canonical_write_count: u64,
}

impl LocalLifecycleStoreV2 {
    pub fn new(
        versions: Vec<LocalVersionV2>,
        current_version_id: Option<&str>,
    ) -> Result<Self, LifecycleErrorV2> {
        let mut indexed = BTreeMap::new();
        for version in versions {
            version.validate()?;
            if indexed
                .insert(version.version_id.clone(), version)
                .is_some()
            {
                return Err(LifecycleErrorV2::InvalidInput(
                    "duplicate immutable version_id".to_owned(),
                ));
            }
        }
        let current = match current_version_id {
            Some(id) => {
                let version = indexed
                    .get(id)
                    .ok_or_else(|| LifecycleErrorV2::UnknownVersion(id.to_owned()))?;
                if version.disposition != BundleDispositionV2::CurrentEligible {
                    return Err(LifecycleErrorV2::NotCurrentEligible(id.to_owned()));
                }
                Some(pointer_for(version)?)
            }
            None => None,
        };
        Ok(Self {
            versions: indexed,
            current,
            canonical_write_count: 0,
        })
    }

    pub fn canonical_write_count(&self) -> u64 {
        self.canonical_write_count
    }

    pub fn current_digest(&self) -> Result<Option<String>, LifecycleErrorV2> {
        self.current
            .as_ref()
            .map(CurrentPointerV2::digest)
            .transpose()
    }

    pub fn select(
        &self,
        selector: ArtifactSelectorV2,
    ) -> Result<SelectionReceiptV2, LifecycleErrorV2> {
        let version = match &selector {
            ArtifactSelectorV2::Current {
                expected_current_sha256,
            } => {
                validate_sha256(expected_current_sha256).map_err(|error| {
                    LifecycleErrorV2::InvalidInput(format!(
                        "current selector digest invalid: {error}"
                    ))
                })?;
                let current = self
                    .current
                    .as_ref()
                    .ok_or(LifecycleErrorV2::CurrentMissing)?;
                if current.digest()? != *expected_current_sha256 {
                    return Err(LifecycleErrorV2::CasConflict);
                }
                self.versions
                    .get(&current.version_id)
                    .ok_or_else(|| LifecycleErrorV2::UnknownVersion(current.version_id.clone()))?
            }
            ArtifactSelectorV2::Replay { version_id } => self
                .versions
                .get(version_id)
                .ok_or_else(|| LifecycleErrorV2::UnknownVersion(version_id.clone()))?,
        };
        let identity = version.identity.identity_sha256()?;
        Ok(SelectionReceiptV2 {
            selector,
            version_id: version.version_id.clone(),
            version_bundle_sha256: version.immutable_bundle_sha256.clone(),
            lifecycle_identity_sha256: identity,
            canonical_write_count: self.canonical_write_count,
        })
    }

    /// Local CAS only. It is for deterministic recovery tests and does not
    /// route to the externally-authorised `current.activate` operation.
    pub fn activate_local_cas(
        &mut self,
        expected_current_sha256: &str,
        next_version_id: &str,
    ) -> Result<String, LifecycleErrorV2> {
        let observed = self
            .current_digest()?
            .ok_or(LifecycleErrorV2::CurrentMissing)?;
        if observed != expected_current_sha256 {
            return Err(LifecycleErrorV2::CasConflict);
        }
        let next = self
            .versions
            .get(next_version_id)
            .ok_or_else(|| LifecycleErrorV2::UnknownVersion(next_version_id.to_owned()))?;
        if next.disposition != BundleDispositionV2::CurrentEligible {
            return Err(LifecycleErrorV2::NotCurrentEligible(
                next_version_id.to_owned(),
            ));
        }
        self.current = Some(pointer_for(next)?);
        self.canonical_write_count += 1;
        self.current_digest()?
            .ok_or(LifecycleErrorV2::CurrentMissing)
    }

    /// Compensating rollback is allowed only after a successful local write
    /// whose post-write readback failed. The caller must CAS the exact new
    /// pointer; a concurrent pointer produces zero new writes.
    pub fn rollback_after_failed_readback_local(
        &mut self,
        receipt: &PostActivationReadbackReceiptV2,
        previous_version_id: &str,
        suspect_version_id: &str,
    ) -> Result<String, LifecycleErrorV2> {
        receipt.validate()?;
        if receipt.status != ExactReadbackStatusV2::Failed {
            return Err(LifecycleErrorV2::RollbackNotPermitted);
        }
        let observed = self
            .current_digest()?
            .ok_or(LifecycleErrorV2::CurrentMissing)?;
        if observed != receipt.observed_current_sha256 {
            return Err(LifecycleErrorV2::CasConflict);
        }
        let current = self
            .current
            .as_ref()
            .ok_or(LifecycleErrorV2::CurrentMissing)?;
        if current.version_id != suspect_version_id {
            return Err(LifecycleErrorV2::RollbackNotPermitted);
        }
        if current.digest()? != receipt.expected_current_sha256
            || current.lifecycle_identity_sha256 != receipt.expected_lifecycle_identity_sha256
            || current.lifecycle_identity_sha256 != receipt.observed_lifecycle_identity_sha256
        {
            return Err(LifecycleErrorV2::RollbackNotPermitted);
        }
        let previous = self
            .versions
            .get(previous_version_id)
            .ok_or_else(|| LifecycleErrorV2::UnknownVersion(previous_version_id.to_owned()))?;
        if previous.disposition != BundleDispositionV2::CurrentEligible {
            return Err(LifecycleErrorV2::NotCurrentEligible(
                previous_version_id.to_owned(),
            ));
        }
        self.current = Some(pointer_for(previous)?);
        self.canonical_write_count += 1;
        self.current_digest()?
            .ok_or(LifecycleErrorV2::CurrentMissing)
    }

    pub fn quarantine_version(&mut self, version_id: &str) -> Result<(), LifecycleErrorV2> {
        let version = self
            .versions
            .get_mut(version_id)
            .ok_or_else(|| LifecycleErrorV2::UnknownVersion(version_id.to_owned()))?;
        version.disposition = BundleDispositionV2::Quarantined;
        Ok(())
    }
}

fn pointer_for(version: &LocalVersionV2) -> Result<CurrentPointerV2, LifecycleErrorV2> {
    Ok(CurrentPointerV2 {
        schema_version: LIFECYCLE_SCHEMA_V2.to_owned(),
        version_id: version.version_id.clone(),
        version_bundle_sha256: version.immutable_bundle_sha256.clone(),
        lifecycle_identity_sha256: version.identity.identity_sha256()?,
    })
}

/// A v1 migration never changes the original bytes and never promotes legacy
/// semantic content.  The generated descriptor is replay-only until a fresh
/// v2 source rebuild supplies all current identities.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct V1ReplayMigrationV2 {
    pub schema_version: String,
    pub source_version_id: String,
    pub source_bundle_sha256: String,
    pub source_bytes_sha256: String,
    pub disposition: BundleDispositionV2,
    pub semantic_state: String,
    pub migration_gap: String,
}

pub fn migrate_v1_for_replay_v2(
    source_version_id: &str,
    source_bundle_sha256: &str,
    source_bytes: &[u8],
) -> Result<V1ReplayMigrationV2, LifecycleErrorV2> {
    validate_sha256(source_bundle_sha256).map_err(|error| {
        LifecycleErrorV2::InvalidInput(format!("v1 bundle digest invalid: {error}"))
    })?;
    if source_version_id.is_empty()
        || source_version_id.contains('/')
        || source_version_id.contains("..")
    {
        return Err(LifecycleErrorV2::InvalidInput(
            "v1 source version_id invalid".to_owned(),
        ));
    }
    let source_bytes_sha256 = format!("sha256:{:x}", sha2::Sha256::digest(source_bytes));
    Ok(V1ReplayMigrationV2 {
        schema_version: "gtkg.v1-replay-migration/v2".to_owned(),
        source_version_id: source_version_id.to_owned(),
        source_bundle_sha256: source_bundle_sha256.to_owned(),
        source_bytes_sha256,
        disposition: BundleDispositionV2::ReplayOnly,
        semantic_state: "not_proven".to_owned(),
        migration_gap: "fresh_v2_source_rebuild_required".to_owned(),
    })
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum LifecycleErrorV2 {
    #[error("invalid T13 lifecycle input: {0}")]
    InvalidInput(String),
    #[error("unknown immutable version: {0}")]
    UnknownVersion(String),
    #[error("CURRENT is not initialized")]
    CurrentMissing,
    #[error("CURRENT CAS conflict")]
    CasConflict,
    #[error("version is not current-eligible: {0}")]
    NotCurrentEligible(String),
    #[error("rollback is only allowed after a successful write with failed exact readback")]
    RollbackNotPermitted,
}

impl LifecycleErrorV2 {
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidInput(_) => "E_V2_LIFECYCLE_INVALID_INPUT",
            Self::UnknownVersion(_) => "E_V2_LIFECYCLE_UNKNOWN_VERSION",
            Self::CurrentMissing => "E_V2_LIFECYCLE_CURRENT_MISSING",
            Self::CasConflict => "E_V2_LIFECYCLE_CAS_CONFLICT",
            Self::NotCurrentEligible(_) => "E_V2_LIFECYCLE_NOT_CURRENT_ELIGIBLE",
            Self::RollbackNotPermitted => "E_V2_LIFECYCLE_ROLLBACK_NOT_PERMITTED",
        }
    }
}
