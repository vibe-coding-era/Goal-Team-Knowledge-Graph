//! I01 read-only identity lifecycle join.
//!
//! This module never activates Current, changes a canonical pointer, writes a
//! replay, or invokes an installer.  It validates a local candidate selector
//! against the already source-bound I00 provenance and the frozen Q06/D03
//! query/profile projections, then compares every downstream identity before
//! a caller may use the candidate elsewhere.

use std::path::{Path, PathBuf};

use gtkg_protocol::FileReceiptRef;
use gtkg_protocol::canonical_json_sha256;
use gtkg_protocol::v03::discovery_profiles_v03;
use gtkg_protocol::v03::query::{
    FileQueryExpectedIdentitiesV1, FileQueryRequestV1, QueryIndexEquivalenceIdentityErrorV1,
    QueryIndexEquivalenceIdentityV1,
};
#[cfg(feature = "test-faults")]
use gtkg_protocol::validate_sha256;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::CallContext;
use crate::exact_read::read_bound_regular_file;
#[cfg(feature = "test-faults")]
use crate::v03::installer::InstallActionV1;
use crate::v03::installer::{
    InstallManifestV1, InstallReceiptV1, IsolatedInstallRootV1,
    read_isolated_install_identity_with_capability_v1,
};
use crate::v03::lifecycle::read_source_bound_identity_v2;
#[cfg(feature = "test-faults")]
use crate::v03::lifecycle::{
    LifecycleFailureV1, validate_migration_rebuild_provenance_source_bound_v2,
};
use crate::v03::query::inspect_file_query_index_v1;

#[cfg(feature = "test-faults")]
pub const IDENTITY_LIFECYCLE_CANDIDATE_SCHEMA_V1: &str = "gtkg.identity-lifecycle-candidate/v1";
#[cfg(feature = "test-faults")]
pub const IDENTITY_LIFECYCLE_RECEIPT_SCHEMA_V1: &str = "gtkg.identity-lifecycle-receipt/v1";
pub const IDENTITY_LIFECYCLE_READBACK_RECEIPT_SCHEMA_V2: &str =
    "gtkg.identity-lifecycle-readback-receipt/v2";

/// Every member of the Current-selector identity tuple is compared separately
/// so callers receive a precise stale result rather than an auto-upgrade.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityLifecycleStaleComponentV1 {
    MigrationProvenance,
    Source,
    Bundle,
    Adapter,
    Graph,
    Overlay,
    Index,
    Binary,
    Profile,
    InstallManifest,
    InstallReceipt,
}

/// A read-only candidate selector.  The fields are digest identities only;
/// they are not a license to discover, rebuild, install, or activate content.
#[cfg(feature = "test-faults")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityLifecycleCandidateV1 {
    pub schema_version: String,
    pub migration_provenance_ref: FileReceiptRef,
    pub source_identity: String,
    pub bundle_identity: String,
    pub adapter_identity: String,
    pub graph_identity: String,
    pub overlay_identity: String,
    pub index_manifest_ref: FileReceiptRef,
    pub index_manifest_identity: String,
    pub binary_identity: String,
    pub profile_id: String,
    pub profile_digest: String,
    pub install_manifest: InstallManifestV1,
    pub install_manifest_identity: String,
    pub install_receipt: InstallReceiptV1,
    pub install_receipt_identity: String,
    pub current_activation: bool,
    pub current_write_count: u64,
    pub canonical_write_count: u64,
    pub replay_write_count: u64,
    pub candidate_sha256: String,
}

/// Durable, local-only confirmation returned only after all checks succeed.
#[cfg(feature = "test-faults")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityLifecycleReceiptV1 {
    pub schema_version: String,
    pub candidate_sha256: String,
    pub migration_provenance_sha256: String,
    pub a06_source_attestation_sha256: String,
    pub a06_gate_receipt_sha256: String,
    pub current_activation: bool,
    pub current_write_count: u64,
    pub canonical_write_count: u64,
    pub replay_write_count: u64,
}

/// A strict I01 successor input.  It carries handles and exact references for
/// secure readback; it intentionally has no caller-supplied source, adapter,
/// graph, overlay, index, binary, or install digest authority.
pub struct IdentityLifecycleReadbackInputV2<'a> {
    pub migration_provenance_ref: FileReceiptRef,
    pub profile_id: String,
    pub profile_digest: String,
    pub index_root: PathBuf,
    pub index_manifest_ref: FileReceiptRef,
    pub index_request: FileQueryRequestV1,
    pub isolated_install_root: &'a IsolatedInstallRootV1,
    pub install_manifest: InstallManifestV1,
    pub install_receipt: InstallReceiptV1,
}

/// Artifact identities discovered from secure I00/Q06/U01 readback.  This is
/// local Development evidence only and never represents an activated Current.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityLifecycleReadbackReceiptV2 {
    pub schema_version: String,
    pub migration_provenance_sha256: String,
    pub source_identity: String,
    pub bundle_identity: String,
    pub adapter_replay_identity: String,
    pub graph_identity: String,
    pub overlay_identity: String,
    pub index_receipt_sha256: String,
    pub index_manifest_sha256: String,
    pub binary_sha256: String,
    pub profile_id: String,
    pub profile_digest: String,
    pub install_manifest_sha256: String,
    pub install_receipt_sha256: String,
    pub current_activation: bool,
    pub current_write_count: u64,
    pub canonical_write_count: u64,
    pub replay_write_count: u64,
}

#[derive(Debug, Error)]
pub enum IdentityLifecycleErrorV1 {
    #[error("I01 candidate schema is unsupported")]
    UnsupportedSchema,
    #[error("I01 {field} is not a valid identity")]
    InvalidIdentity { field: &'static str },
    #[error("I01 profile is unknown or its frozen digest differs")]
    InvalidProfile,
    #[error("I01 candidate digest is invalid")]
    CandidateDigestMismatch,
    #[error("I01 candidate attempts Current/canonical/Replay side effects")]
    SideEffectAttempt,
    #[error("I01 identity is stale: {component:?}")]
    Stale {
        component: IdentityLifecycleStaleComponentV1,
        expected: String,
        observed: String,
    },
    #[error("I01 identity serialization failed")]
    Serialization,
    #[error("I01 could not revalidate source-bound migration provenance at {stage}: {message}")]
    MigrationRead {
        stage: &'static str,
        message: String,
    },
    #[error(transparent)]
    QueryIdentity(#[from] QueryIndexEquivalenceIdentityErrorV1),
}

#[cfg(feature = "test-faults")]
impl IdentityLifecycleCandidateV1 {
    /// Seals an in-memory, read-only selector candidate.  The digest covers
    /// all fields except itself and does not turn the object into a Current
    /// write or a trusted upstream receipt.
    pub fn seal(mut self) -> Result<Self, IdentityLifecycleErrorV1> {
        self.candidate_sha256 = self.content_sha256()?;
        self.validate_unbound_shape()?;
        Ok(self)
    }

    pub fn validate_shape(&self) -> Result<(), IdentityLifecycleErrorV1> {
        self.validate_unbound_shape()?;
        if self.index_manifest_ref.sha256 != self.index_manifest_identity
            || install_manifest_sha256(&self.install_manifest)? != self.install_manifest_identity
            || self.install_receipt.manifest_sha256 != self.install_manifest_identity
            || !matches!(
                self.install_receipt.action,
                InstallActionV1::Install | InstallActionV1::Upgrade | InstallActionV1::Rollback
            )
            || !self.install_receipt.readback_verified
            || self.install_receipt_identity
                != canonical_json_sha256(&self.install_receipt)
                    .map_err(|_| IdentityLifecycleErrorV1::Serialization)?
            || self.install_manifest.digests.get("bin/gtkg") != Some(&self.binary_identity)
        {
            return Err(IdentityLifecycleErrorV1::CandidateDigestMismatch);
        }
        if !discovery_profiles_v03().into_iter().any(|profile| {
            profile.profile_id.as_str() == self.profile_id && profile.digest == self.profile_digest
        }) {
            return Err(IdentityLifecycleErrorV1::InvalidProfile);
        }
        Ok(())
    }

    fn validate_unbound_shape(&self) -> Result<(), IdentityLifecycleErrorV1> {
        if self.schema_version != IDENTITY_LIFECYCLE_CANDIDATE_SCHEMA_V1 {
            return Err(IdentityLifecycleErrorV1::UnsupportedSchema);
        }
        self.migration_provenance_ref.validate().map_err(|_| {
            IdentityLifecycleErrorV1::InvalidIdentity {
                field: "migration_provenance_ref",
            }
        })?;
        self.index_manifest_ref.validate().map_err(|_| {
            IdentityLifecycleErrorV1::InvalidIdentity {
                field: "index_manifest_ref",
            }
        })?;
        for (field, value) in [
            ("source_identity", self.source_identity.as_str()),
            ("bundle_identity", self.bundle_identity.as_str()),
            ("adapter_identity", self.adapter_identity.as_str()),
            ("graph_identity", self.graph_identity.as_str()),
            ("overlay_identity", self.overlay_identity.as_str()),
            (
                "index_manifest_identity",
                self.index_manifest_identity.as_str(),
            ),
            ("binary_identity", self.binary_identity.as_str()),
            ("profile_digest", self.profile_digest.as_str()),
            (
                "install_manifest_identity",
                self.install_manifest_identity.as_str(),
            ),
            (
                "install_receipt_identity",
                self.install_receipt_identity.as_str(),
            ),
            ("candidate_sha256", self.candidate_sha256.as_str()),
        ] {
            validate_sha256(value)
                .map_err(|_| IdentityLifecycleErrorV1::InvalidIdentity { field })?;
        }
        if self.profile_id.is_empty() {
            return Err(IdentityLifecycleErrorV1::InvalidProfile);
        }
        if self.current_activation
            || self.current_write_count != 0
            || self.canonical_write_count != 0
            || self.replay_write_count != 0
        {
            return Err(IdentityLifecycleErrorV1::SideEffectAttempt);
        }
        if self.candidate_sha256 != self.content_sha256()? {
            return Err(IdentityLifecycleErrorV1::CandidateDigestMismatch);
        }
        Ok(())
    }

    fn content_sha256(&self) -> Result<String, IdentityLifecycleErrorV1> {
        let mut value =
            serde_json::to_value(self).map_err(|_| IdentityLifecycleErrorV1::Serialization)?;
        value
            .as_object_mut()
            .expect("candidate serializes to an object")
            .remove("candidate_sha256");
        canonical_json_sha256(&value).map_err(|_| IdentityLifecycleErrorV1::Serialization)
    }
}

/// Validates a candidate's source-bound I00 provenance, its frozen Q06
/// graph/overlay projection, and all downstream selector identities.  This
/// operation only reads the I00 provenance; it intentionally has no Current,
/// installer, replay, or network path.
#[cfg(feature = "test-faults")]
pub fn verify_identity_lifecycle_join_v1(
    context: &CallContext,
    workspace_root: &Path,
    expected: &IdentityLifecycleCandidateV1,
    observed: &IdentityLifecycleCandidateV1,
) -> Result<IdentityLifecycleReceiptV1, IdentityLifecycleErrorV1> {
    expected.validate_shape()?;
    observed.validate_unbound_shape()?;
    let provenance = validate_migration_rebuild_provenance_source_bound_v2(
        context,
        workspace_root,
        &expected.migration_provenance_ref,
    )
    .map_err(migration_error)?;
    let provenance_ref = provenance.file_receipt_ref().map_err(migration_error)?;
    compare(
        IdentityLifecycleStaleComponentV1::MigrationProvenance,
        &expected.migration_provenance_ref.sha256,
        &provenance_ref.sha256,
    )?;
    compare(
        IdentityLifecycleStaleComponentV1::Source,
        &expected.source_identity,
        provenance.rebuilt_source_snapshot_exact_set_sha256(),
    )?;
    compare(
        IdentityLifecycleStaleComponentV1::Bundle,
        &expected.bundle_identity,
        provenance.rebuilt_bundle_sha256(),
    )?;

    let query_identity = QueryIndexEquivalenceIdentityV1::new(
        expected.source_identity.clone(),
        expected.adapter_identity.clone(),
        expected.profile_digest.clone(),
    )?;
    let projected = query_identity.file_query_expected_identities()?;
    compare(
        IdentityLifecycleStaleComponentV1::Graph,
        &expected.graph_identity,
        &projected.graph_identity,
    )?;
    compare(
        IdentityLifecycleStaleComponentV1::Overlay,
        &expected.overlay_identity,
        &projected.overlay_identity,
    )?;
    if expected.profile_id != observed.profile_id {
        return Err(IdentityLifecycleErrorV1::Stale {
            component: IdentityLifecycleStaleComponentV1::Profile,
            expected: expected.profile_id.clone(),
            observed: observed.profile_id.clone(),
        });
    }
    if expected.migration_provenance_ref != observed.migration_provenance_ref {
        return Err(IdentityLifecycleErrorV1::Stale {
            component: IdentityLifecycleStaleComponentV1::MigrationProvenance,
            expected: receipt_ref_identity(&expected.migration_provenance_ref),
            observed: receipt_ref_identity(&observed.migration_provenance_ref),
        });
    }
    if expected.index_manifest_ref != observed.index_manifest_ref {
        return Err(IdentityLifecycleErrorV1::Stale {
            component: IdentityLifecycleStaleComponentV1::Index,
            expected: receipt_ref_identity(&expected.index_manifest_ref),
            observed: receipt_ref_identity(&observed.index_manifest_ref),
        });
    }

    for (component, expected_value, observed_value) in [
        (
            IdentityLifecycleStaleComponentV1::MigrationProvenance,
            expected.migration_provenance_ref.sha256.as_str(),
            observed.migration_provenance_ref.sha256.as_str(),
        ),
        (
            IdentityLifecycleStaleComponentV1::Source,
            expected.source_identity.as_str(),
            observed.source_identity.as_str(),
        ),
        (
            IdentityLifecycleStaleComponentV1::Bundle,
            expected.bundle_identity.as_str(),
            observed.bundle_identity.as_str(),
        ),
        (
            IdentityLifecycleStaleComponentV1::Adapter,
            expected.adapter_identity.as_str(),
            observed.adapter_identity.as_str(),
        ),
        (
            IdentityLifecycleStaleComponentV1::Graph,
            expected.graph_identity.as_str(),
            observed.graph_identity.as_str(),
        ),
        (
            IdentityLifecycleStaleComponentV1::Overlay,
            expected.overlay_identity.as_str(),
            observed.overlay_identity.as_str(),
        ),
        (
            IdentityLifecycleStaleComponentV1::Index,
            expected.index_manifest_identity.as_str(),
            observed.index_manifest_identity.as_str(),
        ),
        (
            IdentityLifecycleStaleComponentV1::Binary,
            expected.binary_identity.as_str(),
            observed.binary_identity.as_str(),
        ),
        (
            IdentityLifecycleStaleComponentV1::Profile,
            expected.profile_digest.as_str(),
            observed.profile_digest.as_str(),
        ),
        (
            IdentityLifecycleStaleComponentV1::InstallManifest,
            expected.install_manifest_identity.as_str(),
            observed.install_manifest_identity.as_str(),
        ),
        (
            IdentityLifecycleStaleComponentV1::InstallReceipt,
            expected.install_receipt_identity.as_str(),
            observed.install_receipt_identity.as_str(),
        ),
    ] {
        compare(component, expected_value, observed_value)?;
    }

    Ok(IdentityLifecycleReceiptV1 {
        schema_version: IDENTITY_LIFECYCLE_RECEIPT_SCHEMA_V1.to_owned(),
        candidate_sha256: expected.candidate_sha256.clone(),
        migration_provenance_sha256: expected.migration_provenance_ref.sha256.clone(),
        a06_source_attestation_sha256: provenance.a06_source_attestation_sha256().to_owned(),
        a06_gate_receipt_sha256: provenance.a06_gate_receipt_sha256().to_owned(),
        current_activation: false,
        current_write_count: 0,
        canonical_write_count: 0,
        replay_write_count: 0,
    })
}

/// I01 r2 secure join.  Every accepted identity is obtained from a real
/// source-bound provenance, strict index inspection, and descriptor-bound
/// isolated-install readback.  No caller-provided digest tuple can replace
/// those reads, and the function has no Current, canonical, Replay, or write
/// path.
pub fn verify_identity_lifecycle_readback_v2(
    context: &CallContext,
    workspace_root: &Path,
    input: &IdentityLifecycleReadbackInputV2<'_>,
) -> Result<IdentityLifecycleReadbackReceiptV2, IdentityLifecycleErrorV1> {
    let provenance =
        read_source_bound_identity_v2(context, workspace_root, &input.migration_provenance_ref)
            .map_err(|_| {
                stale_component(
                    IdentityLifecycleStaleComponentV1::MigrationProvenance,
                    &input.migration_provenance_ref.sha256,
                    "secure_provenance_readback_failed",
                )
            })?;
    let profile = discovery_profiles_v03()
        .into_iter()
        .find(|profile| {
            profile.profile_id.as_str() == input.profile_id
                && profile.digest == input.profile_digest
        })
        .ok_or_else(|| {
            stale_component(
                IdentityLifecycleStaleComponentV1::Profile,
                "frozen_profile",
                &input.profile_digest,
            )
        })?;
    let query_identity = QueryIndexEquivalenceIdentityV1::new(
        provenance.source_identity.clone(),
        provenance.adapter_replay_identity.clone(),
        profile.digest.clone(),
    )?;
    let expected: FileQueryExpectedIdentitiesV1 =
        query_identity.file_query_expected_identities()?;
    let index = inspect_file_query_index_v1(
        context,
        &input.index_root,
        &input.index_manifest_ref,
        &expected,
        &input.index_request,
    )
    .map_err(|_| {
        stale_component(
            IdentityLifecycleStaleComponentV1::Index,
            &input.index_manifest_ref.sha256,
            "secure_index_readback_failed",
        )
    })?;
    let expected_binary = input
        .install_manifest
        .digests
        .get("bin/gtkg")
        .ok_or_else(|| {
            stale_component(
                IdentityLifecycleStaleComponentV1::InstallManifest,
                "manifest_bin_gtkg_digest",
                "missing",
            )
        })?;
    let supplied_manifest_sha256 = install_manifest_sha256(&input.install_manifest)?;
    compare(
        IdentityLifecycleStaleComponentV1::InstallManifest,
        &input.install_receipt.manifest_sha256,
        &supplied_manifest_sha256,
    )?;
    let binary_path = input.isolated_install_root.path().join("bin/gtkg");
    let binary = read_bound_regular_file(context, &binary_path).map_err(|_| {
        stale_component(
            IdentityLifecycleStaleComponentV1::Binary,
            expected_binary,
            "secure_binary_readback_failed",
        )
    })?;
    compare(
        IdentityLifecycleStaleComponentV1::Binary,
        expected_binary,
        &binary.sha256,
    )?;
    let install = read_isolated_install_identity_with_capability_v1(
        input.isolated_install_root,
        &input.install_manifest,
        &input.install_receipt,
    )
    .map_err(|_| {
        stale_component(
            IdentityLifecycleStaleComponentV1::InstallReceipt,
            &input.install_receipt.manifest_sha256,
            "descriptor_install_readback_failed",
        )
    })?;
    compare(
        IdentityLifecycleStaleComponentV1::InstallManifest,
        &input.install_receipt.manifest_sha256,
        &install.manifest_sha256,
    )?;
    compare(
        IdentityLifecycleStaleComponentV1::Binary,
        &install.binary_sha256,
        &binary.sha256,
    )?;
    let install_receipt_sha256 = canonical_json_sha256(&input.install_receipt)
        .map_err(|_| IdentityLifecycleErrorV1::Serialization)?;
    Ok(IdentityLifecycleReadbackReceiptV2 {
        schema_version: IDENTITY_LIFECYCLE_READBACK_RECEIPT_SCHEMA_V2.to_owned(),
        migration_provenance_sha256: provenance.provenance_ref.sha256,
        source_identity: provenance.source_identity,
        bundle_identity: provenance.bundle_identity,
        adapter_replay_identity: provenance.adapter_replay_identity,
        graph_identity: expected.graph_identity,
        overlay_identity: expected.overlay_identity,
        index_receipt_sha256: input.index_manifest_ref.sha256.clone(),
        index_manifest_sha256: index.index_manifest_sha256,
        binary_sha256: binary.sha256,
        profile_id: profile.profile_id.as_str().to_owned(),
        profile_digest: profile.digest,
        install_manifest_sha256: install.manifest_sha256,
        install_receipt_sha256,
        current_activation: false,
        current_write_count: 0,
        canonical_write_count: 0,
        replay_write_count: 0,
    })
}

#[cfg(feature = "test-faults")]
fn migration_error(error: LifecycleFailureV1) -> IdentityLifecycleErrorV1 {
    IdentityLifecycleErrorV1::MigrationRead {
        stage: error.stage,
        message: error.message,
    }
}

#[cfg(feature = "test-faults")]
fn receipt_ref_identity(reference: &FileReceiptRef) -> String {
    format!("{}:{}", reference.path, reference.sha256)
}

fn stale_component(
    component: IdentityLifecycleStaleComponentV1,
    expected: &str,
    observed: &str,
) -> IdentityLifecycleErrorV1 {
    IdentityLifecycleErrorV1::Stale {
        component,
        expected: expected.to_owned(),
        observed: observed.to_owned(),
    }
}

fn install_manifest_sha256(
    manifest: &InstallManifestV1,
) -> Result<String, IdentityLifecycleErrorV1> {
    let bytes =
        serde_json::to_vec(manifest).map_err(|_| IdentityLifecycleErrorV1::Serialization)?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
}

fn compare(
    component: IdentityLifecycleStaleComponentV1,
    expected: &str,
    observed: &str,
) -> Result<(), IdentityLifecycleErrorV1> {
    if expected == observed {
        Ok(())
    } else {
        Err(IdentityLifecycleErrorV1::Stale {
            component,
            expected: expected.to_owned(),
            observed: observed.to_owned(),
        })
    }
}
