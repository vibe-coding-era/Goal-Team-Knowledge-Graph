//! Closed A00 contracts for file-only external fact adapters.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use super::AdapterKindV1;
use crate::{canonical_json_sha256, validate_sha256};

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AdapterContractErrorV1 {
    #[error("adapter identity mismatch")]
    IdentityMismatch,
    #[error("adapter denominator is invalid")]
    DenominatorInvalid,
    #[error("adapter bundle is invalid")]
    BundleInvalid,
    #[error("adapter trust laundering detected")]
    TrustLaundering,
    #[error("verified receipt is invalid")]
    ReceiptInvalid,
}

impl AdapterContractErrorV1 {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::IdentityMismatch => "E_ADAPTER_IDENTITY_MISMATCH",
            Self::DenominatorInvalid => "E_ADAPTER_DENOMINATOR_INVALID",
            Self::BundleInvalid => "E_ADAPTER_BUNDLE_INVALID",
            Self::TrustLaundering => "E_TRUST_LAUNDERING",
            Self::ReceiptInvalid => "E_EXTERNAL_EVIDENCE_UNVERIFIED",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterDescriptorV1 {
    pub schema_version: String,
    pub adapter_id: String,
    pub kind: AdapterKindV1,
    pub adapter_version: String,
    pub schema_sha256: String,
    pub source_commit: String,
    pub license: String,
    pub capabilities: Vec<String>,
    pub trust_policy_id: String,
    pub descriptor_sha256: String,
}

impl AdapterDescriptorV1 {
    pub fn with_computed_digest(mut self) -> Result<Self, AdapterContractErrorV1> {
        self.validate_shape()?;
        self.descriptor_sha256 = digest_without(&self, "descriptor_sha256")
            .map_err(|_| AdapterContractErrorV1::IdentityMismatch)?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), AdapterContractErrorV1> {
        self.validate_shape()?;
        if self.descriptor_sha256
            != digest_without(self, "descriptor_sha256")
                .map_err(|_| AdapterContractErrorV1::IdentityMismatch)?
        {
            return Err(AdapterContractErrorV1::IdentityMismatch);
        }
        Ok(())
    }

    fn validate_shape(&self) -> Result<(), AdapterContractErrorV1> {
        if self.schema_version != "gtkg.adapter-descriptor/v1"
            || !local_id(&self.adapter_id)
            || !contract_id(&self.trust_policy_id)
            || !version(&self.adapter_version)
            || !commit(&self.source_commit)
            || validate_sha256(&self.schema_sha256).is_err()
            || self.license.trim().is_empty()
            || self.license.eq_ignore_ascii_case("unknown")
            || self.capabilities.is_empty()
            || self.capabilities.iter().any(|item| !local_id(item))
            || self.capabilities.iter().collect::<BTreeSet<_>>().len() != self.capabilities.len()
        {
            return Err(AdapterContractErrorV1::IdentityMismatch);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateFactStateV1 {
    CandidateExternal,
    Ambiguous,
    LocatorOnly,
}

impl CandidateFactStateV1 {
    pub const ALL: [Self; 3] = [Self::CandidateExternal, Self::Ambiguous, Self::LocatorOnly];
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CandidateExternal => "candidate_external",
            Self::Ambiguous => "ambiguous",
            Self::LocatorOnly => "locator_only",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FactTrustStateV1 {
    Unverified,
    Ambiguous,
    Inferred,
    Extracted,
}

impl FactTrustStateV1 {
    pub const ALL: [Self; 4] = [
        Self::Unverified,
        Self::Ambiguous,
        Self::Inferred,
        Self::Extracted,
    ];
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unverified => "unverified",
            Self::Ambiguous => "ambiguous",
            Self::Inferred => "inferred",
            Self::Extracted => "extracted",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalEvidenceV1 {
    pub evidence_id: String,
    pub source_snapshot_sha256: String,
    pub source_logical_path: String,
    pub source_bytes_sha256: String,
    pub byte_start: u64,
    pub byte_end: u64,
    pub snippet_sha256: String,
    pub observed_trust: FactTrustStateV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalNodeFactV1 {
    pub fact_id: String,
    pub node_id: String,
    pub node_kind: String,
    pub name: String,
    pub candidate_state: CandidateFactStateV1,
    pub trust_state: FactTrustStateV1,
    pub evidence_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalEdgeFactV1 {
    pub fact_id: String,
    pub edge_id: String,
    pub edge_kind: String,
    pub source_node_id: String,
    pub target_reference: String,
    pub candidate_node_ids: Vec<String>,
    pub candidate_state: CandidateFactStateV1,
    pub trust_state: FactTrustStateV1,
    pub evidence_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalFactOmissionV1 {
    pub omitted_id: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalFactBundleV1 {
    pub schema_version: String,
    pub source_snapshot_sha256: String,
    pub adapter_descriptor_sha256: String,
    pub nodes: Vec<ExternalNodeFactV1>,
    pub edges: Vec<ExternalEdgeFactV1>,
    pub evidence: Vec<ExternalEvidenceV1>,
    pub candidate_states: Vec<CandidateFactStateV1>,
    pub discovered_count: u64,
    pub admitted_count: u64,
    pub omitted_count: u64,
    pub omissions: Vec<ExternalFactOmissionV1>,
    pub bundle_sha256: String,
}

impl ExternalFactBundleV1 {
    pub fn with_computed_digest(mut self) -> Result<Self, AdapterContractErrorV1> {
        self.validate_shape()?;
        self.bundle_sha256 = digest_without(&self, "bundle_sha256")
            .map_err(|_| AdapterContractErrorV1::BundleInvalid)?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), AdapterContractErrorV1> {
        self.validate_shape()?;
        if self.bundle_sha256
            != digest_without(self, "bundle_sha256")
                .map_err(|_| AdapterContractErrorV1::BundleInvalid)?
        {
            return Err(AdapterContractErrorV1::IdentityMismatch);
        }
        Ok(())
    }

    fn validate_shape(&self) -> Result<(), AdapterContractErrorV1> {
        if self.schema_version != "gtkg.external-fact-bundle/v1"
            || validate_sha256(&self.source_snapshot_sha256).is_err()
            || validate_sha256(&self.adapter_descriptor_sha256).is_err()
        {
            return Err(AdapterContractErrorV1::BundleInvalid);
        }
        if self.discovered_count != self.admitted_count + self.omitted_count
            || self.admitted_count != (self.nodes.len() + self.edges.len()) as u64
            || self.omitted_count != self.omissions.len() as u64
        {
            return Err(AdapterContractErrorV1::DenominatorInvalid);
        }
        let fact_ids = self
            .nodes
            .iter()
            .map(|item| item.fact_id.as_str())
            .chain(self.edges.iter().map(|item| item.fact_id.as_str()))
            .collect::<Vec<_>>();
        let evidence_ids = self
            .evidence
            .iter()
            .map(|item| item.evidence_id.as_str())
            .collect::<Vec<_>>();
        let omission_ids = self
            .omissions
            .iter()
            .map(|item| item.omitted_id.as_str())
            .collect::<Vec<_>>();
        let actual_candidate_states = self
            .nodes
            .iter()
            .map(|item| item.candidate_state)
            .chain(self.edges.iter().map(|item| item.candidate_state))
            .collect::<BTreeSet<_>>();
        let declared_candidate_states = self
            .candidate_states
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        if fact_ids.iter().any(|id| !local_id(id))
            || fact_ids.iter().copied().collect::<BTreeSet<_>>().len() != fact_ids.len()
            || evidence_ids.iter().any(|id| !local_id(id))
            || evidence_ids.iter().copied().collect::<BTreeSet<_>>().len() != evidence_ids.len()
            || omission_ids.iter().any(|id| !local_id(id))
            || omission_ids.iter().copied().collect::<BTreeSet<_>>().len() != omission_ids.len()
            || omission_ids.iter().any(|id| fact_ids.contains(id))
            || declared_candidate_states.len() != self.candidate_states.len()
            || declared_candidate_states != actual_candidate_states
            || self.evidence.iter().any(|item| {
                !local_id(&item.evidence_id)
                    || item.source_logical_path.is_empty()
                    || item.source_logical_path.starts_with('/')
                    || item.source_logical_path.contains("..")
                    || validate_sha256(&item.source_snapshot_sha256).is_err()
                    || item.source_snapshot_sha256 != self.source_snapshot_sha256
                    || validate_sha256(&item.source_bytes_sha256).is_err()
                    || validate_sha256(&item.snippet_sha256).is_err()
                    || item.byte_start >= item.byte_end
            })
            || self
                .omissions
                .iter()
                .any(|item| !local_id(&item.omitted_id) || item.reason.trim().is_empty())
        {
            return Err(AdapterContractErrorV1::BundleInvalid);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifiedResolutionV1 {
    ResolvedVerified,
    Ambiguous,
    LocatorOnly,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedFactReceiptV1 {
    pub schema_version: String,
    pub fact_id: String,
    pub resolution: VerifiedResolutionV1,
    pub reason: String,
    pub source_snapshot_sha256: String,
    pub adapter_descriptor_sha256: String,
    pub bundle_sha256: String,
    pub source_replay_sha256: String,
    pub source_spans: Vec<VerifiedSourceSpanV1>,
    pub evidence_ids: Vec<String>,
    pub verifier_identity: String,
    pub receipt_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedSourceSpanV1 {
    pub evidence_id: String,
    pub source_logical_path: String,
    pub source_bytes_sha256: String,
    pub byte_start: u64,
    pub byte_end: u64,
    pub snippet_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedFactReceiptInputV1 {
    pub fact_id: String,
    pub resolution: VerifiedResolutionV1,
    pub reason: String,
    pub source_snapshot_sha256: String,
    pub adapter_descriptor_sha256: String,
    pub bundle_sha256: String,
    pub source_spans: Vec<VerifiedSourceSpanV1>,
    pub evidence_ids: Vec<String>,
    pub verifier_identity: String,
}

impl VerifiedFactReceiptV1 {
    pub fn new(input: VerifiedFactReceiptInputV1) -> Result<Self, AdapterContractErrorV1> {
        let mut value = Self {
            schema_version: "gtkg.verified-fact-receipt/v1".to_owned(),
            fact_id: input.fact_id,
            resolution: input.resolution,
            reason: input.reason,
            source_snapshot_sha256: input.source_snapshot_sha256,
            adapter_descriptor_sha256: input.adapter_descriptor_sha256,
            bundle_sha256: input.bundle_sha256,
            source_replay_sha256: String::new(),
            source_spans: input.source_spans,
            evidence_ids: input.evidence_ids,
            verifier_identity: input.verifier_identity,
            receipt_sha256: String::new(),
        };
        value.source_replay_sha256 = replay_digest(&value)?;
        value.validate_shape()?;
        value.receipt_sha256 = digest_without(&value, "receipt_sha256")
            .map_err(|_| AdapterContractErrorV1::ReceiptInvalid)?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), AdapterContractErrorV1> {
        self.validate_shape()?;
        if self.receipt_sha256
            != digest_without(self, "receipt_sha256")
                .map_err(|_| AdapterContractErrorV1::ReceiptInvalid)?
        {
            return Err(AdapterContractErrorV1::ReceiptInvalid);
        }
        Ok(())
    }

    fn validate_shape(&self) -> Result<(), AdapterContractErrorV1> {
        let reason_ok = matches!(
            (self.resolution, self.reason.as_str()),
            (
                VerifiedResolutionV1::ResolvedVerified,
                "exact_source_replay"
            ) | (VerifiedResolutionV1::Ambiguous, "ambiguous_candidates")
                | (VerifiedResolutionV1::LocatorOnly, "missing_evidence")
                | (
                    VerifiedResolutionV1::LocatorOnly,
                    "source_bytes_digest_mismatch"
                )
                | (VerifiedResolutionV1::LocatorOnly, "source_span_mismatch")
        );
        if self.schema_version != "gtkg.verified-fact-receipt/v1"
            || !local_id(&self.fact_id)
            || !contract_id(&self.verifier_identity)
            || validate_sha256(&self.source_snapshot_sha256).is_err()
            || validate_sha256(&self.adapter_descriptor_sha256).is_err()
            || validate_sha256(&self.bundle_sha256).is_err()
            || (self.source_spans.is_empty() && self.reason != "missing_evidence")
            || self.source_spans.iter().any(|span| {
                !local_id(&span.evidence_id)
                    || span.source_logical_path.is_empty()
                    || validate_sha256(&span.source_bytes_sha256).is_err()
                    || validate_sha256(&span.snippet_sha256).is_err()
                    || span.byte_start >= span.byte_end
            })
            || !reason_ok
        {
            return Err(AdapterContractErrorV1::ReceiptInvalid);
        }
        if self.source_replay_sha256 != replay_digest(self)? {
            return Err(AdapterContractErrorV1::ReceiptInvalid);
        }
        Ok(())
    }
}

fn replay_digest(value: &VerifiedFactReceiptV1) -> Result<String, AdapterContractErrorV1> {
    #[derive(Serialize)]
    struct Replay<'a> {
        fact_id: &'a str,
        source_snapshot_sha256: &'a str,
        adapter_descriptor_sha256: &'a str,
        bundle_sha256: &'a str,
        source_spans: &'a [VerifiedSourceSpanV1],
        evidence_ids: &'a [String],
    }
    canonical_json_sha256(&Replay {
        fact_id: &value.fact_id,
        source_snapshot_sha256: &value.source_snapshot_sha256,
        adapter_descriptor_sha256: &value.adapter_descriptor_sha256,
        bundle_sha256: &value.bundle_sha256,
        source_spans: &value.source_spans,
        evidence_ids: &value.evidence_ids,
    })
    .map_err(|_| AdapterContractErrorV1::ReceiptInvalid)
}

fn digest_without<T: Serialize>(value: &T, field: &str) -> Result<String, ()> {
    let mut encoded = serde_json::to_value(value).map_err(|_| ())?;
    let Value::Object(object) = &mut encoded else {
        return Err(());
    };
    object.remove(field);
    canonical_json_sha256(&encoded).map_err(|_| ())
}

fn local_id(value: &str) -> bool {
    !value.trim().is_empty() && !value.contains('/') && !value.contains("..") && value != "."
}

fn contract_id(value: &str) -> bool {
    !value.trim().is_empty()
        && !value.starts_with('/')
        && !value.ends_with('/')
        && !value.contains("..")
}

fn version(value: &str) -> bool {
    !value.trim().is_empty()
        && !matches!(
            value.to_ascii_lowercase().as_str(),
            "latest" | "current" | "head"
        )
}

fn commit(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}
