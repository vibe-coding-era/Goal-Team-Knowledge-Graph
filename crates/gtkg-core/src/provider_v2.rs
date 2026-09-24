//! V0.2 T09 local-only Provider bridge.
//!
//! This module deliberately has no network client, credential field, or
//! provider SDK.  Its input boundary is [`ContextSelectedBytesV2`], which is
//! only emitted by T07 after replaying its ContextPack receipt.  The bridge
//! records an append-only, metadata-only attempt receipt and fails closed when
//! the local Provider identity or capability is absent.  It never claims that
//! a model invocation, LLM validation, or remote data transfer occurred.

use std::collections::BTreeSet;

use gtkg_protocol::{canonical_json_sha256, validate_sha256};
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::context_v2::{
    ContextSelectedBindingV2, ContextSelectedBytesV2, LOCAL_TOKENIZER_ID_V2,
    LOCAL_TOKENIZER_IMPLEMENTATION_SHA256_V2, LocalTokenizerV2,
    local_tokenizer_implementation_sha256_v2, selected_binding_v2,
};

const SUMMARY_JOB_SCHEMA: &str = "gtkg.summary-job/v2";
const PROVIDER_ATTEMPT_SCHEMA: &str = "gtkg.provider-attempt/v2";
const LOCAL_ONLY_POLICY_ID: &str = "gtkg.local-only.no-egress/v1";
const LOCAL_STUB_TRANSPORT_ID: &str = "gtkg.local.stub/v1";
const LOCAL_STUB_TRANSPORT_DESCRIPTOR: &str = concat!(
    "gtkg.local.stub.transport/v1\n",
    "execution=none\n",
    "network=disabled\n",
    "credentials=unsupported\n",
    "receipt=metadata-only\n"
);
const LOCAL_ONLY_POLICY_DESCRIPTOR: &str = concat!(
    "gtkg.local-only.no-egress/v1\n",
    "remote_egress=false\n",
    "secret_persistence=false\n"
);

/// The immutable job envelope.  It intentionally contains no prompt and no
/// arbitrary source payload; selected T07 bytes are supplied separately.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SummaryJobV2 {
    pub schema_version: String,
    pub job_id: String,
    pub source_snapshot_exact_set_sha256: String,
    pub context_pack_sha256: String,
    pub selected_context_sha256: String,
    pub output_schema: String,
    pub generation_policy: String,
    pub required_provider_mode: String,
    pub job_sha256: String,
}

impl SummaryJobV2 {
    /// Construct a job that is constrained to a local, non-executing bridge.
    /// It is not a request to invoke a model.
    pub fn local_only(
        job_id: impl Into<String>,
        selected: &[ContextSelectedBytesV2],
    ) -> Result<Self, ProviderBridgeErrorV2> {
        let binding = selected_binding_v2(selected)
            .map_err(|_| ProviderBridgeErrorV2::SelectedContextInvalid)?;
        let mut job = Self {
            schema_version: SUMMARY_JOB_SCHEMA.to_owned(),
            job_id: job_id.into(),
            source_snapshot_exact_set_sha256: binding.source_snapshot_exact_set_sha256,
            context_pack_sha256: binding.context_pack_sha256,
            selected_context_sha256: binding.selected_context_sha256,
            output_schema: "gtkg.summary-output/v2".to_owned(),
            generation_policy: "local_preflight_only_no_generation".to_owned(),
            required_provider_mode: "local_only".to_owned(),
            job_sha256: String::new(),
        };
        job.job_sha256 = job
            .recompute_digest()
            .expect("serializable fixed SummaryJobV2");
        Ok(job)
    }

    pub fn validate(&self) -> Result<(), ProviderBridgeErrorV2> {
        if self.schema_version != SUMMARY_JOB_SCHEMA
            || !valid_identifier(&self.job_id)
            || !valid_sha256(&self.source_snapshot_exact_set_sha256)
            || !valid_sha256(&self.context_pack_sha256)
            || !valid_sha256(&self.selected_context_sha256)
            || self.output_schema != "gtkg.summary-output/v2"
            || self.generation_policy != "local_preflight_only_no_generation"
            || self.required_provider_mode != "local_only"
            || self.recompute_digest()? != self.job_sha256
        {
            return Err(ProviderBridgeErrorV2::InvalidSummaryJob);
        }
        Ok(())
    }

    pub fn recompute_digest(&self) -> Result<String, ProviderBridgeErrorV2> {
        #[derive(Serialize)]
        struct DigestView<'a> {
            schema_version: &'a str,
            job_id: &'a str,
            source_snapshot_exact_set_sha256: &'a str,
            context_pack_sha256: &'a str,
            selected_context_sha256: &'a str,
            output_schema: &'a str,
            generation_policy: &'a str,
            required_provider_mode: &'a str,
        }
        canonical_json_sha256(&DigestView {
            schema_version: &self.schema_version,
            job_id: &self.job_id,
            source_snapshot_exact_set_sha256: &self.source_snapshot_exact_set_sha256,
            context_pack_sha256: &self.context_pack_sha256,
            selected_context_sha256: &self.selected_context_sha256,
            output_schema: &self.output_schema,
            generation_policy: &self.generation_policy,
            required_provider_mode: &self.required_provider_mode,
        })
        .map_err(|_| ProviderBridgeErrorV2::ReceiptEncoding)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProviderIdentityV2 {
    pub provider_id: String,
    pub implementation_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProviderTransportIdentityV2 {
    pub transport_id: String,
    pub implementation_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ContentPolicyV2 {
    pub policy_id: String,
    pub policy_sha256: String,
    pub permits_remote_egress: bool,
    pub permits_secret_persistence: bool,
}

impl ContentPolicyV2 {
    pub fn local_only_no_egress() -> Self {
        let policy_id = LOCAL_ONLY_POLICY_ID.to_owned();
        let policy_sha256 = sha256(LOCAL_ONLY_POLICY_DESCRIPTOR.as_bytes());
        Self {
            policy_id,
            policy_sha256,
            permits_remote_egress: false,
            permits_secret_persistence: false,
        }
    }

    fn validate(&self) -> Result<(), ProviderBridgeErrorV2> {
        if self.policy_id != LOCAL_ONLY_POLICY_ID
            || self.policy_sha256 != sha256(LOCAL_ONLY_POLICY_DESCRIPTOR.as_bytes())
            || self.permits_remote_egress
            || self.permits_secret_persistence
        {
            return Err(ProviderBridgeErrorV2::ContentPolicyDenied);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalProviderAvailabilityV2 {
    Available,
    Unavailable,
}

/// Configuration has no credential material.  A caller that lacks an exact
/// Provider or transport identity passes `None`, which becomes a recorded,
/// fail-closed attempt rather than a guessed identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LocalProviderConfigV2 {
    pub provider_identity: Option<ProviderIdentityV2>,
    pub transport_identity: Option<ProviderTransportIdentityV2>,
    pub tokenizer: LocalTokenizerV2,
    pub content_policy: ContentPolicyV2,
    pub availability: LocalProviderAvailabilityV2,
}

impl LocalProviderConfigV2 {
    pub fn unavailable() -> Self {
        Self {
            provider_identity: None,
            transport_identity: None,
            tokenizer: LocalTokenizerV2::controlled_local(),
            content_policy: ContentPolicyV2::local_only_no_egress(),
            availability: LocalProviderAvailabilityV2::Unavailable,
        }
    }

    /// An explicit local adapter identity.  This remains a preflight-only
    /// bridge: `attempt` will record `not_implemented`, never call a model.
    pub fn available_local_stub(provider_id: impl Into<String>) -> Self {
        let provider_id = provider_id.into();
        let transport_id = LOCAL_STUB_TRANSPORT_ID.to_owned();
        Self {
            provider_identity: Some(ProviderIdentityV2 {
                implementation_sha256: sha256(
                    local_adapter_descriptor_bytes(&provider_id).as_bytes(),
                ),
                provider_id,
            }),
            transport_identity: Some(ProviderTransportIdentityV2 {
                implementation_sha256: sha256(LOCAL_STUB_TRANSPORT_DESCRIPTOR.as_bytes()),
                transport_id,
            }),
            tokenizer: LocalTokenizerV2::controlled_local(),
            content_policy: ContentPolicyV2::local_only_no_egress(),
            availability: LocalProviderAvailabilityV2::Available,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SelectedContextRefV2 {
    pub chunk_id: String,
    pub immutable_content_ref: String,
    pub content_sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderAttemptStateV2 {
    Blocked,
}

/// An append-only local observation.  It carries only identities and content
/// digests/references; raw selected source bytes are never persisted here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProviderAttemptReceiptV2 {
    pub schema_version: String,
    pub attempt_sequence: u64,
    pub previous_receipt_sha256: Option<String>,
    pub first_failure_attempt: u64,
    pub state: ProviderAttemptStateV2,
    pub outcome_code: String,
    /// This in-memory receipt is not a durable run ledger or an external
    /// Provider receipt. Its chain is limited to this bridge instance.
    pub persistence_scope: String,
    pub durable_receipt: bool,
    pub source_snapshot_exact_set_sha256: String,
    pub context_source_snapshot_exact_set_sha256: String,
    pub context_pack_sha256: String,
    pub expected_context_pack_sha256: String,
    pub expected_selected_context_sha256: String,
    pub summary_job_sha256: String,
    pub provider_identity: Option<ProviderIdentityV2>,
    pub transport_identity: Option<ProviderTransportIdentityV2>,
    pub availability: LocalProviderAvailabilityV2,
    pub tokenizer: LocalTokenizerV2,
    pub content_policy: ContentPolicyV2,
    pub selected_context: Vec<SelectedContextRefV2>,
    pub selected_context_sha256: String,
    pub real_provider_call: bool,
    pub receipt_sha256: String,
}

impl ProviderAttemptReceiptV2 {
    pub fn recompute_digest(&self) -> Result<String, ProviderBridgeErrorV2> {
        #[derive(Serialize)]
        struct DigestView<'a> {
            schema_version: &'a str,
            attempt_sequence: u64,
            previous_receipt_sha256: &'a Option<String>,
            first_failure_attempt: u64,
            state: ProviderAttemptStateV2,
            outcome_code: &'a str,
            persistence_scope: &'a str,
            durable_receipt: bool,
            source_snapshot_exact_set_sha256: &'a str,
            context_source_snapshot_exact_set_sha256: &'a str,
            context_pack_sha256: &'a str,
            expected_context_pack_sha256: &'a str,
            expected_selected_context_sha256: &'a str,
            summary_job_sha256: &'a str,
            provider_identity: &'a Option<ProviderIdentityV2>,
            transport_identity: &'a Option<ProviderTransportIdentityV2>,
            availability: LocalProviderAvailabilityV2,
            tokenizer: &'a LocalTokenizerV2,
            content_policy: &'a ContentPolicyV2,
            selected_context: &'a [SelectedContextRefV2],
            selected_context_sha256: &'a str,
            real_provider_call: bool,
        }
        canonical_json_sha256(&DigestView {
            schema_version: &self.schema_version,
            attempt_sequence: self.attempt_sequence,
            previous_receipt_sha256: &self.previous_receipt_sha256,
            first_failure_attempt: self.first_failure_attempt,
            state: self.state,
            outcome_code: &self.outcome_code,
            persistence_scope: &self.persistence_scope,
            durable_receipt: self.durable_receipt,
            source_snapshot_exact_set_sha256: &self.source_snapshot_exact_set_sha256,
            context_source_snapshot_exact_set_sha256: &self
                .context_source_snapshot_exact_set_sha256,
            context_pack_sha256: &self.context_pack_sha256,
            expected_context_pack_sha256: &self.expected_context_pack_sha256,
            expected_selected_context_sha256: &self.expected_selected_context_sha256,
            summary_job_sha256: &self.summary_job_sha256,
            provider_identity: &self.provider_identity,
            transport_identity: &self.transport_identity,
            availability: self.availability,
            tokenizer: &self.tokenizer,
            content_policy: &self.content_policy,
            selected_context: &self.selected_context,
            selected_context_sha256: &self.selected_context_sha256,
            real_provider_call: self.real_provider_call,
        })
        .map_err(|_| ProviderBridgeErrorV2::ReceiptEncoding)
    }

    pub fn validate(&self) -> Result<(), ProviderBridgeErrorV2> {
        if self.schema_version != PROVIDER_ATTEMPT_SCHEMA
            || self.attempt_sequence == 0
            || self.first_failure_attempt == 0
            || self.first_failure_attempt > self.attempt_sequence
            || self.state != ProviderAttemptStateV2::Blocked
            || self.real_provider_call
            || self.persistence_scope != "local_ephemeral_not_durable"
            || self.durable_receipt
            || !valid_sha256(&self.source_snapshot_exact_set_sha256)
            || !valid_sha256(&self.context_source_snapshot_exact_set_sha256)
            || !valid_sha256(&self.context_pack_sha256)
            || !valid_sha256(&self.expected_context_pack_sha256)
            || !valid_sha256(&self.expected_selected_context_sha256)
            || !valid_sha256(&self.summary_job_sha256)
            || !valid_sha256(&self.selected_context_sha256)
            || !valid_sha256(&self.receipt_sha256)
            || self.recompute_digest()? != self.receipt_sha256
        {
            return Err(ProviderBridgeErrorV2::ReceiptMismatch);
        }
        if let Some(previous) = &self.previous_receipt_sha256
            && !valid_sha256(previous)
        {
            return Err(ProviderBridgeErrorV2::ReceiptMismatch);
        }
        validate_selected_refs(&self.selected_context)?;
        if canonical_json_sha256(&self.selected_context)
            .map_err(|_| ProviderBridgeErrorV2::ReceiptEncoding)?
            != self.selected_context_sha256
        {
            return Err(ProviderBridgeErrorV2::ReceiptMismatch);
        }
        if self.outcome_code != receipt_preflight_outcome(self).code() {
            return Err(ProviderBridgeErrorV2::ReceiptMismatch);
        }
        Ok(())
    }

    /// Validate the append-only chain for one in-memory local bridge. A
    /// non-initial receipt must be adjacent to its predecessor; receipts from
    /// different bridge instances cannot be spliced together.
    pub fn validate_chain(
        previous: Option<&ProviderAttemptReceiptV2>,
        current: &ProviderAttemptReceiptV2,
    ) -> Result<(), ProviderBridgeErrorV2> {
        current.validate()?;
        match previous {
            None if current.attempt_sequence == 1 && current.previous_receipt_sha256.is_none() => {
                if current.first_failure_attempt != 1 {
                    return Err(ProviderBridgeErrorV2::ReceiptMismatch);
                }
            }
            Some(previous) => {
                previous.validate()?;
                if current.attempt_sequence
                    != previous
                        .attempt_sequence
                        .checked_add(1)
                        .ok_or(ProviderBridgeErrorV2::AttemptSequenceOverflow)?
                    || current.previous_receipt_sha256.as_deref() != Some(&previous.receipt_sha256)
                    || current.first_failure_attempt != previous.first_failure_attempt
                {
                    return Err(ProviderBridgeErrorV2::ReceiptMismatch);
                }
            }
            None => return Err(ProviderBridgeErrorV2::ReceiptMismatch),
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct LocalProviderBridgeV2 {
    config: LocalProviderConfigV2,
    attempts: Vec<ProviderAttemptReceiptV2>,
}

impl LocalProviderBridgeV2 {
    pub fn new(config: LocalProviderConfigV2) -> Self {
        Self {
            config,
            attempts: Vec::new(),
        }
    }

    pub fn attempts(&self) -> &[ProviderAttemptReceiptV2] {
        &self.attempts
    }

    /// Record one local preflight attempt.  The sole content input is the T07
    /// selected-read value.  There is deliberately no API accepting a full
    /// ContextPack request, an arbitrary prompt, or unselected chunks.
    pub fn attempt(
        &mut self,
        job: &SummaryJobV2,
        selected_bytes: &[ContextSelectedBytesV2],
    ) -> Result<(), ProviderBridgeErrorV2> {
        job.validate()?;
        let binding = selected_binding_v2(selected_bytes)
            .map_err(|_| ProviderBridgeErrorV2::SelectedContextInvalid)?;
        let selected_context = selected_refs(selected_bytes)?;
        let outcome = self.preflight_outcome(job, &binding);
        let sequence = u64::try_from(self.attempts.len())
            .map_err(|_| ProviderBridgeErrorV2::AttemptSequenceOverflow)?
            .checked_add(1)
            .ok_or(ProviderBridgeErrorV2::AttemptSequenceOverflow)?;
        let mut receipt = ProviderAttemptReceiptV2 {
            schema_version: PROVIDER_ATTEMPT_SCHEMA.to_owned(),
            attempt_sequence: sequence,
            previous_receipt_sha256: self.attempts.last().map(|item| item.receipt_sha256.clone()),
            first_failure_attempt: self
                .attempts
                .first()
                .map_or(sequence, |item| item.first_failure_attempt),
            state: ProviderAttemptStateV2::Blocked,
            outcome_code: outcome.code().to_owned(),
            persistence_scope: "local_ephemeral_not_durable".to_owned(),
            durable_receipt: false,
            source_snapshot_exact_set_sha256: job.source_snapshot_exact_set_sha256.clone(),
            context_source_snapshot_exact_set_sha256: binding.source_snapshot_exact_set_sha256,
            context_pack_sha256: binding.context_pack_sha256,
            expected_context_pack_sha256: job.context_pack_sha256.clone(),
            expected_selected_context_sha256: job.selected_context_sha256.clone(),
            summary_job_sha256: job.job_sha256.clone(),
            provider_identity: self.config.provider_identity.clone(),
            transport_identity: self.config.transport_identity.clone(),
            availability: self.config.availability,
            tokenizer: self.config.tokenizer.clone(),
            content_policy: self.config.content_policy.clone(),
            selected_context_sha256: binding.selected_context_sha256,
            selected_context,
            real_provider_call: false,
            receipt_sha256: String::new(),
        };
        receipt.receipt_sha256 = receipt.recompute_digest()?;
        ProviderAttemptReceiptV2::validate_chain(self.attempts.last(), &receipt)?;
        self.attempts.push(receipt);
        Err(outcome)
    }

    fn preflight_outcome(
        &self,
        job: &SummaryJobV2,
        binding: &ContextSelectedBindingV2,
    ) -> ProviderBridgeErrorV2 {
        if job.source_snapshot_exact_set_sha256 != binding.source_snapshot_exact_set_sha256
            || job.context_pack_sha256 != binding.context_pack_sha256
            || job.selected_context_sha256 != binding.selected_context_sha256
        {
            return ProviderBridgeErrorV2::ContextJobMismatch;
        }
        if self.config.provider_identity.is_none() || self.config.transport_identity.is_none() {
            return ProviderBridgeErrorV2::ProviderIdentityMissing;
        }
        if let Some(identity) = &self.config.provider_identity
            && let Err(error) = validate_provider_identity(identity)
        {
            return error;
        }
        if let Some(identity) = &self.config.transport_identity
            && let Err(error) = validate_transport_identity(identity)
        {
            return error;
        }
        if let Err(error) = validate_tokenizer(&self.config.tokenizer) {
            return error;
        }
        if let Err(error) = self.config.content_policy.validate() {
            return error;
        }
        if self.config.availability == LocalProviderAvailabilityV2::Unavailable {
            return ProviderBridgeErrorV2::LocalProviderUnavailable;
        }
        ProviderBridgeErrorV2::LocalProviderNotImplemented
    }
}

fn receipt_preflight_outcome(receipt: &ProviderAttemptReceiptV2) -> ProviderBridgeErrorV2 {
    if receipt.source_snapshot_exact_set_sha256 != receipt.context_source_snapshot_exact_set_sha256
        || receipt.context_pack_sha256 != receipt.expected_context_pack_sha256
        || receipt.selected_context_sha256 != receipt.expected_selected_context_sha256
    {
        return ProviderBridgeErrorV2::ContextJobMismatch;
    }
    if receipt.provider_identity.is_none() || receipt.transport_identity.is_none() {
        return ProviderBridgeErrorV2::ProviderIdentityMissing;
    }
    if let Some(identity) = &receipt.provider_identity
        && let Err(error) = validate_provider_identity(identity)
    {
        return error;
    }
    if let Some(identity) = &receipt.transport_identity
        && let Err(error) = validate_transport_identity(identity)
    {
        return error;
    }
    if let Err(error) = validate_tokenizer(&receipt.tokenizer) {
        return error;
    }
    if let Err(error) = receipt.content_policy.validate() {
        return error;
    }
    if receipt.availability == LocalProviderAvailabilityV2::Unavailable {
        return ProviderBridgeErrorV2::LocalProviderUnavailable;
    }
    ProviderBridgeErrorV2::LocalProviderNotImplemented
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProviderBridgeErrorV2 {
    #[error("invalid SummaryJobV2")]
    InvalidSummaryJob,
    #[error("Provider or transport identity is absent or invalid")]
    ProviderIdentityMissing,
    #[error("Provider identity is invalid")]
    ProviderIdentityInvalid,
    #[error("Provider transport identity is invalid")]
    TransportIdentityInvalid,
    #[error("local Provider is unavailable")]
    LocalProviderUnavailable,
    #[error("no local Provider implementation is configured")]
    LocalProviderNotImplemented,
    #[error("selected ContextPack bytes are invalid or not uniquely bound")]
    SelectedContextInvalid,
    #[error("T07 ContextPack binding does not exactly match SummaryJobV2")]
    ContextJobMismatch,
    #[error("the local tokenizer identity is invalid")]
    TokenizerIdentityInvalid,
    #[error("content policy denies this Provider attempt")]
    ContentPolicyDenied,
    #[error("Provider attempt receipt does not match its immutable content")]
    ReceiptMismatch,
    #[error("Provider attempt sequence overflow")]
    AttemptSequenceOverflow,
    #[error("Provider attempt receipt encoding failed")]
    ReceiptEncoding,
}

impl ProviderBridgeErrorV2 {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidSummaryJob => "E_SUMMARY_JOB_INVALID",
            Self::ProviderIdentityMissing | Self::ProviderIdentityInvalid => "E_PROVIDER_IDENTITY",
            Self::TransportIdentityInvalid => "E_TRANSPORT_IDENTITY",
            Self::LocalProviderUnavailable => "E_LOCAL_PROVIDER_UNAVAILABLE",
            Self::LocalProviderNotImplemented => "E_LOCAL_PROVIDER_NOT_IMPLEMENTED",
            Self::SelectedContextInvalid => "E_SELECTED_CONTEXT_INVALID",
            Self::ContextJobMismatch => "E_CONTEXT_JOB_MISMATCH",
            Self::TokenizerIdentityInvalid => "E_TOKENIZER_IDENTITY",
            Self::ContentPolicyDenied => "E_CONTENT_POLICY_DENIED",
            Self::ReceiptMismatch => "E_PROVIDER_RECEIPT_MISMATCH",
            Self::AttemptSequenceOverflow => "E_PROVIDER_ATTEMPT_OVERFLOW",
            Self::ReceiptEncoding => "E_PROVIDER_RECEIPT_ENCODING",
        }
    }
}

fn selected_refs(
    selected_bytes: &[ContextSelectedBytesV2],
) -> Result<Vec<SelectedContextRefV2>, ProviderBridgeErrorV2> {
    if selected_bytes.is_empty() {
        return Err(ProviderBridgeErrorV2::SelectedContextInvalid);
    }
    let mut refs = selected_bytes
        .iter()
        .map(|item| SelectedContextRefV2 {
            chunk_id: item.chunk_id().to_owned(),
            immutable_content_ref: item.immutable_content_ref().to_owned(),
            content_sha256: item.content_sha256().to_owned(),
        })
        .collect::<Vec<_>>();
    let mut seen = BTreeSet::new();
    for item in selected_bytes {
        if item.chunk_id().is_empty()
            || item.content().is_empty()
            || !valid_sha256(item.content_sha256())
            || item.content_sha256() != sha256(item.content().as_bytes())
            || !valid_context_ref(item.immutable_content_ref(), item.content_sha256())
            || !seen.insert((item.chunk_id(), item.immutable_content_ref()))
        {
            return Err(ProviderBridgeErrorV2::SelectedContextInvalid);
        }
    }
    refs.sort_by(|left, right| {
        (&left.chunk_id, &left.immutable_content_ref)
            .cmp(&(&right.chunk_id, &right.immutable_content_ref))
    });
    validate_selected_refs(&refs)?;
    Ok(refs)
}

fn validate_selected_refs(refs: &[SelectedContextRefV2]) -> Result<(), ProviderBridgeErrorV2> {
    if refs.is_empty() {
        return Err(ProviderBridgeErrorV2::SelectedContextInvalid);
    }
    let mut seen = BTreeSet::new();
    for item in refs {
        if item.chunk_id.is_empty()
            || !valid_sha256(&item.content_sha256)
            || !valid_context_ref(&item.immutable_content_ref, &item.content_sha256)
            || !seen.insert((item.chunk_id.as_str(), item.immutable_content_ref.as_str()))
        {
            return Err(ProviderBridgeErrorV2::SelectedContextInvalid);
        }
    }
    Ok(())
}

fn valid_context_ref(reference: &str, content_sha256: &str) -> bool {
    let mut fields = reference.split(':');
    matches!(
        (
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
        ),
        (
            Some("context-content"),
            Some("v2"),
            Some("sha256"),
            Some(snapshot),
            Some("sha256"),
            Some(source),
            Some(start),
            Some(end),
            Some("sha256"),
            Some(content),
        ) if fields.next().is_none()
            && valid_sha256(&format!("sha256:{snapshot}"))
            && valid_sha256(&format!("sha256:{source}"))
            && start.parse::<u64>().is_ok()
            && end.parse::<u64>().is_ok()
            && format!("sha256:{content}") == content_sha256
    )
}

fn validate_provider_identity(identity: &ProviderIdentityV2) -> Result<(), ProviderBridgeErrorV2> {
    if !valid_identifier(&identity.provider_id)
        || !valid_sha256(&identity.implementation_sha256)
        || identity.implementation_sha256
            != sha256(local_adapter_descriptor_bytes(&identity.provider_id).as_bytes())
    {
        return Err(ProviderBridgeErrorV2::ProviderIdentityInvalid);
    }
    Ok(())
}

fn validate_transport_identity(
    identity: &ProviderTransportIdentityV2,
) -> Result<(), ProviderBridgeErrorV2> {
    if identity.transport_id != LOCAL_STUB_TRANSPORT_ID
        || !valid_sha256(&identity.implementation_sha256)
        || identity.implementation_sha256 != sha256(LOCAL_STUB_TRANSPORT_DESCRIPTOR.as_bytes())
    {
        return Err(ProviderBridgeErrorV2::TransportIdentityInvalid);
    }
    Ok(())
}

fn validate_tokenizer(tokenizer: &LocalTokenizerV2) -> Result<(), ProviderBridgeErrorV2> {
    if tokenizer.id != LOCAL_TOKENIZER_ID_V2
        || tokenizer.implementation_sha256 != LOCAL_TOKENIZER_IMPLEMENTATION_SHA256_V2
        || tokenizer.implementation_sha256 != local_tokenizer_implementation_sha256_v2()
    {
        return Err(ProviderBridgeErrorV2::TokenizerIdentityInvalid);
    }
    Ok(())
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '_' | '/')
        })
}

fn local_adapter_descriptor_bytes(provider_id: &str) -> String {
    format!(
        "gtkg.local.provider-adapter/v1\nprovider_id={provider_id}\nexecution=none\nnetwork=disabled\ncredentials=unsupported\n"
    )
}

fn valid_sha256(value: &str) -> bool {
    validate_sha256(value).is_ok()
}

fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}
