//! A00 adapter trust and exact source-replay validation.

pub mod codegraph;
pub mod graphify;
pub mod lsp_snapshot;
pub mod native;
pub mod scip;
pub mod verifier;

use std::collections::{BTreeMap, BTreeSet};

use sha2::{Digest, Sha256};

use gtkg_protocol::v03::adapter::{
    AdapterContractErrorV1, AdapterDescriptorV1, CandidateFactStateV1, ExternalEvidenceV1,
    ExternalFactBundleV1, FactTrustStateV1, VerifiedFactReceiptInputV1, VerifiedFactReceiptV1,
    VerifiedResolutionV1, VerifiedSourceSpanV1,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterVerificationV1 {
    pub receipts: Vec<VerifiedFactReceiptV1>,
    pub resolved_verified_fact_ids: Vec<String>,
    pub false_confirmed: u64,
    pub canonical_write_count: u64,
}

pub fn verify_external_fact_bundle_v1(
    expected_descriptor: &AdapterDescriptorV1,
    observed_descriptor: &AdapterDescriptorV1,
    bundle: &ExternalFactBundleV1,
    source_files: &BTreeMap<String, Vec<u8>>,
    verifier_identity: &str,
) -> Result<AdapterVerificationV1, AdapterContractErrorV1> {
    expected_descriptor.validate()?;
    observed_descriptor.validate()?;
    if expected_descriptor.descriptor_sha256 != observed_descriptor.descriptor_sha256 {
        return Err(AdapterContractErrorV1::IdentityMismatch);
    }
    bundle.validate()?;
    if bundle.adapter_descriptor_sha256 != expected_descriptor.descriptor_sha256 {
        return Err(AdapterContractErrorV1::IdentityMismatch);
    }

    let evidence = bundle
        .evidence
        .iter()
        .map(|item| (item.evidence_id.as_str(), item))
        .collect::<BTreeMap<_, _>>();
    let mut receipts = Vec::with_capacity(bundle.nodes.len() + bundle.edges.len());
    let mut resolved = Vec::new();

    for node in &bundle.nodes {
        let outcome = verify_fact(
            &node.fact_id,
            node.candidate_state,
            node.trust_state,
            &node.evidence_ids,
            false,
            &evidence,
            source_files,
        )?;
        if outcome.0 == VerifiedResolutionV1::ResolvedVerified {
            resolved.push(node.fact_id.clone());
        }
        receipts.push(VerifiedFactReceiptV1::new(VerifiedFactReceiptInputV1 {
            fact_id: node.fact_id.clone(),
            resolution: outcome.0,
            reason: outcome.1.to_owned(),
            source_snapshot_sha256: bundle.source_snapshot_sha256.clone(),
            adapter_descriptor_sha256: bundle.adapter_descriptor_sha256.clone(),
            bundle_sha256: bundle.bundle_sha256.clone(),
            source_spans: receipt_spans(&node.evidence_ids, &evidence),
            evidence_ids: node.evidence_ids.clone(),
            verifier_identity: verifier_identity.to_owned(),
        })?);
    }
    for edge in &bundle.edges {
        let outcome = verify_fact(
            &edge.fact_id,
            edge.candidate_state,
            edge.trust_state,
            &edge.evidence_ids,
            edge.candidate_node_ids.len() > 1,
            &evidence,
            source_files,
        )?;
        if outcome.0 == VerifiedResolutionV1::ResolvedVerified {
            resolved.push(edge.fact_id.clone());
        }
        receipts.push(VerifiedFactReceiptV1::new(VerifiedFactReceiptInputV1 {
            fact_id: edge.fact_id.clone(),
            resolution: outcome.0,
            reason: outcome.1.to_owned(),
            source_snapshot_sha256: bundle.source_snapshot_sha256.clone(),
            adapter_descriptor_sha256: bundle.adapter_descriptor_sha256.clone(),
            bundle_sha256: bundle.bundle_sha256.clone(),
            source_spans: receipt_spans(&edge.evidence_ids, &evidence),
            evidence_ids: edge.evidence_ids.clone(),
            verifier_identity: verifier_identity.to_owned(),
        })?);
    }

    resolved.sort();
    Ok(AdapterVerificationV1 {
        receipts,
        resolved_verified_fact_ids: resolved,
        false_confirmed: 0,
        canonical_write_count: 0,
    })
}

fn receipt_spans(
    evidence_ids: &[String],
    evidence: &BTreeMap<&str, &ExternalEvidenceV1>,
) -> Vec<VerifiedSourceSpanV1> {
    evidence_ids
        .iter()
        .filter_map(|evidence_id| evidence.get(evidence_id.as_str()))
        .map(|item| VerifiedSourceSpanV1 {
            evidence_id: item.evidence_id.clone(),
            source_logical_path: item.source_logical_path.clone(),
            source_bytes_sha256: item.source_bytes_sha256.clone(),
            byte_start: item.byte_start,
            byte_end: item.byte_end,
            snippet_sha256: item.snippet_sha256.clone(),
        })
        .collect()
}

fn verify_fact<'a>(
    _fact_id: &str,
    candidate_state: CandidateFactStateV1,
    trust_state: FactTrustStateV1,
    evidence_ids: &[String],
    multiple_candidates: bool,
    evidence: &BTreeMap<&'a str, &'a ExternalEvidenceV1>,
    source_files: &BTreeMap<String, Vec<u8>>,
) -> Result<(VerifiedResolutionV1, &'static str), AdapterContractErrorV1> {
    if evidence_ids.is_empty() {
        return Ok((VerifiedResolutionV1::LocatorOnly, "missing_evidence"));
    }
    let mut seen = BTreeSet::new();
    for evidence_id in evidence_ids {
        if !seen.insert(evidence_id.as_str()) {
            return Err(AdapterContractErrorV1::BundleInvalid);
        }
        let Some(item) = evidence.get(evidence_id.as_str()) else {
            return Ok((VerifiedResolutionV1::LocatorOnly, "missing_evidence"));
        };
        if trust_state == FactTrustStateV1::Extracted
            && item.observed_trust != FactTrustStateV1::Extracted
        {
            return Err(AdapterContractErrorV1::TrustLaundering);
        }
        let Some(bytes) = source_files.get(&item.source_logical_path) else {
            return Ok((VerifiedResolutionV1::LocatorOnly, "missing_evidence"));
        };
        if sha256(bytes) != item.source_bytes_sha256 {
            return Ok((
                VerifiedResolutionV1::LocatorOnly,
                "source_bytes_digest_mismatch",
            ));
        }
        let Ok(start) = usize::try_from(item.byte_start) else {
            return Ok((VerifiedResolutionV1::LocatorOnly, "source_span_mismatch"));
        };
        let Ok(end) = usize::try_from(item.byte_end) else {
            return Ok((VerifiedResolutionV1::LocatorOnly, "source_span_mismatch"));
        };
        let Some(snippet) = bytes.get(start..end) else {
            return Ok((VerifiedResolutionV1::LocatorOnly, "source_span_mismatch"));
        };
        if sha256(snippet) != item.snippet_sha256 {
            return Ok((VerifiedResolutionV1::LocatorOnly, "source_span_mismatch"));
        }
    }

    if candidate_state == CandidateFactStateV1::Ambiguous || multiple_candidates {
        return Ok((VerifiedResolutionV1::Ambiguous, "ambiguous_candidates"));
    }
    if candidate_state == CandidateFactStateV1::CandidateExternal
        && trust_state == FactTrustStateV1::Extracted
    {
        return Ok((
            VerifiedResolutionV1::ResolvedVerified,
            "exact_source_replay",
        ));
    }
    Ok((VerifiedResolutionV1::LocatorOnly, "missing_evidence"))
}

fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}
