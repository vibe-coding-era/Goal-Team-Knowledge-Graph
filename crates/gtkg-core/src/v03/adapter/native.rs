//! A01 native adapter over the frozen V0.2 Rust, Python, TypeScript, and
//! JavaScript static extractors.
//!
//! The adapter is deliberately file-only. It reads the caller-selected source
//! once through `gtkg-extract`, reuses the V0.2 typed IR and local resolver,
//! then projects every semantic fact and byte span into A00's common
//! `ExternalFactBundleV1`. It never executes target content, opens a network
//! connection, or writes canonical state.

use std::collections::BTreeSet;
use std::path::Path;

use gtkg_extract::{ExtractError, build_typed_ir_v2, extract_path, resolve_local_typed_ir_v2};
use gtkg_protocol::v2::{
    IrResolutionStateV2, SourceSnapshotV2, TypedIrError, TypedIrModeV2, TypedIrV2,
};
use gtkg_protocol::v03::AdapterKindV1;
use gtkg_protocol::v03::adapter::{
    AdapterContractErrorV1, AdapterDescriptorV1, CandidateFactStateV1, ExternalEdgeFactV1,
    ExternalEvidenceV1, ExternalFactBundleV1, ExternalFactOmissionV1, ExternalNodeFactV1,
    FactTrustStateV1,
};
use sha2::{Digest, Sha256};
use thiserror::Error;

const NATIVE_ADAPTER_ID: &str = "gtkg.adapter.native";
const NATIVE_ADAPTER_VERSION: &str = "0.3.0";
const NATIVE_ADAPTER_SOURCE_COMMIT: &str = "ad8b801fa53245336ef137b9f46d29742cc63af4";
const NATIVE_ADAPTER_SCHEMA: &[u8] = b"gtkg.native-adapter/v1|gtkg.external-fact-bundle/v1|gtkg.typed-ir/v2|rust,python,typescript,javascript";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeAdapterEffectsV1 {
    pub source_file_read_count: u64,
    pub target_process_count: u64,
    pub network_call_count: u64,
    pub write_count: u64,
    pub executed_target_content: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeAdapterOutputV1 {
    pub descriptor: AdapterDescriptorV1,
    pub bundle: ExternalFactBundleV1,
    pub effects: NativeAdapterEffectsV1,
}

#[derive(Debug, Error)]
pub enum NativeAdapterErrorV1 {
    #[error("native source extraction failed: {0}")]
    Extract(#[from] ExtractError),
    #[error("native typed IR validation failed: {0}")]
    TypedIr(#[from] TypedIrError),
    #[error("native A00 contract validation failed: {0}")]
    Contract(#[from] AdapterContractErrorV1),
    #[error("native extractor reported a forbidden target side effect")]
    TargetSideEffect,
}

impl NativeAdapterErrorV1 {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Extract(ExtractError::Unsupported(_)) => "E_NATIVE_ADAPTER_UNSUPPORTED",
            Self::Extract(_) => "E_NATIVE_ADAPTER_SOURCE_READ_FAILED",
            Self::TypedIr(error) => error.code(),
            Self::Contract(error) => error.code(),
            Self::TargetSideEffect => "E_NATIVE_ADAPTER_TARGET_SIDE_EFFECT",
        }
    }
}

pub fn native_adapter_descriptor_v1() -> Result<AdapterDescriptorV1, NativeAdapterErrorV1> {
    Ok(AdapterDescriptorV1 {
        schema_version: "gtkg.adapter-descriptor/v1".to_owned(),
        adapter_id: NATIVE_ADAPTER_ID.to_owned(),
        kind: AdapterKindV1::Native,
        adapter_version: NATIVE_ADAPTER_VERSION.to_owned(),
        schema_sha256: sha256(NATIVE_ADAPTER_SCHEMA),
        source_commit: NATIVE_ADAPTER_SOURCE_COMMIT.to_owned(),
        license: "Apache-2.0".to_owned(),
        capabilities: [
            "calls",
            "evidence_readback",
            "imports",
            "inheritance",
            "nodes",
            "static_file_only",
        ]
        .map(str::to_owned)
        .to_vec(),
        trust_policy_id: "gtkg.adapter-trust/v1".to_owned(),
        descriptor_sha256: String::new(),
    }
    .with_computed_digest()?)
}

/// Read one source file admitted by `snapshot` and return an A00 common fact
/// bundle. `source_path` is the caller-authorized physical read path while
/// `logical_path` is the stable snapshot identity carried by all evidence.
pub fn adapt_native_path_v1(
    snapshot: &SourceSnapshotV2,
    logical_path: &str,
    source_path: &Path,
) -> Result<NativeAdapterOutputV1, NativeAdapterErrorV1> {
    snapshot
        .validate()
        .map_err(|_| NativeAdapterErrorV1::TypedIr(TypedIrError::SourceSnapshotInvalid))?;
    let extracted = extract_path(source_path)?;
    if extracted.target_process_count != 0 || extracted.executed_target_content {
        return Err(NativeAdapterErrorV1::TargetSideEffect);
    }
    let ir = build_typed_ir_v2(snapshot, logical_path, &extracted)?;
    let ir = resolve_local_typed_ir_v2(&ir, extracted.text.as_bytes())?;
    let descriptor = native_adapter_descriptor_v1()?;
    let bundle = fact_bundle_from_ir(&descriptor, &ir)?;
    Ok(NativeAdapterOutputV1 {
        descriptor,
        bundle,
        effects: NativeAdapterEffectsV1 {
            source_file_read_count: 1,
            target_process_count: 0,
            network_call_count: 0,
            write_count: 0,
            executed_target_content: false,
        },
    })
}

fn fact_bundle_from_ir(
    descriptor: &AdapterDescriptorV1,
    ir: &TypedIrV2,
) -> Result<ExternalFactBundleV1, NativeAdapterErrorV1> {
    let mut evidence = ir
        .evidence
        .iter()
        .map(|item| ExternalEvidenceV1 {
            evidence_id: item.id.clone(),
            source_snapshot_sha256: ir.source_snapshot_exact_set_sha256.clone(),
            source_logical_path: item.source_logical_path.clone(),
            source_bytes_sha256: item.source_sha256.clone(),
            byte_start: item.byte_start,
            byte_end: item.byte_end,
            snippet_sha256: item.snippet_sha256.clone(),
            observed_trust: FactTrustStateV1::Extracted,
        })
        .collect::<Vec<_>>();
    evidence.sort_by(|left, right| left.evidence_id.cmp(&right.evidence_id));

    let mut nodes = ir
        .nodes
        .iter()
        .map(|node| ExternalNodeFactV1 {
            fact_id: stable_id("native-node-fact", &[&node.id]),
            node_id: node.id.clone(),
            node_kind: node.kind.clone(),
            name: node.name.clone(),
            candidate_state: CandidateFactStateV1::CandidateExternal,
            trust_state: FactTrustStateV1::Extracted,
            evidence_ids: node.evidence_ids.clone(),
        })
        .collect::<Vec<_>>();
    nodes.sort_by(|left, right| left.fact_id.cmp(&right.fact_id));

    let module_scope_id = stable_id(
        "native-module-scope",
        &[
            &ir.source_snapshot_exact_set_sha256,
            &ir.source_logical_path,
            &ir.source_sha256,
        ],
    );
    let mut edges = ir
        .edges
        .iter()
        .map(|edge| {
            let (candidate_state, trust_state, candidate_node_ids) = match edge.resolution {
                IrResolutionStateV2::Resolved => (
                    CandidateFactStateV1::CandidateExternal,
                    FactTrustStateV1::Extracted,
                    edge.resolved_node_id.iter().cloned().collect(),
                ),
                IrResolutionStateV2::Ambiguous => (
                    CandidateFactStateV1::Ambiguous,
                    FactTrustStateV1::Ambiguous,
                    edge.candidate_node_ids.clone(),
                ),
                IrResolutionStateV2::Unresolved => (
                    CandidateFactStateV1::LocatorOnly,
                    FactTrustStateV1::Inferred,
                    Vec::new(),
                ),
                IrResolutionStateV2::NotApplicable => (
                    CandidateFactStateV1::LocatorOnly,
                    FactTrustStateV1::Unverified,
                    Vec::new(),
                ),
            };
            ExternalEdgeFactV1 {
                fact_id: stable_id("native-edge-fact", &[&edge.id]),
                edge_id: edge.id.clone(),
                edge_kind: edge.kind.clone(),
                source_node_id: edge
                    .source_node_id
                    .clone()
                    .unwrap_or_else(|| module_scope_id.clone()),
                target_reference: edge.target_reference.clone(),
                candidate_node_ids,
                candidate_state,
                trust_state,
                evidence_ids: edge.evidence_ids.clone(),
            }
        })
        .collect::<Vec<_>>();
    edges.sort_by(|left, right| left.fact_id.cmp(&right.fact_id));

    let omissions = if ir.mode == TypedIrModeV2::FallbackLexical {
        vec![ExternalFactOmissionV1 {
            omitted_id: stable_id(
                "native-parser-omission",
                &[
                    &ir.source_snapshot_exact_set_sha256,
                    &ir.source_logical_path,
                    &ir.source_sha256,
                ],
            ),
            reason: "parser_fallback_lexical".to_owned(),
        }]
    } else {
        Vec::new()
    };
    let candidate_states = nodes
        .iter()
        .map(|item| item.candidate_state)
        .chain(edges.iter().map(|item| item.candidate_state))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let admitted_count = (nodes.len() + edges.len()) as u64;
    let omitted_count = omissions.len() as u64;
    Ok(ExternalFactBundleV1 {
        schema_version: "gtkg.external-fact-bundle/v1".to_owned(),
        source_snapshot_sha256: ir.source_snapshot_exact_set_sha256.clone(),
        adapter_descriptor_sha256: descriptor.descriptor_sha256.clone(),
        nodes,
        edges,
        evidence,
        candidate_states,
        discovered_count: admitted_count + omitted_count,
        admitted_count,
        omitted_count,
        omissions,
        bundle_sha256: String::new(),
    }
    .with_computed_digest()?)
}

fn stable_id(prefix: &str, fields: &[&str]) -> String {
    let mut hasher = Sha256::new();
    for field in fields {
        hasher.update((field.len() as u64).to_be_bytes());
        hasher.update(field.as_bytes());
    }
    format!("{prefix}:v1:{}", hex::encode(hasher.finalize()))
}

fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}
