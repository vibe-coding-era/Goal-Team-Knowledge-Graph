//! A03 pinned, file-only LSP snapshot adapter.
//!
//! The adapter accepts only one deterministic, digest-pinned JSON snapshot
//! captured without a live language-server or JSON-RPC exchange. LSP positions
//! are accepted only with the explicitly pinned UTF-8 encoding and are converted
//! to exact source byte spans before A00 candidate facts are emitted.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, Metadata};
use std::io::Read;
use std::path::{Component, Path};

use gtkg_protocol::v03::AdapterKindV1;
use gtkg_protocol::v03::adapter::{
    AdapterDescriptorV1, CandidateFactStateV1, ExternalEdgeFactV1, ExternalEvidenceV1,
    ExternalFactBundleV1, ExternalNodeFactV1, FactTrustStateV1,
};
use gtkg_protocol::{canonical_json_sha256, validate_sha256};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

const SUPPORTED_SNAPSHOT_SCHEMA: &str = "gtkg.lsp-snapshot/v1";
const SUPPORTED_LSP_PROTOCOL: &str = "3.17";
const SUPPORTED_POSITION_ENCODING: &str = "utf-8";
const FROZEN_CAPTURE_MODE: &str = "frozen_file";
const RECEIPT_SCHEMA: &str = "gtkg.lsp-snapshot-import-receipt/v1";

/// Exact file, producer, configuration, protocol, and source identities.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LspSnapshotFilePinV1 {
    pub file_sha256: String,
    pub schema_version: String,
    pub schema_sha256: String,
    pub protocol_version: String,
    pub position_encoding: String,
    pub producer_name: String,
    pub producer_version: String,
    pub producer_commit: String,
    pub producer_license: String,
    pub producer_config_sha256: String,
    pub source_snapshot_sha256: String,
    pub max_file_bytes: u64,
}

impl LspSnapshotFilePinV1 {
    pub fn validate(&self) -> Result<(), LspSnapshotAdapterErrorV1> {
        if self.schema_version != SUPPORTED_SNAPSHOT_SCHEMA {
            return Err(LspSnapshotAdapterErrorV1::SchemaUnsupported);
        }
        if self.protocol_version != SUPPORTED_LSP_PROTOCOL {
            return Err(LspSnapshotAdapterErrorV1::ProtocolUnsupported);
        }
        if self.position_encoding != SUPPORTED_POSITION_ENCODING {
            return Err(LspSnapshotAdapterErrorV1::PositionEncodingUnsupported);
        }
        let version_is_floating = floating_version(&self.producer_version);
        if validate_sha256(&self.file_sha256).is_err()
            || validate_sha256(&self.schema_sha256).is_err()
            || !identity_component(&self.producer_name)
            || self.producer_version.trim().is_empty()
            || version_is_floating
            || !commit_identity(&self.producer_commit)
            || self.producer_license.trim().is_empty()
            || unknown_license(&self.producer_license)
            || validate_sha256(&self.producer_config_sha256).is_err()
            || validate_sha256(&self.source_snapshot_sha256).is_err()
            || self.max_file_bytes == 0
        {
            return Err(LspSnapshotAdapterErrorV1::PinMismatch);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum LspSnapshotAdapterErrorV1 {
    #[error("LSP snapshot input is not a bounded regular file")]
    FileInvalid,
    #[error("LSP snapshot JSON is not closed or well formed")]
    JsonInvalid,
    #[error("LSP snapshot or declared identity differs from the exact pin")]
    PinMismatch,
    #[error("LSP snapshot schema version is unsupported")]
    SchemaUnsupported,
    #[error("LSP protocol version is unsupported")]
    ProtocolUnsupported,
    #[error("LSP position encoding is unsupported")]
    PositionEncodingUnsupported,
    #[error("live LSP or JSON-RPC response input is forbidden")]
    LiveResponseRejected,
    #[error("LSP snapshot is not explicitly deterministic")]
    NonDeterministic,
    #[error("LSP snapshot source bytes or source identity is tampered")]
    SourceTampered,
    #[error("LSP source range is invalid for the pinned position encoding")]
    RangeInvalid,
    #[error("LSP relationship kind is unsupported")]
    RelationshipUnsupported,
    #[error("LSP candidate bundle is invalid")]
    BundleInvalid,
    #[error("LSP import receipt is invalid")]
    ReceiptInvalid,
}

impl LspSnapshotAdapterErrorV1 {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::FileInvalid => "E_LSP_FILE_INVALID",
            Self::JsonInvalid => "E_LSP_JSON_INVALID",
            Self::PinMismatch => "E_LSP_PIN_MISMATCH",
            Self::SchemaUnsupported => "E_LSP_SCHEMA_UNSUPPORTED",
            Self::ProtocolUnsupported => "E_LSP_PROTOCOL_UNSUPPORTED",
            Self::PositionEncodingUnsupported => "E_LSP_POSITION_ENCODING_UNSUPPORTED",
            Self::LiveResponseRejected => "E_LSP_LIVE_RESPONSE_REJECTED",
            Self::NonDeterministic => "E_LSP_NONDETERMINISTIC_SNAPSHOT",
            Self::SourceTampered => "E_LSP_SOURCE_TAMPERED",
            Self::RangeInvalid => "E_LSP_RANGE_INVALID",
            Self::RelationshipUnsupported => "E_LSP_RELATION_UNSUPPORTED",
            Self::BundleInvalid => "E_LSP_BUNDLE_INVALID",
            Self::ReceiptInvalid => "E_LSP_RECEIPT_INVALID",
        }
    }
}

/// Bounded evidence that import used no live LSP, process, network, or write.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LspSnapshotImportReceiptV1 {
    pub schema_version: String,
    pub snapshot_file_sha256: String,
    pub snapshot_schema_sha256: String,
    pub protocol_version: String,
    pub position_encoding: String,
    pub producer_name: String,
    pub producer_version: String,
    pub producer_commit: String,
    pub producer_license: String,
    pub producer_config_sha256: String,
    pub source_snapshot_sha256: String,
    pub adapter_descriptor_sha256: String,
    pub bundle_sha256: String,
    pub document_count: u64,
    pub symbol_count: u64,
    pub diagnostic_count: u64,
    pub relationship_count: u64,
    pub source_range_count: u64,
    pub discovered_count: u64,
    pub admitted_count: u64,
    pub omitted_count: u64,
    pub lsp_server_invocation_count: u64,
    pub json_rpc_request_count: u64,
    pub json_rpc_response_count: u64,
    pub target_execution_count: u64,
    pub network_call_count: u64,
    pub write_count: u64,
    pub canonical_write_count: u64,
    pub receipt_sha256: String,
}

impl LspSnapshotImportReceiptV1 {
    pub fn validate(&self) -> Result<(), LspSnapshotAdapterErrorV1> {
        if self.schema_version != RECEIPT_SCHEMA
            || validate_sha256(&self.snapshot_file_sha256).is_err()
            || validate_sha256(&self.snapshot_schema_sha256).is_err()
            || self.protocol_version != SUPPORTED_LSP_PROTOCOL
            || self.position_encoding != SUPPORTED_POSITION_ENCODING
            || !identity_component(&self.producer_name)
            || self.producer_version.trim().is_empty()
            || floating_version(&self.producer_version)
            || !commit_identity(&self.producer_commit)
            || self.producer_license.trim().is_empty()
            || unknown_license(&self.producer_license)
            || validate_sha256(&self.producer_config_sha256).is_err()
            || validate_sha256(&self.source_snapshot_sha256).is_err()
            || validate_sha256(&self.adapter_descriptor_sha256).is_err()
            || validate_sha256(&self.bundle_sha256).is_err()
            || self.document_count == 0
            || self.symbol_count == 0
            || self.source_range_count
                != self
                    .symbol_count
                    .saturating_mul(2)
                    .saturating_add(self.diagnostic_count)
                    .saturating_add(self.relationship_count)
            || self.discovered_count != self.admitted_count + self.omitted_count
            || self.admitted_count
                != self.symbol_count + self.diagnostic_count + self.relationship_count
            || self.lsp_server_invocation_count != 0
            || self.json_rpc_request_count != 0
            || self.json_rpc_response_count != 0
            || self.target_execution_count != 0
            || self.network_call_count != 0
            || self.write_count != 0
            || self.canonical_write_count != 0
            || self.receipt_sha256 != receipt_digest(self)?
        {
            return Err(LspSnapshotAdapterErrorV1::ReceiptInvalid);
        }
        Ok(())
    }
}

/// A00 candidate facts plus exact source bytes and file-only import evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LspSnapshotImportV1 {
    pub descriptor: AdapterDescriptorV1,
    pub bundle: ExternalFactBundleV1,
    pub source_files: BTreeMap<String, Vec<u8>>,
    pub receipt: LspSnapshotImportReceiptV1,
}

/// Read and normalize one exact deterministic LSP snapshot JSON file.
pub fn import_pinned_lsp_snapshot_json_file_v1(
    path: &Path,
    pin: &LspSnapshotFilePinV1,
) -> Result<LspSnapshotImportV1, LspSnapshotAdapterErrorV1> {
    pin.validate()?;
    let bytes = read_bounded_regular_file(path, pin.max_file_bytes)?;
    if sha256(&bytes) != pin.file_sha256 {
        return Err(LspSnapshotAdapterErrorV1::PinMismatch);
    }

    let mut root: LspSnapshotRoot =
        serde_json::from_slice(&bytes).map_err(|_| LspSnapshotAdapterErrorV1::JsonInvalid)?;
    if root.schema.version != SUPPORTED_SNAPSHOT_SCHEMA {
        return Err(LspSnapshotAdapterErrorV1::SchemaUnsupported);
    }
    if root.protocol_version != SUPPORTED_LSP_PROTOCOL {
        return Err(LspSnapshotAdapterErrorV1::ProtocolUnsupported);
    }
    if root.position_encoding != SUPPORTED_POSITION_ENCODING {
        return Err(LspSnapshotAdapterErrorV1::PositionEncodingUnsupported);
    }
    if root.capture.mode != FROZEN_CAPTURE_MODE
        || root.capture.lsp_server_invocation_count != 0
        || root.capture.json_rpc_request_count != 0
        || root.capture.json_rpc_response_count != 0
    {
        return Err(LspSnapshotAdapterErrorV1::LiveResponseRejected);
    }
    if !root.capture.deterministic {
        return Err(LspSnapshotAdapterErrorV1::NonDeterministic);
    }
    if root.schema.version != pin.schema_version
        || root.schema.sha256 != pin.schema_sha256
        || root.protocol_version != pin.protocol_version
        || root.position_encoding != pin.position_encoding
        || root.producer.name != pin.producer_name
        || root.producer.version != pin.producer_version
        || root.producer.commit != pin.producer_commit
        || root.producer.license != pin.producer_license
        || root.producer.config_sha256 != pin.producer_config_sha256
        || root.source_snapshot_sha256 != pin.source_snapshot_sha256
    {
        return Err(LspSnapshotAdapterErrorV1::PinMismatch);
    }
    if root.documents.is_empty() {
        return Err(LspSnapshotAdapterErrorV1::BundleInvalid);
    }
    root.documents
        .sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    let producer_config_identity = root
        .producer
        .config_sha256
        .strip_prefix("sha256:")
        .ok_or(LspSnapshotAdapterErrorV1::PinMismatch)?;

    let descriptor = AdapterDescriptorV1 {
        schema_version: "gtkg.adapter-descriptor/v1".to_owned(),
        adapter_id: format!("gtkg.adapter.lsp_snapshot.{}", root.producer.name),
        kind: AdapterKindV1::LspSnapshot,
        adapter_version: root.producer.version.clone(),
        schema_sha256: root.schema.sha256.clone(),
        source_commit: root.producer.commit.clone(),
        license: root.producer.license.clone(),
        capabilities: vec![
            "diagnostics".to_owned(),
            "frozen_snapshot".to_owned(),
            format!("lsp_protocol_{}", root.protocol_version),
            format!("position_encoding_{}", root.position_encoding),
            format!("producer_config_sha256_{producer_config_identity}"),
            "producer_config_bound".to_owned(),
            "source_ranges".to_owned(),
            "symbols".to_owned(),
        ],
        trust_policy_id: "gtkg.adapter-trust/v1".to_owned(),
        descriptor_sha256: String::new(),
    }
    .with_computed_digest()
    .map_err(|_| LspSnapshotAdapterErrorV1::PinMismatch)?;

    let normalized = normalize_documents(&root)?;
    let bundle = build_bundle(&root.source_snapshot_sha256, &descriptor, &normalized)?;
    let mut receipt = LspSnapshotImportReceiptV1 {
        schema_version: RECEIPT_SCHEMA.to_owned(),
        snapshot_file_sha256: pin.file_sha256.clone(),
        snapshot_schema_sha256: root.schema.sha256,
        protocol_version: root.protocol_version,
        position_encoding: root.position_encoding,
        producer_name: root.producer.name,
        producer_version: root.producer.version,
        producer_commit: root.producer.commit,
        producer_license: root.producer.license,
        producer_config_sha256: root.producer.config_sha256,
        source_snapshot_sha256: root.source_snapshot_sha256,
        adapter_descriptor_sha256: descriptor.descriptor_sha256.clone(),
        bundle_sha256: bundle.bundle_sha256.clone(),
        document_count: normalized.document_count,
        symbol_count: normalized.symbol_count,
        diagnostic_count: normalized.diagnostic_count,
        relationship_count: normalized.relationship_count,
        source_range_count: bundle.evidence.len() as u64,
        discovered_count: bundle.discovered_count,
        admitted_count: bundle.admitted_count,
        omitted_count: bundle.omitted_count,
        lsp_server_invocation_count: 0,
        json_rpc_request_count: 0,
        json_rpc_response_count: 0,
        target_execution_count: 0,
        network_call_count: 0,
        write_count: 0,
        canonical_write_count: 0,
        receipt_sha256: String::new(),
    };
    receipt.receipt_sha256 = receipt_digest(&receipt)?;
    receipt.validate()?;

    Ok(LspSnapshotImportV1 {
        descriptor,
        bundle,
        source_files: normalized.source_files,
        receipt,
    })
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LspSnapshotRoot {
    schema: LspSnapshotSchemaIdentity,
    protocol_version: String,
    position_encoding: String,
    producer: LspProducerIdentity,
    source_snapshot_sha256: String,
    capture: LspCaptureIdentity,
    documents: Vec<LspDocument>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LspSnapshotSchemaIdentity {
    version: String,
    sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LspProducerIdentity {
    name: String,
    version: String,
    commit: String,
    license: String,
    config_sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LspCaptureIdentity {
    mode: String,
    deterministic: bool,
    lsp_server_invocation_count: u64,
    json_rpc_request_count: u64,
    json_rpc_response_count: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LspDocument {
    relative_path: String,
    language_id: String,
    text: String,
    text_sha256: String,
    symbols: Vec<LspSymbol>,
    diagnostics: Vec<LspDiagnostic>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct LspSymbol {
    symbol_id: String,
    name: String,
    kind: String,
    range: [u64; 4],
    selection_range: [u64; 4],
    references: Vec<LspReference>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct LspReference {
    kind: String,
    range: [u64; 4],
    target_reference: String,
    target_symbol_ids: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct LspDiagnostic {
    diagnostic_id: String,
    severity: LspDiagnosticSeverity,
    code: String,
    message: String,
    range: [u64; 4],
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum LspDiagnosticSeverity {
    Error,
    Warning,
    Information,
    Hint,
}

impl LspDiagnosticSeverity {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warning => "warning",
            Self::Information => "information",
            Self::Hint => "hint",
        }
    }
}

#[derive(Debug, Serialize)]
struct LspSourceIdentity<'a> {
    language_id: &'a str,
    relative_path: &'a str,
    text_sha256: &'a str,
}

#[derive(Debug)]
struct NormalizedSymbol {
    symbol: LspSymbol,
    source_logical_path: String,
    source_node_id: String,
}

#[derive(Debug)]
struct NormalizedLsp {
    document_count: u64,
    symbol_count: u64,
    diagnostic_count: u64,
    relationship_count: u64,
    nodes: Vec<ExternalNodeFactV1>,
    edges: Vec<ExternalEdgeFactV1>,
    evidence: BTreeMap<String, ExternalEvidenceV1>,
    source_files: BTreeMap<String, Vec<u8>>,
}

fn normalize_documents(root: &LspSnapshotRoot) -> Result<NormalizedLsp, LspSnapshotAdapterErrorV1> {
    let mut nodes = Vec::new();
    let mut evidence = BTreeMap::new();
    let mut source_files = BTreeMap::new();
    let mut source_identities = Vec::with_capacity(root.documents.len());
    let mut symbols = BTreeMap::new();
    let mut diagnostic_ids = BTreeSet::new();
    let mut diagnostic_count = 0_u64;

    for document in &root.documents {
        if !relative_logical_path(&document.relative_path)
            || !identity_component(&document.language_id)
            || validate_sha256(&document.text_sha256).is_err()
            || sha256(document.text.as_bytes()) != document.text_sha256
        {
            return Err(LspSnapshotAdapterErrorV1::SourceTampered);
        }
        if source_files
            .insert(
                document.relative_path.clone(),
                document.text.as_bytes().to_vec(),
            )
            .is_some()
        {
            return Err(LspSnapshotAdapterErrorV1::BundleInvalid);
        }
        source_identities.push(LspSourceIdentity {
            language_id: &document.language_id,
            relative_path: &document.relative_path,
            text_sha256: &document.text_sha256,
        });

        let mut document_symbols = document.symbols.clone();
        document_symbols.sort_by(|left, right| left.symbol_id.cmp(&right.symbol_id));
        for symbol in document_symbols {
            if !local_identity(&symbol.symbol_id)
                || symbol.name.trim().is_empty()
                || !identity_component(&symbol.kind)
            {
                return Err(LspSnapshotAdapterErrorV1::BundleInvalid);
            }
            let (range_start, range_end) = byte_range(&document.text, symbol.range)?;
            let (selection_start, selection_end) =
                byte_range(&document.text, symbol.selection_range)?;
            if selection_start < range_start || selection_end > range_end {
                return Err(LspSnapshotAdapterErrorV1::RangeInvalid);
            }
            let node_id = stable_id("lsp-node", &(&document.relative_path, &symbol.symbol_id))?;
            let range_evidence = insert_evidence(
                &mut evidence,
                root,
                document,
                "symbol_range",
                &symbol.symbol_id,
                range_start,
                range_end,
                FactTrustStateV1::Extracted,
            )?;
            let selection_evidence = insert_evidence(
                &mut evidence,
                root,
                document,
                "symbol_selection_range",
                &symbol.symbol_id,
                selection_start,
                selection_end,
                FactTrustStateV1::Extracted,
            )?;
            let mut evidence_ids = vec![range_evidence, selection_evidence];
            evidence_ids.sort();
            nodes.push(ExternalNodeFactV1 {
                fact_id: stable_id(
                    "lsp-fact-symbol",
                    &(&document.relative_path, &symbol.symbol_id),
                )?,
                node_id: node_id.clone(),
                node_kind: format!("lsp.symbol.{}", symbol.kind),
                name: symbol.name.clone(),
                candidate_state: CandidateFactStateV1::CandidateExternal,
                trust_state: FactTrustStateV1::Extracted,
                evidence_ids,
            });
            let key = symbol.symbol_id.clone();
            if symbols
                .insert(
                    key,
                    NormalizedSymbol {
                        symbol,
                        source_logical_path: document.relative_path.clone(),
                        source_node_id: node_id,
                    },
                )
                .is_some()
            {
                return Err(LspSnapshotAdapterErrorV1::BundleInvalid);
            }
        }

        let mut diagnostics = document.diagnostics.clone();
        diagnostics.sort_by(|left, right| left.diagnostic_id.cmp(&right.diagnostic_id));
        for diagnostic in diagnostics {
            if !local_identity(&diagnostic.diagnostic_id)
                || !local_identity(&diagnostic.code)
                || diagnostic.message.trim().is_empty()
                || !diagnostic_ids.insert((
                    document.relative_path.clone(),
                    diagnostic.diagnostic_id.clone(),
                ))
            {
                return Err(LspSnapshotAdapterErrorV1::BundleInvalid);
            }
            let (start, end) = byte_range(&document.text, diagnostic.range)?;
            let evidence_id = insert_evidence(
                &mut evidence,
                root,
                document,
                "diagnostic_range",
                &diagnostic.diagnostic_id,
                start,
                end,
                FactTrustStateV1::Extracted,
            )?;
            nodes.push(ExternalNodeFactV1 {
                fact_id: stable_id(
                    "lsp-fact-diagnostic",
                    &(&document.relative_path, &diagnostic.diagnostic_id),
                )?,
                node_id: stable_id(
                    "lsp-diagnostic",
                    &(&document.relative_path, &diagnostic.diagnostic_id),
                )?,
                node_kind: format!("lsp.diagnostic.{}", diagnostic.severity.as_str()),
                name: format!("{}: {}", diagnostic.code, diagnostic.message),
                candidate_state: CandidateFactStateV1::CandidateExternal,
                trust_state: FactTrustStateV1::Extracted,
                evidence_ids: vec![evidence_id],
            });
            diagnostic_count += 1;
        }
    }

    source_identities.sort_by(|left, right| left.relative_path.cmp(right.relative_path));
    let mut source_manifest = serde_json::to_vec(&source_identities)
        .map_err(|_| LspSnapshotAdapterErrorV1::SourceTampered)?;
    source_manifest.push(b'\n');
    if sha256(&source_manifest) != root.source_snapshot_sha256 || symbols.is_empty() {
        return Err(LspSnapshotAdapterErrorV1::SourceTampered);
    }

    let mut edges = Vec::new();
    let mut relationship_ids = BTreeSet::new();
    for (source_symbol_id, normalized) in &symbols {
        let document = root
            .documents
            .iter()
            .find(|document| document.relative_path == normalized.source_logical_path)
            .ok_or(LspSnapshotAdapterErrorV1::BundleInvalid)?;
        let (source_range_start, source_range_end) =
            byte_range(&document.text, normalized.symbol.range)?;
        let mut references = normalized.symbol.references.clone();
        for reference in &mut references {
            let original_count = reference.target_symbol_ids.len();
            reference.target_symbol_ids.sort();
            reference.target_symbol_ids.dedup();
            if reference.target_symbol_ids.len() != original_count {
                return Err(LspSnapshotAdapterErrorV1::BundleInvalid);
            }
        }
        references.sort_by(|left, right| {
            (
                &left.kind,
                left.range,
                &left.target_reference,
                &left.target_symbol_ids,
            )
                .cmp(&(
                    &right.kind,
                    right.range,
                    &right.target_reference,
                    &right.target_symbol_ids,
                ))
        });
        for reference in references {
            let edge_kind = relationship_kind(&reference.kind)?;
            if reference.target_reference.trim().is_empty()
                || reference
                    .target_symbol_ids
                    .iter()
                    .any(|target| !local_identity(target))
            {
                return Err(LspSnapshotAdapterErrorV1::BundleInvalid);
            }
            let identity = (
                source_symbol_id.as_str(),
                edge_kind,
                reference.range,
                reference.target_reference.as_str(),
                reference.target_symbol_ids.as_slice(),
            );
            let identity_digest = canonical_json_sha256(&identity)
                .map_err(|_| LspSnapshotAdapterErrorV1::BundleInvalid)?;
            if !relationship_ids.insert(identity_digest) {
                return Err(LspSnapshotAdapterErrorV1::BundleInvalid);
            }
            let (start, end) = byte_range(&document.text, reference.range)?;
            if start < source_range_start
                || end > source_range_end
                || document.text.as_bytes().get(start..end)
                    != Some(reference.target_reference.as_bytes())
            {
                return Err(LspSnapshotAdapterErrorV1::RangeInvalid);
            }
            let mut candidate_node_ids = reference
                .target_symbol_ids
                .iter()
                .filter_map(|target| symbols.get(target))
                .map(|target| target.source_node_id.clone())
                .collect::<Vec<_>>();
            candidate_node_ids.sort();
            let missing_targets = candidate_node_ids.len() != reference.target_symbol_ids.len();
            let (candidate_state, trust_state) = match (candidate_node_ids.len(), missing_targets) {
                (1, false) => (
                    CandidateFactStateV1::CandidateExternal,
                    FactTrustStateV1::Extracted,
                ),
                (0, _) => (
                    CandidateFactStateV1::LocatorOnly,
                    FactTrustStateV1::Unverified,
                ),
                _ => (CandidateFactStateV1::Ambiguous, FactTrustStateV1::Ambiguous),
            };
            let evidence_id = insert_evidence(
                &mut evidence,
                root,
                document,
                "relationship_range",
                &format!(
                    "{source_symbol_id}:{edge_kind}:{}",
                    reference.target_reference
                ),
                start,
                end,
                trust_state,
            )?;
            edges.push(ExternalEdgeFactV1 {
                fact_id: stable_id("lsp-fact-edge", &identity)?,
                edge_id: stable_id("lsp-edge", &identity)?,
                edge_kind: format!("lsp.{edge_kind}"),
                source_node_id: normalized.source_node_id.clone(),
                target_reference: reference.target_reference,
                candidate_node_ids,
                candidate_state,
                trust_state,
                evidence_ids: vec![evidence_id],
            });
        }
    }

    nodes.sort_by(|left, right| left.node_id.cmp(&right.node_id));
    edges.sort_by(|left, right| left.edge_id.cmp(&right.edge_id));
    Ok(NormalizedLsp {
        document_count: root.documents.len() as u64,
        symbol_count: symbols.len() as u64,
        diagnostic_count,
        relationship_count: edges.len() as u64,
        nodes,
        edges,
        evidence,
        source_files,
    })
}

#[allow(clippy::too_many_arguments)]
fn insert_evidence(
    evidence: &mut BTreeMap<String, ExternalEvidenceV1>,
    root: &LspSnapshotRoot,
    document: &LspDocument,
    evidence_kind: &str,
    evidence_identity: &str,
    byte_start: usize,
    byte_end: usize,
    observed_trust: FactTrustStateV1,
) -> Result<String, LspSnapshotAdapterErrorV1> {
    let snippet = document
        .text
        .as_bytes()
        .get(byte_start..byte_end)
        .ok_or(LspSnapshotAdapterErrorV1::RangeInvalid)?;
    let evidence_id = stable_id(
        "lsp-evidence",
        &(
            &document.relative_path,
            evidence_kind,
            evidence_identity,
            byte_start,
            byte_end,
        ),
    )?;
    let item = ExternalEvidenceV1 {
        evidence_id: evidence_id.clone(),
        source_snapshot_sha256: root.source_snapshot_sha256.clone(),
        source_logical_path: document.relative_path.clone(),
        source_bytes_sha256: document.text_sha256.clone(),
        byte_start: byte_start as u64,
        byte_end: byte_end as u64,
        snippet_sha256: sha256(snippet),
        observed_trust,
    };
    if evidence.insert(evidence_id.clone(), item).is_some() {
        return Err(LspSnapshotAdapterErrorV1::BundleInvalid);
    }
    Ok(evidence_id)
}

fn build_bundle(
    source_snapshot_sha256: &str,
    descriptor: &AdapterDescriptorV1,
    normalized: &NormalizedLsp,
) -> Result<ExternalFactBundleV1, LspSnapshotAdapterErrorV1> {
    let candidate_states = normalized
        .nodes
        .iter()
        .map(|node| node.candidate_state)
        .chain(normalized.edges.iter().map(|edge| edge.candidate_state))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let admitted_count = (normalized.nodes.len() + normalized.edges.len()) as u64;
    ExternalFactBundleV1 {
        schema_version: "gtkg.external-fact-bundle/v1".to_owned(),
        source_snapshot_sha256: source_snapshot_sha256.to_owned(),
        adapter_descriptor_sha256: descriptor.descriptor_sha256.clone(),
        nodes: normalized.nodes.clone(),
        edges: normalized.edges.clone(),
        evidence: normalized.evidence.values().cloned().collect(),
        candidate_states,
        discovered_count: admitted_count,
        admitted_count,
        omitted_count: 0,
        omissions: Vec::new(),
        bundle_sha256: String::new(),
    }
    .with_computed_digest()
    .map_err(|_| LspSnapshotAdapterErrorV1::BundleInvalid)
}

fn relationship_kind(kind: &str) -> Result<&'static str, LspSnapshotAdapterErrorV1> {
    match kind {
        "reference" => Ok("reference"),
        "call" => Ok("call"),
        "implementation" => Ok("implementation"),
        "type_definition" => Ok("type_definition"),
        _ => Err(LspSnapshotAdapterErrorV1::RelationshipUnsupported),
    }
}

fn byte_range(text: &str, range: [u64; 4]) -> Result<(usize, usize), LspSnapshotAdapterErrorV1> {
    let start_line =
        usize::try_from(range[0]).map_err(|_| LspSnapshotAdapterErrorV1::RangeInvalid)?;
    let start_column =
        usize::try_from(range[1]).map_err(|_| LspSnapshotAdapterErrorV1::RangeInvalid)?;
    let end_line =
        usize::try_from(range[2]).map_err(|_| LspSnapshotAdapterErrorV1::RangeInvalid)?;
    let end_column =
        usize::try_from(range[3]).map_err(|_| LspSnapshotAdapterErrorV1::RangeInvalid)?;
    if (start_line, start_column) >= (end_line, end_column) {
        return Err(LspSnapshotAdapterErrorV1::RangeInvalid);
    }

    let bytes = text.as_bytes();
    let mut line_starts = vec![0_usize];
    for (index, byte) in bytes.iter().enumerate() {
        if *byte == b'\n' {
            line_starts.push(index + 1);
        }
    }
    let line_position = |line: usize, column: usize| -> Option<usize> {
        let start = *line_starts.get(line)?;
        let mut end = line_starts
            .get(line + 1)
            .map_or(bytes.len(), |next| next.saturating_sub(1));
        if end > start && bytes.get(end.saturating_sub(1)) == Some(&b'\r') {
            end -= 1;
        }
        let position = start.checked_add(column)?;
        (position <= end && text.is_char_boundary(position)).then_some(position)
    };
    let start =
        line_position(start_line, start_column).ok_or(LspSnapshotAdapterErrorV1::RangeInvalid)?;
    let end = line_position(end_line, end_column).ok_or(LspSnapshotAdapterErrorV1::RangeInvalid)?;
    if start >= end {
        return Err(LspSnapshotAdapterErrorV1::RangeInvalid);
    }
    Ok((start, end))
}

fn read_bounded_regular_file(
    path: &Path,
    max_file_bytes: u64,
) -> Result<Vec<u8>, LspSnapshotAdapterErrorV1> {
    let before =
        std::fs::symlink_metadata(path).map_err(|_| LspSnapshotAdapterErrorV1::FileInvalid)?;
    if before.file_type().is_symlink()
        || !before.file_type().is_file()
        || before.len() > max_file_bytes
        || private_link_check(&before).is_err()
    {
        return Err(LspSnapshotAdapterErrorV1::FileInvalid);
    }
    let file = open_regular_nofollow(path)?;
    let opened = file
        .metadata()
        .map_err(|_| LspSnapshotAdapterErrorV1::FileInvalid)?;
    if !opened.file_type().is_file()
        || opened.len() > max_file_bytes
        || !same_file_snapshot(&before, &opened)
        || private_link_check(&opened).is_err()
    {
        return Err(LspSnapshotAdapterErrorV1::FileInvalid);
    }
    let mut reader = file.take(max_file_bytes.saturating_add(1));
    let mut bytes = Vec::new();
    reader
        .read_to_end(&mut bytes)
        .map_err(|_| LspSnapshotAdapterErrorV1::FileInvalid)?;
    if bytes.len() as u64 > max_file_bytes {
        return Err(LspSnapshotAdapterErrorV1::FileInvalid);
    }
    let opened_after = reader
        .get_ref()
        .metadata()
        .map_err(|_| LspSnapshotAdapterErrorV1::FileInvalid)?;
    let path_after =
        std::fs::symlink_metadata(path).map_err(|_| LspSnapshotAdapterErrorV1::FileInvalid)?;
    if !same_file_snapshot(&opened, &opened_after)
        || !same_file_snapshot(&opened, &path_after)
        || private_link_check(&opened_after).is_err()
        || private_link_check(&path_after).is_err()
    {
        return Err(LspSnapshotAdapterErrorV1::FileInvalid);
    }
    Ok(bytes)
}

#[cfg(unix)]
fn open_regular_nofollow(path: &Path) -> Result<File, LspSnapshotAdapterErrorV1> {
    use rustix::fs::{Mode, OFlags, open};

    let descriptor = open(
        path,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| LspSnapshotAdapterErrorV1::FileInvalid)?;
    Ok(File::from(descriptor))
}

#[cfg(not(unix))]
fn open_regular_nofollow(path: &Path) -> Result<File, LspSnapshotAdapterErrorV1> {
    File::open(path).map_err(|_| LspSnapshotAdapterErrorV1::FileInvalid)
}

#[cfg(unix)]
fn same_file_snapshot(left: &Metadata, right: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;

    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}

#[cfg(not(unix))]
fn same_file_snapshot(left: &Metadata, right: &Metadata) -> bool {
    left.file_type().is_file() && right.file_type().is_file() && left.len() == right.len()
}

#[cfg(unix)]
fn private_link_check(metadata: &Metadata) -> Result<(), ()> {
    use std::os::unix::fs::MetadataExt;

    (metadata.nlink() == 1).then_some(()).ok_or(())
}

#[cfg(not(unix))]
fn private_link_check(_metadata: &Metadata) -> Result<(), ()> {
    Ok(())
}

fn stable_id<T: Serialize>(prefix: &str, value: &T) -> Result<String, LspSnapshotAdapterErrorV1> {
    let digest =
        canonical_json_sha256(value).map_err(|_| LspSnapshotAdapterErrorV1::BundleInvalid)?;
    let hexadecimal = digest
        .strip_prefix("sha256:")
        .ok_or(LspSnapshotAdapterErrorV1::BundleInvalid)?;
    Ok(format!("{prefix}-{hexadecimal}"))
}

fn receipt_digest(
    receipt: &LspSnapshotImportReceiptV1,
) -> Result<String, LspSnapshotAdapterErrorV1> {
    #[derive(Serialize)]
    struct ReceiptIdentity<'a> {
        schema_version: &'a str,
        snapshot_file_sha256: &'a str,
        snapshot_schema_sha256: &'a str,
        protocol_version: &'a str,
        position_encoding: &'a str,
        producer_name: &'a str,
        producer_version: &'a str,
        producer_commit: &'a str,
        producer_license: &'a str,
        producer_config_sha256: &'a str,
        source_snapshot_sha256: &'a str,
        adapter_descriptor_sha256: &'a str,
        bundle_sha256: &'a str,
        document_count: u64,
        symbol_count: u64,
        diagnostic_count: u64,
        relationship_count: u64,
        source_range_count: u64,
        discovered_count: u64,
        admitted_count: u64,
        omitted_count: u64,
        lsp_server_invocation_count: u64,
        json_rpc_request_count: u64,
        json_rpc_response_count: u64,
        target_execution_count: u64,
        network_call_count: u64,
        write_count: u64,
        canonical_write_count: u64,
    }
    canonical_json_sha256(&ReceiptIdentity {
        schema_version: &receipt.schema_version,
        snapshot_file_sha256: &receipt.snapshot_file_sha256,
        snapshot_schema_sha256: &receipt.snapshot_schema_sha256,
        protocol_version: &receipt.protocol_version,
        position_encoding: &receipt.position_encoding,
        producer_name: &receipt.producer_name,
        producer_version: &receipt.producer_version,
        producer_commit: &receipt.producer_commit,
        producer_license: &receipt.producer_license,
        producer_config_sha256: &receipt.producer_config_sha256,
        source_snapshot_sha256: &receipt.source_snapshot_sha256,
        adapter_descriptor_sha256: &receipt.adapter_descriptor_sha256,
        bundle_sha256: &receipt.bundle_sha256,
        document_count: receipt.document_count,
        symbol_count: receipt.symbol_count,
        diagnostic_count: receipt.diagnostic_count,
        relationship_count: receipt.relationship_count,
        source_range_count: receipt.source_range_count,
        discovered_count: receipt.discovered_count,
        admitted_count: receipt.admitted_count,
        omitted_count: receipt.omitted_count,
        lsp_server_invocation_count: receipt.lsp_server_invocation_count,
        json_rpc_request_count: receipt.json_rpc_request_count,
        json_rpc_response_count: receipt.json_rpc_response_count,
        target_execution_count: receipt.target_execution_count,
        network_call_count: receipt.network_call_count,
        write_count: receipt.write_count,
        canonical_write_count: receipt.canonical_write_count,
    })
    .map_err(|_| LspSnapshotAdapterErrorV1::ReceiptInvalid)
}

fn relative_logical_path(value: &str) -> bool {
    let path = Path::new(value);
    !value.is_empty()
        && !value.contains('\\')
        && path.is_relative()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

fn local_identity(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'+' | b'-'))
}

fn identity_component(value: &str) -> bool {
    local_identity(value)
}

fn floating_version(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "latest" | "current" | "head"
    )
}

fn unknown_license(value: &str) -> bool {
    value.trim().eq_ignore_ascii_case("unknown")
}

fn commit_identity(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}
