//! A02 pinned, file-only SCIP JSON adapter.
//!
//! The adapter reads one digest-pinned regular file and emits an A00
//! [`ExternalFactBundleV1`]. It never starts a language process, reaches the
//! network, writes target state, or promotes candidate facts into canonical
//! knowledge.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
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

const SUPPORTED_SCIP_SCHEMA: &str = "scip/0.4-json";
const RECEIPT_SCHEMA: &str = "gtkg.scip-import-receipt/v1";

/// Exact identities and size budget required before a SCIP file can be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScipFilePinV1 {
    pub file_sha256: String,
    pub schema_version: String,
    pub schema_sha256: String,
    pub tool_name: String,
    pub tool_version: String,
    pub tool_commit: String,
    pub tool_license: String,
    pub source_snapshot_sha256: String,
    pub max_file_bytes: u64,
}

impl ScipFilePinV1 {
    pub fn validate(&self) -> Result<(), ScipAdapterErrorV1> {
        let version_is_floating = matches!(
            self.tool_version.to_ascii_lowercase().as_str(),
            "latest" | "current" | "head"
        );
        if validate_sha256(&self.file_sha256).is_err()
            || self.schema_version != SUPPORTED_SCIP_SCHEMA
            || validate_sha256(&self.schema_sha256).is_err()
            || !identity_component(&self.tool_name)
            || self.tool_version.trim().is_empty()
            || version_is_floating
            || !commit_identity(&self.tool_commit)
            || self.tool_license.trim().is_empty()
            || self.tool_license.eq_ignore_ascii_case("unknown")
            || validate_sha256(&self.source_snapshot_sha256).is_err()
            || self.max_file_bytes == 0
        {
            return Err(ScipAdapterErrorV1::PinMismatch);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ScipAdapterErrorV1 {
    #[error("SCIP input is not a bounded regular file")]
    FileInvalid,
    #[error("SCIP JSON is not closed or well formed")]
    JsonInvalid,
    #[error("SCIP file or declared identity differs from the exact pin")]
    PinMismatch,
    #[error("SCIP schema version is unsupported")]
    SchemaUnsupported,
    #[error("SCIP source bytes or snapshot identity is tampered")]
    SourceTampered,
    #[error("SCIP source range is invalid")]
    RangeInvalid,
    #[error("SCIP relationship kind is unsupported")]
    RelationshipUnsupported,
    #[error("SCIP candidate bundle is invalid")]
    BundleInvalid,
    #[error("SCIP import receipt is invalid")]
    ReceiptInvalid,
}

impl ScipAdapterErrorV1 {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::FileInvalid => "E_SCIP_FILE_INVALID",
            Self::JsonInvalid => "E_SCIP_JSON_INVALID",
            Self::PinMismatch => "E_SCIP_PIN_MISMATCH",
            Self::SchemaUnsupported => "E_SCIP_SCHEMA_UNSUPPORTED",
            Self::SourceTampered => "E_SCIP_SOURCE_TAMPERED",
            Self::RangeInvalid => "E_SCIP_RANGE_INVALID",
            Self::RelationshipUnsupported => "E_SCIP_RELATION_UNSUPPORTED",
            Self::BundleInvalid => "E_SCIP_BUNDLE_INVALID",
            Self::ReceiptInvalid => "E_SCIP_RECEIPT_INVALID",
        }
    }
}

/// Bounded evidence that the adapter used only the pinned file path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScipImportReceiptV1 {
    pub schema_version: String,
    pub scip_file_sha256: String,
    pub source_snapshot_sha256: String,
    pub adapter_descriptor_sha256: String,
    pub bundle_sha256: String,
    pub document_count: u64,
    pub symbol_count: u64,
    pub relationship_count: u64,
    pub discovered_count: u64,
    pub admitted_count: u64,
    pub omitted_count: u64,
    pub target_execution_count: u64,
    pub network_call_count: u64,
    pub write_count: u64,
    pub canonical_write_count: u64,
    pub receipt_sha256: String,
}

impl ScipImportReceiptV1 {
    pub fn validate(&self) -> Result<(), ScipAdapterErrorV1> {
        if self.schema_version != RECEIPT_SCHEMA
            || validate_sha256(&self.scip_file_sha256).is_err()
            || validate_sha256(&self.source_snapshot_sha256).is_err()
            || validate_sha256(&self.adapter_descriptor_sha256).is_err()
            || validate_sha256(&self.bundle_sha256).is_err()
            || self.document_count == 0
            || self.symbol_count == 0
            || self.discovered_count != self.admitted_count + self.omitted_count
            || self.admitted_count != self.symbol_count + self.relationship_count
            || self.target_execution_count != 0
            || self.network_call_count != 0
            || self.write_count != 0
            || self.canonical_write_count != 0
            || self.receipt_sha256 != receipt_digest(self)?
        {
            return Err(ScipAdapterErrorV1::ReceiptInvalid);
        }
        Ok(())
    }
}

/// Candidate facts plus exact source bytes for A00 source replay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScipImportV1 {
    pub descriptor: AdapterDescriptorV1,
    pub bundle: ExternalFactBundleV1,
    pub source_files: BTreeMap<String, Vec<u8>>,
    pub receipt: ScipImportReceiptV1,
}

/// Read and normalize one exact, frozen SCIP JSON export.
pub fn import_pinned_scip_json_file_v1(
    path: &Path,
    pin: &ScipFilePinV1,
) -> Result<ScipImportV1, ScipAdapterErrorV1> {
    pin.validate()?;
    let bytes = read_bounded_regular_file(path, pin.max_file_bytes)?;
    if sha256(&bytes) != pin.file_sha256 {
        return Err(ScipAdapterErrorV1::PinMismatch);
    }

    let mut root: ScipJsonRoot =
        serde_json::from_slice(&bytes).map_err(|_| ScipAdapterErrorV1::JsonInvalid)?;
    if root.schema.version != SUPPORTED_SCIP_SCHEMA {
        return Err(ScipAdapterErrorV1::SchemaUnsupported);
    }
    if root.schema.version != pin.schema_version
        || root.schema.sha256 != pin.schema_sha256
        || root.tool.name != pin.tool_name
        || root.tool.version != pin.tool_version
        || root.tool.commit != pin.tool_commit
        || root.tool.license != pin.tool_license
        || root.source_snapshot_sha256 != pin.source_snapshot_sha256
    {
        return Err(ScipAdapterErrorV1::PinMismatch);
    }
    if root.documents.is_empty() {
        return Err(ScipAdapterErrorV1::BundleInvalid);
    }
    root.documents
        .sort_by(|left, right| left.relative_path.cmp(&right.relative_path));

    let descriptor = AdapterDescriptorV1 {
        schema_version: "gtkg.adapter-descriptor/v1".to_owned(),
        adapter_id: format!("gtkg.adapter.scip.{}", root.tool.name),
        kind: AdapterKindV1::Scip,
        adapter_version: root.tool.version.clone(),
        schema_sha256: root.schema.sha256.clone(),
        source_commit: root.tool.commit.clone(),
        license: root.tool.license.clone(),
        capabilities: vec![
            "relationships".to_owned(),
            "source_ranges".to_owned(),
            "symbols".to_owned(),
        ],
        trust_policy_id: "gtkg.adapter-trust/v1".to_owned(),
        descriptor_sha256: String::new(),
    }
    .with_computed_digest()
    .map_err(|_| ScipAdapterErrorV1::PinMismatch)?;

    let normalized = normalize_documents(&root)?;
    let bundle = build_bundle(&root.source_snapshot_sha256, &descriptor, &normalized)?;
    let mut receipt = ScipImportReceiptV1 {
        schema_version: RECEIPT_SCHEMA.to_owned(),
        scip_file_sha256: pin.file_sha256.clone(),
        source_snapshot_sha256: root.source_snapshot_sha256,
        adapter_descriptor_sha256: descriptor.descriptor_sha256.clone(),
        bundle_sha256: bundle.bundle_sha256.clone(),
        document_count: normalized.document_count,
        symbol_count: bundle.nodes.len() as u64,
        relationship_count: bundle.edges.len() as u64,
        discovered_count: bundle.discovered_count,
        admitted_count: bundle.admitted_count,
        omitted_count: bundle.omitted_count,
        target_execution_count: 0,
        network_call_count: 0,
        write_count: 0,
        canonical_write_count: 0,
        receipt_sha256: String::new(),
    };
    receipt.receipt_sha256 = receipt_digest(&receipt)?;
    receipt.validate()?;

    Ok(ScipImportV1 {
        descriptor,
        bundle,
        source_files: normalized.source_files,
        receipt,
    })
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScipJsonRoot {
    schema: ScipSchemaIdentity,
    tool: ScipToolIdentity,
    source_snapshot_sha256: String,
    documents: Vec<ScipDocument>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScipSchemaIdentity {
    version: String,
    sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScipToolIdentity {
    name: String,
    version: String,
    commit: String,
    license: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScipDocument {
    relative_path: String,
    language: String,
    text: String,
    text_sha256: String,
    occurrences: Vec<ScipOccurrence>,
    symbols: Vec<ScipSymbol>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScipOccurrence {
    range: [u64; 4],
    symbol: String,
    role: ScipOccurrenceRole,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ScipOccurrenceRole {
    Definition,
    Reference,
}

impl ScipOccurrenceRole {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Definition => "definition",
            Self::Reference => "reference",
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScipSymbol {
    symbol: String,
    display_name: String,
    kind: String,
    relationships: Vec<ScipRelationship>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScipRelationship {
    symbol: String,
    kind: String,
}

#[derive(Debug, Serialize)]
struct ScipSourceIdentity<'a> {
    language: &'a str,
    relative_path: &'a str,
    text_sha256: &'a str,
}

#[derive(Debug)]
struct NormalizedScip {
    document_count: u64,
    symbols: BTreeMap<String, ScipSymbol>,
    evidence: BTreeMap<String, ExternalEvidenceV1>,
    evidence_by_symbol: BTreeMap<String, Vec<String>>,
    reference_evidence_by_symbol: BTreeMap<String, Vec<String>>,
    source_files: BTreeMap<String, Vec<u8>>,
}

fn normalize_documents(root: &ScipJsonRoot) -> Result<NormalizedScip, ScipAdapterErrorV1> {
    let mut symbols = BTreeMap::new();
    let mut evidence = BTreeMap::new();
    let mut evidence_by_symbol: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut reference_evidence_by_symbol: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut source_files = BTreeMap::new();
    let mut source_identities = Vec::with_capacity(root.documents.len());

    for document in &root.documents {
        if !relative_logical_path(&document.relative_path)
            || !identity_component(&document.language)
            || validate_sha256(&document.text_sha256).is_err()
            || sha256(document.text.as_bytes()) != document.text_sha256
        {
            return Err(ScipAdapterErrorV1::SourceTampered);
        }
        if source_files
            .insert(
                document.relative_path.clone(),
                document.text.as_bytes().to_vec(),
            )
            .is_some()
        {
            return Err(ScipAdapterErrorV1::BundleInvalid);
        }
        source_identities.push(ScipSourceIdentity {
            language: &document.language,
            relative_path: &document.relative_path,
            text_sha256: &document.text_sha256,
        });

        let mut document_symbols = document.symbols.clone();
        document_symbols.sort_by(|left, right| left.symbol.cmp(&right.symbol));
        for symbol in document_symbols {
            if symbol.symbol.trim().is_empty()
                || symbol.display_name.trim().is_empty()
                || !identity_component(&symbol.kind)
                || symbols.insert(symbol.symbol.clone(), symbol).is_some()
            {
                return Err(ScipAdapterErrorV1::BundleInvalid);
            }
        }

        for occurrence in &document.occurrences {
            if occurrence.symbol.trim().is_empty() {
                return Err(ScipAdapterErrorV1::BundleInvalid);
            }
            let (byte_start, byte_end) = byte_range(&document.text, occurrence.range)?;
            let snippet = document
                .text
                .as_bytes()
                .get(byte_start..byte_end)
                .ok_or(ScipAdapterErrorV1::RangeInvalid)?;
            let evidence_id = stable_id(
                "scip-evidence",
                &(
                    &document.relative_path,
                    byte_start,
                    byte_end,
                    &occurrence.symbol,
                    occurrence.role.as_str(),
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
                observed_trust: FactTrustStateV1::Extracted,
            };
            if evidence.insert(evidence_id.clone(), item).is_some() {
                return Err(ScipAdapterErrorV1::BundleInvalid);
            }
            evidence_by_symbol
                .entry(occurrence.symbol.clone())
                .or_default()
                .push(evidence_id.clone());
            if matches!(occurrence.role, ScipOccurrenceRole::Reference) {
                reference_evidence_by_symbol
                    .entry(occurrence.symbol.clone())
                    .or_default()
                    .push(evidence_id);
            }
        }
    }

    source_identities.sort_by(|left, right| left.relative_path.cmp(right.relative_path));
    let mut source_manifest =
        serde_json::to_vec(&source_identities).map_err(|_| ScipAdapterErrorV1::SourceTampered)?;
    source_manifest.push(b'\n');
    let computed_snapshot = sha256(&source_manifest);
    if computed_snapshot != root.source_snapshot_sha256 {
        return Err(ScipAdapterErrorV1::SourceTampered);
    }
    if symbols.is_empty()
        || evidence.is_empty()
        || symbols
            .keys()
            .any(|symbol| !evidence_by_symbol.contains_key(symbol))
        || evidence_by_symbol
            .keys()
            .any(|symbol| !symbols.contains_key(symbol))
    {
        return Err(ScipAdapterErrorV1::BundleInvalid);
    }
    for evidence_ids in evidence_by_symbol.values_mut() {
        evidence_ids.sort();
    }
    for evidence_ids in reference_evidence_by_symbol.values_mut() {
        evidence_ids.sort();
    }

    Ok(NormalizedScip {
        document_count: root.documents.len() as u64,
        symbols,
        evidence,
        evidence_by_symbol,
        reference_evidence_by_symbol,
        source_files,
    })
}

fn build_bundle(
    source_snapshot_sha256: &str,
    descriptor: &AdapterDescriptorV1,
    normalized: &NormalizedScip,
) -> Result<ExternalFactBundleV1, ScipAdapterErrorV1> {
    let mut node_ids = BTreeMap::new();
    for symbol in normalized.symbols.keys() {
        node_ids.insert(symbol.clone(), stable_id("scip-node", symbol)?);
    }

    let mut nodes = Vec::with_capacity(normalized.symbols.len());
    for (symbol, information) in &normalized.symbols {
        let evidence_ids = normalized
            .evidence_by_symbol
            .get(symbol)
            .cloned()
            .ok_or(ScipAdapterErrorV1::BundleInvalid)?;
        nodes.push(ExternalNodeFactV1 {
            fact_id: stable_id("scip-fact-node", symbol)?,
            node_id: node_ids
                .get(symbol)
                .cloned()
                .ok_or(ScipAdapterErrorV1::BundleInvalid)?,
            node_kind: information.kind.clone(),
            name: information.display_name.clone(),
            candidate_state: CandidateFactStateV1::CandidateExternal,
            trust_state: FactTrustStateV1::Extracted,
            evidence_ids,
        });
    }
    nodes.sort_by(|left, right| left.node_id.cmp(&right.node_id));

    let mut relationships = BTreeSet::new();
    let mut edges = Vec::new();
    for (source_symbol, information) in &normalized.symbols {
        let mut source_relationships = information.relationships.clone();
        source_relationships
            .sort_by(|left, right| (&left.kind, &left.symbol).cmp(&(&right.kind, &right.symbol)));
        for relationship in source_relationships {
            let edge_kind = relationship_kind(&relationship.kind)?;
            let identity = (
                source_symbol.as_str(),
                relationship.symbol.as_str(),
                edge_kind,
            );
            if !relationships.insert((
                source_symbol.clone(),
                relationship.symbol.clone(),
                edge_kind.to_owned(),
            )) {
                return Err(ScipAdapterErrorV1::BundleInvalid);
            }
            let candidate_node_ids = node_ids
                .get(&relationship.symbol)
                .cloned()
                .into_iter()
                .collect::<Vec<_>>();
            let target_is_known = !candidate_node_ids.is_empty();
            edges.push(ExternalEdgeFactV1 {
                fact_id: stable_id("scip-fact-edge", &identity)?,
                edge_id: stable_id("scip-edge", &identity)?,
                edge_kind: format!("scip.{edge_kind}"),
                source_node_id: node_ids
                    .get(source_symbol)
                    .cloned()
                    .ok_or(ScipAdapterErrorV1::BundleInvalid)?,
                target_reference: relationship.symbol.clone(),
                candidate_node_ids,
                candidate_state: if target_is_known {
                    CandidateFactStateV1::CandidateExternal
                } else {
                    CandidateFactStateV1::LocatorOnly
                },
                trust_state: if target_is_known {
                    FactTrustStateV1::Extracted
                } else {
                    FactTrustStateV1::Unverified
                },
                evidence_ids: normalized
                    .reference_evidence_by_symbol
                    .get(&relationship.symbol)
                    .cloned()
                    .ok_or(ScipAdapterErrorV1::BundleInvalid)?,
            });
        }
    }
    edges.sort_by(|left, right| left.edge_id.cmp(&right.edge_id));

    let candidate_states = nodes
        .iter()
        .map(|node| node.candidate_state)
        .chain(edges.iter().map(|edge| edge.candidate_state))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let admitted_count = (nodes.len() + edges.len()) as u64;
    ExternalFactBundleV1 {
        schema_version: "gtkg.external-fact-bundle/v1".to_owned(),
        source_snapshot_sha256: source_snapshot_sha256.to_owned(),
        adapter_descriptor_sha256: descriptor.descriptor_sha256.clone(),
        nodes,
        edges,
        evidence: normalized.evidence.values().cloned().collect(),
        candidate_states,
        discovered_count: admitted_count,
        admitted_count,
        omitted_count: 0,
        omissions: Vec::new(),
        bundle_sha256: String::new(),
    }
    .with_computed_digest()
    .map_err(|_| ScipAdapterErrorV1::BundleInvalid)
}

fn relationship_kind(kind: &str) -> Result<&'static str, ScipAdapterErrorV1> {
    match kind {
        "reference" => Ok("reference"),
        "implementation" => Ok("implementation"),
        "type_definition" => Ok("type_definition"),
        "definition" => Ok("definition"),
        _ => Err(ScipAdapterErrorV1::RelationshipUnsupported),
    }
}

fn byte_range(text: &str, range: [u64; 4]) -> Result<(usize, usize), ScipAdapterErrorV1> {
    let start_line = usize::try_from(range[0]).map_err(|_| ScipAdapterErrorV1::RangeInvalid)?;
    let start_column = usize::try_from(range[1]).map_err(|_| ScipAdapterErrorV1::RangeInvalid)?;
    let end_line = usize::try_from(range[2]).map_err(|_| ScipAdapterErrorV1::RangeInvalid)?;
    let end_column = usize::try_from(range[3]).map_err(|_| ScipAdapterErrorV1::RangeInvalid)?;
    if (start_line, start_column) >= (end_line, end_column) {
        return Err(ScipAdapterErrorV1::RangeInvalid);
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
    let start = line_position(start_line, start_column).ok_or(ScipAdapterErrorV1::RangeInvalid)?;
    let end = line_position(end_line, end_column).ok_or(ScipAdapterErrorV1::RangeInvalid)?;
    if start >= end {
        return Err(ScipAdapterErrorV1::RangeInvalid);
    }
    Ok((start, end))
}

fn read_bounded_regular_file(
    path: &Path,
    max_file_bytes: u64,
) -> Result<Vec<u8>, ScipAdapterErrorV1> {
    let path_metadata =
        std::fs::symlink_metadata(path).map_err(|_| ScipAdapterErrorV1::FileInvalid)?;
    if path_metadata.file_type().is_symlink() || !path_metadata.is_file() {
        return Err(ScipAdapterErrorV1::FileInvalid);
    }
    let file = File::open(path).map_err(|_| ScipAdapterErrorV1::FileInvalid)?;
    let opened_metadata = file
        .metadata()
        .map_err(|_| ScipAdapterErrorV1::FileInvalid)?;
    if !opened_metadata.is_file() || opened_metadata.len() > max_file_bytes {
        return Err(ScipAdapterErrorV1::FileInvalid);
    }
    let mut reader = file.take(max_file_bytes.saturating_add(1));
    let mut bytes = Vec::new();
    reader
        .read_to_end(&mut bytes)
        .map_err(|_| ScipAdapterErrorV1::FileInvalid)?;
    if bytes.len() as u64 > max_file_bytes {
        return Err(ScipAdapterErrorV1::FileInvalid);
    }
    Ok(bytes)
}

fn stable_id<T: Serialize>(prefix: &str, value: &T) -> Result<String, ScipAdapterErrorV1> {
    let digest = canonical_json_sha256(value).map_err(|_| ScipAdapterErrorV1::BundleInvalid)?;
    let hexadecimal = digest
        .strip_prefix("sha256:")
        .ok_or(ScipAdapterErrorV1::BundleInvalid)?;
    Ok(format!("{prefix}-{hexadecimal}"))
}

fn receipt_digest(receipt: &ScipImportReceiptV1) -> Result<String, ScipAdapterErrorV1> {
    #[derive(Serialize)]
    struct ReceiptIdentity<'a> {
        schema_version: &'a str,
        scip_file_sha256: &'a str,
        source_snapshot_sha256: &'a str,
        adapter_descriptor_sha256: &'a str,
        bundle_sha256: &'a str,
        document_count: u64,
        symbol_count: u64,
        relationship_count: u64,
        discovered_count: u64,
        admitted_count: u64,
        omitted_count: u64,
        target_execution_count: u64,
        network_call_count: u64,
        write_count: u64,
        canonical_write_count: u64,
    }
    canonical_json_sha256(&ReceiptIdentity {
        schema_version: &receipt.schema_version,
        scip_file_sha256: &receipt.scip_file_sha256,
        source_snapshot_sha256: &receipt.source_snapshot_sha256,
        adapter_descriptor_sha256: &receipt.adapter_descriptor_sha256,
        bundle_sha256: &receipt.bundle_sha256,
        document_count: receipt.document_count,
        symbol_count: receipt.symbol_count,
        relationship_count: receipt.relationship_count,
        discovered_count: receipt.discovered_count,
        admitted_count: receipt.admitted_count,
        omitted_count: receipt.omitted_count,
        target_execution_count: receipt.target_execution_count,
        network_call_count: receipt.network_call_count,
        write_count: receipt.write_count,
        canonical_write_count: receipt.canonical_write_count,
    })
    .map_err(|_| ScipAdapterErrorV1::ReceiptInvalid)
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

fn identity_component(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'+' | b'-'))
}

fn commit_identity(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}
