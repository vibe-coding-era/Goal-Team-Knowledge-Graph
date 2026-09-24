//! A04 pinned, file-only CodeGraph community JSON export adapter.
//!
//! CodeGraph's pinned community exporter emits D3-compatible `nodes` and
//! `links` arrays. It does not embed the source bytes needed for A00 replay,
//! so this adapter deliberately preserves every imported fact as an
//! unverified locator. It never starts CodeGraph, reaches the network, writes
//! target state, or grants canonical-writer authority.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::Read;
use std::path::Path;

use gtkg_protocol::v03::AdapterKindV1;
use gtkg_protocol::v03::adapter::{
    AdapterDescriptorV1, CandidateFactStateV1, ExternalEdgeFactV1, ExternalFactBundleV1,
    ExternalNodeFactV1, FactTrustStateV1,
};
use gtkg_protocol::{canonical_json_sha256, validate_sha256};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const CODEGRAPH_PINNED_VERSION_V1: &str = "0.20.1";
pub const CODEGRAPH_PINNED_COMMIT_V1: &str = "489ccf1612555510f8367e3e673181f6a1275fe4";
pub const CODEGRAPH_PINNED_LICENSE_V1: &str = "Apache-2.0";

/// SHA-256 of the pinned `crates/codegraph/src/export/json.rs` source bytes.
///
/// The upstream format has no declared schema version. Binding the exact
/// exporter source closes that gap without claiming compatibility with later
/// or unrelated JSON shapes.
pub const CODEGRAPH_EXPORT_SCHEMA_SHA256_V1: &str =
    "sha256:b7a9743ee957d11268c5e1c2342c14d6071ae3a69ed1ed52ada0e6ab997fd1f0";

const RECEIPT_SCHEMA: &str = "gtkg.codegraph-import-receipt/v1";
const MAX_EXPORT_BYTES: u64 = 64 * 1024 * 1024;

/// Caller authorization for one exact community export file and source
/// snapshot identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeGraphExportPinV1 {
    pub file_sha256: String,
    pub schema_sha256: String,
    pub tool_version: String,
    pub tool_commit: String,
    pub tool_license: String,
    pub source_snapshot_sha256: String,
    pub max_file_bytes: u64,
}

impl CodeGraphExportPinV1 {
    pub fn validate(&self) -> Result<(), CodeGraphAdapterErrorV1> {
        if validate_sha256(&self.file_sha256).is_err()
            || self.schema_sha256 != CODEGRAPH_EXPORT_SCHEMA_SHA256_V1
            || self.tool_version != CODEGRAPH_PINNED_VERSION_V1
            || self.tool_commit != CODEGRAPH_PINNED_COMMIT_V1
            || self.tool_license != CODEGRAPH_PINNED_LICENSE_V1
            || validate_sha256(&self.source_snapshot_sha256).is_err()
            || self.max_file_bytes == 0
            || self.max_file_bytes > MAX_EXPORT_BYTES
        {
            return Err(CodeGraphAdapterErrorV1::PinMismatch);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CodeGraphAdapterErrorV1 {
    #[error("CodeGraph export is not a bounded regular file")]
    FileInvalid,
    #[error("CodeGraph export JSON is not closed or well formed")]
    JsonInvalid,
    #[error("CodeGraph export identity differs from the exact pin")]
    PinMismatch,
    #[error("CodeGraph export shape differs from the pinned community exporter")]
    SchemaUnsupported,
    #[error("CodeGraph export contains duplicate or dangling graph identities")]
    GraphInvalid,
    #[error("CodeGraph candidate bundle is invalid")]
    BundleInvalid,
    #[error("CodeGraph import receipt is invalid")]
    ReceiptInvalid,
}

impl CodeGraphAdapterErrorV1 {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::FileInvalid => "E_CODEGRAPH_FILE_INVALID",
            Self::JsonInvalid => "E_CODEGRAPH_JSON_INVALID",
            Self::PinMismatch => "E_CODEGRAPH_PIN_MISMATCH",
            Self::SchemaUnsupported => "E_CODEGRAPH_SCHEMA_UNSUPPORTED",
            Self::GraphInvalid => "E_CODEGRAPH_GRAPH_INVALID",
            Self::BundleInvalid => "E_CODEGRAPH_BUNDLE_INVALID",
            Self::ReceiptInvalid => "E_CODEGRAPH_RECEIPT_INVALID",
        }
    }
}

/// Bounded proof of the adapter's file-only effects and locator-only trust
/// ceiling.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodeGraphImportReceiptV1 {
    pub schema_version: String,
    pub codegraph_file_sha256: String,
    pub source_snapshot_sha256: String,
    pub adapter_descriptor_sha256: String,
    pub bundle_sha256: String,
    pub node_count: u64,
    pub link_count: u64,
    pub discovered_count: u64,
    pub admitted_count: u64,
    pub omitted_count: u64,
    pub source_evidence_count: u64,
    pub locator_only_count: u64,
    pub export_file_read_count: u64,
    pub target_execution_count: u64,
    pub network_call_count: u64,
    pub write_count: u64,
    pub canonical_write_count: u64,
    pub receipt_sha256: String,
}

impl CodeGraphImportReceiptV1 {
    pub fn validate(&self) -> Result<(), CodeGraphAdapterErrorV1> {
        let graph_count = self
            .node_count
            .checked_add(self.link_count)
            .ok_or(CodeGraphAdapterErrorV1::ReceiptInvalid)?;
        let denominator_count = self
            .admitted_count
            .checked_add(self.omitted_count)
            .ok_or(CodeGraphAdapterErrorV1::ReceiptInvalid)?;
        if self.schema_version != RECEIPT_SCHEMA
            || validate_sha256(&self.codegraph_file_sha256).is_err()
            || validate_sha256(&self.source_snapshot_sha256).is_err()
            || validate_sha256(&self.adapter_descriptor_sha256).is_err()
            || validate_sha256(&self.bundle_sha256).is_err()
            || self.discovered_count != denominator_count
            || self.discovered_count != graph_count
            || self.admitted_count != graph_count
            || self.omitted_count != 0
            || self.source_evidence_count != 0
            || self.locator_only_count != graph_count
            || self.export_file_read_count != 1
            || self.target_execution_count != 0
            || self.network_call_count != 0
            || self.write_count != 0
            || self.canonical_write_count != 0
            || self.receipt_sha256 != receipt_digest(self)?
        {
            return Err(CodeGraphAdapterErrorV1::ReceiptInvalid);
        }
        Ok(())
    }
}

/// Locator bundle plus an intentionally empty source-byte map.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeGraphImportV1 {
    pub descriptor: AdapterDescriptorV1,
    pub bundle: ExternalFactBundleV1,
    pub source_files: BTreeMap<String, Vec<u8>>,
    pub receipt: CodeGraphImportReceiptV1,
}

/// Read and normalize one exact, frozen CodeGraph community JSON export.
pub fn import_pinned_codegraph_json_file_v1(
    path: &Path,
    pin: &CodeGraphExportPinV1,
) -> Result<CodeGraphImportV1, CodeGraphAdapterErrorV1> {
    pin.validate()?;
    let bytes = read_bounded_regular_file(path, pin.max_file_bytes)?;
    if sha256(&bytes) != pin.file_sha256 {
        return Err(CodeGraphAdapterErrorV1::PinMismatch);
    }

    let value: Value =
        serde_json::from_slice(&bytes).map_err(|_| CodeGraphAdapterErrorV1::JsonInvalid)?;
    validate_root_shape(&value)?;
    let root: CodeGraphJsonRoot =
        serde_json::from_value(value).map_err(|_| CodeGraphAdapterErrorV1::SchemaUnsupported)?;
    validate_graph(&root)?;

    let descriptor = descriptor()?;
    let bundle = build_locator_bundle(&root, &descriptor, &pin.source_snapshot_sha256)?;
    let graph_count = bundle.admitted_count;
    let mut receipt = CodeGraphImportReceiptV1 {
        schema_version: RECEIPT_SCHEMA.to_owned(),
        codegraph_file_sha256: pin.file_sha256.clone(),
        source_snapshot_sha256: pin.source_snapshot_sha256.clone(),
        adapter_descriptor_sha256: descriptor.descriptor_sha256.clone(),
        bundle_sha256: bundle.bundle_sha256.clone(),
        node_count: root.nodes.len() as u64,
        link_count: root.links.len() as u64,
        discovered_count: graph_count,
        admitted_count: graph_count,
        omitted_count: 0,
        source_evidence_count: 0,
        locator_only_count: graph_count,
        export_file_read_count: 1,
        target_execution_count: 0,
        network_call_count: 0,
        write_count: 0,
        canonical_write_count: 0,
        receipt_sha256: String::new(),
    };
    receipt.receipt_sha256 = receipt_digest(&receipt)?;
    receipt.validate()?;

    Ok(CodeGraphImportV1 {
        descriptor,
        bundle,
        source_files: BTreeMap::new(),
        receipt,
    })
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CodeGraphJsonRoot {
    nodes: Vec<CodeGraphJsonNode>,
    links: Vec<CodeGraphJsonLink>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CodeGraphJsonNode {
    id: u64,
    #[serde(rename = "type")]
    node_type: String,
    properties: BTreeMap<String, Value>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CodeGraphJsonLink {
    id: u64,
    source: u64,
    target: u64,
    #[serde(rename = "type")]
    link_type: String,
    properties: BTreeMap<String, Value>,
}

fn descriptor() -> Result<AdapterDescriptorV1, CodeGraphAdapterErrorV1> {
    AdapterDescriptorV1 {
        schema_version: "gtkg.adapter-descriptor/v1".to_owned(),
        adapter_id: "gtkg.adapter.codegraph.community-export".to_owned(),
        kind: AdapterKindV1::CodeGraphExport,
        adapter_version: CODEGRAPH_PINNED_VERSION_V1.to_owned(),
        schema_sha256: CODEGRAPH_EXPORT_SCHEMA_SHA256_V1.to_owned(),
        source_commit: CODEGRAPH_PINNED_COMMIT_V1.to_owned(),
        license: CODEGRAPH_PINNED_LICENSE_V1.to_owned(),
        capabilities: vec![
            "community_json_export".to_owned(),
            "graph_locators".to_owned(),
            "static_file_only".to_owned(),
        ],
        trust_policy_id: "gtkg.adapter-trust/v1".to_owned(),
        descriptor_sha256: String::new(),
    }
    .with_computed_digest()
    .map_err(|_| CodeGraphAdapterErrorV1::PinMismatch)
}

fn validate_root_shape(value: &Value) -> Result<(), CodeGraphAdapterErrorV1> {
    let object = value
        .as_object()
        .ok_or(CodeGraphAdapterErrorV1::SchemaUnsupported)?;
    let keys = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
    if keys != BTreeSet::from(["links", "nodes"])
        || !object.get("nodes").is_some_and(Value::is_array)
        || !object.get("links").is_some_and(Value::is_array)
    {
        return Err(CodeGraphAdapterErrorV1::SchemaUnsupported);
    }
    Ok(())
}

fn validate_graph(root: &CodeGraphJsonRoot) -> Result<(), CodeGraphAdapterErrorV1> {
    let mut node_ids = BTreeSet::new();
    for node in &root.nodes {
        if !node_ids.insert(node.id)
            || node_kind(&node.node_type).is_none()
            || !properties_supported(&node.properties)
        {
            return Err(CodeGraphAdapterErrorV1::GraphInvalid);
        }
    }
    let mut link_ids = BTreeSet::new();
    for link in &root.links {
        if !link_ids.insert(link.id)
            || !node_ids.contains(&link.source)
            || !node_ids.contains(&link.target)
            || link_kind(&link.link_type).is_none()
            || !properties_supported(&link.properties)
        {
            return Err(CodeGraphAdapterErrorV1::GraphInvalid);
        }
    }
    Ok(())
}

fn properties_supported(properties: &BTreeMap<String, Value>) -> bool {
    properties.values().all(|value| match value {
        Value::Null | Value::Bool(_) | Value::String(_) => true,
        Value::Number(number) => number.is_i64() || number.is_f64(),
        Value::Array(values) => {
            values.is_empty()
                || values.iter().all(Value::is_string)
                || values
                    .iter()
                    .all(|item| item.as_number().is_some_and(serde_json::Number::is_i64))
        }
        Value::Object(_) => false,
    })
}

fn build_locator_bundle(
    root: &CodeGraphJsonRoot,
    descriptor: &AdapterDescriptorV1,
    source_snapshot_sha256: &str,
) -> Result<ExternalFactBundleV1, CodeGraphAdapterErrorV1> {
    let mut node_id_by_export_id = BTreeMap::new();
    let mut name_by_export_id = BTreeMap::new();
    let mut nodes = Vec::with_capacity(root.nodes.len());
    for node in &root.nodes {
        let node_id = stable_id(
            "codegraph-node",
            &(source_snapshot_sha256, node.id, &node.node_type),
        )?;
        let name = locator_name(node);
        node_id_by_export_id.insert(node.id, node_id.clone());
        name_by_export_id.insert(node.id, name.clone());
        nodes.push(ExternalNodeFactV1 {
            fact_id: stable_id(
                "codegraph-fact-node",
                &(source_snapshot_sha256, node.id, &node.node_type, &name),
            )?,
            node_id,
            node_kind: format!(
                "codegraph.{}",
                node_kind(&node.node_type).ok_or(CodeGraphAdapterErrorV1::GraphInvalid)?
            ),
            name,
            candidate_state: CandidateFactStateV1::LocatorOnly,
            trust_state: FactTrustStateV1::Unverified,
            evidence_ids: Vec::new(),
        });
    }
    nodes.sort_by(|left, right| left.node_id.cmp(&right.node_id));

    let mut edges = Vec::with_capacity(root.links.len());
    for link in &root.links {
        let kind = link_kind(&link.link_type).ok_or(CodeGraphAdapterErrorV1::GraphInvalid)?;
        let source_node_id = node_id_by_export_id
            .get(&link.source)
            .cloned()
            .ok_or(CodeGraphAdapterErrorV1::GraphInvalid)?;
        let target_node_id = node_id_by_export_id
            .get(&link.target)
            .cloned()
            .ok_or(CodeGraphAdapterErrorV1::GraphInvalid)?;
        let target_reference = name_by_export_id
            .get(&link.target)
            .cloned()
            .ok_or(CodeGraphAdapterErrorV1::GraphInvalid)?;
        let identity = (
            source_snapshot_sha256,
            link.id,
            link.source,
            link.target,
            &link.link_type,
        );
        edges.push(ExternalEdgeFactV1 {
            fact_id: stable_id("codegraph-fact-edge", &identity)?,
            edge_id: stable_id("codegraph-edge", &identity)?,
            edge_kind: format!("codegraph.{kind}"),
            source_node_id,
            target_reference,
            candidate_node_ids: vec![target_node_id],
            candidate_state: CandidateFactStateV1::LocatorOnly,
            trust_state: FactTrustStateV1::Unverified,
            evidence_ids: Vec::new(),
        });
    }
    edges.sort_by(|left, right| left.edge_id.cmp(&right.edge_id));

    let admitted_count = (nodes.len() + edges.len()) as u64;
    ExternalFactBundleV1 {
        schema_version: "gtkg.external-fact-bundle/v1".to_owned(),
        source_snapshot_sha256: source_snapshot_sha256.to_owned(),
        adapter_descriptor_sha256: descriptor.descriptor_sha256.clone(),
        nodes,
        edges,
        evidence: Vec::new(),
        candidate_states: if admitted_count == 0 {
            Vec::new()
        } else {
            vec![CandidateFactStateV1::LocatorOnly]
        },
        discovered_count: admitted_count,
        admitted_count,
        omitted_count: 0,
        omissions: Vec::new(),
        bundle_sha256: String::new(),
    }
    .with_computed_digest()
    .map_err(|_| CodeGraphAdapterErrorV1::BundleInvalid)
}

fn locator_name(node: &CodeGraphJsonNode) -> String {
    let preferred_key = if node.node_type == "CodeFile" {
        "path"
    } else {
        "name"
    };
    node.properties
        .get(preferred_key)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| format!("codegraph-export-node-{}", node.id))
}

fn node_kind(value: &str) -> Option<&'static str> {
    match value {
        "CodeFile" => Some("code_file"),
        "Function" => Some("function"),
        "Class" => Some("class"),
        "Module" => Some("module"),
        "Variable" => Some("variable"),
        "Type" => Some("type"),
        "Interface" => Some("interface"),
        "Generic" => Some("generic"),
        _ => None,
    }
}

fn link_kind(value: &str) -> Option<&'static str> {
    match value {
        "Imports" => Some("imports"),
        "ImportsFrom" => Some("imports_from"),
        "Contains" => Some("contains"),
        "Calls" => Some("calls"),
        "Invokes" => Some("invokes"),
        "Instantiates" => Some("instantiates"),
        "Extends" => Some("extends"),
        "Implements" => Some("implements"),
        "Uses" => Some("uses"),
        "Defines" => Some("defines"),
        "References" => Some("references"),
        "RuntimeCalls" => Some("runtime_calls"),
        _ => None,
    }
}

fn read_bounded_regular_file(
    path: &Path,
    max_file_bytes: u64,
) -> Result<Vec<u8>, CodeGraphAdapterErrorV1> {
    let path_metadata =
        std::fs::symlink_metadata(path).map_err(|_| CodeGraphAdapterErrorV1::FileInvalid)?;
    if path_metadata.file_type().is_symlink() || !path_metadata.is_file() {
        return Err(CodeGraphAdapterErrorV1::FileInvalid);
    }
    let file = File::open(path).map_err(|_| CodeGraphAdapterErrorV1::FileInvalid)?;
    let opened_metadata = file
        .metadata()
        .map_err(|_| CodeGraphAdapterErrorV1::FileInvalid)?;
    if !opened_metadata.is_file()
        || opened_metadata.len() > max_file_bytes
        || !same_file_identity(&path_metadata, &opened_metadata)
    {
        return Err(CodeGraphAdapterErrorV1::FileInvalid);
    }
    let mut reader = file.take(max_file_bytes.saturating_add(1));
    let mut bytes = Vec::new();
    reader
        .read_to_end(&mut bytes)
        .map_err(|_| CodeGraphAdapterErrorV1::FileInvalid)?;
    if bytes.len() as u64 > max_file_bytes {
        return Err(CodeGraphAdapterErrorV1::FileInvalid);
    }
    Ok(bytes)
}

#[cfg(unix)]
fn same_file_identity(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;

    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(not(unix))]
fn same_file_identity(_left: &std::fs::Metadata, _right: &std::fs::Metadata) -> bool {
    true
}

fn stable_id<T: Serialize>(prefix: &str, value: &T) -> Result<String, CodeGraphAdapterErrorV1> {
    let digest =
        canonical_json_sha256(value).map_err(|_| CodeGraphAdapterErrorV1::BundleInvalid)?;
    let hexadecimal = digest
        .strip_prefix("sha256:")
        .ok_or(CodeGraphAdapterErrorV1::BundleInvalid)?;
    Ok(format!("{prefix}-{hexadecimal}"))
}

fn receipt_digest(receipt: &CodeGraphImportReceiptV1) -> Result<String, CodeGraphAdapterErrorV1> {
    #[derive(Serialize)]
    struct ReceiptIdentity<'a> {
        schema_version: &'a str,
        codegraph_file_sha256: &'a str,
        source_snapshot_sha256: &'a str,
        adapter_descriptor_sha256: &'a str,
        bundle_sha256: &'a str,
        node_count: u64,
        link_count: u64,
        discovered_count: u64,
        admitted_count: u64,
        omitted_count: u64,
        source_evidence_count: u64,
        locator_only_count: u64,
        export_file_read_count: u64,
        target_execution_count: u64,
        network_call_count: u64,
        write_count: u64,
        canonical_write_count: u64,
    }
    canonical_json_sha256(&ReceiptIdentity {
        schema_version: &receipt.schema_version,
        codegraph_file_sha256: &receipt.codegraph_file_sha256,
        source_snapshot_sha256: &receipt.source_snapshot_sha256,
        adapter_descriptor_sha256: &receipt.adapter_descriptor_sha256,
        bundle_sha256: &receipt.bundle_sha256,
        node_count: receipt.node_count,
        link_count: receipt.link_count,
        discovered_count: receipt.discovered_count,
        admitted_count: receipt.admitted_count,
        omitted_count: receipt.omitted_count,
        source_evidence_count: receipt.source_evidence_count,
        locator_only_count: receipt.locator_only_count,
        export_file_read_count: receipt.export_file_read_count,
        target_execution_count: receipt.target_execution_count,
        network_call_count: receipt.network_call_count,
        write_count: receipt.write_count,
        canonical_write_count: receipt.canonical_write_count,
    })
    .map_err(|_| CodeGraphAdapterErrorV1::ReceiptInvalid)
}

fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}
