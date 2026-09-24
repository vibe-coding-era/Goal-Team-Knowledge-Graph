//! A05 pinned, file-only Graphify `graph.json` adapter.
//!
//! Graphify source locations are locators, not source-byte evidence. This
//! adapter therefore preserves Graphify's `EXTRACTED`, `INFERRED`, and
//! `AMBIGUOUS` confidence states while leaving A00 exact-source verification
//! empty. Nothing in this module starts Graphify, calls a provider, reaches the
//! network, writes a target, or grants canonical-writer authority.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, Metadata};
use std::io::Read;
use std::path::{Component, Path};

use gtkg_protocol::v03::AdapterKindV1;
use gtkg_protocol::v03::adapter::{
    AdapterDescriptorV1, CandidateFactStateV1, ExternalEdgeFactV1, ExternalFactBundleV1,
    ExternalFactOmissionV1, ExternalNodeFactV1, FactTrustStateV1,
};
use gtkg_protocol::{canonical_json_sha256, validate_sha256};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const GRAPHIFY_PINNED_VERSION_V1: &str = "0.9.52";
pub const GRAPHIFY_PINNED_COMMIT_V1: &str = "680e3ed8edd3dc1fa1961050912941880b778207";
pub const GRAPHIFY_PINNED_LICENSE_V1: &str = "Apache-2.0";
pub const GRAPHIFY_GRAPH_SCHEMA_SHA256_V1: &str =
    "sha256:eeaf28766aaac19841e6a98c686fde9227598d60d3db1e9262b627feed6dd715";
pub const MAX_GRAPHIFY_BYTES_V1: u64 = 64 * 1024 * 1024;
pub const GRAPHIFY_CANONICAL_SCHEMA_SHA256_V2: &str =
    "sha256:3bad32555ba7930ca4856522d2a643cd70e1f305b1c2fd98ff1aa54bd34445ac";
pub const GRAPHIFY_EXPORT_PY_SHA256_V2: &str =
    "sha256:573079762778f191aceb500598bdc23d7142efd6a21ba881bb7d424334a83f67";
pub const GRAPHIFY_VALIDATE_PY_SHA256_V2: &str =
    "sha256:be068c6b2ff4e514f31663e0155a9d63f35096d154b98ab6c9c467a23febd6f7";
pub const GRAPHIFY_PYPROJECT_SHA256_V2: &str =
    "sha256:b27257549612da75f9e50696e395a545a514aefb0c148340912673a31a9c166b";
pub const GRAPHIFY_LICENSE_SHA256_V2: &str =
    "sha256:cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30";
pub const GRAPHIFY_EXTRACTION_SPEC_SHA256_V2: &str =
    "sha256:32d7decad42d58129c6694ea4e4ce1f72a531bc5161827d2095787e9448735e9";

const RECEIPT_SCHEMA: &str = "gtkg.graphify-import-receipt/v1";
const RECEIPT_SCHEMA_V2: &str = "gtkg.graphify-import-receipt/v2";
const GRAPHIFY_ROOT_FIELDS: [&str; 7] = [
    "built_at_commit",
    "directed",
    "graph",
    "hyperedges",
    "links",
    "multigraph",
    "nodes",
];

/// Caller-authorized identities and bounds for exactly one offline graph file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphifyGraphPinV1 {
    pub file_sha256: String,
    pub schema_sha256: String,
    pub tool_version: String,
    pub tool_commit: String,
    pub tool_license: String,
    pub source_snapshot_sha256: String,
    pub source_repository_commit: String,
    pub max_file_bytes: u64,
    pub max_node_count: u64,
    pub max_link_count: u64,
    pub max_hyperedge_count: u64,
}

impl GraphifyGraphPinV1 {
    pub fn validate(&self) -> Result<(), GraphifyAdapterErrorV1> {
        if validate_sha256(&self.file_sha256).is_err()
            || self.schema_sha256 != GRAPHIFY_GRAPH_SCHEMA_SHA256_V1
            || self.tool_version != GRAPHIFY_PINNED_VERSION_V1
            || self.tool_commit != GRAPHIFY_PINNED_COMMIT_V1
            || self.tool_license != GRAPHIFY_PINNED_LICENSE_V1
            || validate_sha256(&self.source_snapshot_sha256).is_err()
            || self.max_file_bytes == 0
            || self.max_file_bytes > MAX_GRAPHIFY_BYTES_V1
            || self.max_node_count == 0
            || self.max_link_count == 0
            || self.max_hyperedge_count == 0
        {
            return Err(GraphifyAdapterErrorV1::PinMismatch);
        }
        if !commit_identity(&self.source_repository_commit) {
            return Err(GraphifyAdapterErrorV1::SourceIdentityMismatch);
        }
        Ok(())
    }
}

/// Strict successor pin. V2 binds the reviewed upstream blobs and canonical
/// schema derivation in addition to the frozen graph and source identities.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphifyGraphPinV2 {
    pub file_sha256: String,
    pub canonical_schema_sha256: String,
    pub tool_version: String,
    pub tool_commit: String,
    pub tool_license: String,
    pub export_py_sha256: String,
    pub validate_py_sha256: String,
    pub pyproject_sha256: String,
    pub license_sha256: String,
    pub extraction_spec_sha256: String,
    pub source_snapshot_sha256: String,
    pub source_repository_commit: String,
    pub max_file_bytes: u64,
    pub max_node_count: u64,
    pub max_link_count: u64,
    pub max_hyperedge_count: u64,
}

impl GraphifyGraphPinV2 {
    pub fn validate(&self) -> Result<(), GraphifyAdapterErrorV1> {
        if validate_sha256(&self.file_sha256).is_err()
            || self.canonical_schema_sha256 != GRAPHIFY_CANONICAL_SCHEMA_SHA256_V2
            || self.tool_version != GRAPHIFY_PINNED_VERSION_V1
            || self.tool_commit != GRAPHIFY_PINNED_COMMIT_V1
            || self.tool_license != GRAPHIFY_PINNED_LICENSE_V1
            || self.export_py_sha256 != GRAPHIFY_EXPORT_PY_SHA256_V2
            || self.validate_py_sha256 != GRAPHIFY_VALIDATE_PY_SHA256_V2
            || self.pyproject_sha256 != GRAPHIFY_PYPROJECT_SHA256_V2
            || self.license_sha256 != GRAPHIFY_LICENSE_SHA256_V2
            || self.extraction_spec_sha256 != GRAPHIFY_EXTRACTION_SPEC_SHA256_V2
            || validate_sha256(&self.source_snapshot_sha256).is_err()
            || self.max_file_bytes == 0
            || self.max_file_bytes > MAX_GRAPHIFY_BYTES_V1
            || self.max_node_count == 0
            || self.max_link_count == 0
            || self.max_hyperedge_count == 0
        {
            return Err(GraphifyAdapterErrorV1::PinMismatch);
        }
        if !commit_identity(&self.source_repository_commit) {
            return Err(GraphifyAdapterErrorV1::SourceIdentityMismatch);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum GraphifyAdapterErrorV1 {
    #[error("Graphify graph.json is not a bounded private regular file")]
    FileInvalid,
    #[error("Graphify graph.json is not valid JSON")]
    JsonInvalid,
    #[error("Graphify file, tool, schema, license, or snapshot pin differs")]
    PinMismatch,
    #[error("Graphify graph.json root schema is unsupported")]
    SchemaUnsupported,
    #[error("Graphify source repository identity differs from the caller pin")]
    SourceIdentityMismatch,
    #[error("Graphify graph contains invalid, duplicate, or dangling facts")]
    GraphInvalid,
    #[error("Graphify confidence enum and score do not agree")]
    ConfidenceInvalid,
    #[error("Graphify graph metadata and top-level hyperedge slots differ")]
    HyperedgeSlotMismatch,
    #[error("Graphify import receipt is invalid")]
    ReceiptInvalid,
    #[error("Graphify strict V2 import receipt is invalid")]
    ReceiptV2Invalid,
}

impl GraphifyAdapterErrorV1 {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::FileInvalid => "E_GRAPHIFY_FILE_INVALID",
            Self::JsonInvalid => "E_GRAPHIFY_JSON_INVALID",
            Self::PinMismatch => "E_GRAPHIFY_PIN_MISMATCH",
            Self::SchemaUnsupported => "E_GRAPHIFY_SCHEMA_UNSUPPORTED",
            Self::SourceIdentityMismatch => "E_GRAPHIFY_SOURCE_IDENTITY_MISMATCH",
            Self::GraphInvalid => "E_GRAPHIFY_GRAPH_INVALID",
            Self::ConfidenceInvalid => "E_GRAPHIFY_CONFIDENCE_INVALID",
            Self::HyperedgeSlotMismatch => "E_GRAPHIFY_HYPEREDGE_SLOT_MISMATCH",
            Self::ReceiptInvalid => "E_GRAPHIFY_RECEIPT_INVALID",
            Self::ReceiptV2Invalid => "E_GRAPHIFY_V2_RECEIPT_INVALID",
        }
    }
}

/// A Graphify location retained as an unverified locator, never as evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphifySourceLocatorV1 {
    pub fact_id: String,
    pub source_logical_path: String,
    pub source_location: String,
}

/// Bounded evidence that only one pinned file was read and no target action ran.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphifyImportReceiptV1 {
    pub schema_version: String,
    pub graphify_file_sha256: String,
    pub graph_schema_sha256: String,
    pub graphify_version: String,
    pub graphify_commit: String,
    pub graphify_license: String,
    pub source_snapshot_sha256: String,
    pub source_repository_commit: String,
    pub adapter_descriptor_sha256: String,
    pub bundle_sha256: String,
    pub node_count: u64,
    pub link_count: u64,
    pub hyperedge_count: u64,
    pub discovered_count: u64,
    pub admitted_count: u64,
    pub omitted_count: u64,
    pub extracted_relationship_count: u64,
    pub inferred_relationship_count: u64,
    pub ambiguous_relationship_count: u64,
    pub source_locator_count: u64,
    pub missing_source_location_count: u64,
    pub locator_only_count: u64,
    pub export_file_read_count: u64,
    pub target_execution_count: u64,
    pub provider_call_count: u64,
    pub network_call_count: u64,
    pub write_count: u64,
    pub canonical_write_count: u64,
    pub receipt_sha256: String,
}

impl GraphifyImportReceiptV1 {
    pub fn validate(&self) -> Result<(), GraphifyAdapterErrorV1> {
        if self.schema_version != RECEIPT_SCHEMA
            || validate_sha256(&self.graphify_file_sha256).is_err()
            || self.graph_schema_sha256 != GRAPHIFY_GRAPH_SCHEMA_SHA256_V1
            || self.graphify_version != GRAPHIFY_PINNED_VERSION_V1
            || self.graphify_commit != GRAPHIFY_PINNED_COMMIT_V1
            || self.graphify_license != GRAPHIFY_PINNED_LICENSE_V1
            || validate_sha256(&self.source_snapshot_sha256).is_err()
            || !commit_identity(&self.source_repository_commit)
            || validate_sha256(&self.adapter_descriptor_sha256).is_err()
            || validate_sha256(&self.bundle_sha256).is_err()
            || self.node_count == 0
            || self.discovered_count
                != self
                    .node_count
                    .saturating_add(self.link_count)
                    .saturating_add(self.hyperedge_count)
            || self.admitted_count != self.node_count.saturating_add(self.link_count)
            || self.omitted_count != self.hyperedge_count
            || self.discovered_count != self.admitted_count.saturating_add(self.omitted_count)
            || self
                .extracted_relationship_count
                .saturating_add(self.inferred_relationship_count)
                .saturating_add(self.ambiguous_relationship_count)
                != self.link_count.saturating_add(self.hyperedge_count)
            || self
                .source_locator_count
                .saturating_add(self.missing_source_location_count)
                != self.admitted_count
            || self.locator_only_count > self.admitted_count
            || self.export_file_read_count != 1
            || self.target_execution_count != 0
            || self.provider_call_count != 0
            || self.network_call_count != 0
            || self.write_count != 0
            || self.canonical_write_count != 0
            || self.receipt_sha256 != receipt_digest(self)?
        {
            return Err(GraphifyAdapterErrorV1::ReceiptInvalid);
        }
        Ok(())
    }
}

/// Acceptance-authoritative strict receipt. V1 remains readable only as a
/// legacy regression; V2 binds the dual hyperedge slots and upstream blobs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphifyImportReceiptV2 {
    pub schema_version: String,
    pub graphify_file_sha256: String,
    pub canonical_schema_sha256: String,
    pub graphify_version: String,
    pub graphify_commit: String,
    pub graphify_license: String,
    pub export_py_sha256: String,
    pub validate_py_sha256: String,
    pub pyproject_sha256: String,
    pub license_sha256: String,
    pub extraction_spec_sha256: String,
    pub source_snapshot_sha256: String,
    pub source_repository_commit: String,
    pub adapter_descriptor_sha256: String,
    pub bundle_sha256: String,
    pub node_count: u64,
    pub link_count: u64,
    pub hyperedge_count: u64,
    pub dual_slot_hyperedge_count: u64,
    pub discovered_count: u64,
    pub admitted_count: u64,
    pub omitted_count: u64,
    pub extracted_relationship_count: u64,
    pub inferred_relationship_count: u64,
    pub ambiguous_relationship_count: u64,
    pub source_locator_count: u64,
    pub missing_source_location_count: u64,
    pub locator_only_count: u64,
    pub export_file_read_count: u64,
    pub target_execution_count: u64,
    pub provider_call_count: u64,
    pub network_call_count: u64,
    pub write_count: u64,
    pub canonical_write_count: u64,
    pub receipt_sha256: String,
}

impl GraphifyImportReceiptV2 {
    pub fn validate(&self) -> Result<(), GraphifyAdapterErrorV1> {
        if self.schema_version != RECEIPT_SCHEMA_V2
            || validate_sha256(&self.graphify_file_sha256).is_err()
            || self.canonical_schema_sha256 != GRAPHIFY_CANONICAL_SCHEMA_SHA256_V2
            || self.graphify_version != GRAPHIFY_PINNED_VERSION_V1
            || self.graphify_commit != GRAPHIFY_PINNED_COMMIT_V1
            || self.graphify_license != GRAPHIFY_PINNED_LICENSE_V1
            || self.export_py_sha256 != GRAPHIFY_EXPORT_PY_SHA256_V2
            || self.validate_py_sha256 != GRAPHIFY_VALIDATE_PY_SHA256_V2
            || self.pyproject_sha256 != GRAPHIFY_PYPROJECT_SHA256_V2
            || self.license_sha256 != GRAPHIFY_LICENSE_SHA256_V2
            || self.extraction_spec_sha256 != GRAPHIFY_EXTRACTION_SPEC_SHA256_V2
            || validate_sha256(&self.source_snapshot_sha256).is_err()
            || !commit_identity(&self.source_repository_commit)
            || validate_sha256(&self.adapter_descriptor_sha256).is_err()
            || validate_sha256(&self.bundle_sha256).is_err()
            || self.node_count == 0
            || self.dual_slot_hyperedge_count != self.hyperedge_count
            || self.discovered_count
                != self
                    .node_count
                    .saturating_add(self.link_count)
                    .saturating_add(self.hyperedge_count)
            || self.admitted_count != self.node_count.saturating_add(self.link_count)
            || self.omitted_count != self.hyperedge_count
            || self.discovered_count != self.admitted_count.saturating_add(self.omitted_count)
            || self
                .extracted_relationship_count
                .saturating_add(self.inferred_relationship_count)
                .saturating_add(self.ambiguous_relationship_count)
                != self.link_count.saturating_add(self.hyperedge_count)
            || self
                .source_locator_count
                .saturating_add(self.missing_source_location_count)
                != self.admitted_count
            || self.locator_only_count > self.admitted_count
            || self.export_file_read_count != 1
            || self.target_execution_count != 0
            || self.provider_call_count != 0
            || self.network_call_count != 0
            || self.write_count != 0
            || self.canonical_write_count != 0
            || self.receipt_sha256 != receipt_digest_v2(self)?
        {
            return Err(GraphifyAdapterErrorV1::ReceiptV2Invalid);
        }
        Ok(())
    }
}

/// Candidate graph facts, source locators, and zero source-byte evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphifyImportV1 {
    pub descriptor: AdapterDescriptorV1,
    pub bundle: ExternalFactBundleV1,
    pub source_files: BTreeMap<String, Vec<u8>>,
    pub source_locators: Vec<GraphifySourceLocatorV1>,
    pub receipt: GraphifyImportReceiptV1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphifyImportV2 {
    pub descriptor: AdapterDescriptorV1,
    pub bundle: ExternalFactBundleV1,
    pub source_files: BTreeMap<String, Vec<u8>>,
    pub source_locators: Vec<GraphifySourceLocatorV1>,
    pub receipt: GraphifyImportReceiptV2,
}

/// Read and normalize one exact Graphify v0.9.52 `graph.json` file.
pub fn import_pinned_graphify_json_file_v1(
    path: &Path,
    pin: &GraphifyGraphPinV1,
) -> Result<GraphifyImportV1, GraphifyAdapterErrorV1> {
    pin.validate()?;
    let bytes = read_bounded_regular_file(path, pin.max_file_bytes)?;
    if sha256(&bytes) != pin.file_sha256 {
        return Err(GraphifyAdapterErrorV1::PinMismatch);
    }

    let encoded: Value =
        serde_json::from_slice(&bytes).map_err(|_| GraphifyAdapterErrorV1::JsonInvalid)?;
    validate_root_schema(&encoded)?;
    let root: GraphifyRoot =
        serde_json::from_value(encoded).map_err(|_| GraphifyAdapterErrorV1::SchemaUnsupported)?;
    if root.built_at_commit != pin.source_repository_commit {
        return Err(GraphifyAdapterErrorV1::SourceIdentityMismatch);
    }
    if root.multigraph {
        return Err(GraphifyAdapterErrorV1::GraphInvalid);
    }
    let _directed = root.directed;
    let _graph_metadata = &root.graph;
    validate_counts(&root, pin)?;

    let descriptor = AdapterDescriptorV1 {
        schema_version: "gtkg.adapter-descriptor/v1".to_owned(),
        adapter_id: "gtkg.adapter.graphify.v0952".to_owned(),
        kind: AdapterKindV1::GraphifyExport,
        adapter_version: GRAPHIFY_PINNED_VERSION_V1.to_owned(),
        schema_sha256: GRAPHIFY_GRAPH_SCHEMA_SHA256_V1.to_owned(),
        source_commit: GRAPHIFY_PINNED_COMMIT_V1.to_owned(),
        license: GRAPHIFY_PINNED_LICENSE_V1.to_owned(),
        capabilities: vec![
            "confidence_states".to_owned(),
            "graph_json".to_owned(),
            "source_locators".to_owned(),
        ],
        trust_policy_id: "gtkg.adapter-trust/v1".to_owned(),
        descriptor_sha256: String::new(),
    }
    .with_computed_digest()
    .map_err(|_| GraphifyAdapterErrorV1::PinMismatch)?;

    let normalized = normalize_graph(root, &descriptor, &pin.source_snapshot_sha256, 3)?;
    let bundle = normalized.bundle;
    let mut receipt = GraphifyImportReceiptV1 {
        schema_version: RECEIPT_SCHEMA.to_owned(),
        graphify_file_sha256: pin.file_sha256.clone(),
        graph_schema_sha256: GRAPHIFY_GRAPH_SCHEMA_SHA256_V1.to_owned(),
        graphify_version: GRAPHIFY_PINNED_VERSION_V1.to_owned(),
        graphify_commit: GRAPHIFY_PINNED_COMMIT_V1.to_owned(),
        graphify_license: GRAPHIFY_PINNED_LICENSE_V1.to_owned(),
        source_snapshot_sha256: pin.source_snapshot_sha256.clone(),
        source_repository_commit: pin.source_repository_commit.clone(),
        adapter_descriptor_sha256: descriptor.descriptor_sha256.clone(),
        bundle_sha256: bundle.bundle_sha256.clone(),
        node_count: normalized.node_count,
        link_count: normalized.link_count,
        hyperedge_count: normalized.hyperedge_count,
        discovered_count: bundle.discovered_count,
        admitted_count: bundle.admitted_count,
        omitted_count: bundle.omitted_count,
        extracted_relationship_count: normalized.extracted_relationship_count,
        inferred_relationship_count: normalized.inferred_relationship_count,
        ambiguous_relationship_count: normalized.ambiguous_relationship_count,
        source_locator_count: normalized.source_locators.len() as u64,
        missing_source_location_count: bundle
            .admitted_count
            .saturating_sub(normalized.source_locators.len() as u64),
        locator_only_count: normalized.locator_only_count,
        export_file_read_count: 1,
        target_execution_count: 0,
        provider_call_count: 0,
        network_call_count: 0,
        write_count: 0,
        canonical_write_count: 0,
        receipt_sha256: String::new(),
    };
    receipt.receipt_sha256 = receipt_digest(&receipt)?;
    receipt.validate()?;

    Ok(GraphifyImportV1 {
        descriptor,
        bundle,
        source_files: BTreeMap::new(),
        source_locators: normalized.source_locators,
        receipt,
    })
}

/// Strict, acceptance-authoritative Graphify import successor.
pub fn import_pinned_graphify_json_file_v2(
    path: &Path,
    pin: &GraphifyGraphPinV2,
) -> Result<GraphifyImportV2, GraphifyAdapterErrorV1> {
    pin.validate()?;
    let bytes = read_bounded_regular_file(path, pin.max_file_bytes)?;
    if sha256(&bytes) != pin.file_sha256 {
        return Err(GraphifyAdapterErrorV1::PinMismatch);
    }

    let encoded: Value =
        serde_json::from_slice(&bytes).map_err(|_| GraphifyAdapterErrorV1::JsonInvalid)?;
    validate_root_schema(&encoded)?;
    let dual_slot_hyperedge_count = validate_hyperedge_slots_v2(&encoded)?;
    let root: GraphifyRoot =
        serde_json::from_value(encoded).map_err(|_| GraphifyAdapterErrorV1::SchemaUnsupported)?;
    if root.built_at_commit != pin.source_repository_commit {
        return Err(GraphifyAdapterErrorV1::SourceIdentityMismatch);
    }
    if root.multigraph {
        return Err(GraphifyAdapterErrorV1::GraphInvalid);
    }
    validate_counts_v2(&root, pin)?;

    let descriptor = AdapterDescriptorV1 {
        schema_version: "gtkg.adapter-descriptor/v1".to_owned(),
        adapter_id: "gtkg.adapter.graphify.v0952.strict-v2".to_owned(),
        kind: AdapterKindV1::GraphifyExport,
        adapter_version: GRAPHIFY_PINNED_VERSION_V1.to_owned(),
        schema_sha256: GRAPHIFY_CANONICAL_SCHEMA_SHA256_V2.to_owned(),
        source_commit: GRAPHIFY_PINNED_COMMIT_V1.to_owned(),
        license: GRAPHIFY_PINNED_LICENSE_V1.to_owned(),
        capabilities: vec![
            "confidence_states".to_owned(),
            "dual_slot_hyperedges".to_owned(),
            "graph_json".to_owned(),
            "source_locators".to_owned(),
            "upstream_blob_pins".to_owned(),
        ],
        trust_policy_id: "gtkg.adapter-trust/v1".to_owned(),
        descriptor_sha256: String::new(),
    }
    .with_computed_digest()
    .map_err(|_| GraphifyAdapterErrorV1::PinMismatch)?;

    let normalized = normalize_graph(root, &descriptor, &pin.source_snapshot_sha256, 1)?;
    let bundle = normalized.bundle;
    let source_locator_count = count(normalized.source_locators.len())?;
    let mut receipt = GraphifyImportReceiptV2 {
        schema_version: RECEIPT_SCHEMA_V2.to_owned(),
        graphify_file_sha256: pin.file_sha256.clone(),
        canonical_schema_sha256: GRAPHIFY_CANONICAL_SCHEMA_SHA256_V2.to_owned(),
        graphify_version: GRAPHIFY_PINNED_VERSION_V1.to_owned(),
        graphify_commit: GRAPHIFY_PINNED_COMMIT_V1.to_owned(),
        graphify_license: GRAPHIFY_PINNED_LICENSE_V1.to_owned(),
        export_py_sha256: GRAPHIFY_EXPORT_PY_SHA256_V2.to_owned(),
        validate_py_sha256: GRAPHIFY_VALIDATE_PY_SHA256_V2.to_owned(),
        pyproject_sha256: GRAPHIFY_PYPROJECT_SHA256_V2.to_owned(),
        license_sha256: GRAPHIFY_LICENSE_SHA256_V2.to_owned(),
        extraction_spec_sha256: GRAPHIFY_EXTRACTION_SPEC_SHA256_V2.to_owned(),
        source_snapshot_sha256: pin.source_snapshot_sha256.clone(),
        source_repository_commit: pin.source_repository_commit.clone(),
        adapter_descriptor_sha256: descriptor.descriptor_sha256.clone(),
        bundle_sha256: bundle.bundle_sha256.clone(),
        node_count: normalized.node_count,
        link_count: normalized.link_count,
        hyperedge_count: normalized.hyperedge_count,
        dual_slot_hyperedge_count,
        discovered_count: bundle.discovered_count,
        admitted_count: bundle.admitted_count,
        omitted_count: bundle.omitted_count,
        extracted_relationship_count: normalized.extracted_relationship_count,
        inferred_relationship_count: normalized.inferred_relationship_count,
        ambiguous_relationship_count: normalized.ambiguous_relationship_count,
        source_locator_count,
        missing_source_location_count: bundle.admitted_count.saturating_sub(source_locator_count),
        locator_only_count: normalized.locator_only_count,
        export_file_read_count: 1,
        target_execution_count: 0,
        provider_call_count: 0,
        network_call_count: 0,
        write_count: 0,
        canonical_write_count: 0,
        receipt_sha256: String::new(),
    };
    receipt.receipt_sha256 = receipt_digest_v2(&receipt)?;
    receipt.validate()?;

    Ok(GraphifyImportV2 {
        descriptor,
        bundle,
        source_files: BTreeMap::new(),
        source_locators: normalized.source_locators,
        receipt,
    })
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GraphifyRoot {
    directed: bool,
    multigraph: bool,
    graph: BTreeMap<String, Value>,
    nodes: Vec<GraphifyNode>,
    links: Vec<GraphifyLink>,
    hyperedges: Vec<GraphifyHyperedge>,
    built_at_commit: String,
}

#[derive(Debug, Deserialize)]
struct GraphifyNode {
    id: String,
    label: String,
    file_type: String,
    source_file: String,
    source_location: Option<String>,
    #[serde(flatten)]
    _metadata: BTreeMap<String, Value>,
}

#[derive(Debug, Deserialize)]
struct GraphifyLink {
    source: String,
    target: String,
    relation: String,
    confidence: GraphifyConfidence,
    confidence_score: f64,
    source_file: String,
    source_location: Option<String>,
    #[serde(flatten)]
    _metadata: BTreeMap<String, Value>,
}

#[derive(Debug, Deserialize)]
struct GraphifyHyperedge {
    id: String,
    label: String,
    nodes: Vec<String>,
    relation: String,
    confidence: GraphifyConfidence,
    confidence_score: f64,
    source_file: String,
    #[serde(flatten)]
    _metadata: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
enum GraphifyConfidence {
    #[serde(rename = "EXTRACTED")]
    Extracted,
    #[serde(rename = "INFERRED")]
    Inferred,
    #[serde(rename = "AMBIGUOUS")]
    Ambiguous,
}

impl GraphifyConfidence {
    const fn trust_state(self) -> FactTrustStateV1 {
        match self {
            Self::Extracted => FactTrustStateV1::Extracted,
            Self::Inferred => FactTrustStateV1::Inferred,
            Self::Ambiguous => FactTrustStateV1::Ambiguous,
        }
    }

    const fn omission_reason(self) -> &'static str {
        match self {
            Self::Extracted => "graphify_hyperedge_extracted_not_representable_v1",
            Self::Inferred => "graphify_hyperedge_inferred_not_representable_v1",
            Self::Ambiguous => "graphify_hyperedge_ambiguous_not_representable_v1",
        }
    }
}

#[derive(Debug)]
struct NormalizedGraphify {
    bundle: ExternalFactBundleV1,
    source_locators: Vec<GraphifySourceLocatorV1>,
    node_count: u64,
    link_count: u64,
    hyperedge_count: u64,
    extracted_relationship_count: u64,
    inferred_relationship_count: u64,
    ambiguous_relationship_count: u64,
    locator_only_count: u64,
}

fn normalize_graph(
    root: GraphifyRoot,
    descriptor: &AdapterDescriptorV1,
    source_snapshot_sha256: &str,
    minimum_hyperedge_members: usize,
) -> Result<NormalizedGraphify, GraphifyAdapterErrorV1> {
    let node_count = count(root.nodes.len())?;
    let link_count = count(root.links.len())?;
    let hyperedge_count = count(root.hyperedges.len())?;
    let mut raw_node_ids = BTreeSet::new();
    let mut raw_nodes = BTreeMap::new();

    for node in root.nodes {
        validate_node(&node)?;
        if !raw_node_ids.insert(node.id.clone()) {
            return Err(GraphifyAdapterErrorV1::GraphInvalid);
        }
        raw_nodes.insert(node.id.clone(), node);
    }
    if raw_nodes.is_empty() {
        return Err(GraphifyAdapterErrorV1::GraphInvalid);
    }

    let node_ids = raw_nodes
        .keys()
        .map(|raw_id| Ok((raw_id.clone(), stable_id("graphify-node", raw_id)?)))
        .collect::<Result<BTreeMap<_, _>, GraphifyAdapterErrorV1>>()?;
    let mut source_locators = Vec::new();
    let mut nodes = Vec::with_capacity(raw_nodes.len());
    for (raw_id, raw) in &raw_nodes {
        let fact_id = stable_id("graphify-fact-node", raw_id)?;
        let locator = source_locator(&raw.source_file, raw.source_location.as_deref())?;
        if let Some((source_logical_path, source_location)) = locator.clone() {
            source_locators.push(GraphifySourceLocatorV1 {
                fact_id: fact_id.clone(),
                source_logical_path,
                source_location,
            });
        }
        nodes.push(ExternalNodeFactV1 {
            fact_id,
            node_id: node_ids
                .get(raw_id)
                .cloned()
                .ok_or(GraphifyAdapterErrorV1::GraphInvalid)?,
            node_kind: raw.file_type.clone(),
            name: raw.label.clone(),
            candidate_state: if locator.is_some() {
                CandidateFactStateV1::CandidateExternal
            } else {
                CandidateFactStateV1::LocatorOnly
            },
            trust_state: FactTrustStateV1::Unverified,
            evidence_ids: Vec::new(),
        });
    }
    nodes.sort_by(|left, right| left.node_id.cmp(&right.node_id));

    let mut edge_identities = BTreeSet::new();
    let mut edges = Vec::with_capacity(root.links.len());
    let mut extracted_relationship_count = 0_u64;
    let mut inferred_relationship_count = 0_u64;
    let mut ambiguous_relationship_count = 0_u64;
    for link in root.links {
        validate_link(&link, &raw_node_ids)?;
        increment_confidence(
            link.confidence,
            &mut extracted_relationship_count,
            &mut inferred_relationship_count,
            &mut ambiguous_relationship_count,
        );
        let identity = (
            link.source.clone(),
            link.target.clone(),
            link.relation.clone(),
        );
        if !edge_identities.insert(identity.clone()) {
            return Err(GraphifyAdapterErrorV1::GraphInvalid);
        }
        let fact_id = stable_id("graphify-fact-edge", &identity)?;
        let locator = source_locator(&link.source_file, link.source_location.as_deref())?;
        if let Some((source_logical_path, source_location)) = locator.clone() {
            source_locators.push(GraphifySourceLocatorV1 {
                fact_id: fact_id.clone(),
                source_logical_path,
                source_location,
            });
        }
        let target = raw_nodes
            .get(&link.target)
            .ok_or(GraphifyAdapterErrorV1::GraphInvalid)?;
        edges.push(ExternalEdgeFactV1 {
            fact_id,
            edge_id: stable_id("graphify-edge", &identity)?,
            edge_kind: format!("graphify.{}", link.relation),
            source_node_id: node_ids
                .get(&link.source)
                .cloned()
                .ok_or(GraphifyAdapterErrorV1::GraphInvalid)?,
            target_reference: target.label.clone(),
            candidate_node_ids: vec![
                node_ids
                    .get(&link.target)
                    .cloned()
                    .ok_or(GraphifyAdapterErrorV1::GraphInvalid)?,
            ],
            candidate_state: match (link.confidence, locator.is_some()) {
                (GraphifyConfidence::Ambiguous, _) => CandidateFactStateV1::Ambiguous,
                (_, true) => CandidateFactStateV1::CandidateExternal,
                (_, false) => CandidateFactStateV1::LocatorOnly,
            },
            trust_state: link.confidence.trust_state(),
            evidence_ids: Vec::new(),
        });
    }
    edges.sort_by(|left, right| left.edge_id.cmp(&right.edge_id));

    let mut hyperedge_ids = BTreeSet::new();
    let mut omissions = Vec::with_capacity(root.hyperedges.len());
    for hyperedge in root.hyperedges {
        validate_hyperedge(&hyperedge, &raw_node_ids, minimum_hyperedge_members)?;
        increment_confidence(
            hyperedge.confidence,
            &mut extracted_relationship_count,
            &mut inferred_relationship_count,
            &mut ambiguous_relationship_count,
        );
        if !hyperedge_ids.insert(hyperedge.id.clone()) {
            return Err(GraphifyAdapterErrorV1::GraphInvalid);
        }
        omissions.push(ExternalFactOmissionV1 {
            omitted_id: stable_id("graphify-omitted-hyperedge", &hyperedge.id)?,
            reason: hyperedge.confidence.omission_reason().to_owned(),
        });
    }
    omissions.sort_by(|left, right| left.omitted_id.cmp(&right.omitted_id));
    source_locators.sort_by(|left, right| left.fact_id.cmp(&right.fact_id));

    let candidate_states = nodes
        .iter()
        .map(|node| node.candidate_state)
        .chain(edges.iter().map(|edge| edge.candidate_state))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let admitted_count = node_count.saturating_add(link_count);
    let discovered_count = admitted_count.saturating_add(hyperedge_count);
    let locator_only_count = nodes
        .iter()
        .filter(|node| node.candidate_state == CandidateFactStateV1::LocatorOnly)
        .count()
        .saturating_add(
            edges
                .iter()
                .filter(|edge| edge.candidate_state == CandidateFactStateV1::LocatorOnly)
                .count(),
        ) as u64;
    let bundle = ExternalFactBundleV1 {
        schema_version: "gtkg.external-fact-bundle/v1".to_owned(),
        source_snapshot_sha256: source_snapshot_sha256.to_owned(),
        adapter_descriptor_sha256: descriptor.descriptor_sha256.clone(),
        nodes,
        edges,
        evidence: Vec::new(),
        candidate_states,
        discovered_count,
        admitted_count,
        omitted_count: hyperedge_count,
        omissions,
        bundle_sha256: String::new(),
    }
    .with_computed_digest()
    .map_err(|_| GraphifyAdapterErrorV1::GraphInvalid)?;

    Ok(NormalizedGraphify {
        bundle,
        source_locators,
        node_count,
        link_count,
        hyperedge_count,
        extracted_relationship_count,
        inferred_relationship_count,
        ambiguous_relationship_count,
        locator_only_count,
    })
}

fn validate_root_schema(encoded: &Value) -> Result<(), GraphifyAdapterErrorV1> {
    let object = encoded
        .as_object()
        .ok_or(GraphifyAdapterErrorV1::SchemaUnsupported)?;
    let actual = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let expected = GRAPHIFY_ROOT_FIELDS.into_iter().collect::<BTreeSet<_>>();
    if actual != expected {
        return Err(GraphifyAdapterErrorV1::SchemaUnsupported);
    }
    Ok(())
}

fn validate_hyperedge_slots_v2(encoded: &Value) -> Result<u64, GraphifyAdapterErrorV1> {
    let top_level = encoded
        .get("hyperedges")
        .and_then(Value::as_array)
        .ok_or(GraphifyAdapterErrorV1::SchemaUnsupported)?;
    let graph_metadata = encoded
        .get("graph")
        .and_then(Value::as_object)
        .ok_or(GraphifyAdapterErrorV1::SchemaUnsupported)?;
    let metadata_slot = graph_metadata
        .get("hyperedges")
        .and_then(Value::as_array)
        .ok_or(GraphifyAdapterErrorV1::HyperedgeSlotMismatch)?;
    let top_digests = canonical_item_digest_set(top_level)?;
    let metadata_digests = canonical_item_digest_set(metadata_slot)?;
    if top_digests != metadata_digests {
        return Err(GraphifyAdapterErrorV1::HyperedgeSlotMismatch);
    }
    count(top_level.len())
}

fn canonical_item_digest_set(values: &[Value]) -> Result<BTreeSet<String>, GraphifyAdapterErrorV1> {
    let digests = values
        .iter()
        .map(|value| canonical_json_sha256(value).map_err(|_| GraphifyAdapterErrorV1::GraphInvalid))
        .collect::<Result<BTreeSet<_>, _>>()?;
    if digests.len() != values.len() {
        return Err(GraphifyAdapterErrorV1::GraphInvalid);
    }
    Ok(digests)
}

fn validate_counts(
    root: &GraphifyRoot,
    pin: &GraphifyGraphPinV1,
) -> Result<(), GraphifyAdapterErrorV1> {
    if root.nodes.len() as u128 > u128::from(pin.max_node_count)
        || root.links.len() as u128 > u128::from(pin.max_link_count)
        || root.hyperedges.len() as u128 > u128::from(pin.max_hyperedge_count)
    {
        return Err(GraphifyAdapterErrorV1::GraphInvalid);
    }
    Ok(())
}

fn validate_counts_v2(
    root: &GraphifyRoot,
    pin: &GraphifyGraphPinV2,
) -> Result<(), GraphifyAdapterErrorV1> {
    if root.nodes.len() as u128 > u128::from(pin.max_node_count)
        || root.links.len() as u128 > u128::from(pin.max_link_count)
        || root.hyperedges.len() as u128 > u128::from(pin.max_hyperedge_count)
    {
        return Err(GraphifyAdapterErrorV1::GraphInvalid);
    }
    Ok(())
}

fn validate_node(node: &GraphifyNode) -> Result<(), GraphifyAdapterErrorV1> {
    if !graphify_id(&node.id)
        || !bounded_text(&node.label, 512)
        || !matches!(
            node.file_type.as_str(),
            "code" | "document" | "paper" | "image" | "rationale" | "concept"
        )
        || (!node.source_file.is_empty() && !relative_logical_path(&node.source_file))
        || (node.source_file.is_empty()
            && !matches!(node.file_type.as_str(), "concept" | "rationale"))
    {
        return Err(GraphifyAdapterErrorV1::GraphInvalid);
    }
    source_locator(&node.source_file, node.source_location.as_deref())?;
    Ok(())
}

fn validate_link(
    link: &GraphifyLink,
    node_ids: &BTreeSet<String>,
) -> Result<(), GraphifyAdapterErrorV1> {
    if !node_ids.contains(&link.source)
        || !node_ids.contains(&link.target)
        || !relationship_id(&link.relation)
        || !relative_logical_path(&link.source_file)
    {
        return Err(GraphifyAdapterErrorV1::GraphInvalid);
    }
    validate_confidence(link.confidence, link.confidence_score)?;
    source_locator(&link.source_file, link.source_location.as_deref())?;
    Ok(())
}

fn validate_hyperedge(
    hyperedge: &GraphifyHyperedge,
    node_ids: &BTreeSet<String>,
    minimum_members: usize,
) -> Result<(), GraphifyAdapterErrorV1> {
    let members = hyperedge.nodes.iter().collect::<BTreeSet<_>>();
    if !graphify_id(&hyperedge.id)
        || !bounded_text(&hyperedge.label, 512)
        || hyperedge.nodes.len() < minimum_members
        || members.len() != hyperedge.nodes.len()
        || members.iter().any(|node| !node_ids.contains(*node))
        || !relationship_id(&hyperedge.relation)
        || !relative_logical_path(&hyperedge.source_file)
    {
        return Err(GraphifyAdapterErrorV1::GraphInvalid);
    }
    validate_confidence(hyperedge.confidence, hyperedge.confidence_score)
}

fn validate_confidence(
    confidence: GraphifyConfidence,
    score: f64,
) -> Result<(), GraphifyAdapterErrorV1> {
    let valid = score.is_finite()
        && match confidence {
            GraphifyConfidence::Extracted => score == 1.0,
            GraphifyConfidence::Inferred => [0.55, 0.65, 0.75, 0.85, 0.95].contains(&score),
            GraphifyConfidence::Ambiguous => (0.1..=0.3).contains(&score),
        };
    if !valid {
        return Err(GraphifyAdapterErrorV1::ConfidenceInvalid);
    }
    Ok(())
}

fn increment_confidence(
    confidence: GraphifyConfidence,
    extracted: &mut u64,
    inferred: &mut u64,
    ambiguous: &mut u64,
) {
    match confidence {
        GraphifyConfidence::Extracted => *extracted = extracted.saturating_add(1),
        GraphifyConfidence::Inferred => *inferred = inferred.saturating_add(1),
        GraphifyConfidence::Ambiguous => *ambiguous = ambiguous.saturating_add(1),
    }
}

fn source_locator(
    source_file: &str,
    source_location: Option<&str>,
) -> Result<Option<(String, String)>, GraphifyAdapterErrorV1> {
    let Some(location) = source_location else {
        return Ok(None);
    };
    if location.is_empty() {
        return Ok(None);
    }
    if !relative_logical_path(source_file) || !bounded_text(location, 128) {
        return Err(GraphifyAdapterErrorV1::GraphInvalid);
    }
    Ok(Some((source_file.to_owned(), location.to_owned())))
}

fn read_bounded_regular_file(
    path: &Path,
    max_file_bytes: u64,
) -> Result<Vec<u8>, GraphifyAdapterErrorV1> {
    if max_file_bytes == 0 || max_file_bytes > MAX_GRAPHIFY_BYTES_V1 {
        return Err(GraphifyAdapterErrorV1::FileInvalid);
    }
    let before =
        std::fs::symlink_metadata(path).map_err(|_| GraphifyAdapterErrorV1::FileInvalid)?;
    if before.file_type().is_symlink()
        || !before.file_type().is_file()
        || before.len() > max_file_bytes
        || private_link_check(&before).is_err()
    {
        return Err(GraphifyAdapterErrorV1::FileInvalid);
    }
    let file = open_regular_nofollow(path)?;
    let opened = file
        .metadata()
        .map_err(|_| GraphifyAdapterErrorV1::FileInvalid)?;
    if !opened.file_type().is_file()
        || opened.len() > max_file_bytes
        || !same_file_identity(&before, &opened)
        || private_link_check(&opened).is_err()
    {
        return Err(GraphifyAdapterErrorV1::FileInvalid);
    }
    let mut reader = file.take(max_file_bytes.saturating_add(1));
    let mut bytes = Vec::new();
    reader
        .read_to_end(&mut bytes)
        .map_err(|_| GraphifyAdapterErrorV1::FileInvalid)?;
    if bytes.len() as u128 > u128::from(max_file_bytes) {
        return Err(GraphifyAdapterErrorV1::FileInvalid);
    }
    let after = std::fs::symlink_metadata(path).map_err(|_| GraphifyAdapterErrorV1::FileInvalid)?;
    if !same_file_identity(&opened, &after) || private_link_check(&after).is_err() {
        return Err(GraphifyAdapterErrorV1::FileInvalid);
    }
    Ok(bytes)
}

#[cfg(unix)]
fn open_regular_nofollow(path: &Path) -> Result<File, GraphifyAdapterErrorV1> {
    use rustix::fs::{Mode, OFlags, open};

    let descriptor = open(
        path,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| GraphifyAdapterErrorV1::FileInvalid)?;
    Ok(File::from(descriptor))
}

#[cfg(not(unix))]
fn open_regular_nofollow(path: &Path) -> Result<File, GraphifyAdapterErrorV1> {
    File::open(path).map_err(|_| GraphifyAdapterErrorV1::FileInvalid)
}

#[cfg(unix)]
fn same_file_identity(left: &Metadata, right: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;

    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(not(unix))]
fn same_file_identity(left: &Metadata, right: &Metadata) -> bool {
    left.len() == right.len() && left.file_type().is_file() && right.file_type().is_file()
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

fn stable_id<T: Serialize>(prefix: &str, value: &T) -> Result<String, GraphifyAdapterErrorV1> {
    let digest = canonical_json_sha256(value).map_err(|_| GraphifyAdapterErrorV1::GraphInvalid)?;
    let hexadecimal = digest
        .strip_prefix("sha256:")
        .ok_or(GraphifyAdapterErrorV1::GraphInvalid)?;
    Ok(format!("{prefix}-{hexadecimal}"))
}

fn receipt_digest(receipt: &GraphifyImportReceiptV1) -> Result<String, GraphifyAdapterErrorV1> {
    #[derive(Serialize)]
    struct ReceiptIdentity<'a> {
        schema_version: &'a str,
        graphify_file_sha256: &'a str,
        graph_schema_sha256: &'a str,
        graphify_version: &'a str,
        graphify_commit: &'a str,
        graphify_license: &'a str,
        source_snapshot_sha256: &'a str,
        source_repository_commit: &'a str,
        adapter_descriptor_sha256: &'a str,
        bundle_sha256: &'a str,
        node_count: u64,
        link_count: u64,
        hyperedge_count: u64,
        discovered_count: u64,
        admitted_count: u64,
        omitted_count: u64,
        extracted_relationship_count: u64,
        inferred_relationship_count: u64,
        ambiguous_relationship_count: u64,
        source_locator_count: u64,
        missing_source_location_count: u64,
        locator_only_count: u64,
        export_file_read_count: u64,
        target_execution_count: u64,
        provider_call_count: u64,
        network_call_count: u64,
        write_count: u64,
        canonical_write_count: u64,
    }
    canonical_json_sha256(&ReceiptIdentity {
        schema_version: &receipt.schema_version,
        graphify_file_sha256: &receipt.graphify_file_sha256,
        graph_schema_sha256: &receipt.graph_schema_sha256,
        graphify_version: &receipt.graphify_version,
        graphify_commit: &receipt.graphify_commit,
        graphify_license: &receipt.graphify_license,
        source_snapshot_sha256: &receipt.source_snapshot_sha256,
        source_repository_commit: &receipt.source_repository_commit,
        adapter_descriptor_sha256: &receipt.adapter_descriptor_sha256,
        bundle_sha256: &receipt.bundle_sha256,
        node_count: receipt.node_count,
        link_count: receipt.link_count,
        hyperedge_count: receipt.hyperedge_count,
        discovered_count: receipt.discovered_count,
        admitted_count: receipt.admitted_count,
        omitted_count: receipt.omitted_count,
        extracted_relationship_count: receipt.extracted_relationship_count,
        inferred_relationship_count: receipt.inferred_relationship_count,
        ambiguous_relationship_count: receipt.ambiguous_relationship_count,
        source_locator_count: receipt.source_locator_count,
        missing_source_location_count: receipt.missing_source_location_count,
        locator_only_count: receipt.locator_only_count,
        export_file_read_count: receipt.export_file_read_count,
        target_execution_count: receipt.target_execution_count,
        provider_call_count: receipt.provider_call_count,
        network_call_count: receipt.network_call_count,
        write_count: receipt.write_count,
        canonical_write_count: receipt.canonical_write_count,
    })
    .map_err(|_| GraphifyAdapterErrorV1::ReceiptInvalid)
}

fn receipt_digest_v2(receipt: &GraphifyImportReceiptV2) -> Result<String, GraphifyAdapterErrorV1> {
    let mut encoded =
        serde_json::to_value(receipt).map_err(|_| GraphifyAdapterErrorV1::ReceiptV2Invalid)?;
    let object = encoded
        .as_object_mut()
        .ok_or(GraphifyAdapterErrorV1::ReceiptV2Invalid)?;
    object.remove("receipt_sha256");
    canonical_json_sha256(&encoded).map_err(|_| GraphifyAdapterErrorV1::ReceiptV2Invalid)
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

fn graphify_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn relationship_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-' | b'.')
        })
}

fn bounded_text(value: &str, maximum_bytes: usize) -> bool {
    !value.trim().is_empty() && value.len() <= maximum_bytes && !value.chars().any(char::is_control)
}

fn commit_identity(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn count(value: usize) -> Result<u64, GraphifyAdapterErrorV1> {
    u64::try_from(value).map_err(|_| GraphifyAdapterErrorV1::GraphInvalid)
}

fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}
