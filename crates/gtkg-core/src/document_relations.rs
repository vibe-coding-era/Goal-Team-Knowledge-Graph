//! V0.2 T06 local document relation closure.
//!
//! This module intentionally implements only the Markdown profile. PDF and
//! Office inputs are surfaced as explicit omissions instead of being parsed
//! through a lossy text fallback and falsely promoted to relation coverage.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};

use gtkg_protocol::v2::OkfSpecPinV2;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::okf::parse_okf;

const T03_RECEIPT_SCHEMA: &str = "gtkg.current-okf-normative-corpus-receipt/v1";
const T03_CORPUS_SCHEMA: &str = "gtkg.current-okf-normative-corpus/v1";
const T03_RAW_ASSET_SCHEMA: &str = "gtkg.external-asset-manifest/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DocumentRelationFormatV2 {
    Markdown,
    Pdf,
    Office,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DocumentRelationStatusV2 {
    Passed,
    Failed,
    OmittedUnsupported,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentRelationIssueV2 {
    pub code: String,
    pub subject: String,
    pub detail: String,
}

/// The exact current-OKF pin and passed T03 receipt that scoped a relation
/// result. This is an evidence binding, not a statement that arbitrary
/// Markdown is externally OKF-conformant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct T03RelationBindingV2 {
    pub raw_spec_pin: OkfSpecPinV2,
    pub corpus_manifest_path: String,
    pub corpus_manifest_sha256: String,
    pub receipt_path: String,
    pub receipt_sha256: String,
    pub corpus_id: String,
}

#[derive(Debug, Error)]
pub enum DocumentRelationBindingErrorV2 {
    #[error("invalid T03 raw-spec pin: {0}")]
    InvalidPin(String),
    #[error("cannot read T03 receipt {path}: {source}")]
    ReceiptIo {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("T03 receipt {path} is not valid JSON: {source}")]
    ReceiptJson {
        path: String,
        #[source]
        source: serde_json::Error,
    },
    #[error("T03 receipt {0} does not prove a passed frozen corpus")]
    ReceiptNotPassed(String),
    #[error("T03 corpus manifest {0} does not bind the exact raw pin, raw asset, and receipt")]
    CorpusManifestMismatch(String),
    #[error("T03 receipt {0} does not exactly match its frozen corpus manifest")]
    ReceiptManifestMismatch(String),
    #[error("T03 raw asset at {0} does not match the exact raw pin")]
    RawAssetDigestMismatch(String),
    #[error("T03 path is unsafe or outside the supplied workspace root: {0}")]
    UnsafeWorkspacePath(String),
}

impl T03RelationBindingV2 {
    /// Binds a local relation run to the exact raw pin, frozen T03 corpus
    /// manifest, and passed T03 receipt. The manifest is checked against the
    /// bytes of both the pinned raw asset and its acquisition manifest; the
    /// receipt must report exactly the corpus's declared case set.
    pub fn from_receipt(
        workspace_root: &Path,
        raw_spec_pin: OkfSpecPinV2,
        corpus_manifest_path: &Path,
        receipt_path: &Path,
    ) -> Result<Self, DocumentRelationBindingErrorV2> {
        raw_spec_pin
            .validate()
            .map_err(|error| DocumentRelationBindingErrorV2::InvalidPin(error.to_string()))?;
        let manifest_bytes = fs::read(corpus_manifest_path).map_err(|source| {
            DocumentRelationBindingErrorV2::ReceiptIo {
                path: corpus_manifest_path.display().to_string(),
                source,
            }
        })?;
        let manifest: Value = serde_json::from_slice(&manifest_bytes).map_err(|source| {
            DocumentRelationBindingErrorV2::ReceiptJson {
                path: corpus_manifest_path.display().to_string(),
                source,
            }
        })?;
        let raw_spec = &manifest["raw_spec"];
        let manifest_cases = exact_case_ids(&manifest["cases"]);
        let receipt_relative = relative_workspace_path(workspace_root, receipt_path)?;
        let raw_asset_relative = raw_spec["path"].as_str().unwrap_or_default();
        let raw_manifest_relative = raw_spec["manifest"].as_str().unwrap_or_default();
        let manifest_is_bound = manifest["schema_version"].as_str() == Some(T03_CORPUS_SCHEMA)
            && manifest["status"].as_str() == Some("frozen_for_execution")
            && manifest["corpus_id"]
                .as_str()
                .is_some_and(|corpus_id| !corpus_id.trim().is_empty())
            && raw_spec["upstream_commit"].as_str() == Some(raw_spec_pin.upstream_commit.as_str())
            && raw_spec["sha256"].as_str() == Some(raw_spec_pin.raw_sha256.as_str())
            && manifest["receipt_path"].as_str() == Some(receipt_relative.as_str())
            && !raw_asset_relative.is_empty()
            && !raw_manifest_relative.is_empty()
            && !manifest_cases.is_empty();
        if !manifest_is_bound {
            return Err(DocumentRelationBindingErrorV2::CorpusManifestMismatch(
                corpus_manifest_path.display().to_string(),
            ));
        }
        let raw_asset = workspace_path(workspace_root, raw_asset_relative)?;
        let raw_manifest = workspace_path(workspace_root, raw_manifest_relative)?;
        let raw_asset_bytes =
            fs::read(&raw_asset).map_err(|source| DocumentRelationBindingErrorV2::ReceiptIo {
                path: raw_asset.display().to_string(),
                source,
            })?;
        if format!("sha256:{:x}", Sha256::digest(&raw_asset_bytes)) != raw_spec_pin.raw_sha256 {
            return Err(DocumentRelationBindingErrorV2::RawAssetDigestMismatch(
                raw_asset.display().to_string(),
            ));
        }
        let raw_manifest_bytes = fs::read(&raw_manifest).map_err(|source| {
            DocumentRelationBindingErrorV2::ReceiptIo {
                path: raw_manifest.display().to_string(),
                source,
            }
        })?;
        let raw_asset_manifest: Value =
            serde_json::from_slice(&raw_manifest_bytes).map_err(|source| {
                DocumentRelationBindingErrorV2::ReceiptJson {
                    path: raw_manifest.display().to_string(),
                    source,
                }
            })?;
        let raw_asset_filename = raw_asset.file_name().and_then(|value| value.to_str());
        if raw_asset_manifest["schema_version"].as_str() != Some(T03_RAW_ASSET_SCHEMA)
            || raw_asset_manifest["kind"].as_str() != Some("upstream_spec_raw")
            || raw_asset_manifest["upstream_commit"].as_str()
                != Some(raw_spec_pin.upstream_commit.as_str())
            || raw_asset_manifest["sha256"].as_str() != Some(raw_spec_pin.raw_sha256.as_str())
            || raw_asset_manifest["relative_path"].as_str() != raw_asset_filename
            || raw_asset_manifest["bytes"].as_u64() != Some(raw_asset_bytes.len() as u64)
        {
            return Err(DocumentRelationBindingErrorV2::CorpusManifestMismatch(
                corpus_manifest_path.display().to_string(),
            ));
        }
        let bytes =
            fs::read(receipt_path).map_err(|source| DocumentRelationBindingErrorV2::ReceiptIo {
                path: receipt_path.display().to_string(),
                source,
            })?;
        let receipt: Value = serde_json::from_slice(&bytes).map_err(|source| {
            DocumentRelationBindingErrorV2::ReceiptJson {
                path: receipt_path.display().to_string(),
                source,
            }
        })?;
        let receipt_cases = exact_case_ids(&receipt["cases"]);
        let valid = receipt["schema_version"].as_str() == Some(T03_RECEIPT_SCHEMA)
            && receipt["status"].as_str() == Some("passed")
            && receipt["corpus_id"].as_str() == manifest["corpus_id"].as_str()
            && receipt["case_count"].as_u64() == Some(manifest_cases.len() as u64)
            && receipt_cases == manifest_cases;
        if !valid {
            return Err(DocumentRelationBindingErrorV2::ReceiptManifestMismatch(
                receipt_path.display().to_string(),
            ));
        }
        Ok(Self {
            raw_spec_pin,
            corpus_manifest_path: corpus_manifest_path.display().to_string(),
            corpus_manifest_sha256: format!("sha256:{:x}", Sha256::digest(&manifest_bytes)),
            receipt_path: receipt_relative,
            receipt_sha256: format!("sha256:{:x}", Sha256::digest(&bytes)),
            corpus_id: receipt["corpus_id"].as_str().unwrap_or_default().to_owned(),
        })
    }
}

fn exact_case_ids(value: &Value) -> BTreeSet<String> {
    let Some(cases) = value.as_array() else {
        return BTreeSet::new();
    };
    let mut ids = BTreeSet::new();
    for case in cases {
        let Some(id) = case.get("id").and_then(Value::as_str) else {
            return BTreeSet::new();
        };
        if id.trim().is_empty() || !ids.insert(id.to_owned()) {
            return BTreeSet::new();
        }
    }
    ids
}

fn workspace_path(
    workspace_root: &Path,
    relative: &str,
) -> Result<PathBuf, DocumentRelationBindingErrorV2> {
    let relative_path = Path::new(relative);
    if relative_path.is_absolute()
        || relative_path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(DocumentRelationBindingErrorV2::UnsafeWorkspacePath(
            relative.to_owned(),
        ));
    }
    Ok(workspace_root.join(relative_path))
}

fn relative_workspace_path(
    workspace_root: &Path,
    path: &Path,
) -> Result<String, DocumentRelationBindingErrorV2> {
    let relative = path.strip_prefix(workspace_root).map_err(|_| {
        DocumentRelationBindingErrorV2::UnsafeWorkspacePath(path.display().to_string())
    })?;
    let relative = relative.to_str().ok_or_else(|| {
        DocumentRelationBindingErrorV2::UnsafeWorkspacePath(path.display().to_string())
    })?;
    workspace_path(workspace_root, relative)?;
    Ok(relative.replace('\\', "/"))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentRelationValidationV2 {
    pub format: DocumentRelationFormatV2,
    pub status: DocumentRelationStatusV2,
    pub binding: T03RelationBindingV2,
    pub source_ids: Vec<String>,
    pub footnote_ids: Vec<String>,
    pub issues: Vec<DocumentRelationIssueV2>,
}

const DOCUMENT_RELATION_RECEIPT_SCHEMA: &str = "gtkg.document-relation-receipt/v2";

/// A deterministic local receipt for one document relation execution. It
/// deliberately records only the profile scope and its T03 dependency, never
/// an unsupported format or a local pass as external document conformance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentRelationReceiptV2 {
    pub schema_version: String,
    pub document_path: String,
    pub document_sha256: String,
    pub relation: DocumentRelationValidationV2,
}

#[derive(Debug, Error)]
pub enum DocumentRelationReceiptErrorV2 {
    #[error("cannot read document {path}: {source}")]
    DocumentIo {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("Markdown document {0} is not valid UTF-8")]
    MarkdownUtf8(String),
    #[error("cannot encode document relation receipt: {0}")]
    Encode(#[from] serde_json::Error),
    #[error("cannot write document relation receipt {path}: {source}")]
    ReceiptWrite {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("cannot read document relation receipt {path}: {source}")]
    ReceiptRead {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("document relation receipt {0} has an invalid schema or digest")]
    InvalidReceipt(String),
}

/// Execute the local T06 relation profile over one file and materialize the
/// result as a value suitable for an append-only receipt store.
pub fn execute_local_document_relation_receipt(
    format: DocumentRelationFormatV2,
    document_path: &Path,
    binding: &T03RelationBindingV2,
) -> Result<DocumentRelationReceiptV2, DocumentRelationReceiptErrorV2> {
    let bytes =
        fs::read(document_path).map_err(|source| DocumentRelationReceiptErrorV2::DocumentIo {
            path: document_path.display().to_string(),
            source,
        })?;
    let input = if format == DocumentRelationFormatV2::Markdown {
        std::str::from_utf8(&bytes).map_err(|_| {
            DocumentRelationReceiptErrorV2::MarkdownUtf8(document_path.display().to_string())
        })?
    } else {
        ""
    };
    Ok(DocumentRelationReceiptV2 {
        schema_version: DOCUMENT_RELATION_RECEIPT_SCHEMA.to_owned(),
        document_path: document_path.display().to_string(),
        document_sha256: format!("sha256:{:x}", Sha256::digest(&bytes)),
        relation: validate_document_relations(format, input, binding),
    })
}

/// Persist a deterministic local relation receipt. No parent is created and
/// no projection/Current state is changed by this function.
pub fn write_document_relation_receipt(
    output_path: &Path,
    receipt: &DocumentRelationReceiptV2,
) -> Result<(), DocumentRelationReceiptErrorV2> {
    let bytes = serde_json::to_vec_pretty(receipt)?;
    fs::write(output_path, bytes).map_err(|source| DocumentRelationReceiptErrorV2::ReceiptWrite {
        path: output_path.display().to_string(),
        source,
    })
}

/// Read one local relation receipt back through its strict schema.
pub fn read_document_relation_receipt(
    receipt_path: &Path,
) -> Result<DocumentRelationReceiptV2, DocumentRelationReceiptErrorV2> {
    let bytes =
        fs::read(receipt_path).map_err(|source| DocumentRelationReceiptErrorV2::ReceiptRead {
            path: receipt_path.display().to_string(),
            source,
        })?;
    let receipt: DocumentRelationReceiptV2 = serde_json::from_slice(&bytes)?;
    if receipt.schema_version != DOCUMENT_RELATION_RECEIPT_SCHEMA
        || !is_sha256(&receipt.document_sha256)
        || receipt.document_path.trim().is_empty()
    {
        return Err(DocumentRelationReceiptErrorV2::InvalidReceipt(
            receipt_path.display().to_string(),
        ));
    }
    Ok(receipt)
}

fn is_sha256(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

/// Validate the GTKG local Markdown profile's source-id → footnote → link
/// closure. Markdown syntax remains untrusted input; malformed declarations,
/// missing joins, duplicate IDs, and URL mismatches fail closed. A source may
/// be cited more than once, but every declared source must be cited at least
/// once and every cited footnote must resolve to exactly one declared source.
pub fn validate_document_relations(
    format: DocumentRelationFormatV2,
    input: &str,
    binding: &T03RelationBindingV2,
) -> DocumentRelationValidationV2 {
    if format != DocumentRelationFormatV2::Markdown {
        return DocumentRelationValidationV2 {
            format,
            status: DocumentRelationStatusV2::OmittedUnsupported,
            binding: binding.clone(),
            source_ids: Vec::new(),
            footnote_ids: Vec::new(),
            issues: vec![issue(
                "O_V2_DOC_RELATION_FORMAT_UNSUPPORTED",
                format_name(format),
                "T06 implements the Markdown relation profile only; PDF and Office relation extraction are omitted, not passed",
            )],
        };
    }

    let document = match parse_okf(input) {
        Ok(document) => document,
        Err(error) => {
            return failed(
                format,
                binding,
                Vec::new(),
                Vec::new(),
                vec![issue(
                    "E_V2_DOC_RELATION_OKF_PARSE",
                    "document",
                    format!("cannot parse Markdown/OKF input: {error}"),
                )],
            );
        }
    };

    let mut issues = Vec::new();
    let mut sources = BTreeMap::new();
    for source in &document.frontmatter.sources {
        let Some(id) = source.extra.get("id").and_then(|value| value.as_str()) else {
            issues.push(issue(
                "E_V2_DOC_RELATION_SOURCE_ID_MISSING",
                "sources[]",
                "each local-profile source declaration requires a non-empty id",
            ));
            continue;
        };
        let id = id.trim();
        if id.is_empty() {
            issues.push(issue(
                "E_V2_DOC_RELATION_SOURCE_ID_MISSING",
                "sources[]",
                "each local-profile source declaration requires a non-empty id",
            ));
            continue;
        }
        if source.resource.trim().is_empty() {
            issues.push(issue(
                "E_V2_DOC_RELATION_SOURCE_RESOURCE_MISSING",
                id,
                "a declared source id requires a non-empty resource",
            ));
            continue;
        }
        if sources
            .insert(id.to_owned(), normalize_link_target(&source.resource))
            .is_some()
        {
            issues.push(issue(
                "E_V2_DOC_RELATION_SOURCE_DUPLICATE",
                id,
                "a source id must uniquely identify one declared resource",
            ));
        }
    }

    let parsed = parse_markdown_footnotes(&document.body);
    for malformed in parsed.malformed_definitions {
        issues.push(issue(
            "E_V2_DOC_RELATION_FOOTNOTE_DEFINITION_MALFORMED",
            &malformed,
            "a footnote definition must have a non-empty label and body",
        ));
    }
    for duplicate in parsed.duplicate_definitions {
        issues.push(issue(
            "E_V2_DOC_RELATION_FOOTNOTE_DUPLICATE",
            &duplicate,
            "a footnote label may have only one definition",
        ));
    }

    for id in &parsed.references {
        let Some(resource) = sources.get(id) else {
            issues.push(issue(
                "E_V2_DOC_RELATION_FOOTNOTE_UNKNOWN_SOURCE",
                id,
                "a cited footnote label must identify one declared frontmatter source",
            ));
            continue;
        };
        let Some(definition) = parsed.definitions.get(id) else {
            issues.push(issue(
                "E_V2_DOC_RELATION_FOOTNOTE_DEFINITION_MISSING",
                id,
                "a cited source footnote must have one Markdown definition",
            ));
            continue;
        };
        if !markdown_link_targets(definition)
            .iter()
            .any(|target| target == resource)
        {
            issues.push(issue(
                "E_V2_DOC_RELATION_FOOTNOTE_LINK_MISMATCH",
                id,
                "the source footnote definition must contain a Markdown link to its declared resource",
            ));
        }
    }

    for id in sources.keys() {
        if !parsed.references.contains(id) {
            issues.push(issue(
                "E_V2_DOC_RELATION_SOURCE_ORPHAN",
                id,
                "each declared source must be cited by at least one body footnote",
            ));
        }
    }
    for id in parsed.definitions.keys() {
        if !parsed.references.contains(id) {
            issues.push(issue(
                "E_V2_DOC_RELATION_FOOTNOTE_ORPHAN",
                id,
                "a footnote definition without a body citation is not provenance closure",
            ));
        }
    }

    let source_ids = sources.into_keys().collect();
    let footnote_ids = parsed.references.into_iter().collect();
    if issues.is_empty() {
        DocumentRelationValidationV2 {
            format,
            status: DocumentRelationStatusV2::Passed,
            binding: binding.clone(),
            source_ids,
            footnote_ids,
            issues,
        }
    } else {
        failed(format, binding, source_ids, footnote_ids, issues)
    }
}

fn failed(
    format: DocumentRelationFormatV2,
    binding: &T03RelationBindingV2,
    source_ids: Vec<String>,
    footnote_ids: Vec<String>,
    issues: Vec<DocumentRelationIssueV2>,
) -> DocumentRelationValidationV2 {
    DocumentRelationValidationV2 {
        format,
        status: DocumentRelationStatusV2::Failed,
        binding: binding.clone(),
        source_ids,
        footnote_ids,
        issues,
    }
}

fn issue(
    code: impl Into<String>,
    subject: impl Into<String>,
    detail: impl Into<String>,
) -> DocumentRelationIssueV2 {
    DocumentRelationIssueV2 {
        code: code.into(),
        subject: subject.into(),
        detail: detail.into(),
    }
}

fn format_name(format: DocumentRelationFormatV2) -> &'static str {
    match format {
        DocumentRelationFormatV2::Markdown => "markdown",
        DocumentRelationFormatV2::Pdf => "pdf",
        DocumentRelationFormatV2::Office => "office",
    }
}

#[derive(Default)]
struct ParsedFootnotes {
    references: BTreeSet<String>,
    definitions: BTreeMap<String, String>,
    duplicate_definitions: BTreeSet<String>,
    malformed_definitions: BTreeSet<String>,
}

#[derive(Debug, Clone, Copy)]
struct FenceDelimiter {
    marker: char,
    length: usize,
}

fn parse_markdown_footnotes(body: &str) -> ParsedFootnotes {
    let mut parsed = ParsedFootnotes::default();
    let mut fence: Option<FenceDelimiter> = None;
    for line in body.lines() {
        let trimmed = line.trim_start();
        if let Some(opening) = fence {
            if fence_length(trimmed, opening.marker) >= opening.length {
                fence = None;
            }
            continue;
        }
        if let Some(opening) = opening_fence(trimmed) {
            fence = Some(opening);
            continue;
        }
        if let Some((id, definition)) = footnote_definition(trimmed) {
            if id.is_empty() || definition.trim().is_empty() {
                parsed.malformed_definitions.insert(id);
            } else if parsed.definitions.insert(id.clone(), definition).is_some() {
                parsed.duplicate_definitions.insert(id);
            }
            continue;
        }
        parsed.references.extend(footnote_references(line));
    }
    parsed
}

fn opening_fence(line: &str) -> Option<FenceDelimiter> {
    for marker in ['`', '~'] {
        let length = fence_length(line, marker);
        if length >= 3 {
            return Some(FenceDelimiter { marker, length });
        }
    }
    None
}

fn fence_length(line: &str, marker: char) -> usize {
    line.chars()
        .take_while(|candidate| *candidate == marker)
        .count()
}

fn footnote_definition(line: &str) -> Option<(String, String)> {
    let suffix = line.strip_prefix("[^")?;
    let (id, definition) = suffix
        .split_once("]: ")
        .or_else(|| suffix.split_once("]:"))?;
    Some((id.trim().to_owned(), definition.trim().to_owned()))
}

fn footnote_references(line: &str) -> BTreeSet<String> {
    let mut ids = BTreeSet::new();
    let mut remaining = line;
    while let Some(start) = remaining.find("[^") {
        let after = &remaining[start + 2..];
        let Some(end) = after.find(']') else {
            break;
        };
        let id = after[..end].trim();
        if !id.is_empty() {
            ids.insert(id.to_owned());
        }
        remaining = &after[end + 1..];
    }
    ids
}

fn markdown_link_targets(definition: &str) -> Vec<String> {
    let mut targets = Vec::new();
    let mut remaining = definition;
    while let Some(open) = remaining.find("](") {
        let after = &remaining[open + 2..];
        let Some(close) = after.find(')') else {
            break;
        };
        let target = after[..close].split_whitespace().next().unwrap_or_default();
        if !target.is_empty() {
            targets.push(normalize_link_target(target));
        }
        remaining = &after[close + 1..];
    }
    targets
}

fn normalize_link_target(target: &str) -> String {
    target.trim().trim_matches(['<', '>']).to_owned()
}
