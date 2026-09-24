//! Static, no-execution source extractors.
pub mod v04;

mod semantics;

use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use gtkg_protocol::v2::{
    CapabilityState, EvidenceSpanV2, IrEdgeV2, IrNodeV2, IrResolutionStateV2, SourceSnapshotV2,
    TypedIrError, TypedIrModeV2, TypedIrV2,
};
use lopdf::Document;
use quick_xml::Reader;
use quick_xml::events::{BytesStart, Event};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zip::ZipArchive;

const MAX_SOURCE_BYTES: u64 = 32 * 1024 * 1024;
const MAX_ARCHIVE_ENTRIES: usize = 4_096;
const MAX_ARCHIVE_UNCOMPRESSED_BYTES: u64 = 128 * 1024 * 1024;
const MAX_SVG_EVENTS: usize = 100_000;
const MAX_SVG_DEPTH: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceByteSpan {
    /// Inclusive UTF-8 byte offset in the exact source blob.
    pub start: u64,
    /// Exclusive UTF-8 byte offset in the exact source blob.
    pub end: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedStaticFact {
    /// Open string vocabulary. A fact is emitted only when matching syntax was observed.
    pub kind: String,
    /// Exact marker text selected from `span`; downstream entity ids are `{kind}:{marker_id}`.
    pub marker_id: String,
    pub span: SourceByteSpan,
    pub evidence_level: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtractedDocument {
    pub source_sha256: String,
    pub media_type: String,
    pub extractor_id: String,
    pub text: String,
    pub observations: BTreeMap<String, String>,
    pub observed_facts: Vec<ObservedStaticFact>,
    pub target_process_count: u64,
    pub executed_target_content: bool,
}

#[derive(Debug, Error)]
pub enum ExtractError {
    #[error("source file is missing: {0}")]
    Missing(PathBuf),
    #[error("source file exceeds the static extraction limit: {path} ({bytes} bytes)")]
    SourceTooLarge { path: PathBuf, bytes: u64 },
    #[error("unsupported source format: {0}")]
    Unsupported(PathBuf),
    #[error("source is not valid UTF-8: {0}")]
    InvalidUtf8(PathBuf),
    #[error("failed to read {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid PDF {path}: {message}")]
    InvalidPdf { path: PathBuf, message: String },
    #[error("PDF has no statically extractable text and needs OCR: {0}")]
    NeedsOcr(PathBuf),
    #[error("invalid OpenXML package {path}: {message}")]
    InvalidOpenXml { path: PathBuf, message: String },
    #[error("OpenXML package exceeds extraction budgets: {0}")]
    ArchiveBudget(PathBuf),
    #[error("invalid SVG {path}: {message}")]
    InvalidSvg { path: PathBuf, message: String },
    #[error("unsafe active SVG content is rejected: {0}")]
    UnsafeSvg(PathBuf),
    #[error("SVG exceeds static extraction budgets: {0}")]
    SvgBudget(PathBuf),
}

pub fn extract_path(path: &Path) -> Result<ExtractedDocument, ExtractError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| {
        if source.kind() == std::io::ErrorKind::NotFound {
            ExtractError::Missing(path.to_path_buf())
        } else {
            ExtractError::Io {
                path: path.to_path_buf(),
                source,
            }
        }
    })?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(ExtractError::Unsupported(path.to_path_buf()));
    }
    if metadata.len() > MAX_SOURCE_BYTES {
        return Err(ExtractError::SourceTooLarge {
            path: path.to_path_buf(),
            bytes: metadata.len(),
        });
    }
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .map(str::to_ascii_lowercase)
        .ok_or_else(|| ExtractError::Unsupported(path.to_path_buf()))?;
    match extension.as_str() {
        "md" | "markdown" => extract_markdown(path),
        "rs" => extract_code_file(
            path,
            "text/x-rust",
            "gtkg-code-static-rust/v1",
            CodeLanguage::Rust,
        ),
        "py" => extract_code_file(
            path,
            "text/x-python",
            "gtkg-code-static-python/v1",
            CodeLanguage::Python,
        ),
        "ts" | "tsx" => extract_code_file(
            path,
            "text/typescript",
            "gtkg-code-static-ts/v1",
            CodeLanguage::TypeScript,
        ),
        "js" | "jsx" => extract_code_file(
            path,
            "text/javascript",
            "gtkg-code-static-js/v1",
            CodeLanguage::JavaScript,
        ),
        "css" => extract_css(path),
        "svg" => extract_svg(path),
        "toml" => extract_toml_like(path, "application/toml", "gtkg-toml-static/v1"),
        "lock" => extract_toml_like(path, "text/x-lockfile", "gtkg-lock-static/v1"),
        "json" => extract_json(path),
        "yaml" | "yml" => extract_yaml(path),
        "sh" => extract_shell(path),
        "html" => extract_html(path),
        "pdf" => extract_pdf(path),
        "docx" | "xlsx" | "pptx" => extract_openxml(path, &extension),
        _ => Err(ExtractError::Unsupported(path.to_path_buf())),
    }
}

pub fn is_supported_path(path: &Path) -> bool {
    path.extension()
        .and_then(|value| value.to_str())
        .map(str::to_ascii_lowercase)
        .is_some_and(|extension| {
            matches!(
                extension.as_str(),
                "md" | "markdown"
                    | "rs"
                    | "py"
                    | "ts"
                    | "tsx"
                    | "js"
                    | "jsx"
                    | "css"
                    | "svg"
                    | "toml"
                    | "lock"
                    | "json"
                    | "yaml"
                    | "yml"
                    | "sh"
                    | "html"
                    | "pdf"
                    | "docx"
                    | "xlsx"
                    | "pptx"
            )
        })
}

/// Build the T02 transport-neutral typed IR for one already statically
/// extracted code source. The source must be an admitted entry in the exact
/// T01 snapshot; code with parser failure produces explicit fallback lexical
/// mode with no semantic facts rather than promoting legacy string matches.
pub fn build_typed_ir_v2(
    snapshot: &SourceSnapshotV2,
    logical_path: &str,
    extracted: &ExtractedDocument,
) -> Result<TypedIrV2, TypedIrError> {
    let source_bytes = extracted.text.as_bytes();
    if digest_bytes(source_bytes) != extracted.source_sha256 {
        return Err(TypedIrError::ExtractedSourceDigestMismatch);
    }
    snapshot
        .validate()
        .map_err(|_| TypedIrError::SourceSnapshotInvalid)?;
    let admitted = snapshot.inventory.iter().any(|entry| {
        entry.logical_path == logical_path
            && entry.content_sha256 == extracted.source_sha256
            && entry.bytes == source_bytes.len() as u64
    });
    if !admitted {
        return Err(TypedIrError::SourceNotAdmitted);
    }
    let Some(language) = code_language_for_extractor(&extracted.extractor_id) else {
        return Err(TypedIrError::SourceNotAdmitted);
    };
    if extractor_id_for_logical_path(logical_path) != Some(extracted.extractor_id.as_str()) {
        return Err(TypedIrError::ExtractorIdentityMismatch);
    }
    let capabilities = typed_ir_capabilities();
    let Some(semantics) = semantics::analyze(&extracted.text, language) else {
        return Ok(TypedIrV2 {
            schema_version: "gtkg.typed-ir/v2".to_owned(),
            source_snapshot_exact_set_sha256: snapshot.exact_set_sha256.clone(),
            source_logical_path: logical_path.to_owned(),
            source_sha256: extracted.source_sha256.clone(),
            extractor_id: extracted.extractor_id.clone(),
            mode: TypedIrModeV2::FallbackLexical,
            capabilities,
            evidence: Vec::new(),
            nodes: Vec::new(),
            edges: Vec::new(),
            typed_ir_sha256: String::new(),
        }
        .with_digest());
    };

    let source_snapshot_digest = snapshot.exact_set_sha256.clone();
    let source_digest = extracted.source_sha256.clone();
    let typed_source = TypedIrSourceContext {
        snapshot_digest: &source_snapshot_digest,
        logical_path,
        source_digest: &source_digest,
        bytes: source_bytes,
    };
    let mut evidence = Vec::new();
    let mut nodes = Vec::new();
    for definition in &semantics.definitions {
        let evidence_id = push_evidence(
            &mut evidence,
            &typed_source,
            "definition",
            definition.start,
            definition.end,
        );
        let id = stable_id(
            "node",
            &[
                &source_snapshot_digest,
                logical_path,
                &source_digest,
                definition.kind,
                &definition.name,
                &definition.start.to_string(),
                &definition.end.to_string(),
            ],
        );
        nodes.push(IrNodeV2 {
            id,
            kind: definition.kind.to_owned(),
            name: definition.name.clone(),
            scope_id: stable_id(
                "scope",
                &[
                    &source_snapshot_digest,
                    logical_path,
                    &source_digest,
                    "module",
                ],
            ),
            evidence_ids: vec![evidence_id],
        });
    }
    nodes.sort();

    let mut node_ids_by_name = BTreeMap::<String, Vec<String>>::new();
    for node in &nodes {
        node_ids_by_name
            .entry(node.name.clone())
            .or_default()
            .push(node.id.clone());
    }

    let mut edges = Vec::new();
    for import in &semantics.imports {
        let evidence_id = push_evidence(
            &mut evidence,
            &typed_source,
            "import",
            import.start,
            import.end,
        );
        edges.push(unresolved_edge(
            "imports",
            None,
            &import.module,
            import.start,
            import.end,
            &source_snapshot_digest,
            logical_path,
            &source_digest,
            evidence_id,
        ));
    }
    for call in &semantics.calls {
        let evidence_id = push_evidence(&mut evidence, &typed_source, "call", call.start, call.end);
        edges.push(unresolved_edge(
            "calls",
            unique_node_id(&node_ids_by_name, &call.caller),
            &call.callee,
            call.start,
            call.end,
            &source_snapshot_digest,
            logical_path,
            &source_digest,
            evidence_id,
        ));
    }
    for inherit in &semantics.inherits {
        let evidence_id = push_evidence(
            &mut evidence,
            &typed_source,
            "inherits",
            inherit.start,
            inherit.end,
        );
        edges.push(unresolved_edge(
            "inherits",
            unique_node_id(&node_ids_by_name, &inherit.child),
            &inherit.parent,
            inherit.start,
            inherit.end,
            &source_snapshot_digest,
            logical_path,
            &source_digest,
            evidence_id,
        ));
    }
    evidence.sort();
    edges.sort();
    Ok(TypedIrV2 {
        schema_version: "gtkg.typed-ir/v2".to_owned(),
        source_snapshot_exact_set_sha256: source_snapshot_digest,
        source_logical_path: logical_path.to_owned(),
        source_sha256: source_digest,
        extractor_id: extracted.extractor_id.clone(),
        mode: TypedIrModeV2::AstSemantic,
        capabilities,
        evidence,
        nodes,
        edges,
        typed_ir_sha256: String::new(),
    }
    .with_digest())
}

/// A language-specific, intentionally local resolver declaration for the T05
/// development profile.  It describes what the resolver is allowed to infer;
/// it is not a claim of type checking, workspace/module resolution, CFG,
/// def-use, state flow, or an externally scored semantic result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalResolverProfileV2 {
    pub schema_version: String,
    pub adapter_id: String,
    pub language: String,
    pub scope: String,
    pub capabilities: BTreeMap<String, CapabilityState>,
}

/// Return the resolver profile associated with one of the four static code
/// extractors.  Unknown extractors deliberately have no resolver profile.
pub fn local_resolver_profile_v2(extractor_id: &str) -> Option<LocalResolverProfileV2> {
    let language = match extractor_id {
        "gtkg-code-static-rust/v1" => "rust",
        "gtkg-code-static-python/v1" => "python",
        "gtkg-code-static-ts/v1" => "typescript",
        "gtkg-code-static-js/v1" => "javascript",
        _ => return None,
    };
    Some(LocalResolverProfileV2 {
        schema_version: "gtkg.local-resolver-profile/v2".to_owned(),
        adapter_id: format!("gtkg-local-{language}-resolver/v2"),
        language: language.to_owned(),
        scope: "same_file_syntax_observed_only".to_owned(),
        capabilities: BTreeMap::from([
            ("calls".to_owned(), CapabilityState::Supported),
            ("cfg".to_owned(), CapabilityState::Unsupported),
            ("def_use".to_owned(), CapabilityState::Unsupported),
            ("exception".to_owned(), CapabilityState::Unsupported),
            ("imports".to_owned(), CapabilityState::Partial),
            ("inheritance".to_owned(), CapabilityState::Partial),
            (
                "same_file_reference_resolution".to_owned(),
                CapabilityState::Supported,
            ),
            ("state_flow".to_owned(), CapabilityState::Unsupported),
            ("symbols".to_owned(), CapabilityState::Supported),
            ("syntax".to_owned(), CapabilityState::Supported),
            (
                "workspace_import_resolution".to_owned(),
                CapabilityState::Unsupported,
            ),
            ("types".to_owned(), CapabilityState::Unsupported),
            (
                "external_semantic_score".to_owned(),
                CapabilityState::Unsupported,
            ),
        ]),
    })
}

/// Resolve only exact, same-file references against nodes already backed by
/// byte-verifiable evidence in a T02 IR.  The source readback is required so a
/// caller cannot promote a pre-tampered node/evidence set.  Import edges stay
/// unresolved because this function has no workspace topology, package
/// manifest, or cross-file source admission evidence.  Zero candidates remain
/// unresolved and multiple candidates remain ambiguous; neither condition is
/// guessed into a target.
pub fn resolve_local_typed_ir_v2(
    ir: &TypedIrV2,
    source_bytes: &[u8],
) -> Result<TypedIrV2, TypedIrError> {
    ir.validate_for_source(source_bytes)?;
    let expected_extractor_id = extractor_id_for_logical_path(&ir.source_logical_path)
        .ok_or(TypedIrError::ExtractorIdentityMismatch)?;
    if ir.extractor_id != expected_extractor_id {
        return Err(TypedIrError::ExtractorIdentityMismatch);
    }
    let profile = local_resolver_profile_v2(&ir.extractor_id)
        .ok_or(TypedIrError::ExtractorIdentityMismatch)?;

    let mut resolved = ir.clone();
    resolved.capabilities = profile.capabilities.clone();

    let node_evidence_by_id = resolved
        .nodes
        .iter()
        .map(|node| (node.id.as_str(), node.evidence_ids.as_slice()))
        .collect::<BTreeMap<_, _>>();
    let mut candidate_ids_by_name = BTreeMap::<String, Vec<String>>::new();
    for node in &resolved.nodes {
        candidate_ids_by_name
            .entry(node.name.clone())
            .or_default()
            .push(node.id.clone());
    }
    for candidates in candidate_ids_by_name.values_mut() {
        candidates.sort();
        candidates.dedup();
    }

    for edge in &mut resolved.edges {
        // Resolver input is not authoritative: clear any preloaded target,
        // candidate, or state before deciding against the exact local profile.
        edge.resolution = IrResolutionStateV2::Unresolved;
        edge.resolved_node_id = None;
        edge.candidate_node_ids.clear();
        // Imports and any future relation kinds require workspace or language
        // semantic evidence absent from this profile. A syntax span cannot be
        // promoted merely because a same-named local node exists.
        if !matches!(edge.kind.as_str(), "calls" | "inherits") {
            continue;
        }
        let candidates = candidate_ids_by_name
            .get(&edge.target_reference)
            .cloned()
            .unwrap_or_default();
        match candidates.as_slice() {
            [] => {}
            [target_id] => {
                let Some(target_evidence_ids) = node_evidence_by_id.get(target_id.as_str()) else {
                    return Err(TypedIrError::DanglingEvidenceReference);
                };
                edge.resolution = IrResolutionStateV2::Resolved;
                edge.resolved_node_id = Some(target_id.clone());
                edge.candidate_node_ids.clear();
                edge.evidence_ids.extend_from_slice(target_evidence_ids);
                edge.evidence_ids.sort();
                edge.evidence_ids.dedup();
            }
            _ => {
                edge.resolution = IrResolutionStateV2::Ambiguous;
                edge.resolved_node_id = None;
                edge.candidate_node_ids = candidates;
            }
        }
    }

    let resolved = resolved.with_digest();
    resolved.validate_for_source(source_bytes)?;
    Ok(resolved)
}

fn extractor_id_for_logical_path(logical_path: &str) -> Option<&'static str> {
    let extension = Path::new(logical_path)
        .extension()
        .and_then(|value| value.to_str())?
        .to_ascii_lowercase();
    match extension.as_str() {
        "rs" => Some("gtkg-code-static-rust/v1"),
        "py" => Some("gtkg-code-static-python/v1"),
        "ts" | "tsx" => Some("gtkg-code-static-ts/v1"),
        "js" | "jsx" => Some("gtkg-code-static-js/v1"),
        _ => None,
    }
}

fn code_language_for_extractor(extractor_id: &str) -> Option<CodeLanguage> {
    match extractor_id {
        "gtkg-code-static-rust/v1" => Some(CodeLanguage::Rust),
        "gtkg-code-static-python/v1" => Some(CodeLanguage::Python),
        "gtkg-code-static-ts/v1" => Some(CodeLanguage::TypeScript),
        "gtkg-code-static-js/v1" => Some(CodeLanguage::JavaScript),
        _ => None,
    }
}

fn typed_ir_capabilities() -> BTreeMap<String, CapabilityState> {
    BTreeMap::from([
        ("calls".to_owned(), CapabilityState::Supported),
        ("cfg".to_owned(), CapabilityState::Unsupported),
        ("def_use".to_owned(), CapabilityState::Unsupported),
        ("exception".to_owned(), CapabilityState::Unsupported),
        ("imports".to_owned(), CapabilityState::Supported),
        ("inheritance".to_owned(), CapabilityState::Partial),
        ("state_flow".to_owned(), CapabilityState::Unsupported),
        ("symbols".to_owned(), CapabilityState::Supported),
        ("syntax".to_owned(), CapabilityState::Supported),
        ("types".to_owned(), CapabilityState::Unsupported),
    ])
}

struct TypedIrSourceContext<'a> {
    snapshot_digest: &'a str,
    logical_path: &'a str,
    source_digest: &'a str,
    bytes: &'a [u8],
}

fn push_evidence(
    evidence: &mut Vec<EvidenceSpanV2>,
    source: &TypedIrSourceContext<'_>,
    kind: &str,
    start: usize,
    end: usize,
) -> String {
    let snippet = &source.bytes[start..end];
    let snippet_sha256 = digest_bytes(snippet);
    let id = stable_id(
        "evidence",
        &[
            source.snapshot_digest,
            source.logical_path,
            source.source_digest,
            kind,
            &start.to_string(),
            &end.to_string(),
            &snippet_sha256,
        ],
    );
    evidence.push(EvidenceSpanV2 {
        id: id.clone(),
        source_snapshot_exact_set_sha256: source.snapshot_digest.to_owned(),
        source_logical_path: source.logical_path.to_owned(),
        source_sha256: source.source_digest.to_owned(),
        byte_start: start as u64,
        byte_end: end as u64,
        line_start: source_line_for_byte(source.bytes, start),
        line_end: source_line_for_byte(source.bytes, end.saturating_sub(1)),
        snippet_sha256,
        evidence_level: "syntax_observed".to_owned(),
    });
    id
}

fn source_line_for_byte(source_bytes: &[u8], offset: usize) -> u64 {
    source_bytes[..offset]
        .iter()
        .filter(|byte| **byte == b'\n')
        .count() as u64
        + 1
}

#[allow(clippy::too_many_arguments)]
fn unresolved_edge(
    kind: &str,
    source_node_id: Option<String>,
    target_reference: &str,
    start: usize,
    end: usize,
    source_snapshot_exact_set_sha256: &str,
    logical_path: &str,
    source_sha256: &str,
    evidence_id: String,
) -> IrEdgeV2 {
    let id = stable_id(
        "edge",
        &[
            source_snapshot_exact_set_sha256,
            logical_path,
            source_sha256,
            kind,
            source_node_id.as_deref().unwrap_or("<module>"),
            target_reference,
            &start.to_string(),
            &end.to_string(),
        ],
    );
    IrEdgeV2 {
        id,
        kind: kind.to_owned(),
        source_node_id,
        target_reference: target_reference.to_owned(),
        candidate_node_ids: Vec::new(),
        resolved_node_id: None,
        resolution: IrResolutionStateV2::Unresolved,
        evidence_ids: vec![evidence_id],
    }
}

fn unique_node_id(nodes: &BTreeMap<String, Vec<String>>, name: &str) -> Option<String> {
    let candidates = nodes.get(name)?;
    (candidates.len() == 1).then(|| candidates[0].clone())
}

fn stable_id(prefix: &str, fields: &[&str]) -> String {
    let mut hasher = Sha256::new();
    for field in fields {
        hasher.update((field.len() as u64).to_be_bytes());
        hasher.update(field.as_bytes());
    }
    format!("{prefix}:v2:{:x}", hasher.finalize())
}

fn extract_text_file(
    path: &Path,
    media_type: &str,
    extractor_id: &str,
) -> Result<ExtractedDocument, ExtractError> {
    let bytes = fs::read(path).map_err(|source| ExtractError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let text = String::from_utf8(bytes.clone())
        .map_err(|_| ExtractError::InvalidUtf8(path.to_path_buf()))?;
    Ok(ExtractedDocument {
        source_sha256: digest_bytes(&bytes),
        media_type: media_type.to_owned(),
        extractor_id: extractor_id.to_owned(),
        text,
        observations: BTreeMap::from([
            ("mode".to_owned(), "static".to_owned()),
            ("target_process_count".to_owned(), "0".to_owned()),
        ]),
        observed_facts: Vec::new(),
        target_process_count: 0,
        executed_target_content: false,
    })
}

fn extract_markdown(path: &Path) -> Result<ExtractedDocument, ExtractError> {
    let mut extracted = extract_text_file(path, "text/markdown", "gtkg-markdown/v1")?;
    extracted.observed_facts = markdown_facts(&extracted.text);
    extracted.observations.insert(
        "observed_fact_count".to_owned(),
        extracted.observed_facts.len().to_string(),
    );
    Ok(extracted)
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum CodeLanguage {
    Rust,
    Python,
    TypeScript,
    JavaScript,
}

fn extract_code_file(
    path: &Path,
    media_type: &str,
    extractor_id: &str,
    language: CodeLanguage,
) -> Result<ExtractedDocument, ExtractError> {
    let bytes = fs::read(path).map_err(|source| ExtractError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let text = String::from_utf8(bytes.clone())
        .map_err(|_| ExtractError::InvalidUtf8(path.to_path_buf()))?;
    let symbols = static_symbols(&text, language);
    let observed_facts = match language {
        CodeLanguage::TypeScript | CodeLanguage::JavaScript => ecmascript_frontend_facts(&text),
        CodeLanguage::Rust | CodeLanguage::Python => Vec::new(),
    };
    let semantics = semantics::analyze(&text, language);
    let mut observations = BTreeMap::from([
        ("mode".to_owned(), "static".to_owned()),
        (
            "structure_mode".to_owned(),
            if semantics.is_some() {
                "ast_semantic".to_owned()
            } else {
                "lexical_declarations".to_owned()
            },
        ),
        ("symbol_count".to_owned(), symbols.len().to_string()),
        (
            "symbols".to_owned(),
            symbols.into_iter().collect::<Vec<_>>().join("\n"),
        ),
        ("target_process_count".to_owned(), "0".to_owned()),
        (
            "observed_fact_count".to_owned(),
            observed_facts.len().to_string(),
        ),
    ]);
    semantics::apply_observations(semantics.as_ref(), &mut observations);
    Ok(ExtractedDocument {
        source_sha256: digest_bytes(&bytes),
        media_type: media_type.to_owned(),
        extractor_id: extractor_id.to_owned(),
        text,
        observations,
        observed_facts,
        target_process_count: 0,
        executed_target_content: false,
    })
}

fn ecmascript_frontend_facts(source: &str) -> Vec<ObservedStaticFact> {
    let mut facts = Vec::new();
    let code = lexical_code_mask(source, true, true);
    for (attribute, kind) in [
        ("data-app-id", "app"),
        ("data-surface-id", "surface"),
        ("data-component-id", "component"),
        ("aria-label", "accessibility"),
    ] {
        scan_jsx_string_attribute(source, &code, attribute, kind, &mut facts);
    }
    scan_call_string_argument(source, &code, "openKnowledge", "interaction", &mut facts);
    scan_bracket_string_access(source, &code, "model", "data_binding", &mut facts);
    for (_, start, end) in object_string_fields(source, &code, "stateId") {
        push_fact(source, "ui_state", start, end, &mut facts);
    }

    // `id` and `path` must be direct members of the same lexical object. A path in
    // a comment, string, nested object, or unrelated object cannot promote an id.
    let braces = ecmascript_brace_spans(source, &code);
    let path_objects = object_field_positions(source, &code, "path")
        .into_iter()
        .filter_map(|position| innermost_enclosing_brace(&braces, position))
        .collect::<std::collections::BTreeSet<_>>();
    for (position, start, end) in object_string_fields(source, &code, "id") {
        if innermost_enclosing_brace(&braces, position)
            .is_some_and(|object| path_objects.contains(&object))
        {
            push_fact(source, "route", start, end, &mut facts);
        }
    }
    normalize_facts(facts)
}

fn lexical_code_mask(source: &str, line_comments: bool, template_literals: bool) -> Vec<bool> {
    let bytes = source.as_bytes();
    let mut code = vec![true; bytes.len()];
    let mut cursor = 0_usize;
    while cursor < bytes.len() {
        if bytes[cursor] == b'/' && bytes.get(cursor + 1) == Some(&b'*') {
            let start = cursor;
            cursor = cursor.saturating_add(2);
            while cursor < bytes.len()
                && !(bytes[cursor] == b'*' && bytes.get(cursor + 1) == Some(&b'/'))
            {
                cursor = cursor.saturating_add(1);
            }
            cursor = (cursor + 2).min(bytes.len());
            code[start..cursor].fill(false);
            continue;
        }
        if line_comments && bytes[cursor] == b'/' && bytes.get(cursor + 1) == Some(&b'/') {
            let start = cursor;
            cursor = cursor.saturating_add(2);
            while cursor < bytes.len() && bytes[cursor] != b'\n' {
                cursor = cursor.saturating_add(1);
            }
            code[start..cursor].fill(false);
            continue;
        }
        let quote = bytes[cursor];
        if quote == b'\'' || quote == b'"' || (template_literals && quote == b'`') {
            let start = cursor;
            cursor = cursor.saturating_add(1);
            while cursor < bytes.len() {
                if bytes[cursor] == b'\\' {
                    cursor = (cursor + 2).min(bytes.len());
                } else if bytes[cursor] == quote {
                    cursor = cursor.saturating_add(1);
                    break;
                } else {
                    cursor = cursor.saturating_add(1);
                }
            }
            code[start..cursor].fill(false);
            continue;
        }
        cursor = cursor.saturating_add(1);
    }
    code
}

fn scan_jsx_string_attribute(
    source: &str,
    code: &[bool],
    attribute: &str,
    kind: &str,
    facts: &mut Vec<ObservedStaticFact>,
) {
    let mut cursor = 0_usize;
    while let Some(relative) = source[cursor..].find(attribute) {
        let position = cursor + relative;
        let after_name = position + attribute.len();
        if code.get(position) == Some(&true)
            && has_identifier_boundaries(source.as_bytes(), position, after_name)
            && inside_jsx_open_tag(source, code, position)
        {
            let equals = skip_ascii_whitespace(source.as_bytes(), after_name);
            if source.as_bytes().get(equals) == Some(&b'=') {
                let quote = skip_ascii_whitespace(source.as_bytes(), equals + 1);
                if let Some((start, end)) = quoted_literal_span(source, quote) {
                    push_fact(source, kind, start, end, facts);
                }
            }
        }
        cursor = after_name;
    }
}

fn scan_call_string_argument(
    source: &str,
    code: &[bool],
    callee: &str,
    kind: &str,
    facts: &mut Vec<ObservedStaticFact>,
) {
    let mut cursor = 0_usize;
    while let Some(relative) = source[cursor..].find(callee) {
        let position = cursor + relative;
        let after_name = position + callee.len();
        if code.get(position) == Some(&true)
            && has_identifier_boundaries(source.as_bytes(), position, after_name)
        {
            let open = skip_ascii_whitespace(source.as_bytes(), after_name);
            if source.as_bytes().get(open) == Some(&b'(') {
                let quote = skip_ascii_whitespace(source.as_bytes(), open + 1);
                if let Some((start, end)) = quoted_literal_span(source, quote) {
                    push_fact(source, kind, start, end, facts);
                }
            }
        }
        cursor = after_name;
    }
}

fn scan_bracket_string_access(
    source: &str,
    code: &[bool],
    object: &str,
    kind: &str,
    facts: &mut Vec<ObservedStaticFact>,
) {
    let mut cursor = 0_usize;
    while let Some(relative) = source[cursor..].find(object) {
        let position = cursor + relative;
        let after_name = position + object.len();
        if code.get(position) == Some(&true)
            && has_identifier_boundaries(source.as_bytes(), position, after_name)
        {
            let open = skip_ascii_whitespace(source.as_bytes(), after_name);
            if source.as_bytes().get(open) == Some(&b'[') {
                let quote = skip_ascii_whitespace(source.as_bytes(), open + 1);
                if let Some((start, end)) = quoted_literal_span(source, quote) {
                    push_fact(source, kind, start, end, facts);
                }
            }
        }
        cursor = after_name;
    }
}

fn object_string_fields(source: &str, code: &[bool], field: &str) -> Vec<(usize, usize, usize)> {
    let mut fields = Vec::new();
    let mut cursor = 0_usize;
    while let Some(relative) = source[cursor..].find(field) {
        let position = cursor + relative;
        let after_name = position + field.len();
        if code.get(position) == Some(&true)
            && has_identifier_boundaries(source.as_bytes(), position, after_name)
        {
            let colon = skip_ascii_whitespace(source.as_bytes(), after_name);
            if source.as_bytes().get(colon) == Some(&b':') {
                let quote = skip_ascii_whitespace(source.as_bytes(), colon + 1);
                if let Some((start, end)) = quoted_literal_span(source, quote) {
                    fields.push((position, start, end));
                }
            }
        }
        cursor = after_name;
    }
    fields
}

fn object_field_positions(source: &str, code: &[bool], field: &str) -> Vec<usize> {
    let mut positions = Vec::new();
    let mut cursor = 0_usize;
    while let Some(relative) = source[cursor..].find(field) {
        let position = cursor + relative;
        let after_name = position + field.len();
        if code.get(position) == Some(&true)
            && has_identifier_boundaries(source.as_bytes(), position, after_name)
            && source
                .as_bytes()
                .get(skip_ascii_whitespace(source.as_bytes(), after_name))
                == Some(&b':')
        {
            positions.push(position);
        }
        cursor = after_name;
    }
    positions
}

fn quoted_literal_span(source: &str, quote: usize) -> Option<(usize, usize)> {
    let bytes = source.as_bytes();
    let delimiter = *bytes.get(quote)?;
    if delimiter != b'\'' && delimiter != b'"' {
        return None;
    }
    let start = quote + 1;
    let mut cursor = start;
    while cursor < bytes.len() {
        if bytes[cursor] == b'\\' {
            cursor = (cursor + 2).min(bytes.len());
        } else if bytes[cursor] == delimiter {
            return Some((start, cursor));
        } else {
            cursor = cursor.saturating_add(1);
        }
    }
    None
}

fn skip_ascii_whitespace(bytes: &[u8], mut cursor: usize) -> usize {
    while bytes.get(cursor).is_some_and(u8::is_ascii_whitespace) {
        cursor = cursor.saturating_add(1);
    }
    cursor
}

fn has_identifier_boundaries(bytes: &[u8], start: usize, end: usize) -> bool {
    bytes
        .get(start.wrapping_sub(1))
        .is_none_or(|byte| !is_ecmascript_identifier_byte(*byte))
        && bytes
            .get(end)
            .is_none_or(|byte| !is_ecmascript_identifier_byte(*byte))
}

fn is_ecmascript_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'$' | b'-')
}

fn inside_jsx_open_tag(source: &str, code: &[bool], position: usize) -> bool {
    let bytes = source.as_bytes();
    for cursor in (0..position).rev() {
        if code.get(cursor) != Some(&true) {
            continue;
        }
        match bytes[cursor] {
            b'>' => return false,
            b'<' => {
                let next = skip_ascii_whitespace(bytes, cursor + 1);
                return next < position
                    && !matches!(bytes.get(next), Some(b'/') | Some(b'!') | Some(b'?'));
            }
            _ => {}
        }
    }
    false
}

fn ecmascript_brace_spans(source: &str, code: &[bool]) -> Vec<(usize, usize)> {
    let mut stack = Vec::new();
    let mut spans = Vec::new();
    for (position, byte) in source.bytes().enumerate() {
        if code.get(position) != Some(&true) {
            continue;
        }
        if byte == b'{' {
            stack.push(position);
        } else if byte == b'}'
            && let Some(open) = stack.pop()
        {
            spans.push((open, position));
        }
    }
    spans
}

fn innermost_enclosing_brace(spans: &[(usize, usize)], position: usize) -> Option<usize> {
    spans
        .iter()
        .filter(|(open, close)| *open < position && position < *close)
        .map(|(open, _)| *open)
        .max()
}

fn extract_css(path: &Path) -> Result<ExtractedDocument, ExtractError> {
    let mut extracted = extract_text_file(path, "text/css", "gtkg-css-static/v1")?;
    extracted.observed_facts = css_facts(&extracted.text);
    extracted.observations.insert(
        "observed_fact_count".to_owned(),
        extracted.observed_facts.len().to_string(),
    );
    Ok(extracted)
}

fn css_facts(source: &str) -> Vec<ObservedStaticFact> {
    let mut facts = Vec::new();
    let bytes = source.as_bytes();
    let code = lexical_code_mask(source, false, false);
    let mut cursor = 0;
    while let Some(open) = find_active_byte(bytes, &code, cursor, b'{') {
        let selector_start =
            last_active_byte(bytes, &code, open, b'}').map_or(0, |index| index.saturating_add(1));
        let Some(close) = find_active_byte(bytes, &code, open + 1, b'}') else {
            break;
        };
        if (contains_active(source, &code, open + 1, close, "display: grid")
            || contains_active(source, &code, open + 1, close, "display:grid")
            || contains_active(source, &code, open + 1, close, "grid-template"))
            && let Some(dot) = find_active_byte(bytes, &code, selector_start, b'.')
            && dot < open
        {
            let marker_start = dot + 1;
            let marker_len = bytes[marker_start..open]
                .iter()
                .take_while(|byte| is_marker_byte(**byte))
                .count();
            if marker_len > 0
                && code[marker_start..marker_start + marker_len]
                    .iter()
                    .all(|active| *active)
            {
                push_fact(
                    source,
                    "layout",
                    marker_start,
                    marker_start + marker_len,
                    &mut facts,
                );
            }
        }
        cursor = close.saturating_add(1);
    }

    let mut cursor = 0;
    while let Some(relative) = source[cursor..].find("--") {
        let start = cursor + relative + 2;
        let length = bytes[start..]
            .iter()
            .take_while(|byte| is_marker_byte(**byte))
            .count();
        if code.get(start.saturating_sub(2)) == Some(&true)
            && code.get(start.saturating_sub(1)) == Some(&true)
            && length > 0
            && code[start..start + length].iter().all(|active| *active)
            && bytes.get(start + length) == Some(&b':')
            && code.get(start + length) == Some(&true)
        {
            push_fact(source, "style_token", start, start + length, &mut facts);
        }
        cursor = start.saturating_add(length.max(1));
    }
    normalize_facts(facts)
}

fn find_active_byte(bytes: &[u8], code: &[bool], start: usize, target: u8) -> Option<usize> {
    bytes
        .iter()
        .enumerate()
        .skip(start)
        .find_map(|(position, byte)| {
            (*byte == target && code.get(position) == Some(&true)).then_some(position)
        })
}

fn last_active_byte(bytes: &[u8], code: &[bool], end: usize, target: u8) -> Option<usize> {
    (0..end)
        .rev()
        .find(|position| bytes[*position] == target && code.get(*position) == Some(&true))
}

fn contains_active(source: &str, code: &[bool], start: usize, end: usize, needle: &str) -> bool {
    let mut cursor = start;
    while cursor < end {
        let Some(relative) = source[cursor..end].find(needle) else {
            return false;
        };
        let position = cursor + relative;
        let after = position + needle.len();
        if code[position..after].iter().all(|active| *active) {
            return true;
        }
        cursor = position.saturating_add(needle.len().max(1));
    }
    false
}

const MAX_STRUCTURE_KEY_PATHS: usize = 512;
const MAX_STRUCTURE_DEPTH: usize = 32;

fn extract_toml_like(
    path: &Path,
    media_type: &str,
    extractor_id: &str,
) -> Result<ExtractedDocument, ExtractError> {
    let mut extracted = extract_text_file(path, media_type, extractor_id)?;
    extracted.observed_facts = toml_facts(&extracted.text);
    extracted
        .observations
        .insert("structure_mode".to_owned(), "lexical_toml".to_owned());
    extracted.observations.insert(
        "observed_fact_count".to_owned(),
        extracted.observed_facts.len().to_string(),
    );
    Ok(extracted)
}

/// Lexical TOML evidence: `[section]` headers and bare `key = value` keys. No TOML
/// parser is involved; malformed input simply yields fewer facts, never an error.
fn toml_facts(source: &str) -> Vec<ObservedStaticFact> {
    let mut facts = Vec::new();
    let mut offset = 0_usize;
    for line in source.split_inclusive('\n') {
        let content = line.trim_end_matches(['\r', '\n']);
        let leading = content.len() - content.trim_start().len();
        let trimmed = content.trim_start();
        if !trimmed.is_empty() && !trimmed.starts_with('#') {
            if trimmed.starts_with('[') {
                let inner = trimmed
                    .trim_start_matches('[')
                    .split(']')
                    .next()
                    .unwrap_or("")
                    .trim();
                if !inner.is_empty()
                    && inner.bytes().all(is_marker_byte)
                    && let Some(relative) = trimmed.find(inner)
                {
                    let start = offset + leading + relative;
                    push_fact(
                        source,
                        "toml_section",
                        start,
                        start + inner.len(),
                        &mut facts,
                    );
                }
            } else if let Some(equals) = trimmed.find('=') {
                let key = trimmed[..equals].trim();
                if !key.is_empty()
                    && key.bytes().all(is_marker_byte)
                    && let Some(relative) = trimmed.find(key)
                {
                    let start = offset + leading + relative;
                    push_fact(source, "toml_key", start, start + key.len(), &mut facts);
                }
            }
        }
        offset = offset.saturating_add(line.len());
    }
    normalize_facts(facts)
}

fn extract_json(path: &Path) -> Result<ExtractedDocument, ExtractError> {
    let bytes = fs::read(path).map_err(|source| ExtractError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let text = String::from_utf8(bytes.clone())
        .map_err(|_| ExtractError::InvalidUtf8(path.to_path_buf()))?;
    let observed_facts = json_key_facts(&text);
    let mut observations = BTreeMap::from([
        ("mode".to_owned(), "static".to_owned()),
        ("target_process_count".to_owned(), "0".to_owned()),
        (
            "observed_fact_count".to_owned(),
            observed_facts.len().to_string(),
        ),
    ]);
    match serde_json::from_str::<serde_json::Value>(&text) {
        Ok(value) => {
            observations.insert("structure_mode".to_owned(), "parsed_json".to_owned());
            observations.insert(
                "json_top_level_shape".to_owned(),
                json_shape(&value).to_owned(),
            );
            let mut key_paths = std::collections::BTreeSet::new();
            collect_json_key_paths(&value, "", 0, &mut key_paths);
            observations.insert(
                "json_key_paths".to_owned(),
                key_paths.into_iter().collect::<Vec<_>>().join("\n"),
            );
            observations.insert(
                "json_node_count".to_owned(),
                json_node_count(&value, 0).to_string(),
            );
        }
        Err(_) => {
            observations.insert("structure_mode".to_owned(), "fallback_text".to_owned());
        }
    }
    Ok(ExtractedDocument {
        source_sha256: digest_bytes(&bytes),
        media_type: "application/json".to_owned(),
        extractor_id: "gtkg-json-static/v1".to_owned(),
        text,
        observations,
        observed_facts,
        target_process_count: 0,
        executed_target_content: false,
    })
}

fn json_shape(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Object(_) => "object",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::Bool(_) => "boolean",
        serde_json::Value::Null => "null",
    }
}

fn collect_json_key_paths(
    value: &serde_json::Value,
    prefix: &str,
    depth: usize,
    paths: &mut std::collections::BTreeSet<String>,
) {
    if paths.len() >= MAX_STRUCTURE_KEY_PATHS || depth >= MAX_STRUCTURE_DEPTH {
        return;
    }
    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map {
                let path = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{prefix}.{key}")
                };
                paths.insert(path.clone());
                collect_json_key_paths(child, &path, depth.saturating_add(1), paths);
            }
        }
        serde_json::Value::Array(items) => {
            let path = format!("{prefix}[]");
            for child in items {
                collect_json_key_paths(child, &path, depth.saturating_add(1), paths);
            }
        }
        _ => {}
    }
}

fn json_node_count(value: &serde_json::Value, depth: usize) -> u64 {
    if depth >= MAX_STRUCTURE_DEPTH {
        return 1;
    }
    let children: u64 = match value {
        serde_json::Value::Object(map) => map
            .values()
            .map(|child| json_node_count(child, depth.saturating_add(1)))
            .sum(),
        serde_json::Value::Array(items) => items
            .iter()
            .map(|child| json_node_count(child, depth.saturating_add(1)))
            .sum(),
        _ => 0,
    };
    children.saturating_add(1)
}

/// Lexical JSON key evidence: a string literal directly followed by `:` is an
/// object key. String contents are skipped, so markers never select string data.
fn json_key_facts(source: &str) -> Vec<ObservedStaticFact> {
    let bytes = source.as_bytes();
    let mut facts = Vec::new();
    let mut cursor = 0_usize;
    while cursor < bytes.len() {
        if bytes[cursor] == b'"' {
            let start = cursor.saturating_add(1);
            let mut end = start;
            while end < bytes.len() {
                if bytes[end] == b'\\' {
                    end = end.saturating_add(2).min(bytes.len());
                } else if bytes[end] == b'"' {
                    break;
                } else {
                    end = end.saturating_add(1);
                }
            }
            if end < bytes.len() {
                let next = skip_ascii_whitespace(bytes, end.saturating_add(1));
                if bytes.get(next) == Some(&b':') {
                    push_fact(source, "json_key", start, end, &mut facts);
                }
                cursor = end.saturating_add(1);
            } else {
                cursor = bytes.len();
            }
        } else {
            cursor = cursor.saturating_add(1);
        }
    }
    normalize_facts(facts)
}

fn extract_yaml(path: &Path) -> Result<ExtractedDocument, ExtractError> {
    let bytes = fs::read(path).map_err(|source| ExtractError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let text = String::from_utf8(bytes.clone())
        .map_err(|_| ExtractError::InvalidUtf8(path.to_path_buf()))?;
    let observed_facts = yaml_key_facts(&text);
    let mut observations = BTreeMap::from([
        ("mode".to_owned(), "static".to_owned()),
        ("target_process_count".to_owned(), "0".to_owned()),
        (
            "observed_fact_count".to_owned(),
            observed_facts.len().to_string(),
        ),
    ]);
    match serde_yaml::from_str::<serde_yaml::Value>(&text) {
        Ok(value) => {
            observations.insert("structure_mode".to_owned(), "parsed_yaml".to_owned());
            observations.insert(
                "yaml_top_level_shape".to_owned(),
                yaml_shape(&value).to_owned(),
            );
            let mut key_paths = std::collections::BTreeSet::new();
            collect_yaml_key_paths(&value, "", 0, &mut key_paths);
            observations.insert(
                "yaml_key_paths".to_owned(),
                key_paths.into_iter().collect::<Vec<_>>().join("\n"),
            );
        }
        Err(_) => {
            observations.insert("structure_mode".to_owned(), "fallback_text".to_owned());
        }
    }
    Ok(ExtractedDocument {
        source_sha256: digest_bytes(&bytes),
        media_type: "application/yaml".to_owned(),
        extractor_id: "gtkg-yaml-static/v1".to_owned(),
        text,
        observations,
        observed_facts,
        target_process_count: 0,
        executed_target_content: false,
    })
}

fn yaml_shape(value: &serde_yaml::Value) -> &'static str {
    match value {
        serde_yaml::Value::Mapping(_) => "mapping",
        serde_yaml::Value::Sequence(_) => "sequence",
        serde_yaml::Value::String(_) => "string",
        serde_yaml::Value::Number(_) => "number",
        serde_yaml::Value::Bool(_) => "boolean",
        serde_yaml::Value::Null => "null",
        serde_yaml::Value::Tagged(_) => "tagged",
    }
}

fn collect_yaml_key_paths(
    value: &serde_yaml::Value,
    prefix: &str,
    depth: usize,
    paths: &mut std::collections::BTreeSet<String>,
) {
    if paths.len() >= MAX_STRUCTURE_KEY_PATHS || depth >= MAX_STRUCTURE_DEPTH {
        return;
    }
    match value {
        serde_yaml::Value::Mapping(map) => {
            for (key, child) in map {
                let Some(key) = key.as_str() else {
                    continue;
                };
                let path = if prefix.is_empty() {
                    key.to_owned()
                } else {
                    format!("{prefix}.{key}")
                };
                paths.insert(path.clone());
                collect_yaml_key_paths(child, &path, depth.saturating_add(1), paths);
            }
        }
        serde_yaml::Value::Sequence(items) => {
            let path = format!("{prefix}[]");
            for child in items {
                collect_yaml_key_paths(child, &path, depth.saturating_add(1), paths);
            }
        }
        _ => {}
    }
}

/// Lexical YAML key evidence: line-initial bare keys followed by `: `. Comments,
/// document markers, and sequence items are skipped.
fn yaml_key_facts(source: &str) -> Vec<ObservedStaticFact> {
    let mut facts = Vec::new();
    let mut offset = 0_usize;
    for line in source.split_inclusive('\n') {
        let content = line.trim_end_matches(['\r', '\n']);
        let leading = content.len() - content.trim_start().len();
        let trimmed = content.trim_start();
        if !trimmed.is_empty()
            && !trimmed.starts_with('#')
            && !trimmed.starts_with("- ")
            && trimmed != "---"
            && trimmed != "..."
            && let Some(colon) = trimmed.find(':')
        {
            let follows = trimmed[colon..].chars().nth(1);
            let key = trimmed[..colon].trim();
            if matches!(follows, None | Some(' ') | Some('\t'))
                && !key.is_empty()
                && key.bytes().all(is_marker_byte)
            {
                let start = offset + leading;
                push_fact(source, "yaml_key", start, start + key.len(), &mut facts);
            }
        }
        offset = offset.saturating_add(line.len());
    }
    normalize_facts(facts)
}

fn extract_shell(path: &Path) -> Result<ExtractedDocument, ExtractError> {
    let mut extracted = extract_text_file(path, "text/x-shellscript", "gtkg-shell-static/v1")?;
    let (facts, shebang) = shell_facts(&extracted.text);
    extracted.observed_facts = facts;
    extracted
        .observations
        .insert("structure_mode".to_owned(), "lexical_shell".to_owned());
    if let Some(shebang) = shebang {
        extracted.observations.insert("shebang".to_owned(), shebang);
    }
    extracted.observations.insert(
        "observed_fact_count".to_owned(),
        extracted.observed_facts.len().to_string(),
    );
    Ok(extracted)
}

const SHELL_KEYWORDS: [&str; 20] = [
    "if", "then", "else", "elif", "fi", "for", "while", "until", "do", "done", "case", "esac",
    "function", "select", "in", "time", "coproc", "{", "}", "!",
];

/// Lexical shell evidence: shebang, `name()`/`function name` definitions, and the
/// leading command word of executable lines. Assignments and keywords are skipped.
fn shell_facts(source: &str) -> (Vec<ObservedStaticFact>, Option<String>) {
    let mut facts = Vec::new();
    let mut shebang = None;
    let mut offset = 0_usize;
    for (index, line) in source.split_inclusive('\n').enumerate() {
        let content = line.trim_end_matches(['\r', '\n']);
        let leading = content.len() - content.trim_start().len();
        let trimmed = content.trim_start();
        if index == 0 && trimmed.starts_with("#!") {
            shebang = Some(trimmed.to_owned());
        }
        if !trimmed.is_empty() && !trimmed.starts_with('#') {
            let function_name = if let Some(rest) = trimmed.strip_prefix("function ") {
                rest.split(|character: char| character.is_ascii_whitespace() || character == '(')
                    .next()
            } else {
                trimmed.find("()").map(|parens| trimmed[..parens].trim())
            };
            if let Some(name) = function_name
                && !name.is_empty()
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
                && let Some(relative) = trimmed.find(name)
            {
                let start = offset + leading + relative;
                push_fact(
                    source,
                    "shell_function",
                    start,
                    start + name.len(),
                    &mut facts,
                );
            }
            if let Some(word) = trimmed.split_whitespace().next()
                && word.bytes().all(is_marker_byte)
                && !word.contains('=')
                && !SHELL_KEYWORDS.contains(&word)
            {
                let start = offset + leading;
                push_fact(
                    source,
                    "shell_command",
                    start,
                    start + word.len(),
                    &mut facts,
                );
            }
        }
        offset = offset.saturating_add(line.len());
    }
    (normalize_facts(facts), shebang)
}

fn extract_html(path: &Path) -> Result<ExtractedDocument, ExtractError> {
    let bytes = fs::read(path).map_err(|source| ExtractError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let text = String::from_utf8(bytes.clone())
        .map_err(|_| ExtractError::InvalidUtf8(path.to_path_buf()))?;
    let lower = text.to_ascii_lowercase();
    let mut facts = Vec::new();
    if let Some(open) = lower.find("<title")
        && let Some(close_tag) = lower[open..].find('>')
    {
        let content_start = open + close_tag + 1;
        if let Some(close) = lower[content_start..].find("</title") {
            let inner = &text[content_start..content_start + close];
            let trimmed = inner.trim();
            if !trimmed.is_empty() {
                let start = content_start + (inner.len() - inner.trim_start().len());
                push_fact(
                    &text,
                    "html_title",
                    start,
                    start + trimmed.len(),
                    &mut facts,
                );
            }
        }
    }
    let mut cursor = 0_usize;
    while let Some(relative) = lower[cursor..].find("id=") {
        let position = cursor + relative;
        let preceded = position == 0
            || lower
                .as_bytes()
                .get(position.wrapping_sub(1))
                .is_some_and(u8::is_ascii_whitespace);
        if preceded && let Some((start, end)) = quoted_literal_span(&text, position + 3) {
            push_fact(&text, "html_id", start, end, &mut facts);
        }
        cursor = position.saturating_add(3);
    }
    let observed_facts = normalize_facts(facts);
    let visible = html_visible_text(&lower, &text);
    let text = if visible.trim().is_empty() {
        text
    } else {
        visible
    };
    Ok(ExtractedDocument {
        source_sha256: digest_bytes(&bytes),
        media_type: "text/html".to_owned(),
        extractor_id: "gtkg-html-static/v1".to_owned(),
        text,
        observations: BTreeMap::from([
            ("mode".to_owned(), "static".to_owned()),
            ("structure_mode".to_owned(), "lexical_html".to_owned()),
            ("target_process_count".to_owned(), "0".to_owned()),
            (
                "observed_fact_count".to_owned(),
                observed_facts.len().to_string(),
            ),
        ]),
        observed_facts,
        target_process_count: 0,
        executed_target_content: false,
    })
}

/// Static tag stripping: markup, `<script>`, and `<style>` bodies are dropped and
/// the remaining visible text is kept as data. Nothing is ever executed.
fn html_visible_text(lower: &str, source: &str) -> String {
    let bytes = lower.as_bytes();
    let mut parts = Vec::new();
    let mut cursor = 0_usize;
    while cursor < bytes.len() {
        if bytes[cursor] == b'<' {
            if lower[cursor..].starts_with("<script") || lower[cursor..].starts_with("<style") {
                let tag_end = lower[cursor..]
                    .find('>')
                    .map_or(bytes.len(), |relative| cursor + relative + 1);
                let closing = if lower[cursor..].starts_with("<script") {
                    "</script"
                } else {
                    "</style"
                };
                cursor = lower[tag_end..]
                    .find(closing)
                    .and_then(|relative| {
                        lower[tag_end + relative..]
                            .find('>')
                            .map(|gt| tag_end + relative + gt + 1)
                    })
                    .unwrap_or(bytes.len());
                continue;
            }
            cursor = lower[cursor..]
                .find('>')
                .map_or(bytes.len(), |relative| cursor + relative + 1);
            continue;
        }
        let end = lower[cursor..]
            .find('<')
            .map_or(bytes.len(), |relative| cursor + relative);
        let chunk = source[cursor..end].trim();
        if !chunk.is_empty() {
            parts.push(chunk.to_owned());
        }
        cursor = end;
    }
    parts.join("\n")
}

fn extract_svg(path: &Path) -> Result<ExtractedDocument, ExtractError> {
    let bytes = fs::read(path).map_err(|source| ExtractError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let text = String::from_utf8(bytes.clone())
        .map_err(|_| ExtractError::InvalidUtf8(path.to_path_buf()))?;
    validate_passive_svg(path, &text)?;
    let observed_facts = svg_facts(&text);
    Ok(ExtractedDocument {
        source_sha256: digest_bytes(&bytes),
        media_type: "image/svg+xml".to_owned(),
        extractor_id: "gtkg-svg-static/v1".to_owned(),
        text,
        observations: BTreeMap::from([
            ("mode".to_owned(), "static".to_owned()),
            ("target_process_count".to_owned(), "0".to_owned()),
            (
                "observed_fact_count".to_owned(),
                observed_facts.len().to_string(),
            ),
        ]),
        observed_facts,
        target_process_count: 0,
        executed_target_content: false,
    })
}

fn validate_passive_svg(path: &Path, source: &str) -> Result<(), ExtractError> {
    let mut reader = Reader::from_str(source);
    reader.config_mut().trim_text(false);
    let mut depth = 0_usize;
    let mut events = 0_usize;
    loop {
        events = events.saturating_add(1);
        if events > MAX_SVG_EVENTS || depth > MAX_SVG_DEPTH {
            return Err(ExtractError::SvgBudget(path.to_path_buf()));
        }
        match reader.read_event() {
            Ok(Event::Start(event)) => {
                validate_svg_element(path, &event)?;
                depth = depth.saturating_add(1);
            }
            Ok(Event::Empty(event)) => validate_svg_element(path, &event)?,
            Ok(Event::End(_)) => depth = depth.saturating_sub(1),
            Ok(Event::DocType(_)) => return Err(ExtractError::UnsafeSvg(path.to_path_buf())),
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(error) => {
                return Err(ExtractError::InvalidSvg {
                    path: path.to_path_buf(),
                    message: error.to_string(),
                });
            }
        }
    }
    Ok(())
}

fn validate_svg_element(path: &Path, event: &BytesStart<'_>) -> Result<(), ExtractError> {
    let event_name = event.name();
    let name = String::from_utf8_lossy(event_name.as_ref()).to_ascii_lowercase();
    if matches!(name.as_str(), "script" | "foreignobject") {
        return Err(ExtractError::UnsafeSvg(path.to_path_buf()));
    }
    for attribute in event.attributes().with_checks(true) {
        let attribute = attribute.map_err(|error| ExtractError::InvalidSvg {
            path: path.to_path_buf(),
            message: error.to_string(),
        })?;
        let key = String::from_utf8_lossy(attribute.key.as_ref()).to_ascii_lowercase();
        let value = String::from_utf8_lossy(attribute.value.as_ref())
            .trim()
            .to_ascii_lowercase();
        if key.starts_with("on")
            || ((key == "href" || key.ends_with(":href"))
                && (value.starts_with("http:")
                    || value.starts_with("https:")
                    || value.starts_with("javascript:")
                    || value.starts_with("data:text/html")))
        {
            return Err(ExtractError::UnsafeSvg(path.to_path_buf()));
        }
    }
    Ok(())
}

fn svg_facts(source: &str) -> Vec<ObservedStaticFact> {
    let mut facts = Vec::new();
    for tag in ["symbol", "svg"] {
        let mut cursor = 0;
        let opener = format!("<{tag}");
        while let Some(relative) = source[cursor..].find(&opener) {
            let start = cursor + relative;
            let Some(end_relative) = source[start..].find('>') else {
                break;
            };
            let end = start + end_relative;
            let tag_source = &source[start..end];
            if let Some(id_relative) = tag_source.find("id=\"") {
                let marker_start = start + id_relative + "id=\"".len();
                if let Some(length) = source[marker_start..].find('"') {
                    push_fact(
                        source,
                        "asset",
                        marker_start,
                        marker_start + length,
                        &mut facts,
                    );
                }
            }
            cursor = end.saturating_add(1);
        }
    }
    normalize_facts(facts)
}

fn markdown_facts(source: &str) -> Vec<ObservedStaticFact> {
    let mut facts = Vec::new();
    let mut lines = source.split_inclusive('\n');
    let Some(first_line) = lines.next() else {
        return facts;
    };
    if first_line.trim_end_matches(['\r', '\n']) != "---" {
        return facts;
    }

    let mut offset = first_line.len();
    for line in lines {
        let content = line.trim_end_matches(['\r', '\n']);
        if content.trim() == "---" {
            break;
        }
        let trimmed = line.trim_start();
        if let Some(value) = trimmed.strip_prefix("evidence_ref:") {
            let value_leading = value.len() - value.trim_start().len();
            let value_start =
                offset + (line.len() - trimmed.len()) + "evidence_ref:".len() + value_leading;
            if let Some((start, end)) = yaml_scalar_span(source, value_start) {
                push_fact(source, "evidence_ref", start, end, &mut facts);
            }
        }
        offset = offset.saturating_add(line.len());
    }
    normalize_facts(facts)
}

fn yaml_scalar_span(source: &str, start: usize) -> Option<(usize, usize)> {
    let bytes = source.as_bytes();
    let first = *bytes.get(start)?;
    if first == b'\'' || first == b'"' {
        let (marker_start, marker_end) = quoted_literal_span(source, start)?;
        return (marker_start < marker_end).then_some((marker_start, marker_end));
    }
    let end = bytes[start..]
        .iter()
        .position(|byte| byte.is_ascii_whitespace() || *byte == b'#')
        .map_or(bytes.len(), |relative| start + relative);
    (start < end && !matches!(first, b'|' | b'>')).then_some((start, end))
}

fn push_fact(
    source: &str,
    kind: &str,
    start: usize,
    end: usize,
    facts: &mut Vec<ObservedStaticFact>,
) {
    if start >= end
        || end > source.len()
        || !source.is_char_boundary(start)
        || !source.is_char_boundary(end)
    {
        return;
    }
    let marker = &source[start..end];
    if marker.len() > 256
        || marker.is_empty()
        || marker.chars().any(|character| character.is_control())
    {
        return;
    }
    facts.push(ObservedStaticFact {
        kind: kind.to_owned(),
        marker_id: marker.to_owned(),
        span: SourceByteSpan {
            start: start as u64,
            end: end as u64,
        },
        evidence_level: "observed_static".to_owned(),
    });
}

fn normalize_facts(mut facts: Vec<ObservedStaticFact>) -> Vec<ObservedStaticFact> {
    facts.sort();
    facts.dedup();
    facts
}

fn is_marker_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')
}

fn static_symbols(source: &str, language: CodeLanguage) -> std::collections::BTreeSet<String> {
    let mut symbols = std::collections::BTreeSet::new();
    for raw_line in source.lines() {
        let line = raw_line.trim_start();
        if line.is_empty()
            || line.starts_with("//")
            || line.starts_with('#')
            || line.starts_with("/*")
            || line.starts_with('*')
        {
            continue;
        }
        match language {
            CodeLanguage::Rust => scan_rust_declaration(line, &mut symbols),
            CodeLanguage::Python => scan_python_declaration(line, &mut symbols),
            CodeLanguage::TypeScript | CodeLanguage::JavaScript => {
                scan_ecmascript_declaration(line, &mut symbols)
            }
        }
    }
    symbols
}

fn scan_rust_declaration(line: &str, symbols: &mut std::collections::BTreeSet<String>) {
    let line = strip_rust_visibility(line);
    for (prefix, kind) in [
        ("async fn ", "function"),
        ("const fn ", "function"),
        ("unsafe fn ", "function"),
        ("fn ", "function"),
        ("struct ", "struct"),
        ("enum ", "enum"),
        ("trait ", "trait"),
        ("mod ", "module"),
        ("type ", "type"),
    ] {
        if let Some(remainder) = line.strip_prefix(prefix)
            && let Some(name) = declaration_name(remainder)
        {
            symbols.insert(format!("{kind}:{name}"));
            return;
        }
    }
}

fn strip_rust_visibility(line: &str) -> &str {
    if let Some(remainder) = line.strip_prefix("pub ") {
        return remainder;
    }
    if let Some(remainder) = line.strip_prefix("pub(")
        && let Some((_, tail)) = remainder.split_once(") ")
    {
        return tail;
    }
    line
}

fn scan_python_declaration(line: &str, symbols: &mut std::collections::BTreeSet<String>) {
    for (prefix, kind) in [
        ("async def ", "function"),
        ("def ", "function"),
        ("class ", "class"),
    ] {
        if let Some(remainder) = line.strip_prefix(prefix)
            && let Some(name) = declaration_name(remainder)
        {
            symbols.insert(format!("{kind}:{name}"));
            return;
        }
    }
}

fn scan_ecmascript_declaration(line: &str, symbols: &mut std::collections::BTreeSet<String>) {
    let mut line = line;
    for prefix in ["export default ", "export ", "declare "] {
        if let Some(remainder) = line.strip_prefix(prefix) {
            line = remainder;
        }
    }
    for (prefix, kind) in [
        ("async function ", "function"),
        ("function ", "function"),
        ("class ", "class"),
        ("interface ", "interface"),
        ("type ", "type"),
        ("enum ", "enum"),
    ] {
        if let Some(remainder) = line.strip_prefix(prefix)
            && let Some(name) = declaration_name(remainder)
        {
            symbols.insert(format!("{kind}:{name}"));
            return;
        }
    }
    for prefix in ["const ", "let ", "var "] {
        if let Some(remainder) = line.strip_prefix(prefix)
            && let Some(name) = declaration_name(remainder)
        {
            symbols.insert(format!("binding:{name}"));
            return;
        }
    }
}

fn declaration_name(value: &str) -> Option<&str> {
    let end = value
        .char_indices()
        .find_map(|(index, character)| {
            (!(character == '_' || character == '$' || character.is_alphanumeric()))
                .then_some(index)
        })
        .unwrap_or(value.len());
    let name = &value[..end];
    (!name.is_empty()).then_some(name)
}

fn extract_pdf(path: &Path) -> Result<ExtractedDocument, ExtractError> {
    let bytes = fs::read(path).map_err(|source| ExtractError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if !bytes.starts_with(b"%PDF-") {
        return Err(ExtractError::InvalidPdf {
            path: path.to_path_buf(),
            message: "missing PDF header".to_owned(),
        });
    }
    let document = Document::load(path).map_err(|error| ExtractError::InvalidPdf {
        path: path.to_path_buf(),
        message: error.to_string(),
    })?;
    if document.is_encrypted() {
        return Err(ExtractError::InvalidPdf {
            path: path.to_path_buf(),
            message: "encrypted PDFs are not processed".to_owned(),
        });
    }
    let pages: Vec<u32> = document.get_pages().keys().copied().collect();
    let text = document
        .extract_text(&pages)
        .map_err(|error| ExtractError::InvalidPdf {
            path: path.to_path_buf(),
            message: error.to_string(),
        })?;
    if text.trim().is_empty() {
        return Err(ExtractError::NeedsOcr(path.to_path_buf()));
    }
    Ok(ExtractedDocument {
        source_sha256: digest_bytes(&bytes),
        media_type: "application/pdf".to_owned(),
        extractor_id: "gtkg-pdf-static/v1".to_owned(),
        text,
        observations: BTreeMap::from([
            ("mode".to_owned(), "static".to_owned()),
            ("page_count".to_owned(), pages.len().to_string()),
            ("target_process_count".to_owned(), "0".to_owned()),
        ]),
        observed_facts: Vec::new(),
        target_process_count: 0,
        executed_target_content: false,
    })
}

fn extract_openxml(path: &Path, extension: &str) -> Result<ExtractedDocument, ExtractError> {
    let bytes = fs::read(path).map_err(|source| ExtractError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let file = fs::File::open(path).map_err(|source| ExtractError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let mut archive = ZipArchive::new(file).map_err(|error| ExtractError::InvalidOpenXml {
        path: path.to_path_buf(),
        message: error.to_string(),
    })?;
    if archive.len() > MAX_ARCHIVE_ENTRIES {
        return Err(ExtractError::ArchiveBudget(path.to_path_buf()));
    }
    let mut total_uncompressed = 0_u64;
    let mut parts = Vec::new();
    for index in 0..archive.len() {
        let mut member = archive
            .by_index(index)
            .map_err(|error| ExtractError::InvalidOpenXml {
                path: path.to_path_buf(),
                message: error.to_string(),
            })?;
        total_uncompressed = total_uncompressed.saturating_add(member.size());
        if total_uncompressed > MAX_ARCHIVE_UNCOMPRESSED_BYTES
            || member.size() > MAX_SOURCE_BYTES
            || (member.compressed_size() > 0
                && member.size() / member.compressed_size().max(1) > 1_000)
        {
            return Err(ExtractError::ArchiveBudget(path.to_path_buf()));
        }
        let name = member.name().to_owned();
        if !selected_openxml_member(extension, &name) {
            continue;
        }
        let mut xml = String::new();
        member
            .read_to_string(&mut xml)
            .map_err(|source| ExtractError::Io {
                path: path.to_path_buf(),
                source,
            })?;
        let text = extract_xml_text(path, &xml)?;
        if !text.is_empty() {
            parts.push((name, text));
        }
    }
    parts.sort_by(|left, right| left.0.cmp(&right.0));
    if parts.is_empty() {
        return Err(ExtractError::InvalidOpenXml {
            path: path.to_path_buf(),
            message: "package has no supported textual parts".to_owned(),
        });
    }
    let text = parts
        .iter()
        .map(|(name, text)| format!("[{name}]\n{text}"))
        .collect::<Vec<_>>()
        .join("\n\n");
    let media_type = match extension {
        "docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "pptx" => "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        _ => "application/zip",
    };
    Ok(ExtractedDocument {
        source_sha256: digest_bytes(&bytes),
        media_type: media_type.to_owned(),
        extractor_id: format!("gtkg-openxml-{extension}/v1"),
        text,
        observations: BTreeMap::from([
            ("mode".to_owned(), "static".to_owned()),
            ("selected_part_count".to_owned(), parts.len().to_string()),
            ("target_process_count".to_owned(), "0".to_owned()),
        ]),
        observed_facts: Vec::new(),
        target_process_count: 0,
        executed_target_content: false,
    })
}

fn selected_openxml_member(extension: &str, name: &str) -> bool {
    if !name.ends_with(".xml") || name.contains("../") || name.starts_with('/') {
        return false;
    }
    match extension {
        "docx" => {
            name == "word/document.xml"
                || name.starts_with("word/header")
                || name.starts_with("word/footer")
                || name == "word/footnotes.xml"
        }
        "xlsx" => {
            name == "xl/sharedStrings.xml"
                || name.starts_with("xl/worksheets/")
                || name == "xl/workbook.xml"
        }
        "pptx" => name.starts_with("ppt/slides/") || name.starts_with("ppt/notesSlides/"),
        _ => false,
    }
}

fn extract_xml_text(path: &Path, xml: &str) -> Result<String, ExtractError> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut text = Vec::new();
    loop {
        match reader.read_event() {
            Ok(Event::Text(value)) => {
                let decoded = value
                    .decode()
                    .map_err(|error| ExtractError::InvalidOpenXml {
                        path: path.to_path_buf(),
                        message: error.to_string(),
                    })?;
                if !decoded.trim().is_empty() {
                    text.push(decoded.into_owned());
                }
            }
            Ok(Event::CData(value)) => {
                let decoded = value
                    .decode()
                    .map_err(|error| ExtractError::InvalidOpenXml {
                        path: path.to_path_buf(),
                        message: error.to_string(),
                    })?;
                if !decoded.trim().is_empty() {
                    text.push(decoded.into_owned());
                }
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(error) => {
                return Err(ExtractError::InvalidOpenXml {
                    path: path.to_path_buf(),
                    message: error.to_string(),
                });
            }
        }
    }
    Ok(text.join("\n"))
}

fn digest_bytes(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}
