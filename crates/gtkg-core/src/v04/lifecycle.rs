//! Successor package and read-only legacy migration contracts.
//! Packages contain only replayed artifacts; legacy inspection never upgrades facts.
use super::{analysis, artifact, authoring, graph_projection, index, query, source};
use crate::CallContext;
use crate::exact_read::read_bound_regular_file;
use gtkg_protocol::FileReceiptRef;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PipelineIdentity {
    pub profile: String,
    pub snapshot_id: String,
    pub source_commit: String,
    pub source_tree: String,
    pub source_ledger_sha256: String,
    pub source_policy_sha256: String,
    pub extractor_profile: String,
    pub parser_identities: BTreeMap<String, String>,
    pub resolver_profile: String,
    pub verifier_profile: String,
    pub analysis_context_digest: String,
    pub chunker: String,
    pub tokenizer: String,
    pub query_policy: String,
    pub accepted_digests: Vec<String>,
    pub views_digest: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleLocator {
    pub workspace_root: PathBuf,
    /// Relative to this package's workspace root, never the original workspace.
    pub manifest_ref: FileReceiptRef,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalizeRequest {
    pub verified_ref: FileReceiptRef,
    pub accepted_refs: Vec<FileReceiptRef>,
    pub views_ref: FileReceiptRef,
    pub output_path: PathBuf,
    pub predecessor: Option<BundleLocator>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleFile {
    pub reference: FileReceiptRef,
    pub bytes: u64,
    pub role: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleManifest {
    pub schema: String,
    pub identity: PipelineIdentity,
    pub verified_ref: FileReceiptRef,
    pub source_ref: FileReceiptRef,
    pub index_ref: FileReceiptRef,
    pub accepted_refs: Vec<FileReceiptRef>,
    pub views_ref: FileReceiptRef,
    pub canonical_okf_refs: Vec<FileReceiptRef>,
    pub files: Vec<BundleFile>,
    pub indexes_rebuildable: bool,
    pub knowledge_ready: bool,
    pub llm_qa_validated: bool,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildDelta {
    pub added_paths: Vec<String>,
    pub changed_paths: Vec<String>,
    pub deleted_paths: Vec<String>,
    pub retained_paths: Vec<String>,
    pub invalidated_dependencies: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleResult {
    pub bundle: BundleLocator,
    pub manifest: BundleManifest,
    pub delta: BuildDelta,
    pub authority_exported: bool,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleVerification {
    pub manifest: BundleManifest,
    pub verified_files: usize,
    pub status: String,
    pub authority_required_for_read_verification: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationRequest {
    pub legacy_root: PathBuf,
    pub legacy_manifest_ref: FileReceiptRef,
    pub source_ref: Option<FileReceiptRef>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationLedger {
    pub schema: String,
    pub legacy_manifest_ref: FileReceiptRef,
    pub legacy_tree_digest: String,
    pub preserved_files: Vec<BundleFile>,
    pub relationship_status: String,
    pub source_ref: Option<FileReceiptRef>,
    pub gaps: Vec<String>,
    pub successor_created: bool,
    pub current_changed: bool,
}

pub fn finalize(
    context: &CallContext,
    workspace: &Path,
    request: &FinalizeRequest,
) -> Result<BundleResult, String> {
    if context.effect_policy != crate::EffectPolicy::WorkspaceWrite {
        return Err("bundle finalization requires WorkspaceWrite effect policy".into());
    }
    let root = artifact::workspace(context, workspace)?;
    let primary = context
        .workspace_root()
        .ok_or("primary workspace missing")?;
    let lexical_primary = context
        .authorized_lexical_roots()
        .first()
        .ok_or("primary lexical workspace missing")?;
    let relative_output = request
        .output_path
        .strip_prefix(primary)
        .or_else(|_| request.output_path.strip_prefix(lexical_primary))
        .map_err(|_| "bundle output is outside primary workspace")?;
    let output_path = primary.join(relative_output);
    let allowed = primary.join(".gtkg/qk/bundles");
    if !request.output_path.is_absolute()
        || !output_path.starts_with(&allowed)
        || output_path == allowed
        || root.starts_with(&output_path)
        || request.output_path.components().any(|c| {
            matches!(
                c,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
    {
        return Err(
            "bundle output must be strictly within primary workspace .gtkg/qk/bundles".into(),
        );
    }
    let authorized_output = context
        .authorize_write(&request.output_path)
        .map_err(|e| e.to_string())?;
    if authorized_output != output_path {
        return Err("bundle output contains a symlink or changed directory identity".into());
    }
    let (manifest, closure, current_source) = gather(
        context,
        &root,
        &request.verified_ref,
        &request.accepted_refs,
        &request.views_ref,
    )?;
    let previous = if let Some(locator) = &request.predecessor {
        let prior = verify(context, locator)?;
        let (ledger, _): (source::SourceCoverageLedger, _) =
            artifact::read(context, &locator.workspace_root, &prior.manifest.source_ref)?;
        Some((prior.manifest.identity, ledger))
    } else {
        None
    };
    let delta = build_delta(previous.as_ref(), &manifest.identity, &current_source)?;
    let raw_manifest = serde_json::to_vec_pretty(&manifest).map_err(|e| e.to_string())?;
    let manifest_ref = FileReceiptRef {
        path: MANIFEST_PATH.into(),
        sha256: artifact::digest(&raw_manifest),
    };
    // An existing partial destination is resumable only when every existing
    // byte belongs to this exact output. Never pollute an older finished bundle.
    if output_path.exists() {
        for (path, bytes) in read_tree(context, &output_path)? {
            let expected = if path == MANIFEST_PATH {
                Some(raw_manifest.as_slice())
            } else {
                closure.files.get(&path).map(|(_, raw)| raw.as_slice())
            };
            if expected != Some(bytes.as_slice()) {
                return Err(
                    "bundle destination contains unrelated or different immutable bytes".into(),
                );
            }
        }
    }
    let prefix = output_path
        .strip_prefix(primary)
        .map_err(|_| "bundle outside primary workspace")?
        .to_str()
        .ok_or("non-UTF8 bundle path")?;
    for (path, (_, raw)) in &closure.files {
        source::write_workspace_object(primary, &format!("{prefix}/{path}"), raw)
            .map_err(|e| e.to_string())?;
    }
    source::write_workspace_object(primary, &format!("{prefix}/{MANIFEST_PATH}"), &raw_manifest)
        .map_err(|e| e.to_string())?;
    let bundle = BundleLocator {
        workspace_root: output_path,
        manifest_ref,
    };
    let checked = verify(context, &bundle)?;
    if checked.manifest != manifest {
        return Err("final bundle readback differs from assembled source closure".into());
    }
    Ok(BundleResult {
        bundle,
        manifest,
        delta,
        authority_exported: false,
    })
}
pub fn verify(context: &CallContext, bundle: &BundleLocator) -> Result<BundleVerification, String> {
    let root = artifact::workspace(context, &bundle.workspace_root)?;
    if bundle.manifest_ref.path != MANIFEST_PATH {
        return Err("bundle manifest must use its canonical package-relative path".into());
    }
    let (recorded, _): (BundleManifest, _) = artifact::read(context, &root, &bundle.manifest_ref)?;
    if recorded.schema != BUNDLE_SCHEMA {
        return Err("stale bundle schema".into());
    }
    let (current, closure, _) = gather(
        context,
        &root,
        &recorded.verified_ref,
        &recorded.accepted_refs,
        &recorded.views_ref,
    )?;
    require_identity(&recorded.identity, &current.identity)?;
    if recorded != current {
        return Err("bundle manifest differs from replayed complete reference closure".into());
    }
    let actual = read_tree_excluding_authority(context, &root, true)?;
    let expected: std::collections::BTreeSet<_> = closure
        .files
        .keys()
        .map(String::as_str)
        .chain(std::iter::once(MANIFEST_PATH))
        .collect();
    if actual
        .keys()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>()
        != expected
    {
        return Err("bundle file denominator contains missing or undeclared public files".into());
    }
    for (path, (_, raw)) in &closure.files {
        if actual.get(path) != Some(raw) {
            return Err("bundle closure changed during readback".into());
        }
    }
    Ok(BundleVerification { verified_files: current.files.len(), manifest: current,
        status: "verified_reference_closure_source_spans_and_lexical_projection; ranking_and_full_corpus_quality_not_evaluated".into(),
        authority_required_for_read_verification: false })
}
pub fn import_bundle(
    context: &CallContext,
    bundle: &BundleLocator,
) -> Result<BundleVerification, String> {
    if context.effect_policy != crate::EffectPolicy::WorkspaceWrite {
        return Err("bundle import requires WorkspaceWrite effect policy".into());
    }
    let result = verify(context, bundle)?;
    context
        .authorize_write(&bundle.workspace_root.join(AUTHORITY_PATH))
        .map_err(|e| e.to_string())?;
    query::initialize_authority(context, &bundle.workspace_root)?;
    Ok(result)
}
pub fn migrate(
    context: &CallContext,
    workspace: &Path,
    request: &MigrationRequest,
) -> Result<MigrationLedger, String> {
    let workspace = artifact::workspace(context, workspace)?;
    let legacy = artifact::workspace(context, &request.legacy_root)?;
    if !legacy.starts_with(&workspace) {
        return Err("legacy root is outside workspace".into());
    }
    request
        .legacy_manifest_ref
        .validate()
        .map_err(|e| e.to_string())?;
    if request.legacy_manifest_ref.path != "manifest.json" {
        return Err("legacy V1 requires root manifest.json".into());
    }
    let tree = read_tree(context, &legacy)?;
    let raw = tree.get("manifest.json").ok_or("legacy manifest missing")?;
    if artifact::digest(raw) != request.legacy_manifest_ref.sha256 {
        return Err("legacy manifest digest mismatch".into());
    }
    let manifest: serde_json::Value = serde_json::from_slice(raw).map_err(|e| e.to_string())?;
    if manifest["schema_version"] != "gtkg.bundle/v1" {
        return Err("legacy manifest schema must be gtkg.bundle/v1".into());
    }
    let mut gaps = vec![
        "migration_gap: successor source replay, semantic review and rebuild have not run".into(),
    ];
    if let Some(reference) = &request.source_ref {
        let (ledger, path): (source::SourceCoverageLedger, _) =
            artifact::read(context, &workspace, reference)?;
        let checked = source::load_archive(path.parent().ok_or("source archive parent missing")?)
            .map_err(|e| e.to_string())?;
        if ledger != checked {
            return Err("migration source archive changed".into());
        }
    } else {
        gaps.push("migration_gap: exact source archive unavailable".into());
    }
    let files: Vec<_> = tree
        .iter()
        .map(|(path, raw)| BundleFile {
            reference: FileReceiptRef {
                path: path.clone(),
                sha256: artifact::digest(raw),
            },
            bytes: raw.len() as u64,
            role: "legacy_material_not_proven".into(),
        })
        .collect();
    let second = read_tree(context, &legacy)?;
    if second != tree {
        return Err("legacy tree changed during read-only inspection".into());
    }
    Ok(MigrationLedger {
        schema: "gtkg.qk.legacy-migration-ledger/v1".into(),
        legacy_manifest_ref: request.legacy_manifest_ref.clone(),
        legacy_tree_digest: artifact::digest(
            &serde_json::to_vec(&files).map_err(|e| e.to_string())?,
        ),
        preserved_files: files,
        relationship_status: "legacy_unverified".into(),
        source_ref: request.source_ref.clone(),
        gaps,
        successor_created: false,
        current_changed: false,
    })
}
pub fn require_identity(
    recorded: &PipelineIdentity,
    expected: &PipelineIdentity,
) -> Result<(), String> {
    if recorded == expected {
        return Ok(());
    }
    let left = serde_json::to_value(recorded).map_err(|e| e.to_string())?;
    let right = serde_json::to_value(expected).map_err(|e| e.to_string())?;
    let changed: Vec<_> = left
        .as_object()
        .ok_or("identity object required")?
        .iter()
        .filter(|(key, value)| right.get(*key) != Some(*value))
        .map(|(key, _)| key.as_str())
        .collect();
    Err(format!("stale pipeline identity: {}", changed.join(", ")))
}

fn read_tree(context: &CallContext, root: &Path) -> Result<BTreeMap<String, Vec<u8>>, String> {
    read_tree_excluding_authority(context, root, false)
}
fn read_tree_excluding_authority(
    context: &CallContext,
    root: &Path,
    skip_authority: bool,
) -> Result<BTreeMap<String, Vec<u8>>, String> {
    let mut files = BTreeMap::new();
    let mut pending = vec![root.to_owned()];
    let mut bytes = 0u64;
    while let Some(directory) = pending.pop() {
        let metadata = std::fs::symlink_metadata(&directory).map_err(|e| e.to_string())?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err("tree directory is not a regular directory".into());
        }
        for entry in std::fs::read_dir(&directory).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            let path = entry.path();
            let kind = entry.file_type().map_err(|e| e.to_string())?;
            if kind.is_dir() {
                pending.push(path);
                continue;
            }
            if !kind.is_file() {
                return Err("tree contains a symlink or special file".into());
            }
            let relative = path
                .strip_prefix(root)
                .map_err(|_| "tree path escaped root")?
                .to_str()
                .ok_or("non-UTF8 tree path")?
                .to_owned();
            if skip_authority && private_runtime_path(&relative) {
                continue;
            }
            let raw = read_bound_regular_file(context, &path).map_err(|e| e.message)?;
            bytes = bytes
                .checked_add(raw.bytes.len() as u64)
                .ok_or("tree size overflow")?;
            if files.len() >= 100_000 || bytes > 512 * 1024 * 1024 {
                return Err("tree inspection budget exceeded".into());
            }
            let relative = path
                .strip_prefix(root)
                .map_err(|_| "tree path escaped root")?
                .to_str()
                .ok_or("non-UTF8 tree path")?
                .to_owned();
            FileReceiptRef {
                path: relative.clone(),
                sha256: raw.sha256,
            }
            .validate()
            .map_err(|e| e.to_string())?;
            files.insert(relative, raw.bytes);
        }
    }
    Ok(files)
}

const BUNDLE_SCHEMA: &str = "gtkg.qk.portable-bundle/v1";
const MANIFEST_PATH: &str = ".gtkg/qk/bundle-manifest.json";
const AUTHORITY_PATH: &str = ".gtkg/qk/runtime/query-authority.json";
fn private_runtime_path(path: &str) -> bool {
    if path == AUTHORITY_PATH || path.starts_with(".gtkg/qk/runtime/semantic-admission/") {
        return true;
    }
    // Durable publication leaves ordinary advisory lock files. They belong to
    // workspace runtime state and cannot be exported as public bundle evidence.
    path.strip_prefix(".gtkg/locks/receipts/")
        .and_then(|name| name.strip_suffix(".lock"))
        .is_some_and(|name| name.len() == 64 && name.bytes().all(|c| c.is_ascii_hexdigit()))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticFinalizeRequest {
    pub schema: String,
    pub verified_ref: FileReceiptRef,
    pub accepted_refs: Vec<FileReceiptRef>,
    pub views_ref: FileReceiptRef,
    pub output_path: PathBuf,
    pub predecessor: Option<BundleLocator>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticPipelineIdentity {
    pub base: PipelineIdentity,
    pub base_index_ref: FileReceiptRef,
    pub query_index_ref: FileReceiptRef,
    pub catalog_ref: FileReceiptRef,
    pub accepted_set_digest: String,
    pub projection_policy: String,
    pub query_policy: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticBundleManifest {
    pub schema: String,
    pub identity: SemanticPipelineIdentity,
    pub verified_ref: FileReceiptRef,
    pub source_ref: FileReceiptRef,
    pub base_index_ref: FileReceiptRef,
    pub query_index_ref: FileReceiptRef,
    pub semantic_catalog_ref: FileReceiptRef,
    pub accepted_refs: Vec<FileReceiptRef>,
    pub views_ref: FileReceiptRef,
    pub canonical_okf_refs: Vec<FileReceiptRef>,
    pub files: Vec<BundleFile>,
    pub indexes_rebuildable: bool,
    pub knowledge_ready: bool,
    pub llm_qa_validated: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticBundleResult {
    pub bundle: BundleLocator,
    pub manifest: SemanticBundleManifest,
    pub delta: BuildDelta,
    pub authority_exported: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticBundleVerification {
    pub manifest: SemanticBundleManifest,
    pub verified_files: usize,
    pub status: String,
    pub authority_required_for_read_verification: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AnyBundleVerification {
    Source(Box<BundleVerification>),
    Semantic(Box<SemanticBundleVerification>),
}
const SEMANTIC_BUNDLE_SCHEMA: &str = "gtkg.qk.portable-semantic-bundle/v1";

fn semantic_manifest(
    context: &CallContext,
    root: &Path,
    base: BundleManifest,
    closure: &mut Closure,
    replayed: &super::semantic_projection::ReplayedProjection,
) -> Result<SemanticBundleManifest, String> {
    let overlay = replayed.overlay();
    let catalog_ref = FileReceiptRef {
        path: overlay.catalog_ref.path.clone(),
        sha256: overlay.catalog_ref.sha256.clone(),
    };
    let raw = replayed
        .files()
        .get(&catalog_ref.path)
        .ok_or("replayed semantic catalog absent")?;
    let catalog: super::semantic_projection::SemanticCatalogManifest =
        serde_json::from_slice(raw).map_err(|e| e.to_string())?;
    if overlay.verified_ref.sha256 != base.verified_ref.sha256
        || overlay.verified_ref.path != base.verified_ref.path
        || overlay.base_index_ref.sha256 != base.index_ref.sha256
        || overlay.base_index_ref.path != base.index_ref.path
        || overlay.source_ref != base.source_ref
        || catalog
            .accepted_refs
            .iter()
            .map(|r| FileReceiptRef {
                path: r.path.clone(),
                sha256: r.sha256.clone(),
            })
            .collect::<Vec<_>>()
            != base.accepted_refs
    {
        return Err("semantic bundle accepted/base/source set mismatch".into());
    }
    for (path, raw) in replayed.files() {
        let r = FileReceiptRef {
            path: path.clone(),
            sha256: artifact::digest(raw),
        };
        let actual = closure.add(
            context,
            root,
            &r,
            Some(raw.len() as u64),
            "semantic_projection",
        )?;
        if actual != *raw {
            return Err("semantic projection changed while gathering bundle closure".into());
        }
    }
    let identity = SemanticPipelineIdentity {
        base: base.identity,
        base_index_ref: base.index_ref.clone(),
        query_index_ref: replayed.overlay_ref().clone(),
        catalog_ref: catalog_ref.clone(),
        accepted_set_digest: catalog.accepted_set_digest,
        projection_policy: overlay.projection_policy.clone(),
        query_policy: overlay.query_policy.clone(),
    };
    Ok(SemanticBundleManifest {
        schema: SEMANTIC_BUNDLE_SCHEMA.into(),
        identity,
        verified_ref: base.verified_ref,
        source_ref: base.source_ref,
        base_index_ref: base.index_ref,
        query_index_ref: replayed.overlay_ref().clone(),
        semantic_catalog_ref: catalog_ref,
        accepted_refs: base.accepted_refs,
        views_ref: base.views_ref,
        canonical_okf_refs: base.canonical_okf_refs,
        files: closure.files.values().map(|(f, _)| f.clone()).collect(),
        indexes_rebuildable: true,
        knowledge_ready: base.knowledge_ready,
        llm_qa_validated: false,
    })
}
fn semantic_output(
    context: &CallContext,
    root: &Path,
    requested: &Path,
) -> Result<PathBuf, String> {
    let primary = context
        .workspace_root()
        .ok_or("primary workspace missing")?;
    let lexical = context
        .authorized_lexical_roots()
        .first()
        .ok_or("primary lexical workspace missing")?;
    let relative = requested
        .strip_prefix(primary)
        .or_else(|_| requested.strip_prefix(lexical))
        .map_err(|_| "bundle output is outside primary workspace")?;
    let output = primary.join(relative);
    let allowed = primary.join(".gtkg/qk/bundles");
    if !requested.is_absolute()
        || !output.starts_with(&allowed)
        || output == allowed
        || root.starts_with(&output)
        || requested.components().any(|c| {
            matches!(
                c,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
    {
        return Err(
            "bundle output must be strictly within primary workspace .gtkg/qk/bundles".into(),
        );
    }
    if context
        .authorize_write(requested)
        .map_err(|e| e.to_string())?
        != output
    {
        return Err("bundle output contains a symlink or changed directory identity".into());
    }
    Ok(output)
}
fn publish_semantic_bundle(
    context: &CallContext,
    output: &Path,
    manifest: &SemanticBundleManifest,
    closure: &Closure,
) -> Result<BundleLocator, String> {
    let raw = serde_json::to_vec_pretty(manifest).map_err(|e| e.to_string())?;
    if output.exists() {
        for (path, actual) in read_tree(context, output)? {
            let expected = if path == MANIFEST_PATH {
                Some(raw.as_slice())
            } else {
                closure.files.get(&path).map(|(_, bytes)| bytes.as_slice())
            };
            if expected != Some(actual.as_slice()) {
                return Err(
                    "bundle destination contains unrelated or different immutable bytes".into(),
                );
            }
        }
    }
    let primary = context
        .workspace_root()
        .ok_or("primary workspace missing")?;
    let prefix = output
        .strip_prefix(primary)
        .map_err(|_| "bundle output escaped workspace")?
        .to_str()
        .ok_or("non UTF8 bundle path")?;
    for (path, (_, bytes)) in &closure.files {
        source::write_workspace_object(primary, &format!("{prefix}/{path}"), bytes)
            .map_err(|e| e.to_string())?;
    }
    source::write_workspace_object(primary, &format!("{prefix}/{MANIFEST_PATH}"), &raw)
        .map_err(|e| e.to_string())?;
    Ok(BundleLocator {
        workspace_root: output.to_owned(),
        manifest_ref: FileReceiptRef {
            path: MANIFEST_PATH.into(),
            sha256: artifact::digest(&raw),
        },
    })
}
pub fn finalize_semantic(
    context: &CallContext,
    workspace: &Path,
    request: &SemanticFinalizeRequest,
) -> Result<SemanticBundleResult, String> {
    if context.effect_policy != crate::EffectPolicy::WorkspaceWrite {
        return Err("semantic bundle finalization requires WorkspaceWrite".into());
    }
    if request.schema != "gtkg.qk.semantic-finalize/v1" {
        return Err("unsupported semantic finalize request".into());
    }
    let root = artifact::workspace(context, workspace)?;
    let output = semantic_output(context, &root, &request.output_path)?;
    let mut refs = request.accepted_refs.clone();
    refs.sort_by(|a, b| (&a.path, &a.sha256).cmp(&(&b.path, &b.sha256)));
    refs.dedup();
    let (base, mut closure, source) = gather(
        context,
        &root,
        &request.verified_ref,
        &refs,
        &request.views_ref,
    )?;
    let replayed = super::semantic_projection::replay_projection(
        context,
        &root,
        &super::semantic_projection::SemanticPrepareRequest {
            schema: "gtkg.qk.semantic-prepare/v1".into(),
            verified_ref: request.verified_ref.clone(),
            base_index_ref: base.index_ref.clone(),
            accepted_refs: refs,
        },
    )?;
    // Publication is exclusively on this authorized write path, never in gather/verify.
    super::semantic_projection::publish_projection(context, &root, replayed.clone())?;
    let manifest = semantic_manifest(context, &root, base, &mut closure, &replayed)?;
    let mut previous_projection = None;
    let previous = if let Some(locator) = &request.predecessor {
        let (identity, source_ref) = match verify_any(context, locator)? {
            AnyBundleVerification::Source(v) => (v.manifest.identity, v.manifest.source_ref),
            AnyBundleVerification::Semantic(v) => {
                previous_projection = Some(v.manifest.identity.clone());
                (v.manifest.identity.base, v.manifest.source_ref)
            }
        };
        let (ledger, _): (source::SourceCoverageLedger, _) =
            artifact::read(context, &locator.workspace_root, &source_ref)?;
        Some((identity, ledger))
    } else {
        None
    };
    let mut delta = build_delta(previous.as_ref(), &manifest.identity.base, &source)?;
    if request.predecessor.is_some() && previous_projection.as_ref() != Some(&manifest.identity) {
        delta
            .invalidated_dependencies
            .push("semantic_projection".into());
    }
    let bundle = publish_semantic_bundle(context, &output, &manifest, &closure)?;
    let checked = verify_semantic(context, &bundle)?;
    if checked.manifest != manifest {
        return Err("semantic bundle readback differs from complete replay".into());
    }
    Ok(SemanticBundleResult {
        bundle,
        manifest,
        delta,
        authority_exported: false,
    })
}
pub fn verify_semantic(
    context: &CallContext,
    bundle: &BundleLocator,
) -> Result<SemanticBundleVerification, String> {
    let root = artifact::workspace(context, &bundle.workspace_root)?;
    if bundle.manifest_ref.path != MANIFEST_PATH {
        return Err("bundle manifest must use canonical package-relative path".into());
    }
    let (recorded, _): (SemanticBundleManifest, _) =
        artifact::read(context, &root, &bundle.manifest_ref)?;
    if recorded.schema != SEMANTIC_BUNDLE_SCHEMA {
        return Err("unsupported semantic bundle schema".into());
    }
    let (base, mut closure, _) = gather(
        context,
        &root,
        &recorded.verified_ref,
        &recorded.accepted_refs,
        &recorded.views_ref,
    )?;
    let replayed =
        super::semantic_projection::verify_projection(context, &root, &recorded.query_index_ref)?;
    let current = semantic_manifest(context, &root, base, &mut closure, &replayed)?;
    if current != recorded {
        return Err("semantic bundle differs from complete replayed reference closure".into());
    }
    let actual = read_tree_excluding_authority(context, &root, true)?;
    let expected: std::collections::BTreeSet<_> = closure
        .files
        .keys()
        .map(String::as_str)
        .chain(std::iter::once(MANIFEST_PATH))
        .collect();
    if actual
        .keys()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>()
        != expected
    {
        return Err(
            "semantic bundle file denominator has missing or undeclared public files".into(),
        );
    }
    for (path, (_, raw)) in &closure.files {
        if actual.get(path) != Some(raw) {
            return Err("semantic bundle closure changed during readback".into());
        }
    }
    Ok(SemanticBundleVerification {verified_files:current.files.len(),manifest:current,status:"verified_reference_closure_source_spans_lexical_and_reviewed_context_projection; retrieval_and_model_quality_not_evaluated".into(),authority_required_for_read_verification:false})
}
pub fn verify_any(
    context: &CallContext,
    bundle: &BundleLocator,
) -> Result<AnyBundleVerification, String> {
    let root = artifact::workspace(context, &bundle.workspace_root)?;
    let (value, _): (serde_json::Value, _) = artifact::read(context, &root, &bundle.manifest_ref)?;
    match value.get("schema").and_then(serde_json::Value::as_str) {
        Some(BUNDLE_SCHEMA) => verify(context, bundle)
            .map(Box::new)
            .map(AnyBundleVerification::Source),
        Some(SEMANTIC_BUNDLE_SCHEMA) => verify_semantic(context, bundle)
            .map(Box::new)
            .map(AnyBundleVerification::Semantic),
        _ => Err("unsupported bundle schema".into()),
    }
}
pub fn import_any(
    context: &CallContext,
    bundle: &BundleLocator,
) -> Result<AnyBundleVerification, String> {
    if context.effect_policy != crate::EffectPolicy::WorkspaceWrite {
        return Err("bundle import requires WorkspaceWrite".into());
    }
    let checked = verify_any(context, bundle)?;
    match &checked {
        AnyBundleVerification::Source(_) => {
            query::initialize_authority(context, &bundle.workspace_root)?;
        }
        AnyBundleVerification::Semantic(v) => {
            let replayed = super::semantic_projection::verify_projection(
                context,
                &bundle.workspace_root,
                &v.manifest.query_index_ref,
            )?;
            replayed.admit(context, &bundle.workspace_root)?;
        }
    }
    Ok(checked)
}
#[derive(Default)]
struct Closure {
    files: BTreeMap<String, (BundleFile, Vec<u8>)>,
    total_bytes: u64,
}
impl Closure {
    fn add(
        &mut self,
        context: &CallContext,
        root: &Path,
        reference: &FileReceiptRef,
        bytes: Option<u64>,
        role: &str,
    ) -> Result<Vec<u8>, String> {
        reference.validate().map_err(|e| e.to_string())?;
        if reference.path.starts_with(".gtkg/qk/runtime/")
            || reference.path.starts_with(".gtkg/locks/")
            || reference.path == MANIFEST_PATH
        {
            return Err(
                "private runtime authority or bundle root cannot enter artifact closure".into(),
            );
        }
        if let Some((entry, raw)) = self.files.get(&reference.path) {
            if entry.reference != *reference || bytes.is_some_and(|n| n != entry.bytes) {
                return Err("closure has conflicting identities for one path".into());
            }
            return Ok(raw.clone());
        }
        let read =
            read_bound_regular_file(context, &root.join(&reference.path)).map_err(|e| e.message)?;
        if read.sha256 != reference.sha256 || bytes.is_some_and(|n| n != read.bytes.len() as u64) {
            return Err("closure artifact hash/length mismatch".into());
        }
        self.total_bytes = self
            .total_bytes
            .checked_add(read.bytes.len() as u64)
            .ok_or("closure size overflow")?;
        if self.files.len() >= 100_000 || self.total_bytes > 512 * 1024 * 1024 {
            return Err("closure build bound exceeded".into());
        }
        self.files.insert(
            reference.path.clone(),
            (
                BundleFile {
                    reference: reference.clone(),
                    bytes: read.bytes.len() as u64,
                    role: role.into(),
                },
                read.bytes.clone(),
            ),
        );
        Ok(read.bytes)
    }
    fn arc(
        &mut self,
        context: &CallContext,
        root: &Path,
        anchor: &str,
        r: &source::ArchiveRef,
        role: &str,
    ) -> Result<Vec<u8>, String> {
        let reference = FileReceiptRef {
            path: format!("{anchor}/{}", r.path),
            sha256: format!("sha256:{}", r.sha256),
        };
        self.add(context, root, &reference, Some(r.bytes), role)
    }
    fn index(
        &mut self,
        context: &CallContext,
        root: &Path,
        r: &index::ArtifactRef,
        role: &str,
    ) -> Result<Vec<u8>, String> {
        self.add(
            context,
            root,
            &FileReceiptRef {
                path: r.path.clone(),
                sha256: r.sha256.clone(),
            },
            Some(r.bytes),
            role,
        )
    }
}
fn sorted_refs(refs: &[FileReceiptRef]) -> Result<Vec<FileReceiptRef>, String> {
    let mut output = refs.to_vec();
    for r in &output {
        r.validate().map_err(|e| e.to_string())?;
    }
    output.sort_by(|a, b| (&a.path, &a.sha256).cmp(&(&b.path, &b.sha256)));
    if output.windows(2).any(|w| w[0].path == w[1].path) {
        return Err("duplicate artifact reference in frozen root set".into());
    }
    Ok(output)
}
fn gather(
    context: &CallContext,
    root: &Path,
    verified_ref: &FileReceiptRef,
    accepted_refs: &[FileReceiptRef],
    views_ref: &FileReceiptRef,
) -> Result<(BundleManifest, Closure, source::SourceCoverageLedger), String> {
    let (v, candidate, ledger, archive, _) = analysis::load_verified(context, root, verified_ref)?;
    let index_ref = v
        .index_ref
        .clone()
        .ok_or("verified analysis has no admitted index reference")?;
    let m = index::load_manifest(context, root, &index_ref)?;
    let context_digest = gtkg_extract::v04::context_digest(&v.context);
    if m.source_ref != v.source_ref
        || m.snapshot_id != v.snapshot_id
        || m.source_tree != v.source_tree
        || m.source_commit != v.source_commit
        || m.analysis_context_digest != context_digest
    {
        return Err("stale analysis/index/source/context identity".into());
    }
    let refs = sorted_refs(accepted_refs)?;
    let views = authoring::replay_views(context, root, views_ref)?;
    if views.verified_ref != *verified_ref || sorted_refs(&views.accepted_refs)? != refs {
        return Err("views do not bind this complete accepted/source set".into());
    }
    let mut closure = Closure::default();
    for (r, role) in [
        (verified_ref, "verified_analysis"),
        (&v.candidate_ref, "analysis_candidate"),
        (&v.plan_ref, "analysis_plan"),
        (&v.source_ref, "source_ledger"),
        (&index_ref, "index_manifest"),
        (views_ref, "project_views"),
    ] {
        closure.add(context, root, r, None, role)?;
    }
    let anchor = archive
        .strip_prefix(root)
        .map_err(|_| "source archive escaped package")?
        .to_str()
        .ok_or("non-UTF8 source archive")?;
    let selection: source::AnalysisSelectionManifest = serde_json::from_slice(&closure.arc(
        context,
        root,
        anchor,
        &ledger.selection_manifest,
        "source_selection",
    )?)
    .map_err(|e| e.to_string())?;
    for page in selection.pages {
        closure.arc(context, root, anchor, &page, "source_selection_page")?;
    }
    let objects: source::SourceObjectManifest = serde_json::from_slice(&closure.arc(
        context,
        root,
        anchor,
        &ledger.object_manifest,
        "source_object_manifest",
    )?)
    .map_err(|e| e.to_string())?;
    for object in objects.objects {
        closure.arc(context, root, anchor, &object, "source_object")?;
    }
    for name in ["source-coverage-ledger.sha256", "checkpoint.json"] {
        let path = archive.join(name);
        let reference = artifact::reference(context, root, &path)?;
        closure.add(context, root, &reference, None, "source_archive_seal")?;
    }
    let mut canonical_okf_refs = Vec::new();
    let mut accepted_digests = Vec::new();
    for reference in &refs {
        let (a, job, proposal, review, _) = authoring::accepted_chain(context, root, reference)?;
        if job.verified_ref != *verified_ref {
            return Err("mixed verified source revisions in bundle knowledge".into());
        }
        for (r, role) in [
            (reference, "accepted_knowledge"),
            (&a.job_ref, "authoring_job"),
            (&a.review_ref, "knowledge_review"),
            (&review.proposal_ref, "knowledge_proposal"),
            (&a.okf_ref, "canonical_okf"),
        ] {
            closure.add(context, root, r, None, role)?;
        }
        if proposal.job_ref != a.job_ref {
            return Err("authoring closure job mismatch".into());
        }
        accepted_digests.push(reference.sha256.clone());
        canonical_okf_refs.push(a.okf_ref);
    }
    canonical_okf_refs.sort_by(|a, b| (&a.path, &a.sha256).cmp(&(&b.path, &b.sha256)));
    canonical_okf_refs.dedup();
    accepted_digests.sort();
    validate_index_closure(context, root, &m, &candidate, &v, &mut closure)?;
    let mut parsers = BTreeMap::new();
    for fact in &candidate.facts {
        if parsers
            .insert(fact.language.clone(), fact.parser_identity.clone())
            .is_some_and(|prior| prior != fact.parser_identity)
        {
            return Err("mixed parser identities for one language".into());
        }
    }
    let identity = PipelineIdentity {
        profile: gtkg_protocol::v04::PROFILE_ID.into(),
        snapshot_id: v.snapshot_id,
        source_commit: v.source_commit,
        source_tree: v.source_tree,
        source_ledger_sha256: v.source_ref.sha256.clone(),
        source_policy_sha256: ledger.policy_sha256.clone(),
        extractor_profile: gtkg_extract::v04::EXTRACTOR_PROFILE.into(),
        parser_identities: parsers,
        resolver_profile: gtkg_extract::v04::binding::RESOLVER_PROFILE.into(),
        verifier_profile: gtkg_extract::v04::binding::VERIFIER_PROFILE.into(),
        analysis_context_digest: context_digest,
        chunker: m.chunker,
        tokenizer: m.tokenizer,
        query_policy: m.query_policy,
        accepted_digests,
        views_digest: views.views.view_digest,
    };
    let manifest = BundleManifest {
        schema: BUNDLE_SCHEMA.into(),
        identity,
        verified_ref: verified_ref.clone(),
        source_ref: v.source_ref,
        index_ref,
        accepted_refs: refs,
        views_ref: views_ref.clone(),
        canonical_okf_refs,
        files: closure
            .files
            .values()
            .map(|(file, _)| file.clone())
            .collect(),
        indexes_rebuildable: true,
        knowledge_ready: views.views.knowledge_ready,
        llm_qa_validated: false,
    };
    Ok((manifest, closure, ledger))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClosureChunkShard {
    schema: String,
    snapshot_id: String,
    index_root: String,
    bucket: String,
    chunks: BTreeMap<String, index::ArtifactRef>,
}
fn validate_index_closure(
    context: &CallContext,
    root: &Path,
    m: &index::IndexManifest,
    candidate: &analysis::AnalysisCandidate,
    v: &analysis::VerifiedAnalysis,
    closure: &mut Closure,
) -> Result<(), String> {
    let (binding, _) = index::load_source_binding(context, root, m)?;
    let mut expected: BTreeMap<String, Vec<index::Posting>> = BTreeMap::new();
    let mut chunk_ids = std::collections::BTreeSet::new();
    let mut total_tokens = 0u64;
    let mut index_bytes = 0u64;
    let index_manifest_ref = FileReceiptRef {
        path: format!("{}/manifest.json", m.index_root),
        sha256: v.index_ref.as_ref().ok_or("index absent")?.sha256.clone(),
    };
    index_bytes += closure
        .add(context, root, &index_manifest_ref, None, "index_manifest")?
        .len() as u64;
    for (bucket, reference) in m
        .chunk_router
        .iter()
        .filter_map(|(b, r)| r.as_ref().map(|r| (b, r)))
    {
        let raw = closure.index(context, root, reference, "chunk_router")?;
        index_bytes += raw.len() as u64;
        let shard: ClosureChunkShard = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
        if shard.schema != "gtkg.qk.chunk-router-shard/v1"
            || shard.snapshot_id != m.snapshot_id
            || shard.index_root != m.index_root
            || shard.bucket != *bucket
        {
            return Err("typed chunk router identity mismatch".into());
        }
        for (id, reference) in &shard.chunks {
            if id.len() != 64
                || !id
                    .bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
                || !id.starts_with(bucket)
                || reference.path != format!("{}/chunks/{id}.json", m.index_root)
            {
                return Err("typed chunk router path/id mismatch".into());
            }
            if !chunk_ids.insert(id.clone()) {
                return Err("duplicate chunk in complete index denominator".into());
            }
            let raw = closure.index(context, root, reference, "evidence_chunk")?;
            let chunk: index::EvidenceChunk =
                serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
            if chunk.id != *id {
                return Err("chunk content ID disagrees with router".into());
            }
            index::validate_chunk_source_with_binding(context, root, m, &chunk, &binding)?;
            if chunk.text.chars().count() != chunk.tokens as usize {
                return Err("chunk tokenizer count does not replay".into());
            }
            total_tokens += u64::from(chunk.tokens);
            index_bytes += raw.len() as u64;
            let mut frequencies: BTreeMap<String, u32> = BTreeMap::new();
            for term in index::tokenize(&chunk.text) {
                *frequencies.entry(term).or_default() += 1;
            }
            for (term, term_frequency) in frequencies {
                expected.entry(term).or_default().push(index::Posting {
                    chunk_id: id.clone(),
                    chunk_ref: reference.clone(),
                    term_frequency,
                    tokens: chunk.tokens,
                });
            }
        }
    }
    if chunk_ids.len() != m.total_chunks || total_tokens != m.total_tokens {
        return Err("complete chunk/token denominator mismatch".into());
    }
    for postings in expected.values_mut() {
        postings.sort_by(|a, b| a.chunk_id.cmp(&b.chunk_id));
    }
    let mut observed = std::collections::BTreeSet::new();
    for (bucket, reference) in m
        .router
        .iter()
        .filter_map(|(b, r)| r.as_ref().map(|r| (b, r)))
    {
        let raw = closure.index(context, root, reference, "posting_shard")?;
        index_bytes += raw.len() as u64;
        let shard: index::PostingShard = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
        index::validate_posting_container(m, &shard, bucket)?;
        let mut leaves = vec![];
        if shard.partitions.is_empty() {
            leaves.push(shard);
        } else {
            for (prefix, r) in &shard.partitions {
                if let Some(r) = r {
                    let raw = closure.index(context, root, r, "posting_partition")?;
                    index_bytes += raw.len() as u64;
                    let child: index::PostingShard =
                        serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
                    index::validate_posting_container(m, &child, prefix)?;
                    leaves.push(child);
                }
            }
        }
        for shard in leaves {
            for (term, postings) in &shard.terms {
                if index::token_bucket(term) != *bucket {
                    return Err("posting term disagrees with shard bucket".into());
                }
                if !observed.insert(term.clone()) {
                    return Err("duplicate term across posting shard denominator".into());
                }
                if expected.get(term) != Some(postings) {
                    return Err("posting projection does not match exact chunk tokenization".into());
                }
            }
        }
    }
    if observed != expected.keys().cloned().collect() {
        return Err("postings omit part of the exact chunk lexical projection".into());
    }
    if let Some(reference) = &m.graph_ref {
        let (graph, mut links, _) = graph_projection::verify_all(context, root, reference)?;
        if graph.source_ref != v.source_ref
            || graph.candidate_ref != v.candidate_ref
            || graph.context_digest != m.analysis_context_digest
            || graph.snapshot_id != v.snapshot_id
            || graph.source_tree != v.source_tree
            || graph.source_commit != v.source_commit
            || graph.total_calls != v.total_calls
            || graph.total_links != v.confirmed_calls
        {
            return Err("stale graph/analysis/source identity".into());
        }
        let mut expected = Vec::new();
        for proof in candidate
            .proofs
            .iter()
            .filter(|p| p.proof_status == "confirmed")
        {
            let target = proof.target.as_ref().ok_or("confirmed target missing")?;
            expected.push(graph_projection::GraphLink {
                call_id: proof.call.id.clone(),
                source_path: proof.source_path.clone(),
                call_span: proof.call.span.clone(),
                expression: proof.call.expression.clone(),
                target_path: target.path.clone(),
                target_id: target.declaration.id.clone(),
                target_name: target.declaration.name.clone(),
                target_span: target.declaration.span.clone(),
                target_name_span: target.declaration.name_span.clone(),
            });
        }
        expected.sort_by(|a, b| a.call_id.cmp(&b.call_id));
        links.sort_by(|a, b| a.call_id.cmp(&b.call_id));
        if links != expected {
            return Err(
                "graph projection disagrees with independently replayed confirmed proofs".into(),
            );
        }
        closure.add(context, root, reference, None, "graph_manifest")?;
        for r in graph.router.values().flatten() {
            closure.index(context, root, r, "graph_shard")?;
        }
        index_bytes += graph.total_graph_bytes;
    }
    if index_bytes != m.total_index_bytes {
        return Err("total index/graph byte denominator mismatch".into());
    }
    Ok(())
}
/// Full build/import admission, never a query-time helper. Reuse the existing
/// complete source/token/graph replay and return only the immutable source chunks.
pub(crate) fn replay_index_chunks(
    context: &CallContext,
    root: &Path,
    m: &index::IndexManifest,
    candidate: &analysis::AnalysisCandidate,
    verified: &analysis::VerifiedAnalysis,
) -> Result<Vec<(index::EvidenceChunk, index::ArtifactRef)>, String> {
    let mut closure = Closure::default();
    validate_index_closure(context, root, m, candidate, verified, &mut closure)?;
    closure
        .files
        .into_values()
        .filter(|(f, _)| f.role == "evidence_chunk")
        .map(|(file, raw)| {
            Ok((
                serde_json::from_slice(&raw).map_err(|e| e.to_string())?,
                index::ArtifactRef {
                    path: file.reference.path,
                    sha256: file.reference.sha256,
                    bytes: file.bytes,
                },
            ))
        })
        .collect()
}
fn source_paths(ledger: &source::SourceCoverageLedger) -> BTreeMap<String, String> {
    ledger
        .leaves
        .iter()
        .filter(|l| l.scope == source::Scope::Included)
        .map(|l| {
            (
                l.path.clone(),
                format!(
                    "{}:{}:{}",
                    l.mode,
                    l.git_oid,
                    l.content_sha256.as_deref().unwrap_or("unavailable")
                ),
            )
        })
        .collect()
}
fn build_delta(
    previous: Option<&(PipelineIdentity, source::SourceCoverageLedger)>,
    identity: &PipelineIdentity,
    current: &source::SourceCoverageLedger,
) -> Result<BuildDelta, String> {
    let new = source_paths(current);
    let old = previous.map(|(_, l)| source_paths(l)).unwrap_or_default();
    let mut delta = BuildDelta {
        added_paths: vec![],
        changed_paths: vec![],
        deleted_paths: vec![],
        retained_paths: vec![],
        invalidated_dependencies: vec![],
    };
    for (path, value) in &new {
        match old.get(path) {
            None => delta.added_paths.push(path.clone()),
            Some(prior) if prior != value => delta.changed_paths.push(path.clone()),
            Some(_) => delta.retained_paths.push(path.clone()),
        }
    }
    delta.deleted_paths = old
        .keys()
        .filter(|p| !new.contains_key(*p))
        .cloned()
        .collect();
    if let Some((previous, _)) = previous {
        let before = serde_json::to_value(previous).map_err(|e| e.to_string())?;
        let after = serde_json::to_value(identity).map_err(|e| e.to_string())?;
        delta.invalidated_dependencies = before
            .as_object()
            .ok_or("identity required")?
            .iter()
            .filter(|(key, value)| after.get(*key) != Some(*value))
            .map(|(key, _)| key.clone())
            .collect();
    }
    Ok(delta)
}
