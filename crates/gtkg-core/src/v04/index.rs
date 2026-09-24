//! Transferable evidence chunks and immutable, selectively readable lexical shards.
use crate::CallContext;
use gtkg_extract::v04::{AnalysisContext, ExtractedFile, context_digest, extract};
use gtkg_protocol::FileReceiptRef;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

pub const CHUNKER: &str = "gtkg.qk.semantic-lines/v1";
pub const TOKENIZER: &str = "UTF8-codepoint-v1";
pub const QUERY_POLICY: &str = "gtkg.qk.query/v1";
pub const INDEX_SCHEMA: &str = "gtkg.qk.evidence-chunk-manifest/v1";
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactRef {
    pub path: String,
    pub bytes: u64,
    pub sha256: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IndexManifest {
    pub schema: String,
    pub profile: String,
    pub snapshot_id: String,
    pub source_commit: String,
    pub source_tree: String,
    pub source_ref: FileReceiptRef,
    #[serde(default)]
    pub graph_ref: Option<FileReceiptRef>,
    pub archive_root: String,
    pub index_root: String,
    pub chunker: String,
    pub tokenizer: String,
    pub query_policy: String,
    pub analysis_context_digest: String,
    pub total_chunks: usize,
    pub total_tokens: u64,
    pub total_index_bytes: u64,
    pub router: BTreeMap<String, Option<ArtifactRef>>,
    pub chunk_router: BTreeMap<String, Option<ArtifactRef>>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChunkParent {
    pub kind: String,
    pub name: String,
    pub byte_start: usize,
    pub byte_end: usize,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceChunk {
    pub schema: String,
    pub id: String,
    pub snapshot_id: String,
    pub source_commit: String,
    pub source_tree: String,
    pub path: String,
    pub file_sha: String,
    pub object_sha: String,
    pub object_bytes: u64,
    pub byte_start: usize,
    pub byte_end: usize,
    pub line_start: usize,
    pub line_end: usize,
    pub language: String,
    pub role: String,
    pub text: String,
    pub tokens: u32,
    pub parent: Option<ChunkParent>,
    pub previous: Option<String>,
    pub next: Option<String>,
    pub chunker: String,
    pub tokenizer: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Posting {
    pub chunk_id: String,
    pub chunk_ref: ArtifactRef,
    pub term_frequency: u32,
    pub tokens: u32,
}

use super::{
    artifact,
    source::{self, MainRoute, Scope, TextStatus},
};
use crate::{durable::publish_immutable_json, exact_read::read_bound_regular_file};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap};
use unicode_normalization::UnicodeNormalization;
const PROFILE: &str = "GTKG-V0.4-KNOWLEDGE-QUALITY";
const CHUNK_SCHEMA: &str = "gtkg.qk.evidence-chunk/v1";
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PostingShard {
    pub(crate) schema: String,
    pub(crate) snapshot_id: String,
    pub(crate) index_root: String,
    pub(crate) bucket: String,
    pub(crate) terms: BTreeMap<String, Vec<Posting>>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) partitions: BTreeMap<String, Option<ArtifactRef>>,
}

/// The authenticated top-level router has already been read. A query reserves
/// the selected child bytes before the second read; unrelated children stay closed.
pub(crate) struct PostingSelection {
    shard: PostingShard,
    selected: Option<ArtifactRef>,
    bucket: String,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChunkShard {
    schema: String,
    snapshot_id: String,
    index_root: String,
    bucket: String,
    chunks: BTreeMap<String, ArtifactRef>,
}
fn plain_hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn json_hash<T: Serialize>(v: &T) -> Result<String, String> {
    Ok(plain_hash(
        &serde_json::to_vec(v).map_err(|e| e.to_string())?,
    ))
}
fn buckets() -> BTreeMap<String, Option<ArtifactRef>> {
    (0..256).map(|b| (format!("{b:02x}"), None)).collect()
}
fn hex_id(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn relative(s: &str) -> Result<(), String> {
    if s.is_empty()
        || s.contains('\\')
        || s.contains('\0')
        || s.split('/').any(|x| x.is_empty() || x == "." || x == "..")
        || Path::new(s).is_absolute()
    {
        Err("noncanonical relative artifact path".into())
    } else {
        Ok(())
    }
}
fn checked_ref(r: &ArtifactRef) -> Result<(), String> {
    relative(&r.path)?;
    FileReceiptRef {
        path: r.path.clone(),
        sha256: r.sha256.clone(),
    }
    .validate()
    .map_err(|e| e.to_string())
}
fn publish<T: Serialize>(
    context: &CallContext,
    workspace: &Path,
    path: &str,
    value: &T,
) -> Result<ArtifactRef, String> {
    relative(path)?;
    let raw = serde_json::to_vec_pretty(value).map_err(|e| e.to_string())?;
    publish_immutable_json(context, &workspace.join(path), value, "qk-evidence-index")
        .map_err(|e| e.to_string())?;
    Ok(ArtifactRef {
        path: path.into(),
        bytes: raw.len() as u64,
        sha256: artifact::digest(&raw),
    })
}
fn read_ref<T: serde::de::DeserializeOwned>(
    context: &CallContext,
    workspace: &Path,
    r: &ArtifactRef,
) -> Result<T, String> {
    checked_ref(r)?;
    let root = artifact::workspace(context, workspace)?;
    let read = read_bound_regular_file(context, &root.join(&r.path)).map_err(|e| e.message)?;
    if read.bytes.len() as u64 != r.bytes || read.sha256 != r.sha256 {
        return Err("index artifact digest/byte length mismatch".into());
    }
    serde_json::from_slice(&read.bytes).map_err(|e| e.to_string())
}
fn han(c: char) -> bool {
    matches!(c as u32,0x3400..=0x4dbf|0x4e00..=0x9fff|0xf900..=0xfaff|0x20000..=0x323af)
}
/// Repeated terms retain tf. `exact:` preserves case and full qualified names/error codes;
/// `fold:` applies NFC then Unicode lowercase without merging source identities;
/// `cjk:` emits Han unigrams and overlapping bigrams. Identifier component terms
/// supplement the full token; each occurrence contributes once to each channel.
pub fn tokenize(text: &str) -> Vec<String> {
    let mut raw = lexical_terms(text);
    raw.retain(|term| !term.starts_with("fold:"));
    let normalized: String = text.nfc().collect();
    raw.extend(
        lexical_terms(&normalized)
            .into_iter()
            .filter(|term| term.starts_with("fold:")),
    );
    raw
}
fn lexical_terms(text: &str) -> Vec<String> {
    let mut terms = Vec::new();
    for run in text
        .split(|c: char| {
            !(c.is_alphanumeric()
                || unicode_normalization::char::canonical_combining_class(c) != 0
                || matches!(c, '_' | '.' | ':' | '-'))
        })
        .filter(|s| !s.is_empty())
    {
        let run = run.trim_matches(['.', ':', '-']);
        if run.is_empty() {
            continue;
        }
        let mut pieces = BTreeSet::new();
        pieces.insert(run.to_string());
        for component in run.split(['.', ':', '_', '-']).filter(|s| !s.is_empty()) {
            pieces.insert(component.into());
            let chars: Vec<_> = component.char_indices().collect();
            let mut start = 0;
            for i in 1..chars.len() {
                let current = chars[i].1;
                let prev = chars[i - 1].1;
                let next = chars.get(i + 1).map(|x| x.1);
                if current.is_uppercase()
                    && (prev.is_lowercase()
                        || prev.is_numeric()
                        || next.is_some_and(char::is_lowercase))
                {
                    pieces.insert(component[start..chars[i].0].into());
                    start = chars[i].0;
                }
            }
            pieces.insert(component[start..].into());
        }
        for p in pieces.into_iter().filter(|s| !s.is_empty()) {
            terms.push(format!("exact:{p}"));
            terms.push(format!(
                "fold:{}",
                p.nfc().flat_map(char::to_lowercase).collect::<String>()
            ));
        }
        for sequence in run.split(|c: char| !han(c)).filter(|s| !s.is_empty()) {
            let cs: Vec<char> = sequence.chars().collect();
            for c in &cs {
                terms.push(format!("cjk:{c}"));
            }
            for pair in cs.windows(2) {
                terms.push(format!("cjk:{}{}", pair[0], pair[1]));
            }
        }
    }
    terms
}
pub fn token_bucket(term: &str) -> String {
    plain_hash(term.as_bytes())[..2].into()
}
fn chunk_id(snapshot: &str, path: &str, start: usize, end: usize) -> Result<String, String> {
    json_hash(&(snapshot, path, start, end, CHUNKER, TOKENIZER))
}
fn frontmatter_end(text: &str) -> usize {
    let mut lines = text.split_inclusive('\n');
    if lines.next().map(str::trim) != Some("---") {
        return 0;
    }
    let mut offset = text.find('\n').map_or(text.len(), |n| n + 1);
    for line in lines {
        offset += line.len();
        if matches!(line.trim(), "---" | "...") {
            return offset;
        }
    }
    0
}
#[derive(Clone)]
struct Unit {
    start: usize,
    end: usize,
    parent: Option<ChunkParent>,
}
fn units(path: &str, text: &str, facts: Option<&ExtractedFile>) -> Vec<Unit> {
    let markdown = path.ends_with(".md") || path.ends_with(".markdown");
    let begin = if markdown { frontmatter_end(text) } else { 0 };
    let mut boundaries = BTreeSet::from([begin, text.len()]);
    let mut parents = Vec::new();
    if let Some(file) = facts.filter(|f| f.parse_status == "parsed" && f.variant_status == "active")
    {
        for d in &file.declarations {
            if matches!(
                d.kind.as_str(),
                "function" | "method" | "type" | "class" | "interface"
            ) && d.span.byte_start >= begin
                && d.span.byte_end <= text.len()
                && text.is_char_boundary(d.span.byte_start)
                && text.is_char_boundary(d.span.byte_end)
            {
                boundaries.insert(d.span.byte_start);
                boundaries.insert(d.span.byte_end);
                parents.push(ChunkParent {
                    kind: d.kind.clone(),
                    name: d.name.clone(),
                    byte_start: d.span.byte_start,
                    byte_end: d.span.byte_end,
                });
            }
        }
    } else if markdown {
        let mut headings = Vec::new();
        let mut offset = begin;
        for line in text[begin..].split_inclusive('\n') {
            let trimmed = line.trim_start();
            if trimmed.starts_with('#') && trimmed.trim_start_matches('#').starts_with(' ') {
                headings.push((offset, trimmed.trim_start_matches('#').trim().to_string()));
                boundaries.insert(offset);
            }
            offset += line.len();
        }
        for (i, (start, name)) in headings.iter().enumerate() {
            let end = headings.get(i + 1).map_or(text.len(), |h| h.0);
            parents.push(ChunkParent {
                kind: "markdown_section".into(),
                name: name.clone(),
                byte_start: *start,
                byte_end: end,
            });
        }
    } else if path.ends_with(".toml") || path.ends_with(".ini") {
        let mut sections = Vec::new();
        let mut offset = begin;
        for line in text[begin..].split_inclusive('\n') {
            let t = line.trim();
            if t.starts_with('[') && t.ends_with(']') {
                sections.push((offset, t.trim_matches(['[', ']']).to_string()));
                boundaries.insert(offset);
            }
            offset += line.len();
        }
        for (i, (start, name)) in sections.iter().enumerate() {
            parents.push(ChunkParent {
                kind: "configuration_group".into(),
                name: name.clone(),
                byte_start: *start,
                byte_end: sections.get(i + 1).map_or(text.len(), |h| h.0),
            });
        }
    }
    let points: Vec<_> = boundaries.into_iter().collect();
    points
        .windows(2)
        .filter(|p| p[0] < p[1])
        .map(|p| Unit {
            start: p[0],
            end: p[1],
            parent: parents
                .iter()
                .filter(|par| par.byte_start <= p[0] && par.byte_end >= p[1])
                .min_by_key(|par| par.byte_end - par.byte_start)
                .cloned(),
        })
        .collect()
}
fn split_unit(text: &str, unit: &Unit) -> Vec<Unit> {
    let mut chunks = Vec::new();
    let mut start = unit.start;
    while start < unit.end {
        let tail = &text[start..unit.end];
        let chars: Vec<(usize, char)> = tail.char_indices().take(1025).collect();
        if chars.len() <= 512 {
            chunks.push(Unit {
                start,
                end: unit.end,
                parent: unit.parent.clone(),
            });
            break;
        }
        let target = chars.get(512).map_or(tail.len(), |x| x.0);
        let max = chars.get(1024).map_or(tail.len(), |x| x.0);
        let line_boundary = tail[..target].rfind('\n').map(|n| n + 1).filter(|n| *n > 0);
        let end_relative = if let Some(n) = line_boundary {
            n
        } else if let Some(n) = tail[target..max].find('\n') {
            target + n + 1
        } else {
            target
        };
        let end = start + end_relative;
        if end <= start {
            break;
        }
        chunks.push(Unit {
            start,
            end,
            parent: unit.parent.clone(),
        });
        start = end;
    }
    chunks
}
fn line_at(text: &str, byte: usize) -> usize {
    text.as_bytes()[..byte]
        .iter()
        .filter(|b| **b == b'\n')
        .count()
        + 1
}
/// Build validates the complete archive once. Empty facts select explicit unverified
/// code-text chunking; they never assert verified syntax or semantic knowledge.
pub fn build(
    context: &CallContext,
    workspace: &Path,
    source_ref: &FileReceiptRef,
    facts: &[ExtractedFile],
) -> Result<FileReceiptRef, String> {
    let (ledger, _): (source::SourceCoverageLedger, _) =
        artifact::read(context, workspace, source_ref)?;
    let analysis_context = AnalysisContext {
        snapshot_id: ledger.snapshot_id,
        ..Default::default()
    };
    build_with_context(context, workspace, source_ref, facts, &analysis_context)
}
/// Every supplied fact is re-extracted from original bytes using this exact context.
pub fn build_with_context(
    context: &CallContext,
    workspace: &Path,
    source_ref: &FileReceiptRef,
    facts: &[ExtractedFile],
    analysis_context: &AnalysisContext,
) -> Result<FileReceiptRef, String> {
    build_with_graph(
        context,
        workspace,
        source_ref,
        facts,
        analysis_context,
        None,
    )
}
/// Build the lexical projection with an optional independently replayed call graph.
pub fn build_with_graph(
    context: &CallContext,
    workspace: &Path,
    source_ref: &FileReceiptRef,
    facts: &[ExtractedFile],
    analysis_context: &AnalysisContext,
    graph_ref: Option<&FileReceiptRef>,
) -> Result<FileReceiptRef, String> {
    let root = artifact::workspace(context, workspace)?;
    super::query::initialize_authority(context, &root)?;
    let (ledger, source_path): (source::SourceCoverageLedger, _) =
        artifact::read(context, &root, source_ref)?;
    let archive = source_path
        .parent()
        .ok_or("source archive parent missing")?;
    let checked = source::load_archive(archive).map_err(|e| e.to_string())?;
    if checked != ledger {
        return Err("source ledger changed during index admission".into());
    }
    let archive_root = archive
        .strip_prefix(&root)
        .map_err(|_| "archive outside workspace")?
        .to_str()
        .ok_or("non-UTF8 archive path")?
        .to_string();
    relative(&archive_root)?;
    if analysis_context.snapshot_id != ledger.snapshot_id {
        return Err("analysis context snapshot differs from source".into());
    }
    let analysis_context_digest = context_digest(analysis_context);
    let graph_bytes = if let Some(reference) = graph_ref {
        let g = super::graph_projection::verify_source_projection(context, &root, reference)?;
        if g.source_ref != *source_ref
            || g.snapshot_id != ledger.snapshot_id
            || g.source_commit != ledger.source_commit
            || g.source_tree != ledger.source_tree
            || g.context_digest != analysis_context_digest
        {
            return Err("graph/index source or context identity mismatch".into());
        }
        g.total_graph_bytes
    } else {
        0
    };
    let leaves: HashMap<_, _> = ledger.leaves.iter().map(|l| (l.path.as_str(), l)).collect();
    let mut fact_map = BTreeMap::new();
    for fact in facts {
        let leaf = leaves
            .get(fact.path.as_str())
            .ok_or("fact path not in source ledger")?;
        if fact.snapshot_id != ledger.snapshot_id
            || fact.context_digest != analysis_context_digest
            || leaf.scope != Scope::Included
            || leaf.text != TextStatus::Extracted
            || leaf.main_route != MainRoute::Code
            || leaf.content_sha256.as_ref().map(|s| format!("sha256:{s}"))
                != Some(fact.file_sha.clone())
            || fact_map.insert(fact.path.clone(), fact).is_some()
        {
            return Err("facts require unique current source paths and byte identity".into());
        }
    }
    let generation = json_hash(&(
        source_ref,
        &fact_map,
        &analysis_context_digest,
        graph_ref,
        "index-source-binding-r4-adaptive-posting-partitions",
        CHUNKER,
        TOKENIZER,
        QUERY_POLICY,
    ))?;
    let index_root = format!(".gtkg/qk/index/{generation}");
    let mut router = buckets();
    let mut chunk_router = buckets();
    let mut posting_shards: Vec<BTreeMap<String, Vec<Posting>>> = vec![BTreeMap::new(); 256];
    let mut chunk_shards: Vec<BTreeMap<String, ArtifactRef>> = vec![BTreeMap::new(); 256];
    let mut total_chunks = 0usize;
    let mut total_tokens = 0u64;
    let mut total_bytes = graph_bytes;
    for leaf in &ledger.leaves {
        if leaf.scope != Scope::Included || leaf.text != TextStatus::Extracted {
            continue;
        }
        let object_sha = leaf
            .object_sha256
            .as_ref()
            .ok_or("text source is not archived")?;
        let bytes = source::read_object(archive, object_sha).map_err(|e| e.to_string())?;
        let text = std::str::from_utf8(&bytes).map_err(|_| "archived text is not UTF8")?;
        let fact = fact_map.get(&leaf.path).copied();
        if let Some(f) = fact {
            let replay =
                extract(&leaf.path, &bytes, analysis_context).map_err(|e| e.to_string())?;
            if &replay != f {
                return Err(
                    "facts differ from independent original-source extraction under frozen context"
                        .into(),
                );
            }
            for d in &f.declarations {
                if d.span.byte_start > d.span.byte_end
                    || d.span.byte_end > text.len()
                    || d.name_span.byte_start > d.name_span.byte_end
                    || d.name_span.byte_end > text.len()
                    || text.get(d.name_span.byte_start..d.name_span.byte_end)
                        != Some(d.name.as_str())
                {
                    return Err("fact declaration source span is invalid".into());
                }
            }
        }
        let parts: Vec<Unit> = units(&leaf.path, text, fact)
            .into_iter()
            .flat_map(|u| split_unit(text, &u))
            .collect();
        let ids: Vec<String> = parts
            .iter()
            .map(|p| chunk_id(&ledger.snapshot_id, &leaf.path, p.start, p.end))
            .collect::<Result<_, _>>()?;
        for (i, part) in parts.iter().enumerate() {
            let body = &text[part.start..part.end];
            if body.is_empty() {
                continue;
            }
            let tokens = body.chars().count();
            if tokens > 1024 {
                return Err("chunk exceeds codepoint budget".into());
            }
            let role = match leaf.main_route {
                MainRoute::Code => {
                    if fact
                        .is_some_and(|f| f.parse_status == "parsed" && f.variant_status == "active")
                    {
                        "source_code"
                    } else {
                        "code_text_unverified"
                    }
                }
                _ => {
                    if leaf.path.ends_with(".md") {
                        "document_body"
                    } else {
                        "configuration_or_text"
                    }
                }
            };
            let chunk = EvidenceChunk {
                schema: CHUNK_SCHEMA.into(),
                id: ids[i].clone(),
                snapshot_id: ledger.snapshot_id.clone(),
                source_commit: ledger.source_commit.clone(),
                source_tree: ledger.source_tree.clone(),
                path: leaf.path.clone(),
                file_sha: leaf.content_sha256.clone().ok_or("content hash absent")?,
                object_sha: object_sha.clone(),
                object_bytes: leaf.byte_len,
                byte_start: part.start,
                byte_end: part.end,
                line_start: line_at(text, part.start),
                line_end: line_at(text, part.end.saturating_sub(1)),
                language: leaf.language.clone().unwrap_or_else(|| "text".into()),
                role: role.into(),
                text: body.into(),
                tokens: tokens as u32,
                parent: part.parent.clone(),
                previous: i.checked_sub(1).map(|j| ids[j].clone()),
                next: ids.get(i + 1).cloned(),
                chunker: CHUNKER.into(),
                tokenizer: TOKENIZER.into(),
            };
            let reference = publish(
                context,
                &root,
                &format!("{index_root}/chunks/{}.json", chunk.id),
                &chunk,
            )?;
            total_bytes = total_bytes
                .checked_add(reference.bytes)
                .ok_or("index size overflow")?;
            let bucket = usize::from_str_radix(&chunk.id[..2], 16).map_err(|e| e.to_string())?;
            chunk_shards[bucket].insert(chunk.id.clone(), reference.clone());
            let mut tf: BTreeMap<String, u32> = BTreeMap::new();
            for term in tokenize(body) {
                let n = tf.entry(term).or_default();
                *n = n.saturating_add(1);
            }
            for (term, term_frequency) in tf {
                let b =
                    usize::from_str_radix(&token_bucket(&term), 16).map_err(|e| e.to_string())?;
                posting_shards[b].entry(term).or_default().push(Posting {
                    chunk_id: chunk.id.clone(),
                    chunk_ref: reference.clone(),
                    term_frequency,
                    tokens: chunk.tokens,
                });
            }
            total_chunks += 1;
            total_tokens += tokens as u64;
        }
    }
    for b in 0..256 {
        let key = format!("{b:02x}");
        if !posting_shards[b].is_empty() {
            let mut terms = std::mem::take(&mut posting_shards[b]);
            for postings in terms.values_mut() {
                postings.sort_by(|a, b| a.chunk_id.cmp(&b.chunk_id));
            }
            let mut shard = PostingShard {
                schema: "gtkg.qk.posting-shard/v1".into(),
                snapshot_id: ledger.snapshot_id.clone(),
                index_root: index_root.clone(),
                bucket: key.clone(),
                terms,
                partitions: BTreeMap::new(),
            };
            // Keep small buckets compact; partition large buckets by one more
            // hash digit without changing tokenization, postings, or query limits.
            if shard.terms.values().map(Vec::len).sum::<usize>() > 1024 {
                let mut parts: Vec<BTreeMap<String, Vec<Posting>>> = vec![BTreeMap::new(); 16];
                for (term, posts) in std::mem::take(&mut shard.terms) {
                    let b = usize::from_str_radix(&plain_hash(term.as_bytes())[2..3], 16)
                        .map_err(|e| e.to_string())?;
                    parts[b].insert(term, posts);
                }
                shard.schema = "gtkg.qk.posting-partitions/v2".into();
                for (b, terms) in parts.into_iter().enumerate() {
                    let prefix = format!("{key}{b:x}");
                    let r = if terms.is_empty() {
                        None
                    } else {
                        let child = PostingShard {
                            schema: "gtkg.qk.posting-shard/v1".into(),
                            snapshot_id: ledger.snapshot_id.clone(),
                            index_root: index_root.clone(),
                            bucket: prefix.clone(),
                            terms,
                            partitions: BTreeMap::new(),
                        };
                        let r = publish(
                            context,
                            &root,
                            &format!("{index_root}/postings/{key}/{b:x}.json"),
                            &child,
                        )?;
                        total_bytes += r.bytes;
                        Some(r)
                    };
                    shard.partitions.insert(prefix, r);
                }
            }
            let r = publish(
                context,
                &root,
                &format!("{index_root}/postings/{key}.json"),
                &shard,
            )?;
            total_bytes += r.bytes;
            router.insert(key.clone(), Some(r));
        }
        if !chunk_shards[b].is_empty() {
            let shard = ChunkShard {
                schema: "gtkg.qk.chunk-router-shard/v1".into(),
                snapshot_id: ledger.snapshot_id.clone(),
                index_root: index_root.clone(),
                bucket: key.clone(),
                chunks: std::mem::take(&mut chunk_shards[b]),
            };
            let r = publish(
                context,
                &root,
                &format!("{index_root}/chunk-router/{key}.json"),
                &shard,
            )?;
            total_bytes += r.bytes;
            chunk_router.insert(key, Some(r));
        }
    }
    let mut manifest = IndexManifest {
        schema: INDEX_SCHEMA.into(),
        profile: PROFILE.into(),
        snapshot_id: ledger.snapshot_id,
        source_commit: ledger.source_commit,
        source_tree: ledger.source_tree,
        source_ref: source_ref.clone(),
        graph_ref: graph_ref.cloned(),
        archive_root,
        index_root: index_root.clone(),
        chunker: CHUNKER.into(),
        tokenizer: TOKENIZER.into(),
        query_policy: QUERY_POLICY.into(),
        analysis_context_digest,
        total_chunks,
        total_tokens,
        total_index_bytes: total_bytes,
        router,
        chunk_router,
    };
    // Include exact root bytes in the denominator; the decimal-length fixed point stabilizes quickly.
    for _ in 0..8 {
        let bytes = serde_json::to_vec_pretty(&manifest)
            .map_err(|e| e.to_string())?
            .len() as u64;
        let next = total_bytes + bytes;
        if next == manifest.total_index_bytes {
            break;
        }
        manifest.total_index_bytes = next;
    }
    let r = publish(
        context,
        &root,
        &format!("{index_root}/manifest.json"),
        &manifest,
    )?;
    Ok(FileReceiptRef {
        path: r.path,
        sha256: r.sha256,
    })
}
#[cfg(test)]
std::thread_local! {
    static MANIFEST_VALIDATIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

pub(crate) fn validate_manifest(m: &IndexManifest) -> Result<(), String> {
    #[cfg(test)]
    MANIFEST_VALIDATIONS.with(|count| count.set(count.get() + 1));
    if m.schema != INDEX_SCHEMA
        || m.profile != PROFILE
        || m.chunker != CHUNKER
        || m.tokenizer != TOKENIZER
        || m.query_policy != QUERY_POLICY
        || !hex_id(&m.snapshot_id)
        || m.analysis_context_digest
            .strip_prefix("sha256:")
            .is_none_or(|s| !hex_id(s))
    {
        return Err("unsupported or invalid index identity".into());
    }
    relative(&m.archive_root)?;
    relative(&m.index_root)?;
    m.source_ref.validate().map_err(|e| e.to_string())?;
    if let Some(r) = &m.graph_ref {
        r.validate().map_err(|e| e.to_string())?;
    }
    if m.source_ref.path != format!("{}/{}", m.archive_root, source::LEDGER_FILE) {
        return Err("source reference/archive root mismatch".into());
    }
    for (routes, directory) in [(&m.router, "postings"), (&m.chunk_router, "chunk-router")] {
        if routes.len() != 256 {
            return Err("complete 256-bucket router required".into());
        }
        for b in 0..256 {
            let key = format!("{b:02x}");
            let r = routes.get(&key).ok_or("router missing bucket")?;
            if let Some(r) = r {
                checked_ref(r)?;
                if r.path != format!("{}/{directory}/{key}.json", m.index_root) {
                    return Err("router artifact path mismatch".into());
                }
            }
        }
    }
    Ok(())
}
/// Read only the caller-pinned root manifest. Other shards/objects remain unverified.
pub fn load_manifest(
    context: &CallContext,
    workspace: &Path,
    index_ref: &FileReceiptRef,
) -> Result<IndexManifest, String> {
    load_manifest_with_io(context, workspace, index_ref).map(|(m, _)| m)
}
/// Return exact opened bytes so every query read can be charged.
pub fn load_manifest_with_io(
    context: &CallContext,
    workspace: &Path,
    index_ref: &FileReceiptRef,
) -> Result<(IndexManifest, u64), String> {
    let (manifest, bytes, _) = read_manifest(context, workspace, index_ref)?;
    Ok((manifest, bytes))
}

fn read_manifest(
    context: &CallContext,
    workspace: &Path,
    index_ref: &FileReceiptRef,
) -> Result<(IndexManifest, u64, PathBuf), String> {
    index_ref.validate().map_err(|e| e.to_string())?;
    let root = artifact::workspace(context, workspace)?;
    let path = root.join(&index_ref.path);
    let read = read_bound_regular_file(context, &path).map_err(|e| e.message)?;
    if read.sha256 != index_ref.sha256 {
        return Err("index manifest digest mismatch".into());
    }
    let m: IndexManifest = serde_json::from_slice(&read.bytes).map_err(|e| e.to_string())?;
    validate_manifest(&m)?;
    if path != root.join(&m.index_root).join("manifest.json") {
        return Err("index root location mismatch".into());
    }
    Ok((m, read.bytes.len() as u64, root))
}

/// One query's immutable, authenticated manifest and authorized read context.
/// Only the pinned manifest read can create this value. No caller can replace
/// its manifest, workspace or context after the complete root validation.
pub(crate) struct QueryIndexReader<'a> {
    context: &'a CallContext,
    workspace: PathBuf,
    manifest: IndexManifest,
}

impl<'a> QueryIndexReader<'a> {
    pub(crate) fn load(
        context: &'a CallContext,
        workspace: &Path,
        index_ref: &FileReceiptRef,
    ) -> Result<(Self, u64), String> {
        let (manifest, bytes, workspace) = read_manifest(context, workspace, index_ref)?;
        Ok((
            Self {
                context,
                workspace,
                manifest,
            },
            bytes,
        ))
    }

    pub(crate) fn manifest(&self) -> &IndexManifest {
        &self.manifest
    }

    pub(crate) fn load_chunk(&self, posting: &Posting) -> Result<EvidenceChunk, String> {
        read_chunk(self.context, &self.workspace, &self.manifest, posting)
    }

    pub(crate) fn lookup_chunk_ref(&self, id: &str) -> Result<(ArtifactRef, u64), String> {
        read_chunk_ref(self.context, &self.workspace, &self.manifest, id)
    }

    pub(crate) fn load_chunk_by_id(&self, id: &str) -> Result<EvidenceChunk, String> {
        read_chunk_by_id(self.context, &self.workspace, &self.manifest, id)
    }

    pub(crate) fn load_source_binding(&self) -> Result<(SourceBinding, u64), String> {
        read_source_binding(self.context, &self.workspace, &self.manifest)
    }

    pub(crate) fn validate_chunk_source_with_binding(
        &self,
        chunk: &EvidenceChunk,
        binding: &SourceBinding,
    ) -> Result<u64, String> {
        check_chunk_source_with_binding(
            self.context,
            &self.workspace,
            &self.manifest,
            chunk,
            binding,
        )
    }
}
pub(crate) fn validate_posting(m: &IndexManifest, p: &Posting) -> Result<(), String> {
    checked_ref(&p.chunk_ref)?;
    if !hex_id(&p.chunk_id)
        || p.chunk_ref.path != format!("{}/chunks/{}.json", m.index_root, p.chunk_id)
        || p.term_frequency == 0
        || p.tokens == 0
        || p.tokens > 1024
    {
        return Err("invalid posting/chunk reference".into());
    }
    Ok(())
}
/// Exactly one selected posting shard is read (zero for an explicitly empty bucket).
/// Callers can charge its manifest ref.bytes before calling, including repeated reads.
pub fn load_postings(
    context: &CallContext,
    workspace: &Path,
    m: &IndexManifest,
    term: &str,
) -> Result<Vec<Posting>, String> {
    load_postings_bounded(context, workspace, m, term, usize::MAX).map(|(p, _)| p)
}
/// Count and bound every posting validated in the selected leaf, including
/// non-matching terms. Routing-only files contain no postings.
pub fn load_postings_bounded(
    context: &CallContext,
    workspace: &Path,
    m: &IndexManifest,
    term: &str,
    remaining: usize,
) -> Result<(Vec<Posting>, usize), String> {
    let selection = select_postings(context, workspace, m, term)?;
    load_selected_postings(context, workspace, m, term, selection, remaining)
}
pub(crate) fn validate_posting_container(
    m: &IndexManifest,
    shard: &PostingShard,
    bucket: &str,
) -> Result<(), String> {
    if shard.snapshot_id != m.snapshot_id
        || shard.index_root != m.index_root
        || shard.bucket != bucket
        || !matches!(bucket.len(), 2 | 3)
    {
        return Err("posting shard identity mismatch".into());
    }
    if shard.schema == "gtkg.qk.posting-partitions/v2" {
        if bucket.len() != 2 || !shard.terms.is_empty() || shard.partitions.len() != 16 {
            return Err("invalid posting partition router".into());
        }
        for b in 0..16 {
            let prefix = format!("{bucket}{b:x}");
            let r = shard
                .partitions
                .get(&prefix)
                .ok_or("posting partition missing")?;
            if let Some(r) = r {
                checked_ref(r)?;
                if r.path != format!("{}/postings/{bucket}/{b:x}.json", m.index_root) {
                    return Err("posting partition path mismatch".into());
                }
            }
        }
    } else if shard.schema != "gtkg.qk.posting-shard/v1" || !shard.partitions.is_empty() {
        return Err("invalid posting leaf schema".into());
    }
    for key in shard.terms.keys() {
        if !plain_hash(key.as_bytes()).starts_with(bucket) {
            return Err("term belongs to another routing bucket".into());
        }
    }
    Ok(())
}
pub(crate) fn select_postings(
    context: &CallContext,
    workspace: &Path,
    m: &IndexManifest,
    term: &str,
) -> Result<Option<PostingSelection>, String> {
    validate_manifest(m)?;
    let bucket = token_bucket(term);
    let Some(r) = m.router.get(&bucket).ok_or("router incomplete")? else {
        return Ok(None);
    };
    let shard: PostingShard = read_ref(context, workspace, r)?;
    validate_posting_container(m, &shard, &bucket)?;
    let prefix = plain_hash(term.as_bytes())[..3].to_string();
    let selected = if shard.partitions.is_empty() {
        None
    } else {
        shard
            .partitions
            .get(&prefix)
            .ok_or("posting partition missing")?
            .clone()
    };
    Ok(Some(PostingSelection {
        shard,
        selected,
        bucket: prefix,
    }))
}
pub(crate) fn load_selected_postings(
    context: &CallContext,
    workspace: &Path,
    m: &IndexManifest,
    term: &str,
    selection: Option<PostingSelection>,
    remaining: usize,
) -> Result<(Vec<Posting>, usize), String> {
    let Some(selection) = selection else {
        return Ok((vec![], 0));
    };
    let shard = if !selection.shard.partitions.is_empty() {
        let Some(r) = selection.selected else {
            return Ok((vec![], 0));
        };
        let child: PostingShard = read_ref(context, workspace, &r)?;
        validate_posting_container(m, &child, &selection.bucket)?;
        child
    } else {
        selection.shard
    };
    let scanned = shard.terms.values().map(Vec::len).sum::<usize>();
    if scanned > remaining {
        return Err("E_POSTING_BUDGET".into());
    }
    for postings in shard.terms.values() {
        let mut previous = None;
        for p in postings {
            validate_posting(m, p)?;
            if previous.is_some_and(|s: &str| s >= p.chunk_id.as_str()) {
                return Err("duplicate/unordered posting".into());
            }
            previous = Some(p.chunk_id.as_str());
        }
    }
    Ok((shard.terms.get(term).cloned().unwrap_or_default(), scanned))
}
pub(crate) fn validate_chunk(m: &IndexManifest, c: &EvidenceChunk) -> Result<(), String> {
    relative(&c.path)?;
    if c.schema != CHUNK_SCHEMA
        || c.snapshot_id != m.snapshot_id
        || c.source_commit != m.source_commit
        || c.source_tree != m.source_tree
        || c.chunker != m.chunker
        || c.tokenizer != m.tokenizer
        || !hex_id(&c.file_sha)
        || c.file_sha != c.object_sha
        || !hex_id(&c.id)
        || c.id != chunk_id(&c.snapshot_id, &c.path, c.byte_start, c.byte_end)?
        || c.byte_start >= c.byte_end
        || c.byte_end as u64 > c.object_bytes
        || c.byte_end - c.byte_start != c.text.len()
        || c.tokens as usize != c.text.chars().count()
        || c.tokens > 1024
        || c.tokens == 0
        || c.line_start == 0
        || c.line_end < c.line_start
    {
        return Err("chunk identity/span/budget mismatch".into());
    }
    if c.previous.as_ref().is_some_and(|id| !hex_id(id))
        || c.next.as_ref().is_some_and(|id| !hex_id(id))
    {
        return Err("invalid neighbor identity".into());
    }
    if let Some(p) = &c.parent
        && (p.byte_start > c.byte_start
            || p.byte_end < c.byte_end
            || p.byte_end as u64 > c.object_bytes)
    {
        return Err("parent does not contain chunk".into());
    }
    Ok(())
}
/// Verify only the selected chunk's bytes/identity. This does not reread its source object.
pub fn load_chunk(
    context: &CallContext,
    workspace: &Path,
    m: &IndexManifest,
    p: &Posting,
) -> Result<EvidenceChunk, String> {
    validate_manifest(m)?;
    read_chunk(context, workspace, m, p)
}

fn read_chunk(
    context: &CallContext,
    workspace: &Path,
    m: &IndexManifest,
    p: &Posting,
) -> Result<EvidenceChunk, String> {
    validate_posting(m, p)?;
    let c: EvidenceChunk = read_ref(context, workspace, &p.chunk_ref)?;
    validate_chunk(m, &c)?;
    if c.id != p.chunk_id || c.tokens != p.tokens {
        return Err("posting/chunk identity mismatch".into());
    }
    Ok(c)
}
/// Neighbor lookup reads one chunk-router shard plus the selected chunk; charge both refs.
pub fn lookup_chunk_ref(
    context: &CallContext,
    workspace: &Path,
    m: &IndexManifest,
    id: &str,
) -> Result<(ArtifactRef, u64), String> {
    validate_manifest(m)?;
    read_chunk_ref(context, workspace, m, id)
}

fn read_chunk_ref(
    context: &CallContext,
    workspace: &Path,
    m: &IndexManifest,
    id: &str,
) -> Result<(ArtifactRef, u64), String> {
    if !hex_id(id) {
        return Err("invalid chunk ID".into());
    }
    let bucket = &id[..2];
    let r = m
        .chunk_router
        .get(bucket)
        .ok_or("chunk router incomplete")?
        .as_ref()
        .ok_or("chunk absent")?;
    let shard: ChunkShard = read_ref(context, workspace, r)?;
    if shard.schema != "gtkg.qk.chunk-router-shard/v1"
        || shard.snapshot_id != m.snapshot_id
        || shard.index_root != m.index_root
        || shard.bucket != bucket
    {
        return Err("chunk router identity mismatch".into());
    }
    for (key, r) in &shard.chunks {
        if !hex_id(key)
            || &key[..2] != bucket
            || r.path != format!("{}/chunks/{key}.json", m.index_root)
        {
            return Err("chunk router entry mismatch".into());
        }
        checked_ref(r)?;
    }
    let found = shard
        .chunks
        .get(id)
        .ok_or("chunk absent from declared shard")?;
    Ok((found.clone(), r.bytes))
}
pub fn load_chunk_by_id(
    context: &CallContext,
    workspace: &Path,
    m: &IndexManifest,
    id: &str,
) -> Result<EvidenceChunk, String> {
    validate_manifest(m)?;
    read_chunk_by_id(context, workspace, m, id)
}

fn read_chunk_by_id(
    context: &CallContext,
    workspace: &Path,
    m: &IndexManifest,
    id: &str,
) -> Result<EvidenceChunk, String> {
    let (r, _) = read_chunk_ref(context, workspace, m, id)?;
    let c: EvidenceChunk = read_ref(context, workspace, &r)?;
    validate_chunk(m, &c)?;
    if c.id != id {
        return Err("chunk ID mismatch".into());
    }
    Ok(c)
}
/// A caller cannot fabricate path-to-object membership: only load_source_binding
/// can construct this value from the manifest-pinned source ledger.
#[derive(Debug)]
pub struct SourceBinding {
    source_ref: FileReceiptRef,
    snapshot_id: String,
    source_commit: String,
    source_tree: String,
    entries: BTreeMap<String, (String, String, u64)>,
}
/// Read the pinned ledger once, without reading graph/shards/source objects.
/// The second return value is the exact number of ledger bytes read.
pub fn load_source_binding(
    context: &CallContext,
    workspace: &Path,
    m: &IndexManifest,
) -> Result<(SourceBinding, u64), String> {
    validate_manifest(m)?;
    read_source_binding(context, workspace, m)
}

fn read_source_binding(
    context: &CallContext,
    workspace: &Path,
    m: &IndexManifest,
) -> Result<(SourceBinding, u64), String> {
    let root = artifact::workspace(context, workspace)?;
    let raw =
        read_bound_regular_file(context, &root.join(&m.source_ref.path)).map_err(|e| e.message)?;
    if raw.sha256 != m.source_ref.sha256 {
        return Err("source binding ledger digest mismatch".into());
    }
    let ledger: source::SourceCoverageLedger =
        serde_json::from_slice(&raw.bytes).map_err(|e| e.to_string())?;
    if ledger.schema_version != "gtkg.qk.source-coverage-ledger/v1"
        || ledger.snapshot_id != m.snapshot_id
        || ledger.source_commit != m.source_commit
        || ledger.source_tree != m.source_tree
    {
        return Err("source binding identity differs from index".into());
    }
    let mut paths = BTreeSet::new();
    let mut entries = BTreeMap::new();
    for leaf in &ledger.leaves {
        relative(&leaf.path)?;
        if !paths.insert(&leaf.path) {
            return Err("duplicate source ledger path".into());
        }
        if leaf.scope == Scope::Included && leaf.text == TextStatus::Extracted {
            let file = leaf
                .content_sha256
                .as_ref()
                .ok_or("text source digest absent")?;
            let object = leaf
                .object_sha256
                .as_ref()
                .ok_or("text object digest absent")?;
            if !hex_id(file) || file != object {
                return Err("source path/object identity invalid".into());
            }
            entries.insert(
                leaf.path.clone(),
                (file.clone(), object.clone(), leaf.byte_len),
            );
        }
    }
    Ok((
        SourceBinding {
            source_ref: m.source_ref.clone(),
            snapshot_id: m.snapshot_id.clone(),
            source_commit: m.source_commit.clone(),
            source_tree: m.source_tree.clone(),
            entries,
        },
        raw.bytes.len() as u64,
    ))
}
/// Reuse one authenticated source binding for a query. This call reads exactly
/// object_bytes, including repeated calls; callers precharge that amount.
pub fn validate_chunk_source_with_binding(
    context: &CallContext,
    workspace: &Path,
    m: &IndexManifest,
    c: &EvidenceChunk,
    binding: &SourceBinding,
) -> Result<u64, String> {
    validate_manifest(m)?;
    check_chunk_source_with_binding(context, workspace, m, c, binding)
}

fn check_chunk_source_with_binding(
    context: &CallContext,
    workspace: &Path,
    m: &IndexManifest,
    c: &EvidenceChunk,
    binding: &SourceBinding,
) -> Result<u64, String> {
    validate_chunk(m, c)?;
    if binding.source_ref != m.source_ref
        || binding.snapshot_id != m.snapshot_id
        || binding.source_commit != m.source_commit
        || binding.source_tree != m.source_tree
        || binding.entries.get(&c.path)
            != Some(&(c.file_sha.clone(), c.object_sha.clone(), c.object_bytes))
    {
        return Err("chunk path is not bound to this source object in the pinned ledger".into());
    }
    let root = artifact::workspace(context, workspace)?;
    let archive = root.join(&m.archive_root);
    context
        .authorize_read(&archive)
        .map_err(|e| e.to_string())?;
    let bytes = source::read_object(&archive, &c.object_sha).map_err(|e| e.to_string())?;
    if bytes.len() as u64 != c.object_bytes
        || bytes.get(c.byte_start..c.byte_end) != Some(c.text.as_bytes())
    {
        return Err("source span does not match chunk".into());
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| "source object no longer UTF8")?;
    if !text.is_char_boundary(c.byte_start)
        || !text.is_char_boundary(c.byte_end)
        || line_at(text, c.byte_start) != c.line_start
        || line_at(text, c.byte_end - 1) != c.line_end
    {
        return Err("source line/span mapping mismatch".into());
    }
    Ok(bytes.len() as u64)
}
/// Complete standalone verification. The returned IO is ledger bytes plus
/// object bytes. Query loops should load SourceBinding once and use the method above.
pub fn validate_chunk_source(
    context: &CallContext,
    workspace: &Path,
    m: &IndexManifest,
    c: &EvidenceChunk,
) -> Result<u64, String> {
    let (binding, ledger_bytes) = load_source_binding(context, workspace, m)?;
    Ok(ledger_bytes + validate_chunk_source_with_binding(context, workspace, m, c, &binding)?)
}

#[cfg(test)]
#[path = "../../tests/support/v04_performance_readers.rs"]
mod performance_reader_tests;

#[cfg(test)]
#[path = "../../tests/support/v04_checked_reader_boundaries.rs"]
mod checked_reader_boundary_tests;
