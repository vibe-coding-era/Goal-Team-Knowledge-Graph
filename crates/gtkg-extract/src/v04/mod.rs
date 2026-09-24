//! Source-only successor extraction. No filesystem access or target execution.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const EXTRACTOR_PROFILE: &str = "gtkg.qk.extractor/v1";
pub mod binding;
mod go_variants;
mod rust;
mod trees;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnalysisContext {
    pub snapshot_id: String,
    pub profile: String,
    pub goos: String,
    pub goarch: String,
    pub build_tags: Vec<String>,
    pub cgo: bool,
    pub include_tests: bool,
    /// Frozen import module -> source file or directory mapping. No stem search.
    pub import_modules: BTreeMap<String, String>,
}
impl Default for AnalysisContext {
    fn default() -> Self {
        Self {
            snapshot_id: "unspecified".into(),
            profile: EXTRACTOR_PROFILE.into(),
            goos: "darwin".into(),
            goarch: "arm64".into(),
            build_tags: vec![],
            cgo: false,
            include_tests: false,
            import_modules: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Span {
    pub byte_start: usize,
    pub byte_end: usize,
    pub line_start: usize,
    pub line_end: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    pub id: String,
    pub parent: Option<String>,
    pub kind: String,
    pub name: String,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Declaration {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub scope_id: String,
    pub span: Span,
    pub name_span: Span,
    pub signature: String,
    /// callable, non_callable, or unknown; syntax does not prove runtime dispatch.
    pub callability: String,
    pub receiver_type: Option<String>,
    pub type_hint: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Import {
    pub module: String,
    /// Empty for Go imports without a written alias: package name requires mapped source.
    pub alias: String,
    pub symbol: Option<String>,
    pub scope_id: String,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallSite {
    pub id: String,
    pub scope_id: String,
    pub expression: String,
    pub callee: String,
    pub receiver: Option<String>,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtractedFile {
    pub schema: String,
    pub path: String,
    pub language: String,
    pub file_sha: String,
    pub snapshot_id: String,
    pub extractor_profile: String,
    pub parser_identity: String,
    pub context_digest: String,
    pub package: Option<String>,
    pub parse_status: String,
    pub semantic_status: String,
    pub variant_status: String,
    pub limitations: Vec<String>,
    pub scopes: Vec<Scope>,
    pub declarations: Vec<Declaration>,
    pub imports: Vec<Import>,
    pub calls: Vec<CallSite>,
}

#[derive(Debug, thiserror::Error)]
pub enum ExtractError {
    #[error("unsupported language: {0}")]
    Unsupported(String),
    #[error("source is not UTF-8")]
    Utf8,
    #[error("parser unavailable: {0}")]
    Parser(String),
}

pub fn digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}
pub fn context_digest(context: &AnalysisContext) -> String {
    digest(&serde_json::to_vec(context).unwrap_or_default())
}

pub fn extract(
    path: &str,
    bytes: &[u8],
    context: &AnalysisContext,
) -> Result<ExtractedFile, ExtractError> {
    let source = std::str::from_utf8(bytes).map_err(|_| ExtractError::Utf8)?;
    let (language, parser) = match path.rsplit('.').next().unwrap_or("") {
        "go" => ("go", "tree-sitter-go/0.23.4/abi14"),
        "py" | "pyi" => ("python", "tree-sitter-python/0.23.6"),
        "ts" | "tsx" | "mts" | "cts" => ("typescript", "tree-sitter-typescript/0.23.2"),
        "js" | "jsx" | "mjs" | "cjs" => ("javascript", "tree-sitter-javascript/0.23.1"),
        "rs" => ("rust", "syn/2.0.119"),
        _ => return Err(ExtractError::Unsupported(path.into())),
    };
    let mut b = Builder::new(path, source, language, parser, context);
    if language == "rust" {
        rust::extract(&mut b);
    } else {
        trees::extract(&mut b)?;
    }
    if language == "go" {
        go_variants::apply(&mut b, context);
    }
    if source
        .lines()
        .any(|l| l.contains("Code generated") && l.contains("DO NOT EDIT"))
    {
        b.limit("generated_source");
    }
    b.file
        .declarations
        .sort_by_key(|d| (d.name_span.byte_start, d.kind.clone()));
    b.file.calls.sort_by_key(|c| c.span.byte_start);
    b.file.imports.sort_by_key(|i| i.span.byte_start);
    b.file.limitations.sort();
    b.file.limitations.dedup();
    Ok(b.file)
}

struct Builder<'a> {
    source: &'a str,
    file: ExtractedFile,
    stack: Vec<String>,
    line_starts: Vec<usize>,
}
impl<'a> Builder<'a> {
    fn new(
        path: &str,
        source: &'a str,
        language: &str,
        parser: &str,
        context: &AnalysisContext,
    ) -> Self {
        let mut b = Self {
            source,
            stack: vec![],
            line_starts: std::iter::once(0)
                .chain(
                    source
                        .bytes()
                        .enumerate()
                        .filter_map(|(i, x)| (x == b'\n').then_some(i + 1)),
                )
                .collect(),
            file: ExtractedFile {
                schema: "gtkg.qk.extracted-file/v1".into(),
                path: path.into(),
                language: language.into(),
                file_sha: digest(source.as_bytes()),
                snapshot_id: context.snapshot_id.clone(),
                extractor_profile: EXTRACTOR_PROFILE.into(),
                parser_identity: parser.into(),
                context_digest: context_digest(context),
                package: None,
                parse_status: "parsed".into(),
                semantic_status: "analyzed".into(),
                variant_status: "active".into(),
                limitations: vec![],
                scopes: vec![],
                declarations: vec![],
                imports: vec![],
                calls: vec![],
            },
        };
        b.push_scope("module", path, 0, source.len());
        b
    }
    fn span(&self, start: usize, end: usize) -> Span {
        Span {
            byte_start: start,
            byte_end: end,
            line_start: self.line_starts.partition_point(|x| *x <= start),
            line_end: self
                .line_starts
                .partition_point(|x| *x <= end.saturating_sub(usize::from(end > start))),
        }
    }
    fn text(&self, start: usize, end: usize) -> String {
        self.source.get(start..end).unwrap_or("").to_owned()
    }
    fn scope(&self) -> String {
        self.stack.last().cloned().unwrap_or_default()
    }
    fn identity(&self, kind: &str, start: usize, end: usize, scope: &str) -> String {
        digest(
            format!(
                "{}\0{}\0{}\0{}\0{}\0{}\0{kind}\0{start}\0{end}\0{scope}",
                self.file.snapshot_id,
                self.file.path,
                self.file.file_sha,
                self.file.extractor_profile,
                self.file.parser_identity,
                self.file.context_digest
            )
            .as_bytes(),
        )
    }
    fn push_scope(&mut self, kind: &str, name: &str, start: usize, end: usize) {
        let id = self.identity(
            "scope",
            start,
            end,
            &format!("{}:{kind}:{name}", self.scope()),
        );
        self.file.scopes.push(Scope {
            id: id.clone(),
            parent: self.stack.last().cloned(),
            kind: kind.into(),
            name: name.into(),
            span: self.span(start, end),
        });
        self.stack.push(id);
    }
    fn pop_scope(&mut self) {
        self.stack.pop();
    }
    #[allow(clippy::too_many_arguments)] // Raw syntax ranges stay explicit at parser call sites.
    fn decl(
        &mut self,
        kind: &str,
        name_start: usize,
        name_end: usize,
        start: usize,
        end: usize,
        sig_end: usize,
        callability: &str,
        receiver: Option<String>,
        type_hint: Option<String>,
    ) {
        let name = self.text(name_start, name_end);
        if name.is_empty() {
            return;
        }
        self.file.declarations.push(Declaration {
            id: self.identity("declaration", name_start, name_end, &self.scope()),
            name,
            kind: kind.into(),
            scope_id: self.scope(),
            span: self.span(start, end),
            name_span: self.span(name_start, name_end),
            signature: self.text(start, sig_end).trim().to_owned(),
            callability: callability.into(),
            receiver_type: receiver,
            type_hint,
        });
    }
    fn import(
        &mut self,
        module: String,
        alias: String,
        symbol: Option<String>,
        start: usize,
        end: usize,
    ) {
        self.file.imports.push(Import {
            module,
            alias,
            symbol,
            scope_id: self.scope(),
            span: self.span(start, end),
        });
    }
    fn call(&mut self, start: usize, end: usize, callee: String, receiver: Option<String>) {
        self.file.calls.push(CallSite {
            id: self.identity("call", start, end, &self.scope()),
            scope_id: self.scope(),
            expression: self.text(start, end),
            callee,
            receiver,
            span: self.span(start, end),
        });
    }
    fn limit(&mut self, reason: &str) {
        self.file.limitations.push(reason.into());
    }
    fn parse_error(&mut self) {
        self.file.parse_status = "error".into();
        self.file.semantic_status = "partial".into();
        self.limit("parse_error");
    }
}

fn clean_type(value: &str) -> String {
    value
        .trim()
        .trim_start_matches(':')
        .trim()
        .trim_start_matches('&')
        .trim_start_matches("mut ")
        .trim_start_matches('*')
        .trim()
        .to_owned()
}
