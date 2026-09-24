//! AST/syntax-level semantic extraction for Rust, Python, TypeScript, and
//! JavaScript (E02).
//!
//! Everything here is static analysis: parsers turn untrusted source bytes into
//! a syntax tree as data; no target code is ever compiled or executed. A source
//! that fails to parse yields `None` and the caller degrades to the legacy
//! lexical facts. Records are sorted, deduplicated, and pinned by a digest so
//! identical inputs always produce identical outputs.

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

use crate::CodeLanguage;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DefinitionRecord {
    pub kind: &'static str,
    pub name: String,
    pub start: usize,
    pub end: usize,
    pub line_start: u64,
    pub line_end: u64,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ImportEdge {
    pub module: String,
    pub start: usize,
    pub end: usize,
    pub line: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CallEdge {
    pub caller: String,
    pub callee: String,
    pub start: usize,
    pub end: usize,
    pub line: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InheritEdge {
    pub child: String,
    pub parent: String,
    pub start: usize,
    pub end: usize,
    pub line: u64,
}

#[derive(Debug, Default)]
pub(crate) struct CodeSemantics {
    pub engine: &'static str,
    pub definitions: Vec<DefinitionRecord>,
    pub imports: Vec<ImportEdge>,
    pub calls: Vec<CallEdge>,
    pub inherits: Vec<InheritEdge>,
}

struct LineIndex {
    starts: Vec<usize>,
}

impl LineIndex {
    fn new(source: &str) -> Self {
        let mut starts = vec![0];
        for (offset, byte) in source.bytes().enumerate() {
            if byte == b'\n' {
                starts.push(offset + 1);
            }
        }
        Self { starts }
    }

    /// 1-based line number containing `offset`.
    fn line(&self, offset: usize) -> u64 {
        self.starts.partition_point(|start| *start <= offset) as u64
    }
}

pub(crate) fn analyze(source: &str, language: CodeLanguage) -> Option<CodeSemantics> {
    match language {
        CodeLanguage::Rust => rust::analyze(source),
        CodeLanguage::Python => python::analyze(source),
        CodeLanguage::TypeScript => typescript::analyze(source),
        CodeLanguage::JavaScript => javascript::analyze(source),
    }
}

/// Serializes semantic records into deterministic observation sections. The
/// legacy lexical observations and `observed_facts` are untouched.
pub(crate) fn apply_observations(
    result: Option<&CodeSemantics>,
    observations: &mut BTreeMap<String, String>,
) {
    let Some(semantics) = result else {
        observations.insert("semantic_mode".to_owned(), "fallback_lexical".to_owned());
        return;
    };
    observations.insert("semantic_mode".to_owned(), "ast".to_owned());
    observations.insert("semantic_engine".to_owned(), semantics.engine.to_owned());

    let mut definition_lines = semantics
        .definitions
        .iter()
        .map(|record| {
            format!(
                "{}\t{}\t{}\t{}\t{}\t{}\t{}",
                record.kind,
                record.name,
                record.start,
                record.end,
                record.line_start,
                record.line_end,
                record.signature
            )
        })
        .collect::<Vec<_>>();
    definition_lines.sort();
    definition_lines.dedup();
    let definitions = definition_lines.join("\n");

    let mut import_lines = semantics
        .imports
        .iter()
        .map(|edge| {
            format!(
                "{}\t{}\t{}\t{}",
                edge.module, edge.start, edge.end, edge.line
            )
        })
        .collect::<Vec<_>>();
    import_lines.sort();
    import_lines.dedup();
    let imports = import_lines.join("\n");

    let mut call_lines = semantics
        .calls
        .iter()
        .map(|edge| {
            format!(
                "{}\t{}\t{}\t{}\t{}",
                edge.caller, edge.callee, edge.start, edge.end, edge.line
            )
        })
        .collect::<Vec<_>>();
    call_lines.sort();
    call_lines.dedup();
    let calls = call_lines.join("\n");

    let mut inherit_lines = semantics
        .inherits
        .iter()
        .map(|edge| {
            format!(
                "{}\t{}\t{}\t{}\t{}",
                edge.child, edge.parent, edge.start, edge.end, edge.line
            )
        })
        .collect::<Vec<_>>();
    inherit_lines.sort();
    inherit_lines.dedup();
    let inherits = inherit_lines.join("\n");

    let digest = Sha256::digest(
        format!(
            "engine={}\ndefinitions:\n{definitions}\nimports:\n{imports}\ncalls:\n{calls}\ninherits:\n{inherits}\n",
            semantics.engine
        )
        .as_bytes(),
    );
    observations.insert("semantic_definitions".to_owned(), definitions);
    observations.insert("semantic_imports".to_owned(), imports);
    observations.insert("semantic_calls".to_owned(), calls);
    observations.insert("semantic_inherits".to_owned(), inherits);
    observations.insert(
        "semantic_definition_count".to_owned(),
        definition_lines.len().to_string(),
    );
    observations.insert(
        "semantic_import_count".to_owned(),
        import_lines.len().to_string(),
    );
    observations.insert(
        "semantic_call_count".to_owned(),
        call_lines.len().to_string(),
    );
    observations.insert(
        "semantic_inherit_count".to_owned(),
        inherit_lines.len().to_string(),
    );
    observations.insert("semantics_digest".to_owned(), format!("sha256:{digest:x}"));
}

fn normalize_signature(text: &str) -> String {
    let joined = text.split_whitespace().collect::<Vec<_>>().join(" ");
    joined
        .trim_end_matches([';', '{', ':', ','])
        .trim_end()
        .to_owned()
}

mod rust {
    use syn::spanned::Spanned;
    use syn::visit::{self, Visit};
    use syn::{Expr, Fields, ImplItem, Item, TraitItem, Type, UseTree};

    use super::{
        CallEdge, CodeSemantics, DefinitionRecord, ImportEdge, InheritEdge, LineIndex,
        normalize_signature,
    };

    pub(super) fn analyze(source: &str) -> Option<CodeSemantics> {
        let file = syn::parse_file(source).ok()?;
        let mut visitor = RustVisitor {
            source,
            lines: LineIndex::new(source),
            callers: Vec::new(),
            semantics: CodeSemantics {
                engine: "syn/2",
                ..CodeSemantics::default()
            },
        };
        visitor.visit_file(&file);
        Some(visitor.semantics)
    }

    struct RustVisitor<'a> {
        source: &'a str,
        lines: LineIndex,
        callers: Vec<String>,
        semantics: CodeSemantics,
    }

    impl RustVisitor<'_> {
        fn caller(&self) -> String {
            self.callers
                .last()
                .cloned()
                .unwrap_or_else(|| "<module>".to_owned())
        }

        fn push_definition(
            &mut self,
            kind: &'static str,
            name: String,
            name_span: std::ops::Range<usize>,
            signature_start: usize,
            signature_end: usize,
            item_end: usize,
        ) {
            let signature = self
                .source
                .get(signature_start..signature_end)
                .map(normalize_signature)
                .unwrap_or_default();
            if signature.is_empty() {
                return;
            }
            self.semantics.definitions.push(DefinitionRecord {
                kind,
                line_start: self.lines.line(name_span.start),
                line_end: self.lines.line(item_end),
                name,
                start: name_span.start,
                end: name_span.end,
                signature,
            });
        }

        fn record_fn(
            &mut self,
            kind: &'static str,
            signature: &syn::Signature,
            block: Option<&syn::Block>,
            fallback_end: usize,
        ) -> String {
            let name = signature.ident.to_string();
            let name_span = signature.ident.span().byte_range();
            let signature_start = signature.fn_token.span.byte_range().start;
            let signature_end = block.map_or(fallback_end, |block| {
                block.brace_token.span.open().byte_range().start
            });
            self.push_definition(
                kind,
                name.clone(),
                name_span,
                signature_start,
                signature_end,
                block.map_or(fallback_end, |block| {
                    block.brace_token.span.join().byte_range().end
                }),
            );
            name
        }

        fn record_call(&mut self, callee: String, span: std::ops::Range<usize>) {
            self.semantics.calls.push(CallEdge {
                caller: self.caller(),
                callee,
                line: self.lines.line(span.start),
                start: span.start,
                end: span.end,
            });
        }

        fn walk_use_tree(&mut self, tree: &UseTree, prefix: String) {
            match tree {
                UseTree::Path(path) => {
                    self.walk_use_tree(&path.tree, format!("{prefix}{}::", path.ident));
                }
                UseTree::Name(name) => {
                    let span = name.ident.span().byte_range();
                    self.semantics.imports.push(ImportEdge {
                        module: format!("{prefix}{}", name.ident),
                        line: self.lines.line(span.start),
                        start: span.start,
                        end: span.end,
                    });
                }
                UseTree::Rename(rename) => {
                    let span = rename.ident.span().byte_range();
                    self.semantics.imports.push(ImportEdge {
                        module: format!("{prefix}{}", rename.ident),
                        line: self.lines.line(span.start),
                        start: span.start,
                        end: span.end,
                    });
                }
                UseTree::Glob(glob) => {
                    let span = glob.star_token.span.byte_range();
                    self.semantics.imports.push(ImportEdge {
                        module: format!("{prefix}*"),
                        line: self.lines.line(span.start),
                        start: span.start,
                        end: span.end,
                    });
                }
                UseTree::Group(group) => {
                    for tree in &group.items {
                        self.walk_use_tree(tree, prefix.clone());
                    }
                }
            }
        }
    }

    fn type_last_segment(ty: &Type) -> Option<(String, std::ops::Range<usize>)> {
        if let Type::Path(path) = ty
            && let Some(segment) = path.path.segments.last()
        {
            return Some((segment.ident.to_string(), segment.ident.span().byte_range()));
        }
        None
    }

    impl<'ast> Visit<'ast> for RustVisitor<'_> {
        fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
            let name = self.record_fn(
                "function",
                &node.sig,
                Some(&node.block),
                node.span().byte_range().end,
            );
            self.callers.push(name);
            visit::visit_block(self, &node.block);
            self.callers.pop();
        }

        fn visit_item_struct(&mut self, node: &'ast syn::ItemStruct) {
            let name_span = node.ident.span().byte_range();
            let signature_start = node.struct_token.span.byte_range().start;
            let item_end = node.span().byte_range().end;
            let signature_end = match &node.fields {
                Fields::Named(fields) => fields.brace_token.span.open().byte_range().start,
                _ => item_end,
            };
            self.push_definition(
                "struct",
                node.ident.to_string(),
                name_span,
                signature_start,
                signature_end,
                item_end,
            );
            if let Fields::Named(fields) = &node.fields {
                for field in &fields.named {
                    if let Some(ident) = &field.ident {
                        let field_span = field.span().byte_range();
                        self.push_definition(
                            "field",
                            ident.to_string(),
                            ident.span().byte_range(),
                            field_span.start,
                            field_span.end,
                            field_span.end,
                        );
                    }
                }
            }
        }

        fn visit_item_enum(&mut self, node: &'ast syn::ItemEnum) {
            self.push_definition(
                "enum",
                node.ident.to_string(),
                node.ident.span().byte_range(),
                node.enum_token.span.byte_range().start,
                node.brace_token.span.open().byte_range().start,
                node.brace_token.span.join().byte_range().end,
            );
        }

        fn visit_item_trait(&mut self, node: &'ast syn::ItemTrait) {
            self.push_definition(
                "trait",
                node.ident.to_string(),
                node.ident.span().byte_range(),
                node.trait_token.span.byte_range().start,
                node.brace_token.span.open().byte_range().start,
                node.brace_token.span.join().byte_range().end,
            );
            for item in &node.items {
                if let TraitItem::Fn(method) = item {
                    let fallback_end = method.span().byte_range().end;
                    let name = self.record_fn(
                        "method",
                        &method.sig,
                        method.default.as_ref(),
                        fallback_end,
                    );
                    if let Some(block) = &method.default {
                        self.callers.push(name);
                        visit::visit_block(self, block);
                        self.callers.pop();
                    }
                }
            }
        }

        fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
            let impl_span = node.span().byte_range();
            let self_segment = type_last_segment(&node.self_ty);
            if let Some((self_name, self_span)) = &self_segment {
                self.push_definition(
                    "impl",
                    self_name.clone(),
                    self_span.clone(),
                    node.impl_token.span.byte_range().start,
                    node.brace_token.span.open().byte_range().start,
                    node.brace_token.span.join().byte_range().end,
                );
                if let Some((_, trait_path, _)) = &node.trait_
                    && let Some(segment) = trait_path.segments.last()
                {
                    let parent_span = segment.ident.span().byte_range();
                    self.semantics.inherits.push(InheritEdge {
                        child: self_name.clone(),
                        parent: segment.ident.to_string(),
                        line: self.lines.line(parent_span.start),
                        start: parent_span.start,
                        end: parent_span.end,
                    });
                }
            }
            let _ = impl_span;
            for item in &node.items {
                if let ImplItem::Fn(method) = item {
                    let fallback_end = method.span().byte_range().end;
                    let name =
                        self.record_fn("method", &method.sig, Some(&method.block), fallback_end);
                    self.callers.push(name);
                    visit::visit_block(self, &method.block);
                    self.callers.pop();
                }
            }
        }

        fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
            let item_end = node.span().byte_range().end;
            let signature_end = node
                .content
                .as_ref()
                .map_or(item_end, |(brace, _)| brace.span.open().byte_range().start);
            self.push_definition(
                "module",
                node.ident.to_string(),
                node.ident.span().byte_range(),
                node.mod_token.span.byte_range().start,
                signature_end,
                item_end,
            );
            if let Some((_, items)) = &node.content {
                for item in items {
                    self.visit_item(item);
                }
            }
        }

        fn visit_item_type(&mut self, node: &'ast syn::ItemType) {
            let item_end = node.span().byte_range().end;
            self.push_definition(
                "type",
                node.ident.to_string(),
                node.ident.span().byte_range(),
                node.type_token.span.byte_range().start,
                item_end,
                item_end,
            );
        }

        fn visit_item_const(&mut self, node: &'ast syn::ItemConst) {
            let item_end = node.span().byte_range().end;
            self.push_definition(
                "variable",
                node.ident.to_string(),
                node.ident.span().byte_range(),
                node.const_token.span.byte_range().start,
                item_end,
                item_end,
            );
        }

        fn visit_item_static(&mut self, node: &'ast syn::ItemStatic) {
            let item_end = node.span().byte_range().end;
            self.push_definition(
                "variable",
                node.ident.to_string(),
                node.ident.span().byte_range(),
                node.static_token.span.byte_range().start,
                item_end,
                item_end,
            );
        }

        fn visit_item_use(&mut self, node: &'ast syn::ItemUse) {
            self.walk_use_tree(&node.tree, String::new());
        }

        fn visit_item(&mut self, node: &'ast Item) {
            visit::visit_item(self, node);
        }

        fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
            self.record_call(node.method.to_string(), node.method.span().byte_range());
            visit::visit_expr_method_call(self, node);
        }

        fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
            if let Expr::Path(path) = &*node.func
                && let Some(segment) = path.path.segments.last()
            {
                self.record_call(segment.ident.to_string(), segment.ident.span().byte_range());
            }
            visit::visit_expr_call(self, node);
        }
    }
}

/// Shared tree-sitter walker state for the Python/TypeScript/JavaScript
/// grammars.
struct TreeWalk<'a> {
    source: &'a str,
    lines: LineIndex,
    callers: Vec<String>,
    semantics: CodeSemantics,
}

impl<'a> TreeWalk<'a> {
    fn new(source: &'a str, engine: &'static str) -> Self {
        Self {
            source,
            lines: LineIndex::new(source),
            callers: Vec::new(),
            semantics: CodeSemantics {
                engine,
                ..CodeSemantics::default()
            },
        }
    }

    fn text(&self, node: tree_sitter::Node<'_>) -> Option<&'a str> {
        node.utf8_text(self.source.as_bytes()).ok()
    }

    fn caller(&self) -> String {
        self.callers
            .last()
            .cloned()
            .unwrap_or_else(|| "<module>".to_owned())
    }

    fn push_definition(
        &mut self,
        kind: &'static str,
        name_node: tree_sitter::Node<'_>,
        signature_start: usize,
        signature_end: usize,
        item_end: usize,
    ) {
        let Some(name) = self.text(name_node) else {
            return;
        };
        if name.is_empty() {
            return;
        }
        let signature = self
            .source
            .get(signature_start..signature_end)
            .map(normalize_signature)
            .unwrap_or_default();
        if signature.is_empty() {
            return;
        }
        self.semantics.definitions.push(DefinitionRecord {
            kind,
            name: name.to_owned(),
            start: name_node.start_byte(),
            end: name_node.end_byte(),
            line_start: self.lines.line(name_node.start_byte()),
            line_end: self.lines.line(item_end),
            signature,
        });
    }

    fn push_import(&mut self, module: String, start: usize, end: usize) {
        self.semantics.imports.push(ImportEdge {
            module,
            line: self.lines.line(start),
            start,
            end,
        });
    }

    fn push_call(&mut self, callee: String, start: usize, end: usize) {
        self.semantics.calls.push(CallEdge {
            caller: self.caller(),
            callee,
            line: self.lines.line(start),
            start,
            end,
        });
    }

    fn push_inherit(&mut self, child: String, parent: String, start: usize, end: usize) {
        self.semantics.inherits.push(InheritEdge {
            child,
            parent,
            line: self.lines.line(start),
            start,
            end,
        });
    }

    fn walk_children(&mut self, node: tree_sitter::Node<'a>, in_class: bool) {
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            self.walk(child, in_class);
        }
    }

    fn walk(&mut self, node: tree_sitter::Node<'a>, in_class: bool) {
        match node.kind() {
            "function_definition" => {
                let in_class = in_class
                    || node.parent().is_some_and(|parent| {
                        parent.kind() == "decorated_definition" && {
                            parent
                                .parent()
                                .and_then(|grand| grand.parent())
                                .is_some_and(|great| great.kind() == "class_definition")
                        }
                    });
                let Some(name) = node.child_by_field_name("name") else {
                    return self.walk_children(node, in_class);
                };
                let body = node.child_by_field_name("body");
                let signature_end = body.map_or(node.end_byte(), |body| body.start_byte());
                self.push_definition(
                    if in_class { "method" } else { "function" },
                    name,
                    node.start_byte(),
                    signature_end,
                    node.end_byte(),
                );
                let caller = self.text(name).unwrap_or("").to_owned();
                self.callers.push(caller);
                if let Some(body) = body {
                    self.walk_children(body, false);
                }
                self.callers.pop();
            }
            "class_definition" => {
                let Some(name) = node.child_by_field_name("name") else {
                    return self.walk_children(node, in_class);
                };
                let body = node.child_by_field_name("body");
                let signature_end = body.map_or(node.end_byte(), |body| body.start_byte());
                let class_name = self.text(name).unwrap_or("").to_owned();
                self.push_definition(
                    "class",
                    name,
                    node.start_byte(),
                    signature_end,
                    node.end_byte(),
                );
                if let Some(superclasses) = node.child_by_field_name("superclasses") {
                    let mut cursor = superclasses.walk();
                    for base in superclasses.named_children(&mut cursor) {
                        self.record_python_base(&class_name, base);
                    }
                }
                if let Some(body) = body {
                    self.walk_children(body, true);
                }
            }
            "decorated_definition" => self.walk_children(node, in_class),
            "import_statement" => self.record_python_import_statement(node),
            "import_from_statement" => self.record_python_from_import(node),
            "assignment" => {
                if node.parent().is_some_and(|parent| {
                    parent.kind() == "expression_statement"
                        && parent
                            .parent()
                            .is_some_and(|grand| grand.kind() == "module")
                }) && let Some(left) = node.child_by_field_name("left")
                    && left.kind() == "identifier"
                {
                    self.push_definition(
                        "variable",
                        left,
                        node.start_byte(),
                        node.end_byte(),
                        node.end_byte(),
                    );
                }
                if let Some(right) = node.child_by_field_name("right") {
                    self.walk(right, in_class);
                }
            }
            "call" => {
                if let Some(function) = node.child_by_field_name("function") {
                    match function.kind() {
                        "identifier" => {
                            if let Some(callee) = self.text(function) {
                                self.push_call(
                                    callee.to_owned(),
                                    function.start_byte(),
                                    function.end_byte(),
                                );
                            }
                        }
                        "attribute" => {
                            if let Some(attribute) = function.child_by_field_name("attribute")
                                && let Some(callee) = self.text(attribute)
                            {
                                self.push_call(
                                    callee.to_owned(),
                                    attribute.start_byte(),
                                    attribute.end_byte(),
                                );
                            }
                        }
                        _ => {}
                    }
                }
                self.walk_children(node, in_class);
            }
            _ => self.walk_children(node, in_class),
        }
    }

    fn record_python_base(&mut self, class_name: &str, base: tree_sitter::Node<'a>) {
        let target = match base.kind() {
            "identifier" => Some(base),
            "attribute" => base.child_by_field_name("attribute"),
            _ => None,
        };
        if let Some(target) = target
            && let Some(parent) = self.text(target)
        {
            self.push_inherit(
                class_name.to_owned(),
                parent.to_owned(),
                target.start_byte(),
                target.end_byte(),
            );
        }
    }

    fn record_python_import_statement(&mut self, node: tree_sitter::Node<'a>) {
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            let target = if child.kind() == "aliased_import" {
                child.child_by_field_name("name")
            } else {
                Some(child)
            };
            if let Some(target) = target
                && target.kind() == "dotted_name"
                && let Some(module) = self.text(target)
            {
                self.push_import(module.to_owned(), target.start_byte(), target.end_byte());
            }
        }
    }

    fn record_python_from_import(&mut self, node: tree_sitter::Node<'a>) {
        let Some(module_node) = node.child_by_field_name("module_name") else {
            return;
        };
        let Some(module) = self.text(module_node).map(str::to_owned) else {
            return;
        };
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if child.id() == module_node.id() || child.kind() == "wildcard_import" {
                continue;
            }
            let target = if child.kind() == "aliased_import" {
                child.child_by_field_name("name")
            } else {
                Some(child)
            };
            if let Some(target) = target
                && target.kind() == "dotted_name"
                && let Some(name) = self.text(target)
            {
                self.push_import(
                    format!("{module}.{name}"),
                    target.start_byte(),
                    target.end_byte(),
                );
            }
        }
    }
}

mod python {
    use super::{CodeSemantics, TreeWalk};

    pub(super) fn analyze(source: &str) -> Option<CodeSemantics> {
        let tree = parse_tree(source, &tree_sitter_python::LANGUAGE.into())?;
        let mut walk = TreeWalk::new(source, "tree-sitter-python/0.23");
        walk.walk(tree.root_node(), false);
        Some(walk.semantics)
    }

    fn parse_tree(source: &str, language: &tree_sitter::Language) -> Option<tree_sitter::Tree> {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(language).ok()?;
        let tree = parser.parse(source, None)?;
        (!tree.root_node().has_error()).then_some(tree)
    }
}

mod typescript {
    use super::{CodeSemantics, TreeWalk, ecmascript};

    pub(super) fn analyze(source: &str) -> Option<CodeSemantics> {
        let tree = ecmascript::parse(source, &tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
            .or_else(|| {
            ecmascript::parse(source, &tree_sitter_typescript::LANGUAGE_TSX.into())
        })?;
        let mut walk = TreeWalk::new(source, "tree-sitter-typescript/0.23");
        ecmascript::walk_module(&mut walk, tree.root_node());
        Some(walk.semantics)
    }
}

mod javascript {
    use super::{CodeSemantics, TreeWalk, ecmascript};

    pub(super) fn analyze(source: &str) -> Option<CodeSemantics> {
        let tree = ecmascript::parse(source, &tree_sitter_javascript::LANGUAGE.into())?;
        let mut walk = TreeWalk::new(source, "tree-sitter-javascript/0.23");
        ecmascript::walk_module(&mut walk, tree.root_node());
        Some(walk.semantics)
    }
}

/// TypeScript/JavaScript share the same declaration/expression vocabulary; the
/// walker only differs in the grammar used to build the tree.
mod ecmascript {
    use super::TreeWalk;

    pub(super) fn parse(
        source: &str,
        language: &tree_sitter::Language,
    ) -> Option<tree_sitter::Tree> {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(language).ok()?;
        let tree = parser.parse(source, None)?;
        (!tree.root_node().has_error()).then_some(tree)
    }

    pub(super) fn walk_module(walk: &mut TreeWalk<'_>, root: tree_sitter::Node<'_>) {
        let mut cursor = root.walk();
        for child in root.named_children(&mut cursor) {
            walk_node(walk, child);
        }
    }

    fn walk_children(walk: &mut TreeWalk<'_>, node: tree_sitter::Node<'_>) {
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            walk_node(walk, child);
        }
    }

    fn string_content(node: tree_sitter::Node<'_>) -> Option<(usize, usize)> {
        if node.kind() != "string" || node.end_byte() <= node.start_byte() + 1 {
            return None;
        }
        Some((node.start_byte() + 1, node.end_byte() - 1))
    }

    fn walk_node(walk: &mut TreeWalk<'_>, node: tree_sitter::Node<'_>) {
        match node.kind() {
            "function_declaration" | "generator_function_declaration" => {
                let Some(name) = node.child_by_field_name("name") else {
                    return walk_children(walk, node);
                };
                let body = node.child_by_field_name("body");
                let signature_end = body.map_or(node.end_byte(), |body| body.start_byte());
                walk.push_definition(
                    "function",
                    name,
                    node.start_byte(),
                    signature_end,
                    node.end_byte(),
                );
                let caller = walk.text(name).unwrap_or("").to_owned();
                walk.callers.push(caller);
                if let Some(body) = body {
                    walk_children(walk, body);
                }
                walk.callers.pop();
            }
            "method_definition" | "method_signature" => {
                let Some(name) = node.child_by_field_name("name") else {
                    return walk_children(walk, node);
                };
                let body = node.child_by_field_name("body");
                let signature_end = body.map_or(node.end_byte(), |body| body.start_byte());
                walk.push_definition(
                    "method",
                    name,
                    node.start_byte(),
                    signature_end,
                    node.end_byte(),
                );
                let caller = walk.text(name).unwrap_or("").to_owned();
                walk.callers.push(caller);
                if let Some(body) = body {
                    walk_children(walk, body);
                }
                walk.callers.pop();
            }
            "class_declaration" => {
                let Some(name) = node.child_by_field_name("name") else {
                    return walk_children(walk, node);
                };
                let body = node.child_by_field_name("body");
                let signature_end = body.map_or(node.end_byte(), |body| body.start_byte());
                let class_name = walk.text(name).unwrap_or("").to_owned();
                walk.push_definition(
                    "class",
                    name,
                    node.start_byte(),
                    signature_end,
                    node.end_byte(),
                );
                record_heritage(walk, &class_name, node, body);
                if let Some(body) = body {
                    walk_children(walk, body);
                }
            }
            "interface_declaration" => {
                let Some(name) = node.child_by_field_name("name") else {
                    return walk_children(walk, node);
                };
                let body = node.child_by_field_name("body");
                let signature_end = body.map_or(node.end_byte(), |body| body.start_byte());
                let interface_name = walk.text(name).unwrap_or("").to_owned();
                walk.push_definition(
                    "interface",
                    name,
                    node.start_byte(),
                    signature_end,
                    node.end_byte(),
                );
                record_heritage(walk, &interface_name, node, body);
                if let Some(body) = body {
                    walk_children(walk, body);
                }
            }
            "type_alias_declaration" => {
                if let Some(name) = node.child_by_field_name("name") {
                    walk.push_definition(
                        "type",
                        name,
                        node.start_byte(),
                        node.end_byte(),
                        node.end_byte(),
                    );
                }
            }
            "enum_declaration" => {
                if let Some(name) = node.child_by_field_name("name") {
                    let body = node.child_by_field_name("body");
                    let signature_end = body.map_or(node.end_byte(), |body| body.start_byte());
                    walk.push_definition(
                        "enum",
                        name,
                        node.start_byte(),
                        signature_end,
                        node.end_byte(),
                    );
                }
            }
            "lexical_declaration" | "variable_declaration" => {
                let mut cursor = node.walk();
                for child in node.named_children(&mut cursor) {
                    if child.kind() != "variable_declarator" {
                        continue;
                    }
                    let Some(name) = child.child_by_field_name("name") else {
                        continue;
                    };
                    if name.kind() == "identifier" {
                        walk.push_definition(
                            "variable",
                            name,
                            child.start_byte(),
                            child.end_byte(),
                            child.end_byte(),
                        );
                    }
                    if let Some(value) = child.child_by_field_name("value") {
                        if matches!(value.kind(), "arrow_function" | "function_expression")
                            && name.kind() == "identifier"
                        {
                            let caller = walk.text(name).unwrap_or("").to_owned();
                            walk.callers.push(caller);
                            walk_node(walk, value);
                            walk.callers.pop();
                        } else {
                            walk_node(walk, value);
                        }
                    }
                }
            }
            "arrow_function" | "function_expression" => {
                // Anonymous callbacks keep the enclosing caller; named bindings
                // were already pushed by the declarator case above.
                if let Some(body) = node.child_by_field_name("body") {
                    walk_children(walk, body);
                }
            }
            "public_field_definition" | "field_definition" | "property_signature" => {
                let name = node
                    .child_by_field_name("property")
                    .or_else(|| node.child_by_field_name("name"));
                if let Some(name) = name {
                    walk.push_definition(
                        "field",
                        name,
                        node.start_byte(),
                        node.end_byte(),
                        node.end_byte(),
                    );
                }
            }
            "import_statement" => {
                if let Some(source) = node.child_by_field_name("source")
                    && let Some((start, end)) = string_content(source)
                    && let Some(module) = walk.source.get(start..end)
                {
                    walk.push_import(module.to_owned(), start, end);
                }
            }
            "call_expression" => {
                if let Some(function) = node.child_by_field_name("function") {
                    match function.kind() {
                        "identifier" => {
                            let callee = walk.text(function).unwrap_or("");
                            if callee == "require" {
                                record_require(walk, node);
                            } else if !callee.is_empty() {
                                walk.push_call(
                                    callee.to_owned(),
                                    function.start_byte(),
                                    function.end_byte(),
                                );
                            }
                        }
                        "member_expression" => {
                            if let Some(property) = function.child_by_field_name("property")
                                && let Some(callee) = walk.text(property)
                            {
                                walk.push_call(
                                    callee.to_owned(),
                                    property.start_byte(),
                                    property.end_byte(),
                                );
                            }
                            // The receiver can itself be a call: `a.b().c()`.
                            walk_children(walk, function);
                        }
                        _ => {}
                    }
                }
                if let Some(arguments) = node.child_by_field_name("arguments") {
                    walk_children(walk, arguments);
                }
            }
            "new_expression" => {
                if let Some(constructor) = node.child_by_field_name("constructor") {
                    let target = if constructor.kind() == "member_expression" {
                        constructor.child_by_field_name("property")
                    } else {
                        Some(constructor)
                    };
                    if let Some(target) = target
                        && let Some(callee) = walk.text(target)
                    {
                        walk.push_call(callee.to_owned(), target.start_byte(), target.end_byte());
                    }
                }
                if let Some(arguments) = node.child_by_field_name("arguments") {
                    walk_children(walk, arguments);
                }
            }
            _ => walk_children(walk, node),
        }
    }

    fn record_require(walk: &mut TreeWalk<'_>, call: tree_sitter::Node<'_>) {
        let Some(arguments) = call.child_by_field_name("arguments") else {
            return;
        };
        if let Some(first) = arguments.named_child(0)
            && let Some((start, end)) = string_content(first)
            && let Some(module) = walk.source.get(start..end)
        {
            walk.push_import(module.to_owned(), start, end);
        }
    }

    /// Records extends/implements heritage. Only the clause nodes outside the
    /// class/interface body are inspected.
    fn record_heritage(
        walk: &mut TreeWalk<'_>,
        child_name: &str,
        node: tree_sitter::Node<'_>,
        body: Option<tree_sitter::Node<'_>>,
    ) {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if body.is_some_and(|body| body.id() == child.id()) {
                continue;
            }
            match child.kind() {
                "extends_clause" | "extends_type_clause" | "implements_clause" => {
                    record_clause(walk, child_name, child);
                }
                "class_heritage" => {
                    let mut inner = child.walk();
                    for clause in child.children(&mut inner) {
                        if matches!(
                            clause.kind(),
                            "extends_clause" | "extends_type_clause" | "implements_clause"
                        ) {
                            record_clause(walk, child_name, clause);
                        } else if matches!(clause.kind(), "identifier" | "member_expression") {
                            // tree-sitter-javascript puts the superclass
                            // expression directly inside `class_heritage`.
                            record_clause(walk, child_name, child);
                            break;
                        }
                    }
                }
                _ => {}
            }
        }
    }

    fn record_clause(walk: &mut TreeWalk<'_>, child_name: &str, clause: tree_sitter::Node<'_>) {
        let mut cursor = clause.walk();
        for part in clause.named_children(&mut cursor) {
            let target = match part.kind() {
                "identifier" | "type_identifier" | "property_identifier" => Some(part),
                "member_expression" => part.child_by_field_name("property"),
                "generic_type" => part
                    .child_by_field_name("name")
                    .or_else(|| part.named_child(0)),
                _ => None,
            };
            if let Some(target) = target
                && let Some(parent) = walk.text(target)
            {
                walk.push_inherit(
                    child_name.to_owned(),
                    parent.to_owned(),
                    target.start_byte(),
                    target.end_byte(),
                );
            }
        }
    }
}
