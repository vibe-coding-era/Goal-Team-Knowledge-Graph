use super::{Builder, clean_type};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};

pub(super) fn extract(b: &mut Builder<'_>) {
    match syn::parse_file(b.source) {
        Ok(file) => Walker { b, receiver: None }.visit_file(&file),
        Err(_) => b.parse_error(),
    }
}
struct Walker<'a, 's> {
    b: &'a mut Builder<'s>,
    receiver: Option<String>,
}
impl Walker<'_, '_> {
    fn text<T: Spanned>(&self, n: &T) -> String {
        let r = n.span().byte_range();
        self.b.text(r.start, r.end)
    }
    fn declaration<T: Spanned>(
        &mut self,
        n: &T,
        name: &syn::Ident,
        kind: &str,
        callability: &str,
        hint: Option<String>,
    ) {
        let r = n.span().byte_range();
        let nr = name.span().byte_range();
        self.b.decl(
            kind,
            nr.start,
            nr.end,
            r.start,
            r.end,
            r.end,
            callability,
            None,
            hint,
        );
    }
    fn signature(&mut self, s: &syn::Signature, end: usize, callability: &str) {
        let r = s.span().byte_range();
        let name = s.ident.span().byte_range();
        self.b.decl(
            if self.receiver.is_some() {
                "method"
            } else {
                "function"
            },
            name.start,
            name.end,
            r.start,
            end,
            r.end,
            callability,
            self.receiver.clone(),
            None,
        );
        self.b
            .push_scope("function", &s.ident.to_string(), r.start, end);
        for input in &s.inputs {
            match input {
                syn::FnArg::Typed(p) => self.pattern(
                    &p.pat,
                    "parameter",
                    "unknown",
                    Some(clean_type(&self.text(&p.ty))),
                ),
                syn::FnArg::Receiver(p) => {
                    let r = p.span().byte_range();
                    let name = p.self_token.span.byte_range();
                    self.b.decl(
                        "parameter",
                        name.start,
                        name.end,
                        r.start,
                        r.end,
                        r.end,
                        "unknown",
                        None,
                        self.receiver.clone(),
                    );
                }
            }
        }
        if !s.generics.params.is_empty() {
            self.b.limit("generic_type_solving_not_supported");
        }
    }
    fn pattern(&mut self, p: &syn::Pat, kind: &str, callability: &str, hint: Option<String>) {
        match p {
            syn::Pat::Ident(p) => self.declaration(p, &p.ident, kind, callability, hint),
            syn::Pat::Type(p) => self.pattern(
                &p.pat,
                kind,
                callability,
                Some(clean_type(&self.text(&p.ty))),
            ),
            syn::Pat::Tuple(p) => {
                for p in &p.elems {
                    self.pattern(p, kind, callability, None)
                }
            }
            syn::Pat::TupleStruct(p) => {
                for p in &p.elems {
                    self.pattern(p, kind, callability, None)
                }
            }
            syn::Pat::Struct(p) => {
                for p in &p.fields {
                    self.pattern(&p.pat, kind, callability, None)
                }
            }
            syn::Pat::Reference(p) => self.pattern(&p.pat, kind, callability, hint),
            syn::Pat::Slice(p) => {
                for p in &p.elems {
                    self.pattern(p, kind, callability, None)
                }
            }
            _ => self.b.limit("rust_pattern_binding_partial"),
        }
    }
    fn import(&mut self, n: &syn::UseTree, prefix: &str) {
        match n {
            syn::UseTree::Path(p) => self.import(&p.tree, &format!("{prefix}{}::", p.ident)),
            syn::UseTree::Name(p) => {
                let name = p.ident.to_string();
                let r = p.span().byte_range();
                self.b.import(
                    prefix.trim_end_matches("::").into(),
                    name.clone(),
                    Some(name),
                    r.start,
                    r.end,
                );
            }
            syn::UseTree::Rename(p) => {
                let r = p.span().byte_range();
                self.b.import(
                    prefix.trim_end_matches("::").into(),
                    p.rename.to_string(),
                    Some(p.ident.to_string()),
                    r.start,
                    r.end,
                );
            }
            syn::UseTree::Group(g) => {
                for n in &g.items {
                    self.import(n, prefix)
                }
            }
            syn::UseTree::Glob(_) => self.b.limit("wildcard_import_binding_not_supported"),
        }
    }
}
impl<'ast> Visit<'ast> for Walker<'_, '_> {
    fn visit_item_fn(&mut self, n: &'ast syn::ItemFn) {
        for attr in &n.attrs {
            self.visit_attribute(attr);
        }
        let previous = self.receiver.take();
        self.signature(&n.sig, n.span().byte_range().end, "callable");
        self.visit_block(&n.block);
        self.b.pop_scope();
        self.receiver = previous;
    }
    fn visit_item_impl(&mut self, n: &'ast syn::ItemImpl) {
        let previous = self.receiver.replace(clean_type(&self.text(&n.self_ty)));
        if n.trait_.is_some() {
            self.b.limit("trait_dispatch_requires_review");
        }
        if !n.generics.params.is_empty() {
            self.b.limit("generic_type_solving_not_supported");
        }
        let r = n.span().byte_range();
        self.b.push_scope(
            "impl",
            self.receiver.as_deref().unwrap_or("<impl>"),
            r.start,
            r.end,
        );
        for item in &n.items {
            self.visit_impl_item(item)
        }
        self.b.pop_scope();
        self.receiver = previous;
    }
    fn visit_impl_item_fn(&mut self, n: &'ast syn::ImplItemFn) {
        self.signature(&n.sig, n.span().byte_range().end, "callable");
        self.visit_block(&n.block);
        self.b.pop_scope();
    }
    fn visit_item_trait(&mut self, n: &'ast syn::ItemTrait) {
        self.declaration(n, &n.ident, "interface", "non_callable", None);
        self.b.limit("interface_dispatch_not_proven");
        let prev = self.receiver.replace(n.ident.to_string());
        let r = n.span().byte_range();
        self.b
            .push_scope("type", &n.ident.to_string(), r.start, r.end);
        for item in &n.items {
            self.visit_trait_item(item)
        }
        self.b.pop_scope();
        self.receiver = prev;
    }
    fn visit_trait_item_fn(&mut self, n: &'ast syn::TraitItemFn) {
        self.signature(&n.sig, n.span().byte_range().end, "unknown");
        if let Some(body) = &n.default {
            self.visit_block(body)
        }
        self.b.pop_scope();
    }
    fn visit_item_struct(&mut self, n: &'ast syn::ItemStruct) {
        self.declaration(n, &n.ident, "type", "non_callable", Some("struct".into()));
        let r = n.span().byte_range();
        self.b
            .push_scope("type", &n.ident.to_string(), r.start, r.end);
        for f in &n.fields {
            self.visit_field(f)
        }
        self.b.pop_scope();
    }
    fn visit_item_enum(&mut self, n: &'ast syn::ItemEnum) {
        self.declaration(n, &n.ident, "type", "non_callable", Some("enum".into()));
        let r = n.span().byte_range();
        self.b
            .push_scope("type", &n.ident.to_string(), r.start, r.end);
        for variant in &n.variants {
            self.declaration(variant, &variant.ident, "variant", "unknown", None);
            visit::visit_variant(self, variant);
        }
        self.b.pop_scope();
    }
    fn visit_item_type(&mut self, n: &'ast syn::ItemType) {
        self.declaration(n, &n.ident, "type", "non_callable", Some(self.text(&n.ty)));
    }
    fn visit_field(&mut self, n: &'ast syn::Field) {
        if let Some(name) = &n.ident {
            self.declaration(
                n,
                name,
                "field",
                "unknown",
                Some(clean_type(&self.text(&n.ty))),
            )
        } else {
            self.b.limit("tuple_field_has_no_explicit_name");
        }
    }
    fn visit_item_const(&mut self, n: &'ast syn::ItemConst) {
        self.declaration(
            n,
            &n.ident,
            "variable",
            expr_kind(&n.expr),
            Some(clean_type(&self.text(&n.ty))),
        );
        self.visit_expr(&n.expr);
    }
    fn visit_item_static(&mut self, n: &'ast syn::ItemStatic) {
        self.declaration(
            n,
            &n.ident,
            "variable",
            expr_kind(&n.expr),
            Some(clean_type(&self.text(&n.ty))),
        );
        self.visit_expr(&n.expr);
    }
    fn visit_item_mod(&mut self, n: &'ast syn::ItemMod) {
        self.declaration(n, &n.ident, "module", "non_callable", None);
        let r = n.span().byte_range();
        self.b
            .push_scope("module", &n.ident.to_string(), r.start, r.end);
        if let Some((_, items)) = &n.content {
            for item in items {
                self.visit_item(item)
            }
        } else {
            self.b.limit("external_module_requires_source_mapping");
        }
        self.b.pop_scope();
    }
    fn visit_item_use(&mut self, n: &'ast syn::ItemUse) {
        self.import(&n.tree, "");
    }
    fn visit_local(&mut self, n: &'ast syn::Local) {
        self.pattern(
            &n.pat,
            "variable",
            n.init.as_ref().map_or("unknown", |i| expr_kind(&i.expr)),
            None,
        );
        if let Some(i) = &n.init {
            self.visit_expr(&i.expr);
            if let Some((_, expr)) = &i.diverge {
                self.visit_expr(expr)
            }
        }
    }
    fn visit_block(&mut self, n: &'ast syn::Block) {
        let r = n.span().byte_range();
        self.b.push_scope("block", "<block>", r.start, r.end);
        visit::visit_block(self, n);
        self.b.pop_scope();
    }
    fn visit_expr_call(&mut self, n: &'ast syn::ExprCall) {
        let r = n.span().byte_range();
        let (callee, receiver) = match &*n.func {
            syn::Expr::Path(p) => {
                let parts: Vec<_> = p
                    .path
                    .segments
                    .iter()
                    .map(|s| s.ident.to_string())
                    .collect();
                (
                    parts.last().cloned().unwrap_or_default(),
                    (parts.len() > 1).then(|| parts[..parts.len() - 1].join("::")),
                )
            }
            _ => (self.text(&n.func), None),
        };
        self.b.call(r.start, r.end, callee, receiver);
        visit::visit_expr_call(self, n);
    }
    fn visit_expr_method_call(&mut self, n: &'ast syn::ExprMethodCall) {
        let r = n.span().byte_range();
        self.b.call(
            r.start,
            r.end,
            n.method.to_string(),
            Some(self.text(&n.receiver)),
        );
        visit::visit_expr_method_call(self, n);
    }
    fn visit_expr_closure(&mut self, n: &'ast syn::ExprClosure) {
        let r = n.span().byte_range();
        self.b.push_scope("function", "<anonymous>", r.start, r.end);
        for p in &n.inputs {
            self.pattern(p, "parameter", "unknown", None)
        }
        self.visit_expr(&n.body);
        self.b.pop_scope();
    }
    fn visit_expr_for_loop(&mut self, n: &'ast syn::ExprForLoop) {
        self.visit_expr(&n.expr);
        let r = n.span().byte_range();
        self.b.push_scope("block", "for", r.start, r.end);
        self.pattern(&n.pat, "variable", "unknown", None);
        self.visit_block(&n.body);
        self.b.pop_scope();
    }
    fn visit_expr_if(&mut self, n: &'ast syn::ExprIf) {
        let r = n.span().byte_range();
        self.b.push_scope("block", "if_condition", r.start, r.end);
        self.visit_expr(&n.cond);
        self.visit_block(&n.then_branch);
        self.b.pop_scope();
        if let Some((_, other)) = &n.else_branch {
            self.visit_expr(other)
        }
    }
    fn visit_expr_while(&mut self, n: &'ast syn::ExprWhile) {
        let r = n.span().byte_range();
        self.b
            .push_scope("block", "while_condition", r.start, r.end);
        self.visit_expr(&n.cond);
        self.visit_block(&n.body);
        self.b.pop_scope();
    }
    fn visit_expr_let(&mut self, n: &'ast syn::ExprLet) {
        self.visit_expr(&n.expr);
        self.pattern(&n.pat, "variable", "unknown", None);
    }
    fn visit_expr_match(&mut self, n: &'ast syn::ExprMatch) {
        self.visit_expr(&n.expr);
        for arm in &n.arms {
            let r = arm.span().byte_range();
            self.b.push_scope("block", "match_arm", r.start, r.end);
            self.pattern(&arm.pat, "variable", "unknown", None);
            if let Some((_, guard)) = &arm.guard {
                self.visit_expr(guard)
            }
            self.visit_expr(&arm.body);
            self.b.pop_scope();
        }
    }
    fn visit_expr_assign(&mut self, n: &'ast syn::ExprAssign) {
        if let syn::Expr::Path(p) = &*n.left
            && p.path.segments.len() == 1
            && let Some(seg) = p.path.segments.first()
        {
            self.declaration(n, &seg.ident, "assignment", "unknown", None)
        }
        visit::visit_expr_assign(self, n);
    }
    fn visit_macro(&mut self, _n: &'ast syn::Macro) {
        self.b.limit("macro_expansion_not_executed");
    }
    fn visit_attribute(&mut self, n: &'ast syn::Attribute) {
        if n.path().is_ident("cfg") || n.path().is_ident("cfg_attr") {
            self.b.limit("rust_cfg_variant_not_selected");
        }
    }
}
fn expr_kind(n: &syn::Expr) -> &'static str {
    match n {
        syn::Expr::Closure(_) => "callable",
        syn::Expr::Lit(_) | syn::Expr::Array(_) | syn::Expr::Tuple(_) | syn::Expr::Struct(_) => {
            "non_callable"
        }
        _ => "unknown",
    }
}
