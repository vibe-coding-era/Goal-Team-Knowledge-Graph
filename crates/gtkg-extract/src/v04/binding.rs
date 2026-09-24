//! Statically provable bindings with source replay, separate from observations.
use super::{
    AnalysisContext, CallSite, Declaration, EXTRACTOR_PROFILE, ExtractedFile, Import, Scope,
    context_digest, digest, extract,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const RESOLVER_PROFILE: &str = "gtkg.qk.resolver/v1";
pub const VERIFIER_PROFILE: &str = "gtkg.qk.binding-verifier/v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BindingTarget {
    pub path: String,
    pub declaration: Declaration,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallBindingProof {
    pub schema: String,
    pub source_path: String,
    pub language: String,
    pub source_set_digest: String,
    pub context_digest: String,
    pub extractor_profile: String,
    pub resolver_profile: String,
    pub verifier_profile: String,
    pub call: CallSite,
    pub resolution: String,
    pub proof_status: String,
    pub rule: String,
    pub reason: String,
    pub target: Option<BindingTarget>,
    pub candidates: Vec<String>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphEdge {
    pub call_id: String,
    pub source_path: String,
    pub target_path: String,
    pub target_id: String,
}
#[derive(Debug, thiserror::Error)]
pub enum BindingError {
    #[error("binding proof is stale or unsupported: {0}")]
    Invalid(String),
}

#[derive(Clone, Copy)]
struct DeclAt<'a> {
    file: &'a ExtractedFile,
    decl: &'a Declaration,
}
struct Imported<'a> {
    item: &'a Import,
    alias: String,
}
#[derive(Default)]
struct Lookup<'a> {
    decls: Vec<DeclAt<'a>>,
    imports: Vec<&'a Import>,
    package: bool,
}
impl Lookup<'_> {
    fn found(&self) -> bool {
        !self.decls.is_empty() || !self.imports.is_empty()
    }
}

/// Immutable per-source indexes. Construction is linear in facts; each lookup
/// walks only the enclosing scopes or a named module/type bucket.
struct Index<'a> {
    context: &'a AnalysisContext,
    context_id: String,
    source_id: String,
    files: BTreeMap<&'a str, &'a ExtractedFile>,
    scopes: BTreeMap<&'a str, &'a Scope>,
    scoped: BTreeMap<&'a str, BTreeMap<&'a str, Vec<DeclAt<'a>>>>,
    top: BTreeMap<&'a str, BTreeMap<&'a str, Vec<DeclAt<'a>>>>,
    exports: BTreeMap<&'a str, BTreeMap<String, Vec<DeclAt<'a>>>>,
    directories: BTreeMap<(String, String), Vec<&'a ExtractedFile>>,
    packages: BTreeMap<(String, String), BTreeMap<&'a str, Vec<DeclAt<'a>>>>,
    methods: BTreeMap<(String, String, String, String), Vec<DeclAt<'a>>>,
    imports: BTreeMap<&'a str, Vec<Imported<'a>>>,
    calls: BTreeMap<&'a str, (&'a ExtractedFile, &'a CallSite)>,
    identities_valid: bool,
}
fn directory(path: &str) -> &str {
    path.rsplit_once('/').map_or("", |(dir, _)| dir)
}
fn active(file: &ExtractedFile) -> bool {
    file.parse_status == "parsed"
        && file.semantic_status == "analyzed"
        && file.variant_status == "active"
}
fn callable(d: &Declaration) -> bool {
    d.callability == "callable" && d.kind == "function"
}
fn same_target(a: DeclAt<'_>, t: &BindingTarget) -> bool {
    a.file.path == t.path && *a.decl == t.declaration
}
fn syntax_limited(file: &ExtractedFile) -> bool {
    file.limitations.iter().any(|s| {
        matches!(
            s.as_str(),
            "explicit_global_nonlocal_binding_not_supported"
                | "wildcard_import_binding_not_supported"
                | "javascript_var_hoisting_requires_review"
                | "rust_cfg_variant_not_selected"
                | "rust_attribute_expansion_not_evaluated"
                | "dynamic_namespace_mutation_not_proven"
        )
    })
}
impl<'a> Index<'a> {
    fn new(files: &'a [ExtractedFile], context: &'a AnalysisContext) -> Self {
        let mut fingerprints: Vec<_> = files
            .iter()
            .map(|f| {
                (
                    f.path.clone(),
                    digest(&serde_json::to_vec(f).unwrap_or_default()),
                )
            })
            .collect();
        fingerprints.sort();
        let mut s = Self {
            context,
            context_id: context_digest(context),
            source_id: digest(&serde_json::to_vec(&fingerprints).unwrap_or_default()),
            files: BTreeMap::new(),
            scopes: BTreeMap::new(),
            scoped: BTreeMap::new(),
            top: BTreeMap::new(),
            exports: BTreeMap::new(),
            directories: BTreeMap::new(),
            packages: BTreeMap::new(),
            methods: BTreeMap::new(),
            imports: BTreeMap::new(),
            calls: BTreeMap::new(),
            identities_valid: true,
        };
        for f in files {
            s.identities_valid &= s.files.insert(&f.path, f).is_none()
                && f.context_digest == s.context_id
                && f.snapshot_id == context.snapshot_id
                && f.extractor_profile == EXTRACTOR_PROFILE;
            s.directories
                .entry((f.language.clone(), directory(&f.path).into()))
                .or_default()
                .push(f);
            for scope in &f.scopes {
                s.identities_valid &= s.scopes.insert(&scope.id, scope).is_none();
            }
            for call in &f.calls {
                s.identities_valid &= s.calls.insert(&call.id, (f, call)).is_none();
            }
            for d in &f.declarations {
                let at = DeclAt { file: f, decl: d };
                s.scoped
                    .entry(&d.scope_id)
                    .or_default()
                    .entry(&d.name)
                    .or_default()
                    .push(at);
                let root = f.scopes.first().is_some_and(|root| root.id == d.scope_id);
                if root {
                    s.top
                        .entry(&f.path)
                        .or_default()
                        .entry(&d.name)
                        .or_default()
                        .push(at);
                    if matches!(f.language.as_str(), "javascript" | "typescript") {
                        let mut prefix = d.signature.split_whitespace();
                        if prefix.next() == Some("export") {
                            let exported = if prefix.next() == Some("default") {
                                "default".into()
                            } else {
                                d.name.clone()
                            };
                            s.exports
                                .entry(&f.path)
                                .or_default()
                                .entry(exported)
                                .or_default()
                                .push(at);
                        }
                    }
                    if f.language == "go" && active(f) {
                        s.packages
                            .entry((
                                directory(&f.path).into(),
                                f.package.clone().unwrap_or_default(),
                            ))
                            .or_default()
                            .entry(&d.name)
                            .or_default()
                            .push(at);
                    }
                }
                if let Some(receiver) = &d.receiver_type {
                    let domain = if f.language == "go" {
                        format!(
                            "{}\0{}",
                            directory(&f.path),
                            f.package.as_deref().unwrap_or("")
                        )
                    } else {
                        f.path.clone()
                    };
                    if active(f) {
                        s.methods
                            .entry((f.language.clone(), domain, receiver.clone(), d.name.clone()))
                            .or_default()
                            .push(at);
                    }
                }
            }
        }
        for f in files {
            for i in &f.imports {
                let alias = if f.language == "go" && i.alias.is_empty() {
                    let packages: BTreeSet<_> = s
                        .module_files(f, &i.module)
                        .iter()
                        .filter_map(|f| f.package.as_deref())
                        .collect();
                    if packages.len() == 1 {
                        packages.iter().next().copied().unwrap_or("").to_owned()
                    } else {
                        String::new()
                    }
                } else {
                    i.alias.clone()
                };
                s.imports
                    .entry(&i.scope_id)
                    .or_default()
                    .push(Imported { item: i, alias });
            }
        }
        s
    }
    fn module_files(&self, source: &ExtractedFile, module: &str) -> Vec<&'a ExtractedFile> {
        let Some(mapped) = self.context.import_modules.get(module) else {
            return vec![];
        };
        if let Some(f) = self.files.get(mapped.as_str()) {
            return if f.language == source.language && active(f) {
                vec![f]
            } else {
                vec![]
            };
        }
        if source.language == "go" {
            return self
                .directories
                .get(&("go".into(), mapped.trim_end_matches('/').into()))
                .into_iter()
                .flatten()
                .filter(|f| active(f))
                .copied()
                .collect();
        }
        vec![]
    }
    fn package_bucket(&self, file: &ExtractedFile, name: &str) -> Vec<DeclAt<'a>> {
        self.packages
            .get(&(
                directory(&file.path).into(),
                file.package.clone().unwrap_or_default(),
            ))
            .and_then(|m| m.get(name))
            .cloned()
            .unwrap_or_default()
    }
    fn lexical(&self, file: &ExtractedFile, call: &CallSite, name: &str) -> Lookup<'a> {
        let mut id = Some(call.scope_id.as_str());
        let mut visited = BTreeSet::new();
        while let Some(scope_id) = id {
            if !visited.insert(scope_id) {
                return Lookup::default();
            }
            let Some(scope) = self.scopes.get(scope_id) else {
                return Lookup::default();
            };
            id = scope.parent.as_deref();
            if matches!(scope.kind.as_str(), "class" | "type" | "impl") {
                continue;
            }
            let package = file.language == "go" && scope.parent.is_none();
            let decls = if package {
                self.package_bucket(file, name)
            } else {
                self.scoped
                    .get(scope_id)
                    .and_then(|m| m.get(name))
                    .cloned()
                    .unwrap_or_default()
            };
            let decls = decls
                .into_iter()
                .filter(|at| {
                    let d = at.decl;
                    if matches!(
                        d.kind.as_str(),
                        "method" | "field" | "accessor" | "interface_method"
                    ) {
                        return false;
                    }
                    // Go and Rust locals begin after the binding expression. Python
                    // locals and JS TDZ bindings shadow for the whole lexical scope.
                    if matches!(file.language.as_str(), "go" | "rust")
                        && !package
                        && matches!(d.kind.as_str(), "variable" | "assignment")
                    {
                        d.span.byte_end <= call.span.byte_start
                    } else {
                        true
                    }
                })
                .collect();
            let imports = self
                .imports
                .get(scope_id)
                .into_iter()
                .flatten()
                .filter(|i| !i.alias.is_empty() && i.alias == name)
                .map(|i| i.item)
                .collect();
            let found = Lookup {
                decls,
                imports,
                package,
            };
            if found.found() {
                return found;
            }
        }
        Lookup::default()
    }
    fn package_sound(&self, file: &ExtractedFile) -> bool {
        !self
            .directories
            .get(&(file.language.clone(), directory(&file.path).into()))
            .into_iter()
            .flatten()
            .any(|f| f.variant_status == "active" && f.parse_status != "parsed")
    }
    fn import_targets(&self, file: &ExtractedFile, import: &Import, name: &str) -> Vec<DeclAt<'a>> {
        if matches!(import.alias.as_str(), "." | "_") {
            return vec![];
        }
        let modules = self.module_files(file, &import.module);
        if modules.is_empty()
            || modules
                .iter()
                .any(|m| syntax_limited(m) || !self.package_sound(m))
        {
            return vec![];
        }
        if file.language == "go" {
            let packages: BTreeSet<_> = modules
                .iter()
                .filter_map(|m| m.package.as_deref())
                .collect();
            if packages.len() != 1 || !name.chars().next().is_some_and(char::is_uppercase) {
                return vec![];
            }
        }
        if file.language == "rust" {
            return vec![];
        } // Rust visibility/module reexports require a dedicated proof.
        modules
            .into_iter()
            .flat_map(|m| {
                if matches!(file.language.as_str(), "javascript" | "typescript") {
                    self.exports
                        .get(m.path.as_str())
                        .and_then(|t| t.get(name))
                        .into_iter()
                        .flatten()
                        .copied()
                        .collect::<Vec<_>>()
                } else {
                    self.top
                        .get(m.path.as_str())
                        .and_then(|t| t.get(name))
                        .into_iter()
                        .flatten()
                        .copied()
                        .collect::<Vec<_>>()
                }
            })
            .collect()
    }
    fn receiver_targets(&self, file: &ExtractedFile, call: &CallSite) -> Vec<DeclAt<'a>> {
        if !matches!(file.language.as_str(), "go" | "rust") {
            return vec![];
        }
        let Some(receiver) = &call.receiver else {
            return vec![];
        };
        if !receiver.chars().all(|c| c.is_alphanumeric() || c == '_') {
            return vec![];
        }
        let lookup = self.lexical(file, call, receiver);
        if !lookup.imports.is_empty() || lookup.decls.len() != 1 {
            return vec![];
        }
        let variable = lookup.decls[0].decl;
        let Some(ty) = variable.type_hint.as_deref() else {
            return vec![];
        };
        if !ty.chars().all(|c| c.is_alphanumeric() || c == '_') {
            return vec![];
        }
        let type_refs = if file.language == "go" {
            self.package_bucket(file, ty)
        } else {
            self.top
                .get(file.path.as_str())
                .and_then(|m| m.get(ty))
                .cloned()
                .unwrap_or_default()
        };
        if type_refs.len() != 1
            || type_refs[0].decl.kind != "type"
            || !type_refs[0]
                .decl
                .type_hint
                .as_deref()
                .is_some_and(|t| t.starts_with("struct"))
        {
            return vec![];
        }
        if file.language == "rust"
            && file
                .limitations
                .iter()
                .any(|s| s == "trait_dispatch_requires_review")
        {
            return vec![];
        }
        let domain = if file.language == "go" {
            format!(
                "{}\0{}",
                directory(&file.path),
                file.package.as_deref().unwrap_or("")
            )
        } else {
            file.path.clone()
        };
        self.methods
            .get(&(
                file.language.clone(),
                domain,
                ty.into(),
                call.callee.clone(),
            ))
            .cloned()
            .unwrap_or_default()
    }
}

struct Decision<'a> {
    resolution: &'static str,
    rule: &'static str,
    reason: &'static str,
    target: Option<DeclAt<'a>>,
    candidates: Vec<String>,
}
fn unknown(reason: &'static str) -> Decision<'static> {
    Decision {
        resolution: "unresolved",
        rule: "none",
        reason,
        target: None,
        candidates: vec![],
    }
}
fn choose<'a>(rule: &'static str, candidates: Vec<DeclAt<'a>>, method: bool) -> Decision<'a> {
    let ids = candidates.iter().map(|a| a.decl.id.clone()).collect();
    if candidates.len() > 1 {
        return Decision {
            resolution: "ambiguous",
            rule: "none",
            reason: "multiple_lexical_or_module_candidates",
            target: None,
            candidates: ids,
        };
    }
    let Some(target) = candidates.first().copied() else {
        return unknown("no_provable_candidate");
    };
    let can_call = if method {
        target.decl.kind == "method" && target.decl.callability == "callable"
    } else {
        callable(target.decl)
    };
    if !can_call {
        return Decision {
            resolution: "unresolved",
            rule: "none",
            reason: "lexical_symbol_not_proven_callable",
            target: None,
            candidates: ids,
        };
    }
    Decision {
        resolution: "resolved",
        rule,
        reason: "source_replay_required",
        target: Some(target),
        candidates: ids,
    }
}
fn decide<'a>(index: &Index<'a>, file: &'a ExtractedFile, call: &CallSite) -> Decision<'a> {
    if !index.identities_valid {
        return unknown("context_or_source_identity_mismatch");
    }
    if !active(file) {
        return unknown("source_parse_or_variant_not_active");
    }
    if syntax_limited(file) {
        return unknown("language_scope_or_expansion_requires_review");
    }
    if !index.package_sound(file) {
        return unknown("package_parse_gap");
    }
    if call.callee.is_empty() {
        return unknown("dynamic_call_expression");
    }
    if let Some(receiver) = &call.receiver {
        if file
            .limitations
            .iter()
            .any(|s| s == "member_mutation_requires_binding_review")
        {
            return unknown("receiver_mutation_requires_review");
        }
        let lookup = index.lexical(file, call, receiver);
        if !lookup.decls.is_empty() && !lookup.imports.is_empty() {
            return unknown("import_declaration_collision");
        }
        if lookup.imports.len() == 1 && lookup.decls.is_empty() {
            return choose(
                "explicit_module_callable",
                index.import_targets(file, lookup.imports[0], &call.callee),
                false,
            );
        }
        if lookup.imports.len() > 1 {
            return unknown("ambiguous_import_alias");
        }
        return choose(
            "concrete_receiver_method",
            index.receiver_targets(file, call),
            true,
        );
    }
    let lookup = index.lexical(file, call, &call.callee);
    if !lookup.decls.is_empty() && !lookup.imports.is_empty() {
        return unknown("import_declaration_collision");
    }
    if lookup.imports.len() == 1 {
        let import = lookup.imports[0];
        return match import.symbol.as_deref() {
            Some(symbol) => choose(
                "explicit_module_callable",
                index.import_targets(file, import, symbol),
                false,
            ),
            None => unknown("module_object_is_not_callable"),
        };
    }
    if lookup.imports.len() > 1 {
        return unknown("ambiguous_import_alias");
    }
    if !lookup.decls.is_empty() {
        return choose(
            if lookup.package {
                "same_go_package_callable"
            } else {
                "lexical_callable"
            },
            lookup.decls,
            false,
        );
    }
    if file.language == "python"
        && matches!(
            call.callee.as_str(),
            "str"
                | "int"
                | "float"
                | "len"
                | "bool"
                | "list"
                | "dict"
                | "set"
                | "tuple"
                | "print"
                | "range"
                | "object"
                | "type"
                | "super"
        )
    {
        return unknown("builtin_symbol_not_repository_declaration");
    }
    unknown("external_or_unresolved_symbol")
}

pub fn bind(files: &[ExtractedFile], context: &AnalysisContext) -> Vec<CallBindingProof> {
    let index = Index::new(files, context);
    let mut proofs = vec![];
    for file in index.files.values() {
        for call in &file.calls {
            let decision = decide(&index, file, call);
            proofs.push(CallBindingProof {
                schema: "gtkg.qk.call-binding-proof/v1".into(),
                source_path: file.path.clone(),
                language: file.language.clone(),
                source_set_digest: index.source_id.clone(),
                context_digest: index.context_id.clone(),
                extractor_profile: EXTRACTOR_PROFILE.into(),
                resolver_profile: RESOLVER_PROFILE.into(),
                verifier_profile: VERIFIER_PROFILE.into(),
                call: call.clone(),
                resolution: decision.resolution.into(),
                proof_status: if decision.target.is_some() {
                    "confirmed"
                } else {
                    "unknown"
                }
                .into(),
                rule: decision.rule.into(),
                reason: decision.reason.into(),
                target: decision.target.map(|a| BindingTarget {
                    path: a.file.path.clone(),
                    declaration: a.decl.clone(),
                }),
                candidates: decision.candidates,
            });
        }
    }
    proofs.sort_by(|a, b| {
        (&a.source_path, a.call.span.byte_start, &a.call.id).cmp(&(
            &b.source_path,
            b.call.span.byte_start,
            &b.call.id,
        ))
    });
    proofs
}

fn invalid(reason: &str) -> BindingError {
    BindingError::Invalid(reason.into())
}
fn read_sources(
    raw_sources: &BTreeMap<String, Vec<u8>>,
    context: &AnalysisContext,
) -> Result<Vec<ExtractedFile>, BindingError> {
    raw_sources
        .iter()
        .map(|(path, bytes)| {
            extract(path, bytes, context).map_err(|e| invalid(&format!("source_replay:{path}:{e}")))
        })
        .collect()
}

/// This verifier never calls `bind` or the resolver decision procedure. It
/// rebuilds source facts and checks the asserted proof rule independently.
fn verify_index(proof: &CallBindingProof, index: &Index<'_>) -> Result<(), BindingError> {
    if !index.identities_valid
        || proof.schema != "gtkg.qk.call-binding-proof/v1"
        || proof.source_set_digest != index.source_id
        || proof.context_digest != index.context_id
        || proof.extractor_profile != EXTRACTOR_PROFILE
        || proof.resolver_profile != RESOLVER_PROFILE
        || proof.verifier_profile != VERIFIER_PROFILE
    {
        return Err(invalid("identity_changed"));
    }
    let Some((file, call)) = index.calls.get(proof.call.id.as_str()).copied() else {
        return Err(invalid("call_site_absent"));
    };
    if proof.source_path != file.path || proof.language != file.language || *call != proof.call {
        return Err(invalid("call_observation_changed"));
    }
    if proof.proof_status == "unknown" {
        if proof.target.is_some()
            || !matches!(proof.resolution.as_str(), "unresolved" | "ambiguous")
            || proof.rule != "none"
            || proof.reason.is_empty()
        {
            return Err(invalid("invalid_unknown_projection"));
        }
        return Ok(());
    }
    if proof.proof_status != "confirmed"
        || proof.resolution != "resolved"
        || !active(file)
        || syntax_limited(file)
        || !index.package_sound(file)
        || call.receiver.is_some()
            && file
                .limitations
                .iter()
                .any(|s| s == "member_mutation_requires_binding_review")
    {
        return Err(invalid("confirmation_not_admissible"));
    }
    let Some(target) = &proof.target else {
        return Err(invalid("target_missing"));
    };
    let actual_target = index
        .scoped
        .get(target.declaration.scope_id.as_str())
        .and_then(|m| m.get(target.declaration.name.as_str()))
        .into_iter()
        .flatten()
        .find(|a| same_target(**a, target))
        .copied()
        .ok_or_else(|| invalid("target_source_replay_changed"))?;
    if !active(actual_target.file)
        || syntax_limited(actual_target.file)
        || actual_target.file.language != file.language
    {
        return Err(invalid("target_language_or_source_not_admissible"));
    }
    if proof.candidates != vec![target.declaration.id.clone()] {
        return Err(invalid("candidate_set_not_unique"));
    }
    let candidates = match proof.rule.as_str() {
        "lexical_callable" | "same_go_package_callable" => {
            if call.receiver.is_some() || !callable(actual_target.decl) {
                return Err(invalid("not_a_bare_callable"));
            }
            let lexical = index.lexical(file, call, &call.callee);
            if !lexical.imports.is_empty()
                || lexical.package != (proof.rule == "same_go_package_callable")
            {
                return Err(invalid("lexical_rule_scope_mismatch"));
            }
            lexical.decls
        }
        "explicit_module_callable" => {
            if !callable(actual_target.decl) {
                return Err(invalid("import_not_callable"));
            }
            let identifier = call.receiver.as_deref().unwrap_or(&call.callee);
            let lexical = index.lexical(file, call, identifier);
            if !lexical.decls.is_empty() || lexical.imports.len() != 1 {
                return Err(invalid("import_alias_not_unique"));
            }
            let import = lexical.imports[0];
            let symbol = if call.receiver.is_some() {
                call.callee.as_str()
            } else {
                import
                    .symbol
                    .as_deref()
                    .ok_or_else(|| invalid("import_module_not_callable"))?
            };
            index.import_targets(file, import, symbol)
        }
        "concrete_receiver_method" => {
            if call.receiver.is_none()
                || actual_target.decl.kind != "method"
                || actual_target.decl.callability != "callable"
            {
                return Err(invalid("receiver_method_not_callable"));
            }
            index.receiver_targets(file, call)
        }
        _ => return Err(invalid("unknown_binding_rule")),
    };
    if candidates.len() != 1 || !same_target(candidates[0], target) {
        return Err(invalid("binding_rule_replay_rejected"));
    }
    Ok(())
}
pub fn verify(
    proof: &CallBindingProof,
    raw_sources: &BTreeMap<String, Vec<u8>>,
    context: &AnalysisContext,
) -> Result<(), BindingError> {
    let files = read_sources(raw_sources, context)?;
    let index = Index::new(&files, context);
    verify_index(proof, &index)
}
fn verify_batch(
    proofs: &[CallBindingProof],
    raw_sources: &BTreeMap<String, Vec<u8>>,
    context: &AnalysisContext,
) -> Result<(), BindingError> {
    let files = read_sources(raw_sources, context)?;
    let index = Index::new(&files, context);
    if proofs.len() != index.calls.len() {
        return Err(invalid("call_exact_set_incomplete"));
    }
    let mut seen = BTreeSet::new();
    for proof in proofs {
        if !seen.insert(proof.call.id.as_str()) {
            return Err(invalid("duplicate_call_proof"));
        }
        verify_index(proof, &index)?;
    }
    Ok(())
}
/// One source parse/index per batch, never one whole-project parse per proof.
pub fn verify_all(
    proofs: &[CallBindingProof],
    raw_sources: &BTreeMap<String, Vec<u8>>,
    context: &AnalysisContext,
) -> Result<(), String> {
    verify_batch(proofs, raw_sources, context).map_err(|e| e.to_string())
}
pub fn confirmed_edges(
    proofs: &[CallBindingProof],
    raw_sources: &BTreeMap<String, Vec<u8>>,
    context: &AnalysisContext,
) -> Result<Vec<GraphEdge>, BindingError> {
    verify_batch(proofs, raw_sources, context)?;
    Ok(proofs
        .iter()
        .filter(|p| p.proof_status == "confirmed")
        .filter_map(|p| {
            p.target.as_ref().map(|t| GraphEdge {
                call_id: p.call.id.clone(),
                source_path: p.source_path.clone(),
                target_path: t.path.clone(),
                target_id: t.declaration.id.clone(),
            })
        })
        .collect())
}
