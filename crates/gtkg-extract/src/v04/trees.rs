use super::{Builder, ExtractError, clean_type};
use tree_sitter::{Node, Parser};

pub(super) fn extract(b: &mut Builder<'_>) -> Result<(), ExtractError> {
    let lang = match b.file.language.as_str() {
        "go" => tree_sitter_go::LANGUAGE.into(),
        "python" => tree_sitter_python::LANGUAGE.into(),
        "javascript" => tree_sitter_javascript::LANGUAGE.into(),
        _ => {
            if b.file.path.ends_with(".tsx") {
                tree_sitter_typescript::LANGUAGE_TSX.into()
            } else {
                tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into()
            }
        }
    };
    let mut parser = Parser::new();
    parser
        .set_language(&lang)
        .map_err(|e| ExtractError::Parser(e.to_string()))?;
    let tree = parser
        .parse(b.source, None)
        .ok_or_else(|| ExtractError::Parser("parser cancelled".into()))?;
    if tree.root_node().has_error() {
        b.parse_error();
    }
    walk(b, tree.root_node(), None);
    Ok(())
}
fn text(b: &Builder<'_>, n: Node<'_>) -> String {
    b.text(n.start_byte(), n.end_byte())
}
fn children(n: Node<'_>) -> Vec<Node<'_>> {
    let mut c = n.walk();
    n.named_children(&mut c).collect()
}
fn names<'n>(n: Node<'n>, field: &str) -> Vec<Node<'n>> {
    let mut c = n.walk();
    n.children_by_field_name(field, &mut c).collect()
}
fn declare(
    b: &mut Builder<'_>,
    n: Node<'_>,
    name: Node<'_>,
    kind: &str,
    callability: &str,
    receiver: Option<String>,
    hint: Option<String>,
) {
    let sig_end = n
        .child_by_field_name("body")
        .map_or(n.end_byte(), |body| body.start_byte());
    // An import proof needs the actual export modifier, not a same-name match.
    let start = n
        .parent()
        .filter(|p| p.kind() == "export_statement")
        .map_or(n.start_byte(), |p| p.start_byte());
    b.decl(
        kind,
        name.start_byte(),
        name.end_byte(),
        start,
        n.end_byte(),
        sig_end,
        callability,
        receiver,
        hint,
    );
}
fn id_node(n: Node<'_>) -> bool {
    matches!(
        n.kind(),
        "identifier"
            | "field_identifier"
            | "type_identifier"
            | "property_identifier"
            | "shorthand_property_identifier_pattern"
    )
}
fn pattern_names(n: Node<'_>) -> Vec<Node<'_>> {
    if n.kind() == "pair_pattern" {
        return n
            .child_by_field_name("value")
            .map(pattern_names)
            .unwrap_or_default();
    }
    if matches!(n.kind(), "assignment_pattern" | "object_assignment_pattern") {
        return n
            .child_by_field_name("left")
            .map(pattern_names)
            .unwrap_or_default();
    }
    if id_node(n) {
        return vec![n];
    }
    if matches!(
        n.kind(),
        "attribute" | "member_expression" | "selector_expression" | "subscript"
    ) {
        return vec![];
    }
    children(n)
        .into_iter()
        .filter(|x| !matches!(x.kind(), "type_annotation" | "type" | "predefined_type"))
        .flat_map(pattern_names)
        .collect()
}
fn member_target(n: Node<'_>) -> bool {
    matches!(
        n.kind(),
        "attribute" | "member_expression" | "subscript" | "subscript_expression"
    ) || children(n).into_iter().any(member_target)
}
fn value_kind(value: Option<Node<'_>>) -> &'static str {
    match value.map(|x| x.kind()) {
        Some("arrow_function" | "function_expression" | "function" | "lambda" | "func_literal") => {
            "callable"
        }
        Some(
            "true"
            | "false"
            | "none"
            | "null"
            | "integer"
            | "float"
            | "number"
            | "string"
            | "string_literal"
            | "interpreted_string_literal"
            | "raw_string_literal"
            | "int_literal"
            | "float_literal"
            | "list"
            | "dictionary"
            | "array"
            | "object",
        ) => "non_callable",
        _ => "unknown",
    }
}
fn parameter(b: &mut Builder<'_>, n: Node<'_>, class: Option<&str>) {
    let hint = n
        .child_by_field_name("type")
        .map(|t| clean_type(&text(b, t)));
    let mut ns = names(n, "name");
    if ns.is_empty() {
        if let Some(p) = n.child_by_field_name("pattern") {
            ns = pattern_names(p)
        } else {
            ns = children(n)
                .into_iter()
                .filter(|x| id_node(*x))
                .take(1)
                .collect();
            if id_node(n) {
                ns = vec![n]
            }
            if ns.is_empty()
                && matches!(n.kind(), "list_splat_pattern" | "dictionary_splat_pattern")
            {
                ns = pattern_names(n)
            }
        }
    }
    for name in ns {
        let label = text(b, name);
        let ty = hint.clone().or_else(|| {
            if matches!(label.as_str(), "self" | "cls" | "this") {
                class.map(str::to_owned)
            } else {
                None
            }
        });
        declare(b, n, name, "parameter", "unknown", None, ty);
    }
}
fn parameters(b: &mut Builder<'_>, params: Node<'_>, class: Option<&str>) {
    for n in children(params) {
        parameter(b, n, class);
    }
}
fn walk(b: &mut Builder<'_>, n: Node<'_>, class: Option<String>) {
    let kind = n.kind();
    if matches!(
        kind,
        "type_parameter_list" | "type_parameters" | "type_arguments"
    ) {
        b.limit("generic_type_solving_not_supported");
    }
    if matches!(kind, "interface_type" | "interface_declaration") {
        b.limit("interface_dispatch_not_proven");
    }
    if matches!(kind, "global_statement" | "nonlocal_statement") {
        b.limit("explicit_global_nonlocal_binding_not_supported");
    }
    if matches!(kind, "assignment_expression" | "update_expression") {
        b.limit("mutation_requires_binding_review");
    }
    if matches!(
        b.file.language.as_str(),
        "python" | "javascript" | "typescript"
    ) && matches!(
        kind,
        "assignment" | "assignment_expression" | "augmented_assignment_expression"
    ) && n.child_by_field_name("left").is_some_and(member_target)
    {
        b.limit("member_mutation_requires_binding_review");
    }
    match kind {
        "package_clause" => {
            b.file.package = children(n).first().map(|x| text(b, *x));
        }
        "function_definition"
        | "function_declaration"
        | "generator_function_declaration"
        | "method_definition"
        | "method_declaration" => {
            let Some(name) = n.child_by_field_name("name") else {
                for c in children(n) {
                    walk(b, c, class.clone())
                }
                return;
            };
            let receiver = n
                .child_by_field_name("receiver")
                .and_then(|r| children(r).first().copied())
                .and_then(|r| r.child_by_field_name("type"))
                .map(|ty| clean_type(&text(b, ty)))
                .or_else(|| class.clone());
            let accessor = {
                let mut cursor = n.walk();
                n.children(&mut cursor)
                    .any(|c| matches!(c.kind(), "get" | "set"))
            };
            let decorated = n
                .parent()
                .is_some_and(|p| p.kind() == "decorated_definition");
            declare(
                b,
                n,
                name,
                if accessor {
                    "accessor"
                } else if receiver.is_some() {
                    "method"
                } else {
                    "function"
                },
                if accessor || decorated {
                    "unknown"
                } else {
                    "callable"
                },
                receiver.clone(),
                None,
            );
            // Default arguments execute in the enclosing scope, not the body scope.
            if b.file.language == "python"
                && let Some(p) = n.child_by_field_name("parameters")
            {
                for p in children(p) {
                    if let Some(v) = p.child_by_field_name("value") {
                        walk(b, v, class.clone())
                    }
                }
            }
            b.push_scope("function", &text(b, name), n.start_byte(), n.end_byte());
            if let Some(p) = n.child_by_field_name("receiver") {
                parameters(b, p, receiver.as_deref());
            }
            if let Some(p) = n.child_by_field_name("parameters") {
                parameters(b, p, receiver.as_deref());
            }
            if let Some(p) = n.child_by_field_name("type_parameters") {
                walk(b, p, receiver.clone());
            }
            if let Some(body) = n.child_by_field_name("body") {
                walk(b, body, None);
            }
            b.pop_scope();
        }
        "class_definition" | "class_declaration" | "abstract_class_declaration" => {
            if let Some(name) = n.child_by_field_name("name") {
                let label = text(b, name);
                declare(
                    b,
                    n,
                    name,
                    "class",
                    if b.file.language == "python" {
                        "callable"
                    } else {
                        "non_callable"
                    },
                    None,
                    None,
                );
                b.push_scope("class", &label, n.start_byte(), n.end_byte());
                if let Some(body) = n.child_by_field_name("body") {
                    for c in children(body) {
                        walk(b, c, Some(label.clone()));
                    }
                }
                b.pop_scope();
            }
        }
        "type_spec" | "type_alias" | "interface_declaration" => {
            if let Some(name) = n.child_by_field_name("name") {
                let ty = n.child_by_field_name("type");
                let label = text(b, name);
                let dk = if ty.is_some_and(|t| t.kind() == "interface_type")
                    || kind == "interface_declaration"
                {
                    "interface"
                } else {
                    "type"
                };
                declare(b, n, name, dk, "non_callable", None, ty.map(|t| text(b, t)));
                b.push_scope("type", &label, n.start_byte(), n.end_byte());
                for c in children(n) {
                    if c.id() != name.id() {
                        walk(b, c, Some(label.clone()));
                    }
                }
                b.pop_scope();
            }
        }
        "field_declaration" | "public_field_definition" | "property_signature" => {
            let hint = n
                .child_by_field_name("type")
                .map(|t| clean_type(&text(b, t)));
            let ns = names(n, "name");
            if ns.is_empty() {
                b.limit("embedded_field_has_no_explicit_name");
            }
            for name in ns {
                declare(b, n, name, "field", "unknown", class.clone(), hint.clone());
            }
            for c in children(n) {
                if matches!(c.kind(), "call" | "call_expression") {
                    walk(b, c, class.clone())
                }
            }
        }
        "method_elem" | "method_signature" => {
            if let Some(name) = n.child_by_field_name("name") {
                declare(
                    b,
                    n,
                    name,
                    "interface_method",
                    "unknown",
                    None,
                    class.clone(),
                );
            }
            b.limit("interface_dispatch_not_proven");
        }
        "func_literal"
        | "arrow_function"
        | "function_expression"
        | "generator_function"
        | "lambda" => {
            b.push_scope("function", "<anonymous>", n.start_byte(), n.end_byte());
            if let Some(p) = n.child_by_field_name("parameters") {
                parameters(b, p, None);
            }
            if let Some(p) = n.child_by_field_name("parameter") {
                parameter(b, p, None);
            }
            if let Some(body) = n.child_by_field_name("body") {
                walk(b, body, None);
            }
            b.pop_scope();
        }
        "for_statement" if b.file.language == "python" => {
            if let Some(left) = n.child_by_field_name("left") {
                for name in pattern_names(left) {
                    declare(b, n, name, "variable", "unknown", None, None);
                }
            }
            for c in children(n) {
                if n.child_by_field_name("left")
                    .is_none_or(|left| left.id() != c.id())
                {
                    walk(b, c, class.clone());
                }
            }
        }
        "for_statement" | "for_in_statement" | "catch_clause" => {
            b.push_scope("block", kind, n.start_byte(), n.end_byte());
            let binding = if kind == "catch_clause" {
                n.child_by_field_name("parameter")
            } else if kind == "for_in_statement" {
                n.child_by_field_name("left")
            } else {
                None
            };
            if let Some(left) = binding {
                for name in pattern_names(left) {
                    declare(b, n, name, "variable", "unknown", None, None);
                }
            }
            for c in children(n) {
                if binding.is_none_or(|left| left.id() != c.id()) {
                    walk(b, c, class.clone());
                }
            }
            b.pop_scope();
        }
        "if_statement"
        | "expression_switch_statement"
        | "type_switch_statement"
        | "select_statement"
            if b.file.language == "go" =>
        {
            b.push_scope("block", kind, n.start_byte(), n.end_byte());
            if let Some(alias) = n.child_by_field_name("alias") {
                for name in pattern_names(alias) {
                    declare(b, n, name, "variable", "unknown", None, None);
                }
            }
            for c in children(n) {
                walk(b, c, class.clone());
            }
            b.pop_scope();
        }
        "communication_case" | "type_case" if b.file.language == "go" => {
            b.push_scope("block", kind, n.start_byte(), n.end_byte());
            for c in children(n) {
                walk(b, c, class.clone());
            }
            b.pop_scope();
        }
        "range_clause" | "receive_statement" | "for_in_clause" => {
            if let Some(left) = n.child_by_field_name("left") {
                for name in pattern_names(left) {
                    declare(b, n, name, "variable", "unknown", None, None);
                }
            }
            for c in children(n) {
                if n.child_by_field_name("left")
                    .is_none_or(|left| left.id() != c.id())
                {
                    walk(b, c, class.clone());
                }
            }
        }
        "list_comprehension"
        | "set_comprehension"
        | "dictionary_comprehension"
        | "generator_expression" => {
            b.push_scope(
                "comprehension",
                "<comprehension>",
                n.start_byte(),
                n.end_byte(),
            );
            for c in children(n) {
                walk(b, c, class.clone());
            }
            b.pop_scope();
        }
        "as_pattern" | "except_clause" => {
            if let Some(alias) = n.child_by_field_name("alias") {
                for name in pattern_names(alias) {
                    declare(b, n, name, "variable", "unknown", None, None);
                }
            }
            for c in children(n) {
                if n.child_by_field_name("alias")
                    .is_none_or(|alias| alias.id() != c.id())
                {
                    walk(b, c, class.clone());
                }
            }
        }
        "block" | "statement_block" => {
            let lexical = b.file.language != "python";
            if lexical {
                b.push_scope("block", "<block>", n.start_byte(), n.end_byte());
            }
            for c in children(n) {
                walk(b, c, class.clone());
            }
            if lexical {
                b.pop_scope();
            }
        }
        "variable_declarator" => {
            let value = n.child_by_field_name("value");
            let hint = n
                .child_by_field_name("type")
                .map(|t| clean_type(&text(b, t)));
            if let Some(name) = n.child_by_field_name("name") {
                for name in pattern_names(name) {
                    declare(
                        b,
                        n,
                        name,
                        "variable",
                        value_kind(value),
                        None,
                        hint.clone(),
                    );
                }
            }
            if n.parent()
                .is_some_and(|p| p.kind() == "variable_declaration")
            {
                b.limit("javascript_var_hoisting_requires_review");
            }
            if let Some(value) = value {
                walk(b, value, class);
            }
        }
        "assignment" | "short_var_declaration" | "var_spec" | "const_spec" => {
            let value = n
                .child_by_field_name("right")
                .or_else(|| n.child_by_field_name("value"));
            let values = value.map(children).unwrap_or_default();
            let hint = n
                .child_by_field_name("type")
                .map(|t| clean_type(&text(b, t)));
            let ns = if let Some(left) = n.child_by_field_name("left") {
                pattern_names(left)
            } else {
                names(n, "name")
            };
            for (i, name) in ns.into_iter().enumerate() {
                let val = if value.is_some_and(|v| v.kind() == "expression_list") {
                    values.get(i).copied()
                } else {
                    value
                };
                declare(b, n, name, "variable", value_kind(val), None, hint.clone());
            }
            if let Some(v) = value {
                walk(b, v, class);
            }
        }
        "assignment_statement" | "assignment_expression" | "augmented_assignment_expression" => {
            // Every assignment participates in shadow/mutation accounting.
            if let Some(left) = n.child_by_field_name("left") {
                for name in pattern_names(left) {
                    declare(b, n, name, "assignment", "unknown", None, None);
                }
            }
            if let Some(right) = n.child_by_field_name("right") {
                walk(b, right, class);
            }
        }
        "delete_statement" => {
            for child in children(n) {
                if member_target(child) {
                    b.limit("member_mutation_requires_binding_review");
                }
                for name in pattern_names(child) {
                    declare(b, n, name, "deletion", "unknown", None, None);
                }
            }
        }
        "call" | "call_expression" | "new_expression" | "type_conversion_expression" => {
            if kind == "type_conversion_expression" {
                b.limit("call_or_type_conversion_requires_binding");
            }
            if let Some(fun) = n
                .child_by_field_name("function")
                .or_else(|| n.child_by_field_name("constructor"))
                .or_else(|| n.child_by_field_name("type"))
            {
                let (callee, receiver) = callee(b, fun);
                if receiver.is_none()
                    && (b.file.language == "python"
                        && matches!(callee.as_str(), "eval" | "exec" | "globals" | "locals")
                        || matches!(b.file.language.as_str(), "javascript" | "typescript")
                            && callee == "eval")
                {
                    b.limit("dynamic_namespace_mutation_not_proven");
                }
                if receiver.is_none()
                    && b.file.language == "python"
                    && matches!(callee.as_str(), "setattr" | "delattr")
                {
                    b.limit("member_mutation_requires_binding_review");
                }
                b.call(n.start_byte(), n.end_byte(), callee, receiver);
            }
            for c in children(n) {
                walk(b, c, class.clone());
            }
        }
        "import_spec" => {
            if let Some(p) = n.child_by_field_name("path") {
                let module = text(b, p).trim_matches(['"', '`']).to_owned();
                let alias = n
                    .child_by_field_name("name")
                    .map(|x| text(b, x))
                    .unwrap_or_default();
                if matches!(alias.as_str(), "." | "_") {
                    b.limit("go_dot_or_blank_import");
                }
                b.import(module, alias, None, n.start_byte(), n.end_byte());
            }
        }
        "import_statement" if b.file.language == "python" => python_import(b, n),
        "import_from_statement" => python_import(b, n),
        "import_statement" => js_import(b, n),
        _ => {
            for c in children(n) {
                walk(b, c, class.clone());
            }
        }
    }
}

fn callee(b: &Builder<'_>, n: Node<'_>) -> (String, Option<String>) {
    for (member, object) in [
        ("attribute", "object"),
        ("property", "object"),
        ("field", "operand"),
    ] {
        if let (Some(field), Some(receiver)) =
            (n.child_by_field_name(member), n.child_by_field_name(object))
        {
            return (text(b, field), Some(text(b, receiver)));
        }
    }
    if matches!(
        n.kind(),
        "generic_type" | "instantiation_expression" | "type_instantiation_expression"
    ) && let Some(inner) = n
        .child_by_field_name("operand")
        .or_else(|| n.child_by_field_name("type"))
        .or_else(|| n.child_by_field_name("function"))
        .or_else(|| children(n).first().copied())
    {
        return callee(b, inner);
    }
    (text(b, n), None)
}
fn python_import(b: &mut Builder<'_>, n: Node<'_>) {
    let module = n.child_by_field_name("module_name");
    let from = module.map(|x| text(b, x));
    for item in children(n) {
        if module.is_some_and(|m| m.id() == item.id()) {
            continue;
        }
        if item.kind() == "wildcard_import" {
            b.limit("wildcard_import_binding_not_supported");
            continue;
        }
        let name = item.child_by_field_name("name").unwrap_or(item);
        if !matches!(name.kind(), "dotted_name" | "identifier") {
            continue;
        }
        let label = text(b, name);
        let alias = item
            .child_by_field_name("alias")
            .map(|a| text(b, a))
            .unwrap_or_else(|| {
                if from.is_some() {
                    label.clone()
                } else {
                    label.split('.').next().unwrap_or("").into()
                }
            });
        b.import(
            from.clone().unwrap_or_else(|| label.clone()),
            alias,
            from.as_ref().map(|_| label),
            item.start_byte(),
            item.end_byte(),
        );
    }
}
fn js_import(b: &mut Builder<'_>, n: Node<'_>) {
    let Some(src) = n.child_by_field_name("source") else {
        b.limit("typescript_import_alias_requires_review");
        return;
    };
    let module = text(b, src).trim_matches(['\'', '"']).to_owned();
    fn each(b: &mut Builder<'_>, n: Node<'_>, module: &str) {
        match n.kind() {
            "import_specifier" => {
                if let Some(name) = n.child_by_field_name("name") {
                    let symbol = text(b, name);
                    let alias = n
                        .child_by_field_name("alias")
                        .map(|x| text(b, x))
                        .unwrap_or_else(|| symbol.clone());
                    b.import(
                        module.into(),
                        alias,
                        Some(symbol),
                        n.start_byte(),
                        n.end_byte(),
                    );
                }
            }
            "namespace_import" => {
                if let Some(name) = children(n).into_iter().find(|x| x.kind() == "identifier") {
                    b.import(
                        module.into(),
                        text(b, name),
                        None,
                        n.start_byte(),
                        n.end_byte(),
                    );
                }
            }
            "identifier" => b.import(
                module.into(),
                text(b, n),
                Some("default".into()),
                n.start_byte(),
                n.end_byte(),
            ),
            _ => {
                for c in children(n) {
                    each(b, c, module)
                }
            }
        }
    }
    for c in children(n) {
        if c.id() != src.id() {
            each(b, c, &module)
        }
    }
}
