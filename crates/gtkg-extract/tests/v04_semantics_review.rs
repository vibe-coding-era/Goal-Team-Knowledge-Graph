//! Independent QK-T02 syntax/scope oracles; no runtime execution or quality-percentage claim.
use gtkg_extract::v04::{AnalysisContext, extract};
#[test]
fn go_build_looking_text_inside_block_comment_is_not_a_directive() {
    let src = "/* documentation example:\n//go:build linux\n*/\n\npackage p\nfunc Active() {}\n";
    let f = extract("p/host.go", src.as_bytes(), &AnalysisContext::default()).unwrap();
    assert_eq!(f.parse_status, "parsed");
    assert_eq!(
        f.variant_status, "active",
        "Go does not recognize build tags inside a block comment"
    );
}
#[test]
fn go_ignored_filename_has_explicit_inactive_status() {
    for path in ["p/_ignored.go", "p/.ignored.go"] {
        let f = extract(
            path,
            b"package p\nfunc Hidden() {}\n",
            &AnalysisContext::default(),
        )
        .unwrap();
        assert_eq!(
            f.variant_status, "inactive",
            "Go ignores file basename beginning with . or _: {path}"
        );
        assert_eq!(f.semantic_status, "not_requested");
        assert!(!f.limitations.is_empty());
    }
}
#[test]
fn javascript_and_typescript_getters_are_not_callable_methods() {
    for path in ["a.js", "a.ts"] {
        let src = "class A { get ready() { return false; } run() { return this.ready(); } }";
        let f = extract(path, src.as_bytes(), &AnalysisContext::default()).unwrap();
        assert_eq!(f.parse_status, "parsed");
        let getter = f.declarations.iter().find(|d| d.name == "ready").unwrap();
        assert_ne!(
            getter.callability, "callable",
            "an accessor property returning false is not a callable declaration"
        );
        assert_eq!(f.calls.len(), 1);
        assert_eq!(
            &src[f.calls[0].span.byte_start..f.calls[0].span.byte_end],
            "this.ready()"
        );
    }
}
#[test]
fn rust_if_let_binding_shadows_global_in_its_lexical_branch() {
    let src = "fn f() {}\nfn run(x: Option<fn()>) { if let Some(f) = x { f(); } f(); }";
    let parsed = extract("a.rs", src.as_bytes(), &AnalysisContext::default()).unwrap();
    assert_eq!(parsed.parse_status, "parsed");
    let bind = parsed
        .declarations
        .iter()
        .find(|d| d.name == "f" && d.kind == "variable")
        .expect("if-let introduces a lexical binding, never a global-name guess");
    let calls: Vec<_> = parsed
        .calls
        .iter()
        .filter(|c| c.expression == "f()")
        .collect();
    assert_eq!(calls.len(), 2);
    assert_ne!(calls[0].scope_id, calls[1].scope_id);
    let mut id = Some(calls[0].scope_id.as_str());
    let mut found = false;
    while let Some(scope) = id {
        if scope == bind.scope_id {
            found = true;
            break;
        }
        id = parsed
            .scopes
            .iter()
            .find(|s| s.id == scope)
            .and_then(|s| s.parent.as_deref());
    }
    assert!(found, "branch call must reach its if-let binding scope");
}
#[test]
fn python_comprehension_and_nested_function_keep_separate_shadow_scopes() {
    let src = "def f():\n    return 1\ndef outer(callbacks):\n    values = [f() for f in callbacks]\n    def inner(f):\n        return f()\n    return f()\n";
    let f = extract("a.py", src.as_bytes(), &AnalysisContext::default()).unwrap();
    let calls: Vec<_> = f.calls.iter().filter(|c| c.expression == "f()").collect();
    assert_eq!(calls.len(), 3);
    assert_ne!(calls[0].scope_id, calls[1].scope_id);
    assert_ne!(calls[1].scope_id, calls[2].scope_id);
    assert!(
        f.declarations
            .iter()
            .any(|d| d.name == "f" && d.kind == "parameter")
    );
    assert!(
        f.declarations
            .iter()
            .any(|d| d.name == "f" && d.kind == "variable")
    );
    for call in calls {
        assert_eq!(
            &src[call.span.byte_start..call.span.byte_end],
            call.expression
        );
    }
}
