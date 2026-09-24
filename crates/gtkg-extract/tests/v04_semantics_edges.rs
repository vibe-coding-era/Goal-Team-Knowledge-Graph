use gtkg_extract::v04::{AnalysisContext,CallSite,Declaration,ExtractedFile,extract};
fn parse(path:&str,src:&str)->ExtractedFile{extract(path,src.as_bytes(),&AnalysisContext::default()).unwrap()}
fn visible(f:&ExtractedFile,d:&Declaration,c:&CallSite)->bool{
    let mut scope=Some(c.scope_id.as_str());while let Some(id)=scope{if id==d.scope_id{return true}scope=f.scopes.iter().find(|s|s.id==id).and_then(|s|s.parent.as_deref())}false
}

#[test]
fn go_control_bindings_have_lexical_lifetime() {
    let f=parse("p/a.go","package p\nfunc f() {}\nfunc run(xs []int) { for i, f := range xs { f(); _ = i }; if f := false; f { f() }; f() }\n");
    let calls:Vec<_>=f.calls.iter().filter(|c|c.expression=="f()").collect();assert_eq!(calls.len(),3);
    let locals:Vec<_>=f.declarations.iter().filter(|d|d.name=="f" && d.kind=="variable").collect();assert_eq!(locals.len(),2);
    assert!(locals.iter().any(|d|visible(&f,d,calls[0])));assert!(locals.iter().any(|d|visible(&f,d,calls[1])));
    assert!(locals.iter().all(|d|!visible(&f,d,calls[2])));
    assert!(f.declarations.iter().any(|d|d.name=="i"));
}

#[test]
fn python_loop_with_except_and_comprehension_bindings_are_retained() {
    let f=parse("a.py","def f(): pass\ndef run(xs, cm):\n    for f in xs:\n        f()\n    with cm() as g:\n        g()\n    try:\n        f()\n    except Exception as err:\n        err()\n    values = [item() for item in xs]\n");
    for name in ["f","g","err","item"]{assert!(f.declarations.iter().any(|d|d.name==name&&d.kind=="variable"),"missing {name}");}
    let item=f.declarations.iter().find(|d|d.name=="item").unwrap();
    let call=f.calls.iter().find(|c|c.expression=="item()").unwrap();assert!(visible(&f,item,call));
    let g=f.declarations.iter().find(|d|d.name=="g").unwrap();assert_ne!(item.scope_id,g.scope_id);
}

#[test]
fn javascript_catch_loop_and_destructured_names_do_not_escape() {
    let f=parse("a.js","function f() {} function run(xs, obj) { for (let f of xs) { f(); } try { f(); } catch(f) { f(); } f(); const {exists: local, value = 2} = obj; local(); }");
    let calls:Vec<_>=f.calls.iter().filter(|c|c.expression=="f()").collect();assert_eq!(calls.len(),4);
    let locals:Vec<_>=f.declarations.iter().filter(|d|d.name=="f"&&d.kind!="function").collect();assert_eq!(locals.len(),2);
    assert!(locals.iter().any(|d|visible(&f,d,calls[0])));assert!(locals.iter().any(|d|visible(&f,d,calls[2])));
    assert!(locals.iter().all(|d|!visible(&f,d,calls[1])&&!visible(&f,d,calls[3])));
    assert!(f.declarations.iter().any(|d|d.name=="local"));assert!(f.declarations.iter().any(|d|d.name=="value"));
    assert!(!f.declarations.iter().any(|d|d.name=="exists"));
}

#[test]
fn rust_for_and_match_patterns_are_scoped_and_indexed_calls_stay_dynamic() {
    let f=parse("a.rs","fn f() {} fn run(xs: Vec<fn()>, opt: Option<fn()>) { for f in xs { f(); } match opt { Some(f) => f(), None => f() } f(); }");
    let calls:Vec<_>=f.calls.iter().filter(|c|c.expression=="f()").collect();assert_eq!(calls.len(),4);
    let locals:Vec<_>=f.declarations.iter().filter(|d|d.name=="f"&&d.kind=="variable").collect();assert_eq!(locals.len(),2);
    assert!(locals.iter().any(|d|visible(&f,d,calls[0])));assert!(locals.iter().any(|d|visible(&f,d,calls[1])));
    assert!(locals.iter().all(|d|!visible(&f,d,calls[2])&&!visible(&f,d,calls[3])));
    let go=parse("a.go","package p\nfunc f() {}\nfunc run(fs []func()) { fs[0]() }\n");
    assert_eq!(go.calls[0].callee,"fs[0]");
}

#[test]
fn go_grouped_names_variadic_parameters_and_build_constraint_precedence() {
    let src="//go:build (darwin || linux) && arm64 && !special\n\npackage p\nconst A, B = 1, 2\nvar C, D bool\nfunc run(first, second int, rest ...string) { }\n";
    let f=parse("p/a.go",src);assert_eq!(f.variant_status,"active");
    for name in ["A","B","C","D","first","second","rest"]{assert!(f.declarations.iter().any(|d|d.name==name),"missing {name}");}
    let invalid=parse("p/a.go","//go:build darwin &&\n\npackage p\n");assert_eq!(invalid.variant_status,"inactive");assert!(invalid.limitations.iter().any(|l|l=="invalid_build_constraint"));
}
