//! Independent source-language counterexamples for conservative binding proofs.
use gtkg_extract::v04::binding::{BindingTarget, bind, confirmed_edges, verify, verify_all};
use gtkg_extract::v04::{AnalysisContext, extract};
use std::collections::BTreeMap;
fn run(
    items: &[(&str, &str)],
    ctx: &AnalysisContext,
) -> (
    BTreeMap<String, Vec<u8>>,
    Vec<gtkg_extract::v04::ExtractedFile>,
    Vec<gtkg_extract::v04::binding::CallBindingProof>,
) {
    let raw: BTreeMap<_, _> = items
        .iter()
        .map(|(p, s)| (p.to_string(), s.as_bytes().to_vec()))
        .collect();
    let facts: Vec<_> = raw
        .iter()
        .map(|(p, s)| extract(p, s, ctx).unwrap())
        .collect();
    let proofs = bind(&facts, ctx);
    (raw, facts, proofs)
}
#[test]
fn javascript_reassignment_and_python_deletion_do_not_confirm_original_function() {
    let ctx = AnalysisContext::default();
    for (path, src) in [
        ("a.js", "function f() {} f = false; f();"),
        ("a.ts", "function f() {} f = false; f();"),
        ("a.py", "def f(): pass\ndel f\nf()\n"),
    ] {
        let (raw, _, proofs) = run(&[(path, src)], &ctx);
        let call = proofs.iter().find(|p| p.call.expression == "f()").unwrap();
        assert_ne!(
            call.proof_status, "confirmed",
            "deleted or reassigned non-callable binding in {path} cannot resolve to original declaration"
        );
        verify_all(&proofs, &raw, &ctx).unwrap();
        assert!(confirmed_edges(&proofs, &raw, &ctx).unwrap().is_empty());
    }
}
#[test]
fn default_export_internal_name_is_not_a_named_export() {
    let mut ctx = AnalysisContext::default();
    ctx.import_modules.insert("./dep".into(), "dep.js".into());
    let (raw, _, proofs) = run(
        &[
            ("a.js", "import { hidden } from './dep'; hidden();"),
            ("dep.js", "export default function hidden() {}"),
        ],
        &ctx,
    );
    let p = proofs
        .iter()
        .find(|p| p.call.expression == "hidden()")
        .unwrap();
    assert_ne!(
        p.proof_status, "confirmed",
        "named declaration of default export is module-local, not a named export"
    );
    verify_all(&proofs, &raw, &ctx).unwrap();
}
#[test]
fn independently_replayed_real_spans_do_not_authorize_wrong_language_or_package() {
    let ctx = AnalysisContext::default();
    let (raw, facts, proofs) = run(
        &[
            ("p/a.go", "package p\nfunc f() {}\nfunc run(){ f() }"),
            ("other/a.go", "package p\nfunc f() {}"),
            ("same.py", "def f(): pass\n"),
        ],
        &ctx,
    );
    let proof = &proofs[0];
    assert_eq!(proof.target.as_ref().unwrap().path, "p/a.go");
    verify(proof, &raw, &ctx).unwrap();
    for path in ["other/a.go", "same.py"] {
        let mut bad = proof.clone();
        let decl = facts
            .iter()
            .find(|f| f.path == path)
            .unwrap()
            .declarations
            .iter()
            .find(|d| d.name == "f")
            .unwrap()
            .clone();
        bad.target = Some(BindingTarget {
            path: path.into(),
            declaration: decl,
        });
        bad.candidates = vec![bad.target.as_ref().unwrap().declaration.id.clone()];
        assert!(verify(&bad, &raw, &ctx).is_err());
    }
}
#[test]
fn full_call_denominator_and_target_context_are_bound() {
    let ctx = AnalysisContext::default();
    let (raw, _, proofs) = run(&[("a.py", "def f(): pass\nf()\nf()\n")], &ctx);
    verify_all(&proofs, &raw, &ctx).unwrap();
    assert!(verify_all(&proofs[..1], &raw, &ctx).is_err());
    assert!(verify_all(&[proofs[0].clone(), proofs[0].clone()], &raw, &ctx).is_err());
    let mut changed = ctx.clone();
    changed.snapshot_id = "another-source-context".into();
    assert!(verify_all(&proofs, &raw, &changed).is_err());
}
