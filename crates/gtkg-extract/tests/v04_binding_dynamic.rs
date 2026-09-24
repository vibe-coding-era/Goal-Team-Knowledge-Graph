use gtkg_extract::v04::binding::{bind, verify_all};
use gtkg_extract::v04::{AnalysisContext, extract};
use std::collections::BTreeMap;
#[test]
fn imported_python_module_members_are_not_confirmed_after_explicit_mutation() {
    let mut ctx = AnalysisContext::default();
    ctx.import_modules.insert("dep".into(), "dep.py".into());
    for statement in ["dep.f = False", "del dep.f", "setattr(dep, 'f', False)"] {
        let raw: BTreeMap<_, _> = [
            (
                "a.py".to_string(),
                format!("import dep\n{statement}\ndep.f()\n").into_bytes(),
            ),
            ("dep.py".to_string(), b"def f(): pass\n".to_vec()),
        ]
        .into_iter()
        .collect();
        let files: Vec<_> = raw
            .iter()
            .map(|(p, s)| extract(p, s, &ctx).unwrap())
            .collect();
        let proofs = bind(&files, &ctx);
        assert_ne!(
            proofs
                .iter()
                .find(|p| p.call.expression == "dep.f()")
                .unwrap()
                .proof_status,
            "confirmed",
            "{statement}"
        );
        verify_all(&proofs, &raw, &ctx).unwrap();
    }
}
#[test]
fn explicit_eval_cannot_leave_a_callable_proof_for_a_replaced_lexical_function() {
    let ctx = AnalysisContext::default();
    for (path, src) in [
        ("a.py", "def f(): pass\nexec('f = False')\nf()\n"),
        ("a.js", "function f(){} eval('f = false'); f();"),
    ] {
        let raw: BTreeMap<_, _> = [(path.to_string(), src.as_bytes().to_vec())]
            .into_iter()
            .collect();
        let files: Vec<_> = raw
            .iter()
            .map(|(p, s)| extract(p, s, &ctx).unwrap())
            .collect();
        let proofs = bind(&files, &ctx);
        assert_ne!(
            proofs
                .iter()
                .find(|p| p.call.expression == "f()")
                .unwrap()
                .proof_status,
            "confirmed",
            "{path}"
        );
        verify_all(&proofs, &raw, &ctx).unwrap();
    }
}
