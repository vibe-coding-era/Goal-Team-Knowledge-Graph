use std::collections::{BTreeMap,BTreeSet};
use gtkg_extract::v04::{AnalysisContext,ExtractedFile,extract};
use gtkg_extract::v04::binding::{bind,verify,confirmed_edges,CallBindingProof,BindingTarget};
fn fixture(items:&[(&str,&str)],ctx:&AnalysisContext)->(BTreeMap<String,Vec<u8>>,Vec<ExtractedFile>){let raw:BTreeMap<_,_>=items.iter().map(|(p,s)|(p.to_string(),s.as_bytes().to_vec())).collect();let files=raw.iter().map(|(p,s)|extract(p,s,ctx).unwrap()).collect();(raw,files)}
fn proof<'a>(proofs:&'a [CallBindingProof],path:&str,expression:&str)->&'a CallBindingProof{proofs.iter().find(|p|p.source_path==path && p.call.expression==expression).expect("every observed call retained")}
fn is_confirmed(p:&CallBindingProof)->bool{p.proof_status=="confirmed"}

#[test]
fn frozen_five_language_positive_denominator_requires_recall_and_all_emitted_precision(){
    let ctx=AnalysisContext::default();let(raw,files)=fixture(&[
        ("p/a.go","package p\nfunc f() {}\nfunc run(){ f() }"),
        ("a.py","def f(): pass\ndef run():\n    f()\n"),
        ("a.js","function f() {} function run(){ f(); }"),
        ("a.ts","function f(): void {} function run(){ f(); }"),
        ("a.rs","fn f() {} fn run(){ f(); }"),
    ],&ctx);let ps=bind(&files,&ctx);assert_eq!(ps.len(),5);
    let expected:BTreeSet<_>=raw.keys().map(|p|(p.clone(),p.clone(),"f".to_string())).collect();
    let mut actual=BTreeSet::new();for p in &ps{assert!(is_confirmed(p),"{}: {}",p.source_path,p.reason);assert_eq!(p.resolution,"resolved");verify(p,&raw,&ctx).unwrap();let t=p.target.as_ref().unwrap();actual.insert((p.source_path.clone(),t.path.clone(),t.declaration.name.clone()));}
    assert_eq!(actual,expected,"all emitted confirmed are in the independent literal gold");
    assert_eq!(confirmed_edges(&ps,&raw,&ctx).unwrap().len(),5);
}

#[test]
fn language_receiver_and_callability_adversaries_never_confirm_wrong_edges(){
    let ctx=AnalysisContext::default();let(raw,files)=fixture(&[
        ("a.py","import os\nclass A:\n    def f(self): pass\nclass B:\n    def f(self): pass\ndef run(obj):\n    exists = False\n    os.path.exists('a')\n    str(exists)\n    obj.f()\n    obj.exists()\n    exists()\n"),
        ("a.ts","const exists = false; function str(x: unknown) { return x; } function f() {}"),
    ],&ctx);let ps=bind(&files,&ctx);assert_eq!(ps.len(),5);for p in &ps{assert!(!is_confirmed(p),"false confirmed {}",p.call.expression);assert!(p.target.is_none());verify(p,&raw,&ctx).unwrap();}
    assert!(confirmed_edges(&ps,&raw,&ctx).unwrap().is_empty());
}

#[test]
fn lexical_shadowing_and_repeated_call_sites_keep_exact_targets(){
    let ctx=AnalysisContext::default();let(raw,files)=fixture(&[("a.py","def f(): pass\ndef outer():\n    f()\n    f()\n    def inner():\n        def f(): pass\n        f()\n    inner()\ndef str(x): return x\nstr(1)\n")],&ctx);
    let ps=bind(&files,&ctx);assert_eq!(ps.len(),5);assert!(ps.iter().all(is_confirmed));for p in &ps{verify(p,&raw,&ctx).unwrap();}
    let fs:Vec<_>=ps.iter().filter(|p|p.call.expression=="f()").collect();assert_eq!(fs.len(),3);assert_ne!(fs[0].call.id,fs[1].call.id);assert_eq!(fs[0].target,fs[1].target);assert_ne!(fs[0].target,fs[2].target);
    assert_eq!(proof(&ps,"a.py","str(1)").target.as_ref().unwrap().declaration.name,"str");
}

#[test]
fn control_bound_values_block_outer_same_name_functions(){
    let ctx=AnalysisContext::default();let(_,files)=fixture(&[
        ("a.py","def f(): pass\ndef run(xs):\n    for f in xs:\n        f()\n"),
        ("a.js","function f(){} function run(xs){for(let f of xs){f();} try{}catch(f){f();}}"),
        ("p/a.go","package p\nfunc f(){}\nfunc run(xs []int){for _, f := range xs {f()}}"),
        ("a.rs","fn f(){} fn run(xs: Vec<fn()>){for f in xs{f();}}"),
    ],&ctx);let ps=bind(&files,&ctx);assert_eq!(ps.len(),5);assert!(ps.iter().all(|p|!is_confirmed(p)));
}

#[test]
fn go_package_import_and_concrete_receiver_are_proven_without_stem_guessing(){
    let mut ctx=AnalysisContext::default();ctx.import_modules.insert("example/path".into(),"dep".into());
    let(raw,files)=fixture(&[
        ("p/a.go","package p\nimport \"example/path\"\nfunc run(w *Worker){ local(); w.Run(); real.F(); path.F() }"),
        ("p/b.go","package p\ntype Worker struct{}\nfunc local(){}\nfunc(w *Worker) Run(){}"),
        ("other/b.go","package p\nfunc local(){}\nfunc F(){}"),
        ("dep/remote.go","package real\nfunc F(){}"),
    ],&ctx);let ps=bind(&files,&ctx);assert_eq!(ps.len(),4);
    for expr in ["local()","w.Run()","real.F()"]{let p=proof(&ps,"p/a.go",expr);assert!(is_confirmed(p),"{expr}: {}",p.reason);verify(p,&raw,&ctx).unwrap();}
    assert_eq!(proof(&ps,"p/a.go","local()").target.as_ref().unwrap().path,"p/b.go");
    assert_eq!(proof(&ps,"p/a.go","real.F()").target.as_ref().unwrap().path,"dep/remote.go");
    assert!(!is_confirmed(proof(&ps,"p/a.go","path.F()")));
}

#[test]
fn aliases_require_exact_frozen_module_sources(){
    let mut ctx=AnalysisContext::default();ctx.import_modules.insert("pkg.one".into(),"one/same.py".into());ctx.import_modules.insert("./one".into(),"one.ts".into());
    let(raw,files)=fixture(&[
        ("a.py","from pkg.one import f as alias\nalias()\n"),("one/same.py","def f(): pass\n"),("two/same.py","def f(): pass\n"),
        ("a.ts","import { f as alias } from './one'; alias();"),("one.ts","export function f() {}"),("two.ts","export function f() {}"),
    ],&ctx);let ps=bind(&files,&ctx);assert_eq!(ps.len(),2);for p in &ps{assert!(is_confirmed(p),"{}",p.reason);verify(p,&raw,&ctx).unwrap();}
    assert_eq!(proof(&ps,"a.py","alias()").target.as_ref().unwrap().path,"one/same.py");
    assert_eq!(proof(&ps,"a.ts","alias()").target.as_ref().unwrap().path,"one.ts");
    let ctx2=AnalysisContext::default();let(_,missing)=fixture(&[("a.py","from pkg.one import f as alias\nalias()\n"),("one/same.py","def f(): pass\n")],&ctx2);assert!(bind(&missing,&ctx2).iter().all(|p|!is_confirmed(p)));
}

#[test]
fn real_spans_for_unrelated_target_do_not_prove_a_relation(){
    let ctx=AnalysisContext::default();let(raw,files)=fixture(&[("a.py","def right(): pass\ndef wrong(): pass\nright()\n")],&ctx);let ps=bind(&files,&ctx);let original=proof(&ps,"a.py","right()");verify(original,&raw,&ctx).unwrap();
    let mut swapped=original.clone();swapped.target=Some(BindingTarget{path:"a.py".into(),declaration:files[0].declarations.iter().find(|d|d.name=="wrong").unwrap().clone()});assert!(verify(&swapped,&raw,&ctx).is_err());assert!(confirmed_edges(&[swapped],&raw,&ctx).is_err());
    let mut rule=original.clone();rule.rule="name_is_unique".into();assert!(verify(&rule,&raw,&ctx).is_err());
}

#[test]
fn source_context_import_and_profile_changes_make_proofs_stale(){
    let ctx=AnalysisContext::default();let(raw,files)=fixture(&[("a.py","def f(): pass\nf()\n")],&ctx);let ps=bind(&files,&ctx);let p=proof(&ps,"a.py","f()");verify(p,&raw,&ctx).unwrap();
    let mut changed=raw.clone();changed.get_mut("a.py").unwrap().extend_from_slice(b"# changed\n");assert!(verify(p,&changed,&ctx).is_err());
    let mut context=ctx.clone();context.goarch="amd64".into();assert!(verify(p,&raw,&context).is_err());
    let mut context=ctx.clone();context.import_modules.insert("x".into(),"y".into());assert!(verify(p,&raw,&context).is_err());
    let mut modified=p.clone();modified.resolver_profile="old-resolver".into();assert!(verify(&modified,&raw,&ctx).is_err());
    let mut modified=p.clone();modified.verifier_profile="span-only".into();assert!(verify(&modified,&raw,&ctx).is_err());
    let mut reversed=files.clone();reversed.reverse();assert_eq!(bind(&files,&ctx),bind(&reversed,&ctx));
}
