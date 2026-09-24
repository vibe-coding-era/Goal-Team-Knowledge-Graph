use std::collections::BTreeMap;
use gtkg_extract::v04::{AnalysisContext,extract};
use gtkg_extract::v04::binding::{bind,verify_all,confirmed_edges};

#[test]
fn batch_replay_requires_all_call_sites_and_rejects_duplicates(){
    let ctx=AnalysisContext::default();let raw:BTreeMap<_,_>=(0..256).map(|i|(format!("p{i}/a.py"),b"def f(): pass\nf()\nf()\n".to_vec())).collect();
    let files:Vec<_>=raw.iter().map(|(p,s)|extract(p,s,&ctx).unwrap()).collect();let proofs=bind(&files,&ctx);assert_eq!(proofs.len(),512);
    verify_all(&proofs,&raw,&ctx).unwrap();assert_eq!(confirmed_edges(&proofs,&raw,&ctx).unwrap().len(),512);
    let mut missing=proofs.clone();missing.pop();assert!(verify_all(&missing,&raw,&ctx).is_err());
    let mut duplicate=proofs.clone();duplicate[1]=duplicate[0].clone();assert!(verify_all(&duplicate,&raw,&ctx).is_err());
    let mut reversed=files.clone();reversed.reverse();assert_eq!(bind(&reversed,&ctx),proofs);
}

#[test]
fn source_authority_flags_prevent_unexported_decorated_and_disabled_confirmations(){
    let mut ctx=AnalysisContext::default();ctx.import_modules.insert("./dep".into(),"dep.ts".into());
    let raw:BTreeMap<_,_>=[("a.ts","import {hidden, visible} from './dep'; hidden(); visible();"),("dep.ts","function hidden(){} export function visible(){}"),("a.py","def wrap(f): return f\n@wrap\ndef altered(): pass\ndef plain(): pass\naltered()\nplain()\n"),("a.rs","#[cfg(any())]\nfn disabled() {}\nfn run(){ disabled(); }")].into_iter().map(|(p,s)|(p.to_string(),s.as_bytes().to_vec())).collect();
    let files:Vec<_>=raw.iter().map(|(p,s)|extract(p,s,&ctx).unwrap()).collect();let proofs=bind(&files,&ctx);assert_eq!(proofs.len(),5);
    for expression in ["hidden()","altered()","disabled()"]{assert_ne!(proofs.iter().find(|p|p.call.expression==expression).unwrap().proof_status,"confirmed","{expression}");}
    for expression in ["visible()","plain()"]{assert_eq!(proofs.iter().find(|p|p.call.expression==expression).unwrap().proof_status,"confirmed","{expression}");}
    verify_all(&proofs,&raw,&ctx).unwrap();
}
