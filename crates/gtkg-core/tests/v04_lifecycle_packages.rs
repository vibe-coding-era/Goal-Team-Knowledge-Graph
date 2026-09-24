#[path = "v04_lifecycle_fixture.rs"] mod fixture;
use fixture::Fixture;
use gtkg_core::{CallContext,EffectPolicy,TransportKind};
use gtkg_core::v04::{artifact,index,lifecycle::*,query};
use gtkg_protocol::v04::{QueryPayload,Revision};
use std::fs;
fn request(f:&Fixture, refs:(gtkg_protocol::FileReceiptRef,Vec<gtkg_protocol::FileReceiptRef>,gtkg_protocol::FileReceiptRef), name:&str)->FinalizeRequest {
    FinalizeRequest {verified_ref:refs.0,accepted_refs:refs.1,views_ref:refs.2,output_path:f.workspace.join(format!(".gtkg/qk/bundles/{name}")),predecessor:None}
}
#[test]
fn bundle_moves_with_complete_source_knowledge_index_closure_and_fresh_authority() {
    let f=Fixture::new(); let refs=f.build("v1",&[("extra.md","Entry Entry extra fixture evidence.\n")],false);
    let built=finalize(&f.context,&f.workspace,&request(&f,refs,"portable")).unwrap();
    assert!(built.manifest.indexes_rebuildable && built.manifest.knowledge_ready);
    assert!(!built.authority_exported && !built.manifest.llm_qa_validated);
    assert!(!built.manifest.canonical_okf_refs.is_empty());
    assert!(built.manifest.files.iter().any(|x|x.role=="source_object"));
    assert!(built.manifest.files.iter().all(|x|!x.reference.path.contains("query-authority")));
    let original_key=fs::read(f.workspace.join(".gtkg/qk/runtime/query-authority.json")).unwrap();
    let original_query=QueryPayload {payload_revision:Revision::R1,workspace_root:f.workspace.clone(),index_ref:built.manifest.index_ref.clone(),query:"Entry".into(),query_policy:index::QUERY_POLICY.into(),max_results:1,max_tokens:8000,continuation:None};
    let cursor=query::search(&f.context,&original_query).unwrap()["continuation"].as_str().expect("multi-candidate or bounded query yields a continuation").to_string();
    let moved=f.temp.path().join("imported");fs::rename(&built.bundle.workspace_root,&moved).unwrap();
    fs::rename(&f.repository,f.temp.path().join("repository-moved-away")).unwrap();
    let locator=BundleLocator {workspace_root:moved.clone(),manifest_ref:built.bundle.manifest_ref};
    let read=CallContext::restricted(TransportKind::Test,vec![moved.clone()],EffectPolicy::ReadOnly).unwrap();
    assert!(!moved.join(".gtkg/qk/runtime/query-authority.json").exists());
    assert_eq!(verify(&read,&locator).unwrap().verified_files,built.manifest.files.len());
    let write=CallContext::restricted(TransportKind::Test,vec![moved.clone()],EffectPolicy::WorkspaceWrite).unwrap();
    import_bundle(&write,&locator).unwrap();
    assert_ne!(fs::read(moved.join(".gtkg/qk/runtime/query-authority.json")).unwrap(),original_key);
    let mut continued=original_query;continued.workspace_root=moved;continued.continuation=Some(cursor);
    assert!(query::search(&write,&continued).is_err());
    assert!(verify(&read,&locator).is_ok(),"private imported runtime authority is outside the public closure");
}
#[test]
fn incremental_same_source_matches_full_and_deleted_source_never_leaks_into_new_closure() {
    let f=Fixture::new();let old=f.build("old",&[("obsolete.md","ObsoleteEntry marker.\n"),("changed.md","previous content\n")],false);
    let predecessor=finalize(&f.context,&f.workspace,&request(&f,old,"old")).unwrap();
    let current=f.build("new",&[("fresh.md","FreshEntry marker.\n"),("changed.md","new content\n")],false);
    let full=finalize(&f.context,&f.workspace,&request(&f,current.clone(),"full")).unwrap();
    let mut incremental=request(&f,current,"incremental");incremental.predecessor=Some(predecessor.bundle);
    let next=finalize(&f.context,&f.workspace,&incremental).unwrap();
    assert_eq!(full.manifest,next.manifest);
    assert_eq!(full.bundle.manifest_ref.sha256,next.bundle.manifest_ref.sha256);
    assert!(next.delta.deleted_paths.contains(&"obsolete.md".into()));
    assert!(next.delta.added_paths.contains(&"fresh.md".into()));
    assert!(next.delta.changed_paths.contains(&"changed.md".into()));
    let(m,_):(index::IndexManifest,_)=artifact::read(&f.context,&next.bundle.workspace_root,&next.manifest.index_ref).unwrap();
    assert!(index::load_postings(&f.context,&next.bundle.workspace_root,&m,"exact:ObsoleteEntry").unwrap().is_empty());
    assert!(!index::load_postings(&f.context,&next.bundle.workspace_root,&m,"exact:FreshEntry").unwrap().is_empty());
}
#[test]
fn package_verify_rejects_canonical_okf_tamper_missing_source_and_rehashed_identity() {
    let f=Fixture::new();let refs=f.build("v1",&[],false);
    let built=finalize(&f.context,&f.workspace,&request(&f,refs,"tamper")).unwrap();
    let path=built.bundle.workspace_root.join(&built.manifest.canonical_okf_refs[0].path);
    let old=fs::read(&path).unwrap();fs::write(&path,b"invented accepted knowledge").unwrap();assert!(verify(&f.context,&built.bundle).is_err());fs::write(&path,old).unwrap();
    let source=built.manifest.files.iter().find(|x|x.role=="source_object").unwrap();let path=built.bundle.workspace_root.join(&source.reference.path);
    let bytes=fs::read(&path).unwrap();fs::remove_file(&path).unwrap();assert!(verify(&f.context,&built.bundle).is_err());fs::write(path,bytes).unwrap();
    let mut manifest=built.manifest;manifest.identity.query_policy="forged-policy".into();let raw=serde_json::to_vec_pretty(&manifest).unwrap();
    fs::write(built.bundle.workspace_root.join(&built.bundle.manifest_ref.path),&raw).unwrap();
    let mut forged=built.bundle;forged.manifest_ref.sha256=artifact::digest(&raw);
    assert!(verify(&f.context,&forged).unwrap_err().contains("stale"));
}
#[test]
fn finalize_refuses_output_escape_readonly_effects_and_unrelated_files() {
    let f=Fixture::new();let refs=f.build("v1",&[],false);let mut input=request(&f,refs,"safe");
    input.output_path=f.workspace.join("unscoped");assert!(finalize(&f.context,&f.workspace,&input).is_err());assert!(!input.output_path.exists());
    input.output_path=f.workspace.join(".gtkg/qk/bundles/safe");
    let readonly=CallContext::restricted(TransportKind::Test,vec![f.workspace.clone()],EffectPolicy::ReadOnly).unwrap();assert!(finalize(&readonly,&f.workspace,&input).is_err());
    fs::create_dir_all(&input.output_path).unwrap();fs::write(input.output_path.join("unrelated.txt"),b"keep me").unwrap();
    assert!(finalize(&f.context,&f.workspace,&input).is_err());assert_eq!(fs::read(input.output_path.join("unrelated.txt")).unwrap(),b"keep me");
}
