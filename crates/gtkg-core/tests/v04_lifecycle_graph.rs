#[path = "v04_lifecycle_fixture.rs"] mod fixture;
use fixture::Fixture;
use gtkg_core::{CallContext, EffectPolicy, TransportKind};
use gtkg_core::v04::{artifact,graph_projection,index,lifecycle::*};
use std::fs;
#[test]
fn confirmed_graph_root_and_all_shards_are_portable_and_source_replayed() {
    let f=Fixture::new();let refs=f.build("graph",&[],true);
    let input=FinalizeRequest {verified_ref:refs.0,accepted_refs:refs.1,views_ref:refs.2,output_path:f.workspace.join(".gtkg/qk/bundles/graph"),predecessor:None};
    let bundle=finalize(&f.context,&f.workspace,&input).unwrap();
    let(m,_):(index::IndexManifest,_)=artifact::read(&f.context,&bundle.bundle.workspace_root,&bundle.manifest.index_ref).unwrap();
    let graph_ref=m.graph_ref.unwrap();
    assert!(bundle.manifest.files.iter().any(|f|f.role=="graph_manifest"&&f.reference==graph_ref));
    let(g,links,_)=graph_projection::verify_all(&f.context,&bundle.bundle.workspace_root,&graph_ref).unwrap();
    assert_eq!(links.len(),1);assert_eq!(links[0].target_name,"Entry");
    for reference in g.router.values().flatten() {assert!(bundle.manifest.files.iter().any(|f|f.role=="graph_shard"&&f.reference.path==reference.path));}
    let readonly=CallContext::restricted(TransportKind::Test,vec![bundle.bundle.workspace_root.clone()],EffectPolicy::ReadOnly).unwrap();
    assert!(verify(&readonly,&bundle.bundle).is_ok());
    let missing=g.router.values().flatten().next().unwrap();fs::remove_file(bundle.bundle.workspace_root.join(&missing.path)).unwrap();
    assert!(verify(&readonly,&bundle.bundle).is_err());
}
#[cfg(unix)]
#[test]
fn package_destination_and_legacy_tree_symlinks_fail_closed() {
    use std::os::unix::fs::symlink;
    let f=Fixture::new();let refs=f.build("v1",&[],false);
    let outside=f.workspace.join("unrelated");fs::create_dir(&outside).unwrap();
    let parent=f.workspace.join(".gtkg/qk/bundles");fs::create_dir_all(&parent).unwrap();symlink(&outside,parent.join("alias")).unwrap();
    let input=FinalizeRequest {verified_ref:refs.0,accepted_refs:refs.1,views_ref:refs.2,output_path:parent.join("alias/export"),predecessor:None};
    assert!(finalize(&f.context,&f.workspace,&input).is_err());assert!(!outside.join("export").exists());
    let old=f.workspace.join("legacy");fs::create_dir(&old).unwrap();let manifest=b"{\"schema_version\":\"gtkg.bundle/v1\"}";
    fs::write(old.join("manifest.json"),manifest).unwrap();symlink(f.workspace.join("README-never-read"),old.join("pointer")).unwrap();
    let request=MigrationRequest {legacy_root:old,legacy_manifest_ref:gtkg_protocol::FileReceiptRef {path:"manifest.json".into(),sha256:artifact::digest(manifest)},source_ref:None};
    assert!(migrate(&f.context,&f.workspace,&request).is_err());
}
