#[path = "v04_lifecycle_fixture.rs"]
mod fixture;
use fixture::Fixture;
use gtkg_core::{CallContext,EffectPolicy,TransportKind};
use gtkg_core::v04::{lifecycle as life,semantic_projection as semantic,query_meter::{QueryMeter,QueryBudgetLimits,QueryBudgetUsage}};

#[test]
fn portable_import_replays_then_creates_a_new_workspace_local_admission() {
    let f=Fixture::new(); let (verified_ref,accepted_refs,views_ref)=f.build("portable",&[],false);
    let result=life::finalize_semantic(&f.context,&f.workspace,&life::SemanticFinalizeRequest {schema:"gtkg.qk.semantic-finalize/v1".into(),verified_ref,accepted_refs,views_ref,output_path:f.workspace.join(".gtkg/qk/bundles/before"),predecessor:None}).unwrap();
    let moved=f.workspace.join(".gtkg/qk/bundles/after"); std::fs::rename(&result.bundle.workspace_root,&moved).unwrap(); std::fs::remove_dir_all(&f.repository).unwrap();
    let locator=life::BundleLocator {workspace_root:moved.clone(),manifest_ref:result.bundle.manifest_ref};
    let ro=CallContext::restricted(TransportKind::Test,vec![f.workspace.clone()],EffectPolicy::ReadOnly).unwrap();
    assert!(matches!(life::verify_any(&ro,&locator).unwrap(),life::AnyBundleVerification::Semantic(_)));
    assert!(life::import_any(&ro,&locator).is_err());
    assert!(!moved.join(".gtkg/qk/runtime/query-authority.json").exists());
    life::import_any(&f.context,&locator).unwrap();
    let mut meter=QueryMeter::new(QueryBudgetUsage::default(),QueryBudgetLimits::for_index(1280*1024*1024));
    semantic::load_overlay_with_io(&ro,&moved,&result.manifest.query_index_ref,&mut meter).unwrap();
    life::verify_any(&ro,&locator).unwrap();
}

#[test]
fn identical_frozen_input_is_identical_with_a_predecessor_and_manifest_tampering_fails() {
    let f=Fixture::new(); let (verified_ref,accepted_refs,views_ref)=f.build("identical",&[],false);
    let mut request=life::SemanticFinalizeRequest {schema:"gtkg.qk.semantic-finalize/v1".into(),verified_ref,accepted_refs,views_ref,output_path:f.workspace.join(".gtkg/qk/bundles/full"),predecessor:None};
    let full=life::finalize_semantic(&f.context,&f.workspace,&request).unwrap();
    request.output_path=f.workspace.join(".gtkg/qk/bundles/incremental"); request.predecessor=Some(full.bundle.clone());
    let incremental=life::finalize_semantic(&f.context,&f.workspace,&request).unwrap();
    assert_eq!(full.manifest,incremental.manifest); assert!(incremental.delta.invalidated_dependencies.is_empty());
    let path=incremental.bundle.workspace_root.join(&incremental.manifest.semantic_catalog_ref.path);
    let mut raw=std::fs::read(&path).unwrap(); raw[0]=b'['; std::fs::write(path,raw).unwrap();
    assert!(life::verify_any(&f.context,&incremental.bundle).is_err());
}
