//! Public synthetic portable closure, separate from existing source bundle schema.
#[path = "v04_lifecycle_fixture.rs"]
mod fixture;
use fixture::Fixture;
use gtkg_core::v04::{lifecycle,artifact,semantic_projection};
use gtkg_protocol::FileReceiptRef;

#[test]
fn semantic_finalize_includes_the_query_overlay_and_keeps_private_admission_out() {
    let f=Fixture::new();
    let (verified_ref,accepted_refs,views_ref)=f.build("portable_semantic",&[],false);
    let result=lifecycle::finalize_semantic(&f.context,&f.workspace,&lifecycle::SemanticFinalizeRequest {
        schema:"gtkg.qk.semantic-finalize/v1".into(),verified_ref,accepted_refs,views_ref,
        output_path:f.workspace.join(".gtkg/qk/bundles/semantic"),predecessor:None,
    }).unwrap();
    assert_eq!(result.manifest.schema,"gtkg.qk.portable-semantic-bundle/v1");
    assert_ne!(result.manifest.query_index_ref,result.manifest.base_index_ref);
    assert!(!result.authority_exported);
    assert!(result.manifest.files.iter().all(|f|!f.reference.path.starts_with(".gtkg/qk/runtime/")));
    let (overlay,_):(semantic_projection::QueryIndexOverlay,_)=artifact::read(&f.context,&result.bundle.workspace_root,&result.manifest.query_index_ref).unwrap();
    assert_eq!(FileReceiptRef {path:overlay.catalog_ref.path,sha256:overlay.catalog_ref.sha256},result.manifest.semantic_catalog_ref);
    assert!(!result.bundle.workspace_root.join(".gtkg/qk/runtime/query-authority.json").exists());
}
