//! Public synthetic source only: accepted bodies must reach a separate transferable index.
#[path = "v04_lifecycle_fixture.rs"]
mod fixture;
use fixture::Fixture;
use gtkg_core::v04::{analysis, artifact, semantic_projection::{self as semantic, SemanticPrepareRequest}};

#[test]
fn accepted_claim_projection_has_a_distinct_overlay_and_preserves_source_index() {
    let f = Fixture::new();
    let (verified_ref, accepted_refs, _) = f.build("semantic", &[], false);
    let (v, _): (analysis::VerifiedAnalysis, _) = artifact::read(&f.context, &f.workspace, &verified_ref).unwrap();
    let base_index_ref = v.index_ref.unwrap();
    let original = std::fs::read(f.workspace.join(&base_index_ref.path)).unwrap();
    let replayed = semantic::replay_projection(&f.context, &f.workspace, &SemanticPrepareRequest {
        schema: "gtkg.qk.semantic-prepare/v1".into(), verified_ref, base_index_ref: base_index_ref.clone(), accepted_refs,
    }).unwrap();
    let overlay = semantic::publish_projection(&f.context, &f.workspace, replayed).unwrap();
    assert_ne!(overlay, base_index_ref);
    assert_eq!(std::fs::read(f.workspace.join(&base_index_ref.path)).unwrap(), original);
    let (value, _): (semantic::QueryIndexOverlay, _) = artifact::read(&f.context, &f.workspace, &overlay).unwrap();
    assert_eq!(value.base_index_ref.sha256, base_index_ref.sha256);
    let (catalog, _): (semantic::SemanticCatalogManifest, _) = artifact::read(&f.context, &f.workspace, &gtkg_protocol::FileReceiptRef { path: value.catalog_ref.path, sha256: value.catalog_ref.sha256 }).unwrap();
    assert_eq!(catalog.total_contexts, 1);
    assert!(catalog.total_mappings > 0);
    assert_eq!(catalog.router.len(), 256);
    assert_eq!(catalog.context_router.len(), 256);
}
