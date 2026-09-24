//! Narrow independent regression for transparent boxed verification results.
#![allow(clippy::unwrap_used)]
#[allow(dead_code)]
#[path = "v04_lifecycle_fixture.rs"]
mod fixture;
use fixture::Fixture;
use gtkg_core::v04::lifecycle::{self as life, AnyBundleVerification};
use gtkg_core::{CallContext, EffectPolicy, TransportKind};

fn assert_transparent(value: &AnyBundleVerification) {
    let wire = serde_json::to_vec(value).unwrap();
    let underlying = match value {
        AnyBundleVerification::Source(inner) => serde_json::to_vec(inner.as_ref()).unwrap(),
        AnyBundleVerification::Semantic(inner) => serde_json::to_vec(inner.as_ref()).unwrap(),
    };
    assert_eq!(
        wire, underlying,
        "Box or enum wrapping changed the public JSON shape"
    );
    let restored: AnyBundleVerification = serde_json::from_slice(&wire).unwrap();
    assert!(matches!(
        (value, &restored),
        (
            AnyBundleVerification::Source(_),
            AnyBundleVerification::Source(_)
        ) | (
            AnyBundleVerification::Semantic(_),
            AnyBundleVerification::Semantic(_)
        )
    ));
    assert_eq!(serde_json::to_vec(&restored).unwrap(), wire);
}

#[test]
fn boxed_verification_preserves_both_wire_shapes_and_portable_import() {
    let f = Fixture::new();
    let (verified_ref, accepted_refs, views_ref) = f.build("boxed-verification", &[], false);
    let source = life::finalize(
        &f.context,
        &f.workspace,
        &life::FinalizeRequest {
            verified_ref: verified_ref.clone(),
            accepted_refs: accepted_refs.clone(),
            views_ref: views_ref.clone(),
            output_path: f.workspace.join(".gtkg/qk/bundles/source-box"),
            predecessor: None,
        },
    )
    .unwrap();
    let semantic = life::finalize_semantic(
        &f.context,
        &f.workspace,
        &life::SemanticFinalizeRequest {
            schema: "gtkg.qk.semantic-finalize/v1".into(),
            verified_ref,
            accepted_refs,
            views_ref,
            output_path: f.workspace.join(".gtkg/qk/bundles/semantic-box"),
            predecessor: None,
        },
    )
    .unwrap();
    std::fs::remove_dir_all(&f.repository).unwrap();
    let ro = CallContext::restricted(
        TransportKind::Test,
        vec![f.workspace.clone()],
        EffectPolicy::ReadOnly,
    )
    .unwrap();
    for locator in [&source.bundle, &semantic.bundle] {
        let verified = life::verify_any(&ro, locator).unwrap();
        assert_transparent(&verified);
        let authority = locator
            .workspace_root
            .join(".gtkg/qk/runtime/query-authority.json");
        assert!(!authority.exists());
        assert!(life::import_any(&ro, locator).is_err());
        assert!(!authority.exists());
        let imported = life::import_any(&f.context, locator).unwrap();
        assert_transparent(&imported);
        assert!(authority.exists());
        assert_eq!(
            serde_json::to_vec(&verified).unwrap(),
            serde_json::to_vec(&imported).unwrap()
        );
    }
}
