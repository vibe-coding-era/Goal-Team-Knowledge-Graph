//! Immutable TestCase K03-LEGACY-BUNDLE-COMPATIBILITY-R3.
//!
//! A caller-held digest authenticates bytes; it does not make a pre-current
//! bundle readable. Missing the root `index.gtkg.json` marker must produce a
//! stable rebuild disposition before current bundle verification begins.

use std::fs;

use gtkg_core::file_model::tree_sha256;
use gtkg_core::{CallContext, Dispatcher, EffectPolicy, TransportKind};
use gtkg_protocol::{ErrorCode, OperationId, OperationRequest};
use serde_json::json;
use tempfile::tempdir;

#[test]
fn legacy_bundle_with_matching_caller_digest_requires_stable_rebuild() {
    let temp = tempdir().expect("tempdir");
    let bundle = temp.path().join("legacy-bundle");
    fs::create_dir_all(&bundle).expect("bundle root");
    fs::write(bundle.join("artifact-manifest.json"), b"{}\n").expect("legacy marker");
    let digest = tree_sha256(&bundle).expect("caller-held tree digest");

    let context = CallContext::restricted(
        TransportKind::Test,
        vec![temp.path().to_path_buf()],
        EffectPolicy::WorkspaceWrite,
    )
    .expect("restricted context");
    let error = Dispatcher
        .execute(
            &context,
            OperationRequest::new(
                OperationId::BundleVerify,
                "k03-legacy-rebuild",
                json!({
                    "bundle_path": bundle,
                    "expected_tree_sha256": digest
                }),
            ),
        )
        .expect_err("legacy bundle must fail closed with rebuild disposition");

    assert_eq!(error.error.code, ErrorCode::BundleInvalid);
    assert_eq!(error.error.stage, "bundle.compatibility");
    assert!(
        error
            .error
            .message
            .contains("current index.gtkg.json marker")
    );
    assert!(error.error.recovery_hint.contains("rebuild"));
}

#[test]
fn current_marker_never_falls_back_to_legacy_compatibility() {
    let temp = tempdir().expect("tempdir");
    let bundle = temp.path().join("invalid-current-bundle");
    fs::create_dir_all(&bundle).expect("bundle root");
    fs::write(bundle.join("index.gtkg.json"), b"{}\n").expect("current marker");
    fs::write(bundle.join("artifact-manifest.json"), b"{}\n").expect("invalid manifest");
    let digest = tree_sha256(&bundle).expect("caller-held tree digest");

    let context = CallContext::restricted(
        TransportKind::Test,
        vec![temp.path().to_path_buf()],
        EffectPolicy::WorkspaceWrite,
    )
    .expect("restricted context");
    let error = Dispatcher
        .execute(
            &context,
            OperationRequest::new(
                OperationId::BundleVerify,
                "k03-current-no-fallback",
                json!({
                    "bundle_path": bundle,
                    "expected_tree_sha256": digest
                }),
            ),
        )
        .expect_err("invalid current bundle must use current verification only");

    assert_eq!(error.error.code, ErrorCode::BundleInvalid);
    assert_ne!(error.error.stage, "bundle.compatibility");
}
