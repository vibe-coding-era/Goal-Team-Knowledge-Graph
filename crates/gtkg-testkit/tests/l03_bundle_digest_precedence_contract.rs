//! Rev24 L03 coverage follow-up: caller digest precedence over compatibility.
//!
//! This is an independent Oracle, not a new implementation-driving Red. A
//! markerless bundle with a wrong caller digest must be rejected for digest
//! mismatch before it can receive the stable rebuild disposition.

use std::fs;

use gtkg_core::{CallContext, Dispatcher, EffectPolicy, TransportKind};
use gtkg_protocol::{ErrorCode, OperationId, OperationRequest};
use serde_json::json;
use tempfile::tempdir;

#[test]
fn wrong_caller_digest_precedes_markerless_bundle_compatibility() {
    let temp = tempdir().expect("tempdir");
    let bundle = temp.path().join("legacy-bundle");
    fs::create_dir_all(&bundle).expect("legacy bundle root");
    fs::write(bundle.join("artifact-manifest.json"), b"{}\n").expect("legacy marker");

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
                "l03-digest-precedence",
                json!({
                    "bundle_path": bundle,
                    "expected_tree_sha256": format!("sha256:{}", "0".repeat(64))
                }),
            ),
        )
        .expect_err("wrong caller digest must fail before compatibility classification");

    assert_eq!(error.error.code, ErrorCode::BundleInvalid);
    assert_ne!(error.error.stage, "bundle.compatibility");
    assert!(
        error
            .error
            .message
            .contains("expected tree digest mismatch")
    );
    assert!(!error.error.recovery_hint.contains("legacy bundle"));
}
