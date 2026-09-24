//! V0.2 T04: a local fixture may freeze a corpus contract, but can never
//! masquerade as external evidence, a measured host run, or a 10k result.

use std::fs;

use gtkg_core::corpus_v2::{CorpusFreezeErrorCodeV2, load_local_corpus_manifest_v2};
use gtkg_core::{CallContext, EffectPolicy, TransportKind};
use gtkg_protocol::v2::{CorpusItemV2, CorpusManifestV2, CorpusOriginV2, CorpusReadinessStatusV2};
use tempfile::TempDir;

const FIXTURE: &str = include_str!("../fixtures/v02_t04/local-corpus-contract.json");

fn root() -> TempDir {
    let root = tempfile::tempdir().expect("fixture root");
    fs::create_dir_all(root.path().join("fixtures")).expect("fixtures directory");
    fs::write(
        root.path().join("fixtures/local-corpus-contract.json"),
        FIXTURE,
    )
    .expect("fixture manifest");
    root
}

fn context(root: &TempDir) -> CallContext {
    CallContext::restricted(
        TransportKind::Test,
        vec![root.path().to_path_buf()],
        EffectPolicy::ReadOnly,
    )
    .expect("restricted context")
}

#[test]
fn local_fixture_freezes_kind_source_pin_annotation_host_and_blocked_readiness() {
    let root = root();
    let raw_manifest: CorpusManifestV2 = serde_json::from_str(FIXTURE).expect("fixture json");
    let canonical = raw_manifest
        .clone()
        .with_manifest_digest()
        .expect("fixture shape must canonicalize");
    assert_eq!(raw_manifest.manifest_sha256, canonical.manifest_sha256);
    let receipt = load_local_corpus_manifest_v2(
        &context(&root),
        &root.path().join("fixtures/local-corpus-contract.json"),
    )
    .expect("local fixture contract must validate");

    assert_eq!(receipt.manifest.kind.as_str(), "adversarial");
    assert_eq!(receipt.manifest.source.origin, CorpusOriginV2::Fixture);
    assert_eq!(
        receipt.manifest.readiness.status,
        CorpusReadinessStatusV2::Blocked
    );
    assert!(!receipt.manifest.readiness.counts_as_pass());
    assert!(!receipt.counts_toward_external_gate());
    assert_eq!(
        receipt.manifest.annotation.annotator_ids,
        vec!["fixture".to_owned()]
    );
    assert_eq!(receipt.manifest.host.host_id, "fixture-host");
    assert_eq!(receipt.manifest.split.holdout.len(), 1);
}

#[test]
fn anti_overfit_rejects_overlap_between_calibration_and_holdout_even_when_ids_differ() {
    let mut manifest: CorpusManifestV2 = serde_json::from_str(FIXTURE).expect("fixture json");
    manifest.split.holdout[0] = CorpusItemV2 {
        item_id: "different-id".to_owned(),
        content_sha256: manifest.split.calibration[0].content_sha256.clone(),
    };
    let error = manifest
        .with_manifest_digest()
        .expect_err("shared content must not cross the tuning/holdout boundary");
    assert_eq!(error.code(), "E_V2_CORPUS_SPLIT_OVERLAP");
}

#[test]
fn unknown_manifest_fields_fail_closed_during_decode() {
    let unknown = FIXTURE.replace(
        "\"schema_version\"",
        "\"unexpected\": true,\n  \"schema_version\"",
    );
    assert!(serde_json::from_str::<CorpusManifestV2>(&unknown).is_err());
}

#[test]
fn unlocked_source_or_host_identity_fails_closed() {
    let mut manifest: CorpusManifestV2 = serde_json::from_str(FIXTURE).expect("fixture json");
    manifest.source.revision = "latest".to_owned();
    let error = manifest
        .with_manifest_digest()
        .expect_err("floating source revision must fail closed");
    assert_eq!(error.code(), "E_V2_CORPUS_SOURCE_UNPINNED");

    let mut manifest: CorpusManifestV2 = serde_json::from_str(FIXTURE).expect("fixture json");
    manifest.host.toolchain_sha256 = "sha256:bad".to_owned();
    let error = manifest
        .with_manifest_digest()
        .expect_err("host toolchain identity must be exact");
    assert_eq!(error.code(), "E_V2_CORPUS_HOST_INVALID");
}

#[test]
fn canonical_manifest_digest_detects_a_post_freeze_field_change() {
    let mut manifest: CorpusManifestV2 = serde_json::from_str(FIXTURE).expect("fixture json");
    manifest.host.cpu_model = "fixture-cpu-after-change".to_owned();
    let error = manifest
        .validate()
        .expect_err("every frozen field must be bound by manifest_sha256");
    assert_eq!(error.code(), "E_V2_CORPUS_MANIFEST_DIGEST_MISMATCH");
}

#[test]
fn blocked_readiness_with_a_pass_count_is_invalid_not_a_pass() {
    let mut manifest: CorpusManifestV2 = serde_json::from_str(FIXTURE).expect("fixture json");
    manifest.readiness.pass_count = 1;
    let error = manifest
        .with_manifest_digest()
        .expect_err("blocked readiness cannot carry a pass count");
    assert_eq!(error.code(), "E_V2_CORPUS_READINESS_INVALID");
}

#[test]
fn local_loader_refuses_an_external_origin_and_never_upgrades_fixture_to_external_evidence() {
    let root = root();
    let path = root.path().join("fixtures/local-corpus-contract.json");
    let external = FIXTURE.replace("\"fixture\"", "\"external_repository\"");
    fs::write(&path, external).expect("external-looking fixture");

    let error = load_local_corpus_manifest_v2(&context(&root), &path)
        .expect_err("local fixture loader must not consume external evidence declarations");
    assert_eq!(error.code(), CorpusFreezeErrorCodeV2::ExternalOriginDenied);
}
