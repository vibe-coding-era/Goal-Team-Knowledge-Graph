//! T15C: local current-OKF observation binds T03's frozen corpus, T11B's
//! accepted-claim overlay, and T14A's local runtime receipt.  It is expressly
//! not a Google certification or a claim of general OKF conformance.

use std::path::PathBuf;

use gtkg_core::knowledge_overlay_v2::{
    KnowledgeOverlayNodeV2, KnowledgeOverlayProvenanceV2, KnowledgeOverlayV2,
    write_knowledge_overlay_v2,
};
use gtkg_core::lifecycle_v2::{
    ArtifactSelectorV2, LifecycleIdentityV2, PostActivationReadbackReceiptV2, SelectionReceiptV2,
};
use gtkg_core::okf_current_suite_v2::{
    InternalOkfProfileV2, LocalCurrentOkfSuiteInputV2, LocalCurrentOkfSuiteReadbackInputV2,
    validate_local_current_okf_suite, validate_local_current_okf_suite_from_readbacks,
};
use gtkg_core::okf_v2::{
    CurrentNormativeCorpusValidationV2, OkfAxisEvidenceV2, validate_current_normative_corpus,
};
use gtkg_core::runtime_receipt_v2::{
    LOCAL_RUNTIME_RECEIPT_SCHEMA_V2, LocalRuntimeAuthorityV2, LocalRuntimeLifecycleReceiptV2,
    RuntimeVerifierIdentityV2, persist_local_runtime_lifecycle_receipt_v2,
};
use gtkg_core::{CallContext, EffectPolicy, TransportKind};
use gtkg_protocol::canonical_json_sha256;
use gtkg_protocol::v2::{OkfAxisStatusV2, OkfSpecPinV2};
use sha2::{Digest, Sha256};

const CURRENT_PIN_SHA256: &str =
    "sha256:26aa5da029278939f914e578107242d9607d4f2dc5fe153272b82f9ed1030101";

fn digest(character: char) -> String {
    format!("sha256:{}", character.to_string().repeat(64))
}

fn pin() -> OkfSpecPinV2 {
    OkfSpecPinV2::new(
        "0.2",
        "62432a095456147ee71e70ac6e4dc0d2dea3ac30",
        CURRENT_PIN_SHA256,
    )
    .expect("pin")
}

fn passed_corpus() -> CurrentNormativeCorpusValidationV2 {
    let evidence = OkfAxisEvidenceV2 {
        status: OkfAxisStatusV2::Passed,
        code: "I_V2_OKF_CURRENT_NORMATIVE_CORPUS_PASSED",
        detail: "local frozen corpus only; not Google certification".to_owned(),
    };
    CurrentNormativeCorpusValidationV2 {
        official_format: evidence.clone(),
        reference_compatibility: evidence,
        case_count: 13,
        receipt_path: Some(PathBuf::from(
            "deliverables/v02-t03/current-okf-normative-corpus-receipt.json",
        )),
    }
}

fn overlay(t03_receipt_sha256: &str) -> KnowledgeOverlayV2 {
    let provenance = KnowledgeOverlayProvenanceV2 {
        structural_graph_sha256: digest('a'),
        verification_receipt_sha256: digest('b'),
        accepted_claim_set_sha256: digest('c'),
        t03_receipt_sha256: t03_receipt_sha256.to_owned(),
        t04_manifest_sha256: digest('d'),
        document_relation_receipt_sha256s: vec![digest('e')],
    };
    KnowledgeOverlayV2 {
        schema_version: "gtkg.knowledge-overlay/v2".to_owned(),
        layer: "knowledge_overlay".to_owned(),
        source_snapshot_exact_set_sha256: digest('f'),
        structural_graph_sha256: provenance.structural_graph_sha256.clone(),
        nodes: vec![KnowledgeOverlayNodeV2 {
            id: "provenance.t10".to_owned(),
            kind: "provenance".to_owned(),
            label: "t10_verification".to_owned(),
            claim_id: None,
            structural_evidence_ids: Vec::new(),
            provenance,
        }],
        edges: Vec::new(),
        overlay_sha256: digest('9'),
    }
}

fn runtime_receipt(lifecycle: &LifecycleIdentityV2) -> LocalRuntimeLifecycleReceiptV2 {
    let lifecycle_identity_sha256 = lifecycle.identity_sha256().expect("lifecycle digest");
    let current = digest('8');
    LocalRuntimeLifecycleReceiptV2 {
        schema_version: LOCAL_RUNTIME_RECEIPT_SCHEMA_V2.to_owned(),
        receipt_id: "t15c-local-runtime".to_owned(),
        authority: LocalRuntimeAuthorityV2::local_development("gtkg-local-runtime"),
        verifier: RuntimeVerifierIdentityV2 {
            verifier_id: "t15c-local-verifier".to_owned(),
            verifier_sha256: digest('7'),
        },
        selection: SelectionReceiptV2 {
            selector: ArtifactSelectorV2::Replay {
                version_id: "v2-local".to_owned(),
            },
            version_id: "v2-local".to_owned(),
            version_bundle_sha256: digest('6'),
            lifecycle_identity_sha256: lifecycle_identity_sha256.clone(),
            canonical_write_count: 0,
        },
        readback: PostActivationReadbackReceiptV2::passed(current, lifecycle_identity_sha256)
            .expect("readback"),
    }
}

fn internal_profile() -> InternalOkfProfileV2 {
    InternalOkfProfileV2 {
        consumer_documents: vec!["---\ntype: concept\nokf_version: \"0.2\"\n---\nbody\n".to_owned()],
        producer_documents: vec!["---\ntype: concept\nokf_version: \"0.2\"\ngenerated:\n  by: gtkg\n  at: now\n---\nbody\n".to_owned()],
    }
}

fn lifecycle(overlay: &KnowledgeOverlayV2) -> LifecycleIdentityV2 {
    LifecycleIdentityV2 {
        source_snapshot_exact_set_sha256: digest('1'),
        local_resolver_profile_sha256: digest('2'),
        document_relation_receipts_sha256: digest('3'),
        context_pack_sha256: digest('4'),
        claim_verification_receipt_sha256: digest('5'),
        structural_graph_sha256: overlay.structural_graph_sha256.clone(),
        knowledge_overlay_sha256: overlay.overlay_sha256.clone(),
    }
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

fn seal_overlay(mut overlay: KnowledgeOverlayV2) -> KnowledgeOverlayV2 {
    overlay.overlay_sha256.clear();
    overlay.overlay_sha256 = canonical_json_sha256(&overlay).expect("overlay digest");
    overlay
}

#[test]
fn local_suite_separates_all_four_axes_and_declares_its_scope() {
    let t03_receipt_sha256 = digest('0');
    let overlay = overlay(&t03_receipt_sha256);
    let lifecycle = lifecycle(&overlay);
    let result = validate_local_current_okf_suite(LocalCurrentOkfSuiteInputV2 {
        pin: pin(),
        internal_profile: internal_profile(),
        current_corpus: passed_corpus(),
        t03_receipt_sha256,
        knowledge_overlay: &overlay,
        lifecycle_identity: &lifecycle,
        runtime_receipt: &runtime_receipt(&lifecycle),
    });

    assert!(result.verdict.all_axes_passed());
    assert_eq!(result.verdict.internal.consumer, OkfAxisStatusV2::Passed);
    assert_eq!(result.verdict.internal.producer, OkfAxisStatusV2::Passed);
    assert_eq!(
        result.verdict.current_official_format,
        OkfAxisStatusV2::Passed
    );
    assert_eq!(
        result.verdict.reference_compatibility,
        OkfAxisStatusV2::Passed
    );
    assert_eq!(result.verdict.curated_profile, OkfAxisStatusV2::Passed);
    assert_eq!(result.scope, "local_frozen_current_corpus");
    assert!(!result.google_certification);
    assert!(result.boundary.contains("not Google certification"));
}

#[test]
fn overlay_t03_drift_fails_only_curated_profile_axis() {
    let t03_receipt_sha256 = digest('0');
    let mut overlay = overlay(&t03_receipt_sha256);
    overlay.nodes[0].provenance.t03_receipt_sha256 = digest('x');
    let lifecycle = lifecycle(&overlay);
    let result = validate_local_current_okf_suite(LocalCurrentOkfSuiteInputV2 {
        pin: pin(),
        internal_profile: internal_profile(),
        current_corpus: passed_corpus(),
        t03_receipt_sha256,
        knowledge_overlay: &overlay,
        lifecycle_identity: &lifecycle,
        runtime_receipt: &runtime_receipt(&lifecycle),
    });

    assert_eq!(result.verdict.internal.status(), OkfAxisStatusV2::Passed);
    assert_eq!(
        result.verdict.current_official_format,
        OkfAxisStatusV2::Passed
    );
    assert_eq!(
        result.verdict.reference_compatibility,
        OkfAxisStatusV2::Passed
    );
    assert_eq!(result.verdict.curated_profile, OkfAxisStatusV2::Invalid);
    assert!(!result.verdict.all_axes_passed());
    assert_eq!(result.verdict.blocking_axis_ids(), vec!["curated_profile"]);
}

#[test]
fn frozen_t03_runner_receipt_feeds_a_scoped_local_t15c_observation() {
    let workspace = workspace_root();
    let corpus = validate_current_normative_corpus(
        &workspace,
        &pin(),
        &workspace.join("deliverables/v02-t03/current-okf-normative-corpus.json"),
    );
    assert_eq!(corpus.official_format.status, OkfAxisStatusV2::Passed);
    assert_eq!(
        corpus.reference_compatibility.status,
        OkfAxisStatusV2::Passed
    );
    assert_eq!(corpus.case_count, 13);
    let receipt_path = corpus.receipt_path.as_ref().expect("T03 receipt");
    let t03_receipt_sha256 = format!(
        "sha256:{:x}",
        Sha256::digest(std::fs::read(receipt_path).expect("T03 receipt bytes"))
    );
    let overlay = overlay(&t03_receipt_sha256);
    let lifecycle = lifecycle(&overlay);
    let result = validate_local_current_okf_suite(LocalCurrentOkfSuiteInputV2 {
        pin: pin(),
        internal_profile: internal_profile(),
        current_corpus: corpus,
        t03_receipt_sha256,
        knowledge_overlay: &overlay,
        lifecycle_identity: &lifecycle,
        runtime_receipt: &runtime_receipt(&lifecycle),
    });

    assert!(result.verdict.all_axes_passed());
    assert_eq!(result.scope, "local_frozen_current_corpus");
    assert!(!result.google_certification);
}

#[test]
fn strict_suite_reads_t03_t11b_and_persisted_t14a_evidence() {
    let workspace = workspace_root();
    let corpus = validate_current_normative_corpus(
        &workspace,
        &pin(),
        &workspace.join("deliverables/v02-t03/current-okf-normative-corpus.json"),
    );
    let t03_digest = format!(
        "sha256:{:x}",
        Sha256::digest(
            std::fs::read(corpus.receipt_path.as_ref().expect("T03 receipt")).expect("T03 bytes"),
        )
    );
    let temporary = tempfile::tempdir().expect("evidence root");
    let overlay = seal_overlay(overlay(&t03_digest));
    let overlay_root = temporary.path().join("overlay");
    write_knowledge_overlay_v2(&overlay_root, &overlay).expect("persist T11B overlay");
    let lifecycle = lifecycle(&overlay);
    let receipt = runtime_receipt(&lifecycle);
    let context = CallContext::restricted(
        TransportKind::Test,
        vec![temporary.path().to_path_buf()],
        EffectPolicy::WorkspaceWrite,
    )
    .expect("bounded evidence root");
    let paths = persist_local_runtime_lifecycle_receipt_v2(
        &context,
        &temporary.path().join(".gtkg/t15c"),
        &receipt,
    )
    .expect("persist T14A receipt/event");
    let result =
        validate_local_current_okf_suite_from_readbacks(LocalCurrentOkfSuiteReadbackInputV2 {
            workspace_root: &workspace,
            pin: pin(),
            internal_profile: internal_profile(),
            current_corpus: corpus,
            corpus_manifest_path: &workspace
                .join("deliverables/v02-t03/current-okf-normative-corpus.json"),
            overlay_artifact_root: &overlay_root,
            lifecycle_identity: &lifecycle,
            runtime_receipt_path: &paths.receipt_path,
            runtime_event_path: &paths.event_path,
            cli_mcp_identity_sha256: receipt.verifier.verifier_sha256.clone(),
        });
    assert_eq!(
        result.verdict.current_official_format,
        OkfAxisStatusV2::Passed
    );
    assert_eq!(
        result.verdict.reference_compatibility,
        OkfAxisStatusV2::Passed
    );
    assert_eq!(result.verdict.curated_profile, OkfAxisStatusV2::Passed);
}

#[test]
fn strict_suite_rejects_t11b_bytes_replaced_under_the_same_manifest() {
    let workspace = workspace_root();
    let corpus = validate_current_normative_corpus(
        &workspace,
        &pin(),
        &workspace.join("deliverables/v02-t03/current-okf-normative-corpus.json"),
    );
    let receipt_path = corpus.receipt_path.as_ref().expect("T03 receipt");
    let t03_digest = format!(
        "sha256:{:x}",
        Sha256::digest(std::fs::read(receipt_path).expect("T03 bytes"))
    );
    let temporary = tempfile::tempdir().expect("evidence root");
    let overlay = seal_overlay(overlay(&t03_digest));
    let overlay_root = temporary.path().join("overlay");
    write_knowledge_overlay_v2(&overlay_root, &overlay).expect("persist overlay");
    let lifecycle = lifecycle(&overlay);
    let receipt = runtime_receipt(&lifecycle);
    let context = CallContext::restricted(
        TransportKind::Test,
        vec![temporary.path().to_path_buf()],
        EffectPolicy::WorkspaceWrite,
    )
    .expect("context");
    let paths = persist_local_runtime_lifecycle_receipt_v2(
        &context,
        &temporary.path().join(".gtkg/t15c"),
        &receipt,
    )
    .expect("persist runtime");
    let overlay_path = overlay_root.join("overlay.json");
    let mut bytes = std::fs::read(&overlay_path).expect("overlay bytes");
    bytes.push(b' ');
    std::fs::write(&overlay_path, bytes).expect("replace bytes without replacing manifest");
    let result =
        validate_local_current_okf_suite_from_readbacks(LocalCurrentOkfSuiteReadbackInputV2 {
            workspace_root: &workspace,
            pin: pin(),
            internal_profile: internal_profile(),
            current_corpus: corpus,
            corpus_manifest_path: &workspace
                .join("deliverables/v02-t03/current-okf-normative-corpus.json"),
            overlay_artifact_root: &overlay_root,
            lifecycle_identity: &lifecycle,
            runtime_receipt_path: &paths.receipt_path,
            runtime_event_path: &paths.event_path,
            cli_mcp_identity_sha256: receipt.verifier.verifier_sha256.clone(),
        });
    assert_eq!(result.verdict.curated_profile, OkfAxisStatusV2::Invalid);
}
