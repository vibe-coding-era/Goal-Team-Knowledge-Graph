//! T14B: verified T12B/T13 identities feed a progressive local Wiki/A2UI
//! projection. Browser execution is local-only and remains below the existing
//! renderer-replicable evidence ceiling.

use std::path::{Path, PathBuf};

use gtkg_core::claim_aware_query_v2::execute_claim_aware_hybrid_query_v2;
use gtkg_core::claim_v2::{
    AtomicClaimV2, ClaimEvidenceRefV2, ClaimModalityV2, ClaimPolarityV2, ClaimVerificationInputV2,
    RiskClassV2, T03ClaimEvidenceV2, T04ClaimEvidenceV2, verify_atomic_claims_v2,
};
use gtkg_core::context_v2::{
    ContextChunkV2, ContextPackRequestV2, ContextSourceV2, LocalTokenizerV2, build_context_pack_v2,
};
use gtkg_core::document_relations::{
    DocumentRelationFormatV2, DocumentRelationReceiptV2, DocumentRelationStatusV2,
    DocumentRelationValidationV2, T03RelationBindingV2,
};
use gtkg_core::graph_v3::{
    DocumentRelationGraphInputV3, StructuralGraphBuildInputV3, TypedIrGraphInputV3,
    build_structural_graph_v3, write_structural_graph_v3,
};
use gtkg_core::knowledge_overlay_v2::{
    KnowledgeOverlayBuildInputV2, build_knowledge_overlay_v2, write_knowledge_overlay_v2,
};
use gtkg_core::lifecycle_v2::LifecycleIdentityV2;
use gtkg_core::provider_v2::SummaryJobV2;
use gtkg_core::wiki_a2ui_v2::{
    ClaimAwareQueryReceiptV2, LOCAL_WIKI_A2UI_EVIDENCE_STATE_V2, LocalWikiA2uiInputV2,
    build_local_wiki_a2ui_projection_v2, read_local_wiki_a2ui_page_v2,
    read_local_wiki_a2ui_projection_v2, write_local_wiki_a2ui_projection_v2,
};
use gtkg_core::{CallContext, EffectPolicy, TransportKind};
use gtkg_extract::{build_typed_ir_v2, extract_path, resolve_local_typed_ir_v2};
use gtkg_protocol::v2::{
    OkfSpecPinV2, SourceBaselineIdentityV2, SourceCaptureModeV2, SourceEligibilityV2,
    SourceSnapshotDenominatorV2, SourceSnapshotEntryV2, SourceSnapshotV2,
};
use sha2::{Digest, Sha256};
use tempfile::tempdir;

const DIGEST: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const CURRENT_PIN_SHA256: &str =
    "sha256:26aa5da029278939f914e578107242d9607d4f2dc5fe153272b82f9ed1030101";

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

fn sha(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn snapshot(source: &str) -> SourceSnapshotV2 {
    SourceSnapshotV2 {
        schema_version: "gtkg.source-snapshot/v2".to_owned(),
        capture_mode: SourceCaptureModeV2::DirectoryExact,
        repository_id: "t14b".to_owned(),
        baseline: SourceBaselineIdentityV2 {
            kind: "directory".to_owned(),
            head: None,
            tree: None,
            status_sha256: DIGEST.to_owned(),
        },
        inventory: vec![SourceSnapshotEntryV2 {
            logical_path: "src/stable.rs".to_owned(),
            content_sha256: sha(source.as_bytes()),
            bytes: source.len() as u64,
        }],
        omissions: Vec::new(),
        denominator: SourceSnapshotDenominatorV2 {
            discovered_entries: 1,
            admitted_entries: 1,
            omitted_entries: 0,
        },
        exact_set_sha256: String::new(),
        eligibility: SourceEligibilityV2 {
            development_eligible: true,
            source_release_candidate: false,
            environment_ready: false,
            release_ready: false,
        },
    }
    .with_exact_set_digest()
    .expect("snapshot")
}

fn t03_binding() -> T03ClaimEvidenceV2 {
    T03ClaimEvidenceV2::from_receipt(
        &workspace_root(),
        OkfSpecPinV2::new(
            "0.2",
            "62432a095456147ee71e70ac6e4dc0d2dea3ac30",
            CURRENT_PIN_SHA256,
        )
        .expect("pin"),
        &workspace_root().join("deliverables/v02-t03/current-okf-normative-corpus.json"),
        &workspace_root().join("deliverables/v02-t03/current-okf-normative-corpus-receipt.json"),
    )
    .expect("T03 binding")
}

fn t04_receipt() -> T04ClaimEvidenceV2 {
    let context = CallContext::restricted(
        TransportKind::Test,
        vec![workspace_root()],
        EffectPolicy::ReadOnly,
    )
    .expect("context");
    T04ClaimEvidenceV2::load_local(
        &context,
        &workspace_root().join("crates/gtkg-testkit/fixtures/v02_t04/local-corpus-contract.json"),
    )
    .expect("T04 receipt")
}

fn relation() -> DocumentRelationGraphInputV3 {
    DocumentRelationGraphInputV3 {
        logical_path: "README.md".to_owned(),
        receipt: DocumentRelationReceiptV2 {
            schema_version: "gtkg.document-relation-receipt/v2".to_owned(),
            document_path: "/host/README.md".to_owned(),
            document_sha256: sha(b"# README\n"),
            relation: DocumentRelationValidationV2 {
                format: DocumentRelationFormatV2::Markdown,
                status: DocumentRelationStatusV2::Passed,
                binding: T03RelationBindingV2 {
                    raw_spec_pin: OkfSpecPinV2::new(
                        "0.2",
                        "62432a095456147ee71e70ac6e4dc0d2dea3ac30",
                        CURRENT_PIN_SHA256,
                    )
                    .expect("pin"),
                    corpus_manifest_path: "deliverables/v02-t03/current-okf-normative-corpus.json"
                        .to_owned(),
                    corpus_manifest_sha256: DIGEST.to_owned(),
                    receipt_path: "deliverables/v02-t03/current-okf-normative-corpus-receipt.json"
                        .to_owned(),
                    receipt_sha256: DIGEST.to_owned(),
                    corpus_id: "current-okf".to_owned(),
                },
                source_ids: vec!["handbook".to_owned()],
                footnote_ids: vec!["handbook".to_owned()],
                issues: Vec::new(),
            },
        },
    }
}

fn fixture() -> (
    tempfile::TempDir,
    PathBuf,
    PathBuf,
    LifecycleIdentityV2,
    ClaimAwareQueryReceiptV2,
) {
    let source = "fn stable() {}\n";
    let snapshot = snapshot(source);
    let temporary = tempdir().expect("temporary");
    let source_path = temporary.path().join("stable.rs");
    std::fs::write(&source_path, source).expect("source");
    let ir = resolve_local_typed_ir_v2(
        &build_typed_ir_v2(
            &snapshot,
            "src/stable.rs",
            &extract_path(&source_path).expect("extract"),
        )
        .expect("IR"),
        source.as_bytes(),
    )
    .expect("resolve");
    let evidence = ir.evidence.first().expect("evidence");
    let source_context = ContextSourceV2::new(
        ir.source_snapshot_exact_set_sha256.clone(),
        "src/stable.rs",
        source,
    );
    let chunk = ContextChunkV2::new(
        "stable",
        "focus",
        0,
        &source_context,
        evidence.byte_start,
        evidence.byte_end,
        evidence.id.clone(),
    )
    .expect("chunk");
    let request = ContextPackRequestV2 {
        source_snapshot_exact_set_sha256: ir.source_snapshot_exact_set_sha256.clone(),
        tokenizer: LocalTokenizerV2::controlled_local(),
        token_budget: 10,
        required_chunk_ids: vec!["stable".to_owned()],
        sources: vec![source_context],
        chunks: vec![chunk],
    };
    let pack = build_context_pack_v2(&request).expect("pack");
    let context_pack_sha256 = pack.context_pack_sha256.clone();
    let selected = pack.read_selected_bytes(&request).expect("selected");
    let claim = AtomicClaimV2 {
        claim_id: "stable-declared".to_owned(),
        subject: "stable".to_owned(),
        predicate: "is_declared".to_owned(),
        object: "function".to_owned(),
        polarity: ClaimPolarityV2::Positive,
        modality: ClaimModalityV2::Asserted,
        natural_language: source[evidence.byte_start as usize..evidence.byte_end as usize]
            .to_owned(),
        evidence: vec![ClaimEvidenceRefV2 {
            evidence_id: evidence.id.clone(),
            context_chunk_id: "stable".to_owned(),
            source_snapshot_exact_set_sha256: evidence.source_snapshot_exact_set_sha256.clone(),
            source_logical_path: evidence.source_logical_path.clone(),
            source_sha256: evidence.source_sha256.clone(),
            byte_start: evidence.byte_start,
            byte_end: evidence.byte_end,
            snippet_sha256: evidence.snippet_sha256.clone(),
        }],
        risk_class: RiskClassV2::Normal,
    };
    let job = SummaryJobV2::local_only("t14b", &selected).expect("job");
    let verified = verify_atomic_claims_v2(
        ClaimVerificationInputV2 {
            source_bytes: source.as_bytes(),
            typed_ir: &ir,
            selected_context: &selected,
            summary_job: &job,
            t03_evidence: &t03_binding(),
            t04_evidence: &t04_receipt(),
        },
        &[claim.clone()],
    )
    .expect("T10");
    let document_relation = relation();
    let graph = build_structural_graph_v3(&StructuralGraphBuildInputV3 {
        source_snapshot_exact_set_sha256: snapshot.exact_set_sha256,
        typed_inputs: vec![TypedIrGraphInputV3 {
            ir,
            source_bytes: source.as_bytes().to_vec(),
        }],
        document_relations: vec![document_relation.clone()],
    })
    .expect("T11A");
    let overlay = build_knowledge_overlay_v2(&KnowledgeOverlayBuildInputV2 {
        structural_graph: graph.clone(),
        claims: vec![claim],
        verification_receipt: verified.receipt.clone(),
        accepted_claim_set: verified.accepted,
        document_relations: vec![document_relation],
    })
    .expect("T11B");
    let graph_root = temporary.path().join("graph");
    let overlay_root = temporary.path().join("overlay");
    write_structural_graph_v3(&graph_root, &graph).expect("graph write");
    write_knowledge_overlay_v2(&overlay_root, &overlay).expect("overlay write");
    let query_receipt = ClaimAwareQueryReceiptV2::from_result(
        execute_claim_aware_hybrid_query_v2(
            &graph_root,
            &overlay_root,
            &serde_json::json!({"query": "stable"}),
        )
        .expect("T12B graph.search"),
    )
    .expect("query receipt");
    let lifecycle = LifecycleIdentityV2 {
        source_snapshot_exact_set_sha256: graph.source_snapshot_exact_set_sha256,
        local_resolver_profile_sha256: DIGEST.to_owned(),
        document_relation_receipts_sha256: DIGEST.to_owned(),
        context_pack_sha256,
        claim_verification_receipt_sha256: verified.receipt.receipt_sha256,
        structural_graph_sha256: graph.graph_sha256,
        knowledge_overlay_sha256: overlay.overlay_sha256,
    };
    (
        temporary,
        graph_root,
        overlay_root,
        lifecycle,
        query_receipt,
    )
}

#[test]
fn t14b_progressive_wiki_a2ui_readback_binds_t12b_and_t13_without_eager_pages() {
    let (temporary, graph_root, overlay_root, lifecycle, query_receipt) = fixture();
    let projection = build_local_wiki_a2ui_projection_v2(&LocalWikiA2uiInputV2 {
        graph_artifact_root: graph_root,
        overlay_artifact_root: overlay_root,
        lifecycle_identity: lifecycle,
        query_receipt,
    })
    .expect("T14B projection");
    assert_eq!(projection.evidence_state, LOCAL_WIKI_A2UI_EVIDENCE_STATE_V2);
    assert!(
        projection
            .entries
            .iter()
            .any(|entry| entry.kind == "accepted_claim")
    );
    let output = temporary.path().join("wiki");
    write_local_wiki_a2ui_projection_v2(&output, &projection).expect("write projection");
    let readback = read_local_wiki_a2ui_projection_v2(&output).expect("index-only readback");
    assert_eq!(readback, projection);
    let page = read_local_wiki_a2ui_page_v2(&output, &readback, &readback.entries[0].id)
        .expect("selected page only");
    assert_eq!(page["id"], readback.entries[0].id);
    assert_eq!(page["evidence_state"], LOCAL_WIKI_A2UI_EVIDENCE_STATE_V2);
    let shell = std::fs::read_to_string(output.join("app.js")).expect("browser shell");
    assert!(shell.contains("fetch(entry.page)"));
    assert!(shell.contains("textContent"));
    assert!(!shell.contains("innerHTML"));
    let stream = std::fs::read_to_string(output.join("a2ui/stream.jsonl")).expect("stream");
    assert_eq!(stream.lines().count(), 3);
    assert!(stream.contains("a2ui_generatable"));
    let messages = stream
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("A2UI JSONL"))
        .collect::<Vec<_>>();
    assert!(messages[0]["createSurface"].is_object());
    assert!(messages[1]["updateComponents"]["components"].is_array());
    assert!(messages[2]["updateDataModel"]["value"]["provenance"].is_object());
}

#[test]
fn t14b_rejects_t13_identity_drift_before_writing_projection() {
    let (temporary, graph_root, overlay_root, mut lifecycle, query_receipt) = fixture();
    lifecycle.knowledge_overlay_sha256 = DIGEST.to_owned();
    let error = build_local_wiki_a2ui_projection_v2(&LocalWikiA2uiInputV2 {
        graph_artifact_root: graph_root,
        overlay_artifact_root: overlay_root,
        lifecycle_identity: lifecycle,
        query_receipt,
    })
    .expect_err("stale lifecycle must fail closed");
    assert_eq!(error.code(), "E_V2_WIKI_A2UI_INPUT_INVALID");
    assert!(!temporary.path().join("wiki").exists());
}

#[test]
fn t14b_rejects_t12b_query_receipt_drift_even_when_it_is_rehashed() {
    let (temporary, graph_root, overlay_root, lifecycle, mut query_receipt) = fixture();
    query_receipt.result["evidence_pack"]["overlay_readback"]["overlay_sha256"] =
        serde_json::Value::String(DIGEST.to_owned());
    query_receipt = ClaimAwareQueryReceiptV2::from_result(query_receipt.result)
        .expect("rehashed but invalid query receipt");
    let error = build_local_wiki_a2ui_projection_v2(&LocalWikiA2uiInputV2 {
        graph_artifact_root: graph_root,
        overlay_artifact_root: overlay_root,
        lifecycle_identity: lifecycle,
        query_receipt,
    })
    .expect_err("T12B identity drift must fail before writing");
    assert_eq!(error.code(), "E_V2_WIKI_A2UI_INPUT_INVALID");
    assert!(!temporary.path().join("wiki").exists());
}

#[cfg(unix)]
#[test]
fn t14b_readback_rejects_hardlinked_index_and_selected_page_symlink() {
    let (temporary, graph_root, overlay_root, lifecycle, query_receipt) = fixture();
    let projection = build_local_wiki_a2ui_projection_v2(&LocalWikiA2uiInputV2 {
        graph_artifact_root: graph_root,
        overlay_artifact_root: overlay_root,
        lifecycle_identity: lifecycle,
        query_receipt,
    })
    .expect("projection");
    let output = temporary.path().join("wiki");
    write_local_wiki_a2ui_projection_v2(&output, &projection).expect("write");
    let external = temporary.path().join("external-index.json");
    std::fs::rename(output.join("index.json"), &external).expect("move");
    std::fs::hard_link(&external, output.join("index.json")).expect("hardlink");
    let error = read_local_wiki_a2ui_projection_v2(&output).expect_err("index hardlink must fail");
    assert_eq!(error.code(), "E_V2_WIKI_A2UI_ARTIFACT_INVALID");

    let (temporary_2, graph_root, overlay_root, lifecycle, query_receipt) = fixture();
    let projection = build_local_wiki_a2ui_projection_v2(&LocalWikiA2uiInputV2 {
        graph_artifact_root: graph_root,
        overlay_artifact_root: overlay_root,
        lifecycle_identity: lifecycle,
        query_receipt,
    })
    .expect("projection");
    let page_output = temporary_2.path().join("wiki-pages");
    write_local_wiki_a2ui_projection_v2(&page_output, &projection).expect("write pages");
    let selected = &projection.entries[0];
    let external_page = temporary_2.path().join("external-page.json");
    std::fs::copy(
        page_output.join(&selected.page_relative_path),
        &external_page,
    )
    .expect("copy");
    std::fs::remove_file(page_output.join(&selected.page_relative_path)).expect("remove");
    std::os::unix::fs::symlink(
        &external_page,
        page_output.join(&selected.page_relative_path),
    )
    .expect("page symlink");
    let error = read_local_wiki_a2ui_page_v2(&page_output, &projection, &selected.id)
        .expect_err("selected page symlink must fail");
    assert_eq!(error.code(), "E_V2_WIKI_A2UI_ARTIFACT_INVALID");
}

#[test]
#[ignore = "driven by v02_t14b_local_wiki_e2e.sh with a local-only browser"]
fn emit_t14b_local_wiki_browser_fixture() {
    let output = PathBuf::from(
        std::env::var_os("GTKG_T14B_BROWSER_OUTPUT")
            .expect("GTKG_T14B_BROWSER_OUTPUT must name an empty output directory"),
    );
    std::fs::create_dir_all(&output).expect("output directory");
    assert!(
        std::fs::read_dir(&output)
            .expect("output listing")
            .next()
            .is_none(),
        "browser output must be empty"
    );
    let (_temporary, graph_root, overlay_root, lifecycle, query_receipt) = fixture();
    let projection = build_local_wiki_a2ui_projection_v2(&LocalWikiA2uiInputV2 {
        graph_artifact_root: graph_root,
        overlay_artifact_root: overlay_root,
        lifecycle_identity: lifecycle,
        query_receipt,
    })
    .expect("T14B projection");
    let site = output.join("site");
    write_local_wiki_a2ui_projection_v2(&site, &projection).expect("site write");
    std::fs::write(
        output.join("receipt.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "schema_version": "gtkg.t14b-browser-fixture/v2",
            "site": site,
            "projection_sha256": projection.projection_sha256,
            "structural_graph_sha256": projection.structural_graph_sha256,
            "knowledge_overlay_sha256": projection.knowledge_overlay_sha256,
            "lifecycle_identity_sha256": projection.lifecycle_identity_sha256,
            "query_receipt_sha256": projection.query_receipt_sha256,
            "evidence_state": projection.evidence_state,
            "site_index_sha256": sha(&std::fs::read(site.join("index.json")).expect("index")),
            "site_stream_sha256": sha(&std::fs::read(site.join("a2ui/stream.jsonl")).expect("stream")),
            "site_manifest_sha256": sha(&std::fs::read(site.join("manifest.json")).expect("manifest")),
        }))
        .expect("receipt"),
    )
    .expect("write receipt");
}
