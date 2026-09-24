//! Independent cross-review by the pack implementer; public synthetic inputs only.
//! These are boundary fixtures, not claims of actual human/model execution.
#![allow(clippy::unwrap_used)]
#[path = "v04_lifecycle_fixture.rs"]
mod fixture;
use fixture::Fixture;
use gtkg_core::v04::{
    analysis, artifact, authoring,
    knowledge::*,
    lifecycle as life,
    query_meter::{QueryBudgetLimits, QueryBudgetUsage, QueryMeter},
    semantic_projection::{self as semantic, SemanticPrepareRequest},
};
use gtkg_core::{CallContext, EffectPolicy, TransportKind};
use gtkg_extract::v04::Span;
use gtkg_protocol::FileReceiptRef;
use serde_json::{Value, json};
use std::{collections::BTreeMap, fs, path::Path};

fn meter() -> QueryMeter {
    QueryMeter::new(
        QueryBudgetUsage::default(),
        QueryBudgetLimits::for_index(1280 * 1024 * 1024),
    )
}
fn reference(path: &str, bytes: &[u8]) -> FileReceiptRef {
    FileReceiptRef {
        path: path.into(),
        sha256: artifact::digest(bytes),
    }
}
fn raw<T: serde::Serialize>(value: &T) -> Vec<u8> {
    serde_json::to_vec_pretty(value).unwrap()
}
fn tree(root: &Path) -> BTreeMap<String, String> {
    fn visit(root: &Path, at: &Path, out: &mut BTreeMap<String, String>) {
        for item in fs::read_dir(at).unwrap() {
            let item = item.unwrap();
            let path = item.path();
            let meta = fs::symlink_metadata(&path).unwrap();
            assert!(
                !meta.file_type().is_symlink(),
                "fixture contains no symlinks"
            );
            if meta.is_dir() {
                visit(root, &path, out);
            } else {
                out.insert(
                    path.strip_prefix(root).unwrap().to_str().unwrap().into(),
                    artifact::digest(&fs::read(path).unwrap()),
                );
            }
        }
    }
    let mut result = BTreeMap::new();
    visit(root, root, &mut result);
    result
}
fn prepare(f: &Fixture, r: &SemanticPrepareRequest) -> FileReceiptRef {
    let replayed = semantic::replay_projection(&f.context, &f.workspace, r).unwrap();
    semantic::publish_projection(&f.context, &f.workspace, replayed).unwrap()
}
fn reviewed_fixture(f: &Fixture) -> SemanticPrepareRequest {
    let guide = "The otter queue never retries delivery after cancellation.\n";
    let (verified_ref, mut accepted_refs, _) =
        f.build("review-independent", &[("guide.md", guide)], false);
    let (v, _): (analysis::VerifiedAnalysis, _) =
        artifact::read(&f.context, &f.workspace, &verified_ref).unwrap();
    let (_, sources) =
        authoring::load_verified_sources(&f.context, &f.workspace, &verified_ref).unwrap();
    let job = prepare_job(
        &KnowledgeInput {
            job_id: "independent-otter".into(),
            goal: KnowledgeGoal::SemanticUnderstanding,
            source_paths: vec!["guide.md".into()],
            understanding_items: vec!["delivery".into()],
            prompt: "POISON_PROMPT_UNREVIEWED".into(),
            policy: "independent-public-fixture".into(),
            max_context_units: 8000,
            source_spans: BTreeMap::new(),
        },
        &sources,
    )
    .unwrap();
    let job_ref = artifact::publish(
        &f.context,
        &f.workspace,
        "authoring-jobs",
        &authoring::JobArtifact {
            verified_ref: verified_ref.clone(),
            job: job.clone(),
        },
    )
    .unwrap();
    let candidate = KnowledgeCandidate {
        author_id: "independent-fixture-author".into(),
        author_mode: AuthorMode::HumanAuthored,
        summary: "POISON_SUMMARY_UNREVIEWED".into(),
        claims: vec![KnowledgeClaim {
            claim_id: "otter-cancellation".into(),
            understanding_item: "delivery".into(),
            natural_language: "POISON_NATURAL_LANGUAGE_UNREVIEWED".into(),
            body: ClaimBody::Interpretive {
                proposition: "The otter queue never retries delivery after cancellation.".into(),
                epistemic: EpistemicStatus::Direct,
                version_condition: "Only frozen version 7; never applies to version 8.".into(),
            },
            citations: vec![Citation {
                path: "guide.md".into(),
                file_sha256: digest(guide.as_bytes()),
                span: Span {
                    byte_start: 0,
                    byte_end: guide.len(),
                    line_start: 1,
                    line_end: 1,
                },
                excerpt: guide.into(),
            }],
        }],
    };
    let output = serde_json::to_string(&candidate).unwrap();
    let execution = GenerationExecutionRecord {
        schema: "gtkg.qk.generation-execution-record/v1".into(),
        job_digest: job.job_digest.clone(),
        context_digest: job.context_digest.clone(),
        prompt_digest: job.prompt_digest.clone(),
        policy_digest: job.policy_digest.clone(),
        author_id: candidate.author_id.clone(),
        author_mode: AuthorMode::HumanAuthored,
        execution_evidence: ExecutionEvidence::HumanRecorded,
        host_id: None,
        model_id: None,
        transcript: None,
        transcript_digest: None,
        output_digest: digest(output.as_bytes()),
        output,
        usage: Usage {
            input_tokens: None,
            output_tokens: None,
        },
    };
    let proposal = submit_proposal(&job, &candidate, Some(&execution), &sources).unwrap();
    let proposal_ref = artifact::publish(
        &f.context,
        &f.workspace,
        "proposals",
        &authoring::ProposalArtifact {
            job_ref: job_ref.clone(),
            proposal: proposal.clone(),
        },
    )
    .unwrap();
    let reviews = [
        "independent-fixture-review-one",
        "independent-fixture-review-two",
    ]
    .into_iter()
    .map(|id| IndependentReview {
        reviewer_id: id.into(),
        proposal_digest: proposal.proposal_digest.clone(),
        decisions: vec![ClaimReview {
            claim_id: candidate.claims[0].claim_id.clone(),
            claim_digest: claim_digest(&candidate.claims[0]).unwrap(),
            judgment: Judgment::Supported,
            reason: "Public synthetic boundary fixture; no external execution claim".into(),
        }],
    })
    .collect::<Vec<_>>();
    let verification = review_proposal(&job, &proposal, &reviews, &sources).unwrap();
    let review_ref = artifact::publish(
        &f.context,
        &f.workspace,
        "knowledge-reviews",
        &authoring::ReviewArtifact {
            proposal_ref,
            verification: verification.clone(),
        },
    )
    .unwrap();
    let accepted = accept(&job, &proposal, &verification, &sources).unwrap();
    let okf_ref = artifact::publish_text(
        &f.context,
        &f.workspace,
        "knowledge",
        &authoring::render_okf(&job, &accepted),
    )
    .unwrap();
    accepted_refs.push(
        artifact::publish(
            &f.context,
            &f.workspace,
            "accepted",
            &authoring::AcceptedArtifact {
                review_ref,
                job_ref,
                accepted,
                okf_ref,
            },
        )
        .unwrap(),
    );
    SemanticPrepareRequest {
        schema: "gtkg.qk.semantic-prepare/v1".into(),
        verified_ref,
        base_index_ref: v.index_ref.unwrap(),
        accepted_refs,
    }
}

#[test]
fn independent_review_checks_selected_trust_text_denominator_and_self_consistent_tampering() {
    let f = Fixture::new();
    let request = reviewed_fixture(&f);
    let overlay_ref = prepare(&f, &request);
    let ro = CallContext::restricted(
        TransportKind::Test,
        vec![f.workspace.clone()],
        EffectPolicy::ReadOnly,
    )
    .unwrap();
    let before = tree(&f.workspace);
    let loaded =
        semantic::load_overlay_with_io(&ro, &f.workspace, &overlay_ref, &mut meter()).unwrap();
    assert_eq!(loaded.catalog.total_contexts, 2);
    for term in [
        "exact:POISON_PROMPT_UNREVIEWED",
        "exact:POISON_SUMMARY_UNREVIEWED",
        "exact:POISON_NATURAL_LANGUAGE_UNREVIEWED",
    ] {
        assert!(
            semantic::load_selected_postings(&ro, &f.workspace, &loaded, term, &mut meter())
                .unwrap()
                .is_empty(),
            "unreviewed text entered the semantic route"
        );
    }
    let rows =
        semantic::load_selected_postings(&ro, &f.workspace, &loaded, "fold:otter", &mut meter())
            .unwrap();
    assert!(!rows.is_empty());
    let record = semantic::load_selected_context(
        &ro,
        &f.workspace,
        &loaded,
        &rows[0].context_ref,
        &mut meter(),
    )
    .unwrap();
    let context = semantic::verify_selected_lineage(
        &ro,
        &f.workspace,
        &loaded,
        &record,
        &rows[0].context_ref,
        &mut meter(),
    )
    .unwrap();
    assert!(context.text.contains("never retries"));
    assert_eq!(
        context.version_condition.as_deref(),
        Some("Only frozen version 7; never applies to version 8.")
    );
    assert_eq!(context.reviewer_ids.len(), 2);
    assert_eq!(context.citation_coverage_in_pack, "partial");
    assert_eq!(
        context.text_units(),
        context.text.chars().count() + context.version_condition.as_ref().unwrap().chars().count()
    );
    let body = serde_json::to_value(&context).unwrap();
    assert!(body.get("body").is_none());
    assert!(body.get("proposition").is_none());
    let structural_rows =
        semantic::load_selected_postings(&ro, &f.workspace, &loaded, "exact:Entry", &mut meter())
            .unwrap();
    assert!(!structural_rows.is_empty());
    let structural_record = semantic::load_selected_context(
        &ro,
        &f.workspace,
        &loaded,
        &structural_rows[0].context_ref,
        &mut meter(),
    )
    .unwrap();
    let structural = semantic::verify_selected_lineage(
        &ro,
        &f.workspace,
        &loaded,
        &structural_record,
        &structural_rows[0].context_ref,
        &mut meter(),
    )
    .unwrap();
    assert_eq!(structural.review_kind, "structural_replayed");
    assert!(structural.reviewer_ids.is_empty());
    semantic::verify_projection(&ro, &f.workspace, &overlay_ref).unwrap();
    assert_eq!(
        tree(&f.workspace),
        before,
        "ReadOnly projection/selected verification changed workspace bytes"
    );

    for r in [
        &record.lineage.accepted_ref,
        &record.lineage.job_ref,
        &record.lineage.proposal_ref,
        &record.lineage.review_ref,
        &record.lineage.okf_ref,
    ] {
        let path = f.workspace.join(&r.path);
        let original = fs::read(&path).unwrap();
        let mut corrupted = original.clone();
        corrupted[0] ^= 1;
        fs::write(&path, corrupted).unwrap();
        let mut charged = meter();
        assert!(
            semantic::verify_selected_lineage(
                &ro,
                &f.workspace,
                &loaded,
                &record,
                &rows[0].context_ref,
                &mut charged
            )
            .is_err()
        );
        assert!(charged.usage().io_bytes > 0);
        fs::write(path, original).unwrap();
    }
    // Preserve all closed policy/source identities and recompute dependent lengths
    // and hashes. Only the prior authority MAC is unavailable for the new bytes.
    let catalog_path = f.workspace.join(&loaded.overlay.catalog_ref.path);
    let original_catalog = fs::read(&catalog_path).unwrap();
    let overlay_path = f.workspace.join(&overlay_ref.path);
    let original_overlay = fs::read(&overlay_path).unwrap();
    let mut catalog = loaded.catalog.clone();
    catalog.total_contexts += 1;
    let derived = catalog.total_index_bytes - original_catalog.len() as u64;
    for _ in 0..16 {
        let next = derived + raw(&catalog).len() as u64;
        if next == catalog.total_index_bytes {
            break;
        }
        catalog.total_index_bytes = next;
    }
    let changed_catalog = raw(&catalog);
    fs::write(&catalog_path, &changed_catalog).unwrap();
    let mut overlay = loaded.overlay.clone();
    overlay.catalog_ref.bytes = changed_catalog.len() as u64;
    overlay.catalog_ref.sha256 = artifact::digest(&changed_catalog);
    for _ in 0..16 {
        let next =
            loaded.base.total_index_bytes + catalog.total_index_bytes + raw(&overlay).len() as u64;
        if next == overlay.total_index_bytes {
            break;
        }
        overlay.total_index_bytes = next;
    }
    let changed_overlay = raw(&overlay);
    fs::write(&overlay_path, &changed_overlay).unwrap();
    let resigned = reference(&overlay_ref.path, &changed_overlay);
    let old_admission = f.workspace.join(format!(
        ".gtkg/qk/runtime/semantic-admission/{}.json",
        &overlay_ref.sha256[7..]
    ));
    let new_admission = f.workspace.join(format!(
        ".gtkg/qk/runtime/semantic-admission/{}.json",
        &resigned.sha256[7..]
    ));
    let mut admission: Value = serde_json::from_slice(&fs::read(old_admission).unwrap()).unwrap();
    admission["overlay_ref"] = json!(resigned);
    fs::write(&new_admission, raw(&admission)).unwrap();
    let error =
        semantic::load_overlay_with_io(&ro, &f.workspace, &resigned, &mut meter()).unwrap_err();
    assert!(
        error.contains("authentication failed"),
        "self-consistent attack did not reach MAC gate: {error}"
    );
    assert!(semantic::verify_projection(&ro, &f.workspace, &resigned).is_err());
    fs::write(catalog_path, original_catalog).unwrap();
    fs::write(overlay_path, original_overlay).unwrap();
    fs::remove_file(new_admission).unwrap();

    let (accepted, _): (authoring::AcceptedArtifact, _) =
        artifact::read(&f.context, &f.workspace, &request.accepted_refs[1]).unwrap();
    let duplicate = artifact::publish(
        &f.context,
        &f.workspace,
        "independent-accepted-copy",
        &accepted,
    )
    .unwrap();
    let mut duplicates = request.clone();
    duplicates.accepted_refs.push(duplicate);
    duplicates
        .accepted_refs
        .push(request.accepted_refs[1].clone());
    let repeated_ref = prepare(&f, &duplicates);
    let repeated =
        semantic::load_overlay_with_io(&ro, &f.workspace, &repeated_ref, &mut meter()).unwrap();
    assert_eq!(
        repeated.catalog.total_contexts,
        loaded.catalog.total_contexts
    );
    assert_eq!(
        repeated.catalog.total_context_tokens,
        loaded.catalog.total_context_tokens
    );
    assert_eq!(
        repeated.catalog.total_mappings,
        loaded.catalog.total_mappings
    );
    assert!(
        repeated
            .catalog
            .excluded_claims
            .iter()
            .any(|c| c.reason == "duplicate_supported_fact")
    );
    let (other_verified, _, _) = f.build(
        "independent-other-source",
        &[("guide.md", "A different frozen source.\n")],
        false,
    );
    let (other, _): (analysis::VerifiedAnalysis, _) =
        artifact::read(&f.context, &f.workspace, &other_verified).unwrap();
    let mut cross = request;
    cross.verified_ref = other_verified;
    cross.base_index_ref = other.index_ref.unwrap();
    assert!(
        semantic::replay_projection(&ro, &f.workspace, &cross).is_err(),
        "accepted claims crossed verified source identity"
    );
}

#[test]
fn independent_review_portable_missing_members_and_readonly_import_boundary() {
    let f = Fixture::new();
    let (verified_ref, accepted_refs, views_ref) = f.build("independent-portable", &[], false);
    let built = life::finalize_semantic(
        &f.context,
        &f.workspace,
        &life::SemanticFinalizeRequest {
            schema: "gtkg.qk.semantic-finalize/v1".into(),
            verified_ref,
            accepted_refs,
            views_ref,
            output_path: f.workspace.join(".gtkg/qk/bundles/original"),
            predecessor: None,
        },
    )
    .unwrap();
    assert!(!built.authority_exported);
    assert!(
        built
            .manifest
            .files
            .iter()
            .all(|f| !f.reference.path.contains("runtime/"))
    );
    let moved = f.workspace.join(".gtkg/qk/bundles/moved");
    fs::rename(&built.bundle.workspace_root, &moved).unwrap();
    fs::remove_dir_all(&f.repository).unwrap();
    let locator = life::BundleLocator {
        workspace_root: moved.clone(),
        manifest_ref: built.bundle.manifest_ref.clone(),
    };
    let ro = CallContext::restricted(
        TransportKind::Test,
        vec![f.workspace.clone()],
        EffectPolicy::ReadOnly,
    )
    .unwrap();
    let before = tree(&moved);
    let verified = life::verify_semantic(&ro, &locator).unwrap();
    assert!(!verified.authority_required_for_read_verification);
    assert_eq!(tree(&moved), before);
    assert!(life::import_any(&ro, &locator).is_err());
    assert_eq!(tree(&moved), before);
    let authority = moved.join(".gtkg/qk/runtime/query-authority.json");
    assert!(!authority.exists());
    let victim = built
        .manifest
        .files
        .iter()
        .find(|v| v.reference.path.contains("/contexts/"))
        .unwrap();
    let path = moved.join(&victim.reference.path);
    let bytes = fs::read(&path).unwrap();
    fs::remove_file(&path).unwrap();
    assert!(life::verify_semantic(&ro, &locator).is_err());
    assert!(!authority.exists());
    fs::write(&path, bytes).unwrap();
    let extras = moved.join("undeclared-public-proof.json");
    fs::write(&extras, b"{}").unwrap();
    assert!(life::verify_semantic(&ro, &locator).is_err());
    fs::remove_file(extras).unwrap();
    life::import_any(&f.context, &locator).unwrap();
    assert!(authority.exists());
    let admitted =
        semantic::load_overlay_with_io(&ro, &moved, &built.manifest.query_index_ref, &mut meter())
            .unwrap();
    assert_eq!(admitted.catalog.total_contexts, 1);
    let imported = tree(&moved);
    life::verify_semantic(&ro, &locator).unwrap();
    assert_eq!(tree(&moved), imported);
}
