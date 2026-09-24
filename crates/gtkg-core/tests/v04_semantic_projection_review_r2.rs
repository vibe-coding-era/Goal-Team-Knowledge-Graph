//! Second independent review: real archived delimiter spans, not inferred coverage.
#![allow(clippy::unwrap_used)]
#[path = "v04_lifecycle_fixture.rs"]
mod fixture;
use fixture::Fixture;
use gtkg_core::v04::{
    analysis, artifact, index,
    query_meter::{QueryBudgetLimits, QueryBudgetUsage, QueryMeter},
    semantic_projection::{self as semantic, SemanticPrepareRequest},
};
use gtkg_core::{CallContext, EffectPolicy, TransportKind};
use std::{collections::BTreeSet, fs};

fn meter(used: u64) -> QueryMeter {
    QueryMeter::new(
        QueryBudgetUsage {
            posting_rows: used,
            ..Default::default()
        },
        QueryBudgetLimits::for_index(1280 * 1024 * 1024),
    )
}

#[test]
fn whitespace_mapping_is_retained_without_becoming_a_semantic_hit_or_resetting_posting_budget() {
    let f = Fixture::new();
    let (verified_ref, accepted_refs, _) = f.build("independent-delimiter", &[], false);
    let (verified, _): (analysis::VerifiedAnalysis, _) =
        artifact::read(&f.context, &f.workspace, &verified_ref).unwrap();
    let replayed = semantic::replay_projection(
        &f.context,
        &f.workspace,
        &SemanticPrepareRequest {
            schema: "gtkg.qk.semantic-prepare/v1".into(),
            verified_ref,
            base_index_ref: verified.index_ref.unwrap(),
            accepted_refs,
        },
    )
    .unwrap();
    let overlay_ref = semantic::publish_projection(&f.context, &f.workspace, replayed).unwrap();
    let ro = CallContext::restricted(
        TransportKind::Test,
        vec![f.workspace.clone()],
        EffectPolicy::ReadOnly,
    )
    .unwrap();
    let loaded =
        semantic::load_overlay_with_io(&ro, &f.workspace, &overlay_ref, &mut meter(0)).unwrap();
    let rows =
        semantic::load_selected_postings(&ro, &f.workspace, &loaded, "exact:Entry", &mut meter(0))
            .unwrap();
    assert!(!rows.is_empty());
    let record = semantic::load_selected_context(
        &ro,
        &f.workspace,
        &loaded,
        &rows[0].context_ref,
        &mut meter(0),
    )
    .unwrap();
    assert_eq!(record.citations.len(), 1);
    assert_eq!(
        (
            record.citations[0].span.byte_start,
            record.citations[0].span.byte_end
        ),
        (10, 26),
        "original reviewed citation must retain its trailing delimiter span"
    );
    let mut whitespace = BTreeSet::new();
    let mut content = BTreeSet::new();
    for mapping in &record.mappings {
        let chunk =
            index::load_chunk_by_id(&ro, &f.workspace, &loaded.base, &mapping.chunk_id).unwrap();
        let object = fs::read(
            f.workspace
                .join(&loaded.base.archive_root)
                .join("objects")
                .join(&chunk.object_sha),
        )
        .unwrap();
        let start = mapping.overlap_byte_start;
        let end = mapping.overlap_byte_end;
        assert!(
            start < end
                && start
                    >= record.citations[mapping.citation_index as usize]
                        .span
                        .byte_start
                && end
                    <= record.citations[mapping.citation_index as usize]
                        .span
                        .byte_end
        );
        let raw = &object[start..end];
        let mapped = &chunk.text.as_bytes()[start - chunk.byte_start..end - chunk.byte_start];
        assert_eq!(raw, mapped);
        if std::str::from_utf8(raw)
            .unwrap()
            .chars()
            .all(char::is_whitespace)
        {
            whitespace.insert(mapping.chunk_id.clone());
        } else {
            content.insert(mapping.chunk_id.clone());
        }
    }
    assert!(
        !whitespace.is_empty(),
        "fixture must contain an actual delimiter-only mapping"
    );
    assert!(
        !content.is_empty(),
        "fixture must also contain the declaration body mapping"
    );
    let targets: BTreeSet<_> = rows.iter().map(|row| row.chunk_id.clone()).collect();
    assert_eq!(
        targets, content,
        "semantic targets must match content-bearing citation overlaps"
    );
    assert!(
        targets.is_disjoint(&whitespace),
        "delimiter-only chunks acquired semantic relevance"
    );
    assert_eq!(
        loaded.catalog.total_mappings,
        record.mappings.len() as u64,
        "coverage denominator silently dropped delimiter mappings"
    );
    let summary = semantic::verify_selected_lineage(
        &ro,
        &f.workspace,
        &loaded,
        &record,
        &rows[0].context_ref,
        &mut meter(0),
    )
    .unwrap();
    assert_eq!(summary.citations, record.citations);
    assert_eq!(summary.citation_coverage_in_pack, "partial");
    assert_eq!(summary.review_kind, "structural_replayed");
    assert!(summary.reviewer_ids.is_empty());

    let mut limited = meter(100_000 - rows.len() as u64);
    let first =
        semantic::load_selected_postings(&ro, &f.workspace, &loaded, "exact:Entry", &mut limited)
            .unwrap();
    assert_eq!(first, rows);
    assert_eq!(limited.usage().posting_rows, 100_000);
    let prior_io = limited.usage().io_bytes;
    let error =
        semantic::load_selected_postings(&ro, &f.workspace, &loaded, "exact:Entry", &mut limited)
            .unwrap_err();
    assert_eq!(error, "E_QUERY_POSTING_BUDGET");
    assert_eq!(limited.usage().posting_rows, 100_000);
    assert!(
        limited.usage().io_bytes > prior_io,
        "a repeated actual leaf read was incorrectly free"
    );
    semantic::verify_projection(&ro, &f.workspace, &overlay_ref).unwrap();
}
