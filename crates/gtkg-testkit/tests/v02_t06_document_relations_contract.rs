//! V0.2 T06 contract: Markdown source declarations, citations, footnotes, and
//! link targets form one fail-closed local relation closure.

use std::path::{Path, PathBuf};

use gtkg_core::document_relations::{
    DocumentRelationFormatV2, DocumentRelationStatusV2, T03RelationBindingV2,
    execute_local_document_relation_receipt, read_document_relation_receipt,
    validate_document_relations, write_document_relation_receipt,
};
use gtkg_protocol::v2::OkfSpecPinV2;

const CURRENT_PIN_SHA256: &str =
    "sha256:26aa5da029278939f914e578107242d9607d4f2dc5fe153272b82f9ed1030101";

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

fn current_pin() -> OkfSpecPinV2 {
    OkfSpecPinV2::new(
        "0.2",
        "62432a095456147ee71e70ac6e4dc0d2dea3ac30",
        CURRENT_PIN_SHA256,
    )
    .expect("current pin")
}

fn t03_binding() -> T03RelationBindingV2 {
    T03RelationBindingV2::from_receipt(
        &workspace_root(),
        current_pin(),
        &workspace_root().join("deliverables/v02-t03/current-okf-normative-corpus.json"),
        &workspace_root().join("deliverables/v02-t03/current-okf-normative-corpus-receipt.json"),
    )
    .expect("T03 receipt is a passed frozen corpus receipt")
}

#[test]
fn t03_binding_requires_the_exact_raw_pin_corpus_manifest_and_receipt_relation() {
    let temporary = tempfile::tempdir().expect("temporary T03 manifest");
    let manifest = temporary.path().join("current-okf-normative-corpus.json");
    let source = std::fs::read_to_string(
        workspace_root().join("deliverables/v02-t03/current-okf-normative-corpus.json"),
    )
    .expect("read frozen T03 corpus manifest");
    std::fs::write(
        &manifest,
        source.replacen(
            CURRENT_PIN_SHA256,
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            1,
        ),
    )
    .expect("write tampered corpus manifest");

    let error = T03RelationBindingV2::from_receipt(
        &workspace_root(),
        current_pin(),
        &manifest,
        &workspace_root().join("deliverables/v02-t03/current-okf-normative-corpus-receipt.json"),
    )
    .expect_err("raw pin drift must fail T06 binding");
    assert!(error.to_string().contains("does not bind"));

    let receipt_directory =
        tempfile::tempdir_in(workspace_root()).expect("workspace receipt directory");
    let receipt = receipt_directory
        .path()
        .join("current-okf-normative-corpus-receipt.json");
    let receipt_source = std::fs::read_to_string(
        workspace_root().join("deliverables/v02-t03/current-okf-normative-corpus-receipt.json"),
    )
    .expect("read frozen T03 receipt");
    std::fs::write(&receipt, receipt_source.replacen("\"C13\"", "\"D13\"", 1))
        .expect("write tampered receipt");
    let receipt_relative = receipt
        .strip_prefix(workspace_root())
        .expect("workspace-local test receipt")
        .to_string_lossy()
        .replace('\\', "/");
    let case_manifest = temporary.path().join("case-set-manifest.json");
    let source = std::fs::read_to_string(
        workspace_root().join("deliverables/v02-t03/current-okf-normative-corpus.json"),
    )
    .expect("read frozen T03 corpus manifest");
    std::fs::write(
        &case_manifest,
        source.replace(
            "deliverables/v02-t03/current-okf-normative-corpus-receipt.json",
            &receipt_relative,
        ),
    )
    .expect("write receipt-bound T03 corpus manifest");
    let error = T03RelationBindingV2::from_receipt(
        &workspace_root(),
        current_pin(),
        &case_manifest,
        &receipt,
    )
    .expect_err("receipt case-set drift must fail T06 binding");
    assert!(error.to_string().contains("does not exactly match"));
}

fn valid_markdown() -> &'static str {
    r#"---
type: Note
sources:
  - id: handbook
    resource: https://example.test/handbook
---

The policy is sourced.[^handbook]

[^handbook]: [Handbook](https://example.test/handbook)
"#
}

#[test]
fn markdown_source_footnote_and_link_close_against_a_t03_receipt() {
    let report = validate_document_relations(
        DocumentRelationFormatV2::Markdown,
        valid_markdown(),
        &t03_binding(),
    );

    assert_eq!(report.status, DocumentRelationStatusV2::Passed);
    assert!(report.issues.is_empty());
    assert_eq!(report.source_ids, vec!["handbook"]);
    assert_eq!(report.footnote_ids, vec!["handbook"]);
    assert_eq!(report.binding.raw_spec_pin, current_pin());
    assert!(report.binding.receipt_sha256.starts_with("sha256:"));
}

#[test]
fn v02_prd_source_footnote_and_link_relations_close() {
    let prd = std::fs::read_to_string(workspace_root().join("V0.2PRD.md"))
        .expect("V0.2 PRD is available");
    let report =
        validate_document_relations(DocumentRelationFormatV2::Markdown, &prd, &t03_binding());

    assert_eq!(report.status, DocumentRelationStatusV2::Passed);
    assert_eq!(report.source_ids.len(), 5);
    assert_eq!(report.footnote_ids.len(), 5);
}

#[test]
fn missing_or_orphan_or_duplicate_relations_fail_closed() {
    let cases = [
        (
            "missing definition",
            valid_markdown().replace("\n[^handbook]: [Handbook](https://example.test/handbook)\n", "\n"),
            "E_V2_DOC_RELATION_FOOTNOTE_DEFINITION_MISSING",
        ),
        (
            "orphan source",
            valid_markdown().replace("The policy is sourced.[^handbook]", "The policy is sourced."),
            "E_V2_DOC_RELATION_SOURCE_ORPHAN",
        ),
        (
            "unknown citation",
            valid_markdown().replace("[^handbook]", "[^unknown]"),
            "E_V2_DOC_RELATION_FOOTNOTE_UNKNOWN_SOURCE",
        ),
        (
            "wrong target",
            valid_markdown().replace("https://example.test/handbook)\n", "https://example.test/other)\n"),
            "E_V2_DOC_RELATION_FOOTNOTE_LINK_MISMATCH",
        ),
        (
            "duplicate source id",
            valid_markdown().replace(
                "    resource: https://example.test/handbook\n",
                "    resource: https://example.test/handbook\n  - id: handbook\n    resource: https://example.test/duplicate\n",
            ),
            "E_V2_DOC_RELATION_SOURCE_DUPLICATE",
        ),
    ];

    for (name, markdown, expected) in cases {
        let report = validate_document_relations(
            DocumentRelationFormatV2::Markdown,
            &markdown,
            &t03_binding(),
        );
        assert_eq!(report.status, DocumentRelationStatusV2::Failed, "{name}");
        assert!(
            report.issues.iter().any(|issue| issue.code == expected),
            "{name}"
        );
    }
}

#[test]
fn fenced_examples_do_not_create_relations_and_unsupported_formats_are_explicitly_omitted() {
    let markdown = valid_markdown().replace(
        "\n[^handbook]: [Handbook](https://example.test/handbook)\n",
        "\n```markdown\n[^unknown]: [not a source](https://example.test/unknown)\n```\n\n[^handbook]: [Handbook](https://example.test/handbook)\n",
    );
    let report = validate_document_relations(
        DocumentRelationFormatV2::Markdown,
        &markdown,
        &t03_binding(),
    );
    assert_eq!(report.status, DocumentRelationStatusV2::Passed);

    let nested_shorter_close = valid_markdown().replace(
        "\n[^handbook]: [Handbook](https://example.test/handbook)\n",
        "\n````markdown\n```\n[^unknown]\n[^unknown]: [not a source](https://example.test/unknown)\n````\n\n[^handbook]: [Handbook](https://example.test/handbook)\n",
    );
    let nested_report = validate_document_relations(
        DocumentRelationFormatV2::Markdown,
        &nested_shorter_close,
        &t03_binding(),
    );
    assert_eq!(nested_report.status, DocumentRelationStatusV2::Passed);

    for format in [
        DocumentRelationFormatV2::Pdf,
        DocumentRelationFormatV2::Office,
    ] {
        let omitted = validate_document_relations(format, "%binary input%", &t03_binding());
        assert_eq!(omitted.status, DocumentRelationStatusV2::OmittedUnsupported);
        assert_eq!(
            omitted.issues[0].code,
            "O_V2_DOC_RELATION_FORMAT_UNSUPPORTED"
        );
    }
}

#[test]
fn executable_local_receipt_round_trips_the_actual_v02_prd_relation_result() {
    let temporary = tempfile::tempdir().expect("temporary receipt directory");
    let receipt = execute_local_document_relation_receipt(
        DocumentRelationFormatV2::Markdown,
        &workspace_root().join("V0.2PRD.md"),
        &t03_binding(),
    )
    .expect("execute local relation receipt");
    assert_eq!(receipt.relation.status, DocumentRelationStatusV2::Passed);
    let output = temporary.path().join("document-relations.receipt.json");
    write_document_relation_receipt(&output, &receipt).expect("write deterministic receipt");
    let readback = read_document_relation_receipt(&output).expect("read exact receipt");
    assert_eq!(readback, receipt);
}
