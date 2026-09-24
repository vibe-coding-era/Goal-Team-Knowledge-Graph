//! H02 follow-up contract: distinguish permissive OKF consumer parsing from
//! strict non-reserved concept validation.
//!
//! SPEC §8/§12 reserves index shapes that may omit `type`; SPEC §11 requires
//! every non-reserved concept to carry a non-empty `type`. A parser without
//! caller context must not let the index exception leak into production concept
//! validation. SPEC §12 also recommends best-effort consumption of unknown
//! versions, while the GTKG application profile may reject one separately.

use gtkg_core::okf::{OkfError, parse_okf, parse_okf_concept, validate_current_version};

#[test]
fn frontmatterless_markdown_is_only_accepted_on_the_index_aware_path() {
    let source = "# Directory\n\n* [Child](child.md)\n";
    assert!(parse_okf(source).is_ok(), "SPEC §8 index shape");
    assert!(matches!(
        parse_okf_concept(source),
        Err(OkfError::MissingOpeningDelimiter)
    ));
}

#[test]
fn root_index_exception_requires_the_exact_okf_version_key_set() {
    let exact = "---\nokf_version: \"0.2\"\n---\n\n# Bundle\n";
    assert!(parse_okf(exact).is_ok());

    for invalid in [
        "---\nstatus: stable\n---\n\n# Not an index\n",
        "---\ntype: \"\"\n---\n\n# Empty type\n",
        "---\nokf_version: \"0.2\"\nstatus: stable\n---\n\n# Extra key\n",
        "---\ngenerated: false\nverified: false\n---\n\n# Legacy markers\n",
    ] {
        assert!(
            parse_okf(invalid).is_err(),
            "a deserialized default must not masquerade as a root index: {invalid:?}"
        );
    }
}

#[test]
fn generic_consumer_is_best_effort_but_gtkg_profile_can_require_current_version() {
    let source = "---\ntype: knowledge\nokf_version: \"9.9\"\n---\n\n# Future\n";
    let document = parse_okf_concept(source).expect("generic consumer is best effort");
    assert!(matches!(
        validate_current_version(&document.frontmatter),
        Err(OkfError::UnsupportedVersion(version)) if version == "9.9"
    ));
}

#[test]
fn generated_actor_can_be_truthful_when_change_time_is_unavailable() {
    let source = "---\ntype: knowledge\ngenerated: { by: gtkg/0.1.0 }\n---\n\n# Knowledge\n";
    let document = parse_okf_concept(source).expect("generated.by is the required signal");
    let generated = document.frontmatter.generated.expect("generated metadata");
    assert_eq!(generated.by, "gtkg/0.1.0");
    assert!(
        generated.at.is_empty(),
        "no fictional timestamp is synthesized"
    );
}

#[test]
fn empty_concept_body_accepts_a_closing_delimiter_at_eof() {
    let document = parse_okf_concept("---\ntype: Reference\n---")
        .expect("SPEC §4.2 allows a concept with an empty markdown body");
    assert!(document.body.is_empty());
    assert_eq!(document.frontmatter.kind, "Reference");
}
