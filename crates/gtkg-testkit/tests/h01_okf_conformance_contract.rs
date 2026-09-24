//! H01 frozen contract: Google OKF v0.2 official conformance corpus.
//!
//! Oracle: docs/external-specs/okf-SPEC-v0.2.md (SHA-256
//! 5a3311d270bebb16d558010e75064f5b75323f284992641732b1c8097511f948,
//! GoogleCloudPlatform/knowledge-catalog@8e389230). No network access; the
//! local SPEC file is the sole authority.
//!
//! Every fixture under `fixtures/h01_okf/` is constructed to be *officially
//! conformant* per the SPEC. The assertions below express the official
//! conformance direction: a conformant consumer MUST accept these documents.
//! The current custom GTKG OKF profile (`gtkg_core::okf`) rejects them, so
//! this contract is expected RED until the OKF migration lands.
//!
//! Machine-checkable conformance points under test (SPEC section):
//! (a) §4.1/§11   `type` is the only always-required key; a type-only
//!                concept is fully conformant.
//! (b) §4.1/§11   producers MAY add unknown keys; consumers MUST NOT reject.
//! (c) §5.2       `generated` is a `{ by, at }` object, not a bool.
//! (d) §5.2/§11   `verified` is a list of `{ by, at }` events; a bare
//!                mapping MUST be treated as a one-element list.
//! (e) §5.4       `status` enum is draft | stable | deprecated.
//! (f) §5.1       `sources[]` entries carry `resource` (plus optional
//!                credibility signals); `resource` may be a scope descriptor.
//! (g) §6.2       path-valued fields accept absolute URLs, bundle-relative
//!                paths (`/...`), and relative paths (including `..`).
//! (h) §8/§11     non-root `index.md` carries NO frontmatter; its body is
//!                markdown links. It must not be rejected.
//! (i) §12        bundle-root `index.md` MAY carry only `okf_version`.

use std::fs;
use std::path::{Path, PathBuf};

use gtkg_core::file_model::sha256_file;
use gtkg_core::okf::parse_okf;

fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/h01_okf")
}

fn fixture_source(relative: &str) -> String {
    let path = fixture_root().join(relative);
    fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("fixture {} unreadable: {error}", path.display()))
}

fn parse_fixture(relative: &str) -> gtkg_core::okf::OkfDocument {
    let source = fixture_source(relative);
    parse_okf(&source).unwrap_or_else(|error| {
        panic!("official-conformant fixture {relative} must be accepted (SPEC): {error}")
    })
}

#[test]
fn h01_local_spec_derived_fixture_exact_set_is_digest_locked() {
    let root = fixture_root();
    let manifest = fs::read_to_string(root.join("SHA256SUMS.txt")).expect("fixture manifest");
    let mut listed = Vec::new();
    for line in manifest.lines().filter(|line| !line.trim().is_empty()) {
        let (hash, relative) = line.split_once("  ").expect("sha256sum line");
        let path = root.join(relative);
        assert!(path.is_file(), "listed fixture is missing: {relative}");
        assert_eq!(
            sha256_file(&path).expect("fixture digest"),
            format!("sha256:{hash}"),
            "fixture drift: {relative}"
        );
        listed.push(relative.to_owned());
    }
    listed.sort();

    let mut observed = Vec::new();
    collect_fixture_files(&root, &root, &mut observed);
    observed.sort();
    assert_eq!(observed, listed, "fixture manifest must be an exact set");
}

fn collect_fixture_files(root: &Path, directory: &Path, observed: &mut Vec<String>) {
    let mut entries = fs::read_dir(directory)
        .expect("fixture directory")
        .collect::<Result<Vec<_>, _>>()
        .expect("fixture entries");
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        let kind = entry.file_type().expect("fixture file type");
        if kind.is_dir() {
            collect_fixture_files(root, &path, observed);
        } else if kind.is_file() && entry.file_name() != "SHA256SUMS.txt" {
            observed.push(
                path.strip_prefix(root)
                    .expect("fixture relative path")
                    .to_string_lossy()
                    .replace('\\', "/"),
            );
        }
    }
}

/// SPEC §4.1 + §11: `type` is the only always-required key; a concept
/// carrying just `type` is fully conformant. Missing optional fields
/// (`title`, `description`, `resource`, `tags`, trust/lifecycle/provenance
/// families) MUST NOT cause rejection.
#[test]
fn spec_4_1_type_only_concept_is_conformant() {
    let document = parse_fixture("resource-forms/minimal-type-only.md");
    assert_eq!(document.frontmatter.kind, "Reference");
}

/// SPEC §5.2: `generated` is `{ by: <actor>, at: <ISO 8601> }`, not a bool.
/// SPEC §5.2 + §11: `verified` is a list of verification events
/// `{ by, at }`; multiple entries capture independent checks.
#[test]
fn spec_5_2_generated_object_and_verified_event_list_parse() {
    let document = parse_fixture("bundle/tables/orders.md");
    assert_eq!(document.frontmatter.kind, "BigQuery Table");
    assert!(document.body.contains("# Schema"));
}

/// SPEC §4.1 Extensions + §11: producers MAY include additional keys;
/// consumers MUST NOT reject documents with unrecognized fields.
/// The fixture carries `owner_team` and `x_acme_priority`.
#[test]
fn spec_4_1_unknown_producer_extension_fields_are_tolerated() {
    let document = parse_fixture("bundle/playbooks/incident-response.md");
    assert_eq!(document.frontmatter.kind, "Playbook");
}

/// SPEC §5.4: `status` enum is `draft | stable | deprecated`; absent means
/// `stable`. Every official value MUST be accepted.
#[test]
fn spec_5_4_official_status_enum_values_are_accepted() {
    for status in ["draft", "stable", "deprecated"] {
        let source = format!(
            "---\ntype: Metric\ntitle: T\ndescription: D\nstatus: {status}\n---\n\n# Body\n"
        );
        parse_okf(&source).unwrap_or_else(|error| {
            panic!("official status value {status:?} must be accepted (SPEC §5.4): {error}")
        });
    }
}

/// SPEC §5.2 + §11: a single verifier MAY be written as one bare
/// `{ by, at }` mapping without the list dash; consumers MUST treat it as a
/// one-element list. Fixture: computations/revenue.md.
#[test]
fn spec_5_2_bare_verified_mapping_is_accepted() {
    let document = parse_fixture("bundle/computations/revenue.md");
    assert_eq!(document.frontmatter.kind, "Attested Computation");
}

/// SPEC §5.1: each `sources` entry requires `resource`; credibility signals
/// (`author`, `usage_count`, `last_modified`) are optional. A
/// `sources[].resource` may be a scope descriptor (e.g. "all queries in
/// BigQuery project acme") rather than a path. Both fixtures under
/// `bundle/` exercise this and MUST parse.
#[test]
fn spec_5_1_sources_entries_with_resource_and_scope_descriptors_parse() {
    let document = parse_fixture("bundle/computations/revenue.md");
    assert!(
        document.body.contains("[^rev-policy]"),
        "per-claim attribution footnote body must survive parsing"
    );
}

/// SPEC §6.2: path-valued fields accept an absolute URL.
#[test]
fn spec_6_2_resource_accepts_absolute_url() {
    let document = parse_fixture("resource-forms/absolute-url.md");
    assert_eq!(document.frontmatter.kind, "BigQuery Table");
}

/// SPEC §6.2: path-valued fields accept a bundle-relative path beginning
/// with `/`.
#[test]
fn spec_6_2_resource_accepts_bundle_relative_path() {
    let document = parse_fixture("resource-forms/bundle-relative.md");
    assert_eq!(document.frontmatter.kind, "Reference");
}

/// SPEC §6.2: path-valued fields accept a relative path, explicitly
/// including `../` forms (the SPEC's own example is
/// `../computations/revenue.md`).
#[test]
fn spec_6_2_resource_accepts_relative_path_with_parent() {
    let document = parse_fixture("resource-forms/relative-parent.md");
    assert_eq!(document.frontmatter.kind, "Metric");
}

/// SPEC §8 + §11(3): non-root `index.md` files contain NO frontmatter; the
/// body is markdown links grouped under headings. A conformant consumer
/// MUST NOT reject a non-root index for missing frontmatter.
#[test]
fn spec_8_non_root_index_without_frontmatter_is_accepted() {
    let source = fixture_source("bundle/tables/index.md");
    assert!(
        !source.starts_with("---"),
        "fixture invariant: non-root index.md carries no frontmatter (SPEC §8)"
    );
    parse_okf(&source).unwrap_or_else(|error| {
        panic!("non-root index.md without frontmatter must be accepted (SPEC §8/§11): {error}")
    });
}

/// SPEC §12: a bundle-root `index.md` MAY carry an `okf_version` key — the
/// only frontmatter permitted in any `index.md` — and needs no `type`.
#[test]
fn spec_12_root_index_may_carry_only_okf_version() {
    let document = parse_fixture("bundle/index.md");
    assert!(
        document.body.contains("[Tables](tables/)"),
        "root index body links must survive parsing"
    );
}
