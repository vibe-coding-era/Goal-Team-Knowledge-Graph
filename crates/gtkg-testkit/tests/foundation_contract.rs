use std::fs;

use gtkg_core::file_model::{publish_immutable_version, validate_index_tree, write_index_tree};
use gtkg_core::no_db::scan_no_database;
use gtkg_core::okf::{parse_okf, validate_current_version};
use gtkg_protocol::{
    GitObjectId, RepositoryIdentity, SourceLock, SourceManifestEntry, TemplateLock, VersionRef,
    canonical_json_sha256,
};
use tempfile::tempdir;

fn valid_okf(title: &str, resource: &str) -> String {
    format!(
        r#"---
type: knowledge
title: "{title}"
description: "fixture"
resource: "{resource}"
tags: [fixture]
generated: {{ by: "process:fixture", at: "2026-01-01T00:00:00Z" }}
status: draft
sources: []
okf_version: "0.2"
gtkg:
  schema: "gtkg.knowledge/v1"
  progressive_loading:
    level: "L2"
---

# {title}

Evidence-bound fixture.
"#
    )
}

#[test]
fn okf_v02_parser_is_strict_and_keeps_gtkg_extensions_scoped() {
    let parsed = parse_okf(&valid_okf("Valid", "./valid.md")).expect("valid OKF parses");
    assert_eq!(parsed.frontmatter.title.as_deref(), Some("Valid"));
    assert_eq!(parsed.frontmatter.okf_version.as_deref(), Some("0.2"));
    assert!(parsed.body.contains("Evidence-bound"));

    let wrong_version = valid_okf("Wrong", "./wrong.md").replace("\"0.2\"", "\"0.1\"");
    let wrong_version = parse_okf(&wrong_version).expect("generic OKF consumer is best effort");
    assert!(validate_current_version(&wrong_version.frontmatter).is_err());
    // SPEC §6.2: relative paths including `../` are accepted at the parse
    // layer; filesystem access stays behind the exact_read authorization
    // boundary.
    let escaped = valid_okf("Escaped", "../secret.md");
    let escaped = parse_okf(&escaped).expect("relative parent resource is accepted (SPEC §6.2)");
    assert_eq!(
        escaped.frontmatter.resource.as_deref(),
        Some("../secret.md")
    );
    // SPEC §4.1 Extensions + §11: unknown producer keys are tolerated and
    // preserved, never rejected.
    let leaked_extension = valid_okf("Leak", "./leak.md").replace(
        "okf_version: \"0.2\"",
        "okf_version: \"0.2\"\ngtkg_secret: true",
    );
    let leaked = parse_okf(&leaked_extension).expect("unknown producer keys are tolerated");
    assert!(leaked.frontmatter.extra.contains_key("gtkg_secret"));
}

#[test]
fn exact_template_and_git_locks_are_digest_stable() {
    let version = VersionRef {
        id: "summary-template".to_owned(),
        version: "0.1.0".to_owned(),
        manifest_sha256: format!("sha256:{}", "a".repeat(64)),
    };
    let template = TemplateLock {
        template: version,
        parent: None,
        slot_ids: vec!["summary".to_owned()],
    };
    template.validate().expect("exact template lock validates");
    let floating = TemplateLock {
        template: VersionRef {
            version: "current".to_owned(),
            ..template.template.clone()
        },
        ..template.clone()
    };
    assert!(floating.validate().is_err());

    let source = SourceLock {
        schema_version: "gtkg.source-lock/v1".to_owned(),
        repositories: vec![RepositoryIdentity {
            repo_id: "repo-a".to_owned(),
            remote: Some("ssh://example.invalid/repo-a".to_owned()),
            commit: GitObjectId::sha1("1".repeat(40)).expect("valid oid"),
            tree: GitObjectId::sha1("2".repeat(40)).expect("valid oid"),
            dirty: false,
            submodules: Vec::new(),
        }],
        entries: vec![SourceManifestEntry {
            repo_id: "repo-a".to_owned(),
            logical_path: "docs/a.md".to_owned(),
            role: "documentation".to_owned(),
            content_sha256: format!("sha256:{}", "b".repeat(64)),
            bytes: 7,
        }],
    };
    source.validate().expect("Git-bound source lock validates");
    assert_eq!(
        canonical_json_sha256(&source).unwrap(),
        canonical_json_sha256(&source).unwrap()
    );
}

#[test]
fn file_indexes_close_and_versions_are_immutable() {
    let temp = tempdir().expect("tempdir");
    let stage = temp.path().join("stage-one");
    fs::create_dir_all(stage.join("knowledge/nested")).expect("create stage");
    fs::write(stage.join("knowledge/a.md"), valid_okf("A", "./a.md")).expect("write A");
    fs::write(
        stage.join("knowledge/nested/b.md"),
        valid_okf("B", "./b.md"),
    )
    .expect("write B");
    write_index_tree(&stage).expect("indexes generated");
    validate_index_tree(&stage).expect("index closure validates");

    let versions = temp.path().join("versions");
    let published = publish_immutable_version(&stage, &versions, "0.1.0")
        .expect("first immutable publish succeeds");
    assert!(published.join("index.md").is_file());

    let second = temp.path().join("stage-two");
    fs::create_dir_all(&second).expect("create second stage");
    fs::write(
        second.join("changed.md"),
        valid_okf("Changed", "./changed.md"),
    )
    .expect("write changed");
    write_index_tree(&second).expect("second index");
    assert!(publish_immutable_version(&second, &versions, "0.1.0").is_err());
}

#[test]
fn no_database_gate_checks_dependencies_files_and_magic() {
    let clean = tempdir().expect("clean tempdir");
    fs::write(clean.path().join("Cargo.lock"), "name = \"serde\"\n").expect("clean lock");
    assert!(
        scan_no_database(clean.path())
            .expect("clean scan")
            .is_empty()
    );

    let dirty = tempdir().expect("dirty tempdir");
    fs::write(dirty.path().join("Cargo.lock"), "name = \"rusqlite\"\n").expect("dirty lock");
    fs::write(
        dirty.path().join("hidden.bin"),
        b"SQLite format 3\0forbidden",
    )
    .expect("magic file");
    let findings = scan_no_database(dirty.path()).expect("dirty scan");
    assert!(
        findings
            .iter()
            .any(|finding| finding.rule_id == "forbidden_dependency")
    );
    assert!(
        findings
            .iter()
            .any(|finding| finding.rule_id == "forbidden_magic")
    );
}
