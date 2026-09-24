use std::fs;
use std::path::Path;

use gtkg_core::no_db::scan_no_database;
use tempfile::tempdir;

fn plant_forbidden_artifacts(base: &Path) {
    let db_file = base.join("state.sqlite");
    fs::write(&db_file, b"SQLite format 3\0payload").expect("plant sqlite artifact");
    let source_file = base.join("worker.rs");
    fs::write(&source_file, "use rusqlite::Connection;\n").expect("plant source artifact");
}

#[test]
fn gtkg_runtime_directory_is_excluded_from_no_database_scan() {
    let temp = tempdir().expect("tempdir");
    let runtime_dir = temp.path().join(".gtkg").join("inspections").join("run-1");
    fs::create_dir_all(&runtime_dir).expect("create runtime dir");
    plant_forbidden_artifacts(&runtime_dir);

    let findings = scan_no_database(temp.path()).expect("scan completes");
    assert!(
        findings.is_empty(),
        ".gtkg runtime artifacts must be excluded, got: {findings:#?}"
    );
}

#[test]
fn generated_output_directory_is_excluded_from_no_database_scan() {
    let temp = tempdir().expect("tempdir");
    let output_dir = temp
        .path()
        .join("output")
        .join("g03")
        .join("organic-corpus");
    fs::create_dir_all(&output_dir).expect("create output dir");
    plant_forbidden_artifacts(&output_dir);

    let findings = scan_no_database(temp.path()).expect("scan completes");
    assert!(
        findings.is_empty(),
        "output generated artifacts must be excluded, got: {findings:#?}"
    );
}

#[test]
fn forbidden_artifacts_outside_runtime_directory_are_still_found() {
    let temp = tempdir().expect("tempdir");
    let data_dir = temp.path().join("data");
    fs::create_dir_all(&data_dir).expect("create data dir");
    plant_forbidden_artifacts(&data_dir);

    let findings = scan_no_database(temp.path()).expect("scan completes");
    let rules: Vec<&str> = findings
        .iter()
        .map(|finding| finding.rule_id.as_str())
        .collect();
    assert!(
        rules.contains(&"forbidden_extension"),
        "expected forbidden_extension finding, got: {findings:#?}"
    );
    assert!(
        rules.contains(&"forbidden_magic"),
        "expected forbidden_magic finding, got: {findings:#?}"
    );
    assert!(
        rules.contains(&"forbidden_source_api"),
        "expected forbidden_source_api finding, got: {findings:#?}"
    );
}
