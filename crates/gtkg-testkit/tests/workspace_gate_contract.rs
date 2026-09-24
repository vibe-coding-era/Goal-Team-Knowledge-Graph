use std::path::Path;

use gtkg_core::no_db::scan_no_database;

#[test]
fn production_workspace_contains_no_database_dependency_or_artifact() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir
        .parent()
        .and_then(Path::parent)
        .expect("testkit belongs to the Cargo workspace");
    let findings = scan_no_database(workspace_root).expect("workspace no-database scan completes");
    assert!(findings.is_empty(), "database findings: {findings:#?}");
}
