//! Normal-build guard: raw target paths never acquire installer authority.

use std::collections::BTreeMap;

use gtkg_core::v03::installer::{InstallErrorV1, InstallManifestV1, preview_install_v1};

#[test]
fn v03_u01_raw_path_preview_rejects_in_a_normal_feature_build() {
    let package = tempfile::tempdir().unwrap();
    let target = tempfile::tempdir().unwrap();
    let manifest = InstallManifestV1 {
        schema_version: "not-read-by-raw-api".to_owned(),
        version: String::new(),
        platform: String::new(),
        files: Vec::new(),
        modes: BTreeMap::new(),
        digests: BTreeMap::new(),
        destinations: BTreeMap::new(),
    };
    assert_eq!(
        preview_install_v1(package.path(), target.path(), &manifest),
        Err(InstallErrorV1::IsolationRequired)
    );
}
