//! Normal-build dynamic guard for every retired raw U01 entry point.

use std::collections::BTreeMap;
use std::fs;

use gtkg_core::v03::installer::{
    InstallErrorV1, InstallManifestV1, apply_install_v1, apply_install_with_capability_v1,
    create_isolated_root_v1, preview_install_v1, preview_install_with_capability_v1,
    preview_rollback_v1, preview_upgrade_v1, uninstall_v1, uninstall_with_capability_v1,
};
use sha2::{Digest, Sha256};

fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

#[test]
fn v03_u01_raw_entrypoints_reject_without_capability_in_a_normal_build() {
    let package = tempfile::tempdir().expect("temporary package root");
    fs::create_dir(package.path().join("bin")).expect("package bin directory");
    let payload = b"normal-build payload\n";
    fs::write(package.path().join("bin/gtkg"), payload).expect("package payload");
    let manifest = InstallManifestV1 {
        schema_version: "gtkg.install-manifest/v1".to_owned(),
        version: "0.3.0-test".to_owned(),
        platform: "darwin-arm64".to_owned(),
        files: vec!["bin/gtkg".to_owned()],
        modes: BTreeMap::from([("bin/gtkg".to_owned(), 0o755)]),
        digests: BTreeMap::from([("bin/gtkg".to_owned(), sha256(payload))]),
        destinations: BTreeMap::from([("bin/gtkg".to_owned(), "bin/gtkg".to_owned())]),
    };
    let parent = tempfile::tempdir().expect("authorized temporary parent");
    let root = create_isolated_root_v1(parent.path()).expect("isolated root capability");
    let preview = preview_install_with_capability_v1(package.path(), &root, &manifest)
        .expect("strict preview");

    assert_eq!(
        preview_install_v1(package.path(), root.path(), &manifest),
        Err(InstallErrorV1::IsolationRequired)
    );
    assert_eq!(
        preview_upgrade_v1(package.path(), root.path(), &manifest),
        Err(InstallErrorV1::IsolationRequired)
    );
    assert_eq!(
        preview_rollback_v1(package.path(), root.path(), &manifest, &dummy_receipt()),
        Err(InstallErrorV1::IsolationRequired)
    );
    assert_eq!(
        apply_install_v1(root.path(), &preview),
        Err(InstallErrorV1::IsolationRequired)
    );

    let receipt = apply_install_with_capability_v1(&root, &preview).expect("strict apply");
    assert_eq!(
        uninstall_v1(root.path(), &receipt),
        Err(InstallErrorV1::IsolationRequired)
    );
    assert!(
        uninstall_with_capability_v1(&root, &receipt)
            .expect("strict cleanup")
            .readback_verified
    );
}

fn dummy_receipt() -> gtkg_core::v03::installer::InstallReceiptV1 {
    gtkg_core::v03::installer::InstallReceiptV1 {
        schema_version: "ignored-by-raw-api".to_owned(),
        action: gtkg_core::v03::installer::InstallActionV1::Install,
        version: String::new(),
        platform: String::new(),
        manifest_sha256: String::new(),
        previous_manifest_sha256: None,
        root_identity_sha256: String::new(),
        capability_id: String::new(),
        capability_digest: String::new(),
        managed_files: Vec::new(),
        managed_file_write_count: 0,
        managed_file_remove_count: 0,
        metadata_write_count: 0,
        dry_run: true,
        readback_verified: false,
    }
}
