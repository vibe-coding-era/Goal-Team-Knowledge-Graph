use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

const APACHE_2_SHA256: &str = "c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4";

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root")
}

fn read(relative: &str) -> String {
    fs::read_to_string(root().join(relative)).unwrap_or_else(|error| panic!("{relative}: {error}"))
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[test]
fn root_license_notice_version_and_cargo_metadata_are_exact() {
    let license = fs::read(root().join("LICENSE")).expect("root LICENSE");
    assert_eq!(sha256(&license), APACHE_2_SHA256);
    assert!(String::from_utf8_lossy(&license).contains("Apache License"));
    assert_eq!(read("VERSION"), "0.3.0\n");

    let cargo = read("Cargo.toml");
    assert!(cargo.contains("version = \"0.3.0\""));
    assert!(cargo.contains("license = \"Apache-2.0\""));
    assert!(cargo.contains("product-version = \"V0.3\""));

    let notice = read("NOTICE");
    assert!(notice.contains("GTKG"));
    assert!(notice.contains("Apache License 2.0"));
    assert!(notice.contains("third-party"));
}

#[test]
fn readme_states_install_and_release_boundaries_without_fake_quickstart() {
    let readme = read("README.md");
    for required in [
        "# GTKG",
        "V0.3",
        "Rust 2024",
        "one binary",
        "OKF and ordinary files",
        "no database",
        "Development",
        "Release",
        "installation",
        "Current activation",
        "business validation",
    ] {
        assert!(readme.contains(required), "README missing {required}");
    }
    assert!(!readme.contains("curl | sh"));
    assert!(!readme.contains("mock data"));
}

#[test]
fn package_manifest_is_closed_digest_bound_and_excludes_private_outputs() {
    let path = root().join("scripts/package-manifest-v0.3.json");
    let bytes = fs::read(&path).expect("package manifest");
    let manifest: Value = serde_json::from_slice(&bytes).expect("valid package manifest JSON");
    assert_eq!(manifest["schema_version"], "gtkg.package-manifest/v1");
    assert_eq!(manifest["product_version"], "V0.3");
    assert_eq!(manifest["crate_version"], "0.3.0");
    assert_eq!(manifest["license_spdx"], "Apache-2.0");
    assert_eq!(manifest["license_sha256"], APACHE_2_SHA256);
    assert_eq!(manifest["state"], "development_manifest");
    assert_eq!(manifest["release_asset"], false);

    let files = manifest["required_files"]
        .as_array()
        .expect("required_files");
    let paths = files
        .iter()
        .map(|entry| entry["path"].as_str().expect("path"))
        .collect::<Vec<_>>();
    assert_eq!(
        paths.len(),
        paths.iter().copied().collect::<BTreeSet<_>>().len()
    );
    for required in [
        "Cargo.toml",
        "Cargo.lock",
        "README.md",
        "LICENSE",
        "NOTICE",
        "VERSION",
    ] {
        assert!(paths.contains(&required));
    }
    for entry in files {
        let relative = entry["path"].as_str().expect("path");
        let expected = entry["sha256"].as_str().expect("sha256");
        let actual = fs::read(root().join(relative)).expect("manifest member");
        assert_eq!(sha256(&actual), expected, "digest drift for {relative}");
    }

    let forbidden = manifest["forbidden_prefixes"]
        .as_array()
        .expect("forbidden_prefixes")
        .iter()
        .map(|value| value.as_str().expect("forbidden prefix"))
        .collect::<BTreeSet<_>>();
    for expected in [
        ".git/",
        "target/",
        "develops/",
        ".workbuddy/",
        "deliverables/",
    ] {
        assert!(forbidden.contains(expected));
    }
}
