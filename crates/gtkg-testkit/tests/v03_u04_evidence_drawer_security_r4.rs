//! U04 r4 successor: public readback cannot become writer input, and a
//! self-consistent but Q04-mismatched U03 receipt/index is rejected.

use std::fs;
use std::path::Path;

use gtkg_core::v03::evidence_drawer::{
    build_evidence_drawer_from_artifacts_v1, create_evidence_drawer_output_root_v1,
    read_evidence_drawer_v1, write_evidence_drawer_with_capability_v1,
};
use gtkg_protocol::canonical_json_sha256;

#[path = "v03_u04_evidence_drawer_security_r3.rs"]
mod r3;

fn digest(label: &str) -> String {
    use sha2::{Digest, Sha256};
    format!("sha256:{}", hex::encode(Sha256::digest(label.as_bytes())))
}

fn raw_sha256(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

#[cfg(unix)]
#[test]
fn u04_r4_rejects_self_consistent_u03_artifact_when_its_projection_drifts_from_q04() {
    let fixture = r3::Fixture::new();
    let context = fixture.write_context();
    let root = Path::new(&fixture.explorer_receipt.site_root);
    let index_path = root.join("index.html");
    let mut html = fs::read_to_string(&index_path).unwrap();
    let forged_source = digest("forged-u03-source");
    html = html.replacen(&fixture.expected.source_identity, &forged_source, 1);
    fs::write(&index_path, &html).unwrap();
    let index_sha256 = raw_sha256(html.as_bytes());

    let manifest_path = root.join("manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
    manifest["index_sha256"] = serde_json::Value::String(index_sha256.clone());
    let manifest_bytes = serde_json::to_vec_pretty(&manifest).unwrap();
    fs::write(&manifest_path, &manifest_bytes).unwrap();

    let mut input = fixture.input();
    input.explorer_receipt.index_sha256 = index_sha256;
    input.explorer_receipt.site_manifest_sha256 = canonical_json_sha256(&manifest).unwrap();
    assert_eq!(
        build_evidence_drawer_from_artifacts_v1(&context, &input)
            .unwrap_err()
            .code(),
        "E_U04_U03_BINDING"
    );
}

#[cfg(unix)]
#[test]
fn u04_r4_root_replacement_cannot_redirect_a_descriptor_bound_write() {
    use std::os::unix::fs::symlink;

    let fixture = r3::Fixture::new();
    let context = fixture.write_context();
    let projection = build_evidence_drawer_from_artifacts_v1(&context, &fixture.input()).unwrap();
    let capability = create_evidence_drawer_output_root_v1(&context, &fixture.u04_parent).unwrap();
    let root = capability.path().to_path_buf();
    let parked = fixture.workspace.path().join("parked-u04-root");
    let external = fixture.workspace.path().join("external-root-target");
    fs::create_dir(&external).unwrap();
    fs::rename(&root, &parked).unwrap();
    symlink(&external, &root).unwrap();
    assert_eq!(
        write_evidence_drawer_with_capability_v1(&context, &capability, &projection)
            .unwrap_err()
            .code(),
        "E_U04_CAPABILITY_MISMATCH"
    );
    assert!(fs::read_dir(&external).unwrap().next().is_none());
}

#[cfg(unix)]
#[test]
fn u04_r4_public_readback_is_metadata_not_a_writer_projection() {
    let fixture = r3::Fixture::new();
    let context = fixture.write_context();
    let projection = build_evidence_drawer_from_artifacts_v1(&context, &fixture.input()).unwrap();
    let capability = create_evidence_drawer_output_root_v1(&context, &fixture.u04_parent).unwrap();
    let receipt =
        write_evidence_drawer_with_capability_v1(&context, &capability, &projection).unwrap();
    let readback = read_evidence_drawer_v1(&context, &receipt).unwrap();
    assert_eq!(readback, projection);
    assert!(std::any::type_name_of_val(&readback).ends_with("EvidenceDrawerReadbackV1"));
}
