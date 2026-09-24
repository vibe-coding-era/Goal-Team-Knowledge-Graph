//! Independent T09 checks reuse one real local fixture/package only.
#[path = "v04_lifecycle_fixture.rs"]
mod fixture;
use fixture::Fixture;
use gtkg_core::v04::{artifact, lifecycle::*};
use gtkg_core::{CallContext, EffectPolicy, TransportKind};
use std::fs;

#[test]
fn public_closure_rejects_extra_files_and_resealed_fake_knowledge_without_runtime_writes() {
    let fixture = Fixture::new();
    let (verified_ref, accepted_refs, views_ref) = fixture.build("independent", &[], true);
    let package = finalize(&fixture.context, &fixture.workspace, &FinalizeRequest {
        verified_ref, accepted_refs, views_ref,
        output_path: fixture.workspace.join(".gtkg/qk/bundles/independent"), predecessor: None,
    }).unwrap();
    let root = &package.bundle.workspace_root;
    let reader = CallContext::restricted(TransportKind::Test, vec![root.clone()], EffectPolicy::ReadOnly).unwrap();
    let authority = root.join(".gtkg/qk/runtime/query-authority.json");
    assert!(!authority.exists());
    let checked = verify(&reader, &package.bundle).unwrap();
    assert_eq!(checked.verified_files, package.manifest.files.len());
    assert!(!checked.authority_required_for_read_verification);
    assert!(!checked.manifest.llm_qa_validated);
    assert!(!authority.exists(), "ReadOnly verification created runtime authority");
    assert!(import_bundle(&reader, &package.bundle).is_err());
    assert!(!authority.exists(), "Rejected ReadOnly import created runtime authority");

    let undeclared = root.join(".gtkg/qk/undeclared-public-artifact.json");
    fs::write(&undeclared, b"{\"fixture\":true}").unwrap();
    assert!(verify(&reader, &package.bundle).unwrap_err().contains("undeclared"));
    fs::remove_file(undeclared).unwrap();
    assert!(verify(&reader, &package.bundle).is_ok());

    let canonical_path = &package.manifest.canonical_okf_refs[0].path;
    let original_knowledge = fs::read(root.join(canonical_path)).unwrap();
    let invented = b"# Independently unreviewed fixture claim\nThis must not become accepted knowledge.\n";
    fs::write(root.join(canonical_path), invented).unwrap();
    let mut altered = package.manifest.clone();
    let fake_sha = artifact::digest(invented);
    altered.canonical_okf_refs[0].sha256 = fake_sha.clone();
    for entry in &mut altered.files {
        if entry.reference.path == *canonical_path {
            entry.reference.sha256 = fake_sha.clone();
            entry.bytes = invented.len() as u64;
        }
    }
    let manifest_path = root.join(&package.bundle.manifest_ref.path);
    let original_manifest = fs::read(&manifest_path).unwrap();
    let bytes = serde_json::to_vec_pretty(&altered).unwrap();
    fs::write(&manifest_path, &bytes).unwrap();
    let mut resealed = package.bundle.clone();
    resealed.manifest_ref.sha256 = artifact::digest(&bytes);
    assert!(verify(&reader, &resealed).is_err(), "A self-consistent public inventory cannot replace the accepted claim chain");
    fs::write(root.join(canonical_path), original_knowledge).unwrap();
    fs::write(manifest_path, original_manifest).unwrap();
    assert!(verify(&reader, &package.bundle).is_ok());
    assert!(!authority.exists());
}
