//! T09 first behavior gates: exact identity and non-upgrading legacy inspection.
use gtkg_core::{CallContext, EffectPolicy, TransportKind};
use gtkg_core::v04::{artifact, lifecycle::*};
use gtkg_protocol::FileReceiptRef;
use std::{collections::BTreeMap, fs};

fn identity() -> PipelineIdentity {
    PipelineIdentity { profile: "GTKG-V0.4-KNOWLEDGE-QUALITY".into(), snapshot_id: "fixture-snapshot".into(),
        source_commit: "a".repeat(40), source_tree: "b".repeat(40), source_ledger_sha256: format!("sha256:{}", "c".repeat(64)),
        source_policy_sha256: "d".repeat(64), extractor_profile: "gtkg.qk.extractor/v1".into(),
        parser_identities: BTreeMap::from([("go".into(), "tree-sitter-go/0.23.4/abi14".into())]),
        resolver_profile: "gtkg.qk.resolver/v1".into(), verifier_profile: "gtkg.qk.binding-verifier/v1".into(),
        analysis_context_digest: format!("sha256:{}", "e".repeat(64)), chunker: "gtkg.qk.semantic-lines/v1".into(),
        tokenizer: "UTF8-codepoint-v1".into(), query_policy: "gtkg.qk.query/v1".into(),
        accepted_digests: vec![format!("sha256:{}", "f".repeat(64))], views_digest: format!("sha256:{}", "1".repeat(64)) }
}
#[test]
fn identity_accepts_exact_match_and_refuses_each_semantic_dependency_change() {
    let original = identity();
    require_identity(&original, &original).unwrap();
    for field in ["profile", "snapshot_id", "source_commit", "source_tree", "source_ledger_sha256", "source_policy_sha256",
        "extractor_profile", "parser_identities", "resolver_profile", "verifier_profile", "analysis_context_digest", "chunker", "tokenizer", "query_policy", "accepted_digests", "views_digest"] {
        let mut value = serde_json::to_value(&original).unwrap();
        match field {
            "parser_identities" => value[field] = serde_json::json!({"go":"different-parser"}),
            "accepted_digests" => value[field] = serde_json::json!([format!("sha256:{}", "2".repeat(64))]),
            _ => value[field] = serde_json::json!("changed"),
        }
        let changed: PipelineIdentity = serde_json::from_value(value).unwrap();
        assert!(require_identity(&original, &changed).unwrap_err().contains("stale"), "{field} change needs explicit stale refusal");
    }
}
#[test]
fn legacy_v1_is_read_only_digest_bound_and_never_inherits_resolved_or_current() {
    let temp = tempfile::tempdir().unwrap();
    let workspace = temp.path().join("workspace");
    let legacy = workspace.join("legacy");
    fs::create_dir_all(&legacy).unwrap();
    let manifest = b"{\"schema_version\":\"gtkg.bundle/v1\",\"resolved\":true}";
    let old_knowledge = b"# Old knowledge\nresolution: resolved\n";
    fs::write(legacy.join("manifest.json"), manifest).unwrap();
    fs::write(legacy.join("knowledge.md"), old_knowledge).unwrap();
    fs::write(workspace.join("Current"), b"legacy/current\n").unwrap();
    let context = CallContext::restricted(TransportKind::Test, vec![workspace.clone()], EffectPolicy::ReadOnly).unwrap();
    let request = MigrationRequest { legacy_root: legacy.clone(),
        legacy_manifest_ref: FileReceiptRef { path: "manifest.json".into(), sha256: artifact::digest(manifest) }, source_ref: None };
    let ledger = migrate(&context, &workspace, &request).unwrap();
    assert_eq!(ledger.relationship_status, "legacy_unverified");
    assert!(ledger.gaps.iter().any(|gap| gap.contains("migration_gap")));
    assert!(!ledger.current_changed && !ledger.successor_created);
    assert_eq!(ledger.preserved_files.len(), 2);
    assert_eq!(fs::read(legacy.join("manifest.json")).unwrap(), manifest);
    assert_eq!(fs::read(legacy.join("knowledge.md")).unwrap(), old_knowledge);
    assert_eq!(fs::read(workspace.join("Current")).unwrap(), b"legacy/current\n");
    assert!(!workspace.join(".gtkg").exists(), "legacy inspection must be truly read-only");
    fs::write(legacy.join("manifest.json"), b"changed").unwrap();
    assert!(migrate(&context, &workspace, &request).is_err());
}
