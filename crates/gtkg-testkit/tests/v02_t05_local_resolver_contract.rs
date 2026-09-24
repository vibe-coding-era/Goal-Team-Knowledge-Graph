//! V0.2 T05 contract: local language adapters may resolve only same-IR,
//! byte-evidenced symbols.  They must retain ambiguity and unknown targets.

use std::fs;

use gtkg_extract::{
    build_typed_ir_v2, extract_path, local_resolver_profile_v2, resolve_local_typed_ir_v2,
};
use gtkg_protocol::v2::{
    CapabilityState, IrResolutionStateV2, SourceBaselineIdentityV2, SourceCaptureModeV2,
    SourceEligibilityV2, SourceSnapshotDenominatorV2, SourceSnapshotEntryV2, SourceSnapshotV2,
};
use sha2::{Digest, Sha256};
use tempfile::tempdir;

const SNAPSHOT_DIGEST: &str =
    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn snapshot(logical_path: &str, source: &str) -> SourceSnapshotV2 {
    SourceSnapshotV2 {
        schema_version: "gtkg.source-snapshot/v2".to_owned(),
        capture_mode: SourceCaptureModeV2::DirectoryExact,
        repository_id: "t05-fixture".to_owned(),
        baseline: SourceBaselineIdentityV2 {
            kind: "directory".to_owned(),
            head: None,
            tree: None,
            status_sha256: SNAPSHOT_DIGEST.to_owned(),
        },
        inventory: vec![SourceSnapshotEntryV2 {
            logical_path: logical_path.to_owned(),
            content_sha256: digest(source.as_bytes()),
            bytes: source.len() as u64,
        }],
        omissions: Vec::new(),
        denominator: SourceSnapshotDenominatorV2 {
            discovered_entries: 1,
            admitted_entries: 1,
            omitted_entries: 0,
        },
        exact_set_sha256: String::new(),
        eligibility: SourceEligibilityV2 {
            development_eligible: true,
            source_release_candidate: false,
            environment_ready: false,
            release_ready: false,
        },
    }
    .with_exact_set_digest()
    .expect("fixture snapshot")
}

fn typed(name: &str, source: &str) -> gtkg_protocol::v2::TypedIrV2 {
    let temp = tempdir().expect("tempdir");
    let path = temp.path().join(name);
    fs::write(&path, source).expect("fixture write");
    let extracted = extract_path(&path).expect("static extraction");
    build_typed_ir_v2(&snapshot(name, source), name, &extracted).expect("typed IR")
}

fn resolved(name: &str, source: &str) -> gtkg_protocol::v2::TypedIrV2 {
    let ir = typed(name, source);
    resolve_local_typed_ir_v2(&ir, source.as_bytes()).expect("local resolver")
}

#[test]
fn four_language_profiles_disclose_local_only_capabilities() {
    for (name, extractor_id) in [
        ("source.rs", "gtkg-code-static-rust/v1"),
        ("source.py", "gtkg-code-static-python/v1"),
        ("source.ts", "gtkg-code-static-ts/v1"),
        ("source.js", "gtkg-code-static-js/v1"),
    ] {
        let profile = local_resolver_profile_v2(extractor_id).expect(name);
        assert_eq!(profile.schema_version, "gtkg.local-resolver-profile/v2");
        assert_eq!(
            profile.capabilities["same_file_reference_resolution"],
            CapabilityState::Supported
        );
        assert_eq!(
            profile.capabilities["workspace_import_resolution"],
            CapabilityState::Unsupported
        );
        assert_eq!(profile.capabilities["types"], CapabilityState::Unsupported);
        assert_eq!(profile.capabilities["cfg"], CapabilityState::Unsupported);
        assert_eq!(
            profile.capabilities["def_use"],
            CapabilityState::Unsupported
        );
        assert_eq!(
            profile.capabilities["state_flow"],
            CapabilityState::Unsupported
        );
        assert_eq!(
            profile.capabilities["external_semantic_score"],
            CapabilityState::Unsupported
        );
    }
}

#[test]
fn exact_same_file_calls_resolve_in_each_supported_language_with_target_evidence() {
    let fixtures = [
        ("source.rs", "fn helper() {}\nfn caller() { helper(); }\n"),
        (
            "source.py",
            "def helper():\n    pass\ndef caller():\n    helper()\n",
        ),
        (
            "source.ts",
            "function helper() {}\nfunction caller() { helper(); }\n",
        ),
        (
            "source.js",
            "function helper() {}\nfunction caller() { helper(); }\n",
        ),
    ];
    for (name, source) in fixtures {
        let ir = resolved(name, source);
        let helper = ir
            .nodes
            .iter()
            .find(|node| node.name == "helper")
            .expect(name);
        let call = ir
            .edges
            .iter()
            .find(|edge| edge.kind == "calls" && edge.target_reference == "helper")
            .expect(name);
        assert_eq!(call.resolution, IrResolutionStateV2::Resolved, "{name}");
        assert_eq!(
            call.resolved_node_id.as_deref(),
            Some(helper.id.as_str()),
            "{name}"
        );
        assert!(call.candidate_node_ids.is_empty(), "{name}");
        assert!(
            helper
                .evidence_ids
                .iter()
                .all(|id| call.evidence_ids.contains(id)),
            "{name} requires observed target evidence"
        );
        ir.validate_for_source(source.as_bytes()).expect(name);
    }
}

#[test]
fn ambiguous_and_unknown_references_are_never_promoted() {
    let ambiguous = resolved(
        "source.js",
        "function run() {}\nclass Holder { run() {} }\nfunction caller() { run(); }\n",
    );
    let edge = ambiguous
        .edges
        .iter()
        .find(|edge| edge.kind == "calls" && edge.target_reference == "run")
        .expect("call");
    assert_eq!(edge.resolution, IrResolutionStateV2::Ambiguous);
    assert_eq!(edge.candidate_node_ids.len(), 2);
    assert!(edge.resolved_node_id.is_none());

    let unknown = resolved("source.py", "def caller():\n    missing()\n");
    let edge = unknown
        .edges
        .iter()
        .find(|edge| edge.kind == "calls" && edge.target_reference == "missing")
        .expect("call");
    assert_eq!(edge.resolution, IrResolutionStateV2::Unresolved);
    assert!(edge.candidate_node_ids.is_empty());
    assert!(edge.resolved_node_id.is_none());
}

#[test]
fn resolver_requires_exact_source_readback_before_promoting_any_edge() {
    let source = "fn helper() {}\nfn caller() { helper(); }\n";
    let ir = typed("source.rs", source);
    let error = resolve_local_typed_ir_v2(&ir, b"fn helper() {}\nfn caller() { bogus(); }\n")
        .expect_err("same-length source replacement must fail closed");
    assert_eq!(error.code(), "E_V2_IR_SOURCE_DIGEST_MISMATCH");
}

#[test]
fn imports_remain_unresolved_without_workspace_topology_evidence() {
    for (name, source) in [
        ("source.rs", "use crate::model::Entry;\nfn caller() {}\n"),
        (
            "source.py",
            "from model import Entry\ndef caller():\n    pass\n",
        ),
        (
            "source.ts",
            "import { Entry } from './model';\nfunction caller() {}\n",
        ),
        (
            "source.js",
            "import { Entry } from './model.js';\nfunction caller() {}\n",
        ),
    ] {
        let ir = resolved(name, source);
        let imports = ir
            .edges
            .iter()
            .filter(|edge| edge.kind == "imports")
            .collect::<Vec<_>>();
        assert!(!imports.is_empty(), "{name} fixture must expose an import");
        for edge in imports {
            assert_eq!(edge.resolution, IrResolutionStateV2::Unresolved, "{name}");
            assert!(edge.candidate_node_ids.is_empty(), "{name}");
            assert!(edge.resolved_node_id.is_none(), "{name}");
        }
    }
}

#[test]
fn resolver_clears_preloaded_nonlocal_resolution_states_and_rebuilds_capabilities() {
    let source = "use crate::model::Entry;\nfn one() {}\nfn two() {}\n";
    let raw = typed("source.rs", source);
    let node_ids = raw
        .nodes
        .iter()
        .map(|node| node.id.clone())
        .collect::<Vec<_>>();

    let mut falsely_resolved = raw.clone();
    let import = falsely_resolved
        .edges
        .iter_mut()
        .find(|edge| edge.kind == "imports")
        .expect("import edge");
    import.resolution = IrResolutionStateV2::Resolved;
    import.resolved_node_id = Some(node_ids[0].clone());
    falsely_resolved = falsely_resolved.with_digest();
    let cleaned = resolve_local_typed_ir_v2(&falsely_resolved, source.as_bytes())
        .expect("resolver must clear an import's false resolved state");
    let import = cleaned
        .edges
        .iter()
        .find(|edge| edge.kind == "imports")
        .expect("import edge");
    assert_eq!(import.resolution, IrResolutionStateV2::Unresolved);
    assert!(import.resolved_node_id.is_none());
    assert!(import.candidate_node_ids.is_empty());

    let mut falsely_ambiguous = raw.clone();
    let import = falsely_ambiguous
        .edges
        .iter_mut()
        .find(|edge| edge.kind == "imports")
        .expect("import edge");
    import.resolution = IrResolutionStateV2::Ambiguous;
    import.candidate_node_ids = node_ids;
    falsely_ambiguous = falsely_ambiguous.with_digest();
    let cleaned = resolve_local_typed_ir_v2(&falsely_ambiguous, source.as_bytes())
        .expect("resolver must clear an import's false ambiguous state");
    let import = cleaned
        .edges
        .iter()
        .find(|edge| edge.kind == "imports")
        .expect("import edge");
    assert_eq!(import.resolution, IrResolutionStateV2::Unresolved);
    assert!(import.resolved_node_id.is_none());
    assert!(import.candidate_node_ids.is_empty());

    let mut injected = raw;
    for capability in ["types", "cfg", "def_use", "state_flow"] {
        injected
            .capabilities
            .insert(capability.to_owned(), CapabilityState::Supported);
    }
    injected = injected.with_digest();
    let cleaned = resolve_local_typed_ir_v2(&injected, source.as_bytes())
        .expect("resolver must rebuild the complete local capability matrix");
    assert_eq!(
        cleaned.capabilities,
        local_resolver_profile_v2("gtkg-code-static-rust/v1")
            .expect("Rust profile")
            .capabilities,
        "resolver must replace, rather than patch, the inherited capability matrix"
    );
    for capability in ["types", "cfg", "def_use", "state_flow"] {
        assert_eq!(
            cleaned.capabilities[capability],
            CapabilityState::Unsupported,
            "{capability} cannot survive injected support"
        );
    }
}

#[test]
fn typed_ir_rejects_logical_path_and_extractor_identity_mismatch() {
    let source = "fn caller() {}\n";
    let temp = tempdir().expect("tempdir");
    let path = temp.path().join("source.rs");
    fs::write(&path, source).expect("fixture write");
    let extracted = extract_path(&path).expect("Rust extraction");
    let error = build_typed_ir_v2(&snapshot("source.py", source), "source.py", &extracted)
        .expect_err("a Rust extractor cannot be bound to a Python logical path");
    assert_eq!(error.code(), "E_V2_IR_EXTRACTOR_IDENTITY_MISMATCH");

    let mut ir = typed("source.rs", source);
    assert_eq!(ir.extractor_id, "gtkg-code-static-rust/v1");
    ir.extractor_id = "gtkg-code-static-python/v1".to_owned();
    let error = resolve_local_typed_ir_v2(&ir.with_digest(), source.as_bytes())
        .expect_err("a digest-valid extractor identity substitution must fail closed");
    assert_eq!(error.code(), "E_V2_IR_EXTRACTOR_IDENTITY_MISMATCH");
}
