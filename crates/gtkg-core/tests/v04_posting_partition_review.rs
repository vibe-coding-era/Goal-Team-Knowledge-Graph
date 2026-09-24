#![allow(clippy::unwrap_used)]
//! Independent routing, byte-accounting and package-closure checks. All inputs
//! are synthetic tokens/fixtures; no gold questions or retrieval quality metrics.
#[path = "v04_lifecycle_fixture.rs"]
mod fixture;
use fixture::Fixture;
use gtkg_core::v04::{analysis::VerifiedAnalysis, artifact, index, lifecycle, query};
use gtkg_core::{CallContext, EffectPolicy, TransportKind};
use gtkg_protocol::{
    FileReceiptRef,
    v04::{QueryPayload, Revision},
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, fs, path::Path};
fn hash(t: &str) -> String {
    hex::encode(Sha256::digest(t.as_bytes()))
}
fn tokens() -> (String, String, String) {
    let first = (0..100)
        .map(|i| format!("neutralprobe{i}"))
        .find(|t| &hash(&format!("exact:{t}"))[2..3] != "f")
        .unwrap();
    let prefix = hash(&format!("exact:{first}"));
    let second = (0..100_000)
        .map(|i| format!("neutralpeer{i}"))
        .find(|t| {
            let h = hash(&format!("exact:{t}"));
            h[..2] == prefix[..2] && h[2..3] != prefix[2..3] && &h[2..3] != "f"
        })
        .unwrap();
    let second_hash = hash(&format!("exact:{second}"));
    let forbidden_fold_buckets = [
        hash(&format!("fold:{first}"))[..2].to_string(),
        hash(&format!("fold:{second}"))[..2].to_string(),
        prefix[..2].to_string(),
    ];
    let noise: Vec<_> = (0..200_000)
        .map(|i| format!("neutralnoise{i:06}"))
        .filter(|t| {
            let h = hash(&format!("exact:{t}"));
            let f = hash(&format!("fold:{t}"));
            h[..2] == prefix[..2]
                && h[2..3] != prefix[2..3]
                && h[2..3] != second_hash[2..3]
                && &h[2..3] != "f"
                && !forbidden_fold_buckets.contains(&f[..2].to_string())
        })
        .take(16)
        .collect();
    assert_eq!(noise.len(), 16);
    (first, second, (noise.join(" ") + "\n\n").repeat(400))
}
fn json(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}
fn setup() -> (
    Fixture,
    (FileReceiptRef, Vec<FileReceiptRef>, FileReceiptRef),
    index::IndexManifest,
    String,
    String,
) {
    let f = Fixture::new();
    let (first, second, noise) = tokens();
    let probe = format!("{first}\n{second}\n");
    let refs = f.build(
        "partitionreview",
        &[("probe.md", &probe), ("neutral.md", &noise)],
        false,
    );
    let (v, _): (VerifiedAnalysis, _) = artifact::read(&f.context, &f.workspace, &refs.0).unwrap();
    let m = index::load_manifest(&f.context, &f.workspace, &v.index_ref.unwrap()).unwrap();
    (f, refs, m, first, second)
}
fn reseal_router(
    f: &Fixture,
    m: &index::IndexManifest,
    bucket: &str,
    value: &Value,
) -> index::IndexManifest {
    let mut modified = m.clone();
    let reference = modified.router.get_mut(bucket).unwrap().as_mut().unwrap();
    let raw = serde_json::to_vec_pretty(value).unwrap();
    fs::write(f.workspace.join(&reference.path), &raw).unwrap();
    reference.bytes = raw.len() as u64;
    reference.sha256 = artifact::digest(&raw);
    modified
}
#[test]
fn partition_selection_rejects_wrong_identity_and_counts_each_real_read() {
    let (f, _refs, m, first, second) = setup();
    let term = format!("exact:{first}");
    let digest = hash(&term);
    let bucket = &digest[..2];
    let r = m.router[bucket].as_ref().unwrap();
    let router_path = f.workspace.join(&r.path);
    let original_router = fs::read(&router_path).unwrap();
    let router = json(&router_path);
    assert_eq!(router["schema"], "gtkg.qk.posting-partitions/v2");
    assert_eq!(router["partitions"].as_object().unwrap().len(), 16);
    assert!(router["terms"].as_object().unwrap().is_empty());
    let leaf_ref = &router["partitions"][&digest[..3]];
    let leaf_path = f.workspace.join(leaf_ref["path"].as_str().unwrap());
    let original_leaf = fs::read(&leaf_path).unwrap();
    let (posts, scanned) =
        index::load_postings_bounded(&f.context, &f.workspace, &m, &term, 16).unwrap();
    assert_eq!(posts.len(), 1);
    assert!(scanned <= 16);
    let other = router["partitions"]
        .as_object()
        .unwrap()
        .iter()
        .find(|(key, value)| key.as_str() != &digest[..3] && !value.is_null())
        .unwrap();
    let other_path = f.workspace.join(other.1["path"].as_str().unwrap());
    let other_bytes = fs::read(&other_path).unwrap();
    fs::write(&other_path, b"unread partition deliberately invalid").unwrap();
    assert_eq!(
        index::load_postings_bounded(&f.context, &f.workspace, &m, &term, 16)
            .unwrap()
            .0,
        posts,
        "an unrelated child is not a selected read"
    );
    fs::write(&other_path, other_bytes).unwrap();
    fs::remove_file(&leaf_path).unwrap();
    assert!(index::load_postings_bounded(&f.context, &f.workspace, &m, &term, 16).is_err());
    fs::write(&leaf_path, &original_leaf).unwrap();
    let mut missing = router.clone();
    missing["partitions"]
        .as_object_mut()
        .unwrap()
        .remove(other.0);
    let altered = reseal_router(&f, &m, bucket, &missing);
    assert!(
        index::load_postings_bounded(&f.context, &f.workspace, &altered, &term, 16)
            .unwrap_err()
            .contains("partition"),
        "a resealed 15-key route denominator must fail"
    );
    fs::write(&router_path, &original_router).unwrap();
    let mut foreign: Value = serde_json::from_slice(&original_leaf).unwrap();
    foreign["snapshot_id"] = Value::String("f".repeat(64));
    let raw = serde_json::to_vec_pretty(&foreign).unwrap();
    fs::write(&leaf_path, &raw).unwrap();
    let mut foreign_router = router.clone();
    foreign_router["partitions"][&digest[..3]]["bytes"] = Value::from(raw.len() as u64);
    foreign_router["partitions"][&digest[..3]]["sha256"] = Value::String(artifact::digest(&raw));
    let altered = reseal_router(&f, &m, bucket, &foreign_router);
    assert!(
        index::load_postings_bounded(&f.context, &f.workspace, &altered, &term, 16)
            .unwrap_err()
            .contains("identity"),
        "authenticating JSON bytes must not erase foreign source identity"
    );
    fs::write(&leaf_path, &original_leaf).unwrap();
    fs::write(&router_path, &original_router).unwrap();
    // Legacy leaves remain readable; routing metadata cannot masquerade as data.
    let legacy = m
        .router
        .values()
        .flatten()
        .find_map(|reference| {
            let data = json(&f.workspace.join(&reference.path));
            (data["schema"] == "gtkg.qk.posting-shard/v1").then_some(data)
        })
        .unwrap();
    let legacy_term = legacy["terms"].as_object().unwrap().keys().next().unwrap();
    assert!(
        !index::load_postings(&f.context, &f.workspace, &m, legacy_term)
            .unwrap()
            .is_empty()
    );
    let index_ref = FileReceiptRef {
        path: format!("{}/manifest.json", m.index_root),
        sha256: artifact::digest(
            &fs::read(f.workspace.join(&m.index_root).join("manifest.json")).unwrap(),
        ),
    };
    let reader = CallContext::restricted(
        TransportKind::Test,
        vec![f.workspace.clone()],
        EffectPolicy::ReadOnly,
    )
    .unwrap();
    let result = query::search(
        &reader,
        &QueryPayload {
            payload_revision: Revision::R1,
            workspace_root: f.workspace.clone(),
            index_ref: index_ref.clone(),
            query: format!("{first} {second}"),
            query_policy: index::QUERY_POLICY.into(),
            max_results: 1,
            max_tokens: 8000,
            continuation: None,
        },
    )
    .unwrap();
    assert_eq!(
        result["ranking_complete"], true,
        "synthetic route-only fixture must finish within unchanged limits: {result}"
    );
    assert_eq!(result["evidence"].as_array().unwrap().len(), 1);
    let mut terms = BTreeSet::new();
    let mut route_bytes = 0u64;
    let mut route_reads = 0u64;
    for group in result["query_plan"]["initial_subqueries"]
        .as_array()
        .unwrap()
    {
        for entry in group["terms"].as_array().unwrap() {
            let t = entry["term"].as_str().unwrap();
            if !terms.insert(t.to_string()) {
                continue;
            }
            if let Some(ref top) = m.router[&index::token_bucket(t)] {
                route_bytes += top.bytes;
                route_reads += 1;
                let top = json(&f.workspace.join(&top.path));
                if let Some(parts) = top["partitions"].as_object() {
                    let child = &parts[&hash(t)[..3]];
                    if !child.is_null() {
                        route_bytes += child["bytes"].as_u64().unwrap();
                        route_reads += 1;
                    }
                }
            }
        }
    }
    let hit = &result["evidence"][0];
    let chunk_path = f
        .workspace
        .join(&m.index_root)
        .join("chunks")
        .join(format!("{}.json", hit["id"].as_str().unwrap()));
    let chunk_bytes = fs::metadata(&chunk_path).unwrap().len();
    let chunk = json(&chunk_path);
    let expected = fs::metadata(f.workspace.join(&index_ref.path))
        .unwrap()
        .len()
        + fs::metadata(f.workspace.join(".gtkg/qk/runtime/query-authority.json"))
            .unwrap()
            .len()
        + route_bytes
        + 2 * chunk_bytes
        + fs::metadata(f.workspace.join(&m.source_ref.path))
            .unwrap()
            .len()
        + chunk["object_bytes"].as_u64().unwrap();
    assert_eq!(
        result["budget"]["io_bytes"], expected,
        "current uncached selected routing plan must charge roots, children, repeated roots, chunks, ledger, and object bytes"
    );
    assert_eq!(
        result["verification_scope"]["posting_shard_reads"],
        route_reads
    );
    assert_eq!(
        result["budget"]["io_limit"],
        (m.total_index_bytes / 20).min(64 * 1024 * 1024)
    );
}
#[test]
fn portable_closure_contains_every_partition_and_rejects_missing_unselected_child() {
    let (f, refs, m, first, _second) = setup();
    let package = lifecycle::finalize(
        &f.context,
        &f.workspace,
        &lifecycle::FinalizeRequest {
            verified_ref: refs.0,
            accepted_refs: refs.1,
            views_ref: refs.2,
            output_path: f.workspace.join(".gtkg/qk/bundles/partition-review"),
            predecessor: None,
        },
    )
    .unwrap();
    assert!(
        package
            .bundle
            .workspace_root
            .starts_with(fs::canonicalize(f.temp.path()).unwrap())
    );
    let root = &package.bundle.workspace_root;
    let reader = CallContext::restricted(
        TransportKind::Test,
        vec![root.clone()],
        EffectPolicy::ReadOnly,
    )
    .unwrap();
    assert!(lifecycle::verify(&reader, &package.bundle).is_ok());
    assert!(!root.join(".gtkg/qk/runtime/query-authority.json").exists());
    let term = format!("exact:{first}");
    let h = hash(&term);
    let router = json(&root.join(&m.router[&h[..2]].as_ref().unwrap().path));
    let children: Vec<_> = router["partitions"]
        .as_object()
        .unwrap()
        .iter()
        .filter(|(_, r)| !r.is_null())
        .collect();
    assert!(children.len() > 1);
    for (_, reference) in &children {
        assert!(
            package
                .manifest
                .files
                .iter()
                .any(|entry| entry.role == "posting_partition"
                    && entry.reference.path == reference["path"].as_str().unwrap()
                    && entry.reference.sha256 == reference["sha256"].as_str().unwrap()
                    && entry.bytes == reference["bytes"].as_u64().unwrap()),
            "public closure omitted a routed partition"
        );
    }
    let other = children
        .into_iter()
        .find(|(key, _)| key.as_str() != &h[..3])
        .unwrap();
    let path = root.join(other.1["path"].as_str().unwrap());
    fs::remove_file(&path).unwrap();
    let loaded = index::load_manifest(&reader, root, &package.manifest.index_ref).unwrap();
    assert!(
        !index::load_postings(&reader, root, &loaded, &term)
            .unwrap()
            .is_empty(),
        "selected read must remain local"
    );
    assert!(
        lifecycle::verify(&reader, &package.bundle).is_err(),
        "full package verification must detect a missing unselected partition"
    );
    assert!(
        !root.join(".gtkg/qk/runtime/query-authority.json").exists(),
        "read-only package verification must not initialize authority"
    );
}
