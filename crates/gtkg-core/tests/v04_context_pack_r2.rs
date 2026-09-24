//! Public synthetic reference-pack fixture. No model, benchmark, or target execution.
#![allow(clippy::unwrap_used)]
use gtkg_core::v04::{
    artifact,
    context_pack::{self, *},
    index, query,
    query_meter::{QueryBudgetLimits, QueryBudgetUsage, QueryMeter},
    source::{self, ScopePolicy, SourceCaptureRequest},
};
use gtkg_core::{CallContext, EffectPolicy, TransportKind};
use gtkg_protocol::{
    FileReceiptRef,
    v04::{ArtifactPayload, QueryPayload, Revision},
};
use serde_json::{Value, json};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

fn git(root: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "synthetic fixture Git operation failed"
    );
    String::from_utf8(out.stdout).unwrap().trim().into()
}
struct Fixture {
    _temp: tempfile::TempDir,
    root: PathBuf,
    writer: CallContext,
    reader: CallContext,
    plan: QueryPlanArtifact,
    hits: QueryHitsArtifact,
    usage: QueryBudgetUsage,
    key: [u8; 32],
}
fn fixture() -> Fixture {
    let temp = tempfile::tempdir().unwrap();
    let base = fs::canonicalize(temp.path()).unwrap();
    let root = base.join("work");
    let repo = base.join("repo");
    fs::create_dir(&root).unwrap();
    fs::create_dir(&repo).unwrap();
    git(&repo, &["init", "-q"]);
    fs::write(
        repo.join("manual.md"),
        "# Source\nPACK_EXACT_EVIDENCE：仅在已归档版本中恢复；不能推断远端状态。\n",
    )
    .unwrap();
    let noise = (0..16000)
        .map(|i| format!("{:064x}\n", (i as u128 + 7) * 0x123456789abcdef123u128))
        .collect::<String>();
    fs::write(repo.join("unrelated.md"), noise).unwrap();
    git(&repo, &["add", "."]);
    git(
        &repo,
        &[
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "-c",
            "core.hooksPath=/dev/null",
            "commit",
            "-qm",
            "fixture",
        ],
    );
    let writer = CallContext::restricted(
        TransportKind::Test,
        vec![root.clone(), repo.clone()],
        EffectPolicy::WorkspaceWrite,
    )
    .unwrap();
    source::capture(&SourceCaptureRequest {
        repository_id: "pack-synthetic".into(),
        source_root: repo.clone(),
        source_commit: git(&repo, &["rev-parse", "HEAD"]),
        expected_tree: git(&repo, &["rev-parse", "HEAD^{tree}"]),
        output_path: root.join("archive"),
        policy: ScopePolicy::default(),
    })
    .unwrap();
    let source_ref = artifact::reference(
        &writer,
        &root,
        &root.join("archive").join(source::LEDGER_FILE),
    )
    .unwrap();
    let index_ref = index::build(&writer, &root, &source_ref, &[]).unwrap();
    let manifest = index::load_manifest(&writer, &root, &index_ref).unwrap();
    let reader = CallContext::restricted(
        TransportKind::Test,
        vec![root.clone()],
        EffectPolicy::ReadOnly,
    )
    .unwrap();
    let response = query::search(
        &reader,
        &QueryPayload {
            payload_revision: Revision::R1,
            workspace_root: root.clone(),
            index_ref: index_ref.clone(),
            query: "PACK_EXACT_EVIDENCE".into(),
            query_policy: index::QUERY_POLICY.into(),
            max_results: 10,
            max_tokens: 8000,
            continuation: None,
        },
    )
    .unwrap();
    let evidence = response["evidence"].as_array().unwrap();
    assert_eq!(evidence.len(), 1);
    let hit = &evidence[0];
    let id = hit["id"].as_str().unwrap();
    let (chunk_ref, _) = index::lookup_chunk_ref(&reader, &root, &manifest, id).unwrap();
    let chunk = index::load_chunk_by_id(&reader, &root, &manifest, id).unwrap();
    let identity = artifact::digest(b"synthetic actual-query pack preparation");
    let plan = QueryPlanArtifact {
        schema: PLAN_SCHEMA.into(),
        original_query: "PACK_EXACT_EVIDENCE".into(),
        query_policy: index::QUERY_POLICY.into(),
        query_identity: identity.clone(),
        public_index_ref: index_ref.clone(),
        base_index_ref: index_ref,
        selected_index_lineage: vec![],
        total_index_bytes: manifest.total_index_bytes,
        source_identity: QuerySourceIdentity {
            snapshot_id: manifest.snapshot_id,
            source_commit: manifest.source_commit,
            source_tree: manifest.source_tree,
            source_ref,
        },
        query_plan: response["query_plan"].clone(),
    };
    let hits = QueryHitsArtifact {
        schema: HITS_SCHEMA.into(),
        query_identity: identity,
        plan_sha256: String::new(),
        ranking_complete: true,
        ranking_scope: "all_required_candidates".into(),
        candidate_ambiguities: vec![],
        hits: vec![PackHitRef {
            rank: 0,
            posting: index::Posting {
                chunk_id: chunk.id,
                chunk_ref,
                term_frequency: 1,
                tokens: chunk.tokens,
            },
            evidence_byte_start: hit["byte_start"].as_u64().unwrap() as usize,
            evidence_byte_end: hit["byte_end"].as_u64().unwrap() as usize,
            score: hit["score"].as_f64().unwrap(),
            score_reasons: hit["score_reasons"].clone(),
            neighbor_of: None,
            graph_relation: None,
            summary_context: vec![],
        }],
    };
    let usage = QueryBudgetUsage {
        io_bytes: response["budget"]["io_bytes"].as_u64().unwrap(),
        wall_time_us: response["budget"]["wall_time_us"].as_u64().unwrap(),
        posting_rows: response["scanned"]["postings"].as_u64().unwrap(),
        candidate_count: response["scanned"]["candidates"].as_u64().unwrap(),
        initial_subqueries: response["query_plan"]["initial_subqueries"]
            .as_array()
            .unwrap()
            .len() as u32,
        structural_expansions: 0,
    };
    let authority: Value = serde_json::from_slice(
        &fs::read(root.join(".gtkg/qk/runtime/query-authority.json")).unwrap(),
    )
    .unwrap();
    let key: [u8; 32] = hex::decode(authority["key"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    fs::rename(&repo, base.join("source-unavailable")).unwrap();
    Fixture {
        _temp: temp,
        root,
        writer,
        reader,
        plan,
        hits,
        usage,
        key,
    }
}
fn stage(f: &Fixture, preparation: &PackPreparation, units: u32) -> (ArtifactPayload, PackRequest) {
    fs::write(f.root.join("plan.json"), &preparation.plan_json).unwrap();
    fs::write(f.root.join("hits.json"), &preparation.hits_json).unwrap();
    let request = PackRequest {
        schema: REQUEST_SCHEMA.into(),
        plan_ref: artifact::reference(&f.writer, &f.root, &f.root.join("plan.json")).unwrap(),
        hits_ref: artifact::reference(&f.writer, &f.root, &f.root.join("hits.json")).unwrap(),
        pack_ticket: preparation.pack_ticket.clone(),
        max_context_units: units,
    };
    (stage_request(f, &request), request)
}
fn stage_request(f: &Fixture, request: &PackRequest) -> ArtifactPayload {
    fs::write(
        f.root.join("pack-request.json"),
        serde_json::to_vec(request).unwrap(),
    )
    .unwrap();
    ArtifactPayload {
        payload_revision: Revision::R1,
        workspace_root: f.root.clone(),
        artifact_ref: artifact::reference(&f.writer, &f.root, &f.root.join("pack-request.json"))
            .unwrap(),
    }
}
fn prepare(f: &Fixture) -> PackPreparation {
    context_pack::prepare_pack(
        &f.root,
        &f.plan,
        &f.hits,
        f.usage.clone(),
        QueryBudgetLimits::for_index(f.plan.total_index_bytes),
        &f.key,
    )
    .unwrap()
}

#[test]
fn referenced_pack_roundtrip_keeps_source_and_cumulative_usage_r2() {
    let f = fixture();
    let prep = prepare(&f);
    let (payload, _) = stage(&f, &prep, 8000);
    let authority = f.root.join(".gtkg/qk/runtime/query-authority.json");
    let before = fs::read(&authority).unwrap();
    let packed = context_pack::execute(&f.reader, &payload)
        .expect("reference pack must consume an authenticated query batch");
    assert_eq!(packed["schema"], "gtkg.qk.context-pack-receipt/v1");
    assert_eq!(packed["status"], "complete");
    assert_eq!(packed["terminal"], true);
    let raw = &packed["raw_evidence"][0];
    assert!(
        raw["text"]
            .as_str()
            .unwrap()
            .contains("PACK_EXACT_EVIDENCE")
    );
    let object = fs::read(
        f.root
            .join("archive/objects")
            .join(raw["object_sha"].as_str().unwrap()),
    )
    .unwrap();
    assert_eq!(
        &object[raw["byte_start"].as_u64().unwrap() as usize
            ..raw["byte_end"].as_u64().unwrap() as usize],
        raw["text"].as_str().unwrap().as_bytes()
    );
    assert!(packed["budget"]["usage"]["io_bytes"].as_u64().unwrap() > f.usage.io_bytes);
    assert!(packed["budget"]["usage"]["wall_time_us"].as_u64().unwrap() >= f.usage.wall_time_us);
    assert_eq!(
        packed["budget"]["usage"]["candidate_count"],
        f.usage.candidate_count
    );
    assert_eq!(
        packed["budget"]["usage"]["posting_rows"],
        f.usage.posting_rows
    );
    assert_eq!(packed["verification_scope"]["full_graph_reads"], 0);
    assert_eq!(
        packed["verification_scope"]["unread_objects"],
        "not_checked"
    );
    assert_eq!(fs::read(authority).unwrap(), before);

    // Same authenticated batch, restricted output: Unicode windows remain exact.
    let (small, _) = stage(&f, &prep, 19);
    let narrow = context_pack::execute(&f.reader, &small).unwrap();
    assert_eq!(narrow["status"], "partial");
    assert!(narrow["budget"]["context_units"].as_u64().unwrap() <= 19);
    let e = &narrow["raw_evidence"][0];
    let begin = e["byte_start"].as_u64().unwrap() as usize;
    let end = e["byte_end"].as_u64().unwrap() as usize;
    assert_eq!(&object[begin..end], e["text"].as_str().unwrap().as_bytes());

    // Rehashed caller files cannot substitute a different authenticated plan/hit.
    for name in ["plan", "hits"] {
        let (_, mut request) = stage(&f, &prep, 8000);
        let path = f.root.join(format!("{name}.json"));
        let mut value: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        if name == "plan" {
            value["original_query"] = json!("forged question");
        } else {
            value["hits"][0]["score"] = json!(999999999);
        }
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        let changed = artifact::reference(&f.writer, &f.root, &path).unwrap();
        if name == "plan" {
            request.plan_ref = changed;
        } else {
            request.hits_ref = changed;
        }
        let error = context_pack::execute(&f.reader, &stage_request(&f, &request)).unwrap_err();
        assert!(error.contains("authenticated bytes"), "{error}");
        assert!(
            error.contains("authenticated_budget_usage"),
            "rejected staged input lost already spent bootstrap IO"
        );
    }
    let (_, mut request) = stage(&f, &prep, 8000);
    let (body, sig) = request.pack_ticket.split_once('.').unwrap();
    let mut value: Value = serde_json::from_slice(&hex::decode(body).unwrap()).unwrap();
    value["usage"]["io_bytes"] = json!(0);
    request.pack_ticket = format!(
        "{}.{}",
        hex::encode(serde_json::to_vec(&value).unwrap()),
        sig
    );
    assert!(
        context_pack::execute(&f.reader, &stage_request(&f, &request))
            .unwrap_err()
            .contains("authentication failed")
    );
    let (_, mut request) = stage(&f, &prep, 8000);
    request.pack_ticket = "00.00".into();
    assert!(context_pack::execute(&f.reader, &stage_request(&f, &request)).is_err());

    // A selected source modified after query admission is still read and rejected.
    let (valid, _) = stage(&f, &prep, 8000);
    let source_path = f
        .root
        .join("archive/objects")
        .join(raw["object_sha"].as_str().unwrap());
    let mut changed = object.clone();
    changed[0] ^= 1;
    fs::write(&source_path, changed).unwrap();
    let error = context_pack::execute(&f.reader, &valid).unwrap_err();
    assert!(error.contains("source object identity mismatch"));
    assert!(error.contains("authenticated_budget_usage"));
    fs::write(source_path, &object).unwrap();

    // Controlled fixture-authority signing tests terminal budget transition logic.
    for exhausted in ["io", "time"] {
        let mut usage = f.usage.clone();
        let limits = QueryBudgetLimits::for_index(f.plan.total_index_bytes);
        if exhausted == "io" {
            usage.io_bytes = limits.io_bytes;
        } else {
            usage.wall_time_us = limits.wall_time_us;
        }
        let prep =
            context_pack::prepare_pack(&f.root, &f.plan, &f.hits, usage.clone(), limits, &f.key)
                .unwrap();
        let (input, _) = stage(&f, &prep, 8000);
        let stopped = context_pack::execute(&f.reader, &input).unwrap();
        assert_eq!(stopped["status"], "partial");
        assert!(stopped["raw_evidence"].as_array().unwrap().is_empty());
        assert_eq!(stopped["verification_scope"]["source_object_reads"], 0);
        assert!(stopped["budget"]["usage"]["io_bytes"].as_u64().unwrap() > usage.io_bytes);
        if exhausted == "io" {
            assert_eq!(stopped["budget"]["mandatory_header_overrun"], true);
        }
        assert!(
            stopped["retry_fork_accounting"]
                .as_str()
                .unwrap()
                .contains("host_owned")
        );
    }
    let (valid, _) = stage(&f, &prep, 8000);
    let authority = f.root.join(".gtkg/qk/runtime/query-authority.json");
    fs::remove_file(&authority).unwrap();
    assert!(context_pack::execute(&f.reader, &valid).is_err());
    assert!(
        !authority.exists(),
        "ReadOnly packing created missing authority"
    );
}

#[test]
fn metered_rejection_preserves_real_bytes_and_never_reads_oversized_files_r2() {
    let temp = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(temp.path()).unwrap();
    fs::write(root.join("data.json"), b"{\"value\":42}").unwrap();
    let ctx = CallContext::restricted(
        TransportKind::Test,
        vec![root.clone()],
        EffectPolicy::ReadOnly,
    )
    .unwrap();
    let mut meter = QueryMeter::new(
        QueryBudgetUsage::default(),
        QueryBudgetLimits::for_index(100_000),
    );
    let reference = FileReceiptRef {
        path: "data.json".into(),
        sha256: artifact::digest(b"wrong"),
    };
    assert!(
        meter
            .read_reference::<Value>(&ctx, &root, &reference, 100)
            .is_err()
    );
    assert_eq!(meter.usage().io_bytes, 12);
    assert!(meter.read(&ctx, &root.join("data.json"), 3).is_err());
    assert_eq!(meter.usage().io_bytes, 12);
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(root.join("data.json"), root.join("link")).unwrap();
        assert!(meter.read(&ctx, &root.join("link"), 100).is_err());
        assert_eq!(meter.usage().io_bytes, 12);
    }
}
