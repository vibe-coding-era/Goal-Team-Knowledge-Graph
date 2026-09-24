//! Independent r11 policy review using only synthetic source. No gold or target input.
#![allow(clippy::unwrap_used)]
use gtkg_core::v04::{
    artifact, index, query,
    source::{self, ScopePolicy, ScopeRule, SourceCaptureRequest},
};
use gtkg_core::{CallContext, EffectPolicy, TransportKind};
use gtkg_protocol::{
    FileReceiptRef,
    v04::{PAYLOAD_REVISION, QueryPayload},
};
use hmac::{Hmac, Mac};
use serde_json::{Value, json};
use sha2::Sha256;
use std::{
    collections::BTreeSet,
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

const V2: &str = "gtkg.qk.query/v2";
const NOISE: usize = 2105;
struct Fixture {
    _temp: tempfile::TempDir,
    root: PathBuf,
    reader: CallContext,
    index_ref: FileReceiptRef,
    other_index_ref: FileReceiptRef,
    manifest: index::IndexManifest,
}
fn git(root: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .unwrap();
    assert!(output.status.success(), "synthetic fixture Git failed");
    String::from_utf8(output.stdout).unwrap().trim().into()
}
fn fixture() -> Fixture {
    let temp = tempfile::tempdir().unwrap();
    let base = fs::canonicalize(temp.path()).unwrap();
    let repo = base.join("repo");
    let root = base.join("work");
    fs::create_dir(&repo).unwrap();
    fs::create_dir(&root).unwrap();
    git(&repo, &["init", "-q"]);
    let body = (0..NOISE)
        .map(|i| {
            let words = (0..24)
                .map(|j| format!("z{i:04x}q{j:x}"))
                .collect::<Vec<_>>()
                .join(" ");
            format!("# Unit {i}\nAster {words}\n\n")
        })
        .collect::<String>();
    // Neither exact-case variant exists in the shared pair. Fold alternatives
    // must be ORed with exact alternatives within each of the two signal groups.
    let related = "# Shared one\naster BERYL witnessone\n\n# Shared two\naster BERYL witnesstwo\n\n# Separate one\nCobalt standaloneone\n\n# Separate two\nCobalt standalonetwo\n";
    let stream = format!(
        "blob\nmark :1\ndata {}\n{}\nblob\nmark :2\ndata {}\n{}\ncommit refs/heads/main\ncommitter Fixture <fixture@example.invalid> 0 +0000\ndata 7\nfixture\nM 100644 :1 reference.md\nM 100644 :2 related.md\n\n",
        body.len(),
        body,
        related.len(),
        related
    );
    let mut child = Command::new("git")
        .arg("-C")
        .arg(&repo)
        .args(["fast-import", "--quiet"])
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stream.as_bytes())
        .unwrap();
    assert!(child.wait().unwrap().success());
    let writer = CallContext::restricted(
        TransportKind::Test,
        vec![root.clone(), repo.clone()],
        EffectPolicy::WorkspaceWrite,
    )
    .unwrap();
    let mut request = SourceCaptureRequest {
        repository_id: "selective-independent".into(),
        source_root: repo.clone(),
        source_commit: git(&repo, &["rev-parse", "main"]),
        expected_tree: git(&repo, &["rev-parse", "main^{tree}"]),
        output_path: root.join("archive"),
        policy: ScopePolicy::default(),
    };
    source::capture(&request).unwrap();
    let source_ref = artifact::reference(
        &writer,
        &root,
        &request.output_path.join(source::LEDGER_FILE),
    )
    .unwrap();
    let index_ref = index::build(&writer, &root, &source_ref, &[]).unwrap();
    let manifest = index::load_manifest(&writer, &root, &index_ref).unwrap();
    assert_eq!(
        manifest.total_chunks,
        NOISE + 4,
        "fixture must use the complete actual index"
    );
    request.output_path = root.join("other-archive");
    request.policy = ScopePolicy {
        revision: "review-other-scope/v1".into(),
        archive_binary: false,
        rules: vec![ScopeRule {
            path_prefix: "reference.md".into(),
            included: false,
            rule_id: "omit-fixture".into(),
            origin: "independent-review".into(),
            reason: "second legitimate index identity".into(),
        }],
    };
    source::capture(&request).unwrap();
    let other_source = artifact::reference(
        &writer,
        &root,
        &request.output_path.join(source::LEDGER_FILE),
    )
    .unwrap();
    let other_index_ref = index::build(&writer, &root, &other_source, &[]).unwrap();
    let reader = CallContext::restricted(
        TransportKind::Test,
        vec![root.clone()],
        EffectPolicy::ReadOnly,
    )
    .unwrap();
    fs::rename(repo, base.join("original-source-moved")).unwrap();
    Fixture {
        _temp: temp,
        root,
        reader,
        index_ref,
        other_index_ref,
        manifest,
    }
}
fn payload(f: &Fixture, text: &str, policy: &str) -> QueryPayload {
    serde_json::from_value(json!({"payload_revision":PAYLOAD_REVISION,"workspace_root":f.root,"index_ref":f.index_ref,"query":text,"query_policy":policy,"max_results":1,"max_tokens":8000,"continuation":null})).unwrap()
}
fn run(f: &Fixture, p: &QueryPayload) -> Value {
    query::search(&f.reader, p).expect("generic valid query must return a bounded receipt")
}
fn n(v: &Value, key: &str) -> u64 {
    v[key].as_u64().expect("required numeric receipt field")
}
fn hits(v: &Value) -> &[Value] {
    v["evidence"].as_array().unwrap()
}
fn cursor(v: &Value) -> String {
    v["continuation"]
        .as_str()
        .expect("fixture must retain a next page")
        .into()
}
fn rejected(f: &Fixture, p: &QueryPayload, reason: &str) {
    assert!(query::search(&f.reader, p).is_err(), "{reason}");
}
fn state(token: &str) -> Value {
    serde_json::from_slice(&hex::decode(token.split_once('.').unwrap().0).unwrap()).unwrap()
}
/// Only the isolated fixture's own authority signs controlled exhausted state.
/// This checks persisted budget transitions, not an HMAC/security bypass.
fn signed(f: &Fixture, s: &Value) -> String {
    let authority: Value = serde_json::from_slice(
        &fs::read(f.root.join(".gtkg/qk/runtime/query-authority.json")).unwrap(),
    )
    .unwrap();
    let key = hex::decode(authority["key"].as_str().unwrap()).unwrap();
    let bytes = serde_json::to_vec(s).unwrap();
    let mut mac = Hmac::<Sha256>::new_from_slice(&key).unwrap();
    mac.update(&bytes);
    format!(
        "{}.{}",
        hex::encode(bytes),
        hex::encode(mac.finalize().into_bytes())
    )
}
fn source_exact(f: &Fixture, hit: &Value) {
    assert_eq!(hit["source_span_verified"], true);
    let raw = fs::read(
        f.root
            .join(&f.manifest.archive_root)
            .join("objects")
            .join(hit["object_sha"].as_str().unwrap()),
    )
    .unwrap();
    let a = n(hit, "byte_start") as usize;
    let b = n(hit, "byte_end") as usize;
    assert_eq!(&raw[a..b], hit["text"].as_str().unwrap().as_bytes());
    assert_eq!(
        raw[..a].iter().filter(|x| **x == b'\n').count() + 1,
        n(hit, "line_start") as usize
    );
    assert_eq!(
        raw[..b - 1].iter().filter(|x| **x == b'\n').count() + 1,
        n(hit, "line_end") as usize
    );
    assert_eq!(
        hit["file_sha"],
        artifact::digest(&raw).strip_prefix("sha256:").unwrap()
    );
}
fn bounds(v: &Value) {
    let scan = &v["scanned"];
    for k in ["candidates", "ranked_candidates", "evaluated_candidates"] {
        assert!(
            n(scan, k) <= 2000,
            "actual candidate counter exceeded cap: {k}"
        );
    }
    assert!(n(scan, "postings") <= 100000);
    assert!(n(scan, "posting_ids_observed") <= n(scan, "postings"));
    assert!(n(scan, "eligible_ids") <= n(scan, "posting_ids_observed"));
    assert_eq!(
        n(scan, "filtered_ids") + n(scan, "eligible_ids"),
        n(scan, "posting_ids_observed")
    );
    assert!(n(scan, "candidates") <= n(scan, "eligible_ids"));
    assert_eq!(v["source_fallback"], false);
    assert_eq!(v["target_execution"], false);
    if n(&v["budget"], "io_bytes") > n(&v["budget"], "io_limit") {
        assert_eq!(v["budget"]["mandatory_header_overrun"], true);
        assert!(hits(v).is_empty());
    }
}
fn tamper(f: &Fixture, p: &QueryPayload, relative: &str) {
    let path = f.root.join(relative);
    let old = fs::read(&path).unwrap();
    let mut altered = old.clone();
    let at = altered.len() / 2;
    altered[at] ^= 1;
    fs::write(&path, &altered).unwrap();
    let denied = query::search(&f.reader, p).is_err();
    fs::write(path, old).unwrap();
    assert!(denied, "selected artifact/source tamper must be rejected");
}

#[test]
fn independent_selective_groups_identity_source_and_cumulative_limits() {
    let f = fixture();
    let manifest_before = fs::read(f.root.join(&f.index_ref.path)).unwrap();
    let authority_path = f.root.join(".gtkg/qk/runtime/query-authority.json");
    let authority_before = fs::read(&authority_path).unwrap();
    assert_eq!(f.manifest.query_policy, index::QUERY_POLICY);
    let p = payload(&f, "Aster Beryl", V2);
    let selected = run(&f, &p);
    eprintln!(
        "selective diagnostic: status={}, reason={}, io={}/{}, wall_us={}, observed={}, eligible={}, candidates={}, hits={}",
        selected["status"],
        selected["truncation"]["reason"],
        selected["budget"]["io_bytes"],
        selected["budget"]["io_limit"],
        selected["budget"]["wall_time_us"],
        selected["scanned"]["posting_ids_observed"],
        selected["scanned"]["eligible_ids"],
        selected["scanned"]["candidates"],
        hits(&selected).len()
    );
    bounds(&selected);
    assert_eq!(selected["query_policy"], V2);
    assert_eq!(selected["index_projection_policy"], index::QUERY_POLICY);
    assert_eq!(selected["query_plan"]["revision"], "gtkg.qk.query-plan/v2");
    assert_eq!(
        selected["query_plan"]["candidate_selection"],
        "all_signal_groups"
    );
    assert_eq!(selected["ranking_complete"], true);
    assert_eq!(selected["status"], "complete");
    assert_eq!(selected["scanned"]["posting_ids_observed"], NOISE + 2);
    assert_eq!(selected["scanned"]["eligible_ids"], 2);
    assert_eq!(selected["scanned"]["filtered_ids"], NOISE);
    assert_eq!(selected["scanned"]["candidates"], 2);
    assert_eq!(hits(&selected).len(), 1);
    source_exact(&f, &hits(&selected)[0]);
    assert!(
        hits(&selected)[0]["text"]
            .as_str()
            .unwrap()
            .contains("aster BERYL")
    );
    // A disjoint nonempty group and a genuinely absent group both force an
    // explicit union. The missing signal must never masquerade as intersection.
    for (q, eligible) in [("Beryl Cobalt", 4), ("Beryl Absentlexeme", 2)] {
        let r = run(&f, &payload(&f, q, V2));
        bounds(&r);
        assert_eq!(r["query_plan"]["candidate_selection"], "union_fallback");
        assert_eq!(r["scanned"]["eligible_ids"], eligible);
        assert_eq!(r["scanned"]["filtered_ids"], 0);
        assert_eq!(r["ranking_complete"], true);
    }
    // Frozen candidates retain their cumulative posting/IO/time accounting;
    // broad fallback must not disguise eligible IDs as scored candidates.
    let broad_request = payload(&f, "Aster Absentlexeme", V2);
    let broad = run(&f, &broad_request);
    eprintln!(
        "broad diagnostic: status={}, reason={}, io={}/{}, wall_us={}, observed={}, eligible={}, candidates={}, hits={}",
        broad["status"],
        broad["truncation"]["reason"],
        broad["budget"]["io_bytes"],
        broad["budget"]["io_limit"],
        broad["budget"]["wall_time_us"],
        broad["scanned"]["posting_ids_observed"],
        broad["scanned"]["eligible_ids"],
        broad["scanned"]["candidates"],
        hits(&broad).len()
    );
    bounds(&broad);
    assert_eq!(broad["query_plan"]["candidate_selection"], "union_fallback");
    assert_eq!(broad["scanned"]["eligible_ids"], NOISE + 2);
    assert_eq!(broad["scanned"]["candidates"], 2000);
    assert_eq!(broad["ranking_complete"], false);
    assert_eq!(broad["status"], "partial");
    assert_eq!(
        broad["ranking_scope"],
        "observed_candidates_provisional_scores"
    );
    let mut next_broad = broad_request.clone();
    next_broad.continuation = Some(cursor(&broad));
    let broad_again = run(&f, &next_broad);
    bounds(&broad_again);
    for key in [
        "postings",
        "posting_ids_observed",
        "eligible_ids",
        "filtered_ids",
        "candidates",
    ] {
        assert_eq!(
            broad_again["scanned"][key], broad["scanned"][key],
            "continuation restarted preselection/admission"
        );
    }
    assert_eq!(broad_again["ranking_complete"], false);
    for key in ["io_bytes", "wall_time_us"] {
        assert!(n(&broad_again["budget"], key) >= n(&broad["budget"], key));
    }
    // Small eligible set makes positive clean second-page and tamper controls
    // affordable. No original source directory remains available to the reader.
    let rare = payload(&f, "Beryl", V2);
    let first = run(&f, &rare);
    let mut resumed = rare.clone();
    resumed.continuation = Some(cursor(&first));
    let second = run(&f, &resumed);
    assert_eq!(
        hits(&second).len(),
        1,
        "positive control requires actual second source evidence"
    );
    let mut ids = BTreeSet::new();
    for page in [&first, &second] {
        bounds(page);
        for hit in hits(page) {
            source_exact(&f, hit);
            assert!(ids.insert(hit["id"].as_str().unwrap()));
        }
    }
    assert_eq!(ids.len(), 2);
    assert_eq!(second["continuation"], Value::Null);
    assert!(
        n(&second["budget"], "io_bytes")
            >= n(&first["budget"], "io_bytes")
                + n(&second["budget"], "manifest_bytes_this_call")
                + n(&second["budget"], "authority_bytes_this_call")
    );
    assert!(n(&second["budget"], "wall_time_us") >= n(&first["budget"], "wall_time_us"));
    assert_eq!(second["scanned"], first["scanned"]);
    let object = format!(
        "{}/objects/{}",
        f.manifest.archive_root,
        hits(&second)[0]["object_sha"].as_str().unwrap()
    );
    tamper(&f, &resumed, &object);
    tamper(&f, &rare, &f.manifest.source_ref.path);
    let (chunk_ref, _) = index::lookup_chunk_ref(
        &f.reader,
        &f.root,
        &f.manifest,
        hits(&second)[0]["id"].as_str().unwrap(),
    )
    .unwrap();
    tamper(&f, &resumed, &chunk_ref.path);
    let posting_ref = f.manifest.router[&index::token_bucket("exact:Beryl")]
        .as_ref()
        .unwrap();
    tamper(&f, &rare, &posting_ref.path);
    let mut wrong = rare.clone();
    wrong.index_ref.sha256 = format!("sha256:{}", "0".repeat(64));
    rejected(&f, &wrong, "invalid index reference accepted");
    wrong = rare.clone();
    wrong.query_policy = "gtkg.qk.query/unknown".into();
    rejected(&f, &wrong, "unknown query policy accepted");
    // Same-length rehashed policy changes isolate compatibility from size/hash
    // failures. v2 execution on a claimed v2 projection is also unregistered.
    for projection in ["gtkg.qk.query/v9", V2] {
        let mut unknown = f.manifest.clone();
        unknown.query_policy = projection.into();
        let unknown_bytes = serde_json::to_vec_pretty(&unknown).unwrap();
        assert_eq!(unknown_bytes.len(), manifest_before.len());
        fs::write(f.root.join(&f.index_ref.path), &unknown_bytes).unwrap();
        wrong = rare.clone();
        wrong.index_ref.sha256 = artifact::digest(&unknown_bytes);
        let denied = query::search(&f.reader, &wrong).is_err();
        fs::write(f.root.join(&f.index_ref.path), &manifest_before).unwrap();
        assert!(denied, "unregistered query/materialization pair accepted");
    }
    wrong = resumed.clone();
    wrong.index_ref = f.other_index_ref.clone();
    rejected(&f, &wrong, "cross-index continuation accepted");
    wrong = resumed.clone();
    wrong.query_policy = index::QUERY_POLICY.into();
    rejected(&f, &wrong, "v2 continuation accepted by v1");
    let legacy = payload(&f, "Beryl", index::QUERY_POLICY);
    let legacy_first = run(&f, &legacy);
    assert_eq!(hits(&legacy_first).len(), 1);
    wrong = rare.clone();
    wrong.continuation = Some(cursor(&legacy_first));
    rejected(&f, &wrong, "v1 continuation accepted by v2");
    let original_state = state(&cursor(&broad));
    for kind in ["io", "wall_time", "postings"] {
        let mut injected = original_state.clone();
        if kind == "io" {
            injected["counts"]["io"] = broad["budget"]["io_limit"].clone();
        } else if kind == "wall_time" {
            injected["counts"]["elapsed_us"] = broad["budget"]["wall_time_limit_us"].clone();
        } else {
            injected["counts"]["postings"] = json!(100000);
        }
        let mut stopped = broad_request.clone();
        stopped.continuation = Some(signed(&f, &injected));
        let r = run(&f, &stopped);
        bounds(&r);
        assert_eq!(r["ranking_complete"], false);
        for key in [
            "posting_ids_observed",
            "eligible_ids",
            "filtered_ids",
            "candidates",
        ] {
            assert_eq!(r["scanned"][key], broad["scanned"][key]);
        }
        assert!(n(&r["budget"], "io_bytes") >= n(&injected["counts"], "io"));
        assert!(n(&r["budget"], "wall_time_us") >= n(&injected["counts"], "elapsed_us"));
        assert!(n(&r["scanned"], "postings") >= n(&injected["counts"], "postings"));
        if kind != "postings" {
            assert!(hits(&r).is_empty());
            assert_eq!(r["truncation"]["reason"], kind);
        }
    }
    assert_eq!(
        fs::read(f.root.join(&f.index_ref.path)).unwrap(),
        manifest_before
    );
    assert!(
        fs::read(authority_path).unwrap() == authority_before,
        "ReadOnly review query changed authority"
    );
    eprintln!(
        "independent selective controls passed: source_chunks={}, selective_eligible=2, fallback_eligible={}, actual_candidate_cap=2000, distinct_pages={}",
        f.manifest.total_chunks,
        NOISE + 2,
        ids.len()
    );
}
