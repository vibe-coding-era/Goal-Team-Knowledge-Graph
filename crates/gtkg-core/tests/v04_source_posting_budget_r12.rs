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
fn both_source_policies_charge_the_last_admitted_row_before_exhaustion() {
    let f=fixture();
    for policy in ["gtkg.qk.query/v1", "gtkg.qk.query/v2"] {
        let p=payload(&f,"Cobalt",policy); let first=run(&f,&p);
        let mut s=state(&cursor(&first));
        // Controlled prior authenticated consumption in this isolated fixture.
        // No real run/cost claim is derived from signing this boundary state.
        s["counts"]["postings"]=json!(99999);
        s["counts"]["posting_ids_observed"]=json!(0);
        s["counts"]["eligible_ids"]=json!(0);
        s["counts"]["filtered_ids"]=json!(0);
        s["candidates"]=json!({}); s["considered_ids"]=json!([]);
        s["ranked"]=json!([]); s["ranking_complete"]=json!(false);
        s["term_index"]=json!(0);s["posting_offset"]=json!(0);
        s["evaluated"]=json!(0);s["page_offset"]=json!(0);
        s["expansion_done"]=json!(false);s["exhausted"]=Value::Null;
        let mut boundary=p.clone();boundary.continuation=Some(signed(&f,&s));
        let limited=run(&f,&boundary);
        assert_eq!(limited["status"],"partial");
        assert_eq!(limited["truncation"]["reason"],"postings");
        assert_eq!(limited["scanned"]["postings"],100000,"{policy}: admitted row must remain charged when the next row is refused");
        assert_eq!(limited["ranking_complete"],false);
        assert!(limited["budget"]["io_bytes"].as_u64().unwrap()>s["counts"]["io"].as_u64().unwrap());
        assert!(limited["evidence"].as_array().unwrap().is_empty());
    }
}
