//! Independent generic partial-result review. No benchmark/gold/target-project input.
#![allow(clippy::unwrap_used)]
use gtkg_core::{CallContext, EffectPolicy, TransportKind};
use gtkg_core::v04::{artifact, index, query, source::{self, ScopePolicy, ScopeRule, SourceCaptureRequest}};
use gtkg_protocol::{FileReceiptRef, v04::{QueryPayload, PAYLOAD_REVISION}};
use hmac::{Hmac, Mac};
use serde_json::{Value, json};
use sha2::Sha256;
use std::{collections::BTreeSet, fs, io::Write, path::{Path, PathBuf}, process::{Command, Stdio}};

const MARKER: &str = "GENERIC_PARTIAL_WITNESS";
fn git(root: &Path, args: &[&str]) -> String {
    let output = Command::new("git").arg("-C").arg(root).args(args).output().unwrap();
    assert!(output.status.success(), "isolated fixture Git operation failed");
    String::from_utf8(output.stdout).unwrap().trim().into()
}
struct Fixture {
    _temp: tempfile::TempDir,
    root: PathBuf,
    reader: CallContext,
    index_ref: FileReceiptRef,
    other_index_ref: FileReceiptRef,
    manifest: index::IndexManifest,
}
fn fixture() -> Fixture {
    let temp = tempfile::tempdir().unwrap();
    let base = fs::canonicalize(temp.path()).unwrap();
    let repo = base.join("fixture-repo"); let root = base.join("fixture-workspace");
    fs::create_dir(&repo).unwrap(); fs::create_dir(&root).unwrap();
    git(&repo, &["init", "-q"]);
    let text = (0..2111).map(|i| {
        let words = (0..16).map(|j| format!("r{i:04x}t{j:x}")).collect::<Vec<_>>().join(" ");
        format!("# Unit {i}\n{MARKER} {words}\n\n")
    }).collect::<String>();
    // Only synthetic fixture objects are created; no project code is executed.
    let stream = format!("blob\nmark :1\ndata {}\n{}\ncommit refs/heads/main\ncommitter Fixture <fixture@example.invalid> 0 +0000\ndata 7\nfixture\nM 100644 :1 reference.md\n\n", text.len(), text);
    let mut child = Command::new("git").arg("-C").arg(&repo).args(["fast-import", "--quiet"]).stdin(Stdio::piped()).spawn().unwrap();
    child.stdin.take().unwrap().write_all(stream.as_bytes()).unwrap(); assert!(child.wait().unwrap().success());
    let commit = git(&repo, &["rev-parse", "main"]); let tree = git(&repo, &["rev-parse", "main^{tree}"]);
    let writer = CallContext::restricted(TransportKind::Test, vec![root.clone(), repo.clone()], EffectPolicy::WorkspaceWrite).unwrap();
    let mut request = SourceCaptureRequest {repository_id:"independent-partial-fixture".into(), source_root:repo.clone(), source_commit:commit,
        expected_tree:tree, output_path:root.join("archive"), policy:ScopePolicy::default()};
    source::capture(&request).unwrap();
    let source_ref = artifact::reference(&writer, &root, &request.output_path.join(source::LEDGER_FILE)).unwrap();
    let index_ref = index::build(&writer, &root, &source_ref, &[]).unwrap();
    let manifest = index::load_manifest(&writer, &root, &index_ref).unwrap();
    assert!(manifest.total_chunks > 2000);
    // A second legitimate index shares the same authority but has a different
    // source/scope identity. It is built, not an invented manifest reference.
    request.output_path = root.join("other-archive");
    request.policy = ScopePolicy {revision:"independent-empty-scope/v1".into(), archive_binary:false,
        rules:vec![ScopeRule {path_prefix:"reference.md".into(),included:false,rule_id:"excluded-fixture".into(),origin:"review-fixture".into(),reason:"independent second index scope".into()}]};
    source::capture(&request).unwrap();
    let other_source_ref = artifact::reference(&writer, &root, &request.output_path.join(source::LEDGER_FILE)).unwrap();
    let other_index_ref = index::build(&writer, &root, &other_source_ref, &[]).unwrap();
    assert_eq!(index::load_manifest(&writer, &root, &other_index_ref).unwrap().total_chunks, 0);
    let reader = CallContext::restricted(TransportKind::Test, vec![root.clone()], EffectPolicy::ReadOnly).unwrap();
    fs::rename(&repo, base.join("source-moved-away")).unwrap();
    Fixture {_temp:temp,root,reader,index_ref,other_index_ref,manifest}
}
fn payload(f: &Fixture) -> QueryPayload {
    serde_json::from_value(json!({"payload_revision":PAYLOAD_REVISION,"workspace_root":f.root,"index_ref":f.index_ref,
        "query":MARKER,"query_policy":index::QUERY_POLICY,"max_results":1,"max_tokens":8000,"continuation":null})).unwrap()
}
fn token_state(token: &str) -> Value {
    let (body, _) = token.split_once('.').unwrap();
    serde_json::from_slice(&hex::decode(body).unwrap()).unwrap()
}
fn cursor(result: &Value) -> String { result["continuation"].as_str().expect("partial discovery must remain explicitly incomplete").to_owned() }
fn hits(result: &Value) -> &[Value] { result["evidence"].as_array().unwrap() }
fn number(value: &Value, field: &str) -> u64 { value[field].as_u64().unwrap() }
fn assert_partial(result: &Value) {
    assert_eq!(result["status"], "partial");
    assert_eq!(result["ranking_complete"], false);
    assert_eq!(result["ranking_scope"], "observed_candidates_provisional_scores");
    assert_eq!(result["answerability"], "budget_exhausted");
    assert_eq!(result["source_fallback"], false);
    assert_eq!(result["target_execution"], false);
    assert_eq!(result["scanned"]["candidates"], 2000);
    assert!(result.get("knowledge_conflicts").is_none());
}
fn assert_hit_source(f: &Fixture, hit: &Value) {
    assert_eq!(hit["source_span_verified"], true);
    let raw = fs::read(f.root.join(&f.manifest.archive_root).join("objects").join(hit["object_sha"].as_str().unwrap())).unwrap();
    let begin = number(hit,"byte_start") as usize; let end = number(hit,"byte_end") as usize;
    assert_eq!(&raw[begin..end], hit["text"].as_str().unwrap().as_bytes());
    assert_eq!(raw[..begin].iter().filter(|c| **c == b'\n').count() + 1, number(hit,"line_start") as usize);
    assert_eq!(raw[..end-1].iter().filter(|c| **c == b'\n').count() + 1, number(hit,"line_end") as usize);
    assert_eq!(hit["file_sha"], artifact::digest(&raw).strip_prefix("sha256:").unwrap());
    assert!(hit["text"].as_str().unwrap().contains(MARKER));
}
/// Controlled exhausted-state injection uses only the authority created by this
/// fixture, never a user key. It tests budget transition logic, not HMAC bypass.
fn fixture_signed_state(f: &Fixture, state: &Value) -> String {
    let authority:Value = serde_json::from_slice(&fs::read(f.root.join(".gtkg/qk/runtime/query-authority.json")).unwrap()).unwrap();
    let key = hex::decode(authority["key"].as_str().unwrap()).unwrap();
    let bytes = serde_json::to_vec(state).unwrap();
    let mut mac = Hmac::<Sha256>::new_from_slice(&key).unwrap(); mac.update(&bytes);
    format!("{}.{}",hex::encode(bytes),hex::encode(mac.finalize().into_bytes()))
}
#[test]
fn independent_partial_paging_source_identity_and_cumulative_budget_controls() {
    let f = fixture(); let original = payload(&f);
    let authority_path = f.root.join(".gtkg/qk/runtime/query-authority.json");
    let authority_before = fs::read(&authority_path).unwrap();
    let first = query::search(&f.reader, &original).expect("generic fixture must yield a bounded first response");
    assert_partial(&first);
    assert_eq!(first["truncation"]["reason"], "candidates");
    assert_eq!(hits(&first).len(),1,"fixture must leave IO/time for observed evidence");
    assert_hit_source(&f,&hits(&first)[0]);
    let first_token = cursor(&first); let first_state = token_state(&first_token);
    assert_eq!(first_state["page_offset"],1);
    assert_eq!(first_state["counts"]["io"],first["budget"]["io_bytes"]);
    assert_eq!(first_state["counts"]["elapsed_us"],first["budget"]["wall_time_us"]);
    let mut resumed = original.clone(); resumed.continuation=Some(first_token.clone());
    let clean_next = query::search(&f.reader,&resumed).unwrap();
    assert_partial(&clean_next);
    eprintln!("partial fixture: first_io={}, second_io={}, io_limit={}, second_hits={}, second_reason={}", number(&first["budget"],"io_bytes"), number(&clean_next["budget"],"io_bytes"), number(&clean_next["budget"],"io_limit"), hits(&clean_next).len(), clean_next["truncation"]["reason"].as_str().unwrap_or("none"));
    assert!(!hits(&clean_next).is_empty(),"source-tamper control requires an affordable second source read");
    // Full-file source digest is rechecked even on an already authenticated
    // candidate cursor. Original repository access has already been removed.
    let object=f.root.join(&f.manifest.archive_root).join("objects").join(hits(&clean_next)[0]["object_sha"].as_str().unwrap());
    let bytes=fs::read(&object).unwrap();let mut altered=bytes.clone();altered[0]^=1;fs::write(&object,&altered).unwrap();
    assert!(query::search(&f.reader,&resumed).is_err(),"source tamper must not produce successful partial evidence");
    fs::write(&object,&bytes).unwrap();
    // The two index identities are both real and valid in the same workspace.
    let mut wrong=resumed.clone();wrong.index_ref=f.other_index_ref.clone();
    let error=match query::search(&f.reader,&wrong) {Err(error)=>error,Ok(_)=>panic!("cross-index continuation was accepted")};
    assert!(error.contains("identity mismatch"),"cross-index continuation must fail identity binding");
    // Paging continues only within the frozen observed candidate set.
    let mut seen=BTreeSet::new();let mut page=first.clone();let mut prior_io=0;let mut prior_time=0;let mut prior_offset=0;
    let scan_before=first["scanned"].clone();let mut pages=0;
    loop {
        assert_partial(&page);
        for field in ["term_count","current_posting_offset","postings","postings_scored","candidates","ranked_candidates"] {
            assert_eq!(page["scanned"][field],scan_before[field],"partial continuation restarted discovery");
        }
        let io=number(&page["budget"],"io_bytes");let wall=number(&page["budget"],"wall_time_us");
        assert!(io>=prior_io && wall>=prior_time,"cumulative IO/time counters regressed");
        if io>number(&page["budget"],"io_limit") {assert_eq!(page["budget"]["mandatory_header_overrun"],true);assert!(hits(&page).is_empty());}
        let state=token_state(&cursor(&page));let offset=number(&state,"page_offset");
        assert!(offset>=prior_offset);assert_eq!(offset as usize,seen.len()+hits(&page).len());
        for hit in hits(&page) {assert!(seen.insert(hit["id"].as_str().unwrap().to_owned()),"continuation repeated evidence ID");assert_hit_source(&f,hit);}
        if hits(&page).is_empty() || pages==7 {break;}
        prior_io=io;prior_time=wall;prior_offset=offset;pages+=1;
        let previous=page;resumed.continuation=Some(cursor(&previous));page=query::search(&f.reader,&resumed).unwrap();
        let mandatory=number(&page["budget"],"manifest_bytes_this_call")+number(&page["budget"],"authority_bytes_this_call");
        assert!(number(&page["budget"],"io_bytes")>=prior_io+mandatory,"resumed call omitted mandatory header IO");
    }
    assert!(seen.len()>=2,"two actual distinct pages are required");
    // Authenticated persisted exhaustion is terminal for optional evidence reads;
    // it does not mint a new budget or resume posting discovery.
    for budget_kind in ["io","wall_time"] {
        let mut state=first_state.clone();
        if budget_kind=="io" {state["counts"]["io"]=first["budget"]["io_limit"].clone();}
        else {state["counts"]["elapsed_us"]=first["budget"]["wall_time_limit_us"].clone();}
        let mut stopped=original.clone();stopped.continuation=Some(fixture_signed_state(&f,&state));
        let result=query::search(&f.reader,&stopped).unwrap();assert_partial(&result);assert!(hits(&result).is_empty());
        assert_eq!(result["truncation"]["reason"],budget_kind);
        assert_eq!(result["scanned"],scan_before);
        assert_eq!(result["verification_scope"]["source_object_reads"],state["counts"]["source_object_reads"]);
        assert_eq!(result["verification_scope"]["source_ledger_reads"],state["counts"]["source_ledger_reads"]);
        assert!(number(&result["budget"],"io_bytes")>=number(&state["counts"],"io"));
        assert!(number(&result["budget"],"wall_time_us")>=number(&state["counts"],"elapsed_us"));
        if budget_kind=="io" {assert_eq!(result["budget"]["mandatory_header_overrun"],true);}
        stopped.continuation=Some(cursor(&result));let again=query::search(&f.reader,&stopped).unwrap();
        assert!(hits(&again).is_empty());assert_partial(&again);
        assert_eq!(again["scanned"],scan_before);
        assert!(number(&again["budget"],"io_bytes")>=number(&result["budget"],"io_bytes"));
        assert!(number(&again["budget"],"wall_time_us")>=number(&result["budget"],"wall_time_us"));
    }
    assert!(fs::read(authority_path).unwrap()==authority_before,"ReadOnly partial queries mutated runtime authority");
    // Deliberately print only compact measurements, never response/cursor/key bytes.
    eprintln!("independent partial controls passed: distinct_evidence={}, pages_checked={}, candidate_denominator=2000",seen.len(),pages+1);
}
