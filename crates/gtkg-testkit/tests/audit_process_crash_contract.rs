use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

use gtkg_core::file_model::sha256_file;
use gtkg_core::{CallContext, Dispatcher, EffectPolicy, TransportKind};
use gtkg_protocol::{
    ErrorCode, NodeDescriptor, NodeTransport, OperationId, OperationRequest, ShardResult, WorkUnit,
    canonical_json_sha256,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tempfile::{TempDir, tempdir};

const TEST_FAULT_POINT_ENV: &str = "GTKG_TEST_FAULT_POINT";
const TEST_FAULT_READY_ENV: &str = "GTKG_TEST_FAULT_READY";
const TEST_CHILD_ROOT_ENV: &str = "GTKG_TEST_CHILD_ROOT";
const TEST_CHILD_REQUEST_ENV: &str = "GTKG_TEST_CHILD_REQUEST";
const TEST_CHILD_TRANSPORT_ENV: &str = "GTKG_TEST_CHILD_TRANSPORT";
const FEDERATION_RECEIPT_FAULT: &str = "federation.receipt.after_temp_sync_before_rename";
const ACCEPTED_SUMMARY_RECEIPT_FAULT: &str =
    "summary.accept.accepted_receipt.after_partial_temp_write";
const SOURCE_RECEIPT_FAULT: &str = "source.inspect.receipt.after_partial_temp_write";
const TEMPLATE_RECEIPT_FAULT: &str = "template.receipt.after_partial_temp_write";

#[test]
fn child_process_holds_writer_lock_until_sigkill() {
    let Some(lock_path) = std::env::var_os("GTKG_TEST_WRITER_LOCK") else {
        return;
    };
    let ready_path =
        PathBuf::from(std::env::var_os("GTKG_TEST_WRITER_READY").expect("child ready path"));
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(PathBuf::from(lock_path))
        .expect("child opens writer lock");
    file.lock().expect("child acquires OS advisory lock");
    fs::write(ready_path, b"locked").expect("child readiness marker");
    loop {
        thread::park_timeout(Duration::from_secs(1));
    }
}

#[test]
fn real_sigkill_releases_writer_lock_and_exact_request_can_replay() {
    let fixture = Fixture::new();
    let context = fixture.context();
    let receipts = inspect_and_validate(&fixture, &context);
    let request = plan_request(&fixture.workspace, &receipts, "crash-lock-plan", "20.0.0");
    let gtkg = fixture.workspace.join(".gtkg");
    fs::create_dir_all(&gtkg).expect("gtkg state directory");
    let lock = gtkg.join("writer.lock");
    let ready = fixture.root.join("writer-ready");
    let mut child = spawn_lock_holder(&lock, &ready);
    wait_until_ready(&mut child, &ready);

    let blocked = Dispatcher
        .execute(&context, request.clone())
        .expect_err("live advisory lock must exclude a second writer");
    assert_eq!(blocked.error.code, ErrorCode::InvalidState);

    child.kill().expect("SIGKILL lock holder");
    let status = child.wait().expect("reap lock holder");
    assert!(!status.success(), "child must have been killed");
    assert!(
        lock.is_file(),
        "lock inode may persist without owning a lock"
    );

    let replayed = Dispatcher
        .execute(&context, request)
        .expect("OS must release advisory lock when process dies");
    assert!(replayed.run_id.is_some());
}

#[test]
fn child_process_executes_receipt_fault_request() {
    let Some(request_path) = std::env::var_os(TEST_CHILD_REQUEST_ENV) else {
        return;
    };
    let root =
        PathBuf::from(std::env::var_os(TEST_CHILD_ROOT_ENV).expect("child authorized root path"));
    let transport = match std::env::var(TEST_CHILD_TRANSPORT_ENV).as_deref() {
        Ok("test") => TransportKind::Test,
        Ok("cli") => TransportKind::Cli,
        other => panic!("unsupported child transport: {other:?}"),
    };
    let context = CallContext::restricted(transport, vec![root], EffectPolicy::WorkspaceWrite)
        .expect("child context");
    let request: OperationRequest = serde_json::from_slice(
        &fs::read(PathBuf::from(request_path)).expect("child reads exact request"),
    )
    .expect("child request JSON");
    Dispatcher
        .execute(&context, request)
        .expect("child operation reaches the private fault point");
}

#[test]
fn federation_receipt_temp_sync_crash_exact_replay_is_durable() {
    let fixture = Fixture::new();
    let context = fixture.context();
    let request = federation_request(&fixture.workspace);
    let request_path = write_child_request(&fixture.root, "federation", &request);
    let ready = fixture.root.join("federation-receipt-fault-ready");
    let mut child = spawn_receipt_fault_child(
        &fixture.root,
        &request_path,
        &ready,
        FEDERATION_RECEIPT_FAULT,
        "test",
    );
    wait_until_fault_ready(&mut child, &ready, FEDERATION_RECEIPT_FAULT);
    sigkill_and_reap(&mut child);

    let replayed = Dispatcher
        .execute(&context, request)
        .expect("exact federation request must recover a synced pre-rename receipt temp");
    let final_path = replayed
        .evidence_refs
        .first()
        .map(PathBuf::from)
        .expect("federation receipt evidence path");
    assert_eq!(replayed.evidence_refs.len(), 1);
    assert_single_final_receipt(
        final_path.parent().expect("federation receipt directory"),
        &final_path,
    );
    let observed: Value =
        serde_json::from_slice(&fs::read(&final_path).expect("complete federation receipt bytes"))
            .expect("complete federation receipt JSON");
    assert_eq!(observed, replayed.result["receipt"]);
    assert_eq!(
        canonical_json_sha256(&observed).expect("federation receipt digest"),
        replayed.result["receipt_sha256"]
    );
}

#[test]
fn accepted_summary_receipt_mid_write_crash_exact_replay_is_durable() {
    let fixture = Fixture::new();
    let context = fixture.context();
    let pending = prepare_summary_accept(&fixture, &context);
    let request_path = write_child_request(&fixture.root, "accepted-summary", &pending.request);
    let ready = fixture.root.join("accepted-summary-receipt-fault-ready");
    let mut child = spawn_receipt_fault_child(
        &fixture.root,
        &request_path,
        &ready,
        ACCEPTED_SUMMARY_RECEIPT_FAULT,
        "test",
    );
    wait_until_fault_ready(&mut child, &ready, ACCEPTED_SUMMARY_RECEIPT_FAULT);
    sigkill_and_reap(&mut child);

    let replayed = Dispatcher
        .execute(&context, pending.request)
        .expect("exact summary.accept must recover an interrupted immutable receipt write");
    assert_eq!(replayed.result["accepted"], true);
    assert_eq!(replayed.result["accepted_summaries"], 1);
    assert_single_final_receipt(
        pending
            .receipt_path
            .parent()
            .expect("accepted receipt directory"),
        &pending.receipt_path,
    );
    let receipt: Value = serde_json::from_slice(
        &fs::read(&pending.receipt_path).expect("complete accepted-summary receipt bytes"),
    )
    .expect("complete accepted-summary receipt JSON");
    assert_eq!(receipt["schema_version"], "gtkg.accepted-summary/v1");
    assert_eq!(receipt["packet_id"], pending.packet_id);
    assert_eq!(
        receipt["candidate_sha256"],
        sha256_file(&pending.candidate_path).expect("candidate digest")
    );
    let receipt_sha256 = sha256_file(&pending.receipt_path).expect("receipt digest");
    let ledger = fs::read_to_string(pending.run_directory.join("acceptance-events.ndjson"))
        .expect("acceptance event ledger");
    let events = ledger.lines().collect::<Vec<_>>();
    assert_eq!(
        events.len(),
        1,
        "exact replay must append one acceptance event"
    );
    let event: Value = serde_json::from_str(events[0]).expect("acceptance event JSON");
    assert_eq!(event["packet_id"], pending.packet_id);
    assert_eq!(event["acceptance_receipt_sha256"], receipt_sha256);
}

#[test]
fn source_receipt_legacy_partial_final_is_quarantined_and_exactly_rebuilt() {
    let fixture = Fixture::new();
    let context = fixture.context();
    let request = source_inspect_request(&fixture, "crash-source-partial-final");
    let initial = Dispatcher
        .execute(&context, request.clone())
        .expect("initial source.inspect receipt");
    let final_path = PathBuf::from(
        initial
            .evidence_refs
            .first()
            .expect("source receipt evidence path"),
    );
    let expected = fs::read(&final_path).expect("complete source receipt");
    fs::write(&final_path, &expected[..expected.len() / 2])
        .expect("simulate legacy direct-final crash residue");

    let replayed = Dispatcher
        .execute(&context, request)
        .expect("invalid partial final must be quarantined and rebuilt from exact source locks");
    assert_eq!(fs::read(&final_path).expect("rebuilt receipt"), expected);
    assert_eq!(
        sha256_file(&final_path).expect("rebuilt receipt digest"),
        replayed.result["inspection_ref"]["sha256"]
    );
    assert_single_final_receipt(
        final_path.parent().expect("source receipt directory"),
        &final_path,
    );
}

#[test]
fn template_receipt_partial_temp_recovers_but_valid_conflicting_final_is_rejected() {
    let fixture = Fixture::new();
    let context = fixture.context();
    let request = template_resolve_request(&fixture, "crash-template-partial-temp");
    let initial = Dispatcher
        .execute(&context, request.clone())
        .expect("initial template.resolve receipt");
    let final_path = PathBuf::from(
        initial
            .evidence_refs
            .first()
            .expect("template receipt evidence path"),
    );
    let expected = fs::read(&final_path).expect("complete template receipt");
    fs::remove_file(&final_path).expect("simulate absent pre-publish final");
    let temporary = receipt_temporary_path(&final_path);
    write_synced(&temporary, &expected[..expected.len() / 2]);

    let replayed = Dispatcher
        .execute(&context, request.clone())
        .expect("partial template temp must be quarantined and exactly rebuilt");
    assert_eq!(fs::read(&final_path).expect("rebuilt receipt"), expected);
    assert_eq!(
        sha256_file(&final_path).expect("rebuilt receipt digest"),
        replayed.result["resolution_ref"]["sha256"]
    );
    assert!(!temporary.exists(), "partial temp must not survive replay");

    fs::write(&final_path, b"{}\n").expect("valid but conflicting immutable receipt");
    let rejected = Dispatcher
        .execute(&context, request)
        .expect_err("valid conflicting final receipt must fail closed");
    assert_eq!(rejected.error.code, ErrorCode::LockMismatch);
    assert_eq!(fs::read(&final_path).expect("conflict retained"), b"{}\n");
}

#[test]
fn receipt_fault_environment_is_inert_outside_test_transport() {
    let fixture = Fixture::new();
    let request = federation_request(&fixture.workspace);
    let request_path = write_child_request(&fixture.root, "federation-cli", &request);
    let ready = fixture.root.join("federation-cli-fault-ready");
    let mut child = spawn_receipt_fault_child(
        &fixture.root,
        &request_path,
        &ready,
        FEDERATION_RECEIPT_FAULT,
        "cli",
    );
    let status = wait_for_child_exit(&mut child, FEDERATION_RECEIPT_FAULT);
    assert!(status.success(), "non-Test child failed: {status}");
    assert!(
        !ready.exists(),
        "private fault environment must be ignored outside TransportKind::Test"
    );
}

#[test]
fn durable_receipt_writer_fault_matrix_never_writes_final_path_directly() {
    let core = Path::new(env!("CARGO_MANIFEST_DIR")).join("../gtkg-core/src");
    let cases = [
        (
            "source inspection receipt",
            "source.rs",
            "fn write_immutable_json",
            SOURCE_RECEIPT_FAULT,
        ),
        (
            "template receipt",
            "template.rs",
            "fn write_immutable_json",
            TEMPLATE_RECEIPT_FAULT,
        ),
        (
            "federation receipt",
            "node.rs",
            "fn write_immutable_json",
            FEDERATION_RECEIPT_FAULT,
        ),
        (
            "accepted-summary receipt",
            "pipeline.rs",
            "fn write_json_immutable",
            ACCEPTED_SUMMARY_RECEIPT_FAULT,
        ),
    ];
    let mut fault_points = std::collections::BTreeSet::new();
    for (label, module, signature, fault_point) in cases {
        assert!(
            fault_points.insert(fault_point),
            "fault matrix has duplicate point {fault_point}"
        );
        let source = fs::read_to_string(core.join(module)).expect("production module source");
        let function = rust_function_source(&source, signature);
        let compact = function
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect::<String>();
        assert!(
            !compact.contains(".create_new(true).open(path)")
                && !compact.contains(".create_new(true).open(&path)"),
            "{label} opens and writes its final receipt path directly; use a durable temp, sync, and atomic publish"
        );
    }
}

#[test]
fn exact_partial_plan_without_initial_event_bootstraps_after_revalidation() {
    let fixture = Fixture::new();
    let context = fixture.context();
    let receipts = inspect_and_validate(&fixture, &context);
    let request = plan_request(
        &fixture.workspace,
        &receipts,
        "partial-bootstrap-plan",
        "20.1.0",
    );
    let planned = Dispatcher
        .execute(&context, request.clone())
        .expect("initial plan");
    let run_id = planned.run_id.expect("run id");
    let run = fixture.workspace.join(".gtkg/runs").join(&run_id);
    fs::remove_file(run.join("events.ndjson")).expect("fault before initial event commit");
    fs::remove_file(run.join("state.json")).expect("state projection absent");

    let replayed = Dispatcher
        .execute(&context, request)
        .expect("exact partial run must bootstrap after receipt and lock revalidation");
    assert_eq!(replayed.run_id.as_deref(), Some(run_id.as_str()));
    assert_eq!(
        fs::read_to_string(run.join("events.ndjson"))
            .expect("rebuilt event ledger")
            .lines()
            .count(),
        1
    );
    let observed = execute_ok_run(
        &context,
        OperationId::RunGet,
        Some(&run_id),
        "partial-bootstrap-get",
        json!({"workspace_root": fixture.workspace}),
    );
    assert_eq!(observed.result["projected_stale"], false);
    assert_eq!(observed.result["state"]["state"], "planned");
}

#[test]
fn snapshot_and_restore_quarantine_request_staging_crash_residue() {
    let fixture = Fixture::new();
    let context = fixture.context();
    let finalized = finalize(&fixture, &context, "20.2.0");

    let snapshot_request_id = "crash-snapshot-create";
    let snapshot_staging = fixture.workspace.join(".gtkg/staging").join(format!(
        "snapshot-create-{}",
        request_digest_prefix(snapshot_request_id)
    ));
    fs::create_dir_all(&snapshot_staging).expect("snapshot crash staging");
    fs::write(snapshot_staging.join("partial"), b"crash residue").expect("snapshot residue");
    let snapshot = execute_ok_run(
        &context,
        OperationId::SnapshotCreate,
        None,
        snapshot_request_id,
        json!({
            "workspace_root": fixture.workspace,
            "bundle_path": finalized.bundle_path,
            "expected_bundle_tree_sha256": finalized.tree_digest,
            "snapshot_version": "20.2.0"
        }),
    );
    let snapshot_path = PathBuf::from(
        snapshot.result["snapshot_path"]
            .as_str()
            .expect("snapshot path"),
    );
    let snapshot_digest = snapshot.result["tree_digest"]
        .as_str()
        .expect("snapshot digest")
        .to_owned();
    assert!(!snapshot_staging.exists());
    assert!(!snapshot_path.join("partial").exists());

    let restore_request_id = "crash-snapshot-restore";
    let restore_staging = fixture.workspace.join(".gtkg/staging").join(format!(
        "snapshot-restore-{}",
        request_digest_prefix(restore_request_id)
    ));
    fs::create_dir_all(&restore_staging).expect("restore crash staging");
    fs::write(restore_staging.join("partial"), b"crash residue").expect("restore residue");
    let restored = execute_ok_run(
        &context,
        OperationId::SnapshotRestore,
        None,
        restore_request_id,
        json!({
            "workspace_root": fixture.workspace,
            "snapshot_path": snapshot_path,
            "expected_snapshot_tree_sha256": snapshot_digest,
            "restore_version": "20.2.0"
        }),
    );
    let restored_path = PathBuf::from(
        restored.result["restored_path"]
            .as_str()
            .expect("restored path"),
    );
    assert!(!restore_staging.exists());
    assert!(!restored_path.join("partial").exists());
    let quarantine = fixture.workspace.join(".gtkg/quarantine");
    let quarantined = fs::read_dir(quarantine)
        .expect("quarantine")
        .map(|entry| entry.expect("quarantine entry").file_name())
        .collect::<Vec<_>>();
    assert!(quarantined.len() >= 2);
}

struct Fixture {
    _temp: TempDir,
    root: PathBuf,
    workspace: PathBuf,
    repository: PathBuf,
    catalog: PathBuf,
}

struct Receipts {
    source: Value,
    template: Value,
}

struct Finalized {
    bundle_path: PathBuf,
    tree_digest: String,
}

struct PendingSummaryAccept {
    request: OperationRequest,
    run_directory: PathBuf,
    packet_id: String,
    candidate_path: PathBuf,
    receipt_path: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let temp = tempdir().expect("tempdir");
        let root = temp.path().to_path_buf();
        let workspace = root.join("workspace");
        let repository = root.join("repo");
        let catalog = root.join("catalog");
        fs::create_dir_all(&workspace).expect("workspace");
        fs::create_dir_all(&repository).expect("repository");
        fs::write(repository.join("README.md"), "crash fixture\n").expect("source");
        git(&repository, &["init"]);
        git(&repository, &["config", "user.name", "GTKG Fixture"]);
        git(
            &repository,
            &["config", "user.email", "fixture@invalid.example"],
        );
        git(&repository, &["add", "-A"]);
        git(&repository, &["commit", "-m", "fixture"]);
        create_template_catalog(&catalog);
        Self {
            _temp: temp,
            root,
            workspace,
            repository,
            catalog,
        }
    }

    fn context(&self) -> CallContext {
        CallContext::restricted(
            TransportKind::Test,
            vec![self.root.clone()],
            EffectPolicy::WorkspaceWrite,
        )
        .expect("context")
    }
}

fn spawn_lock_holder(lock: &Path, ready: &Path) -> Child {
    Command::new(std::env::current_exe().expect("current test executable"))
        .arg("--exact")
        .arg("child_process_holds_writer_lock_until_sigkill")
        .arg("--nocapture")
        .env("GTKG_TEST_WRITER_LOCK", lock)
        .env("GTKG_TEST_WRITER_READY", ready)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn lock holder")
}

fn spawn_receipt_fault_child(
    root: &Path,
    request_path: &Path,
    ready: &Path,
    fault_point: &str,
    transport: &str,
) -> Child {
    Command::new(std::env::current_exe().expect("current test executable"))
        .arg("--exact")
        .arg("child_process_executes_receipt_fault_request")
        .arg("--nocapture")
        .env(TEST_CHILD_ROOT_ENV, root)
        .env(TEST_CHILD_REQUEST_ENV, request_path)
        .env(TEST_CHILD_TRANSPORT_ENV, transport)
        .env(TEST_FAULT_POINT_ENV, fault_point)
        .env(TEST_FAULT_READY_ENV, ready)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn receipt fault child")
}

fn wait_until_ready(child: &mut Child, ready: &Path) {
    for _ in 0..200 {
        assert!(
            child.try_wait().expect("poll child").is_none(),
            "lock holder exited before readiness"
        );
        if ready.is_file() {
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("lock holder did not become ready");
}

fn wait_until_fault_ready(child: &mut Child, ready: &Path, fault_point: &str) {
    for _ in 0..300 {
        if let Some(status) = child.try_wait().expect("poll fault child") {
            panic!(
                "child exited before fault readiness at {fault_point}: {status}; the private TransportKind::Test fault hook is missing or misplaced"
            );
        }
        if ready.is_file() {
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
    let _ = child.kill();
    let _ = child.wait();
    panic!("child did not reach fault point {fault_point}");
}

fn wait_for_child_exit(child: &mut Child, fault_point: &str) -> std::process::ExitStatus {
    for _ in 0..300 {
        if let Some(status) = child.try_wait().expect("poll non-Test fault child") {
            return status;
        }
        thread::sleep(Duration::from_millis(10));
    }
    let _ = child.kill();
    let status = child.wait().expect("reap hung non-Test fault child");
    panic!(
        "fault point {fault_point} activated outside TransportKind::Test; killed child with {status}"
    );
}

fn sigkill_and_reap(child: &mut Child) {
    child.kill().expect("SIGKILL fault child");
    let status = child.wait().expect("reap fault child");
    assert!(!status.success(), "fault child must have been killed");
}

fn write_child_request(root: &Path, label: &str, request: &OperationRequest) -> PathBuf {
    let path = root.join(format!("{label}-request.json"));
    fs::write(
        &path,
        serde_json::to_vec_pretty(request).expect("request JSON bytes"),
    )
    .expect("write exact child request");
    path
}

fn receipt_temporary_path(final_path: &Path) -> PathBuf {
    let file_name = final_path
        .file_name()
        .and_then(|value| value.to_str())
        .expect("UTF-8 receipt filename");
    final_path.with_file_name(format!(".{file_name}.receipt.tmp"))
}

fn write_synced(path: &Path, bytes: &[u8]) {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .expect("create crash residue");
    use std::io::Write as _;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .expect("sync crash residue");
}

fn assert_single_final_receipt(directory: &Path, final_path: &Path) {
    assert!(final_path.is_file(), "final receipt is missing");
    let mut entries = fs::read_dir(directory)
        .expect("receipt directory")
        .map(|entry| entry.expect("receipt entry").file_name())
        .collect::<Vec<_>>();
    entries.sort();
    assert_eq!(
        entries,
        vec![
            final_path
                .file_name()
                .expect("final receipt filename")
                .to_owned()
        ],
        "replay must leave one final receipt and no temporary residue"
    );
}

fn rust_function_source<'a>(source: &'a str, signature: &str) -> &'a str {
    let start = source
        .find(signature)
        .unwrap_or_else(|| panic!("missing production function {signature}"));
    let open = source[start..]
        .find('{')
        .map(|offset| start + offset)
        .unwrap_or_else(|| panic!("function {signature} has no body"));
    let mut depth = 0usize;
    for (offset, character) in source[open..].char_indices() {
        match character {
            '{' => depth += 1,
            '}' => {
                depth = depth
                    .checked_sub(1)
                    .unwrap_or_else(|| panic!("unbalanced function body for {signature}"));
                if depth == 0 {
                    return &source[start..open + offset + character.len_utf8()];
                }
            }
            _ => {}
        }
    }
    panic!("unterminated production function {signature}");
}

fn federation_request(workspace: &Path) -> OperationRequest {
    let executable = std::env::current_exe().expect("test executable");
    let node = NodeDescriptor {
        schema_version: "gtkg.node/v1".to_owned(),
        node_id: "worker-crash".to_owned(),
        logical_address: "local://worker-crash".to_owned(),
        transport: NodeTransport::Exec,
        endpoint: executable.to_string_lossy().into_owned(),
        binary_sha256: repeated_digest('a'),
        source_sha256: repeated_digest('b'),
        protocol_version: gtkg_protocol::PROTOCOL_VERSION.to_owned(),
        parser_sha256: repeated_digest('c'),
        sandbox_policy_sha256: repeated_digest('d'),
        platform: std::env::consts::OS.to_owned(),
        capabilities: vec!["static_extract".to_owned()],
        max_parallel: 1,
        work_unit_kinds: vec!["static_extract".to_owned()],
    };
    let work = WorkUnit::new(
        "static_extract",
        repeated_digest('e'),
        repeated_digest('f'),
        json!({"source_path": "README.md"}),
    )
    .expect("work unit");
    let result = ShardResult::new(&work, "worker-crash", 1, json!({"text": "durable"}))
        .expect("shard result");
    OperationRequest::new(
        OperationId::FederationValidate,
        "crash-federation-receipt",
        json!({
            "nodes": [node],
            "work_units": [work],
            "shard_results": [result],
            "workspace_root": workspace
        }),
    )
}

fn source_inspect_request(fixture: &Fixture, request_id: &str) -> OperationRequest {
    OperationRequest::new(
        OperationId::SourceInspect,
        request_id,
        json!({
            "workspace_root": fixture.workspace,
            "repositories": [{
                "repo_id": "repo-a",
                "path": fixture.repository,
                "role": "docs",
                "include": []
            }]
        }),
    )
}

fn template_resolve_request(fixture: &Fixture, request_id: &str) -> OperationRequest {
    OperationRequest::new(
        OperationId::TemplateResolve,
        request_id,
        json!({
            "workspace_root": fixture.workspace,
            "catalog_root": fixture.catalog,
            "template_id": "summary-template",
            "version": "0.1.0"
        }),
    )
}

fn repeated_digest(character: char) -> String {
    format!("sha256:{}", character.to_string().repeat(64))
}

fn prepare_summary_accept(fixture: &Fixture, context: &CallContext) -> PendingSummaryAccept {
    let receipts = inspect_and_validate(fixture, context);
    let planned = Dispatcher
        .execute(
            context,
            plan_request(
                &fixture.workspace,
                &receipts,
                "crash-accepted-receipt-plan",
                "20.3.0",
            ),
        )
        .expect("build.plan");
    let run_id = planned.run_id.expect("run id");
    execute_ok_run(
        context,
        OperationId::BuildPrepare,
        Some(&run_id),
        "crash-accepted-receipt-prepare",
        json!({"workspace_root": fixture.workspace}),
    );
    let next = execute_ok_run(
        context,
        OperationId::SummaryNext,
        Some(&run_id),
        "crash-accepted-receipt-next",
        json!({"workspace_root": fixture.workspace}),
    );
    let job = &next.result["job"];
    let packet_id = job["packet_id"].as_str().expect("packet id").to_owned();
    let mut request = OperationRequest::new(
        OperationId::SummaryAccept,
        "crash-accepted-receipt",
        json!({
            "workspace_root": fixture.workspace,
            "packet_id": packet_id,
            "source_sha256": job["source_sha256"],
            "template_manifest_sha256": job["template_manifest_sha256"],
            "summary_markdown": "durable accepted summary"
        }),
    );
    request.run_id = Some(run_id.clone());
    let run_directory = fixture.workspace.join(".gtkg/runs").join(run_id);
    PendingSummaryAccept {
        request,
        candidate_path: run_directory
            .join("candidates")
            .join(format!("{packet_id}.json")),
        receipt_path: run_directory
            .join("accepted")
            .join(format!("{packet_id}.json")),
        run_directory,
        packet_id,
    }
}

fn finalize(fixture: &Fixture, context: &CallContext, version: &str) -> Finalized {
    let receipts = inspect_and_validate(fixture, context);
    let planned = Dispatcher
        .execute(
            context,
            plan_request(
                &fixture.workspace,
                &receipts,
                "crash-finalize-plan",
                version,
            ),
        )
        .expect("build.plan");
    let run_id = planned.run_id.expect("run id");
    execute_ok_run(
        context,
        OperationId::BuildPrepare,
        Some(&run_id),
        "crash-build-prepare",
        json!({"workspace_root": fixture.workspace}),
    );
    let next = execute_ok_run(
        context,
        OperationId::SummaryNext,
        Some(&run_id),
        "crash-summary-next",
        json!({"workspace_root": fixture.workspace}),
    );
    let job = &next.result["job"];
    execute_ok_run(
        context,
        OperationId::SummaryAccept,
        Some(&run_id),
        "crash-summary-accept",
        json!({
            "workspace_root": fixture.workspace,
            "packet_id": job["packet_id"],
            "source_sha256": job["source_sha256"],
            "template_manifest_sha256": job["template_manifest_sha256"],
            "summary_markdown": "crash-safe accepted summary"
        }),
    );
    let response = execute_ok_run(
        context,
        OperationId::BuildFinalize,
        Some(&run_id),
        "crash-build-finalize",
        json!({"workspace_root": fixture.workspace}),
    );
    Finalized {
        bundle_path: PathBuf::from(
            response.result["bundle_path"]
                .as_str()
                .expect("bundle path"),
        ),
        tree_digest: response.result["tree_digest"]
            .as_str()
            .expect("tree digest")
            .to_owned(),
    }
}

fn inspect_and_validate(fixture: &Fixture, context: &CallContext) -> Receipts {
    let inspected = execute_ok_run(
        context,
        OperationId::SourceInspect,
        None,
        "crash-source-inspect",
        json!({
            "workspace_root": fixture.workspace,
            "repositories": [{
                "repo_id": "repo-a",
                "path": fixture.repository,
                "role": "docs",
                "include": []
            }]
        }),
    );
    let resolved = execute_ok_run(
        context,
        OperationId::TemplateResolve,
        None,
        "crash-template-resolve",
        json!({
            "workspace_root": fixture.workspace,
            "catalog_root": fixture.catalog,
            "template_id": "summary-template",
            "version": "0.1.0"
        }),
    );
    let validated = execute_ok_run(
        context,
        OperationId::TemplateValidate,
        None,
        "crash-template-validate",
        json!({
            "workspace_root": fixture.workspace,
            "resolution_ref": resolved.result["resolution_ref"]
        }),
    );
    Receipts {
        source: inspected.result["inspection_ref"].clone(),
        template: validated.result["validation_ref"].clone(),
    }
}

fn plan_request(
    workspace: &Path,
    receipts: &Receipts,
    request_id: &str,
    version: &str,
) -> OperationRequest {
    let mut request = OperationRequest::new(
        OperationId::BuildPlan,
        request_id,
        json!({
            "workspace_root": workspace,
            "mode": "full",
            "source_inspection_ref": receipts.source,
            "template_validation_ref": receipts.template,
            "baseline_bundle": null,
            "baseline_tree_sha256": null,
            "bundle_version": version
        }),
    );
    request.locks = BTreeMap::from([
        (
            "source_inspection".to_owned(),
            receipts.source["sha256"]
                .as_str()
                .expect("source receipt digest")
                .to_owned(),
        ),
        (
            "template_validation".to_owned(),
            receipts.template["sha256"]
                .as_str()
                .expect("template receipt digest")
                .to_owned(),
        ),
    ]);
    request
}

fn execute_ok_run(
    context: &CallContext,
    operation: OperationId,
    run_id: Option<&str>,
    request_id: &str,
    payload: Value,
) -> gtkg_protocol::OperationResponse {
    let mut request = OperationRequest::new(operation, request_id, payload);
    request.run_id = run_id.map(str::to_owned);
    Dispatcher
        .execute(context, request)
        .unwrap_or_else(|error| panic!("{} failed: {error:#?}", operation.as_str()))
}

fn request_digest_prefix(request_id: &str) -> String {
    hex::encode(Sha256::digest(request_id.as_bytes()))[..24].to_owned()
}

fn create_template_catalog(catalog: &Path) {
    let staging = catalog.join("summary-template/versions/staging");
    fs::create_dir_all(&staging).expect("template staging");
    let template = staging.join("template.md");
    fs::write(
        &template,
        "---\ntype: template\ntitle: Summary\ndescription: Crash fixture\nresource: ./template.md\ntags: [fixture]\ngenerated: false\nverified: false\nstatus: validated\nsources: []\nokf_version: '0.2'\ngtkg:\n  schema: gtkg.template/v1\n---\n\n# Summary\n",
    )
    .expect("template");
    let manifest = json!({
        "schema_version": "gtkg.template-manifest/v1",
        "template_id": "summary-template",
        "version": "0.1.0",
        "template_file": "template.md",
        "template_sha256": sha256_file(&template).expect("digest"),
        "slot_ids": ["summary"]
    });
    fs::write(
        staging.join("template-manifest.json"),
        serde_json::to_vec_pretty(&manifest).expect("manifest bytes"),
    )
    .expect("manifest");
    let digest = canonical_json_sha256(&manifest).expect("manifest digest");
    fs::rename(
        &staging,
        staging
            .parent()
            .expect("versions")
            .join(format!("v0.1.0--{}", &digest[7..19])),
    )
    .expect("publish template");
}

fn git(root: &Path, arguments: &[&str]) {
    let output = Command::new("/usr/bin/git")
        .arg("-C")
        .arg(root)
        .args(arguments)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .output()
        .expect("git");
    assert!(
        output.status.success(),
        "git {} failed: {}",
        arguments.join(" "),
        String::from_utf8_lossy(&output.stderr)
    );
}
