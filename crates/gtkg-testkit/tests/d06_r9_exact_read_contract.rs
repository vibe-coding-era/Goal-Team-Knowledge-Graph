#![cfg(unix)]

use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use gtkg_protocol::{OperationId, OperationRequest};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tempfile::{TempDir, tempdir};

const CHILD_DEADLINE: Duration = Duration::from_millis(750);

#[test]
fn regular_config_and_current_cli_reads_bind_the_exact_file_bytes() {
    let fixture = ExactReadFixture::new();

    let config_bytes = fs::read(&fixture.config_path).expect("read regular config bytes");
    let config_sha256 = sha256_bytes(&config_bytes);
    let config = run_cli_bounded(
        &fixture.root,
        OperationRequest::new(
            OperationId::ConfigValidate,
            "r9-regular-config",
            json!({"config_path": fixture.config_path}),
        ),
        "regular config",
    );
    assert!(
        config.status.success(),
        "regular config child failed: {}",
        String::from_utf8_lossy(&config.stderr)
    );
    let config_response: Value =
        serde_json::from_slice(&config.stdout).expect("regular config JSON response");
    assert_eq!(config_response["status"], "completed");
    assert_eq!(config_response["result"]["valid"], true);
    assert_eq!(config_response["result"]["config_sha256"], config_sha256);

    let current_bytes = fs::read(&fixture.current_path).expect("read regular CURRENT bytes");
    let current_sha256 = sha256_bytes(&current_bytes);
    let current = run_cli_bounded(
        &fixture.root,
        OperationRequest::new(
            OperationId::CurrentGet,
            "r9-regular-current",
            json!({
                "current_path": fixture.current_path,
                "expected_current_sha256": current_sha256
            }),
        ),
        "regular CURRENT",
    );
    assert!(
        current.status.success(),
        "regular CURRENT child failed: {}",
        String::from_utf8_lossy(&current.stderr)
    );
    let current_response: Value =
        serde_json::from_slice(&current.stdout).expect("regular CURRENT JSON response");
    assert_eq!(current_response["status"], "completed");
    assert_eq!(current_response["result"]["current_sha256"], current_sha256);
    assert_eq!(
        current_response["result"]["current"]["deliverable_id"],
        "knowledge"
    );
    assert!(
        !fixture.root.join(".gtkg").exists(),
        "read-only exact reads must not create run state"
    );
}

#[test]
fn config_fifo_final_endpoint_quick_fails_without_hanging_the_cli() {
    let fixture = ExactReadFixture::new();
    let fifo = fixture.root.join("config.fifo");
    create_fifo(&fifo);

    let output = run_cli_bounded(
        &fixture.root,
        OperationRequest::new(
            OperationId::ConfigValidate,
            "r9-fifo-config",
            json!({"config_path": fifo}),
        ),
        "config FIFO final endpoint",
    );
    assert_non_regular_rejection(output, "config FIFO final endpoint");
}

#[test]
fn current_fifo_final_endpoint_quick_fails_without_hanging_the_cli() {
    let fixture = ExactReadFixture::new();
    let fifo = fixture.root.join("CURRENT.fifo");
    create_fifo(&fifo);

    let output = run_cli_bounded(
        &fixture.root,
        OperationRequest::new(
            OperationId::CurrentGet,
            "r9-fifo-current",
            json!({
                "current_path": fifo,
                "expected_current_sha256": sha256_bytes(b"caller-held-current-digest")
            }),
        ),
        "CURRENT FIFO final endpoint",
    );
    assert_non_regular_rejection(output, "CURRENT FIFO final endpoint");
}

struct ExactReadFixture {
    _temp: TempDir,
    root: PathBuf,
    config_path: PathBuf,
    current_path: PathBuf,
}

impl ExactReadFixture {
    fn new() -> Self {
        let temp = tempdir().expect("R9 exact-read fixture");
        let root = fs::canonicalize(temp.path()).expect("canonical fixture root");
        let workspace = root.join("workspace");
        let repository = root.join("repository");
        let catalog = root.join("catalog");
        for directory in [&workspace, &repository, &catalog] {
            fs::create_dir_all(directory).expect("fixture directory");
        }

        let config_path = root.join("gtkg-config.json");
        write_json(
            &config_path,
            &json!({
                "schema_version": "gtkg.config/v1",
                "workspace_root": workspace,
                "storage_model": "okf-and-ordinary-files",
                "database_backend": null,
                "repository_roots": [repository],
                "template_catalog_roots": [catalog],
                "node_endpoints": []
            }),
        );

        let current_path = root.join("CURRENT.json");
        write_json(
            &current_path,
            &json!({
                "schema_version": "gtkg.current/v1",
                "deliverable_id": "knowledge",
                "version": "0.1.0",
                "version_path": "versions/v0.1.0--111111111111",
                "tree_sha256": digest('1'),
                "manifest_sha256": digest('2')
            }),
        );

        Self {
            _temp: temp,
            root,
            config_path,
            current_path,
        }
    }
}

struct BoundedOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

fn run_cli_bounded(root: &Path, request: OperationRequest, label: &str) -> BoundedOutput {
    let binary = gtkg_binary();
    let mut child = Command::new(binary)
        .args([
            "op",
            request.operation_id.as_str(),
            "--request",
            "-",
            "--output",
            "json",
        ])
        .current_dir(root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|error| panic!("spawn gtkg for {label}: {error}"));
    serde_json::to_writer(child.stdin.as_mut().expect("CLI stdin"), &request)
        .expect("write CLI request");
    child
        .stdin
        .as_mut()
        .unwrap()
        .flush()
        .expect("flush CLI stdin");
    drop(child.stdin.take());

    let status = wait_bounded_or_kill_and_reap(&mut child, label);
    let mut stdout = Vec::new();
    child
        .stdout
        .take()
        .expect("CLI stdout")
        .read_to_end(&mut stdout)
        .expect("read CLI stdout");
    let mut stderr = Vec::new();
    child
        .stderr
        .take()
        .expect("CLI stderr")
        .read_to_end(&mut stderr)
        .expect("read CLI stderr");
    BoundedOutput {
        status,
        stdout,
        stderr,
    }
}

fn wait_bounded_or_kill_and_reap(child: &mut Child, label: &str) -> ExitStatus {
    let started = Instant::now();
    loop {
        if let Some(status) = child.try_wait().expect("poll gtkg child") {
            return status;
        }
        if started.elapsed() >= CHILD_DEADLINE {
            child
                .kill()
                .unwrap_or_else(|error| panic!("kill hung {label} child: {error}"));
            let killed = child
                .wait()
                .unwrap_or_else(|error| panic!("reap hung {label} child: {error}"));
            panic!(
                "{label} did not quick-fail within {CHILD_DEADLINE:?}; killed and reaped child with {killed}"
            );
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn assert_non_regular_rejection(output: BoundedOutput, label: &str) {
    assert!(
        output.status.success(),
        "{label} CLI process failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let response: Value = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("{label} JSON response: {error}"));
    assert_eq!(
        response["error"]["code"], "E_SYMLINK_REJECTED",
        "{label} must fail closed as a non-regular exact-read endpoint"
    );
    assert!(response.get("result").is_none(), "{label}");
}

fn create_fifo(path: &Path) {
    let status = Command::new("mkfifo")
        .arg(path)
        .status()
        .unwrap_or_else(|error| panic!("create controlled FIFO {}: {error}", path.display()));
    assert!(status.success(), "mkfifo failed for {}", path.display());
    let metadata = fs::symlink_metadata(path).expect("FIFO metadata");
    assert!(
        metadata.file_type().is_fifo(),
        "controlled endpoint is FIFO"
    );
}

fn gtkg_binary() -> PathBuf {
    if let Some(path) = std::env::var_os("GTKG_BIN") {
        let path = PathBuf::from(path);
        assert!(path.is_file(), "GTKG_BIN is not a file: {}", path.display());
        return path;
    }
    let path = workspace_root().join("target/debug/gtkg");
    assert!(path.is_file(), "build {} before this test", path.display());
    path
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

fn write_json(path: &Path, value: &Value) {
    fs::write(path, serde_json::to_vec_pretty(value).expect("JSON bytes")).expect("write JSON");
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn digest(fill: char) -> String {
    format!("sha256:{}", fill.to_string().repeat(64))
}
