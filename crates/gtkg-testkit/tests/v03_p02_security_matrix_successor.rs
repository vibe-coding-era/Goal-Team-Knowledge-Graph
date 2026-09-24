//! P02 integration security denominator for effects, adapter inputs, duplicate
//! selections, immutable replay, temporary recovery, and no-clobber conflict.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Barrier};

use gtkg_core::{CallContext, Dispatcher, EffectPolicy, TransportKind};
use gtkg_protocol::FileReceiptRef;
use gtkg_protocol::v2::{OperationRequestV2, V2ErrorCode};
use serde_json::{Value, json};

#[test]
fn p02_all_three_operations_enforce_read_only_policy() {
    let fixture = Fixture::new();
    let plan = fixture.plan("p02-security-plan");
    let build = fixture.build("p02-security-build", plan.clone());
    let candidate: FileReceiptRef = serde_json::from_value(build["candidate_ref"].clone()).unwrap();
    for request in [
        fixture.plan_request("p02-readonly-plan"),
        OperationRequestV2::new(
            "analysis.build",
            "p02-readonly-build",
            json!({"workspace_root": fixture.root(), "plan_ref": plan}),
        ),
        OperationRequestV2::new(
            "analysis.verify",
            "p02-readonly-verify",
            json!({"workspace_root": fixture.root(), "candidate_ref": candidate}),
        ),
    ] {
        let error = Dispatcher
            .execute_v2(&fixture.context(EffectPolicy::ReadOnly), request)
            .unwrap_err();
        assert_eq!(error.error.code, V2ErrorCode::SideEffectDenied);
        assert_eq!(error.error.stage, "effect-policy");
    }
}

#[cfg(unix)]
#[test]
fn p02_rejects_symlink_hardlink_and_post_plan_input_drift() {
    use std::os::unix::fs::symlink;

    let fixture = Fixture::new();
    let input = fixture.copy_codegraph("codegraph.json");
    let link = fixture.root().join("codegraph-link.json");
    symlink(&input, &link).unwrap();
    assert_input_rejected(&fixture, &link);

    let private = fixture.copy_codegraph("codegraph-private.json");
    let hardlink = fixture.root().join("codegraph-hardlink.json");
    fs::hard_link(&private, &hardlink).unwrap();
    assert_input_rejected(&fixture, &hardlink);

    let drift = fixture.copy_codegraph("codegraph-drift.json");
    let plan = fixture.codegraph_plan("p02-drift-plan", &drift).unwrap();
    fs::write(&drift, b"{}\n").unwrap();
    let error = Dispatcher
        .execute_v2(
            &fixture.context(EffectPolicy::WorkspaceWrite),
            OperationRequestV2::new(
                "analysis.build",
                "p02-post-plan-drift",
                json!({"workspace_root": fixture.root(), "plan_ref": plan}),
            ),
        )
        .unwrap_err();
    assert!(matches!(
        error.error.code,
        V2ErrorCode::BundleInvalid | V2ErrorCode::SourceChanged | V2ErrorCode::Io
    ));
}

#[test]
fn p02_rejects_duplicate_selections_and_nested_unknown_pin_fields() {
    let fixture = Fixture::new();
    let duplicate = Dispatcher
        .execute_v2(
            &fixture.context(EffectPolicy::WorkspaceWrite),
            OperationRequestV2::new(
                "analysis.plan",
                "p02-duplicate",
                json!({
                    "workspace_root": fixture.root(),
                    "source_root": fixture.source_root,
                    "source_snapshot_ref": fixture.snapshot_ref,
                    "adapter_inputs": [
                        {"adapter_kind": "native", "logical_path": "lib.rs"},
                        {"adapter_kind": "native", "logical_path": "lib.rs"}
                    ]
                }),
            ),
        )
        .unwrap_err();
    assert_eq!(duplicate.error.code, V2ErrorCode::InvalidRequest);

    let input = fixture.copy_codegraph("codegraph-unknown.json");
    let mut payload = fixture.codegraph_payload(&input);
    payload["adapter_inputs"][0]["pin"]["unexpected"] = json!(true);
    let unknown = Dispatcher
        .execute_v2(
            &fixture.context(EffectPolicy::WorkspaceWrite),
            OperationRequestV2::new("analysis.plan", "p02-nested-unknown", payload),
        )
        .unwrap_err();
    assert_eq!(unknown.error.code, V2ErrorCode::InvalidRequest);
    assert_eq!(unknown.error.stage, "payload-schema");
}

#[test]
fn p02_semantic_replay_recovers_partial_temp_and_never_clobbers_conflict() {
    let fixture = Fixture::new();
    let first = Dispatcher
        .execute_v2(
            &fixture.context(EffectPolicy::WorkspaceWrite),
            fixture.plan_request("p02-replay-first"),
        )
        .unwrap();
    let second = Dispatcher
        .execute_v2(
            &fixture.context(EffectPolicy::WorkspaceWrite),
            fixture.plan_request("p02-replay-second"),
        )
        .unwrap();
    assert_eq!(first.result, second.result);
    let reference: FileReceiptRef =
        serde_json::from_value(first.result["plan_ref"].clone()).unwrap();
    let final_path = fixture.root().join(&reference.path);
    let file_name = final_path.file_name().unwrap().to_string_lossy();
    let temporary = final_path
        .parent()
        .unwrap()
        .join(format!(".{file_name}.receipt.tmp"));
    fs::write(&temporary, b"partial").unwrap();
    let recovered = Dispatcher
        .execute_v2(
            &fixture.context(EffectPolicy::WorkspaceWrite),
            fixture.plan_request("p02-replay-recover"),
        )
        .unwrap();
    assert_eq!(recovered.result, first.result);
    assert!(!temporary.exists());

    fs::remove_file(&final_path).unwrap();
    let conflict = b"{}";
    fs::write(&final_path, conflict).unwrap();
    let error = Dispatcher
        .execute_v2(
            &fixture.context(EffectPolicy::WorkspaceWrite),
            fixture.plan_request("p02-replay-conflict"),
        )
        .unwrap_err();
    assert_eq!(error.error.code, V2ErrorCode::InvalidState);
    assert_eq!(fs::read(&final_path).unwrap(), conflict);
}

#[test]
fn p02_concurrent_same_semantic_plan_converges_to_one_reference() {
    let fixture = Fixture::new();
    let barrier = Arc::new(Barrier::new(2));
    let results = std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for index in 0..2 {
            let barrier = barrier.clone();
            let context = fixture.context(EffectPolicy::WorkspaceWrite);
            let request = fixture.plan_request(&format!("p02-concurrent-{index}"));
            handles.push(scope.spawn(move || {
                barrier.wait();
                Dispatcher.execute_v2(&context, request)
            }));
        }
        handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>()
    });
    let first = results[0].as_ref().unwrap();
    let second = results[1].as_ref().unwrap();
    assert_eq!(first.result, second.result);
}

fn assert_input_rejected(fixture: &Fixture, path: &Path) {
    let error = fixture
        .codegraph_plan("p02-linked-input", path)
        .unwrap_err();
    assert!(matches!(
        error.error.code,
        V2ErrorCode::SymlinkRejected | V2ErrorCode::PathEscape
    ));
}

struct Fixture {
    workspace: tempfile::TempDir,
    source_root: PathBuf,
    snapshot_ref: FileReceiptRef,
    snapshot_exact_set: String,
}

impl Fixture {
    fn new() -> Self {
        let workspace = tempfile::tempdir().unwrap();
        let source_root = workspace.path().join("source");
        fs::create_dir(&source_root).unwrap();
        fs::write(source_root.join("lib.rs"), "fn stable() {}\n").unwrap();
        let output = workspace.path().join(".gtkg/source-snapshots/source.json");
        let context = CallContext::restricted(
            TransportKind::Test,
            vec![workspace.path().to_path_buf()],
            EffectPolicy::WorkspaceWrite,
        )
        .unwrap();
        let captured = Dispatcher
            .execute_v2(
                &context,
                OperationRequestV2::new(
                    "source.capture",
                    "p02-security-capture",
                    json!({
                        "capture_mode": "directory_exact",
                        "repository_id": "p02-security",
                        "source_root": source_root,
                        "output_path": output,
                    }),
                ),
            )
            .unwrap();
        Self {
            workspace,
            source_root,
            snapshot_ref: FileReceiptRef {
                path: ".gtkg/source-snapshots/source.json".to_owned(),
                sha256: captured.result["snapshot_ref"]["artifact_sha256"]
                    .as_str()
                    .unwrap()
                    .to_owned(),
            },
            snapshot_exact_set: captured.result["snapshot"]["exact_set_sha256"]
                .as_str()
                .unwrap()
                .to_owned(),
        }
    }

    fn root(&self) -> &Path {
        self.workspace.path()
    }

    fn context(&self, policy: EffectPolicy) -> CallContext {
        CallContext::restricted(TransportKind::Test, vec![self.root().to_path_buf()], policy)
            .unwrap()
    }

    fn plan_request(&self, request_id: &str) -> OperationRequestV2 {
        OperationRequestV2::new(
            "analysis.plan",
            request_id,
            json!({
                "workspace_root": self.root(),
                "source_root": self.source_root,
                "source_snapshot_ref": self.snapshot_ref,
                "adapter_inputs": [{"adapter_kind": "native", "logical_path": "lib.rs"}]
            }),
        )
    }

    fn plan(&self, request_id: &str) -> FileReceiptRef {
        serde_json::from_value(
            Dispatcher
                .execute_v2(
                    &self.context(EffectPolicy::WorkspaceWrite),
                    self.plan_request(request_id),
                )
                .unwrap()
                .result["plan_ref"]
                .clone(),
        )
        .unwrap()
    }

    fn build(&self, request_id: &str, plan_ref: FileReceiptRef) -> Value {
        Dispatcher
            .execute_v2(
                &self.context(EffectPolicy::WorkspaceWrite),
                OperationRequestV2::new(
                    "analysis.build",
                    request_id,
                    json!({"workspace_root": self.root(), "plan_ref": plan_ref}),
                ),
            )
            .unwrap()
            .result
    }

    fn copy_codegraph(&self, name: &str) -> PathBuf {
        let path = self.root().join(name);
        fs::write(
            &path,
            fs::read(
                Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/v03_a04/valid-codegraph.json"),
            )
            .unwrap(),
        )
        .unwrap();
        path
    }

    fn codegraph_payload(&self, input: &Path) -> Value {
        json!({
            "workspace_root": self.root(),
            "source_root": self.source_root,
            "source_snapshot_ref": self.snapshot_ref,
            "adapter_inputs": [{
                "adapter_kind": "codegraph",
                "input_path": input,
                "pin": {
                    "file_sha256": "sha256:66b2bc48661dc6348c2930afc8e368c71a5dd5bdfb580c911c726d4fed70842b",
                    "schema_sha256": "sha256:b7a9743ee957d11268c5e1c2342c14d6071ae3a69ed1ed52ada0e6ab997fd1f0",
                    "tool_version": "0.20.1",
                    "tool_commit": "489ccf1612555510f8367e3e673181f6a1275fe4",
                    "tool_license": "Apache-2.0",
                    "source_snapshot_sha256": self.snapshot_exact_set,
                    "max_file_bytes": 65536
                }
            }]
        })
    }

    fn codegraph_plan(
        &self,
        request_id: &str,
        input: &Path,
    ) -> Result<FileReceiptRef, gtkg_protocol::v2::V2ErrorEnvelope> {
        Dispatcher
            .execute_v2(
                &self.context(EffectPolicy::WorkspaceWrite),
                OperationRequestV2::new("analysis.plan", request_id, self.codegraph_payload(input)),
            )
            .map(|response| serde_json::from_value(response.result["plan_ref"].clone()).unwrap())
    }
}
