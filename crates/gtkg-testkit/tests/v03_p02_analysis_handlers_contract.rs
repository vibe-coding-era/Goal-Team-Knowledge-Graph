//! P02 immutable contract: source snapshot -> adapter plan -> typed candidate
//! IR -> exact source verification, with only immutable local receipts.

use std::fs;
use std::path::{Path, PathBuf};

use gtkg_core::{CallContext, Dispatcher, EffectPolicy, TransportKind};
use gtkg_protocol::FileReceiptRef;
use gtkg_protocol::v2::{
    CallabilityV2, OperationAvailabilityV2, OperationRequestV2, V2_PUBLIC_OPERATIONS, V2ErrorCode,
    V2OperationId, v2_operation_definition, v2_operation_request_schema,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const P02_OPERATIONS: [V2OperationId; 3] = [
    V2OperationId::AnalysisPlan,
    V2OperationId::AnalysisBuild,
    V2OperationId::AnalysisVerify,
];

#[test]
fn p02_promotes_exactly_three_handlers_with_closed_adapter_payloads() {
    for operation_id in P02_OPERATIONS {
        let definition = v2_operation_definition(operation_id).unwrap();
        assert_eq!(
            definition.availability,
            OperationAvailabilityV2::Implemented
        );
        assert_eq!(definition.callability, CallabilityV2::Callable);
        let payload = &v2_operation_request_schema(operation_id)["properties"]["payload"];
        assert_eq!(payload["type"], "object");
        assert_eq!(payload["additionalProperties"], false);
    }
    let plan = v2_operation_request_schema(V2OperationId::AnalysisPlan);
    let plan_payload = &plan["properties"]["payload"];
    assert_eq!(
        string_set(&plan_payload["required"]),
        [
            "adapter_inputs",
            "source_root",
            "source_snapshot_ref",
            "workspace_root",
        ]
    );
    assert!(plan_payload.to_string().contains("codegraph"));
    assert!(plan_payload.to_string().contains("graphify"));
    assert!(plan_payload.to_string().contains("lsp_snapshot"));
    assert!(plan_payload.to_string().contains("native"));
    assert!(plan_payload.to_string().contains("scip"));

    assert_eq!(
        V2_PUBLIC_OPERATIONS
            .iter()
            .filter(|definition| definition.availability == OperationAvailabilityV2::Implemented)
            .count(),
        31
    );
    assert_eq!(
        v2_operation_definition(V2OperationId::BuildFinalizeV2)
            .unwrap()
            .availability,
        OperationAvailabilityV2::NotImplemented
    );
}

#[test]
fn p02_native_journey_is_deterministic_and_exact_source_verified() {
    let fixture = Fixture::new();
    let plan_request = fixture.native_plan_request("p02-native-plan");
    let plan = Dispatcher
        .execute_v2(
            &fixture.context(EffectPolicy::WorkspaceWrite),
            plan_request.clone(),
        )
        .unwrap();
    assert_eq!(plan.result["adapter_selection_count"], 2);
    assert_eq!(plan.result["target_execution_count"], 0);
    assert_eq!(plan.result["network_call_count"], 0);
    assert_eq!(plan.result["provider_call_count"], 0);
    assert_eq!(plan.result["canonical_write_count"], 0);
    let plan_ref = fixture.assert_receipt(&plan.result["plan_ref"]);

    let build_request = OperationRequestV2::new(
        "analysis.build",
        "p02-native-build",
        json!({"workspace_root": fixture.root(), "plan_ref": plan_ref}),
    );
    let build = Dispatcher
        .execute_v2(
            &fixture.context(EffectPolicy::WorkspaceWrite),
            build_request.clone(),
        )
        .unwrap();
    assert_eq!(build.result["adapter_run_count"], 2);
    assert!(build.result["admitted_count"].as_u64().unwrap() > 0);
    assert_eq!(build.result["target_execution_count"], 0);
    assert_eq!(build.result["network_call_count"], 0);
    assert_eq!(build.result["provider_call_count"], 0);
    assert_eq!(build.result["adapter_write_count"], 0);
    assert_eq!(build.result["canonical_write_count"], 0);
    let candidate_ref = fixture.assert_receipt(&build.result["candidate_ref"]);

    let verify_request = OperationRequestV2::new(
        "analysis.verify",
        "p02-native-verify",
        json!({"workspace_root": fixture.root(), "candidate_ref": candidate_ref}),
    );
    let verified = Dispatcher
        .execute_v2(
            &fixture.context(EffectPolicy::WorkspaceWrite),
            verify_request.clone(),
        )
        .unwrap();
    assert!(verified.result["resolved_verified_count"].as_u64().unwrap() > 0);
    assert_eq!(verified.result["false_confirmed"], 0);
    assert_eq!(verified.result["target_execution_count"], 0);
    assert_eq!(verified.result["network_call_count"], 0);
    assert_eq!(verified.result["provider_call_count"], 0);
    assert_eq!(verified.result["canonical_write_count"], 0);
    fixture.assert_receipt(&verified.result["verification_ref"]);

    let plan_replay = Dispatcher
        .execute_v2(&fixture.context(EffectPolicy::WorkspaceWrite), plan_request)
        .unwrap();
    let build_replay = Dispatcher
        .execute_v2(
            &fixture.context(EffectPolicy::WorkspaceWrite),
            build_request,
        )
        .unwrap();
    let verify_replay = Dispatcher
        .execute_v2(
            &fixture.context(EffectPolicy::WorkspaceWrite),
            verify_request,
        )
        .unwrap();
    assert_eq!(plan_replay.result, plan.result);
    assert_eq!(build_replay.result, build.result);
    assert_eq!(verify_replay.result, verified.result);
}

#[test]
fn p02_frozen_codegraph_remains_locator_only_after_verification() {
    let fixture = Fixture::new();
    let snapshot_sha256 = fixture.snapshot_exact_set_sha256();
    let codegraph = fixture
        .repo_root
        .join("crates/gtkg-testkit/fixtures/v03_a04/valid-codegraph.json");
    let plan = Dispatcher
        .execute_v2(
            &fixture.context(EffectPolicy::WorkspaceWrite),
            OperationRequestV2::new(
                "analysis.plan",
                "p02-codegraph-plan",
                json!({
                    "workspace_root": fixture.root(),
                    "source_root": fixture.source_root,
                    "source_snapshot_ref": fixture.snapshot_ref,
                    "adapter_inputs": [{
                        "adapter_kind": "codegraph",
                        "input_path": codegraph,
                        "pin": {
                            "file_sha256": "sha256:66b2bc48661dc6348c2930afc8e368c71a5dd5bdfb580c911c726d4fed70842b",
                            "schema_sha256": "sha256:b7a9743ee957d11268c5e1c2342c14d6071ae3a69ed1ed52ada0e6ab997fd1f0",
                            "tool_version": "0.20.1",
                            "tool_commit": "489ccf1612555510f8367e3e673181f6a1275fe4",
                            "tool_license": "Apache-2.0",
                            "source_snapshot_sha256": snapshot_sha256,
                            "max_file_bytes": 65536
                        }
                    }]
                }),
            ),
        )
        .unwrap();
    let plan_ref = fixture.assert_receipt(&plan.result["plan_ref"]);
    let build = Dispatcher
        .execute_v2(
            &fixture.context(EffectPolicy::WorkspaceWrite),
            OperationRequestV2::new(
                "analysis.build",
                "p02-codegraph-build",
                json!({"workspace_root": fixture.root(), "plan_ref": plan_ref}),
            ),
        )
        .unwrap();
    assert_eq!(build.result["adapter_run_count"], 1);
    assert_eq!(build.result["admitted_count"], 8);
    let candidate_ref = fixture.assert_receipt(&build.result["candidate_ref"]);
    let verified = Dispatcher
        .execute_v2(
            &fixture.context(EffectPolicy::WorkspaceWrite),
            OperationRequestV2::new(
                "analysis.verify",
                "p02-codegraph-verify",
                json!({"workspace_root": fixture.root(), "candidate_ref": candidate_ref}),
            ),
        )
        .unwrap();
    assert_eq!(verified.result["resolved_verified_count"], 0);
    assert_eq!(verified.result["locator_only_count"], 8);
    assert_eq!(verified.result["false_confirmed"], 0);
    assert_eq!(verified.result["canonical_write_count"], 0);
}

#[test]
fn p02_closed_effect_path_and_tamper_boundaries_fail_closed() {
    let fixture = Fixture::new();
    let mut invalid = fixture.native_plan_request("p02-unknown-field");
    invalid.payload["unexpected"] = Value::Bool(true);
    let error = Dispatcher
        .execute_v2(&fixture.context(EffectPolicy::WorkspaceWrite), invalid)
        .unwrap_err();
    assert_eq!(error.error.code, V2ErrorCode::InvalidRequest);
    assert_eq!(error.error.stage, "payload-schema");

    let denied = Dispatcher
        .execute_v2(
            &fixture.context(EffectPolicy::ReadOnly),
            fixture.native_plan_request("p02-read-only"),
        )
        .unwrap_err();
    assert_eq!(denied.error.code, V2ErrorCode::SideEffectDenied);

    let outside = tempfile::tempdir().unwrap();
    let escaped = Dispatcher
        .execute_v2(
            &fixture.context(EffectPolicy::WorkspaceWrite),
            OperationRequestV2::new(
                "analysis.plan",
                "p02-path-escape",
                json!({
                    "workspace_root": fixture.root(),
                    "source_root": outside.path(),
                    "source_snapshot_ref": fixture.snapshot_ref,
                    "adapter_inputs": [{"adapter_kind": "native", "logical_path": "lib.rs"}]
                }),
            ),
        )
        .unwrap_err();
    assert_eq!(escaped.error.code, V2ErrorCode::PathEscape);

    let plan = Dispatcher
        .execute_v2(
            &fixture.context(EffectPolicy::WorkspaceWrite),
            fixture.native_plan_request("p02-tamper-plan"),
        )
        .unwrap();
    let plan_ref = fixture.assert_receipt(&plan.result["plan_ref"]);
    let build = Dispatcher
        .execute_v2(
            &fixture.context(EffectPolicy::WorkspaceWrite),
            OperationRequestV2::new(
                "analysis.build",
                "p02-tamper-build",
                json!({"workspace_root": fixture.root(), "plan_ref": plan_ref}),
            ),
        )
        .unwrap();
    let candidate_ref = fixture.assert_receipt(&build.result["candidate_ref"]);
    let candidate_path = fixture.root().join(&candidate_ref.path);
    let mut tampered: Value = serde_json::from_slice(&fs::read(candidate_path).unwrap()).unwrap();
    tampered["adapter_runs"][0]["bundle"]["nodes"][0]["name"] = json!("tampered");
    let tampered_bytes = serde_json::to_vec_pretty(&tampered).unwrap();
    let tampered_path = fixture
        .root()
        .join(".gtkg/analysis/tampered-candidate.json");
    fs::create_dir_all(tampered_path.parent().unwrap()).unwrap();
    fs::write(&tampered_path, &tampered_bytes).unwrap();
    let tampered_error = Dispatcher
        .execute_v2(
            &fixture.context(EffectPolicy::WorkspaceWrite),
            OperationRequestV2::new(
                "analysis.verify",
                "p02-candidate-tamper",
                json!({
                    "workspace_root": fixture.root(),
                    "candidate_ref": {
                        "path": ".gtkg/analysis/tampered-candidate.json",
                        "sha256": sha256(&tampered_bytes)
                    }
                }),
            ),
        )
        .unwrap_err();
    assert!(matches!(
        tampered_error.error.code,
        V2ErrorCode::InvalidState | V2ErrorCode::BundleInvalid
    ));

    fs::write(fixture.source_root.join("lib.rs"), "fn changed() {}\n").unwrap();
    let changed = Dispatcher
        .execute_v2(
            &fixture.context(EffectPolicy::WorkspaceWrite),
            OperationRequestV2::new(
                "analysis.verify",
                "p02-source-drift",
                json!({"workspace_root": fixture.root(), "candidate_ref": candidate_ref}),
            ),
        )
        .unwrap_err();
    assert!(matches!(
        changed.error.code,
        V2ErrorCode::SourceChanged | V2ErrorCode::LockMismatch
    ));
}

struct Fixture {
    workspace: tempfile::TempDir,
    source_root: PathBuf,
    snapshot_ref: FileReceiptRef,
    repo_root: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let workspace = tempfile::tempdir().unwrap();
        let source_root = workspace.path().join("source");
        fs::create_dir(&source_root).unwrap();
        fs::write(
            source_root.join("lib.rs"),
            "fn main() { helper(); }\nfn helper() {}\n",
        )
        .unwrap();
        fs::write(
            source_root.join("utils.py"),
            "def helper():\n    return 1\n\ndef main():\n    return helper()\n",
        )
        .unwrap();
        let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .unwrap();
        let output = workspace
            .path()
            .join(".gtkg/source-snapshots/p02-source.json");
        let context = CallContext::restricted(
            TransportKind::Test,
            vec![workspace.path().to_path_buf(), repo_root.clone()],
            EffectPolicy::WorkspaceWrite,
        )
        .unwrap();
        let captured = Dispatcher
            .execute_v2(
                &context,
                OperationRequestV2::new(
                    "source.capture",
                    "p02-source-capture",
                    json!({
                        "capture_mode": "directory_exact",
                        "repository_id": "p02-fixture",
                        "source_root": source_root,
                        "output_path": output,
                    }),
                ),
            )
            .unwrap();
        let snapshot_ref = FileReceiptRef {
            path: ".gtkg/source-snapshots/p02-source.json".to_owned(),
            sha256: captured.result["snapshot_ref"]["artifact_sha256"]
                .as_str()
                .unwrap()
                .to_owned(),
        };
        Self {
            workspace,
            source_root,
            snapshot_ref,
            repo_root,
        }
    }

    fn root(&self) -> &Path {
        self.workspace.path()
    }

    fn context(&self, effect_policy: EffectPolicy) -> CallContext {
        CallContext::restricted(
            TransportKind::Test,
            vec![self.root().to_path_buf(), self.repo_root.clone()],
            effect_policy,
        )
        .unwrap()
    }

    fn native_plan_request(&self, request_id: &str) -> OperationRequestV2 {
        OperationRequestV2::new(
            "analysis.plan",
            request_id,
            json!({
                "workspace_root": self.root(),
                "source_root": self.source_root,
                "source_snapshot_ref": self.snapshot_ref,
                "adapter_inputs": [
                    {"adapter_kind": "native", "logical_path": "lib.rs"},
                    {"adapter_kind": "native", "logical_path": "utils.py"}
                ]
            }),
        )
    }

    fn snapshot_exact_set_sha256(&self) -> String {
        let value: Value =
            serde_json::from_slice(&fs::read(self.root().join(&self.snapshot_ref.path)).unwrap())
                .unwrap();
        value["exact_set_sha256"].as_str().unwrap().to_owned()
    }

    fn assert_receipt(&self, value: &Value) -> FileReceiptRef {
        let reference: FileReceiptRef = serde_json::from_value(value.clone()).unwrap();
        reference.validate().unwrap();
        let bytes = fs::read(self.root().join(&reference.path)).unwrap();
        assert_eq!(sha256(&bytes), reference.sha256);
        reference
    }
}

fn string_set(value: &Value) -> [&str; 4] {
    let mut values = value
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item.as_str().unwrap())
        .collect::<Vec<_>>();
    values.sort();
    values.try_into().unwrap()
}

fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}
