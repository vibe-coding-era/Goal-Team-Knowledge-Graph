//! P02 immutable successor: strict SCIP/LSP/Graphify orchestration, critical
//! source join, and semantic-path/self-digest hardening.

use std::fs;
use std::path::{Path, PathBuf};

use gtkg_core::{CallContext, Dispatcher, EffectPolicy, TransportKind};
use gtkg_protocol::v2::{OperationRequestV2, V2ErrorCode};
use gtkg_protocol::{FileReceiptRef, canonical_json_sha256};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

#[test]
fn p02_scip_lsp_and_strict_graphify_preserve_their_trust_ceilings() {
    let scip = Harness::new(&[(
        "src/lib.rs",
        "pub fn run() {\n    helper();\n}\n\nfn helper() {}\n",
    )]);
    let scip_input = scip.copy_fixture("v03_a02/valid-scip.json", "scip.json");
    let (_, scip_verify, _) = scip.journey(json!({
        "adapter_kind": "scip",
        "input_path": scip_input,
        "pin": {
            "file_sha256": "sha256:6c1aa34317015297620f517829cbbe1105765f28897a2f3f87c5a622d5672fce",
            "schema_version": "scip/0.4-json",
            "schema_sha256": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "tool_name": "scip-rust",
            "tool_version": "0.3.3",
            "tool_commit": "0123456789abcdef0123456789abcdef01234567",
            "tool_license": "Apache-2.0",
            "source_snapshot_sha256": "sha256:7a516a066420d92c5b10da8f76f5e8eccf1dd1250d425879dab88f3af4654a20",
            "max_file_bytes": 65536
        }
    }));
    assert!(scip_verify["resolved_verified_count"].as_u64().unwrap() > 0);
    assert_eq!(scip_verify["false_confirmed"], 0);

    let lsp = Harness::new(&[(
        "src/main.rs",
        "fn main() {\n    helper(\"中文🙂\");\n}\n\nfn helper(message: &str) {}\n",
    )]);
    let lsp_input = lsp.copy_fixture("v03_a03/valid-lsp-snapshot.json", "lsp.json");
    let (_, lsp_verify, _) = lsp.journey(json!({
        "adapter_kind": "lsp_snapshot",
        "input_path": lsp_input,
        "pin": {
            "file_sha256": "sha256:34f19599535a24ad43b2c8da9fc74a0df76d36885a7fdb7f8e79cc25839f3841",
            "schema_version": "gtkg.lsp-snapshot/v1",
            "schema_sha256": "sha256:97a36add17cb89ec94b92222e8c4b1673dbb5bd5443644f1f346140ad4dd19c1",
            "protocol_version": "3.17",
            "position_encoding": "utf-8",
            "producer_name": "rust-analyzer",
            "producer_version": "2026-08-24",
            "producer_commit": "0123456789abcdef0123456789abcdef01234567",
            "producer_license": "MIT OR Apache-2.0",
            "producer_config_sha256": "sha256:9569022226845a35bce92d52c125556785d8a1d67f6e78b900bb3dc02bac9228",
            "source_snapshot_sha256": "sha256:c45839fdd713b1acb620523e6c9d80ac07fc271113cfad5eb76ef328045e6ddc",
            "max_file_bytes": 65536
        }
    }));
    assert!(lsp_verify["resolved_verified_count"].as_u64().unwrap() > 0);
    assert_eq!(lsp_verify["false_confirmed"], 0);

    let graphify = Harness::new(&[("src/lib.rs", "fn graphify_source() {}\n")]);
    let graphify_input = graphify.copy_fixture("v03_a05/strict-graphify-v2.json", "graphify.json");
    let (graphify_build, graphify_verify, candidate) = graphify.journey(json!({
        "adapter_kind": "graphify",
        "input_path": graphify_input,
        "pin": {
            "file_sha256": "sha256:0e2e258daef9182ca2573c561bad47958a56f08a5e5b853ce71bcf9508e4edf0",
            "canonical_schema_sha256": "sha256:3bad32555ba7930ca4856522d2a643cd70e1f305b1c2fd98ff1aa54bd34445ac",
            "tool_version": "0.9.52",
            "tool_commit": "680e3ed8edd3dc1fa1961050912941880b778207",
            "tool_license": "Apache-2.0",
            "export_py_sha256": "sha256:573079762778f191aceb500598bdc23d7142efd6a21ba881bb7d424334a83f67",
            "validate_py_sha256": "sha256:be068c6b2ff4e514f31663e0155a9d63f35096d154b98ab6c9c467a23febd6f7",
            "pyproject_sha256": "sha256:b27257549612da75f9e50696e395a545a514aefb0c148340912673a31a9c166b",
            "license_sha256": "sha256:cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30",
            "extraction_spec_sha256": "sha256:32d7decad42d58129c6694ea4e4ce1f72a531bc5161827d2095787e9448735e9",
            "source_snapshot_sha256": graphify.snapshot_exact_set,
            "source_repository_commit": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "max_file_bytes": 65536,
            "max_node_count": 64,
            "max_link_count": 64,
            "max_hyperedge_count": 16
        }
    }));
    assert_eq!(graphify_build["admitted_count"], 8);
    assert_eq!(graphify_verify["resolved_verified_count"], 0);
    assert_eq!(graphify_verify["false_confirmed"], 0);
    assert_eq!(graphify_verify["canonical_eligible"], false);
    assert_eq!(
        candidate["adapter_runs"][0]["import_receipt"]["schema_version"],
        "gtkg.graphify-import-receipt/v2"
    );
    assert_eq!(
        candidate["adapter_runs"][0]["import_receipt"]["provider_call_count"],
        0
    );
}

#[test]
fn p02_rejects_self_consistent_export_source_that_differs_from_current_snapshot() {
    let harness = Harness::new(&[("src/lib.rs", "pub fn different() {}\n")]);
    let input = harness.copy_fixture("v03_a02/valid-scip.json", "scip.json");
    let plan = harness.plan(json!({
        "adapter_kind": "scip",
        "input_path": input,
        "pin": {
            "file_sha256": "sha256:6c1aa34317015297620f517829cbbe1105765f28897a2f3f87c5a622d5672fce",
            "schema_version": "scip/0.4-json",
            "schema_sha256": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "tool_name": "scip-rust",
            "tool_version": "0.3.3",
            "tool_commit": "0123456789abcdef0123456789abcdef01234567",
            "tool_license": "Apache-2.0",
            "source_snapshot_sha256": "sha256:7a516a066420d92c5b10da8f76f5e8eccf1dd1250d425879dab88f3af4654a20",
            "max_file_bytes": 65536
        }
    }));
    let error = Dispatcher
        .execute_v2(
            &harness.context(EffectPolicy::WorkspaceWrite),
            OperationRequestV2::new(
                "analysis.build",
                "p02-source-join-attack",
                json!({"workspace_root": harness.root(), "plan_ref": plan}),
            ),
        )
        .unwrap_err();
    assert_eq!(error.error.code, V2ErrorCode::SourceChanged);
}

#[test]
fn p02_rejects_rehashed_plan_denominator_and_semantic_path_alias() {
    let harness = Harness::new(&[("lib.rs", "fn stable() {}\n")]);
    let plan_ref = harness.plan(json!({"adapter_kind": "native", "logical_path": "lib.rs"}));
    let plan_path = harness.root().join(&plan_ref.path);
    let bytes = fs::read(&plan_path).unwrap();

    let alias_path = harness.root().join(".gtkg/analysis/plans/alias.json");
    fs::write(&alias_path, &bytes).unwrap();
    let alias = FileReceiptRef {
        path: ".gtkg/analysis/plans/alias.json".to_owned(),
        sha256: sha256(&bytes),
    };
    let alias_error = Dispatcher
        .execute_v2(
            &harness.context(EffectPolicy::WorkspaceWrite),
            OperationRequestV2::new(
                "analysis.build",
                "p02-plan-alias",
                json!({"workspace_root": harness.root(), "plan_ref": alias}),
            ),
        )
        .unwrap_err();
    assert_eq!(alias_error.error.code, V2ErrorCode::InvalidState);

    let mut tampered: Value = serde_json::from_slice(&bytes).unwrap();
    tampered["selection_exact_set_sha256"] = json!(digest('f'));
    let mut semantic = tampered.clone();
    semantic.as_object_mut().unwrap().remove("plan_sha256");
    tampered["plan_sha256"] = json!(canonical_json_sha256(&semantic).unwrap());
    let tampered_bytes = serde_json::to_vec_pretty(&tampered).unwrap();
    let tampered_path = harness
        .root()
        .join(".gtkg/analysis/plans/rehashed-tampered.json");
    fs::write(&tampered_path, &tampered_bytes).unwrap();
    let tampered_error = Dispatcher
        .execute_v2(
            &harness.context(EffectPolicy::WorkspaceWrite),
            OperationRequestV2::new(
                "analysis.build",
                "p02-plan-rehashed",
                json!({
                    "workspace_root": harness.root(),
                    "plan_ref": {
                        "path": ".gtkg/analysis/plans/rehashed-tampered.json",
                        "sha256": sha256(&tampered_bytes)
                    }
                }),
            ),
        )
        .unwrap_err();
    assert_eq!(tampered_error.error.code, V2ErrorCode::InvalidState);
}

struct Harness {
    workspace: tempfile::TempDir,
    source_root: PathBuf,
    snapshot_ref: FileReceiptRef,
    snapshot_exact_set: String,
}

impl Harness {
    fn new(files: &[(&str, &str)]) -> Self {
        let workspace = tempfile::tempdir().unwrap();
        let source_root = workspace.path().join("source");
        fs::create_dir(&source_root).unwrap();
        for (relative, text) in files {
            let path = source_root.join(relative);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, text).unwrap();
        }
        let output = workspace
            .path()
            .join(".gtkg/source-snapshots/snapshot.json");
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
                    "p02-successor-capture",
                    json!({
                        "capture_mode": "directory_exact",
                        "repository_id": "p02-successor",
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
                path: ".gtkg/source-snapshots/snapshot.json".to_owned(),
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

    fn copy_fixture(&self, relative: &str, name: &str) -> PathBuf {
        let source = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures")
            .join(relative);
        let destination = self.root().join("inputs").join(name);
        fs::create_dir_all(destination.parent().unwrap()).unwrap();
        fs::write(&destination, fs::read(source).unwrap()).unwrap();
        destination
    }

    fn plan(&self, adapter_input: Value) -> FileReceiptRef {
        let response = Dispatcher
            .execute_v2(
                &self.context(EffectPolicy::WorkspaceWrite),
                OperationRequestV2::new(
                    "analysis.plan",
                    "p02-successor-plan",
                    json!({
                        "workspace_root": self.root(),
                        "source_root": self.source_root,
                        "source_snapshot_ref": self.snapshot_ref,
                        "adapter_inputs": [adapter_input]
                    }),
                ),
            )
            .unwrap();
        serde_json::from_value(response.result["plan_ref"].clone()).unwrap()
    }

    fn journey(&self, adapter_input: Value) -> (Value, Value, Value) {
        let plan_ref = self.plan(adapter_input);
        let build = Dispatcher
            .execute_v2(
                &self.context(EffectPolicy::WorkspaceWrite),
                OperationRequestV2::new(
                    "analysis.build",
                    "p02-successor-build",
                    json!({"workspace_root": self.root(), "plan_ref": plan_ref}),
                ),
            )
            .unwrap();
        let candidate_ref: FileReceiptRef =
            serde_json::from_value(build.result["candidate_ref"].clone()).unwrap();
        let candidate: Value =
            serde_json::from_slice(&fs::read(self.root().join(&candidate_ref.path)).unwrap())
                .unwrap();
        let verify = Dispatcher
            .execute_v2(
                &self.context(EffectPolicy::WorkspaceWrite),
                OperationRequestV2::new(
                    "analysis.verify",
                    "p02-successor-verify",
                    json!({"workspace_root": self.root(), "candidate_ref": candidate_ref}),
                ),
            )
            .unwrap();
        (build.result, verify.result, candidate)
    }
}

fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn digest(character: char) -> String {
    format!("sha256:{}", character.to_string().repeat(64))
}
