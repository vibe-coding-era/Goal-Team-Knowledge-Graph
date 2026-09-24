//! P02 stored plans must retain the selected SourceSnapshot binding even when
//! an attacker recomputes every enclosing semantic digest and filename.

use std::fs;
use std::path::Path;

use gtkg_core::{CallContext, Dispatcher, EffectPolicy, TransportKind};
use gtkg_protocol::v2::{OperationRequestV2, V2ErrorCode};
use gtkg_protocol::{FileReceiptRef, canonical_json_sha256};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

#[test]
fn p02_rejects_rehashed_stored_plan_with_missing_or_wrong_selected_snapshot() {
    let workspace = tempfile::tempdir().unwrap();
    let source_root = workspace.path().join("source");
    let source_path = source_root.join("src/lib.rs");
    fs::create_dir_all(source_path.parent().unwrap()).unwrap();
    fs::write(
        &source_path,
        "pub fn run() {\n    helper();\n}\n\nfn helper() {}\n",
    )
    .unwrap();
    let input_path = workspace.path().join("scip.json");
    fs::write(
        &input_path,
        fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/v03_a02/valid-scip.json"))
            .unwrap(),
    )
    .unwrap();
    let context = CallContext::restricted(
        TransportKind::Test,
        vec![workspace.path().to_path_buf()],
        EffectPolicy::WorkspaceWrite,
    )
    .unwrap();
    let output = workspace.path().join(".gtkg/source-snapshots/source.json");
    let captured = Dispatcher
        .execute_v2(
            &context,
            OperationRequestV2::new(
                "source.capture",
                "p02-stored-capture",
                json!({
                    "capture_mode": "directory_exact",
                    "repository_id": "p02-stored",
                    "source_root": source_root,
                    "output_path": output,
                }),
            ),
        )
        .unwrap();
    let snapshot_ref = FileReceiptRef {
        path: ".gtkg/source-snapshots/source.json".to_owned(),
        sha256: captured.result["snapshot_ref"]["artifact_sha256"]
            .as_str()
            .unwrap()
            .to_owned(),
    };
    let selected = captured.result["snapshot"]["exact_set_sha256"]
        .as_str()
        .unwrap();
    let planned = Dispatcher
        .execute_v2(
            &context,
            OperationRequestV2::new(
                "analysis.plan",
                "p02-stored-plan",
                json!({
                    "workspace_root": workspace.path(),
                    "source_root": source_root,
                    "source_snapshot_ref": snapshot_ref,
                    "adapter_inputs": [{
                        "adapter_kind": "scip",
                        "input_path": input_path,
                        "pin": {
                            "file_sha256": "sha256:6c1aa34317015297620f517829cbbe1105765f28897a2f3f87c5a622d5672fce",
                            "schema_version": "scip/0.4-json",
                            "schema_sha256": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                            "tool_name": "scip-rust",
                            "tool_version": "0.3.3",
                            "tool_commit": "0123456789abcdef0123456789abcdef01234567",
                            "tool_license": "Apache-2.0",
                            "source_snapshot_sha256": "sha256:7a516a066420d92c5b10da8f76f5e8eccf1dd1250d425879dab88f3af4654a20",
                            "selected_source_snapshot_sha256": selected,
                            "max_file_bytes": 65536
                        }
                    }]
                }),
            ),
        )
        .unwrap();
    let plan_ref: FileReceiptRef =
        serde_json::from_value(planned.result["plan_ref"].clone()).unwrap();
    let original: Value =
        serde_json::from_slice(&fs::read(workspace.path().join(&plan_ref.path)).unwrap()).unwrap();

    for selected_mutation in [Value::Null, json!(digest('e'))] {
        let mut plan = original.clone();
        plan["adapters"][0]["input"]["pin"]["selected_source_snapshot_sha256"] = selected_mutation;
        let selection_id = canonical_json_sha256(&plan["adapters"][0]["input"]).unwrap();
        plan["adapters"][0]["selection_id"] = json!(selection_id);
        plan["selection_exact_set_sha256"] =
            json!(canonical_json_sha256(&vec![selection_id.as_str()]).unwrap());
        let mut semantic = plan.clone();
        semantic.as_object_mut().unwrap().remove("plan_sha256");
        let plan_sha256 = canonical_json_sha256(&semantic).unwrap();
        plan["plan_sha256"] = json!(plan_sha256);
        let bytes = serde_json::to_vec_pretty(&plan).unwrap();
        let path = workspace.path().join(format!(
            ".gtkg/analysis/plans/{}.json",
            plan_sha256.strip_prefix("sha256:").unwrap()
        ));
        fs::write(&path, &bytes).unwrap();
        let reference = FileReceiptRef {
            path: path
                .strip_prefix(workspace.path())
                .unwrap()
                .to_string_lossy()
                .into_owned(),
            sha256: sha256(&bytes),
        };
        let error = Dispatcher
            .execute_v2(
                &context,
                OperationRequestV2::new(
                    "analysis.build",
                    "p02-stored-plan-attack",
                    json!({"workspace_root": workspace.path(), "plan_ref": reference}),
                ),
            )
            .unwrap_err();
        assert!(matches!(
            error.error.code,
            V2ErrorCode::InvalidState | V2ErrorCode::SourceChanged
        ));
    }
}

fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn digest(character: char) -> String {
    format!("sha256:{}", character.to_string().repeat(64))
}
