//! P02 selected SourceSnapshot binding is distinct from SCIP/LSP export
//! manifest identity and must be explicit in the canonical plan.

use std::fs;
use std::path::Path;

use gtkg_core::{CallContext, Dispatcher, EffectPolicy, TransportKind};
use gtkg_protocol::FileReceiptRef;
use gtkg_protocol::v2::{OperationRequestV2, V2ErrorCode};
use serde_json::{Value, json};

#[test]
fn p02_scip_and_lsp_bind_selected_snapshot_separately_from_export_manifest() {
    assert_selected_binding(
        "v03_a02/valid-scip.json",
        "src/lib.rs",
        "pub fn run() {\n    helper();\n}\n\nfn helper() {}\n",
        |input_path, selected| {
            json!({
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
            })
        },
    );
    assert_selected_binding(
        "v03_a03/valid-lsp-snapshot.json",
        "src/main.rs",
        "fn main() {\n    helper(\"中文🙂\");\n}\n\nfn helper(message: &str) {}\n",
        |input_path, selected| {
            json!({
                "adapter_kind": "lsp_snapshot",
                "input_path": input_path,
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
                    "selected_source_snapshot_sha256": selected,
                    "max_file_bytes": 65536
                }
            })
        },
    );
}

fn assert_selected_binding<F>(fixture: &str, logical_path: &str, source: &str, input: F)
where
    F: Fn(&Path, &str) -> Value,
{
    let workspace = tempfile::tempdir().unwrap();
    let source_root = workspace.path().join("source");
    let source_path = source_root.join(logical_path);
    fs::create_dir_all(source_path.parent().unwrap()).unwrap();
    fs::write(&source_path, source).unwrap();
    let input_path = workspace.path().join("input.json");
    let fixture_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join(fixture);
    fs::write(&input_path, fs::read(fixture_path).unwrap()).unwrap();
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
                "p02-selected-capture",
                json!({
                    "capture_mode": "directory_exact",
                    "repository_id": "p02-selected",
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

    let wrong = Dispatcher
        .execute_v2(
            &context,
            OperationRequestV2::new(
                "analysis.plan",
                "p02-selected-wrong",
                json!({
                    "workspace_root": workspace.path(),
                    "source_root": source_root,
                    "source_snapshot_ref": snapshot_ref,
                    "adapter_inputs": [input(&input_path, &digest('e'))]
                }),
            ),
        )
        .unwrap_err();
    assert_eq!(wrong.error.code, V2ErrorCode::SourceChanged);

    let planned = Dispatcher
        .execute_v2(
            &context,
            OperationRequestV2::new(
                "analysis.plan",
                "p02-selected-correct",
                json!({
                    "workspace_root": workspace.path(),
                    "source_root": source_root,
                    "source_snapshot_ref": snapshot_ref,
                    "adapter_inputs": [input(&input_path, selected)]
                }),
            ),
        )
        .unwrap();
    let plan_ref: FileReceiptRef =
        serde_json::from_value(planned.result["plan_ref"].clone()).unwrap();
    let plan: Value =
        serde_json::from_slice(&fs::read(workspace.path().join(&plan_ref.path)).unwrap()).unwrap();
    assert_eq!(
        plan["adapters"][0]["input"]["pin"]["selected_source_snapshot_sha256"],
        selected
    );
}

fn digest(character: char) -> String {
    format!("sha256:{}", character.to_string().repeat(64))
}
