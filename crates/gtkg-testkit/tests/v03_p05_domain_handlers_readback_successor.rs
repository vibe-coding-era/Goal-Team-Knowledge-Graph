//! P05 oracle successor: v1 FileReceiptRef paths remain relative to the
//! authorized workspace and are resolved below that exact root for readback.

use std::fs;
use std::path::{Component, PathBuf};

use gtkg_core::file_model::tree_sha256;
use gtkg_core::{CallContext, Dispatcher, EffectPolicy, TransportKind};
use gtkg_protocol::v2::{OperationRequestV2, V2OperationId};
use gtkg_protocol::{
    FileReceiptRef, NodeDescriptor, NodeTransport, OperationId, OperationRequest, ShardResult,
    WorkUnit,
};
use serde_json::json;
use sha2::{Digest, Sha256};

#[test]
fn p05_deliverable_receipt_is_relative_chainable_and_digest_read_back() {
    let workspace = tempfile::tempdir().unwrap();
    let parent = workspace.path().join("published-parent");
    fs::create_dir(&parent).unwrap();
    fs::write(parent.join("artifact.md"), "# P05 successor parent\n").unwrap();
    let parent_tree_sha256 = tree_sha256(&parent).unwrap();
    let context = CallContext::restricted(
        TransportKind::Test,
        vec![workspace.path().to_path_buf()],
        EffectPolicy::WorkspaceWrite,
    )
    .unwrap();

    let current_path = workspace.path().join("CURRENT.json");
    let current_bytes = serde_json::to_vec_pretty(&json!({
        "schema_version": "gtkg.current/v1",
        "deliverable_id": "p05-successor",
        "version": "0.3.0",
        "version_path": "versions/0.3.0",
        "tree_sha256": digest('1'),
        "manifest_sha256": digest('2'),
    }))
    .unwrap();
    fs::write(&current_path, &current_bytes).unwrap();
    let catalog = workspace.path().join("template-catalog");
    fs::create_dir(&catalog).unwrap();
    let node = local_node();
    let work = WorkUnit::new(
        "static_extract",
        digest('3'),
        digest('4'),
        json!({"source_path": "README.md"}),
    )
    .unwrap();
    let shard = ShardResult::new(&work, &node.node_id, 1, json!({"text": "stable"})).unwrap();

    for (v2_id, v1_id, payload) in [
        (
            V2OperationId::CurrentGet,
            OperationId::CurrentGet,
            json!({
                "current_path": current_path,
                "expected_current_sha256": sha256(&current_bytes),
            }),
        ),
        (
            V2OperationId::NodeDescribe,
            OperationId::NodeDescribe,
            json!({"descriptor": node, "probe_sandbox": false}),
        ),
        (
            V2OperationId::FederationValidate,
            OperationId::FederationValidate,
            json!({
                "nodes": [node],
                "work_units": [work],
                "shard_results": [shard],
            }),
        ),
        (
            V2OperationId::TemplateList,
            OperationId::TemplateList,
            json!({"catalog_root": catalog}),
        ),
    ] {
        let legacy = Dispatcher
            .execute(
                &context,
                OperationRequest::new(
                    v1_id,
                    format!("p05-successor-v1-{}", v1_id.as_str()),
                    payload.clone(),
                ),
            )
            .unwrap();
        let v2 = Dispatcher
            .execute_v2(
                &context,
                OperationRequestV2::new(
                    v2_id.as_str(),
                    format!("p05-successor-v2-{}", v2_id.as_str()),
                    payload,
                ),
            )
            .unwrap();
        assert_eq!(v2.result, legacy.result);
    }

    let response = Dispatcher
        .execute_v2(
            &context,
            OperationRequestV2::new(
                V2OperationId::DeliverableDerive.as_str(),
                "p05-relative-readback-successor",
                json!({
                    "workspace_root": workspace.path(),
                    "parent_path": parent,
                    "expected_parent_tree_sha256": parent_tree_sha256,
                    "deliverable_id": "p05-successor",
                    "new_version": "0.3.1",
                    "slot_overrides": {},
                }),
            ),
        )
        .unwrap();
    let reference: FileReceiptRef =
        serde_json::from_value(response.result["draft_ref"].clone()).unwrap();
    reference.validate().unwrap();
    let relative = PathBuf::from(&reference.path);
    assert!(relative.is_relative());
    assert!(
        relative
            .components()
            .all(|component| { matches!(component, Component::Normal(_) | Component::CurDir) })
    );
    let bound = workspace.path().join(&relative);
    assert!(bound.is_file());
    assert_eq!(sha256(&fs::read(bound).unwrap()), reference.sha256);
    assert_eq!(response.result["status"], "draft");
    assert_eq!(response.result["verified"], false);
}

fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn digest(character: char) -> String {
    format!("sha256:{}", character.to_string().repeat(64))
}

fn local_node() -> NodeDescriptor {
    NodeDescriptor {
        schema_version: "gtkg.node/v1".to_owned(),
        node_id: "p05-successor-worker".to_owned(),
        logical_address: "local://p05-successor-worker".to_owned(),
        transport: NodeTransport::Exec,
        endpoint: std::env::current_exe()
            .unwrap()
            .to_string_lossy()
            .into_owned(),
        binary_sha256: digest('a'),
        source_sha256: digest('b'),
        protocol_version: gtkg_protocol::PROTOCOL_VERSION.to_owned(),
        parser_sha256: digest('c'),
        sandbox_policy_sha256: digest('d'),
        platform: std::env::consts::OS.to_owned(),
        capabilities: vec!["static_extract".to_owned()],
        max_parallel: 1,
        work_unit_kinds: vec!["static_extract".to_owned()],
    }
}
