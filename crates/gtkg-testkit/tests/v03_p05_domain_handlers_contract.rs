//! P05 immutable contract: 18 v2 domain handlers reuse the exact v1 domain
//! semantics while preserving closed payloads and effect-policy denial.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use gtkg_core::file_model::tree_sha256;
use gtkg_core::{CallContext, Dispatcher, EffectPolicy, TransportKind};
use gtkg_protocol::v2::{
    CallabilityV2, OperationAvailabilityV2, OperationRequestV2, V2_PUBLIC_OPERATIONS, V2ErrorCode,
    V2OperationId, v2_operation_definition, v2_operation_request_schema,
    validate_v2_operation_payload,
};
use gtkg_protocol::{
    NodeDescriptor, NodeTransport, OperationId, OperationRequest, ShardResult, WorkUnit,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const P05_OPERATIONS: [V2OperationId; 18] = [
    V2OperationId::GitPublish,
    V2OperationId::CurrentGet,
    V2OperationId::CurrentActivate,
    V2OperationId::NodeDescribe,
    V2OperationId::FederationValidate,
    V2OperationId::TemplateList,
    V2OperationId::TemplateResolve,
    V2OperationId::TemplatePrefetch,
    V2OperationId::TemplateGet,
    V2OperationId::TemplateValidate,
    V2OperationId::TemplateDerive,
    V2OperationId::TemplatePublish,
    V2OperationId::DeliverableDerive,
    V2OperationId::DeliverablePublish,
    V2OperationId::A2uiResolve,
    V2OperationId::A2uiGenerate,
    V2OperationId::A2uiGet,
    V2OperationId::A2uiValidate,
];

const POLICY_DENIED: [V2OperationId; 4] = [
    V2OperationId::GitPublish,
    V2OperationId::CurrentActivate,
    V2OperationId::TemplatePublish,
    V2OperationId::DeliverablePublish,
];

#[test]
fn p05_promotes_exactly_18_domain_handlers_with_closed_payload_schemas() {
    assert_eq!(
        P05_OPERATIONS.into_iter().collect::<BTreeSet<_>>().len(),
        18
    );
    for operation_id in P05_OPERATIONS {
        let definition = v2_operation_definition(operation_id).expect("P05 registry entry");
        assert_eq!(
            definition.availability,
            OperationAvailabilityV2::Implemented
        );
        let expected_callability = if POLICY_DENIED.contains(&operation_id) {
            CallabilityV2::DeniedByPolicy
        } else {
            CallabilityV2::Callable
        };
        assert_eq!(definition.callability, expected_callability);

        let schema = v2_operation_request_schema(operation_id);
        let payload = &schema["properties"]["payload"];
        assert_eq!(schema["additionalProperties"], false);
        let payload = if operation_id == V2OperationId::DeliverableDerive {
            let branches = payload["oneOf"]
                .as_array()
                .expect("two explicit payload revisions");
            assert_eq!(branches.len(), 2);
            assert!(branches[0]["properties"].get("payload_revision").is_none());
            let current = &branches[1];
            assert_eq!(current["type"], "object");
            assert_eq!(current["additionalProperties"], false);
            assert_eq!(
                current["properties"]["payload_revision"]["const"],
                gtkg_protocol::v04::PAYLOAD_REVISION
            );
            let fields = ["artifact_ref", "payload_revision", "workspace_root"]
                .into_iter()
                .collect::<BTreeSet<_>>();
            assert_eq!(string_set(&current["required"]), fields);
            assert_eq!(
                current["properties"]
                    .as_object()
                    .unwrap()
                    .keys()
                    .map(String::as_str)
                    .collect::<BTreeSet<_>>(),
                fields
            );
            let mut request = json!({
                "payload_revision": gtkg_protocol::v04::PAYLOAD_REVISION,
                "workspace_root": ".",
                "artifact_ref": {"path": ".gtkg/qk/views.json", "sha256": digest('a')}
            });
            assert!(validate_v2_operation_payload(operation_id, &request).is_ok());
            request["unexpected"] = json!(true);
            assert!(validate_v2_operation_payload(operation_id, &request).is_err());
            request.as_object_mut().unwrap().remove("unexpected");
            request["payload_revision"] = json!("unsupported-revision");
            assert!(validate_v2_operation_payload(operation_id, &request).is_err());
            &branches[0]
        } else {
            assert!(payload.get("oneOf").is_none());
            payload
        };
        assert_eq!(payload["type"], "object");
        assert_eq!(payload["additionalProperties"], false);
        assert_eq!(
            string_set(&payload["required"]),
            expected_required(operation_id)
                .iter()
                .copied()
                .collect::<BTreeSet<_>>()
        );
        assert_eq!(
            payload["properties"]
                .as_object()
                .expect("closed payload properties")
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            expected_properties(operation_id)
                .iter()
                .copied()
                .collect::<BTreeSet<_>>()
        );
    }
}

#[test]
fn p05_historical_stage_keeps_28_handlers_and_analysis_unimplemented() {
    let implemented = V2_PUBLIC_OPERATIONS
        .iter()
        .filter(|definition| definition.availability == OperationAvailabilityV2::Implemented)
        .map(|definition| definition.id)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        implemented.len(),
        28,
        "P05 adds 18 to the prior 10 handlers"
    );
    assert!(P05_OPERATIONS.iter().all(|id| implemented.contains(id)));
    assert_eq!(
        v2_operation_definition(V2OperationId::AnalysisPlan)
            .unwrap()
            .availability,
        OperationAvailabilityV2::NotImplemented,
        "P05 must not claim the P06 46-handler denominator"
    );
}

#[test]
fn p05_rejects_unknown_fields_before_domain_or_effect_evaluation() {
    let fixture = Fixture::new();
    let context = fixture.context(EffectPolicy::WorkspaceWrite);
    for operation_id in P05_OPERATIONS {
        let mut payload = fixture.payload(operation_id);
        payload
            .as_object_mut()
            .unwrap()
            .insert("unexpected".to_owned(), Value::Bool(true));
        let error = Dispatcher
            .execute_v2(
                &context,
                OperationRequestV2::new(
                    operation_id.as_str(),
                    format!("p05-closed-{}", operation_id.as_str()),
                    payload,
                ),
            )
            .expect_err("unknown P05 payload field must fail closed");
        assert_eq!(error.error.code, V2ErrorCode::InvalidRequest);
        assert_eq!(error.error.stage, "payload-schema");
    }
}

#[test]
fn p05_effect_policy_denies_external_publish_and_current_activation_without_writes() {
    let fixture = Fixture::new();
    let context = fixture.context(EffectPolicy::WorkspaceWrite);
    assert!(!fixture.root().join(".gtkg").exists());
    for operation_id in POLICY_DENIED {
        let error = Dispatcher
            .execute_v2(
                &context,
                OperationRequestV2::new(
                    operation_id.as_str(),
                    format!("p05-denied-{}", operation_id.as_str()),
                    fixture.payload(operation_id),
                ),
            )
            .expect_err("external/current writes remain outside Development authority");
        assert_eq!(error.error.code, V2ErrorCode::SideEffectDenied);
        assert_eq!(error.error.stage, "effect-policy");
    }
    assert!(!fixture.root().join(".gtkg").exists());

    let read_only = fixture.context(EffectPolicy::ReadOnly);
    let local_write = Dispatcher
        .execute_v2(
            &read_only,
            OperationRequestV2::new(
                "template.resolve",
                "p05-read-only-denied",
                fixture.payload(V2OperationId::TemplateResolve),
            ),
        )
        .expect_err("declared local write must respect the read-only context");
    assert_eq!(local_write.error.code, V2ErrorCode::SideEffectDenied);
    assert_eq!(local_write.error.stage, "effect-policy");
}

#[test]
fn p05_all_18_requests_reach_real_domain_or_policy_handlers() {
    let fixture = Fixture::new();
    let context = fixture.context(EffectPolicy::WorkspaceWrite);
    for operation_id in P05_OPERATIONS {
        let outcome = Dispatcher.execute_v2(
            &context,
            OperationRequestV2::new(
                operation_id.as_str(),
                format!("p05-invoke-{}", operation_id.as_str()),
                fixture.payload(operation_id),
            ),
        );
        if let Err(error) = outcome {
            assert_ne!(error.error.code, V2ErrorCode::OperationNotImplemented);
            assert_ne!(error.error.stage, "dispatch");
        }
    }
}

#[test]
fn p05_positive_reads_and_local_receipts_match_v1_domain_semantics() {
    let fixture = Fixture::new();
    let context = fixture.context(EffectPolicy::WorkspaceWrite);
    for (v2_id, v1_id) in [
        (V2OperationId::CurrentGet, OperationId::CurrentGet),
        (V2OperationId::NodeDescribe, OperationId::NodeDescribe),
        (
            V2OperationId::FederationValidate,
            OperationId::FederationValidate,
        ),
        (V2OperationId::TemplateList, OperationId::TemplateList),
    ] {
        let payload = fixture.payload(v2_id);
        let v1 = Dispatcher
            .execute(
                &context,
                OperationRequest::new(v1_id, format!("p05-v1-{}", v1_id.as_str()), payload.clone()),
            )
            .expect("v1 domain operation succeeds");
        let v2 = Dispatcher
            .execute_v2(
                &context,
                OperationRequestV2::new(
                    v2_id.as_str(),
                    format!("p05-v2-{}", v2_id.as_str()),
                    payload,
                ),
            )
            .expect("v2 domain mapping succeeds");
        assert_eq!(v2.result, v1.result);
        assert_eq!(v2.operation_id, v2_id);
    }

    let deliverable = Dispatcher
        .execute_v2(
            &context,
            OperationRequestV2::new(
                "deliverable.derive",
                "p05-deliverable-positive",
                fixture.payload(V2OperationId::DeliverableDerive),
            ),
        )
        .expect("deliverable.derive writes a real immutable local draft receipt");
    assert_eq!(deliverable.result["status"], "draft");
    assert_eq!(deliverable.result["verified"], false);
    let draft_path = fixture
        .root
        .path()
        .join(deliverable.result["draft_ref"]["path"].as_str().unwrap());
    assert!(draft_path.is_file());
    assert_eq!(
        sha256(&fs::read(&draft_path).unwrap()),
        deliverable.result["draft_ref"]["sha256"]
    );
}

struct Fixture {
    root: tempfile::TempDir,
    current_path: PathBuf,
    current_sha256: String,
    catalog_root: PathBuf,
    parent_root: PathBuf,
    parent_tree_sha256: String,
    node: NodeDescriptor,
    work: WorkUnit,
    result: ShardResult,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().expect("P05 workspace");
        let current_path = root.path().join("CURRENT.json");
        let current_bytes = serde_json::to_vec_pretty(&json!({
            "schema_version": "gtkg.current/v1",
            "deliverable_id": "p05-deliverable",
            "version": "0.3.0",
            "version_path": "versions/0.3.0",
            "tree_sha256": digest('1'),
            "manifest_sha256": digest('2'),
        }))
        .unwrap();
        fs::write(&current_path, &current_bytes).unwrap();
        let current_sha256 = sha256(&current_bytes);

        let catalog_root = root.path().join("template-catalog");
        fs::create_dir(&catalog_root).unwrap();
        let parent_root = root.path().join("published-parent");
        fs::create_dir(&parent_root).unwrap();
        fs::write(parent_root.join("artifact.md"), "# P05 parent\n").unwrap();
        let parent_tree_sha256 = tree_sha256(&parent_root).unwrap();

        let node = local_node();
        let work = WorkUnit::new(
            "static_extract",
            digest('3'),
            digest('4'),
            json!({"source_path": "README.md"}),
        )
        .unwrap();
        let result = ShardResult::new(&work, &node.node_id, 1, json!({"text": "stable"})).unwrap();
        Self {
            root,
            current_path,
            current_sha256,
            catalog_root,
            parent_root,
            parent_tree_sha256,
            node,
            work,
            result,
        }
    }

    fn root(&self) -> &Path {
        self.root.path()
    }

    fn context(&self, effect_policy: EffectPolicy) -> CallContext {
        CallContext::restricted(
            TransportKind::Test,
            vec![self.root.path().to_path_buf()],
            effect_policy,
        )
        .unwrap()
    }

    fn payload(&self, operation_id: V2OperationId) -> Value {
        let missing_ref = || json!({"path": "missing.json", "sha256": digest('f')});
        match operation_id {
            V2OperationId::GitPublish => json!({
                "workspace_root": self.root(),
                "artifact_path": self.parent_root,
                "expected_tree_sha256": self.parent_tree_sha256,
                "repository_root": self.root(),
                "ref_name": "refs/heads/p05",
            }),
            V2OperationId::CurrentGet => json!({
                "current_path": self.current_path,
                "expected_current_sha256": self.current_sha256,
            }),
            V2OperationId::CurrentActivate => json!({
                "workspace_root": self.root(),
                "current_root": self.root().join("current"),
                "version_path": "versions/0.3.0",
                "expected_tree_sha256": digest('1'),
            }),
            V2OperationId::NodeDescribe => json!({
                "descriptor": self.node,
                "probe_sandbox": false,
            }),
            V2OperationId::FederationValidate => json!({
                "nodes": [self.node],
                "work_units": [self.work],
                "shard_results": [self.result],
            }),
            V2OperationId::TemplateList => json!({"catalog_root": self.catalog_root}),
            V2OperationId::TemplateResolve => json!({
                "workspace_root": self.root(),
                "catalog_root": self.catalog_root,
                "template_id": "p05-template",
                "version": "0.3.0",
            }),
            V2OperationId::TemplatePrefetch => json!({
                "workspace_root": self.root(),
                "resolution_ref": missing_ref(),
            }),
            V2OperationId::TemplateGet => json!({
                "workspace_root": self.root(),
                "template_ref": missing_ref(),
            }),
            V2OperationId::TemplateValidate => json!({
                "workspace_root": self.root(),
                "resolution_ref": missing_ref(),
            }),
            V2OperationId::TemplateDerive => json!({
                "workspace_root": self.root(),
                "parent_ref": missing_ref(),
                "new_version": "0.3.1",
                "slot_overrides": {},
            }),
            V2OperationId::TemplatePublish => json!({
                "workspace_root": self.root(),
                "draft_ref": missing_ref(),
                "repository_root": self.root(),
                "version": "0.3.1",
            }),
            V2OperationId::DeliverableDerive => json!({
                "workspace_root": self.root(),
                "parent_path": self.parent_root,
                "expected_parent_tree_sha256": self.parent_tree_sha256,
                "deliverable_id": "p05-deliverable",
                "new_version": "0.3.1",
                "slot_overrides": BTreeMap::<String, String>::new(),
            }),
            V2OperationId::DeliverablePublish => json!({
                "workspace_root": self.root(),
                "draft_ref": missing_ref(),
                "repository_root": self.root(),
                "version": "0.3.1",
            }),
            V2OperationId::A2uiResolve => json!({
                "workspace_root": self.root(),
                "catalog_root": self.root().join("a2ui-catalog"),
                "spec_version": "0.9.1",
                "profile_id": "basic",
                "profile_version": "0.9.1",
                "catalog_id": "basic",
                "catalog_version": "0.9.1",
                "renderer_id": "lit",
                "renderer_version": "0.9.1",
                "expected_manifest_sha256": digest('5'),
            }),
            V2OperationId::A2uiGenerate => json!({
                "workspace_root": self.root(),
                "bundle_path": self.parent_root,
                "expected_bundle_tree_sha256": self.parent_tree_sha256,
                "resolution_ref": missing_ref(),
                "projection_version": "0.3.0",
            }),
            V2OperationId::A2uiGet => json!({
                "workspace_root": self.root(),
                "generation_ref": missing_ref(),
                "expected_projection_tree_sha256": digest('6'),
            }),
            V2OperationId::A2uiValidate => json!({
                "workspace_root": self.root(),
                "generation_ref": missing_ref(),
                "expected_projection_tree_sha256": digest('6'),
                "required_evidence_state": "a2ui_generatable",
            }),
            _ => panic!("operation is outside P05"),
        }
    }
}

fn local_node() -> NodeDescriptor {
    NodeDescriptor {
        schema_version: "gtkg.node/v1".to_owned(),
        node_id: "p05-worker".to_owned(),
        logical_address: "local://p05-worker".to_owned(),
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

fn string_set(value: &Value) -> BTreeSet<&str> {
    value
        .as_array()
        .expect("string array")
        .iter()
        .map(|item| item.as_str().expect("string item"))
        .collect()
}

fn expected_properties(id: V2OperationId) -> &'static [&'static str] {
    match id {
        V2OperationId::GitPublish => &[
            "workspace_root",
            "artifact_path",
            "expected_tree_sha256",
            "repository_root",
            "ref_name",
        ],
        V2OperationId::CurrentGet => &["current_path", "expected_current_sha256"],
        V2OperationId::CurrentActivate => &[
            "workspace_root",
            "current_root",
            "version_path",
            "expected_tree_sha256",
        ],
        V2OperationId::NodeDescribe => &["descriptor", "probe_sandbox", "sandbox_policy"],
        V2OperationId::FederationValidate => {
            &["nodes", "work_units", "shard_results", "workspace_root"]
        }
        V2OperationId::TemplateList => &["catalog_root"],
        V2OperationId::TemplateResolve => {
            &["workspace_root", "catalog_root", "template_id", "version"]
        }
        V2OperationId::TemplatePrefetch | V2OperationId::TemplateValidate => {
            &["workspace_root", "resolution_ref"]
        }
        V2OperationId::TemplateGet => &["workspace_root", "template_ref"],
        V2OperationId::TemplateDerive => &[
            "workspace_root",
            "parent_ref",
            "new_version",
            "slot_overrides",
        ],
        V2OperationId::TemplatePublish | V2OperationId::DeliverablePublish => {
            &["workspace_root", "draft_ref", "repository_root", "version"]
        }
        V2OperationId::DeliverableDerive => &[
            "workspace_root",
            "parent_path",
            "expected_parent_tree_sha256",
            "deliverable_id",
            "new_version",
            "slot_overrides",
        ],
        V2OperationId::A2uiResolve => &[
            "workspace_root",
            "catalog_root",
            "spec_version",
            "profile_id",
            "profile_version",
            "catalog_id",
            "catalog_version",
            "renderer_id",
            "renderer_version",
            "expected_manifest_sha256",
        ],
        V2OperationId::A2uiGenerate => &[
            "workspace_root",
            "bundle_path",
            "expected_bundle_tree_sha256",
            "resolution_ref",
            "projection_version",
        ],
        V2OperationId::A2uiGet => &[
            "workspace_root",
            "generation_ref",
            "expected_projection_tree_sha256",
        ],
        V2OperationId::A2uiValidate => &[
            "workspace_root",
            "generation_ref",
            "expected_projection_tree_sha256",
            "required_evidence_state",
            "renderer_smoke_ref",
        ],
        _ => panic!("operation is outside P05"),
    }
}

fn expected_required(id: V2OperationId) -> &'static [&'static str] {
    match id {
        V2OperationId::NodeDescribe => &["descriptor"],
        V2OperationId::FederationValidate => &["nodes", "work_units", "shard_results"],
        V2OperationId::A2uiValidate => &[
            "workspace_root",
            "generation_ref",
            "expected_projection_tree_sha256",
            "required_evidence_state",
        ],
        _ => expected_properties(id),
    }
}

fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn digest(character: char) -> String {
    format!("sha256:{}", character.to_string().repeat(64))
}
