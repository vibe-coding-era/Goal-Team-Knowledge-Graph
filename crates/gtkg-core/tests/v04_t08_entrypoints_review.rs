//! Independent T08 public-boundary checks, using only synthetic local artifacts.
#![allow(clippy::unwrap_used)]
#[allow(dead_code)]
#[path = "v04_lifecycle_fixture.rs"]
mod fixture;
use gtkg_core::v04::{
    analysis, artifact, authoring,
    knowledge::{KnowledgeGoal, KnowledgeInput},
    query,
};
use gtkg_core::{CallContext, Dispatcher, EffectPolicy, TransportKind};
use gtkg_protocol::{
    FileReceiptRef,
    v2::{OperationRequestV2, V2OperationId as Op},
    v04::{self, QueryPayload, Revision},
};
use serde_json::{Value, json};
use std::{collections::BTreeMap, fs, path::Path};

fn invoke(c: &CallContext, op: &str, p: Value) -> Result<Value, String> {
    Dispatcher
        .execute_v2(c, OperationRequestV2::new(op, "t08-independent", p))
        .map(|r| r.result)
        .map_err(|e| serde_json::to_string(&e).unwrap())
}
fn tree(root: &Path) -> BTreeMap<String, String> {
    fn scan(root: &Path, p: &Path, out: &mut BTreeMap<String, String>) {
        for e in fs::read_dir(p).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                scan(root, &p, out);
            } else {
                out.insert(
                    p.strip_prefix(root).unwrap().to_str().unwrap().into(),
                    artifact::digest(&fs::read(&p).unwrap()),
                );
            }
        }
    }
    let mut out = BTreeMap::new();
    scan(root, root, &mut out);
    out
}

#[test]
fn schema_and_public_runtime_reject_invalid_limits_policy_and_mixed_pack_shapes_before_io() {
    let temp = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(temp.path()).unwrap();
    let c = CallContext::restricted(
        TransportKind::Test,
        vec![root.clone()],
        EffectPolicy::ReadOnly,
    )
    .unwrap();
    let reference = FileReceiptRef {
        path: "absent-index.json".into(),
        sha256: format!("sha256:{}", "a".repeat(64)),
    };
    let schema = v04::payload_schema(Op::GraphSearch).unwrap();
    assert_eq!(
        schema["properties"]["query_policy"]["enum"],
        json!([
            v04::QUERY_POLICY,
            v04::SELECTIVE_QUERY_POLICY,
            v04::REVIEWED_CONTEXT_QUERY_POLICY
        ])
    );
    assert_eq!(schema["properties"]["max_tokens"]["minimum"], 1);
    assert_eq!(schema["properties"]["max_tokens"]["maximum"], 8000);
    let pack_schema = v04::payload_schema(Op::ContextPack).unwrap();
    assert_eq!(pack_schema["oneOf"][0], schema);
    assert_eq!(pack_schema["oneOf"][1]["additionalProperties"], false);
    for policy in [
        v04::QUERY_POLICY,
        v04::SELECTIVE_QUERY_POLICY,
        v04::REVIEWED_CONTEXT_QUERY_POLICY,
    ] {
        let base = json!({"payload_revision":v04::PAYLOAD_REVISION,"workspace_root":root,"index_ref":reference,"query":"Entry","query_policy":policy,"max_results":1,"max_tokens":8000,"continuation":null});
        for (name, op) in [
            ("graph.search", Op::GraphSearch),
            ("context.pack", Op::ContextPack),
        ] {
            assert!(v04::validate_payload(op, &base).is_ok());
            for (field, value) in [
                ("max_tokens", json!(0)),
                ("max_tokens", json!(8001)),
                ("max_tokens", json!(-1)),
                ("max_tokens", json!(1.5)),
                ("max_results", json!(0)),
                ("max_results", json!(1001)),
                ("query_policy", json!("unknown")),
                ("unregistered_field", json!(true)),
            ] {
                let mut invalid = base.clone();
                invalid[field] = value;
                assert!(v04::validate_payload(op, &invalid).is_err());
                let error = invoke(&c, name, invalid).unwrap_err();
                assert!(
                    error.contains("payload-schema"),
                    "public invalid input reached IO: {error}"
                );
            }
        }
        let error = query::search(
            &c,
            &QueryPayload {
                payload_revision: Revision::R1,
                workspace_root: root.clone(),
                index_ref: reference.clone(),
                query: "Entry".into(),
                query_policy: policy.into(),
                max_results: 1,
                max_tokens: 8001,
                continuation: None,
            },
        )
        .unwrap_err();
        assert!(
            error.contains("bounds invalid"),
            "direct helper did not reject excess context before absent-index IO: {error}"
        );
    }
    let reference_shape = json!({"payload_revision":v04::PAYLOAD_REVISION,"workspace_root":root,"artifact_ref":reference});
    assert!(v04::validate_payload(Op::ContextPack, &reference_shape).is_ok());
    for field in ["index_ref", "query", "max_tokens"] {
        let mut mixed = reference_shape.clone();
        mixed[field] = json!("mixed");
        assert!(v04::validate_payload(Op::ContextPack, &mixed).is_err());
        assert!(
            invoke(&c, "context.pack", mixed)
                .unwrap_err()
                .contains("payload-schema")
        );
    }
    assert!(fs::read_dir(root).unwrap().next().is_none());
}

#[test]
fn documented_inline_reference_and_pending_authoring_entries_are_real_and_readonly() {
    let f = fixture::Fixture::new();
    let (verified_ref, _, _) = f.build("t08-public-entry", &[], false);
    let (v, _): (analysis::VerifiedAnalysis, _) =
        artifact::read(&f.context, &f.workspace, &verified_ref).unwrap();
    let c = CallContext::restricted(
        TransportKind::Test,
        vec![f.workspace.clone()],
        EffectPolicy::ReadOnly,
    )
    .unwrap();
    let capability = invoke(
        &c,
        "capability.describe",
        json!({"payload_revision":v04::PAYLOAD_REVISION,"capability_profile":v04::PROFILE_ID}),
    )
    .unwrap();
    assert_eq!(capability["public_operation_count"], 46);
    assert_eq!(
        capability["knowledge_query_policy"],
        v04::REVIEWED_CONTEXT_QUERY_POLICY
    );
    let before = tree(&f.workspace);
    let inline=invoke(&c,"context.pack",json!({"payload_revision":v04::PAYLOAD_REVISION,"workspace_root":f.workspace,"index_ref":v.index_ref.unwrap(),"query":"Entry","query_policy":v04::SELECTIVE_QUERY_POLICY,"max_results":1,"max_tokens":8000,"continuation":null})).unwrap();
    assert_eq!(inline["schema"], "gtkg.qk.query-context-receipt/v1");
    assert_eq!(tree(&f.workspace), before);
    let prep = &inline["pack_preparation"];
    fs::write(
        f.workspace.join("t08-plan.json"),
        prep["plan_json"].as_str().unwrap(),
    )
    .unwrap();
    fs::write(
        f.workspace.join("t08-hits.json"),
        prep["hits_json"].as_str().unwrap(),
    )
    .unwrap();
    let request = json!({"schema":"gtkg.qk.context-pack-request/v1","plan_ref":artifact::reference(&f.context,&f.workspace,&f.workspace.join("t08-plan.json")).unwrap(),"hits_ref":artifact::reference(&f.context,&f.workspace,&f.workspace.join("t08-hits.json")).unwrap(),"pack_ticket":prep["pack_ticket"],"max_context_units":8000});
    fs::write(
        f.workspace.join("t08-pack.json"),
        serde_json::to_vec(&request).unwrap(),
    )
    .unwrap();
    let before = tree(&f.workspace);
    let packed=invoke(&c,"context.pack",json!({"payload_revision":v04::PAYLOAD_REVISION,"workspace_root":f.workspace,"artifact_ref":artifact::reference(&f.context,&f.workspace,&f.workspace.join("t08-pack.json")).unwrap()})).unwrap();
    assert_eq!(packed["schema"], "gtkg.qk.context-pack-receipt/v1");
    assert!(packed["raw_evidence"].is_array());
    assert!(packed.get("evidence").is_none());
    assert_eq!(packed["terminal"], true);
    assert_eq!(packed["target_execution"], false);
    assert_eq!(tree(&f.workspace), before);

    let job = authoring::JobRequest {
        verified_ref,
        input: KnowledgeInput {
            job_id: "t08-unexecuted-authoring".into(),
            goal: KnowledgeGoal::SemanticUnderstanding,
            source_paths: vec!["main.go".into()],
            understanding_items: vec!["entry".into()],
            prompt: "Explain exact synthetic source".into(),
            policy: "public-only-review".into(),
            max_context_units: 8000,
            source_spans: BTreeMap::new(),
        },
    };
    let job_request = artifact::publish(&f.context, &f.workspace, "t08-inputs", &job).unwrap();
    let before = tree(&f.workspace);
    let pending=invoke(&c,"summary.job.next",json!({"payload_revision":v04::PAYLOAD_REVISION,"workspace_root":f.workspace,"artifact_ref":job_request})).unwrap();
    assert_eq!(pending["status"], "needs_authoring");
    assert_eq!(pending["persistence"], "host_staged_input");
    assert_eq!(pending["execution_evidence"], "not_run");
    assert!(pending["job_artifact"].is_object());
    assert!(pending.get("artifact_ref").is_none());
    assert_eq!(tree(&f.workspace), before);
}
