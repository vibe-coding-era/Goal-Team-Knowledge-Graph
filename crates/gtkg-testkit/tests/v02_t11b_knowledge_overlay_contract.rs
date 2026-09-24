//! V0.2 T11B: accepted claims form a separate, tamper-evident knowledge
//! overlay. The artifact is not a Provider output and cannot alter Graph v3.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use gtkg_core::claim_aware_query_v2::execute_claim_aware_hybrid_query_v2;
use gtkg_core::claim_v2::{
    AtomicClaimV2, ClaimEvidenceRefV2, ClaimModalityV2, ClaimPolarityV2, ClaimVerificationInputV2,
    RiskClassV2, T03ClaimEvidenceV2, T04ClaimEvidenceV2, verify_atomic_claims_v2,
};
use gtkg_core::context_v2::{
    ContextChunkV2, ContextPackRequestV2, ContextSourceV2, LocalTokenizerV2, build_context_pack_v2,
};
use gtkg_core::document_relations::{
    DocumentRelationFormatV2, DocumentRelationReceiptV2, DocumentRelationStatusV2,
    DocumentRelationValidationV2, T03RelationBindingV2,
};
use gtkg_core::graph_v3::{
    DocumentRelationGraphInputV3, StructuralGraphBuildInputV3, TypedIrGraphInputV3,
    build_structural_graph_v3, write_structural_graph_v3,
};
use gtkg_core::knowledge_overlay_v2::{
    KnowledgeOverlayBuildInputV2, build_knowledge_overlay_v2, read_knowledge_overlay_v2,
    write_knowledge_overlay_v2,
};
use gtkg_core::provider_v2::SummaryJobV2;
use gtkg_core::{CallContext, EffectPolicy, TransportKind};
use gtkg_extract::{build_typed_ir_v2, extract_path, resolve_local_typed_ir_v2};
use gtkg_protocol::v2::{
    OkfSpecPinV2, OperationRequestV2, SourceBaselineIdentityV2, SourceCaptureModeV2,
    SourceEligibilityV2, SourceSnapshotDenominatorV2, SourceSnapshotEntryV2, SourceSnapshotV2,
    V2ErrorCode, V2OperationId,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use tempfile::tempdir;

const DIGEST: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const CURRENT_PIN_SHA256: &str =
    "sha256:26aa5da029278939f914e578107242d9607d4f2dc5fe153272b82f9ed1030101";

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

fn sha(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn snapshot(source: &str) -> SourceSnapshotV2 {
    SourceSnapshotV2 {
        schema_version: "gtkg.source-snapshot/v2".to_owned(),
        capture_mode: SourceCaptureModeV2::DirectoryExact,
        repository_id: "t11b".to_owned(),
        baseline: SourceBaselineIdentityV2 {
            kind: "directory".to_owned(),
            head: None,
            tree: None,
            status_sha256: DIGEST.to_owned(),
        },
        inventory: vec![SourceSnapshotEntryV2 {
            logical_path: "src/stable.rs".to_owned(),
            content_sha256: sha(source.as_bytes()),
            bytes: source.len() as u64,
        }],
        omissions: Vec::new(),
        denominator: SourceSnapshotDenominatorV2 {
            discovered_entries: 1,
            admitted_entries: 1,
            omitted_entries: 0,
        },
        exact_set_sha256: String::new(),
        eligibility: SourceEligibilityV2 {
            development_eligible: true,
            source_release_candidate: false,
            environment_ready: false,
            release_ready: false,
        },
    }
    .with_exact_set_digest()
    .expect("snapshot")
}

fn t03_binding() -> T03ClaimEvidenceV2 {
    T03ClaimEvidenceV2::from_receipt(
        &workspace_root(),
        OkfSpecPinV2::new(
            "0.2",
            "62432a095456147ee71e70ac6e4dc0d2dea3ac30",
            CURRENT_PIN_SHA256,
        )
        .expect("pin"),
        &workspace_root().join("deliverables/v02-t03/current-okf-normative-corpus.json"),
        &workspace_root().join("deliverables/v02-t03/current-okf-normative-corpus-receipt.json"),
    )
    .expect("T03 binding")
}

fn t04_receipt() -> T04ClaimEvidenceV2 {
    let context = CallContext::restricted(
        TransportKind::Test,
        vec![workspace_root()],
        EffectPolicy::ReadOnly,
    )
    .expect("context");
    T04ClaimEvidenceV2::load_local(
        &context,
        &workspace_root().join("crates/gtkg-testkit/fixtures/v02_t04/local-corpus-contract.json"),
    )
    .expect("T04 receipt")
}

fn relation() -> DocumentRelationGraphInputV3 {
    DocumentRelationGraphInputV3 {
        logical_path: "README.md".to_owned(),
        receipt: DocumentRelationReceiptV2 {
            schema_version: "gtkg.document-relation-receipt/v2".to_owned(),
            document_path: "/host/README.md".to_owned(),
            document_sha256: sha(b"# README\n"),
            relation: DocumentRelationValidationV2 {
                format: DocumentRelationFormatV2::Markdown,
                status: DocumentRelationStatusV2::Passed,
                binding: T03RelationBindingV2 {
                    raw_spec_pin: OkfSpecPinV2::new(
                        "0.2",
                        "62432a095456147ee71e70ac6e4dc0d2dea3ac30",
                        CURRENT_PIN_SHA256,
                    )
                    .expect("pin"),
                    corpus_manifest_path: "deliverables/v02-t03/current-okf-normative-corpus.json"
                        .to_owned(),
                    corpus_manifest_sha256: DIGEST.to_owned(),
                    receipt_path: "deliverables/v02-t03/current-okf-normative-corpus-receipt.json"
                        .to_owned(),
                    receipt_sha256: DIGEST.to_owned(),
                    corpus_id: "current-okf".to_owned(),
                },
                source_ids: vec!["handbook".to_owned()],
                footnote_ids: vec!["handbook".to_owned()],
                issues: Vec::new(),
            },
        },
    }
}

fn fixture_with_unknown(include_unknown: bool) -> (KnowledgeOverlayBuildInputV2, AtomicClaimV2) {
    let source = "fn stable() {}\n";
    let snapshot = snapshot(source);
    let temporary = tempdir().expect("temp");
    let path = temporary.path().join("stable.rs");
    std::fs::write(&path, source).expect("source");
    let extracted = extract_path(&path).expect("extract");
    let ir = resolve_local_typed_ir_v2(
        &build_typed_ir_v2(&snapshot, "src/stable.rs", &extracted).expect("IR"),
        source.as_bytes(),
    )
    .expect("resolve");
    let evidence = ir.evidence.first().expect("evidence");
    let context_source = ContextSourceV2::new(
        ir.source_snapshot_exact_set_sha256.clone(),
        "src/stable.rs",
        source,
    );
    let chunk = ContextChunkV2::new(
        "stable",
        "focus",
        0,
        &context_source,
        evidence.byte_start,
        evidence.byte_end,
        evidence.id.clone(),
    )
    .expect("chunk");
    let request = ContextPackRequestV2 {
        source_snapshot_exact_set_sha256: ir.source_snapshot_exact_set_sha256.clone(),
        tokenizer: LocalTokenizerV2::controlled_local(),
        token_budget: 10,
        required_chunk_ids: vec!["stable".to_owned()],
        sources: vec![context_source],
        chunks: vec![chunk],
    };
    let selected = build_context_pack_v2(&request)
        .expect("pack")
        .read_selected_bytes(&request)
        .expect("selected");
    let job = SummaryJobV2::local_only("t11b", &selected).expect("job");
    let claim = AtomicClaimV2 {
        claim_id: "stable-declared".to_owned(),
        subject: "stable".to_owned(),
        predicate: "is_declared".to_owned(),
        object: "function".to_owned(),
        polarity: ClaimPolarityV2::Positive,
        modality: ClaimModalityV2::Asserted,
        natural_language: source[evidence.byte_start as usize..evidence.byte_end as usize]
            .to_owned(),
        evidence: vec![ClaimEvidenceRefV2 {
            evidence_id: evidence.id.clone(),
            context_chunk_id: "stable".to_owned(),
            source_snapshot_exact_set_sha256: evidence.source_snapshot_exact_set_sha256.clone(),
            source_logical_path: evidence.source_logical_path.clone(),
            source_sha256: evidence.source_sha256.clone(),
            byte_start: evidence.byte_start,
            byte_end: evidence.byte_end,
            snippet_sha256: evidence.snippet_sha256.clone(),
        }],
        risk_class: RiskClassV2::Normal,
    };
    let mut claims = vec![claim.clone()];
    if include_unknown {
        let mut unknown = claim.clone();
        unknown.claim_id = "stable-unknown".to_owned();
        unknown.modality = ClaimModalityV2::Unknown;
        claims.push(unknown);
    }
    let verified = verify_atomic_claims_v2(
        ClaimVerificationInputV2 {
            source_bytes: source.as_bytes(),
            typed_ir: &ir,
            selected_context: &selected,
            summary_job: &job,
            t03_evidence: &t03_binding(),
            t04_evidence: &t04_receipt(),
        },
        &claims,
    )
    .expect("T10");
    let document_relation = relation();
    let graph = build_structural_graph_v3(&StructuralGraphBuildInputV3 {
        source_snapshot_exact_set_sha256: snapshot.exact_set_sha256,
        typed_inputs: vec![TypedIrGraphInputV3 {
            ir,
            source_bytes: source.as_bytes().to_vec(),
        }],
        document_relations: vec![document_relation.clone()],
    })
    .expect("T11A");
    (
        KnowledgeOverlayBuildInputV2 {
            structural_graph: graph,
            claims,
            verification_receipt: verified.receipt,
            accepted_claim_set: verified.accepted,
            document_relations: vec![document_relation],
        },
        claim,
    )
}

fn fixture() -> (KnowledgeOverlayBuildInputV2, AtomicClaimV2) {
    fixture_with_unknown(false)
}

#[test]
fn overlay_is_deterministic_separate_from_structural_graph_and_readable() {
    let (input, _) = fixture();
    let first = build_knowledge_overlay_v2(&input).expect("overlay");
    let second = build_knowledge_overlay_v2(&input).expect("rebuild");
    assert_eq!(first, second);
    assert_eq!(first.layer, "knowledge_overlay");
    assert_eq!(input.structural_graph.layer, "structural_only");
    assert!(input.structural_graph.knowledge_overlay.is_none());
    assert!(first.nodes.iter().any(|node| node.kind == "accepted_claim"));
    assert!(first.nodes.iter().any(|node| node.kind == "source"));
    assert!(first.nodes.iter().any(|node| node.kind == "footnote"));
    assert!(first.nodes.iter().any(|node| node.kind == "provenance"));
    assert!(
        first
            .nodes
            .iter()
            .filter(|node| node.kind == "accepted_claim")
            .all(|node| !node.structural_evidence_ids.is_empty())
    );

    let temporary = tempdir().expect("artifact root");
    let output = temporary.path().join("overlay");
    write_knowledge_overlay_v2(&output, &first).expect("write");
    assert_eq!(read_knowledge_overlay_v2(&output).expect("readback"), first);
}

#[test]
fn overlay_rejects_claim_rewrite_after_t10_and_structural_snapshot_drift() {
    let (mut input, _) = fixture();
    input.claims[0].predicate = "rewritten_after_verification".to_owned();
    let error = build_knowledge_overlay_v2(&input).expect_err("T10 proposal binding");
    assert_eq!(error.code(), "E_V2_OVERLAY_T10_PROPOSAL_MISMATCH");

    let (mut input, _) = fixture();
    input.structural_graph.source_snapshot_exact_set_sha256 = DIGEST.to_owned();
    let error = build_knowledge_overlay_v2(&input).expect_err("structural graph tamper");
    assert_eq!(error.code(), "E_V2_OVERLAY_INPUT_INVALID");
}

#[test]
fn partial_t10_input_binds_the_complete_proposal_but_never_accepts_unknown_claims() {
    let (input, _) = fixture_with_unknown(true);
    assert_eq!(
        input.accepted_claim_set.state,
        gtkg_core::claim_v2::ClaimSetStateV2::AcceptedPartialWithAbstention
    );
    assert_eq!(input.claims.len(), 2, "complete T10 proposal enters T11B");
    assert_eq!(input.accepted_claim_set.accepted_claim_ids.len(), 1);
    let overlay = build_knowledge_overlay_v2(&input).expect("partial overlay");
    let accepted = overlay
        .nodes
        .iter()
        .filter(|node| node.kind == "accepted_claim")
        .collect::<Vec<_>>();
    assert_eq!(accepted.len(), 1);
    assert_eq!(accepted[0].claim_id.as_deref(), Some("stable-declared"));
    assert!(overlay.nodes.iter().any(|node| {
        node.kind == "abstention" && node.claim_id.as_deref() == Some("stable-unknown")
    }));
    assert!(
        overlay
            .edges
            .iter()
            .any(|edge| edge.kind == "abstains_from")
    );
    assert!(
        !accepted
            .iter()
            .any(|node| node.claim_id.as_deref() == Some("stable-unknown"))
    );

    let mut incomplete = input.clone();
    incomplete
        .claims
        .retain(|claim| claim.claim_id != "stable-unknown");
    let error = build_knowledge_overlay_v2(&incomplete).expect_err("complete proposal is required");
    assert_eq!(error.code(), "E_V2_OVERLAY_T10_PROPOSAL_MISMATCH");
}

#[test]
fn overlay_readback_rejects_json_whitespace_byte_tamper() {
    let (input, _) = fixture();
    let overlay = build_knowledge_overlay_v2(&input).expect("overlay");
    let temporary = tempdir().expect("artifact root");
    let output = temporary.path().join("overlay");
    write_knowledge_overlay_v2(&output, &overlay).expect("write");
    let path = output.join("overlay.json");
    let mut bytes = std::fs::read(&path).expect("overlay bytes");
    bytes.push(b'\n');
    std::fs::write(&path, bytes).expect("tamper");
    let error = read_knowledge_overlay_v2(&output).expect_err("byte tamper");
    assert_eq!(error.code(), "E_V2_OVERLAY_READBACK_INVALID");
}

#[test]
fn claim_aware_hybrid_query_reads_verified_layers_without_promoting_abstentions_or_structure() {
    let (input, _) = fixture_with_unknown(true);
    let graph = input.structural_graph.clone();
    let overlay = build_knowledge_overlay_v2(&input).expect("overlay");
    let temporary = tempdir().expect("artifact root");
    let graph_root = temporary.path().join("graph");
    let overlay_root = temporary.path().join("overlay");
    write_structural_graph_v3(&graph_root, &graph).expect("graph shards");
    write_knowledge_overlay_v2(&overlay_root, &overlay).expect("overlay artifact");

    let response = execute_claim_aware_hybrid_query_v2(
        &graph_root,
        &overlay_root,
        &json!({ "query": "stable", "max_results": 100 }),
    )
    .expect("claim-aware query");
    assert_eq!(response["mode"], "claim_aware_hybrid");
    assert_eq!(
        response["evidence_pack"]["graph_readback"]["graph_sha256"],
        graph.graph_sha256
    );
    assert_eq!(
        response["evidence_pack"]["overlay_readback"]["overlay_sha256"],
        overlay.overlay_sha256
    );
    let matches = response["result"]["matches"].as_array().expect("matches");
    assert!(matches.iter().any(|entry| {
        entry["kind"] == "accepted_claim"
            && entry["claim_id"] == "stable-declared"
            && entry["knowledge_state"] == "accepted_grounded"
    }));
    assert!(matches.iter().any(|entry| {
        entry["kind"] == "abstention"
            && entry["claim_id"] == "stable-unknown"
            && entry["knowledge_state"] == "abstention"
    }));
    assert!(matches.iter().any(|entry| {
        entry["kind"] == "structural_node"
            && entry["knowledge_state"] == "structural_only"
            && entry.get("claim_id").is_none()
    }));
    assert!(
        response["evidence_pack"]["evidence"]
            .as_array()
            .is_some_and(|items| !items.is_empty())
    );
}

#[test]
fn claim_aware_hybrid_query_fails_closed_on_unbounded_or_unauthorized_payload_fields() {
    let (input, _) = fixture();
    let graph = input.structural_graph.clone();
    let overlay = build_knowledge_overlay_v2(&input).expect("overlay");
    let temporary = tempdir().expect("artifact root");
    let graph_root = temporary.path().join("graph");
    let overlay_root = temporary.path().join("overlay");
    write_structural_graph_v3(&graph_root, &graph).expect("graph shards");
    write_knowledge_overlay_v2(&overlay_root, &overlay).expect("overlay artifact");

    let error = execute_claim_aware_hybrid_query_v2(
        &graph_root,
        &overlay_root,
        &json!({ "query": "stable", "knowledge_state": "accepted_grounded" }),
    )
    .expect_err("callers cannot request a state promotion");
    assert_eq!(error.code(), "E_V2_CLAIM_QUERY_INVALID");
    let error = execute_claim_aware_hybrid_query_v2(
        &graph_root,
        &overlay_root,
        &json!({ "query": "stable", "max_results": 1001 }),
    )
    .expect_err("result limit must remain bounded");
    assert_eq!(error.code(), "E_V2_CLAIM_QUERY_INVALID");
}

#[test]
fn graph_search_v2_dispatcher_requires_two_workspace_bound_verified_artifacts() {
    let (input, _) = fixture();
    let graph = input.structural_graph.clone();
    let overlay = build_knowledge_overlay_v2(&input).expect("overlay");
    let temporary = tempdir().expect("artifact root");
    let graph_root = temporary.path().join("graph");
    let overlay_root = temporary.path().join("overlay");
    write_structural_graph_v3(&graph_root, &graph).expect("graph shards");
    write_knowledge_overlay_v2(&overlay_root, &overlay).expect("overlay artifact");
    let context = CallContext::restricted(
        TransportKind::Test,
        vec![temporary.path().to_path_buf()],
        EffectPolicy::ReadOnly,
    )
    .expect("context");
    let response = gtkg_core::Dispatcher
        .execute_v2(
            &context,
            OperationRequestV2::new(
                "graph.search",
                "t12b-v2",
                json!({
                    "graph_artifact_path": "graph",
                    "overlay_artifact_path": "overlay",
                    "query": "stable",
                }),
            ),
        )
        .expect("v2 graph search");
    assert_eq!(response.operation_id, V2OperationId::GraphSearch);
    assert_eq!(response.result["mode"], "claim_aware_hybrid");

    #[cfg(unix)]
    {
        let overlay_link = temporary.path().join("overlay-link");
        std::os::unix::fs::symlink(&overlay_root, &overlay_link).expect("overlay root symlink");
        let error = gtkg_core::Dispatcher
            .execute_v2(
                &context,
                OperationRequestV2::new(
                    "graph.search",
                    "t12b-lexical-symlink",
                    json!({
                        "graph_artifact_path": "graph",
                        "overlay_artifact_path": "overlay-link",
                        "query": "stable",
                    }),
                ),
            )
            .expect_err("dispatcher must reject the lexical symlink before canonicalization");
        assert_eq!(error.error.code, V2ErrorCode::InvalidRequest);
    }

    let error = gtkg_core::Dispatcher
        .execute_v2(
            &context,
            OperationRequestV2::new(
                "graph.search",
                "t12b-escape",
                json!({
                    "graph_artifact_path": "graph",
                    "overlay_artifact_path": "../overlay",
                    "query": "stable",
                }),
            ),
        )
        .expect_err("overlay escape must fail before readback");
    assert_eq!(error.error.code, V2ErrorCode::InvalidRequest);

    let overlay_file = overlay_root.join("overlay.json");
    let mut bytes = std::fs::read(&overlay_file).expect("overlay bytes");
    bytes.push(b' ');
    std::fs::write(&overlay_file, bytes).expect("tamper overlay");
    let error = gtkg_core::Dispatcher
        .execute_v2(
            &context,
            OperationRequestV2::new(
                "graph.search",
                "t12b-readback",
                json!({
                    "graph_artifact_path": "graph",
                    "overlay_artifact_path": "overlay",
                    "query": "stable",
                }),
            ),
        )
        .expect_err("tampered overlay must be a distinct readback failure");
    assert_eq!(error.error.code, V2ErrorCode::ClaimAwareQueryReadbackFailed);
}

#[cfg(unix)]
#[test]
fn overlay_readback_rejects_symlinked_and_hardlinked_artifact_files() {
    let (input, _) = fixture();
    let overlay = build_knowledge_overlay_v2(&input).expect("overlay");
    let temporary = tempdir().expect("artifact root");

    let symlinked = temporary.path().join("symlinked");
    write_knowledge_overlay_v2(&symlinked, &overlay).expect("write overlay");
    let external_manifest = temporary.path().join("external-manifest.json");
    std::fs::copy(symlinked.join("manifest.json"), &external_manifest).expect("copy manifest");
    std::fs::remove_file(symlinked.join("manifest.json")).expect("remove manifest");
    std::os::unix::fs::symlink(&external_manifest, symlinked.join("manifest.json"))
        .expect("manifest symlink");
    let error = read_knowledge_overlay_v2(&symlinked).expect_err("manifest symlink must fail");
    assert_eq!(error.code(), "E_V2_OVERLAY_READBACK_INVALID");

    let hardlinked = temporary.path().join("hardlinked");
    write_knowledge_overlay_v2(&hardlinked, &overlay).expect("write overlay");
    std::fs::hard_link(
        hardlinked.join("overlay.json"),
        temporary.path().join("external-overlay.json"),
    )
    .expect("overlay hardlink");
    let error = read_knowledge_overlay_v2(&hardlinked).expect_err("overlay hardlink must fail");
    assert_eq!(error.code(), "E_V2_OVERLAY_READBACK_INVALID");
}

#[cfg(unix)]
#[test]
fn claim_aware_hybrid_query_rejects_a_symlinked_overlay_root() {
    let (input, _) = fixture();
    let graph = input.structural_graph.clone();
    let overlay = build_knowledge_overlay_v2(&input).expect("overlay");
    let temporary = tempdir().expect("artifact root");
    let graph_root = temporary.path().join("graph");
    let overlay_root = temporary.path().join("overlay");
    let overlay_link = temporary.path().join("overlay-link");
    write_structural_graph_v3(&graph_root, &graph).expect("graph shards");
    write_knowledge_overlay_v2(&overlay_root, &overlay).expect("overlay artifact");
    std::os::unix::fs::symlink(&overlay_root, &overlay_link).expect("overlay root symlink");

    let error = execute_claim_aware_hybrid_query_v2(
        &graph_root,
        &overlay_link,
        &json!({ "query": "stable" }),
    )
    .expect_err("a symlinked overlay root cannot be a verified query input");
    assert_eq!(error.code(), "E_V2_CLAIM_QUERY_BINDING_MISMATCH");
}

#[test]
fn graph_search_success_has_cli_mcp_structured_content_parity() {
    let (input, _) = fixture();
    let graph = input.structural_graph.clone();
    let overlay = build_knowledge_overlay_v2(&input).expect("overlay");
    let temporary = tempdir().expect("artifact root");
    let graph_root = temporary.path().join("graph");
    let overlay_root = temporary.path().join("overlay");
    write_structural_graph_v3(&graph_root, &graph).expect("graph shards");
    write_knowledge_overlay_v2(&overlay_root, &overlay).expect("overlay artifact");
    let request = OperationRequestV2::new(
        "graph.search",
        "t12b-cli-mcp-success",
        json!({
            "graph_artifact_path": "graph",
            "overlay_artifact_path": "overlay",
            "query": "stable",
        }),
    );
    let binary = std::env::var_os("GTKG_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| workspace_root().join("target/debug/gtkg"));
    assert!(binary.is_file(), "build the GTKG CLI before this E2E test");

    let mut cli = Command::new(&binary)
        .args([
            "v2-op",
            "graph.search",
            "--request",
            "-",
            "--output",
            "json",
        ])
        .current_dir(temporary.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn CLI");
    serde_json::to_writer(cli.stdin.as_mut().expect("CLI stdin"), &request).expect("CLI request");
    drop(cli.stdin.take());
    let cli_output = cli.wait_with_output().expect("wait CLI");
    assert!(
        cli_output.status.success(),
        "graph.search CLI failed: {}",
        String::from_utf8_lossy(&cli_output.stderr)
    );
    let cli_response: serde_json::Value =
        serde_json::from_slice(&cli_output.stdout).expect("CLI response JSON");

    let mut mcp = Command::new(&binary)
        .args(["mcp", "serve", "--protocol", "v2", "--stdio"])
        .current_dir(temporary.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn MCP");
    serde_json::to_writer(
        mcp.stdin.as_mut().expect("MCP stdin"),
        &json!({
            "jsonrpc": "2.0",
            "id": "t12b-success",
            "method": "tools/call",
            "params": {"name": "gtkg_v2_graph_search", "arguments": request}
        }),
    )
    .expect("MCP request");
    mcp.stdin
        .as_mut()
        .expect("MCP stdin")
        .write_all(b"\n")
        .expect("MCP newline");
    mcp.stdin
        .as_mut()
        .expect("MCP stdin")
        .flush()
        .expect("MCP flush");
    let mut line = String::new();
    BufReader::new(mcp.stdout.take().expect("MCP stdout"))
        .read_line(&mut line)
        .expect("MCP response");
    let _ = mcp.kill();
    let _ = mcp.wait();
    let mcp_response: serde_json::Value = serde_json::from_str(&line).expect("MCP response JSON");
    assert_eq!(mcp_response["result"]["isError"], false);
    assert_eq!(mcp_response["result"]["structuredContent"], cli_response);
    assert_eq!(
        mcp_response["result"]["content"][0]["text"],
        serde_json::to_string(&cli_response).expect("CLI response serializes")
    );
}
