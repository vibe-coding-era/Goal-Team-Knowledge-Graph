//! V0.2 T11A contract: a provider-free structural graph is rebuilt only from
//! local typed IR and passed document-relation receipts.  It must retain exact
//! provenance/evidence and survive file-shard readback without creating a
//! knowledge overlay.

use gtkg_core::graph_v3::{
    DocumentRelationGraphInputV3, StructuralGraphBuildInputV3, TypedIrGraphInputV3,
    build_structural_graph_v3, read_structural_graph_v3, write_structural_graph_v3,
};
use gtkg_extract::{build_typed_ir_v2, extract_path, resolve_local_typed_ir_v2};
use gtkg_protocol::v2::{
    SourceBaselineIdentityV2, SourceCaptureModeV2, SourceEligibilityV2,
    SourceSnapshotDenominatorV2, SourceSnapshotEntryV2, SourceSnapshotV2,
};
use sha2::{Digest, Sha256};

const SNAPSHOT_DIGEST: &str =
    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn snapshot(files: &[(&str, &str)]) -> SourceSnapshotV2 {
    SourceSnapshotV2 {
        schema_version: "gtkg.source-snapshot/v2".to_owned(),
        capture_mode: SourceCaptureModeV2::DirectoryExact,
        repository_id: "t11a-fixture".to_owned(),
        baseline: SourceBaselineIdentityV2 {
            kind: "directory".to_owned(),
            head: None,
            tree: None,
            status_sha256: SNAPSHOT_DIGEST.to_owned(),
        },
        inventory: files
            .iter()
            .map(|(path, source)| SourceSnapshotEntryV2 {
                logical_path: (*path).to_owned(),
                content_sha256: digest(source.as_bytes()),
                bytes: source.len() as u64,
            })
            .collect(),
        omissions: Vec::new(),
        denominator: SourceSnapshotDenominatorV2 {
            discovered_entries: files.len() as u64,
            admitted_entries: files.len() as u64,
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
    .expect("fixture snapshot")
}

fn typed_inputs() -> (SourceSnapshotV2, Vec<TypedIrGraphInputV3>) {
    let files = [
        ("src/lib.rs", "fn helper() {}\nfn caller() { helper(); }\n"),
        ("src/other.rs", "fn other() {}\n"),
    ];
    let snapshot = snapshot(&files);
    let temporary = tempfile::tempdir().expect("fixture root");
    let mut result = Vec::new();
    for (path, source) in files {
        let full = temporary.path().join(path);
        std::fs::create_dir_all(full.parent().expect("parent")).expect("parent directory");
        std::fs::write(&full, source).expect("source fixture");
        let extracted = extract_path(&full).expect("static extraction");
        let ir = build_typed_ir_v2(&snapshot, path, &extracted).expect("typed IR");
        result.push(TypedIrGraphInputV3 {
            ir: resolve_local_typed_ir_v2(&ir, source.as_bytes()).expect("local resolver"),
            source_bytes: source.as_bytes().to_vec(),
        });
    }
    (snapshot, result)
}

#[test]
fn structural_graph_is_deterministic_sharded_readable_and_has_no_knowledge_layer() {
    let (snapshot, typed_inputs) = typed_inputs();
    let input = StructuralGraphBuildInputV3 {
        source_snapshot_exact_set_sha256: snapshot.exact_set_sha256.clone(),
        typed_inputs,
        document_relations: Vec::<DocumentRelationGraphInputV3>::new(),
    };

    let first = build_structural_graph_v3(&input).expect("provider-free build");
    let second = build_structural_graph_v3(&input).expect("deterministic rebuild");
    assert_eq!(first, second);
    assert_eq!(first.layer, "structural_only");
    assert!(first.knowledge_overlay.is_none());
    assert!(first.nodes.iter().any(|node| node.kind == "code_symbol"));
    assert!(first.edges.iter().any(|edge| edge.kind == "calls"));
    assert!(
        first
            .nodes
            .iter()
            .filter(|node| node.kind == "code_symbol")
            .all(|node| !node.evidence.is_empty() && node.provenance.input_kind == "typed_ir")
    );
    assert!(
        first
            .edges
            .iter()
            .all(|edge| !edge.provenance.input_sha256.is_empty())
    );
    assert!(!first.shards.is_empty());

    let temporary = tempfile::tempdir().expect("artifact root");
    let output = temporary.path().join("graph-v3");
    write_structural_graph_v3(&output, &first).expect("write shards");
    let readback = read_structural_graph_v3(&output).expect("verified readback");
    assert_eq!(readback, first);
}

#[test]
fn graph_rejects_ir_from_another_snapshot_or_unpassed_document_relation() {
    let (snapshot, mut typed_inputs) = typed_inputs();
    typed_inputs[0].ir.source_snapshot_exact_set_sha256 = SNAPSHOT_DIGEST.to_owned();
    let error = build_structural_graph_v3(&StructuralGraphBuildInputV3 {
        source_snapshot_exact_set_sha256: snapshot.exact_set_sha256,
        typed_inputs,
        document_relations: Vec::new(),
    })
    .expect_err("mixed snapshot IR must fail closed");
    assert_eq!(error.code(), "E_V2_GRAPH_INPUT_SNAPSHOT_MISMATCH");
}

#[test]
fn graph_recomputes_typed_ir_and_evidence_before_building() {
    let (snapshot, mut typed_inputs) = typed_inputs();
    typed_inputs[0].ir.typed_ir_sha256 = SNAPSHOT_DIGEST.to_owned();
    let error = build_structural_graph_v3(&StructuralGraphBuildInputV3 {
        source_snapshot_exact_set_sha256: snapshot.exact_set_sha256,
        typed_inputs,
        document_relations: Vec::new(),
    })
    .expect_err("an old typed-IR digest cannot become graph evidence");
    assert_eq!(error.code(), "E_V2_GRAPH_INPUT_INVALID");
    assert!(error.to_string().contains("exact source/evidence readback"));
}

#[test]
fn document_relation_inputs_are_structural_citations_not_knowledge_claims() {
    let (snapshot, typed_inputs) = typed_inputs();
    let relation = gtkg_core::document_relations::DocumentRelationReceiptV2 {
        schema_version: "gtkg.document-relation-receipt/v2".to_owned(),
        document_path: "/host/path/README.md".to_owned(),
        document_sha256: digest(b"# README\n"),
        relation: gtkg_core::document_relations::DocumentRelationValidationV2 {
            format: gtkg_core::document_relations::DocumentRelationFormatV2::Markdown,
            status: gtkg_core::document_relations::DocumentRelationStatusV2::Passed,
            binding: gtkg_core::document_relations::T03RelationBindingV2 {
                raw_spec_pin: gtkg_protocol::v2::OkfSpecPinV2::new(
                    "0.2",
                    "62432a095456147ee71e70ac6e4dc0d2dea3ac30",
                    "sha256:26aa5da029278939f914e578107242d9607d4f2dc5fe153272b82f9ed1030101",
                )
                .expect("pin"),
                corpus_manifest_path: "deliverables/corpus.json".to_owned(),
                corpus_manifest_sha256: SNAPSHOT_DIGEST.to_owned(),
                receipt_path: "deliverables/receipt.json".to_owned(),
                receipt_sha256: SNAPSHOT_DIGEST.to_owned(),
                corpus_id: "current-okf".to_owned(),
            },
            source_ids: vec!["handbook".to_owned()],
            footnote_ids: vec!["handbook".to_owned()],
            issues: Vec::new(),
        },
    };
    let graph = build_structural_graph_v3(&StructuralGraphBuildInputV3 {
        source_snapshot_exact_set_sha256: snapshot.exact_set_sha256,
        typed_inputs,
        document_relations: vec![DocumentRelationGraphInputV3 {
            logical_path: "README.md".to_owned(),
            receipt: relation,
        }],
    })
    .expect("passed local relation is a structural input");
    assert!(graph.edges.iter().any(|edge| edge.kind == "cites_source"));
    assert!(graph.nodes.iter().all(|node| !node.id.contains("claim:")));
    assert!(graph.knowledge_overlay.is_none());
    let host_paths = graph
        .nodes
        .iter()
        .map(|node| node.source_logical_path.as_str())
        .collect::<Vec<_>>();
    assert!(!host_paths.contains(&"/host/path/README.md"));
}

#[test]
fn graph_readback_rejects_tampered_shard_bytes() {
    let (snapshot, typed_inputs) = typed_inputs();
    let graph = build_structural_graph_v3(&StructuralGraphBuildInputV3 {
        source_snapshot_exact_set_sha256: snapshot.exact_set_sha256,
        typed_inputs,
        document_relations: Vec::new(),
    })
    .expect("build graph");
    let temporary = tempfile::tempdir().expect("artifact root");
    let output = temporary.path().join("graph-v3");
    write_structural_graph_v3(&output, &graph).expect("write graph");
    let shard = output.join(&graph.shards[0].relative_path);
    let bytes = std::fs::read_to_string(&shard).expect("read shard");
    std::fs::write(
        &shard,
        bytes.replacen("gtkg.structural-graph-shard/v3", "tampered-shard-schema", 1),
    )
    .expect("tamper shard");
    let error = read_structural_graph_v3(&output).expect_err("tamper must fail readback");
    assert_eq!(error.code(), "E_V2_GRAPH_READBACK_INVALID");
}

#[test]
fn graph_readback_rejects_semantically_equivalent_whitespace_byte_tamper() {
    let (snapshot, typed_inputs) = typed_inputs();
    let graph = build_structural_graph_v3(&StructuralGraphBuildInputV3 {
        source_snapshot_exact_set_sha256: snapshot.exact_set_sha256,
        typed_inputs,
        document_relations: Vec::new(),
    })
    .expect("build graph");
    let temporary = tempfile::tempdir().expect("artifact root");
    let output = temporary.path().join("graph-v3");
    write_structural_graph_v3(&output, &graph).expect("write graph");
    let shard = output.join(&graph.shards[0].relative_path);
    let mut bytes = std::fs::read(&shard).expect("read raw shard");
    bytes.push(b'\n');
    std::fs::write(&shard, bytes).expect("append JSON-insignificant whitespace");
    let error = read_structural_graph_v3(&output).expect_err("raw byte tamper must fail");
    assert_eq!(error.code(), "E_V2_GRAPH_READBACK_INVALID");
}
