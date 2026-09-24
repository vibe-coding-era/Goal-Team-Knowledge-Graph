use std::fs;
use std::path::PathBuf;

use gtkg_core::v03::query::{
    AdjacencyEdgeInputV1, FileQueryErrorV1, FileQueryPageV1, LexicalDocumentV1,
    build_adjacency_routing_index_v1, build_lexical_shard_v1, execute_file_query_page_v1,
    execute_file_query_page_with_pre_shard_read_hook_v1,
    file_query_index_manifest_content_sha256_v1, lexical_routing_catalog_content_sha256_v1,
    write_file_query_index_v1,
};
use gtkg_core::{CallContext, EffectPolicy, TransportKind};
use gtkg_protocol::FileReceiptRef;
use gtkg_protocol::v03::query::{
    AdjacencyDirectionV1, FileQueryExpectedIdentitiesV1, FileQueryIndexManifestV1,
    FileQueryLookupV1, FileQueryRequestV1, QueryResolutionStateV1, QueryTruncationStateV1,
};

fn digest(label: &str) -> String {
    use sha2::{Digest, Sha256};
    format!("sha256:{}", hex::encode(Sha256::digest(label.as_bytes())))
}

fn bytes_digest(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn document(node_id: &str, evidence_ref: &str, text: &str) -> LexicalDocumentV1 {
    LexicalDocumentV1 {
        node_id: node_id.to_owned(),
        evidence_ref: evidence_ref.to_owned(),
        text: text.to_owned(),
    }
}

fn edge(edge_id: &str, source: &str, target: &str) -> AdjacencyEdgeInputV1 {
    AdjacencyEdgeInputV1 {
        edge_id: edge_id.to_owned(),
        source_node_id: source.to_owned(),
        target_node_id: target.to_owned(),
        resolution_state: QueryResolutionStateV1::Resolved,
        evidence_ref: format!("evidence:{edge_id}"),
    }
}

struct IndexFixture {
    workspace: tempfile::TempDir,
    index_root: PathBuf,
    manifest_ref: FileReceiptRef,
    expected: FileQueryExpectedIdentitiesV1,
}

impl IndexFixture {
    fn new(lexical_groups: Vec<(&str, Vec<LexicalDocumentV1>)>) -> Self {
        let workspace = tempfile::tempdir().unwrap();
        let index_root = workspace.path().join(".gtkg/query-index");
        let context = CallContext::restricted(
            TransportKind::Test,
            vec![workspace.path().to_path_buf()],
            EffectPolicy::WorkspaceWrite,
        )
        .unwrap();
        let lexical = lexical_groups
            .into_iter()
            .map(|(shard_id, documents)| build_lexical_shard_v1(shard_id, &documents).unwrap())
            .collect::<Vec<_>>();
        let adjacency = build_adjacency_routing_index_v1(
            &[
                "node-client".to_owned(),
                "node-store".to_owned(),
                "服务:认证".to_owned(),
            ],
            &[
                edge("edge-client-auth", "node-client", "服务:认证"),
                edge("edge-auth-store", "服务:认证", "node-store"),
            ],
        )
        .unwrap();
        let expected = FileQueryExpectedIdentitiesV1 {
            source_identity: digest("source"),
            graph_identity: digest("graph"),
            overlay_identity: digest("overlay"),
        };
        let manifest_ref =
            write_file_query_index_v1(&context, &index_root, &expected, &lexical, &adjacency)
                .unwrap();
        Self {
            workspace,
            index_root,
            manifest_ref,
            expected,
        }
    }

    fn basic() -> Self {
        Self::new(vec![
            (
                "lex-auth",
                vec![document(
                    "node-auth",
                    "evidence:auth",
                    "authentication token verifier",
                )],
            ),
            (
                "lex-billing",
                vec![document(
                    "node-billing",
                    "evidence:billing",
                    "billing invoice renderer",
                )],
            ),
        ])
    }

    fn context(&self) -> CallContext {
        CallContext::restricted(
            TransportKind::Test,
            vec![self.workspace.path().to_path_buf()],
            EffectPolicy::WorkspaceWrite,
        )
        .unwrap()
    }

    fn query(&self, request: FileQueryRequestV1) -> Result<FileQueryPageV1, FileQueryErrorV1> {
        execute_file_query_page_v1(
            &self.context(),
            &self.index_root,
            &self.manifest_ref,
            &self.expected,
            &request,
        )
    }

    fn manifest(&self) -> FileQueryIndexManifestV1 {
        let bytes = fs::read(self.index_root.join(&self.manifest_ref.path)).unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    fn selected_file(&self, shard_id: &str) -> PathBuf {
        let manifest = self.manifest();
        let shard = manifest
            .shard_files
            .iter()
            .find(|shard| shard.shard_id == shard_id)
            .unwrap();
        self.index_root.join(&shard.relative_path)
    }

    fn forge_manifest(&self, mut manifest: FileQueryIndexManifestV1) -> FileReceiptRef {
        manifest.manifest_sha256 = file_query_index_manifest_content_sha256_v1(&manifest);
        let bytes = serde_json::to_vec_pretty(&manifest).unwrap();
        let path = format!(
            "manifests/{}.json",
            manifest.manifest_sha256.strip_prefix("sha256:").unwrap()
        );
        let absolute = self.index_root.join(&path);
        fs::create_dir_all(absolute.parent().unwrap()).unwrap();
        fs::write(&absolute, &bytes).unwrap();
        FileReceiptRef {
            path,
            sha256: bytes_digest(&bytes),
        }
    }
}

fn search(query: &str, max_results: u64, continuation: Option<String>) -> FileQueryRequestV1 {
    FileQueryRequestV1 {
        lookup: FileQueryLookupV1::Search {
            query: query.to_owned(),
        },
        max_results,
        continuation,
    }
}

#[test]
fn q03_plans_before_read_and_opens_only_the_selected_lexical_shard() {
    let fixture = IndexFixture::basic();
    let page = fixture.query(search("authentication", 10, None)).unwrap();
    assert_eq!(page.lexical_hits.len(), 1);
    assert_eq!(page.lexical_hits[0].node_id, "node-auth");
    assert_eq!(page.opened_shards, ["lex-auth"]);
    assert_eq!(page.receipt.selected_shards, ["lex-auth"]);
    assert!(
        page.receipt
            .excluded_shards
            .contains(&"lex-billing".to_owned())
    );
    assert_eq!(page.shard_files_opened, 1);
    assert!(page.manifest_bytes_read > 0);
    assert!(page.shard_bytes_read > 0);
    assert_eq!(
        page.receipt.bytes_read,
        page.manifest_bytes_read + page.shard_bytes_read
    );
    assert!(page.plan_completed_before_shard_read);
    assert_eq!(page.full_graph_read_count, 0);
    assert_eq!(page.database_read_count, 0);
    assert_eq!(page.network_call_count, 0);
    assert_eq!(page.daemon_call_count, 0);
}

#[test]
fn q03_adjacency_plan_routes_one_directional_shard_without_opening_lexical_files() {
    let fixture = IndexFixture::basic();
    let page = fixture
        .query(FileQueryRequestV1 {
            lookup: FileQueryLookupV1::Adjacency {
                node_id: "服务:认证".to_owned(),
                direction: AdjacencyDirectionV1::Outgoing,
            },
            max_results: 10,
            continuation: None,
        })
        .unwrap();
    assert_eq!(page.adjacency_edges.len(), 1);
    assert_eq!(page.adjacency_edges[0].edge_id, "edge-auth-store");
    assert_eq!(page.shard_files_opened, 1);
    assert_eq!(page.receipt.selected_shards.len(), 1);
    assert!(page.opened_shards[0].starts_with("adj-"));
    assert!(
        page.receipt
            .excluded_shards
            .contains(&"lex-auth".to_owned())
    );
    assert_eq!(page.full_graph_read_count, 0);
}

#[test]
fn q03_continuation_is_opaque_digest_bound_and_never_silently_cuts_results() {
    let documents = (0..5)
        .map(|index| {
            document(
                &format!("node-{index}"),
                &format!("evidence:{index}"),
                "shared_query result",
            )
        })
        .collect();
    let fixture = IndexFixture::new(vec![("lex-page", documents)]);
    let first = fixture.query(search("shared_query", 2, None)).unwrap();
    assert_eq!(first.result_count, 2);
    assert_eq!(first.total_result_count, 5);
    assert_eq!(first.receipt.truncation, QueryTruncationStateV1::Truncated);
    let token = first.receipt.continuation.clone().unwrap();
    assert!(token.starts_with("gtkgc1."));
    assert!(!token.contains("next_offset"));

    let second = fixture
        .query(search("shared_query", 2, Some(token.clone())))
        .unwrap();
    assert_eq!(second.result_count, 2);
    let third = fixture
        .query(search(
            "shared_query",
            2,
            second.receipt.continuation.clone(),
        ))
        .unwrap();
    assert_eq!(third.result_count, 1);
    assert_eq!(
        third.receipt.truncation,
        QueryTruncationStateV1::NotTruncated
    );
    assert!(third.receipt.continuation.is_none());

    let mut tampered = token.into_bytes();
    let last = tampered.len() - 1;
    tampered[last] = if tampered[last] == b'0' { b'1' } else { b'0' };
    assert_eq!(
        fixture.query(search(
            "shared_query",
            2,
            Some(String::from_utf8(tampered).unwrap())
        )),
        Err(FileQueryErrorV1::ContinuationInvalid)
    );
}

#[test]
fn q03_stale_zero_shard_tamper_and_unsafe_files_fail_with_rebuild_or_security_signal() {
    let stale = IndexFixture::basic();
    let mut wrong = stale.expected.clone();
    wrong.graph_identity = digest("other-graph");
    let error = execute_file_query_page_v1(
        &stale.context(),
        &stale.index_root,
        &stale.manifest_ref,
        &wrong,
        &search("authentication", 10, None),
    )
    .unwrap_err();
    assert_eq!(error, FileQueryErrorV1::StaleIndex);
    assert!(error.requires_rebuild());
    let no_answer = stale.query(search("definitely_missing", 10, None)).unwrap();
    assert!(no_answer.lexical_hits.is_empty());
    assert!(no_answer.receipt.selected_shards.is_empty());

    let false_negative = IndexFixture::basic();
    let mut manifest = false_negative.manifest();
    let entry = manifest
        .lexical_routing_catalog
        .entries
        .iter_mut()
        .find(|entry| entry.routing_key.ends_with(&hex::encode("authentication")))
        .unwrap();
    entry.shard_ids.clear();
    manifest.lexical_routing_catalog.raw_bytes_sha256 =
        lexical_routing_catalog_content_sha256_v1(&manifest.lexical_routing_catalog);
    let forged_ref = false_negative.forge_manifest(manifest);
    let zero = execute_file_query_page_v1(
        &false_negative.context(),
        &false_negative.index_root,
        &forged_ref,
        &false_negative.expected,
        &search("authentication", 10, None),
    )
    .unwrap_err();
    assert_eq!(zero, FileQueryErrorV1::ZeroShardSelection);
    assert!(zero.requires_rebuild());

    let tamper = IndexFixture::basic();
    let shard = tamper.selected_file("lex-auth");
    fs::write(&shard, b"{}\n").unwrap();
    assert_eq!(
        tamper.query(search("authentication", 10, None)),
        Err(FileQueryErrorV1::ShardTampered)
    );

    #[cfg(unix)]
    {
        let hardlink = IndexFixture::basic();
        let shard = hardlink.selected_file("lex-auth");
        fs::hard_link(&shard, shard.with_extension("hardlink")).unwrap();
        assert_eq!(
            hardlink.query(search("authentication", 10, None)),
            Err(FileQueryErrorV1::UnsafePath)
        );

        use std::os::unix::fs::symlink;
        let symlinked = IndexFixture::basic();
        let manifest = symlinked.index_root.join(&symlinked.manifest_ref.path);
        let saved = manifest.with_extension("saved");
        fs::rename(&manifest, &saved).unwrap();
        symlink(&saved, &manifest).unwrap();
        assert_eq!(
            symlinked.query(search("authentication", 10, None)),
            Err(FileQueryErrorV1::UnsafePath)
        );
    }
}

#[test]
fn q03_detects_post_plan_toctou_and_oversize_before_accepting_shard_bytes() {
    let fixture = IndexFixture::basic();
    let result = execute_file_query_page_with_pre_shard_read_hook_v1(
        &fixture.context(),
        &fixture.index_root,
        &fixture.manifest_ref,
        &fixture.expected,
        &search("authentication", 10, None),
        |path| fs::write(path, b"{}\n").unwrap(),
    );
    assert_eq!(result, Err(FileQueryErrorV1::ShardTampered));

    let oversize = IndexFixture::basic();
    let path = oversize.selected_file("lex-auth");
    let file = fs::OpenOptions::new().write(true).open(path).unwrap();
    file.set_len(
        gtkg_protocol::v03::query::QueryResourceBudgetsV1::v03_frozen().max_shard_bytes + 1,
    )
    .unwrap();
    assert_eq!(
        oversize.query(search("authentication", 10, None)),
        Err(FileQueryErrorV1::ResourceBudgetExceeded)
    );
}

#[test]
fn q03_one_thousand_document_smoke_remains_single_shard_and_zero_external_effects() {
    let documents = (0..1_000)
        .map(|index| {
            document(
                &format!("node-{index:04}"),
                &format!("evidence:{index:04}"),
                &format!("symbol_{index:04} shared_corpus"),
            )
        })
        .collect();
    let fixture = IndexFixture::new(vec![("lex-1k", documents)]);
    let page = fixture.query(search("symbol_0999", 10, None)).unwrap();
    assert_eq!(page.lexical_hits.len(), 1);
    assert_eq!(page.lexical_hits[0].node_id, "node-0999");
    assert_eq!(page.shard_files_opened, 1);
    assert_eq!(page.full_graph_read_count, 0);
    assert_eq!(page.database_read_count, 0);
    assert_eq!(page.network_call_count, 0);
    assert_eq!(page.daemon_call_count, 0);
}
