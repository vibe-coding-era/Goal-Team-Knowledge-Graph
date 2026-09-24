use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use gtkg_core::v03::query::{
    AdjacencyEdgeInputV1, FileQueryErrorV1, LexicalDocumentV1, build_adjacency_routing_index_v1,
    build_lexical_shard_v1, execute_first_file_query_page_v1, file_query_manifest_cache_stats_v1,
    reset_file_query_manifest_cache_v1, write_file_query_index_v1,
};
use gtkg_core::{CallContext, EffectPolicy, TransportKind};
use gtkg_protocol::FileReceiptRef;
use gtkg_protocol::v03::query::{
    FileQueryExpectedIdentitiesV1, FileQueryLookupV1, FileQueryRequestV1, QueryResolutionStateV1,
};
use sha2::{Digest, Sha256};

static CACHE_TEST_LOCK: Mutex<()> = Mutex::new(());

fn digest(label: &str) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(label.as_bytes())))
}

fn context(root: &Path) -> CallContext {
    CallContext::restricted(
        TransportKind::Test,
        vec![root.to_path_buf()],
        EffectPolicy::WorkspaceWrite,
    )
    .unwrap()
}

fn query() -> FileQueryRequestV1 {
    FileQueryRequestV1 {
        lookup: FileQueryLookupV1::Search {
            query: "cache_anchor".to_owned(),
        },
        max_results: 10,
        continuation: None,
    }
}

struct CacheFixture {
    workspace: tempfile::TempDir,
    index_root: PathBuf,
    manifest_ref: FileReceiptRef,
    expected: FileQueryExpectedIdentitiesV1,
}

impl CacheFixture {
    fn new() -> Self {
        let workspace = tempfile::tempdir().unwrap();
        let index_root = workspace.path().join(".gtkg/query-index");
        let expected = FileQueryExpectedIdentitiesV1 {
            source_identity: digest("q05-cache-source"),
            graph_identity: digest("q05-cache-graph"),
            overlay_identity: digest("q05-cache-overlay"),
        };
        let lexical = [build_lexical_shard_v1(
            "q05-cache-lexical",
            &[LexicalDocumentV1 {
                node_id: "q05-cache-node".to_owned(),
                evidence_ref: "evidence:q05-cache".to_owned(),
                text: "cache_anchor deterministic query".to_owned(),
            }],
        )
        .unwrap()];
        let adjacency = build_adjacency_routing_index_v1(
            &["q05-cache-a".to_owned(), "q05-cache-b".to_owned()],
            &[AdjacencyEdgeInputV1 {
                edge_id: "q05-cache-edge".to_owned(),
                source_node_id: "q05-cache-a".to_owned(),
                target_node_id: "q05-cache-b".to_owned(),
                resolution_state: QueryResolutionStateV1::Resolved,
                evidence_ref: "evidence:q05-cache-edge".to_owned(),
            }],
        )
        .unwrap();
        let manifest_ref = write_file_query_index_v1(
            &context(workspace.path()),
            &index_root,
            &expected,
            &lexical,
            &adjacency,
        )
        .unwrap();
        Self {
            workspace,
            index_root,
            manifest_ref,
            expected,
        }
    }

    fn execute(&self) -> Result<gtkg_core::v03::query::FileQueryPageV1, FileQueryErrorV1> {
        execute_first_file_query_page_v1(
            &context(self.workspace.path()),
            &self.index_root,
            &self.manifest_ref,
            &self.expected,
            &query(),
        )
    }

    fn assert_warm_hit(&self) {
        let first = self.execute().unwrap();
        assert_eq!(first.lexical_hits.len(), 1);
        let after_first = file_query_manifest_cache_stats_v1();
        let second = self.execute().unwrap();
        assert_eq!(second.lexical_hits, first.lexical_hits);
        let after_second = file_query_manifest_cache_stats_v1();
        assert!(after_first.misses >= 1);
        assert!(after_second.hits > after_first.hits);
        assert!(after_second.entries >= 1);
    }

    fn manifest_path(&self) -> PathBuf {
        self.index_root.join(&self.manifest_ref.path)
    }

    fn binding_path(&self) -> PathBuf {
        self.index_root.join("binding/current.json")
    }
}

fn replace_exact_inode(path: &Path) {
    let bytes = fs::read(path).unwrap();
    let saved = path.with_extension("q05-replaced");
    fs::rename(path, &saved).unwrap();
    fs::write(path, bytes).unwrap();
}

fn mutate_source_identity_same_inode(path: &Path) {
    let mut bytes = fs::read(path).unwrap();
    let marker = b"source_identity";
    let marker_offset = bytes
        .windows(marker.len())
        .position(|window| window == marker)
        .unwrap();
    let digest_offset = bytes[marker_offset..]
        .windows(b"sha256:".len())
        .position(|window| window == b"sha256:")
        .map(|offset| marker_offset + offset + b"sha256:".len())
        .unwrap();
    bytes[digest_offset] = if bytes[digest_offset] == b'0' {
        b'1'
    } else {
        b'0'
    };
    fs::write(path, bytes).unwrap();
}

#[test]
fn q05_warm_cache_rejects_same_inode_manifest_content_change() {
    let _guard = CACHE_TEST_LOCK.lock().unwrap();
    reset_file_query_manifest_cache_v1();
    let fixture = CacheFixture::new();
    fixture.assert_warm_hit();
    mutate_source_identity_same_inode(&fixture.manifest_path());
    assert!(matches!(
        fixture.execute(),
        Err(FileQueryErrorV1::ManifestTampered | FileQueryErrorV1::UnsafePath)
    ));
}

#[test]
fn q05_warm_cache_rejects_exact_manifest_inode_replacement() {
    let _guard = CACHE_TEST_LOCK.lock().unwrap();
    reset_file_query_manifest_cache_v1();
    let fixture = CacheFixture::new();
    fixture.assert_warm_hit();
    replace_exact_inode(&fixture.manifest_path());
    assert_eq!(fixture.execute(), Err(FileQueryErrorV1::UnsafePath));
}

#[test]
fn q05_warm_cache_rejects_exact_current_binding_inode_replacement() {
    let _guard = CACHE_TEST_LOCK.lock().unwrap();
    reset_file_query_manifest_cache_v1();
    let fixture = CacheFixture::new();
    fixture.assert_warm_hit();
    replace_exact_inode(&fixture.binding_path());
    assert!(matches!(
        fixture.execute(),
        Err(FileQueryErrorV1::UnsafePath | FileQueryErrorV1::InvalidManifest)
    ));
}

#[test]
fn q05_cache_key_keeps_different_canonical_roots_with_same_digest_isolated() {
    let _guard = CACHE_TEST_LOCK.lock().unwrap();
    reset_file_query_manifest_cache_v1();
    let first = CacheFixture::new();
    let second = CacheFixture::new();
    assert_eq!(first.manifest_ref, second.manifest_ref);
    first.assert_warm_hit();
    second.assert_warm_hit();
    mutate_source_identity_same_inode(&first.manifest_path());
    let page = second.execute().unwrap();
    assert_eq!(page.lexical_hits.len(), 1);
    let stats = file_query_manifest_cache_stats_v1();
    assert_eq!(stats.entries, 2);
    assert!(stats.hits >= 3);
}

#[test]
fn q05_manifest_cache_is_bounded_and_evicts_without_cross_root_reuse() {
    let _guard = CACHE_TEST_LOCK.lock().unwrap();
    reset_file_query_manifest_cache_v1();
    let initial = file_query_manifest_cache_stats_v1();
    assert!(initial.capacity > 0 && initial.capacity <= 16);
    let fixtures = (0..=initial.capacity)
        .map(|_| CacheFixture::new())
        .collect::<Vec<_>>();
    for fixture in &fixtures {
        let page = fixture.execute().unwrap();
        assert_eq!(page.lexical_hits.len(), 1);
    }
    let final_stats = file_query_manifest_cache_stats_v1();
    assert!(final_stats.entries <= final_stats.capacity);
    assert!(final_stats.evictions >= 1);
    assert!(final_stats.misses >= u64::try_from(fixtures.len()).unwrap());
}
