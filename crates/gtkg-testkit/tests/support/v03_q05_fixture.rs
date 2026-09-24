use std::collections::BTreeSet;

use gtkg_core::v03::query::{LexicalDocumentV1, build_lexical_shard_v1};
use gtkg_protocol::v03::query::LexicalShardV1;
use sha2::{Digest, Sha256};

pub const DOCUMENTS_PER_SHARD: usize = 100;

#[derive(Debug, Clone, Copy)]
pub struct ScaleSpec {
    pub document_count: usize,
    pub canonical_bytes: usize,
    pub canonical_sha256: &'static str,
}

pub const SCALE_SPECS: [ScaleSpec; 3] = [
    ScaleSpec {
        document_count: 1_000,
        canonical_bytes: 89_014,
        canonical_sha256: "sha256:a34e2ef2d91cbb9461efcda710c32a1798b222bca4ad1bd654090336982ad842",
    },
    ScaleSpec {
        document_count: 10_000,
        canonical_bytes: 890_014,
        canonical_sha256: "sha256:117a428aa3285da2e31943699ecc8613c287538a5b7cd172ccf63c68a358e9dc",
    },
    ScaleSpec {
        document_count: 10_001,
        canonical_bytes: 890_103,
        canonical_sha256: "sha256:963350e0b13f61f524530a09d7fa39b3998a5b3c966f7300fd52ea1d6fc2509b",
    },
];

pub struct DeterministicCorpus {
    pub documents: Vec<LexicalDocumentV1>,
    pub canonical_bytes: usize,
    pub canonical_sha256: String,
}

pub fn generate_corpus(spec: ScaleSpec) -> Result<DeterministicCorpus, String> {
    let documents = (0..spec.document_count)
        .map(|index| {
            let collision_form = match index {
                0 => " café",
                1 => " cafe\u{301}",
                _ => "",
            };
            LexicalDocumentV1 {
                node_id: format!("q05-node-{index:05}"),
                evidence_ref: format!("evidence:q05:{index:05}"),
                text: format!("q05_symbol_{index:05} q05_shared_token 模块查询{collision_form}"),
            }
        })
        .collect::<Vec<_>>();
    let canonical_records = documents
        .iter()
        .map(|document| {
            (
                document.node_id.as_str(),
                document.evidence_ref.as_str(),
                document.text.as_str(),
            )
        })
        .collect::<Vec<_>>();
    let canonical = serde_json::to_vec(&canonical_records).map_err(|error| error.to_string())?;
    let canonical_sha256 = format!("sha256:{}", hex::encode(Sha256::digest(&canonical)));
    if canonical.len() != spec.canonical_bytes || canonical_sha256 != spec.canonical_sha256 {
        return Err(format!(
            "deterministic corpus drift: denominator={} bytes={} sha256={}",
            spec.document_count,
            canonical.len(),
            canonical_sha256
        ));
    }
    Ok(DeterministicCorpus {
        documents,
        canonical_bytes: canonical.len(),
        canonical_sha256,
    })
}

pub fn build_lexical_shards(
    documents: &[LexicalDocumentV1],
) -> Result<Vec<LexicalShardV1>, String> {
    documents
        .chunks(DOCUMENTS_PER_SHARD)
        .enumerate()
        .map(|(shard_index, chunk)| {
            let first = shard_index * DOCUMENTS_PER_SHARD;
            let last = first + chunk.len() - 1;
            build_lexical_shard_v1(&format!("q05-lex-{first:05}-{last:05}"), chunk)
                .map_err(|error| error.to_string())
        })
        .collect()
}

pub fn expected_node_ids(document_count: usize) -> BTreeSet<String> {
    (0..document_count)
        .map(|index| format!("q05-node-{index:05}"))
        .collect()
}
