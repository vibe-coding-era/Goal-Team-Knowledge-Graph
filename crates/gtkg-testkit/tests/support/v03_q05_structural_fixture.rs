use std::collections::{BTreeMap, BTreeSet};

use gtkg_core::v03::query::{
    AdjacencyEdgeInputV1, LexicalDocumentV1, build_adjacency_routing_index_v1,
    build_lexical_shard_v1,
};
use gtkg_protocol::v03::query::{
    AdjacencyDirectionV1, AdjacencyRoutingIndexV1, LexicalShardV1, QueryResolutionStateV1,
};
use sha2::{Digest, Sha256};

pub const DISTRIBUTED_SAMPLE_COUNT: usize = 20;
pub const LEXICAL_SHARD_COUNT: usize = DISTRIBUTED_SAMPLE_COUNT + 1;

#[derive(Debug, Clone, Copy)]
pub struct StructuralScaleSpec {
    pub denominator: usize,
    pub canonical_bytes: usize,
    pub canonical_sha256: &'static str,
}

pub const STRUCTURAL_SCALE_SPECS: [StructuralScaleSpec; 3] = [
    StructuralScaleSpec {
        denominator: 1_000,
        canonical_bytes: 61_201,
        canonical_sha256: "sha256:28ec60a44a2a46708e8b71e217c395b5df9541b48ffe8f156de9b7cab8b4925a",
    },
    StructuralScaleSpec {
        denominator: 10_000,
        canonical_bytes: 610_201,
        canonical_sha256: "sha256:4414b03edc61e6580bc19193ba346d14324a84b515312ffc8aa8a87085866919",
    },
    StructuralScaleSpec {
        denominator: 10_001,
        canonical_bytes: 610_262,
        canonical_sha256: "sha256:89d0112acd48575a6bea0d00cba1aeef2f35c80f064af0bb7477604f3c92283b",
    },
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructuralSamplePair {
    pub slot: usize,
    pub document_index: usize,
    pub node_id: String,
    pub direction: AdjacencyDirectionV1,
    pub search_term: String,
}

pub struct DeterministicStructuralCorpus {
    pub documents: Vec<LexicalDocumentV1>,
    pub nodes: Vec<String>,
    pub edges: Vec<AdjacencyEdgeInputV1>,
    pub samples: Vec<StructuralSamplePair>,
    pub canonical_bytes: usize,
    pub canonical_sha256: String,
}

pub fn node_id(index: usize) -> String {
    char::from_u32(0x4e00 + u32::try_from(index).unwrap_or(u32::MAX))
        .expect("the frozen Q05 denominator stays inside the CJK scalar range")
        .to_string()
}

fn lexical_evidence_id(index: usize) -> String {
    char::from_u32(0xa800 + u32::try_from(index).unwrap_or(u32::MAX))
        .expect("the frozen Q05 denominator stays below the surrogate range")
        .to_string()
}

fn edge_id(index: usize) -> String {
    char::from_u32(0x8000 + u32::try_from(index).unwrap_or(u32::MAX))
        .expect("the frozen Q05 denominator stays inside the edge scalar range")
        .to_string()
}

fn edge_evidence_id(index: usize) -> String {
    char::from_u32(0x10000 + u32::try_from(index).unwrap_or(u32::MAX))
        .expect("the frozen Q05 denominator stays inside the evidence scalar range")
        .to_string()
}

pub fn expected_node_ids(denominator: usize) -> BTreeSet<String> {
    (0..denominator).map(node_id).collect()
}

pub fn expected_edge_ids(denominator: usize) -> BTreeSet<String> {
    (0..denominator).map(edge_id).collect()
}

pub fn sample_indices(denominator: usize) -> Vec<usize> {
    (0..DISTRIBUTED_SAMPLE_COUNT)
        .map(|slot| slot * (denominator - 1) / (DISTRIBUTED_SAMPLE_COUNT - 1))
        .collect()
}

pub fn generate_structural_corpus(
    spec: StructuralScaleSpec,
) -> Result<DeterministicStructuralCorpus, String> {
    let sample_slots = sample_indices(spec.denominator)
        .into_iter()
        .enumerate()
        .map(|(slot, index)| (index, slot))
        .collect::<BTreeMap<_, _>>();
    if sample_slots.len() != DISTRIBUTED_SAMPLE_COUNT {
        return Err("distributed sample indices collided".to_owned());
    }

    let mut documents = Vec::with_capacity(spec.denominator);
    let mut nodes = Vec::with_capacity(spec.denominator);
    let mut edges = Vec::with_capacity(spec.denominator);
    let mut canonical_rows = Vec::with_capacity(spec.denominator);
    let sampled_node_ids = sample_indices(spec.denominator)
        .into_iter()
        .map(node_id)
        .collect::<Vec<_>>();
    for index in 0..spec.denominator {
        let node = node_id(index);
        let evidence = lexical_evidence_id(index);
        let text = sample_slots.get(&index).map_or_else(
            || "structural_document".to_owned(),
            |slot| format!("anchor_{slot:02} structural_document"),
        );
        let edge_id = edge_id(index);
        let source = sampled_node_ids[index % DISTRIBUTED_SAMPLE_COUNT].clone();
        let target = sampled_node_ids[(index + 1) % DISTRIBUTED_SAMPLE_COUNT].clone();
        let edge_evidence = edge_evidence_id(index);
        documents.push(LexicalDocumentV1 {
            node_id: node.clone(),
            evidence_ref: evidence.clone(),
            text: text.clone(),
        });
        nodes.push(node.clone());
        edges.push(AdjacencyEdgeInputV1 {
            edge_id: edge_id.clone(),
            source_node_id: source.clone(),
            target_node_id: target.clone(),
            resolution_state: QueryResolutionStateV1::Resolved,
            evidence_ref: edge_evidence.clone(),
        });
        canonical_rows.push((node, evidence, text, edge_id, source, target, edge_evidence));
    }
    let canonical = serde_json::to_vec(&canonical_rows).map_err(|error| error.to_string())?;
    let canonical_sha256 = format!("sha256:{}", hex::encode(Sha256::digest(&canonical)));
    if canonical.len() != spec.canonical_bytes || canonical_sha256 != spec.canonical_sha256 {
        return Err(format!(
            "structural corpus drift: denominator={} bytes={} sha256={}",
            spec.denominator,
            canonical.len(),
            canonical_sha256
        ));
    }
    let samples = sample_slots
        .into_iter()
        .map(|(document_index, slot)| StructuralSamplePair {
            slot,
            document_index,
            node_id: node_id(document_index),
            direction: if slot % 2 == 0 {
                AdjacencyDirectionV1::Outgoing
            } else {
                AdjacencyDirectionV1::Incoming
            },
            search_term: format!("anchor_{slot:02}"),
        })
        .collect::<Vec<_>>();
    Ok(DeterministicStructuralCorpus {
        documents,
        nodes,
        edges,
        samples,
        canonical_bytes: canonical.len(),
        canonical_sha256,
    })
}

pub fn build_lexical_shards(
    documents: &[LexicalDocumentV1],
) -> Result<Vec<LexicalShardV1>, String> {
    let mut anchors = documents
        .iter()
        .filter(|document| document.text.starts_with("anchor_"))
        .cloned()
        .collect::<Vec<_>>();
    anchors.sort_by(|left, right| left.text.cmp(&right.text));
    if anchors.len() != DISTRIBUTED_SAMPLE_COUNT {
        return Err("anchor document denominator drifted".to_owned());
    }
    let generic = documents
        .iter()
        .filter(|document| !document.text.starts_with("anchor_"))
        .cloned()
        .collect::<Vec<_>>();
    if generic.is_empty() {
        return Err("generic lexical denominator is empty".to_owned());
    }
    let mut shards = anchors
        .iter()
        .enumerate()
        .map(|(slot, document)| {
            build_lexical_shard_v1(
                &format!("q05s-anchor-{slot:02}"),
                std::slice::from_ref(document),
            )
            .map_err(|error| error.to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    shards
        .push(build_lexical_shard_v1("q05s-generic", &generic).map_err(|error| error.to_string())?);
    if shards.len() != LEXICAL_SHARD_COUNT {
        return Err("lexical shard denominator drifted".to_owned());
    }
    Ok(shards)
}

pub fn build_adjacency_index(
    corpus: &DeterministicStructuralCorpus,
) -> Result<AdjacencyRoutingIndexV1, String> {
    build_adjacency_routing_index_v1(&corpus.nodes, &corpus.edges)
        .map_err(|error| error.to_string())
}
