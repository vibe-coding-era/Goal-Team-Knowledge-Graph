use gtkg_core::v03::query::{AdjacencyEdgeInputV1, LexicalDocumentV1};
use gtkg_core::v03::query_equivalence::{
    QueryIndexEquivalenceInputV1, QueryIndexEquivalenceMutationV1,
    QueryIndexIdentityComponentV1, QueryIndexLexicalGroupV1,
};
use gtkg_protocol::v03::query::{
    AdjacencyDirectionV1, FileQueryLookupV1, FileQueryRequestV1,
    QueryIndexEquivalenceIdentityV1, QueryResolutionStateV1,
};

pub fn digest(label: &str) -> String {
    use sha2::{Digest, Sha256};

    format!("sha256:{}", hex::encode(Sha256::digest(label.as_bytes())))
}

pub fn identity(source: &str, adapter: &str, profile: &str) -> QueryIndexEquivalenceIdentityV1 {
    QueryIndexEquivalenceIdentityV1::new(digest(source), digest(adapter), digest(profile)).unwrap()
}

pub fn document(node_id: &str, text: &str) -> LexicalDocumentV1 {
    LexicalDocumentV1 {
        node_id: node_id.to_owned(),
        evidence_ref: format!("evidence:{node_id}"),
        text: text.to_owned(),
    }
}

pub fn edge(edge_id: &str, source_node_id: &str, target_node_id: &str) -> AdjacencyEdgeInputV1 {
    AdjacencyEdgeInputV1 {
        edge_id: edge_id.to_owned(),
        source_node_id: source_node_id.to_owned(),
        target_node_id: target_node_id.to_owned(),
        resolution_state: QueryResolutionStateV1::Resolved,
        evidence_ref: format!("evidence:{edge_id}"),
    }
}

pub fn base_input() -> QueryIndexEquivalenceInputV1 {
    QueryIndexEquivalenceInputV1 {
        identity: identity("source-base", "adapter-base", "profile-base"),
        lexical_groups: vec![QueryIndexLexicalGroupV1 {
            shard_id: "lex-main".to_owned(),
            documents: vec![
                document("node-alpha", "alpha stable document"),
                document("node-beta", "beta stable document"),
                document("node-gamma", "gamma stable document"),
            ],
        }],
        nodes: vec![
            "node-alpha".to_owned(),
            "node-beta".to_owned(),
            "node-gamma".to_owned(),
        ],
        edges: vec![
            edge("edge-alpha-beta", "node-alpha", "node-beta"),
            edge("edge-alpha-gamma", "node-alpha", "node-gamma"),
        ],
    }
}

pub fn edge_replacement_terminal() -> QueryIndexEquivalenceInputV1 {
    QueryIndexEquivalenceInputV1 {
        identity: identity("source-edge-replacement", "adapter-base", "profile-base"),
        lexical_groups: base_input().lexical_groups,
        nodes: vec![
            "node-alpha".to_owned(),
            "node-beta".to_owned(),
            "node-gamma".to_owned(),
        ],
        edges: vec![
            edge("edge-alpha-beta", "node-alpha", "node-beta"),
            edge(
                "edge-alpha-gamma-replacement",
                "node-alpha",
                "node-gamma",
            ),
        ],
    }
}

pub fn edge_replacement_mutations() -> Vec<QueryIndexEquivalenceMutationV1> {
    vec![
        QueryIndexEquivalenceMutationV1::Identity {
            component: QueryIndexIdentityComponentV1::Source,
            value: digest("source-edge-replacement"),
        },
        QueryIndexEquivalenceMutationV1::GraphEdgeDelete {
            edge_id: "edge-alpha-gamma".to_owned(),
        },
        QueryIndexEquivalenceMutationV1::GraphEdgeUpsert(edge(
            "edge-alpha-gamma-replacement",
            "node-alpha",
            "node-gamma",
        )),
    ]
}

pub fn adjacency_alpha() -> FileQueryRequestV1 {
    FileQueryRequestV1 {
        lookup: FileQueryLookupV1::Adjacency {
            node_id: "node-alpha".to_owned(),
            direction: AdjacencyDirectionV1::Outgoing,
        },
        max_results: 10,
        continuation: None,
    }
}
