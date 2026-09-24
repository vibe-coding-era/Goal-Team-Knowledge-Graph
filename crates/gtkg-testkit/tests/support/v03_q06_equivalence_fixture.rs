use gtkg_core::v03::query::{AdjacencyEdgeInputV1, LexicalDocumentV1};
use gtkg_core::v03::query_equivalence::{
    QueryIndexEquivalenceInputV1, QueryIndexEquivalenceMutationV1,
    QueryIndexIdentityComponentV1, QueryIndexLexicalGroupV1,
};
use gtkg_protocol::v03::query::{
    AdjacencyDirectionV1, FileQueryLookupV1, FileQueryRequestV1,
    QueryIndexEquivalenceIdentityV1, QueryResolutionStateV1,
};

fn digest(label: &str) -> String {
    use sha2::{Digest, Sha256};

    format!("sha256:{}", hex::encode(Sha256::digest(label.as_bytes())))
}

fn document(node_id: &str, text: &str) -> LexicalDocumentV1 {
    LexicalDocumentV1 {
        node_id: node_id.to_owned(),
        evidence_ref: format!("evidence:{node_id}"),
        text: text.to_owned(),
    }
}

fn edge(edge_id: &str, source_node_id: &str, target_node_id: &str) -> AdjacencyEdgeInputV1 {
    AdjacencyEdgeInputV1 {
        edge_id: edge_id.to_owned(),
        source_node_id: source_node_id.to_owned(),
        target_node_id: target_node_id.to_owned(),
        resolution_state: QueryResolutionStateV1::Resolved,
        evidence_ref: format!("evidence:{edge_id}"),
    }
}

fn identity(source: &str, adapter: &str, profile: &str) -> QueryIndexEquivalenceIdentityV1 {
    QueryIndexEquivalenceIdentityV1::new(digest(source), digest(adapter), digest(profile)).unwrap()
}

fn input(
    source: &str,
    adapter: &str,
    profile: &str,
    documents: Vec<LexicalDocumentV1>,
    nodes: Vec<&str>,
    edges: Vec<AdjacencyEdgeInputV1>,
) -> QueryIndexEquivalenceInputV1 {
    QueryIndexEquivalenceInputV1 {
        identity: identity(source, adapter, profile),
        lexical_groups: vec![QueryIndexLexicalGroupV1 {
            shard_id: "lex-main".to_owned(),
            documents,
        }],
        nodes: nodes.into_iter().map(str::to_owned).collect(),
        edges,
    }
}

pub struct EquivalenceScenario {
    pub name: &'static str,
    pub base: QueryIndexEquivalenceInputV1,
    pub terminal: QueryIndexEquivalenceInputV1,
    pub mutations: Vec<QueryIndexEquivalenceMutationV1>,
    pub required_search: &'static str,
    pub forbidden_search: Option<&'static str>,
}

fn base_input() -> QueryIndexEquivalenceInputV1 {
    input(
        "source-base",
        "adapter-base",
        "profile-base",
        vec![
            document("node-alpha", "alpha stable document"),
            document("node-beta", "beta transient document"),
            document("node-gamma", "gamma retained document"),
        ],
        vec!["node-alpha", "node-beta", "node-gamma"],
        vec![
            edge("edge-alpha-beta", "node-alpha", "node-beta"),
            edge("edge-alpha-gamma", "node-alpha", "node-gamma"),
        ],
    )
}

pub fn scenarios() -> Vec<EquivalenceScenario> {
    let base = base_input();
    vec![
        EquivalenceScenario {
            name: "add",
            base: base.clone(),
            terminal: input(
                "source-add",
                "adapter-base",
                "profile-base",
                vec![
                    document("node-alpha", "alpha stable document"),
                    document("node-beta", "beta transient document"),
                    document("node-delta", "delta added document"),
                    document("node-gamma", "gamma retained document"),
                ],
                vec!["node-alpha", "node-beta", "node-delta", "node-gamma"],
                vec![
                    edge("edge-alpha-beta", "node-alpha", "node-beta"),
                    edge("edge-alpha-gamma", "node-alpha", "node-gamma"),
                    edge("edge-gamma-delta", "node-gamma", "node-delta"),
                ],
            ),
            mutations: vec![
                QueryIndexEquivalenceMutationV1::Identity {
                    component: QueryIndexIdentityComponentV1::Source,
                    value: digest("source-add"),
                },
                QueryIndexEquivalenceMutationV1::Lexical {
                    shard_id: "lex-main".to_owned(),
                    document: document("node-delta", "delta added document"),
                },
                QueryIndexEquivalenceMutationV1::GraphNodeUpsert {
                    node_id: "node-delta".to_owned(),
                },
                QueryIndexEquivalenceMutationV1::GraphEdgeUpsert(edge(
                    "edge-gamma-delta",
                    "node-gamma",
                    "node-delta",
                )),
            ],
            required_search: "delta",
            forbidden_search: None,
        },
        EquivalenceScenario {
            name: "change",
            base: base.clone(),
            terminal: input(
                "source-change",
                "adapter-base",
                "profile-base",
                vec![
                    document("node-alpha", "alpha refreshed document"),
                    document("node-beta", "beta transient document"),
                    document("node-gamma", "gamma retained document"),
                ],
                vec!["node-alpha", "node-beta", "node-gamma"],
                vec![
                    edge("edge-alpha-beta", "node-alpha", "node-beta"),
                    edge("edge-alpha-gamma", "node-alpha", "node-gamma"),
                ],
            ),
            mutations: vec![
                QueryIndexEquivalenceMutationV1::Identity {
                    component: QueryIndexIdentityComponentV1::Source,
                    value: digest("source-change"),
                },
                QueryIndexEquivalenceMutationV1::Lexical {
                    shard_id: "lex-main".to_owned(),
                    document: document("node-alpha", "alpha refreshed document"),
                },
            ],
            required_search: "refreshed",
            forbidden_search: None,
        },
        EquivalenceScenario {
            name: "delete",
            base: base.clone(),
            terminal: input(
                "source-delete",
                "adapter-base",
                "profile-base",
                vec![
                    document("node-alpha", "alpha stable document"),
                    document("node-gamma", "gamma retained document"),
                ],
                vec!["node-alpha", "node-gamma"],
                vec![edge("edge-alpha-gamma", "node-alpha", "node-gamma")],
            ),
            mutations: vec![
                QueryIndexEquivalenceMutationV1::Identity {
                    component: QueryIndexIdentityComponentV1::Source,
                    value: digest("source-delete"),
                },
                QueryIndexEquivalenceMutationV1::LexicalDelete {
                    shard_id: "lex-main".to_owned(),
                    node_id: "node-beta".to_owned(),
                },
                QueryIndexEquivalenceMutationV1::GraphNodeDelete {
                    node_id: "node-beta".to_owned(),
                },
            ],
            required_search: "gamma",
            forbidden_search: Some("beta"),
        },
        EquivalenceScenario {
            name: "adapter",
            base: base.clone(),
            terminal: input(
                "source-base",
                "adapter-next",
                "profile-base",
                base.lexical_groups[0].documents.clone(),
                vec!["node-alpha", "node-beta", "node-gamma"],
                vec![
                    edge("edge-alpha-beta", "node-alpha", "node-beta"),
                    edge("edge-alpha-gamma", "node-alpha", "node-gamma"),
                ],
            ),
            mutations: vec![QueryIndexEquivalenceMutationV1::Identity {
                component: QueryIndexIdentityComponentV1::Adapter,
                value: digest("adapter-next"),
            }],
            required_search: "alpha",
            forbidden_search: None,
        },
        EquivalenceScenario {
            name: "profile",
            base: base.clone(),
            terminal: input(
                "source-base",
                "adapter-base",
                "profile-next",
                base.lexical_groups[0].documents.clone(),
                vec!["node-alpha", "node-beta", "node-gamma"],
                vec![
                    edge("edge-alpha-beta", "node-alpha", "node-beta"),
                    edge("edge-alpha-gamma", "node-alpha", "node-gamma"),
                ],
            ),
            mutations: vec![QueryIndexEquivalenceMutationV1::Identity {
                component: QueryIndexIdentityComponentV1::Profile,
                value: digest("profile-next"),
            }],
            required_search: "alpha",
            forbidden_search: None,
        },
    ]
}

pub fn requests(required_search: &str, forbidden_search: Option<&str>) -> Vec<FileQueryRequestV1> {
    let mut requests = vec![
        FileQueryRequestV1 {
            lookup: FileQueryLookupV1::Search {
                query: required_search.to_owned(),
            },
            max_results: 10,
            continuation: None,
        },
        FileQueryRequestV1 {
            lookup: FileQueryLookupV1::Adjacency {
                node_id: "node-alpha".to_owned(),
                direction: AdjacencyDirectionV1::Outgoing,
            },
            max_results: 10,
            continuation: None,
        },
    ];
    if let Some(query) = forbidden_search {
        requests.push(FileQueryRequestV1 {
            lookup: FileQueryLookupV1::Search {
                query: query.to_owned(),
            },
            max_results: 10,
            continuation: None,
        });
    }
    requests
}
