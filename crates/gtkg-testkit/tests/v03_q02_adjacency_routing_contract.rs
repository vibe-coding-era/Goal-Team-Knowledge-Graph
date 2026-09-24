use gtkg_core::v03::query::{
    AdjacencyEdgeInputV1, AdjacencyIndexErrorV1, AdjacencyIndexStateV1, AdjacencyMutationV1,
    adjacency_routing_catalog_content_sha256_v1, adjacency_routing_shard_content_sha256_v1,
    build_adjacency_routing_index_v1, build_adjacency_routing_index_with_budgets_v1,
    query_adjacency_shard_descriptors_v1, route_adjacency_edges_v1,
    validate_adjacency_routing_index_v1,
};
use gtkg_protocol::v03::query::{
    AdjacencyDirectionV1, AdjacencyRoutingIndexV1, QueryResolutionStateV1, QueryResourceBudgetsV1,
    QueryShardKindV1,
};
fn fixture() -> (Vec<String>, Vec<AdjacencyEdgeInputV1>) {
    let value: serde_json::Value =
        serde_json::from_str(include_str!("../fixtures/v03_q02/routing-graph.json"))
            .expect("closed Q02 fixture");
    let root = value.as_object().expect("fixture object");
    assert_eq!(
        root.keys().map(String::as_str).collect::<Vec<_>>(),
        ["edges", "nodes"]
    );
    let nodes = root["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap().to_owned())
        .collect();
    let edges = root["edges"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| {
            let edge = value.as_object().unwrap();
            assert_eq!(
                edge.keys().map(String::as_str).collect::<Vec<_>>(),
                [
                    "edge_id",
                    "evidence_ref",
                    "resolution_state",
                    "source_node_id",
                    "target_node_id",
                ]
            );
            let resolution_state = match edge["resolution_state"].as_str().unwrap() {
                "resolved" => QueryResolutionStateV1::Resolved,
                "ambiguous" => QueryResolutionStateV1::Ambiguous,
                "unresolved" => QueryResolutionStateV1::Unresolved,
                "unsupported" => QueryResolutionStateV1::Unsupported,
                other => panic!("unknown resolution {other}"),
            };
            AdjacencyEdgeInputV1 {
                edge_id: edge["edge_id"].as_str().unwrap().to_owned(),
                source_node_id: edge["source_node_id"].as_str().unwrap().to_owned(),
                target_node_id: edge["target_node_id"].as_str().unwrap().to_owned(),
                resolution_state,
                evidence_ref: edge["evidence_ref"].as_str().unwrap().to_owned(),
            }
        })
        .collect();
    (nodes, edges)
}

fn edge(
    edge_id: &str,
    source_node_id: &str,
    target_node_id: &str,
    resolution_state: QueryResolutionStateV1,
    evidence_ref: &str,
) -> AdjacencyEdgeInputV1 {
    AdjacencyEdgeInputV1 {
        edge_id: edge_id.to_owned(),
        source_node_id: source_node_id.to_owned(),
        target_node_id: target_node_id.to_owned(),
        resolution_state,
        evidence_ref: evidence_ref.to_owned(),
    }
}

#[test]
fn q02_routes_outgoing_and_incoming_edges_with_exact_evidence_and_no_hidden_io() {
    let (nodes, edges) = fixture();
    let index =
        build_adjacency_routing_index_v1(&nodes, &edges).expect("deterministic adjacency build");
    validate_adjacency_routing_index_v1(&index, &QueryResourceBudgetsV1::v03_frozen())
        .expect("closed adjacency routing index");

    let outgoing = route_adjacency_edges_v1(&index, "服务:认证", AdjacencyDirectionV1::Outgoing)
        .expect("outgoing route");
    assert_eq!(outgoing.edges.len(), 1);
    assert_eq!(outgoing.edges[0].edge_id, "edge-auth-store");
    assert_eq!(outgoing.edges[0].source_node_id, "服务:认证");
    assert_eq!(outgoing.edges[0].target_node_id, "node-store");
    assert_eq!(outgoing.edges[0].evidence_ref, "evidence:auth-store");
    assert_eq!(
        outgoing.edges[0].resolution_state,
        QueryResolutionStateV1::Resolved
    );
    assert_eq!(outgoing.selected_shard_count, 1);
    assert_eq!(outgoing.full_graph_read_count, 0);
    assert_eq!(outgoing.database_read_count, 0);
    assert_eq!(outgoing.network_call_count, 0);
    assert_eq!(outgoing.daemon_call_count, 0);

    let incoming = route_adjacency_edges_v1(&index, "服务:认证", AdjacencyDirectionV1::Incoming)
        .expect("incoming route");
    assert_eq!(incoming.edges.len(), 1);
    assert_eq!(incoming.edges[0].edge_id, "edge-client-auth");
    assert_eq!(
        incoming.edges[0].resolution_state,
        QueryResolutionStateV1::Ambiguous
    );
}

#[test]
fn q02_full_build_is_order_independent_content_bound_and_crosses_shard_boundaries() {
    let (nodes, edges) = fixture();
    let mut reverse_nodes = nodes.clone();
    reverse_nodes.reverse();
    let mut reverse_edges = edges.clone();
    reverse_edges.reverse();

    let first = build_adjacency_routing_index_v1(&nodes, &edges).unwrap();
    let second = build_adjacency_routing_index_v1(&reverse_nodes, &reverse_edges).unwrap();
    assert_eq!(first, second);
    assert_eq!(
        first.catalog.raw_bytes_sha256,
        adjacency_routing_catalog_content_sha256_v1(&first.catalog)
    );
    for shard in &first.shards {
        assert_eq!(
            shard.header.raw_bytes_sha256,
            adjacency_routing_shard_content_sha256_v1(shard)
        );
    }
    let descriptors = query_adjacency_shard_descriptors_v1(&first).unwrap();
    assert_eq!(descriptors.len(), first.shards.len());
    assert!(
        descriptors
            .iter()
            .all(|entry| entry.shard_kind == QueryShardKindV1::Adjacency)
    );
    assert!(
        first
            .catalog
            .routes
            .iter()
            .any(|route| route.node_id == "服务:认证")
    );
    assert!(
        first
            .catalog
            .routes
            .iter()
            .map(|route| route.shard_id.as_str())
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            >= 2
    );
}

#[test]
fn q02_incremental_add_change_delete_is_full_rebuild_equivalent_and_has_no_ghost_edges() {
    let mut state = AdjacencyIndexStateV1::from_graph(
        &[
            "node-a".to_owned(),
            "node-b".to_owned(),
            "node-delete".to_owned(),
        ],
        &[
            edge(
                "edge-change",
                "node-a",
                "node-b",
                QueryResolutionStateV1::Resolved,
                "evidence:old",
            ),
            edge(
                "edge-delete",
                "node-delete",
                "node-a",
                QueryResolutionStateV1::Resolved,
                "evidence:delete",
            ),
        ],
    )
    .unwrap();
    state
        .apply_mutations(&[
            AdjacencyMutationV1::UpsertNode {
                node_id: "节点-c".to_owned(),
            },
            AdjacencyMutationV1::UpsertEdge(edge(
                "edge-change",
                "node-a",
                "节点-c",
                QueryResolutionStateV1::Ambiguous,
                "evidence:changed",
            )),
            AdjacencyMutationV1::DeleteNode {
                node_id: "node-delete".to_owned(),
            },
            AdjacencyMutationV1::UpsertEdge(edge(
                "edge-add",
                "节点-c",
                "node-b",
                QueryResolutionStateV1::Unresolved,
                "evidence:add",
            )),
        ])
        .unwrap();
    let incremental = state.build_index().unwrap();

    let full = build_adjacency_routing_index_v1(
        &[
            "node-a".to_owned(),
            "node-b".to_owned(),
            "节点-c".to_owned(),
        ],
        &[
            edge(
                "edge-add",
                "节点-c",
                "node-b",
                QueryResolutionStateV1::Unresolved,
                "evidence:add",
            ),
            edge(
                "edge-change",
                "node-a",
                "节点-c",
                QueryResolutionStateV1::Ambiguous,
                "evidence:changed",
            ),
        ],
    )
    .unwrap();
    assert_eq!(incremental, full);
    assert!(
        !incremental
            .catalog
            .nodes
            .contains(&"node-delete".to_owned())
    );
    assert!(
        incremental
            .shards
            .iter()
            .flat_map(|shard| shard.records.iter())
            .all(|record| record.edge_id != "edge-delete")
    );
    assert_eq!(incremental.catalog.denominator.edge_count, 2);
    assert_eq!(incremental.catalog.denominator.adjacency_record_count, 4);
}

#[test]
fn q02_duplicate_dangling_unknown_and_duplicate_mutation_inputs_fail_closed() {
    assert_eq!(
        build_adjacency_routing_index_v1(&["node".to_owned(), "node".to_owned()], &[]),
        Err(AdjacencyIndexErrorV1::DuplicateNode)
    );
    let dangling = edge(
        "edge",
        "node",
        "ghost",
        QueryResolutionStateV1::Resolved,
        "evidence:edge",
    );
    assert_eq!(
        build_adjacency_routing_index_v1(&["node".to_owned()], &[dangling]),
        Err(AdjacencyIndexErrorV1::DanglingEdge)
    );

    let duplicate_edge = edge(
        "edge",
        "node-a",
        "node-b",
        QueryResolutionStateV1::Resolved,
        "evidence:edge",
    );
    assert_eq!(
        build_adjacency_routing_index_v1(
            &["node-a".to_owned(), "node-b".to_owned()],
            &[duplicate_edge.clone(), duplicate_edge]
        ),
        Err(AdjacencyIndexErrorV1::DuplicateEdge)
    );

    let mut state =
        AdjacencyIndexStateV1::from_graph(&["node-a".to_owned(), "node-b".to_owned()], &[])
            .unwrap();
    assert_eq!(
        state.apply_mutations(&[
            AdjacencyMutationV1::UpsertNode {
                node_id: "节点-c".to_owned(),
            },
            AdjacencyMutationV1::DeleteNode {
                node_id: "节点-c".to_owned(),
            },
        ]),
        Err(AdjacencyIndexErrorV1::DuplicateMutation)
    );

    let index = state.build_index().unwrap();
    assert_eq!(
        route_adjacency_edges_v1(&index, "ghost", AdjacencyDirectionV1::Outgoing),
        Err(AdjacencyIndexErrorV1::UnknownNode)
    );
}

#[test]
fn q02_tamper_denominator_and_budget_fail_before_routing() {
    let (nodes, edges) = fixture();
    let index = build_adjacency_routing_index_v1(&nodes, &edges).unwrap();

    let mut content_tamper = index.clone();
    content_tamper.shards[0].records[0].evidence_ref = "evidence:tampered".to_owned();
    assert_eq!(
        validate_adjacency_routing_index_v1(&content_tamper, &QueryResourceBudgetsV1::v03_frozen()),
        Err(AdjacencyIndexErrorV1::ContentDigestMismatch)
    );

    let mut catalog_tamper = index.clone();
    catalog_tamper.catalog.raw_bytes_sha256 =
        "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_owned();
    assert_eq!(
        validate_adjacency_routing_index_v1(&catalog_tamper, &QueryResourceBudgetsV1::v03_frozen()),
        Err(AdjacencyIndexErrorV1::CatalogDigestMismatch)
    );

    let mut denominator_tamper = index.clone();
    denominator_tamper.catalog.denominator.edge_count += 1;
    denominator_tamper.catalog.raw_bytes_sha256 =
        adjacency_routing_catalog_content_sha256_v1(&denominator_tamper.catalog);
    assert_eq!(
        validate_adjacency_routing_index_v1(
            &denominator_tamper,
            &QueryResourceBudgetsV1::v03_frozen()
        ),
        Err(AdjacencyIndexErrorV1::DenominatorInvalid)
    );

    let mut tiny = QueryResourceBudgetsV1::v03_frozen();
    tiny.max_records_per_shard = 1;
    assert_eq!(
        build_adjacency_routing_index_with_budgets_v1(&nodes, &edges, &tiny),
        Err(AdjacencyIndexErrorV1::ResourceBudgetExceeded)
    );

    assert!(matches!(
        route_adjacency_edges_v1(
            &AdjacencyRoutingIndexV1 {
                catalog: catalog_tamper.catalog,
                shards: catalog_tamper.shards,
            },
            "node-client",
            AdjacencyDirectionV1::Outgoing,
        ),
        Err(AdjacencyIndexErrorV1::CatalogDigestMismatch)
    ));
}
