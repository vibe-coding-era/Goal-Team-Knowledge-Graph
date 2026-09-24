//! V0.2 T12A structural-only Graph v3 queries.
//!
//! Every query starts with verified Graph-v3 shard readback.  This module does
//! not accept an overlay, claims, summaries, embeddings, or provider input.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::Path;

use gtkg_protocol::v2::IrResolutionStateV2;
use serde_json::{Value, json};
use thiserror::Error;

use crate::graph_v3::{
    GraphEvidenceV3, StructuralGraphEdgeV3, StructuralGraphErrorV3, StructuralGraphNodeV3,
    StructuralGraphV3, read_structural_graph_v3,
};

pub const STRUCTURAL_QUERY_RESULT_SCHEMA_V3: &str = "gtkg.structural-query-result/v3";
const MAX_QUERY_DEPTH_V3: usize = 8;
const MAX_QUERY_RESULTS_V3: usize = 1_000;
const DEFAULT_QUERY_RESULTS_V3: usize = 100;
const MAX_QUERY_GRAPH_NODES_V3: usize = 50_000;
const MAX_QUERY_GRAPH_EDGES_V3: usize = 50_000;
const MAX_QUERY_QUEUE_V3: usize = 10_000;
const MAX_QUERY_VISITED_NODES_V3: usize = 10_000;
const MAX_QUERY_INSPECTED_EDGES_V3: usize = 50_000;
const MAX_QUERY_EVIDENCE_ITEMS_V3: usize = 4_096;
const MAX_QUERY_RESPONSE_BYTES_V3: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StructuralQueryOperationV3 {
    Neighbors,
    Path,
    Impact,
    Explain,
    Trace,
}

impl StructuralQueryOperationV3 {
    pub const fn operation_id(self) -> &'static str {
        match self {
            Self::Neighbors => "graph.neighbors",
            Self::Path => "graph.path",
            Self::Impact => "graph.impact",
            Self::Explain => "graph.explain",
            Self::Trace => "graph.trace",
        }
    }
}

#[derive(Debug, Error)]
pub enum StructuralQueryErrorV3 {
    #[error("invalid structural query: {0}")]
    InvalidRequest(String),
    #[error("structural graph readback failed: {0}")]
    Readback(#[from] StructuralGraphErrorV3),
}

impl StructuralQueryErrorV3 {
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidRequest(_) => "E_V2_STRUCTURAL_QUERY_INVALID",
            Self::Readback(_) => "E_V2_STRUCTURAL_QUERY_READBACK",
        }
    }
}

/// Execute one bounded query against a verified T11A graph artifact directory.
/// The result always contains an Evidence Pack and never creates a knowledge
/// overlay.  `payload` is deliberately closed per operation.
pub fn execute_structural_query_v3(
    graph_artifact_root: &Path,
    operation: StructuralQueryOperationV3,
    payload: &Value,
) -> Result<Value, StructuralQueryErrorV3> {
    let graph = read_structural_graph_v3(graph_artifact_root)?;
    require_structural_only(&graph)?;
    enforce_graph_budget(&graph)?;
    let result = match operation {
        StructuralQueryOperationV3::Neighbors => neighbors(&graph, payload)?,
        StructuralQueryOperationV3::Path => path(&graph, payload)?,
        StructuralQueryOperationV3::Impact => impact(&graph, payload)?,
        StructuralQueryOperationV3::Explain => explain(&graph, payload)?,
        StructuralQueryOperationV3::Trace => trace(&graph, payload)?,
    };
    let response = envelope(operation, &graph, result);
    enforce_response_budget(&response)?;
    Ok(response)
}

fn require_structural_only(graph: &StructuralGraphV3) -> Result<(), StructuralQueryErrorV3> {
    if graph.layer != "structural_only" || graph.knowledge_overlay.is_some() {
        return Err(StructuralQueryErrorV3::InvalidRequest(
            "T12A accepts only a Graph v3 structural_only artifact with no overlay".to_owned(),
        ));
    }
    Ok(())
}

fn envelope(
    operation: StructuralQueryOperationV3,
    graph: &StructuralGraphV3,
    result: QueryResult,
) -> Value {
    json!({
        "schema_version": STRUCTURAL_QUERY_RESULT_SCHEMA_V3,
        "operation_id": operation.operation_id(),
        "mode": "structural_only",
        "result": result.value,
        "truncated": result.truncated,
        "evidence_pack": {
            "schema_version": "gtkg.structural-evidence-pack/v3",
            "graph_readback": {
                "graph_sha256": graph.graph_sha256,
                "source_snapshot_exact_set_sha256": graph.source_snapshot_exact_set_sha256,
                "layer": graph.layer,
                "knowledge_overlay": graph.knowledge_overlay,
            },
            "evidence": result.evidence,
        }
    })
}

fn enforce_graph_budget(graph: &StructuralGraphV3) -> Result<(), StructuralQueryErrorV3> {
    if graph.nodes.len() > MAX_QUERY_GRAPH_NODES_V3 {
        return Err(budget_error("graph nodes", MAX_QUERY_GRAPH_NODES_V3));
    }
    if graph.edges.len() > MAX_QUERY_GRAPH_EDGES_V3 {
        return Err(budget_error("graph edges", MAX_QUERY_GRAPH_EDGES_V3));
    }
    Ok(())
}

fn enforce_response_budget(response: &Value) -> Result<(), StructuralQueryErrorV3> {
    let evidence_count = response["evidence_pack"]["evidence"]
        .as_array()
        .map_or(0, Vec::len);
    if evidence_count > MAX_QUERY_EVIDENCE_ITEMS_V3 {
        return Err(budget_error("evidence items", MAX_QUERY_EVIDENCE_ITEMS_V3));
    }
    let bytes = serde_json::to_vec(response).map_err(|error| {
        StructuralQueryErrorV3::InvalidRequest(format!(
            "cannot encode structural response: {error}"
        ))
    })?;
    if bytes.len() > MAX_QUERY_RESPONSE_BYTES_V3 {
        return Err(budget_error("response bytes", MAX_QUERY_RESPONSE_BYTES_V3));
    }
    Ok(())
}

fn budget_error(kind: &str, limit: usize) -> StructuralQueryErrorV3 {
    StructuralQueryErrorV3::InvalidRequest(format!(
        "query budget exceeded for {kind}; limit is {limit}"
    ))
}

struct QueryResult {
    value: Value,
    evidence: Vec<Value>,
    truncated: bool,
}

fn neighbors(
    graph: &StructuralGraphV3,
    payload: &Value,
) -> Result<QueryResult, StructuralQueryErrorV3> {
    let object = object(payload, &["node_id", "direction", "max_results"])?;
    let node_id = required_string(object, "node_id")?;
    let node = graph_node(graph, node_id)?;
    let direction = optional_string(object, "direction")?.unwrap_or("both");
    if !matches!(direction, "incoming" | "outgoing" | "both") {
        return Err(StructuralQueryErrorV3::InvalidRequest(
            "direction must be incoming, outgoing, or both".to_owned(),
        ));
    }
    let max_results = bounded_results(object)?;
    let mut entries = Vec::new();
    let mut truncated = false;
    for edge in &graph.edges {
        let outgoing = edge.source_node_id == node_id;
        let incoming = edge.target_node_id.as_deref() == Some(node_id);
        if (direction == "outgoing" && !outgoing)
            || (direction == "incoming" && !incoming)
            || (direction == "both" && !outgoing && !incoming)
        {
            continue;
        }
        let neighbor_id = if outgoing {
            edge.target_node_id.as_deref()
        } else {
            Some(edge.source_node_id.as_str())
        };
        if entries.len() == max_results {
            truncated = true;
            continue;
        }
        entries.push((edge.id.clone(), edge, neighbor_id));
    }
    let mut evidence = evidence_for_node(node);
    let rows = entries
        .into_iter()
        .map(|(_, edge, neighbor_id)| {
            evidence.extend(evidence_for_edge(edge));
            json!({
                "edge_id": edge.id,
                "edge_kind": edge.kind,
                "direction": if edge.source_node_id == node_id { "outgoing" } else { "incoming" },
                "neighbor_node_id": neighbor_id,
                "target_reference": edge.target_reference,
                "resolution": resolution_name(edge.resolution),
            })
        })
        .collect::<Vec<_>>();
    Ok(QueryResult {
        value: json!({ "node_id": node_id, "direction": direction, "neighbors": rows }),
        evidence: dedup_evidence(evidence),
        truncated,
    })
}

fn path(graph: &StructuralGraphV3, payload: &Value) -> Result<QueryResult, StructuralQueryErrorV3> {
    let object = object(payload, &["source_node_id", "target_node_id", "max_depth"])?;
    let source = required_string(object, "source_node_id")?;
    let target = required_string(object, "target_node_id")?;
    let source_node = graph_node(graph, source)?;
    let target_node = graph_node(graph, target)?;
    let max_depth = bounded_depth(object)?;
    let adjacency = outgoing_adjacency(graph);
    let mut queue = VecDeque::from([(
        source.to_owned(),
        Vec::<String>::new(),
        Vec::<String>::new(),
    )]);
    let mut seen_depth = BTreeMap::from([(source.to_owned(), 0_usize)]);
    let mut inspected_edges = 0_usize;
    let mut found = None;
    while let Some((node_id, node_ids, edge_ids)) = queue.pop_front() {
        if node_id == target {
            let mut nodes = vec![source.to_owned()];
            nodes.extend(node_ids);
            found = Some((nodes, edge_ids));
            break;
        }
        if edge_ids.len() == max_depth {
            continue;
        }
        if let Some(items) = adjacency.get(&node_id) {
            for (next, edge_id) in items {
                inspected_edges = inspected_edges
                    .checked_add(1)
                    .ok_or_else(|| budget_error("inspected edges", MAX_QUERY_INSPECTED_EDGES_V3))?;
                if inspected_edges > MAX_QUERY_INSPECTED_EDGES_V3 {
                    return Err(budget_error(
                        "inspected edges",
                        MAX_QUERY_INSPECTED_EDGES_V3,
                    ));
                }
                let next_depth = edge_ids.len() + 1;
                if seen_depth
                    .get(next)
                    .is_some_and(|depth| *depth <= next_depth)
                {
                    continue;
                }
                if seen_depth.len() == MAX_QUERY_VISITED_NODES_V3 {
                    return Err(budget_error("visited nodes", MAX_QUERY_VISITED_NODES_V3));
                }
                if queue.len() == MAX_QUERY_QUEUE_V3 {
                    return Err(budget_error("queue entries", MAX_QUERY_QUEUE_V3));
                }
                seen_depth.insert(next.clone(), next_depth);
                let mut next_nodes = node_ids.clone();
                next_nodes.push(next.clone());
                let mut next_edges = edge_ids.clone();
                next_edges.push(edge_id.clone());
                queue.push_back((next.clone(), next_nodes, next_edges));
            }
        }
    }
    let mut evidence = evidence_for_node(source_node);
    evidence.extend(evidence_for_node(target_node));
    let value = if let Some((node_ids, edge_ids)) = found {
        for edge_id in &edge_ids {
            evidence.extend(evidence_for_edge(graph_edge(graph, edge_id)?));
        }
        json!({ "source_node_id": source, "target_node_id": target, "max_depth": max_depth, "found": true, "node_ids": node_ids, "edge_ids": edge_ids })
    } else {
        json!({ "source_node_id": source, "target_node_id": target, "max_depth": max_depth, "found": false, "node_ids": [], "edge_ids": [] })
    };
    Ok(QueryResult {
        value,
        evidence: dedup_evidence(evidence),
        truncated: false,
    })
}

fn impact(
    graph: &StructuralGraphV3,
    payload: &Value,
) -> Result<QueryResult, StructuralQueryErrorV3> {
    let object = object(payload, &["node_id", "max_depth", "max_results"])?;
    let source = required_string(object, "node_id")?;
    let source_node = graph_node(graph, source)?;
    let max_depth = bounded_depth(object)?;
    let max_results = bounded_results(object)?;
    let mut queue = VecDeque::from([(source.to_owned(), 0_usize)]);
    let mut visited = BTreeMap::from([(source.to_owned(), 0_usize)]);
    let mut rows = Vec::new();
    let mut truncated = false;
    let mut inspected_edges = 0_usize;
    let mut evidence = evidence_for_node(source_node);
    while let Some((node_id, depth)) = queue.pop_front() {
        if depth == max_depth {
            continue;
        }
        for edge in graph
            .edges
            .iter()
            .filter(|edge| edge.source_node_id == node_id)
        {
            inspected_edges = inspected_edges
                .checked_add(1)
                .ok_or_else(|| budget_error("inspected edges", MAX_QUERY_INSPECTED_EDGES_V3))?;
            if inspected_edges > MAX_QUERY_INSPECTED_EDGES_V3 {
                return Err(budget_error(
                    "inspected edges",
                    MAX_QUERY_INSPECTED_EDGES_V3,
                ));
            }
            let next_depth = depth + 1;
            match edge.resolution {
                IrResolutionStateV2::Resolved => {
                    if let Some(target) = &edge.target_node_id {
                        push_impact_row(
                            &mut rows,
                            max_results,
                            &mut truncated,
                            impact_row(edge, "confirmed", Some(target), next_depth),
                            &mut evidence,
                            edge,
                            graph_node(graph, target)?,
                        );
                        if visited.get(target).is_none_or(|known| *known > next_depth) {
                            if visited.len() == MAX_QUERY_VISITED_NODES_V3 {
                                return Err(budget_error(
                                    "visited nodes",
                                    MAX_QUERY_VISITED_NODES_V3,
                                ));
                            }
                            if queue.len() == MAX_QUERY_QUEUE_V3 {
                                return Err(budget_error("queue entries", MAX_QUERY_QUEUE_V3));
                            }
                            visited.insert(target.clone(), next_depth);
                            queue.push_back((target.clone(), next_depth));
                        }
                    }
                }
                IrResolutionStateV2::Ambiguous => {
                    for target in &edge.candidate_node_ids {
                        push_impact_row(
                            &mut rows,
                            max_results,
                            &mut truncated,
                            impact_row(edge, "possible", Some(target), next_depth),
                            &mut evidence,
                            edge,
                            graph_node(graph, target)?,
                        );
                    }
                }
                IrResolutionStateV2::Unresolved | IrResolutionStateV2::NotApplicable => {
                    if rows.len() == max_results {
                        truncated = true;
                    } else {
                        evidence.extend(evidence_for_edge(edge));
                        rows.push(impact_row(edge, "unknown", None, next_depth));
                    }
                }
            }
        }
    }
    rows.sort_by(|left, right| {
        left["depth"]
            .as_u64()
            .cmp(&right["depth"].as_u64())
            .then_with(|| left["edge_id"].as_str().cmp(&right["edge_id"].as_str()))
            .then_with(|| left["node_id"].as_str().cmp(&right["node_id"].as_str()))
    });
    Ok(QueryResult {
        value: json!({ "node_id": source, "max_depth": max_depth, "impacts": rows }),
        evidence: dedup_evidence(evidence),
        truncated,
    })
}

fn explain(
    graph: &StructuralGraphV3,
    payload: &Value,
) -> Result<QueryResult, StructuralQueryErrorV3> {
    let object = object(payload, &["node_id", "max_results"])?;
    let node_id = required_string(object, "node_id")?;
    let node = graph_node(graph, node_id)?;
    let max_results = bounded_results(object)?;
    let mut edges = Vec::new();
    let mut truncated = false;
    for edge in graph.edges.iter().filter(|edge| {
        edge.source_node_id == node_id || edge.target_node_id.as_deref() == Some(node_id)
    }) {
        if edges.len() == max_results {
            truncated = true;
        } else {
            edges.push(edge);
        }
    }
    let mut evidence = evidence_for_node(node);
    let relations = edges
        .into_iter()
        .map(|edge| {
            evidence.extend(evidence_for_edge(edge));
            edge_value(edge)
        })
        .collect::<Vec<_>>();
    Ok(QueryResult {
        value: json!({ "node": node_value(node), "relations": relations }),
        evidence: dedup_evidence(evidence),
        truncated,
    })
}

fn trace(
    graph: &StructuralGraphV3,
    payload: &Value,
) -> Result<QueryResult, StructuralQueryErrorV3> {
    let object = object(payload, &["entity_id"])?;
    let entity_id = required_string(object, "entity_id")?;
    let (provenance, evidence, entity_kind) =
        if let Some(node) = graph.nodes.iter().find(|node| node.id == entity_id) {
            (json!(node.provenance), evidence_for_node(node), "node")
        } else if let Some(edge) = graph.edges.iter().find(|edge| edge.id == entity_id) {
            (json!(edge.provenance), evidence_for_edge(edge), "edge")
        } else {
            return Err(StructuralQueryErrorV3::InvalidRequest(format!(
                "entity_id {entity_id} is absent from the verified structural graph"
            )));
        };
    Ok(QueryResult {
        value: json!({
            "entity_id": entity_id,
            "entity_kind": entity_kind,
            "structural_provenance": provenance,
            "unavailable_lineage": ["accepted_claim", "okf_verification"],
            "reason": "T12A is structural_only and does not read a knowledge overlay",
        }),
        evidence: dedup_evidence(evidence),
        truncated: false,
    })
}

fn object<'a>(
    value: &'a Value,
    allowed: &[&str],
) -> Result<&'a serde_json::Map<String, Value>, StructuralQueryErrorV3> {
    let object = value.as_object().ok_or_else(|| {
        StructuralQueryErrorV3::InvalidRequest("payload must be a JSON object".to_owned())
    })?;
    if object.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err(StructuralQueryErrorV3::InvalidRequest(
            "payload contains an unsupported field for this structural operation".to_owned(),
        ));
    }
    Ok(object)
}

fn required_string<'a>(
    object: &'a serde_json::Map<String, Value>,
    key: &str,
) -> Result<&'a str, StructuralQueryErrorV3> {
    object
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            StructuralQueryErrorV3::InvalidRequest(format!("{key} must be a non-empty string"))
        })
}

fn optional_string<'a>(
    object: &'a serde_json::Map<String, Value>,
    key: &str,
) -> Result<Option<&'a str>, StructuralQueryErrorV3> {
    match object.get(key) {
        None => Ok(None),
        Some(value) => value.as_str().map(Some).ok_or_else(|| {
            StructuralQueryErrorV3::InvalidRequest(format!("{key} must be a string"))
        }),
    }
}

fn bounded_depth(object: &serde_json::Map<String, Value>) -> Result<usize, StructuralQueryErrorV3> {
    bounded_unsigned(object, "max_depth", 1, MAX_QUERY_DEPTH_V3, 1)
}
fn bounded_results(
    object: &serde_json::Map<String, Value>,
) -> Result<usize, StructuralQueryErrorV3> {
    bounded_unsigned(
        object,
        "max_results",
        1,
        MAX_QUERY_RESULTS_V3,
        DEFAULT_QUERY_RESULTS_V3,
    )
}

fn bounded_unsigned(
    object: &serde_json::Map<String, Value>,
    key: &str,
    min: usize,
    max: usize,
    default: usize,
) -> Result<usize, StructuralQueryErrorV3> {
    let Some(value) = object.get(key) else {
        return Ok(default);
    };
    let value = value
        .as_u64()
        .and_then(|number| usize::try_from(number).ok())
        .ok_or_else(|| {
            StructuralQueryErrorV3::InvalidRequest(format!("{key} must be an unsigned integer"))
        })?;
    if !(min..=max).contains(&value) {
        return Err(StructuralQueryErrorV3::InvalidRequest(format!(
            "{key} must be between {min} and {max}"
        )));
    }
    Ok(value)
}

fn graph_node<'a>(
    graph: &'a StructuralGraphV3,
    id: &str,
) -> Result<&'a StructuralGraphNodeV3, StructuralQueryErrorV3> {
    graph
        .nodes
        .iter()
        .find(|node| node.id == id)
        .ok_or_else(|| {
            StructuralQueryErrorV3::InvalidRequest(format!(
                "node_id {id} is absent from the verified structural graph"
            ))
        })
}
fn graph_edge<'a>(
    graph: &'a StructuralGraphV3,
    id: &str,
) -> Result<&'a StructuralGraphEdgeV3, StructuralQueryErrorV3> {
    graph
        .edges
        .iter()
        .find(|edge| edge.id == id)
        .ok_or_else(|| {
            StructuralQueryErrorV3::InvalidRequest(format!(
                "edge_id {id} is absent from the verified structural graph"
            ))
        })
}

fn outgoing_adjacency(graph: &StructuralGraphV3) -> BTreeMap<String, Vec<(String, String)>> {
    let mut adjacency = BTreeMap::<String, Vec<(String, String)>>::new();
    for edge in &graph.edges {
        if edge.resolution == IrResolutionStateV2::Resolved
            && let Some(target) = &edge.target_node_id
        {
            adjacency
                .entry(edge.source_node_id.clone())
                .or_default()
                .push((target.clone(), edge.id.clone()));
        }
    }
    for targets in adjacency.values_mut() {
        targets.sort();
    }
    adjacency
}

fn node_value(node: &StructuralGraphNodeV3) -> Value {
    json!({ "id": node.id, "kind": node.kind, "label": node.label, "source_logical_path": node.source_logical_path })
}
fn edge_value(edge: &StructuralGraphEdgeV3) -> Value {
    json!({ "id": edge.id, "kind": edge.kind, "source_node_id": edge.source_node_id, "target_node_id": edge.target_node_id, "target_reference": edge.target_reference, "resolution": resolution_name(edge.resolution), "candidate_node_ids": edge.candidate_node_ids })
}
fn impact_row(
    edge: &StructuralGraphEdgeV3,
    label: &str,
    node_id: Option<&str>,
    depth: usize,
) -> Value {
    json!({ "edge_id": edge.id, "node_id": node_id, "target_reference": edge.target_reference, "label": label, "depth": depth })
}
fn resolution_name(value: IrResolutionStateV2) -> &'static str {
    match value {
        IrResolutionStateV2::Resolved => "resolved",
        IrResolutionStateV2::Unresolved => "unresolved",
        IrResolutionStateV2::Ambiguous => "ambiguous",
        IrResolutionStateV2::NotApplicable => "not_applicable",
    }
}

fn evidence_for_node(node: &StructuralGraphNodeV3) -> Vec<Value> {
    evidence_values(&node.evidence)
}
fn evidence_for_edge(edge: &StructuralGraphEdgeV3) -> Vec<Value> {
    evidence_values(&edge.evidence)
}
fn evidence_values(items: &[GraphEvidenceV3]) -> Vec<Value> {
    items.iter().map(|item| json!(item)).collect()
}
fn dedup_evidence(items: Vec<Value>) -> Vec<Value> {
    let mut seen = BTreeSet::new();
    let mut result = Vec::new();
    for item in items {
        let encoded = serde_json::to_string(&item).expect("graph evidence serializes");
        if seen.insert(encoded) {
            result.push(item);
        }
    }
    result
}

fn push_impact_row(
    rows: &mut Vec<Value>,
    max_results: usize,
    truncated: &mut bool,
    row: Value,
    evidence: &mut Vec<Value>,
    edge: &StructuralGraphEdgeV3,
    target: &StructuralGraphNodeV3,
) {
    if rows.len() == max_results {
        *truncated = true;
        return;
    }
    evidence.extend(evidence_for_edge(edge));
    evidence.extend(evidence_for_node(target));
    rows.push(row);
}
