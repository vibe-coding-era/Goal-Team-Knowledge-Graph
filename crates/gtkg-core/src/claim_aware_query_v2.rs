//! V0.2 T12B claim-aware, file-backed hybrid search.
//!
//! T11A remains the authority for structure and byte evidence; T11B is the
//! authority for accepted claims and explicit abstentions.  This module reads
//! both independently verified artifacts, binds their immutable identities,
//! and never lets a structural hit become a knowledge assertion.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use serde_json::{Map, Value, json};
use thiserror::Error;

use crate::graph_v3::{
    GraphEvidenceV3, StructuralGraphErrorV3, StructuralGraphV3, read_structural_graph_v3,
};
use crate::knowledge_overlay_v2::{
    KnowledgeOverlayErrorV2, KnowledgeOverlayNodeV2, KnowledgeOverlayV2, read_knowledge_overlay_v2,
};

pub const CLAIM_AWARE_QUERY_RESULT_SCHEMA_V2: &str = "gtkg.claim-aware-query-result/v2";
const MAX_QUERY_LENGTH: usize = 512;
const MAX_RESULTS: usize = 1_000;
const DEFAULT_RESULTS: usize = 100;
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

#[derive(Debug, Error)]
pub enum ClaimAwareQueryErrorV2 {
    #[error("invalid claim-aware query: {0}")]
    InvalidRequest(String),
    #[error("verified structural graph readback failed: {0}")]
    GraphReadback(#[from] StructuralGraphErrorV3),
    #[error("verified knowledge overlay readback failed: {0}")]
    OverlayReadback(#[from] KnowledgeOverlayErrorV2),
    #[error("structural graph and knowledge overlay do not bind: {0}")]
    BindingMismatch(String),
}

impl ClaimAwareQueryErrorV2 {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidRequest(_) => "E_V2_CLAIM_QUERY_INVALID",
            Self::GraphReadback(_) => "E_V2_CLAIM_QUERY_GRAPH_READBACK",
            Self::OverlayReadback(_) => "E_V2_CLAIM_QUERY_OVERLAY_READBACK",
            Self::BindingMismatch(_) => "E_V2_CLAIM_QUERY_BINDING_MISMATCH",
        }
    }
}

/// Search accepted claims, explicit abstentions, and independently verified
/// graph records. The payload is deliberately closed: `query` is required and
/// `max_results` is a bounded presentation limit, never an eager-load hint.
pub fn execute_claim_aware_hybrid_query_v2(
    graph_artifact_root: &Path,
    overlay_artifact_root: &Path,
    payload: &Value,
) -> Result<Value, ClaimAwareQueryErrorV2> {
    let (query, max_results) = parse_request(payload)?;
    let graph = read_structural_graph_v3(graph_artifact_root)?;
    require_plain_overlay_root(overlay_artifact_root)?;
    let overlay = read_knowledge_overlay_v2(overlay_artifact_root)?;
    validate_binding(&graph, &overlay)?;
    let evidence = graph_evidence_by_id(&graph);
    let terms = query_terms(&query);
    let mut candidates = overlay_candidates(&overlay, &evidence)?;
    candidates.extend(structural_candidates(&graph));
    let mut matches = candidates
        .into_iter()
        .filter_map(|candidate| candidate.score(&terms).map(|score| (candidate, score)))
        .collect::<Vec<_>>();
    matches.sort_by(|(left, left_score), (right, right_score)| {
        right_score
            .cmp(left_score)
            .then_with(|| left.kind_rank.cmp(&right.kind_rank))
            .then_with(|| left.entity_id.cmp(&right.entity_id))
    });
    let truncated = matches.len() > max_results;
    matches.truncate(max_results);

    let mut pack_evidence = Vec::new();
    let mut overlay_nodes = Vec::new();
    let result_matches = matches
        .into_iter()
        .map(|(candidate, score)| {
            pack_evidence.extend(candidate.evidence.iter().map(|item| json!(item)));
            if let Some(node) = &candidate.overlay_node {
                overlay_nodes.push(json!({
                    "id": node.id,
                    "kind": node.kind,
                    "claim_id": node.claim_id,
                    "structural_evidence_ids": node.structural_evidence_ids,
                    "provenance": node.provenance,
                }));
            }
            candidate.result_value(score, &terms)
        })
        .collect::<Vec<_>>();
    let response = json!({
        "schema_version": CLAIM_AWARE_QUERY_RESULT_SCHEMA_V2,
        "operation_id": "graph.search",
        "mode": "claim_aware_hybrid",
        "result": {
            "query": query,
            "matches": result_matches,
            "knowledge_conflicts": [],
            "truncated": truncated,
        },
        "evidence_pack": {
            "schema_version": "gtkg.claim-aware-evidence-pack/v2",
            "graph_readback": {
                "graph_sha256": graph.graph_sha256,
                "source_snapshot_exact_set_sha256": graph.source_snapshot_exact_set_sha256,
                "layer": graph.layer,
            },
            "overlay_readback": {
                "overlay_sha256": overlay.overlay_sha256,
                "structural_graph_sha256": overlay.structural_graph_sha256,
                "source_snapshot_exact_set_sha256": overlay.source_snapshot_exact_set_sha256,
                "layer": overlay.layer,
            },
            "overlay_nodes": dedup_values(overlay_nodes),
            "evidence": dedup_values(pack_evidence),
        }
    });
    enforce_response_budget(&response)?;
    Ok(response)
}

fn require_plain_overlay_root(path: &Path) -> Result<(), ClaimAwareQueryErrorV2> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        ClaimAwareQueryErrorV2::BindingMismatch(format!(
            "cannot inspect knowledge overlay artifact root {}: {error}",
            path.display()
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(ClaimAwareQueryErrorV2::BindingMismatch(
            "knowledge overlay artifact root must be a non-symlink directory".to_owned(),
        ));
    }
    Ok(())
}

fn parse_request(payload: &Value) -> Result<(String, usize), ClaimAwareQueryErrorV2> {
    let object = payload.as_object().ok_or_else(|| {
        ClaimAwareQueryErrorV2::InvalidRequest("payload must be a JSON object".to_owned())
    })?;
    if object
        .keys()
        .any(|key| key != "query" && key != "max_results")
    {
        return Err(ClaimAwareQueryErrorV2::InvalidRequest(
            "payload contains an unsupported field for graph.search".to_owned(),
        ));
    }
    let query = object
        .get("query")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            ClaimAwareQueryErrorV2::InvalidRequest("query must be a non-empty string".to_owned())
        })?;
    if query.len() > MAX_QUERY_LENGTH {
        return Err(ClaimAwareQueryErrorV2::InvalidRequest(format!(
            "query must be at most {MAX_QUERY_LENGTH} bytes"
        )));
    }
    let max_results = match object.get("max_results") {
        None => DEFAULT_RESULTS,
        Some(value) => value
            .as_u64()
            .and_then(|number| usize::try_from(number).ok())
            .filter(|number| (1..=MAX_RESULTS).contains(number))
            .ok_or_else(|| {
                ClaimAwareQueryErrorV2::InvalidRequest(format!(
                    "max_results must be an unsigned integer between 1 and {MAX_RESULTS}"
                ))
            })?,
    };
    Ok((query.to_owned(), max_results))
}

fn validate_binding(
    graph: &StructuralGraphV3,
    overlay: &KnowledgeOverlayV2,
) -> Result<(), ClaimAwareQueryErrorV2> {
    if graph.layer != "structural_only" || graph.knowledge_overlay.is_some() {
        return Err(ClaimAwareQueryErrorV2::BindingMismatch(
            "T12B requires a structural_only T11A graph without an embedded overlay".to_owned(),
        ));
    }
    if overlay.layer != "knowledge_overlay"
        || overlay.structural_graph_sha256 != graph.graph_sha256
        || overlay.source_snapshot_exact_set_sha256 != graph.source_snapshot_exact_set_sha256
    {
        return Err(ClaimAwareQueryErrorV2::BindingMismatch(
            "T11B overlay does not match the verified T11A graph identity".to_owned(),
        ));
    }
    for node in &overlay.nodes {
        if node.provenance.structural_graph_sha256 != graph.graph_sha256 {
            return Err(ClaimAwareQueryErrorV2::BindingMismatch(
                "overlay node provenance does not match the verified structural graph".to_owned(),
            ));
        }
    }
    Ok(())
}

fn graph_evidence_by_id(graph: &StructuralGraphV3) -> BTreeMap<String, GraphEvidenceV3> {
    graph
        .nodes
        .iter()
        .flat_map(|node| node.evidence.iter())
        .chain(graph.edges.iter().flat_map(|edge| edge.evidence.iter()))
        .map(|item| (item.evidence_id.clone(), item.clone()))
        .collect()
}

fn overlay_candidates(
    overlay: &KnowledgeOverlayV2,
    evidence_by_id: &BTreeMap<String, GraphEvidenceV3>,
) -> Result<Vec<Candidate>, ClaimAwareQueryErrorV2> {
    let mut result = Vec::new();
    for node in &overlay.nodes {
        let (kind, knowledge_state, kind_rank) = match node.kind.as_str() {
            "accepted_claim" => ("accepted_claim", "accepted_grounded", 0),
            "abstention" => ("abstention", "abstention", 1),
            _ => continue,
        };
        let evidence = node
            .structural_evidence_ids
            .iter()
            .map(|id| {
                evidence_by_id.get(id).cloned().ok_or_else(|| {
                    ClaimAwareQueryErrorV2::BindingMismatch(format!(
                        "overlay node {} references structural evidence absent from T11A",
                        node.id
                    ))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        if evidence.is_empty() {
            return Err(ClaimAwareQueryErrorV2::BindingMismatch(format!(
                "semantic overlay node {} has no verified structural evidence",
                node.id
            )));
        }
        let claim_id = node.claim_id.clone().ok_or_else(|| {
            ClaimAwareQueryErrorV2::BindingMismatch(format!(
                "semantic overlay node {} lacks its claim id",
                node.id
            ))
        })?;
        result.push(Candidate {
            kind,
            kind_rank,
            entity_id: node.id.clone(),
            label: node.label.clone(),
            claim_id: Some(claim_id),
            knowledge_state,
            searchable: format!(
                "{} {} {}",
                node.id,
                node.label,
                node.claim_id.as_deref().unwrap_or_default()
            ),
            evidence,
            overlay_node: Some(node.clone()),
        });
    }
    Ok(result)
}

fn structural_candidates(graph: &StructuralGraphV3) -> Vec<Candidate> {
    let mut result = Vec::new();
    for node in &graph.nodes {
        result.push(Candidate {
            kind: "structural_node",
            kind_rank: 2,
            entity_id: node.id.clone(),
            label: node.label.clone(),
            claim_id: None,
            knowledge_state: "structural_only",
            searchable: format!(
                "{} {} {} {}",
                node.id, node.kind, node.label, node.source_logical_path
            ),
            evidence: node.evidence.clone(),
            overlay_node: None,
        });
    }
    for edge in &graph.edges {
        result.push(Candidate {
            kind: "structural_edge",
            kind_rank: 3,
            entity_id: edge.id.clone(),
            label: format!("{} {}", edge.kind, edge.target_reference),
            claim_id: None,
            knowledge_state: "structural_only",
            searchable: format!(
                "{} {} {} {} {}",
                edge.id,
                edge.kind,
                edge.source_node_id,
                edge.target_node_id.as_deref().unwrap_or_default(),
                edge.target_reference
            ),
            evidence: edge.evidence.clone(),
            overlay_node: None,
        });
    }
    result
}

#[derive(Debug, Clone)]
struct Candidate {
    kind: &'static str,
    kind_rank: u8,
    entity_id: String,
    label: String,
    claim_id: Option<String>,
    knowledge_state: &'static str,
    searchable: String,
    evidence: Vec<GraphEvidenceV3>,
    overlay_node: Option<KnowledgeOverlayNodeV2>,
}

impl Candidate {
    fn score(&self, terms: &[String]) -> Option<u64> {
        let searchable = self.searchable.to_ascii_lowercase();
        let matched = terms
            .iter()
            .filter(|term| searchable.contains(term.as_str()))
            .count() as u64;
        (matched > 0).then_some(matched * 100 + self.evidence.len() as u64)
    }

    fn result_value(&self, score: u64, terms: &[String]) -> Value {
        let searchable = self.searchable.to_ascii_lowercase();
        let matched_terms = terms
            .iter()
            .filter(|term| searchable.contains(term.as_str()))
            .cloned()
            .collect::<Vec<_>>();
        let mut value = Map::new();
        value.insert("kind".to_owned(), json!(self.kind));
        value.insert("entity_id".to_owned(), json!(self.entity_id));
        value.insert("label".to_owned(), json!(self.label));
        value.insert("knowledge_state".to_owned(), json!(self.knowledge_state));
        value.insert("matched_terms".to_owned(), json!(matched_terms));
        value.insert("score".to_owned(), json!(score));
        if let Some(claim_id) = &self.claim_id {
            value.insert("claim_id".to_owned(), json!(claim_id));
        }
        Value::Object(value)
    }
}

fn query_terms(query: &str) -> Vec<String> {
    let mut terms = query
        .split(|character: char| {
            !character.is_alphanumeric() && character != '_' && character != '-'
        })
        .map(str::trim)
        .filter(|term| !term.is_empty())
        .map(str::to_ascii_lowercase)
        .collect::<Vec<_>>();
    terms.sort();
    terms.dedup();
    terms
}

fn dedup_values(values: Vec<Value>) -> Vec<Value> {
    let mut seen = BTreeSet::new();
    values
        .into_iter()
        .filter(|value| seen.insert(serde_json::to_string(value).expect("evidence serializes")))
        .collect()
}

fn enforce_response_budget(response: &Value) -> Result<(), ClaimAwareQueryErrorV2> {
    let bytes = serde_json::to_vec(response).map_err(|error| {
        ClaimAwareQueryErrorV2::InvalidRequest(format!("cannot encode query response: {error}"))
    })?;
    if bytes.len() > MAX_RESPONSE_BYTES {
        return Err(ClaimAwareQueryErrorV2::InvalidRequest(format!(
            "query response exceeds {MAX_RESPONSE_BYTES} bytes"
        )));
    }
    Ok(())
}
