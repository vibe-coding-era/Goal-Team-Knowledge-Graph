//! Explicit bounded inspection of the confirmed-call projection.
use super::{artifact, graph_projection, index};
use crate::CallContext;
use gtkg_protocol::{v2::V2OperationId, v04::GraphReadPayload};
use serde_json::{Value, json};
use std::{
    collections::{BTreeSet, VecDeque},
    time::Instant,
};
pub fn execute(
    context: &CallContext,
    p: &GraphReadPayload,
    op: V2OperationId,
) -> Result<Value, String> {
    let start = Instant::now();
    let root = artifact::workspace(context, &p.workspace_root)?;
    let (m, mut bytes) = index::load_manifest_with_io(context, &root, &p.index_ref)?;
    let reference = m
        .graph_ref
        .as_ref()
        .ok_or("confirmed graph projection unavailable")?;
    let (g, n) = graph_projection::load_manifest(context, &root, reference)?;
    bytes += n;
    let mut todo = VecDeque::from([(p.source_path.clone(), 0u32)]);
    let mut seen = BTreeSet::new();
    let mut links = vec![];
    let mut partial = false;
    while let Some((path, depth)) = todo.pop_front() {
        if !seen.insert(path.clone()) {
            continue;
        }
        let bucket = index::token_bucket(&path);
        let amount = g
            .router
            .get(&bucket)
            .ok_or("graph routing incomplete")?
            .as_ref()
            .map_or(0, |r| r.bytes);
        if bytes + amount > 64 * 1024 * 1024 || start.elapsed().as_secs_f64() > 5.0 {
            partial = true;
            todo.push_front((path, depth));
            break;
        }
        let (items, n) = graph_projection::load_related_from_manifest(context, &root, &g, &path)?;
        bytes += n;
        for link in items {
            if depth == 0 && p.call_id.as_ref().is_some_and(|id| id != &link.call_id) {
                continue;
            }
            if links.len() >= p.max_results as usize {
                partial = true;
                break;
            }
            if op == V2OperationId::GraphTrace && depth + 1 < p.max_depth {
                todo.push_back((link.target_path.clone(), depth + 1));
            }
            links.push(link);
        }
        if partial {
            break;
        }
    }
    Ok(
        json!({"status":if partial{"partial"}else{"completed_declared_scope"},"source_commit":m.source_commit,"source_tree":m.source_tree,"index_ref":p.index_ref,"graph_ref":reference,"links":links,"pending_sources":todo,"io_bytes":bytes,"wall_seconds":start.elapsed().as_secs_f64(),"query_policy":"gtkg.qk.trace/v1","verification_scope":"pinned index and graph root, selected graph shards; relations replayed at build admission","unresolved_proofs_location":"analysis candidate","candidate_ref":g.candidate_ref,"traversal_scope":"file-level confirmed-call dependencies, not a runtime call path","absence_claim":false}),
    )
}
