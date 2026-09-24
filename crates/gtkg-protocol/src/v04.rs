//! Closed, explicit knowledge-quality revisions of existing v2 operations.
use crate::FileReceiptRef;
use crate::v2::V2OperationId as Op;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use std::path::PathBuf;

pub const PROFILE_ID: &str = "GTKG-V0.4-KNOWLEDGE-QUALITY";
pub const PAYLOAD_REVISION: &str = "gtkg.knowledge-quality/v0.4-r1";
pub const QUERY_POLICY: &str = "gtkg.qk.query/v1";
pub const SELECTIVE_QUERY_POLICY: &str = "gtkg.qk.query/v2";
pub const REVIEWED_CONTEXT_QUERY_POLICY: &str = "gtkg.qk.query-reviewed-context/v1";

/// The exact v2 operations that accept the V0.4 knowledge-quality payload revision.
///
/// Every public v2 operation also accepts its default `gtkg.protocol/v2` closed
/// schema, so this set is strictly additive. It mirrors the closed schema set in
/// [`payload_schema`] and [`validate_payload`]; a caller that sends the V0.4
/// revision to an operation outside this set is rejected at the protocol layer
/// with `operation does not support this payload revision`.
///
/// Discovery MUST disclose this set. A profile lists operations, not payload
/// revisions, so without this predicate a caller cannot tell that e.g.
/// `graph.neighbors` is reachable only through the default schema while
/// `graph.search` also accepts the knowledge-quality revision.
pub const fn accepts_knowledge_quality_payload(op: Op) -> bool {
    matches!(
        op,
        Op::SourceCapture
            | Op::AnalysisPlan
            | Op::AnalysisBuild
            | Op::AnalysisVerify
            | Op::BuildFinalizeV2
            | Op::BundleVerify
            | Op::BundleMigrateV1ToV2
            | Op::SummaryJobNext
            | Op::SummaryVerificationNext
            | Op::SummaryProposalSubmit
            | Op::SummaryVerificationSubmit
            | Op::SummaryAcceptV2
            | Op::DeliverableDerive
            | Op::SnapshotRestore
            | Op::GraphSearch
            | Op::ContextPack
            | Op::GraphExplain
            | Op::GraphTrace
            | Op::CapabilityDescribe
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum Revision {
    #[serde(rename = "gtkg.knowledge-quality/v0.4-r1")]
    R1,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScopeRule {
    pub path_prefix: String,
    pub included: bool,
    pub rule_id: String,
    pub origin: String,
    pub reason: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScopePolicy {
    pub revision: String,
    pub rules: Vec<ScopeRule>,
    pub archive_binary: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SourcePayload {
    pub payload_revision: Revision,
    pub repository_id: String,
    pub source_root: PathBuf,
    pub source_commit: String,
    pub expected_tree: String,
    pub output_path: PathBuf,
    pub policy: ScopePolicy,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ArtifactPayload {
    pub payload_revision: Revision,
    pub workspace_root: PathBuf,
    pub artifact_ref: FileReceiptRef,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QueryPayload {
    pub payload_revision: Revision,
    pub workspace_root: PathBuf,
    pub index_ref: FileReceiptRef,
    pub query: String,
    pub query_policy: String,
    pub max_results: u32,
    pub max_tokens: u32,
    pub continuation: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CapabilityPayload {
    pub payload_revision: Revision,
    pub capability_profile: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GraphReadPayload {
    pub payload_revision: Revision,
    pub workspace_root: PathBuf,
    pub index_ref: FileReceiptRef,
    pub source_path: String,
    pub call_id: Option<String>,
    pub max_depth: u32,
    pub max_results: u32,
}
fn parse<T: DeserializeOwned>(value: &Value) -> Result<T, String> {
    serde_json::from_value(value.clone()).map_err(|e| e.to_string())
}
fn oid(s: &str) -> bool {
    (s.len() == 40 || s.len() == 64)
        && s.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}
fn path(p: &std::path::Path) -> Result<(), String> {
    if p.as_os_str().is_empty() {
        Err("path must not be empty".into())
    } else {
        Ok(())
    }
}
fn text(s: &str) -> Result<(), String> {
    if s.trim().is_empty() {
        Err("text must not be empty".into())
    } else {
        Ok(())
    }
}
fn validate_scope_path(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 4096
        || value.contains('\\')
        || value.contains('\0')
        || value.starts_with('/')
        || value
            .split('/')
            .any(|p| p.is_empty() || p == "." || p == "..")
    {
        return Err("scope prefix must be a canonical relative path".into());
    }
    Ok(())
}
pub fn validate_payload(op: Op, value: &Value) -> Result<(), String> {
    if op == Op::ContextPack && value.get("artifact_ref").is_some() {
        let p: ArtifactPayload = parse(value)?;
        path(&p.workspace_root)?;
        return p.artifact_ref.validate().map_err(|e| e.to_string());
    }
    match op {
        Op::SourceCapture => {
            let p: SourcePayload = parse(value)?;
            text(&p.repository_id)?;
            path(&p.source_root)?;
            path(&p.output_path)?;
            if !oid(&p.source_commit) || !oid(&p.expected_tree) {
                return Err("exact lowercase commit/tree object IDs required".into());
            }
            text(&p.policy.revision)?;
            for r in &p.policy.rules {
                validate_scope_path(&r.path_prefix)?;
                text(&r.rule_id)?;
                text(&r.origin)?;
                text(&r.reason)?;
            }
            Ok(())
        }
        Op::AnalysisPlan
        | Op::AnalysisBuild
        | Op::AnalysisVerify
        | Op::BuildFinalizeV2
        | Op::BundleVerify
        | Op::BundleMigrateV1ToV2
        | Op::SummaryJobNext
        | Op::SummaryVerificationNext
        | Op::SummaryProposalSubmit
        | Op::SummaryVerificationSubmit
        | Op::SummaryAcceptV2
        | Op::DeliverableDerive
        | Op::SnapshotRestore => {
            let p: ArtifactPayload = parse(value)?;
            path(&p.workspace_root)?;
            p.artifact_ref.validate().map_err(|e| e.to_string())
        }
        Op::GraphSearch | Op::ContextPack => {
            let p: QueryPayload = parse(value)?;
            path(&p.workspace_root)?;
            p.index_ref.validate().map_err(|e| e.to_string())?;
            text(&p.query)?;
            if p.query.len() > 16384
                || !matches!(
                    p.query_policy.as_str(),
                    QUERY_POLICY | SELECTIVE_QUERY_POLICY | REVIEWED_CONTEXT_QUERY_POLICY
                )
                || !(1..=1000).contains(&p.max_results)
                || !(1..=8000).contains(&p.max_tokens)
                || p.continuation
                    .as_ref()
                    .is_some_and(|c| c.is_empty() || c.len() > 4 * 1024 * 1024)
            {
                return Err("query policy or bounds invalid".into());
            }
            Ok(())
        }
        Op::GraphExplain | Op::GraphTrace => {
            let p: GraphReadPayload = parse(value)?;
            path(&p.workspace_root)?;
            p.index_ref.validate().map_err(|e| e.to_string())?;
            validate_scope_path(&p.source_path)?;
            if !(1..=8).contains(&p.max_depth)
                || !(1..=1000).contains(&p.max_results)
                || p.call_id
                    .as_ref()
                    .is_some_and(|id| id.is_empty() || id.len() > 512)
            {
                return Err("graph query bounds invalid".into());
            }
            Ok(())
        }
        Op::CapabilityDescribe => {
            let p: CapabilityPayload = parse(value)?;
            if p.capability_profile != PROFILE_ID {
                return Err("unsupported capability profile".into());
            }
            Ok(())
        }
        _ => Err("operation does not support this payload revision".into()),
    }
}
fn schema<T: JsonSchema>() -> Value {
    let mut v = serde_json::to_value(schemars::schema_for!(T)).expect("schema serialization");
    let defs = v.get("$defs").cloned().unwrap_or(json!({}));
    fn inline(v: &mut Value, defs: &Value, depth: usize) {
        if depth > 32 {
            return;
        }
        if let Some(name) = v
            .get("$ref")
            .and_then(Value::as_str)
            .and_then(|r| r.strip_prefix("#/$defs/"))
            && let Some(d) = defs.get(name)
        {
            *v = d.clone();
            inline(v, defs, depth + 1);
            return;
        }
        match v {
            Value::Object(m) => {
                for (k, v) in m.iter_mut() {
                    if k != "$defs" {
                        inline(v, defs, depth + 1)
                    }
                }
            }
            Value::Array(a) => {
                for v in a {
                    inline(v, defs, depth + 1)
                }
            }
            _ => {}
        }
    }
    inline(&mut v, &defs, 0);
    if let Some(o) = v.as_object_mut() {
        o.remove("$defs");
        o.remove("$schema");
    }
    v["properties"]["payload_revision"] = json!({"type":"string","const":PAYLOAD_REVISION});
    v
}
fn query_schema() -> Value {
    let mut value = schema::<QueryPayload>();
    value["properties"]["query_policy"] = json!({"type":"string","enum":[QUERY_POLICY,SELECTIVE_QUERY_POLICY,REVIEWED_CONTEXT_QUERY_POLICY]});
    value["properties"]["max_results"] = json!({"type":"integer","minimum":1,"maximum":1000});
    value["properties"]["max_tokens"] = json!({"type":"integer","minimum":1,"maximum":8000});
    value
}
pub fn payload_schema(op: Op) -> Option<Value> {
    Some(match op {
        Op::SourceCapture => schema::<SourcePayload>(),
        Op::AnalysisPlan
        | Op::AnalysisBuild
        | Op::AnalysisVerify
        | Op::BuildFinalizeV2
        | Op::BundleVerify
        | Op::BundleMigrateV1ToV2
        | Op::SummaryJobNext
        | Op::SummaryVerificationNext
        | Op::SummaryProposalSubmit
        | Op::SummaryVerificationSubmit
        | Op::SummaryAcceptV2
        | Op::DeliverableDerive
        | Op::SnapshotRestore => schema::<ArtifactPayload>(),
        Op::GraphSearch => query_schema(),
        Op::ContextPack => json!({"oneOf":[query_schema(),schema::<ArtifactPayload>()]}),
        Op::CapabilityDescribe => schema::<CapabilityPayload>(),
        Op::GraphExplain | Op::GraphTrace => schema::<GraphReadPayload>(),
        _ => return None,
    })
}
