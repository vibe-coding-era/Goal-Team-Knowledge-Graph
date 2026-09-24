//! Public local node description and federation validation operations.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::Write;
use std::path::{Path, PathBuf};

use gtkg_protocol::{
    ErrorCode, NodeDescriptor, OperationRequest, OperationResponse, SandboxPolicyLock, ShardResult,
    WorkUnit, canonical_json_sha256,
};
use serde::Deserialize;
use serde_json::json;

use crate::CallContext;
use crate::durable::{DurableErrorKind, DurableWriteError, publish_immutable_json};
use crate::federation::{freeze_node_set, reduce_shard_results};
use crate::sandbox::{MacOsSandboxExecProvider, SandboxProvider};

#[derive(Debug)]
pub struct NodeFailure {
    pub code: ErrorCode,
    pub stage: &'static str,
    pub message: String,
    pub recovery_hint: &'static str,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NodeDescribePayload {
    descriptor: NodeDescriptor,
    #[serde(default)]
    probe_sandbox: bool,
    #[serde(default)]
    sandbox_policy: Option<SandboxPolicyLock>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FederationValidatePayload {
    nodes: Vec<NodeDescriptor>,
    work_units: Vec<WorkUnit>,
    shard_results: Vec<ShardResult>,
    #[serde(default)]
    workspace_root: Option<PathBuf>,
}

pub fn describe(
    context: &CallContext,
    request: &OperationRequest,
) -> Result<OperationResponse, NodeFailure> {
    let payload: NodeDescribePayload = parse_payload(request, "node.describe")?;
    payload
        .descriptor
        .validate()
        .map_err(|error| invalid("node.describe", error.to_string()))?;
    let descriptor_digest = canonical_json_sha256(&payload.descriptor)
        .map_err(|error| invalid("node.describe", error.to_string()))?;
    let provider = MacOsSandboxExecProvider::new();
    let provider_description = provider.describe();
    let probe = if payload.probe_sandbox {
        let policy = payload.sandbox_policy.as_ref().ok_or_else(|| {
            invalid(
                "node.describe",
                "probe_sandbox=true requires an exact sandbox_policy",
            )
        })?;
        for root in &policy.input_roots {
            context
                .authorize_read(root)
                .map_err(|error| path_failure("node.describe", error))?;
        }
        context
            .authorize_write(&policy.scratch_root)
            .map_err(|error| path_failure("node.describe", error))?;
        Some(provider.probe(policy).map_err(|failure| NodeFailure {
            code: failure.code,
            stage: failure.stage,
            message: failure.message,
            recovery_hint: failure.recovery_hint,
        })?)
    } else {
        if payload.sandbox_policy.is_some() {
            return Err(invalid(
                "node.describe",
                "sandbox_policy is only accepted when probe_sandbox=true",
            ));
        }
        None
    };
    Ok(OperationResponse::completed(
        request,
        json!({
            "descriptor": payload.descriptor,
            "descriptor_sha256": descriptor_digest,
            "sandbox_provider": provider_description,
            "sandbox_probe": probe,
            "sb2_claimed": probe.as_ref().is_some_and(|result| result.passed),
            "release_ready": false,
        }),
    ))
}

pub fn validate_federation(
    context: &CallContext,
    request: &OperationRequest,
) -> Result<OperationResponse, NodeFailure> {
    let payload: FederationValidatePayload = parse_payload(request, "federation.validate")?;
    let node_set = freeze_node_set(payload.nodes).map_err(map_federation)?;
    let node_ids: BTreeSet<_> = node_set
        .nodes
        .iter()
        .map(|node| node.node_id.as_str())
        .collect();
    let work_by_id: BTreeMap<_, _> = payload
        .work_units
        .iter()
        .map(|work| (work.work_id.as_str(), work))
        .collect();
    let nodes_by_id: BTreeMap<_, _> = node_set
        .nodes
        .iter()
        .map(|node| (node.node_id.as_str(), node))
        .collect();
    for result in &payload.shard_results {
        if !node_ids.contains(result.node_id.as_str()) {
            return Err(invalid(
                "federation.validate",
                format!("result uses an unlocked node: {}", result.node_id),
            ));
        }
        let work = work_by_id.get(result.work_id.as_str()).ok_or_else(|| {
            invalid(
                "federation.validate",
                format!("result uses an unknown WorkId: {}", result.work_id),
            )
        })?;
        let node = nodes_by_id.get(result.node_id.as_str()).ok_or_else(|| {
            invalid(
                "federation.validate",
                format!("node descriptor disappeared: {}", result.node_id),
            )
        })?;
        if !node.work_unit_kinds.contains(&work.kind) {
            return Err(invalid(
                "federation.validate",
                format!(
                    "node {} is not locked for work kind {}",
                    node.node_id, work.kind
                ),
            ));
        }
    }
    let accepted = reduce_shard_results(&payload.work_units, &payload.shard_results)
        .map_err(map_federation)?;
    let node_set_sha256 = canonical_json_sha256(&node_set)
        .map_err(|error| invalid("federation.validate", error.to_string()))?;
    let mut work_ids = payload
        .work_units
        .iter()
        .map(|work| work.work_id.as_str())
        .collect::<Vec<_>>();
    work_ids.sort();
    let accepted_outputs = accepted
        .iter()
        .map(|result| {
            json!({
                "work_id": result.work_id,
                "output_sha256": result.output_sha256,
            })
        })
        .collect::<Vec<_>>();
    let receipt = json!({
        "schema_version": "gtkg.federation-receipt/v1",
        "node_set_sha256": node_set_sha256,
        "work_ids": work_ids,
        "accepted_outputs": accepted_outputs,
        "canonical_write_count": 0,
        "reduction_order": "work_id",
        "delivery": "at_least_once_idempotent",
    });
    let receipt_sha256 = canonical_json_sha256(&receipt)
        .map_err(|error| invalid("federation.validate", error.to_string()))?;
    let mut evidence_refs = Vec::new();
    if let Some(workspace_root) = payload.workspace_root {
        if !workspace_root.is_absolute() {
            return Err(invalid(
                "federation.validate",
                "workspace_root must be absolute",
            ));
        }
        let workspace_root = context
            .authorize_write(&workspace_root)
            .map_err(|error| path_failure("federation.validate", error))?;
        let lock_path = context
            .authorize_write(&workspace_root.join(".gtkg/federation-writer.lock"))
            .map_err(|error| path_failure("federation.validate", error))?;
        let _guard = ReceiptGuard::acquire(&lock_path)?;
        let directory = context
            .authorize_write(&workspace_root.join(".gtkg/receipts/federation"))
            .map_err(|error| path_failure("federation.validate", error))?;
        fs::create_dir_all(&directory)
            .map_err(|error| io_failure("federation.validate", &directory, error))?;
        let path = context
            .authorize_write(&directory.join(format!("{}.json", &receipt_sha256[7..31])))
            .map_err(|error| path_failure("federation.validate", error))?;
        let path = write_immutable_json(context, &path, &receipt)?;
        evidence_refs.push(path.to_string_lossy().into_owned());
    }
    let mut response = OperationResponse::completed(
        request,
        json!({
            "node_set_lock": node_set,
            "node_set_sha256": node_set_sha256,
            "accepted_results": accepted,
            "receipt": receipt,
            "receipt_sha256": receipt_sha256,
        }),
    );
    response.evidence_refs = evidence_refs;
    Ok(response)
}

fn path_failure(stage: &'static str, error: crate::ContextError) -> NodeFailure {
    NodeFailure {
        code: ErrorCode::PathEscape,
        stage,
        message: error.to_string(),
        recovery_hint: "use only canonical paths authorized by CallContext",
    }
}

fn parse_payload<T>(request: &OperationRequest, stage: &'static str) -> Result<T, NodeFailure>
where
    T: for<'de> Deserialize<'de>,
{
    serde_json::from_value(request.payload.clone())
        .map_err(|error| invalid(stage, format!("invalid payload: {error}")))
}

fn map_federation(failure: crate::federation::FederationFailure) -> NodeFailure {
    NodeFailure {
        code: failure.code,
        stage: failure.stage,
        message: failure.message,
        recovery_hint: failure.recovery_hint,
    }
}

fn invalid(stage: &'static str, message: impl Into<String>) -> NodeFailure {
    NodeFailure {
        code: ErrorCode::InvalidRequest,
        stage,
        message: message.into(),
        recovery_hint: "repair the exact local node/federation contract and retry",
    }
}

fn io_failure(stage: &'static str, path: &Path, error: impl std::fmt::Display) -> NodeFailure {
    NodeFailure {
        code: ErrorCode::Io,
        stage,
        message: format!("{}: {error}", path.display()),
        recovery_hint: "verify the explicit workspace receipt path and permissions",
    }
}

fn write_immutable_json(
    context: &CallContext,
    path: &Path,
    value: &serde_json::Value,
) -> Result<PathBuf, NodeFailure> {
    publish_immutable_json(
        context,
        path,
        value,
        "federation.receipt.after_temp_sync_before_rename",
    )
    .map_err(durable_failure)
}

fn durable_failure(error: DurableWriteError) -> NodeFailure {
    let code = match error.kind {
        DurableErrorKind::Invalid => ErrorCode::InvalidRequest,
        DurableErrorKind::Unauthorized => ErrorCode::PathEscape,
        DurableErrorKind::Unsafe => ErrorCode::SymlinkRejected,
        DurableErrorKind::Conflict => ErrorCode::NonDeterministicResult,
        DurableErrorKind::Io => ErrorCode::Io,
    };
    NodeFailure {
        code,
        stage: "federation.validate",
        message: error.to_string(),
        recovery_hint: "recover or quarantine the durable receipt and retry exact work",
    }
}

struct ReceiptGuard {
    file: File,
}

impl ReceiptGuard {
    fn acquire(path: &Path) -> Result<Self, NodeFailure> {
        let directory = path
            .parent()
            .ok_or_else(|| invalid("federation.single-writer", "lock has no parent"))?;
        fs::create_dir_all(directory)
            .map_err(|error| io_failure("federation.single-writer", directory, error))?;
        if path.exists() {
            let metadata = fs::symlink_metadata(path)
                .map_err(|error| io_failure("federation.single-writer", path, error))?;
            if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
                return Err(NodeFailure {
                    code: ErrorCode::SymlinkRejected,
                    stage: "federation.single-writer",
                    message: format!("writer lock is not a regular file: {}", path.display()),
                    recovery_hint: "replace the lock path with a private regular file",
                });
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if metadata.nlink() > 1 {
                    return Err(NodeFailure {
                        code: ErrorCode::SymlinkRejected,
                        stage: "federation.single-writer",
                        message: format!("writer lock is hardlinked: {}", path.display()),
                        recovery_hint: "replace the lock path with a private regular file",
                    });
                }
            }
        }
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .map_err(|error| io_failure("federation.single-writer", path, error))?;
        let path_metadata = fs::symlink_metadata(path)
            .map_err(|error| io_failure("federation.single-writer", path, error))?;
        let file_metadata = file
            .metadata()
            .map_err(|error| io_failure("federation.single-writer", path, error))?;
        if path_metadata.file_type().is_symlink() || !file_metadata.is_file() {
            return Err(NodeFailure {
                code: ErrorCode::SymlinkRejected,
                stage: "federation.single-writer",
                message: format!("writer lock changed during open: {}", path.display()),
                recovery_hint: "replace the lock path with a private regular file",
            });
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if file_metadata.nlink() > 1
                || path_metadata.dev() != file_metadata.dev()
                || path_metadata.ino() != file_metadata.ino()
            {
                return Err(NodeFailure {
                    code: ErrorCode::SymlinkRejected,
                    stage: "federation.single-writer",
                    message: format!("writer lock identity changed: {}", path.display()),
                    recovery_hint: "replace the lock path with a private regular file",
                });
            }
        }
        match file.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => {
                return Err(NodeFailure {
                    code: ErrorCode::InvalidState,
                    stage: "federation.single-writer",
                    message: format!("writer lock is held at {}", path.display()),
                    recovery_hint: "retry after the active local coordinator exits",
                });
            }
            Err(TryLockError::Error(error)) => {
                return Err(io_failure("federation.single-writer", path, error));
            }
        }
        file.set_len(0)
            .and_then(|()| writeln!(file, "pid={}", std::process::id()))
            .and_then(|()| file.sync_data())
            .map_err(|error| io_failure("federation.single-writer", path, error))?;
        Ok(Self { file })
    }
}

impl Drop for ReceiptGuard {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}
