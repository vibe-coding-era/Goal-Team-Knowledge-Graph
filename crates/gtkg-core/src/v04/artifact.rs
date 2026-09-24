//! Immutable artifact I/O shared by the explicit successor pipeline.
use crate::{CallContext, durable::publish_immutable_json, exact_read::read_bound_regular_file};
use gtkg_protocol::FileReceiptRef;
use serde::{Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
pub use super::QkError;
/// Artefact I/O result. The error keeps the dedicated code of the layer that
/// produced it; a free-form message stays `E_INVALID_REQUEST`.
pub type QkResult<T> = Result<T, QkError>;
pub fn digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}
pub fn workspace(context: &CallContext, root: &Path) -> QkResult<PathBuf> {
    let p = context
        .authorize_read(root)
        .map_err(QkError::from_context)?;
    let first = context.workspace_root().ok_or_else(|| {
        QkError::new(
            gtkg_protocol::v2::V2ErrorCode::ScopeDenied,
            "authorized-root",
            "workspace absent",
        )
    })?;
    if !p.starts_with(first) {
        return Err("workspace must be within the primary authorized root".into());
    }
    Ok(p)
}
pub fn read<T: DeserializeOwned>(
    context: &CallContext,
    root: &Path,
    reference: &FileReceiptRef,
) -> QkResult<(T, PathBuf)> {
    reference.validate().map_err(|e| e.to_string())?;
    let root = workspace(context, root)?;
    let path = root.join(&reference.path);
    let r = read_bound_regular_file(context, &path)
        .map_err(|e| QkError::from_exact_read(e.code, e.message))?;
    if r.sha256 != reference.sha256 {
        return Err("artifact digest mismatch".into());
    }
    Ok((
        serde_json::from_slice(&r.bytes).map_err(|e| e.to_string())?,
        path,
    ))
}
pub fn reference(context: &CallContext, root: &Path, path: &Path) -> QkResult<FileReceiptRef> {
    let r = read_bound_regular_file(context, path)
        .map_err(|e| QkError::from_exact_read(e.code, e.message))?;
    let relative = path
        .strip_prefix(root)
        .map_err(|_| "artifact outside workspace")?;
    let result = FileReceiptRef {
        path: relative
            .to_str()
            .ok_or("non-UTF8 artifact path")?
            .replace('\\', "/"),
        sha256: r.sha256,
    };
    result.validate().map_err(|e| e.to_string())?;
    Ok(result)
}
pub fn publish<T: Serialize>(
    context: &CallContext,
    root: &Path,
    kind: &str,
    value: &T,
) -> QkResult<FileReceiptRef> {
    if context.effect_policy != crate::EffectPolicy::WorkspaceWrite {
        return Err("QK artifact write requires WorkspaceWrite".into());
    }
    if kind.is_empty() || !kind.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
        return Err("invalid artifact kind".into());
    }
    let root = workspace(context, root)?;
    let bytes = serde_json::to_vec_pretty(value).map_err(|e| e.to_string())?;
    let name = digest(&bytes);
    let path = root
        .join(".gtkg")
        .join("qk")
        .join(kind)
        .join(format!("{}.json", &name[7..]));
    publish_immutable_json(context, &path, value, "qk-artifact").map_err(|e| e.to_string())?;
    reference(context, &root, &path)
}

pub fn publish_text(
    context: &CallContext,
    root: &Path,
    kind: &str,
    text: &str,
) -> QkResult<FileReceiptRef> {
    if context.effect_policy != crate::EffectPolicy::WorkspaceWrite {
        return Err("QK artifact write requires WorkspaceWrite".into());
    }
    if kind.is_empty() || !kind.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
        return Err("invalid artifact kind".into());
    }
    let root = workspace(context, root)?;
    let d = digest(text.as_bytes());
    let path = format!(".gtkg/qk/{kind}/{}.md", &d[7..]);
    super::source::write_workspace_object(&root, &path, text.as_bytes())
        .map_err(|e| e.to_string())?;
    reference(context, &root, &root.join(path))
}
