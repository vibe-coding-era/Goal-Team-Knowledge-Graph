//! T04 restricted local corpus-manifest boundary.
//!
//! The loader only accepts metadata explicitly marked `fixture` or
//! `synthetic`.  It never fetches a repository, probes a provider, runs a
//! benchmark, or treats a blocked local fixture as external evidence.

use std::fs;
use std::path::{Path, PathBuf};

use gtkg_protocol::v2::{CorpusManifestV2, CorpusManifestValidationErrorV2, CorpusOriginV2};
use thiserror::Error;

use crate::{CallContext, ContextError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CorpusFreezeErrorCodeV2 {
    UnauthorizedPath,
    Io,
    Decode,
    ExternalOriginDenied,
    InvalidManifest,
}

#[derive(Debug, Error)]
pub enum CorpusFreezeErrorV2 {
    #[error("corpus manifest path is not authorized: {0}")]
    UnauthorizedPath(#[source] ContextError),
    #[error("corpus manifest cannot be read at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("corpus manifest JSON is invalid: {0}")]
    Decode(#[source] serde_json::Error),
    #[error("local corpus loader rejects external_repository origin")]
    ExternalOriginDenied,
    #[error("corpus manifest contract is invalid: {0}")]
    InvalidManifest(#[source] CorpusManifestValidationErrorV2),
}

impl CorpusFreezeErrorV2 {
    pub const fn code(&self) -> CorpusFreezeErrorCodeV2 {
        match self {
            Self::UnauthorizedPath(_) => CorpusFreezeErrorCodeV2::UnauthorizedPath,
            Self::Io { .. } => CorpusFreezeErrorCodeV2::Io,
            Self::Decode(_) => CorpusFreezeErrorCodeV2::Decode,
            Self::ExternalOriginDenied => CorpusFreezeErrorCodeV2::ExternalOriginDenied,
            Self::InvalidManifest(_) => CorpusFreezeErrorCodeV2::InvalidManifest,
        }
    }
}

/// Read a bounded local contract fixture.  This is intentionally not an
/// external corpus ingestion API.  Its output only says the local metadata is
/// self-consistent; callers must use separate T15 evidence to establish any
/// external, provider, or performance claim.
pub fn load_local_corpus_manifest_v2(
    context: &CallContext,
    manifest_path: &Path,
) -> Result<LocalCorpusFreezeReceiptV2, CorpusFreezeErrorV2> {
    let path = context
        .authorize_read(manifest_path)
        .map_err(CorpusFreezeErrorV2::UnauthorizedPath)?;
    let raw = fs::read_to_string(&path).map_err(|source| CorpusFreezeErrorV2::Io {
        path: path.clone(),
        source,
    })?;
    let manifest: CorpusManifestV2 =
        serde_json::from_str(&raw).map_err(CorpusFreezeErrorV2::Decode)?;
    if matches!(manifest.source.origin, CorpusOriginV2::ExternalRepository) {
        return Err(CorpusFreezeErrorV2::ExternalOriginDenied);
    }
    manifest
        .validate()
        .map_err(CorpusFreezeErrorV2::InvalidManifest)?;
    Ok(LocalCorpusFreezeReceiptV2 { manifest, path })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalCorpusFreezeReceiptV2 {
    pub manifest: CorpusManifestV2,
    pub path: PathBuf,
}

impl LocalCorpusFreezeReceiptV2 {
    /// The restricted loader's accepted origins are deliberately unable to
    /// count toward an external evidence gate.
    pub const fn counts_toward_external_gate(&self) -> bool {
        false
    }
}
