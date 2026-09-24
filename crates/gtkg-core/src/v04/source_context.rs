//! Shared source/context presentation: reviewed text never replaces original source.
use super::{
    index::ArtifactRef,
    knowledge::{AuthorMode, EpistemicStatus},
};
use gtkg_extract::v04::Span;
use gtkg_protocol::FileReceiptRef;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceCitationAnchor {
    pub path: String,
    pub file_sha256: String,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewedSummaryContext {
    pub context_id: String,
    pub context_ref: ArtifactRef,
    pub text: String,
    pub claim_id: String,
    pub claim_digest: String,
    pub author_mode: AuthorMode,
    pub epistemic: EpistemicStatus,
    pub version_condition: Option<String>,
    pub review_kind: String,
    pub accepted_ref: FileReceiptRef,
    pub review_ref: FileReceiptRef,
    pub job_ref: FileReceiptRef,
    pub verification_digest: String,
    pub reviewer_ids: Vec<String>,
    pub citations: Vec<SourceCitationAnchor>,
    pub selected_lineage: Vec<ArtifactRef>,
    pub evidence_ids: Vec<String>,
    pub citation_coverage_in_pack: String,
    pub execution_assurance: String,
}

impl ReviewedSummaryContext {
    /// The proposition and condition are each presented and charged exactly once.
    pub fn text_units(&self) -> usize {
        self.text.chars().count()
            + self
                .version_condition
                .as_deref()
                .map_or(0, |s| s.chars().count())
    }
}
