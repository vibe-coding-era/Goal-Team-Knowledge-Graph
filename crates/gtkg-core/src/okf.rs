use std::collections::BTreeMap;

use serde::{Deserialize, Deserializer, Serialize};
use serde_yaml::Value;
use thiserror::Error;

pub const OKF_VERSION: &str = "0.2";

/// OKF v0.2 concept frontmatter (SPEC §4.1).
///
/// `type` is the only always-required key (SPEC §4.1/§11); every other field
/// is optional. Producer extension keys that are not part of the official
/// schema are captured in `extra` for inspection and round-tripping, never
/// rejected (SPEC §4.1 Extensions, §11).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct OkfFrontmatter {
    #[serde(rename = "type", default)]
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_generated"
    )]
    pub generated: Option<GeneratedBy>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_verified"
    )]
    pub verified: Option<Vec<VerificationEvent>>,
    #[serde(default)]
    pub status: OkfStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stale_after: Option<Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sources: Vec<SourceEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub okf_version: Option<String>,
    /// GTKG producer extension namespace. Purely producer-defined; consumers
    /// tolerate its absence (SPEC §11).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gtkg: Option<BTreeMap<String, Value>>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl OkfFrontmatter {
    /// SPEC §12: a bundle-root `index.md` may carry an `okf_version` key as
    /// its only frontmatter; such a block needs no `type`.
    fn is_version_only_index(&self) -> bool {
        self.okf_version.is_some()
            && self.kind.trim().is_empty()
            && self.title.is_none()
            && self.description.is_none()
            && self.resource.is_none()
            && self.tags.is_empty()
            && self.generated.is_none()
            && self.verified.is_none()
            && self.status == OkfStatus::Stable
            && self.stale_after.is_none()
            && self.sources.is_empty()
            && self.gtkg.is_none()
            && self.extra.is_empty()
    }
}

/// SPEC §5.2: `generated` records how the content was produced.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GeneratedBy {
    pub by: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub at: String,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// SPEC §5.2: one entry of the `verified` event list; additional keys are
/// tolerated (SPEC §11).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VerificationEvent {
    pub by: String,
    pub at: String,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// SPEC §5.1: a `sources` entry. `resource` is required by the SPEC and is
/// always written by GTKG producers; the parse layer tolerates its absence
/// (and the legacy `uri` alias) because consumers must not reject documents
/// over producer deviations (SPEC §11).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SourceEntry {
    #[serde(default, alias = "uri", skip_serializing_if = "String::is_empty")]
    pub resource: String,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// SPEC §5.4 lifecycle. Absent means `stable`. Legacy or unknown producer
/// values deserialize to `Unknown` instead of failing (SPEC §11 soft
/// guidance); GTKG producers only ever write the three official values.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OkfStatus {
    Draft,
    #[default]
    Stable,
    Deprecated,
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, PartialEq)]
pub struct OkfDocument {
    pub frontmatter: OkfFrontmatter,
    pub body: String,
}

#[derive(Debug, Error)]
pub enum OkfError {
    #[error("OKF concept document must begin with a YAML frontmatter delimiter")]
    MissingOpeningDelimiter,
    #[error("OKF document is missing the closing frontmatter delimiter")]
    MissingClosingDelimiter,
    #[error("invalid OKF YAML: {0}")]
    InvalidYaml(#[from] serde_yaml::Error),
    #[error("unsupported OKF version {0}; expected {OKF_VERSION}")]
    UnsupportedVersion(String),
    #[error("required OKF field is empty: {0}")]
    EmptyField(&'static str),
}

/// Parses an OKF document in consumer mode.
///
/// Consumer mode accepts the two reserved `index.md` shapes from SPEC §8/§12:
/// frontmatterless markdown and an exact `{okf_version}` root block. Callers
/// that know they are reading a non-reserved concept must use
/// [`parse_okf_concept`] so a frontmatterless file cannot masquerade as an
/// index.
pub fn parse_okf(input: &str) -> Result<OkfDocument, OkfError> {
    parse_okf_internal(input, true)
}

/// Parses a non-reserved OKF concept document (SPEC §4/§11). A concept always
/// requires frontmatter and a non-empty `type`; root/non-root index exceptions
/// are deliberately unavailable on this path.
pub fn parse_okf_concept(input: &str) -> Result<OkfDocument, OkfError> {
    parse_okf_internal(input, false)
}

fn parse_okf_internal(input: &str, allow_index_shapes: bool) -> Result<OkfDocument, OkfError> {
    let normalized = input.replace("\r\n", "\n");
    let Some(after_open) = normalized.strip_prefix("---\n") else {
        // SPEC §8: non-root `index.md` files carry no frontmatter; the body is
        // markdown links. Consumers must not reject them (SPEC §11), so a
        // document without a frontmatter block parses as an index-style
        // document with a default (type-less) frontmatter.
        if allow_index_shapes {
            return Ok(OkfDocument {
                frontmatter: OkfFrontmatter::default(),
                body: normalized,
            });
        }
        return Err(OkfError::MissingOpeningDelimiter);
    };
    let (yaml, body) = if let Some(closing_offset) = after_open.find("\n---\n") {
        (
            &after_open[..closing_offset],
            &after_open[closing_offset + "\n---\n".len()..],
        )
    } else if let Some(yaml) = after_open.strip_suffix("\n---") {
        // SPEC §4.2 permits an empty body. A closing delimiter at EOF is
        // therefore complete even when no trailing newline follows it.
        (yaml, "")
    } else {
        return Err(OkfError::MissingClosingDelimiter);
    };
    let raw: Value = serde_yaml::from_str(yaml)?;
    let version_only_index = raw.as_mapping().is_some_and(|mapping| {
        mapping.len() == 1 && mapping.contains_key(Value::String("okf_version".to_owned()))
    });
    let frontmatter: OkfFrontmatter = serde_yaml::from_value(raw)?;
    if allow_index_shapes && version_only_index {
        if !frontmatter.is_version_only_index() {
            return Err(OkfError::EmptyField("type"));
        }
    } else {
        validate_frontmatter(&frontmatter)?;
    }
    Ok(OkfDocument {
        frontmatter,
        body: body.to_owned(),
    })
}

pub fn validate_frontmatter(frontmatter: &OkfFrontmatter) -> Result<(), OkfError> {
    // SPEC §11(2): every non-reserved concept frontmatter contains a non-empty
    // `type`. Index exceptions are handled from the raw YAML key set inside
    // `parse_okf_internal`; a deserialized default value is not sufficient to
    // prove that the input was an index.
    if frontmatter.kind.trim().is_empty() {
        return Err(OkfError::EmptyField("type"));
    }
    Ok(())
}

/// GTKG's current application profile can require the exact producer version
/// after a best-effort OKF consumer parse. Keeping this check separate avoids
/// violating SPEC §12 for generic consumers that encounter a future version.
pub fn validate_current_version(frontmatter: &OkfFrontmatter) -> Result<(), OkfError> {
    if let Some(version) = &frontmatter.okf_version
        && version != OKF_VERSION
    {
        return Err(OkfError::UnsupportedVersion(version.clone()));
    }
    Ok(())
}

/// SPEC §5.2: `generated` is a `{ by, at }` mapping. Legacy GTKG boolean
/// markers (`generated: true/false`) predate the official schema and are
/// tolerated as "no provenance recorded" (SPEC §11).
fn deserialize_generated<'de, D>(deserializer: D) -> Result<Option<GeneratedBy>, D::Error>
where
    D: Deserializer<'de>,
{
    match Option::<Value>::deserialize(deserializer)? {
        None | Some(Value::Null) | Some(Value::Bool(_)) => Ok(None),
        Some(value @ Value::Mapping(_)) => GeneratedBy::deserialize(value)
            .map(Some)
            .map_err(serde::de::Error::custom),
        Some(other) => Err(serde::de::Error::custom(format!(
            "generated must be a mapping with by/at, got {other:?}"
        ))),
    }
}

/// SPEC §5.2 + §11: `verified` is a list of `{ by, at }` events; a bare
/// mapping is normalized to a one-element list. Legacy GTKG boolean markers
/// are tolerated as "no verification recorded".
fn deserialize_verified<'de, D>(deserializer: D) -> Result<Option<Vec<VerificationEvent>>, D::Error>
where
    D: Deserializer<'de>,
{
    match Option::<Value>::deserialize(deserializer)? {
        None | Some(Value::Null) | Some(Value::Bool(_)) => Ok(None),
        Some(value @ Value::Mapping(_)) => VerificationEvent::deserialize(value)
            .map(|event| Some(vec![event]))
            .map_err(serde::de::Error::custom),
        Some(value @ Value::Sequence(_)) => Vec::<VerificationEvent>::deserialize(value)
            .map(Some)
            .map_err(serde::de::Error::custom),
        Some(other) => Err(serde::de::Error::custom(format!(
            "verified must be a list of by/at events, got {other:?}"
        ))),
    }
}
