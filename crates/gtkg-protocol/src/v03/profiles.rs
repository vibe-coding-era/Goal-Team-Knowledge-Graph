//! P00 operation-binding projection and fail-closed discovery selection.
//!
//! Profiles are an ordered discovery projection over the frozen v2 registry.
//! They never change an operation's schema, effect, availability, callability,
//! or authorization. A profile containing an unimplemented operation can be
//! inspected as a contract, but it cannot be exposed by live discovery.

use std::collections::{BTreeMap, BTreeSet};

use crate::v2::{OperationAvailabilityV2, V2OperationId};

use super::{
    DISCOVERY_PROFILE_DIGESTS_V1, DiscoveryProfileErrorV03, DiscoveryProfileIdV1,
    DiscoveryProfileV1, OperationBindingV2, discovery_profiles_v03, operation_bindings_v03,
};

pub const DEFAULT_DISCOVERY_PROFILE_V1: &str = "core";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationProfileProjectionV03 {
    pub profile: DiscoveryProfileV1,
    pub bindings: Vec<OperationBindingV2>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OperationProfileErrorV03 {
    UnknownProfile {
        profile_id: String,
    },
    StaleProfile {
        profile_id: String,
        expected_digest: String,
        actual_digest: String,
    },
    InvalidProfile {
        profile_id: String,
        reason: DiscoveryProfileErrorV03,
    },
    ContractDigestDrift {
        profile_id: String,
        expected_digest: String,
        actual_digest: String,
    },
    BindingDrift {
        profile_id: String,
    },
    DeadToolExposed {
        profile_id: String,
        selected_operation_count: usize,
        unavailable_operation_ids: Vec<V2OperationId>,
    },
}

impl OperationProfileErrorV03 {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::UnknownProfile { .. } => "E_PROFILE_UNKNOWN",
            Self::StaleProfile { .. } | Self::ContractDigestDrift { .. } => "E_PROFILE_STALE",
            Self::InvalidProfile { .. } | Self::BindingDrift { .. } => "E_PROFILE_INVALID",
            Self::DeadToolExposed { .. } => "E_DEAD_TOOL_EXPOSED",
        }
    }

    pub fn profile_id(&self) -> &str {
        match self {
            Self::UnknownProfile { profile_id }
            | Self::StaleProfile { profile_id, .. }
            | Self::InvalidProfile { profile_id, .. }
            | Self::ContractDigestDrift { profile_id, .. }
            | Self::BindingDrift { profile_id }
            | Self::DeadToolExposed { profile_id, .. } => profile_id,
        }
    }

    pub const fn selected_operation_count(&self) -> usize {
        match self {
            Self::DeadToolExposed {
                selected_operation_count,
                ..
            } => *selected_operation_count,
            _ => 0,
        }
    }

    pub fn unavailable_operation_ids(&self) -> &[V2OperationId] {
        match self {
            Self::DeadToolExposed {
                unavailable_operation_ids,
                ..
            } => unavailable_operation_ids,
            _ => &[],
        }
    }

    pub fn expected_digest(&self) -> Option<&str> {
        match self {
            Self::StaleProfile {
                expected_digest, ..
            }
            | Self::ContractDigestDrift {
                expected_digest, ..
            } => Some(expected_digest),
            _ => None,
        }
    }

    pub fn actual_digest(&self) -> Option<&str> {
        match self {
            Self::StaleProfile { actual_digest, .. }
            | Self::ContractDigestDrift { actual_digest, .. } => Some(actual_digest),
            _ => None,
        }
    }
}

fn selected_profile_id(profile_id: Option<&str>) -> &str {
    profile_id.unwrap_or(DEFAULT_DISCOVERY_PROFILE_V1)
}

fn contract_digest(profile_id: DiscoveryProfileIdV1) -> Option<&'static str> {
    DISCOVERY_PROFILE_DIGESTS_V1
        .iter()
        .find(|(candidate, _)| *candidate == profile_id)
        .map(|(_, digest)| *digest)
}

/// Project the exact ordered operation bindings for a named profile.
///
/// `expected_digest` represents a caller-pinned profile identity. A mismatch
/// never auto-upgrades to the current profile.
pub fn operation_profile_projection_v03(
    profile_id: Option<&str>,
    expected_digest: Option<&str>,
) -> Result<OperationProfileProjectionV03, OperationProfileErrorV03> {
    let selected_id = selected_profile_id(profile_id);
    let profile = discovery_profiles_v03()
        .into_iter()
        .find(|profile| profile.profile_id.as_str() == selected_id)
        .ok_or_else(|| OperationProfileErrorV03::UnknownProfile {
            profile_id: selected_id.to_owned(),
        })?;

    profile
        .validate()
        .map_err(|reason| OperationProfileErrorV03::InvalidProfile {
            profile_id: selected_id.to_owned(),
            reason,
        })?;

    let Some(frozen_digest) = contract_digest(profile.profile_id) else {
        return Err(OperationProfileErrorV03::InvalidProfile {
            profile_id: selected_id.to_owned(),
            reason: DiscoveryProfileErrorV03::DigestMismatch,
        });
    };
    if profile.digest != frozen_digest {
        return Err(OperationProfileErrorV03::ContractDigestDrift {
            profile_id: selected_id.to_owned(),
            expected_digest: frozen_digest.to_owned(),
            actual_digest: profile.digest,
        });
    }
    if let Some(expected_digest) = expected_digest
        && expected_digest != profile.digest
    {
        return Err(OperationProfileErrorV03::StaleProfile {
            profile_id: selected_id.to_owned(),
            expected_digest: expected_digest.to_owned(),
            actual_digest: profile.digest,
        });
    }

    let binding_by_id = operation_bindings_v03()
        .into_iter()
        .map(|binding| (binding.operation_id, binding))
        .collect::<BTreeMap<_, _>>();
    let operation_ids = profile
        .operation_ids
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    if operation_ids.len() != profile.operation_ids.len() {
        return Err(OperationProfileErrorV03::BindingDrift {
            profile_id: selected_id.to_owned(),
        });
    }
    let bindings = profile
        .operation_ids
        .iter()
        .map(|operation_id| binding_by_id.get(operation_id).cloned())
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| OperationProfileErrorV03::BindingDrift {
            profile_id: selected_id.to_owned(),
        })?;

    Ok(OperationProfileProjectionV03 { profile, bindings })
}

/// Resolve a profile for live CLI/MCP discovery.
///
/// Registry presence is not implementation. The complete selected projection
/// is rejected when any binding is still unimplemented, so `tools/list` never
/// exposes a dead tool while later P tasks are incomplete.
pub fn discoverable_operation_profile_v03(
    profile_id: Option<&str>,
    expected_digest: Option<&str>,
) -> Result<OperationProfileProjectionV03, OperationProfileErrorV03> {
    let projection = operation_profile_projection_v03(profile_id, expected_digest)?;
    let unavailable_operation_ids = projection
        .bindings
        .iter()
        .filter(|binding| binding.availability != OperationAvailabilityV2::Implemented)
        .map(|binding| binding.operation_id)
        .collect::<Vec<_>>();
    if unavailable_operation_ids.is_empty() {
        return Ok(projection);
    }

    Err(OperationProfileErrorV03::DeadToolExposed {
        profile_id: projection.profile.profile_id.as_str().to_owned(),
        selected_operation_count: projection.bindings.len(),
        unavailable_operation_ids,
    })
}
