//! P04 closes availability while P06 transport/conformance remains separate.

use gtkg_protocol::v2::{CallabilityV2, OperationAvailabilityV2};
use gtkg_protocol::v03::profiles::discoverable_operation_profile_v03;

#[test]
fn p04_all_profiles_are_implemented_but_external_effects_remain_denied() {
    for (profile, count) in [
        ("core", 10),
        ("authoring", 8),
        ("lifecycle", 13),
        ("templates", 9),
        ("a2ui", 4),
        ("graph", 6),
        ("all", 46),
    ] {
        let projection = discoverable_operation_profile_v03(Some(profile), None).unwrap();
        assert_eq!(projection.bindings.len(), count);
        assert!(projection.bindings.iter().all(|binding| {
            binding.availability == OperationAvailabilityV2::Implemented
                && matches!(
                    binding.callability,
                    CallabilityV2::Callable | CallabilityV2::DeniedByPolicy
                )
        }));
    }
    let all = discoverable_operation_profile_v03(Some("all"), None).unwrap();
    assert_eq!(
        all.bindings
            .iter()
            .filter(|binding| binding.callability == CallabilityV2::DeniedByPolicy)
            .count(),
        4
    );
}
