//! P02 availability successor for the evolving v2 handler denominator.

use gtkg_protocol::v2::OperationAvailabilityV2;
use gtkg_protocol::v03::profiles::{
    discoverable_operation_profile_v03, operation_profile_projection_v03,
};

#[test]
fn p02_updates_core_and_all_denominators_without_claiming_p03_p04_or_p06() {
    let core = operation_profile_projection_v03(Some("core"), None).unwrap();
    assert_eq!(core.bindings.len(), 10);
    assert_eq!(
        core.bindings
            .iter()
            .filter(|binding| binding.availability == OperationAvailabilityV2::Implemented)
            .count(),
        8
    );
    let core_blocked = discoverable_operation_profile_v03(Some("core"), None).unwrap_err();
    assert_eq!(core_blocked.unavailable_operation_ids().len(), 2);

    let authoring = discoverable_operation_profile_v03(Some("authoring"), None).unwrap_err();
    assert_eq!(authoring.unavailable_operation_ids().len(), 7);

    let all = operation_profile_projection_v03(Some("all"), None).unwrap();
    assert_eq!(all.bindings.len(), 46);
    assert_eq!(
        all.bindings
            .iter()
            .filter(|binding| binding.availability == OperationAvailabilityV2::Implemented)
            .count(),
        31
    );
    let all_blocked = discoverable_operation_profile_v03(Some("all"), None).unwrap_err();
    assert_eq!(all_blocked.unavailable_operation_ids().len(), 15);
}
