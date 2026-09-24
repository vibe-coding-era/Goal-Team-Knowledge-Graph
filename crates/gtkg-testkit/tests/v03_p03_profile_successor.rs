//! P03 evolving availability denominator without claiming P04/P06 closure.

use gtkg_protocol::v2::OperationAvailabilityV2;
use gtkg_protocol::v03::profiles::{
    discoverable_operation_profile_v03, operation_profile_projection_v03,
};

#[test]
fn p03_leaves_only_build_finalize_in_core_and_authoring() {
    for profile in ["core", "authoring"] {
        let projection = operation_profile_projection_v03(Some(profile), None).unwrap();
        assert_eq!(
            projection.bindings.len(),
            if profile == "core" { 10 } else { 8 }
        );
        assert_eq!(
            projection
                .bindings
                .iter()
                .filter(|binding| binding.availability == OperationAvailabilityV2::NotImplemented)
                .count(),
            1
        );
        assert_eq!(
            discoverable_operation_profile_v03(Some(profile), None)
                .unwrap_err()
                .unavailable_operation_ids()
                .len(),
            1
        );
    }
    let all = operation_profile_projection_v03(Some("all"), None).unwrap();
    assert_eq!(
        all.bindings
            .iter()
            .filter(|binding| binding.availability == OperationAvailabilityV2::Implemented)
            .count(),
        37
    );
    assert_eq!(
        discoverable_operation_profile_v03(Some("all"), None)
            .unwrap_err()
            .unavailable_operation_ids()
            .len(),
        9
    );
}
