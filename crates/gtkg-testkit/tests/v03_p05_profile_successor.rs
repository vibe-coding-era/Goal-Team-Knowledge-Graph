//! P05 profile successor: fully implemented P05 partitions are discoverable,
//! while the 46-operation `all` profile remains fail-closed for P06.

use gtkg_protocol::v2::{CallabilityV2, OperationAvailabilityV2};
use gtkg_protocol::v03::profiles::{
    discoverable_operation_profile_v03, operation_profile_projection_v03,
};

#[test]
fn p05_templates_and_a2ui_are_live_but_all_remains_p06_blocked() {
    let templates = discoverable_operation_profile_v03(Some("templates"), None).unwrap();
    assert_eq!(templates.bindings.len(), 9);
    assert!(templates.bindings.iter().all(|binding| {
        binding.availability == OperationAvailabilityV2::Implemented
            && matches!(
                binding.callability,
                CallabilityV2::Callable | CallabilityV2::DeniedByPolicy
            )
    }));
    assert_eq!(
        templates
            .bindings
            .iter()
            .filter(|binding| binding.callability == CallabilityV2::DeniedByPolicy)
            .count(),
        2
    );

    let a2ui = discoverable_operation_profile_v03(Some("a2ui"), None).unwrap();
    assert_eq!(a2ui.bindings.len(), 4);
    assert!(a2ui.bindings.iter().all(|binding| {
        binding.availability == OperationAvailabilityV2::Implemented
            && binding.callability == CallabilityV2::Callable
    }));

    let lifecycle = discoverable_operation_profile_v03(Some("lifecycle"), None).unwrap_err();
    assert_eq!(lifecycle.code(), "E_DEAD_TOOL_EXPOSED");
    assert_eq!(lifecycle.selected_operation_count(), 13);
    assert_eq!(lifecycle.unavailable_operation_ids().len(), 8);

    let all = operation_profile_projection_v03(Some("all"), None).unwrap();
    assert_eq!(all.bindings.len(), 46);
    assert_eq!(
        all.bindings
            .iter()
            .filter(|binding| binding.availability == OperationAvailabilityV2::Implemented)
            .count(),
        28
    );
    let blocked = discoverable_operation_profile_v03(Some("all"), None).unwrap_err();
    assert_eq!(blocked.code(), "E_DEAD_TOOL_EXPOSED");
    assert_eq!(blocked.selected_operation_count(), 46);
    assert_eq!(blocked.unavailable_operation_ids().len(), 18);
}
