//! U04 r7 dynamic authorization successor: an otherwise equivalent
//! WorkspaceWrite Context must explicitly authorize the capability's output
//! parent. Merely authorizing the enclosing workspace root is insufficient.

use gtkg_core::v03::evidence_drawer::{
    build_evidence_drawer_from_artifacts_v1, create_evidence_drawer_output_root_v1,
    write_evidence_drawer_with_capability_v1,
};
use gtkg_core::{CallContext, EffectPolicy, TransportKind};

#[path = "v03_u04_evidence_drawer_security_r3.rs"]
mod r3;

#[cfg(unix)]
#[test]
fn u04_r7_rejects_same_workspace_context_when_capability_parent_is_not_explicitly_authorized() {
    let fixture = r3::Fixture::new();
    let minting_context = fixture.write_context();
    let projection =
        build_evidence_drawer_from_artifacts_v1(&minting_context, &fixture.input()).unwrap();
    let capability =
        create_evidence_drawer_output_root_v1(&minting_context, &fixture.u04_parent).unwrap();

    let parent_omitted_context = CallContext::restricted(
        TransportKind::Test,
        vec![fixture.workspace.path().to_path_buf()],
        EffectPolicy::WorkspaceWrite,
    )
    .unwrap();
    assert_eq!(
        write_evidence_drawer_with_capability_v1(
            &parent_omitted_context,
            &capability,
            &projection,
        )
        .unwrap_err()
        .code(),
        "E_U04_CAPABILITY_CONTEXT_REJECTED"
    );
    assert!(
        std::fs::read_dir(capability.path())
            .unwrap()
            .next()
            .is_none()
    );
}
