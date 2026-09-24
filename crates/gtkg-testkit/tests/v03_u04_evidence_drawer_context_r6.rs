//! U04 r6 context contract: a capability is bound to its canonical workspace
//! root and exact authorized output parent, not to one in-memory CallContext
//! instance. An equivalent WorkspaceWrite Context is intentionally accepted;
//! a different root remains rejected.

use std::fs;
use std::path::PathBuf;

use gtkg_core::v03::evidence_drawer::{
    build_evidence_drawer_from_artifacts_v1, create_evidence_drawer_output_root_v1,
    read_evidence_drawer_v1, write_evidence_drawer_with_capability_v1,
};
use gtkg_core::{CallContext, EffectPolicy, TransportKind};

#[path = "v03_u04_evidence_drawer_security_r3.rs"]
mod r3;

fn context(roots: Vec<PathBuf>, policy: EffectPolicy) -> CallContext {
    CallContext::restricted(TransportKind::Test, roots, policy).unwrap()
}

#[cfg(unix)]
#[test]
fn u04_r6_accepts_equivalent_authorized_context_and_rejects_different_workspace_root() {
    let fixture = r3::Fixture::new();
    let minting_context = fixture.write_context();
    let projection =
        build_evidence_drawer_from_artifacts_v1(&minting_context, &fixture.input()).unwrap();
    let capability =
        create_evidence_drawer_output_root_v1(&minting_context, &fixture.u04_parent).unwrap();

    let equivalent_context = context(
        vec![
            fixture.workspace.path().to_path_buf(),
            fixture.u03_parent.clone(),
            fixture.u04_parent.clone(),
        ],
        EffectPolicy::WorkspaceWrite,
    );
    let receipt =
        write_evidence_drawer_with_capability_v1(&equivalent_context, &capability, &projection)
            .unwrap();
    assert_eq!(
        read_evidence_drawer_v1(&equivalent_context, &receipt).unwrap(),
        projection
    );

    let rejected_capability =
        create_evidence_drawer_output_root_v1(&minting_context, &fixture.u04_parent).unwrap();
    let foreign_root = fixture.workspace.path().join("r6-foreign-root");
    fs::create_dir(&foreign_root).unwrap();
    let foreign_context = context(
        vec![foreign_root, fixture.u04_parent.clone()],
        EffectPolicy::WorkspaceWrite,
    );
    assert_eq!(
        write_evidence_drawer_with_capability_v1(
            &foreign_context,
            &rejected_capability,
            &projection,
        )
        .unwrap_err()
        .code(),
        "E_U04_CAPABILITY_CONTEXT_REJECTED"
    );
}
