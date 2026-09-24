//! U04 r5 immutable Red: writers require the exact workspace-write Context
//! that minted their capability; a read-only or different-root context cannot
//! emit a drawer even when it holds the capability object.

use std::fs;
use std::path::PathBuf;

use gtkg_core::v03::evidence_drawer::{
    build_evidence_drawer_from_artifacts_v1, create_evidence_drawer_output_root_v1,
    write_evidence_drawer_v1, write_evidence_drawer_with_capability_v1,
};
use gtkg_core::{CallContext, EffectPolicy, TransportKind};

#[path = "v03_u04_evidence_drawer_security_r3.rs"]
mod r3;

fn context(roots: Vec<PathBuf>, policy: EffectPolicy) -> CallContext {
    CallContext::restricted(TransportKind::Test, roots, policy).unwrap()
}

#[cfg(unix)]
#[test]
fn u04_r5_rejects_read_only_and_cross_context_capability_writes_before_file_creation() {
    let fixture = r3::Fixture::new();
    let writer = fixture.write_context();
    let projection = build_evidence_drawer_from_artifacts_v1(&writer, &fixture.input()).unwrap();
    let capability = create_evidence_drawer_output_root_v1(&writer, &fixture.u04_parent).unwrap();

    let read_only = context(
        vec![
            fixture.workspace.path().to_path_buf(),
            fixture.u03_parent.clone(),
            fixture.u04_parent.clone(),
        ],
        EffectPolicy::ReadOnly,
    );
    assert_eq!(
        write_evidence_drawer_with_capability_v1(&read_only, &capability, &projection)
            .unwrap_err()
            .code(),
        "E_U04_WRITE_DENIED"
    );
    assert!(fs::read_dir(capability.path()).unwrap().next().is_none());
    let raw_output = fixture.u04_parent.join("raw-read-only-output");
    assert_eq!(
        write_evidence_drawer_v1(&read_only, &raw_output, &projection)
            .unwrap_err()
            .code(),
        "E_U04_WRITE_DENIED"
    );
    assert!(!raw_output.exists());

    let foreign_root = fixture.workspace.path().join("foreign-context-root");
    fs::create_dir(&foreign_root).unwrap();
    let foreign_writer = context(
        vec![foreign_root, fixture.u04_parent.clone()],
        EffectPolicy::WorkspaceWrite,
    );
    assert_eq!(
        write_evidence_drawer_with_capability_v1(&foreign_writer, &capability, &projection)
            .unwrap_err()
            .code(),
        "E_U04_CAPABILITY_CONTEXT_REJECTED"
    );
    assert!(fs::read_dir(capability.path()).unwrap().next().is_none());
}
