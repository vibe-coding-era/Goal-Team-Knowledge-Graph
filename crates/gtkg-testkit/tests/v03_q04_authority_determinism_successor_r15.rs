include!("v03_q04_file_graph_operations.rs");

#[test]
fn q04_r15_same_input_rebuild_reuses_deterministic_manifest_and_private_authority() {
    let fixture = Fixture::new();
    let manifest: FileGraphEvidenceManifestV1 = serde_json::from_slice(
        &fs::read(
            fixture
                .evidence_root
                .join(&fixture.evidence_manifest_ref.path),
        )
        .unwrap(),
    )
    .unwrap();
    let entities = manifest
        .records
        .iter()
        .map(|entry| {
            let value: Value = serde_json::from_slice(
                &fs::read(fixture.evidence_root.join(&entry.relative_path)).unwrap(),
            )
            .unwrap();
            serde_json::from_value::<GraphQueryEntityV1>(value["entity"].clone()).unwrap()
        })
        .collect::<Vec<_>>();
    let query_manifest: gtkg_protocol::v03::query::FileQueryIndexManifestV1 =
        serde_json::from_slice(
            &fs::read(fixture.query_root.join(&fixture.query_manifest_ref.path)).unwrap(),
        )
        .unwrap();
    let replay = write_graph_query_evidence_index_v1(
        &context(fixture.workspace.path(), EffectPolicy::WorkspaceWrite),
        &fixture.evidence_root,
        &fixture.expected,
        &fixture.query_manifest_ref,
        &query_manifest.index_manifest_sha256,
        &entities,
    )
    .unwrap();
    assert_eq!(replay, fixture.evidence_manifest_ref);
    let controls = fs::read_dir(fixture.evidence_root.join("control"))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(controls.len(), 1);
}
