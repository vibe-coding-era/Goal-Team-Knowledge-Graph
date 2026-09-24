include!("v03_q04_file_graph_operations.rs");

fn recovery_entities(fixture: &Fixture) -> Vec<GraphQueryEntityV1> {
    let manifest: FileGraphEvidenceManifestV1 = serde_json::from_slice(
        &fs::read(
            fixture
                .evidence_root
                .join(&fixture.evidence_manifest_ref.path),
        )
        .unwrap(),
    )
    .unwrap();
    manifest
        .records
        .iter()
        .map(|entry| {
            let value: Value = serde_json::from_slice(
                &fs::read(fixture.evidence_root.join(&entry.relative_path)).unwrap(),
            )
            .unwrap();
            serde_json::from_value::<GraphQueryEntityV1>(value["entity"].clone()).unwrap()
        })
        .collect()
}

#[test]
fn q04_authority_crash_child() {
    let Some(input) = std::env::var_os("Q04_AUTHORITY_CRASH_INPUT") else {
        return;
    };
    let value: Value = serde_json::from_slice(&fs::read(input).unwrap()).unwrap();
    let root = PathBuf::from(value["root"].as_str().unwrap());
    let evidence_root = PathBuf::from(value["evidence_root"].as_str().unwrap());
    let expected: FileQueryExpectedIdentitiesV1 =
        serde_json::from_value(value["expected"].clone()).unwrap();
    let query_ref: FileReceiptRef = serde_json::from_value(value["query_ref"].clone()).unwrap();
    let entities: Vec<GraphQueryEntityV1> =
        serde_json::from_value(value["entities"].clone()).unwrap();
    write_graph_query_evidence_index_v1(
        &context(&root, EffectPolicy::WorkspaceWrite),
        &evidence_root,
        &expected,
        &query_ref,
        value["index_manifest_sha256"].as_str().unwrap(),
        &entities,
    )
    .unwrap();
}

#[test]
fn q04_crash_after_private_authority_before_manifest_recovers_deterministically() {
    let fixture = Fixture::new();
    let entities = recovery_entities(&fixture);
    let query_manifest: gtkg_protocol::v03::query::FileQueryIndexManifestV1 =
        serde_json::from_slice(
            &fs::read(fixture.query_root.join(&fixture.query_manifest_ref.path)).unwrap(),
        )
        .unwrap();
    let evidence_root = fixture.workspace.path().join(".gtkg/recovery-evidence");
    let input = fixture.workspace.path().join("authority-crash-input.json");
    fs::write(
        &input,
        serde_json::to_vec(&json!({
            "root": fixture.workspace.path(),
            "evidence_root": evidence_root,
            "expected": fixture.expected,
            "query_ref": fixture.query_manifest_ref,
            "index_manifest_sha256": query_manifest.index_manifest_sha256,
            "entities": entities,
        }))
        .unwrap(),
    )
    .unwrap();
    let ready = fixture.workspace.path().join("authority-crash-ready");
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "q04_authority_crash_child", "--nocapture"])
        .env("Q04_AUTHORITY_CRASH_INPUT", &input)
        .env(
            "GTKG_TEST_FAULT_POINT",
            "v03_q04_authority_after_publish_before_manifest",
        )
        .env("GTKG_TEST_FAULT_READY", &ready)
        .spawn()
        .unwrap();
    for _ in 0..100 {
        if ready.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert!(
        ready.exists(),
        "authority child did not reach the frozen fault point"
    );
    child.kill().unwrap();
    assert!(!child.wait().unwrap().success());
    assert!(evidence_root.join("control").exists());
    assert!(!evidence_root.join("manifests").exists());

    let replay = write_graph_query_evidence_index_v1(
        &context(fixture.workspace.path(), EffectPolicy::WorkspaceWrite),
        &evidence_root,
        &fixture.expected,
        &fixture.query_manifest_ref,
        &query_manifest.index_manifest_sha256,
        &recovery_entities(&fixture),
    )
    .unwrap();
    assert!(replay.path.starts_with("manifests/"));
    assert_eq!(
        fs::read_dir(evidence_root.join("control")).unwrap().count(),
        1
    );
}
