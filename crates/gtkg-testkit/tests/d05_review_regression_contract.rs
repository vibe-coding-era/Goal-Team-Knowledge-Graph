//! Independent D05 review regressions.
//!
//! This contract deliberately reuses the frozen R5 real-D03 fixture in the same
//! integration-test module. Production code and the frozen source contract stay
//! untouched while the review findings remain executable against real bundles.

mod frozen_r5_fixture {
    include!("d05_integration_hardening_contract.rs");

    #[test]
    fn a0_official_catalog_lock_ignores_legacy_descriptor_drift_and_enforces_renderer_closure() {
        let fixture = Fixture::new();
        let context = fixture.context();

        // H04: schema/common-types/catalog semantics come from the vendored,
        // digest-locked official assets. A coherent rewrite of the legacy local
        // schema descriptor must not alter the resulting official lock.
        let nested_image = fixture.root.join("review-catalog-nested-image");
        copy_tree(&fixture.a2ui_catalog, &nested_image);
        let schema_path = nested_image.join("schema.json");
        let mut schema = read_json(&schema_path);
        schema["$defs"]["component"]["properties"]["component"]["enum"] = json!(["Image"]);
        fs::write(&schema_path, serde_json::to_vec_pretty(&schema).unwrap()).unwrap();
        rewrite_a2ui_manifest_digests(&nested_image);
        let resolution = fixture.resolve(&context, &nested_image);
        let lock = &resolution.result["a2ui_lock"];
        assert_eq!(lock["profile_id"], OFFICIAL_SERVER_SCHEMA_ID);
        assert_eq!(lock["common_types_id"], OFFICIAL_COMMON_TYPES_ID);
        assert_eq!(lock["catalog_id"], OFFICIAL_BASIC_CATALOG_ID);
        assert_eq!(
            lock["profile_sha256"],
            sha256_file(&vendor_dir().join("server_to_client.json")).unwrap()
        );
        assert_eq!(
            lock["catalog_sha256"],
            sha256_file(&vendor_dir().join("catalog.json")).unwrap()
        );
        let generated = fixture.generate(
            &context,
            &resolution.result["resolution_ref"],
            "61.0.0",
            "review-official-lock-descriptor-drift",
        );
        let validated = Dispatcher
            .execute(
                &context,
                OperationRequest::new(
                    OperationId::A2uiValidate,
                    "review-official-lock-descriptor-drift-validate",
                    json!({
                        "workspace_root": fixture.workspace,
                        "generation_ref": generated.result["generation_ref"],
                        "expected_projection_tree_sha256": generated.result["projection_tree_sha256"],
                        "required_evidence_state": "a2ui_generatable"
                    }),
                ),
            )
            .expect("official lock remains valid after legacy descriptor drift");
        assert_eq!(validated.result["valid"], true);

        // A manifest may point at an integrity-locked local catalog descriptor,
        // but the renderer still has to support the exact projected component
        // set. A renderer narrowed to Text must fail before publication.
        let locked_path = fixture.root.join("review-catalog-locked-path");
        copy_tree(&fixture.a2ui_catalog, &locked_path);
        fs::write(
            locked_path.join("locked-catalog.json"),
            serde_json::to_vec_pretty(&json!({
                "id": "gtkg-test-catalog",
                "version": "0.1.0",
                "components": ["Text"],
                "actions": []
            }))
            .unwrap(),
        )
        .unwrap();
        let mut renderer = read_json(&locked_path.join("renderer.json"));
        renderer["supported_components"] = json!(["Text"]);
        renderer["supported_actions"] = json!([]);
        fs::write(
            locked_path.join("renderer.json"),
            serde_json::to_vec_pretty(&renderer).unwrap(),
        )
        .unwrap();
        rewrite_manifest_with_catalog_path(&locked_path, "locked-catalog.json");
        let resolution = fixture.resolve(&context, &locked_path);
        let error = fixture.generate_error(
            &context,
            &resolution.result["resolution_ref"],
            "61.0.1",
            "review-renderer-component-gap",
        );
        assert!(matches!(
            error,
            ErrorCode::InvalidRequest
                | ErrorCode::LockMismatch
                | ErrorCode::BundleInvalid
                | ErrorCode::InvalidState
        ));
    }

    fn rewrite_manifest_with_catalog_path(root: &Path, catalog_path: &str) {
        let manifest = json!({
            "schema_version": "gtkg.a2ui-local-catalog-manifest/v1",
            "spec_version": "0.9.1",
            "profile": {
                "id": "gtkg-test-profile",
                "version": "0.9.1",
                "path": "profile.json",
                "sha256": sha256_file(&root.join("profile.json")).unwrap()
            },
            "schema": {
                "path": "schema.json",
                "sha256": sha256_file(&root.join("schema.json")).unwrap()
            },
            "common_types": {
                "id": "gtkg-test-common-types",
                "version": "0.1.0",
                "path": "common_types.json",
                "sha256": sha256_file(&root.join("common_types.json")).unwrap()
            },
            "catalog": {
                "id": "gtkg-test-catalog",
                "version": "0.1.0",
                "path": catalog_path,
                "sha256": sha256_file(&root.join(catalog_path)).unwrap()
            },
            "renderer": {
                "id": "gtkg-test-renderer",
                "version": "test-only",
                "path": "renderer.json",
                "sha256": sha256_file(&root.join("renderer.json")).unwrap()
            },
            "scope": "official_basic_catalog"
        });
        fs::write(
            root.join("manifest.json"),
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn a1_untrusted_knowledge_tokens_remain_data_and_never_escape_into_ui_structure() {
        let fixture = Fixture::new();
        let context = fixture.context();
        let executable_substring = build_additional_bundle(
            &fixture,
            "exec-marker",
            Some(("component", "component-exec-card")),
        );
        let resolution = fixture.resolve(&context, &fixture.a2ui_catalog);
        let version = "62.0.0";
        let versions_before = count_version_directories(&fixture.workspace, version);
        let receipts_before = count_files(&fixture.workspace.join(".gtkg/a2ui/generations"));
        let generated = Dispatcher
            .execute(
                &context,
                review_generate_request(
                    &fixture,
                    &executable_substring,
                    &resolution.result["resolution_ref"],
                    version,
                    "review-data-bound-exec-marker",
                ),
            )
            .expect("knowledge text is inert A2UI data");
        assert_eq!(generated.result["executed_target_content"], false);

        let readback = Dispatcher
            .execute(
                &context,
                OperationRequest::new(
                    OperationId::A2uiGet,
                    "review-data-bound-get",
                    json!({
                        "workspace_root": fixture.workspace,
                        "generation_ref": generated.result["generation_ref"],
                        "expected_projection_tree_sha256": generated.result["projection_tree_sha256"]
                    }),
                ),
            )
            .expect("generated stream readback");
        let stream = readback.result["stream"].as_array().expect("stream array");
        assert!(
            stream[2]["updateDataModel"]
                .to_string()
                .contains("exec-marker"),
            "untrusted knowledge token must stay in the data model"
        );
        assert!(
            !stream[1]["updateComponents"]
                .to_string()
                .contains("exec-marker"),
            "untrusted knowledge token must not enter component structure"
        );
        let validation = Dispatcher
            .execute(
                &context,
                OperationRequest::new(
                    OperationId::A2uiValidate,
                    "review-data-bound-validate",
                    json!({
                        "workspace_root": fixture.workspace,
                        "generation_ref": generated.result["generation_ref"],
                        "expected_projection_tree_sha256": generated.result["projection_tree_sha256"],
                        "required_evidence_state": "a2ui_generatable"
                    }),
                ),
            )
            .expect("data-bound stream validates");
        assert_eq!(validation.result["valid"], true);
        let versions_after = count_version_directories(&fixture.workspace, version);
        let receipts_after = count_files(&fixture.workspace.join(".gtkg/a2ui/generations"));
        assert_eq!(versions_after, versions_before + 1);
        assert_eq!(receipts_after, receipts_before + 1);
    }

    #[test]
    fn a2_generation_receipt_cannot_rebind_projection_a_to_canonical_bundle_b() {
        let fixture = Fixture::new();
        let context = fixture.context();
        let bundle_b = build_additional_bundle(&fixture, "bundle-b", None);
        let resolution = fixture.resolve(&context, &fixture.a2ui_catalog);
        let generated_a = Dispatcher
            .execute(
                &context,
                review_generate_request(
                    &fixture,
                    &primary_bundle(&fixture),
                    &resolution.result["resolution_ref"],
                    "63.0.0",
                    "review-cross-bundle-a",
                ),
            )
            .expect("legal generation A");
        let generated_b = Dispatcher
            .execute(
                &context,
                review_generate_request(
                    &fixture,
                    &bundle_b,
                    &resolution.result["resolution_ref"],
                    "63.0.1",
                    "review-cross-bundle-b",
                ),
            )
            .expect("legal generation B");

        let ref_a = parse_receipt_ref(&generated_a.result["generation_ref"]);
        let ref_b = parse_receipt_ref(&generated_b.result["generation_ref"]);
        let mut forged = read_json(&fixture.workspace.join(&ref_a.path));
        let receipt_b = read_json(&fixture.workspace.join(&ref_b.path));
        for field in [
            "canonical_bundle_path",
            "canonical_bundle_tree_sha256",
            "artifact_manifest_sha256",
            "source_lock_sha256",
        ] {
            forged[field] = receipt_b[field].clone();
        }
        let forged_seed = canonical_json_sha256(&forged).unwrap();
        let forged_id = format!("generate-{}", &forged_seed[7..31]);
        forged["projection_id"] = Value::String(forged_id.clone());
        let forged_path = fixture
            .workspace
            .join(format!(".gtkg/a2ui/generations/{forged_id}.json"));
        fs::write(&forged_path, serde_json::to_vec_pretty(&forged).unwrap()).unwrap();
        let forged_ref = json!({
            "path": receipt_relative(&fixture.workspace, &forged_path),
            "sha256": sha256_file(&forged_path).unwrap()
        });

        let get_result = Dispatcher.execute(
            &context,
            OperationRequest::new(
                OperationId::A2uiGet,
                "review-cross-bundle-get",
                json!({
                    "workspace_root": fixture.workspace,
                    "generation_ref": forged_ref,
                    "expected_projection_tree_sha256": generated_a.result["projection_tree_sha256"]
                }),
            ),
        );
        let validate_result = Dispatcher.execute(
            &context,
            OperationRequest::new(
                OperationId::A2uiValidate,
                "review-cross-bundle-validate",
                json!({
                    "workspace_root": fixture.workspace,
                    "generation_ref": forged_ref,
                    "expected_projection_tree_sha256": generated_a.result["projection_tree_sha256"],
                    "required_evidence_state": "a2ui_generatable"
                }),
            ),
        );
        assert!(
            get_result.is_err() && validate_result.is_err(),
            "receipt cannot combine bundle B closure with projection A: get_ok={}, validate_ok={}",
            get_result.is_ok(),
            validate_result.is_ok()
        );
    }

    #[cfg(unix)]
    #[test]
    fn a3_intermediate_receipt_namespace_symlinks_inside_workspace_are_rejected() {
        use std::os::unix::fs::symlink;

        let resolution_fixture = Fixture::new();
        let resolution_context = resolution_fixture.context();
        let resolution =
            resolution_fixture.resolve(&resolution_context, &resolution_fixture.a2ui_catalog);
        let resolution_dir = resolution_fixture.workspace.join(".gtkg/a2ui/resolutions");
        let resolution_shadow = resolution_fixture
            .workspace
            .join(".gtkg/a2ui/review-resolution-shadow");
        fs::rename(&resolution_dir, &resolution_shadow).unwrap();
        symlink(&resolution_shadow, &resolution_dir).unwrap();
        let resolution_namespace_result = Dispatcher.execute(
            &resolution_context,
            resolution_fixture.generate_request(
                &resolution.result["resolution_ref"],
                "64.0.0",
                "review-resolution-intermediate-symlink",
            ),
        );

        let generation_fixture = Fixture::new();
        let generation_context = generation_fixture.context();
        let generation_resolution =
            generation_fixture.resolve(&generation_context, &generation_fixture.a2ui_catalog);
        let generated = generation_fixture.generate(
            &generation_context,
            &generation_resolution.result["resolution_ref"],
            "64.0.1",
            "review-generation-before-symlink",
        );
        let generation_dir = generation_fixture.workspace.join(".gtkg/a2ui/generations");
        let generation_shadow = generation_fixture
            .workspace
            .join(".gtkg/a2ui/review-generation-shadow");
        fs::rename(&generation_dir, &generation_shadow).unwrap();
        symlink(&generation_shadow, &generation_dir).unwrap();
        let generation_namespace_result = Dispatcher.execute(
            &generation_context,
            OperationRequest::new(
                OperationId::A2uiGet,
                "review-generation-intermediate-symlink",
                json!({
                    "workspace_root": generation_fixture.workspace,
                    "generation_ref": generated.result["generation_ref"],
                    "expected_projection_tree_sha256": generated.result["projection_tree_sha256"]
                }),
            ),
        );

        assert!(
            resolution_namespace_result.is_err() && generation_namespace_result.is_err(),
            "every intermediate producer namespace component must be a real directory: resolution_generate_ok={}, generation_get_ok={}",
            resolution_namespace_result.is_ok(),
            generation_namespace_result.is_ok()
        );
    }

    #[test]
    fn a4_projection_version_is_globally_immutable_across_generation_identities() {
        let fixture = Fixture::new();
        let context = fixture.context();
        let bundle_a = primary_bundle(&fixture);
        let bundle_b = build_additional_bundle(&fixture, "version-b", None);
        let resolution = fixture.resolve(&context, &fixture.a2ui_catalog);

        Dispatcher
            .execute(
                &context,
                review_generate_request(
                    &fixture,
                    &bundle_a,
                    &resolution.result["resolution_ref"],
                    "65.0.0",
                    "review-version-sequential-a",
                ),
            )
            .expect("first sequential publisher");
        let sequential_loser = Dispatcher.execute(
            &context,
            review_generate_request(
                &fixture,
                &bundle_b,
                &resolution.result["resolution_ref"],
                "65.0.0",
                "review-version-sequential-b",
            ),
        );
        assert_eq!(
            sequential_loser
                .expect_err("second identity must lose")
                .error
                .code,
            ErrorCode::VersionImmutable
        );

        let mut race_violations = Vec::new();
        for attempt in 1..=24 {
            let version = format!("65.1.{attempt}");
            let request_a = review_generate_request(
                &fixture,
                &bundle_a,
                &resolution.result["resolution_ref"],
                &version,
                &format!("review-version-race-a-{attempt}"),
            );
            let request_b = review_generate_request(
                &fixture,
                &bundle_b,
                &resolution.result["resolution_ref"],
                &version,
                &format!("review-version-race-b-{attempt}"),
            );
            let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
            let barrier_a = barrier.clone();
            let barrier_b = barrier;
            let context_a = context.clone();
            let context_b = context.clone();
            let (result_a, result_b) = std::thread::scope(|scope| {
                let a = scope.spawn(move || {
                    barrier_a.wait();
                    Dispatcher.execute(&context_a, request_a)
                });
                let b = scope.spawn(move || {
                    barrier_b.wait();
                    Dispatcher.execute(&context_b, request_b)
                });
                (a.join().unwrap(), b.join().unwrap())
            });
            let results = [result_a, result_b];
            let successes = results.iter().filter(|result| result.is_ok()).count();
            let error_codes = results
                .iter()
                .filter_map(|result| result.as_ref().err().map(|error| error.error.code))
                .collect::<Vec<_>>();
            let versions = count_version_directories(&fixture.workspace, &version);
            if successes != 1 || versions != 1 || error_codes != vec![ErrorCode::VersionImmutable] {
                race_violations.push(format!(
                    "{version}: successes={successes}, version_dirs={versions}, errors={error_codes:?}"
                ));
                break;
            }
        }
        assert!(
            race_violations.is_empty(),
            "projection-version lock cannot be sharded by generation identity: {}",
            race_violations.join("; ")
        );
    }

    #[test]
    fn a5_commented_and_string_literal_markers_are_not_observed_static_entities() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("CommentOnly.tsx");
        fs::write(
            &path,
            r#"
// <main data-surface-id="commented-surface" />
/* openKnowledge("commented-interaction") */
const documentation = 'data-app-id="string-app"';
const example = 'stateId: "string-state"';
export const harmless = 1;
"#,
        )
        .unwrap();
        let extracted = gtkg_extract::extract_path(&path).unwrap();
        assert!(
            extracted.observed_facts.is_empty(),
            "comments and inert string literals are not syntax observations: {:?}",
            extracted.observed_facts
        );
    }

    #[derive(Clone)]
    struct ReviewBundle {
        bundle: PathBuf,
        tree_sha256: String,
    }

    fn primary_bundle(fixture: &Fixture) -> ReviewBundle {
        ReviewBundle {
            bundle: fixture.bundle.clone(),
            tree_sha256: fixture.bundle_tree_sha256.clone(),
        }
    }

    fn review_generate_request(
        fixture: &Fixture,
        bundle: &ReviewBundle,
        resolution_ref: &Value,
        version: &str,
        request_id: &str,
    ) -> OperationRequest {
        OperationRequest::new(
            OperationId::A2uiGenerate,
            request_id,
            json!({
                "workspace_root": fixture.workspace,
                "bundle_path": bundle.bundle,
                "expected_bundle_tree_sha256": bundle.tree_sha256,
                "resolution_ref": resolution_ref,
                "projection_version": version
            }),
        )
    }

    fn build_additional_bundle(
        fixture: &Fixture,
        label: &str,
        marker_override: Option<(&str, &str)>,
    ) -> ReviewBundle {
        let repository = fixture.root.join(format!("review-frontend-{label}"));
        fs::create_dir_all(repository.join("src")).unwrap();
        let identity =
            canonical_json_sha256(&format!("{}:{label}", fixture.root.display())).unwrap();
        let nonce = &identity[7..15];
        for (kind, logical_path, marker_base, _) in ENTITY_FIXTURES {
            let base = marker_override
                .filter(|(target, _)| *target == kind)
                .map_or(marker_base, |(_, replacement)| replacement);
            let marker = format!("{base}-{nonce}");
            fs::write(
                repository.join(logical_path),
                frontend_fixture_source(kind, &marker),
            )
            .unwrap();
        }
        init_and_commit(&repository);
        let repo_id = format!("frontend-{label}");
        let inspected = execute_ok(
            &fixture.context(),
            OperationId::SourceInspect,
            &format!("review-source-inspect-{label}"),
            json!({
                "workspace_root": fixture.workspace,
                "repositories": [{
                    "repo_id": repo_id,
                    "path": repository,
                    "role": "frontend",
                    "include": []
                }]
            }),
        );
        let resolved = execute_ok(
            &fixture.context(),
            OperationId::TemplateResolve,
            &format!("review-template-resolve-{label}"),
            json!({
                "workspace_root": fixture.workspace,
                "catalog_root": fixture.root.join("template-catalog"),
                "template_id": "summary-template",
                "version": "0.1.0"
            }),
        );
        let validated = execute_ok(
            &fixture.context(),
            OperationId::TemplateValidate,
            &format!("review-template-validate-{label}"),
            json!({
                "workspace_root": fixture.workspace,
                "resolution_ref": resolved.result["resolution_ref"]
            }),
        );
        let source_ref = inspected.result["inspection_ref"].clone();
        let template_ref = validated.result["validation_ref"].clone();
        let version_patch = label.bytes().map(u64::from).sum::<u64>() % 10_000;
        let mut plan = OperationRequest::new(
            OperationId::BuildPlan,
            format!("review-build-plan-{label}"),
            json!({
                "workspace_root": fixture.workspace,
                "mode": "full",
                "source_inspection_ref": source_ref,
                "template_validation_ref": template_ref,
                "baseline_bundle": null,
                "bundle_version": format!("81.0.{version_patch}")
            }),
        );
        plan.locks = BTreeMap::from([
            (
                "source_inspection".to_owned(),
                source_ref["sha256"].as_str().unwrap().to_owned(),
            ),
            (
                "template_validation".to_owned(),
                template_ref["sha256"].as_str().unwrap().to_owned(),
            ),
        ]);
        let planned = Dispatcher.execute(&fixture.context(), plan).unwrap();
        let run_id = planned.run_id.unwrap();
        execute_ok_run(
            &fixture.context(),
            OperationId::BuildPrepare,
            &run_id,
            &format!("review-build-prepare-{label}"),
            json!({"workspace_root": fixture.workspace}),
        );
        loop {
            let next = execute_ok_run(
                &fixture.context(),
                OperationId::SummaryNext,
                &run_id,
                &format!("review-summary-next-{label}"),
                json!({"workspace_root": fixture.workspace}),
            );
            let Some(job) = next.result.get("job").filter(|value| !value.is_null()) else {
                break;
            };
            execute_ok_run(
                &fixture.context(),
                OperationId::SummaryAccept,
                &run_id,
                &format!(
                    "review-summary-{label}-{}",
                    job["packet_id"].as_str().unwrap()
                ),
                json!({
                    "workspace_root": fixture.workspace,
                    "packet_id": job["packet_id"],
                    "source_sha256": job["source_sha256"],
                    "template_manifest_sha256": job["template_manifest_sha256"],
                    "summary_markdown": format!(
                        "# Static frontend analysis\n\nrepo_id: {}\nlogical_path: {}\n\n```text\n{}\n```",
                        job["repo_id"].as_str().unwrap(),
                        job["source_path"].as_str().unwrap(),
                        job["analysis_text"].as_str().unwrap()
                    )
                }),
            );
        }
        let finalized = execute_ok_run(
            &fixture.context(),
            OperationId::BuildFinalize,
            &run_id,
            &format!("review-build-finalize-{label}"),
            json!({"workspace_root": fixture.workspace}),
        );
        let bundle = result_path(&finalized, "bundle_path");
        let bundle_tree_sha256 = finalized.result["tree_digest"].as_str().unwrap().to_owned();
        assert_eq!(tree_sha256(&bundle).unwrap(), bundle_tree_sha256);
        ReviewBundle {
            bundle,
            tree_sha256: bundle_tree_sha256,
        }
    }

    pub(super) fn execute_inherited_fault_child() {
        child_executes_d05_generation_fault_request();
    }
}

// The inherited crash fixture spawns the current test binary by this exact
// root-level name. Keep the bridge explicit so inclusion does not create a
// false mechanical Red unrelated to the independent review findings.
#[test]
fn child_executes_d05_generation_fault_request() {
    frozen_r5_fixture::execute_inherited_fault_child();
}
