#[path = "support/v03_q06_equivalence_fixture.rs"]
mod fixture;

use std::fs;

use gtkg_core::v03::query_equivalence::verify_full_incremental_file_query_equivalence_v1;
use gtkg_core::{CallContext, EffectPolicy, TransportKind};
use gtkg_protocol::v03::query::FileQueryIndexManifestV1;

#[test]
fn q06_full_and_incremental_file_indices_are_exactly_equivalent_for_mutation_matrix() {
    for scenario in fixture::scenarios() {
        let workspace = tempfile::tempdir().unwrap();
        let context = CallContext::restricted(
            TransportKind::Test,
            vec![workspace.path().to_path_buf()],
            EffectPolicy::WorkspaceWrite,
        )
        .unwrap();
        let full_root = workspace.path().join(format!("full-{}", scenario.name));
        let incremental_root = workspace
            .path()
            .join(format!("incremental-{}", scenario.name));
        let report = verify_full_incremental_file_query_equivalence_v1(
            &context,
            &full_root,
            &incremental_root,
            &scenario.base,
            &scenario.mutations,
            &scenario.terminal,
            &fixture::requests(scenario.required_search, scenario.forbidden_search),
        )
        .unwrap();

        assert!(report.terminal_manifest_equal, "{}", scenario.name);
        assert!(report.shard_exact_set_equal, "{}", scenario.name);
        assert_eq!(report.stale_count, 0, "{}", scenario.name);
        assert_eq!(report.ghost_count, 0, "{}", scenario.name);
        assert_eq!(report.silent_omission_count, 0, "{}", scenario.name);
        assert!(report.query_results.iter().all(|result| result.equal));
        assert_eq!(report.full_manifest_ref, report.incremental_manifest_ref);

        let full_manifest: FileQueryIndexManifestV1 = serde_json::from_slice(
            &fs::read(full_root.join(&report.full_manifest_ref.path)).unwrap(),
        )
        .unwrap();
        let incremental_manifest: FileQueryIndexManifestV1 = serde_json::from_slice(
            &fs::read(incremental_root.join(&report.incremental_manifest_ref.path)).unwrap(),
        )
        .unwrap();
        assert_eq!(full_manifest, incremental_manifest, "{}", scenario.name);
        assert_eq!(
            full_manifest.shard_files,
            report.full_shard_exact_set,
            "{}",
            scenario.name
        );
        assert!(
            report
                .query_results
                .first()
                .is_some_and(|result| result.full_result_count > 0),
            "{}",
            scenario.name
        );
        if scenario.forbidden_search.is_some() {
            assert_eq!(
                report.query_results.last().unwrap().full_result_count,
                0,
                "{}",
                scenario.name
            );
        }
    }
}
