//! V0.2 T01 source-capture contract.  These tests deliberately use the
//! internal v2 API: transport projection belongs to T08.

use std::fs;
use std::path::Path;
use std::process::Command;

use gtkg_core::source_v2::{
    CaptureErrorCode, SourceCaptureRequestV2, SuppliedManifestV2, TrustedManifestAuthorityV2,
    capture_source_snapshot_v2, capture_source_snapshot_v2_with_observer,
    capture_source_snapshot_v2_with_phases, capture_supplied_manifest_v2,
};
use gtkg_protocol::v2::SourceCaptureModeV2;
use tempfile::TempDir;

fn git(root: &Path, arguments: &[&str]) {
    let output = Command::new("/usr/bin/git")
        .arg("-C")
        .arg(root)
        .args(arguments)
        .output()
        .expect("git must start");
    assert!(
        output.status.success(),
        "git {} failed: {}",
        arguments.join(" "),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn git_repository() -> TempDir {
    let temp = tempfile::tempdir().expect("tempdir");
    git(temp.path(), &["init", "--quiet"]);
    git(
        temp.path(),
        &["config", "user.email", "test@example.invalid"],
    );
    git(temp.path(), &["config", "user.name", "GTKG test"]);
    fs::write(temp.path().join("tracked.rs"), "fn stable() {}\n").expect("tracked fixture");
    git(temp.path(), &["add", "tracked.rs"]);
    git(temp.path(), &["commit", "--quiet", "-m", "initial"]);
    temp
}

fn request(root: &Path, output: &Path) -> SourceCaptureRequestV2 {
    request_for(SourceCaptureModeV2::WorktreeExact, root, output)
}

fn request_for(mode: SourceCaptureModeV2, root: &Path, output: &Path) -> SourceCaptureRequestV2 {
    SourceCaptureRequestV2::new(mode, "fixture", root.to_path_buf(), output.to_path_buf())
}

#[test]
fn worktree_exact_is_development_eligible_but_never_a_source_release_candidate() {
    let repository = git_repository();
    fs::write(repository.path().join("tracked.rs"), "fn dirty() {}\n").expect("dirty fixture");
    fs::write(repository.path().join("untracked.md"), "# exact bytes\n")
        .expect("untracked fixture");
    let output = tempfile::tempdir().expect("output");

    let snapshot = capture_source_snapshot_v2(&request(repository.path(), output.path()))
        .expect("worktree exact capture");

    assert_eq!(snapshot.capture_mode, SourceCaptureModeV2::WorktreeExact);
    assert!(snapshot.eligibility.development_eligible);
    assert!(!snapshot.eligibility.source_release_candidate);
    assert!(!snapshot.eligibility.environment_ready);
    assert!(!snapshot.eligibility.release_ready);
    assert_eq!(snapshot.denominator.admitted_entries, 2);
    assert_eq!(
        snapshot.denominator.discovered_entries,
        snapshot.denominator.admitted_entries + snapshot.denominator.omitted_entries
    );
    assert!(
        snapshot
            .inventory
            .iter()
            .any(|entry| entry.logical_path == "tracked.rs")
    );
    assert!(
        snapshot
            .inventory
            .iter()
            .any(|entry| entry.logical_path == "untracked.md")
    );
}

#[test]
fn source_output_overlap_is_rejected_before_any_inventory_is_admitted() {
    let repository = git_repository();
    let error = capture_source_snapshot_v2(&request(
        repository.path(),
        &repository.path().join("derived-output"),
    ))
    .expect_err("output under source must fail closed");

    assert_eq!(error.code(), CaptureErrorCode::SourceOutputOverlap);
}

#[cfg(unix)]
#[test]
fn symlink_in_source_fails_closed_instead_of_becoming_an_unaccounted_omission() {
    use std::os::unix::fs::symlink;

    let repository = git_repository();
    symlink("tracked.rs", repository.path().join("linked.rs")).expect("symlink fixture");
    let output = tempfile::tempdir().expect("output");

    let error = capture_source_snapshot_v2(&request(repository.path(), output.path()))
        .expect_err("symlink must fail closed");

    assert_eq!(error.code(), CaptureErrorCode::SymlinkRejected);
}

#[test]
fn metadata_or_content_change_during_capture_fails_closed_without_a_partial_snapshot() {
    let repository = git_repository();
    let output = tempfile::tempdir().expect("output");
    let error = capture_source_snapshot_v2_with_observer(
        &request(repository.path(), output.path()),
        |path| {
            if path.file_name().is_some_and(|name| name == "tracked.rs") {
                fs::write(path, "fn changed_during_capture() {}\n").expect("mutation");
            }
        },
    )
    .expect_err("TOCTOU must fail closed");

    assert_eq!(error.code(), CaptureErrorCode::SnapshotDrift);
}

#[test]
fn directory_exact_rechecks_the_full_inventory_before_returning_a_snapshot() {
    let source = tempfile::tempdir().expect("source");
    let output = tempfile::tempdir().expect("output");
    let fixture = source.path().join("document.md");
    fs::write(&fixture, "before\n").expect("fixture");

    let error = capture_source_snapshot_v2_with_phases(
        &request_for(
            SourceCaptureModeV2::DirectoryExact,
            source.path(),
            output.path(),
        ),
        |_| {},
        || fs::write(&fixture, "after\n").expect("post-inventory mutation"),
    )
    .expect_err("post-inventory mutation must invalidate directory exact capture");

    assert_eq!(error.code(), CaptureErrorCode::SnapshotDrift);
}

#[test]
fn git_commit_uses_git_blob_inventory_and_rejects_a_dirty_worktree() {
    let repository = git_repository();
    let output = tempfile::tempdir().expect("output");
    fs::write(repository.path().join("tracked.rs"), "fn dirty() {}\n").expect("dirty fixture");
    fs::write(repository.path().join("untracked.md"), "untracked\n").expect("untracked fixture");

    let error = capture_source_snapshot_v2(&request_for(
        SourceCaptureModeV2::GitCommit,
        repository.path(),
        output.path(),
    ))
    .expect_err("Git commit capture must never silently use dirty worktree bytes");
    assert_eq!(error.code(), CaptureErrorCode::SourceDirty);

    git(repository.path(), &["reset", "--hard", "--quiet", "HEAD"]);
    fs::remove_file(repository.path().join("untracked.md")).expect("remove untracked fixture");
    let snapshot = capture_source_snapshot_v2(&request_for(
        SourceCaptureModeV2::GitCommit,
        repository.path(),
        output.path(),
    ))
    .expect("clean Git blob capture");

    assert!(snapshot.eligibility.source_release_candidate);
    assert_eq!(snapshot.inventory.len(), 1);
    assert_eq!(snapshot.inventory[0].logical_path, "tracked.rs");
    assert_eq!(
        snapshot.inventory[0].content_sha256,
        "sha256:af2f02ad0b09831697256fb0fa84a89bbed8e7cd6463b181242686078e735da1"
    );
}

#[test]
fn supplied_manifest_requires_a_trusted_authority_and_revalidates_every_entry() {
    let source = tempfile::tempdir().expect("source");
    let output = tempfile::tempdir().expect("output");
    fs::write(source.path().join("README.md"), "# supplied\n").expect("fixture");
    let directory_snapshot = capture_source_snapshot_v2(&request_for(
        SourceCaptureModeV2::DirectoryExact,
        source.path(),
        output.path(),
    ))
    .expect("directory source inventory");
    assert!(directory_snapshot.eligibility.development_eligible);
    assert!(!directory_snapshot.eligibility.source_release_candidate);
    let supplied_request = request_for(
        SourceCaptureModeV2::SuppliedManifest,
        source.path(),
        output.path(),
    );
    let manifest = SuppliedManifestV2::new(
        "authority-01",
        directory_snapshot.inventory.clone(),
        directory_snapshot.omissions.clone(),
    );

    let untrusted = capture_supplied_manifest_v2(&supplied_request, None, &manifest)
        .expect_err("manifest without an authority must fail closed");
    assert_eq!(untrusted.code(), CaptureErrorCode::UntrustedAuthority);

    let authority = TrustedManifestAuthorityV2::new("authority-01");
    let wrong_authority = TrustedManifestAuthorityV2::new("authority-02");
    let wrong_authority_error =
        capture_supplied_manifest_v2(&supplied_request, Some(&wrong_authority), &manifest)
            .expect_err("authority id mismatch must fail closed");
    assert_eq!(
        wrong_authority_error.code(),
        CaptureErrorCode::UntrustedAuthority
    );
    let snapshot = capture_supplied_manifest_v2(&supplied_request, Some(&authority), &manifest)
        .expect("trusted manifest must be read back exactly");
    assert!(snapshot.eligibility.development_eligible);
    assert!(!snapshot.eligibility.source_release_candidate);
    assert_eq!(snapshot.inventory, manifest.entries);
    assert_eq!(snapshot.omissions, manifest.omissions);

    fs::write(source.path().join("README.md"), "# changed\n").expect("mutate fixture");
    let stale = capture_supplied_manifest_v2(&supplied_request, Some(&authority), &manifest)
        .expect_err("supplied manifest must be revalidated entry by entry");
    assert_eq!(stale.code(), CaptureErrorCode::ManifestMismatch);
}

#[test]
fn supplied_manifest_fails_when_a_default_omission_appears_after_authorization() {
    let source = tempfile::tempdir().expect("source");
    let output = tempfile::tempdir().expect("output");
    fs::write(source.path().join("README.md"), "# supplied\n").expect("fixture");
    let directory_snapshot = capture_source_snapshot_v2(&request_for(
        SourceCaptureModeV2::DirectoryExact,
        source.path(),
        output.path(),
    ))
    .expect("directory source inventory");
    let supplied_request = request_for(
        SourceCaptureModeV2::SuppliedManifest,
        source.path(),
        output.path(),
    );
    let manifest = SuppliedManifestV2::new(
        "authority-01",
        directory_snapshot.inventory,
        directory_snapshot.omissions,
    );
    let authority = TrustedManifestAuthorityV2::new("authority-01");

    fs::create_dir(source.path().join("target")).expect("default omission root");
    fs::write(source.path().join("target/generated.json"), "{}\n").expect("generated fixture");
    let error = capture_supplied_manifest_v2(&supplied_request, Some(&authority), &manifest)
        .expect_err("a new default omission must invalidate the supplied exact set");

    assert_eq!(error.code(), CaptureErrorCode::ManifestMismatch);
}
