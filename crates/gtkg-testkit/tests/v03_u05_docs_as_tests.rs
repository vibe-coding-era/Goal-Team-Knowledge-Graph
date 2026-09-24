//! U05 immutable documentation-as-tests contract.
//!
//! The guide and harness are deliberately included as source bytes.  This
//! makes a missing guide, a stale command catalog, or a changed local-only
//! boundary a compile/test failure rather than a documentation review note.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use tempfile::{Builder, TempDir};

const GUIDE: &str = include_str!("../../../docs/v03-product/U05-local-development.md");
const HARNESS: &str = include_str!("../../../scripts/v03/run-u05-docs-as-tests.sh");

const REQUIRED_CASES: [&str; 6] = [
    "quickstart",
    "privacy",
    "telemetry",
    "recovery",
    "performance",
    "uninstall",
];

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repository root")
}

fn isolated_output_root() -> TempDir {
    let parent = if cfg!(target_os = "macos") {
        Path::new("/private/tmp")
    } else {
        Path::new("/tmp")
    };
    Builder::new()
        .prefix("gtkg-u05-docs-")
        .tempdir_in(parent)
        .expect("private temporary U05 output root")
}

#[test]
fn u05_local_development_guide_commands_are_real_and_boundary_bound() {
    for heading in [
        "# U05 Local Development Guide",
        "## Quickstart",
        "## Privacy and telemetry",
        "## Recovery",
        "## Performance",
        "## Uninstall",
        "## Explicit non-claims",
    ] {
        assert!(GUIDE.contains(heading), "guide is missing {heading}");
    }
    for case_name in REQUIRED_CASES {
        assert!(
            GUIDE.contains(&format!("run-u05-docs-as-tests.sh {case_name}")),
            "guide is missing runnable {case_name} command"
        );
        assert!(
            HARNESS.contains(&format!("{case_name})")),
            "harness is missing {case_name} case"
        );
    }
    for boundary in [
        "local Development",
        "B01 remains blocked",
        "Release, publication, system installation, Current activation, and external runtime are not_run",
        "process-wide egress is not_verified",
    ] {
        assert!(GUIDE.contains(boundary), "guide omits boundary: {boundary}");
    }
    for prohibited in [
        "Release is complete",
        "Current is activated",
        "B01 is complete",
        "external runtime verified",
    ] {
        assert!(
            !GUIDE.contains(prohibited),
            "guide makes prohibited claim: {prohibited}"
        );
    }

    let output_root = isolated_output_root();
    let output = Command::new("sh")
        .args([
            "scripts/v03/run-u05-docs-as-tests.sh",
            "all",
            output_root.path().to_str().expect("utf-8 temporary path"),
        ])
        .current_dir(repository_root())
        .output()
        .expect("start U05 documentation harness");
    assert!(
        output.status.success(),
        "U05 documentation harness failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let receipt = fs::read_to_string(output_root.path().join("u05-docs-as-tests-receipt.json"))
        .expect("U05 documentation receipt");
    for case_name in REQUIRED_CASES {
        assert!(
            receipt.contains(&format!("\"{case_name}\"")),
            "receipt omits {case_name}"
        );
    }
    assert!(receipt.contains("\"scope\":\"local_development_only\""));
    assert!(receipt.contains("\"release_state\":\"not_run\""));
    assert!(receipt.contains("\"current_activation\":\"not_run\""));
}
