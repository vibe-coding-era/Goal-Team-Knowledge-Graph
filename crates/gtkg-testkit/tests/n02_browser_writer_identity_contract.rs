//! Rev26 N02 browser writer identity and stdin contract.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

#[cfg(unix)]
#[test]
fn secure_writer_rejects_output_root_swap_without_writing_outside() {
    use std::io::Write;
    use std::os::unix::fs::symlink;

    let helper = root().join("crates/gtkg-testkit/browser/support/pixel_diff.py");
    let fixture = tempfile::tempdir().unwrap();
    let workspace = fixture.path().canonicalize().unwrap();
    let output = workspace.join("output/n02-writer-swap");
    let publish = workspace.join("output/n02-writer-publish");
    let outside = tempfile::tempdir().unwrap();
    let prepared = Command::new("python3")
        .args(["-B"])
        .arg(&helper)
        .arg("--prepare-roots")
        .arg("--repo-root")
        .arg(&workspace)
        .arg("--output-root")
        .arg(&output)
        .arg("--publish-root")
        .arg(&publish)
        .output()
        .unwrap();
    assert!(prepared.status.success());
    let token = String::from_utf8(prepared.stdout).unwrap();
    fs::rename(&output, workspace.join("output/n02-writer-anchored")).unwrap();
    symlink(outside.path(), &output).unwrap();

    let mut child = Command::new("python3")
        .args(["-B"])
        .arg(&helper)
        .arg("--secure-write")
        .arg("--repo-root")
        .arg(&workspace)
        .arg("--identity-token")
        .arg(token.trim())
        .arg("--relative-path")
        .arg("generated/probe.png")
        .arg("--encoding")
        .arg("base64")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"cHJvYmU=").unwrap();
    let result = child.wait_with_output().unwrap();
    assert_eq!(result.status.code(), Some(2));
    assert!(!outside.path().join("generated/probe.png").exists());

    fs::remove_file(&output).unwrap();
    fs::remove_dir_all(workspace.join("output/n02-writer-anchored")).unwrap();
    fs::remove_dir_all(&publish).unwrap();
}

#[test]
fn browser_harness_streams_all_binary_and_json_writes_through_secure_writer() {
    let harness = fs::read_to_string(
        root().join("crates/gtkg-testkit/browser/i06_codex_wiki_e2e_contract.sh"),
    )
    .unwrap();
    assert!(!harness.contains("screenshot --filename"));
    assert!(!harness.contains("fs.writeFileSync"));
    assert!(!harness.contains("cp \"$RECEIPT\""));
    assert!(harness.matches("--secure-write").count() >= 3);
    assert!(harness.contains("page.screenshot({type:\"png\"})"));
    assert!(harness.contains("--encoding base64"));
    assert!(harness.contains("--encoding raw"));
    assert!(harness.contains("--identity-token \"$ROOT_IDENTITY\""));
}
