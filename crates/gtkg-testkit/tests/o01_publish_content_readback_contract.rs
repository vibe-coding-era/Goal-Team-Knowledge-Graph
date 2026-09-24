//! Rev27 O01 v2 immutable publication content-readback contract.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

#[test]
fn publish_rejects_same_metadata_content_change_before_checksum_visibility() {
    let temp = tempfile::tempdir().unwrap();
    let driver = temp.path().join("driver.py");
    let source = format!(
        r#"import importlib.util
import os
from pathlib import Path

runner = Path({runner:?})
spec = importlib.util.spec_from_file_location("pixel_diff", runner)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
repo = Path({repo:?})
run = repo / "run"
publish = repo / "publish"
for directory in ("source", "generated", "diff", "e2e"):
    (run / directory).mkdir(parents=True, exist_ok=True)
    (publish / directory).mkdir(parents=True, exist_ok=True)
for relative in module.EVIDENCE_EXACT_SET:
    expected = ("expected-content:" + relative).encode("utf-8")
    source = publish / relative if relative.startswith("source/") else run / relative
    source.write_bytes(expected)
    if not relative.startswith("source/"):
        (publish / relative).write_bytes(b"previous-content:" + relative.encode("utf-8"))

root_identity = (publish.stat().st_dev, publish.stat().st_ino)
diff_identity = ((publish / "diff").stat().st_dev, (publish / "diff").stat().st_ino)
changed = False
def change_content_keep_metadata(relative):
    global changed
    if not changed and relative.startswith("diff/"):
        changed = True
        target = publish / relative
        before = target.stat()
        payload = bytearray(target.read_bytes())
        payload[0] ^= 1
        with target.open("r+b") as handle:
            handle.write(payload)
            handle.truncate(len(payload))
            handle.flush()
            os.fsync(handle.fileno())
        after = target.stat()
        assert (before.st_dev, before.st_ino, before.st_size) == (after.st_dev, after.st_ino, after.st_size)
        assert root_identity == (publish.stat().st_dev, publish.stat().st_ino)
        assert diff_identity == ((publish / "diff").stat().st_dev, (publish / "diff").stat().st_ino)

module._after_publish_file_hook = change_content_keep_metadata
try:
    module.publish_evidence(repo, run, publish)
except ValueError as error:
    assert "payload" in str(error) or "content" in str(error) or "readback" in str(error)
else:
    raise AssertionError("changed publication content reported success")
assert changed
assert not (publish / "SHA256SUMS.txt").exists()
"#,
        runner = root().join("crates/gtkg-testkit/browser/support/pixel_diff.py"),
        repo = temp.path().join("repo"),
    );
    fs::write(&driver, source).unwrap();
    let output = Command::new("python3")
        .args(["-B"])
        .arg(driver)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "publication content-readback contract failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
