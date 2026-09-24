//! Rev27 O01 immutable same-inode publication readback contract.

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
fn publish_rejects_same_inode_payload_rewrite_before_checksum_visibility() {
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
    payload = ("expected:" + relative).encode("utf-8")
    target = publish / relative if relative.startswith("source/") else run / relative
    target.write_bytes(payload)
    published = publish / relative
    if not relative.startswith("source/"):
        published.write_bytes(b"previous:" + relative.encode("utf-8"))

fired = False
rewritten_inode = None
def rewrite_same_inode(relative):
    global fired, rewritten_inode
    if not fired and relative.startswith("diff/"):
        fired = True
        target = publish / relative
        before = target.stat()
        with target.open("r+b") as handle:
            handle.seek(0)
            handle.write(b"attacker-same-inode")
            handle.truncate()
            handle.flush()
            os.fsync(handle.fileno())
        after = target.stat()
        assert (before.st_dev, before.st_ino) == (after.st_dev, after.st_ino)
        rewritten_inode = (after.st_dev, after.st_ino)

module._after_publish_file_hook = rewrite_same_inode
try:
    module.publish_evidence(repo, run, publish)
except ValueError as error:
    assert "payload" in str(error) or "readback" in str(error) or "checksum" in str(error)
else:
    raise AssertionError("same-inode publication rewrite reported success")
assert fired and rewritten_inode is not None
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
        "same-inode readback contract failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
