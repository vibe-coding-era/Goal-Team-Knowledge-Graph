//! Rev26 N01 split-brain publication transaction contract.

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
fn publish_detects_diff_directory_split_brain_after_first_anchored_write() {
    let temp = tempfile::tempdir().unwrap();
    let driver = temp.path().join("driver.py");
    let source = format!(
        r#"import importlib.util
from pathlib import Path
import shutil

runner = Path({runner:?})
spec = importlib.util.spec_from_file_location("pixel_diff", runner)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
workspace = Path({workspace:?})
repo = Path({repo:?})
run = repo / "run"
publish = repo / "publish"
for directory in ("source", "generated", "diff", "e2e"):
    (run / directory).mkdir(parents=True, exist_ok=True)
    (publish / directory).mkdir(parents=True, exist_ok=True)
evidence = workspace / "deliverables/codex-wiki-reverse/evidence"
for relative in module.EVIDENCE_EXACT_SET:
    source = evidence / relative
    target_root = publish if relative.startswith("source/") else run
    target = target_root / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)
    if not relative.startswith("source/"):
        published = publish / relative
        published.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, published)

fired = False
def split_brain(relative):
    global fired
    if not fired and relative.startswith("diff/"):
        fired = True
        (publish / "diff").rename(publish / "diff-anchored")
        (publish / "diff").mkdir()
        (publish / "diff" / "stale.txt").write_text("stale", encoding="utf-8")
module._after_publish_file_hook = split_brain
try:
    module.publish_evidence(repo, run, publish)
except ValueError as error:
    assert "identity" in str(error) or "split" in str(error)
else:
    raise AssertionError("split-brain publication reported success")
assert fired
assert (publish / "diff" / "stale.txt").read_text(encoding="utf-8") == "stale"
assert not (publish / "SHA256SUMS.txt").exists()
"#,
        runner = root().join("crates/gtkg-testkit/browser/support/pixel_diff.py"),
        workspace = root(),
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
        "split-brain contract failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
