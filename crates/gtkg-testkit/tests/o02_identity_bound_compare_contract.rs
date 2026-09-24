//! Rev27 O02 v2 immutable identity-bound compare contract.

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
fn compare_reads_and_writes_through_one_open_directory_transaction() {
    let temp = tempfile::tempdir().unwrap();
    let driver = temp.path().join("driver.py");
    let source = format!(
        r#"import base64
import importlib.util
import json
from pathlib import Path
import sys

runner = Path({runner:?})
spec = importlib.util.spec_from_file_location("pixel_diff", runner)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
repo = Path({repo:?})
repo.mkdir(parents=True)
output = repo / "output"
anchored = repo / "output-anchored"
replacement_saved = repo / "output-replacement-observed"
publish = repo / "publish"
for directory in ("generated", "diff", "e2e"):
    (output / directory).mkdir(parents=True, exist_ok=True)
for directory in ("source", "generated", "diff", "e2e"):
    (publish / directory).mkdir(parents=True, exist_ok=True)
original_png = module._rgb_png_bytes(1, 1, bytes((10, 20, 30)))
different_png = module._rgb_png_bytes(1, 1, bytes((200, 100, 50)))
(output / "generated" / "baseline.png").write_bytes(original_png)
(output / "generated" / "candidate.png").write_bytes(original_png)
identities = {{}}
for name, path in (
    ("root", output),
    ("generated", output / "generated"),
    ("diff", output / "diff"),
    ("e2e", output / "e2e"),
):
    details = path.stat()
    identities[name] = [details.st_dev, details.st_ino]
token = base64.b64encode(json.dumps({{
    "repo_root": str(repo.resolve()),
    "output_root": "output",
    "identities": identities,
}}, separators=(",", ":")).encode("utf-8")).decode("ascii")

original_compare = module.compare
replacement_diff_entries = None
def replace_visible_path_during_compare(*args, **kwargs):
    global replacement_diff_entries
    output.rename(anchored)
    for directory in ("generated", "diff", "e2e"):
        (output / directory).mkdir(parents=True, exist_ok=True)
    (output / "generated" / "baseline.png").write_bytes(original_png)
    (output / "generated" / "candidate.png").write_bytes(different_png)
    try:
        return original_compare(*args, **kwargs)
    finally:
        replacement_diff_entries = sorted(path.name for path in (output / "diff").iterdir())
        output.rename(replacement_saved)
        anchored.rename(output)
module.compare = replace_visible_path_during_compare

sys.argv = [
    str(runner),
    "--repo-root", str(repo),
    "--output-identity-token", token,
    "--baseline", str(output / "generated" / "baseline.png"),
    "--candidate", str(output / "generated" / "candidate.png"),
    "--diff", str(output / "diff" / "result.png"),
    "--metrics", str(output / "diff" / "result.json"),
    "--max-diff-ratio", "0",
    "--max-mae", "0",
]
assert module.main() == 0
assert replacement_diff_entries == [], replacement_diff_entries
assert sorted(path.name for path in (output / "diff").iterdir()) == ["result.json", "result.png"]
metrics = json.loads((output / "diff" / "result.json").read_text(encoding="utf-8"))
assert metrics["passed"] is True and metrics["changed_pixels"] == 0
for name, path in (
    ("root", output),
    ("generated", output / "generated"),
    ("diff", output / "diff"),
    ("e2e", output / "e2e"),
):
    details = path.stat()
    assert [details.st_dev, details.st_ino] == identities[name]
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
        "identity-bound compare contract failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
