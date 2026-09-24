//! Rev27 O02 immutable output-identity transaction contract.

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
fn pixel_compare_keeps_generated_and_diff_fds_across_real_directory_swap() {
    let temp = tempfile::tempdir().unwrap();
    let driver = temp.path().join("driver.py");
    let source = format!(
        r#"import base64
import importlib.util
import json
from pathlib import Path
import shutil
import sys

runner = Path({runner:?})
spec = importlib.util.spec_from_file_location("pixel_diff", runner)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
repo = Path({repo:?})
repo.mkdir(parents=True)
output = repo / "output"
anchored = repo / "output-anchored"
publish = repo / "publish"
for directory in ("generated", "diff", "e2e"):
    (output / directory).mkdir(parents=True, exist_ok=True)
for directory in ("source", "generated", "diff", "e2e"):
    (publish / directory).mkdir(parents=True, exist_ok=True)
png = module._rgb_png_bytes(1, 1, bytes((10, 20, 30)))
(output / "generated" / "baseline.png").write_bytes(png)
(output / "generated" / "candidate.png").write_bytes(png)
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

original_validate = module.validate_output_identity
validation_count = 0
def attack_after_first_validate(*args, **kwargs):
    global validation_count
    result = original_validate(*args, **kwargs)
    validation_count += 1
    if validation_count == 1:
        output.rename(anchored)
        for directory in ("generated", "diff", "e2e"):
            (output / directory).mkdir(parents=True, exist_ok=True)
        shutil.copyfile(anchored / "generated" / "baseline.png", output / "generated" / "baseline.png")
        shutil.copyfile(anchored / "generated" / "candidate.png", output / "generated" / "candidate.png")
    return result
module.validate_output_identity = attack_after_first_validate

original_compare = module.compare
attacker_wrote = None
def restore_after_compare(*args, **kwargs):
    global attacker_wrote
    result = original_compare(*args, **kwargs)
    attacker_wrote = (output / "diff" / "result.png").exists() or (output / "diff" / "result.json").exists()
    shutil.rmtree(output)
    anchored.rename(output)
    return result
module.compare = restore_after_compare

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
assert validation_count >= 1
assert attacker_wrote is False, "compare wrote into swapped attacker directory"
assert (output / "diff" / "result.png").is_file()
assert (output / "diff" / "result.json").is_file()
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
        "identity transaction contract failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
