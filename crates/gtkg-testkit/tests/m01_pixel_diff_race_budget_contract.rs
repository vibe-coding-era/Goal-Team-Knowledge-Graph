//! Rev25 M01 race and peak-budget contract for the repo-local pixel diff.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root")
}

fn runner() -> PathBuf {
    root().join("crates/gtkg-testkit/browser/support/pixel_diff.py")
}

fn invoke_thresholds(ratio: &str, mae: &str, channel: &str) -> Output {
    Command::new("python3")
        .args(["-B"])
        .arg(runner())
        .args([
            "--baseline",
            "missing-a.png",
            "--candidate",
            "missing-b.png",
            "--diff",
            "missing-diff.png",
            "--metrics",
            "missing-metrics.json",
            "--max-diff-ratio",
            ratio,
            "--max-mae",
            mae,
            "--per-channel-threshold",
            channel,
        ])
        .output()
        .expect("run threshold validation")
}

#[test]
fn thresholds_are_finite_and_within_metric_ranges_before_io() {
    for (ratio, mae, channel) in [
        ("nan", "0", "0"),
        ("inf", "0", "0"),
        ("0", "nan", "0"),
        ("0", "inf", "0"),
        ("1.0001", "0", "0"),
        ("0", "255.0001", "0"),
        ("0", "0", "-1"),
        ("0", "0", "256"),
    ] {
        let output = invoke_thresholds(ratio, mae, channel);
        assert_eq!(output.status.code(), Some(2), "unsafe threshold reached IO");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("threshold"),
            "unexpected rejection: {stderr}"
        );
        assert!(
            !stderr.contains("missing"),
            "threshold validation ran after input IO"
        );
    }
}

#[test]
fn default_peak_budgets_are_bounded_for_playwright_screenshots() {
    let source = fs::read_to_string(runner()).unwrap();
    for required in [
        "DEFAULT_MAX_PIXELS = 4_500_000",
        "DEFAULT_MAX_DECOMPRESSED_BYTES = 32 * 1024 * 1024",
        "DEFAULT_MAX_CHANGED_PIXELS = 1_500_000",
        "DEFAULT_MAX_CLUSTER_PIXELS = 1_500_000",
    ] {
        assert!(
            source.contains(required),
            "missing bounded default: {required}"
        );
    }
    assert!(!source.contains("remaining = set(changed)"));
}

#[cfg(unix)]
#[test]
fn output_dirfd_resists_leaf_and_parent_swap_races() {
    let temp = tempfile::tempdir().unwrap();
    let driver = temp.path().join("race_driver.py");
    let source = format!(
        r#"import importlib.util
import os
from pathlib import Path
import sys

runner = Path({runner:?})
spec = importlib.util.spec_from_file_location("pixel_diff", runner)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

root = Path(sys.argv[1])
case = sys.argv[2]
inputs = root / "inputs"
outputs = root / "outputs"
outside = root / "outside"
inputs.mkdir()
outputs.mkdir()
outside.mkdir()
baseline = inputs / "baseline.png"
candidate = inputs / "candidate.png"
pixels = bytes([10, 20, 30])
module.write_rgb_png(baseline, 1, 1, pixels)
module.write_rgb_png(candidate, 1, 1, pixels)
diff = outputs / "diff.png"
metrics = outputs / "metrics.json"
victim = outside / "victim.txt"
victim.write_text("victim", encoding="utf-8")

original_read = module.read_png
fired = False
def racing_read(*args, **kwargs):
    global fired
    if not fired:
        fired = True
        if case == "leaf":
            os.symlink(victim, diff)
        else:
            outputs.rename(root / "anchored")
            os.symlink(outside, outputs)
    return original_read(*args, **kwargs)
module.read_png = racing_read

budget = module.Budgets(
    module.DEFAULT_MAX_FILE_BYTES,
    module.DEFAULT_MAX_WIDTH,
    module.DEFAULT_MAX_HEIGHT,
    module.DEFAULT_MAX_PIXELS,
    module.DEFAULT_MAX_IDAT_BYTES,
    module.DEFAULT_MAX_DECOMPRESSED_BYTES,
    module.DEFAULT_MAX_CHANGED_PIXELS,
    module.DEFAULT_MAX_CLUSTER_PIXELS,
)
passed = module.compare(baseline, candidate, diff, metrics, 0, 0, 0, budget)
assert passed and fired
assert victim.read_text(encoding="utf-8") == "victim"
if case == "leaf":
    assert diff.is_file() and not diff.is_symlink()
    assert metrics.is_file()
else:
    assert not any(outside.glob("diff.png"))
    assert not any(outside.glob("metrics.json"))
    assert (root / "anchored" / "diff.png").is_file()
    assert (root / "anchored" / "metrics.json").is_file()
"#,
        runner = runner()
    );
    fs::write(&driver, source).unwrap();

    for case in ["leaf", "parent"] {
        let case_root = temp.path().join(case);
        fs::create_dir(&case_root).unwrap();
        let output = Command::new("python3")
            .args(["-B"])
            .arg(&driver)
            .arg(&case_root)
            .arg(case)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{case} race escaped trusted dirfd: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
