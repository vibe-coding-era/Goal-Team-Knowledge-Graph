//! Rev24 L02 adversarial contract for the repo-local PNG pixel diff runner.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root")
}

fn runner() -> PathBuf {
    root().join("crates/gtkg-testkit/browser/support/pixel_diff.py")
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320u32 & 0u32.wrapping_sub(crc & 1));
        }
    }
    !crc
}

fn adler32(bytes: &[u8]) -> u32 {
    let mut first = 1u32;
    let mut second = 0u32;
    for byte in bytes {
        first = (first + u32::from(*byte)) % 65_521;
        second = (second + first) % 65_521;
    }
    (second << 16) | first
}

fn chunk(kind: &[u8; 4], data: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    output.extend_from_slice(&(data.len() as u32).to_be_bytes());
    output.extend_from_slice(kind);
    output.extend_from_slice(data);
    let mut crc_input = kind.to_vec();
    crc_input.extend_from_slice(data);
    output.extend_from_slice(&crc32(&crc_input).to_be_bytes());
    output
}

fn stored_zlib(bytes: &[u8]) -> Vec<u8> {
    assert!(bytes.len() <= u16::MAX as usize);
    let length = bytes.len() as u16;
    let mut output = vec![0x78, 0x01, 0x01];
    output.extend_from_slice(&length.to_le_bytes());
    output.extend_from_slice(&(!length).to_le_bytes());
    output.extend_from_slice(bytes);
    output.extend_from_slice(&adler32(bytes).to_be_bytes());
    output
}

fn rgba_png(width: u32, height: u32, pixels: &[u8]) -> Vec<u8> {
    assert_eq!(pixels.len(), width as usize * height as usize * 4);
    let mut scanlines = Vec::new();
    for row in pixels.chunks_exact(width as usize * 4) {
        scanlines.push(0);
        scanlines.extend_from_slice(row);
    }
    let mut ihdr = Vec::new();
    ihdr.extend_from_slice(&width.to_be_bytes());
    ihdr.extend_from_slice(&height.to_be_bytes());
    ihdr.extend_from_slice(&[8, 6, 0, 0, 0]);
    let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
    png.extend(chunk(b"IHDR", &ihdr));
    png.extend(chunk(b"IDAT", &stored_zlib(&scanlines)));
    png.extend(chunk(b"IEND", &[]));
    png
}

fn invoke(
    baseline: &Path,
    candidate: &Path,
    diff: &Path,
    metrics: &Path,
    extra: &[&str],
) -> Output {
    let mut command = Command::new("python3");
    command
        .arg("-B")
        .arg(runner())
        .arg("--baseline")
        .arg(baseline)
        .arg("--candidate")
        .arg(candidate)
        .arg("--diff")
        .arg(diff)
        .arg("--metrics")
        .arg(metrics)
        .args(["--max-diff-ratio", "0", "--max-mae", "0"])
        .args(extra);
    command.output().expect("run pixel diff")
}

#[test]
fn rgba_alpha_is_a_material_pixel_channel() {
    let temp = tempfile::tempdir().unwrap();
    let baseline = temp.path().join("baseline.png");
    let candidate = temp.path().join("candidate.png");
    let diff = temp.path().join("out/diff.png");
    let metrics = temp.path().join("out/metrics.json");
    fs::write(&baseline, rgba_png(1, 1, &[20, 30, 40, 255])).unwrap();
    fs::write(&candidate, rgba_png(1, 1, &[20, 30, 40, 0])).unwrap();

    let output = invoke(&baseline, &candidate, &diff, &metrics, &[]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "alpha-only drift must fail zero thresholds"
    );
    let metrics: Value = serde_json::from_slice(&fs::read(metrics).unwrap()).unwrap();
    assert_eq!(metrics["changed_pixels"], 1);
    assert_eq!(metrics["max_channel_delta"], 255);
    assert_eq!(metrics["passed"], false);
}

#[test]
fn file_shape_idat_and_decompression_budgets_fail_closed() {
    let temp = tempfile::tempdir().unwrap();
    let baseline = temp.path().join("baseline.png");
    let candidate = temp.path().join("candidate.png");
    let png = rgba_png(2, 2, &[10; 16]);
    fs::write(&baseline, &png).unwrap();
    fs::write(&candidate, &png).unwrap();

    for (name, option, limit) in [
        ("file", "--max-file-bytes", "16"),
        ("width", "--max-width", "1"),
        ("height", "--max-height", "1"),
        ("pixel", "--max-pixels", "3"),
        ("idat", "--max-idat-bytes", "1"),
        ("decompress", "--max-decompressed-bytes", "8"),
    ] {
        let diff = temp.path().join(format!("{name}/diff.png"));
        let metrics = temp.path().join(format!("{name}/metrics.json"));
        let output = invoke(&baseline, &candidate, &diff, &metrics, &[option, limit]);
        assert_eq!(
            output.status.code(),
            Some(2),
            "{name} budget must reject input"
        );
        assert!(
            !diff.exists() && !metrics.exists(),
            "{name} rejection wrote output"
        );
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("budget"),
            "{name} rejection did not identify budget: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[cfg(unix)]
#[test]
fn output_alias_symlink_and_root_overlap_are_rejected_before_write() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().unwrap();
    let input = temp.path().join("inputs");
    let output = temp.path().join("outputs");
    fs::create_dir_all(&input).unwrap();
    fs::create_dir_all(&output).unwrap();
    let baseline = input.join("baseline.png");
    let candidate = input.join("candidate.png");
    let png = rgba_png(1, 1, &[1, 2, 3, 255]);
    fs::write(&baseline, &png).unwrap();
    fs::write(&candidate, &png).unwrap();

    let alias = output.join("alias");
    let result = invoke(&baseline, &candidate, &alias, &alias, &[]);
    assert_eq!(result.status.code(), Some(2));
    assert!(!alias.exists());

    let sentinel = output.join("sentinel");
    fs::write(&sentinel, b"keep").unwrap();
    let linked_diff = output.join("linked-diff.png");
    symlink(&sentinel, &linked_diff).unwrap();
    let result = invoke(
        &baseline,
        &candidate,
        &linked_diff,
        &output.join("metrics.json"),
        &[],
    );
    assert_eq!(result.status.code(), Some(2));
    assert_eq!(fs::read(&sentinel).unwrap(), b"keep");

    let real_parent = output.join("real-parent");
    fs::create_dir(&real_parent).unwrap();
    let linked_parent = output.join("linked-parent");
    symlink(&real_parent, &linked_parent).unwrap();
    let result = invoke(
        &baseline,
        &candidate,
        &output.join("safe-diff.png"),
        &linked_parent.join("metrics.json"),
        &[],
    );
    assert_eq!(result.status.code(), Some(2));

    let result = invoke(
        &baseline,
        &candidate,
        &input.join("diff.png"),
        &input.join("metrics.json"),
        &[],
    );
    assert_eq!(
        result.status.code(),
        Some(2),
        "output root overlaps input root"
    );
}

#[test]
fn runner_imports_match_the_frozen_python_stdlib_allowlist() {
    let source = fs::read_to_string(runner()).unwrap();
    let imports = source
        .lines()
        .filter_map(|line| {
            line.strip_prefix("import ")
                .or_else(|| line.strip_prefix("from "))
                .and_then(|tail| tail.split_whitespace().next())
        })
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        imports,
        BTreeSet::from([
            "argparse".to_owned(),
            "base64".to_owned(),
            "binascii".to_owned(),
            "hashlib".to_owned(),
            "json".to_owned(),
            "math".to_owned(),
            "os".to_owned(),
            "pathlib".to_owned(),
            "stat".to_owned(),
            "struct".to_owned(),
            "sys".to_owned(),
            "zlib".to_owned(),
        ])
    );
}
