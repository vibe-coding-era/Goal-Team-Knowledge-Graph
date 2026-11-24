#!/usr/bin/env python3
"""Run the complete Cargo gate plus the local, digest-bound integration runners."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import uuid

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
CARGO = ["cargo", "test", "--workspace", "--locked", "--no-fail-fast"]
LOCAL_SOURCE_PATHS = [".cargo", "crates", "templates", "skills", "deploy", "scripts",
                      "thinker", "thinker_tests", "bin", "docs/thinker.md", "docs/thinker-tui.md"]


def file_hash(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(256 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def fingerprint(paths):
    digest = hashlib.sha256()
    for path in sorted(set(paths)):
        name = path.relative_to(ROOT).as_posix()
        if path.is_symlink():
            value = "link " + os.readlink(path)
        elif not path.exists():
            value = "missing"
        elif stat.S_ISREG(path.stat().st_mode):
            value = file_hash(path)
        else:
            raise ValueError("unexpected validation input " + name)
        digest.update(name.encode() + b"\0" + value.encode() + b"\n")
    return digest.hexdigest()


def identities():
    listed = subprocess.check_output(["git", "ls-files", "-z", "--cached"], cwd=ROOT)
    listed += subprocess.check_output(["git", "ls-files", "-z", "--others",
                                       "--exclude-standard", "--", *LOCAL_SOURCE_PATHS], cwd=ROOT)
    sources = [ROOT / os.fsdecode(name) for name in listed.split(b"\0") if name]
    inputs = []
    for base in ("deliverables", "docs/reference"):
        for directory, dirs, names in os.walk(ROOT / base):
            dirs[:] = [item for item in dirs if item != ".git"]
            inputs.extend(Path(directory) / name for name in names)
    return fingerprint(sources), fingerprint(inputs)


def save(path, data):
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def expected_targets(env):
    rust_info = subprocess.check_output(["rustc", "-vV"], text=True, env=env)
    host = next(line.split(": ", 1)[1] for line in rust_info.splitlines() if line.startswith("host: "))
    metadata = json.loads(subprocess.check_output(
        ["cargo", "metadata", "--format-version=1", "--locked", "--offline", "--filter-platform", host],
        cwd=ROOT, env=env))
    features = {node["id"]: set(node["features"]) for node in metadata["resolve"]["nodes"]}
    targets = []
    for package in metadata["packages"]:
        if package["id"] not in metadata["workspace_members"]:
            continue
        for target in package["targets"]:
            if not set(target.get("required-features", ())) <= features[package["id"]]:
                continue
            kind, name = target["kind"], target["name"]
            if target["test"] and ("lib" in kind or "bin" in kind or "example" in kind):
                targets.append("unit::" + name.replace("-", "_"))
            if target["test"] and "test" in kind:
                targets.append(name)
            if target["doctest"] and "lib" in kind:
                targets.append("doc::" + name.replace("-", "_"))
    if not targets or len(targets) != len(set(targets)):
        raise ValueError("Cargo metadata contains no targets or ambiguous target names")
    return sorted(targets)


def run(args, log, env):
    with log.open("x") as output:
        return subprocess.run(args, cwd=ROOT, env=env, stdout=output,
                              stderr=subprocess.STDOUT, check=False).returncode


def capture(folder, env, frozen_classification):
    manifest = {"schema_version": "gtkg.current-run/v1", "run_id": str(uuid.uuid4()),
                "head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
                "command": CARGO, "log": "cargo.log", "classification_sha256": frozen_classification,
                "expected_targets": expected_targets(env)}
    manifest["source_digest_before"], manifest["input_digest_before"] = identities()
    manifest["inventory_source_digest"] = manifest["source_digest_before"]
    save(folder / "started.json", manifest)
    # Several process tests start target/debug/gtkg directly.
    if run(["cargo", "build", "--locked", "-p", "gtkg-app", "--bin", "gtkg"], folder/"build.log", env):
        raise RuntimeError("could not build local CLI; see build.log")
    manifest["exit_code"] = run(CARGO, folder / "cargo.log", env)
    manifest["log_sha256"] = file_hash(folder / "cargo.log")
    manifest["source_digest_after"], manifest["input_digest_after"] = identities()
    save(folder / "cargo-run.json", manifest)
    return manifest


def declared_cases(target):
    cases = []
    for path in sorted(HERE.glob("*-history.json")):
        for row in json.loads(path.read_text()):
            if row["class"] == "runner" and row["target"] == target:
                cases.append({"target":target, "test":row["test"]})
    if not cases:
        raise ValueError("missing runner contract for " + target)
    return cases


def runner_record(folder, manifest, target, command, code, test_log, stdout_log):
    if not test_log.is_file() or not stdout_log.is_file():
        raise RuntimeError("incomplete runner output for " + target)
    data = {"schema_version":"gtkg.current-runner/v1", "run_id":manifest["run_id"],
            "source_digest":manifest["source_digest_before"], "input_digest":manifest["input_digest_before"],
            "command":command, "exit_code":code, "cases":declared_cases(target)}
    for field, path in (("log", test_log), ("stdout_log", stdout_log)):
        data[field] = path.relative_to(folder).as_posix()
        data[field+"_sha256"] = file_hash(path)
    save(folder / (target + ".runner.json"), data)


def run_specialized(folder, manifest, env):
    folder.mkdir(mode=0o700)
    if identities() != (manifest["source_digest_before"], manifest["input_digest_before"]):
        raise RuntimeError("source or fixture digest differs from start of Cargo run")
    debug = ROOT / "target/debug/gtkg"
    r4 = "v03_p06_current_transport_successor_r4"
    command = ["cargo", "test", "--locked", "-p", "gtkg-testkit", "--test", r4,
               declared_cases(r4)[0]["test"], "--", "--exact"]
    log = folder / "p06-r4.log"
    code = run(command, log, dict(env, GTKG_BIN=str(debug), P06_BINARY_SHA256="sha256:"+file_hash(debug)))
    runner_record(folder, manifest, r4, command, code, log, log)
    if code:
        raise RuntimeError("P06 r4 current-binary contract failed")
    for rev in ("r5", "r6"):
        target = "v03_p06_current_transport_successor_" + rev
        output = folder / ("p06-" + rev)
        stdout = folder / ("p06-" + rev + ".log")
        command = ["bash", "scripts/v03/run-p06-current-transport-" + rev + ".sh", str(output)]
        code = run(command, stdout, env)
        runner_record(folder, manifest, target, command, code, output / "test.log", stdout)
        if code:
            raise RuntimeError("P06 " + rev + " failed")
    # The I01 runner requires a private temporary root and invokes U06 itself.
    with tempfile.TemporaryDirectory(prefix="gtkg-i01-r2-", dir=env["TMPDIR"]) as private:
        original = Path(private) / "run"
        command = ["bash", "scripts/v03/run-i01-identity-join-r2.sh", str(original)]
        stdout = folder / "i01.log"
        code = run(command, stdout, env)
        if original.is_dir():
            shutil.copytree(original, folder / "i01")
        for target, log in [("v03_i01_identity_join_successor_r2", "i01-r2-test.log"),
                             ("v03_u06_local_e2e_successor_r2", "u06-current-binary/u06-test.log")]:
            runner_record(folder, manifest, target, command, code, folder/"i01"/log, stdout)
        if code:
            raise RuntimeError("I01 or U06 failed")
    if identities() != (manifest["source_digest_before"], manifest["input_digest_before"]):
        raise RuntimeError("source or fixtures changed during specialized runs")


def classification_digest():
    digest = hashlib.sha256()
    paths = sorted(HERE.glob("*-history.json"))
    if not paths:
        raise ValueError("missing version classification")
    for path in paths:
        digest.update(path.name.encode() + b"\0" + file_hash(path).encode() + b"\n")
    return digest.hexdigest()


def verify(folder, manifest, result_path):
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    if manifest["head"] != head:
        raise ValueError("saved commit differs from the current checkout")
    if identities() != (manifest["source_digest_after"], manifest["input_digest_after"]):
        raise ValueError("saved run does not match the current source or fixtures")
    args = [sys.executable, str(HERE/"check-current.py"), "--log", str(folder/"cargo.log"),
            "--classification-dir", str(HERE), "--evidence-dir", str(folder/"runners"),
            "--run-manifest", str(folder/"run.json"), "--output", str(result_path)]
    return subprocess.run(args, cwd=ROOT).returncode


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="new report directory (existing report with --verify)")
    parser.add_argument("--verify", action="store_true", help="verify an existing report against this checkout")
    args = parser.parse_args()
    folder = args.output.resolve()
    if args.verify:
        with tempfile.TemporaryDirectory() as scratch:
            result = Path(scratch) / "recomputed.json"
            code = verify(folder, json.loads((folder/"run.json").read_text()), result)
            if code == 0 and json.loads(result.read_text()) != json.loads((folder/"current-result.json").read_text()):
                raise ValueError("saved current result differs from replay")
            return code
    env = dict(os.environ, TMPDIR="/private/tmp" if sys.platform == "darwin" else "/tmp",
               CARGO_TARGET_DIR=str(ROOT/"target"))
    for name in list(env):
        if name in ("GTKG_BIN", "CARGO_BUILD_TARGET") or name.startswith(("P06_", "U06_", "I01_")):
            del env[name]
    folder.mkdir(mode=0o700, parents=True, exist_ok=False)
    frozen = classification_digest()
    manifest = capture(folder, env, frozen)
    if manifest["source_digest_before"] != manifest["source_digest_after"] or manifest["input_digest_before"] != manifest["input_digest_after"]:
        raise RuntimeError("Cargo inputs changed; see cargo-run.json")
    run_specialized(folder/"runners", manifest, env)
    if frozen != classification_digest():
        raise RuntimeError("historical classification changed during the run")
    manifest["classification_sha256"] = frozen
    save(folder/"run.json", manifest)
    return verify(folder, manifest, folder/"current-result.json")


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.CalledProcessError) as error:
        print("Validation could not finish:", error, file=sys.stderr)
        sys.exit(2)
