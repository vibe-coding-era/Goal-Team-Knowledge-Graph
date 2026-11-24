#!/usr/bin/env python3
"""Run exact original Rust tests from an explicit local Git commit in isolation.

Example (public snapshot observation, not an earlier-stage acceptance):
  python3 scripts/validation/check-history.py --checkout . \
    --commit 2f7859474219f034556ffd1e492960b70496cdc6 \
    --target e07_arch_docs_contract \
    --test architecture_documents_are_deterministic_and_verifiable \
    --report history-e07.json

For archived cases, omit --test to select only that target's exact archived
names. --material-root supplies missing original frozen artifacts (defaults to
the given checkout); copied bytes are individually recorded, never invented.
Exit: 0 exact selected tests passed; 1 observed failure; 2 blocked/invalid input.
An isolated checkout is not an OS security sandbox. Only run trusted local source.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import tempfile
import time


CATALOG_DIRECTORY = Path(__file__).parent
PUBLIC_SNAPSHOT = "2f7859474219f034556ffd1e492960b70496cdc6"
INTERNAL_SOURCE = "f9c9990d235e337ecebc46c86bacd13b63f90408"
T03_INPUTS = [
    "docs/reference/okf-v0.2-reference-W4G1",
    "deliverables/v02-t03/current-okf-normative-corpus.json",
    "deliverables/v02-t03/current-okf-normative-corpus-receipt.json",
]


class Blocked(Exception):
    pass


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def command(argv, cwd, report, timeout=60, env=None):
    started = time.monotonic()
    with subprocess.Popen(argv, cwd=str(cwd), env=env, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, start_new_session=True) as process:
        timed_out = False
        try:
            out, err = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(process.pid, signal.SIGTERM)
            try:
                out, err = process.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                out, err = process.communicate()
        entry = {"argv": argv, "exit_code": process.returncode, "timed_out": timed_out,
                 "elapsed_seconds": round(time.monotonic() - started, 3)}
        for label, data in (("stdout", out), ("stderr", err)):
            entry[label + "_sha256"] = digest(data)
            entry[label] = data[-2000000:].decode("utf-8", "replace")
            entry[label + "_truncated"] = len(data) > 2000000
        report["commands"].append(entry)
        return entry


def git(checkout, args, report, env, required=True):
    result = command(["git", "-c", "core.hooksPath=/dev/null", "-C", str(checkout), *args],
                     checkout, report, env=env)
    if required and result["exit_code"]:
        raise Blocked("Git 无法提供指定原始对象：" + " ".join(args))
    return result["stdout"].strip() if not result["exit_code"] else None


def required_materials(target, tests):
    if target.startswith(("v02_t03_", "v02_t06_", "v02_t10_", "v02_t11b_", "v02_t14b_", "v02_t15c_")):
        return T03_INPUTS
    if target.startswith(("i06_", "l02_", "m02_", "n01_")):
        return ["deliverables/codex-wiki-reverse"]
    if target == "audit_regression_contract" or (target == "d07_development_acceptance_contract"
            and any(t != "thin_skill_candidate_has_the_exact_progressive_surface_and_only_calls_gtkg" for t in tests)):
        return ["deliverables/goal-team-knowledge-graph/versions/V0.1/PRD.md",
                "deliverables/goal-team-knowledge-graph/versions/V0.1/ARCHITECTURE.md"]
    if target == "h02b_summary_frontmatter_contract":
        # Exact run identity is in the original test. It must already be present
        # in the supplied checkout/material root, never guessed by this script.
        return ["deliverables/g03-organic-eval/accepts"]
    if target == "v02_t15d_local_readiness_contract":
        return ["deliverables/v02-t15d/local-readiness-plan.json"]
    if target == "v03_a05_graphify_adapter_security_successor":
        return ["deliverables/v03-development/test-receipts/a05-upstream-pin.json"]
    if target.startswith("v03_b00_"):
        return ["deliverables/v03-benchmark/" + name + ".json" for name in
                ("corpus-manifest", "benchmark-plan-v3", "query-denominator", "agent-task-denominator", "pins")]
    if target.startswith("v03_b01_"):
        return ["deliverables/v03-benchmark/receipts/b01-environment-preflight-r1.json",
                "deliverables/v03-benchmark/pins.json"]
    return []


def add_material(relative, original, isolated, report, env):
    source, destination = original / relative, isolated / relative
    if destination.exists() and not destination.is_dir():
        return
    if source.is_symlink() or not source.exists():
        raise Blocked("缺少原始冻结材料或路径为符号链接：" + relative)
    # A reference runner is an actual Git checkout pinned by its original manifest.
    if relative == T03_INPUTS[0]:
        manifest = source / "MANIFEST.json"
        if not manifest.is_file() or manifest.is_symlink():
            raise Blocked("缺少原始 runner MANIFEST.json")
        if destination.exists():
            if (destination / ".git").exists():
                return
            raise Blocked("隔离源码已有不完整 runner 目录；需要原提交中完整绑定的 runner checkout")
        raw = manifest.read_bytes()
        pin = json.loads(raw)["commit"]
        if not re.fullmatch(r"[0-9a-f]{40}", pin):
            raise Blocked("runner commit 必须为原始完整 SHA")
        git(source, ["cat-file", "-e", pin + "^{commit}"], report, env)
        destination.parent.mkdir(parents=True, exist_ok=True)
        clone = command(["git", "-c", "core.hooksPath=/dev/null", "clone", "--no-hardlinks",
                         "--no-checkout", "--quiet", "--", str(source), str(destination)],
                        isolated, report, env=env)
        if clone["exit_code"]:
            raise Blocked("无法隔离原始 runner checkout")
        git(destination, ["checkout", "--quiet", "--detach", pin], report, env)
        (destination / "MANIFEST.json").write_bytes(raw)
        report["materials"].append({"path": relative + "/MANIFEST.json", "sha256": digest(raw),
                                    "runner_commit": pin, "origin": "supplied_original_material"})
        return
    files = sorted(source.rglob("*")) if source.is_dir() else [source]
    if len(files) > 20000:
        raise Blocked("材料文件数超过 20000；请提供限定的原件目录")
    total = 0
    for file in files:
        if file.is_symlink():
            raise Blocked("原材料含符号链接：" + str(file.relative_to(original)))
        if file.is_dir():
            continue
        if not file.is_file():
            raise Blocked("原材料不是普通文件")
        total += file.stat().st_size
        if total > 512 * 1024 * 1024:
            raise Blocked("材料超过 512 MiB；请提供限定的原件目录")
        raw = file.read_bytes()
        rel = file.relative_to(original)
        target = isolated / rel
        if target.exists():
            if target.is_symlink() or not target.is_file() or target.read_bytes() != raw:
                raise Blocked("提供材料与指定 Git 提交的既存字节冲突：" + str(rel))
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as output:
            output.write(raw)
        report["materials"].append({"path": str(rel), "sha256": digest(raw), "bytes": len(raw),
                                    "origin": "supplied_original_material_not_git_attested"})


def execute(args, report):
    if not re.fullmatch(r"[0-9a-f]{40}", args.commit):
        raise Blocked("必须明确提供完整的 40 位 Git commit，不能使用分支或缩写")
    if not re.fullmatch(r"[a-zA-Z0-9_]+", args.target):
        raise Blocked("target 必须是单个测试 target 名称")
    checkout = Path(args.checkout).resolve(strict=True)
    material_root = Path(args.material_root).resolve(strict=True) if args.material_root else checkout
    rows = []
    report["history_catalogs"] = []
    for path in sorted(CATALOG_DIRECTORY.glob("*-history.json")):
        raw = path.read_bytes()
        rows.extend(row for row in json.loads(raw) if row["class"] == "historical")
        report["history_catalogs"].append({"path": path.name, "sha256": digest(raw)})
    archived = {(r["target"], r["test"]): r for r in rows}
    if len(archived) != len(rows):
        raise Blocked("历史清单含重复 target + test；必须先消除重复归类")
    selected = args.test or [r["test"] for r in rows if r["target"] == args.target]
    if not selected or len(set(selected)) != len(selected):
        raise Blocked("指定 --test 精确原始函数名；非历史 target 不自动扩大为整 target")
    if any(not re.fullmatch(r"[A-Za-z0-9_:]+", name) for name in selected):
        raise Blocked("test 必须是完整函数名")
    report["selected_tests"] = selected
    report["archive_entries"] = [archived[(args.target, name)] for name in selected
                                 if (args.target, name) in archived]
    env = {key: os.environ[key] for key in ("PATH", "HOME", "CARGO_HOME", "RUSTUP_HOME", "SDKROOT",
           "MACOSX_DEPLOYMENT_TARGET", "TMPDIR", "LANG") if key in os.environ}
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull, CARGO_NET_OFFLINE="true")
    git(checkout, ["cat-file", "-e", args.commit + "^{commit}"], report, env)
    report["source_tree"] = git(checkout, ["rev-parse", args.commit + "^{tree}"], report, env)
    test_path = "crates/gtkg-testkit/tests/" + args.target + ".rs"
    original_test = git(checkout, ["show", args.commit + ":" + test_path], report, env)
    # Mixed tests were split in current source, without rewriting old Git objects.
    # An old source tree must use its original function, including its full oracle.
    original_names = {
        "audit_regression_contract": (
            "original_v01_design_documents_conform_to_okf",
            "bundle_verify_checks_every_canonical_okf_resource_and_manifest_digest_closure"),
        "v03_p05_domain_handlers_contract": (
            "p05_historical_stage_keeps_28_handlers_and_analysis_unimplemented",
            "p05_promotes_exactly_18_domain_handlers_with_closed_payload_schemas"),
    }
    if args.target in original_names:
        new, old = original_names[args.target]
    else:
        new = old = None
    if new and "fn " + new not in original_test:
        if new in selected:
            selected = [old if name == new else name for name in selected]
            report["selected_tests"] = selected
            report["original_name_mapping"] = {new: old}
        elif old in selected and (args.target, new) in archived:
            report["archive_entries"].append(archived[(args.target, new)])
    # Git show output is recorded verbatim by command(); hash the actual blob bytes.
    original_bytes = subprocess.check_output(["git", "-C", str(checkout), "show", args.commit + ":" + test_path], env=env)
    report["original_test"] = {"path": test_path, "sha256": digest(original_bytes)}
    source_sync = git(checkout, ["show", args.commit + ":SOURCE_SYNC.md"], report, env, required=False)
    snapshot = args.commit == PUBLIC_SNAPSHOT or bool(source_sync and INTERNAL_SOURCE in source_sync)
    report["source_kind"] = "public_source_snapshot" if snapshot else "user_selected_original_git_commit"
    report["boundary"] = ("Only the selected original tests at this exact Git commit; no reconstruction "
                          "of an earlier release, unpublished oracle, prior execution or acceptance.")
    cargo_toml = git(checkout, ["show", args.commit + ":Cargo.toml"], report, env)
    version = re.search(r'(?ms)^\[workspace\.package\]\s*.*?^version\s*=\s*"([^"]+)"', cargo_toml)
    report["workspace_version"] = version[1] if version else "not_declared"
    # Prerequisites follow exact archived cases, never every function in a target.
    required = required_materials(args.target, selected) if report["archive_entries"] else []
    report["required_materials"] = required
    report["missing_materials"] = [relative for relative in required
                                   if not (material_root / relative).exists()]
    if snapshot and report["archive_entries"]:
        raise Blocked("该提交是公开 source snapshot，不是归档用例原阶段源码；需要原始 Git 历史与冻结原件")
    with tempfile.TemporaryDirectory(prefix="gtkg-history-") as temporary:
        isolated = Path(temporary) / "source"
        clone = command(["git", "-c", "core.hooksPath=/dev/null", "clone", "--no-hardlinks",
                         "--no-checkout", "--quiet", "--", str(checkout), str(isolated)],
                        checkout, report, env=env)
        if clone["exit_code"]:
            raise Blocked("无法创建隔离 Git checkout")
        git(isolated, ["checkout", "--quiet", "--detach", args.commit], report, env)
        report["isolated_head"] = git(isolated, ["rev-parse", "HEAD"], report, env)
        if report["isolated_head"] != args.commit or (isolated / test_path).read_bytes() != original_bytes:
            raise Blocked("隔离源码与指定原始提交不一致")
        for relative in required:
            add_material(relative, material_root, isolated, report, env)
        env["CARGO_TARGET_DIR"] = str(Path(temporary) / "target")
        env["CARGO_BUILD_JOBS"] = "2"
        for tool in ("cargo", "rustc"):
            version = command([tool, "--version"], isolated, report, env=env)
            if version["exit_code"]:
                raise Blocked("缺少可用的 " + tool)
        base = ["cargo", "test", "--locked", "--offline", "-p", "gtkg-testkit", "--test", args.target]
        discovery = command(base + ["--", "--list"], isolated, report, args.timeout, env)
        if discovery["exit_code"] or discovery["timed_out"]:
            raise Blocked("原始 target 无法编译/枚举；查看原始日志，可能缺依赖或工具链")
        available = set(re.findall(r"^(.+): test$", discovery["stdout"], re.M))
        if not set(selected) <= available:
            raise Blocked("所选函数不存在于原始测试列表：" + ", ".join(sorted(set(selected) - available)))
        failed = False
        blocked = False
        for name in selected:
            run = command(base + [name, "--", "--exact", "--nocapture"], isolated, report, args.timeout, env)
            passed = not run["exit_code"] and not run["timed_out"] and "1 passed; 0 failed; 0 ignored" in run["stdout"]
            missing = not passed and bool(re.search(r"No such file or directory|kind: NotFound|T03 binding: T03BindingInvalid",
                                                   run["stdout"] + run["stderr"]))
            report["results"].append({"target": args.target, "test": name,
                                      "status": "passed" if passed else "blocked" if missing else "failed",
                                      "command_index": len(report["commands"]) - 1})
            failed |= not passed
            blocked |= missing
        report["status"] = "blocked" if blocked else "failed" if failed else "passed"
        return 2 if blocked else 1 if failed else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--checkout", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--test", action="append")
    parser.add_argument("--material-root")
    parser.add_argument("--report", required=True, help="new JSON path; existing files are never overwritten")
    parser.add_argument("--timeout", type=int, default=900, help="per command seconds, 1..3600")
    args = parser.parse_args()
    report_path = Path(args.report).absolute()
    log_path = report_path.with_suffix(".cargo.log")
    if report_path.exists() or report_path.is_symlink() or log_path.exists() or log_path.is_symlink() or not 1 <= args.timeout <= 3600:
        parser.error("report and sibling .cargo.log must be new paths and timeout must be 1..3600")
    report = {"schema_version": "gtkg.history-validation/v1", "requested_commit": args.commit,
              "target": args.target, "observed_at_epoch": time.time(), "status": "blocked",
              "runner_sha256": digest(Path(__file__).read_bytes()),
              "commands": [], "materials": [], "results": [],
              "isolation": "temporary local Git clone; original checkout not modified; cargo locked/offline"}
    try:
        code = execute(args, report)
    except (Blocked, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        report["reason"] = str(error)
        code = 2
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report["cargo_log"] = log_path.name
    with log_path.open("x", encoding="utf-8") as output:
        for entry in report["commands"]:
            if entry["argv"][0] not in ("cargo", "rustc"):
                continue
            output.write("$ " + " ".join(entry["argv"]) + "\n")
            output.write(entry["stdout"])
            output.write(entry["stderr"])
            output.write("\nexit_code=" + str(entry["exit_code"]) + "\n\n")
    with report_path.open("x", encoding="utf-8") as output:
        json.dump(report, output, ensure_ascii=False, indent=2)
        output.write("\n")
    print(json.dumps({"status": report["status"], "report": str(report_path), "results": report["results"],
                      "reason": report.get("reason")}, ensure_ascii=False))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
