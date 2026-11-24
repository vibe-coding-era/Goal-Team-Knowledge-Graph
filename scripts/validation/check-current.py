#!/usr/bin/env python3
"""Evaluate current Rust tests without changing Cargo's native test selection.

The wrapper owns execution and supplies gtkg.current-run/v1 metadata. This
program never executes Cargo, runners, source fixtures, or historical tests.
Exit 0: the bound current gate passed; 1: current failures/unproven runners;
2: incomplete, ambiguous, malformed, or differently bound evidence;
3: diagnostic-only --inspect output (not a bound gate verdict).

Targets: integration-file stem; unit::<executable-stem>; doc::<crate-name>.
Classification files are JSON arrays of exact target/test/class/stage/reason/
successor objects. Their digest is SHA256 of sorted basename + NUL + raw-file
SHA256 hex + LF records, encoded as UTF-8. No wildcard classifications exist.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shlex
import sys

CARGO_COMMAND = ["cargo", "test", "--workspace", "--locked", "--no-fail-fast"]
MAX_LOG_BYTES = 256 * 1024 * 1024
HEADER = re.compile(r"^\s*Running (.+?) \(([^\n]+)\)\s*$|^\s*Doc-tests (\S+)\s*$", re.M)
START = re.compile(r"^running (\d+) tests?\s*$", re.M)
SUMMARY = re.compile(
    r"^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; "
    r"(\d+) measured; (\d+) filtered out; finished in ([^\n]+)\s*$", re.M)
CASE = re.compile(r"(?<!\S)test (?!result:)([^\n]*?) \.\.\.")
EXACT_CASE = re.compile(r"^test (?!result:)(.+?) \.\.\. (ok|FAILED|ignored)(?:, [^\n]*)?\s*$", re.M)
FOOTER = re.compile(r"^error: (\d+) targets? failed:\s*$", re.M)
RERUN = re.compile(r"^error: (?:test|doctest) failed, to rerun pass `([^`]+)`\s*$", re.M)
HEX = re.compile(r"^[0-9a-f]{64}$")


class EvidenceError(ValueError):
    pass


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def digest(value):
    if not isinstance(value, str):
        raise EvidenceError("digest must be a SHA256 string")
    value = value.removeprefix("sha256:")
    if not HEX.fullmatch(value):
        raise EvidenceError("invalid SHA256 digest")
    return value


def unique_object(items):
    result = {}
    for key, value in items:
        if key in result:
            raise EvidenceError("duplicate JSON key: " + key)
        result[key] = value
    return result


def read_bytes(path):
    path = Path(path)
    if not path.is_file() or path.stat().st_size > MAX_LOG_BYTES:
        raise EvidenceError("missing, non-file, or oversized evidence: " + str(path))
    return path.read_bytes()


def read_json(path):
    return json.loads(read_bytes(path), object_pairs_hook=unique_object)


def classification_files(directory):
    directory = Path(directory)
    if not directory.is_dir():
        raise EvidenceError("classification directory is missing")
    files = sorted(directory.glob("*-history.json"), key=lambda p: p.name)
    if any(p.is_symlink() or not p.is_file() for p in files):
        raise EvidenceError("classification entries must be regular files")
    return files


def classification_snapshot(directory):
    return [(path.name, read_bytes(path)) for path in classification_files(directory)]


def classification_digest(directory, snapshot=None):
    value = hashlib.sha256()
    for name, raw in classification_snapshot(directory) if snapshot is None else snapshot:
        value.update((name + "\0" + sha256(raw) + "\n").encode("utf-8"))
    return value.hexdigest()


def load_classifications(directory, snapshot=None):
    result = {}
    fields = {"target", "test", "class", "stage", "reason", "successor"}
    for name, raw in classification_snapshot(directory) if snapshot is None else snapshot:
        rows = json.loads(raw, object_pairs_hook=unique_object)
        if not isinstance(rows, list):
            raise EvidenceError(name + " must contain a JSON array")
        for row in rows:
            if not isinstance(row, dict) or set(row) != fields:
                raise EvidenceError(name + ": unrecognized classification fields")
            if any(not isinstance(v, str) or not v.strip() for v in row.values()):
                raise EvidenceError(name + ": classification fields must be nonempty strings")
            if row["class"] not in ("historical", "runner"):
                raise EvidenceError(name + ": unknown classification class")
            key = (row["target"], row["test"])
            if any(c in key[0] + key[1] for c in "\n\r\0*") or key in result:
                raise EvidenceError(name + ": duplicate or non-exact classification")
            result[key] = dict(row, classification_file=name)
    return result


def case_name(name):
    return name.removesuffix(" - should panic").strip()


def header_target(match):
    if match.group(3):
        return "doc::" + match.group(3)
    label, executable = match.group(1), match.group(2)
    if label.startswith("unittests "):
        stem = Path(executable).name.removesuffix(".exe")
        stem = re.sub(r"-[0-9a-f]+$", "", stem)
        return "unit::" + stem
    if re.fullmatch(r"(?:[^\s]+/)?tests/[^\s]+\.rs", label) or label.startswith("tests/") and label.endswith(".rs"):
        return Path(label).stem
    raise EvidenceError("unrecognized Cargo target header: " + label)


def selector_target(selector):
    words = shlex.split(selector)
    if len(words) not in (3, 4) or words[0] not in ("-p", "--package") or (
        len(words) == 3 and words[2] not in ("--lib", "--doc")
    ) or (len(words) == 4 and words[2] not in ("--test", "--bin")):
        raise EvidenceError("unrecognized Cargo failure selector: " + selector)
    def option(flag):
        return words[words.index(flag) + 1] if flag in words else None
    package = option("-p") or option("--package")
    if option("--test"):
        return option("--test")
    if option("--bin"):
        return "unit::" + option("--bin")
    if "--lib" in words and package:
        return "unit::" + package.replace("-", "_")
    if "--doc" in words and package:
        return "doc::" + package.replace("-", "_")
    raise EvidenceError("unrecognized Cargo failure selector: " + selector)


def parse_suite(target, body, full_workspace):
    errors, notes = [], []
    starts, summaries = list(START.finditer(body)), list(SUMMARY.finditer(body))
    result = {"target": target, "cases": {}, "errors": errors, "notes": notes}
    if not starts or not summaries:
        errors.append("missing running/result tail")
        return result
    outer = summaries[-1]
    if outer.start() < starts[0].end():
        errors.append("result precedes suite start")
    labels = ("passed", "failed", "ignored", "measured", "filtered_out")
    counts = dict(zip(labels, (int(outer.group(i)) for i in range(2, 7))))
    result["summary"] = counts
    if int(starts[0].group(1)) != sum(counts[k] for k in labels[:4]):
        errors.append("outer running/result count mismatch")
    if (outer.group(1) == "FAILED") != bool(counts["failed"]):
        errors.append("result status contradicts failed count")
    if counts["measured"] or full_workspace and counts["filtered_out"]:
        errors.append("unexpected measured or filtered cases in full workspace run")
    if any(s.start() > outer.start() for s in starts):
        errors.append("unfinished suite after last result")
    # The final complete libtest summary belongs to the outer target. Child
    # summaries are never added to its counts, even when output is interleaved.
    pre = body[starts[0].end():outer.start()]
    nested = len(starts) > 1
    case_matches = list(CASE.finditer(pre))
    names = {case_name(m.group(1)) for m in case_matches}
    exact = {}
    for match in EXACT_CASE.finditer(pre):
        name = case_name(match.group(1))
        # A line containing another harness prefix has character-level mixing.
        if "test " not in name and " ... " not in name:
            exact.setdefault(name, set()).add(match.group(2))
    # --nocapture runners may print a receipt between the harness prefix and
    # its standalone result. Only one unambiguous pending case can own it.
    nocapture = set()
    for index, match in enumerate(case_matches):
        end = case_matches[index + 1].start() if index + 1 < len(case_matches) else len(pre)
        interval = pre[match.end():end]
        statuses = re.findall(r"^(ok|FAILED|ignored)\s*$", interval, re.M)
        if len(statuses) == 1 and not START.search(interval) and not SUMMARY.search(interval):
            name = case_name(match.group(1))
            exact.setdefault(name, set()).add(statuses[0])
            nocapture.add(name)
    failed = []
    if counts["failed"]:
        lists = []
        for mark in re.finditer(r"^failures:\s*$", pre, re.M):
            values = []
            for line in pre[mark.end():].splitlines():
                if not line.strip():
                    if values:
                        break
                    continue
                if not line.startswith("    "):
                    break
                values.append(line.strip())
            if values:
                lists.append(values)
        failed = lists[-1] if lists else []
        if len(set(failed)) != counts["failed"] or len(failed) != len(set(failed)):
            errors.append("outer failure list missing, duplicate, or count mismatch")
        names.update(failed)
    ignored = {name for name, values in exact.items() if values == {"ignored"}}
    if len(ignored) != counts["ignored"]:
        errors.append("ignored case identities do not match outer count")
    if len(names) > int(starts[0].group(1)):
        errors.append("ambiguous nested case identities exceed outer case count")
    if not nested and len(names) != int(starts[0].group(1)):
        errors.append("missing exact case identities")
    for match in case_matches:
        tail = pre[match.end():].split("\n", 1)[0].strip()
        if case_name(match.group(1)) not in nocapture and not re.match(r"^(ok|FAILED|ignored)(?:$|,|\s)", tail):
            if not nested or tail and not (tail.startswith("test ") or re.fullmatch(r"(?:ok)+", tail)):
                errors.append("unrecognized case result: " + case_name(match.group(1)))
    for name in sorted(names):
        status = "failed" if name in failed else "ignored" if name in ignored else "passed"
        if not nested and status == "passed" and exact.get(name) != {"ok"}:
            errors.append("missing explicit case success: " + name)
        result["cases"][name] = {"status": status, "exact_pass": status == "passed" and exact.get(name) == {"ok"}}
    named_passed = sum(v["status"] == "passed" for v in result["cases"].values())
    if named_passed > counts["passed"]:
        errors.append("case statuses contradict outer counts")
    result["unresolved_passed_cases"] = max(0, counts["passed"] - named_passed)
    if nested:
        notes.append("nested child output excluded from outer counts")
    # Cargo diagnostics may follow this result, but no more case output may.
    tail = body[outer.end():]
    if CASE.search(tail) or START.search(tail):
        errors.append("case output after outer result")
    result["tail"] = tail
    return result


def parse_log(text, exit_code, runner_target=None, require_footer=True):
    errors, targets = [], []
    result = {"targets": targets, "errors": errors, "exit_code": exit_code, "failed_targets": []}
    if type(exit_code) is not int or exit_code not in (0, 101):
        errors.append("Cargo interrupted or non-test exit status")
    headers = list(HEADER.finditer(text))
    if not headers and runner_target:
        targets.append(parse_suite(runner_target, text, False))
    elif not headers:
        errors.append("no outer Cargo targets")
    else:
        for index, header in enumerate(headers):
            try:
                target = header_target(header)
            except EvidenceError as error:
                errors.append(str(error))
                continue
            end = headers[index + 1].start() if index + 1 < len(headers) else len(text)
            targets.append(parse_suite(target, text[header.end():end], require_footer))
    names = [t["target"] for t in targets]
    if len(names) != len(set(names)):
        errors.append("duplicate/ambiguous outer target identity")
    for target in targets:
        errors.extend(target["target"] + ": " + e for e in target["errors"])
    failed = {t["target"] for t in targets if t.get("summary", {}).get("failed", 0)}
    result["failed_targets"] = sorted(failed)
    try:
        reruns = [selector_target(m.group(1)) for m in RERUN.finditer(text)]
        footers = list(FOOTER.finditer(text))
        final = []
        if footers:
            if len(footers) != 1:
                errors.append("multiple Cargo final failure footers")
            after = text[footers[-1].end():]
            for line in after.splitlines():
                if not line.strip() or line.startswith("# exit:"):
                    continue
                match = re.fullmatch(r"\s+`([^`]+)`\s*", line)
                if not match:
                    errors.append("unrecognized entry after Cargo failure footer")
                    continue
                final.append(selector_target(match.group(1)))
            if len(final) != int(footers[-1].group(1)) or len(final) != len(set(final)):
                errors.append("Cargo final failure count mismatch")
        if require_footer:
            if failed and (not footers or set(final) != failed or set(reruns) != failed):
                errors.append("Cargo failed-target set differs from outer target results")
            if not failed and (footers or reruns):
                errors.append("Cargo failure diagnostics without failed outer targets")
        if bool(failed) != (exit_code == 101):
            errors.append("Cargo exit status differs from outer results")
    except (ValueError, IndexError) as error:
        errors.append(str(error))
    for line in text.splitlines():
        stripped = line.lstrip()
        cargo_error = re.match(r"^error(?:\[[^]]+\])?:", line) or re.match(
            r"^error(?:\[[^]]+\])?: (?:could not compile|could not execute|failed to |aborting due)", stripped)
        if cargo_error and not (RERUN.fullmatch(stripped) or FOOTER.fullmatch(stripped)):
            errors.append("unrecognized Cargo error / compilation failure: " + line[:200])
        if stripped.startswith("warning: build failed"):
            errors.append("Cargo reported a build failure")
        if re.match(r"^\s*(?:Running|Doc-tests)\s", line) and not HEADER.fullmatch(line):
            errors.append("unrecognized outer target header")
    if targets and not failed:
        tail = targets[-1].get("tail", "")
        if any(line.strip() and not line.startswith("# exit:") for line in tail.splitlines()):
            errors.append("unrecognized output after final successful result")
    for target in targets:
        target.pop("tail", None)
    result["outer_counts"] = {key: sum(t.get("summary", {}).get(key, 0) for t in targets)
                              for key in ("passed", "failed", "ignored", "measured", "filtered_out")}
    return result


def bound_file(directory, relative, expected_digest):
    if not isinstance(relative, str) or not relative or Path(relative).is_absolute() or ".." in Path(relative).parts:
        raise EvidenceError("runner evidence path must be relative and contained")
    root = Path(directory).resolve()
    path = root / relative
    if path.is_symlink() or root not in path.resolve().parents:
        raise EvidenceError("runner evidence path escapes evidence directory")
    data = read_bytes(path)
    if sha256(data) != digest(expected_digest):
        raise EvidenceError("runner log digest mismatch: " + relative)
    return data


def runner_proofs(directory, manifest):
    proofs, errors = {}, []
    if not Path(directory).is_dir():
        return proofs, ["runner evidence directory is missing"]
    for path in sorted(Path(directory).glob("*.runner.json")):
        try:
            if path.is_symlink():
                raise EvidenceError("runner metadata cannot be a symlink")
            meta = read_json(path)
            if not isinstance(meta, dict) or meta.get("schema_version") != "gtkg.current-runner/v1":
                raise EvidenceError("unknown runner metadata schema")
            if meta.get("run_id") != manifest["run_id"]:
                raise EvidenceError("runner belongs to a different run")
            if digest(meta["source_digest"]) != digest(manifest["source_digest_before"]) or digest(meta["input_digest"]) != digest(manifest["input_digest_before"]):
                raise EvidenceError("runner source/input binding mismatch")
            if type(meta.get("exit_code")) is not int or meta["exit_code"] != 0:
                raise EvidenceError("runner did not complete successfully")
            if not isinstance(meta.get("command"), list) or not meta["command"] or not all(isinstance(x, str) and x for x in meta["command"]):
                raise EvidenceError("runner command missing")
            bound_file(directory, meta["stdout_log"], meta["stdout_log_sha256"])
            raw = bound_file(directory, meta["log"], meta["log_sha256"]).decode("utf-8")
            rows = meta["cases"]
            if not isinstance(rows, list) or not rows:
                raise EvidenceError("runner cases missing")
            keys = []
            for row in rows:
                if not isinstance(row, dict) or set(row) != {"target", "test"} or not all(isinstance(v, str) and v for v in row.values()):
                    raise EvidenceError("unrecognized runner case entry")
                keys.append((row["target"], row["test"]))
            if len(keys) != len(set(keys)):
                raise EvidenceError("duplicate runner case declaration")
            target_names = {key[0] for key in keys}
            single = next(iter(target_names)) if len(target_names) == 1 else None
            parsed = parse_log(raw, 0, runner_target=single, require_footer=False)
            if parsed["errors"]:
                raise EvidenceError("runner test log invalid: " + "; ".join(parsed["errors"]))
            observed = {(t["target"], n): c for t in parsed["targets"] for n, c in t["cases"].items()}
            for key in keys:
                case = observed.get(key, {})
                if not case.get("exact_pass") or case.get("status") != "passed":
                    raise EvidenceError("runner exact-case success not observed: " + repr(key))
                if key in proofs:
                    raise EvidenceError("multiple runner proofs for one exact case")
                proofs[key] = {"metadata": path.name, "log": meta["log"], "log_sha256": digest(meta["log_sha256"])}
        except (ValueError, OSError, KeyError, TypeError, UnicodeError) as error:
            errors.append(path.name + ": " + str(error))
    return proofs, errors


def evaluate(log_path, classification_dir, evidence_dir, manifest_path):
    result = {"schema_version": "gtkg.current-gate-result/v1", "status": "invalid", "errors": [], "current_failures": [], "historical": [], "runner_cases": []}
    errors = result["errors"]
    try:
        raw = read_bytes(log_path)
        snapshot = classification_snapshot(classification_dir)
        classes = load_classifications(classification_dir, snapshot)
        class_digest = classification_digest(classification_dir, snapshot)
        manifest = read_json(manifest_path)
        if not isinstance(manifest, dict) or manifest.get("schema_version") != "gtkg.current-run/v1" or not isinstance(manifest.get("run_id"), str) or not manifest["run_id"]:
            raise EvidenceError("invalid current-run manifest")
        if manifest.get("command") != CARGO_COMMAND:
            raise EvidenceError("raw command must be the full default no-fail-fast workspace command")
        if digest(manifest["log_sha256"]) != sha256(raw):
            raise EvidenceError("raw Cargo log digest mismatch")
        for name in ("source_digest", "input_digest"):
            if digest(manifest[name + "_before"]) != digest(manifest[name + "_after"]):
                raise EvidenceError(name + " changed during execution")
        expected = manifest["expected_targets"]
        if not isinstance(expected, list) or not expected or not all(isinstance(t, str) and t.strip() == t and t for t in expected):
            raise EvidenceError("expected_targets must be a nonempty exact Cargo inventory")
        if len(expected) != len(set(expected)):
            raise EvidenceError("duplicate target in Cargo inventory")
        if digest(manifest["inventory_source_digest"]) != digest(manifest["source_digest_before"]):
            raise EvidenceError("Cargo inventory belongs to a different source snapshot")
        if digest(manifest["classification_sha256"]) != class_digest:
            raise EvidenceError("classification manifest digest mismatch")
        result.update(run_id=manifest["run_id"], log_sha256=sha256(raw), classification_sha256=class_digest)
        parsed = parse_log(raw.decode("utf-8"), manifest["exit_code"])
        result["cargo"] = parsed
        errors.extend(parsed["errors"])
        observed_targets = {t["target"] for t in parsed["targets"]}
        missing, unexpected = sorted(set(expected) - observed_targets), sorted(observed_targets - set(expected))
        result["inventory"] = {"expected_count": len(expected), "observed_count": len(parsed["targets"]),
                               "missing_targets": missing, "unexpected_targets": unexpected}
        if missing or unexpected:
            errors.append("Cargo target inventory mismatch: missing=%r unexpected=%r" % (missing, unexpected))
        proofs, proof_errors = runner_proofs(evidence_dir, manifest)
        errors.extend(proof_errors)
        seen, totals = set(), {"passed": 0, "failed": 0, "ignored": 0, "unresolved_passed": 0}
        for target in parsed["targets"]:
            totals["unresolved_passed"] += target.get("unresolved_passed_cases", 0)
            for name, case in target["cases"].items():
                key = (target["target"], name); seen.add(key)
                row = dict(target=key[0], test=key[1], status=case["status"])
                declaration = classes.get(key)
                if declaration and declaration["class"] == "historical":
                    result["historical"].append(dict(declaration, status=case["status"]))
                    continue
                if declaration and declaration["class"] == "runner":
                    verified = case["status"] == "passed" and case["exact_pass"] or key in proofs
                    result["runner_cases"].append(dict(declaration, raw_status=case["status"], verified=verified, proof=proofs.get(key)))
                    if verified:
                        totals["passed"] += 1
                    else:
                        totals["failed"] += 1
                        result["current_failures"].append(dict(row, reason="same-run exact runner success required"))
                else:
                    totals[case["status"]] += 1
                    if case["status"] == "failed":
                        result["current_failures"].append(row)
        for key in sorted(set(classes) - seen):
            errors.append("classification does not identify an observed exact case: " + repr(key))
        result["current_counts"] = totals
        result["status"] = "invalid" if errors else "failed" if result["current_failures"] else "passed"
    except (ValueError, OSError, KeyError, TypeError, UnicodeError) as error:
        errors.append(str(error))
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", type=Path)
    parser.add_argument("--classification-dir", type=Path, default=Path(__file__).parent)
    parser.add_argument("--evidence-dir", type=Path)
    parser.add_argument("--run-manifest", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--classification-digest", action="store_true", help="print only the classification SHA256")
    parser.add_argument("--inspect", action="store_true", help="parse without bindings; never emits a gate passed status")
    parser.add_argument("--exit-code", type=int, help="required for --inspect")
    args = parser.parse_args(argv)
    try:
        if args.classification_digest:
            print(classification_digest(args.classification_dir))
            return 0
        if not args.log:
            parser.error("--log is required")
        if args.inspect:
            if args.exit_code is None:
                parser.error("--inspect requires --exit-code")
            result = parse_log(read_bytes(args.log).decode("utf-8"), args.exit_code)
            result["status"] = "invalid" if result["errors"] else "parsed_unbound"
        else:
            if not args.evidence_dir or not args.run_manifest:
                parser.error("--evidence-dir and --run-manifest are required for a bound gate")
            result = evaluate(args.log, args.classification_dir, args.evidence_dir, args.run_manifest)
    except (ValueError, OSError, UnicodeError) as error:
        result = {"status": "invalid", "errors": [str(error)]}
    encoded = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    return {"passed": 0, "failed": 1, "invalid": 2, "parsed_unbound": 3}[result["status"]]


if __name__ == "__main__":
    sys.exit(main())
