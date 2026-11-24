#!/usr/bin/env python3
"""Restore only T04's eight pinned public files; print fresh provenance as JSON.

Run with Python 3.9+ from any directory. Uses anonymous HTTPS, never credentials
or source execution. Existing different files are rejected, never overwritten.
This restores selected source bytes, not full checkouts or historical receipts.
"""
import base64
import concurrent.futures
from contextlib import contextmanager, ExitStack
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import time
import urllib.parse
import urllib.request


ROOT = Path(__file__).resolve().parents[1]
PREFIX = "docs/reference/v02-external-corpus-candidates/"
MANIFEST = ROOT / "deliverables/v02-t04/frozen-holdout-case-manifest.json"
REGISTRY = ROOT / "deliverables/v02-t04/candidate-external-repositories.json"
PACKET = ROOT / "deliverables/v02-t04/annotation-adjudication-packet.md"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha256(content):
    return "sha256:" + hashlib.sha256(content).hexdigest()


def destination(case):
    relative = case["source_path"]
    prefix = PREFIX + case["candidate_id"] + "/"
    require(relative.startswith(prefix) and ".." not in Path(relative).parts,
            "unexpected source path")
    cursor = ROOT
    for part in Path(relative).parts:
        cursor /= part
        require(not cursor.is_symlink(), "source cache path is a symlink")
    return cursor


def request_json(url):
    request = urllib.request.Request(url, headers={
        "User-Agent": "GTKG-T04-public-source-verification",
        "Accept": "application/vnd.github+json",
    })
    # No credential, proxy, Git configuration, or shell integration.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(request, timeout=40) as response:
        raw = response.read(2 * 1024 * 1024 + 1)
    require(len(raw) <= 2 * 1024 * 1024, "public response exceeds size bound")
    return json.loads(raw)


def inspect(case):
    repo, commit = case["repository"], case["commit"]
    require(re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo), "invalid repository")
    require(re.fullmatch(r"[0-9a-f]{40}", commit), "invalid commit")
    path = case["source_path"][len(PREFIX + case["candidate_id"] + "/"):]
    commit_url = "https://api.github.com/repos/" + repo + "/git/commits/" + commit
    commit_obj = request_json(commit_url)
    require(commit_obj["sha"] == commit and commit_obj["tree"]["sha"] == case["tree"],
            "commit/tree identity mismatch: " + repo)
    content_url = ("https://api.github.com/repos/" + repo + "/contents/"
                   + urllib.parse.quote(path, safe="/") + "?ref=" + commit)
    blob = request_json(content_url)
    require(blob["type"] == "file" and blob["path"] == path and blob["encoding"] == "base64",
            "unexpected public blob response")
    content = base64.b64decode("".join(blob["content"].split()), validate=True)
    blob_oid = hashlib.sha1(b"blob " + str(len(content)).encode() + b"\0" + content).hexdigest()
    require(sha256(content) == case["source_sha256"] and blob_oid == blob["sha"]
            and len(content) == blob["size"], "source bytes identity mismatch: " + repo)
    return case, content, {
        "case_id": case["case_id"], "repository": repo, "commit": commit,
        "tree": commit_obj["tree"]["sha"], "blob": blob_oid, "bytes": len(content),
        "source_path": case["source_path"], "source_sha256": sha256(content),
        "commit_url": commit_url, "content_url": content_url,
        "license_declared_by_existing_registry": case["license"],
    }


@contextmanager
def cache_parent(case):
    """Keep every cache directory open; never publish via a resolved path string."""
    parts = destination(case).relative_to(ROOT).parts
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    with ExitStack() as opened:
        root_fd = os.open(ROOT, flags)
        opened.callback(os.close, root_fd)
        parent_fd = root_fd
        chain = []
        for name in parts[:-1]:
            try:
                os.mkdir(name, dir_fd=parent_fd)
            except FileExistsError:
                pass
            child_fd = os.open(name, flags, dir_fd=parent_fd)
            opened.callback(os.close, child_fd)
            chain.append((parent_fd, name, child_fd))
            parent_fd = child_fd

        def check_identity():
            require(os.path.samestat(os.stat(ROOT, follow_symlinks=False), os.fstat(root_fd)),
                    "repository root identity changed")
            for parent, name, child in chain:
                require(os.path.samestat(os.stat(name, dir_fd=parent, follow_symlinks=False),
                                         os.fstat(child)), "cache directory identity changed")

        check_identity()
        yield parent_fd, parts[-1], check_identity
        check_identity()


def read_existing(parent_fd, name):
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent_fd)
    except FileNotFoundError:
        return None
    with os.fdopen(fd, "rb") as source:
        require(stat.S_ISREG(os.fstat(source.fileno()).st_mode), "existing cache is not a regular file")
        content = source.read(2 * 1024 * 1024 + 1)
        require(len(content) <= 2 * 1024 * 1024, "existing cache exceeds size bound")
        return content


def publish(case, content):
    with cache_parent(case) as (parent_fd, name, check_identity):
        existing = read_existing(parent_fd, name)
        if existing is not None:
            require(existing == content, "existing cache differs; refusing overwrite")
            return "verified_existing"
        temporary = ".t04-restore-" + secrets.token_hex(16)
        check_identity()
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=parent_fd)
        try:
            with os.fdopen(fd, "wb") as output:
                output.write(content)
                output.flush()
                os.fsync(output.fileno())
            check_identity()
            try:
                os.link(temporary, name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd,
                        follow_symlinks=False)
                return "restored_exact_public_bytes"
            except FileExistsError:
                require(read_existing(parent_fd, name) == content,
                        "concurrent cache differs; refusing overwrite")
                return "verified_existing"
        finally:
            os.unlink(temporary, dir_fd=parent_fd)


def main():
    inputs = {path: path.read_bytes() for path in (MANIFEST, REGISTRY, PACKET)}
    manifest, registry = json.loads(inputs[MANIFEST]), json.loads(inputs[REGISTRY])
    binding = manifest["annotation_binding"]
    require(manifest["schema_version"] == "gtkg.external-holdout-case-manifest/v1"
            and manifest["status"] == "candidate_only_not_annotation_locked"
            and manifest["readiness"] == "blocked" and "gold" not in manifest
            and binding["gold_label_state"] == "absent"
            and binding["annotation_state"] == "planned_not_run",
            "unexpected T04 evidence boundary")
    require(binding["packet_path"] == str(PACKET.relative_to(ROOT))
            and binding["packet_sha256"] == sha256(inputs[PACKET]), "packet identity mismatch")
    payload = dict(manifest)
    claimed = payload.pop("manifest_sha256")
    require(claimed == sha256(json.dumps(payload, ensure_ascii=False, sort_keys=True,
                                        separators=(",", ":")).encode()), "manifest identity mismatch")
    candidates = {item["repository"]: item for item in registry["candidates"]}
    trees = {item["candidate"]: item["tree"] for item in registry["materialized_checkouts"]}
    cases = manifest["cases"]
    require(len(cases) == 8 and len({case["source_path"] for case in cases}) == 8,
            "expected exactly eight distinct source files")
    for case in cases:
        require(case["commit"] == candidates[case["repository"]]["commit"]
                and case["license"] == candidates[case["repository"]]["license"]
                and case["tree"] == trees[case["candidate_id"]], "registry identity mismatch")
        path = destination(case)
        if path.exists():
            require(sha256(path.read_bytes()) == case["source_sha256"],
                    "existing cache differs; refusing overwrite")
    # A remote failure writes nothing. A later local failure can be retried:
    # already published files remain exact, and incomplete files are never published.
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        verified = list(pool.map(inspect, cases))
    require(all(path.read_bytes() == raw for path, raw in inputs.items()), "inputs changed during verification")
    observations = []
    for case, content, observation in verified:
        observation["action"] = publish(case, content)
        observations.append(observation)
    require(all(path.read_bytes() == raw for path, raw in inputs.items()), "inputs changed during publication")
    print(json.dumps({
        "schema_version": "gtkg.t04-public-source-restoration-observation/v1",
        "observed_at_epoch": time.time(),
        "manifest_sha256": sha256(inputs[MANIFEST]), "registry_sha256": sha256(inputs[REGISTRY]),
        "verified_files": len(observations), "total_bytes": sum(x["bytes"] for x in observations),
        "files": observations, "manifest_unchanged": True,
        "source_execution": "not_performed", "historical_annotations_or_execution_receipts": "not_created",
        "scope": "Eight selected files only; not full materialized repository checkouts.",
        "annotation_state": "planned_not_run", "gold_label_state": "absent",
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError) as error:
        print("T04 restore failed: " + str(error), file=sys.stderr)
        sys.exit(1)
