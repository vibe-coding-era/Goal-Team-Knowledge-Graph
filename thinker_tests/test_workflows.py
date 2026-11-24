"""Exercise the installed transport across fresh executor processes and local Git changes."""

import hashlib
import json
import os
import statistics
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

from thinker.client import call
from thinker.service import initialize


class Handoff(unittest.TestCase):
    def test_noninteractive_tui_reports_disconnect(self):
        self.daemon.terminate()
        self.daemon.wait(5)
        result = subprocess.run(
            self.command + ["tui", "--project", "alpha"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
        )
        self.assertNotEqual(result.returncode, 0)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.home = self.root / "control"
        initialize(self.home)
        self.key = (self.home / "operator.key").read_text().strip()
        self.command = [sys.executable, "-m", "thinker", "--home", str(self.home)]
        self.daemon = subprocess.Popen(self.command + ["serve", "--interval", "0.15"])
        self.addCleanup(self.daemon.wait, 5)
        self.addCleanup(self.daemon.terminate)
        for _ in range(100):
            if (self.home / "thinker.sock").is_socket():
                break
            time.sleep(0.03)
        self.ref = "refs/heads/main"

    def repo(self, name):
        path = self.root / name
        path.mkdir()

        def git(*args):
            env = dict(
                os.environ,
                GIT_AUTHOR_DATE="2026-01-01T00:00:00Z",
                GIT_COMMITTER_DATE="2026-01-01T00:00:00Z",
            )
            return subprocess.check_output(
                ["git", "-C", str(path), *args], text=True, env=env
            ).strip()

        git("init", "-qb", "main")
        git("config", "user.name", "Thinker fixture")
        git("config", "user.email", "fixture@example.invalid")
        (path / "contract.txt").write_text("B imports A\nRun B when A changes\n")
        git("add", "contract.txt")
        git("commit", "-qm", "Pin the dependency")
        return path, git

    def register(self, name, project="alpha"):
        path, git = self.repo(name)
        self.req(
            "repos.add",
            project=project,
            repo=name,
            location=str(path),
            refs=[self.ref],
            paths=["contract.txt"],
            poll_interval=1,
        )
        return {
            "repo": name,
            "ref": self.ref,
            "source_revision": git("rev-parse", "HEAD"),
        }, git

    def req(self, op, project="alpha", **fields):
        return call(self.home, self.key, op, dict(project=project, **fields))

    def view(self, version, project="alpha"):
        p = subprocess.run(
            self.command
            + ["context", "get", "--project", project, "--args", json.dumps(version)],
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(p.returncode, 0, p.stderr)
        return json.loads(p.stdout)

    def record(self, ver, name, base=0, claim="Run B when A changes", **extra):
        args = dict(
            ver,
            judgment_id=name,
            base_revision=base,
            claim=claim,
            review_after=time.time() + 3600,
            **extra,
        )
        j = self.req("judgment.propose", **args)
        return self.req(
            "judgment.publish",
            **ver,
            judgment_id=name,
            revision=j["revision"],
            base_revision=base,
        )

    def test_handoff_correction_and_withdrawal(self):
        ver, _ = self.register("checkout")
        ev = self.req("evidence.capture", **ver, path="contract.txt")
        self.assertEqual(
            ev["content_hash"],
            "sha256:"
            + hashlib.sha256(
                (self.root / "checkout" / "contract.txt").read_bytes()
            ).hexdigest(),
        )
        self.record(
            ver, "impact", claim="Changing A alone is sufficient", supports=[ev["id"]]
        )
        self.assertEqual(
            self.view(ver)["active_judgments"][0]["judgment_revision"], "impact@1"
        )
        # Independent local CI oracle checks the exact committed source, not a worktree file.
        actual = subprocess.check_output(
            [
                "git",
                "-C",
                str(self.root / "checkout"),
                "show",
                ver["source_revision"] + ":contract.txt",
            ]
        )
        self.assertIn(b"B imports A", actual)
        ci = self.req(
            "ci.record",
            **ver,
            id="ci-1",
            run_id="fixture-run-1",
            check="dependency B",
            conclusion="success",
            attribution="code",
        )
        self.record(
            ver,
            "impact",
            base=1,
            supports=[ci["id"]],
            contradicts=[ev["id"]],
            reason="The pinned dependency check confirmed B imports A.",
        )
        self.req(
            "recommendation.send",
            **ver,
            id="rec-1",
            judgment_revision="impact@2",
            executor_task_id="case",
            next_action="Run B integration first",
            expected_check="B integration",
            expires_at=time.time() + 1200,
        )
        fresh = self.view(dict(ver, task="case"))
        self.assertEqual(
            [j["judgment_revision"] for j in fresh["active_judgments"]], ["impact@2"]
        )
        self.assertEqual(
            fresh["recommendations"][0]["next_action"], "Run B integration first"
        )
        self.req(
            "evidence.revoke", id=ci["id"], reason="sole supporting CI result withdrawn"
        )
        after = self.view(dict(ver, task="case"))
        self.assertFalse(after["recommendations"])
        self.assertFalse(after["active_judgments"])

    def test_hot_registry_and_cross_project_same_filename(self):
        a, git_a = self.register("repoA")
        b, git_b = self.register("repoB", "beta")
        self.req("repos.pause", repo="repoA")
        (self.root / "repoB" / "contract.txt").write_text("new B-only change\n")
        git_b("commit", "-qam", "fast forward")
        new = git_b("rev-parse", "HEAD")
        for _ in range(140):
            status = self.req("watch.status", project="beta")["repos"][0]
            if status["refs"][0]["observed_oid"] == new:
                break
            time.sleep(0.08)
        self.assertEqual(status["refs"][0]["observed_oid"], new)
        self.assertEqual(
            self.req("watch.status")["repos"][0]["refs"][0]["observed_oid"],
            a["source_revision"],
        )
        self.assertNotIn("repoB", str(self.req("watch.status")))
        self.req("repos.remove", repo="repoB", project="beta")
        self.assertTrue((self.root / "repoB" / ".git").is_dir())
        with self.assertRaises(ValueError):
            self.req(
                "source.read",
                project="beta",
                repo="repoB",
                ref=self.ref,
                path="contract.txt",
            )

    def test_evaluation(self):
        # Golden cases are explicit so that a missing check cannot inflate the score.
        mode = os.environ.get("THINKER_EVAL", "agent")
        ver, _ = self.register("repo")
        evidence = self.req("evidence.capture", **ver, path="contract.txt")
        query = dict(ver, task="handoff")
        verified = []

        def check(name, condition):
            self.assertTrue(condition, name)
            verified.append(name)

        baseline = self.view(query)
        check(
            "source provenance", evidence["source_revision"] == ver["source_revision"]
        )
        check("unpublished context", not baseline["active_judgments"])
        if mode == "baseline":
            rows = self.req("source.search", **ver, query="B imports A")["evidence"]
            self.assertTrue(any(e["locator"]["path"] == "contract.txt" for e in rows))
            print(
                json.dumps(
                    {"mode": mode, "checks": verified, "retrieved_task_decisions": 0}
                )
            )
            return
        self.record(ver, "decision", supports=[evidence["id"]])
        ctx = self.view(query)
        check(
            "handoff after publish",
            ctx["active_judgments"][0]["judgment_revision"] == "decision@1",
        )
        check("task before recommendation", not ctx["recommendations"])
        self.req(
            "recommendation.send",
            **ver,
            id="rec",
            judgment_revision="decision@1",
            executor_task_id="handoff",
            next_action="Run B",
            expected_check="B integration",
            expires_at=time.time() + 1200,
        )
        check(
            "correct next action",
            self.view(query)["recommendations"][0]["next_action"] == "Run B",
        )
        check(
            "unrelated task", not self.view(dict(ver, task="other"))["recommendations"]
        )
        self.record(
            ver, "decision", base=1, claim="Also check C", supports=[evidence["id"]]
        )
        check("obsolete action", not self.view(query)["recommendations"])
        check(
            "new judgment only",
            [j["judgment_revision"] for j in self.view(query)["active_judgments"]]
            == ["decision@2"],
        )
        self.req("evidence.revoke", id=evidence["id"], reason="withdrawn")
        check("no withdrawn judgment", not self.view(query)["active_judgments"])
        check(
            "redacted explanation",
            "Also check C"
            not in str(self.req("judgment.explain", judgment_id="decision")),
        )
        print(
            json.dumps(
                {"mode": mode, "checks": verified, "retrieved_task_decisions": 1}
            )
        )

    def test_paired_handoffs(self):
        """Same ten requests, oracle, source revision and task ids in each access mode."""
        mode = os.environ.get("THINKER_EVAL", "agent")
        ver, _ = self.register("handoff")
        source = self.req("evidence.capture", **ver, path="contract.txt")
        self.record(ver, "impact", supports=[source["id"]])
        tasks = [
            "api",
            "cli",
            "desktop",
            "worker",
            "release",
            "index",
            "restore",
            "archive",
            "replay",
            "notify",
        ]
        expected = {name: "Verify B integration for " + name for name in tasks}
        for name in tasks:
            self.req(
                "recommendation.send",
                **ver,
                id="rec-" + name,
                judgment_revision="impact@1",
                category=name,
                executor_task_id=name,
                next_action=expected[name],
                expected_check="B integration",
                expires_at=time.time() + 120,
            )
        self.req(
            "memory.retain",
            id="observation",
            kind="observation",
            judgment_revision="impact@1",
            evidence_ids=[source["id"]],
            data_class="internal",
            consent=True,
        )
        self.req("memory.project")
        samples = []
        for name in tasks:
            start = time.monotonic()
            if mode == "baseline":
                answer = self.req("source.search", **ver, query="B imports A")
                self.assertIn("B imports A", answer["evidence"][0]["text"])
            else:
                answer = self.view(dict(ver, task=name))
            actions = [r["next_action"] for r in answer.get("recommendations", [])]
            samples.append(
                {
                    "task": name,
                    "expected": expected[name],
                    "observed": actions,
                    "elapsed_ms": round((time.monotonic() - start) * 1000, 1),
                }
            )
            if mode != "baseline":
                self.assertEqual([expected[name]], actions)
                self.assertEqual([m["id"] for m in answer["memories"]], ["observation"])
        correct = sum(row["observed"] == [row["expected"]] for row in samples)
        print(
            json.dumps(
                {
                    "mode": mode,
                    "oracle": "exact recorded task action",
                    "revision": ver["source_revision"],
                    "cases": samples,
                    "correct": correct,
                    "total": len(tasks),
                    "median_ms": statistics.median(
                        row["elapsed_ms"] for row in samples
                    ),
                }
            )
        )
        self.assertEqual(correct, 0 if mode == "baseline" else len(tasks))
