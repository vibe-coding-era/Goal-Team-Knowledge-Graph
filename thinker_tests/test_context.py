"""Service-level retrieval tests using fresh local control and Git repositories."""

import subprocess
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from pathlib import Path
from unittest.mock import patch
from thinker import client, service
from thinker_tests import test_workflows


class LocalContext(unittest.TestCase):
    def setUp(self):
        self.fixture = test_workflows.Handoff()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

    def test_withdrawal_can_commit_during_model_reflection(self):
        f = self.fixture
        ver, _ = f.register("reflect")
        evidence = f.req("evidence.capture", **ver, path="contract.txt")
        f.req("memory.retain", id="incident", kind="experience", evidence_ids=[evidence["id"]],
              consent=True, data_class="internal")
        f.req("memory.project")
        f.daemon.terminate()
        f.daemon.wait(5)
        (f.home / "thinker.sock").unlink(missing_ok=True)
        entered = threading.Event()
        release = threading.Event()

        def slow_model(query):
            entered.set()
            release.wait(5)
            return "Answer based on withdrawn source"

        with service.Server(str(f.home / "thinker.sock"), service.Handler) as server:
            server.home, server.master = f.home, service.token_digest(f.key)
            serving = threading.Thread(target=server.serve_forever, daemon=True)
            serving.start()
            try:
                with patch("thinker.memory.LocalBackend.reflect", side_effect=slow_model), ThreadPoolExecutor(2) as pool:
                    reflection = pool.submit(f.req, "memory.reflect", query="incident")
                    try:
                        self.assertTrue(entered.wait(3))
                        revoke = pool.submit(f.req, "evidence.revoke", id=evidence["id"], reason="withdrawn")
                        try:
                            revoke.result(timeout=2)
                        except FutureTimeout:
                            self.fail("slow reflection blocked evidence withdrawal")
                    finally:
                        release.set()
                    self.assertTrue(reflection.result(timeout=3)["partial"])
                    self.assertEqual(f.req("memory.candidates")["candidates"], [])
            finally:
                server.shutdown()
                serving.join(5)

    def test_sensitive_source_is_quarantined_before_context(self):
        f = self.fixture
        ver, git = f.register("sensitive")
        (f.root / "sensitive" / "contract.txt").write_text(
            "api_key=fixture_only_value\n"
        )
        git("commit", "-qam", "synthetic secret detector fixture")
        f.req("watch.reconcile", repo="sensitive")
        ver["source_revision"] = git("rev-parse", "HEAD")
        result = f.view(dict(ver, query="fixture_only_value"))
        self.assertFalse(result["evidence_refs"])
        self.assertIn("quarantined_source", result["partial_sources"])
        with self.assertRaises(ValueError):
            f.req("evidence.capture", **ver, path="contract.txt")

    def test_context_recalls_scoped_experience_without_published_judgment(self):
        f = self.fixture
        ver, _ = f.register("A")
        other, _ = f.register("B")
        receipt = f.req(
            "decision.record", **ver, id="trial", text="Prior trial used offline mode"
        )
        f.req(
            "memory.retain",
            id="experience",
            kind="experience",
            evidence_ids=[receipt["id"]],
            consent=True,
            data_class="internal",
        )
        f.req("memory.project")
        context = f.view(dict(ver, query="offline"))
        self.assertFalse(context["active_judgments"])
        self.assertEqual(["experience"], [m["id"] for m in context["memories"]])
        self.assertFalse(context["memories"][0]["authoritative"])
        self.assertIn(receipt["id"], [e["id"] for e in context["evidence_refs"]])
        self.assertFalse(f.view(dict(other, query="offline"))["memories"])
        f.req("evidence.revoke", id="trial", reason="access withdrawn")
        self.assertFalse(f.view(dict(ver, query="offline"))["memories"])

    def test_revoked_source_not_returned_by_query_or_manual_read(self):
        f = self.fixture
        ver, _ = f.register("sample")
        record = f.req("evidence.capture", **ver, path="contract.txt")
        f.req("evidence.revoke", id=record["id"], reason="access withdrawn")
        self.assertEqual(
            [], f.req("source.read", **ver, path="contract.txt")["evidence"]
        )
        self.assertEqual([], f.view(dict(ver, query="imports"))["evidence_refs"])


class ReadValidation(unittest.TestCase):
    def test_continuous_poll_metadata_does_not_starve_readers(self):
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp)
            service.initialize(home)
            token = (home / "operator.key").read_text().strip()
            scope = service.scoped({"project": "p"})
            db = service.connect(home)
            db.execute(
                "INSERT INTO tk_repos(scope,repo,location,common_dir,config,config_revision,enabled,removed,health) VALUES(?,?,?,?,?,?,?,?,?)",
                (scope, "repo", "unused", "unused", "{}", 1, 1, 0, "healthy"),
            )
            db.close()
            with service.Server(str(home / "thinker.sock"), service.Handler) as server:
                server.home, server.master = home, service.token_digest(token)
                worker = threading.Thread(target=server.serve_forever, daemon=True)
                worker.start()
                original = service.dispatch
                writes = []

                def concurrent_poll(connection, master, req):
                    result = original(connection, master, req)
                    # Commit a real independent write while the read snapshot is
                    # open. This happens on EVERY attempt, not a timing sleep.
                    other = service.connect(home)
                    try:
                        other.execute(
                            "UPDATE tk_repos SET polls=polls+1,last_polled=last_polled+1 WHERE scope=?",
                            (scope,),
                        )
                        writes.append(True)
                    finally:
                        other.close()
                    return result

                try:
                    with patch("thinker.service.dispatch", side_effect=concurrent_poll):
                        result = client.call(home, token, "status", {"project": "p"})
                    self.assertEqual(result["status"], "ok")
                    self.assertEqual(len(writes), 1)
                finally:
                    server.shutdown()
                    worker.join(3)
