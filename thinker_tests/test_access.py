import json
import hashlib
import os
import shutil
from pathlib import Path
import secrets
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from thinker import client, service
from thinker_tests import test_workflows


class ScopedTransport(unittest.TestCase):
    @unittest.skipUnless(
        os.environ.get("THINKER_REAL_GTKG_HANDOFF"), "local GTKG handoff not configured"
    )
    def test_existing_gtkg_index_through_control_socket(self):
        f = test_workflows.Handoff()
        f.setUp()
        self.addCleanup(f.doCleanups)
        path = Path(os.environ["THINKER_REAL_GTKG_HANDOFF"])
        kb = json.loads(path.read_text())
        refs = subprocess.check_output(
            [
                "git",
                "-C",
                kb["source_root"],
                "for-each-ref",
                "--format=%(refname)",
                "--points-at=" + kb["source_commit"],
                "refs/heads",
            ],
            text=True,
        ).splitlines()
        self.assertTrue(refs, "source commit requires an explicitly registrable branch")
        binary = shutil.which("gtkg") or str(Path.home() / ".cargo" / "bin" / "gtkg")
        f.req(
            "repos.add",
            repo="kb",
            location=kb["source_root"],
            refs=[refs[0]],
            adapter={"kind": "gtkg", "handoff": str(path), "binary": binary},
        )
        result = f.view(
            {
                "repo": "kb",
                "ref": refs[0],
                "query": os.environ.get("THINKER_REAL_GTKG_QUERY", "main"),
                "source_revision": kb["source_commit"],
                "budget": 24000,
            }
        )
        self.assertEqual(kb["source_commit"], result["binding"]["indexed_oid"])
        self.assertTrue(result["evidence_refs"])
        for hit in result["evidence_refs"]:
            loc = hit["locator"]
            raw = subprocess.check_output(
                [
                    "git",
                    "-C",
                    kb["source_root"],
                    "show",
                    kb["source_commit"] + ":" + loc["path"],
                ]
            )
            span = raw[loc["byte_start"] : loc["byte_end"]]
            self.assertEqual(
                hit["content_hash"], "sha256:" + hashlib.sha256(span).hexdigest()
            )
            self.assertEqual(hit["text"], span.decode())

    def test_stdio_and_cli_share_authorized_evidence_and_freshness(self):
        f = test_workflows.Handoff()
        f.setUp()
        self.addCleanup(f.doCleanups)
        version, _ = f.register("checkout")
        token = f.home / "reader"
        subprocess.run(
            f.command
            + [
                "access",
                "grant",
                "--project",
                "alpha",
                "--actor",
                "executor",
                "--task",
                "review",
                "--output",
                str(token),
            ],
            check=True,
            capture_output=True,
        )
        args = dict(version, project="alpha", task="review", query="B imports A")
        command = f.command + ["--token-file", str(token)]
        cli = json.loads(
            subprocess.check_output(
                command + ["context", "get", "--args", json.dumps(args)]
            )
        )
        messages = [
            {
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": "2025-11-25"},
            },
            {"method": "notifications/initialized"},
            {
                "id": 2,
                "method": "tools/call",
                "params": {"name": "thinker_get_context", "arguments": args},
            },
        ]
        actual = subprocess.check_output(
            command + ["mcp"],
            text=True,
            timeout=10,
            input="".join(json.dumps(dict(m, jsonrpc="2.0")) + "\n" for m in messages),
        )
        mcp = json.loads(actual.splitlines()[-1])["result"]["structuredContent"]
        self.assertTrue(cli["evidence_refs"])
        self.assertEqual(
            [e["id"] for e in cli["evidence_refs"]],
            [e["id"] for e in mcp["evidence_refs"]],
        )
        self.assertEqual(cli["status"], mcp["status"])
        self.assertEqual(cli["binding"], mcp["binding"])

    def test_grant_is_checked_again_after_slow_read(self):
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp)
            service.initialize(home)
            operator = (home / "operator.key").read_text().strip()
            token = secrets.token_hex(32)
            db = service.connect(home)
            try:
                service.manage_access(
                    db,
                    service.scoped({"project": "p"}),
                    "access.grant",
                    {
                        "token_file_id": "one",
                        "actor": "exec",
                        "role": "reader",
                        "task": "a",
                        "ttl": 15,
                        "digest": service.token_digest(token),
                    },
                )
            finally:
                db.close()
            with service.Server(str(home / "thinker.sock"), service.Handler) as server:
                server.home, server.master = home, service.token_digest(operator)
                worker = threading.Thread(target=server.serve_forever, daemon=True)
                worker.start()
                try:

                    def request(op, **args):
                        return client.call(home, token, op, args)

                    self.assertEqual(request("status")["role"], "reader")
                    with self.assertRaisesRegex(ValueError, "access denied"):
                        request("context.get", task="b", repo="r")
                    wall = [time.time()]
                    dispatch = service.dispatch

                    def slow(db, master, req):
                        value = dispatch(db, master, req)
                        wall[0] += 30
                        return value

                    with (
                        patch("thinker.service.dispatch", side_effect=slow),
                        patch("time.time", side_effect=lambda: wall[0]),
                    ):
                        with self.assertRaisesRegex(ValueError, "access denied"):
                            request("status")
                finally:
                    server.shutdown()
                    worker.join(3)
