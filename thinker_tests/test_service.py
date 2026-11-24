import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest


class Interfaces(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name) / "control"
        self.base = [sys.executable, "-m", "thinker", "--home", str(self.home)]

    def cli(self, *args, check=True):
        p = subprocess.run(
            self.base + list(args), capture_output=True, text=True, timeout=8
        )
        if check:
            self.assertEqual(p.returncode, 0, p.stderr)
        return p

    def start(self):
        daemon = subprocess.Popen(
            self.base + ["serve", "--interval", "0"], stderr=subprocess.PIPE
        )
        self.addCleanup(daemon.stderr.close)
        self.addCleanup(daemon.wait, 5)
        self.addCleanup(daemon.terminate)
        for _ in range(100):
            if (self.home / "thinker.sock").exists():
                return
            if daemon.poll() is not None:
                self.fail(daemon.stderr.read().decode())
            time.sleep(0.03)
        self.fail("control did not listen")

    def test_private_service_and_readonly_executor(self):
        self.cli("init")
        self.start()
        self.assertEqual(
            json.loads(self.cli("status", "--json").stdout)["status"], "ok"
        )
        token = self.home / "executor"
        self.cli(
            "access",
            "grant",
            "--project",
            "alpha",
            "--actor",
            "executor",
            "--task",
            "job",
            "--output",
            str(token),
        )
        self.assertEqual(token.stat().st_mode & 0o777, 0o600)
        self.assertNotEqual(
            self.cli(
                "--token-file",
                str(token),
                "repos",
                "list",
                "--project",
                "other",
                check=False,
            ).returncode,
            0,
        )
        messages = [
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": "2025-11-25"},
            },
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "thinker_record_feedback", "arguments": {}},
            },
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {
                    "name": "thinker_repo_status",
                    "arguments": {"project": "alpha"},
                },
            },
        ]
        p = subprocess.run(
            self.base + ["--token-file", str(token), "mcp"],
            input="".join(json.dumps(m) + "\n" for m in messages),
            text=True,
            capture_output=True,
            timeout=8,
            check=True,
        )
        init, listing, denied, status = map(json.loads, p.stdout.splitlines())
        self.assertEqual(init["result"]["protocolVersion"], "2025-11-25")
        for tool in listing["result"]["tools"]:
            self.assertIs(tool.get("annotations", {}).get("readOnlyHint"), True)
        self.assertEqual(
            {x["name"] for x in listing["result"]["tools"]},
            {"thinker_repo_status", "thinker_get_context", "thinker_explain_judgment"},
        )
        self.assertIn("error", denied)
        self.assertFalse(status["result"].get("isError", False), status)
        self.cli(
            "access", "revoke", "--token-file-id", "executor", "--project", "alpha"
        )
        self.assertNotEqual(
            self.cli(
                "--token-file", str(token), "status", "--project", "alpha", check=False
            ).returncode,
            0,
        )

    def test_queries_leave_daemon_lifecycle_to_operator(self):
        self.cli("init")
        self.assertNotEqual(self.cli("status", check=False).returncode, 0)
        self.assertFalse((self.home / "thinker.sock").exists())
