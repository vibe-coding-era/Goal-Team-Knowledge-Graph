import argparse
import json
import os
from pathlib import Path
import secrets
import sys

from . import VERSION
from .client import call, mcp
from .service import (
    CORE,
    MEMORY,
    REPO,
    initialize,
    private_home,
    private_write,
    serve,
    token_digest,
)


def parser():
    p = argparse.ArgumentParser(
        prog="thinker", description="Versioned project handoffs"
    )
    p.add_argument("--version", action="version", version="thinker " + VERSION)
    p.add_argument(
        "--home",
        type=Path,
        default=Path(os.environ.get("THINKER_HOME", Path.home() / ".thinker")),
    )
    p.add_argument(
        "--token-file", type=Path, default=os.environ.get("THINKER_TOKEN_FILE")
    )
    commands = p.add_subparsers(dest="command", required=True)
    ops = (
        CORE
        | REPO
        | MEMORY
        | {
            "ci.record",
            "ci.import",
            "evidence.capture",
            "decision.record",
            "access.grant",
            "access.revoke",
        }
    )
    groups = {}
    for op in sorted(ops | {"init", "serve", "tui", "status", "mcp"}):
        if "." in op:
            group, action = op.split(".")
            if group not in groups:
                groups[group] = commands.add_parser(group).add_subparsers(
                    dest="action", required=True
                )
            cmd = groups[group].add_parser(action)
        else:
            cmd = commands.add_parser(op)
        cmd.set_defaults(op=op)
        if op == "serve":
            cmd.add_argument(
                "--interval",
                type=float,
                default=5,
                help="Seconds between repository polls; 0 for manual reconciliation",
            )
        if op == "judgment.explain":
            cmd.add_argument("judgment", nargs="?")
        cmd.add_argument(
            "--args",
            metavar="JSON",
            help="Operation fields, or '-' to read JSON on stdin",
        )
        for field in (
            "tenant",
            "workspace",
            "project",
            "repo",
            "ref",
            "task",
            "source-revision",
            "location",
            "id",
            "judgment-id",
            "recommendation",
            "judgment-revision",
            "acceptance",
            "outcome",
            "query",
            "path",
            "reason",
            "token-file-id",
            "actor",
            "role",
            "output",
        ):
            cmd.add_argument("--" + field)
        for field in ("limit", "ttl", "budget"):
            cmd.add_argument("--" + field, type=int)
        cmd.add_argument("--require-fresh", action="store_true")
        cmd.add_argument(
            "--json",
            action="store_true",
            help="Emit JSON (default for non-interactive commands)",
        )
        # argparse accepts these options before or after the operation.
        cmd.add_argument("--home", type=Path, default=argparse.SUPPRESS)
        cmd.add_argument("--token-file", type=Path, default=argparse.SUPPRESS)
    return p


def run(argv=None):
    ns = vars(parser().parse_args(argv))
    op = ns.pop("op")
    home = ns.pop("home").expanduser().absolute()
    token_file = ns.pop("token_file")
    raw = ns.pop("args")
    args = json.loads(sys.stdin.read(1024 * 1024) if raw == "-" else raw) if raw else {}
    if not isinstance(args, dict):
        raise ValueError("--args requires a JSON object")
    fresh = ns.pop("require_fresh")
    for key in ("command", "action", "json"):
        ns.pop(key, None)
    aliases = {"judgment": "judgment_id", "recommendation": "recommendation_id"}
    args.update({aliases.get(k, k): v for k, v in ns.items() if v is not None})
    if op == "init":
        result = initialize(home)
    elif op == "serve":
        serve(home, args["interval"])
        return 0
    else:
        if op == "mcp" and not token_file:
            raise ValueError("MCP requires a scoped reader token via --token-file")
        private_home(home)
        token = (
            (Path(token_file) if token_file else home / "operator.key")
            .read_text()
            .strip()
        )

        def request(operation, params):
            return call(home, token, operation, params)

        if op == "mcp":
            identity = request("status", {})
            if identity["role"] != "reader":
                raise ValueError("MCP requires a reader grant")
            mcp(request, sys.stdin.buffer, sys.stdout.buffer)
            return 0
        if op == "tui":
            from . import tui

            return tui.run(request, args)
        if op == "access.grant":
            output = Path(args.pop("output"))
            secret = secrets.token_hex(32)
            args.setdefault("token_file_id", output.name)
            args["digest"] = token_digest(secret)
            private_write(output, secret)
            try:
                result = request(op, args)
            except (ValueError, OSError):
                output.unlink()
                raise
        else:
            result = request(op, args)
    print(json.dumps(result, ensure_ascii=False))
    if fresh and (
        result.get("status") in {"stale", "pending", "partial", "degraded"}
        or result.get("partial_sources")
    ):
        return 3
    return 0


if __name__ == "__main__":
    try:
        sys.exit(run())
    except (ValueError, OSError, KeyError) as err:
        print(json.dumps({"error": str(err)}, ensure_ascii=False), file=sys.stderr)
        sys.exit(2)
