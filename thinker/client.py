"""Bounded socket client and a read-only MCP stdio bridge."""

import json
import socket

from . import VERSION
from .service import MAX_FRAME, encode, frame


def call(home, token, op, args):
    body = encode({"token": token, "op": op, "args": args})
    if len(body) > MAX_FRAME:
        raise ValueError("request exceeds budget")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(75 if op == "memory.reflect" else 15)
        sock.connect(str(home / "thinker.sock"))
        sock.sendall(body)
        with sock.makefile("rb") as stream:
            response = frame(stream)
    if not response.get("ok"):
        raise ValueError(response.get("error", "request unavailable"))
    return response["result"]


TOOLS = {
    "thinker_repo_status": (
        "watch.status",
        "List authorized repository and index states.",
        ("project", "repo"),
        (),
    ),
    "thinker_get_context": (
        "context.get",
        "Get current scoped judgments and supporting evidence.",
        ("project", "repo", "ref", "source_revision", "task", "budget", "query"),
        ("repo",),
    ),
    "thinker_explain_judgment": (
        "judgment.explain",
        "Read judgment history and evidence.",
        ("project", "judgment_id"),
        ("judgment_id",),
    ),
}


def schema(fields, required):
    return {
        "type": "object",
        "properties": {
            k: (
                {"type": "integer", "minimum": 1, "maximum": 8000}
                if k == "budget"
                else {"type": "string"}
            )
            for k in fields
        },
        "required": list(required),
        "additionalProperties": False,
    }


def mcp(request, inp, out):
    state = "new"
    while True:
        raw = inp.readline(MAX_FRAME + 1)
        if not raw:
            return
        if len(raw) > MAX_FRAME:
            return
        ident = None
        try:
            msg = json.loads(raw)
            if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0":
                raise ValueError("invalid request")
            ident, method = msg.get("id"), msg.get("method")
            params = msg.get("params", {})
            if not isinstance(params, dict):
                raise ValueError("invalid params")
            if "id" not in msg:
                if method == "notifications/initialized" and state == "negotiated":
                    state = "ready"
                continue
            if method == "initialize" and state == "new":
                supported = ("2025-11-25", "2025-06-18", "2025-03-26")
                version = params.get("protocolVersion")
                result = {
                    "protocolVersion": version
                    if version in supported
                    else supported[0],
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "thinker", "version": VERSION},
                }
                state = "negotiated"
            elif method == "ping":
                result = {}
            elif state != "ready":
                raise ValueError("initialization required")
            elif method == "tools/list":
                result = {
                    "tools": [
                        {
                            "name": name,
                            "description": info[1],
                            "inputSchema": schema(*info[2:]),
                            "annotations": {"readOnlyHint": True},
                        }
                        for name, info in TOOLS.items()
                    ]
                }
            elif method == "tools/call":
                tool = TOOLS.get(params.get("name"))
                if tool is None:
                    raise ValueError("unknown tool")
                args = params.get("arguments", {})
                if (
                    not isinstance(args, dict)
                    or set(args) - set(tool[2])
                    or set(tool[3]) - set(args)
                    or any(
                        not isinstance(v, str) for k, v in args.items() if k != "budget"
                    )
                    or (
                        "budget" in args
                        and (
                            type(args["budget"]) is not int
                            or not 1 <= args["budget"] <= 8000
                        )
                    )
                ):
                    raise ValueError("invalid tool arguments")
                try:
                    value = request(tool[0], args)
                    result = {
                        "content": [
                            {
                                "type": "text",
                                "text": json.dumps(value, ensure_ascii=False),
                            }
                        ],
                        "structuredContent": value,
                    }
                except (ValueError, OSError) as err:
                    result = {
                        "isError": True,
                        "content": [{"type": "text", "text": str(err)}],
                    }
            else:
                raise LookupError
            reply = {"result": result}
        except (TypeError, ValueError, LookupError, RecursionError) as err:
            code = (
                -32700
                if isinstance(err, json.JSONDecodeError)
                else -32601
                if isinstance(err, LookupError)
                else -32602
            )
            reply = {
                "error": {
                    "code": code,
                    "message": "invalid request or unavailable method",
                }
            }
        out.write(encode(dict(reply, jsonrpc="2.0", id=ident)))
        out.flush()
