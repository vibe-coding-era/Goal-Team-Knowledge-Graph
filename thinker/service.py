"""Identity, Unix transport and transaction boundary shared by all interfaces."""

import contextlib
import fcntl
import hashlib
import hmac
import json
import logging
import math
import os
import re
import secrets
import signal
import socketserver
import sqlite3
import stat
import threading
import time

from . import VERSION

MAX_FRAME = 1024 * 1024
DEFAULT_REF = "refs/heads/main"
READ = {
    "status",
    "repos.list",
    "watch.status",
    "context.get",
    "judgment.explain",
    "evidence.get",
    "feedback.receipt",
    "timeline.read",
    "events.list",
    "memory.recall",
    "memory.wiki",
    "memory.status",
    "memory.candidates",
}
HUMAN = READ | {"feedback.record", "timeline.mark"}
REPO = {
    "repos.add",
    "repos.list",
    "repos.remove",
    "repos.pause",
    "repos.resume",
    "watch.status",
    "watch.reconcile",
    "source.read",
    "source.search",
}
CORE = {
    "context.get",
    "evidence.get",
    "evidence.revoke",
    "judgment.propose",
    "judgment.publish",
    "judgment.explain",
    "recommendation.send",
    "feedback.record",
    "feedback.receipt",
    "events.list",
}
MEMORY = {
    "timeline.read",
    "timeline.mark",
    "memory.setup",
    "memory.retain",
    "memory.recall",
    "memory.project",
    "memory.retry",
    "memory.forget",
    "memory.wiki",
    "memory.reflect",
    "memory.status",
    "memory.candidates",
}


def filter_sources(db, scope, rows):
    from . import core, memory

    return [
        row
        for row in rows
        if not core.is_revoked(db, scope, row["id"], row)
        and not memory.contains_secret(row.get("text", ""))
    ]


def invalidate_transitions(db, scope, actor, result, extra=()):
    from . import core, memory

    pairs = {(e["repo"], e["ref"]) for e in result.get("events", [])}
    pairs.update(extra)
    for repo, ref in pairs:
        core.reconcile_source(db, scope, actor, repo, ref)
    if pairs:
        memory.invalidate(db, scope)


def label(value):
    if not isinstance(value, str) or not re.fullmatch(r"[\w.:-]{1,100}", value):
        raise ValueError("invalid identity or project label")
    return value


def encode(obj):
    return (
        json.dumps(obj, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
        + "\n"
    ).encode()


def frame(stream):
    line = stream.readline(MAX_FRAME + 1)
    if len(line) > MAX_FRAME or not line.endswith(b"\n"):
        raise ValueError("invalid frame size")
    obj = json.loads(line)
    if not isinstance(obj, dict):
        raise ValueError("expected an object")
    return obj


def private_home(home, create=False):
    if create:
        home.mkdir(0o700, parents=True, exist_ok=True)
    s = home.lstat()
    if not stat.S_ISDIR(s.st_mode) or s.st_uid != os.getuid() or s.st_mode & 0o077:
        raise ValueError("control directory must be owned by this user with mode 0700")


def private_write(path, value):
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w") as out:
        out.write(value + "\n")


def token_digest(token):
    if not isinstance(token, str) or len(token) != 64:
        raise ValueError("access denied")
    return hashlib.sha256(token.encode()).hexdigest()


def connect(home):
    db = sqlite3.connect(home / "state.sqlite", isolation_level=None, timeout=8)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    return db


def initialize(home):
    from . import core, repos, memory

    private_home(home, create=True)
    with contextlib.closing(connect(home)) as db:
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("""CREATE TABLE IF NOT EXISTS access_grants
           (token_id TEXT, scope TEXT, digest TEXT UNIQUE, actor TEXT, task TEXT,
            role TEXT, expires REAL, PRIMARY KEY(scope,token_id))""")
        core.init_db(db)
        repos.init_db(db)
        memory.init_db(db)
    key = home / "operator.key"
    if not key.exists():
        private_write(key, secrets.token_hex(32))
    return {"status": "initialized", "version": VERSION}


def scoped(args):
    return json.dumps(
        [
            label(args.get("tenant", "local")),
            label(args.get("workspace", "default")),
            label(args.get("project", "default")),
        ],
        ensure_ascii=False,
        separators=(",", ":"),
    )


def identity(db, master, token, args):
    digest = token_digest(token)
    if hmac.compare_digest(digest, master):
        return scoped(args), "operator", "admin", None
    row = db.execute(
        "SELECT * FROM access_grants WHERE digest=? AND expires>?",
        (digest, time.time()),
    ).fetchone()
    if row is None:
        raise ValueError("access denied")
    for key, expected in zip(
        ("tenant", "workspace", "project"), json.loads(row["scope"])
    ):
        if key in args and args[key] != expected:
            raise ValueError("access denied")
    return row["scope"], row["actor"], row["role"], row["task"]


def manage_access(db, scope, op, a):
    token_id = label(a["token_file_id"])
    if op == "access.revoke":
        db.execute(
            "DELETE FROM access_grants WHERE scope=? AND token_id=?", (scope, token_id)
        )
    else:
        ttl = int(a.get("ttl", 86400))
        role = a.get("role", "reader")
        if role not in {"reader", "human"} or not 1 <= ttl <= 2592000:
            raise ValueError("invalid grant")
        if not re.fullmatch("[0-9a-f]{64}", a["digest"]):
            raise ValueError("invalid token digest")
        db.execute(
            "INSERT INTO access_grants VALUES(?,?,?,?,?,?,?)",
            (
                token_id,
                scope,
                a["digest"],
                label(a["actor"]),
                label(a["task"]),
                role,
                time.time() + ttl,
            ),
        )
    return {
        "token_id": token_id,
        "status": "granted" if op == "access.grant" else "revoked",
    }


def stale_context():
    return {
        "as_of": time.time(),
        "status": "stale",
        "partial": True,
        "brief": "",
        "briefs": [],
        "evidence_refs": [],
        "active_judgments": [],
        "recommendations": [],
        "memories": [],
        "open_questions": ["A current authorized source revision is required."],
        "partial_sources": ["repository"],
        "cursor": 0,
    }


def dispatch(db, master, request, *, unlock_reflection=False):
    from . import core, repos, memory

    a = request["args"].copy()
    op = request["op"]
    scope, actor, role, task = identity(db, master, request["token"], a)
    if role != "admin" and op not in (HUMAN if role == "human" else READ):
        raise ValueError("access denied")
    for name in (
        "scope",
        "tenant",
        "workspace",
        "project",
        "actor",
        "role",
        "config_revision",
        "ref_generation",
    ):
        a.pop(name, None)
    if task:
        if any(a.get(k, task) != task for k in ("task", "task_id", "executor_task_id")):
            raise ValueError("access denied")
        if op in (
            "context.get",
            "feedback.record",
            "feedback.receipt",
            "timeline.read",
            "timeline.mark",
        ):
            a["executor_task_id"] = task
            a["task"] = task
    elif "task" in a:
        a.setdefault("executor_task_id", a["task"])
    if op == "status":
        return {
            "status": "ok",
            "version": VERSION,
            "project": json.loads(scope)[2],
            "role": role,
        }
    if op in {"access.grant", "access.revoke"}:
        # Actor and role here describe the new grant; authentication came from the server.
        return manage_access(db, scope, op, request["args"])
    if op in REPO:
        changed = op in {"repos.add", "repos.pause", "repos.resume", "repos.remove"}
        before = (
            repos.dispatch(db, scope, actor, "repos.list", {})["repos"]
            if changed
            else []
        )
        result = repos.dispatch(db, scope, actor, op, a)
        if changed or op == "watch.reconcile":
            extra = [
                (r["repo"], s["ref"])
                for r in before
                if r["repo"] == a.get("repo", a.get("repo_id"))
                for s in r["refs"]
            ]
            invalidate_transitions(db, scope, actor, result, extra)
        for key in ("evidence", "refreshed_evidence"):
            if key in result:
                result[key] = filter_sources(db, scope, result[key])
        return result
    if op in {"evidence.capture", "ci.record", "ci.import", "decision.record"}:
        if op == "evidence.capture":
            rows = repos.dispatch(db, scope, actor, "source.read", a)
            if not rows.get("evidence"):
                raise ValueError("verified source bytes unavailable")
            evidence = rows["evidence"][0]
        elif op == "ci.import":
            from . import ci
            from .evidence import git

            binding = repos.current_binding(
                db, scope, a["repo"], a["ref"], a["source_revision"]
            )
            registered = repos.dispatch(
                db, scope, actor, "repos.list", {"repo": a["repo"]}
            )["repos"][0]
            remote = git(
                registered["location"],
                "config",
                "--local",
                "--get",
                "remote.origin.url",
            )
            evidence = ci.verify_job(
                remote.stdout.decode().strip(), a["job_id"], binding
            )
        elif op == "ci.record":
            binding = repos.current_binding(
                db, scope, a["repo"], a["ref"], a["source_revision"]
            )
            locator = {k: a[k] for k in ("run_id", "check", "conclusion")}
            locator["attribution"] = a.get("attribution", "unknown")
            if not all(
                isinstance(x, str) and 0 < len(x) <= 300 for x in locator.values()
            ):
                raise ValueError("invalid CI result")
            if locator["conclusion"] not in {"success", "failure", "cancelled"}:
                raise ValueError("invalid CI conclusion")
            body = json.dumps(locator, sort_keys=True, ensure_ascii=False)
            evidence = dict(
                binding,
                id=a["id"],
                repo=a["repo"],
                ref=a["ref"],
                source_revision=a["source_revision"],
                source_kind="ci",
                assurance="operator_attested",
                locator=locator,
                attribution=locator["attribution"],
                content_hash=hashlib.sha256(body.encode()).hexdigest(),
                text=body,
            )
        else:
            binding = repos.current_binding(
                db, scope, a["repo"], a["ref"], a["source_revision"]
            )
            body = a["text"]
            evidence = dict(
                binding,
                id=a["id"],
                source_kind="manual_decision",
                locator={"decision_id": a["id"]},
                content_hash=hashlib.sha256(body.encode()).hexdigest(),
                text=body,
            )
        if memory.contains_secret(evidence["text"]):
            raise ValueError("source quarantined")
        return core.dispatch(
            db, scope, actor, "evidence.record", {"evidence": evidence}
        )
    if op == "memory.reflect" and unlock_reflection:
        def call_provider(backend, query):
            # End the read snapshot before inference so a withdrawal can commit.
            db.commit()
            result = backend.reflect(query)
            db.execute("BEGIN IMMEDIATE")
            if identity(db, master, request["token"], request["args"]) != (scope, actor, role, task):
                raise ValueError("access changed during reflection")
            return result

        return memory.reflect(db, scope, actor, a, call_provider)
    if op in MEMORY:
        return memory.dispatch(db, scope, actor, op, a)
    if op not in CORE:
        raise ValueError("unknown operation")
    if op == "context.get":
        a.setdefault("ref", DEFAULT_REF)
        try:
            binding = repos.current_binding(
                db, scope, a["repo"], a["ref"], a.get("source_revision")
            )
        except ValueError:
            return stale_context()
        a.setdefault(
            "source_revision",
            binding.get("observed_oid") or binding.get("source_revision"),
        )
        result = core.dispatch(db, scope, actor, op, a)
        result["binding"] = binding
        budget = a.get("budget", 16000)
        remaining = max(0, budget - len(encode(result).decode()))
        seen = {e["id"] for e in result["evidence_refs"]}
        if a.get("query"):
            hits = repos.search_context(
                db,
                scope,
                {k: a[k] for k in ("repo", "ref", "source_revision", "query")},
            )
            result["partial_sources"].extend(hits.get("partial_sources", []))
            for hit in hits["evidence"]:
                if memory.contains_secret(hit["text"]):
                    result["partial_sources"].append("quarantined_source")
                    continue
                if (
                    hit["id"] in seen
                    or core.is_revoked(db, scope, hit["id"], hit)
                    or not repos.validate_current(db, scope, hit)
                ):
                    continue
                cost = len(encode(hit).decode())
                if cost > remaining:
                    result["partial_sources"].append("context_budget")
                    break
                result["evidence_refs"].append(hit)
                remaining -= cost
                seen.add(hit["id"])
        result["memories"] = []
        selected = {j["judgment_revision"] for j in result["active_judgments"]}
        try:
            recall = memory.dispatch(
                db, scope, actor, "memory.recall", {"query": a.get("query", "")}
            )
            if recall.get("partial"):
                result["partial_sources"].append("memory")
            for item in recall["memories"]:
                if (
                    item.get("judgment_revision")
                    and item["judgment_revision"] not in selected
                ):
                    continue
                evidence = [
                    core.get_evidence(db, scope, eid) for eid in item["evidence_ids"]
                ]
                if not evidence or any(
                    any(e[k] != binding[k] for k in ("repo", "ref", "source_revision"))
                    for e in evidence
                ):
                    continue
                new_refs = [e for e in evidence if e["id"] not in seen]
                entry = dict(item, authoritative=False)
                cost = len(encode([entry, *new_refs]).decode())
                if cost > remaining:
                    result["partial_sources"].append("context_budget")
                    break
                result["memories"].append(entry)
                result["evidence_refs"].extend(new_refs)
                seen.update(e["id"] for e in new_refs)
                remaining -= cost
        except (ValueError, OSError):
            result["partial_sources"].append("memory")
        try:
            if binding != repos.current_binding(
                db, scope, a["repo"], a["ref"], a["source_revision"]
            ):
                return stale_context()
        except ValueError:
            return stale_context()
        now = time.time()
        if (
            any(j["review_after"] <= now for j in result["active_judgments"])
            or any(r["expires_at"] <= now for r in result["recommendations"])
            or any(
                min(
                    e.get("expires_at", float("inf")),
                    e.get("review_after", float("inf")),
                )
                <= now
                for e in result["evidence_refs"]
            )
        ):
            return stale_context()
        result["partial_sources"] = sorted(set(result["partial_sources"]))
        result["partial"] = bool(result["partial_sources"])
        result["status"] = "partial" if result["partial"] else binding["index_status"]
        return result
    if any(
        memory.contains_secret(a[field])
        for field in ("claim", "reason", "next_action", "correction")
        if isinstance(a.get(field), str)
    ):
        raise ValueError("submitted content quarantined")
    result = core.dispatch(db, scope, actor, op, a)
    if op in {"evidence.revoke", "judgment.publish"} or (
        op == "feedback.record" and a["acceptance"] == "corrected"
    ):
        memory.invalidate(db, scope)
    return result


def read_authority_stamp(db, scope):
    """Compare authority, not polling counters or outbox delivery bookkeeping.

    Every core domain mutation publishes a scoped event in the same transaction.
    Registry changes and memory tombstones also gate reads, so include their
    binding metadata explicitly. No external calls or writer lock are needed.
    """
    queries = (
        "SELECT COALESCE(MAX(seq),0) FROM core_events WHERE scope=?",
        "SELECT repo,config_revision,enabled,removed,health FROM tk_repos WHERE scope=? ORDER BY repo",
        "SELECT repo,ref,observed_oid,indexed_oid,ref_generation,state FROM tk_refs WHERE scope=? ORDER BY repo,ref",
        "SELECT id,lifecycle FROM memory_refs WHERE scope=? ORDER BY id",
    )
    return tuple(
        tuple(tuple(row) for row in db.execute(query, (scope,))) for query in queries
    )


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.connection.settimeout(10)
        try:
            req = frame(self.rfile)
            with contextlib.closing(connect(self.server.home)) as db:
                readonly = req.get("op") in READ
                reflecting = req.get("op") == "memory.reflect"
                for attempt in range(2):
                    with db:
                        db.execute("BEGIN" if readonly or reflecting else "BEGIN IMMEDIATE")
                        if readonly:
                            principal = identity(
                                db, self.server.master, req["token"], req["args"]
                            )
                            version = read_authority_stamp(db, principal[0])
                        if reflecting:
                            result = dispatch(db, self.server.master, req, unlock_reflection=True)
                        else:
                            result = dispatch(db, self.server.master, req)
                        if readonly:
                            identity(db, self.server.master, req["token"], req["args"])
                    if not readonly:
                        break
                    # A new snapshot observes revocation committed during slow
                    # external reads. Poll timestamps cannot starve this check.
                    with db:
                        db.execute("BEGIN")
                        current = identity(
                            db, self.server.master, req["token"], req["args"]
                        )
                        unchanged = (
                            principal == current
                            and version == read_authority_stamp(db, current[0])
                        )
                    if unchanged:
                        break
                else:
                    raise ValueError("state changed while reading; refresh the request")
                reply = {"ok": True, "result": result}
        except (
            ValueError,
            PermissionError,
            KeyError,
            TypeError,
            AttributeError,
            OSError,
            sqlite3.Error,
            OverflowError,
            UnicodeError,
            RecursionError,
        ) as error:
            # A failed operation may reference private paths, SQL, or another project.
            detail = str(error) if type(error) is ValueError else "request unavailable"
            reply = {"ok": False, "error": detail[:200]}
        data = encode(reply)
        if len(data) > MAX_FRAME:
            data = encode({"ok": False, "error": "response exceeds budget"})
        self.wfile.write(data)


class Server(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True
    request_queue_size = 32
    slots = threading.BoundedSemaphore(16)

    def process_request(self, request, client_address):
        if self.slots.acquire(blocking=False):
            super().process_request(request, client_address)
        else:
            self.shutdown_request(request)

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()


def serve(home, interval):
    from . import repos, memory

    private_home(home)
    if not math.isfinite(interval) or interval < 0 or 0 < interval < 0.1:
        raise ValueError("invalid reconcile interval")
    private = home / "thinker.sock"
    with (home / "server.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        master = token_digest((home / "operator.key").read_text().strip())
        if private.is_socket():
            private.unlink()
        stopped = threading.Event()

        def poll():
            while not stopped.wait(interval):
                try:
                    with contextlib.closing(connect(home)) as db, db:
                        db.execute("BEGIN IMMEDIATE")
                        update = repos.tick(db)
                        if update["processed"]:
                            invalidate_transitions(
                                db, update["scope"], "observer", update["result"]
                            )
                    with contextlib.closing(connect(home)) as db, db:
                        db.execute("BEGIN IMMEDIATE")
                        memory.tick(db)
                except Exception as err:
                    logging.warning("reconcile deferred (%s)", type(err).__name__)

        with Server(str(private), Handler) as server:
            try:
                private.chmod(0o600)
                server.home, server.master, server.timeout = home, master, 0.25
                for sig in (signal.SIGTERM, signal.SIGINT):
                    signal.signal(sig, lambda *_: stopped.set())
                if interval:
                    threading.Thread(target=poll, daemon=True).start()
                while not stopped.is_set():
                    server.handle_request()
            finally:
                stopped.set()
                private.unlink(missing_ok=True)
