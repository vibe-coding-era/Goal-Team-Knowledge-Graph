"""Scoped Thinker authority. The authenticated service owns transactions and ACLs.

All source material is data, never an instruction. Evidence import is a trusted
adapter operation, not a public raw-JSON ingestion endpoint. No function commits;
domain mutations and the local outbox must share the caller's BEGIN IMMEDIATE.
"""

import hashlib
import json
import math
import re
import time
import uuid


MAX_CANDIDATES_PER_SCOPE = 128
BRIEF_SCHEMA = "CREATE TABLE IF NOT EXISTS core_briefs (scope TEXT NOT NULL,judgment_id TEXT NOT NULL,revision INTEGER NOT NULL,data TEXT NOT NULL,created_at REAL NOT NULL,PRIMARY KEY(scope,judgment_id,revision))"


def init_db(db):
    statements = [
        "CREATE TABLE IF NOT EXISTS core_evidence (scope TEXT NOT NULL,id TEXT NOT NULL,data TEXT NOT NULL,state TEXT NOT NULL,recorded_at REAL NOT NULL,PRIMARY KEY(scope,id))",
        "CREATE TABLE IF NOT EXISTS core_judgments (scope TEXT NOT NULL,judgment_id TEXT NOT NULL,revision INTEGER NOT NULL,base_revision INTEGER NOT NULL,status TEXT NOT NULL,data TEXT NOT NULL,recorded_at REAL NOT NULL,PRIMARY KEY(scope,judgment_id,revision))",
        "CREATE TABLE IF NOT EXISTS core_heads (scope TEXT NOT NULL,judgment_id TEXT NOT NULL,revision INTEGER NOT NULL,PRIMARY KEY(scope,judgment_id))",
        "CREATE TABLE IF NOT EXISTS core_recommendations (scope TEXT NOT NULL,id TEXT NOT NULL,data TEXT NOT NULL,request_hash TEXT NOT NULL,state TEXT NOT NULL,PRIMARY KEY(scope,id))",
        "CREATE TABLE IF NOT EXISTS core_feedback (scope TEXT NOT NULL,id TEXT NOT NULL,data TEXT NOT NULL,request_hash TEXT NOT NULL,PRIMARY KEY(scope,id))",
        "CREATE TABLE IF NOT EXISTS core_events (scope TEXT NOT NULL,seq INTEGER NOT NULL,event_id TEXT NOT NULL UNIQUE,type TEXT NOT NULL,payload TEXT NOT NULL,recorded_at REAL NOT NULL,actor TEXT NOT NULL,delivery_state TEXT NOT NULL DEFAULT 'pending',attempts INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(scope,seq))",
        BRIEF_SCHEMA,
    ]
    for statement in statements:
        db.execute(statement)


def _json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _digest(value):
    return hashlib.sha256(_json(value).encode("utf-8")).hexdigest()


def _id(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:/@-]{0,159}", value):
        raise ValueError("invalid identifier")
    return value


def _text(value, limit=20000):
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise ValueError("invalid text")
    return value


def _number(value, name):
    if isinstance(value, bool) or not isinstance(value, (float, int)) or not math.isfinite(value):
        raise ValueError("invalid " + name)
    return value


def _integer(value, name, minimum=0, maximum=1000000000):
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError("invalid " + name)
    return value


def _ids(value):
    if not isinstance(value, list) or len(value) > 64:
        raise ValueError("invalid evidence references")
    ids = [_id(x) for x in value]
    if len(set(ids)) != len(ids):
        raise ValueError("duplicate evidence references")
    return ids


def _version(args):
    repo = _id(args.get("repo"))
    ref = _text(args.get("ref"), 300)
    revision = args.get("source_revision")
    if not isinstance(revision, str) or not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", revision):
        raise ValueError("invalid source revision")
    return {"repo": repo, "ref": ref, "source_revision": revision}


def _current_binding(db, scope, repo, ref, source_revision):
    from . import repos
    return repos.current_binding(db, scope, repo, ref, source_revision)


def _validate_binding(db, scope, evidence):
    from . import repos
    return repos.validate_current(db, scope, evidence)


def _event(db, scope, actor, kind, payload):
    # Only validated identifiers/status travel in events, never raw or derived text.
    seq = db.execute("SELECT COALESCE(MAX(seq),0)+1 FROM core_events WHERE scope=?", (scope,)).fetchone()[0]
    event_id = uuid.uuid4().hex
    db.execute("INSERT INTO core_events(scope,seq,event_id,type,payload,recorded_at,actor) VALUES(?,?,?,?,?,?,?)",
               (scope, seq, event_id, kind, _json(payload), time.time(), actor))
    return event_id


def _evidence_row(db, scope, eid):
    row = db.execute("SELECT * FROM core_evidence WHERE scope=? AND id=?", (scope, _id(eid))).fetchone()
    if row is None:
        raise ValueError("evidence unavailable")
    return row


def is_revoked(db, scope, eid, evidence=None):
    """Check tombstones even before import; file-level revocation is conservative.

    Pass the adapter's evidence object for retrieved hits. New IDs, shorter
    slices, or overlapping slices cannot evade a revoked file at that revision.
    A bare ID only checks the ID tombstone and must not gate arbitrary new hits.
    """
    _id(eid)
    row = db.execute("SELECT state FROM core_evidence WHERE scope=? AND id=?", (scope, eid)).fetchone()
    if row and row["state"] == "revoked":
        return True
    if not isinstance(evidence, dict):
        return False
    for row in db.execute("SELECT data FROM core_evidence WHERE scope=? AND state='revoked'", (scope,)):
        revoked = json.loads(row[0])
        if any(revoked.get(k) != evidence.get(k) for k in ("repo", "ref", "source_revision")):
            continue
        old_locator, locator = revoked.get("locator", {}), evidence.get("locator", {})
        if old_locator.get("path") and old_locator.get("path") == locator.get("path"):
            return True
        if old_locator.get("run_id") and all(old_locator.get(k) == locator.get(k) for k in ("run_id", "check")):
            return True
        if old_locator.get("page_path") and all(old_locator.get(k) == locator.get(k) for k in ("page_path", "bundle_digest")):
            return True
    return False


def get_evidence(db, scope, eid):
    """Expand only currently authorized, non-revoked, fresh source evidence."""
    row = _evidence_row(db, scope, eid)
    evidence = json.loads(row["data"])
    if row["state"] != "active" or is_revoked(db, scope, eid, evidence):
        raise ValueError("evidence unavailable")
    for name in ("expires_at", "review_after"):
        if name in evidence and evidence[name] <= time.time():
            raise ValueError("evidence expired")
    if not _validate_binding(db, scope, evidence):
        raise ValueError("source unavailable or stale")
    for source in evidence.get("source_bindings", []):
        if not isinstance(source, dict) or is_revoked(db, scope, source.get("id"), source) or not _validate_binding(db, scope, source):
            raise ValueError("derived source unavailable")
    evidence.update(state=row["state"], recorded_at=row["recorded_at"])
    return evidence


def _evidence_set(db, scope, ids, version):
    result = []
    for eid in ids:
        evidence = get_evidence(db, scope, eid)
        if evidence["source_kind"] == "knowledge_page" or evidence.get("independent_evidence") is False:
            raise ValueError("independent supporting evidence required")
        if any(evidence.get(key) != value for key, value in version.items()):
            raise ValueError("evidence source revision mismatch")
        result.append(evidence)
    return result


def _head(db, scope, jid):
    row = db.execute("SELECT revision FROM core_heads WHERE scope=? AND judgment_id=?", (scope, jid)).fetchone()
    return row[0] if row else 0


def _judgment_row(db, scope, jid, revision):
    row = db.execute("SELECT * FROM core_judgments WHERE scope=? AND judgment_id=? AND revision=?",
                     (scope, _id(jid), _integer(revision, "revision", 1))).fetchone()
    if row is None:
        raise ValueError("judgment unavailable")
    return row


def _judgment_data(row):
    data = json.loads(row["data"])
    data.update(status=row["status"], judgment_revision="{}@{}".format(row["judgment_id"], row["revision"]))
    return data


def _split_revision(value):
    if not isinstance(value, str) or "@" not in value:
        raise ValueError("invalid judgment revision")
    jid, revision = value.rsplit("@", 1)
    if not revision.isascii() or not revision.isdigit() or str(int(revision)) != revision:
        raise ValueError("invalid judgment revision")
    return _id(jid), _integer(int(revision), "revision", 1)


def get_live_judgment(db, scope, judgment_revision):
    """Shared gate for projections: never trust their cached freshness flag."""
    jid, revision = _split_revision(judgment_revision)
    row = _judgment_row(db, scope, jid, revision)
    data = _judgment_data(row)
    if row["status"] != "active" or _head(db, scope, jid) != revision:
        raise ValueError("judgment is not current")
    if data["review_after"] <= time.time():
        raise ValueError("judgment expired")
    data["evidence_refs"] = _evidence_set(db, scope, data["supports"] + data["contradicts"], _version(data))
    return data


def _record_evidence(db, scope, actor, args):
    source = args.get("evidence")
    if not isinstance(source, dict):
        raise ValueError("invalid evidence")
    evidence = dict(source)
    eid = _id(evidence.get("id"))
    version = _version(evidence)
    allowed = {"source", "git_source", "gtkg_source", "ci", "manual_decision", "knowledge_page"}
    if evidence.get("source_kind") not in allowed:
        raise ValueError("independent source evidence required")
    if "scope" in evidence and evidence["scope"] != scope:
        raise ValueError("evidence scope mismatch")
    text = _text(evidence.get("text"), 250000)
    digest = "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()
    if evidence.get("content_hash") not in (digest, digest[7:]):
        raise ValueError("evidence hash mismatch")
    locator = evidence.get("locator")
    if not isinstance(locator, dict) or not locator:
        raise ValueError("evidence locator required")
    if evidence["source_kind"] == "ci":
        _id(locator.get("run_id"))
        _text(locator.get("check"), 300)
        if locator.get("conclusion") not in ("success", "failure", "cancelled", "unknown"):
            raise ValueError("invalid CI conclusion")
    if evidence["source_kind"] == "knowledge_page":
        if evidence.get("independent_evidence") is not False or not locator.get("page_path") or not locator.get("bundle_digest"):
            raise ValueError("verified page-local derived evidence required")
    if evidence["source_kind"] == "manual_decision":
        evidence["source_actor"] = actor
        evidence["source_attribution"] = "human"
    if not isinstance(evidence.get("source_bindings", []), list):
        raise ValueError("invalid derived source bindings")
    for name in ("expires_at", "review_after"):
        if name in evidence:
            _number(evidence[name], name)
            if evidence[name] <= time.time():
                raise ValueError("evidence expired")
    binding = _current_binding(db, scope, **version)
    # Stamp identity from the authorized registry, never a caller-provided stamp.
    for name in ("config_revision", "ref_generation", "transition_seq"):
        if name in binding:
            if name in evidence and evidence[name] != binding[name]:
                raise ValueError("evidence capture identity is stale")
            evidence[name] = binding[name]
    evidence["scope"] = scope
    evidence["content_hash"] = digest
    evidence.pop("recorded_at", None)
    evidence.pop("state", None)
    if is_revoked(db, scope, eid, evidence):
        raise ValueError("evidence is revoked")
    old = db.execute("SELECT * FROM core_evidence WHERE scope=? AND id=?", (scope, eid)).fetchone()
    if old:
        previous = json.loads(old["data"])
        # Source adapters timestamp each observation, not the immutable source.
        # Replaying the same identity keeps the original observation timestamp.
        if "occurred_at" in previous:
            evidence["occurred_at"] = previous["occurred_at"]
        if old["data"] != _json(evidence) or old["state"] != "active":
            raise ValueError("evidence is immutable or revoked")
        return get_evidence(db, scope, eid)
    encoded = _json(evidence)
    db.execute("INSERT INTO core_evidence VALUES(?,?,?,?,?)", (scope, eid, encoded, "active", time.time()))
    _event(db, scope, actor, "EvidenceRecorded", {"evidence_id": eid})
    return get_evidence(db, scope, eid)


def _revoke_evidence(db, scope, actor, args):
    eid = _id(args.get("id"))
    _text(args.get("reason"), 2000)
    row = db.execute("SELECT * FROM core_evidence WHERE scope=? AND id=?", (scope, eid)).fetchone()
    if row is not None and row["state"] == "revoked":
        return {"id": eid, "state": "revoked"}
    if row is None:
        # Unknown IDs can be tombstoned without importing or expanding content.
        # Optional locator metadata comes from the service's trusted adapter.
        tombstone = {"id": eid}
        supplied = args.get("evidence")
        if supplied is not None:
            if not isinstance(supplied, dict) or supplied.get("id", eid) != eid or supplied.get("scope", scope) != scope:
                raise ValueError("invalid revocation metadata")
            tombstone.update(_version(supplied))
            if not isinstance(supplied.get("locator"), dict):
                raise ValueError("invalid revocation locator")
            tombstone["locator"] = supplied["locator"]
        db.execute("INSERT INTO core_evidence VALUES(?,?,?,?,?)", (scope, eid, _json(tombstone), "revoked", time.time()))
    else:
        db.execute("UPDATE core_evidence SET state='revoked' WHERE scope=? AND id=?", (scope, eid))
    for judgment in db.execute("SELECT * FROM core_judgments WHERE scope=? AND status IN ('active','candidate')", (scope,)).fetchall():
        data = json.loads(judgment["data"])
        if eid in data["supports"] + data["contradicts"]:
            db.execute("UPDATE core_judgments SET status='needs_evidence' WHERE scope=? AND judgment_id=? AND revision=?",
                       (scope, judgment["judgment_id"], judgment["revision"]))
    _event(db, scope, actor, "EvidenceRevoked", {"evidence_id": eid})
    return {"id": eid, "state": "revoked"}


def _propose(db, scope, actor, args):
    version = _version(args)
    _current_binding(db, scope, **version)
    jid = _id(args.get("judgment_id"))
    base = _integer(args.get("base_revision"), "base revision")
    if _head(db, scope, jid) != base:
        raise ValueError("judgment revision conflict")
    supports = _ids(args.get("supports"))
    contradicts = _ids(args.get("contradicts", []))
    if not supports or set(supports).intersection(contradicts):
        raise ValueError("independent supporting evidence required")
    _evidence_set(db, scope, supports + contradicts, version)
    deadline = _number(args.get("review_after", time.time() + 3600), "review deadline")
    if deadline <= time.time():
        raise ValueError("judgment expired")
    pending = sum(json.loads(row[0])["review_after"] > time.time() for row in
                  db.execute("SELECT data FROM core_judgments WHERE scope=? AND status='candidate'", (scope,)))
    if pending >= MAX_CANDIDATES_PER_SCOPE:
        raise ValueError("candidate quota exceeded")
    revision = db.execute("SELECT COALESCE(MAX(revision),0)+1 FROM core_judgments WHERE scope=? AND judgment_id=?", (scope, jid)).fetchone()[0]
    data = dict(version, judgment_id=jid, revision=revision, base_revision=base,
                claim=_text(args.get("claim")), supports=supports, contradicts=contradicts,
                supersedes="{}@{}".format(jid, base) if base else None,
                review_after=deadline, valid_from=time.time(), policy_version=1, proposer=actor,
                reason=args.get("reason", ""))
    if not isinstance(data["reason"], str) or len(data["reason"]) > 20000:
        raise ValueError("invalid reason")
    db.execute("INSERT INTO core_judgments VALUES(?,?,?,?,?,?,?)", (scope, jid, revision, base, "candidate", _json(data), time.time()))
    _event(db, scope, actor, "JudgmentProposed", {"judgment_id": jid, "revision": revision})
    return _judgment_data(_judgment_row(db, scope, jid, revision))


def _brief_payload(judgment):
    """Deterministic publication artifact; citations contain no raw evidence body."""
    citations = []
    for evidence in judgment['evidence_refs']:
        citations.append({
            'evidence_id': evidence['id'],
            'relation': 'supports' if evidence['id'] in judgment['supports'] else 'contradicts',
            **{key: evidence.get(key) for key in ('source_kind', 'content_hash', 'locator',
               'repo', 'ref', 'source_revision', 'config_revision', 'ref_generation')},
        })
    return dict(_version(judgment), brief_id='brief:' + judgment['judgment_revision'],
                judgment_revision=judgment['judgment_revision'], format_version=1,
                generator='deterministic-v1', text=judgment['claim'], citations=citations,
                authoritative=False)


def _live_brief(db, scope, judgment):
    """Only accept a stored projection matching an already revalidated live judgment.

    Old databases remain readable without DDL or backfills on the read path.
    Legacy views are explicitly distinguished from publication-time artifacts.
    """
    expected = _brief_payload(judgment)
    table = db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='core_briefs'").fetchone()
    row = (db.execute('SELECT data,created_at FROM core_briefs WHERE scope=? AND judgment_id=? AND revision=?',
                      (scope, judgment['judgment_id'], judgment['revision'])).fetchone() if table else None)
    if row is None:
        return dict(expected, generator='legacy_live', pre_generated=False, generated_at=None)
    try:
        stored = json.loads(row['data'])
    except (TypeError, ValueError):
        return None
    # A stale or corrupt snapshot cannot supply new claim text or provenance.
    if stored != expected:
        return None
    return dict(stored, pre_generated=True, generated_at=row['created_at'])


def _publish(db, scope, actor, args):
    version = _version(args)
    row = _judgment_row(db, scope, args.get("judgment_id"), args.get("revision"))
    data = _judgment_data(row)
    base = _integer(args.get("base_revision"), "base revision")
    if row["status"] != "candidate" or row["base_revision"] != base or _head(db, scope, row["judgment_id"]) != base:
        raise ValueError("judgment revision conflict")
    if _version(data) != version or data["review_after"] <= time.time():
        raise ValueError("judgment source mismatch or expired")
    _current_binding(db, scope, **version)
    _evidence_set(db, scope, data["supports"] + data["contradicts"], version)
    if base:
        db.execute("UPDATE core_judgments SET status='superseded' WHERE scope=? AND judgment_id=? AND revision=?",
                   (scope, row["judgment_id"], base))
    db.execute("UPDATE core_judgments SET status='active' WHERE scope=? AND judgment_id=? AND revision=?",
               (scope, row["judgment_id"], row["revision"]))
    db.execute("INSERT INTO core_heads VALUES(?,?,?) ON CONFLICT(scope,judgment_id) DO UPDATE SET revision=excluded.revision",
               (scope, row["judgment_id"], row["revision"]))
    live = get_live_judgment(db, scope, data['judgment_revision'])
    brief = _brief_payload(live)
    # Migration is allowed on an authorized publication, never during a read.
    db.execute(BRIEF_SCHEMA)
    db.execute('INSERT INTO core_briefs VALUES(?,?,?,?,?)',
               (scope, row['judgment_id'], row['revision'], _json(brief), time.time()))
    _event(db, scope, actor, "JudgmentPublished", {"judgment_id": row["judgment_id"], "revision": row["revision"],
                                                'brief_id': brief['brief_id'], 'brief_format_version': 1})
    return live


def _explain(db, scope, args):
    jid = _id(args.get("judgment_id"))
    rows = db.execute("SELECT * FROM core_judgments WHERE scope=? AND judgment_id=? ORDER BY revision", (scope, jid)).fetchall()
    if not rows:
        raise ValueError("judgment unavailable")
    current = None
    for row in rows:
        if row["status"] == "active":
            try:
                current = get_live_judgment(db, scope, "{}@{}".format(jid, row["revision"]))
            except ValueError:
                pass
    revisions = []
    for row in rows:
        data = _judgment_data(row)
        item = {"judgment_id": jid, "revision": row["revision"], "judgment_revision": data["judgment_revision"],
                "base_revision": row["base_revision"], "status": row["status"], "redacted": True}
        if data["review_after"] <= time.time():
            item["reason_code"] = "expired"
        elif row["status"] not in ("active", "superseded"):
            item["reason_code"] = row["status"]
        else:
            try:
                evidence_refs = _evidence_set(db, scope, data["supports"] + data["contradicts"], _version(data))
                _current_binding(db, scope, **_version(data))
            except ValueError:
                item["reason_code"] = "evidence_or_source_unavailable"
            else:
                item.update(data, evidence_refs=evidence_refs, redacted=False, reason_code=row["status"])
        revisions.append(item)
    return {"judgment_id": jid, "current": current, "revisions": revisions,
            "partial": current is None or any(r["redacted"] for r in revisions)}


def _live_recommendation(db, scope, rid):
    row = db.execute("SELECT * FROM core_recommendations WHERE scope=? AND id=?", (scope, _id(rid))).fetchone()
    if row is None:
        raise ValueError("recommendation unavailable")
    data = json.loads(row["data"])
    if data["expires_at"] <= time.time():
        raise ValueError("recommendation expired")
    judgment = get_live_judgment(db, scope, data["judgment_revision"])
    if _version(data) != _version(judgment):
        raise ValueError("recommendation source mismatch")
    return data


def _recommend(db, scope, actor, args):
    version = _version(args)
    rid = _id(args.get("id"))
    judgment = get_live_judgment(db, scope, args.get("judgment_revision"))
    if _version(judgment) != version:
        raise ValueError("recommendation source mismatch")
    expires = _number(args.get("expires_at"), "recommendation expiry")
    if expires <= time.time() or expires > judgment["review_after"]:
        raise ValueError("recommendation expiry outside judgment validity")
    data = dict(version, id=rid, recommendation_id=rid, judgment_revision=judgment["judgment_revision"],
                executor_task_id=_id(args.get("executor_task_id")), next_action=_text(args.get("next_action")),
                expected_check=_text(args.get("expected_check"), 300), expires_at=expires,
                category=_id(args.get("category", "advice")), uncertainty=args.get("uncertainty", "human review required"),
                evidence_ids=judgment["supports"] + judgment["contradicts"], delivery_state="sent", requires_human_approval=True)
    if not isinstance(data["uncertainty"], str) or len(data["uncertainty"]) > 2000:
        raise ValueError("invalid uncertainty")
    digest = _digest(data)
    old = db.execute("SELECT * FROM core_recommendations WHERE scope=? AND id=?", (scope, rid)).fetchone()
    if old:
        if old["request_hash"] != digest:
            raise ValueError("idempotency conflict")
        return json.loads(old["data"])
    for other in db.execute("SELECT data FROM core_recommendations WHERE scope=?", (scope,)):
        item = json.loads(other[0])
        if all(item[k] == data[k] for k in ("executor_task_id", "judgment_revision", "category")):
            raise ValueError("recommendation already sent for task and revision")
    db.execute("INSERT INTO core_recommendations VALUES(?,?,?,?,?)", (scope, rid, _json(data), digest, "sent"))
    _event(db, scope, actor, "RecommendationSent", {"recommendation_id": rid, "judgment_revision": data["judgment_revision"], "executor_task_id": data["executor_task_id"]})
    return data


def _feedback(db, scope, actor, args):
    version = _version(args)
    fid = _id(args.get("id"))
    # A receipt replay is allowed only for identical, same-scope input and actor.
    request = dict(args, actor=actor)
    digest = _digest(request)
    old = db.execute("SELECT * FROM core_feedback WHERE scope=? AND id=?", (scope, fid)).fetchone()
    if old:
        if old["request_hash"] != digest:
            raise ValueError("idempotency conflict")
        _live_recommendation(db, scope, args.get("recommendation_id"))
        return json.loads(old["data"])
    rec = _live_recommendation(db, scope, args.get("recommendation_id"))
    if any(args.get(k) != rec[k] for k in ("judgment_revision", "executor_task_id", "expected_check")) or _version(rec) != version:
        raise ValueError("feedback task, revision or check mismatch")
    acceptance = args.get("acceptance")
    reported = args.get("outcome", "unverified")
    attribution = args.get("attribution", "unknown")
    if acceptance not in ("accepted", "rejected", "corrected", "ignored") or reported not in ("unverified", "success", "failure"):
        raise ValueError("invalid feedback labels")
    if attribution not in ("code", "environment", "unknown"):
        raise ValueError("invalid attribution")
    ids = _ids(args.get("evidence_ids", []))
    evidence = _evidence_set(db, scope, ids, version)
    outcome = "unverified"
    if reported != "unverified":
        matches = [e for e in evidence if e["source_kind"] == "ci" and
                   e["locator"].get("check") == rec["expected_check"] and
                   e["locator"].get("conclusion") == reported and
                   e.get("attribution", "unknown") != "environment"]
        if matches and attribution != "environment":
            outcome = reported
    data = dict(version, id=fid, recommendation_id=rec["id"], judgment_revision=rec["judgment_revision"],
                executor_task_id=rec["executor_task_id"], acceptance=acceptance, reported_outcome=reported,
                outcome=outcome, expected_check=rec["expected_check"], evidence_ids=ids,
                attribution=attribution, actor=actor, observed_at=time.time(), correction=args.get("correction", ""),
                delivery_state="feedback_recorded", execution_authorized=False)
    # CI success/failure is a measured check outcome, not causal evidence that
    # following (or rejecting) this recommendation produced that outcome.
    data["check_attribution"] = attribution
    data["advice_attribution"] = ("not_applicable_not_adopted" if acceptance in ("rejected", "ignored")
                                  else "unverified_no_causal_evidence")
    if not isinstance(data["correction"], str) or len(data["correction"]) > 20000:
        raise ValueError("invalid correction")
    db.execute("INSERT INTO core_feedback VALUES(?,?,?,?)", (scope, fid, _json(data), digest))
    if acceptance == "corrected":
        jid, revision = _split_revision(rec["judgment_revision"])
        db.execute("UPDATE core_judgments SET status='needs_evidence' WHERE scope=? AND judgment_id=? AND revision=? AND status='active'", (scope, jid, revision))
    _event(db, scope, actor, "OutcomeRecorded", {"feedback_id": fid, "recommendation_id": rec["id"], "judgment_revision": rec["judgment_revision"], "acceptance": acceptance, "outcome": outcome})
    return data


def _events(db, scope, args):
    cursor = _integer(args.get("after_cursor", 0), "cursor")
    limit = _integer(args.get("limit", 100), "limit", 1, 500)
    rows = db.execute("SELECT * FROM core_events WHERE scope=? AND seq>? ORDER BY seq LIMIT ?", (scope, cursor, limit + 1)).fetchall()
    events = [{"seq": r["seq"], "event_id": r["event_id"], "type": r["type"], "payload": json.loads(r["payload"]),
               "scope": scope, "recorded_at": r["recorded_at"], "schema_version": 1} for r in rows[:limit]]
    return {"events": events, "cursor": events[-1]["seq"] if events else cursor, "has_more": len(rows) > limit}


def _feedback_receipt(db, scope, actor, args):
    """Recover a lost ACK, never recover revoked material or execution authority."""
    row = db.execute("SELECT data FROM core_feedback WHERE scope=? AND id=?", (scope, _id(args.get("id")))).fetchone()
    if row is None:
        raise ValueError("feedback receipt unavailable")
    data = json.loads(row["data"])
    if data["actor"] != actor or any(data[k] != args.get(k) for k in ("recommendation_id", "judgment_revision", "executor_task_id")):
        raise ValueError("feedback receipt unavailable")
    receipt = {key: data[key] for key in ("id", "recommendation_id", "judgment_revision", "executor_task_id", "acceptance", "outcome")}
    receipt.update(delivery_state="feedback_recorded", receipt_only=True, execution_authorized=False, current_authority=False)
    return receipt


def reconcile_source(db, scope, actor, repo, ref):
    """Invalidate stale authority after an authenticated registry transition.

    This is a deterministic review request, not an inferred new judgment. The
    caller includes it in the registry transaction. Reads also gate independently
    so delayed processing cannot leave stale authority usable in the meantime.
    """
    _id(repo)
    _text(ref, 300)
    affected = []
    rows = db.execute("SELECT * FROM core_judgments WHERE scope=? AND status IN ('active','candidate')", (scope,)).fetchall()
    for row in rows:
        data = json.loads(row["data"])
        if data["repo"] != repo or data["ref"] != ref:
            continue
        try:
            _evidence_set(db, scope, data["supports"] + data["contradicts"], _version(data))
        except ValueError:
            db.execute("UPDATE core_judgments SET status='needs_evidence' WHERE scope=? AND judgment_id=? AND revision=?",
                       (scope, row["judgment_id"], row["revision"]))
            affected.append("{}@{}".format(row["judgment_id"], row["revision"]))
    if affected:
        _event(db, scope, actor, "SourceChanged", {"repo": repo, "ref": ref, "judgment_revisions": affected, "status": "needs_evidence"})
    return {"invalidated": len(affected), "judgment_revisions": affected}


def _context(db, scope, args):
    version = _version(args)
    budget = _integer(args.get("budget", 16000), "budget", 1, 100000)
    task = args.get("executor_task_id")
    if task is not None:
        _id(task)
    judgments, refs, partial, briefs = [], {}, [], []
    try:
        _current_binding(db, scope, **version)
    except ValueError:
        return {"as_of": time.time(), "brief": "", "briefs": [], "active_judgments": [], "recommendations": [],
                "evidence_refs": [], "open_questions": ["Source is unavailable or not current"],
                "partial_sources": ["source_unavailable"], "partial": True,
                "cursor": db.execute("SELECT COALESCE(MAX(seq),0) FROM core_events WHERE scope=?", (scope,)).fetchone()[0], **version}
    used = 0
    for row in db.execute("SELECT * FROM core_judgments WHERE scope=? AND status='active' ORDER BY judgment_id,revision", (scope,)).fetchall():
        stored = json.loads(row["data"])
        if _version(stored) != version:
            continue
        try:
            item = get_live_judgment(db, scope, "{}@{}".format(row["judgment_id"], row["revision"]))
        except ValueError:
            partial.append("judgment_unavailable")
            continue
        brief = _live_brief(db, scope, item)
        if brief is None:
            partial.append('brief_unavailable')
        cost = len(_json(item)) + (len(_json(brief)) + len(brief['text']) if brief else 0)
        if used + cost > budget:
            partial.append("context_budget")
            continue
        used += cost
        for evidence in item.pop("evidence_refs"):
            refs[evidence["id"]] = evidence
        judgments.append(item)
        if brief is not None:
            briefs.append(brief)
    recommendations = []
    included = {j["judgment_revision"] for j in judgments}
    for row in db.execute("SELECT id FROM core_recommendations WHERE scope=? ORDER BY id", (scope,)).fetchall():
        try:
            rec = _live_recommendation(db, scope, row["id"])
        except ValueError:
            continue
        if rec["judgment_revision"] not in included or (task is not None and rec["executor_task_id"] != task):
            continue
        cost = len(_json(rec))
        if used + cost > budget:
            partial.append("context_budget")
            continue
        used += cost
        recommendations.append(rec)
    questions = []
    for row in db.execute("SELECT * FROM core_judgments WHERE scope=? AND status='needs_evidence' ORDER BY judgment_id,revision", (scope,)):
        data = json.loads(row["data"])
        if data["repo"] == version["repo"] and data["ref"] == version["ref"]:
            questions.append({"judgment_id": row["judgment_id"], "judgment_revision": "{}@{}".format(row["judgment_id"], row["revision"]),
                              "status": "needs_evidence", "reason": "source_or_evidence_changed"})
    if questions:
        partial.append("judgment_needs_evidence")
    cursor = db.execute("SELECT COALESCE(MAX(seq),0) FROM core_events WHERE scope=?", (scope,)).fetchone()[0]
    return {"as_of": time.time(), "brief": "\n".join(b['text'] for b in briefs), "briefs": briefs,
            "active_judgments": judgments, "recommendations": recommendations, "evidence_refs": list(refs.values()),
            "open_questions": questions or ([] if judgments else ["No current evidence-backed judgment available"]),
            "partial_sources": sorted(set(partial)), "partial": bool(partial), "cursor": cursor, **version}


def dispatch(db, scope, actor, op, args):
    """Operate within a server-derived scope. The service enforces operation ACLs."""
    _text(scope, 4096)
    _text(actor, 300)
    if not isinstance(args, dict):
        raise ValueError("arguments must be an object")
    if "scope" in args and args["scope"] != scope:
        raise ValueError("scope is server-owned")
    operations = {
        "evidence.record": _record_evidence, "evidence.revoke": _revoke_evidence,
        "judgment.propose": _propose, "judgment.publish": _publish,
        "recommendation.send": _recommend, "feedback.record": _feedback,
    }
    if op in operations:
        return operations[op](db, scope, actor, args)
    if op == "evidence.get":
        return get_evidence(db, scope, args.get("id"))
    if op == "judgment.explain":
        return _explain(db, scope, args)
    if op == "context.get":
        return _context(db, scope, args)
    if op == "events.list":
        return _events(db, scope, args)
    if op == "feedback.receipt":
        return _feedback_receipt(db, scope, actor, args)
    raise ValueError("unsupported core operation")
