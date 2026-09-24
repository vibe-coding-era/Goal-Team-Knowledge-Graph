#!/usr/bin/env python3
"""Host-side authoring driver for the GTKG V0.4 knowledge-quality chain.

GTKG Core deliberately owns no network and no LLM SDK: it emits a job packet and
gates the proposal, the two independent reviews and the acceptance. This script
is the *host* half of that contract. It drives the public CLI, calls a real model
for the authoring and for two independent reviews, and hands every artefact back
through the Core gates so nothing here can write canonical knowledge directly.

The API key is read from the environment only; it is never written to disk.
"""
from __future__ import annotations

import datetime
import hashlib
import re as _re
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
import uuid
from pathlib import Path

GTKG = os.environ.get("GTKG_BIN", "/Users/Rou/dev_projects/GTKG/develops/v0.4/target/debug/gtkg")
# The authorized root is the process working directory, and the source, the host
# inputs and every produced bundle must live under it. The workspace therefore
# defaults to the current directory; GTKG_WORKSPACE overrides it for ad-hoc runs.
# The path is resolved because /tmp is a symlink to /private/tmp on macOS and
# Core compares canonical roots lexically.
WS = Path(os.environ.get("GTKG_WORKSPACE") or os.getcwd()).resolve()
STATE = WS / ".gtkg" / "host" / "state.json"
def _run_config_path() -> Path:
    """GTKG_RUN_CONFIG wins, then a workspace-root file, then the internal one."""
    override = os.environ.get("GTKG_RUN_CONFIG")
    if override:
        return Path(override)
    for candidate in (WS / "gtkg-run.json", WS / ".gtkg" / "host" / "run-config.json"):
        if candidate.exists():
            return candidate
    return WS / "gtkg-run.json"


RUN_CONFIG = _run_config_path()
API = "https://api.deepseek.com/chat/completions"
MODEL = os.environ.get("GTKG_AUTHOR_MODEL", "deepseek-flash")
REV = "gtkg.knowledge-quality/v0.4-r1"


def config() -> dict:
    """Per-repository run configuration.

    Everything that differs between targets (commit, windows, understanding
    items, reviewer ids) lives here so the same driver can be scheduled against
    any number of repositories.
    """
    if not RUN_CONFIG.exists():
        raise SystemExit(f"run config not found: {RUN_CONFIG}")
    return json.loads(RUN_CONFIG.read_text())


def sha256_bytes(b: bytes) -> str:
    return "sha256:" + hashlib.sha256(b).hexdigest()


def sha256_file(p: Path) -> str:
    return sha256_bytes(p.read_bytes())


def line_window(repo: Path, rel: str, first: int, last: int) -> dict:
    """Byte span for an inclusive 1-based line window.

    Large files never enter the context whole: the job packet only carries the
    windows the author is allowed to reason about, and any implementation outside
    them must not be written up as known.
    """
    data = (repo / rel).read_bytes()
    lines = data.split(b"\n")
    start = sum(len(l) + 1 for l in lines[: first - 1])
    end = start + sum(len(l) + 1 for l in lines[first - 1 : last])
    end = min(end, len(data))
    return {"byte_start": start, "byte_end": end, "line_start": first, "line_end": last}


def v2op(op: str, profile: str, payload: dict) -> dict:
    """Run one v2 operation. --strict-exit makes a Core rejection a hard failure."""
    req = {
        "protocol_version": "gtkg.protocol/v2",
        "operation_id": op,
        "request_id": f"host-{uuid.uuid4().hex[:12]}",
        "payload": payload,
    }
    proc = subprocess.run(
        [GTKG, "--strict-exit", "v2-op", op, "--profile", profile,
         "--request", "-", "--output", "json"],
        input=json.dumps(req).encode(),
        capture_output=True,
    )
    if proc.returncode != 0:
        raise SystemExit(f"{op} failed (exit {proc.returncode}):\n"
                         f"stdout={proc.stdout.decode()[:2000]}\n"
                         f"stderr={proc.stderr.decode()[:2000]}")
    out = json.loads(proc.stdout)
    if "error" in out:
        raise SystemExit(f"{op} rejected: {json.dumps(out['error'], indent=2)}")
    return out["result"]


def artifact(payload: dict, ref: dict) -> dict:
    return {"payload_revision": REV, "workspace_root": str(WS), "artifact_ref": ref}


def write_host_input(name: str, value) -> dict:
    """Stage one host-side JSON input and return its FileReceiptRef."""
    d = WS / ".gtkg" / "host"
    d.mkdir(parents=True, exist_ok=True)
    p = d / name
    p.write_bytes(json.dumps(value, indent=2).encode())
    return {"path": f".gtkg/host/{name}", "sha256": sha256_file(p)}


def load_state() -> dict:
    return json.loads(STATE.read_text()) if STATE.exists() else {}


def save_state(s: dict) -> None:
    STATE.parent.mkdir(parents=True, exist_ok=True)
    STATE.write_text(json.dumps(s, indent=2))


# --------------------------------------------------------------------------- model


def call_model(messages: list[dict], *, max_tokens: int, json_mode: bool) -> tuple[str, dict]:
    key = os.environ.get("DEEPSEEK_API_KEY")
    if not key:
        raise SystemExit("DEEPSEEK_API_KEY is not set")
    body = {"model": MODEL, "messages": messages, "max_tokens": max_tokens, "temperature": 0}
    if json_mode:
        body["response_format"] = {"type": "json_object"}
    req = urllib.request.Request(
        API,
        data=json.dumps(body).encode(),
        headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=300) as r:
            payload = json.loads(r.read())
    except urllib.error.HTTPError as e:
        raise SystemExit(f"model call failed: {e.code} {e.read().decode()[:800]}")
    content = payload["choices"][0]["message"]["content"]
    usage = payload.get("usage", {})
    return content, {
        "input_tokens": usage.get("prompt_tokens"),
        "output_tokens": usage.get("completion_tokens"),
        "model": payload.get("model"),
        "id": payload.get("id"),
    }


def extract_json(text: str) -> dict:
    """Accept a bare object, a fenced block, or one with trailing commas.

    A trailing comma is a common model defect and not a semantic problem, so it
    is repaired rather than failing the run. Anything else raises ValueError so
    the caller can re-prompt instead of aborting the whole pipeline.
    """
    t = text.strip()
    if t.startswith("```"):
        t = t.split("```")[1]
        if t.startswith("json"):
            t = t[4:]
        t = t.strip()
    start = t.find("{")
    end = t.rfind("}")
    if start < 0 or end < 0:
        raise ValueError(f"model did not return a JSON object: {text[:200]!r}")
    body = t[start:end + 1]
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        repaired = re.sub(r",(\s*[}\]])", r"\1", body)
        try:
            return json.loads(repaired)
        except json.JSONDecodeError as e:
            raise ValueError(f"model returned unparseable JSON: {e}") from e


# ------------------------------------------------------------------------ stages


def stage_capture(state: dict) -> None:
    c = config()
    r = v2op("source.capture", "core", {
        "payload_revision": REV,
        "repository_id": c["repo_id"],
        "source_root": str(WS / c["source_root"]),
        "source_commit": c["source_commit"],
        "expected_tree": c["expected_tree"],
        "output_path": str(WS / ".gtkg" / "source-snapshots" / "archive"),
        "policy": {"revision": "full-tree-r1", "rules": [], "archive_binary": False},
    })
    state["ledger_ref"] =  r["artifact_ref"]
    state["capture"] = {k: r[k] for k in ("status", "snapshot_id", "source_tree", "total_paths")}
    print(f"  captured: {r['total_paths']} paths, snapshot {r['snapshot_id'][:16]}…")


def stage_analyze(state: dict) -> None:
    plan = v2op("analysis.plan", "core", artifact({}, need(state, "ledger_ref")))
    state["plan_ref"] = plan["artifact_ref"]
    print(f"  plan: {plan.get('status')} selected_files={plan.get('selected_files')}")
    build = v2op("analysis.build", "core", artifact({}, state["plan_ref"]))
    state["candidate_ref"] = build["artifact_ref"]
    print(f"  build: {build.get('status')} keys={sorted(build.keys())[:6]}")
    verify = v2op("analysis.verify", "core", artifact({}, state["candidate_ref"]))
    state["verified_ref"] =  verify["artifact_ref"]
    print(f"  verify: total_calls={verify.get('total_calls')} confirmed={verify.get('confirmed_calls')}")
    save_state(state)


def stage_job(state: dict) -> dict:
    c = config()
    windows = {p: tuple(r) for p, r in c["windows"].items()}
    source_spans = {
        rel: [line_window(WS / c["source_root"], rel, a, b)]
        for rel, (a, b) in windows.items()
    }
    job_req = {
        "verified_ref": need(state, "verified_ref"),
        "input": {
            "job_id": c["job_id"],
            "goal": "semantic_understanding",
            "source_paths": sorted(windows),
            "understanding_items": sorted(c["understanding_items"]),
            "prompt": c["prompt"],
            "policy": "grounded_semantic_understanding/v1",
            "max_context_units": c.get("max_context_units", 7500),
            "source_spans": source_spans,
        },
    }
    req_ref = write_host_input("job-request.json", job_req)
    r = v2op("summary.job.next", "authoring", artifact({}, req_ref))
    state["job_artifact"] =  r["job_artifact"]
    state["job_status"] = r["status"]
    save_state(state)
    return r["job_artifact"]


def main() -> None:
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    stage = args[0] if args else "all"
    # Stages must run in chain order: each one consumes the receipt the previous
    # one produced. "all" is the full chain; a single name reruns just that stage
    # and relies on the persisted state for everything before it.
    chain = [
        ("capture",  "[1]  source.capture",            stage_capture,       True),
        ("analyze",  "[2]  analysis.plan/build/verify", stage_analyze,      True),
        ("job",      "[3]  summary.job.next",          stage_job_report,    False),
        ("author",   "[4]  DeepSeek author",           stage_author,        True),
        ("proposal", "[5]  summary.proposal.submit",   stage_proposal,      True),
        ("review",   "[6]  verification.next + 2 independent reviews", stage_review_chain, True),
        ("accept",   "[7]  summary.accept.v2",         stage_accept,        True),
        ("views",    "[8]  deliverable.derive",        stage_views,         True),
        ("finalize", "[9]  build.finalize.v2",         stage_finalize,      True),
        ("verify",   "[10] bundle.verify",             stage_verify_bundle, False),
    ]
    known = {name for name, *_ in chain}
    if stage != "all" and stage not in known:
        raise SystemExit(f"unknown stage {stage!r}; expected all or one of {sorted(known)}")

    state = load_state()
    for name, label, fn, saves in chain:
        if stage not in (name, "all"):
            continue
        print(label)
        result = fn(state)
        if saves:
            save_state(state)
        if name == "job":
            job = result["job"]
            print(f"  status: {state['job_status']}")
            print(f"  job_digest: {job['job_digest']}")
            print(f"  context sources: {len(job['context'])}")
            for c in job["context"]:
                print(f"    - {c['path']}  span lines {c['span']['line_start']}.."
                      f"{c['span']['line_end']}  {len(c['text'])} chars")


def stage_job_report(state: dict) -> dict:
    """Run summary.job.next and return its job artifact for the caller to print."""
    return stage_job(state)


# ----------------------------------------------------------------------- authoring

AUTHOR_SYSTEM = """You are a senior engineer writing grounded project knowledge.
You may only state what the supplied source windows actually show. Never infer
behaviour from a name, a docstring or prior familiarity with the project.
Every claim must cite the exact line window you read it from."""

AUTHOR_TEMPLATE = """Project windows (the ONLY evidence you may use):

{windows}

Write knowledge that answers exactly these understanding items:
{items}

Return ONE JSON object:
{{
  "summary": "<3-6 sentence orientation for an engineer new to this project>",
  "claims": [
    {{
      "claim_id": "c1",
      "understanding_item": "<copy one of the items above verbatim>",
      "natural_language": "<one sentence stating what the code does>",
      "proposition": "<the same statement, stripped of hedging>",
      "epistemic": "direct",
      "citations": [{{"path": "<exact path>", "line_start": <int>, "line_end": <int>}}]
    }}
  ]
}}

Rules:
- Produce 4 to 8 claims. Cover all three understanding items.
- "line_start"/"line_end" must fall inside the windows above and must cover the
  lines you actually relied on.
- Cite only files from: {paths}
- Do not mention anything you cannot point at a line window for."""


def stage_author(state: dict) -> None:
    job = json.loads(json.dumps(need(state, "job_artifact")))["job"]
    windows = []
    for part in job["context"]:
        lo = part["span"]["line_start"]
        windows.append(f"### {part['path']} (lines {lo}-{part['span']['line_end']})")
        for i, line in enumerate(part["text"].split("\n")):
            windows.append(f"{lo + i:5d}| {line}")
    items = "\n".join(f"- {x}" for x in job["input"]["understanding_items"])
    user = AUTHOR_TEMPLATE.format(
        windows="\n".join(windows), items=items,
        paths=", ".join(job["input"]["source_paths"]),
    )
    windows_by_path = {}
    for part in job["context"]:
        a = part["span"]["line_start"]
        b = part["span"]["line_end"]
        windows_by_path.setdefault(part["path"], []).append((a, b))

    def citation_errors(cand: dict) -> list[str]:
        """Reject citations that leave the observed windows before Core sees them.

        Core fails closed on an unobserved window, so the driver must not burn a
        round trip on a citation that could never be admitted.
        """
        errs = []
        for c in cand.get("claims", []):
            for cit in c.get("citations", []):
                path = cit.get("path", "")
                spans = windows_by_path.get(path)
                if not spans:
                    errs.append(f"{path} is not an observed source path")
                    continue
                a, b = int(cit["line_start"]), int(cit["line_end"])
                if not any(a >= lo and b <= hi for lo, hi in spans):
                    allowed = ", ".join(f"{lo}-{hi}" for lo, hi in spans)
                    errs.append(f"{path} lines {a}-{b} is outside the observed window(s) {allowed}")
        return errs

    text = usage = None
    raw = None
    for attempt in range(1, 4):
        messages = [{"role": "system", "content": AUTHOR_SYSTEM},
                    {"role": "user", "content": user}]
        if attempt > 1:
            messages.append({"role": "user", "content":
                "Your previous answer was rejected:\n- " + "\n- ".join(errors) +
                "\nReturn the corrected JSON object. Every citation must fall inside the "
                "windows listed above."})
        text, usage = call_model(messages, max_tokens=8000, json_mode=True)
        try:
            raw = extract_json(text)
        except ValueError as e:
            errors = [str(e)]
            print(f"  author attempt {attempt} unparseable: {e}")
            continue
        errors = citation_errors(raw)
        if not errors:
            break
        print(f"  author attempt {attempt} rejected: {errors[0]}")
    else:
        raise SystemExit("author could not produce in-window citations: " + "; ".join(errors))
    # The execution record must carry a real transcript: for a host-observed model
    # run the transcript is what was actually sent and returned, never a summary.
    state["author_transcript"] =  json.dumps({
        "model": MODEL,
        "request_messages": [
            {"role": "system", "content": AUTHOR_SYSTEM},
            {"role": "user", "content": user},
        ],
        "response_text": text,
        "usage": usage,
    }, indent=2)
    author_id = config().get("author_id", "deepseek-flash-author")
    repo = WS / config()["source_root"]
    file_digests = {p: sha256_file(repo / p) for p in job["input"]["source_paths"]}
    allowed = set(job["input"]["source_paths"])
    items_set = set(job["input"]["understanding_items"])
    claims = []
    for i, c in enumerate(raw["claims"], 1):
        item = c["understanding_item"].strip()
        if item not in items_set:
            # tolerate whitespace/case drift only; never invent an item
            match = next((x for x in items_set if x.lower() == item.lower()), None)
            if match is None:
                raise SystemExit(f"author returned an unknown understanding item: {item!r}")
            item = match
        cits = []
        for cit in c["citations"]:
            path = cit["path"].strip()
            if path not in allowed:
                raise SystemExit(f"citation outside job context: {path!r}")
            a, b = int(cit["line_start"]), int(cit["line_end"])
            span = line_window(repo, path, a, b)
            excerpt = (repo / path).read_bytes()[span["byte_start"]:span["byte_end"]].decode()
            cits.append({"path": path, "file_sha256": file_digests[path],
                         "span": span, "excerpt": excerpt})
        claims.append({
            "claim_id": c.get("claim_id") or f"c{i}",
            "understanding_item": item,
            "natural_language": c["natural_language"].strip(),
            "body": {"claim_kind": "interpretive",
                     "proposition": c["proposition"].strip(),
                     "epistemic": c.get("epistemic", "direct"),
                     "version_condition": config()["version_condition"]},
            "citations": cits,
        })
    candidate = {
        "author_id": author_id,
        "author_mode": "model_generated",
        "summary": raw["summary"].strip(),
        "claims": claims,
    }
    output_text = json.dumps(candidate, indent=2)
    state["candidate"] =  candidate
    state["author_usage"] =  usage
    state["author_output"] =  output_text
    save_state(state)
    print(f"  author: {len(claims)} claims, {len(output_text)} output bytes, "
          f"tokens in={usage['input_tokens']} out={usage['output_tokens']}")
    for c in claims:
        print(f"    - {c['claim_id']}: {c['natural_language'][:70]}")



# ---------------------------------------------------------------------- proposal

def stage_proposal(state: dict) -> None:
    job = need(state, "job_artifact")["job"]
    job_ref = write_host_input("job-artifact.json", need(state, "job_artifact"))
    state["job_ref"] = job_ref
    candidate = need(state, "candidate")
    output_text = need(state, "author_output")
    usage = need(state, "author_usage")
    transcript = need(state, "author_transcript")
    record = {
        "schema": "gtkg.qk.generation-execution-record/v1",
        "job_digest": job["job_digest"],
        "context_digest": job["context_digest"],
        "prompt_digest": job["prompt_digest"],
        "policy_digest": job["policy_digest"],
        "author_id": candidate["author_id"],
        "author_mode": candidate["author_mode"],
        "execution_evidence": "host_observed",
        "host_id": "dsh-host",
        "model_id": usage.get("model") or MODEL,
        "transcript": transcript,
        "transcript_digest": sha256_bytes(transcript.encode()),
        "output": output_text,
        "output_digest": sha256_bytes(output_text.encode()),
        "usage": {"input_tokens": usage["input_tokens"], "output_tokens": usage["output_tokens"]},
    }
    req_ref = write_host_input("proposal-request.json", {
        "job_ref": job_ref, "candidate": candidate, "execution_record": record,
    })
    r = v2op("summary.proposal.submit", "authoring", artifact({}, req_ref))
    state["proposal_ref"] =  r["artifact_ref"]
    state["proposal_state"] = r["status"]
    save_state(state)
    print(f"  proposal: status={r['status']} ref={r['artifact_ref']['path']}")


def stage_review_request(state: dict) -> None:
    r = v2op("summary.verification.next", "authoring", artifact({}, need(state, "proposal_ref")))
    state["claim_digests"] =  r["claims"]
    state["proposal_digest"] =  r["proposal_digest"]
    save_state(state)
    print(f"  verification.next: {r['status']}, claims={len(r['claims'])}")


REVIEW_SYSTEM = """You are an independent reviewer. You did not write this candidate and
you must not assume it is correct. For every claim decide whether the quoted
source bytes actually support the stated proposition."""

REVIEW_TEMPLATE = """You are reviewing a knowledge candidate against the raw source.

{claims}

For EACH claim id above, reply with a decision. Return ONE JSON object:
{{"decisions": [{{"claim_id": "<id>", "judgment": "supported"|"rejected"|"unknown",
                  "reason": "<one sentence tying the judgment to the quoted bytes>"}}]}}

Rules:
- Judge only from the quoted excerpt and the stated proposition.
- "supported" means the excerpt entails the proposition as written.
- If the proposition adds anything the excerpt does not show, say "rejected".
- Every claim id must appear exactly once."""


def stage_reviews(state: dict) -> None:
    candidate = need(state, "candidate")
    cits = {c["claim_id"]: c["citations"][0]["excerpt"] for c in candidate["claims"]}
    blocks = []
    for c in candidate["claims"]:
        blocks.append(
            f"[{c['claim_id']}] item: {c['understanding_item']}\n"
            f"  proposition: {c['body']['proposition']}\n"
            f"  excerpt ({cits[c['claim_id']] and c['citations'][0]['path']} "
            f"lines {c['citations'][0]['span']['line_start']}-{c['citations'][0]['span']['line_end']}):\n"
            f"```\n{cits[c['claim_id']]}\n```"
        )
    user = REVIEW_TEMPLATE.format(claims="\n\n".join(blocks))
    reviews = []
    for idx, reviewer in enumerate(config()["reviewer_ids"], 1):
        text, usage = call_model(
            [{"role": "system", "content": f"{REVIEW_SYSTEM}\nYour reviewer id is {reviewer}."},
             {"role": "user", "content": user}],
            max_tokens=6000, json_mode=True,
        )
        try:
            raw = extract_json(text)
            decisions_raw = raw["decisions"]
        except (ValueError, KeyError) as e:
            print(f"  reviewer {idx} returned unusable output ({e}); treating all as unknown")
            decisions_raw = []
        by_id = {d["claim_id"]: d for d in decisions_raw}
        decisions = []
        for cd in need(state, "claim_digests"):
            d = by_id.get(cd["claim_id"])
            if d is None:
                d = {"judgment": "unknown", "reason": "reviewer omitted this claim"}
            decisions.append({
                "claim_id": cd["claim_id"],
                "claim_digest": cd["claim_digest"],
                "judgment": d["judgment"],
                "reason": (d.get("reason") or "no reason given").strip(),
            })
        reviews.append({
            "reviewer_id": reviewer,
            "proposal_digest": need(state, "proposal_digest"),
            "decisions": decisions,
        })
        supported = sum(1 for d in decisions if d["judgment"] == "supported")
        print(f"  reviewer {idx} ({reviewer}): {supported}/{len(decisions)} supported "
              f"(in={usage['input_tokens']} out={usage['output_tokens']})")
        state[f"review_usage_{idx}"] = usage
    req_ref = write_host_input("review-request.json", {
        "proposal_ref": need(state, "proposal_ref"), "reviews": reviews,
    })
    r = v2op("summary.verification.submit", "authoring", artifact({}, req_ref))
    state["review_ref"] =  r["artifact_ref"]
    state["reviews"] = reviews
    save_state(state)
    print(f"  verification.submit: status={r['status']}")


def stage_review_chain(state: dict) -> None:
    """verification.next must run first: it produces the claim digests that every
    review decision has to bind."""
    stage_review_request(state)
    stage_reviews(state)


def need(state: dict, key: str) -> object:
    """Fail with the missing prerequisite instead of a bare KeyError."""
    if key not in state:
        raise SystemExit(
            f"state is missing {key!r}; run the earlier stages first "
            f"(current keys: {sorted(k for k in state if not k.startswith('review_usage'))})"
        )
    return state[key]


def stage_accept(state: dict) -> None:
    r = v2op("summary.accept.v2", "authoring", artifact({}, need(state, "review_ref")))
    state["accepted_ref"] =  r["artifact_ref"]
    state["okf_ref"] = r["okf_ref"]
    state["accepted"] = r
    save_state(state)
    print(f"  accept: status={r['status']} knowledge_ready={r['knowledge_ready']}")
    print(f"    OKF document -> {r['okf_ref']['path']}  ({r['okf_ref']['sha256'][:26]}…)")



# ---------------------------------------------------------------- views and bundle

def stage_views(state: dict) -> None:
    job = need(state, "job_artifact")["job"]
    items = job["input"]["understanding_items"]
    views = ["overview", "key_flows", "design_decisions", "agent_task_guide", "project_rules"]
    req = {
        "verified_ref": need(state, "verified_ref"),
        "input": {
            "project_name": config()["project_name"],
            "inventory_id": config()["inventory_id"],
            "understanding_items": [
                # Core keys the coverage denominator by item_id but looks claims up
                # by their understanding_item text, so the item_id must BE the
                # question. Otherwise coverage silently reports zero.
                {"item_id": q, "question": q,
                 "view": views[i % len(views)], "module_id": None, "aspect": None}
                for i, q in enumerate(items, 1)
            ],
            "modules": config()["modules"],
        },
        "accepted_refs": [need(state, "accepted_ref")],
    }
    ref = write_host_input("views-request.json", req)
    # deliverable.derive belongs to the templates profile, not authoring.
    r = v2op("deliverable.derive", "templates", artifact({}, ref))
    state["views_ref"] =  r["artifact_ref"]
    v = r["views"]
    print(f"  views: status={r['status']}")
    print(f"    project={v['project_name']} readiness={v['readiness_scope']} "
          f"knowledge_ready={v['knowledge_ready']} views={len(v['views'])} modules={len(v['modules'])}")
    cov = v["coverage"]
    print(f"    coverage: {json.dumps(cov)[:240]}")
    save_state(state)


def stage_finalize(state: dict) -> None:
    """Finalize one immutable bundle.

    A bundle destination is immutable and a re-run produces different bytes
    (the author is a model), so a fixed name collides on the second run. Each
    run therefore gets its own stamped directory and a `latest.json` pointer
    records which one is current.
    """
    c = config()
    base = c["bundle_name"]
    if c.get("bundle_name_strategy", "run_stamped") == "run_stamped":
        stamp = datetime.datetime.now(datetime.UTC).strftime("%Y%m%dT%H%M%SZ")
        name = f"{base}-{stamp}"
    else:
        name = base
    state["bundle_name"] = name
    req = {
        "verified_ref": need(state, "verified_ref"),
        "accepted_refs": [need(state, "accepted_ref")],
        "views_ref": need(state, "views_ref"),
        "output_path": str(WS / ".gtkg" / "qk" / "bundles" / name),
        "predecessor": None,
    }
    ref = write_host_input("finalize-request.json", req)
    r = v2op("build.finalize.v2", "authoring", artifact({}, ref))
    state["bundle"] =  r
    save_state(state)
    print(f"  finalize: {json.dumps({k: v for k, v in r.items() if k != 'runtime'})[:400]}")


def stage_verify_bundle(state: dict) -> None:
    b = need(state, "bundle")["bundle"]
    r = v2op("bundle.verify", "lifecycle", {
        "payload_revision": REV,
        "workspace_root": b["workspace_root"],
        "artifact_ref": b["manifest_ref"],
    })
    # The ledger lets the scheduler skip a workspace whose pinned commit already
    # produced a verified bundle, so an interval timer does not burn a model call
    # every time it fires.
    import datetime as _dt, pathlib as _pl
    c = config()
    ledger = WS / ".gtkg" / "host" / "runs.json"
    history = json.loads(ledger.read_text()) if ledger.exists() else []
    history.append({
        "run_at_utc": _dt.datetime.now(_dt.UTC).isoformat(),
        "source_commit": c["source_commit"],
        "expected_tree": c["expected_tree"],
        "bundle_name": state.get("bundle_name"),
        "bundle_workspace_root": b["workspace_root"],
        "manifest_sha256": b["manifest_ref"]["sha256"],
        "verified_files": r.get("verified_files"),
        "knowledge_document": need(state, "okf_ref")["path"],
        "status": r.get("status"),
    })
    ledger.parent.mkdir(parents=True, exist_ok=True)
    ledger.write_text(json.dumps(history, indent=2))
    (WS / ".gtkg" / "qk" / "bundles" / "latest.json").write_text(json.dumps(history[-1], indent=2))
    print(f"  ledger: {ledger} ({len(history)} run(s))")
    print(f"  bundle.verify: {json.dumps({k: v for k, v in r.items() if k != 'runtime'})[:400]}")


if __name__ == "__main__":
    main()
