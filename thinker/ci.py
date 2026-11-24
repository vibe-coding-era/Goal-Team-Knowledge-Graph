"""Read a completed public GitHub Actions job from its owning repository."""

import hashlib
import json
import re
from datetime import datetime
import urllib.error
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def read_api(url):
    client = urllib.request.build_opener(NoRedirect)
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "gtkg-thinker/0.5",
        },
    )
    try:
        with client.open(request, timeout=4) as response:
            body = response.read(1024 * 1024 + 1)
            if len(body) > 1024 * 1024:
                raise ValueError("CI response exceeds budget")
            data = json.loads(body)
            if not isinstance(data, dict):
                raise ValueError("invalid CI response")
            return data
    except OSError:
        raise ValueError("GitHub Actions unavailable") from None


def verify_job(origin, job_id, binding):
    # Derive the host/repository from registered Git, never a request-provided API URL.
    remote = re.fullmatch(
        r"(?:https://github\.com/|git@github\.com:)([A-Za-z0-9_-]+/[A-Za-z0-9_.-]+)",
        origin,
    )
    if not remote or type(job_id) is not int or not 0 < job_id < 2**63:
        raise ValueError("registered GitHub origin and numeric job ID required")
    slug = remote.group(1).removesuffix(".git")
    if slug.split("/")[1] in ("", ".", ".."):
        raise ValueError("invalid GitHub repository")
    base = "https://api.github.com/repos/" + slug + "/actions"
    job = read_api(f"{base}/jobs/{job_id}")
    revision = binding["source_revision"]
    run_id = job.get("run_id")
    if (
        job.get("id") != job_id
        or job.get("head_sha") != revision
        or job.get("status") != "completed"
        or job.get("conclusion") not in {"success", "failure", "cancelled"}
        or not isinstance(job.get("name"), str)
        or not 0 < len(job["name"]) <= 300
        or type(run_id) is not int
        or not 0 < run_id < 2**63
    ):
        raise ValueError("CI job is incomplete or targets another revision")
    run = read_api(f"{base}/runs/{run_id}")
    branch = run.get("head_branch")
    if (
        not isinstance(branch, str)
        or not branch
        or binding["ref"] != "refs/heads/" + branch
    ):
        raise ValueError("CI push branch does not match the registered ref")
    if (
        run.get("id") != run_id
        or run.get("event") != "push"
        or run.get("head_sha") != revision
        or run.get("repository", {}).get("full_name", "").casefold() != slug.casefold()
    ):
        raise ValueError("CI run repository or revision mismatch")
    try:
        finished = datetime.fromisoformat(job["completed_at"].replace("Z", "+00:00"))
        if finished.tzinfo is None:
            raise ValueError("missing time zone")
    except (KeyError, ValueError, AttributeError):
        raise ValueError("missing CI completion timestamp") from None
    locator = {
        "run_id": str(run_id),
        "job_id": str(job_id),
        "check": job["name"],
        "conclusion": job["conclusion"],
        "repo": slug,
        "commit": revision,
        "ref": binding["ref"],
    }
    text = json.dumps(locator, sort_keys=True, ensure_ascii=False)
    fingerprint = hashlib.sha256(text.encode()).hexdigest()
    return dict(
        binding,
        id="ci-" + fingerprint,
        source_kind="ci",
        text=text,
        content_hash="sha256:" + fingerprint,
        locator=locator,
        attribution="unknown",
        assurance="github_actions_verified",
        occurred_at=finished.timestamp(),
        source_uri=f"https://github.com/{slug}/actions/runs/{run_id}/job/{job_id}",
    )
