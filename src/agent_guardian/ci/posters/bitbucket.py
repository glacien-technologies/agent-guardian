"""Bitbucket Cloud PR-comment + Code Insights poster (CI/CD feature).

Uses the Bitbucket Cloud REST API v2 to:

* **Upsert** a single AgentGuardian comment per pull request — list the PR's
  comments, find the first whose raw-markdown body carries the AgentGuardian
  marker, and PUT it in place; if none is found, POST a new one. This keeps a
  noisy PR to one always-current AgentGuardian comment, exactly like the GitHub
  poster.
* **Publish a Code Insights report** against the build commit — PUT a report
  keyed by a *fixed* report id (``agentguardian-scan``) so re-runs replace the
  prior report idempotently rather than piling up one per push, with a
  ``PASS``/``FAIL`` result and a few key metrics, then POST one annotation per
  finding (severity mapped to ``LOW``/``MEDIUM``/``HIGH``/``CRITICAL``).

Context is read from the standard Bitbucket Pipelines environment:

* ``BITBUCKET_WORKSPACE``  — the workspace id/slug (``$BITBUCKET_WORKSPACE``).
* ``BITBUCKET_REPO_SLUG``  — the repository slug (``$BITBUCKET_REPO_SLUG``).
* ``BITBUCKET_PR_ID``      — the pull-request id (``$BITBUCKET_PR_ID``); only
  required for ``upsert`` (comments live on a PR).
* ``BITBUCKET_COMMIT``     — the build commit sha (``$BITBUCKET_COMMIT``); only
  required for ``post_code_insights`` (reports live on a commit).

Authentication is either a Bearer token (``BITBUCKET_TOKEN`` — a repository or
workspace access token), or HTTP Basic with ``BITBUCKET_USERNAME`` +
``BITBUCKET_APP_PASSWORD`` (an app password). Bearer takes precedence.

Code Insights is best-effort: a non-2xx response is logged and swallowed so a
flaky reporting call can never fail the build on its own (the gate already ran).
"""

from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING

import httpx

from agent_guardian.ci.posters.base import Poster, PosterError

if TYPE_CHECKING:  # ``UseClientDefault`` is the sentinel type, not re-exported.
    from httpx._client import UseClientDefault
from agent_guardian.core.gate import evaluate_gate
from agent_guardian.models.scan import Scan
from agent_guardian.models.severity import Severity, humanise_band

__all__ = ["BitbucketPoster", "get_poster"]

_LOG = logging.getLogger(__name__)

_DEFAULT_API_URL = "https://api.bitbucket.org"
_TIMEOUT = httpx.Timeout(15.0)

# A FIXED report key (not a timestamp): PUTting the same key replaces the prior
# report so a PR's commit carries exactly one AgentGuardian report, however many
# times the pipeline re-runs.
_REPORT_KEY = "agentguardian-scan"

# Bitbucket Code Insights annotation severities.
_SEVERITY_TO_INSIGHT = {
    Severity.CRITICAL: "CRITICAL",
    Severity.HIGH: "HIGH",
    Severity.MEDIUM: "MEDIUM",
    Severity.LOW: "LOW",
}

# Cap how many annotations we POST — Bitbucket limits annotations per report
# (1000) and a wall of low-severity rows is noise. Highest-severity first.
_MAX_ANNOTATIONS = 100


def _severity_rank(finding_severity: Severity) -> int:
    """Sort key: CRITICAL first, LOW last."""
    order = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
    }
    return order.get(finding_severity, 99)


class BitbucketPoster(Poster):
    """Upsert a PR comment and publish a Code Insights report on Bitbucket Cloud."""

    def __init__(
        self,
        *,
        workspace: str,
        repo_slug: str,
        pr_id: int | None = None,
        commit: str | None = None,
        token: str | None = None,
        username: str | None = None,
        app_password: str | None = None,
        api_url: str = _DEFAULT_API_URL,
        client: httpx.Client | None = None,
    ) -> None:
        if not workspace:
            raise PosterError("BITBUCKET_WORKSPACE is not set")
        if not repo_slug:
            raise PosterError("BITBUCKET_REPO_SLUG is not set")
        if not token and not (username and app_password):
            raise PosterError(
                "no Bitbucket credentials -- set BITBUCKET_TOKEN (Bearer) or "
                "BITBUCKET_USERNAME + BITBUCKET_APP_PASSWORD (basic)"
            )
        self._workspace = workspace
        self._repo_slug = repo_slug
        self._pr_id = pr_id
        self._commit = commit
        self._token = token
        self._username = username
        self._app_password = app_password
        self._api_url = api_url.rstrip("/")
        # An injected client lets tests mock httpx without monkeypatching env.
        self._client = client

    # -- shared HTTP plumbing ------------------------------------------------

    @property
    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json"}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        return headers

    @property
    def _auth(self) -> httpx.BasicAuth | UseClientDefault:
        # Bearer takes precedence (carried in the Authorization header); only
        # fall back to HTTP Basic when no token. ``USE_CLIENT_DEFAULT`` is the
        # httpx sentinel for "send no per-request auth".
        if not self._token and self._username and self._app_password:
            return httpx.BasicAuth(self._username, self._app_password)
        return httpx.USE_CLIENT_DEFAULT

    def _repo_base(self) -> str:
        return f"{self._api_url}/2.0/repositories/{self._workspace}/{self._repo_slug}"

    # -- PR comment upsert ---------------------------------------------------

    def _comments_url(self) -> str:
        return f"{self._repo_base()}/pullrequests/{self._pr_id}/comments"

    def upsert(self, body: str) -> None:
        """Find the marker-bearing PR comment and PUT it, else POST a new one."""
        if self._pr_id is None:
            raise PosterError("BITBUCKET_PR_ID is not set -- a PR comment needs a pull-request id")
        owns_client = self._client is None
        client = self._client or httpx.Client(timeout=_TIMEOUT)
        payload = {"content": {"raw": body}}
        try:
            existing_id = self._find_existing(client)
            if existing_id is not None:
                resp = client.put(
                    f"{self._comments_url()}/{existing_id}",
                    headers=self._headers,
                    auth=self._auth,
                    json=payload,
                )
            else:
                resp = client.post(
                    self._comments_url(),
                    headers=self._headers,
                    auth=self._auth,
                    json=payload,
                )
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            raise PosterError(f"Bitbucket comment upsert failed: {exc}") from exc
        finally:
            if owns_client:
                client.close()

    def _find_existing(self, client: httpx.Client) -> int | None:
        """Return the id of this PR's first AgentGuardian comment, or ``None``."""
        url: str | None = self._comments_url()
        params: dict[str, int] | None = {"pagelen": 100}
        while url:
            resp = client.get(url, headers=self._headers, auth=self._auth, params=params)
            resp.raise_for_status()
            doc = resp.json()
            if not isinstance(doc, dict):
                return None
            values = doc.get("values")
            if isinstance(values, list):
                for comment in values:
                    if not isinstance(comment, dict):
                        continue
                    content = comment.get("content")
                    raw = content.get("raw") if isinstance(content, dict) else None
                    if isinstance(raw, str) and self.marker in raw:
                        comment_id = comment.get("id")
                        if isinstance(comment_id, int):
                            return comment_id
            # Follow Bitbucket's cursor-style ``next`` link if present.
            next_url = doc.get("next")
            url = next_url if isinstance(next_url, str) and next_url else None
            params = None  # the next link already carries its query string
        return None

    # -- Code Insights -------------------------------------------------------

    def _report_url(self) -> str:
        return f"{self._repo_base()}/commit/{self._commit}/reports/{_REPORT_KEY}"

    def _annotations_url(self) -> str:
        return f"{self._report_url()}/annotations"

    def _build_report(self, scan: Scan, *, passed: bool) -> dict[str, object]:
        """Build the Code Insights report body for ``scan``."""
        counts = scan.findings_summary()
        if scan.scoring_valid:
            aivss_label = f"{scan.aivss}/100 ({humanise_band(scan.band)})"
        else:
            aivss_label = "n/a (not evaluated)"
        return {
            "title": "AgentGuardian",
            "report_type": "SECURITY",
            "reporter": "agent-guardian",
            "result": "PASSED" if passed else "FAILED",
            "details": (
                f"AIVSS {aivss_label} -- {len(scan.findings)} finding(s) "
                f"across {len(scan.asi_scores)} ASI categories."
            ),
            "data": [
                {"title": "AIVSS", "type": "NUMBER", "value": scan.aivss},
                {"title": "Findings", "type": "NUMBER", "value": len(scan.findings)},
                {"title": "Critical", "type": "NUMBER", "value": counts.get("critical", 0)},
                {"title": "High", "type": "NUMBER", "value": counts.get("high", 0)},
                {"title": "Medium", "type": "NUMBER", "value": counts.get("medium", 0)},
                {"title": "Low", "type": "NUMBER", "value": counts.get("low", 0)},
            ],
        }

    def _build_annotations(self, scan: Scan) -> list[dict[str, object]]:
        """Build one annotation per finding (highest-severity first, capped)."""
        ranked = sorted(scan.findings, key=lambda f: _severity_rank(f.severity))
        annotations: list[dict[str, object]] = []
        for finding in ranked[:_MAX_ANNOTATIONS]:
            severity = _SEVERITY_TO_INSIGHT.get(finding.severity, "MEDIUM")
            annotations.append(
                {
                    # Stable per-finding external id so re-PUTting the report
                    # replaces, rather than duplicates, each annotation.
                    "external_id": f"agentguardian-{finding.id}",
                    "title": f"{finding.asi.value} -- {finding.probe_id}",
                    "annotation_type": "VULNERABILITY",
                    "summary": finding.summary,
                    "severity": severity,
                    "path": f"agentguardian/{finding.asi.value}.md",
                    "line": 1,
                    "result": "FAILED",
                }
            )
        return annotations

    def post_code_insights(self, scan: Scan, *, dry_run: bool = False) -> None:
        """Publish a Code Insights report + annotations for ``scan``.

        Best-effort: a non-2xx response (or a transport error) is logged and
        swallowed so a flaky reporting call never fails the build — the gate
        verdict has already been decided elsewhere. With ``dry_run`` nothing is
        sent; the report/annotation payloads are merely built (so the command
        can validate them).
        """
        gate = evaluate_gate(scan)
        report = self._build_report(scan, passed=gate.passed)
        annotations = self._build_annotations(scan)
        if dry_run:
            return
        if not self._commit:
            raise PosterError(
                "BITBUCKET_COMMIT is not set -- a Code Insights report needs a commit sha"
            )
        owns_client = self._client is None
        client = self._client or httpx.Client(timeout=_TIMEOUT)
        try:
            self._put_report(client, report)
            self._post_annotations(client, annotations)
        finally:
            if owns_client:
                client.close()

    def _put_report(self, client: httpx.Client, report: dict[str, object]) -> None:
        """PUT the Code Insights report; log+continue on failure."""
        try:
            resp = client.put(
                self._report_url(),
                headers=self._headers,
                auth=self._auth,
                json=report,
            )
            if resp.status_code >= 300:
                _LOG.warning(
                    "Bitbucket Code Insights report PUT returned %s: %s",
                    resp.status_code,
                    resp.text[:500],
                )
        except httpx.HTTPError as exc:
            _LOG.warning("Bitbucket Code Insights report PUT failed: %s", exc)

    def _post_annotations(self, client: httpx.Client, annotations: list[dict[str, object]]) -> None:
        """POST annotations one per finding; log+continue on each failure."""
        for annotation in annotations:
            try:
                external_id = annotation.get("external_id")
                resp = client.put(
                    f"{self._annotations_url()}/{external_id}",
                    headers=self._headers,
                    auth=self._auth,
                    json=annotation,
                )
                if resp.status_code >= 300:
                    _LOG.warning(
                        "Bitbucket annotation %s returned %s: %s",
                        external_id,
                        resp.status_code,
                        resp.text[:300],
                    )
            except httpx.HTTPError as exc:
                _LOG.warning("Bitbucket annotation POST failed: %s", exc)


def _env_pr_id() -> int | None:
    """Parse ``BITBUCKET_PR_ID`` into an int, or ``None`` if unset/malformed."""
    raw = os.environ.get("BITBUCKET_PR_ID")
    if not raw:
        return None
    try:
        return int(raw)
    except ValueError:
        return None


def get_poster() -> BitbucketPoster:
    """Build a :class:`BitbucketPoster` from the Bitbucket Pipelines environment."""
    workspace = os.environ.get("BITBUCKET_WORKSPACE", "")
    repo_slug = os.environ.get("BITBUCKET_REPO_SLUG", "")
    return BitbucketPoster(
        workspace=workspace,
        repo_slug=repo_slug,
        pr_id=_env_pr_id(),
        commit=os.environ.get("BITBUCKET_COMMIT"),
        token=os.environ.get("BITBUCKET_TOKEN"),
        username=os.environ.get("BITBUCKET_USERNAME"),
        app_password=os.environ.get("BITBUCKET_APP_PASSWORD"),
        api_url=os.environ.get("BITBUCKET_API_URL", _DEFAULT_API_URL),
    )
