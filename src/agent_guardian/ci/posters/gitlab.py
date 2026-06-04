"""GitLab MR-note poster (CI/CD feature).

Uses the GitLab REST API (v4) to upsert a single AgentGuardian note per merge
request. Context is read from the standard GitLab CI/CD environment:

* ``CI_API_V4_URL``          — API base (e.g. ``https://gitlab.com/api/v4``;
  self-managed instances set this to their own host).
* ``CI_PROJECT_ID``          — the numeric/path-encoded project id.
* ``CI_MERGE_REQUEST_IID``   — the merge-request *iid* (per-project, not global).
  Only present on ``merge_request_event`` pipelines.
* ``GITLAB_TOKEN`` *(preferred)* — a project/personal access token with ``api``
  scope, sent as the ``PRIVATE-TOKEN`` header. Falls back to ``CI_JOB_TOKEN``
  (the per-job token GitLab injects automatically), sent as ``JOB-TOKEN`` —
  note ``CI_JOB_TOKEN`` cannot write MR notes on many GitLab tiers, so a real
  ``GITLAB_TOKEN`` is recommended.

The poster lists the MR's notes, finds the first whose body contains the
AgentGuardian marker, and PUTs it; if none is found it POSTs a new one.
"""

from __future__ import annotations

import logging
import os

import httpx

from agent_guardian.ci.posters.base import Poster, PosterError

__all__ = ["GitlabPoster", "get_poster"]

_LOG = logging.getLogger(__name__)
_TIMEOUT = httpx.Timeout(15.0)


class GitlabPoster(Poster):
    """Upsert a single AgentGuardian note on a GitLab merge request."""

    def __init__(
        self,
        *,
        api_url: str,
        project_id: str,
        mr_iid: int,
        token: str,
        token_header: str = "PRIVATE-TOKEN",
        client: httpx.Client | None = None,
    ) -> None:
        if not project_id:
            raise PosterError("CI_PROJECT_ID is empty -- cannot address the GitLab project")
        self._api_url = api_url.rstrip("/")
        self._project_id = project_id
        self._mr_iid = mr_iid
        self._token = token
        self._token_header = token_header
        # An injected client lets tests mock httpx without monkeypatching env.
        self._client = client

    @property
    def _headers(self) -> dict[str, str]:
        return {self._token_header: self._token}

    def _notes_url(self) -> str:
        # GitLab path-encodes the project id when it is a namespace/path; a
        # numeric CI_PROJECT_ID needs no encoding, and httpx leaves it intact.
        return f"{self._api_url}/projects/{self._project_id}/merge_requests/{self._mr_iid}/notes"

    def upsert(self, body: str) -> None:
        """Find the marker-bearing note and PUT it, else POST a new one."""
        owns_client = self._client is None
        client = self._client or httpx.Client(timeout=_TIMEOUT)
        try:
            existing_id = self._find_existing(client)
            if existing_id is not None:
                resp = client.put(
                    f"{self._notes_url()}/{existing_id}",
                    headers=self._headers,
                    json={"body": body},
                )
            else:
                resp = client.post(
                    self._notes_url(),
                    headers=self._headers,
                    json={"body": body},
                )
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            _LOG.warning("GitLab note upsert failed: %s", exc)
            raise PosterError(f"GitLab note upsert failed: {exc}") from exc
        finally:
            if owns_client:
                client.close()

    def _find_existing(self, client: httpx.Client) -> int | None:
        """Return the id of this MR's first AgentGuardian note, or ``None``."""
        page = 1
        while True:
            resp = client.get(
                self._notes_url(),
                headers=self._headers,
                params={"per_page": 100, "page": page},
            )
            resp.raise_for_status()
            notes = resp.json()
            if not isinstance(notes, list) or not notes:
                return None
            for note in notes:
                if isinstance(note, dict) and self.marker in (note.get("body") or ""):
                    note_id = note.get("id")
                    if isinstance(note_id, int):
                        return note_id
            if len(notes) < 100:
                return None
            page += 1


def _resolve_mr_iid() -> int:
    """Find the merge-request iid from the GitLab CI environment."""
    raw = os.environ.get("CI_MERGE_REQUEST_IID", "").strip()
    if not raw:
        raise PosterError(
            "CI_MERGE_REQUEST_IID is not set -- this command must run on a "
            "merge_request_event pipeline (set rules: - if: "
            "$CI_PIPELINE_SOURCE == 'merge_request_event')."
        )
    try:
        return int(raw)
    except ValueError as exc:
        raise PosterError(f"CI_MERGE_REQUEST_IID is not an integer: '{raw}'") from exc


def get_poster() -> GitlabPoster:
    """Build a :class:`GitlabPoster` from the GitLab CI/CD environment.

    Prefers ``GITLAB_TOKEN`` (``PRIVATE-TOKEN`` header); falls back to
    ``CI_JOB_TOKEN`` (``JOB-TOKEN`` header) which GitLab injects automatically.
    """
    api_url = os.environ.get("CI_API_V4_URL")
    if not api_url:
        raise PosterError(
            "CI_API_V4_URL is not set -- expected the GitLab API base "
            "(e.g. https://gitlab.com/api/v4)"
        )
    project_id = os.environ.get("CI_PROJECT_ID")
    if not project_id:
        raise PosterError("CI_PROJECT_ID is not set -- cannot address the GitLab project")
    private_token = os.environ.get("GITLAB_TOKEN")
    if private_token:
        token = private_token
        token_header = "PRIVATE-TOKEN"
    else:
        job_token = os.environ.get("CI_JOB_TOKEN")
        if not job_token:
            raise PosterError(
                "neither GITLAB_TOKEN nor CI_JOB_TOKEN is set -- cannot "
                "authenticate to the GitLab API"
            )
        token = job_token
        token_header = "JOB-TOKEN"
    mr_iid = _resolve_mr_iid()
    return GitlabPoster(
        api_url=api_url,
        project_id=project_id,
        mr_iid=mr_iid,
        token=token,
        token_header=token_header,
    )
