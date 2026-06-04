"""GitHub PR-comment poster (CI/CD feature).

Uses the GitHub REST API (issue comments — a PR is an issue for the comments
endpoint) to upsert a single AgentGuardian comment per pull request. Context is
read from the standard GitHub Actions environment:

* ``GITHUB_TOKEN``      — the API token (``${{ secrets.GITHUB_TOKEN }}``).
* ``GITHUB_REPOSITORY`` — ``owner/repo``.
* ``GITHUB_EVENT_PATH`` — path to the event JSON; ``pull_request.number`` is
  the PR number. Falls back to parsing ``GITHUB_REF`` (``refs/pull/<n>/merge``).
* ``GITHUB_API_URL``    — API base (defaults to ``https://api.github.com``;
  GitHub Enterprise sets this).

The poster lists the PR's issue comments, finds the first whose body contains
the AgentGuardian marker, and PATCHes it; if none is found it POSTs a new one.
"""

from __future__ import annotations

import json
import logging
import os
import re
from pathlib import Path

import httpx

from agent_guardian.ci.posters.base import Poster, PosterError

__all__ = ["GithubPoster", "get_poster"]

_LOG = logging.getLogger(__name__)
_DEFAULT_API_URL = "https://api.github.com"
_REF_PR_RE = re.compile(r"^refs/pull/(\d+)/(?:merge|head)$")
_TIMEOUT = httpx.Timeout(15.0)


def _resolve_pr_number() -> int:
    """Find the PR number from the GitHub Actions environment.

    Prefers ``pull_request.number`` in the event JSON; falls back to parsing
    ``GITHUB_REF`` (``refs/pull/<n>/merge``).
    """
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    if event_path:
        path = Path(event_path)
        if path.is_file():
            try:
                event = json.loads(path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError) as exc:
                _LOG.debug("could not parse GITHUB_EVENT_PATH %s: %s", event_path, exc)
                event = None
            if isinstance(event, dict):
                pr = event.get("pull_request")
                if isinstance(pr, dict):
                    number = pr.get("number")
                    if isinstance(number, int):
                        return number
    ref = os.environ.get("GITHUB_REF", "")
    match = _REF_PR_RE.match(ref)
    if match:
        return int(match.group(1))
    raise PosterError(
        "could not determine the pull-request number from the environment "
        "(checked GITHUB_EVENT_PATH -> pull_request.number and GITHUB_REF "
        "'refs/pull/<n>/merge'). Run this on a pull_request event."
    )


class GithubPoster(Poster):
    """Upsert a single AgentGuardian comment on a GitHub pull request."""

    def __init__(
        self,
        *,
        token: str,
        repository: str,
        pr_number: int,
        api_url: str = _DEFAULT_API_URL,
        client: httpx.Client | None = None,
    ) -> None:
        if "/" not in repository:
            raise PosterError(f"GITHUB_REPOSITORY must be 'owner/repo'; got '{repository}'")
        self._token = token
        self._repository = repository
        self._pr_number = pr_number
        self._api_url = api_url.rstrip("/")
        # An injected client lets tests mock httpx without monkeypatching env.
        self._client = client

    @property
    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    def _comments_url(self) -> str:
        return f"{self._api_url}/repos/{self._repository}/issues/{self._pr_number}/comments"

    def upsert(self, body: str) -> None:
        """Find the marker-bearing comment and PATCH it, else POST a new one."""
        owns_client = self._client is None
        client = self._client or httpx.Client(timeout=_TIMEOUT)
        try:
            existing_id = self._find_existing(client)
            if existing_id is not None:
                resp = client.patch(
                    f"{self._api_url}/repos/{self._repository}/issues/comments/{existing_id}",
                    headers=self._headers,
                    json={"body": body},
                )
            else:
                resp = client.post(
                    self._comments_url(),
                    headers=self._headers,
                    json={"body": body},
                )
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            raise PosterError(f"GitHub comment upsert failed: {exc}") from exc
        finally:
            if owns_client:
                client.close()

    def _find_existing(self, client: httpx.Client) -> int | None:
        """Return the id of this PR's first AgentGuardian comment, or ``None``."""
        page = 1
        while True:
            resp = client.get(
                self._comments_url(),
                headers=self._headers,
                params={"per_page": 100, "page": page},
            )
            resp.raise_for_status()
            comments = resp.json()
            if not isinstance(comments, list) or not comments:
                return None
            for comment in comments:
                if isinstance(comment, dict) and self.marker in (comment.get("body") or ""):
                    comment_id = comment.get("id")
                    if isinstance(comment_id, int):
                        return comment_id
            if len(comments) < 100:
                return None
            page += 1


def get_poster() -> GithubPoster:
    """Build a :class:`GithubPoster` from the GitHub Actions environment."""
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        raise PosterError("GITHUB_TOKEN is not set -- cannot authenticate to the GitHub API")
    repository = os.environ.get("GITHUB_REPOSITORY")
    if not repository:
        raise PosterError("GITHUB_REPOSITORY is not set -- expected 'owner/repo'")
    api_url = os.environ.get("GITHUB_API_URL", _DEFAULT_API_URL)
    pr_number = _resolve_pr_number()
    return GithubPoster(
        token=token,
        repository=repository,
        pr_number=pr_number,
        api_url=api_url,
    )
