"""Shared deterministic fixtures for the Phase 6 approved-action test suite.

Builds:

* canned ``FakeGraphClient`` results for the remediation queries **and** the
  repository record the action service resolves its write target from;
* a :class:`GitHubHarness` — an ``httpx.MockTransport`` handler that records
  every request and serves scripted GitHub REST responses, so the real
  :class:`~app.github.issue_client.GitHubIssueClient` code path is exercised
  with zero network;
* fully configured :class:`~app.actions.config.ActionSettings` pointing at a
  temporary SQLite action store.

Nothing here reaches the network or FalkorDB.
"""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import httpx
from pydantic import SecretStr

from app.actions.config import ActionSettings
from app.actions.service import GitHubIssueService
from app.actions.store import ActionStore
from app.github.issue_client import GitHubIssueClient
from app.graph.queries import GET_REPOSITORY
from app.graph.service import GraphService
from app.graph.vulnerability import VulnerabilityGraphService
from app.models.ids import stable_id
from app.remediation.service import RemediationService
from tests.remediation_support import (
    ANALYSIS,
    COMMIT,
    PKG_REQUESTS,
    REPO,
    VULN_REQUESTS,
    install,
    query_result,
)
from tests.support import FakeGraphClient

OWNER = "example"
NAME = "priority-demo"
FULL_NAME = f"{OWNER}/{NAME}"
GROUP_ID = stable_id("fixgroup", ANALYSIS, PKG_REQUESTS, "2.32.1")
FINDING_ID = stable_id("finding", ANALYSIS, PKG_REQUESTS, VULN_REQUESTS)

APPROVAL_SECRET = "unit-test-approval-secret"
ACTION_TOKEN = "unit-test-action-token"

_MISSING = object()


class FakeClock:
    """Deterministic UTC clock the service and tests share."""

    def __init__(self, moment: datetime | None = None) -> None:
        self.moment = moment or datetime(2026, 3, 1, 12, 0, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        return self.moment

    def advance(self, seconds: float) -> datetime:
        self.moment = self.moment + timedelta(seconds=seconds)
        return self.moment


def repository_row(**overrides: Any) -> dict[str, Any]:
    """Shape mirrors the ``GET_REPOSITORY`` query columns."""
    row: dict[str, Any] = {
        "id": REPO,
        "canonical_id": REPO,
        "owner": OWNER,
        "name": NAME,
        "host": "github.com",
        "canonical_url": f"https://github.com/{FULL_NAME}",
        "clone_url": f"https://github.com/{FULL_NAME}.git",
        "api_url": f"https://api.github.com/repos/{FULL_NAME}",
        "description": "Demo repository",
        "default_branch": "main",
        "is_private": False,
        "is_archived": False,
        "is_fork": False,
        "stars": 1,
        "forks": 0,
        "open_issues": 0,
        "size_kb": 10,
        "license_spdx_id": "MIT",
        "primary_language": "Python",
        "pushed_at": "2026-02-01T00:00:00+00:00",
        "created_at": "2025-01-01T00:00:00+00:00",
        "metadata_source": "github_api",
        "commit_sha": COMMIT,
        "updated_at": "2026-02-02T00:00:00+00:00",
    }
    row.update(overrides)
    return row


def make_graph_client(
    *,
    repository: dict[str, Any] | object = _MISSING,
    **install_kwargs: Any,
) -> FakeGraphClient:
    """Install Phase 5 fixtures plus the repository record the service reads."""
    client = FakeGraphClient()
    install(client, **install_kwargs)
    if repository is _MISSING:
        repository = repository_row()
    if repository is not None:
        client.canned[GET_REPOSITORY] = query_result([repository])
    return client


# ---------------------------------------------------------------------------
# GitHub HTTP double
# ---------------------------------------------------------------------------

@dataclass
class GitHubHarness:
    """Scriptable GitHub REST responses with full request recording."""

    repo_status: int = 200
    repo_payload: dict[str, Any] | None = None
    repo_headers: dict[str, str] = field(default_factory=dict)
    repo_error: Exception | None = None
    create_status: int = 201
    create_payload: dict[str, Any] | None = None
    create_headers: dict[str, str] = field(default_factory=dict)
    create_error: Exception | None = None
    create_started: threading.Event | None = None
    create_release: threading.Event | None = None
    search_status: int = 200
    search_items: list[dict[str, Any]] | None = None
    search_error: Exception | None = None
    requests: list[httpx.Request] = field(default_factory=list)
    created_bodies: list[dict[str, Any]] = field(default_factory=list)

    @property
    def posts(self) -> list[httpx.Request]:
        return [request for request in self.requests if request.method == "POST"]

    @property
    def gets(self) -> list[httpx.Request]:
        return [request for request in self.requests if request.method == "GET"]

    def _default_repo_payload(self) -> dict[str, Any]:
        return {
            "full_name": FULL_NAME,
            "has_issues": True,
            "permissions": {"admin": False, "maintain": False, "push": True, "triage": False, "pull": True},
            "default_branch": "main",
            "archived": False,
        }

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        path = request.url.path
        if request.method == "GET" and path == f"/repos/{OWNER}/{NAME}":
            if self.repo_error is not None:
                raise self.repo_error
            if self.repo_status != 200:
                return httpx.Response(self.repo_status, json={"message": "error"}, headers=self.repo_headers)
            payload = self.repo_payload if self.repo_payload is not None else self._default_repo_payload()
            return httpx.Response(200, json=payload, headers=self.repo_headers)
        if request.method == "POST" and path == f"/repos/{OWNER}/{NAME}/issues":
            if self.create_started is not None:
                self.create_started.set()
            if self.create_release is not None:
                self.create_release.wait(timeout=10)
            if self.create_error is not None:
                raise self.create_error
            if self.create_status not in (200, 201):
                return httpx.Response(self.create_status, json={"message": "error"}, headers=self.create_headers)
            body: dict[str, Any] = {}
            try:
                loaded = json.loads(request.content.decode("utf-8"))
                if isinstance(loaded, dict):
                    body = loaded
            except ValueError:  # pragma: no cover - defensive
                pass
            self.created_bodies.append(body)
            payload = self.create_payload
            if payload is None:
                payload = {
                    "number": 42,
                    "html_url": f"https://github.com/{FULL_NAME}/issues/42",
                    "title": body.get("title", "issue"),
                    "state": "open",
                }
            return httpx.Response(self.create_status, json=payload, headers=self.create_headers)
        if request.method == "GET" and path == "/search/issues":
            if self.search_error is not None:
                raise self.search_error
            if self.search_status != 200:
                return httpx.Response(self.search_status, json={"message": "error"})
            items = self.search_items if self.search_items is not None else []
            return httpx.Response(200, json={"total_count": len(items), "items": items})
        return httpx.Response(404, json={"message": "unexpected request"})

    def client(self) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(self.handler))

    def known_issue(self, **overrides: Any) -> dict[str, Any]:
        item: dict[str, Any] = {
            "number": 42,
            "html_url": f"https://github.com/{FULL_NAME}/issues/42",
            "title": "issue",
            "state": "open",
        }
        item.update(overrides)
        return item


# ---------------------------------------------------------------------------
# settings + service bundle
# ---------------------------------------------------------------------------

def make_action_settings(
    tmp_path: Path,
    **overrides: Any,
) -> ActionSettings:
    """Fully configured, enabled action settings backed by a temp store."""
    values: dict[str, Any] = {
        "enabled": True,
        "github_token": SecretStr(ACTION_TOKEN),
        "approval_secret": SecretStr(APPROVAL_SECRET),
        "github_api_base_url": "https://api.github.test",
        "user_agent": "BlastRadius-test",
        "timeout_seconds": 5.0,
        "preview_ttl_seconds": 900.0,
        "store_path": tmp_path / "actions.sqlite3",
        "retention_seconds": 7 * 24 * 3600,
    }
    values.update(overrides)
    return ActionSettings(**values)


@dataclass
class ActionBundle:
    """Everything a Phase 6 test needs, wired to the real production classes."""

    service: GitHubIssueService
    graph_client: FakeGraphClient
    github: GitHubHarness
    settings: ActionSettings
    store: ActionStore
    clock: FakeClock
    remediation: RemediationService


def build_bundle(
    tmp_path: Path,
    *,
    repository: dict[str, Any] | object = _MISSING,
    settings: ActionSettings | None = None,
    clock: FakeClock | None = None,
    harness: GitHubHarness | None = None,
    graph_client: FakeGraphClient | None = None,
    **install_kwargs: Any,
) -> ActionBundle:
    """Build the real Phase 6 service over fake graph/GitHub transports."""
    effective_graph_client = (
        graph_client
        if graph_client is not None
        else make_graph_client(repository=repository, **install_kwargs)
    )
    graph_service = GraphService(effective_graph_client)
    remediation = RemediationService(
        graph_service, VulnerabilityGraphService(effective_graph_client, graph_service)
    )
    effective_settings = settings if settings is not None else make_action_settings(tmp_path)
    store = ActionStore(effective_settings.effective_store_path)
    store.initialize()
    effective_harness = harness if harness is not None else GitHubHarness()
    github_client = GitHubIssueClient(effective_settings, client=effective_harness.client())
    effective_clock = clock if clock is not None else FakeClock()
    service = GitHubIssueService(
        remediation=remediation,
        graph=graph_service,
        github=github_client,
        store=store,
        settings=effective_settings,
        clock=effective_clock,
    )
    return ActionBundle(
        service=service,
        graph_client=effective_graph_client,
        github=effective_harness,
        settings=effective_settings,
        store=store,
        clock=effective_clock,
        remediation=remediation,
    )


__all__ = [
    "ACTION_TOKEN",
    "ANALYSIS",
    "APPROVAL_SECRET",
    "ActionBundle",
    "COMMIT",
    "FINDING_ID",
    "FULL_NAME",
    "FakeClock",
    "GitHubHarness",
    "GROUP_ID",
    "NAME",
    "OWNER",
    "REPO",
    "build_bundle",
    "make_action_settings",
    "make_graph_client",
    "repository_row",
]
