"""Unit tests for the dedicated Phase 6 GitHub issue client.

All HTTP is served by an ``httpx.MockTransport``; nothing here touches the
network, and every error path is asserted to avoid leaking the token.
"""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from app.actions.config import ActionSettings
from app.core.errors import (
    ActionEvidenceChangedError,
    ActionNotConfiguredError,
    GitHubCredentialsInvalidError,
    GitHubIssueCreationError,
    GitHubIssuesDisabledError,
    GitHubPermissionDeniedError,
    GitHubWriteAmbiguousError,
    InputValidationError,
    NetworkFailureError,
    RateLimitExceededError,
    RepositoryNotFoundError,
)
from app.github.issue_client import REQUIRED_PERMISSION, GitHubIssueClient
from tests.actions_support import (
    ACTION_TOKEN,
    FULL_NAME,
    NAME,
    OWNER,
    GitHubHarness,
    make_action_settings,
)


def _client(
    tmp_path: Path, harness: GitHubHarness, **settings_overrides
) -> tuple[GitHubIssueClient, ActionSettings]:
    settings = make_action_settings(tmp_path, **settings_overrides)
    return GitHubIssueClient(settings, client=harness.client()), settings


# ---------------------------------------------------------------------------
# repository preflight
# ---------------------------------------------------------------------------


def test_check_repository_access_parses_metadata(tmp_path: Path) -> None:
    harness = GitHubHarness()
    client, _ = _client(tmp_path, harness)
    access = client.check_repository_access(OWNER, NAME)
    assert access.full_name == FULL_NAME
    assert access.has_issues is True
    assert access.default_branch == "main"
    assert access.archived is False
    assert access.permissions["push"] is True
    assert access.permission_hint is None
    request = harness.requests[0]
    assert request.method == "GET"
    assert request.url.path == f"/repos/{OWNER}/{NAME}"
    assert request.headers["x-github-api-version"] == "2022-11-28"
    assert request.headers["accept"] == "application/vnd.github+json"
    assert request.headers["authorization"] == f"Bearer {ACTION_TOKEN}"


def test_read_only_permissions_produce_an_actionable_hint(tmp_path: Path) -> None:
    harness = GitHubHarness(
        repo_payload={
            "full_name": FULL_NAME,
            "has_issues": True,
            "permissions": {"pull": True, "push": False, "triage": False, "admin": False},
        }
    )
    client, _ = _client(tmp_path, harness)
    access = client.check_repository_access(OWNER, NAME)
    assert access.permission_hint is not None
    assert "Issues: write" in access.permission_hint
    assert ACTION_TOKEN not in access.permission_hint


def test_missing_token_refuses_before_any_request(tmp_path: Path) -> None:
    harness = GitHubHarness()
    settings = make_action_settings(tmp_path, github_token=None)
    client = GitHubIssueClient(settings, client=harness.client())
    with pytest.raises(ActionNotConfiguredError) as excinfo:
        client.check_repository_access(OWNER, NAME)
    assert "BLASTRADIUS_ACTIONS_GITHUB_TOKEN" in excinfo.value.message
    with pytest.raises(ActionNotConfiguredError):
        client.create_issue(OWNER, NAME, title="t", body="b")
    with pytest.raises(ActionNotConfiguredError):
        client.find_issue_by_marker(OWNER, NAME, "marker")
    assert harness.requests == []


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (401, GitHubCredentialsInvalidError),
        (404, RepositoryNotFoundError),
        (410, GitHubIssuesDisabledError),
        (403, GitHubPermissionDeniedError),
        (422, NetworkFailureError),
    ],
)
def test_repository_errors_map_to_the_typed_taxonomy(
    tmp_path: Path, status: int, expected: type[Exception]
) -> None:
    harness = GitHubHarness(repo_status=status)
    client, _ = _client(tmp_path, harness)
    with pytest.raises(expected) as excinfo:
        client.check_repository_access(OWNER, NAME)
    assert ACTION_TOKEN not in str(excinfo.value)
    assert str(excinfo.value) != ""


def test_rate_limit_is_detected_from_403_headers(tmp_path: Path) -> None:
    harness = GitHubHarness(
        repo_status=403,
        repo_headers={"x-ratelimit-remaining": "0", "x-ratelimit-reset": "1800000000"},
    )
    client, _ = _client(tmp_path, harness)
    with pytest.raises(RateLimitExceededError) as excinfo:
        client.check_repository_access(OWNER, NAME)
    details = excinfo.value.details or {}
    assert details.get("rate_limit_remaining") == "0"
    assert details.get("rate_limit_reset")


def test_rate_limit_is_detected_from_429(tmp_path: Path) -> None:
    harness = GitHubHarness(repo_status=429, repo_headers={"retry-after": "30"})
    client, _ = _client(tmp_path, harness)
    with pytest.raises(RateLimitExceededError) as excinfo:
        client.check_repository_access(OWNER, NAME)
    assert (excinfo.value.details or {}).get("retry_after_seconds") == "30"


def test_permission_denied_details_list_required_permissions(tmp_path: Path) -> None:
    harness = GitHubHarness(repo_status=403)
    client, _ = _client(tmp_path, harness)
    with pytest.raises(GitHubPermissionDeniedError) as excinfo:
        client.check_repository_access(OWNER, NAME)
    details = excinfo.value.details or {}
    assert details.get("required_permissions") == ["issues:write", "metadata:read"]
    assert "Issues: write" in REQUIRED_PERMISSION


def test_redirects_are_never_followed(tmp_path: Path) -> None:
    harness = GitHubHarness(repo_status=301)
    client, _ = _client(tmp_path, harness)
    with pytest.raises(ActionEvidenceChangedError):
        client.check_repository_access(OWNER, NAME)
    assert len(harness.requests) == 1


def test_read_transport_failure_is_a_network_error(tmp_path: Path) -> None:
    harness = GitHubHarness(repo_error=httpx.ConnectError("boom"))
    client, _ = _client(tmp_path, harness)
    with pytest.raises(NetworkFailureError) as excinfo:
        client.check_repository_access(OWNER, NAME)
    assert (excinfo.value.details or {}).get("cause") == "ConnectError"


# ---------------------------------------------------------------------------
# issue creation
# ---------------------------------------------------------------------------


def test_create_issue_returns_the_verified_identifier(tmp_path: Path) -> None:
    harness = GitHubHarness()
    client, _ = _client(tmp_path, harness)
    created = client.create_issue(OWNER, NAME, title="Issue title", body="Issue body")
    assert created.number == 42
    assert created.url == f"https://github.com/{FULL_NAME}/issues/42"
    assert created.title == "Issue title"
    assert created.state == "open"
    request = harness.posts[0]
    assert request.url.path == f"/repos/{OWNER}/{NAME}/issues"
    assert harness.created_bodies == [{"title": "Issue title", "body": "Issue body"}]
    # only the documented fields are sent
    assert set(harness.created_bodies[0]) == {"title", "body"}


def test_create_issue_sends_no_secret_in_the_payload(tmp_path: Path) -> None:
    harness = GitHubHarness()
    client, _ = _client(tmp_path, harness)
    client.create_issue(OWNER, NAME, title="t", body="b")
    assert ACTION_TOKEN not in harness.created_bodies[0]["title"]
    assert ACTION_TOKEN not in harness.created_bodies[0]["body"]


def test_create_issue_validation_failure_is_definitive(tmp_path: Path) -> None:
    harness = GitHubHarness(create_status=422)
    client, _ = _client(tmp_path, harness)
    with pytest.raises(GitHubIssueCreationError) as excinfo:
        client.create_issue(OWNER, NAME, title="t", body="b")
    assert excinfo.value.retryable is False
    assert ACTION_TOKEN not in str(excinfo.value)


def test_create_issue_rate_limit_is_not_ambiguous(tmp_path: Path) -> None:
    harness = GitHubHarness(
        create_status=403, create_headers={"x-ratelimit-remaining": "0"}
    )
    client, _ = _client(tmp_path, harness)
    with pytest.raises(RateLimitExceededError):
        client.create_issue(OWNER, NAME, title="t", body="b")


def test_create_issue_permission_denied_is_definitive(tmp_path: Path) -> None:
    harness = GitHubHarness(create_status=403)
    client, _ = _client(tmp_path, harness)
    with pytest.raises(GitHubPermissionDeniedError):
        client.create_issue(OWNER, NAME, title="t", body="b")


@pytest.mark.parametrize("status", [500, 502, 503])
def test_create_issue_server_error_is_ambiguous(tmp_path: Path, status: int) -> None:
    harness = GitHubHarness(create_status=status)
    client, _ = _client(tmp_path, harness)
    with pytest.raises(GitHubWriteAmbiguousError) as excinfo:
        client.create_issue(OWNER, NAME, title="t", body="b")
    assert (excinfo.value.details or {}).get("status_code") == status
    assert excinfo.value.retryable is False


def test_create_issue_transport_error_is_ambiguous(tmp_path: Path) -> None:
    harness = GitHubHarness(create_error=httpx.ReadTimeout("slow"))
    client, _ = _client(tmp_path, harness)
    with pytest.raises(GitHubWriteAmbiguousError) as excinfo:
        client.create_issue(OWNER, NAME, title="t", body="b")
    assert (excinfo.value.details or {}).get("cause") == "ReadTimeout"


def test_create_issue_unverifiable_success_payload_is_ambiguous(tmp_path: Path) -> None:
    harness = GitHubHarness(create_payload={"number": 0, "html_url": "not-a-url"})
    client, _ = _client(tmp_path, harness)
    with pytest.raises(GitHubWriteAmbiguousError):
        client.create_issue(OWNER, NAME, title="t", body="b")


def test_create_issue_requires_title_and_body(tmp_path: Path) -> None:
    harness = GitHubHarness()
    client, _ = _client(tmp_path, harness)
    with pytest.raises(InputValidationError):
        client.create_issue(OWNER, NAME, title="", body="b")
    assert harness.requests == []


# ---------------------------------------------------------------------------
# marker reconciliation
# ---------------------------------------------------------------------------


def test_find_issue_by_marker_parses_matches(tmp_path: Path) -> None:
    harness = GitHubHarness()
    harness.search_items = [harness.known_issue(number=7, title="Found")]
    client, _ = _client(tmp_path, harness)
    found = client.find_issue_by_marker(OWNER, NAME, "<!-- blastradius-action: act_x -->")
    assert len(found) == 1
    assert found[0].number == 7
    assert found[0].url == f"https://github.com/{FULL_NAME}/issues/42"
    assert found[0].title == "Found"
    request = harness.gets[0]
    assert request.url.path == "/search/issues"
    assert request.url.params["q"] == (
        f'repo:{OWNER}/{NAME} in:body "<!-- blastradius-action: act_x -->"'
    )


def test_find_issue_by_marker_skips_malformed_items(tmp_path: Path) -> None:
    harness = GitHubHarness()
    harness.search_items = [
        {"number": "not-an-int"},
        {"number": 3, "html_url": "http://insecure.example/issues/3"},
        harness.known_issue(number=4),
    ]
    client, _ = _client(tmp_path, harness)
    found = client.find_issue_by_marker(OWNER, NAME, "marker")
    assert [item.number for item in found] == [4]


def test_find_issue_by_marker_empty_result(tmp_path: Path) -> None:
    harness = GitHubHarness(search_items=[])
    client, _ = _client(tmp_path, harness)
    assert client.find_issue_by_marker(OWNER, NAME, "marker") == []


def test_find_issue_by_marker_failure_is_a_read_error(tmp_path: Path) -> None:
    harness = GitHubHarness(search_status=500)
    client, _ = _client(tmp_path, harness)
    with pytest.raises(NetworkFailureError):
        client.find_issue_by_marker(OWNER, NAME, "marker")


def test_find_issue_by_marker_transport_error(tmp_path: Path) -> None:
    harness = GitHubHarness(search_error=httpx.ConnectError("down"))
    client, _ = _client(tmp_path, harness)
    with pytest.raises(NetworkFailureError):
        client.find_issue_by_marker(OWNER, NAME, "marker")


# ---------------------------------------------------------------------------
# lifecycle
# ---------------------------------------------------------------------------


def test_close_is_idempotent_and_owned_only(tmp_path: Path) -> None:
    settings = make_action_settings(tmp_path)
    client = GitHubIssueClient(settings)  # owns a lazily-created httpx client
    client.close()
    client.close()
    # injected clients are owned by the caller and never closed by us
    harness = GitHubHarness()
    injected = GitHubIssueClient(settings, client=harness.client())
    injected.close()
    injected.check_repository_access(OWNER, NAME)
    assert len(harness.requests) == 1
