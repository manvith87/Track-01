"""GitHub REST client tests using ``httpx.MockTransport``.

The client is read-only by construction; these tests pin down that every HTTP
failure becomes a typed, actionable error (never a raw ``httpx`` exception) and
that the token is only ever sent as an ``Authorization`` header.
"""

from __future__ import annotations

from datetime import datetime, timezone

import httpx
import pytest

from app.core.config import Settings
from app.core.errors import (
    MetadataRetrievalError,
    NetworkFailureError,
    RateLimitExceededError,
    ReferenceNotFoundError,
    RepositoryAccessDeniedError,
    RepositoryNotFoundError,
)
from app.ingestion import github_api
from app.ingestion.github_api import GitHubApiClient, ReferenceResolution, RepositoryMetadataSnapshot
from app.ingestion.urls import parse_repository_url, validate_reference
from app.models.common import ReferenceType
from tests.support import make_settings

IDENTITY = parse_repository_url("https://github.com/psf/requests").identity
SHA = "abcdef0123456789abcdef0123456789abcdef01"


def make_client(handler, *, settings: Settings | None = None) -> GitHubApiClient:
    settings = settings or make_settings()
    transport = httpx.MockTransport(handler)
    return GitHubApiClient(
        settings,
        client=httpx.Client(transport=transport, base_url=settings.github_api_base_url),
    )


def json_response(request: httpx.Request, payload, *, status: int = 200, headers: dict | None = None) -> httpx.Response:
    return httpx.Response(status, json=payload, headers=headers, request=request)


def commit_payload(*, sha: str = SHA.upper(), message: str = "Fix the thing.\n\nMore details.") -> dict:
    return {
        "sha": sha,
        "commit": {
            "message": message,
            "author": {"name": "Jane Dev", "date": "2024-05-01T10:30:00Z"},
        },
    }


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------
def test_token_is_sent_as_bearer_header_only(monkeypatch) -> None:
    from pydantic import SecretStr

    captured: dict = {}

    class FakeHttpClient:
        def __init__(self, **kwargs) -> None:
            captured.update(kwargs)
            captured["instance"] = self
            self.closed = False

        def close(self) -> None:
            self.closed = True

    monkeypatch.setattr(github_api.httpx, "Client", FakeHttpClient)
    settings = make_settings(github_token=SecretStr("secret-token"))
    client = GitHubApiClient(settings)

    headers = captured["headers"]
    assert headers["Authorization"] == "Bearer secret-token"
    assert headers["Accept"] == "application/vnd.github+json"
    assert headers["X-GitHub-Api-Version"] == "2022-11-28"
    assert headers["User-Agent"] == settings.user_agent
    assert captured["base_url"] == settings.github_api_base_url
    assert captured["follow_redirects"] is False
    client.close()
    assert captured["instance"].closed is True  # the owned client is closed


def test_no_authorization_header_without_a_token(monkeypatch) -> None:
    captured: dict = {}

    class FakeHttpClient:
        def __init__(self, **kwargs) -> None:
            captured.update(kwargs)

        def close(self) -> None:
            pass

    monkeypatch.setattr(github_api.httpx, "Client", FakeHttpClient)
    GitHubApiClient(make_settings())
    assert "Authorization" not in captured["headers"]


def test_close_only_closes_the_owned_client() -> None:
    injected = httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(200, json={})))
    client = GitHubApiClient(make_settings(), client=injected)
    client.close()
    assert injected.is_closed is False
    injected.close()


# ---------------------------------------------------------------------------
# Repository metadata
# ---------------------------------------------------------------------------
def test_get_repository_maps_the_payload() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return json_response(
            request,
            {
                "default_branch": "main",
                "description": "A simple, yet elegant, HTTP library.",
                "private": False,
                "archived": True,
                "fork": True,
                "stargazers_count": 52000,
                "forks_count": 9400,
                "open_issues_count": 250,
                "size": 12800,
                "license": {"spdx_id": "Apache-2.0"},
                "language": "Python",
                "pushed_at": "2024-05-01T10:30:00Z",
                "created_at": "2011-02-13T18:38:17Z",
            },
        )

    snapshot = make_client(handler).get_repository(IDENTITY)
    assert requests[0].url.path == "/repos/psf/requests"
    assert requests[0].method == "GET"
    assert snapshot == RepositoryMetadataSnapshot(
        default_branch="main",
        description="A simple, yet elegant, HTTP library.",
        is_private=False,
        is_archived=True,
        is_fork=True,
        stars=52000,
        forks=9400,
        open_issues=250,
        size_kb=12800,
        license_spdx_id="Apache-2.0",
        primary_language="Python",
        pushed_at=datetime(2024, 5, 1, 10, 30, tzinfo=timezone.utc),
        created_at=datetime(2011, 2, 13, 18, 38, 17, tzinfo=timezone.utc),
    )


@pytest.mark.parametrize(
    ("status", "headers", "payload", "expected", "expected_http"),
    [
        (404, None, {}, RepositoryNotFoundError, 404),
        (401, None, {}, RepositoryAccessDeniedError, 403),
        (403, None, {}, RepositoryAccessDeniedError, 403),
        (451, None, {}, RepositoryAccessDeniedError, 403),
        (403, {"x-ratelimit-remaining": "0", "x-ratelimit-reset": "1714550400"}, {}, RateLimitExceededError, 429),
        (429, None, {}, RateLimitExceededError, 429),
        (403, None, {"message": "API rate limit exceeded for 1.2.3.4"}, RateLimitExceededError, 429),
        (422, None, {}, MetadataRetrievalError, 502),
        (500, None, {}, MetadataRetrievalError, 502),
        (302, None, {}, RepositoryNotFoundError, 404),
    ],
)
def test_http_statuses_map_to_typed_errors(status, headers, payload, expected, expected_http) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return json_response(request, payload, status=status, headers=headers)

    with pytest.raises(expected) as excinfo:
        make_client(handler).get_repository(IDENTITY)
    error = excinfo.value
    assert error.http_status == expected_http
    if status in {429, 500}:
        assert error.retryable is True


def test_rate_limit_details_are_exposed() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return json_response(
            request,
            {},
            status=403,
            headers={"x-ratelimit-remaining": "0", "x-ratelimit-reset": "1714550400", "retry-after": "60"},
        )

    with pytest.raises(RateLimitExceededError) as excinfo:
        make_client(handler).get_repository(IDENTITY)
    details = excinfo.value.details
    assert details["rate_limit_remaining"] == "0"
    assert details["rate_limit_reset"].startswith("2024-05-01T")
    assert details["retry_after_seconds"] == "60"


def test_network_failure_and_timeout_are_retryable() -> None:
    def timeout_handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timed out", request=request)

    with pytest.raises(NetworkFailureError) as excinfo:
        make_client(timeout_handler).get_repository(IDENTITY)
    assert excinfo.value.retryable is True

    def broken_handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    with pytest.raises(NetworkFailureError):
        make_client(broken_handler).get_repository(IDENTITY)


def test_unexpected_payloads_are_typed_errors() -> None:
    def non_json(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html>not json</html>", request=request)

    with pytest.raises(MetadataRetrievalError, match="non-JSON"):
        make_client(non_json).get_repository(IDENTITY)

    def wrong_shape(request: httpx.Request) -> httpx.Response:
        return json_response(request, ["not", "an", "object"])

    with pytest.raises(MetadataRetrievalError, match="unexpected JSON"):
        make_client(wrong_shape).get_repository(IDENTITY)


# ---------------------------------------------------------------------------
# Reference resolution
# ---------------------------------------------------------------------------
def test_default_branch_resolution_uses_the_commits_endpoint() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        assert request.url.path == "/repos/psf/requests/commits/main"
        return json_response(request, commit_payload())

    resolution = make_client(handler).resolve_reference(IDENTITY, None, default_branch="main")
    assert resolution == ReferenceResolution(
        commit_sha=SHA,
        ref_type=ReferenceType.DEFAULT_BRANCH,
        resolved_via="github_api",
        default_branch="main",
        commit_message="Fix the thing.",  # first line only
        commit_author="Jane Dev",
        committed_at=datetime(2024, 5, 1, 10, 30, tzinfo=timezone.utc),
        commit_source="github_api",
    )


def test_default_branch_without_metadata_is_an_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:  # pragma: no cover - must not be called
        raise AssertionError("no request expected")

    with pytest.raises(MetadataRetrievalError, match="default branch"):
        make_client(handler).resolve_reference(IDENTITY, None, default_branch=None)


def test_full_sha_reference_needs_no_network_call() -> None:
    def handler(request: httpx.Request) -> httpx.Response:  # pragma: no cover - must not be called
        raise AssertionError("no request expected")

    reference = validate_reference("A" * 40)
    resolution = make_client(handler).resolve_reference(IDENTITY, reference, default_branch="main")
    assert resolution.commit_sha == "a" * 40
    assert resolution.ref_type is ReferenceType.COMMIT
    assert resolution.resolved_via == "provided_commit_sha"


def test_branch_reference_probes_the_commit_endpoint() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return json_response(request, commit_payload())

    resolution = make_client(handler).resolve_reference(
        IDENTITY, validate_reference("release/2.0"), default_branch="main"
    )
    assert requests[0].url.path == "/repos/psf/requests/commits/release/2.0"
    assert resolution.ref_type is ReferenceType.BRANCH
    assert resolution.resolved_via == "github_api"
    assert resolution.default_branch == "main"


def test_short_sha_reference_is_resolved_through_commits() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return json_response(request, commit_payload(sha=SHA))

    resolution = make_client(handler).resolve_reference(IDENTITY, validate_reference("abcdef0"), default_branch="main")
    assert requests[0].url.path == "/repos/psf/requests/commits/abcdef0"
    assert resolution.commit_sha == SHA


def test_missing_reference_is_reported_as_not_found() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return json_response(request, {"message": "No commit found"}, status=404)

    with pytest.raises(ReferenceNotFoundError) as excinfo:
        make_client(handler).resolve_reference(IDENTITY, validate_reference("nope"), default_branch="main")
    assert excinfo.value.details["ref"] == "nope"
    assert excinfo.value.details["repository"] == "github.com/psf/requests"


def test_bad_commit_payload_is_rejected() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return json_response(request, {"sha": "too-short"})

    with pytest.raises(MetadataRetrievalError, match="unexpected commit payload"):
        make_client(handler).resolve_reference(IDENTITY, validate_reference("main"), default_branch="main")


def test_rate_limited_resolution_is_typed() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return json_response(request, {}, status=403, headers={"x-ratelimit-remaining": "0"})

    with pytest.raises(RateLimitExceededError):
        make_client(handler).resolve_reference(IDENTITY, validate_reference("main"), default_branch="main")


# ---------------------------------------------------------------------------
# Tag probe
# ---------------------------------------------------------------------------
def test_tag_probe_reports_true_false_and_network_failure() -> None:
    def found(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/repos/psf/requests/git/ref/tags/v2.32.3"
        return json_response(request, {"ref": "refs/tags/v2.32.3"})

    assert make_client(found).is_ref_a_tag(IDENTITY, "v2.32.3") is True

    def missing(request: httpx.Request) -> httpx.Response:
        return json_response(request, {"message": "Not Found"}, status=404)

    assert make_client(missing).is_ref_a_tag(IDENTITY, "v9.9.9") is False

    def broken(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("boom", request=request)

    assert make_client(broken).is_ref_a_tag(IDENTITY, "v1") is False
