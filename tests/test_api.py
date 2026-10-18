"""HTTP API tests: contract, validation, error envelope and bounded payloads.

The ingestion service is overridden through the production dependency
(``app.api.deps.get_ingestion_service``), so these tests exercise the real
FastAPI app, the real request models and the real error handlers without any
network access.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.api.deps import get_app_settings, get_ingestion_service
from app.core.errors import (
    ArchiveExtractionError,
    DownloadTimeoutError,
    EmbeddedCredentialsError,
    IngestionTimeoutError,
    InputValidationError,
    InvalidReferenceError,
    InvalidRepositoryUrlError,
    MetadataRetrievalError,
    NetworkFailureError,
    RateLimitExceededError,
    ReferenceNotFoundError,
    RepositoryAccessDeniedError,
    RepositoryNotFoundError,
    RepositoryTooLargeError,
    RetrievalError,
    RetrievalToolMissingError,
    UnsafeRepositoryContentError,
    UnsupportedHostError,
)
from app.ingestion.retrieval import GitRetrievalError
from app.main import create_app
from tests.support import FAKE_SHA, make_settings

INGEST_PATH = "/api/v1/repositories/ingest"
PAYLOAD = {"repository_url": "https://github.com/example/clean"}


@pytest.fixture
def client_factory():
    created: list[TestClient] = []

    def factory(service, settings=None) -> TestClient:
        effective = settings or make_settings(log_level="ERROR")
        app = create_app(effective)
        app.dependency_overrides[get_ingestion_service] = lambda: service
        app.dependency_overrides[get_app_settings] = lambda: effective
        client = TestClient(app)
        created.append(client)
        return client

    yield factory
    for client in created:
        client.close()


# ---------------------------------------------------------------------------
# Success path
# ---------------------------------------------------------------------------
def test_ingest_endpoint_returns_the_full_structured_result(client_factory, canned_ingestion_result) -> None:
    calls: list[dict] = []

    def service(url, ref, *, settings):
        calls.append({"url": url, "ref": ref, "settings": settings})
        return canned_ingestion_result

    client = client_factory(service)
    response = client.post(INGEST_PATH, json={**PAYLOAD, "ref": "main"})

    assert response.status_code == 200
    assert calls[0]["url"] == "https://github.com/example/clean"
    assert calls[0]["ref"] == "main"
    assert response.headers["X-Request-ID"]

    body = response.json()
    assert body["status"] == "success"
    assert body["repository"]["identity"]["canonical_id"] == "github.com/example/clean"
    assert body["repository"]["commit"]["sha"] == FAKE_SHA
    assert body["repository"]["commit"]["short_sha"] == FAKE_SHA[:12]
    assert body["reference"]["ref_type"] == "default_branch"
    assert body["reference"]["resolved_commit_sha"] == FAKE_SHA
    assert body["summary"]["declarations"] == 4
    assert body["summary"]["warning_count"] == 0
    assert len(body["declarations"]) == 4
    assert len(body["manifests"]) == 2
    assert body["warnings"] == []
    assert body["errors"] == []
    assert body["truncated"] == {
        "declarations": False,
        "resolved_packages": False,
        "dependency_edges": False,
        "warnings": False,
        "errors": False,
        "manifests": False,
        "source_files": False,
    }

    formats = [entry["format"] for entry in body["supported_formats"]]
    assert formats == ["requirements.txt", "pyproject.toml", "poetry.lock", "uv.lock"]
    by_format = {entry["format"]: entry for entry in body["supported_formats"]}
    assert by_format["requirements.txt"]["is_lockfile"] is False
    assert by_format["poetry.lock"]["is_lockfile"] is True
    assert by_format["uv.lock"]["is_lockfile"] is True
    assert all(entry["capabilities"] for entry in body["supported_formats"])


def test_request_id_is_echoed_back(client_factory, canned_ingestion_result) -> None:
    client = client_factory(lambda *a, **k: canned_ingestion_result)
    response = client.post(INGEST_PATH, json=PAYLOAD, headers={"X-Request-ID": "trace-123"})
    assert response.status_code == 200
    assert response.headers["X-Request-ID"] == "trace-123"


# ---------------------------------------------------------------------------
# Request validation
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"repository_url": ""},
        {"repository_url": "x" * 4096},
        {**PAYLOAD, "ref": "r" * 300},
        {**PAYLOAD, "unexpected": "field"},
        {"repository_url": 12345},
    ],
)
def test_invalid_bodies_are_rejected_without_calling_the_service(client_factory, canned_ingestion_result, payload) -> None:
    calls: list[tuple] = []

    def service(url, ref, *, settings):  # pragma: no cover - must not be called
        calls.append((url, ref))
        return canned_ingestion_result

    client = client_factory(service)
    response = client.post(INGEST_PATH, json=payload)

    assert response.status_code == 422
    body = response.json()
    assert body["error"]["code"] == "invalid_input"
    assert body["error"]["stage"] == "validation"
    assert body["error"]["retryable"] is False
    assert body["error"]["details"]["errors"]
    # Raw input is never echoed back.
    assert "x" * 100 not in response.text
    assert calls == []


# ---------------------------------------------------------------------------
# Domain errors -> error envelope
# ---------------------------------------------------------------------------
DOMAIN_ERRORS = [
    pytest.param(InvalidRepositoryUrlError("bad url"), 400, "invalid_repository_url", False, id="invalid_url"),
    pytest.param(UnsupportedHostError("gitlab"), 400, "unsupported_host", False, id="unsupported_host"),
    pytest.param(EmbeddedCredentialsError("creds"), 400, "embedded_credentials", False, id="embedded_credentials"),
    pytest.param(InvalidReferenceError("bad ref"), 400, "invalid_reference", False, id="invalid_reference"),
    pytest.param(InputValidationError("bad input"), 400, "invalid_input", False, id="input_validation"),
    pytest.param(RepositoryNotFoundError("gone"), 404, "repository_not_found", False, id="not_found"),
    pytest.param(ReferenceNotFoundError("no ref"), 404, "reference_not_found", False, id="ref_not_found"),
    pytest.param(RepositoryAccessDeniedError("private"), 403, "repository_access_denied", False, id="denied"),
    pytest.param(RateLimitExceededError("limited"), 429, "rate_limit_exceeded", True, id="rate_limit"),
    pytest.param(RepositoryTooLargeError("big"), 413, "repository_too_large", False, id="too_large"),
    pytest.param(DownloadTimeoutError("slow"), 504, "download_timeout", True, id="download_timeout"),
    pytest.param(IngestionTimeoutError("budget"), 504, "ingestion_timeout", True, id="ingestion_timeout"),
    pytest.param(RetrievalToolMissingError("no git"), 503, "retrieval_tool_missing", False, id="no_tool"),
    pytest.param(UnsafeRepositoryContentError("unsafe"), 422, "unsafe_archive_content", False, id="unsafe"),
    pytest.param(ArchiveExtractionError("broken"), 502, "archive_extraction_failed", False, id="archive_error"),
    pytest.param(NetworkFailureError("net"), 502, "network_failure", True, id="network"),
    pytest.param(RetrievalError("failed"), 502, "retrieval_failed", False, id="retrieval"),
    pytest.param(GitRetrievalError("git failed"), 502, "retrieval_failed", False, id="git"),
    pytest.param(MetadataRetrievalError("meta"), 502, "retrieval_failed", False, id="metadata"),
]


@pytest.mark.parametrize(("error", "status", "code", "retryable"), DOMAIN_ERRORS)
def test_domain_errors_are_translated_into_the_envelope(client_factory, error, status, code, retryable) -> None:
    def service(url, ref, *, settings):
        raise error

    client = client_factory(service)
    response = client.post(INGEST_PATH, json=PAYLOAD)

    assert response.status_code == status
    body = response.json()
    assert set(body) == {"error"}
    assert body["error"]["code"] == code
    assert body["error"]["retryable"] is retryable
    assert body["error"]["stage"]
    assert body["error"]["message"]
    assert isinstance(body["error"]["details"], dict)


def test_unknown_routes_use_the_same_envelope(client_factory, canned_ingestion_result) -> None:
    client = client_factory(lambda *a, **k: canned_ingestion_result)

    missing = client.get("/api/v1/does-not-exist")
    assert missing.status_code == 404
    assert missing.json()["error"]["code"] == "http_404"

    wrong_method = client.get(INGEST_PATH)
    assert wrong_method.status_code == 405
    assert wrong_method.json()["error"]["code"] == "http_405"


def test_unexpected_errors_use_the_same_envelope() -> None:
    """Regression: an internal bug must not return a bare 500 text body.

    Live trigger: a TypeError inside conflict detection produced
    ``HTTP 500 "Internal Server Error"`` with no machine-readable error, so
    API clients could not distinguish it from a proxy failure.
    """

    def service(url, ref, *, settings):
        raise RuntimeError("unexpected bug")

    effective = make_settings(log_level="CRITICAL")
    app = create_app(effective)
    app.dependency_overrides[get_ingestion_service] = lambda: service
    app.dependency_overrides[get_app_settings] = lambda: effective
    client = TestClient(app, raise_server_exceptions=False)
    try:
        response = client.post(INGEST_PATH, json=PAYLOAD)
    finally:
        client.close()

    assert response.status_code == 500
    body = response.json()
    assert body["error"]["code"] == "internal_error"
    assert body["error"]["stage"] == "unknown"
    assert body["error"]["retryable"] is False
    assert body["error"]["message"]
    assert body["error"]["details"] == {"exception": "RuntimeError"}


# ---------------------------------------------------------------------------
# Meta endpoints
# ---------------------------------------------------------------------------
def test_health_endpoint(client_factory, canned_ingestion_result) -> None:
    client = client_factory(lambda *a, **k: canned_ingestion_result)
    response = client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["phase"] == "phase-4b-agent"


def test_formats_endpoint_lists_only_real_parsers(client_factory, canned_ingestion_result) -> None:
    client = client_factory(lambda *a, **k: canned_ingestion_result)
    response = client.get("/api/v1/repositories/formats")
    assert response.status_code == 200
    formats = response.json()
    assert [entry["format"] for entry in formats] == ["requirements.txt", "pyproject.toml", "poetry.lock", "uv.lock"]
    assert all(entry["support_level"] == "supported" for entry in formats)
    assert all(entry["capabilities"] for entry in formats)


# ---------------------------------------------------------------------------
# Response bounding
# ---------------------------------------------------------------------------
def test_large_results_are_truncated_and_flagged(client_factory, canned_ingestion_result) -> None:
    settings = make_settings(log_level="ERROR", max_api_records=1)
    client = client_factory(lambda *a, **k: canned_ingestion_result, settings=settings)
    response = client.post(INGEST_PATH, json=PAYLOAD)

    assert response.status_code == 200
    body = response.json()
    assert len(body["manifests"]) == 1
    assert len(body["declarations"]) == 1
    assert body["truncated"]["manifests"] is True
    assert body["truncated"]["declarations"] is True
    assert body["truncated"]["resolved_packages"] is False
    assert body["truncated"]["dependency_edges"] is False
    assert body["truncated"]["warnings"] is False
    assert body["truncated"]["errors"] is False
    assert body["truncated"]["source_files"] is False
