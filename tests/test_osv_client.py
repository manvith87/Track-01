"""OSV HTTP client tests: bounded retries, timeouts, pagination, batch, errors.

Every request is served by an ``httpx.MockTransport`` handler, so these tests
are fully deterministic and never touch api.osv.dev.  Retries sleep through an
injected fake clock.
"""

from __future__ import annotations

import json
from typing import Any, Callable

import httpx
import pytest

from app.osv.client import OsvApiClient
from app.osv.config import OsvSettings
from app.osv.errors import (
    OsvInvalidResponseError,
    OsvRateLimitedError,
    OsvRecordNotFoundError,
    OsvRequestError,
    OsvTimeoutError,
    OsvUnavailableError,
)


class SleepRecorder:
    def __init__(self) -> None:
        self.calls: list[float] = []

    def __call__(self, seconds: float) -> None:
        self.calls.append(seconds)


def make_settings(**overrides: Any) -> OsvSettings:
    values = {"timeout_seconds": 5.0, "connect_timeout_seconds": 1.0}
    values.update(overrides)
    return OsvSettings(**values)


def make_transport(handler: Callable[[httpx.Request], httpx.Response]) -> httpx.Client:
    return httpx.Client(
        transport=httpx.MockTransport(handler),
        base_url="https://api.osv.dev",
        headers={"User-Agent": "blastradius-test"},
        follow_redirects=False,
    )


def json_response(payload: dict[str, Any], status: int = 200) -> httpx.Response:
    return httpx.Response(status, json=payload, request=httpx.Request("POST", "https://api.osv.dev/v1/query"))


# ---------------------------------------------------------------------------
# /v1/query
# ---------------------------------------------------------------------------
def test_query_returns_raw_response() -> None:
    requests_seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests_seen.append(request)
        return json_response({"vulns": [{"id": "GHSA-1"}]})

    client = OsvApiClient(make_settings(), client=make_transport(handler))
    body = client.query_vulnerabilities(ecosystem="PyPI", package_name="requests", version="2.3.0")
    assert body == {"vulns": [{"id": "GHSA-1"}]}
    sent = json.loads(requests_seen[0].content)
    assert sent == {
        "package": {"name": "requests", "ecosystem": "PyPI"},
        "version": "2.3.0",
    }
    assert "page_token" not in sent


def test_query_omits_version_when_absent() -> None:
    requests_seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests_seen.append(request)
        return json_response({"vulns": []})

    client = OsvApiClient(make_settings(), client=make_transport(handler))
    client.iter_vulnerabilities(ecosystem="PyPI", package_name="requests")
    sent = json.loads(requests_seen[0].content)
    assert "version" not in sent


def test_query_paginates_until_exhausted() -> None:
    tokens_sent: list[str | None] = []
    page = {"calls": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content or b"{}")
        tokens_sent.append(payload.get("page_token"))
        page["calls"] += 1
        if page["calls"] == 1:
            return json_response({"vulns": [{"id": "GHSA-1"}], "next_page_token": "tok-2"})
        return json_response({"vulns": [{"id": "GHSA-2"}]})

    client = OsvApiClient(make_settings(), client=make_transport(handler))
    records = client.iter_vulnerabilities(ecosystem="PyPI", package_name="requests", version="2.3.0")
    assert [r["id"] for r in records] == ["GHSA-1", "GHSA-2"]
    assert tokens_sent == [None, "tok-2"]


def test_query_pagination_respects_page_cap() -> None:
    page = {"calls": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        page["calls"] += 1
        return json_response({"vulns": [{"id": f"GHSA-{page['calls']}"}], "next_page_token": f"t{page['calls']}"})

    client = OsvApiClient(make_settings(max_pages_per_query=3), client=make_transport(handler))
    records = client.iter_vulnerabilities(ecosystem="PyPI", package_name="requests")
    assert len(records) == 3
    assert page["calls"] == 3


def test_query_rejects_malformed_bodies() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"<html>blocked</html>", request=request)

    client = OsvApiClient(make_settings(), client=make_transport(handler))
    with pytest.raises(OsvInvalidResponseError):
        client.query_vulnerabilities(ecosystem="PyPI", package_name="requests")


@pytest.mark.parametrize(
    "body",
    [
        pytest.param([{"vulns": []}], id="array-body"),
        pytest.param({"vulns": {"id": "x"}}, id="vulns-not-list"),
    ],
)
def test_query_rejects_structurally_invalid_bodies(body: Any) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return json_response(body)

    client = OsvApiClient(make_settings(), client=make_transport(handler))
    with pytest.raises(OsvInvalidResponseError):
        client.query_vulnerabilities(ecosystem="PyPI", package_name="requests")


# ---------------------------------------------------------------------------
# /v1/querybatch
# ---------------------------------------------------------------------------
def test_batch_returns_positional_results() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        sent = json.loads(request.content)
        assert [q["package"]["name"] for q in sent["queries"]] == ["requests", "jinja2"]
        return json_response({"results": [{"vulns": [{"id": "GHSA-1"}]}, {"vulns": []}]})

    client = OsvApiClient(make_settings(), client=make_transport(handler))
    results = client.query_batch(
        [
            {"package": {"name": "requests", "ecosystem": "PyPI"}, "version": "2.3.0"},
            {"package": {"name": "jinja2", "ecosystem": "PyPI"}, "version": "2.11.3"},
        ]
    )
    assert results == [{"vulns": [{"id": "GHSA-1"}]}, {"vulns": []}]


def test_batch_rejects_oversized_chunks() -> None:
    client = OsvApiClient(make_settings(batch_size=2), client=make_transport(lambda r: json_response({})))
    with pytest.raises(OsvRequestError):
        client.query_batch(
            [
                {"package": {"name": f"pkg{i}", "ecosystem": "PyPI"}, "version": "1.0.0"}
                for i in range(3)
            ]
        )


def test_batch_rejects_malformed_results() -> None:
    for payload in [{"results": "nope"}, {"results": [42]}]:
        def handler(request: httpx.Request, payload=payload) -> httpx.Response:
            return json_response(payload)

        client = OsvApiClient(make_settings(), client=make_transport(handler))
        with pytest.raises(OsvInvalidResponseError):
            client.query_batch([{"package": {"name": "requests", "ecosystem": "PyPI"}}])


def test_batch_empty_input_makes_no_request() -> None:
    client = OsvApiClient(
        make_settings(),
        client=make_transport(lambda r: pytest.fail("must not request")),
    )
    assert client.query_batch([]) == []


# ---------------------------------------------------------------------------
# GET /v1/vulns/{id}
# ---------------------------------------------------------------------------
def test_get_vulnerability_returns_record() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert request.url.path == "/v1/vulns/GHSA-1"
        return json_response({"id": "GHSA-1", "summary": "ok"})

    client = OsvApiClient(make_settings(), client=make_transport(handler))
    record = client.get_vulnerability("GHSA-1")
    assert record["id"] == "GHSA-1"


def test_get_vulnerability_rejects_bad_ids_without_requesting() -> None:
    client = OsvApiClient(
        make_settings(),
        client=make_transport(lambda r: pytest.fail("must not request")),
    )
    for bad in ("", "   ", "GHSA x", "id/with/slash"):
        with pytest.raises(OsvRequestError):
            client.get_vulnerability(bad)


def test_get_vulnerability_404_maps_to_record_not_found() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"code": 5, "message": "not found"}, request=request)

    client = OsvApiClient(make_settings(), client=make_transport(handler), sleep=SleepRecorder())
    with pytest.raises(OsvRecordNotFoundError):
        client.get_vulnerability("GHSA-unknown")


def test_get_vulnerability_rejects_record_without_id() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return json_response({"message": "weird"})

    client = OsvApiClient(make_settings(), client=make_transport(handler))
    with pytest.raises(OsvInvalidResponseError):
        client.get_vulnerability("GHSA-1")


# ---------------------------------------------------------------------------
# retries and failure mapping
# ---------------------------------------------------------------------------
def test_retries_then_succeeds_on_server_error() -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] < 3:
            return httpx.Response(500, json={"message": "boom"}, request=request)
        return json_response({"vulns": []})

    sleeper = SleepRecorder()
    client = OsvApiClient(make_settings(max_retries=3, retry_backoff_seconds=0.25), client=make_transport(handler), sleep=sleeper)
    body = client.query_vulnerabilities(ecosystem="PyPI", package_name="requests")
    assert body == {"vulns": []}
    assert calls["n"] == 3
    assert len(sleeper.calls) == 2
    # Exponential growth: base * 2**(attempt-1), plus jitter <= 25% of base.
    assert sleeper.calls[0] >= 0.25
    assert sleeper.calls[1] >= 0.5


def test_server_error_after_retry_exhaustion_raises_unavailable() -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(503, json={"message": "unavailable"}, request=request)

    sleeper = SleepRecorder()
    client = OsvApiClient(make_settings(max_retries=2), client=make_transport(handler), sleep=sleeper)
    with pytest.raises(OsvUnavailableError):
        client.query_vulnerabilities(ecosystem="PyPI", package_name="requests")
    assert calls["n"] == 3  # 1 initial attempt + 2 retries
    assert len(sleeper.calls) == 2


def test_connect_error_is_retried_and_raises_unavailable() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    sleeper = SleepRecorder()
    client = OsvApiClient(make_settings(max_retries=2), client=make_transport(handler), sleep=sleeper)
    with pytest.raises(OsvUnavailableError):
        client.query_vulnerabilities(ecosystem="PyPI", package_name="requests")
    assert len(sleeper.calls) == 2


def test_timeout_is_retried_and_raises_timeout_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("read timed out", request=request)

    sleeper = SleepRecorder()
    client = OsvApiClient(make_settings(max_retries=2), client=make_transport(handler), sleep=sleeper)
    with pytest.raises(OsvTimeoutError):
        client.query_vulnerabilities(ecosystem="PyPI", package_name="requests")
    assert len(sleeper.calls) == 2


def test_rate_limit_respects_retry_after_header() -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(429, headers={"Retry-After": "7"}, request=request)
        return json_response({"vulns": []})

    sleeper = SleepRecorder()
    client = OsvApiClient(make_settings(max_retries=2), client=make_transport(handler), sleep=sleeper)
    client.query_vulnerabilities(ecosystem="PyPI", package_name="requests")
    assert calls["n"] == 2
    assert sleeper.calls == [7.0]


def test_rate_limit_exhaustion_raises_rate_limited_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, headers={"Retry-After": "bogus"}, request=request)

    sleeper = SleepRecorder()
    client = OsvApiClient(make_settings(max_retries=2), client=make_transport(handler), sleep=sleeper)
    with pytest.raises(OsvRateLimitedError):
        client.query_vulnerabilities(ecosystem="PyPI", package_name="requests")
    assert len(sleeper.calls) == 2  # non-numeric Retry-After falls back to backoff


def test_client_errors_are_not_retried() -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(400, json={"message": "bad request"}, request=request)

    sleeper = SleepRecorder()
    client = OsvApiClient(make_settings(max_retries=3), client=make_transport(handler), sleep=sleeper)
    with pytest.raises(OsvRequestError):
        client.query_vulnerabilities(ecosystem="PyPI", package_name="requests")
    assert calls["n"] == 1
    assert sleeper.calls == []


def test_success_does_not_sleep() -> None:
    sleeper = SleepRecorder()
    client = OsvApiClient(
        make_settings(),
        client=make_transport(lambda r: json_response({"vulns": []})),
        sleep=sleeper,
    )
    client.query_vulnerabilities(ecosystem="PyPI", package_name="requests")
    assert sleeper.calls == []
