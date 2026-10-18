"""HTTP client for the OSV.dev REST API (Phase 3).

Endpoints used (https://google.github.io/osv.dev/api/):

* ``POST /v1/query``            - vulnerabilities for one package (+ version/commit)
* ``POST /v1/querybatch``       - id-only discovery for many queries at once
* ``GET  /v1/vulns/{id}``        - full vulnerability record

Client behaviour:

* every request carries a bounded timeout and a ``User-Agent``;
* retryable failures (connect/transport errors, timeouts, HTTP 429 and 5xx)
  are retried a bounded number of times with exponential backoff; the
  upstream ``Retry-After`` header is respected when present;
* non-retryable HTTP 4xx (except 429) fail fast with typed errors;
* malformed bodies raise :class:`OsvInvalidResponseError` instead of
  partially-trusted data;
* every retry/response size is bounded through :class:`app.osv.config.OsvSettings`
  so a stuck upstream can never hang an ingestion run.

The client never invents vulnerability data: responses are returned as raw
JSON objects and decoded strictly by :mod:`app.osv.models`.
"""

from __future__ import annotations

import json
import random
import time
from collections.abc import Callable, Mapping, Sequence
from typing import Any

import httpx

from app.core.logging import get_logger, safe_text
from app.osv.config import OsvSettings
from app.osv.errors import (
    OsvError,
    OsvInvalidResponseError,
    OsvRateLimitedError,
    OsvRecordNotFoundError,
    OsvRequestError,
    OsvTimeoutError,
    OsvUnavailableError,
)

_log = get_logger("osv.client")

SleepCallable = Callable[[float], None]

#: HTTP statuses for which a retry is attempted (besides 429, handled with
#: Retry-After awareness).
_RETRYABLE_STATUS: frozenset[int] = frozenset({500, 502, 503, 504})


class OsvApiClient:
    """Thin, read-only wrapper around the OSV.dev REST API."""

    def __init__(
        self,
        settings: OsvSettings,
        *,
        client: httpx.Client | None = None,
        sleep: SleepCallable | None = None,
    ) -> None:
        self._settings = settings
        self._owned_client = client is None
        self._client = client or httpx.Client(
            base_url=settings.base_url,
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                "User-Agent": "blastradius (+https://github.com/blastradius)",
            },
            timeout=httpx.Timeout(
                settings.timeout_seconds, connect=settings.connect_timeout_seconds
            ),
            follow_redirects=False,
        )
        self._sleep: SleepCallable = sleep or time.sleep

    # -- lifecycle ----------------------------------------------------------
    def close(self) -> None:
        if self._owned_client:
            self._client.close()

    def __enter__(self) -> "OsvApiClient":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    # -- public API ----------------------------------------------------------
    def query_vulnerabilities(
        self,
        *,
        ecosystem: str,
        package_name: str,
        version: str | None = None,
        page_token: str | None = None,
    ) -> dict[str, Any]:
        """Run ``POST /v1/query`` and return the raw response object.

        The response is ``{"vulns": [...], "next_page_token": "..."?}``.
        Pagination is *not* followed here (use
        :meth:`iter_vulnerabilities`); the service decides how many pages to
        trust.
        """
        payload: dict[str, Any] = {
            "package": {"name": package_name, "ecosystem": ecosystem}
        }
        if version:
            payload["version"] = version
        if page_token:
            payload["page_token"] = page_token
        body = self._request_expect_json("POST", "/v1/query", payload)
        return self._validate_query_response(body)

    def iter_vulnerabilities(
        self,
        *,
        ecosystem: str,
        package_name: str,
        version: str | None = None,
    ) -> list[dict[str, Any]]:
        """Run ``POST /v1/query`` and follow pagination, up to the page cap.

        Returns every raw vulnerability object across the followed pages.
        """
        raw_records: list[dict[str, Any]] = []
        token: str | None = None
        for _ in range(self._settings.max_pages_per_query):
            response = self.query_vulnerabilities(
                ecosystem=ecosystem,
                package_name=package_name,
                version=version,
                page_token=token,
            )
            raw_records.extend(response.get("vulns") or [])
            token = response.get("next_page_token")
            if not token:
                break
        return raw_records

    def query_batch(self, queries: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
        """Run ``POST /v1/querybatch`` for a bounded chunk of queries.

        Each query is a ``/v1/query`` payload (package/version or commit).
        Returns the raw per-query results in request order; every entry is
        validated to be an object so callers never index into malformed data.
        """
        if not queries:
            return []
        if len(queries) > self._settings.batch_size:
            raise OsvRequestError(
                f"querybatch accepts at most {self._settings.batch_size} queries per request",
                details={"submitted": len(queries)},
            )
        body = self._request_expect_json("POST", "/v1/querybatch", {"queries": list(queries)})
        results = body.get("results")
        if not isinstance(results, list):
            raise OsvInvalidResponseError(
                "querybatch response is missing a 'results' list",
                details={"operation": "querybatch"},
            )
        validated: list[dict[str, Any]] = []
        for index, item in enumerate(results):
            if not isinstance(item, dict):
                raise OsvInvalidResponseError(
                    "querybatch result entry is not an object",
                    details={"operation": "querybatch", "index": index},
                )
            validated.append(item)
        return validated

    def get_vulnerability(self, osv_id: str) -> dict[str, Any]:
        """Fetch one full vulnerability record via ``GET /v1/vulns/{id}``."""
        identifier = osv_id.strip()
        if not identifier or "/" in identifier or any(ch.isspace() for ch in identifier):
            raise OsvRequestError("vulnerability id must be a non-empty, unpathed token")
        body = self._request_expect_json("GET", f"/v1/vulns/{identifier}", None)
        if not isinstance(body, dict) or not isinstance(body.get("id"), str):
            raise OsvInvalidResponseError(
                "vulnerability record response is missing an 'id'",
                details={"operation": "get_vulns"},
            )
        return body

    # -- internals -----------------------------------------------------------
    def _request_expect_json(
        self, method: str, url: str, payload: Mapping[str, Any] | None
    ) -> Any:
        """Perform one (retried) request and decode a JSON body."""
        response = self._send_with_retries(method, url, payload)
        try:
            decoded = response.json()
        except (json.JSONDecodeError, ValueError) as exc:
            raise OsvInvalidResponseError(
                "OSV API returned a malformed JSON body for the request",
                details={"operation": safe_text(url, 120)},
            ) from exc
        return decoded

    def _send_with_retries(
        self, method: str, url: str, payload: Mapping[str, Any] | None
    ) -> httpx.Response:
        """Send one request, retrying bounded, retryable failures."""
        attempts = 0
        max_attempts = self._settings.max_retries + 1
        last_error: OsvError | None = None
        while attempts < max_attempts:
            attempts += 1
            try:
                response = self._client.request(
                    method, url, json=dict(payload) if payload is not None else None
                )
            except httpx.TimeoutException as exc:
                error: OsvError = OsvTimeoutError(details={"operation": safe_text(url, 120)})
                if attempts < max_attempts:
                    last_error = error
                    self._backoff(attempts)
                    continue
                raise error from exc
            except httpx.HTTPError as exc:  # connect / read / network errors
                error = OsvUnavailableError(details={"operation": safe_text(url, 120)})
                if attempts < max_attempts:
                    last_error = error
                    self._backoff(attempts)
                    continue
                raise error from exc

            status = response.status_code
            if status < 400:
                return response
            if status == 404:
                raise OsvRecordNotFoundError(
                    details={"operation": safe_text(url, 120)}
                )
            if status == 429:
                last_error = OsvRateLimitedError(
                    details={
                        "operation": safe_text(url, 120),
                        "retry_after_seconds": response.headers.get("retry-after"),
                    }
                )
                if attempts < max_attempts:
                    self._backoff(
                        attempts, retry_after=_retry_after(response.headers)
                    )
                    continue
                raise last_error
            if status in _RETRYABLE_STATUS:
                last_error = OsvUnavailableError(
                    details={"operation": safe_text(url, 120), "http_status": status}
                )
                if attempts < max_attempts:
                    self._backoff(attempts)
                    continue
                raise last_error
            raise OsvRequestError(
                details={"operation": safe_text(url, 120), "http_status": status}
            )
        # Defensive: the loop always raises before exhausting attempts.
        raise last_error or OsvUnavailableError(details={"operation": safe_text(url, 120)})

    def _validate_query_response(self, body: Any) -> dict[str, Any]:
        if not isinstance(body, dict):
            raise OsvInvalidResponseError(
                "query response must be a JSON object",
                details={"operation": "query"},
            )
        vulns = body.get("vulns")
        if vulns is not None and not isinstance(vulns, list):
            raise OsvInvalidResponseError(
                "query response 'vulns' must be a list when present",
                details={"operation": "query"},
            )
        return body

    def _backoff(
        self, attempt: int, *, retry_after: float | None = None
    ) -> None:
        """Sleep before the next retry (bounded, with jitter)."""
        if retry_after and retry_after > 0:
            delay = min(retry_after, 30.0)
        else:
            base = self._settings.retry_backoff_seconds * (2 ** (attempt - 1))
            delay = base + random.uniform(0, base * 0.25)
        self._sleep(delay)
        _log.debug("osv retry attempt=%d delay=%.2fs", attempt, delay)


def _retry_after(headers: Mapping[str, str]) -> float | None:
    """Parse the ``Retry-After`` header when it is a numeric value."""
    value = headers.get("retry-after")
    if not value:
        return None
    try:
        parsed = float(value.strip())
    except ValueError:
        return None
    if parsed <= 0:
        return None
    return min(parsed, 30.0)


__all__ = [
    "OsvApiClient",
    "SleepCallable",
]
