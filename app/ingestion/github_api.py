"""Minimal, read-only GitHub REST client.

Phase 1 only ever performs ``GET`` requests.  The client is used for two
things that a plain clone cannot provide reliably:

* repository metadata (existence, visibility, size, default branch) so that
  errors are precise and oversized downloads are refused *before* they start;
* reference resolution to an exact commit SHA, including short SHAs and tags.

The client degrades gracefully: a missing token, an exhausted rate limit or a
network hiccup is reported to the orchestrator, which can fall back to
``git ls-remote`` instead of failing the request.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote, urlsplit

import httpx

from app.core.config import Settings
from app.core.errors import (
    MetadataRetrievalError,
    NetworkFailureError,
    RateLimitExceededError,
    ReferenceNotFoundError,
    RepositoryAccessDeniedError,
    RepositoryNotFoundError,
)
from app.core.logging import get_logger, safe_text
from app.ingestion.urls import ValidatedReference
from app.models.common import ReferenceType
from app.models.repository import RepositoryIdentity

_log = get_logger("ingestion.github_api")

_API_VERSION = "2022-11-28"
_MAX_COMMIT_MESSAGE = 200


@dataclass(frozen=True, slots=True)
class RepositoryMetadataSnapshot:
    """Repository level metadata as reported by GitHub."""

    default_branch: str | None = None
    description: str | None = None
    is_private: bool = False
    is_archived: bool = False
    is_fork: bool = False
    stars: int | None = None
    forks: int | None = None
    open_issues: int | None = None
    size_kb: int | None = None
    license_spdx_id: str | None = None
    primary_language: str | None = None
    pushed_at: datetime | None = None
    created_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class ReferenceResolution:
    """A requested reference resolved to an exact commit."""

    commit_sha: str
    ref_type: ReferenceType
    resolved_via: str
    default_branch: str | None = None
    commit_message: str | None = None
    commit_author: str | None = None
    committed_at: datetime | None = None
    commit_source: str = "unknown"


def _parse_datetime(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return None


def _int_or_none(value: Any) -> int | None:
    return value if isinstance(value, int) else None


def _rate_limit_details(response: httpx.Response) -> dict[str, Any]:
    headers = response.headers
    details: dict[str, Any] = {"status_code": response.status_code}
    remaining = headers.get("x-ratelimit-remaining")
    reset = headers.get("x-ratelimit-reset")
    if remaining is not None:
        details["rate_limit_remaining"] = remaining
    if reset is not None:
        try:
            details["rate_limit_reset"] = datetime.fromtimestamp(int(reset), tz=timezone.utc).isoformat()
        except (TypeError, ValueError):  # pragma: no cover - defensive
            details["rate_limit_reset"] = reset
    retry_after = headers.get("retry-after")
    if retry_after:
        details["retry_after_seconds"] = retry_after
    return details


class GitHubApiClient:
    """Thin, read-only wrapper around a subset of the GitHub REST API."""

    def __init__(self, settings: Settings, *, client: httpx.Client | None = None) -> None:
        self._settings = settings
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": _API_VERSION,
            "User-Agent": settings.user_agent,
        }
        if settings.has_github_token:
            # SecretStr is unwrapped here only; it is never logged or returned.
            headers["Authorization"] = f"Bearer {settings.github_token.get_secret_value()}"  # type: ignore[union-attr]
        self._owned_client = client is None
        self._client = client or httpx.Client(
            base_url=settings.github_api_base_url,
            headers=headers,
            timeout=httpx.Timeout(settings.metadata_timeout_seconds, connect=min(10.0, settings.metadata_timeout_seconds)),
            follow_redirects=False,
        )

    # -- lifecycle ---------------------------------------------------------
    def close(self) -> None:
        if self._owned_client:
            self._client.close()

    def __enter__(self) -> "GitHubApiClient":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    # -- public API --------------------------------------------------------
    def get_repository(self, identity: RepositoryIdentity) -> RepositoryMetadataSnapshot:
        """Fetch repository metadata. Raises on missing/private/rate-limited."""
        path = f"/repos/{quote(identity.owner, safe='')}/{quote(identity.name, safe='')}"
        response = self._request(path, context="repository metadata")
        payload = self._json(response, context="repository metadata")
        license_info = payload.get("license") if isinstance(payload.get("license"), dict) else None
        return RepositoryMetadataSnapshot(
            default_branch=payload.get("default_branch") if isinstance(payload.get("default_branch"), str) else None,
            description=payload.get("description") if isinstance(payload.get("description"), str) else None,
            is_private=bool(payload.get("private", False)),
            is_archived=bool(payload.get("archived", False)),
            is_fork=bool(payload.get("fork", False)),
            stars=_int_or_none(payload.get("stargazers_count")),
            forks=_int_or_none(payload.get("forks_count")),
            open_issues=_int_or_none(payload.get("open_issues_count")),
            size_kb=_int_or_none(payload.get("size")),
            license_spdx_id=(license_info or {}).get("spdx_id") if license_info else None,
            primary_language=payload.get("language") if isinstance(payload.get("language"), str) else None,
            pushed_at=_parse_datetime(payload.get("pushed_at")),
            created_at=_parse_datetime(payload.get("created_at")),
        )

    def resolve_reference(
        self,
        identity: RepositoryIdentity,
        reference: ValidatedReference | None,
        *,
        default_branch: str | None,
        is_default_branch: bool = False,
    ) -> ReferenceResolution:
        """Resolve a reference (or the default branch) to an exact commit."""
        if reference is not None:
            if reference.is_full_sha:
                return ReferenceResolution(
                    commit_sha=reference.name,
                    ref_type=ReferenceType.COMMIT,
                    resolved_via="provided_commit_sha",
                    default_branch=default_branch,
                )
            ref_for_api = reference.name
            ref_type = ReferenceType.BRANCH
        else:
            if not default_branch:
                raise MetadataRetrievalError(
                    "Cannot resolve the default branch without repository metadata",
                    details={"repository": identity.canonical_id},
                )
            ref_for_api = default_branch
            ref_type = ReferenceType.DEFAULT_BRANCH

        commit = self._get_commit(identity, ref_for_api)
        sha = commit.get("sha")
        if not isinstance(sha, str) or len(sha) != 40:
            raise MetadataRetrievalError(
                "GitHub returned an unexpected commit payload",
                details={"repository": identity.canonical_id},
            )

        if reference is not None and reference.ref_type_hint == ReferenceType.COMMIT:
            ref_type = ReferenceType.COMMIT
        elif not is_default_branch:
            ref_type = _guess_ref_type(ref_type, reference)

        commit_info = commit.get("commit") if isinstance(commit.get("commit"), dict) else {}
        author_info = commit_info.get("author") if isinstance(commit_info.get("author"), dict) else {}
        message = commit_info.get("message") if isinstance(commit_info.get("message"), str) else None
        return ReferenceResolution(
            commit_sha=sha.lower(),
            ref_type=ref_type,
            resolved_via="github_api",
            default_branch=default_branch,
            commit_message=_first_line(message),
            commit_author=author_info.get("name") if isinstance(author_info.get("name"), str) else None,
            committed_at=_parse_datetime(author_info.get("date")),
            commit_source="github_api",
        )

    def is_ref_a_tag(self, identity: RepositoryIdentity, name: str) -> bool:
        """Best-effort tag probe, used only to label references correctly."""
        path = f"/repos/{quote(identity.owner, safe='')}/{quote(identity.name, safe='')}/git/ref/tags/{quote(name, safe='')}"
        try:
            response = self._client.get(path)
        except httpx.HTTPError:  # pragma: no cover - network hiccup, label only
            return False
        return response.status_code == 200

    # -- internals ---------------------------------------------------------
    def _get_commit(self, identity: RepositoryIdentity, ref: str) -> dict[str, Any]:
        path = (
            f"/repos/{quote(identity.owner, safe='')}/{quote(identity.name, safe='')}"
            f"/commits/{quote(ref, safe='')}"
        )
        try:
            response = self._request(path, context="reference resolution", allow_not_found=True)
        except MetadataRetrievalError as exc:
            if exc.details.get("status_code") == 404:
                raise ReferenceNotFoundError(
                    f"Reference '{safe_text(ref, 80)}' does not exist in {identity.canonical_id}",
                    details={"repository": identity.canonical_id, "ref": safe_text(ref, 80)},
                ) from exc
            raise
        return self._json(response, context="reference resolution")

    def _request(self, path: str, *, context: str, allow_not_found: bool = False) -> httpx.Response:
        try:
            response = self._client.get(path)
        except httpx.TimeoutException as exc:
            raise NetworkFailureError(
                f"Timed out while requesting {context} from GitHub",
                details={"path": urlsplit(str(path)).path, "timeout_seconds": self._settings.metadata_timeout_seconds},
                retryable=True,
            ) from exc
        except httpx.HTTPError as exc:
            raise NetworkFailureError(
                f"Network error while requesting {context} from GitHub",
                details={"reason": safe_text(exc, 200)},
                retryable=True,
            ) from exc

        if 300 <= response.status_code < 400:
            raise RepositoryNotFoundError(
                "GitHub redirected the request; the repository may have been renamed",
                details={"context": context, "status_code": response.status_code},
            )
        if response.status_code < 400:
            return response
        if allow_not_found and response.status_code == 404:
            raise MetadataRetrievalError(
                f"Not found while requesting {context}",
                details={"status_code": 404},
            )
        self._raise_for_status(response, context=context)
        raise AssertionError("unreachable")  # pragma: no cover

    def _raise_for_status(self, response: httpx.Response, *, context: str) -> None:
        status = response.status_code
        if status == 429 or (status == 403 and _is_rate_limited(response)):
            raise RateLimitExceededError(
                "GitHub API rate limit exceeded",
                details={"context": context, **_rate_limit_details(response)},
                retryable=True,
            )
        if status == 404:
            raise RepositoryNotFoundError(
                "The repository was not found. It may not exist, may have been renamed, or may be private.",
                details={"context": context, "status_code": 404},
            )
        if status in (401, 403, 451):
            raise RepositoryAccessDeniedError(
                "GitHub denied access to the repository",
                details={"context": context, "status_code": status},
            )
        if status == 422:
            raise MetadataRetrievalError(
                "GitHub rejected the request as unprocessable (invalid reference)",
                details={"context": context, "status_code": status},
            )
        raise MetadataRetrievalError(
            f"GitHub returned an unexpected status while requesting {context}",
            details={"context": context, "status_code": status},
            retryable=status >= 500,
        )

    @staticmethod
    def _json(response: httpx.Response, *, context: str) -> dict[str, Any]:
        try:
            payload = response.json()
        except ValueError as exc:
            raise MetadataRetrievalError(
                f"GitHub returned a non-JSON response while requesting {context}",
                details={"context": context, "status_code": response.status_code},
            ) from exc
        if not isinstance(payload, dict):
            raise MetadataRetrievalError(
                f"GitHub returned an unexpected JSON payload while requesting {context}",
                details={"context": context, "status_code": response.status_code},
            )
        return payload


def _is_rate_limited(response: httpx.Response) -> bool:
    if response.headers.get("x-ratelimit-remaining") == "0":
        return True
    retry_after = response.headers.get("retry-after")
    if retry_after:
        return True
    try:
        body = response.json()
    except ValueError:
        return False
    message = body.get("message") if isinstance(body, dict) else None
    return isinstance(message, str) and "rate limit" in message.lower()


def _guess_ref_type(ref_type: ReferenceType, reference: ValidatedReference | None) -> ReferenceType:
    """Label a non-default-branch reference without inventing information.

    GitHub's commit endpoint does not say whether a name was a branch or a tag;
    the orchestrator upgrades this to ``tag`` when a tag probe succeeds.  A
    commit-shaped reference is always labelled ``commit``.
    """
    if reference is None:
        return ref_type
    if reference.ref_type_hint is not None:
        return reference.ref_type_hint
    return ref_type


def _first_line(message: str | None) -> str | None:
    if not message:
        return None
    line = message.splitlines()[0].strip()
    return line[:_MAX_COMMIT_MESSAGE] if line else None


__all__ = ["GitHubApiClient", "ReferenceResolution", "RepositoryMetadataSnapshot"]
