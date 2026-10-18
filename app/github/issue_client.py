"""The only GitHub write client in BlastRadius: issue creation (Phase 6).

Capabilities are deliberately minimal:

* ``GET /repos/{owner}/{repo}`` — validate that the configured identity can
  access the target and that issues are enabled (read-only metadata);
* ``POST /repos/{owner}/{repo}/issues`` — the one write BlastRadius performs;
* ``GET /search/issues`` — reconcile an ambiguous write outcome through the
  unique action marker embedded in the issue body.

Nothing else is exposed: no arbitrary URLs from request bodies, no labels, no
assignments, no pull requests, no repository file writes.  The token is read
from ``ActionSettings.github_token`` (a dedicated environment variable), is
sent only in the ``Authorization`` header and never appears in logs, errors or
issue content.

HTTP failures are translated into the typed Phase 6 taxonomy
(:mod:`app.core.errors`) so the API/MCP layers never leak provider exceptions.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Final
from urllib.parse import quote

import httpx

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

_API_VERSION: Final[str] = "2022-11-28"

#: The permission BlastRadius needs on the target repository, surfaced verbatim
#: in permission errors so an operator can fix the deployment.
REQUIRED_PERMISSION: Final[str] = (
    "'Issues: write' (fine-grained token) or the 'repo'/'public_repo' scope "
    "(classic token), plus read access to repository metadata"
)


@dataclass(frozen=True, slots=True)
class RepositoryAccess:
    """Result of the preflight repository metadata lookup."""

    full_name: str
    has_issues: bool
    permissions: dict[str, bool] = field(default_factory=dict)
    default_branch: str | None = None
    archived: bool = False
    permission_hint: str | None = None


@dataclass(frozen=True, slots=True)
class CreatedIssue:
    """A verified issue creation response."""

    number: int
    url: str
    title: str
    state: str | None = None


@dataclass(frozen=True, slots=True)
class IssueSummary:
    """One issue found while reconciling an ambiguous outcome."""

    number: int
    url: str
    title: str
    state: str | None = None


def _rate_limit_details(response: httpx.Response) -> dict[str, Any]:
    headers = response.headers
    details: dict[str, Any] = {"status_code": response.status_code}
    remaining = headers.get("x-ratelimit-remaining")
    reset = headers.get("x-ratelimit-reset")
    if remaining is not None:
        details["rate_limit_remaining"] = remaining
    if reset is not None:
        try:
            details["rate_limit_reset"] = datetime.fromtimestamp(
                int(reset), tz=timezone.utc
            ).isoformat()
        except (TypeError, ValueError):  # pragma: no cover - defensive
            details["rate_limit_reset"] = reset
    retry_after = headers.get("retry-after")
    if retry_after:
        details["retry_after_seconds"] = retry_after
    return details


def _is_rate_limited(response: httpx.Response) -> bool:
    if response.status_code == 429:
        return True
    if response.status_code != 403:
        return False
    if response.headers.get("x-ratelimit-remaining") == "0":
        return True
    return bool(response.headers.get("retry-after"))


def _json_or_none(response: httpx.Response) -> Any:
    try:
        return response.json()
    except ValueError:
        return None


class GitHubIssueClient:
    """Minimal, typed wrapper around the GitHub REST endpoints Phase 6 needs."""

    def __init__(
        self,
        settings: ActionSettings,
        *,
        client: httpx.Client | None = None,
    ) -> None:
        self._settings = settings
        self._client = client
        self._owns_client = client is None

    # -- lifecycle ----------------------------------------------------------

    def _http(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(
                timeout=httpx.Timeout(self._settings.timeout_seconds),
                follow_redirects=False,
            )
        return self._client

    def close(self) -> None:
        if self._owns_client and self._client is not None:
            self._client.close()
            self._client = None

    def __enter__(self) -> "GitHubIssueClient":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    # -- request helpers ----------------------------------------------------

    def _require_token(self) -> str:
        if not self._settings.has_token:
            raise ActionNotConfiguredError(
                "GitHub issue actions require a configured action token "
                "(BLASTRADIUS_ACTIONS_GITHUB_TOKEN)",
                details={"operation": "github_action"},
            )
        assert self._settings.github_token is not None  # guarded by has_token
        return self._settings.github_token.get_secret_value()

    def _headers(self) -> dict[str, str]:
        return {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": _API_VERSION,
            "User-Agent": self._settings.user_agent,
            "Authorization": f"Bearer {self._require_token()}",
        }

    def _url(self, path: str, **params: Any) -> str:
        base = self._settings.github_api_base_url.rstrip("/")
        request = httpx.Request("GET", f"{base}{path}", params=params or None)
        return str(request.url)

    @staticmethod
    def _repository_path(owner: str, name: str) -> str:
        return f"/repos/{quote(owner, safe='')}/{quote(name, safe='')}"

    def _raise_for_status(self, response: httpx.Response, *, operation: str) -> None:
        """Translate an error response; never include the token or URL secrets."""
        status = response.status_code
        if status < 400:
            return
        if status < 500:
            if _is_rate_limited(response):
                raise RateLimitExceededError(
                    "GitHub rate limit exceeded for the configured action token",
                    details=_rate_limit_details(response),
                )
            if status == 401:
                raise GitHubCredentialsInvalidError(
                    "GitHub rejected the configured action token (invalid or expired)",
                    details={"operation": operation, "status_code": status},
                )
            if status == 403:
                raise GitHubPermissionDeniedError(
                    "The configured GitHub identity is not permitted to perform "
                    f"this operation; it needs {REQUIRED_PERMISSION}",
                    details={
                        "operation": operation,
                        "status_code": status,
                        "required_permissions": ["issues:write", "metadata:read"],
                    },
                )
            if status == 404:
                raise RepositoryNotFoundError(
                    "GitHub reports the repository as not found or not visible to "
                    "the configured action token",
                    details={"operation": operation, "status_code": status},
                )
            if status == 410:
                raise GitHubIssuesDisabledError(
                    "GitHub reports that issues are disabled for the target repository",
                    details={"operation": operation, "status_code": status},
                )
            if operation == "write":
                raise GitHubIssueCreationError(
                    "GitHub rejected the issue creation request",
                    details={"status_code": status},
                )
            raise NetworkFailureError(
                "Unexpected GitHub response while reading repository metadata",
                details={"operation": operation, "status_code": status},
            )
        # 5xx
        if operation == "write":
            raise GitHubWriteAmbiguousError(
                "GitHub returned a server error during the write; the outcome is unknown",
                details={"operation": operation, "status_code": status},
            )
        raise NetworkFailureError(
            "GitHub returned a server error while reading repository metadata",
            details={"operation": operation, "status_code": status},
        )

    def _request(
        self,
        method: str,
        path: str,
        *,
        operation: str,
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
    ) -> httpx.Response:
        try:
            response = self._http().request(
                method,
                f"{self._settings.github_api_base_url.rstrip('/')}{path}",
                headers=self._headers(),
                params=params,
                json=json_body,
            )
        except httpx.TimeoutException as exc:
            if operation == "write":
                raise GitHubWriteAmbiguousError(
                    "The GitHub write timed out; the outcome is unknown",
                    details={"operation": operation, "cause": type(exc).__name__},
                ) from exc
            raise NetworkFailureError(
                "Timed out while contacting GitHub",
                details={"operation": operation, "cause": type(exc).__name__},
            ) from exc
        except httpx.TransportError as exc:
            if operation == "write":
                raise GitHubWriteAmbiguousError(
                    "The GitHub write failed at the transport level; the outcome is unknown",
                    details={"operation": operation, "cause": type(exc).__name__},
                ) from exc
            raise NetworkFailureError(
                "Network failure while contacting GitHub",
                details={"operation": operation, "cause": type(exc).__name__},
            ) from exc

        if 300 <= response.status_code < 400:
            # Redirects are never followed: a moved/renamed repository must not
            # silently change the write target.
            raise ActionEvidenceChangedError(
                "GitHub redirected the repository request; the repository may have "
                "been renamed or moved since the analysis",
                details={"operation": operation, "status_code": response.status_code},
            )
        self._raise_for_status(response, operation=operation)
        return response

    # -- public API ---------------------------------------------------------

    def check_repository_access(self, owner: str, name: str) -> RepositoryAccess:
        """Verify the token can see the repository and issues are enabled."""
        if not owner or not name:
            raise InputValidationError("owner and name are required")
        response = self._request("GET", self._repository_path(owner, name), operation="read")
        payload = _json_or_none(response)
        if not isinstance(payload, dict):
            raise NetworkFailureError(
                "GitHub returned an unreadable repository metadata response",
                details={"operation": "read", "status_code": response.status_code},
            )
        full_name = payload.get("full_name")
        if not isinstance(full_name, str) or not full_name.strip():
            full_name = f"{owner}/{name}"
        has_issues = payload.get("has_issues")
        if not isinstance(has_issues, bool):
            has_issues = True
        raw_permissions = payload.get("permissions")
        permissions: dict[str, bool] = {}
        if isinstance(raw_permissions, dict):
            permissions = {
                key: value for key, value in raw_permissions.items() if isinstance(value, bool)
            }
        permission_hint: str | None = None
        if permissions and permissions.get("pull"):
            can_manage = any(
                permissions.get(role)
                for role in ("push", "triage", "maintain", "admin")
            )
            if not can_manage:
                permission_hint = (
                    "the configured token reports read-only repository permissions; "
                    f"creating an issue needs {REQUIRED_PERMISSION}"
                )
        default_branch = payload.get("default_branch")
        return RepositoryAccess(
            full_name=full_name.strip(),
            has_issues=has_issues,
            permissions=permissions,
            default_branch=default_branch if isinstance(default_branch, str) else None,
            archived=bool(payload.get("archived")),
            permission_hint=permission_hint,
        )

    def create_issue(
        self,
        owner: str,
        name: str,
        *,
        title: str,
        body: str,
    ) -> CreatedIssue:
        """Create one issue.  Only a verified response counts as success."""
        if not owner or not name:
            raise InputValidationError("owner and name are required")
        if not title or not body:
            raise InputValidationError("title and body are required")
        response = self._request(
            "POST",
            f"{self._repository_path(owner, name)}/issues",
            operation="write",
            json_body={"title": title, "body": body},
        )
        payload = _json_or_none(response)
        number = payload.get("number") if isinstance(payload, dict) else None
        url = payload.get("html_url") if isinstance(payload, dict) else None
        created_title = payload.get("title") if isinstance(payload, dict) else None
        state = payload.get("state") if isinstance(payload, dict) else None
        if (
            not isinstance(number, int)
            or number <= 0
            or not isinstance(url, str)
            or not url.startswith("https://")
            or not isinstance(created_title, str)
        ):
            # A success status with an unusable payload: the issue may exist.
            raise GitHubWriteAmbiguousError(
                "GitHub accepted the write but the response could not be verified; "
                "the outcome is unknown",
                details={"operation": "write", "status_code": response.status_code},
            )
        return CreatedIssue(
            number=number,
            url=url,
            title=created_title,
            state=state if isinstance(state, str) else None,
        )

    def find_issue_by_marker(
        self,
        owner: str,
        name: str,
        marker: str,
    ) -> list[IssueSummary]:
        """Return issues whose body contains the unique action marker.

        Used only to reconcile an ambiguous write outcome.  The caller decides
        what a non-unique result means; this method never assumes the issue
        exists.
        """
        if not owner or not name or not marker:
            raise InputValidationError("owner, name and marker are required")
        query = f'repo:{owner}/{name} in:body "{marker}"'
        response = self._request(
            "GET",
            "/search/issues",
            operation="read",
            params={"q": query, "per_page": 5},
        )
        payload = _json_or_none(response)
        items = payload.get("items") if isinstance(payload, dict) else None
        if not isinstance(items, list):
            raise NetworkFailureError(
                "GitHub returned an unreadable issue search response",
                details={"operation": "read", "status_code": response.status_code},
            )
        summaries: list[IssueSummary] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            number = item.get("number")
            url = item.get("html_url")
            title = item.get("title")
            state = item.get("state")
            if not isinstance(number, int) or number <= 0:
                continue
            if not isinstance(url, str) or not url.startswith("https://"):
                continue
            if not isinstance(title, str):
                continue
            summaries.append(
                IssueSummary(
                    number=number,
                    url=url,
                    title=title,
                    state=state if isinstance(state, str) else None,
                )
            )
        return summaries


__all__ = [
    "REQUIRED_PERMISSION",
    "CreatedIssue",
    "GitHubIssueClient",
    "IssueSummary",
    "RepositoryAccess",
]
