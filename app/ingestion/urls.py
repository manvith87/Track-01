"""GitHub repository URL and reference validation.

Everything that arrives through the API is treated as hostile input.  A URL is
only accepted when it is:

* ``https`` (no ``http``, ``git``, ``ssh``, ``file`` schemes);
* hosted on ``github.com`` (no other host, no subdomains, no ports);
* a repository *root* (``/owner/repo`` optionally with ``.git``);
* free of credentials, tokens and other secrets;
* free of path traversal, control characters and local filesystem paths.

References (branch / tag / commit) are validated against Git's own ref naming
rules before they are ever handed to ``git``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import unquote, urlsplit

from app.core.config import Settings, get_settings
from app.core.errors import (
    EmbeddedCredentialsError,
    InvalidReferenceError,
    InvalidRepositoryUrlError,
    UnsupportedHostError,
)
from app.models.common import ReferenceType
from app.models.repository import RepositoryIdentity

SUPPORTED_HOSTS = frozenset({"github.com", "www.github.com"})
ALLOWED_SCHEMES = frozenset({"https"})
MAX_URL_LENGTH = 2048
MAX_REF_LENGTH = 255

_OWNER_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")
_REPO_RE = re.compile(r"^[A-Za-z0-9._-]{1,100}$")
_COMMIT_RE = re.compile(r"^[0-9a-fA-F]{7,40}$")
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")
_REF_FORBIDDEN = re.compile(r"[~^:?*\[\]\\\s]")
_SENSITIVE_QUERY_KEYS = frozenset(
    {"token", "access_token", "key", "api_key", "secret", "signature", "sig", "password", "auth", "private_token"}
)

#: Path segments that identify a sub-page rather than the repository root.
_NON_ROOT_SEGMENTS = {
    "blob",
    "raw",
    "releases",
    "issues",
    "pulls",
    "actions",
    "wiki",
    "settings",
    "blame",
    "archive",
    "compare",
    "graphs",
    "network",
    "projects",
    "security",
    "discussions",
    "packages",
    "deployments",
    "contributors",
    "tags",
}
#: Path segments that carry a reference we can honour.
_REF_SEGMENTS = {"tree": ReferenceType.BRANCH, "commits": ReferenceType.BRANCH, "commit": ReferenceType.COMMIT}


@dataclass(frozen=True, slots=True)
class ValidatedReference:
    """A reference string that passed validation."""

    raw: str
    name: str
    ref_type_hint: ReferenceType | None
    is_full_sha: bool


@dataclass(frozen=True, slots=True)
class ParsedRepositoryUrl:
    """Validation output for a repository URL."""

    identity: RepositoryIdentity
    derived_ref: ValidatedReference | None = None
    ignored_query: bool = False
    original: str = ""


def validate_reference(raw: str) -> ValidatedReference:
    """Validate and normalise an optional branch / tag / commit reference.

    Raises :class:`InvalidReferenceError` for anything that could be abused as
    a Git option, a path or a different protocol.  The reference is *never*
    replaced by the default branch: an unknown reference fails loudly later.
    """
    if raw is None or not isinstance(raw, str):
        raise InvalidReferenceError("ref must be a string", details={"ref": repr(raw)})

    text = raw.strip()
    if not text:
        raise InvalidReferenceError("ref must not be empty")
    if len(text) > MAX_REF_LENGTH:
        raise InvalidReferenceError(
            f"ref is longer than {MAX_REF_LENGTH} characters", details={"length": len(text)}
        )
    if _CONTROL_CHARS.search(text):
        raise InvalidReferenceError("ref contains control characters")
    if text.startswith("-"):
        raise InvalidReferenceError("ref must not start with '-'", details={"ref": text})
    if "\\" in text:
        raise InvalidReferenceError("ref must not contain backslashes", details={"ref": text})
    if text.endswith("/") or text.startswith("/"):
        raise InvalidReferenceError("ref must not start or end with '/'", details={"ref": text})
    if "//" in text or ".." in text:
        raise InvalidReferenceError("ref contains an illegal path sequence", details={"ref": text})
    if text.endswith(".lock") or text.endswith("."):
        raise InvalidReferenceError("ref must not end with '.lock' or '.'", details={"ref": text})
    if "@{" in text:
        raise InvalidReferenceError("ref must not contain '@{'", details={"ref": text})
    if _REF_FORBIDDEN.search(text):
        raise InvalidReferenceError(
            "ref contains characters that are not allowed in Git references", details={"ref": text}
        )

    original = text
    # Normalise fully qualified refs to the short form Git/GitHub accept.
    for prefix in ("refs/heads/", "refs/tags/", "refs/remotes/origin/"):
        if text.startswith(prefix):
            text = text[len(prefix) :]
            break
    if not text:
        raise InvalidReferenceError("ref must not be empty after normalisation", details={"ref": original})

    if _COMMIT_RE.match(text):
        is_full_sha = len(text) == 40
        return ValidatedReference(
            raw=original,
            name=text.lower(),
            ref_type_hint=ReferenceType.COMMIT if is_full_sha else None,
            is_full_sha=is_full_sha,
        )

    return ValidatedReference(raw=original, name=text, ref_type_hint=None, is_full_sha=False)


def parse_repository_url(raw: str, *, settings: Settings | None = None) -> ParsedRepositoryUrl:
    """Validate and normalise a public GitHub repository URL.

    Returns the canonical :class:`RepositoryIdentity` plus any reference that
    was embedded in the URL (``/tree/<ref>`` or ``/commit/<sha>``).
    """
    settings = settings or get_settings()

    if raw is None or not isinstance(raw, str):
        raise InvalidRepositoryUrlError("repository_url must be a string", details={"type": type(raw).__name__})

    text = raw.strip()
    if not text:
        raise InvalidRepositoryUrlError("repository_url must not be empty")
    if len(text) > MAX_URL_LENGTH:
        raise InvalidRepositoryUrlError(
            f"repository_url is longer than {MAX_URL_LENGTH} characters", details={"length": len(text)}
        )
    if _CONTROL_CHARS.search(text):
        raise InvalidRepositoryUrlError("repository_url contains control characters")

    # Reject scp style / SSH input early: it carries a username and a colon.
    if re.match(r"^[A-Za-z0-9._-]+@[A-Za-z0-9._-]+:", text):
        raise InvalidRepositoryUrlError(
            "SSH/scp style repository URLs are not supported; use https://github.com/<owner>/<repo>",
            details={"url": _redact(text)},
        )
    if re.match(r"^[A-Za-z]:[\\/]", text):
        raise InvalidRepositoryUrlError(
            "Local filesystem paths are not accepted; use https://github.com/<owner>/<repo>",
            details={"url": _redact(text)},
        )

    parts = urlsplit(text)
    scheme = (parts.scheme or "").lower()
    if not scheme:
        raise InvalidRepositoryUrlError(
            "repository_url must be an absolute https URL, e.g. https://github.com/psf/requests",
            details={"url": _redact(text)},
        )
    if scheme not in ALLOWED_SCHEMES:
        raise InvalidRepositoryUrlError(
            f"unsupported URL scheme '{scheme}'; only https is accepted",
            details={"url": _redact(text)},
        )

    if parts.username or parts.password:
        raise EmbeddedCredentialsError(
            "repository_url must not contain credentials",
            details={"url": _redact(text)},
        )

    host = (parts.hostname or "").lower().rstrip(".")
    if not host:
        raise InvalidRepositoryUrlError("repository_url has no host", details={"url": _redact(text)})
    if host not in SUPPORTED_HOSTS:
        raise UnsupportedHostError(
            "only repositories on github.com are supported",
            details={"host": host},
        )
    try:
        port = parts.port
    except ValueError as exc:
        raise InvalidRepositoryUrlError("repository_url has an invalid port", details={"url": _redact(text)}) from exc
    if port not in (None, 443):
        raise InvalidRepositoryUrlError(
            "repository_url must not specify a port", details={"port": port}
        )

    ignored_query = False
    if parts.query:
        sensitive = sorted(
            {
                chunk.split("=", 1)[0].lower()
                for chunk in parts.query.split("&")
                if chunk and chunk.split("=", 1)[0].lower() in _SENSITIVE_QUERY_KEYS
            }
        )
        if sensitive:
            raise EmbeddedCredentialsError(
                "repository_url must not contain credentials or tokens in the query string",
                details={"keys": sensitive},
            )
        ignored_query = True

    segments = [segment for segment in unquote(parts.path).split("/") if segment != ""]
    if len(segments) < 2:
        raise InvalidRepositoryUrlError(
            "repository_url must point to a repository root, e.g. https://github.com/<owner>/<repo>",
            details={"url": _redact(text)},
        )

    owner_raw, repo_raw = segments[0], segments[1]
    if owner_raw in {".", ".."} or repo_raw in {".", ".."}:
        raise InvalidRepositoryUrlError("repository_url contains path traversal", details={"url": _redact(text)})
    if not _OWNER_RE.match(owner_raw):
        raise InvalidRepositoryUrlError("repository_url contains an invalid owner name", details={"owner": owner_raw})

    repo_name = repo_raw[:-4] if repo_raw.lower().endswith(".git") else repo_raw
    if not _REPO_RE.match(repo_name) or repo_name in {".", ".."}:
        raise InvalidRepositoryUrlError(
            "repository_url contains an invalid repository name", details={"repository": repo_raw}
        )

    derived_ref: ValidatedReference | None = None
    if len(segments) > 2:
        extra = segments[2].lower()
        if extra in _REF_SEGMENTS:
            remainder = "/".join(segments[3:]).strip("/")
            if not remainder:
                raise InvalidRepositoryUrlError(
                    "repository_url points to a reference but the reference is missing",
                    details={"url": _redact(text)},
                )
            derived_ref = validate_reference(remainder)
        elif extra in _NON_ROOT_SEGMENTS:
            raise InvalidRepositoryUrlError(
                "repository_url must point to the repository root, not to a sub-page",
                details={"segment": extra},
            )
        else:
            raise InvalidRepositoryUrlError(
                "repository_url contains unexpected path segments; use https://github.com/<owner>/<repo>",
                details={"segment": extra},
            )

    canonical_id = f"github.com/{owner_raw.lower()}/{repo_name.lower()}"
    canonical_url = f"{settings.github_web_base_url}/{owner_raw}/{repo_name}"
    identity = RepositoryIdentity(
        host="github.com",
        owner=owner_raw,
        name=repo_name,
        canonical_id=canonical_id,
        canonical_url=canonical_url,
        clone_url=f"{canonical_url}.git",
        api_url=f"{settings.github_api_base_url}/repos/{owner_raw}/{repo_name}",
    )
    return ParsedRepositoryUrl(
        identity=identity,
        derived_ref=derived_ref,
        ignored_query=ignored_query,
        original=text,
    )


def _redact(url: str) -> str:
    """Redact secrets before a URL is embedded in a message."""
    from app.ingestion.safety import redact_url

    return redact_url(url)


__all__ = [
    "ALLOWED_SCHEMES",
    "ParsedRepositoryUrl",
    "SUPPORTED_HOSTS",
    "ValidatedReference",
    "parse_repository_url",
    "validate_reference",
]
