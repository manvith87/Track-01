"""Safe repository retrieval.

Two strategies are implemented, both read-only:

``git``
    A shallow clone performed with a hardened Git environment: only the
    ``https`` transport is allowed, global/system configuration is bypassed,
    credential prompting is disabled, hooks and LFS smudging are neutralised
    and symlink creation is turned off.  The requested commit is fetched by
    SHA (falling back to a shallow clone of the named reference), so the tree
    that is analysed is provably the tree of the recorded SHA.

``archive``
    A byte-capped download of GitHub's ``codeload`` tarball for the exact SHA,
    extracted by :func:`app.ingestion.safety.extract_tar_safely`, which never
    creates symlinks/hardlinks/device nodes and refuses paths that escape the
    extraction root.

Neither strategy executes repository code: no ``setup.py``, no build backend,
no package installation, no imports of the analysed project.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final, Protocol
from urllib.parse import quote

import httpx

from app.core.config import Settings
from app.core.errors import (
    DownloadTimeoutError,
    NetworkFailureError,
    RateLimitExceededError,
    ReferenceNotFoundError,
    RepositoryAccessDeniedError,
    RepositoryNotFoundError,
    RepositoryTooLargeError,
    RetrievalError,
    RetrievalToolMissingError,
    UnsafeRepositoryContentError,
)
from app.core.logging import get_logger, safe_text
from app.ingestion.safety import (
    ArchiveExtractionReport,
    extract_tar_safely,
    redact_url,
    remove_tree,
)
from app.ingestion.urls import ValidatedReference
from app.models.common import (
    IngestionStage,
    ReferenceType,
    RetrievalStrategy,
    Severity,
    WarningCode,
)
from app.models.ingestion import IngestionWarning
from app.models.repository import RepositoryIdentity

_log = get_logger("ingestion.retrieval")

_GIT_TIMEOUT_EXIT_NOTE = "git command timed out"


class GitRetrievalError(RetrievalError):
    """The Git strategy failed; the orchestrator may fall back to an archive."""

    def __init__(self, message: str, *, details: dict[str, object] | None = None) -> None:
        super().__init__(message, details=details)


@dataclass(frozen=True, slots=True)
class RetrievalReport:
    """Facts about a completed retrieval."""

    strategy: RetrievalStrategy
    repository_root: Path
    commit_sha: str | None
    commit_sha_verified: bool
    files_written: int
    bytes_written: int
    duration_ms: int
    commit_message: str | None = None
    commit_author: str | None = None
    stripped_root: str | None = None
    symlinks_skipped: int = 0
    oversized_skipped: int = 0
    unsafe_names_skipped: int = 0
    warnings: tuple[IngestionWarning, ...] = ()


class RepositoryRetriever(Protocol):
    """Retrieval strategy interface (also the seam used by the test suite)."""

    name: str

    def retrieve(
        self,
        *,
        identity: RepositoryIdentity,
        commit_sha: str,
        reference: ValidatedReference | None,
        reference_type: ReferenceType,
        workdir: Path,
        deadline: float | None = None,
    ) -> RetrievalReport:  # pragma: no cover - protocol
        ...


# ---------------------------------------------------------------------------
# Git helpers
# ---------------------------------------------------------------------------
_HARDENED_GIT_CONFIG: tuple[tuple[str, str], ...] = (
    ("protocol.allow", "never"),
    ("protocol.https.allow", "always"),
    ("core.symlinks", "false"),
    ("core.hooksPath", os.devnull),
    ("core.fsmonitor", "false"),
    ("credential.helper", ""),
    ("credential.interactive", "never"),
    ("http.followRedirects", "false"),
    ("submodule.recurse", "false"),
    ("advice.detachedHead", "false"),
)


def git_binary_available(settings: Settings) -> bool:
    """Whether the configured Git binary can be executed."""
    return shutil.which(settings.git_binary) is not None


#: Fragments that mark an environment variable as credential material.
_CREDENTIAL_ENV_MARKERS: Final[tuple[str, ...]] = (
    "TOKEN",
    "SECRET",
    "PASSWORD",
    "PASSWD",
    "CREDENTIAL",
)

#: Prefixes of variables that could otherwise alter Git's behaviour.
_DROPPED_ENV_PREFIXES: Final[tuple[str, ...]] = ("GIT_", "GCM_")

#: Non-secret credential carriers that are dropped by name.
_DROPPED_ENV_NAMES: Final[frozenset[str]] = frozenset(
    {
        "SSH_AUTH_SOCK",
        "SSH_AGENT_PID",
        "AWS_ACCESS_KEY_ID",
        "AWS_PROFILE",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "DOCKER_CONFIG",
    }
)


def _safe_inherited_env() -> dict[str, str]:
    """Copy the process environment minus credentials and Git overrides.

    A *complete* base environment is required: on Windows Git's transport and
    its helper executables (``git-remote-https``, ``git-upload-pack`` ...) fail
    with cryptic errors such as ``getaddrinfo() thread failed to start`` when
    ``SystemRoot`` or ``PATH`` are missing.  Everything that could carry a
    credential or override Git's configuration is removed instead; the
    hardening variables below are then applied on top.
    """
    env: dict[str, str] = {}
    for key, value in os.environ.items():
        upper = key.upper()
        if upper in _DROPPED_ENV_NAMES:
            continue
        if upper.startswith(_DROPPED_ENV_PREFIXES):
            continue
        if any(marker in upper for marker in _CREDENTIAL_ENV_MARKERS):
            continue
        env[key] = value
    return env


def _git_env(workdir: Path, *, sandbox_root: Path | None = None) -> dict[str, str]:
    """Environment that keeps Git non-interactive and configuration-free.

    The sandbox (``HOME`` and an empty global Git config) is created under
    ``sandbox_root``, which callers set to a directory *outside* the repository
    working tree: the checkout must contain nothing but repository content.
    """
    base = sandbox_root if sandbox_root is not None else workdir
    sandbox_home = base / ".git-home"
    sandbox_home.mkdir(parents=True, exist_ok=True)
    empty_config = base / ".gitconfig-empty"
    if not empty_config.exists():
        empty_config.write_text("", encoding="utf-8")
    env = _safe_inherited_env()
    env.update(
        {
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_ASKPASS": "",
            "SSH_ASKPASS": "",
            "GCM_INTERACTIVE": "never",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": str(empty_config),
            "GIT_LFS_SKIP_SMUDGE": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "HOME": str(sandbox_home),
            "USERPROFILE": str(sandbox_home),
            "XDG_CONFIG_HOME": str(sandbox_home),
            "LC_ALL": "C",
        }
    )
    # Authentication for private repositories is deliberately NOT supported in
    # Phase 1: no token is ever handed to Git.
    env["GIT_CONFIG_COUNT"] = "0"
    return env


def _run_git(
    args: list[str],
    *,
    settings: Settings,
    workdir: Path,
    timeout: float,
    allow_failure: bool = False,
    sandbox_root: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    command = [settings.git_binary]
    for key, value in _HARDENED_GIT_CONFIG:
        command += ["-c", f"{key}={value}"]
    command += args

    creationflags = 0
    if os.name == "nt":  # pragma: no cover - platform specific
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)

    popen_kwargs: dict[str, object] = {
        "cwd": str(workdir),
        "env": _git_env(workdir, sandbox_root=sandbox_root),
        "capture_output": True,
        "text": True,
        "encoding": "utf-8",
        "errors": "replace",
        "timeout": timeout,
        "shell": False,
        "creationflags": creationflags,
    }
    if os.name == "posix":  # pragma: no cover - platform specific
        popen_kwargs["start_new_session"] = True

    try:
        completed = subprocess.run(command, check=False, **popen_kwargs)  # type: ignore[arg-type]
    except subprocess.TimeoutExpired as exc:
        raise DownloadTimeoutError(
            f"{_GIT_TIMEOUT_EXIT_NOTE} after {timeout:.0f}s",
            details={"operation": args[0] if args else "git", "timeout_seconds": timeout},
            retryable=True,
        ) from exc
    except FileNotFoundError as exc:
        raise RetrievalToolMissingError(
            f"The configured Git binary '{settings.git_binary}' was not found",
            details={"git_binary": settings.git_binary},
        ) from exc

    if completed.returncode != 0 and not allow_failure:
        raise GitRetrievalError(
            f"git {args[0] if args else ''} failed with exit code {completed.returncode}",
            details={
                "operation": args[0] if args else "git",
                "exit_code": completed.returncode,
                "stderr": safe_text((completed.stderr or "").strip(), 400),
            },
        )
    return completed


def _remaining(deadline: float | None, default: float) -> float:
    if deadline is None:
        return default
    left = deadline - time.monotonic()
    if left <= 1.0:
        raise DownloadTimeoutError("The configured ingestion time budget was exhausted during retrieval")
    return min(default, left)


def git_resolve_reference(
    identity: RepositoryIdentity,
    *,
    settings: Settings,
    workdir: Path,
    reference: ValidatedReference | None,
    timeout: float,
) -> tuple[str, ReferenceType, str | None]:
    """Resolve a reference to a commit SHA using ``git ls-remote``.

    Returns ``(sha, ref_type, default_branch)``.  Used only when the GitHub API
    cannot answer (for example when the anonymous rate limit is exhausted).
    """
    completed = _run_git(
        ["ls-remote", "--exit-code", identity.clone_url],
        settings=settings,
        workdir=workdir,
        timeout=timeout,
        allow_failure=True,
    )
    if completed.returncode not in (0, 2):
        raise GitRetrievalError(
            "git ls-remote failed",
            details={"exit_code": completed.returncode, "stderr": safe_text((completed.stderr or "").strip(), 300)},
        )

    heads: dict[str, str] = {}
    tags: dict[str, str] = {}
    head_sha: str | None = None
    for line in (completed.stdout or "").splitlines():
        if "\t" not in line:
            continue
        sha, ref = line.split("\t", 1)
        sha, ref = sha.strip().lower(), ref.strip()
        if ref == "HEAD":
            head_sha = sha
        elif ref.startswith("refs/heads/"):
            heads[ref[len("refs/heads/") :]] = sha
        elif ref.startswith("refs/tags/"):
            name = ref[len("refs/tags/") :]
            if name.endswith("^{}"):
                tags[name[:-3]] = sha  # dereferenced annotated tag -> commit
            else:
                tags.setdefault(name, sha)

    if reference is not None:
        name = reference.name
        if name in heads:
            return heads[name], ReferenceType.BRANCH, None
        if name in tags:
            return tags[name], ReferenceType.TAG, None
        lowered = name.lower()
        for sha in set(heads.values()) | set(tags.values()) | {head_sha} - {None}:
            if sha and sha.startswith(lowered):
                return sha, ReferenceType.COMMIT, None
        raise ReferenceNotFoundError(
            f"Reference '{safe_text(name, 80)}' does not exist in the repository",
            details={"repository": identity.canonical_id, "ref": safe_text(name, 80)},
        )

    if head_sha is None:
        raise RetrievalError(
            "The repository has no commits, so there is nothing to analyse",
            details={"repository": identity.canonical_id},
        )
    default_branch = next((name for name, sha in heads.items() if sha == head_sha), None)
    if default_branch is None:
        raise RetrievalError(
            "Could not determine the default branch of the repository",
            details={"repository": identity.canonical_id},
        )
    return head_sha, ReferenceType.DEFAULT_BRANCH, default_branch


# ---------------------------------------------------------------------------
# Git strategy
# ---------------------------------------------------------------------------
class GitRetriever:
    """Shallow, hardened, read-only clone pinned to one commit."""

    name = "git"

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    def retrieve(
        self,
        *,
        identity: RepositoryIdentity,
        commit_sha: str,
        reference: ValidatedReference | None,
        reference_type: ReferenceType,
        workdir: Path,
        deadline: float | None = None,
    ) -> RetrievalReport:
        started = time.monotonic()
        settings = self._settings
        checkout = workdir / "repo"
        checkout.mkdir(parents=True, exist_ok=True)

        _log.info(
            "git retrieval started repository=%s commit=%s",
            identity.canonical_id,
            commit_sha[:12],
        )

        try:
            self._fetch_by_sha(
                identity=identity,
                commit_sha=commit_sha,
                checkout=checkout,
                deadline=deadline,
            )
        except GitRetrievalError as exc:
            if reference is None or reference.is_full_sha:
                raise
            _log.warning(
                "git fetch by sha failed, retrying with a shallow clone of the reference repository=%s detail=%s",
                identity.canonical_id,
                safe_text(exc.details.get("stderr", ""), 200),
            )
            self._clone_reference(identity=identity, reference=reference, checkout=checkout, deadline=deadline)

        warnings: list[IngestionWarning] = []
        verified_sha, commit_message, commit_author = self._inspect_checkout(checkout, deadline=deadline)

        if verified_sha is None:
            raise GitRetrievalError(
                "Could not determine the checked out commit SHA",
                details={"repository": identity.canonical_id},
            )
        if verified_sha != commit_sha:
            if reference_type == ReferenceType.COMMIT:
                raise GitRetrievalError(
                    "The checked out commit does not match the requested commit",
                    details={"requested_sha": commit_sha, "checked_out_sha": verified_sha},
                )
            warnings.append(
                IngestionWarning(
                    code=WarningCode.BRANCH_MOVED_DURING_RETRIEVAL,
                    message=(
                        "The reference moved between resolution and checkout; the analysed commit is the one "
                        "that was actually checked out"
                    ),
                    severity=Severity.WARNING,
                    stage=IngestionStage.RETRIEVAL,
                    details={"resolved_sha": commit_sha, "checked_out_sha": verified_sha},
                )
            )
            _log.warning(
                "reference moved during retrieval repository=%s resolved=%s actual=%s",
                identity.canonical_id,
                commit_sha[:12],
                verified_sha[:12],
            )

        files_written, bytes_written = _measure_tree(checkout)
        # The .git directory is removed: Phase 1 only needs the working tree and
        # never runs further Git operations on untrusted content.
        remove_tree(checkout / ".git")

        return RetrievalReport(
            strategy=RetrievalStrategy.GIT,
            repository_root=checkout,
            commit_sha=verified_sha,
            commit_sha_verified=True,
            files_written=files_written,
            bytes_written=bytes_written,
            duration_ms=int((time.monotonic() - started) * 1000),
            commit_message=commit_message,
            commit_author=commit_author,
            warnings=tuple(warnings),
        )

    # -- internals ---------------------------------------------------------
    def _fetch_by_sha(
        self,
        *,
        identity: RepositoryIdentity,
        commit_sha: str,
        checkout: Path,
        deadline: float | None,
    ) -> None:
        settings = self._settings
        sandbox_root = checkout.parent  # never write Git sandbox files into the checkout
        _run_git(
            ["init", "--quiet", str(checkout)],
            settings=settings,
            workdir=checkout,
            sandbox_root=sandbox_root,
            timeout=_remaining(deadline, settings.git_timeout_seconds),
        )
        _run_git(
            ["remote", "add", "origin", identity.clone_url],
            settings=settings,
            workdir=checkout,
            sandbox_root=sandbox_root,
            timeout=_remaining(deadline, settings.git_timeout_seconds),
        )
        _run_git(
            ["fetch", "--quiet", "--depth", "1", "--no-tags", "origin", commit_sha],
            settings=settings,
            workdir=checkout,
            sandbox_root=sandbox_root,
            timeout=_remaining(deadline, settings.git_timeout_seconds),
        )
        _run_git(
            ["checkout", "--quiet", "--detach", "--force", "FETCH_HEAD"],
            settings=settings,
            workdir=checkout,
            sandbox_root=sandbox_root,
            timeout=_remaining(deadline, settings.git_timeout_seconds),
        )

    def _clone_reference(
        self,
        *,
        identity: RepositoryIdentity,
        reference: ValidatedReference,
        checkout: Path,
        deadline: float | None,
    ) -> None:
        settings = self._settings
        remove_tree(checkout)
        checkout.mkdir(parents=True, exist_ok=True)
        _run_git(
            [
                "clone",
                "--quiet",
                "--depth",
                "1",
                "--single-branch",
                "--no-tags",
                "--branch",
                reference.name,
                "--",
                identity.clone_url,
                str(checkout),
            ],
            settings=settings,
            workdir=checkout.parent,
            timeout=_remaining(deadline, settings.git_timeout_seconds),
        )

    def _inspect_checkout(self, checkout: Path, *, deadline: float | None) -> tuple[str | None, str | None, str | None]:
        settings = self._settings
        sandbox_root = checkout.parent
        try:
            rev = _run_git(
                ["rev-parse", "HEAD"],
                settings=settings,
                workdir=checkout,
                sandbox_root=sandbox_root,
                timeout=_remaining(deadline, settings.git_timeout_seconds),
                allow_failure=True,
            )
        except DownloadTimeoutError:
            raise
        if rev.returncode != 0:
            return None, None, None
        sha = (rev.stdout or "").strip().lower() or None

        message: str | None = None
        author: str | None = None
        log = _run_git(
            ["log", "-1", "--format=%s%x00%an"],
            settings=settings,
            workdir=checkout,
            sandbox_root=sandbox_root,
            timeout=_remaining(deadline, settings.git_timeout_seconds),
            allow_failure=True,
        )
        if log.returncode == 0 and log.stdout:
            head, _, tail = log.stdout.strip().partition("\x00")
            message = head.strip()[:200] or None
            author = tail.strip()[:120] or None
        return sha, message, author


# ---------------------------------------------------------------------------
# Archive strategy
# ---------------------------------------------------------------------------
class ArchiveRetriever:
    """Byte-capped codeload tarball download with hardened extraction."""

    name = "archive"

    def __init__(self, settings: Settings, *, client: httpx.Client | None = None) -> None:
        self._settings = settings
        self._owned_client = client is None
        self._client = client or httpx.Client(
            timeout=httpx.Timeout(settings.download_timeout_seconds, connect=min(10.0, settings.download_timeout_seconds)),
            follow_redirects=False,
            headers={"User-Agent": settings.user_agent},
        )

    def close(self) -> None:
        if self._owned_client:
            self._client.close()

    def __enter__(self) -> "ArchiveRetriever":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def archive_url(self, identity: RepositoryIdentity, commit_sha: str) -> str:
        return (
            f"{self._settings.github_codeload_base_url}/{quote(identity.owner, safe='')}"
            f"/{quote(identity.name, safe='')}/tar.gz/{quote(commit_sha, safe='')}"
        )

    def retrieve(
        self,
        *,
        identity: RepositoryIdentity,
        commit_sha: str,
        reference: ValidatedReference | None,
        reference_type: ReferenceType,
        workdir: Path,
        deadline: float | None = None,
    ) -> RetrievalReport:
        started = time.monotonic()
        settings = self._settings
        archive_path = workdir / "repository.tar.gz"
        url = self.archive_url(identity, commit_sha)
        _log.info("archive retrieval started repository=%s commit=%s", identity.canonical_id, commit_sha[:12])

        self._download(url, archive_path, deadline=deadline, identity=identity)
        extraction: ArchiveExtractionReport = extract_tar_safely(
            archive_path,
            workdir / "repo",
            max_members=settings.max_archive_members,
            max_total_bytes=settings.max_extracted_bytes,
            max_file_bytes=settings.max_download_bytes,
        )
        try:
            archive_path.unlink()
        except OSError:  # pragma: no cover - best effort disk hygiene
            _log.debug("could not delete temporary archive %s", safe_text(archive_path, 120))

        warnings: list[IngestionWarning] = []
        stripped = extraction.stripped_root or ""
        if commit_sha[:12] and stripped and commit_sha[:12] not in stripped:
            warnings.append(
                IngestionWarning(
                    code=WarningCode.ARCHIVE_ROOT_DIR_UNEXPECTED,
                    message="The archive root directory does not contain the requested commit SHA",
                    severity=Severity.INFO,
                    stage=IngestionStage.RETRIEVAL,
                    details={"archive_root": safe_text(stripped, 120), "commit_sha": commit_sha},
                )
            )

        return RetrievalReport(
            strategy=RetrievalStrategy.ARCHIVE,
            repository_root=workdir / "repo",
            commit_sha=commit_sha,
            commit_sha_verified=True,
            files_written=extraction.files_written,
            bytes_written=extraction.bytes_written,
            duration_ms=int((time.monotonic() - started) * 1000),
            stripped_root=extraction.stripped_root,
            symlinks_skipped=extraction.symlinks_skipped,
            oversized_skipped=extraction.oversized_skipped,
            unsafe_names_skipped=extraction.unsafe_names_skipped,
            warnings=tuple(warnings),
        )

    def _download(
        self,
        url: str,
        destination: Path,
        *,
        deadline: float | None,
        identity: RepositoryIdentity,
    ) -> int:
        settings = self._settings
        timeout = _remaining(deadline, settings.download_timeout_seconds)
        written = 0
        try:
            with self._client.stream("GET", url, timeout=timeout) as response:
                if response.status_code == 404:
                    raise ReferenceNotFoundError(
                        "The requested revision is not available as an archive",
                        details={"repository": identity.canonical_id, "status_code": 404},
                    )
                if response.status_code in (401, 403, 429):
                    remaining = response.headers.get("x-ratelimit-remaining")
                    if remaining == "0" or response.status_code == 429:
                        raise RateLimitExceededError(
                            "GitHub rate limited the archive download",
                            details={"repository": identity.canonical_id, "status_code": response.status_code},
                            retryable=True,
                        )
                    raise RepositoryAccessDeniedError(
                        "GitHub denied the archive download",
                        details={"repository": identity.canonical_id, "status_code": response.status_code},
                    )
                if response.status_code >= 400:
                    raise RetrievalError(
                        f"GitHub returned status {response.status_code} for the archive download",
                        details={"repository": identity.canonical_id, "status_code": response.status_code},
                        retryable=response.status_code >= 500,
                    )

                declared = response.headers.get("content-length")
                if declared is not None and declared.isdigit() and int(declared) > settings.max_download_bytes:
                    raise RepositoryTooLargeError(
                        "The repository archive exceeds the configured download limit",
                        details={"content_length": int(declared), "max_download_bytes": settings.max_download_bytes},
                    )

                with open(destination, "wb") as handle:
                    for chunk in response.iter_bytes(chunk_size=262_144):
                        written += len(chunk)
                        if written > settings.max_download_bytes:
                            raise RepositoryTooLargeError(
                                "The repository archive exceeds the configured download limit",
                                details={"max_download_bytes": settings.max_download_bytes},
                            )
                        handle.write(chunk)
        except httpx.TimeoutException as exc:
            raise DownloadTimeoutError(
                "Timed out while downloading the repository archive",
                details={"repository": identity.canonical_id, "timeout_seconds": timeout},
                retryable=True,
            ) from exc
        except httpx.HTTPError as exc:
            raise NetworkFailureError(
                "Network error while downloading the repository archive",
                details={"repository": identity.canonical_id, "reason": safe_text(exc, 200)},
                retryable=True,
            ) from exc

        if written == 0:
            raise UnsafeRepositoryContentError(
                "The downloaded archive is empty",
                details={"repository": identity.canonical_id, "url": redact_url(url)},
            )
        return written


def select_retriever(settings: Settings) -> RepositoryRetriever:
    """Pick a retrieval strategy according to configuration and availability."""
    strategy = settings.retrieval_strategy
    if strategy == "git":
        if not git_binary_available(settings):
            raise RetrievalToolMissingError(
                "retrieval_strategy=git was requested but the Git binary is not available",
                details={"git_binary": settings.git_binary},
            )
        return GitRetriever(settings)
    if strategy == "archive":
        return ArchiveRetriever(settings)
    if git_binary_available(settings):
        return GitRetriever(settings)
    _log.info("git binary not available; falling back to archive retrieval")
    return ArchiveRetriever(settings)


def _measure_tree(root: Path) -> tuple[int, int]:
    """Count regular files and total bytes in a working tree."""
    files = 0
    total = 0
    for current_root, dirs, names in os.walk(root, followlinks=False):
        dirs[:] = [name for name in dirs if name != ".git"]
        for name in names:
            path = Path(current_root) / name
            try:
                if path.is_symlink() or not path.is_file():
                    continue
                total += path.stat().st_size
                files += 1
            except OSError:  # pragma: no cover - unreadable entry
                continue
    return files, total


__all__ = [
    "ArchiveRetriever",
    "GitRetrievalError",
    "GitRetriever",
    "RepositoryRetriever",
    "RetrievalReport",
    "git_binary_available",
    "git_resolve_reference",
    "select_retriever",
]
