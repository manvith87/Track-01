"""Filesystem, archive and command safety helpers.

Threat model for Phase 1: the analysed repository is untrusted.  Nothing in
this module executes repository code, imports repository modules or shells out
with untrusted input.  The helpers here have three jobs:

1. decide whether a path is safe to materialise on the local filesystem
   (no traversal, no absolute paths, no NTFS alternate data streams, ...);
2. extract GNU tar archives without ever creating symlinks, hardlinks or
   device nodes, and while enforcing member/size limits;
3. clean up temporary directories reliably on Windows, where Git leaves
   read-only files behind that ``shutil.rmtree`` cannot delete.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import stat
import sys
import tarfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from app.core.errors import RepositoryTooLargeError, UnsafeRepositoryContentError
from app.core.logging import safe_text

_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")
_WINDOWS_DRIVE = re.compile(r"^[A-Za-z]:")

#: Windows reserved device names (case-insensitive, with or without extension).
_WINDOWS_RESERVED_NAMES = frozenset(
    {"CON", "PRN", "AUX", "NUL"}
    | {f"COM{digit}" for digit in "123456789"}
    | {f"LPT{digit}" for digit in "123456789"}
)

_SENSITIVE_QUERY_KEYS = ("token", "access_token", "key", "api_key", "secret", "signature", "sig", "password", "auth")

_COPY_CHUNK = 1024 * 256


def validate_relative_path(raw: str, *, context: str = "repository path") -> str:
    """Return a normalised POSIX relative path, or raise.

    Rejects absolute paths, drive letters, traversal segments, UNC prefixes and
    control characters.  The returned value is safe to join onto a temporary
    directory root.
    """
    if raw is None or not isinstance(raw, str):
        raise UnsafeRepositoryContentError(f"{context} is not a string", details={"path": safe_text(raw)})

    text = raw.strip().replace("\\", "/")
    if not text:
        raise UnsafeRepositoryContentError(f"{context} is empty", details={"path": raw})
    if _CONTROL_CHARS.search(text):
        raise UnsafeRepositoryContentError(
            f"{context} contains control characters", details={"path": safe_text(raw)}
        )
    if text.startswith("/") or text.startswith("//") or _WINDOWS_DRIVE.match(text):
        raise UnsafeRepositoryContentError(
            f"{context} must be relative, got an absolute path", details={"path": safe_text(raw)}
        )

    parts: list[str] = []
    for part in PurePosixPath(text).parts:
        if part in {"", "."}:
            continue
        if part == "..":
            raise UnsafeRepositoryContentError(
                f"{context} escapes the repository root", details={"path": safe_text(raw)}
            )
        parts.append(part)

    if not parts:
        raise UnsafeRepositoryContentError(f"{context} is empty after normalisation", details={"path": safe_text(raw)})

    return "/".join(parts)


def is_windows_unsafe_component(part: str) -> bool:
    """Whether a single path component cannot be materialised on Windows.

    Such members are skipped (never rewritten) during archive extraction so a
    single odd file name cannot abort a whole ingestion.
    """
    if ":" in part or "\x00" in part:
        return True
    if part != part.rstrip(" ."):
        return True
    stem = part.split(".")[0].upper()
    return stem in _WINDOWS_RESERVED_NAMES


def safe_join(root: Path, relative: str) -> Path:
    """Join a validated relative path onto ``root`` and verify containment."""
    normalized = validate_relative_path(relative)
    candidate = (root / Path(*normalized.split("/"))).resolve()
    if not is_within(candidate, root):
        raise UnsafeRepositoryContentError(
            "resolved path escapes the working directory", details={"path": safe_text(relative)}
        )
    return candidate


def is_within(candidate: Path, root: Path) -> bool:
    """True when ``candidate`` is ``root`` itself or lives underneath it."""
    try:
        root_resolved = root.resolve()
        candidate_resolved = candidate.resolve()
    except OSError:  # pragma: no cover - resolving can fail on broken links
        return False
    return candidate_resolved == root_resolved or root_resolved in candidate_resolved.parents


@dataclass(slots=True)
class ArchiveExtractionReport:
    """What happened while extracting an archive."""

    files_written: int = 0
    bytes_written: int = 0
    members_seen: int = 0
    symlinks_skipped: int = 0
    oversized_skipped: int = 0
    unsafe_names_skipped: int = 0
    non_regular_skipped: int = 0
    stripped_root: str | None = None
    skipped_names: list[str] = field(default_factory=list)


def _archive_root_prefix(members: list[tarfile.TarInfo]) -> str | None:
    """Return the single common top-level directory of an archive, if any.

    GitHub's codeload tarballs are wrapped in ``<repo>-<sha>/``; stripping that
    wrapper keeps repository-relative paths identical across strategies.
    """
    prefixes: set[str] = set()
    saw_root_entry = False
    for member in members:
        name = member.name.strip().replace("\\", "/").strip("/")
        if not name:
            continue
        if "/" not in name and not member.isdir():
            # A top-level *file* means the archive is not wrapped in a single
            # directory.  The wrapper's own directory entry is fine.
            saw_root_entry = True
        prefixes.add(name.split("/", 1)[0])
        if len(prefixes) > 1:
            return None
    if saw_root_entry or len(prefixes) != 1:
        return None
    return next(iter(prefixes))


def extract_tar_safely(
    archive_path: Path,
    destination: Path,
    *,
    max_members: int,
    max_total_bytes: int,
    max_file_bytes: int | None = None,
    strip_single_root: bool = True,
) -> ArchiveExtractionReport:
    """Safely extract a tar archive into ``destination``.

    Guarantees:

    * no symlink, hardlink, FIFO or device node is ever created;
    * paths that would escape ``destination`` abort the extraction;
    * member count and total uncompressed size are capped;
    * every written file is re-verified to be inside ``destination``.
    """
    report = ArchiveExtractionReport()
    destination = destination.resolve()
    destination.mkdir(parents=True, exist_ok=True)

    try:
        archive = tarfile.open(archive_path, mode="r:*")
    except tarfile.TarError as exc:
        raise UnsafeRepositoryContentError(
            "The downloaded archive is not a readable tar archive", details={"reason": safe_text(exc)}
        ) from exc

    with archive:
        try:
            members = archive.getmembers()
        except tarfile.TarError as exc:
            raise UnsafeRepositoryContentError(
                "The downloaded archive is corrupt", details={"reason": safe_text(exc)}
            ) from exc

        if len(members) > max_members:
            raise RepositoryTooLargeError(
                f"Archive contains {len(members)} entries which exceeds the limit of {max_members}",
                details={"members": len(members), "max_members": max_members},
            )

        prefix = _archive_root_prefix(members) if strip_single_root else None
        report.stripped_root = prefix

        for member in members:
            report.members_seen += 1
            normalized = validate_relative_path(member.name, context="archive member path")

            if prefix:
                if normalized == prefix:
                    continue
                if normalized.startswith(f"{prefix}/"):
                    normalized = normalized[len(prefix) + 1 :]
                else:  # pragma: no cover - impossible when prefix is common
                    continue
                if not normalized:
                    continue

            parts = normalized.split("/")
            if any(is_windows_unsafe_component(part) for part in parts):
                report.unsafe_names_skipped += 1
                report.skipped_names.append(normalized)
                continue

            if member.issym() or member.islnk():
                _verify_link_target_safe(member, normalized, prefix)
                report.symlinks_skipped += 1
                continue

            if member.isdir():
                continue

            if not member.isfile():
                report.non_regular_skipped += 1
                continue

            if max_file_bytes is not None and member.size > max_file_bytes:
                report.oversized_skipped += 1
                report.skipped_names.append(normalized)
                continue

            if report.bytes_written + member.size > max_total_bytes:
                raise RepositoryTooLargeError(
                    "Extracted repository exceeds the configured uncompressed size limit",
                    details={"max_total_bytes": max_total_bytes},
                )

            target = safe_join(destination, normalized)
            target.parent.mkdir(parents=True, exist_ok=True)
            source = archive.extractfile(member)
            if source is None:  # pragma: no cover - defensive
                report.non_regular_skipped += 1
                continue
            with source, open(target, "wb") as handle:
                while True:
                    chunk = source.read(_COPY_CHUNK)
                    if not chunk:
                        break
                    handle.write(chunk)
            report.files_written += 1
            report.bytes_written += member.size

    return report


def _verify_link_target_safe(member: tarfile.TarInfo, normalized: str, prefix: str | None) -> None:
    """Reject links that escape the extraction root.

    Links are never materialised; this check exists purely so that a hostile
    archive is reported as such instead of silently being partially extracted.
    """
    target = (member.linkname or "").strip().replace("\\", "/")
    if not target:
        return
    if target.startswith("/") or _WINDOWS_DRIVE.match(target):
        raise UnsafeRepositoryContentError(
            "Archive contains a link with an absolute target",
            details={"member": safe_text(member.name), "target": safe_text(target)},
        )
    if member.issym():
        base = PurePosixPath(normalized).parent
        combined = base / target
    else:
        combined = PurePosixPath(target)
    depth = 0
    for part in combined.parts:
        if part in {"", "."}:
            continue
        depth += -1 if part == ".." else 1
        if depth < 0:
            raise UnsafeRepositoryContentError(
                "Archive contains a link that escapes the repository root",
                details={"member": safe_text(member.name), "target": safe_text(target)},
            )
    if prefix and combined.parts and combined.parts[0] != prefix and not member.issym():
        raise UnsafeRepositoryContentError(
            "Archive contains a hardlink pointing outside the archive root",
            details={"member": safe_text(member.name), "target": safe_text(target)},
        )


def file_sha256(path: Path, *, max_bytes: int | None = None) -> str | None:
    """SHA-256 of a file, or ``None`` when it exceeds ``max_bytes``."""
    digest = hashlib.sha256()
    total = 0
    try:
        with open(path, "rb") as handle:
            while True:
                chunk = handle.read(_COPY_CHUNK)
                if not chunk:
                    break
                total += len(chunk)
                if max_bytes is not None and total > max_bytes:
                    return None
                digest.update(chunk)
    except OSError:
        return None
    return digest.hexdigest()


@dataclass(frozen=True, slots=True)
class TextFileRead:
    """Outcome of reading a text file from the working tree."""

    text: str | None
    #: ``None`` when the file was read, otherwise a machine readable reason:
    #: ``too_large``, ``not_utf8``, ``binary``, ``read_error``.
    skip_reason: str | None = None
    size_bytes: int = 0

    @property
    def ok(self) -> bool:
        return self.text is not None


def read_text_file(path: Path, *, max_bytes: int) -> TextFileRead:
    """Read a text file, refusing binary or oversized content.

    Repository content is untrusted: decoding never raises, embedded NUL bytes
    mark the file as binary, and the read is bounded by ``max_bytes``.
    """
    try:
        size = path.stat().st_size
    except OSError:
        return TextFileRead(text=None, skip_reason="read_error")
    if size > max_bytes:
        return TextFileRead(text=None, skip_reason="too_large", size_bytes=size)
    try:
        raw = path.read_bytes()
    except OSError:
        return TextFileRead(text=None, skip_reason="read_error", size_bytes=size)
    if b"\x00" in raw:
        return TextFileRead(text=None, skip_reason="binary", size_bytes=size)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        try:
            # Latin-1 never fails; keeping the crumb of information is more
            # useful than dropping the file, and the caller warns about it.
            text = raw.decode("latin-1")
        except UnicodeDecodeError:  # pragma: no cover - defensive
            return TextFileRead(text=None, skip_reason="not_utf8", size_bytes=size)
        return TextFileRead(text=text, skip_reason="not_utf8", size_bytes=size)
    return TextFileRead(text=text, size_bytes=size)


def redact_url(url: str) -> str:
    """Remove credentials and sensitive query parameters before logging."""
    from urllib.parse import urlsplit, urlunsplit

    if not url:
        return ""
    try:
        parts = urlsplit(url)
    except ValueError:
        return safe_text(url, limit=120)
    netloc = parts.hostname or ""
    if parts.port:
        netloc = f"{netloc}:{parts.port}"
    query = ""
    if parts.query:
        kept = [
            chunk
            for chunk in parts.query.split("&")
            if chunk and chunk.split("=", 1)[0].lower() not in _SENSITIVE_QUERY_KEYS
        ]
        query = "&".join(kept)
    return urlunsplit((parts.scheme, netloc, parts.path, query, ""))


def remove_tree(path: Path | str) -> None:
    """Delete a directory tree, tolerating read-only files (Windows/Git)."""
    target = Path(path)
    if not target.exists():
        return

    def _handle(func, failed_path, _exc_info) -> None:  # type: ignore[no-untyped-def]
        try:
            os.chmod(failed_path, stat.S_IWRITE)
            func(failed_path)
        except OSError:
            # Never raise from cleanup: leaving a temporary directory behind is
            # loud (logged by the caller) but must not mask the real result.
            return

    if sys.version_info >= (3, 12):
        shutil.rmtree(target, onexc=_handle)
    else:  # pragma: no cover - Python 3.11
        shutil.rmtree(target, onerror=_handle)


__all__ = [
    "ArchiveExtractionReport",
    "TextFileRead",
    "extract_tar_safely",
    "file_sha256",
    "is_unsafe_component",
    "is_within",
    "read_text_file",
    "redact_url",
    "remove_tree",
    "safe_join",
    "validate_relative_path",
]


def is_unsafe_component(part: str) -> bool:
    """Public alias of :func:`is_windows_unsafe_component`."""
    return is_windows_unsafe_component(part)
