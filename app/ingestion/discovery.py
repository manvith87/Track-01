"""Manifest discovery.

Walks the retrieved working tree exactly once, with hard limits, and decides
which files are dependency manifests BlastRadius can parse.

Safety properties:

* symlinks (files *and* directories) are never followed, only counted;
* virtualenvs are detected precisely through ``pyvenv.cfg`` (rather than by
  guessing directory names), caches/VCS/build outputs are pruned by name;
* the number of files examined, the number of manifests and the size of any
  manifest are all capped, so a hostile repository cannot exhaust resources;
* nothing is imported, executed or resolved.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from app.core.config import Settings
from app.core.logging import get_logger, safe_text
from app.ingestion.safety import file_sha256, read_text_file
from app.models.common import (
    IngestionStage,
    ManifestFormat,
    Severity,
    SupportLevel,
    UnsupportedManifestFormat,
    WarningCode,
)
from app.models.ingestion import IngestionWarning
from app.models.source import SourceFile

_log = get_logger("ingestion.discovery")

_UNSUPPORTED_BY_FILENAME: dict[str, UnsupportedManifestFormat] = {
    "pipfile": UnsupportedManifestFormat.PIPFILE,
    "pipfile.lock": UnsupportedManifestFormat.PIPFILE_LOCK,
    "setup.py": UnsupportedManifestFormat.SETUP_PY,
    "setup.cfg": UnsupportedManifestFormat.SETUP_CFG,
    "environment.yml": UnsupportedManifestFormat.ENVIRONMENT_YML,
    "environment.yaml": UnsupportedManifestFormat.ENVIRONMENT_YAML,
    "conda.yml": UnsupportedManifestFormat.CONDA_YML,
    "conda.yaml": UnsupportedManifestFormat.CONDA_YAML,
    "requirements.in": UnsupportedManifestFormat.REQUIREMENTS_IN,
}

_SUPPORTED_BY_FILENAME: dict[str, ManifestFormat] = {
    "pyproject.toml": ManifestFormat.PYPROJECT_TOML,
    "poetry.lock": ManifestFormat.POETRY_LOCK,
    "uv.lock": ManifestFormat.UV_LOCK,
}

_REQUIREMENT_DIR_NAMES = frozenset({"requirements", "reqs", "requirements.d"})


@dataclass(slots=True)
class DiscoveredManifest:
    """A dependency manifest found in the working tree."""

    path: str
    directory: str
    absolute_path: Path
    format: ManifestFormat | None
    unsupported_format: UnsupportedManifestFormat | None
    support_level: SupportLevel
    size_bytes: int
    sha256: str | None = None
    text: str | None = None
    skipped_reason: str | None = None

    @property
    def is_lockfile(self) -> bool:
        return self.format is not None and self.format.is_lockfile


@dataclass(slots=True)
class DiscoveryResult:
    """Outcome of scanning a repository working tree."""

    files: list[SourceFile] = field(default_factory=list)
    manifests: list[DiscoveredManifest] = field(default_factory=list)
    files_examined: int = 0
    directories_pruned: int = 0
    symlinks_skipped: int = 0
    oversized_manifests_skipped: int = 0
    truncated: bool = False
    limits_hit: list[str] = field(default_factory=list)
    warnings: list[IngestionWarning] = field(default_factory=list)


def classify_dependency_file(relative_path: str) -> tuple[ManifestFormat | None, UnsupportedManifestFormat | None]:
    """Return the supported/unsupported format for a repository relative path."""
    pure = PurePosixPath(relative_path)
    name = pure.name.lower()
    parent_parts = pure.parts[:-1]

    if name in _SUPPORTED_BY_FILENAME:
        return _SUPPORTED_BY_FILENAME[name], None
    if name in _UNSUPPORTED_BY_FILENAME:
        return None, _UNSUPPORTED_BY_FILENAME[name]
    if _looks_like_requirements(name, parent_parts):
        return ManifestFormat.REQUIREMENTS_TXT, None
    return None, None


def _looks_like_requirements(name: str, parent_parts: tuple[str, ...]) -> bool:
    """Recognise the ``requirements*.txt`` family (and ``*.txt`` in a requirements dir)."""
    if not name.endswith(".txt"):
        return False
    stem = name[: -len(".txt")]
    if stem in {"requirements", "reqs"}:
        return True
    if stem.startswith(("requirements-", "requirements_", "requirements.")):
        return True
    if stem.endswith(("-requirements", "_requirements")):
        return True
    return any(part.lower() in _REQUIREMENT_DIR_NAMES for part in parent_parts)


def discover_repository_files(root: Path, settings: Settings) -> DiscoveryResult:
    """Scan ``root`` for dependency manifests and collect source file metadata."""
    result = DiscoveryResult()
    if not root.exists():
        return result

    manifest_entries: list[tuple[str, DiscoveredManifest]] = []
    other_files: list[tuple[str, SourceFile]] = []
    limit_reached = False
    manifest_limit_reached = False
    excluded_directories = frozenset(name.lower() for name in settings.excluded_directories)
    excluded_suffixes = tuple(suffix.lower() for suffix in settings.excluded_directory_suffixes)

    for current_root, dir_names, file_names in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current_root)
        rel_dir = current_path.relative_to(root).as_posix()
        rel_dir = "" if rel_dir == "." else rel_dir

        kept_dirs: list[str] = []
        for dir_name in sorted(dir_names):
            child = current_path / dir_name
            try:
                if child.is_symlink():
                    result.symlinks_skipped += 1
                    result.directories_pruned += 1
                    continue
                if _is_excluded_directory(dir_name, excluded_directories, excluded_suffixes):
                    result.directories_pruned += 1
                    continue
                if (child / "pyvenv.cfg").is_file():
                    result.directories_pruned += 1
                    result.warnings.append(
                        IngestionWarning(
                            code=WarningCode.VIRTUALENV_DETECTED,
                            message="Skipped a Python virtual environment directory",
                            severity=Severity.INFO,
                            stage=IngestionStage.DISCOVERY,
                            details={"directory": _rel(rel_dir, dir_name)},
                        )
                    )
                    continue
            except OSError:  # pragma: no cover - unreadable entry
                result.directories_pruned += 1
                continue
            kept_dirs.append(dir_name)

        if len(kept_dirs) > settings.max_directory_entries:
            result.warnings.append(
                IngestionWarning(
                    code=WarningCode.DIRECTORY_ENTRY_LIMIT_EXCEEDED,
                    message="A directory contains more sub-directories than the configured limit; it was pruned",
                    severity=Severity.WARNING,
                    stage=IngestionStage.DISCOVERY,
                    details={"directory": rel_dir or ".", "sub_directories": len(kept_dirs)},
                )
            )
            result.directories_pruned += len(kept_dirs)
            result.limits_hit.append("max_directory_entries")
            dir_names[:] = []
        else:
            dir_names[:] = kept_dirs

        for file_name in sorted(file_names):
            if result.files_examined >= settings.max_files_scanned:
                limit_reached = True
                break
            path = current_path / file_name
            try:
                if path.is_symlink():
                    result.symlinks_skipped += 1
                    continue
                if not path.is_file():
                    continue
                size = path.stat().st_size
            except OSError:  # pragma: no cover - unreadable entry
                continue

            result.files_examined += 1
            rel_path = _rel(rel_dir, file_name)
            supported, unsupported = classify_dependency_file(rel_path)

            if supported is None and unsupported is None:
                other_files.append((rel_path, SourceFile(path=rel_path, size_bytes=size)))
                continue

            if len(manifest_entries) >= settings.max_manifests:
                result.limits_hit.append("max_manifests")
                result.warnings.append(
                    IngestionWarning(
                        code=WarningCode.MANIFEST_LIMIT_REACHED,
                        message="More dependency manifests were found than the configured limit; the rest were ignored",
                        severity=Severity.WARNING,
                        stage=IngestionStage.DISCOVERY,
                        details={"limit": settings.max_manifests},
                    )
                )
                manifest_limit_reached = True
                break

            entry = _build_manifest_entry(
                rel_path=rel_path,
                rel_dir=rel_dir,
                path=path,
                size=size,
                supported=supported,
                unsupported=unsupported,
                settings=settings,
                result=result,
            )
            manifest_entries.append((rel_path, entry))

            result.files.append(
                SourceFile(
                    path=rel_path,
                    size_bytes=size,
                    sha256=entry.sha256,
                    manifest_format=entry.format,
                    unsupported_format=entry.unsupported_format,
                    support_level=entry.support_level,
                    skipped_reason=entry.skipped_reason,
                )
            )
        if limit_reached or manifest_limit_reached:
            break

    if limit_reached:
        result.truncated = True
        result.limits_hit.append("max_files_scanned")
        result.warnings.append(
            IngestionWarning(
                code=WarningCode.TREE_TRUNCATED_FILE_LIMIT,
                message="The repository tree was truncated at the configured file limit",
                severity=Severity.WARNING,
                stage=IngestionStage.DISCOVERY,
                details={"max_files_scanned": settings.max_files_scanned},
            )
        )

    if result.symlinks_skipped:
        result.warnings.append(
            IngestionWarning(
                code=WarningCode.SYMLINKS_SKIPPED,
                message="Symlinks in the repository were skipped and never followed",
                severity=Severity.INFO,
                stage=IngestionStage.DISCOVERY,
                details={"count": result.symlinks_skipped},
            )
        )

    gitmodules = root / ".gitmodules"
    if gitmodules.is_file():
        result.warnings.append(
            IngestionWarning(
                code=WarningCode.SUBMODULES_NOT_FETCHED,
                message="The repository declares Git submodules; submodule content was not retrieved",
                severity=Severity.INFO,
                stage=IngestionStage.DISCOVERY,
                details={"path": ".gitmodules"},
            )
        )

    manifest_entries.sort(key=lambda item: item[0])
    other_files.sort(key=lambda item: item[0])
    result.manifests = [entry for _, entry in manifest_entries]
    result.files = result.files + [source for _, source in other_files]
    return result


def _build_manifest_entry(
    *,
    rel_path: str,
    rel_dir: str,
    path: Path,
    size: int,
    supported: ManifestFormat | None,
    unsupported: UnsupportedManifestFormat | None,
    settings: Settings,
    result: DiscoveryResult,
) -> DiscoveredManifest:
    directory = rel_dir or "."
    if unsupported is not None:
        result.warnings.append(
            IngestionWarning(
                code=WarningCode.UNSUPPORTED_FORMAT,
                message=f"Dependency file format '{unsupported.value}' is recognised but not parsed by BlastRadius",
                severity=Severity.WARNING,
                stage=IngestionStage.DISCOVERY,
                manifest_path=rel_path,
                details={"format": unsupported.value, "support_level": SupportLevel.UNSUPPORTED.value},
            )
        )
        return DiscoveredManifest(
            path=rel_path,
            directory=directory,
            absolute_path=path,
            format=None,
            unsupported_format=unsupported,
            support_level=SupportLevel.UNSUPPORTED,
            size_bytes=size,
            skipped_reason="unsupported_format",
        )

    assert supported is not None  # nosec - guaranteed by the caller
    read = read_text_file(path, max_bytes=settings.max_manifest_bytes)
    sha = file_sha256(path, max_bytes=settings.max_manifest_bytes)
    skipped_reason: str | None = None
    if read.skip_reason == "too_large":
        skipped_reason = "too_large"
        result.oversized_manifests_skipped += 1
        result.limits_hit.append("max_manifest_bytes")
        result.warnings.append(
            IngestionWarning(
                code=WarningCode.MANIFEST_TOO_LARGE,
                message="A dependency manifest exceeds the configured size limit and was not parsed",
                severity=Severity.WARNING,
                stage=IngestionStage.DISCOVERY,
                manifest_path=rel_path,
                details={"size_bytes": size, "max_manifest_bytes": settings.max_manifest_bytes},
            )
        )
    elif read.skip_reason in {"not_utf8", "binary"}:
        skipped_reason = read.skip_reason
        result.warnings.append(
            IngestionWarning(
                code=WarningCode.MANIFEST_NOT_UTF8,
                message="A dependency manifest is not valid UTF-8 text and may have been parsed incorrectly",
                severity=Severity.WARNING,
                stage=IngestionStage.DISCOVERY,
                manifest_path=rel_path,
                details={"reason": read.skip_reason, "size_bytes": size},
            )
        )
    elif read.skip_reason == "read_error":
        skipped_reason = "read_error"
        result.warnings.append(
            IngestionWarning(
                code=WarningCode.MANIFEST_PARSE_ERROR,
                message="A dependency manifest could not be read from disk",
                severity=Severity.WARNING,
                stage=IngestionStage.DISCOVERY,
                manifest_path=rel_path,
            )
        )

    if skipped_reason == "too_large":
        text = None
    elif skipped_reason == "read_error":
        text = None
    else:
        text = read.text

    return DiscoveredManifest(
        path=rel_path,
        directory=directory,
        absolute_path=path,
        format=supported,
        unsupported_format=None,
        support_level=SupportLevel.SUPPORTED,
        size_bytes=size,
        sha256=sha,
        text=text,
        skipped_reason=skipped_reason,
    )


def _is_excluded_directory(name: str, excluded: frozenset[str], suffixes: tuple[str, ...]) -> bool:
    lowered = name.lower()
    if lowered in excluded:
        return True
    return any(lowered.endswith(suffix) for suffix in suffixes)


def _rel(rel_dir: str, name: str) -> str:
    return f"{rel_dir}/{name}" if rel_dir else name


__all__ = [
    "DiscoveredManifest",
    "DiscoveryResult",
    "classify_dependency_file",
    "discover_repository_files",
]
