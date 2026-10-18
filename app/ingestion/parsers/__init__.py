"""Dependency manifest parsers.

Exactly four formats are parsed by BlastRadius, and each one is covered by
tests (see ``tests/test_parser_*.py``).  Anything else is detected and reported
as an unsupported format instead of being guessed at.
"""

from __future__ import annotations

from collections.abc import Callable

from app.ingestion.parsers.base import (
    FileResolver,
    MappingFileResolver,
    ParseOutcome,
    ParserContext,
    RecordOrigin,
)
from app.ingestion.parsers.poetry_lock import parse_poetry_lock
from app.ingestion.parsers.pyproject import parse_pyproject
from app.ingestion.parsers.requirements import parse_requirements
from app.ingestion.parsers.uv_lock import parse_uv_lock
from app.models.common import ManifestFormat

ParserFunction = Callable[[ParserContext], ParseOutcome]

PARSERS: dict[ManifestFormat, ParserFunction] = {
    ManifestFormat.REQUIREMENTS_TXT: parse_requirements,
    ManifestFormat.PYPROJECT_TOML: parse_pyproject,
    ManifestFormat.POETRY_LOCK: parse_poetry_lock,
    ManifestFormat.UV_LOCK: parse_uv_lock,
}

SUPPORTED_FORMATS: tuple[ManifestFormat, ...] = tuple(PARSERS)
LOCKFILE_FORMATS: tuple[ManifestFormat, ...] = tuple(
    manifest_format for manifest_format in SUPPORTED_FORMATS if manifest_format.is_lockfile
)

FORMAT_CAPABILITIES: dict[ManifestFormat, str] = {
    ManifestFormat.REQUIREMENTS_TXT: (
        "PEP 508 requirements, exact pins (as constraints), extras, markers, direct URL references, editable "
        "installs, local -r includes, hash options, constraint file references"
    ),
    ManifestFormat.PYPROJECT_TOML: (
        "PEP 621 [project] dependencies and optional-dependencies, PEP 735 [dependency-groups] (including "
        "include-group), Poetry dependencies/dev-dependencies/group tables, uv legacy dev-dependencies, "
        "[build-system] requires"
    ),
    ManifestFormat.POETRY_LOCK: (
        "[[package]] resolved versions, dependency groups (groups/category), markers, python-versions, "
        "non-registry sources, [package.dependencies] edges, [metadata] lock version"
    ),
    ManifestFormat.UV_LOCK: (
        "version/revision, [[package]] resolved versions, workspace root detection, optional-dependencies and "
        "dev-dependencies groups, dependency edges with resolved versions and specifiers, requires-dist metadata"
    ),
}


def get_parser(manifest_format: ManifestFormat) -> ParserFunction:
    """Return the parser for a supported format."""
    try:
        return PARSERS[manifest_format]
    except KeyError as exc:  # pragma: no cover - guarded by callers
        raise KeyError(f"no parser is registered for format {manifest_format!r}") from exc


__all__ = [
    "FORMAT_CAPABILITIES",
    "LOCKFILE_FORMATS",
    "PARSERS",
    "SUPPORTED_FORMATS",
    "FileResolver",
    "MappingFileResolver",
    "ParseOutcome",
    "ParserContext",
    "ParserFunction",
    "RecordOrigin",
    "get_parser",
    "parse_poetry_lock",
    "parse_pyproject",
    "parse_requirements",
    "parse_uv_lock",
]
