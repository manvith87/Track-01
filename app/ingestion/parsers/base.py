"""Shared parser infrastructure.

The parsers are pure functions over text: they never import, execute or resolve
anything from the analysed repository, and they never invent versions.  They
receive a :class:`ParserContext` (file path, content, a resolver for files the
manifest itself references) and return a :class:`ParseOutcome` that the
aggregation layer merges.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Protocol

from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.utils import canonicalize_name

from app.core.config import Settings
from app.core.logging import get_logger
from app.models.common import (
    ConstraintScheme,
    DependencyRelation,
    DependencyScope,
    Ecosystem,
    ErrorCode,
    IngestionStage,
    ManifestParseStatus,
    Severity,
    SourceKind,
    WarningCode,
)
from app.models.dependencies import (
    DependencyDeclaration,
    DependencyProvenance,
    ResolvedDependencyEdge,
    ResolvedPackage,
)
from app.models.ids import stable_id
from app.models.ingestion import IngestionError, IngestionWarning

_log = get_logger("ingestion.parsers")

MAX_SNIPPET_LENGTH = 200


class FileResolver(Protocol):
    """Reads files that a manifest references (``-r other.txt``, PEP 735 includes)."""

    def read_text(self, relative_path: str) -> str | None:  # pragma: no cover - protocol
        ...

    def exists(self, relative_path: str) -> bool:  # pragma: no cover - protocol
        ...


class MappingFileResolver:
    """In-memory resolver used by unit tests and by the fixture tools."""

    def __init__(self, files: Mapping[str, str]) -> None:
        self._files = {key.replace("\\", "/"): value for key, value in files.items()}

    def read_text(self, relative_path: str) -> str | None:
        return self._files.get(relative_path.replace("\\", "/"))

    def exists(self, relative_path: str) -> bool:
        return relative_path.replace("\\", "/") in self._files


@dataclass(frozen=True, slots=True)
class ParserContext:
    """Everything a parser needs about one manifest."""

    path: str
    text: str
    settings: Settings
    resolver: FileResolver
    repository_files: frozenset[str] = frozenset()

    @property
    def lines(self) -> list[str]:
        return self.text.splitlines()

    @property
    def directory(self) -> str:
        parent = self.path.rsplit("/", 1)[0] if "/" in self.path else ""
        return parent or "."

    def resolve_sibling(self, reference: str) -> str:
        """Resolve a path referenced by this manifest, relative to its directory."""
        import posixpath

        base = "" if self.directory == "." else self.directory
        return posixpath.normpath(posixpath.join(base, reference)).lstrip("/")


@dataclass(slots=True)
class ParseOutcome:
    """Result of parsing one manifest."""

    status: ManifestParseStatus = ManifestParseStatus.PARSED
    declarations: list[DependencyDeclaration] = field(default_factory=list)
    resolved_packages: list[ResolvedPackage] = field(default_factory=list)
    edges: list[ResolvedDependencyEdge] = field(default_factory=list)
    warnings: list[IngestionWarning] = field(default_factory=list)
    errors: list[IngestionError] = field(default_factory=list)
    metadata: dict[str, object] = field(default_factory=dict)
    sections: dict[str, int] = field(default_factory=dict)
    requires_python: str | None = None
    project_name: str | None = None
    project_version: str | None = None
    direct_names: set[str] = field(default_factory=set)
    lock_root_names: set[str] = field(default_factory=set)

    def count_section(self, section: str, amount: int = 1) -> None:
        self.sections[section] = self.sections.get(section, 0) + amount


# ---------------------------------------------------------------------------
# Small helpers shared by all parsers
# ---------------------------------------------------------------------------
def normalize_name(raw: str) -> str:
    """PEP 503 normalisation (lower-case, ``-`` separators, no runs of dots)."""
    return str(canonicalize_name(raw))


def parse_requirement(text: str) -> Requirement:
    """Parse a PEP 508 requirement string."""
    return Requirement(text)


def specifier_is_exact_pin(specifier: SpecifierSet) -> bool:
    """True for a single ``==<version>`` constraint without a wildcard."""
    specs = list(specifier)
    return len(specs) == 1 and specs[0].operator == "==" and "*" not in specs[0].version


def constraint_scheme(specifier: str | None, *, default: ConstraintScheme = ConstraintScheme.PEP440) -> ConstraintScheme:
    """Classify a constraint string without interpreting it.

    Poetry-only syntax (``^1.2``, ``~1.2``, ``1.2.3``, ``||``) is labelled
    :attr:`ConstraintScheme.POETRY` and preserved verbatim.  A constraint a
    Poetry table writes in PEP 440 syntax (``>=2.0``, ``==1.2.3``) is labelled
    :attr:`ConstraintScheme.PEP440` because :mod:`packaging` can evaluate it -
    the originating table is always recorded in the provenance, so no
    information is lost.  Bare versions from non-Poetry sources fall back to
    ``default``; anything unrecognised is :attr:`ConstraintScheme.UNKNOWN`.
    """
    if specifier is None:
        return ConstraintScheme.ANY
    stripped = specifier.strip()
    if not stripped or stripped == "*":
        return ConstraintScheme.ANY
    if stripped[0] == "^" or (stripped[0] == "~" and not stripped.startswith("~=")):
        return ConstraintScheme.POETRY
    if "||" in stripped or "&&" in stripped:
        return ConstraintScheme.POETRY
    if is_valid_specifier(stripped):
        return ConstraintScheme.PEP440
    if re.match(r"^\d", stripped) or stripped.startswith("="):
        # Poetry allows bare versions ("1.2.3") and "==1.2.3"; PEP 440 accepts
        # the latter only with an operator, so keep whatever the manifest wrote.
        return default
    return ConstraintScheme.UNKNOWN


def is_valid_specifier(specifier: str) -> bool:
    """Whether a constraint is a valid PEP 440 specifier."""
    try:
        SpecifierSet(specifier)
    except InvalidSpecifier:
        return False
    return True


def snippet_for_line(line: str, *, limit: int = MAX_SNIPPET_LENGTH) -> str:
    """Trim a source line for provenance/evidence purposes."""
    text = line.strip()
    return text if len(text) <= limit else f"{text[:limit]}..."


def warn(
    code: WarningCode,
    message: str,
    *,
    severity: Severity = Severity.WARNING,
    manifest_path: str | None = None,
    line_number: int | None = None,
    stage: IngestionStage = IngestionStage.PARSING,
    **details: object,
) -> IngestionWarning:
    return IngestionWarning(
        code=code,
        message=message,
        severity=severity,
        stage=stage,
        manifest_path=manifest_path,
        line_number=line_number,
        details=dict(details),
    )


def err(
    code: ErrorCode,
    message: str,
    *,
    manifest_path: str | None = None,
    line_number: int | None = None,
    stage: IngestionStage = IngestionStage.PARSING,
    retryable: bool = False,
    **details: object,
) -> IngestionError:
    return IngestionError(
        code=code,
        message=message,
        stage=stage,
        manifest_path=manifest_path,
        line_number=line_number,
        retryable=retryable,
        details=dict(details),
    )


@dataclass(frozen=True, slots=True)
class RecordOrigin:
    """Provenance for one extracted record."""

    path: str
    manifest_format: str
    evidence: str
    section: str | None = None
    line_number: int | None = None
    snippet: str | None = None

    def to_provenance(self) -> DependencyProvenance:
        return DependencyProvenance(
            manifest_path=self.path,
            manifest_format=self.manifest_format,
            section=self.section,
            line_number=self.line_number,
            snippet=self.snippet,
            evidence=self.evidence,
        )


def build_declaration(
    *,
    origin: RecordOrigin,
    original_name: str,
    constraint: str | None,
    scheme: ConstraintScheme,
    scope: DependencyScope,
    relation: DependencyRelation = DependencyRelation.DIRECT,
    marker: str | None = None,
    extras: Sequence[str] = (),
    requires_python: str | None = None,
    group: str | None = None,
    source_kind: SourceKind = SourceKind.UNKNOWN,
    source_reference: str | None = None,
    is_direct_url_reference: bool = False,
    referenced_version: str | None = None,
    occurrence: int = 0,
    ecosystem: Ecosystem = Ecosystem.PYPI,
) -> DependencyDeclaration:
    """Create a declaration with a deterministic id and PEP 503 normalised name."""
    normalized = normalize_name(original_name)
    is_pin = False
    if constraint and scheme is ConstraintScheme.PEP440 and is_valid_specifier(constraint):
        is_pin = specifier_is_exact_pin(SpecifierSet(constraint))
    declaration_id = stable_id(
        "decl",
        origin.path,
        origin.section,
        origin.line_number,
        normalized,
        constraint,
        marker,
        scope.value,
        group,
        occurrence,
    )
    return DependencyDeclaration(
        id=declaration_id,
        original_name=original_name,
        normalized_name=normalized,
        ecosystem=ecosystem,
        version_constraint=constraint,
        constraint_scheme=scheme,
        is_exact_pin=is_pin,
        scope=scope,
        relation=relation,
        extras=tuple(sorted(extras)),
        marker=marker,
        requires_python=requires_python,
        source_kind=source_kind,
        source_reference=source_reference,
        is_direct_url_reference=is_direct_url_reference,
        referenced_version=referenced_version,
        group=group,
        provenance=origin.to_provenance(),
    )


def build_resolved_package(
    *,
    origin: RecordOrigin,
    original_name: str,
    version: str,
    relation: DependencyRelation = DependencyRelation.UNKNOWN,
    is_dev: bool = False,
    is_optional: bool = False,
    is_root_project: bool = False,
    groups: Iterable[str] = (),
    marker: str | None = None,
    requires_python: str | None = None,
    source_kind: SourceKind = SourceKind.REGISTRY,
    source_reference: str | None = None,
    dependency_count: int = 0,
    ecosystem: Ecosystem = Ecosystem.PYPI,
) -> ResolvedPackage:
    normalized = normalize_name(original_name)
    package_id = stable_id("pkg", origin.path, normalized, version, source_reference)
    return ResolvedPackage(
        id=package_id,
        original_name=original_name,
        normalized_name=normalized,
        version=version,
        ecosystem=ecosystem,
        relation=relation,
        is_dev=is_dev,
        is_optional=is_optional,
        is_root_project=is_root_project,
        groups=tuple(sorted(set(groups))),
        marker=marker,
        requires_python=requires_python,
        source_kind=source_kind,
        source_reference=source_reference,
        dependency_count=dependency_count,
        source_manifest=origin.path,
        provenance=origin.to_provenance(),
    )


def build_edge(
    *,
    origin: RecordOrigin,
    from_name: str,
    from_version: str | None,
    to_name: str,
    to_version_constraint: str | None = None,
    to_resolved_version: str | None = None,
    marker: str | None = None,
    extras: Sequence[str] = (),
    optional: bool = False,
    dev: bool = False,
) -> ResolvedDependencyEdge:
    normalized_from = normalize_name(from_name)
    normalized_to = normalize_name(to_name)
    edge_id = stable_id(
        "edge",
        origin.path,
        normalized_from,
        from_version,
        normalized_to,
        to_version_constraint,
        marker,
        tuple(sorted(extras)),
        optional,
        dev,
    )
    return ResolvedDependencyEdge(
        id=edge_id,
        from_name=normalized_from,
        from_version=from_version,
        to_name=normalized_to,
        to_version_constraint=to_version_constraint,
        to_resolved_version=to_resolved_version,
        marker=marker,
        extras=tuple(sorted(extras)),
        optional=optional,
        dev=dev,
        source_manifest=origin.path,
        provenance=origin.to_provenance(),
    )


_WHEEL_SUFFIX = ".whl"
_SDIST_SUFFIXES = (".tar.gz", ".zip", ".tar.bz2", ".tgz")


def classify_source_kind(reference: str) -> SourceKind:
    """Classify a direct reference (URL/path/VCS) without fetching it."""
    lowered = reference.strip().lower()
    if lowered.startswith("git+") or lowered.startswith("git:"):
        return SourceKind.GIT
    if lowered.startswith(("http://", "https://")):
        return SourceKind.URL
    if lowered.startswith("file:"):
        return SourceKind.PATH
    if "/" in lowered or lowered.startswith("."):
        return SourceKind.PATH
    return SourceKind.UNKNOWN


def version_from_reference(reference: str, expected_name: str) -> str | None:
    """Extract a version from a wheel/sdist filename referenced by a direct URL.

    Returns ``None`` when the filename does not unambiguously encode a version
    for the expected distribution - BlastRadius never guesses.
    """
    from urllib.parse import unquote, urlsplit

    path = urlsplit(reference).path if "://" in reference else reference
    basename = unquote(path.rstrip("/").rsplit("/", 1)[-1])
    lowered = basename.lower()

    candidate_name: str | None = None
    candidate_version: str | None = None
    if lowered.endswith(_WHEEL_SUFFIX):
        stem = basename[: -len(_WHEEL_SUFFIX)]
        head, _, rest = stem.partition("-")
        if head and rest:
            candidate_name = head
            candidate_version = rest.split("-", 1)[0]
    else:
        for suffix in _SDIST_SUFFIXES:
            if lowered.endswith(suffix):
                stem = basename[: -len(suffix)]
                head, sep, tail = stem.rpartition("-")
                if sep and head and tail:
                    candidate_name = head
                    candidate_version = tail
                break

    if candidate_name is None or candidate_version is None:
        return None
    if normalize_name(candidate_name) != normalize_name(expected_name):
        return None
    if not candidate_version[:1].isdigit():
        return None
    return candidate_version


def parse_pep508(
    text: str,
) -> tuple[Requirement | None, str | None]:
    """Parse a PEP 508 string, returning ``(requirement, error_message)``.

    ``packaging`` raises :class:`InvalidRequirement` for a malformed
    requirement and :class:`InvalidSpecifier` (a sibling, not a subclass) when
    the version part of an otherwise well-formed requirement is not a valid
    PEP 440 specifier; both are treated as malformed input because neither may
    ever crash a parser running on untrusted repository content.
    """
    try:
        return parse_requirement(text), None
    except (InvalidRequirement, InvalidSpecifier) as exc:
        return None, str(exc)


__all__ = [
    "MAX_SNIPPET_LENGTH",
    "FileResolver",
    "MappingFileResolver",
    "ParseOutcome",
    "ParserContext",
    "RecordOrigin",
    "build_declaration",
    "build_edge",
    "build_resolved_package",
    "classify_source_kind",
    "constraint_scheme",
    "err",
    "is_valid_specifier",
    "normalize_name",
    "parse_pep508",
    "parse_requirement",
    "snippet_for_line",
    "specifier_is_exact_pin",
    "version_from_reference",
    "warn",
]
