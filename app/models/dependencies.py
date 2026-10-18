"""Dependency records produced by the parsers.

These models are the payload that Phase 2 writes to FalkorDB:

* :class:`DependencyDeclaration` - what a manifest *declares* (may be a range);
* :class:`ResolvedPackage` - what a lockfile *resolved* (a concrete version);
* :class:`ResolvedDependencyEdge` - the resolved dependency graph edges that
  lockfiles expose, used for transitive reachability and blast-radius walks.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.models.common import (
    ConstraintScheme,
    DependencyRelation,
    DependencyScope,
    Ecosystem,
    ManifestFormat,
    ManifestParseStatus,
    SourceKind,
    SupportLevel,
    UnsupportedManifestFormat,
)


class DependencyProvenance(BaseModel):
    """Where a dependency fact came from.

    Every declaration and resolved package carries provenance so that a
    finding can always be traced back to a file, a line and a section.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    manifest_path: str = Field(description="Repository-relative path of the source file.")
    manifest_format: str = Field(description="Format identifier (e.g. 'requirements.txt', 'poetry.lock').")
    section: str | None = Field(default=None, description="TOML path / section the record came from.")
    line_number: int | None = Field(default=None, ge=1, description="1-based line number, when applicable.")
    snippet: str | None = Field(default=None, description="Truncated source snippet that produced the record.")
    evidence: str = Field(description="Human readable explanation of how the fact was derived.")


class DependencyDeclaration(BaseModel):
    """A dependency as declared by a manifest (requirement, constraint, group entry)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str
    repository_id: str | None = Field(default=None, description="Canonical repository id, stamped by the service.")
    commit_sha: str | None = Field(default=None, description="Analysed commit SHA, stamped by the service.")

    original_name: str = Field(description="Package name exactly as written in the manifest.")
    normalized_name: str = Field(description="PEP 503 normalised name (lower-case, '-' separators).")
    ecosystem: Ecosystem = Ecosystem.PYPI

    version_constraint: str | None = Field(
        default=None, description="Declared version constraint (e.g. '>=2.0,<3'). None when nothing was declared."
    )
    constraint_scheme: ConstraintScheme = ConstraintScheme.PEP440
    is_exact_pin: bool = Field(
        default=False, description="True for a single '==<version>' constraint. NOT proof of the installed version."
    )
    resolved_version: str | None = Field(
        default=None,
        description="Concrete version taken from a lockfile. Never derived from a constraint.",
    )
    resolved_from: str | None = Field(default=None, description="Lockfile that provided resolved_version, if any.")
    referenced_version: str | None = Field(
        default=None,
        description=(
            "Version parsed from a direct reference (wheel/sdist filename in a URL). Evidence about the requested "
            "artifact, not a resolution of the dependency graph."
        ),
    )

    scope: DependencyScope = DependencyScope.RUNTIME
    relation: DependencyRelation = DependencyRelation.DIRECT
    extras: tuple[str, ...] = ()
    marker: str | None = Field(default=None, description="PEP 508 environment marker / Poetry markers, verbatim.")
    requires_python: str | None = Field(default=None, description="Python version constraint attached to the entry.")

    source_kind: SourceKind = SourceKind.UNKNOWN
    source_reference: str | None = Field(default=None, description="Git URL/rev, path or URL for non-registry sources.")
    is_direct_url_reference: bool = False
    group: str | None = Field(default=None, description="Optional-dependency extra, Poetry group or PEP 735 group.")
    provenance: DependencyProvenance


class ResolvedDependencyEdge(BaseModel):
    """A dependency edge established by a lockfile (``from`` -> ``to``)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str
    repository_id: str | None = None
    commit_sha: str | None = None

    from_name: str = Field(description="Normalised name of the dependent package.")
    from_version: str | None = Field(default=None, description="Version of the dependent package.")
    to_name: str = Field(description="Normalised name of the dependency.")
    to_version_constraint: str | None = Field(
        default=None, description="Constraint written on the edge (poetry.lock 'dependencies', uv 'specifier')."
    )
    to_resolved_version: str | None = Field(
        default=None, description="Exact version of the target when the source lockfile provides it."
    )
    marker: str | None = None
    extras: tuple[str, ...] = ()
    optional: bool = Field(default=False, description="Edge belongs to an optional (extra) dependency group.")
    dev: bool = Field(default=False, description="Edge belongs to a development dependency group.")
    source_manifest: str = Field(description="Lockfile that established the edge.")
    provenance: DependencyProvenance


class ResolvedPackage(BaseModel):
    """A concrete package version resolved by a lockfile."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str
    repository_id: str | None = None
    commit_sha: str | None = None

    original_name: str
    normalized_name: str
    version: str = Field(description="Concrete resolved version. Lockfiles always provide one.")
    ecosystem: Ecosystem = Ecosystem.PYPI

    relation: DependencyRelation = DependencyRelation.UNKNOWN
    is_dev: bool = False
    is_optional: bool = False
    is_root_project: bool = Field(
        default=False, description="True for the repository's own project entry (uv.lock workspace root)."
    )
    groups: tuple[str, ...] = ()
    marker: str | None = None
    requires_python: str | None = None
    source_kind: SourceKind = SourceKind.REGISTRY
    source_reference: str | None = None
    dependency_count: int = Field(default=0, ge=0, description="Number of outgoing edges recorded for this package.")
    source_manifest: str = Field(description="Lockfile that resolved this package.")
    provenance: DependencyProvenance


class DependencyManifestRecord(BaseModel):
    """A detected dependency manifest and the outcome of parsing it."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str
    repository_id: str | None = None
    commit_sha: str | None = None

    path: str = Field(description="Repository-relative POSIX path.")
    directory: str = Field(default=".", description="Directory containing the manifest ('.' for the repository root).")
    format: ManifestFormat | None = None
    unsupported_format: UnsupportedManifestFormat | None = None
    support_level: SupportLevel
    is_lockfile: bool = False
    size_bytes: int = Field(ge=0, default=0)
    sha256: str | None = None
    status: ManifestParseStatus
    companion_manifest: str | None = Field(
        default=None, description="Related file, e.g. the pyproject.toml next to a poetry.lock/uv.lock."
    )
    declaration_count: int = Field(default=0, ge=0)
    resolved_count: int = Field(default=0, ge=0)
    edge_count: int = Field(default=0, ge=0)
    requires_python: str | None = None
    sections: dict[str, int] = Field(default_factory=dict, description="Record counts per parsed section.")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Format specific metadata (lock version, ...).")
    warning_codes: tuple[str, ...] = ()
    error_codes: tuple[str, ...] = ()
    skipped_reason: str | None = None


__all__ = [
    "DependencyDeclaration",
    "DependencyManifestRecord",
    "DependencyProvenance",
    "ResolvedDependencyEdge",
    "ResolvedPackage",
]
