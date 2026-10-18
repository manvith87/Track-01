"""``requirements.txt`` parser.

Supported (and tested) subset of pip's requirements file format:

* PEP 508 requirement lines, including extras, environment markers and
  parenthesised version specifiers;
* exact pins (``==1.2.3``) - recorded as *constraints*, never as installed
  versions, because a requirements file does not prove what is installed;
* direct references (``name @ https://.../name-1.2.3-py3-none-any.whl``), with
  the artifact version extracted only when the filename is unambiguous;
* editable/local references (``-e .``, ``-e git+https://...#egg=name``);
* ``-r``/``--requirement`` includes, resolved inside the repository only, with
  depth limiting and cycle detection;
* ``-c``/``--constraint`` references (reported, not resolved);
* hashes (``--hash=sha256:...``), index options and other pip options.

Unsupported by design (reported as warnings, never guessed): remote includes,
``--index-url`` based resolution, ``--global-option``/``--install-option``
build flags and requirements files that are not valid UTF-8.
"""

from __future__ import annotations

import posixpath

from app.ingestion.parsers.base import (
    ParseOutcome,
    ParserContext,
    RecordOrigin,
    build_declaration,
    classify_source_kind,
    constraint_scheme,
    parse_pep508,
    snippet_for_line,
    version_from_reference,
    warn,
)
from app.ingestion.safety import validate_relative_path
from app.models.common import (
    ConstraintScheme,
    DependencyScope,
    ManifestFormat,
    ManifestParseStatus,
    Severity,
    SourceKind,
    WarningCode,
)
from app.models.dependencies import DependencyDeclaration

FORMAT = ManifestFormat.REQUIREMENTS_TXT

_LONG_OPTIONS_WITH_VALUE = frozenset(
    {
        "requirement",
        "constraint",
        "index-url",
        "extra-index-url",
        "find-links",
        "trusted-host",
        "no-binary",
        "only-binary",
        "platform",
        "python-version",
        "implementation",
        "abi",
        "hash",
        "global-option",
        "install-option",
        "config-settings",
        "report",
    }
)
_LONG_FLAGS = frozenset(
    {
        "pre",
        "prefer-binary",
        "no-index",
        "no-deps",
        "no-build-isolation",
        "use-pep517",
        "no-cache-dir",
        "require-hashes",
        "require-virtualenv",
        "quiet",
        "verbose",
        "disable-pip-version-check",
        "break-system-packages",
        "root-user-action",
        "progress-bar",
        "no-color",
        "no-warn-script-location",
        "no-warn-conflicts",
        "ignore-installed",
        "isolated",
        "no-clean",
        "log",
        "exists-action",
    }
)
_SHORT_OPTIONS_WITH_VALUE = frozenset({"r", "c", "e", "i", "f", "t"})

_DEV_HINTS = ("dev", "test", "tests", "lint", "docs", "typing", "ci")


def parse_requirements(context: ParserContext) -> ParseOutcome:
    """Parse a requirements file, following local ``-r`` includes."""
    outcome = ParseOutcome()
    state = _RequirementsState(context, outcome)
    state.parse_file(context.path, context.text, depth=0, visited=(context.path,))

    if not outcome.declarations and not outcome.errors:
        has_content = any(
            line.strip() and not line.strip().startswith("#") for line in context.text.splitlines()
        )
        outcome.warnings.append(
            warn(
                WarningCode.EMPTY_MANIFEST if not has_content else WarningCode.NO_DEPENDENCIES_FOUND,
                "The requirements file does not declare any dependency"
                if not has_content
                else "The requirements file declares options but no dependencies",
                severity=Severity.INFO,
                manifest_path=context.path,
            )
        )

    outcome.metadata.setdefault("included_files", [])
    return outcome


class _RequirementsState:
    """Mutable parsing state for one requirements file (and its includes)."""

    def __init__(self, context: ParserContext, outcome: ParseOutcome) -> None:
        self.context = context
        self.outcome = outcome
        self.settings = context.settings
        self.limit_warned = False
        self.seen: dict[tuple[object, ...], int] = {}
        self.index_urls: list[str] = []
        self.extra_index_urls: list[str] = []
        self.find_links: list[str] = []
        self.hash_pinned = 0
        self.editable = 0

    # -- file / line handling ---------------------------------------------
    def parse_file(self, path: str, text: str, *, depth: int, visited: tuple[str, ...]) -> None:
        lines = text.splitlines()
        index = 0
        while index < len(lines):
            if self._cap_reached():
                return
            line_number = index + 1
            logical = lines[index]
            # Join backslash continuations (pip allows them, e.g. before --hash).
            while logical.rstrip().endswith("\\") and index + 1 < len(lines):
                logical = logical.rstrip()[:-1] + " " + lines[index + 1]
                index += 1
            index += 1

            stripped = _strip_comment(logical)
            if not stripped:
                continue

            if stripped.startswith("-"):
                self._handle_option(
                    path=path,
                    line=stripped,
                    line_number=line_number,
                    depth=depth,
                    visited=visited,
                )
                continue

            self._handle_requirement(path=path, line=stripped, line_number=line_number)

    def _handle_option(
        self,
        *,
        path: str,
        line: str,
        line_number: int,
        depth: int,
        visited: tuple[str, ...],
    ) -> None:
        name, value = _split_option(line)
        lowered = name.lower()

        if lowered in {"-r", "--requirement"}:
            self._include(reference=value, path=path, line_number=line_number, depth=depth, visited=visited)
            return
        if lowered in {"-c", "--constraint"}:
            self.outcome.warnings.append(
                warn(
                    WarningCode.CONSTRAINT_FILE_REFERENCE,
                    "A constraint file reference was found; constraints are not dependency declarations and "
                    "were not resolved",
                    severity=Severity.INFO,
                    manifest_path=path,
                    line_number=line_number,
                    reference=value,
                )
            )
            self.outcome.count_section("constraint_references")
            return
        if lowered in {"-e", "--editable"}:
            self._handle_editable(path=path, reference=value, line_number=line_number)
            return
        if lowered in {"--index-url", "-i"}:
            self.index_urls.append(value)
            return
        if lowered == "--extra-index-url":
            self.extra_index_urls.append(value)
            return
        if lowered in {"--find-links", "-f"}:
            self.find_links.append(value)
            return
        if lowered == "--hash":
            self.hash_pinned += 1
            self.outcome.count_section("hash_options")
            return
        if lowered in {"--global-option", "--install-option", "--config-settings"}:
            self.outcome.warnings.append(
                warn(
                    WarningCode.UNSUPPORTED_DEPENDENCY_SECTION,
                    "A pip build option was found; build options are ignored and never executed",
                    severity=Severity.INFO,
                    manifest_path=path,
                    line_number=line_number,
                    option=name,
                )
            )
            return
        if lowered in _LONG_OPTIONS_WITH_VALUE or lowered in _LONG_FLAGS:
            return
        self.outcome.warnings.append(
            warn(
                WarningCode.UNSUPPORTED_DEPENDENCY_SECTION,
                "An unrecognised pip option was ignored",
                severity=Severity.INFO,
                manifest_path=path,
                line_number=line_number,
                option=name,
            )
        )

    def _include(self, *, reference: str, path: str, line_number: int, depth: int, visited: tuple[str, ...]) -> None:
        target = reference.strip()
        if not target:
            self.outcome.warnings.append(
                warn(
                    WarningCode.MALFORMED_ENTRY,
                    "A requirements include was declared without a file reference",
                    manifest_path=path,
                    line_number=line_number,
                )
            )
            self.outcome.status = ManifestParseStatus.PARTIAL
            return
        if target.lower().startswith(("http://", "https://", "git+", "git:", "ftp://")):
            self.outcome.warnings.append(
                warn(
                    WarningCode.REMOTE_REQUIREMENT_REFERENCE,
                    "A remote requirements include was not fetched; only repository-local includes are followed",
                    severity=Severity.WARNING,
                    manifest_path=path,
                    line_number=line_number,
                    reference=target,
                )
            )
            self.outcome.count_section("remote_includes")
            return

        if depth >= self.settings.max_requirement_include_depth:
            self.outcome.warnings.append(
                warn(
                    WarningCode.INCLUDE_DEPTH_EXCEEDED,
                    "The requirements include depth limit was reached; nested includes were not followed",
                    manifest_path=path,
                    line_number=line_number,
                    reference=target,
                    max_depth=self.settings.max_requirement_include_depth,
                )
            )
            self.outcome.status = ManifestParseStatus.PARTIAL
            return

        try:
            resolved = validate_relative_path(
                posixpath.normpath(posixpath.join(posixpath.dirname(path), target)),
                context="requirements include path",
            )
        except Exception:  # pragma: no cover - validate_relative_path raises UnsafeRepositoryContentError
            self.outcome.warnings.append(
                warn(
                    WarningCode.MALFORMED_ENTRY,
                    "A requirements include points outside the repository and was not followed",
                    manifest_path=path,
                    line_number=line_number,
                    reference=target,
                )
            )
            self.outcome.status = ManifestParseStatus.PARTIAL
            return

        if resolved in visited:
            self.outcome.warnings.append(
                warn(
                    WarningCode.NESTED_REQUIREMENT_CYCLE,
                    "A requirements include cycle was detected and not followed",
                    manifest_path=path,
                    line_number=line_number,
                    reference=resolved,
                )
            )
            self.outcome.status = ManifestParseStatus.PARTIAL
            return

        if not self.context.resolver.exists(resolved):
            self.outcome.warnings.append(
                warn(
                    WarningCode.NESTED_REQUIREMENT_NOT_FOUND,
                    "A referenced requirements file does not exist in the repository",
                    manifest_path=path,
                    line_number=line_number,
                    reference=resolved,
                )
            )
            self.outcome.status = ManifestParseStatus.PARTIAL
            return

        text = self.context.resolver.read_text(resolved)
        if text is None:
            self.outcome.warnings.append(
                warn(
                    WarningCode.NESTED_REQUIREMENT_NOT_FOUND,
                    "A referenced requirements file could not be read",
                    manifest_path=path,
                    line_number=line_number,
                    reference=resolved,
                )
            )
            self.outcome.status = ManifestParseStatus.PARTIAL
            return

        included = self.outcome.metadata.setdefault("included_files", [])
        assert isinstance(included, list)
        included.append(resolved)
        self.outcome.count_section("includes")
        self.parse_file(resolved, text, depth=depth + 1, visited=(*visited, resolved))

    def _handle_editable(self, *, path: str, reference: str, line_number: int) -> None:
        self.editable += 1
        target = reference.strip()
        origin = RecordOrigin(
            path=path,
            manifest_format=FORMAT.value,
            section="editable",
            line_number=line_number,
            snippet=snippet_for_line(f"-e {target}"),
            evidence="editable install declared in the requirements file",
        )
        name = _egg_name(target)
        if name is None:
            self.outcome.warnings.append(
                warn(
                    WarningCode.EDITABLE_REFERENCE,
                    "An editable reference without a '#egg=<name>' fragment was found; no package name could be "
                    "derived and no declaration was created",
                    severity=Severity.WARNING,
                    manifest_path=path,
                    line_number=line_number,
                    reference=target,
                )
            )
            self.outcome.count_section("editable_references")
            self.outcome.status = ManifestParseStatus.PARTIAL
            return

        kind = classify_source_kind(target)
        declaration = build_declaration(
            origin=origin,
            original_name=name,
            constraint=None,
            scheme=ConstraintScheme.ANY,
            scope=DependencyScope.RUNTIME,
            marker=None,
            source_kind=SourceKind.EDITABLE if kind in {SourceKind.PATH, SourceKind.UNKNOWN} else kind,
            source_reference=target,
            occurrence=self._occurrence(origin, "editable"),
        )
        self._add_declaration(declaration)
        self.outcome.count_section("editable_references")
        self.outcome.warnings.append(
            warn(
                WarningCode.EDITABLE_REFERENCE,
                "An editable install was recorded without a version; the local source is not resolved here",
                severity=Severity.INFO,
                manifest_path=path,
                line_number=line_number,
                package=name,
            )
        )

    def _handle_requirement(self, *, path: str, line: str, line_number: int) -> None:
        cleaned, has_hash, has_build_option = _strip_trailing_options(line)
        if has_hash:
            self.hash_pinned += 1
            self.outcome.count_section("hash_options")
        if has_build_option:
            self.outcome.warnings.append(
                warn(
                    WarningCode.UNSUPPORTED_DEPENDENCY_SECTION,
                    "A per-requirement build option was ignored and never executed",
                    severity=Severity.INFO,
                    manifest_path=path,
                    line_number=line_number,
                )
            )

        if _looks_like_local_artifact(cleaned):
            self.outcome.warnings.append(
                warn(
                    WarningCode.LOCAL_PATH_REQUIREMENT,
                    "A local path or archive requirement cannot be resolved without installing the project; it was "
                    "recorded as unsupported input",
                    severity=Severity.WARNING,
                    manifest_path=path,
                    line_number=line_number,
                    reference=cleaned,
                )
            )
            self.outcome.count_section("local_path_requirements")
            self.outcome.status = ManifestParseStatus.PARTIAL
            return

        requirement, error = parse_pep508(cleaned)
        if requirement is None:
            self.outcome.warnings.append(
                warn(
                    WarningCode.MALFORMED_ENTRY,
                    "A requirement line could not be parsed as PEP 508 and was skipped",
                    severity=Severity.WARNING,
                    manifest_path=path,
                    line_number=line_number,
                    snippet=snippet_for_line(line),
                    reason=error,
                )
            )
            self.outcome.count_section("malformed_entries")
            self.outcome.status = ManifestParseStatus.PARTIAL
            return

        scope, group, scope_evidence = _scope_from_filename(path)
        origin = RecordOrigin(
            path=path,
            manifest_format=FORMAT.value,
            section="requirements",
            line_number=line_number,
            snippet=snippet_for_line(line),
            evidence=scope_evidence,
        )
        marker = str(requirement.marker) if requirement.marker is not None else None
        constraint = str(requirement.specifier) or None
        constraint_scheme_value = constraint_scheme(constraint)
        source_kind = SourceKind.REGISTRY
        source_reference: str | None = None
        referenced_version: str | None = None
        is_direct_url = False

        if requirement.url:
            is_direct_url = True
            source_reference = requirement.url
            source_kind = classify_source_kind(requirement.url)
            referenced_version = version_from_reference(requirement.url, requirement.name)
            origin = RecordOrigin(
                path=origin.path,
                manifest_format=origin.manifest_format,
                section="direct_reference",
                line_number=origin.line_number,
                snippet=origin.snippet,
                evidence=(
                    "direct reference declared in the requirements file; the requested artifact is "
                    f"{'version ' + referenced_version if referenced_version else 'not version pinned'}"
                ),
            )
            self.outcome.warnings.append(
                warn(
                    WarningCode.DIRECT_URL_REFERENCE,
                    "A direct URL reference was recorded; its version is only known when the artifact filename "
                    "encodes it and is not treated as a resolved version",
                    severity=Severity.INFO,
                    manifest_path=path,
                    line_number=line_number,
                    package=requirement.name,
                    version_from_url=referenced_version,
                )
            )

        declaration = build_declaration(
            origin=origin,
            original_name=requirement.name,
            constraint=constraint,
            scheme=constraint_scheme_value,
            scope=scope,
            marker=marker,
            extras=requirement.extras,
            group=group,
            source_kind=source_kind,
            source_reference=source_reference,
            is_direct_url_reference=is_direct_url,
            referenced_version=referenced_version,
            occurrence=self._occurrence(origin, "requirement"),
        )
        self._add_declaration(declaration)

        if has_hash:
            self.outcome.warnings.append(
                warn(
                    WarningCode.HASH_PINNED_REQUIREMENT,
                    "The requirement is hash pinned; hashes are recorded but not verified",
                    severity=Severity.INFO,
                    manifest_path=path,
                    line_number=line_number,
                    package=requirement.name,
                )
            )
        if scope is DependencyScope.DEV and group:
            self.outcome.warnings.append(
                warn(
                    WarningCode.RELATION_INFERRED,
                    "The dependency was classified as development-only based on the requirements file name",
                    severity=Severity.INFO,
                    manifest_path=path,
                    line_number=line_number,
                    package=requirement.name,
                    group=group,
                )
            )

    # -- bookkeeping ------------------------------------------------------
    def _occurrence(self, origin: RecordOrigin, kind: str) -> int:
        key = (origin.path, origin.line_number, origin.section, kind)
        count = self.seen.get(key, 0)
        self.seen[key] = count + 1
        return count

    def _add_declaration(self, declaration: DependencyDeclaration) -> None:
        self.outcome.declarations.append(declaration)
        self.outcome.direct_names.add(declaration.normalized_name)
        self.outcome.count_section("dependencies")

    def _cap_reached(self) -> bool:
        if len(self.outcome.declarations) < self.settings.max_dependencies:
            return False
        if not self.limit_warned:
            self.limit_warned = True
            self.outcome.warnings.append(
                warn(
                    WarningCode.DEPENDENCY_LIMIT_REACHED,
                    "The dependency limit was reached; the remaining declarations were not parsed",
                    manifest_path=self.context.path,
                    limit=self.settings.max_dependencies,
                )
            )
            self.outcome.status = ManifestParseStatus.PARTIAL
        return True


def _strip_comment(line: str) -> str:
    """Remove a trailing comment, keeping ``#`` inside URLs (``#egg=``)."""
    text = line
    index = 0
    while True:
        position = text.find("#", index)
        if position < 0:
            return text.strip()
        if position == 0 or text[position - 1].isspace():
            return text[:position].strip()
        index = position + 1


def _split_option(line: str) -> tuple[str, str]:
    """Split an option line into ``(option, value)``."""
    text = line.strip()
    if text.startswith("--"):
        head, sep, tail = text.partition("=")
        if sep:
            return head.strip(), tail.strip()
        parts = head.strip().split(None, 1)
        option = parts[0]
        remainder = parts[1].strip() if len(parts) > 1 else ""
        return option, remainder
    if len(text) >= 2:
        return text[:2], text[2:].strip()
    return text, ""


def _strip_trailing_options(line: str) -> tuple[str, bool, bool]:
    """Remove ``--hash`` / build options appended to a requirement line."""
    has_hash = False
    has_build_option = False
    kept: list[str] = []
    for token in line.split():
        if token.startswith("--hash=") or token == "--hash":
            has_hash = True
            continue
        if token.startswith("--global-option=") or token.startswith("--install-option="):
            has_build_option = True
            continue
        kept.append(token)
    return " ".join(kept).strip(), has_hash, has_build_option


def _looks_like_local_artifact(line: str) -> bool:
    """Whether a line references a local path/archive rather than a distribution."""
    tokens = line.strip().split()
    if not tokens:
        return False
    first = tokens[0].lower()
    if first.startswith(("./", "../", "/", ".\\", "..\\", "file:", "~/")):
        return True
    if len(tokens) == 1:
        lowered = tokens[0].lower()
        if lowered.endswith((".whl", ".tar.gz", ".zip", ".tar.bz2", ".tgz", ".egg")):
            return True
    return False


def _egg_name(reference: str) -> str | None:
    """Extract ``#egg=`` from an editable/VCS reference."""
    if "#egg=" not in reference:
        return None
    fragment = reference.split("#egg=", 1)[1]
    name = fragment.split("&", 1)[0].split("#", 1)[0].strip()
    return name or None


def _scope_from_filename(path: str) -> tuple[DependencyScope, str | None, str]:
    """Classify dev/test requirement files by their conventional file name."""
    base = posixpath.basename(path).lower()
    stem = base[: -len(".txt")] if base.endswith(".txt") else base
    normalized_stem = stem.replace("_", "-")
    parts = [part for part in normalized_stem.split("-") if part and part != "requirements"]
    group = normalized_stem or None
    for hint in _DEV_HINTS:
        if hint in parts:
            return (
                DependencyScope.DEV,
                group,
                f"declared in requirements file '{path}' which by naming convention holds development dependencies",
            )
    return (
        DependencyScope.RUNTIME,
        group,
        f"declared in requirements file '{path}'",
    )


__all__ = ["FORMAT", "parse_requirements"]
