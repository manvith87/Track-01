"""``pyproject.toml`` parser.

Parsed, tested subsets:

* PEP 621 ``[project].dependencies`` and ``[project.optional-dependencies]``;
* PEP 735 ``[dependency-groups]`` (including ``{include-group = "..."}``);
* Poetry ``[tool.poetry.dependencies]``, ``[tool.poetry.dev-dependencies]`` and
  ``[tool.poetry.group.<name>.dependencies]``;
* uv's legacy ``[tool.uv].dev-dependencies``;
* ``[build-system].requires`` (classified as build scope, not runtime).

Recognised but *not* parsed (reported as warnings): PDM dependency tables,
``dynamic = ["dependencies"]`` projects whose real requirements live in
``setup.py``/``setup.cfg``, and unknown tool sections.

Poetry constraints (``^1.2``, ``~1.2``, ``||``) are preserved verbatim with
``constraint_scheme = poetry`` - they are never converted to PEP 440 and never
treated as resolved versions.
"""

from __future__ import annotations

import re
from typing import Any

try:  # pragma: no cover - Python < 3.11 only
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11 only
    import tomli as tomllib  # type: ignore[no-redef]

from app.core.logging import safe_text
from app.ingestion.parsers.base import (
    ParseOutcome,
    ParserContext,
    RecordOrigin,
    build_declaration,
    classify_source_kind,
    constraint_scheme,
    err,
    snippet_for_line,
    warn,
)
from app.models.common import (
    ConstraintScheme,
    DependencyRelation,
    DependencyScope,
    ErrorCode,
    ManifestFormat,
    ManifestParseStatus,
    Severity,
    SourceKind,
    WarningCode,
)
from app.models.dependencies import DependencyDeclaration

FORMAT = ManifestFormat.PYPROJECT_TOML

_DEV_GROUP_HINTS = frozenset({"dev", "development", "test", "tests", "testing", "lint", "linting", "docs", "typing", "ci"})
_LINE_NUMBER_RE = re.compile(r"line (\d+)")


class TomlLineIndex:
    """Best-effort mapping from TOML structures to source line numbers.

    ``tomllib`` does not expose source positions, so this index re-scans the
    (already in-memory, untrusted) text.  Line numbers are provenance hints;
    when they cannot be determined ``None`` is reported instead of a guess.
    """

    def __init__(self, lines: list[str]) -> None:
        self._lines = lines
        self._section_of_line: list[str | None] = []
        self._key_lines: dict[tuple[str, str], int] = {}
        self._block_starts: dict[str, list[int]] = {}
        current = ""
        for number, raw in enumerate(lines, start=1):
            line = raw.strip()
            self._section_of_line.append(current)
            if line.startswith("[[") and line.endswith("]]"):
                header = line[2:-2].strip()
                current = header
                self._block_starts.setdefault(header, []).append(number)
                self._section_of_line[-1] = current
                continue
            if line.startswith("[") and line.endswith("]"):
                current = line[1:-1].strip()
                self._section_of_line[-1] = current
                continue
            if "=" in line and not line.startswith("#"):
                key = line.split("=", 1)[0].strip().strip('"').strip("'")
                self._key_lines.setdefault((current, key), number)
        self._current_section = current

    def line_text(self, number: int | None) -> str | None:
        if number is None or number < 1 or number > len(self._lines):
            return None
        return snippet_for_line(self._lines[number - 1])

    def section_line(self, section: str) -> int | None:
        for number, raw in enumerate(self._lines, start=1):
            stripped = raw.strip()
            if stripped in {f"[{section}]", f"[[{section}]]"}:
                return number
        return None

    def key_line(self, section: str, key: str) -> int | None:
        return self._key_lines.get((section, key))

    def array_entry_line(self, section: str, key: str, entry: str, *, span: int = 200) -> int | None:
        start = self.key_line(section, key)
        if start is None:
            return None
        needle = entry.strip().strip('"').strip("'")
        if not needle:
            return start
        depth = 0
        for offset in range(0, span):
            number = start + offset
            if number > len(self._lines):
                break
            line = self._lines[number - 1]
            if needle in line:
                return number
            depth += line.count("[") - line.count("]")
            if offset > 0 and depth <= 0 and line.strip().endswith("]"):
                break
        return start

    def block_start_lines(self, header: str) -> list[int]:
        return list(self._block_starts.get(header, []))


def parse_pyproject(context: ParserContext) -> ParseOutcome:
    """Parse a pyproject.toml dependency declaration surface."""
    outcome = ParseOutcome()
    index = TomlLineIndex(context.lines)

    try:
        data = tomllib.loads(context.text)
    except tomllib.TOMLDecodeError as exc:
        line = _line_from_message(str(exc))
        outcome.status = ManifestParseStatus.FAILED
        outcome.errors.append(
            err(
                ErrorCode.MANIFEST_PARSE_ERROR,
                "pyproject.toml is not valid TOML and could not be parsed",
                manifest_path=context.path,
                line_number=line,
                reason=safe_text(exc, 200),
            )
        )
        outcome.warnings.append(
            warn(
                WarningCode.MANIFEST_PARSE_ERROR,
                "pyproject.toml is not valid TOML; no dependency information could be extracted from it",
                severity=Severity.ERROR,
                manifest_path=context.path,
                line_number=line,
            )
        )
        return outcome

    if not isinstance(data, dict):
        outcome.status = ManifestParseStatus.FAILED
        outcome.errors.append(
            err(
                ErrorCode.MANIFEST_PARSE_ERROR,
                "pyproject.toml did not parse into a TOML table",
                manifest_path=context.path,
            )
        )
        return outcome

    project = data.get("project")
    poetry = _table(data, "tool", "poetry")
    uv_tool = _table(data, "tool", "uv")

    if isinstance(project, dict):
        _parse_pep621(context, index, outcome, project)
    if poetry is not None:
        _parse_poetry(context, index, outcome, poetry)
    if uv_tool is not None:
        _parse_uv_legacy(context, index, outcome, uv_tool)
    _parse_dependency_groups(context, index, outcome, data.get("dependency-groups"))
    _parse_build_system(context, index, outcome, data.get("build-system"))
    _warn_about_other_tools(context, index, outcome, data, project_declares=isinstance(project, dict))

    if not outcome.declarations and not outcome.errors:
        outcome.warnings.append(
            warn(
                WarningCode.NO_DEPENDENCIES_FOUND,
                "pyproject.toml does not contain any recognised dependency declaration",
                severity=Severity.INFO,
                manifest_path=context.path,
                sections=sorted(outcome.sections),
            )
        )
    return outcome


# ---------------------------------------------------------------------------
# PEP 621
# ---------------------------------------------------------------------------
def _parse_pep621(context: ParserContext, index: TomlLineIndex, outcome: ParseOutcome, project: dict[str, Any]) -> None:
    name = project.get("name")
    if isinstance(name, str):
        outcome.project_name = name
    version = project.get("version")
    if isinstance(version, str):
        outcome.project_version = version
    requires_python = project.get("requires-python")
    if isinstance(requires_python, str):
        outcome.requires_python = requires_python
        outcome.metadata["requires_python"] = requires_python
        outcome.count_section("project.requires-python")

    dynamic = project.get("dynamic")
    if isinstance(dynamic, list) and any(entry == "dependencies" for entry in dynamic if isinstance(entry, str)):
        outcome.warnings.append(
            warn(
                WarningCode.UNSUPPORTED_DEPENDENCY_SECTION,
                "The project declares dynamic dependencies, which live outside pyproject.toml (for example in "
                "setup.py or setup.cfg) and are not parsed by BlastRadius",
                severity=Severity.WARNING,
                manifest_path=context.path,
                line_number=index.key_line("project", "dynamic"),
                section="project.dynamic",
            )
        )

    dependencies = project.get("dependencies")
    if dependencies is not None:
        _parse_pep508_array(
            context,
            index,
            outcome,
            entries=dependencies,
            section="project.dependencies",
            scope=DependencyScope.RUNTIME,
            group=None,
        )

    optional = project.get("optional-dependencies")
    if isinstance(optional, dict):
        for extra, entries in optional.items():
            if not isinstance(entries, list):
                outcome.warnings.append(
                    warn(
                        WarningCode.MALFORMED_ENTRY,
                        "An optional dependency group is not a list and was skipped",
                        manifest_path=context.path,
                        line_number=index.key_line("project.optional-dependencies", str(extra)),
                        section=f"project.optional-dependencies.{extra}",
                    )
                )
                continue
            _parse_pep508_array(
                context,
                index,
                outcome,
                entries=entries,
                section=f"project.optional-dependencies.{extra}",
                scope=DependencyScope.OPTIONAL,
                group=str(extra),
            )
    elif optional is not None:
        outcome.warnings.append(
            warn(
                WarningCode.MALFORMED_ENTRY,
                "[project.optional-dependencies] is not a table and was skipped",
                manifest_path=context.path,
                section="project.optional-dependencies",
            )
        )


def _parse_pep508_array(
    context: ParserContext,
    index: TomlLineIndex,
    outcome: ParseOutcome,
    *,
    entries: Any,
    section: str,
    scope: DependencyScope,
    group: str | None,
) -> None:
    if not isinstance(entries, list):
        outcome.warnings.append(
            warn(
                WarningCode.MALFORMED_ENTRY,
                f"'{section}' is not a list of requirements and was skipped",
                manifest_path=context.path,
                section=section,
            )
        )
        outcome.status = ManifestParseStatus.PARTIAL
        return

    key = section.rsplit(".", 1)[-1]
    parent_section = section.rsplit(".", 1)[0] if "." in section and not section.startswith("dependency-groups") else section
    for entry in entries:
        if not isinstance(entry, str):
            outcome.warnings.append(
                warn(
                    WarningCode.MALFORMED_ENTRY,
                    f"An entry in '{section}' is not a PEP 508 string and was skipped",
                    manifest_path=context.path,
                    section=section,
                )
            )
            outcome.status = ManifestParseStatus.PARTIAL
            continue
        line_number = index.array_entry_line(parent_section, key, entry)
        _add_pep508_declaration(
            context,
            outcome,
            text=entry,
            section=section,
            scope=scope,
            group=group,
            line_number=line_number,
            evidence=f"declared in [{section}]",
        )


def _add_pep508_declaration(
    context: ParserContext,
    outcome: ParseOutcome,
    *,
    text: str,
    section: str,
    scope: DependencyScope,
    group: str | None,
    line_number: int | None,
    evidence: str,
) -> None:
    from app.ingestion.parsers.base import parse_pep508

    requirement, error = parse_pep508(text)
    if requirement is None:
        outcome.warnings.append(
            warn(
                WarningCode.MALFORMED_ENTRY,
                "A dependency entry could not be parsed as a PEP 508 requirement and was skipped",
                manifest_path=context.path,
                line_number=line_number,
                snippet=snippet_for_line(text),
                section=section,
                reason=error,
            )
        )
        outcome.status = ManifestParseStatus.PARTIAL
        return

    constraint = str(requirement.specifier) or None
    origin = RecordOrigin(
        path=context.path,
        manifest_format=FORMAT.value,
        section=section,
        line_number=line_number,
        snippet=snippet_for_line(text),
        evidence=evidence,
    )
    declaration = build_declaration(
        origin=origin,
        original_name=requirement.name,
        constraint=constraint,
        scheme=constraint_scheme(constraint),
        scope=scope,
        marker=str(requirement.marker) if requirement.marker is not None else None,
        extras=requirement.extras,
        group=group,
        source_kind=classify_source_kind(requirement.url) if requirement.url else SourceKind.REGISTRY,
        source_reference=requirement.url,
        is_direct_url_reference=requirement.url is not None,
    )
    outcome.declarations.append(declaration)
    outcome.direct_names.add(declaration.normalized_name)
    outcome.count_section(section)


# ---------------------------------------------------------------------------
# Poetry
# ---------------------------------------------------------------------------
def _parse_poetry(
    context: ParserContext,
    index: TomlLineIndex,
    outcome: ParseOutcome,
    poetry: dict[str, Any],
) -> None:
    if outcome.project_name is None:
        name = poetry.get("name")
        if isinstance(name, str):
            outcome.project_name = name
    version = poetry.get("version")
    if isinstance(version, str) and outcome.project_version is None:
        outcome.project_version = version

    if isinstance(poetry.get("dependencies"), dict):
        _parse_poetry_dependencies(
            context,
            index,
            outcome,
            dependencies=poetry["dependencies"],
            section="tool.poetry.dependencies",
            scope=DependencyScope.RUNTIME,
            group=None,
        )
    if isinstance(poetry.get("dev-dependencies"), dict):
        _parse_poetry_dependencies(
            context,
            index,
            outcome,
            dependencies=poetry["dev-dependencies"],
            section="tool.poetry.dev-dependencies",
            scope=DependencyScope.DEV,
            group="dev",
        )

    groups = poetry.get("group")
    if isinstance(groups, dict):
        for group_name, table in groups.items():
            if not isinstance(table, dict):
                continue
            section = f"tool.poetry.group.{group_name}"
            group_optional = bool(table.get("optional", False))
            scope = DependencyScope.OPTIONAL if group_optional else _classify_group(str(group_name))
            dependencies = table.get("dependencies")
            if dependencies is None:
                continue
            _parse_poetry_dependencies(
                context,
                index,
                outcome,
                dependencies=dependencies if isinstance(dependencies, dict) else {},
                section=f"{section}.dependencies",
                scope=scope,
                group=str(group_name),
            )

    extras = poetry.get("extras")
    if isinstance(extras, dict):
        # [tool.poetry.extras] only enables declarations made elsewhere.
        outcome.metadata["tool.poetry.extras"] = {
            str(extra): [str(item) for item in value if isinstance(item, str)]
            for extra, value in extras.items()
            if isinstance(value, list)
        }


def _parse_poetry_dependencies(
    context: ParserContext,
    index: TomlLineIndex,
    outcome: ParseOutcome,
    *,
    dependencies: dict[str, Any],
    section: str,
    scope: DependencyScope,
    group: str | None,
) -> None:
    for raw_name, value in dependencies.items():
        name = str(raw_name)
        if name.lower() == "python":
            if isinstance(value, str):
                # PEP 621's requires-python wins when both are present; the
                # Poetry value is always preserved in the manifest metadata.
                if outcome.requires_python is None:
                    outcome.requires_python = value
                outcome.metadata.setdefault("tool.poetry.python", value)
                outcome.count_section(f"{section}.python")
            continue
        for declaration in _build_poetry_declarations(
            context=context,
            index=index,
            outcome=outcome,
            name=name,
            value=value,
            section=section,
            scope=scope,
            group=group,
        ):
            outcome.declarations.append(declaration)
            outcome.direct_names.add(declaration.normalized_name)
            outcome.count_section(section)


def _build_poetry_declarations(
    *,
    context: ParserContext,
    index: TomlLineIndex,
    outcome: ParseOutcome,
    name: str,
    value: Any,
    section: str,
    scope: DependencyScope,
    group: str | None,
) -> list[DependencyDeclaration]:
    line_number = index.key_line(section, name)
    snippet = index.line_text(line_number) or f"{name} = {safe_text(value, 120)}"
    entries: list[Any] = value if isinstance(value, list) else [value]

    if isinstance(value, list) and len(value) > 1:
        outcome.warnings.append(
            warn(
                WarningCode.MULTIPLE_CONSTRAINTS_FOR_PACKAGE,
                "A Poetry dependency declares multiple alternative constraints; each alternative was recorded",
                severity=Severity.INFO,
                manifest_path=context.path,
                line_number=line_number,
                package=name,
                section=section,
                constraints=[safe_text(entry, 80) for entry in value],
            )
        )

    declarations: list[DependencyDeclaration] = []
    for entry in entries:
        constraint: str | None = None
        scheme = ConstraintScheme.ANY
        marker: str | None = None
        extras: tuple[str, ...] = ()
        requires_python: str | None = None
        source_kind = SourceKind.REGISTRY
        source_reference: str | None = None
        entry_scope = scope
        evidence = f"declared in [{section}]"

        if isinstance(entry, str):
            constraint = None if entry.strip() in {"", "*"} else entry.strip()
            scheme = constraint_scheme(constraint, default=ConstraintScheme.POETRY)
        elif isinstance(entry, dict):
            version = entry.get("version")
            if isinstance(version, str) and version.strip() not in {"", "*"}:
                constraint = version.strip()
                scheme = constraint_scheme(constraint, default=ConstraintScheme.POETRY)
            markers = entry.get("markers")
            if isinstance(markers, str):
                marker = markers
            python = entry.get("python")
            if isinstance(python, str):
                requires_python = python
            entry_extras = entry.get("extras")
            if isinstance(entry_extras, list):
                extras = tuple(str(item) for item in entry_extras if isinstance(item, str))
            if bool(entry.get("optional", False)):
                entry_scope = DependencyScope.OPTIONAL
            source_kind, source_reference, evidence = _poetry_source(entry, section, name, evidence)
        else:
            outcome.warnings.append(
                warn(
                    WarningCode.MALFORMED_ENTRY,
                    "A Poetry dependency entry has an unsupported shape and was skipped",
                    manifest_path=context.path,
                    line_number=line_number,
                    package=name,
                    section=section,
                )
            )
            outcome.status = ManifestParseStatus.PARTIAL
            continue

        origin = RecordOrigin(
            path=context.path,
            manifest_format=FORMAT.value,
            section=section,
            line_number=line_number,
            snippet=snippet,
            evidence=evidence,
        )
        declaration = build_declaration(
            origin=origin,
            original_name=name,
            constraint=constraint,
            scheme=scheme,
            scope=entry_scope,
            marker=marker,
            extras=extras,
            requires_python=requires_python,
            group=group,
            source_kind=source_kind,
            source_reference=source_reference,
            occurrence=len(declarations),
        )
        declarations.append(declaration)
        if constraint is None and source_reference is None and not extras and marker is None:
            outcome.warnings.append(
                warn(
                    WarningCode.UNRESOLVED_VERSION,
                    "A Poetry dependency declares neither a version constraint nor a source; no version information is "
                    "available",
                    severity=Severity.INFO,
                    manifest_path=context.path,
                    line_number=line_number,
                    package=name,
                    section=section,
                )
            )
    return declarations


def _poetry_source(entry: dict[str, Any], section: str, name: str, evidence: str) -> tuple[SourceKind, str | None, str]:
    """Classify a Poetry non-registry dependency (git/path/url)."""
    for key, kind in (("git", SourceKind.GIT), ("path", SourceKind.PATH), ("url", SourceKind.URL)):
        reference = entry.get(key)
        if not isinstance(reference, str) or not reference:
            continue
        revision = ""
        for rev_key in ("rev", "tag", "branch"):
            rev_value = entry.get(rev_key)
            if isinstance(rev_value, str) and rev_value:
                revision = f"@{rev_key}={rev_value}"
                break
        if key == "path" and bool(entry.get("develop", False)):
            kind = SourceKind.EDITABLE
        return (
            kind,
            f"{reference}{revision}",
            f"declared in [{section}] as a {key} dependency for '{name}'",
        )
    return SourceKind.REGISTRY, None, evidence


# ---------------------------------------------------------------------------
# PEP 735, uv legacy, build system, other tools
# ---------------------------------------------------------------------------
def _parse_dependency_groups(
    context: ParserContext,
    index: TomlLineIndex,
    outcome: ParseOutcome,
    groups: Any,
) -> None:
    if groups is None:
        return
    if not isinstance(groups, dict):
        outcome.warnings.append(
            warn(
                WarningCode.MALFORMED_ENTRY,
                "[dependency-groups] is not a table and was skipped",
                manifest_path=context.path,
                section="dependency-groups",
            )
        )
        outcome.status = ManifestParseStatus.PARTIAL
        return

    expanded_groups: set[str] = set()
    for raw_group, entries in groups.items():
        group_name = str(raw_group)
        section = f"dependency-groups.{group_name}"
        if not isinstance(entries, list):
            outcome.warnings.append(
                warn(
                    WarningCode.MALFORMED_ENTRY,
                    "A dependency group is not a list and was skipped",
                    manifest_path=context.path,
                    section=section,
                )
            )
            outcome.status = ManifestParseStatus.PARTIAL
            continue
        outcome.metadata.setdefault("dependency_groups", [])
        groups_meta = outcome.metadata["dependency_groups"]
        if isinstance(groups_meta, list):
            groups_meta.append(group_name)
        _expand_dependency_group(
            context,
            index,
            outcome,
            group_name=group_name,
            entries=entries,
            all_groups=groups,
            depth=0,
            chain=(group_name,),
            expanded=expanded_groups,
        )


def _expand_dependency_group(
    context: ParserContext,
    index: TomlLineIndex,
    outcome: ParseOutcome,
    *,
    group_name: str,
    entries: list[Any],
    all_groups: dict[str, Any],
    depth: int,
    chain: tuple[str, ...],
    expanded: set[str],
) -> None:
    if depth > context.settings.max_dependency_group_depth:
        outcome.warnings.append(
            warn(
                WarningCode.INCLUDE_DEPTH_EXCEEDED,
                "The dependency group include depth limit was reached; nested groups were not expanded",
                manifest_path=context.path,
                section=f"dependency-groups.{group_name}",
                max_depth=context.settings.max_dependency_group_depth,
            )
        )
        outcome.status = ManifestParseStatus.PARTIAL
        return

    # A group reachable both directly and through ``include-group`` is
    # expanded only once so its requirements are not declared twice.
    if group_name in expanded:
        return
    expanded.add(group_name)

    scope = _classify_group(group_name)
    for entry in entries:
        if isinstance(entry, str):
            _add_pep508_declaration(
                context,
                outcome,
                text=entry,
                section=f"dependency-groups.{group_name}",
                scope=scope,
                group=group_name,
                line_number=index.array_entry_line("dependency-groups", group_name, entry),
                evidence=f"declared in PEP 735 dependency group '{group_name}'",
            )
            continue

        include = entry.get("include-group") if isinstance(entry, dict) else None
        if isinstance(include, str):
            included = all_groups.get(include)
            if included is None:
                outcome.warnings.append(
                    warn(
                        WarningCode.DEPENDENCY_GROUP_INCLUDE_MISSING,
                        "A dependency group includes another group that does not exist",
                        manifest_path=context.path,
                        section=f"dependency-groups.{group_name}",
                        included_group=include,
                    )
                )
                outcome.status = ManifestParseStatus.PARTIAL
                continue
            if include in chain:
                outcome.warnings.append(
                    warn(
                        WarningCode.DEPENDENCY_GROUP_CYCLE,
                        "A dependency group include cycle was detected and not followed",
                        manifest_path=context.path,
                        section=f"dependency-groups.{group_name}",
                        included_group=include,
                    )
                )
                outcome.status = ManifestParseStatus.PARTIAL
                continue
            if not isinstance(included, list):
                continue
            if include in expanded:
                outcome.warnings.append(
                    warn(
                        WarningCode.DEPENDENCY_GROUP_INCLUDE_RESOLVED,
                        "A dependency group include points at a group that was already expanded elsewhere; its "
                        "requirements were not declared twice",
                        severity=Severity.INFO,
                        manifest_path=context.path,
                        section=f"dependency-groups.{group_name}",
                        included_group=include,
                    )
                )
                continue
            outcome.warnings.append(
                warn(
                    WarningCode.DEPENDENCY_GROUP_INCLUDE_RESOLVED,
                    "A dependency group include was expanded",
                    severity=Severity.INFO,
                    manifest_path=context.path,
                    section=f"dependency-groups.{group_name}",
                    included_group=include,
                )
            )
            _expand_dependency_group(
                context,
                index,
                outcome,
                group_name=include,
                entries=included,
                all_groups=all_groups,
                depth=depth + 1,
                chain=(*chain, include),
                expanded=expanded,
            )
            continue

        outcome.warnings.append(
            warn(
                WarningCode.MALFORMED_ENTRY,
                "A dependency group entry is neither a requirement nor an include-group directive",
                manifest_path=context.path,
                section=f"dependency-groups.{group_name}",
                snippet=safe_text(entry, 80),
            )
        )
        outcome.status = ManifestParseStatus.PARTIAL


def _parse_uv_legacy(
    context: ParserContext,
    index: TomlLineIndex,
    outcome: ParseOutcome,
    uv_tool: dict[str, Any],
) -> None:
    dev_dependencies = uv_tool.get("dev-dependencies")
    if dev_dependencies is None:
        return
    outcome.warnings.append(
        warn(
            WarningCode.UNSUPPORTED_DEPENDENCY_SECTION,
            "[tool.uv].dev-dependencies is a deprecated uv layout; it was parsed as development dependencies",
            severity=Severity.INFO,
            manifest_path=context.path,
            line_number=index.key_line("tool.uv", "dev-dependencies"),
            section="tool.uv.dev-dependencies",
        )
    )
    _parse_pep508_array(
        context,
        index,
        outcome,
        entries=dev_dependencies,
        section="tool.uv.dev-dependencies",
        scope=DependencyScope.DEV,
        group="dev",
    )


def _parse_build_system(
    context: ParserContext,
    index: TomlLineIndex,
    outcome: ParseOutcome,
    build_system: Any,
) -> None:
    if not isinstance(build_system, dict):
        return
    requires = build_system.get("requires")
    if requires is None:
        return
    _parse_pep508_array(
        context,
        index,
        outcome,
        entries=requires,
        section="build-system.requires",
        scope=DependencyScope.BUILD,
        group="build-system",
    )


def _warn_about_other_tools(
    context: ParserContext,
    index: TomlLineIndex,
    outcome: ParseOutcome,
    data: dict[str, Any],
    *,
    project_declares: bool,
) -> None:
    tool = data.get("tool")
    if isinstance(tool, dict):
        for tool_name, section in (("pdm", "tool.pdm.dev-dependencies"),):
            if tool_name in tool:
                outcome.warnings.append(
                    warn(
                        WarningCode.UNSUPPORTED_DEPENDENCY_SECTION,
                        f"[{section}] dependency declarations are recognised but not parsed by BlastRadius",
                        manifest_path=context.path,
                        line_number=index.section_line(section) or index.section_line(f"tool.{tool_name}"),
                        section=section,
                    )
                )
        poetry = tool.get("poetry")
        if isinstance(poetry, dict) and project_declares and isinstance(poetry.get("dependencies"), dict):
            outcome.warnings.append(
                warn(
                    WarningCode.MULTIPLE_CONSTRAINTS_FOR_PACKAGE,
                    "Both [project] and [tool.poetry] declare dependencies; both were parsed and may disagree",
                    severity=Severity.INFO,
                    manifest_path=context.path,
                    line_number=index.section_line("tool.poetry.dependencies"),
                    sections=["project.dependencies", "tool.poetry.dependencies"],
                )
            )

    if isinstance(data.get("tool"), dict) and "poetry" in data["tool"]:
        outcome.metadata["packaging_backend"] = "poetry"
    elif isinstance(data.get("build-system"), dict):
        backend = data["build-system"].get("build-backend")
        if isinstance(backend, str):
            outcome.metadata["packaging_backend"] = backend


def _classify_group(group_name: str) -> DependencyScope:
    """Classify a dependency group as development or optional (non-runtime)."""
    if group_name.lower() in _DEV_GROUP_HINTS:
        return DependencyScope.DEV
    return DependencyScope.OPTIONAL


def _table(data: dict[str, Any], *path: str) -> dict[str, Any] | None:
    current: Any = data
    for key in path:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current if isinstance(current, dict) else None


def _line_from_message(message: str) -> int | None:
    match = _LINE_NUMBER_RE.search(message)
    return int(match.group(1)) if match else None


__all__ = ["FORMAT", "TomlLineIndex", "parse_pyproject"]
