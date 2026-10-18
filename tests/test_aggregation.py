"""Aggregation tests: resolution, directness, conflicts, coverage, caps.

Aggregation is where BlastRadius reasons across manifests.  The fixtures here
are small but each one exercises exactly one rule, so a regression points at a
single decision: which lockfile resolves a declaration, what makes a package
direct, and which disagreements are reported instead of silently resolved.
"""

from __future__ import annotations

from pathlib import Path

from app.core.config import Settings
from app.ingestion.aggregation import AggregatedDependencies, aggregate_dependencies
from app.ingestion.discovery import discover_repository_files
from app.ingestion.parsers import MappingFileResolver, ParserContext, get_parser
from app.models.common import (
    DependencyRelation,
    DependencyScope,
    ManifestFormat,
    ManifestParseStatus,
    Severity,
    SupportLevel,
    WarningCode,
)
from tests.support import make_settings, write_tree

LOCK_FAMILY = {
    "requirements.txt": "requests>=2.31,<3\nclick==8.1.7\n",
    "pyproject.toml": (
        "[project]\n"
        'name = "agg"\n'
        'version = "0.1.0"\n'
        "dependencies = [\n"
        '  "requests>=2.31,<3",\n'
        "]\n"
        "\n"
        "[dependency-groups]\n"
        'dev = ["pytest>=8"]\n'
    ),
    "poetry.lock": (
        "[[package]]\n"
        'name = "requests"\n'
        'version = "2.31.0"\n'
        "files = []\n"
        "\n"
        "[package.dependencies]\n"
        'certifi = ">=2017.4.17"\n'
        "\n"
        "[[package]]\n"
        'name = "certifi"\n'
        'version = "2024.2.2"\n'
        "files = []\n"
        "\n"
        "[[package]]\n"
        'name = "click"\n'
        'version = "8.1.7"\n'
        "files = []\n"
        "\n"
        "[[package]]\n"
        'name = "pytest"\n'
        'version = "8.2.0"\n'
        "files = []\n"
        "\n"
        "[package.dependencies]\n"
        'pluggy = ">=1.5,<2"\n'
        "\n"
        "[[package]]\n"
        'name = "pluggy"\n'
        'version = "1.5.0"\n'
        "files = []\n"
    ),
}


def run_aggregation(
    tmp_path: Path,
    files: dict[str, str | bytes],
    *,
    settings: Settings | None = None,
    repository_id: str = "github.com/example/aggregate",
    commit_sha: str = "f" * 40,
) -> AggregatedDependencies:
    """Run discovery + parsing + aggregation exactly like the service does."""
    settings = settings or make_settings()
    root = tmp_path / "repo"
    write_tree(root, files)
    discovery = discover_repository_files(root, settings)
    resolver = MappingFileResolver(
        {manifest.path: manifest.text for manifest in discovery.manifests if manifest.text is not None}
    )
    known_files = frozenset(source.path for source in discovery.files)
    outcomes = {}
    for manifest in discovery.manifests:
        if manifest.format is None or manifest.text is None:
            continue
        context = ParserContext(
            path=manifest.path,
            text=manifest.text,
            settings=settings,
            resolver=resolver,
            repository_files=known_files,
        )
        outcomes[manifest.path] = get_parser(manifest.format)(context)
    return aggregate_dependencies(
        repository_id=repository_id,
        commit_sha=commit_sha,
        discovery=discovery,
        outcomes=outcomes,
        settings=settings,
    )


def warning_codes(result: AggregatedDependencies) -> list[str]:
    return [warning.code.value for warning in result.warnings]


def warnings_of(result: AggregatedDependencies, code: WarningCode) -> list:
    return [warning for warning in result.warnings if warning.code is code]


def declaration_for(result: AggregatedDependencies, path: str, name: str):
    matches = [
        declaration
        for declaration in result.declarations
        if declaration.provenance.manifest_path == path and declaration.normalized_name == name
    ]
    assert matches, f"no declaration {name} from {path}"
    return matches[0]


def package_for(result: AggregatedDependencies, name: str):
    matches = [package for package in result.resolved_packages if package.normalized_name == name]
    assert matches, f"no resolved package {name}"
    return matches[0]


# ---------------------------------------------------------------------------
# Resolution
# ---------------------------------------------------------------------------
def test_declarations_are_resolved_from_the_directorys_lockfile(tmp_path: Path) -> None:
    result = run_aggregation(tmp_path, LOCK_FAMILY)

    requests_decl = declaration_for(result, "requirements.txt", "requests")
    assert requests_decl.resolved_version == "2.31.0"
    assert requests_decl.resolved_from == "poetry.lock"
    assert requests_decl.is_exact_pin is False

    click = declaration_for(result, "requirements.txt", "click")
    assert click.is_exact_pin is True
    assert click.version_constraint == "==8.1.7"
    assert click.resolved_version == "8.1.7"

    # The pyproject declaration agrees with the lock as well.
    assert declaration_for(result, "pyproject.toml", "requests").resolved_version == "2.31.0"
    pytest_decl = declaration_for(result, "pyproject.toml", "pytest")
    assert pytest_decl.scope is DependencyScope.DEV
    assert pytest_decl.resolved_version == "8.2.0"

    assert result.direct_declarations == 4
    assert result.dev_declarations == 1
    assert result.optional_declarations == 0
    assert warnings_of(result, WarningCode.PIN_RESOLVED_MISMATCH) == []


def test_declarations_without_a_nearby_lockfile_stay_unresolved(tmp_path: Path) -> None:
    result = run_aggregation(
        tmp_path,
        {
            "requirements.txt": "requests>=2.0\n",
            "sub/poetry.lock": (
                "[[package]]\n"
                'name = "requests"\n'
                'version = "2.31.0"\n'
                "files = []\n"
            ),
        },
    )
    declaration = declaration_for(result, "requirements.txt", "requests")
    assert declaration.resolved_version is None
    assert declaration.resolved_from is None

    assert warning_codes(result).count(WarningCode.LOCKFILE_WITHOUT_MANIFEST.value) == 1
    directness = warnings_of(result, WarningCode.DIRECTNESS_UNKNOWN)
    assert len(directness) == 1
    assert directness[0].severity is Severity.WARNING
    assert package_for(result, "requests").relation is DependencyRelation.UNKNOWN
    assert result.unknown_relation_packages == 1


def test_conflicting_lockfiles_do_not_produce_a_resolved_version(tmp_path: Path) -> None:
    result = run_aggregation(
        tmp_path,
        {
            "requirements.txt": "requests>=2.0\n",
            "poetry.lock": (
                "[[package]]\n"
                'name = "requests"\n'
                'version = "2.31.0"\n'
                "files = []\n"
            ),
            "uv.lock": (
                "version = 1\n"
                "[[package]]\n"
                'name = "requests"\n'
                'version = "2.32.3"\n'
                'source = { registry = "https://pypi.org/simple" }\n'
            ),
        },
    )
    declaration = declaration_for(result, "requirements.txt", "requests")
    assert declaration.resolved_version is None

    conflict = warnings_of(result, WarningCode.CONFLICTING_RESOLVED_VERSIONS)
    assert any(w.severity is Severity.WARNING and w.details["package"] == "requests" for w in conflict)
    assert result.conflicting_packages == {"requests"}


def test_single_lockfile_with_multiple_versions_is_reported_not_guessed(tmp_path: Path) -> None:
    result = run_aggregation(
        tmp_path,
        {
            "requirements.txt": "requests>=2.0\ncertifi\n",
            "poetry.lock": (
                "[[package]]\n"
                'name = "requests"\n'
                'version = "2.31.0"\n'
                "files = []\n"
                'markers = "python_version < \\"3.12\\""\n'
                "\n"
                "[[package]]\n"
                'name = "requests"\n'
                'version = "2.32.0"\n'
                "files = []\n"
                'markers = "python_version >= \\"3.12\\""\n'
                "\n"
                "[package.dependencies]\n"
                'certifi = ">=2017"\n'
                "\n"
                "[[package]]\n"
                'name = "certifi"\n'
                'version = "2024.2.2"\n'
                "files = []\n"
                "\n"
                "[[package]]\n"
                'name = "certifi"\n'
                'version = "2024.1.1"\n'
                "files = []\n"
            ),
        },
    )
    assert declaration_for(result, "requirements.txt", "requests").resolved_version is None

    ambiguous_edge = next(edge for edge in result.edges if edge.to_name == "certifi")
    assert ambiguous_edge.to_resolved_version is None

    conflicts = warnings_of(result, WarningCode.CONFLICTING_RESOLVED_VERSIONS)
    by_package = {w.details["package"]: w for w in conflicts}
    assert by_package["requests"].severity is Severity.INFO
    assert by_package["requests"].details["resolutions"] == {"poetry.lock": ["2.31.0", "2.32.0"]}
    assert by_package["certifi"].severity is Severity.INFO
    # A conditional resolution is never a "conflicting package".
    assert result.conflicting_packages == set()


def test_edges_get_resolved_versions_from_their_own_lockfile(tmp_path: Path) -> None:
    result = run_aggregation(tmp_path, LOCK_FAMILY)
    certifi_edge = next(edge for edge in result.edges if edge.to_name == "certifi")
    assert certifi_edge.to_version_constraint == ">=2017.4.17"
    assert certifi_edge.to_resolved_version == "2024.2.2"

    pluggy_edge = next(edge for edge in result.edges if edge.to_name == "pluggy")
    assert pluggy_edge.to_resolved_version == "1.5.0"


# ---------------------------------------------------------------------------
# Directness
# ---------------------------------------------------------------------------
def test_directness_is_derived_from_declarations_and_lock_edges(tmp_path: Path) -> None:
    result = run_aggregation(tmp_path, LOCK_FAMILY)
    assert package_for(result, "requests").relation is DependencyRelation.DIRECT
    assert package_for(result, "click").relation is DependencyRelation.DIRECT
    assert package_for(result, "pytest").relation is DependencyRelation.DIRECT
    assert package_for(result, "certifi").relation is DependencyRelation.TRANSITIVE
    assert package_for(result, "pluggy").relation is DependencyRelation.TRANSITIVE
    assert result.transitive_packages == 2
    assert result.unknown_relation_packages == 0
    assert warnings_of(result, WarningCode.DIRECTNESS_UNKNOWN) == []


def test_unreachable_packages_are_reported_unknown_not_transitive(tmp_path: Path) -> None:
    result = run_aggregation(
        tmp_path,
        {
            "requirements.txt": "requests>=2.0\n",
            "poetry.lock": (
                "[[package]]\n"
                'name = "requests"\n'
                'version = "2.31.0"\n'
                "files = []\n"
                "\n"
                "[[package]]\n"
                'name = "leftover"\n'
                'version = "9.9.9"\n'
                "files = []\n"
            ),
        },
    )
    assert package_for(result, "leftover").relation is DependencyRelation.UNKNOWN
    assert result.transitive_packages == 0
    assert result.unknown_relation_packages == 1
    directness = warnings_of(result, WarningCode.DIRECTNESS_UNKNOWN)
    assert directness[0].severity is Severity.INFO
    assert directness[0].details["packages"] == ["leftover"]


def test_uv_lock_workspace_root_establishes_directness(tmp_path: Path) -> None:
    result = run_aggregation(
        tmp_path,
        {
            "uv.lock": (
                "version = 1\n"
                "\n"
                "[[package]]\n"
                'name = "proj"\n'
                'version = "0.1.0"\n'
                'source = { editable = "." }\n'
                "dependencies = [\n"
                '    { name = "requests" },\n'
                "]\n"
                "\n"
                "[[package]]\n"
                'name = "requests"\n'
                'version = "2.32.3"\n'
                'source = { registry = "https://pypi.org/simple" }\n'
                "dependencies = [\n"
                '    { name = "certifi" },\n'
                "]\n"
                "\n"
                "[[package]]\n"
                'name = "certifi"\n'
                'version = "2024.2.2"\n'
                'source = { registry = "https://pypi.org/simple" }\n'
            ),
        },
    )
    proj = package_for(result, "proj")
    assert proj.is_root_project is True
    assert proj.relation is DependencyRelation.DIRECT
    assert package_for(result, "requests").relation is DependencyRelation.DIRECT
    assert package_for(result, "certifi").relation is DependencyRelation.TRANSITIVE
    # No companion pyproject.toml exists, but the workspace root is enough.
    assert warnings_of(result, WarningCode.DIRECTNESS_UNKNOWN) == []
    record = next(record for record in result.manifests if record.path == "uv.lock")
    assert record.companion_manifest is None
    assert record.is_lockfile is True


# ---------------------------------------------------------------------------
# Conflicts
# ---------------------------------------------------------------------------
def test_conflicting_exact_pins_are_reported(tmp_path: Path) -> None:
    result = run_aggregation(
        tmp_path,
        {
            "requirements.txt": "click==8.1.7\n",
            "requirements-dev.txt": "click==8.1.6\n",
        },
    )
    conflicts = warnings_of(result, WarningCode.CONFLICTING_EXACT_PINS)
    assert len(conflicts) == 1
    assert conflicts[0].severity is Severity.WARNING
    assert conflicts[0].details["package"] == "click"
    assert set(conflicts[0].details["declarations"]) == {"==8.1.6", "==8.1.7"}
    assert result.conflicting_packages == {"click"}


def test_pin_resolved_mismatch_is_reported(tmp_path: Path) -> None:
    result = run_aggregation(
        tmp_path,
        {
            "requirements.txt": "click==8.1.6\n",
            "poetry.lock": (
                "[[package]]\n"
                'name = "click"\n'
                'version = "8.1.7"\n'
                "files = []\n"
            ),
        },
    )
    mismatch = warnings_of(result, WarningCode.PIN_RESOLVED_MISMATCH)
    assert len(mismatch) == 1
    assert mismatch[0].severity is Severity.WARNING
    assert mismatch[0].details["pinned"] == "==8.1.6"
    assert mismatch[0].details["resolved"] == "8.1.7"
    assert mismatch[0].details["resolved_from"] == "poetry.lock"
    assert result.conflicting_packages == {"click"}

    declaration = declaration_for(result, "requirements.txt", "click")
    assert declaration.resolved_version == "8.1.7"  # the lock is still reported


def test_different_constraints_in_one_directory_are_reported(tmp_path: Path) -> None:
    result = run_aggregation(
        tmp_path,
        {
            "requirements.txt": "requests>=2.0\n",
            "pyproject.toml": (
                "[project]\n"
                'name = "x"\n'
                'version = "0.1.0"\n'
                'dependencies = ["requests>=2.31,<3"]\n'
            ),
        },
    )
    constrained = warnings_of(result, WarningCode.MULTIPLE_CONSTRAINTS_FOR_PACKAGE)
    assert len(constrained) == 1
    assert constrained[0].severity is Severity.INFO
    assert constrained[0].details["package"] == "requests"
    assert constrained[0].details["directory"] == "."
    # PEP 440 constraints are canonicalised by ``packaging`` (e.g. "<3,>=2.31").
    assert set(constrained[0].details["constraints"]) == {">=2.0", "<3,>=2.31"}


def test_constraints_in_different_directories_are_not_a_conflict(tmp_path: Path) -> None:
    result = run_aggregation(
        tmp_path,
        {
            "requirements.txt": "requests>=2.0\n",
            "sub/requirements.txt": "requests>=2.31\n",
        },
    )
    assert warnings_of(result, WarningCode.MULTIPLE_CONSTRAINTS_FOR_PACKAGE) == []
    assert result.conflicting_packages == set()


def test_none_and_string_markers_do_not_break_conflict_detection(tmp_path: Path) -> None:
    """Regression: sorting (name, marker[, directory]) keys crashed on None.

    Live trigger: python-poetry/poetry@1.1.0 declares the same package both
    with and without an environment marker, so ``sorted()`` compared ``None``
    with a marker string and the ingest endpoint returned a bare HTTP 500.
    """
    result = run_aggregation(
        tmp_path,
        {
            "requirements.txt": "click==8.1.7\nrequests>=2.0\n",
            "pyproject.toml": (
                "[project]\n"
                'name = "x"\n'
                'version = "0.1.0"\n'
                "dependencies = [\n"
                '    "click==8.1.8",\n'
                '    "click==8.1.6; python_version < \'3.9\'",\n'
                '    "requests>=2.31; python_version < \'3.9\'",\n'
                "]\n"
            ),
        },
    )
    pins = warnings_of(result, WarningCode.CONFLICTING_EXACT_PINS)
    assert len(pins) == 1
    assert pins[0].details["package"] == "click"
    assert pins[0].details["marker"] is None
    assert set(pins[0].details["declarations"]) == {"==8.1.7", "==8.1.8"}
    assert result.conflicting_packages == {"click"}
    # The marked/unmarked constraint keys sort cleanly but are not one conflict.
    assert warnings_of(result, WarningCode.MULTIPLE_CONSTRAINTS_FOR_PACKAGE) == []


def test_multiple_lockfiles_are_announced(tmp_path: Path) -> None:
    result = run_aggregation(
        tmp_path,
        {
            "poetry.lock": (
                "[[package]]\n"
                'name = "requests"\n'
                'version = "2.31.0"\n'
                "files = []\n"
            ),
            "uv.lock": (
                "version = 1\n"
                "[[package]]\n"
                'name = "proj"\n'
                'version = "0.1.0"\n'
                'source = { virtual = "." }\n'
            ),
        },
    )
    multiple = warnings_of(result, WarningCode.MULTIPLE_LOCKFILES)
    assert len(multiple) == 1
    assert multiple[0].severity is Severity.INFO
    assert multiple[0].details["lockfiles"] == ["poetry.lock", "uv.lock"]
    # No package is resolved by both locks here.
    assert result.conflicting_packages == set()
    assert len(warnings_of(result, WarningCode.CONFLICTING_RESOLVED_VERSIONS)) == 0


def test_conflict_warnings_are_capped_and_reported_as_truncated(tmp_path: Path) -> None:
    result = run_aggregation(
        tmp_path,
        {
            "requirements.txt": "alpha>=1\nbeta>=1\n",
            "requirements-dev.txt": "alpha>=2\nbeta>=2\n",
        },
        settings=make_settings(max_conflict_warnings=1),
    )
    constrained = warnings_of(result, WarningCode.MULTIPLE_CONSTRAINTS_FOR_PACKAGE)
    assert len(constrained) == 1
    assert result.truncated_warning_count == 1
    truncated = warnings_of(result, WarningCode.WARNINGS_TRUNCATED)
    assert len(truncated) == 1
    assert truncated[0].details["suppressed"] == 1
    assert truncated[0].details["limit"] == 1


# ---------------------------------------------------------------------------
# Caps and records
# ---------------------------------------------------------------------------
def test_declaration_limit_is_enforced_with_a_warning(tmp_path: Path) -> None:
    result = run_aggregation(
        tmp_path,
        {"requirements.txt": "alpha\nbeta\ngamma\n"},
        settings=make_settings(max_dependencies=2),
    )
    assert len(result.declarations) == 2
    limit = warnings_of(result, WarningCode.DEPENDENCY_LIMIT_REACHED)
    assert len(limit) == 1
    assert limit[0].details["limit"] == 2


def test_manifest_records_describe_what_was_parsed(tmp_path: Path) -> None:
    result = run_aggregation(tmp_path, LOCK_FAMILY)
    records = {record.path: record for record in result.manifests}
    assert set(records) == {"requirements.txt", "pyproject.toml", "poetry.lock"}

    lock_record = records["poetry.lock"]
    assert lock_record.status is ManifestParseStatus.PARSED
    assert lock_record.is_lockfile is True
    assert lock_record.companion_manifest == "pyproject.toml"
    assert lock_record.resolved_count == 5
    assert lock_record.edge_count == 2
    assert lock_record.declaration_count == 0

    requirements_record = records["requirements.txt"]
    assert requirements_record.declaration_count == 2
    assert requirements_record.resolved_count == 0
    assert requirements_record.sha256 is not None

    # Records and dependency facts are stamped with the repository and commit.
    assert all(record.repository_id == "github.com/example/aggregate" for record in result.manifests)
    assert all(declaration.commit_sha == "f" * 40 for declaration in result.declarations)
    assert all(package.commit_sha == "f" * 40 for package in result.resolved_packages)
    assert all(edge.repository_id == "github.com/example/aggregate" for edge in result.edges)


def test_unsupported_and_unparsed_manifests_become_skipped_records(tmp_path: Path) -> None:
    result = run_aggregation(
        tmp_path,
        {
            "Pipfile": '[packages]\nrequests = "*"\n',
            "legacy/setup.py": "from setuptools import setup\nsetup()\n",
            "requirements.txt": "requests>=2.31,<3\n" + "# padding\n" * 40,
        },
        settings=make_settings(max_manifest_bytes=32),
    )
    records = {record.path: record for record in result.manifests}

    pipfile = records["Pipfile"]
    assert pipfile.status is ManifestParseStatus.SKIPPED
    assert pipfile.support_level is SupportLevel.UNSUPPORTED
    assert pipfile.skipped_reason == "unsupported_format"

    setup = records["legacy/setup.py"]
    assert setup.status is ManifestParseStatus.SKIPPED
    assert setup.support_level is SupportLevel.UNSUPPORTED

    oversized = records["requirements.txt"]
    assert oversized.status is ManifestParseStatus.SKIPPED
    assert oversized.skipped_reason == "too_large"
    assert oversized.format is ManifestFormat.REQUIREMENTS_TXT


def test_coverage_reports_detected_parsed_failed_and_unsupported(tmp_path: Path) -> None:
    result = run_aggregation(
        tmp_path,
        {
            "requirements.txt": "requests>=2.31,<3\n",
            "poetry.lock": "[[package]\nname = broken\n",
            "Pipfile": '[packages]\nrequests = "*"\n',
            "legacy/setup.py": "from setuptools import setup\nsetup()\n",
        },
    )
    coverage = {entry.format: entry for entry in result.coverage}

    requirements = coverage["requirements.txt"]
    assert requirements.support_level is SupportLevel.SUPPORTED
    assert (requirements.detected_files, requirements.parsed_files, requirements.failed_files) == (1, 1, 0)

    poetry = coverage["poetry.lock"]
    assert (poetry.detected_files, poetry.parsed_files, poetry.failed_files) == (1, 0, 1)

    for absent in ("pyproject.toml", "uv.lock"):
        assert coverage[absent].detected_files == 0

    pipfile = coverage["Pipfile"]
    assert pipfile.support_level is SupportLevel.UNSUPPORTED
    assert pipfile.detected_files == 1
    setup = coverage["setup.py"]
    assert setup.support_level is SupportLevel.UNSUPPORTED

    failed_records = [record for record in result.manifests if record.status is ManifestParseStatus.FAILED]
    assert [record.path for record in failed_records] == ["poetry.lock"]
    assert failed_records[0].error_codes == ("manifest_parse_error",)
    assert len(result.errors) == 1
