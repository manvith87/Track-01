"""``uv.lock`` parser tests.

uv's lock file is the only supported format that proves directness (via the
workspace root package and its ``requires-dist`` metadata) and records resolved
versions on the edges themselves.  The tests pin those guarantees down.
"""

from __future__ import annotations

from app.core.config import Settings
from app.ingestion.parsers import MappingFileResolver, ParserContext, parse_uv_lock
from app.ingestion.parsers.base import ParseOutcome
from app.models.common import (
    DependencyRelation,
    ManifestParseStatus,
    Severity,
    SourceKind,
    WarningCode,
)
from tests.support import make_settings

UV_LOCK = """version = 1
revision = 3
requires-python = ">=3.11"
resolution-markers = ["python_full_version < '3.12'", "python_full_version >= '3.12'"]

[[package]]
name = "demo"
version = "0.1.0"
source = { virtual = "." }
dependencies = [
    { name = "requests" },
]

[package.optional-dependencies]
socks = [
    { name = "pysocks", specifier = ">=1.5.6" },
]

[package.dev-dependencies]
dev = [
    { name = "pytest", specifier = ">=8.0" },
]

[package.metadata]
requires-dist = [
    { name = "requests", specifier = ">=2.31,<3" },
    { name = "pysocks", marker = "extra == 'socks'", specifier = ">=1.5.6" },
]
requires-dev = { dev = [{ name = "pytest", specifier = ">=8.0" }] }

[[package]]
name = "requests"
version = "2.32.3"
source = { registry = "https://pypi.org/simple" }
dependencies = [
    { name = "certifi" },
    { name = "urllib3", specifier = ">=1.21.1,<3", version = "2.2.2" },
]

[[package]]
name = "localdep"
version = "0.0.0"
source = { editable = "../localdep" }

[[package]]
name = "gitdep"
version = "1.2.0"
source = { git = "https://github.com/foo/bar?rev=main#abc" }

[[package]]
name = "urldep"
version = "3.0.0"
source = { url = "https://example.com/urldep-3.0.0.tar.gz" }

[[package]]
name = "pysocks"
version = "1.7.1"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "pytest"
version = "8.3.2"
source = { registry = "https://pypi.org/simple" }
"""


def parse(text: str, *, settings: Settings | None = None) -> ParseOutcome:
    context = ParserContext(
        path="uv.lock",
        text=text,
        settings=settings or make_settings(),
        resolver=MappingFileResolver({}),
    )
    return parse_uv_lock(context)


def codes(outcome: ParseOutcome) -> set[str]:
    return {warning.code.value for warning in outcome.warnings}


def warning(outcome: ParseOutcome, code: WarningCode):
    matches = [w for w in outcome.warnings if w.code is code]
    assert matches, f"expected warning {code} in {sorted(codes(outcome))}"
    return matches[0]


def packages(outcome: ParseOutcome) -> dict[str, object]:
    return {package.normalized_name: package for package in outcome.resolved_packages}


def edges(outcome: ParseOutcome, *, from_name: str, to_name: str):
    return [edge for edge in outcome.edges if edge.from_name == from_name and edge.to_name == to_name]


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------
def test_lock_metadata_is_recorded() -> None:
    outcome = parse(UV_LOCK)
    assert outcome.status is ManifestParseStatus.PARSED
    assert outcome.requires_python == ">=3.11"
    assert outcome.metadata["lock_version"] == 1
    assert outcome.metadata["revision"] == 3
    assert outcome.metadata["resolution_markers"] == [
        "python_full_version < '3.12'",
        "python_full_version >= '3.12'",
    ]
    assert outcome.sections["packages"] == 7
    assert outcome.sections["root_packages"] == 1


def test_workspace_root_is_identified_and_classified_direct() -> None:
    outcome = parse(UV_LOCK)
    root = packages(outcome)["demo"]
    assert root.is_root_project is True
    assert root.relation is DependencyRelation.DIRECT
    assert root.source_kind is SourceKind.PATH
    assert root.source_reference == "."
    assert root.dependency_count == 3


def test_all_packages_and_sources_are_recorded() -> None:
    outcome = parse(UV_LOCK)
    by_name = packages(outcome)
    assert list(by_name) == ["demo", "requests", "localdep", "gitdep", "urldep", "pysocks", "pytest"]
    assert by_name["requests"].relation is DependencyRelation.UNKNOWN  # directness is an aggregation concern
    assert by_name["localdep"].source_kind is SourceKind.EDITABLE
    assert by_name["localdep"].source_reference == "../localdep"
    assert by_name["localdep"].is_root_project is False
    assert by_name["gitdep"].source_kind is SourceKind.GIT
    assert by_name["urldep"].source_kind is SourceKind.URL
    assert by_name["pytest"].source_kind is SourceKind.REGISTRY
    assert by_name["pytest"].source_reference == "https://pypi.org/simple"


def test_line_numbers_point_at_package_headers() -> None:
    outcome = parse(UV_LOCK)
    lines = {package.normalized_name: package.provenance.line_number for package in outcome.resolved_packages}
    assert lines == {
        "demo": 6,
        "requests": 31,
        "localdep": 40,
        "gitdep": 45,
        "urldep": 50,
        "pysocks": 55,
        "pytest": 60,
    }


def test_root_declares_direct_names() -> None:
    outcome = parse(UV_LOCK)
    assert outcome.lock_root_names == {"requests", "pysocks", "pytest"}
    assert outcome.sections["metadata.requires-dist"] == 2
    assert outcome.sections["metadata.requires-dev"] == 1


def test_edges_keep_constraints_and_resolved_versions_separate() -> None:
    outcome = parse(UV_LOCK)
    assert len(outcome.edges) == 5

    edge = edges(outcome, from_name="requests", to_name="urllib3")[0]
    assert edge.from_version == "2.32.3"
    assert edge.to_version_constraint == ">=1.21.1,<3"
    assert edge.to_resolved_version == "2.2.2"

    certifi = edges(outcome, from_name="requests", to_name="certifi")[0]
    assert certifi.to_version_constraint is None
    assert certifi.to_resolved_version is None


def test_optional_and_dev_edges_are_tagged_with_their_group() -> None:
    outcome = parse(UV_LOCK)

    optional = edges(outcome, from_name="demo", to_name="pysocks")[0]
    assert optional.optional is True
    assert optional.dev is False
    assert optional.to_version_constraint == ">=1.5.6"
    assert optional.provenance.section == "package.optional-dependencies.socks"

    dev = edges(outcome, from_name="demo", to_name="pytest")[0]
    assert dev.dev is True
    assert dev.optional is False
    assert dev.provenance.section == "package.dev-dependencies.dev"

    runtime = edges(outcome, from_name="demo", to_name="requests")[0]
    assert runtime.optional is False
    assert runtime.dev is False
    assert runtime.to_version_constraint is None
    assert runtime.provenance.section == "package.dependencies"


# ---------------------------------------------------------------------------
# Degraded and malformed locks
# ---------------------------------------------------------------------------
def test_lock_without_a_root_package_reports_directness_unknown() -> None:
    outcome = parse(
        "version = 1\n"
        "[[package]]\n"
        'name = "a"\n'
        'version = "1.0.0"\n'
        'source = { registry = "https://pypi.org/simple" }\n'
    )
    assert outcome.status is ManifestParseStatus.PARSED
    directness = warning(outcome, WarningCode.DIRECTNESS_UNKNOWN)
    assert directness.severity is Severity.WARNING
    assert outcome.resolved_packages[0].relation is DependencyRelation.UNKNOWN


def test_root_without_dependencies_is_reported_as_info() -> None:
    outcome = parse('version = 1\n[[package]]\nname = "root"\nversion = "0.1.0"\nsource = { virtual = "." }\n')
    directness = warning(outcome, WarningCode.DIRECTNESS_UNKNOWN)
    assert directness.severity is Severity.INFO


def test_newer_lock_version_is_parsed_but_flagged() -> None:
    outcome = parse(
        "version = 2\n"
        "[[package]]\n"
        'name = "a"\n'
        'version = "1.0.0"\n'
        'source = { registry = "https://pypi.org/simple" }\n'
    )
    assert outcome.status is ManifestParseStatus.PARTIAL
    assert WarningCode.MANIFEST_PARSE_ERROR.value in codes(outcome)
    assert outcome.resolved_packages[0].version == "1.0.0"


def test_missing_lock_version_is_flagged() -> None:
    outcome = parse("[[package]]\n" 'name = "a"\n' 'version = "1.0.0"\n')
    assert outcome.status is ManifestParseStatus.PARTIAL
    assert WarningCode.MANIFEST_PARSE_ERROR.value in codes(outcome)


def test_lock_without_packages_is_partial() -> None:
    outcome = parse("version = 1\n")
    assert outcome.status is ManifestParseStatus.PARTIAL
    assert WarningCode.NO_DEPENDENCIES_FOUND.value in codes(outcome)


def test_invalid_toml_fails_the_file_not_the_run() -> None:
    outcome = parse("version = nope\n")
    assert outcome.status is ManifestParseStatus.FAILED
    assert outcome.errors[0].code.value == "manifest_parse_error"
    assert outcome.errors[0].manifest_path == "uv.lock"


def test_package_without_version_is_skipped_never_guessed() -> None:
    outcome = parse(
        "version = 1\n"
        "[[package]]\n"
        'name = "broken"\n'
        'source = { registry = "https://pypi.org/simple" }\n'
    )
    assert outcome.resolved_packages == []
    assert outcome.status is ManifestParseStatus.PARTIAL
    assert WarningCode.MALFORMED_ENTRY.value in codes(outcome)
    assert WarningCode.NO_DEPENDENCIES_FOUND.value in codes(outcome)


def test_package_without_name_is_skipped() -> None:
    outcome = parse('version = 1\n[[package]]\nversion = "1.0.0"\n')
    assert outcome.resolved_packages == []
    assert WarningCode.MALFORMED_ENTRY.value in codes(outcome)


def test_malformed_dependency_entries_are_reported() -> None:
    not_a_list = parse(
        "version = 1\n"
        "[[package]]\n"
        'name = "root"\n'
        'version = "0.1.0"\n'
        'source = { virtual = "." }\n'
        'dependencies = "requests"\n'
    )
    assert not_a_list.status is ManifestParseStatus.PARTIAL
    assert WarningCode.MALFORMED_ENTRY.value in codes(not_a_list)

    nameless = parse(
        "version = 1\n"
        "[[package]]\n"
        'name = "root"\n'
        'version = "0.1.0"\n'
        'source = { virtual = "." }\n'
        'dependencies = [{ specifier = ">=1" }]\n'
    )
    assert WarningCode.MALFORMED_ENTRY.value in codes(nameless)

    wrong_shape = parse(
        "version = 1\n"
        "[[package]]\n"
        'name = "root"\n'
        'version = "0.1.0"\n'
        'source = { virtual = "." }\n'
        "dependencies = [42]\n"
    )
    assert WarningCode.MALFORMED_ENTRY.value in codes(wrong_shape)


def test_edge_extras_are_preserved() -> None:
    outcome = parse(
        "version = 1\n"
        "[[package]]\n"
        'name = "root"\n'
        'version = "0.1.0"\n'
        'source = { virtual = "." }\n'
        'dependencies = [{ name = "requests", extra = ["socks", "security"] }]\n'
    )
    edge = outcome.edges[0]
    assert edge.extras == ("security", "socks")  # sorted by build_edge
