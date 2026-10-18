"""``requirements.txt`` parser tests (pip requirements file format subset)."""

from __future__ import annotations

import pytest
from packaging.specifiers import SpecifierSet

from app.core.config import Settings
from app.ingestion.parsers import MappingFileResolver, ParserContext, parse_requirements
from app.ingestion.parsers.base import ParseOutcome
from app.models.common import (
    ConstraintScheme,
    DependencyScope,
    ManifestParseStatus,
    Severity,
    SourceKind,
    WarningCode,
)
from tests.support import make_settings


def parse(
    text: str,
    *,
    files: dict[str, str] | None = None,
    settings: Settings | None = None,
    path: str = "requirements.txt",
) -> ParseOutcome:
    context = ParserContext(
        path=path,
        text=text,
        settings=settings or make_settings(),
        resolver=MappingFileResolver(files or {}),
    )
    return parse_requirements(context)


def codes(outcome: ParseOutcome) -> set[str]:
    return {warning.code.value for warning in outcome.warnings}


# ---------------------------------------------------------------------------
# Declarations, pins and constraints
# ---------------------------------------------------------------------------
def test_exact_pin_is_a_constraint_not_a_resolved_version() -> None:
    outcome = parse("click==8.1.7\n")
    assert outcome.status is ManifestParseStatus.PARSED
    declaration = outcome.declarations[0]
    assert declaration.original_name == "click"
    assert declaration.version_constraint == "==8.1.7"
    assert declaration.is_exact_pin is True
    assert declaration.resolved_version is None
    assert declaration.resolved_from is None
    assert declaration.relation.value == "direct"
    assert declaration.scope is DependencyScope.RUNTIME


def test_range_constraint_is_canonicalised_and_not_a_pin() -> None:
    outcome = parse("requests>=2.31,<3\n")
    declaration = outcome.declarations[0]
    assert declaration.version_constraint == str(SpecifierSet(">=2.31,<3"))
    assert declaration.is_exact_pin is False
    assert declaration.constraint_scheme is ConstraintScheme.PEP440


def test_wildcard_pin_is_not_treated_as_an_exact_pin() -> None:
    outcome = parse("foo==1.2.*\n")
    assert outcome.declarations[0].version_constraint == "==1.2.*"
    assert outcome.declarations[0].is_exact_pin is False


def test_extras_markers_and_parenthesised_specifiers_are_preserved() -> None:
    outcome = parse('requests[security,socks] (>=2.31,<3) ; python_version >= "3.9"\n')
    declaration = outcome.declarations[0]
    assert declaration.extras == ("security", "socks")
    assert declaration.marker == 'python_version >= "3.9"'
    assert declaration.version_constraint == str(SpecifierSet(">=2.31,<3"))


def test_names_are_normalised_but_originals_are_kept() -> None:
    outcome = parse("Flask_SQLAlchemy>=3\nzope.interface==6.0\n")
    names = {(declaration.original_name, declaration.normalized_name) for declaration in outcome.declarations}
    assert names == {("Flask_SQLAlchemy", "flask-sqlalchemy"), ("zope.interface", "zope-interface")}


def test_trailing_comment_is_stripped() -> None:
    outcome = parse("requests==2.31.0  # pinned for the fixtures\n")
    assert len(outcome.declarations) == 1
    assert WarningCode.HASH_PINNED_REQUIREMENT.value not in codes(outcome)


def test_line_numbers_and_snippets_are_recorded() -> None:
    outcome = parse("# comment\n\nrequests>=2.31,<3\n")
    declaration = outcome.declarations[0]
    assert declaration.provenance.manifest_path == "requirements.txt"
    assert declaration.provenance.line_number == 3
    assert declaration.provenance.snippet == "requests>=2.31,<3"


# ---------------------------------------------------------------------------
# Direct references
# ---------------------------------------------------------------------------
def test_wheel_direct_reference_yields_an_artifact_version() -> None:
    outcome = parse(
        "requests @ https://files.pythonhosted.org/packages/req/requests-2.32.3-py3-none-any.whl\n"
    )
    declaration = outcome.declarations[0]
    assert declaration.is_direct_url_reference is True
    assert declaration.source_kind is SourceKind.URL
    assert declaration.referenced_version == "2.32.3"
    assert declaration.resolved_version is None  # a URL is not a resolution
    assert warning(outcome, WarningCode.DIRECT_URL_REFERENCE).details["version_from_url"] == "2.32.3"


def test_sdist_direct_reference_version_is_extracted() -> None:
    outcome = parse("demo @ https://example.com/files/demo-1.2.3.tar.gz\n")
    assert outcome.declarations[0].referenced_version == "1.2.3"


def test_direct_reference_with_mismatched_artifact_never_guesses() -> None:
    outcome = parse("requests @ https://example.com/files/other-9.9.9-py3-none-any.whl\n")
    declaration = outcome.declarations[0]
    assert declaration.referenced_version is None
    assert declaration.source_reference == "https://example.com/files/other-9.9.9-py3-none-any.whl"


def test_local_archive_without_a_name_is_reported_not_parsed() -> None:
    outcome = parse("./wheels/demo-1.0.0-py3-none-any.whl\n")
    assert outcome.declarations == []
    assert outcome.status is ManifestParseStatus.PARTIAL
    assert WarningCode.LOCAL_PATH_REQUIREMENT.value in codes(outcome)


# ---------------------------------------------------------------------------
# Editable installs
# ---------------------------------------------------------------------------
def test_editable_vcs_reference_is_recorded_without_a_version() -> None:
    outcome = parse("-e git+https://github.com/foo/bar.git#egg=bar\n")
    declaration = outcome.declarations[0]
    assert declaration.normalized_name == "bar"
    assert declaration.source_kind is SourceKind.GIT
    assert declaration.source_reference == "git+https://github.com/foo/bar.git#egg=bar"
    assert declaration.version_constraint is None
    assert WarningCode.EDITABLE_REFERENCE.value in codes(outcome)


def test_editable_local_path_is_classified_as_editable() -> None:
    outcome = parse("-e .#egg=project-name\n")
    declaration = outcome.declarations[0]
    assert declaration.source_kind is SourceKind.EDITABLE
    assert declaration.normalized_name == "project-name"


def test_editable_without_egg_fragment_is_reported_not_invented() -> None:
    outcome = parse("-e .\n")
    assert outcome.declarations == []
    assert outcome.status is ManifestParseStatus.PARTIAL
    assert WarningCode.EDITABLE_REFERENCE.value in codes(outcome)


# ---------------------------------------------------------------------------
# Includes
# ---------------------------------------------------------------------------
def test_local_include_is_followed_and_dev_scope_is_inferred() -> None:
    outcome = parse(
        "requests>=2.31,<3\n-r requirements-dev.txt\n",
        files={"requirements-dev.txt": "pytest>=8\n"},
    )
    names = {declaration.normalized_name: declaration for declaration in outcome.declarations}
    assert set(names) == {"requests", "pytest"}
    assert names["pytest"].scope is DependencyScope.DEV
    assert names["pytest"].group == "requirements-dev"
    assert names["pytest"].provenance.manifest_path == "requirements-dev.txt"
    assert names["pytest"].provenance.line_number == 1
    assert outcome.metadata["included_files"] == ["requirements-dev.txt"]
    assert WarningCode.RELATION_INFERRED.value in codes(outcome)


def test_include_is_resolved_relative_to_the_declaring_file() -> None:
    outcome = parse(
        "-r base.txt\n",
        files={"sub/base.txt": "requests>=2.31,<3\n"},
        path="sub/requirements.txt",
    )
    assert outcome.declarations[0].normalized_name == "requests"
    assert outcome.declarations[0].provenance.manifest_path == "sub/base.txt"


def test_missing_include_is_reported() -> None:
    outcome = parse("-r missing.txt\n")
    assert outcome.declarations == []
    assert outcome.status is ManifestParseStatus.PARTIAL
    assert WarningCode.NESTED_REQUIREMENT_NOT_FOUND.value in codes(outcome)


def test_include_cycle_is_detected() -> None:
    outcome = parse(
        "requests>=2.31,<3\n-r b.txt\n",
        files={"b.txt": "-r requirements.txt\n"},
    )
    assert WarningCode.NESTED_REQUIREMENT_CYCLE.value in codes(outcome)
    assert len(outcome.declarations) == 1


def test_include_depth_limit_is_enforced() -> None:
    settings = make_settings(max_requirement_include_depth=1)
    outcome = parse(
        "-r b.txt\n",
        files={"b.txt": "-r c.txt\n", "c.txt": "requests>=2\n"},
        settings=settings,
    )
    assert WarningCode.INCLUDE_DEPTH_EXCEEDED.value in codes(outcome)
    assert outcome.status is ManifestParseStatus.PARTIAL


def test_include_escaping_the_repository_is_rejected() -> None:
    outcome = parse("-r ../../outside.txt\n")
    assert outcome.declarations == []
    assert outcome.status is ManifestParseStatus.PARTIAL
    assert warning(outcome, WarningCode.MALFORMED_ENTRY).details["reference"] == "../../outside.txt"


def test_remote_include_is_reported_but_never_fetched() -> None:
    outcome = parse("-r https://example.com/requirements.txt\n")
    assert outcome.declarations == []
    assert WarningCode.REMOTE_REQUIREMENT_REFERENCE.value in codes(outcome)


# ---------------------------------------------------------------------------
# Options, hashes, constraint files, malformed input
# ---------------------------------------------------------------------------
def test_hashes_and_continuations_are_handled() -> None:
    outcome = parse(
        "requests==2.31.0 \\\n    --hash=sha256:aaaa \\\n    --hash=sha256:bbbb\n"
    )
    assert len(outcome.declarations) == 1
    assert outcome.declarations[0].is_exact_pin is True
    # The counter records hash-pinned requirement lines, not individual hashes.
    assert outcome.sections["hash_options"] == 1
    assert WarningCode.HASH_PINNED_REQUIREMENT.value in codes(outcome)


def test_constraint_file_reference_is_reported_not_resolved() -> None:
    outcome = parse("-c constraints.txt\nrequests>=2\n")
    assert len(outcome.declarations) == 1
    assert outcome.sections["constraint_references"] == 1
    assert WarningCode.CONSTRAINT_FILE_REFERENCE.value in codes(outcome)


def test_index_options_are_ignored_and_unknown_options_warn() -> None:
    outcome = parse("--index-url https://pypi.org/simple\n--frobnicate\nrequests>=2\n")
    assert len(outcome.declarations) == 1
    unrecognised = warning(outcome, WarningCode.UNSUPPORTED_DEPENDENCY_SECTION)
    assert unrecognised.details["option"] == "--frobnicate"


def test_build_options_are_reported_and_never_executed() -> None:
    outcome = parse("--global-option=--fast\nrequests>=2\n")
    assert len(outcome.declarations) == 1
    options = [w for w in outcome.warnings if w.code is WarningCode.UNSUPPORTED_DEPENDENCY_SECTION]
    assert options and "build option" in options[0].message


def test_malformed_requirement_is_reported_without_crashing() -> None:
    outcome = parse("this is not a requirement\nrequests>=2\n")
    assert [declaration.normalized_name for declaration in outcome.declarations] == ["requests"]
    assert outcome.status is ManifestParseStatus.PARTIAL
    malformed = warning(outcome, WarningCode.MALFORMED_ENTRY)
    assert malformed.line_number == 1
    assert "reason" in malformed.details


def test_invalid_specifier_is_malformed_input_not_a_crash() -> None:
    # packaging raises InvalidSpecifier (not InvalidRequirement) for this line;
    # the parser must report it as malformed instead of propagating the error.
    outcome = parse("somepkg==not-a-version\nrequests>=2\n")
    assert [declaration.normalized_name for declaration in outcome.declarations] == ["requests"]
    assert outcome.status is ManifestParseStatus.PARTIAL
    assert WarningCode.MALFORMED_ENTRY.value in codes(outcome)


def test_empty_and_comment_only_files_are_reported() -> None:
    empty = parse("")
    assert WarningCode.EMPTY_MANIFEST.value in codes(empty)

    comments = parse("# just a comment\n\n")
    assert WarningCode.EMPTY_MANIFEST.value in codes(comments)

    options_only = parse("--index-url https://pypi.org/simple\n")
    assert WarningCode.NO_DEPENDENCIES_FOUND.value in codes(options_only)
    assert all(warning.severity is Severity.INFO for warning in options_only.warnings[:1])


def test_dependency_limit_is_enforced() -> None:
    settings = make_settings(max_dependencies=2)
    outcome = parse("a==1\nb==1\nc==1\nd==1\n", settings=settings)
    assert len(outcome.declarations) == 2
    assert outcome.status is ManifestParseStatus.PARTIAL
    assert WarningCode.DEPENDENCY_LIMIT_REACHED.value in codes(outcome)


def test_scope_of_a_plain_requirements_file_is_runtime() -> None:
    outcome = parse("requests>=2\n")
    declaration = outcome.declarations[0]
    assert declaration.scope is DependencyScope.RUNTIME
    assert declaration.group == "requirements"
    assert WarningCode.RELATION_INFERRED.value not in codes(outcome)


@pytest.mark.parametrize(
    ("filename", "expected_scope"),
    [
        ("requirements-dev.txt", DependencyScope.DEV),
        ("requirements_test.txt", DependencyScope.DEV),
        ("test-requirements.txt", DependencyScope.DEV),
        ("requirements-ci.txt", DependencyScope.DEV),
        ("requirements-prod.txt", DependencyScope.RUNTIME),
    ],
)
def test_dev_scope_inference(filename: str, expected_scope: DependencyScope) -> None:
    outcome = parse("pytest>=8\n", path=f"project/{filename}")
    assert outcome.declarations[0].scope is expected_scope


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def warning(outcome: ParseOutcome, code: WarningCode):
    matches = [w for w in outcome.warnings if w.code is code]
    assert matches, f"expected warning {code} in {sorted(codes(outcome))}"
    return matches[0]


def test_direct_url_reference_is_not_a_resolution() -> None:
    # Guard rail: no code path may turn a URL into resolved_version.
    outcome = parse("demo @ https://example.com/files/demo-1.2.3.tar.gz\n")
    assert all(declaration.resolved_version is None for declaration in outcome.declarations)
    assert all(declaration.resolved_from is None for declaration in outcome.declarations)
