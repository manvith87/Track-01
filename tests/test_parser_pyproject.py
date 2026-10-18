"""``pyproject.toml`` parser tests (PEP 621, PEP 735, Poetry, uv legacy)."""

from __future__ import annotations

from packaging.specifiers import SpecifierSet

from app.core.config import Settings
from app.ingestion.parsers import MappingFileResolver, ParserContext, parse_pyproject
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

PEP621_DOCUMENT = """[project]
name = "demo"
version = "1.2.3"
requires-python = ">=3.9"
dependencies = [
  "requests>=2.31,<3",
  "click==8.1.7",
]

[project.optional-dependencies]
socks = ["PySocks>=1.5.6"]

[dependency-groups]
dev = ["pytest>=8", {include-group = "lint"}]
lint = ["ruff>=0.5"]

[build-system]
requires = ["setuptools>=68", "wheel"]
build-backend = "setuptools.build_meta"
"""


def parse(text: str, *, settings: Settings | None = None, path: str = "pyproject.toml") -> ParseOutcome:
    context = ParserContext(
        path=path,
        text=text,
        settings=settings or make_settings(),
        resolver=MappingFileResolver({}),
    )
    return parse_pyproject(context)


def codes(outcome: ParseOutcome) -> set[str]:
    return {warning.code.value for warning in outcome.warnings}


def warning(outcome: ParseOutcome, code: WarningCode):
    matches = [w for w in outcome.warnings if w.code is code]
    assert matches, f"expected warning {code} in {sorted(codes(outcome))}"
    return matches[0]


def declarations_by_section(outcome: ParseOutcome):
    result: dict[str, list] = {}
    for declaration in outcome.declarations:
        result.setdefault(declaration.provenance.section or "", []).append(declaration)
    return result


# ---------------------------------------------------------------------------
# PEP 621
# ---------------------------------------------------------------------------
def test_pep621_project_metadata_and_dependencies() -> None:
    outcome = parse(PEP621_DOCUMENT)
    assert outcome.status is ManifestParseStatus.PARSED
    assert outcome.project_name == "demo"
    assert outcome.project_version == "1.2.3"
    assert outcome.requires_python == ">=3.9"
    assert outcome.metadata["requires_python"] == ">=3.9"

    sections = declarations_by_section(outcome)
    runtime = sections["project.dependencies"]
    assert [declaration.original_name for declaration in runtime] == ["requests", "click"]
    assert runtime[0].version_constraint == str(SpecifierSet(">=2.31,<3"))
    assert runtime[0].constraint_scheme is ConstraintScheme.PEP440
    assert runtime[0].scope is DependencyScope.RUNTIME
    assert runtime[0].relation.value == "direct"
    assert runtime[1].is_exact_pin is True
    assert runtime[1].resolved_version is None

    optional = sections["project.optional-dependencies.socks"]
    assert [declaration.original_name for declaration in optional] == ["PySocks"]
    assert optional[0].scope is DependencyScope.OPTIONAL
    assert optional[0].group == "socks"

    build = sections["build-system.requires"]
    assert [declaration.original_name for declaration in build] == ["setuptools", "wheel"]
    assert all(declaration.scope is DependencyScope.BUILD for declaration in build)
    assert build[0].group == "build-system"
    assert outcome.metadata["packaging_backend"] == "setuptools.build_meta"


def test_line_numbers_are_recorded_for_every_section() -> None:
    outcome = parse(PEP621_DOCUMENT)
    lines = {
        (declaration.original_name, declaration.provenance.line_number)
        for declaration in outcome.declarations
    }
    assert lines == {
        ("requests", 6),
        ("click", 7),
        ("PySocks", 11),
        ("pytest", 14),
        ("ruff", 15),
        ("setuptools", 18),
        ("wheel", 18),
    }


def test_dynamic_dependencies_are_reported() -> None:
    outcome = parse(
        '[project]\nname = "x"\ndynamic = ["dependencies"]\n',
    )
    assert WarningCode.UNSUPPORTED_DEPENDENCY_SECTION.value in codes(outcome)
    assert outcome.declarations == []
    assert WarningCode.NO_DEPENDENCIES_FOUND.value in codes(outcome)


# ---------------------------------------------------------------------------
# PEP 735 dependency groups
# ---------------------------------------------------------------------------
def test_include_group_is_expanded_exactly_once() -> None:
    outcome = parse(
        "[dependency-groups]\n"
        'dev = ["pytest>=8", {include-group = "lint"}]\n'
        'lint = ["ruff>=0.5"]\n'
    )
    pairs = [(declaration.original_name, declaration.group, declaration.scope) for declaration in outcome.declarations]
    assert pairs == [
        ("pytest", "dev", DependencyScope.DEV),
        ("ruff", "lint", DependencyScope.DEV),
    ]
    include = warning(outcome, WarningCode.DEPENDENCY_GROUP_INCLUDE_RESOLVED)
    assert include.details["included_group"] == "lint"
    assert include.severity is Severity.INFO


def test_group_defined_before_its_includer_is_not_duplicated() -> None:
    outcome = parse(
        "[dependency-groups]\n"
        'lint = ["ruff>=0.5"]\n'
        'dev = ["pytest>=8", {include-group = "lint"}]\n'
    )
    names = [declaration.original_name for declaration in outcome.declarations]
    assert sorted(names) == ["pytest", "ruff"]
    assert len(outcome.declarations) == 2


def test_custom_group_names_are_optional_not_dev() -> None:
    outcome = parse('[dependency-groups]\ncustom = ["somepkg>=1"]\n')
    assert outcome.declarations[0].scope is DependencyScope.OPTIONAL
    assert outcome.declarations[0].group == "custom"


def test_missing_included_group_is_reported() -> None:
    outcome = parse('[dependency-groups]\ndev = [{include-group = "ghost"}]\n')
    assert WarningCode.DEPENDENCY_GROUP_INCLUDE_MISSING.value in codes(outcome)
    assert outcome.status is ManifestParseStatus.PARTIAL


def test_include_cycle_is_detected() -> None:
    outcome = parse(
        "[dependency-groups]\n"
        'a = [{include-group = "b"}]\n'
        'b = [{include-group = "a"}]\n'
    )
    assert WarningCode.DEPENDENCY_GROUP_CYCLE.value in codes(outcome)
    assert outcome.status is ManifestParseStatus.PARTIAL


def test_include_depth_limit_is_enforced() -> None:
    settings = make_settings(max_dependency_group_depth=1)
    outcome = parse(
        "[dependency-groups]\n"
        'a = [{include-group = "b"}]\n'
        'b = [{include-group = "c"}]\n'
        'c = ["deep>=1"]\n',
        settings=settings,
    )
    assert WarningCode.INCLUDE_DEPTH_EXCEEDED.value in codes(outcome)
    assert outcome.status is ManifestParseStatus.PARTIAL
    # group c is still expanded at top level (depth 0), so nothing is lost
    assert "deep" in {declaration.normalized_name for declaration in outcome.declarations}


def test_malformed_group_shapes_are_reported() -> None:
    not_a_list = parse('[dependency-groups]\ndev = "pytest"\n')
    assert WarningCode.MALFORMED_ENTRY.value in codes(not_a_list)
    assert not_a_list.status is ManifestParseStatus.PARTIAL

    bad_entry = parse("[dependency-groups]\ndev = [42]\n")
    assert WarningCode.MALFORMED_ENTRY.value in codes(bad_entry)

    not_a_table = parse('dependency-groups = "dev"\n')
    assert WarningCode.MALFORMED_ENTRY.value in codes(not_a_table)


# ---------------------------------------------------------------------------
# Poetry
# ---------------------------------------------------------------------------
POETRY_DOCUMENT = """[tool.poetry]
name = "demo2"
version = "0.1.0"

[tool.poetry.dependencies]
python = "^3.10"
requests = "^2.31"
flask = {version = ">=2.0", extras = ["async"], optional = true}
gitdep = {git = "https://github.com/foo/bar.git", tag = "v1.0"}
localdep = {path = "../local", develop = true}
multi = [
  {version = "<2.0", python = "<3.11"},
  {version = ">=2.0", python = ">=3.11"},
]

[tool.poetry.group.docs]
optional = true
[tool.poetry.group.docs.dependencies]
mkdocs = "*"

[tool.poetry.dev-dependencies]
black = ">=24.0"
"""


def test_poetry_dependencies_and_sources() -> None:
    outcome = parse(POETRY_DOCUMENT)
    assert outcome.project_name == "demo2"
    assert outcome.project_version == "0.1.0"
    assert outcome.requires_python == "^3.10"
    assert outcome.metadata["tool.poetry.python"] == "^3.10"
    assert outcome.metadata["packaging_backend"] == "poetry"

    by_name: dict[str, list] = {}
    for declaration in outcome.declarations:
        by_name.setdefault(declaration.normalized_name, []).append(declaration)

    requests = by_name["requests"][0]
    assert requests.version_constraint == "^2.31"
    assert requests.constraint_scheme is ConstraintScheme.POETRY
    assert requests.is_exact_pin is False
    assert requests.scope is DependencyScope.RUNTIME

    flask = by_name["flask"][0]
    assert flask.version_constraint == ">=2.0"
    # Poetry tables may use PEP 440 syntax, which packaging can evaluate.
    assert flask.constraint_scheme is ConstraintScheme.PEP440
    assert flask.scope is DependencyScope.OPTIONAL
    assert flask.extras == ("async",)

    gitdep = by_name["gitdep"][0]
    assert gitdep.source_kind is SourceKind.GIT
    assert gitdep.source_reference == "https://github.com/foo/bar.git@tag=v1.0"
    assert gitdep.version_constraint is None

    localdep = by_name["localdep"][0]
    assert localdep.source_kind is SourceKind.EDITABLE
    assert localdep.source_reference == "../local"

    multi = by_name["multi"]
    assert [declaration.version_constraint for declaration in multi] == ["<2.0", ">=2.0"]
    assert [declaration.requires_python for declaration in multi] == ["<3.11", ">=3.11"]
    assert multi[0].id != multi[1].id
    assert WarningCode.MULTIPLE_CONSTRAINTS_FOR_PACKAGE.value in codes(outcome)

    mkdocs = by_name["mkdocs"][0]
    assert mkdocs.version_constraint is None
    assert mkdocs.scope is DependencyScope.OPTIONAL  # the group declares optional = true
    assert mkdocs.group == "docs"
    assert WarningCode.UNRESOLVED_VERSION.value in codes(outcome)

    black = by_name["black"][0]
    assert black.scope is DependencyScope.DEV
    assert black.group == "dev"


def test_poetry_constraint_schemes() -> None:
    outcome = parse(
        "[tool.poetry.dependencies]\n"
        'caret = "^1.2"\n'
        'tilde = "~1.2"\n'
        'bare = "1.2.3"\n'
        'range = ">=1.0,<2.0"\n'
        'pick = "==1.2.3"\n'
        'wildcard = "1.2.*"\n'
    )
    declarations = {declaration.normalized_name: declaration for declaration in outcome.declarations}
    schemes = {name: declaration.constraint_scheme for name, declaration in declarations.items()}
    assert schemes["caret"] is ConstraintScheme.POETRY
    assert schemes["tilde"] is ConstraintScheme.POETRY
    assert schemes["bare"] is ConstraintScheme.POETRY
    assert schemes["range"] is ConstraintScheme.PEP440
    assert schemes["pick"] is ConstraintScheme.PEP440
    assert schemes["wildcard"] is ConstraintScheme.POETRY
    assert declarations["pick"].is_exact_pin is True
    assert declarations["caret"].is_exact_pin is False
    assert declarations["wildcard"].is_exact_pin is False


def test_poetry_extras_table_is_recorded_as_metadata_only() -> None:
    outcome = parse(
        "[tool.poetry.dependencies]\n"
        'requests = {version = "*", extras = ["socks"]}\n'
        "\n"
        "[tool.poetry.extras]\n"
        'socks = ["PySocks"]\n'
    )
    assert outcome.metadata["tool.poetry.extras"] == {"socks": ["PySocks"]}
    assert [declaration.normalized_name for declaration in outcome.declarations] == ["requests"]


def test_project_and_poetry_dependencies_together_are_flagged() -> None:
    outcome = parse(
        "[project]\n"
        'name = "both"\n'
        "dependencies = [\"requests>=2.31\"]\n"
        "\n"
        "[tool.poetry.dependencies]\n"
        'requests = "^2.31"\n'
    )
    assert len(outcome.declarations) == 2
    assert WarningCode.MULTIPLE_CONSTRAINTS_FOR_PACKAGE.value in codes(outcome)


def test_pep621_requires_python_wins_over_poetry_python() -> None:
    outcome = parse(
        "[project]\n"
        'name = "both"\n'
        'requires-python = ">=3.10"\n'
        "\n"
        "[tool.poetry.dependencies]\n"
        'python = "^3.9"\n'
    )
    assert outcome.requires_python == ">=3.10"
    assert outcome.metadata["tool.poetry.python"] == "^3.9"


# ---------------------------------------------------------------------------
# uv legacy, PDM, malformed input
# ---------------------------------------------------------------------------
def test_uv_legacy_dev_dependencies_are_parsed_and_flagged() -> None:
    outcome = parse('[tool.uv]\ndev-dependencies = ["pytest>=8"]\n')
    assert outcome.declarations[0].scope is DependencyScope.DEV
    assert outcome.declarations[0].group == "dev"
    assert WarningCode.UNSUPPORTED_DEPENDENCY_SECTION.value in codes(outcome)


def test_pdm_dependency_tables_are_reported_as_unsupported() -> None:
    outcome = parse('[tool.pdm.dev-dependencies]\ntest = ["tox"]\n')
    assert WarningCode.UNSUPPORTED_DEPENDENCY_SECTION.value in codes(outcome)
    assert outcome.declarations == []


def test_invalid_toml_fails_the_manifest_only() -> None:
    outcome = parse("[project\nname = broken\n")
    assert outcome.status is ManifestParseStatus.FAILED
    assert outcome.declarations == []
    assert [error.code.value for error in outcome.errors] == ["manifest_parse_error"]
    assert outcome.errors[0].line_number is not None
    parse_warning = warning(outcome, WarningCode.MANIFEST_PARSE_ERROR)
    assert parse_warning.severity is Severity.ERROR


def test_empty_pyproject_reports_no_dependencies() -> None:
    outcome = parse("")
    assert outcome.status is ManifestParseStatus.PARSED
    assert WarningCode.NO_DEPENDENCIES_FOUND.value in codes(outcome)


def test_malformed_dependency_shapes_are_reported() -> None:
    not_a_list = parse('[project]\nname = "x"\ndependencies = "requests"\n')
    assert not_a_list.status is ManifestParseStatus.PARTIAL
    assert WarningCode.MALFORMED_ENTRY.value in codes(not_a_list)

    bad_entry = parse('[project]\nname = "x"\ndependencies = [{version = "1"}]\n')
    assert WarningCode.MALFORMED_ENTRY.value in codes(bad_entry)

    bad_optional = parse('[project]\nname = "x"\noptional-dependencies = ["requests"]\n')
    assert WarningCode.MALFORMED_ENTRY.value in codes(bad_optional)

    bad_optional_value = parse('[project.optional-dependencies]\nsocks = "PySocks"\n')
    assert WarningCode.MALFORMED_ENTRY.value in codes(bad_optional_value)


def test_unparsable_requirement_string_is_reported() -> None:
    outcome = parse('[project]\nname = "x"\ndependencies = ["not a requirement !!!"]\n')
    assert outcome.declarations == []
    assert outcome.status is ManifestParseStatus.PARTIAL
    malformed = warning(outcome, WarningCode.MALFORMED_ENTRY)
    assert malformed.details.get("reason")


def test_unknown_tool_sections_do_not_break_parsing() -> None:
    outcome = parse(
        "[project]\n"
        'name = "x"\n'
        'dependencies = ["requests>=2"]\n'
        "\n"
        "[tool.other.thing]\n"
        "key = 1\n"
    )
    assert [declaration.normalized_name for declaration in outcome.declarations] == ["requests"]
    assert outcome.status is ManifestParseStatus.PARSED
