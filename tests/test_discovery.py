"""Manifest discovery tests: classification, pruning, caps, degraded files.

Discovery is the component that turns an untrusted working tree into a bounded
list of manifests, so the tests focus on the boundaries: what is recognised,
what is never entered, what happens when a limit is hit and how broken files
are reported (never guessed at).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.ingestion.discovery import (
    DiscoveryResult,
    classify_dependency_file,
    discover_repository_files,
)
from app.models.common import (
    ManifestFormat,
    Severity,
    SupportLevel,
    UnsupportedManifestFormat,
    WarningCode,
)
from tests.support import make_settings, try_symlink, write_tree


def codes(result: DiscoveryResult) -> set[str]:
    return {warning.code.value for warning in result.warnings}


def warning(result: DiscoveryResult, code: WarningCode):
    matches = [w for w in result.warnings if w.code is code]
    assert matches, f"expected {code} in {sorted(codes(result))}"
    return matches[0]


def manifest_paths(result: DiscoveryResult) -> list[str]:
    return [manifest.path for manifest in result.manifests]


def discover(root: Path, **overrides) -> DiscoveryResult:
    return discover_repository_files(root, make_settings(**overrides))


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("path", "supported"),
    [
        ("requirements.txt", ManifestFormat.REQUIREMENTS_TXT),
        ("requirements-dev.txt", ManifestFormat.REQUIREMENTS_TXT),
        ("requirements_test.txt", ManifestFormat.REQUIREMENTS_TXT),
        ("test-requirements.txt", ManifestFormat.REQUIREMENTS_TXT),
        ("reqs.txt", ManifestFormat.REQUIREMENTS_TXT),
        ("requirements/base.txt", ManifestFormat.REQUIREMENTS_TXT),
        ("requirements.d/base.txt", ManifestFormat.REQUIREMENTS_TXT),
        ("pyproject.toml", ManifestFormat.PYPROJECT_TOML),
        ("PYPROJECT.TOML", ManifestFormat.PYPROJECT_TOML),
        ("sub/dir/pyproject.toml", ManifestFormat.PYPROJECT_TOML),
        ("poetry.lock", ManifestFormat.POETRY_LOCK),
        ("uv.lock", ManifestFormat.UV_LOCK),
        ("sub/uv.lock", ManifestFormat.UV_LOCK),
    ],
)
def test_supported_formats_are_recognised(path: str, supported: ManifestFormat) -> None:
    assert classify_dependency_file(path) == (supported, None)


@pytest.mark.parametrize(
    ("path", "unsupported"),
    [
        ("Pipfile", UnsupportedManifestFormat.PIPFILE),
        ("Pipfile.lock", UnsupportedManifestFormat.PIPFILE_LOCK),
        ("setup.py", UnsupportedManifestFormat.SETUP_PY),
        ("setup.cfg", UnsupportedManifestFormat.SETUP_CFG),
        ("environment.yml", UnsupportedManifestFormat.ENVIRONMENT_YML),
        ("environment.yaml", UnsupportedManifestFormat.ENVIRONMENT_YAML),
        ("conda.yml", UnsupportedManifestFormat.CONDA_YML),
        ("conda.yaml", UnsupportedManifestFormat.CONDA_YAML),
        ("requirements.in", UnsupportedManifestFormat.REQUIREMENTS_IN),
        ("sub/setup.py", UnsupportedManifestFormat.SETUP_PY),
    ],
)
def test_known_unsupported_formats_are_detected(path: str, unsupported: UnsupportedManifestFormat) -> None:
    assert classify_dependency_file(path) == (None, unsupported)


@pytest.mark.parametrize(
    "path",
    [
        "constraints.txt",
        "README.md",
        "requirements.md",
        "pyproject.cfg",
        "notrequirements.txt",
        "requirements.txt.bak",
    ],
)
def test_unrelated_files_are_ignored(path: str) -> None:
    assert classify_dependency_file(path) == (None, None)


# ---------------------------------------------------------------------------
# Clean tree
# ---------------------------------------------------------------------------
def test_clean_tree_manifests_are_sorted_and_hashed(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    write_tree(root, {
        "requirements.txt": "requests>=2.31,<3\n",
        "README.md": "# readme\n",
        "pyproject.toml": '[project]\nname = "x"\nversion = "0.1.0"\n',
    })

    result = discover(root)
    assert manifest_paths(result) == ["pyproject.toml", "requirements.txt"]
    assert result.files_examined == 3
    assert result.truncated is False
    assert result.limits_hit == []
    assert result.warnings == []

    pyproject = result.manifests[0]
    assert pyproject.directory == "."
    assert pyproject.support_level is SupportLevel.SUPPORTED
    assert pyproject.text is not None and pyproject.text.startswith("[project]")
    assert pyproject.sha256 is not None and len(pyproject.sha256) == 64
    assert pyproject.is_lockfile is False
    assert result.manifests[1].is_lockfile is False

    # Manifest files come first, then other files (both sorted).
    assert [source.path for source in result.files] == ["pyproject.toml", "requirements.txt", "README.md"]
    readme = result.files[-1]
    assert readme.sha256 is None
    assert readme.manifest_format is None
    assert readme.support_level is None


def test_missing_root_returns_empty_result(tmp_path: Path) -> None:
    result = discover(tmp_path / "does-not-exist")
    assert result.manifests == []
    assert result.files == []
    assert result.files_examined == 0


def test_nested_manifests_get_their_directory(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    write_tree(root, {"sub/dir/requirements.txt": "requests\n"})
    result = discover(root)
    assert manifest_paths(result) == ["sub/dir/requirements.txt"]
    assert result.manifests[0].directory == "sub/dir"


# ---------------------------------------------------------------------------
# Exclusions
# ---------------------------------------------------------------------------
def test_excluded_directories_are_pruned_without_scanning(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    write_tree(root, {
        "README.md": "# ok\n",
        ".git/requirements.txt": "evil\n",
        ".venv/pyvenv.cfg": "home = /usr/bin\n",
        ".venv/requirements.txt": "ignored\n",
        "node_modules/requirements.txt": "ignored\n",
        "build/requirements.txt": "ignored\n",
        "__pycache__/requirements.txt": "ignored\n",
        "pkg.egg-info/requirements.txt": "ignored\n",
        "keep/requirements.txt": "requests\n",
    })

    result = discover(root)
    assert manifest_paths(result) == ["keep/requirements.txt"]
    assert result.directories_pruned == 6
    # ".venv" is pruned by name, so the pyvenv detection never fires for it.
    assert WarningCode.VIRTUALENV_DETECTED.value not in codes(result)
    assert result.warnings == []


def test_virtualenv_is_detected_precisely_via_pyvenv_cfg(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    write_tree(root, {
        "env/pyvenv.cfg": "home = /usr/bin\n",
        "env/lib/requirements.txt": "from-the-venv\n",
        "requirements.txt": "requests\n",
    })

    result = discover(root)
    assert manifest_paths(result) == ["requirements.txt"]
    detected = warning(result, WarningCode.VIRTUALENV_DETECTED)
    assert detected.severity is Severity.INFO
    assert detected.details["directory"] == "env"
    assert result.directories_pruned == 1


def test_directory_entry_limit_prunes_the_directory(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    write_tree(root, {
        "a/requirements.txt": "requests\n",
        "b/requirements.txt": "click\n",
        "c/requirements.txt": "rich\n",
    })

    result = discover(root, max_directory_entries=2)
    assert manifest_paths(result) == []
    limit = warning(result, WarningCode.DIRECTORY_ENTRY_LIMIT_EXCEEDED)
    assert limit.severity is Severity.WARNING
    assert limit.details["sub_directories"] == 3
    assert "max_directory_entries" in result.limits_hit


# ---------------------------------------------------------------------------
# Caps
# ---------------------------------------------------------------------------
def test_file_scan_limit_truncates_the_walk(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    write_tree(root, {
        "a.txt": "a\n",
        "b.txt": "b\n",
        "c.txt": "c\n",
        "d.txt": "d\n",
        "requirements.txt": "requests\n",
    })

    result = discover(root, max_files_scanned=2)
    assert result.files_examined == 2
    assert result.truncated is True
    assert manifest_paths(result) == []
    assert "max_files_scanned" in result.limits_hit
    truncation = warning(result, WarningCode.TREE_TRUNCATED_FILE_LIMIT)
    assert truncation.details["max_files_scanned"] == 2


def test_manifest_limit_stops_collecting(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    write_tree(root, {
        "pyproject.toml": '[project]\nname = "x"\nversion = "0.1.0"\n',
        "requirements.txt": "requests\n",
    })

    result = discover(root, max_manifests=1)
    assert manifest_paths(result) == ["pyproject.toml"]
    assert result.truncated is False
    assert "max_manifests" in result.limits_hit
    limit = warning(result, WarningCode.MANIFEST_LIMIT_REACHED)
    assert limit.details["limit"] == 1


def test_oversized_manifest_is_skipped_with_a_warning(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    write_tree(root, {"requirements.txt": "requests>=2.31,<3\n" + "# pad\n" * 50})

    result = discover(root, max_manifest_bytes=16)
    assert len(result.manifests) == 1
    manifest = result.manifests[0]
    assert manifest.text is None
    assert manifest.skipped_reason == "too_large"
    assert manifest.sha256 is None
    assert result.oversized_manifests_skipped == 1
    assert "max_manifest_bytes" in result.limits_hit
    assert WarningCode.MANIFEST_TOO_LARGE.value in codes(result)


# ---------------------------------------------------------------------------
# Degraded manifests
# ---------------------------------------------------------------------------
def test_non_utf8_manifest_is_reported_but_still_exposed(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    write_tree(root, {"requirements.txt": b"caf\xe9>=1.0\n"})

    result = discover(root)
    manifest = result.manifests[0]
    assert manifest.skipped_reason == "not_utf8"
    assert manifest.text == "café>=1.0\n"  # latin-1 fallback
    non_utf8 = warning(result, WarningCode.MANIFEST_NOT_UTF8)
    assert non_utf8.details["reason"] == "not_utf8"
    assert non_utf8.manifest_path == "requirements.txt"


def test_binary_manifest_is_skipped(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    write_tree(root, {"requirements.txt": b"PK\x03\x04\x00\x00\x00\x00"})

    result = discover(root)
    manifest = result.manifests[0]
    assert manifest.skipped_reason == "binary"
    assert manifest.text is None
    assert warning(result, WarningCode.MANIFEST_NOT_UTF8).details["reason"] == "binary"


def test_unsupported_format_is_recorded_and_warned(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    write_tree(root, {
        "Pipfile": '[packages]\nrequests = "*"\n',
        "setup.py": "from setuptools import setup\nsetup()\n",
    })

    result = discover(root)
    assert manifest_paths(result) == ["Pipfile", "setup.py"]
    assert all(manifest.support_level is SupportLevel.UNSUPPORTED for manifest in result.manifests)
    assert all(manifest.skipped_reason == "unsupported_format" for manifest in result.manifests)
    assert all(manifest.format is None for manifest in result.manifests)
    assert all(manifest.unsupported_format is not None for manifest in result.manifests)
    assert len([w for w in result.warnings if w.code is WarningCode.UNSUPPORTED_FORMAT]) == 2


def test_gitmodules_is_reported(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    write_tree(root, {
        ".gitmodules": '[submodule "dep"]\n\tpath = dep\n\turl = https://example.com/dep.git\n',
        "requirements.txt": "requests\n",
    })

    result = discover(root)
    submodules = warning(result, WarningCode.SUBMODULES_NOT_FETCHED)
    assert submodules.severity is Severity.INFO
    assert submodules.details["path"] == ".gitmodules"


# ---------------------------------------------------------------------------
# Symlinks
# ---------------------------------------------------------------------------
def test_symlinks_are_never_followed(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    write_tree(root, {
        "real/requirements.txt": "requests\n",
        "README.md": "# target\n",
    })
    file_link_ok = try_symlink(root / "README.md", root / "linked.txt")
    dir_link_ok = try_symlink(root / "real", root / "linked-dir", target_is_directory=True)
    if not (file_link_ok and dir_link_ok):
        pytest.skip("symlinks are not available on this platform")

    result = discover(root)
    assert result.symlinks_skipped == 2
    assert result.directories_pruned == 1
    assert manifest_paths(result) == ["real/requirements.txt"]
    assert "linked.txt" not in {source.path for source in result.files}
    skipped = warning(result, WarningCode.SYMLINKS_SKIPPED)
    assert skipped.severity is Severity.INFO
    assert skipped.details["count"] == 2
