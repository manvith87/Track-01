"""Opt-in live test: one real, read-only ingestion of a public repository.

Enable it with::

    $env:BLASTRADIUS_RUN_LIVE_TESTS = "1"       # PowerShell
    python -m pytest tests/test_live_github.py -m live -s

Anonymous GitHub API access is limited to 60 requests/hour; set
``BLASTRADIUS_GITHUB_TOKEN`` to raise the limit.  The token is only ever sent
as an ``Authorization`` header to api.github.com and is never handed to Git.
Override the sample repository with ``BLASTRADIUS_LIVE_REPOSITORY``.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

import pytest

from app.core.config import Settings
from app.ingestion.service import ingest_repository

pytestmark = pytest.mark.live

LIVE = os.environ.get("BLASTRADIUS_RUN_LIVE_TESTS") == "1"
REPOSITORY_URL = os.environ.get("BLASTRADIUS_LIVE_REPOSITORY", "https://github.com/psf/requests")

skip_unless_enabled = pytest.mark.skipif(
    not LIVE,
    reason="live GitHub test: set BLASTRADIUS_RUN_LIVE_TESTS=1 to enable",
)


def live_settings(tmp_path: Path) -> Settings:
    return Settings(
        log_level="WARNING",
        temp_root=tmp_path / "live-work",
        git_timeout_seconds=180.0,
        download_timeout_seconds=120.0,
        metadata_timeout_seconds=30.0,
        max_ingestion_seconds=420.0,
        github_token=os.environ.get("BLASTRADIUS_GITHUB_TOKEN") or None,
    )


@skip_unless_enabled
def test_live_ingestion_of_a_public_repository(tmp_path: Path) -> None:
    settings = live_settings(tmp_path)
    result = ingest_repository(REPOSITORY_URL, settings=settings)

    # --- provenance: the exact analysed commit is recorded everywhere ----
    identity = result.repository.identity
    assert identity.canonical_id == "github.com/psf/requests"
    sha = result.reference.resolved_commit_sha
    assert re.fullmatch(r"[0-9a-f]{40}", sha or ""), f"unexpected commit sha: {sha!r}"
    assert result.summary.commit_sha == sha
    assert result.repository.commit.sha == sha
    assert result.reference.resolved_via in {"github_api", "git_ls_remote", "provided_commit_sha"}
    assert result.summary.retrieval_strategy in {"git", "archive"}

    # --- real dependency content was extracted ---------------------------
    assert result.status.value in {"success", "partial"}
    assert len(result.manifests) >= 1
    assert len(result.declarations) >= 3
    names = {declaration.normalized_name for declaration in result.declarations}
    assert {"urllib3", "idna"} & names, f"unexpected declarations: {sorted(names)}"

    # Versions are only ever reported when a source states them.
    for declaration in result.declarations:
        assert declaration.resolved_version is None or declaration.resolved_from is not None

    loaded_formats = {record.format.value for record in result.manifests if record.format is not None}
    assert loaded_formats & {"requirements.txt", "pyproject.toml"}

    # --- temporary working directories are gone --------------------------
    work_root = settings.temp_root
    assert work_root is not None
    assert not work_root.exists() or list(work_root.iterdir()) == []

    print(
        f"live ingestion ok: {identity.canonical_id}@{sha[:12]} "
        f"status={result.status.value} strategy={result.summary.retrieval_strategy} "
        f"manifests={len(result.manifests)} declarations={len(result.declarations)} "
        f"resolved_packages={len(result.resolved_packages)} edges={len(result.dependency_edges)} "
        f"warnings={len(result.warnings)} errors={len(result.errors)}"
    )
