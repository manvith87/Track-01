"""Shared pytest fixtures.

Every fixture is offline and deterministic: fakes are injected through the same
seams the production code exposes (``ingest_repository(..., retriever=...,
api_client=...)`` and FastAPI's dependency overrides).
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:  # pytest already inserts it with python -m pytest
    sys.path.insert(0, str(ROOT))

from app.core.config import Settings  # noqa: E402
from app.models.ingestion import IngestionResult  # noqa: E402
from tests.support import (  # noqa: E402
    CLEAN_REPOSITORY,
    FakeRetriever,
    StubGitHubClient,
    make_settings,
    write_tree,
)


@pytest.fixture
def settings_factory(tmp_path):
    """Factory for isolated Settings objects with a temporary working root."""

    def factory(**overrides):
        work_root = overrides.pop("temp_root", None) or tmp_path / "blastradius-tmp"
        return make_settings(temp_root=work_root, **overrides)

    return factory


@pytest.fixture
def settings(settings_factory) -> Settings:
    return settings_factory()


@pytest.fixture
def clean_repository_tree(tmp_path) -> Path:
    """The clean fixture repository written to disk."""
    root = tmp_path / "clean-repo"
    write_tree(root, CLEAN_REPOSITORY)
    return root


@pytest.fixture
def stub_client() -> StubGitHubClient:
    return StubGitHubClient()


@pytest.fixture
def fake_retriever() -> FakeRetriever:
    return FakeRetriever(CLEAN_REPOSITORY)


@pytest.fixture(scope="module")
def canned_ingestion_result(tmp_path_factory) -> IngestionResult:
    """A real ingestion run over the fake retriever, reused by the API tests."""
    from app.ingestion.service import ingest_repository

    work_root = tmp_path_factory.mktemp("canned-work")
    settings = make_settings(temp_root=work_root)
    return ingest_repository(
        "https://github.com/example/clean",
        settings=settings,
        retriever=FakeRetriever(CLEAN_REPOSITORY),
        api_client=StubGitHubClient(),
    )
