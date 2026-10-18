"""Health endpoint regression tests (Phase 2 fix).

The ``/health`` probe once always reported ``graph: false`` even while
FalkorDB was up: its ``get_graph_settings()`` call silently raised
``NameError`` inside the broad ``except Exception``.  These tests would have
caught it: a healthy graph client must surface as ``graph: true``, and a
broken one as ``graph: false`` — never ``unknown`` or a 500.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.main import create_app


class ConnectedGraphClient:
    """Stand-in for GraphClient that reports a reachable graph."""

    def __init__(self, settings):  # noqa: ANN001 - matches GraphClient signature
        self.settings = settings

    def ping(self) -> bool:
        return True

    def close(self) -> None:
        pass


class BrokenGraphClient:
    """Stand-in for GraphClient whose ping fails (e.g. DB down)."""

    def __init__(self, settings):  # noqa: ANN001
        self.settings = settings
        from app.graph.errors import GraphUnavailableError

        raise GraphUnavailableError("connection refused")


def make_health_client(monkeypatch: pytest.MonkeyPatch, target: type) -> TestClient:
    monkeypatch.setattr("app.graph.client.GraphClient", target)
    app = create_app(Settings(log_level="ERROR"))
    return TestClient(app)


def test_health_reports_graph_true_when_graph_is_connected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = make_health_client(monkeypatch, ConnectedGraphClient).get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["graph"] is True


def test_health_reports_graph_false_when_graph_is_down(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = make_health_client(monkeypatch, BrokenGraphClient).get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["graph"] is False
    assert body["status"] == "ok"


def test_health_graph_status_is_never_unknown_after_graph_settings_resolution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Regression: a missing get_graph_settings import unnoticed -> 'graph': False."""
    import app.main as main_module

    # Prove the import the handler depends on actually exists on the module.
    assert hasattr(main_module, "get_graph_settings"), (
        "app.main must import get_graph_settings at module level; "
        "if this fails, /health silently degrades to graph=false"
    )
    response = make_health_client(monkeypatch, ConnectedGraphClient).get("/health")
    assert response.json()["graph"] != "unknown"
