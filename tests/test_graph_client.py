"""Graph client tests (offline; FalkorDB driver is mocked)."""

from __future__ import annotations

from unittest.mock import patch

import pytest
from redis.exceptions import ResponseError

from app.graph.client import GraphClient, _translate_driver_error
from app.graph.config import GraphSettings
from app.graph.errors import (
    GraphAuthenticationError,
    GraphError,
    GraphQueryError,
    GraphTimeoutError,
    GraphUnavailableError,
)


class _FakeRedisConnection:
    def ping(self) -> None:
        return None

    def close(self) -> None:
        return None


class _FakeQueryResult:
    def __init__(self, header, rows, run_time_ms=1.0):
        self.header = header
        self._rows = rows
        self.run_time_ms = run_time_ms

    @property
    def result_set(self):
        return self._rows


class _FakeGraph:
    def query(self, q: str, *, params: dict | None = None, timeout: int | None = None):
        return _FakeQueryResult([], [])

    def ro_query(self, q: str, *, params: dict | None = None, timeout: int | None = None):
        return _FakeQueryResult([], [])


class _FakeFalkorDB:
    def __init__(self, *, fail_ping: bool = False, **kwargs: object) -> None:
        self.kwargs = kwargs
        self.connection = _FakeRedisConnection()
        self._fail_ping = fail_ping
        self._closed = False

    def ping(self) -> None:
        if self._fail_ping:
            raise ConnectionError("getaddrinfo() thread failed to start")
        return None

    def close(self) -> None:
        self._closed = True

    def graph(self, name: str) -> _FakeGraph:
        return _FakeGraph()

    def select_graph(self, name: str) -> _FakeGraph:
        return _FakeGraph()


class _ScriptedGraph:
    """Graph stub with scripted RO failures that counts RO vs write calls."""

    def __init__(self, ro_error: Exception | None = None) -> None:
        self.ro_error = ro_error
        self.ro_calls = 0
        self.write_calls = 0

    def ro_query(self, q: str, *, params: dict | None = None, timeout: int | None = None):
        self.ro_calls += 1
        if self.ro_error is not None:
            raise self.ro_error
        return _FakeQueryResult([], [])

    def query(self, q: str, *, params: dict | None = None, timeout: int | None = None):
        self.write_calls += 1
        return _FakeQueryResult([], [[1]])


class _FakeFalkorDBWith(_FakeFalkorDB):
    """FalkorDB stub that always hands out one scripted graph."""

    def __init__(self, scripted: _ScriptedGraph) -> None:
        super().__init__()
        self._scripted = scripted

    def select_graph(self, name: str) -> _ScriptedGraph:
        return self._scripted


def test_client_connect_stores_settings_and_pings() -> None:
    settings = GraphSettings(host="graph.example.test", port=6380, password="pw", database=1)
    with patch("app.graph.client.FalkorDB", side_effect=lambda **kw: _FakeFalkorDB(**kw)) as falkor_mock:
        client = GraphClient(settings)
        assert not client.is_connected
        client.connect()
        assert client.is_connected
        falkor_mock.assert_called_once()
        kwargs = falkor_mock.call_args.kwargs
        assert kwargs["host"] == "graph.example.test"
        assert kwargs["port"] == 6380
        assert kwargs["db"] == 1
        assert kwargs["password"] == "pw"
        assert kwargs.get("ssl", False) is False
        assert client.graph is not None
        client.close()
        assert not client.is_connected


def test_client_connect_ssl_passes_flag() -> None:
    settings = GraphSettings(ssl=True)
    with patch("app.graph.client.FalkorDB", side_effect=lambda **kw: _FakeFalkorDB(**kw)) as falkor_mock:
        client = GraphClient(settings)
        client.connect()
        assert falkor_mock.call_args.kwargs["ssl"] is True
        client.close()


def test_client_connect_without_credentials_omits_them() -> None:
    settings = GraphSettings()
    with patch("app.graph.client.FalkorDB", side_effect=lambda **kw: _FakeFalkorDB(**kw)) as falkor_mock:
        client = GraphClient(settings)
        client.connect()
        kwargs = falkor_mock.call_args.kwargs
        assert "username" not in kwargs
        assert "password" not in kwargs
        client.close()


def test_client_connect_refused_translates_to_unavailable() -> None:
    settings = GraphSettings()
    with patch("app.graph.client.FalkorDB", side_effect=ConnectionRefusedError("refused")):
        client = GraphClient(settings)
        with pytest.raises(GraphUnavailableError):
            client.connect()


def test_client_ping_round_trip() -> None:
    settings = GraphSettings()
    with patch("app.graph.client.FalkorDB", side_effect=lambda **kw: _FakeFalkorDB(**kw)):
        client = GraphClient(settings)
        client.connect()
        assert client.ping() is True
        client.close()


def test_client_ping_failure_returns_false() -> None:
    settings = GraphSettings()
    with patch("app.graph.client.FalkorDB", side_effect=ConnectionError("refused")):
        client = GraphClient(settings)
        with pytest.raises(GraphUnavailableError):
            client.connect()
        # The client never connected, so GraphClient.ping() reports False.
        assert client.ping() is False
        client.close()


def test_client_query_before_connect_raises_unavailable() -> None:
    settings = GraphSettings(host="nonexistent.invalid")
    client = GraphClient(settings)
    with pytest.raises(GraphUnavailableError):
        client.query("RETURN 1 AS ping")


def _empty_graph_response_error() -> Exception:
    """The exact driver error FalkorDB raises for RO queries on a missing graph."""
    return ResponseError("Invalid graph operation on empty key")


def test_client_ro_query_on_missing_graph_retries_without_read_only() -> None:
    graph = _ScriptedGraph(_empty_graph_response_error())
    with patch("app.graph.client.FalkorDB", side_effect=lambda **kw: _FakeFalkorDBWith(graph)):
        client = GraphClient(GraphSettings())
        result = client.query("MATCH (n:Package) WHERE n.id IN $ids RETURN n.id", read_only=True)
        client.close()
    assert result.result_set == [[1]]
    assert graph.ro_calls == 1
    assert graph.write_calls == 1  # exactly one retry, no loop


def test_client_ro_query_on_existing_graph_does_not_retry() -> None:
    graph = _ScriptedGraph()
    with patch("app.graph.client.FalkorDB", side_effect=lambda **kw: _FakeFalkorDBWith(graph)):
        client = GraphClient(GraphSettings())
        result = client.query("MATCH (n) RETURN n", read_only=True)
        client.close()
    assert result.result_set == []
    assert graph.ro_calls == 1
    assert graph.write_calls == 0


def test_client_ro_query_other_query_errors_are_not_retried() -> None:
    graph = _ScriptedGraph(ResponseError("bad cypher syntax"))
    with patch("app.graph.client.FalkorDB", side_effect=lambda **kw: _FakeFalkorDBWith(graph)):
        client = GraphClient(GraphSettings())
        with pytest.raises(GraphQueryError):
            client.query("MATCH (n RETURN n", read_only=True)
        client.close()
    assert graph.ro_calls == 1
    assert graph.write_calls == 0


def test_translate_driver_error_mapps_known_failures() -> None:
    assert isinstance(
        _translate_driver_error(ConnectionRefusedError("refused"), "connect"), GraphUnavailableError
    )
    assert isinstance(
        _translate_driver_error(TimeoutError("timed out"), "query"), GraphTimeoutError
    )
    assert isinstance(
        _translate_driver_error(Exception("authentication failed"), "connect"), GraphAuthenticationError
    )
    assert isinstance(
        _translate_driver_error(Exception("ResponseError: bad cypher syntax"), "query"), GraphQueryError
    )
    assert isinstance(
        _translate_driver_error(ValueError("something odd"), "query"), GraphError
    )


def test_client_context_manager_connects_and_closes() -> None:
    settings = GraphSettings()
    with patch("app.graph.client.FalkorDB", side_effect=lambda **kw: _FakeFalkorDB(**kw)) as falkor_mock:
        with GraphClient(settings) as client:
            assert client.is_connected
        assert falkor_mock.return_value._closed  # type: ignore[attr-defined]
