"""Graph client wrapping the FalkorDB Python driver.

The client owns the connection lifecycle and translates driver-level failures
(ConnectionRefused, authentication, timeouts, query errors) into the BlastRadius
error taxonomy.  It is intentionally small and easy to substitute with a test
double.
"""

from __future__ import annotations

from typing import Any, Optional

from falkordb import FalkorDB, Graph
from falkordb.query_result import QueryResult

from app.core.logging import get_logger
from app.graph.config import GraphSettings
from app.graph.errors import (
    GraphAuthenticationError,
    GraphError,
    GraphQueryError,
    GraphTimeoutError,
    GraphUnavailableError,
)

_log = get_logger("graph.client")

#: FalkorDB rejects ``GRAPH.RO_QUERY`` for a graph that has not been created
#: yet (graphs come into existence with the first write query) with this exact
#: message.  Reads against a fresh deployment must see an empty graph, not a
#: query error.
_EMPTY_GRAPH_MESSAGE = "Invalid graph operation on empty key"


def _is_empty_graph_error(exc: BaseException) -> bool:
    """Whether a driver error means "this graph does not exist yet"."""
    return type(exc).__name__ == "ResponseError" and _EMPTY_GRAPH_MESSAGE in str(exc)


def _translate_driver_error(exc: BaseException, operation: str) -> GraphError:
    """Map redis/falkordb driver exceptions to typed graph errors."""
    message = str(exc) or exc.__class__.__name__
    lowered = message.lower()

    if isinstance(exc, GraphError):
        return exc

    # redis.exceptions.AuthenticationError / wrong password
    if "AuthenticationError" in type(exc).__name__ or "authentication" in lowered or "invalid username" in lowered or "no password" in lowered:
        return GraphAuthenticationError(message, details={"operation": operation})

    # redis.exceptions.TimeoutError / socket timeout
    if "TimeoutError" in type(exc).__name__ or "timed out" in lowered or "timeout" in lowered:
        return GraphTimeoutError(message, details={"operation": operation})

    # redis.exceptions.ConnectionError / refused / DNS
    if "ConnectionError" in type(exc).__name__ or "refused" in lowered or "failed to connect" in lowered or "getaddrinfo" in lowered or "network is unreachable" in lowered:
        return GraphUnavailableError(message, details={"operation": operation})

    # falkordb ResponseError / query errors
    if "ResponseError" in type(exc).__name__ or "query" in lowered or "cypher" in lowered or "syntax" in lowered:
        return GraphQueryError(message, details={"operation": operation})

    return GraphError(message, details={"operation": operation, "exception": type(exc).__name__})


class GraphClient:
    """A FalkorDB graph client with explicit connect/close lifecycle.

    The underlying :class:`falkordb.FalkorDB` connection is not established until
    :meth:`connect` is called, so constructing a client never touches the
    network.
    """

    def __init__(self, settings: GraphSettings) -> None:
        self._settings = settings
        self._client: FalkorDB | None = None
        self._graph: Graph | None = None

    # ------------------------------------------------------------------ #
    # lifecycle
    # ------------------------------------------------------------------ #
    def connect(self) -> None:
        """Establish the connection and select the graph.

        Raises:
            GraphUnavailableError: if FalkorDB cannot be reached.
            GraphAuthenticationError: if credentials are rejected.
        """
        if self._client is not None:
            return
        try:
            kwargs: dict[str, object] = {
                "host": self._settings.host,
                "port": self._settings.port,
                "socket_timeout": self._settings.socket_timeout_seconds,
                "socket_connect_timeout": self._settings.socket_connect_timeout_seconds,
            }
            if self._settings.username:
                kwargs["username"] = self._settings.username
            if self._settings.password is not None:
                kwargs["password"] = self._settings.password.get_secret_value()
            if self._settings.database:
                kwargs["db"] = self._settings.database
            if self._settings.ssl:
                kwargs["ssl"] = True

            client = FalkorDB(**kwargs)
            # Force an immediate, cheap round-trip so connectivity problems are
            # surfaced at connect time rather than on first query.
            client.connection.ping()  # type: ignore[attr-defined]
            self._client = client
            self._graph = client.select_graph(self._settings.graph_name)
            _log.info("graph connected %s", self._settings.connection_label)
        except GraphError:
            raise
        except Exception as exc:  # noqa: BLE001 - translate any driver failure
            raise _translate_driver_error(exc, "connect") from exc

    def close(self) -> None:
        """Close the underlying connection, if any."""
        if self._client is not None:
            try:
                self._client.close()  # type: ignore[attr-defined]
            except Exception:  # noqa: BLE001 - close must never raise
                _log.debug("error closing graph connection", exc_info=True)
            self._client = None
            self._graph = None

    @property
    def settings(self) -> GraphSettings:
        """Read-only view of the client configuration."""
        return self._settings

    @property
    def is_connected(self) -> bool:
        return self._client is not None and self._graph is not None

    def ping(self) -> bool:
        """Return True when a round-trip to FalkorDB succeeds right now.

        Uses the underlying Redis connection ping rather than a Cypher query,
        because FalkorDB graphs are created lazily on first write and a query
        against a non-existent graph would fail.
        """
        try:
            self.connect()
            self._client.connection.ping()  # type: ignore[attr-defined]
            return True
        except GraphError:
            return False

    # ------------------------------------------------------------------ #
    # query execution
    # ------------------------------------------------------------------ #
    @property
    def graph(self) -> Graph:
        if self._graph is None:
            raise GraphUnavailableError("Graph client is not connected", details={"operation": "graph"})
        return self._graph

    def query(
        self,
        cypher: str,
        *,
        params: Optional[dict[str, object]] = None,
        timeout: Optional[int] = None,
        read_only: bool = False,
    ) -> QueryResult:
        """Run a parameterised Cypher query.

        Values are never interpolated into the Cypher string: they are passed as
        driver parameters.  The client connects lazily on the first query.

        Raises:
            GraphUnavailableError: if the database cannot be reached.
            GraphAuthenticationError: if credentials are rejected.
            GraphTimeoutError: if the query times out.
            GraphQueryError: if the query itself fails.
        """
        if self._graph is None:
            self.connect()
        if self._graph is None:
            raise GraphUnavailableError("Graph client could not connect", details={"operation": "query"})
        try:
            if read_only:
                try:
                    return self._graph.ro_query(cypher, params=params, timeout=timeout)
                except GraphError:
                    raise
                except Exception as exc:  # noqa: BLE001 - translate any driver failure
                    if not _is_empty_graph_error(exc):
                        raise
                    # The graph does not exist yet, so run the same statement
                    # without the read-only flag: the graph is created empty
                    # and the caller receives an empty result set (instead of
                    # a misleading query error).  The statement is unchanged,
                    # so no caller data is modified.
                    return self._graph.query(cypher, params=params, timeout=timeout)
            return self._graph.query(cypher, params=params, timeout=timeout)
        except GraphError:
            raise
        except Exception as exc:  # noqa: BLE001 - translate any driver failure
            raise _translate_driver_error(exc, "query") from exc

    def __enter__(self) -> "GraphClient":
        self.connect()
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


__all__ = ["GraphClient"]
