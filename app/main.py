"""FastAPI application factory for BlastRadius (Phase 1).

The application is intentionally thin: it exposes the ingestion engine and
translates every failure into one consistent error envelope.
"""

from __future__ import annotations

from collections.abc import Callable

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.api.v1.router import router as v1_router
from app.api.v1.schemas import ErrorDetail, ErrorResponse
from app.core.config import Settings, get_settings
from app.core.errors import BlastRadiusError
from app.core.logging import configure_logging, get_logger, new_request_id, safe_text, set_request_id
from app.graph.config import get_graph_settings
from app.mcp.server import mcp_lifespan, mount_mcp
from app.models.common import ErrorCode, IngestionStage

_log = get_logger("api")

REQUEST_ID_HEADER = "X-Request-ID"


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the FastAPI application."""
    effective = settings or get_settings()
    configure_logging(effective.log_level, json_output=effective.log_json)

    app = FastAPI(
        title=effective.app_name,
        version=effective.app_version,
        description=(
            "BlastRadius Phase 1: safe, read-only ingestion of public GitHub repositories with real Python "
            "dependency extraction (requirements.txt, pyproject.toml, poetry.lock, uv.lock)."
        ),
        # Runs the mounted MCP session manager (see app/mcp/server.py); no-op
        # when no MCP sub-app is mounted.
        lifespan=mcp_lifespan,
    )
    app.state.settings = effective
    app.include_router(v1_router, prefix=effective.api_prefix)
    mount_mcp(app)
    _register_handlers(app)
    _register_middleware(app)

    @app.get("/health", tags=["meta"], summary="Liveness probe")
    def health() -> dict[str, str | bool]:
        graph_status: str | bool = "unknown"
        try:
            from app.graph.client import GraphClient

            graph_client = GraphClient(get_graph_settings())
            graph_status = graph_client.ping()
            graph_client.close()
        except Exception:  # noqa: BLE001 - the probe must never fail the request
            graph_status = False
        return {
            "status": "ok",
            "app": effective.app_name,
            "version": effective.app_version,
            "phase": effective.phase,
            "graph": graph_status,
        }

    return app


def _register_middleware(app: FastAPI) -> None:
    @app.middleware("http")
    async def request_context(request: Request, call_next: Callable):  # type: ignore[no-untyped-def]
        request_id = request.headers.get(REQUEST_ID_HEADER) or new_request_id()
        set_request_id(request_id)
        try:
            response = await call_next(request)
        finally:
            set_request_id(None)
        response.headers[REQUEST_ID_HEADER] = request_id
        return response


def _register_handlers(app: FastAPI) -> None:
    @app.exception_handler(BlastRadiusError)
    async def _blastradius_error_handler(_request: Request, exc: BlastRadiusError) -> JSONResponse:
        _log.warning(
            "request failed code=%s stage=%s http_status=%d message=%s",
            exc.code.value,
            exc.stage.value,
            exc.http_status,
            safe_text(exc.message, 300),
        )
        body = ErrorResponse(
            error=ErrorDetail(
                code=exc.code.value,
                message=exc.message,
                stage=exc.stage.value,
                retryable=exc.retryable,
                details=exc.details,
            )
        )
        return JSONResponse(status_code=exc.http_status, content=body.model_dump(mode="json"))

    @app.exception_handler(RequestValidationError)
    async def _validation_error_handler(_request: Request, exc: RequestValidationError) -> JSONResponse:
        body = ErrorResponse(
            error=ErrorDetail(
                code="invalid_input",
                message="The request body failed validation",
                stage="validation",
                retryable=False,
                details={"errors": _safe_validation_errors(exc)},
            )
        )
        return JSONResponse(status_code=422, content=body.model_dump(mode="json"))

    @app.exception_handler(StarletteHTTPException)
    async def _http_error_handler(_request: Request, exc: StarletteHTTPException) -> JSONResponse:
        body = ErrorResponse(
            error=ErrorDetail(
                code=f"http_{exc.status_code}",
                message=str(exc.detail),
                stage="http",
                retryable=False,
                details={},
            )
        )
        return JSONResponse(status_code=exc.status_code, content=body.model_dump(mode="json"))

    @app.exception_handler(Exception)
    async def _unexpected_error_handler(request: Request, exc: Exception) -> JSONResponse:
        """Answer unexpected bugs with the documented envelope.

        Without this handler Starlette returns a bare ``Internal Server Error``
        text body, which breaks the API's error contract (and hides the
        request id).  The traceback is logged server-side; the client receives
        a stable ``internal_error`` envelope that never echoes internals.
        """
        _log.exception("unhandled error on %s %s", request.method, request.url.path)
        body = ErrorResponse(
            error=ErrorDetail(
                code=ErrorCode.INTERNAL_ERROR.value,
                message="The server encountered an unexpected error",
                stage=IngestionStage.UNKNOWN.value,
                retryable=False,
                details={"exception": type(exc).__name__},
            )
        )
        return JSONResponse(status_code=500, content=body.model_dump(mode="json"))


def _safe_validation_errors(exc: RequestValidationError) -> list[dict[str, str]]:
    """Summarise validation errors without echoing raw user input back."""
    summary: list[dict[str, str]] = []
    for error in exc.errors()[:20]:
        location = ".".join(str(part) for part in error.get("loc", ()))
        summary.append({"location": location, "type": str(error.get("type", "value_error"))})
    return summary


app = create_app()


__all__ = ["app", "create_app"]
