"""Repository endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from app.api.deps import IngestionCallable, get_app_settings, get_ingestion_service
from app.api.v1.schemas import (
    RepositoryIngestRequest,
    RepositoryIngestResponse,
    SupportedFormatInfo,
    supported_formats,
)
from app.core.config import Settings
from app.core.logging import get_logger

_log = get_logger("api.repositories")

router = APIRouter(prefix="/repositories", tags=["repositories"])


@router.post(
    "/ingest",
    response_model=RepositoryIngestResponse,
    summary="Ingest a public GitHub repository and extract its Python dependencies",
    responses={
        400: {"description": "Invalid, unsupported or unsafe repository URL / reference"},
        403: {"description": "Repository is not public"},
        404: {"description": "Repository or reference not found"},
        413: {"description": "Repository exceeds the configured size limit"},
        422: {"description": "Unsafe repository content or unparsable request"},
        429: {"description": "GitHub API rate limit exceeded"},
        502: {"description": "Retrieval failed (network, Git, archive)"},
        504: {"description": "Retrieval or ingestion timed out"},
    },
)
def ingest_repository_endpoint(
    payload: RepositoryIngestRequest,
    settings: Settings = Depends(get_app_settings),
    service: IngestionCallable = Depends(get_ingestion_service),
) -> RepositoryIngestResponse:
    """Run the ingestion pipeline for one repository revision.

    The endpoint is synchronous on purpose: retrieval and parsing are bounded by
    configured timeouts, and FastAPI runs it in a worker thread so the event
    loop is never blocked. Failures raise typed errors which the application
    error handlers translate into the documented error envelope.
    """
    result = service(payload.repository_url, payload.ref, settings=settings)
    return RepositoryIngestResponse.from_result(result, settings)


@router.get(
    "/formats",
    response_model=list[SupportedFormatInfo],
    summary="List the dependency formats this build parses",
)
def list_supported_formats() -> list[SupportedFormatInfo]:
    """Report the real parser coverage of this build (no aspirational formats)."""
    return supported_formats()


__all__ = ["router"]
