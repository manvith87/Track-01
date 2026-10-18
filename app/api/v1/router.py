"""Version 1 API router."""

from __future__ import annotations

from fastapi import APIRouter

from app.api.v1.actions import router as actions_router
from app.api.v1.agent import router as agent_router
from app.api.v1.graph import router as graph_router
from app.api.v1.remediation import router as remediation_router
from app.api.v1.repositories import router as repositories_router
from app.api.v1.vulnerabilities import router as vulnerabilities_router

router = APIRouter()
router.include_router(repositories_router)
router.include_router(graph_router)
router.include_router(agent_router)
router.include_router(vulnerabilities_router)
router.include_router(remediation_router)
router.include_router(actions_router)

__all__ = ["router"]
