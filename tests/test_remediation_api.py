"""HTTP contract tests for the Phase 5 read-only API.

The real ``RemediationService`` is wired through FastAPI's dependency override
to a ``FakeGraphClient``; the tests assert the versioned routes, pagination,
error envelopes and that caller-supplied advisory data is never accepted.
"""

from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient

from app.api.deps import get_remediation_service
from app.core.config import Settings
from app.main import create_app
from app.models.ids import stable_id
from app.remediation.service import RemediationService
from tests.remediation_support import (
    ANALYSIS,
    PKG_REQUESTS,
    VULN_REQUESTS,
    install,
    make_service,
)
from tests.support import FakeGraphClient

BASE = f"/api/v1/analyses/{ANALYSIS}"
FINDING_ID = stable_id("finding", ANALYSIS, PKG_REQUESTS, VULN_REQUESTS)
GROUP_ID = stable_id("fixgroup", ANALYSIS, PKG_REQUESTS, "2.32.1")


def _installed_service(**kwargs: Any) -> RemediationService:
    client = FakeGraphClient()
    install(client, **kwargs)
    return make_service(client)


def _client(service: RemediationService | None = None) -> TestClient:
    app = create_app(Settings(log_level="ERROR"))
    app.dependency_overrides[get_remediation_service] = (
        lambda: service if service is not None else _installed_service()
    )
    return TestClient(app)


# ---------------------------------------------------------------------------
# ranked findings
# ---------------------------------------------------------------------------

def test_list_findings_returns_ranked_priorities() -> None:
    response = _client().get(f"{BASE}/findings")
    assert response.status_code == 200
    body = response.json()

    assert body["analysis_id"] == ANALYSIS
    assert body["count"] == 2
    assert body["total"] == 2
    assert body["skip"] == 0
    assert body["limit"] == 50
    assert body["analysis_context"]["complete"] is True
    assert [finding["priority"]["rank"] for finding in body["findings"]] == [1, 2]
    assert body["findings"][0]["package"]["package_name"] == "requests"
    assert body["findings"][0]["priority"]["score"] == 79.2
    assert body["findings"][0]["priority"]["formula_version"] == "blastradius-priority-v1"
    assert body["findings"][0]["vulnerability_id"] == VULN_REQUESTS

    # The custom score and advisory severity are separate; no field pretends
    # the BlastRadius score is a CVSS score.
    priority = body["findings"][0]["priority"]
    assert "cvss_score" not in priority
    assert priority["severity"]["numeric_score"] == 9.8
    assert priority["score"] != priority["severity"]["numeric_score"]
    assert [factor["name"] for factor in priority["factors"]] == [
        "severity",
        "reachability",
        "impact",
        "remediation",
    ]
    assert body["limitations"] == ["reachability_traversal_bounded_at_5_hops"]


def test_list_findings_paginates_deterministically() -> None:
    response = _client().get(f"{BASE}/findings", params={"skip": 1, "limit": 1})
    assert response.status_code == 200
    body = response.json()
    assert body["count"] == 1
    assert body["total"] == 2
    assert body["skip"] == 1
    assert body["limit"] == 1
    assert body["findings"][0]["vulnerability_id"] != VULN_REQUESTS


def test_findings_pagination_bounds_are_validated() -> None:
    client = _client()
    for params in ({"skip": -1}, {"limit": 0}, {"limit": 501}):
        response = client.get(f"{BASE}/findings", params=params)
        assert response.status_code == 422
        body = response.json()
        assert body["error"]["code"] == "invalid_input"
        assert body["error"]["stage"] == "validation"


def test_finding_detail_exposes_every_factor_and_remediation_plan() -> None:
    response = _client().get(f"{BASE}/findings/{FINDING_ID}")
    assert response.status_code == 200
    body = response.json()

    finding = body["finding"]
    assert finding["finding_id"] == FINDING_ID
    assert finding["priority"]["rank"] == 1
    assert finding["priority"]["severity"]["numeric_score"] == 9.8
    assert finding["priority"]["reachability"]["status"] == "direct"
    assert finding["priority"]["remediation_available"] is True
    assert all("notes" in factor and "raw" in factor for factor in finding["priority"]["factors"])

    remediation = body["remediation"]
    assert remediation["package_id"] == PKG_REQUESTS
    assert remediation["current_version"] == "2.32.0"
    assert remediation["candidates"][0]["selected"] is True
    assert remediation["candidates"][0]["proposed_version"] == "2.32.1"
    assert remediation["candidates"][0]["resolver_executed"] is False
    assert body["limitations"] == ["reachability_traversal_bounded_at_5_hops"]


def test_unknown_finding_returns_the_error_envelope() -> None:
    response = _client().get(f"{BASE}/findings/finding_missing")
    assert response.status_code == 404
    body = response.json()
    assert body["error"]["code"] == "repository_not_found"
    assert body["error"]["details"] == {
        "analysis_id": ANALYSIS,
        "finding_id": "finding_missing",
    }


# ---------------------------------------------------------------------------
# remediation candidates
# ---------------------------------------------------------------------------

def test_candidates_endpoint_returns_per_package_plans() -> None:
    response = _client().get(f"{BASE}/remediation/candidates")
    assert response.status_code == 200
    body = response.json()

    assert body["count"] == 2
    assert body["total"] == 2
    assert [plan["package_name"] for plan in body["plans"]] == ["requests", "urllib3"]
    requests_plan = body["plans"][0]
    assert requests_plan["candidates"][0]["proposed_version"] == "2.32.1"
    assert requests_plan["candidates"][0]["compatibility"] == "constraints_satisfied"
    assert requests_plan["candidates"][0]["resolver_executed"] is False
    assert requests_plan["candidates"][0]["constraint_checks"]
    assert requests_plan["candidates"][0]["resolves"][0]["status"] == "resolves"
    assert body["plans"][1]["candidates"][0]["compatibility"] == "unverified"


def test_candidates_pagination_is_validated() -> None:
    client = _client()
    response = client.get(f"{BASE}/remediation/candidates", params={"limit": 201})
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "invalid_input"
    response = client.get(f"{BASE}/remediation/candidates", params={"skip": -1})
    assert response.status_code == 422


# ---------------------------------------------------------------------------
# fix groups
# ---------------------------------------------------------------------------

def test_groups_endpoint_returns_ranked_verified_metrics() -> None:
    response = _client().get(f"{BASE}/remediation/groups")
    assert response.status_code == 200
    body = response.json()

    assert body["count"] == 2
    assert body["total"] == 2
    assert [group["package_name"] for group in body["groups"]] == ["requests", "urllib3"]
    first = body["groups"][0]
    assert first["group_id"] == GROUP_ID
    assert first["coverage"] == "confirmed_advisory"
    assert first["ranking"]["rank"] == 1
    assert first["ranking"]["verified_resolved_count"] == 1
    assert first["ranking"]["verified_resolved_priority_sum"] == 79.2
    assert first["ranking"]["compatibility_tier_label"] == "constraints_satisfied"
    assert first["advisory_evidence"][0]["vulnerability_id"] == VULN_REQUESTS
    assert body["unresolved_findings"] == []
    assert body["unresolved_findings_truncated"] is False


def test_group_detail_returns_evidence_and_compatibility_checks() -> None:
    response = _client().get(f"{BASE}/remediation/groups/{GROUP_ID}")
    assert response.status_code == 200
    body = response.json()

    group = body["group"]
    assert group["group_id"] == GROUP_ID
    assert group["package_name"] == "requests"
    assert group["candidates"][0]["selected"] is True
    assert group["constraint_checks"][0]["satisfied"] is True
    assert group["unresolved_relationships"] == []
    assert body["limitations"] == ["reachability_traversal_bounded_at_5_hops"]


def test_groups_pagination_and_unknown_group_errors() -> None:
    client = _client()
    response = client.get(f"{BASE}/remediation/groups", params={"limit": 201})
    assert response.status_code == 422
    response = client.get(f"{BASE}/remediation/groups", params={"skip": -1})
    assert response.status_code == 422

    response = client.get(f"{BASE}/remediation/groups/group_missing")
    assert response.status_code == 404
    body = response.json()
    assert body["error"]["code"] == "repository_not_found"
    assert body["error"]["details"] == {
        "analysis_id": ANALYSIS,
        "group_id": "group_missing",
    }


# ---------------------------------------------------------------------------
# read-only guarantees and caller-supplied data rejection
# ---------------------------------------------------------------------------

def test_caller_supplied_severity_or_fixed_version_is_rejected() -> None:
    client = _client()
    response = client.get(
        f"{BASE}/findings",
        params={
            "severity": "10.0",
            "cvss": "10.0",
            "fixed_version": "99.9.9",
            "cve": "CVE-9999-0000",
        },
    )
    assert response.status_code == 400
    body = response.json()
    assert body["error"]["code"] == "invalid_input"
    details = body["error"]["details"]
    assert sorted(details["unsupported_query_parameters"]) == [
        "cve",
        "cvss",
        "fixed_version",
        "severity",
    ]
    assert details["allowed_query_parameters"] == ["limit", "skip"]

    # Detail routes accept no query parameters at all.
    for path in (
        f"{BASE}/findings/{FINDING_ID}",
        f"{BASE}/remediation/groups/{GROUP_ID}",
    ):
        response = client.get(path, params={"fixed_version": "99.9.9"})
        assert response.status_code == 400
        assert response.json()["error"]["code"] == "invalid_input"


def test_mutation_methods_are_not_exposed() -> None:
    client = _client()
    for path in (
        f"{BASE}/findings",
        f"{BASE}/findings/{FINDING_ID}",
        f"{BASE}/remediation/candidates",
        f"{BASE}/remediation/groups",
        f"{BASE}/remediation/groups/{GROUP_ID}",
    ):
        response = client.post(path, json={"fixed_version": "99.9.9"})
        assert response.status_code == 405
        assert response.json()["error"]["code"] == "http_405"


def test_unknown_analysis_returns_404() -> None:
    client = FakeGraphClient()
    client.connect()
    service = make_service(client)
    response = _client(service).get(f"{BASE}/findings")
    assert response.status_code == 404
    body = response.json()
    assert body["error"]["code"] == "repository_not_found"
    assert body["error"]["details"] == {"analysis_id": ANALYSIS}


def test_openapi_documents_the_five_read_only_routes() -> None:
    app = create_app(Settings(log_level="ERROR"))
    schema = app.openapi()
    expected = {
        f"/api/v1/analyses/{{analysis_id}}/findings": "get",
        f"/api/v1/analyses/{{analysis_id}}/findings/{{finding_id}}": "get",
        f"/api/v1/analyses/{{analysis_id}}/remediation/candidates": "get",
        f"/api/v1/analyses/{{analysis_id}}/remediation/groups": "get",
        f"/api/v1/analyses/{{analysis_id}}/remediation/groups/{{group_id}}": "get",
    }
    for path, method in expected.items():
        assert path in schema["paths"]
        assert method in schema["paths"][path]
