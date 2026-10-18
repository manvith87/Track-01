"""Vulnerability graph persistence tests (offline, FakeGraphClient).

Covers: Vulnerability node upserts, AFFECTED_BY edges with endpoint
enforcement and scope stamping, idempotent re-runs (no duplicates), missing
endpoints skipping (never fabricating), and graph reads including 404s.
"""

from __future__ import annotations

from typing import Any

import pytest

from app.graph.service import GraphService
from app.graph.vulnerability import VulnerabilityGraphService
from app.osv.models import decode_vulnerability
from app.osv.service import OsvConfirmedMatch
from tests.support import FakeGraphClient, raw_osv_record


def vuln_from_raw(osv_id: str = "GHSA-v1", **overrides: Any):
    record = raw_osv_record(osv_id, **overrides)
    return decode_vulnerability(record)


def match(
    vulnerability_id: str = "GHSA-v1",
    *,
    package_name: str = "requests",
    package_version: str = "2.3.0",
    fixed: tuple[str, ...] = ("2.20.0",),
) -> OsvConfirmedMatch:
    return OsvConfirmedMatch(
        vulnerability_id=vulnerability_id,
        ecosystem="pypi",
        upstream_ecosystem="PyPI",
        package_name=package_name,
        package_version=package_version,
        match_type="version",
        fixed_versions=fixed,
        ranges_json='[{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]',
        osv_modified="2024-05-01T00:00:00Z",
    )


def seed_package(service: VulnerabilityGraphService, client: FakeGraphClient, *, repository_id: str, commit_sha: str, name: str = "requests", version: str = "2.3.0") -> str:
    graph = GraphService(client)
    package_id = GraphService.package_id(repository_id, commit_sha, name, version)
    graph._upsert_node(
        "Package",
        {
            "id": package_id,
            "repository_id": repository_id,
            "commit_sha": commit_sha,
            "original_name": name,
            "normalized_name": name,
            "ecosystem": "pypi",
            "version": version,
        },
        now="2024-06-01T00:00:00+00:00",
    )
    return package_id


def make_service() -> tuple[VulnerabilityGraphService, FakeGraphClient]:
    client = FakeGraphClient()
    return VulnerabilityGraphService(client), client


REPO = "github.com/example/demo"
SHA = "a" * 40


def test_record_vulnerabilities_writes_nodes_and_edges() -> None:
    service, client = make_service()
    package_id = seed_package(service, client, repository_id=REPO, commit_sha=SHA)

    record = vuln_from_raw(
        aliases=["CVE-2023-0001"],
        severity=[{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N"}],
        references=[{"type": "WEB", "url": "https://example.test/advisory"}],
    )
    summary = service.record_vulnerabilities(
        [record],
        [match().model_dump() | {"repository_id": REPO, "commit_sha": SHA}],
        repository_id=REPO,
        commit_sha=SHA,
    )

    assert summary.vulnerabilities_created == 1
    assert summary.edges_created == 1
    assert client.affected_by[(package_id, "GHSA-v1")]["match_type"] == "version"
    assert client.affected_by[(package_id, "GHSA-v1")]["fixed_versions"] == ["2.20.0"]
    assert client.affected_by[(package_id, "GHSA-v1")]["package_name"] == "requests"
    stored = client.nodes["Vulnerability"]["GHSA-v1"]
    assert stored["source"] == "osv"
    assert stored["aliases"] == ["CVE-2023-0001"]
    assert stored["affected_packages"] == ["PyPI:requests"]
    assert stored["severities"] == ["CVSS_V3 CVSS:3.1/AV:N"]
    assert stored["references"] == ["WEB https://example.test/advisory"]


def test_record_vulnerabilities_is_idempotent_on_repeated_runs() -> None:
    service, client = make_service()
    seed_package(service, client, repository_id=REPO, commit_sha=SHA)
    first = service.record_vulnerabilities(
        [vuln_from_raw()],
        [match().model_dump() | {"repository_id": REPO, "commit_sha": SHA}],
        repository_id=REPO, commit_sha=SHA,
    )
    assert (first.vulnerabilities_created, first.edges_created) == (1, 1)

    second = service.record_vulnerabilities(
        [vuln_from_raw()],
        [match().model_dump() | {"repository_id": REPO, "commit_sha": SHA}],
        repository_id=REPO, commit_sha=SHA,
    )
    assert (second.vulnerabilities_created, second.edges_created) == (0, 0)
    assert (second.vulnerabilities_updated, second.edges_updated) == (1, 1)
    assert len(client.affected_by) == 1
    assert len(client.nodes["Vulnerability"]) == 1


def test_record_vulnerabilities_preserves_existing_metadata_when_upstream_lacks_it() -> None:
    service, client = make_service()
    seed_package(service, client, repository_id=REPO, commit_sha=SHA)
    rich = vuln_from_raw(aliases=["CVE-2023-0001"])
    service.record_vulnerabilities(
        [rich],
        [match().model_dump() | {"repository_id": REPO, "commit_sha": SHA}],
        repository_id=REPO, commit_sha=SHA,
    )
    # Same record id with no aliases at all on the second run.
    bare = decode_vulnerability({"id": "GHSA-v1", "modified": "2024-06-01T00:00:00Z"})
    service.record_vulnerabilities(
        [bare],
        [match().model_dump() | {"repository_id": REPO, "commit_sha": SHA}],
        repository_id=REPO, commit_sha=SHA,
    )
    stored = client.nodes["Vulnerability"]["GHSA-v1"]
    assert stored["aliases"] == ["CVE-2023-0001"]  # kept, never overwritten with missing data


def test_record_vulnerabilities_skips_edges_without_graph_endpoints() -> None:
    service, client = make_service()
    # The package node was never persisted: the edge must be skipped, not fabricated.
    summary = service.record_vulnerabilities(
        [vuln_from_raw()],
        [match(package_version="9.9.9").model_dump() | {"repository_id": REPO, "commit_sha": SHA}],
        repository_id=REPO, commit_sha=SHA,
    )
    assert summary.edges_created == 0
    assert summary.skipped_edges == 1
    assert client.affected_by == {}


def test_record_vulnerabilities_scopes_edges_per_repository() -> None:
    service, client = make_service()
    seed_package(service, client, repository_id=REPO, commit_sha="b" * 40)
    summary = service.record_vulnerabilities(
        [vuln_from_raw()],
        [match().model_dump() | {"repository_id": REPO, "commit_sha": SHA}],
        repository_id=REPO,
        commit_sha=SHA,  # mismatch: package exists only at "b" * 40
    )
    assert summary.edges_created == 0
    assert summary.skipped_edges == 1


def test_non_osv_extra_records_are_stamped_with_source() -> None:
    service, client = make_service()
    record = decode_vulnerability({"id": "CVE-2024-9999"})
    seed_package(service, client, repository_id=REPO, commit_sha=SHA)
    service.record_vulnerabilities(
        [record],
        [],
        repository_id=REPO,
        commit_sha=SHA,
    )
    stored = client.nodes["Vulnerability"]["CVE-2024-9999"]
    assert stored["source"] == "osv"
    assert "aliases" not in stored  # missing metadata is absent, not invented


def test_get_vulnerability_missing_raises_record_not_found() -> None:
    from app.graph.errors import GraphRecordNotFoundError

    service, _client = make_service()
    with pytest.raises(GraphRecordNotFoundError):
        service.get_vulnerability("GHSA-nope")


def test_get_vulnerability_returns_canned_record() -> None:
    from app.graph.queries import GET_VULNERABILITY
    from tests.support import FakeQueryResult

    service, client = make_service()
    client.canned[GET_VULNERABILITY] = FakeQueryResult(
        ["id", "summary", "aliases"], [["GHSA-v1", "bad widget", ["CVE-1"]]]
    )
    detail = service.get_vulnerability("GHSA-v1")
    assert detail["id"] == "GHSA-v1"
    assert detail["summary"] == "bad widget"
    assert detail["aliases"] == ["CVE-1"]


def test_impact_paths_template_depth_bounds() -> None:
    from app.graph.queries import MAX_IMPACT_DEPTH, impact_paths_template

    # Depths 0..MAX_IMPACT_DEPTH are accepted and produce an inlined integer.
    for depth in (0, 1, MAX_IMPACT_DEPTH):
        template = impact_paths_template(depth)
        assert f"*0..{depth}" in template
        assert "$analysis_id" in template and "$skip" in template and "$limit" in template
    # Out-of-range depths are refused: never interpolated into a query.
    with pytest.raises(ValueError, match="must be in \\[0, 5\\]"):
        impact_paths_template(MAX_IMPACT_DEPTH + 1)
    with pytest.raises(ValueError, match="must be an integer"):
        impact_paths_template("three")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="must be an integer"):
        impact_paths_template(None)  # type: ignore[arg-type]


def test_record_vulnerabilities_skips_edges_without_vulnerability_endpoint() -> None:
    # Edge references a vulnerability that is NOT among the records being
    # written: its endpoint is missing, so the edge is skipped, not fabricated.
    service, client = make_service()
    seed_package(service, client, repository_id=REPO, commit_sha=SHA)
    summary = service.record_vulnerabilities(
        [vuln_from_raw("GHSA-v1")],
        [match(vulnerability_id="GHSA-v2").model_dump() | {"repository_id": REPO, "commit_sha": SHA}],
        repository_id=REPO,
        commit_sha=SHA,
    )
    assert summary.edges_created == 0
    assert summary.skipped_edges == 1
    assert client.affected_by == {}


def test_get_vulnerability_components_returns_rows_with_scope() -> None:
    from app.graph.queries import GET_VULNERABILITY_COMPONENTS
    from tests.support import FakeQueryResult

    service, client = make_service()
    client.canned[GET_VULNERABILITY_COMPONENTS] = FakeQueryResult(
        [
            "package_id",
            "package_name",
            "package_version",
            "ecosystem",
            "repository_id",
            "commit_sha",
            "match_type",
            "fixed_versions",
            "last_synced_at",
        ],
        [
            [
                "pkg_1",
                "requests",
                "2.31.0",
                "pypi",
                "github.com/repo/one",
                "c1" * 40,
                "version",
                '["2.32.0"]',
                "2024-05-01T00:00:00Z",
            ],
            [
                "pkg_2",
                "requests",
                "2.31.0",
                "pypi",
                "github.com/repo/two",
                "c2" * 40,
                "version",
                '["2.32.0"]',
                "2024-05-01T00:00:00Z",
            ],
        ],
    )
    components = service.get_vulnerability_components("GHSA-v1")
    assert components["count"] == 2
    repos = {row["repository_id"] for row in components["rows"]}
    # The detail endpoint is intentionally cross-repository: rows name their own
    # scope so callers can filter per analysis.
    assert repos == {"github.com/repo/one", "github.com/repo/two"}