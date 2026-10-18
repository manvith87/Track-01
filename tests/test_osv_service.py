"""OSV orchestration service tests (offline, scriptable fake client).

Covers: version-confirmed discovery via batch, per-item pagination
continuation, PyPI name-spelling fallback, hydration failures, records that
do not declare the queried package, name-only handling, capability caps and
total-upstream-failure semantics.
"""

from __future__ import annotations

from typing import Any

import pytest

from app.core.errors import InputValidationError
from app.osv.errors import OsvRecordNotFoundError, OsvUnavailableError
from app.osv.service import (
    MATCH_TYPE_NAME,
    MATCH_TYPE_VERSION,
    OsvPackageItem,
    OsvService,
    STATUS_CONFIRMED,
    STATUS_NAME_ONLY,
)
from tests.support import FakeOsvClient, make_osv_settings, raw_osv_record

RECORD_A = "GHSA-aaaa-bbbb-cccc"
RECORD_B = "GHSA-dddd-eeee-ffff"


def make_service(client: FakeOsvClient, **overrides: Any) -> OsvService:
    return OsvService(client, make_osv_settings(**overrides))


def item(name: str, version: str | None, original: str | None = None, ecosystem: str = "pypi") -> OsvPackageItem:
    return OsvPackageItem(
        ecosystem=ecosystem,
        package_name=name,
        original_name=original,
        version=version,
    )


# ---------------------------------------------------------------------------
# batched discovery, hydration and evidence
# ---------------------------------------------------------------------------
def test_sync_builds_confirmed_matches_for_multiple_items() -> None:
    client = FakeOsvClient(
        batch_results=[[{"vulns": [{"id": RECORD_A}]}, {"vulns": [{"id": RECORD_B}]}][-1:]],
        records={
            RECORD_A: raw_osv_record(RECORD_A, fixed="2.20.0", modified="2024-05-01T00:00:00Z"),
            RECORD_B: raw_osv_record(RECORD_B, name="jinja2", fixed="2.11.3", modified="2024-05-02T00:00:00Z"),
        },
    )
    # Replay the same batch for the single call under test.
    client._batch_results = [
        [{"vulns": [{"id": RECORD_A}]}, {"vulns": [{"id": RECORD_B}]}]
    ]
    service = make_service(client)
    report = service.sync(
        [
            item("requests", "2.30.0"),
            item("jinja2", "2.11.3"),
        ]
    )

    assert report.status == "completed"
    assert report.errors == ()
    assert report.items_scanned == 2
    assert report.items_with_matches == 2
    assert len(client.batch_calls) == 1
    sent = client.batch_calls[0]
    assert sent == [
        {"package": {"name": "requests", "ecosystem": "PyPI"}, "version": "2.30.0"},
        {"package": {"name": "jinja2", "ecosystem": "PyPI"}, "version": "2.11.3"},
    ]
    assert set(client.get_calls) == {RECORD_A, RECORD_B}

    by_id = {match.vulnerability_id: match for match in report.matches}
    assert set(by_id) == {RECORD_A, RECORD_B}
    match_a = by_id[RECORD_A]
    assert match_a.package_name == "requests"
    assert match_a.package_version == "2.30.0"
    assert match_a.ecosystem == "pypi"
    assert match_a.upstream_ecosystem == "PyPI"
    assert match_a.match_type == MATCH_TYPE_VERSION
    assert match_a.fixed_versions == ("2.20.0",)
    assert match_a.osv_modified == "2024-05-01T00:00:00Z"
    # Ranges evidence is machine-readable JSON containing the fixed event.
    assert '"fixed": "2.20.0"' in match_a.ranges_json
    assert len(report.vulnerabilities) == 2
    assert all(vuln.id in {RECORD_A, RECORD_B} for vuln in report.vulnerabilities)


def test_sync_handles_items_without_vulnerabilities() -> None:
    client = FakeOsvClient(
        batch_results=[[{"vulns": [{"id": RECORD_A}]}, {"vulns": []}]],
        records={RECORD_A: raw_osv_record(RECORD_A)},
    )
    report = make_service(client).sync([item("requests", "2.30.0"), item("clean-pkg", "1.0.0")])
    assert report.items_with_matches == 1
    assert report.items_without_matches == 1
    statuses = {o.package_name: o.status for o in report.outcomes}
    assert statuses == {"requests": STATUS_CONFIRMED, "clean-pkg": "no_matches"}


def test_sync_follows_per_item_pagination_from_batch() -> None:
    client = FakeOsvClient(
        batch_results=[[{"vulns": [{"id": RECORD_A}], "next_page_token": "tok-2"}]],
        records={
            RECORD_A: raw_osv_record(RECORD_A, fixed="2.20.0"),
            RECORD_B: raw_osv_record(RECORD_B, name="requests", fixed="2.31.0"),
        },
    )

    def extra_page(**kwargs: Any) -> dict[str, list[dict[str, str]]]:
        return {"vulns": [{"id": RECORD_B}]}

    client.query_vulnerabilities = extra_page  # type: ignore[method-assign]
    report = make_service(client).sync([item("requests", "2.30.0")])
    assert report.matches and {m.vulnerability_id for m in report.matches} == {RECORD_A, RECORD_B}
    assert report.outcomes[0].vulnerability_ids == (RECORD_A, RECORD_B)


def test_sync_respects_pagination_cap_and_never_loops_forever() -> None:
    # The upstream advertises an endless next_page_token: the configured page
    # cap, not the upstream, must bound discovery.
    client = FakeOsvClient(
        batch_results=[[{"vulns": [{"id": RECORD_A}], "next_page_token": "tok-2"}]],
        records={
            RECORD_A: raw_osv_record(RECORD_A, fixed="2.20.0"),
            RECORD_B: raw_osv_record(RECORD_B, name="requests", fixed="2.31.0"),
        },
    )

    def never_ending_page(**kwargs: Any) -> dict[str, list[dict[str, str]]]:
        # Record the call like the real client does, then advertise another page.
        client.query_calls.append({"page_token": kwargs.get("page_token")})
        return {"vulns": [{"id": RECORD_B}], "next_page_token": "tok"}

    client.query_vulnerabilities = never_ending_page  # type: ignore[method-assign]
    report = make_service(client, max_pages_per_query=1).sync([item("requests", "2.30.0")])

    follows = [c for c in client.query_calls if c.get("page_token")]
    assert len(follows) == 1  # capped at max_pages_per_query, not endless
    assert follows[0]["page_token"] == "tok-2"
    assert {m.vulnerability_id for m in report.matches} == {RECORD_A, RECORD_B}


def test_sync_retries_missed_items_with_declared_name_spelling() -> None:
    # PyPI may index the underscore spelling while BlastRadius normalizes to '-';
    # a batch miss triggers exactly one retry with the declared original name.
    client = FakeOsvClient(
        batch_results=[[{"vulns": []}]],
        records={RECORD_A: raw_osv_record(RECORD_A, name="typing_extensions")},
    )

    def fallback_query(**kwargs: Any) -> list[dict[str, str]]:
        assert kwargs["package_name"] == "typing_extensions"
        assert kwargs["version"] == "4.7.1"
        return [{"id": RECORD_A}]

    client.iter_vulnerabilities = fallback_query  # type: ignore[method-assign]
    report = make_service(client).sync([item("typing-extensions", "4.7.1", original="typing_extensions")])
    matches = [m for m in report.matches if m.vulnerability_id == RECORD_A]
    assert matches and matches[0].package_name == "typing-extensions"


def test_sync_does_not_retry_when_spellings_are_equivalent() -> None:
    client = FakeOsvClient(batch_results=[[{"vulns": []}]])
    client.iter_vulnerabilities = lambda **kwargs: pytest.fail("fallback must not run")  # type: ignore[method-assign]
    report = make_service(client).sync([item("requests", "2.30.0", original="requests")])
    assert report.matches == ()
    assert report.items_with_matches == 0


def test_sync_skips_records_that_do_not_declare_the_package() -> None:
    client = FakeOsvClient(
        batch_results=[[{"vulns": [{"id": RECORD_A}]}]],
        records={RECORD_A: raw_osv_record(RECORD_A, name="other-package", omit_affected=False)},
    )
    report = make_service(client).sync([item("requests", "2.30.0")])
    assert report.matches == ()
    assert report.errors
    mismatch = [e for e in report.errors if e.kind == "package_mismatch"]
    assert mismatch and mismatch[0].vulnerability_id == RECORD_A
    assert report.status == "completed_with_errors"


def test_sync_hydration_failure_becomes_error_entry() -> None:
    client = FakeOsvClient(
        batch_results=[[{"vulns": [{"id": RECORD_A}]}]],
        record_errors={RECORD_A: OsvRecordNotFoundError("gone")},
    )
    report = make_service(client).sync([item("requests", "2.30.0")])
    assert report.matches == ()
    kinds = [e.kind for e in report.errors]
    assert kinds == ["hydrate"]
    assert report.errors[0].vulnerability_id == RECORD_A
    assert report.status == "completed_with_errors"


def test_sync_skips_undecodable_hydrated_records() -> None:
    client = FakeOsvClient(
        batch_results=[[{"vulns": [{"id": RECORD_A}]}]],
        records={RECORD_A: {"id": "not-usable"}},  # no usable id inside either
    )
    # RAW record replaced wholesale with garbage that fails decoding.
    client._records = {RECORD_A: {"summary": "no id here"}}
    report = make_service(client).sync([item("requests", "2.30.0")])
    kinds = [e.kind for e in report.errors]
    assert kinds == ["hydrate"]


def test_sync_name_only_item_is_reported_but_not_ingested() -> None:
    client = FakeOsvClient(
        batch_results=[[{"vulns": [{"id": RECORD_A}]}]],
        records={RECORD_A: raw_osv_record(RECORD_A)},
    )
    report = make_service(client).sync([item("requests", None)])
    assert report.outcomes[0].status == STATUS_NAME_ONLY
    assert report.outcomes[0].vulnerability_ids == (RECORD_A,)
    assert report.matches == ()
    assert client.get_calls == []  # nothing was hydrated: no evidence claim
    assert any(e.kind == "name_only" for e in report.errors)


def test_sync_name_only_with_no_matches_has_no_error() -> None:
    client = FakeOsvClient(batch_results=[[{"vulns": []}]])
    report = make_service(client).sync([item("requests", None)])
    assert report.outcomes[0].status == "no_matches"
    assert report.errors == ()
    assert report.status == "completed"


def test_sync_dedupes_and_prefers_items_with_original_names() -> None:
    client = FakeOsvClient(
        batch_results=[[{"vulns": [{"id": RECORD_A}]}]],
        records={RECORD_A: raw_osv_record(RECORD_A, name="typing_extensions")},
    )

    def fallback_query(**kwargs: Any) -> list[dict[str, str]]:
        return [{"id": RECORD_A}]

    client.iter_vulnerabilities = fallback_query  # type: ignore[method-assign]
    report = make_service(client).sync(
        [
            OsvPackageItem(ecosystem="pypi", package_name="typing-extensions", version="4.7.1"),
            OsvPackageItem(
                ecosystem="pypi", package_name="typing-extensions",
                original_name="typing_extensions", version="4.7.1",
            ),
            OsvPackageItem(ecosystem="pypi", package_name="typing-extensions", version="4.7.1"),
        ]
    )
    assert report.items_scanned == 1
    assert len(client.batch_calls[0]) == 1
    assert report.matches and report.matches[0].package_name == "typing-extensions"


def test_root_project_empty_package_name_is_rejected() -> None:
    service = make_service(FakeOsvClient())
    with pytest.raises(InputValidationError):
        service.sync([item("", "1.0.0")])
    with pytest.raises(InputValidationError):
        service.lookup("pypi", "  ", None)


def test_sync_rejects_unknown_ecosystems() -> None:
    service = make_service(FakeOsvClient())
    with pytest.raises(InputValidationError):
        service.sync([item("left-pad", "1.0.0", ecosystem="npm")])
    with pytest.raises(InputValidationError):
        service.lookup("npm", "left-pad", None)


# ---------------------------------------------------------------------------
# caps and total failure
# ---------------------------------------------------------------------------
def test_sync_enforces_package_cap() -> None:
    service = make_service(FakeOsvClient(), max_packages_per_ingest=1)
    with pytest.raises(InputValidationError) as excinfo:
        service.sync([item("a", "1.0.0"), item("b", "1.0.0")])
    assert "MAX_PACKAGES_PER_INGEST" in str(excinfo.value)


def test_sync_enforces_vulnerability_cap() -> None:
    settings = {"max_vulnerabilities_per_ingest": 1, "batch_size": 50}
    client = FakeOsvClient(
        batch_results=[[{"vulns": [{"id": RECORD_A}, {"id": RECORD_B}]}]],
        records={RECORD_A: raw_osv_record(RECORD_A), RECORD_B: raw_osv_record(RECORD_B, name="x")},
    )
    service = make_service(client, **settings)
    service._settings = service.settings.model_copy(update={"max_vulnerabilities_per_ingest": 1, "max_packages_per_ingest": 10})
    with pytest.raises(InputValidationError) as excinfo:
        service.sync([item("requests", "2.30.0")])
    assert "MAX_VULNERABILITIES_PER_INGEST" in str(excinfo.value)


def test_sync_total_discovery_failure_reraises_upstream_error() -> None:
    upstream = OsvUnavailableError("api.osv.dev is down")
    client = FakeOsvClient(batch_errors=[upstream])
    service = make_service(client)
    with pytest.raises(OsvUnavailableError):
        service.sync([item("requests", "2.30.0")])


def test_sync_partial_batch_failure_collects_errors_and_continues() -> None:
    upstream = OsvUnavailableError("flaky")
    client = FakeOsvClient(
        batch_errors=[upstream, None],  # first chunk fails, second succeeds
        batch_results=[[{"vulns": [{"id": RECORD_A}]}]],
        records={RECORD_A: raw_osv_record(RECORD_A)},
    )
    report = make_service(client, batch_size=2).sync(
        [item("a", "1.0.0"), item("b", "1.0.0"), item("requests", "2.30.0")]
    )
    assert [e.kind for e in report.errors].count("discovery") == 1
    matched_items = [o for o in report.outcomes if o.status == STATUS_CONFIRMED]
    assert matched_items and matched_items[0].package_name == "requests"


# ---------------------------------------------------------------------------
# single lookups
# ---------------------------------------------------------------------------
def test_lookup_with_version_reports_confirmed_matches() -> None:
    client = FakeOsvClient(
        query_responses={
            ("PyPI", "requests", "2.30.0"): {"vulns": [raw_osv_record(RECORD_A, fixed="2.20.0")]}
        }
    )
    result = make_service(client).lookup("pypi", "requests", "2.30.0")
    assert result.match_type == MATCH_TYPE_VERSION
    assert result.confirmed() is True
    assert result.count == 1
    assert result.vulnerabilities[0].id == RECORD_A
    assert result.upstream_ecosystem == "PyPI"


def test_lookup_without_version_is_name_level_only() -> None:
    client = FakeOsvClient(
        query_responses={("PyPI", "requests", None): {"vulns": [raw_osv_record(RECORD_A)]}}
    )
    result = make_service(client).lookup("pypi", "requests")
    assert result.match_type == MATCH_TYPE_NAME
    assert result.confirmed() is False
    assert result.version is None
    assert result.count == 1


def test_lookup_excludes_records_not_declaring_the_package() -> None:
    client = FakeOsvClient(
        query_responses={
            ("PyPI", "requests", "2.30.0"): {
                "vulns": [raw_osv_record(RECORD_A)], raw_osv_record(RECORD_B, name="unrelated")["id"]: raw_osv_record(RECORD_B, name="unrelated"),
            }
        }
    )
    client._query_responses[("PyPI", "requests", "2.30.0")]["vulns"].append(
        raw_osv_record(RECORD_B, name="unrelated")
    )
    result = make_service(client).lookup("pypi", "requests", "2.30.0")
    ids = [v.id for v in result.vulnerabilities]
    assert ids == [RECORD_A]
    assert any("does not declare" in message for message in result.errors)


def test_lookup_survives_undecodable_entries() -> None:
    client = FakeOsvClient(
        query_responses={("PyPI", "requests", None): {"vulns": [{"message": "garbage"}, raw_osv_record(RECORD_A)]}}
    )
    result = make_service(client).lookup("pypi", "requests")
    assert result.count == 1
    assert len(result.errors) == 1


def test_lookup_propagates_upstream_errors() -> None:
    def boom(**kwargs: Any) -> None:
        raise OsvUnavailableError("api down")

    client = FakeOsvClient()
    client.iter_vulnerabilities = boom  # type: ignore[method-assign]
    with pytest.raises(OsvUnavailableError):
        make_service(client).lookup("pypi", "requests", "2.30.0")
