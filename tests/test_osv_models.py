"""Strict OSV response decoding tests (offline).

Missing metadata must surface as ``None``/empty — never as invented values —
and long text is truncated to the configured bound without adding anything.
"""

from __future__ import annotations

import pytest

from app.osv.models import (
    decode_vulnerability,
    decode_vulnerability_stub,
)


def test_decode_minimal_record_keeps_missing_metadata_unknown() -> None:
    vuln = decode_vulnerability({"id": "PYSEC-2024-1"})
    assert vuln.id == "PYSEC-2024-1"
    assert vuln.summary is None
    assert vuln.details is None
    assert vuln.aliases == ()
    assert vuln.related == ()
    assert vuln.published is None
    assert vuln.modified is None
    assert vuln.withdrawn is None
    assert vuln.severities == ()
    assert vuln.references == ()
    assert vuln.affected == ()
    assert vuln.affected_package_keys() == ()
    assert vuln.schema_version is None


def test_decode_full_record_with_ranges_and_severity() -> None:
    raw = {
        "id": "GHSA-aaaa-bbbb-cccc",
        "summary": "XSS in widget",
        "details": "Long description",
        "aliases": ["CVE-2024-0001", "CVE-2024-0002"],
        "related": ["GHSA-related"],
        "published": "2024-01-01T00:00:00Z",
        "modified": "2024-02-03T00:00:00Z",
        "withdrawn": None,
        "schema_version": "1.4.1.0",
        "severity": [
            {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
            {"type": "Ubuntu", "score": "medium"},
        ],
        "references": [
            {"type": "ADVISORY", "url": "https://example.test/advisory"},
            {"type": "REPORT", "url": "https://example.test/issue/1"},
        ],
        "affected": [
            {
                "package": {"name": "requests", "ecosystem": "PyPI"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": "2.20.0"}],
                    },
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "2.21.0"}, {"fixed": "2.31.0"}],
                    },
                    {
                        # GIT ranges carry commit SHAs and must never look like versions.
                        "type": "GIT",
                        "repo": "https://github.com/example/repo.git",
                        "events": [{"introduced": "abc123"}, {"fixed": "def456"}],
                    },
                ],
                "versions": ["2.3.0", "2.30.0"],
                "database_specific": {"severity": "HIGH"},
            }
        ],
    }
    vuln = decode_vulnerability(raw, max_text_length=1000)
    assert vuln.aliases == ("CVE-2024-0001", "CVE-2024-0002")
    assert vuln.related == ("GHSA-related",)
    assert vuln.severities[0].type == "CVSS_V3"
    assert vuln.severities[0].score == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    assert vuln.severities[1].type == "Ubuntu"
    assert [r.type for r in vuln.references] == ["ADVISORY", "REPORT"]

    entry = vuln.affected_entry_for("requests", "PyPI")
    assert entry is not None
    # GIT-fixed SHAs are excluded from version-level answers.
    assert entry.fixed_versions == ("2.20.0", "2.31.0")
    assert entry.versions == ("2.3.0", "2.30.0")
    assert vuln.affected_package_keys() == ("PyPI:requests",)


def test_decode_name_matching_is_normalized_but_not_invented() -> None:
    raw = raw_record_with_package("Typing_Extensions")
    vuln = decode_vulnerability(raw)
    assert vuln.affected_entry_for("typing-extensions", "PyPI") is not None
    assert vuln.affected_entry_for("typing_ext", "PyPI") is None


def test_decode_foreign_ecosystem_never_matches() -> None:
    raw = raw_record_with_package("requests", ecosystem="npm")
    vuln = decode_vulnerability(raw)
    assert vuln.affected_entry_for("requests", "PyPI") is None


@pytest.mark.parametrize(
    "raw",
    [
        pytest.param(None, id="not-an-object"),
        pytest.param([{"id": "x"}], id="list"),
        pytest.param({}, id="missing-id"),
        pytest.param({"id": "   "}, id="blank-id"),
        pytest.param({"id": 42}, id="numeric-id"),
    ],
)
def test_decode_rejects_unusable_records(raw: object) -> None:
    with pytest.raises(ValueError):
        decode_vulnerability(raw)


def test_decode_truncates_long_text_without_adding_content() -> None:
    raw = {"id": "GHSA-x", "summary": "s" * 500, "details": "d" * 500}
    vuln = decode_vulnerability(raw, max_text_length=100)
    assert vuln.summary == "s" * 100
    assert vuln.details == "d" * 100


def test_decode_ignores_malformed_substructures() -> None:
    raw = {
        "id": "GHSA-x",
        "severity": "not-a-list",  # wrong type entirely
        "references": ["bare-string", {"url": "https://ok.test"}],
        "affected": ["not-a-dict", {"ranges": "nope", "package": {"name": "x", "ecosystem": "PyPI"}}],
    }
    vuln = decode_vulnerability(raw)
    assert vuln.severities == ()
    assert [r.url for r in vuln.references] == ["https://ok.test"]
    assert [e.package.name for e in vuln.affected if e.package] == ["x"]


def test_decode_stub_records_from_querybatch() -> None:
    stub = decode_vulnerability_stub({"id": "GHSA-1", "modified": "2024-01-01T00:00:00Z"})
    assert stub.id == "GHSA-1"
    assert stub.modified == "2024-01-01T00:00:00Z"
    with pytest.raises(ValueError):
        decode_vulnerability_stub("nope")
    with pytest.raises(ValueError):
        decode_vulnerability_stub({"modified": "2024-01-01T00:00:00Z"})


def raw_record_with_package(name: str, ecosystem: str = "PyPI") -> dict:
    return {
        "id": "GHSA-z",
        "affected": [
            {
                "package": {"name": name, "ecosystem": ecosystem},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
            }
        ],
    }