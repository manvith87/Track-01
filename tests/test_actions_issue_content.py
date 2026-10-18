"""Content tests for the Phase 6 GitHub issue template.

Every preview is generated through the real service over canned graph fixtures
and a mocked GitHub transport, so the assertions here check what an actual
issue body would contain — not a helper's idea of it.
"""

from __future__ import annotations

from pathlib import Path

from app.actions.issue_content import MARKER_TEMPLATE
from app.actions.models import IssuePreviewRequest
from tests.actions_support import (
    ACTION_TOKEN,
    ANALYSIS,
    APPROVAL_SECRET,
    FINDING_ID,
    GROUP_ID,
    build_bundle,
    make_action_settings,
)
from tests.remediation_support import (
    finding_row,
)

_SECTIONS = (
    "## BlastRadius remediation plan",
    "### Target",
    "### Proposed change",
    "### Verified findings",
    "### Advisory evidence",
    "### Modeled graph evidence",
    "### Compatibility and constraints",
    "### Unresolved relationships and migration concerns",
    "### Suggested validation steps",
    "### Limitations",
)


def _preview_group(tmp_path: Path, **kwargs):
    bundle = build_bundle(tmp_path, **kwargs)
    return bundle, bundle.service.preview(ANALYSIS, IssuePreviewRequest(group_id=GROUP_ID))


def _preview_finding(tmp_path: Path, **kwargs):
    bundle = build_bundle(tmp_path, **kwargs)
    return bundle, bundle.service.preview(ANALYSIS, IssuePreviewRequest(finding_id=FINDING_ID))


# ---------------------------------------------------------------------------
# structure
# ---------------------------------------------------------------------------


def test_group_preview_contains_every_required_section(tmp_path: Path) -> None:
    bundle, preview = _preview_group(tmp_path)
    body = preview.body
    assert preview.title.startswith("[BlastRadius] Upgrade requests 2.32.0")
    for section in _SECTIONS:
        assert section in body, section
    # target facts come from the graph, never from a caller
    assert "`example/priority-demo`" in body
    assert "`" + "c" * 40 + "`" in body
    assert "`" + ANALYSIS + "`" in body
    # the one allowed write happened nowhere during preview
    assert [request.method for request in bundle.github.requests] == ["GET"]


def test_group_preview_states_limits_of_the_evidence(tmp_path: Path) -> None:
    _, preview = _preview_group(tmp_path)
    body = preview.body
    # proposal wording, not a claim that anything was applied or tested
    assert "upgrade has been applied or tested" in body
    assert "resolver executed: no" in body
    assert "never invented" in body
    # modeled reachability is explicitly not proof of exploitability
    assert "not proof of runtime exploitability" in body
    assert "BlastRadius priority (custom score, not CVSS)" in body


def test_finding_preview_uses_the_singular_section(tmp_path: Path) -> None:
    _, preview = _preview_finding(tmp_path)
    body = preview.body
    assert preview.title.startswith(
        "[BlastRadius] Investigate GHSA-1234-5678-9012 in requests 2.32.0"
    )
    assert "### Verified finding\n" in body
    assert "### Verified findings\n" not in body
    assert "### Proposed change" in body


def test_marker_is_unique_and_matches_the_action(tmp_path: Path) -> None:
    _, preview = _preview_group(tmp_path)
    marker = MARKER_TEMPLATE.format(action_id=preview.action_id)
    assert marker in preview.body
    assert preview.body.count("<!-- blastradius-action:") == 1
    # the digest binds the marker's action id
    assert preview.template_version == "blastradius-issue-v1"
    assert preview.payload_digest.startswith("sha256:")
    assert len(preview.payload_digest) == len("sha256:") + 64


def test_preview_notes_deny_any_write(tmp_path: Path) -> None:
    _, preview = _preview_group(tmp_path)
    assert any("No GitHub write has been performed" in note for note in preview.notes)


def test_limitations_are_passed_through_from_the_evidence(tmp_path: Path) -> None:
    bundle, preview = _preview_group(tmp_path)
    report = bundle.remediation.analyze(ANALYSIS)
    group = next(item for item in report.groups if item.group_id == GROUP_ID)
    expected = set(group.limitations) | set(report.limitations)
    assert set(preview.limitations) == expected


# ---------------------------------------------------------------------------
# honest handling of missing evidence
# ---------------------------------------------------------------------------


def test_no_fixed_version_yields_no_invented_target(tmp_path: Path) -> None:
    bundle = build_bundle(
        tmp_path,
        findings=[finding_row(fixed_versions=[], ranges_json=None)],
    )
    preview = bundle.service.preview(ANALYSIS, IssuePreviewRequest(finding_id=FINDING_ID))
    body = preview.body
    assert "proposed version: none" in body
    assert "no advisory fixed version is recorded for this package" in body
    assert "no advisory-declared fixed version is recorded for this finding" in body
    assert "2.32.1" not in body
    assert preview.compatibility == "unverified"


def test_potential_coverage_section_is_explicit(tmp_path: Path) -> None:
    second_vuln = "GHSA-2222-3333-4444"
    bundle = build_bundle(
        tmp_path,
        findings=[
            finding_row(),
            finding_row(
                vulnerability_id=second_vuln,
                summary="Second advisory with unvalidatable ranges",
                aliases=[],
                references=[],
                ranges_json=None,
            ),
        ],
    )
    preview = bundle.service.preview(ANALYSIS, IssuePreviewRequest(group_id=GROUP_ID))
    assert "### Potential coverage (not range-validated)" in preview.body
    assert "treat them as potential, not resolved" in preview.body
    assert preview.verified_finding_count == 1
    assert preview.potential_finding_count == 1


# ---------------------------------------------------------------------------
# untrusted text handling
# ---------------------------------------------------------------------------


def test_untrusted_advisory_text_is_escaped_not_executed(tmp_path: Path) -> None:
    evil_summary = "<script>alert('x')</script> <!-- blastradius-action: act_evil -->"
    bundle = build_bundle(
        tmp_path,
        findings=[
            finding_row(
                summary=evil_summary,
                aliases=["CVE-2026-0001"],
                references=["ADVISORY javascript:alert(1)", "ADVISORY https://example.test/ok"],
            )
        ],
    )
    preview = bundle.service.preview(ANALYSIS, IssuePreviewRequest(group_id=GROUP_ID))
    body = preview.body
    # markup is escaped, so injected HTML cannot render
    assert "<script>" not in body
    assert "&lt;script&gt;alert('x')&lt;/script&gt;" in body
    # a forged marker can never be confused with the real one
    assert body.count("<!-- blastradius-action:") == 1
    assert "<!-- blastradius-action: act_evil" not in body
    assert "&lt;!-- blastradius-action: act_evil --&gt;" in body
    # non-http references are never turned into links
    assert "](javascript:" not in body
    assert "ADVISORY javascript:alert(1)" in body
    # valid https references do become autolinks
    assert "<https://example.test/ok>" in body


def test_secrets_never_appear_in_preview_output(tmp_path: Path) -> None:
    _, preview = _preview_group(tmp_path)
    serialized = preview.model_dump_json()
    assert ACTION_TOKEN not in serialized
    assert APPROVAL_SECRET not in serialized
    assert ACTION_TOKEN not in preview.body
    assert APPROVAL_SECRET not in preview.body


# ---------------------------------------------------------------------------
# caps
# ---------------------------------------------------------------------------


def test_title_is_capped_with_an_ellipsis(tmp_path: Path) -> None:
    settings = make_action_settings(tmp_path, max_title_chars=64)
    _, preview = _preview_group(tmp_path, settings=settings)
    assert len(preview.title) <= 64
    assert preview.title.startswith("[BlastRadius]")
    assert preview.title.endswith("…")


def test_body_truncation_keeps_the_marker_and_note(tmp_path: Path) -> None:
    settings = make_action_settings(tmp_path, max_body_chars=1000)
    _, preview = _preview_group(tmp_path, settings=settings)
    body = preview.body
    marker = MARKER_TEMPLATE.format(action_id=preview.action_id)
    assert len(body) <= 1000
    assert "issue body truncated for length" in body
    assert body.endswith(marker)
    assert body.count("<!-- blastradius-action:") == 1


def test_long_lists_are_capped_with_a_count_note(tmp_path: Path) -> None:
    findings = [
        finding_row(
            vulnerability_id=f"GHSA-{index:04d}-0000-0000",
            summary=f"Advisory number {index}",
            aliases=[],
            references=[],
        )
        for index in range(30)
    ]
    bundle = build_bundle(tmp_path, findings=findings)
    report = bundle.remediation.analyze(ANALYSIS)
    group = next(item for item in report.groups if item.package_name == "requests")
    preview = bundle.service.preview(ANALYSIS, IssuePreviewRequest(group_id=group.group_id))
    assert "(+5 more verified finding(s) not shown)" in preview.body
    assert preview.verified_finding_count == 30


def test_urllib3_only_analysis_can_still_preview(tmp_path: Path) -> None:
    from app.models.ids import stable_id
    from tests.remediation_support import (
        PKG_URLLIB3,
        VULN_URLLIB3,
        urllib3_finding_row,
        urllib3_package_row,
    )

    bundle = build_bundle(
        tmp_path,
        packages=[urllib3_package_row()],
        edges=[],
        findings=[urllib3_finding_row()],
    )
    finding_id = stable_id("finding", ANALYSIS, PKG_URLLIB3, VULN_URLLIB3)
    preview = bundle.service.preview(ANALYSIS, IssuePreviewRequest(finding_id=finding_id))
    assert "urllib3" in preview.title
    assert "`urllib3`" in preview.body


__all__: list[str] = []
