"""Deterministic GitHub issue content generation (Phase 6).

Builds the exact title and Markdown body a confirmed write would create.  The
builder is a pure function of the Phase 5 result models:

* every fact is taken verbatim from a ``FindingOut`` / ``FixGroup`` /
  ``PackageRemediationPlan`` computed by the deterministic remediation engine —
  no priority is recalculated, no fixed version is invented, no file name or
  line number is generated;
* modeled graph reachability is always labelled as *modeled* and never as
  proof of runtime exploitability;
* compatibility is only ever reported with the engine's status
  (``constraints_satisfied`` / ``constraints_violated`` / ``unverified``) and
  the explicit note that no resolver or test was executed;
* untrusted advisory text is escaped before it is embedded, and the unique
  action marker is an HTML comment readers do not see.

The template is stable and versioned (``blastradius-issue-v1``); the version is
part of the payload digest.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final

from app.actions.digest import TEMPLATE_VERSION
from app.actions.models import RepositoryTarget
from app.remediation.models import (
    AdvisoryEvidenceRef,
    ConstraintCheck,
    FindingOut,
    FixGroup,
    PackageRemediationPlan,
    RemediationCandidate,
)

#: Invisible marker used for reconciliation of ambiguous write outcomes.
MARKER_TEMPLATE: Final[str] = "<!-- blastradius-action: {action_id} -->"

#: Bounded listings so an issue body stays reviewable.  Truncation is always
#: stated explicitly in the body.
MAX_LISTED_FINDINGS: Final[int] = 25
MAX_LISTED_COMPONENTS: Final[int] = 50
MAX_LISTED_ENTRY_POINTS: Final[int] = 25
MAX_LISTED_CHECKS: Final[int] = 50
MAX_LISTED_REFERENCES: Final[int] = 40

_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_URL_RE = re.compile(r"^https?://[^\s<>)`]+$")

#: The static, never-executed validation guidance.  Deliberately phrased as
#: suggestions — BlastRadius does not run installs, resolvers or tests.
_SUGGESTED_STEPS: Final[tuple[str, ...]] = (
    "Update the dependency in the repository's own manifest/lockfile tooling "
    "(for example `poetry lock`, `uv lock` or `pip-compile`) and review the diff.",
    "Install the updated dependency set into an isolated environment and run the "
    "project's test suite, including any integration tests that exercise this "
    "dependency.",
    "Confirm the installed version with the project's tooling (for example "
    "`python -m pip show <package>`), because the lockfile alone does not prove "
    "what is deployed.",
    "Re-run BlastRadius on the resulting commit and confirm the finding is gone "
    "from the prioritized findings list.",
)

_SUGGESTED_STEPS_NO_VERSION: Final[tuple[str, ...]] = (
    "Investigate whether the upstream project has published a fixed release "
    "(no advisory-declared fixed version is recorded for this finding).",
    "If no fixed release exists, evaluate mitigations (configuration, usage "
    "changes, network controls) with the maintainers.",
    "Re-run BlastRadius on the resulting commit and confirm the finding status.",
)


# ---------------------------------------------------------------------------
# small formatting helpers
# ---------------------------------------------------------------------------

def _escape(text: str) -> str:
    """Escape untrusted text for inline Markdown (single line)."""
    collapsed = " ".join(str(text).split())
    collapsed = _CONTROL_RE.sub("", collapsed)
    return (
        collapsed.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def _code(text: str) -> str:
    """Render a value as a safe inline code span."""
    collapsed = " ".join(str(text).split())
    collapsed = _CONTROL_RE.sub("", collapsed).replace("`", "'")
    return f"`{collapsed}`"


def _bullets(items: list[str], *, cap: int, truncated_note: str) -> list[str]:
    if not items:
        return []
    shown = items[:cap]
    lines = [f"- {item}" for item in shown]
    if len(items) > cap:
        lines.append(f"- {truncated_note.format(count=len(items) - cap)}")
    return lines


def _reference_line(reference: str) -> str:
    """Render one stored ``TYPE url`` advisory reference safely."""
    text = " ".join(str(reference).split())
    parts = text.split(" ", 1)
    if len(parts) == 2 and _URL_RE.match(parts[1]):
        kind = _escape(parts[0]) or "REFERENCE"
        return f"- {kind}: <{parts[1]}>"
    if _URL_RE.match(parts[0]):
        return f"- <{parts[0]}>"
    return f"- {_escape(text)}"


def _severity_line(finding: FindingOut) -> str:
    severity = finding.priority.severity
    if severity.numeric_score is not None:
        score_type = f" ({_escape(severity.score_type)})" if severity.score_type else ""
        return (
            f"advisory severity: {severity.numeric_score:g}{score_type} — "
            "reported by the advisory record, never computed by BlastRadius"
        )
    if severity.vector:
        return (
            "advisory severity: vector only ("
            + _code(severity.vector)
            + ") — kept verbatim; BlastRadius never converts vectors to scores"
        )
    if severity.entries:
        return "advisory severity: " + _escape(", ".join(severity.entries))
    return "advisory severity: not reported by the advisory record"


def _reachability_line(finding: FindingOut) -> str:
    reachability = finding.priority.reachability
    status = _escape(reachability.status)
    if reachability.status == "direct":
        return (
            "reachability: direct — the package is declared by this repository; "
            "modeled from lockfile dependency edges, not proof of runtime exploitability"
        )
    if reachability.status == "not_reachable":
        return (
            "reachability: not_reachable — no modeled dependency path was found "
            "within the traversal bound; this is not proof of unexploitability"
        )
    if reachability.status == "unavailable":
        return (
            "reachability: unavailable — the analysis lacks the dependency graph "
            "data needed to model a path"
        )
    hops = f" (shortest modeled path: {reachability.min_hops} hop(s))" if reachability.min_hops else ""
    return (
        f"reachability: {status}{hops} — modeled from lockfile "
        "dependency edges, not proof of runtime exploitability"
    )


def _finding_lines(finding: FindingOut, *, resolution: str | None = None) -> list[str]:
    vuln = _code(finding.vulnerability_id)
    summary = f" — {_escape(finding.vulnerability_summary)}" if finding.vulnerability_summary else ""
    lines = [f"- **{vuln}**{summary}"]
    if finding.aliases:
        lines.append("  - aliases: " + ", ".join(_code(alias) for alias in finding.aliases))
    for reference in finding.advisory_references:
        lines.append("  " + _reference_line(reference).lstrip())
    lines.append(
        "  - package: "
        + _code(finding.package.package_name)
        + (f" {_code(finding.package.package_version)}" if finding.package.package_version else "")
    )
    lines.append(
        "  - BlastRadius priority (custom score, not CVSS): "
        f"{finding.priority.score:g} (rank {finding.priority.rank}, "
        f"formula {_code(finding.priority.formula_version)})"
    )
    lines.append("  - " + _severity_line(finding))
    lines.append("  - " + _reachability_line(finding))
    if resolution:
        lines.append(f"  - resolution validation: {resolution}")
    if finding.advisory_withdrawn:
        lines.append("  - limitation: the advisory record has been withdrawn")
    for limitation in finding.limitations:
        lines.append("  - limitation: " + _escape(limitation))
    return lines


def _constraint_lines(checks: list[ConstraintCheck]) -> list[str]:
    lines: list[str] = []
    for check in checks[:MAX_LISTED_CHECKS]:
        if check.satisfied is True:
            verdict = "satisfied"
        elif check.satisfied is False:
            verdict = "violated"
        else:
            verdict = "not evaluable"
        origin = _escape(check.origin)
        constraint = f" {_code(check.constraint)}" if check.constraint else ""
        scheme = f" [{_escape(check.scheme)}]"
        lines.append(f"- {verdict}: {origin}{constraint}{scheme} — {_escape(check.detail)}")
    if len(checks) > MAX_LISTED_CHECKS:
        lines.append(
            f"- (+{len(checks) - MAX_LISTED_CHECKS} more constraint check(s) not shown)"
        )
    return lines


def _advisory_evidence_lines(evidence: list[AdvisoryEvidenceRef]) -> list[str]:
    lines: list[str] = []
    for item in evidence[:MAX_LISTED_REFERENCES]:
        fixed = ", ".join(_code(v) for v in item.fixed_versions) or "none recorded"
        summary = f" — {_escape(item.summary)}" if item.summary else ""
        lines.append(f"- {_code(item.vulnerability_id)}{summary}")
        lines.append(f"  - advisory-declared fixed version(s): {fixed}")
        if item.osv_modified:
            lines.append(f"  - OSV record last modified: {_code(item.osv_modified)}")
    if len(evidence) > MAX_LISTED_REFERENCES:
        lines.append(f"- (+{len(evidence) - MAX_LISTED_REFERENCES} more advisory record(s) not shown)")
    return lines


def _dedupe(items: list[str]) -> list[str]:
    return list(dict.fromkeys(item for item in items if item))


# ---------------------------------------------------------------------------
# subject + content
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class IssueSubject:
    """Everything the template needs; produced only from server-side models."""

    action_id: str
    analysis_id: str
    repository: RepositoryTarget
    commit_sha: str
    group: FixGroup | None = None
    finding: FindingOut | None = None
    plan: PackageRemediationPlan | None = None
    report_limitations: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class IssueContent:
    """The generated title/body plus the reconciliation marker."""

    title: str
    body: str
    marker: str


def _subject_candidate(subject: IssueSubject) -> RemediationCandidate | None:
    """The selected candidate of the preview subject (group or package plan)."""
    if subject.group is not None:
        candidates = subject.group.candidates
    elif subject.plan is not None:
        candidates = subject.plan.candidates
    else:
        candidates = []
    for candidate in candidates:
        if candidate.selected:
            return candidate
    return candidates[0] if candidates else None


def _build_title(subject: IssueSubject, *, max_title_chars: int) -> str:
    if subject.group is not None:
        group = subject.group
        verified = len(group.verified_resolved_finding_ids)
        potential = len(group.potential_resolved_finding_ids)
        if verified:
            purpose = f"resolve {verified} verified finding(s)"
        elif potential:
            purpose = f"assess {potential} potential finding(s)"
        else:
            purpose = "review remediation evidence"
        title = (
            f"[BlastRadius] Upgrade {group.package_name} {group.current_version} → "
            f"{group.proposed_version} — {purpose}"
        )
    else:
        assert subject.finding is not None
        finding = subject.finding
        version = f" {finding.package.package_version}" if finding.package.package_version else ""
        title = (
            f"[BlastRadius] Investigate {finding.vulnerability_id} in "
            f"{finding.package.package_name}{version}"
        )
    if len(title) > max_title_chars:
        title = title[: max_title_chars - 1].rstrip() + "…"
    return title


def _proposed_change_lines(subject: IssueSubject) -> list[str]:
    if subject.group is not None:
        group = subject.group
        candidate = _subject_candidate(subject)
        lines = [
            "### Proposed change",
            "",
            f"- package: {_code(group.package_name)} ({_escape(group.ecosystem or 'unknown ecosystem')})"
            + (f" · dependency role: {_escape(group.dependency_role)}" if group.dependency_role else ""),
            f"- current version: {_code(group.current_version)}",
            f"- proposed version: {_code(group.proposed_version)} "
            "(from advisory-declared fixed-version data — never invented)",
            f"- coverage: {_escape(group.coverage)}",
        ]
        if candidate is not None:
            lines.append(
                f"- compatibility: {_escape(candidate.compatibility)} — "
                f"{_escape(candidate.compatibility_detail)}"
            )
            lines.append(
                "- resolver executed: no (BlastRadius never runs package managers, "
                "resolvers or builds)"
            )
        lines.append(
            f"- verified findings addressed: {len(group.verified_resolved_finding_ids)}; "
            f"potential: {len(group.potential_resolved_finding_ids)}; "
            f"not resolved by this version: {len(group.unresolved_finding_ids)}"
        )
        return lines

    assert subject.finding is not None
    finding = subject.finding
    plan = subject.plan
    candidate = _subject_candidate(subject)
    lines = [
        "### Proposed change",
        "",
        f"- package: {_code(finding.package.package_name)}"
        + (f" at {_code(finding.package.package_version)}" if finding.package.package_version else ""),
        f"- finding: {_code(finding.vulnerability_id)}",
    ]
    if candidate is not None:
        lines.append(
            f"- proposed version: {_code(candidate.proposed_version)} "
            "(from advisory-declared fixed-version data — never invented)"
        )
        lines.append(
            f"- compatibility: {_escape(candidate.compatibility)} — "
            f"{_escape(candidate.compatibility_detail)}"
        )
        lines.append(
            "- resolver executed: no (BlastRadius never runs package managers, "
            "resolvers or builds)"
        )
    else:
        reason = f" — {_escape(plan.no_candidate_reason)}" if plan and plan.no_candidate_reason else ""
        lines.append(
            "- proposed version: none — no advisory-declared fixed version is "
            f"recorded for this package{reason}, so BlastRadius cannot propose one."
        )
    return lines


def _graph_evidence_lines(subject: IssueSubject) -> list[str]:
    lines = ["### Modeled graph evidence", ""]
    if subject.group is not None:
        group = subject.group
        if group.entry_points:
            shown = group.entry_points[:MAX_LISTED_ENTRY_POINTS]
            lines.append(
                "Entry points with a modeled dependency path to the affected package:"
            )
            lines.extend(f"- {_code(item)}" for item in shown)
            if len(group.entry_points) > MAX_LISTED_ENTRY_POINTS:
                lines.append(
                    f"- (+{len(group.entry_points) - MAX_LISTED_ENTRY_POINTS} more entry point(s) not shown)"
                )
        if group.affected_components:
            shown = group.affected_components[:MAX_LISTED_COMPONENTS]
            lines.append("")
            lines.append("Components depending on the affected package (modeled):")
            lines.extend(f"- {_code(item)}" for item in shown)
            if len(group.affected_components) > MAX_LISTED_COMPONENTS:
                lines.append(
                    f"- (+{len(group.affected_components) - MAX_LISTED_COMPONENTS} more component(s) not shown)"
                )
        if not group.entry_points and not group.affected_components:
            lines.append(
                "No modeled entry path or dependent component is recorded for this "
                "group in the analysis."
            )
    else:
        assert subject.finding is not None
        reachability = subject.finding.priority.reachability
        if reachability.entry_points:
            lines.append("Entry points with a modeled dependency path:")
            lines.extend(
                f"- {_code(item)}" for item in reachability.entry_points[:MAX_LISTED_ENTRY_POINTS]
            )
        if reachability.dependent_components:
            lines.append("")
            lines.append("Packages depending on the affected package (modeled):")
            lines.extend(
                f"- {_code(item)}"
                for item in reachability.dependent_components[:MAX_LISTED_COMPONENTS]
            )
            if reachability.dependent_components_truncated:
                lines.append("- (dependent component list truncated upstream)")
        if not reachability.entry_points and not reachability.dependent_components:
            lines.append(
                "No modeled entry path or dependent component is recorded for this "
                "finding in the analysis."
            )
    lines.append("")
    lines.append(
        "These paths are modeled from lockfile-derived dependency edges. They are "
        "not proof of runtime exploitability: BlastRadius does not execute the "
        "analyzed code."
    )
    return lines


def _build_body(subject: IssueSubject, *, max_body_chars: int) -> str:
    repository = subject.repository
    commit_url = f"{repository.canonical_url}/commit/{subject.commit_sha}"
    lines: list[str] = [
        "## BlastRadius remediation plan",
        "",
        "> Generated by BlastRadius from the persisted dependency graph and OSV",
        "> advisory records for the analysis below. This issue is a proposal: no",
        "> upgrade has been applied or tested, no package manager or resolver has",
        "> been executed, and no repository file has been modified.",
        "",
        "### Target",
        "",
        f"- repository: {_code(repository.full_name)}",
        f"- analyzed commit: {_code(subject.commit_sha)} ([commit]({commit_url}))",
        f"- analysis: {_code(subject.analysis_id)}",
        "",
    ]

    lines.extend(_proposed_change_lines(subject))
    lines.append("")

    # -- verified findings --------------------------------------------------
    candidate = _subject_candidate(subject)
    if subject.group is not None:
        group = subject.group
        lines.append("### Verified findings")
        lines.append("")
        if group.resolved_findings:
            resolutions = {
                evaluation.vulnerability_id: evaluation
                for evaluation in (candidate.resolves if candidate is not None else [])
            }
            shown = group.resolved_findings[:MAX_LISTED_FINDINGS]
            for finding in shown:
                evaluation = resolutions.get(finding.vulnerability_id)
                resolution = (
                    f"{evaluation.status} — {_escape(evaluation.detail)}"
                    if evaluation is not None
                    else "resolves — validated against the stored advisory ranges"
                )
                lines.extend(_finding_lines(finding, resolution=resolution))
            if len(group.resolved_findings) > MAX_LISTED_FINDINGS:
                lines.append(
                    f"- (+{len(group.resolved_findings) - MAX_LISTED_FINDINGS} more verified finding(s) not shown)"
                )
        else:
            lines.append("No finding is range-validated against the proposed version.")
        if group.potential_resolved_finding_ids:
            lines.append("")
            lines.append("### Potential coverage (not range-validated)")
            lines.append("")
            lines.append(
                "The advisory data does not let BlastRadius validate these findings "
                "against the proposed version; treat them as potential, not resolved:"
            )
            for finding_id in group.potential_resolved_finding_ids[:MAX_LISTED_FINDINGS]:
                lines.append(f"- {_code(finding_id)}")
        lines.append("")
        if group.advisory_evidence:
            lines.append("### Advisory evidence")
            lines.append("")
            lines.extend(_advisory_evidence_lines(group.advisory_evidence))
            lines.append("")
    else:
        assert subject.finding is not None
        lines.append("### Verified finding")
        lines.append("")
        lines.extend(_finding_lines(subject.finding))
        lines.append("")

    lines.extend(_graph_evidence_lines(subject))
    lines.append("")

    # -- compatibility ------------------------------------------------------
    lines.append("### Compatibility and constraints")
    lines.append("")
    if subject.group is not None:
        compatibility = subject.group.compatibility
    elif candidate is not None:
        compatibility = candidate.compatibility
    else:
        compatibility = "unverified"
    lines.append(f"- compatibility status: {_escape(compatibility)}")
    lines.append(
        "- `constraints_satisfied` means the recorded declarations and dependency "
        "edges accept the version; `unverified` means they could not be evaluated. "
        "Neither is a resolver result."
    )
    checks = (
        subject.group.constraint_checks
        if subject.group is not None
        else (candidate.constraint_checks if candidate is not None else [])
    )
    if checks:
        lines.append("- recorded constraint checks:")
        lines.extend("  " + line for line in _constraint_lines(checks))
    else:
        lines.append("- no recorded constraint checks are available for this package.")
    lines.append("")

    # -- unresolved / migration --------------------------------------------
    unresolved = (
        subject.group.unresolved_relationships
        if subject.group is not None
        else (subject.plan.unresolved_relationships if subject.plan is not None else [])
    )
    concerns = (
        subject.group.migration_concerns
        if subject.group is not None
        else (subject.plan.migration_concerns if subject.plan is not None else [])
    )
    lines.append("### Unresolved relationships and migration concerns")
    lines.append("")
    if unresolved:
        lines.extend(_bullets([_escape(item) for item in unresolved], cap=20, truncated_note="(+{count} more not shown)"))
    else:
        lines.append("- no unresolved dependency relationship is recorded for this package.")
    if concerns:
        lines.extend(_bullets([_escape(item) for item in concerns], cap=20, truncated_note="(+{count} more not shown)"))
    lines.append("")

    # -- suggested validation ----------------------------------------------
    lines.append("### Suggested validation steps")
    lines.append("")
    has_version = subject.group is not None or candidate is not None
    lines.extend(
        f"- {step}" for step in (_SUGGESTED_STEPS if has_version else _SUGGESTED_STEPS_NO_VERSION)
    )
    lines.append("")

    # -- limitations --------------------------------------------------------
    limitations: list[str] = []
    if subject.group is not None:
        limitations.extend(subject.group.limitations)
    else:
        assert subject.finding is not None
        limitations.extend(subject.finding.limitations)
        if subject.plan is not None:
            limitations.extend(subject.plan.limitations)
    limitations.extend(subject.report_limitations)
    lines.append("### Limitations")
    lines.append("")
    if limitations:
        lines.extend(_bullets([_escape(item) for item in _dedupe(limitations)], cap=30, truncated_note="(+{count} more not shown)"))
    else:
        lines.append("- none reported for this analysis.")
    lines.append("")
    lines.append("---")
    lines.append(
        "Generated by BlastRadius · issue template " + _code(TEMPLATE_VERSION)
    )
    lines.append(MARKER_TEMPLATE.format(action_id=subject.action_id))

    body = "\n".join(lines)
    if len(body) > max_body_chars:
        # The action marker is a recovery/anchor line: it must survive the
        # truncation so an ambiguous write can still be reconciled.  Reserve
        # room for the note plus the marker.
        tail = (
            "\n\n_(issue body truncated for length; see the BlastRadius API "
            "for the full evidence)_\n\n" + MARKER_TEMPLATE.format(action_id=subject.action_id)
        )
        keep = max(0, max_body_chars - len(tail))
        body = body[:keep].rstrip() + tail
    return body


def build_issue_content(
    subject: IssueSubject,
    *,
    max_title_chars: int = 256,
    max_body_chars: int = 60_000,
) -> IssueContent:
    """Build the deterministic title/body for one preview subject."""
    return IssueContent(
        title=_build_title(subject, max_title_chars=max_title_chars),
        body=_build_body(subject, max_body_chars=max_body_chars),
        marker=MARKER_TEMPLATE.format(action_id=subject.action_id),
    )


__all__ = [
    "MARKER_TEMPLATE",
    "IssueContent",
    "IssueSubject",
    "build_issue_content",
]
