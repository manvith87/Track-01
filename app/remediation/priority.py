"""Deterministic prioritization of findings (Phase 5).

The BlastRadius priority score is a documented, deterministic *custom* score.
It is not, and is never presented as, a CVSS score: the advisory's own
severity data is carried separately in :class:`~app.remediation.models.SeverityEvidence`.

Formula (``blastradius-priority-v1``)::

    score = 100 * (0.40 * severity + 0.30 * reachability
                   + 0.20 * impact + 0.10 * remediation)

Factors (each normalized to ``[0, 1]``; ``raw`` on every contribution shows
the facts it was derived from):

* **severity** — advisory-reported numeric score / 10 when OSV carries one;
  ``0.5`` (neutral) when the advisory only has CVSS vectors or no severity
  data at all.  A vector is never converted into a score.
* **reachability** — ``1.0`` when the affected package is itself an entry
  point (directly declared or the lockfile root project); ``0.75`` when a
  modeled ``DEPENDS_ON`` path from an entry point exists; ``0.35`` when the
  graph had the data needed to look and no path was found (absence of a
  modeled path is not proof of unexploitability — it is never ``0``);
  ``0.5`` (neutral) when no reachability evidence exists at all.
* **impact** — ``min(1, log2(1 + c) / 3)`` where ``c`` is the number of
  distinct dependent components backed by ``DEPENDS_ON`` evidence
  (``c = 7`` saturates; ``c = 0`` stays ``0`` — reachability carries the
  "no evidence" case).
* **remediation** — ``1.0`` when the advisory records a fixed version for the
  finding's package (an actionable upgrade exists); ``0.25`` when it does
  not.  "No recorded fix" is a fact about the advisory, not about risk.

Missing information is represented as *neutral*, never as zero, and the
factor notes say exactly why.  The same input always produces the same score:
the formula uses only arithmetic over the values above.

Tie-breaking between equal scores (deterministic total order):

1. higher advisory numeric severity (findings without one sort last);
2. higher reachability status (direct > reachable_from_entry > unavailable >
   not_reachable);
3. ``finding_id`` ascending.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from app.remediation.models import (
    FactorContribution,
    FindingInput,
    FindingPriority,
    ReachabilityEvidence,
    SeverityEvidence,
)
from app.remediation.severity import parse_advisory_severity

FORMULA_VERSION = "blastradius-priority-v1"

#: Documented factor weights; they sum to 1.0.
FACTOR_WEIGHTS: dict[str, float] = {
    "severity": 0.40,
    "reachability": 0.30,
    "impact": 0.20,
    "remediation": 0.10,
}

#: Neutral value used whenever a factor has no supporting data.
NEUTRAL = 0.5

#: Documented reachability normalization.
REACHABILITY_VALUES: dict[str, float] = {
    "direct": 1.0,
    "reachable_from_entry": 0.75,
    "not_reachable": 0.35,
    "unavailable": NEUTRAL,
}

#: Tie-break ordering between equal scores.
_REACHABILITY_RANK: dict[str, int] = {
    "direct": 3,
    "reachable_from_entry": 2,
    "unavailable": 1,
    "not_reachable": 0,
}

#: How many dependent components (sorted, for display) a single finding carries.
MAX_DEPENDENT_COMPONENTS = 25


@dataclass(frozen=True)
class Prioritized:
    """One finding input plus its computed priority (rank assigned)."""

    inputs: FindingInput
    priority: FindingPriority


def _round(value: float, digits: int = 4) -> float:
    return round(value, digits)


def severity_factor(severity: SeverityEvidence) -> FactorContribution:
    """Advisory severity normalized to ``[0, 1]`` (never a vector-derived score)."""
    if severity.numeric_score is not None:
        normalized = min(1.0, max(0.0, severity.numeric_score / 10.0))
        note = (
            f"advisory-reported numeric score {severity.numeric_score:g}"
            + (f" ({severity.score_type})" if severity.score_type else "")
        )
    else:
        normalized = NEUTRAL
        note = severity.note or "no numeric advisory severity is available"
    weight = FACTOR_WEIGHTS["severity"]
    return FactorContribution(
        name="severity",
        weight=weight,
        normalized=_round(normalized),
        contribution=_round(weight * normalized),
        raw={
            "quantified": severity.quantified,
            "numeric_score": severity.numeric_score,
            "score_type": severity.score_type,
            "vector_types": list(severity.vector_types),
        },
        notes=[note],
    )


def reachability_factor(
    *,
    dependency_role: str,
    is_root_project: bool,
    entry_points: tuple[str, ...],
    entry_min_hops: int | None,
    graph_has_dependency_edges: bool,
    entry_packages_defined: bool,
) -> tuple[FactorContribution, ReachabilityEvidence]:
    """Modeled reachability of the affected package from entry points."""
    is_entry = is_root_project or dependency_role == "direct"
    evidence_available = graph_has_dependency_edges and entry_packages_defined

    if is_entry:
        status = "direct"
    elif entry_points:
        status = "reachable_from_entry"
    elif evidence_available:
        status = "not_reachable"
    else:
        status = "unavailable"

    normalized = REACHABILITY_VALUES[status]
    if status == "direct":
        note = "the affected package is itself an entry point (directly declared or root project)"
    elif status == "reachable_from_entry":
        note = "a modeled DEPENDS_ON path exists from at least one entry point"
    elif status == "not_reachable":
        note = (
            "the graph contained dependency edges and entry points but no modeled path "
            "within the traversal bound was found; this is not proof of unexploitability"
        )
    else:
        note = "the analysis does not contain the dependency edges/entry points needed to model reachability"

    weight = FACTOR_WEIGHTS["reachability"]
    factor = FactorContribution(
        name="reachability",
        weight=weight,
        normalized=_round(normalized),
        contribution=_round(weight * normalized),
        raw={
            "status": status,
            "entry_points": list(entry_points),
            "min_hops": entry_min_hops,
            "dependency_edges_present": graph_has_dependency_edges,
            "entry_packages_defined": entry_packages_defined,
        },
        notes=[note],
    )
    return factor, ReachabilityEvidence(
        status=status,
        entry_points=list(entry_points),
        min_hops=entry_min_hops,
        evidence_available=evidence_available,
    )


def impact_factor(dependent_component_count: int) -> FactorContribution:
    """Distinct dependent components normalized on a log scale."""
    count = max(0, int(dependent_component_count))
    normalized = min(1.0, math.log2(1 + count) / 3.0)
    weight = FACTOR_WEIGHTS["impact"]
    note = (
        "distinct packages that (transitively) depend on the affected package "
        "through modeled DEPENDS_ON paths"
        if count
        else "no downstream dependents are modeled for the affected package"
    )
    return FactorContribution(
        name="impact",
        weight=weight,
        normalized=_round(normalized),
        contribution=_round(weight * normalized),
        raw={"dependent_component_count": count},
        notes=[note],
    )


def remediation_factor(advisory_fixed_versions: tuple[str, ...]) -> FactorContribution:
    """Whether an advisory-supported upgrade target exists."""
    available = bool(advisory_fixed_versions)
    normalized = 1.0 if available else 0.25
    weight = FACTOR_WEIGHTS["remediation"]
    note = (
        f"advisory fixed version(s) recorded: {', '.join(advisory_fixed_versions)}"
        if available
        else "the advisory records no fixed version for this package"
    )
    return FactorContribution(
        name="remediation",
        weight=weight,
        normalized=_round(normalized),
        contribution=_round(weight * normalized),
        raw={
            "available": available,
            "advisory_fixed_versions": list(advisory_fixed_versions),
        },
        notes=[note],
    )


def compute_priority(
    inputs: FindingInput,
    *,
    graph_has_dependency_edges: bool,
    entry_packages_defined: bool,
) -> tuple[SeverityEvidence, ReachabilityEvidence, list[FactorContribution], float]:
    """Compute the documented custom score and its factor breakdown."""
    severity = parse_advisory_severity(inputs.severities)
    reach_factor, reachability = reachability_factor(
        dependency_role=inputs.dependency_role,
        is_root_project=inputs.is_root_project,
        entry_points=inputs.entry_points,
        entry_min_hops=inputs.entry_min_hops,
        graph_has_dependency_edges=graph_has_dependency_edges,
        entry_packages_defined=entry_packages_defined,
    )
    factors = [
        severity_factor(severity),
        reach_factor,
        impact_factor(inputs.dependent_component_count),
        remediation_factor(inputs.fixed_versions),
    ]
    score = 100.0 * sum(factor.weight * factor.normalized for factor in factors)
    return severity, reachability, factors, round(score, 2)


def prioritize(
    inputs: list[FindingInput],
    *,
    graph_has_dependency_edges: bool,
    entry_packages_defined: bool,
) -> list[Prioritized]:
    """Compute priorities for every input and return them ranked best-first."""
    computed: list[tuple[SeverityEvidence, ReachabilityEvidence, list[FactorContribution], float, FindingInput]] = []
    for item in inputs:
        severity, reachability, factors, score = compute_priority(
            item,
            graph_has_dependency_edges=graph_has_dependency_edges,
            entry_packages_defined=entry_packages_defined,
        )
        computed.append((severity, reachability, factors, score, item))

    ordered = sorted(
        computed,
        key=lambda row: (
            -row[3],
            -(row[0].numeric_score if row[0].numeric_score is not None else -1.0),
            -_REACHABILITY_RANK.get(row[1].status, 0),
            row[4].finding_id,
        ),
    )

    prioritized: list[Prioritized] = []
    for rank, (severity, reachability, factors, score, item) in enumerate(ordered, start=1):
        dependent_components = list(item.dependent_components)[:MAX_DEPENDENT_COMPONENTS]
        reachability = reachability.model_copy(
            update={
                "dependent_component_count": item.dependent_component_count,
                "dependent_components": dependent_components,
                "dependent_components_truncated": len(item.dependent_components) > MAX_DEPENDENT_COMPONENTS,
                "scope_exposure": _scope_exposure(item),
                "notes": [
                    *reachability.notes,
                    *(
                        ["the traversal for dependents/entry paths is bounded at 5 hops"]
                        if item.dependent_components or item.entry_points
                        else []
                    ),
                ],
            }
        )
        priority = FindingPriority(
            score=score,
            formula_version=FORMULA_VERSION,
            rank=rank,
            factors=factors,
            severity=severity,
            reachability=reachability,
            remediation_available=bool(item.fixed_versions),
            remediation_note=(
                "an advisory fixed version exists for this package"
                if item.fixed_versions
                else "no fixed version is recorded in the advisory evidence"
            ),
        )
        prioritized.append(Prioritized(inputs=item, priority=priority))
    return prioritized


def _scope_exposure(inputs: FindingInput) -> str:
    if inputs.is_dev:
        return "dev"
    if inputs.is_optional:
        return "optional"
    if inputs.dependency_role == "direct" or inputs.dependency_role == "transitive":
        return "runtime"
    return "unknown"


__all__ = [
    "FACTOR_WEIGHTS",
    "FORMULA_VERSION",
    "MAX_DEPENDENT_COMPONENTS",
    "NEUTRAL",
    "Prioritized",
    "REACHABILITY_VALUES",
    "compute_priority",
    "impact_factor",
    "prioritize",
    "remediation_factor",
    "severity_factor",
]
