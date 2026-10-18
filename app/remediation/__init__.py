"""BlastRadius Phase 5: deterministic prioritization and remediation planning.

The package is deliberately LLM-free: every number, ranking and proposed
version is derived from persisted graph/advisory facts (Phases 2/3) with a
documented formula.  Nothing is written back to the graph and no resolver or
package manager is ever executed.

Modules:

* :mod:`app.remediation.models` — typed output contract (findings, factors,
  candidates, groups);
* :mod:`app.remediation.priority` — the documented priority formula
  (``blastradius-priority-v1``; never a CVSS score);
* :mod:`app.remediation.ranges` — OSV range validation of proposed versions;
* :mod:`app.remediation.severity` — advisory severity parsing (verbatim);
* :mod:`app.remediation.versions` — PEP 440 constraint evaluation;
* :mod:`app.remediation.candidates` — advisory-sourced upgrade candidates;
* :mod:`app.remediation.groups` — fix grouping and ranking;
* :mod:`app.remediation.service` — read-only orchestration.
"""

from app.remediation.models import (
    AnalysisReport,
    FindingOut,
    FixGroup,
    PackageRemediationPlan,
)
from app.remediation.service import RemediationService

__all__ = [
    "AnalysisReport",
    "FindingOut",
    "FixGroup",
    "PackageRemediationPlan",
    "RemediationService",
]
