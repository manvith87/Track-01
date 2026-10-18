"""GitHub REST integration for BlastRadius Phase 6.

The Phase 1 read-only client lives in :mod:`app.ingestion.github_api`; this
package deliberately contains a *separate* client whose only capability is the
one write BlastRadius is allowed to perform (issue creation) plus the read-only
metadata lookups needed to validate the target and reconcile ambiguous
outcomes.  Keeping the write capability in its own module means the ingestion
client continues to guarantee "no writes" by construction.
"""

from __future__ import annotations

__all__: list[str] = []
