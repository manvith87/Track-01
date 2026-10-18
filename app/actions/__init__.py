"""Secure, user-approved GitHub actions (Phase 6).

This package implements the only code path in BlastRadius that performs a
GitHub **write**: creating one issue from a previewed, digest-bound remediation
payload after an explicitly authorized confirmation.

Design rules encoded here:

* GitHub writes are disabled unless ``BLASTRADIUS_ACTIONS_ENABLED`` is set and a
  dedicated token is configured;
* the target repository always comes from the persisted analysis/repository
  records — never from a request body;
* a preview never calls a write endpoint; confirmation revalidates the evidence,
  binds to the previewed payload digest and is refused after expiry or replay;
* every state transition is recorded in a persistent store for audit, and an
  ambiguous write outcome is reconciled through a unique action marker instead of
  being retried blindly.
"""

from __future__ import annotations

__all__: list[str] = []
