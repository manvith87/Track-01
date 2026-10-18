"""Canonical payload digest for preview/confirmation binding (Phase 6).

The digest binds a confirmation to the *exact* payload that was previewed:
repository target, analysis/commit, the selected finding or group, the issue
title/body and the template version.  It is computed over a canonical JSON
rendering (sorted keys, compact separators, UTF-8) so any change to any bound
field — including a repository substitution attempt — produces a different
digest and is rejected.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Final

#: Digest prefix so stored/inspected values are self-describing.
DIGEST_PREFIX: Final[str] = "sha256:"

#: Stable identifier of the issue template; changing the template requires a
#: new version so a stored digest never silently matches different content.
TEMPLATE_VERSION: Final[str] = "blastradius-issue-v1"

PayloadValue = str | int | None


def canonical_payload_json(payload: dict[str, Any]) -> str:
    """Render a payload as canonical JSON (sorted keys, compact, UTF-8 safe)."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def compute_payload_digest(payload: dict[str, Any]) -> str:
    """Return ``sha256:<64 hex>`` over the canonical payload JSON."""
    canonical = canonical_payload_json(payload)
    return DIGEST_PREFIX + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def build_action_payload(
    *,
    action_id: str,
    analysis_id: str,
    repository_id: str,
    repository_owner: str,
    repository_name: str,
    commit_sha: str,
    group_id: str | None,
    finding_id: str | None,
    title: str,
    body: str,
) -> dict[str, PayloadValue]:
    """The single canonical payload bound by a preview/confirmation pair."""
    return {
        "template_version": TEMPLATE_VERSION,
        "action_id": action_id,
        "analysis_id": analysis_id,
        "repository_id": repository_id,
        "repository_owner": repository_owner,
        "repository_name": repository_name,
        "commit_sha": commit_sha,
        "group_id": group_id,
        "finding_id": finding_id,
        "title": title,
        "body": body,
    }


__all__ = [
    "DIGEST_PREFIX",
    "TEMPLATE_VERSION",
    "build_action_payload",
    "canonical_payload_json",
    "compute_payload_digest",
]
