"""Stable identifier helpers.

Every persisted record needs an identifier that is

* deterministic - ingesting the same repository at the same commit with the
  same parser version yields the same ids, so Phase 2 can upsert idempotently;
* collision resistant - a truncated SHA-256 digest over all distinguishing
  fields;
* human scannable - a short, typed prefix (``decl_``, ``pkg_``, ``edge_``).
"""

from __future__ import annotations

import hashlib
from typing import Final

_ID_PREFIX_LENGTH: Final[int] = 16


def stable_id(prefix: str, *parts: object) -> str:
    """Return ``f"{prefix}_{digest}"`` for the given identifying parts.

    ``None`` values are rendered as an empty string so that adding an optional
    field does not change the id space unexpectedly.
    """
    joined = "|".join("" if part is None else str(part) for part in parts)
    digest = hashlib.sha256(joined.encode("utf-8")).hexdigest()[:_ID_PREFIX_LENGTH]
    return f"{prefix}_{digest}"


def short_sha(sha: str, length: int = 12) -> str:
    """Return a shortened commit SHA for display purposes."""
    return sha[:length] if sha else ""


__all__ = ["short_sha", "stable_id"]
