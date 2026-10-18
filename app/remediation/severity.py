"""Advisory severity parsing (Phase 5).

Phase 3 stores OSV severity entries verbatim as ``f"{type} {score}"`` strings
(e.g. ``"CVSS_V3 CVSS:3.1/AV:N/..."`` or ``"CVSS_V3 9.8"``).  This module
splits those entries without altering them and extracts a *reported numeric
score* only when the advisory itself carries one.

BlastRadius never computes a CVSS base score from a vector, so a vector-only
advisory yields ``quantified=False`` with the vector kept verbatim for
display.  The custom priority score treats that case as neutral — it is never
labelled, or used, as CVSS.
"""

from __future__ import annotations

from collections.abc import Iterable

from app.remediation.models import SeverityEvidence


def parse_advisory_severity(entries: Iterable[str] | None) -> SeverityEvidence:
    """Parse stored ``"TYPE score"`` severity entries into typed evidence."""
    verbatim: list[str] = []
    for entry in entries or ():
        if entry is None:
            continue
        text = str(entry).strip()
        if text:
            verbatim.append(text)

    numeric: list[tuple[str, float]] = []
    vectors: list[tuple[str, str]] = []
    for entry in verbatim:
        score_type, _, score = entry.partition(" ")
        score_type = score_type.strip() or "UNKNOWN"
        score = score.strip()
        if not score:
            continue
        if score.upper().startswith("CVSS:"):
            vectors.append((score_type, score))
            continue
        try:
            value = float(score)
        except ValueError:
            continue
        if 0.0 <= value <= 10.0:
            numeric.append((score_type, value))

    numeric_score: float | None = None
    score_type: str | None = None
    if numeric:
        # Deterministic: highest reported score, ties broken by type name.
        best = sorted(numeric, key=lambda item: (-item[1], item[0]))[0]
        score_type, numeric_score = best

    vector: str | None = None
    vector_types: list[str] = []
    if vectors:
        vector = sorted(vectors, key=lambda item: item[0])[0][1]
        vector_types = sorted({item[0] for item in vectors})

    if numeric_score is not None:
        note = f"advisory-reported numeric score ({score_type})"
    elif vector is not None:
        note = (
            "the advisory reports CVSS vector(s) but no numeric score; "
            "BlastRadius never computes scores from vectors"
        )
    elif verbatim:
        note = "the advisory severity entries carry no numeric score"
    else:
        note = "the advisory record carries no severity entries"

    return SeverityEvidence(
        source="osv",
        quantified=numeric_score is not None,
        numeric_score=numeric_score,
        score_type=score_type,
        vector=vector,
        vector_types=vector_types,
        entries=verbatim,
        note=note,
    )


__all__ = ["parse_advisory_severity"]
