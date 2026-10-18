"""Deterministic version and constraint evaluation (Phase 5).

All comparisons use :mod:`packaging` (PEP 440).  When a version or constraint
cannot be evaluated with PEP 440 semantics — for example Poetry-style
constraints (``^1.2``, ``1.2 || 1.3``) — the result is explicitly unknown
rather than guessed.  Nothing here ever invents a version.
"""

from __future__ import annotations

import re

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

#: Constraint scheme identifiers (mirrors app.models.common.ConstraintScheme).
SCHEME_PEP440 = "pep440"
SCHEME_POETRY = "poetry"
SCHEME_ANY = "any"
SCHEME_UNKNOWN = "unknown"

#: Substrings that identify Poetry-style constraint syntax PEP 440 cannot parse.
_POETRY_MARKERS = ("^", "||")

#: Prefix wildcards (``*``, ``2.*``, ``2.3.*``, ``==2.*``, ``!=2.*``) are common
#: in Python projects but are not valid ``SpecifierSet`` strings.  They are
#: evaluated deterministically as PEP 440-style prefix matches.
_WILDCARD_PATTERN = re.compile(r"^(?P<op>==|!=)?(?:v)?(?P<prefix>\d+(?:\.\d+)*)?\.?\*$")


def parse_version(text: str | None) -> Version | None:
    """Parse a PEP 440 version, returning ``None`` when it is not comparable."""
    if text is None:
        return None
    cleaned = str(text).strip()
    if not cleaned:
        return None
    try:
        return Version(cleaned)
    except InvalidVersion:
        return None


def version_sort_key(text: str | None) -> tuple[int, Version | str]:
    """Total order key: parsable versions sort numerically, others last."""
    parsed = parse_version(text)
    if parsed is not None:
        return (0, parsed)
    return (1, text or "")


def looks_like_poetry(constraint: str) -> bool:
    """True when the constraint uses syntax outside PEP 440 (``^``, ``||``, bare ``~``)."""
    if any(marker in constraint for marker in _POETRY_MARKERS):
        return True
    return "~" in constraint and "~=" not in constraint


def _evaluate_prefix_wildcard(text: str, target: Version) -> bool | None:
    """Evaluate a prefix wildcard as a PEP 440 prefix match.

    ``2.*`` matches any version whose release starts with ``2`` and ``2.3.*``
    any release starting with ``2.3`` — the same semantics pip gives ``==2.*``.
    Returns ``None`` when *text* is not a prefix wildcard.
    """
    match = _WILDCARD_PATTERN.match(text)
    if match is None:
        return None
    prefix_text = match.group("prefix")
    if prefix_text is None:
        matched = True
    else:
        prefix = tuple(int(part) for part in prefix_text.split("."))
        matched = target.release[: len(prefix)] == prefix
    if match.group("op") == "!=":
        return not matched
    return matched


def evaluate_constraint(
    constraint: str | None,
    scheme: str | None,
    proposed: str,
) -> tuple[bool | None, str, str]:
    """Evaluate one recorded constraint against a proposed version.

    Returns ``(satisfied, scheme_used, detail)`` where ``satisfied`` is

    * ``True``  — the constraint admits the proposed version (PEP 440), or the
      source records no version restriction at all;
    * ``False`` — the constraint rejects the proposed version (PEP 440),
      including prefix wildcards such as ``2.*``;
    * ``None``  — it cannot be evaluated (Poetry syntax, non-PEP 440 version
      or specifier), so compatibility stays unverified.
    """
    normalized_scheme = (scheme or "").strip().lower() or SCHEME_UNKNOWN
    text = "" if constraint is None else str(constraint).strip()

    if not text:
        return True, normalized_scheme, "no version restriction is recorded for this source"
    if normalized_scheme == SCHEME_ANY:
        return True, SCHEME_ANY, "the source places no version restriction on the package"
    if normalized_scheme == SCHEME_POETRY or looks_like_poetry(text):
        return (
            None,
            SCHEME_POETRY,
            f"Poetry-style constraint {text!r} cannot be evaluated with PEP 440 tooling",
        )

    target = parse_version(proposed)
    if target is None:
        return (
            None,
            SCHEME_PEP440,
            f"proposed version {proposed!r} is not a PEP 440 version",
        )

    wildcard_satisfied = _evaluate_prefix_wildcard(text, target)
    if wildcard_satisfied is not None:
        verb = "satisfies" if wildcard_satisfied else "violates"
        return (
            wildcard_satisfied,
            SCHEME_PEP440,
            f"{proposed!r} {verb} wildcard prefix constraint {text!r}",
        )

    try:
        specifier = SpecifierSet(text)
    except InvalidSpecifier:
        return (
            None,
            SCHEME_UNKNOWN,
            f"constraint {text!r} is not a PEP 440 specifier set",
        )

    satisfied = specifier.contains(target)
    verb = "satisfies" if satisfied else "violates"
    return satisfied, SCHEME_PEP440, f"{proposed!r} {verb} {text!r}"


__all__ = [
    "SCHEME_ANY",
    "SCHEME_PEP440",
    "SCHEME_POETRY",
    "SCHEME_UNKNOWN",
    "evaluate_constraint",
    "looks_like_poetry",
    "parse_version",
    "version_sort_key",
]
