"""Strict decoding of OSV API responses into validated models (Phase 3).

The models below mirror the OSV schema (https://ossf.github.io/osv-schema/)
only for the fields BlastRadius stores.  Decoding rules:

* unknown fields are ignored, missing fields default to ``None``/empty —
  BlastRadius never invents severity scores, dates or affected ranges;
* anything typed differently than expected is treated as absent rather than
  coerced, so malformed upstream data surfaces as "unknown" instead of as a
  fabricated value;
* long free-text fields are truncated to the configured bound (truncation is
  flagged, the truncated value is still exactly what upstream sent).
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class OsvPackage(BaseModel):
    """An affected package as identified by OSV."""

    model_config = ConfigDict(extra="ignore", frozen=True)

    name: str | None = None
    ecosystem: str | None = None
    purl: str | None = None


class OsvRangeEvent(BaseModel):
    """One event of a version range (mutually exclusive keys in OSV)."""

    model_config = ConfigDict(extra="ignore", frozen=True)

    introduced: str | None = None
    fixed: str | None = None
    last_affected: str | None = None
    limit: str | None = None


class OsvRange(BaseModel):
    """A single affected range of one affected package entry."""

    model_config = ConfigDict(extra="ignore", frozen=True)

    type: str | None = None
    repo: str | None = None
    events: tuple[OsvRangeEvent, ...] = ()

    @property
    def fixed_versions(self) -> tuple[str, ...]:
        """Versions at which the vulnerability stops affecting the range.

        ``GIT`` ranges carry commit SHAs, not released versions; they are
        excluded so that a commit sha is never mistaken for a package version.
        """
        keep = tuple(
            event.fixed
            for event in self.events
            if event.fixed and self.type in {"ECOSYSTEM", "SEMVER"}
        )
        seen: set[str] = set()
        ordered: list[str] = []
        for value in keep:
            if value not in seen:
                seen.add(value)
                ordered.append(value)
        return tuple(ordered)


class OsvAffected(BaseModel):
    """One ``affected`` entry of an OSV record."""

    model_config = ConfigDict(extra="ignore", frozen=True)

    package: OsvPackage | None = None
    ranges: tuple[OsvRange, ...] = ()
    versions: tuple[str, ...] = ()
    severity_type: str | None = None
    severity_score: str | None = None

    @property
    def fixed_versions(self) -> tuple[str, ...]:
        """De-duplicated ``fixed`` versions across this entry's ranges."""
        ordered: list[str] = []
        for entry_range in self.ranges:
            ordered.extend(entry_range.fixed_versions)
        return tuple(dict.fromkeys(ordered))

    def matches(self, name: str, ecosystem: str) -> bool:
        """Whether this entry identifies the given package (name-normalized).

        PyPI-style ecosystems are case-insensitive and hyphen/underscore
        equivalent, so the comparison normalizes both sides minimally without
        inventing any data.
        """
        if self.package is None:
            return False
        entry_name = self.package.name
        entry_ecosystem = self.package.ecosystem
        if not entry_name or not entry_ecosystem:
            return False
        return _normalize_name(entry_name) == _normalize_name(name) and (
            entry_ecosystem.lower() == ecosystem.lower()
        )


class OsvReference(BaseModel):
    """A reference URL attached to a vulnerability record."""

    model_config = ConfigDict(extra="ignore", frozen=True)

    type: str | None = None
    url: str | None = None


class OsvSeverity(BaseModel):
    """Severity metadata exactly as supplied by OSV (never normalised)."""

    model_config = ConfigDict(extra="ignore", frozen=True)

    type: str | None = None
    score: str | None = None


class OsvVulnerability(BaseModel):
    """A decoded OSV vulnerability record."""

    model_config = ConfigDict(extra="ignore", frozen=True)

    id: str
    summary: str | None = None
    details: str | None = None
    aliases: tuple[str, ...] = ()
    related: tuple[str, ...] = ()
    published: str | None = None
    modified: str | None = None
    withdrawn: str | None = None
    schema_version: str | None = None
    severities: tuple[OsvSeverity, ...] = ()
    references: tuple[OsvReference, ...] = ()
    affected: tuple[OsvAffected, ...] = ()

    @field_validator("id")
    @classmethod
    def _validate_id(cls, value: Any) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValueError("OSV record is missing a usable 'id'")
        return value.strip()

    def affected_entry_for(self, name: str, ecosystem: str) -> OsvAffected | None:
        """The affected entry matching the requested package, if any."""
        for entry in self.affected:
            if entry.matches(name, ecosystem):
                return entry
        return None

    def affected_package_keys(self) -> tuple[str, ...]:
        """Compact ``ecosystem:name`` keys for every affected entry."""
        keys: list[str] = []
        for entry in self.affected:
            if entry.package and entry.package.name and entry.package.ecosystem:
                keys.append(f"{entry.package.ecosystem}:{entry.package.name}")
        return tuple(dict.fromkeys(keys))


class OsvVulnerabilityStub(BaseModel):
    """Id + modified pair returned by ``/v1/querybatch`` discovery."""

    model_config = ConfigDict(extra="ignore", frozen=True)

    id: str
    modified: str | None = None


def decode_vulnerability(
    raw: Any, *, max_text_length: int = 4_000, max_references: int = 50
) -> OsvVulnerability:
    """Decode one raw upstream vulnerability object into :class:`OsvVulnerability`.

    Raises:
        ValueError: if the payload is not an object or has no usable ``id``.
    """
    if not isinstance(raw, dict):
        raise ValueError("OSV vulnerability record must be a JSON object")
    if not isinstance(raw.get("id"), str) or not raw.get("id", "").strip():
        raise ValueError("OSV vulnerability record is missing a usable 'id'")

    summary = _short_text(raw.get("summary"), max_text_length)
    details = _short_text(raw.get("details"), max_text_length)
    aliases = _string_tuple(raw.get("aliases"))
    related = _string_tuple(raw.get("related"))

    published = _timestamp_text(raw.get("published"))
    modified = _timestamp_text(raw.get("modified"))
    withdrawn = _timestamp_text(raw.get("withdrawn"))
    schema_version = raw.get("schema_version") if isinstance(raw.get("schema_version"), str) else None

    severities: list[OsvSeverity] = []
    for item in _list_of_dicts(raw.get("severity")):
        if not _has_severity_shape(item):
            continue
        sev = OsvSeverity(
            type=item.get("type") if isinstance(item.get("type"), str) else None,
            score=item.get("score") if isinstance(item.get("score"), str) else None,
        )
        if sev.type or sev.score:
            severities.append(sev)

    references: list[OsvReference] = []
    for item in _list_of_dicts(raw.get("references")):
        ref = OsvReference(
            type=item.get("type") if isinstance(item.get("type"), str) else None,
            url=item.get("url") if isinstance(item.get("url"), str) else None,
        )
        if ref.url:
            references.append(ref)

    affected: list[OsvAffected] = []
    for item in _list_of_dicts(raw.get("affected")):
        affected.append(_decode_affected(item))

    return OsvVulnerability(
        id=raw["id"],
        summary=summary,
        details=details,
        aliases=aliases,
        related=related,
        published=published,
        modified=modified,
        withdrawn=withdrawn,
        schema_version=schema_version,
        severities=tuple(severities),
        references=tuple(references[: max(1, max_references)]),
        affected=tuple(affected),
    )


def _decode_affected(item: dict[str, Any]) -> OsvAffected:
    package_raw = item.get("package") if isinstance(item.get("package"), dict) else None
    package = None
    if package_raw is not None and any(
        isinstance(package_raw.get(key), str) for key in ("name", "ecosystem", "purl")
    ):
        package = OsvPackage(
            name=package_raw.get("name") if isinstance(package_raw.get("name"), str) else None,
            ecosystem=(
                package_raw.get("ecosystem") if isinstance(package_raw.get("ecosystem"), str) else None
            ),
            purl=package_raw.get("purl") if isinstance(package_raw.get("purl"), str) else None,
        )

    ranges: list[OsvRange] = []
    for range_raw in _list_of_dicts(item.get("ranges")):
        type_value = range_raw.get("type") if isinstance(range_raw.get("type"), str) else None
        repo = range_raw.get("repo") if isinstance(range_raw.get("repo"), str) else None
        events: list[OsvRangeEvent] = []
        for event_raw in _list_of_dicts(range_raw.get("events")):
            known = OsvRangeEvent(
                introduced=(
                    event_raw.get("introduced")
                    if isinstance(event_raw.get("introduced"), str)
                    else None
                ),
                fixed=event_raw.get("fixed") if isinstance(event_raw.get("fixed"), str) else None,
                last_affected=(
                    event_raw.get("last_affected")
                    if isinstance(event_raw.get("last_affected"), str)
                    else None
                ),
                limit=event_raw.get("limit") if isinstance(event_raw.get("limit"), str) else None,
            )
            if any((known.introduced, known.fixed, known.last_affected, known.limit)):
                events.append(known)
        if events or type_value or repo:
            ranges.append(OsvRange(type=type_value, repo=repo, events=tuple(events)))

    versions = _string_tuple(item.get("versions"))

    severity_type: str | None = None
    severity_score: str | None = None
    for key in ("severity", "database_specific"):
        nested = item.get(key)
        if isinstance(nested, dict):
            if isinstance(nested.get("type"), str):
                severity_type = nested["type"]
            if isinstance(nested.get("score"), str):
                severity_score = nested["score"]

    return OsvAffected(
        package=package,
        ranges=tuple(ranges),
        versions=versions,
        severity_type=severity_type,
        severity_score=severity_score,
    )


def decode_vulnerability_stub(raw: Any) -> OsvVulnerabilityStub:
    """Decode a querybatch result entry (``id`` + optional ``modified``)."""
    if not isinstance(raw, dict):
        raise ValueError("querybatch result entry must be a JSON object")
    if not isinstance(raw.get("id"), str) or not raw.get("id", "").strip():
        raise ValueError("querybatch result entry is missing a usable 'id'")
    return OsvVulnerabilityStub(
        id=raw["id"],
        modified=raw.get("modified") if isinstance(raw.get("modified"), str) else None,
    )


def _list_of_dicts(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _has_severity_shape(item: dict[str, Any]) -> bool:
    return isinstance(item.get("type"), str) or isinstance(item.get("score"), str)


def _string_tuple(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(item for item in value if isinstance(item, str) and item.strip())


def _short_text(value: Any, max_length: int) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if len(text) > max_length:
        return text[:max_length]
    return text


def _timestamp_text(value: Any) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    return value.strip()


def _normalize_name(name: str) -> str:
    return name.strip().lower().replace("_", "-")

__all__ = [
    "OsvAffected",
    "OsvPackage",
    "OsvRange",
    "OsvRangeEvent",
    "OsvReference",
    "OsvSeverity",
    "OsvVulnerability",
    "OsvVulnerabilityStub",
    "decode_vulnerability",
    "decode_vulnerability_stub",
]
