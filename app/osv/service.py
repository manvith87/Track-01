"""OSV orchestration service (Phase 3).

Turns *targeted*, version-backed lookups into a deterministic report with
explicit, non-fabricating semantics:

* ``match_type="version"``  - OSV was queried with an exact resolved version,
  so upstream already confirmed that version falls inside the affected
  ranges.  Only these matches may become ``AFFECTED_BY`` edges.
* ``match_type="name"``     - only the package name was known; results are
  name-level information and are never written as vulnerability claims.

Reliability behaviour: discovery uses one batched ``/v1/querybatch`` per
chunk (with per-item page-token continuation through ``/v1/query``), full
records are hydrated via ``GET /v1/vulns/{id}`` with de-duplication, and
every per-item failure becomes a typed entry in the report instead of being
swallowed.  A discovery phase that yields nothing at all re-raises the
upstream error so partial ingestion cannot silently look successful.

The service also re-verifies that each hydrated record actually declares the
package it was matched for (defence in depth) and skips unmatched records.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.core.errors import InputValidationError
from app.core.logging import get_logger, safe_text
from app.osv.client import OsvApiClient
from app.osv.config import OsvSettings
from app.osv.errors import OsvError
from app.osv.models import (
    OsvAffected,
    OsvVulnerability,
    decode_vulnerability,
    decode_vulnerability_stub,
)

_log = get_logger("osv.service")

#: Graph ecosystem identifier -> OSV ecosystem token (case-sensitive upstream).
ECOSYSTEM_UPSTREAM: dict[str, str] = {"pypi": "PyPI"}
SUPPORTED_ECOSYSTEMS: tuple[str, ...] = tuple(ECOSYSTEM_UPSTREAM)

#: Status values for an :class:`OsvItemOutcome`.
STATUS_CONFIRMED = "confirmed"
STATUS_NO_MATCHES = "no_matches"
STATUS_NAME_ONLY = "name_only"

MATCH_TYPE_VERSION = "version"
MATCH_TYPE_NAME = "name"


class OsvPackageItem(BaseModel):
    """One package to look up upstream.

    ``version`` is the resolved version; ``None`` means only the package name
    is known (name-level lookups yield unverifiable matches).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    ecosystem: str
    package_name: str
    original_name: str | None = None
    version: str | None = None

    @property
    def key(self) -> str:
        return f"{self.ecosystem}|{self.package_name}|{self.version or ''}"


class OsvLookupResult(BaseModel):
    """Outcome of a single live ``/v1/query`` lookup (no graph writes)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    ecosystem: str = Field(description="BlastRadius ecosystem identifier (e.g. 'pypi').")
    upstream_ecosystem: str = Field(description="Ecosystem token sent to OSV (e.g. 'PyPI').")
    package_name: str
    version: str | None = None
    match_type: str = Field(description="'version' when queried with a version, else 'name'.")
    vulnerabilities: tuple[OsvVulnerability, ...] = ()
    errors: tuple[str, ...] = ()

    @property
    def count(self) -> int:
        return len(self.vulnerabilities)

    def confirmed(self) -> bool:
        """Whether the matches carry version evidence (not name-only)."""
        return self.match_type == MATCH_TYPE_VERSION


class OsvSyncError(BaseModel):
    """A typed, reportable failure of one targeted lookup step."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: str = Field(description="Machine-readable kind: discovery|hydrate|decode|package_mismatch|name_only.")
    message: str
    ecosystem: str | None = None
    package_name: str | None = None
    version: str | None = None
    vulnerability_id: str | None = None
    retryable: bool = False


class OsvItemOutcome(BaseModel):
    """Per-package outcome of one ingestion run."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    ecosystem: str
    package_name: str
    version: str | None
    status: str
    vulnerability_ids: tuple[str, ...] = ()


class OsvConfirmedMatch(BaseModel):
    """Version-backed package/vulnerability association ready for the graph."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    vulnerability_id: str
    ecosystem: str = Field(description="BlastRadius ecosystem identifier (e.g. 'pypi').")
    upstream_ecosystem: str
    package_name: str
    package_version: str
    match_type: str
    fixed_versions: tuple[str, ...] = ()
    ranges_json: str = Field(
        description="JSON string summarising the matched affected entry's ranges."
    )
    osv_modified: str | None = None


class OsvSyncReport(BaseModel):
    """Full outcome of one targeted vulnerability ingestion run."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    items_scanned: int = Field(ge=0)
    items_with_matches: int = Field(ge=0)
    items_without_matches: int = Field(ge=0)
    matches: tuple[OsvConfirmedMatch, ...] = ()
    vulnerabilities: tuple[OsvVulnerability, ...] = Field(
        default=(), description="Hydrated upstream records for this run (deduplicated)."
    )
    outcomes: tuple[OsvItemOutcome, ...] = ()
    errors: tuple[OsvSyncError, ...] = ()

    @property
    def vulnerability_count(self) -> int:
        return len(self.vulnerabilities)

    @property
    def status(self) -> str:
        if self.items_scanned == 0:
            return "nothing_to_scan"
        if self.errors:
            return "completed_with_errors"
        return "completed"


class OsvService:
    """Orchestrates OSV lookups and produces evidenced ingestion reports."""

    def __init__(self, client: OsvApiClient, settings: OsvSettings) -> None:
        self._client = client
        self._settings = settings

    # -- configuration helpers -----------------------------------------------
    @property
    def settings(self) -> OsvSettings:
        return self._settings

    @staticmethod
    def upstream_ecosystem(ecosystem: str) -> str:
        """Map a BlastRadius ecosystem identifier to the OSV token.

        Raises:
            InputValidationError: for ecosystems OSV lookups do not support.
        """
        mapped = ECOSYSTEM_UPSTREAM.get(ecosystem.strip().lower())
        if mapped is None:
            supported = ", ".join(SUPPORTED_ECOSYSTEMS)
            raise InputValidationError(
                f"Ecosystem {ecosystem!r} is not supported for OSV lookups (supported: {supported})"
            )
        return mapped

    # -- single lookup ---------------------------------------------------------
    def lookup(
        self, ecosystem: str, package_name: str, version: str | None = None
    ) -> OsvLookupResult:
        """Run one live ``/v1/query`` lookup and parse every returned record.

        With a ``version``, results are version-confirmed by OSV; without one,
        results are name-level only and reported with ``match_type="name"``.

        Raises:
            InputValidationError: for unknown ecosystems or an empty name.
            OsvError: when upstream communication fails.
        """
        upstream = self.upstream_ecosystem(ecosystem)
        name = package_name.strip()
        if not name:
            raise InputValidationError("package_name must not be empty")
        resolved_version = version.strip() if version else None
        match_type = MATCH_TYPE_VERSION if resolved_version else MATCH_TYPE_NAME

        raw_records = self._client.iter_vulnerabilities(
            ecosystem=upstream, package_name=name, version=resolved_version
        )

        vulns: list[OsvVulnerability] = []
        errors: list[str] = []
        for raw in raw_records:
            try:
                decoded = decode_vulnerability(
                    raw,
                    max_text_length=self._settings.max_details_length,
                    max_references=self._settings.max_references_per_vulnerability,
                )
            except ValueError as exc:
                errors.append(f"skipped undecodable record: {safe_text(exc, 160)}")
                continue
            # Defence in depth: only keep records that really declare the
            # requested package and ecosystem.
            if decoded.affected_entry_for(name, upstream) is None:
                errors.append(
                    f"record {decoded.id} does not declare package {name!r}; excluded"
                )
                continue
            vulns.append(decoded)

        return OsvLookupResult(
            ecosystem=upstream_ecosystem_key(ecosystem),
            upstream_ecosystem=upstream,
            package_name=name,
            version=resolved_version,
            match_type=match_type,
            vulnerabilities=tuple(vulns),
            errors=tuple(errors),
        )

    # -- ingestion synchroniser -----------------------------------------------
    def sync(self, items: Sequence[OsvPackageItem]) -> OsvSyncReport:
        """Discover, hydrate and evidence version-confirmed matches.

        Raises:
            InputValidationError: when caps from :class:`OsvSettings` would be
                exceeded (the run is refused rather than silently truncated).
            OsvError: when discovery fails for *every* chunk (nothing was
                learned, so the upstream failure is surfaced茉直接 to callers).
        """
        unique_items = _dedupe_items(items)
        for candidate in unique_items:
            if not candidate.package_name or not candidate.package_name.strip():
                raise InputValidationError("package_name must not be empty")
            # Normalises the ecosystem early so unsupported ecosystems fail
            # before any upstream traffic is generated.
            self.upstream_ecosystem(candidate.ecosystem)
        if len(unique_items) > self._settings.max_packages_per_ingest:
            raise InputValidationError(
                f"This ingestion would scan {len(unique_items)} distinct package items; "
                f"the configured cap is {self._settings.max_packages_per_ingest} "
                "(BLASTRADIUS_OSV_MAX_PACKAGES_PER_INGEST)"
            )

        discovered: dict[str, set[str]] = {item.key: set() for item in unique_items}
        errors: list[OsvSyncError] = []
        batch_failures = 0
        last_batch_error: OsvError | None = None

        # -- 1. batched discovery ---------------------------------------------
        for start in range(0, len(unique_items), self._settings.batch_size):
            chunk = unique_items[start : start + self._settings.batch_size]
            try:
                response = self._client.query_batch([_query_payload(item) for item in chunk])
            except OsvError as exc:
                batch_failures += 1
                last_batch_error = exc
                errors.append(_sync_error_from("discovery", exc))
                continue
            self._collect_discovery(
                [(start + position, item) for position, item in enumerate(chunk)],
                response,
                discovered,
                errors,
            )

        # -- 1b. name-spelling fallback for versioned misses --------------------
        if not batch_failures:
            fallback_items = [
                item
                for item in unique_items
                if item.version and not discovered[item.key] and _has_name_variant(item)
            ]
            for item in fallback_items:
                self._single_query_discovery(item, discovered, errors)

        if batch_failures and not any(discovered.values()):
            # Nothing at all was learned: surface the upstream failure.
            raise last_batch_error or OsvError("OSV discovery failed")

        # -- 2. outcomes & hydration set ---------------------------------------
        outcomes: list[OsvItemOutcome] = []
        hydrate_ids: set[str] = set()
        for item in unique_items:
            ids = discovered[item.key]
            if item.version is None:
                if ids:
                    errors.append(
                        OsvSyncError(
                            kind="name_only",
                            message=(
                                f"package {item.package_name} has no resolved version; "
                                f"{len(ids)} name-level OSV match(es) were reported but "
                                "not ingested"
                            ),
                            ecosystem=item.ecosystem,
                            package_name=item.package_name,
                        )
                    )
                outcomes.append(
                    OsvItemOutcome(
                        ecosystem=item.ecosystem,
                        package_name=item.package_name,
                        version=item.version,
                        status=STATUS_NAME_ONLY if ids else STATUS_NO_MATCHES,
                        vulnerability_ids=tuple(sorted(ids)),
                    )
                )
                continue
            if ids:
                hydrate_ids.update(ids)
            outcomes.append(
                OsvItemOutcome(
                    ecosystem=item.ecosystem,
                    package_name=item.package_name,
                    version=item.version,
                    status=STATUS_CONFIRMED if ids else STATUS_NO_MATCHES,
                    vulnerability_ids=tuple(sorted(ids)),
                )
            )

        # -- 3. hydrate full records (dedup, bounded, deterministic order) ------
        hydrated = self._hydrate(sorted(hydrate_ids), errors)

        # -- 4. evidence: verify then build matches -----------------------------
        matches: list[OsvConfirmedMatch] = []
        for item in unique_items:
            if item.version is None:
                continue
            for osv_id in sorted(hydrated):
                if osv_id not in discovered[item.key]:
                    continue
                vuln = hydrated[osv_id]
                entry = vuln.affected_entry_for(
                    item.package_name, self.upstream_ecosystem(item.ecosystem)
                )
                if entry is None:
                    errors.append(
                        OsvSyncError(
                            kind="package_mismatch",
                            message=(
                                f"record {osv_id} was matched for {item.package_name} "
                                f"{item.version} but does not declare that package; skipped"
                            ),
                            ecosystem=item.ecosystem,
                            package_name=item.package_name,
                            version=item.version,
                            vulnerability_id=osv_id,
                        )
                    )
                    continue
                matches.append(_confirmed_match(item, vuln, entry))

        report = OsvSyncReport(
            items_scanned=len(unique_items),
            items_with_matches=sum(1 for o in outcomes if o.status == STATUS_CONFIRMED),
            items_without_matches=sum(
                1 for o in outcomes if o.status in {STATUS_NO_MATCHES, STATUS_NAME_ONLY}
            ),
            matches=tuple(matches),
            vulnerabilities=tuple(vuln for vuln in (hydrated[osv_id] for osv_id in sorted(hydrated))),
            outcomes=tuple(outcomes),
            errors=tuple(errors),
        )
        _log.info(
            "osv sync items=%d matches=%d vulns=%d errors=%d",
            report.items_scanned,
            len(matches),
            len(report.vulnerabilities),
            len(errors),
        )
        return report

    # -- internals -------------------------------------------------------------
    def _collect_discovery(
        self,
        indexed_items: list[tuple[int, OsvPackageItem]],
        response: Sequence[Mapping[str, Any]],
        discovered: dict[str, set[str]],
        errors: list[OsvSyncError],
    ) -> None:
        """Apply one querybatch response to per-item discovery sets.

        ``indexed_items`` maps result position back to the unique item.
        """
        for position, (_item_index, item) in enumerate(indexed_items):
            if position >= len(response):
                errors.append(
                    OsvSyncError(
                        kind="discovery",
                        message=f"querybatch response missing result {position}",
                        ecosystem=item.ecosystem,
                        package_name=item.package_name,
                    )
                )
                continue
            entry = response[position]
            for raw in entry.get("vulns") or []:
                try:
                    stub = decode_vulnerability_stub(raw)
                except ValueError as exc:
                    errors.append(
                        OsvSyncError(
                            kind="decode",
                            message=f"querybatch result unusable: {safe_text(exc, 160)}",
                            ecosystem=item.ecosystem,
                            package_name=item.package_name,
                        )
                    )
                    continue
                discovered[item.key].add(stub.id)
            token = entry.get("next_page_token")
            if token:
                self._follow_item_pagination(item, token, discovered, errors)

    def _follow_item_pagination(
        self,
        item: OsvPackageItem,
        first_token: str,
        discovered: dict[str, set[str]],
        errors: list[OsvSyncError],
    ) -> None:
        """Continue one item's discovery through the single-query endpoint."""
        token: str | None = first_token
        pages = 0
        while token and pages < self._settings.max_pages_per_query:
            pages += 1
            try:
                response = self._client.query_vulnerabilities(
                    ecosystem=self.upstream_ecosystem(item.ecosystem),
                    package_name=item.package_name,
                    version=item.version,
                    page_token=token,
                )
            except OsvError as exc:
                errors.append(_sync_error_from("discovery", exc, item=item))
                return
            for raw in response.get("vulns") or []:
                try:
                    stub = decode_vulnerability_stub(raw)
                except ValueError as exc:
                    errors.append(
                        OsvSyncError(
                            kind="decode",
                            message=f"pagination entry unusable: {safe_text(exc, 160)}",
                            ecosystem=item.ecosystem,
                            package_name=item.package_name,
                        )
                    )
                    continue
                discovered[item.key].add(stub.id)
            token = response.get("next_page_token")

    def _single_query_discovery(
        self,
        item: OsvPackageItem,
        discovered: dict[str, set[str]],
        errors: list[OsvSyncError],
    ) -> None:
        """Retry one versioned miss with the alternate declared spelling."""
        variant = _alternate_name(item)
        if variant is None:
            return
        try:
            raw_records = self._client.iter_vulnerabilities(
                ecosystem=self.upstream_ecosystem(item.ecosystem),
                package_name=variant,
                version=item.version,
            )
        except OsvError as exc:
            errors.append(_sync_error_from("discovery", exc, item=item))
            return
        for raw in raw_records:
            try:
                stub = decode_vulnerability_stub(raw)
            except ValueError:
                continue
            discovered[item.key].add(stub.id)

    def _hydrate(
        self, osv_ids: Sequence[str], errors: list[OsvSyncError]
    ) -> dict[str, OsvVulnerability]:
        if len(osv_ids) > self._settings.max_vulnerabilities_per_ingest:
            raise InputValidationError(
                f"These packages matched {len(osv_ids)} distinct vulnerability records; "
                f"the configured cap is {self._settings.max_vulnerabilities_per_ingest} "
                "(BLASTRADIUS_OSV_MAX_VULNERABILITIES_PER_INGEST)"
            )
        hydrated: dict[str, OsvVulnerability] = {}
        for osv_id in osv_ids:
            try:
                raw = self._client.get_vulnerability(osv_id)
                vuln = decode_vulnerability(
                    raw,
                    max_text_length=self._settings.max_details_length,
                    max_references=self._settings.max_references_per_vulnerability,
                )
            except (OsvError, ValueError) as exc:
                errors.append(_sync_error_from("hydrate", exc, vulnerability_id=osv_id))
                continue
            hydrated[vuln.id] = vuln
        return hydrated


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def upstream_ecosystem_key(ecosystem: str) -> str:
    """Normalise an ecosystem identifier to its BlastRadius key form."""
    return ecosystem.strip().lower()


def _dedupe_items(items: Sequence[OsvPackageItem]) -> list[OsvPackageItem]:
    """Stable-order de-duplication by item key, preferring original names."""
    seen: dict[str, OsvPackageItem] = {}
    for item in items:
        existing = seen.get(item.key)
        if existing is None or (
            existing.original_name is None and item.original_name is not None
        ):
            seen[item.key] = item
    return list(seen.values())


def _query_payload(item: OsvPackageItem) -> dict[str, Any]:
    """Build one ``/v1/query``-shaped payload for discovery."""
    if item.ecosystem.strip().lower() not in ECOSYSTEM_UPSTREAM:
        raise InputValidationError(
            f"Ecosystem {item.ecosystem!r} is not supported for OSV lookups"
        )
    payload: dict[str, Any] = {
        "package": {
            "name": item.package_name,
            "ecosystem": OsvService.upstream_ecosystem(item.ecosystem),
        }
    }
    if item.version:
        payload["version"] = item.version
    return payload


def _has_name_variant(item: OsvPackageItem) -> bool:
    original = (item.original_name or "").strip()
    return bool(original) and original != item.package_name.strip()


def _alternate_name(item: OsvPackageItem) -> str | None:
    """A second, legitimate spelling of the package name worth retrying.

    The comparison is deliberately case/underscore sensitive: upstream
    registries (e.g. OSV's PyPI sources) may index the exact project spelling
    while BlastRadius normalizes names (PEP 503).
    """
    original = (item.original_name or "").strip()
    if not original or original == item.package_name.strip():
        return None
    return original


def _sync_error_from(
    kind: str,
    exc: Exception,
    *,
    item: OsvPackageItem | None = None,
    vulnerability_id: str | None = None,
) -> OsvSyncError:
    return OsvSyncError(
        kind=kind,
        message=safe_text(str(exc) or exc.__class__.__name__, 200),
        ecosystem=item.ecosystem if item else None,
        package_name=item.package_name if item else None,
        version=item.version if item else None,
        vulnerability_id=vulnerability_id,
        retryable=bool(getattr(exc, "retryable", False)),
    )


def _confirmed_match(
    item: OsvPackageItem, vuln: OsvVulnerability, entry: OsvAffected
) -> OsvConfirmedMatch:
    ranges = [range_obj.model_dump() for range_obj in entry.ranges]
    return OsvConfirmedMatch(
        vulnerability_id=vuln.id,
        ecosystem=item.ecosystem,
        upstream_ecosystem=OsvService.upstream_ecosystem(item.ecosystem),
        package_name=item.package_name,
        package_version=item.version or "",
        match_type=MATCH_TYPE_VERSION,
        fixed_versions=tuple(entry.fixed_versions),
        ranges_json=json.dumps(ranges, sort_keys=True),
        osv_modified=vuln.modified,
    )


__all__ = [
    "ECOSYSTEM_UPSTREAM",
    "MATCH_TYPE_NAME",
    "MATCH_TYPE_VERSION",
    "OsvConfirmedMatch",
    "OsvLookupResult",
    "OsvPackageItem",
    "OsvSyncError",
    "OsvSyncReport",
    "OsvService",
    "SUPPORTED_ECOSYSTEMS",
    "STATUS_CONFIRMED",
    "STATUS_NAME_ONLY",
    "STATUS_NO_MATCHES",
]
