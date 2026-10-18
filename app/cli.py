"""Command line interface for BlastRadius Phase 1.

Used for manual and live verification (it is the same service function the API
calls):

    python -m app.cli ingest https://github.com/psf/requests
    python -m app.cli ingest https://github.com/psf/requests --ref v2.32.3 --json
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter

from app.core.config import get_settings
from app.core.errors import BlastRadiusError
from app.core.logging import configure_logging
from app.ingestion.service import ingest_repository
from app.models.ingestion import IngestionResult


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="blastradius", description="BlastRadius Phase 1 repository ingestion")
    subparsers = parser.add_subparsers(dest="command", required=True)

    ingest = subparsers.add_parser("ingest", help="Ingest a public GitHub repository and extract dependencies")
    ingest.add_argument("repository_url", help="HTTPS URL of a public GitHub repository")
    ingest.add_argument("--ref", default=None, help="Branch, tag or commit SHA (defaults to the default branch)")
    ingest.add_argument("--json", action="store_true", help="Print the complete result as JSON")
    ingest.add_argument("--max-records", type=int, default=5, help="Records to show per section in the text summary")
    return parser


def _print_summary(result: IngestionResult, *, max_records: int) -> None:
    repository = result.repository
    identity = repository.identity.canonical_id if repository else "<unknown>"
    print(f"repository        : {identity}")
    print(f"status            : {result.status.value}")
    print(f"commit sha        : {result.reference.resolved_commit_sha}")
    print(f"reference         : {result.reference.requested_ref or '<default branch>'} ({result.reference.ref_type.value})")
    print(f"retrieved via     : {result.summary.retrieval_strategy}")
    print(f"files examined    : {result.summary.files_examined}")
    print(f"manifests detected: {result.summary.manifests_detected}")
    print(f"declarations      : {result.summary.declarations}")
    print(f"resolved packages : {result.summary.resolved_packages}")
    print(f"dependency edges  : {result.summary.dependency_edges}")
    print(f"warnings / errors : {result.summary.warning_count} / {result.summary.error_count}")

    if result.declarations:
        print("\ndeclarations:")
        for declaration in result.declarations[:max_records]:
            constraint = declaration.version_constraint or "<none>"
            resolved = declaration.resolved_version or "-"
            print(
                f"  - {declaration.original_name} ({declaration.normalized_name}) {constraint} "
                f"[scope={declaration.scope.value} relation={declaration.relation.value} resolved={resolved}] "
                f"<- {declaration.provenance.manifest_path}:{declaration.provenance.line_number or '?'}"
            )
        if len(result.declarations) > max_records:
            print(f"  ... {len(result.declarations) - max_records} more")

    if result.resolved_packages:
        print("\nresolved packages:")
        for package in result.resolved_packages[:max_records]:
            print(
                f"  - {package.normalized_name}=={package.version} "
                f"[relation={package.relation.value} dev={package.is_dev} from={package.source_manifest}]"
            )
        if len(result.resolved_packages) > max_records:
            print(f"  ... {len(result.resolved_packages) - max_records} more")

    unsupported = [coverage for coverage in result.coverage if coverage.support_level.value == "unsupported"]
    if unsupported:
        print("\nunsupported dependency files detected:")
        for coverage in unsupported:
            print(f"  - {coverage.format} ({coverage.detected_files} file(s))")

    if result.warnings:
        counts = Counter(warning.code.value for warning in result.warnings)
        print("\nwarnings by code:")
        for code, count in sorted(counts.items()):
            print(f"  - {code}: {count}")

    if result.errors:
        print("\nerrors:")
        for error in result.errors[:max_records]:
            print(f"  - {error.code.value} [{error.manifest_path or '-'}]: {error.message}")


def main(argv: list[str] | None = None) -> int:
    """Entry point for ``blastradius-ingest`` and ``python -m app.cli``."""
    args = _build_parser().parse_args(argv)
    settings = get_settings()
    configure_logging(settings.log_level, json_output=False)

    if args.command != "ingest":  # pragma: no cover - argparse enforces this
        return 2

    try:
        result = ingest_repository(args.repository_url, args.ref, settings=settings)
    except BlastRadiusError as exc:
        print(f"ingestion failed: {exc.code.value} ({exc.stage.value}) - {exc.message}", file=sys.stderr)
        if exc.details:
            print(f"details: {json.dumps(exc.details, default=str)}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(result.model_dump(mode="json"), indent=2, default=str))
    else:
        _print_summary(result, max_records=max(0, args.max_records))
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
