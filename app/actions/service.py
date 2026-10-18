"""Preview/confirm orchestration for approved GitHub issues (Phase 6).

The service is the only place where the Phase 5 remediation evidence, the
persisted repository identity, the persistent action store and the GitHub issue
client meet.  Its guarantees:

* **No caller-supplied facts.**  A preview selects a server-issued
  ``group_id``/``finding_id``; the target repository, commit SHA and every fact
  in the issue body come from the analysis itself.
* **No write during preview.**  Preview only reads GitHub repository metadata
  (preflight) and persists a local PREVIEWED action.
* **Explicit, digest-bound authorization.**  Confirmation requires the
  dedicated confirmation secret, the exact payload digest of the preview, and
  the evidence is regenerated and compared before the write.
* **Single-shot execution.**  The store's compare-and-set transition reserves
  the action; duplicates, replays and expired previews are refused.
* **Fail safe on ambiguity.**  An ambiguous GitHub outcome is reconciled
  through the unique action marker, never retried blindly.
"""

from __future__ import annotations

import hmac
import secrets
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from typing import Any

from app.actions.config import ActionSettings
from app.actions.digest import (
    TEMPLATE_VERSION,
    build_action_payload,
    compute_payload_digest,
)
from app.actions.issue_content import (
    MARKER_TEMPLATE,
    IssueSubject,
    build_issue_content,
)
from app.actions.models import (
    PREVIEW_NOTES,
    ActionRecord,
    IssueConfirmOut,
    IssueConfirmRequest,
    IssuePreviewOut,
    IssuePreviewRequest,
    IssueSubjectSelection,
    RepositoryTarget,
)
from app.actions.store import ActionStore
from app.core.errors import (
    ActionAuthorizationNotConfiguredError,
    ActionConsumedError,
    ActionEvidenceChangedError,
    ActionExpiredError,
    ActionInProgressError,
    ActionNotFoundError,
    ActionNotConfiguredError,
    ActionPayloadMismatchError,
    ActionRepositoryInvalidError,
    ActionRepositoryNotAllowedError,
    ActionUnauthorizedError,
    ActionStoreError,
    BlastRadiusError,
    GitHubIssuesDisabledError,
    GitHubWriteAmbiguousError,
    GitHubWriteDisabledError,
)
from app.core.logging import get_logger
from app.github.issue_client import GitHubIssueClient, RepositoryAccess
from app.graph.errors import GraphRecordNotFoundError
from app.graph.service import GraphService
from app.ingestion.urls import parse_repository_url
from app.models.common import ErrorCode
from app.remediation.models import (
    AnalysisReport,
    FindingOut,
    FixGroup,
    PackageRemediationPlan,
)
from app.remediation.service import RemediationService

_log = get_logger("actions.github_issue")

#: Action ids are random capabilities: 128 bits of entropy, prefixed so their
#: role is obvious in logs and responses.
ACTION_ID_PREFIX = "act_"


def new_action_id() -> str:
    """Return a fresh, unguessable action identifier."""
    return f"{ACTION_ID_PREFIX}{secrets.token_hex(16)}"


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _dedupe(items: list[str]) -> list[str]:
    return list(dict.fromkeys(item for item in items if item))


class GitHubIssueService:
    """Deterministic preview generation plus the single authorized write path."""

    def __init__(
        self,
        *,
        remediation: RemediationService,
        graph: GraphService,
        github: GitHubIssueClient,
        store: ActionStore,
        settings: ActionSettings,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._remediation = remediation
        self._graph = graph
        self._github = github
        self._store = store
        self._settings = settings
        self._clock = clock or utcnow

    # ------------------------------------------------------------------ #
    # configuration gates
    # ------------------------------------------------------------------ #
    def _require_write_ready(self) -> None:
        if not self._settings.enabled:
            raise GitHubWriteDisabledError(
                "GitHub write actions are disabled in this deployment "
                "(set BLASTRADIUS_ACTIONS_ENABLED=true to enable them)",
                details={"config": "BLASTRADIUS_ACTIONS_ENABLED"},
            )
        if not self._settings.has_token:
            raise ActionNotConfiguredError(
                "GitHub issue actions are not configured: no action token is set",
                details={"config": "BLASTRADIUS_ACTIONS_GITHUB_TOKEN"},
            )

    def _require_authorization(self, approval_key: str | None) -> None:
        if not self._settings.has_approval_secret:
            raise ActionAuthorizationNotConfiguredError(
                "GitHub issue confirmation is disabled: no confirmation secret is configured",
                details={"config": "BLASTRADIUS_ACTIONS_APPROVAL_SECRET"},
            )
        assert self._settings.approval_secret is not None  # guarded by has_approval_secret
        secret = self._settings.approval_secret.get_secret_value()
        if not approval_key:
            raise ActionUnauthorizedError(
                "The confirmation request carried no authorization secret"
            )
        if not hmac.compare_digest(approval_key, secret):
            raise ActionUnauthorizedError(
                "The confirmation request carried an invalid authorization secret"
            )

    # ------------------------------------------------------------------ #
    # evidence loading
    # ------------------------------------------------------------------ #
    def _resolve_target(self, repository_id: str) -> RepositoryTarget:
        """Resolve and validate the canonical write target from graph records."""
        try:
            row = self._graph.get_repository(repository_id)
        except GraphRecordNotFoundError as exc:
            raise ActionRepositoryInvalidError(
                "The analysis repository record is missing from the graph",
                details={"repository_id": repository_id},
            ) from exc
        owner = str(row.get("owner") or "").strip()
        name = str(row.get("name") or "").strip()
        host = str(row.get("host") or "github.com").strip().lower()
        stored_id = str(row.get("canonical_id") or row.get("id") or "").strip().lower()
        if host != "github.com":
            raise ActionRepositoryInvalidError(
                "Only github.com repositories can be written to",
                details={"host": host},
            )
        try:
            parsed = parse_repository_url(f"https://github.com/{owner}/{name}")
        except BlastRadiusError as exc:
            raise ActionRepositoryInvalidError(
                "The stored repository identity is not a valid canonical GitHub repository",
                details={"repository_id": repository_id, "reason": exc.code.value},
            ) from exc
        identity = parsed.identity
        if stored_id and stored_id != identity.canonical_id:
            raise ActionRepositoryInvalidError(
                "The stored repository identity conflicts with its canonical id",
                details={
                    "repository_id": repository_id,
                    "stored_canonical_id": stored_id,
                    "derived_canonical_id": identity.canonical_id,
                },
            )
        if identity.canonical_id != str(repository_id).strip().lower():
            raise ActionRepositoryInvalidError(
                "The analysis repository id does not match the persisted repository record",
                details={
                    "analysis_repository_id": repository_id,
                    "derived_canonical_id": identity.canonical_id,
                },
            )
        if self._settings.repository_allowlist and (
            identity.canonical_id not in self._settings.repository_allowlist
        ):
            raise ActionRepositoryNotAllowedError(
                "The repository is not in the configured GitHub action allowlist",
                details={"repository": identity.canonical_id},
            )
        return RepositoryTarget(
            host="github.com",
            owner=identity.owner,
            name=identity.name,
            full_name=identity.full_name,
            canonical_id=identity.canonical_id,
            canonical_url=identity.canonical_url,
        )

    def _preflight(self, target: RepositoryTarget) -> RepositoryAccess:
        """Read-only GitHub check that the target is accessible and writable in principle."""
        access = self._github.check_repository_access(target.owner, target.name)
        if access.full_name.lower() != target.full_name.lower():
            raise ActionEvidenceChangedError(
                "GitHub reports a different repository name than the analysis recorded; "
                "the repository may have been renamed or transferred",
                details={
                    "expected": target.full_name,
                    "reported": access.full_name,
                },
            )
        if not access.has_issues:
            raise GitHubIssuesDisabledError(
                "Issues are disabled for the target repository; BlastRadius cannot "
                "create the proposed issue there",
                details={"repository": target.full_name},
            )
        return access

    def _load_report(self, analysis_id: str) -> AnalysisReport:
        analysis_id = (analysis_id or "").strip()
        if not analysis_id:
            raise ActionEvidenceChangedError("The action record has no analysis id")
        return self._remediation.analyze(analysis_id)

    @staticmethod
    def _find_group(report: AnalysisReport, group_id: str) -> FixGroup:
        group = next((item for item in report.groups if item.group_id == group_id), None)
        if group is None:
            raise GraphRecordNotFoundError(
                f"Fix group {group_id!r} was not found for this analysis",
                details={"analysis_id": report.analysis_id, "group_id": group_id},
            )
        return group

    @staticmethod
    def _find_finding(
        report: AnalysisReport, finding_id: str
    ) -> tuple[FindingOut, PackageRemediationPlan | None]:
        finding = next(
            (item for item in report.findings if item.finding_id == finding_id), None
        )
        if finding is None:
            raise GraphRecordNotFoundError(
                f"Finding {finding_id!r} was not found for this analysis",
                details={"analysis_id": report.analysis_id, "finding_id": finding_id},
            )
        plan = next(
            (item for item in report.plans if item.package_id == finding.package.package_id),
            None,
        )
        return finding, plan

    def _select_subject(
        self, report: AnalysisReport, selection: IssueSubjectSelection
    ) -> tuple[FixGroup | None, FindingOut | None, PackageRemediationPlan | None]:
        if selection.group_id:
            return self._find_group(report, selection.group_id), None, None
        if not selection.finding_id:
            raise ActionEvidenceChangedError("The action record has no subject selection")
        finding, plan = self._find_finding(report, selection.finding_id)
        return None, finding, plan

    def _build_payload(
        self,
        *,
        action_id: str,
        report: AnalysisReport,
        target: RepositoryTarget,
        group: FixGroup | None,
        finding: FindingOut | None,
        plan: PackageRemediationPlan | None,
    ) -> tuple[IssueSubject, str, str, str]:
        subject = IssueSubject(
            action_id=action_id,
            analysis_id=report.analysis_id,
            repository=target,
            commit_sha=report.commit_sha,
            group=group,
            finding=finding,
            plan=plan,
            report_limitations=tuple(report.limitations),
        )
        content = build_issue_content(
            subject,
            max_title_chars=self._settings.max_title_chars,
            max_body_chars=self._settings.max_body_chars,
        )
        digest = compute_payload_digest(
            build_action_payload(
                action_id=action_id,
                analysis_id=report.analysis_id,
                repository_id=target.canonical_id,
                repository_owner=target.owner,
                repository_name=target.name,
                commit_sha=report.commit_sha,
                group_id=group.group_id if group is not None else None,
                finding_id=finding.finding_id if finding is not None else None,
                title=content.title,
                body=content.body,
            )
        )
        return subject, content.title, digest, content.body

    # ------------------------------------------------------------------ #
    # preview
    # ------------------------------------------------------------------ #
    def preview(self, analysis_id: str, request: IssuePreviewRequest) -> IssuePreviewOut:
        """Build the exact, digest-bound issue proposal.  Never writes to GitHub."""
        self._require_write_ready()
        report = self._load_report(analysis_id)
        target = self._resolve_target(report.repository_id)
        group, finding, plan = self._select_subject(
            report,
            IssueSubjectSelection(group_id=request.group_id, finding_id=request.finding_id),
        )
        access = self._preflight(target)

        action_id = new_action_id()
        subject, title, digest, body = self._build_payload(
            action_id=action_id,
            report=report,
            target=target,
            group=group,
            finding=finding,
            plan=plan,
        )

        now = self._clock()
        expires_at = now + timedelta(seconds=self._settings.preview_ttl_seconds)
        try:
            self._store.purge(
                now=now, retain_seconds=self._settings.retention_seconds
            )
            self._store.create(
                ActionRecord(
                    action_id=action_id,
                    state="PREVIEWED",
                    analysis_id=report.analysis_id,
                    repository_id=target.canonical_id,
                    repository_owner=target.owner,
                    repository_name=target.name,
                    commit_sha=report.commit_sha,
                    group_id=group.group_id if group is not None else None,
                    finding_id=finding.finding_id if finding is not None else None,
                    payload_digest=digest,
                    title=title,
                    body=body,
                    created_at=now,
                    expires_at=expires_at,
                )
            )
        except ActionStoreError:
            raise

        if group is not None:
            limitations = [*group.limitations, *report.limitations]
            coverage = group.coverage
            compatibility = group.compatibility
            verified = len(group.verified_resolved_finding_ids)
            potential = len(group.potential_resolved_finding_ids)
        else:
            assert finding is not None
            limitations = [
                *finding.limitations,
                *([] if plan is None else plan.limitations),
                *report.limitations,
            ]
            coverage = None
            candidate = None
            if plan is not None:
                for item in plan.candidates:
                    if item.selected:
                        candidate = item
                        break
                if candidate is None and plan.candidates:
                    candidate = plan.candidates[0]
            compatibility = candidate.compatibility if candidate is not None else "unverified"
            verified = 1
            potential = 0

        notes = list(PREVIEW_NOTES)
        if access.permission_hint:
            notes.append(access.permission_hint)

        _log.info(
            "github_issue_preview_created",
            extra={
                "action_id": action_id,
                "analysis_id": report.analysis_id,
                "repository": target.full_name,
                "subject": group.group_id if group is not None else (finding.finding_id if finding else ""),
            },
        )
        return IssuePreviewOut(
            action_id=action_id,
            state="PREVIEWED",
            template_version=TEMPLATE_VERSION,
            created_at=now,
            expires_at=expires_at,
            payload_digest=digest,
            repository=target,
            commit_sha=report.commit_sha,
            analysis_id=report.analysis_id,
            selection=IssueSubjectSelection(
                group_id=group.group_id if group is not None else None,
                finding_id=finding.finding_id if finding is not None else None,
            ),
            title=title,
            body=body,
            coverage=coverage,
            compatibility=compatibility,
            verified_finding_count=verified,
            potential_finding_count=potential,
            limitations=_dedupe(limitations),
            notes=notes,
        )

    # ------------------------------------------------------------------ #
    # confirmation
    # ------------------------------------------------------------------ #
    def confirm(
        self, request: IssueConfirmRequest, *, approval_key: str | None
    ) -> IssueConfirmOut:
        """Execute the single authorized write for a previewed action."""
        self._require_write_ready()
        self._require_authorization(approval_key)

        record = self._store.get(request.action_id)
        if record is None:
            raise ActionNotFoundError(
                "The action id is unknown or has been purged",
                details={"action_id": request.action_id},
            )
        if not hmac.compare_digest(record.payload_digest, request.payload_digest):
            raise ActionPayloadMismatchError(
                "The payload digest does not match the stored preview",
                details={"action_id": record.action_id},
            )
        stored = self._stored_outcome(record)
        if stored is not None:
            return stored

        now = self._clock()
        if now >= record.expires_at:
            self._store.expire(record.action_id)
            raise ActionExpiredError(
                "The action has expired; generate a new preview",
                details={"action_id": record.action_id, "expires_at": record.expires_at.isoformat()},
            )

        # -- revalidate the evidence and the payload ------------------------
        target, report = self._revalidate(record)

        # -- atomically reserve the action before any GitHub call -----------
        reserved = self._store.try_reserve(record.action_id, now=now)
        if reserved is None:
            latest = self._store.get(record.action_id)
            if latest is None:
                raise ActionNotFoundError(
                    "The action id is unknown or has been purged",
                    details={"action_id": record.action_id},
                )
            stored = self._stored_outcome(latest)
            if stored is not None:
                return stored
            raise ActionInProgressError(
                "The action is already being executed",
                details={"action_id": record.action_id},
            )

        # -- the one write --------------------------------------------------
        try:
            created = self._github.create_issue(
                target.owner,
                target.name,
                title=record.title,
                body=record.body,
            )
        except GitHubWriteAmbiguousError as exc:
            return self._reconcile(reserved, target, exc, now=self._clock())
        except BlastRadiusError as exc:
            self._store.mark_failed(
                reserved.action_id,
                category=exc.code.value,
                message=exc.message,
                executed_at=self._clock(),
            )
            raise

        updated = self._store.mark_succeeded(
            reserved.action_id,
            issue_number=created.number,
            issue_url=created.url,
            executed_at=self._clock(),
        )
        _log.info(
            "github_issue_created",
            extra={
                "action_id": updated.action_id,
                "repository": target.full_name,
                "issue_number": created.number,
            },
        )
        return self._result_from_record(updated, created=True)

    # ------------------------------------------------------------------ #
    # internals
    # ------------------------------------------------------------------ #
    def _revalidate(self, record: ActionRecord) -> tuple[RepositoryTarget, Any]:
        """Regenerate the preview and require it to reproduce the stored digest."""
        try:
            report = self._load_report(record.analysis_id)
            target = self._resolve_target(report.repository_id)
            selection = IssueSubjectSelection(
                group_id=record.group_id, finding_id=record.finding_id
            )
            group, finding, plan = self._select_subject(report, selection)
        except GraphRecordNotFoundError as exc:
            raise ActionEvidenceChangedError(
                "The analysis evidence no longer resolves the previewed subject; "
                "generate a new preview",
                details={"action_id": record.action_id, "reason": exc.code.value},
            ) from exc
        if (
            target.canonical_id != record.repository_id
            or target.owner != record.repository_owner
            or target.name != record.repository_name
            or report.commit_sha != record.commit_sha
        ):
            raise ActionEvidenceChangedError(
                "The analysis now resolves to a different repository or commit; "
                "generate a new preview",
                details={"action_id": record.action_id},
            )
        _, title, digest, body = self._build_payload(
            action_id=record.action_id,
            report=report,
            target=target,
            group=group,
            finding=finding,
            plan=plan,
        )
        if not hmac.compare_digest(digest, record.payload_digest):
            raise ActionEvidenceChangedError(
                "The remediation evidence changed since the preview; generate a new preview",
                details={"action_id": record.action_id},
            )
        if title != record.title or body != record.body:
            raise ActionEvidenceChangedError(
                "The regenerated issue content does not match the stored preview",
                details={"action_id": record.action_id},
            )
        self._preflight(target)
        return target, report

    def _stored_outcome(self, record: ActionRecord) -> IssueConfirmOut | None:
        """Return the stored result for a SUCCEEDED action; raise for dead states.

        ``PREVIEWED`` returns None (the caller may proceed); every other state
        either returns the idempotent result or raises the matching typed
        error, so a confirmation can never re-execute a consumed action.
        """
        if record.state == "SUCCEEDED":
            return self._result_from_record(record, created=False)
        if record.state == "EXECUTING":
            raise ActionInProgressError(
                "The action is already being executed",
                details={"action_id": record.action_id},
            )
        if record.state == "FAILED":
            raise ActionConsumedError(
                "The action has already been attempted and cannot be replayed; "
                "generate a new preview",
                details={
                    "action_id": record.action_id,
                    "failure_category": record.failure_category,
                },
            )
        if record.state == "EXPIRED":
            raise ActionExpiredError(
                "The action has expired; generate a new preview",
                details={"action_id": record.action_id},
            )
        return None

    def _result_from_record(self, record: ActionRecord, *, created: bool) -> IssueConfirmOut:
        if record.issue_number is None or not record.issue_url:
            raise ActionStoreError(
                "The stored action has no verified issue result",
                details={"action_id": record.action_id},
            )
        return IssueConfirmOut(
            action_id=record.action_id,
            state="SUCCEEDED",
            repository=RepositoryTarget(
                host="github.com",
                owner=record.repository_owner,
                name=record.repository_name,
                full_name=f"{record.repository_owner}/{record.repository_name}",
                canonical_id=record.repository_id,
                canonical_url=f"https://github.com/{record.repository_owner}/{record.repository_name}",
            ),
            analysis_id=record.analysis_id,
            commit_sha=record.commit_sha,
            title=record.title,
            issue_number=record.issue_number,
            issue_url=record.issue_url,
            created=created,
            reconciled=record.reconciled,
            executed_at=record.executed_at or record.created_at,
        )

    def _reconcile(
        self,
        record: ActionRecord,
        target: RepositoryTarget,
        original: GitHubWriteAmbiguousError,
        *,
        now: datetime,
    ) -> IssueConfirmOut:
        """Establish the outcome of an ambiguous write through the action marker."""
        marker = MARKER_TEMPLATE.format(action_id=record.action_id)
        found: list[Any] | None
        try:
            found = self._github.find_issue_by_marker(target.owner, target.name, marker)
        except Exception:  # noqa: BLE001 - any search failure means "cannot establish"
            found = None

        if found is not None and len(found) == 1:
            issue = found[0]
            updated = self._store.mark_succeeded(
                record.action_id,
                issue_number=issue.number,
                issue_url=issue.url,
                executed_at=now,
                reconciled=True,
            )
            _log.warning(
                "github_issue_reconciled",
                extra={
                    "action_id": record.action_id,
                    "repository": target.full_name,
                    "issue_number": issue.number,
                },
            )
            return self._result_from_record(updated, created=True)

        message = (
            "The GitHub write outcome could not be established; the action is "
            "marked failed and will not be retried automatically. Check the "
            "repository for an issue containing the action marker before "
            "generating a new preview."
        )
        self._store.mark_failed(
            record.action_id,
            category=ErrorCode.GITHUB_WRITE_AMBIGUOUS.value,
            message=message,
            executed_at=now,
            reconciled=True,
        )
        raise GitHubWriteAmbiguousError(
            message,
            details={
                "action_id": record.action_id,
                "original_error": original.code.value,
                "marker_matches": None if found is None else len(found),
            },
            retryable=False,
        )


__all__ = ["ACTION_ID_PREFIX", "GitHubIssueService", "new_action_id", "utcnow"]
