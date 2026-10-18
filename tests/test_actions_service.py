"""Service tests for the Phase 6 preview/confirm workflow.

These exercise the real :class:`~app.actions.service.GitHubIssueService` over
canned graph fixtures and a mocked GitHub transport.  They cover the workflow's
central promises: previews never write, confirmation is explicitly authorized
and digest-bound, evidence is revalidated, execution is single-shot and
outcomes are never guessed.
"""

from __future__ import annotations

import threading
from datetime import timedelta
from pathlib import Path

import httpx
import pytest

from app.actions.models import (
    PREVIEW_NOTES,
    IssueConfirmRequest,
    IssuePreviewRequest,
)
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
    GitHubIssuesDisabledError,
    GitHubPermissionDeniedError,
    GitHubWriteAmbiguousError,
    GitHubWriteDisabledError,
    RateLimitExceededError,
    RepositoryNotFoundError,
)
from app.graph.queries import GET_ANALYSIS, GET_REPOSITORY
from tests.actions_support import (
    ACTION_TOKEN,
    ANALYSIS,
    APPROVAL_SECRET,
    FINDING_ID,
    GROUP_ID,
    GitHubHarness,
    build_bundle,
    make_action_settings,
    repository_row,
)
from tests.remediation_support import (
    analysis_row,
    finding_row,
    install,
    query_result,
)
from tests.support import FakeGraphClient, FakeQueryResult


class _IdAwareGraphClient(FakeGraphClient):
    """Answer ``GET_ANALYSIS`` only for the expected analysis id."""

    def query(self, cypher, *, params=None, timeout=None, read_only=False):  # type: ignore[override]
        if cypher == GET_ANALYSIS and (params or {}).get("analysis_id") != ANALYSIS:
            return FakeQueryResult([], [])
        return super().query(cypher, params=params, timeout=timeout, read_only=read_only)


def _preview(bundle, *, group: str | None = GROUP_ID, finding: str | None = None):
    request = IssuePreviewRequest(
        group_id=group if finding is None else None, finding_id=finding
    )
    return bundle.service.preview(ANALYSIS, request)


def _confirm(bundle, preview, *, secret: str | None = APPROVAL_SECRET):
    request = IssueConfirmRequest(
        action_id=preview.action_id, payload_digest=preview.payload_digest
    )
    return bundle.service.confirm(request, approval_key=secret)


# ---------------------------------------------------------------------------
# preview
# ---------------------------------------------------------------------------


def test_preview_performs_no_write_and_persists_a_previewed_action(tmp_path: Path) -> None:
    bundle = build_bundle(tmp_path)
    preview = _preview(bundle)
    assert preview.state == "PREVIEWED"
    assert preview.repository.canonical_id == "github.com/example/priority-demo"
    assert preview.repository.full_name == "example/priority-demo"
    assert preview.analysis_id == ANALYSIS
    assert preview.commit_sha == "c" * 40
    assert preview.selection.group_id == GROUP_ID
    assert preview.selection.finding_id is None
    assert preview.created_at == bundle.clock()
    assert preview.expires_at == bundle.clock() + timedelta(seconds=900)
    assert [note for note in preview.notes] == list(PREVIEW_NOTES)
    # the only network traffic is the read-only repository preflight
    assert [(r.method, r.url.path) for r in bundle.github.requests] == [
        ("GET", "/repos/example/priority-demo")
    ]
    record = bundle.store.get(preview.action_id)
    assert record is not None
    assert record.state == "PREVIEWED"
    assert record.title == preview.title
    assert record.body == preview.body
    assert record.payload_digest == preview.payload_digest


def test_preview_finding_subject_selection(tmp_path: Path) -> None:
    bundle = build_bundle(tmp_path)
    preview = _preview(bundle, group=None, finding=FINDING_ID)
    assert preview.selection.finding_id == FINDING_ID
    assert preview.selection.group_id is None
    assert preview.verified_finding_count == 1
    assert bundle.github.posts == []


def test_preview_action_ids_and_digests_are_unique_per_action(tmp_path: Path) -> None:
    bundle = build_bundle(tmp_path)
    first = _preview(bundle)
    second = _preview(bundle)
    assert first.action_id != second.action_id
    assert first.payload_digest != second.payload_digest
    assert first.title == second.title
    marker_one = f"<!-- blastradius-action: {first.action_id} -->"
    marker_two = f"<!-- blastradius-action: {second.action_id} -->"
    assert first.body.replace(marker_one, "") == second.body.replace(marker_two, "")
    assert bundle.github.posts == []


def test_preview_unknown_group_is_not_found(tmp_path: Path) -> None:
    from app.graph.errors import GraphRecordNotFoundError

    bundle = build_bundle(tmp_path)
    with pytest.raises(GraphRecordNotFoundError):
        _preview(bundle, group="fixgroup_missing")


def test_preview_unknown_analysis_is_not_found(tmp_path: Path) -> None:
    from app.graph.errors import GraphRecordNotFoundError

    client = _IdAwareGraphClient()
    install(client)
    client.canned[GET_REPOSITORY] = query_result([repository_row()])
    bundle = build_bundle(tmp_path, graph_client=client)
    with pytest.raises(GraphRecordNotFoundError):
        bundle.service.preview("analysis_other", IssuePreviewRequest(group_id=GROUP_ID))
    assert bundle.github.requests == []


def test_preview_writes_disabled_is_reported_before_any_work(tmp_path: Path) -> None:
    settings = make_action_settings(tmp_path, enabled=False)
    bundle = build_bundle(tmp_path, settings=settings)
    with pytest.raises(GitHubWriteDisabledError) as excinfo:
        _preview(bundle)
    assert "BLASTRADIUS_ACTIONS_ENABLED" in excinfo.value.message
    assert bundle.github.requests == []


def test_preview_requires_a_dedicated_token(tmp_path: Path) -> None:
    settings = make_action_settings(tmp_path, github_token=None)
    bundle = build_bundle(tmp_path, settings=settings)
    with pytest.raises(ActionNotConfiguredError) as excinfo:
        _preview(bundle)
    assert (excinfo.value.details or {}).get("config") == "BLASTRADIUS_ACTIONS_GITHUB_TOKEN"
    assert bundle.github.requests == []


def test_preview_rejects_a_repository_outside_the_allowlist(tmp_path: Path) -> None:
    settings = make_action_settings(tmp_path, repository_allowlist=("github.com/other/repo",))
    bundle = build_bundle(tmp_path, settings=settings)
    with pytest.raises(ActionRepositoryNotAllowedError):
        _preview(bundle)
    assert bundle.github.requests == []


def test_preview_rejects_a_missing_repository_record(tmp_path: Path) -> None:
    bundle = build_bundle(tmp_path, repository=None)
    with pytest.raises(ActionRepositoryInvalidError):
        _preview(bundle)
    assert bundle.github.requests == []


def test_preview_rejects_a_conflicting_canonical_id(tmp_path: Path) -> None:
    bundle = build_bundle(
        tmp_path, repository=repository_row(canonical_id="github.com/evil/other")
    )
    with pytest.raises(ActionRepositoryInvalidError):
        _preview(bundle)


def test_preview_rejects_a_non_github_host(tmp_path: Path) -> None:
    bundle = build_bundle(tmp_path, repository=repository_row(host="gitlab.com"))
    with pytest.raises(ActionRepositoryInvalidError):
        _preview(bundle)


def test_preview_rejects_a_malformed_owner_or_name(tmp_path: Path) -> None:
    bundle = build_bundle(tmp_path, repository=repository_row(owner="bad owner"))
    with pytest.raises(ActionRepositoryInvalidError):
        _preview(bundle)


def test_preview_requires_issues_enabled(tmp_path: Path) -> None:
    harness = GitHubHarness(
        repo_payload={"full_name": "example/priority-demo", "has_issues": False}
    )
    bundle = build_bundle(tmp_path, harness=harness)
    with pytest.raises(GitHubIssuesDisabledError):
        _preview(bundle)
    assert harness.posts == []
    # nothing was persisted because the preflight failed before create()
    import sqlite3

    connection = sqlite3.connect(bundle.settings.effective_store_path)
    try:
        count = connection.execute("SELECT COUNT(*) FROM actions").fetchone()[0]
    finally:
        connection.close()
    assert count == 0


def test_preview_refuses_a_renamed_repository(tmp_path: Path) -> None:
    harness = GitHubHarness(
        repo_payload={"full_name": "example/priority-demo-renamed", "has_issues": True}
    )
    bundle = build_bundle(tmp_path, harness=harness)
    with pytest.raises(ActionEvidenceChangedError):
        _preview(bundle)


def test_preview_surfaces_rate_limits(tmp_path: Path) -> None:
    harness = GitHubHarness(
        repo_status=403, repo_headers={"x-ratelimit-remaining": "0"}
    )
    bundle = build_bundle(tmp_path, harness=harness)
    with pytest.raises(RateLimitExceededError):
        _preview(bundle)


def test_preview_reports_a_read_only_token_as_a_note(tmp_path: Path) -> None:
    harness = GitHubHarness(
        repo_payload={
            "full_name": "example/priority-demo",
            "has_issues": True,
            "permissions": {"pull": True, "push": False},
        }
    )
    bundle = build_bundle(tmp_path, harness=harness)
    preview = _preview(bundle)
    assert any("Issues: write" in note for note in preview.notes)
    assert ACTION_TOKEN not in " ".join(preview.notes)


# ---------------------------------------------------------------------------
# confirmation: authorization and binding
# ---------------------------------------------------------------------------


def test_confirm_executes_the_single_authorized_write(tmp_path: Path) -> None:
    bundle = build_bundle(tmp_path)
    preview = _preview(bundle)
    result = _confirm(bundle, preview)
    assert result.state == "SUCCEEDED"
    assert result.created is True
    assert result.reconciled is False
    assert result.issue_number == 42
    assert result.issue_url == "https://github.com/example/priority-demo/issues/42"
    assert result.action_id == preview.action_id
    assert result.repository.canonical_id == preview.repository.canonical_id
    assert len(bundle.github.posts) == 1
    assert bundle.github.created_bodies == [{"title": preview.title, "body": preview.body}]
    record = bundle.store.get(preview.action_id)
    assert record is not None
    assert record.state == "SUCCEEDED"
    assert record.issue_number == 42
    assert record.approved_at is not None
    assert record.executed_at is not None


def test_confirm_requires_the_approval_secret(tmp_path: Path) -> None:
    bundle = build_bundle(tmp_path)
    preview = _preview(bundle)
    with pytest.raises(ActionUnauthorizedError):
        _confirm(bundle, preview, secret=None)
    with pytest.raises(ActionUnauthorizedError):
        _confirm(bundle, preview, secret="wrong-secret")
    assert bundle.github.posts == []
    record = bundle.store.get(preview.action_id)
    assert record is not None and record.state == "PREVIEWED"


def test_confirm_without_a_configured_secret_refuses_everyone(tmp_path: Path) -> None:
    settings = make_action_settings(tmp_path, approval_secret=None)
    bundle = build_bundle(tmp_path, settings=settings)
    preview = _preview(bundle)
    with pytest.raises(ActionAuthorizationNotConfiguredError):
        _confirm(bundle, preview)
    assert bundle.github.posts == []


def test_confirm_rejects_an_unknown_action_id(tmp_path: Path) -> None:
    bundle = build_bundle(tmp_path)
    request = IssueConfirmRequest(
        action_id="act_" + "f" * 32, payload_digest="sha256:" + "0" * 64
    )
    with pytest.raises(ActionNotFoundError):
        bundle.service.confirm(request, approval_key=APPROVAL_SECRET)
    assert bundle.github.posts == []


def test_confirm_rejects_an_altered_digest(tmp_path: Path) -> None:
    bundle = build_bundle(tmp_path)
    preview = _preview(bundle)
    request = IssueConfirmRequest(
        action_id=preview.action_id, payload_digest="sha256:" + "0" * 64
    )
    with pytest.raises(ActionPayloadMismatchError):
        bundle.service.confirm(request, approval_key=APPROVAL_SECRET)
    assert bundle.github.posts == []
    record = bundle.store.get(preview.action_id)
    assert record is not None and record.state == "PREVIEWED"


def test_confirm_rejects_a_digest_from_a_different_action(tmp_path: Path) -> None:
    bundle = build_bundle(tmp_path)
    first = _preview(bundle)
    second = _preview(bundle)
    request = IssueConfirmRequest(
        action_id=first.action_id, payload_digest=second.payload_digest
    )
    with pytest.raises(ActionPayloadMismatchError):
        bundle.service.confirm(request, approval_key=APPROVAL_SECRET)


def test_confirm_refuses_an_expired_action(tmp_path: Path) -> None:
    bundle = build_bundle(tmp_path)
    preview = _preview(bundle)
    bundle.clock.advance(901)
    with pytest.raises(ActionExpiredError):
        _confirm(bundle, preview)
    record = bundle.store.get(preview.action_id)
    assert record is not None and record.state == "EXPIRED"
    assert bundle.github.posts == []
    # and it stays refused
    with pytest.raises(ActionExpiredError):
        _confirm(bundle, preview)


def test_confirm_refuses_an_action_reserved_by_someone_else(tmp_path: Path) -> None:
    bundle = build_bundle(tmp_path)
    preview = _preview(bundle)
    assert bundle.store.try_reserve(preview.action_id, now=bundle.clock()) is not None
    with pytest.raises(ActionInProgressError):
        _confirm(bundle, preview)
    assert bundle.github.posts == []


def test_confirm_refuses_a_consumed_action(tmp_path: Path) -> None:
    harness = GitHubHarness(create_status=403)
    bundle = build_bundle(tmp_path, harness=harness)
    preview = _preview(bundle)
    with pytest.raises(GitHubPermissionDeniedError):
        _confirm(bundle, preview)
    record = bundle.store.get(preview.action_id)
    assert record is not None
    assert record.state == "FAILED"
    assert record.failure_category == "github_permission_denied"
    with pytest.raises(ActionConsumedError) as excinfo:
        _confirm(bundle, preview)
    assert (excinfo.value.details or {}).get("failure_category") == "github_permission_denied"
    assert len(harness.posts) == 1  # never retried


# ---------------------------------------------------------------------------
# confirmation: evidence revalidation
# ---------------------------------------------------------------------------


def test_confirm_revalidates_the_regenerated_payload(tmp_path: Path) -> None:
    bundle = build_bundle(tmp_path)
    preview = _preview(bundle)
    # the advisory text stored in the graph changed after the preview
    install(bundle.graph_client, findings=[finding_row(summary="Advisory text changed")])
    with pytest.raises(ActionEvidenceChangedError):
        _confirm(bundle, preview)
    assert bundle.github.posts == []
    record = bundle.store.get(preview.action_id)
    assert record is not None and record.state == "PREVIEWED"


def test_confirm_revalidates_the_commit(tmp_path: Path) -> None:
    bundle = build_bundle(tmp_path)
    preview = _preview(bundle)
    install(bundle.graph_client, analysis=analysis_row(commit_sha="d" * 40))
    with pytest.raises(ActionEvidenceChangedError):
        _confirm(bundle, preview)
    assert bundle.github.posts == []


def test_confirm_rejects_a_stale_group(tmp_path: Path) -> None:
    bundle = build_bundle(tmp_path)
    preview = _preview(bundle)
    # the resolution evidence for this group no longer exists
    install(
        bundle.graph_client,
        findings=[finding_row(vulnerability_id="GHSA-changed-0000-0000")],
    )
    with pytest.raises(ActionEvidenceChangedError):
        _confirm(bundle, preview)
    assert bundle.github.posts == []


def test_confirm_revalidates_repository_access(tmp_path: Path) -> None:
    harness = GitHubHarness()
    bundle = build_bundle(tmp_path, harness=harness)
    preview = _preview(bundle)
    harness.repo_status = 404  # the repository became invisible to the token
    with pytest.raises(RepositoryNotFoundError):
        _confirm(bundle, preview)
    assert harness.posts == []
    record = bundle.store.get(preview.action_id)
    assert record is not None and record.state == "PREVIEWED"


def test_confirm_rechecks_that_issues_are_still_enabled(tmp_path: Path) -> None:
    harness = GitHubHarness()
    bundle = build_bundle(tmp_path, harness=harness)
    preview = _preview(bundle)
    harness.repo_payload = {"full_name": "example/priority-demo", "has_issues": False}
    with pytest.raises(GitHubIssuesDisabledError):
        _confirm(bundle, preview)
    assert harness.posts == []


def test_confirm_rejects_a_repository_record_changed_after_preview(tmp_path: Path) -> None:
    bundle = build_bundle(tmp_path)
    preview = _preview(bundle)
    bundle.graph_client.canned[GET_REPOSITORY] = query_result(
        [repository_row(owner="attacker", name="other")]
    )
    with pytest.raises(ActionRepositoryInvalidError):
        _confirm(bundle, preview)
    assert bundle.github.posts == []


# ---------------------------------------------------------------------------
# confirmation: idempotency, concurrency, ambiguity
# ---------------------------------------------------------------------------


def test_confirming_a_completed_action_returns_the_stored_result(tmp_path: Path) -> None:
    bundle = build_bundle(tmp_path)
    preview = _preview(bundle)
    first = _confirm(bundle, preview)
    second = _confirm(bundle, preview)
    assert first.created is True
    assert second.created is False
    assert second.issue_number == first.issue_number
    assert second.issue_url == first.issue_url
    assert len(bundle.github.posts) == 1


def test_completed_action_result_survives_a_restart(tmp_path: Path) -> None:
    bundle = build_bundle(tmp_path)
    preview = _preview(bundle)
    _confirm(bundle, preview)

    fresh_harness = GitHubHarness()
    restarted = build_bundle(
        tmp_path, settings=bundle.settings, harness=fresh_harness
    )
    result = _confirm(restarted, preview)
    assert result.created is False
    assert result.issue_number == 42
    assert fresh_harness.requests == []


def test_concurrent_confirmations_create_exactly_one_issue(tmp_path: Path) -> None:
    started = threading.Event()
    release = threading.Event()
    harness = GitHubHarness(create_started=started, create_release=release)
    bundle = build_bundle(tmp_path, harness=harness)
    preview = _preview(bundle)

    outcomes: dict[str, object] = {}

    def run_first() -> None:
        try:
            outcomes["first"] = _confirm(bundle, preview)
        except Exception as exc:  # pragma: no cover - failure path
            outcomes["error"] = exc

    thread = threading.Thread(target=run_first)
    thread.start()
    assert started.wait(timeout=10)

    with pytest.raises(ActionInProgressError):
        _confirm(bundle, preview)

    release.set()
    thread.join(timeout=10)
    assert "error" not in outcomes
    first = outcomes["first"]
    assert getattr(first, "created") is True
    assert len(harness.posts) == 1
    record = bundle.store.get(preview.action_id)
    assert record is not None and record.state == "SUCCEEDED"


def test_ambiguous_write_is_reconciled_through_the_marker(tmp_path: Path) -> None:
    harness = GitHubHarness(create_error=httpx.ReadTimeout("slow"))
    harness.search_items = [
        harness.known_issue(
            number=9,
            html_url="https://github.com/example/priority-demo/issues/9",
            title="Reconciled issue",
        )
    ]
    bundle = build_bundle(tmp_path, harness=harness)
    preview = _preview(bundle)
    result = _confirm(bundle, preview)
    assert result.created is True
    assert result.reconciled is True
    assert result.issue_number == 9
    assert len(harness.posts) == 1
    assert any(request.url.path == "/search/issues" for request in harness.gets)
    record = bundle.store.get(preview.action_id)
    assert record is not None
    assert record.state == "SUCCEEDED"
    assert record.reconciled is True


def test_ambiguous_write_without_a_unique_marker_fails_safely(tmp_path: Path) -> None:
    harness = GitHubHarness(create_error=httpx.ReadTimeout("slow"))
    harness.search_items = []  # marker not found
    bundle = build_bundle(tmp_path, harness=harness)
    preview = _preview(bundle)
    with pytest.raises(GitHubWriteAmbiguousError) as excinfo:
        _confirm(bundle, preview)
    assert (excinfo.value.details or {}).get("marker_matches") == 0
    assert len(harness.posts) == 1  # never retried
    record = bundle.store.get(preview.action_id)
    assert record is not None
    assert record.state == "FAILED"
    assert record.failure_category == "github_write_ambiguous"
    assert record.reconciled is True
    with pytest.raises(ActionConsumedError):
        _confirm(bundle, preview)
    assert len(harness.posts) == 1


def test_ambiguous_write_with_duplicate_markers_fails_safely(tmp_path: Path) -> None:
    harness = GitHubHarness(create_error=httpx.ReadTimeout("slow"))
    harness.search_items = [harness.known_issue(number=1), harness.known_issue(number=2)]
    bundle = build_bundle(tmp_path, harness=harness)
    preview = _preview(bundle)
    with pytest.raises(GitHubWriteAmbiguousError) as excinfo:
        _confirm(bundle, preview)
    assert (excinfo.value.details or {}).get("marker_matches") == 2
    record = bundle.store.get(preview.action_id)
    assert record is not None and record.state == "FAILED"


def test_ambiguous_write_with_failed_reconciliation_search_fails_safely(
    tmp_path: Path,
) -> None:
    harness = GitHubHarness(create_error=httpx.ReadTimeout("slow"))
    harness.search_error = httpx.ConnectError("search down")
    bundle = build_bundle(tmp_path, harness=harness)
    preview = _preview(bundle)
    with pytest.raises(GitHubWriteAmbiguousError) as excinfo:
        _confirm(bundle, preview)
    assert (excinfo.value.details or {}).get("marker_matches") is None
    record = bundle.store.get(preview.action_id)
    assert record is not None and record.state == "FAILED"


def test_server_error_on_create_is_reconciled_through_the_marker(tmp_path: Path) -> None:
    harness = GitHubHarness(create_status=503)
    harness.search_items = [harness.known_issue(number=11)]
    bundle = build_bundle(tmp_path, harness=harness)
    preview = _preview(bundle)
    result = _confirm(bundle, preview)
    assert result.created is True
    assert result.reconciled is True
    assert result.issue_number == 11


def test_marker_searches_use_the_stored_action_id(tmp_path: Path) -> None:
    harness = GitHubHarness(create_error=httpx.ReadTimeout("slow"))
    bundle = build_bundle(tmp_path, harness=harness)
    preview = _preview(bundle)
    with pytest.raises(GitHubWriteAmbiguousError):
        _confirm(bundle, preview)
    search = next(request for request in harness.gets if request.url.path == "/search/issues")
    assert preview.action_id in search.url.params["q"]


# ---------------------------------------------------------------------------
# audit hygiene
# ---------------------------------------------------------------------------


def test_no_secret_is_persisted_or_echoed(tmp_path: Path) -> None:
    bundle = build_bundle(tmp_path)
    preview = _preview(bundle)
    result = _confirm(bundle, preview)
    assert ACTION_TOKEN not in preview.model_dump_json()
    assert APPROVAL_SECRET not in preview.model_dump_json()
    assert ACTION_TOKEN not in result.model_dump_json()
    assert APPROVAL_SECRET not in result.model_dump_json()
    data = bundle.settings.effective_store_path.read_bytes()
    assert ACTION_TOKEN.encode("utf-8") not in data
    assert APPROVAL_SECRET.encode("utf-8") not in data


def test_failure_details_never_contain_the_token(tmp_path: Path) -> None:
    harness = GitHubHarness(create_status=403)
    bundle = build_bundle(tmp_path, harness=harness)
    preview = _preview(bundle)
    with pytest.raises(GitHubPermissionDeniedError) as excinfo:
        _confirm(bundle, preview)
    assert ACTION_TOKEN not in str(excinfo.value)
    record = bundle.store.get(preview.action_id)
    assert record is not None
    assert ACTION_TOKEN not in (record.failure_message or "")
