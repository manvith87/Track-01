"""HTTP contract tests for the Phase 6 approved-GitHub-issue endpoints.

The real preview/confirm service is wired through FastAPI's dependency override
over canned graph fixtures and a mocked GitHub transport, so these tests assert
the actual wire behaviour: status codes, the uniform error envelope, the safe
disabled-by-default posture and that no caller-supplied facts are accepted.
"""

from __future__ import annotations

from pathlib import Path

import httpx
from fastapi.testclient import TestClient

from app.api.deps import get_github_issue_service
from app.core.config import Settings
from app.main import create_app
from tests.actions_support import (
    ACTION_TOKEN,
    ANALYSIS,
    APPROVAL_SECRET,
    FINDING_ID,
    GROUP_ID,
    GitHubHarness,
    build_bundle,
    make_action_settings,
)
from tests.remediation_support import finding_row, install

BASE = f"/api/v1/analyses/{ANALYSIS}/remediation/github-issue"
CONFIRM = "/api/v1/actions/github-issue/confirm"


def _setup(tmp_path: Path, **kwargs):
    bundle = build_bundle(tmp_path, **kwargs)
    app = create_app(Settings(log_level="ERROR"))
    app.dependency_overrides[get_github_issue_service] = lambda: bundle.service
    return bundle, TestClient(app)


def _preview(client: TestClient, **body):
    if not body:
        body = {"group_id": GROUP_ID}
    return client.post(f"{BASE}/preview", json=body)


def _confirm(client: TestClient, action_id: str, digest: str, secret: str | None = APPROVAL_SECRET):
    headers = {"X-BlastRadius-Approval": secret} if secret is not None else {}
    return client.post(
        CONFIRM, json={"action_id": action_id, "payload_digest": digest}, headers=headers
    )


# ---------------------------------------------------------------------------
# preview endpoint
# ---------------------------------------------------------------------------


def test_preview_endpoint_returns_the_digest_bound_proposal(tmp_path: Path) -> None:
    bundle, client = _setup(tmp_path)
    response = _preview(client)
    assert response.status_code == 201
    body = response.json()
    assert body["state"] == "PREVIEWED"
    assert body["template_version"] == "blastradius-issue-v1"
    assert body["repository"]["canonical_id"] == "github.com/example/priority-demo"
    assert body["repository"]["full_name"] == "example/priority-demo"
    assert body["analysis_id"] == ANALYSIS
    assert body["commit_sha"] == "c" * 40
    assert body["selection"] == {"group_id": GROUP_ID, "finding_id": None}
    assert body["payload_digest"].startswith("sha256:")
    assert len(body["payload_digest"]) == 71
    assert body["title"].startswith("[BlastRadius] Upgrade requests")
    assert "### Verified findings" in body["body"]
    assert any("No GitHub write has been performed" in note for note in body["notes"])
    # the request surface never wrote to GitHub
    assert [request.method for request in bundle.github.requests] == ["GET"]


def test_preview_endpoint_accepts_a_finding_selector(tmp_path: Path) -> None:
    _, client = _setup(tmp_path)
    response = _preview(client, finding_id=FINDING_ID)
    assert response.status_code == 201
    assert response.json()["selection"] == {"group_id": None, "finding_id": FINDING_ID}


def test_preview_endpoint_rejects_caller_supplied_security_facts(tmp_path: Path) -> None:
    _, client = _setup(tmp_path)
    for extra in (
        {"group_id": GROUP_ID, "fixed_version": "9.9.9"},
        {"group_id": GROUP_ID, "repository": "attacker/repo"},
        {"group_id": GROUP_ID, "severity": "low"},
        {"group_id": GROUP_ID, "body": "custom issue body"},
    ):
        response = client.post(f"{BASE}/preview", json=extra)
        assert response.status_code == 422
        assert response.json()["error"]["code"] == "invalid_input"
        assert response.json()["error"]["stage"] == "validation"


def test_preview_endpoint_requires_exactly_one_selector(tmp_path: Path) -> None:
    _, client = _setup(tmp_path)
    for body in ({}, {"group_id": GROUP_ID, "finding_id": FINDING_ID}):
        response = client.post(f"{BASE}/preview", json=body)
        assert response.status_code == 422
        assert response.json()["error"]["code"] == "invalid_input"


def test_preview_endpoint_rejects_unknown_query_parameters(tmp_path: Path) -> None:
    _, client = _setup(tmp_path)
    response = client.post(f"{BASE}/preview?repository=attacker/repo", json={"group_id": GROUP_ID})
    assert response.status_code == 400
    body = response.json()
    assert body["error"]["code"] == "invalid_input"
    assert body["error"]["details"]["unsupported_query_parameters"] == ["repository"]


def test_preview_endpoint_unknown_group_is_a_404(tmp_path: Path) -> None:
    _, client = _setup(tmp_path)
    response = _preview(client, group_id="fixgroup_missing")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "repository_not_found"


def test_preview_endpoint_is_403_when_writes_are_disabled(tmp_path: Path) -> None:
    settings = make_action_settings(tmp_path, enabled=False)
    bundle, client = _setup(tmp_path, settings=settings)
    response = _preview(client)
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "github_write_disabled"
    assert bundle.github.requests == []


def test_preview_endpoint_is_503_without_a_token(tmp_path: Path) -> None:
    settings = make_action_settings(tmp_path, github_token=None)
    _, client = _setup(tmp_path, settings=settings)
    response = _preview(client)
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "action_not_configured"


def test_preview_endpoint_reports_github_rate_limits_as_429(tmp_path: Path) -> None:
    harness = GitHubHarness(repo_status=403, repo_headers={"x-ratelimit-remaining": "0"})
    _, client = _setup(tmp_path, harness=harness)
    response = _preview(client)
    assert response.status_code == 429
    assert response.json()["error"]["code"] == "rate_limit_exceeded"


def test_preview_endpoint_reports_a_renamed_repository_as_conflict(tmp_path: Path) -> None:
    harness = GitHubHarness(
        repo_payload={"full_name": "example/renamed", "has_issues": True}
    )
    _, client = _setup(tmp_path, harness=harness)
    response = _preview(client)
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "action_evidence_changed"


def test_preview_endpoint_rejects_a_repository_outside_the_allowlist(tmp_path: Path) -> None:
    settings = make_action_settings(tmp_path, repository_allowlist=("github.com/other/repo",))
    _, client = _setup(tmp_path, settings=settings)
    response = _preview(client)
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "action_repository_not_allowed"


def test_preview_endpoint_rejects_get(tmp_path: Path) -> None:
    _, client = _setup(tmp_path)
    response = client.get(f"{BASE}/preview")
    assert response.status_code == 405
    assert response.json()["error"]["code"] == "http_405"


# ---------------------------------------------------------------------------
# confirm endpoint
# ---------------------------------------------------------------------------


def test_confirm_endpoint_creates_exactly_one_issue(tmp_path: Path) -> None:
    bundle, client = _setup(tmp_path)
    preview = _preview(client).json()
    response = _confirm(client, preview["action_id"], preview["payload_digest"])
    assert response.status_code == 200
    body = response.json()
    assert body["state"] == "SUCCEEDED"
    assert body["created"] is True
    assert body["reconciled"] is False
    assert body["issue_number"] == 42
    assert body["issue_url"] == "https://github.com/example/priority-demo/issues/42"
    assert body["action_id"] == preview["action_id"]
    assert len(bundle.github.posts) == 1
    assert bundle.github.created_bodies == [
        {"title": preview["title"], "body": preview["body"]}
    ]


def test_confirm_endpoint_replay_returns_the_stored_result(tmp_path: Path) -> None:
    bundle, client = _setup(tmp_path)
    preview = _preview(client).json()
    first = _confirm(client, preview["action_id"], preview["payload_digest"])
    second = _confirm(client, preview["action_id"], preview["payload_digest"])
    assert first.status_code == 200 and first.json()["created"] is True
    assert second.status_code == 200 and second.json()["created"] is False
    assert second.json()["issue_number"] == 42
    assert len(bundle.github.posts) == 1


def test_confirm_endpoint_requires_the_secret_header(tmp_path: Path) -> None:
    bundle, client = _setup(tmp_path)
    preview = _preview(client).json()
    missing = _confirm(client, preview["action_id"], preview["payload_digest"], secret=None)
    assert missing.status_code == 401
    assert missing.json()["error"]["code"] == "action_unauthorized"
    wrong = _confirm(client, preview["action_id"], preview["payload_digest"], secret="nope")
    assert wrong.status_code == 401
    assert wrong.json()["error"]["code"] == "action_unauthorized"
    assert bundle.github.posts == []


def test_confirm_endpoint_is_503_without_a_configured_secret(tmp_path: Path) -> None:
    settings = make_action_settings(tmp_path, approval_secret=None)
    _, client = _setup(tmp_path, settings=settings)
    preview = _preview(client).json()
    response = _confirm(client, preview["action_id"], preview["payload_digest"])
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "action_authorization_not_configured"


def test_confirm_endpoint_rejects_unknown_or_malformed_actions(tmp_path: Path) -> None:
    _, client = _setup(tmp_path)
    unknown = _confirm(client, "act_" + "f" * 32, "sha256:" + "0" * 64)
    assert unknown.status_code == 404
    assert unknown.json()["error"]["code"] == "action_not_found"
    malformed = client.post(
        CONFIRM,
        json={"action_id": "act_x", "payload_digest": "not-a-digest"},
        headers={"X-BlastRadius-Approval": APPROVAL_SECRET},
    )
    assert malformed.status_code == 422
    assert malformed.json()["error"]["code"] == "invalid_input"


def test_confirm_endpoint_rejects_an_altered_digest(tmp_path: Path) -> None:
    bundle, client = _setup(tmp_path)
    preview = _preview(client).json()
    response = _confirm(client, preview["action_id"], "sha256:" + "0" * 64)
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "action_payload_mismatch"
    assert bundle.github.posts == []


def test_confirm_endpoint_rejects_caller_supplied_facts(tmp_path: Path) -> None:
    _, client = _setup(tmp_path)
    preview = _preview(client).json()
    response = client.post(
        CONFIRM,
        json={
            "action_id": preview["action_id"],
            "payload_digest": preview["payload_digest"],
            "repository": "attacker/repo",
        },
        headers={"X-BlastRadius-Approval": APPROVAL_SECRET},
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "invalid_input"


def test_confirm_endpoint_expired_action_is_a_410(tmp_path: Path) -> None:
    bundle, client = _setup(tmp_path)
    preview = _preview(client).json()
    bundle.clock.advance(901)
    response = _confirm(client, preview["action_id"], preview["payload_digest"])
    assert response.status_code == 410
    assert response.json()["error"]["code"] == "action_expired"
    assert bundle.github.posts == []


def test_confirm_endpoint_evidence_change_is_a_409(tmp_path: Path) -> None:
    bundle, client = _setup(tmp_path)
    preview = _preview(client).json()
    install(bundle.graph_client, findings=[finding_row(summary="Changed after preview")])
    response = _confirm(client, preview["action_id"], preview["payload_digest"])
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "action_evidence_changed"
    assert bundle.github.posts == []


def test_confirm_endpoint_permission_denied_is_a_403(tmp_path: Path) -> None:
    harness = GitHubHarness(create_status=403)
    bundle, client = _setup(tmp_path, harness=harness)
    preview = _preview(client).json()
    response = _confirm(client, preview["action_id"], preview["payload_digest"])
    assert response.status_code == 403
    body = response.json()
    assert body["error"]["code"] == "github_permission_denied"
    assert "Issues: write" in body["error"]["message"]
    record = bundle.store.get(preview["action_id"])
    assert record is not None and record.state == "FAILED"


def test_confirm_endpoint_ambiguous_outcome_is_a_502(tmp_path: Path) -> None:
    harness = GitHubHarness(create_error=httpx.ReadTimeout("slow"))
    bundle, client = _setup(tmp_path, harness=harness)
    preview = _preview(client).json()
    response = _confirm(client, preview["action_id"], preview["payload_digest"])
    assert response.status_code == 502
    body = response.json()
    assert body["error"]["code"] == "github_write_ambiguous"
    assert body["error"]["retryable"] is False
    record = bundle.store.get(preview["action_id"])
    assert record is not None
    assert record.state == "FAILED"
    assert record.failure_category == "github_write_ambiguous"


def test_confirm_endpoint_rate_limit_is_a_429(tmp_path: Path) -> None:
    harness = GitHubHarness(create_status=403, create_headers={"x-ratelimit-remaining": "0"})
    _, client = _setup(tmp_path, harness=harness)
    preview = _preview(client).json()
    response = _confirm(client, preview["action_id"], preview["payload_digest"])
    assert response.status_code == 429
    assert response.json()["error"]["code"] == "rate_limit_exceeded"


def test_confirm_endpoint_is_403_when_writes_are_disabled(tmp_path: Path) -> None:
    settings = make_action_settings(tmp_path, enabled=False)
    bundle, client = _setup(tmp_path, settings=settings)
    response = _confirm(client, "act_" + "0" * 32, "sha256:" + "0" * 64)
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "github_write_disabled"
    assert bundle.github.requests == []


# ---------------------------------------------------------------------------
# hygiene
# ---------------------------------------------------------------------------


def test_no_secret_is_ever_echoed_by_the_api(tmp_path: Path) -> None:
    bundle, client = _setup(tmp_path)
    preview = _preview(client)
    assert ACTION_TOKEN not in preview.text
    assert APPROVAL_SECRET not in preview.text
    wrong = _confirm(client, preview.json()["action_id"], preview.json()["payload_digest"], secret="boom")
    assert ACTION_TOKEN not in wrong.text
    assert APPROVAL_SECRET not in wrong.text
    ok = _confirm(client, preview.json()["action_id"], preview.json()["payload_digest"])
    assert ACTION_TOKEN not in ok.text
    assert APPROVAL_SECRET not in ok.text


def test_both_phase6_routes_are_visible_in_openapi(tmp_path: Path) -> None:
    _, client = _setup(tmp_path)
    schema = client.get("/openapi.json").json()
    paths = schema["paths"]
    assert "/api/v1/analyses/{analysis_id}/remediation/github-issue/preview" in paths
    assert "/api/v1/actions/github-issue/confirm" in paths
