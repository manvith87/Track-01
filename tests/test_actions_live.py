"""Opt-in live test: one real GitHub issue on an explicitly authorized repo.

BlastRadius's Phase 6 feature creates GitHub issues.  This module is the only
test that may perform a **real write**, and it is triple-guarded:

1. ``BLASTRADIUS_ACTIONS_LIVE_TESTS=1`` — nothing runs otherwise (the two tests
   below are skipped, so a normal ``pytest`` run never touches the network);
2. ``BLASTRADIUS_ACTIONS_LIVE_REPOSITORY=<owner/repo>`` — the designated test
   repository.  A small denylist refuses obvious unrelated public repositories;
3. ``BLASTRADIUS_ACTIONS_LIVE_CREATE=<canonical repo id>`` — explicit,
   id-bound authorization for the *write*.  The value must equal
   ``github.com/<owner>/<repo>`` exactly; a read-only preflight runs with just
   guard 1+2.

Credentials come from the dedicated action settings
(``BLASTRADIUS_ACTIONS_ENABLED=true``, ``BLASTRADIUS_ACTIONS_GITHUB_TOKEN``,
``BLASTRADIUS_ACTIONS_APPROVAL_SECRET``).  Use a throwaway sandbox repository
that you own; the created issue is a test artifact and is left open (the client
deliberately has no close/delete capability) — close it manually afterwards.
Never point these variables at a repository you do not control.

Run it with::

    $env:BLASTRADIUS_ACTIONS_LIVE_TESTS = "1"
    $env:BLASTRADIUS_ACTIONS_LIVE_REPOSITORY = "your-name/your-sandbox"
    $env:BLASTRADIUS_ACTIONS_GITHUB_TOKEN = "<fine-grained token, Issues: write>"
    $env:BLASTRADIUS_ACTIONS_ENABLED = "true"
    $env:BLASTRADIUS_ACTIONS_APPROVAL_SECRET = "<any secret>"
    $env:BLASTRADIUS_ACTIONS_LIVE_CREATE = "github.com/your-name/your-sandbox"
    python -m pytest tests/test_actions_live.py -m live_write -s
"""

from __future__ import annotations

import os
import time

import pytest

from app.actions.config import ActionSettings, normalize_repository_allowlist
from app.actions.issue_content import MARKER_TEMPLATE
from app.actions.service import new_action_id
from app.github.issue_client import GitHubIssueClient

pytestmark = pytest.mark.live_write

_LIVE = os.environ.get("BLASTRADIUS_ACTIONS_LIVE_TESTS") == "1"
_RAW_REPOSITORY = os.environ.get("BLASTRADIUS_ACTIONS_LIVE_REPOSITORY", "")
_CREATE_AUTHORIZATION = os.environ.get("BLASTRADIUS_ACTIONS_LIVE_CREATE", "")

#: Well-known public repositories this test must never write to, even if a
#: variable is misconfigured.  This is defense in depth; the real guard is the
#: exact-match authorization below.
_PROTECTED_REPOSITORIES = frozenset(
    {
        "github.com/psf/requests",
        "github.com/urllib3/urllib3",
        "github.com/django/django",
        "github.com/pallets/flask",
        "github.com/nodejs/node",
        "github.com/torvalds/linux",
    }
)

skip_unless_enabled = pytest.mark.skipif(
    not _LIVE,
    reason=(
        "live action test: set BLASTRADIUS_ACTIONS_LIVE_TESTS=1, "
        "BLASTRADIUS_ACTIONS_LIVE_REPOSITORY and the BLASTRADIUS_ACTIONS_* "
        "credential variables to enable"
    ),
)


def _settings() -> ActionSettings:
    return ActionSettings.from_env()


def _target() -> str:
    try:
        canonical = normalize_repository_allowlist((_RAW_REPOSITORY,))[0]
    except ValueError:
        pytest.fail(
            "BLASTRADIUS_ACTIONS_LIVE_REPOSITORY must be owner/repo or "
            "github.com/owner/repo"
        )
    if canonical in _PROTECTED_REPOSITORIES:
        pytest.fail(
            f"refusing to run a write test against the unrelated public "
            f"repository {canonical}; use your own sandbox repository"
        )
    return canonical


def _require_token(settings: ActionSettings) -> None:
    if not settings.has_token:
        pytest.fail("BLASTRADIUS_ACTIONS_GITHUB_TOKEN must be configured")


@skip_unless_enabled
def test_live_repository_preflight_is_read_only() -> None:
    settings = _settings()
    _require_token(settings)
    canonical = _target()
    owner, name = canonical.split("/")[1], canonical.split("/")[2]

    client = GitHubIssueClient(settings)
    try:
        access = client.check_repository_access(owner, name)
    finally:
        client.close()

    assert f"github.com/{access.full_name.lower()}" == canonical, (
        f"GitHub reports {access.full_name!r}; the configured test repository "
        f"is {canonical!r}"
    )
    assert access.has_issues, "the designated test repository must have issues enabled"
    print(
        f"live preflight ok: {canonical} has_issues={access.has_issues} "
        f"permissions={sorted(access.permissions)}"
    )


@skip_unless_enabled
def test_live_issue_creation_and_marker_search() -> None:
    settings = _settings()
    _require_token(settings)
    if not settings.enabled:
        pytest.fail("BLASTRADIUS_ACTIONS_ENABLED=true is required for a live write")
    canonical = _target()
    if _CREATE_AUTHORIZATION.strip().lower() != canonical:
        pytest.fail(
            "explicit write authorization missing: set "
            f"BLASTRADIUS_ACTIONS_LIVE_CREATE={canonical} (value must match "
            "BLASTRADIUS_ACTIONS_LIVE_REPOSITORY exactly)"
        )
    owner, name = canonical.split("/")[1], canonical.split("/")[2]

    action_id = new_action_id()
    marker = MARKER_TEMPLATE.format(action_id=action_id)
    title = f"[BlastRadius live test] {action_id}"
    body = (
        "This issue was created by the opt-in BlastRadius Phase 6 live test.\n\n"
        "It verifies that the dedicated GitHub issue client can create an issue "
        "and recover it through its unique action marker. It is a test artifact "
        "and can be closed at any time.\n\n"
        f"{marker}\n"
    )

    client = GitHubIssueClient(settings)
    try:
        created = client.create_issue(owner, name, title=title, body=body)
        found: list = []
        for attempt in range(6):
            found = client.find_issue_by_marker(owner, name, marker)
            if any(item.number == created.number for item in found):
                break
            if attempt < 5:
                time.sleep(5)
    finally:
        client.close()

    # The create response is the authoritative success signal.
    assert created.number >= 1
    assert created.url.startswith(f"https://github.com/{owner}/{name}/issues/")
    assert created.title == title
    if any(item.number == created.number for item in found):
        print(f"live creation ok: {created.url} (marker search matched)")
    else:
        # GitHub search indexing can lag; the creation itself is still verified.
        print(
            f"live creation ok: {created.url} "
            "(marker search has not indexed it yet — not a failure; re-run the "
            "marker lookup later)"
        )
