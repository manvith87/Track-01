"""Unit tests for the persistent action store.

The store's compare-and-set transitions are the core replay/duplicate
protection of Phase 6, so they are tested directly: state machine, atomicity,
persistence across restarts and purge semantics.
"""

from __future__ import annotations

import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from app.actions.models import ActionRecord
from app.actions.store import ActionStore
from app.core.errors import ActionStoreError

NOW = datetime(2026, 3, 1, 12, 0, tzinfo=timezone.utc)


def _record(**overrides: object) -> ActionRecord:
    values: dict[str, object] = {
        "action_id": "act_" + "0" * 32,
        "state": "PREVIEWED",
        "analysis_id": "analysis_1",
        "repository_id": "github.com/example/demo",
        "repository_owner": "example",
        "repository_name": "demo",
        "commit_sha": "a" * 40,
        "group_id": "fixgroup_1",
        "finding_id": None,
        "payload_digest": "sha256:" + "b" * 64,
        "title": "title",
        "body": "body",
        "created_at": NOW,
        "expires_at": NOW + timedelta(seconds=900),
    }
    values.update(overrides)
    return ActionRecord(**values)  # type: ignore[arg-type]


def _store(tmp_path: Path) -> ActionStore:
    store = ActionStore(tmp_path / "actions.sqlite3")
    store.initialize()
    return store


# ---------------------------------------------------------------------------
# create / get
# ---------------------------------------------------------------------------


def test_create_and_get_roundtrip(tmp_path: Path) -> None:
    store = _store(tmp_path)
    record = _record()
    store.create(record)
    loaded = store.get(record.action_id)
    assert loaded is not None
    assert loaded.action_id == record.action_id
    assert loaded.state == "PREVIEWED"
    assert loaded.analysis_id == record.analysis_id
    assert loaded.repository_id == record.repository_id
    assert loaded.repository_owner == record.repository_owner
    assert loaded.repository_name == record.repository_name
    assert loaded.commit_sha == record.commit_sha
    assert loaded.group_id == record.group_id
    assert loaded.finding_id is None
    assert loaded.payload_digest == record.payload_digest
    assert loaded.title == record.title
    assert loaded.body == record.body
    assert loaded.created_at == record.created_at
    assert loaded.expires_at == record.expires_at
    assert loaded.issue_number is None
    assert loaded.issue_url is None
    assert loaded.failure_category is None
    assert loaded.reconciled is False


def test_create_only_accepts_previewed_records(tmp_path: Path) -> None:
    store = _store(tmp_path)
    with pytest.raises(ActionStoreError):
        store.create(_record(state="EXECUTING"))


def test_duplicate_action_id_is_rejected(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.create(_record())
    with pytest.raises(ActionStoreError):
        store.create(_record())


def test_get_unknown_action_returns_none(tmp_path: Path) -> None:
    store = _store(tmp_path)
    assert store.get("act_" + "f" * 32) is None
    assert store.get("") is None


# ---------------------------------------------------------------------------
# compare-and-set transitions
# ---------------------------------------------------------------------------


def test_try_reserve_wins_exactly_once(tmp_path: Path) -> None:
    store = _store(tmp_path)
    record = _record()
    store.create(record)
    reserved = store.try_reserve(record.action_id, now=NOW)
    assert reserved is not None
    assert reserved.state == "EXECUTING"
    assert reserved.approved_at == NOW
    assert store.try_reserve(record.action_id, now=NOW) is None
    loaded = store.get(record.action_id)
    assert loaded is not None and loaded.state == "EXECUTING"


def test_try_reserve_refuses_an_expired_preview(tmp_path: Path) -> None:
    store = _store(tmp_path)
    record = _record(expires_at=NOW - timedelta(seconds=1))
    store.create(record)
    assert store.try_reserve(record.action_id, now=NOW) is None
    loaded = store.get(record.action_id)
    assert loaded is not None
    assert loaded.state == "PREVIEWED"  # untouched by the refused reservation


def test_expire_transitions_only_previewed(tmp_path: Path) -> None:
    store = _store(tmp_path)
    record = _record()
    store.create(record)
    expired = store.expire(record.action_id)
    assert expired is not None and expired.state == "EXPIRED"
    # expiring again is a no-op returning the current record
    again = store.expire(record.action_id)
    assert again is not None and again.state == "EXPIRED"
    # unknown ids return None
    assert store.expire("act_" + "f" * 32) is None


def test_expire_does_not_touch_executing(tmp_path: Path) -> None:
    store = _store(tmp_path)
    record = _record()
    store.create(record)
    store.try_reserve(record.action_id, now=NOW)
    loaded = store.expire(record.action_id)
    assert loaded is not None and loaded.state == "EXECUTING"


def test_mark_succeeded_requires_executing(tmp_path: Path) -> None:
    store = _store(tmp_path)
    record = _record()
    store.create(record)
    with pytest.raises(ActionStoreError):
        store.mark_succeeded(
            record.action_id,
            issue_number=1,
            issue_url="https://github.com/example/demo/issues/1",
            executed_at=NOW,
        )


def test_mark_succeeded_records_the_issue(tmp_path: Path) -> None:
    store = _store(tmp_path)
    record = _record(expires_at=NOW + timedelta(seconds=900))
    store.create(record)
    store.try_reserve(record.action_id, now=NOW)
    executed = NOW + timedelta(seconds=5)
    updated = store.mark_succeeded(
        record.action_id,
        issue_number=42,
        issue_url="https://github.com/example/demo/issues/42",
        executed_at=executed,
    )
    assert updated.state == "SUCCEEDED"
    assert updated.issue_number == 42
    assert updated.issue_url == "https://github.com/example/demo/issues/42"
    assert updated.executed_at == executed
    assert updated.reconciled is False
    # a later replay returns the same stored result through get()
    loaded = store.get(record.action_id)
    assert loaded is not None and loaded.issue_number == 42


def test_mark_succeeded_reconciled_flag(tmp_path: Path) -> None:
    store = _store(tmp_path)
    record = _record()
    store.create(record)
    store.try_reserve(record.action_id, now=NOW)
    updated = store.mark_succeeded(
        record.action_id,
        issue_number=7,
        issue_url="https://github.com/example/demo/issues/7",
        executed_at=NOW,
        reconciled=True,
    )
    assert updated.reconciled is True


def test_mark_failed_records_the_category(tmp_path: Path) -> None:
    store = _store(tmp_path)
    record = _record()
    store.create(record)
    store.try_reserve(record.action_id, now=NOW)
    updated = store.mark_failed(
        record.action_id,
        category="github_permission_denied",
        message="token cannot create issues",
        executed_at=NOW + timedelta(seconds=2),
    )
    assert updated.state == "FAILED"
    assert updated.failure_category == "github_permission_denied"
    assert updated.failure_message == "token cannot create issues"
    assert updated.reconciled is False


def test_mark_failed_requires_executing(tmp_path: Path) -> None:
    store = _store(tmp_path)
    record = _record()
    store.create(record)
    with pytest.raises(ActionStoreError):
        store.mark_failed(
            record.action_id, category="x", message="y", executed_at=NOW
        )


# ---------------------------------------------------------------------------
# persistence + atomicity
# ---------------------------------------------------------------------------


def test_state_survives_a_restart(tmp_path: Path) -> None:
    path = tmp_path / "actions.sqlite3"
    first = ActionStore(path)
    first.initialize()
    record = _record()
    first.create(record)
    first.try_reserve(record.action_id, now=NOW)
    first.mark_succeeded(
        record.action_id,
        issue_number=3,
        issue_url="https://github.com/example/demo/issues/3",
        executed_at=NOW,
    )
    first.close()

    second = ActionStore(path)
    second.initialize()
    loaded = second.get(record.action_id)
    assert loaded is not None
    assert loaded.state == "SUCCEEDED"
    assert loaded.issue_number == 3
    # the successful action can never be reserved again after a restart
    assert second.try_reserve(record.action_id, now=NOW) is None


def test_concurrent_reservations_have_exactly_one_winner(tmp_path: Path) -> None:
    store = _store(tmp_path)
    record = _record()
    store.create(record)

    barrier = threading.Barrier(2)
    results: list[ActionRecord | None] = []
    lock = threading.Lock()

    def attempt() -> None:
        barrier.wait(timeout=5)
        outcome = store.try_reserve(record.action_id, now=NOW)
        with lock:
            results.append(outcome)

    threads = [threading.Thread(target=attempt) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)

    assert len(results) == 2
    assert sum(1 for item in results if item is not None) == 1
    loaded = store.get(record.action_id)
    assert loaded is not None and loaded.state == "EXECUTING"


def test_lazy_initialisation_on_first_use(tmp_path: Path) -> None:
    store = ActionStore(tmp_path / "nested" / "dir" / "actions.sqlite3")
    assert store.get("act_" + "f" * 32) is None
    assert store.path.parent.exists()


# ---------------------------------------------------------------------------
# purge
# ---------------------------------------------------------------------------


def test_purge_removes_old_records_but_keeps_successes(tmp_path: Path) -> None:
    store = _store(tmp_path)
    old = NOW - timedelta(days=30)
    fresh = NOW

    succeeded = _record(action_id="act_" + "1" * 32, created_at=old, expires_at=old + timedelta(seconds=1))
    failed = _record(action_id="act_" + "2" * 32, created_at=old, expires_at=old + timedelta(seconds=1))
    expired = _record(action_id="act_" + "3" * 32, created_at=old, expires_at=old + timedelta(seconds=1))
    current = _record(action_id="act_" + "4" * 32, created_at=fresh, expires_at=fresh + timedelta(seconds=900))

    store.create(succeeded)
    store.create(failed)
    store.create(expired)
    store.create(current)
    store.try_reserve(succeeded.action_id, now=old)
    store.mark_succeeded(
        succeeded.action_id,
        issue_number=1,
        issue_url="https://github.com/example/demo/issues/1",
        executed_at=old,
    )
    store.try_reserve(failed.action_id, now=old)
    store.mark_failed(
        failed.action_id, category="x", message="y", executed_at=old
    )

    removed = store.purge(now=NOW, retain_seconds=7 * 24 * 3600)
    assert removed == 2  # failed + expired
    assert store.get(succeeded.action_id) is not None  # audit/idempotency kept
    assert store.get(current.action_id) is not None
    assert store.get(failed.action_id) is None
    assert store.get(expired.action_id) is None


def test_purge_never_removes_a_fresh_preview(tmp_path: Path) -> None:
    store = _store(tmp_path)
    record = _record()
    store.create(record)
    assert store.purge(now=NOW, retain_seconds=1) == 0
    loaded = store.get(record.action_id)
    assert loaded is not None and loaded.state == "PREVIEWED"
