"""Persistent, atomic action store for the Phase 6 approval workflow.

Approval and execution guarantees cannot live only in process memory: a
confirmation must survive restarts, replay attempts must be refused after a
restart too, and two concurrent confirmations must not create two issues.  The
store is therefore a small SQLite database with compare-and-set transitions:

``PREVIEWED --(try_reserve)--> EXECUTING --(mark_succeeded / mark_failed)--> ...``

``PREVIEWED --(expire / try_reserve past expiry)--> EXPIRED``

The compare-and-set updates (``WHERE state = ...``) make every transition
atomic across threads and processes: exactly one caller can reserve an action,
so exactly one GitHub issue can be created for it.  No token, confirmation
secret or other credential is ever written to the store; failure details are
restricted to a stable error code plus a safe message.
"""

from __future__ import annotations

import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Final

from app.actions.models import ActionRecord
from app.core.errors import ActionStoreError

_COLUMNS: Final[tuple[str, ...]] = (
    "action_id",
    "state",
    "analysis_id",
    "repository_id",
    "repository_owner",
    "repository_name",
    "commit_sha",
    "group_id",
    "finding_id",
    "payload_digest",
    "title",
    "body",
    "created_at",
    "expires_at",
    "expires_at_ms",
    "approved_at",
    "executed_at",
    "issue_number",
    "issue_url",
    "failure_category",
    "failure_message",
    "reconciled",
)

_SCHEMA: Final[str] = """
CREATE TABLE IF NOT EXISTS actions (
    action_id TEXT PRIMARY KEY,
    state TEXT NOT NULL,
    analysis_id TEXT NOT NULL,
    repository_id TEXT NOT NULL,
    repository_owner TEXT NOT NULL,
    repository_name TEXT NOT NULL,
    commit_sha TEXT NOT NULL,
    group_id TEXT,
    finding_id TEXT,
    payload_digest TEXT NOT NULL,
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    expires_at_ms INTEGER NOT NULL,
    approved_at TEXT,
    executed_at TEXT,
    issue_number INTEGER,
    issue_url TEXT,
    failure_category TEXT,
    failure_message TEXT,
    reconciled INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS actions_expires_at_idx ON actions (expires_at_ms);
"""


def _iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).isoformat()


def _parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:  # pragma: no cover - defensive
        return None


def _ms(moment: datetime) -> int:
    return int(moment.astimezone(timezone.utc).timestamp() * 1000)


class ActionStore:
    """SQLite-backed action store with atomic compare-and-set transitions."""

    def __init__(self, path: Path | str) -> None:
        self._path = Path(path)
        self._lock = threading.Lock()
        self._conn: sqlite3.Connection | None = None

    # -- lifecycle ----------------------------------------------------------

    @property
    def path(self) -> Path:
        return self._path

    def initialize(self) -> None:
        """Create the parent directory, the database and the schema."""
        with self._lock:
            self._initialize_locked()

    def _initialize_locked(self) -> None:
        if self._conn is not None:
            return
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(
                self._path, timeout=5.0, check_same_thread=False
            )
        except (OSError, sqlite3.Error) as exc:
            raise ActionStoreError(
                "The action store could not be opened",
                details={"reason": type(exc).__name__},
            ) from exc
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA busy_timeout=5000")
            conn.executescript(_SCHEMA)
            conn.commit()
        except sqlite3.Error as exc:
            conn.close()
            raise ActionStoreError(
                "The action store schema could not be initialised",
                details={"reason": type(exc).__name__},
            ) from exc
        self._conn = conn

    def _connection(self) -> sqlite3.Connection:
        if self._conn is None:
            self._initialize_locked()
        assert self._conn is not None
        return self._conn

    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                self._conn.close()
                self._conn = None

    # -- row mapping ---------------------------------------------------------

    @staticmethod
    def _row_to_record(row: sqlite3.Row | tuple) -> ActionRecord:
        (
            action_id,
            state,
            analysis_id,
            repository_id,
            repository_owner,
            repository_name,
            commit_sha,
            group_id,
            finding_id,
            payload_digest,
            title,
            body,
            created_at,
            expires_at,
            _expires_at_ms,
            approved_at,
            executed_at,
            issue_number,
            issue_url,
            failure_category,
            failure_message,
            reconciled,
        ) = row
        return ActionRecord(
            action_id=action_id,
            state=state,
            analysis_id=analysis_id,
            repository_id=repository_id,
            repository_owner=repository_owner,
            repository_name=repository_name,
            commit_sha=commit_sha,
            group_id=group_id,
            finding_id=finding_id,
            payload_digest=payload_digest,
            title=title,
            body=body,
            created_at=_parse_iso(created_at) or datetime.now(timezone.utc),
            expires_at=_parse_iso(expires_at) or datetime.now(timezone.utc),
            approved_at=_parse_iso(approved_at),
            executed_at=_parse_iso(executed_at),
            issue_number=issue_number,
            issue_url=issue_url,
            failure_category=failure_category,
            failure_message=failure_message,
            reconciled=bool(reconciled),
        )

    def _select(self, action_id: str) -> ActionRecord | None:
        conn = self._connection()
        try:
            row = conn.execute(
                f"SELECT {', '.join(_COLUMNS)} FROM actions WHERE action_id = ?",
                (action_id,),
            ).fetchone()
        except sqlite3.Error as exc:
            raise ActionStoreError(
                "The action store could not be read",
                details={"reason": type(exc).__name__},
            ) from exc
        if row is None:
            return None
        return self._row_to_record(row)

    # -- mutations -----------------------------------------------------------

    def create(self, record: ActionRecord) -> None:
        """Insert a new PREVIEWED action record."""
        if record.state != "PREVIEWED":
            raise ActionStoreError(
                "Only PREVIEWED actions can be created",
                details={"state": record.state},
            )
        with self._lock:
            conn = self._connection()
            try:
                conn.execute(
                    f"INSERT INTO actions ({', '.join(_COLUMNS)}) VALUES "
                    f"({', '.join('?' for _ in _COLUMNS)})",
                    (
                        record.action_id,
                        record.state,
                        record.analysis_id,
                        record.repository_id,
                        record.repository_owner,
                        record.repository_name,
                        record.commit_sha,
                        record.group_id,
                        record.finding_id,
                        record.payload_digest,
                        record.title,
                        record.body,
                        _iso(record.created_at),
                        _iso(record.expires_at),
                        _ms(record.expires_at),
                        _iso(record.approved_at) if record.approved_at else None,
                        _iso(record.executed_at) if record.executed_at else None,
                        record.issue_number,
                        record.issue_url,
                        record.failure_category,
                        record.failure_message,
                        1 if record.reconciled else 0,
                    ),
                )
                conn.commit()
            except sqlite3.IntegrityError as exc:
                rollback_quietly(conn)
                raise ActionStoreError(
                    "An action with this id already exists",
                    details={"action_id": record.action_id},
                ) from exc
            except sqlite3.Error as exc:
                rollback_quietly(conn)
                raise ActionStoreError(
                    "The action could not be persisted",
                    details={"reason": type(exc).__name__},
                ) from exc

    def get(self, action_id: str) -> ActionRecord | None:
        """Return one record or None; expired PREVIEWED records are not mutated."""
        if not action_id:
            return None
        with self._lock:
            return self._select(action_id)

    def try_reserve(
        self,
        action_id: str,
        *,
        now: datetime,
    ) -> ActionRecord | None:
        """Atomically transition PREVIEWED -> EXECUTING.

        Returns the EXECUTING record when this caller won the race, or None
        when the action is not PREVIEWED any more (expired, already running,
        already consumed).  The expiry check is part of the same statement so
        an expired preview can never be executed.
        """
        with self._lock:
            conn = self._connection()
            try:
                cursor = conn.execute(
                    "UPDATE actions SET state = 'EXECUTING', approved_at = ? "
                    "WHERE action_id = ? AND state = 'PREVIEWED' AND expires_at_ms > ?",
                    (_iso(now), action_id, _ms(now)),
                )
                conn.commit()
            except sqlite3.Error as exc:
                rollback_quietly(conn)
                raise ActionStoreError(
                    "The action could not be reserved",
                    details={"reason": type(exc).__name__},
                ) from exc
            if cursor.rowcount != 1:
                return None
            return self._select(action_id)

    def expire(self, action_id: str) -> ActionRecord | None:
        """Atomically transition PREVIEWED -> EXPIRED (no-op for other states)."""
        with self._lock:
            conn = self._connection()
            try:
                conn.execute(
                    "UPDATE actions SET state = 'EXPIRED' "
                    "WHERE action_id = ? AND state = 'PREVIEWED'",
                    (action_id,),
                )
                conn.commit()
            except sqlite3.Error as exc:
                rollback_quietly(conn)
                raise ActionStoreError(
                    "The action could not be expired",
                    details={"reason": type(exc).__name__},
                ) from exc
            return self._select(action_id)

    def mark_succeeded(
        self,
        action_id: str,
        *,
        issue_number: int,
        issue_url: str,
        executed_at: datetime,
        reconciled: bool = False,
    ) -> ActionRecord:
        """Transition EXECUTING -> SUCCEEDED with the verified issue identity."""
        with self._lock:
            conn = self._connection()
            try:
                cursor = conn.execute(
                    "UPDATE actions SET state = 'SUCCEEDED', issue_number = ?, "
                    "issue_url = ?, executed_at = ?, reconciled = ?, "
                    "failure_category = NULL, failure_message = NULL "
                    "WHERE action_id = ? AND state = 'EXECUTING'",
                    (
                        issue_number,
                        issue_url,
                        _iso(executed_at),
                        1 if reconciled else 0,
                        action_id,
                    ),
                )
                conn.commit()
            except sqlite3.Error as exc:
                rollback_quietly(conn)
                raise ActionStoreError(
                    "The action result could not be recorded",
                    details={"reason": type(exc).__name__},
                ) from exc
            if cursor.rowcount != 1:
                raise ActionStoreError(
                    "The action was not in EXECUTING state",
                    details={"action_id": action_id},
                )
            record = self._select(action_id)
            assert record is not None
            return record

    def mark_failed(
        self,
        action_id: str,
        *,
        category: str,
        message: str,
        executed_at: datetime,
        reconciled: bool = False,
    ) -> ActionRecord:
        """Transition EXECUTING -> FAILED with a stable, non-secret failure record."""
        with self._lock:
            conn = self._connection()
            try:
                cursor = conn.execute(
                    "UPDATE actions SET state = 'FAILED', failure_category = ?, "
                    "failure_message = ?, executed_at = ?, reconciled = ? "
                    "WHERE action_id = ? AND state = 'EXECUTING'",
                    (
                        category,
                        message,
                        _iso(executed_at),
                        1 if reconciled else 0,
                        action_id,
                    ),
                )
                conn.commit()
            except sqlite3.Error as exc:
                rollback_quietly(conn)
                raise ActionStoreError(
                    "The action failure could not be recorded",
                    details={"reason": type(exc).__name__},
                ) from exc
            if cursor.rowcount != 1:
                raise ActionStoreError(
                    "The action was not in EXECUTING state",
                    details={"action_id": action_id},
                )
            record = self._select(action_id)
            assert record is not None
            return record

    def purge(self, *, now: datetime, retain_seconds: float) -> int:
        """Delete old consumed/expired records; SUCCEEDED records are retained.

        SUCCEEDED rows stay for idempotent replay and audit.  PREVIEWED rows
        are purged only long after expiry, so a late confirmation of an expired
        action still reports ``action_expired`` rather than ``action_not_found``
        within the retention window.
        """
        cutoff_ms = _ms(now) - int(retain_seconds * 1000)
        with self._lock:
            conn = self._connection()
            try:
                cursor = conn.execute(
                    "DELETE FROM actions WHERE state IN ('PREVIEWED', 'EXPIRED', 'FAILED') "
                    "AND expires_at_ms < ?",
                    (cutoff_ms,),
                )
                conn.commit()
            except sqlite3.Error as exc:
                rollback_quietly(conn)
                raise ActionStoreError(
                    "The action store could not be purged",
                    details={"reason": type(exc).__name__},
                ) from exc
            return int(cursor.rowcount or 0)


def rollback_quietly(conn: sqlite3.Connection) -> None:
    try:
        conn.rollback()
    except sqlite3.Error:  # pragma: no cover - defensive
        pass


__all__ = ["ActionStore"]
