"""Shared helpers for the BlastRadius test suite.

Nothing in here touches the network: retrievers and GitHub clients are fakes
with the same interfaces as the real ones, and every fixture repository is
materialised from an explicit in-test dictionary so the tests are fully
controlled and deterministic.  Phase 3 additions cover OSV record builders and
a scriptable OSV client double.
"""

from __future__ import annotations

import io
import tarfile
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from app.core.config import Settings
from app.graph.config import GraphSettings
from app.ingestion.github_api import ReferenceResolution, RepositoryMetadataSnapshot
from app.ingestion.retrieval import RetrievalReport
from app.models.common import ReferenceType, RetrievalStrategy
from app.models.repository import RepositoryIdentity

#: Deterministic commit SHAs used by the fakes (40 hex characters).
FAKE_SHA = "a" * 40
FAKE_SHA_ALT = "b" * 40
FAKE_SHA_MOVED = "c" * 40

FileContent = str | bytes
FileTree = Mapping[str, FileContent]


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------
def make_settings(temp_root: Path | None = None, **overrides: Any) -> Settings:
    """Build a Settings object without touching the environment."""
    values: dict[str, Any] = {
        "log_level": "WARNING",
        "metadata_timeout_seconds": 5.0,
        "git_timeout_seconds": 10.0,
        "download_timeout_seconds": 5.0,
        "max_ingestion_seconds": 30.0,
    }
    if temp_root is not None:
        values["temp_root"] = temp_root
    values.update(overrides)
    return Settings(**values)


# ---------------------------------------------------------------------------
# Fixture file trees
# ---------------------------------------------------------------------------
def write_tree(root: Path, files: FileTree) -> None:
    """Materialise a dict of relative paths -> content under ``root``."""
    root.mkdir(parents=True, exist_ok=True)
    for relative, content in files.items():
        path = root.joinpath(*relative.split("/"))
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content, encoding="utf-8")


CLEAN_REPOSITORY: FileTree = {
    "README.md": "# clean\n",
    "requirements.txt": "requests>=2.31,<3\nclick==8.1.7\n",
    "pyproject.toml": (
        "[project]\n"
        'name = "clean"\n'
        'version = "0.1.0"\n'
        'requires-python = ">=3.9"\n'
        "dependencies = [\n"
        '  "requests>=2.31,<3",\n'
        '  "click==8.1.7",\n'
        "]\n"
    ),
}

MESSY_REPOSITORY: FileTree = {
    "README.md": "# messy repository used to exercise conflict reporting\n",
    "requirements.txt": "requests>=2.31,<3\nclick==8.1.7\n-r requirements-dev.txt\n",
    "requirements-dev.txt": "pytest==7.0.0\nclick==8.1.6\n",
    "pyproject.toml": (
        "[project]\n"
        'name = "messy"\n'
        'version = "1.0.0"\n'
        'requires-python = ">=3.9"\n'
        "dependencies = [\n"
        '  "requests>=2.31,<3",\n'
        "]\n"
        "\n"
        "[project.optional-dependencies]\n"
        'socks = ["PySocks>=1.5.6"]\n'
        "\n"
        "[dependency-groups]\n"
        'dev = ["pytest>=8"]\n'
    ),
    "poetry.lock": (
        "# generated lock file used as a fixture\n"
        "[[package]]\n"
        'name = "requests"\n'
        'version = "2.31.0"\n'
        "optional = false\n"
        'python-versions = ">=3.7"\n'
        'groups = ["main"]\n'
        "files = []\n"
        "\n"
        "[package.dependencies]\n"
        'certifi = ">=2017.4.17"\n'
        'urllib3 = ">=1.21.1,<3"\n'
        "\n"
        "[[package]]\n"
        'name = "urllib3"\n'
        'version = "2.2.1"\n'
        "optional = false\n"
        'python-versions = ">=3.8"\n'
        'groups = ["main"]\n'
        "files = []\n"
        "\n"
        "[[package]]\n"
        'name = "certifi"\n'
        'version = "2024.2.2"\n'
        "optional = false\n"
        'python-versions = ">=3.6"\n'
        'groups = ["main"]\n'
        "files = []\n"
        "\n"
        "[[package]]\n"
        'name = "click"\n'
        'version = "8.1.7"\n'
        "optional = false\n"
        'python-versions = ">=3.7"\n'
        'groups = ["main"]\n'
        "files = []\n"
        "\n"
        "[[package]]\n"
        'name = "pytest"\n'
        'version = "8.2.0"\n'
        "optional = false\n"
        'python-versions = ">=3.8"\n'
        'groups = ["dev"]\n'
        "files = []\n"
        "\n"
        "[package.dependencies]\n"
        'pluggy = ">=1.5,<2"\n'
        "\n"
        "[[package]]\n"
        'name = "pluggy"\n'
        'version = "1.5.0"\n'
        "optional = false\n"
        'python-versions = ">=3.8"\n'
        'groups = ["dev"]\n'
        "files = []\n"
        "\n"
        "[[package]]\n"
        'name = "pysocks"\n'
        'version = "1.7.1"\n'
        "optional = false\n"
        'python-versions = ">=3.7"\n'
        'groups = ["main"]\n'
        "files = []\n"
        "\n"
        "[[package]]\n"
        'name = "rich"\n'
        'version = "13.7.1"\n'
        "optional = false\n"
        'python-versions = ">=3.7"\n'
        'groups = ["main"]\n'
        "files = []\n"
        'markers = "python_version >= \\"3.8\\""\n'
        "\n"
        "[[package]]\n"
        'name = "rich"\n'
        'version = "13.6.0"\n'
        "optional = false\n"
        'python-versions = ">=3.7"\n'
        'groups = ["main"]\n'
        "files = []\n"
        'markers = "python_version < \\"3.8\\""\n'
        "\n"
        "[metadata]\n"
        'lock-version = "2.0"\n'
        'python-versions = "^3.9"\n'
        'content-hash = "0000000000000000000000000000000000000000000000000000000000000000"\n'
    ),
    "uvproj/pyproject.toml": (
        "[project]\n"
        'name = "uvproj"\n'
        'version = "0.1.0"\n'
        'requires-python = ">=3.11"\n'
        "dependencies = [\n"
        '  "rich>=13",\n'
        "]\n"
    ),
    "uvproj/uv.lock": (
        "version = 1\n"
        'requires-python = ">=3.11"\n'
        "\n"
        "[[package]]\n"
        'name = "uvproj"\n'
        'version = "0.1.0"\n'
        'source = { editable = "." }\n'
        "dependencies = [\n"
        '    { name = "rich" },\n'
        "]\n"
        "\n"
        "[[package]]\n"
        'name = "rich"\n'
        'version = "13.7.1"\n'
        'source = { registry = "https://pypi.org/simple" }\n'
        "dependencies = [\n"
        '    { name = "markdown-it-py", specifier = ">=2.2.0" },\n'
        "]\n"
        "\n"
        "[[package]]\n"
        'name = "markdown-it-py"\n'
        'version = "3.0.0"\n'
        'source = { registry = "https://pypi.org/simple" }\n'
        "dependencies = [\n"
        '    { name = "mdurl", specifier = ">=0.1.0" },\n'
        "]\n"
        "\n"
        "[[package]]\n"
        'name = "mdurl"\n'
        'version = "0.1.2"\n'
        'source = { registry = "https://pypi.org/simple" }\n'
    ),
    "Pipfile": '[packages]\nrequests = "*"\n',
    "legacy/setup.py": "from setuptools import setup\nsetup(name='legacy')\n",
    ".venv/pyvenv.cfg": "home = /usr/bin\n",
    ".venv/lib/requirements.txt": "requests\n",
    "node_modules/requirements.txt": "left-pad\n",
}

EMPTY_REPOSITORY: FileTree = {"README.md": "# nothing to see here\n"}

BROKEN_REPOSITORY: FileTree = {
    "poetry.lock": "[[package]\nname = broken\n",
    "requirements.txt": "requests>=2.31,<3\n",
}

OVERSIZED_REPOSITORY: FileTree = {
    "requirements.txt": "requests>=2.31,<3\n" + "\n" + "".join(f"package-{i}==1.0.{i}\n" for i in range(200)),
}


# ---------------------------------------------------------------------------
# Fakes for retrieval and the GitHub API
# ---------------------------------------------------------------------------
class FakeRetriever:
    """Retrieval strategy that materialises a file tree instead of using Git."""

    def __init__(
        self,
        files: FileTree | None = None,
        *,
        sha: str = FAKE_SHA,
        verified: bool = True,
        strategy: RetrievalStrategy = RetrievalStrategy.GIT,
        error: Exception | None = None,
        warnings: Iterable[Any] = (),
        files_written: int | None = None,
        bytes_written: int | None = None,
    ) -> None:
        self.files = dict(files or {})
        self.sha = sha
        self.verified = verified
        self.strategy = strategy
        self.error = error
        self.warnings = tuple(warnings)
        self.files_written = files_written
        self.bytes_written = bytes_written
        self.calls: list[dict[str, Any]] = []
        self.name = "fake"

    def retrieve(
        self,
        *,
        identity: RepositoryIdentity,
        commit_sha: str,
        reference: Any,
        reference_type: ReferenceType,
        workdir: Path,
        deadline: float | None = None,
    ) -> RetrievalReport:
        self.calls.append(
            {
                "identity": identity.canonical_id,
                "commit_sha": commit_sha,
                "reference": reference.name if reference is not None else None,
                "reference_type": reference_type,
                "workdir": workdir,
                "deadline": deadline,
            }
        )
        if self.error is not None:
            raise self.error
        root = workdir / "repo"
        write_tree(root, self.files)
        written = self.files_written if self.files_written is not None else len(self.files)
        size = self.bytes_written
        if size is None:
            size = sum(len(value.encode("utf-8")) if isinstance(value, str) else len(value) for value in self.files.values())
        return RetrievalReport(
            strategy=self.strategy,
            repository_root=root,
            commit_sha=self.sha,
            commit_sha_verified=self.verified,
            files_written=written,
            bytes_written=size,
            duration_ms=1,
            warnings=self.warnings,
        )


class StubGitHubClient:
    """Read-only GitHub API client stub with the real client's interface."""

    def __init__(
        self,
        *,
        snapshot: RepositoryMetadataSnapshot | None = None,
        sha: str = FAKE_SHA,
        metadata_error: Exception | None = None,
        resolution_error: Exception | None = None,
        tags: Iterable[str] = (),
        commit_message: str | None = "test commit",
        commit_author: str | None = "Test Author",
    ) -> None:
        self.snapshot = snapshot if snapshot is not None else RepositoryMetadataSnapshot(
            default_branch="main",
            description="fixture repository",
            size_kb=128,
            stars=3,
            license_spdx_id="MIT",
            primary_language="Python",
        )
        self.sha = sha
        self.metadata_error = metadata_error
        self.resolution_error = resolution_error
        self.tags = set(tags)
        self.commit_message = commit_message
        self.commit_author = commit_author
        self.metadata_calls = 0
        self.resolution_calls: list[str | None] = []
        self.closed = False

    def get_repository(self, identity: RepositoryIdentity) -> RepositoryMetadataSnapshot:
        self.metadata_calls += 1
        if self.metadata_error is not None:
            raise self.metadata_error
        return self.snapshot

    def resolve_reference(
        self,
        identity: RepositoryIdentity,
        reference: Any,
        *,
        default_branch: str | None,
        is_default_branch: bool = False,
    ) -> ReferenceResolution:
        self.resolution_calls.append(reference.name if reference is not None else None)
        if self.resolution_error is not None:
            raise self.resolution_error
        if reference is None:
            return ReferenceResolution(
                commit_sha=self.sha,
                ref_type=ReferenceType.DEFAULT_BRANCH,
                resolved_via="github_api",
                default_branch=default_branch,
                commit_message=self.commit_message,
                commit_author=self.commit_author,
                commit_source="github_api",
            )
        if reference.is_full_sha:
            return ReferenceResolution(
                commit_sha=reference.name,
                ref_type=ReferenceType.COMMIT,
                resolved_via="provided_commit_sha",
                default_branch=default_branch,
                commit_message=self.commit_message,
                commit_author=self.commit_author,
                commit_source="request",
            )
        return ReferenceResolution(
            commit_sha=self.sha,
            ref_type=ReferenceType.BRANCH,
            resolved_via="github_api",
            default_branch=default_branch,
            commit_message=self.commit_message,
            commit_author=self.commit_author,
            commit_source="github_api",
        )

    def is_ref_a_tag(self, identity: RepositoryIdentity, name: str) -> bool:
        return name in self.tags

    def close(self) -> None:
        self.closed = True


# ---------------------------------------------------------------------------
# Archives
# ---------------------------------------------------------------------------
def make_tar_gz(files: FileTree, *, wrapper: str | None = None) -> bytes:
    """Build a gzipped tar archive with regular file members."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        for relative, content in files.items():
            payload = content.encode("utf-8") if isinstance(content, str) else content
            name = f"{wrapper}/{relative}" if wrapper else relative
            info = tarfile.TarInfo(name=name)
            info.size = len(payload)
            info.mode = 0o644
            tar.addfile(info, io.BytesIO(payload))
    return buffer.getvalue()


def make_tar_gz_members(members: Iterable[tuple[tarfile.TarInfo, bytes | None]]) -> bytes:
    """Build a gzipped tar archive from raw TarInfo members (adversarial cases)."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        for info, payload in members:
            tar.addfile(info, io.BytesIO(payload) if payload is not None else None)
    return buffer.getvalue()


def file_member(name: str, content: bytes = b"x") -> tuple[tarfile.TarInfo, bytes]:
    info = tarfile.TarInfo(name=name)
    info.size = len(content)
    info.mode = 0o644
    return info, content


def symlink_member(name: str, target: str) -> tuple[tarfile.TarInfo, None]:
    info = tarfile.TarInfo(name=name)
    info.type = tarfile.SYMTYPE
    info.linkname = target
    return info, None


def hardlink_member(name: str, target: str) -> tuple[tarfile.TarInfo, None]:
    info = tarfile.TarInfo(name=name)
    info.type = tarfile.LNKTYPE
    info.linkname = target
    return info, None


def device_member(name: str) -> tuple[tarfile.TarInfo, None]:
    info = tarfile.TarInfo(name=name)
    info.type = tarfile.CHRTYPE
    info.devmajor = 1
    info.devminor = 3
    return info, None


# ---------------------------------------------------------------------------
# Misc
# ---------------------------------------------------------------------------
def try_symlink(target: Path, link: Path, *, target_is_directory: bool = False) -> bool:
    """Create a symlink, returning False when the platform refuses (Windows)."""
    try:
        link.symlink_to(target, target_is_directory=target_is_directory)
    except (OSError, NotImplementedError):
        return False
    return True


# ---------------------------------------------------------------------------
# Graph test doubles (Phase 2)
# ---------------------------------------------------------------------------

class FakeQueryResult:
    """In-memory stand-in for ``falkordb.query_result.QueryResult``."""

    def __init__(self, header: list[str], rows: list[list[Any]], run_time_ms: float = 1.0) -> None:
        self.header = list(header)
        self._rows = [list(row) for row in rows]
        self.run_time_ms = run_time_ms

    @property
    def result_set(self) -> list[list[Any]]:
        return self._rows


class FakeGraphClient:
    """Stateful in-memory FalkorDB stand-in for unit tests.

    Records every query, tracks nodes created through upserts, and answers
    ``WHERE n.id IN $ids`` existence checks so that idempotent re-ingestion can
    be exercised without a real database.
    """

    def __init__(self, settings: GraphSettings | None = None) -> None:
        self.settings = settings or GraphSettings()
        self.connected = False
        self.queries: list[tuple[str, dict[str, Any]]] = []
        self.nodes: dict[str, dict[str, dict[str, Any]]] = {}  # label -> id -> props
        # (relationship type, from_id, to_id, variant_key) -> edge params
        # (Phase 8: parallel variants of the same package pair stay distinct).
        self.relationships: dict[tuple[str, str, str, str], dict[str, Any]] = {}
        # (package_id, vulnerability_id) -> edge params (Phase 3).
        self.affected_by: dict[tuple[str, str], dict[str, Any]] = {}
        # Exact-query-string canned results for read tests (template -> result).
        self.canned: dict[str, FakeQueryResult] = {}

    def connect(self) -> None:
        self.connected = True

    def close(self) -> None:
        self.connected = False

    @property
    def is_connected(self) -> bool:
        return self.connected

    def ping(self) -> bool:
        return self.connected

    @property
    def graph(self):
        if not self.connected:
            from app.graph.errors import GraphUnavailableError

            raise GraphUnavailableError("not connected")
        return self

    def query(
        self,
        cypher: str,
        *,
        params: dict[str, Any] | None = None,
        timeout: int | None = None,
        read_only: bool = False,
    ) -> FakeQueryResult:
        params = dict(params or {})
        self.queries.append((cypher, params))

        import re

        # Exact canned results take precedence (used to simulate real reads).
        canned = self.canned.get(cypher)
        if canned is not None:
            return canned

        # Existence check used by _existing_ids / _existing_vulnerability_ids.
        m = re.search(r"MATCH \(\w+:(\w+)\)\s+WHERE \w+\.id IN \$ids RETURN \w+\.id AS id", cypher)
        if m:
            label = m.group(1)
            ids = list(params.get("ids", []))
            existing = self.nodes.get(label, {})
            rows = [[node_id] for node_id in ids if node_id in existing]
            return FakeQueryResult(["id"], rows)

        # Node upsert (idempotent MERGE with COALESCE semantics: a None
        # parameter leaves the previously stored value untouched).
        m = re.search(r"MERGE \(\w+:(\w+) \{id: \$id\}\)", cypher)
        if m and "RETURN n.id AS id" in cypher:
            label = m.group(1)
            node_id = str(params.get("id"))
            stored = self.nodes.get(label, {}).get(node_id, {})
            merged = dict(stored)
            merged.update(
                {
                    key: value
                    for key, value in params.items()
                    if key not in {"id", "created_at", "updated_at"} and value is not None
                }
            )
            self.nodes.setdefault(label, {})[node_id] = merged
            return FakeQueryResult(["id"], [[node_id]])

        # Variant-aware relationship upsert (Phase 8): relationships of the same
        # type between the same nodes stay distinct when their variant keys
        # differ; re-upserting the same key updates the stored properties.
        m = re.search(
            r"MERGE \(\w+\)-\[rel:(\w+) \{variant_key: \$variant_key\}\]->\(\w+\)", cypher
        )
        if m:
            key = (
                m.group(1),
                str(params.get("from_id")),
                str(params.get("to_id")),
                str(params.get("variant_key")),
            )
            stored = dict(self.relationships.get(key, {}))
            stored.update(
                {
                    name: value
                    for name, value in params.items()
                    if name not in {"from_id", "to_id", "variant_key", "created_at", "updated_at"}
                    and value is not None
                }
            )
            self.relationships[key] = stored
            return FakeQueryResult(["rel"], [])

        # AFFECTED_BY edge upsert (Phase 3): enforces that both endpoints exist,
        # mirroring the real MATCH-then-MERGE semantics.
        if "MERGE (p)-[rel:AFFECTED_BY]->(n)" in cypher:
            package_id = str(params.get("package_id"))
            vulnerability_id = str(params.get("vulnerability_id"))
            package_ok = package_id in self.nodes.get("Package", {})
            vulnerability_ok = vulnerability_id in self.nodes.get("Vulnerability", {})
            if not (package_ok and vulnerability_ok):
                return FakeQueryResult(["package_id", "vulnerability_id"], [])
            key = (package_id, vulnerability_id)
            self.affected_by[key] = {
                k: v
                for k, v in params.items()
                if k not in {"package_id", "vulnerability_id", "created_at", "updated_at"}
                and v is not None
            }
            return FakeQueryResult(["package_id", "vulnerability_id"], [[package_id, vulnerability_id]])

        # Existing AFFECTED_BY edge enumeration (scope-aware, Phase 3).
        if "RETURN p.id AS package_id, v.id AS vulnerability_id" in cypher:
            repository_id = params.get("repository_id")
            commit_sha = params.get("commit_sha")
            rows = []
            for (package_id, _vuln_id), edge_props in self.affected_by.items():
                if edge_props.get("repository_id") == repository_id and edge_props.get("commit_sha") == commit_sha:
                    if package_id in self.nodes.get("Package", {}):
                        rows.append([package_id, _vuln_id])
            return FakeQueryResult(["package_id", "vulnerability_id"], rows)

        # Relationship upsert.
        if "RETURN rel" in cypher:
            return FakeQueryResult(["rel"], [[]])

        # Reads: empty result by default.
        return FakeQueryResult([], [])


def make_fake_graph_client() -> FakeGraphClient:
    return FakeGraphClient()


# ---------------------------------------------------------------------------
# OSV test doubles (Phase 3)
# ---------------------------------------------------------------------------

def raw_osv_record(
    osv_id: str = "GHSA-test-0001",
    *,
    ecosystem: str = "PyPI",
    name: str = "requests",
    introduced: str = "0",
    fixed: str | None = "2.31.0",
    aliases: list[str] | None = None,
    modified: str = "2024-01-01T00:00:00Z",
    severity: list[dict[str, Any]] | None = None,
    references: list[dict[str, Any]] | None = None,
    versions: list[str] | None = None,
    omit_affected: bool = False,
) -> dict[str, Any]:
    """Build a raw OSV record shaped like the upstream API payloads."""
    affected: list[dict[str, Any]] = [] if omit_affected else [
        {
            "package": {"name": name, "ecosystem": ecosystem},
            "ranges": [
                {
                    "type": "ECOSYSTEM",
                    "events": ([{"introduced": introduced}] if fixed is None else [{"introduced": introduced}, {"fixed": fixed}]),
                }
            ],
            **({"versions": versions} if versions else {}),
        }
    ]
    record: dict[str, Any] = {
        "id": osv_id,
        "modified": modified,
        "affected": affected,
    }
    if aliases is not None:
        record["aliases"] = aliases
    if severity is not None:
        record["severity"] = severity
    if references is not None:
        record["references"] = references
    return record


class FakeOsvClient:
    """Scriptable stand-in for :class:`app.osv.client.OsvApiClient`.

    Response maps are keyed by (ecosystem, package_name, version) — the value
    is either a raw response dict, a raw record list for ``iter_vulnerabilities``
    or an exception instance to raise.
    """

    def __init__(
        self,
        *,
        query_responses: dict[tuple[str, str, str | None], Any] | None = None,
        batch_results: list[Any] | None = None,
        batch_errors: list[Any] | None = None,
        records: dict[str, Any] | None = None,
        record_errors: dict[str, Any] | None = None,
        query_errors: dict[tuple[str, str, str | None], Any] | None = None,
        record_error_for_missing: Any = None,
    ) -> None:
        self.query_calls: list[dict[str, Any]] = []
        self.batch_calls: list[list[dict[str, Any]]] = []
        self.get_calls: list[str] = []
        self._query_responses = dict(query_responses or {})
        self._batch_results = list(batch_results or [])  # list per call, consumed in order
        self._batch_errors = list(batch_errors or [])
        self._records = dict(records or {})
        self._record_errors = dict(record_errors or {})
        self._query_errors = dict(query_errors or {})
        self._record_error_for_missing = record_error_for_missing

    # -- client surface ------------------------------------------------------
    def iter_vulnerabilities(
        self, *, ecosystem: str, package_name: str, version: str | None = None
    ) -> list[dict[str, Any]]:
        self.query_calls.append(
            {"ecosystem": ecosystem, "package_name": package_name, "version": version}
        )
        key = (ecosystem, package_name, version)
        error = self._query_errors.get(key)
        if error is not None:
            if isinstance(error, Exception):
                raise error
            raise AssertionError("configured error must be an exception")
        response = self._query_responses.get(key, {"vulns": []})
        if isinstance(response, Exception):
            raise response
        return list(response.get("vulns") or [])

    def query_vulnerabilities(
        self,
        *,
        ecosystem: str,
        package_name: str,
        version: str | None = None,
        page_token: str | None = None,
    ) -> dict[str, Any]:
        self.query_calls.append(
            {
                "ecosystem": ecosystem,
                "package_name": package_name,
                "version": version,
                "page_token": page_token,
            }
        )
        return {"vulns": []}

    def query_batch(self, queries: list[dict[str, Any]]) -> list[dict[str, Any]]:
        self.batch_calls.append(list(queries))
        if self._batch_errors:
            error = self._batch_errors.pop(0)
            if error is not None:
                raise error
        if len(self._batch_results) > 1:
            return list(self._batch_results.pop(0))
        # A single configured batch is replayed for every call.
        if self._batch_results:
            return list(self._batch_results[0])
        return [{"vulns": []} for _ in queries]

    def get_vulnerability(self, osv_id: str) -> dict[str, Any]:
        self.get_calls.append(osv_id)
        error = self._record_errors.get(osv_id)
        if error is not None:
            raise error
        record = self._records.get(osv_id)
        if record is None:
            if self._record_error_for_missing is not None:
                raise self._record_error_for_missing
            return raw_osv_record(osv_id)
        return dict(record)


def make_osv_settings(**overrides: Any) -> Any:
    """Build OsvSettings for tests without touching the environment."""
    from app.osv.config import OsvSettings

    values: dict[str, Any] = {"max_retries": 0, "retry_backoff_seconds": 0.01}
    values.update(overrides)
    return OsvSettings(**values)

