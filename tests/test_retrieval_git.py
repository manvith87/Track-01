"""Git retrieval tests.

``subprocess.run`` is replaced by a fake that records the *real* commands the
retriever builds, so the tests verify the hardened configuration, the exact
fetch-by-SHA sequence, the fallback path and the SHA checks without ever
touching the network.
"""

from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path

import pytest

from app.core.errors import (
    DownloadTimeoutError,
    ReferenceNotFoundError,
    RetrievalError,
    RetrievalToolMissingError,
)
from app.ingestion import retrieval
from app.ingestion.retrieval import (
    GitRetrievalError,
    GitRetriever,
    _remaining,
    git_binary_available,
    git_resolve_reference,
    select_retriever,
)
from app.ingestion.urls import parse_repository_url, validate_reference
from app.models.common import ReferenceType, RetrievalStrategy
from tests.support import FAKE_SHA, FAKE_SHA_MOVED, make_settings

IDENTITY = parse_repository_url("https://github.com/psf/requests").identity
SUBCOMMAND_INDEX = 1 + 2 * len(retrieval._HARDENED_GIT_CONFIG)


class FakeGit:
    """Records git invocations and returns canned results per sub-command."""

    def __init__(self, handler=None) -> None:
        self.handler = handler
        self.calls: list[dict] = []

    def __call__(self, command, *, check, **kwargs):
        operation = command[SUBCOMMAND_INDEX] if len(command) > SUBCOMMAND_INDEX else ""
        record = {"command": list(command), "operation": operation, "kwargs": kwargs, "check": check}
        self.calls.append(record)
        if self.handler is None:
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")
        result = self.handler(record)
        if isinstance(result, Exception):
            raise result
        return result

    def operations(self) -> list[str]:
        return [call["operation"] for call in self.calls]

    def command_for(self, operation: str) -> list[str]:
        matches = [call["command"] for call in self.calls if call["operation"] == operation]
        assert matches, f"no {operation} call recorded: {self.operations()}"
        return matches[0]


def ok(record, *, stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(record["command"], 0, stdout=stdout, stderr=stderr)


def fail(record, code: int = 128, *, stderr: str = "fatal: bad thing") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(record["command"], code, stdout="", stderr=stderr)


# ---------------------------------------------------------------------------
# Hardened git invocation
# ---------------------------------------------------------------------------
def test_run_git_builds_a_hardened_non_interactive_command(tmp_path: Path, monkeypatch) -> None:
    fake = FakeGit()
    monkeypatch.setattr(retrieval.subprocess, "run", fake)
    settings = make_settings()

    completed = retrieval._run_git(["version"], settings=settings, workdir=tmp_path, timeout=5.0)
    assert completed.returncode == 0

    command = fake.command_for("version")
    assert command[0] == settings.git_binary
    for key, value in retrieval._HARDENED_GIT_CONFIG:
        assert f"{key}={value}" in command
    assert command[SUBCOMMAND_INDEX] == "version"

    kwargs = fake.calls[0]["kwargs"]
    assert kwargs["shell"] is False
    assert kwargs["timeout"] == 5.0
    assert str(kwargs["cwd"]) == str(tmp_path)
    assert kwargs["capture_output"] is True

    env = kwargs["env"]
    assert env["GIT_TERMINAL_PROMPT"] == "0"
    assert env["GIT_CONFIG_NOSYSTEM"] == "1"
    assert env["GIT_LFS_SKIP_SMUDGE"] == "1"
    assert env["GIT_CONFIG_COUNT"] == "0"
    assert Path(env["GIT_CONFIG_GLOBAL"]).exists()
    assert Path(env["GIT_CONFIG_GLOBAL"]).read_text(encoding="utf-8") == ""
    assert Path(env["HOME"]) == tmp_path / ".git-home"
    # No credentials are ever handed to git.
    for key in ("GITHUB_TOKEN", "GH_TOKEN", "AWS_SECRET_ACCESS_KEY", "GIT_ASKPASS_PASSWORD"):
        assert key not in env


def test_git_env_keeps_the_os_environment_but_drops_credentials(tmp_path: Path, monkeypatch) -> None:
    # Git's transport needs a complete base environment: without PATH/SystemRoot
    # it fails with "getaddrinfo() thread failed to start" on Windows.
    monkeypatch.setenv("GITHUB_TOKEN", "leak-me")
    monkeypatch.setenv("SOMETHING_SECRET", "leak-me-too")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIAEXAMPLE")
    monkeypatch.setenv("SSH_AUTH_SOCK", str(tmp_path / "agent.sock"))
    monkeypatch.setenv("GIT_DIR", str(tmp_path / "elsewhere"))
    monkeypatch.setenv("GIT_SSH_COMMAND", "ssh -o StrictHostKeyChecking=no")
    monkeypatch.setenv("GCM_INTERACTIVE", "always")

    env = retrieval._git_env(tmp_path)

    for key in (
        "GITHUB_TOKEN",
        "SOMETHING_SECRET",
        "AWS_ACCESS_KEY_ID",
        "SSH_AUTH_SOCK",
        "GIT_DIR",
        "GIT_SSH_COMMAND",
    ):
        assert key not in env, f"{key} must never reach a git subprocess"
    # The user's value is replaced, not inherited.
    assert env["GCM_INTERACTIVE"] == "never"
    # Windows environment keys are case-insensitive: compare case-folded.
    lowered = {key.lower(): value for key, value in env.items()}
    assert lowered["path"] == os.environ["PATH"]
    if os.name == "nt":
        assert lowered["systemroot"] == os.environ["SystemRoot"]
    assert env["GIT_TERMINAL_PROMPT"] == "0"


def test_run_git_failure_is_a_typed_error(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(retrieval.subprocess, "run", FakeGit(lambda record: fail(record, stderr="fatal: nope")))
    with pytest.raises(GitRetrievalError) as excinfo:
        retrieval._run_git(["fetch"], settings=make_settings(), workdir=tmp_path, timeout=5.0)
    assert excinfo.value.details["exit_code"] == 128
    assert "fatal: nope" in excinfo.value.details["stderr"]


def test_run_git_allow_failure_returns_the_result(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(retrieval.subprocess, "run", FakeGit(lambda record: fail(record, code=2)))
    completed = retrieval._run_git(
        ["rev-parse", "HEAD"], settings=make_settings(), workdir=tmp_path, timeout=5.0, allow_failure=True
    )
    assert completed.returncode == 2


def test_run_git_timeout_and_missing_binary(tmp_path: Path, monkeypatch) -> None:
    def timeout(record):
        raise subprocess.TimeoutExpired(record["command"], 5.0)

    monkeypatch.setattr(retrieval.subprocess, "run", FakeGit(timeout))
    with pytest.raises(DownloadTimeoutError) as excinfo:
        retrieval._run_git(["fetch"], settings=make_settings(), workdir=tmp_path, timeout=5.0)
    assert excinfo.value.retryable is True

    def missing(record):
        raise FileNotFoundError("git")

    monkeypatch.setattr(retrieval.subprocess, "run", FakeGit(missing))
    with pytest.raises(RetrievalToolMissingError):
        retrieval._run_git(["fetch"], settings=make_settings(), workdir=tmp_path, timeout=5.0)


def test_remaining_budget_uses_the_deadline() -> None:
    assert _remaining(None, 10.0) == 10.0
    assert _remaining(time.monotonic() + 30.0, 10.0) == 10.0
    assert _remaining(time.monotonic() + 4.0, 10.0) <= 4.0
    with pytest.raises(DownloadTimeoutError):
        _remaining(time.monotonic() + 0.2, 10.0)
    with pytest.raises(DownloadTimeoutError):
        _remaining(time.monotonic() - 5.0, 10.0)


def test_git_binary_availability() -> None:
    import shutil

    assert git_binary_available(make_settings(git_binary="definitely-not-a-real-binary-xyz")) is False
    if shutil.which("git"):
        assert git_binary_available(make_settings()) is True


# ---------------------------------------------------------------------------
# ls-remote reference resolution
# ---------------------------------------------------------------------------
def ls_remote_handler(stdout: str, *, returncode: int = 0):
    def handler(record):
        return subprocess.CompletedProcess(record["command"], returncode, stdout=stdout, stderr="")

    return handler


LS_REMOTE_OUTPUT = (
    f"{FAKE_SHA}\tHEAD\n"
    f"{FAKE_SHA}\trefs/heads/main\n"
    f"{'d' * 40}\trefs/heads/develop\n"
    f"{'e' * 40}\trefs/tags/v1.0.0\n"
    f"{'f' * 40}\trefs/tags/v2.0.0\n"
    f"{'a' * 40}\trefs/tags/v2.0.0^{{}}\n"
)


def test_ls_remote_resolves_the_default_branch(tmp_path: Path, monkeypatch) -> None:
    fake = FakeGit(ls_remote_handler(LS_REMOTE_OUTPUT))
    monkeypatch.setattr(retrieval.subprocess, "run", fake)
    sha, ref_type, default_branch = git_resolve_reference(
        IDENTITY, settings=make_settings(), workdir=tmp_path, reference=None, timeout=10.0
    )
    assert (sha, ref_type, default_branch) == (FAKE_SHA, ReferenceType.DEFAULT_BRANCH, "main")
    command = fake.command_for("ls-remote")
    assert command[SUBCOMMAND_INDEX : SUBCOMMAND_INDEX + 3] == ["ls-remote", "--exit-code", IDENTITY.clone_url]


def test_ls_remote_resolves_branches_tags_and_short_shas(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(retrieval.subprocess, "run", FakeGit(ls_remote_handler(LS_REMOTE_OUTPUT)))
    settings = make_settings()

    sha, ref_type, _ = git_resolve_reference(
        IDENTITY, settings=settings, workdir=tmp_path, reference=validate_reference("develop"), timeout=10.0
    )
    assert (sha, ref_type) == ("d" * 40, ReferenceType.BRANCH)

    # Annotated tags resolve to the dereferenced commit.
    sha, ref_type, _ = git_resolve_reference(
        IDENTITY, settings=settings, workdir=tmp_path, reference=validate_reference("v2.0.0"), timeout=10.0
    )
    assert (sha, ref_type) == ("a" * 40, ReferenceType.TAG)

    sha, ref_type, _ = git_resolve_reference(
        IDENTITY, settings=settings, workdir=tmp_path, reference=validate_reference("eeeeeee"), timeout=10.0
    )
    assert (sha, ref_type) == ("e" * 40, ReferenceType.COMMIT)


def test_ls_remote_missing_reference_is_reported(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(retrieval.subprocess, "run", FakeGit(ls_remote_handler(LS_REMOTE_OUTPUT)))
    with pytest.raises(ReferenceNotFoundError) as excinfo:
        git_resolve_reference(
            IDENTITY,
            settings=make_settings(),
            workdir=tmp_path,
            reference=validate_reference("nope"),
            timeout=10.0,
        )
    assert excinfo.value.details["ref"] == "nope"


def test_ls_remote_empty_repository(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(retrieval.subprocess, "run", FakeGit(ls_remote_handler("", returncode=2)))
    with pytest.raises(RetrievalError, match="no commits"):
        git_resolve_reference(IDENTITY, settings=make_settings(), workdir=tmp_path, reference=None, timeout=10.0)


def test_ls_remote_ambiguous_default_branch(tmp_path: Path, monkeypatch) -> None:
    output = f"{FAKE_SHA}\tHEAD\n{'c' * 40}\trefs/heads/main\n"
    monkeypatch.setattr(retrieval.subprocess, "run", FakeGit(ls_remote_handler(output)))
    with pytest.raises(RetrievalError, match="default branch"):
        git_resolve_reference(IDENTITY, settings=make_settings(), workdir=tmp_path, reference=None, timeout=10.0)


def test_ls_remote_hard_failure_is_a_git_error(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(retrieval.subprocess, "run", FakeGit(ls_remote_handler("", returncode=128)))
    with pytest.raises(GitRetrievalError):
        git_resolve_reference(IDENTITY, settings=make_settings(), workdir=tmp_path, reference=None, timeout=10.0)


# ---------------------------------------------------------------------------
# GitRetriever
# ---------------------------------------------------------------------------
def test_git_retriever_fetches_the_exact_sha(tmp_path: Path, monkeypatch) -> None:
    checkout = tmp_path / "repo"

    def handler(record):
        if record["operation"] == "checkout":
            (checkout / ".git").mkdir(parents=True, exist_ok=True)
            (checkout / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
            (checkout / "README.md").write_text("hello\n", encoding="utf-8")
            (checkout / "pyproject.toml").write_text("[project]\n", encoding="utf-8")
            return ok(record)
        if record["operation"] == "rev-parse":
            return ok(record, stdout=f"{FAKE_SHA}\n")
        if record["operation"] == "log":
            return ok(record, stdout="Commit subject\x00Jane Dev\n")
        return ok(record)

    fake = FakeGit(handler)
    monkeypatch.setattr(retrieval.subprocess, "run", fake)

    report = GitRetriever(make_settings()).retrieve(
        identity=IDENTITY,
        commit_sha=FAKE_SHA,
        reference=None,
        reference_type=ReferenceType.DEFAULT_BRANCH,
        workdir=tmp_path,
    )

    assert fake.operations() == ["init", "remote", "fetch", "checkout", "rev-parse", "log"]
    fetch = fake.command_for("fetch")
    assert fetch[SUBCOMMAND_INDEX:] == ["fetch", "--quiet", "--depth", "1", "--no-tags", "origin", FAKE_SHA]
    remote_add = fake.command_for("remote")
    assert remote_add[SUBCOMMAND_INDEX : SUBCOMMAND_INDEX + 2] == ["remote", "add"]

    assert report.strategy is RetrievalStrategy.GIT
    assert report.repository_root == checkout
    assert report.commit_sha == FAKE_SHA
    assert report.commit_sha_verified is True
    assert report.commit_message == "Commit subject"
    assert report.commit_author == "Jane Dev"
    assert report.warnings == ()
    assert report.files_written == 2
    expected_bytes = (checkout / "README.md").stat().st_size + (checkout / "pyproject.toml").stat().st_size
    assert report.bytes_written == expected_bytes
    # The .git directory never survives retrieval.
    assert not (checkout / ".git").exists()
    # No credential material appears anywhere in the recorded commands.
    for call in fake.calls:
        assert not any("token" in argument.lower() for argument in call["command"])


def test_git_retriever_falls_back_to_a_shallow_clone_and_reports_a_moved_ref(tmp_path: Path, monkeypatch) -> None:
    checkout = tmp_path / "repo"

    def handler(record):
        if record["operation"] == "fetch":
            return fail(record, stderr="fatal: couldn't find remote ref")
        if record["operation"] == "clone":
            target = Path(record["command"][-1])
            (target / "README.md").write_text("hello\n", encoding="utf-8")
            return ok(record)
        if record["operation"] == "rev-parse":
            return ok(record, stdout=f"{FAKE_SHA_MOVED}\n")
        if record["operation"] == "log":
            return ok(record, stdout="Moved\x00Author\n")
        return ok(record)

    fake = FakeGit(handler)
    monkeypatch.setattr(retrieval.subprocess, "run", fake)

    report = GitRetriever(make_settings()).retrieve(
        identity=IDENTITY,
        commit_sha=FAKE_SHA,
        reference=validate_reference("main"),
        reference_type=ReferenceType.BRANCH,
        workdir=tmp_path,
    )

    assert fake.operations() == ["init", "remote", "fetch", "clone", "rev-parse", "log"]
    clone = fake.command_for("clone")
    assert clone[SUBCOMMAND_INDEX:] == [
        "clone",
        "--quiet",
        "--depth",
        "1",
        "--single-branch",
        "--no-tags",
        "--branch",
        "main",
        "--",
        IDENTITY.clone_url,
        str(checkout),
    ]
    assert report.commit_sha == FAKE_SHA_MOVED
    assert len(report.warnings) == 1
    warning = report.warnings[0]
    assert warning.code.value == "branch_moved_during_retrieval"
    assert warning.details == {"resolved_sha": FAKE_SHA, "checked_out_sha": FAKE_SHA_MOVED}


def test_git_retriever_without_a_reference_does_not_fall_back(tmp_path: Path, monkeypatch) -> None:
    def handler(record):
        if record["operation"] == "fetch":
            return fail(record)
        return ok(record)

    fake = FakeGit(handler)
    monkeypatch.setattr(retrieval.subprocess, "run", fake)
    with pytest.raises(GitRetrievalError):
        GitRetriever(make_settings()).retrieve(
            identity=IDENTITY,
            commit_sha=FAKE_SHA,
            reference=None,
            reference_type=ReferenceType.DEFAULT_BRANCH,
            workdir=tmp_path,
        )
    assert fake.operations() == ["init", "remote", "fetch"]


def test_git_retriever_rejects_a_commit_sha_mismatch(tmp_path: Path, monkeypatch) -> None:
    def handler(record):
        if record["operation"] == "rev-parse":
            return ok(record, stdout=f"{FAKE_SHA_MOVED}\n")
        return ok(record)

    monkeypatch.setattr(retrieval.subprocess, "run", FakeGit(handler))
    with pytest.raises(GitRetrievalError, match="does not match"):
        GitRetriever(make_settings()).retrieve(
            identity=IDENTITY,
            commit_sha=FAKE_SHA,
            reference=validate_reference(FAKE_SHA),
            reference_type=ReferenceType.COMMIT,
            workdir=tmp_path,
        )


def test_git_retriever_requires_a_resolvable_head(tmp_path: Path, monkeypatch) -> None:
    def handler(record):
        if record["operation"] == "rev-parse":
            return fail(record, code=1)
        return ok(record)

    monkeypatch.setattr(retrieval.subprocess, "run", FakeGit(handler))
    with pytest.raises(GitRetrievalError, match="checked out commit"):
        GitRetriever(make_settings()).retrieve(
            identity=IDENTITY,
            commit_sha=FAKE_SHA,
            reference=None,
            reference_type=ReferenceType.DEFAULT_BRANCH,
            workdir=tmp_path,
        )


# ---------------------------------------------------------------------------
# Retriever selection
# ---------------------------------------------------------------------------
def test_select_retriever_respects_configuration(monkeypatch) -> None:
    monkeypatch.setattr(retrieval, "git_binary_available", lambda settings: True)
    assert isinstance(select_retriever(make_settings(retrieval_strategy="auto")), GitRetriever)
    assert isinstance(select_retriever(make_settings(retrieval_strategy="git")), GitRetriever)
    assert isinstance(select_retriever(make_settings(retrieval_strategy="archive")), retrieval.ArchiveRetriever)

    monkeypatch.setattr(retrieval, "git_binary_available", lambda settings: False)
    assert isinstance(select_retriever(make_settings(retrieval_strategy="auto")), retrieval.ArchiveRetriever)
    assert isinstance(select_retriever(make_settings(retrieval_strategy="archive")), retrieval.ArchiveRetriever)
    with pytest.raises(RetrievalToolMissingError):
        select_retriever(make_settings(retrieval_strategy="git"))
