"""Filesystem and archive safety tests.

The analysed repository is untrusted: these tests feed hostile paths, hostile
archives and unreadable files into the safety helpers and assert that nothing
escapes the extraction root, nothing is executed and nothing raises raw OS
errors.
"""

from __future__ import annotations

import io
import os
import stat
import tarfile

import pytest

from app.core.errors import RepositoryTooLargeError, UnsafeRepositoryContentError
from app.ingestion.safety import (
    extract_tar_safely,
    file_sha256,
    is_unsafe_component,
    is_within,
    read_text_file,
    redact_url,
    remove_tree,
    safe_join,
    validate_relative_path,
)
from tests.support import (
    device_member,
    file_member,
    hardlink_member,
    make_tar_gz,
    make_tar_gz_members,
    symlink_member,
)


# ---------------------------------------------------------------------------
# validate_relative_path
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("setup.py", "setup.py"),
        ("a/b/c.txt", "a/b/c.txt"),
        ("a\\b\\c.txt", "a/b/c.txt"),
        ("./a/./b.txt", "a/b.txt"),
        ("a//b.txt", "a/b.txt"),
    ],
)
def test_relative_paths_are_normalised(raw: str, expected: str) -> None:
    assert validate_relative_path(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "   ",
        "/etc/passwd",
        "//server/share/file",
        "C:/Windows/system32",
        "c:\\windows\\system32",
        "../outside.txt",
        "a/../../outside.txt",
        "a/b/../../../outside.txt",
        "bad\x00name.txt",
        "bad\nname.txt",
    ],
)
def test_unsafe_relative_paths_are_rejected(raw: str) -> None:
    with pytest.raises(UnsafeRepositoryContentError):
        validate_relative_path(raw)


def test_validate_relative_path_rejects_non_strings() -> None:
    with pytest.raises(UnsafeRepositoryContentError):
        validate_relative_path(None)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("component", "unsafe"),
    [
        ("CON", True),
        ("con", True),
        ("aux.txt", True),
        ("COM3", True),
        ("lpt9.log", True),
        ("trailing.", True),
        ("trailing ", True),
        ("has:colon", True),
        ("normal.py", False),
        ("conftest.py", False),
        ("console.py", False),
        ("auxiliary.py", False),
    ],
)
def test_windows_reserved_names_are_detected(component: str, unsafe: bool) -> None:
    assert is_unsafe_component(component) is unsafe


def test_is_within_and_safe_join(tmp_path) -> None:
    inside = tmp_path / "root" / "a" / "b.txt"
    inside.parent.mkdir(parents=True)
    inside.write_text("x", encoding="utf-8")
    assert is_within(inside, tmp_path / "root") is True
    assert is_within(tmp_path / "root", tmp_path / "root") is True
    assert is_within(tmp_path / "other", tmp_path / "root") is False
    assert safe_join(tmp_path / "root", "a/b.txt") == inside.resolve()
    with pytest.raises(UnsafeRepositoryContentError):
        safe_join(tmp_path / "root", "../escape.txt")


# ---------------------------------------------------------------------------
# Archive extraction
# ---------------------------------------------------------------------------
def test_archive_is_extracted_and_wrapper_directory_stripped(tmp_path) -> None:
    archive = tmp_path / "repo.tar.gz"
    archive.write_bytes(
        make_tar_gz(
            {"pyproject.toml": "[project]\n", "src/pkg/requirements.txt": "requests\n"},
            wrapper="psf-requests-abc123",
        )
    )
    report = extract_tar_safely(
        archive,
        tmp_path / "out",
        max_members=100,
        max_total_bytes=10_000,
    )
    assert report.files_written == 2
    assert report.stripped_root == "psf-requests-abc123"
    assert (tmp_path / "out" / "pyproject.toml").read_text(encoding="utf-8") == "[project]\n"
    assert (tmp_path / "out" / "src" / "pkg" / "requirements.txt").is_file()


def test_wrapper_root_is_stripped_when_the_directory_entry_is_present(tmp_path) -> None:
    # Real codeload tarballs contain the wrapper root as an explicit directory
    # member; that must not be mistaken for a top-level file.
    root_entry = tarfile.TarInfo("psf-requests-abc123")
    root_entry.type = tarfile.DIRTYPE
    root_entry.mode = 0o755
    archive = tmp_path / "github.tar.gz"
    archive.write_bytes(
        make_tar_gz_members(
            [
                (root_entry, None),
                file_member("psf-requests-abc123/requirements.txt", b"requests\n"),
            ]
        )
    )
    report = extract_tar_safely(archive, tmp_path / "out", max_members=100, max_total_bytes=10_000)
    assert report.stripped_root == "psf-requests-abc123"
    assert (tmp_path / "out" / "requirements.txt").read_bytes() == b"requests\n"


def test_top_level_files_prevent_root_stripping(tmp_path) -> None:
    archive = tmp_path / "flat.tar.gz"
    archive.write_bytes(
        make_tar_gz_members(
            [
                file_member("README.md", b"# hi\n"),
                file_member("pkg/requirements.txt", b"requests\n"),
            ]
        )
    )
    report = extract_tar_safely(archive, tmp_path / "out", max_members=100, max_total_bytes=10_000)
    assert report.stripped_root is None
    assert (tmp_path / "out" / "README.md").is_file()
    assert (tmp_path / "out" / "pkg" / "requirements.txt").is_file()


@pytest.mark.parametrize("member_name", ["../escape.txt", "/absolute.txt", "a/../../escape.txt", "C:/escape.txt"])
def test_escaping_members_abort_extraction(tmp_path, member_name: str) -> None:
    archive = tmp_path / "evil.tar.gz"
    archive.write_bytes(make_tar_gz_members([file_member(member_name)]))
    with pytest.raises(UnsafeRepositoryContentError):
        extract_tar_safely(archive, tmp_path / "out", max_members=100, max_total_bytes=10_000)
    assert not (tmp_path / "escape.txt").exists()


def test_symlink_escaping_the_root_aborts_extraction(tmp_path) -> None:
    archive = tmp_path / "evil.tar.gz"
    archive.write_bytes(make_tar_gz_members([symlink_member("repo/link", "../../outside")]))
    with pytest.raises(UnsafeRepositoryContentError):
        extract_tar_safely(archive, tmp_path / "out", max_members=100, max_total_bytes=10_000)


def test_symlinks_are_never_materialised(tmp_path) -> None:
    archive = tmp_path / "links.tar.gz"
    archive.write_bytes(
        make_tar_gz_members(
            [
                file_member("repo/target.txt", b"payload"),
                symlink_member("repo/link.txt", "target.txt"),
                hardlink_member("repo/hard.txt", "repo/target.txt"),
                file_member("repo/kept.txt", b"kept"),
            ]
        )
    )
    out = tmp_path / "out"
    report = extract_tar_safely(archive, out, max_members=100, max_total_bytes=10_000)
    assert report.files_written == 2
    assert report.symlinks_skipped == 2
    assert not (out / "link.txt").exists()
    assert not (out / "hard.txt").exists()
    assert (out / "target.txt").read_bytes() == b"payload"


def test_hardlink_pointing_outside_the_archive_root_aborts(tmp_path) -> None:
    archive = tmp_path / "evil.tar.gz"
    archive.write_bytes(
        make_tar_gz_members(
            [
                file_member("repo/inside.txt", b"data"),
                hardlink_member("repo/hard.txt", "elsewhere/inside.txt"),
            ]
        )
    )
    with pytest.raises(UnsafeRepositoryContentError):
        extract_tar_safely(archive, tmp_path / "out", max_members=100, max_total_bytes=10_000)


def test_device_nodes_are_skipped(tmp_path) -> None:
    archive = tmp_path / "devices.tar.gz"
    archive.write_bytes(make_tar_gz_members([file_member("repo/ok.txt", b"ok"), device_member("repo/sda")]))
    report = extract_tar_safely(archive, tmp_path / "out", max_members=100, max_total_bytes=10_000)
    assert report.files_written == 1
    assert report.non_regular_skipped == 1
    assert not (tmp_path / "out" / "sda").exists()


def test_windows_unsafe_member_names_are_skipped_not_rewritten(tmp_path) -> None:
    archive = tmp_path / "names.tar.gz"
    archive.write_bytes(
        make_tar_gz_members(
            [
                file_member("repo/normal.txt", b"ok"),
                file_member("repo/CON", b"reserved"),
                file_member("repo/bad:name.txt", b"colon"),
            ]
        )
    )
    report = extract_tar_safely(archive, tmp_path / "out", max_members=100, max_total_bytes=10_000)
    assert report.files_written == 1
    assert report.unsafe_names_skipped == 2
    assert report.skipped_names == ["CON", "bad:name.txt"]


def test_member_limit_is_enforced(tmp_path) -> None:
    archive = tmp_path / "many.tar.gz"
    members = [file_member(f"repo/file-{index}.txt", b"x") for index in range(5)]
    archive.write_bytes(make_tar_gz_members(members))
    with pytest.raises(RepositoryTooLargeError):
        extract_tar_safely(archive, tmp_path / "out", max_members=4, max_total_bytes=10_000)


def test_total_size_limit_is_enforced(tmp_path) -> None:
    archive = tmp_path / "big.tar.gz"
    archive.write_bytes(make_tar_gz_members([file_member("repo/a.bin", b"a" * 1000)]))
    with pytest.raises(RepositoryTooLargeError):
        extract_tar_safely(archive, tmp_path / "out", max_members=100, max_total_bytes=100)


def test_max_file_size_skips_the_file(tmp_path) -> None:
    archive = tmp_path / "files.tar.gz"
    archive.write_bytes(
        make_tar_gz_members([file_member("repo/small.txt", b"x"), file_member("repo/big.bin", b"y" * 100)])
    )
    report = extract_tar_safely(
        archive,
        tmp_path / "out",
        max_members=100,
        max_total_bytes=10_000,
        max_file_bytes=10,
    )
    assert report.files_written == 1
    assert report.oversized_skipped == 1
    assert not (tmp_path / "out" / "big.bin").exists()


def test_corrupt_archive_is_reported_not_crashed(tmp_path) -> None:
    archive = tmp_path / "corrupt.tar.gz"
    archive.write_bytes(b"this is definitely not a tar archive")
    with pytest.raises(UnsafeRepositoryContentError):
        extract_tar_safely(archive, tmp_path / "out", max_members=10, max_total_bytes=100)


def test_uncompressed_archive_is_accepted(tmp_path) -> None:
    inner = tmp_path / "plain.tar"
    with tarfile.open(inner, "w") as tar:
        info, payload = file_member("repo/a.txt", b"hello")
        tar.addfile(info, io.BytesIO(payload))
    report = extract_tar_safely(inner, tmp_path / "out", max_members=10, max_total_bytes=1000)
    assert report.files_written == 1
    assert (tmp_path / "out" / "a.txt").read_bytes() == b"hello"


# ---------------------------------------------------------------------------
# Text reading, hashing, redaction, removal
# ---------------------------------------------------------------------------
def test_read_text_file_handles_binary_and_oversized_content(tmp_path) -> None:
    binary = tmp_path / "binary.txt"
    binary.write_bytes(b"PK\x03\x04\x00\x00")
    assert read_text_file(binary, max_bytes=100).skip_reason == "binary"
    assert read_text_file(binary, max_bytes=100).text is None

    big = tmp_path / "big.txt"
    big.write_text("x" * 100, encoding="utf-8")
    oversized = read_text_file(big, max_bytes=10)
    assert oversized.skip_reason == "too_large"
    assert oversized.text is None
    assert oversized.size_bytes == 100


def test_read_text_file_falls_back_to_latin1_with_a_reason(tmp_path) -> None:
    path = tmp_path / "cp1252.txt"
    path.write_bytes("caf\xe9".encode("latin-1"))
    read = read_text_file(path, max_bytes=100)
    assert read.skip_reason == "not_utf8"
    assert read.text == "café"


def test_read_text_file_reports_missing_files(tmp_path) -> None:
    missing = read_text_file(tmp_path / "nope.txt", max_bytes=10)
    assert missing.skip_reason == "read_error"
    assert missing.text is None


def test_file_sha256_respects_the_size_cap(tmp_path) -> None:
    path = tmp_path / "file.txt"
    path.write_bytes(b"hello world")
    assert file_sha256(path) == "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    assert file_sha256(path, max_bytes=5) is None
    assert file_sha256(tmp_path / "missing.txt") is None


def test_redact_url_removes_credentials_and_secrets() -> None:
    assert redact_url("https://user:pass@github.com/psf/requests") == "https://github.com/psf/requests"
    assert redact_url("https://github.com/psf/requests?token=abc&tab=x") == "https://github.com/psf/requests?tab=x"
    assert redact_url("") == ""


def test_remove_tree_deletes_read_only_files(tmp_path) -> None:
    root = tmp_path / "tree"
    nested = root / "nested"
    nested.mkdir(parents=True)
    file = nested / "readonly.txt"
    file.write_text("keep", encoding="utf-8")
    os.chmod(file, stat.S_IREAD)
    try:
        remove_tree(root)
        assert not root.exists()
    finally:
        if root.exists():  # pragma: no cover - cleanup for other platforms
            os.chmod(file, stat.S_IWRITE)
            remove_tree(root)


def test_remove_tree_is_a_noop_for_missing_paths(tmp_path) -> None:
    remove_tree(tmp_path / "not-there")
