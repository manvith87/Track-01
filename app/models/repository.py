"""Repository identity, reference and metadata models."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.models.common import ReferenceType


class RepositoryIdentity(BaseModel):
    """Canonical identity of a public GitHub repository.

    ``canonical_id`` is the stable key that Phase 2 uses to associate every
    record with a repository: ``github.com/<owner>/<repo>`` (lower-cased).
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    host: str = Field(default="github.com", description="Repository host (only github.com is supported).")
    owner: str = Field(description="Repository owner / organisation login, as provided.")
    name: str = Field(description="Repository name, as provided.")
    canonical_id: str = Field(description="Stable identity, e.g. 'github.com/psf/requests'.")
    canonical_url: str = Field(description="Canonical HTTPS repository URL.")
    clone_url: str = Field(description="HTTPS URL used for read-only clones.")
    api_url: str = Field(description="GitHub REST API URL for the repository.")

    @property
    def full_name(self) -> str:
        return f"{self.owner}/{self.name}"


class RepositoryCommit(BaseModel):
    """Metadata about the exact commit that was analysed."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    sha: str = Field(description="Full 40 character commit SHA.")
    short_sha: str = Field(description="Abbreviated SHA (12 characters).")
    message: str | None = Field(default=None, description="First line of the commit message, truncated.")
    author_name: str | None = Field(default=None, description="Commit author name reported by the source.")
    committed_at: datetime | None = Field(default=None, description="Commit timestamp (UTC) when available.")
    source: str = Field(default="unknown", description="Where the commit metadata came from (github_api, git, ...).")


class RepositoryReference(BaseModel):
    """The requested reference and how it was resolved."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    requested_ref: str | None = Field(default=None, description="Reference as supplied by the caller (None = default branch).")
    ref_type: ReferenceType = Field(description="Branch, tag, commit or default branch.")
    resolved_commit_sha: str = Field(description="Exact commit SHA whose tree was analysed.")
    default_branch: str | None = Field(default=None, description="Default branch reported by the host, when known.")
    resolved_via: str = Field(description="How the SHA was resolved: github_api, git_ls_remote or provided_commit_sha.")
    is_default_branch: bool = Field(default=False, description="True when the default branch was analysed.")
    sha_verified: bool = Field(
        default=False,
        description="True when the SHA was independently confirmed against the retrieved working tree.",
    )


class RepositoryMetadata(BaseModel):
    """Repository level metadata returned by the host (best effort)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    identity: RepositoryIdentity
    commit: RepositoryCommit
    reference: RepositoryReference
    description: str | None = None
    default_branch: str | None = None
    is_private: bool = Field(default=False, description="Always False for Phase 1: public repositories only.")
    is_archived: bool = False
    is_fork: bool = False
    stars: int | None = None
    forks: int | None = None
    open_issues: int | None = None
    size_kb: int | None = Field(default=None, description="Repository size reported by the host, in KiB.")
    license_spdx_id: str | None = None
    primary_language: str | None = None
    pushed_at: datetime | None = None
    created_at: datetime | None = None
    metadata_source: str = Field(
        default="unavailable",
        description="github_api when live metadata was retrieved, unavailable when it could not be fetched.",
    )


__all__ = ["RepositoryCommit", "RepositoryIdentity", "RepositoryMetadata", "RepositoryReference"]
