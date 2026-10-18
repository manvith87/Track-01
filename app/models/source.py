"""Source file metadata models."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from app.models.common import ManifestFormat, SupportLevel, UnsupportedManifestFormat


class SourceFile(BaseModel):
    """Metadata for a single file found in the repository working tree.

    Content is never stored here: Phase 1 reports provenance only.  ``sha256``
    is computed for dependency manifests (which are small) so that downstream
    phases can detect changed content cheaply.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    path: str = Field(description="Repository-relative POSIX path.")
    size_bytes: int = Field(ge=0)
    sha256: str | None = Field(default=None, description="SHA-256 of the file content for manifests.")
    manifest_format: ManifestFormat | None = Field(
        default=None, description="Detected format when this file is a supported dependency manifest."
    )
    unsupported_format: UnsupportedManifestFormat | None = Field(
        default=None, description="Detected but unsupported dependency file format."
    )
    support_level: SupportLevel | None = None
    skipped_reason: str | None = Field(default=None, description="Why the file was not parsed, when applicable.")


__all__ = ["SourceFile"]
