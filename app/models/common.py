"""Shared enumerations used across the ingestion domain."""

from __future__ import annotations

from enum import Enum


class Ecosystem(str, Enum):
    """Package ecosystem. Phase 1 supports PyPI only."""

    PYPI = "pypi"


class DependencyScope(str, Enum):
    """Why a dependency exists (as established by the declaring manifest)."""

    RUNTIME = "runtime"
    DEV = "dev"
    OPTIONAL = "optional"
    BUILD = "build"
    UNKNOWN = "unknown"


class DependencyRelation(str, Enum):
    """Whether the source establishes a direct or transitive relationship."""

    DIRECT = "direct"
    TRANSITIVE = "transitive"
    UNKNOWN = "unknown"


class ConstraintScheme(str, Enum):
    """Syntax of a version constraint.

    ``pep440`` constraints can be evaluated with :mod:`packaging`;
    ``poetry`` constraints (``^1.2``, ``~1.2``, ``||``) cannot and are
    preserved verbatim instead of being guessed at.
    """

    PEP440 = "pep440"
    POETRY = "poetry"
    ANY = "any"
    UNKNOWN = "unknown"


class SourceKind(str, Enum):
    """Where a dependency is expected to be resolved from."""

    REGISTRY = "registry"
    GIT = "git"
    PATH = "path"
    URL = "url"
    EDITABLE = "editable"
    UNKNOWN = "unknown"


class ManifestFormat(str, Enum):
    """Dependency file formats that Phase 1 parses for real."""

    REQUIREMENTS_TXT = "requirements.txt"
    PYPROJECT_TOML = "pyproject.toml"
    POETRY_LOCK = "poetry.lock"
    UV_LOCK = "uv.lock"

    @property
    def is_lockfile(self) -> bool:
        return self in {ManifestFormat.POETRY_LOCK, ManifestFormat.UV_LOCK}


class UnsupportedManifestFormat(str, Enum):
    """Dependency-ish files that are detected but intentionally not parsed."""

    PIPFILE = "Pipfile"
    PIPFILE_LOCK = "Pipfile.lock"
    SETUP_PY = "setup.py"
    SETUP_CFG = "setup.cfg"
    ENVIRONMENT_YML = "environment.yml"
    ENVIRONMENT_YAML = "environment.yaml"
    CONDA_YML = "conda.yml"
    CONDA_YAML = "conda.yaml"
    REQUIREMENTS_IN = "requirements.in"
    PYPROJECT_INI = "pyproject.ini"


class SupportLevel(str, Enum):
    """How completely BlastRadius understands a dependency file."""

    SUPPORTED = "supported"
    PARTIAL = "partial"
    UNSUPPORTED = "unsupported"


class ManifestParseStatus(str, Enum):
    """Outcome of parsing a single manifest."""

    PARSED = "parsed"
    PARTIAL = "partial"
    FAILED = "failed"
    SKIPPED = "skipped"


class IngestionStatus(str, Enum):
    """Overall status of an ingestion run."""

    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"


class Severity(str, Enum):
    """Severity of an ingestion warning."""

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


class IngestionStage(str, Enum):
    """Pipeline stage, used for logging and error reporting."""

    VALIDATION = "validation"
    METADATA = "metadata"
    RETRIEVAL = "retrieval"
    DISCOVERY = "discovery"
    PARSING = "parsing"
    AGGREGATION = "aggregation"
    RESPONSE = "response"
    AGENT = "agent"
    ACTIONS = "actions"
    UNKNOWN = "unknown"


class RetrievalStrategy(str, Enum):
    """How repository content was obtained."""

    GIT = "git"
    ARCHIVE = "archive"


class ReferenceType(str, Enum):
    """What kind of Git reference was analysed."""

    DEFAULT_BRANCH = "default_branch"
    BRANCH = "branch"
    TAG = "tag"
    COMMIT = "commit"


class WarningCode(str, Enum):
    """Machine-readable warning taxonomy.

    The codes are stable and are intended to be consumed by later phases
    (for example to decide whether a finding is trustworthy).
    """

    # Retrieval / metadata
    METADATA_UNAVAILABLE = "metadata_unavailable"
    RATE_LIMIT_FALLBACK = "rate_limit_fallback"
    REF_RESOLVED_LOCALLY = "ref_resolved_locally"
    BRANCH_MOVED_DURING_RETRIEVAL = "branch_moved_during_retrieval"
    RETRIEVAL_FALLBACK = "retrieval_fallback"
    COMMIT_SHA_UNVERIFIED = "commit_sha_unverified"
    ARCHIVE_ROOT_DIR_UNEXPECTED = "archive_root_dir_unexpected"

    # Discovery
    EMPTY_REPOSITORY = "empty_repository"
    NO_MANIFESTS_FOUND = "no_manifests_found"
    UNSUPPORTED_FORMAT = "unsupported_format"
    MANIFEST_LIMIT_REACHED = "manifest_limit_reached"
    MANIFEST_TOO_LARGE = "manifest_too_large"
    MANIFEST_NOT_UTF8 = "manifest_not_utf8"
    TREE_TRUNCATED_FILE_LIMIT = "tree_truncated_file_limit"
    DIRECTORY_ENTRY_LIMIT_EXCEEDED = "directory_entry_limit_exceeded"
    SYMLINKS_SKIPPED = "symlinks_skipped"
    OVERSIZED_FILES_SKIPPED = "oversized_files_skipped"
    VIRTUALENV_DETECTED = "virtualenv_detected"
    SUBMODULES_NOT_FETCHED = "submodules_not_fetched"

    # Parsing
    MANIFEST_PARSE_ERROR = "manifest_parse_error"
    MALFORMED_ENTRY = "malformed_entry"
    EMPTY_MANIFEST = "empty_manifest"
    NO_DEPENDENCIES_FOUND = "no_dependencies_found"
    UNSUPPORTED_DEPENDENCY_SECTION = "unsupported_dependency_section"
    UNRESOLVED_VERSION = "unresolved_version"
    HASH_PINNED_REQUIREMENT = "hash_pinned_requirement"
    DIRECT_URL_REFERENCE = "direct_url_reference"
    EDITABLE_REFERENCE = "editable_reference"
    LOCAL_PATH_REQUIREMENT = "local_path_requirement"
    NESTED_REQUIREMENT_NOT_FOUND = "nested_requirement_not_found"
    NESTED_REQUIREMENT_CYCLE = "nested_requirement_cycle"
    REMOTE_REQUIREMENT_REFERENCE = "remote_requirement_reference"
    INCLUDE_DEPTH_EXCEEDED = "include_depth_exceeded"
    CONSTRAINT_FILE_REFERENCE = "constraint_file_reference"
    DEPENDENCY_GROUP_INCLUDE_RESOLVED = "dependency_group_include_resolved"
    DEPENDENCY_GROUP_INCLUDE_MISSING = "dependency_group_include_missing"
    DEPENDENCY_GROUP_CYCLE = "dependency_group_cycle"
    LOCKFILE_WITHOUT_MANIFEST = "lockfile_without_manifest"
    LOCKFILE_NO_DEV_MARKERS = "lockfile_no_dev_markers"

    # Aggregation / conflicts
    DIRECTNESS_UNKNOWN = "directness_unknown"
    RELATION_INFERRED = "relation_inferred"
    MULTIPLE_LOCKFILES = "multiple_lockfiles"
    CONFLICTING_EXACT_PINS = "conflicting_exact_pins"
    CONFLICTING_RESOLVED_VERSIONS = "conflicting_resolved_versions"
    PIN_RESOLVED_MISMATCH = "pin_resolved_mismatch"
    MULTIPLE_CONSTRAINTS_FOR_PACKAGE = "multiple_constraints_for_package"
    DEPENDENCY_LIMIT_REACHED = "dependency_limit_reached"
    WARNINGS_TRUNCATED = "warnings_truncated"


class ErrorCode(str, Enum):
    """Machine-readable error taxonomy."""

    # Input validation (4xx)
    INVALID_INPUT = "invalid_input"
    INVALID_REPOSITORY_URL = "invalid_repository_url"
    UNSUPPORTED_HOST = "unsupported_host"
    EMBEDDED_CREDENTIALS = "embedded_credentials"
    INVALID_REFERENCE = "invalid_reference"

    # Retrieval
    REPOSITORY_NOT_FOUND = "repository_not_found"
    REPOSITORY_ACCESS_DENIED = "repository_access_denied"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    REFERENCE_NOT_FOUND = "reference_not_found"
    DOWNLOAD_TIMEOUT = "download_timeout"
    INGESTION_TIMEOUT = "ingestion_timeout"
    REPOSITORY_TOO_LARGE = "repository_too_large"
    NETWORK_FAILURE = "network_failure"
    RETRIEVAL_FAILED = "retrieval_failed"
    RETRIEVAL_TOOL_MISSING = "retrieval_tool_missing"

    # Safety
    UNSAFE_PATH = "unsafe_path"
    UNSAFE_ARCHIVE_CONTENT = "unsafe_archive_content"
    ARCHIVE_EXTRACTION_FAILED = "archive_extraction_failed"

    # Local processing
    MANIFEST_READ_ERROR = "manifest_read_error"
    MANIFEST_PARSE_ERROR = "manifest_parse_error"
    INTERNAL_ERROR = "internal_error"

    # Upstream vulnerability intelligence (Phase 3)
    OSV_INVALID_RESPONSE = "osv_invalid_response"

    # Evidence-grounded agent (Phase 4B)
    AGENT_NOT_CONFIGURED = "agent_not_configured"
    AGENT_PROVIDER_ERROR = "agent_provider_error"
    AGENT_TIMEOUT = "agent_timeout"
    AGENT_MCP_UNAVAILABLE = "agent_mcp_unavailable"

    # Secure user-approved GitHub actions (Phase 6)
    GITHUB_WRITE_DISABLED = "github_write_disabled"
    ACTION_NOT_CONFIGURED = "action_not_configured"
    ACTION_AUTHORIZATION_NOT_CONFIGURED = "action_authorization_not_configured"
    ACTION_UNAUTHORIZED = "action_unauthorized"
    ACTION_NOT_FOUND = "action_not_found"
    ACTION_EXPIRED = "action_expired"
    ACTION_CONSUMED = "action_consumed"
    ACTION_IN_PROGRESS = "action_in_progress"
    ACTION_PAYLOAD_MISMATCH = "action_payload_mismatch"
    ACTION_EVIDENCE_CHANGED = "action_evidence_changed"
    ACTION_REPOSITORY_INVALID = "action_repository_invalid"
    ACTION_REPOSITORY_NOT_ALLOWED = "action_repository_not_allowed"
    ACTION_STORE_ERROR = "action_store_error"
    GITHUB_CREDENTIALS_INVALID = "github_credentials_invalid"
    GITHUB_PERMISSION_DENIED = "github_permission_denied"
    GITHUB_ISSUES_DISABLED = "github_issues_disabled"
    GITHUB_ISSUE_CREATION_FAILED = "github_issue_creation_failed"
    GITHUB_WRITE_AMBIGUOUS = "github_write_ambiguous"


__all__ = [
    "ConstraintScheme",
    "DependencyRelation",
    "DependencyScope",
    "Ecosystem",
    "ErrorCode",
    "IngestionStage",
    "IngestionStatus",
    "ManifestFormat",
    "ManifestParseStatus",
    "ReferenceType",
    "RetrievalStrategy",
    "Severity",
    "SourceKind",
    "SupportLevel",
    "UnsupportedManifestFormat",
    "WarningCode",
]
