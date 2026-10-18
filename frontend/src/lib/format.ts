/**
 * Presentation helpers. These only format values the backend reported —
 * nothing here computes risk, reachability or compatibility.
 */

import type { ResponseTruncation, SeverityEvidence } from "../api/generated";

export function shortSha(sha?: string | null, length = 12): string {
  if (!sha) return "—";
  return sha.slice(0, length);
}

export function formatDateTime(value?: string | null): string {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function formatNumber(value?: number | null): string {
  if (value === undefined || value === null) return "—";
  return value.toLocaleString();
}

export function formatScore(value?: number | null): string {
  if (value === undefined || value === null) return "—";
  return Number.isInteger(value) ? String(value) : value.toFixed(2);
}

export function formatDurationMs(value?: number | null): string {
  if (value === undefined || value === null) return "—";
  if (value < 1000) return `${Math.round(value)} ms`;
  const seconds = value / 1000;
  if (seconds < 60) return `${seconds.toFixed(1)} s`;
  const minutes = Math.floor(seconds / 60);
  const rest = Math.round(seconds % 60);
  return `${minutes} min ${rest} s`;
}

const TRUNCATION_LABELS: Array<[keyof ResponseTruncation, string]> = [
  ["source_files", "examined files"],
  ["manifests", "manifests"],
  ["declarations", "declarations"],
  ["resolved_packages", "resolved packages"],
  ["dependency_edges", "dependency edges"],
  ["warnings", "warnings"],
  ["errors", "errors"],
];

/** Human-readable notes for every collection the server bounded for transport. */
export function truncationNotes(truncated?: ResponseTruncation | null): string[] {
  if (!truncated) return [];
  return TRUNCATION_LABELS.filter(([key]) => truncated[key]).map(([, label]) => `${label} truncated`);
}

/**
 * Verbatim severity label from the advisory's own evidence.
 * The UI never derives a severity level of its own.
 */
export function severityLabel(severity?: SeverityEvidence | null): string {
  if (!severity) return "No severity evidence";
  if (severity.quantified && severity.numeric_score !== undefined && severity.numeric_score !== null) {
    return `${severity.score_type ?? "advisory score"} ${severity.numeric_score}`;
  }
  const entries = severity.entries?.length ?? 0;
  if (entries > 0) return `Unquantified (${entries} advisory ${entries === 1 ? "entry" : "entries"})`;
  return "Not reported by the advisory";
}

/**
 * Presentation-only colour band for the advisory's numeric score.
 * This never replaces or renames the reported score.
 */
export function severityToneClass(severity?: SeverityEvidence | null): string {
  if (!severity?.quantified || severity.numeric_score === undefined || severity.numeric_score === null) {
    return "border-zinc-700 bg-zinc-800/60 text-zinc-300";
  }
  const score = severity.numeric_score;
  if (score >= 9) return "border-red-500/50 bg-red-500/15 text-red-300";
  if (score >= 7) return "border-orange-500/50 bg-orange-500/15 text-orange-300";
  if (score >= 4) return "border-amber-400/50 bg-amber-400/15 text-amber-200";
  return "border-sky-400/50 bg-sky-400/15 text-sky-200";
}

/** Label for the modeled reachability status. Never claims "safe". */
export const REACHABILITY_LABELS: Record<string, string> = {
  direct: "Direct dependency",
  reachable_from_entry: "Modeled path from an entry point",
  not_reachable: "No modeled path found",
  unavailable: "Reachability unavailable (incomplete graph data)",
};

export function reachabilityLabel(status?: string | null): string {
  if (!status) return "Reachability unknown";
  return REACHABILITY_LABELS[status] ?? status;
}

/** Label for candidate/groups compatibility. Never claims "verified" or "tested". */
export const COMPATIBILITY_LABELS: Record<string, string> = {
  constraints_satisfied: "Constraints satisfied (not resolver-verified)",
  constraints_violated: "Declared constraints violated",
  unverified: "Compatibility unverified",
};

export function compatibilityLabel(value?: string | null): string {
  if (!value) return "Compatibility not evaluated";
  return COMPATIBILITY_LABELS[value] ?? value;
}

/** Label for fix-group coverage. */
export const COVERAGE_LABELS: Record<string, string> = {
  confirmed_advisory: "Advisory-confirmed",
  potential_only: "Potential only (not range-validated)",
  no_advisory_resolution: "No advisory resolution",
};

export function coverageLabel(value?: string | null): string {
  if (!value) return "Coverage unknown";
  return COVERAGE_LABELS[value] ?? value;
}
