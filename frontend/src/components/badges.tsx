/** Status/semantics badges. Labels come from the backend's own values. */

import type { ReactNode } from "react";
import type { SeverityEvidence } from "../api/generated";
import {
  compatibilityLabel,
  coverageLabel,
  reachabilityLabel,
  severityLabel,
  severityToneClass,
} from "../lib/format";

export type BadgeTone = "neutral" | "info" | "success" | "warning" | "danger" | "accent";

const TONES: Record<BadgeTone, string> = {
  neutral: "border-zinc-700 bg-zinc-800/60 text-zinc-300",
  info: "border-sky-500/40 bg-sky-500/10 text-sky-200",
  success: "border-emerald-500/40 bg-emerald-500/10 text-emerald-200",
  warning: "border-amber-400/40 bg-amber-400/10 text-amber-100",
  danger: "border-red-500/40 bg-red-500/10 text-red-200",
  accent: "border-violet-500/40 bg-violet-500/10 text-violet-200",
};

export function Badge({ tone = "neutral", children }: { tone?: BadgeTone; children: ReactNode }) {
  return (
    <span
      className={`inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium ${TONES[tone]}`}
    >
      {children}
    </span>
  );
}

export function IngestionStatusBadge({ status }: { status: string }) {
  const tone: BadgeTone = status === "success" ? "success" : status === "partial" ? "warning" : "danger";
  return <Badge tone={tone}>Ingestion: {status}</Badge>;
}

export function SeverityBadge({ severity }: { severity?: SeverityEvidence | null }) {
  return (
    <span
      className={`inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium ${severityToneClass(severity)}`}
      title={severity?.vector ? `Vector: ${severity.vector}` : undefined}
    >
      {severityLabel(severity)}
    </span>
  );
}

export function ReachabilityBadge({ status, minHops }: { status?: string | null; minHops?: number | null }) {
  const tone: BadgeTone =
    status === "direct"
      ? "danger"
      : status === "reachable_from_entry"
        ? "warning"
        : status === "not_reachable"
          ? "info"
          : "neutral";
  const hops = status === "reachable_from_entry" && minHops ? ` (min ${minHops} hops)` : "";
  return (
    <Badge tone={tone}>
      {reachabilityLabel(status)}
      {hops}
    </Badge>
  );
}

export function CompatibilityBadge({ value }: { value?: string | null }) {
  const tone: BadgeTone =
    value === "constraints_satisfied" ? "success" : value === "constraints_violated" ? "danger" : "warning";
  return <Badge tone={tone}>{compatibilityLabel(value)}</Badge>;
}

export function CoverageBadge({ value }: { value?: string | null }) {
  const tone: BadgeTone =
    value === "confirmed_advisory" ? "success" : value === "potential_only" ? "warning" : "neutral";
  return <Badge tone={tone}>{coverageLabel(value)}</Badge>;
}

export function ConfidenceBadge({ confidence }: { confidence: string }) {
  const tone: BadgeTone = confidence === "verified" ? "success" : "warning";
  return <Badge tone={tone}>{confidence === "verified" ? "Verified match" : "Reduced confidence"}</Badge>;
}

export function MatchTypeBadge({ matchType }: { matchType?: string | null }) {
  if (!matchType) return null;
  return (
    <Badge tone={matchType === "version" ? "success" : "warning"}>
      {matchType === "version" ? "Version match" : "Name-only match (not confirmed)"}
    </Badge>
  );
}

export function GraphConnectionBadge({ connected, error }: { connected: boolean; error?: string | null }) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 text-xs ${connected ? "text-emerald-300" : "text-amber-300"}`}
      title={error ?? undefined}
    >
      <span
        aria-hidden="true"
        className={`h-2 w-2 rounded-full ${connected ? "bg-emerald-400" : "bg-amber-400"}`}
      />
      {connected ? "FalkorDB connected" : "FalkorDB unavailable"}
    </span>
  );
}

export function ActionStateBadge({ state }: { state: string }) {
  const tone: BadgeTone =
    state === "SUCCEEDED"
      ? "success"
      : state === "FAILED"
        ? "danger"
        : state === "EXPIRED"
          ? "warning"
          : state === "EXECUTING"
            ? "info"
            : "neutral";
  return <Badge tone={tone}>{state}</Badge>;
}
