/** Loading / empty / error / partial states shared by every screen. */

import type { ReactNode } from "react";
import { isApiError } from "../api/client";
import { InfoIcon, SpinnerIcon, WarningIcon, XIcon } from "./icons";

export function LoadingState({ label = "Loading…" }: { label?: string }) {
  return (
    <div role="status" aria-live="polite" className="flex items-center gap-3 py-8 text-sm text-zinc-400">
      <SpinnerIcon className="text-sky-400" />
      <span>{label}</span>
    </div>
  );
}

export function EmptyState({
  title,
  description,
  action,
}: {
  title: string;
  description?: ReactNode;
  action?: ReactNode;
}) {
  return (
    <div className="rounded-lg border border-dashed border-zinc-800 bg-zinc-900/40 p-6 text-sm">
      <p className="font-medium text-zinc-200">{title}</p>
      {description ? <div className="mt-1 text-zinc-400">{description}</div> : null}
      {action ? <div className="mt-3">{action}</div> : null}
    </div>
  );
}

/**
 * Error state that renders the backend's structured error envelope verbatim
 * (code, message, stage, retryability) and distinguishes transport failures.
 */
export function ErrorState({
  error,
  title = "Request failed",
  onRetry,
  compact = false,
}: {
  error: unknown;
  title?: string;
  onRetry?: () => void;
  compact?: boolean;
}) {
  if (!isApiError(error)) {
    const message = error instanceof Error ? error.message : String(error);
    return (
      <div
        role="alert"
        className="rounded-lg border border-red-500/40 bg-red-500/10 p-4 text-sm text-red-200"
      >
        <p className="font-medium">{title}</p>
        <p className="mt-1 break-words">{message}</p>
      </div>
    );
  }

  const transport = error.isTransportFailure && error.code === "network_error";
  const timeout = error.code === "request_timeout";
  return (
    <div
      role="alert"
      className={`rounded-lg border p-4 text-sm ${
        transport || timeout
          ? "border-amber-400/40 bg-amber-400/10 text-amber-100"
          : "border-red-500/40 bg-red-500/10 text-red-100"
      }`}
    >
      <div className="flex items-start gap-2">
        <XIcon className="mt-0.5 shrink-0" />
        <div className="min-w-0">
          <p className="font-medium">{title}</p>
          <p className="mt-1 break-words">{error.message}</p>
          {!compact ? (
            <dl className="mt-2 grid grid-cols-2 gap-x-4 gap-y-1 text-xs text-zinc-300">
              <dt className="text-zinc-400">Code</dt>
              <dd className="font-mono">{error.code}</dd>
              {error.status > 0 ? (
                <>
                  <dt className="text-zinc-400">HTTP status</dt>
                  <dd className="font-mono">{error.status}</dd>
                </>
              ) : null}
              <dt className="text-zinc-400">Stage</dt>
              <dd className="font-mono">{error.stage}</dd>
              <dt className="text-zinc-400">Retryable</dt>
              <dd className="font-mono">{error.retryable ? "yes" : "no"}</dd>
            </dl>
          ) : null}
          {onRetry ? (
            <button
              type="button"
              onClick={onRetry}
              className="focus-ring mt-3 rounded border border-zinc-600 px-3 py-1 text-xs font-medium text-zinc-100 hover:bg-zinc-800"
            >
              Retry
            </button>
          ) : null}
        </div>
      </div>
    </div>
  );
}

export function Notice({
  tone = "info",
  title,
  children,
}: {
  tone?: "info" | "warning" | "danger" | "success";
  title?: string;
  children: ReactNode;
}) {
  const tones = {
    info: "border-sky-500/40 bg-sky-500/10 text-sky-100",
    warning: "border-amber-400/40 bg-amber-400/10 text-amber-100",
    danger: "border-red-500/40 bg-red-500/10 text-red-100",
    success: "border-emerald-500/40 bg-emerald-500/10 text-emerald-100",
  } as const;
  const Icon = tone === "info" || tone === "success" ? InfoIcon : WarningIcon;
  return (
    <div className={`rounded-lg border p-3 text-sm ${tones[tone]}`}>
      <div className="flex items-start gap-2">
        <Icon className="mt-0.5 shrink-0" />
        <div className="min-w-0">
          {title ? <p className="font-medium">{title}</p> : null}
          <div className={title ? "mt-1" : ""}>{children}</div>
        </div>
      </div>
    </div>
  );
}

export function SectionCard({
  title,
  description,
  actions,
  children,
  id,
}: {
  title: string;
  description?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  id?: string;
}) {
  return (
    <section id={id} className="rounded-xl border border-zinc-800 bg-zinc-900/50">
      <header className="flex flex-wrap items-start justify-between gap-3 border-b border-zinc-800 px-4 py-3">
        <div>
          <h2 className="text-sm font-semibold tracking-wide text-zinc-100">{title}</h2>
          {description ? <p className="mt-0.5 text-xs text-zinc-400">{description}</p> : null}
        </div>
        {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
      </header>
      <div className="p-4">{children}</div>
    </section>
  );
}

export function DescriptionList({ items }: { items: Array<{ term: string; value: ReactNode }> }) {
  return (
    <dl className="grid grid-cols-1 gap-x-6 gap-y-2 text-sm sm:grid-cols-[minmax(10rem,auto)_1fr]">
      {items.map((item) => (
        <div key={item.term} className="contents">
          <dt className="text-zinc-400">{item.term}</dt>
          <dd className="min-w-0 break-words text-zinc-100">{item.value}</dd>
        </div>
      ))}
    </dl>
  );
}

export function TruncationNotice({ notes }: { notes: string[] }) {
  if (notes.length === 0) return null;
  return (
    <Notice tone="warning" title="Server response was bounded">
      <p>
        The backend capped large collections for transport ({notes.join(", ")}). Everything shown comes from
        the returned records; anything persisted from this page contains exactly those records.
      </p>
    </Notice>
  );
}
