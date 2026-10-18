import { useEffect, useState, type ReactNode } from "react";
import { CheckIcon, CopyIcon, SpinnerIcon } from "./icons";

export function CopyButton({ value, label = "Copy" }: { value: string; label?: string }) {
  const [state, setState] = useState<"idle" | "copied" | "failed">("idle");

  useEffect(() => {
    if (state === "idle") return;
    const timer = setTimeout(() => setState("idle"), 1600);
    return () => clearTimeout(timer);
  }, [state]);

  return (
    <button
      type="button"
      onClick={() => {
        void navigator.clipboard
          .writeText(value)
          .then(() => setState("copied"))
          .catch(() => setState("failed"));
      }}
      className="focus-ring inline-flex items-center gap-1 rounded border border-zinc-700 px-2 py-1 text-xs text-zinc-300 hover:bg-zinc-800"
      aria-label={`${label}: ${value.slice(0, 80)}`}
    >
      {state === "copied" ? <CheckIcon width={14} height={14} /> : <CopyIcon width={14} height={14} />}
      {state === "copied" ? "Copied" : state === "failed" ? "Copy failed" : label}
    </button>
  );
}

export function SpinnerLabel({ label }: { label: string }) {
  return (
    <span className="inline-flex items-center gap-2 text-sm text-zinc-300">
      <SpinnerIcon className="text-sky-400" width={16} height={16} />
      {label}
    </span>
  );
}

export function Stat({
  label,
  value,
  hint,
  tone = "default",
}: {
  label: string;
  value: ReactNode;
  hint?: ReactNode;
  tone?: "default" | "warning" | "danger" | "success";
}) {
  const toneClass =
    tone === "warning"
      ? "border-amber-400/40"
      : tone === "danger"
        ? "border-red-500/40"
        : tone === "success"
          ? "border-emerald-500/40"
          : "border-zinc-800";
  return (
    <div className={`rounded-lg border ${toneClass} bg-zinc-900/50 p-3`}>
      <dt className="text-[11px] uppercase tracking-wide text-zinc-500">{label}</dt>
      <dd className="mt-1 text-lg font-semibold text-zinc-100">{value}</dd>
      {hint ? <dd className="mt-0.5 text-xs text-zinc-400">{hint}</dd> : null}
    </div>
  );
}

export function StatGrid({ children }: { children: ReactNode }) {
  return <dl className="grid grid-cols-2 gap-3 sm:grid-cols-3 xl:grid-cols-4">{children}</dl>;
}
