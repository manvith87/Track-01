import { useState } from "react";
import { NavLink, Outlet, useLocation } from "react-router-dom";
import { GraphConnectionBadge } from "./badges";
import {
  AnalystIcon,
  FindingsIcon,
  GraphIcon,
  IssueIcon,
  RemediationIcon,
  RepositoryIcon,
  ShieldIcon,
} from "./icons";
import { useGraphHealth, useGraphStatus } from "../hooks/queries";
import { shortSha } from "../lib/format";
import { useSelectedAnalysisId } from "../state/useSelectedAnalysisId";

interface NavItem {
  segment: string;
  label: string;
  description: string;
  Icon: typeof RepositoryIcon;
}

const NAV_ITEMS: NavItem[] = [
  {
    segment: "",
    label: "Repository",
    description: "Ingest, inspect and persist an analysis",
    Icon: RepositoryIcon,
  },
  {
    segment: "findings",
    label: "Findings",
    description: "Ranked findings with priority factors",
    Icon: FindingsIcon,
  },
  {
    segment: "graph",
    label: "Graph explorer",
    description: "Dependency graph, evidence paths, trivially bounded",
    Icon: GraphIcon,
  },
  {
    segment: "analyst",
    label: "AI analyst",
    description: "Evidence-grounded answers from the agent",
    Icon: AnalystIcon,
  },
  {
    segment: "remediation",
    label: "Remediation",
    description: "Fix groups, candidates and coverage",
    Icon: RemediationIcon,
  },
  {
    segment: "issue",
    label: "GitHub issue",
    description: "Preview and confirm one approved issue",
    Icon: IssueIcon,
  },
];

function currentTitle(pathname: string): string {
  if (pathname === "/") return "Repository analysis";
  const segment = pathname.split("/")[3] ?? "";
  return NAV_ITEMS.find((item) => item.segment === segment)?.label ?? "BlastRadius";
}

export function Layout() {
  const analysisId = useSelectedAnalysisId();
  const { pathname } = useLocation();
  const [navOpen, setNavOpen] = useState(false);
  const health = useGraphHealth();
  const status = useGraphStatus(analysisId ?? "");

  const linkFor = (item: NavItem): string => {
    if (!analysisId) return "/";
    return item.segment ? `/analysis/${encodeURIComponent(analysisId)}/${item.segment}` : "/";
  };

  const disabled = (item: NavItem): boolean =>
    (!analysisId && item.segment !== "") || (!!analysisId && item.segment === "");

  return (
    <div className="min-h-full lg:grid lg:grid-cols-[260px_minmax(0,1fr)]">
      <a
        href="#main-content"
        className="focus-ring sr-only focus:not-sr-only focus:absolute focus:left-3 focus:top-3 focus:z-50 focus:rounded focus:bg-zinc-900 focus:px-3 focus:py-2 focus:text-sm"
      >
        Skip to content
      </a>

      <aside className="border-b border-zinc-800 bg-zinc-950 lg:border-b-0 lg:border-r">
        <div className="flex items-center justify-between px-4 py-4">
          <div className="flex items-center gap-2">
            <ShieldIcon className="text-sky-400" width={22} height={22} />
            <div>
              <p className="text-sm font-semibold tracking-wide text-zinc-100">BlastRadius</p>
              <p className="text-[11px] text-zinc-500">graph-powered security analysis</p>
            </div>
          </div>
          <button
            type="button"
            onClick={() => setNavOpen((open) => !open)}
            aria-expanded={navOpen}
            aria-controls="primary-navigation"
            className="focus-ring rounded border border-zinc-700 px-2 py-1 text-xs text-zinc-300 lg:hidden"
          >
            {navOpen ? "Close" : "Menu"}
          </button>
        </div>

        <nav
          id="primary-navigation"
          aria-label="Primary"
          className={`${navOpen ? "block" : "hidden"} border-t border-zinc-800 px-2 py-2 lg:block lg:border-t-0`}
        >
          <ul className="space-y-1">
            {NAV_ITEMS.map((item) => {
              const isDisabled = disabled(item);
              const to = linkFor(item);
              return (
                <li key={item.segment || "repository"}>
                  {isDisabled ? (
                    <span
                      aria-disabled="true"
                      className="flex items-start gap-3 rounded-lg px-3 py-2 text-sm text-zinc-600"
                    >
                      <item.Icon className="mt-0.5 shrink-0" />
                      <span>
                        <span className="block">{item.label}</span>
                        <span className="block text-[11px] text-zinc-700">
                          {item.segment === "" ? "Clear the current analysis" : "Persist an analysis first"}
                        </span>
                      </span>
                    </span>
                  ) : (
                    <NavLink
                      to={to}
                      end={item.segment === ""}
                      onClick={() => setNavOpen(false)}
                      className={({ isActive }) =>
                        `focus-ring flex items-start gap-3 rounded-lg px-3 py-2 text-sm ${
                          isActive
                            ? "bg-sky-500/10 text-sky-100 ring-1 ring-inset ring-sky-500/30"
                            : "text-zinc-300 hover:bg-zinc-900"
                        }`
                      }
                    >
                      <item.Icon className="mt-0.5 shrink-0" />
                      <span>
                        <span className="block font-medium">{item.label}</span>
                        <span className="block text-[11px] text-zinc-500">{item.description}</span>
                      </span>
                    </NavLink>
                  )}
                </li>
              );
            })}
          </ul>
        </nav>
      </aside>

      <div className="flex min-w-0 flex-col">
        <header className="flex flex-wrap items-center justify-between gap-3 border-b border-zinc-800 px-4 py-3">
          <div className="min-w-0">
            <h1 className="truncate text-base font-semibold text-zinc-100">{currentTitle(pathname)}</h1>
            <p className="truncate text-xs text-zinc-500">
              {analysisId ? (
                <>
                  analysis <span className="font-mono">{analysisId}</span>
                  {status.data ? (
                    <>
                      {" · "}
                      {status.data.repository_id}@{shortSha(status.data.commit_sha)}
                    </>
                  ) : null}
                </>
              ) : (
                "No analysis selected"
              )}
            </p>
          </div>
          {health.data ? (
            <GraphConnectionBadge connected={health.data.connected} error={health.data.error} />
          ) : health.isError ? (
            <span className="text-xs text-amber-300">FalkorDB health probe failed</span>
          ) : null}
        </header>

        <main id="main-content" className="min-w-0 flex-1 p-4 lg:p-6">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
