import { useMemo, useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { useSearchParams } from "react-router-dom";
import type { IssueConfirmOut, IssuePreviewOut } from "../api/generated";
import { confirmIssue, previewIssue } from "../api/endpoints";
import { isApiError } from "../api/client";
import { AnalysisGuard } from "../components/AnalysisGuard";
import { ActionStateBadge, Badge, CompatibilityBadge, CoverageBadge } from "../components/badges";
import { CopyButton, SpinnerLabel } from "../components/data";
import { EmptyState, ErrorState, Notice, SectionCard } from "../components/StateViews";
import { LockIcon } from "../components/icons";
import { useFindings, useFixGroups } from "../hooks/queries";
import { formatDateTime, formatNumber, shortSha } from "../lib/format";
import { useAnalysis } from "../state/analysis-context";

/** Errors that invalidate the current preview: a fresh preview is mandatory. */
function invalidatesPreview(error: unknown): boolean {
  return (
    isApiError(error) &&
    [
      "action_expired",
      "action_consumed",
      "action_evidence_changed",
      "action_payload_mismatch",
      "action_not_found",
    ].includes(error.code)
  );
}

function ActionErrorNotice({ error }: { error: unknown }) {
  let notice = null as null | React.ReactNode;
  if (isApiError(error)) {
    switch (error.code) {
      case "github_write_disabled":
        notice = (
          <Notice tone="warning" title="GitHub write actions are disabled on this server">
            <p>
              The backend refuses every write with{" "}
              <span className="font-mono">403 github_write_disabled</span> — {error.message} An operator must
              explicitly enable the GitHub action feature (and configure repository allow-lists) before this
              screen can create anything. No request was sent to GitHub.
            </p>
          </Notice>
        );
        break;
      case "action_authorization_not_configured":
        notice = (
          <Notice tone="warning" title="Server-side approval authorization is not configured">
            <p>
              The backend reported <span className="font-mono">503 action_authorization_not_configured</span>{" "}
              — {error.message} Set the approval secret server-side; the browser must never carry it in the
              frontend build.
            </p>
          </Notice>
        );
        break;
      case "action_unauthorized":
        notice = (
          <Notice tone="danger" title="Approval rejected">
            <p>
              The server did not accept the approval value (
              <span className="font-mono">401 action_unauthorized</span>). Re-enter the secret exactly as
              configured on the server. The value you typed was cleared and was never stored.
            </p>
          </Notice>
        );
        break;
      case "action_expired":
      case "action_consumed":
        notice = (
          <Notice tone="warning" title="This preview can no longer be confirmed">
            <p>
              The action expired or was already consumed (<span className="font-mono">{error.code}</span>).
              Create a new preview to see the currently authorized payload, then confirm again.
            </p>
          </Notice>
        );
        break;
      case "action_evidence_changed":
        notice = (
          <Notice tone="warning" title="Evidence changed since the preview">
            <p>
              The stored findings changed (<span className="font-mono">action_evidence_changed</span>), so the
              previewed issue no longer matches the data. Create a new preview and review the updated title
              and body.
            </p>
          </Notice>
        );
        break;
      case "action_payload_mismatch":
        notice = (
          <Notice tone="danger" title="Payload digest mismatch">
            <p>
              The confirmation did not match the previewed payload digest. The preview was invalidated; start
              again from a fresh preview.
            </p>
          </Notice>
        );
        break;
      case "github_write_ambiguous":
        notice = (
          <Notice tone="warning" title="Write outcome ambiguous">
            <p>
              The GitHub request may or may not have created the issue. BlastRadius marks this explicitly
              instead of guessing; check the repository before retrying.
            </p>
          </Notice>
        );
        break;
      case "action_in_progress":
        notice = (
          <Notice tone="info" title="Another confirmation is in flight">
            <p>The action is already executing; wait for it to finish before retrying.</p>
          </Notice>
        );
        break;
      case "github_permission_denied":
      case "github_credentials_invalid":
        notice = (
          <Notice tone="danger" title="GitHub rejected the server credentials">
            <p>
              The backend's GitHub token lacks permission (or is invalid) for this repository. Fix the
              server-side credential; the browser never holds it.
            </p>
          </Notice>
        );
        break;
      case "action_repository_not_allowed":
      case "action_repository_invalid":
        notice = (
          <Notice tone="warning" title="Repository not allowed">
            <p>The server's allow-list rejected this repository ({error.code}).</p>
          </Notice>
        );
        break;
      case "action_not_configured":
        notice = (
          <Notice tone="warning" title="GitHub actions are not configured">
            <p>The backend has no GitHub write configuration at all ({error.code}).</p>
          </Notice>
        );
        break;
      default:
        notice = null;
    }
  }
  if (notice) return <>{notice}</>;
  return <ErrorState error={error} title="The action request failed" />;
}

function IssuePreviewPanel({ preview, analysisId }: { preview: IssuePreviewOut; analysisId: string }) {
  return (
    <SectionCard
      title="Server-prepared issue preview"
      description="The exact title and body the backend would send to GitHub. Nothing here was composed by the browser."
      actions={
        <div className="flex flex-wrap items-center gap-2">
          <ActionStateBadge state={preview.state} />
          <CopyButton value={preview.payload_digest} label="Copy digest" />
        </div>
      }
    >
      <div className="space-y-4">
        <dl className="grid grid-cols-1 gap-x-6 gap-y-2 text-xs sm:grid-cols-2">
          <div className="contents">
            <dt className="text-zinc-400">Target repository</dt>
            <dd className="font-mono text-zinc-100">
              {preview.repository.full_name} ({preview.repository.canonical_id})
            </dd>
          </div>
          <div className="contents">
            <dt className="text-zinc-400">Commit</dt>
            <dd className="font-mono text-zinc-100">{shortSha(preview.commit_sha, 40)}</dd>
          </div>
          <div className="contents">
            <dt className="text-zinc-400">Analysis</dt>
            <dd className="font-mono text-zinc-100">{preview.analysis_id || analysisId}</dd>
          </div>
          <div className="contents">
            <dt className="text-zinc-400">Template version</dt>
            <dd className="font-mono text-zinc-100">{preview.template_version}</dd>
          </div>
          <div className="contents">
            <dt className="text-zinc-400">Created</dt>
            <dd className="text-zinc-100">{formatDateTime(preview.created_at)}</dd>
          </div>
          <div className="contents">
            <dt className="text-zinc-400">Expires (server clock)</dt>
            <dd className="text-zinc-100">{formatDateTime(preview.expires_at)}</dd>
          </div>
        </dl>

        <div className="flex flex-wrap items-center gap-2">
          {preview.coverage ? <CoverageBadge value={preview.coverage} /> : null}
          {preview.compatibility ? <CompatibilityBadge value={preview.compatibility} /> : null}
          <Badge tone="neutral">
            {formatNumber(preview.verified_finding_count ?? 0)} advisory-confirmed ·{" "}
            {formatNumber(preview.potential_finding_count ?? 0)} potential
          </Badge>
          {preview.selection.group_id ? (
            <Badge tone="accent">selection: group {preview.selection.group_id}</Badge>
          ) : null}
          {preview.selection.finding_id ? (
            <Badge tone="accent">selection: finding {preview.selection.finding_id}</Badge>
          ) : null}
        </div>

        <div>
          <h3 className="mb-1 text-xs font-semibold uppercase tracking-wide text-zinc-400">Title</h3>
          <p className="break-words rounded-lg border border-zinc-800 bg-zinc-950 p-3 text-sm text-zinc-100">
            {preview.title}
          </p>
        </div>

        <div>
          <h3 className="mb-1 text-xs font-semibold uppercase tracking-wide text-zinc-400">Body</h3>
          <pre className="max-h-96 overflow-auto whitespace-pre-wrap break-words rounded-lg border border-zinc-800 bg-zinc-950 p-3 text-xs text-zinc-200">
            {preview.body}
          </pre>
        </div>

        {(preview.limitations?.length ?? 0) > 0 ? (
          <Notice tone="warning" title="Limitations stated by the backend">
            <ul className="list-disc space-y-1 pl-4">
              {preview.limitations?.map((item) => (
                <li key={item}>{item}</li>
              ))}
            </ul>
          </Notice>
        ) : null}
        {(preview.notes?.length ?? 0) > 0 ? (
          <Notice tone="info" title="Notes">
            <ul className="list-disc space-y-1 pl-4">
              {preview.notes?.map((item) => (
                <li key={item}>{item}</li>
              ))}
            </ul>
          </Notice>
        ) : null}
      </div>
    </SectionCard>
  );
}

function IssueConfirmPanel({
  preview,
  onSucceeded,
  onFailed,
}: {
  preview: IssuePreviewOut;
  onSucceeded: (result: IssueConfirmOut) => void;
  onFailed: (error: unknown) => void;
}) {
  const [reviewed, setReviewed] = useState(false);
  const [approval, setApproval] = useState("");

  const confirm = useMutation({
    mutationFn: () =>
      confirmIssue({
        action_id: preview.action_id,
        payload_digest: preview.payload_digest,
        approvalSecret: approval,
      }),
    onSuccess: (data) => {
      onSucceeded(data);
    },
    onError: (error) => {
      onFailed(error);
    },
    onSettled: () => {
      // The secret lives only for the duration of the request.
      setApproval("");
    },
  });

  return (
    <SectionCard
      title="Explicit confirmation"
      description="Creating the issue is a separate, deliberate step. The preview alone changes nothing."
    >
      <div className="space-y-4">
        <Notice tone="info" title="How this confirmation is secured">
          <ul className="list-disc space-y-1 pl-4">
            <li>
              The approval value is sent once, for this single request, as the{" "}
              <span className="font-mono">X-BlastRadius-Approval</span> header.
            </li>
            <li>
              It is never written to <span className="font-mono">localStorage</span> or{" "}
              <span className="font-mono">sessionStorage</span>, never bundled into the frontend build, and is
              cleared from this form after every attempt.
            </li>
            <li>
              The GitHub token stays exclusively on the backend. The server re-validates the payload digest,
              the allow-list and the action state before writing anything.
            </li>
          </ul>
        </Notice>

        <>
          <label className="flex items-start gap-2 text-sm text-zinc-200">
            <input
              type="checkbox"
              checked={reviewed}
              onChange={(event) => setReviewed(event.target.checked)}
              className="focus-ring mt-0.5 h-4 w-4 rounded border-zinc-600 bg-zinc-950"
            />
            <span>
              I reviewed the exact title and body above and want to create this issue in{" "}
              <span className="font-mono">{preview.repository.full_name}</span>.
            </span>
          </label>

          <div>
            <label htmlFor="approval-secret" className="block text-xs font-medium text-zinc-300">
              Approval secret (kept in memory only)
            </label>
            <div className="mt-1 flex items-center gap-2">
              <LockIcon className="text-zinc-500" />
              <input
                id="approval-secret"
                name="approval-secret"
                type="password"
                autoComplete="new-password"
                spellCheck={false}
                value={approval}
                onChange={(event) => setApproval(event.target.value)}
                placeholder="Operator approval secret configured on the server"
                className="focus-ring w-full max-w-md rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm text-zinc-100 placeholder:text-zinc-600"
              />
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <button
              type="button"
              disabled={!reviewed || approval.trim().length === 0 || confirm.isPending}
              onClick={() => confirm.mutate()}
              className="focus-ring rounded-lg bg-red-500 px-4 py-2 text-sm font-semibold text-zinc-950 hover:bg-red-400 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {confirm.isPending ? "Confirming…" : "Confirm and create GitHub issue"}
            </button>
            {confirm.isPending ? (
              <SpinnerLabel label="The server is executing the one approved write" />
            ) : null}
          </div>
        </>
      </div>
    </SectionCard>
  );
}

function IssueResultPanel({ result }: { result: IssueConfirmOut }) {
  return (
    <SectionCard
      title="GitHub result"
      description="Returned by the backend after the write. This panel only ever shows what the API reported."
      actions={<ActionStateBadge state={result.state} />}
    >
      <div className="space-y-3 text-sm">
        {!result.created ? (
          <Notice tone="info" title="Stored result returned — no new issue was created">
            <p>
              This confirmation matched an already completed action, so the backend returned its stored result
              (duplicate submissions create nothing new).{" "}
              {result.reconciled
                ? "The issue was additionally reconciled by its unique action marker after an ambiguous write outcome."
                : ""}
            </p>
          </Notice>
        ) : (
          <Notice tone="success" title="Issue created">
            <p>The GitHub API accepted the write; the numbers below are from the API response.</p>
          </Notice>
        )}
        {result.reconciled && result.created ? (
          <Notice tone="warning" title="Recovered after an ambiguous outcome">
            <p>
              The backend did not receive a definitive create response and found the issue through its unique
              marker instead. The issue exists; treat the exact create timing as reconstructed.
            </p>
          </Notice>
        ) : null}

        <dl className="grid grid-cols-1 gap-x-6 gap-y-2 text-xs sm:grid-cols-2">
          <div className="contents">
            <dt className="text-zinc-400">Issue</dt>
            <dd className="text-zinc-100">
              {result.repository.full_name}#{result.issue_number}
            </dd>
          </div>
          <div className="contents">
            <dt className="text-zinc-400">URL</dt>
            <dd>
              <a
                href={result.issue_url}
                target="_blank"
                rel="noreferrer noopener"
                className="focus-ring break-all font-mono text-sky-300 underline decoration-dotted"
              >
                {result.issue_url}
              </a>
            </dd>
          </div>
          <div className="contents">
            <dt className="text-zinc-400">Executed</dt>
            <dd className="text-zinc-100">{formatDateTime(result.executed_at)}</dd>
          </div>
          <div className="contents">
            <dt className="text-zinc-400">Created this attempt</dt>
            <dd className="text-zinc-100">{result.created ? "yes" : "no (stored result)"}</dd>
          </div>
          <div className="contents">
            <dt className="text-zinc-400">Commit</dt>
            <dd className="font-mono text-zinc-100">{shortSha(result.commit_sha, 40)}</dd>
          </div>
          <div className="contents">
            <dt className="text-zinc-400">Action</dt>
            <dd className="font-mono text-zinc-100">{result.action_id}</dd>
          </div>
        </dl>
      </div>
    </SectionCard>
  );
}

function IssueActionContent() {
  const { analysisId } = useAnalysis();
  const [searchParams] = useSearchParams();
  const [selectionMode, setSelectionMode] = useState<"group" | "finding">(
    searchParams.get("finding") ? "finding" : "group",
  );
  const [groupId, setGroupId] = useState(searchParams.get("group") ?? "");
  const [findingId, setFindingId] = useState(searchParams.get("finding") ?? "");
  const [preview, setPreview] = useState<IssuePreviewOut | null>(null);
  const [result, setResult] = useState<IssueConfirmOut | null>(null);
  const [actionError, setActionError] = useState<unknown>(null);

  const groups = useFixGroups(analysisId, 0, 200);
  const findings = useFindings(analysisId, 0, 200);

  const selection = useMemo(
    () =>
      selectionMode === "group"
        ? groupId
          ? { group_id: groupId }
          : null
        : findingId
          ? { finding_id: findingId }
          : null,
    [selectionMode, groupId, findingId],
  );

  const previewMutation = useMutation({
    mutationFn: (input: { group_id?: string; finding_id?: string }) => previewIssue(analysisId, input),
    onSuccess: (data) => {
      setPreview(data);
      setResult(null);
      setActionError(null);
    },
  });

  return (
    <div className="mx-auto max-w-5xl space-y-5">
      <SectionCard
        title="GitHub issue action"
        description="Two-step, approval-gated flow: the server prepares an exact preview, you confirm explicitly, and only then does the backend call GitHub. Preview is not success."
      >
        <div className="space-y-4">
          <fieldset className="space-y-3">
            <legend className="text-xs font-semibold uppercase tracking-wide text-zinc-400">Subject</legend>
            <div className="flex flex-wrap gap-4">
              <label className="flex items-center gap-2 text-sm text-zinc-200">
                <input
                  type="radio"
                  name="selection-mode"
                  checked={selectionMode === "group"}
                  onChange={() => {
                    setSelectionMode("group");
                    setPreview(null);
                    setResult(null);
                    setActionError(null);
                  }}
                  className="focus-ring h-4 w-4 border-zinc-600 bg-zinc-950"
                />
                Fix group
              </label>
              <label className="flex items-center gap-2 text-sm text-zinc-200">
                <input
                  type="radio"
                  name="selection-mode"
                  checked={selectionMode === "finding"}
                  onChange={() => {
                    setSelectionMode("finding");
                    setPreview(null);
                    setResult(null);
                    setActionError(null);
                  }}
                  className="focus-ring h-4 w-4 border-zinc-600 bg-zinc-950"
                />
                Single finding
              </label>
            </div>

            {selectionMode === "group" ? (
              <div>
                <label htmlFor="issue-group" className="block text-xs text-zinc-400">
                  Choose a fix group
                </label>
                <select
                  id="issue-group"
                  value={groupId}
                  onChange={(event) => {
                    setGroupId(event.target.value);
                    setPreview(null);
                    setResult(null);
                    setActionError(null);
                  }}
                  className="focus-ring mt-1 w-full max-w-xl rounded-lg border border-zinc-700 bg-zinc-950 px-2 py-2 text-sm text-zinc-100"
                >
                  <option value="">Select a fix group…</option>
                  {(groups.data?.groups ?? []).map((group) => (
                    <option key={group.group_id} value={group.group_id}>
                      #{group.ranking.rank} {group.package_name} {group.current_version} →{" "}
                      {group.proposed_version} ({group.coverage})
                    </option>
                  ))}
                </select>
                {groups.isError ? (
                  <ErrorState error={groups.error} title="Could not load fix groups" compact />
                ) : null}
                {groups.isPending ? <p className="mt-1 text-xs text-zinc-500">Loading fix groups…</p> : null}
              </div>
            ) : (
              <div>
                <label htmlFor="issue-finding" className="block text-xs text-zinc-400">
                  Finding
                </label>
                <select
                  id="issue-finding"
                  value={findingId}
                  onChange={(event) => {
                    setFindingId(event.target.value);
                    setPreview(null);
                    setResult(null);
                    setActionError(null);
                  }}
                  className="focus-ring mt-1 w-full max-w-xl rounded-lg border border-zinc-700 bg-zinc-950 px-2 py-2 text-sm text-zinc-100"
                >
                  <option value="">Select a finding…</option>
                  {(findings.data?.findings ?? []).map((finding) => (
                    <option key={finding.finding_id} value={finding.finding_id}>
                      {finding.vulnerability_id} · {finding.package.package_name}{" "}
                      {finding.package.package_version ?? "?"} · priority {finding.priority.score}
                    </option>
                  ))}
                </select>
                {findings.isError ? (
                  <ErrorState error={findings.error} title="Could not load findings" compact />
                ) : null}
                {findings.isPending ? <p className="mt-1 text-xs text-zinc-500">Loading findings…</p> : null}
              </div>
            )}

            <div className="flex flex-wrap items-center gap-3">
              <button
                type="button"
                disabled={!selection || previewMutation.isPending}
                onClick={() => {
                  if (selection) previewMutation.mutate(selection);
                }}
                className="focus-ring rounded-lg bg-zinc-100 px-4 py-2 text-sm font-semibold text-zinc-900 hover:bg-white disabled:cursor-not-allowed disabled:opacity-50"
              >
                {previewMutation.isPending ? "Preparing preview…" : "Prepare preview"}
              </button>
              {preview ? (
                <button
                  type="button"
                  onClick={() => {
                    setPreview(null);
                    setResult(null);
                    setActionError(null);
                  }}
                  className="focus-ring rounded-lg border border-zinc-700 px-4 py-2 text-sm text-zinc-200 hover:bg-zinc-800"
                >
                  Discard preview
                </button>
              ) : null}
            </div>
            <p className="text-xs text-zinc-500">
              Preparing a preview never writes to GitHub.{" "}
              {selectionMode === "finding"
                ? "Findings pages are bounded to 200 entries here; use the findings screen to copy an id if yours is not listed."
                : ""}
            </p>
          </fieldset>

          {previewMutation.isError ? <ActionErrorNotice error={previewMutation.error} /> : null}
        </div>
      </SectionCard>

      {preview ? <IssuePreviewPanel preview={preview} analysisId={analysisId} /> : null}

      {preview && !result ? (
        <IssueConfirmPanel
          preview={preview}
          onSucceeded={(data) => {
            setResult(data);
            setActionError(null);
          }}
          onFailed={(error) => {
            setActionError(error);
            if (invalidatesPreview(error)) {
              // The preview is no longer confirmable: a new one is required.
              setPreview(null);
            }
          }}
        />
      ) : null}

      {actionError ? <ActionErrorNotice error={actionError} /> : null}

      {result ? <IssueResultPanel result={result} /> : null}

      {!preview && !result ? (
        <EmptyState
          title="Nothing prepared yet"
          description="Choose a fix group or a finding and prepare a preview. The preview shows the exact server-composed title and body; issue creation happens only after a separate explicit confirmation."
        />
      ) : null}
    </div>
  );
}

export function IssueActionPage() {
  return (
    <AnalysisGuard>
      <IssueActionContent />
    </AnalysisGuard>
  );
}
