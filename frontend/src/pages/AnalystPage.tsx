import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import type { AgentAskResponse } from "../api/generated";
import { askAgent } from "../api/endpoints";
import { isApiError } from "../api/client";
import { AnalysisGuard } from "../components/AnalysisGuard";
import { Badge } from "../components/badges";
import { CopyButton, SpinnerLabel } from "../components/data";
import { DataTable } from "../components/DataTable";
import { EmptyState, ErrorState, Notice, SectionCard } from "../components/StateViews";
import { formatDateTime, shortSha } from "../lib/format";
import { useAnalysis } from "../state/analysis-context";

const SUGGESTED_QUESTIONS = [
  "Which packages are affected by advisories and have a modeled path from an entry point?",
  "Which advisories were matched by name only rather than by an exact version?",
  "What does the graph say about the highest-priority finding's dependency context?",
  "Which fix groups resolve the most advisory-confirmed findings?",
];

interface Exchange {
  id: number;
  question: string;
  response: AgentAskResponse;
  askedAt: number;
}

/** Provider/configuration failures deserve their own explanation, not a raw 5xx. */
function AgentErrorNotice({ error }: { error: unknown }) {
  if (isApiError(error) && error.code === "agent_not_configured") {
    return (
      <Notice tone="warning" title="The analysis agent is not configured on this server">
        <p>
          The backend answered <span className="font-mono">503 agent_not_configured</span> — {error.message}{" "}
          No answer was produced, and nothing was generated locally.
        </p>
        <p>
          Configure the agent on the server (the message above names the variables this deployment expects)
          and ask again. Deterministic pages — repository, findings, graph, remediation and issue preview —
          remain fully usable without the agent.
        </p>
      </Notice>
    );
  }
  if (isApiError(error) && error.code === "agent_provider_error") {
    return (
      <Notice tone="danger" title="The LLM provider returned an error">
        <p>
          {error.message} The provider call failed ({error.retryable ? "retryable" : "not retryable"}). The
          answer was not produced by BlastRadius; nothing was generated locally.
        </p>
      </Notice>
    );
  }
  return <ErrorState error={error} title="The question could not be answered" />;
}

function AnswerPanel({ exchange }: { exchange: Exchange }) {
  const { response } = exchange;
  return (
    <article className="space-y-4 rounded-xl border border-zinc-800 bg-zinc-900/40 p-4">
      <header className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="text-xs uppercase tracking-wide text-zinc-500">Question</p>
          <h3 className="mt-0.5 text-sm font-medium text-zinc-100">{exchange.question}</h3>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Badge tone={response.grounded ? "success" : "warning"}>
            {response.grounded ? "Grounded in tool evidence" : "Not grounded in evidence"}
          </Badge>
          {response.incomplete ? <Badge tone="warning">Answer flagged incomplete</Badge> : null}
          <Badge tone="neutral">{response.rounds_used} round(s)</Badge>
        </div>
      </header>

      <div className="whitespace-pre-wrap rounded-lg border border-zinc-800 bg-zinc-950 p-3 text-sm text-zinc-100">
        {response.answer}
      </div>

      <div className="flex flex-wrap items-center gap-3 text-xs text-zinc-400">
        <span>
          repository <span className="font-mono text-zinc-300">{response.repository_id ?? "—"}</span> @{" "}
          <span className="font-mono text-zinc-300">{shortSha(response.commit_sha)}</span>
        </span>
        <span>
          analysis <span className="font-mono text-zinc-300">{response.analysis_id}</span>
        </span>
        <span>asked {formatDateTime(new Date(exchange.askedAt).toISOString())}</span>
      </div>

      {response.advisory_links && response.advisory_links.length > 0 ? (
        <div>
          <h4 className="mb-1 text-xs font-semibold uppercase tracking-wide text-zinc-400">
            Advisory links cited
          </h4>
          <div className="flex flex-wrap gap-2">
            {response.advisory_links.map((link) => (
              <Badge key={link} tone="danger">
                {link}
              </Badge>
            ))}
          </div>
        </div>
      ) : null}

      <div className="grid gap-4 lg:grid-cols-2">
        <div>
          <h4 className="mb-2 text-xs font-semibold uppercase tracking-wide text-zinc-400">
            Tool calls ({response.tool_calls?.length ?? 0})
          </h4>
          <DataTable
            caption="Agent tool calls"
            rows={response.tool_calls ?? []}
            rowKey={(call, index) => `${call.round_index}-${call.name}-${index}`}
            initialRows={10}
            emptyLabel="No tool calls were recorded for this answer."
            columns={[
              { key: "round", header: "Round", render: (call) => <span>{call.round_index}</span> },
              {
                key: "name",
                header: "Tool",
                render: (call) => <span className="font-mono text-xs">{call.name}</span>,
              },
              {
                key: "status",
                header: "Status",
                render: (call) => (
                  <span>
                    {call.status}
                    {call.reason ? ` — ${call.reason}` : ""}
                  </span>
                ),
              },
              {
                key: "arguments",
                header: "Arguments",
                render: (call) => (
                  <span className="break-all font-mono text-[11px] text-zinc-400">
                    {call.arguments ? JSON.stringify(call.arguments) : "—"}
                  </span>
                ),
              },
              {
                key: "chars",
                header: "Result chars",
                render: (call) => <span>{call.result_chars ?? 0}</span>,
              },
            ]}
          />
        </div>
        <div>
          <h4 className="mb-2 text-xs font-semibold uppercase tracking-wide text-zinc-400">
            Evidence excerpts ({response.evidence?.length ?? 0})
          </h4>
          <DataTable
            caption="Agent evidence excerpts"
            rows={response.evidence ?? []}
            rowKey={(item, index) => `${item.round_index}-${item.tool}-${item.sequence}-${index}`}
            initialRows={10}
            emptyLabel="The agent reported no evidence excerpts."
            columns={[
              { key: "round", header: "Round", render: (item) => <span>{item.round_index}</span> },
              {
                key: "tool",
                header: "Tool",
                render: (item) => <span className="font-mono text-xs">{item.tool}</span>,
              },
              {
                key: "excerpt",
                header: "Excerpt",
                render: (item) => (
                  <span className="whitespace-pre-wrap break-words text-[11px] text-zinc-300">
                    {item.excerpt}
                  </span>
                ),
              },
              { key: "chars", header: "Chars", render: (item) => <span>{item.result_chars}</span> },
            ]}
          />
        </div>
      </div>

      {response.limitations && response.limitations.length > 0 ? (
        <Notice tone="warning" title="Limitations reported with this answer">
          <ul className="list-disc space-y-1 pl-4">
            {response.limitations.map((limitation) => (
              <li key={limitation}>{limitation}</li>
            ))}
          </ul>
        </Notice>
      ) : null}
    </article>
  );
}

function AnalystContent() {
  const { analysisId } = useAnalysis();
  const [question, setQuestion] = useState("");
  const [maxRounds, setMaxRounds] = useState<string>("");
  const [history, setHistory] = useState<Exchange[]>([]);

  const ask = useMutation({
    mutationFn: (input: { question: string; max_rounds?: number }) => askAgent(analysisId, input),
    onSuccess: (response, variables) => {
      setHistory((current) => [
        ...current,
        { id: current.length + 1, question: variables.question, response, askedAt: Date.now() },
      ]);
      setQuestion("");
    },
  });

  const submit = (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const trimmed = question.trim();
    if (!trimmed || ask.isPending) return;
    const rounds = Number(maxRounds);
    ask.mutate({
      question: trimmed,
      ...(maxRounds && Number.isFinite(rounds) && rounds > 0 ? { max_rounds: rounds } : {}),
    });
  };

  return (
    <div className="mx-auto max-w-5xl space-y-5">
      <SectionCard
        title="Ask the analysis agent"
        description="Questions run against this analysis's stored graph and advisory records. Answers come from the configured LLM provider through the backend agent — the browser never generates security explanations."
      >
        <form onSubmit={submit} className="space-y-3">
          <div>
            <label htmlFor="agent-question" className="block text-xs font-medium text-zinc-300">
              Question
            </label>
            <textarea
              id="agent-question"
              value={question}
              onChange={(event) => setQuestion(event.target.value)}
              rows={3}
              maxLength={1000}
              required
              placeholder="Which advisories affect packages with a modeled path from an entry point?"
              className="focus-ring mt-1 w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm text-zinc-100 placeholder:text-zinc-600"
            />
            <p className="mt-1 text-xs text-zinc-500">{question.length}/1000 characters</p>
          </div>

          <div className="flex flex-wrap items-end gap-3">
            <div>
              <label htmlFor="agent-max-rounds" className="block text-xs text-zinc-400">
                Max reasoning rounds (optional)
              </label>
              <input
                id="agent-max-rounds"
                type="number"
                min={1}
                max={20}
                value={maxRounds}
                onChange={(event) => setMaxRounds(event.target.value)}
                placeholder="server default"
                className="focus-ring mt-1 w-40 rounded-lg border border-zinc-700 bg-zinc-950 px-2 py-1.5 text-sm text-zinc-100"
              />
            </div>
            <button
              type="submit"
              disabled={ask.isPending || question.trim().length === 0}
              className="focus-ring rounded-lg bg-sky-500 px-4 py-2 text-sm font-semibold text-zinc-950 hover:bg-sky-400 disabled:cursor-not-allowed disabled:opacity-60"
            >
              {ask.isPending ? "Asking…" : "Ask"}
            </button>
            {ask.isPending ? <SpinnerLabel label="Running the agent loop against stored evidence" /> : null}
          </div>
        </form>

        <div className="mt-4">
          <h3 className="text-xs font-semibold uppercase tracking-wide text-zinc-400">Suggested questions</h3>
          <div className="mt-2 flex flex-wrap gap-2">
            {SUGGESTED_QUESTIONS.map((suggestion) => (
              <button
                key={suggestion}
                type="button"
                onClick={() => setQuestion(suggestion)}
                className="focus-ring rounded-full border border-zinc-700 px-3 py-1 text-xs text-zinc-300 hover:bg-zinc-800"
              >
                {suggestion}
              </button>
            ))}
          </div>
        </div>

        <p className="mt-4 text-xs text-zinc-500">
          Each question is an independent server request; the backend does not persist conversations. The
          history below lives only in this browser tab and disappears on reload.
        </p>
      </SectionCard>

      {ask.isError ? <AgentErrorNotice error={ask.error} /> : null}

      {history.length === 0 && !ask.isPending ? (
        <EmptyState
          title="No questions asked yet"
          description="Ask a question above. Answers will include the evidence excerpts, tool calls, and limitations the backend returned."
        />
      ) : null}

      {history
        .slice()
        .reverse()
        .map((exchange) => (
          <AnswerPanel key={exchange.id} exchange={exchange} />
        ))}

      {history.length > 0 ? (
        <SectionCard
          title="Cited details"
          description="Everything the agent said is reproducible from these references."
          actions={
            <CopyButton
              value={history[history.length - 1]?.response.answer ?? ""}
              label="Copy latest answer"
            />
          }
        >
          <p className="text-xs text-zinc-400">
            Advisory evidence, tool calls and excerpts are shown with each answer. Use the findings, graph and
            remediation screens to inspect the underlying records directly.
          </p>
        </SectionCard>
      ) : null}
    </div>
  );
}

export function AnalystPage() {
  return (
    <AnalysisGuard>
      <AnalystContent />
    </AnalysisGuard>
  );
}
