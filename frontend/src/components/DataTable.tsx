import { useState, type ReactNode } from "react";

export interface Column<T> {
  key: string;
  header: string;
  render: (row: T) => ReactNode;
  className?: string;
}

/**
 * Bounded, accessible table. Large server collections are rendered in chunks
 * with an explicit "show all returned rows" control, so the DOM stays bounded
 * while everything the server returned stays reachable.
 */
export function DataTable<T>({
  caption,
  columns,
  rows,
  rowKey,
  emptyLabel = "No records returned by the server.",
  initialRows = 25,
}: {
  caption: string;
  columns: Array<Column<T>>;
  rows: T[];
  rowKey: (row: T, index: number) => string;
  emptyLabel?: string;
  initialRows?: number;
}) {
  const [expanded, setExpanded] = useState(false);
  const visible = expanded ? rows : rows.slice(0, initialRows);

  if (rows.length === 0) {
    return <p className="text-sm text-zinc-400">{emptyLabel}</p>;
  }

  return (
    <div className="space-y-2">
      <div className="overflow-x-auto rounded-lg border border-zinc-800">
        <table className="min-w-full divide-y divide-zinc-800 text-left text-sm">
          <caption className="sr-only">{caption}</caption>
          <thead className="bg-zinc-900/70 text-xs uppercase tracking-wide text-zinc-400">
            <tr>
              {columns.map((column) => (
                <th
                  key={column.key}
                  scope="col"
                  className={`px-3 py-2 font-medium ${column.className ?? ""}`}
                >
                  {column.header}
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-zinc-800/70">
            {visible.map((row, index) => (
              <tr key={rowKey(row, index)} className="align-top hover:bg-zinc-900/40">
                {columns.map((column) => (
                  <td key={column.key} className={`px-3 py-2 text-zinc-200 ${column.className ?? ""}`}>
                    {column.render(row)}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="flex flex-wrap items-center gap-3 text-xs text-zinc-400">
        <span>
          Showing {visible.length} of {rows.length} returned rows
        </span>
        {rows.length > initialRows ? (
          <button
            type="button"
            onClick={() => setExpanded((value) => !value)}
            className="focus-ring rounded border border-zinc-700 px-2 py-0.5 text-xs text-zinc-200 hover:bg-zinc-800"
          >
            {expanded ? "Collapse" : `Show all ${rows.length}`}
          </button>
        ) : null}
      </p>
    </div>
  );
}
