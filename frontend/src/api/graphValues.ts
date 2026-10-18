/**
 * Runtime narrowing for graph API row values.
 *
 * `GET /analyses/{id}/graph` returns whole nodes and relationships. The
 * backend serialises them as plain JSON objects (documented shape):
 *
 *   node: {"id": 15, "labels": ["Package"], "properties": {...}}
 *   edge: {"id": 11, "type": "DEPENDS_ON", "src": 15, "dst": 27, "properties": {...}}
 *
 * `src`/`dst` reference node `id` values inside the same response. These
 * helpers accept only that shape and never invent values.
 */

export interface GraphNodeValue {
  internalId: number | string | null;
  labels: string[];
  properties: Record<string, unknown>;
}

export interface GraphEdgeValue {
  internalId: number | string | null;
  type: string;
  src: number | string | null;
  dst: number | string | null;
  properties: Record<string, unknown>;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function idValue(value: unknown): number | string | null {
  if (typeof value === "number" || typeof value === "string") return value;
  return null;
}

export function asNodeValue(value: unknown): GraphNodeValue | null {
  if (!isRecord(value)) return null;
  const { labels, properties } = value;
  if (!Array.isArray(labels) || !isRecord(properties)) return null;
  return {
    internalId: idValue(value.id),
    labels: labels.map((label) => String(label)),
    properties,
  };
}

export function asEdgeValue(value: unknown): GraphEdgeValue | null {
  if (!isRecord(value)) return null;
  const { type, properties } = value;
  if (typeof type !== "string" || !isRecord(properties)) return null;
  return {
    internalId: idValue(value.id),
    type,
    src: idValue(value.src),
    dst: idValue(value.dst),
    properties,
  };
}

// ---------------------------------------------------------------------------
// Flat row helpers (packages / dependency-edges / neighborhood rows)
// ---------------------------------------------------------------------------

export function rowText(row: Record<string, unknown>, key: string): string | null {
  const value = row[key];
  if (typeof value === "string" && value !== "") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  return null;
}

export function rowNumber(row: Record<string, unknown>, key: string): number | null {
  const value = row[key];
  return typeof value === "number" ? value : null;
}

export function rowBool(row: Record<string, unknown>, key: string): boolean | null {
  const value = row[key];
  return typeof value === "boolean" ? value : null;
}

export function rowStringList(row: Record<string, unknown>, key: string): string[] {
  const value = row[key];
  if (!Array.isArray(value)) return [];
  return value.filter((item): item is string => typeof item === "string");
}
