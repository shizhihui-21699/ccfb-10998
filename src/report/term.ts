/** Terminal rendering: colour, tables, and per-host report cards. */

const useColour =
  process.env.NO_COLOR === undefined &&
  process.env.FORCE_COLOR !== "0" &&
  (process.stdout.isTTY === true || process.env.FORCE_COLOR === "1");

type Colour = (text: string) => string;

const wrap =
  (open: number, close: number): Colour =>
  (text: string): string =>
    useColour ? `\u001b[${open}m${text}\u001b[${close}m` : text;

export const colour = {
  reset: wrap(0, 0),
  bold: wrap(1, 22),
  dim: wrap(2, 22),
  red: wrap(31, 39),
  green: wrap(32, 39),
  yellow: wrap(33, 39),
  blue: wrap(34, 39),
  magenta: wrap(35, 39),
  cyan: wrap(36, 39),
  grey: wrap(90, 39),
};

export function severityColour(severity: string): Colour {
  switch (severity) {
    case "critical":
      return colour.magenta;
    case "high":
      return colour.red;
    case "medium":
      return colour.yellow;
    case "low":
      return colour.blue;
    default:
      return colour.grey;
  }
}

export function statusColour(status: string): Colour {
  switch (status) {
    case "pass":
      return colour.green;
    case "fail":
      return colour.red;
    case "warn":
      return colour.yellow;
    default:
      return colour.grey;
  }
}

export function gradeColour(score: number): Colour {
  if (score >= 90) return colour.green;
  if (score >= 70) return colour.yellow;
  return colour.red;
}

/** Strip ANSI codes so widths can be measured. */
export function visibleLength(text: string): number {
  // eslint-disable-next-line no-control-regex
  return text.replace(/\u001b\[[0-9;]*m/g, "").length;
}

export function padEnd(text: string, width: number): string {
  const visible = visibleLength(text);
  return visible >= width ? text : text + " ".repeat(width - visible);
}

export function padStart(text: string, width: number): string {
  const visible = visibleLength(text);
  return visible >= width ? text : " ".repeat(width - visible) + text;
}

export interface Column {
  header: string;
  width?: number;
  align?: "left" | "right";
}

/** Render an aligned table; column widths derive from content when omitted. */
export function table(rows: string[][], columns: Column[]): string {
  const widths = columns.map((col, i) => {
    if (col.width !== undefined) return col.width;
    return Math.max(col.header.length, ...rows.map((r) => visibleLength(r[i] ?? "")));
  });
  const header = columns
    .map((col, i) => padEnd(col.header, widths[i]!))
    .join("  ");
  const sep = widths.map((w) => "─".repeat(w)).join("  ");
  const body = rows.map((row) =>
    columns
      .map((col, i) => {
        const cell = row[i] ?? "";
        return col.align === "right" ? padStart(cell, widths[i]!) : padEnd(cell, widths[i]!);
      })
      .join("  "),
  );
  return [colour.dim(header), colour.dim(sep), ...body].join("\n");
}

/** A horizontal rule sized to the terminal (capped for readability). */
export function rule(width = 78): string {
  return colour.dim("─".repeat(Math.min(width, process.stdout.columns ?? 100)));
}

export function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}
