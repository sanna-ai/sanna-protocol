/**
 * Sanna DriftAnalyzer — governance drift analytics over stored receipts.
 *
 * Calculates per-agent, per-check failure rates with trend analysis and
 * threshold breach projection. Pure TypeScript — no external math libraries.
 */

import type { ReceiptStore } from "./store.js";
import type {
  CheckDriftDetail,
  AgentDriftSummary,
  DriftReport,
  DriftStatus,
} from "./types.js";

// ── Pure linear regression helpers ───────────────────────────────────

/**
 * Least-squares slope: slope = (nSxy - SxSy) / (nSx2 - (Sx)^2).
 * Returns 0 when fewer than 2 data points or denominator is zero.
 */
export function calculateSlope(xs: number[], ys: number[]): number {
  const n = xs.length;
  if (n < 2 || n !== ys.length) return 0.0;

  let sumX = 0, sumY = 0, sumXY = 0, sumX2 = 0;
  for (let i = 0; i < n; i++) {
    sumX += xs[i];
    sumY += ys[i];
    sumXY += xs[i] * ys[i];
    sumX2 += xs[i] * xs[i];
  }

  const denom = n * sumX2 - sumX * sumX;
  if (denom === 0) return 0.0;

  return (n * sumXY - sumX * sumY) / denom;
}

/**
 * Days until currentRate reaches threshold at slope per day.
 * Returns 0 if already at/above threshold, null if slope <= 0.
 */
export function projectBreach(
  currentRate: number,
  slope: number,
  threshold: number,
): number | null {
  if (currentRate >= threshold) return 0;
  if (slope <= 0) return null;
  return Math.ceil((threshold - currentRate) / slope);
}

// ── Internal helpers ─────────────────────────────────────────────────

const MIN_RECEIPTS = 5;

const STATUS_RANK: Record<string, number> = {
  HEALTHY: 0,
  INSUFFICIENT_DATA: 1,
  WARNING: 2,
  CRITICAL: 3,
};

function worstStatus(...statuses: string[]): DriftStatus {
  return statuses.reduce((worst, s) =>
    (STATUS_RANK[s] ?? 0) > (STATUS_RANK[worst] ?? 0) ? s : worst,
  ) as DriftStatus;
}

function extractAgentId(receipt: Record<string, unknown>): string | null {
  const ref = receipt.constitution_ref as Record<string, unknown> | undefined;
  if (!ref || typeof ref !== "object") return null;
  const docId = ref.document_id;
  if (!docId || typeof docId !== "string") return null;
  const parts = docId.split("/", 2);
  return parts[0] || null;
}

function extractConstitutionId(receipt: Record<string, unknown>): string | null {
  const ref = receipt.constitution_ref as Record<string, unknown> | undefined;
  if (!ref || typeof ref !== "object") return null;
  const docId = ref.document_id;
  return typeof docId === "string" ? docId : null;
}

function parseTs(tsStr: unknown): Date | null {
  if (typeof tsStr !== "string" || !tsStr) return null;
  try {
    const d = new Date(tsStr.replace("Z", "+00:00"));
    return isNaN(d.getTime()) ? null : d;
  } catch {
    return null;
  }
}

function dayOffset(ts: Date, windowStart: Date): number {
  return (ts.getTime() - windowStart.getTime()) / 86_400_000;
}

// ── Analyzer ─────────────────────────────────────────────────────────

export class DriftAnalyzer {
  private _store: ReceiptStore;

  constructor(store: ReceiptStore) {
    this._store = store;
  }

  analyze(
    windowDays: number = 30,
    opts: {
      agentId?: string;
      threshold?: number;
      projectionDays?: number;
    } = {},
  ): DriftReport {
    const threshold = opts.threshold ?? 0.15;
    const projectionDays = opts.projectionDays ?? 90;

    const now = new Date();
    const since = new Date(now.getTime() - windowDays * 86_400_000);

    const queryFilters: Record<string, unknown> = { since: since.toISOString() };
    if (opts.agentId) queryFilters.agent_id = opts.agentId;

    const receipts = this._store.query(queryFilters as any);

    // Group by agent
    const agentBuckets = new Map<string, Record<string, unknown>[]>();
    const agentConst = new Map<string, string>();

    for (const r of receipts) {
      const aid = extractAgentId(r);
      if (!aid) continue;
      if (!agentBuckets.has(aid)) agentBuckets.set(aid, []);
      agentBuckets.get(aid)!.push(r);
      const cid = extractConstitutionId(r);
      if (cid) agentConst.set(aid, cid);
    }

    const agentSummaries: AgentDriftSummary[] = [];
    for (const aid of [...agentBuckets.keys()].sort()) {
      const bucket = agentBuckets.get(aid)!;
      const cid = agentConst.get(aid) ?? "";
      agentSummaries.push(
        this._analyzeAgent(aid, cid, bucket, since, threshold, projectionDays),
      );
    }

    const fleetStatus = agentSummaries.length > 0
      ? worstStatus(...agentSummaries.map((a) => a.status))
      : "HEALTHY";

    return {
      window_days: windowDays,
      threshold,
      generated_at: now.toISOString(),
      agents: agentSummaries,
      fleet_status: fleetStatus,
    };
  }

  analyzeMulti(
    windows: number[] = [7, 30, 90, 180],
    opts: {
      agentId?: string;
      threshold?: number;
      projectionDays?: number;
    } = {},
  ): DriftReport[] {
    return windows.map((w) => this.analyze(w, opts));
  }

  private _analyzeAgent(
    agentId: string,
    constitutionId: string,
    receipts: Record<string, unknown>[],
    windowStart: Date,
    threshold: number,
    projectionDays: number,
  ): AgentDriftSummary {
    const total = receipts.length;

    if (total < MIN_RECEIPTS) {
      return {
        agent_id: agentId,
        constitution_id: constitutionId,
        status: "INSUFFICIENT_DATA",
        total_receipts: total,
        checks: [],
        projected_breach_days: null,
      };
    }

    // Collect per-check stats
    const checkStats = new Map<
      string,
      { pass: number; fail: number; dayPoints: Map<number, number[]> }
    >();

    for (const r of receipts) {
      const ts = parseTs(r.timestamp);
      const dayOff = ts ? dayOffset(ts, windowStart) : null;

      const checks = r.checks;
      if (!Array.isArray(checks)) continue;

      for (const check of checks) {
        if (!check || typeof check !== "object") continue;
        const c = check as Record<string, unknown>;
        if (c.status === "NOT_CHECKED" || c.status === "ERRORED") continue;

        const cid = String(c.check_id ?? "unknown");
        if (!checkStats.has(cid)) {
          checkStats.set(cid, { pass: 0, fail: 0, dayPoints: new Map() });
        }
        const st = checkStats.get(cid)!;

        const passed = Boolean(c.passed);
        if (passed) st.pass++;
        else st.fail++;

        if (dayOff !== null) {
          const dayKey = Math.floor(dayOff);
          if (!st.dayPoints.has(dayKey)) st.dayPoints.set(dayKey, []);
          st.dayPoints.get(dayKey)!.push(passed ? 0.0 : 1.0);
        }
      }
    }

    const checkDetails: CheckDriftDetail[] = [];
    let worstBreach: number | null = null;
    let agentStatus: DriftStatus = "HEALTHY";

    for (const cid of [...checkStats.keys()].sort()) {
      const st = checkStats.get(cid)!;
      const totalEval = st.pass + st.fail;
      if (totalEval === 0) continue;

      const failRate = st.fail / totalEval;

      // Build per-day failure rates for trend
      const daysSorted = [...st.dayPoints.keys()].sort((a, b) => a - b);
      let slope = 0.0;
      if (daysSorted.length >= 2) {
        const xs = daysSorted.map((d) => d);
        const ys = daysSorted.map((d) => {
          const pts = st.dayPoints.get(d)!;
          return pts.reduce((a, b) => a + b, 0) / pts.length;
        });
        slope = calculateSlope(xs, ys);
      }

      const breach = projectBreach(failRate, slope, threshold);

      let checkStatus: DriftStatus;
      if (failRate >= threshold) {
        checkStatus = "CRITICAL";
      } else if (breach !== null && breach <= projectionDays) {
        checkStatus = "WARNING";
      } else {
        checkStatus = "HEALTHY";
      }

      agentStatus = worstStatus(agentStatus, checkStatus);

      if (breach !== null) {
        if (worstBreach === null || breach < worstBreach) {
          worstBreach = breach;
        }
      }

      checkDetails.push({
        check_id: cid,
        total_evaluated: totalEval,
        pass_count: st.pass,
        fail_count: st.fail,
        fail_rate: failRate,
        trend_slope: slope,
        projected_breach_days: breach,
        status: checkStatus,
      });
    }

    return {
      agent_id: agentId,
      constitution_id: constitutionId,
      status: agentStatus,
      total_receipts: total,
      checks: checkDetails,
      projected_breach_days: agentStatus !== "HEALTHY" ? worstBreach : null,
    };
  }
}

// ── Report formatting ────────────────────────────────────────────────

export function formatDriftReport(report: DriftReport): string {
  const lines: string[] = [];

  lines.push("");
  lines.push("Sanna Fleet Governance Report");
  lines.push("=".repeat(55));
  lines.push(
    `Window: ${report.window_days} days | ` +
    `Threshold: ${(report.threshold * 100).toFixed(1)}% | ` +
    `Generated: ${report.generated_at}`,
  );
  lines.push("");

  if (report.agents.length === 0) {
    lines.push("  No agents with receipts in this window.");
  } else {
    for (const agent of report.agents) {
      if (agent.status === "INSUFFICIENT_DATA") {
        lines.push(
          `  ${agent.agent_id.padEnd(20)} | ` +
          `${agent.total_receipts} receipts | ` +
          `INSUFFICIENT_DATA`,
        );
        continue;
      }

      const totalEval = agent.checks.reduce((s, c) => s + c.total_evaluated, 0);
      const totalFail = agent.checks.reduce((s, c) => s + c.fail_count, 0);
      const aggRate = totalEval > 0 ? totalFail / totalEval : 0;

      const slopes = agent.checks
        .filter((c) => c.total_evaluated > 0)
        .map((c) => c.trend_slope);
      const avgSlope = slopes.length > 0
        ? slopes.reduce((a, b) => a + b, 0) / slopes.length
        : 0;

      let trendStr: string;
      if (avgSlope > 0.001) trendStr = "^ degrading";
      else if (avgSlope < -0.001) trendStr = "v improving";
      else trendStr = "- stable";

      lines.push(
        `  ${agent.agent_id.padEnd(20)} | ` +
        `Fail rate: ${(aggRate * 100).toFixed(1).padStart(5)}% | ` +
        `Trend: ${trendStr.padEnd(13)} | ` +
        agent.status,
      );

      if (agent.projected_breach_days !== null && agent.projected_breach_days > 0) {
        lines.push(
          `  ${"".padEnd(20)}   ` +
          `Projected threshold breach in ${agent.projected_breach_days} days`,
        );
      }
    }
  }

  lines.push("");
  lines.push(`Fleet Status: ${report.fleet_status}`);
  lines.push("=".repeat(55));
  return lines.join("\n");
}

// ── Export helpers ────────────────────────────────────────────────────

const CSV_COLUMNS = [
  "window_days", "threshold", "generated_at", "fleet_status",
  "agent_id", "constitution_id", "agent_status", "total_receipts",
  "projected_breach_days", "check_id", "total_evaluated", "pass_count",
  "fail_count", "fail_rate", "trend_slope", "check_projected_breach_days",
  "check_status",
];

export function exportDriftReport(report: DriftReport, fmt: "json" | "csv" = "json"): string {
  if (fmt === "json") {
    return JSON.stringify(report, null, 2);
  }

  // CSV
  const rows: string[][] = [CSV_COLUMNS];

  if (report.agents.length === 0) {
    rows.push([
      String(report.window_days), String(report.threshold),
      report.generated_at, report.fleet_status,
      "", "", "", "", "", "", "", "", "", "", "", "", "",
    ]);
  } else {
    for (const agent of report.agents) {
      if (agent.checks.length === 0) {
        rows.push([
          String(report.window_days), String(report.threshold),
          report.generated_at, report.fleet_status,
          agent.agent_id, agent.constitution_id, agent.status,
          String(agent.total_receipts),
          agent.projected_breach_days !== null ? String(agent.projected_breach_days) : "",
          "", "", "", "", "", "", "", "",
        ]);
      } else {
        for (const check of agent.checks) {
          rows.push([
            String(report.window_days), String(report.threshold),
            report.generated_at, report.fleet_status,
            agent.agent_id, agent.constitution_id, agent.status,
            String(agent.total_receipts),
            agent.projected_breach_days !== null ? String(agent.projected_breach_days) : "",
            check.check_id, String(check.total_evaluated),
            String(check.pass_count), String(check.fail_count),
            String(check.fail_rate), String(check.trend_slope),
            check.projected_breach_days !== null ? String(check.projected_breach_days) : "",
            check.status,
          ]);
        }
      }
    }
  }

  return rows.map((r) => r.map(csvEscape).join(",")).join("\n") + "\n";
}

function csvEscape(val: string): string {
  if (val.includes(",") || val.includes('"') || val.includes("\n")) {
    return `"${val.replace(/"/g, '""')}"`;
  }
  return val;
}
