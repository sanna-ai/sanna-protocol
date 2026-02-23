import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { ReceiptStore } from "../src/store.js";
import {
  DriftAnalyzer,
  calculateSlope,
  projectBreach,
  formatDriftReport,
  exportDriftReport,
} from "../src/drift.js";

function makeReceipt(
  agentId: string,
  status: string,
  checks: { check_id: string; passed: boolean; severity: string }[],
  daysAgo: number = 0,
): Record<string, unknown> {
  const ts = new Date(Date.now() - daysAgo * 86400000).toISOString();
  return {
    receipt_id: `r-${Math.random().toString(36).slice(2, 10)}`,
    correlation_id: "test-corr",
    timestamp: ts,
    status,
    checks: checks.map((c) => ({ ...c, evidence: null })),
    checks_passed: checks.filter((c) => c.passed).length,
    checks_failed: checks.filter((c) => !c.passed).length,
    inputs: { q: "test" },
    outputs: { r: "test" },
    context_hash: "a".repeat(64),
    output_hash: "b".repeat(64),
    constitution_ref: {
      document_id: `${agentId}/1.0`,
      policy_hash: "c".repeat(64),
    },
  };
}

describe("calculateSlope", () => {
  it("should return 0 for fewer than 2 points", () => {
    expect(calculateSlope([], [])).toBe(0);
    expect(calculateSlope([1], [1])).toBe(0);
  });

  it("should compute positive slope for increasing data", () => {
    const xs = [0, 1, 2, 3, 4];
    const ys = [0, 0.1, 0.2, 0.3, 0.4];
    expect(calculateSlope(xs, ys)).toBeCloseTo(0.1);
  });

  it("should compute negative slope for decreasing data", () => {
    const xs = [0, 1, 2, 3, 4];
    const ys = [0.4, 0.3, 0.2, 0.1, 0];
    expect(calculateSlope(xs, ys)).toBeCloseTo(-0.1);
  });

  it("should return 0 for flat data", () => {
    const xs = [0, 1, 2, 3];
    const ys = [0.5, 0.5, 0.5, 0.5];
    expect(calculateSlope(xs, ys)).toBeCloseTo(0);
  });

  it("should return 0 for identical x values", () => {
    expect(calculateSlope([1, 1, 1], [0, 0.5, 1])).toBe(0);
  });
});

describe("projectBreach", () => {
  it("should return 0 when current rate is at threshold", () => {
    expect(projectBreach(0.15, 0.01, 0.15)).toBe(0);
  });

  it("should return 0 when current rate is above threshold", () => {
    expect(projectBreach(0.20, 0.01, 0.15)).toBe(0);
  });

  it("should return null when slope is zero", () => {
    expect(projectBreach(0.10, 0, 0.15)).toBeNull();
  });

  it("should return null when slope is negative", () => {
    expect(projectBreach(0.10, -0.01, 0.15)).toBeNull();
  });

  it("should calculate days to breach", () => {
    // 0.05 gap, 0.01 per day = 5 days
    expect(projectBreach(0.10, 0.01, 0.15)).toBe(5);
  });

  it("should ceil fractional days", () => {
    // 0.05 gap, 0.03 per day = 1.67 → 2
    expect(projectBreach(0.10, 0.03, 0.15)).toBe(2);
  });
});

describe("DriftAnalyzer", () => {
  let tmpDir: string;
  let store: ReceiptStore;

  beforeEach(() => {
    process.env.SANNA_ALLOW_TEMP_DB = "1";
    tmpDir = mkdtempSync(join(tmpdir(), "sanna-drift-test-"));
    store = new ReceiptStore(join(tmpDir, "test.db"));
  });

  afterEach(() => {
    store.close();
    try { rmSync(tmpDir, { recursive: true, force: true }); } catch { /* */ }
    delete process.env.SANNA_ALLOW_TEMP_DB;
  });

  it("should return HEALTHY for all-passing receipts", () => {
    for (let i = 0; i < 10; i++) {
      store.save(makeReceipt("agent-a", "PASS", [
        { check_id: "C1", passed: true, severity: "info" },
      ], i));
    }
    const analyzer = new DriftAnalyzer(store);
    const report = analyzer.analyze(30);
    expect(report.fleet_status).toBe("HEALTHY");
    expect(report.agents).toHaveLength(1);
    expect(report.agents[0].status).toBe("HEALTHY");
  });

  it("should return INSUFFICIENT_DATA for fewer than 5 receipts", () => {
    for (let i = 0; i < 3; i++) {
      store.save(makeReceipt("agent-a", "PASS", [
        { check_id: "C1", passed: true, severity: "info" },
      ], i));
    }
    const analyzer = new DriftAnalyzer(store);
    const report = analyzer.analyze(30);
    expect(report.agents[0].status).toBe("INSUFFICIENT_DATA");
  });

  it("should return CRITICAL when fail rate exceeds threshold", () => {
    // 8 fails out of 10 = 80% > 15%
    for (let i = 0; i < 10; i++) {
      const passed = i < 2;
      store.save(makeReceipt("agent-a", passed ? "PASS" : "FAIL", [
        { check_id: "C1", passed, severity: "info" },
      ], i));
    }
    const analyzer = new DriftAnalyzer(store);
    const report = analyzer.analyze(30);
    expect(report.agents[0].status).toBe("CRITICAL");
    expect(report.fleet_status).toBe("CRITICAL");
  });

  it("should handle multiple agents", () => {
    for (let i = 0; i < 10; i++) {
      store.save(makeReceipt("agent-a", "PASS", [
        { check_id: "C1", passed: true, severity: "info" },
      ], i));
      store.save(makeReceipt("agent-b", "FAIL", [
        { check_id: "C1", passed: false, severity: "high" },
      ], i));
    }
    const analyzer = new DriftAnalyzer(store);
    const report = analyzer.analyze(30);
    expect(report.agents).toHaveLength(2);
    const aAgent = report.agents.find((a) => a.agent_id === "agent-a")!;
    const bAgent = report.agents.find((a) => a.agent_id === "agent-b")!;
    expect(aAgent.status).toBe("HEALTHY");
    expect(bAgent.status).toBe("CRITICAL");
    expect(report.fleet_status).toBe("CRITICAL");
  });

  it("should filter by agent_id", () => {
    for (let i = 0; i < 10; i++) {
      store.save(makeReceipt("agent-a", "PASS", [
        { check_id: "C1", passed: true, severity: "info" },
      ], i));
      store.save(makeReceipt("agent-b", "PASS", [
        { check_id: "C1", passed: true, severity: "info" },
      ], i));
    }
    const analyzer = new DriftAnalyzer(store);
    const report = analyzer.analyze(30, { agentId: "agent-a" });
    expect(report.agents).toHaveLength(1);
    expect(report.agents[0].agent_id).toBe("agent-a");
  });

  it("should report per-check details", () => {
    for (let i = 0; i < 10; i++) {
      store.save(makeReceipt("agent-a", i < 7 ? "PASS" : "FAIL", [
        { check_id: "C1", passed: i < 7, severity: "info" },
        { check_id: "C2", passed: true, severity: "info" },
      ], i));
    }
    const analyzer = new DriftAnalyzer(store);
    const report = analyzer.analyze(30);
    const c1 = report.agents[0].checks.find((c) => c.check_id === "C1")!;
    const c2 = report.agents[0].checks.find((c) => c.check_id === "C2")!;
    expect(c1.fail_count).toBe(3);
    expect(c1.pass_count).toBe(7);
    expect(c1.fail_rate).toBeCloseTo(0.3);
    expect(c2.fail_count).toBe(0);
    expect(c2.fail_rate).toBeCloseTo(0);
  });

  it("should analyze multiple windows", () => {
    for (let i = 0; i < 10; i++) {
      store.save(makeReceipt("agent-a", "PASS", [
        { check_id: "C1", passed: true, severity: "info" },
      ], i));
    }
    const analyzer = new DriftAnalyzer(store);
    const reports = analyzer.analyzeMulti([7, 30]);
    expect(reports).toHaveLength(2);
    expect(reports[0].window_days).toBe(7);
    expect(reports[1].window_days).toBe(30);
  });

  it("should skip NOT_CHECKED and ERRORED checks", () => {
    for (let i = 0; i < 10; i++) {
      store.save(makeReceipt("agent-a", "PASS", [
        { check_id: "C1", passed: true, severity: "info" },
      ], i));
    }
    // Add receipts with non-evaluated checks
    store.save({
      ...makeReceipt("agent-a", "PASS", [], 0),
      checks: [{ check_id: "C2", passed: false, severity: "info", status: "NOT_CHECKED", evidence: null }],
    });
    const analyzer = new DriftAnalyzer(store);
    const report = analyzer.analyze(30);
    // C2 should not appear in checks since all are NOT_CHECKED
    const c2 = report.agents[0].checks.find((c) => c.check_id === "C2");
    expect(c2).toBeUndefined();
  });

  it("should return empty agents for no receipts", () => {
    const analyzer = new DriftAnalyzer(store);
    const report = analyzer.analyze(30);
    expect(report.agents).toHaveLength(0);
    expect(report.fleet_status).toBe("HEALTHY");
  });
});

describe("formatDriftReport", () => {
  it("should format a report as human-readable text", () => {
    const report = {
      window_days: 30,
      threshold: 0.15,
      generated_at: "2026-02-22T00:00:00Z",
      agents: [],
      fleet_status: "HEALTHY",
    };
    const text = formatDriftReport(report);
    expect(text).toContain("Sanna Fleet Governance Report");
    expect(text).toContain("Window: 30 days");
    expect(text).toContain("Fleet Status: HEALTHY");
  });
});

describe("exportDriftReport", () => {
  const report = {
    window_days: 30,
    threshold: 0.15,
    generated_at: "2026-02-22T00:00:00Z",
    agents: [],
    fleet_status: "HEALTHY",
  };

  it("should export as JSON", () => {
    const json = exportDriftReport(report, "json");
    const parsed = JSON.parse(json);
    expect(parsed.window_days).toBe(30);
    expect(parsed.fleet_status).toBe("HEALTHY");
  });

  it("should export as CSV", () => {
    const csv = exportDriftReport(report, "csv");
    expect(csv).toContain("window_days");
    expect(csv).toContain("30");
  });
});
