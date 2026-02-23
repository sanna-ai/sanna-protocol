import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { ReceiptStore } from "../src/store.js";

function makeReceipt(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    receipt_id: `receipt-${Math.random().toString(36).slice(2, 10)}`,
    correlation_id: "test-corr-001",
    timestamp: new Date().toISOString(),
    status: "PASS",
    checks: [
      { check_id: "C1", passed: true, severity: "info", evidence: null },
    ],
    checks_passed: 1,
    checks_failed: 0,
    inputs: { query: "test" },
    outputs: { response: "test" },
    context_hash: "a".repeat(64),
    output_hash: "b".repeat(64),
    constitution_ref: {
      document_id: "test-agent/1.0",
      policy_hash: "c".repeat(64),
    },
    ...overrides,
  };
}

describe("ReceiptStore", () => {
  let tmpDir: string;
  let dbPath: string;
  let store: ReceiptStore;

  beforeEach(() => {
    process.env.SANNA_ALLOW_TEMP_DB = "1";
    tmpDir = mkdtempSync(join(tmpdir(), "sanna-store-test-"));
    dbPath = join(tmpDir, "test.db");
    store = new ReceiptStore(dbPath);
  });

  afterEach(() => {
    store.close();
    try {
      rmSync(tmpDir, { recursive: true, force: true });
    } catch { /* ignore */ }
    delete process.env.SANNA_ALLOW_TEMP_DB;
  });

  describe("save and query", () => {
    it("should save a receipt and return the receipt_id", () => {
      const receipt = makeReceipt({ receipt_id: "test-001" });
      const id = store.save(receipt);
      expect(id).toBe("test-001");
    });

    it("should round-trip a receipt through save and query", () => {
      const receipt = makeReceipt();
      store.save(receipt);
      const results = store.query();
      expect(results).toHaveLength(1);
      expect(results[0].receipt_id).toBe(receipt.receipt_id);
      expect(results[0].status).toBe("PASS");
    });

    it("should save multiple receipts", () => {
      for (let i = 0; i < 5; i++) {
        store.save(makeReceipt());
      }
      expect(store.count()).toBe(5);
    });

    it("should upsert on duplicate receipt_id", () => {
      const receipt = makeReceipt({ receipt_id: "dup-001", status: "PASS" });
      store.save(receipt);
      const updated = { ...receipt, status: "FAIL" };
      store.save(updated);
      expect(store.count()).toBe(1);
      const results = store.query();
      expect(results[0].status).toBe("FAIL");
    });

    it("should generate receipt_id when not provided", () => {
      const receipt = makeReceipt();
      delete receipt.receipt_id;
      const id = store.save(receipt);
      expect(typeof id).toBe("string");
      expect(id.length).toBeGreaterThan(0);
    });
  });

  describe("query filters", () => {
    it("should filter by agent_id", () => {
      store.save(makeReceipt({ constitution_ref: { document_id: "agent-a/1.0", policy_hash: "x" } }));
      store.save(makeReceipt({ constitution_ref: { document_id: "agent-b/1.0", policy_hash: "x" } }));
      const results = store.query({ agent_id: "agent-a" });
      expect(results).toHaveLength(1);
    });

    it("should filter by constitution_id", () => {
      store.save(makeReceipt({ constitution_ref: { document_id: "agent-a/1.0", policy_hash: "x" } }));
      store.save(makeReceipt({ constitution_ref: { document_id: "agent-b/2.0", policy_hash: "y" } }));
      const results = store.query({ constitution_id: "agent-a/1.0" });
      expect(results).toHaveLength(1);
    });

    it("should filter by correlation_id", () => {
      store.save(makeReceipt({ correlation_id: "corr-A" }));
      store.save(makeReceipt({ correlation_id: "corr-B" }));
      const results = store.query({ correlation_id: "corr-A" });
      expect(results).toHaveLength(1);
    });

    it("should filter by status", () => {
      store.save(makeReceipt({ status: "PASS" }));
      store.save(makeReceipt({ status: "FAIL" }));
      store.save(makeReceipt({ status: "PASS" }));
      const fails = store.query({ status: "FAIL" });
      expect(fails).toHaveLength(1);
    });

    it("should filter by enforcement", () => {
      store.save(makeReceipt());
      store.save(makeReceipt({
        enforcement: { action: "halted", reason: "test", failed_checks: ["C1"], enforcement_mode: "strict" },
      }));
      const halted = store.query({ enforcement: true });
      expect(halted).toHaveLength(1);
    });

    it("should filter by since timestamp", () => {
      const old = new Date(Date.now() - 86400000 * 30).toISOString();
      const recent = new Date().toISOString();
      store.save(makeReceipt({ timestamp: old }));
      store.save(makeReceipt({ timestamp: recent }));
      const since = new Date(Date.now() - 86400000).toISOString();
      const results = store.query({ since });
      expect(results).toHaveLength(1);
    });

    it("should filter by until timestamp", () => {
      const old = new Date(Date.now() - 86400000 * 30).toISOString();
      const recent = new Date().toISOString();
      store.save(makeReceipt({ timestamp: old }));
      store.save(makeReceipt({ timestamp: recent }));
      const until = new Date(Date.now() - 86400000).toISOString();
      const results = store.query({ until });
      expect(results).toHaveLength(1);
    });

    it("should apply limit and offset", () => {
      for (let i = 0; i < 10; i++) {
        store.save(makeReceipt({ timestamp: new Date(Date.now() + i * 1000).toISOString() }));
      }
      const page1 = store.query({ limit: 3, offset: 0 });
      expect(page1).toHaveLength(3);
      const page2 = store.query({ limit: 3, offset: 3 });
      expect(page2).toHaveLength(3);
      // Pages should be different
      expect(page1[0].receipt_id).not.toBe(page2[0].receipt_id);
    });

    it("should combine multiple filters", () => {
      store.save(makeReceipt({ status: "FAIL", constitution_ref: { document_id: "agent-a/1.0", policy_hash: "x" } }));
      store.save(makeReceipt({ status: "PASS", constitution_ref: { document_id: "agent-a/1.0", policy_hash: "x" } }));
      store.save(makeReceipt({ status: "FAIL", constitution_ref: { document_id: "agent-b/1.0", policy_hash: "x" } }));
      const results = store.query({ agent_id: "agent-a", status: "FAIL" });
      expect(results).toHaveLength(1);
    });
  });

  describe("count", () => {
    it("should count all receipts", () => {
      store.save(makeReceipt());
      store.save(makeReceipt());
      expect(store.count()).toBe(2);
    });

    it("should count with filters", () => {
      store.save(makeReceipt({ status: "PASS" }));
      store.save(makeReceipt({ status: "FAIL" }));
      expect(store.count({ status: "PASS" })).toBe(1);
    });

    it("should return 0 for empty store", () => {
      expect(store.count()).toBe(0);
    });
  });

  describe("security", () => {
    it("should refuse /tmp paths without SANNA_ALLOW_TEMP_DB", () => {
      delete process.env.SANNA_ALLOW_TEMP_DB;
      expect(() => new ReceiptStore("/tmp/bad.db")).toThrow(/Refusing to store receipts in temp directory/);
    });

    it("should allow /tmp paths with SANNA_ALLOW_TEMP_DB=1", () => {
      process.env.SANNA_ALLOW_TEMP_DB = "1";
      const tmpPath = join(tmpDir, "allowed.db");
      const s = new ReceiptStore(tmpPath);
      s.close();
    });
  });

  describe("close and dispose", () => {
    it("should close idempotently", () => {
      store.close();
      store.close(); // should not throw
    });

    it("should support Symbol.dispose", () => {
      const s = new ReceiptStore(join(tmpDir, "dispose.db"));
      s[Symbol.dispose]();
      // calling again should not throw
      s[Symbol.dispose]();
    });
  });

  describe("ordering", () => {
    it("should return results ordered by timestamp descending", () => {
      const t1 = "2026-01-01T00:00:00Z";
      const t2 = "2026-02-01T00:00:00Z";
      const t3 = "2026-03-01T00:00:00Z";
      store.save(makeReceipt({ timestamp: t2 }));
      store.save(makeReceipt({ timestamp: t1 }));
      store.save(makeReceipt({ timestamp: t3 }));
      const results = store.query();
      expect(results[0].timestamp).toBe(t3);
      expect(results[1].timestamp).toBe(t2);
      expect(results[2].timestamp).toBe(t1);
    });
  });
});
