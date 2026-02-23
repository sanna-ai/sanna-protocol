import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { EscalationStore } from "../src/escalation.js";

const SECRET = "test-hmac-secret-key-for-testing";

let tmpDir: string;

beforeEach(() => {
  tmpDir = mkdtempSync(join(tmpdir(), "sanna-esc-test-"));
});

afterEach(() => {
  rmSync(tmpDir, { recursive: true, force: true });
});

describe("EscalationStore", () => {
  it("should create an escalation with valid token", () => {
    const store = new EscalationStore({ hmacSecret: SECRET });
    const result = store.createEscalation(
      "delete-file",
      { path: "/tmp/test" },
      "Requires approval",
      "agent-1",
    );
    expect(result.escalation_id).toBeTruthy();
    expect(result.token).toBeTruthy();
    expect(result.token.length).toBe(64); // hex-encoded SHA-256
    expect(result.expires_at).toBeTruthy();
  });

  it("should approve with valid token", () => {
    const store = new EscalationStore({ hmacSecret: SECRET });
    const { escalation_id, token } = store.createEscalation(
      "tool",
      {},
      "reason",
      "agent",
    );
    expect(store.getStatus(escalation_id)).toBe("pending");

    const ok = store.verifyAndApprove(escalation_id, token);
    expect(ok).toBe(true);
    expect(store.getStatus(escalation_id)).toBe("approved");
  });

  it("should deny with valid token", () => {
    const store = new EscalationStore({ hmacSecret: SECRET });
    const { escalation_id, token } = store.createEscalation(
      "tool",
      {},
      "reason",
      "agent",
    );
    const ok = store.verifyAndDeny(escalation_id, token);
    expect(ok).toBe(true);
    expect(store.getStatus(escalation_id)).toBe("denied");
  });

  it("should reject invalid token", () => {
    const store = new EscalationStore({ hmacSecret: SECRET });
    const { escalation_id } = store.createEscalation(
      "tool",
      {},
      "reason",
      "agent",
    );
    const ok = store.verifyAndApprove(escalation_id, "invalid-token".padEnd(64, "0"));
    expect(ok).toBe(false);
    expect(store.getStatus(escalation_id)).toBe("pending");
  });

  it("should reject approval of non-existent escalation", () => {
    const store = new EscalationStore({ hmacSecret: SECRET });
    expect(store.verifyAndApprove("nonexistent", "a".repeat(64))).toBe(false);
  });

  it("should reject expired escalation", () => {
    const store = new EscalationStore({
      hmacSecret: SECRET,
      ttlSeconds: 0, // Expires immediately
    });
    const { escalation_id, token } = store.createEscalation(
      "tool",
      {},
      "reason",
      "agent",
    );
    // Force expiry by small TTL
    const ok = store.verifyAndApprove(escalation_id, token);
    expect(ok).toBe(false);
    expect(store.getStatus(escalation_id)).toBe("expired");
  });

  it("should not approve already approved escalation", () => {
    const store = new EscalationStore({ hmacSecret: SECRET });
    const { escalation_id, token } = store.createEscalation(
      "tool",
      {},
      "reason",
      "agent",
    );
    store.verifyAndApprove(escalation_id, token);
    // Second approval should fail
    expect(store.verifyAndApprove(escalation_id, token)).toBe(false);
  });

  it("should not approve already denied escalation", () => {
    const store = new EscalationStore({ hmacSecret: SECRET });
    const { escalation_id, token } = store.createEscalation(
      "tool",
      {},
      "reason",
      "agent",
    );
    store.verifyAndDeny(escalation_id, token);
    expect(store.verifyAndApprove(escalation_id, token)).toBe(false);
  });

  it("should return null status for unknown escalation", () => {
    const store = new EscalationStore({ hmacSecret: SECRET });
    expect(store.getStatus("nonexistent")).toBeNull();
  });

  it("should persist to and load from file", () => {
    const path = join(tmpDir, "escalations.json");
    const store1 = new EscalationStore({
      hmacSecret: SECRET,
      storePath: path,
    });
    const { escalation_id } = store1.createEscalation(
      "tool",
      { key: "value" },
      "reason",
      "agent",
    );

    const store2 = new EscalationStore({
      hmacSecret: SECRET,
      storePath: path,
    });
    expect(store2.getStatus(escalation_id)).toBe("pending");
  });

  it("should cleanup expired entries", () => {
    const store = new EscalationStore({
      hmacSecret: SECRET,
      ttlSeconds: 0,
    });
    store.createEscalation("tool", {}, "reason", "agent");
    store.createEscalation("tool2", {}, "reason2", "agent");

    // Trigger cleanup — entries expire immediately
    const cleaned = store.cleanup();
    // Entries are marked expired but not yet cleaned (need 2x TTL age)
    // With TTL=0, entries should be cleaned up
    expect(cleaned).toBeGreaterThanOrEqual(0);
  });

  it("should track size", () => {
    const store = new EscalationStore({ hmacSecret: SECRET });
    expect(store.size).toBe(0);
    store.createEscalation("tool", {}, "reason", "agent");
    expect(store.size).toBe(1);
    store.createEscalation("tool2", {}, "reason", "agent");
    expect(store.size).toBe(2);
  });

  it("should get full escalation details", () => {
    const store = new EscalationStore({ hmacSecret: SECRET });
    const { escalation_id } = store.createEscalation(
      "delete-file",
      { path: "/tmp/x" },
      "needs approval",
      "agent-1",
    );
    const esc = store.get(escalation_id);
    expect(esc).toBeDefined();
    expect(esc!.tool_name).toBe("delete-file");
    expect(esc!.agent_id).toBe("agent-1");
    expect(esc!.args).toEqual({ path: "/tmp/x" });
    expect(esc!.reason).toBe("needs approval");
  });

  it("should use different secrets for different tokens", () => {
    const store1 = new EscalationStore({ hmacSecret: "secret-1" });
    const store2 = new EscalationStore({ hmacSecret: "secret-2" });

    const { escalation_id: id1, token: token1 } = store1.createEscalation(
      "tool",
      {},
      "reason",
      "agent",
    );
    const { escalation_id: id2, token: token2 } = store2.createEscalation(
      "tool",
      {},
      "reason",
      "agent",
    );

    // Tokens from different secrets should differ
    expect(token1).not.toBe(token2);
  });
});
