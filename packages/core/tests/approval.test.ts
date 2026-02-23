import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  createApprovalRequest,
  signApproval,
  verifyApproval,
  isApprovalExpired,
  ApprovalStore,
  generateKeypair,
  hashContent,
} from "../src/index.js";
import type { ApprovalRequest } from "../src/index.js";

let tmpDir: string;

beforeEach(() => {
  tmpDir = mkdtempSync(join(tmpdir(), "sanna-approval-test-"));
});

afterEach(() => {
  rmSync(tmpDir, { recursive: true, force: true });
});

const CONSTITUTION_HASH = "a".repeat(64);

describe("createApprovalRequest", () => {
  it("should create a request with default options", () => {
    const req = createApprovalRequest(CONSTITUTION_HASH, "alice@sanna.dev");
    expect(req.id).toBeTruthy();
    expect(req.constitution_hash).toBe(CONSTITUTION_HASH);
    expect(req.requester).toBe("alice@sanna.dev");
    expect(req.status).toBe("pending");
    expect(req.required_approvals).toBe(1);
    expect(req.approvals).toHaveLength(0);
    expect(new Date(req.expires_at).getTime()).toBeGreaterThan(Date.now());
  });

  it("should respect custom options", () => {
    const req = createApprovalRequest(CONSTITUTION_HASH, "bob@sanna.dev", {
      required_approvals: 3,
      expires_in_hours: 24,
    });
    expect(req.required_approvals).toBe(3);
    const expiresIn = new Date(req.expires_at).getTime() - new Date(req.requested_at).getTime();
    expect(expiresIn).toBeCloseTo(24 * 3600_000, -2);
  });

  it("should generate unique IDs", () => {
    const r1 = createApprovalRequest(CONSTITUTION_HASH, "user");
    const r2 = createApprovalRequest(CONSTITUTION_HASH, "user");
    expect(r1.id).not.toBe(r2.id);
  });
});

describe("signApproval", () => {
  it("should add a single approval", () => {
    const req = createApprovalRequest(CONSTITUTION_HASH, "requester");
    const kp = generateKeypair();
    signApproval(req, kp.privateKey);
    expect(req.approvals).toHaveLength(1);
    expect(req.approvals[0].approver_key_id).toBe(kp.keyId);
    expect(req.approvals[0].signature).toBeTruthy();
    expect(req.status).toBe("approved"); // 1 required, 1 signed
  });

  it("should not auto-approve when more signatures required", () => {
    const req = createApprovalRequest(CONSTITUTION_HASH, "requester", {
      required_approvals: 2,
    });
    const kp = generateKeypair();
    signApproval(req, kp.privateKey);
    expect(req.approvals).toHaveLength(1);
    expect(req.status).toBe("pending");
  });

  it("should auto-approve when threshold reached", () => {
    const req = createApprovalRequest(CONSTITUTION_HASH, "requester", {
      required_approvals: 2,
    });
    const kp1 = generateKeypair();
    const kp2 = generateKeypair();
    signApproval(req, kp1.privateKey);
    expect(req.status).toBe("pending");
    signApproval(req, kp2.privateKey);
    expect(req.status).toBe("approved");
    expect(req.approvals).toHaveLength(2);
  });

  it("should reject duplicate approvals from same key", () => {
    const req = createApprovalRequest(CONSTITUTION_HASH, "requester", {
      required_approvals: 2,
    });
    const kp = generateKeypair();
    signApproval(req, kp.privateKey);
    expect(() => signApproval(req, kp.privateKey)).toThrow("already signed");
  });

  it("should reject signing an already approved request", () => {
    const req = createApprovalRequest(CONSTITUTION_HASH, "requester");
    const kp1 = generateKeypair();
    signApproval(req, kp1.privateKey);
    expect(req.status).toBe("approved");
    const kp2 = generateKeypair();
    expect(() => signApproval(req, kp2.privateKey)).toThrow("approved");
  });

  it("should reject signing a rejected request", () => {
    const req = createApprovalRequest(CONSTITUTION_HASH, "requester");
    req.status = "rejected";
    const kp = generateKeypair();
    expect(() => signApproval(req, kp.privateKey)).toThrow("rejected");
  });
});

describe("verifyApproval", () => {
  it("should verify valid signatures", () => {
    const req = createApprovalRequest(CONSTITUTION_HASH, "requester");
    const kp = generateKeypair();
    signApproval(req, kp.privateKey);

    const keys = new Map([[kp.keyId, kp.publicKey]]);
    const result = verifyApproval(req, keys);
    expect(result.valid).toBe(true);
    expect(result.verified_count).toBe(1);
    expect(result.required_count).toBe(1);
    expect(result.details).toHaveLength(1);
    expect(result.details[0].signature_valid).toBe(true);
  });

  it("should verify multi-approver signatures", () => {
    const req = createApprovalRequest(CONSTITUTION_HASH, "requester", {
      required_approvals: 2,
    });
    const kp1 = generateKeypair();
    const kp2 = generateKeypair();
    signApproval(req, kp1.privateKey);
    signApproval(req, kp2.privateKey);

    const keys = new Map([
      [kp1.keyId, kp1.publicKey],
      [kp2.keyId, kp2.publicKey],
    ]);
    const result = verifyApproval(req, keys);
    expect(result.valid).toBe(true);
    expect(result.verified_count).toBe(2);
  });

  it("should fail when public key not provided", () => {
    const req = createApprovalRequest(CONSTITUTION_HASH, "requester");
    const kp = generateKeypair();
    signApproval(req, kp.privateKey);

    const result = verifyApproval(req, new Map());
    expect(result.valid).toBe(false);
    expect(result.verified_count).toBe(0);
    expect(result.details[0].error).toContain("not found");
  });

  it("should fail with wrong public key", () => {
    const req = createApprovalRequest(CONSTITUTION_HASH, "requester");
    const kp1 = generateKeypair();
    const kp2 = generateKeypair();
    signApproval(req, kp1.privateKey);

    // Provide wrong key for the approver's key_id
    const keys = new Map([[kp1.keyId, kp2.publicKey]]);
    const result = verifyApproval(req, keys);
    expect(result.valid).toBe(false);
    expect(result.details[0].signature_valid).toBe(false);
  });

  it("should fail when insufficient approvals verified", () => {
    const req = createApprovalRequest(CONSTITUTION_HASH, "requester", {
      required_approvals: 2,
    });
    const kp1 = generateKeypair();
    const kp2 = generateKeypair();
    signApproval(req, kp1.privateKey);
    signApproval(req, kp2.privateKey);

    // Only provide one key
    const keys = new Map([[kp1.keyId, kp1.publicKey]]);
    const result = verifyApproval(req, keys);
    expect(result.valid).toBe(false);
    expect(result.verified_count).toBe(1);
    expect(result.required_count).toBe(2);
  });
});

describe("isApprovalExpired", () => {
  it("should return false for non-expired request", () => {
    const req = createApprovalRequest(CONSTITUTION_HASH, "requester");
    expect(isApprovalExpired(req)).toBe(false);
  });

  it("should return true for expired request", () => {
    const req = createApprovalRequest(CONSTITUTION_HASH, "requester");
    req.expires_at = new Date(Date.now() - 1000).toISOString();
    expect(isApprovalExpired(req)).toBe(true);
  });

  it("should prevent signing expired request", () => {
    const req = createApprovalRequest(CONSTITUTION_HASH, "requester");
    req.expires_at = new Date(Date.now() - 1000).toISOString();
    const kp = generateKeypair();
    expect(() => signApproval(req, kp.privateKey)).toThrow("expired");
    expect(req.status).toBe("expired");
  });
});

describe("ApprovalStore", () => {
  it("should save and retrieve a request", () => {
    const store = new ApprovalStore();
    const req = createApprovalRequest(CONSTITUTION_HASH, "requester");
    store.save(req);
    const retrieved = store.get(req.id);
    expect(retrieved).toBeDefined();
    expect(retrieved!.id).toBe(req.id);
  });

  it("should return undefined for unknown ID", () => {
    const store = new ApprovalStore();
    expect(store.get("nonexistent")).toBeUndefined();
  });

  it("should list with filters", () => {
    const store = new ApprovalStore();
    const r1 = createApprovalRequest("hash1", "alice");
    const r2 = createApprovalRequest("hash2", "bob");
    r2.status = "approved";
    store.save(r1);
    store.save(r2);

    expect(store.list()).toHaveLength(2);
    expect(store.list({ status: "pending" })).toHaveLength(1);
    expect(store.list({ requester: "alice" })).toHaveLength(1);
    expect(store.list({ constitution_hash: "hash2" })).toHaveLength(1);
  });

  it("should update status", () => {
    const store = new ApprovalStore();
    const req = createApprovalRequest(CONSTITUTION_HASH, "requester");
    store.save(req);
    expect(store.updateStatus(req.id, "rejected")).toBe(true);
    expect(store.get(req.id)!.status).toBe("rejected");
  });

  it("should return false for updating unknown ID", () => {
    const store = new ApprovalStore();
    expect(store.updateStatus("nonexistent", "rejected")).toBe(false);
  });

  it("should persist to and load from file", () => {
    const filePath = join(tmpDir, "approvals.json");
    const store1 = new ApprovalStore(filePath);
    const req = createApprovalRequest(CONSTITUTION_HASH, "requester");
    store1.save(req);

    const store2 = new ApprovalStore(filePath);
    const retrieved = store2.get(req.id);
    expect(retrieved).toBeDefined();
    expect(retrieved!.requester).toBe("requester");
  });
});
