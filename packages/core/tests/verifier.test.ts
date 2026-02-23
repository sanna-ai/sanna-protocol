import { describe, it, expect } from "vitest";
import { resolve } from "node:path";
import { readFileSync } from "node:fs";
import { verifyReceipt } from "../src/verifier.js";
import { loadPublicKey } from "../src/crypto.js";
import { generateReceipt, signReceipt } from "../src/receipt.js";
import { loadPrivateKey } from "../src/crypto.js";

const FIXTURES = resolve(__dirname, "../../../spec/fixtures");
const pubKey = loadPublicKey(resolve(FIXTURES, "keypairs/test-author.pub"));
const privKey = loadPrivateKey(resolve(FIXTURES, "keypairs/test-author.key"));

// ── Helper: create and sign a valid receipt ──────────────────────────

function makeSignedReceipt(): Record<string, unknown> {
  const receipt = generateReceipt({
    correlation_id: "verify-test-001",
    inputs: { query: "What is 2+2?", context: "Math" },
    outputs: { response: "4" },
    checks: [
      { check_id: "C1", passed: true, severity: "info", evidence: null },
    ],
  }) as unknown as Record<string, unknown>;
  signReceipt(receipt, privKey, "test@sanna.dev");
  return receipt;
}

// ── Verify valid receipt ─────────────────────────────────────────────

describe("verifyReceipt — valid receipt", () => {
  it("passes all checks for a freshly signed receipt", () => {
    const receipt = makeSignedReceipt();
    const result = verifyReceipt(receipt, pubKey);
    expect(result.valid).toBe(true);
    expect(result.errors).toEqual([]);
    expect(result.checks_performed).toContain("schema");
    expect(result.checks_performed).toContain("signature");
    expect(result.checks_performed).toContain("fingerprint");
    expect(result.checks_performed).toContain("content_hashes");
    expect(result.checks_performed).toContain("status_consistency");
    expect(result.checks_performed).toContain("timestamp");
  });
});

// ── Tampered receipts ────────────────────────────────────────────────

describe("verifyReceipt — tampered receipts", () => {
  it("detects modified field (breaks signature + fingerprint)", () => {
    const receipt = makeSignedReceipt();
    receipt.correlation_id = "tampered-id";
    const result = verifyReceipt(receipt, pubKey);
    expect(result.valid).toBe(false);
    expect(result.errors.length).toBeGreaterThan(0);
  });

  it("detects wrong signature", () => {
    const receipt = makeSignedReceipt();
    const sig = receipt.receipt_signature as Record<string, unknown>;
    // Corrupt the signature
    sig.signature = "AAAA" + (sig.signature as string).slice(4);
    const result = verifyReceipt(receipt, pubKey);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes("signature"))).toBe(true);
  });

  it("detects bad fingerprint", () => {
    const receipt = makeSignedReceipt();
    receipt.receipt_fingerprint = "0000000000000000";
    const result = verifyReceipt(receipt, pubKey);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes("Fingerprint"))).toBe(true);
  });

  it("detects tampered inputs (content hash mismatch)", () => {
    const receipt = makeSignedReceipt();
    (receipt.inputs as Record<string, unknown>).query = "tampered query";
    const result = verifyReceipt(receipt, pubKey);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes("context_hash"))).toBe(true);
  });

  it("detects checks_passed count mismatch", () => {
    const receipt = makeSignedReceipt();
    receipt.checks_passed = 99;
    const result = verifyReceipt(receipt, pubKey);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes("checks_passed"))).toBe(true);
  });
});

// ── Without public key ───────────────────────────────────────────────

describe("verifyReceipt — no public key", () => {
  it("skips signature check, warns about missing key", () => {
    const receipt = makeSignedReceipt();
    const result = verifyReceipt(receipt);
    expect(result.valid).toBe(true);
    expect(result.checks_performed).not.toContain("signature");
    expect(result.warnings.some((w) => w.includes("no public key"))).toBe(true);
  });
});

// ── Schema validation ────────────────────────────────────────────────

describe("verifyReceipt — schema errors", () => {
  it("catches missing required fields", () => {
    const result = verifyReceipt({ receipt_id: "not-a-uuid" });
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes("Missing required field"))).toBe(true);
  });
});
