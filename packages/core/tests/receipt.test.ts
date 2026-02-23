import { describe, it, expect } from "vitest";
import { resolve } from "node:path";
import { readFileSync } from "node:fs";
import {
  generateReceipt,
  signReceipt,
  computeFingerprints,
  SPEC_VERSION,
  CHECKS_VERSION,
} from "../src/receipt.js";
import { loadPrivateKey, loadPublicKey } from "../src/crypto.js";
import { verify } from "../src/crypto.js";
import { canonicalize } from "../src/hashing.js";

const FIXTURES = resolve(__dirname, "../../../spec/fixtures");
const golden = JSON.parse(readFileSync(resolve(FIXTURES, "golden-hashes.json"), "utf-8"));
const privKey = loadPrivateKey(resolve(FIXTURES, "keypairs/test-author.key"));
const pubKey = loadPublicKey(resolve(FIXTURES, "keypairs/test-author.pub"));

// ── generateReceipt ──────────────────────────────────────────────────

describe("generateReceipt", () => {
  const receipt = generateReceipt({
    correlation_id: "test-001",
    inputs: { query: "What is 2+2?", context: "Math" },
    outputs: { response: "4" },
    checks: [
      {
        check_id: "C1",
        name: "Context Contradiction",
        passed: true,
        severity: "info",
        evidence: null,
      },
    ],
  });

  it("has correct spec_version", () => {
    expect(receipt.spec_version).toBe(SPEC_VERSION);
  });

  it("has correct checks_version", () => {
    expect(receipt.checks_version).toBe(CHECKS_VERSION);
  });

  it("generates UUID v4 receipt_id", () => {
    const uuid4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
    expect(receipt.receipt_id).toMatch(uuid4);
  });

  it("computes context_hash and output_hash", () => {
    expect(receipt.context_hash).toHaveLength(64);
    expect(receipt.output_hash).toHaveLength(64);
  });

  it("computes fingerprints", () => {
    expect(receipt.receipt_fingerprint).toHaveLength(16);
    expect(receipt.full_fingerprint).toHaveLength(64);
  });

  it("counts checks correctly", () => {
    expect(receipt.checks_passed).toBe(1);
    expect(receipt.checks_failed).toBe(0);
    expect(receipt.status).toBe("PASS");
  });

  it("auto-detects FAIL status", () => {
    const failReceipt = generateReceipt({
      correlation_id: "test-fail",
      inputs: { query: "test" },
      outputs: { response: "test" },
      checks: [
        { check_id: "C1", passed: false, severity: "critical", evidence: "bad" },
      ],
    });
    expect(failReceipt.status).toBe("FAIL");
  });

  it("includes optional fields when provided", () => {
    const r = generateReceipt({
      correlation_id: "test-full",
      inputs: { q: "x" },
      outputs: { r: "y" },
      checks: [{ check_id: "C1", passed: true, severity: "info", evidence: null }],
      enforcement: { action: "allowed", reason: "ok", failed_checks: [], enforcement_mode: "log", timestamp: "2026-01-01T00:00:00Z" },
      extensions: { "com.test": { val: 1 } },
    });
    expect(r.enforcement).toBeDefined();
    expect(r.extensions).toBeDefined();
  });
});

// ── Fingerprint determinism ──────────────────────────────────────────

describe("fingerprint determinism", () => {
  it("same inputs produce same fingerprint", () => {
    const base = {
      correlation_id: "det-001",
      context_hash: "aaaa".repeat(16),
      output_hash: "bbbb".repeat(16),
      checks_version: "5",
      checks: [{ check_id: "C1", passed: true, severity: "info", evidence: null }],
    };
    const fp1 = computeFingerprints(base);
    const fp2 = computeFingerprints(base);
    expect(fp1.receipt_fingerprint).toBe(fp2.receipt_fingerprint);
    expect(fp1.full_fingerprint).toBe(fp2.full_fingerprint);
  });

  it("different correlation_id changes fingerprint", () => {
    const base = {
      correlation_id: "det-001",
      context_hash: "aaaa".repeat(16),
      output_hash: "bbbb".repeat(16),
      checks_version: "5",
      checks: [],
    };
    const fp1 = computeFingerprints(base);
    const fp2 = computeFingerprints({ ...base, correlation_id: "det-002" });
    expect(fp1.receipt_fingerprint).not.toBe(fp2.receipt_fingerprint);
  });
});

// ── signReceipt ──────────────────────────────────────────────────────

describe("signReceipt", () => {
  it("adds valid receipt_signature block", () => {
    const receipt = generateReceipt({
      correlation_id: "sign-test",
      inputs: { query: "test" },
      outputs: { response: "test" },
      checks: [{ check_id: "C1", passed: true, severity: "info", evidence: null }],
    }) as unknown as Record<string, unknown>;

    signReceipt(receipt, privKey, "test@sanna.dev");

    const sig = receipt.receipt_signature as Record<string, unknown>;
    expect(sig).toBeDefined();
    expect(sig.signature).toBeTruthy();
    expect(sig.key_id).toBe(golden.test_key_id);
    expect(sig.scheme).toBe("receipt_sig_v1");
    expect(sig.signed_by).toBe("test@sanna.dev");
  });

  it("signature verifies with public key", () => {
    const receipt = generateReceipt({
      correlation_id: "sign-verify",
      inputs: { query: "test" },
      outputs: { response: "test" },
      checks: [{ check_id: "C1", passed: true, severity: "info", evidence: null }],
    }) as unknown as Record<string, unknown>;

    signReceipt(receipt, privKey, "test@sanna.dev");

    // Reconstruct signable form
    const signable = structuredClone(receipt);
    (signable.receipt_signature as Record<string, unknown>).signature = "";
    const canonical = canonicalize(signable);
    const data = Buffer.from(canonical, "utf-8");
    const sig = (receipt.receipt_signature as Record<string, unknown>).signature as string;

    expect(verify(data, sig, pubKey)).toBe(true);
  });
});
