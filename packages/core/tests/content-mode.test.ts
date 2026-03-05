/**
 * Tests for content_mode and content_mode_source metadata fields.
 * These fields do NOT participate in the fingerprint.
 */

import { describe, it, expect } from "vitest";
import { generateReceipt, computeFingerprints } from "../src/receipt.js";

describe("content_mode metadata", () => {
  const baseParams = {
    correlation_id: "cm-001",
    inputs: { query: "test" },
    outputs: { response: "test" },
    checks: [{ check_id: "C1", passed: true, severity: "info" as const, evidence: null }],
  };

  it("content_mode included when provided", () => {
    const receipt = generateReceipt({
      ...baseParams,
      content_mode: "full",
    });
    expect(receipt.content_mode).toBe("full");
  });

  it("content_mode_source included when provided", () => {
    const receipt = generateReceipt({
      ...baseParams,
      content_mode_source: "local_config",
    });
    expect(receipt.content_mode_source).toBe("local_config");
  });

  it("content_mode absent when not provided", () => {
    const receipt = generateReceipt(baseParams);
    expect(receipt.content_mode).toBeUndefined();
    expect(receipt.content_mode_source).toBeUndefined();
  });

  it("content_mode=redacted works", () => {
    const receipt = generateReceipt({
      ...baseParams,
      content_mode: "redacted",
    });
    expect(receipt.content_mode).toBe("redacted");
  });

  it("content_mode=hashes_only works", () => {
    const receipt = generateReceipt({
      ...baseParams,
      content_mode: "hashes_only",
    });
    expect(receipt.content_mode).toBe("hashes_only");
  });

  it("content_mode=null is treated as absent", () => {
    const receipt = generateReceipt({
      ...baseParams,
      content_mode: null,
    });
    expect(receipt.content_mode).toBeUndefined();
  });

  it("content_mode does NOT affect fingerprint", () => {
    const r1 = generateReceipt(baseParams);
    const r2 = generateReceipt({ ...baseParams, content_mode: "redacted" });
    const r3 = generateReceipt({ ...baseParams, content_mode: "hashes_only" });

    // Fingerprints computed on same base data should match
    const base = {
      correlation_id: baseParams.correlation_id,
      context_hash: r1.context_hash,
      output_hash: r1.output_hash,
      checks_version: r1.checks_version,
      checks: r1.checks,
    };
    const fp = computeFingerprints(base);
    const fp2 = computeFingerprints({ ...base, content_mode: "redacted" });
    const fp3 = computeFingerprints({ ...base, content_mode: "hashes_only" });

    expect(fp.full_fingerprint).toBe(fp2.full_fingerprint);
    expect(fp.full_fingerprint).toBe(fp3.full_fingerprint);
  });

  it("content_mode_source does NOT affect fingerprint", () => {
    const base = {
      correlation_id: "cm-fp-test",
      context_hash: "a".repeat(64),
      output_hash: "b".repeat(64),
      checks_version: "6",
      checks: [],
    };
    const fp1 = computeFingerprints(base);
    const fp2 = computeFingerprints({ ...base, content_mode_source: "cloud_policy" });
    expect(fp1.full_fingerprint).toBe(fp2.full_fingerprint);
  });

  it("both content_mode and content_mode_source can be set together", () => {
    const receipt = generateReceipt({
      ...baseParams,
      content_mode: "full",
      content_mode_source: "local_config",
    });
    expect(receipt.content_mode).toBe("full");
    expect(receipt.content_mode_source).toBe("local_config");
  });

  it("content_mode present alongside parent_receipts and workflow_id", () => {
    const receipt = generateReceipt({
      ...baseParams,
      parent_receipts: ["fp-1"],
      workflow_id: "wf-001",
      content_mode: "redacted",
      content_mode_source: "gateway",
    });
    expect(receipt.parent_receipts).toEqual(["fp-1"]);
    expect(receipt.workflow_id).toBe("wf-001");
    expect(receipt.content_mode).toBe("redacted");
    expect(receipt.content_mode_source).toBe("gateway");
  });
});
