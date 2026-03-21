import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { EMPTY_HASH, hashContent, hashObj } from "../src/hashing.js";

const FIXTURES = resolve(__dirname, "fixtures");
const vectors = JSON.parse(
  readFileSync(resolve(FIXTURES, "fingerprint-edge-cases.json"), "utf-8"),
);

describe("fingerprint edge case vectors", () => {
  describe("EMPTY_HASH constant", () => {
    it("matches the value in the vectors file", () => {
      expect(EMPTY_HASH).toBe(vectors.EMPTY_HASH);
    });
  });

  describe("checks_hash", () => {
    const checksVectors = vectors.vectors.checks_hash;

    it("empty array returns EMPTY_HASH", () => {
      const input = checksVectors.empty_array.input as unknown[];
      const hash = input.length > 0 ? hashObj(input) : EMPTY_HASH;
      expect(hash).toBe(checksVectors.empty_array.expected_hash);
    });

    it("null checks returns EMPTY_HASH", () => {
      const input = checksVectors.null_checks.input;
      const checks = input ?? [];
      const hash = (checks as unknown[]).length > 0 ? hashObj(checks) : EMPTY_HASH;
      expect(hash).toBe(checksVectors.null_checks.expected_hash);
    });

    it("non-empty 4-field checks hashes correctly", () => {
      const input = checksVectors.non_empty_4_fields.input as Record<string, unknown>[];
      const hasEnforcementFields = input.some((c) => c.triggered_by !== undefined);
      let checksData: Record<string, unknown>[];
      if (hasEnforcementFields) {
        checksData = input.map((c) => ({
          check_id: c.check_id ?? "",
          passed: c.passed,
          severity: c.severity ?? "",
          evidence: c.evidence ?? null,
          triggered_by: c.triggered_by ?? null,
          enforcement_level: c.enforcement_level ?? null,
          check_impl: c.check_impl ?? null,
          replayable: c.replayable ?? null,
        }));
      } else {
        checksData = input.map((c) => ({
          check_id: c.check_id ?? "",
          passed: c.passed,
          severity: c.severity ?? "",
          evidence: c.evidence ?? null,
        }));
      }
      const hash = checksData.length > 0 ? hashObj(checksData) : EMPTY_HASH;
      expect(hash).toBe(checksVectors.non_empty_4_fields.expected_hash);
    });
  });

  describe("workflow_id_hash", () => {
    const wfVectors = vectors.vectors.workflow_id_hash;

    it("null returns EMPTY_HASH", () => {
      const input = wfVectors.null_value.input;
      const hash = input != null ? hashContent(input, 64) : EMPTY_HASH;
      expect(hash).toBe(wfVectors.null_value.expected_hash);
    });

    it("empty string returns EMPTY_HASH", () => {
      const input = wfVectors.empty_string.input as string;
      const hash = input != null ? hashContent(input, 64) : EMPTY_HASH;
      expect(hash).toBe(wfVectors.empty_string.expected_hash);
    });

    it("non-empty string hashes correctly", () => {
      const input = wfVectors.non_empty.input as string;
      const hash = input != null ? hashContent(input, 64) : EMPTY_HASH;
      expect(hash).toBe(wfVectors.non_empty.expected_hash);
    });
  });

  describe("check_enforcement_fields", () => {
    const enfVectors = vectors.vectors.check_enforcement_fields;

    function buildChecksData(input: Record<string, unknown>[]): Record<string, unknown>[] {
      const hasEnforcementFields = input.some((c) => c.triggered_by !== undefined);
      if (hasEnforcementFields) {
        return input.map((c) => ({
          check_id: c.check_id ?? "",
          passed: c.passed,
          severity: c.severity ?? "",
          evidence: c.evidence ?? null,
          triggered_by: c.triggered_by ?? null,
          enforcement_level: c.enforcement_level ?? null,
          check_impl: c.check_impl ?? null,
          replayable: c.replayable ?? null,
        }));
      }
      return input.map((c) => ({
        check_id: c.check_id ?? "",
        passed: c.passed,
        severity: c.severity ?? "",
        evidence: c.evidence ?? null,
      }));
    }

    it("without enforcement fields hashes 4 fields per check", () => {
      const input = enfVectors.without_enforcement.input as Record<string, unknown>[];
      const checksData = buildChecksData(input);
      const hash = checksData.length > 0 ? hashObj(checksData) : EMPTY_HASH;
      expect(hash).toBe(enfVectors.without_enforcement.expected_hash);
    });

    it("with enforcement fields hashes 8 fields per check", () => {
      const input = enfVectors.with_enforcement.input as Record<string, unknown>[];
      const checksData = buildChecksData(input);
      const hash = checksData.length > 0 ? hashObj(checksData) : EMPTY_HASH;
      expect(hash).toBe(enfVectors.with_enforcement.expected_hash);
    });

    it("mixed enforcement: all checks use 8-field mode", () => {
      const input = enfVectors.mixed_enforcement.input as Record<string, unknown>[];
      const checksData = buildChecksData(input);
      const hash = checksData.length > 0 ? hashObj(checksData) : EMPTY_HASH;
      expect(hash).toBe(enfVectors.mixed_enforcement.expected_hash);
    });
  });
});
