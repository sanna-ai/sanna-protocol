// SAN-880 (mirrors tests/reference/test_oracles.py from the Python
// reference, SAN-879): loads oracles.json and generated.json (the SAME
// files the Python reference's fixtures live in -- there is exactly one
// fixture corpus, not a TypeScript-side copy) and asserts every
// hand-pinned expected tuple exactly, plus per-record live reproduction
// of every generated fixture and internal cross-consistency between
// generated.json and its base oracles.
//
// reference/generate_fixtures.py itself (the surface-variant generator
// that PRODUCES generated.json from oracles.json) is a Python-only
// harness concern per the SAN-880 module-mirroring list and is not
// ported -- see TEST-COVERAGE.md's mapping for
// test_generated_fixtures_regeneration_is_byte_identical.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { test } from "node:test";
import { Fixture, evaluate } from "../src/evaluate.js";

// Compiled to reference/ts/dist/test/oracles.test.js; the shared fixture
// corpus lives at reference/fixtures/ -- three levels up from dist/test/
// (dist/test -> dist -> ts -> reference, then + fixtures/).
const TEST_DIR = path.dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = path.resolve(TEST_DIR, "../../../fixtures");
const ORACLES_PATH = path.join(FIXTURES_DIR, "oracles.json");
const GENERATED_PATH = path.join(FIXTURES_DIR, "generated.json");

interface ExpectedTuple {
  readonly outcome: string;
  readonly outcome_reason: string;
  readonly severity: string | null;
  readonly advisory?: boolean;
}

interface FixtureRecord {
  readonly id: string;
  readonly check_id: string;
  readonly output: string;
  readonly context?: string;
  readonly context_sources?: { text: string; tier?: string }[];
  readonly context_repeat?: { text: string; count: number };
  readonly expected: ExpectedTuple;
  readonly base_oracle?: string;
}

const ORACLES: FixtureRecord[] = JSON.parse(readFileSync(ORACLES_PATH, "utf-8"));
const GENERATED: FixtureRecord[] = JSON.parse(readFileSync(GENERATED_PATH, "utf-8"));

function fixtureInput(record: FixtureRecord): Fixture {
  if (record.context_sources !== undefined) {
    return { output: record.output, context_sources: record.context_sources };
  }
  if (record.context_repeat !== undefined) {
    return { output: record.output, context_repeat: record.context_repeat };
  }
  return { output: record.output, context: record.context ?? "" };
}

function assertMatchesExpected(got: { outcome: string; outcome_reason: string; severity: string | null; advisory: boolean }, expected: ExpectedTuple, id: string): void {
  assert.equal(got.outcome, expected.outcome, `${id}: outcome`);
  assert.equal(got.outcome_reason, expected.outcome_reason, `${id}: outcome_reason`);
  assert.equal(got.severity, expected.severity, `${id}: severity`);
  assert.equal(Boolean(got.advisory), Boolean(expected.advisory), `${id}: advisory`);
}

test("test_oracle_expected_tuple_exact", async (t) => {
  // Every hand-pinned oracle's COMPLETE expected tuple {outcome,
  // outcome_reason, severity} (+ the C1 advisory flag, implicitly pinned
  // False when absent) must be reproduced exactly. These are hand-pinned;
  // if the implementation cannot reach one, that is a reference-
  // implementation bug, never a reason to adjust the oracle.
  for (const oracle of ORACLES) {
    await t.test(oracle.id, () => {
      const result = evaluate(fixtureInput(oracle));
      const got = result[oracle.check_id];
      assert.ok(got, `${oracle.id}: no result for check_id ${oracle.check_id}`);
      assertMatchesExpected(got!, oracle.expected, oracle.id);
    });
  }
});

test("test_every_oracle_binds_the_complete_tuple", () => {
  // Every oracle JSON record must explicitly carry severity (null for
  // PASS/NOT_EVALUATED rows), never omit the field. `advisory` is the
  // only optional extra key (C1 row-9 fixtures).
  const REQUIRED = ["outcome", "outcome_reason", "severity"];
  const ALLOWED = new Set(["outcome", "outcome_reason", "severity", "advisory"]);
  for (const oracle of ORACLES) {
    const keys = Object.keys(oracle.expected);
    for (const required of REQUIRED) {
      assert.ok(keys.includes(required), `${oracle.id} missing required key ${required}`);
    }
    for (const k of keys) {
      assert.ok(ALLOWED.has(k), `${oracle.id} has disallowed key ${k}`);
    }
  }
});

test("test_generated_fixtures_file_exists_and_is_nonempty", () => {
  assert.ok(GENERATED.length > 0);
});

test("test_generated_fixture_variants_match_their_base_oracle", () => {
  // Spec: surface variants (casing / whitespace / contraction swaps) MUST
  // yield identical results to their base oracle. This is a pure
  // fixture-file self-consistency check (comparing the two files'
  // recorded "expected" blocks against each other), independent of
  // live evaluate() re-derivation -- see the next test for that.
  const oraclesById = new Map(ORACLES.map((o) => [o.id, o]));
  for (const rec of GENERATED) {
    assert.ok(rec.base_oracle, `${rec.id}: missing base_oracle`);
    const base = oraclesById.get(rec.base_oracle!);
    assert.ok(base, `${rec.id}: unknown base_oracle ${rec.base_oracle}`);
    assert.deepEqual(rec.expected, base!.expected, rec.id);
  }
});

test("test_generated_fixture_reproduces_live", async (t) => {
  // Each generated fixture, re-evaluated live against the current
  // TypeScript implementation, matches its recorded expected tuple
  // exactly.
  for (const rec of GENERATED) {
    await t.test(rec.id, () => {
      const result = evaluate(fixtureInput(rec));
      const got = result[rec.check_id];
      assert.ok(got, `${rec.id}: no result for check_id ${rec.check_id}`);
      assertMatchesExpected(got!, rec.expected, rec.id);
    });
  }
});
