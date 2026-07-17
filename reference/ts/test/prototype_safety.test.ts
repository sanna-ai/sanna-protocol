// SAN-880 amendment (review round 2): regression tests for the
// prototype-pollution-shaped crash fixed in reference/ts/src/tables.ts.
// JSON-parsed objects inherit Object.prototype, so a plain bracket
// lookup keyed by an INPUT-DERIVED string (e.g. a tokenized word) could
// resolve an inherited Object.prototype member instead of missing. The
// word "constructor" is the concrete word-reachable collision: before
// the fix, `T.contractionsV1["constructor"]` returned the inherited
// Object constructor function (not undefined), which crashed
// tokenize()'s contraction-expansion loop (`for (const word of
// expansion)` -- a Function is not iterable), and
// `T.unitsV1["constructor"]` likewise returned a Function, which is not
// nullish, so `?? null` in unitOf() did not convert it to null.
//
// The fix makes all six Record-typed tables in tables.ts (unitsV1,
// currencySymbolsV1, facetsV1, facetprojV1, contractionsV1, conceptV1)
// null-prototype copies at construction, so every bracket lookup on
// them misses cleanly (undefined) regardless of the key's relationship
// to Object.prototype's own member names.
//
// No Python counterpart: this is a JavaScript/JSON-specific hazard that
// does not exist for Python dict.get() lookups.

import assert from "node:assert/strict";
import { test } from "node:test";
import { run } from "../src/diff_harness.js";
import { T } from "../src/tables.js";
import { tokenize, unitOf } from "../src/primitives.js";

const CHECK_IDS = ["C1", "C2", "C3", "C4"] as const;

test("all six Record-typed reference tables are null-prototype", () => {
  assert.equal(Object.getPrototypeOf(T.unitsV1), null);
  assert.equal(Object.getPrototypeOf(T.currencySymbolsV1), null);
  assert.equal(Object.getPrototypeOf(T.facetsV1), null);
  assert.equal(Object.getPrototypeOf(T.facetprojV1), null);
  assert.equal(Object.getPrototypeOf(T.contractionsV1), null);
  assert.equal(Object.getPrototypeOf(T.conceptV1), null);
});

test("tokenize() does not throw on input containing the word constructor", () => {
  assert.doesNotThrow(() => tokenize("The constructor is available."));
});

test("unitOf() returns null (not the inherited Object constructor) for the WORD token constructor", () => {
  const toks = tokenize("5 constructor");
  const wordTok = toks.find((t) => t.kind === "WORD");
  assert.ok(wordTok, "expected a WORD token in \"5 constructor\"");
  assert.equal(wordTok!.raw, "constructor");
  assert.equal(unitOf(wordTok!), null);
});

test("evaluate through run() over context/output containing constructor: all four checks PASS cleanly (contraction-expansion path)", () => {
  const context = "Items are refundable.";
  const output = "The constructor is available.";
  const records = CHECK_IDS.map((checkId) => ({
    id: `prototype-safety-contraction-${checkId}`,
    check_id: checkId,
    context,
    output,
  }));
  const results = run(records);
  assert.equal(results.length, 4);
  for (const checkId of CHECK_IDS) {
    const got = results.find((r) => r.check_id === checkId);
    assert.ok(got, `missing result for ${checkId}`);
    assert.equal(got!.outcome, "PASS", `${checkId} outcome`);
    assert.equal(got!.outcome_reason, "detection_complete", `${checkId} outcome_reason`);
    assert.equal(got!.severity, null, `${checkId} severity`);
    assert.equal(got!.advisory, false, `${checkId} advisory`);
  }
});

test("evaluate through run() over context/output containing constructor: all four checks PASS cleanly (unitOf path)", () => {
  const context = "Items are refundable.";
  const output = "Refunds arrive within 5 constructor of purchase.";
  const records = CHECK_IDS.map((checkId) => ({
    id: `prototype-safety-unitof-${checkId}`,
    check_id: checkId,
    context,
    output,
  }));
  const results = run(records);
  assert.equal(results.length, 4);
  for (const checkId of CHECK_IDS) {
    const got = results.find((r) => r.check_id === checkId);
    assert.ok(got, `missing result for ${checkId}`);
    assert.equal(got!.outcome, "PASS", `${checkId} outcome`);
    assert.equal(got!.outcome_reason, "detection_complete", `${checkId} outcome_reason`);
    assert.equal(got!.severity, null, `${checkId} severity`);
    assert.equal(got!.advisory, false, `${checkId} advisory`);
  }
});
