// SAN-880 Phase 2: POISONED-METADATA tests proving that changes to
// `expected`, `notes`, `base_oracle`, variant fields (`variant_kind`,
// `variant_field`), and the original fixture `id` do NOT alter the
// semantic result diff_harness.ts / evaluate.ts compute. The harness
// reads `check_id` for record routing and echoes the caller-supplied `id`
// back for row identification (both legitimate), but evaluate() itself
// receives a freshly constructed object containing ONLY output and its
// context shape -- never id, check_id, expected, notes, base_oracle, or
// variant metadata (see diff_harness.ts's buildFixtureInput). This also
// exercises the PROHIBITED-behavior guard: no fixture-ID lookup tables or
// id-conditional behavior (an id shaped like a real synthetic matrix id
// must not trigger special-casing).

import assert from "node:assert/strict";
import { test } from "node:test";
import { run } from "../src/diff_harness.js";
import { Fixture, evaluate } from "../src/evaluate.js";

test("changing expected/notes/base_oracle/variant fields and the original id does not alter the semantic result", () => {
  const cleanContext = "Refunds require approval.";
  const cleanOutput = "Refunds are available.";
  const checkId = "C3";

  // Ground truth: what evaluate() actually produces for this context/
  // output pair (the flagship SAN-880/spec-section-9 violation vector).
  const truth = evaluate({ context: cleanContext, output: cleanOutput })[checkId]!;

  const baseRecord = {
    id: "flagship-violation",
    check_id: checkId,
    context: cleanContext,
    output: cleanOutput,
  };

  const poisonedRecord = {
    ...baseRecord,
    id: "totally-different-poisoned-id-000999",
    expected: { outcome: "PASS", outcome_reason: "detection_complete", severity: null }, // deliberately WRONG
    notes: "THIS NOTE CLAIMS A DIFFERENT OUTCOME AND MUST BE IGNORED BY THE HARNESS.",
    base_oracle: "some-other-oracle-that-does-not-exist",
    variant_kind: "case",
    variant_field: "output",
  };

  const [gotClean] = run([baseRecord]);
  const [gotPoisoned] = run([poisonedRecord]);

  // The semantic result (outcome/outcome_reason/severity/advisory) must
  // be identical regardless of the poisoned metadata, and must match
  // ground truth -- never the poisoned "expected" block.
  assert.equal(gotPoisoned!.outcome, gotClean!.outcome);
  assert.equal(gotPoisoned!.outcome_reason, gotClean!.outcome_reason);
  assert.equal(gotPoisoned!.severity, gotClean!.severity);
  assert.equal(gotPoisoned!.advisory, gotClean!.advisory);

  assert.equal(gotPoisoned!.outcome, truth.outcome);
  assert.equal(gotPoisoned!.outcome_reason, truth.outcome_reason);
  assert.equal(gotPoisoned!.severity, truth.severity);
  assert.equal(Boolean(gotPoisoned!.advisory), Boolean(truth.advisory));

  // Sanity: the poisoned "expected" block really was wrong (proves the
  // test is discriminating, not vacuously true).
  assert.notEqual(poisonedRecord.expected.outcome, truth.outcome);

  // The harness legitimately echoes back the CALLER-SUPPLIED id for row
  // identification -- correct behavior, not a leak of poisoned fields
  // into evaluation.
  assert.equal(gotPoisoned!.id, poisonedRecord.id);
});

test("a fixture id shaped like a real synthetic matrix id is never treated as an evaluation shortcut", () => {
  // PROHIBITED (SAN-880 hard constraint): "fixture-ID lookup tables or
  // any id-conditional behavior". An id that LOOKS like a real
  // matrix:<source>:<index>:<check> id, paired with a deliberately wrong
  // "expected" block and content that actually produces a VIOLATION, must
  // still evaluate purely from output/context content.
  const record = {
    id: "matrix:oracles:000000:C1",
    check_id: "C1",
    context: "Items are nonrefundable.",
    output: "Items are refundable.",
    expected: { outcome: "PASS", outcome_reason: "detection_complete", severity: null }, // deliberately WRONG
  };
  const [got] = run([record]);
  // Ground truth for this context/output: a direct antonym conflict.
  assert.equal(got!.outcome, "VIOLATION");
  assert.equal(got!.outcome_reason, "detection_complete");
  assert.equal(got!.severity, "critical");
});

test("evaluate() itself never reads any field beyond output and the declared context shape", () => {
  // Constructing the Fixture argument with extra (structurally foreign)
  // properties must not change the result. `Fixture`'s TypeScript shape
  // has no slot for id/check_id/expected/notes/base_oracle/variant_*, so
  // this also documents that evaluate()'s own signature cannot accept
  // poisoned metadata by construction; the `as Fixture` cast below
  // simulates a caller that bypasses that type boundary (e.g. from
  // untyped JSON) to prove the RUNTIME behavior is equally indifferent.
  const a = evaluate({ context: "Items are refundable.", output: "Items are refundable." });

  const poisoned: unknown = {
    context: "Items are refundable.",
    output: "Items are refundable.",
    id: "poisoned-id",
    check_id: "C4",
    notes: "ignored",
    base_oracle: "ignored",
    expected: { outcome: "VIOLATION", outcome_reason: "detection_complete", severity: "critical" },
  };
  const b = evaluate(poisoned as Fixture);

  assert.deepEqual(a, b);
});
