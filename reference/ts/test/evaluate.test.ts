// SAN-880 (mirrors tests/reference/test_evaluate.py from the Python
// reference, SAN-879): wrapper-gate ordering regression for evaluate().
//
// Locked A1 wrapper order: ... -> envelope_exceeded -> scan_incomplete ->
// basis_incomplete -> basis_unclassified -> basis_empty. envelope_exceeded
// must WIN over basis_empty: Stage X's context envelope limits are
// evaluated before the declared-tier basis_empty wrapper arm commits.

import assert from "node:assert/strict";
import { test } from "node:test";
import { T } from "../src/tables.js";
import { evaluate } from "../src/evaluate.js";

test("test_envelope_exceeded_wins_over_basis_empty_on_tier3_only_context", () => {
  // A tier_3-only context that breaches ENV_MAX_SENTENCES must report
  // envelope_exceeded for C1/C3/C4, not basis_empty (both fail closed;
  // this pins the audit reason).
  //
  // The Python test monkeypatches T.ENV_MAX_SENTENCES down to 3 to keep
  // the fixture small. tables.ts's `T` is deliberately immutable
  // (readonly fields, module-level singleton) so a shared-state
  // monkeypatch isn't available -- and isn't desirable, since mutating a
  // process-wide singleton mid-test-run risks bleeding into unrelated
  // tests. This port instead breaches the REAL ENV_MAX_SENTENCES cap
  // directly: same code path, same regression coverage, no shared-state
  // mutation.
  const ctxText = "Items are refundable. ".repeat(T.ENV_MAX_SENTENCES + 1);
  const result = evaluate({
    context_sources: [{ text: ctxText, tier: "tier_3" }],
    output: "Items are refundable.",
  });
  for (const cid of ["C1", "C3", "C4"]) {
    assert.equal(result[cid]!.outcome, "NOT_EVALUATED", cid);
    assert.equal(result[cid]!.outcome_reason, "envelope_exceeded", cid);
    assert.equal(result[cid]!.severity, null, cid);
  }
});
