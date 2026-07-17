// Unit tests for src/extraction.ts adjunctModifiers' spec 3.2
// facet-trigger abstain arm (SAN-894, mirrors tests/reference/
// test_extraction.py from the Python reference): a facet trigger folded
// sequence inside an adjunct group must abstain the field to PARTIAL. The
// nested-adjunct arm of the same spec clause is a separate, pre-existing
// divergence tracked as SAN-897 and is out of scope here.
//
// Test titles intentionally match their Python counterpart's function name
// (see reference/ts/TEST-COVERAGE.md) for direct traceability.

import assert from "node:assert/strict";
import { test } from "node:test";
import { extractFrames } from "../src/extraction.js";

test("test_adjunct_group_facet_trigger_abstains_to_partial", () => {
  const [, partial] = extractFrames("context", "Refunds for available items are refundable.");
  assert.equal(partial, true);
});

test("test_adjunct_group_deny_trigger_abstains_to_partial", () => {
  const [, partial] = extractFrames("output", "Refunds for banned items are available.", true);
  assert.equal(partial, true);
});

test("test_adjunct_group_without_trigger_extracts_fully", () => {
  const [frames, partial] = extractFrames("context", "Refunds for physical items are refundable.");
  assert.equal(partial, false);
  assert.equal(frames.length, 1);
  const modifiers = frames[0]!.extent.modifiers.toArray();
  const found = modifiers.some(
    (p) => p.rel === "for" && p.objset.size === 2 && p.objset.has("physical") && p.objset.has("item"),
  );
  assert.ok(found);
});
