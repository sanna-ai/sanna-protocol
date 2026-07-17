// Unit tests for src/extraction.ts adjunctModifiers' spec 3.2
// facet-trigger abstain arm (SAN-894, mirrors tests/reference/
// test_extraction.py from the Python reference): a facet trigger folded
// sequence inside an adjunct group must abstain the field to PARTIAL. The
// nested-adjunct arm of the same spec clause is NOW ENFORCED per erratum
// e15 (SAN-897): a role span containing consecutive adjunct prepositions
// with content between them abstains to PARTIAL unless the second
// preposition is immediately preceded by folded "and" (the only v1
// sibling separator). See test_nested_adjunct_chain_abstains_to_partial
// and test_sibling_adjunct_forms_extract_fully below.
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

test("test_nested_adjunct_chain_abstains_to_partial", () => {
  // e15 NESTED_ADJUNCT_v1 (SAN-897), pairwise over adjunct-preposition
  // indices per role span: content between consecutive prepositions with
  // the second not immediately preceded by folded "and" -> abstain. Both
  // chain inputs are evaluated into a results array FIRST, then asserted,
  // so a bare-chain failure cannot prevent the coordinated-NP case (the
  // escape this ticket closes) from executing during the red baseline.
  const results = [
    "Refunds for physical items with receipts are refundable.",
    "Refunds for physical and digital items with receipts are refundable.",
  ].map((t) => extractFrames("context", t));
  for (const [frames, partial] of results) {
    assert.equal(partial, true);
    assert.equal(frames.length, 0);
  }
});

test("test_sibling_adjunct_forms_extract_fully", () => {
  // Four non-abstaining sibling-adjunct forms under e15 (SAN-897).

  // (i) literal "and <preposition>" is the ONLY v1 sibling separator.
  {
    const [frames, partial] = extractFrames(
      "context",
      "Refunds for physical items and with receipts are refundable.",
    );
    assert.equal(partial, false);
    assert.equal(frames.length, 1);
    const modifiers = frames[0]!.extent.modifiers.toArray();
    assert.ok(
      modifiers.some((p) => p.rel === "for" && p.objset.size === 2 && p.objset.has("physical") && p.objset.has("item")),
    );
    assert.ok(modifiers.some((p) => p.rel === "with" && p.objset.size === 1 && p.objset.has("receipt")));
  }

  // (ii) cross-role spans: subject-side "for physical items", object-side
  // "with receipts" -- evaluated independently, no chain interaction.
  {
    const [frames, partial] = extractFrames(
      "context",
      "Refunds for physical items are refundable with receipts.",
    );
    assert.equal(partial, false);
    assert.equal(frames.length, 1);
    const modifiers = frames[0]!.extent.modifiers.toArray();
    assert.ok(
      modifiers.some((p) => p.rel === "for" && p.objset.size === 2 && p.objset.has("physical") && p.objset.has("item")),
    );
    assert.ok(modifiers.some((p) => p.rel === "with" && p.objset.size === 1 && p.objset.has("receipt")));
  }

  // (iii) empty first group ("for" immediately followed by "with"):
  // retains existing (pre-e15) behavior.
  {
    const [frames, partial] = extractFrames("context", "Refunds for with receipts are refundable.");
    assert.equal(partial, false);
    assert.equal(frames.length, 1);
    const modifiers = frames[0]!.extent.modifiers.toArray();
    assert.equal(modifiers.length, 1);
    assert.ok(modifiers.some((p) => p.rel === "with" && p.objset.size === 1 && p.objset.has("receipt")));
  }

  // (iv) single modifier, no chain at all.
  {
    const [frames, partial] = extractFrames("context", "Refunds for physical items are refundable.");
    assert.equal(partial, false);
    assert.equal(frames.length, 1);
    const modifiers = frames[0]!.extent.modifiers.toArray();
    assert.equal(modifiers.length, 1);
    assert.ok(
      modifiers.some((p) => p.rel === "for" && p.objset.size === 2 && p.objset.has("physical") && p.objset.has("item")),
    );
  }
});
