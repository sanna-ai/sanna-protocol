// SAN-880 amendment (review round 2): regression tests for
// reference/ts/src/unicode.ts's isAlphaCp() after it was reimplemented
// against a vendored, generator-produced letter table
// (reference/ts/src/unicode_letters_v15.ts) instead of the host Node
// runtime's built-in `\p{L}` Unicode property escape. The host tables
// float with the runtime's Unicode version (Node 22 ships Unicode 15.1;
// later Node releases ship later versions still), which diverges from
// the CPython 3.12 / Unicode Character Database (UCD) 15.0.0 baseline
// this reference/CI pins to. All non-ASCII literals below are written as
// escape sequences per the ASCII-only conformance gate
// (scripts/check_reference_ascii.py).
//
// NORMATIVE STATUS: spec section 2.1 pins Unicode 15.0.0 for the
// NORMALIZER only; spec section 2.2 rule 4 says just "letters" with no
// version pin for classification. The pin exercised here is a
// reference/CI baseline choice, not a claim that the spec already pins
// letter classification -- the spec-level pin is tracked separately as
// SAN-896.
//
// No direct Python test counterpart is needed for this TypeScript-specific
// differential because CI pins Python 3.12 / UCD 15.0.0 as the comparison
// baseline. Python's str.isalpha() also follows the UCD bundled with its
// host CPython runtime; future runtime movement remains part of SAN-896's
// cross-runtime/spec-pinning work.

import assert from "node:assert/strict";
import { test } from "node:test";
import { isAlphaCp } from "../src/unicode.js";
import { LETTER_RANGES_V15 } from "../src/unicode_letters_v15.js";
import { run } from "../src/diff_harness.js";

const ALL_CHECK_IDS = ["C1", "C2", "C3", "C4"] as const;

// ---------------------------------------------------------------------
// isAlphaCp classification pins (CPython 3.12 / UCD 15.0.0 baseline)
// ---------------------------------------------------------------------

test("test_is_alpha_cp_classification_pins", () => {
  assert.equal(isAlphaCp("A"), true);
  assert.equal(isAlphaCp("a"), true);
  // LATIN SMALL LETTER A WITH RING ABOVE
  assert.equal(isAlphaCp("\u00e5"), true);

  // ARABIC-INDIC DIGIT TWO -- category Nd (decimal number), not a letter.
  assert.equal(isAlphaCp("\u0662"), false);

  // CJK UNIFIED IDEOGRAPH-20000 -- CJK Extension B, a 15.0-era letter.
  assert.equal(isAlphaCp("\u{20000}"), true);

  // U+2EBF0 / U+2EBF1: CJK Extension I ideographs added in Unicode
  // 15.1. Unassigned (category Cn) under the pinned CPython 3.12 / UCD
  // 15.0.0 baseline, so isAlphaCp MUST stay false here until the pinned
  // baseline moves (SAN-896).
  assert.equal(isAlphaCp("\u{2ebf0}"), false);
  assert.equal(isAlphaCp("\u{2ebf1}"), false);
});

// ---------------------------------------------------------------------
// isAlphaCp totality pins
// ---------------------------------------------------------------------

test("test_is_alpha_cp_totality_pins", () => {
  assert.equal(isAlphaCp(""), false);
  assert.equal(isAlphaCp("AB"), false);
  assert.equal(isAlphaCp("\ud800"), false); // lone high surrogate
  assert.equal(isAlphaCp("\udc00"), false); // lone low surrogate
  assert.equal(isAlphaCp("\u{20000}A"), false); // astral letter + trailing char
});

// ---------------------------------------------------------------------
// Generated-table invariants -- mirrors
// scripts/generate_letter_table_u15.py's own asserts, independently
// re-verified here against the committed table.
// ---------------------------------------------------------------------

test("test_letter_ranges_v15_invariants", () => {
  assert.equal(LETTER_RANGES_V15.length, 659);

  let total = 0;
  for (const [lo, hi] of LETTER_RANGES_V15) total += hi - lo + 1;
  assert.equal(total, 136104);

  assert.deepEqual(LETTER_RANGES_V15[0], [0x41, 0x5a]);
  assert.deepEqual(LETTER_RANGES_V15[LETTER_RANGES_V15.length - 1], [0x31350, 0x323af]);

  for (const [lo, hi] of LETTER_RANGES_V15) {
    assert.ok(lo <= hi, `malformed range (${lo}, ${hi})`);
    assert.ok(lo >= 0 && hi <= 0x10ffff, `range (${lo}, ${hi}) out of [0, 0x10ffff]`);
    assert.ok(
      !(lo <= 0xdfff && hi >= 0xd800),
      `range (${lo}, ${hi}) intersects the surrogate block [0xd800, 0xdfff]`,
    );
  }

  for (let i = 1; i < LETTER_RANGES_V15.length; i++) {
    const prevHi = LETTER_RANGES_V15[i - 1]![1];
    const nextLo = LETTER_RANGES_V15[i]![0];
    assert.ok(nextLo > prevHi, `ranges not strictly ascending/non-overlapping at index ${i}`);
  }
});

// ---------------------------------------------------------------------
// Astral C1 differential regression: three adjacent U+2EBF0 code points
// in the context and U+2EBF1 code points in the output each formed a
// 3-code-point WORD token under host `\p{L}` tables (Unicode >= 15.1).
// Those distinct WORDs polluted the two subject sets, making the context
// and output frames INERT to each other. TypeScript therefore reported
// PASS and missed the contradiction. Python (CPython 3.12 / UCD 15.0.0,
// where these code points are unassigned and tokenize as PUNCT) excluded
// them from the subject sets and reported VIOLATION/critical. Pinning
// classification to UCD 15.0.0 makes TypeScript report the same
// VIOLATION/critical result.
// ---------------------------------------------------------------------

test("test_astral_c1_letter_pin_closes_the_2ebf0_differential", () => {
  const context = "\u{2ebf0}\u{2ebf0}\u{2ebf0} items are refundable.";
  const output = "\u{2ebf1}\u{2ebf1}\u{2ebf1} items are not refundable.";
  const records = ALL_CHECK_IDS.map((checkId) => ({
    id: `astral-2ebf0-${checkId}`,
    check_id: checkId,
    context,
    output,
  }));
  const results = run(records);
  assert.equal(results.length, 4);

  const c1 = results.find((r) => r.check_id === "C1");
  assert.ok(c1, "missing C1 result");
  assert.equal(c1!.outcome, "VIOLATION");
  assert.equal(c1!.outcome_reason, "detection_complete");
  assert.equal(c1!.severity, "critical");
  assert.equal(c1!.advisory, false);

  for (const checkId of ["C2", "C3", "C4"] as const) {
    const got = results.find((r) => r.check_id === checkId);
    assert.ok(got, `missing ${checkId} result`);
    assert.equal(got!.outcome, "PASS", `${checkId} outcome`);
    assert.equal(got!.outcome_reason, "detection_complete", `${checkId} outcome_reason`);
    assert.equal(got!.severity, null, `${checkId} severity`);
    assert.equal(got!.advisory, false, `${checkId} advisory`);
  }
});
