// Unit tests for src/primitives.ts (SAN-880, mirrors tests/reference/
// test_primitives.py from the Python reference, SAN-879/SAN-893): tokenizer
// (PCT100, contractions, apostrophes), stem_v1 rules, parse_dec (canonical
// form, 2^53 boundary distinctness, trailing zeros, malformed grouping),
// parse_values (each comparator), sentences/segments, ascii_lower.
//
// Test titles intentionally match their Python counterpart's function name
// (see reference/ts/TEST-COVERAGE.md) for direct traceability.

import assert from "node:assert/strict";
import { test } from "node:test";
import { evaluate } from "../src/evaluate.js";
import {
  Abstain,
  Dec,
  asciiLower,
  decCmp,
  listMarkerIndices,
  parseDec,
  parseValues,
  segments,
  sentences,
  stemV1,
  tokenize,
} from "../src/primitives.js";

// ---------------------------------------------------------------------
// tokenizer
// ---------------------------------------------------------------------

test("test_pct100_is_a_dedicated_token_kind", () => {
  const toks = tokenize("100% guaranteed");
  assert.equal(toks[0]!.kind, "PCT100");
  assert.equal(toks[0]!.raw, "100%");
});

test("test_pct100_does_not_fire_mid_digit_run", () => {
  // "1100%" is not the bare literal "100%": PCT100 must not fire on a
  // digit run that merely contains "100" as a substring.
  const toks = tokenize("1100%");
  assert.equal(toks[0]!.kind, "NUMBER");
  assert.equal(toks[0]!.raw, "1100%");
  assert.equal(toks.length, 1);
});

test("test_percent_other_than_100_is_a_number_token", () => {
  const toks = tokenize("50% off");
  assert.equal(toks[0]!.kind, "NUMBER");
  assert.equal(toks[0]!.raw, "50%");
});

test("test_contraction_expansion_splits_into_two_tokens", () => {
  const toks = tokenize("can't");
  assert.deepEqual(
    toks.map((t) => t.fold),
    ["can", "not"],
  );
  // first expanded token keeps the raw span; the rest carry empty raw
  assert.equal(toks[0]!.raw, "can't");
  assert.equal(toks[1]!.raw, "");
});

test("test_contraction_expansion_matches_plain_form_fold", () => {
  // "cannot" (single word, no apostrophe) expands identically to "can't"
  const a = tokenize("can't enter");
  const b = tokenize("cannot enter");
  assert.deepEqual(
    a.map((t) => t.fold),
    b.map((t) => t.fold),
  );
});

test("test_apostrophe_word_curly_and_straight_normalize_identically", () => {
  // spec 2.2 rule 4: "letters with internal apostrophes joined (U+2019 ->
  // ')" -- exercised with an internal apostrophe (followed by a letter),
  // not a trailing possessive. Escaped \u literal (never the raw glyph)
  // so this file stays ASCII.
  const straight = tokenize("y'all access");
  const curly = tokenize("y\u2019all access");
  assert.deepEqual(
    straight.map((t) => t.raw),
    curly.map((t) => t.raw),
  );
  assert.equal(straight[0]!.raw, "y'all");
});

test("test_internal_apostrophe_joins_letters", () => {
  const toks = tokenize("don't");
  // "don't" is itself a contraction key -> expands to do/not
  assert.deepEqual(
    toks.map((t) => t.fold),
    ["do", "not"],
  );
});

test("test_word_with_non_contraction_internal_apostrophe_stays_one_token", () => {
  const toks = tokenize("y'all");
  assert.equal(toks.length, 1);
  assert.equal(toks[0]!.kind, "WORD");
  assert.equal(toks[0]!.raw, "y'all");
});

test("test_whitespace_is_skipped_including_tabs_and_newlines", () => {
  const toks = tokenize("a\tb\nc");
  assert.deepEqual(
    toks.map((t) => t.raw),
    ["a", "b", "c"],
  );
});

test("test_currency_and_comma_grouping_tokenizes_as_one_number", () => {
  const toks = tokenize("$23,456");
  assert.equal(toks.length, 1);
  assert.equal(toks[0]!.kind, "NUMBER");
  assert.equal(toks[0]!.raw, "$23,456");
});

test("test_malformed_comma_grouping_splits_into_multiple_number_tokens", () => {
  const toks = tokenize("$1,23,456");
  const numberCount = toks.filter((t) => t.kind === "NUMBER").length;
  assert.ok(numberCount >= 2, `expected >=2 NUMBER tokens, got ${numberCount}`);
});

test("test_decimal_fraction_tokenizes_as_single_number", () => {
  const toks = tokenize("$25.50");
  assert.equal(toks.length, 1);
  assert.equal(toks[0]!.raw, "$25.50");
});

// ---------------------------------------------------------------------
// stem_v1
// ---------------------------------------------------------------------

test("test_stem_ies_to_y", () => {
  assert.equal(stemV1("cities"), "city");
});

test("test_stem_sses_to_ss", () => {
  assert.equal(stemV1("glasses"), "glass");
});

test("test_stem_es_after_sibilant_drops", () => {
  assert.equal(stemV1("boxes"), "box");
});

test("test_stem_final_s_not_ss_drops", () => {
  assert.equal(stemV1("cats"), "cat");
  assert.equal(stemV1("needs"), "need");
  assert.equal(stemV1("requires"), "require");
});

test("test_stem_double_s_is_not_stripped", () => {
  assert.equal(stemV1("glass"), "glass");
});

test("test_stem_short_word_below_min_len_unchanged", () => {
  assert.equal(stemV1("is"), "is");
  assert.equal(stemV1("was"), "was");
});

test("test_stem_unmatched_word_unchanged", () => {
  assert.equal(stemV1("available"), "available");
  assert.equal(stemV1("required"), "required");
});

// ---------------------------------------------------------------------
// parse_dec
// ---------------------------------------------------------------------

test("test_parse_dec_canonical_form_strips_trailing_zeros", () => {
  const d = parseDec("$25.00");
  assert.equal(d.coefficient, 25n);
  assert.equal(d.scale, 0);
});

test("test_parse_dec_2_53_boundary_distinctness_never_floats", () => {
  // 2^53 = 9007199254740992; float64 cannot distinguish adjacent integers
  // beyond this magnitude. Dec must, since it is BigInt-only.
  const a = parseDec("9007199254740993");
  const b = parseDec("9007199254740992");
  assert.notDeepEqual(a, b);
  assert.equal(a.coefficient - b.coefficient, 1n);
  assert.equal(decCmp(a, b), 1);
});

test("test_parse_dec_trailing_zero_equal_to_bare_integer", () => {
  const a = parseDec("$25.00");
  const b = parseDec("$25");
  assert.equal(decCmp(a, b), 0);
  assert.deepEqual(a, b);
});

test("test_parse_dec_negative_sign", () => {
  const d = parseDec("-5");
  assert.equal(d.coefficient, -5n);
});

test("test_parse_dec_digit_cap_abstains", () => {
  const tooManyDigits = "1".repeat(39); // MAX_DEC_DIGITS = 38
  assert.throws(
    () => parseDec(tooManyDigits),
    (e: unknown) => e instanceof Abstain && e.cause === "malformed_mention",
  );
});

test("test_parse_dec_scale_cap_abstains", () => {
  const tooMuchScale = "1." + "1".repeat(13); // MAX_DEC_SCALE = 12
  assert.throws(
    () => parseDec(tooMuchScale),
    (e: unknown) => e instanceof Abstain && e.cause === "malformed_mention",
  );
});

// ---------------------------------------------------------------------
// parse_values -- every comparator
// ---------------------------------------------------------------------

function firstInterval(text: string) {
  const iv = parseValues(tokenize(text));
  assert.ok(iv !== null && iv.length === 1);
  return iv![0]!;
}

function decNum(d: Dec | null): bigint | null {
  return d === null ? null : d.coefficient;
}

test("test_parse_values_over_is_open_lower_unbounded_upper", () => {
  const iv = firstInterval("over 5");
  assert.equal(decNum(iv.lo), 5n);
  assert.equal(iv.loOpen, true);
  assert.equal(iv.hi, null);
  assert.equal(iv.hiOpen, true);
});

test("test_parse_values_above_is_open_lower_unbounded_upper", () => {
  const iv = firstInterval("above 5");
  assert.equal(decNum(iv.lo), 5n);
  assert.equal(iv.loOpen, true);
  assert.equal(iv.hi, null);
});

test("test_parse_values_more_than_is_open_lower", () => {
  const iv = firstInterval("more than 5");
  assert.equal(decNum(iv.lo), 5n);
  assert.equal(iv.loOpen, true);
});

test("test_parse_values_at_least_is_closed_lower", () => {
  const iv = firstInterval("at least 5");
  assert.equal(decNum(iv.lo), 5n);
  assert.equal(iv.loOpen, false);
  assert.equal(iv.hi, null);
});

test("test_parse_values_under_is_open_upper_unbounded_lower", () => {
  const iv = firstInterval("under 5");
  assert.equal(iv.lo, null);
  assert.equal(decNum(iv.hi), 5n);
  assert.equal(iv.hiOpen, true);
});

test("test_parse_values_below_is_open_upper", () => {
  const iv = firstInterval("below 5");
  assert.equal(decNum(iv.hi), 5n);
  assert.equal(iv.hiOpen, true);
});

test("test_parse_values_less_than_is_open_upper", () => {
  const iv = firstInterval("less than 5");
  assert.equal(decNum(iv.hi), 5n);
  assert.equal(iv.hiOpen, true);
});

test("test_parse_values_at_most_is_closed_upper", () => {
  const iv = firstInterval("at most 5");
  assert.equal(decNum(iv.hi), 5n);
  assert.equal(iv.hiOpen, false);
  assert.equal(iv.lo, null);
});

test("test_parse_values_up_to_is_closed_upper", () => {
  const iv = firstInterval("up to 5");
  assert.equal(decNum(iv.hi), 5n);
  assert.equal(iv.hiOpen, false);
});

test("test_parse_values_within_is_0_to_v_closed", () => {
  const iv = firstInterval("within 5");
  assert.equal(decNum(iv.lo), 0n);
  assert.equal(iv.loOpen, false);
  assert.equal(decNum(iv.hi), 5n);
  assert.equal(iv.hiOpen, false);
});

test("test_parse_values_bare_scalar_is_point_interval", () => {
  const iv = firstInterval("5");
  assert.equal(decNum(iv.lo), 5n);
  assert.equal(decNum(iv.hi), 5n);
  assert.equal(iv.loOpen, false);
  assert.equal(iv.hiOpen, false);
});

test("test_parse_values_no_number_returns_none", () => {
  assert.equal(parseValues(tokenize("hello world")), null);
});

test("test_parse_values_second_number_abstains", () => {
  assert.throws(
    () => parseValues(tokenize("5 and 6")),
    (e: unknown) => e instanceof Abstain && e.cause === "malformed_mention",
  );
});

test("test_parse_values_leftover_tokens_abstain", () => {
  assert.throws(() => parseValues(tokenize("roughly costs 5 today")), Abstain);
});

test("test_parse_values_unit_conversion", () => {
  const iv = firstInterval("2 hour");
  assert.equal(iv.unit, "time_a");
  assert.equal(decNum(iv.lo), 120n); // 2 hours * 60 min/hour
});

test("test_parse_values_approx_token_abstains", () => {
  assert.throws(
    () => parseValues(tokenize("about 5")),
    (e: unknown) => e instanceof Abstain && e.cause === "malformed_mention",
  );
});

// ---------------------------------------------------------------------
// sentences / segments
// ---------------------------------------------------------------------

test("test_sentences_splits_on_terminal_punct_followed_by_whitespace", () => {
  const toks = tokenize("Users may enter. Users may not enter after hours.");
  const sents = sentences(toks);
  assert.equal(sents.length, 2);
  assert.equal(sents[0]![sents[0]!.length - 1]!.raw, ".");
  assert.equal(sents[1]![0]!.raw, "Users");
});

test("test_sentences_numeric_period_is_not_a_terminator", () => {
  const toks = tokenize("Basic costs $25.50 today.");
  const sents = sentences(toks);
  assert.equal(sents.length, 1);
});

test("test_segments_split_on_structural_punctuation", () => {
  const toks = tokenize("Refunds, if approved, are available.");
  const sent = sentences(toks)[0]!;
  const segs = segments(sent);
  assert.equal(segs.length, 3);
  assert.deepEqual(
    segs[0]!.map((t) => t.raw),
    ["Refunds"],
  );
});

test("test_sentences_bullet_line_starts_new_sentence", () => {
  // spec 2.6: a line whose first token is '-' or '*' starts a new
  // sentence even without a preceding terminator
  const text = "Refunds apply\n- Fees apply";
  const toks = tokenize(text);
  const sents = sentences(toks, text);
  assert.equal(sents.length, 2);
  assert.equal(sents[1]![0]!.raw, "-");
});

test("test_sentences_numbered_line_starts_new_sentence", () => {
  // e10 (spec 2.6): a line whose first token is NUMBER+'.' starts a new
  // sentence and the marker BELONGS to the item's sentence -- its period
  // is NOT a sentence terminator.
  const text = "Terms follow\n1. Refunds apply";
  const toks = tokenize(text);
  const sents = sentences(toks, text);
  assert.equal(sents.length, 2);
  assert.deepEqual(
    sents[1]!.map((t) => t.raw),
    ["1", ".", "Refunds", "apply"],
  );
});

test("test_sentences_numbered_item_is_one_sentence", () => {
  // e10: '1. Items are refundable.' is ONE sentence, behaviorally
  // identical to '- Items are refundable.'
  const text = "1. Items are refundable.";
  const toks = tokenize(text);
  const sents = sentences(toks, text);
  assert.equal(sents.length, 1);
  const bulletText = "- Items are refundable.";
  const bulletSents = sentences(tokenize(bulletText), bulletText);
  assert.equal(bulletSents.length, 1);
});

test("test_sentences_without_text_applies_terminator_rule_only", () => {
  const text = "Refunds apply\n- Fees apply";
  const toks = tokenize(text);
  assert.equal(sentences(toks).length, 1);
});

test("test_indented_bullet_marker_single_leading_space_recognized", () => {
  // e10 + Sol 914f832 delta: leading whitespace that reaches
  // beginning-of-field still starts a line
  const text = " - Items are refundable.";
  const toks = tokenize(text);
  assert.ok(listMarkerIndices(toks, text).has(0));
});

test("test_indented_bullet_marker_multiple_leading_spaces_recognized", () => {
  const text = "   * Items are refundable.";
  const toks = tokenize(text);
  assert.ok(listMarkerIndices(toks, text).has(0));
});

test("test_indented_bullet_marker_leading_tab_recognized", () => {
  const text = "\t- Items are refundable.";
  const toks = tokenize(text);
  assert.ok(listMarkerIndices(toks, text).has(0));
});

test("test_indented_numbered_marker_recognized_and_one_sentence", () => {
  // " 12. Items are refundable." must behave identically to the bullet
  // form: marker recognized (NUMBER + '.' indices), period not a
  // terminator, ONE sentence
  const text = " 12. Items are refundable.";
  const toks = tokenize(text);
  const markers = listMarkerIndices(toks, text);
  assert.ok(markers.has(0) && markers.has(1));
  assert.equal(sentences(toks, text).length, 1);
});

test("test_indented_numbered_marker_after_newline_with_indent", () => {
  const text = "Terms follow.\n  3. Fees apply.";
  const toks = tokenize(text);
  const sents = sentences(toks, text);
  assert.equal(sents.length, 2);
  assert.equal(sents[1]![0]!.kind, "NUMBER");
});

// ---------------------------------------------------------------------
// ascii_lower (SAN-893): maps ONLY ASCII A-Z (0x41-0x5A) to a-z; every
// non-ASCII code point passes through UNCHANGED. Deliberately narrower
// than JS's toLowerCase(), which folds per the full Unicode casing tables
// and would manufacture token-fold collisions the spec does not intend.
// Escaped \u literals below (never the raw glyph) so this file stays
// ASCII and the discriminating code point is unambiguous.
// ---------------------------------------------------------------------

test("test_ascii_lower_lowers_only_ascii_letters", () => {
  assert.equal(asciiLower("ABCz"), "abcz");
});

test("test_ascii_lower_leaves_kelvin_sign_unchanged", () => {
  // KELVIN SIGN (U+212A) visually resembles ASCII 'K' but is a distinct
  // code point outside A-Z; toLowerCase() folds it to ASCII 'k'
  // (U+006B), which asciiLower must NOT do.
  const kelvinSign = "\u212a";
  assert.equal(asciiLower(kelvinSign), kelvinSign);
});

test("test_ascii_lower_leaves_capital_i_with_dot_above_unchanged", () => {
  // LATIN CAPITAL LETTER I WITH DOT ABOVE (U+0130): full Unicode casing
  // would fold it toward 'i' + COMBINING DOT ABOVE; asciiLower must leave
  // the single code point unchanged since it is not ASCII A-Z.
  const capitalIDot = "\u0130";
  assert.equal(asciiLower(capitalIDot), capitalIDot);
});

test("test_ascii_lower_leaves_a_with_ring_above_unchanged", () => {
  // LATIN CAPITAL LETTER A WITH RING ABOVE (U+00C5): toLowerCase() folds
  // it to U+00E5; asciiLower must leave it unchanged since it is not
  // ASCII A-Z.
  const aRing = "\u00c5";
  assert.equal(asciiLower(aRing), aRing);
});

// ---------------------------------------------------------------------
// SPLIT_v1 terminator condition (SAN-893, spec 2.6): '.', '!', '?' PUNCT
// terminates ONLY when the next raw character is WS_v1 or EOF -- e.g.
// "refundable.Items" (no whitespace between) is NOT a sentence split.
// Parameterized over all three sentence-terminator marks.
// ---------------------------------------------------------------------

for (const mark of [".", "!", "?"]) {
  test(`test_sentences_adjacent_punctuation_does_not_terminate[${mark}]`, () => {
    const text = `Items are refundable${mark}Items are refundable${mark}`;
    const toks = tokenize(text);
    assert.equal(sentences(toks, text).length, 1);
  });
}

for (const mark of [".", "!", "?"]) {
  test(`test_sentences_punctuation_followed_by_space_terminates[${mark}]`, () => {
    const text = `Items are refundable${mark} Items are refundable${mark}`;
    const toks = tokenize(text);
    assert.equal(sentences(toks, text).length, 2);
  });
}

for (const mark of [".", "!", "?"]) {
  test(`test_sentences_punctuation_followed_by_tab_terminates[${mark}]`, () => {
    const text = `Items are refundable${mark}\tItems are refundable${mark}`;
    const toks = tokenize(text);
    assert.equal(sentences(toks, text).length, 2);
  });
}

for (const mark of [".", "!", "?"]) {
  test(`test_sentences_punctuation_followed_by_newline_terminates[${mark}]`, () => {
    const text = `Items are refundable${mark}\nItems are refundable${mark}`;
    const toks = tokenize(text);
    assert.equal(sentences(toks, text).length, 2);
  });
}

for (const mark of [".", "!", "?"]) {
  test(`test_sentences_punctuation_followed_by_eof_terminates[${mark}]`, () => {
    const text = `Items are refundable${mark}`;
    const toks = tokenize(text);
    assert.equal(sentences(toks, text).length, 1);
  });
}

// ---------------------------------------------------------------------
// ASCII digit grammar (SAN-895, spec 2.2: `digit` is ASCII 0-9 only).
// These mirror tests/reference/test_primitives.py's SAN-895 additions and
// pin the ALREADY-CONFORMANT TypeScript behavior so it cannot regress:
// TS's isDigitCp / isAsciiDigits are ASCII-only already (see
// matchNumberCore and parseDec in src/primitives.ts), unlike the Python
// reference's pre-fix broad str.isdigit() call sites. Escaped \u literals
// below (never the raw glyph) so this file stays ASCII.
// ---------------------------------------------------------------------

test("test_comma_group_requires_ascii_digits", () => {
  // Arabic-Indic U+0662/0663/0664 ("234" in Unicode decimal digits) must
  // NOT be absorbed into the comma-grouped NUMBER core: the grammar's
  // `digit` production is ASCII 0-9 only (spec 2.2), so the NUMBER token
  // stops at the lone ASCII lead digit "1" and the comma + non-ASCII run
  // falls out as separate token(s).
  const toks = tokenize("Refunds arrive within 1,\u0662\u0663\u0664 days.");
  const numberToks = toks.filter((t) => t.kind === "NUMBER");
  assert.equal(numberToks.length, 1);
  assert.equal(numberToks[0]!.raw, "1");

  // Control: the equivalent ASCII comma group IS absorbed as one NUMBER
  // token.
  const controlToks = tokenize("within 1,234 days");
  const controlNumbers = controlToks.filter((t) => t.kind === "NUMBER");
  assert.equal(controlNumbers.length, 1);
  assert.equal(controlNumbers[0]!.raw, "1,234");
});

test("test_parse_dec_rejects_non_ascii_digits", () => {
  // A lone Arabic-Indic digit is not `digit+` under spec 2.2 -> Abstain,
  // not a parsed Dec.
  assert.throws(
    () => parseDec("\u0662"),
    (e: unknown) => e instanceof Abstain && e.cause === "malformed_mention",
  );

  // Superscript digits are rejected by the same ASCII-only guard. This
  // pins that parseDec raises Abstain, never lets any other error escape.
  assert.throws(
    () => parseDec("1,\u00b2\u00b3\u2074"),
    (e: unknown) => e instanceof Abstain && e.cause === "malformed_mention",
  );
});

test("test_non_ascii_number_inputs_evaluate_structured_not_crash", () => {
  // Structured abstention, never an exception, for both non-ASCII digit
  // subclasses. Pins the full four-check projection matrix: C1/C3/C4
  // (frame-extraction consumers) see the non-ASCII digits as unconsumed
  // PUNCT inside the post-trigger value region -> spec 2.6 span
  // accounting drives the field to PARTIAL -> NOT_EVALUATED /
  // extraction_partial. C2 (e11, C2-local out_tokens scan) is unaffected
  // by frame-extraction partiality and still PASSes.
  const outputs = [
    "Refunds arrive within 1,\u0662\u0663\u0664 days.",
    "Refunds arrive within 1,\u00b2\u00b3\u2074 days.",
  ];
  const expected: Record<string, [string, string, string | null]> = {
    C1: ["NOT_EVALUATED", "extraction_partial", null],
    C2: ["PASS", "detection_complete", null],
    C3: ["NOT_EVALUATED", "extraction_partial", null],
    C4: ["NOT_EVALUATED", "extraction_partial", null],
  };
  for (const output of outputs) {
    const result = evaluate({ output, context: "Refunds require approval." });
    for (const [checkId, [outcome, outcomeReason, severity]] of Object.entries(expected)) {
      const got = result[checkId]!;
      assert.equal(got.outcome, outcome, checkId);
      assert.equal(got.outcome_reason, outcomeReason, checkId);
      assert.equal(got.severity, severity, checkId);
      assert.equal(Boolean(got.advisory), false, checkId);
    }
  }
});
