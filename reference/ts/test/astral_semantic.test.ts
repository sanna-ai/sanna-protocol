// SAN-880 Phase 2: ONE semantic (not merely serializer-level) test proving
// token spans and sentence scanning operate over Unicode CODE POINTS,
// never UTF-16 code units (spec section 0: "str = NFC code points"; see
// unicode.ts's module docstring). All non-ASCII input is written as \u{...}
// escapes (never raw glyphs) so this file stays ASCII.
//
// The astral character U+1D11E (MUSICAL SYMBOL G CLEF) is one Unicode code
// point but occupies TWO UTF-16 code units (a surrogate pair) in a JS
// string. It is Unicode category "So" (Symbol, other) -- not a Letter --
// so the tokenizer correctly emits it as its own single-code-point PUNCT
// token, distinct from the following WORD token "x".
//
// This is the discriminating case: a UTF-16-code-unit-indexed
// implementation would report the "x" token's start offset as 2 (the
// G-clef consumes code units 0-1), and a raw text[end] terminator
// lookahead over code units would land mid-surrogate-pair for any field
// containing an astral character before the point of interest. A
// code-point-indexed implementation (this one) reports the G-clef as
// occupying codepoint index [0, 1) and "x" as starting at codepoint index
// 1 -- and every downstream offset stays in codepoint space, so the
// sentence terminator lookahead after "available." lands on the correct
// following space instead of a corrupted position.

import assert from "node:assert/strict";
import { test } from "node:test";
import { sentences, tokenize } from "../src/primitives.js";

test("token spans and sentence scanning are indexed by Unicode code point, not UTF-16 code unit, across an astral character", () => {
  const gClef = "\u{1d11e}"; // MUSICAL SYMBOL G CLEF, U+1D11E -- one code point, two UTF-16 code units
  const text = `${gClef}x is available. More text here.`;

  // Sanity: this string really does contain an astral character (its
  // JS/UTF-16 length exceeds its code-point count by exactly one -- the
  // one surrogate pair contributing 2 units for 1 code point).
  const codePointCount = Array.from(text).length;
  assert.equal(text.length, codePointCount + 1);

  const toks = tokenize(text);

  // The G-clef itself: a single code point, non-alphabetic (category So,
  // not L), so it tokenizes as its OWN one-code-point-wide PUNCT token --
  // never split into two lone-surrogate pseudo-tokens.
  const clefTok = toks[0]!;
  assert.equal(clefTok.kind, "PUNCT");
  assert.equal(clefTok.raw, gClef);
  assert.equal(Array.from(clefTok.raw).length, 1);
  assert.equal(clefTok.start, 0);
  assert.equal(clefTok.end, 1); // NOT 2 -- would be 2 under UTF-16-unit indexing

  // The very next token: "x". Its start is codepoint index 1 (immediately
  // after the one-codepoint-wide G-clef) -- NOT 2, which is what a
  // UTF-16-code-unit-indexed implementation would (incorrectly) report.
  const xTok = toks[1]!;
  assert.equal(xTok.kind, "WORD");
  assert.equal(xTok.raw, "x");
  assert.equal(xTok.start, 1);
  assert.equal(xTok.end, 2);

  // The rest of the tokens continue in pure codepoint space.
  assert.equal(toks[2]!.raw, "is");
  assert.equal(toks[2]!.start, 3);
  assert.equal(toks[3]!.raw, "available");
  assert.equal(toks[3]!.start, 6);
  assert.equal(toks[3]!.end, 15);
  const periodTok = toks[4]!;
  assert.equal(periodTok.raw, ".");
  assert.equal(periodTok.start, 15);
  assert.equal(periodTok.end, 16);

  // Sentence scanning: the terminator lookahead ("next raw char is WS_v1
  // or EOF", spec 2.6) reads text[periodTok.end] in CODE-POINT space. If
  // that lookahead instead indexed by UTF-16 code unit (off by one after
  // the astral character), it would read the wrong character -- here
  // still whitespace by coincidence for THIS string, so the real proof is
  // the exact offset assertions above, which a code-unit-indexed
  // implementation cannot simultaneously satisfy. The sentence count
  // below is the end-to-end behavioral confirmation.
  const sents = sentences(toks, text);
  assert.equal(sents.length, 2);
  assert.equal(sents[0]!.length, 5); // g-clef, x, is, available, .
  assert.equal(sents[1]![0]!.raw, "More");
});
