// SAN-880 Phase 2: canonical-JSON serializer tests with hard-coded expected
// bytes, verified directly against Python's
// json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",",":"))
// (the byte shape diff_harness.ts's canonicalJson() must reproduce).
// Covers: non-ASCII BMP text, astral (surrogate-pair) code points,
// U+2028/U+2029, control characters, quotes, backslashes, recursive key
// sorting, and unchanged array order. All non-ASCII inputs are written as
// \u escapes (never raw glyphs) so this file itself stays ASCII.

import assert from "node:assert/strict";
import { test } from "node:test";
import { canonicalJson } from "../src/diff_harness.js";

test("canonicalJson escapes non-ASCII BMP text as \\uXXXX", () => {
  const got = canonicalJson("caf\u00e9");
  assert.equal(got, '"caf\\u00e9"\n');
});

test("canonicalJson escapes an astral code point as a UTF-16 surrogate pair", () => {
  // MUSICAL SYMBOL G CLEF, U+1D11E -> UTF-16 surrogate pair D834 DD1E.
  // Python's C-accelerated encoder manually constructs this same pair for
  // any code point >= 0x10000; this module gets it "for free" by escaping
  // per UTF-16 code unit (a JS string already stores astral characters as
  // a surrogate pair -- see diff_harness.ts's jsonEscapeStringAscii doc
  // comment).
  const got = canonicalJson("\u{1d11e}");
  assert.equal(got, '"\\ud834\\udd1e"\n');
});

test("canonicalJson escapes U+2028 LINE SEPARATOR and U+2029 PARAGRAPH SEPARATOR", () => {
  const got = canonicalJson("\u2028\u2029");
  assert.equal(got, '"\\u2028\\u2029"\n');
});

test("canonicalJson escapes control characters below U+0020 (including non-named ones) and DEL", () => {
  const got = canonicalJson("\u0000\u0001\u001f\u007f");
  assert.equal(got, '"\\u0000\\u0001\\u001f\\u007f"\n');
});

test("canonicalJson uses the named short escapes for \\b \\f \\n \\r \\t", () => {
  const got = canonicalJson("\b\f\n\r\t");
  assert.equal(got, '"\\b\\f\\n\\r\\t"\n');
});

test("canonicalJson escapes quotes and backslashes", () => {
  const got = canonicalJson('a"b\\c');
  assert.equal(got, '"a\\"b\\\\c"\n');
});

test("canonicalJson recursively sorts object keys at every nesting level and leaves array order unchanged", () => {
  const got = canonicalJson({ b: { z: 1, a: 2 }, a: [3, 1, 2] });
  assert.equal(got, '{"a":[3,1,2],"b":{"a":2,"z":1}}\n');
});

test("canonicalJson reproduces a full diff_harness output record byte-for-byte", () => {
  const got = canonicalJson([
    {
      id: "x",
      check_id: "C1",
      outcome: "PASS",
      outcome_reason: "detection_complete",
      severity: null,
      advisory: false,
    },
  ]);
  assert.equal(
    got,
    '[{"advisory":false,"check_id":"C1","id":"x","outcome":"PASS","outcome_reason":"detection_complete","severity":null}]\n',
  );
});

test("canonicalJson terminates with exactly one trailing newline and no other whitespace", () => {
  const got = canonicalJson([1, 2, 3]);
  assert.equal(got, "[1,2,3]\n");
  assert.equal(got.endsWith("\n"), true);
  assert.equal(got.slice(0, -1).includes("\n"), false);
  assert.equal(got.includes(" "), false);
});
