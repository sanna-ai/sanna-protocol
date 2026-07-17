import { LETTER_RANGES_V15 } from "./unicode_letters_v15.js";

/**
 * Codepoint-safe string helpers. Spec section 0: "str = NFC code points."
 * Plain JavaScript string indexing (`s[i]`, `s.length`) counts UTF-16 code
 * UNITS, not Unicode code points -- for any character outside the Basic
 * Multilingual Plane (astral / supplementary-plane, code point > U+FFFF,
 * represented as a UTF-16 surrogate pair) this diverges from Python's `str`,
 * which is inherently a sequence of code points. Every place the reference
 * algorithm indexes into or measures the length of raw field text (the
 * tokenizer's scan position, sentence-terminator lookahead, list-marker
 * line-start walk) MUST use code-point positions so TypeScript and Python
 * script identically over astral input. This module is the single place
 * that boundary is crossed; every other module consumes `string[]`
 * code-point arrays (via `toCodePoints`) instead of raw JS string indices
 * for any position-sensitive text scan.
 */

/** Splits `text` into an array of single-code-point strings. `Array.from`
 * (like `for...of`) iterates a JS string by Unicode code point, correctly
 * keeping a surrogate pair together as one element -- unlike `text.split("")`
 * or `text[i]`, which split/index by UTF-16 code unit. */
export function toCodePoints(text: string): string[] {
  return Array.from(text);
}

/** Python `len(text)` on a `str` counts code points. */
export function cpLength(text: string): number {
  let n = 0;
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  for (const _cp of text) n++;
  return n;
}

/** Binary search over LETTER_RANGES_V15 (sorted ascending, strictly
 * non-overlapping -- see reference/ts/src/unicode_letters_v15.ts) for a
 * single code point. Returns true iff `cp` falls within some range. */
function isLetterCodepoint(cp: number): boolean {
  let lo = 0;
  let hi = LETTER_RANGES_V15.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >>> 1;
    const [rangeLo, rangeHi] = LETTER_RANGES_V15[mid]!;
    if (cp < rangeLo) {
      hi = mid - 1;
    } else if (cp > rangeHi) {
      lo = mid + 1;
    } else {
      return true;
    }
  }
  return false;
}

/** Python `ch.isalpha()` for a single code point: true for any Unicode
 * "Letter" general-category code point (Lu/Ll/Lt/Lm/Lo). `ch` must be
 * exactly one code point (i.e. one element of a `toCodePoints()` array).
 *
 * This used to be implemented as `/^\p{L}$/u.test(ch)`, which matches
 * against the HOST Node runtime's built-in Unicode tables -- and those
 * float with the runtime's Unicode version (Node 22 ships Unicode 15.1;
 * later Node releases ship later versions still, e.g. a Node 25 install
 * reports Unicode 17.0). The Python reference behavior this package
 * mirrors is CPython 3.12, i.e. `unicodedata` UCD version 15.0.0, which
 * is the current reference/CI baseline. This function instead does a
 * total binary-search lookup against LETTER_RANGES_V15, a table vendored
 * by scripts/generate_letter_table_u15.py that pins classification to
 * that exact CPython 3.12 / UCD 15.0.0 baseline, independent of whatever
 * Unicode version the host Node runtime happens to ship.
 *
 * NORMATIVE STATUS: spec section 2.1 pins Unicode 15.0.0 for the
 * NORMALIZER only; spec section 2.2 rule 4 says just "letters" with no
 * version pin for classification. Pinning here is a reference/CI
 * baseline choice, not a claim that the spec already pins letter
 * classification -- the spec-level pin is tracked separately as
 * SAN-896.
 *
 * Preserves the old anchored-regex semantics exactly as a TOTAL
 * function: empty string and any string spanning more than one code
 * point both return false (a naive `codePointAt`-only version would
 * misclassify "" via an `undefined` comparison and would classify "AB"
 * by "A" alone); a lone surrogate falls through to `false` because
 * LETTER_RANGES_V15 contains no range intersecting the surrogate block. */
export function isAlphaCp(ch: string): boolean {
  const cp = ch.codePointAt(0);
  if (cp === undefined) return false;
  if (ch !== String.fromCodePoint(cp)) return false;
  return isLetterCodepoint(cp);
}

/** Spec section 2.3 (SAN-893): ascii_lower maps ONLY ASCII A-Z (0x41-0x5A)
 * to a-z; every other code point -- including non-ASCII letters and astral
 * code points -- passes through UNCHANGED. Deliberately narrower than
 * `String.prototype.toLowerCase()`, which folds per the full Unicode
 * casing tables. Iterates by code point (never by UTF-16 code unit) so an
 * astral code point is never split into a lone surrogate. */
export function asciiLower(s: string): string {
  return Array.from(s, (ch) => {
    const code = ch.codePointAt(0)!;
    if (code >= 0x41 && code <= 0x5a) {
      return String.fromCodePoint(code + 32);
    }
    return ch;
  }).join("");
}

/** Compares two strings by Unicode code point sequence -- Python's default
 * string ordering. Plain JS `<` / `.sort()` compare by UTF-16 code unit,
 * which diverges from code-point order for strings mixing an astral
 * character (surrogate pair, lead unit >= 0xD800) against a BMP character
 * in the 0xE000-0xFFFF range. Used wherever internal canonicalization
 * needs a total, deterministic order over strings that may contain
 * non-ASCII content (fold sequences pass non-ASCII code points through
 * unchanged, per `asciiLower` above). */
export function cpCompare(a: string, b: string): number {
  const ai = a[Symbol.iterator]();
  const bi = b[Symbol.iterator]();
  for (;;) {
    const an = ai.next();
    const bn = bi.next();
    if (an.done && bn.done) return 0;
    if (an.done) return -1;
    if (bn.done) return 1;
    const ac = an.value.codePointAt(0)!;
    const bc = bn.value.codePointAt(0)!;
    if (ac !== bc) return ac < bc ? -1 : 1;
  }
}
