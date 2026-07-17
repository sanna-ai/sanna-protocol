/**
 * Section 0 (types) and section 2 (text primitives) of ALGORITHM v4 draft
 * 5.4. Hosts the shared type vocabulary (Bool AST, Extent, Frame, Evidence,
 * Obligation, Dec, Interval, Token, Roles) because section 0 precedes every
 * other section in the spec and every other module in this package depends
 * on these types. Tables are never restated here -- every constant/list is
 * read through tables.ts's `T` (or the compiled-fold indices built at the
 * bottom of this module by tokenizing each table entry through tokenize()
 * itself, per spec section 1: "the loader tokenizes each entry once at
 * load").
 *
 * Mirrors reference/primitives.py one-for-one EXCEPT `normalize()` (spec
 * section 2.1): per the SAN-880/SAN-883 slice-boundary adjudication, this
 * package's harness accepts already-decoded JS strings as the slice's
 * "already-decoded string" input and MUST NOT implement or wire section
 * 2.1 into evaluate/tokenize -- that normalization-conformance work is
 * owned exclusively by SAN-883. `String.prototype.normalize()` is
 * correspondingly never called anywhere in this package.
 */

import { T, unorderedPairKey } from "./tables.js";
import { FSet, ModSet } from "./fset.js";
import { asciiLower, cpLength, isAlphaCp, toCodePoints } from "./unicode.js";

// ----------------------------------------------------------------------
// Abstention (spec section 0: "abstain(cause): cause in {malformed_mention,
// unextractable}; an abstained product makes its FIELD PARTIAL (symmetric
// rule)").
// ----------------------------------------------------------------------

export class Abstain extends Error {
  readonly cause: string;
  constructor(cause: string) {
    super(cause);
    this.name = "Abstain";
    this.cause = cause;
  }
}

/** EVALUATOR_ERROR(evaluator_exception) per LOCKED A1 (spec section 0:
 * "Unexpected exceptions = EVALUATOR_ERROR(evaluator_exception)"). */
export class EvaluatorError extends Error {}

export const MALFORMED_MENTION = "malformed_mention";
export const CONDITION_UNDECIDABLE = "condition_undecidable";
export const UNEXTRACTABLE = "unextractable";

/** def worst_cause(cs) = malformed_mention if present else condition_undecidable */
export function worstCause(cs: Iterable<string | null | undefined>): string {
  for (const c of cs) {
    if (c === MALFORMED_MENTION) return MALFORMED_MENTION;
  }
  return CONDITION_UNDECIDABLE;
}

// ----------------------------------------------------------------------
// Token (section 2.2). start/end are CODE POINT indices (never UTF-16 code
// unit indices) -- see unicode.ts.
// ----------------------------------------------------------------------

export type TokenKind = "WORD" | "NUMBER" | "PCT100" | "PUNCT";

export interface Token {
  readonly raw: string;
  readonly fold: string;
  readonly start: number;
  readonly end: number;
  readonly kind: TokenKind;
}

export type Span = readonly [number, number]; // token index range [start, end)

// ----------------------------------------------------------------------
// Dec (section 0 / 2.4) -- BigInt only, never float.
// ----------------------------------------------------------------------

export interface Dec {
  readonly coefficient: bigint;
  readonly scale: number;
}

/** while scale > 0 and coefficient % 10 == 0: coefficient /= 10; scale -= 1 */
export function canonicalizeDec(d: Dec): Dec {
  let coeff = d.coefficient;
  let scale = d.scale;
  if (coeff === 0n) return { coefficient: 0n, scale: 0 };
  while (scale > 0 && coeff % 10n === 0n) {
    coeff /= 10n;
    scale -= 1;
  }
  return { coefficient: coeff, scale };
}

function digitCount(n: bigint): number {
  const abs = n < 0n ? -n : n;
  return abs === 0n ? 1 : abs.toString().length;
}

/** sign(a.coefficient * 10^(s-a.scale) - b.coefficient * 10^(s-b.scale)),
 * s = max(a.scale, b.scale). BigInt only; never floats. */
export function decCmp(a: Dec, b: Dec): number {
  const s = Math.max(a.scale, b.scale);
  const av = a.coefficient * 10n ** BigInt(s - a.scale);
  const bv = b.coefficient * 10n ** BigInt(s - b.scale);
  if (av > bv) return 1;
  if (av < bv) return -1;
  return 0;
}

export function decConvert(d: Dec, factor: number): Dec {
  return canonicalizeDec({ coefficient: d.coefficient * BigInt(factor), scale: d.scale });
}

export function decZero(): Dec {
  return { coefficient: 0n, scale: 0 };
}

export function decEqual(a: Dec, b: Dec): boolean {
  const ca = canonicalizeDec(a);
  const cb = canonicalizeDec(b);
  return ca.coefficient === cb.coefficient && ca.scale === cb.scale;
}

/** Canonical-form decimal string per ATOMENC_v1 section 7 dec(): minimal
 * digits, '-' prefix, scale rendered as a '.' fraction, no exponent. */
export function decToStr(dIn: Dec): string {
  const d = canonicalizeDec(dIn);
  const neg = d.coefficient < 0n;
  let digits = (neg ? -d.coefficient : d.coefficient).toString();
  let s: string;
  if (d.scale === 0) {
    s = digits;
  } else {
    if (digits.length <= d.scale) {
      digits = "0".repeat(d.scale - digits.length + 1) + digits;
    }
    s = digits.slice(0, digits.length - d.scale) + "." + digits.slice(digits.length - d.scale);
  }
  return neg ? "-" + s : s;
}

// ----------------------------------------------------------------------
// Interval (section 0)
// ----------------------------------------------------------------------

export interface Interval {
  readonly lo: Dec | null;
  readonly loOpen: boolean;
  readonly hi: Dec | null;
  readonly hiOpen: boolean;
  readonly unit: string; // unit-group name, or "currency:<CODE>", or "" (dimensionless)
}

// ----------------------------------------------------------------------
// Bool AST (section 0) -- TOP | BOTTOM | Atom | AND | OR | NOT
// ----------------------------------------------------------------------

export interface TopNode {
  readonly kind: "TOP";
}
export interface BottomNode {
  readonly kind: "BOTTOM";
}
export interface TermAtom {
  readonly kind: "TermAtom";
  readonly terms: FSet;
  readonly pol: 0 | 1; // 0 POS, 1 NEG
  readonly restrictive: 0 | 1;
}
export type MeasureQty = readonly [facet: string, subjectKey: FSet, unitGroup: string];
export interface MeasureAtom {
  readonly kind: "MeasureAtom";
  readonly qty: MeasureQty;
  readonly intervals: readonly Interval[];
}
export interface UnknownAtom {
  readonly kind: "UnknownAtom";
  readonly cause: string;
}
export interface AndNode {
  readonly kind: "And";
  readonly children: readonly Bool[];
}
export interface OrNode {
  readonly kind: "Or";
  readonly children: readonly Bool[];
}
export interface NotNode {
  readonly kind: "Not";
  readonly child: Bool;
}

export type Atom = TermAtom | MeasureAtom | UnknownAtom;
export type Bool = TopNode | BottomNode | TermAtom | MeasureAtom | UnknownAtom | AndNode | OrNode | NotNode;

export const TOP_: TopNode = { kind: "TOP" };
export const BOTTOM_: BottomNode = { kind: "BOTTOM" };

export function mkTermAtom(terms: FSet, pol: 0 | 1, restrictive: 0 | 1): TermAtom {
  return { kind: "TermAtom", terms, pol, restrictive };
}
export function mkMeasureAtom(qty: MeasureQty, intervals: readonly Interval[]): MeasureAtom {
  return { kind: "MeasureAtom", qty, intervals };
}
export function mkUnknownAtom(cause: string): UnknownAtom {
  return { kind: "UnknownAtom", cause };
}
export function mkAnd(children: readonly Bool[]): AndNode {
  return { kind: "And", children };
}
export function mkOr(children: readonly Bool[]): OrNode {
  return { kind: "Or", children };
}
export function mkNot(child: Bool): NotNode {
  return { kind: "Not", child };
}

// ----------------------------------------------------------------------
// Extent / Hit / CondNode / Frame / Roles / Evidence / Obligation (section 0)
// ----------------------------------------------------------------------

export const UNSPECIFIED = 0 as const;
export const UNIVERSAL = 1 as const;
export const EXISTENTIAL = 2 as const;
export const POS = 0 as const;
export const NEG = 1 as const;
export const EXPLICIT = 0 as const;
export const IMPLICIT = 1 as const;
export const GRANT = 0 as const;
export const RESTRICTION = 1 as const;

export interface Extent {
  readonly facet: string;
  readonly subject: FSet;
  readonly object: FSet;
  readonly modifiers: ModSet;
  readonly quant: 0 | 1 | 2;
  readonly polarity: 0 | 1;
  readonly values: readonly Interval[] | null;
}

export interface Hit {
  readonly facet: string;
  readonly span: Span;
  readonly isDeny: boolean;
  readonly triggerKey: readonly string[]; // FOLDED trigger token sequence
}

export interface CondNode {
  readonly formula: Bool;
  readonly force: 0 | 1; // 0 GRANT, 1 RESTRICTION
  readonly kind: string; // IF | ONLY_IF | SUBJECT_TO
}

export interface Frame {
  readonly fieldId: string;
  readonly frameId: number;
  readonly extent: Extent;
  readonly conds: readonly CondNode[];
  readonly assertive: boolean;
  // Per-conjunct subject structure (spec 3.5: explicit obligations and
  // requirement evidence are "per governed conjunct"; the flat
  // extent.subject union loses conjunct boundaries, so they are carried
  // here alongside their COMPOUND_HEAD-rule heads).
  readonly subjectConjuncts: readonly FSet[];
  readonly subjectConjunctHeads: readonly (string | null)[];
  // For approval_requirement-facet frames: the parse_bool product over
  // the required span (restrictive=True per spec 3.5). null for other
  // facets.
  readonly reqFormula: Bool | null;
}

export interface Roles {
  readonly subject: Span;
  readonly object: Span | null;
  readonly value: Span | null;
  readonly pattern: "OP" | "PASSIVE" | "COORD" | "ACTIVE";
}

export interface Evidence {
  readonly fieldId: string;
  readonly frameId: number;
  readonly spanId: number;
  readonly governedIdentity: Extent;
  readonly domain: Bool;
  readonly assertedFormula: Bool;
  readonly assertionPolarity: 0 | 1;
}

export interface Obligation {
  readonly kind: 0 | 1; // 0 explicit, 1 implicit
  readonly governedIdentity: Extent;
  readonly sourceActivationDomain: Bool;
  readonly applicabilityScope: Bool;
  readonly requirementFormula: Bool;
  readonly sourcePolarity: 0 | 1;
  readonly trivial: boolean;
  readonly sourceFrameIds: readonly number[];
}

/** def eff(e: Evidence) = e.asserted_formula if e.assertion_polarity == 0
 * else NOT(e.asserted_formula) */
export function eff(e: Evidence): Bool {
  return e.assertionPolarity === 0 ? e.assertedFormula : mkNot(e.assertedFormula);
}

/** TOTAL: eff_quant(UNSPECIFIED)=UNIVERSAL; eff_quant(UNIVERSAL)=UNIVERSAL;
 * eff_quant(EXISTENTIAL)=EXISTENTIAL. */
export function effQuant(q: number): 1 | 2 {
  return q === EXISTENTIAL ? EXISTENTIAL : UNIVERSAL;
}

// ----------------------------------------------------------------------
// 2.3 stem_v1 / ascii_lower / fold_of
// ----------------------------------------------------------------------

export function stemV1(w: string): string {
  for (const rule of T.stemV1Rules) {
    const suffix = rule.if_ends;
    if (!w.endsWith(suffix)) continue;
    if (cpLength(w) < rule.min_len) continue;
    if (rule.not_ends && w.endsWith(rule.not_ends)) continue;
    if (rule.only_after) {
      const prefix = w.slice(0, w.length - suffix.length);
      if (!rule.only_after.some((a) => prefix.endsWith(a))) continue;
    }
    return w.slice(0, w.length - suffix.length) + rule.replace_with;
  }
  return w;
}

export { asciiLower };

export function foldOf(raw: string): string {
  return stemV1(asciiLower(raw));
}

// ----------------------------------------------------------------------
// 2.2 tokenize
// ----------------------------------------------------------------------

const APOSTROPHES = new Set(["'", "\u2019"]); // ASCII apostrophe + RIGHT SINGLE QUOTATION MARK (escaped, never a raw glyph, to keep this source file ASCII-only)
const CURRENCY_SYMBOLS: ReadonlySet<string> = new Set(Object.keys(T.currencySymbolsV1));

function isDigitCp(ch: string | undefined): boolean {
  return ch !== undefined && ch >= "0" && ch <= "9";
}

/** Greedy match of the `core` grammar production starting at i:
 * core := digit+ | digit{1,3} ("," digit{3})+ | core "." digit+
 * Returns the end index of the matched core, or null if no digit at i. */
function matchNumberCore(cps: readonly string[], i: number): number | null {
  const n = cps.length;
  if (i >= n || !isDigitCp(cps[i])) return null;

  // Attempt the comma-grouped alternative first (maximal munch).
  let j = i;
  let lead = 0;
  while (j < n && isDigitCp(cps[j]) && lead < 3) {
    j += 1;
    lead += 1;
  }
  let groupedEnd: number | null = null;
  let k = j;
  let groups = 0;
  for (;;) {
    if (!(k < n && cps[k] === ",")) break;
    const seg = cps.slice(k + 1, k + 4);
    if (!(seg.length === 3 && seg.every(isDigitCp))) break;
    if (!(k + 4 === n || !isDigitCp(cps[k + 4]))) break;
    k += 4;
    groups += 1;
  }
  if (groups >= 1) {
    groupedEnd = k;
  }

  let end: number;
  if (groupedEnd !== null) {
    end = groupedEnd;
  } else {
    end = i;
    while (end < n && isDigitCp(cps[end])) end += 1;
  }

  // optional ".", digit+ fraction (core "." digit+) -- at most one "."
  if (end < n && cps[end] === "." && end + 1 < n && isDigitCp(cps[end + 1])) {
    end += 1;
    while (end < n && isDigitCp(cps[end])) end += 1;
  }

  return end;
}

function matchPct100(cps: readonly string[], i: number): number | null {
  const n = cps.length;
  if (cps.slice(i, i + 3).join("") !== "100") return null;
  if (i > 0 && isDigitCp(cps[i - 1])) return null;
  if (i + 3 >= n || cps[i + 3] !== "%") return null;
  return i + 4;
}

function matchWord(cps: readonly string[], i: number): number | null {
  const n = cps.length;
  const c0 = cps[i];
  if (c0 === undefined || !isAlphaCp(c0)) return null;
  let end = i + 1;
  while (end < n && isAlphaCp(cps[end]!)) end += 1;
  while (end < n && APOSTROPHES.has(cps[end]!) && end + 1 < n && isAlphaCp(cps[end + 1]!)) {
    end += 1;
    while (end < n && isAlphaCp(cps[end]!)) end += 1;
  }
  return end;
}

interface MutableToken {
  raw: string;
  fold: string;
  start: number;
  end: number;
  kind: TokenKind;
}

/** Rules 1-5 of section 2.2, one left-to-right scan over CODE POINTS.
 * Returns tokens with fold="" (fold is computed in a later pass, after
 * contraction expansion, per spec). */
function rawTokenize(cps: readonly string[]): MutableToken[] {
  const tokens: MutableToken[] = [];
  let i = 0;
  const n = cps.length;
  while (i < n) {
    const ch = cps[i]!;
    if (T.wsV1.has(ch)) {
      i += 1;
      continue;
    }
    const pctEnd = matchPct100(cps, i);
    if (pctEnd !== null) {
      tokens.push({ raw: cps.slice(i, pctEnd).join(""), fold: "", start: i, end: pctEnd, kind: "PCT100" });
      i = pctEnd;
      continue;
    }
    // NUMBER: [currency] [sign] core [pct]
    let j = i;
    if (j < n && CURRENCY_SYMBOLS.has(cps[j]!)) j += 1;
    if (j < n && (cps[j] === "+" || cps[j] === "-")) j += 1;
    const coreEnd = matchNumberCore(cps, j);
    if (coreEnd !== null) {
      let end = coreEnd;
      if (end < n && cps[end] === "%") end += 1;
      tokens.push({ raw: cps.slice(i, end).join(""), fold: "", start: i, end, kind: "NUMBER" });
      i = end;
      continue;
    }
    const wordEnd = matchWord(cps, i);
    if (wordEnd !== null) {
      const raw = cps
        .slice(i, wordEnd)
        .join("")
        .replace(/\u2019/g, "'");
      tokens.push({ raw, fold: "", start: i, end: wordEnd, kind: "WORD" });
      i = wordEnd;
      continue;
    }
    tokens.push({ raw: ch, fold: "", start: i, end: i + 1, kind: "PUNCT" });
    i += 1;
  }
  return tokens;
}

function expandContractions(tokens: readonly MutableToken[]): Token[] {
  const out: Token[] = [];
  for (const tok of tokens) {
    if (tok.kind === "WORD") {
      const key = asciiLower(tok.raw);
      const expansion = T.contractionsV1[key];
      if (expansion) {
        let first = true;
        for (const word of expansion) {
          if (first) {
            out.push({ raw: tok.raw, fold: foldOf(word), start: tok.start, end: tok.end, kind: "WORD" });
            first = false;
          } else {
            out.push({ raw: "", fold: foldOf(word), start: tok.end, end: tok.end, kind: "WORD" });
          }
        }
        continue;
      }
    }
    out.push({
      raw: tok.raw,
      fold: tok.raw ? foldOf(tok.raw) : "",
      start: tok.start,
      end: tok.end,
      kind: tok.kind,
    });
  }
  return out;
}

/** One left-to-right scan (rules 1-5), then a POST-PASS contraction
 * expansion, then fold computed for every token. fold =
 * stem_v1(ascii_lower(token)) applied AFTER expansion. Operates over
 * CODE POINTS throughout (see unicode.ts). */
export function tokenize(text: string): Token[] {
  const cps = toCodePoints(text);
  const raw = rawTokenize(cps);
  return expandContractions(raw);
}

/** Tokenize a table entry string through the real tokenizer and return the
 * resulting fold sequence. Spec section 1: "Multi-token entries match as
 * FOLDED TOKEN SEQUENCES after contraction expansion (the loader
 * tokenizes each entry once at load)." */
export function foldSequence(entry: string): string[] {
  return tokenize(entry).map((t) => t.fold);
}

/** Join a fold sequence into a canonical string key for Map/Set membership
 * tests (stands in for Python's native tuple hashing/equality, which
 * compares actual tuples element-by-element -- never string-joins them).
 * Uses JSON.stringify of the array so the key is injective regardless of
 * fold content (quote/comma-delimited array structure cannot collide the
 * way a bare concatenation could, e.g. ["it","s"] vs ["its"], and JSON
 * escaping neutralizes any control character a PUNCT token's fold could
 * carry from raw input). */
export function joinFold(seq: readonly string[]): string {
  return JSON.stringify(seq);
}

// ----------------------------------------------------------------------
// 2.4 Numbers -> Dec
// ----------------------------------------------------------------------

function isAsciiDigits(s: string): boolean {
  if (s.length === 0) return false;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 0x30 || c > 0x39) return false;
  }
  return true;
}

export function parseDec(lexeme: string): Dec {
  let s = lexeme;
  for (const sym of CURRENCY_SYMBOLS) {
    if (s.startsWith(sym)) {
      s = s.slice(sym.length);
      break;
    }
  }
  let sign = 1n;
  if (s.startsWith("+")) {
    s = s.slice(1);
  } else if (s.startsWith("-")) {
    sign = -1n;
    s = s.slice(1);
  }
  if (s.endsWith("%")) s = s.slice(0, -1);

  let intPart: string;
  let fracPart: string;
  const dotIdx = s.indexOf(".");
  if (dotIdx !== -1) {
    intPart = s.slice(0, dotIdx);
    fracPart = s.slice(dotIdx + 1);
  } else {
    intPart = s;
    fracPart = "";
  }
  const intDigits = intPart.split(",").join("");
  if (!isAsciiDigits(intDigits) || (fracPart.length > 0 && !isAsciiDigits(fracPart))) {
    throw new Abstain(MALFORMED_MENTION);
  }
  const digits = intDigits + fracPart;
  const coeff = digits.length > 0 ? sign * BigInt(digits) : 0n;
  const scale = fracPart.length;
  const d = canonicalizeDec({ coefficient: coeff, scale });
  if (digitCount(d.coefficient) > T.MAX_DEC_DIGITS || d.scale > T.MAX_DEC_SCALE) {
    throw new Abstain(MALFORMED_MENTION);
  }
  return d;
}

/** 2.4: the WORD immediately after the number whose fold is a T.units_v1
 * key -> {group, factor}. */
export function unitOf(tok: Token): { group: string; factor: number } | null {
  if (tok.kind !== "WORD") return null;
  return T.unitsV1[tok.fold] ?? null;
}

export function currencyCodeOf(numberTokenRaw: string): string | null {
  for (const [sym, code] of Object.entries(T.currencySymbolsV1)) {
    if (numberTokenRaw.startsWith(sym)) return code;
  }
  return null;
}

// ----------------------------------------------------------------------
// 2.5 parse_values
// ----------------------------------------------------------------------

/** Longest T.comparators_v1 folded token-sequence match ending immediately
 * at tokens[endIdx] (i.e. immediately preceding the NUMBER/PCT100 token at
 * index endIdx). */
function contentPrefixFolds(tokens: readonly Token[], endIdx: number): CompiledComparator | null {
  let best: CompiledComparator | null = null;
  let bestLen = -1;
  for (const entry of COMPARATORS_V1) {
    const ln = entry.folds.length;
    if (endIdx - ln < 0) continue;
    const window = joinFold(tokens.slice(endIdx - ln, endIdx).map((t) => t.fold));
    if (window === joinFold(entry.folds)) {
      if (ln > bestLen) {
        best = entry;
        bestLen = ln;
      }
    }
  }
  return best;
}

function isFillerToken(tok: Token): boolean {
  return tok.kind === "PUNCT" && T.structuralPunctuation.has(tok.raw);
}

/** value_span_tokens: token array for the span under consideration.
 * Returns a tuple of Interval, or null if no NUMBER/PCT100 token is
 * present, or throws Abstain on a malformed span. */
export function parseValues(valueSpanTokens: readonly Token[]): readonly Interval[] | null {
  const numberPositions: number[] = [];
  for (let idx = 0; idx < valueSpanTokens.length; idx++) {
    const k = valueSpanTokens[idx]!.kind;
    if (k === "NUMBER" || k === "PCT100") numberPositions.push(idx);
  }
  if (numberPositions.length === 0) return null;
  if (numberPositions.length > 1) throw new Abstain(MALFORMED_MENTION);

  const idx = numberPositions[0]!;
  const numTok = valueSpanTokens[idx]!;

  if (idx > 0) {
    const prev = valueSpanTokens[idx - 1]!;
    if (APPROX_V1.has(prev.fold)) throw new Abstain(MALFORMED_MENTION);
  }

  const comparator = contentPrefixFolds(valueSpanTokens, idx);

  let v: Dec;
  let unitGroup: string;
  if (numTok.kind === "PCT100") {
    v = parseDec("100");
    unitGroup = "";
  } else {
    v = parseDec(numTok.raw);
    unitGroup = "";
    const cur = currencyCodeOf(numTok.raw);
    if (cur) unitGroup = `currency:${cur}`;
  }

  let consumedHi = idx + 1;
  if (consumedHi < valueSpanTokens.length) {
    const u = unitOf(valueSpanTokens[consumedHi]!);
    if (u !== null) {
      v = decConvert(v, u.factor);
      unitGroup = u.group;
      consumedHi += 1;
    }
  }

  let consumedLo = idx;
  if (comparator !== null) {
    consumedLo = idx - comparator.folds.length;
  }

  for (let i = 0; i < valueSpanTokens.length; i++) {
    if (consumedLo <= i && i < consumedHi) continue;
    if (isFillerToken(valueSpanTokens[i]!)) continue;
    throw new Abstain(MALFORMED_MENTION);
  }

  if (comparator === null) {
    return [{ lo: v, loOpen: false, hi: v, hiOpen: false, unit: unitGroup }];
  }

  const tmpl = comparator.interval;
  const bound = (spec: string | null): Dec | null => {
    if (spec === null) return null;
    if (spec === "v") return v;
    if (spec === "0") return decZero();
    throw new EvaluatorError(`unrecognized comparator bound template ${JSON.stringify(spec)}`);
  };

  return [
    {
      lo: bound(tmpl.lo),
      loOpen: tmpl.lo_open,
      hi: bound(tmpl.hi),
      hiOpen: tmpl.hi_open,
      unit: unitGroup,
    },
  ];
}

// ----------------------------------------------------------------------
// 2.6 sentences / segments / span accounting
// ----------------------------------------------------------------------

function tokenStartsLine(cps: readonly string[], tok: Token): boolean {
  if (tok.start === 0) return true;
  let i = tok.start - 1;
  while (i >= 0 && cps[i] !== "\n" && T.wsV1.has(cps[i]!)) i -= 1;
  return i < 0 || cps[i] === "\n";
}

/** e10 (spec 2.6): indices of line-initial structural LIST MARKER tokens
 * -- a '-'/'*' PUNCT, or a NUMBER plus its immediately following '.'
 * PUNCT, at the start of a line. Requires the original `text` for line
 * positions; without it, no markers are identified. */
export function listMarkerIndices(tokens: readonly Token[], text: string | null): Set<number> {
  const marked = new Set<number>();
  if (text === null) return marked;
  const cps = toCodePoints(text);
  for (let i = 0; i < tokens.length; i++) {
    const tok = tokens[i]!;
    if (!tokenStartsLine(cps, tok)) continue;
    if (tok.kind === "PUNCT" && (tok.raw === "-" || tok.raw === "*")) {
      marked.add(i);
    } else if (
      tok.kind === "NUMBER" &&
      i + 1 < tokens.length &&
      tokens[i + 1]!.kind === "PUNCT" &&
      tokens[i + 1]!.raw === "."
    ) {
      marked.add(i);
      marked.add(i + 1);
    }
  }
  return marked;
}

/** Sentence ends at PUNCT '.', '!', '?' whose next raw char is WS_v1 or
 * EOF. LIST MARKERS (e10) start a new sentence. Requires the original
 * `text` for line positions and the SPLIT_v1 next-char rule; without it
 * only the token-adjacency proxy applies (see primitives.py's comment on
 * why this is an exact proxy). Returns Token[][]. */
export function sentences(tokens: readonly Token[], text: string | null = null): Token[][] {
  const markers = listMarkerIndices(tokens, text);
  const cps = text !== null ? toCodePoints(text) : null;
  const out: Token[][] = [];
  let cur: Token[] = [];
  const n = tokens.length;
  for (let i = 0; i < tokens.length; i++) {
    const tok = tokens[i]!;
    if (cur.length > 0 && markers.has(i) && (i === 0 || !markers.has(i - 1))) {
      out.push(cur);
      cur = [];
    }
    cur.push(tok);
    if (tok.kind === "PUNCT" && T.sentenceTerminators.has(tok.raw) && !markers.has(i)) {
      let terminates: boolean;
      if (cps !== null) {
        terminates = tok.end === cps.length || T.wsV1.has(cps[tok.end]!);
      } else {
        terminates = i + 1 >= n || tokens[i + 1]!.start > tok.end;
      }
      if (terminates) {
        out.push(cur);
        cur = [];
      }
    }
  }
  if (cur.length > 0) out.push(cur);
  return out;
}

/** Segments split at T.structural_punctuation PUNCT tokens (segment
 * boundaries themselves are dropped). */
export function segments(sentenceTokens: readonly Token[]): Token[][] {
  const out: Token[][] = [];
  let cur: Token[] = [];
  for (const tok of sentenceTokens) {
    if (tok.kind === "PUNCT" && T.structuralPunctuation.has(tok.raw)) {
      out.push(cur);
      cur = [];
    } else {
      cur.push(tok);
    }
  }
  out.push(cur);
  return out;
}

/** Content token := fold length >= 3 and fold not in T.stop_v1. */
export function isContentToken(tok: Token): boolean {
  return cpLength(tok.fold) >= 3 && !STOP_V1.has(tok.fold);
}

export function contentTokens(tokens: readonly Token[]): Token[] {
  return tokens.filter(isContentToken);
}

export function isInterrogative(sentenceTokens: readonly Token[]): boolean {
  for (let i = sentenceTokens.length - 1; i >= 0; i--) {
    const tok = sentenceTokens[i]!;
    if (tok.kind === "PUNCT" && T.sentenceTerminators.has(tok.raw)) {
      return tok.raw === "?";
    }
    if (tok.kind !== "PUNCT") break;
  }
  return false;
}

// ----------------------------------------------------------------------
// Compiled fold indices (spec section 1: "the loader tokenizes each entry
// once at load"). Built here, after tokenize() is defined, mirroring
// reference/primitives.py's compiled section (built after tokenize() to
// avoid a circular dependency between tables and primitives -- moot for
// this module split since tables.ts never imports primitives.ts, but kept
// in the same declaration order for one-for-one fidelity).
// ----------------------------------------------------------------------

export const STOP_V1: ReadonlySet<string> = new Set(T.raw.stop_v1.map((w) => foldSequence(w)[0]!));

const _definitiveFoldSeqs: readonly string[][] = T.raw.definitive_v1.map((w) => foldSequence(w));
export const DEFINITIVE_V1: ReadonlySet<string> = new Set(_definitiveFoldSeqs.map((seq) => joinFold(seq)));
// checks.ts's C2 (Python: `max(len(k) for k in DEFINITIVE_V1)`) needs the
// max TOKEN-SEQUENCE LENGTH across entries; the joined-string Set above
// loses that once collapsed to string keys, so it is exported alongside.
export const MAX_DEFINITIVE_LEN: number = _definitiveFoldSeqs.reduce((m, seq) => Math.max(m, seq.length), 1);

const _hedgeFoldSeqs: readonly string[][] = T.raw.hedge_v1.map((w) => foldSequence(w));
export const HEDGE_V1: ReadonlySet<string> = new Set(_hedgeFoldSeqs.map((seq) => joinFold(seq)));
export const MAX_HEDGE_LEN: number = _hedgeFoldSeqs.reduce((m, seq) => Math.max(m, seq.length), 1);
export const HEDGE_WINDOW_BOUNDARIES: ReadonlySet<string> = new Set(
  T.raw.hedge_window_boundaries.map((w) => foldSequence(w)[0]!),
);
export const NEGATORS_V1: ReadonlySet<string> = new Set(T.raw.negators_v1.map((w) => foldSequence(w)[0]!));
export const NEGATION_EXCEPTIONS: ReadonlySet<string> = new Set(
  T.raw.negation_exceptions.map(([a, b]) => joinFold([foldSequence(a)[0]!, foldSequence(b)[0]!])),
);
export const QUANT_UNIVERSAL: ReadonlySet<string> = new Set(
  T.raw.quant_v1.universal.map((w) => foldSequence(w)[0]!),
);
export const QUANT_EXISTENTIAL: ReadonlySet<string> = new Set(
  T.raw.quant_v1.existential.map((w) => foldSequence(w)[0]!),
);
export const QUANT_ABSTAIN: ReadonlySet<string> = new Set(T.raw.quant_v1.abstain.map((w) => foldSequence(w)[0]!));
export const MODAL_ABSTAIN_V1: ReadonlySet<string> = new Set(
  T.raw.modal_abstain_v1.map((w) => foldSequence(w)[0]!),
);
export const ADJUNCT_PREPOSITIONS_V1: ReadonlySet<string> = new Set(
  T.raw.adjunct_prepositions_v1.map((w) => foldSequence(w)[0]!),
);
export const RELATIVE_MARKERS_V1: ReadonlySet<string> = new Set(
  T.raw.relative_markers_v1.map((w) => foldSequence(w)[0]!),
);
export const EXCL_V1: ReadonlySet<string> = new Set(
  T.raw.excl_v1.map((pair) => unorderedPairKey(foldSequence(pair[0])[0]!, foldSequence(pair[1])[0]!)),
);
export const GENERIC_BENEFIT_TRIGGERS_V1: ReadonlySet<string> = new Set(
  T.raw.generic_benefit_triggers_v1.map((w) => foldSequence(w)[0]!),
);
export const FACETPROJ_V1: ReadonlyMap<string, string> = new Map(
  Object.entries(T.raw.facetproj_v1).map(([k, v]) => [foldSequence(k)[0]!, v]),
);
export const CONCEPT_V1: ReadonlyMap<string, string> = new Map(
  Object.entries(T.raw.concept_v1).map(([k, v]) => [foldSequence(k)[0]!, v]),
);

/** The normalized form Bool-atom terms carry: post-stem (fold_sequence)
 * then post-CONCEPT_v1. e9 (spec 4.2): COMPLEMENT_v1 pair lookup operates
 * on this SAME normalized form. */
function boolAtomNormalize(word: string): string {
  const fold = foldSequence(word)[0]!;
  return CONCEPT_V1.get(fold) ?? fold;
}

export const COMPLEMENT_V1: readonly (readonly [string, string])[] = T.raw.complement_v1.map(
  ([a, b]) => [boolAtomNormalize(a), boolAtomNormalize(b)] as const,
);
// e7: participle-vs-stative trigger classification comes from the tables
// artifact (folded forms; never a code list).
export const PARTICIPLE_TRIGGERS_V1: ReadonlySet<string> = new Set(
  T.raw.participle_triggers_v1.map((w) => foldSequence(w)[0]!),
);
export const APPROX_V1: ReadonlySet<string> = new Set(T.raw.approx_v1.map((w) => foldSequence(w)[0]!));

export interface CompiledConditionOperator {
  readonly folds: readonly string[];
  readonly kind: string;
  readonly polarity: string;
  readonly force: 0 | 1;
}
export const CONDITION_OPERATORS_V1: readonly CompiledConditionOperator[] = T.raw.condition_operators_v1.map(
  (op) => ({
    folds: foldSequence(op.tokens.join(" ")),
    kind: op.kind,
    polarity: op.polarity,
    force: op.force === "grant" ? GRANT : RESTRICTION,
  }),
);

export interface CompiledComparator {
  readonly folds: readonly string[];
  readonly interval: { lo: string | null; lo_open: boolean; hi: string | null; hi_open: boolean };
}
export const COMPARATORS_V1: readonly CompiledComparator[] = T.raw.comparators_v1.map((entry) => ({
  folds: foldSequence(entry.tokens.join(" ")),
  interval: entry.interval,
}));

// Trigger index: folded token sequence (joined) -> list[(facet, is_deny)]
function buildTriggerIndex(): {
  index: ReadonlyMap<string, readonly (readonly [string, boolean])[]>;
  maxLen: number;
} {
  const trig = new Map<string, [string, boolean][]>();
  let maxLen = 1;
  for (const [facetName, facet] of Object.entries(T.facetsV1)) {
    for (const trigWord of facet.triggers) {
      const seq = foldSequence(trigWord);
      maxLen = Math.max(maxLen, seq.length);
      const key = joinFold(seq);
      const arr = trig.get(key);
      if (arr) arr.push([facetName, false]);
      else trig.set(key, [[facetName, false]]);
    }
    for (const trigWord of facet.deny_triggers) {
      const seq = foldSequence(trigWord);
      maxLen = Math.max(maxLen, seq.length);
      const key = joinFold(seq);
      const arr = trig.get(key);
      if (arr) arr.push([facetName, true]);
      else trig.set(key, [[facetName, true]]);
    }
  }
  return { index: trig, maxLen };
}

const _triggerIndexBuild = buildTriggerIndex();
export const TRIGGER_INDEX = _triggerIndexBuild.index;
export const MAX_TRIGGER_LEN = _triggerIndexBuild.maxLen;
