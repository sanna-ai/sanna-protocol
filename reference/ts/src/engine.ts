/**
 * Section 4.1/4.2 of ALGORITHM v4 draft 5.4: bitsets, varmap, elementary
 * interval decomposition, GAMMA, and the boolean queries (SAT/UNSAT/EQUIV/
 * NEGATE/ENTAILS/DOMAIN/IMPLIES). Depends only on primitives.ts (Bool AST +
 * Dec/Interval) and tables.ts (MAX_BOOL_ATOMS); does not depend on
 * extraction.ts, so extraction.ts can safely import this module without a
 * cycle. Mirrors reference/engine.py one-for-one.
 *
 * A note on internal ordering vs. output determinism: Python's build_varmap
 * assigns boolean-variable indices via `sorted(canonical_keys, key=...)` --
 * a specific, reproducible order. This module intentionally does NOT
 * replicate that exact ordering (via Map insertion order instead): the
 * Bitset arithmetic (AND/OR/NOT/SAT/ENTAILS/...) is invariant under variable
 * relabeling -- a boolean formula's truth value never depends on which
 * index a given variable happens to occupy -- so the assigned index order
 * has no effect on any evaluate() output. It is purely an internal
 * implementation bookkeeping detail. (The one place the actual VALUE order
 * of Dec endpoints matters -- decompose()'s interval endpoints, which
 * define the different elementary intervals themselves, not just their
 * bookkeeping index -- IS sorted by true numeric value via dec_cmp, exactly
 * mirroring Python.)
 */

import { T } from "./tables.js";
import { FSet } from "./fset.js";
import {
  Bool,
  COMPLEMENT_V1,
  Dec,
  Interval,
  MeasureAtom,
  MeasureQty,
  TermAtom,
  decCmp,
  mkAnd,
  worstCause,
} from "./primitives.js";

export class EnvelopeExceeded extends Error {}

export class Uncompilable extends Error {
  readonly cause: string;
  constructor(cause: string) {
    super(cause);
    this.name = "Uncompilable";
    this.cause = cause;
  }
}

// --------------------------------------------------------------------------
// Bitset (section 4.1): EXACTLY 2^n valid bits, held in a single arbitrary-
// precision BigInt (Python's Bitset.words is likewise a single native
// Python int despite the "ceil(2^n/64) words" docstring framing -- the
// actual implementation never splits into 64-bit words). Padding bits
// above 2^n are ALWAYS zero; NOT(F) = mask_n & ~F.words (width-bounded);
// every op that could set padding re-masks.
// --------------------------------------------------------------------------

export class Bitset {
  readonly n: number;
  readonly size: number; // 2^n valid bits
  readonly mask: bigint;
  readonly words: bigint;

  constructor(n: number, words: bigint = 0n) {
    this.n = n;
    this.size = 2 ** n;
    this.mask = (1n << BigInt(this.size)) - 1n;
    this.words = words & this.mask;
  }

  static zero(n: number): Bitset {
    return new Bitset(n, 0n);
  }

  static full(n: number): Bitset {
    return new Bitset(n, (1n << BigInt(2 ** n)) - 1n);
  }

  private checkWidth(other: Bitset): void {
    if (other.n !== this.n) {
      throw new RangeError(`bitset width mismatch: ${this.n} vs ${other.n}`);
    }
  }

  opAnd(other: Bitset): Bitset {
    this.checkWidth(other);
    return new Bitset(this.n, this.words & other.words);
  }

  opOr(other: Bitset): Bitset {
    this.checkWidth(other);
    return new Bitset(this.n, this.words | other.words);
  }

  opXor(other: Bitset): Bitset {
    this.checkWidth(other);
    return new Bitset(this.n, this.words ^ other.words);
  }

  opNot(): Bitset {
    return new Bitset(this.n, this.mask & ~this.words);
  }

  isZero(): boolean {
    return this.words === 0n;
  }

  isNonzero(): boolean {
    return this.words !== 0n;
  }

  equals(other: Bitset): boolean {
    this.checkWidth(other);
    return this.words === other.words;
  }
}

// --------------------------------------------------------------------------
// Elementary intervals (section 4.1 decompose) + GAMMA (build_gamma)
// --------------------------------------------------------------------------

/** An elementary interval indicator's bounds (no `unit` -- unlike
 * Interval, an indicator is a pure number-line region). */
export interface Bound {
  readonly lo: Dec | null;
  readonly loOpen: boolean;
  readonly hi: Dec | null;
  readonly hiOpen: boolean;
}

function endpoints(intervals: readonly Interval[]): Dec[] {
  const finite: Dec[] = [];
  for (const iv of intervals) {
    if (iv.lo !== null) finite.push(iv.lo);
    if (iv.hi !== null) finite.push(iv.hi);
  }
  finite.sort(decCmp);
  const out: Dec[] = [];
  for (const d of finite) {
    if (out.length === 0 || decCmp(out[out.length - 1]!, d) !== 0) {
      out.push(d);
    }
  }
  return out;
}

/** Convert all bounds to elementary-interval indicators. Endpoints are
 * dec_cmp-sorted unique finite bounds e1..ek; indicators in order:
 * (-inf,e1), [e1,e1], (e1,e2), [e2,e2], ..., [ek,ek], (ek,+inf) => 2k+1
 * variables. Index i in the returned array IS the indicator's position for
 * GAMMA's exactly-one group. */
export function decompose(quantityIntervals: readonly Interval[]): Bound[] {
  const eps = endpoints(quantityIntervals);
  const k = eps.length;
  const indicators: Bound[] = [];
  if (k === 0) {
    indicators.push({ lo: null, loOpen: true, hi: null, hiOpen: true });
    return indicators;
  }
  indicators.push({ lo: null, loOpen: true, hi: eps[0]!, hiOpen: true });
  for (let idx = 0; idx < k; idx++) {
    const e = eps[idx]!;
    indicators.push({ lo: e, loOpen: false, hi: e, hiOpen: false });
    if (idx + 1 < k) {
      indicators.push({ lo: e, loOpen: true, hi: eps[idx + 1]!, hiOpen: true });
    }
  }
  indicators.push({ lo: eps[k - 1]!, loOpen: true, hi: null, hiOpen: true });
  return indicators;
}

/** Does interval iv (with open/closed bounds) cover elementary indicator
 * ind (an elementary indicator, by construction of decompose, either a
 * single point [e,e] or an open span strictly between two consecutive
 * contributing endpoints, possibly unbounded on one/both sides)? */
function intervalCoversIndicator(iv: Interval, indicator: Bound): boolean {
  const ilo = indicator.lo;
  const iloOpen = indicator.loOpen;
  const ihi = indicator.hi;
  const ihiOpen = indicator.hiOpen;

  if (ilo !== null && iloOpen === false && ihi !== null && ihiOpen === false && decCmp(ilo, ihi) === 0) {
    // point indicator [e, e]
    const e = ilo;
    if (iv.lo !== null) {
      const c = decCmp(e, iv.lo);
      if (c < 0 || (c === 0 && iv.loOpen)) return false;
    }
    if (iv.hi !== null) {
      const c = decCmp(e, iv.hi);
      if (c > 0 || (c === 0 && iv.hiOpen)) return false;
    }
    return true;
  }
  // open span indicator (possibly unbounded on one/both sides)
  if (iv.lo !== null && ilo !== null) {
    const c = decCmp(ilo, iv.lo);
    if (c < 0) return false;
  }
  if (iv.lo !== null && ilo === null) return false;
  if (iv.hi !== null && ihi !== null) {
    const c = decCmp(ihi, iv.hi);
    if (c > 0) return false;
  }
  if (iv.hi !== null && ihi === null) return false;
  return true;
}

function indicatorBitmaskForIntervals(intervals: readonly Interval[], indicators: readonly Bound[]): number {
  let mask = 0;
  for (let i = 0; i < indicators.length; i++) {
    for (const iv of intervals) {
      if (intervalCoversIndicator(iv, indicators[i]!)) {
        mask |= 1 << i;
        break;
      }
    }
  }
  return mask;
}

/** BUILD_EXACTLY_ONE(indicators): exactly one of the given variables (by
 * bit index in the nVars-variable space) is true in a valid assignment. */
export function buildExactlyOneGroup(nVars: number, varIndices: readonly number[]): Bitset {
  const bs = Bitset.zero(nVars);
  const size = bs.size;
  let words = 0n;
  for (let assignment = 0; assignment < size; assignment++) {
    let count = 0;
    for (const vi of varIndices) {
      if ((assignment >> vi) & 1) count += 1;
    }
    if (count === 1) {
      words |= 1n << BigInt(assignment);
    }
  }
  return new Bitset(nVars, words & bs.mask);
}

/** per quantity: BUILD_EXACTLY_ONE(indicators); combine across Q
 * quantities with AND_REDUCE. Q == 0 -> GAMMA = TOP (full mask). */
export function buildGamma(nVars: number, quantityVarGroups: readonly (readonly number[])[]): Bitset {
  if (quantityVarGroups.length === 0) return Bitset.full(nVars);
  let gamma = Bitset.full(nVars);
  for (const group of quantityVarGroups) {
    gamma = gamma.opAnd(buildExactlyOneGroup(nVars, group));
  }
  return gamma;
}

// --------------------------------------------------------------------------
// build_varmap (section 4.1): keys = ATOMENC atom bytes EXCLUDING the
// restrictive flag (variable identity = terms + polarity); COMPLEMENT_v1
// pairs and opposite-polarity twins collapse to ONE variable (negated side
// flagged); MeasureAtoms expand to elementary-interval indicators.
// --------------------------------------------------------------------------

/** Fold COMPLEMENT_v1 pairs to a single canonical variable identity. Only
 * applies when `terms` is a single-term atom whose sole term is the
 * "negated side" of a configured complement pair; multi-term atoms are
 * never complement-folded (COMPLEMENT_v1 entries are single words). e9
 * (spec 4.2): the pair lookup operates on the SAME normalized form as Bool
 * atoms (post-stem, post-CONCEPT_v1) -- the normalized pairs are compiled
 * once in primitives.ts (COMPLEMENT_V1). */
function canonicalTermKey(terms: FSet): [FSet, boolean] {
  if (terms.size === 1) {
    const term = terms.toArray()[0]!;
    for (const [positive, negative] of COMPLEMENT_V1) {
      if (term === negative) return [FSet.of([positive]), true];
      if (term === positive) return [FSet.of([positive]), false];
    }
  }
  return [terms, false];
}

function collectAtoms(node: Bool, termAtoms: TermAtom[], measureAtoms: MeasureAtom[]): void {
  switch (node.kind) {
    case "TermAtom":
      termAtoms.push(node);
      return;
    case "MeasureAtom":
      measureAtoms.push(node);
      return;
    case "UnknownAtom":
      return;
    case "Not":
      collectAtoms(node.child, termAtoms, measureAtoms);
      return;
    case "And":
    case "Or":
      for (const c of node.children) collectAtoms(c, termAtoms, measureAtoms);
      return;
    case "TOP":
    case "BOTTOM":
      return;
  }
}

function qtyKey(q: MeasureQty): string {
  return JSON.stringify([q[0], q[1].key(), q[2]]);
}

export class Compiled {
  constructor(
    readonly n: number,
    readonly termVarIndex: ReadonlyMap<string, number>,
    readonly negatedOf: ReadonlyMap<string, boolean>,
    readonly qtyVarGroups: ReadonlyMap<string, readonly number[]>,
    readonly qtyIndicators: ReadonlyMap<string, readonly Bound[]>,
    readonly gamma: Bitset,
  ) {}

  private varBitset(index: number): Bitset {
    const size = 2 ** this.n;
    let words = 0n;
    for (let a = 0; a < size; a++) {
      if ((a >> index) & 1) {
        words |= 1n << BigInt(a);
      }
    }
    return new Bitset(this.n, words);
  }

  compile(node: Bool): Bitset {
    switch (node.kind) {
      case "TOP":
        return Bitset.full(this.n);
      case "BOTTOM":
        return Bitset.zero(this.n);
      case "TermAtom": {
        const [key, baseNeg] = canonicalTermKey(node.terms);
        const idx = this.termVarIndex.get(key.key());
        if (idx === undefined) {
          throw new RangeError(`internal error: unknown variable ${key.key()}`);
        }
        const negate = baseNeg !== (node.pol === 1);
        const v = this.varBitset(idx);
        return negate ? v.opNot() : v;
      }
      case "MeasureAtom": {
        const k = qtyKey(node.qty);
        const varIndices = this.qtyVarGroups.get(k) ?? [];
        const indicators = this.qtyIndicators.get(k) ?? [];
        const covered = indicatorBitmaskForIntervals(node.intervals, indicators);
        let bs = Bitset.zero(this.n);
        for (let localI = 0; localI < varIndices.length; localI++) {
          if ((covered >> localI) & 1) {
            bs = bs.opOr(this.varBitset(varIndices[localI]!));
          }
        }
        return bs;
      }
      case "UnknownAtom":
        throw new Uncompilable(node.cause);
      case "Not":
        return this.compile(node.child).opNot();
      case "And": {
        let result = Bitset.full(this.n);
        for (const c of node.children) result = result.opAnd(this.compile(c));
        return result;
      }
      case "Or": {
        let result = Bitset.zero(this.n);
        for (const c of node.children) result = result.opOr(this.compile(c));
        return result;
      }
    }
  }
}

/** Returns a Compiled object or throws EnvelopeExceeded if
 * |variables| > MAX_BOOL_ATOMS. */
export function buildVarmap(taskFormulas: readonly Bool[]): Compiled {
  const termAtoms: TermAtom[] = [];
  const measureAtoms: MeasureAtom[] = [];
  for (const f of taskFormulas) collectAtoms(f, termAtoms, measureAtoms);

  const canonicalKeys = new Map<string, FSet>();
  const negatedOf = new Map<string, boolean>();
  for (const atom of termAtoms) {
    const [key, neg] = canonicalTermKey(atom.terms);
    canonicalKeys.set(key.key(), key);
    negatedOf.set(key.key(), neg);
  }
  const sortedKeys = Array.from(canonicalKeys.values());

  const qtyIntervals = new Map<string, { qty: MeasureQty; intervals: Interval[] }>();
  for (const atom of measureAtoms) {
    const k = qtyKey(atom.qty);
    const existing = qtyIntervals.get(k);
    if (existing) {
      existing.intervals.push(...atom.intervals);
    } else {
      qtyIntervals.set(k, { qty: atom.qty, intervals: atom.intervals.slice() });
    }
  }
  const sortedQtys = Array.from(qtyIntervals.values());

  const termVarIndex = new Map<string, number>();
  sortedKeys.forEach((key, i) => termVarIndex.set(key.key(), i));
  let n = sortedKeys.length;

  const qtyVarGroups = new Map<string, number[]>();
  const qtyIndicators = new Map<string, Bound[]>();
  for (const { qty, intervals } of sortedQtys) {
    const indicators = decompose(intervals);
    const varIndices: number[] = [];
    for (let x = 0; x < indicators.length; x++) varIndices.push(n + x);
    n += indicators.length;
    const k = qtyKey(qty);
    qtyVarGroups.set(k, varIndices);
    qtyIndicators.set(k, indicators);
  }

  if (n > T.MAX_BOOL_ATOMS) {
    throw new EnvelopeExceeded(`envelope_exceeded: ${n} > MAX_BOOL_ATOMS=${T.MAX_BOOL_ATOMS}`);
  }

  const gamma = buildGamma(n, Array.from(qtyVarGroups.values()));

  return new Compiled(n, termVarIndex, negatedOf, qtyVarGroups, qtyIndicators, gamma);
}

/** SET ARITHMETIC ONLY (spec section 8): the number of boolean variables
 * the task would materialize -- canonical TermAtom keys (complement-folded)
 * plus 2k+1 elementary-interval indicators per MeasureAtom quantity --
 * computed without building any bitset. Mirrors build_varmap's counting
 * phase exactly. */
export function preflightAtomCount(taskFormulas: readonly Bool[]): number {
  const termAtoms: TermAtom[] = [];
  const measureAtoms: MeasureAtom[] = [];
  for (const f of taskFormulas) collectAtoms(f, termAtoms, measureAtoms);

  const canonicalKeys = new Set<string>();
  for (const a of termAtoms) {
    const [key] = canonicalTermKey(a.terms);
    canonicalKeys.add(key.key());
  }

  const qtyIntervals = new Map<string, Interval[]>();
  for (const atom of measureAtoms) {
    const k = qtyKey(atom.qty);
    const existing = qtyIntervals.get(k);
    if (existing) existing.push(...atom.intervals);
    else qtyIntervals.set(k, atom.intervals.slice());
  }

  let n = canonicalKeys.size;
  for (const intervals of qtyIntervals.values()) {
    n += decompose(intervals).length;
  }
  return n;
}

/** Node count of a formula AST (COMPILE(F) = nodes(F) in the pinned
 * BOOLISA_v1 cost macros, spec section 8). */
export function boolNodes(node: Bool): number {
  switch (node.kind) {
    case "TOP":
    case "BOTTOM":
    case "TermAtom":
    case "MeasureAtom":
    case "UnknownAtom":
      return 1;
    case "Not":
      return 1 + boolNodes(node.child);
    case "And":
    case "Or":
      return 1 + node.children.reduce((sum, c) => sum + boolNodes(c), 0);
  }
}

function containsUnknown(node: Bool): string | null {
  switch (node.kind) {
    case "UnknownAtom":
      return node.cause;
    case "Not":
      return containsUnknown(node.child);
    case "And":
    case "Or": {
      const causes: string[] = [];
      for (const c of node.children) {
        const cu = containsUnknown(c);
        if (cu) causes.push(cu);
      }
      if (causes.length > 0) return worstCause(causes);
      return null;
    }
    default:
      return null;
  }
}

export function uncompilable(node: Bool): boolean {
  return containsUnknown(node) !== null;
}

/** Named `causeOf` (not `cause`, a common local parameter name elsewhere in
 * this package) -- corresponds to Python's `engine.cause(node)`. */
export function causeOf(node: Bool): string | null {
  return containsUnknown(node);
}

// --------------------------------------------------------------------------
// 4.2 Queries
// --------------------------------------------------------------------------

export function SAT(compiled: Compiled, F: Bool): boolean {
  const fb = compiled.compile(F);
  return fb.opAnd(compiled.gamma).isNonzero();
}

export function UNSAT(compiled: Compiled, F: Bool): boolean {
  return !SAT(compiled, F);
}

export function EQUIV(compiled: Compiled, F: Bool, H: Bool): boolean {
  const fb = compiled.compile(F);
  const hb = compiled.compile(H);
  return fb.opXor(hb).opAnd(compiled.gamma).isZero();
}

export function NEGATE(compiled: Compiled, F: Bool): Bitset {
  return compiled.compile(F).opNot();
}

function termAtomsOf(node: Bool, out: TermAtom[]): void {
  switch (node.kind) {
    case "TermAtom":
      out.push(node);
      return;
    case "Not":
      termAtomsOf(node.child, out);
      return;
    case "And":
    case "Or":
      for (const c of node.children) termAtomsOf(c, out);
      return;
    default:
      return;
  }
}

/** YES|NO. STRUCTURAL PRE-CHECK, GENERALIZED at e9 (spec 4.2, normative):
 * collect the TermAtoms of F and H. An atom pairing (same variable) with
 * mismatched restrictive flags provides NO entailment, in EITHER
 * direction. If ANY H TermAtom -- grant or restrictive -- has no
 * flag-matching F counterpart on a variable that F constrains, return NO.
 * Variables F does NOT constrain carry no structural verdict (so BOTTOM
 * still entails everything semantically). */
export function ENTAILS(compiled: Compiled, F: Bool, H: Bool): "YES" | "NO" {
  const fAtoms: TermAtom[] = [];
  const hAtoms: TermAtom[] = [];
  termAtomsOf(F, fAtoms);
  termAtomsOf(H, hAtoms);

  const fByVar = new Map<number, Set<0 | 1>>();
  for (const a of fAtoms) {
    const [key] = canonicalTermKey(a.terms);
    const idx = compiled.termVarIndex.get(key.key());
    if (idx !== undefined) {
      let set = fByVar.get(idx);
      if (!set) {
        set = new Set<0 | 1>();
        fByVar.set(idx, set);
      }
      set.add(a.restrictive);
    }
  }

  for (const a of hAtoms) {
    const [key] = canonicalTermKey(a.terms);
    const idx = compiled.termVarIndex.get(key.key());
    if (idx === undefined) continue;
    const flagsOnF = fByVar.get(idx);
    if (flagsOnF === undefined) continue; // F does not constrain this variable
    if (!flagsOnF.has(a.restrictive)) return "NO";
  }

  const fb = compiled.compile(F);
  const hn = NEGATE(compiled, H);
  return fb.opAnd(hn).opAnd(compiled.gamma).isZero() ? "YES" : "NO";
}

/** UNKNOWN (uncompilable) | DISJOINT (UNSAT either or !SAT(D1&D2)) |
 * OVERLAP. */
export function DOMAIN(compiledOrNull: Compiled | null, D1: Bool, D2: Bool): "UNKNOWN" | "DISJOINT" | "OVERLAP" {
  if (uncompilable(D1) || uncompilable(D2)) return "UNKNOWN";
  const compiled = compiledOrNull ?? buildVarmap([D1, D2]);
  if (UNSAT(compiled, D1) || UNSAT(compiled, D2)) return "DISJOINT";
  if (!SAT(compiled, mkAnd([D1, D2]))) return "DISJOINT";
  return "OVERLAP";
}

/** UNKNOWN | YES iff ENTAILS(a,b) | NO. */
export function IMPLIES(compiled: Compiled | null, a: Bool, b: Bool): "UNKNOWN" | "YES" | "NO" {
  if (uncompilable(a) || uncompilable(b)) return "UNKNOWN";
  const c = compiled ?? buildVarmap([a, b]);
  return ENTAILS(c, a, b) === "YES" ? "YES" : "NO";
}
