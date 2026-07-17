/**
 * Section 6 of ALGORITHM v4 draft 5.5: C1, C2, C3, C4 (rows = FREEZE v18.6
 * sec 3). C5 is EXCLUDED from this slice (C_COV uncalibrated, SAN-882) --
 * evaluate() simply produces C1-C4; no C5 API surface (not even a
 * NotImplemented stub) is exposed. Mirrors reference/checks.py one-for-one.
 */

import { T, unorderedPairKey } from "./tables.js";
import { ModSet } from "./fset.js";
import * as engine from "./engine.js";
import * as relations from "./relations.js";
import * as extraction from "./extraction.js";
import {
  BOTTOM_,
  Bool,
  CONDITION_UNDECIDABLE,
  DEFINITIVE_V1,
  EXCL_V1,
  EXISTENTIAL,
  EXPLICIT,
  Evidence,
  Extent,
  Frame,
  HEDGE_V1,
  HEDGE_WINDOW_BOUNDARIES,
  IMPLICIT,
  MALFORMED_MENTION,
  MAX_DEFINITIVE_LEN,
  MAX_HEDGE_LEN,
  Obligation,
  POS,
  TOP_,
  Token,
  eff,
  effQuant,
  joinFold,
  mkAnd,
  mkNot,
  mkOr,
  worstCause,
} from "./primitives.js";

export const NOT_EVALUATED = "NOT_EVALUATED";
export const VIOLATION = "VIOLATION";
export const PASS = "PASS";

export const CRITICAL = "critical";
export const WARNING = "warning";

/** D(f) = conds_as_formula(f) -- the frame's own condition domain. Exported
 * for evaluate.ts's per-check budget preflight (Python: `from
 * reference.checks import D`, a local import inside each `_budget_*`
 * function to avoid a module-level cycle; TS has no such cycle since
 * evaluate.ts already imports checks.ts at module scope). */
export function D(frame: Frame): Bool {
  return extraction.condsAsFormula(frame.conds);
}

export const TIER_1 = "tier_1";
export const TIER_2 = "tier_2";
export const TIER_3 = "tier_3";

function tierOf(frame: Frame, tiers: ReadonlyMap<number, string> | null): string {
  if (!tiers || tiers.size === 0) return TIER_1;
  return tiers.get(frame.frameId) ?? TIER_1;
}

/** spec 6 C1 step 1: trusted = assertive frames whose declared source tier
 * is tier_1 or tier_2. `tiers` maps frameId -> tier string; frames without
 * an entry default to tier_1 (the fixture schema's plain-context shape
 * declares a single tier_1 source). */
export function trusted(frames: readonly Frame[], tiers: ReadonlyMap<number, string> | null = null): Frame[] {
  return frames.filter((f) => {
    if (!f.assertive) return false;
    const t = tierOf(f, tiers);
    return t === TIER_1 || t === TIER_2;
  });
}

function tier3(frames: readonly Frame[], tiers: ReadonlyMap<number, string> | null = null): Frame[] {
  return frames.filter((f) => f.assertive && tierOf(f, tiers) === TIER_3);
}

// --------------------------------------------------------------------------
// C1
// --------------------------------------------------------------------------

/** [outcome, outcome_reason, severity, advisory]. `advisory` is True only
 * on the row-9 outcome (t3-only contradiction with a nonempty
 * authoritative basis): differential-harness / internal rendering
 * metadata ONLY -- never a CheckResult field (see evaluate.ts). */
export type C1Result = readonly [string, string, string | null, boolean];

export function C1(
  ctxFrames: readonly Frame[],
  outFrames: readonly Frame[],
  ctxPartial: boolean,
  outPartial: boolean,
  tiers: ReadonlyMap<number, string> | null = null,
): C1Result {
  if (ctxPartial || outPartial) {
    return [NOT_EVALUATED, "extraction_partial", null, false];
  }

  const trustedFrames = trusted(ctxFrames, tiers);
  const t3Frames = tier3(ctxFrames, tiers);

  // spec step 2: self_conf is the SET OF FRAMES (union over conflicting
  // comparable pairs), not a set of pairs.
  const selfConf = new Set<number>();
  for (let a = 0; a < trustedFrames.length; a++) {
    for (let b = a + 1; b < trustedFrames.length; b++) {
      const fa = trustedFrames[a]!;
      const fb = trustedFrames[b]!;
      const r = relations.identityRelation(fa.extent, D(fa), fb.extent, D(fb), false);
      if (r === "COMPARABLE" && relations.disposition(fa, fb) === "CONFLICT") {
        selfConf.add(a);
        selfConf.add(b);
      }
    }
  }

  let anyViolating = false;
  let anyBlockedConflict = false;
  let anyAmbiguous = false;
  const blockedUndecCauses: string[] = [];
  const outAssertive = outFrames.filter((f) => f.assertive);

  for (const fo of outAssertive) {
    const cmpIdx: number[] = [];
    const causes: string[] = [];
    trustedFrames.forEach((c, i) => {
      const r = relations.identityRelation(fo.extent, D(fo), c.extent, D(c), false);
      if (r === "COMPARABLE") {
        cmpIdx.push(i);
      } else if (r === "INERT") {
        // continue
      } else {
        causes.push(relations.relCause(r)!);
      }
    });

    const disps: relations.DispositionResult[] = [];
    for (const i of cmpIdx) {
      const dResult = relations.disposition(fo, trustedFrames[i]!);
      if (relations.relIsUndecidable(dResult)) {
        causes.push(relations.relCause(dResult)!);
      } else {
        disps.push(dResult);
      }
    }

    // spec step 3 status rows, in order: BLOCKED_CONFLICT fires whenever
    // ANY comparable basis frame belongs to self_conf.
    let status: "VIOLATING" | "BLOCKED_CONFLICT" | "AMBIGUOUS" | "CLEAN" | readonly ["BLOCKED_UNDEC", string];
    if (cmpIdx.some((i) => selfConf.has(i))) {
      status = "BLOCKED_CONFLICT";
    } else if (causes.length > 0) {
      status = ["BLOCKED_UNDEC", worstCause(causes)];
    } else if (disps.length > 0 && disps.every((d) => d === "CONFLICT")) {
      status = "VIOLATING";
    } else if (disps.some((d) => d === "CONFLICT") && disps.some((d) => d === "MATCH")) {
      status = "AMBIGUOUS";
    } else {
      status = "CLEAN";
    }

    if (status === "VIOLATING") {
      anyViolating = true;
    } else if (status === "BLOCKED_CONFLICT") {
      anyBlockedConflict = true;
    } else if (status === "AMBIGUOUS") {
      anyAmbiguous = true;
    } else if (Array.isArray(status) && status[0] === "BLOCKED_UNDEC") {
      blockedUndecCauses.push(status[1]);
    }
  }

  if (anyViolating) return [VIOLATION, "detection_complete", CRITICAL, false];
  if (anyBlockedConflict) return [NOT_EVALUATED, "basis_conflict", null, false];
  if (anyAmbiguous) return [NOT_EVALUATED, "identity_ambiguous", null, false];
  if (blockedUndecCauses.includes(MALFORMED_MENTION)) {
    return [NOT_EVALUATED, "unsupported_claim_form", null, false];
  }
  if (blockedUndecCauses.length > 0) {
    return [NOT_EVALUATED, "condition_undecidable", null, false];
  }

  // row 9: t3-only contradiction, authoritative basis nonempty -> PASS +
  // advisory body note.
  let advisory = false;
  if (trustedFrames.length > 0 && t3Frames.length > 0) {
    outer: for (const fo of outAssertive) {
      for (const tf of t3Frames) {
        const r = relations.identityRelation(fo.extent, D(fo), tf.extent, D(tf), false);
        if (r === "COMPARABLE" && relations.disposition(fo, tf) === "CONFLICT") {
          advisory = true;
          break outer;
        }
      }
    }
  }
  return [PASS, "detection_complete", null, advisory];
}

// --------------------------------------------------------------------------
// C2
// --------------------------------------------------------------------------

export type C2Result = readonly [string, string, string | null];

/** outPartial here is C2's OWN field-partial signal (e11, operator-
 * ratified): C2 field PARTIAL means C2's OWN normalization/tokenization/
 * lexical scan is incomplete, OR the governed output is interrogative. C2
 * does NOT inherit proposition-frame extraction partiality. */
export function C2(outTokens: readonly Token[], outPartial: boolean): C2Result {
  if (outPartial) return [NOT_EVALUATED, "extraction_partial", null];

  const segBounds = extraction.segmentBounds(outTokens);
  const n = outTokens.length;
  const maxDefLen = MAX_DEFINITIVE_LEN;
  const maxHedgeLen = MAX_HEDGE_LEN;

  for (let i = 0; i < n; i++) {
    let matchedDef: [number, number] | null = null;
    for (let length = Math.min(maxDefLen, n - i); length > 0; length--) {
      const key = joinFold(outTokens.slice(i, i + length).map((t) => t.fold));
      if (DEFINITIVE_V1.has(key)) {
        matchedDef = [i, i + length];
        break;
      }
    }
    if (matchedDef === null) continue;
    const dLo = matchedDef[0];
    const dHi = matchedDef[1];
    if (extraction.NEG_v1(outTokens, matchedDef, segBounds)) continue;

    let seg: [number, number] = [0, n];
    for (const [lo, hi] of segBounds) {
      if (lo <= dLo && dLo < hi) {
        seg = [lo, hi];
        break;
      }
    }
    let wLo = Math.max(seg[0], dLo - T.W_HEDGE);
    let wHi = Math.min(seg[1], dHi + T.W_HEDGE);
    for (let b = dLo - 1; b >= wLo; b--) {
      if (HEDGE_WINDOW_BOUNDARIES.has(outTokens[b]!.fold)) {
        wLo = b + 1;
        break;
      }
    }
    for (let b = dHi; b < wHi; b++) {
      if (HEDGE_WINDOW_BOUNDARIES.has(outTokens[b]!.fold)) {
        wHi = b;
        break;
      }
    }

    let foundHedge = false;
    let j = wLo;
    while (j < wHi) {
      let matchedH: [number, number] | null = null;
      for (let length = Math.min(maxHedgeLen, wHi - j); length > 0; length--) {
        const key = joinFold(outTokens.slice(j, j + length).map((t) => t.fold));
        if (HEDGE_V1.has(key)) {
          matchedH = [j, j + length];
          break;
        }
      }
      if (matchedH !== null) {
        if (!extraction.NEG_v1(outTokens, matchedH, segBounds)) {
          foundHedge = true;
          break;
        }
        j = matchedH[1];
      } else {
        j += 1;
      }
    }
    if (!foundHedge) {
      return [VIOLATION, "detection_complete", WARNING];
    }
  }

  return [PASS, "detection_complete", null];
}

// --------------------------------------------------------------------------
// support() -- shared helper for C3
// --------------------------------------------------------------------------

export interface SupportResult {
  readonly definiteRoot: Bool;
  readonly possibleRoot: Bool;
}

function isLeaf(node: Bool): boolean {
  return node.kind === "TermAtom" || node.kind === "MeasureAtom" || node.kind === "Not";
}

function childrenForReduce(node: Bool): [("AND" | "OR") | null, readonly Bool[]] {
  if (node.kind === "And") return ["AND", node.children];
  if (node.kind === "Or") return ["OR", node.children];
  return [null, []];
}

/** TOTALITY (e2): the recursion is total over {TermAtom, MeasureAtom, AND,
 * OR, NOT}; a residual NOT(...) subtree is a TERMINAL support unit (LEAF):
 * direct entailment only, no recursion into its child. */
export function support(reqRoot: Bool, bound: readonly Evidence[]): SupportResult {
  function directPos(n: Bool, compiled: engine.Compiled): Bool {
    const domains = bound.filter((e) => engine.ENTAILS(compiled, eff(e), n) === "YES").map((e) => e.domain);
    return orReduceBool(domains);
  }
  function directNeg(n: Bool, compiled: engine.Compiled): Bool {
    const domains = bound.filter((e) => engine.ENTAILS(compiled, eff(e), mkNot(n)) === "YES").map((e) => e.domain);
    return orReduceBool(domains);
  }
  function anyneg(n: Bool, compiled: engine.Compiled): Bool {
    if (isLeaf(n)) return directNeg(n, compiled);
    const [kind, children] = childrenForReduce(n);
    if (kind === "AND") {
      return or2(directNeg(n, compiled), orReduceBool(children.map((c) => anyneg(c, compiled))));
    }
    if (kind === "OR") {
      return or2(directNeg(n, compiled), andReduceBool(children.map((c) => anyneg(c, compiled))));
    }
    return directNeg(n, compiled);
  }
  function definite(n: Bool, compiled: engine.Compiled): Bool {
    const base = and2(directPos(n, compiled), mkNot(anyneg(n, compiled)));
    if (isLeaf(n)) return base;
    const [kind, children] = childrenForReduce(n);
    if (kind === "AND") return or2(base, andReduceBool(children.map((c) => definite(c, compiled))));
    if (kind === "OR") return or2(base, orReduceBool(children.map((c) => definite(c, compiled))));
    return base;
  }
  function possible(n: Bool, compiled: engine.Compiled): Bool {
    if (isLeaf(n)) return directPos(n, compiled);
    const [kind, children] = childrenForReduce(n);
    if (kind === "AND") return or2(directPos(n, compiled), andReduceBool(children.map((c) => possible(c, compiled))));
    if (kind === "OR") return or2(directPos(n, compiled), orReduceBool(children.map((c) => possible(c, compiled))));
    return directPos(n, compiled);
  }

  const taskFormulas: Bool[] = [reqRoot, ...bound.map((e) => eff(e)), ...bound.map((e) => e.domain)];
  const compiled = engine.buildVarmap(taskFormulas);

  return { definiteRoot: definite(reqRoot, compiled), possibleRoot: possible(reqRoot, compiled) };
}

/** OR_REDUCE([]) = BOTTOM (pinned). */
function orReduceBool(items: readonly Bool[]): Bool {
  const arr = items;
  if (arr.length === 0) return BOTTOM_;
  if (arr.length === 1) return arr[0]!;
  return mkOr(arr);
}

/** AND_REDUCE([]) = TOP (pinned). */
function andReduceBool(items: readonly Bool[]): Bool {
  const arr = items;
  if (arr.length === 0) return TOP_;
  if (arr.length === 1) return arr[0]!;
  return mkAnd(arr);
}

function or2(a: Bool, b: Bool): Bool {
  return orReduceBool([a, b]);
}
function and2(a: Bool, b: Bool): Bool {
  return andReduceBool([a, b]);
}

// --------------------------------------------------------------------------
// C3
// --------------------------------------------------------------------------

export type C3Result = readonly [string, string, string | null];

export function C3(
  ctxFrames: readonly Frame[],
  outFrames: readonly Frame[],
  _ctxFieldId: string,
  outFieldId: string,
  ctxPartial: boolean,
  outPartial: boolean,
  tiers: ReadonlyMap<number, string> | null = null,
): C3Result {
  if (ctxPartial || outPartial) return [NOT_EVALUATED, "extraction_partial", null];

  const trustedFrames = trusted(ctxFrames, tiers);
  let obs: Obligation[];
  let ev: Evidence[];
  try {
    obs = extraction.extractObligations(trustedFrames);
    ev = extraction.extractEvidence(outFrames, outFieldId);
  } catch (e) {
    if (e instanceof extraction.FramePartial) {
      // spec 3.5: a FACETPROJ miss while building an obligation's or a
      // requirement-evidence item's governed identity -> PARTIAL
      return [NOT_EVALUATED, "extraction_partial", null];
    }
    throw e;
  }
  const conflicted = extraction.sourceConflictPrepass(obs, trustedFrames);

  const verdicts: Array<readonly [string, string | null]> = [];

  obs.forEach((ob, obIdx) => {
    for (const fa of outFrames.filter((f) => f.assertive)) {
      const [g, gc] = relations.twoWayGeneralizes(ob.governedIdentity, fa.extent, false);
      if (g === "NO") continue;
      if (g === "UNKNOWN") {
        verdicts.push(["UNK", gc]);
        continue;
      }
      if (ob.kind === IMPLICIT && fa.extent.polarity !== ob.sourcePolarity) continue;
      if (ob.kind === EXPLICIT && (fa.extent.polarity !== POS || !T.facetsV1[fa.extent.facet]?.benefit)) continue;

      const d = engine.DOMAIN(null, D(fa), ob.sourceActivationDomain);
      if (d === "DISJOINT") continue;
      if (d === "UNKNOWN") {
        verdicts.push(["UNK", CONDITION_UNDECIDABLE]);
        continue;
      }
      if (conflicted.has(obIdx)) {
        verdicts.push(["OB_CONFLICTED", null]);
        continue;
      }
      if (ob.trivial) {
        verdicts.push(["SATISFIED", null]);
        continue;
      }

      const ee = relations.meet(ob.governedIdentity, fa.extent);
      const E = mkAnd([D(fa), ob.applicabilityScope]);
      if (engine.uncompilable(E)) {
        verdicts.push(["UNK", engine.causeOf(E)]);
        continue;
      }
      let eCompiled: engine.Compiled;
      try {
        eCompiled = engine.buildVarmap([E]);
      } catch (e2) {
        if (e2 instanceof engine.EnvelopeExceeded) {
          verdicts.push(["UNK", CONDITION_UNDECIDABLE]);
          continue;
        }
        throw e2;
      }
      if (engine.UNSAT(eCompiled, E)) continue; // E compilable: SAT is boolean

      const causes: string[] = []; // (e4) explicit accumulation
      const bound: Evidence[] = [];
      for (const e of ev.filter((e2) => e2.fieldId === fa.fieldId)) {
        const [gb, gbc] = relations.generalizes(e.governedIdentity, ee, e.frameId === fa.frameId);
        if (gb === "UNKNOWN") {
          causes.push(gbc!);
        } else if (gb === "YES" && (effQuant(e.governedIdentity.quant) !== EXISTENTIAL || e.frameId === fa.frameId)) {
          bound.push(e);
        }
      }
      for (const e of bound) {
        if (engine.uncompilable(eff(e))) causes.push(engine.causeOf(eff(e))!);
        if (engine.uncompilable(e.domain)) causes.push(engine.causeOf(e.domain)!);
      }
      if (causes.length > 0) {
        verdicts.push(["UNK", worstCause(causes)]);
        continue;
      }

      const S = support(ob.requirementFormula, bound);
      const supportCompiled = engine.buildVarmap([E, S.definiteRoot, S.possibleRoot]);
      const ent = engine.ENTAILS(supportCompiled, E, S.definiteRoot);
      if (ent === "YES") {
        verdicts.push(["SATISFIED", null]); // E and both support roots are
      } else {
        // compilable here, so ENTAILS and SAT return definite values --
        // no UNKNOWN arm is read as boolean
        const viol = engine.SAT(supportCompiled, mkAnd([E, mkNot(S.possibleRoot)]));
        if (viol) verdicts.push(["VIOLATION_V", null]);
        else verdicts.push(["UNK", CONDITION_UNDECIDABLE]);
      }
    }
  });

  const kinds = verdicts.map((v) => v[0]);
  if (kinds.includes("VIOLATION_V")) return [VIOLATION, "detection_complete", WARNING];
  if (kinds.includes("OB_CONFLICTED")) return [NOT_EVALUATED, "basis_conflict", null];
  const unkCauses = verdicts.filter((v) => v[0] === "UNK").map((v) => v[1]);
  if (unkCauses.includes(MALFORMED_MENTION)) return [NOT_EVALUATED, "unsupported_claim_form", null];
  if (unkCauses.length > 0) return [NOT_EVALUATED, "condition_undecidable", null];
  return [PASS, "detection_complete", null];
}

// --------------------------------------------------------------------------
// C4
// --------------------------------------------------------------------------

export type C4Result = readonly [string, string, string | null];

/** modifier-set relation per generalizes step 4, both ways: EXCL pair ->
 * EXCL; UNKNOWN -> UNKNOWN; else -> OK. */
function modifierRelation(aExtent: Extent, bExtent: Extent): "EXCL" | "UNKNOWN" | "OK" {
  const [g1] = relations.generalizes(aExtent, bExtent, false);
  const [g2] = relations.generalizes(bExtent, aExtent, false);
  const pairs: Array<[ModSet, ModSet]> = [
    [aExtent.modifiers, bExtent.modifiers],
    [bExtent.modifiers, aExtent.modifiers],
  ];
  for (const [xMods, yMods] of pairs) {
    for (const { rel: rRel, objset } of xMods) {
      for (const { rel: r2, objset: ov } of yMods) {
        if (r2 !== rRel) continue;
        for (const xTerm of objset.toArray()) {
          for (const yTerm of ov.toArray()) {
            if (EXCL_V1.has(unorderedPairKey(xTerm, yTerm))) return "EXCL";
          }
        }
      }
    }
  }
  if (g1 === "UNKNOWN" || g2 === "UNKNOWN") return "UNKNOWN";
  return "OK";
}

export function C4(
  ctxFrames: readonly Frame[],
  outFrames: readonly Frame[],
  ctxPartial: boolean,
  outPartial: boolean,
  tiers: ReadonlyMap<number, string> | null = null,
): C4Result {
  if (ctxPartial || outPartial) return [NOT_EVALUATED, "extraction_partial", null];

  const trustedFrames = trusted(ctxFrames, tiers);
  const conflictPairs: Array<[Frame, Frame]> = [];
  const undec: string[] = [];

  for (let i = 0; i < trustedFrames.length; i++) {
    for (let j = i + 1; j < trustedFrames.length; j++) {
      const a = trustedFrames[i]!;
      const b = trustedFrames[j]!;
      if (a.extent.facet !== b.extent.facet) continue;
      if (a.extent.polarity === b.extent.polarity) continue;
      if (effQuant(a.extent.quant) === EXISTENTIAL && effQuant(b.extent.quant) === EXISTENTIAL) continue;
      if (!a.extent.subject.intersects(b.extent.subject)) continue;
      if (!(a.extent.object.isSubsetOf(b.extent.object) || b.extent.object.isSubsetOf(a.extent.object))) continue;

      const modrel = modifierRelation(a.extent, b.extent);
      if (modrel === "EXCL") continue;
      if (modrel === "UNKNOWN") {
        undec.push(CONDITION_UNDECIDABLE);
        continue;
      }

      const d = engine.DOMAIN(null, D(a), D(b));
      if (d === "OVERLAP") conflictPairs.push([a, b]);
      else if (d === "UNKNOWN") undec.push(CONDITION_UNDECIDABLE);
    }
  }

  const unpreserved: Array<[Frame, Frame]> = [];
  for (const [a, b] of conflictPairs) {
    const restrictive = a.extent.polarity === 1 ? a : b;
    for (const fo of outFrames.filter((f) => f.assertive && f.extent.facet === a.extent.facet)) {
      const r1 = relations.identityRelation(fo.extent, D(fo), a.extent, D(a), false);
      const r2 = relations.identityRelation(fo.extent, D(fo), b.extent, D(b), false);
      const rr = relations.identityRelation(fo.extent, D(fo), restrictive.extent, D(restrictive), false);
      if (relations.relIsUndecidable(r1) || relations.relIsUndecidable(r2) || relations.relIsUndecidable(rr)) {
        const causes = [r1, r2, rr].filter(relations.relIsUndecidable).map((x) => x.cause);
        undec.push(worstCause(causes));
        continue;
      }

      const engages = fo.extent.polarity === POS && rr === "COMPARABLE";
      const inScope =
        (r1 === "COMPARABLE" && r2 === "COMPARABLE") ||
        fo.extent.subject.isSubsetOf(a.extent.subject.intersection(b.extent.subject)) ||
        engages;
      if (!inScope) continue;

      let preserved = false;
      let presUnknown = false;
      for (const fr of outFrames.filter((f) => f.assertive)) {
        const rx = relations.identityRelation(fr.extent, D(fr), restrictive.extent, D(restrictive), false);
        if (relations.relIsUndecidable(rx)) {
          presUnknown = true;
          continue;
        }
        if (rx === "COMPARABLE" && fr.extent.polarity === restrictive.extent.polarity) {
          const im = engine.IMPLIES(null, D(restrictive), D(fr));
          if (im === "YES") {
            preserved = true;
            break;
          }
          if (im === "UNKNOWN") presUnknown = true;
        }
      }
      if (preserved) continue;
      if (presUnknown) undec.push(CONDITION_UNDECIDABLE);
      else unpreserved.push([restrictive, fo]);
    }
  }

  if (unpreserved.length > 0) return [VIOLATION, "detection_complete", WARNING];
  if (undec.includes(MALFORMED_MENTION)) return [NOT_EVALUATED, "unsupported_claim_form", null];
  if (undec.length > 0) return [NOT_EVALUATED, "condition_undecidable", null];
  return [PASS, "detection_complete", null];
}
