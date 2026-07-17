/**
 * Section 4.3 of ALGORITHM v4 draft 5.4: identity_relation and friends.
 * Depends on primitives.ts (types) and engine.ts (DOMAIN, SAT,
 * decompose/build_gamma for measure-facet disposition), NOT on
 * extraction.ts (no cycle). Mirrors reference/relations.py one-for-one.
 */

import { T, unorderedPairKey } from "./tables.js";
import { FSet } from "./fset.js";
import {
  Bool,
  CONDITION_UNDECIDABLE,
  EXCL_V1,
  EXISTENTIAL,
  Extent,
  MALFORMED_MENTION,
  MeasureAtom,
  MeasureQty,
  UNIVERSAL,
  effQuant,
  mkAnd,
  mkMeasureAtom,
  worstCause,
} from "./primitives.js";
import * as engine from "./engine.js";

export const YES = "YES";
export const NO = "NO";
export const UNKNOWN = "UNKNOWN";
export const COMPARABLE = "COMPARABLE";
export const INERT = "INERT";
export const UNDECIDABLE_TAG = "UNDECIDABLE";
export const MATCH = "MATCH";
export const CONFLICT = "CONFLICT";

export interface UndecidableTag {
  readonly tag: "UNDECIDABLE";
  readonly cause: string;
}

/** Rel3 (TOTAL): COMPARABLE | INERT | UNDECIDABLE(cause). Never read as
 * boolean -- every consumer branches on all three arms via relIsUndecidable
 * / plain string equality against COMPARABLE / INERT. */
export type Rel3 = "COMPARABLE" | "INERT" | UndecidableTag;

export type DispositionResult = "MATCH" | "CONFLICT" | UndecidableTag;

export function relIsUndecidable(r: Rel3 | DispositionResult): r is UndecidableTag {
  return typeof r === "object" && r.tag === "UNDECIDABLE";
}

export function relCause(r: Rel3 | DispositionResult): string | null {
  return relIsUndecidable(r) ? r.cause : null;
}

export type GenResult = readonly ["YES" | "NO" | "UNKNOWN", string | null];

/** generalizes step 6: "A carries any malformed value/modifier product".
 * Structurally unreachable in this pipeline BY CONSTRUCTION, not by
 * fixture coverage: spec section 0's symmetric rule makes every malformed
 * value/modifier product abstain() DURING extraction (2.4, 2.5, 3.2 step
 * 7, 3.2 adjunct rules), which raises before the Extent is constructed and
 * drives the FIELD to PARTIAL -- so no Extent carrying a malformed product
 * ever reaches identity comparison. Kept as an explicit named check
 * (returning the invariant's value) so the numbered spec steps remain
 * visibly total. */
function hasMalformed(_extent: Extent): boolean {
  return false;
}

export function generalizes(A: Extent, B: Extent, sameFrame: boolean): GenResult {
  if (A.facet !== B.facet) return ["NO", null];
  if (!A.subject.isSubsetOf(B.subject)) return ["NO", null];
  if (!A.object.isSubsetOf(B.object)) return ["NO", null];

  // step 4: modifiers (spec order: EXCL pair -> NO; no same-rel match in
  // B -> NO; same-rel match(es) exist but none contains a.objset ->
  // UNKNOWN(condition_undecidable). NO is definitive and takes precedence
  // over UNKNOWN when both occur across different modifiers of A.)
  let anyUnknown = false;
  for (const { rel, objset } of A.modifiers) {
    const sameRelInB: FSet[] = [];
    for (const mb of B.modifiers) {
      if (mb.rel === rel) sameRelInB.push(mb.objset);
    }
    if (sameRelInB.length === 0) return ["NO", null];
    for (const ov of sameRelInB) {
      for (const aTerm of objset.toArray()) {
        for (const bTerm of ov.toArray()) {
          if (EXCL_V1.has(unorderedPairKey(aTerm, bTerm))) {
            return ["NO", null];
          }
        }
      }
    }
    if (!sameRelInB.some((ov) => objset.isSubsetOf(ov))) {
      anyUnknown = true;
    }
  }
  if (anyUnknown) return ["UNKNOWN", CONDITION_UNDECIDABLE];

  // step 5
  if (effQuant(A.quant) === EXISTENTIAL && !sameFrame) {
    return ["UNKNOWN", CONDITION_UNDECIDABLE];
  }

  // step 6
  if (hasMalformed(A)) return ["UNKNOWN", MALFORMED_MENTION];

  return ["YES", null];
}

/** Returns one of COMPARABLE | INERT | UNDECIDABLE(cause). */
export function identityRelation(A: Extent, DA: Bool, B: Extent, DB: Bool, sameFrame: boolean): Rel3 {
  const [g1, c1] = generalizes(A, B, sameFrame);
  const [g2, c2] = generalizes(B, A, sameFrame);
  if (g1 !== "YES" && g2 !== "YES") {
    if (g1 === "UNKNOWN" || g2 === "UNKNOWN") {
      return { tag: "UNDECIDABLE", cause: worstCause([c1, c2]) };
    }
    return "INERT";
  }
  const d = engine.DOMAIN(null, DA, DB);
  if (d === "OVERLAP") return "COMPARABLE";
  if (d === "DISJOINT") return "INERT";
  // d == UNKNOWN
  const causeVal = domainHasMalformed(DA, DB) ? MALFORMED_MENTION : CONDITION_UNDECIDABLE;
  return { tag: "UNDECIDABLE", cause: causeVal };
}

function domainHasMalformed(DA: Bool, DB: Bool): boolean {
  const c1 = engine.causeOf(DA);
  const c2 = engine.causeOf(DB);
  return c1 === MALFORMED_MENTION || c2 === MALFORMED_MENTION;
}

export function twoWayGeneralizes(A: Extent, B: Extent, sameFrame: boolean): GenResult {
  const [g1, c1] = generalizes(A, B, sameFrame);
  if (g1 === "YES") return ["YES", null];
  const [g2, c2] = generalizes(B, A, sameFrame);
  if (g2 === "YES") return ["YES", null];
  if (g1 === "NO" && g2 === "NO") return ["NO", null];
  return ["UNKNOWN", worstCause([c1, c2])];
}

export function meet(A: Extent, B: Extent): Extent {
  const modifiers = A.modifiers.size >= B.modifiers.size ? A.modifiers : B.modifiers;
  const q = effQuant(A.quant) === EXISTENTIAL || effQuant(B.quant) === EXISTENTIAL ? EXISTENTIAL : UNIVERSAL;
  return {
    facet: A.facet,
    subject: A.subject.union(B.subject),
    object: A.object.union(B.object),
    modifiers,
    quant: q,
    polarity: A.polarity,
    values: null,
  };
}

export interface HasExtent {
  readonly extent: Extent;
}

export function measureAtomOf(extent: Extent): MeasureAtom {
  const unit = extent.values && extent.values.length > 0 ? extent.values[0]!.unit : "";
  const qty: MeasureQty = [extent.facet, extent.subject, unit];
  return mkMeasureAtom(qty, extent.values ?? []);
}

/** MATCH|CONFLICT|UNDECIDABLE(cause). */
export function disposition(a: HasExtent, b: HasExtent): DispositionResult {
  const facetA = T.facetsV1[a.extent.facet];
  const isMeasureFacet = Boolean(facetA?.measure);
  if (isMeasureFacet) {
    if (a.extent.values === null || b.extent.values === null) {
      return { tag: "UNDECIDABLE", cause: CONDITION_UNDECIDABLE };
    }
    // spec 2.4: comparisons are legal only within one unit group and one
    // currency -- cross-group/cross-currency -> UnknownAtom with cause
    // malformed_mention, so the disposition is UNDECIDABLE, never a
    // silent MATCH of two independent quantities.
    const unitA = a.extent.values[0]!.unit;
    const unitB = b.extent.values[0]!.unit;
    if (unitA !== unitB) {
      return { tag: "UNDECIDABLE", cause: MALFORMED_MENTION };
    }
    let compiled: engine.Compiled;
    try {
      compiled = engine.buildVarmap([measureAtomOf(a.extent), measureAtomOf(b.extent)]);
    } catch (e) {
      if (e instanceof engine.EnvelopeExceeded) {
        return { tag: "UNDECIDABLE", cause: CONDITION_UNDECIDABLE };
      }
      throw e;
    }
    const conflict = !engine.SAT(compiled, mkAnd([measureAtomOf(a.extent), measureAtomOf(b.extent)]));
    return conflict ? "CONFLICT" : "MATCH";
  }

  if (
    a.extent.polarity !== b.extent.polarity &&
    !(effQuant(a.extent.quant) === EXISTENTIAL && effQuant(b.extent.quant) === EXISTENTIAL)
  ) {
    return "CONFLICT";
  }
  return "MATCH";
}
