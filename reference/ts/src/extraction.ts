/**
 * Section 3 of ALGORITHM v4 draft 5.4: extraction (triggers, negation,
 * polarity, roles, conditions, frames, obligations, evidence), including
 * total span accounting (spec 2.6). Mirrors reference/extraction.py
 * one-for-one.
 *
 * Depends on primitives.ts (types + text primitives), tables.ts (raw table
 * access for facet metadata) and engine.ts (the "engine-TOP-equivalent
 * formula -> trivial" check, the UNSAT arm of the source-conflict prepass,
 * and the MAX_EXPR_NODES envelope path in parse_bool). source_conflict_prepass
 * additionally uses relations.ts (relations depends only on
 * engine.ts/primitives.ts, so no cycle -- imported at module top level here,
 * unlike Python's local import, since TS has no equivalent import-cycle
 * concern for this particular dependency direction).
 */

import { T } from "./tables.js";
import { FSet, ModSet } from "./fset.js";
import { toCodePoints } from "./unicode.js";
import * as engine from "./engine.js";
import * as relations from "./relations.js";
import {
  ADJUNCT_PREPOSITIONS_V1,
  APPROX_V1,
  Abstain,
  Bool,
  BOTTOM_,
  COMPARATORS_V1,
  CONCEPT_V1,
  CONDITION_OPERATORS_V1,
  CondNode,
  CompiledComparator,
  CompiledConditionOperator,
  Dec,
  Evidence,
  Extent,
  EXISTENTIAL,
  EXPLICIT,
  FACETPROJ_V1,
  Frame,
  GENERIC_BENEFIT_TRIGGERS_V1,
  GRANT,
  Hit,
  IMPLICIT,
  Interval,
  MALFORMED_MENTION,
  MeasureQty,
  MODAL_ABSTAIN_V1,
  NEG,
  NEGATION_EXCEPTIONS,
  NEGATORS_V1,
  Obligation,
  PARTICIPLE_TRIGGERS_V1,
  POS,
  QUANT_ABSTAIN,
  QUANT_EXISTENTIAL,
  QUANT_UNIVERSAL,
  RELATIVE_MARKERS_V1,
  RESTRICTION,
  Roles,
  STOP_V1,
  Span,
  TOP_,
  TRIGGER_INDEX,
  MAX_TRIGGER_LEN,
  Token,
  UNEXTRACTABLE,
  UNIVERSAL,
  UNSPECIFIED,
  isContentToken,
  isInterrogative,
  joinFold,
  listMarkerIndices,
  mkAnd,
  mkMeasureAtom,
  mkNot,
  mkOr,
  mkTermAtom,
  mkUnknownAtom,
  parseValues,
  sentences,
  tokenize,
  unitOf,
} from "./primitives.js";

export const FIELD_PARTIAL = "PARTIAL";

/** Internal signal: the frame currently being built abstained; caller
 * (extractFrames) converts this into FIELD_PARTIAL per spec 3.4: "any
 * abstention -> return PARTIAL". */
export class FramePartial extends Error {
  readonly cause: string;
  constructor(cause: string) {
    super(cause);
    this.name = "FramePartial";
    this.cause = cause;
  }
}

// --------------------------------------------------------------------------
// 3.1 Triggers, negation, polarity, benefit normalization
// --------------------------------------------------------------------------

/** One pass over the union of all facets' triggers + deny_triggers as
 * folded token sequences, longest-match-first, non-overlapping. A
 * MODAL_ABSTAIN token in trigger position -> abstain('unextractable'). */
export function triggerScan(tokens: readonly Token[]): Hit[] {
  const hits: Hit[] = [];
  let i = 0;
  const n = tokens.length;
  while (i < n) {
    if (MODAL_ABSTAIN_V1.has(tokens[i]!.fold)) {
      throw new Abstain(UNEXTRACTABLE);
    }
    let matched = false;
    for (let length = Math.min(MAX_TRIGGER_LEN, n - i); length > 0; length--) {
      const keySeq = tokens.slice(i, i + length).map((t) => t.fold);
      const key = joinFold(keySeq);
      const candidates = TRIGGER_INDEX.get(key);
      if (candidates && candidates.length > 0) {
        // Equal-span precedence (spec 3.1): OBLIGATION PASSIVE > generic
        // passive > active, applied when the SAME span matches triggers
        // of more than one facet.
        const precedence = (candidate: readonly [string, boolean]): number => {
          const facetName = candidate[0];
          if (facetName === "facet:approval_requirement") return 0;
          if (PARTICIPLE_TRIGGERS_V1.has(keySeq[0]!)) return 1;
          return 2;
        };
        const sortedCandidates = candidates.slice().sort((a, b) => precedence(a) - precedence(b));
        const [facetName, isDeny] = sortedCandidates[0]!;
        hits.push({ facet: facetName, span: [i, i + length], isDeny, triggerKey: keySeq });
        i += length;
        matched = true;
        break;
      }
    }
    if (!matched) i += 1;
  }
  return hits;
}

function sameSegment(segBounds: readonly Span[], a: number, b: number): boolean {
  for (const [lo, hi] of segBounds) {
    if (lo <= a && a < hi && lo <= b && b < hi) return true;
  }
  return false;
}

/** Token-index bounds of each structural-punctuation-delimited segment
 * within a single sentence's token list. Exported: checks.ts's C2 needs
 * this too (mirrors Python's cross-module import of `_segment_bounds`). */
export function segmentBounds(tokens: readonly Token[]): Span[] {
  const bounds: Span[] = [];
  let start = 0;
  for (let idx = 0; idx < tokens.length; idx++) {
    const tok = tokens[idx]!;
    if (tok.kind === "PUNCT" && T.structuralPunctuation.has(tok.raw)) {
      bounds.push([start, idx]);
      start = idx + 1;
    }
  }
  bounds.push([start, tokens.length]);
  return bounds;
}

/** PRE rule: a negator within NEG_WINDOW tokens before span, same segment,
 * not forming a negation_exceptions pair with its successor. POST-MODAL
 * rule: a negator immediately after span's last token, same segment.
 * Either rule negates. Exported for checks.ts's C2. */
export function NEG_v1(tokens: readonly Token[], span: Span, segBounds: readonly Span[]): boolean {
  const [start, end] = span;
  const windowLo = Math.max(0, start - T.NEG_WINDOW);
  for (let i = windowLo; i < start; i++) {
    const tok = tokens[i]!;
    if (NEGATORS_V1.has(tok.fold) && sameSegment(segBounds, i, start)) {
      const nxt = i + 1 < tokens.length ? tokens[i + 1]!.fold : null;
      if (nxt !== null && NEGATION_EXCEPTIONS.has(joinFold([tok.fold, nxt]))) continue;
      return true;
    }
  }
  if (end < tokens.length) {
    const tok = tokens[end]!;
    if (NEGATORS_V1.has(tok.fold) && sameSegment(segBounds, end, start)) {
      return true;
    }
  }
  return false;
}

/** Index of the specific negator token consumed by NEG_v1 for this hit
 * (dual-role: also excluded from the hit's own subject/object noun-group
 * extraction). */
function consumedNegatorIndex(tokens: readonly Token[], span: Span, segBounds: readonly Span[]): number | null {
  const [start, end] = span;
  const windowLo = Math.max(0, start - T.NEG_WINDOW);
  for (let i = windowLo; i < start; i++) {
    const tok = tokens[i]!;
    if (NEGATORS_V1.has(tok.fold) && sameSegment(segBounds, i, start)) {
      const nxt = i + 1 < tokens.length ? tokens[i + 1]!.fold : null;
      if (nxt !== null && NEGATION_EXCEPTIONS.has(joinFold([tok.fold, nxt]))) continue;
      return i;
    }
  }
  if (end < tokens.length) {
    const tok = tokens[end]!;
    if (NEGATORS_V1.has(tok.fold) && sameSegment(segBounds, end, start)) {
      return end;
    }
  }
  return null;
}

/** polarity(hit) = NEG_v1(hit) XOR hit.is_deny */
export function polarity(isNeg: boolean, isDeny: boolean): 0 | 1 {
  return isNeg !== isDeny ? NEG : POS;
}

export function normalizeBenefitFacet(hit: Hit, subjectHead: string | null): string {
  if (
    hit.triggerKey.length === 1 &&
    GENERIC_BENEFIT_TRIGGERS_V1.has(hit.triggerKey[0]!) &&
    subjectHead !== null &&
    FACETPROJ_V1.has(subjectHead)
  ) {
    return FACETPROJ_V1.get(subjectHead)!;
  }
  return hit.facet;
}

// --------------------------------------------------------------------------
// 3.2 Roles
// --------------------------------------------------------------------------

const COPULAS = new Set(["is", "are", "was", "were", "been", "being"]);

/** Split at role-level 'and' into conjuncts; per conjunct return its
 * content-term set and its COMPOUND_HEAD-rule head (the RIGHTMOST content
 * token of the conjunct's group). 'or' | '/' | '|' between noun groups ->
 * abstain. `exclude` is the set of token indices already consumed by
 * another frame product. Conjuncts with no content tokens are dropped; the
 * two returned arrays stay parallel. */
function conjunctTermsAndHeads(
  tokens: readonly Token[],
  span: Span,
  exclude: ReadonlySet<number> = new Set(),
): [FSet[], (string | null)[]] {
  const [start, end] = span;
  const conjuncts: Token[][] = [[]];
  let i = start;
  while (i < end) {
    if (exclude.has(i)) {
      i += 1;
      continue;
    }
    const tok = tokens[i]!;
    if (tok.fold === "or" || tok.raw === "/" || tok.raw === "|") {
      throw new Abstain(UNEXTRACTABLE);
    }
    if (tok.fold === "and") {
      conjuncts.push([]);
      i += 1;
      continue;
    }
    conjuncts[conjuncts.length - 1]!.push(tok);
    i += 1;
  }
  const groups: FSet[] = [];
  const heads: (string | null)[] = [];
  for (const conj of conjuncts) {
    const contentToks = conj.filter(isContentToken);
    if (contentToks.length === 0) continue;
    let headFold: string | null = null;
    for (let k = conj.length - 1; k >= 0; k--) {
      if (isContentToken(conj[k]!)) {
        headFold = conj[k]!.fold;
        break;
      }
    }
    groups.push(FSet.of(contentToks.map((t) => t.fold)));
    heads.push(headFold);
  }
  return [groups, heads];
}

/** Per-conjunct content-term sets (see conjunctTermsAndHeads). */
export function nounGroups(tokens: readonly Token[], span: Span, exclude: ReadonlySet<number> = new Set()): FSet[] {
  return conjunctTermsAndHeads(tokens, span, exclude)[0];
}

/** Each adjunct preposition + following noun group ->
 * (prep, frozenset(content folds)); a facet trigger, NUMBER, REL_MARKER +
 * content, or nested adjunct inside -> abstain. Returns
 * [modifiers, consumed_token_indices]. */
function adjunctModifiers(tokens: readonly Token[], span: Span): [ModSet, number[]] {
  const [start, end] = span;
  const mods: { rel: string; objset: FSet }[] = [];
  const consumed: number[] = [];
  let i = start;
  while (i < end) {
    const tok = tokens[i]!;
    if (ADJUNCT_PREPOSITIONS_V1.has(tok.fold)) {
      const prep = tok.fold;
      let j = i + 1;
      const groupTokens: Token[] = [];
      let sawContent = false;
      // spec 3.2 facet-trigger arm (SAN-894): the adjunct group's upper
      // bound is the first "and" or adjunct-preposition token at or
      // after the group start, capped at the enclosing span end.
      // Computed once per group since it is invariant across the walk
      // below (the while loop's own break condition below is the same
      // test, so j never advances past it).
      let groupEnd = end;
      for (let k = j; k < end; k++) {
        if (tokens[k]!.fold === "and" || ADJUNCT_PREPOSITIONS_V1.has(tokens[k]!.fold)) {
          groupEnd = k;
          break;
        }
      }
      while (j < end) {
        const t2 = tokens[j]!;
        if (t2.fold === "and" || ADJUNCT_PREPOSITIONS_V1.has(t2.fold)) break;
        if (RELATIVE_MARKERS_V1.has(t2.fold)) throw new Abstain(UNEXTRACTABLE);
        if (t2.kind === "NUMBER" || t2.kind === "PCT100") throw new Abstain(UNEXTRACTABLE);
        // Longest-match folded-sequence scan for a facet trigger (spec
        // 3.2: "a facet trigger ... inside -> abstain"). A bare
        // single-fold membership check (`TRIGGER_INDEX.has(t2.fold)`) is
        // insufficient because TRIGGER_INDEX keys are joined fold
        // sequences, not bare folds -- a future multi-token trigger
        // table must not silently under-abstain. Descending window
        // lengths, capped at groupEnd, so a boundary-crossing window is
        // never tested and a valid shorter trigger prefix is never
        // skipped. (The nested-adjunct arm of this same spec clause
        // remains a separate, tracked divergence: SAN-897.)
        for (let length = Math.min(MAX_TRIGGER_LEN, groupEnd - j); length > 0; length--) {
          const key = joinFold(tokens.slice(j, j + length).map((t) => t.fold));
          if (TRIGGER_INDEX.has(key)) throw new Abstain(UNEXTRACTABLE);
        }
        groupTokens.push(t2);
        if (isContentToken(t2)) sawContent = true;
        j += 1;
      }
      if (!sawContent) {
        i += 1;
        continue;
      }
      const objset = FSet.of(groupTokens.filter(isContentToken).map((t) => t.fold));
      mods.push({ rel: prep, objset });
      for (let x = i; x < j; x++) consumed.push(x);
      i = j;
      continue;
    }
    i += 1;
  }
  return [ModSet.of(mods), consumed];
}

/** T.quant_v1 class of the head-position token: universal->1;
 * existential->2; abstain-class -> frame PARTIAL; absent -> 0. */
export function quant(subjectTokens: readonly Token[]): 0 | 1 | 2 {
  for (const tok of subjectTokens) {
    if (QUANT_UNIVERSAL.has(tok.fold)) return UNIVERSAL;
    if (QUANT_EXISTENTIAL.has(tok.fold)) return EXISTENTIAL;
    if (QUANT_ABSTAIN.has(tok.fold)) throw new FramePartial(UNEXTRACTABLE);
  }
  return UNSPECIFIED;
}

function findOperatorAfter(tokens: readonly Token[], fromIdx: number, toIdx: number, word: string): number | null {
  for (let i = fromIdx; i < toIdx; i++) {
    if (tokens[i]!.fold === word) return i;
  }
  return null;
}

/** Numbered steps 1-8; any failure -> abstain('unextractable'). */
export function extractRoles(hit: Hit, tokens: readonly Token[], segBounds: readonly Span[]): Roles {
  const [start, end] = hit.span;
  let seg: Span = [0, tokens.length];
  for (const [lo, hi] of segBounds) {
    if (lo <= start && start < hi) {
      seg = [lo, hi];
      break;
    }
  }
  const [segLo, segHi] = seg;

  const facetDef = T.facetsV1[hit.facet] ?? null;
  const valency: readonly string[] = facetDef ? facetDef.valency : [];

  // -- rule 1: OBLIGATION-PASSIVE: "[Y] copula required for [X]" --
  if (hit.facet === "facet:approval_requirement" && hit.triggerKey.length === 1 && hit.triggerKey[0] === "required") {
    const prevTok = start - 1 >= segLo ? tokens[start - 1]! : null;
    if (prevTok !== null && COPULAS.has(prevTok.fold)) {
      const forIdx = findOperatorAfter(tokens, end, segHi, "for");
      if (forIdx !== null) {
        const ySpan: Span = [segLo, start - 1];
        const xSpan: Span = [forIdx + 1, segHi];
        return { subject: xSpan, object: ySpan, value: null, pattern: "OP" };
      }
    }
  }

  // -- rule 2: PASSIVE: "[X] copula <participle> by [Y]" --
  // e7 (spec 3.2 rule 2): applies ONLY when the trigger's fold is in
  // T.participle_triggers_v1.
  const prevTok2 = start - 1 >= segLo ? tokens[start - 1]! : null;
  if (prevTok2 !== null && COPULAS.has(prevTok2.fold) && PARTICIPLE_TRIGGERS_V1.has(hit.triggerKey[0]!)) {
    const byIdx = findOperatorAfter(tokens, end, segHi, "by");
    if (byIdx === null) throw new Abstain(UNEXTRACTABLE);
    const xSpan: Span = [segLo, start - 1];
    const ySpan: Span = [byIdx + 1, segHi];
    return { subject: ySpan, object: xSpan, value: null, pattern: "PASSIVE" };
  }

  // -- rule 3: COORDINATION --
  if (start - 1 >= segLo && tokens[start - 1]!.fold === "and") {
    return { subject: [start, start], object: [end, segHi], value: null, pattern: "COORD" };
  }

  // -- rule 4: ACTIVE (default) --
  const subjSpan: Span = [segLo, start];
  let objSpan: Span = [end, segHi];
  const condStart = firstConditionMarkerIndex(tokens, end, segHi);
  if (condStart !== null && condStart < objSpan[1]) {
    objSpan = [objSpan[0], condStart];
  }
  let roles: Roles = { subject: subjSpan, object: objSpan, value: null, pattern: "ACTIVE" };

  // -- rule 7: VALUE role (measure facets only) --
  if (facetDef && facetDef.measure) {
    const sentHi = tokens.length;
    let valueRegionHi = sentHi;
    const cs = firstConditionMarkerIndex(tokens, end, sentHi);
    if (cs !== null) valueRegionHi = cs;
    const valueSpan = findUniqueValueSpan(tokens, end, valueRegionHi, hit.span);
    roles = { subject: roles.subject, object: roles.object, value: valueSpan, pattern: roles.pattern };
  }

  // -- rule 8: enforce valency --
  for (const roleName of valency) {
    if (roleName === "subject") {
      const [lo, hi] = roles.subject;
      if (!tokens.slice(lo, hi).some(isContentToken)) throw new Abstain(UNEXTRACTABLE);
    } else if (roleName === "object") {
      if (roles.object === null || !tokens.slice(roles.object[0], roles.object[1]).some(isContentToken)) {
        throw new Abstain(UNEXTRACTABLE);
      }
    } else if (roleName === "value") {
      if (roles.value === null) throw new Abstain(UNEXTRACTABLE);
    }
  }

  return roles;
}

function firstConditionMarkerIndex(tokens: readonly Token[], lo: number, hi: number): number | null {
  let best: number | null = null;
  for (let i = lo; i < hi; i++) {
    for (const op of CONDITION_OPERATORS_V1) {
      const ln = op.folds.length;
      if (i + ln > hi) continue;
      const window = joinFold(tokens.slice(i, i + ln).map((t) => t.fold));
      if (window === joinFold(op.folds)) {
        if (best === null || i < best) best = i;
      }
    }
  }
  return best;
}

/** Roles.value = the UNIQUE MAXIMAL span within [lo, hi) consisting of an
 * optional comparator sequence + one NUMBER/PCT100 token + an optional
 * adjacent unit WORD. ZERO or MORE THAN ONE candidate ->
 * abstain('malformed_mention'). Spec 2.4: an APPROX_v1 token immediately
 * before the number -> abstain. DUAL-ROLE TRIGGER (e8, spec 3.2 step 7). */
function findUniqueValueSpan(tokens: readonly Token[], lo: number, hi: number, triggerSpan: Span | null): Span | null {
  const numPositions: number[] = [];
  for (let i = lo; i < hi; i++) {
    const k = tokens[i]!.kind;
    if (k === "NUMBER" || k === "PCT100") numPositions.push(i);
  }
  if (numPositions.length === 0) return null;
  if (numPositions.length > 1) throw new Abstain(MALFORMED_MENTION);

  const idx = numPositions[0]!;
  if (idx > 0 && APPROX_V1.has(tokens[idx - 1]!.fold)) {
    throw new Abstain(MALFORMED_MENTION);
  }

  let bestCompLen = 0;
  for (const entry of COMPARATORS_V1) {
    const ln = entry.folds.length;
    if (idx - ln < lo) continue;
    const window = joinFold(tokens.slice(idx - ln, idx).map((t) => t.fold));
    if (window === joinFold(entry.folds) && ln > bestCompLen) bestCompLen = ln;
  }
  let spanLo = idx - bestCompLen;

  if (bestCompLen === 0 && triggerSpan !== null && triggerSpan[1] === idx) {
    const triggerFolds = joinFold(tokens.slice(triggerSpan[0], triggerSpan[1]).map((t) => t.fold));
    if (COMPARATORS_V1.some((entry: CompiledComparator) => joinFold(entry.folds) === triggerFolds)) {
      spanLo = triggerSpan[0];
    }
  }

  let spanHi = idx + 1;
  if (spanHi < hi && unitOf(tokens[spanHi]!) !== null) {
    spanHi += 1;
  }

  return [spanLo, spanHi];
}

// --------------------------------------------------------------------------
// 3.3 Conditions
// --------------------------------------------------------------------------

const CONDITION_OPERATORS_BY_LENGTH_DESC: readonly CompiledConditionOperator[] = CONDITION_OPERATORS_V1.slice().sort(
  (a, b) => b.folds.length - a.folds.length,
);

/** COND_OPS_v1, longest-match, left-to-right, non-overlapping, over
 * [lo, hi). One marker scope = ONE formula (spec 3.3). Returns
 * [op, bodyStart, bodyEnd, markerStart] tuples. */
export function conditionMarkerSpans(
  tokens: readonly Token[],
  lo: number,
  hi: number,
): Array<[CompiledConditionOperator, number, number, number]> {
  const markers: Array<[CompiledConditionOperator, number, number]> = [];
  let i = lo;
  while (i < hi) {
    let matched: [CompiledConditionOperator, number, number] | null = null;
    for (const op of CONDITION_OPERATORS_BY_LENGTH_DESC) {
      const ln = op.folds.length;
      if (i + ln > hi) continue;
      const window = joinFold(tokens.slice(i, i + ln).map((t) => t.fold));
      if (window === joinFold(op.folds)) {
        matched = [op, i, i + ln];
        break;
      }
    }
    if (matched !== null) {
      markers.push(matched);
      i = matched[2];
    } else {
      i += 1;
    }
  }
  const out: Array<[CompiledConditionOperator, number, number, number]> = [];
  for (let k = 0; k < markers.length; k++) {
    const marker = markers[k]!;
    const bodyEnd = k + 1 < markers.length ? markers[k + 1]![1] : hi;
    out.push([marker[0], marker[2], bodyEnd, marker[1]]);
  }
  return out;
}

/** top-level split at 'or' -> alternatives; each split at 'and' ->
 * conjuncts (OR of ANDs); a conjunct containing a further 'or' -> abstain. */
export function parseBool(tokens: readonly Token[], lo: number, hi: number, restrictive: boolean): Bool {
  const content = tokens.slice(lo, hi).filter((t) => t.kind !== "PUNCT");
  if (content.length === 0) throw new Abstain(MALFORMED_MENTION);

  const altSpans: Token[][] = [[]];
  for (const t of content) {
    if (t.fold === "or") altSpans.push([]);
    else altSpans[altSpans.length - 1]!.push(t);
  }
  if (altSpans.some((a) => a.length === 0)) throw new Abstain(MALFORMED_MENTION);

  const altAtoms: Bool[] = [];
  for (const alt of altSpans) {
    const conjSpans: Token[][] = [[]];
    for (const t of alt) {
      if (t.fold === "and") conjSpans.push([]);
      else conjSpans[conjSpans.length - 1]!.push(t);
    }
    if (conjSpans.some((c) => c.length === 0)) throw new Abstain(MALFORMED_MENTION);
    const conjAtoms = conjSpans.map((c) => atomFromConjunct(c, restrictive));
    altAtoms.push(conjAtoms.length === 1 ? conjAtoms[0]! : mkAnd(conjAtoms));
  }
  const formula: Bool = altAtoms.length === 1 ? altAtoms[0]! : mkOr(altAtoms);

  // spec 3.3: node/atom count > MAX_EXPR_NODES -> envelope path (sec 8)
  if (engine.boolNodes(formula) > T.MAX_EXPR_NODES) {
    throw new engine.EnvelopeExceeded(`envelope_exceeded: formula nodes > MAX_EXPR_NODES=${T.MAX_EXPR_NODES}`);
  }
  return formula;
}

function atomFromConjunct(conjTokens: readonly Token[], restrictive: boolean): Bool {
  let intervals: readonly Interval[] | null;
  try {
    intervals = parseValues(conjTokens);
  } catch (e) {
    if (e instanceof Abstain) return mkUnknownAtom(MALFORMED_MENTION);
    throw e;
  }
  if (intervals !== null) {
    const subjTerms = FSet.of(conjTokens.filter((t) => isContentToken(t) && t.kind === "WORD").map((t) => t.fold));
    const qty: MeasureQty = ["measure", subjTerms, intervals[0]!.unit];
    return mkMeasureAtom(qty, intervals);
  }
  const terms = conceptTerms(conjTokens);
  if (terms.isEmpty()) throw new Abstain(MALFORMED_MENTION);
  const neg = NEG_v1(conjTokens, [0, conjTokens.length], [[0, conjTokens.length]]);
  return mkTermAtom(terms, neg ? NEG : POS, restrictive ? RESTRICTION : GRANT);
}

/** CONCEPT_v1 applies ONLY inside Bool atoms -- never to extent terms. */
function conceptTerms(conjunctTokens: readonly Token[]): FSet {
  return FSet.of(conjunctTokens.filter(isContentToken).map((t) => CONCEPT_V1.get(t.fold) ?? t.fold));
}

/** Combine a single frame's own CondNodes into one formula: grants OR,
 * restrictions AND, mixed AND(OR(G), AND(R)); TOP if no conds. */
export function condsAsFormula(conds: readonly CondNode[]): Bool {
  if (conds.length === 0) return TOP_;
  const grants = conds.filter((c) => c.force === GRANT).map((c) => c.formula);
  const restrictions = conds.filter((c) => c.force === RESTRICTION).map((c) => c.formula);
  return combineGrantRestriction(grants, restrictions);
}

function combineGrantRestriction(grants: readonly Bool[], restrictions: readonly Bool[]): Bool {
  const g = orReduce(grants);
  const r = andReduce(restrictions);
  if (restrictions.length === 0) return g;
  if (grants.length === 0) return r;
  return mkAnd([g, r]);
}

function orReduce(items: readonly Bool[]): Bool {
  if (items.length === 0) return BOTTOM_;
  if (items.length === 1) return items[0]!;
  return mkOr(items);
}

function andReduce(items: readonly Bool[]): Bool {
  if (items.length === 0) return TOP_;
  if (items.length === 1) return items[0]!;
  return mkAnd(items);
}

export function parseConditions(tokens: readonly Token[], hit: Hit, segBounds: readonly Span[]): CondNode[] {
  let seg: Span = [0, tokens.length];
  for (const [lo, hi] of segBounds) {
    if (lo <= hit.span[0] && hit.span[0] < hi) {
      seg = [lo, hi];
      break;
    }
  }
  const segHi = seg[1];
  const out: CondNode[] = [];
  for (const [op, bodyStart, bodyEnd] of conditionMarkerSpans(tokens, hit.span[1], segHi)) {
    let f = parseBool(tokens, bodyStart, bodyEnd, op.force === RESTRICTION);
    if (op.polarity === "-") f = mkNot(f);
    out.push({ formula: f, force: op.force, kind: op.kind });
  }
  return out;
}

// --------------------------------------------------------------------------
// 3.4 Frames
// --------------------------------------------------------------------------

let frameCounter = 0;
function nextFrameId(): number {
  frameCounter += 1;
  return frameCounter;
}

function unionAll(sets: readonly FSet[]): FSet {
  let acc = FSet.EMPTY;
  for (const s of sets) acc = acc.union(s);
  return acc;
}

/** FILLER per spec 2.6: STOP_v1 words in grammar positions, structural
 * punctuation in structural positions, sentence-terminal '.'/'!'.
 * SEMANTIC-FORCE tokens are never filler, so an unconsumed occurrence
 * falls through to PARTIAL. */
function isFiller(tok: Token): boolean {
  if (tok.kind === "PUNCT") {
    return T.structuralPunctuation.has(tok.raw) || tok.raw === "." || tok.raw === "!";
  }
  if (tok.kind === "WORD") {
    return STOP_V1.has(tok.fold);
  }
  return false;
}

/** Returns [frames, partial]. PARTIAL when any abstention occurs anywhere
 * while extracting the field's frames, OR when total span accounting
 * (spec 2.6) finds an unconsumed non-filler span, OR when a governed-
 * output sentence is interrogative. */
export function extractFrames(fieldId: string, text: string, governed: boolean = false): [Frame[], boolean] {
  const tokens = tokenize(text);
  const frames: Frame[] = [];
  let partial = false;
  const cps = toCodePoints(text);

  for (const sent of sentences(tokens, text)) {
    const segBounds = segmentBounds(sent);
    const interrogative = isInterrogative(sent);
    if (interrogative && governed) {
      // spec 2.6: governed-output sentence-terminal '?' -> FIELD PARTIAL
      partial = true;
      continue;
    }

    // NONTERMINATING SENTENCE PUNCTUATION (e13, spec 2.6): detected
    // BEFORE role extraction so it can never be absorbed into a role
    // span.
    const markers = listMarkerIndices(sent, text);
    let e13Nonterminating = false;
    for (let i = 0; i < sent.length; i++) {
      const tok = sent[i]!;
      if (tok.kind === "PUNCT" && T.sentenceTerminators.has(tok.raw)) {
        const terminates = tok.end === cps.length || T.wsV1.has(cps[tok.end]!);
        if (!markers.has(i) && !terminates) {
          e13Nonterminating = true;
          break;
        }
      }
    }
    if (e13Nonterminating) {
      partial = true;
      continue;
    }

    let hits: Hit[];
    try {
      hits = triggerScan(sent);
    } catch (e) {
      if (e instanceof Abstain) {
        partial = true;
        continue;
      }
      throw e;
    }

    const assertive = !interrogative;
    const consumed = new Set<number>();
    let sentenceAbstained = false;
    let prevSubjectSpan: Span | null = null;

    for (const hit of hits) {
      try {
        let roles = extractRoles(hit, sent, segBounds);
        let coordinatorIdx: number | null = null;
        if (roles.pattern === "COORD") {
          if (prevSubjectSpan === null) throw new Abstain(UNEXTRACTABLE);
          coordinatorIdx = hit.span[0] - 1;
          roles = { subject: prevSubjectSpan, object: roles.object, value: roles.value, pattern: "COORD" };
        }
        prevSubjectSpan = roles.subject;

        const negIdx = consumedNegatorIndex(sent, hit.span, segBounds);
        const negExcl: readonly number[] = negIdx === null ? [] : [negIdx];

        const [modsSubj, consumedSubj] = adjunctModifiers(sent, roles.subject);
        const [modsObj, consumedObj] =
          roles.object !== null ? adjunctModifiers(sent, roles.object) : ([ModSet.EMPTY, []] as [ModSet, number[]]);
        const mods = modsSubj.union(modsObj);
        const consumedSubjSet = new Set<number>([...consumedSubj, ...negExcl]);
        const consumedObjSet = new Set<number>([...consumedObj, ...negExcl]);

        if (roles.value !== null && roles.object !== null) {
          for (let x = roles.value[0]; x < roles.value[1]; x++) consumedObjSet.add(x);
        }

        const [subjGroups, subjHeads] = conjunctTermsAndHeads(sent, roles.subject, consumedSubjSet);
        const subjTerms = unionAll(subjGroups);
        const objGroups = roles.object !== null ? nounGroups(sent, roles.object, consumedObjSet) : [];
        const objTerms = unionAll(objGroups);

        const subjHead: string | null = subjHeads.length > 0 ? subjHeads[0]! : null;

        const fx = normalizeBenefitFacet(hit, subjHead);
        const q = quant(sent.slice(roles.subject[0], roles.subject[1]));
        const isNeg = NEG_v1(sent, hit.span, segBounds);
        const pol = polarity(isNeg, hit.isDeny);

        let values: readonly Interval[] | null = null;
        if (roles.value !== null) {
          values = parseValues(sent.slice(roles.value[0], roles.value[1]));
        }

        // requirement frames carry their parse_bool requirement product
        let reqFormula: Bool | null = null;
        if (fx === "facet:approval_requirement" && roles.object !== null) {
          reqFormula = parseBool(sent, roles.object[0], roles.object[1], true);
        }

        const extent: Extent = {
          facet: fx,
          subject: subjTerms,
          object: objTerms,
          modifiers: mods,
          quant: q,
          polarity: pol,
          values,
        };
        const conds = parseConditions(sent, hit, segBounds);
        frames.push({
          fieldId,
          frameId: nextFrameId(),
          extent,
          conds,
          assertive,
          subjectConjuncts: subjGroups,
          subjectConjunctHeads: subjHeads,
          reqFormula,
        });

        // -- span consumption (spec 2.6 frame products) --
        for (let x = hit.span[0]; x < hit.span[1]; x++) consumed.add(x);
        if (negIdx !== null) consumed.add(negIdx); // dual-role
        if (coordinatorIdx !== null) consumed.add(coordinatorIdx);
        for (let x = roles.subject[0]; x < roles.subject[1]; x++) consumed.add(x);
        if (roles.object !== null) {
          for (let x = roles.object[0]; x < roles.object[1]; x++) consumed.add(x);
        }
        if (roles.value !== null) {
          for (let x = roles.value[0]; x < roles.value[1]; x++) consumed.add(x);
        }
        let segHiForCond = sent.length;
        for (const [lo, hi] of segBounds) {
          if (lo <= hit.span[0] && hit.span[0] < hi) {
            segHiForCond = hi;
            break;
          }
        }
        for (const [, , bodyEnd, markerStart] of conditionMarkerSpans(sent, hit.span[1], segHiForCond)) {
          for (let x = markerStart; x < bodyEnd; x++) consumed.add(x);
        }
      } catch (e) {
        if (e instanceof Abstain || e instanceof FramePartial) {
          partial = true;
          sentenceAbstained = true;
          continue;
        }
        throw e;
      }
    }

    if (interrogative) {
      // context '?' sentence: excluded from every basis, spans accounted
      continue;
    }
    if (!sentenceAbstained) {
      // -- total span accounting (spec 2.6) --
      for (let i = 0; i < sent.length; i++) {
        if (consumed.has(i) || markers.has(i)) continue;
        if (isFiller(sent[i]!)) continue;
        partial = true;
        break;
      }
    }
  }
  return [frames, partial];
}

// --------------------------------------------------------------------------
// 3.5 Obligations, aggregation, evidence
// --------------------------------------------------------------------------

/** EXPLICIT obligations from approval_requirement-facet frames (governed
 * conjunct = each SUBJECT conjunct), plus raw IMPLICIT candidates (one per
 * assertive, non-requirement-parent frame with conds != []) which
 * aggregate() groups by PropositionIdentity. */
export function extractObligations(trustedFrames: readonly Frame[]): Obligation[] {
  const explicit: Obligation[] = [];
  const implicitCandidates: Frame[] = [];

  for (const frame of trustedFrames) {
    if (!frame.assertive) continue;
    if (frame.extent.facet === "facet:approval_requirement") {
      if (frame.extent.polarity !== POS) {
        // A negated requirement statement asserts the ABSENCE of a
        // requirement; contributes no explicit (or implicit) obligation.
        continue;
      }
      for (let k = 0; k < frame.subjectConjuncts.length; k++) {
        const conjunctTerms = frame.subjectConjuncts[k]!;
        const conjunctHead = frame.subjectConjunctHeads[k]!;
        const projFacet = conjunctHead !== null ? FACETPROJ_V1.get(conjunctHead) ?? null : null;
        if (projFacet === null) {
          throw new FramePartial(UNEXTRACTABLE);
        }
        const governedIdentity: Extent = {
          facet: projFacet,
          subject: conjunctTerms,
          object: FSet.EMPTY,
          modifiers: frame.extent.modifiers,
          quant: frame.extent.quant,
          polarity: POS,
          values: null,
        };
        const requirementFormula = frame.reqFormula !== null ? frame.reqFormula : TOP_;
        const applicabilityScope = condsAsFormula(frame.conds);
        explicit.push({
          kind: EXPLICIT,
          governedIdentity,
          sourceActivationDomain: TOP_,
          applicabilityScope,
          requirementFormula,
          sourcePolarity: POS,
          trivial: isTrivial(requirementFormula),
          sourceFrameIds: [frame.frameId],
        });
      }
    } else if (frame.conds.length > 0) {
      implicitCandidates.push(frame);
    }
  }

  return [...explicit, ...aggregate(implicitCandidates)];
}

function decKey(d: Dec | null): string {
  return d === null ? "null" : `${d.coefficient.toString()}:${d.scale}`;
}

function intervalKey(iv: Interval): string {
  return JSON.stringify([decKey(iv.lo), iv.loOpen, decKey(iv.hi), iv.hiOpen, iv.unit]);
}

function valuesKey(values: readonly Interval[] | null): string {
  return values === null ? "null" : JSON.stringify(values.map(intervalKey));
}

/** EQUAL PropositionIdentity = byte-equal enc_extent (spec 3.5/7): every
 * enc_extent component participates, including values. */
function extentIdentityKey(extent: Extent): string {
  return JSON.stringify([
    extent.facet,
    extent.subject.key(),
    extent.object.key(),
    extent.modifiers.key(),
    extent.quant,
    extent.polarity,
    valuesKey(extent.values),
  ]);
}

function isTrivial(formula: Bool): boolean {
  let compiled: engine.Compiled;
  try {
    compiled = engine.buildVarmap([formula]);
  } catch (e) {
    if (e instanceof engine.EnvelopeExceeded) return false;
    throw e;
  }
  if (engine.uncompilable(formula)) return false;
  return engine.EQUIV(compiled, formula, TOP_);
}

/** group by EQUAL PropositionIdentity (byte-equal enc_extent); per group
 * over ALL condition nodes (across and within frames): G = grant formulas,
 * R = restriction formulas; formula = OR(G) if R==[] else AND(R) if G==[]
 * else AND(OR(G), AND(R)); atoms keep restrictive flags verbatim;
 * source_activation_domain = OR of member domains; engine-TOP-equivalent
 * formula -> trivial=True. */
export function aggregate(frames: readonly Frame[]): Obligation[] {
  const groups = new Map<string, Frame[]>();
  for (const f of frames) {
    const key = extentIdentityKey(f.extent);
    const arr = groups.get(key);
    if (arr) arr.push(f);
    else groups.set(key, [f]);
  }

  const out: Obligation[] = [];
  for (const members of groups.values()) {
    const grants: Bool[] = [];
    const restrictions: Bool[] = [];
    for (const m of members) {
      for (const c of m.conds) {
        if (c.force === GRANT) grants.push(c.formula);
        else restrictions.push(c.formula);
      }
    }
    const formula = combineGrantRestriction(grants, restrictions);
    const domain = orReduce(members.map((m) => condsAsFormula(m.conds)));
    const rep = members[0]!;
    out.push({
      kind: IMPLICIT,
      governedIdentity: rep.extent,
      sourceActivationDomain: domain,
      applicabilityScope: TOP_,
      requirementFormula: formula,
      sourcePolarity: rep.extent.polarity,
      trivial: isTrivial(formula),
      sourceFrameIds: members.map((m) => m.frameId),
    });
  }
  return out;
}

/** conflicted iff (a) aggregated requirement_formula UNSAT (DECIDED:
 * basis_conflict, never deny-all inference) or (b) two comparable-identity
 * trusted source frames with disposition CONFLICT. */
export function sourceConflictPrepass(obligations: readonly Obligation[], trustedFrames: readonly Frame[]): Set<number> {
  const conflictedFrameIds = new Set<number>();
  const assertive = trustedFrames.filter((f) => f.assertive);
  for (let i = 0; i < assertive.length; i++) {
    for (let j = i + 1; j < assertive.length; j++) {
      const a = assertive[i]!;
      const b = assertive[j]!;
      const r = relations.identityRelation(a.extent, condsAsFormula(a.conds), b.extent, condsAsFormula(b.conds), false);
      if (r === "COMPARABLE" && relations.disposition(a, b) === "CONFLICT") {
        conflictedFrameIds.add(a.frameId);
        conflictedFrameIds.add(b.frameId);
      }
    }
  }

  const conflicted = new Set<number>();
  obligations.forEach((ob, i) => {
    if (ob.sourceFrameIds.some((fid) => conflictedFrameIds.has(fid))) {
      conflicted.add(i);
      return;
    }
    let compiled: engine.Compiled;
    try {
      compiled = engine.buildVarmap([ob.requirementFormula]);
    } catch (e) {
      if (e instanceof engine.EnvelopeExceeded) return;
      throw e;
    }
    if (engine.uncompilable(ob.requirementFormula)) return;
    if (engine.UNSAT(compiled, ob.requirementFormula)) conflicted.add(i);
  });
  return conflicted;
}

/** (a) requirement statements in governed output; (b) condition-bearing
 * assertive output frames. */
export function extractEvidence(outFrames: readonly Frame[], fieldId: string): Evidence[] {
  const evidence: Evidence[] = [];
  let spanCounter = 0;
  for (const fr of outFrames) {
    if (!fr.assertive) continue;
    if (fr.extent.facet === "facet:approval_requirement") {
      for (let k = 0; k < fr.subjectConjuncts.length; k++) {
        const conjunctTerms = fr.subjectConjuncts[k]!;
        const conjunctHead = fr.subjectConjunctHeads[k]!;
        const projFacet = conjunctHead !== null ? FACETPROJ_V1.get(conjunctHead) ?? null : null;
        if (projFacet === null) {
          throw new FramePartial(UNEXTRACTABLE);
        }
        const governedIdentity: Extent = {
          facet: projFacet,
          subject: conjunctTerms,
          object: FSet.EMPTY,
          modifiers: fr.extent.modifiers,
          quant: fr.extent.quant,
          polarity: POS,
          values: null,
        };
        const asserted = fr.reqFormula !== null ? fr.reqFormula : TOP_;
        spanCounter += 1;
        evidence.push({
          fieldId,
          frameId: fr.frameId,
          spanId: spanCounter,
          governedIdentity,
          domain: condsAsFormula(fr.conds),
          assertedFormula: asserted,
          assertionPolarity: fr.extent.polarity,
        });
      }
    }
    if (fr.conds.length > 0) {
      spanCounter += 1;
      evidence.push({
        fieldId,
        frameId: fr.frameId,
        spanId: spanCounter,
        governedIdentity: fr.extent,
        domain: TOP_,
        assertedFormula: condsAsFormula(fr.conds),
        assertionPolarity: POS,
      });
    }
  }
  return evidence;
}
