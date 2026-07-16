/**
 * Slice-1 harness entry point: evaluate(fixture) -> per-check results.
 * Mirrors reference/evaluate.py one-for-one.
 *
 * SLICE BOUNDARY: inputs arrive pre-classified -- fixtures declare
 * per-source tiers (a plain "context" string = one tier_1 source; a
 * "context_sources" list of {text, tier} records with tier in {tier_1,
 * tier_2, tier_3}; or "context_repeat" = {text, count}, expanded by the
 * harness into one tier_1 source for envelope-cap fixtures) and basis is
 * assumed complete/attested. Wrapper attestation/trust gates (spec section
 * 5, Stage W1's runtime_binding_missing / dynamic_config_rejected /
 * context_disabled / attestation gates) are Gate-2 integration (SAN-885)
 * and are OUT OF SCOPE for this module. C5 is out of slice scope
 * (C_COV uncalibrated, SAN-882) -- this module produces C1-C4 only; no C5
 * API surface is exposed.
 *
 * ENVELOPE SCOPING IS PER CHECK (e12, spec sections 5/8, normative): a cap
 * breach attaches ONLY to the checks that consume the breached field (C2
 * consumes the output field only; C1/C3/C4 consume context + output), and
 * a task/engine overflow attaches ONLY to the owning check. Unaffected
 * checks evaluate normally; there is NO global envelope result.
 *
 * ADVISORY FIELD GUARD: the "advisory" key in these result objects is
 * differential-harness / internal rendering metadata ONLY (the C1 row-9
 * "PASS + advisory body note" flag). It MUST NEVER become an extra cv=11
 * CheckResult field: {outcome, outcome_reason, severity} is the REFERENCE
 * DETECTION PROJECTION of a CheckResult, and "advisory" is not part of
 * that projection nor of the full locked eight-field cv=11 tuple; any
 * integration layer emitting receipts must not serialize it into them.
 */

import { T } from "./tables.js";
import * as engine from "./engine.js";
import * as checks from "./checks.js";
import * as relations from "./relations.js";
import {
  Bool,
  Evidence,
  Frame,
  MeasureAtom,
  Obligation,
  eff,
  mkAnd,
  sentences,
  tokenize,
} from "./primitives.js";
import { FramePartial, extractEvidence, extractFrames, extractObligations } from "./extraction.js";

export const CHECK_IDS = ["C1", "C2", "C3", "C4"] as const;
export const CTX_CONSUMERS = ["C1", "C3", "C4"] as const; // C2 consumes the output field only

function isEmpty(text: string | null | undefined): boolean {
  if (text === null || text === undefined) return true;
  if (text.length === 0) return true;
  for (const ch of text) {
    if (!T.wsV1.has(ch)) return false;
  }
  return true;
}

export interface CheckResultRecord {
  readonly outcome: string;
  readonly outcome_reason: string;
  readonly severity: string | null;
  readonly advisory: boolean;
}

function result(outcome: string, reason: string, severity: string | null, advisory: boolean = false): CheckResultRecord {
  return { outcome, outcome_reason: reason, severity, advisory };
}

/** e11: the field-level rule that gates C2 -- a governed-output sentence
 * with terminal '?' (C2's other partial source, an incomplete C2-local
 * lexical scan, cannot occur in this total implementation). */
function hasGovernedQuestion(text: string): boolean {
  const tokens = tokenize(text);
  for (const sent of sentences(tokens, text)) {
    for (let i = sent.length - 1; i >= 0; i--) {
      const tok = sent[i]!;
      if (tok.kind === "PUNCT" && T.sentenceTerminators.has(tok.raw)) {
        if (tok.raw === "?") return true;
        break;
      }
      if (tok.kind !== "PUNCT") break;
    }
  }
  return false;
}

/** bytes(n) = max(1, 2^(n-3)) (spec section 8). */
function bytesN(n: number): number {
  return Math.max(1, 2 ** Math.max(0, n - 3));
}

function byteLength(text: string): number {
  return Buffer.byteLength(text, "utf8");
}

function measureAtomsOf(frame: Frame): MeasureAtom[] {
  if (frame.extent.values === null) return [];
  return [relations.measureAtomOf(frame.extent)];
}

/** Per-check W/M accumulator (e12: budgets are evaluated per check). */
class Budget {
  wTotal = 0;
  mPeak = 0;

  pairTask(formulas: readonly Bool[], measureTask: boolean): void {
    const n = engine.preflightAtomCount(formulas);
    if (n > T.MAX_BOOL_ATOMS) {
      throw new engine.EnvelopeExceeded("envelope_exceeded: MAX_BOOL_ATOMS");
    }
    let w = formulas.reduce((sum, f) => sum + engine.boolNodes(f), 0) + 3; // COMPILEs + DOMAIN
    if (measureTask) w += 3; // VALUE-intersection query
    this.wTotal += w;
    // M_C1/C4(pair) = (4 + |task formulas| + 1) * bytes(n)
    this.mPeak = Math.max(this.mPeak, (4 + formulas.length + 1) * bytesN(n));
  }

  checkTotals(): void {
    if (this.wTotal > T.MAX_ENGINE_WORK) {
      throw new engine.EnvelopeExceeded("envelope_exceeded: MAX_ENGINE_WORK");
    }
    if (this.mPeak > T.MAX_ENGINE_BYTES) {
      throw new engine.EnvelopeExceeded("envelope_exceeded: MAX_ENGINE_BYTES");
    }
  }
}

/** C1 tasks: (out x trusted-ctx) + ctx pairs, facet-equality screened. */
function budgetC1(ctxFrames: readonly Frame[], outFrames: readonly Frame[], tiers: ReadonlyMap<number, string>): void {
  const trustedFrames = checks.trusted(ctxFrames, tiers);
  const outAssertive = outFrames.filter((f) => f.assertive);
  const budget = new Budget();
  for (const fo of outAssertive) {
    for (const c of trustedFrames) {
      if (fo.extent.facet !== c.extent.facet) continue;
      const measure = Boolean(T.facetsV1[fo.extent.facet]?.measure);
      budget.pairTask([checks.D(fo), checks.D(c), ...measureAtomsOf(fo), ...measureAtomsOf(c)], measure);
    }
  }
  for (let i = 0; i < trustedFrames.length; i++) {
    for (let j = i + 1; j < trustedFrames.length; j++) {
      const a = trustedFrames[i]!;
      const b = trustedFrames[j]!;
      if (a.extent.facet !== b.extent.facet) continue;
      const measure = Boolean(T.facetsV1[a.extent.facet]?.measure);
      budget.pairTask([checks.D(a), checks.D(b), ...measureAtomsOf(a), ...measureAtomsOf(b)], measure);
    }
  }
  budget.checkTotals();
}

/** C4 tasks: ctx pairs + pair x out (facet + polarity screens; each
 * pair-x-out leg budgeted as 3 identity DOMAIN queries + one IMPLIES per
 * out-frame preservation candidate -- a conservative superset). */
function budgetC4(ctxFrames: readonly Frame[], outFrames: readonly Frame[], tiers: ReadonlyMap<number, string>): void {
  const trustedFrames = checks.trusted(ctxFrames, tiers);
  const outAssertive = outFrames.filter((f) => f.assertive);
  const budget = new Budget();
  for (let i = 0; i < trustedFrames.length; i++) {
    for (let j = i + 1; j < trustedFrames.length; j++) {
      const a = trustedFrames[i]!;
      const b = trustedFrames[j]!;
      if (a.extent.facet !== b.extent.facet) continue;
      if (a.extent.polarity === b.extent.polarity) continue;
      budget.pairTask([checks.D(a), checks.D(b)], false);
      for (const fo of outAssertive) {
        if (fo.extent.facet !== a.extent.facet) continue;
        const formulas = [checks.D(fo), checks.D(a), checks.D(b)];
        const n = engine.preflightAtomCount(formulas);
        if (n > T.MAX_BOOL_ATOMS) {
          throw new engine.EnvelopeExceeded("envelope_exceeded: MAX_BOOL_ATOMS");
        }
        budget.wTotal += formulas.reduce((sum, f) => sum + engine.boolNodes(f), 0) + 3 * 3 + outAssertive.length * 3;
        budget.mPeak = Math.max(budget.mPeak, (4 + formulas.length + 1) * bytesN(n));
      }
    }
  }
  budget.checkTotals();
}

/** C3 tasks: every identity-screened (obligation, out frame) pair,
 * budgeted AS IF activated with its full bindable evidence. Also owns the
 * ENV_MAX_OBLIGATIONS / ENV_MAX_EVIDENCE counts. */
function budgetC3(obs: readonly Obligation[], ev: readonly Evidence[], outFrames: readonly Frame[]): void {
  if (obs.length > T.ENV_MAX_OBLIGATIONS) {
    throw new engine.EnvelopeExceeded("envelope_exceeded: ENV_MAX_OBLIGATIONS");
  }
  if (ev.length > T.ENV_MAX_EVIDENCE) {
    throw new engine.EnvelopeExceeded("envelope_exceeded: ENV_MAX_EVIDENCE");
  }

  const outAssertive = outFrames.filter((f) => f.assertive);
  const budget = new Budget();
  for (const ob of obs) {
    for (const fa of outAssertive) {
      if (ob.governedIdentity.facet !== fa.extent.facet) continue;
      const E = mkAnd([checks.D(fa), ob.applicabilityScope]);
      const boundCandidates = ev.filter((e) => e.fieldId === fa.fieldId);
      const formulas: Bool[] = [ob.requirementFormula, checks.D(fa), ob.sourceActivationDomain, ob.applicabilityScope, E];
      for (const e of boundCandidates) {
        formulas.push(eff(e));
        formulas.push(e.domain);
      }
      const n = engine.preflightAtomCount(formulas);
      if (n > T.MAX_BOOL_ATOMS) {
        throw new engine.EnvelopeExceeded("envelope_exceeded: MAX_BOOL_ATOMS");
      }
      const nreq = engine.boolNodes(ob.requirementFormula);
      const k = boundCandidates.length;
      budget.wTotal +=
        formulas.reduce((sum, f) => sum + engine.boolNodes(f), 0) // COMPILEs
        + nreq * (6 * k + 2 * k + 4) // support() recursion bound
        + 3 // final ENTAILS
        + 2 // SAT
        + 3; // DOMAIN
      // M_C3(task) = (4 + |formulas(task)| + 3*nodes(req) + 1) * bytes(n)
      budget.mPeak = Math.max(budget.mPeak, (4 + formulas.length + 3 * nreq + 1) * bytesN(n));
    }
  }
  budget.checkTotals();
}

export interface ContextSourceRecord {
  readonly text: string;
  readonly tier?: string;
}
export interface ContextRepeatSpec {
  readonly text: string;
  readonly count: number;
}
export interface Fixture {
  readonly context?: string;
  readonly context_sources?: readonly ContextSourceRecord[];
  readonly context_repeat?: ContextRepeatSpec;
  readonly output?: string;
}

/** Normalized [[text, tier]] list from any fixture shape: "context" (one
 * tier_1 source), "context_sources" ([{text, tier}]), or "context_repeat"
 * ({text, count} -- the harness expands text*count into one tier_1
 * source; used for envelope-cap fixtures so oracle files stay reviewable
 * instead of carrying megabyte literals). */
function contextSources(fixture: Fixture): Array<[string, string]> {
  if (fixture.context_sources !== undefined) {
    return fixture.context_sources.map((s): [string, string] => [s.text, s.tier ?? "tier_1"]);
  }
  if (fixture.context_repeat !== undefined) {
    const spec = fixture.context_repeat;
    return [[spec.text.repeat(spec.count), "tier_1"]];
  }
  return [[fixture.context ?? "", "tier_1"]];
}

export type EvaluateResult = Record<string, CheckResultRecord>;

/** fixture: {"context" | "context_sources" | "context_repeat", plus
 * "output": str, ...}. Returns per-check result records {outcome,
 * outcome_reason, severity, advisory} for C1..C4. The first three fields
 * are the reference detection projection of a cv=11 CheckResult;
 * "advisory" is the C1 row-9 flag and is harness/rendering metadata ONLY
 * (see module docstring). */
export function evaluate(fixture: Fixture): EvaluateResult {
  const sources = contextSources(fixture);
  const outText = fixture.output ?? "";

  const ctxEmpty = sources.every(([text]) => isEmpty(text));
  const outEmpty = isEmpty(outText);

  const results: Record<string, CheckResultRecord> = {};

  const gate = (cids: readonly string[], reason: string): void => {
    for (const cid of cids) {
      if (!(cid in results)) results[cid] = result("NOT_EVALUATED", reason, null);
    }
  };

  // -- Stage W1: input_empty, per consumed field --
  if (outEmpty) {
    gate(CHECK_IDS, "input_empty");
    return results;
  }
  if (ctxEmpty) {
    gate(CTX_CONSUMERS, "input_empty");
  }

  // -- Stage R: per-field raw byte caps (e12: consumers only) --
  if (byteLength(outText) > T.ENV_MAX_FIELD_BYTES) {
    gate(CHECK_IDS, "envelope_exceeded");
  }
  if (sources.some(([text]) => byteLength(text) > T.ENV_MAX_FIELD_BYTES)) {
    gate(CTX_CONSUMERS, "envelope_exceeded");
  }
  if (CHECK_IDS.every((cid) => cid in results)) return results;

  // -- C2's own lexical inputs (independent of frame extraction) --
  const outTokens = tokenize(outText);
  const c2Partial = hasGovernedQuestion(outText);
  if (sentences(outTokens, outText).length > T.ENV_MAX_SENTENCES) {
    // the output sentence cap gates every output consumer, C2 included
    gate(CHECK_IDS, "envelope_exceeded");
    if (CHECK_IDS.every((cid) => cid in results)) return results;
  }

  // The declared basis tier composition is computed here (from the
  // DECLARED context_sources, not extraction), but the basis_empty gate is
  // EMITTED only after Stage X: locked A1's wrapper order is ... ->
  // envelope_exceeded -> scan_incomplete -> basis_incomplete ->
  // basis_unclassified -> basis_empty, so every envelope gate must commit
  // its result first.
  const declaredAuthoritative = sources.some(
    ([text, tier]) => !isEmpty(text) && (tier === checks.TIER_1 || tier === checks.TIER_2),
  );

  // -- Stage X: frame extraction (C1/C3/C4 products only, per e11/e12) --
  let ctxFrames: Frame[] = [];
  const tiers = new Map<number, string>();
  let ctxPartial = false;
  let outFrames: Frame[] = [];
  let outPartial = false;
  if (CTX_CONSUMERS.some((cid) => !(cid in results))) {
    try {
      if (!ctxEmpty) {
        for (const [text, tier] of sources) {
          if (isEmpty(text)) continue;
          if (sentences(tokenize(text), text).length > T.ENV_MAX_SENTENCES) {
            throw new engine.EnvelopeExceeded("envelope_exceeded: ENV_MAX_SENTENCES");
          }
          const [frames, partial] = extractFrames("context", text, false);
          ctxPartial = ctxPartial || partial;
          for (const f of frames) tiers.set(f.frameId, tier);
          ctxFrames.push(...frames);
        }
      }
      const [oFrames, oPartial] = extractFrames("output", outText, true);
      outFrames = oFrames;
      outPartial = oPartial;
      if (ctxFrames.length > T.ENV_MAX_FRAMES || outFrames.length > T.ENV_MAX_FRAMES) {
        throw new engine.EnvelopeExceeded("envelope_exceeded: ENV_MAX_FRAMES");
      }
    } catch (e) {
      if (e instanceof engine.EnvelopeExceeded) {
        // frame products are consumed by C1/C3/C4; C2 is unaffected
        gate(CTX_CONSUMERS, "envelope_exceeded");
      } else {
        throw e;
      }
    }
  }

  // -- basis_empty: PRE-DETECTION wrapper gate (locked A1) --
  if (!declaredAuthoritative) {
    gate(CTX_CONSUMERS, "basis_empty");
  }

  // -- Stage W2: post-extraction basis arm + per-check budgets --
  if (CTX_CONSUMERS.some((cid) => !(cid in results)) && !ctxPartial && !outPartial) {
    const trustedFrames = checks.trusted(ctxFrames, tiers);
    if (trustedFrames.length === 0) {
      // basis_empty, post-extraction arm
      gate(CTX_CONSUMERS, "basis_empty");
    } else {
      if (!("C1" in results)) {
        try {
          budgetC1(ctxFrames, outFrames, tiers);
        } catch (e) {
          if (e instanceof engine.EnvelopeExceeded) gate(["C1"], "envelope_exceeded");
          else throw e;
        }
      }
      if (!("C4" in results)) {
        try {
          budgetC4(ctxFrames, outFrames, tiers);
        } catch (e) {
          if (e instanceof engine.EnvelopeExceeded) gate(["C4"], "envelope_exceeded");
          else throw e;
        }
      }
      if (!("C3" in results)) {
        try {
          const obs = extractObligations(trustedFrames);
          const ev = extractEvidence(outFrames, "output");
          budgetC3(obs, ev, outFrames);
        } catch (e) {
          if (e instanceof FramePartial) {
            // C3 reports extraction_partial through its own gate
          } else if (e instanceof engine.EnvelopeExceeded) {
            gate(["C3"], "envelope_exceeded");
          } else {
            throw e;
          }
        }
      }
    }
  }

  // -- Stage D: detection --
  if (!("C1" in results)) {
    const [outcome, reason, severity, advisory] = checks.C1(ctxFrames, outFrames, ctxPartial, outPartial, tiers);
    results["C1"] = result(outcome, reason, severity, advisory);
  }

  if (!("C2" in results)) {
    const [outcome, reason, severity] = checks.C2(outTokens, c2Partial);
    results["C2"] = result(outcome, reason, severity);
  }

  if (!("C3" in results)) {
    const [outcome, reason, severity] = checks.C3(ctxFrames, outFrames, "context", "output", ctxPartial, outPartial, tiers);
    results["C3"] = result(outcome, reason, severity);
  }

  if (!("C4" in results)) {
    const [outcome, reason, severity] = checks.C4(ctxFrames, outFrames, ctxPartial, outPartial, tiers);
    results["C4"] = result(outcome, reason, severity);
  }

  return results;
}
