"""Slice-1 harness entry point: evaluate(fixture) -> per-check results.

SLICE BOUNDARY: inputs arrive pre-classified -- fixtures declare
per-source tiers (a plain "context" string = one tier_1 source; a
"context_sources" list of {"text", "tier"} records with tier in
{tier_1, tier_2, tier_3}; or "context_repeat" = {text, count}, expanded
by the harness into one tier_1 source for envelope-cap fixtures) and
basis is assumed complete/attested. Wrapper attestation/trust gates
(spec section 5, Stage W1's runtime_binding_missing /
dynamic_config_rejected / context_disabled / attestation gates) are
Gate-2 integration (SAN-885) and are OUT OF SCOPE for this module. C5
is out of slice scope (C_COV uncalibrated, SAN-882).

ENVELOPE SCOPING IS PER CHECK (e12, spec sections 5/8, normative): a
cap breach attaches ONLY to the checks that consume the breached field
(C2 consumes the output field only -- an oversized context can never
suppress it; C1/C3/C4 consume context + output), and a task/engine
overflow attaches ONLY to the owning check (C1 task budgets gate C1;
C3 obligation/evidence counts and task budgets gate C3; C4 task budgets
gate C4). Unaffected checks evaluate normally; there is NO global
envelope result.

Implemented pipeline (spec section 5 stage order, scoped per check):

  Stage R   per-field raw byte cap (ENV_MAX_FIELD_BYTES) -> NOT_EVALUATED
            / envelope_exceeded for that field's consumers only
            (input_empty fires earlier).
  Stage W1  input_empty (WS_v1): an empty-or-whitespace-only consumed
            field -> NOT_EVALUATED / input_empty for its consumers.
  Stage X   bounded extraction (extract_frames) incl. total span
            accounting (spec 2.6); MAX_EXPR_NODES breaches in
            parse_bool and ENV_MAX_SENTENCES / ENV_MAX_FRAMES breaches
            gate the affected field's consumers as envelope_exceeded
            (frame products are consumed by C1/C3/C4; the output
            SENTENCE cap also gates C2, which scans output sentences).
  Stage W2  basis gates + envelope preflight, per check, with SET
            ARITHMETIC ONLY (spec section 8): basis_empty (no
            authoritative tier_1/tier_2 basis after extraction and tier
            resolution -> NOT_EVALUATED / basis_empty for C1/C3/C4);
            ENV_MAX_OBLIGATIONS / ENV_MAX_EVIDENCE (C3 only); per-task
            n(task) <= MAX_BOOL_ATOMS and per-check W_total <=
            MAX_ENGINE_WORK / M_peak <= MAX_ENGINE_BYTES, each gating
            its owning check only.
  Stage D   detection (checks C1-C4); the per-check row-0 partial gate
            reports NOT_EVALUATED / extraction_partial. C2's partial
            gate is C2-LOCAL per e11 (its own lexical scan or an
            interrogative governed output; never inherited frame
            partiality).

Task enumeration for W2 uses the spec's task sets (C1 = out x
trusted-ctx + ctx pairs; C3 = identity-screened (obligation, out frame)
pairs budgeted AS IF activated with full bindable evidence; C4 = ctx
pairs + pair x out) with facet-equality identity screens (pure set
arithmetic). Where a finer screen is cheaper to omit than to compute, it
is omitted, which only ENLARGES the budgeted task set -- conservative
per section 8's "conservative preflight" mandate. W task costs use the
pinned BOOLISA_v1 macros (COMPILE(F)=nodes(F), SAT=2, ENTAILS=3,
DOMAIN-overlap=3, VALUE-intersection=3, OR/AND_REDUCE(k)=max(0,k-1));
support() recursion cost is bounded above by nodes(req) * (6*|bound| +
2*|bound| + 4). M uses the spec's byte formulas verbatim.

ADVISORY FIELD GUARD: the "advisory" key in these result dicts is
differential-harness / internal rendering metadata ONLY (the C1 row-9
"PASS + advisory body note" flag; its wording is owned by FREEZE). It
MUST NEVER become an extra cv=11 CheckResult field: {outcome,
outcome_reason, severity} is the REFERENCE DETECTION PROJECTION of a
CheckResult -- the slice of the locked eight-field cv=11 CheckResult
tuple that this reference implementation computes -- and "advisory" is
not part of that projection nor of the full tuple; any integration
layer emitting receipts must not serialize it into them.
"""

from __future__ import annotations

from itertools import combinations
from typing import Any, Dict, List, Optional, Tuple

from reference import checks
from reference import engine
from reference.extraction import (
    FramePartial,
    extract_evidence,
    extract_frames,
    extract_obligations,
)
from reference.primitives import And, Frame, eff, sentences, tokenize
from reference.tables import T

CHECK_IDS = ("C1", "C2", "C3", "C4")
CTX_CONSUMERS = ("C1", "C3", "C4")  # C2 consumes the output field only


def _is_empty(text: Optional[str]) -> bool:
    if text is None:
        return True
    return all(ch in T.ws_v1 for ch in text) if text else True


def _result(outcome: str, reason: str, severity, advisory: bool = False) -> Dict[str, Any]:
    return {
        "outcome": outcome,
        "outcome_reason": reason,
        "severity": severity,
        "advisory": advisory,
    }


def _has_governed_question(text: str) -> bool:
    """e11: the field-level rule that gates C2 -- a governed-output
    sentence with terminal '?' (C2's other partial source, an incomplete
    C2-local lexical scan, cannot occur in this total implementation)."""
    tokens = tokenize(text)
    for sent in sentences(tokens, text):
        for tok in reversed(sent):
            if tok.kind == "PUNCT" and tok.raw in T.sentence_terminators:
                if tok.raw == "?":
                    return True
                break
            if tok.kind != "PUNCT":
                break
    return False


def _bytes_n(n: int) -> int:
    """bytes(n) = max(1, 2^(n-3)) (spec section 8)."""
    return max(1, 2 ** max(0, n - 3))


def _measure_atoms_of(frame: Frame):
    from reference.relations import _measure_atom

    if frame.extent.values is None:
        return []
    return [_measure_atom(frame.extent)]


class _Budget:
    """Per-check W/M accumulator (e12: budgets are evaluated per check)."""

    def __init__(self):
        self.W_total = 0
        self.M_peak = 0

    def pair_task(self, formulas, measure_task: bool):
        n = engine.preflight_atom_count(formulas)
        if n > T.MAX_BOOL_ATOMS:
            raise engine.EnvelopeExceeded("envelope_exceeded: MAX_BOOL_ATOMS")
        W = sum(engine.bool_nodes(f) for f in formulas) + 3  # COMPILEs + DOMAIN
        if measure_task:
            W += 3  # VALUE-intersection query
        self.W_total += W
        # M_C1/C4(pair) = (4 + |task formulas| + 1) * bytes(n)
        self.M_peak = max(self.M_peak, (4 + len(formulas) + 1) * _bytes_n(n))

    def check_totals(self):
        if self.W_total > T.MAX_ENGINE_WORK:
            raise engine.EnvelopeExceeded("envelope_exceeded: MAX_ENGINE_WORK")
        if self.M_peak > T.MAX_ENGINE_BYTES:
            raise engine.EnvelopeExceeded("envelope_exceeded: MAX_ENGINE_BYTES")


def _budget_c1(ctx_frames: List[Frame], out_frames: List[Frame], tiers) -> None:
    """C1 tasks: (out x trusted-ctx) + ctx pairs, facet-equality screened."""
    from reference.checks import D

    trusted = checks._trusted(ctx_frames, tiers)
    out_assertive = [f for f in out_frames if f.assertive]
    budget = _Budget()
    for fo in out_assertive:
        for c in trusted:
            if fo.extent.facet != c.extent.facet:
                continue
            measure = bool(T.facets_v1.get(fo.extent.facet, {}).get("measure"))
            budget.pair_task([D(fo), D(c)] + _measure_atoms_of(fo) + _measure_atoms_of(c), measure)
    for a, b in combinations(trusted, 2):
        if a.extent.facet != b.extent.facet:
            continue
        measure = bool(T.facets_v1.get(a.extent.facet, {}).get("measure"))
        budget.pair_task([D(a), D(b)] + _measure_atoms_of(a) + _measure_atoms_of(b), measure)
    budget.check_totals()


def _budget_c4(ctx_frames: List[Frame], out_frames: List[Frame], tiers) -> None:
    """C4 tasks: ctx pairs + pair x out (facet + polarity screens; each
    pair-x-out leg budgeted as 3 identity DOMAIN queries + one IMPLIES
    per out-frame preservation candidate -- a conservative superset)."""
    from reference.checks import D

    trusted = checks._trusted(ctx_frames, tiers)
    out_assertive = [f for f in out_frames if f.assertive]
    budget = _Budget()
    for a, b in combinations(trusted, 2):
        if a.extent.facet != b.extent.facet:
            continue
        if a.extent.polarity == b.extent.polarity:
            continue
        budget.pair_task([D(a), D(b)], False)
        for fo in out_assertive:
            if fo.extent.facet != a.extent.facet:
                continue
            formulas = [D(fo), D(a), D(b)]
            n = engine.preflight_atom_count(formulas)
            if n > T.MAX_BOOL_ATOMS:
                raise engine.EnvelopeExceeded("envelope_exceeded: MAX_BOOL_ATOMS")
            budget.W_total += (
                sum(engine.bool_nodes(f) for f in formulas) + 3 * 3 + len(out_assertive) * 3
            )
            budget.M_peak = max(budget.M_peak, (4 + len(formulas) + 1) * _bytes_n(n))
    budget.check_totals()


def _budget_c3(obs, ev, out_frames: List[Frame]) -> None:
    """C3 tasks: every identity-screened (obligation, out frame) pair,
    budgeted AS IF activated with its full bindable evidence. Also owns
    the ENV_MAX_OBLIGATIONS / ENV_MAX_EVIDENCE counts (obligations and
    evidence are C3 products)."""
    from reference.checks import D

    if len(obs) > T.ENV_MAX_OBLIGATIONS:
        raise engine.EnvelopeExceeded("envelope_exceeded: ENV_MAX_OBLIGATIONS")
    if len(ev) > T.ENV_MAX_EVIDENCE:
        raise engine.EnvelopeExceeded("envelope_exceeded: ENV_MAX_EVIDENCE")

    out_assertive = [f for f in out_frames if f.assertive]
    budget = _Budget()
    for ob in obs:
        for fa in out_assertive:
            if ob.governed_identity.facet != fa.extent.facet:
                continue
            E = And((D(fa), ob.applicability_scope))
            bound_candidates = [e for e in ev if e.field_id == fa.field_id]
            formulas = [
                ob.requirement_formula,
                D(fa),
                ob.source_activation_domain,
                ob.applicability_scope,
                E,
            ]
            for e in bound_candidates:
                formulas.append(eff(e))
                formulas.append(e.domain)
            n = engine.preflight_atom_count(formulas)
            if n > T.MAX_BOOL_ATOMS:
                raise engine.EnvelopeExceeded("envelope_exceeded: MAX_BOOL_ATOMS")
            nreq = engine.bool_nodes(ob.requirement_formula)
            k = len(bound_candidates)
            budget.W_total += (
                sum(engine.bool_nodes(f) for f in formulas)  # COMPILEs
                + nreq * (6 * k + 2 * k + 4)  # support() recursion bound
                + 3  # final ENTAILS
                + 2  # SAT
                + 3  # DOMAIN
            )
            # M_C3(task) = (4 + |formulas(task)| + 3*nodes(req) + 1) * bytes(n)
            budget.M_peak = max(
                budget.M_peak, (4 + len(formulas) + 3 * nreq + 1) * _bytes_n(n)
            )
    budget.check_totals()


def _context_sources(fixture: Dict[str, Any]) -> List[Tuple[str, str]]:
    """Normalized [(text, tier)] list from any fixture shape:
    "context" (one tier_1 source), "context_sources" ([{text, tier}]),
    or "context_repeat" ({text, count} -- the harness expands text*count
    into one tier_1 source; used for envelope-cap fixtures so oracle
    files stay reviewable instead of carrying megabyte literals)."""
    if "context_sources" in fixture:
        return [(s["text"], s.get("tier", "tier_1")) for s in fixture["context_sources"]]
    if "context_repeat" in fixture:
        spec = fixture["context_repeat"]
        return [(spec["text"] * spec["count"], "tier_1")]
    return [(fixture.get("context", ""), "tier_1")]


def evaluate(fixture: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """fixture: {"context" | "context_sources" | "context_repeat", plus
    "output": str, ...}. Returns per-check result dicts {"outcome",
    "outcome_reason", "severity", "advisory"} for C1..C4. The first
    three keys are the reference detection projection of a cv=11
    CheckResult; "advisory" is the C1 row-9 flag and is
    harness/rendering metadata ONLY -- never a CheckResult field (see
    module docstring)."""
    sources = _context_sources(fixture)
    out_text = fixture.get("output", "")

    ctx_empty = all(_is_empty(text) for text, _tier in sources)
    out_empty = _is_empty(out_text)

    results: Dict[str, Dict[str, Any]] = {}

    def gate(cids, reason: str):
        for cid in cids:
            results.setdefault(cid, _result("NOT_EVALUATED", reason, None))

    # -- Stage W1: input_empty, per consumed field --
    if out_empty:
        gate(CHECK_IDS, "input_empty")
        return results
    if ctx_empty:
        gate(CTX_CONSUMERS, "input_empty")

    # -- Stage R: per-field raw byte caps (e12: consumers only) --
    if len(out_text.encode("utf-8")) > T.ENV_MAX_FIELD_BYTES:
        gate(CHECK_IDS, "envelope_exceeded")
    if any(len(text.encode("utf-8")) > T.ENV_MAX_FIELD_BYTES for text, _tier in sources):
        gate(CTX_CONSUMERS, "envelope_exceeded")
    if all(cid in results for cid in CHECK_IDS):
        return results

    # -- C2's own lexical inputs (independent of frame extraction) --
    out_tokens = tokenize(out_text)
    c2_partial = _has_governed_question(out_text)
    if len(sentences(out_tokens, out_text)) > T.ENV_MAX_SENTENCES:
        # the output sentence cap gates every output consumer, C2 included
        gate(CHECK_IDS, "envelope_exceeded")
        if all(cid in results for cid in CHECK_IDS):
            return results

    # The declared basis tier composition is computed here (it comes
    # from the DECLARED context_sources, not from extraction), but the
    # basis_empty gate is EMITTED only after Stage X: locked A1's
    # wrapper order is ... -> envelope_exceeded -> scan_incomplete ->
    # basis_incomplete -> basis_unclassified -> basis_empty, so every
    # envelope gate must commit its result first.
    declared_authoritative = any(
        tier in (checks.TIER_1, checks.TIER_2)
        for text, tier in sources
        if not _is_empty(text)
    )

    # -- Stage X: frame extraction (C1/C3/C4 products only, per e11/e12) --
    ctx_frames: List[Frame] = []
    tiers: Dict[int, str] = {}
    ctx_partial = False
    out_frames: List[Frame] = []
    out_partial = False
    if any(cid not in results for cid in CTX_CONSUMERS):
        try:
            if not ctx_empty:
                for text, tier in sources:
                    if _is_empty(text):
                        continue
                    if len(sentences(tokenize(text), text)) > T.ENV_MAX_SENTENCES:
                        raise engine.EnvelopeExceeded("envelope_exceeded: ENV_MAX_SENTENCES")
                    frames, partial = extract_frames("context", text, governed=False)
                    ctx_partial = ctx_partial or partial
                    for f in frames:
                        tiers[f.frame_id] = tier
                    ctx_frames.extend(frames)
            out_frames, out_partial = extract_frames("output", out_text, governed=True)
            if len(ctx_frames) > T.ENV_MAX_FRAMES or len(out_frames) > T.ENV_MAX_FRAMES:
                raise engine.EnvelopeExceeded("envelope_exceeded: ENV_MAX_FRAMES")
        except engine.EnvelopeExceeded:
            # frame products are consumed by C1/C3/C4; C2 is unaffected
            gate(CTX_CONSUMERS, "envelope_exceeded")

    # -- basis_empty: PRE-DETECTION wrapper gate (locked A1), emitted
    # for the C1/C3/C4 checks that SURVIVED the envelope gates. A
    # context declaring no tier_1/tier_2 source has an empty
    # authoritative basis regardless of either field's extraction
    # partiality (extraction_partial is a detection-stage reason and
    # cannot pre-empt a wrapper gate). When an authoritative source IS
    # declared, partiality keeps precedence via the checks' row-0 gate. --
    if not declared_authoritative:
        gate(CTX_CONSUMERS, "basis_empty")

    # -- Stage W2: post-extraction basis arm + per-check budgets --
    if (
        any(cid not in results for cid in CTX_CONSUMERS)
        and not ctx_partial
        and not out_partial
    ):
        trusted = checks._trusted(ctx_frames, tiers)
        if not trusted:
            # basis_empty, post-extraction arm: an authoritative source
            # was DECLARED (the wrapper arm above didn't fire) but tier
            # resolution over the cleanly-extracted frames left no
            # trusted basis (e.g. a tier_1 source whose only sentences
            # are non-assertive context questions).
            gate(CTX_CONSUMERS, "basis_empty")
        else:
            if "C1" not in results:
                try:
                    _budget_c1(ctx_frames, out_frames, tiers)
                except engine.EnvelopeExceeded:
                    gate(("C1",), "envelope_exceeded")
            if "C4" not in results:
                try:
                    _budget_c4(ctx_frames, out_frames, tiers)
                except engine.EnvelopeExceeded:
                    gate(("C4",), "envelope_exceeded")
            if "C3" not in results:
                try:
                    obs = extract_obligations(trusted)
                    ev = extract_evidence(out_frames, "output")
                    _budget_c3(obs, ev, out_frames)
                except FramePartial:
                    pass  # C3 reports extraction_partial through its own gate
                except engine.EnvelopeExceeded:
                    gate(("C3",), "envelope_exceeded")

    # -- Stage D: detection --
    if "C1" not in results:
        outcome, reason, severity, advisory = checks.C1(
            ctx_frames, out_frames, ctx_partial, out_partial, tiers
        )
        results["C1"] = _result(outcome, reason, severity, advisory)

    if "C2" not in results:
        outcome, reason, severity = checks.C2(out_tokens, c2_partial)
        results["C2"] = _result(outcome, reason, severity)

    if "C3" not in results:
        outcome, reason, severity = checks.C3(
            ctx_frames, out_frames, "context", "output", ctx_partial, out_partial, tiers
        )
        results["C3"] = _result(outcome, reason, severity)

    if "C4" not in results:
        outcome, reason, severity = checks.C4(
            ctx_frames, out_frames, ctx_partial, out_partial, tiers
        )
        results["C4"] = _result(outcome, reason, severity)

    return results
