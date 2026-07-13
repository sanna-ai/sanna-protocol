"""Slice-1 harness entry point: evaluate(fixture) -> per-check results.

SLICE BOUNDARY: inputs arrive pre-classified -- fixtures declare
per-source tiers (either a plain "context" string, one tier_1 source, or
a "context_sources" list of {"text", "tier"} records with tier in
{tier_1, tier_2, tier_3}) and basis is assumed complete/attested.
Wrapper attestation/trust gates (spec section 5, Stage W1's
runtime_binding_missing / dynamic_config_rejected / context_disabled /
attestation gates) are Gate-2 integration (SAN-885) and are OUT OF SCOPE
for this module. C5 is out of slice scope (C_COV uncalibrated, SAN-882).

Implemented pipeline (spec section 5 stage order, scoped to this slice):

  Stage R   per-field raw byte cap (ENV_MAX_FIELD_BYTES); a breach is
            recorded and selected as envelope_exceeded only if no
            earlier W1 gate fires (input_empty fires earlier).
  Stage W1  input_empty (WS_v1): an empty-or-whitespace-only consumed
            field -> NOT_EVALUATED / input_empty for every check that
            consumes it (C2 consumes only the output field).
  Stage X   bounded extraction (extract_frames), including total span
            accounting (spec 2.6). MAX_EXPR_NODES breaches inside
            parse_bool raise EnvelopeExceeded (the sec-8 envelope path),
            as do ENV_MAX_SENTENCES / ENV_MAX_FRAMES count breaches.
  Stage W2  envelope preflight with SET ARITHMETIC ONLY (spec section
            8): ENV_MAX_OBLIGATIONS / ENV_MAX_EVIDENCE counts, per-task
            n(task) <= MAX_BOOL_ATOMS, W_total <= MAX_ENGINE_WORK,
            M_peak <= MAX_ENGINE_BYTES. Any breach -> NOT_EVALUATED /
            envelope_exceeded (never condition_undecidable).
  Stage D   detection (checks C1-C4); the per-check row-0 partial gate
            reports NOT_EVALUATED / extraction_partial.

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
    """Field-level spec 2.6 rule that also gates C2: a governed-output
    sentence with terminal '?'."""
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


def _preflight_budgets(
    ctx_frames: List[Frame],
    out_frames: List[Frame],
    obs,
    ev,
    tiers,
) -> None:
    """Stage W2 envelope preflight (spec section 8). Raises
    engine.EnvelopeExceeded on any breach. Set arithmetic only: task
    atom counts come from engine.preflight_atom_count (canonical keys +
    elementary-interval counts), never from built bitsets."""
    from reference.checks import D

    trusted = checks._trusted(ctx_frames, tiers)
    out_assertive = [f for f in out_frames if f.assertive]

    if len(obs) > T.ENV_MAX_OBLIGATIONS:
        raise engine.EnvelopeExceeded("envelope_exceeded: ENV_MAX_OBLIGATIONS")
    if len(ev) > T.ENV_MAX_EVIDENCE:
        raise engine.EnvelopeExceeded("envelope_exceeded: ENV_MAX_EVIDENCE")

    W_total = 0
    M_peak = 0

    def _pair_task(formulas, measure_task: bool):
        nonlocal W_total, M_peak
        n = engine.preflight_atom_count(formulas)
        if n > T.MAX_BOOL_ATOMS:
            raise engine.EnvelopeExceeded("envelope_exceeded: MAX_BOOL_ATOMS")
        W = sum(engine.bool_nodes(f) for f in formulas) + 3  # COMPILEs + DOMAIN
        if measure_task:
            W += 3  # VALUE-intersection query
        W_total += W
        # M_C1/C4(pair) = (4 + |task formulas| + 1) * bytes(n)
        M_peak = max(M_peak, (4 + len(formulas) + 1) * _bytes_n(n))

    # C1 tasks: (out x trusted-ctx) + ctx pairs, facet-equality screened
    for fo in out_assertive:
        for c in trusted:
            if fo.extent.facet != c.extent.facet:
                continue
            measure = bool(T.facets_v1.get(fo.extent.facet, {}).get("measure"))
            _pair_task([D(fo), D(c)] + _measure_atoms_of(fo) + _measure_atoms_of(c), measure)
    for a, b in combinations(trusted, 2):
        if a.extent.facet != b.extent.facet:
            continue
        measure = bool(T.facets_v1.get(a.extent.facet, {}).get("measure"))
        _pair_task([D(a), D(b)] + _measure_atoms_of(a) + _measure_atoms_of(b), measure)

    # C4 tasks: ctx pairs + pair x out (facet + polarity screens; each
    # pair-x-out leg budgeted as 3 identity DOMAIN queries + one IMPLIES
    # per out-frame preservation candidate -- a conservative superset)
    for a, b in combinations(trusted, 2):
        if a.extent.facet != b.extent.facet:
            continue
        if a.extent.polarity == b.extent.polarity:
            continue
        _pair_task([D(a), D(b)], False)
        for fo in out_assertive:
            if fo.extent.facet != a.extent.facet:
                continue
            formulas = [D(fo), D(a), D(b)]
            n = engine.preflight_atom_count(formulas)
            if n > T.MAX_BOOL_ATOMS:
                raise engine.EnvelopeExceeded("envelope_exceeded: MAX_BOOL_ATOMS")
            W_total += sum(engine.bool_nodes(f) for f in formulas) + 3 * 3 + len(out_assertive) * 3
            M_peak = max(M_peak, (4 + len(formulas) + 1) * _bytes_n(n))

    # C3 tasks: every identity-screened (obligation, out frame) pair,
    # budgeted AS IF activated with its full bindable evidence
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
            W_total += (
                sum(engine.bool_nodes(f) for f in formulas)  # COMPILEs
                + nreq * (6 * k + 2 * k + 4)  # support() recursion bound
                + 3  # final ENTAILS
                + 2  # SAT
                + 3  # DOMAIN
            )
            # M_C3(task) = (4 + |formulas(task)| + 3*nodes(req) + 1) * bytes(n)
            M_peak = max(M_peak, (4 + len(formulas) + 3 * nreq + 1) * _bytes_n(n))

    if W_total > T.MAX_ENGINE_WORK:
        raise engine.EnvelopeExceeded("envelope_exceeded: MAX_ENGINE_WORK")
    if M_peak > T.MAX_ENGINE_BYTES:
        raise engine.EnvelopeExceeded("envelope_exceeded: MAX_ENGINE_BYTES")


def _context_sources(fixture: Dict[str, Any]) -> List[Tuple[str, str]]:
    """Normalized [(text, tier)] list from either fixture shape."""
    if "context_sources" in fixture:
        return [(s["text"], s.get("tier", "tier_1")) for s in fixture["context_sources"]]
    return [(fixture.get("context", ""), "tier_1")]


def evaluate(fixture: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """fixture: {"context": str | "context_sources": [{"text","tier"}],
    "output": str, ...}. Returns per-check result dicts {"outcome",
    "outcome_reason", "severity", "advisory"} for C1..C4 (advisory is
    the C1 row-9 flag; always False elsewhere)."""
    sources = _context_sources(fixture)
    out_text = fixture.get("output", "")

    ctx_empty = all(_is_empty(text) for text, _tier in sources)
    out_empty = _is_empty(out_text)

    results: Dict[str, Dict[str, Any]] = {}

    # -- Stage W1: input_empty (per consumed field) --
    if out_empty:
        return {cid: _result("NOT_EVALUATED", "input_empty", None) for cid in CHECK_IDS}
    if ctx_empty:
        for cid in ("C1", "C3", "C4"):
            results[cid] = _result("NOT_EVALUATED", "input_empty", None)

    # -- Stage R: raw byte caps (selected only when no W1 gate fired) --
    field_bytes_breach = len(out_text.encode("utf-8")) > T.ENV_MAX_FIELD_BYTES or any(
        len(text.encode("utf-8")) > T.ENV_MAX_FIELD_BYTES for text, _tier in sources
    )
    if field_bytes_breach:
        for cid in CHECK_IDS:
            results.setdefault(cid, _result("NOT_EVALUATED", "envelope_exceeded", None))
        return results

    # -- Stage X: extraction (incl. span accounting + MAX_EXPR_NODES) --
    ctx_frames: List[Frame] = []
    tiers: Dict[int, str] = {}
    ctx_partial = False
    out_frames: List[Frame] = []
    out_partial = False
    try:
        if not ctx_empty:
            for text, tier in sources:
                if _is_empty(text):
                    continue
                frames, partial = extract_frames("context", text, governed=False)
                ctx_partial = ctx_partial or partial
                for f in frames:
                    tiers[f.frame_id] = tier
                ctx_frames.extend(frames)
        out_frames, out_partial = extract_frames("output", out_text, governed=True)
    except engine.EnvelopeExceeded:
        for cid in CHECK_IDS:
            results.setdefault(cid, _result("NOT_EVALUATED", "envelope_exceeded", None))
        return results

    out_tokens = tokenize(out_text)
    c2_partial = _has_governed_question(out_text)

    # per-field sentence / frame count caps
    envelope_hit = False
    for text, _tier in sources:
        if _is_empty(text):
            continue
        if len(sentences(tokenize(text), text)) > T.ENV_MAX_SENTENCES:
            envelope_hit = True
    if len(sentences(out_tokens, out_text)) > T.ENV_MAX_SENTENCES:
        envelope_hit = True
    if len(ctx_frames) > T.ENV_MAX_FRAMES or len(out_frames) > T.ENV_MAX_FRAMES:
        envelope_hit = True
    if envelope_hit:
        for cid in CHECK_IDS:
            results.setdefault(cid, _result("NOT_EVALUATED", "envelope_exceeded", None))
        return results

    # -- Stage W2: envelope preflight over enumerated tasks --
    # (obligations/evidence computed here for counting/budgeting; the
    # extraction pipeline is pure and deterministic, so C3's own
    # recomputation below is identical)
    try:
        if not ctx_partial and not out_partial and "C3" not in results:
            trusted = checks._trusted(ctx_frames, tiers)
            obs = extract_obligations(trusted)
            ev = extract_evidence(out_frames, "output")
            _preflight_budgets(ctx_frames, out_frames, obs, ev, tiers)
    except FramePartial:
        pass  # C3 reports extraction_partial through its own gate below
    except engine.EnvelopeExceeded:
        for cid in CHECK_IDS:
            results.setdefault(cid, _result("NOT_EVALUATED", "envelope_exceeded", None))
        return results

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
