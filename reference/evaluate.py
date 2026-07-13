"""Slice-1 harness entry point: evaluate(fixture) -> per-check results.

SLICE BOUNDARY: inputs arrive pre-classified -- fixtures declare
per-source tiers directly (context frames default to tier_1 unless a
fixture states otherwise) and basis is assumed complete/attested.
Wrapper attestation/trust gates (spec section 5, Stage W1's
runtime_binding_missing / dynamic_config_rejected / context_disabled /
per-run coverage attestation gates) are Gate-2 integration (SAN-885) and
are OUT OF SCOPE for this module.

Implemented in this slice:
  - the symmetric partial gate (extraction_partial, spec section 6 row 0
    of every check)
  - input_empty (WS_v1): an empty-or-whitespace-only field short-circuits
    straight to NOT_EVALUATED/extraction_partial for every check, mirroring
    Stage W1's input_empty gate ahead of Stage X extraction
  - the envelope preflight caps (MAX_BOOL_ATOMS / MAX_ENGINE_WORK /
    MAX_ENGINE_BYTES per spec section 8), applied conservatively: any
    engine.EnvelopeExceeded raised while compiling a check's boolean
    task is caught here and reported as NOT_EVALUATED/condition_undecidable
    rather than propagating as an uncaught exception (detection has "no
    cap checks" per spec section 5's Stage D note; this harness enforces
    the caps at the W2 boundary, before Stage D checks run, as the spec's
    pipeline dictates -- not mid-check).
"""

from __future__ import annotations

from typing import Any, Dict

from reference import checks
from reference import engine
from reference.primitives import tokenize
from reference.extraction import extract_frames

CHECK_IDS = ("C1", "C2", "C3", "C4")


def _is_empty(text: str) -> bool:
    from reference.tables import T

    if text is None:
        return True
    return all(ch in T.ws_v1 for ch in text) if text else True


def evaluate(fixture: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """fixture: {"context": str, "output": str, ...}. Returns
    {"C1": {"outcome":..., "outcome_reason":..., "severity":...}, "C2":
    {...}, "C3": {...}, "C4": {...}}."""
    ctx_text = fixture.get("context", "")
    out_text = fixture.get("output", "")

    ctx_empty = _is_empty(ctx_text)
    out_empty = _is_empty(out_text)

    def empty_result():
        return {"outcome": "NOT_EVALUATED", "outcome_reason": "extraction_partial", "severity": None}

    # input_empty (WS_v1) is a per-field gate: C2 only consumes the
    # output field, so an empty context field (used by the required
    # c2-definitive / c2-hedged oracles, which supply "") must not
    # block C2. C1/C3/C4 consume both fields.
    ctx_frames, ctx_partial = ((), False) if ctx_empty else extract_frames("context", ctx_text)
    out_frames, out_partial = ((), False) if out_empty else extract_frames("output", out_text)

    results: Dict[str, Dict[str, Any]] = {}

    if ctx_empty or out_empty:
        results["C1"] = empty_result()
    else:
        try:
            outcome, reason, severity = checks.C1(ctx_frames, out_frames, ctx_partial, out_partial)
        except engine.EnvelopeExceeded:
            outcome, reason, severity = "NOT_EVALUATED", "condition_undecidable", None
        results["C1"] = {"outcome": outcome, "outcome_reason": reason, "severity": severity}

    if out_empty:
        results["C2"] = empty_result()
    else:
        out_tokens = tokenize(out_text)
        try:
            outcome, reason, severity = checks.C2(out_tokens, out_partial)
        except engine.EnvelopeExceeded:
            outcome, reason, severity = "NOT_EVALUATED", "condition_undecidable", None
        results["C2"] = {"outcome": outcome, "outcome_reason": reason, "severity": severity}

    if ctx_empty or out_empty:
        results["C3"] = empty_result()
    else:
        try:
            outcome, reason, severity = checks.C3(
                ctx_frames, out_frames, "context", "output", ctx_partial, out_partial
            )
        except engine.EnvelopeExceeded:
            outcome, reason, severity = "NOT_EVALUATED", "condition_undecidable", None
        results["C3"] = {"outcome": outcome, "outcome_reason": reason, "severity": severity}

    if ctx_empty or out_empty:
        results["C4"] = empty_result()
    else:
        try:
            outcome, reason, severity = checks.C4(ctx_frames, out_frames, ctx_partial, out_partial)
        except engine.EnvelopeExceeded:
            outcome, reason, severity = "NOT_EVALUATED", "condition_undecidable", None
        results["C4"] = {"outcome": outcome, "outcome_reason": reason, "severity": severity}

    return results
