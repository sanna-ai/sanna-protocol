"""SAN-879: wrapper-gate ordering regressions for evaluate().

Locked A1 wrapper order: ... -> envelope_exceeded -> scan_incomplete ->
basis_incomplete -> basis_unclassified -> basis_empty. envelope_exceeded
must WIN over basis_empty: Stage X's context envelope limits are
evaluated before the declared-tier basis_empty wrapper arm commits.
"""

from reference.evaluate import evaluate
from reference.tables import T


def test_envelope_exceeded_wins_over_basis_empty_on_tier3_only_context(monkeypatch):
    """A tier_3-only context that breaches ENV_MAX_SENTENCES must report
    envelope_exceeded for C1/C3/C4, not basis_empty (both fail closed;
    this pins the audit reason). The cap is monkeypatched low so the
    fixture stays small."""
    monkeypatch.setattr(T, "ENV_MAX_SENTENCES", 3)
    ctx_text = "Items are refundable. " * 4  # 4 sentences > patched cap of 3
    result = evaluate(
        {
            "context_sources": [{"text": ctx_text, "tier": "tier_3"}],
            "output": "Items are refundable.",
        }
    )
    for cid in ("C1", "C3", "C4"):
        assert result[cid]["outcome"] == "NOT_EVALUATED", cid
        assert result[cid]["outcome_reason"] == "envelope_exceeded", cid
        assert result[cid]["severity"] is None, cid
