"""Unit tests for reference/extraction.py adjunct_modifiers' spec 3.2
facet-trigger abstain arm (SAN-894): a facet trigger folded-sequence
inside an adjunct group must abstain the field to PARTIAL. The
nested-adjunct arm of the same spec clause is NOW ENFORCED per erratum
e15 (SAN-897): a role span containing consecutive adjunct prepositions
with content between them abstains to PARTIAL unless the second
preposition is immediately preceded by folded "and" (the only v1
sibling separator). See test_nested_adjunct_chain_abstains_to_partial
and test_sibling_adjunct_forms_extract_fully below.
"""

from reference.extraction import extract_frames


def test_adjunct_group_facet_trigger_abstains_to_partial():
    frames, partial = extract_frames(
        "context", "Refunds for available items are refundable."
    )
    assert partial is True


def test_adjunct_group_deny_trigger_abstains_to_partial():
    frames, partial = extract_frames(
        "output", "Refunds for banned items are available.", True
    )
    assert partial is True


def test_adjunct_group_without_trigger_extracts_fully():
    frames, partial = extract_frames(
        "context", "Refunds for physical items are refundable."
    )
    assert partial is False
    assert len(frames) == 1
    assert ("for", frozenset({"physical", "item"})) in frames[0].extent.modifiers


def test_nested_adjunct_chain_abstains_to_partial():
    """e15 NESTED_ADJUNCT_v1 (SAN-897), pairwise over adjunct-preposition
    indices per role span: content between consecutive prepositions with
    the second not immediately preceded by folded "and" -> abstain. Both
    chain inputs are evaluated into a results list FIRST, then asserted,
    so a bare-chain failure cannot prevent the coordinated-NP case (the
    escape this ticket closes) from executing during the red baseline.
    """
    results = [
        extract_frames("context", t)
        for t in [
            "Refunds for physical items with receipts are refundable.",
            "Refunds for physical and digital items with receipts are refundable.",
        ]
    ]
    for frames, partial in results:
        assert partial is True and frames == []


def test_sibling_adjunct_forms_extract_fully():
    """Four non-abstaining sibling-adjunct forms under e15 (SAN-897)."""
    # (i) literal "and <preposition>" is the ONLY v1 sibling separator.
    frames, partial = extract_frames(
        "context", "Refunds for physical items and with receipts are refundable."
    )
    assert partial is False
    assert len(frames) == 1
    assert ("for", frozenset({"physical", "item"})) in frames[0].extent.modifiers
    assert ("with", frozenset({"receipt"})) in frames[0].extent.modifiers

    # (ii) cross-role spans: subject-side "for physical items", object-side
    # "with receipts" -- evaluated independently, no chain interaction.
    frames, partial = extract_frames(
        "context", "Refunds for physical items are refundable with receipts."
    )
    assert partial is False
    assert len(frames) == 1
    assert ("for", frozenset({"physical", "item"})) in frames[0].extent.modifiers
    assert ("with", frozenset({"receipt"})) in frames[0].extent.modifiers

    # (iii) empty first group ("for" immediately followed by "with"):
    # retains existing (pre-e15) behavior.
    frames, partial = extract_frames(
        "context", "Refunds for with receipts are refundable."
    )
    assert partial is False
    assert len(frames) == 1
    assert frames[0].extent.modifiers == frozenset({("with", frozenset({"receipt"}))})

    # (iv) single modifier, no chain at all.
    frames, partial = extract_frames(
        "context", "Refunds for physical items are refundable."
    )
    assert partial is False
    assert len(frames) == 1
    assert frames[0].extent.modifiers == frozenset({("for", frozenset({"physical", "item"}))})
