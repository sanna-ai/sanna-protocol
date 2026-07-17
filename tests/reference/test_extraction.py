"""Unit tests for reference/extraction.py adjunct_modifiers' spec 3.2
facet-trigger abstain arm (SAN-894): a facet trigger folded-sequence
inside an adjunct group must abstain the field to PARTIAL. The
nested-adjunct arm of the same spec clause is a separate, pre-existing
divergence tracked as SAN-897 and is out of scope here.
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
