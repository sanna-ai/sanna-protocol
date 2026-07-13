"""Unit tests for reference/relations.py (SAN-879): identity_relation
three arms (incl. the employees/contractors UNDECIDABLE vector), EXCL
pairs, existential cross-frame abstention, meet, dispositions.
"""

from reference.primitives import (
    Dec,
    EXISTENTIAL,
    Extent,
    Interval,
    NEG,
    POS,
    TOP_,
    UNIVERSAL,
    UNSPECIFIED,
)
from reference.relations import (
    COMPARABLE,
    CONFLICT,
    INERT,
    MATCH,
    disposition,
    generalizes,
    identity_relation,
    meet,
    rel_cause,
    rel_is_undecidable,
    two_way_generalizes,
)


def _extent(facet="facet:refund_availability", subject=None, obj=None, modifiers=None,
            quant=UNSPECIFIED, polarity=POS, values=None):
    return Extent(
        facet=facet,
        subject=frozenset(subject or {"refund"}),
        object=frozenset(obj or set()),
        modifiers=frozenset(modifiers or set()),
        quant=quant,
        polarity=polarity,
        values=values,
    )


class DummyFrame:
    def __init__(self, extent, frame_id=1, field_id="f", conds=(), assertive=True):
        self.extent = extent
        self.frame_id = frame_id
        self.field_id = field_id
        self.conds = conds
        self.assertive = assertive


# ---------------------------------------------------------------------
# identity_relation: TOTAL, three arms
# ---------------------------------------------------------------------

def test_identity_relation_comparable_when_generalizes_and_domain_overlap():
    A = _extent()
    B = _extent()
    assert identity_relation(A, TOP_, B, TOP_, False) == COMPARABLE


def test_identity_relation_inert_when_neither_generalizes():
    A = _extent(facet="facet:refund_availability")
    B = _extent(facet="facet:access_permission")
    assert identity_relation(A, TOP_, B, TOP_, False) == INERT


def test_identity_relation_undecidable_employees_contractors_vector():
    # "Refunds for employees are refundable." vs "Refunds for
    # contractors are nonrefundable." -- required tri-state fixture.
    employees = _extent(modifiers={("for", frozenset({"employee"}))})
    contractors = _extent(modifiers={("for", frozenset({"contractor"}))}, polarity=NEG)
    r = identity_relation(employees, TOP_, contractors, TOP_, False)
    assert rel_is_undecidable(r)
    assert rel_cause(r) == "condition_undecidable"


def test_identity_relation_never_read_as_boolean():
    # a Rel3 result must be one of exactly three distinguishable shapes;
    # this test documents/enforces that UNDECIDABLE is never
    # accidentally equal to a bare string a caller might `if result:`
    # test against.
    A = _extent(modifiers={("for", frozenset({"employee"}))})
    B = _extent(modifiers={("for", frozenset({"contractor"}))})
    r = identity_relation(A, TOP_, B, TOP_, False)
    assert r != COMPARABLE
    assert r != INERT
    assert rel_is_undecidable(r)


# ---------------------------------------------------------------------
# EXCL_v1 pairs
# ---------------------------------------------------------------------

def test_generalizes_excl_pair_modifiers_is_no():
    digital = _extent(facet="facet:access_permission", obj={"system"},
                       modifiers={("to", frozenset({"digital"}))})
    physical = _extent(facet="facet:access_permission", obj={"system"},
                        modifiers={("to", frozenset({"physical"}))})
    assert generalizes(digital, physical, False) == ("NO", None)


def test_generalizes_no_same_rel_match_is_no():
    a = _extent(modifiers={("for", frozenset({"employee"}))})
    b = _extent(modifiers=set())
    assert generalizes(a, b, False) == ("NO", None)


# ---------------------------------------------------------------------
# existential cross-frame abstention
# ---------------------------------------------------------------------

def test_generalizes_existential_cross_frame_is_undecidable():
    a = _extent(quant=EXISTENTIAL)
    b = _extent(quant=UNIVERSAL)
    assert generalizes(a, b, same_frame=False) == ("UNKNOWN", "condition_undecidable")


def test_generalizes_existential_same_frame_is_yes():
    a = _extent(quant=EXISTENTIAL)
    b = _extent(quant=UNIVERSAL)
    assert generalizes(a, b, same_frame=True) == ("YES", None)


# ---------------------------------------------------------------------
# two_way_generalizes
# ---------------------------------------------------------------------

def test_two_way_generalizes_yes_if_either_direction():
    a = _extent(subject={"refund"})
    b = _extent(subject={"refund", "extra"})
    # a generalizes b (a.subject <= b.subject) -> YES
    assert two_way_generalizes(a, b, False) == ("YES", None)


def test_two_way_generalizes_no_if_both_no():
    a = _extent(facet="facet:refund_availability")
    b = _extent(facet="facet:access_permission")
    g, cause = two_way_generalizes(a, b, False)
    assert g == "NO"


# ---------------------------------------------------------------------
# meet
# ---------------------------------------------------------------------

def test_meet_unions_subject_and_object():
    a = _extent(subject={"refund"})
    b = _extent(subject={"refund", "premium"})
    m = meet(a, b)
    assert m.subject == frozenset({"refund", "premium"})


def test_meet_quant_existential_if_either_side_existential():
    a = _extent(quant=EXISTENTIAL)
    b = _extent(quant=UNIVERSAL)
    m = meet(a, b)
    assert m.quant == EXISTENTIAL


def test_meet_quant_universal_if_neither_existential():
    a = _extent(quant=UNSPECIFIED)
    b = _extent(quant=UNIVERSAL)
    m = meet(a, b)
    assert m.quant == UNIVERSAL


# ---------------------------------------------------------------------
# disposition
# ---------------------------------------------------------------------

def test_disposition_conflict_on_opposite_polarity_non_existential():
    a = DummyFrame(_extent(facet="facet:access_permission", obj={"system"}, polarity=POS))
    b = DummyFrame(_extent(facet="facet:access_permission", obj={"system"}, polarity=NEG))
    assert disposition(a, b) == CONFLICT


def test_disposition_match_on_same_polarity():
    a = DummyFrame(_extent(facet="facet:access_permission", obj={"system"}, polarity=POS))
    b = DummyFrame(_extent(facet="facet:access_permission", obj={"system"}, polarity=POS))
    assert disposition(a, b) == MATCH


def test_disposition_match_when_both_existential_despite_opposite_polarity():
    a = DummyFrame(_extent(facet="facet:access_permission", obj={"system"}, polarity=POS, quant=EXISTENTIAL))
    b = DummyFrame(_extent(facet="facet:access_permission", obj={"system"}, polarity=NEG, quant=EXISTENTIAL))
    assert disposition(a, b) == MATCH


def test_disposition_measure_conflict_on_disjoint_intervals():
    ivs_a = (Interval(None, True, Dec(5, 0), True, "u"),)  # (-inf, 5)
    ivs_b = (Interval(Dec(10, 0), False, Dec(10, 0), False, "u"),)  # [10,10]
    a = DummyFrame(_extent(facet="facet:cost", values=ivs_a))
    b = DummyFrame(_extent(facet="facet:cost", values=ivs_b))
    assert disposition(a, b) == CONFLICT


def test_disposition_measure_match_on_overlapping_intervals():
    ivs_a = (Interval(None, True, Dec(10, 0), False, "u"),)  # (-inf, 10]
    ivs_b = (Interval(Dec(5, 0), False, Dec(5, 0), False, "u"),)  # [5,5]
    a = DummyFrame(_extent(facet="facet:cost", values=ivs_a))
    b = DummyFrame(_extent(facet="facet:cost", values=ivs_b))
    assert disposition(a, b) == MATCH
