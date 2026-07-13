"""Section 4.3 of ALGORITHM v4 draft 5.2: identity_relation and friends.
Depends on reference.primitives (types) and reference.engine (DOMAIN, SAT,
decompose/build_gamma for measure-facet disposition), NOT on
reference.extraction (no cycle).
"""

from __future__ import annotations

from typing import Optional, Tuple

from reference.primitives import (
    EXCL_V1,
    Extent,
    Frame,
    MALFORMED_MENTION,
    CONDITION_UNDECIDABLE,
    UNIVERSAL,
    EXISTENTIAL,
    eff_quant,
    worst_cause,
)
from reference.tables import T
from reference import engine

YES, NO, UNKNOWN = "YES", "NO", "UNKNOWN"
COMPARABLE, INERT, UNDECIDABLE = "COMPARABLE", "INERT", "UNDECIDABLE"
MATCH, CONFLICT = "MATCH", "CONFLICT"


def _has_malformed(extent: Extent) -> bool:
    """generalizes step 6: "A carries any malformed value/modifier
    product". Structurally unreachable in this pipeline BY CONSTRUCTION,
    not by fixture coverage: spec section 0's symmetric rule makes every
    malformed value/modifier product abstain() DURING extraction (2.4,
    2.5, 3.2 step 7, 3.2 adjunct rules), which raises before the Extent
    is constructed and drives the FIELD to PARTIAL -- so no Extent
    carrying a malformed product ever reaches identity comparison. The
    step is kept as an explicit named check (returning the invariant's
    value) so the numbered spec steps remain visibly total."""
    return False


def generalizes(A: Extent, B: Extent, same_frame: bool) -> Tuple[str, Optional[str]]:
    if A.facet != B.facet:
        return NO, None
    if not A.subject <= B.subject:
        return NO, None
    if not A.object <= B.object:
        return NO, None

    # step 4: modifiers (spec order: EXCL pair -> NO; no same-rel match
    # in B -> NO; same-rel match(es) exist but none contains a.objset ->
    # UNKNOWN(condition_undecidable). NO is definitive and takes
    # precedence over UNKNOWN when both occur across different
    # modifiers of A.)
    any_unknown = False
    for rel, objset in A.modifiers:
        same_rel_in_b = [ov for r2, ov in B.modifiers if r2 == rel]
        if not same_rel_in_b:
            return NO, None
        for ov in same_rel_in_b:
            for a_term in objset:
                for b_term in ov:
                    if frozenset({a_term, b_term}) in EXCL_V1:
                        return NO, None
        if not any(objset <= ov for ov in same_rel_in_b):
            any_unknown = True
    if any_unknown:
        return UNKNOWN, CONDITION_UNDECIDABLE

    # step 5
    if eff_quant(A.quant) == EXISTENTIAL and not same_frame:
        return UNKNOWN, CONDITION_UNDECIDABLE

    # step 6
    if _has_malformed(A):
        return UNKNOWN, MALFORMED_MENTION

    return YES, None


def identity_relation(A: Extent, D_A, B: Extent, D_B, same_frame: bool) -> str:
    """Returns one of COMPARABLE | INERT | ('UNDECIDABLE', cause). A Rel3
    is NEVER read as boolean; callers branch on all three arms -- this
    reference implementation encodes UNDECIDABLE as the 2-tuple
    ('UNDECIDABLE', cause) so callers cannot accidentally treat it as a
    truthy/falsy COMPARABLE-or-not value."""
    g1, c1 = generalizes(A, B, same_frame)
    g2, c2 = generalizes(B, A, same_frame)
    if g1 != YES and g2 != YES:
        if UNKNOWN in (g1, g2):
            return (UNDECIDABLE, worst_cause([c for c in (c1, c2) if c]))
        return INERT
    d = engine.DOMAIN(None, D_A, D_B)
    if d == "OVERLAP":
        return COMPARABLE
    if d == "DISJOINT":
        return INERT
    # d == UNKNOWN
    cause_ = MALFORMED_MENTION if _domain_has_malformed(D_A, D_B) else CONDITION_UNDECIDABLE
    return (UNDECIDABLE, cause_)


def _domain_has_malformed(D_A, D_B) -> bool:
    c1 = engine.cause(D_A)
    c2 = engine.cause(D_B)
    return MALFORMED_MENTION in (c1, c2)


def rel_is_undecidable(rel) -> bool:
    return isinstance(rel, tuple) and rel and rel[0] == UNDECIDABLE


def rel_cause(rel) -> Optional[str]:
    return rel[1] if rel_is_undecidable(rel) else None


def two_way_generalizes(A: Extent, B: Extent, same_frame: bool) -> Tuple[str, Optional[str]]:
    g1, c1 = generalizes(A, B, same_frame)
    if g1 == YES:
        return YES, None
    g2, c2 = generalizes(B, A, same_frame)
    if g2 == YES:
        return YES, None
    if g1 == NO and g2 == NO:
        return NO, None
    return UNKNOWN, worst_cause([c for c in (c1, c2) if c])


def meet(A: Extent, B: Extent) -> Extent:
    modifiers = A.modifiers if len(A.modifiers) >= len(B.modifiers) else B.modifiers
    q = EXISTENTIAL if (eff_quant(A.quant) == EXISTENTIAL or eff_quant(B.quant) == EXISTENTIAL) else UNIVERSAL
    return Extent(
        facet=A.facet,
        subject=A.subject | B.subject,
        object=A.object | B.object,
        modifiers=modifiers,
        quant=q,
        polarity=A.polarity,
        values=None,
    )


def disposition(a: Frame, b: Frame):
    """MATCH|CONFLICT|('UNDECIDABLE', cause)."""
    facet_a = T.facets_v1.get(a.extent.facet, {})
    is_measure_facet = bool(facet_a.get("measure"))
    if is_measure_facet:
        if a.extent.values is None or b.extent.values is None:
            return (UNDECIDABLE, CONDITION_UNDECIDABLE)
        # spec 2.4: comparisons are legal only within one unit group and
        # one currency -- cross-group/cross-currency -> UnknownAtom with
        # cause malformed_mention, so the disposition is UNDECIDABLE,
        # never a silent MATCH of two independent quantities.
        unit_a = a.extent.values[0].unit
        unit_b = b.extent.values[0].unit
        if unit_a != unit_b:
            return (UNDECIDABLE, MALFORMED_MENTION)
        try:
            compiled = engine.build_varmap(
                [_measure_atom(a.extent), _measure_atom(b.extent)]
            )
        except engine.EnvelopeExceeded:
            return (UNDECIDABLE, CONDITION_UNDECIDABLE)
        conflict = not engine.SAT(
            compiled,
            _and2(_measure_atom(a.extent), _measure_atom(b.extent)),
        )
        return CONFLICT if conflict else MATCH

    if a.extent.polarity != b.extent.polarity and not (
        eff_quant(a.extent.quant) == EXISTENTIAL and eff_quant(b.extent.quant) == EXISTENTIAL
    ):
        return CONFLICT
    return MATCH


def _measure_atom(extent: Extent):
    from reference.primitives import MeasureAtom

    unit = extent.values[0].unit if extent.values else ""
    qty = (extent.facet, extent.subject, unit)
    return MeasureAtom(qty, extent.values or ())


def _and2(a, b):
    from reference.primitives import And

    return And((a, b))
