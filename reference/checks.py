"""Section 6 of ALGORITHM v4 draft 5.2: C1, C2, C3, C4 (rows = FREEZE v18.5
sec 3). C5 is EXCLUDED from vertical slice 1 (C_COV uncalibrated, SAN-882).
"""

from __future__ import annotations

from itertools import combinations
from typing import List

from reference import engine
from reference import relations as rel
from reference.extraction import (
    extract_evidence,
    extract_obligations,
    source_conflict_prepass,
)
from reference.primitives import (
    And,
    BOTTOM_,
    Bool,
    CONDITION_UNDECIDABLE,
    EXISTENTIAL,
    Frame,
    MALFORMED_MENTION,
    Not,
    Or,
    POS,
    TOP_,
    eff,
    eff_quant,
    worst_cause,
)
from reference.tables import T

NOT_EVALUATED = "NOT_EVALUATED"
VIOLATION = "VIOLATION"
PASS = "PASS"

CRITICAL = "critical"
WARNING = "warning"


def D(frame: Frame) -> Bool:
    """D(f) = conds_as_formula(f) -- the frame's own condition domain."""
    from reference.extraction import conds_as_formula

    return conds_as_formula(frame.conds)


TIER_1, TIER_2, TIER_3 = "tier_1", "tier_2", "tier_3"


def _tier_of(frame: Frame, tiers) -> str:
    if not tiers:
        return TIER_1
    return tiers.get(frame.frame_id, TIER_1)


def _trusted(frames: List[Frame], tiers=None) -> List[Frame]:
    """spec 6 C1 step 1: trusted = assertive frames whose declared source
    tier is tier_1 or tier_2. `tiers` maps frame_id -> tier string;
    frames without an entry default to tier_1 (the fixture schema's
    plain-context shape declares a single tier_1 source)."""
    return [
        f for f in frames
        if f.assertive and _tier_of(f, tiers) in (TIER_1, TIER_2)
    ]


def _tier3(frames: List[Frame], tiers=None) -> List[Frame]:
    return [f for f in frames if f.assertive and _tier_of(f, tiers) == TIER_3]


# --------------------------------------------------------------------------
# C1
# --------------------------------------------------------------------------

def C1(ctx_frames: List[Frame], out_frames: List[Frame], ctx_partial: bool, out_partial: bool,
       tiers=None):
    """Returns (outcome, outcome_reason, severity, advisory: bool).
    `advisory` is True only on the row-9 outcome (t3-only contradiction
    with a nonempty authoritative basis): the row is "PASS + advisory
    body note"; the note's wording is owned by FREEZE v18.5, so this
    reference emits the stable boolean flag and leaves rendering to the
    integration layer."""
    if ctx_partial or out_partial:
        return (NOT_EVALUATED, "extraction_partial", None, False)

    trusted = _trusted(ctx_frames, tiers)
    t3 = _tier3(ctx_frames, tiers)

    # spec step 2: self_conf is the SET OF FRAMES (union over conflicting
    # comparable pairs), not a set of pairs.
    self_conf: set = set()
    for a, b in combinations(range(len(trusted)), 2):
        fa, fb = trusted[a], trusted[b]
        r = rel.identity_relation(fa.extent, D(fa), fb.extent, D(fb), False)
        if r == rel.COMPARABLE and rel.disposition(fa, fb) == rel.CONFLICT:
            self_conf.add(a)
            self_conf.add(b)

    any_violating = False
    any_blocked_conflict = False
    any_ambiguous = False
    blocked_undec_causes: List[str] = []
    out_assertive = [f for f in out_frames if f.assertive]

    for fo in out_assertive:
        cmp_idx: List[int] = []
        causes: List[str] = []
        for i, c in enumerate(trusted):
            r = rel.identity_relation(fo.extent, D(fo), c.extent, D(c), False)
            if r == rel.COMPARABLE:
                cmp_idx.append(i)
            elif r == rel.INERT:
                continue
            else:
                causes.append(rel.rel_cause(r))

        disps = []
        for i in cmp_idx:
            d_ = rel.disposition(fo, trusted[i])
            if rel.rel_is_undecidable(d_):
                causes.append(rel.rel_cause(d_))
            else:
                disps.append(d_)

        # spec step 3 status rows, in order: BLOCKED_CONFLICT fires
        # whenever ANY comparable basis frame belongs to self_conf --
        # regardless of this output frame's own dispositions.
        if any(i in self_conf for i in cmp_idx):
            status = "BLOCKED_CONFLICT"
        elif causes:
            status = ("BLOCKED_UNDEC", worst_cause(causes))
        elif disps and all(d_ == rel.CONFLICT for d_ in disps):
            status = "VIOLATING"
        elif any(d_ == rel.CONFLICT for d_ in disps) and any(d_ == rel.MATCH for d_ in disps):
            status = "AMBIGUOUS"
        else:
            status = "CLEAN"

        if status == "VIOLATING":
            any_violating = True
        elif status == "BLOCKED_CONFLICT":
            any_blocked_conflict = True
        elif status == "AMBIGUOUS":
            any_ambiguous = True
        elif isinstance(status, tuple) and status[0] == "BLOCKED_UNDEC":
            blocked_undec_causes.append(status[1])

    if any_violating:
        return (VIOLATION, "detection_complete", CRITICAL, False)
    if any_blocked_conflict:
        return (NOT_EVALUATED, "basis_conflict", None, False)
    if any_ambiguous:
        return (NOT_EVALUATED, "identity_ambiguous", None, False)
    if MALFORMED_MENTION in blocked_undec_causes:
        return (NOT_EVALUATED, "unsupported_claim_form", None, False)
    if blocked_undec_causes:
        return (NOT_EVALUATED, "condition_undecidable", None, False)

    # row 9: t3-only contradiction, authoritative basis nonempty ->
    # PASS + advisory body note. tier_3 is L3-advisory (spec header:
    # free-text advisory, log only): UNDECIDABLE/INERT relations against
    # t3 frames carry no verdict weight and are ignored here; only a
    # decided comparable CONFLICT raises the advisory.
    advisory = False
    if trusted and t3:
        for fo in out_assertive:
            for tf in t3:
                r = rel.identity_relation(fo.extent, D(fo), tf.extent, D(tf), False)
                if r == rel.COMPARABLE and rel.disposition(fo, tf) == rel.CONFLICT:
                    advisory = True
                    break
            if advisory:
                break
    return (PASS, "detection_complete", None, advisory)


# --------------------------------------------------------------------------
# C2
# --------------------------------------------------------------------------

def C2(out_tokens, out_partial: bool):
    """out_partial here is C2's OWN field-partial signal. Normative
    basis: e11 (spec 6, C2 row 0, operator-ratified; FREEZE v18.6 3.2):
    C2 field PARTIAL means C2's OWN normalization/tokenization/lexical
    scan is incomplete, OR the governed output is interrogative
    (sentence-terminal '?'). C2 does NOT inherit proposition-frame
    extraction partiality -- its products are DEFINITIVE_v1/HEDGE_v1
    token matches, not frames. evaluate.py computes the signal (in this
    total implementation the lexical scan cannot be incomplete, so the
    realizable source is the interrogative-output rule)."""
    from reference.primitives import DEFINITIVE_V1, HEDGE_V1, HEDGE_WINDOW_BOUNDARIES
    from reference.extraction import NEG_v1, _segment_bounds

    if out_partial:
        return (NOT_EVALUATED, "extraction_partial", None)

    seg_bounds = _segment_bounds(out_tokens)
    n = len(out_tokens)
    max_def_len = max((len(k) for k in DEFINITIVE_V1), default=1)
    max_hedge_len = max((len(k) for k in HEDGE_V1), default=1)

    for i in range(n):
        matched_def = None
        for length in range(min(max_def_len, n - i), 0, -1):
            key = tuple(t.fold for t in out_tokens[i : i + length])
            if key in DEFINITIVE_V1:
                matched_def = (i, i + length)
                break
        if matched_def is None:
            continue
        d_lo, d_hi = matched_def
        if NEG_v1(out_tokens, matched_def, seg_bounds):
            continue

        seg = next(((lo, hi) for lo, hi in seg_bounds if lo <= d_lo < hi), (0, n))
        w_lo = max(seg[0], d_lo - T.W_HEDGE)
        w_hi = min(seg[1], d_hi + T.W_HEDGE)
        for b in range(d_lo - 1, w_lo - 1, -1):
            if out_tokens[b].fold in HEDGE_WINDOW_BOUNDARIES:
                w_lo = b + 1
                break
        for b in range(d_hi, w_hi):
            if out_tokens[b].fold in HEDGE_WINDOW_BOUNDARIES:
                w_hi = b
                break

        found_hedge = False
        j = w_lo
        while j < w_hi:
            matched_h = None
            for length in range(min(max_hedge_len, w_hi - j), 0, -1):
                key = tuple(t.fold for t in out_tokens[j : j + length])
                if key in HEDGE_V1:
                    matched_h = (j, j + length)
                    break
            if matched_h:
                if not NEG_v1(out_tokens, matched_h, seg_bounds):
                    found_hedge = True
                    break
                j = matched_h[1]
            else:
                j += 1
        if not found_hedge:
            return (VIOLATION, "detection_complete", WARNING)

    return (PASS, "detection_complete", None)


# --------------------------------------------------------------------------
# support() -- shared helper for C3
# --------------------------------------------------------------------------

class SupportResult:
    __slots__ = ("definite_root", "possible_root")

    def __init__(self, definite_root, possible_root):
        self.definite_root = definite_root
        self.possible_root = possible_root


def _is_leaf(node: Bool) -> bool:
    from reference.primitives import MeasureAtom, TermAtom

    return isinstance(node, (TermAtom, MeasureAtom, Not))


def _children_for_reduce(node: Bool):
    if isinstance(node, And):
        return "AND", node.children
    if isinstance(node, Or):
        return "OR", node.children
    return None, ()


def support(req_root: Bool, bound: List) -> SupportResult:
    """TOTALITY (e2): the recursion is total over {TermAtom, MeasureAtom,
    AND, OR, NOT}; a residual NOT(...) subtree is a TERMINAL support unit
    (LEAF): direct entailment only, no recursion into its child."""

    def direct_pos(n: Bool, compiled) -> Bool:
        domains = [e.domain for e in bound if engine.ENTAILS(compiled, eff(e), n) == "YES"]
        return _or_reduce_bool(domains)

    def direct_neg(n: Bool, compiled) -> Bool:
        domains = [e.domain for e in bound if engine.ENTAILS(compiled, eff(e), Not(n)) == "YES"]
        return _or_reduce_bool(domains)

    def anyneg(n: Bool, compiled) -> Bool:
        if _is_leaf(n):
            return direct_neg(n, compiled)
        kind, children = _children_for_reduce(n)
        if kind == "AND":
            return _or2(direct_neg(n, compiled), _or_reduce_bool([anyneg(c, compiled) for c in children]))
        if kind == "OR":
            return _or2(direct_neg(n, compiled), _and_reduce_bool([anyneg(c, compiled) for c in children]))
        return direct_neg(n, compiled)

    def definite(n: Bool, compiled) -> Bool:
        base = _and2(direct_pos(n, compiled), Not(anyneg(n, compiled)))
        if _is_leaf(n):
            return base
        kind, children = _children_for_reduce(n)
        if kind == "AND":
            return _or2(base, _and_reduce_bool([definite(c, compiled) for c in children]))
        if kind == "OR":
            return _or2(base, _or_reduce_bool([definite(c, compiled) for c in children]))
        return base

    def possible(n: Bool, compiled) -> Bool:
        if _is_leaf(n):
            return direct_pos(n, compiled)
        kind, children = _children_for_reduce(n)
        if kind == "AND":
            return _or2(direct_pos(n, compiled), _and_reduce_bool([possible(c, compiled) for c in children]))
        if kind == "OR":
            return _or2(direct_pos(n, compiled), _or_reduce_bool([possible(c, compiled) for c in children]))
        return direct_pos(n, compiled)

    task_formulas = [req_root] + [eff(e) for e in bound] + [e.domain for e in bound]
    compiled = engine.build_varmap(task_formulas)

    return SupportResult(definite(req_root, compiled), possible(req_root, compiled))


def _or_reduce_bool(items: List[Bool]) -> Bool:
    """OR_REDUCE([]) = BOTTOM (pinned)."""
    items = list(items)
    if not items:
        return BOTTOM_
    if len(items) == 1:
        return items[0]
    return Or(tuple(items))


def _and_reduce_bool(items: List[Bool]) -> Bool:
    """AND_REDUCE([]) = TOP (pinned)."""
    items = list(items)
    if not items:
        return TOP_
    if len(items) == 1:
        return items[0]
    return And(tuple(items))


def _or2(a: Bool, b: Bool) -> Bool:
    return _or_reduce_bool([a, b])


def _and2(a: Bool, b: Bool) -> Bool:
    return _and_reduce_bool([a, b])


# --------------------------------------------------------------------------
# C3
# --------------------------------------------------------------------------

def C3(ctx_frames: List[Frame], out_frames: List[Frame], ctx_field_id: str, out_field_id: str,
       ctx_partial: bool, out_partial: bool, tiers=None):
    if ctx_partial or out_partial:
        return (NOT_EVALUATED, "extraction_partial", None)

    from reference.extraction import FramePartial

    trusted = _trusted(ctx_frames, tiers)
    try:
        obs = extract_obligations(trusted)
        ev = extract_evidence(out_frames, out_field_id)
    except FramePartial:
        # spec 3.5: a FACETPROJ miss while building an obligation's or a
        # requirement-evidence item's governed identity -> PARTIAL
        return (NOT_EVALUATED, "extraction_partial", None)
    conflicted = source_conflict_prepass(obs, trusted)

    verdicts: List = []

    for ob_idx, ob in enumerate(obs):
        for fa in [f for f in out_frames if f.assertive]:
            g, gc = rel.two_way_generalizes(ob.governed_identity, fa.extent, False)
            if g == "NO":
                continue
            if g == "UNKNOWN":
                verdicts.append(("UNK", gc))
                continue
            from reference.primitives import EXPLICIT, IMPLICIT

            if ob.kind == IMPLICIT and fa.extent.polarity != ob.source_polarity:
                continue
            if ob.kind == EXPLICIT and (
                fa.extent.polarity != POS or not T.facets_v1.get(fa.extent.facet, {}).get("benefit")
            ):
                continue

            d = engine.DOMAIN(None, D(fa), ob.source_activation_domain)
            if d == "DISJOINT":
                continue
            if d == "UNKNOWN":
                verdicts.append(("UNK", CONDITION_UNDECIDABLE))
                continue
            if ob_idx in conflicted:
                verdicts.append(("OB_CONFLICTED", None))
                continue
            if ob.trivial:
                verdicts.append(("SATISFIED", None))
                continue

            ee = rel.meet(ob.governed_identity, fa.extent)
            E = And((D(fa), ob.applicability_scope))
            if engine.uncompilable(E):
                verdicts.append(("UNK", engine.cause(E)))
                continue
            try:
                e_compiled = engine.build_varmap([E])
            except engine.EnvelopeExceeded:
                verdicts.append(("UNK", CONDITION_UNDECIDABLE))
                continue
            if engine.UNSAT(e_compiled, E):
                continue

            causes: List[str] = []
            bound = []
            for e in [e for e in ev if e.field_id == fa.field_id]:
                gb, gbc = rel.generalizes(e.governed_identity, ee, same_frame=(e.frame_id == fa.frame_id))
                if gb == "UNKNOWN":
                    causes.append(gbc)
                elif gb == "YES" and (
                    eff_quant(e.governed_identity.quant) != EXISTENTIAL or e.frame_id == fa.frame_id
                ):
                    bound.append(e)

            for e in bound:
                if engine.uncompilable(eff(e)):
                    causes.append(engine.cause(eff(e)))
                if engine.uncompilable(e.domain):
                    causes.append(engine.cause(e.domain))

            if causes:
                verdicts.append(("UNK", worst_cause(causes)))
                continue

            S = support(ob.requirement_formula, bound)
            support_compiled = engine.build_varmap([E, S.definite_root, S.possible_root])
            ent = engine.ENTAILS(support_compiled, E, S.definite_root)
            if ent == "YES":
                verdicts.append(("SATISFIED", None))
            else:
                viol = engine.SAT(support_compiled, And((E, Not(S.possible_root))))
                if viol:
                    verdicts.append(("VIOLATION_V", None))
                else:
                    verdicts.append(("UNK", CONDITION_UNDECIDABLE))

    kinds = [v[0] for v in verdicts]
    if "VIOLATION_V" in kinds:
        return (VIOLATION, "detection_complete", WARNING)
    if "OB_CONFLICTED" in kinds:
        return (NOT_EVALUATED, "basis_conflict", None)
    unk_causes = [v[1] for v in verdicts if v[0] == "UNK"]
    if MALFORMED_MENTION in unk_causes:
        return (NOT_EVALUATED, "unsupported_claim_form", None)
    if unk_causes:
        return (NOT_EVALUATED, "condition_undecidable", None)
    return (PASS, "detection_complete", None)


# --------------------------------------------------------------------------
# C4
# --------------------------------------------------------------------------

def C4(ctx_frames: List[Frame], out_frames: List[Frame], ctx_partial: bool, out_partial: bool,
       tiers=None):
    if ctx_partial or out_partial:
        return (NOT_EVALUATED, "extraction_partial", None)

    trusted = _trusted(ctx_frames, tiers)
    conflict_pairs = []
    undec: List[str] = []

    for a, b in combinations(trusted, 2):
        if a.extent.facet != b.extent.facet:
            continue
        if a.extent.polarity == b.extent.polarity:
            continue
        if eff_quant(a.extent.quant) == EXISTENTIAL and eff_quant(b.extent.quant) == EXISTENTIAL:
            continue
        if not (a.extent.subject & b.extent.subject):
            continue
        if not (a.extent.object <= b.extent.object or b.extent.object <= a.extent.object):
            continue

        modrel = _modifier_relation(a.extent, b.extent)
        if modrel == "EXCL":
            continue
        if modrel == "UNKNOWN":
            undec.append(CONDITION_UNDECIDABLE)
            continue

        d = engine.DOMAIN(None, D(a), D(b))
        if d == "OVERLAP":
            conflict_pairs.append((a, b))
        elif d == "UNKNOWN":
            undec.append(CONDITION_UNDECIDABLE)

    unpreserved = []
    for a, b in conflict_pairs:
        restrictive = a if a.extent.polarity == 1 else b
        for fo in [f for f in out_frames if f.assertive and f.extent.facet == a.extent.facet]:
            r1 = rel.identity_relation(fo.extent, D(fo), a.extent, D(a), False)
            r2 = rel.identity_relation(fo.extent, D(fo), b.extent, D(b), False)
            rr = rel.identity_relation(fo.extent, D(fo), restrictive.extent, D(restrictive), False)
            if rel.rel_is_undecidable(r1) or rel.rel_is_undecidable(r2) or rel.rel_is_undecidable(rr):
                causes = [rel.rel_cause(x) for x in (r1, r2, rr) if rel.rel_is_undecidable(x)]
                undec.append(worst_cause(causes))
                continue

            engages = fo.extent.polarity == POS and rr == rel.COMPARABLE
            in_scope = (
                (r1 == rel.COMPARABLE and r2 == rel.COMPARABLE)
                or fo.extent.subject <= (a.extent.subject & b.extent.subject)
                or engages
            )
            if not in_scope:
                continue

            preserved = False
            pres_unknown = False
            for fr in [f for f in out_frames if f.assertive]:
                rx = rel.identity_relation(fr.extent, D(fr), restrictive.extent, D(restrictive), False)
                if rel.rel_is_undecidable(rx):
                    pres_unknown = True
                    continue
                if rx == rel.COMPARABLE and fr.extent.polarity == restrictive.extent.polarity:
                    im = engine.IMPLIES(None, D(restrictive), D(fr))
                    if im == "YES":
                        preserved = True
                        break
                    if im == "UNKNOWN":
                        pres_unknown = True
            if preserved:
                continue
            if pres_unknown:
                undec.append(CONDITION_UNDECIDABLE)
            else:
                unpreserved.append((restrictive, fo))

    if unpreserved:
        return (VIOLATION, "detection_complete", WARNING)
    if MALFORMED_MENTION in undec:
        return (NOT_EVALUATED, "unsupported_claim_form", None)
    if undec:
        return (NOT_EVALUATED, "condition_undecidable", None)
    return (PASS, "detection_complete", None)


def _modifier_relation(a_extent, b_extent) -> str:
    """modifier-set relation per generalizes step 4, both ways: EXCL pair
    -> EXCL; UNKNOWN -> UNKNOWN; else -> OK."""
    from reference.primitives import EXCL_V1

    g1, _ = rel.generalizes(a_extent, b_extent, False)
    g2, _ = rel.generalizes(b_extent, a_extent, False)
    for x_mods, y_mods in ((a_extent.modifiers, b_extent.modifiers), (b_extent.modifiers, a_extent.modifiers)):
        for r_rel, objset in x_mods:
            for r2, ov in y_mods:
                if r2 != r_rel:
                    continue
                for x_term in objset:
                    for y_term in ov:
                        if frozenset({x_term, y_term}) in EXCL_V1:
                            return "EXCL"
    if g1 == "UNKNOWN" or g2 == "UNKNOWN":
        return "UNKNOWN"
    return "OK"
