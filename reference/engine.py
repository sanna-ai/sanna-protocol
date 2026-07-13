"""Section 4.1/4.2 of ALGORITHM v4 draft 5.2: bitsets, varmap, elementary
interval decomposition, GAMMA, and the boolean queries (SAT/UNSAT/EQUIV/
NEGATE/ENTAILS/DOMAIN/IMPLIES). Depends only on reference.primitives
(Bool AST + Dec/Interval) and reference.tables (MAX_BOOL_ATOMS); does not
depend on reference.extraction, so extraction.py can safely import this
module without a cycle.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from reference.primitives import (
    And,
    BOTTOM,
    Bool,
    COMPLEMENT_V1,
    Dec,
    MeasureAtom,
    Not,
    Or,
    TOP,
    TermAtom,
    UnknownAtom,
    dec_cmp,
)
from reference.tables import T


class EnvelopeExceeded(Exception):
    """n(task) > MAX_BOOL_ATOMS (section 8 preflight)."""


# --------------------------------------------------------------------------
# Bitset (section 4.1): EXACTLY 2^n valid bits in ceil(2^n/64) words;
# padding bits above 2^n are ALWAYS zero; NOT(F) = mask_n & ~F.words
# (width-bounded); every op that could set padding re-masks.
# --------------------------------------------------------------------------

class Bitset:
    __slots__ = ("n", "size", "words", "mask")

    def __init__(self, n: int, words: Optional[int] = None):
        self.n = n
        self.size = 1 << n  # 2^n valid bits
        self.mask = (1 << self.size) - 1
        self.words = (words if words is not None else 0) & self.mask

    @classmethod
    def zero(cls, n: int) -> "Bitset":
        return cls(n, 0)

    @classmethod
    def full(cls, n: int) -> "Bitset":
        return cls(n, (1 << (1 << n)) - 1)

    def _check(self, other: "Bitset"):
        if other.n != self.n:
            raise ValueError(f"bitset width mismatch: {self.n} vs {other.n}")

    def op_and(self, other: "Bitset") -> "Bitset":
        self._check(other)
        return Bitset(self.n, self.words & other.words)

    def op_or(self, other: "Bitset") -> "Bitset":
        self._check(other)
        return Bitset(self.n, self.words | other.words)

    def op_xor(self, other: "Bitset") -> "Bitset":
        self._check(other)
        return Bitset(self.n, self.words ^ other.words)

    def op_not(self) -> "Bitset":
        return Bitset(self.n, self.mask & ~self.words)

    def is_zero(self) -> bool:
        return self.words == 0

    def is_nonzero(self) -> bool:
        return self.words != 0

    def equals(self, other: "Bitset") -> bool:
        self._check(other)
        return self.words == other.words

    def set_bit(self, index: int):
        if index >= self.size:
            raise ValueError("bit index out of range")
        self.words |= 1 << index
        self.words &= self.mask


def bit_from_assignment(assignment: int, n: int) -> int:
    """assignment is a bitmask over n boolean variables (bit i = variable
    i's truth value); returns the corresponding Bitset bit index (each
    bit of Bitset.words indexes one full assignment of all n variables)."""
    return assignment


# --------------------------------------------------------------------------
# Elementary intervals (section 4.1 decompose) + GAMMA (build_gamma)
# --------------------------------------------------------------------------

def _endpoints(intervals: List) -> List[Dec]:
    finite = []
    for iv in intervals:
        if iv.lo is not None:
            finite.append(iv.lo)
        if iv.hi is not None:
            finite.append(iv.hi)
    finite.sort(key=_DecKey)
    out = []
    for d in finite:
        if not out or dec_cmp(out[-1], d) != 0:
            out.append(d)
    return out


class _DecKey:
    __slots__ = ("d",)

    def __init__(self, d: Dec):
        self.d = d

    def __lt__(self, other):
        return dec_cmp(self.d, other.d) < 0

    def __eq__(self, other):
        return dec_cmp(self.d, other.d) == 0


def decompose(quantity_intervals: List) -> List[Tuple]:
    """Convert all bounds to elementary-interval indicators. Endpoints are
    dec_cmp-sorted unique finite bounds e1..ek; indicators in order:
    (-inf,e1), [e1,e1], (e1,e2), [e2,e2], ..., [ek,ek], (ek,+inf) =>
    2k+1 variables. Returns list of (lo, lo_open, hi, hi_open) tuples,
    each an elementary indicator; index i in the returned list IS the
    indicator's position for GAMMA's exactly-one group."""
    endpoints = _endpoints(quantity_intervals)
    k = len(endpoints)
    indicators = []
    if k == 0:
        # No finite bound anywhere: the whole line is one indicator.
        indicators.append((None, True, None, True))
        return indicators
    indicators.append((None, True, endpoints[0], True))
    for idx, e in enumerate(endpoints):
        indicators.append((e, False, e, False))
        if idx + 1 < k:
            indicators.append((e, True, endpoints[idx + 1], True))
    indicators.append((endpoints[-1], True, None, True))
    return indicators


def _interval_covers_indicator(iv, indicator) -> bool:
    """Does interval iv (with open/closed bounds) cover elementary
    indicator ind (an elementary interval that never straddles a bound
    of any contributing interval, by construction of decompose)?"""
    ilo, ilo_open, ihi, ihi_open = indicator
    # test containment via the indicator's own representative point
    # relation to iv's bounds using the standard interval-in-interval
    # rule for our finite endpoint construction: an elementary indicator
    # is either a single point [e,e] or an open interval strictly
    # between two consecutive contributing endpoints (or unbounded on
    # one/both sides).
    if ilo is not None and ilo_open is False and ihi is not None and ihi_open is False and dec_cmp(ilo, ihi) == 0:
        # point indicator [e, e]
        e = ilo
        if iv.lo is not None:
            c = dec_cmp(e, iv.lo)
            if c < 0 or (c == 0 and iv.lo_open):
                return False
        if iv.hi is not None:
            c = dec_cmp(e, iv.hi)
            if c > 0 or (c == 0 and iv.hi_open):
                return False
        return True
    # open span indicator (possibly unbounded on one/both sides)
    if iv.lo is not None and ilo is not None:
        c = dec_cmp(ilo, iv.lo)
        if c < 0:
            return False
        if c == 0 and not iv.lo_open:
            # indicator's lower edge touches iv.lo (closed) but the
            # indicator itself is an open span starting exactly at
            # iv.lo -- still within iv since iv.lo is included and the
            # span's interior points are > iv.lo >= iv.lo.
            pass
    if iv.lo is not None and ilo is None:
        return False
    if iv.hi is not None and ihi is not None:
        c = dec_cmp(ihi, iv.hi)
        if c > 0:
            return False
    if iv.hi is not None and ihi is None:
        return False
    return True


def indicator_bitmask_for_intervals(intervals, indicators) -> int:
    mask = 0
    for i, ind in enumerate(indicators):
        for iv in intervals:
            if _interval_covers_indicator(iv, ind):
                mask |= 1 << i
                break
    return mask


def build_exactly_one_group(n_vars: int, var_indices: List[int]) -> Bitset:
    """BUILD_EXACTLY_ONE(indicators): exactly one of the given variables
    (by bit index in the n_vars-variable space) is true in a valid
    assignment. Returns a Bitset over the full n_vars-variable space
    whose set bits are exactly the assignments satisfying that."""
    bs = Bitset.zero(n_vars)
    size = bs.size
    words = 0
    for assignment in range(size):
        count = 0
        for vi in var_indices:
            if (assignment >> vi) & 1:
                count += 1
        if count == 1:
            words |= 1 << assignment
    bs.words = words & bs.mask
    return bs


def build_gamma(n_vars: int, quantity_var_groups: List[List[int]]) -> Bitset:
    """per quantity: BUILD_EXACTLY_ONE(indicators); combine across Q
    quantities with AND_REDUCE. Q == 0 -> GAMMA = TOP (full mask)."""
    if not quantity_var_groups:
        return Bitset.full(n_vars)
    gamma = Bitset.full(n_vars)
    for group in quantity_var_groups:
        gamma = gamma.op_and(build_exactly_one_group(n_vars, group))
    return gamma


# --------------------------------------------------------------------------
# build_varmap (section 4.1): keys = ATOMENC atom bytes EXCLUDING the
# restrictive flag (variable identity = terms + polarity); COMPLEMENT_v1
# pairs and opposite-polarity twins collapse to ONE variable (negated
# side flagged); MeasureAtoms expand to elementary-interval indicators.
# --------------------------------------------------------------------------

def _canonical_term_key(terms: frozenset) -> Tuple[frozenset, bool]:
    """Fold COMPLEMENT_v1 pairs to a single canonical variable identity.
    Only applies when `terms` is a single-term atom whose sole term is
    the "negated side" of a configured complement pair; multi-term
    atoms are never complement-folded (COMPLEMENT_v1 entries are single
    words). e9 (spec 4.2): the pair lookup operates on the SAME
    normalized form as Bool atoms (post-stem, post-CONCEPT_v1) -- the
    normalized pairs are compiled once in reference.primitives
    (COMPLEMENT_V1), so 'if verified' (atom term 'verification' via
    CONCEPT_v1) and 'if unverified' collapse to one variable."""
    if len(terms) == 1:
        (term,) = tuple(terms)
        for positive, negative in COMPLEMENT_V1:
            if term == negative:
                return frozenset({positive}), True
            if term == positive:
                return frozenset({positive}), False
    return terms, False


def _collect_atoms(node: Bool, term_atoms: list, measure_atoms: list):
    if isinstance(node, TermAtom):
        term_atoms.append(node)
    elif isinstance(node, MeasureAtom):
        measure_atoms.append(node)
    elif isinstance(node, UnknownAtom):
        pass
    elif isinstance(node, Not):
        _collect_atoms(node.child, term_atoms, measure_atoms)
    elif isinstance(node, (And, Or)):
        for c in node.children:
            _collect_atoms(c, term_atoms, measure_atoms)
    elif isinstance(node, (TOP, BOTTOM)):
        pass
    else:  # pragma: no cover - defensive
        raise TypeError(f"unrecognized Bool node {node!r}")


def build_varmap(task_formulas: List[Bool]):
    """Returns a Compiled object (n, compile(formula)->Bitset, gamma) or
    raises EnvelopeExceeded if |variables| > MAX_BOOL_ATOMS."""
    term_atoms: list = []
    measure_atoms: list = []
    for f in task_formulas:
        _collect_atoms(f, term_atoms, measure_atoms)

    # TermAtom variables, sorted bytewise by canonical key for
    # determinism (spec: "sort keys bytewise").
    canonical_keys = set()
    negated_of = {}
    for atom in term_atoms:
        key, neg = _canonical_term_key(atom.terms)
        canonical_keys.add(key)
        negated_of[key] = neg
    sorted_keys = sorted(canonical_keys, key=lambda k: tuple(sorted(k)))

    # MeasureAtom quantities: group intervals by qty key.
    qty_intervals: Dict[tuple, list] = {}
    for atom in measure_atoms:
        qty_intervals.setdefault(atom.qty, []).extend(atom.intervals)
    sorted_qtys = sorted(qty_intervals.keys(), key=lambda q: (q[0], tuple(sorted(q[1])), q[2]))

    term_var_index = {key: i for i, key in enumerate(sorted_keys)}
    n = len(sorted_keys)

    qty_var_groups: Dict[tuple, List[int]] = {}
    qty_indicators: Dict[tuple, list] = {}
    for qty in sorted_qtys:
        indicators = decompose(qty_intervals[qty])
        var_indices = list(range(n, n + len(indicators)))
        n += len(indicators)
        qty_var_groups[qty] = var_indices
        qty_indicators[qty] = indicators

    if n > T.MAX_BOOL_ATOMS:
        raise EnvelopeExceeded(f"envelope_exceeded: {n} > MAX_BOOL_ATOMS={T.MAX_BOOL_ATOMS}")

    gamma = build_gamma(n, list(qty_var_groups.values()))

    return Compiled(n, term_var_index, negated_of, qty_var_groups, qty_indicators, gamma)


def preflight_atom_count(task_formulas: List[Bool]) -> int:
    """SET ARITHMETIC ONLY (spec section 8): the number of boolean
    variables the task would materialize -- canonical TermAtom keys
    (complement-folded) plus 2k+1 elementary-interval indicators per
    MeasureAtom quantity -- computed without building any bitset.
    Mirrors build_varmap's counting phase exactly."""
    term_atoms: list = []
    measure_atoms: list = []
    for f in task_formulas:
        _collect_atoms(f, term_atoms, measure_atoms)
    canonical_keys = {_canonical_term_key(a.terms)[0] for a in term_atoms}
    qty_intervals: Dict[tuple, list] = {}
    for atom in measure_atoms:
        qty_intervals.setdefault(atom.qty, []).extend(atom.intervals)
    n = len(canonical_keys)
    for qty, intervals in qty_intervals.items():
        n += len(decompose(intervals))
    return n


def bool_nodes(node: Bool) -> int:
    """Node count of a formula AST (COMPILE(F) = nodes(F) in the pinned
    BOOLISA_v1 cost macros, spec section 8)."""
    if isinstance(node, (TOP, BOTTOM, TermAtom, MeasureAtom, UnknownAtom)):
        return 1
    if isinstance(node, Not):
        return 1 + bool_nodes(node.child)
    if isinstance(node, (And, Or)):
        return 1 + sum(bool_nodes(c) for c in node.children)
    raise TypeError(f"unrecognized Bool node {node!r}")  # pragma: no cover


class Compiled:
    def __init__(self, n, term_var_index, negated_of, qty_var_groups, qty_indicators, gamma):
        self.n = n
        self.term_var_index = term_var_index
        self.negated_of = negated_of
        self.qty_var_groups = qty_var_groups
        self.qty_indicators = qty_indicators
        self.gamma = gamma

    def _var_bitset(self, index: int) -> Bitset:
        bs = Bitset.zero(self.n)
        for a in range(bs.size):
            if (a >> index) & 1:
                bs.words |= 1 << a
        bs.words &= bs.mask
        return bs

    def compile(self, node: Bool) -> Bitset:
        if isinstance(node, TOP):
            return Bitset.full(self.n)
        if isinstance(node, BOTTOM):
            return Bitset.zero(self.n)
        if isinstance(node, TermAtom):
            key, base_neg = _canonical_term_key(node.terms)
            idx = self.term_var_index[key]
            negate = base_neg ^ (node.pol == 1)
            v = self._var_bitset(idx)
            return v.op_not() if negate else v
        if isinstance(node, MeasureAtom):
            var_indices = self.qty_var_groups[node.qty]
            indicators = self.qty_indicators[node.qty]
            covered = indicator_bitmask_for_intervals(node.intervals, indicators)
            bs = Bitset.zero(self.n)
            for local_i, global_i in enumerate(var_indices):
                if (covered >> local_i) & 1:
                    bs = bs.op_or(self._var_bitset(global_i))
            return bs
        if isinstance(node, UnknownAtom):
            raise Uncompilable(node.cause)
        if isinstance(node, Not):
            return self.compile(node.child).op_not()
        if isinstance(node, And):
            result = Bitset.full(self.n)
            for c in node.children:
                result = result.op_and(self.compile(c))
            return result
        if isinstance(node, Or):
            result = Bitset.zero(self.n)
            for c in node.children:
                result = result.op_or(self.compile(c))
            return result
        raise TypeError(f"unrecognized Bool node {node!r}")  # pragma: no cover


class Uncompilable(Exception):
    def __init__(self, cause: str):
        super().__init__(cause)
        self.cause = cause


def _contains_unknown(node: Bool) -> Optional[str]:
    if isinstance(node, UnknownAtom):
        return node.cause
    if isinstance(node, Not):
        return _contains_unknown(node.child)
    if isinstance(node, (And, Or)):
        causes = [c for c in (_contains_unknown(x) for x in node.children) if c]
        if causes:
            from reference.primitives import worst_cause

            return worst_cause(causes)
        return None
    return None


def uncompilable(node: Bool) -> bool:
    return _contains_unknown(node) is not None


def cause(node: Bool) -> Optional[str]:
    return _contains_unknown(node)


# --------------------------------------------------------------------------
# 4.2 Queries
# --------------------------------------------------------------------------

def SAT(compiled: Compiled, F: Bool) -> bool:
    fb = compiled.compile(F)
    return fb.op_and(compiled.gamma).is_nonzero()


def UNSAT(compiled: Compiled, F: Bool) -> bool:
    return not SAT(compiled, F)


def EQUIV(compiled: Compiled, F: Bool, H: Bool) -> bool:
    fb = compiled.compile(F)
    hb = compiled.compile(H)
    return fb.op_xor(hb).op_and(compiled.gamma).is_zero()


def NEGATE(compiled: Compiled, F: Bool) -> Bitset:
    return compiled.compile(F).op_not()


def _term_atoms_of(node: Bool, out: list):
    if isinstance(node, TermAtom):
        out.append(node)
    elif isinstance(node, Not):
        _term_atoms_of(node.child, out)
    elif isinstance(node, (And, Or)):
        for c in node.children:
            _term_atoms_of(c, out)


def ENTAILS(compiled: Compiled, F: Bool, H: Bool) -> str:
    """YES|NO. STRUCTURAL PRE-CHECK, GENERALIZED at e9 (draft 5.2, spec
    4.2, normative): collect the TermAtoms of F and H. An atom pairing
    (same variable) with mismatched restrictive flags provides NO
    entailment, in EITHER direction. If ANY H TermAtom -- grant or
    restrictive -- has no flag-matching F counterpart on a variable that
    F constrains, return NO. Consequences: "if verified" never entails
    "only if verified" and vice versa; a restrictive-only F never entails
    AND(grant_atom, restrictive_atom) (the grant atom lacks flag-matching
    evidence). Variables F does NOT constrain carry no structural
    verdict (so BOTTOM still entails everything semantically).
    """
    f_atoms: list = []
    h_atoms: list = []
    _term_atoms_of(F, f_atoms)
    _term_atoms_of(H, h_atoms)

    f_by_var: Dict[int, set] = {}
    for a in f_atoms:
        key, _ = _canonical_term_key(a.terms)
        idx = compiled.term_var_index.get(key)
        if idx is not None:
            f_by_var.setdefault(idx, set()).add(a.restrictive)

    for a in h_atoms:
        key, _ = _canonical_term_key(a.terms)
        idx = compiled.term_var_index.get(key)
        if idx is None:
            continue
        flags_on_f = f_by_var.get(idx)
        if flags_on_f is None:
            # F does not constrain this variable: no structural verdict.
            continue
        if a.restrictive not in flags_on_f:
            return "NO"

    fb = compiled.compile(F)
    hn = NEGATE(compiled, H)
    return "YES" if fb.op_and(hn).op_and(compiled.gamma).is_zero() else "NO"


def DOMAIN(compiled_or_none, D1: Bool, D2: Bool) -> str:
    """UNKNOWN (uncompilable) | DISJOINT (UNSAT either or !SAT(D1&D2)) |
    OVERLAP."""
    if uncompilable(D1) or uncompilable(D2):
        return "UNKNOWN"
    compiled = compiled_or_none or build_varmap([D1, D2])
    if UNSAT(compiled, D1) or UNSAT(compiled, D2):
        return "DISJOINT"
    if not SAT(compiled, And((D1, D2))):
        return "DISJOINT"
    return "OVERLAP"


def IMPLIES(compiled, a: Bool, b: Bool) -> str:
    """UNKNOWN | YES iff ENTAILS(a,b) | NO."""
    if uncompilable(a) or uncompilable(b):
        return "UNKNOWN"
    c = compiled or build_varmap([a, b])
    return "YES" if ENTAILS(c, a, b) == "YES" else "NO"
