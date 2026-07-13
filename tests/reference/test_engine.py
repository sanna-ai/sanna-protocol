"""Unit tests for reference/engine.py (SAN-879): bitset width masking (NOT
on n=0..3), varmap preflight, elementary intervals (open/closed bounds),
GAMMA exactly-one, ENTAILS incl. (A AND B) OR (A AND C) entails A, OR
never entails a leaf, and the restrictive-flag structural NO both
directions.
"""

import pytest

from reference.engine import (
    Bitset,
    EnvelopeExceeded,
    SAT,
    UNSAT,
    ENTAILS,
    EQUIV,
    DOMAIN,
    build_exactly_one_group,
    build_gamma,
    build_varmap,
    decompose,
)
from reference.primitives import (
    And,
    BOTTOM_,
    Dec,
    Interval,
    MeasureAtom,
    Not,
    Or,
    TOP_,
    TermAtom,
)
from reference.tables import T


# ---------------------------------------------------------------------
# Bitset width masking
# ---------------------------------------------------------------------

@pytest.mark.parametrize("n", [0, 1, 2, 3])
def test_bitset_width_exactly_2_pow_n_bits(n):
    bs = Bitset(n, -1)  # attempt to set every bit including padding
    assert bs.size == 2 ** n
    assert bs.words == (1 << (2 ** n)) - 1  # padding above 2^n masked off


@pytest.mark.parametrize("n", [0, 1, 2, 3])
def test_bitset_not_is_width_masked(n):
    full = Bitset(n, -1)
    empty = full.op_not()
    assert empty.words == 0
    # double negation returns to full, never leaking padding bits
    assert empty.op_not().words == full.words


def test_bitset_zero_and_full_helpers():
    assert Bitset.zero(3).words == 0
    assert Bitset.full(3).words == Bitset(3, -1).words


def test_bitset_width_mismatch_raises():
    a = Bitset(2, 0)
    b = Bitset(3, 0)
    with pytest.raises(ValueError):
        a.op_and(b)


# ---------------------------------------------------------------------
# varmap preflight (MAX_BOOL_ATOMS)
# ---------------------------------------------------------------------

def test_varmap_preflight_rejects_too_many_atoms():
    atoms = [TermAtom(frozenset({f"t{i}"}), 0, 0) for i in range(T.MAX_BOOL_ATOMS + 1)]
    formula = And(tuple(atoms))
    with pytest.raises(EnvelopeExceeded):
        build_varmap([formula])


def test_varmap_at_cap_succeeds():
    atoms = [TermAtom(frozenset({f"t{i}"}), 0, 0) for i in range(T.MAX_BOOL_ATOMS)]
    formula = And(tuple(atoms))
    compiled = build_varmap([formula])
    assert compiled.n == T.MAX_BOOL_ATOMS


def test_varmap_complement_pair_collapses_to_one_variable():
    # e9 (spec 4.2): COMPLEMENT_v1 pair lookup operates on the SAME
    # normalized form as Bool atoms (post-stem, post-CONCEPT_v1), so the
    # ('verified', 'unverified') table pair matches atoms carrying
    # 'verification' (the CONCEPT_v1 image of 'verified') and
    # 'unverified' (no CONCEPT_v1 entry; identity).
    verified = TermAtom(frozenset({"verification"}), 0, 0)
    unverified = TermAtom(frozenset({"unverified"}), 0, 0)
    compiled = build_varmap([verified, unverified])
    assert compiled.n == 1
    # unverified is the negated side: verified and unverified must never
    # both be satisfiable simultaneously (they're logical complements)
    assert not SAT(compiled, And((verified, unverified)))
    assert SAT(compiled, Or((verified, unverified)))


def test_varmap_complement_or_is_tautology():
    # the mechanism behind the complement-tautology oracle: OR over a
    # complement pair is engine-TOP-equivalent
    verified = TermAtom(frozenset({"verification"}), 0, 0)
    unverified = TermAtom(frozenset({"unverified"}), 0, 0)
    compiled = build_varmap([verified, unverified])
    assert EQUIV(compiled, Or((verified, unverified)), TOP_)


def test_varmap_raw_unnormalized_word_does_not_complement_fold():
    # a term carrying the RAW table word 'verified' (which real Bool
    # atoms never carry post-CONCEPT_v1) matches neither normalized side
    # -- the e9 normalization is exact, not fuzzy
    raw_verified = TermAtom(frozenset({"verified"}), 0, 0)
    unverified = TermAtom(frozenset({"unverified"}), 0, 0)
    compiled = build_varmap([raw_verified, unverified])
    assert compiled.n == 2


def test_varmap_same_terms_opposite_polarity_collapses_to_one_variable():
    pos = TermAtom(frozenset({"eligible"}), 0, 0)
    neg = TermAtom(frozenset({"eligible"}), 1, 0)
    compiled = build_varmap([pos, neg])
    assert compiled.n == 1
    assert not SAT(compiled, And((pos, neg)))


# ---------------------------------------------------------------------
# decompose: elementary intervals (open/closed bounds)
# ---------------------------------------------------------------------

def test_decompose_single_closed_bound_yields_5_indicators():
    ivs = [Interval(Dec(0, 0), False, Dec(10, 0), True, "u")]
    indicators = decompose(ivs)
    # 1 finite-endpoint-pair (0, 10) -> k=2 unique endpoints -> 2k+1 = 5
    assert len(indicators) == 5


def test_decompose_no_finite_bound_yields_one_indicator():
    ivs = [Interval(None, True, None, True, "u")]
    indicators = decompose(ivs)
    assert indicators == [(None, True, None, True)]


def test_decompose_indicators_ordered_lo_to_hi():
    ivs = [Interval(Dec(5, 0), False, Dec(5, 0), False, "u")]  # point [5,5]
    indicators = decompose(ivs)
    # single endpoint e=5 -> (-inf,5), [5,5], (5,+inf) => 3 indicators
    assert len(indicators) == 3
    assert indicators[1] == (Dec(5, 0), False, Dec(5, 0), False)


# ---------------------------------------------------------------------
# GAMMA exactly-one
# ---------------------------------------------------------------------

def test_build_exactly_one_group_two_vars():
    bs = build_exactly_one_group(2, [0, 1])
    # assignments where exactly one of bit0/bit1 is set: 0b01 and 0b10
    satisfying = [a for a in range(4) if (bs.words >> a) & 1]
    assert satisfying == [1, 2]


def test_build_gamma_zero_quantities_is_top():
    gamma = build_gamma(2, [])
    assert gamma.words == Bitset.full(2).words


def test_build_gamma_single_quantity_restricts_to_exactly_one():
    gamma = build_gamma(2, [[0, 1]])
    satisfying = [a for a in range(4) if (gamma.words >> a) & 1]
    assert satisfying == [1, 2]


def test_measure_atom_sat_respects_gamma_exactly_one():
    ivs_a = (Interval(None, True, Dec(5, 0), True, "u"),)  # (-inf, 5)
    ivs_b = (Interval(Dec(5, 0), True, None, True, "u"),)  # (5, +inf)
    qty = ("facet:x", frozenset({"s"}), "u")
    atom_a = MeasureAtom(qty, ivs_a)
    atom_b = MeasureAtom(qty, ivs_b)
    compiled = build_varmap([atom_a, atom_b])
    # disjoint elementary-interval indicators of the SAME quantity can
    # never both be true under an exactly-one GAMMA
    assert not SAT(compiled, And((atom_a, atom_b)))


# ---------------------------------------------------------------------
# ENTAILS
# ---------------------------------------------------------------------

def test_entails_and_or_and_entails_leaf():
    # (A AND B) OR (A AND C) entails A
    A = TermAtom(frozenset({"a"}), 0, 0)
    B = TermAtom(frozenset({"b"}), 0, 0)
    C = TermAtom(frozenset({"c"}), 0, 0)
    f = Or((And((A, B)), And((A, C))))
    compiled = build_varmap([f, A])
    assert ENTAILS(compiled, f, A) == "YES"


def test_entails_or_never_entails_a_leaf():
    A = TermAtom(frozenset({"a"}), 0, 0)
    B = TermAtom(frozenset({"b"}), 0, 0)
    f = Or((A, B))
    compiled = build_varmap([f, A])
    assert ENTAILS(compiled, f, A) == "NO"


def test_entails_leaf_entails_the_or_containing_it():
    A = TermAtom(frozenset({"a"}), 0, 0)
    B = TermAtom(frozenset({"b"}), 0, 0)
    f = Or((A, B))
    compiled = build_varmap([f, A])
    assert ENTAILS(compiled, A, f) == "YES"


def test_entails_restrictive_flag_structural_no_forward():
    # "if verified" (restrictive=0) never entails "only if verified"
    # (restrictive=1) -- draft 5 item 2.
    if_verified = TermAtom(frozenset({"verification"}), 0, 0)
    only_if_verified = TermAtom(frozenset({"verification"}), 0, 1)
    compiled = build_varmap([if_verified, only_if_verified])
    assert ENTAILS(compiled, if_verified, only_if_verified) == "NO"


def test_entails_restrictive_flag_structural_no_reverse():
    # e9 (spec 4.2, normative in draft 5.2): an atom pairing with
    # mismatched restrictive flags provides no entailment in EITHER
    # direction -- "only if verified" never entails "if verified".
    if_verified = TermAtom(frozenset({"verification"}), 0, 0)
    only_if_verified = TermAtom(frozenset({"verification"}), 0, 1)
    compiled = build_varmap([if_verified, only_if_verified])
    assert ENTAILS(compiled, only_if_verified, if_verified) == "NO"


def test_entails_restrictive_only_f_never_entails_mixed_and():
    # e9 flagship consequence: ENTAILS(A_restrictive,
    # AND(A_grant, A_restrictive)) == NO -- the grant atom lacks
    # flag-matching evidence even though both atoms share one variable.
    a_grant = TermAtom(frozenset({"verification"}), 0, 0)
    a_restrictive = TermAtom(frozenset({"verification"}), 0, 1)
    compiled = build_varmap([a_grant, a_restrictive])
    assert ENTAILS(compiled, a_restrictive, And((a_grant, a_restrictive))) == "NO"
    # per-atom flag matching in the other direction is fine
    assert ENTAILS(compiled, And((a_grant, a_restrictive)), a_restrictive) == "YES"


def test_entails_structural_check_scoped_to_f_constrained_variables():
    # e9 scopes the missing-counterpart rule to "a variable that F
    # constrains": BOTTOM constrains nothing, so it still entails a
    # restrictive atom semantically.
    a_restrictive = TermAtom(frozenset({"verification"}), 0, 1)
    compiled = build_varmap([BOTTOM_, a_restrictive])
    assert ENTAILS(compiled, BOTTOM_, a_restrictive) == "YES"


def test_entails_matching_restrictive_flags_succeeds():
    only_if_verified = TermAtom(frozenset({"verification"}), 0, 1)
    compiled = build_varmap([only_if_verified])
    assert ENTAILS(compiled, only_if_verified, only_if_verified) == "YES"


def test_entails_top_never_entails_bottom():
    compiled = build_varmap([TOP_, BOTTOM_])
    assert ENTAILS(compiled, TOP_, BOTTOM_) == "NO"


def test_entails_bottom_entails_anything():
    A = TermAtom(frozenset({"a"}), 0, 0)
    compiled = build_varmap([BOTTOM_, A])
    assert ENTAILS(compiled, BOTTOM_, A) == "YES"


# ---------------------------------------------------------------------
# SAT / UNSAT / EQUIV / DOMAIN
# ---------------------------------------------------------------------

def test_sat_top_is_satisfiable():
    compiled = build_varmap([TOP_])
    assert SAT(compiled, TOP_) is True
    assert UNSAT(compiled, BOTTOM_) is True


def test_equiv_double_negation():
    A = TermAtom(frozenset({"a"}), 0, 0)
    compiled = build_varmap([A])
    assert EQUIV(compiled, A, Not(Not(A))) is True


def test_domain_top_top_is_overlap():
    assert DOMAIN(None, TOP_, TOP_) == "OVERLAP"


def test_domain_contradiction_is_disjoint():
    A = TermAtom(frozenset({"a"}), 0, 0)
    assert DOMAIN(None, A, Not(A)) == "DISJOINT"
