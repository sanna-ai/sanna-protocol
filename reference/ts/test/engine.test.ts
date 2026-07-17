// Unit tests for src/engine.ts (SAN-880, mirrors tests/reference/
// test_engine.py from the Python reference, SAN-879): bitset width
// masking (NOT on n=0..3), varmap preflight, elementary intervals
// (open/closed bounds), GAMMA exactly-one, ENTAILS incl. (A AND B) OR
// (A AND C) entails A, OR never entails a leaf, and the restrictive-flag
// structural NO both directions.

import assert from "node:assert/strict";
import { test } from "node:test";
import { FSet } from "../src/fset.js";
import { T } from "../src/tables.js";
import {
  Bitset,
  DOMAIN,
  ENTAILS,
  EQUIV,
  EnvelopeExceeded,
  SAT,
  UNSAT,
  buildExactlyOneGroup,
  buildGamma,
  buildVarmap,
  decompose,
} from "../src/engine.js";
import { BOTTOM_, Dec, Interval, MeasureQty, TOP_, mkAnd, mkMeasureAtom, mkNot, mkOr, mkTermAtom } from "../src/primitives.js";

// ---------------------------------------------------------------------
// Bitset width masking
// ---------------------------------------------------------------------

for (const n of [0, 1, 2, 3]) {
  test(`test_bitset_width_exactly_2_pow_n_bits[${n}]`, () => {
    const bs = new Bitset(n, -1n); // attempt to set every bit including padding
    assert.equal(bs.size, 2 ** n);
    assert.equal(bs.words, (1n << BigInt(2 ** n)) - 1n); // padding above 2^n masked off
  });
}

for (const n of [0, 1, 2, 3]) {
  test(`test_bitset_not_is_width_masked[${n}]`, () => {
    const full = new Bitset(n, -1n);
    const empty = full.opNot();
    assert.equal(empty.words, 0n);
    // double negation returns to full, never leaking padding bits
    assert.equal(empty.opNot().words, full.words);
  });
}

test("test_bitset_zero_and_full_helpers", () => {
  assert.equal(Bitset.zero(3).words, 0n);
  assert.equal(Bitset.full(3).words, new Bitset(3, -1n).words);
});

test("test_bitset_width_mismatch_raises", () => {
  const a = new Bitset(2, 0n);
  const b = new Bitset(3, 0n);
  assert.throws(() => a.opAnd(b), RangeError);
});

// ---------------------------------------------------------------------
// varmap preflight (MAX_BOOL_ATOMS)
// ---------------------------------------------------------------------

test("test_varmap_preflight_rejects_too_many_atoms", () => {
  const atoms = Array.from({ length: T.MAX_BOOL_ATOMS + 1 }, (_, i) => mkTermAtom(FSet.of([`t${i}`]), 0, 0));
  const formula = mkAnd(atoms);
  assert.throws(() => buildVarmap([formula]), EnvelopeExceeded);
});

test("test_varmap_at_cap_succeeds", () => {
  const atoms = Array.from({ length: T.MAX_BOOL_ATOMS }, (_, i) => mkTermAtom(FSet.of([`t${i}`]), 0, 0));
  const formula = mkAnd(atoms);
  const compiled = buildVarmap([formula]);
  assert.equal(compiled.n, T.MAX_BOOL_ATOMS);
});

test("test_varmap_complement_pair_collapses_to_one_variable", () => {
  // e9 (spec 4.2): COMPLEMENT_v1 pair lookup operates on the SAME
  // normalized form as Bool atoms (post-stem, post-CONCEPT_v1), so the
  // ('verified', 'unverified') table pair matches atoms carrying
  // 'verification' (the CONCEPT_v1 image of 'verified') and 'unverified'.
  const verified = mkTermAtom(FSet.of(["verification"]), 0, 0);
  const unverified = mkTermAtom(FSet.of(["unverified"]), 0, 0);
  const compiled = buildVarmap([verified, unverified]);
  assert.equal(compiled.n, 1);
  // unverified is the negated side: never both satisfiable simultaneously
  assert.equal(SAT(compiled, mkAnd([verified, unverified])), false);
  assert.equal(SAT(compiled, mkOr([verified, unverified])), true);
});

test("test_varmap_complement_or_is_tautology", () => {
  const verified = mkTermAtom(FSet.of(["verification"]), 0, 0);
  const unverified = mkTermAtom(FSet.of(["unverified"]), 0, 0);
  const compiled = buildVarmap([verified, unverified]);
  assert.equal(EQUIV(compiled, mkOr([verified, unverified]), TOP_), true);
});

test("test_varmap_raw_unnormalized_word_does_not_complement_fold", () => {
  // a term carrying the RAW table word 'verified' (which real Bool atoms
  // never carry post-CONCEPT_v1) matches neither normalized side -- the
  // e9 normalization is exact, not fuzzy
  const rawVerified = mkTermAtom(FSet.of(["verified"]), 0, 0);
  const unverified = mkTermAtom(FSet.of(["unverified"]), 0, 0);
  const compiled = buildVarmap([rawVerified, unverified]);
  assert.equal(compiled.n, 2);
});

test("test_varmap_same_terms_opposite_polarity_collapses_to_one_variable", () => {
  const pos = mkTermAtom(FSet.of(["eligible"]), 0, 0);
  const neg = mkTermAtom(FSet.of(["eligible"]), 1, 0);
  const compiled = buildVarmap([pos, neg]);
  assert.equal(compiled.n, 1);
  assert.equal(SAT(compiled, mkAnd([pos, neg])), false);
});

// ---------------------------------------------------------------------
// decompose: elementary intervals (open/closed bounds)
// ---------------------------------------------------------------------

function dec(coefficient: bigint, scale: number): Dec {
  return { coefficient, scale };
}

test("test_decompose_single_closed_bound_yields_5_indicators", () => {
  const ivs: Interval[] = [{ lo: dec(0n, 0), loOpen: false, hi: dec(10n, 0), hiOpen: true, unit: "u" }];
  const indicators = decompose(ivs);
  // 1 finite-endpoint-pair (0, 10) -> k=2 unique endpoints -> 2k+1 = 5
  assert.equal(indicators.length, 5);
});

test("test_decompose_no_finite_bound_yields_one_indicator", () => {
  const ivs: Interval[] = [{ lo: null, loOpen: true, hi: null, hiOpen: true, unit: "u" }];
  const indicators = decompose(ivs);
  assert.deepEqual(indicators, [{ lo: null, loOpen: true, hi: null, hiOpen: true }]);
});

test("test_decompose_indicators_ordered_lo_to_hi", () => {
  const ivs: Interval[] = [{ lo: dec(5n, 0), loOpen: false, hi: dec(5n, 0), hiOpen: false, unit: "u" }]; // point [5,5]
  const indicators = decompose(ivs);
  // single endpoint e=5 -> (-inf,5), [5,5], (5,+inf) => 3 indicators
  assert.equal(indicators.length, 3);
  assert.deepEqual(indicators[1], { lo: dec(5n, 0), loOpen: false, hi: dec(5n, 0), hiOpen: false });
});

// ---------------------------------------------------------------------
// GAMMA exactly-one
// ---------------------------------------------------------------------

test("test_build_exactly_one_group_two_vars", () => {
  const bs = buildExactlyOneGroup(2, [0, 1]);
  // assignments where exactly one of bit0/bit1 is set: 0b01 and 0b10
  const satisfying: number[] = [];
  for (let a = 0; a < 4; a++) {
    if ((bs.words >> BigInt(a)) & 1n) satisfying.push(a);
  }
  assert.deepEqual(satisfying, [1, 2]);
});

test("test_build_gamma_zero_quantities_is_top", () => {
  const gamma = buildGamma(2, []);
  assert.equal(gamma.words, Bitset.full(2).words);
});

test("test_build_gamma_single_quantity_restricts_to_exactly_one", () => {
  const gamma = buildGamma(2, [[0, 1]]);
  const satisfying: number[] = [];
  for (let a = 0; a < 4; a++) {
    if ((gamma.words >> BigInt(a)) & 1n) satisfying.push(a);
  }
  assert.deepEqual(satisfying, [1, 2]);
});

test("test_measure_atom_sat_respects_gamma_exactly_one", () => {
  const ivsA: Interval[] = [{ lo: null, loOpen: true, hi: dec(5n, 0), hiOpen: true, unit: "u" }]; // (-inf, 5)
  const ivsB: Interval[] = [{ lo: dec(5n, 0), loOpen: true, hi: null, hiOpen: true, unit: "u" }]; // (5, +inf)
  const qty: MeasureQty = ["facet:x", FSet.of(["s"]), "u"];
  const atomA = mkMeasureAtom(qty, ivsA);
  const atomB = mkMeasureAtom(qty, ivsB);
  const compiled = buildVarmap([atomA, atomB]);
  // disjoint elementary-interval indicators of the SAME quantity can
  // never both be true under an exactly-one GAMMA
  assert.equal(SAT(compiled, mkAnd([atomA, atomB])), false);
});

// ---------------------------------------------------------------------
// ENTAILS
// ---------------------------------------------------------------------

test("test_entails_and_or_and_entails_leaf", () => {
  // (A AND B) OR (A AND C) entails A
  const A = mkTermAtom(FSet.of(["a"]), 0, 0);
  const B = mkTermAtom(FSet.of(["b"]), 0, 0);
  const C = mkTermAtom(FSet.of(["c"]), 0, 0);
  const f = mkOr([mkAnd([A, B]), mkAnd([A, C])]);
  const compiled = buildVarmap([f, A]);
  assert.equal(ENTAILS(compiled, f, A), "YES");
});

test("test_entails_or_never_entails_a_leaf", () => {
  const A = mkTermAtom(FSet.of(["a"]), 0, 0);
  const B = mkTermAtom(FSet.of(["b"]), 0, 0);
  const f = mkOr([A, B]);
  const compiled = buildVarmap([f, A]);
  assert.equal(ENTAILS(compiled, f, A), "NO");
});

test("test_entails_leaf_entails_the_or_containing_it", () => {
  const A = mkTermAtom(FSet.of(["a"]), 0, 0);
  const B = mkTermAtom(FSet.of(["b"]), 0, 0);
  const f = mkOr([A, B]);
  const compiled = buildVarmap([f, A]);
  assert.equal(ENTAILS(compiled, A, f), "YES");
});

test("test_entails_restrictive_flag_structural_no_forward", () => {
  // "if verified" (restrictive=0) never entails "only if verified"
  // (restrictive=1) -- draft 5 item 2.
  const ifVerified = mkTermAtom(FSet.of(["verification"]), 0, 0);
  const onlyIfVerified = mkTermAtom(FSet.of(["verification"]), 0, 1);
  const compiled = buildVarmap([ifVerified, onlyIfVerified]);
  assert.equal(ENTAILS(compiled, ifVerified, onlyIfVerified), "NO");
});

test("test_entails_restrictive_flag_structural_no_reverse", () => {
  // e9 (spec 4.2, normative): an atom pairing with mismatched restrictive
  // flags provides no entailment in EITHER direction.
  const ifVerified = mkTermAtom(FSet.of(["verification"]), 0, 0);
  const onlyIfVerified = mkTermAtom(FSet.of(["verification"]), 0, 1);
  const compiled = buildVarmap([ifVerified, onlyIfVerified]);
  assert.equal(ENTAILS(compiled, onlyIfVerified, ifVerified), "NO");
});

test("test_entails_restrictive_only_f_never_entails_mixed_and", () => {
  // e9 flagship consequence: ENTAILS(A_restrictive,
  // AND(A_grant, A_restrictive)) == NO -- the grant atom lacks
  // flag-matching evidence even though both atoms share one variable.
  const aGrant = mkTermAtom(FSet.of(["verification"]), 0, 0);
  const aRestrictive = mkTermAtom(FSet.of(["verification"]), 0, 1);
  const compiled = buildVarmap([aGrant, aRestrictive]);
  assert.equal(ENTAILS(compiled, aRestrictive, mkAnd([aGrant, aRestrictive])), "NO");
  // per-atom flag matching in the other direction is fine
  assert.equal(ENTAILS(compiled, mkAnd([aGrant, aRestrictive]), aRestrictive), "YES");
});

test("test_entails_structural_check_scoped_to_f_constrained_variables", () => {
  // e9 scopes the missing-counterpart rule to "a variable that F
  // constrains": BOTTOM constrains nothing, so it still entails a
  // restrictive atom semantically.
  const aRestrictive = mkTermAtom(FSet.of(["verification"]), 0, 1);
  const compiled = buildVarmap([BOTTOM_, aRestrictive]);
  assert.equal(ENTAILS(compiled, BOTTOM_, aRestrictive), "YES");
});

test("test_entails_matching_restrictive_flags_succeeds", () => {
  const onlyIfVerified = mkTermAtom(FSet.of(["verification"]), 0, 1);
  const compiled = buildVarmap([onlyIfVerified]);
  assert.equal(ENTAILS(compiled, onlyIfVerified, onlyIfVerified), "YES");
});

test("test_entails_top_never_entails_bottom", () => {
  const compiled = buildVarmap([TOP_, BOTTOM_]);
  assert.equal(ENTAILS(compiled, TOP_, BOTTOM_), "NO");
});

test("test_entails_bottom_entails_anything", () => {
  const A = mkTermAtom(FSet.of(["a"]), 0, 0);
  const compiled = buildVarmap([BOTTOM_, A]);
  assert.equal(ENTAILS(compiled, BOTTOM_, A), "YES");
});

// ---------------------------------------------------------------------
// SAT / UNSAT / EQUIV / DOMAIN
// ---------------------------------------------------------------------

test("test_sat_top_is_satisfiable", () => {
  const compiled = buildVarmap([TOP_]);
  assert.equal(SAT(compiled, TOP_), true);
  assert.equal(UNSAT(compiled, BOTTOM_), true);
});

test("test_equiv_double_negation", () => {
  const A = mkTermAtom(FSet.of(["a"]), 0, 0);
  const compiled = buildVarmap([A]);
  assert.equal(EQUIV(compiled, A, mkNot(mkNot(A))), true);
});

test("test_domain_top_top_is_overlap", () => {
  assert.equal(DOMAIN(null, TOP_, TOP_), "OVERLAP");
});

test("test_domain_contradiction_is_disjoint", () => {
  const A = mkTermAtom(FSet.of(["a"]), 0, 0);
  assert.equal(DOMAIN(null, A, mkNot(A)), "DISJOINT");
});
