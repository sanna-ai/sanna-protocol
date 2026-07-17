// Unit tests for src/relations.ts (SAN-880, mirrors tests/reference/
// test_relations.py from the Python reference, SAN-879): identity_relation
// three arms (incl. the employees/contractors UNDECIDABLE vector), EXCL
// pairs, existential cross-frame abstention, meet, dispositions.

import assert from "node:assert/strict";
import { test } from "node:test";
import { FSet, ModPair, ModSet } from "../src/fset.js";
import {
  EXISTENTIAL,
  Extent,
  Interval,
  NEG,
  POS,
  TOP_,
  UNIVERSAL,
  UNSPECIFIED,
} from "../src/primitives.js";
import {
  COMPARABLE,
  CONFLICT,
  INERT,
  MATCH,
  disposition,
  generalizes,
  identityRelation,
  meet,
  relCause,
  relIsUndecidable,
  twoWayGeneralizes,
} from "../src/relations.js";

function extentFactory(
  opts: {
    facet?: string;
    subject?: Iterable<string>;
    obj?: Iterable<string>;
    modifiers?: Iterable<ModPair>;
    quant?: 0 | 1 | 2;
    polarity?: 0 | 1;
    values?: readonly Interval[] | null;
  } = {},
): Extent {
  return {
    facet: opts.facet ?? "facet:refund_availability",
    subject: FSet.of(opts.subject ?? ["refund"]),
    object: FSet.of(opts.obj ?? []),
    modifiers: ModSet.of(opts.modifiers ?? []),
    quant: opts.quant ?? UNSPECIFIED,
    polarity: opts.polarity ?? POS,
    values: opts.values ?? null,
  };
}

function mod(rel: string, ...objTerms: string[]): ModPair {
  return { rel, objset: FSet.of(objTerms) };
}

interface DummyFrame {
  readonly extent: Extent;
}

function frame(extent: Extent): DummyFrame {
  return { extent };
}

// ---------------------------------------------------------------------
// identity_relation: TOTAL, three arms
// ---------------------------------------------------------------------

test("test_identity_relation_comparable_when_generalizes_and_domain_overlap", () => {
  const A = extentFactory();
  const B = extentFactory();
  assert.equal(identityRelation(A, TOP_, B, TOP_, false), COMPARABLE);
});

test("test_identity_relation_inert_when_neither_generalizes", () => {
  const A = extentFactory({ facet: "facet:refund_availability" });
  const B = extentFactory({ facet: "facet:access_permission" });
  assert.equal(identityRelation(A, TOP_, B, TOP_, false), INERT);
});

test("test_identity_relation_undecidable_employees_contractors_vector", () => {
  // "Refunds for employees are refundable." vs "Refunds for
  // contractors are nonrefundable." -- required tri-state fixture.
  const employees = extentFactory({ modifiers: [mod("for", "employee")] });
  const contractors = extentFactory({ modifiers: [mod("for", "contractor")], polarity: NEG });
  const r = identityRelation(employees, TOP_, contractors, TOP_, false);
  assert.ok(relIsUndecidable(r));
  assert.equal(relCause(r), "condition_undecidable");
});

test("test_identity_relation_never_read_as_boolean", () => {
  // a Rel3 result must be one of exactly three distinguishable shapes;
  // this documents/enforces that UNDECIDABLE is never accidentally equal
  // to a bare string a caller might loosely-compare against.
  const A = extentFactory({ modifiers: [mod("for", "employee")] });
  const B = extentFactory({ modifiers: [mod("for", "contractor")] });
  const r = identityRelation(A, TOP_, B, TOP_, false);
  assert.notEqual(r, COMPARABLE);
  assert.notEqual(r, INERT);
  assert.ok(relIsUndecidable(r));
});

// ---------------------------------------------------------------------
// EXCL_v1 pairs
// ---------------------------------------------------------------------

test("test_generalizes_excl_pair_modifiers_is_no", () => {
  const digital = extentFactory({ facet: "facet:access_permission", obj: ["system"], modifiers: [mod("to", "digital")] });
  const physical = extentFactory({ facet: "facet:access_permission", obj: ["system"], modifiers: [mod("to", "physical")] });
  assert.deepEqual(generalizes(digital, physical, false), ["NO", null]);
});

test("test_generalizes_no_same_rel_match_is_no", () => {
  const a = extentFactory({ modifiers: [mod("for", "employee")] });
  const b = extentFactory({ modifiers: [] });
  assert.deepEqual(generalizes(a, b, false), ["NO", null]);
});

// ---------------------------------------------------------------------
// existential cross-frame abstention
// ---------------------------------------------------------------------

test("test_generalizes_existential_cross_frame_is_undecidable", () => {
  const a = extentFactory({ quant: EXISTENTIAL });
  const b = extentFactory({ quant: UNIVERSAL });
  assert.deepEqual(generalizes(a, b, false), ["UNKNOWN", "condition_undecidable"]);
});

test("test_generalizes_existential_same_frame_is_yes", () => {
  const a = extentFactory({ quant: EXISTENTIAL });
  const b = extentFactory({ quant: UNIVERSAL });
  assert.deepEqual(generalizes(a, b, true), ["YES", null]);
});

// ---------------------------------------------------------------------
// two_way_generalizes
// ---------------------------------------------------------------------

test("test_two_way_generalizes_yes_if_either_direction", () => {
  const a = extentFactory({ subject: ["refund"] });
  const b = extentFactory({ subject: ["refund", "extra"] });
  // a generalizes b (a.subject <= b.subject) -> YES
  assert.deepEqual(twoWayGeneralizes(a, b, false), ["YES", null]);
});

test("test_two_way_generalizes_no_if_both_no", () => {
  const a = extentFactory({ facet: "facet:refund_availability" });
  const b = extentFactory({ facet: "facet:access_permission" });
  const [g] = twoWayGeneralizes(a, b, false);
  assert.equal(g, "NO");
});

// ---------------------------------------------------------------------
// meet
// ---------------------------------------------------------------------

test("test_meet_unions_subject_and_object", () => {
  const a = extentFactory({ subject: ["refund"] });
  const b = extentFactory({ subject: ["refund", "premium"] });
  const m = meet(a, b);
  assert.deepEqual(m.subject.toArray().slice().sort(), ["premium", "refund"]);
});

test("test_meet_quant_existential_if_either_side_existential", () => {
  const a = extentFactory({ quant: EXISTENTIAL });
  const b = extentFactory({ quant: UNIVERSAL });
  const m = meet(a, b);
  assert.equal(m.quant, EXISTENTIAL);
});

test("test_meet_quant_universal_if_neither_existential", () => {
  const a = extentFactory({ quant: UNSPECIFIED });
  const b = extentFactory({ quant: UNIVERSAL });
  const m = meet(a, b);
  assert.equal(m.quant, UNIVERSAL);
});

// ---------------------------------------------------------------------
// disposition
// ---------------------------------------------------------------------

test("test_disposition_conflict_on_opposite_polarity_non_existential", () => {
  const a = frame(extentFactory({ facet: "facet:access_permission", obj: ["system"], polarity: POS }));
  const b = frame(extentFactory({ facet: "facet:access_permission", obj: ["system"], polarity: NEG }));
  assert.equal(disposition(a, b), CONFLICT);
});

test("test_disposition_match_on_same_polarity", () => {
  const a = frame(extentFactory({ facet: "facet:access_permission", obj: ["system"], polarity: POS }));
  const b = frame(extentFactory({ facet: "facet:access_permission", obj: ["system"], polarity: POS }));
  assert.equal(disposition(a, b), MATCH);
});

test("test_disposition_match_when_both_existential_despite_opposite_polarity", () => {
  const a = frame(extentFactory({ facet: "facet:access_permission", obj: ["system"], polarity: POS, quant: EXISTENTIAL }));
  const b = frame(extentFactory({ facet: "facet:access_permission", obj: ["system"], polarity: NEG, quant: EXISTENTIAL }));
  assert.equal(disposition(a, b), MATCH);
});

test("test_disposition_measure_conflict_on_disjoint_intervals", () => {
  const ivsA: Interval[] = [{ lo: null, loOpen: true, hi: { coefficient: 5n, scale: 0 }, hiOpen: true, unit: "u" }]; // (-inf, 5)
  const ivsB: Interval[] = [{ lo: { coefficient: 10n, scale: 0 }, loOpen: false, hi: { coefficient: 10n, scale: 0 }, hiOpen: false, unit: "u" }]; // [10,10]
  const a = frame(extentFactory({ facet: "facet:cost", values: ivsA }));
  const b = frame(extentFactory({ facet: "facet:cost", values: ivsB }));
  assert.equal(disposition(a, b), CONFLICT);
});

test("test_disposition_measure_match_on_overlapping_intervals", () => {
  const ivsA: Interval[] = [{ lo: null, loOpen: true, hi: { coefficient: 10n, scale: 0 }, hiOpen: false, unit: "u" }]; // (-inf, 10]
  const ivsB: Interval[] = [{ lo: { coefficient: 5n, scale: 0 }, loOpen: false, hi: { coefficient: 5n, scale: 0 }, hiOpen: false, unit: "u" }]; // [5,5]
  const a = frame(extentFactory({ facet: "facet:cost", values: ivsA }));
  const b = frame(extentFactory({ facet: "facet:cost", values: ivsB }));
  assert.equal(disposition(a, b), MATCH);
});

test("test_disposition_measure_cross_group_is_undecidable_malformed", () => {
  // spec 2.4: comparisons are legal only within one unit group and one
  // currency; cross-group -> UnknownAtom(malformed_mention) -> the
  // disposition is UNDECIDABLE with cause malformed_mention, never a
  // silent MATCH.
  const ivsA: Interval[] = [{ lo: { coefficient: 43200n, scale: 0 }, loOpen: false, hi: { coefficient: 43200n, scale: 0 }, hiOpen: false, unit: "time_a" }];
  const ivsB: Interval[] = [{ lo: { coefficient: 1n, scale: 0 }, loOpen: false, hi: { coefficient: 1n, scale: 0 }, hiOpen: false, unit: "time_b" }];
  const a = frame(extentFactory({ facet: "facet:duration", subject: ["shipping"], values: ivsA }));
  const b = frame(extentFactory({ facet: "facet:duration", subject: ["shipping"], values: ivsB }));
  const d = disposition(a, b);
  assert.ok(relIsUndecidable(d));
  assert.equal(relCause(d), "malformed_mention");
});
