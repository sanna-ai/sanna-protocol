# TEST-COVERAGE.md (SAN-880)

Maps every one of the 127 Python `test_*` functions across the six named
source files (`tests/reference/test_primitives.py`, `test_engine.py`,
`test_relations.py`, `test_oracles.py`, `test_evaluate.py`,
`test_extraction.py`) to its TypeScript coverage. No function is silently
omitted.

Mapping categories:

- **(a) direct** -- a TypeScript `test()` in `reference/ts/test/*.test.ts`
  whose title matches the Python function name (parametrized Python tests
  are expanded into `[param]`-suffixed TypeScript titles or a `for` loop
  over `test()` calls at module scope; the mapping is still 1:1 at the
  Python-function level, not necessarily 1:1 at the individual-case
  level).
- **(b) corpus/matrix parity** -- additionally (never as a substitute for
  a missing (a) mapping unless noted) proven by
  `scripts/check_reference_parity.sh`, which byte-diffs the TypeScript
  harness's output against the Python harness's output over the full
  fixture corpus in both corpus mode (`oracles.json`, `generated.json` as
  distributed) and matrix mode (every fixture projected through all four
  checks C1-C4, 1068 records total, IDs discarded and reassigned
  synthetically so the harness cannot key behavior off them).
- **(c) Python-only, justified** -- the function exercises a generator or
  harness mechanism that is intentionally Python-only per the SAN-880
  module-mirroring boundary (this package consumes fixtures; it does not
  regenerate them).

Counts: 125 of 127 functions have a direct (a) TypeScript test; 2 of those
125 additionally carry (b) corpus/matrix parity coverage; 2 functions are
(c) Python-only-justified with no TypeScript counterpart.

## tests/reference/test_primitives.py -> reference/ts/test/primitives.test.ts (66/67 direct, 1/67 Python-only-justified)

| # | Python function | Mapping |
|---|---|---|
| 1 | `test_pct100_is_a_dedicated_token_kind` | (a) same name |
| 2 | `test_pct100_does_not_fire_mid_digit_run` | (a) same name |
| 3 | `test_percent_other_than_100_is_a_number_token` | (a) same name |
| 4 | `test_contraction_expansion_splits_into_two_tokens` | (a) same name |
| 5 | `test_contraction_expansion_matches_plain_form_fold` | (a) same name |
| 6 | `test_apostrophe_word_curly_and_straight_normalize_identically` | (a) same name |
| 7 | `test_internal_apostrophe_joins_letters` | (a) same name |
| 8 | `test_word_with_non_contraction_internal_apostrophe_stays_one_token` | (a) same name |
| 9 | `test_whitespace_is_skipped_including_tabs_and_newlines` | (a) same name |
| 10 | `test_currency_and_comma_grouping_tokenizes_as_one_number` | (a) same name |
| 11 | `test_malformed_comma_grouping_splits_into_multiple_number_tokens` | (a) same name |
| 12 | `test_decimal_fraction_tokenizes_as_single_number` | (a) same name |
| 13 | `test_stem_ies_to_y` | (a) same name |
| 14 | `test_stem_sses_to_ss` | (a) same name |
| 15 | `test_stem_es_after_sibilant_drops` | (a) same name |
| 16 | `test_stem_final_s_not_ss_drops` | (a) same name |
| 17 | `test_stem_double_s_is_not_stripped` | (a) same name |
| 18 | `test_stem_short_word_below_min_len_unchanged` | (a) same name |
| 19 | `test_stem_unmatched_word_unchanged` | (a) same name |
| 20 | `test_parse_dec_canonical_form_strips_trailing_zeros` | (a) same name |
| 21 | `test_parse_dec_2_53_boundary_distinctness_never_floats` | (a) same name |
| 22 | `test_parse_dec_trailing_zero_equal_to_bare_integer` | (a) same name |
| 23 | `test_parse_dec_negative_sign` | (a) same name |
| 24 | `test_parse_dec_digit_cap_abstains` | (a) same name |
| 25 | `test_parse_dec_scale_cap_abstains` | (a) same name |
| 26 | `test_parse_values_over_is_open_lower_unbounded_upper` | (a) same name |
| 27 | `test_parse_values_above_is_open_lower_unbounded_upper` | (a) same name |
| 28 | `test_parse_values_more_than_is_open_lower` | (a) same name |
| 29 | `test_parse_values_at_least_is_closed_lower` | (a) same name |
| 30 | `test_parse_values_under_is_open_upper_unbounded_lower` | (a) same name |
| 31 | `test_parse_values_below_is_open_upper` | (a) same name |
| 32 | `test_parse_values_less_than_is_open_upper` | (a) same name |
| 33 | `test_parse_values_at_most_is_closed_upper` | (a) same name |
| 34 | `test_parse_values_up_to_is_closed_upper` | (a) same name |
| 35 | `test_parse_values_within_is_0_to_v_closed` | (a) same name |
| 36 | `test_parse_values_bare_scalar_is_point_interval` | (a) same name |
| 37 | `test_parse_values_no_number_returns_none` | (a) same name |
| 38 | `test_parse_values_second_number_abstains` | (a) same name |
| 39 | `test_parse_values_leftover_tokens_abstain` | (a) same name |
| 40 | `test_parse_values_unit_conversion` | (a) same name |
| 41 | `test_parse_values_approx_token_abstains` | (a) same name |
| 42 | `test_sentences_splits_on_terminal_punct_followed_by_whitespace` | (a) same name |
| 43 | `test_sentences_numeric_period_is_not_a_terminator` | (a) same name |
| 44 | `test_segments_split_on_structural_punctuation` | (a) same name |
| 45 | `test_sentences_bullet_line_starts_new_sentence` | (a) same name |
| 46 | `test_sentences_numbered_line_starts_new_sentence` | (a) same name |
| 47 | `test_sentences_numbered_item_is_one_sentence` | (a) same name |
| 48 | `test_sentences_without_text_applies_terminator_rule_only` | (a) same name |
| 49 | `test_indented_bullet_marker_single_leading_space_recognized` | (a) same name |
| 50 | `test_indented_bullet_marker_multiple_leading_spaces_recognized` | (a) same name |
| 51 | `test_indented_bullet_marker_leading_tab_recognized` | (a) same name |
| 52 | `test_indented_numbered_marker_recognized_and_one_sentence` | (a) same name |
| 53 | `test_indented_numbered_marker_after_newline_with_indent` | (a) same name |
| 54 | `test_ascii_lower_lowers_only_ascii_letters` | (a) same name |
| 55 | `test_ascii_lower_leaves_kelvin_sign_unchanged` | (a) same name |
| 56 | `test_ascii_lower_leaves_capital_i_with_dot_above_unchanged` | (a) same name |
| 57 | `test_ascii_lower_leaves_a_with_ring_above_unchanged` | (a) same name |
| 58 | `test_sentences_adjacent_punctuation_does_not_terminate` (parametrized `.`/`!`/`?`) | (a) same name, `[.]`/`[!]`/`[?]` suffixes |
| 59 | `test_sentences_punctuation_followed_by_space_terminates` (parametrized) | (a) same name, `[.]`/`[!]`/`[?]` suffixes |
| 60 | `test_sentences_punctuation_followed_by_tab_terminates` (parametrized) | (a) same name, `[.]`/`[!]`/`[?]` suffixes |
| 61 | `test_sentences_punctuation_followed_by_newline_terminates` (parametrized) | (a) same name, `[.]`/`[!]`/`[?]` suffixes |
| 62 | `test_sentences_punctuation_followed_by_eof_terminates` (parametrized) | (a) same name, `[.]`/`[!]`/`[?]` suffixes |
| 63 | `test_comma_group_requires_ascii_digits` | (a) same name |
| 64 | `test_parse_dec_rejects_non_ascii_digits` | (a) same name |
| 65 | `test_non_ascii_number_inputs_evaluate_structured_not_crash` (parametrized over 2 non-ASCII digit inputs) | (a) same name |
| 66 | `test_unicode_letter_classifier_pinned_to_ucd_15_0_0` | **(c) Python-only, justified.** Directly pins `_is_letter()` (the module-internal category predicate) and the host `unicodedata.unidata_version` guard it depends on -- a host-UCD version-introspection witness with no TypeScript equivalent (`tables.ts`'s module-load guard checks the vendored spec/tables hashes, not a host Unicode Character Database version). The TypeScript-side equivalent evidence is the vendored `unicode_letters_v15.ts` table, `scripts/generate_letter_table_u15.py --check` (drift gate), and `test_letter_ranges_v15_invariants` in `unicode_letters.test.ts`. |
| 67 | `test_astral_c1_letter_pin_closes_the_2ebf0_differential` | (a) same name -- lives in `reference/ts/test/unicode_letters.test.ts`, not `primitives.test.ts` (TypeScript-side placement predates this Python counterpart; see that file's `isAlphaCp()`-focused test suite) |

## tests/reference/test_engine.py -> reference/ts/test/engine.test.ts (31/31 direct)

| # | Python function | Mapping |
|---|---|---|
| 1 | `test_bitset_width_exactly_2_pow_n_bits` (parametrized n=0,1,2,3) | (a) same name, `[0]`/`[1]`/`[2]`/`[3]` suffixes |
| 2 | `test_bitset_not_is_width_masked` (parametrized n=0,1,2,3) | (a) same name, `[0]`/`[1]`/`[2]`/`[3]` suffixes |
| 3 | `test_bitset_zero_and_full_helpers` | (a) same name |
| 4 | `test_bitset_width_mismatch_raises` | (a) same name |
| 5 | `test_varmap_preflight_rejects_too_many_atoms` | (a) same name |
| 6 | `test_varmap_at_cap_succeeds` | (a) same name |
| 7 | `test_varmap_complement_pair_collapses_to_one_variable` | (a) same name |
| 8 | `test_varmap_complement_or_is_tautology` | (a) same name |
| 9 | `test_varmap_raw_unnormalized_word_does_not_complement_fold` | (a) same name |
| 10 | `test_varmap_same_terms_opposite_polarity_collapses_to_one_variable` | (a) same name |
| 11 | `test_decompose_single_closed_bound_yields_5_indicators` | (a) same name |
| 12 | `test_decompose_no_finite_bound_yields_one_indicator` | (a) same name |
| 13 | `test_decompose_indicators_ordered_lo_to_hi` | (a) same name |
| 14 | `test_build_exactly_one_group_two_vars` | (a) same name |
| 15 | `test_build_gamma_zero_quantities_is_top` | (a) same name |
| 16 | `test_build_gamma_single_quantity_restricts_to_exactly_one` | (a) same name |
| 17 | `test_measure_atom_sat_respects_gamma_exactly_one` | (a) same name |
| 18 | `test_entails_and_or_and_entails_leaf` | (a) same name |
| 19 | `test_entails_or_never_entails_a_leaf` | (a) same name |
| 20 | `test_entails_leaf_entails_the_or_containing_it` | (a) same name |
| 21 | `test_entails_restrictive_flag_structural_no_forward` | (a) same name |
| 22 | `test_entails_restrictive_flag_structural_no_reverse` | (a) same name |
| 23 | `test_entails_restrictive_only_f_never_entails_mixed_and` | (a) same name |
| 24 | `test_entails_structural_check_scoped_to_f_constrained_variables` | (a) same name |
| 25 | `test_entails_matching_restrictive_flags_succeeds` | (a) same name |
| 26 | `test_entails_top_never_entails_bottom` | (a) same name |
| 27 | `test_entails_bottom_entails_anything` | (a) same name |
| 28 | `test_sat_top_is_satisfiable` | (a) same name |
| 29 | `test_equiv_double_negation` | (a) same name |
| 30 | `test_domain_top_top_is_overlap` | (a) same name |
| 31 | `test_domain_contradiction_is_disjoint` | (a) same name |

## tests/reference/test_relations.py -> reference/ts/test/relations.test.ts (19/19 direct)

| # | Python function | Mapping |
|---|---|---|
| 1 | `test_identity_relation_comparable_when_generalizes_and_domain_overlap` | (a) same name |
| 2 | `test_identity_relation_inert_when_neither_generalizes` | (a) same name |
| 3 | `test_identity_relation_undecidable_employees_contractors_vector` | (a) same name |
| 4 | `test_identity_relation_never_read_as_boolean` | (a) same name |
| 5 | `test_generalizes_excl_pair_modifiers_is_no` | (a) same name |
| 6 | `test_generalizes_no_same_rel_match_is_no` | (a) same name |
| 7 | `test_generalizes_existential_cross_frame_is_undecidable` | (a) same name |
| 8 | `test_generalizes_existential_same_frame_is_yes` | (a) same name |
| 9 | `test_two_way_generalizes_yes_if_either_direction` | (a) same name |
| 10 | `test_two_way_generalizes_no_if_both_no` | (a) same name |
| 11 | `test_meet_unions_subject_and_object` | (a) same name |
| 12 | `test_meet_quant_existential_if_either_side_existential` | (a) same name |
| 13 | `test_meet_quant_universal_if_neither_existential` | (a) same name |
| 14 | `test_disposition_conflict_on_opposite_polarity_non_existential` | (a) same name |
| 15 | `test_disposition_match_on_same_polarity` | (a) same name |
| 16 | `test_disposition_match_when_both_existential_despite_opposite_polarity` | (a) same name |
| 17 | `test_disposition_measure_conflict_on_disjoint_intervals` | (a) same name |
| 18 | `test_disposition_measure_match_on_overlapping_intervals` | (a) same name |
| 19 | `test_disposition_measure_cross_group_is_undecidable_malformed` | (a) same name |

## tests/reference/test_oracles.py -> reference/ts/test/oracles.test.ts (5/6 direct, 1/6 Python-only-justified; 2/6 additionally corpus/matrix parity)

| # | Python function | Mapping |
|---|---|---|
| 1 | `test_oracle_expected_tuple_exact` (parametrized over all 60 oracles) | (a) same name, one `node:test` subtest per oracle id, **+ (b)** `scripts/check_reference_parity.sh` corpus mode re-proves every oracle's exact tuple against Python's live output (a strictly stronger check than comparing against the JSON-baked `expected` block, since it compares TypeScript's live output directly to Python's live output) |
| 2 | `test_every_oracle_binds_the_complete_tuple` | (a) same name |
| 3 | `test_generated_fixtures_file_exists_and_is_nonempty` | (a) same name |
| 4 | `test_generated_fixtures_regeneration_is_byte_identical` | **(c) Python-only, justified.** Calls `reference.generate_fixtures.generate()`/`render()` -- the surface-variant generator that PRODUCES `generated.json` from `oracles.json` (casing/whitespace/contraction/list-marker swaps via Python-side text mutation helpers). Per the SAN-880 scope boundary this package consumes the two fixture files as an already-built corpus; it does not reimplement the generator (there is exactly one fixture corpus, authored once from the Python reference, not a parallel TypeScript-side copy). `generated.json`'s internal consistency is independently exercised by `test_generated_fixture_variants_match_their_base_oracle` (below) and by `scripts/check_reference_parity.sh`'s NFC and corpus-mode assertions over the same file. |
| 5 | `test_generated_fixture_variants_match_their_base_oracle` | (a) same name |
| 6 | `test_generated_fixture_reproduces_live` (parametrized over all 207 generated fixtures) | (a) same name, one `node:test` subtest per generated fixture id, **+ (b)** `scripts/check_reference_parity.sh` corpus mode (`generated.json` as distributed) and matrix mode (all 207 x 4 = 828 records) re-prove this against Python's live output |

## tests/reference/test_evaluate.py -> reference/ts/test/evaluate.test.ts (1/1 direct)

| # | Python function | Mapping |
|---|---|---|
| 1 | `test_envelope_exceeded_wins_over_basis_empty_on_tier3_only_context` | (a) same name. Python monkeypatches the mutable `T.ENV_MAX_SENTENCES` singleton down to 3 to keep the regression fixture small; `tables.ts`'s `T` is a deliberately immutable (`readonly`-field) module-level singleton, so this port instead constructs a context that breaches the REAL `ENV_MAX_SENTENCES` cap directly (`"Items are refundable. ".repeat(T.ENV_MAX_SENTENCES + 1)`) -- same code path (`envelope_exceeded` must win over `basis_empty` for a tier_3-only context in Locked A1's wrapper order), no shared mutable state. |

## tests/reference/test_extraction.py -> reference/ts/test/extraction.test.ts (3/3 direct)

| # | Python function | Mapping |
|---|---|---|
| 1 | `test_adjunct_group_facet_trigger_abstains_to_partial` | (a) same name |
| 2 | `test_adjunct_group_deny_trigger_abstains_to_partial` | (a) same name |
| 3 | `test_adjunct_group_without_trigger_extracts_fully` | (a) same name |

## Additional TypeScript-only coverage (no Python counterpart required by SAN-880, but required by this ticket's Phase 2)

These are net-new test files with no 1:1 Python source, required directly
by the SAN-880 prompt rather than by the "map every Python test" mandate
above:

- `reference/ts/test/canonical_json.test.ts` -- hard-coded-expected-bytes
  tests for `diff_harness.ts`'s `canonicalJson()`, verified directly
  against Python's `json.dumps(..., sort_keys=True, ensure_ascii=True,
  separators=(",",":"))` output for the same inputs: non-ASCII BMP text,
  an astral (surrogate-pair) code point, U+2028/U+2029, control
  characters (including non-named ones and DEL), the named `\b\f\n\r\t`
  escapes, quotes/backslashes, recursive key sorting at every nesting
  level, and unchanged array order.
- `reference/ts/test/astral_semantic.test.ts` -- ONE semantic (not
  merely serializer-level) test proving `tokenize()`/`sentences()` index
  by Unicode CODE POINT rather than UTF-16 code unit, using an astral
  character (U+1D11E MUSICAL SYMBOL G CLEF) positioned so that a
  UTF-16-code-unit-indexed implementation would report a different token
  offset than a code-point-indexed one.
- `reference/ts/test/poisoned_metadata.test.ts` -- proves that mutating
  `expected`, `notes`, `base_oracle`, `variant_kind`/`variant_field`, and
  the original fixture `id` never changes the computed semantic result
  (`diff_harness.ts`'s `run()` and `evaluate()` read only `output` and
  the declared context shape), and that a fixture `id` shaped like a real
  synthetic matrix id is never treated as an evaluation shortcut
  (PROHIBITED: fixture-ID lookup tables or id-conditional behavior).
- `reference/ts/test/prototype_safety.test.ts` (SAN-880 amendment,
  review round 2) -- pins that all six Record-typed reference tables in
  `tables.ts` (`unitsV1`, `currencySymbolsV1`, `facetsV1`, `facetprojV1`,
  `contractionsV1`, `conceptV1`) are null-prototype at construction, and
  proves the concrete regression this fixes: an input-derived bracket
  lookup keyed by the word "constructor" used to resolve the inherited
  `Object.prototype.constructor` instead of missing, crashing
  `tokenize()`'s contraction-expansion loop and defeating
  `unitOf()`'s `?? null` fallback. No Python counterpart: `dict.get()`
  has no equivalent prototype-inheritance hazard, so this is a
  JavaScript/JSON-specific regression test.
- `reference/ts/test/unicode_letters.test.ts` (SAN-880 amendment,
  review round 2) -- pins `unicode.ts`'s `isAlphaCp()` letter
  classification to the vendored, generator-produced
  `unicode_letters_v15.ts` table (CPython 3.12 / UCD 15.0.0 baseline)
  instead of the host Node runtime's built-in `\p{L}` tables, which float
  with the runtime's Unicode version; covers classification pins,
  totality (empty string, multi-code-point input, lone surrogates),
  and the generated table's own invariants -- these remain TypeScript-only
  (no Python counterpart: `tables.ts`'s letter table is a vendored,
  generator-produced TypeScript artifact with no equivalent Python-side
  data structure to pin). Its astral C1 differential test
  (`test_astral_c1_letter_pin_closes_the_2ebf0_differential`,
  U+2EBF0/U+2EBF1, CJK Extension I additions in Unicode 15.1) now HAS a
  Python (a)-counterpart of the same name in `test_primitives.py` (row 67
  above), added once SAN-896 ratified UCD 15.0.0 letter classification as
  a spec-level pin (erratum e14) rather than a reference/CI-only
  baseline choice.
