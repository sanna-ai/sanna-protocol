"""Unit tests for reference/primitives.py (SAN-879): tokenizer (PCT100,
contractions, apostrophes), stem_v1 rules, parse_dec (canonical form,
2^53 boundary distinctness, trailing zeros, malformed grouping),
parse_values (each comparator), sentences/segments.
"""

from reference.primitives import (
    Abstain,
    Dec,
    dec_cmp,
    list_marker_indices,
    parse_dec,
    parse_values,
    segments,
    sentences,
    stem_v1,
    tokenize,
)


# ---------------------------------------------------------------------
# tokenizer
# ---------------------------------------------------------------------

def test_pct100_is_a_dedicated_token_kind():
    toks = tokenize("100% guaranteed")
    assert toks[0].kind == "PCT100"
    assert toks[0].raw == "100%"


def test_pct100_does_not_fire_mid_digit_run():
    # "1100%" is not the bare literal "100%": PCT100 must not fire on a
    # digit run that merely contains "100" as a substring.
    toks = tokenize("1100%")
    assert toks[0].kind == "NUMBER"
    assert toks[0].raw == "1100%"
    assert len(toks) == 1


def test_percent_other_than_100_is_a_number_token():
    toks = tokenize("50% off")
    assert toks[0].kind == "NUMBER"
    assert toks[0].raw == "50%"


def test_contraction_expansion_splits_into_two_tokens():
    toks = tokenize("can't")
    assert [t.fold for t in toks] == ["can", "not"]
    # first expanded token keeps the raw span; the rest carry empty raw
    assert toks[0].raw == "can't"
    assert toks[1].raw == ""


def test_contraction_expansion_matches_plain_form_fold():
    # "cannot" (single word, no apostrophe) expands identically to "can't"
    a = tokenize("can't enter")
    b = tokenize("cannot enter")
    assert [t.fold for t in a] == [t.fold for t in b]


def test_apostrophe_word_curly_and_straight_normalize_identically():
    # spec 2.2 rule 4: "letters with internal apostrophes joined (U+2019
    # -> ')" -- the curly->straight normalization is scoped to apostrophes
    # that are actually joined into a WORD token (i.e. followed by a
    # letter), so this must be exercised with an internal apostrophe
    # (not a trailing possessive with nothing after it).
    straight = tokenize("y'all access")
    curly = tokenize("y\u2019all access")
    assert [t.raw for t in straight] == [t.raw for t in curly]
    assert straight[0].raw == "y'all"


def test_internal_apostrophe_joins_letters():
    toks = tokenize("don't")
    # "don't" is itself a contraction key -> expands to do/not
    assert [t.fold for t in toks] == ["do", "not"]


def test_word_with_non_contraction_internal_apostrophe_stays_one_token():
    toks = tokenize("y'all")
    assert len(toks) == 1
    assert toks[0].kind == "WORD"
    assert toks[0].raw == "y'all"


def test_whitespace_is_skipped_including_tabs_and_newlines():
    toks = tokenize("a\tb\nc")
    assert [t.raw for t in toks] == ["a", "b", "c"]


def test_currency_and_comma_grouping_tokenizes_as_one_number():
    toks = tokenize("$23,456")
    assert len(toks) == 1
    assert toks[0].kind == "NUMBER"
    assert toks[0].raw == "$23,456"


def test_malformed_comma_grouping_splits_into_multiple_number_tokens():
    toks = tokenize("$1,23,456")
    kinds = [t.kind for t in toks]
    assert kinds.count("NUMBER") >= 2


def test_decimal_fraction_tokenizes_as_single_number():
    toks = tokenize("$25.50")
    assert len(toks) == 1
    assert toks[0].raw == "$25.50"


# ---------------------------------------------------------------------
# stem_v1
# ---------------------------------------------------------------------

def test_stem_ies_to_y():
    assert stem_v1("cities") == "city"


def test_stem_sses_to_ss():
    assert stem_v1("glasses") == "glass"


def test_stem_es_after_sibilant_drops():
    assert stem_v1("boxes") == "box"


def test_stem_final_s_not_ss_drops():
    assert stem_v1("cats") == "cat"
    assert stem_v1("needs") == "need"
    assert stem_v1("requires") == "require"


def test_stem_double_s_is_not_stripped():
    assert stem_v1("glass") == "glass"


def test_stem_short_word_below_min_len_unchanged():
    assert stem_v1("is") == "is"
    assert stem_v1("was") == "was"


def test_stem_unmatched_word_unchanged():
    assert stem_v1("available") == "available"
    assert stem_v1("required") == "required"


# ---------------------------------------------------------------------
# parse_dec
# ---------------------------------------------------------------------

def test_parse_dec_canonical_form_strips_trailing_zeros():
    d = parse_dec("$25.00")
    assert d == Dec(25, 0)


def test_parse_dec_2_53_boundary_distinctness_never_floats():
    # 2^53 = 9007199254740992; float64 cannot distinguish adjacent
    # integers beyond this magnitude. Dec must, since it is BigInt-only.
    a = parse_dec("9007199254740993")
    b = parse_dec("9007199254740992")
    assert a != b
    assert a.coefficient - b.coefficient == 1
    assert dec_cmp(a, b) == 1


def test_parse_dec_trailing_zero_equal_to_bare_integer():
    a = parse_dec("$25.00")
    b = parse_dec("$25")
    assert dec_cmp(a, b) == 0
    assert a == b


def test_parse_dec_negative_sign():
    d = parse_dec("-5")
    assert d.coefficient == -5


def test_parse_dec_digit_cap_abstains():
    too_many_digits = "1" * 39  # MAX_DEC_DIGITS = 38
    try:
        parse_dec(too_many_digits)
        assert False, "expected Abstain"
    except Abstain as e:
        assert e.cause == "malformed_mention"


def test_parse_dec_scale_cap_abstains():
    too_much_scale = "1." + "1" * 13  # MAX_DEC_SCALE = 12
    try:
        parse_dec(too_much_scale)
        assert False, "expected Abstain"
    except Abstain as e:
        assert e.cause == "malformed_mention"


# ---------------------------------------------------------------------
# parse_values -- every comparator
# ---------------------------------------------------------------------

def test_parse_values_over_is_open_lower_unbounded_upper():
    iv = parse_values(tokenize("over 5"))[0]
    assert iv.lo.coefficient == 5 and iv.lo_open is True
    assert iv.hi is None and iv.hi_open is True


def test_parse_values_above_is_open_lower_unbounded_upper():
    iv = parse_values(tokenize("above 5"))[0]
    assert iv.lo.coefficient == 5 and iv.lo_open is True
    assert iv.hi is None


def test_parse_values_more_than_is_open_lower():
    iv = parse_values(tokenize("more than 5"))[0]
    assert iv.lo.coefficient == 5 and iv.lo_open is True


def test_parse_values_at_least_is_closed_lower():
    iv = parse_values(tokenize("at least 5"))[0]
    assert iv.lo.coefficient == 5 and iv.lo_open is False
    assert iv.hi is None


def test_parse_values_under_is_open_upper_unbounded_lower():
    iv = parse_values(tokenize("under 5"))[0]
    assert iv.lo is None
    assert iv.hi.coefficient == 5 and iv.hi_open is True


def test_parse_values_below_is_open_upper():
    iv = parse_values(tokenize("below 5"))[0]
    assert iv.hi.coefficient == 5 and iv.hi_open is True


def test_parse_values_less_than_is_open_upper():
    iv = parse_values(tokenize("less than 5"))[0]
    assert iv.hi.coefficient == 5 and iv.hi_open is True


def test_parse_values_at_most_is_closed_upper():
    iv = parse_values(tokenize("at most 5"))[0]
    assert iv.hi.coefficient == 5 and iv.hi_open is False
    assert iv.lo is None


def test_parse_values_up_to_is_closed_upper():
    iv = parse_values(tokenize("up to 5"))[0]
    assert iv.hi.coefficient == 5 and iv.hi_open is False


def test_parse_values_within_is_0_to_v_closed():
    iv = parse_values(tokenize("within 5"))[0]
    assert iv.lo.coefficient == 0 and iv.lo_open is False
    assert iv.hi.coefficient == 5 and iv.hi_open is False


def test_parse_values_bare_scalar_is_point_interval():
    iv = parse_values(tokenize("5"))[0]
    assert iv.lo.coefficient == 5 and iv.hi.coefficient == 5
    assert iv.lo_open is False and iv.hi_open is False


def test_parse_values_no_number_returns_none():
    assert parse_values(tokenize("hello world")) is None


def test_parse_values_second_number_abstains():
    try:
        parse_values(tokenize("5 and 6"))
        assert False, "expected Abstain"
    except Abstain as e:
        assert e.cause == "malformed_mention"


def test_parse_values_leftover_tokens_abstain():
    try:
        parse_values(tokenize("roughly costs 5 today"))
        assert False, "expected Abstain"
    except Abstain:
        pass


def test_parse_values_unit_conversion():
    iv = parse_values(tokenize("2 hour"))[0]
    assert iv.unit == "time_a"
    assert iv.lo.coefficient == 120  # 2 hours * 60 min/hour


def test_parse_values_approx_token_abstains():
    try:
        parse_values(tokenize("about 5"))
        assert False, "expected Abstain"
    except Abstain as e:
        assert e.cause == "malformed_mention"


# ---------------------------------------------------------------------
# sentences / segments
# ---------------------------------------------------------------------

def test_sentences_splits_on_terminal_punct_followed_by_whitespace():
    toks = tokenize("Users may enter. Users may not enter after hours.")
    sents = sentences(toks)
    assert len(sents) == 2
    assert sents[0][-1].raw == "."
    assert sents[1][0].raw == "Users"


def test_sentences_numeric_period_is_not_a_terminator():
    toks = tokenize("Basic costs $25.50 today.")
    sents = sentences(toks)
    assert len(sents) == 1


def test_segments_split_on_structural_punctuation():
    toks = tokenize("Refunds, if approved, are available.")
    sent = sentences(toks)[0]
    segs = segments(sent)
    assert len(segs) == 3
    assert [t.raw for t in segs[0]] == ["Refunds"]


def test_sentences_bullet_line_starts_new_sentence():
    # spec 2.6: a line whose first token is '-' or '*' starts a new
    # sentence even without a preceding terminator
    text = "Refunds apply\n- Fees apply"
    toks = tokenize(text)
    sents = sentences(toks, text)
    assert len(sents) == 2
    assert sents[1][0].raw == "-"


def test_sentences_numbered_line_starts_new_sentence():
    # e10 (spec 2.6): a line whose first token is NUMBER+'.' starts a
    # new sentence and the marker BELONGS to the item's sentence as a
    # structural list marker -- its period is NOT a sentence terminator.
    text = "Terms follow\n1. Refunds apply"
    toks = tokenize(text)
    sents = sentences(toks, text)
    assert len(sents) == 2
    assert [t.raw for t in sents[1]] == ["1", ".", "Refunds", "apply"]


def test_sentences_numbered_item_is_one_sentence():
    # e10: '1. Items are refundable.' is ONE sentence, behaviorally
    # identical to '- Items are refundable.'
    text = "1. Items are refundable."
    toks = tokenize(text)
    sents = sentences(toks, text)
    assert len(sents) == 1
    bullet_text = "- Items are refundable."
    bullet_sents = sentences(tokenize(bullet_text), bullet_text)
    assert len(bullet_sents) == 1


def test_sentences_without_text_applies_terminator_rule_only():
    text = "Refunds apply\n- Fees apply"
    toks = tokenize(text)
    assert len(sentences(toks)) == 1


def test_indented_bullet_marker_single_leading_space_recognized():
    # e10 + Sol 914f832 delta: leading whitespace that reaches
    # beginning-of-field still starts a line
    text = " - Items are refundable."
    toks = tokenize(text)
    assert 0 in list_marker_indices(toks, text)


def test_indented_bullet_marker_multiple_leading_spaces_recognized():
    text = "   * Items are refundable."
    toks = tokenize(text)
    assert 0 in list_marker_indices(toks, text)


def test_indented_bullet_marker_leading_tab_recognized():
    text = "\t- Items are refundable."
    toks = tokenize(text)
    assert 0 in list_marker_indices(toks, text)


def test_indented_numbered_marker_recognized_and_one_sentence():
    # " 12. Items are refundable." must behave identically to the
    # bullet form: marker recognized (NUMBER + '.' indices), period not
    # a terminator, ONE sentence
    text = " 12. Items are refundable."
    toks = tokenize(text)
    markers = list_marker_indices(toks, text)
    assert 0 in markers and 1 in markers
    assert len(sentences(toks, text)) == 1


def test_indented_numbered_marker_after_newline_with_indent():
    text = "Terms follow.\n  3. Fees apply."
    toks = tokenize(text)
    sents = sentences(toks, text)
    assert len(sents) == 2
    assert sents[1][0].kind == "NUMBER"
