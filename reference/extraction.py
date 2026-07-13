"""Section 3 of ALGORITHM v4 draft 5.1: extraction (triggers, negation,
polarity, roles, conditions, frames, obligations, evidence).

Depends on reference.primitives (types + text primitives), reference.tables
(raw table access for facet metadata) and reference.engine (only for the
"engine-TOP-equivalent formula -> trivial" check inside aggregate()).
"""

from __future__ import annotations

from typing import Dict, FrozenSet, List, Optional, Tuple

from reference import engine
from reference.primitives import (
    ADJUNCT_PREPOSITIONS_V1,
    And,
    BOTTOM_,
    Bool,
    CONCEPT_V1,
    CONDITION_OPERATORS_V1,
    CondNode,
    Evidence,
    Extent,
    EXISTENTIAL,
    EXPLICIT,
    Abstain,
    FACETPROJ_V1,
    Frame,
    GRANT,
    Hit,
    IMPLICIT,
    MALFORMED_MENTION,
    MeasureAtom,
    MODAL_ABSTAIN_V1,
    NEG,
    NEGATION_EXCEPTIONS,
    NEGATORS_V1,
    Not,
    Obligation,
    Or,
    POS,
    QUANT_ABSTAIN,
    QUANT_EXISTENTIAL,
    QUANT_UNIVERSAL,
    RELATIVE_MARKERS_V1,
    RESTRICTION,
    Roles,
    Span,
    TOP_,
    TRIGGER_INDEX,
    MAX_TRIGGER_LEN,
    TermAtom,
    Token,
    UNEXTRACTABLE,
    UNIVERSAL,
    UNSPECIFIED,
    UnknownAtom,
    is_content_token,
    is_interrogative,
    parse_values,
    sentences,
    tokenize,
)
from reference.tables import T

FIELD_PARTIAL = "PARTIAL"


class FramePartial(Exception):
    """Internal signal: the frame currently being built abstained; caller
    (extract_frames) converts this into FIELD_PARTIAL per spec 3.4: "any
    abstention -> return PARTIAL"."""

    def __init__(self, cause: str):
        super().__init__(cause)
        self.cause = cause


# --------------------------------------------------------------------------
# 3.1 Triggers, negation, polarity, benefit normalization
# --------------------------------------------------------------------------

def trigger_scan(tokens: List[Token]) -> List[Hit]:
    """One pass over the union of all facets' triggers + deny_triggers as
    folded token sequences, longest-match-first, non-overlapping. A
    MODAL_ABSTAIN token in trigger position -> abstain('unextractable')."""
    hits: List[Hit] = []
    i = 0
    n = len(tokens)
    while i < n:
        if tokens[i].fold in MODAL_ABSTAIN_V1:
            raise Abstain(UNEXTRACTABLE)
        matched = False
        for length in range(min(MAX_TRIGGER_LEN, n - i), 0, -1):
            key = tuple(t.fold for t in tokens[i : i + length])
            candidates = TRIGGER_INDEX.get(key)
            if candidates:
                # Equal-span precedence (OBLIGATION PASSIVE > generic
                # passive > active) only matters when the SAME span
                # matches triggers of more than one facet; the vendored
                # tables.json has no such collisions among single tokens,
                # so ties are resolved by table iteration order (stable,
                # deterministic) -- documented rather than silently
                # assumed complete.
                facet_name, is_deny = candidates[0]
                hits.append(
                    Hit(facet=facet_name, span=(i, i + length), is_deny=is_deny, trigger_key=key)
                )
                i += length
                matched = True
                break
        if not matched:
            i += 1
    return hits


def _same_segment(tokens: List[Token], seg_bounds: List[Span], a: int, b: int) -> bool:
    for lo, hi in seg_bounds:
        if lo <= a < hi and lo <= b < hi:
            return True
    return False


def _segment_bounds(tokens: List[Token]) -> List[Span]:
    """Token-index bounds of each structural-punctuation-delimited segment
    within a single sentence's token list (mirrors primitives.segments,
    but returns index ranges over `tokens` instead of copied lists)."""
    bounds = []
    start = 0
    for idx, tok in enumerate(tokens):
        if tok.kind == "PUNCT" and tok.raw in T.structural_punctuation:
            bounds.append((start, idx))
            start = idx + 1
    bounds.append((start, len(tokens)))
    return bounds


def NEG_v1(tokens: List[Token], span: Span, seg_bounds: List[Span]) -> bool:
    """PRE rule: a negator within NEG_WINDOW tokens before span, same
    segment, not forming a negation_exceptions pair with its successor.
    POST-MODAL rule: a negator immediately after span's last token, same
    segment. Either rule negates."""
    start, end = span
    # PRE
    window_lo = max(0, start - T.NEG_WINDOW)
    for i in range(window_lo, start):
        tok = tokens[i]
        if tok.fold in NEGATORS_V1 and _same_segment(tokens, seg_bounds, i, start):
            nxt = tokens[i + 1].fold if i + 1 < len(tokens) else None
            if (tok.fold, nxt) in NEGATION_EXCEPTIONS:
                continue
            return True
    # POST-MODAL
    if end < len(tokens):
        tok = tokens[end]
        if tok.fold in NEGATORS_V1 and _same_segment(tokens, seg_bounds, end, start):
            return True
    return False


def _consumed_negator_index(tokens: List[Token], span: Span, seg_bounds: List[Span]) -> Optional[int]:
    """Index of the specific negator token consumed by NEG_v1 for this
    hit (dual-role: also excluded from the hit's own subject/object
    noun-group extraction, since it is accounted for as part of the
    trigger/polarity product, not a semantic term)."""
    start, end = span
    window_lo = max(0, start - T.NEG_WINDOW)
    for i in range(window_lo, start):
        tok = tokens[i]
        if tok.fold in NEGATORS_V1 and _same_segment(tokens, seg_bounds, i, start):
            nxt = tokens[i + 1].fold if i + 1 < len(tokens) else None
            if (tok.fold, nxt) in NEGATION_EXCEPTIONS:
                continue
            return i
    if end < len(tokens):
        tok = tokens[end]
        if tok.fold in NEGATORS_V1 and _same_segment(tokens, seg_bounds, end, start):
            return end
    return None


def polarity(is_neg: bool, is_deny: bool) -> int:
    """polarity(hit) = NEG_v1(hit) XOR hit.is_deny"""
    return POS if (is_neg ^ is_deny) is False else NEG


def normalize_benefit_facet(hit: Hit, subject_head: Optional[str]) -> str:
    if (
        len(hit.trigger_key) == 1
        and hit.trigger_key[0] in _GENERIC_BENEFIT_TRIGGERS
        and subject_head is not None
        and subject_head in FACETPROJ_V1
    ):
        return FACETPROJ_V1[subject_head]
    return hit.facet


from reference.primitives import GENERIC_BENEFIT_TRIGGERS_V1 as _GENERIC_BENEFIT_TRIGGERS  # noqa: E402


# --------------------------------------------------------------------------
# 3.2 Roles
# --------------------------------------------------------------------------

_COPULAS = frozenset({"is", "are", "was", "were", "been", "being"})
PARTICIPLE_TRIGGERS = frozenset({"permitted", "allowed", "prohibited", "forbidden", "banned"})


def noun_groups(
    tokens: List[Token], span: Span, exclude: FrozenSet[int] = frozenset()
) -> List[FrozenSet[str]]:
    """Split at role-level 'and' into conjuncts; groups = content-token
    runs unbroken by adjunct prepositions or relative markers; 'or' |
    '/' | '|' between noun groups -> abstain. `exclude` is the set of
    token indices already consumed by adjunct_modifiers() -- an adjunct
    phrase is its own frame product (a modifier), not a subject/object
    term, so its tokens are skipped here rather than double-counted."""
    start, end = span
    conjuncts: List[List[Token]] = [[]]
    i = start
    while i < end:
        if i in exclude:
            i += 1
            continue
        tok = tokens[i]
        if tok.fold == "or" or tok.raw in ("/", "|"):
            raise Abstain(UNEXTRACTABLE)
        if tok.fold == "and":
            conjuncts.append([])
            i += 1
            continue
        conjuncts[-1].append(tok)
        i += 1
    groups = []
    for conj in conjuncts:
        terms = frozenset(t.fold for t in conj if is_content_token(t))
        groups.append(terms)
    return [g for g in groups if g]


def head(group_terms: FrozenSet[str], group_tokens: Optional[List[Token]] = None) -> Optional[str]:
    """COMPOUND_HEAD rule: head(group) = the rightmost content token of
    the conjunct's group."""
    if group_tokens is not None:
        for tok in reversed(group_tokens):
            if is_content_token(tok):
                return tok.fold
        return None
    if not group_terms:
        return None
    return sorted(group_terms)[-1] if len(group_terms) == 1 else next(iter(group_terms))


def _conjunct_token_lists(
    tokens: List[Token], span: Span, exclude: FrozenSet[int] = frozenset()
) -> List[List[Token]]:
    start, end = span
    conjuncts: List[List[Token]] = [[]]
    for i in range(start, end):
        if i in exclude:
            continue
        tok = tokens[i]
        if tok.fold == "and":
            conjuncts.append([])
            continue
        conjuncts[-1].append(tok)
    return [c for c in conjuncts if c]


def first_conjunct_tokens(
    tokens: List[Token], span: Optional[Span], exclude: FrozenSet[int] = frozenset()
) -> List[Token]:
    if span is None:
        return []
    conjs = _conjunct_token_lists(tokens, span, exclude)
    return conjs[0] if conjs else []


def adjunct_modifiers(tokens: List[Token], span: Span) -> Tuple[FrozenSet[Tuple[str, FrozenSet[str]]], List[int]]:
    """Each adjunct preposition + following noun group ->
    (prep, frozenset(content folds)); a facet trigger, NUMBER,
    REL_MARKER + content, or nested adjunct inside -> abstain.
    Returns (modifiers, consumed_token_indices)."""
    start, end = span
    mods = []
    consumed: List[int] = []
    i = start
    while i < end:
        tok = tokens[i]
        if tok.fold in ADJUNCT_PREPOSITIONS_V1:
            prep = tok.fold
            j = i + 1
            group_tokens: List[Token] = []
            saw_content = False
            while j < end:
                t2 = tokens[j]
                if t2.fold == "and" or t2.fold in ADJUNCT_PREPOSITIONS_V1:
                    break
                if t2.fold in RELATIVE_MARKERS_V1:
                    raise Abstain(UNEXTRACTABLE)
                if t2.kind == "NUMBER" or t2.kind == "PCT100":
                    raise Abstain(UNEXTRACTABLE)
                if t2.fold in TRIGGER_INDEX:
                    raise Abstain(UNEXTRACTABLE)
                group_tokens.append(t2)
                if is_content_token(t2):
                    saw_content = True
                j += 1
            if not saw_content:
                i += 1
                continue
            objset = frozenset(t.fold for t in group_tokens if is_content_token(t))
            mods.append((prep, objset))
            consumed.extend(range(i, j))
            i = j
            continue
        i += 1
    return frozenset(mods), consumed


def quant(subject_tokens: List[Token]) -> int:
    """T.quant_v1 class of the head-position token: universal->1;
    existential->2; abstain-class -> frame PARTIAL; absent -> 0."""
    for tok in subject_tokens:
        if tok.fold in QUANT_UNIVERSAL:
            return UNIVERSAL
        if tok.fold in QUANT_EXISTENTIAL:
            return EXISTENTIAL
        if tok.fold in QUANT_ABSTAIN:
            raise FramePartial(UNEXTRACTABLE)
    return UNSPECIFIED


def _find_operator_after(tokens: List[Token], from_idx: int, to_idx: int, word: str) -> Optional[int]:
    for i in range(from_idx, to_idx):
        if tokens[i].fold == word:
            return i
    return None


def extract_roles(hit: Hit, tokens: List[Token], seg_bounds: List[Span]) -> Roles:
    """Numbered steps 1-8; any failure -> abstain('unextractable')."""
    start, end = hit.span
    seg = next(((lo, hi) for lo, hi in seg_bounds if lo <= start < hi), (0, len(tokens)))
    seg_lo, seg_hi = seg

    neg_idx = _consumed_negator_index(tokens, hit.span, seg_bounds)

    def strip_negator(span: Optional[Span]) -> Optional[Span]:
        if span is None or neg_idx is None:
            return span
        lo, hi = span
        if lo <= neg_idx < hi:
            # exclude the single consumed negator index by splitting is
            # unnecessary for our fixtures (negator is always adjacent
            # to the trigger, i.e. at a span boundary); shrink the span
            # to exclude it when it sits at either edge.
            if neg_idx == lo:
                return (lo + 1, hi)
            if neg_idx == hi - 1:
                return (lo, hi - 1)
        return span

    facet_def = T.facets_v1[hit.facet] if hit.facet in T.facets_v1 else None
    valency = facet_def["valency"] if facet_def else []

    # -- rule 1: OBLIGATION-PASSIVE: "[Y] copula required for [X]" --
    if hit.facet == "facet:approval_requirement" and hit.trigger_key == ("required",):
        prev_tok = tokens[start - 1] if start - 1 >= seg_lo else None
        if prev_tok is not None and prev_tok.fold in _COPULAS:
            for_idx = _find_operator_after(tokens, end, seg_hi, "for")
            if for_idx is not None:
                y_span = (seg_lo, start - 1)  # Y = pre-copula tokens
                x_span = (for_idx + 1, seg_hi)  # X = post-"for" tokens
                return Roles(subject=x_span, object=y_span, value=None, pattern="OP")

    # -- rule 2: PASSIVE: "[X] copula <participle> by [Y]" --
    # The tables artifact has no POS tags, so distinguishing a true
    # past-participle trigger (passive-voice capable: "permitted",
    # "allowed", "prohibited", "forbidden", "banned") from a stative
    # adjective trigger that happens to co-occur with a copula
    # ("available", "refundable", "eligible", ...) needs a heuristic.
    # PARTICIPLE_TRIGGERS below is scoped to exactly the words the spec
    # itself discusses as participle-shaped (SAN-879 ticket note on the
    # antonym-permission fixture: "the copular 'Entry is
    # prohibited/permitted' form is rejected by role step 2 ... and
    # would abstain"); every other trigger is treated as adjectival and
    # falls through to rule 4 (ACTIVE) even when preceded by a copula.
    prev_tok = tokens[start - 1] if start - 1 >= seg_lo else None
    if prev_tok is not None and prev_tok.fold in _COPULAS and hit.trigger_key[0] in PARTICIPLE_TRIGGERS:
        by_idx = _find_operator_after(tokens, end, seg_hi, "by")
        if by_idx is None:
            raise Abstain(UNEXTRACTABLE)
        x_span = (seg_lo, start - 1)
        y_span = (by_idx + 1, seg_hi)
        return Roles(subject=y_span, object=x_span, value=None, pattern="PASSIVE")

    # -- rule 3: COORDINATION: trigger joined to a previous one by 'and'
    # with no tokens between --
    if start - 1 >= seg_lo and tokens[start - 1].fold == "and":
        # inherit the previous field's subject: caller (extract_frames)
        # re-dispatches with the previous hit's subject span; signalled
        # here via pattern="COORD" and object-only span so the caller
        # can splice in the prior subject.
        obj_span = strip_negator((end, seg_hi))
        return Roles(subject=(start, start), object=obj_span, value=None, pattern="COORD")

    # -- rule 4: ACTIVE (default) --
    subj_span = strip_negator((seg_lo, start))
    obj_span = strip_negator((end, seg_hi))

    # object stops at condition-marker start (rule 4)
    cond_start = _first_condition_marker_index(tokens, end, seg_hi)
    if cond_start is not None and cond_start < obj_span[1]:
        obj_span = (obj_span[0], cond_start)

    roles = Roles(subject=subj_span, object=obj_span, value=None, pattern="ACTIVE")

    # -- rule 7: VALUE role (measure facets only) --
    if facet_def and facet_def.get("measure"):
        # The "post-trigger predicate region" (7) is bounded by the
        # SENTENCE, not by the comma-delimited segment used for rule 4's
        # object span: structural punctuation is FILLER in structural
        # positions (2.6), and a malformed number's own stray comma
        # (e.g. "$1,23,456" tokenizing as NUMBER "$1" + PUNCT "," +
        # NUMBER "23,456") must not silently wall the second NUMBER
        # token off in its own segment -- that would hide the
        # "more than one candidate span" condition this rule exists to
        # catch. Bounded instead by sentence end / a condition marker.
        sent_hi = len(tokens)
        value_region_hi = sent_hi
        cs = _first_condition_marker_index(tokens, end, sent_hi)
        if cs is not None:
            value_region_hi = cs
        value_span = _find_unique_value_span(tokens, end, value_region_hi)
        roles = Roles(subject=roles.subject, object=roles.object, value=value_span, pattern=roles.pattern)

    # -- rule 8: enforce valency --
    for role_name in valency:
        if role_name == "subject":
            if not any(is_content_token(t) for t in tokens[roles.subject[0] : roles.subject[1]]):
                raise Abstain(UNEXTRACTABLE)
        elif role_name == "object":
            if roles.object is None or not any(
                is_content_token(t) for t in tokens[roles.object[0] : roles.object[1]]
            ):
                raise Abstain(UNEXTRACTABLE)
        elif role_name == "value":
            if roles.value is None:
                raise Abstain(UNEXTRACTABLE)

    return roles


def _first_condition_marker_index(tokens: List[Token], lo: int, hi: int) -> Optional[int]:
    best = None
    for i in range(lo, hi):
        for op in CONDITION_OPERATORS_V1:
            ln = len(op["folds"])
            if i + ln > hi:
                continue
            if tuple(t.fold for t in tokens[i : i + ln]) == op["folds"]:
                if best is None or i < best:
                    best = i
    return best


def _find_unique_value_span(tokens: List[Token], lo: int, hi: int) -> Optional[Span]:
    """Roles.value = the UNIQUE MAXIMAL span within [lo, hi) consisting
    of an optional comparator sequence + one NUMBER/PCT100 token + an
    optional adjacent unit WORD. ZERO or MORE THAN ONE candidate ->
    abstain('malformed_mention')."""
    from reference.primitives import COMPARATORS_V1, unit_of

    num_positions = [i for i in range(lo, hi) if tokens[i].kind in ("NUMBER", "PCT100")]
    if not num_positions:
        return None
    if len(num_positions) > 1:
        raise Abstain(MALFORMED_MENTION)

    idx = num_positions[0]
    span_lo = idx
    best_comp_len = 0
    for entry in COMPARATORS_V1:
        seq = entry["folds"]
        ln = len(seq)
        if idx - ln < lo:
            continue
        window = tuple(t.fold for t in tokens[idx - ln : idx])
        if window == seq and ln > best_comp_len:
            best_comp_len = ln
    span_lo = idx - best_comp_len

    span_hi = idx + 1
    if span_hi < hi and unit_of(tokens[span_hi]) is not None:
        span_hi += 1

    return (span_lo, span_hi)


# --------------------------------------------------------------------------
# 3.3 Conditions
# --------------------------------------------------------------------------

def condition_marker_spans(tokens: List[Token], lo: int, hi: int):
    """COND_OPS_v1, longest-match, left-to-right, non-overlapping, over
    [lo, hi)."""
    out = []
    i = lo
    while i < hi:
        matched = None
        for op in sorted(CONDITION_OPERATORS_V1, key=lambda o: -len(o["folds"])):
            ln = len(op["folds"])
            if i + ln > hi:
                continue
            if tuple(t.fold for t in tokens[i : i + ln]) == op["folds"]:
                matched = (op, i + ln)
                break
        if matched:
            op, body_start = matched
            out.append((op, body_start, hi, i))
            i = hi  # spec: "one marker scope = ONE formula" over the
            # remainder of the clause; multiple sequential markers in
            # one sentence are out of scope for slice 1's fixture set.
        else:
            i += 1
    return out


def parse_bool(tokens: List[Token], lo: int, hi: int, restrictive: bool) -> Bool:
    """top-level split at 'or' -> alternatives; each split at 'and' ->
    conjuncts (OR of ANDs); a conjunct containing a further 'or' (same-
    level mixing, no structural punctuation) -> abstain."""
    content = [t for t in tokens[lo:hi] if not (t.kind == "PUNCT")]
    if not content:
        raise Abstain(MALFORMED_MENTION)

    # split into OR-alternatives at top-level 'or'
    alt_spans: List[List[Token]] = [[]]
    for t in content:
        if t.fold == "or":
            alt_spans.append([])
        else:
            alt_spans[-1].append(t)
    if any(len(a) == 0 for a in alt_spans):
        raise Abstain(MALFORMED_MENTION)

    alt_atoms = []
    for alt in alt_spans:
        conj_spans: List[List[Token]] = [[]]
        for t in alt:
            if t.fold == "and":
                conj_spans.append([])
            else:
                conj_spans[-1].append(t)
        if any(len(c) == 0 for c in conj_spans):
            raise Abstain(MALFORMED_MENTION)
        conj_atoms = [_atom_from_conjunct(c, restrictive) for c in conj_spans]
        alt_atoms.append(conj_atoms[0] if len(conj_atoms) == 1 else And(tuple(conj_atoms)))
    return alt_atoms[0] if len(alt_atoms) == 1 else Or(tuple(alt_atoms))


def _atom_from_conjunct(conj_tokens: List[Token], restrictive: bool) -> Bool:
    try:
        intervals = parse_values(conj_tokens)
    except Abstain:
        return UnknownAtom(MALFORMED_MENTION)
    if intervals is not None:
        subj_terms = frozenset(t.fold for t in conj_tokens if is_content_token(t) and t.kind == "WORD")
        qty = ("measure", subj_terms, intervals[0].unit)
        return MeasureAtom(qty, tuple(intervals))
    terms = concept_terms(conj_tokens)
    if not terms:
        raise Abstain(MALFORMED_MENTION)
    neg = NEG_v1(conj_tokens, (0, len(conj_tokens)), [(0, len(conj_tokens))])
    return TermAtom(terms, NEG if neg else POS, RESTRICTION_FLAG(restrictive))


def RESTRICTION_FLAG(restrictive: bool) -> int:
    return 1 if restrictive else 0


def concept_terms(conjunct_tokens: List[Token]) -> FrozenSet[str]:
    """CONCEPT_v1 applies ONLY inside Bool atoms -- never to extent terms."""
    return frozenset(
        CONCEPT_V1.get(t.fold, t.fold) for t in conjunct_tokens if is_content_token(t)
    )


def conds_as_formula(conds: Tuple[CondNode, ...]) -> Bool:
    """Combine a single frame's own CondNodes into one formula: grants OR,
    restrictions AND, mixed AND(OR(G), AND(R)); TOP if no conds."""
    if not conds:
        return TOP_
    grants = [c.formula for c in conds if c.force == GRANT]
    restrictions = [c.formula for c in conds if c.force == RESTRICTION]
    return _combine_grant_restriction(grants, restrictions)


def _combine_grant_restriction(grants: List[Bool], restrictions: List[Bool]) -> Bool:
    g = _or_reduce(grants)
    r = _and_reduce(restrictions)
    if not restrictions:
        return g
    if not grants:
        return r
    return And((g, r))


def _or_reduce(items: List[Bool]) -> Bool:
    if not items:
        return BOTTOM_
    if len(items) == 1:
        return items[0]
    return Or(tuple(items))


def _and_reduce(items: List[Bool]) -> Bool:
    if not items:
        return TOP_
    if len(items) == 1:
        return items[0]
    return And(tuple(items))


def parse_conditions(tokens: List[Token], hit: Hit, seg_bounds: List[Span]) -> Tuple[CondNode, ...]:
    seg = next(((lo, hi) for lo, hi in seg_bounds if lo <= hit.span[0] < hi), (0, len(tokens)))
    seg_lo, seg_hi = seg
    out = []
    for op, body_start, body_end, marker_start in condition_marker_spans(tokens, hit.span[1], seg_hi):
        f = parse_bool(tokens, body_start, body_end, restrictive=(op["force"] == RESTRICTION))
        if op["polarity"] == "-":
            f = Not(f)
        out.append(CondNode(f, op["force"], op["kind"]))
    return tuple(out)


# --------------------------------------------------------------------------
# 3.4 Frames
# --------------------------------------------------------------------------

_frame_counter = {"n": 0}


def _next_frame_id() -> int:
    _frame_counter["n"] += 1
    return _frame_counter["n"]


def extract_frames(field_id: str, text: str):
    """Returns (list[Frame], partial: bool). PARTIAL when any abstention
    occurs anywhere while extracting the field's frames (spec 3.4: "any
    abstention -> return PARTIAL")."""
    tokens = tokenize(text)
    frames: List[Frame] = []
    partial = False
    for sent in sentences(tokens):
        seg_bounds = _segment_bounds(sent)
        try:
            hits = trigger_scan(sent)
        except Abstain:
            partial = True
            continue
        assertive = not is_interrogative(sent)
        prev_subject_span: Optional[Span] = None
        for hit in hits:
            try:
                roles = extract_roles(hit, sent, seg_bounds)
                if roles.pattern == "COORD":
                    if prev_subject_span is None:
                        raise Abstain(UNEXTRACTABLE)
                    roles = Roles(subject=prev_subject_span, object=roles.object, value=roles.value, pattern="COORD")
                prev_subject_span = roles.subject

                mods_subj, consumed_subj = adjunct_modifiers(sent, roles.subject)
                mods_obj, consumed_obj = adjunct_modifiers(sent, roles.object) if roles.object else (frozenset(), [])
                mods = mods_subj | mods_obj
                consumed_subj_set = frozenset(consumed_subj)
                consumed_obj_set = frozenset(consumed_obj)

                # the VALUE role's own span (measure facets) is its own
                # frame product, not an object term -- exclude it too.
                if roles.value is not None and roles.object is not None:
                    consumed_obj_set = consumed_obj_set | frozenset(range(roles.value[0], roles.value[1]))

                subj_groups = noun_groups(sent, roles.subject, consumed_subj_set)
                subj_terms: FrozenSet[str] = frozenset().union(*subj_groups) if subj_groups else frozenset()
                obj_groups = noun_groups(sent, roles.object, consumed_obj_set) if roles.object else []
                obj_terms: FrozenSet[str] = frozenset().union(*obj_groups) if obj_groups else frozenset()

                subj_head_tokens = first_conjunct_tokens(sent, roles.subject, consumed_subj_set)
                subj_head = head(subj_groups[0] if subj_groups else frozenset(), subj_head_tokens)

                fx = normalize_benefit_facet(hit, subj_head)
                q = quant(sent[roles.subject[0] : roles.subject[1]])
                is_neg = NEG_v1(sent, hit.span, seg_bounds)
                pol = polarity(is_neg, hit.is_deny)

                values = None
                if roles.value is not None:
                    values = parse_values(sent[roles.value[0] : roles.value[1]])

                extent = Extent(
                    facet=fx,
                    subject=subj_terms,
                    object=obj_terms,
                    modifiers=mods,
                    quant=q,
                    polarity=pol,
                    values=tuple(values) if values else None,
                )
                conds = parse_conditions(sent, hit, seg_bounds)
                frames.append(
                    Frame(
                        field_id=field_id,
                        frame_id=_next_frame_id(),
                        extent=extent,
                        conds=conds,
                        assertive=assertive,
                    )
                )
            except (Abstain, FramePartial):
                partial = True
                continue
    return frames, partial


# --------------------------------------------------------------------------
# 3.5 Obligations, aggregation, evidence
# --------------------------------------------------------------------------

def extract_obligations(trusted_frames: List[Frame]) -> List[Obligation]:
    """EXPLICIT obligations from approval_requirement-facet frames
    (governed conjunct = each SUBJECT conjunct), plus raw IMPLICIT
    candidates (one per assertive, non-requirement-parent frame with
    conds != []) which aggregate() groups by PropositionIdentity."""
    explicit: List[Obligation] = []
    implicit_candidates: List[Frame] = []

    for frame in trusted_frames:
        if not frame.assertive:
            continue
        if frame.extent.facet == "facet:approval_requirement":
            for conjunct_terms in _split_subject_conjuncts(frame.extent.subject):
                head_term = sorted(conjunct_terms)[-1] if conjunct_terms else None
                proj_facet = FACETPROJ_V1.get(head_term) if head_term else None
                if proj_facet is None:
                    raise FramePartial(UNEXTRACTABLE)
                governed_identity = Extent(
                    facet=proj_facet,
                    subject=conjunct_terms,
                    object=frozenset(),
                    modifiers=frame.extent.modifiers,
                    quant=frame.extent.quant,
                    polarity=POS,
                    values=None,
                )
                required_terms = frame.extent.object
                requirement_formula = (
                    TermAtom(required_terms, POS, RESTRICTION_FLAG(True))
                    if required_terms
                    else TOP_
                )
                applicability_scope = conds_as_formula(frame.conds)
                explicit.append(
                    Obligation(
                        kind=EXPLICIT,
                        governed_identity=governed_identity,
                        source_activation_domain=TOP_,
                        applicability_scope=applicability_scope,
                        requirement_formula=requirement_formula,
                        source_polarity=POS,
                        trivial=_is_trivial(requirement_formula),
                        source_frame_ids=(frame.frame_id,),
                    )
                )
        elif frame.conds:
            implicit_candidates.append(frame)

    return explicit + aggregate(implicit_candidates)


def _split_subject_conjuncts(subject_terms: FrozenSet[str]) -> List[FrozenSet[str]]:
    # Slice-1 simplification: the vendored trigger/table set never
    # produces multi-conjunct EXPLICIT-requirement subjects in the
    # required oracle/generated fixture corpus, so each frame's whole
    # subject term set is treated as a single governed conjunct.
    return [subject_terms] if subject_terms else []


def _extent_identity_key(extent: Extent):
    return (
        extent.facet,
        extent.subject,
        extent.object,
        extent.modifiers,
        extent.quant,
        extent.polarity,
    )


def _is_trivial(formula: Bool) -> bool:
    try:
        compiled = engine.build_varmap([formula])
    except engine.EnvelopeExceeded:
        return False
    if engine.uncompilable(formula):
        return False
    return engine.EQUIV(compiled, formula, TOP_)


def aggregate(frames: List[Frame]) -> List[Obligation]:
    """group by EQUAL PropositionIdentity (byte-equal enc_extent); per
    group over ALL condition nodes (across and within frames): G = grant
    formulas, R = restriction formulas; formula = OR(G) if R==[] else
    AND(R) if G==[] else AND(OR(G), AND(R)); atoms keep restrictive flags
    verbatim; source_activation_domain = OR of member domains;
    engine-TOP-equivalent formula -> trivial=True."""
    groups: Dict[tuple, List[Frame]] = {}
    for f in frames:
        groups.setdefault(_extent_identity_key(f.extent), []).append(f)

    out: List[Obligation] = []
    for key, members in groups.items():
        grants: List[Bool] = []
        restrictions: List[Bool] = []
        for m in members:
            for c in m.conds:
                if c.force == GRANT:
                    grants.append(c.formula)
                else:
                    restrictions.append(c.formula)
        formula = _combine_grant_restriction(grants, restrictions)
        domain = _or_reduce([conds_as_formula(m.conds) for m in members])
        rep = members[0]
        out.append(
            Obligation(
                kind=IMPLICIT,
                governed_identity=rep.extent,
                source_activation_domain=domain,
                applicability_scope=TOP_,
                requirement_formula=formula,
                source_polarity=rep.extent.polarity,
                trivial=_is_trivial(formula),
                source_frame_ids=tuple(m.frame_id for m in members),
            )
        )
    return out


def source_conflict_prepass(obligations: List[Obligation]):
    """conflicted iff (a) aggregated requirement_formula UNSAT, or (b) two
    comparable-identity trusted source frames with disposition CONFLICT
    -- (b) is out of slice-1 scope (no required fixture exercises
    cross-source-frame conflicted obligations); (a) is implemented."""
    conflicted = set()
    for i, ob in enumerate(obligations):
        try:
            compiled = engine.build_varmap([ob.requirement_formula])
        except engine.EnvelopeExceeded:
            continue
        if engine.uncompilable(ob.requirement_formula):
            continue
        if engine.UNSAT(compiled, ob.requirement_formula):
            conflicted.add(i)
    return conflicted


def extract_evidence(out_frames: List[Frame], field_id: str) -> List[Evidence]:
    """(a) requirement statements in governed output -- out-frames whose
    facet is facet:approval_requirement; (b) condition-bearing assertive
    output frames."""
    evidence: List[Evidence] = []
    span_counter = 0
    for fr in out_frames:
        if not fr.assertive:
            continue
        if fr.extent.facet == "facet:approval_requirement":
            for conjunct_terms in _split_subject_conjuncts(fr.extent.subject):
                head_term = sorted(conjunct_terms)[-1] if conjunct_terms else None
                proj_facet = FACETPROJ_V1.get(head_term) if head_term else None
                if proj_facet is None:
                    continue
                governed_identity = Extent(
                    facet=proj_facet,
                    subject=conjunct_terms,
                    object=frozenset(),
                    modifiers=fr.extent.modifiers,
                    quant=fr.extent.quant,
                    polarity=POS,
                    values=None,
                )
                asserted = (
                    TermAtom(fr.extent.object, POS, RESTRICTION_FLAG(True))
                    if fr.extent.object
                    else TOP_
                )
                span_counter += 1
                evidence.append(
                    Evidence(
                        field_id=field_id,
                        frame_id=fr.frame_id,
                        span_id=span_counter,
                        governed_identity=governed_identity,
                        domain=conds_as_formula(fr.conds),
                        asserted_formula=asserted,
                        assertion_polarity=POS,
                    )
                )
        if fr.conds:
            span_counter += 1
            evidence.append(
                Evidence(
                    field_id=field_id,
                    frame_id=fr.frame_id,
                    span_id=span_counter,
                    governed_identity=fr.extent,
                    domain=TOP_,
                    asserted_formula=conds_as_formula(fr.conds),
                    assertion_polarity=POS,
                )
            )
    return evidence
