"""Section 3 of ALGORITHM v4 draft 5.2: extraction (triggers, negation,
polarity, roles, conditions, frames, obligations, evidence), including
total span accounting (spec 2.6).

Depends on reference.primitives (types + text primitives),
reference.tables (raw table access for facet metadata) and
reference.engine (the "engine-TOP-equivalent formula -> trivial" check,
the UNSAT arm of the source-conflict prepass, and the MAX_EXPR_NODES
envelope path in parse_bool). source_conflict_prepass additionally uses
reference.relations via a local import (relations depends only on
engine/primitives, so no cycle).
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
    PARTICIPLE_TRIGGERS_V1,
    Obligation,
    Or,
    POS,
    QUANT_ABSTAIN,
    QUANT_EXISTENTIAL,
    QUANT_UNIVERSAL,
    RELATIVE_MARKERS_V1,
    RESTRICTION,
    Roles,
    STOP_V1,
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
    list_marker_indices,
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
                # Equal-span precedence (spec 3.1): OBLIGATION PASSIVE >
                # generic passive > active, applied when the SAME span
                # matches triggers of more than one facet. Class rank:
                # 0 = approval_requirement trigger (obligation-passive
                # capable), 1 = participle trigger (generic passive,
                # T.participle_triggers_v1), 2 = active/stative.
                def _precedence(candidate):
                    facet_name, _ = candidate
                    if facet_name == "facet:approval_requirement":
                        return 0
                    if key[0] in PARTICIPLE_TRIGGERS_V1:
                        return 1
                    return 2

                facet_name, is_deny = sorted(candidates, key=_precedence)[0]
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


def _conjunct_terms_and_heads(
    tokens: List[Token], span: Span, exclude: FrozenSet[int] = frozenset()
) -> Tuple[List[FrozenSet[str]], List[str]]:
    """Split at role-level 'and' into conjuncts; per conjunct return its
    content-term set and its COMPOUND_HEAD-rule head (the RIGHTMOST
    content token of the conjunct's group). 'or' | '/' | '|' between
    noun groups -> abstain. `exclude` is the set of token indices
    already consumed by another frame product (adjunct modifiers, the
    dual-role negator, the VALUE span) -- those are skipped here rather
    than double-counted as terms. Conjuncts with no content tokens are
    dropped; the two returned lists stay parallel."""
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
    groups: List[FrozenSet[str]] = []
    heads: List[str] = []
    for conj in conjuncts:
        terms = frozenset(t.fold for t in conj if is_content_token(t))
        if not terms:
            continue
        head_fold = next(t.fold for t in reversed(conj) if is_content_token(t))
        groups.append(terms)
        heads.append(head_fold)
    return groups, heads


def noun_groups(
    tokens: List[Token], span: Span, exclude: FrozenSet[int] = frozenset()
) -> List[FrozenSet[str]]:
    """Per-conjunct content-term sets (see _conjunct_terms_and_heads)."""
    return _conjunct_terms_and_heads(tokens, span, exclude)[0]


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

    # The consumed negator (dual-role, spec 3.1) is NOT stripped out of
    # role spans here: role spans are grammar spans; the negator index is
    # excluded from term extraction by extract_frames via the noun-group
    # exclude sets, and accounted once as the negation product.
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
    # e7 (spec 3.2 rule 2): applies ONLY when the trigger's fold is in
    # T.participle_triggers_v1 -- stative-adjective triggers like
    # 'available' never enter this pattern and fall through to rule 4
    # (ACTIVE) even when preceded by a copula. The classification is
    # DATA from the vendored tables artifact.
    prev_tok = tokens[start - 1] if start - 1 >= seg_lo else None
    if prev_tok is not None and prev_tok.fold in _COPULAS and hit.trigger_key[0] in PARTICIPLE_TRIGGERS_V1:
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
        return Roles(subject=(start, start), object=(end, seg_hi), value=None, pattern="COORD")

    # -- rule 4: ACTIVE (default) --
    subj_span = (seg_lo, start)
    obj_span = (end, seg_hi)

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
        value_span = _find_unique_value_span(tokens, end, value_region_hi, trigger_span=hit.span)
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


def _find_unique_value_span(
    tokens: List[Token], lo: int, hi: int, trigger_span: Optional[Span] = None
) -> Optional[Span]:
    """Roles.value = the UNIQUE MAXIMAL span within [lo, hi) consisting
    of an optional comparator sequence + one NUMBER/PCT100 token + an
    optional adjacent unit WORD. ZERO or MORE THAN ONE candidate ->
    abstain('malformed_mention').

    Spec 2.4: an APPROX_v1 token immediately before the number (or its
    sign/currency -- both are inside the NUMBER token here) -> abstain.

    DUAL-ROLE TRIGGER (e8, spec 3.2 step 7): a token that is BOTH a
    facet trigger and a comparator (currently only 'within') serves both
    roles in one span: when no comparator precedes the number inside
    [lo, hi) and the trigger's own fold sequence is a comparator ending
    immediately before the number, the span extends to include the
    trigger so its comparator interval template applies; the token is
    accounted once (dual-role consumption, like negators)."""
    from reference.primitives import APPROX_V1, COMPARATORS_V1, unit_of

    num_positions = [i for i in range(lo, hi) if tokens[i].kind in ("NUMBER", "PCT100")]
    if not num_positions:
        return None
    if len(num_positions) > 1:
        raise Abstain(MALFORMED_MENTION)

    idx = num_positions[0]
    if idx > 0 and tokens[idx - 1].fold in APPROX_V1:
        raise Abstain(MALFORMED_MENTION)

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

    if best_comp_len == 0 and trigger_span is not None and trigger_span[1] == idx:
        trigger_folds = tuple(t.fold for t in tokens[trigger_span[0] : trigger_span[1]])
        if any(entry["folds"] == trigger_folds for entry in COMPARATORS_V1):
            span_lo = trigger_span[0]

    span_hi = idx + 1
    if span_hi < hi and unit_of(tokens[span_hi]) is not None:
        span_hi += 1

    return (span_lo, span_hi)


# --------------------------------------------------------------------------
# 3.3 Conditions
# --------------------------------------------------------------------------

def condition_marker_spans(tokens: List[Token], lo: int, hi: int):
    """COND_OPS_v1, longest-match, left-to-right, non-overlapping, over
    [lo, hi). One marker scope = ONE formula (spec 3.3): each marker's
    body runs from the marker's end to the next marker's start (or hi),
    so multiple sequential markers each yield their own CondNode."""
    markers = []
    i = lo
    while i < hi:
        matched = None
        for op in sorted(CONDITION_OPERATORS_V1, key=lambda o: -len(o["folds"])):
            ln = len(op["folds"])
            if i + ln > hi:
                continue
            if tuple(t.fold for t in tokens[i : i + ln]) == op["folds"]:
                matched = (op, i, i + ln)
                break
        if matched:
            markers.append(matched)
            i = matched[2]
        else:
            i += 1

    out = []
    for k, (op, marker_start, body_start) in enumerate(markers):
        body_end = markers[k + 1][1] if k + 1 < len(markers) else hi
        out.append((op, body_start, body_end, marker_start))
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
    formula = alt_atoms[0] if len(alt_atoms) == 1 else Or(tuple(alt_atoms))
    # spec 3.3: node/atom count > MAX_EXPR_NODES -> envelope path (sec 8)
    if engine.bool_nodes(formula) > T.MAX_EXPR_NODES:
        raise engine.EnvelopeExceeded(
            f"envelope_exceeded: formula nodes > MAX_EXPR_NODES={T.MAX_EXPR_NODES}"
        )
    return formula


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


def _is_filler(tok: Token) -> bool:
    """FILLER per spec 2.6: STOP_v1 words in grammar positions,
    structural punctuation in structural positions, sentence-terminal
    '.'/'!' (the sentence-initial capitalized article is subsumed:
    a/an/the are STOP_v1). SEMANTIC-FORCE tokens (negators, condition
    operators, and/or, modals, quantifiers) are never in these filler
    categories, so an unconsumed occurrence falls through to PARTIAL."""
    if tok.kind == "PUNCT":
        return tok.raw in T.structural_punctuation or tok.raw in (".", "!")
    if tok.kind == "WORD":
        return tok.fold in STOP_V1
    return False


def extract_frames(field_id: str, text: str, governed: bool = False):
    """Returns (list[Frame], partial: bool). PARTIAL when any abstention
    occurs anywhere while extracting the field's frames (spec 3.4: "any
    abstention -> return PARTIAL"), OR when total span accounting (spec
    2.6) finds an unconsumed non-filler span, OR when a governed-output
    sentence is interrogative. Context '?' sentences are non-assertive,
    excluded from every basis, spans accounted."""
    tokens = tokenize(text)
    frames: List[Frame] = []
    partial = False
    for sent in sentences(tokens, text):
        seg_bounds = _segment_bounds(sent)
        interrogative = is_interrogative(sent)
        if interrogative and governed:
            # spec 2.6: governed-output sentence-terminal '?' -> FIELD PARTIAL
            partial = True
            continue
        try:
            hits = trigger_scan(sent)
        except Abstain:
            partial = True
            continue
        assertive = not interrogative
        consumed: set = set()
        sentence_abstained = False
        prev_subject_span: Optional[Span] = None
        for hit in hits:
            try:
                roles = extract_roles(hit, sent, seg_bounds)
                coordinator_idx: Optional[int] = None
                if roles.pattern == "COORD":
                    if prev_subject_span is None:
                        raise Abstain(UNEXTRACTABLE)
                    coordinator_idx = hit.span[0] - 1
                    roles = Roles(subject=prev_subject_span, object=roles.object, value=roles.value, pattern="COORD")
                prev_subject_span = roles.subject

                neg_idx = _consumed_negator_index(sent, hit.span, seg_bounds)
                neg_excl = frozenset() if neg_idx is None else frozenset({neg_idx})

                mods_subj, consumed_subj = adjunct_modifiers(sent, roles.subject)
                mods_obj, consumed_obj = adjunct_modifiers(sent, roles.object) if roles.object else (frozenset(), [])
                mods = mods_subj | mods_obj
                consumed_subj_set = frozenset(consumed_subj) | neg_excl
                consumed_obj_set = frozenset(consumed_obj) | neg_excl

                # the VALUE role's own span (measure facets) is its own
                # frame product, not an object term -- exclude it too.
                if roles.value is not None and roles.object is not None:
                    consumed_obj_set = consumed_obj_set | frozenset(range(roles.value[0], roles.value[1]))

                subj_groups, subj_heads = _conjunct_terms_and_heads(sent, roles.subject, consumed_subj_set)
                subj_terms: FrozenSet[str] = frozenset().union(*subj_groups) if subj_groups else frozenset()
                obj_groups = noun_groups(sent, roles.object, consumed_obj_set) if roles.object else []
                obj_terms: FrozenSet[str] = frozenset().union(*obj_groups) if obj_groups else frozenset()

                subj_head = subj_heads[0] if subj_heads else None

                fx = normalize_benefit_facet(hit, subj_head)
                q = quant(sent[roles.subject[0] : roles.subject[1]])
                is_neg = NEG_v1(sent, hit.span, seg_bounds)
                pol = polarity(is_neg, hit.is_deny)

                values = None
                if roles.value is not None:
                    values = parse_values(sent[roles.value[0] : roles.value[1]])

                # requirement frames carry their parse_bool requirement
                # product (spec 3.5: requirement_formula =
                # parse_bool(required_span, restrictive = True))
                req_formula: Optional[Bool] = None
                if fx == "facet:approval_requirement" and roles.object is not None:
                    req_formula = parse_bool(
                        sent, roles.object[0], roles.object[1], restrictive=True
                    )

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
                        subject_conjuncts=tuple(subj_groups),
                        subject_conjunct_heads=tuple(subj_heads),
                        req_formula=req_formula,
                    )
                )

                # -- span consumption (spec 2.6 frame products) --
                consumed.update(range(hit.span[0], hit.span[1]))
                if neg_idx is not None:
                    consumed.add(neg_idx)  # dual-role
                if coordinator_idx is not None:
                    consumed.add(coordinator_idx)
                consumed.update(range(roles.subject[0], roles.subject[1]))
                if roles.object is not None:
                    consumed.update(range(roles.object[0], roles.object[1]))
                if roles.value is not None:
                    consumed.update(range(roles.value[0], roles.value[1]))
                seg = next(((lo, hi) for lo, hi in seg_bounds if lo <= hit.span[0] < hi), (0, len(sent)))
                for _op, _bstart, body_end, marker_start in condition_marker_spans(sent, hit.span[1], seg[1]):
                    consumed.update(range(marker_start, body_end))
            except (Abstain, FramePartial):
                partial = True
                sentence_abstained = True
                continue

        if interrogative:
            # context '?' sentence: excluded from every basis, spans accounted
            continue
        if not sentence_abstained:
            # -- total span accounting (spec 2.6): every non-whitespace
            # span is consumed by a frame product or by FILLER, else the
            # FIELD is PARTIAL. Applies to untriggered sentences too
            # (zero hits => zero products => any non-filler token is
            # unconsumed, e.g. a triggerless retraction sentence).
            # e10: line-initial LIST MARKER tokens are structural markers
            # of the item's sentence, accounted like structural
            # punctuation. --
            markers = list_marker_indices(sent, text)
            for i, tok in enumerate(sent):
                if i in consumed or i in markers:
                    continue
                if _is_filler(tok):
                    continue
                partial = True
                break
    return frames, partial


# --------------------------------------------------------------------------
# 3.5 Obligations, aggregation, evidence
# --------------------------------------------------------------------------

def extract_obligations(trusted_frames: List[Frame]) -> List[Obligation]:
    """EXPLICIT obligations from approval_requirement-facet frames
    (governed conjunct = each SUBJECT conjunct, spec 3.5 "per governed
    conjunct"), plus raw IMPLICIT candidates (one per assertive,
    non-requirement-parent frame with conds != []) which aggregate()
    groups by PropositionIdentity."""
    explicit: List[Obligation] = []
    implicit_candidates: List[Frame] = []

    for frame in trusted_frames:
        if not frame.assertive:
            continue
        if frame.extent.facet == "facet:approval_requirement":
            if frame.extent.polarity != POS:
                # A negated requirement statement asserts the ABSENCE of
                # a requirement. The spec's EXPLICIT extraction pattern
                # (3.5: 'X require(s) Y' / 'Y is required for X', with
                # source_polarity pinned POS) covers the positive form;
                # a NEG requirement frame contributes no explicit
                # obligation, and -- being a requirement-parent frame --
                # no implicit one either.
                continue
            for conjunct_terms, conjunct_head in zip(
                frame.subject_conjuncts, frame.subject_conjunct_heads
            ):
                proj_facet = FACETPROJ_V1.get(conjunct_head) if conjunct_head else None
                if proj_facet is None:
                    # spec 3.5: facetproj miss -> PARTIAL
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
                # spec 3.5: requirement_formula = parse_bool(required_span,
                # restrictive = True) -- the parse product is carried on
                # the frame (req_formula); Boolean structure like
                # "approval and receipt" is preserved, never collapsed
                # into one term bag.
                requirement_formula = (
                    frame.req_formula if frame.req_formula is not None else TOP_
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


def _extent_identity_key(extent: Extent):
    """EQUAL PropositionIdentity = byte-equal enc_extent (spec 3.5/7):
    every enc_extent component participates, including values."""
    return (
        extent.facet,
        extent.subject,
        extent.object,
        extent.modifiers,
        extent.quant,
        extent.polarity,
        extent.values,
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


def source_conflict_prepass(obligations: List[Obligation], trusted_frames: List[Frame]):
    """conflicted iff (a) aggregated requirement_formula UNSAT (DECIDED:
    basis_conflict, never deny-all inference) or (b) two
    comparable-identity trusted source frames with disposition CONFLICT.
    For (b), the conflicting pair may span two different obligations'
    source frames (e.g. opposite-polarity frames aggregate into separate
    PropositionIdentity groups); an obligation is conflicted when any of
    its source frames participates in such a pair."""
    # local import: relations depends only on engine/primitives, so this
    # cannot cycle; kept local because relations is otherwise a consumer
    # of extraction products, not a dependency of extraction.
    from itertools import combinations

    from reference import relations as rel

    conflicted_frame_ids: set = set()
    assertive = [f for f in trusted_frames if f.assertive]
    for a, b in combinations(assertive, 2):
        r = rel.identity_relation(
            a.extent, conds_as_formula(a.conds), b.extent, conds_as_formula(b.conds), False
        )
        if r == rel.COMPARABLE and rel.disposition(a, b) == rel.CONFLICT:
            conflicted_frame_ids.add(a.frame_id)
            conflicted_frame_ids.add(b.frame_id)

    conflicted = set()
    for i, ob in enumerate(obligations):
        if any(fid in conflicted_frame_ids for fid in ob.source_frame_ids):
            conflicted.add(i)
            continue
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
    facet is facet:approval_requirement, per governed conjunct, with
    asserted_formula = the frame's parse_bool requirement product and
    assertion_polarity = NEG_v1(statement.trigger) (the frame's own
    polarity; the requirement facet has no deny triggers, so
    polarity == NEG_v1(trigger)); (b) condition-bearing assertive output
    frames."""
    evidence: List[Evidence] = []
    span_counter = 0
    for fr in out_frames:
        if not fr.assertive:
            continue
        if fr.extent.facet == "facet:approval_requirement":
            for conjunct_terms, conjunct_head in zip(
                fr.subject_conjuncts, fr.subject_conjunct_heads
            ):
                proj_facet = FACETPROJ_V1.get(conjunct_head) if conjunct_head else None
                if proj_facet is None:
                    # spec 3.5 evidence (a) mirrors the EXPLICIT
                    # projection: a facetproj miss -> PARTIAL
                    raise FramePartial(UNEXTRACTABLE)
                governed_identity = Extent(
                    facet=proj_facet,
                    subject=conjunct_terms,
                    object=frozenset(),
                    modifiers=fr.extent.modifiers,
                    quant=fr.extent.quant,
                    polarity=POS,
                    values=None,
                )
                asserted = fr.req_formula if fr.req_formula is not None else TOP_
                span_counter += 1
                evidence.append(
                    Evidence(
                        field_id=field_id,
                        frame_id=fr.frame_id,
                        span_id=span_counter,
                        governed_identity=governed_identity,
                        domain=conds_as_formula(fr.conds),
                        asserted_formula=asserted,
                        assertion_polarity=fr.extent.polarity,
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
