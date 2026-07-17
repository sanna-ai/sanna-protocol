"""Section 0 (types) and section 2 (text primitives) of ALGORITHM v4 draft
5.2. Hosts the shared type vocabulary (Bool AST, Extent, Frame, Evidence,
Obligation, Dec, Interval, Token, Roles) because section 0 precedes every
other section in the spec and every other module in this package depends
on these types. Tables are never restated here -- every constant/list is
read through reference.tables.T (or the compiled-fold indices built at the
bottom of this module by tokenizing each table entry through tokenize()
itself, per spec section 1: "the loader tokenizes each entry once at
load").
"""

from __future__ import annotations

import sys
import unicodedata
from dataclasses import dataclass
from typing import FrozenSet, Optional, Tuple, Union

from reference.tables import T

# Spec section 2.1 step 2 requires "a PROVEN Unicode-15.0.0 normalizer".
# CPython's unicodedata module is generated from the Unicode Character
# Database and its version is introspectable; we record it here and
# assert it is at least 15.0.0 so a future interpreter upgrade cannot
# silently normalize against different NFC tables without notice. The
# spec also calls for a "vendor-or-refuse NormalizationTest.txt CI
# gate" that would replay the official Unicode NormalizationTest.txt
# conformance vectors against unicodedata.normalize('NFC', ...); that
# gate is a documented slice-1 follow-up (SAN-883), NOT silently
# skipped -- this module only records the runtime Unicode version.
UNICODE_VERSION = unicodedata.unidata_version


class UnicodeVersionError(RuntimeError):
    pass


if tuple(int(p) for p in UNICODE_VERSION.split(".")) < (15, 0, 0):
    raise UnicodeVersionError(
        f"reference/primitives.py requires unicodedata >= 15.0.0 "
        f"(spec section 2.1 step 2); got {UNICODE_VERSION} on {sys.version}"
    )


# --------------------------------------------------------------------------
# Abstention (spec section 0: "abstain(cause): cause in {malformed_mention,
# unextractable}; an abstained product makes its FIELD PARTIAL (symmetric
# rule)").
# --------------------------------------------------------------------------

class Abstain(Exception):
    """Raised by any primitive/extraction routine that must abstain. Cause
    is one of 'malformed_mention' | 'unextractable'."""

    def __init__(self, cause: str):
        super().__init__(cause)
        self.cause = cause


class EvaluatorError(Exception):
    """EVALUATOR_ERROR(evaluator_exception) per LOCKED A1 (spec section 0:
    "Unexpected exceptions = EVALUATOR_ERROR(evaluator_exception)")."""


# --------------------------------------------------------------------------
# Token (section 2.2)
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Token:
    raw: str
    fold: str
    start: int
    end: int
    kind: str  # WORD | NUMBER | PCT100 | PUNCT


Span = Tuple[int, int]  # token index range [start, end) into a token list


# --------------------------------------------------------------------------
# Dec (section 0 / 2.4) -- BigInt only, never float.
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Dec:
    coefficient: int
    scale: int


def canonicalize_dec(d: Dec) -> Dec:
    """while scale > 0 and coefficient % 10 == 0: coefficient /= 10; scale -= 1"""
    coeff, scale = d.coefficient, d.scale
    if coeff == 0:
        return Dec(0, 0)
    while scale > 0 and coeff % 10 == 0:
        coeff //= 10
        scale -= 1
    return Dec(coeff, scale)


def _digit_count(n: int) -> int:
    n = abs(n)
    return len(str(n)) if n != 0 else 1


def dec_cmp(a: Dec, b: Dec) -> int:
    """sign(a.coefficient * 10^(s-a.scale) - b.coefficient * 10^(s-b.scale)),
    s = max(a.scale, b.scale). BigInt only; never floats."""
    s = max(a.scale, b.scale)
    av = a.coefficient * (10 ** (s - a.scale))
    bv = b.coefficient * (10 ** (s - b.scale))
    return (av > bv) - (av < bv)


def dec_convert(d: Dec, factor: int) -> Dec:
    return canonicalize_dec(Dec(d.coefficient * factor, d.scale))


def dec_zero() -> Dec:
    return Dec(0, 0)


def dec_to_str(d: Dec) -> str:
    """Canonical-form decimal string per ATOMENC_v1 section 7 dec():
    minimal digits, '-' prefix, scale rendered as a '.' fraction, no
    exponent."""
    d = canonicalize_dec(d)
    neg = d.coefficient < 0
    digits = str(abs(d.coefficient))
    if d.scale == 0:
        s = digits
    else:
        if len(digits) <= d.scale:
            digits = "0" * (d.scale - len(digits) + 1) + digits
        s = digits[: len(digits) - d.scale] + "." + digits[len(digits) - d.scale :]
    return ("-" + s) if neg else s


# --------------------------------------------------------------------------
# Interval (section 0)
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Interval:
    lo: Optional[Dec]
    lo_open: bool
    hi: Optional[Dec]
    hi_open: bool
    unit: str  # unit-group name, or "currency:<CODE>", or "" (dimensionless)


# --------------------------------------------------------------------------
# Bool AST (section 0) -- TOP | BOTTOM | Atom | AND | OR | NOT
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class TOP:
    pass


@dataclass(frozen=True)
class BOTTOM:
    pass


@dataclass(frozen=True)
class TermAtom:
    terms: FrozenSet[str]
    pol: int  # 0 POS, 1 NEG
    restrictive: int  # 0/1


@dataclass(frozen=True)
class MeasureAtom:
    qty: Tuple[str, FrozenSet[str], str]  # (facet, subject_key, unit_group)
    intervals: Tuple[Interval, ...]


@dataclass(frozen=True)
class UnknownAtom:
    cause: str


@dataclass(frozen=True)
class And:
    children: Tuple["Bool", ...]


@dataclass(frozen=True)
class Or:
    children: Tuple["Bool", ...]


@dataclass(frozen=True)
class Not:
    child: "Bool"


Bool = Union[TOP, BOTTOM, TermAtom, MeasureAtom, UnknownAtom, And, Or, Not]
Atom = Union[TermAtom, MeasureAtom, UnknownAtom]

TOP_ = TOP()
BOTTOM_ = BOTTOM()

# Cause (section 0)
MALFORMED_MENTION = "malformed_mention"
CONDITION_UNDECIDABLE = "condition_undecidable"
UNEXTRACTABLE = "unextractable"


def worst_cause(cs) -> str:
    """def worst_cause(cs) = malformed_mention if present else condition_undecidable"""
    cs = list(cs)
    return MALFORMED_MENTION if MALFORMED_MENTION in cs else CONDITION_UNDECIDABLE


# --------------------------------------------------------------------------
# Extent / Hit / CondNode / Frame / Roles / Evidence / Obligation (section 0)
# --------------------------------------------------------------------------

UNSPECIFIED, UNIVERSAL, EXISTENTIAL = 0, 1, 2
POS, NEG = 0, 1
EXPLICIT, IMPLICIT = 0, 1
GRANT, RESTRICTION = 0, 1


@dataclass(frozen=True)
class Extent:
    facet: str
    subject: FrozenSet[str]
    object: FrozenSet[str]
    modifiers: FrozenSet[Tuple[str, FrozenSet[str]]]
    quant: int  # 0|1|2
    polarity: int  # 0|1
    values: Optional[Tuple[Interval, ...]]


@dataclass(frozen=True)
class Hit:
    facet: str
    span: Span
    is_deny: bool
    trigger_key: Tuple[str, ...]


@dataclass(frozen=True)
class CondNode:
    formula: Bool
    force: int  # 0 GRANT, 1 RESTRICTION
    kind: str  # IF | ONLY_IF | SUBJECT_TO


@dataclass(frozen=True)
class Frame:
    field_id: str
    frame_id: int
    extent: Extent
    conds: Tuple[CondNode, ...]
    assertive: bool
    # Per-conjunct subject structure (spec 3.5: explicit obligations and
    # requirement evidence are "per governed conjunct"; the flat
    # extent.subject union loses conjunct boundaries, so they are carried
    # here alongside their COMPOUND_HEAD-rule heads).
    subject_conjuncts: Tuple[FrozenSet[str], ...] = ()
    subject_conjunct_heads: Tuple[Optional[str], ...] = ()
    # For approval_requirement-facet frames: the parse_bool product over
    # the required span (restrictive=True per spec 3.5 "an explicit
    # requirement IS a necessary condition"). None for other facets.
    req_formula: Optional[Bool] = None


@dataclass(frozen=True)
class Roles:
    subject: Span
    object: Optional[Span]
    value: Optional[Span]
    pattern: str  # OP | PASSIVE | COORD | ACTIVE


@dataclass(frozen=True)
class Evidence:
    field_id: str
    frame_id: int
    span_id: int
    governed_identity: Extent
    domain: Bool
    asserted_formula: Bool
    assertion_polarity: int


@dataclass(frozen=True)
class Obligation:
    kind: int  # 0 explicit, 1 implicit
    governed_identity: Extent
    source_activation_domain: Bool
    applicability_scope: Bool
    requirement_formula: Bool
    source_polarity: int
    trivial: bool
    source_frame_ids: Tuple[int, ...]


def eff(e: Evidence) -> Bool:
    """def eff(e: Evidence) = e.asserted_formula if e.assertion_polarity == 0
    else NOT(e.asserted_formula)"""
    return e.asserted_formula if e.assertion_polarity == 0 else Not(e.asserted_formula)


def eff_quant(q: int) -> int:
    """TOTAL: eff_quant(UNSPECIFIED)=UNIVERSAL; eff_quant(UNIVERSAL)=UNIVERSAL;
    eff_quant(EXISTENTIAL)=EXISTENTIAL."""
    return EXISTENTIAL if q == EXISTENTIAL else UNIVERSAL


# --------------------------------------------------------------------------
# 2.1 normalize
# --------------------------------------------------------------------------

def normalize(raw: bytes) -> str:
    text = raw.decode("utf-8")  # invalid -> UnicodeDecodeError, gated upstream
    text = unicodedata.normalize("NFC", text)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    return text


# --------------------------------------------------------------------------
# 2.3 stem_v1
# --------------------------------------------------------------------------

def stem_v1(w: str) -> str:
    for rule in T.stem_v1_rules:
        suffix = rule["if_ends"]
        if not w.endswith(suffix):
            continue
        if len(w) < rule["min_len"]:
            continue
        not_ends = rule.get("not_ends")
        if not_ends and w.endswith(not_ends):
            continue
        only_after = rule.get("only_after")
        if only_after:
            prefix = w[: -len(suffix)]
            if not any(prefix.endswith(a) for a in only_after):
                continue
        return w[: -len(suffix)] + rule["replace_with"]
    return w


def ascii_lower(s: str) -> str:
    """Spec section 2.3: ascii_lower maps ONLY ASCII A-Z (0x41-0x5A) to
    a-z; every other code point -- including non-ASCII letters -- passes
    through UNCHANGED. This is deliberately narrower than Python's
    str.lower(), which folds per the full Unicode casing tables (e.g.
    KELVIN SIGN U+212A -> ASCII 'k'; LATIN CAPITAL LETTER I WITH DOT
    ABOVE U+0130 -> 'i' + COMBINING DOT ABOVE, two code points) and would
    manufacture token-fold collisions the spec's discipline does not
    intend."""
    return "".join(chr(ord(ch) + 32) if "A" <= ch <= "Z" else ch for ch in s)


def fold_of(raw: str) -> str:
    return stem_v1(ascii_lower(raw))


# --------------------------------------------------------------------------
# 2.2 tokenize
# --------------------------------------------------------------------------

_APOSTROPHES = {"'", "\u2019"}  # ASCII apostrophe + RIGHT SINGLE QUOTATION MARK
_CURRENCY_SYMBOLS = tuple(T.currency_symbols_v1.keys())


def _is_digit(ch: str) -> bool:
    return "0" <= ch <= "9"


def _match_number_core(text: str, i: int) -> Optional[int]:
    """Greedy match of the `core` grammar production starting at i:
    core := digit+ | digit{1,3} ("," digit{3})+ | core "." digit+
    Returns the end index of the matched core, or None if no digit at i.
    """
    n = len(text)
    if i >= n or not _is_digit(text[i]):
        return None

    # Attempt the comma-grouped alternative first (maximal munch: when it
    # matches at least one group it always consumes >= the plain digit+
    # alternative).
    j = i
    lead = 0
    while j < n and _is_digit(text[j]) and lead < 3:
        j += 1
        lead += 1
    grouped_end = None
    k = j
    groups = 0
    # spec 2.2's `digit` is ASCII 0-9; broad str.isdigit() admitted
    # non-ASCII decimals (silent misparse) and isdigit-True/int()-invalid
    # characters (unhandled ValueError through evaluate()) -- SAN-895.
    while k < n and text[k] == "," and k + 3 < n + 1 \
            and len(text[k + 1 : k + 4]) == 3 and all(_is_digit(c) for c in text[k + 1 : k + 4]) \
            and (k + 4 == n or not _is_digit(text[k + 4])):
        k += 4
        groups += 1
    if groups >= 1:
        grouped_end = k

    if grouped_end is not None:
        end = grouped_end
    else:
        # plain digit+ alternative
        end = i
        while end < n and _is_digit(text[end]):
            end += 1

    # optional ".", digit+ fraction (core "." digit+) -- at most one "."
    if end < n and text[end] == "." and end + 1 < n and _is_digit(text[end + 1]):
        end += 1
        while end < n and _is_digit(text[end]):
            end += 1

    return end


def _match_pct100(text: str, i: int) -> Optional[int]:
    n = len(text)
    if text[i : i + 3] != "100":
        return None
    if i > 0 and _is_digit(text[i - 1]):
        return None
    if i + 3 >= n or text[i + 3] != "%":
        return None
    return i + 4


def _match_word(text: str, i: int) -> Optional[int]:
    n = len(text)
    if not text[i].isalpha():
        return None
    end = i + 1
    while end < n and text[end].isalpha():
        end += 1
    # internal apostrophes joined
    while end < n and text[end] in _APOSTROPHES and end + 1 < n and text[end + 1].isalpha():
        end += 1
        while end < n and text[end].isalpha():
            end += 1
    return end


def _raw_tokenize(text: str) -> list:
    """Rules 1-5 of section 2.2, one left-to-right scan. Returns Token
    objects with fold="" (fold is computed in a later pass, after
    contraction expansion, per spec)."""
    tokens = []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch in T.ws_v1:
            i += 1
            continue
        pct_end = _match_pct100(text, i)
        if pct_end is not None:
            tokens.append(Token(text[i:pct_end], "", i, pct_end, "PCT100"))
            i = pct_end
            continue
        # NUMBER: [currency] [sign] core [pct]
        j = i
        if j < n and text[j] in _CURRENCY_SYMBOLS:
            j += 1
        if j < n and text[j] in "+-":
            j += 1
        core_end = _match_number_core(text, j)
        if core_end is not None:
            end = core_end
            if end < n and text[end] == "%":
                end += 1
            tokens.append(Token(text[i:end], "", i, end, "NUMBER"))
            i = end
            continue
        word_end = _match_word(text, i)
        if word_end is not None:
            raw = text[i:word_end].replace("\u2019", "'")
            tokens.append(Token(raw, "", i, word_end, "WORD"))
            i = word_end
            continue
        tokens.append(Token(ch, "", i, i + 1, "PUNCT"))
        i += 1
    return tokens


def _expand_contractions(tokens: list) -> list:
    out = []
    for tok in tokens:
        if tok.kind == "WORD":
            key = ascii_lower(tok.raw)
            expansion = T.contractions_v1.get(key)
            if expansion:
                first = True
                for word in expansion:
                    if first:
                        out.append(Token(tok.raw, fold_of(word), tok.start, tok.end, "WORD"))
                        first = False
                    else:
                        out.append(Token("", fold_of(word), tok.end, tok.end, "WORD"))
                continue
        out.append(Token(tok.raw, fold_of(tok.raw) if tok.raw else "", tok.start, tok.end, tok.kind))
    return out


def tokenize(text: str) -> list:
    """One left-to-right scan (rules 1-5), then a POST-PASS contraction
    expansion, then fold computed for every token. fold =
    stem_v1(ascii_lower(token)) applied AFTER expansion."""
    tokens = _raw_tokenize(text)
    tokens = _expand_contractions(tokens)
    return tokens


def fold_sequence(entry: str) -> Tuple[str, ...]:
    """Tokenize a table entry string through the real tokenizer and return
    the resulting fold sequence. Spec section 1: "Multi-token entries
    match as FOLDED TOKEN SEQUENCES after contraction expansion (the
    loader tokenizes each entry once at load)." Applies uniformly to
    single-word entries too: stemming can change a single word's fold
    (e.g. "needs" -> "need"), so every table entry -- not just
    multi-word ones -- must be compiled through tokenize()."""
    return tuple(t.fold for t in tokenize(entry))


# --------------------------------------------------------------------------
# 2.4 Numbers -> Dec
# --------------------------------------------------------------------------

def parse_dec(lexeme: str) -> Dec:
    s = lexeme
    for sym in _CURRENCY_SYMBOLS:
        if s.startswith(sym):
            s = s[len(sym) :]
            break
    sign = 1
    if s.startswith("+"):
        s = s[1:]
    elif s.startswith("-"):
        sign = -1
        s = s[1:]
    if s.endswith("%"):
        s = s[:-1]
    if "." in s:
        int_part, frac_part = s.split(".", 1)
    else:
        int_part, frac_part = s, ""
    int_digits = int_part.replace(",", "")
    # spec 2.2's `digit` is ASCII 0-9; broad str.isdigit() admitted
    # non-ASCII decimals (silent misparse) and isdigit-True/int()-invalid
    # characters (unhandled ValueError through evaluate()) -- SAN-895.
    if (
        not int_digits
        or not all(_is_digit(ch) for ch in int_digits)
        or (frac_part and not all(_is_digit(ch) for ch in frac_part))
    ):
        raise Abstain(MALFORMED_MENTION)
    digits = int_digits + frac_part
    coeff = sign * int(digits) if digits else 0
    scale = len(frac_part)
    d = canonicalize_dec(Dec(coeff, scale))
    if _digit_count(d.coefficient) > T.MAX_DEC_DIGITS or d.scale > T.MAX_DEC_SCALE:
        raise Abstain(MALFORMED_MENTION)
    return d


def unit_of(tok: Token) -> Optional[dict]:
    """2.4: the WORD immediately after the number whose fold is a
    T.units_v1 key -> {group, factor}."""
    if tok.kind != "WORD":
        return None
    return T.units_v1.get(tok.fold)


def currency_code_of(number_token_raw: str) -> Optional[str]:
    for sym, code in T.currency_symbols_v1.items():
        if number_token_raw.startswith(sym):
            return code
    return None


# --------------------------------------------------------------------------
# 2.5 parse_values
# --------------------------------------------------------------------------

APPROX_FOLDS = None  # populated by _compile_folds() below


def _content_prefix_folds(tokens, end_idx):
    """Longest T.comparators_v1 folded token-sequence match ending
    immediately at tokens[end_idx] (i.e. immediately preceding the
    NUMBER/PCT100 token at index end_idx)."""
    best = None
    for entry in COMPARATORS_V1:
        seq = entry["folds"]
        ln = len(seq)
        if end_idx - ln < 0:
            continue
        window = tuple(t.fold for t in tokens[end_idx - ln : end_idx])
        if window == seq:
            if best is None or ln > best[0]:
                best = (ln, entry)
    return best[1] if best else None


def _is_filler_token(tok: Token) -> bool:
    return tok.kind == "PUNCT" and tok.raw in T.structural_punctuation


def parse_values(value_span_tokens) -> Optional[Tuple[Interval, ...]]:
    """value_span_tokens: list[Token] for the span under consideration.
    Returns a tuple of Interval (list[Interval] in the spec's notation),
    or None if no NUMBER/PCT100 token is present, or raises Abstain on a
    malformed span."""
    number_positions = [
        idx for idx, t in enumerate(value_span_tokens) if t.kind in ("NUMBER", "PCT100")
    ]
    if not number_positions:
        return None
    if len(number_positions) > 1:
        raise Abstain(MALFORMED_MENTION)

    idx = number_positions[0]
    num_tok = value_span_tokens[idx]

    # APPROX_v1 token immediately before the number (or its sign/currency)
    if idx > 0:
        prev = value_span_tokens[idx - 1]
        if prev.fold in APPROX_FOLDS:
            raise Abstain(MALFORMED_MENTION)

    comparator = _content_prefix_folds(value_span_tokens, idx)

    if num_tok.kind == "PCT100":
        v = parse_dec("100")
        unit_group = ""
    else:
        v = parse_dec(num_tok.raw)
        unit_group = ""
        cur = currency_code_of(num_tok.raw)
        if cur:
            unit_group = f"currency:{cur}"

    consumed_hi = idx + 1
    if consumed_hi < len(value_span_tokens):
        u = unit_of(value_span_tokens[consumed_hi])
        if u is not None:
            group, factor = u["group"], u["factor"]
            v = dec_convert(v, factor)
            unit_group = group
            consumed_hi += 1

    consumed_lo = idx
    if comparator is not None:
        consumed_lo = idx - len(comparator["folds"])

    # step 5: leftover non-filler tokens in the span -> abstain
    for i, t in enumerate(value_span_tokens):
        if consumed_lo <= i < consumed_hi:
            continue
        if _is_filler_token(t):
            continue
        raise Abstain(MALFORMED_MENTION)

    if comparator is None:
        return (Interval(v, False, v, False, unit_group),)

    tmpl = comparator["interval"]

    def bound(spec):
        if spec is None:
            return None
        if spec == "v":
            return v
        if spec == "0":
            return dec_zero()
        raise EvaluatorError(f"unrecognized comparator bound template {spec!r}")

    return (
        Interval(
            bound(tmpl["lo"]),
            tmpl["lo_open"],
            bound(tmpl["hi"]),
            tmpl["hi_open"],
            unit_group,
        ),
    )


# --------------------------------------------------------------------------
# 2.6 sentences / segments / span accounting
# --------------------------------------------------------------------------

def _token_starts_line(text: str, tok: Token) -> bool:
    if tok.start == 0:
        return True
    # every non-newline whitespace char between the last newline and the
    # token means the token still "starts" its line for the bullet rule;
    # walking past beginning-of-field (i < 0) is equally line-starting
    # (an indented marker on the field's first line).
    i = tok.start - 1
    while i >= 0 and text[i] != "\n" and text[i] in T.ws_v1:
        i -= 1
    return i < 0 or text[i] == "\n"


def list_marker_indices(tokens, text: Optional[str]) -> FrozenSet[int]:
    """e10 (spec 2.6): indices of line-initial structural LIST MARKER
    tokens -- a '-'/'*' PUNCT, or a NUMBER plus its immediately following
    '.' PUNCT, at the start of a line. The marker belongs to the item's
    sentence and is accounted like structural punctuation; the numbered
    marker's period is NOT a sentence terminator. Requires the original
    `text` for line positions; without it, no markers are identified."""
    if text is None:
        return frozenset()
    marked = set()
    for i, tok in enumerate(tokens):
        if not _token_starts_line(text, tok):
            continue
        if tok.kind == "PUNCT" and tok.raw in ("-", "*"):
            marked.add(i)
        elif (
            tok.kind == "NUMBER"
            and i + 1 < len(tokens)
            and tokens[i + 1].kind == "PUNCT"
            and tokens[i + 1].raw == "."
        ):
            marked.add(i)
            marked.add(i + 1)
    return frozenset(marked)


def sentences(tokens, text: Optional[str] = None):
    """Sentence ends at PUNCT '.', '!', '?' whose next raw char is WS_v1 or
    EOF (numeric '.' is inside NUMBER tokens, so it can never be a
    sentence-terminator PUNCT token). LIST MARKERS (e10): a line whose
    first token is '-', '*', or NUMBER+'.' starts a new sentence, and the
    marker BELONGS TO that sentence; the numbered marker's period is NOT
    a sentence terminator, so '1. Items are refundable.' is ONE sentence,
    behaviorally identical to '- Items are refundable.'. Requires the
    original `text` for line positions; without it only the terminator
    rule applies. Returns list[list[Token]]."""
    markers = list_marker_indices(tokens, text)
    out = []
    cur = []
    n = len(tokens)
    for i, tok in enumerate(tokens):
        if cur and i in markers and (i == 0 or (i - 1) not in markers):
            # a marker's FIRST token opens the item's sentence
            out.append(cur)
            cur = []
        cur.append(tok)
        if (
            tok.kind == "PUNCT"
            and tok.raw in T.sentence_terminators
            and i not in markers  # e10: the numbered marker's '.' never terminates
        ):
            # SPLIT_v1 (spec 2.6): terminates ONLY when the next raw
            # character is WS_v1 or EOF -- e.g. "refundable.Items" does
            # NOT split. `text` answers this directly; without it,
            # token adjacency is an exact proxy, since the tokenizer
            # only ever skips whitespace BETWEEN two token spans (every
            # other character is captured into some token) -- a gap
            # before the next token (or no next token at all) is
            # equivalent to "next raw char is WS_v1 or EOF".
            if text is not None:
                terminates = tok.end == len(text) or text[tok.end] in T.ws_v1
            else:
                terminates = i + 1 >= n or tokens[i + 1].start > tok.end
            if terminates:
                out.append(cur)
                cur = []
    if cur:
        out.append(cur)
    return out


def segments(sentence_tokens):
    """Segments split at T.structural_punctuation PUNCT tokens (segment
    boundaries themselves are dropped, matching FILLER treatment of
    structural punctuation in structural positions)."""
    out = []
    cur = []
    for tok in sentence_tokens:
        if tok.kind == "PUNCT" and tok.raw in T.structural_punctuation:
            out.append(cur)
            cur = []
        else:
            cur.append(tok)
    out.append(cur)
    return out


def is_content_token(tok: Token) -> bool:
    """Content token := fold length >= 3 and fold not in T.stop_v1."""
    return len(tok.fold) >= 3 and tok.fold not in STOP_V1


def content_tokens(tokens):
    return [t for t in tokens if is_content_token(t)]


def is_interrogative(sentence_tokens) -> bool:
    for tok in reversed(sentence_tokens):
        if tok.kind == "PUNCT" and tok.raw in T.sentence_terminators:
            return tok.raw == "?"
        if tok.kind != "PUNCT":
            break
    return False


# --------------------------------------------------------------------------
# Compiled fold indices (spec section 1: "the loader tokenizes each entry
# once at load"). Built here, after tokenize() is defined, to avoid a
# circular import between tables.py and primitives.py.
# --------------------------------------------------------------------------

def _compile_single(words) -> frozenset:
    return frozenset(fold_sequence(w) for w in words)


def _compile_pairs(pairs) -> frozenset:
    return frozenset(frozenset(fold_sequence(w)[0] for w in pair) for pair in pairs)


STOP_V1 = frozenset(fold_sequence(w)[0] for w in T.raw["stop_v1"])
DEFINITIVE_V1 = _compile_single(T.raw["definitive_v1"])
HEDGE_V1 = _compile_single(T.raw["hedge_v1"])
HEDGE_WINDOW_BOUNDARIES = frozenset(fold_sequence(w)[0] for w in T.raw["hedge_window_boundaries"])
NEGATORS_V1 = frozenset(fold_sequence(w)[0] for w in T.raw["negators_v1"])
NEGATION_EXCEPTIONS = frozenset(
    tuple(fold_sequence(w)[0] for w in pair) for pair in T.raw["negation_exceptions"]
)
QUANT_UNIVERSAL = frozenset(fold_sequence(w)[0] for w in T.raw["quant_v1"]["universal"])
QUANT_EXISTENTIAL = frozenset(fold_sequence(w)[0] for w in T.raw["quant_v1"]["existential"])
QUANT_ABSTAIN = frozenset(fold_sequence(w)[0] for w in T.raw["quant_v1"]["abstain"])
MODAL_ABSTAIN_V1 = frozenset(fold_sequence(w)[0] for w in T.raw["modal_abstain_v1"])
ADJUNCT_PREPOSITIONS_V1 = frozenset(fold_sequence(w)[0] for w in T.raw["adjunct_prepositions_v1"])
RELATIVE_MARKERS_V1 = frozenset(fold_sequence(w)[0] for w in T.raw["relative_markers_v1"])
EXCL_V1 = frozenset(
    frozenset(fold_sequence(w)[0] for w in pair) for pair in T.raw["excl_v1"]
)
GENERIC_BENEFIT_TRIGGERS_V1 = frozenset(fold_sequence(w)[0] for w in T.raw["generic_benefit_triggers_v1"])
FACETPROJ_V1 = {fold_sequence(k)[0]: v for k, v in T.raw["facetproj_v1"].items()}
CONCEPT_V1 = {fold_sequence(k)[0]: v for k, v in T.raw["concept_v1"].items()}


def _bool_atom_normalize(word: str) -> str:
    """The normalized form Bool-atom terms carry: post-stem
    (fold_sequence) then post-CONCEPT_v1. e9 (spec 4.2): COMPLEMENT_v1
    pair lookup operates on this SAME normalized form."""
    fold = fold_sequence(word)[0]
    return CONCEPT_V1.get(fold, fold)


COMPLEMENT_V1 = tuple(
    tuple(_bool_atom_normalize(w) for w in pair) for pair in T.raw["complement_v1"]
)
# e7: participle-vs-stative trigger classification comes from the tables
# artifact (folded forms; never a code list).
PARTICIPLE_TRIGGERS_V1 = frozenset(
    fold_sequence(w)[0] for w in T.raw["participle_triggers_v1"]
)
APPROX_V1 = frozenset(fold_sequence(w)[0] for w in T.raw["approx_v1"])
APPROX_FOLDS = APPROX_V1

CONDITION_OPERATORS_V1 = tuple(
    {
        "folds": fold_sequence(" ".join(op["tokens"])),
        "kind": op["kind"],
        "polarity": op["polarity"],
        "force": GRANT if op["force"] == "grant" else RESTRICTION,
    }
    for op in T.raw["condition_operators_v1"]
)

COMPARATORS_V1 = tuple(
    {"folds": fold_sequence(" ".join(entry["tokens"])), "interval": entry["interval"]}
    for entry in T.raw["comparators_v1"]
)

# Trigger index: folded token sequence -> list[(facet, is_deny)]
_trig: dict = {}
for _facet_name, _facet in T.facets_v1.items():
    for _trig_word in _facet["triggers"]:
        _key = fold_sequence(_trig_word)
        _trig.setdefault(_key, []).append((_facet_name, False))
    for _trig_word in _facet["deny_triggers"]:
        _key = fold_sequence(_trig_word)
        _trig.setdefault(_key, []).append((_facet_name, True))
TRIGGER_INDEX = _trig
MAX_TRIGGER_LEN = max((len(k) for k in TRIGGER_INDEX), default=1)
