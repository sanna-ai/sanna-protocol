# ALGORITHM v4 (DRAFT 5.3): executable reference semantics for C1-C5 at cv=11 / CHECKS_VERSION 11 -- STANDALONE

> STATUS: DRAFT 5.3 -- three NARROW errata from Sol's fa2a50a delta
> review (adjudications adopted; no design reopening): (e10) LIST MARKERS
> -- a line-initial bullet/number marker ('-', '*', NUMBER+'.') begins the
> item's sentence and BELONGS to it as a structural list marker; the
> marker's '.' is NOT a sentence terminator ('1. Items are refundable.' is
> ONE sentence, identical in behavior to '- Items are refundable.'; the
> prior marker-only-sentence reading is REJECTED); (e11) C2-LOCAL PARTIAL
> (operator-ratified text): C2 field PARTIAL is local to C2's own
> normalization/tokenization/lexical scan, plus governed-output
> interrogatives; C2 does NOT inherit proposition-frame extraction
> partiality; (e12) ENVELOPE SCOPING clarified as already normative per
> A2: cap breaches attach ONLY to checks consuming the breached field, and
> task/engine overflows ONLY to the owning check -- other checks evaluate
> normally; there is no global envelope result.
> DRAFT 5.2 was: three NARROW errata directed by Sol's PR-52
> implementation review (no design reopening): (e7) PARTICIPLE_TRIGGERS_v1
> moves into the shared tables artifact (passive-voice participle vs
> stative-adjective trigger classification is DATA, never a code list);
> (e8) `within` dual-role value span defined (sec 3.2 step 7 note); (e9)
> the ENTAILS structural flag check is generalized per the RATIFIED
> symmetric principle: ANY atom pairing with mismatched restrictive flags
> provides no entailment, and an H atom (either flag) with no flag-matching
> F counterpart on its variable -> NO (a restrictive-only evidence formula
> never entails AND(grant, restrictive)).
> DRAFT 5.1 was: MECHANICAL ERRATA ONLY, then
> dispatch: (e1) the flagship compliant variant is "available only if
> approved" (restrictive flag matches the explicit requirement); (e2)
> support() has an explicit return and total recursion (TOP/BOTTOM
> canonicalized away; a residual NOT(...) subtree is a TERMINAL support
> unit -- closing the unless/except path); (e3) Roles.value is defined
> with pinned unique-maximal-span extraction; (e4) C3 checks
> uncompilable(E) before UNSAT(E), accumulates causes, and never reads
> UNKNOWN as boolean; (e5) eff_quant() is a named total function and C4
> reads a.extent.quant; (e6) FREEZE v18.5 header cleaned. DRAFT 5 was
> the final bounded execution pass; this is the dispatch artifact. Draft-5 closures: (1) CONCEPT_v1 establishes
> lexical identity between approval/approved in condition atoms;
> satisfaction ALSO requires structurally matching restrictive flags --
> "only if approved" satisfies an explicit approval requirement; plain
> "if approved" does not; (2) RESTRICTION DIRECTION PRESERVED --
> atoms introduced under restriction-force operators carry a structural
> `restrictive` flag that survives aggregation and is enforced in ENTAILS
> (flag mismatch = structural NO), so "may enter if verified" can never
> satisfy "may enter only if verified"; (3) identity_relation takes
> (extent, domain) pairs -- no Frame/Extent type mismatch; (4) POST-MODAL
> NEGATION -- a negator immediately following the trigger negates the
> frame, so "Users can't enter" (-> can + not) is a NEG permission frame;
> (5) units_v1 is a flat token map (day -> {group, factor}) matching the
> JSON shape exactly; (6) THIS DOCUMENT IS STANDALONE -- every previously
> "unchanged" section is inlined; no reference to prior drafts is
> normative. Tables artifact: **ALGORITHM-v4-tables-v1.json, SHA-256
> 0a18dd94bc811bb3166a4f8812e78f2b053a9f8f083b781a21fb0f8371f54ecc**.
> C5 is EXCLUDED from vertical slice 1 (C_COV uncalibrated).
> Authority: DECISION-01 + A1 (LOCKED) own ontology/enforcement; A2 rev 3
> owns wrapper scope/applicability; FREEZE v18.6 owns per-check
> outcome/reason tables and attestation schemas. This document owns
> EXECUTABLE SEMANTICS. Reference implementation location (operator
> decision, round 22): `sanna-protocol/reference/`.
> LAYERS: L1 protocol invariants; L2 structured-domain deterministic
> checks (only halt/warn deployment); L3 free-text advisory
> (`_unattested`, log only). COMPETENCE CLAIM: no known bypass within the
> authenticated, versioned grammar and supported input domain; outside
> it, NOT_EVALUATED, failing closed per policy. STOP RULE: a defect
> needing structural NLP redesign descopes the check for v1.6.
> EXIT CRITERIA: generated fixtures byte-identical on Python and
> TypeScript; measured precision/recall/abstention/false-violation rates
> accepted by the operator; runtime within caps.

## 0. Conventions and types

Deterministic, side-effect-free pseudocode; written order is evaluation
order. `str` = NFC code points. All integers are arbitrary precision
(Python int / TypeScript BigInt). `T` = the parsed shared tables
artifact. `abstain(cause)`: cause in {malformed_mention, unextractable};
an abstained product makes its FIELD PARTIAL (symmetric rule). Unexpected
exceptions = EVALUATOR_ERROR(evaluator_exception) per LOCKED A1.

```
type Token   = {raw: str, fold: str, start: int, end: int,
                kind: WORD|NUMBER|PCT100|PUNCT}
type Dec     = {coefficient: BigInt, scale: int >= 0}
               # value = coefficient / 10^scale; CANONICAL FORM required:
               # while scale > 0 and coefficient % 10 == 0:
               #   coefficient /= 10; scale -= 1; zero = {0, 0};
               # digit_count > MAX_DEC_DIGITS or scale > MAX_DEC_SCALE ->
               # abstain('malformed_mention')
type Interval= {lo: Dec|None, lo_open: bool, hi: Dec|None, hi_open: bool,
                unit: str}                    # None bound = unbounded
type Extent  = {facet: str, subject: frozenset[str], object: frozenset[str],
                modifiers: frozenset[(rel: str, objset: frozenset[str])],
                quant: 0|1|2,                 # UNSPECIFIED|UNIVERSAL|EXISTENTIAL
                polarity: 0|1,                # POS|NEG
                values: list[Interval]|None}
type Hit     = {facet: str, span: Span, is_deny: bool,
                trigger_key: tuple[str]}      # FOLDED trigger token sequence
type CondNode= {formula: Bool, force: 0|1,    # GRANT|RESTRICTION
                kind: IF|ONLY_IF|SUBJECT_TO}
type Frame   = {field_id: str, frame_id: int, extent: Extent,
                conds: list[CondNode], assertive: bool}
type Bool    = TOP | BOTTOM | Atom | AND(children) | OR(children) | NOT(child)
type Atom    = TermAtom{terms: frozenset[str], pol: 0|1, restrictive: 0|1}
             | MeasureAtom{qty: (facet, subject_key, unit_group),
                           intervals: list[Interval]}
             | UnknownAtom{cause}
type Rel3    = COMPARABLE | INERT | UNDECIDABLE(cause)      # TOTAL
type Cause   = malformed_mention | condition_undecidable
def worst_cause(cs) = malformed_mention if present else condition_undecidable
type Evidence= {field_id, frame_id, span_id, governed_identity: Extent,
                domain: Bool, asserted_formula: Bool,
                assertion_polarity: 0|1}
type Obligation = {kind: 0|1,                 # explicit|implicit
                governed_identity: Extent, source_activation_domain: Bool,
                applicability_scope: Bool, requirement_formula: Bool,
                source_polarity: 0|1, trivial: bool, source_frame_ids}
def eff(e: Evidence) = e.asserted_formula if e.assertion_polarity == 0
                       else NOT(e.asserted_formula)
def eff_quant(q) -> UNIVERSAL|EXISTENTIAL:          # TOTAL (e5)
    # eff_quant(UNSPECIFIED) = UNIVERSAL (pinned generic-universal
    # reading); eff_quant(UNIVERSAL) = UNIVERSAL;
    # eff_quant(EXISTENTIAL) = EXISTENTIAL. Every quantifier-strength
    # comparison in this document calls eff_quant; the name eff() alone
    # is reserved for Evidence.
```

## 1. Tables

Both SDKs vendor `ALGORITHM-v4-tables-v1.json` (sha256
0a18dd94bc811bb3166a4f8812e78f2b053a9f8f083b781a21fb0f8371f54ecc),
verify the hash at build time, and load EVERY table from it: constants
(incl. MAX_DEC_DIGITS/MAX_DEC_SCALE, W_HEDGE, NEG_WINDOW, ENV_* and
MAX_* caps), WS_v1 code points, STOP_v1, DEFINITIVE_v1 + HEDGE_v1 (exact
v0 seeds), hedge window boundaries, negators + exceptions, QUANT_v1,
COND_OPS_v1 (kind/polarity/force), MODAL_ABSTAIN, adjunct prepositions,
relative markers, EXCL_v1, COMPLEMENT_v1, UNITS_v1 (flat token ->
{group, factor}), currency symbols, COMPARATORS_v1, FACETS_v1,
GENERIC_BENEFIT_TRIGGERS, FACETPROJ_v1, CONCEPT_v1, CONTRACTIONS_v1,
APPROX_v1, STEM_v1 rules, COMPOUND_HEAD rule, structural punctuation,
sentence terminators. Multi-token entries match as FOLDED TOKEN
SEQUENCES after contraction expansion (the loader tokenizes each entry
once at load). Table misses ABSTAIN. Additions = CHECKS_VERSION bump +
regenerated fixtures, justified only by calibration measurement.

## 2. Text primitives (exact, ordered)

### 2.1 normalize(raw: bytes) -> str
1. utf8_decode (invalid -> malformed input, gated upstream). 2. NFC via
a PROVEN Unicode-15.0.0 normalizer (vendor-or-refuse; unassigned code
points identity-mapped). 3. "\r\n" -> "\n"; remaining "\r" -> "\n".

### 2.2 tokenize(text) -> list[Token]   (one left-to-right scan)
First matching rule at each position:
1. WS_v1 code point: skip.
2. digits "100" + "%": one PCT100 token.
3. NUMBER: optional adjacent currency symbol; optional +/-; digits with
   optional comma groups and one optional "." fraction (2.4); optional
   adjacent "%".
4. WORD: letters with internal apostrophes joined (U+2019 -> ').
5. else PUNCT (one code point).
POST-PASS contraction expansion: a WORD whose ascii_lower form is a
T.contractions_v1 key is replaced by that entry's token sequence (first
expanded token keeps the raw span; the rest carry empty raw). fold =
stem_v1(ascii_lower(token)) applied AFTER expansion.

### 2.3 stem_v1(w) -> str
First matching rule of T.stem_v1_rules in order (ies->y with min length;
sses->ss; es after s/x/z/ch/sh -> drop; final s not ss -> drop); else w.

### 2.4 Numbers -> Dec (exact; violations abstain('malformed_mention'))
```
grammar: number := [currency] [sign] core [pct]
         core   := digit+
                 | digit{1,3} ("," digit{3})+      # ALL groups exactly 3
                 | core "." digit+                 # at most one "."
def parse_dec(lexeme) -> Dec:
    d = Dec(BigInt(sign + digits_without_commas_and_dot), len(frac_digits))
    canonicalize(d)
    if digit_count(d.coefficient) > MAX_DEC_DIGITS or
       d.scale > MAX_DEC_SCALE: abstain
    return d
def dec_cmp(a, b) = sign(a.coefficient * 10^(s - a.scale)
                       - b.coefficient * 10^(s - b.scale)),
                    s = max(a.scale, b.scale)       # BigInt; NEVER floats
def dec_convert(d, factor) = canonicalize(Dec(d.coefficient * factor, d.scale))
```
Unit: the WORD immediately after the number whose fold is a T.units_v1
key -> {group, factor} (a flat map: "day" -> {group: time_a, factor:
1440}). Conversion multiplies by the exact integer factor into the
group's base; comparisons are legal only within one group and one
currency -- cross-group/cross-currency -> UnknownAtom. An APPROX_v1
token immediately before the number (or its sign/currency) -> abstain.

### 2.5 parse_values(value_span) -> list[Interval] | None | ABSTAIN
1. Longest T.comparators_v1 token-sequence match immediately preceding a
   NUMBER/PCT100 token; 2. v = parse_dec(number), unit per 2.4; 3. with a
   comparator: instantiate its interval template verbatim ("v" -> the
   Dec; "0" -> Dec zero; null -> unbounded); 4. bare scalar -> [v, v];
   5. a second NUMBER or leftover non-filler tokens in the span ->
   abstain('malformed_mention'); 6. no NUMBER -> None.

### 2.6 sentences / segments / accounting
Sentence ends at PUNCT '.', '!', '?' whose next raw char is WS_v1 or EOF
(numeric '.' is inside NUMBER tokens). LIST MARKERS (e10): a line whose
first token is '-', '*', or NUMBER+'.' starts a new sentence, and the
marker BELONGS TO that sentence as a structural list marker (accounted
like structural punctuation; the NUMBER+'.' marker's period is NOT a
sentence terminator) -- the item's sentence runs to the next genuine
terminator or EOF, so '1. Items are refundable.' is ONE sentence,
behaviorally identical to '- Items are refundable.'. EOF closes the
last. Segments
split at T.structural_punctuation PUNCT tokens. Content token := fold
length >= 3 and fold not in T.stop_v1. LOSSLESS IDENTITY STREAM + TOTAL
SPAN ACCOUNTING: every non-whitespace span is consumed by a frame
product (trigger, role, condition, modifier, quantifier, requirement
atom, scope) or by FILLER -- STOP_v1 words in grammar positions,
structural punctuation in structural positions, sentence-terminal
'.'/'!', the sentence-initial capitalized article followed by a content
token -- else the FIELD is PARTIAL. SEMANTIC-FORCE tokens (negators,
condition operators, 'and'/'or', modals, quantifiers) are never blanket
filler; an unconsumed occurrence -> FIELD PARTIAL. Sentence-terminal
'?': context sentence -> non-assertive, excluded from every basis,
spans accounted; governed-output sentence -> FIELD PARTIAL.

## 3. Extraction

### 3.1 Triggers, negation, polarity, benefit normalization
```
def trigger_scan(sentence) -> list[Hit]:
    # one pass over the union of all facets' triggers + deny_triggers as
    # folded token sequences, longest-match-first, non-overlapping;
    # equal-span precedence: OBLIGATION PASSIVE > generic passive >
    # active. A MODAL_ABSTAIN token in trigger position ->
    # abstain('unextractable'). Hit.trigger_key = matched folded tuple;
    # Hit.is_deny = matched among deny_triggers.

def NEG_v1(hit) -> bool:
    # PRE rule: a T.negators_v1 token within NEG_WINDOW tokens BEFORE
    # hit.span, same segment, not forming a T.negation_exceptions pair
    # with its successor.
    # POST-MODAL rule (draft 5): a T.negators_v1 token IMMEDIATELY AFTER
    # the trigger's last token, same segment ("can not enter" from
    # "can't"; "is not refundable" is caught by PRE on 'refundable').
    # Either rule negates; the negator is consumed (dual-role).

def polarity(hit) = NEG_v1(hit) XOR hit.is_deny
    # refundable POS; nonrefundable NEG; not refundable NEG;
    # can't (can + not) -> NEG permission frame.

def normalize_benefit_facet(hit, subject_head) -> str:
    if len(hit.trigger_key) == 1 \
       and hit.trigger_key[0] in T.generic_benefit_triggers_v1 \
       and subject_head in T.facetproj_v1:
        return T.facetproj_v1[subject_head]      # BOTH polarities
    return hit.facet
    # deny triggers of non-generic facets and non-benefit facets are
    # never renormalized
```

### 3.2 Roles (numbered; any failure -> abstain('unextractable'))
```
def extract_roles(hit, sentence) -> Roles:
 1 OBLIGATION-PASSIVE "[Y] {is|are|was|were|been|being} required for [X]":
     Roles(subject = X groups, object = Y groups)
 2 PASSIVE (applies ONLY when the trigger's fold is in
   T.participle_triggers_v1 -- stative-adjective triggers like 'available'
   never enter this pattern) "[X] {is|are|was|were|been|being}
   <participle> by [Y]":
     Roles(subject = Y, object = X);
   participle + copula with NO 'by'-agent: abstain (never active)
 3 COORDINATION: a second trigger joined to a previous one by 'and' with
     no tokens between: inherit the previous SUBJECT only; predicate-level
     'or': abstain (both frames)
 4 ACTIVE: subject = pre-trigger segment tokens; object = post-trigger
     tokens up to the FIRST of segment end, condition-marker start, or
     the coordinator introducing the next trigger's subject
 5 PREPOSED CONDITION "If V, [clause]": attaches to every coordinated
     predicate of the clause; no delimiting comma -> abstain
 6 pronoun-only subject: PRONOUN marker binding the nearest preceding
     subject extent in the same field; none -> abstain
 7 VALUE role (measure facets only; MUST precede valency enforcement --
     written order is evaluation order): Roles.value = the UNIQUE MAXIMAL
     span within the post-trigger predicate region consisting of an
     optional T.comparators_v1 token sequence + one NUMBER/PCT100 token +
     an optional adjacent unit WORD (a T.units_v1 key). ZERO candidate
     spans, or MORE THAN ONE candidate span, -> abstain('malformed_mention').
     Roles.value is None for non-measure facets.
     DUAL-ROLE TRIGGER (e8): a token that is BOTH a facet trigger and a
     comparator (currently only 'within') serves both roles in one span:
     it is the frame's trigger AND the comparator introducing the value
     span that starts at the immediately following NUMBER (+unit); its
     comparator interval template applies ([0, v] for 'within'); the token
     is accounted once (dual-role consumption, like negators). 'Shipping
     within 5 days' = duration frame with value [0, 5 day].
 8 enforce T.facets_v1 valency (subject / object / value); a required
     role with no tokens (incl. a measure facet whose step-7 value is
     None) -> abstain

type Roles = {subject: Span, object: Span|None, value: Span|None,
              pattern: OP|PASSIVE|COORD|ACTIVE}

def noun_groups(span):
    # split at role-level 'and' into conjuncts; groups = content-token
    # runs unbroken by T.adjunct_prepositions_v1 or T.relative_markers_v1;
    # 'or' | '/' | '|' between noun groups -> abstain.
def head(group) = the RIGHTMOST content token of the conjunct's group
    # COMPOUND_HEAD rule; compound tokens stay in the term set;
    # supersession never crosses a conjunct boundary
def adjunct_modifiers(span):
    # each adjunct preposition + following noun group ->
    # (prep, frozenset(content folds)); a facet trigger, NUMBER,
    # REL_MARKER + content, or nested adjunct inside -> abstain
def quant(subject_group) = T.quant_v1 class of the head-position token:
    # universal -> 1; existential -> 2; abstain-class -> frame PARTIAL;
    # absent -> 0
```

### 3.3 Conditions (one marker scope = ONE formula; node force + atom flags)
```
def parse_conditions(sentence, hit) -> list[CondNode]:
    for span in condition_marker_spans(sentence, hit):   # COND_OPS_v1,
                                                         # longest-match,
                                                         # left-to-right
        f = parse_bool(span.body,
                       restrictive = (span.op.force == RESTRICTION))
        if span.op.polarity == '-': f = NOT(f)
        yield CondNode(f, force = span.op.force, kind = span.op.kind)

def parse_bool(tokens, restrictive) -> Bool:
    # top-level split at 'or' -> alternatives; each split at 'and' ->
    # conjuncts (OR of ANDs); a conjunct containing a further 'or'
    # (same-level mixing, no structural punctuation) -> abstain.
    # Each conjunct -> atom:
    #   measure mention -> MeasureAtom (2.4/2.5; failure -> UnknownAtom)
    #   else TermAtom(concept_terms(conjunct), pol = NEG_v1(conjunct),
    #                 restrictive = restrictive)
    # node/atom count > MAX_EXPR_NODES -> envelope path (sec 8).

def concept_terms(conjunct) -> frozenset[str]:      # draft 5, item 1
    return frozenset(T.concept_v1.get(tok.fold, tok.fold)
                     for tok in content_tokens(conjunct))
    # CONCEPT_v1 applies ONLY inside Bool atoms (conditions, requirement
    # formulas, evidence formulas) -- NEVER to extent terms. "requires
    # approval" and "if approved" therefore share the atom {approval}.
```
The `restrictive` flag SURVIVES aggregation verbatim (atoms are copied,
never rebuilt) and is enforced by ENTAILS (4.2) -- restriction direction
cannot be laundered into a grant.

### 3.4 Frames
```
def extract_frames(field) -> list[Frame] | PARTIAL:
    for s in sentences(field), hit in trigger_scan(s):
        r  = extract_roles(hit, s)
        fx = normalize_benefit_facet(hit, head(first_conjunct(r.subject)))
        frames.add(Frame(field.id, next_id(),
            Extent(fx, terms(r.subject), terms(r.object),
                   adjunct_modifiers(r), quant(r.subject),
                   polarity(hit), parse_values(r.value)),
            parse_conditions(s, hit),
            assertive = not interrogative(s)))
    any abstention -> return PARTIAL
```

### 3.5 Obligations (aggregation preserves flags), evidence
```
def extract_obligations(trusted_frames):
  EXPLICIT -- per requirement frame ("X require(s) Y" / "Y is required
  for X"), per governed conjunct:
      governed_identity = Extent(facet = T.facetproj_v1[head(conjunct)]
                                         (miss -> PARTIAL),
                                 subject = terms(conjunct), object = {},
                                 modifiers = adjunct_modifiers(conjunct),
                                 quant = quant(conjunct), polarity = POS,
                                 values = None)
      requirement_formula = parse_bool(required_span, restrictive = True)
          # an explicit requirement IS a necessary condition
      applicability_scope = conds_as_formula(frame)
      source_activation_domain = TOP; source_polarity = POS
  IMPLICIT -- every assertive, non-requirement-parent frame with
  conds != []:
      Obligation(implicit, frame.extent,
                 source_activation_domain = conds_as_formula(frame),
                 applicability_scope = TOP,
                 requirement per aggregate(), source_polarity =
                 frame.extent.polarity)

def aggregate(implicit_obligations):
    # group by EQUAL PropositionIdentity (byte-equal enc_extent); per
    # group over ALL condition nodes (across and within frames):
    #   G = [n.formula : n.force == GRANT]
    #   R = [n.formula : n.force == RESTRICTION]
    #   formula = OR(G) if R == [] else AND(R) if G == []
    #             else AND(OR(G), AND(R))
    # atoms keep their restrictive flags verbatim (draft 5, item 2);
    # any untypable node -> the group is UNDECIDABLE;
    # source_activation_domain = OR of member domains;
    # engine-TOP-equivalent formula -> trivial = True.

def source_conflict_prepass(obligations):
    # conflicted iff (a) aggregated requirement_formula UNSAT (DECIDED:
    # basis_conflict, never deny-all inference) or (b) two
    # comparable-identity trusted source frames with disposition CONFLICT.

def extract_evidence(out_frames, out_requirement_statements):
    # (a) requirement statements in governed output, per governed
    #     conjunct: Evidence(field/frame/span ids,
    #     governed_identity = PROJECTED-facet Extent (as EXPLICIT above),
    #     domain = conds_as_formula(statement),
    #     asserted_formula = parse_bool(required_span, restrictive=True),
    #     assertion_polarity = NEG_v1(statement.trigger))
    # (b) condition-bearing assertive output frames:
    #     Evidence(ids, governed_identity = frame.extent, domain = TOP,
    #     asserted_formula = conds_as_formula(frame),   # atom flags kept
    #     assertion_polarity = POS)
```

## 4. Engine

### 4.1 Bitsets, varmap, decomposition, GAMMA
```
class Bitset:
    # EXACTLY 2^n valid bits in ceil(2^n/64) words; padding bits above
    # 2^n are ALWAYS zero; NOT(F) = mask_n & ~F.words (width-bounded);
    # every op that could set padding re-masks.

def build_varmap(task_atoms) -> {key: index} | ENVELOPE:
    # keys = ATOMENC atom bytes EXCLUDING the restrictive flag (variable
    # identity = terms + polarity; the flag is structural, enforced in
    # ENTAILS, not a distinct variable); sort keys bytewise;
    # COMPLEMENT_v1 pairs and opposite-polarity twins collapse to ONE
    # variable (negated side flagged); MeasureAtoms expand to
    # elementary-interval indicators; |variables| computed BEFORE any
    # bitset exists; > MAX_BOOL_ATOMS -> envelope_exceeded (preflight).

def decompose(quantity, atoms) -> indicators:
    # convert all bounds to the unit group's base via exact factors
    # (dec_convert); endpoints = dec_cmp-sorted unique finite bounds
    # e1..ek; indicators in order: (-inf,e1), [e1,e1], (e1,e2), [e2,e2],
    # ..., [ek,ek], (ek,+inf) => 2k+1 variables; each atom's intervals
    # map to the exact indicator subset their open/closed bounds cover.

def build_gamma(quantities) -> Bitset:
    # per quantity: BUILD_EXACTLY_ONE(indicators) = prefix-OR at-most-one
    # + at-least-one; combine across Q quantities with AND_REDUCE costing
    # max(0, Q-1); Q == 0 -> GAMMA = TOP.
```

### 4.2 Queries (GAMMA-relativized; UNCOMPILABLE operand -> UNKNOWN + cause)
```
SAT(F)  = nonzero(F & G);   UNSAT = !SAT
EQUIV   = zero((F ^ H) & G)
NEGATE(F) = mask & ~F
ENTAILS(F, H) -> YES|NO:
  STRUCTURAL PRE-CHECK (draft 5 item 2; GENERALIZED at e9 per the ratified
  symmetric principle): collect the TermAtoms of F and H. An atom pairing
  (same variable) with mismatched restrictive flags provides NO
  entailment, in EITHER direction. If ANY H TermAtom -- grant or
  restrictive -- has no flag-matching F counterpart on a variable that F
  constrains, return NO. Consequences: "if verified" never entails "only
  if verified" and vice versa; a restrictive-only F never entails
  AND(grant_atom, restrictive_atom) (the grant atom lacks flag-matching
  evidence). COMPLEMENT_v1 pair lookup operates on the SAME normalized
  form as Bool atoms (post-stem, post-CONCEPT_v1).
  Then: YES iff zero(F & NEGATE(H) & G), else NO.
DOMAIN(D1, D2) = UNKNOWN (uncompilable) | DISJOINT (UNSAT either or
                 !SAT(D1 & D2)) | OVERLAP
IMPLIES(a, b)  = UNKNOWN | (YES iff ENTAILS(a, b)) | NO
```

### 4.3 identity_relation (TOTAL; extents + domains passed separately)
```
def generalizes(A: Extent, B: Extent, same_frame) -> (YES|NO|UNKNOWN, cause):
 1 A.facet != B.facet                       -> (NO, None)
 2 not A.subject <= B.subject               -> (NO, None)
 3 not A.object  <= B.object                -> (NO, None)
 4 modifiers: any same-rel pair with an EXCL_v1 pair across the object
     sets (either direction)                -> (NO, None)
   a in A.modifiers with same-rel matches in B but none containing
     a.objset                               -> (UNKNOWN, condition_undecidable)
   a in A.modifiers with NO same-rel match in B -> (NO, None)
 5 eff_quant(A.quant) == EXISTENTIAL and not same_frame
                                            -> (UNKNOWN, condition_undecidable)
 6 A carries any malformed value/modifier product
                                            -> (UNKNOWN, malformed_mention)
 7 else                                     -> (YES, None)

def identity_relation(A: Extent, D_A: Bool, B: Extent, D_B: Bool,
                      same_frame) -> Rel3:          # draft 5, item 3:
                                                    # domains are ARGUMENTS
    (g1, c1) = generalizes(A, B, same_frame)
    (g2, c2) = generalizes(B, A, same_frame)
    if g1 != YES and g2 != YES:
        return UNDECIDABLE(worst_cause({c1, c2})) if UNKNOWN in {g1, g2} \
               else INERT
    d = DOMAIN(D_A, D_B)
    if d == OVERLAP:  return COMPARABLE
    if d == DISJOINT: return INERT
    return UNDECIDABLE(malformed_mention if any contributing UnknownAtom
                       carries it else condition_undecidable)
# Callers pass (frame.extent, conds_as_formula(frame)) pairs. A Rel3 is
# NEVER read as boolean; every consumer branches on all three arms.

def two_way_generalizes(A, B, same_frame) -> (YES|NO|UNKNOWN, cause):
    # YES if either direction YES; NO if both NO; else (UNKNOWN, worst_cause)
def meet(A, B) -> Extent:
    # defined when generalizes holds either way: facet = the equal facet;
    # subject/object = union; modifiers = per relation the containing
    # side's superset, single-side kept; quant = EXISTENTIAL if either
    # side's eff_quant is EXISTENTIAL else UNIVERSAL (raw kept for C5)
def disposition(a: Frame, b: Frame) -> MATCH|CONFLICT|UNDECIDABLE(cause):
 1 measure facets: either values None or containing an UnknownAtom ->
     UNDECIDABLE(its cause); CONFLICT iff !SAT(AND(indicators(a),
     indicators(b))); else MATCH
 2 else: CONFLICT iff a.extent.polarity != b.extent.polarity and not
     (eff_quant(a.extent.quant) == eff_quant(b.extent.quant) == EXISTENTIAL); else MATCH
```

## 5. Pipeline

```
Stage R   raw caps (ENV_MAX_FIELD_BYTES; UTF-8 validity); no semantics;
          a breach records envelope_exceeded, selected at its LOCKED A1
          position (only if no earlier gate fires). SCOPING (e12,
          normative per A2's check-scoped envelope_exceeded): a breached
          FIELD affects ONLY the checks that consume it (an oversized
          context never suppresses output-only C2); a task/engine
          overflow affects ONLY the owning check; unaffected checks
          evaluate normally -- there is no global envelope result
Stage W1  extraction-free gates: case-A, malformed_structured_input,
          runtime_binding_missing, dynamic_config_rejected,
          context_disabled, input_empty (WS_v1), attestation gates per
          FREEZE v18.6 2.5.2 (SubjectTuple joins, non-circular signed
          containers, P/C/A role authorization, direct signer-identity
          binding, key-identity invariant, per-run coverage)
Stage X   bounded extraction (secs 2-3) on surviving fields
Stage W2  envelope preflight (sec 8), scan_incomplete, basis gates over
          canonical basis-records (A2), dependency_unavailable (custom)
Stage D   detection (sec 6); no cap checks remain
```
Reason SELECTION = first hit in the LOCKED A1.2b order over computed
gate results; iteration scopes per A2 rev 3 Tables A/B (until A2 locks,
A1's text controls traversal).

## 6. Checks (rows = FREEZE v18.6 sec 3)

```
def C1(ctx_frames, out_frames) -> (outcome, reason):
 0 any consumed field PARTIAL -> (NOT_EVALUATED, extraction_partial)
 1 trusted = [f in ctx_frames : f.assertive and tier(f) in {t1, t2}]
   t3 = [f in ctx_frames : f.assertive and tier(f) == tier_3]
 2 self_conf = {a, b : (a, b) in pairs(trusted),
                identity_relation(a.extent, D(a), b.extent, D(b), False)
                  == COMPARABLE,
                disposition(a, b) == CONFLICT}
 3 for fo in [f in out_frames : f.assertive]:
     cmp, causes = [], []
     for c in trusted:
       r = identity_relation(fo.extent, D(fo), c.extent, D(c), False)
       if r == COMPARABLE: cmp.add(c)
       elif r == INERT: continue
       else: causes.add(r.cause)
     disps = []
     for c in cmp:
       d = disposition(fo, c)
       if d == UNDECIDABLE: causes.add(d.cause)
       else: disps.add(d)
     status[fo] = BLOCKED_CONFLICT if any(c in self_conf for c in cmp)
             else BLOCKED_UNDEC(worst_cause(causes)) if causes
             else VIOLATING if disps and all(== CONFLICT)
             else AMBIGUOUS if any CONFLICT and any MATCH
             else CLEAN
 4 any VIOLATING       -> (VIOLATION[critical], detection_complete)
 5 any BLOCKED_CONFLICT-> (NOT_EVALUATED, basis_conflict)
 6 any AMBIGUOUS       -> (NOT_EVALUATED, identity_ambiguous)
 7 any BLOCKED_UNDEC(malformed_mention)
                       -> (NOT_EVALUATED, unsupported_claim_form)
 8 any BLOCKED_UNDEC   -> (NOT_EVALUATED, condition_undecidable)
 9 t3-only contradiction, authoritative basis nonempty
                       -> (PASS + advisory body note, detection_complete)
10 else                -> (PASS, detection_complete)

def C2(out_field) -> (outcome, reason):
 0 C2-LOCAL PARTIAL (e11, operator-ratified): "out_field PARTIAL" for C2
   means C2's OWN normalization/tokenization/lexical scan is incomplete,
   OR the governed output is interrogative (sentence-terminal '?'). C2
   does NOT inherit proposition-frame extraction partiality -- its
   products are DEFINITIVE_v1/HEDGE_v1 token matches, not frames.
   C2-local PARTIAL -> (NOT_EVALUATED, extraction_partial)
 1 for d in folded-sequence matches of T.definitive_v1 in out_field
       where not NEG_v1(d):
     w = tokens within W_HEDGE each side of d, clipped at segment bounds,
         parens/brackets, and T.hedge_window_boundaries tokens
     if no T.hedge_v1 match h in w with not NEG_v1(h):
         return (VIOLATION[warning], detection_complete)
 2 return (PASS, detection_complete)

def support(req_root, bound) -> {definite_root, possible_root}:
    # TOTALITY (e2): req_root is canonicalized first (sec 7 rules), which
    # eliminates TOP/BOTTOM nodes (a TOP-equivalent requirement is TRIVIAL
    # and never reaches support(); BOTTOM-equivalent is UNSAT and gated by
    # the conflict pre-pass). The recursion below is total over the
    # remaining grammar {TermAtom, MeasureAtom, AND, OR, NOT}: a residual
    # NOT(...) subtree (from unless/except) is a TERMINAL SUPPORT UNIT --
    # treated exactly like a leaf: direct entailment only, no recursion
    # into its child.
    LEAF(N) = TermAtom | MeasureAtom | NOT(...)
    direct_pos(N) = OR_REDUCE([e.domain : e in bound,
                               ENTAILS(eff(e), N) == YES])
    direct_neg(N) = OR_REDUCE([e.domain : e in bound,
                               ENTAILS(eff(e), NEGATE(N)) == YES])
    anyneg(N)   = direct_neg(N)                        if LEAF(N)
                | OR(direct_neg(N), OR_REDUCE(anyneg(c)))   if AND
                | OR(direct_neg(N), AND_REDUCE(anyneg(c)))  if OR
    definite(N) = let base = AND(direct_pos(N), NOT(anyneg(N))):
                  base                                 if LEAF(N)
                | OR(base, AND_REDUCE(definite(c)))    if AND
                | OR(base, OR_REDUCE(definite(c)))     if OR
    possible(N) = direct_pos(N)                        if LEAF(N)
                | OR(direct_pos(N), AND_REDUCE(possible(c))) if AND
                | OR(direct_pos(N), OR_REDUCE(possible(c)))  if OR
    # OR_REDUCE([]) = BOTTOM; AND_REDUCE([]) = TOP (pinned)
    return {definite_root: definite(req_root),
            possible_root: possible(req_root)}                    # (e2)

def C3(ctx_frames, out_frames) -> (outcome, reason):
 0 partial gate
 1 obs = aggregate(extract_obligations(trusted(ctx_frames)))
   conflicted = source_conflict_prepass(obs)
   ev = extract_evidence(out_frames, output_requirement_statements)
 2 for ob in obs, fa in [f in out_frames : f.assertive]:
     (g, gc) = two_way_generalizes(ob.governed_identity, fa.extent, False)
     if g == NO: continue
     if g == UNKNOWN: verdicts.add(UNK(gc)); continue
     if ob.kind == implicit and fa.extent.polarity != ob.source_polarity:
         continue
     if ob.kind == explicit and (fa.extent.polarity != POS or
         not T.facets_v1[fa.extent.facet].benefit): continue
     d = DOMAIN(D(fa), ob.source_activation_domain)
     if d == DISJOINT: continue
     if d == UNKNOWN: verdicts.add(UNK(condition_undecidable)); continue
     if ob in conflicted: verdicts.add(OB_CONFLICTED); continue
     if ob.trivial: verdicts.add(SATISFIED); continue
     ee = meet(ob.governed_identity, fa.extent)
     E  = AND(D(fa), ob.applicability_scope)
     if uncompilable(E): verdicts.add(UNK(cause(E))); continue    # (e4)
                                             # compilability BEFORE UNSAT
     if UNSAT(E): continue                   # E compilable: SAT is boolean
     causes = []                             # (e4) explicit accumulation
     bound = []
     for e in [e in ev : e.field_id == fa.field_id]:        # same field
       (gb, gbc) = generalizes(e.governed_identity, ee,
                               same_frame = (e.frame_id == fa.frame_id))
       if gb == UNKNOWN: causes.add(gbc)
       elif gb == YES and (eff_quant(e.governed_identity.quant) != EXISTENTIAL
                           or e.frame_id == fa.frame_id):
           bound.add(e)
     for e in bound:
       if uncompilable(eff(e)): causes.add(cause(eff(e)))
       if uncompilable(e.domain): causes.add(cause(e.domain))
     if causes: verdicts.add(UNK(worst_cause(causes))); continue
     S = support(ob.requirement_formula, bound)
     ent = ENTAILS(E, S.definite_root)       # (e4) explicit comparisons;
     if ent == YES: verdicts.add(SATISFIED)  # E and both support roots are
     else:                                   # compilable here, so ENTAILS
       viol = SAT(AND(E, NOT(S.possible_root)))  # and SAT return definite
       if viol == True: verdicts.add(VIOLATION_V) # values -- no UNKNOWN
       else: verdicts.add(UNK(condition_undecidable))  # arm is read as
                                                       # boolean
 3 any VIOLATION_V   -> (VIOLATION[warning], detection_complete)
 4 any OB_CONFLICTED -> (NOT_EVALUATED, basis_conflict)
 5 any UNK(malformed_mention) -> (NOT_EVALUATED, unsupported_claim_form)
 6 any UNK           -> (NOT_EVALUATED, condition_undecidable)
 7 else              -> (PASS, detection_complete)

def C4(ctx_frames, out_frames) -> (outcome, reason):
 0 partial gate
 1 conflict_pairs, undec = [], []
   for (a, b) in pairs(trusted assertive ctx):
     if a.extent.facet != b.extent.facet: continue
     if a.extent.polarity == b.extent.polarity: continue
     if eff_quant(a.extent.quant) == eff_quant(b.extent.quant) == EXISTENTIAL: continue
     if a.extent.subject & b.extent.subject == {}: continue
     if not (a.extent.object <= b.extent.object or
             b.extent.object <= a.extent.object): continue
     modrel = modifier-set relation per generalizes step 4, both ways:
       EXCL pair -> continue; UNKNOWN -> undec.add(condition_undecidable);
       continue
     d = DOMAIN(D(a), D(b))
     if d == OVERLAP: conflict_pairs.add((a, b))
     elif d == UNKNOWN: undec.add(cause)
 2 for (a, b) in conflict_pairs:
     restrictive = a if a.extent.polarity == NEG else b
     for fo in [f in out_frames : f.assertive and
                f.extent.facet == a.extent.facet]:
       r1 = identity_relation(fo.extent, D(fo), a.extent, D(a), False)
       r2 = identity_relation(fo.extent, D(fo), b.extent, D(b), False)
       rr = identity_relation(fo.extent, D(fo), restrictive.extent,
                              D(restrictive), False)
       if UNDECIDABLE in {r1, r2, rr}:
           undec.add(worst of their causes); continue
       engages  = fo.extent.polarity == POS and rr == COMPARABLE
       in_scope = (r1 == COMPARABLE and r2 == COMPARABLE) \
                  or fo.extent.subject <= (a.extent.subject &
                                           b.extent.subject) \
                  or engages
       if not in_scope: continue
       preserved, pres_unknown = False, False
       for fr in [f in out_frames : f.assertive]:
         rx = identity_relation(fr.extent, D(fr), restrictive.extent,
                                D(restrictive), False)
         if rx == UNDECIDABLE: pres_unknown = True; continue
         if rx == COMPARABLE and fr.extent.polarity ==
            restrictive.extent.polarity:
             im = IMPLIES(D(restrictive), D(fr))
             if im == YES: preserved = True; break
             if im == UNKNOWN: pres_unknown = True
       if preserved: continue
       if pres_unknown: undec.add(condition_undecidable)
       else: unpreserved.add((restrictive, fo))
 3 any unpreserved -> (VIOLATION[warning], detection_complete)
 4 any undec cause == malformed_mention
                   -> (NOT_EVALUATED, unsupported_claim_form)
 5 any undec       -> (NOT_EVALUATED, condition_undecidable)
 6 else            -> (PASS, detection_complete)

def C5(...): EXCLUDED from vertical slice 1 (C_COV uncalibrated).
    Frozen semantics: FRAME/OBLIG atoms by ATOMENC_v1 bytes; both-side
    dedup; sorted-merge intersection (no runtime hashing); VIOLATION iff
    ATOMS >= 3 and covered/ATOMS < C_COV (rational comparison).
```

## 7. ATOMENC_v1 (byte-exact; counts u32 big-endian; enums u8)

```
enc_bytes(b)   = u32_be(len(b)) || b
enc_str(s)     = enc_bytes(utf8(nfc(s)))
enc_set(S)     = u32_be(|S|) || members' enc_str sorted bytewise
enc_pair(r,O)  = enc_str(r) || enc_set(O)
enc_modset(M)  = u32_be(|M|) || enc_pair items sorted by encoded bytes
ENUMS: quant 0/1/2; polarity 0=POS 1=NEG; kind 0=explicit 1=implicit;
bound_kind 0=closed-finite 1=open-finite 2=unbounded; presence 0/1;
force 0=grant 1=restriction; restrictive 0/1.
enc_bound(k,v) = u8(bound_kind) || (enc_str(dec(v)) if finite else
                 enc_str(""))
    # dec() = canonical-form decimal string: minimal digits, '-' prefix,
    # scale rendered as a '.' fraction, no exponent
enc_interval   = 0x49 || enc_bound(lo) || enc_bound(hi) || enc_str(unit_base)
enc_formula(F) = canonicalize first (flatten, dedupe, sort children by
                 encoded bytes, collapse double negation), then prefix
                 walk: TOP=0x54; BOTTOM=0x42; AND=0x41||u32_be(n)||children;
                 OR=0x4F||u32_be(n)||children; NOT=0x4E||child;
                 TermAtom = 0x61 || enc_set(terms) || u8(pol) ||
                            u8(restrictive)
                 MeasureAtom = 0x6D || enc_str(qty_key) || u32_be(k) ||
                            k enc_interval in list order
                 UnknownAtom is NEVER encoded (containing formulas are
                 uncompilable and never reach encoding)
enc_extent(E)  = 0x45 || enc_str(facet) || enc_set(subject) ||
                 enc_set(object) || enc_modset(modifiers) || u8(quant) ||
                 u8(polarity) || u8(values presence) ||
                 (u32_be(k) || k enc_interval if present)
FRAME_ATOM     = 0x46 || enc_extent || enc_formula(conds_as_formula)
OBLIG_ATOM     = 0x4F 0x4F || u8(kind) || enc_extent(governed_identity) ||
                 enc_formula(source_activation_domain) ||
                 enc_formula(applicability_scope) ||
                 enc_formula(requirement_formula)
```
Total encoded length > L_MAX -> the atom abstains('malformed_mention').
Byte equality of encodings IS identity (C5 coverage, PropositionIdentity
grouping, canonical sorts). Varmap variable identity EXCLUDES the
restrictive flag and polarity sign (complement folding); both are
handled structurally.

## 8. Budgets (conservative preflight at W2)

Enumerate every potential task with SET ARITHMETIC ONLY (identity
screens, EXCL lookups -- no engine calls): C1 = (out x trusted-ctx) +
ctx pairs; C3 = every identity-screened (obligation, out frame) pair
budgeted AS IF activated with its full bindable evidence; C4 = ctx pairs
+ pair x out. envelope_exceeded when any of the following trips -- evaluated PER CHECK
over that check's OWN consumed fields and tasks only (e12):
```
n(task) > MAX_BOOL_ATOMS
W_total > MAX_ENGINE_WORK   # BOOLISA_v1 op sums, macros PINNED here
                            # (one op = one width-masked pass of
                            # ceil(2^n/64) words):
                            #  AND/OR/XOR/AND_NOT/NOT = 1; NONZERO = 1;
                            #  EQUAL = 2; OR_REDUCE(k)/AND_REDUCE(k) =
                            #  max(0, k-1); COMPILE(F) = nodes(F);
                            #  SAT = 2; ENTAILS = 3;
                            #  BUILD_EXACTLY_ONE(I) = 4I - 2;
                            #  GAMMA cross-quantity reduce = max(0, Q-1);
                            #  DOMAIN-overlap query = 3;
                            #  VALUE-intersection query = 3;
                            #  ONE formula per marker scope enters budgets
M_peak  > MAX_ENGINE_BYTES
   M_C1/C4(pair) = (4 + |task formulas| + 1) * bytes(n)
   M_C3(task)    = (4 + |formulas(task)| + 3*nodes(req) + 1) * bytes(n)
   M_C5          = 2 * ATOMS * L_MAX + O(1) cursors      # no bitsets
   bytes(n)      = max(1, 2^(n-3))
```
formulas(task) for C3 = {requirement_formula, D(fa),
source_activation_domain, applicability_scope, E} + {eff(e), e.domain}
per bindable evidence item. Dec work is exact BigInt bounded by
MAX_DEC_DIGITS/MAX_DEC_SCALE. Detection has no cap checks; unexpected
aborts -> EVALUATOR_ERROR per the LOCKED A1.2b.

## 9. Fixtures, calibration, vertical slice

- Fixtures GENERATED from the reference implementation (location:
  `sanna-protocol/reference/`); the differential harness runs Python and
  TypeScript over the corpus -- ANY byte divergence is a release blocker.
- REQUIRED FLAGSHIP: ctx "Refunds require approval." + out "Refunds are
  available." -> both project to facet:refund_availability -> C3
  activates -> possible = BOTTOM -> VIOLATION. Variant: out "Refunds are
  available only if approved." -> own-condition evidence; CONCEPT_v1 maps
  approved -> approval AND the ONLY_IF marker makes the evidence atom
  RESTRICTIVE, flag-matching the explicit requirement's restrictive atom
  -> SATISFIED. (An "if approved" grant does NOT satisfy the restrictive
  requirement -- deliberate, see the restriction-direction fixtures;
  temporal "after approval" is an adjunct -> abstains.)
- REQUIRED RESTRICTION-DIRECTION FIXTURES (round-22): ctx "Users may
  enter only if verified." + out "Users may enter if verified." -> the
  IF-form evidence fails the structural flag check against the
  restrictive atom -> NOT satisfied -> VIOLATION; out "Users may enter
  only if verified." -> flag-matching -> SATISFIED.
- REQUIRED POST-MODAL NEGATION FIXTURES (round-22): "Users can't enter"
  == "Users cannot enter" == "Users may not enter" -> NEG permission
  frames; C1 conflict against "Users may enter" context.
- REQUIRED ANTONYM FIXTURES: every facet's positive/negative pair
  (nonrefundable/refundable -> C1 VIOLATION; unavailable under
  projection -> refund_availability NEG; prohibited/permitted -> CONFLICT).
- REQUIRED TRI-STATE FIXTURES: "Refunds for employees are refundable." +
  "Refunds for contractors are nonrefundable." -> UNDECIDABLE ->
  NOT_EVALUATED (condition_undecidable) on both SDKs.
- REQUIRED EXACT-DECIMAL FIXTURES: $9007199254740993 vs $9007199254740992
  -> distinct Dec -> C1 CONFLICT on both SDKs; "$25.00" == "$25";
  comparator vectors (over/under/at least/up to/within); malformed
  grouping "1,23,456" -> abstain.
- CONCEPT_v1 vectors (approve/approved/approval unify; misses stay
  distinct); contraction vectors ("aren't" == "are not"); table-miss
  abstention vectors; all FREEZE v18.6 sec 9 families; BOOLISA
  cost-conformance probes.
- Vertical slice 1 = C1-C4 only, Python first, then TypeScript, both
  loading the tables artifact by content hash; measured
  precision/recall/abstention/false-violation rates reported.

## 10. Documented abstentions (v1.6 competence boundary)

Outside-competence input produces NOT_EVALUATED -- limits, not bugs:
coreference, synonymy, paraphrase; role/predicate alternatives;
proportional quantifiers; modality outside facet tables; cross-frame
existential co-reference; nested modifiers; modifier relations without
EXCL_v1 entries; heads outside FACETPROJ_v1; concepts outside CONCEPT_v1
(distinct atoms stay distinct); force outside COND_OPS_v1;
force-heterogeneous marker spans; temporal condition markers ('after',
'before' -- adjunct-only); comparators outside COMPARATORS_v1;
cross-currency and cross-group values; approximate values; cross-field
evidence (Gate 2 renderer attestation); per-run attester implementation;
free text at halt/warn (L3 advisory via `_unattested` only).
