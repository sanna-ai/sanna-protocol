# SAN-881 C1-C4 Calibration Corpus (Phase A)

Calibration infrastructure for measuring C1-C4 detector competence
against a purposive, synthetic, tier_1-only corpus. This directory is
built in two phases under separate authorization:

- **Phase A (this commit)**: authors the corpus, the commit/reveal
  sealing scheme, and the measurement infrastructure. Phase A NEVER
  runs any evaluator (Python or TypeScript) over any corpus item.
- **Phase B (future, separate authorization)**: runs `measure.py` and
  `benchmark.py` for real, once `labels_frozen.json` and
  `FREEZE-MANIFEST.json` exist.

Scope: **C1-C4 only**. No C_COV, no C5, no provenance/wrapper
measurement (see `reference/spec/ALGORITHM-v4-c1c5-reference.md`
section 0 for the slice boundary this corpus stays inside).

## Files in this directory

Public (this commit):

- `corpus_inputs.json` -- 160 items (`cal:000`..`cal:159`), each
  `{id, context|context_sources, output}`. TIER_1 ONLY.
- `evaluation_profile.json` -- binds the evaluator invocation contract,
  the pinned spec hashes, and the expected C1-C4 identities.
- `commitment.json` -- the commit/reveal envelope: `labeling_context_hash`,
  its component list, and the four author-artifact commitments.
- `measure.py` -- the Phase-B execution contract (never run in Phase A).
- `benchmark.py` -- the Phase-B Python-only timing harness (never run in
  Phase A).
- `validate_design.py` -- structural + cryptographic validator; the only
  script in this directory that is actually run in Phase A.
- `schemas/` -- five JSON Schemas covering design metadata, labels
  (semantic-only / contract-only / merged-frozen), the coverage
  manifest, the commitment envelope, and the freeze manifest.

Sealed (private; staged under a directory OUTSIDE this repo during
authoring; never committed, never printed, never logged):

- `design_metadata.json`, `labels_author_semantic.json`,
  `labels_author_contract.json`, `coverage_manifest.json`, `nonces.json`.

Future artifacts (Phase B; not present after this commit):

- `labels_reviewer_semantic.commitment.json`,
  `labels_reviewer_contract.commitment.json` -- reviewer commitment
  envelopes (filenames pinned now, in `commitment.json`).
- `labels_frozen.json` -- the merged, adjudicated label set (schema:
  `schemas/labels_schema.json`, `mergedFrozenRecord` form).
- `adjudication_log.json` -- the operator's disagreement-resolution log.
- `FREEZE-MANIFEST.json` -- the raw-SHA-256 binding `measure.py` refuses
  to run without (schema: `schemas/freeze_manifest_schema.json`).
- `outcomes.json`, `rates.json`, `RATES-REPORT.md` -- `measure.py`
  output.
- `benchmark.json` -- `benchmark.py` output.

## The commit/reveal + staged-adjudication workflow

1. **Author seals.** The author (this Phase A work) writes the four
   sealed artifacts, runs `validate_design.py --sealed-dir <path>`
   privately until green, then computes `commitment.json`: a
   `labeling_context_hash` binding the base commit SHA and every public
   artifact this corpus depends on (corpus, evaluation profile, all five
   schemas, both pinned spec files), and a domain-separated SHA-256
   commitment per sealed artifact using a fresh 32-byte nonce.
2. **Operator custody transfer.** The operator takes custody of the
   sealed staging directory (the four sealed artifacts + `nonces.json`)
   and **removes it from every agent-readable path on this machine**
   before reviewer labeling begins. This is a manual, out-of-band step;
   no agent should retain or re-derive sealed content after this point.
3. **Fresh no-history reviewer task.** A reviewer -- a fresh task with
   NO access to this session's history, the sealed staging directory, or
   any design/contract reasoning -- receives only the Sol export
   (`corpus_inputs.json`, `evaluation_profile.json`, the five schemas,
   copies of the two pinned spec artifacts, `export_manifest.json`) and
   independently labels the corpus.
4. **Reviewer commits semantic labels, then separately commits contract
   labels.** Same commitment scheme, same `labeling_context_hash`,
   filenames pinned above. The two reviewer label sets are committed
   SEPARATELY (semantic first) so contract-layer, algorithm-relative
   reasoning cannot leak into the semantic-truth judgment.
5. **Reveal.** Author artifacts + nonces are revealed. Both author and
   reviewer commitments are verified by recomputing the domain-separated
   hash from the revealed bytes, nonce, and `labeling_context_hash` and
   comparing against the committed hex (`validate_design.py`'s
   executable reveal verification).
6. **Mechanical disagreement diff.** Author vs. reviewer semantic labels
   are diffed; author vs. reviewer contract labels are diffed
   separately.
7. **Operator adjudicates semantic truth** with contract, design
   metadata, and the coverage manifest still inaccessible -- adjudication
   of what actually happened in the text must not be contaminated by
   which algorithm behavior is "expected."
8. **Semantic adjudication frozen.**
9. **Contract reveal + adjudication.** The contract-layer disagreements
   are adjudicated with the frozen semantic layer as ground truth.
10. **`labels_frozen.json` + `FREEZE-MANIFEST.json`** are produced,
    binding every input artifact's raw SHA-256.
11. **Phase B measurement** runs under separate authorization -- see
    below.

Any byte change to the corpus or a sealed artifact after `commitment.json`
is finalized abandons corpus v1; restart as v2. There is no in-place
correction once blind labeling has begun.

## Tier_1-only scope

Every `corpus_inputs.json` item is either a plain `"context"` string (one
tier_1 source) or a `"context_sources"` array where every source has
`"tier": "tier_1"`. No tier_2/tier_3 source and no basis-empty or
advisory-path construction appears anywhere in this corpus -- those
belong to the existing conformance-fixture lane
(`reference/fixtures/oracles.json`, `generated.json`), not this
calibration corpus.

## C1-C4-only scope

This corpus measures C1, C2, C3, C4 detector competence only. C_COV is
uncalibrated (SAN-882) and C5 is out of slice scope; neither is touched
here.

## No-evaluator-before-freeze rule

Phase A NEVER runs `reference.evaluate.evaluate()` (or the TypeScript
port) over any corpus item, in either SDK. `validate_design.py`'s inline
toy tests exercise harness/report code paths on INLINE TOY fixtures that
are explicitly not corpus items. `measure.py` and `benchmark.py` refuse
to run without `FREEZE-MANIFEST.json`, which does not exist until the
workflow above completes.

## The Phase-B execution contract (`measure.py`)

1. Refuses to run unless `FREEZE-MANIFEST.json` exists and every bound
   raw SHA-256 verifies (corpus_inputs, labels_frozen, design_metadata,
   coverage_manifest, evaluation_profile, algorithm, tables,
   adjudication_log).
2. Builds the canonical ephemeral 640-record projection: every
   allowlisted `corpus_inputs.json` entry x {C1,C2,C3,C4}, ids EXACTLY
   `calx:NNN:CN`, canonical JSON bytes (sorted keys, compact separators,
   `ensure_ascii`, single trailing LF). The allowlist (`context` |
   `context_sources`, `output`) makes a label leak into evaluator input
   structurally impossible.
3. ALWAYS rebuilds the TypeScript package first (`npm ci --ignore-scripts`
   + `npm run build`; a pre-existing `dist/` is never trusted), then
   invokes BOTH harnesses (`reference/diff_harness.py`,
   `reference/ts/dist/src/diff_harness.js`) on the exact same projected
   bytes. Each must yield zero exit and 640 complete, unique,
   well-formed results.
4. Byte-compares the two canonical outputs; any inequality is FATAL.
5. Joins the frozen labels and emits `outcomes.json` (outcomes + freeze
   hash + component hashes + record count + the equal py/ts output hash
   + runner git commit + `measure.py`'s own SHA-256), `rates.json`, and
   `RATES-REPORT.md`.

**Fatality rules**: a crash, nonzero harness exit, or a
duplicate/missing/malformed result is an INFRASTRUCTURE FAILURE -- the
run produces NO final `results/` directory (a fresh temporary directory
is used until success). A SEMANTIC GATE failure (any of the nine hard
gates below is false) still emits the complete auditable artifact set,
but the process exits nonzero. Stale success artifacts can never survive
a failed run.

### The nine hard gates

Populations are pinned per check: **primary** = the check's own 40
target records; **secondary** = all 160 for that check, aggregate only.
**640 pooled across checks is never used for any gate or metric.**

1. `py_ts_byte_equality_640`
2. `contract_tuple_agreement_640` (all 640 records, full tuple equality)
3. `zero_evaluator_errors` (no `EVALUATOR_ERROR`/`CONFIG_ERROR`/crash)
4. `zero_false_violations`
5. `zero_unsafe_violations`
6. `zero_in_domain_escapes` (escape numerator 0 over records whose item
   is the target `in_domain_violation` item for that check)
7. `in_domain_semantic_accuracy_100` (pinned semantic correctness
   mapping: `NO_VIOLATION -> PASS`, `VIOLATION -> VIOLATION`,
   `INDETERMINATE -> NOT_EVALUATED`; every target `in_domain_*` record
   maps correctly)
8. `deliberate_abstention_correct_100` (every target
   `indeterminate_or_unsafe` record: `NOT_EVALUATED` AND
   `outcome_reason` equals the frozen contract reason)
9. `zero_envelope_breaches_640` (no record with `outcome_reason ==
   envelope_exceeded`)

Near-miss recall and coverage-loss abstention are REPORT-ONLY (not
gates). The corpus-impact ranking counts `introduced_feature`
occurrences where `competence == KNOWN_COVERAGE_GAP`, deduped by
`(item_id, check_id)`, ranked by supporting-item count.

### Two reporting views, no Wilson intervals

Every population reports the **primary (40 target items)** view and the
**secondary (all 160, aggregate)** view separately, plus scenario count
alongside item count. Every ratio is `{"numerator": int, "denominator":
int, "value": decimal-string-or-null}` -- a zero denominator is `null`,
never `0%`/`100%`; `value` uses fixed-precision decimal, scale 4,
`ROUND_HALF_EVEN` (Python `decimal`); the rendered report uses the same
rounding at 2 decimal places. **No Wilson intervals anywhere** (removed
by operator direction): this is a purposive synthetic corpus with paired
minimal-pair scenarios, which cannot support statistical inference over
a real-world population. `RATES-REPORT.md` and `rates.json` both state
this caveat prominently.

## Benchmark separation (`benchmark.py`)

Python-reference-only. Cross-SDK claims elsewhere in this project are
about semantic parity (byte-identical outcomes across the two
harnesses), never performance -- `benchmark.py` does not invoke the
TypeScript reference at all. It refuses to run unless `outcomes.json`
exists, belongs to the SAME freeze as the current `FREEZE-MANIFEST.json`
(hash match), and ALL NINE gates in the corresponding `rates.json`
passed. A persistent process with the corpus preloaded runs 10 warm-up
passes + 30 timed passes over all 160 items in fixed `cal:000..cal:159`
order, `time.monotonic_ns()` per item. Percentiles use the nearest-rank
method (sort ascending, 1-indexed rank = `ceil(p/100 * N)`); per-item
N=30 samples, per-pass N=30 totals; P50/P95/max reported for both.
Envelope-breach count is copied from the deterministic `outcomes.json`,
never independently measured during a timing pass. Benchmark runs are
excluded from every determinism gate.

## Corpus construction

160 items = 4 checks (C1-C4) x 4 strata x 10 items, one item per
`facets_v1` family per (check, stratum) block:

- `in_domain_nonviolation` -- target-check semantic `NO_VIOLATION`,
  `IN_DOMAIN` competence, `introduced_feature` null.
- `in_domain_violation` -- `VIOLATION`, `IN_DOMAIN`, null.
- `determinate_out_of_domain` -- a human-determinate truth (balanced
  EXACTLY 5 `VIOLATION` / 5 `NO_VIOLATION` per check), competence
  `KNOWN_COVERAGE_GAP` on the target check, EXACTLY ONE
  `introduced_feature` (a lexical surface or table-pair relation
  verified ABSENT from the pinned tables artifact). One-way pointer to a
  unique in-domain control sharing check/domain/semantic-truth/scenario.
- `indeterminate_or_unsafe` -- `INDETERMINATE`, `DELIBERATE_ABSTENTION`,
  null `introduced_feature`; grounded in documented abstention classes
  from `ALGORITHM-v4-c1c5-reference.md` section 10 and its errata
  catalog (e10/e13/e15, SAN-894, SAN-895).

Domains rotate across all ten `facets_v1` families (`availability`,
`refund_availability`, `exchange_availability`, `discount_availability`
via FACETPROJ projection, `access_permission`, `approval_requirement`,
`eligibility`, and the three measure facets `cost`/`duration`/`limit`
with values, units, comparators, and PCT100/currency).
`coverage_manifest.json` dynamically enumerates every table-derived
surface from the pinned tables artifact; an empty evidence array is a
DOCUMENTED v1 coverage gap (this 160-item corpus does not claim
exhaustive table coverage), not a validator failure. Future expansion to
close specific gaps requires fresh holdout items -- no table changes.
