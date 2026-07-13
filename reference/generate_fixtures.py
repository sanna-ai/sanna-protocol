#!/usr/bin/env python3
"""Expands each hand-pinned oracle in reference/fixtures/oracles.json into
surface variants that MUST yield identical results to the base oracle:
casing changes on non-sentence-initial words, extra WS_v1 whitespace, and
contraction/expansion swaps where applicable. Writes
reference/fixtures/generated.json with the full expected tuples produced
by RUNNING the reference implementation.

Hand-pinned oracles are asserted, never regenerated: this script reads
oracles.json as fixed ground truth and only ever WRITES generated.json.

Usage:
    python3 reference/generate_fixtures.py           # regenerate generated.json
    python3 reference/generate_fixtures.py --check   # exit 1 if stale
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

from reference.evaluate import evaluate  # noqa: E402
from reference.primitives import tokenize  # noqa: E402
from reference.tables import T  # noqa: E402

ORACLES_PATH = Path(__file__).parent / "fixtures" / "oracles.json"
GENERATED_PATH = Path(__file__).parent / "fixtures" / "generated.json"


def case_variant(text: str) -> str | None:
    """Toggle the case of a non-sentence-initial WORD token."""
    toks = [t for t in tokenize(text) if t.kind == "WORD" and t.raw and t.start > 0]
    if not toks:
        return None
    tok = toks[-1]
    new_word = tok.raw.upper() if tok.raw != tok.raw.upper() else tok.raw.lower()
    return text[: tok.start] + new_word + text[tok.end :]


def whitespace_variant(text: str) -> str | None:
    """Insert extra WS_v1 whitespace between the first two tokens."""
    idx = text.find(" ")
    if idx == -1:
        return None
    return text[:idx] + "   " + text[idx + 1 :]


def contraction_expand_variant(text: str) -> str | None:
    """Replace a contraction with its expansion (e.g. "aren't" -> "are not")."""
    lowered = text.lower()
    for key, expansion in T.contractions_v1.items():
        idx = lowered.find(key)
        if idx != -1:
            return text[:idx] + " ".join(expansion) + text[idx + len(key) :]
    return None


def contraction_contract_variant(text: str) -> str | None:
    """Replace an expansion pair with its contraction (e.g. "are not" ->
    "aren't"), inverse of contraction_expand_variant."""
    lowered = text.lower()
    for key, expansion in T.contractions_v1.items():
        phrase = " ".join(expansion)
        idx = lowered.find(phrase)
        if idx != -1:
            return text[:idx] + key + text[idx + len(phrase) :]
    return None


VARIANT_BUILDERS = {
    "case": case_variant,
    "whitespace": whitespace_variant,
    "contraction_expand": contraction_expand_variant,
    "contraction_contract": contraction_contract_variant,
}


def build_variants(oracle: dict) -> list[dict]:
    """Surface variants per oracle. For per-source-tier oracles
    (context_sources shape) only output-side variants are generated; the
    tiered context is carried through verbatim."""
    variants = []
    tiered = "context_sources" in oracle
    fields = ("output",) if tiered else ("context", "output")
    for kind, builder in VARIANT_BUILDERS.items():
        for field in fields:
            base_text = oracle.get(field)
            if not base_text:
                continue
            new_text = builder(base_text)
            if new_text is None or new_text == base_text:
                continue
            record = {
                "id": f"{oracle['id']}__{kind}__{field}",
                "base_oracle": oracle["id"],
                "variant_kind": kind,
                "variant_field": field,
                "output": oracle["output"],
                "check_id": oracle["check_id"],
            }
            if tiered:
                record["context_sources"] = oracle["context_sources"]
            else:
                record["context"] = oracle["context"]
            record[field] = new_text
            variants.append(record)
    return variants


def _evaluate_input(record: dict) -> dict:
    fixture = {"output": record["output"]}
    if "context_sources" in record:
        fixture["context_sources"] = record["context_sources"]
    else:
        fixture["context"] = record["context"]
    return fixture


def generate() -> list[dict]:
    oracles = json.loads(ORACLES_PATH.read_text())
    out = []
    for oracle in oracles:
        for variant in build_variants(oracle):
            result = evaluate(_evaluate_input(variant))
            got = result[variant["check_id"]]
            expected = {
                "outcome": got["outcome"],
                "outcome_reason": got["outcome_reason"],
                "severity": got["severity"],
            }
            if got.get("advisory"):
                expected["advisory"] = True
            rec = dict(variant)
            rec["expected"] = expected
            out.append(rec)
    out.sort(key=lambda r: r["id"])
    return out


def render(records: list[dict]) -> str:
    return json.dumps(records, indent=2, sort_keys=False, ensure_ascii=True) + "\n"


def verify_variants_match_oracles(records: list[dict]) -> list[str]:
    """Spec (Phase 3 of SAN-879): surface variants "MUST yield identical
    results" to their base oracle. Returns a list of mismatch
    descriptions (empty if all variants agree with their base oracle)."""
    oracles_by_id = {o["id"]: o for o in json.loads(ORACLES_PATH.read_text())}
    mismatches = []
    for rec in records:
        base = oracles_by_id[rec["base_oracle"]]
        if rec["expected"] != base["expected"]:
            mismatches.append(
                f"{rec['id']}: variant result {rec['expected']} != "
                f"base oracle {rec['base_oracle']} result {base['expected']}"
            )
    return mismatches


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()

    records = generate()
    mismatches = verify_variants_match_oracles(records)
    if mismatches:
        print("surface-variant divergence from base oracle (spec: variants MUST match):", file=sys.stderr)
        for m in mismatches:
            print(f"  {m}", file=sys.stderr)
        return 1

    rendered = render(records)

    if args.check:
        if not GENERATED_PATH.exists() or GENERATED_PATH.read_text() != rendered:
            print(f"{GENERATED_PATH} is stale; run without --check to regenerate.", file=sys.stderr)
            return 1
        print(f"{GENERATED_PATH} is up to date ({len(records)} generated fixtures).")
        return 0

    GENERATED_PATH.write_text(rendered)
    print(f"wrote {GENERATED_PATH} ({len(records)} generated fixtures)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
