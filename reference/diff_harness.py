#!/usr/bin/env python3
"""Differential-harness scaffold (SAN-879): runs a fixture file and emits
canonical JSON results (sorted keys, LF) to stdout. This is the artifact
the future TypeScript implementation (SAN-880) must byte-match.

Usage:
    python3 reference/diff_harness.py <fixtures.json>
    python3 reference/diff_harness.py <fixtures.json> --self-check

<fixtures.json> is a JSON array of records, each {"id": str,
"check_id": "C1"|"C2"|"C3"|"C4", "output": str, plus exactly one
context shape: "context": str (one tier_1 source), "context_sources":
[{"text": str, "tier": "tier_1"|"tier_2"|"tier_3"}], or
"context_repeat": {"text": str, "count": int} (expanded to text*count
as one tier_1 source; used for envelope-cap fixtures)} -- the same
shapes as reference/fixtures/oracles.json and generated.json. Only
"id", the context shape, "output", and "check_id" are read; extra
fields are ignored so this can run directly against either fixture
file, or a future cross-SDK corpus.

Output: a JSON array, one record per input fixture, each
{"id": ..., "check_id": ..., "outcome": ..., "outcome_reason": ...,
"severity": ..., "advisory": ...}, serialized with sorted keys and terminated with a
single trailing newline (LF) -- the exact byte shape a TypeScript
differential run must reproduce for a byte-diff to be meaningful.

--self-check: runs the Python implementation over the fixture file
TWICE and diffs the two canonical outputs; a divergence means the
reference implementation is non-deterministic, which is itself a defect
(the whole exit-criteria basis in the spec section 0 header depends on
determinism: "generated fixtures byte-identical on Python and
TypeScript").
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

from reference.evaluate import evaluate  # noqa: E402


def run(fixtures: list) -> list:
    results = []
    for fx in fixtures:
        fixture = {"output": fx.get("output", "")}
        if "context_sources" in fx:
            fixture["context_sources"] = fx["context_sources"]
        elif "context_repeat" in fx:
            fixture["context_repeat"] = fx["context_repeat"]
        else:
            fixture["context"] = fx.get("context", "")
        out = evaluate(fixture)
        got = out[fx["check_id"]]
        results.append(
            {
                "id": fx["id"],
                "check_id": fx["check_id"],
                "outcome": got["outcome"],
                "outcome_reason": got["outcome_reason"],
                "severity": got["severity"],
                "advisory": bool(got.get("advisory", False)),
            }
        )
    results.sort(key=lambda r: r["id"])
    return results


def canonical_json(records: list) -> str:
    """sorted keys, LF, single trailing newline."""
    return json.dumps(records, sort_keys=True, ensure_ascii=True, separators=(",", ":")) + "\n"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("fixtures", type=Path)
    parser.add_argument("--self-check", action="store_true")
    args = parser.parse_args(argv)

    fixtures = json.loads(args.fixtures.read_text())

    run1 = canonical_json(run(fixtures))

    if args.self_check:
        run2 = canonical_json(run(fixtures))
        if run1 != run2:
            sys.stderr.write("SELF-CHECK FAILED: two runs of the Python reference implementation diverged\n")
            return 1
        sys.stderr.write(f"SELF-CHECK OK: {len(fixtures)} fixtures, byte-identical across two runs\n")
        return 0

    sys.stdout.write(run1)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
