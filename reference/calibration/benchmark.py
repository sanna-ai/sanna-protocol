#!/usr/bin/env python3
"""SAN-881 Phase-B benchmark. NEVER executed against the corpus in Phase
A. PYTHON-REFERENCE-ONLY: cross-SDK claims made elsewhere in this
project are about semantic parity (byte-identical outcomes), never
performance; this module does not touch the TypeScript reference at all.

Preconditions (checked BEFORE any timing pass): outcomes.json exists,
belongs to the SAME freeze as FREEZE-MANIFEST.json (freeze_manifest_hash
match), and ALL NINE hard gates in the corresponding rates.json passed.
Refuses to run otherwise -- a benchmark over an evaluator that failed a
correctness gate is not a benchmark, it's noise.

Method: persistent process, corpus preloaded once; 10 warm-up passes +
30 timed passes over all 160 items in fixed id order (cal:000..cal:159);
time.monotonic_ns() per item. Nearest-rank percentiles, pinned: sort
ascending, 1-indexed rank = ceil(p/100 * N); per-item N = 30 samples
(one pass's worth of an item across all timed passes); per-pass N = 30
totals (one sample per pass). P50/P95/max reported for both views.
Envelope-breach count is COPIED from the deterministic outcomes.json
(zero_envelope_breaches_640 gate), never independently measured during a
timing pass -- timing runs are excluded from every determinism gate.
"""
from __future__ import annotations

import hashlib
import json
import math
import platform
import sys
import time
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent.parent

WARMUP_PASSES = 10
TIMED_PASSES = 30


class BenchmarkRefused(RuntimeError):
    pass


def nearest_rank_percentile(sorted_samples: list[int], p: float) -> int:
    """sorted_samples ascending; 1-indexed rank = ceil(p/100 * N)."""
    n = len(sorted_samples)
    if n == 0:
        raise ValueError("cannot compute a percentile over zero samples")
    rank = math.ceil((p / 100.0) * n)
    rank = max(1, min(n, rank))
    return sorted_samples[rank - 1]


def check_preconditions(results_dir: Path, freeze_manifest_path: Path) -> dict[str, Any]:
    outcomes_path = results_dir / "outcomes.json"
    rates_path = results_dir / "rates.json"
    if not outcomes_path.exists():
        raise BenchmarkRefused("outcomes.json does not exist -- run measure.py first")
    if not rates_path.exists():
        raise BenchmarkRefused("rates.json does not exist -- run measure.py first")
    if not freeze_manifest_path.exists():
        raise BenchmarkRefused("FREEZE-MANIFEST.json does not exist")

    outcomes = json.loads(outcomes_path.read_text())
    rates = json.loads(rates_path.read_text())
    freeze_hash = hashlib.sha256(freeze_manifest_path.read_bytes()).hexdigest()
    if outcomes.get("freeze_manifest_hash") != freeze_hash:
        raise BenchmarkRefused(
            f"outcomes.json belongs to a different freeze (outcomes says {outcomes.get('freeze_manifest_hash')}, "
            f"current FREEZE-MANIFEST.json hashes to {freeze_hash})"
        )
    if not rates.get("nine_gates_passed"):
        failed = [k for k, v in rates.get("gates", {}).items() if not v]
        raise BenchmarkRefused(f"not all nine hard gates passed; refusing to benchmark. Failed: {failed}")
    return {"outcomes": outcomes, "rates": rates, "freeze_hash": freeze_hash}


def run_timed_passes(corpus_ids_in_order: list[str], evaluate_one, warmup: int = WARMUP_PASSES, timed: int = TIMED_PASSES) -> dict[str, list[int]]:
    """evaluate_one(item_id) -> None (side-effect timed only). Returns
    {item_id: [ns_sample, ...]} with exactly `timed` samples per item,
    in fixed pass order."""
    for _ in range(warmup):
        for iid in corpus_ids_in_order:
            evaluate_one(iid)

    per_item: dict[str, list[int]] = {iid: [] for iid in corpus_ids_in_order}
    for _ in range(timed):
        for iid in corpus_ids_in_order:
            start = time.monotonic_ns()
            evaluate_one(iid)
            per_item[iid].append(time.monotonic_ns() - start)
    return per_item


def summarize(per_item: dict[str, list[int]]) -> dict[str, Any]:
    per_item_summary = {}
    for iid, samples in per_item.items():
        s = sorted(samples)
        per_item_summary[iid] = {
            "n": len(s),
            "p50_ns": nearest_rank_percentile(s, 50),
            "p95_ns": nearest_rank_percentile(s, 95),
            "max_ns": s[-1],
        }
    pass_totals = []
    n_items = len(per_item)
    n_passes = len(next(iter(per_item.values()))) if per_item else 0
    for pass_idx in range(n_passes):
        total = sum(per_item[iid][pass_idx] for iid in per_item)
        pass_totals.append(total)
    pass_totals_sorted = sorted(pass_totals)
    per_pass_summary = {
        "n": len(pass_totals_sorted),
        "p50_ns": nearest_rank_percentile(pass_totals_sorted, 50) if pass_totals_sorted else None,
        "p95_ns": nearest_rank_percentile(pass_totals_sorted, 95) if pass_totals_sorted else None,
        "max_ns": pass_totals_sorted[-1] if pass_totals_sorted else None,
    }
    return {"per_item": per_item_summary, "per_pass": per_pass_summary}


def machine_metadata() -> dict[str, Any]:
    return {
        "python_version": sys.version,
        "platform": platform.platform(),
        "processor": platform.processor(),
        "machine": platform.machine(),
    }


def build_benchmark_json(preconditions: dict[str, Any], timing_summary: dict[str, Any]) -> dict[str, Any]:
    envelope_breaches = sum(
        1 for r in preconditions["outcomes"]["outcomes"] if r["outcome_reason"] == "envelope_exceeded"
    )
    return {
        "freeze_manifest_hash": preconditions["freeze_hash"],
        "outcomes_hash": hashlib.sha256(json.dumps(preconditions["outcomes"], sort_keys=True).encode()).hexdigest(),
        "python_reference_only": True,
        "warmup_passes": WARMUP_PASSES,
        "timed_passes": TIMED_PASSES,
        "corpus_item_count": len(timing_summary["per_item"]),
        "envelope_breach_count_from_outcomes": envelope_breaches,
        "timing": timing_summary,
        "machine": machine_metadata(),
        "excluded_from_determinism_gates": True,
    }


def main(argv: list[str] | None = None) -> int:
    results_dir = HERE / "results"
    freeze_manifest_path = HERE / "FREEZE-MANIFEST.json"
    try:
        preconditions = check_preconditions(results_dir, freeze_manifest_path)
    except BenchmarkRefused as exc:
        sys.stderr.write(f"BENCHMARK REFUSED: {exc}\n")
        return 2

    sys.path.insert(0, str(REPO_ROOT))
    from reference.evaluate import evaluate  # noqa: E402

    corpus_inputs = json.loads((HERE / "corpus_inputs.json").read_text())
    corpus_ids = [r["id"] for r in corpus_inputs]
    by_id = {r["id"]: r for r in corpus_inputs}

    def evaluate_one(iid: str) -> None:
        rec = by_id[iid]
        fixture = {"output": rec["output"]}
        if "context_sources" in rec:
            fixture["context_sources"] = rec["context_sources"]
        else:
            fixture["context"] = rec["context"]
        evaluate(fixture)

    timing = run_timed_passes(corpus_ids, evaluate_one)
    summary = summarize(timing)
    out = build_benchmark_json(preconditions, summary)

    results_dir.mkdir(parents=True, exist_ok=True)
    (results_dir / "benchmark.json").write_text(json.dumps(out, sort_keys=True, indent=2) + "\n")
    sys.stdout.write(f"benchmark.json written: {results_dir / 'benchmark.json'}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
