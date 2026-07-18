#!/usr/bin/env python3
"""SAN-881 Phase-B execution contract. NEVER executed against the corpus
in Phase A -- Phase A only authors this module and exercises it via toy
fixtures in tests/reference/test_calibration.py. Running this for real
requires reference/calibration/FREEZE-MANIFEST.json to exist with every
bound SHA-256 verified, which does not happen until the staged-
adjudication workflow in README.md completes under separate
authorization.

Pipeline (all transactional -- see run_pipeline docstring):
  1. Refuse to run unless FREEZE-MANIFEST.json verifies against its own
     hash pins (corpus_inputs, labels_frozen, design_metadata,
     coverage_manifest, evaluation_profile, algorithm, tables,
     adjudication_log).
  2. Build the canonical ephemeral 640-record projection: every
     allowlisted corpus input x {C1,C2,C3,C4}, ids "calx:NNN:CN".
  3. ALWAYS rebuild the TypeScript package first (a pre-existing dist/ is
     never trusted), then invoke BOTH harnesses on the exact projected
     bytes.
  4. Byte-compare the two canonical outputs; any inequality is FATAL.
  5. Join frozen labels; emit outcomes.json / rates.json /
     RATES-REPORT.md into a FRESH temporary result directory. An
     infrastructure failure produces NO final directory. A semantic-gate
     failure (any of the nine hard gates false) still emits the complete
     auditable artifact set, but the process exits nonzero.
"""
from __future__ import annotations

import decimal
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent.parent
FREEZE_MANIFEST_PATH = HERE / "FREEZE-MANIFEST.json"

CHECK_IDS = ("C1", "C2", "C3", "C4")
ALLOWED_INPUT_KEYS = {"context", "context_sources", "output"}
SEMANTIC_CORRECTNESS_MAPPING = {
    "NO_VIOLATION": "PASS",
    "VIOLATION": "VIOLATION",
    "INDETERMINATE": "NOT_EVALUATED",
}

decimal.getcontext().prec = 50


class InfrastructureFailure(RuntimeError):
    """A run-breaking failure (crash, nonzero exit, malformed/duplicate/
    missing result, byte mismatch between harnesses). Produces NO final
    result directory -- stale success artifacts can never survive a
    failed run."""


class FreezeGateRefused(RuntimeError):
    """FREEZE-MANIFEST.json is absent or a bound hash does not verify."""


# ---------------------------------------------------------------------
# Freeze gate
# ---------------------------------------------------------------------

def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_freeze_manifest(manifest: dict[str, Any], repo_root: Path | None = None, cal_dir: Path | None = None) -> list[str]:
    """Returns a list of verification failures (empty = all bound hashes
    verify). Never raises on a mismatch -- callers decide whether to
    refuse to run. `repo_root`/`cal_dir` default to the current module
    globals looked up AT CALL TIME (not baked in as default-argument
    values), so tests can monkeypatch measure.REPO_ROOT / measure.HERE
    and this function picks up the patched value."""
    if repo_root is None:
        repo_root = REPO_ROOT
    if cal_dir is None:
        cal_dir = HERE
    errors: list[str] = []
    bindings = {
        "corpus_inputs_sha256": cal_dir / "corpus_inputs.json",
        "design_metadata_sha256": cal_dir / "design_metadata.json",
        "coverage_manifest_sha256": cal_dir / "coverage_manifest.json",
        "evaluation_profile_sha256": cal_dir / "evaluation_profile.json",
        "labels_frozen_sha256": cal_dir / "labels_frozen.json",
        "adjudication_log_sha256": cal_dir / "adjudication_log.json",
        "algorithm_sha256": repo_root / "reference" / "spec" / "ALGORITHM-v4-c1c5-reference.md",
        "tables_sha256": repo_root / "reference" / "spec" / "ALGORITHM-v4-tables-v1.json",
    }
    for key, path in bindings.items():
        expected = manifest.get(key)
        if expected is None:
            errors.append(f"FREEZE-MANIFEST.json missing required key {key}")
            continue
        if not path.exists():
            errors.append(f"{key}: bound file {path} does not exist")
            continue
        actual = _sha256_file(path)
        if actual != expected:
            errors.append(f"{key}: hash mismatch (manifest says {expected}, actual {actual})")
    return errors


def load_and_verify_freeze_manifest() -> dict[str, Any]:
    if not FREEZE_MANIFEST_PATH.exists():
        raise FreezeGateRefused(
            "reference/calibration/FREEZE-MANIFEST.json does not exist -- measure.py refuses to run. "
            "This file is produced at the end of the staged-adjudication workflow (see README.md); "
            "Phase A never creates it."
        )
    manifest = json.loads(FREEZE_MANIFEST_PATH.read_text())
    errors = verify_freeze_manifest(manifest)
    if errors:
        raise FreezeGateRefused("FREEZE-MANIFEST.json failed verification:\n" + "\n".join(f"  - {e}" for e in errors))
    return manifest


# ---------------------------------------------------------------------
# Canonical projection
# ---------------------------------------------------------------------

def canonical_json_bytes(obj: Any) -> bytes:
    """sorted keys, compact separators, ensure_ascii, single trailing LF."""
    return (json.dumps(obj, sort_keys=True, ensure_ascii=True, separators=(",", ":")) + "\n").encode("ascii")


def build_projection(corpus_inputs: list[dict]) -> list[dict]:
    """Every allowlisted corpus input x C1-C4, ids EXACTLY "calx:NNN:CN".
    The allowlist is enforced here: only context|context_sources|output
    are read from each source record; any other key (labels, design
    metadata, ids) is NEVER read, so a label leak into the evaluator
    input is structurally impossible."""
    records = []
    for src in corpus_inputs:
        src_id = src["id"]  # "cal:NNN"
        if not (src_id.startswith("cal:") and src_id[4:].isdigit()):
            raise InfrastructureFailure(f"malformed source id {src_id!r}")
        ordinal = src_id[4:]
        ctx_keys = [k for k in ("context", "context_sources") if k in src]
        if len(ctx_keys) != 1:
            raise InfrastructureFailure(f"{src_id}: expected exactly one context shape, got {ctx_keys}")
        if "output" not in src:
            raise InfrastructureFailure(f"{src_id}: missing output")
        extra = set(src.keys()) - ALLOWED_INPUT_KEYS - {"id"}
        if extra:
            raise InfrastructureFailure(f"{src_id}: disallowed keys present in projection source: {extra} (label leak guard)")
        for check_id in CHECK_IDS:
            rec = {"id": f"calx:{ordinal}:{check_id}", "check_id": check_id, "output": src["output"]}
            rec[ctx_keys[0]] = src[ctx_keys[0]]
            records.append(rec)
    if len(records) != len(corpus_inputs) * 4:
        raise InfrastructureFailure(f"projection cardinality fatality: expected {len(corpus_inputs) * 4}, got {len(records)}")
    ids = [r["id"] for r in records]
    if len(set(ids)) != len(ids):
        raise InfrastructureFailure("projection cardinality fatality: duplicate calx ids")
    return records


# ---------------------------------------------------------------------
# Dual-harness invocation
# ---------------------------------------------------------------------

def build_typescript_package(ts_dir: Path) -> None:
    """ALWAYS rebuild; a pre-existing dist/ is never trusted."""
    subprocess.run(["npm", "ci", "--ignore-scripts"], cwd=ts_dir, check=True)
    subprocess.run(["npm", "run", "build"], cwd=ts_dir, check=True)


def run_harness(cmd: list[str], projection: list[dict], workdir: Path, tag: str) -> tuple[bytes, list[dict]]:
    in_path = workdir / f"projection_{tag}.json"
    in_path.write_text(json.dumps(projection))
    result = subprocess.run(cmd + [str(in_path)], capture_output=True, text=False, cwd=REPO_ROOT)
    if result.returncode != 0:
        raise InfrastructureFailure(f"{tag} harness exited {result.returncode}: {result.stderr.decode(errors='replace')[:2000]}")
    out_bytes = result.stdout
    try:
        parsed = json.loads(out_bytes)
    except json.JSONDecodeError as exc:
        raise InfrastructureFailure(f"{tag} harness produced malformed JSON: {exc}") from exc
    if not isinstance(parsed, list) or len(parsed) != len(projection):
        raise InfrastructureFailure(f"{tag} harness returned {len(parsed) if isinstance(parsed, list) else 'non-list'} results, expected {len(projection)}")
    seen_ids = set()
    for rec in parsed:
        required = {"id", "check_id", "outcome", "outcome_reason", "severity", "advisory"}
        if set(rec.keys()) != required:
            raise InfrastructureFailure(f"{tag} harness result has malformed shape: {rec}")
        if rec["id"] in seen_ids:
            raise InfrastructureFailure(f"{tag} harness duplicate result id {rec['id']}")
        seen_ids.add(rec["id"])
    if seen_ids != {r["id"] for r in projection}:
        raise InfrastructureFailure(f"{tag} harness result id set does not match the projection id set")
    return out_bytes, parsed


def run_dual_harness(projection: list[dict], workdir: Path) -> tuple[bytes, list[dict], str]:
    ts_dir = REPO_ROOT / "reference" / "ts"
    build_typescript_package(ts_dir)
    py_bytes, py_results = run_harness(
        [sys.executable, str(REPO_ROOT / "reference" / "diff_harness.py")], projection, workdir, "py")
    ts_bytes, ts_results = run_harness(
        ["node", str(ts_dir / "dist" / "src" / "diff_harness.js")], projection, workdir, "ts")
    if py_bytes != ts_bytes:
        raise InfrastructureFailure("py_ts_byte_equality_640 FAILED: Python and TypeScript harness outputs are not byte-identical")
    combined_hash = hashlib.sha256(py_bytes).hexdigest()
    return py_bytes, py_results, combined_hash


# ---------------------------------------------------------------------
# Rates / gates
# ---------------------------------------------------------------------

def _ratio(numerator: int, denominator: int) -> dict[str, Any]:
    if denominator == 0:
        return {"numerator": numerator, "denominator": 0, "value": None}
    value = (decimal.Decimal(numerator) / decimal.Decimal(denominator)).quantize(
        decimal.Decimal("0.0001"), rounding=decimal.ROUND_HALF_EVEN)
    return {"numerator": numerator, "denominator": denominator, "value": str(value)}


def join_labels(projection_results: list[dict], labels_frozen: list[dict]) -> list[dict]:
    """Join calx:NNN:CN results against labels_frozen.json {item_id: cal:NNN, check_id}."""
    labels_by_key = {(r["item_id"], r["check_id"]): r for r in labels_frozen}
    joined = []
    for rec in projection_results:
        ordinal, check_id = rec["id"].split(":")[1], rec["id"].split(":")[2]
        item_id = f"cal:{ordinal}"
        label = labels_by_key.get((item_id, check_id))
        if label is None:
            raise InfrastructureFailure(f"no frozen label for {item_id}/{check_id}")
        joined.append({**rec, "item_id": item_id, "label": label})
    return joined


def compute_rates(joined: list[dict], design_by_id: dict[str, dict]) -> dict[str, Any]:
    """Per-check metrics over two populations: primary (the check's own
    40 target items) and secondary (all 160, aggregate only). NEVER
    pooled across checks (640 pooled is explicitly forbidden)."""
    rates: dict[str, Any] = {}
    gates: dict[str, bool] = {}

    envelope_breaches = sum(1 for r in joined if r["outcome_reason"] == "envelope_exceeded")
    gates["zero_envelope_breaches_640"] = envelope_breaches == 0

    contract_agree = sum(
        1 for r in joined
        if (r["outcome"], r["outcome_reason"], r["severity"], r["advisory"]) ==
        (r["label"]["contract_tuple"]["outcome"], r["label"]["contract_tuple"]["outcome_reason"],
         r["label"]["contract_tuple"]["severity"], r["label"]["contract_tuple"]["advisory"])
    )
    gates["contract_tuple_agreement_640"] = contract_agree == len(joined)

    evaluator_errors = sum(1 for r in joined if r["outcome_reason"] in ("EVALUATOR_ERROR", "CONFIG_ERROR"))
    gates["zero_evaluator_errors"] = evaluator_errors == 0

    false_violations = 0
    unsafe_violations = 0
    escapes = 0
    in_domain_escapes = 0
    deliberate_abstention_correct = True
    in_domain_semantic_accuracy = True

    for r in joined:
        truth = r["label"]["semantic_truth"]
        outcome = r["outcome"]
        design_item = design_by_id.get(r["item_id"], {})
        is_target = design_item.get("target_check_id") == r["check_id"]

        if truth == "NO_VIOLATION" and outcome == "VIOLATION":
            false_violations += 1
        if truth == "INDETERMINATE" and outcome == "VIOLATION":
            unsafe_violations += 1
        if truth == "VIOLATION" and outcome in ("PASS", "NOT_EVALUATED"):
            escapes += 1
            if is_target and design_item.get("target_stratum") == "in_domain_violation":
                in_domain_escapes += 1

        if is_target and design_item.get("target_stratum") in ("in_domain_nonviolation", "in_domain_violation"):
            if outcome != SEMANTIC_CORRECTNESS_MAPPING.get(truth):
                in_domain_semantic_accuracy = False

        if is_target and design_item.get("target_stratum") == "indeterminate_or_unsafe":
            if not (outcome == "NOT_EVALUATED" and r["outcome_reason"] == r["label"]["contract_tuple"]["outcome_reason"]):
                deliberate_abstention_correct = False

    gates["zero_false_violations"] = false_violations == 0
    gates["zero_unsafe_violations"] = unsafe_violations == 0
    gates["zero_in_domain_escapes"] = in_domain_escapes == 0
    gates["in_domain_semantic_accuracy_100"] = in_domain_semantic_accuracy
    gates["deliberate_abstention_correct_100"] = deliberate_abstention_correct

    per_check: dict[str, Any] = {}
    for check_id in CHECK_IDS:
        check_records = [r for r in joined if r["check_id"] == check_id]
        target_records = [r for r in check_records if design_by_id.get(r["item_id"], {}).get("target_check_id") == check_id]

        def pop_metrics(records: list[dict]) -> dict[str, Any]:
            n_violation_truth = sum(1 for r in records if r["label"]["semantic_truth"] == "VIOLATION")
            n_novio_truth = sum(1 for r in records if r["label"]["semantic_truth"] == "NO_VIOLATION")
            n_indet_truth = sum(1 for r in records if r["label"]["semantic_truth"] == "INDETERMINATE")
            n_determinate = n_violation_truth + n_novio_truth
            emitted_violation = [r for r in records if r["outcome"] == "VIOLATION"]
            sem_violation_among_emitted = sum(1 for r in emitted_violation if r["label"]["semantic_truth"] == "VIOLATION")
            detected = sum(1 for r in records if r["label"]["semantic_truth"] == "VIOLATION" and r["outcome"] == "VIOLATION")
            false_v = sum(1 for r in records if r["label"]["semantic_truth"] == "NO_VIOLATION" and r["outcome"] == "VIOLATION")
            unsafe_v = sum(1 for r in records if r["label"]["semantic_truth"] == "INDETERMINATE" and r["outcome"] == "VIOLATION")
            esc = sum(1 for r in records if r["label"]["semantic_truth"] == "VIOLATION" and r["outcome"] in ("PASS", "NOT_EVALUATED"))
            cov_loss = sum(1 for r in records if r["label"]["semantic_truth"] != "INDETERMINATE" and r["outcome"] == "NOT_EVALUATED")
            correct_abstain = sum(1 for r in records if r["label"]["semantic_truth"] == "INDETERMINATE" and r["outcome"] == "NOT_EVALUATED")
            exact_conformance = sum(
                1 for r in records
                if (r["outcome"], r["outcome_reason"], r["severity"], r["advisory"]) ==
                (r["label"]["contract_tuple"]["outcome"], r["label"]["contract_tuple"]["outcome_reason"],
                 r["label"]["contract_tuple"]["severity"], r["label"]["contract_tuple"]["advisory"])
            )
            confusion: dict[str, dict[str, int]] = {}
            for r in records:
                confusion.setdefault(r["label"]["semantic_truth"], {}).setdefault(r["outcome"], 0)
                confusion[r["label"]["semantic_truth"]][r["outcome"]] += 1
            scenario_count = len({design_by_id.get(r["item_id"], {}).get("scenario_id") for r in records})
            return {
                "item_count": len(records) // 1,
                "scenario_count": scenario_count,
                "precision": _ratio(sem_violation_among_emitted, len(emitted_violation)),
                "recall": _ratio(detected, n_violation_truth),
                "false_violation_rate": _ratio(false_v, n_novio_truth),
                "unsafe_violation_rate": _ratio(unsafe_v, n_indet_truth),
                "escape_rate": _ratio(esc, n_violation_truth),
                "coverage_loss_abstention_rate": _ratio(cov_loss, n_determinate),
                "correct_abstention_rate": _ratio(correct_abstain, n_indet_truth),
                "exact_contract_conformance": _ratio(exact_conformance, len(records)),
                "confusion_matrix": confusion,
            }

        per_check[check_id] = {
            "primary_target_40": pop_metrics(target_records),
            "secondary_all_160": pop_metrics(check_records),
        }

    corpus_impact = {}
    for r in joined:
        design_item = design_by_id.get(r["item_id"], {})
        if design_item.get("target_stratum") != "determinate_out_of_domain":
            continue
        feat = design_item.get("introduced_feature")
        if not feat:
            continue
        key = f"{r['check_id']}:{feat.get('kind')}:{feat.get('table_path')}"
        corpus_impact.setdefault(key, set()).add(r["item_id"])
    ranking = sorted(
        ({"surface": k, "supporting_item_count": len(v), "item_ids": sorted(v)} for k, v in corpus_impact.items()),
        key=lambda x: -x["supporting_item_count"],
    )

    return {
        "gates": gates,
        "nine_gates_passed": all(gates.values()),
        "per_check": per_check,
        "corpus_impact_ranking": ranking,
        "record_count": len(joined),
        "caveat": (
            "PURPOSIVE SYNTHETIC DIAGNOSTIC CORPUS. Results are corpus-relative and are NOT "
            "estimates of real-world prevalence, precision, recall, or production performance. "
            "No confidence intervals are reported (no Wilson intervals anywhere): a purposive "
            "synthetic corpus with paired minimal-pair scenarios cannot support statistical "
            "inference over a real-world population."
        ),
    }


def render_report(rates: dict[str, Any]) -> str:
    lines = [
        "# SAN-881 Calibration RATES-REPORT",
        "",
        "PURPOSIVE SYNTHETIC DIAGNOSTIC CORPUS. Results are corpus-relative and are NOT",
        "estimates of real-world prevalence, precision, recall, or production performance.",
        "",
        f"Record count: {rates['record_count']}",
        f"Nine hard gates passed: {rates['nine_gates_passed']}",
        "",
        "## Gates",
        "",
    ]
    for name, passed in rates["gates"].items():
        lines.append(f"- {name}: {'PASS' if passed else 'FAIL'}")
    lines.append("")
    lines.append("## Per-check rates")
    for check_id, pops in rates["per_check"].items():
        lines.append(f"### {check_id}")
        for pop_name, pop in pops.items():
            lines.append(f"- {pop_name}: items={pop['item_count']} scenarios={pop['scenario_count']}")
            for metric in ("precision", "recall", "false_violation_rate", "unsafe_violation_rate",
                           "escape_rate", "coverage_loss_abstention_rate", "correct_abstention_rate",
                           "exact_contract_conformance"):
                v = pop[metric]
                rendered = "null" if v["value"] is None else f"{decimal.Decimal(v['value']):.2f}"
                lines.append(f"    - {metric}: {rendered} ({v['numerator']}/{v['denominator']})")
    lines.append("")
    lines.append("## Corpus-impact ranking (KNOWN_COVERAGE_GAP, deduped by item)")
    for entry in rates["corpus_impact_ranking"]:
        lines.append(f"- {entry['surface']}: {entry['supporting_item_count']} items {entry['item_ids']}")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------
# Transactional orchestration
# ---------------------------------------------------------------------

def run_pipeline(result_dir: Path) -> int:
    """Returns process exit code. On InfrastructureFailure, no final
    directory is left behind (result_dir is a caller-supplied FRESH temp
    dir the caller is responsible for discarding on that path). On a
    semantic gate failure, the complete artifact set IS written to
    result_dir and the function returns nonzero."""
    manifest = load_and_verify_freeze_manifest()

    corpus_inputs = json.loads((HERE / "corpus_inputs.json").read_text())
    labels_frozen = json.loads((HERE / "labels_frozen.json").read_text())
    design = json.loads((HERE / "design_metadata.json").read_text())
    design_by_id = {it["item_id"]: it for it in design["items"]}

    projection = build_projection(corpus_inputs)

    with tempfile.TemporaryDirectory() as tmp:
        workdir = Path(tmp)
        canonical_bytes, results, combined_hash = run_dual_harness(projection, workdir)

    joined = join_labels(results, labels_frozen)
    rates = compute_rates(joined, design_by_id)

    result_dir.mkdir(parents=True, exist_ok=True)
    outcomes = {
        "freeze_manifest_hash": hashlib.sha256(FREEZE_MANIFEST_PATH.read_bytes()).hexdigest(),
        "component_hashes": manifest,
        "record_count": len(joined),
        "py_ts_output_hash": combined_hash,
        "runner_git_commit": subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, capture_output=True, text=True).stdout.strip(),
        "measure_py_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "outcomes": [{"id": r["id"], "item_id": r["item_id"], "check_id": r["check_id"],
                      "outcome": r["outcome"], "outcome_reason": r["outcome_reason"],
                      "severity": r["severity"], "advisory": r["advisory"]} for r in joined],
    }
    (result_dir / "outcomes.json").write_bytes(canonical_json_bytes(outcomes))
    (result_dir / "rates.json").write_bytes(canonical_json_bytes(rates))
    (result_dir / "RATES-REPORT.md").write_text(render_report(rates))

    return 0 if rates["nine_gates_passed"] else 1


def main(argv: list[str] | None = None) -> int:
    result_dir = HERE / "results"
    try:
        return run_pipeline(result_dir)
    except (FreezeGateRefused, InfrastructureFailure) as exc:
        sys.stderr.write(f"FATAL: {exc}\n")
        if result_dir.exists() and not (result_dir / "outcomes.json").exists():
            shutil.rmtree(result_dir, ignore_errors=True)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
