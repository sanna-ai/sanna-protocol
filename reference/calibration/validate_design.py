#!/usr/bin/env python3
"""SAN-881 calibration corpus validator.

Public artifacts (corpus_inputs.json, evaluation_profile.json, the five
schemas/, commitment.json) are always validated. Sealed artifacts
(design_metadata.json, labels_author_semantic.json,
labels_author_contract.json, coverage_manifest.json) are validated ONLY
when --sealed-dir points at a local directory containing them -- this is
how the author validates privately before sealing (README workflow step
5), and how a later commit/reveal step re-validates against the sealed
staging copy. This script NEVER runs the evaluator over any corpus item;
every check here is either a JSON Schema validation or a structural /
cryptographic consistency check over already-authored bytes.

Usage:
    python3 reference/calibration/validate_design.py [--sealed-dir DIR]
        [--nonces-file FILE] [--reviewer-dir DIR]

Exit code 0 = all checks green. Nonzero = at least one check failed;
every failure is printed with enough detail to locate and fix it.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

try:
    from jsonschema import Draft202012Validator
except ImportError:  # pragma: no cover - CI pins jsonschema; keep a clear message locally
    Draft202012Validator = None

HERE = Path(__file__).resolve().parent
SCHEMAS = HERE / "schemas"

CHECK_IDS = ("C1", "C2", "C3", "C4")
STRATA = (
    "in_domain_nonviolation",
    "in_domain_violation",
    "determinate_out_of_domain",
    "indeterminate_or_unsafe",
)
OUTCOME_REASONS = {
    "detection_complete", "extraction_partial", "basis_conflict",
    "identity_ambiguous", "unsupported_claim_form", "condition_undecidable",
    "input_empty", "envelope_exceeded", "basis_empty",
}
SEMANTIC_TO_OUTCOME = {
    "NO_VIOLATION": "PASS",
    "VIOLATION": "VIOLATION",
    "INDETERMINATE": "NOT_EVALUATED",
}
DOMAIN_SEPARATOR = b"sanna-calibration-commitment/1"


class Errors(list):
    def add(self, msg: str) -> None:
        self.append(msg)


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------
# Commit/reveal primitives (also used by measure.py's freeze-gate cousin
# and by tests/reference/test_calibration.py's toy reveal tests)
# ---------------------------------------------------------------------

def compute_labeling_context_hash(components: list[bytes]) -> bytes:
    """SHA256 over the exact concatenation of the ordered raw components."""
    return hashlib.sha256(b"".join(components)).digest()


def compute_artifact_commitment(artifact_name: str, nonce: bytes, context_hash: bytes, artifact_bytes: bytes) -> str:
    """domain-separated SHA256 per commitment.json's commitment_algorithm.formula:
    SHA256("sanna-calibration-commitment/1" || NUL || artifact_name || NUL ||
    raw_32_byte_nonce || raw_32_byte_labeling_context_hash || exact_artifact_bytes)
    """
    if len(nonce) != 32:
        raise ValueError(f"nonce must be exactly 32 raw bytes, got {len(nonce)}")
    if len(context_hash) != 32:
        raise ValueError(f"labeling_context_hash must be exactly 32 raw bytes, got {len(context_hash)}")
    h = hashlib.sha256()
    h.update(DOMAIN_SEPARATOR)
    h.update(b"\x00")
    h.update(artifact_name.encode("ascii"))
    h.update(b"\x00")
    h.update(nonce)
    h.update(context_hash)
    h.update(artifact_bytes)
    return h.hexdigest()


def verify_reveal(commitment_hex: str, artifact_name: str, nonce: bytes, context_hash: bytes, artifact_bytes: bytes) -> bool:
    """Recompute the commitment from revealed bytes and compare, constant-shape."""
    try:
        recomputed = compute_artifact_commitment(artifact_name, nonce, context_hash, artifact_bytes)
    except ValueError:
        return False
    return recomputed == commitment_hex


# ---------------------------------------------------------------------
# Public-artifact checks
# ---------------------------------------------------------------------

def check_schemas_self_valid(errors: Errors) -> None:
    if Draft202012Validator is None:
        errors.add("jsonschema is not installed; cannot validate schemas")
        return
    for name in [
        "design_metadata_schema.json", "labels_schema.json",
        "coverage_manifest_schema.json", "commitment_schema.json",
        "freeze_manifest_schema.json",
    ]:
        path = SCHEMAS / name
        if not path.exists():
            errors.add(f"missing schema file: {name}")
            continue
        try:
            schema = load_json(path)
            Draft202012Validator.check_schema(schema)
        except Exception as exc:  # noqa: BLE001
            errors.add(f"{name}: invalid JSON Schema: {exc}")


def check_corpus_inputs(errors: Errors, corpus: list[dict]) -> dict[str, dict]:
    """Structural checks (allowlist, ordinals relative to list position,
    tier_1-only, dup-tuple, ENV-cap statics). Count-against-160 is
    checked separately by the caller so this function stays toy-testable
    on corpora of any size."""
    by_id: dict[str, dict] = {}
    seen_tuples: dict[tuple, int] = {}
    for idx, rec in enumerate(corpus):
        expected_id = f"cal:{idx:03d}"
        if rec.get("id") != expected_id:
            errors.add(f"corpus_inputs.json[{idx}]: id ordinal mismatch, expected {expected_id}, got {rec.get('id')}")
        by_id[rec.get("id", expected_id)] = rec

        keys = set(rec.keys())
        has_context = "context" in keys
        has_sources = "context_sources" in keys
        if has_context == has_sources:
            errors.add(f"{rec.get('id')}: must have EXACTLY ONE of context/context_sources, got context={has_context} sources={has_sources}")
        allowed = {"id", "output"} | ({"context"} if has_context else {"context_sources"})
        if keys != allowed:
            errors.add(f"{rec.get('id')}: disallowed keys {keys - allowed}")

        if has_sources:
            for s_idx, source in enumerate(rec["context_sources"]):
                if set(source.keys()) != {"text", "tier"}:
                    errors.add(f"{rec.get('id')}.context_sources[{s_idx}]: expected exactly {{text,tier}}, got {set(source.keys())}")
                if source.get("tier") != "tier_1":
                    errors.add(f"{rec.get('id')}.context_sources[{s_idx}]: non-tier_1 source found (tier_1-only corpus, v1)")

        ctx_text = rec.get("context") or " ".join(s["text"] for s in rec.get("context_sources", []))
        out_text = rec.get("output", "")
        key = (ctx_text, out_text)
        if key in seen_tuples:
            errors.add(f"{rec.get('id')}: duplicate canonical (context,output) tuple with item at index {seen_tuples[key]}")
        seen_tuples[key] = idx

        # ENV-cap statics (field bytes, sentence counts) -- generous
        # static ceilings; the corpus is breach-free by construction.
        if len(out_text.encode("utf-8")) > 1_048_576:
            errors.add(f"{rec.get('id')}: output exceeds ENV_MAX_FIELD_BYTES")
        if len(ctx_text.encode("utf-8")) > 1_048_576:
            errors.add(f"{rec.get('id')}: context exceeds ENV_MAX_FIELD_BYTES")
    return by_id


def check_evaluation_profile(errors: Errors, profile: dict) -> None:
    if profile.get("corpus_version") != 1:
        errors.add("evaluation_profile.json: corpus_version must be 1")
    if profile.get("scope") != ["C1", "C2", "C3", "C4"]:
        errors.add("evaluation_profile.json: scope must be exactly [C1,C2,C3,C4]")
    pins = profile.get("spec_pins", {})
    if pins.get("algorithm_sha256") != "979cf1368fb3cdc6e51b78eaa200a8bcef81e03bfcdc6e89a6c1667b30c16c58":
        errors.add("evaluation_profile.json: algorithm_sha256 pin mismatch")
    if pins.get("tables_sha256") != "0a18dd94bc811bb3166a4f8812e78f2b053a9f8f083b781a21fb0f8371f54ecc":
        errors.add("evaluation_profile.json: tables_sha256 pin mismatch")


def check_commitment(errors: Errors, commitment: dict) -> None:
    if commitment.get("corpus_version") != 1:
        errors.add("commitment.json: corpus_version must be 1")
    names = {c["artifact_name"] for c in commitment.get("author_commitments", [])}
    expected = {
        "design_metadata.json", "labels_author_semantic.json",
        "labels_author_contract.json", "coverage_manifest.json",
    }
    if names != expected:
        errors.add(f"commitment.json: author_commitments artifact set mismatch: {names} != {expected}")
    for c in commitment.get("author_commitments", []):
        if len(c.get("commitment_hex", "")) != 64:
            errors.add(f"commitment.json: {c.get('artifact_name')} commitment_hex is not 64 hex chars")
        if not isinstance(c.get("byte_length"), int) or c["byte_length"] <= 0:
            errors.add(f"commitment.json: {c.get('artifact_name')} byte_length must be a positive int")
    ctx_hash = commitment.get("labeling_context_hash", "")
    if len(ctx_hash) != 64:
        errors.add("commitment.json: labeling_context_hash is not 64 hex chars")


def recompute_labeling_context_hash_from_public(errors: Errors, base_commit_sha: str, corpus_bytes: bytes,
                                                 profile_bytes: bytes, schema_bytes_sorted: list[bytes],
                                                 algorithm_bytes: bytes, tables_bytes: bytes) -> str:
    components = (
        [base_commit_sha.encode("ascii"), hashlib.sha256(corpus_bytes).digest(),
         hashlib.sha256(profile_bytes).digest()]
        + [hashlib.sha256(b).digest() for b in schema_bytes_sorted]
        + [hashlib.sha256(algorithm_bytes).digest(), hashlib.sha256(tables_bytes).digest()]
    )
    return compute_labeling_context_hash(components).hex()


# ---------------------------------------------------------------------
# Sealed-artifact checks (require --sealed-dir)
# ---------------------------------------------------------------------

def check_design_metadata(errors: Errors, design: dict, corpus_by_id: dict) -> dict[str, dict]:
    items = design.get("items", [])
    by_id: dict[str, dict] = {}
    if len(items) != 160:
        errors.add(f"design_metadata.json: expected 160 items, got {len(items)}")

    per_check_stratum: dict[tuple, int] = {}
    facet_closed_list = {
        "facet:availability", "facet:refund_availability", "facet:exchange_availability",
        "facet:discount_availability", "facet:access_permission", "facet:approval_requirement",
        "facet:eligibility", "facet:cost", "facet:duration", "facet:limit",
    }

    for it in items:
        iid = it.get("item_id")
        if iid in by_id:
            errors.add(f"design_metadata.json: duplicate item_id {iid}")
        by_id[iid] = it
        if iid not in corpus_by_id:
            errors.add(f"design_metadata.json: item_id {iid} not present in corpus_inputs.json")

        check_id = it.get("target_check_id")
        stratum = it.get("target_stratum")
        if check_id not in CHECK_IDS:
            errors.add(f"{iid}: invalid target_check_id {check_id}")
        if stratum not in STRATA:
            errors.add(f"{iid}: invalid target_stratum {stratum}")
        per_check_stratum[(check_id, stratum)] = per_check_stratum.get((check_id, stratum), 0) + 1

        for ff in it.get("facet_families", []):
            if ff not in facet_closed_list:
                errors.add(f"{iid}: facet_families entry {ff} not in the closed facets_v1 list")

        mp = it.get("minimal_pair_of")
        feat = it.get("introduced_feature")
        if stratum == "determinate_out_of_domain":
            if mp is None:
                errors.add(f"{iid}: determinate_out_of_domain item missing minimal_pair_of")
            if feat is None:
                errors.add(f"{iid}: determinate_out_of_domain item missing introduced_feature")
        else:
            if mp is not None:
                errors.add(f"{iid}: non-determinate_out_of_domain item ({stratum}) must not have minimal_pair_of")
            if feat is not None:
                errors.add(f"{iid}: non-determinate_out_of_domain item ({stratum}) must not have introduced_feature")

    for check_id in CHECK_IDS:
        for stratum in STRATA:
            n = per_check_stratum.get((check_id, stratum), 0)
            if n != 10:
                errors.add(f"design_metadata.json: {check_id}/{stratum} has {n} items, expected 10")

    # 5/5 determinate_out_of_domain balance is validated jointly with the
    # semantic labels (truth balance), see check_dod_balance_and_pairs.

    return by_id


def check_dod_balance_and_pairs(errors: Errors, design_by_id: dict, semantic_by_key: dict) -> None:
    for check_id in CHECK_IDS:
        dod_items = [it for it in design_by_id.values()
                     if it["target_check_id"] == check_id and it["target_stratum"] == "determinate_out_of_domain"]
        truths = {"VIOLATION": 0, "NO_VIOLATION": 0, "INDETERMINATE": 0}
        for it in dod_items:
            truth = semantic_by_key.get((it["item_id"], check_id), {}).get("semantic_truth")
            if truth in truths:
                truths[truth] += 1
            else:
                errors.add(f"{it['item_id']}/{check_id}: determinate_out_of_domain semantic_truth {truth} is not VIOLATION/NO_VIOLATION")
        if truths["VIOLATION"] != 5 or truths["NO_VIOLATION"] != 5 or truths["INDETERMINATE"] != 0:
            errors.add(f"{check_id}: determinate_out_of_domain truth balance is {truths}, expected exactly 5 VIOLATION / 5 NO_VIOLATION")

    # Minimal pairs: one-way, unique, acyclic; control shares check+domain+
    # semantic_truth+scenario_id; same-semantics in-table replacement proof
    # (best-effort: control and dod item must differ ONLY in that the dod
    # item carries an introduced_feature the control does not, and share
    # the same scenario_id family).
    control_usage: dict[str, str] = {}
    for it in design_by_id.values():
        if it["target_stratum"] != "determinate_out_of_domain":
            continue
        mp = it["minimal_pair_of"]
        control = design_by_id.get(mp)
        if control is None:
            errors.add(f"{it['item_id']}: minimal_pair_of {mp} does not resolve to a design_metadata item")
            continue
        if control["target_stratum"] not in ("in_domain_nonviolation", "in_domain_violation"):
            errors.add(f"{it['item_id']}: minimal_pair_of {mp} does not point at an in-domain control")
        if control["target_check_id"] != it["target_check_id"]:
            errors.add(f"{it['item_id']}: minimal_pair_of check mismatch ({control['target_check_id']} != {it['target_check_id']})")
        if control["domain"] != it["domain"]:
            errors.add(f"{it['item_id']}: minimal_pair_of domain mismatch")
        control_truth = semantic_by_key.get((mp, it["target_check_id"]), {}).get("semantic_truth")
        expected_control_truth = "NO_VIOLATION" if control["target_stratum"] == "in_domain_nonviolation" else "VIOLATION"
        if control_truth != expected_control_truth:
            errors.add(f"{it['item_id']}: minimal_pair_of {mp} truth {control_truth} != expected {expected_control_truth}")
        dod_truth = semantic_by_key.get((it["item_id"], it["target_check_id"]), {}).get("semantic_truth")
        if dod_truth != control_truth:
            errors.add(f"{it['item_id']}: same-semantics proof failed -- dod truth {dod_truth} != control truth {control_truth}")
        if mp == it["item_id"]:
            errors.add(f"{it['item_id']}: self-referential minimal_pair_of")
        if mp in control_usage:
            errors.add(f"minimal_pair_of control {mp} reused by both {control_usage[mp]} and {it['item_id']}")
        control_usage[mp] = it["item_id"]
        # acyclicity: a control must never itself be a determinate_out_of_domain item
        if control["target_stratum"] == "determinate_out_of_domain":
            errors.add(f"{it['item_id']}: minimal_pair_of {mp} is itself determinate_out_of_domain (cycle risk)")


def check_labels(errors: Errors, semantic: list[dict], contract: list[dict], design_by_id: dict):
    if len(semantic) != 640:
        errors.add(f"labels_author_semantic.json: expected 640 records, got {len(semantic)}")
    if len(contract) != 640:
        errors.add(f"labels_author_contract.json: expected 640 records, got {len(contract)}")

    ALLOWED_SEMANTIC_KEYS = {"item_id", "check_id", "semantic_truth", "semantic_rationale"}
    semantic_by_key: dict[tuple, dict] = {}
    seen_pairs = set()
    for r in semantic:
        if set(r.keys()) != ALLOWED_SEMANTIC_KEYS:
            errors.add(f"labels_author_semantic.json {r.get('item_id')}/{r.get('check_id')}: cognitive-separation violation, extra/missing keys {set(r.keys()) ^ ALLOWED_SEMANTIC_KEYS}")
        if r.get("semantic_truth") not in SEMANTIC_TO_OUTCOME:
            errors.add(f"{r.get('item_id')}/{r.get('check_id')}: invalid semantic_truth {r.get('semantic_truth')}")
        key = (r.get("item_id"), r.get("check_id"))
        if key in seen_pairs:
            errors.add(f"labels_author_semantic.json: duplicate (item_id,check_id) {key}")
        seen_pairs.add(key)
        semantic_by_key[key] = r

    contract_by_key: dict[tuple, dict] = {}
    seen_pairs_c = set()
    for r in contract:
        key = (r.get("item_id"), r.get("check_id"))
        if key in seen_pairs_c:
            errors.add(f"labels_author_contract.json: duplicate (item_id,check_id) {key}")
        seen_pairs_c.add(key)
        contract_by_key[key] = r
        ct = r.get("contract_tuple", {})
        outcome = ct.get("outcome")
        reason = ct.get("outcome_reason")
        severity = ct.get("severity")
        advisory = ct.get("advisory")
        if outcome not in ("PASS", "VIOLATION", "NOT_EVALUATED"):
            errors.add(f"{key}: invalid contract outcome {outcome}")
        if reason not in OUTCOME_REASONS:
            errors.add(f"{key}: invalid contract outcome_reason {reason}")
        if outcome == "VIOLATION":
            expected_sev = "critical" if r.get("check_id") == "C1" else "warning"
            if severity != expected_sev:
                errors.add(f"{key}: VIOLATION severity must be {expected_sev}, got {severity}")
        else:
            if severity is not None:
                errors.add(f"{key}: severity must be null when outcome is {outcome}, got {severity}")
        if advisory is not False:
            errors.add(f"{key}: advisory must be false for this tier_1-only corpus, got {advisory}")
        if r.get("competence") not in ("IN_DOMAIN", "KNOWN_COVERAGE_GAP", "DELIBERATE_ABSTENTION"):
            errors.add(f"{key}: invalid competence {r.get('competence')}")

    # cross-check: every (item, check) pair present in both files, and
    # every design_metadata item has exactly 4 check records in each.
    expected_keys = {(iid, c) for iid in design_by_id for c in CHECK_IDS}
    if set(semantic_by_key) != expected_keys:
        missing = expected_keys - set(semantic_by_key)
        extra = set(semantic_by_key) - expected_keys
        errors.add(f"labels_author_semantic.json key-set mismatch: missing={len(missing)} extra={len(extra)}")
    if set(contract_by_key) != expected_keys:
        missing = expected_keys - set(contract_by_key)
        extra = set(contract_by_key) - expected_keys
        errors.add(f"labels_author_contract.json key-set mismatch: missing={len(missing)} extra={len(extra)}")

    # competence-vs-feature consistency: KNOWN_COVERAGE_GAP only on the
    # TARGET check of a determinate_out_of_domain item; DELIBERATE_
    # ABSTENTION only where semantic_truth is INDETERMINATE.
    for (iid, cid), r in contract_by_key.items():
        design_item = design_by_id.get(iid)
        if design_item is None:
            continue
        sem = semantic_by_key.get((iid, cid), {})
        truth = sem.get("semantic_truth")
        expected_outcome_from_truth = SEMANTIC_TO_OUTCOME.get(truth)
        comp = r.get("competence")
        if comp == "DELIBERATE_ABSTENTION" and truth != "INDETERMINATE":
            errors.add(f"{iid}/{cid}: DELIBERATE_ABSTENTION competence requires semantic_truth INDETERMINATE, got {truth}")
        if truth == "INDETERMINATE" and comp != "DELIBERATE_ABSTENTION":
            errors.add(f"{iid}/{cid}: INDETERMINATE semantic_truth requires DELIBERATE_ABSTENTION competence, got {comp}")
        if comp == "KNOWN_COVERAGE_GAP":
            if not (design_item["target_check_id"] == cid and design_item["target_stratum"] == "determinate_out_of_domain"):
                errors.add(f"{iid}/{cid}: KNOWN_COVERAGE_GAP competence only valid on the item's own target check's determinate_out_of_domain record")
        if design_item["target_check_id"] == cid and design_item["target_stratum"] in ("in_domain_nonviolation", "in_domain_violation"):
            if comp != "IN_DOMAIN":
                errors.add(f"{iid}/{cid}: target in_domain_* record must have competence IN_DOMAIN, got {comp}")
            # gate 8 mapping (mechanical crosswalk): semantic truth NO_VIOLATION/VIOLATION maps to PASS/VIOLATION
            if expected_outcome_from_truth and r["contract_tuple"]["outcome"] != expected_outcome_from_truth:
                errors.add(f"{iid}/{cid}: target in_domain_* contract outcome {r['contract_tuple']['outcome']} != semantic-correctness-mapped {expected_outcome_from_truth}")

    return semantic_by_key, contract_by_key


def check_coverage_manifest(errors: Errors, coverage: dict, design_by_id: dict) -> None:
    if not isinstance(coverage, dict):
        errors.add("coverage_manifest.json: top level must be an object")
        return
    scenario_by_item = {iid: it["scenario_id"] for iid, it in design_by_id.items()}
    for surface, records in coverage.items():
        if not isinstance(records, list):
            errors.add(f"coverage_manifest.json[{surface}]: value must be a list")
            continue
        scenarios_claimed: dict[str, list] = {}
        for rec in records:
            if not isinstance(rec, dict) or set(rec.keys()) != {"item_id", "check_id", "field"}:
                errors.add(f"coverage_manifest.json[{surface}]: malformed evidence record {rec}")
                continue
            if rec["item_id"] not in design_by_id:
                errors.add(f"coverage_manifest.json[{surface}]: unknown item_id {rec['item_id']}")
                continue
            if rec["check_id"] not in CHECK_IDS:
                errors.add(f"coverage_manifest.json[{surface}]: invalid check_id {rec['check_id']}")
            if rec["field"] not in ("context", "output"):
                errors.add(f"coverage_manifest.json[{surface}]: invalid field {rec['field']}")
            sid = scenario_by_item.get(rec["item_id"])
            scenarios_claimed.setdefault(sid, []).append(rec["item_id"])
        # scenario independence: two evidence records for the SAME surface
        # sharing a scenario_id (paraphrases) are not independent observations
        for sid, item_ids in scenarios_claimed.items():
            if len(set(item_ids)) > 1:
                errors.add(f"coverage_manifest.json[{surface}]: scenario independence violated -- items {sorted(set(item_ids))} share scenario_id {sid!r}")


# ---------------------------------------------------------------------
# Reveal verification (executable; toy-tested by test_calibration.py)
# ---------------------------------------------------------------------

def reveal_verify_set(commitment: dict, artifact_bytes_by_name: dict[str, bytes], nonces_by_name: dict[str, str]) -> list[str]:
    """Pure, filesystem-free reveal verification over in-memory artifact
    bytes + hex nonces. Returns a list of failures (empty = all declared
    commitments verify AND no undeclared/extra artifact was supplied).
    Exercised directly by the toy reveal tests (valid, tampered-byte,
    wrong-nonce, missing-artifact, extra-artifact)."""
    failures: list[str] = []
    ctx_hash = bytes.fromhex(commitment["labeling_context_hash"])
    declared = {c["artifact_name"] for c in commitment.get("author_commitments", [])}

    extra = set(artifact_bytes_by_name) - declared
    if extra:
        failures.append(f"reveal verification: undeclared extra artifact(s) supplied: {sorted(extra)}")

    for entry in commitment.get("author_commitments", []):
        name = entry["artifact_name"]
        artifact_bytes = artifact_bytes_by_name.get(name)
        if artifact_bytes is None:
            failures.append(f"reveal verification: sealed artifact {name} not supplied")
            continue
        if len(artifact_bytes) != entry["byte_length"]:
            failures.append(f"reveal verification: {name} byte_length mismatch (commitment says {entry['byte_length']}, actual {len(artifact_bytes)})")
        nonce_hex = nonces_by_name.get(name)
        if nonce_hex is None:
            failures.append(f"reveal verification: no nonce provided for {name}")
            continue
        nonce = bytes.fromhex(nonce_hex)
        if not verify_reveal(entry["commitment_hex"], name, nonce, ctx_hash, artifact_bytes):
            failures.append(f"reveal verification: {name} commitment does NOT verify against revealed nonce+bytes")
    return failures


def run_reveal_verification(errors: Errors, commitment: dict, sealed_dir: Path, nonces: dict[str, str]) -> None:
    artifact_bytes_by_name = {}
    for entry in commitment.get("author_commitments", []):
        path = sealed_dir / entry["artifact_name"]
        if path.exists():
            artifact_bytes_by_name[entry["artifact_name"]] = path.read_bytes()
    for failure in reveal_verify_set(commitment, artifact_bytes_by_name, nonces):
        errors.add(failure)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sealed-dir", type=Path, default=None,
                         help="local directory containing design_metadata.json, labels_author_*.json, coverage_manifest.json (never committed)")
    parser.add_argument("--nonces-file", type=Path, default=None,
                         help="local JSON {artifact_name: hex_nonce} for reveal verification (never committed)")
    args = parser.parse_args(argv)

    errors = Errors()

    check_schemas_self_valid(errors)

    corpus = load_json(HERE / "corpus_inputs.json")
    if len(corpus) != 160:
        errors.add(f"corpus_inputs.json: expected 160 items, got {len(corpus)}")
    corpus_by_id = check_corpus_inputs(errors, corpus)

    profile = load_json(HERE / "evaluation_profile.json")
    check_evaluation_profile(errors, profile)

    commitment_path = HERE / "commitment.json"
    commitment = None
    if commitment_path.exists():
        commitment = load_json(commitment_path)
        check_commitment(errors, commitment)

    design_by_id: dict = {}
    if args.sealed_dir and args.sealed_dir.exists():
        design = load_json(args.sealed_dir / "design_metadata.json")
        design_by_id = check_design_metadata(errors, design, corpus_by_id)

        semantic = load_json(args.sealed_dir / "labels_author_semantic.json")
        contract = load_json(args.sealed_dir / "labels_author_contract.json")
        semantic_by_key, _contract_by_key = check_labels(errors, semantic, contract, design_by_id)

        check_dod_balance_and_pairs(errors, design_by_id, semantic_by_key)

        coverage_path = args.sealed_dir / "coverage_manifest.json"
        if coverage_path.exists():
            coverage = load_json(coverage_path)
            check_coverage_manifest(errors, coverage, design_by_id)

        if commitment is not None and args.nonces_file and args.nonces_file.exists():
            nonces = load_json(args.nonces_file)
            run_reveal_verification(errors, commitment, args.sealed_dir, nonces)

    if errors:
        sys.stderr.write(f"VALIDATION FAILED: {len(errors)} error(s)\n")
        for e in errors:
            sys.stderr.write(f"  - {e}\n")
        return 1

    sys.stdout.write("VALIDATION OK: all checks passed\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
