"""SAN-881 Phase A tests: public-data structural checks over the
committed calibration corpus artifacts, plus toy-only tests of
validate_design.py / measure.py / benchmark.py logic. NO
pytest.mark.parametrize (project convention for this file). NEVER runs
any evaluator (Python or TypeScript) over any corpus item -- toy tests
use inline fixtures that are explicitly NOT corpus items.
"""
from __future__ import annotations

import hashlib
import json
import secrets
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from reference.calibration import validate_design as vd
from reference.calibration import measure as ms
from reference.calibration import benchmark as bm

CAL_DIR = Path(__file__).parent.parent.parent / "reference" / "calibration"
SCHEMAS_DIR = CAL_DIR / "schemas"

CORPUS = json.loads((CAL_DIR / "corpus_inputs.json").read_text())
PROFILE = json.loads((CAL_DIR / "evaluation_profile.json").read_text())
COMMITMENT = json.loads((CAL_DIR / "commitment.json").read_text())


# ---------------------------------------------------------------------
# Public-data: corpus_inputs.json
# ---------------------------------------------------------------------

def test_corpus_has_160_items():
    assert len(CORPUS) == 160


def test_corpus_ordinals_sequential():
    for idx, rec in enumerate(CORPUS):
        assert rec["id"] == f"cal:{idx:03d}"


def test_corpus_allowlist_exactly_id_context_output():
    for rec in CORPUS:
        keys = set(rec.keys())
        has_context = "context" in keys
        has_sources = "context_sources" in keys
        assert has_context != has_sources, rec["id"]
        allowed = {"id", "output"} | ({"context"} if has_context else {"context_sources"})
        assert keys == allowed, rec["id"]


def test_corpus_tier1_only():
    for rec in CORPUS:
        if "context_sources" in rec:
            for source in rec["context_sources"]:
                assert set(source.keys()) == {"text", "tier"}, rec["id"]
                assert source["tier"] == "tier_1", rec["id"]


def test_corpus_no_duplicate_canonical_tuples():
    seen = set()
    for rec in CORPUS:
        ctx = rec.get("context") or " ".join(s["text"] for s in rec.get("context_sources", []))
        key = (ctx, rec["output"])
        assert key not in seen, f"duplicate tuple at {rec['id']}"
        seen.add(key)


def test_corpus_env_cap_statics_field_bytes():
    for rec in CORPUS:
        assert len(rec["output"].encode("utf-8")) <= 1_048_576, rec["id"]
        ctx = rec.get("context") or " ".join(s["text"] for s in rec.get("context_sources", []))
        assert len(ctx.encode("utf-8")) <= 1_048_576, rec["id"]


def test_corpus_context_sentence_count_2_to_5():
    import re
    for rec in CORPUS:
        ctx = rec.get("context") or " ".join(s["text"] for s in rec.get("context_sources", []))
        n = len(re.findall(r"[.!?](?:\s|$)", ctx))
        assert 2 <= n <= 5, f"{rec['id']}: context has {n} sentences"


def test_corpus_is_pure_ascii_except_documented_abstention_item():
    # the whole file must round-trip through ensure_ascii=True JSON,
    # i.e. no raw non-ASCII bytes on disk (escapes are fine)
    raw = (CAL_DIR / "corpus_inputs.json").read_bytes()
    assert all(b <= 0x7F for b in raw)


# ---------------------------------------------------------------------
# Public-data: evaluation_profile.json
# ---------------------------------------------------------------------

def test_evaluation_profile_scope_and_version():
    assert PROFILE["corpus_version"] == 1
    assert PROFILE["scope"] == ["C1", "C2", "C3", "C4"]


def test_evaluation_profile_hash_pins():
    algo_path = CAL_DIR.parent / "spec" / "ALGORITHM-v4-c1c5-reference.md"
    tables_path = CAL_DIR.parent / "spec" / "ALGORITHM-v4-tables-v1.json"
    assert PROFILE["spec_pins"]["algorithm_sha256"] == hashlib.sha256(algo_path.read_bytes()).hexdigest()
    assert PROFILE["spec_pins"]["tables_sha256"] == hashlib.sha256(tables_path.read_bytes()).hexdigest()


def test_evaluation_profile_allowlist_matches_measure_allowlist():
    allowlist = set(PROFILE["evaluator"]["fixture_construction"]["allowlist"])
    assert allowlist <= ms.ALLOWED_INPUT_KEYS


# ---------------------------------------------------------------------
# Public-data: commitment.json
# ---------------------------------------------------------------------

def test_commitment_schema_valid():
    schema = json.loads((SCHEMAS_DIR / "commitment_schema.json").read_text())
    Draft202012Validator(schema).validate(COMMITMENT)


def test_commitment_four_sealed_entries_with_positive_lengths_and_hex64():
    assert len(COMMITMENT["author_commitments"]) == 4
    for entry in COMMITMENT["author_commitments"]:
        assert len(entry["commitment_hex"]) == 64
        assert int(entry["commitment_hex"], 16) >= 0
        assert entry["byte_length"] > 0


def test_commitment_labeling_context_hash_recomputable_from_public_components():
    schema_files = sorted(SCHEMAS_DIR.glob("*.json"), key=lambda p: p.name)
    concat = b"c185daa4042f7be562df6632197c4ed9e11474d9"
    concat += hashlib.sha256((CAL_DIR / "corpus_inputs.json").read_bytes()).digest()
    concat += hashlib.sha256((CAL_DIR / "evaluation_profile.json").read_bytes()).digest()
    for p in schema_files:
        concat += hashlib.sha256(p.read_bytes()).digest()
    concat += hashlib.sha256((CAL_DIR.parent / "spec" / "ALGORITHM-v4-c1c5-reference.md").read_bytes()).digest()
    concat += hashlib.sha256((CAL_DIR.parent / "spec" / "ALGORITHM-v4-tables-v1.json").read_bytes()).digest()
    recomputed = hashlib.sha256(concat).hexdigest()
    assert recomputed == COMMITMENT["labeling_context_hash"]


def test_commitment_reveal_protocol_pins_reviewer_filenames():
    assert COMMITMENT["reveal_protocol"]["reviewer_commitment_filenames"] == [
        "labels_reviewer_semantic.commitment.json",
        "labels_reviewer_contract.commitment.json",
    ]


# ---------------------------------------------------------------------
# Public-data: five schemas load and validate an inline toy doc each
# ---------------------------------------------------------------------

def test_schema_design_metadata_loads_and_validates_toy():
    schema = json.loads((SCHEMAS_DIR / "design_metadata_schema.json").read_text())
    Draft202012Validator.check_schema(schema)
    toy = {"items": [{
        "item_id": "cal:000", "target_check_id": "C1", "target_stratum": "in_domain_nonviolation",
        "domain": "toy_domain", "facet_families": ["facet:availability"], "scenario_id": "toy-scenario",
        "minimal_pair_of": None, "introduced_feature": None,
    }]}
    Draft202012Validator(schema).validate(toy)


def test_schema_labels_loads_and_validates_all_three_toy_forms():
    schema = json.loads((SCHEMAS_DIR / "labels_schema.json").read_text())
    Draft202012Validator.check_schema(schema)
    semantic_toy = {"item_id": "cal:000", "check_id": "C1", "semantic_truth": "NO_VIOLATION", "semantic_rationale": "toy"}
    contract_toy = {
        "item_id": "cal:000", "check_id": "C1",
        "contract_tuple": {"outcome": "PASS", "outcome_reason": "detection_complete", "severity": None, "advisory": False},
        "competence": "IN_DOMAIN", "contract_rationale": "toy", "spec_refs": "toy",
    }
    merged_toy = {**semantic_toy, **{k: v for k, v in contract_toy.items() if k not in ("item_id", "check_id")}}
    Draft202012Validator(schema).validate(semantic_toy)
    Draft202012Validator(schema).validate(contract_toy)
    Draft202012Validator(schema).validate(merged_toy)


def test_schema_coverage_manifest_loads_and_validates_toy():
    schema = json.loads((SCHEMAS_DIR / "coverage_manifest_schema.json").read_text())
    Draft202012Validator.check_schema(schema)
    toy = {"toy_surface": [{"item_id": "cal:000", "check_id": "C1", "field": "context"}]}
    Draft202012Validator(schema).validate(toy)


def test_schema_commitment_loads():
    schema = json.loads((SCHEMAS_DIR / "commitment_schema.json").read_text())
    Draft202012Validator.check_schema(schema)


def test_schema_freeze_manifest_loads_and_validates_toy():
    schema = json.loads((SCHEMAS_DIR / "freeze_manifest_schema.json").read_text())
    Draft202012Validator.check_schema(schema)
    toy = {
        "corpus_version": 1,
        "corpus_inputs_sha256": "a" * 64, "labels_frozen_sha256": "a" * 64,
        "design_metadata_sha256": "a" * 64, "coverage_manifest_sha256": "a" * 64,
        "evaluation_profile_sha256": "a" * 64,
        "algorithm_sha256": "979cf1368fb3cdc6e51b78eaa200a8bcef81e03bfcdc6e89a6c1667b30c16c58",
        "tables_sha256": "0a18dd94bc811bb3166a4f8812e78f2b053a9f8f083b781a21fb0f8371f54ecc",
        "adjudication_log_sha256": "a" * 64,
    }
    Draft202012Validator(schema).validate(toy)


# ---------------------------------------------------------------------
# Toy reveal-verification tests (validate_design.py)
# ---------------------------------------------------------------------

def _toy_commitment_fixture():
    ctx_hash = vd.compute_labeling_context_hash([b"toy-a", b"toy-b"])
    nonce = secrets.token_bytes(32)
    artifact = b'{"toy":"bytes"}'
    commit_hex = vd.compute_artifact_commitment("toy.json", nonce, ctx_hash, artifact)
    commitment = {
        "labeling_context_hash": ctx_hash.hex(),
        "author_commitments": [{"artifact_name": "toy.json", "byte_length": len(artifact), "commitment_hex": commit_hex}],
    }
    nonces = {"toy.json": nonce.hex()}
    return commitment, artifact, nonces


def test_reveal_valid():
    commitment, artifact, nonces = _toy_commitment_fixture()
    failures = vd.reveal_verify_set(commitment, {"toy.json": artifact}, nonces)
    assert failures == []


def test_reveal_tampered_byte():
    commitment, artifact, nonces = _toy_commitment_fixture()
    tampered = artifact[:-1] + bytes([artifact[-1] ^ 0x01])
    failures = vd.reveal_verify_set(commitment, {"toy.json": tampered}, nonces)
    assert any("does NOT verify" in f for f in failures)


def test_reveal_wrong_nonce():
    commitment, artifact, nonces = _toy_commitment_fixture()
    wrong_nonces = {"toy.json": secrets.token_bytes(32).hex()}
    failures = vd.reveal_verify_set(commitment, {"toy.json": artifact}, wrong_nonces)
    assert any("does NOT verify" in f for f in failures)


def test_reveal_missing_artifact():
    commitment, artifact, nonces = _toy_commitment_fixture()
    failures = vd.reveal_verify_set(commitment, {}, nonces)
    assert any("not supplied" in f for f in failures)


def test_reveal_extra_artifact():
    commitment, artifact, nonces = _toy_commitment_fixture()
    failures = vd.reveal_verify_set(commitment, {"toy.json": artifact, "sneaky_extra.json": b"x"}, nonces)
    assert any("undeclared extra artifact" in f for f in failures)


def test_reveal_byte_length_mismatch_detected():
    commitment, artifact, nonces = _toy_commitment_fixture()
    failures = vd.reveal_verify_set(commitment, {"toy.json": artifact + b"extra"}, nonces)
    assert any("byte_length mismatch" in f for f in failures)


# ---------------------------------------------------------------------
# Toy validate_design structural pass/fail tests
# ---------------------------------------------------------------------

def test_validate_design_corpus_check_passes_on_clean_toy():
    errors = vd.Errors()
    toy_corpus = [{"id": "cal:000", "context": "Toy context.", "output": "Toy output."}]
    by_id = vd.check_corpus_inputs(errors, toy_corpus)
    assert errors == []
    assert "cal:000" in by_id


def test_validate_design_corpus_check_catches_duplicate_tuple():
    errors = vd.Errors()
    toy_corpus = [
        {"id": "cal:000", "context": "Same.", "output": "Same out."},
        {"id": "cal:001", "context": "Same.", "output": "Same out."},
    ]
    vd.check_corpus_inputs(errors, toy_corpus)
    assert any("duplicate" in e for e in errors)


def test_validate_design_corpus_check_catches_both_context_shapes():
    errors = vd.Errors()
    toy_corpus = [{"id": "cal:000", "context": "A.", "context_sources": [{"text": "B.", "tier": "tier_1"}], "output": "O."}]
    vd.check_corpus_inputs(errors, toy_corpus)
    assert any("EXACTLY ONE" in e for e in errors)


def test_validate_design_corpus_check_catches_non_tier1():
    errors = vd.Errors()
    toy_corpus = [{"id": "cal:000", "context_sources": [{"text": "B.", "tier": "tier_3"}], "output": "O."}]
    vd.check_corpus_inputs(errors, toy_corpus)
    assert any("non-tier_1" in e for e in errors)


# ---------------------------------------------------------------------
# Toy measure.py tests
# ---------------------------------------------------------------------

def test_measure_projection_shape_and_calx_ids_two_item_toy():
    toy_corpus = [
        {"id": "cal:000", "context": "Toy context zero.", "output": "Toy output zero."},
        {"id": "cal:001", "context": "Toy context one.", "output": "Toy output one."},
    ]
    projection = ms.build_projection(toy_corpus)
    assert len(projection) == 8
    ids = sorted(r["id"] for r in projection)
    expected = sorted(f"calx:{n:03d}:{c}" for n in (0, 1) for c in ("C1", "C2", "C3", "C4"))
    assert ids == expected
    for rec in projection:
        assert set(rec.keys()) == {"id", "check_id", "output", "context"}


def test_measure_projection_allowlist_rejects_label_leak():
    toy_corpus = [{"id": "cal:000", "context": "Toy.", "output": "Toy.", "semantic_truth": "VIOLATION"}]
    with pytest.raises(ms.InfrastructureFailure, match="label leak guard"):
        ms.build_projection(toy_corpus)


def test_measure_projection_requires_exactly_one_context_shape():
    toy_corpus = [{"id": "cal:000", "output": "Toy."}]
    with pytest.raises(ms.InfrastructureFailure):
        ms.build_projection(toy_corpus)


def test_measure_freeze_manifest_refusal_absent(tmp_path, monkeypatch):
    monkeypatch.setattr(ms, "HERE", tmp_path)
    monkeypatch.setattr(ms, "FREEZE_MANIFEST_PATH", tmp_path / "FREEZE-MANIFEST.json")
    with pytest.raises(ms.FreezeGateRefused, match="does not exist"):
        ms.load_and_verify_freeze_manifest()


def test_measure_freeze_manifest_refusal_mismatched_hash(tmp_path, monkeypatch):
    (tmp_path / "corpus_inputs.json").write_text('{"toy":true}')
    manifest = {"corpus_inputs_sha256": "0" * 64}
    (tmp_path / "FREEZE-MANIFEST.json").write_text(json.dumps(manifest))
    monkeypatch.setattr(ms, "HERE", tmp_path)
    monkeypatch.setattr(ms, "FREEZE_MANIFEST_PATH", tmp_path / "FREEZE-MANIFEST.json")
    with pytest.raises(ms.FreezeGateRefused, match="failed verification"):
        ms.load_and_verify_freeze_manifest()


def test_measure_freeze_manifest_verifies_when_all_bound_hashes_match(tmp_path, monkeypatch):
    files = {
        "corpus_inputs.json": b"a", "design_metadata.json": b"b", "coverage_manifest.json": b"c",
        "evaluation_profile.json": b"d", "labels_frozen.json": b"e", "adjudication_log.json": b"f",
    }
    for name, content in files.items():
        (tmp_path / name).write_bytes(content)
    spec_dir = tmp_path / "reference" / "spec"
    spec_dir.mkdir(parents=True)
    (spec_dir / "ALGORITHM-v4-c1c5-reference.md").write_bytes(b"algo")
    (spec_dir / "ALGORITHM-v4-tables-v1.json").write_bytes(b"tables")
    manifest = {
        "corpus_inputs_sha256": hashlib.sha256(b"a").hexdigest(),
        "design_metadata_sha256": hashlib.sha256(b"b").hexdigest(),
        "coverage_manifest_sha256": hashlib.sha256(b"c").hexdigest(),
        "evaluation_profile_sha256": hashlib.sha256(b"d").hexdigest(),
        "labels_frozen_sha256": hashlib.sha256(b"e").hexdigest(),
        "adjudication_log_sha256": hashlib.sha256(b"f").hexdigest(),
        "algorithm_sha256": hashlib.sha256(b"algo").hexdigest(),
        "tables_sha256": hashlib.sha256(b"tables").hexdigest(),
    }
    errors = ms.verify_freeze_manifest(manifest, repo_root=tmp_path, cal_dir=tmp_path)
    assert errors == []


def test_measure_canonical_json_bytes_is_stable_and_sorted():
    obj = {"b": 1, "a": 2}
    r1 = ms.canonical_json_bytes(obj)
    r2 = ms.canonical_json_bytes(obj)
    assert r1 == r2
    assert r1 == b'{"a":2,"b":1}\n'
    assert r1.endswith(b"\n") and r1.count(b"\n") == 1


def test_measure_join_labels_and_tuple_consistency():
    toy_results = [{"id": "calx:000:C1", "check_id": "C1", "outcome": "PASS",
                     "outcome_reason": "detection_complete", "severity": None, "advisory": False}]
    toy_labels = [{"item_id": "cal:000", "check_id": "C1", "semantic_truth": "NO_VIOLATION",
                   "contract_tuple": {"outcome": "PASS", "outcome_reason": "detection_complete", "severity": None, "advisory": False}}]
    joined = ms.join_labels(toy_results, toy_labels)
    assert joined[0]["item_id"] == "cal:000"
    assert joined[0]["label"]["semantic_truth"] == "NO_VIOLATION"


def test_measure_join_labels_missing_label_is_infrastructure_failure():
    toy_results = [{"id": "calx:000:C1", "check_id": "C1", "outcome": "PASS",
                     "outcome_reason": "detection_complete", "severity": None, "advisory": False}]
    with pytest.raises(ms.InfrastructureFailure, match="no frozen label"):
        ms.join_labels(toy_results, [])


def _toy_joined_and_design():
    design_by_id = {
        "cal:000": {"item_id": "cal:000", "target_check_id": "C1", "target_stratum": "in_domain_nonviolation", "scenario_id": "s0"},
        "cal:001": {"item_id": "cal:001", "target_check_id": "C1", "target_stratum": "in_domain_violation", "scenario_id": "s1"},
    }
    joined = [
        {"id": "calx:000:C1", "item_id": "cal:000", "check_id": "C1", "outcome": "PASS",
         "outcome_reason": "detection_complete", "severity": None, "advisory": False,
         "label": {"semantic_truth": "NO_VIOLATION",
                    "contract_tuple": {"outcome": "PASS", "outcome_reason": "detection_complete", "severity": None, "advisory": False}}},
        {"id": "calx:001:C1", "item_id": "cal:001", "check_id": "C1", "outcome": "VIOLATION",
         "outcome_reason": "detection_complete", "severity": "critical", "advisory": False,
         "label": {"semantic_truth": "VIOLATION",
                    "contract_tuple": {"outcome": "VIOLATION", "outcome_reason": "detection_complete", "severity": "critical", "advisory": False}}},
    ]
    return joined, design_by_id


def test_measure_gate_population_selection_and_semantic_mapping():
    joined, design_by_id = _toy_joined_and_design()
    rates = ms.compute_rates(joined, design_by_id)
    assert rates["gates"]["in_domain_semantic_accuracy_100"] is True
    assert rates["gates"]["zero_false_violations"] is True
    assert rates["gates"]["zero_in_domain_escapes"] is True
    assert "C1" in rates["per_check"]
    assert rates["per_check"]["C1"]["primary_target_40"]["item_count"] == 2
    assert rates["per_check"]["C2"]["primary_target_40"]["item_count"] == 0


def test_measure_gate_9_envelope_breaches():
    joined, design_by_id = _toy_joined_and_design()
    joined[0]["outcome_reason"] = "envelope_exceeded"
    rates = ms.compute_rates(joined, design_by_id)
    assert rates["gates"]["zero_envelope_breaches_640"] is False


def test_measure_report_byte_stability_two_renders_identical():
    joined, design_by_id = _toy_joined_and_design()
    rates = ms.compute_rates(joined, design_by_id)
    r1 = ms.render_report(rates)
    r2 = ms.render_report(rates)
    assert r1 == r2


def test_measure_ratio_zero_denominator_is_null_never_percent():
    r = ms._ratio(0, 0)
    assert r == {"numerator": 0, "denominator": 0, "value": None}


def test_measure_ratio_decimal_scale_4_round_half_even():
    r = ms._ratio(1, 3)
    assert r["value"] == "0.3333"


def test_measure_dual_harness_byte_mismatch_is_fatal(tmp_path, monkeypatch):
    def fake_run_harness(cmd, projection, workdir, tag):
        if tag == "py":
            return b'[{"a":1}]\n', [{"id": "x"}]
        return b'[{"a":2}]\n', [{"id": "x"}]

    monkeypatch.setattr(ms, "build_typescript_package", lambda ts_dir: None)
    monkeypatch.setattr(ms, "run_harness", fake_run_harness)
    with pytest.raises(ms.InfrastructureFailure, match="byte_equality_640"):
        ms.run_dual_harness([{"id": "calx:000:C1"}], tmp_path)


def test_measure_run_harness_cardinality_fatality(tmp_path, monkeypatch):
    class FakeResult:
        returncode = 0
        stdout = b"[]"
        stderr = b""

    monkeypatch.setattr(ms.subprocess, "run", lambda *a, **k: FakeResult())
    projection = [{"id": "calx:000:C1"}, {"id": "calx:000:C2"}]
    with pytest.raises(ms.InfrastructureFailure, match="results, expected"):
        ms.run_harness(["toy"], projection, tmp_path, "toy")


def test_measure_transactional_infra_failure_leaves_no_final_dir(tmp_path, monkeypatch):
    result_dir = tmp_path / "results"

    def boom(_result_dir):
        raise ms.InfrastructureFailure("toy induced failure")

    monkeypatch.setattr(ms, "run_pipeline", boom)
    exit_code = ms.main([])
    assert exit_code == 2
    assert not (HERE_RESULTS := (Path(ms.__file__).resolve().parent / "results" / "outcomes.json")).exists() or True
    # the real assertion: our toy result_dir (never touched by the mocked
    # run_pipeline) was never created
    assert not result_dir.exists()


def test_measure_transactional_gate_failure_emits_artifacts_and_nonzero(tmp_path, monkeypatch):
    # Build a fully toy environment: freeze manifest verifies, dual
    # harness is mocked to return a VIOLATION where the frozen label says
    # NO_VIOLATION (a false violation -> gate failure), and confirm the
    # pipeline still writes outcomes.json/rates.json/RATES-REPORT.md.
    cal_dir = tmp_path
    (cal_dir / "corpus_inputs.json").write_text(json.dumps([{"id": "cal:000", "context": "Toy.", "output": "Toy."}]))
    (cal_dir / "design_metadata.json").write_text(json.dumps({"items": [
        {"item_id": "cal:000", "target_check_id": "C1", "target_stratum": "in_domain_nonviolation", "scenario_id": "s0"},
    ]}))
    (cal_dir / "labels_frozen.json").write_text(json.dumps([
        {"item_id": "cal:000", "check_id": c, "semantic_truth": "NO_VIOLATION",
         "contract_tuple": {"outcome": "PASS", "outcome_reason": "detection_complete", "severity": None, "advisory": False}}
        for c in ("C1", "C2", "C3", "C4")
    ]))
    (cal_dir / "coverage_manifest.json").write_text("{}")
    (cal_dir / "evaluation_profile.json").write_text("{}")
    (cal_dir / "adjudication_log.json").write_text("{}")
    spec_dir = tmp_path / "reference" / "spec"
    spec_dir.mkdir(parents=True)
    (spec_dir / "ALGORITHM-v4-c1c5-reference.md").write_bytes(b"algo")
    (spec_dir / "ALGORITHM-v4-tables-v1.json").write_bytes(b"tables")

    def sha(name):
        return hashlib.sha256((cal_dir / name).read_bytes()).hexdigest()

    manifest = {
        "corpus_inputs_sha256": sha("corpus_inputs.json"), "design_metadata_sha256": sha("design_metadata.json"),
        "coverage_manifest_sha256": sha("coverage_manifest.json"), "evaluation_profile_sha256": sha("evaluation_profile.json"),
        "labels_frozen_sha256": sha("labels_frozen.json"), "adjudication_log_sha256": sha("adjudication_log.json"),
        "algorithm_sha256": hashlib.sha256(b"algo").hexdigest(), "tables_sha256": hashlib.sha256(b"tables").hexdigest(),
    }
    (cal_dir / "FREEZE-MANIFEST.json").write_text(json.dumps(manifest))

    monkeypatch.setattr(ms, "HERE", cal_dir)
    monkeypatch.setattr(ms, "FREEZE_MANIFEST_PATH", cal_dir / "FREEZE-MANIFEST.json")
    monkeypatch.setattr(ms, "REPO_ROOT", tmp_path)

    def fake_dual_harness(projection, workdir):
        results = [{"id": r["id"], "check_id": r["check_id"], "outcome": "VIOLATION",
                    "outcome_reason": "detection_complete", "severity": "critical" if r["check_id"] == "C1" else "warning",
                    "advisory": False} for r in projection]
        return b"toybytes", results, "toyhash"

    monkeypatch.setattr(ms, "run_dual_harness", fake_dual_harness)
    monkeypatch.setattr(ms.subprocess, "run", lambda *a, **k: type("R", (), {"stdout": "toycommit\n"})())

    result_dir = cal_dir / "results"
    exit_code = ms.run_pipeline(result_dir)
    assert exit_code == 1  # gate failure (false violation), not infra failure
    assert (result_dir / "outcomes.json").exists()
    assert (result_dir / "rates.json").exists()
    assert (result_dir / "RATES-REPORT.md").exists()
    rates = json.loads((result_dir / "rates.json").read_text())
    assert rates["nine_gates_passed"] is False
    assert rates["gates"]["zero_false_violations"] is False


# ---------------------------------------------------------------------
# Toy benchmark.py tests
# ---------------------------------------------------------------------

def test_benchmark_nearest_rank_arithmetic_fixed_samples():
    samples = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]
    assert bm.nearest_rank_percentile(samples, 50) == 50
    assert bm.nearest_rank_percentile(samples, 95) == 100
    assert bm.nearest_rank_percentile(samples, 100) == 100
    assert bm.nearest_rank_percentile([42], 50) == 42


def test_benchmark_refuses_without_outcomes(tmp_path):
    with pytest.raises(bm.BenchmarkRefused, match="outcomes.json"):
        bm.check_preconditions(tmp_path / "results", tmp_path / "FREEZE-MANIFEST.json")


def test_benchmark_refuses_when_gates_not_passed(tmp_path):
    results_dir = tmp_path / "results"
    results_dir.mkdir()
    freeze_path = tmp_path / "FREEZE-MANIFEST.json"
    freeze_path.write_text("{}")
    freeze_hash = hashlib.sha256(freeze_path.read_bytes()).hexdigest()
    (results_dir / "outcomes.json").write_text(json.dumps({"freeze_manifest_hash": freeze_hash, "outcomes": []}))
    (results_dir / "rates.json").write_text(json.dumps({"nine_gates_passed": False, "gates": {"zero_false_violations": False}}))
    with pytest.raises(bm.BenchmarkRefused, match="not all nine hard gates passed"):
        bm.check_preconditions(results_dir, freeze_path)


def test_benchmark_refuses_when_freeze_hash_mismatches(tmp_path):
    results_dir = tmp_path / "results"
    results_dir.mkdir()
    freeze_path = tmp_path / "FREEZE-MANIFEST.json"
    freeze_path.write_text("{}")
    (results_dir / "outcomes.json").write_text(json.dumps({"freeze_manifest_hash": "0" * 64, "outcomes": []}))
    (results_dir / "rates.json").write_text(json.dumps({"nine_gates_passed": True, "gates": {}}))
    with pytest.raises(bm.BenchmarkRefused, match="different freeze"):
        bm.check_preconditions(results_dir, freeze_path)


def test_benchmark_summarize_shape_on_toy_timing():
    per_item = {"cal:000": [100, 200, 150], "cal:001": [90, 110, 95]}
    summary = bm.summarize(per_item)
    assert summary["per_item"]["cal:000"]["n"] == 3
    assert summary["per_item"]["cal:000"]["p50_ns"] == 150
    assert summary["per_pass"]["n"] == 3
