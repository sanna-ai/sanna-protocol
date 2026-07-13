"""SAN-879: loads oracles.json, runs evaluate(), asserts EVERY hand-pinned
expected tuple exactly; then loads generated.json and asserts
regeneration is byte-identical (determinism).
"""

import json
from pathlib import Path

import pytest

from reference.evaluate import evaluate
from reference.generate_fixtures import generate, render

FIXTURES_DIR = Path(__file__).parent.parent.parent / "reference" / "fixtures"
ORACLES_PATH = FIXTURES_DIR / "oracles.json"
GENERATED_PATH = FIXTURES_DIR / "generated.json"

ORACLES = json.loads(ORACLES_PATH.read_text())


@pytest.mark.parametrize("oracle", ORACLES, ids=[o["id"] for o in ORACLES])
def test_oracle_expected_tuple_exact(oracle):
    """Every hand-pinned oracle's COMPLETE expected tuple {outcome,
    outcome_reason, severity} must be reproduced exactly. These are
    hand-pinned; if the implementation cannot reach one, that is a
    reference-implementation bug, never a reason to adjust the oracle."""
    result = evaluate({"context": oracle["context"], "output": oracle["output"]})
    got = result[oracle["check_id"]]
    assert got["outcome"] == oracle["expected"]["outcome"]
    assert got["outcome_reason"] == oracle["expected"]["outcome_reason"]
    assert got["severity"] == oracle["expected"]["severity"]


def test_every_oracle_binds_the_complete_tuple():
    """Every oracle JSON record must explicitly carry severity (null for
    PASS/NOT_EVALUATED rows), never omit the field."""
    for oracle in ORACLES:
        assert "severity" in oracle["expected"], oracle["id"]
        assert set(oracle["expected"].keys()) == {"outcome", "outcome_reason", "severity"}


def test_generated_fixtures_file_exists_and_is_nonempty():
    assert GENERATED_PATH.exists()
    generated = json.loads(GENERATED_PATH.read_text())
    assert len(generated) > 0


def test_generated_fixtures_regeneration_is_byte_identical():
    """Determinism: re-running the generator against the same oracles.json
    reproduces generated.json byte-for-byte."""
    on_disk = GENERATED_PATH.read_text()
    regenerated = render(generate())
    assert regenerated == on_disk


def test_generated_fixture_variants_match_their_base_oracle():
    """Spec: surface variants (casing / whitespace / contraction swaps)
    MUST yield identical results to their base oracle."""
    oracles_by_id = {o["id"]: o for o in ORACLES}
    generated = json.loads(GENERATED_PATH.read_text())
    for rec in generated:
        base = oracles_by_id[rec["base_oracle"]]
        assert rec["expected"] == base["expected"], rec["id"]


@pytest.mark.parametrize(
    "rec",
    json.loads(GENERATED_PATH.read_text()) if GENERATED_PATH.exists() else [],
    ids=lambda r: r["id"],
)
def test_generated_fixture_reproduces_live(rec):
    """Each generated fixture, re-evaluated live against the current
    implementation, matches its recorded expected tuple exactly."""
    result = evaluate({"context": rec["context"], "output": rec["output"]})
    got = result[rec["check_id"]]
    assert got["outcome"] == rec["expected"]["outcome"]
    assert got["outcome_reason"] == rec["expected"]["outcome_reason"]
    assert got["severity"] == rec["expected"]["severity"]
