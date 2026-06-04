"""SAN-765: schema-level enforcement of spec Section 7.3 assurance-when-triad MUST rule."""
import json
from pathlib import Path

import jsonschema
import pytest

SCHEMA = json.loads(
    (Path(__file__).parent.parent / "schemas" / "receipt.schema.json").read_text()
)
_BASE = json.loads(
    (Path(__file__).parent.parent / "fixtures" / "receipts" / "pass-single-check.json").read_text()
)

# Sanity check: base fixture must validate without triad fields present.
jsonschema.validate(_BASE, SCHEMA)


def _base_with(**overrides):
    r = dict(_BASE)
    r.update(overrides)
    return r


def test_triad_without_assurance_rejected():
    """A receipt with input_hash but no assurance must fail (spec Section 7.3)."""
    receipt = _base_with(
        input_hash="a" * 64,
    )
    receipt.pop("assurance", None)
    with pytest.raises(jsonschema.ValidationError, match="assurance"):
        jsonschema.validate(receipt, SCHEMA)


def test_triad_with_partial_assurance_valid():
    """A receipt with input_hash and assurance=partial must validate (spec Section 7.3)."""
    receipt = _base_with(
        input_hash="a" * 64,
        assurance="partial",
    )
    jsonschema.validate(receipt, SCHEMA)


def test_triad_with_null_assurance_rejected():
    """A receipt with input_hash and assurance=null must fail (spec Section 7.3 requires non-null)."""
    receipt = _base_with(
        input_hash="a" * 64,
        assurance=None,
    )
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(receipt, SCHEMA)
