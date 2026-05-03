"""SAN-372: expected-failure regression guard for v1.2 archive fixtures."""
import json
from pathlib import Path

import jsonschema
import pytest

SCHEMA = json.loads(
    (Path(__file__).parent.parent / "schemas" / "receipt.schema.json").read_text()
)
V12_ESCALATED = json.loads(
    (Path(__file__).parent.parent / "fixtures" / "receipts" / "archive" / "v1.2" / "escalated.json").read_text()
)


def test_v12_escalated_expected_failure():
    """v1.2 escalated.json MUST fail current schema (Sprint 15 integrity fix).

    The fixture has enforcement.action=escalated with status=PASS. Sprint 15
    added a cross-field rule requiring status=WARN for escalated actions.
    If this test passes (no ValidationError), the cross-field rule was
    loosened -- a regression in the Sprint 15 integrity guarantee.
    """
    with pytest.raises(jsonschema.ValidationError, match="WARN"):
        jsonschema.validate(V12_ESCALATED, SCHEMA)
