# Archived Receipts

This directory contains golden receipt fixtures from prior protocol versions, preserved for:

- **Regression testing** — verifying that verifiers correctly handle receipts from older spec versions
- **SOC 2 audit trail** — evidence that prior receipt formats were well-defined and testable
- **Customer reference** — customers who received receipts under prior protocol versions can use these to understand the format they were given

## Do not reference archived receipts in new tests

Archived receipts MUST NOT be used as expected outputs for new test cases. They do not satisfy v1.3 schema requirements (missing `enforcement_surface` and `invariants_scope`). Use them only for backward-compatibility verification paths.

## Subdirectory notes

### v1.2/

Receipts from protocol version 1.2 (`spec_version="1.2"`). Generated against the v1.2 spec and JSON schema.

**Note:** v1.2 was never released in SDK form. The v1.2 spec document was published but no SDK release produced receipts with `spec_version="1.2"`. These fixtures were generated for spec validation purposes only. Per the v1.3 normative statement, any receipt in the wild claiming `spec_version="1.2"` is spurious.

Files:
- `escalated.json` — receipt with `enforcement.action="escalated"`
- `fail-halted.json` — receipt with `status="FAIL"` and `enforcement.action="halted"`
- `full-featured.json` — receipt exercising all optional fields
- `pass-single-check.json` — minimal receipt with a single passing check

New v1.3 golden fixtures are regenerated via `generate_fixtures.py` in the `sanna-repo` branch and committed back to `fixtures/receipts/` at the top level of this directory.
