# Sprint 4 Security Review — SAN-36

**Date:** 2026-03-23
**Reviewer:** Claude (automated)
**Scope:** SAN-27 — Cross-language fingerprint edge case test vectors
**Verdict:** PASS — No critical issues found.

## Files Reviewed

| File | Purpose |
|------|---------|
| `packages/core/tests/fixtures/fingerprint-edge-cases.json` | 61-line JSON test vector file |
| `packages/core/tests/fingerprint-edge-cases.test.ts` | 131-line Vitest test file |

## Checklist

### a. Sensitive Data (fixtures file)

- **Real keys:** None. No private keys, public keys, or PEM material present.
- **Real receipts:** None. Fixture contains only synthetic hash vectors and minimal check objects.
- **PII:** None. The only string value resembling an identifier is `"wf-12345"` (obviously synthetic).
- **Secrets/tokens:** None.

**Result:** PASS

### b. Unexpected Imports or Execution (test file)

Imports are limited to:
- `vitest` — test framework (expected)
- `node:fs` / `node:path` — reading the local fixture file (expected)
- `../src/hashing.js` — project's own hashing module (`EMPTY_HASH`, `hashContent`, `hashObj`)

No dynamic imports, no `eval()`, no network calls, no child process spawning, no filesystem writes.

**Result:** PASS

### c. Assertion Correctness & Python SDK Parity

| Vector | Expected Hash | Matches Python Semantics | Notes |
|--------|--------------|--------------------------|-------|
| `checks_hash.empty_array` | EMPTY_HASH | Yes | Empty array → EMPTY_HASH (Python falsy semantics) |
| `checks_hash.null_checks` | EMPTY_HASH | Yes | null/None → EMPTY_HASH |
| `checks_hash.non_empty_4_fields` | `eefc9b...` | Yes | 4-field check object, no enforcement fields |
| `workflow_id_hash.null_value` | EMPTY_HASH | Yes | null → EMPTY_HASH |
| `workflow_id_hash.empty_string` | EMPTY_HASH | Yes | SHA-256 of empty bytes |
| `workflow_id_hash.non_empty` | `855955...` | Yes | hash_text("wf-12345") |
| `check_enforcement_fields.without_enforcement` | `eefc9b...` | Yes | Same as 4-field case above |
| `check_enforcement_fields.with_enforcement` | `2b1e46...` | Yes | 8-field mode when triggered_by present |
| `check_enforcement_fields.mixed_enforcement` | `6c26ad...` | Yes | Mixed triggers → all checks use 8-field mode |

The test logic correctly implements the Python SDK's hashing semantics:
- Empty/null arrays use EMPTY_HASH (Python falsy behavior)
- Enforcement field detection uses `triggered_by !== undefined` presence check
- Mixed enforcement correctly promotes all checks to 8-field mode
- Field defaults (`?? null`, `?? ""`) match Python SDK behavior

**Result:** PASS

## Test Suite

All **926 tests** across **48 test files** pass (previously 771 tests/44 files — growth from SAN-27 additions).

## Critical Issues

None.

## Recommendations (non-blocking)

None. The change surface is minimal and well-scoped — synthetic test vectors with no security implications.
