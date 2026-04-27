# ADR-0003: Status Derivation from Enforcement.action (4-Action Canonical Mapping)

## Status

Accepted

## Date

2026-04-19

## Context

SAN-213 surfaced a critical semantic defect in Python interceptor receipts: `status="PASS"` was emitted alongside `enforcement.action="halted"`. This occurred because the C1–C5 coherence checks run unconditionally in `generate_receipt()`, and at interceptor surfaces these checks trivially pass (empty or non-reasoning context). The only signal that a tool call was blocked was `enforcement.action="halted"`, but no code enforced consistency between `status` and `enforcement.action`.

The result was receipts that were cryptographically valid but semantically defective — an auditor reading `status="PASS"` would conclude governance allowed the action, which was false.

The same gap existed on the verification side: the verifier did not cross-check `status` against `enforcement.action`, so a PASS+halted receipt passed verification.

This is "cryptographically valid, semantically misleading" — the worst failure mode for trust infrastructure.

## Decision

`status` MUST be derived from `Enforcement.action` using this complete 4-value mapping, with no implicit defaults:

| `enforcement.action` | Derived `status` |
|---|---|
| `halted` | `FAIL` |
| `warned` | `WARN` |
| `escalated` | `WARN` |
| `allowed` | `PASS` |

The derivation fires at receipt construction time when `enforcement` is provided (emit-side enforcement). The verifier also applies this mapping and rejects receipts where `status` contradicts `enforcement.action` (verify-side enforcement). Belt and suspenders.

`escalated` maps to `WARN`, not `PASS`: an escalated action has not yet been approved. A receipt emitted at escalation time reports that governance flagged the action for human review and halted autonomous execution. `PASS` would falsely imply "governance allowed this." `WARN` correctly signals "flagged, not greenlit." A separate downstream receipt records the approval outcome if and when it arrives.

This mapping is the single canonical source. All SDKs reference it by pointer, not by copy.

## Alternatives Considered

- **Caller-discipline: trust callers to set status correctly.** Rejected: SAN-213 demonstrated this fails at scale. The Python interceptors were setting `status` from check results, not from enforcement, and the defect persisted undetected. Structural enforcement is required.
- **Compute status from checks alone (ignore enforcement.action).** Rejected: this is precisely what produced the PASS+halted defect. Checks at interceptor surfaces trivially pass; enforcement.action is the authoritative signal of what governance decided.
- **Status = FAIL whenever enforcement.action is set (binary).** Rejected: `warned` and `escalated` represent partial governance outcomes, not hard failures. Collapsing them to FAIL would misrepresent escalated-then-approved workflows.

## Consequences

- No code path in either Python or TypeScript SDK can emit a signed receipt with `status="PASS"` and `enforcement.action="halted"`. Asserted directly in cross-SDK unit tests (AC 8 of SAN-213).
- Verifier-side enforcement catches any emission-side violation that reaches verification — closes the audit trail gap regardless of which SDK generated the receipt.
- Cross-SDK error message byte-equivalence is required so that debugging is consistent regardless of which SDK's verifier is used.
- `escalated` → `WARN` semantic is normative; future receipt consumers must not interpret `WARN` as "allowed" without checking `enforcement.action`.

## References

- SAN-213 (root cause, 4-action mapping decision, cross-SDK implementation)
- ADR-0006 (enforcement at construction — structural enforcement pattern)
- Spec `sanna-specification-v1.4.md` Section 4.6 (cross-field consistency rule)
- `sanna-repo/src/sanna/receipt.py` (emit-side override)
- `sanna-ts/packages/core/src/receipt.ts` (emit-side override)
- `sanna-repo/src/sanna/verify.py` (verify-side override)
- `sanna-ts/packages/core/src/verifier.ts` (verify-side override)
