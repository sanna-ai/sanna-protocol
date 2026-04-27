# ADR-0006: Dict-Mutation Pattern (Option B) — Enforcement at Construction, Never Post-Hoc

## Status

Accepted

## Date

2026-04-20

## Context

The 4-action enforcement override (ADR-0003: halted→FAIL, warned→WARN, escalated→WARN, allowed→PASS) fires at receipt construction time inside `generate_receipt()` / `generateReceipt()`. It ensures the emitted `status` field is consistent with `enforcement.action`.

SAN-213's Branch 2B incident identified an enforcement bypass path: a caller who builds an `Enforcement` object and then mutates `receipt.enforcement` after `generate_receipt()` returns bypasses the override entirely. The returned receipt has whatever `status` the override computed (correct), but the enforcement block now contains different values — producing a receipt whose `status` field contradicts its `enforcement.action` field. Cryptographically valid, semantically defective.

The same pattern applies to any third-party SDK implementer writing to the Sanna protocol: they might reasonably attempt to set enforcement outcome either at construction or post-hoc, depending on their SDK's ergonomics. The spec must be normative about which path is correct.

## Decision

**Option B: structural enforcement at the API level.**

`enforcement` MUST be passed as a kwarg to `generate_receipt()` (Python) / `generateReceipt()` (TypeScript) at construction time:

```python
# Correct (Option B — structural enforcement)
receipt = generate_receipt(
    ...,
    enforcement=Enforcement(action="halted", reason="...", ...)
)
```

`enforcement` MUST NOT be mutated on the returned receipt after construction:

```python
# Wrong — bypasses the override
receipt = generate_receipt(...)
receipt.enforcement = Enforcement(action="halted", ...)  # override already fired; bypass
```

Post-hoc mutation of `enforcement` (or enforcement-adjacent fields) does not trigger the override. The reference verifier catches the resulting inconsistency at verify time (belt) — but construction time is the correct prevention layer (suspenders).

Third-party SDK implementers MUST apply the enforcement override structurally at construction. SHOULD also reject post-hoc mutation if the SDK's type system allows (e.g., immutable receipt types in languages that support such).

This pattern is normative in `sanna-protocol/VERSIONING.md` as guidance for third-party implementers.

## Alternatives Considered

- **Option A: caller discipline only.** Rejected: SAN-213 proved this fails at scale. The Python interceptors were setting status from checks rather than enforcement, and the defect persisted undetected through multiple review cycles. Structural invariants require API-level enforcement, not behavioral documentation.
- **Freeze the receipt object post-construction.** Partially applicable: where a language's type system permits immutable or sealed objects, this is the implementation of "SHOULD reject post-hoc mutation." Rejected as the primary mechanism because ergonomics vary across SDK languages; the normative requirement is the construction-time enforcement kwarg.
- **Dual mode: accept enforcement at construction OR via post-hoc setter that re-triggers the override.** Rejected: dual mode is more complex to specify and implement, and the setter path means the override fires twice, creating edge cases when the first-pass status is already stored somewhere. Single authoritative construction-time path is simpler and safer.

## Consequences

- The enforcement override is structurally enforced. No valid code path in a conforming SDK can emit a receipt where `status` contradicts `enforcement.action`.
- The verifier-side check (ADR-0003) remains as the catch for non-conforming emitters.
- Third-party SDK implementers reading `VERSIONING.md` receive explicit guidance on the correct pattern before writing their first receipt-generating code.
- Some SDK ergonomics may require builder-pattern APIs to make the construction-time kwarg natural. This is the implementer's cost; the governance invariant takes priority.

## References

- SAN-213 (Branch 2B incident — root cause of the bypass pattern)
- ADR-0003 (status derivation from enforcement.action — the override this pattern protects)
- `sanna-protocol/VERSIONING.md` (Dict-mutation pattern section — normative third-party implementer guidance)
- `sanna-repo/src/sanna/receipt.py` (`generate_receipt()` enforcement kwarg)
- `sanna-ts/packages/core/src/receipt.ts` (`generateReceipt()` enforcement kwarg)
