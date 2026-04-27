# ADR-0002: Receipt Fingerprint Formula — cv-Dispatched (12/14/16/20-field)

## Status

Accepted

## Date

2026-04-19 (cv=8, v1.3 — SAN-213); extended 2026-04-21 (cv=9, v1.4 — SAN-222)

## Context

Sanna receipt fingerprints must be byte-identical across Python and TypeScript SDKs, and forward-compatible across protocol versions. Each protocol version bump (v1.1→v1.3→v1.4) adds new fields that participate in the fingerprint. A single fixed-field formula would require either rejecting all receipts generated at prior protocol versions or silently ignoring new fields in old receipts.

The `checks_version` integer (`cv`) is already present in every receipt and is the normative signal for which protocol generation a receipt was emitted under. It is the natural dispatch key.

## Decision

Fingerprint selection is dispatched on `checks_version` (integer). Verifiers in both Python and TypeScript implement a cascade dispatch:

| checks_version | Field count | Protocol version | Notes |
|---|---|---|---|
| 5 | 12-field | v1.0–v1.1 | Legacy; no enforcement block |
| 6, 7 | 14-field | v1.1–v1.2 | Added empty-checks normalization |
| 8 | 16-field | v1.3 | Added enforcement_surface, invariants_scope |
| 9 | 20-field | v1.4 | Added tool_name, agent_model, agent_model_provider, agent_model_version |

Fields at positions 17–20 (cv=9) use `EMPTY_HASH` when the corresponding field is null or absent, preserving the fixed-width pipe-delimited fingerprint string format across all formula versions.

Both Python (`verify.py`) and TypeScript (`verifier.ts`) verifiers implement the full cascade dispatch. Emitters use the formula matching their current `CHECKS_VERSION` constant. No emitter needs to know about future formula versions.

## Alternatives Considered

- **Monotonic single formula (always use the largest field count).** Rejected: would require verifiers to reject all pre-v1.3 receipts lacking the newer fields, breaking backward compatibility for every receipt generated before the protocol upgrade.
- **Single growing formula with EMPTY_HASH padding for missing fields.** Rejected: spec ambiguity — a verifier cannot distinguish "field was absent because this is a v1.1 receipt" from "field was omitted erroneously in a v1.3 receipt." The dispatch makes this unambiguous.
- **Version-keyed separate formula functions (no cascade).** Functionally equivalent to the chosen approach; the cascade structure was preferred for readability in both SDKs.

## Consequences

- Legacy receipts (cv=5 through cv=8) continue to verify against Python and TypeScript verifiers indefinitely.
- New fields participate in the fingerprint at the cv bump that introduces them; no fingerprint inflation on older receipts.
- Cross-SDK byte-parity is testable via shared canonical fixtures (one fixture set per protocol version). The v1.3 and v1.4 fixture sets in `fixtures/` enforce this at CI time.
- Adding a new field requires coordinating: (1) cv bump in both SDKs, (2) fingerprint formula extension in both SDKs and spec Section 4.1, (3) fixture regeneration. This coordination cost is the intentional gate against casual field proliferation.

## References

- SAN-213 (cv=8 16-field formula, enforcement_surface + invariants_scope fields)
- SAN-222 (cv=9 20-field formula, tool_name + agent_model* fields)
- Spec `sanna-specification-v1.4.md` Section 4.1 (fingerprint construction)
- Spec Section 13 (compatibility generator/verifier rules)
- `fixtures/` (canonical cross-SDK fixture sets)
