# ADR-0004: NFC Normalization Scope in Canonical JSON

## Status

Accepted

## Date

2026-02-18 (original decision); re-affirmed 2026-04-24 (SAN-225)

## Context

Sanna receipts contain string fields whose hashes must be byte-identical across Python and TypeScript implementations. Unicode strings can be represented in multiple canonically equivalent forms — most commonly NFC (composed, e.g., single character `é`) and NFD (decomposed, e.g., `e` + combining accent). These forms are visually identical but produce different byte sequences and therefore different SHA-256 hashes.

The system hashes strings in two distinct ways:

1. **`hash_text()` / `canonicalize_text()`** — takes a raw string, applies NFC normalization and whitespace stripping, then hashes. Used for fingerprint input construction and text-mode hashing.
2. **`hash_obj()` / `canonical_json_bytes()`** — takes a dictionary, serializes to canonical JSON (sorted keys, minimal separators), then hashes. Used for `context_hash`, `output_hash`, `checks_hash`, and all structured-data hashing.

Spec v1.0.1 stated: "All string values MUST be normalized to Unicode NFC form before canonicalization." The reference implementation applied NFC only in `hash_text()`; `hash_obj()` hashed strings as-is. This discrepancy was flagged by all four cross-platform reviewers across four consecutive review cycles without resolution.

SAN-225 (2026-04-24) reopened the question after a Codex audit finding (F-006). The same analysis applied and the same decision stood.

## Decision

NFC normalization applies to `hash_text()` inputs only. `canonical_json_bytes()` / `hash_obj()` hash strings as-is without Unicode normalization. Callers are responsible for providing consistent string representations.

Spec v1.0.2 / v1.3 / v1.4 language (Section 3.1 and Section 13.1):

> NFC normalization MUST be applied to string inputs passed to `hash_text()` (fingerprint input construction, text-mode hashing). NFC normalization is NOT applied recursively to string values or keys within `canonical_json_bytes()` / `hash_obj()`. Implementations that hash JSON objects MUST preserve the original string encoding.

SAN-225 executed this as Option (b): narrow the spec to match the code. Choosing Option (a) — fix the code — would have required a SPEC_VERSION 2.0 bump, invalidated every shipped receipt, and touched the most security-critical hashing path with no real test coverage for the intended behavior (all test strings were ASCII).

## Alternatives Considered

- **Broaden code to match spec: recursively NFC-normalize all strings in `hash_obj()`.** Rejected: (1) breaking change — every hash computed by the system changes, every existing receipt becomes unverifiable; (2) touches the highest-risk path (signing pipeline) with a subtle recursive walk; (3) near-zero probability problem — MCP tool arguments are almost universally ASCII; (4) zero test coverage for the actual change; (5) the canonicalization decision became permanent when the first signed receipt was generated.
- **Make NFC a SHOULD instead of MUST.** Rejected: "SHOULD" creates the same ambiguity that generated four review cycles of findings. Implementers need a binary answer; "should" means some will and some won't, worse than either consistent choice.
- **Widen scope to hash_obj() in a future major version.** Tracked: SAN-252 (Backlog, P3) is the contingent upgrade path if real-world NFD strings surface in tool arguments. A future v2.0 protocol bump would gate on `spec_version` and apply appropriate hashing rules per version.

## Consequences

- Spec-code alignment is complete. No further reviewer findings on this topic.
- Zero risk of hash-breaking regression.
- Cross-language implementers have a precise, unambiguous instruction: do not normalize strings in `hash_obj()` paths.
- If a receipt contains NFD-encoded strings in tool arguments and is verified by a third-party implementation that eagerly NFC-normalizes all inputs, that verifier is non-conforming — the spec makes this explicit.
- SAN-252 tracks the contingent upgrade path. If cross-language verification at scale surfaces real-world NFD strings, this ADR is the starting point for a v2.0 migration proposal.

## References

- ADR-004 Notion page (original 2026-02-18 decision record; 4/4 reviewer convergence)
- SAN-225 (NFC normalization in hash_obj: apply recursively or narrow spec claim — Option b chosen)
- SAN-252 (Revisit NFC recursion scope — contingent on NFD evidence; Backlog P3)
- UAX #15: Unicode Normalization Forms
- RFC 8785: JSON Canonicalization Scheme (JCS) — does not mandate NFC normalization
- Spec `sanna-specification-v1.4.md` Section 3.1 and Section 13.1 item 8
