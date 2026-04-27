# ADR-0007: Cloud Ingestion Delegates Crypto to SDK Verifier; Quarantines Unsigned

## Status

Accepted

## Date

2026-04-22

## Context

Cloud receipt ingestion was inserting receipts into the production table regardless of signature status. A best-effort signature check ran, but failure did not block insertion. The verifier was also incorrect: Cloud's home-grown verifier expected `receipt_signature.public_key` — a schema that no SDK uses. SDKs use `key_id` / `signed_by` / `signed_at` / `scheme` / `signature`. Additionally, Cloud hashed the whole-receipt JSON while SDKs blank the signature placeholder before hashing. Result: a Python-SDK-signed receipt valid under `sanna-verify` was classified `unverified` by Cloud and stored in production anyway.

This is a trust-infrastructure defect. Cloud's ingestion pipeline is the first verification gate for third-party receipt submission. If Cloud cannot verify SDK-generated receipts, the "Sanna receipt verified" claim is not meaningful at the ingestion boundary.

Evidence (SAN-223, Codex finding F-004):
- `src/api/services/receipt_ingestion.py:43, 297–300, 375` — minimal validation, best-effort verify, unconditional insert.
- `src/api/services/signature_verify.py:11` — expected `receipt_signature.public_key`.

## Decision

Cloud delegates all cryptographic verification to the `sanna` Python SDK (`verify_receipt()`). Cloud does not re-implement the protocol verifier.

Ingestion routing:

| Outcome | HTTP response | Storage |
|---|---|---|
| Schema / fingerprint / semantic / signature failure | 400 | Rejected; not stored |
| Unsigned / unknown key / inactive key | 202 | `receipts_quarantine` table |
| Verified clean | 201 | `receipts` table (production) |

Cloud extracts the `key_id` from the incoming receipt, looks up the corresponding PEM in the `signing_keys` table, and passes it to `verify_receipt(public_key_pem=...)`. The SDK performs all crypto. Cloud's role is key lookup and routing.

The `receipts_quarantine` table provides a non-destructive holding area for receipts that arrive without a registered key or before a key is activated. Quarantine receipts are isolated from production by RLS policy.

A Python-SDK-signed receipt valid under `sanna-verify` is valid under Cloud ingestion by construction.

## Alternatives Considered

- **Re-implement the protocol verifier in Cloud.** Rejected: byte-parity risk. Any deviation in the hashing or signature-verification implementation — field ordering, placeholder handling, encoding — produces a verifier that agrees with the SDK on simple cases but diverges on edge cases. The SDK is the authoritative implementation; delegating to it eliminates the parity risk.
- **Accept everything; verify asynchronously.** Rejected: the trust guarantee is immediate. A receipt that lands in the production table carries an implicit claim of verification. Asynchronous verification means receipts in production are unverified until the async job runs — undermining the audit trail.
- **Block all unsigned receipts (no quarantine).** Rejected: during Cloud onboarding, customers may submit receipts before their signing key is registered. Quarantine preserves receipts for retroactive verification without silently discarding them.

## Consequences

- Cloud signature verification is byte-equivalent to the SDK's by construction.
- The 14-test gate matrix (SAN-223 CI) verifies all routing outcomes at PR time.
- A receipt valid under `sanna-verify` is valid under Cloud ingestion; no separate "Cloud verification mode" exists.
- `receipts_quarantine` isolation via RLS: quarantined receipts are not accessible via the production receipts API until manually reviewed and promoted.
- `sanna-repo` PR #29 added `verify_receipt(public_key_pem=bytes)` as an additive API to support server-side callers passing PEM bytes directly. No protocol change, no version bump.
- Follow-ups: SAN-243 (customer-facing signing_keys registration endpoint); SAN-244 (sanna-ts PEM bytes API parity).

## References

- SAN-223 (Cloud ingestion: use SDK verifier and quarantine unverified receipts)
- ADR-0003 (status derivation — ensures PASS+halted receipts cannot reach production)
- ADR-0008 (content_mode as ingestion contract — companion decision at the same ingestion boundary)
- `sanna-cloud/src/api/services/receipt_ingestion.py`
- `sanna-cloud/db/migrations/040_san_223_ingestion_verifier_quarantine.sql`
