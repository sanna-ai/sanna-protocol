# ADR-0008: content_mode Is an Ingestion CONTRACT, Not Server-Side Redaction

## Status

Accepted

## Date

2026-04-22

## Context

The original SAN-227 ticket framing said Cloud should redact `raw_signed_receipt` server-side based on `content_mode`. A `content_mode="redacted"` receipt would have its raw content dropped or overwritten before storage.

Discovery during SAN-227 found this framing is governance-incorrect on two grounds:

1. **Signature re-verifiability.** The receipt signature is computed over the canonical receipt bytes. Modifying stored bytes server-side breaks the ability to re-verify the signature independently. For a trust-infrastructure product, auditors must be able to re-verify receipts without trusting Cloud's storage layer. Server-side redaction eliminates that capability.

2. **Redaction only exists in the gateway path.** The `_apply_redaction_markers()` function exists only in the Python gateway (`sanna-repo/gateway/server.py`) and TypeScript gateway (`sanna-ts/packages/gateway/src/pii.ts`). The `@sanna_observe` middleware and TypeScript core interceptors stamp `content_mode` as a metadata tag but cannot produce actually-redacted content. Cloud enforcing a server-side redaction contract that SDKs cannot satisfy is an unshippable design.

An alternative framing — "Cloud attests that verification happened at time T" instead of storing the signed artifact — was also rejected: that is attestation, not cryptographic verification. Governance-weak; not shippable.

## Decision

`content_mode` is enforced as a **contract at ingestion**, not as a server-side operation on the stored content.

The contract model:
- Each workspace declares its `content_mode` policy (e.g., "all receipts submitted to this workspace must be `content_mode="redacted"` or stricter").
- Cloud validates incoming receipts against the workspace policy: correct metadata tag AND actual redaction markers present in the appropriate fields.
- Mismatch → `400 content_mode_violation`.
- `raw_signed_receipt` is stored exactly as received. No server-side modification.
- The signature is always re-verifiable against stored bytes.

`derive_cloud_view()` (the lossy projection that created a redacted view) is deprecated. The `cloud_view` column becomes a non-cryptographic structural index rather than a trusted PII-redacted copy.

The real redaction happens at emission time (SDK gateway path). SAN-248 and SAN-249 port gateway redaction to non-gateway SDK paths so that customers can satisfy the contract across all emission surfaces, not only via the gateway.

## Alternatives Considered

- **Server-side redaction: Cloud drops/overwrites raw content before storage.** Rejected: breaks signature re-verifiability — the core product claim. An auditor cannot re-verify a receipt whose bytes have been modified server-side. This would make "Sanna receipt verified" a Cloud attestation, not a cryptographic proof.
- **Attestation model: Cloud attests "verification occurred at time T."** Rejected: attestation is governance-weak. A receipt consumer cannot distinguish "Cloud verified and attested" from "Cloud verified incorrectly and attested." The signed artifact is the proof; attesting to verification is not a substitute.
- **Nullable `raw_signed_receipt` (original ticket scope options a/b/c).** Rejected: nulling or encrypting stored bytes server-side produces the same signature re-verifiability problem as direct redaction. The only governance-correct approach is to not modify the stored bytes.

## Consequences

- `raw_signed_receipt` is always stored as received; signature is always re-verifiable from storage.
- Cloud beta cannot ship `content_mode` enforcement until SAN-248 and SAN-249 land — non-gateway SDK paths must be capable of actual redaction before a contract enforcing redaction is meaningful.
- After SAN-248/249: SAN-250 retroactively quarantines existing `content_mode` violations in production data.
- `derive_cloud_view()` deprecation removes a lossy projection that misrepresented signature semantics.
- The architecture clarification (gateway = real redaction; non-gateway = metadata tag only) is now explicit. Marketing copy about `content_mode` as a "first-class protection" must be qualified until SAN-248/249 ship.

## References

- SAN-227 (Cloud: honor content_mode for raw_signed_receipt storage — original framing revised 2026-04-22)
- SAN-248 (Port gateway redaction to @sanna_observe middleware)
- SAN-249 (Port gateway pii.ts redaction to sanna-ts core emission paths)
- SAN-250 (Retroactive quarantine of existing content_mode violations in prod)
- ADR-0007 (Cloud ingestion delegates crypto to SDK verifier — companion decision)
- `sanna-cloud/src/api/services/content_mode.py`
- `sanna-repo/gateway/server.py` (`_apply_redaction_markers` — the only real redaction path in Python)
- `sanna-ts/packages/gateway/src/pii.ts` (the only real redaction path in TypeScript)
