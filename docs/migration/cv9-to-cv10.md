# Migrating from cv=9 (v1.4) to cv=10 (v1.5)

Version-history record for the v1.5 receipt-format transition. Shipped 2026-04-30 / 2026-05-01 across the Sanna SDK lockstep release.

## What changed

At v1.5 (`CHECKS_VERSION = "10"`), the receipt fingerprint formula extends from 20 fields to 21 fields. The new field at position 21 is `agent_identity_hash = hash_obj(receipt.agent_identity)`. The `agent_identity` field on the receipt root is required at cv=10 and absent at cv<=9.

Per spec Section 2.19, `agent_identity` binds the receipt to the identity layers required for AARM R6 conformance:

- `agent_session_id` (string, REQUIRED): opaque identifier for the agent's active session. Stable for one governed session.
- `human_principal` (object, OPTIONAL): subject + provider + verified-flag for the user/principal the agent acts on behalf of.
- `service_account` (object, OPTIONAL): id + provider for the IAM service account separate from agent identity.
- `role` (string, OPTIONAL): role assigned to the agent for this session.
- `privilege_scope` (array of strings, OPTIONAL): privileges granted to the agent for this session.

At cv=10, only `agent_identity.agent_session_id` is mandatory. Other sub-fields document the identity stack at the deployment's discretion.

For Sanna SDK emissions, `agent_session_id` is generated as a `crypto.randomUUID()` value at gateway/interceptor instance initialization (stable for the duration of one governed session per spec). Custom emitters integrating with the v1.5 receipt format must supply their own session identifier with the same lifetime guarantee.

## Why

AARM Core (R1-R6) requires identity binding at all layers: human principal, service account, agent session, role/privilege scope. v1.4 (cv=9) bound model identity (`agent_model*`), constitution authorship, and SDK identity (`tool_name`) but NOT agent session identity, human principal, service account, or role. v1.5 closes the gap.

The receipt-format change is fingerprint-binding: `agent_identity` at fingerprint position 21 means re-emission of the same input post-upgrade produces a different fingerprint. Pre-upgrade signed receipts remain cryptographically valid; the verifier dispatches on `checks_version` to apply the correct formula.

Spec Section 2.19 carries the normative requirements; the public conformance claim text lives in the spec's `AARM Conformance and Mapping` section.

## How verifiers handle the transition

The Python sanna verifier and the TypeScript sanna-ts verifier dispatch on the receipt's `checks_version` field:

| Receipt cv | Verifier behavior |
|---|---|
| cv<=8 | Existing legacy paths unchanged |
| cv=9 | Verifies via 20-field fingerprint formula. Emits a CV9_LEGACY-prefixed warning indicating partial R6 conformance only. Receipt is valid. |
| cv=10 | Verifies via 21-field fingerprint formula. Requires `agent_identity` and `agent_identity.agent_session_id`. Receipts missing those fail with a hard error. |

**No-action-required case:** Existing signed cv=9 receipts emitted before v1.5 remain cryptographically valid. Their fingerprints compute correctly under the 20-field formula. They will continue to verify with a CV9_LEGACY warning indefinitely.

**Re-emission case:** Once a deployment upgrades to v1.5 SDKs, gateway and interceptor emission surfaces produce cv=10 receipts with populated `agent_identity`. Library middleware (sannaObserve / @sanna_observe decorator / sanna-generate CLI / sanna_generate_receipt MCP tool) continues to emit cv=9 legacy receipts per spec Section 2.19 line 781-782 -- library middleware does not have session identity context and emits the lower checks_version honestly.

## SDK lockstep

v1.5 ships across three repos at one time. For cross-SDK verification to work, both Python and TypeScript SDKs must pin to the same `spec/` submodule snapshot:

- sanna-protocol: e58ed3e (post-SAN-389 artifact self-consistency)
- sanna v1.5.0 (Python SDK): SPEC_VERSION=1.5, CHECKS_VERSION=10, TOOL_VERSION=1.5.0
- sanna-ts v1.5.0 (TypeScript SDK): SPEC_VERSION=1.5, CHECKS_VERSION=10, TOOL_VERSION=1.5.0

Cross-SDK receipt verification (Python emit / TS verify, TS emit / Python verify) is byte-equal validated.

## Receipt fingerprint compatibility

Receipt fingerprints depend only on the pipe-joined field hashes in the formula -- not on the signing key. Re-signing a receipt with a new keypair produces a DIFFERENT signature but the SAME fingerprint. Re-emitting an identical input produces the SAME fingerprint regardless of which SDK or keypair was used.

The 21-field formula at cv=10 is byte-equal across SDKs. The 20-field formula at cv=9 remains byte-equal across SDKs.

## References

- Spec Section 2.19: `agent_identity` field definition.
- Spec Section 4.1: fingerprint formula with cv-aware dispatch.
- SAN-204: protocol schema work that introduced the field shape.
- SAN-370: cv=10 cascade across protocol + Python SDK + TypeScript SDK.
- SAN-385, SAN-389, SAN-392: artifact self-consistency fixes during the v1.5 release sequence.
- SAN-371: this migration memo + verifier CV9_LEGACY warning emission.
